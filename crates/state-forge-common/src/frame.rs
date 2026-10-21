use crate::InterceptedEvent;
use bincode::Options;
use std::io::{Read, Write};

/// Максимальный размер одного кадра IPC (16 МБ)
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Ошибки при чтении или записи кадра IPC
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    Bincode(bincode::Error),
    FrameTooLarge { len: usize, max: usize },
    TrailingBytes { consumed: usize, total: usize },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "I/O error: {}", e),
            FrameError::Bincode(e) => write!(f, "Bincode error: {}", e),
            FrameError::FrameTooLarge { len, max } => {
                write!(
                    f,
                    "Frame length {} exceeds maximum allowed length {}",
                    len, max
                )
            }
            FrameError::TrailingBytes { consumed, total } => {
                write!(
                    f,
                    "Frame payload had trailing bytes (consumed {}, total {})",
                    consumed, total
                )
            }
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FrameError::Io(e) => Some(e),
            FrameError::Bincode(e) => Some(e),
            FrameError::FrameTooLarge { .. } | FrameError::TrailingBytes { .. } => None,
        }
    }
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

impl From<bincode::Error> for FrameError {
    fn from(e: bincode::Error) -> Self {
        FrameError::Bincode(e)
    }
}

/// Проверка допустимости длины кадра до выделения буфера памяти
pub fn validate_frame_len(len: usize) -> Result<(), FrameError> {
    if len > MAX_FRAME_LEN {
        return Err(FrameError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    Ok(())
}

/// Запись кадра [u32 LE длина][bincode] в поток единым буфером
pub fn write_frame<W: Write>(mut w: W, event: &InterceptedEvent) -> Result<(), FrameError> {
    let encoded = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(event)?;
    validate_frame_len(encoded.len())?;

    let mut frame_buf = Vec::with_capacity(4 + encoded.len());
    frame_buf.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    frame_buf.extend_from_slice(&encoded);

    w.write_all(&frame_buf)?;
    w.flush()?;
    Ok(())
}

/// Чтение кадра [u32 LE длина][bincode] из потока с валидацией отсутствия лишних байтов в payload
pub fn read_frame<R: Read>(mut r: R) -> Result<Option<InterceptedEvent>, FrameError> {
    let mut len_buf = [0u8; 4];
    let mut read_bytes = 0;

    while read_bytes < 4 {
        match r.read(&mut len_buf[read_bytes..]) {
            Ok(0) => {
                if read_bytes == 0 {
                    return Ok(None);
                } else {
                    return Err(FrameError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Truncated frame length header",
                    )));
                }
            }
            Ok(n) => {
                read_bytes += n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e)),
        }
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    validate_frame_len(len)?;

    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;

    let mut cursor = std::io::Cursor::new(&payload);
    let event: InterceptedEvent = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize_from(&mut cursor)?;

    let consumed = cursor.position() as usize;
    if consumed < payload.len() {
        return Err(FrameError::TrailingBytes {
            consumed,
            total: payload.len(),
        });
    }

    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkDirection, NetworkEventPayload};
    use std::io::Cursor;

    struct ByteByByteReader<R> {
        inner: R,
    }

    impl<R: Read> Read for ByteByByteReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.inner.read(&mut buf[..1])
        }
    }

    #[test]
    fn test_roundtrip_all_event_types() {
        let events = vec![
            InterceptedEvent {
                pid: 100,
                seq: 1,
                timestamp_millis: 1000,
                payload: NetworkEventPayload::Connect {
                    socket: 1,
                    remote_addr: Some("127.0.0.1:80".parse().unwrap()),
                    success: true,
                },
            },
            InterceptedEvent {
                pid: 101,
                seq: 2,
                timestamp_millis: 1001,
                payload: NetworkEventPayload::Connect {
                    socket: 2,
                    remote_addr: Some("[::1]:443".parse().unwrap()),
                    success: false,
                },
            },
            InterceptedEvent {
                pid: 102,
                seq: 3,
                timestamp_millis: 1002,
                payload: NetworkEventPayload::Connect {
                    socket: 3,
                    remote_addr: None,
                    success: true,
                },
            },
            InterceptedEvent {
                pid: 103,
                seq: 4,
                timestamp_millis: 1003,
                payload: NetworkEventPayload::Data {
                    socket: 4,
                    direction: NetworkDirection::Tx,
                    original_len: 8,
                    bytes: b"Hello Tx".to_vec(),
                },
            },
            InterceptedEvent {
                pid: 104,
                seq: 5,
                timestamp_millis: 1004,
                payload: NetworkEventPayload::Data {
                    socket: 5,
                    direction: NetworkDirection::Rx,
                    original_len: 8,
                    bytes: b"Hello Rx".to_vec(),
                },
            },
            InterceptedEvent {
                pid: 105,
                seq: 6,
                timestamp_millis: 1005,
                payload: NetworkEventPayload::Data {
                    socket: 6,
                    direction: NetworkDirection::Tx,
                    original_len: 0,
                    bytes: vec![],
                },
            },
            InterceptedEvent {
                pid: 106,
                seq: 7,
                timestamp_millis: 1006,
                payload: NetworkEventPayload::Close { socket: 7 },
            },
            InterceptedEvent {
                pid: 107,
                seq: 8,
                timestamp_millis: 1007,
                payload: NetworkEventPayload::PeerClosed { socket: 8 },
            },
        ];

        for ev in &events {
            let mut buf = Vec::new();
            write_frame(&mut buf, ev).expect("Failed to write frame");

            let mut cursor = Cursor::new(buf);
            let read_ev = read_frame(&mut cursor)
                .expect("Failed to read frame")
                .expect("Expected event, got EOF");

            assert_eq!(read_ev, *ev);
        }
    }

    #[test]
    fn test_wire_format_exact_bytes() {
        let event = InterceptedEvent {
            pid: 1,
            seq: 3,
            timestamp_millis: 2,
            payload: NetworkEventPayload::Close { socket: 7 },
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &event).expect("write_frame failed");

        let expected_bytes: Vec<u8> = vec![
            // Header (4 bytes): length of payload = 32 (0x00000020) LE
            0x20, 0x00, 0x00, 0x00, // Payload (32 bytes):
            // pid: u32 = 1
            0x01, 0x00, 0x00, 0x00, // seq: u64 = 3
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp_millis: u64 = 2
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // discriminant: Close = 2 (u32 LE)
            0x02, 0x00, 0x00, 0x00, // socket: u64 = 7
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(buf.len(), 36);
        assert_eq!(buf, expected_bytes);
    }

    #[test]
    fn test_write_frame_exceeds_max_len_writes_nothing() {
        let event = InterceptedEvent {
            pid: 1,
            seq: 1,
            timestamp_millis: 1,
            payload: NetworkEventPayload::Data {
                socket: 1,
                direction: NetworkDirection::Tx,
                original_len: (MAX_FRAME_LEN + 1) as u32,
                bytes: vec![0u8; MAX_FRAME_LEN + 1],
            },
        };

        let mut buf = Vec::new();
        let res = write_frame(&mut buf, &event);
        assert!(matches!(res, Err(FrameError::FrameTooLarge { .. })));
        assert!(buf.is_empty(), "Expected nothing to be written on error");
    }

    #[test]
    fn test_read_frame_byte_by_byte_reader() {
        let event = InterceptedEvent {
            pid: 42,
            seq: 100,
            timestamp_millis: 500,
            payload: NetworkEventPayload::Close { socket: 10 },
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &event).unwrap();

        let reader = ByteByByteReader {
            inner: Cursor::new(buf),
        };
        let decoded = read_frame(reader).unwrap().expect("event");
        assert_eq!(decoded, event);
    }

    #[test]
    fn test_read_frame_trailing_bytes_error() {
        let event = InterceptedEvent {
            pid: 1,
            seq: 2,
            timestamp_millis: 3,
            payload: NetworkEventPayload::Close { socket: 4 },
        };

        let mut valid_payload = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&event)
            .unwrap();
        valid_payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let mut frame_buf = Vec::new();
        frame_buf.extend_from_slice(&(valid_payload.len() as u32).to_le_bytes());
        frame_buf.extend_from_slice(&valid_payload);

        let mut cursor = Cursor::new(frame_buf);
        let err = read_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::TrailingBytes { consumed, total } => {
                assert_eq!(total, valid_payload.len());
                assert_eq!(consumed, valid_payload.len() - 4);
            }
            _ => panic!("Expected TrailingBytes error, got {:?}", err),
        }
    }

    #[test]
    fn test_peer_closed_roundtrip() {
        let event = InterceptedEvent {
            pid: 111,
            seq: 222,
            timestamp_millis: 333,
            payload: NetworkEventPayload::PeerClosed { socket: 444 },
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &event).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded = read_frame(&mut cursor).unwrap().expect("event");
        assert_eq!(decoded, event);
    }

    #[test]
    fn test_truncated_header() {
        let buf = [0x01u8, 0x02];
        let mut cursor = Cursor::new(&buf);
        let err = read_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            _ => panic!("Expected IO UnexpectedEof error, got {:?}", err),
        }
    }

    #[test]
    fn test_truncated_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(10u32).to_le_bytes());
        buf.extend_from_slice(&[1, 2, 3]);

        let mut cursor = Cursor::new(&buf);
        let err = read_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            _ => panic!("Expected IO UnexpectedEof error, got {:?}", err),
        }
    }

    #[test]
    fn test_frame_length_exceeds_max() {
        let excessive_len = (MAX_FRAME_LEN + 1) as u32;
        let buf = excessive_len.to_le_bytes();
        let mut cursor = Cursor::new(&buf);
        let err = read_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::FrameTooLarge { len, max } => {
                assert_eq!(len, MAX_FRAME_LEN + 1);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            _ => panic!("Expected FrameTooLarge error, got {:?}", err),
        }
    }

    #[test]
    fn test_garbage_payload_with_valid_length() {
        let garbage = [0xFFu8; 16];
        let mut buf = Vec::new();
        buf.extend_from_slice(&(garbage.len() as u32).to_le_bytes());
        buf.extend_from_slice(&garbage);

        let mut cursor = Cursor::new(&buf);
        let err = read_frame(&mut cursor).unwrap_err();
        match err {
            FrameError::Bincode(_) => {}
            _ => panic!("Expected Bincode error, got {:?}", err),
        }
    }

    #[test]
    fn test_multiple_consecutive_frames_in_one_buffer() {
        let ev1 = InterceptedEvent {
            pid: 1,
            seq: 10,
            timestamp_millis: 10,
            payload: NetworkEventPayload::Close { socket: 11 },
        };
        let ev2 = InterceptedEvent {
            pid: 2,
            seq: 20,
            timestamp_millis: 20,
            payload: NetworkEventPayload::Close { socket: 22 },
        };
        let ev3 = InterceptedEvent {
            pid: 3,
            seq: 30,
            timestamp_millis: 30,
            payload: NetworkEventPayload::Close { socket: 33 },
        };

        let mut stream = Vec::new();
        write_frame(&mut stream, &ev1).unwrap();
        write_frame(&mut stream, &ev2).unwrap();
        write_frame(&mut stream, &ev3).unwrap();

        let mut cursor = Cursor::new(stream);
        let r1 = read_frame(&mut cursor).unwrap().expect("ev1");
        assert_eq!(r1, ev1);

        let r2 = read_frame(&mut cursor).unwrap().expect("ev2");
        assert_eq!(r2, ev2);

        let r3 = read_frame(&mut cursor).unwrap().expect("ev3");
        assert_eq!(r3, ev3);

        let eof = read_frame(&mut cursor).unwrap();
        assert!(eof.is_none());
    }

    #[test]
    fn test_max_frame_len_exact_value() {
        // Убивает мутантов: replace * with + в MAX_FRAME_LEN
        // 16 * 1024 * 1024 = 16_777_216 байт (16 МиБ)
        assert_eq!(MAX_FRAME_LEN, 16_777_216);
    }

    #[test]
    fn test_validate_frame_len_boundaries() {
        // Убивает мутанта: `replace > with >= in validate_frame_len`
        // Ровно MAX_FRAME_LEN — допустимый размер кадра!
        assert!(validate_frame_len(MAX_FRAME_LEN).is_ok());
        assert!(validate_frame_len(MAX_FRAME_LEN - 1).is_ok());
        assert!(validate_frame_len(0).is_ok());

        // Превышение границы строго на 1 байт должно давать ошибку
        let err = validate_frame_len(MAX_FRAME_LEN + 1).unwrap_err();
        match err {
            FrameError::FrameTooLarge { len, max } => {
                assert_eq!(len, MAX_FRAME_LEN + 1);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            _ => panic!("Expected FrameTooLarge, got {:?}", err),
        }
    }

    #[test]
    fn test_frame_error_display_and_source() {
        use std::error::Error;

        // 1. FrameError::Io
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "disk failure");
        let err_io: FrameError = io_err.into();
        // Убивает мутанта: `replace <impl Display for FrameError>::fmt with Ok(Default::default())`
        assert_eq!(err_io.to_string(), "I/O error: disk failure");
        // Убивает мутанта: `replace <impl Error for FrameError>::source with None`
        assert!(err_io.source().is_some());
        assert_eq!(
            err_io
                .source()
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound
        );

        // 2. FrameError::Bincode
        let bad_bytes = [0xFF; 2];
        let bincode_err = bincode::deserialize::<InterceptedEvent>(&bad_bytes).unwrap_err();
        let expected_msg = format!("Bincode error: {}", bincode_err);
        let err_bincode: FrameError = bincode_err.into();
        assert_eq!(err_bincode.to_string(), expected_msg);
        assert!(err_bincode.source().is_some());

        // 3. FrameError::FrameTooLarge
        let err_large = FrameError::FrameTooLarge { len: 200, max: 100 };
        assert_eq!(
            err_large.to_string(),
            "Frame length 200 exceeds maximum allowed length 100"
        );
        assert!(err_large.source().is_none());

        // 4. FrameError::TrailingBytes
        let err_trailing = FrameError::TrailingBytes {
            consumed: 10,
            total: 15,
        };
        assert_eq!(
            err_trailing.to_string(),
            "Frame payload had trailing bytes (consumed 10, total 15)"
        );
        assert!(err_trailing.source().is_none());
    }

    struct InterruptedThenDataReader<R> {
        inner: R,
        interrupted_injected: bool,
    }

    impl<R: Read> Read for InterruptedThenDataReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted_injected {
                self.interrupted_injected = true;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "simulated EINTR",
                ));
            }
            self.inner.read(buf)
        }
    }

    #[test]
    fn test_read_frame_interrupted_retry() {
        // Убивает мутанта: `replace match guard e.kind() == Interrupted with false`
        let event = InterceptedEvent {
            pid: 999,
            seq: 1,
            timestamp_millis: 12345,
            payload: NetworkEventPayload::Close { socket: 42 },
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &event).unwrap();

        let mut reader = InterruptedThenDataReader {
            inner: Cursor::new(buf),
            interrupted_injected: false,
        };

        // read_frame обязан проглотить ErrorKind::Interrupted и продолжить чтение
        let result =
            read_frame(&mut reader).expect("read_frame should succeed after retry on Interrupted");
        assert_eq!(result, Some(event));
    }

    struct OtherErrorReader {
        attempts: std::sync::atomic::AtomicUsize,
    }
    impl Read for OtherErrorReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            let count = self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count > 5 {
                panic!("Infinite loop detected: read_frame retried on non-interrupted error");
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "access denied",
            ))
        }
    }

    #[test]
    fn test_read_frame_non_interrupted_error_fails() {
        // Убивает мутантов: `replace match guard e.kind() == Interrupted with true` и `replace == with !=`
        let mut reader = OtherErrorReader {
            attempts: std::sync::atomic::AtomicUsize::new(0),
        };
        let res = read_frame(&mut reader);
        assert!(res.is_err());
        match res.unwrap_err() {
            FrameError::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
            other => panic!("Expected FrameError::Io, got {:?}", other),
        }
    }
}
