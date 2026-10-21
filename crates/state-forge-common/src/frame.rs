use crate::InterceptedEvent;
use std::io::{Read, Write};

/// Максимальный размер одного кадра IPC (16 МБ)
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Ошибки при чтении или записи кадра IPC
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    Bincode(bincode::Error),
    FrameTooLarge { len: usize, max: usize },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "I/O error: {}", e),
            FrameError::Bincode(e) => write!(f, "Bincode deserialization error: {}", e),
            FrameError::FrameTooLarge { len, max } => {
                write!(
                    f,
                    "Frame length {} exceeds maximum allowed length {}",
                    len, max
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
            FrameError::FrameTooLarge { .. } => None,
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

/// Запись кадра [u32 LE длина][bincode] в поток
pub fn write_frame<W: Write>(mut w: W, event: &InterceptedEvent) -> Result<(), FrameError> {
    let encoded = bincode::serialize(event)?;
    validate_frame_len(encoded.len())?;
    let len = (encoded.len() as u32).to_le_bytes();
    w.write_all(&len)?;
    w.write_all(&encoded)?;
    w.flush()?;
    Ok(())
}

/// Чтение кадра [u32 LE длина][bincode] из потока
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

    let event = bincode::deserialize(&payload)?;
    Ok(Some(event))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkDirection, NetworkEventPayload};
    use std::io::Cursor;

    #[test]
    fn test_roundtrip_all_event_types() {
        let events = vec![
            InterceptedEvent {
                pid: 100,
                timestamp_millis: 1000,
                payload: NetworkEventPayload::Connect {
                    socket: 1,
                    remote_addr: Some("127.0.0.1:80".parse().unwrap()),
                    success: true,
                },
            },
            InterceptedEvent {
                pid: 101,
                timestamp_millis: 1001,
                payload: NetworkEventPayload::Connect {
                    socket: 2,
                    remote_addr: Some("[::1]:443".parse().unwrap()),
                    success: false,
                },
            },
            InterceptedEvent {
                pid: 102,
                timestamp_millis: 1002,
                payload: NetworkEventPayload::Connect {
                    socket: 3,
                    remote_addr: None,
                    success: true,
                },
            },
            InterceptedEvent {
                pid: 103,
                timestamp_millis: 1003,
                payload: NetworkEventPayload::Data {
                    socket: 4,
                    direction: NetworkDirection::Tx,
                    bytes: b"Hello Tx".to_vec(),
                },
            },
            InterceptedEvent {
                pid: 104,
                timestamp_millis: 1004,
                payload: NetworkEventPayload::Data {
                    socket: 5,
                    direction: NetworkDirection::Rx,
                    bytes: b"Hello Rx".to_vec(),
                },
            },
            InterceptedEvent {
                pid: 105,
                timestamp_millis: 1005,
                payload: NetworkEventPayload::Data {
                    socket: 6,
                    direction: NetworkDirection::Tx,
                    bytes: vec![],
                },
            },
            InterceptedEvent {
                pid: 106,
                timestamp_millis: 1006,
                payload: NetworkEventPayload::Close { socket: 7 },
            },
        ];

        for ev in &events {
            let mut buf = Vec::new();
            write_frame(&mut buf, ev).expect("Failed to write frame");

            let mut cursor = Cursor::new(buf);
            let read_ev = read_frame(&mut cursor)
                .expect("Failed to read frame")
                .expect("Expected event, got EOF");

            assert_eq!(read_ev.pid, ev.pid);
            assert_eq!(read_ev.timestamp_millis, ev.timestamp_millis);
            match (&read_ev.payload, &ev.payload) {
                (
                    NetworkEventPayload::Connect {
                        socket: s1,
                        remote_addr: r1,
                        success: sc1,
                    },
                    NetworkEventPayload::Connect {
                        socket: s2,
                        remote_addr: r2,
                        success: sc2,
                    },
                ) => {
                    assert_eq!(s1, s2);
                    assert_eq!(r1, r2);
                    assert_eq!(sc1, sc2);
                }
                (
                    NetworkEventPayload::Data {
                        socket: s1,
                        direction: d1,
                        bytes: b1,
                    },
                    NetworkEventPayload::Data {
                        socket: s2,
                        direction: d2,
                        bytes: b2,
                    },
                ) => {
                    assert_eq!(s1, s2);
                    assert_eq!(d1, d2);
                    assert_eq!(b1, b2);
                }
                (
                    NetworkEventPayload::Close { socket: s1 },
                    NetworkEventPayload::Close { socket: s2 },
                ) => {
                    assert_eq!(s1, s2);
                }
                _ => panic!("Payload variant mismatch"),
            }
        }
    }

    #[test]
    fn test_truncated_header() {
        // Only 2 bytes instead of 4
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
        // Header says length is 10, but only 3 bytes of payload provided
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
        // Valid length, but corrupted bincode payload
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
            timestamp_millis: 10,
            payload: NetworkEventPayload::Close { socket: 11 },
        };
        let ev2 = InterceptedEvent {
            pid: 2,
            timestamp_millis: 20,
            payload: NetworkEventPayload::Close { socket: 22 },
        };
        let ev3 = InterceptedEvent {
            pid: 3,
            timestamp_millis: 30,
            payload: NetworkEventPayload::Close { socket: 33 },
        };

        let mut stream = Vec::new();
        write_frame(&mut stream, &ev1).unwrap();
        write_frame(&mut stream, &ev2).unwrap();
        write_frame(&mut stream, &ev3).unwrap();

        let mut cursor = Cursor::new(stream);
        let r1 = read_frame(&mut cursor).unwrap().expect("ev1");
        assert_eq!(r1.pid, 1);

        let r2 = read_frame(&mut cursor).unwrap().expect("ev2");
        assert_eq!(r2.pid, 2);

        let r3 = read_frame(&mut cursor).unwrap().expect("ev3");
        assert_eq!(r3.pid, 3);

        let eof = read_frame(&mut cursor).unwrap();
        assert!(eof.is_none());
    }
}
