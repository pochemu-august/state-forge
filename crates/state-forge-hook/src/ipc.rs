use once_cell::sync::Lazy;
use state_forge_common::InterceptedEvent;
use std::fs::{File, OpenOptions};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static PIPE_CLIENT: Lazy<Mutex<Option<File>>> = Lazy::new(|| Mutex::new(None));
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Подключение к Named Pipe серверу CLI
pub fn init_ipc(pid: u32) -> Result<(), std::io::Error> {
    let pipe_name = format!(r"\\.\pipe\state_forge_{}", pid);
    let mut last_err = None;
    // Пробуем подключиться к пайпу
    for _ in 0..10 {
        match OpenOptions::new().write(true).open(&pipe_name) {
            Ok(file) => {
                let mut client = PIPE_CLIENT
                    .lock()
                    .map_err(|_| std::io::Error::other("PIPE_CLIENT mutex poisoned"))?;
                *client = Some(file);
                return Ok(());
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Timeout connecting to named pipe",
        )
    }))
}

/// Запись события в целевой поток с отслеживанием счетчика недоставленных событий
pub fn emit_event_to_writer<W: std::io::Write>(
    writer: Option<&mut W>,
    event: &InterceptedEvent,
    dropped_counter: &AtomicU64,
) -> Result<u64, state_forge_common::FrameError> {
    if let Some(w) = writer {
        match state_forge_common::write_frame(w, event) {
            Ok(()) => {
                let recovered = dropped_counter.swap(0, Ordering::Relaxed);
                Ok(recovered)
            }
            Err(e) => {
                dropped_counter.fetch_add(1, Ordering::Relaxed);
                crate::log_diagnostic(&format!(
                    "write_frame error: {}. Total dropped events: {}",
                    e,
                    dropped_counter.load(Ordering::Relaxed)
                ));
                Err(e)
            }
        }
    } else {
        dropped_counter.fetch_add(1, Ordering::Relaxed);
        crate::log_diagnostic(&format!(
            "IPC pipe not connected. Total dropped events: {}",
            dropped_counter.load(Ordering::Relaxed)
        ));
        Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "IPC pipe not connected").into())
    }
}

/// Отправка сериализованного события в оркестратор
pub fn emit_event(event: InterceptedEvent) {
    if let Ok(mut client_guard) = PIPE_CLIENT.lock() {
        let writer_opt = client_guard.as_mut();
        let _ = emit_event_to_writer(writer_opt, &event, &DROPPED_EVENTS);
    } else {
        DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use state_forge_common::{NetworkDirection, NetworkEventPayload};
    use std::io::Write;

    #[test]
    fn test_emit_event_to_writer_success_and_recovery() {
        let event = InterceptedEvent {
            pid: 1234,
            seq: 10,
            timestamp_millis: 5000,
            payload: NetworkEventPayload::Data {
                socket: 1,
                direction: NetworkDirection::Tx,
                original_len: 4,
                bytes: b"test".to_vec(),
            },
        };

        // 1. Успешная запись без предшествующих ошибок (dropped == 0)
        let mut buffer = Vec::new();
        let dropped = AtomicU64::new(0);
        let recovered = emit_event_to_writer(Some(&mut buffer), &event, &dropped).unwrap();
        assert_eq!(recovered, 0);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);

        // Проверяем, что кадр корректно читается из буфера
        let read_ev = state_forge_common::read_frame(&mut &buffer[..])
            .unwrap()
            .expect("event expected");
        assert_eq!(read_ev, event);

        // 2. Успешная запись после предшествующих ошибок (dropped == 5)
        // Убивает мутантов `dropped > 0` в emit_event и swap(0)
        let mut buffer2 = Vec::new();
        let dropped_with_errors = AtomicU64::new(5);
        let recovered =
            emit_event_to_writer(Some(&mut buffer2), &event, &dropped_with_errors).unwrap();
        assert_eq!(recovered, 5);
        assert_eq!(dropped_with_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_emit_event_to_writer_none_increments_dropped() {
        let event = InterceptedEvent {
            pid: 1234,
            seq: 11,
            timestamp_millis: 5001,
            payload: NetworkEventPayload::Close { socket: 1 },
        };

        // Убивает мутантов: `replace + with -` и `replace + with *` в dropped_counter.fetch_add(1) + 1
        let dropped = AtomicU64::new(0);
        let res1 = emit_event_to_writer::<Vec<u8>>(None, &event, &dropped);
        assert!(res1.is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        let res2 = emit_event_to_writer::<Vec<u8>>(None, &event, &dropped);
        assert!(res2.is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
    }

    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pipe broken",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pipe broken",
            ))
        }
    }

    #[test]
    fn test_emit_event_to_writer_io_error_increments_dropped() {
        let event = InterceptedEvent {
            pid: 1234,
            seq: 12,
            timestamp_millis: 5002,
            payload: NetworkEventPayload::Close { socket: 2 },
        };

        let mut failing = FailingWriter;
        let dropped = AtomicU64::new(0);
        let res1 = emit_event_to_writer(Some(&mut failing), &event, &dropped);
        assert!(res1.is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);

        let res2 = emit_event_to_writer(Some(&mut failing), &event, &dropped);
        assert!(res2.is_err());
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_emit_event_global_unconnected_increments_dropped() {
        // Убивает мутанта: `replace emit_event with ()`
        let event = InterceptedEvent {
            pid: 1234,
            seq: 13,
            timestamp_millis: 5003,
            payload: NetworkEventPayload::Close { socket: 3 },
        };

        let prev_dropped = DROPPED_EVENTS.load(Ordering::Relaxed);
        emit_event(event.clone());
        let mid_dropped = DROPPED_EVENTS.load(Ordering::Relaxed);
        assert_eq!(mid_dropped, prev_dropped + 1);

        emit_event(event);
        let final_dropped = DROPPED_EVENTS.load(Ordering::Relaxed);
        assert_eq!(final_dropped, prev_dropped + 2);
    }
}
