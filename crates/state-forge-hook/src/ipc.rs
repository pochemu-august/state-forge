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

/// Отправка сериализованного события в оркестратор
pub fn emit_event(event: InterceptedEvent) {
    let mut client_guard = match PIPE_CLIENT.lock() {
        Ok(guard) => guard,
        Err(_) => {
            let dropped = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
            crate::log_diagnostic(&format!(
                "PIPE_CLIENT mutex poisoned. Total dropped events: {}",
                dropped
            ));
            return;
        }
    };

    if let Some(ref mut file) = *client_guard {
        match state_forge_common::write_frame(file, &event) {
            Ok(()) => {
                let dropped = DROPPED_EVENTS.swap(0, Ordering::Relaxed);
                if dropped > 0 {
                    crate::log_diagnostic(&format!(
                        "IPC pipe recovered. Note: {} events were dropped during previous errors.",
                        dropped
                    ));
                }
            }
            Err(e) => {
                let dropped = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
                crate::log_diagnostic(&format!(
                    "write_frame error: {}. Total dropped events: {}",
                    e, dropped
                ));
            }
        }
    } else {
        let dropped = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
        crate::log_diagnostic(&format!(
            "IPC pipe not connected. Total dropped events: {}",
            dropped
        ));
    }
}
