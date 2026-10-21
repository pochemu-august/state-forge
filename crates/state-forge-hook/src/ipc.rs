use once_cell::sync::Lazy;
use state_forge_common::InterceptedEvent;
use std::fs::{File, OpenOptions};
use std::sync::Mutex;

static PIPE_CLIENT: Lazy<Mutex<Option<File>>> = Lazy::new(|| Mutex::new(None));

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
    if let Ok(mut guard) = PIPE_CLIENT.lock()
        && let Some(ref mut file) = *guard
    {
        let _ = state_forge_common::write_frame(file, &event);
    }
}
