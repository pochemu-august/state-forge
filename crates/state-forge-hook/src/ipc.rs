use once_cell::sync::Lazy;
use state_forge_common::InterceptedEvent;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;

static PIPE_CLIENT: Lazy<Mutex<Option<File>>> = Lazy::new(|| Mutex::new(None));

/// Подключение к Named Pipe серверу CLI
pub fn init_ipc(pid: u32) {
    let pipe_name = format!(r"\\.\pipe\state_forge_{}", pid);
    // Пробуем подключиться к пайпу
    for _ in 0..10 {
        if let Ok(file) = OpenOptions::new().write(true).open(&pipe_name)
            && let Ok(mut client) = PIPE_CLIENT.lock()
        {
            *client = Some(file);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Отправка сериализованного события в оркестратор
pub fn emit_event(event: InterceptedEvent) {
    if let Ok(mut guard) = PIPE_CLIENT.lock()
        && let Some(ref mut file) = *guard
        && let Ok(encoded) = bincode::serialize(&event)
    {
        let len = (encoded.len() as u32).to_le_bytes();
        let _ = file.write_all(&len);
        let _ = file.write_all(&encoded);
        let _ = file.flush();
    }
}
