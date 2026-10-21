use state_forge_common::{InterceptedEvent, NetworkDirection, NetworkEventPayload};
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Поиск собранной библиотеки хука с обязательной канонизацией найденного пути
pub fn resolve_hook_dll() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(exe_path) = std::env::current_exe()
        && let Some(parent) = exe_path.parent()
    {
        candidates.push(parent.join("state_forge_hook.dll"));
    }

    candidates.push(PathBuf::from("target/debug/state_forge_hook.dll"));
    candidates.push(PathBuf::from("target/release/state_forge_hook.dll"));
    candidates.push(PathBuf::from("state_forge_hook.dll"));

    for candidate in candidates {
        if candidate.exists()
            && let Ok(canonical) = std::fs::canonicalize(&candidate)
        {
            return Some(canonical);
        }
    }

    None
}

/// Асинхронное чтение одного кадра IPC с проверкой MAX_FRAME_LEN до выделения буфера памяти
pub async fn read_frame_async<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<InterceptedEvent>, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    let mut read_bytes = 0;

    while read_bytes < 4 {
        match reader.read(&mut len_buf[read_bytes..]).await {
            Ok(0) => {
                if read_bytes == 0 {
                    return Ok(None);
                } else {
                    return Err(Box::new(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Truncated frame header",
                    )));
                }
            }
            Ok(n) => {
                read_bytes += n;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Box::new(e)),
        }
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    state_forge_common::validate_frame_len(len)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;

    let event = bincode::deserialize::<InterceptedEvent>(&payload)?;
    Ok(Some(event))
}

/// Вывод hex-дампа буфера
pub fn format_hex_dump(bytes: &[u8], max_len: usize) -> String {
    let display_len = bytes.len().min(max_len);
    let hex_part: Vec<String> = bytes[..display_len]
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let ascii_part: String = bytes[..display_len]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    if bytes.len() > max_len {
        format!(
            "{} ... [ASCII: {}... (+{} bytes)]",
            hex_part.join(" "),
            ascii_part,
            bytes.len() - max_len
        )
    } else {
        format!("{} [ASCII: {}]", hex_part.join(" "), ascii_part)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("══════════════════════════════════════════════════════════");
        eprintln!("  state-forge: Windows Winsock Network Interceptor");
        eprintln!("══════════════════════════════════════════════════════════");
        eprintln!("Использование: state-forge-cli <PID>");
        eprintln!("Пример:        state-forge-cli 1234");
        return Ok(());
    }

    let pid: u32 = args[1].parse().map_err(|_| "Некорректный PID")?;
    let pipe_name = format!(r"\\.\pipe\state_forge_{}", pid);

    // Подготовка директории и файлов для сохранения логов трафика с меткой времени
    let log_dir = Path::new("logs");
    let _ = create_dir_all(log_dir);
    let run_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let text_log_path = log_dir.join(format!("traffic_{}_{}.log", pid, run_timestamp));
    let jsonl_log_path = log_dir.join(format!("traffic_{}_{}.jsonl", pid, run_timestamp));

    info!(pid = pid, pipe = %pipe_name, "Инициализация Named Pipe сервера...");
    info!(
        log_file = %text_log_path.display(),
        jsonl_file = %jsonl_log_path.display(),
        "Логирование перехваченного трафика будет сохранено в файлы"
    );

    let mut text_log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&text_log_path)
        .ok();

    let mut jsonl_log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&jsonl_log_path)
        .ok();

    // Создаем экземпляр Named Pipe сервера
    let pipe_server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)?;

    // Находим путь к скомпилированной DLL (с обязательной канонизацией)
    let dll_path = resolve_hook_dll()
        .ok_or("Не найдена state_forge_hook.dll. Сначала выполните `cargo build --workspace`.")?;

    info!(dll = ?dll_path, "Внедрение перехватчика в процесс PID={}...", pid);
    if let Err(e) = state_forge_injector::inject_dll(pid, &dll_path) {
        eprintln!("[-] Ошибка внедрения DLL в процесс PID={}: {}", pid, e);
        return Err(e.into());
    }

    info!("DLL успешно внедрена. Ожидание подключения целевого процесса к IPC pipe...");

    // Асинхронный канал Tokio для обработки сетевых событий
    let (tx, mut rx) = mpsc::channel::<InterceptedEvent>(1024);

    // Фоновая задача логирования и анализа
    let logger_handle = tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            // Сохранение машиночитаемого JSONL для будущего стейт-машин парсера
            if let Some(ref mut jfile) = jsonl_log_file
                && let Ok(json_str) = serde_json::to_string(&event)
            {
                let _ = writeln!(jfile, "{}", json_str);
                let _ = jfile.flush();
            }

            match &event.payload {
                NetworkEventPayload::Connect {
                    socket,
                    remote_addr,
                    success,
                } => {
                    let log_line = format!(
                        "[{}] CONNECT socket={} remote={:?} success={}",
                        event.timestamp_millis, socket, remote_addr, success
                    );
                    info!(
                        socket = socket,
                        remote = ?remote_addr,
                        success = success,
                        "🔗 [CONNECT] Попытка сетевого соединения"
                    );
                    if let Some(ref mut tfile) = text_log_file {
                        let _ = writeln!(tfile, "{}", log_line);
                        let _ = tfile.flush();
                    }
                }
                NetworkEventPayload::Data {
                    socket,
                    direction,
                    bytes,
                } => {
                    let dir_str = match direction {
                        NetworkDirection::Tx => "TX >>> (SEND)",
                        NetworkDirection::Rx => "RX <<< (RECV)",
                    };
                    let dump = format_hex_dump(bytes, 48);

                    let log_line = format!(
                        "[{}] DATA socket={} dir={} bytes={} dump={}",
                        event.timestamp_millis,
                        socket,
                        dir_str,
                        bytes.len(),
                        dump
                    );
                    info!(
                        socket = socket,
                        dir = dir_str,
                        bytes = bytes.len(),
                        dump = %dump,
                        "📦 [PACKET]"
                    );
                    if let Some(ref mut tfile) = text_log_file {
                        let _ = writeln!(tfile, "{}", log_line);
                        let _ = tfile.flush();
                    }
                }
                NetworkEventPayload::Close { socket } => {
                    let log_line = format!("[{}] CLOSE socket={}", event.timestamp_millis, socket);
                    info!(socket = socket, "🔌 [CLOSE] Сокет закрыт");
                    if let Some(ref mut tfile) = text_log_file {
                        let _ = writeln!(tfile, "{}", log_line);
                        let _ = tfile.flush();
                    }
                }
            }
        }
    });

    // Ожидаем подключения от внедренной DLL с таймаутом в 15 секунд
    const PIPE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
    match tokio::time::timeout(PIPE_CONNECT_TIMEOUT, pipe_server.connect()).await {
        Ok(Ok(())) => {
            info!("Хук успешно подключился! Начат перехват сетевой активности...");
        }
        Ok(Err(e)) => {
            eprintln!("[-] Ошибка при подключении Named Pipe сервера: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            eprintln!(
                "[-] Таймаут ожидания подключения DLL перехватчика ({} с). Проверьте активность PID={} и права доступа.",
                PIPE_CONNECT_TIMEOUT.as_secs(),
                pid
            );
            return Err("Таймаут подключения целевого процесса к IPC pipe".into());
        }
    }

    let mut reader = pipe_server;

    // Цикл чтения структурированных сообщений из Named Pipe
    loop {
        match read_frame_async(&mut reader).await {
            Ok(Some(event)) => {
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                warn!("Ошибка чтения кадра IPC: {}", e);
                break;
            }
        }
    }

    // Закрываем канал передачи событий и дожидаемся завершения записи логов
    drop(tx);
    if let Err(e) = logger_handle.await {
        warn!("Ошибка ожидания задачи логирования: {}", e);
    }

    info!("Целевой процесс отключился или соединение разорвано.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_format_hex_dump_short() {
        let data = b"Hello";
        let formatted = format_hex_dump(data, 10);
        assert_eq!(formatted, "48 65 6C 6C 6F [ASCII: Hello]");
    }

    #[test]
    fn test_format_hex_dump_truncated() {
        let data = b"1234567890";
        let formatted = format_hex_dump(data, 4);
        assert!(formatted.contains("31 32 33 34 ..."));
        assert!(formatted.contains("(+6 bytes)"));
    }

    #[test]
    fn test_format_hex_dump_non_printable() {
        let data = &[0x00, 0x01, 0xFF, 0x20, 0x41];
        let formatted = format_hex_dump(data, 10);
        assert_eq!(formatted, "00 01 FF 20 41 [ASCII: ... A]");
    }

    #[tokio::test]
    async fn test_read_frame_async_roundtrip() {
        let event = InterceptedEvent {
            pid: 777,
            timestamp_millis: 123456,
            payload: NetworkEventPayload::Close { socket: 99 },
        };

        let mut buf = Vec::new();
        state_forge_common::write_frame(&mut buf, &event).unwrap();

        let mut cursor = Cursor::new(buf);
        let read = read_frame_async(&mut cursor).await.unwrap().expect("event");

        assert_eq!(read.pid, 777);
        assert_eq!(read.timestamp_millis, 123456);
        match read.payload {
            NetworkEventPayload::Close { socket } => assert_eq!(socket, 99),
            _ => panic!("Expected Close payload"),
        }
    }

    #[tokio::test]
    async fn test_read_frame_async_exceeds_max_len() {
        let excessive_len = (state_forge_common::MAX_FRAME_LEN + 1) as u32;
        let buf = excessive_len.to_le_bytes();
        let mut cursor = Cursor::new(&buf[..]);

        let res = read_frame_async(&mut cursor).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_read_frame_async_eof() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let res = read_frame_async(&mut cursor).await.unwrap();
        assert!(res.is_none());
    }
}
