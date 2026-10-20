use state_forge_common::{InterceptedEvent, NetworkDirection, NetworkEventPayload};
use std::path::{Path, PathBuf};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Поиск собранной библиотеки хука
fn resolve_hook_dll() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("target/debug/state_forge_hook.dll"),
        PathBuf::from("target/release/state_forge_hook.dll"),
        PathBuf::from("state_forge_hook.dll"),
    ];

    if let Ok(exe_path) = std::env::current_exe()
        && let Some(parent) = exe_path.parent()
    {
        let adjacent = parent.join("state_forge_hook.dll");
        if adjacent.exists() {
            return Some(adjacent);
        }
    }

    candidates.into_iter().find(|candidate| candidate.exists())
}

/// Вывод hex-дампа буфера
fn format_hex_dump(bytes: &[u8], max_len: usize) -> String {
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

    info!(pid = pid, pipe = %pipe_name, "Инициализация Named Pipe сервера...");

    // Создаем экземпляр Named Pipe сервера
    let pipe_server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)?;

    // Находим путь к скомпилированной DLL
    let dll_path = resolve_hook_dll()
        .ok_or("Не найдена state_forge_hook.dll. Сначала выполните `cargo build --workspace`.")?;

    info!(dll = ?dll_path, "Внедрение перехватчика в процесс PID={}...", pid);
    state_forge_injector::inject_dll(pid, Path::new(&dll_path))
        .map_err(|e| format!("Ошибка инъекции DLL: {}", e))?;

    info!("DLL успешно внедрена. Ожидание подключения целевого процесса к IPC pipe...");

    // Асинхронный канал Tokio для обработки сетевых событий
    let (tx, mut rx) = mpsc::channel::<InterceptedEvent>(1024);

    // Фоновая задача логирования и анализа
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event.payload {
                NetworkEventPayload::Connect {
                    socket,
                    remote_addr,
                    success,
                } => {
                    info!(
                        socket = socket,
                        remote = ?remote_addr,
                        success = success,
                        "🔗 [CONNECT] Попытка сетевого соединения"
                    );
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
                    let dump = format_hex_dump(&bytes, 48);

                    info!(
                        socket = socket,
                        dir = dir_str,
                        bytes = bytes.len(),
                        dump = %dump,
                        "📦 [PACKET]"
                    );
                }
                NetworkEventPayload::Close { socket } => {
                    info!(socket = socket, "🔌 [CLOSE] Сокет закрыт");
                }
            }
        }
    });

    // Ожидаем подключения от внедренной DLL
    pipe_server.connect().await?;
    info!("Хук успешно подключился! Начат перехват сетевой активности...");

    let mut reader = pipe_server;
    let mut len_buf = [0u8; 4];

    // Цикл чтения структурированных сообщений из Named Pipe
    loop {
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut payload_buf = vec![0u8; len];
        if reader.read_exact(&mut payload_buf).await.is_err() {
            break;
        }

        match bincode::deserialize::<InterceptedEvent>(&payload_buf) {
            Ok(event) => {
                if tx.send(event).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                warn!("Ошибка десериализации события IPC: {}", e);
            }
        }
    }

    info!("Целевой процесс отключился или соединение разорвано.");
    Ok(())
}
