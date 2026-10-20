use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{sleep, spawn};
use std::time::Duration;

fn start_local_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind local test server");
    let port = listener.local_addr().unwrap().port();

    spawn(move || {
        for mut socket in listener.incoming().flatten() {
            let mut buf = [0u8; 1024];
            if let Ok(n) = socket.read(&mut buf)
                && n > 0
            {
                // Эхо-ответ от сервера
                let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nConnection: close\r\n\r\nHello from Target!";
                let _ = socket.write_all(response);
                let _ = socket.flush();
            }
        }
    });

    port
}

fn main() {
    let pid = std::process::id();
    let local_port = start_local_echo_server();

    println!("══════════════════════════════════════════════════════════");
    println!("  Test Target Process (Winsock traffic generator)");
    println!("  PID: {}", pid);
    println!("  Local Echo Server running on: 127.0.0.1:{}", local_port);
    println!("  Запустите перехватчик в другом окне терминала:");
    println!("    cargo run -p state-forge-cli -- {}", pid);
    println!("  или:");
    println!("    .\\analyze.bat run {}", pid);
    println!("══════════════════════════════════════════════════════════");
    println!("Нажмите ENTER после подключения перехватчика для отправки сетевых пакетов...");

    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);

    println!(
        "[*] Подключение к локальному серверу 127.0.0.1:{}...",
        local_port
    );
    match TcpStream::connect(format!("127.0.0.1:{}", local_port)) {
        Ok(mut stream) => {
            println!("[+] Соединение успешно установлено!");
            let request = b"POST /api/v1/state HTTP/1.1\r\nHost: localhost\r\nUser-Agent: state-forge-client\r\nContent-Length: 17\r\n\r\n{\"action\":\"sync\"}";
            println!("[*] Отправка запроса ({} байт)...", request.len());
            if let Err(e) = stream.write_all(request) {
                eprintln!("[-] Ошибка отправки: {}", e);
            }

            let mut buffer = [0u8; 1024];
            match stream.read(&mut buffer) {
                Ok(n) => {
                    println!("[+] Успешно получено {} байт ответа от сервера!", n);
                    let resp_str = String::from_utf8_lossy(&buffer[..n]);
                    println!("    Ответ:\n{}", resp_str);
                }
                Err(e) => {
                    eprintln!("[-] Ошибка чтения ответа: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Ошибка подключения: {}", e);
        }
    }

    println!("Завершено. Процесс удерживается 5 секунд перед выходом...");
    sleep(Duration::from_secs(5));
}
