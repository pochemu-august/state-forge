use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread::sleep;
use std::time::Duration;

fn main() {
    let pid = std::process::id();
    println!("══════════════════════════════════════════════════════════");
    println!("  Test Target Process (Winsock traffic generator)");
    println!("  PID: {}", pid);
    println!("  Запустите перехватчик в другом окне терминала:");
    println!("    cargo run -p state-forge-cli -- {}", pid);
    println!("══════════════════════════════════════════════════════════");
    println!("Нажмите ENTER после подключения перехватчика для отправки HTTP запроса...");

    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);

    println!("Подключение к example.com:80...");
    match TcpStream::connect("93.184.215.14:80") {
        Ok(mut stream) => {
            println!("Соединение установлено. Отправка HTTP-запроса...");
            let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: state-forge-test\r\nConnection: close\r\n\r\n";
            if let Err(e) = stream.write_all(request) {
                eprintln!("Ошибка отправки: {}", e);
            }

            let mut buffer = [0u8; 1024];
            match stream.read(&mut buffer) {
                Ok(n) => {
                    println!("Успешно получено {} байт ответа!", n);
                }
                Err(e) => {
                    eprintln!("Ошибка чтения: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Не удалось подключиться: {}", e);
        }
    }

    println!("Завершено. Процесс удерживается 5 секунд...");
    sleep(Duration::from_secs(5));
}
