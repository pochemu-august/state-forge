use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, IsWow64Process, OpenProcess, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    WaitForSingleObject,
};

/// Таймаут ожидания завершения инициализации LoadLibraryW в удаленном потоке (10 секунд)
pub const INJECTION_TIMEOUT_MS: u32 = 10_000;

/// Типизированные ошибки внедрения DLL
#[derive(Debug)]
pub enum InjectError {
    Canonicalize(std::io::Error),
    OpenProcess(u32),
    Alloc(u32),
    Write(String),
    ResolveLoadLibrary(String),
    CreateThread(String),
    WaitTimeout(u32),
    LoadLibraryFailed(String),
    ArchMismatch(String),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectError::Canonicalize(e) => write!(f, "Failed to canonicalize DLL path: {}", e),
            InjectError::OpenProcess(code) => {
                write!(f, "OpenProcess failed with Win32 error code {}", code)
            }
            InjectError::Alloc(code) => {
                write!(f, "VirtualAllocEx failed with Win32 error code {}", code)
            }
            InjectError::Write(msg) => write!(f, "WriteProcessMemory failed: {}", msg),
            InjectError::ResolveLoadLibrary(msg) => {
                write!(f, "Failed to resolve LoadLibraryW: {}", msg)
            }
            InjectError::CreateThread(msg) => write!(f, "CreateRemoteThread failed: {}", msg),
            InjectError::WaitTimeout(ms) => {
                write!(f, "Timed out waiting for remote thread after {} ms", ms)
            }
            InjectError::LoadLibraryFailed(msg) => write!(f, "LoadLibraryW failed: {}", msg),
            InjectError::ArchMismatch(msg) => write!(f, "Architecture mismatch: {}", msg),
        }
    }
}

impl std::error::Error for InjectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InjectError::Canonicalize(e) => Some(e),
            _ => None,
        }
    }
}

/// Внедряет динамическую библиотеку DLL в целевой процесс по PID
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), InjectError> {
    let canonical_path = std::fs::canonicalize(dll_path).map_err(InjectError::Canonicalize)?;

    // Срезаем префикс \\?\ у канонизированного пути, так как Win32 LoadLibraryW не всегда его поддерживает
    let path_str = canonical_path.to_string_lossy();
    let clean_path = if let Some(stripped) = path_str.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", stripped)
    } else if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        path_str.to_string()
    };

    // Преобразуем путь в UTF-16 wide string с null-терминатором
    let wide_path: Vec<u16> = OsStr::new(&clean_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_bytes_len = wide_path.len() * std::mem::size_of::<u16>();

    unsafe {
        let process = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            0,
            pid,
        );
        if process.is_null() {
            let err = GetLastError();
            return Err(InjectError::OpenProcess(err));
        }

        // Проверяем разрядность целевого процесса
        let mut is_target_wow64: i32 = 0;
        if IsWow64Process(process, &mut is_target_wow64) == 0 {
            let err = GetLastError();
            CloseHandle(process);
            return Err(InjectError::OpenProcess(err));
        }

        #[cfg(target_pointer_width = "64")]
        if is_target_wow64 != 0 {
            CloseHandle(process);
            return Err(InjectError::ArchMismatch(
                "Target process is 32-bit (running under WOW64), but injector and DLL are 64-bit"
                    .to_string(),
            ));
        }

        #[cfg(target_pointer_width = "32")]
        {
            let mut is_self_wow64: i32 = 0;
            let cur_proc = windows_sys::Win32::System::Threading::GetCurrentProcess();
            if IsWow64Process(cur_proc, &mut is_self_wow64) != 0
                && is_self_wow64 != 0
                && is_target_wow64 == 0
            {
                CloseHandle(process);
                return Err(InjectError::ArchMismatch(
                    "Target process is 64-bit, but injector and DLL are 32-bit".to_string(),
                ));
            }
        }

        // Выделяем память в целевом процессе под строку пути
        let remote_mem = VirtualAllocEx(
            process,
            std::ptr::null(),
            path_bytes_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_mem.is_null() {
            let err = GetLastError();
            CloseHandle(process);
            return Err(InjectError::Alloc(err));
        }

        // Записываем путь к DLL в память целевого процесса
        let mut bytes_written = 0;
        let write_ok = WriteProcessMemory(
            process,
            remote_mem,
            wide_path.as_ptr() as *const _,
            path_bytes_len,
            &mut bytes_written,
        );
        if write_ok == 0 || bytes_written != path_bytes_len {
            let err = GetLastError();
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(InjectError::Write(format!(
                "WriteProcessMemory failed (write_ok={}, written={}, expected={}): Win32 error {}",
                write_ok, bytes_written, path_bytes_len, err
            )));
        }

        // Находим LoadLibraryW в kernel32.dll
        let kernel32 = GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8);
        if kernel32.is_null() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(InjectError::ResolveLoadLibrary(
                "GetModuleHandleA(kernel32.dll) returned null".to_string(),
            ));
        }

        let load_library_w = GetProcAddress(kernel32, c"LoadLibraryW".as_ptr() as *const u8);
        if load_library_w.is_none() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(InjectError::ResolveLoadLibrary(
                "GetProcAddress(LoadLibraryW) not found".to_string(),
            ));
        }

        type ThreadStartRoutine = unsafe extern "system" fn(*mut std::ffi::c_void) -> u32;
        let start_routine: Option<ThreadStartRoutine> = std::mem::transmute(load_library_w);

        // Запускаем LoadLibraryW в удаленном потоке
        let thread = CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            start_routine,
            remote_mem,
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            let err = GetLastError();
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(InjectError::CreateThread(format!(
                "CreateRemoteThread failed with Win32 error {}",
                err
            )));
        }

        // Дожидаемся завершения инициализации LoadLibraryW с ограничением по таймауту
        let wait_res = WaitForSingleObject(thread, INJECTION_TIMEOUT_MS);
        if wait_res == WAIT_TIMEOUT {
            // При таймауте НЕ освобождаем remote_mem, чтобы не вызвать сбой в еще выполняющемся потоке
            CloseHandle(thread);
            CloseHandle(process);
            return Err(InjectError::WaitTimeout(INJECTION_TIMEOUT_MS));
        }
        if wait_res != WAIT_OBJECT_0 {
            let err = GetLastError();
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(thread);
            CloseHandle(process);
            return Err(InjectError::CreateThread(format!(
                "WaitForSingleObject failed (wait_res={}): Win32 error {}",
                wait_res, err
            )));
        }

        // Проверяем код возврата удаленного потока
        let mut exit_code: u32 = 0;
        let get_exit_ok = GetExitCodeThread(thread, &mut exit_code);
        let last_err = GetLastError();

        // Удаленный поток завершился, теперь безопасно освободить память под строку пути
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(thread);
        CloseHandle(process);

        if get_exit_ok == 0 {
            return Err(InjectError::CreateThread(format!(
                "GetExitCodeThread failed with Win32 error {}",
                last_err
            )));
        }

        if exit_code == 0 {
            return Err(InjectError::LoadLibraryFailed(
                "LoadLibraryW returned NULL in remote thread. Remote GetLastError is unavailable; possible causes: architecture mismatch (32/64-bit), missing DLL dependencies (e.g. VC++ runtime), missing file or permissions, or antivirus/EDR blocking.".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn get_temp_dummy_dll() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        let filename = format!(
            "state_forge_test_dummy_{}_{}.dll",
            std::process::id(),
            count
        );
        let path = std::env::temp_dir().join(filename);
        std::fs::write(&path, b"DUMMY").expect("Failed to write dummy DLL");
        path
    }

    #[test]
    fn test_inject_nonexistent_dll() {
        let res = inject_dll(1234, Path::new("non_existent_state_forge_xyz_123.dll"));
        assert!(matches!(res, Err(InjectError::Canonicalize(_))));
    }

    #[test]
    fn test_inject_invalid_pid() {
        let dummy_path = get_temp_dummy_dll();
        let invalid_pid = 0xFFFF_FFFE;
        let res = inject_dll(invalid_pid, &dummy_path);
        let _ = std::fs::remove_file(&dummy_path);

        assert!(matches!(res, Err(InjectError::OpenProcess(_))));
    }

    #[test]
    fn test_inject_system_process() {
        let dummy_path = get_temp_dummy_dll();
        // PID 4 — это системный процесс ядра Windows (System). Доступ к нему с PROCESS_VM_WRITE запрещен.
        let res = inject_dll(4, &dummy_path);
        let _ = std::fs::remove_file(&dummy_path);

        assert!(matches!(res, Err(InjectError::OpenProcess(_))));
    }

    #[test]
    #[cfg(windows)]
    fn test_integration_inject_child_process() {
        use state_forge_common::{InterceptedEvent, NetworkDirection, NetworkEventPayload};
        use std::ffi::OsStr;
        use std::io::Write;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;
        use std::path::PathBuf;
        use std::sync::OnceLock;
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        };
        const PIPE_ACCESS_INBOUND: u32 = 1;

        static BUILD_ONCE: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

        let (hook_dll, test_target) = BUILD_ONCE.get_or_init(|| {
            let cargo = env!("CARGO");
            let status = std::process::Command::new(cargo)
                .args(["build", "-p", "state-forge-hook", "-p", "test-target"])
                .status()
                .expect("Failed to execute cargo build for test dependencies");
            assert!(
                status.success(),
                "cargo build for state-forge-hook and test-target must succeed, exit status: {:?}",
                status
            );

            let mut candidates = vec![
                PathBuf::from("../../target/debug"),
                PathBuf::from("target/debug"),
            ];
            if let Ok(cargo_manifest) = std::env::var("CARGO_MANIFEST_DIR") {
                candidates.push(
                    PathBuf::from(cargo_manifest)
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join("target")
                        .join("debug"),
                );
            }

            let mut hook_dll_opt = None;
            let mut test_target_opt = None;

            for base in candidates {
                let dll = base.join("state_forge_hook.dll");
                let exe = base.join("test-target.exe");
                if dll.exists() && hook_dll_opt.is_none() {
                    hook_dll_opt = Some(dll);
                }
                if exe.exists() && test_target_opt.is_none() {
                    test_target_opt = Some(exe);
                }
            }

            let hook_dll = hook_dll_opt.expect(
                "state_forge_hook.dll not found in target/debug! Build step must produce it.",
            );
            let test_target = test_target_opt
                .expect("test-target.exe not found in target/debug! Build step must produce it.");

            (hook_dll, test_target)
        });

        // Guard с Drop убивает дочерний процесс при любом исходе теста
        struct ChildGuard(Option<std::process::Child>);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let mut child = std::process::Command::new(test_target)
            .arg("--wait-stdin")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to spawn test-target child process");

        let pid = child.id();
        let mut stdin = child.stdin.take().expect("Child stdin must be piped");
        let guard = ChildGuard(Some(child));

        // c) Создаем Named Pipe сервер \\.\pipe\state_forge_<PID> ДО инъекции
        let pipe_name = format!(r"\\.\pipe\state_forge_{}", pid);
        let wide_pipe_name: Vec<u16> = OsStr::new(&pipe_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let pipe_handle = unsafe {
            CreateNamedPipeW(
                wide_pipe_name.as_ptr(),
                PIPE_ACCESS_INBOUND,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                65536,
                65536,
                10000,
                std::ptr::null(),
            )
        };
        assert_ne!(
            pipe_handle,
            INVALID_HANDLE_VALUE,
            "CreateNamedPipeW failed with Win32 error {}",
            unsafe { GetLastError() }
        );

        // e) Читаем кадры через read_frame в отдельном потоке
        let (tx, rx) = std::sync::mpsc::channel::<InterceptedEvent>();
        let (connected_tx, connected_rx) = std::sync::mpsc::channel::<()>();
        let pipe_raw = pipe_handle as isize;
        let reader_thread = std::thread::spawn(move || {
            let handle = pipe_raw as windows_sys::Win32::Foundation::HANDLE;
            let res = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
            let err = unsafe { GetLastError() };
            // res != 0 means success; res == 0 with err == 535 (ERROR_PIPE_CONNECTED) means already connected
            if res == 0 && err != 535 {
                return;
            }
            let _ = connected_tx.send(());
            let mut file = unsafe { std::fs::File::from_raw_handle(handle as _) };
            loop {
                match state_forge_common::read_frame(&mut file) {
                    Ok(Some(event)) => {
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });

        // d) inject_dll, затем отправляем в stdin перевод строки
        let inject_res = inject_dll(pid, hook_dll);
        assert!(
            inject_res.is_ok(),
            "Expected successful DLL injection into child process, got: {:?}",
            inject_res
        );

        // Дожидаемся подключения IPC от внедренной DLL
        let _ = connected_rx.recv_timeout(Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(100));

        stdin
            .write_all(b"\n")
            .expect("Failed to write newline to test-target stdin");
        stdin.flush().expect("Failed to flush test-target stdin");

        // e) Читаем кадры до таймаута 10 с или пока не увидишь Close для клиентского сокета
        let timeout = Duration::from_secs(10);
        let start = Instant::now();
        let mut events: Vec<InterceptedEvent> = Vec::new();
        let mut client_socket: Option<u64> = None;

        while start.elapsed() < timeout {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(event) => {
                    if let NetworkEventPayload::Connect {
                        socket,
                        success: true,
                        ..
                    } = event.payload
                        && client_socket.is_none()
                    {
                        client_socket = Some(socket);
                    }

                    let is_client_close = match &event.payload {
                        NetworkEventPayload::Close { socket } => Some(*socket) == client_socket,
                        _ => false,
                    };

                    events.push(event);

                    if is_client_close {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        // Завершаем дочерний процесс через guard
        drop(guard);
        let _ = reader_thread.join();

        // f) Ассерты:
        // 1. Минимум одно Connect с remote_addr 127.0.0.1 и success=true
        let connect_event = events.iter().find(|e| {
            if let NetworkEventPayload::Connect {
                remote_addr: Some(addr),
                success,
                ..
            } = &e.payload
            {
                *success && addr.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
            } else {
                false
            }
        });
        assert!(
            connect_event.is_some(),
            "Expected at least one Connect event with remote_addr 127.0.0.1 and success=true. Intercepted events: {:?}",
            events
        );

        // 2. Минимум одно Data Tx, чей bytes содержит b"POST /api/v1/state"
        let tx_event = events.iter().find(|e| {
            if let NetworkEventPayload::Data {
                direction: NetworkDirection::Tx,
                bytes,
                ..
            } = &e.payload
            {
                bytes
                    .windows(b"POST /api/v1/state".len())
                    .any(|w| w == b"POST /api/v1/state")
            } else {
                false
            }
        });
        assert!(
            tx_event.is_some(),
            "Expected at least one Data Tx event containing b\"POST /api/v1/state\". Intercepted events: {:?}",
            events
        );

        // 3. Минимум одно Data Rx, чей bytes содержит b"HTTP/1.1 200 OK"
        let rx_event = events.iter().find(|e| {
            if let NetworkEventPayload::Data {
                direction: NetworkDirection::Rx,
                bytes,
                ..
            } = &e.payload
            {
                bytes
                    .windows(b"HTTP/1.1 200 OK".len())
                    .any(|w| w == b"HTTP/1.1 200 OK")
            } else {
                false
            }
        });
        assert!(
            rx_event.is_some(),
            "Expected at least one Data Rx event containing b\"HTTP/1.1 200 OK\". Intercepted events: {:?}",
            events
        );

        // 4. Все seq различны
        let mut seen_seqs = std::collections::HashSet::new();
        for e in &events {
            assert!(
                seen_seqs.insert(e.seq),
                "Duplicate seq detected: {} in event {:?}",
                e.seq,
                e
            );
        }

        // 5. Для Tx-кадра запроса и Rx-кадра с теми же байтами у Tx seq строго меньше, чем у Rx
        let tx = tx_event.unwrap();
        let rx = rx_event.unwrap();
        assert!(
            tx.seq < rx.seq,
            "Tx seq ({}) must be strictly less than Rx seq ({})",
            tx.seq,
            rx.seq
        );

        // 6. Для каждого socket событие Close имеет seq больше, чем все его Data
        for close_event in &events {
            if let NetworkEventPayload::Close { socket } = close_event.payload {
                for data_event in &events {
                    if let NetworkEventPayload::Data {
                        socket: data_sock, ..
                    } = data_event.payload
                        && data_sock == socket
                    {
                        assert!(
                            close_event.seq > data_event.seq,
                            "For socket {}, Close seq ({}) must be strictly greater than Data seq ({})",
                            socket,
                            close_event.seq,
                            data_event.seq
                        );
                    }
                }
            }
        }
    }
}
