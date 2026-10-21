mod hooks;
mod ipc;

use std::ffi::c_void;
use std::sync::atomic::{AtomicPtr, Ordering};

const DLL_PROCESS_ATTACH: u32 = 1;

static DLL_HMODULE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

pub fn get_dll_dir() -> Option<std::path::PathBuf> {
    let hinst = DLL_HMODULE.load(Ordering::SeqCst);
    if hinst.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let len = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW(
            hinst,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len > 0 {
        let path = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..len as usize]));
        return path.parent().map(|p| p.to_path_buf());
    }
    None
}

pub fn log_diagnostic(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW(wide.as_ptr());
    }

    let pid = std::process::id();
    let filename = format!("state_forge_hook_{}.log", pid);

    let target_path = if let Some(dir) = get_dll_dir() {
        let path = dir.join(&filename);
        if std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .is_ok()
        {
            Some(path)
        } else {
            None
        }
    } else {
        None
    };

    let log_path = target_path.unwrap_or_else(|| std::env::temp_dir().join(&filename));

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        use std::io::Write;
        let _ = writeln!(f, "[{}] {}", pid, msg);
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        DLL_HMODULE.store(hinst, Ordering::SeqCst);
        std::thread::spawn(|| {
            let pid = std::process::id();
            // Подключаемся к каналу IPC
            if let Err(e) = ipc::init_ipc(pid) {
                log_diagnostic(&format!(
                    "Failed to connect IPC pipe for PID {}: {}",
                    pid, e
                ));
                return;
            }
            // Устанавливаем перехватчики Winsock
            if let Err(e) = hooks::install_hooks() {
                log_diagnostic(&format!("Failed to install hooks for PID {}: {}", pid, e));
            }
        });
    }
    1
}
