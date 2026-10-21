mod hooks;
mod ipc;

use std::ffi::c_void;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;

const DLL_PROCESS_ATTACH: u32 = 1;

fn output_debug_string(msg: &str) {
    let wide: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        OutputDebugStringW(wide.as_ptr());
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(_hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| {
            let pid = std::process::id();
            // Подключаемся к каналу IPC
            if let Err(e) = ipc::init_ipc(pid) {
                output_debug_string(&format!(
                    "[state-forge-hook] Failed to connect IPC pipe for PID {}: {}",
                    pid, e
                ));
                return;
            }
            // Устанавливаем перехватчики Winsock
            if let Err(e) = hooks::install_hooks() {
                output_debug_string(&format!(
                    "[state-forge-hook] Failed to install hooks for PID {}: {}",
                    pid, e
                ));
            }
        });
    }
    1
}
