mod hooks;
mod ipc;

use std::ffi::c_void;

const DLL_PROCESS_ATTACH: u32 = 1;

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(_hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| {
            let pid = std::process::id();
            // Подключаемся к каналу IPC
            ipc::init_ipc(pid);
            // Устанавливаем перехватчики Winsock
            let _ = hooks::install_hooks();
        });
    }
    1
}
