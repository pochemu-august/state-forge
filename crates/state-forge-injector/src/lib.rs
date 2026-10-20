use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, INFINITE, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, WaitForSingleObject,
};

/// Внедряет динамическую библиотеку DLL в целевой процесс по PID
pub fn inject_dll(pid: u32, dll_path: &Path) -> Result<(), String> {
    let canonical_path = std::fs::canonicalize(dll_path)
        .map_err(|e| format!("Не удалось канонизировать путь к DLL: {}", e))?;

    // Преобразуем путь в UTF-16 wide string с null-терминатором
    let wide_path: Vec<u16> = OsStr::new(canonical_path.as_os_str())
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
            return Err(format!(
                "OpenProcess({}) завершился с ошибкой: {}",
                pid, err
            ));
        }

        // Выделяем память в целевом процессе
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
            return Err(format!("VirtualAllocEx завершился с ошибкой: {}", err));
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
        if write_ok == 0 {
            let err = GetLastError();
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!("WriteProcessMemory завершился с ошибкой: {}", err));
        }

        // Находим LoadLibraryW в kernel32.dll
        let kernel32 = GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8);
        if kernel32.is_null() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err("GetModuleHandleA(kernel32.dll) вернул null".into());
        }

        let load_library_w = GetProcAddress(kernel32, c"LoadLibraryW".as_ptr() as *const u8);
        if load_library_w.is_none() {
            VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err("GetProcAddress(LoadLibraryW) не найден".into());
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
            return Err(format!("CreateRemoteThread завершился с ошибкой: {}", err));
        }

        // Дожидаемся завершения инициализации LoadLibraryW
        WaitForSingleObject(thread, INFINITE);

        // Освобождаем дескрипторы и память под строку пути
        CloseHandle(thread);
        VirtualFreeEx(process, remote_mem, 0, MEM_RELEASE);
        CloseHandle(process);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_inject_nonexistent_dll() {
        let res = inject_dll(1234, Path::new("non_existent_state_forge_xyz.dll"));
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Не удалось канонизировать"));
    }

    #[test]
    fn test_inject_invalid_pid() {
        // Создаем временный существующий файл, чтобы проверка пути прошла
        let temp_dir = std::env::temp_dir();
        let dummy_path = temp_dir.join("state_forge_test_dummy.dll");
        let _ = std::fs::write(&dummy_path, b"DUMMY");

        // Несуществующий PID в Windows
        let invalid_pid = 0xFFFF_FFFE;
        let res = inject_dll(invalid_pid, &dummy_path);
        let _ = std::fs::remove_file(&dummy_path);

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("OpenProcess"));
    }
}
