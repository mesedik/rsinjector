use std::{mem::*, ffi::c_void};

use anyhow::Context;
use clap::{arg, Command};

use windows::{
    core::*, Win32::{Foundation::*, System::Diagnostics::ToolHelp::*}, Win32::System::Threading::*,
    Win32::System::LibraryLoader::*,
    Win32::System::Memory::*, Win32::System::Diagnostics::Debug::*
};

fn win32_str_to_rust_str(win32_string: &[CHAR]) -> String {
    let mut s = String::new();
    for c in win32_string.into_iter() {
        // null terminator
        if c.0 == 0 {
            break;
        }
        s.push(c.0 as char);
    }
    return s;
}

fn win32_error(message: &str) -> anyhow::Error {
    unsafe {
        return windows::core::Error::new(GetLastError().into(), message.into()).into();
    }
}

fn get_process_entry_from_name(name: &String) -> anyhow::Result<PROCESSENTRY32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).context("Failed to create a snapshot of the processes on the system")?;

        let mut entry: PROCESSENTRY32 = Default::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        let mut result = Process32First(snapshot, &mut entry);

        // do while loop basically
        loop {
            if !result.as_bool() {
                return Err(win32_error("Failed to get an entry for any running processes"));
            }

            let process_name = win32_str_to_rust_str(&entry.szExeFile);

            if process_name == *name {
                CloseHandle(snapshot);
                return Ok(entry);
            }

            result = Process32Next(snapshot, &mut entry);

            if !result.as_bool() {
                break;
            }
        }

        CloseHandle(snapshot);
        return Err(anyhow::anyhow!("'{name}' is not currently running."));
    }
}

fn inject(process_entry: PROCESSENTRY32, dll_path: &String) -> anyhow::Result<()> {
    unsafe {
        let kernel32_module = GetModuleHandleA(s!("Kernel32"))?;

        let handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID)?;

        let dll_path_addr = VirtualAllocEx(handle, None, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (dll_path_addr as isize) == 0 {
            return Err(win32_error("Failed to allocate any memory in the process"));
        }

        let result = WriteProcessMemory(handle, dll_path_addr, dll_path.as_ptr() as *const c_void, dll_path.len(), None);
        if !result.as_bool() {
            VirtualFreeEx(handle, dll_path_addr, 0, MEM_RELEASE);
            CloseHandle(handle);
            return Err(win32_error("Failed to write any memory in the process."));
        }

        let load_library = GetProcAddress(kernel32_module, s!("LoadLibraryA")).context("Failed to find the address for 'LoadLibraryA' in the process")?;

        // this might not be necessary as GetProcAddress already returns a Result<>
        if load_library as usize == 0 {
            return Err(win32_error("Failed to find the address for 'LoadLibraryA' in the process"));
        }

        let thread = CreateRemoteThread(handle, None, 0, transmute(load_library), Some(dll_path_addr), 0, None).context("Failed to create a remote thread in the process")?;

        // this might not be necessary as GetProcAddress already return a Result<>
        if thread.is_invalid() {
            return Err(win32_error("Failed to create a remote thread in the process"));
        }

        let success = WaitForSingleObject(thread, 0);

        if success == WAIT_FAILED {
            return Err(win32_error("Failed to create a remote thread in the process"));
        }

        return Ok(());
    }
}

fn main() -> anyhow::Result<()> {
    let matches = Command::new("rsinjector")
        .version("1.0")
        .about("Inject a DLL into a process")
        .arg(arg!(-d --dll <DLL_PATH>).required(true))
        .arg(arg!(-p --process_name <PROCESS_NAME>).required(true))
        .get_matches();

    let process_name = matches.get_one::<String>("process_name").expect("required");
    let dll_path = matches.get_one::<String>("dll").expect("required");

    let abs_dll_path = match std::fs::canonicalize(dll_path) {
        Ok(path) => String::from(path.to_str().unwrap()),
        Err(_) => return Err(anyhow::anyhow!("Failed to get the absolute path to '{}'", dll_path))
    };

    let entry = get_process_entry_from_name(&process_name)?;
    inject(entry, &abs_dll_path)?;

    return Ok(());
}