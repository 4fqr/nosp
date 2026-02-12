

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::Win32::Foundation::{BOOL, HANDLE, NTSTATUS, CloseHandle};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
};
use windows::Win32::System::Diagnostics::Debug::{
    CheckRemoteDebuggerPresent
};
use windows::core::PCWSTR;

type NtSetInformationProcessFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: u32,
    ProcessInformation: *const std::ffi::c_void,
    ProcessInformationLength: u32,
) -> NTSTATUS;

const PROCESS_INFORMATION_CLASS_CRITICAL: u32 = 29;


pub fn enable_critical_process() -> Result<(), String> {
    unsafe {
        let ntdll = windows::Win32::Foundation::GetModuleHandleW(
            PCWSTR::from_raw("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())
        );

        if ntdll.is_err() {
            return Err("Failed to load ntdll.dll".to_string());
        }

        let proc_name = "NtSetInformationProcess\0";
        let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll.unwrap(),
            windows::core::PCSTR(proc_name.as_ptr())
        );

        if proc_addr.is_none() {
            return Err("Failed to find NtSetInformationProcess".to_string());
        }

        let nt_set_info: NtSetInformationProcessFn = std::mem::transmute(proc_addr);

        let mut critical_flag: u32 = 1;
        let status = nt_set_info(
            GetCurrentProcess(),
            PROCESS_INFORMATION_CLASS_CRITICAL,
            &critical_flag as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32
        );

        if status.0 >= 0 {
            Ok(())
        } else {
            Err(format!("NtSetInformationProcess failed: 0x{:08X}", status.0))
        }
    }
}


pub fn disable_critical_process() -> Result<(), String> {
    unsafe {
        let ntdll = windows::Win32::Foundation::GetModuleHandleW(
            PCWSTR::from_raw("ntdll.dll\0".encode_utf16().collect::<Vec<u16>>().as_ptr())
        );

        if ntdll.is_err() {
            return Err("Failed to load ntdll.dll".to_string());
        }

        let proc_name = "NtSetInformationProcess\0";
        let proc_addr = windows::Win32::System::LibraryLoader::GetProcAddress(
            ntdll.unwrap(),
            windows::core::PCSTR(proc_name.as_ptr())
        );

        if proc_addr.is_none() {
            return Err("Failed to find NtSetInformationProcess".to_string());
        }

        let nt_set_info: NtSetInformationProcessFn = std::mem::transmute(proc_addr);

        let mut critical_flag: u32 = 0;
        let status = nt_set_info(
            GetCurrentProcess(),
            PROCESS_INFORMATION_CLASS_CRITICAL,
            &critical_flag as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32
        );

        if status.0 >= 0 {
            Ok(())
        } else {
            Err(format!("NtSetInformationProcess failed: 0x{:08X}", status.0))
        }
    }
}


pub fn is_debugger_present() -> Result<bool, String> {
    unsafe {
        let mut debugger_present: BOOL = BOOL(0);

        let result = CheckRemoteDebuggerPresent(
            GetCurrentProcess(),
            &mut debugger_present
        );

        if result.is_ok() {
            Ok(debugger_present.as_bool())
        } else {
            Err("CheckRemoteDebuggerPresent failed".to_string())
        }
    }
}


pub fn detect_handle_attempts() -> Result<Vec<(u32, u32)>, String> {
    let current_pid = std::process::id();
    let mut suspicious_handles = Vec::new();

    unsafe {
        use windows::Win32::System::Threading::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESS_ALL_ACCESS, TH32CS_SNAPPROCESS, PROCESSENTRY32W
        };

        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| format!("CreateToolhelp32Snapshot failed: {}", e))?;

        let mut pe32 = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut pe32).is_ok() {
            loop {
                let pid = pe32.th32ProcessID;

                if pid != current_pid {
                    let handle = OpenProcess(
                        PROCESS_QUERY_INFORMATION,
                        BOOL(0),
                        pid
                    );

                    if let Ok(h) = handle {

                        let _ = CloseHandle(h);
                    }
                }

                if Process32NextW(snapshot, &mut pe32).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snapshot);
    }

    Ok(suspicious_handles)
}


pub fn get_defense_status() -> std::collections::HashMap<String, String> {
    let mut status = std::collections::HashMap::new();

    match is_debugger_present() {
        Ok(true) => status.insert("debugger".to_string(), "DETECTED".to_string()),
        Ok(false) => status.insert("debugger".to_string(), "None".to_string()),
        Err(e) => status.insert("debugger".to_string(), format!("Error: {}", e))
    };

    status.insert("critical_process".to_string(), "Unknown (requires admin)".to_string());

    match detect_handle_attempts() {
        Ok(handles) => status.insert(
            "suspicious_handles".to_string(),
            format!("{} detected", handles.len())
        ),
        Err(e) => status.insert("suspicious_handles".to_string(), format!("Error: {}", e))
    };

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_detection() {
        let result = is_debugger_present();
        assert!(result.is_ok());

        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_get_defense_status() {
        let status = get_defense_status();
        assert!(status.contains_key("debugger"));
        assert!(status.contains_key("critical_process"));
        assert!(status.contains_key("suspicious_handles"));
    }
}
