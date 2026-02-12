/*
 * NOSP Rust Core - Process Memory Analysis Module
 * Detects process hollowing, injection, and hooking attacks
 * Advanced memory forensics for threat detection
 */

use std::mem;
use std::ptr;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{
    HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use winapi::um::handleapi::CloseHandle;
use winapi::shared::minwindef::FALSE;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub is_executable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessMemoryInfo {
    pub pid: u32,
    pub total_executable_pages: usize,
    pub writable_executable_pages: usize,
    pub suspicious_regions: Vec<MemoryRegion>,
    pub hollowing_detected: bool,
    pub injection_detected: bool,
    pub hook_detected: bool,
    pub risk_score: f32,
}

pub fn scan_process_memory(pid: u32) -> Result<ProcessMemoryInfo, String> {
    unsafe {
        let handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        
        if handle.is_null() {
            return Err(format!("Failed to open process {}", pid));
        }

        let mut info = ProcessMemoryInfo {
            pid,
            total_executable_pages: 0,
            writable_executable_pages: 0,
            suspicious_regions: Vec::new(),
            hollowing_detected: false,
            injection_detected: false,
            hook_detected: false,
            risk_score: 0.0,
        };

        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();

        loop {
            let result = VirtualQueryEx(
                handle,
                address as *const _,
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                let is_executable = is_executable_protection(mbi.Protect);
                let is_writable = is_writable_protection(mbi.Protect);

                if is_executable {
                    info.total_executable_pages += 1;

                    if is_writable {
                        info.writable_executable_pages += 1;
                        
                        let region = MemoryRegion {
                            base_address: mbi.BaseAddress as usize,
                            size: mbi.RegionSize,
                            protection: mbi.Protect,
                            is_executable,
                            is_writable,
                        };
                        
                        info.suspicious_regions.push(region);
                    }

                    if is_potential_hollowing(handle, mbi.BaseAddress as usize, mbi.RegionSize) {
                        info.hollowing_detected = true;
                    }

                    if is_potential_hook(handle, mbi.BaseAddress as usize, mbi.RegionSize) {
                        info.hook_detected = true;
                    }
                }
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
        }

        CloseHandle(handle);

        info.injection_detected = info.writable_executable_pages > 0;

        info.risk_score = calculate_memory_risk(&info);

        Ok(info)
    }
}

fn is_executable_protection(protect: u32) -> bool {
    (protect & PAGE_EXECUTE) != 0
        || (protect & PAGE_EXECUTE_READ) != 0
        || (protect & PAGE_EXECUTE_READWRITE) != 0
        || (protect & PAGE_EXECUTE_WRITECOPY) != 0
}

fn is_writable_protection(protect: u32) -> bool {
    (protect & PAGE_EXECUTE_READWRITE) != 0 || (protect & PAGE_EXECUTE_WRITECOPY) != 0
}

fn is_potential_hollowing(handle: HANDLE, address: usize, size: usize) -> bool {
    unsafe {
        let mut buffer = vec![0u8; std::cmp::min(size, 4096)];
        let mut bytes_read = 0;

        let success = ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            &mut bytes_read,
        );

        if success == 0 || bytes_read < 2 {
            return false;
        }

        if buffer[0] == 0x4D && buffer[1] == 0x5A {
            return true;
        }

        let nop_count = buffer.iter().take(50).filter(|&&b| b == 0x90).count();
        if nop_count > 30 {
            return true;
        }

        false
    }
}

fn is_potential_hook(handle: HANDLE, address: usize, size: usize) -> bool {
    unsafe {
        let mut buffer = vec![0u8; std::cmp::min(size, 256)];
        let mut bytes_read = 0;

        let success = ReadProcessMemory(
            handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            buffer.len(),
            &mut bytes_read,
        );

        if success == 0 || bytes_read < 5 {
            return false;
        }

        if buffer[0] == 0xE9 {
            return true;
        }

        if buffer[0] == 0x68 && buffer.len() > 5 && buffer[5] == 0xC3 {
            return true;
        }

        if buffer[0] == 0x48
            && buffer[1] == 0xB8
            && buffer.len() > 11
            && buffer[10] == 0xFF
            && buffer[11] == 0xE0
        {
            return true;
        }

        false
    }
}

fn calculate_memory_risk(info: &ProcessMemoryInfo) -> f32 {
    let mut risk = 0.0;

    if info.writable_executable_pages > 0 {
        risk += 30.0 * (info.writable_executable_pages as f32).min(5.0);
    }

    if info.hollowing_detected {
        risk += 40.0;
    }

    if info.hook_detected {
        risk += 35.0;
    }

    risk += (info.suspicious_regions.len() as f32 * 10.0).min(30.0);

    risk.min(100.0)
}

pub fn dump_process_memory(pid: u32, output_path: &str) -> Result<(), String> {
    use std::fs::File;
    use std::io::Write;

    unsafe {
        let handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        if handle.is_null() {
            return Err(format!("Failed to open process {}", pid));
        }

        let mut dump_file =
            File::create(output_path).map_err(|e| format!("Failed to create dump file: {}", e))?;

        writeln!(dump_file, "NOSP Memory Dump - PID: {}", pid)
            .map_err(|e| format!("Write error: {}", e))?;
        writeln!(dump_file, "Timestamp: {}", chrono::Local::now())
            .map_err(|e| format!("Write error: {}", e))?;
        writeln!(dump_file, "\n--- Memory Regions ---\n")
            .map_err(|e| format!("Write error: {}", e))?;

        let mut address: usize = 0;
        let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
        let mut total_dumped = 0;

        loop {
            let result = VirtualQueryEx(
                handle,
                address as *const _,
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if result == 0 {
                break;
            }

            if mbi.State == MEM_COMMIT {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0;

                let success = ReadProcessMemory(
                    handle,
                    mbi.BaseAddress,
                    buffer.as_mut_ptr() as *mut _,
                    mbi.RegionSize,
                    &mut bytes_read,
                );

                if success != 0 && bytes_read > 0 {
                    writeln!(
                        dump_file,
                        "Region: 0x{:X} - 0x{:X} (Size: {} bytes, Protect: 0x{:X})",
                        mbi.BaseAddress as usize,
                        mbi.BaseAddress as usize + mbi.RegionSize,
                        mbi.RegionSize,
                        mbi.Protect
                    )
                    .map_err(|e| format!("Write error: {}", e))?;

                    let dump_size = bytes_read.min(256);
                    for i in (0..dump_size).step_by(16) {
                        write!(dump_file, "{:08X}: ", mbi.BaseAddress as usize + i)
                            .map_err(|e| format!("Write error: {}", e))?;
                        for j in 0..16 {
                            if i + j < dump_size {
                                write!(dump_file, "{:02X} ", buffer[i + j])
                                    .map_err(|e| format!("Write error: {}", e))?;
                            } else {
                                write!(dump_file, "   ").map_err(|e| format!("Write error: {}", e))?;
                            }
                        }
                        write!(dump_file, " | ").map_err(|e| format!("Write error: {}", e))?;
                        for j in 0..16 {
                            if i + j < dump_size {
                                let c = buffer[i + j];
                                write!(
                                    dump_file,
                                    "{}",
                                    if c >= 32 && c <= 126 {
                                        c as char
                                    } else {
                                        '.'
                                    }
                                )
                                .map_err(|e| format!("Write error: {}", e))?;
                            }
                        }
                        writeln!(dump_file).map_err(|e| format!("Write error: {}", e))?;
                    }
                    writeln!(dump_file).map_err(|e| format!("Write error: {}", e))?;

                    total_dumped += bytes_read;
                }
            }

            address = mbi.BaseAddress as usize + mbi.RegionSize;
        }

        CloseHandle(handle);

        writeln!(dump_file, "\n--- Summary ---")
            .map_err(|e| format!("Write error: {}", e))?;
        writeln!(dump_file, "Total dumped: {} bytes ({} MB)",total_dumped, total_dumped / (1024 * 1024))
            .map_err(|e| format!("Write error: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_scan() {
        let pid = std::process::id();
        let result = scan_process_memory(pid);
        assert!(result.is_ok());
        
        let info = result.unwrap();
        assert!(info.total_executable_pages > 0);
    }

    #[test]
    fn test_protection_checks() {
        assert!(is_executable_protection(PAGE_EXECUTE_READWRITE));
        assert!(is_writable_protection(PAGE_EXECUTE_READWRITE));
    }
}
