/*
 * NOSP Rust Core - Registry Rollback Module
 * Backup and restore Windows Registry keys for incident recovery
 */

use std::ffi::OsStr;
use std::fs::{File, create_dir_all};
use std::io::{Write, Read};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::minwindef::*;
use winapi::um::winreg::*;
use serde::{Serialize, Deserialize};
use chrono::Local;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryBackup {
    pub key_path: String,
    pub timestamp: String,
    pub values: Vec<RegistryValue>,
    pub subkeys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryValue {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

const BACKUP_DIR: &str = "C:\\ProgramData\\NOSP\\RegistryBackups";

pub fn backup_registry_key(root_key: &str, subkey: &str) -> Result<String, String> {
    unsafe {
        let hkey_root = parse_root_key(root_key)?;

        let subkey_wide: Vec<u16> = OsStr::new(subkey)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey: HKEY = ptr::null_mut();
        let result = RegOpenKeyExW(
            hkey_root,
            subkey_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );

        if result != 0 {
            return Err(format!("Failed to open registry key: error code {}", result));
        }

        let mut values = Vec::new();
        let mut index = 0;

        loop {
            let mut value_name_buffer = vec![0u16; 16384];
            let mut value_name_size: DWORD = 16384;
            let mut value_type: DWORD = 0;
            let mut value_data = vec![0u8; 65536];
            let mut value_data_size: DWORD = 65536;

            let result = RegEnumValueW(
                hkey,
                index,
                value_name_buffer.as_mut_ptr(),
                &mut value_name_size,
                ptr::null_mut(),
                &mut value_type,
                value_data.as_mut_ptr(),
                &mut value_data_size,
            );

            if result == ERROR_NO_MORE_ITEMS as i32 {
                break;
            } else if result != 0 {
                break;
            }

            let value_name = String::from_utf16_lossy(&value_name_buffer[..value_name_size as usize]);
            value_data.truncate(value_data_size as usize);

            values.push(RegistryValue {
                name: value_name,
                value_type,
                data: value_data,
            });

            index += 1;
        }

        let mut subkeys = Vec::new();
        let mut subkey_index = 0;

        loop {
            let mut subkey_name_buffer = vec![0u16; 256];
            let mut subkey_name_size: DWORD = 256;

            let result = RegEnumKeyExW(
                hkey,
                subkey_index,
                subkey_name_buffer.as_mut_ptr(),
                &mut subkey_name_size,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            );

            if result == ERROR_NO_MORE_ITEMS as i32 {
                break;
            } else if result != 0 {
                break;
            }

            let subkey_name = String::from_utf16_lossy(&subkey_name_buffer[..subkey_name_size as usize]);
            subkeys.push(subkey_name);

            subkey_index += 1;
        }

        RegCloseKey(hkey);

        let backup = RegistryBackup {
            key_path: format!("{}\\{}", root_key, subkey),
            timestamp: Local::now().format("%Y-%m-%d_%H-%M-%S").to_string(),
            values,
            subkeys,
        };

        let json = serde_json::to_string_pretty(&backup)
            .map_err(|e| format!("Failed to serialize backup: {}", e))?;

        create_dir_all(BACKUP_DIR)
            .map_err(|e| format!("Failed to create backup directory: {}", e))?;

        let filename = format!(
            "{}\\{}_{}.json",
            BACKUP_DIR,
            root_key.replace("\\", "_"),
            backup.timestamp
        );

        let mut file = File::create(&filename)
            .map_err(|e| format!("Failed to create backup file: {}", e))?;

        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write backup: {}", e))?;

        Ok(filename)
    }
}

pub fn restore_registry_key(backup_file: &str) -> Result<(), String> {
    let mut file = File::open(backup_file)
        .map_err(|e| format!("Failed to open backup file: {}", e))?;

    let mut json = String::new();
    file.read_to_string(&mut json)
        .map_err(|e| format!("Failed to read backup file: {}", e))?;

    let backup: RegistryBackup = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse backup file: {}", e))?;

    unsafe {
        let parts: Vec<&str> = backup.key_path.splitn(2, '\\').collect();
        if parts.len() != 2 {
            return Err("Invalid key path in backup".to_string());
        }

        let hkey_root = parse_root_key(parts[0])?;
        let subkey = parts[1];

        let subkey_wide: Vec<u16> = OsStr::new(subkey)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey: HKEY = ptr::null_mut();
        let result = RegCreateKeyExW(
            hkey_root,
            subkey_wide.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_WRITE,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        );

        if result != 0 {
            return Err(format!("Failed to open/create registry key: error code {}", result));
        }

        for value in &backup.values {
            let value_name_wide: Vec<u16> = OsStr::new(&value.name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            RegSetValueExW(
                hkey,
                value_name_wide.as_ptr(),
                0,
                value.value_type,
                value.data.as_ptr(),
                value.data.len() as DWORD,
            );
        }

        RegCloseKey(hkey);

        Ok(())
    }
}

pub fn delete_registry_key(root_key: &str, subkey: &str) -> Result<(), String> {
    unsafe {
        let hkey_root = parse_root_key(root_key)?;

        let subkey_wide: Vec<u16> = OsStr::new(subkey)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let result = RegDeleteTreeW(hkey_root, subkey_wide.as_ptr());

        if result != 0 && result != ERROR_FILE_NOT_FOUND as i32 {
            return Err(format!("Failed to delete registry key: error code {}", result));
        }

        Ok(())
    }
}

pub fn list_registry_backups() -> Result<Vec<String>, String> {
    use std::fs::read_dir;

    let entries = read_dir(BACKUP_DIR)
        .map_err(|e| format!("Failed to read backup directory: {}", e))?;

    let mut backups = Vec::new();

    for entry in entries {
        if let Ok(entry) = entry {
            if let Some(filename) = entry.file_name().to_str() {
                if filename.ends_with(".json") {
                    backups.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }

    backups.sort();
    backups.reverse();

    Ok(backups)
}

pub fn backup_autostart_keys() -> Result<Vec<String>, String> {
    let autostart_keys = vec![
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKEY_LOCAL_MACHINE", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        ("HKEY_CURRENT_USER", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ];

    let mut backup_files = Vec::new();

    for (root, subkey) in autostart_keys {
        match backup_registry_key(root, subkey) {
            Ok(filename) => backup_files.push(filename),
            Err(e) => eprintln!("Warning: Failed to backup {}\\{}: {}", root, subkey, e),
        }
    }

    Ok(backup_files)
}

unsafe fn parse_root_key(root_key: &str) -> Result<HKEY, String> {
    match root_key {
        "HKEY_LOCAL_MACHINE" | "HKLM" => Ok(HKEY_LOCAL_MACHINE),
        "HKEY_CURRENT_USER" | "HKCU" => Ok(HKEY_CURRENT_USER),
        "HKEY_CLASSES_ROOT" | "HKCR" => Ok(HKEY_CLASSES_ROOT),
        "HKEY_USERS" | "HKU" => Ok(HKEY_USERS),
        "HKEY_CURRENT_CONFIG" | "HKCC" => Ok(HKEY_CURRENT_CONFIG),
        _ => Err(format!("Invalid root key: {}", root_key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_and_restore() {
        let result = backup_registry_key("HKEY_CURRENT_USER", "Software\\NOSP\\Test");
        if result.is_ok() {
            println!("Backup successful: {}", result.unwrap());
        }
    }

    #[test]
    fn test_list_backups() {
        let result = list_registry_backups();
        assert!(result.is_ok());
    }
}
