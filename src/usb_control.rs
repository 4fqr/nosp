/*
 * NOSP Rust Core - USB Device Control Module
 * Block and monitor USB devices via Windows Device Installation API
 */

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use winapi::shared::guiddef::GUID;
use winapi::shared::minwindef::{DWORD, FALSE, TRUE};
use winapi::um::cfgmgr32::*;
use winapi::um::setupapi::*;
use winapi::um::winreg::*;

#[derive(Debug, Clone)]
pub struct USBDevice {
    pub device_id: String,
    pub description: String,
    pub manufacturer: String,
    pub is_blocked: bool,
}

/// List all USB devices
pub fn list_usb_devices() -> Result<Vec<USBDevice>, String> {
    unsafe {
        // Get GUID for USB devices
        let mut class_guid: GUID = std::mem::zeroed();
        let class_name: Vec<u16> = OsStr::new("USB")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        if SetupDiClassGuidsFromNameW(
            class_name.as_ptr(),
            &mut class_guid,
            1,
            ptr::null_mut(),
        ) == FALSE
        {
            return Err("Failed to get USB class GUID".to_string());
        }

        // Get device information set
        let dev_info = SetupDiGetClassDevsW(
            &class_guid,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT,
        );

        if dev_info == INVALID_HANDLE_VALUE {
            return Err("Failed to get device information set".to_string());
        }

        let mut devices = Vec::new();
        let mut dev_info_data: SP_DEVINFO_DATA = std::mem::zeroed();
        dev_info_data.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as DWORD;

        let mut index = 0;
        loop {
            if SetupDiEnumDeviceInfo(dev_info, index, &mut dev_info_data) == FALSE {
                break;
            }

            // Get device ID
            let mut device_id_buffer = vec![0u16; 256];
            if CM_Get_Device_IDW(
                dev_info_data.DevInst,
                device_id_buffer.as_mut_ptr(),
                256,
                0,
            ) == CR_SUCCESS
            {
                let device_id = String::from_utf16_lossy(&device_id_buffer)
                    .trim_end_matches('\0')
                    .to_string();

                // Get device description
                let description = get_device_registry_property(dev_info, &dev_info_data, SPDRP_DEVICEDESC)
                    .unwrap_or_else(|| "Unknown".to_string());

                // Get manufacturer
                let manufacturer = get_device_registry_property(dev_info, &dev_info_data, SPDRP_MFG)
                    .unwrap_or_else(|| "Unknown".to_string());

                devices.push(USBDevice {
                    device_id,
                    description,
                    manufacturer,
                    is_blocked: false,
                });
            }

            index += 1;
        }

        SetupDiDestroyDeviceInfoList(dev_info);

        Ok(devices)
    }
}

/// Get device registry property
unsafe fn get_device_registry_property(
    dev_info: HDEVINFO,
    dev_info_data: &SP_DEVINFO_DATA,
    property: DWORD,
) -> Option<String> {
    let mut buffer = vec![0u16; 256];
    let mut data_type: DWORD = 0;
    let mut required_size: DWORD = 0;

    if SetupDiGetDeviceRegistryPropertyW(
        dev_info,
        dev_info_data as *const _ as *mut _,
        property,
        &mut data_type,
        buffer.as_mut_ptr() as *mut u8,
        (buffer.len() * 2) as DWORD,
        &mut required_size,
    ) != FALSE
    {
        Some(
            String::from_utf16_lossy(&buffer)
                .trim_end_matches('\0')
                .to_string(),
        )
    } else {
        None
    }
}

/// Block USB device by device ID (requires Administrator)
pub fn block_usb_device(device_id: &str) -> Result<(), String> {
    unsafe {
        // Convert device ID to wide string
        let device_id_wide: Vec<u16> = OsStr::new(device_id)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Disable device
        let result = CM_Disable_DevNode(
            get_dev_inst_from_device_id(device_id)?,
            0,
        );

        if result != CR_SUCCESS {
            return Err(format!("Failed to disable device: error code {}", result));
        }

        // Add to blocked devices registry
        add_to_blocked_registry(device_id)?;

        Ok(())
    }
}

/// Unblock USB device
pub fn unblock_usb_device(device_id: &str) -> Result<(), String> {
    unsafe {
        // Enable device
        let result = CM_Enable_DevNode(
            get_dev_inst_from_device_id(device_id)?,
            0,
        );

        if result != CR_SUCCESS {
            return Err(format!("Failed to enable device: error code {}", result));
        }

        // Remove from blocked devices registry
        remove_from_blocked_registry(device_id)?;

        Ok(())
    }
}

/// Get device instance from device ID
unsafe fn get_dev_inst_from_device_id(device_id: &str) -> Result<DWORD, String> {
    let device_id_wide: Vec<u16> = OsStr::new(device_id)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut dev_inst: DWORD = 0;
    let result = CM_Locate_DevNodeW(
        &mut dev_inst,
        device_id_wide.as_ptr() as *mut _,
        CM_LOCATE_DEVNODE_NORMAL,
    );

    if result != CR_SUCCESS {
        return Err(format!("Failed to locate device node: error code {}", result));
    }

    Ok(dev_inst)
}

/// Add device to blocked devices registry
fn add_to_blocked_registry(device_id: &str) -> Result<(), String> {
    unsafe {
        let key_path: Vec<u16> = OsStr::new("SOFTWARE\\NOSP\\BlockedUSB")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey: HKEY = ptr::null_mut();

        // Create or open key
        let result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            ptr::null_mut(),
            0,
            KEY_WRITE,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        );

        if result != 0 {
            return Err("Failed to open registry key".to_string());
        }

        // Set value
        let value_name: Vec<u16> = OsStr::new(device_id)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let value_data: Vec<u16> = OsStr::new("blocked")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        RegSetValueExW(
            hkey,
            value_name.as_ptr(),
            0,
            REG_SZ,
            value_data.as_ptr() as *const u8,
            (value_data.len() * 2) as DWORD,
        );

        RegCloseKey(hkey);

        Ok(())
    }
}

/// Remove device from blocked devices registry
fn remove_from_blocked_registry(device_id: &str) -> Result<(), String> {
    unsafe {
        let key_path: Vec<u16> = OsStr::new("SOFTWARE\\NOSP\\BlockedUSB")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut hkey: HKEY = ptr::null_mut();

        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.as_ptr(), 0, KEY_WRITE, &mut hkey) != 0 {
            return Ok(()); // Key doesn't exist, nothing to remove
        }

        let value_name: Vec<u16> = OsStr::new(device_id)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        RegDeleteValueW(hkey, value_name.as_ptr());
        RegCloseKey(hkey);

        Ok(())
    }
}

/// Block all USB mass storage devices
pub fn block_all_usb_storage() -> Result<usize, String> {
    let devices = list_usb_devices()?;
    let mut blocked_count = 0;

    for device in devices {
        // Filter for mass storage devices
        if device.description.to_lowercase().contains("mass storage")
            || device.description.to_lowercase().contains("disk")
            || device.description.to_lowercase().contains("usb storage")
        {
            if block_usb_device(&device.device_id).is_ok() {
                blocked_count += 1;
            }
        }
    }

    Ok(blocked_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_usb_devices() {
        let result = list_usb_devices();
        assert!(result.is_ok());
    }
}
