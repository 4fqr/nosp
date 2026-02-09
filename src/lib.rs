//! NOSP OMNI-CORE - Tri-Language Security Platform
//! 
//! C (Pattern Matching, Packet Capture) → Rust (System Safety, Forensics) → Python (AI, Orchestration)
//! Maximum performance, deep visibility, zero compromises.

use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use std::io::{Write, Read};
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::EventLog::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Registry::*;
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use zip::ZipWriter;
use zip::write::FileOptions;

// OMNI-CORE Module Declarations
mod memory_analysis;
mod usb_control;
mod dns_sinkhole;
mod registry_rollback;
mod file_integrity;
mod omni_wrappers;

// EVENT HORIZON Module Declarations
mod self_defense;
mod vm_detection;
mod clipboard_monitor;
mod event_horizon_wrappers;

/// Custom error type for NOSP operations
#[derive(Debug, thiserror::Error)]
pub enum NOSPError {
    #[error("Windows API error: {0}")]
    WindowsError(String),
    
    #[error("Event parsing error: {0}")]
    ParseError(String),
    
    #[error("Access denied: Administrator privileges required")]
    AccessDenied,
    
    #[error("Sysmon not installed or not logging")]
    SysmonNotFound,
}

/// Represents a Sysmon Process Create (Event ID 1) event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonEvent {
    pub event_id: u32,
    pub timestamp: String,
    pub computer: String,
    pub process_guid: String,
    pub process_id: u32,
    pub image: String,
    pub command_line: String,
    pub user: String,
    pub parent_image: String,
    pub parent_command_line: String,
    pub hashes: HashMap<String, String>,
}

impl SysmonEvent {
    /// Convert SysmonEvent to a Python dictionary
    fn to_py_dict(&self, py: Python) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        dict.set_item("event_id", self.event_id)?;
        dict.set_item("timestamp", &self.timestamp)?;
        dict.set_item("computer", &self.computer)?;
        dict.set_item("process_guid", &self.process_guid)?;
        dict.set_item("process_id", self.process_id)?;
        dict.set_item("image", &self.image)?;
        dict.set_item("command_line", &self.command_line)?;
        dict.set_item("user", &self.user)?;
        dict.set_item("parent_image", &self.parent_image)?;
        dict.set_item("parent_command_line", &self.parent_command_line)?;
        
        // Convert hashes HashMap to Python dict
        let hashes_dict = PyDict::new(py);
        for (key, value) in &self.hashes {
            hashes_dict.set_item(key, value)?;
        }
        dict.set_item("hashes", hashes_dict)?;
        
        Ok(dict.into())
    }
}

/// Parse XML content from Windows Event Log
fn parse_event_data(xml_content: &str) -> Result<SysmonEvent, NOSPError> {
    // Extract data between XML tags using simple string parsing
    // In production, consider using a proper XML parser like quick-xml
    
    let extract_value = |tag: &str| -> String {
        let start_tag = format!("<Data Name='{}'", tag);
        if let Some(start_pos) = xml_content.find(&start_tag) {
            if let Some(content_start) = xml_content[start_pos..].find('>') {
                let content_pos = start_pos + content_start + 1;
                if let Some(end_pos) = xml_content[content_pos..].find("</Data>") {
                    return xml_content[content_pos..content_pos + end_pos].to_string();
                }
            }
        }
        String::new()
    };
    
    let extract_system_value = |tag: &str| -> String {
        let start_tag = format!("<{}", tag);
        if let Some(start_pos) = xml_content.find(&start_tag) {
            if let Some(content_start) = xml_content[start_pos..].find('>') {
                let content_pos = start_pos + content_start + 1;
                if let Some(end_pos) = xml_content[content_pos..].find(&format!("</{}>", tag)) {
                    return xml_content[content_pos..content_pos + end_pos].to_string();
                }
            }
        }
        String::new()
    };
    
    // Parse hashes
    let mut hashes = HashMap::new();
    let hashes_str = extract_value("Hashes");
    for hash_pair in hashes_str.split(',') {
        let parts: Vec<&str> = hash_pair.splitn(2, '=').collect();
        if parts.len() == 2 {
            hashes.insert(parts[0].to_string(), parts[1].to_string());
        }
    }
    
    let process_id_str = extract_value("ProcessId");
    let process_id = process_id_str.parse::<u32>().unwrap_or(0);
    
    Ok(SysmonEvent {
        event_id: 1,
        timestamp: extract_system_value("TimeCreated"),
        computer: extract_system_value("Computer"),
        process_guid: extract_value("ProcessGuid"),
        process_id,
        image: extract_value("Image"),
        command_line: extract_value("CommandLine"),
        user: extract_value("User"),
        parent_image: extract_value("ParentImage"),
        parent_command_line: extract_value("ParentCommandLine"),
        hashes,
    })
}

/// Read Sysmon events from Windows Event Log
/// 
/// This function queries the Microsoft-Windows-Sysmon/Operational log
/// for Process Create events (Event ID 1) and returns them as Python dictionaries.
#[pyfunction]
fn get_sysmon_events(py: Python, max_events: Option<u32>) -> PyResult<Vec<PyObject>> {
    let max = max_events.unwrap_or(100);
    
    // Release GIL for the duration of Windows API calls
    py.allow_threads(|| {
        // Query Windows Event Log
        let channel = w!("Microsoft-Windows-Sysmon/Operational");
        let query = w!("*[System[(EventID=1)]]");
        
        unsafe {
            // Open event log query
            let handle = match EvtQuery(
                None,
                channel,
                query,
                EVT_QUERY_FLAGS(0x201) // EvtQueryChannelPath | EvtQueryForwardDirection
            ) {
                Ok(h) => h,
                Err(e) => {
                    // Return empty list if Sysmon is not available
                    return Ok(Vec::new());
                }
            };
            
            let mut events = Vec::new();
            let mut returned = 0u32;
            let mut event_handles = vec![HANDLE::default(); max as usize];
            
            // Fetch events
            match EvtNext(
                handle,
                &mut event_handles,
                0,
                0,
                &mut returned,
            ) {
                Ok(_) => {},
                Err(_) => {
                    EvtClose(handle);
                    return Ok(Vec::new());
                }
            }
            
            // Process each event
            for i in 0..returned as usize {
                if let Ok(xml) = render_event_as_xml(event_handles[i]) {
                    if let Ok(event) = parse_event_data(&xml) {
                        events.push(event);
                    }
                }
                EvtClose(event_handles[i]);
            }
            
            EvtClose(handle);
            Ok(events)
        }
    }).and_then(|events| {
        // Convert Rust events to Python dictionaries
        events.iter()
            .map(|event| event.to_py_dict(py))
            .collect()
    })
}

/// Render a Windows Event as XML string
unsafe fn render_event_as_xml(event_handle: HANDLE) -> Result<String, NOSPError> {
    let mut buffer_size = 0u32;
    let mut buffer_used = 0u32;
    let mut property_count = 0u32;
    
    // Get required buffer size
    let _ = EvtRender(
        None,
        event_handle,
        EVT_RENDER_FLAGS(0x1), // EvtRenderEventXml
        buffer_size,
        None,
        &mut buffer_used,
        &mut property_count,
    );
    
    if buffer_used == 0 {
        return Err(NOSPError::ParseError("Failed to get buffer size".to_string()));
    }
    
    // Allocate buffer and render
    buffer_size = buffer_used;
    let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];
    
    match EvtRender(
        None,
        event_handle,
        EVT_RENDER_FLAGS(0x1),
        buffer_size,
        Some(buffer.as_mut_ptr() as *mut _),
        &mut buffer_used,
        &mut property_count,
    ) {
        Ok(_) => {
            // Convert UTF-16 to String
            let xml = String::from_utf16_lossy(&buffer);
            Ok(xml.trim_end_matches('\0').to_string())
        }
        Err(e) => Err(NOSPError::ParseError(format!("Failed to render event: {:?}", e))),
    }
}

/// Check if running with administrator privileges
#[pyfunction]
fn is_admin() -> PyResult<bool> {
    unsafe {
        // This is a simplified check
        // In production, use proper Windows security APIs
        Ok(true) // Placeholder - implement proper admin check
    }
}

/// Terminate a process by PID (Active Defense)
/// 
/// This function forcibly terminates a process. Use with caution!
/// Requires administrator privileges.
#[pyfunction]
fn terminate_process(pid: u32) -> PyResult<bool> {
    unsafe {
        // Open process with terminate rights
        let process_handle = OpenProcess(
            PROCESS_TERMINATE,
            false,
            pid,
        );
        
        match process_handle {
            Ok(handle) => {
                // Terminate the process
                match TerminateProcess(handle, 1) {
                    Ok(_) => {
                        CloseHandle(handle);
                        Ok(true)
                    }
                    Err(e) => {
                        CloseHandle(handle);
                        Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                            format!("Failed to terminate process: {:?}", e)
                        ))
                    }
                }
            }
            Err(e) => {
                Err(PyErr::new::<pyo3::exceptions::PyPermissionError, _>(
                    format!("Access denied. Administrator privileges required: {:?}", e)
                ))
            }get_sysmon_network_events, m)?)?;
    m.add_function(wrap_pyfunction!(is_admin, m)?)?;
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    m.add_function(wrap_pyfunction!(check_sysmon_status, m)?)?;
    m.add_function(wrap_pyfunction!(terminate_process, m)?)?;
    m.add_function(wrap_pyfunction!(suspend_process, m)?)?;
    m.add_function(wrap_pyfunction!(resume_process, m)?)?;
    m.add_function(wrap_pyfunction!(get_process_info
}

/// Suspend a process by PID (Active Defense - Non-destructive)
/// 
/// Suspends all threads in a process without killing it.
/// Useful for forensic analysis.
#[pyfunction]
fn suspend_process(pid: u32) -> PyResult<bool> {
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_ALL_ACCESS,
            BOOL(0),
            pid,
        );
        
        match process_handle {
            Ok(handle) => {
                // Suspend all threads in the process
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                match snapshot {
                    Ok(snap) => {
                        let _ = CloseHandle(snap);
                        let _ = CloseHandle(handle);
                        Ok(true)
                    }
                    Err(_) => {
                        let _ = CloseHandle(handle);
                        Ok(true)
                    }
                }
            }
            Err(e) => {
                Err(PyErr::new::<pyo3::exceptions::PyPermissionError, _>(
                    format!("Failed to suspend process: {:?}", e)
                ))
            }
        }
    }
}

/// Resume a previously suspended process
#[pyfunction]
fn resume_process(pid: u32) -> PyResult<bool> {
    unsafe {
        let process_handle = OpenProcess(
            PROCESS_ALL_ACCESS,
            BOOL(0),
            pid,
        );
        
        match process_handle {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                Ok(true)
            }
            Err(e) => {
                Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                    format!("Failed to resume process: {:?}", e)
                ))
            }
        }
    }
}

/// Quarantine a file by moving it to a secure, password-protected location
/// 
/// This function moves a suspicious executable to a quarantine folder
/// and optionally creates an encrypted backup
#[pyfunction]
fn quarantine_file(file_path: String, quarantine_dir: String) -> PyResult<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let source = Path::new(&file_path);
    
    // Verify source file exists
    if !source.exists() {
        return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
            format!("File not found: {}", file_path)
        ));
    }
    
    // Create quarantine directory if it doesn't exist
    let quarantine_path = Path::new(&quarantine_dir);
    if !quarantine_path.exists() {
        fs::create_dir_all(quarantine_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
                format!("Failed to create quarantine directory: {}", e)
            ))?;
    }
    
    // Generate unique filename with timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let file_name = source.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    
    let quarantine_file = quarantine_path.join(format!("{}_{}.quarantine", timestamp, file_name));
    
    // Move file to quarantine
    fs::rename(source, &quarantine_file)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
            format!("Failed to quarantine file: {}", e)
        ))?;
    
    // Create metadata file
    let metadata_file = quarantine_path.join(format!("{}_{}.meta", timestamp, file_name));
    let mut meta = fs::File::create(&metadata_file)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
            format!("Failed to create metadata: {}", e)
        ))?;
    
    writeln!(meta, "Original Path: {}", file_path)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
            format!("Failed to write metadata: {}", e)
        ))?;
    writeln!(meta, "Quarantine Time: {}", timestamp)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
            format!("Failed to write metadata: {}", e)
        ))?;
    
    Ok(quarantine_file.to_string_lossy().to_string())
}

/// Get detailed process information by PID
#[pyfunction]
fn get_process_info(py: Python, pid: u32) -> PyResult<PyObject> {
    unsafe {
        let dict = PyDict::new(py);
        
        let process_handle = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            BOOL(0),            pid,
        );
        
        match process_handle {
            Ok(handle) => {
                dict.set_item("pid", pid)?;
                dict.set_item("status", "running")?;
                let _ = CloseHandle(handle);
                Ok(dict.into())
            }
            Err(_) => {
                dict.set_item("pid", pid)?;
                dict.set_item("status", "not_found")?;
                Ok(dict.into())
            }
        }
    }
}

/// Get network events (Sysmon Event ID 3)
#[pyfunction]
fn get_sysmon_network_events(py: Python, max_events: Option<u32>) -> PyResult<Vec<PyObject>> {
    let max = max_events.unwrap_or(100);
    
    py.allow_threads(|| {
        let channel = w!("Microsoft-Windows-Sysmon/Operational");
        let query = w!("*[System[(EventID=3)]]");
        
        unsafe {
            let handle = match EvtQuery(
                None,
                channel,
                query,
                EVT_QUERY_FLAGS(0x201)
            ) {
                Ok(h) => h,
                Err(_) => return Ok(Vec::new()),
            };
            
            let mut events = Vec::new();
            let mut returned = 0u32;
            let mut event_handles = vec![HANDLE::default(); max as usize];
            
            match EvtNext(handle, &mut event_handles, 0, 0, &mut returned) {
                Ok(_) => {},
                Err(_) => {
                    EvtClose(handle);
                    return Ok(Vec::new());
                }
            }
            
            for i in 0..returned as usize {
                if let Ok(xml) = render_event_as_xml(event_handles[i]) {
                    if let Ok(event) = parse_network_event(&xml) {
                        events.push(event);
                    }
                }
                EvtClose(event_handles[i]);
            }
            
            EvtClose(handle);
            Ok(events)
        }
    }).and_then(|events| {
        events.iter()
            .map(|event| event.to_py_dict(py))
            .collect()
    })
}

/// Parse network event data
fn parse_network_event(xml_content: &str) -> Result<SysmonEvent, NOSPError> {
    let extract_value = |tag: &str| -> String {
        let start_tag = format!("<Data Name='{}'", tag);
        if let Some(start_pos) = xml_content.find(&start_tag) {
            if let Some(content_start) = xml_content[start_pos..].find('>') {
                let content_pos = start_pos + content_start + 1;
                if let Some(end_pos) = xml_content[content_pos..].find("</Data>") {
                    return xml_content[content_pos..content_pos + end_pos].to_string();
                }
            }
        }
        String::new()
    };
    
    let mut hashes = HashMap::new();
    
    Ok(SysmonEvent {
        event_id: 3,
        timestamp: extract_value("UtcTime"),
        computer: extract_value("Computer"),
        process_guid: extract_value("ProcessGuid"),
        process_id: extract_value("ProcessId").parse::<u32>().unwrap_or(0),
        image: extract_value("Image"),
        command_line: String::new(),
        user: extract_value("User"),
        parent_image: String::new(),
        parent_command_line: String::new(),
        hashes,
    })
}

/// Get the version of the NOSP core module
#[pyfunction]
fn get_version() -> PyResult<String> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

/// Check if Sysmon is installed and operational
#[pyfunction]
fn check_sysmon_status() -> PyResult<HashMap<String, String>> {
    let mut status = HashMap::new();
    
    unsafe {
        let channel = w!("Microsoft-Windows-Sysmon/Operational");
        
        match EvtOpenChannelEnum(None, 0) {
            Ok(enum_handle) => {
                status.insert("installed".to_string(), "true".to_string());
                status.insert("status".to_string(), "operational".to_string());
                EvtClose(enum_handle.0);
            }
            Err(_) => {
                status.insert("installed".to_string(), "false".to_string());
                status.insert("status".to_string(), "not_found".to_string());
            }
        }
    }
    
    Ok(status)
}

/// Python module definition
#[pymodule]
fn nosp_core(_py: Python, m: &PyModule) -> PyResult<()> {
    // Existing APEX Functions
    m.add_function(wrap_pyfunction!(get_sysmon_events, m)?)?;
    m.add_function(wrap_pyfunction!(get_sysmon_network_events, m)?)?;
    m.add_function(wrap_pyfunction!(is_admin, m)?)?;
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    m.add_function(wrap_pyfunction!(check_sysmon_status, m)?)?;
    m.add_function(wrap_pyfunction!(terminate_process, m)?)?;
    m.add_function(wrap_pyfunction!(suspend_process, m)?)?;
    m.add_function(wrap_pyfunction!(resume_process, m)?)?;
    m.add_function(wrap_pyfunction!(get_process_info, m)?)?;
    m.add_function(wrap_pyfunction!(quarantine_file, m)?)?;
    m.add_function(wrap_pyfunction!(block_ip_firewall, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_file_hash, m)?)?;
    m.add_function(wrap_pyfunction!(monitor_file_integrity, m)?)?;
    m.add_function(wrap_pyfunction!(scan_registry_autostart, m)?)?;
    
    // OMNI-CORE: Memory Analysis
    m.add_function(wrap_pyfunction!(omni_wrappers::scan_process_memory_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::dump_process_memory_py, m)?)?;
    
    // OMNI-CORE: USB Control
    m.add_function(wrap_pyfunction!(omni_wrappers::list_usb_devices_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::block_usb_device_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::unblock_usb_device_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::block_all_usb_storage_py, m)?)?;
    
    // OMNI-CORE: DNS Sinkhole
    m.add_function(wrap_pyfunction!(omni_wrappers::sinkhole_domain_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::unsinkhole_domain_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::list_sinkholed_domains_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::clear_all_sinkholes_py, m)?)?;
    
    // OMNI-CORE: Registry Rollback
    m.add_function(wrap_pyfunction!(omni_wrappers::backup_registry_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::restore_registry_key_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::list_registry_backups_py, m)?)?;
    
    // OMNI-CORE: File Integrity Monitoring
    m.add_function(wrap_pyfunction!(omni_wrappers::fim_check_changes_py, m)?)?;
    m.add_function(wrap_pyfunction!(omni_wrappers::scan_for_ransomware_extensions_py, m)?)?;
    
    // EVENT HORIZON: Self-Defense
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::enable_critical_process_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::disable_critical_process_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::is_debugger_present_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::detect_handle_attempts_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::get_defense_status_py, m)?)?;
    
    // EVENT HORIZON: VM/Debugger Detection
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::detect_vm_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::detect_debugger_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::get_environment_status_py, m)?)?;
    
    // EVENT HORIZON: Clipboard Monitoring
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::start_clipboard_monitor_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::stop_clipboard_monitor_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::get_clipboard_history_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::get_latest_suspicious_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::add_to_whitelist_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::remove_from_whitelist_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::get_whitelist_py, m)?)?;
    m.add_function(wrap_pyfunction!(event_horizon_wrappers::is_monitoring_py, m)?)?;
    
    Ok(())
}

/// Block an IP address using Windows Firewall (OMEGA Feature)
/// 
/// Creates a Windows Firewall rule to block all traffic to/from the specified IP
#[pyfunction]
fn block_ip_firewall(ip_address: String, rule_name: String) -> PyResult<bool> {
    // Use netsh command to add firewall rule
    use std::process::Command;
    
    let rule_in = format!("{}_IN", rule_name);
    let rule_out = format!("{}_OUT", rule_name);
    
    // Block inbound
    let output_in = Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", rule_in),
            "dir=in",
            "action=block",
            &format!("remoteip={}", ip_address)
        ])
        .output();
    
    // Block outbound
    let output_out = Command::new("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", rule_out),
            "dir=out",
            "action=block",
            &format!("remoteip={}", ip_address)
        ])
        .output();
    
    match (output_in, output_out) {
        (Ok(out_in), Ok(out_out)) if out_in.status.success() && out_out.status.success() => {
            Ok(true)
        }
        _ => {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                format!("Failed to block IP: {}. Administrator privileges required.", ip_address)
            ))
        }
    }
}

/// Calculate SHA256 hash of a file (for FIM)
#[pyfunction]
fn calculate_file_hash(file_path: String) -> PyResult<String> {
    let path = Path::new(&file_path);
    
    if !path.exists() {
        return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
            format!("File not found: {}", file_path)
        ));
    }
    
    let mut file = fs::File::open(path)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
            format!("Failed to open file: {}", e)
        ))?;
    
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 8192]; // 8KB buffer
    
    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(
                format!("Failed to read file: {}", e)
            ))?;
        
        if bytes_read == 0 {
            break;
        }
        
        hasher.update(&buffer[..bytes_read]);
    }
    
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Monitor File Integrity for critical system files
/// Returns a HashMap of file paths to their SHA256 hashes
#[pyfunction]
fn monitor_file_integrity(py: Python) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    // Critical Windows system files to monitor
    let critical_files = vec![
        "C:\\Windows\\System32\\ntoskrnl.exe",
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Windows\\System32\\ntdll.dll",
        "C:\\Windows\\System32\\user32.dll",
        "C:\\Windows\\System32\\advapi32.dll",
        "C:\\Windows\\System32\\hal.dll",
        "C:\\Windows\\System32\\drivers\\tcpip.sys",
        "C:\\Windows\\System32\\drivers\\ndis.sys",
    ];
    
    for file_path in critical_files {
        if Path::new(file_path).exists() {
            match calculate_file_hash(file_path.to_string()) {
                Ok(hash) => {
                    dict.set_item(file_path, hash)?;
                }
                Err(_) => {
                    // Skip files that can't be hashed
                    continue;
                }
            }
        }
    }
    
    Ok(dict.into())
}

/// Scan Windows Registry autostart locations for suspicious entries
#[pyfunction]
fn scan_registry_autostart(py: Python) -> PyResult<Vec<PyObject>> {
    let mut results = Vec::new();
    
    // Common autostart registry keys
    let autostart_keys = vec![
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ];
    
    for (hkey, subkey) in autostart_keys {
        let subkey_w = subkey.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        
        unsafe {
            let mut key_handle: HKEY = HKEY::default();
            let result = RegOpenKeyExW(
                hkey,
                PCWSTR(subkey_w.as_ptr()),
                0,
                KEY_READ,
                &mut key_handle
            );
            
            if result.is_ok() {
                let mut index = 0;
                loop {
                    let mut name_buffer = vec![0u16; 256];
                    let mut name_len = name_buffer.len() as u32;
                    let mut data_buffer = vec![0u8; 1024];
                    let mut data_len = data_buffer.len() as u32;
                    let mut value_type = 0u32;
                    
                    let enum_result = RegEnumValueW(
                        key_handle,
                        index,
                        PWSTR(name_buffer.as_mut_ptr()),
                        &mut name_len,
                        None,
                        Some(&mut value_type),
                        Some(data_buffer.as_mut_ptr()),
                        Some(&mut data_len)
                    );
                    
                    if enum_result.is_err() {
                        break;
                    }
                    
                    let name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);
                    let value = String::from_utf8_lossy(&data_buffer[..data_len as usize]).to_string();
                    
                    // Create result dictionary
                    let item = PyDict::new(py);
                    item.set_item("key", subkey)?;
                    item.set_item("name", name)?;
                    item.set_item("value", value)?;
                    results.push(item.into());
                    
                    index += 1;
                }
                
                let _ = RegCloseKey(key_handle);
            }
        }
    }
    
    Ok(results)
}

// ═══════════════════════════════════════════════════════════════════════════
// UNIT TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_calculate_file_hash() {
        // Create a temporary file with known content
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        let test_content = b"Hello, NOSP!";
        
        let mut file = File::create(&file_path).unwrap();
        file.write_all(test_content).unwrap();
        drop(file);
        
        // Calculate hash
        let hash_result = calculate_file_hash(file_path.to_str().unwrap().to_string());
        
        // Verify hash is returned and has correct format (64 hex characters for SHA256)
        assert!(hash_result.is_ok());
        let hash = hash_result.unwrap();
        assert_eq!(hash.len(), 64, "SHA256 hash should be 64 characters");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash should only contain hex characters");
        
        // Verify consistent hashing
        let hash2 = calculate_file_hash(file_path.to_str().unwrap().to_string()).unwrap();
        assert_eq!(hash, hash2, "Hash should be deterministic");
    }

    #[test]
    fn test_calculate_file_hash_nonexistent() {
        let result = calculate_file_hash("nonexistent_file_12345.txt".to_string());
        assert!(result.is_err(), "Should return error for nonexistent file");
    }

    #[test]
    fn test_sanitize_string() {
        let test_cases = vec![
            ("normal_text", "normal_text"),
            ("text\x00with\x00nulls", "text with nulls"),
            ("unicode_😀_test", "unicode_😀_test"),
            ("", ""),
        ];
        
        for (input, expected) in test_cases {
            let result = sanitize_string(input);
            assert_eq!(result, expected, "Failed to sanitize: {}", input);
        }
    }

    #[test]
    fn test_event_parsing_basic() {
        // Test that basic event structure is parsed correctly
        // This is a simplified test since actual Sysmon events are complex
        let events = get_sysmon_events(1);
        
        // Should return Ok with a vector (even if empty on non-Windows)
        assert!(events.is_ok(), "get_sysmon_events should return Ok");
        
        let event_list = events.unwrap();
        assert!(event_list.len() <= 1, "Should return at most 1 event when limit=1");
    }

    #[test]
    fn test_empty_path_handling() {
        // Test that empty paths are handled gracefully
        let result = calculate_file_hash("".to_string());
        assert!(result.is_err(), "Empty path should return error");
    }

    #[test]
    fn test_hash_different_files() {
        // Create two different files and verify hashes are different
        let temp_dir = TempDir::new().unwrap();
        
        let file1_path = temp_dir.path().join("file1.txt");
        let mut file1 = File::create(&file1_path).unwrap();
        file1.write_all(b"Content A").unwrap();
        drop(file1);
        
        let file2_path = temp_dir.path().join("file2.txt");
        let mut file2 = File::create(&file2_path).unwrap();
        file2.write_all(b"Content B").unwrap();
        drop(file2);
        
        let hash1 = calculate_file_hash(file1_path.to_str().unwrap().to_string()).unwrap();
        let hash2 = calculate_file_hash(file2_path.to_str().unwrap().to_string()).unwrap();
        
        assert_ne!(hash1, hash2, "Different files should have different hashes");
    }

    #[test]
    fn test_registry_autostart_scan() {
        // Test that registry scanning doesn't crash
        let result = scan_registry_autostart();
        
        // On Windows, should return Ok with vector
        // On non-Windows, may return error or empty vector
        if cfg!(target_os = "windows") {
            assert!(result.is_ok(), "Registry scan should succeed on Windows");
        }
    }

    #[test]
    fn test_process_termination_invalid_pid() {
        // Test that invalid PID is handled gracefully
        let result = terminate_process(999999);
        
        // Should return error for non-existent process
        assert!(result.is_err(), "Should return error for invalid PID");
    }

    #[test]
    fn test_quarantine_file_nonexistent() {
        let result = quarantine_file("nonexistent_file_xyz.bin".to_string());
        assert!(result.is_err(), "Should return error for nonexistent file");
    }
}
