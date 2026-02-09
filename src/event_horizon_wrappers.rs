//! EVENT HORIZON PyO3 Wrappers
//! 
//! Python bindings for God Mode capabilities:
//! - Self-Defense (Critical Process Flag, Debugger Detection)
//! - VM Detection (Registry, Process, MAC, BIOS)
//! - Clipboard Monitoring (Crypto Hijacking Detection)

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

use crate::self_defense;
use crate::vm_detection;
use crate::clipboard_monitor;

// ═══════════════════════════════════════════════════════════════════════════
// SELF-DEFENSE WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Enable critical process flag (BSOD on termination)
/// 
/// WARNING: This makes the NOSP process critical to Windows.
/// Terminating it will trigger a BSOD. Use disable_critical_process_py() for cleanup.
#[pyfunction]
pub fn enable_critical_process_py() -> PyResult<bool> {
    match self_defense::enable_critical_process() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to enable critical process: {}", e)
        )),
    }
}

/// Disable critical process flag (restore normal termination)
#[pyfunction]
pub fn disable_critical_process_py() -> PyResult<bool> {
    match self_defense::disable_critical_process() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to disable critical process: {}", e)
        )),
    }
}

/// Check if a debugger is attached to the current process
#[pyfunction]
pub fn is_debugger_present_py() -> PyResult<bool> {
    Ok(self_defense::is_debugger_present())
}

/// Detect attempts to open a handle to NOSP process
/// 
/// Returns: List of PIDs that have handles to NOSP
#[pyfunction]
pub fn detect_handle_attempts_py() -> PyResult<Vec<u32>> {
    match self_defense::detect_handle_attempts() {
        Ok(pids) => Ok(pids),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to detect handle attempts: {}", e)
        )),
    }
}

/// Get comprehensive defense status
/// 
/// Returns: Dictionary with defense states
#[pyfunction]
pub fn get_defense_status_py(py: Python) -> PyResult<PyObject> {
    let status = self_defense::get_defense_status();
    
    let dict = PyDict::new(py);
    for (key, value) in status {
        dict.set_item(key, value)?;
    }
    
    Ok(dict.into())
}

// ═══════════════════════════════════════════════════════════════════════════
// VM DETECTION WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Detect if running in a virtual machine
/// 
/// Returns: Dictionary with VM detection results
/// - is_vm: bool
/// - vm_type: str (VMware, VirtualBox, Hyper-V, QEMU, Parallels, Unknown)
/// - confidence: int (0-100)
/// - indicators: list of strings
#[pyfunction]
pub fn detect_vm_py(py: Python) -> PyResult<PyObject> {
    let detection = vm_detection::detect_vm();
    
    let dict = PyDict::new(py);
    dict.set_item("is_vm", detection.is_vm)?;
    dict.set_item("vm_type", detection.vm_type)?;
    dict.set_item("confidence", detection.confidence)?;
    dict.set_item("indicators", detection.indicators)?;
    
    Ok(dict.into())
}

/// Detect if a debugger is attached or debugging tools are present
/// 
/// Returns: Dictionary with debugger detection results
/// - is_debugging: bool
/// - debugger_type: str (WinDbg, x64dbg, OllyDbg, IDA Pro, Visual Studio, GDB, Unknown)
/// - confidence: int (0-100)
/// - indicators: list of strings
#[pyfunction]
pub fn detect_debugger_py(py: Python) -> PyResult<PyObject> {
    let detection = vm_detection::detect_debugger();
    
    let dict = PyDict::new(py);
    dict.set_item("is_debugging", detection.is_debugging)?;
    dict.set_item("debugger_type", detection.debugger_type)?;
    dict.set_item("confidence", detection.confidence)?;
    dict.set_item("indicators", detection.indicators)?;
    
    Ok(dict.into())
}

/// Get comprehensive environment status (VM + Debugger)
/// 
/// Returns: Dictionary with full environment analysis
#[pyfunction]
pub fn get_environment_status_py(py: Python) -> PyResult<PyObject> {
    let vm_detection = vm_detection::detect_vm();
    let debugger_detection = vm_detection::detect_debugger();
    
    let dict = PyDict::new(py);
    
    // VM Detection
    let vm_dict = PyDict::new(py);
    vm_dict.set_item("is_vm", vm_detection.is_vm)?;
    vm_dict.set_item("vm_type", vm_detection.vm_type)?;
    vm_dict.set_item("confidence", vm_detection.confidence)?;
    vm_dict.set_item("indicators", vm_detection.indicators)?;
    dict.set_item("vm", vm_dict)?;
    
    // Debugger Detection
    let debugger_dict = PyDict::new(py);
    debugger_dict.set_item("is_debugging", debugger_detection.is_debugging)?;
    debugger_dict.set_item("debugger_type", debugger_detection.debugger_type)?;
    debugger_dict.set_item("confidence", debugger_detection.confidence)?;
    debugger_dict.set_item("indicators", debugger_detection.indicators)?;
    dict.set_item("debugger", debugger_dict)?;
    
    // Overall suspicious flag
    let is_suspicious = vm_detection.is_vm || debugger_detection.is_debugging;
    dict.set_item("is_suspicious", is_suspicious)?;
    
    Ok(dict.into())
}

// ═══════════════════════════════════════════════════════════════════════════
// CLIPBOARD MONITORING WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Start clipboard monitoring in background thread
/// 
/// Returns: True if monitoring started successfully
#[pyfunction]
pub fn start_clipboard_monitor_py() -> PyResult<bool> {
    match clipboard_monitor::start_monitoring() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to start clipboard monitor: {}", e)
        )),
    }
}

/// Stop clipboard monitoring
#[pyfunction]
pub fn stop_clipboard_monitor_py() -> PyResult<bool> {
    clipboard_monitor::stop_monitoring();
    Ok(true)
}

/// Get clipboard event history
/// 
/// Returns: List of dictionaries with clipboard events
/// Each event contains:
/// - timestamp: str
/// - content_type: str (Bitcoin, Ethereum, Monero, CreditCard, etc.)
/// - content: str (masked for sensitive data)
/// - is_sensitive: bool
/// - is_suspicious: bool
/// - warning_message: Optional[str]
#[pyfunction]
pub fn get_clipboard_history_py(py: Python) -> PyResult<Vec<PyObject>> {
    let history = clipboard_monitor::get_history();
    
    let mut py_events = Vec::new();
    
    for event in history {
        let dict = PyDict::new(py);
        dict.set_item("timestamp", event.timestamp.to_rfc3339())?;
        dict.set_item("content_type", format!("{:?}", event.content_type))?;
        
        // Mask sensitive content (show first 6 and last 4 chars)
        let masked_content = if event.is_sensitive && event.content.len() > 10 {
            format!("{}...{}", 
                &event.content[..6.min(event.content.len())],
                &event.content[event.content.len().saturating_sub(4)..]
            )
        } else {
            event.content.clone()
        };
        
        dict.set_item("content", masked_content)?;
        dict.set_item("is_sensitive", event.is_sensitive)?;
        dict.set_item("is_suspicious", event.is_suspicious)?;
        
        if let Some(warning) = event.warning_message {
            dict.set_item("warning_message", warning)?;
        }
        
        py_events.push(dict.into());
    }
    
    Ok(py_events)
}

/// Get only suspicious clipboard events (potential hijacking attempts)
/// 
/// Returns: List of suspicious events
#[pyfunction]
pub fn get_latest_suspicious_py(py: Python) -> PyResult<Vec<PyObject>> {
    let suspicious_events = clipboard_monitor::get_latest_suspicious();
    
    let mut py_events = Vec::new();
    
    for event in suspicious_events {
        let dict = PyDict::new(py);
        dict.set_item("timestamp", event.timestamp.to_rfc3339())?;
        dict.set_item("content_type", format!("{:?}", event.content_type))?;
        
        // For suspicious events, show more context
        let masked_content = if event.content.len() > 20 {
            format!("{}...{}", 
                &event.content[..10.min(event.content.len())],
                &event.content[event.content.len().saturating_sub(10)..]
            )
        } else {
            event.content.clone()
        };
        
        dict.set_item("content", masked_content)?;
        dict.set_item("is_sensitive", event.is_sensitive)?;
        dict.set_item("is_suspicious", event.is_suspicious)?;
        
        if let Some(warning) = event.warning_message {
            dict.set_item("warning_message", warning)?;
        }
        
        py_events.push(dict.into());
    }
    
    Ok(py_events)
}

/// Add address to clipboard monitor whitelist
/// 
/// Args:
///     address: Address to whitelist (BTC, ETH, etc.)
/// 
/// Returns: True if added successfully
#[pyfunction]
pub fn add_to_whitelist_py(address: String) -> PyResult<bool> {
    clipboard_monitor::add_to_whitelist(address);
    Ok(true)
}

/// Remove address from clipboard monitor whitelist
#[pyfunction]
pub fn remove_from_whitelist_py(address: String) -> PyResult<bool> {
    clipboard_monitor::remove_from_whitelist(&address);
    Ok(true)
}

/// Get all whitelisted addresses
#[pyfunction]
pub fn get_whitelist_py() -> PyResult<Vec<String>> {
    Ok(clipboard_monitor::get_whitelist())
}

/// Check if clipboard monitor is currently running
#[pyfunction]
pub fn is_monitoring_py() -> PyResult<bool> {
    Ok(clipboard_monitor::is_monitoring())
}
