
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

use crate::self_defense;
use crate::vm_detection;
use crate::clipboard_monitor;


#[pyfunction]
pub fn enable_critical_process_py() -> PyResult<bool> {
    match self_defense::enable_critical_process() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to enable critical process: {}", e)
        )),
    }
}

#[pyfunction]
pub fn disable_critical_process_py() -> PyResult<bool> {
    match self_defense::disable_critical_process() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to disable critical process: {}", e)
        )),
    }
}

#[pyfunction]
pub fn is_debugger_present_py() -> PyResult<bool> {
    Ok(self_defense::is_debugger_present())
}

#[pyfunction]
pub fn detect_handle_attempts_py() -> PyResult<Vec<u32>> {
    match self_defense::detect_handle_attempts() {
        Ok(pids) => Ok(pids),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to detect handle attempts: {}", e)
        )),
    }
}

#[pyfunction]
pub fn get_defense_status_py(py: Python) -> PyResult<PyObject> {
    let status = self_defense::get_defense_status();
    
    let dict = PyDict::new(py);
    for (key, value) in status {
        dict.set_item(key, value)?;
    }
    
    Ok(dict.into())
}


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

#[pyfunction]
pub fn get_environment_status_py(py: Python) -> PyResult<PyObject> {
    let vm_detection = vm_detection::detect_vm();
    let debugger_detection = vm_detection::detect_debugger();
    
    let dict = PyDict::new(py);
    
    let vm_dict = PyDict::new(py);
    vm_dict.set_item("is_vm", vm_detection.is_vm)?;
    vm_dict.set_item("vm_type", vm_detection.vm_type)?;
    vm_dict.set_item("confidence", vm_detection.confidence)?;
    vm_dict.set_item("indicators", vm_detection.indicators)?;
    dict.set_item("vm", vm_dict)?;
    
    let debugger_dict = PyDict::new(py);
    debugger_dict.set_item("is_debugging", debugger_detection.is_debugging)?;
    debugger_dict.set_item("debugger_type", debugger_detection.debugger_type)?;
    debugger_dict.set_item("confidence", debugger_detection.confidence)?;
    debugger_dict.set_item("indicators", debugger_detection.indicators)?;
    dict.set_item("debugger", debugger_dict)?;
    
    let is_suspicious = vm_detection.is_vm || debugger_detection.is_debugging;
    dict.set_item("is_suspicious", is_suspicious)?;
    
    Ok(dict.into())
}


#[pyfunction]
pub fn start_clipboard_monitor_py() -> PyResult<bool> {
    match clipboard_monitor::start_monitoring() {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            format!("Failed to start clipboard monitor: {}", e)
        )),
    }
}

#[pyfunction]
pub fn stop_clipboard_monitor_py() -> PyResult<bool> {
    clipboard_monitor::stop_monitoring();
    Ok(true)
}

#[pyfunction]
pub fn get_clipboard_history_py(py: Python) -> PyResult<Vec<PyObject>> {
    let history = clipboard_monitor::get_history();
    
    let mut py_events = Vec::new();
    
    for event in history {
        let dict = PyDict::new(py);
        dict.set_item("timestamp", event.timestamp.to_rfc3339())?;
        dict.set_item("content_type", format!("{:?}", event.content_type))?;
        
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

#[pyfunction]
pub fn get_latest_suspicious_py(py: Python) -> PyResult<Vec<PyObject>> {
    let suspicious_events = clipboard_monitor::get_latest_suspicious();
    
    let mut py_events = Vec::new();
    
    for event in suspicious_events {
        let dict = PyDict::new(py);
        dict.set_item("timestamp", event.timestamp.to_rfc3339())?;
        dict.set_item("content_type", format!("{:?}", event.content_type))?;
        
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

#[pyfunction]
pub fn add_to_whitelist_py(address: String) -> PyResult<bool> {
    clipboard_monitor::add_to_whitelist(address);
    Ok(true)
}

#[pyfunction]
pub fn remove_from_whitelist_py(address: String) -> PyResult<bool> {
    clipboard_monitor::remove_from_whitelist(&address);
    Ok(true)
}

#[pyfunction]
pub fn get_whitelist_py() -> PyResult<Vec<String>> {
    Ok(clipboard_monitor::get_whitelist())
}

#[pyfunction]
pub fn is_monitoring_py() -> PyResult<bool> {
    Ok(clipboard_monitor::is_monitoring())
}
