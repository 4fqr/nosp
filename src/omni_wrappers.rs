// ═══════════════════════════════════════════════════════════════════════════
// OMNI-CORE PYTHON WRAPPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

//  ┌─────────────────────────────────────────────────────────────┐
//  │ MEMORY ANALYSIS WRAPPERS                                    │
//  └─────────────────────────────────────────────────────────────┘

/// Scan process memory for anomalies (Python wrapper)
#[pyfunction]
fn scan_process_memory_py(py: Python, pid: u32) -> PyResult<PyObject> {
    match memory_analysis::scan_process_memory(pid) {
        Ok(info) => {
            let dict = PyDict::new(py);
            dict.set_item("pid", info.pid)?;
            dict.set_item("total_executable_pages", info.total_executable_pages)?;
            dict.set_item("writable_executable_pages", info.writable_executable_pages)?;
            dict.set_item("hollowing_detected", info.hollowing_detected)?;
            dict.set_item("injection_detected", info.injection_detected)?;
            dict.set_item("hook_detected", info.hook_detected)?;
            dict.set_item("risk_score", info.risk_score)?;
            

            Ok(dict.into())
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Dump process memory to file (Python wrapper)
#[pyfunction]
fn dump_process_memory_py(pid: u32, output_path: String) -> PyResult<bool> {
    match memory_analysis::dump_process_memory(pid, &output_path) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

//  ┌─────────────────────────────────────────────────────────────┐
//  │ USB CONTROL WRAPPERS                                        │
//  └─────────────────────────────────────────────────────────────┘

/// List USB devices (Python wrapper)
#[pyfunction]
fn list_usb_devices_py(py: Python) -> PyResult<Vec<PyObject>> {
    match usb_control::list_usb_devices() {
        Ok(devices) => {
            let mut result = Vec::new();
            for device in devices {
                let dict = PyDict::new(py);
                dict.set_item("device_id", device.device_id)?;
                dict.set_item("description", device.description)?;
                dict.set_item("manufacturer", device.manufacturer)?;
                dict.set_item("is_blocked", device.is_blocked)?;
                result.push(dict.into());
            }
            Ok(result)
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Block USB device (Python wrapper)
#[pyfunction]
fn block_usb_device_py(device_id: String) -> PyResult<bool> {
    match usb_control::block_usb_device(&device_id) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Unblock USB device (Python wrapper)
#[pyfunction]
fn unblock_usb_device_py(device_id: String) -> PyResult<bool> {
    match usb_control::unblock_usb_device(&device_id) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Block all USB mass storage devices (Python wrapper)
#[pyfunction]
fn block_all_usb_storage_py() -> PyResult<usize> {
    match usb_control::block_all_usb_storage() {
        Ok(count) => Ok(count),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

//  ┌─────────────────────────────────────────────────────────────┐
//  │ DNS SINKHOLE WRAPPERS                                       │
//  └─────────────────────────────────────────────────────────────┘

/// Sinkhole domain (redirect to 127.0.0.1) (Python wrapper)
#[pyfunction]
fn sinkhole_domain_py(domain: String) -> PyResult<bool> {
    match dns_sinkhole::sinkhole_domain(&domain) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Remove domain from sinkhole (Python wrapper)
#[pyfunction]
fn unsinkhole_domain_py(domain: String) -> PyResult<bool> {
    match dns_sinkhole::unsinkhole_domain(&domain) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// List all sinkholed domains (Python wrapper)
#[pyfunction]
fn list_sinkholed_domains_py(py: Python) -> PyResult<Vec<PyObject>> {
    match dns_sinkhole::list_sinkholed_domains() {
        Ok(entries) => {
            let mut result = Vec::new();
            for entry in entries {
                let dict = PyDict::new(py);
                dict.set_item("domain", entry.domain)?;
                dict.set_item("redirect_ip", entry.redirect_ip)?;
                dict.set_item("is_active", entry.is_active)?;
                result.push(dict.into());
            }
            Ok(result)
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Clear all NOSP sinkhole entries (Python wrapper)
#[pyfunction]
fn clear_all_sinkholes_py() -> PyResult<usize> {
    match dns_sinkhole::clear_all_sinkholes() {
        Ok(count) => Ok(count),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

//  ┌─────────────────────────────────────────────────────────────┐
//  │ REGISTRY ROLLBACK WRAPPERS                                  │
//  └─────────────────────────────────────────────────────────────┘

/// Backup registry key (Python wrapper)
#[pyfunction]
fn backup_registry_key_py(root_key: String, subkey: String) -> PyResult<String> {
    match registry_rollback::backup_registry_key(&root_key, &subkey) {
        Ok(filename) => Ok(filename),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Restore registry key from backup (Python wrapper)
#[pyfunction]
fn restore_registry_key_py(backup_file: String) -> PyResult<bool> {
    match registry_rollback::restore_registry_key(&backup_file) {
        Ok(_) => Ok(true),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// List available registry backups (Python wrapper)
#[pyfunction]
fn list_registry_backups_py() -> PyResult<Vec<String>> {
    match registry_rollback::list_registry_backups() {
        Ok(backups) => Ok(backups),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

//  ┌─────────────────────────────────────────────────────────────┐
//  │ FILE INTEGRITY MONITORING WRAPPERS                          │
//  └─────────────────────────────────────────────────────────────┘

/// Check for file changes in monitored directories (Python wrapper)
#[pyfunction]
fn fim_check_changes_py(py: Python, db_path: String) -> PyResult<Vec<PyObject>> {
    // Load FIM database
    let mut db = match file_integrity::FIMDatabase::load(&db_path) {
        Ok(db) => db,
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    };

    // Check for changes
    match db.check_changes() {
        Ok(changes) => {
            // Save updated database
            let _ = db.save(&db_path);

            let mut result = Vec::new();
            for change in changes {
                let dict = PyDict::new(py);
                dict.set_item("path", change.path)?;
                dict.set_item("change_type", format!("{:?}", change.change_type))?;
                if let Some(old_hash) = change.old_hash {
                    dict.set_item("old_hash", old_hash)?;
                }
                if let Some(new_hash) = change.new_hash {
                    dict.set_item("new_hash", new_hash)?;
                }
                result.push(dict.into());
            }
            Ok(result)
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}

/// Scan for ransomware file extensions (Python wrapper)
#[pyfunction]
fn scan_for_ransomware_extensions_py(dir_path: String) -> PyResult<Vec<String>> {
    match file_integrity::scan_for_ransomware_extensions(&dir_path) {
        Ok(files) => Ok(files),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e)),
    }
}
