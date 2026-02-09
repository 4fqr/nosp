/*
 * NOSP Rust Core - File Integrity Monitoring (FIM) Module
 * Real-time file monitoring with hash-based change detection
 */

use std::collections::HashMap;
use std::fs::{File, metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: String,
    pub size: u64,
    pub modified: u64,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FIMDatabase {
    pub snapshots: HashMap<String, FileSnapshot>,
    pub last_updated: u64,
}

#[derive(Debug, Clone)]
pub struct FileChange {
    pub path: String,
    pub change_type: ChangeType,
    pub old_hash: Option<String>,
    pub new_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

impl FIMDatabase {
    /// Create new FIM database
    pub fn new() -> Self {
        FIMDatabase {
            snapshots: HashMap::new(),
            last_updated: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Load database from file
    pub fn load(path: &str) -> Result<Self, String> {
        let mut file = File::open(path)
            .map_err(|e| format!("Failed to open FIM database: {}", e))?;

        let mut json = String::new();
        file.read_to_string(&mut json)
            .map_err(|e| format!("Failed to read FIM database: {}", e))?;

        serde_json::from_str(&json)
            .map_err(|e| format!("Failed to parse FIM database: {}", e))
    }

    /// Save database to file
    pub fn save(&self, path: &str) -> Result<(), String> {
        use std::io::Write;

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize FIM database: {}", e))?;

        let mut file = File::create(path)
            .map_err(|e| format!("Failed to create FIM database: {}", e))?;

        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write FIM database: {}", e))?;

        Ok(())
    }

    /// Add file to monitoring
    pub fn add_file(&mut self, path: &str) -> Result<(), String> {
        let snapshot = create_file_snapshot(path)?;
        self.snapshots.insert(path.to_string(), snapshot);
        Ok(())
    }

    /// Remove file from monitoring
    pub fn remove_file(&mut self, path: &str) {
        self.snapshots.remove(path);
    }

    /// Check for changes (returns list of changed files)
    pub fn check_changes(&mut self) -> Result<Vec<FileChange>, String> {
        let mut changes = Vec::new();
        let mut to_remove = Vec::new();

        // Check existing files for modifications
        for (path, old_snapshot) in &self.snapshots {
            if !Path::new(path).exists() {
                // File deleted
                changes.push(FileChange {
                    path: path.clone(),
                    change_type: ChangeType::Deleted,
                    old_hash: Some(old_snapshot.hash.clone()),
                    new_hash: None,
                });
                to_remove.push(path.clone());
            } else {
                // Check if modified
                match create_file_snapshot(path) {
                    Ok(new_snapshot) => {
                        if new_snapshot.hash != old_snapshot.hash {
                            changes.push(FileChange {
                                path: path.clone(),
                                change_type: ChangeType::Modified,
                                old_hash: Some(old_snapshot.hash.clone()),
                                new_hash: Some(new_snapshot.hash.clone()),
                            });
                            // Update snapshot
                            self.snapshots.insert(path.clone(), new_snapshot);
                        }
                    }
                    Err(_) => {
                        // File may have been deleted or inaccessible
                        to_remove.push(path.clone());
                    }
                }
            }
        }

        // Remove deleted files
        for path in to_remove {
            self.snapshots.remove(&path);
        }

        self.last_updated = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(changes)
    }
}

/// Create file snapshot with hash
fn create_file_snapshot(path: &str) -> Result<FileSnapshot, String> {
    let metadata = metadata(path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;

    let size = metadata.len();
    let modified = metadata
        .modified()
        .unwrap()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Calculate SHA-256 hash
    let hash = calculate_file_hash_sha256(path)?;

    Ok(FileSnapshot {
        path: path.to_string(),
        size,
        modified,
        hash,
    })
}

/// Calculate SHA-256 hash of file
fn calculate_file_hash_sha256(path: &str) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read file: {}", e))?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Monitor directory recursively
pub fn monitor_directory(dir_path: &str, db: &mut FIMDatabase) -> Result<usize, String> {
    let mut file_count = 0;

    for entry in WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let path = entry.path().to_string_lossy().to_string();
            if db.add_file(&path).is_ok() {
                file_count += 1;
            }
        }
    }

    Ok(file_count)
}

/// Monitor critical Windows system directories
pub fn monitor_critical_directories(db: &mut FIMDatabase) -> Result<usize, String> {
    let critical_dirs = vec![
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
    ];

    let mut total_files = 0;

    for dir in critical_dirs {
        if Path::new(dir).exists() {
            match monitor_directory_selective(dir, db, Some(&["exe", "dll", "sys"])) {
                Ok(count) => total_files += count,
                Err(e) => eprintln!("Warning: Failed to monitor {}: {}", dir, e),
            }
        }
    }

    Ok(total_files)
}

/// Monitor directory with file extension filter
pub fn monitor_directory_selective(
    dir_path: &str,
    db: &mut FIMDatabase,
    extensions: Option<&[&str]>,
) -> Result<usize, String> {
    let mut file_count = 0;

    for entry in WalkDir::new(dir_path)
        .max_depth(3) // Limit depth for performance
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            let path = entry.path();

            // Check extension filter
            if let Some(ext_list) = extensions {
                if let Some(ext) = path.extension() {
                    if !ext_list.contains(&ext.to_str().unwrap_or("")) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            let path_str = path.to_string_lossy().to_string();
            if db.add_file(&path_str).is_ok() {
                file_count += 1;
            }
        }
    }

    Ok(file_count)
}

/// Quick scan for ransomware indicators (file extension changes)
pub fn scan_for_ransomware_extensions(dir_path: &str) -> Result<Vec<String>, String> {
    let ransomware_extensions = vec![
        "encrypted", "locked", "crypted", "crypto", "cerber", "locky",
        "zepto", "osiris", "odin", "thor", "vault", "xtbl",
    ];

    let mut suspicious_files = Vec::new();

    for entry in WalkDir::new(dir_path)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() {
            if let Some(ext) = entry.path().extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if ransomware_extensions.contains(&ext_str.as_str()) {
                    suspicious_files.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }

    Ok(suspicious_files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fim_database() {
        let mut db = FIMDatabase::new();
        assert_eq!(db.snapshots.len(), 0);
    }

    #[test]
    fn test_file_hash() {
        // Create a test file
        use std::io::Write;
        let mut file = File::create("test_fim.txt").unwrap();
        file.write_all(b"test content").unwrap();

        let hash = calculate_file_hash_sha256("test_fim.txt");
        assert!(hash.is_ok());

        // Cleanup
        std::fs::remove_file("test_fim.txt").ok();
    }
}
