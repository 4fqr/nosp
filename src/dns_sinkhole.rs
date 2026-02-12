

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

const HOSTS_FILE_PATH: &str = "C:\\Windows\\System32\\drivers\\etc\\hosts";
const NOSP_MARKER: &str = "# NOSP DNS Sinkhole Entry";

#[derive(Debug, Clone)]
pub struct SinkholeEntry {
    pub domain: String,
    pub redirect_ip: String,
    pub is_active: bool,
}

pub fn sinkhole_domain(domain: &str) -> Result<(), String> {
    sinkhole_domain_to_ip(domain, "127.0.0.1")
}

pub fn sinkhole_domain_to_ip(domain: &str, ip: &str) -> Result<(), String> {
    if domain.is_empty() || domain.contains(' ') {
        return Err("Invalid domain name".to_string());
    }

    if !is_valid_ip(ip) {
        return Err("Invalid IP address".to_string());
    }

    if is_domain_sinkholed(domain)? {
        return Ok(());
    }

    let mut file = OpenOptions::new()
        .append(true)
        .open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file (need Administrator): {}", e))?;

    writeln!(file, "{} {} {}", ip, domain, NOSP_MARKER)
        .map_err(|e| format!("Failed to write to hosts file: {}", e))?;

    Ok(())
}

pub fn unsinkhole_domain(domain: &str) -> Result<(), String> {
    let file = File::open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file: {}", e))?;
    let reader = BufReader::new(file);

    let mut lines = Vec::new();
    let mut removed = false;

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;

        if line.contains(domain) && line.contains(NOSP_MARKER) {
            removed = true;
            continue;
        }

        lines.push(line);
    }

    if !removed {
        return Err("Domain not found in sinkhole".to_string());
    }

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file for writing: {}", e))?;

    for line in lines {
        writeln!(file, "{}", line).map_err(|e| format!("Failed to write line: {}", e))?;
    }

    Ok(())
}

pub fn is_domain_sinkholed(domain: &str) -> Result<bool, String> {
    let file = File::open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file: {}", e))?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Ok(line) = line {
            if line.contains(domain) && line.contains(NOSP_MARKER) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub fn list_sinkholed_domains() -> Result<Vec<SinkholeEntry>, String> {
    let file = File::open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file: {}", e))?;
    let reader = BufReader::new(file);

    let mut entries = Vec::new();

    for line in reader.lines() {
        if let Ok(line) = line {
            if line.contains(NOSP_MARKER) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    entries.push(SinkholeEntry {
                        redirect_ip: parts[0].to_string(),
                        domain: parts[1].to_string(),
                        is_active: true,
                    });
                }
            }
        }
    }

    Ok(entries)
}

pub fn sinkhole_ioc_list(domains: &[String]) -> Result<usize, String> {
    let mut success_count = 0;

    for domain in domains {
        if sinkhole_domain(domain).is_ok() {
            success_count += 1;
        }
    }

    Ok(success_count)
}

pub fn clear_all_sinkholes() -> Result<usize, String> {
    let file = File::open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file: {}", e))?;
    let reader = BufReader::new(file);

    let mut lines = Vec::new();
    let mut removed_count = 0;

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Failed to read line: {}", e))?;

        if line.contains(NOSP_MARKER) {
            removed_count += 1;
            continue;
        }

        lines.push(line);
    }

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(HOSTS_FILE_PATH)
        .map_err(|e| format!("Failed to open hosts file for writing: {}", e))?;

    for line in lines {
        writeln!(file, "{}", line).map_err(|e| format!("Failed to write line: {}", e))?;
    }

    Ok(removed_count)
}

fn is_valid_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }

    for part in parts {
        if let Ok(num) = part.parse::<u8>() {
            if num > 255 {
                return false;
            }
        } else {
            return false;
        }
    }

    true
}

pub fn sinkhole_common_c2_domains() -> Result<usize, String> {
    let c2_domains = vec![
        "evil.com",
        "malware-c2.net",
        "ransomware.xyz",
        "phishing-site.com",
        "trojan-server.org",
    ];

    let mut count = 0;
    for domain in c2_domains {
        if sinkhole_domain(domain).is_ok() {
            count += 1;
        }
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_validation() {
        assert!(is_valid_ip("127.0.0.1"));
        assert!(is_valid_ip("192.168.1.1"));
        assert!(!is_valid_ip("256.1.1.1"));
        assert!(!is_valid_ip("invalid"));
    }

    #[test]
    fn test_list_sinkholed() {
        let result = list_sinkholed_domains();
        assert!(result.is_ok());
    }
}
