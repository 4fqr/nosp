# NOSP Usage Reference

## Platform Support

### Windows (Full Features)
- ETW event tracing
- Registry monitoring  
- USB device control via drivers
- Memory forensics
- All features available

### Linux (Debian/Ubuntu)
- Process monitoring (auditd/psutil)
- USB device enumeration (pyudev/lsusb)
- Network capture (netfilterqueue with root)
- File integrity monitoring
- AI threat analysis
- Web dashboard

## Command-Line Interface

### Basic Commands

**Windows:**
```cmd
run_nosp.bat
```

**Linux:**
```bash
sudo ./run_nosp_linux.sh
```

**Cross-platform:**
```bash
python main.py

python main.py --init-db

python main.py --scan

python main.py --watch

python main.py --analyze <PID>
```

### Options

```bash
--host <IP>        Web server bind address (default: 127.0.0.1)
--port <PORT>      Web server port (default: 8080)
--db <PATH>        Database file path (default: nosp.db)
--log <LEVEL>      Log level: DEBUG, INFO, WARNING, ERROR
--no-tray          Disable system tray icon (Windows only)
--no-ai            Disable AI analysis
```

### Linux-Specific Commands

**Setup (one-time):**
```bash
sudo ./setup_linux.sh
```

**Check monitoring capabilities:**
```bash
systemctl status auditd
which auditctl
which bpftrace
pip list | grep -E "psutil|pyudev|netfilterqueue"
```

**Enable process monitoring:**
```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k nosp_exec
```

**View audit events:**
```bash
sudo ausearch -k nosp_exec --format json
```

**Enable packet capture (requires root):**
```bash
sudo python main.py
```

## Python Module Usage

### Safe / developer-facing APIs

- Many public APIs expose a `*_safe` variant that returns a `Result` object instead of raising an exception. The `Result` object has `ok` (bool) and either `value` or `error` fields.
- Use `*_safe` when you require deterministic, programmatic handling of failures. Unexpected exceptions are written to `nosp_error.log` in the working directory.

Example:
```python
res = usb_control.block_device_safe("VID_1234&PID_5678")
if not res.ok:
    print(res.error['message'])
```

### Platform Compatibility Module

```python
from nosp.platform_compat import IS_WINDOWS, IS_LINUX, is_admin, get_platform

if IS_LINUX:
    print("Running on Linux")
    from nosp.linux_compat import LinuxProcessMonitor, LinuxUSBMonitor
    
    proc_mon = LinuxProcessMonitor()
    proc_mon.start_monitoring()
    events = proc_mon.get_events()

if is_admin():
    print("Running with elevated privileges")
```

### Linux Process Monitoring

```python
from nosp.linux_compat import LinuxProcessMonitor

monitor = LinuxProcessMonitor()

backends = monitor._detect_backends()
print(f"Available: {backends}")

monitor.start_monitoring()

events = monitor.get_events()
for event in events:
    print(f"{event['pid']}: {event['name']} - {event['cmdline']}")

monitor.stop_monitoring()
```

### Linux USB Monitoring

```python
from nosp.linux_compat import LinuxUSBMonitor

usb_mon = LinuxUSBMonitor()

devices = usb_mon.get_devices()
for dev in devices:
    print(f"VID: {dev.get('vendor_id')}, PID: {dev.get('product_id')}")
    print(f"Vendor: {dev.get('vendor')}, Model: {dev.get('model')}")

result = usb_mon.block_device("1234:5678")
if result:
    print("✓ Device blocked via udev rules")
```

### Linux Network Capture

```python
from nosp.linux_compat import LinuxNetworkMonitor

net_mon = LinuxNetworkMonitor()

def packet_callback(pkt):
    print(f"Packet: {pkt.get_payload()}")

net_mon.start_packet_capture(packet_callback)
```

### AI Engine

```python
from nosp.ai_engine import AIEngine

engine = AIEngine(model_name="mistral")

# Analyze process event
event = {
    'process_name': 'suspicious.exe',
    'command_line': 'cmd.exe /c powershell -enc ...',
    'parent_process': 'winword.exe',
    'user': 'SYSTEM'
}

analysis = engine.analyze_process(event)
print(analysis)
```

### Memory Forensics

```python
from nosp.forensics import MemoryForensics

forensics = MemoryForensics()

# Scan process memory
results = forensics.scan_process_memory(pid=1234)

# Dump process memory
forensics.dump_process(pid=1234, output="dump.bin")

# String extraction
strings = forensics.extract_strings(pid=1234, min_length=4)

# Pattern search
matches = forensics.search_pattern(pid=1234, pattern=b"MZ\x90\x00")
```

### USB Control

```python
from nosp import usb_control

# Block device by hardware ID
usb_control.block_device("VID_1234&PID_5678")

# Allow device
usb_control.allow_device("VID_1234&PID_5678")

# List connected devices
devices = usb_control.get_connected_devices()
for device in devices:
    print(f"{device['name']}: {device['hardware_id']}")

# Get device status
status = usb_control.get_device_status("VID_1234&PID_5678")
```

### DNS Sinkhole

```python
from nosp import dns_sinkhole

# Add domain to blocklist
dns_sinkhole.block_domain("malicious.com")

# Remove from blocklist
dns_sinkhole.unblock_domain("malicious.com")

# Query domain status
is_blocked = dns_sinkhole.is_blocked("malicious.com")

# Get all blocked domains
blocked = dns_sinkhole.get_blocked_domains()
```

### Registry Operations

```python
from nosp import registry_monitor

# Start monitoring key
registry_monitor.watch_key(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run")

# Get key changes
changes = registry_monitor.get_changes()
for change in changes:
    print(f"{change['operation']}: {change['key']} = {change['value']}")

# Protect key (prevent modifications)
registry_monitor.protect_key(r"HKLM\System\CurrentControlSet\Services")

# Unprotect key
registry_monitor.unprotect_key(r"HKLM\System\CurrentControlSet\Services")
```

### File Integrity Monitoring

```python
from nosp import file_monitor

# Add file to watchlist
file_monitor.watch_file(r"C:\Windows\System32\kernel32.dll")

# Add directory (recursive)
file_monitor.watch_directory(r"C:\Windows\System32", recursive=True)

# Check integrity
violations = file_monitor.check_integrity()
for violation in violations:
    print(f"Modified: {violation['path']}")
    print(f"  Expected: {violation['expected_hash']}")
    print(f"  Actual: {violation['actual_hash']}")

# Get file baseline
baseline = file_monitor.get_baseline(r"C:\Windows\System32\kernel32.dll")
```

### Environment Detection

```python
from nosp import environment

# Check if running in VM
is_vm = environment.detect_vm()
print(f"VM detected: {is_vm}")

# Check if running in sandbox
is_sandbox = environment.detect_sandbox()
print(f"Sandbox detected: {is_sandbox}")

# Get detailed environment info
info = environment.get_environment_info()
print(f"OS: {info['os']}")
print(f"Hostname: {info['hostname']}")
print(f"Username: {info['username']}")
print(f"Privileges: {info['privileges']}")
```

### Self-Defense

```python
from nosp import self_defense

# Enable process protection
self_defense.enable_protection()

# Verify integrity
is_intact = self_defense.verify_integrity()
if not is_intact:
    print("WARNING: NOSP integrity compromised")

# Check for debugger
if self_defense.detect_debugger():
    print("Debugger detected")

# Anti-tampering
self_defense.protect_files([
    "main.py",
    "python/nosp/*.py",
    "nosp.db"
])
```

### Clipboard Monitoring

```python
from nosp import clipboard_monitor

# Start monitoring
clipboard_monitor.start()

# Get clipboard events
events = clipboard_monitor.get_events()
for event in events:
    print(f"{event['timestamp']}: {event['process']} accessed clipboard")
    print(f"  Content type: {event['content_type']}")

# Check for sensitive data
sensitive = clipboard_monitor.scan_for_sensitive_data()
for item in sensitive:
    print(f"Potential leak: {item['type']} in clipboard by {item['process']}")
```

### Blockchain Ledger

```python
from nosp import blockchain

# Add event to blockchain
blockchain.add_event({
    'type': 'process_start',
    'process': 'notepad.exe',
    'timestamp': '2024-02-08T12:00:00',
    'hash': 'abc123...'
})

# Verify chain integrity
is_valid = blockchain.verify_chain()
print(f"Blockchain valid: {is_valid}")

# Get block by index
block = blockchain.get_block(10)

# Export blockchain
blockchain.export("audit_log.json")
```

### P2P Mesh Network

```python
from nosp import mesh_network

# Join network
mesh_network.connect(port=9000)

# Share threat intelligence
mesh_network.share_threat({
    'hash': 'abc123...',
    'threat_name': 'TrojanX',
    'severity': 'high',
    'indicators': ['192.168.1.100', 'malicious.com']
})

# Query network for threats
threats = mesh_network.query_threats(hash='abc123...')

# Get peer list
peers = mesh_network.get_peers()
print(f"Connected peers: {len(peers)}")
```

### Sandbox Operations

```python
from nosp import sandbox

# Create sandbox
sb = sandbox.create(isolated=True, network_enabled=False)

# Execute file in sandbox
result = sb.execute(r"C:\suspicious.exe", timeout=60)
print(f"Exit code: {result['exit_code']}")
print(f"Network activity: {result['network_connections']}")
print(f"File operations: {result['file_operations']}")

# Analyze behavior
behavior = sb.analyze_behavior()
print(f"Threat score: {behavior['score']}")
print(f"Suspicious actions: {behavior['actions']}")

# Destroy sandbox
sb.destroy()
```

### Packet Injection

```python
from nosp import packet_injector

# Inject ICMP packet
packet_injector.inject_icmp(
    src_ip="192.168.1.10",
    dst_ip="192.168.1.1",
    payload=b"test"
)

# Inject TCP packet
packet_injector.inject_tcp(
    src_ip="192.168.1.10",
    dst_ip="192.168.1.100",
    src_port=12345,
    dst_port=80,
    flags="SYN"
)

# Inject UDP packet
packet_injector.inject_udp(
    src_ip="192.168.1.10",
    dst_ip="192.168.1.100",
    src_port=12345,
    dst_port=53,
    payload=b"DNS query"
)

# Inject DNS response
packet_injector.inject_dns(
    query_id=1234,
    domain="example.com",
    ip_address="1.2.3.4"
)
```

### Database Queries

```python
from nosp.database import EventDatabase

db = EventDatabase("nosp.db")

# Get recent events
events = db.get_events(limit=100, offset=0)

# Filter by type
process_events = db.get_events(event_type="process_start")

# Time-based query
recent = db.get_events(
    start_time="2024-02-08T00:00:00",
    end_time="2024-02-08T23:59:59"
)

# Search by process name
notepad_events = db.search_events(process_name="notepad.exe")

# Get statistics
stats = db.get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"Threats detected: {stats['threats']}")
print(f"Blocked events: {stats['blocked']}")
```

### Rules Engine

```python
from nosp import rules_engine

# Add rule
rules_engine.add_rule({
    'name': 'Detect PowerShell Execution',
    'condition': 'process_name == "powershell.exe" AND command_line CONTAINS "-enc"',
    'action': 'alert',
    'severity': 'high'
})

# Execute rules against event
event = {'process_name': 'powershell.exe', 'command_line': 'powershell -enc ...'}
matches = rules_engine.evaluate(event)
for match in matches:
    print(f"Rule triggered: {match['name']}")

# Get all rules
rules = rules_engine.get_rules()

# Delete rule
rules_engine.delete_rule(rule_id=5)
```

## Exit Codes

- 0: Success
- 1: General error
- 2: Database error
- 3: Permission denied (not Administrator)
- 4: Rust module load failure
- 5: AI engine initialization failure
- 6: Network error

## Web API Endpoints

### Events

- `GET /api/events` - Get events (query params: limit, offset, type)
- `GET /api/events/<id>` - Get event by ID
- `POST /api/events` - Add event manually

### Rules

- `GET /api/rules` - List all rules
- `POST /api/rules` - Create rule
- `PUT /api/rules/<id>` - Update rule
- `DELETE /api/rules/<id>` - Delete rule

### USB

- `GET /api/usb/devices` - List USB devices
- `POST /api/usb/block` - Block device (body: {hardware_id})
- `POST /api/usb/allow` - Allow device (body: {hardware_id})

### DNS

- `GET /api/dns/blocked` - Get blocked domains
- `POST /api/dns/block` - Block domain (body: {domain})
- `DELETE /api/dns/block/<domain>` - Unblock domain

### AI Analysis

- `POST /api/analyze` - Analyze event (body: event object)
- `GET /api/analyze/<event_id>` - Get analysis result

### System

- `GET /api/status` - System status
- `GET /api/stats` - Statistics
- `POST /api/scan` - Trigger system scan

## Linux-Specific Features

### Process Monitoring Backends

**auditd (Recommended):**
```bash
sudo apt install auditd
sudo systemctl enable auditd
sudo systemctl start auditd
```

**psutil (Fallback):**
```bash
pip install psutil
```

**bpftrace (Advanced):**
```bash
sudo apt install bpftrace
```

### USB Device Management

**pyudev (Recommended):**
```bash
pip install pyudev
```

**lsusb (Fallback):**
```bash
sudo apt install usbutils
lsusb
```

**Block device via udev rules:**
```bash
sudo cat > /etc/udev/rules.d/99-nosp-block.rules << EOF
SUBSYSTEM=="usb", ATTRS{idVendor}=="1234", ATTRS{idProduct}=="5678", MODE="0000"
EOF
sudo udevadm control --reload-rules
```

### Network Capture

**netfilterqueue (Requires root):**
```bash
sudo apt install build-essential python3-dev libnetfilter-queue-dev
pip install NetfilterQueue
```

**Use NFQUEUE:**
```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
sudo python main.py
```

### File Integrity Monitoring

```python
from nosp import file_monitor

file_monitor.watch_directory("/etc", recursive=True)
file_monitor.watch_directory("/usr/bin")
file_monitor.watch_directory("/home/user/.ssh")

violations = file_monitor.check_integrity()
```

## Troubleshooting

### Windows

**Issue:** ETW events not captured  
**Solution:** Run as Administrator

**Issue:** System tray icon not showing  
**Solution:** Install `pip install pystray pillow`

### Linux

**Issue:** Process monitoring not working  
**Solution:** Install auditd: `sudo apt install auditd`

**Issue:** Permission denied errors  
**Solution:** Run with sudo: `sudo python main.py`

**Issue:** USB devices not detected  
**Solution:** Install pyudev: `pip install pyudev`

**Issue:** Network capture fails  
**Solution:** Install netfilterqueue and run with sudo

**Issue:** Module not found errors  
**Solution:** Run setup script: `sudo ./setup_linux.sh`

### Cross-Platform

**Issue:** AI analysis not working  
**Solution:** Install Ollama: `pip install ollama` and `ollama pull mistral`

**Issue:** Database errors  
**Solution:** Delete nosp.db and restart: `rm nosp.db && python main.py`

**Issue:** Import errors  
**Solution:** Set PYTHONPATH: `export PYTHONPATH=$PWD/python:$PYTHONPATH`

