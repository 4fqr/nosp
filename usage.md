# NOSP Usage Reference

## Command-Line Interface

### Basic Commands

```bash
# Start NOSP with web interface
python main.py

# Initialize database
python main.py --init-db

# Full system scan
python main.py --scan

# Real-time monitoring mode
python main.py --watch

# Analyze specific process
python main.py --analyze <PID>
```

### Options

```bash
--host <IP>        Web server bind address (default: 127.0.0.1)
--port <PORT>      Web server port (default: 8080)
--db <PATH>        Database file path (default: nosp.db)
--log <LEVEL>      Log level: DEBUG, INFO, WARNING, ERROR
--no-tray          Disable system tray icon
--no-ai            Disable AI analysis
```

## Python Module Usage

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
