# NOSP User Guide

## Table of Contents

- [Installation Verification](#installation-verification)
- [First Launch](#first-launch)
- [Web Interface Overview](#web-interface-overview)
- [Creating Rules](#creating-rules)
- [AI Analysis](#ai-analysis)
- [Memory Forensics](#memory-forensics)
- [USB Management](#usb-management)
- [DNS Sinkholing](#dns-sinkholing)
- [Registry Protection](#registry-protection)
- [File Integrity Monitoring](#file-integrity-monitoring)
- [Blockchain Audit Log](#blockchain-audit-log)
- [P2P Threat Sharing](#p2p-threat-sharing)
- [Sandbox Analysis](#sandbox-analysis)
- [Environment Detection](#environment-detection)
- [Clipboard Protection](#clipboard-protection)
- [Packet Injection](#packet-injection)
- [Performance Tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [Advanced Usage](#advanced-usage)
- [Appendix](#appendix)

## Installation Verification

### Windows

After running `setup.bat`, verify components:

```cmd
python -c "from nosp import ai_engine, database, forensics; print('OK')"

python -c "import nosp_core; print('Rust module loaded')"

python main.py --init-db
```

Expected: No errors, database created at `nosp.db`.

### Linux (Debian/Ubuntu)

After running `sudo ./setup_linux.sh`, verify:

```bash
python3 -c "from nosp import ai_engine, database, forensics; print('OK')"

python3 -c "from nosp.linux_compat import LinuxProcessMonitor; print('OK')"

python3 main.py --init-db
```

Check monitoring capabilities:
```bash
systemctl status auditd
which auditctl
pip3 list | grep psutil
```

## First Launch

### Windows

1. Open Command Prompt as Administrator
2. Navigate to NOSP directory
3. Run: `run_nosp.bat` or `python main.py`
4. Wait for startup messages

### Linux

1. Open terminal in NOSP directory
2. Run with elevated privileges:
   ```bash
   sudo ./run_nosp_linux.sh
   ```
   Or manually:
   ```bash
   sudo python3 main.py
   ```
3. Wait for startup messages:
   ```
   ✓ Running on Linux - using compatibility layer
   ✓ AI Engine initialized
   ✓ Database connected
   ✓ Web server starting on http://localhost:8080
   ```

### Startup Output

```
   [INFO] Database initialized
   [INFO] AI engine ready (model: mistral)
   [INFO] ETW monitoring started
   [INFO] Web server running on http://127.0.0.1:8080
   [INFO] System tray icon active
   ```
5. Open browser to `http://localhost:8080`

## Web Interface Overview

### Dashboard Tab

Real-time event stream showing:
- Process starts/stops
- Network connections
- Registry modifications
- File operations
- USB events

Filters:
- Event type dropdown
- Time range selector
- Process name search
- Severity filter (Info/Warning/Critical)

### Logs Tab

Historical event log with:
- Timestamp
- Event type
- Process details
- Risk score
- AI analysis (if available)

Export options: CSV, JSON, XML

### Rules Tab

Rule management interface:
- Add new rules
- Edit existing rules
- Enable/disable rules
- Test rule syntax
- Import/export rule sets

### AI Analysis Tab

AI-powered threat analysis:
- Process behavior analysis
- MITRE ATT&CK technique mapping
- Threat severity rating
- Recommended actions

Actions:
- Analyze specific event
- Bulk analysis
- Schedule periodic scans

### Memory Scan Tab

Process memory forensics:
- Select process by PID or name
- Scan for known malware signatures
- Extract strings
- Dump memory regions
- Search for patterns

Results show:
- Suspicious strings
- Injected code
- Hidden modules
- Encrypted regions

### USB Control Tab

USB device management:
- List connected devices
- View device details (VID, PID, manufacturer)
- Block/allow devices
- Set default policy (allow all/block all/ask)
- View USB event history

### DNS Tab

DNS sinkhole configuration:
- Add domains to blocklist
- Import domain lists (text file, one per line)
- View DNS query log
- Statistics (queries blocked, top domains)

### Registry Tab

Registry protection:
- Monitor specific keys
- Protect critical keys
- View modification history
- Alert on unauthorized changes
- Restore from baseline

### FIM Tab

File Integrity Monitoring:
- Add files/directories to watch
- Scan for changes
- View integrity violations
- Update baselines
- Exclude patterns

### Blockchain Tab

Immutable audit log:
- View blockchain structure
- Verify chain integrity
- Export blockchain
- View block details
- Search blocks

### Mesh Network Tab

P2P threat intelligence:
- View connected peers
- Share threat indicators
- Query network for threats
- View reputation scores
- Configure network settings

### Sandbox Tab

Isolated execution environment:
- Upload suspicious file
- Configure sandbox (network, filesystem access)
- Execute and monitor
- View behavior analysis
- Download execution report

### Advanced Tab

System configuration:
- Log level
- AI model selection
- Database settings
- Performance tuning
- Self-defense options
- Environment detection

## Creating Rules

Rules define automated responses to events.

### Rule Syntax

```json
{
  "name": "Rule Name",
  "enabled": true,
  "condition": "EXPRESSION",
  "action": "ACTION_TYPE",
  "severity": "low|medium|high|critical"
}
```

### Supported Conditions

- `process_name == "notepad.exe"` - Exact match
- `command_line CONTAINS "powershell"` - Substring
- `parent_process == "explorer.exe"` - Parent check
- `user != "Administrator"` - User check
- `risk_score > 75` - Risk threshold
- `network_destination IN ["192.168.1.0/24"]` - IP range

### Logical Operators

- `AND` - Both conditions must be true
- `OR` - Either condition must be true
- `NOT` - Negation

### Actions

- `alert` - Show notification
- `log` - Write to log only
- `block` - Terminate process
- `elevate` - Escalate to security team
- `quarantine` - Move file to quarantine

### Example Rules

**Detect PowerShell with Encoded Command:**
```json
{
  "name": "PowerShell Encoded Execution",
  "condition": "process_name == 'powershell.exe' AND command_line CONTAINS '-enc'",
  "action": "block",
  "severity": "high"
}
```

**Monitor SYSTEM Account Activity:**
```json
{
  "name": "SYSTEM Account Usage",
  "condition": "user == 'SYSTEM' AND process_name NOT IN ['services.exe', 'svchost.exe']",
  "action": "alert",
  "severity": "medium"
}
```

**Block Untrusted USB Devices:**
```json
{
  "name": "Unknown USB Device",
  "condition": "event_type == 'usb_connected' AND device_trusted == false",
  "action": "block",
  "severity": "high"
}
```

## AI Analysis

Enable AI-powered threat detection:

1. Install Ollama: `pip install ollama`
2. Pull model: `ollama pull mistral`
3. Restart NOSP

AI analysis provides:
- Natural language threat description
- MITRE ATT&CK technique (e.g., T1055 - Process Injection)
- Confidence score (0-100)
- Recommended action
- IOCs (Indicators of Compromise)

To analyze an event:
1. Navigate to AI Analysis tab
2. Click "Analyze" on event row
3. Wait for results (2-5 seconds)
4. Review analysis and MITRE mapping

## Memory Forensics

Scan process memory for threats:

1. Navigate to Memory Scan tab
2. Enter PID or select from dropdown
3. Choose scan type:
   - Quick scan (signatures only)
   - Full scan (comprehensive)
   - String extraction
   - Pattern search
4. Click "Scan"
5. Review results:
   - Malware signatures found
   - Suspicious strings
   - Hidden DLLs
   - Injected code regions

To dump process memory:
1. Select process
2. Click "Dump Memory"
3. Choose output location
4. Analyze dump with external tools (Volatility, etc.)

## USB Management

Control USB device access:

**Block Device:**
1. Navigate to USB Control tab
2. Select device from connected list
3. Click "Block Device"
4. Device immediately disabled

**Allow Device:**
1. Select blocked device
2. Click "Allow Device"
3. Device re-enabled

**Set Default Policy:**
- Allow All: All USB devices permitted
- Block All: No USB devices allowed
- Ask: Prompt user for each device

**View History:**
1. Click "USB History"
2. Filter by device, date, action
3. Export report

## DNS Sinkholing

Block malicious domains:

**Add Domain:**
1. Navigate to DNS tab
2. Enter domain (e.g., `malicious.com`)
3. Click "Block"
4. Domain resolution blocked immediately

**Import List:**
1. Click "Import List"
2. Select text file (one domain per line)
3. Click "Upload"
4. All domains added to blocklist

**View Statistics:**
- Total queries
- Queries blocked
- Top queried domains
- Top blocked domains

## Registry Protection

Monitor and protect registry keys:

**Watch Key:**
1. Navigate to Registry tab
2. Enter key path (e.g., `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`)
3. Click "Add Watch"
4. Modifications logged

**Protect Key:**
1. Select watched key
2. Click "Protect"
3. Unauthorized changes blocked

**View History:**
1. Click "Registry History"
2. Filter by key, operation, date
3. See who changed what and when

## File Integrity Monitoring

Detect unauthorized file modifications:

**Add File:**
1. Navigate to FIM tab
2. Enter file path
3. Click "Add to Baseline"
4. Hash recorded

**Add Directory:**
1. Enter directory path
2. Check "Recursive" if needed
3. Click "Add Directory"
4. All files baselined

**Scan for Changes:**
1. Click "Scan Now"
2. Wait for scan to complete
3. Review violations:
   - Modified files
   - Deleted files
   - New files (unexpected)

**Update Baseline:**
1. Select file
2. Click "Update Baseline"
3. New hash recorded

## Blockchain Audit Log

Immutable event history:

**View Blockchain:**
1. Navigate to Blockchain tab
2. See block list with:
   - Block index
   - Timestamp
   - Event count
   - Hash
   - Previous hash

**Verify Integrity:**
1. Click "Verify Chain"
2. Results show if chain intact
3. Any tampering detected

**Export Chain:**
1. Click "Export"
2. Choose format (JSON, CSV)
3. Download file

## P2P Threat Sharing

Share threat intelligence with peers:

**Join Network:**
1. Navigate to Mesh Network tab
2. Click "Connect"
3. Enter port (default: 9000)
4. Connected peers listed

**Share Threat:**
1. Select event
2. Click "Share with Network"
3. Threat broadcast to all peers

**Query Network:**
1. Enter hash or IOC
2. Click "Query Network"
3. Results from all peers shown

## Sandbox Analysis

Execute suspicious files safely:

**Create Sandbox:**
1. Navigate to Sandbox tab
2. Click "New Sandbox"
3. Configure:
   - Network enabled/disabled
   - Filesystem access level
   - Timeout (seconds)
4. Click "Create"

**Execute File:**
1. Upload file or enter path
2. Click "Execute"
3. Monitor real-time:
   - Process activity
   - Network connections
   - File operations
   - Registry changes

**Review Results:**
1. Wait for completion
2. View behavior analysis:
   - Threat score
   - Malicious actions
   - IOCs extracted
3. Export report

## Environment Detection

Detect if NOSP is running in VM/Sandbox:

1. Navigate to Advanced tab
2. Click "Detect Environment"
3. Results show:
   - VM detection (VMware, VirtualBox, Hyper-V)
   - Sandbox detection
   - Debugger detection
   - System information

Use this to validate your deployment environment.

## Clipboard Protection

Monitor clipboard for sensitive data:

1. Navigate to Advanced tab
2. Enable "Clipboard Monitoring"
3. Define sensitive patterns:
   - Credit card numbers
   - Social Security numbers
   - API keys
   - Private keys
4. View clipboard events in logs
5. Alerts on potential data exfiltration

## Packet Injection

Inject network packets (advanced users):

1. Navigate to Advanced tab
2. Select "Packet Injection"
3. Choose packet type (ICMP, TCP, UDP, DNS)
4. Fill in fields:
   - Source/destination IP
   - Ports (TCP/UDP)
   - Payload
5. Click "Inject"

**Warning:** Use only for testing. Improper use may violate laws.

## Performance Tuning

Optimize NOSP performance:

**Reduce Event Load:**
1. Navigate to Advanced tab
2. Configure event filters:
   - Exclude noisy processes (e.g., svchost.exe)
   - Filter by event type
   - Set rate limiting

**Adjust AI Settings:**
1. Disable AI for low-risk events
2. Use smaller model (faster but less accurate)
3. Batch analysis instead of real-time

**Database Optimization:**
1. Set archive policy (auto-delete old events)
2. Enable compression
3. Vacuum database periodically

**Memory Management:**
1. Set max memory limit
2. Enable memory forensics only when needed
3. Adjust cache sizes

## Troubleshooting

### NOSP Won't Start

**Error:** "Access denied"
- **Fix:** Run as Administrator (Windows) or use `sudo` (Linux).

**Error:** "Port 8080 already in use"
- **Fix:** Change port with `--port 8081` or stop the process holding the port.

**Error:** "Database locked"
- **Fix:** Close other NOSP instances, delete `nosp.db-journal` and restart.

### No Events Captured

**Issue:** Dashboard empty
- **Check:** Administrator privileges
- **Check:** ETW provider registration (`wevtutil gp Microsoft-Windows-Kernel-Process`)
- **Fix:** Restart NOSP as Administrator

### AI Analysis Fails

**Error:** "Model not ready"
- **Fix:** Install Ollama: `pip install ollama`
- **Fix:** Pull model: `ollama pull mistral`
- **Check:** Ollama service running

**Error:** "Connection refused"
- **Fix:** Start Ollama service: `ollama serve`

### High CPU Usage

**Issue:** NOSP using >50% CPU
- **Fix:** Reduce event capture rate
- **Fix:** Disable AI for low-risk events
- **Fix:** Limit monitored processes

### Memory Leaks

**Issue:** Memory usage increasing over time
- **Fix:** Enable database archiving
- **Fix:** Clear old events: `DELETE FROM events WHERE timestamp < datetime('now', '-7 days')`
- **Fix:** Restart NOSP daily

### Error reporting & developer diagnostics

- All uncaught exceptions are recorded to `nosp_error.log` in the working directory. The log entries are structured and include trace, module, and remediation hints.
- Use `tail -n 200 nosp_error.log` to inspect recent error reports.
- When interacting programmatically, prefer `*_safe` APIs; these return `Result` objects to avoid exception propagation in host applications.

### pyo3 / Rust linkage notes

- Building or testing pyo3-backed components requires the Python development headers. If `cargo test` reports undefined Python symbols locally, set `PYTHON_SYS_EXECUTABLE` to the desired interpreter (for example: `export PYTHON_SYS_EXECUTABLE=$(which python3)`) before running `cargo test` or `maturin develop`.
- GitHub Actions in this repository sets `PYTHON_SYS_EXECUTABLE` automatically; CI jobs run Rust/Python tests on both Linux and Windows.

## Best Practices

### Security

1. Run NOSP as dedicated service account (not SYSTEM)
2. Encrypt database with DPAPI or BitLocker
3. Enable blockchain audit log for compliance
4. Regularly export and backup database
5. Use strong rules to block known threats
6. Enable all self-defense features

### Operations

1. Monitor NOSP logs for errors
2. Set up email alerts for critical events
3. Review AI analysis daily
4. Update threat intelligence feeds
5. Test rules before deploying
6. Maintain baseline configurations
7. Document custom rules

### Performance

1. Archive events older than 30 days
2. Use database read replicas for reporting
3. Separate AI analysis to dedicated machine
4. Limit DNS blocklist to <100k domains
5. Tune ETW filters to reduce noise

## Advanced Usage

### Custom AI Models

Train custom model:
1. Collect labeled security events
2. Fine-tune Mistral or GPT model
3. Export to ONNX
4. Configure NOSP to use custom model

### Integration with SIEM

Forward events to SIEM:
```python
from nosp.database import EventDatabase
import requests

db = EventDatabase()
events = db.get_events(limit=1000)

for event in events:
    requests.post('https://siem.company.com/api/events', json=event)
```

### Automated Response

Create Python script for automated actions:
```python
from nosp import rules_engine, database

def auto_respond():
    events = database.get_events(severity='critical', limit=10)
    for event in events:
        if event['threat_level'] > 90:
            os.system(f"taskkill /PID {event['pid']} /F")
            print(f"Terminated PID {event['pid']}")

if __name__ == '__main__':
    auto_respond()
```

### Multi-Node Deployment

Deploy NOSP across multiple endpoints:
1. Install NOSP on each endpoint
2. Configure P2P mesh network
3. Set up central dashboard
4. Share threat intelligence automatically
5. Aggregate events to central database

### API Integration

Use REST API in applications:
```python
import requests

# Get recent events
response = requests.get('http://localhost:8080/api/events?limit=10')
events = response.json()

# Create rule
rule = {
    'name': 'Block malware.exe',
    'condition': 'process_name == "malware.exe"',
    'action': 'block',
    'severity': 'critical'
}
response = requests.post('http://localhost:8080/api/rules', json=rule)
```

## Appendix

### File Locations

- Database: `nosp.db`
- Logs: `nosp.log`
- Configuration: `config.ini` (if using config file)
- Rules: Stored in database `rules` table
- Quarantine: `quarantine/` directory
- Memory dumps: `dumps/` directory
- Exports: `exports/` directory

### Network Ports

- Web interface: 8080 (TCP)
- P2P mesh: 9000 (TCP/UDP)
- DNS sinkhole: 53 (UDP)
- API: 8080 (TCP)

### Database Schema

**events table:**
- id (INTEGER PRIMARY KEY)
- timestamp (TEXT)
- event_type (TEXT)
- process_name (TEXT)
- pid (INTEGER)
- command_line (TEXT)
- user (TEXT)
- risk_score (REAL)
- ai_analysis (TEXT)
- blocked (BOOLEAN)

**rules table:**
- id (INTEGER PRIMARY KEY)
- name (TEXT)
- condition (TEXT)
- action (TEXT)
- severity (TEXT)
- enabled (BOOLEAN)

**usb_devices table:**
- hardware_id (TEXT PRIMARY KEY)
- device_name (TEXT)
- status (TEXT: allowed/blocked)
- last_seen (TEXT)

### Environment Variables

- `NOSP_DB_PATH` - Database file location
- `NOSP_LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)
- `NOSP_AI_MODEL` - AI model name
- `NOSP_PORT` - Web server port
- `NOSP_HOST` - Web server bind address
- `OLLAMA_HOST` - Ollama API endpoint

### Keyboard Shortcuts

- `Ctrl+R` - Refresh dashboard
- `Ctrl+F` - Search events
- `Ctrl+E` - Export current view
- `Ctrl+N` - New rule
- `Ctrl+S` - Save changes
- `F5` - Quick refresh
- `Esc` - Close dialog

## Linux-Specific Guide

### Initial Setup

**System Requirements:**
- Debian/Ubuntu Linux (tested on 20.04+)
- Python 3.8+
- Root access for monitoring features

**Installation:**
```bash
cd /path/to/NOSP
sudo ./setup_linux.sh
```

This installs:
- System dependencies (auditd, libpcap-dev, etc.)
- Python packages (psutil, pyudev, netfilterqueue)
- Rust toolchain (if not present)

### Process Monitoring on Linux

**Using auditd (Recommended):**

Enable process execution monitoring:
```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k nosp_exec
```

View audit events:
```bash
sudo ausearch -k nosp_exec | tail -20
```

Make persistent (survives reboot):
```bash
sudo cat >> /etc/audit/rules.d/nosp.rules << EOF
-a always,exit -F arch=b64 -S execve -k nosp_exec
EOF
sudo service auditd restart
```

**Using psutil (Fallback):**

NOSP automatically uses psutil if auditd is unavailable. No configuration needed.

### USB Device Management on Linux

**List USB devices:**
```bash
lsusb
```

**Monitor USB events with udev:**
```bash
sudo udevadm monitor --subsystem=usb
```

**Block specific USB device:**

Create udev rule:
```bash
sudo nano /etc/udev/rules.d/99-nosp-usb-block.rules
```

Add line (replace VID:PID):
```
SUBSYSTEM=="usb", ATTRS{idVendor}=="1234", ATTRS{idProduct}=="5678", MODE="0000"
```

Reload rules:
```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

### Network Packet Capture

**Enable packet capture:**
```bash
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
sudo python3 main.py
```

**View iptables rules:**
```bash
sudo iptables -L -n -v
```

**Remove NFQUEUE rule:**
```bash
sudo iptables -D FORWARD -j NFQUEUE --queue-num 1
```

### File Integrity Monitoring

**Monitor system directories:**
```python
from nosp import file_monitor

file_monitor.watch_directory("/etc", recursive=True)
file_monitor.watch_directory("/usr/bin")
file_monitor.watch_directory("/usr/sbin")
file_monitor.watch_directory("/home/user/.ssh")
```

**Generate baseline:**
```bash
python3 -c "
from nosp import file_monitor
file_monitor.generate_baseline('/etc')
file_monitor.generate_baseline('/usr/bin')
"
```

### Systemd Service Setup

Create service file:
```bash
sudo nano /etc/systemd/system/nosp.service
```

Content:
```ini
[Unit]
Description=NOSP Security Monitor
After=network.target auditd.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/NOSP
ExecStart=/usr/bin/python3 /opt/NOSP/main.py
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nosp
sudo systemctl start nosp
sudo systemctl status nosp
```

View logs:
```bash
sudo journalctl -u nosp -f
```

### Performance on Linux

**Reduce CPU usage:**
```bash
export PYTHONOPTIMIZE=1
nice -n 10 sudo python3 main.py
```

**Limit memory:**
```bash
sudo systemd-run --scope -p MemoryLimit=500M python3 main.py
```

**Check resource usage:**
```bash
top -p $(pgrep -f "python3 main.py")
```

### Troubleshooting Linux

**Issue:** auditd not capturing events  
**Solution:**
```bash
sudo systemctl status auditd
sudo auditctl -l
sudo ausearch -k nosp_exec
```

**Issue:** Permission denied  
**Solution:** Run with sudo or add user to required groups:
```bash
sudo usermod -aG sudo,audit,disk $USER
```

**Issue:** Port 8080 already in use  
**Solution:**
```bash
sudo lsof -i :8080
python3 main.py --port 8081
```

**Issue:** Rusmodule not loading  
**Solution:**
```bash
cd /path/to/NOSP
cargo clean
cargo build --release
```

**Issue:** Python module not found  
**Solution:**
```bash
export PYTHONPATH=$PWD/python:$PYTHONPATH
python3 main.py
```

### Linux Security Hardening

**SELinux compatibility:**
```bash
sudo setenforce 0
```

**AppArmor compatibility:**
```bash
sudo aa-disable /usr/bin/python3
```

**Firewall configuration:**
```bash
sudo ufw allow 8080/tcp
sudo ufw enable
```

### Developer / Testing

- Run Python unit tests: `pytest -q` (Python tests cover non-privileged code paths; current suite contains 30 tests).
- Build Rust library: `cargo build --release`.
- Build/install Python extension: `maturin develop` (requires Python dev headers).
- If pyo3 tests fail locally, set `PYTHON_SYS_EXECUTABLE=$(which python3)` prior to `cargo test` or rely on CI where this is configured.
- CI: GitHub Actions executes linting, Python unit tests, Rust build, and pyo3-linked checks on both Linux and Windows.

### Support Resources

- GitHub Issues: https://github.com/4fqr/nosp/issues
- Documentation: See README.md and usage.md
- License: See LICENSE file
