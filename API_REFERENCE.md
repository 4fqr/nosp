# API Reference

Complete API documentation for NOSP Python and Rust modules.

## 📚 Table of Contents

- [Python API](#python-api)
  - [AI Engine](#ai-engine)
  - [Database](#database)
  - [Risk Scorer](#risk-scorer)
  - [Forensics](#forensics)
  - [Alert System](#alert-system)
  - [Rules Engine](#rules-engine)
- [Rust API](#rust-api)
  - [Event Processing](#event-processing)
  - [System Control](#system-control)
  - [File Operations](#file-operations)
- [Integration Examples](#integration-examples)

---

## Python API

### AI Engine

**Module**: `nosp.ai_engine`

#### Class: `NOSPAIEngine`

AI engine for security threat analysis using local Ollama models.

##### Constructor

```python
NOSPAIEngine(model_name: str = "llama3")
```

**Parameters:**
- `model_name` (str): Name of the Ollama model to use. Default: `"llama3"`

**Available Models:**
- `llama3` - Best accuracy (4GB, ~450ms latency)
- `mistral` - Balanced (3.8GB, ~380ms latency)
- `phi` - Fastest (2GB, ~200ms latency)

**Example:**
```python
from nosp.ai_engine import NOSPAIEngine

# Initialize with default model
ai = NOSPAIEngine()

# Or specify model
ai = NOSPAIEngine(model_name="mistral")
```

##### Methods

###### `analyze_event(event: Dict) -> Dict`

Analyze a security event and provide threat intelligence.

**Parameters:**
- `event` (Dict): Event dictionary with keys:
  - `image` (str): Process executable path
  - `command_line` (str): Process command line
  - `user` (str): User account
  - `parent_image` (str): Parent process path
  - `risk_score` (int): Risk score (0-100)

**Returns:**
- Dict with keys:
  - `analysis` (str): Human-readable threat analysis
  - `mitre_tactics` (List[str]): MITRE ATT&CK tactics
  - `mitre_techniques` (List[str]): MITRE ATT&CK technique IDs
  - `severity` (str): "low", "medium", "high", or "critical"
  - `recommendations` (List[str]): Remediation actions
  - `confidence` (float): Analysis confidence (0.0-1.0)

**Example:**
```python
event = {
    'image': 'C:\\Windows\\System32\\powershell.exe',
    'command_line': 'powershell.exe -encodedCommand ...',
    'user': 'SYSTEM',
    'parent_image': 'C:\\Windows\\explorer.exe',
    'risk_score': 75
}

result = ai.analyze_event(event)
print(result['analysis'])
# Output: "This event shows potential malicious PowerShell execution..."

print(result['mitre_techniques'])
# Output: ['T1059.001', 'T1027']
```

###### `batch_analyze(events: List[Dict]) -> List[Dict]`

Analyze multiple events in batch for efficiency.

**Parameters:**
- `events` (List[Dict]): List of event dictionaries

**Returns:**
- List[Dict]: Analysis results for each event

**Example:**
```python
events = [event1, event2, event3]
results = ai.batch_analyze(events)

for result in results:
    if result['severity'] == 'critical':
        print(f"Critical: {result['analysis']}")
```

###### `get_model_info() -> Dict`

Get information about the current AI model.

**Returns:**
- Dict with keys:
  - `name` (str): Model name
  - `ready` (bool): Model availability status
  - `service_running` (bool): Ollama service status
  - `version` (str): Model version

**Example:**
```python
info = ai.get_model_info()
if not info['ready']:
    print("Model not available. Please run: ollama pull llama3")
```

---

### Database

**Module**: `nosp.database`

#### Class: `NOSPDatabase`

Thread-safe SQLite database handler for security events.

##### Constructor

```python
NOSPDatabase(db_path: str = "nosp_data/events.db")
```

**Parameters:**
- `db_path` (str): Path to SQLite database file. Default: `"nosp_data/events.db"`

**Example:**
```python
from nosp.database import NOSPDatabase

# Use default path
db = NOSPDatabase()

# Or custom path
db = NOSPDatabase(db_path="/secure/events.db")
```

##### Methods

###### `insert_event(event: Dict) -> bool`

Insert a new security event into the database.

**Parameters:**
- `event` (Dict): Event data with required keys:
  - `event_id` (int)
  - `timestamp` (str)
  - `computer` (str)
  - `process_guid` (str)
  - `process_id` (int)
  - `image` (str)
  - `command_line` (str)
  - `user` (str)
  - `parent_image` (str)
  - `parent_command_line` (str)
  - `hashes` (str)
  - `risk_score` (int, optional)
  - `ai_analysis` (str, optional)

**Returns:**
- bool: True if successful, False otherwise

**Example:**
```python
event = {
    'event_id': 1,
    'timestamp': '2026-02-08 12:00:00',
    'computer': 'WORKSTATION-01',
    'process_guid': '{ABC-123}',
    'process_id': 1234,
    'image': 'C:\\malware.exe',
    'command_line': 'malware.exe --spread',
    'user': 'Alice',
    'parent_image': 'C:\\Windows\\explorer.exe',
    'parent_command_line': 'C:\\Windows\\explorer.exe',
    'hashes': 'SHA256=abc123...',
    'risk_score': 85
}

if db.insert_event(event):
    print("Event stored successfully")
```

###### `get_events(limit: int = 100, min_risk: int = 0) -> List[Dict]`

Retrieve events from the database.

**Parameters:**
- `limit` (int): Maximum number of events to retrieve. Default: 100
- `min_risk` (int): Minimum risk score filter (0-100). Default: 0

**Returns:**
- List[Dict]: List of event dictionaries

**Example:**
```python
# Get last 50 high-risk events
high_risk = db.get_events(limit=50, min_risk=70)

for event in high_risk:
    print(f"{event['image']} - Risk: {event['risk_score']}")
```

###### `search_events(query: str) -> List[Dict]`

Search events by process name, command line, or user.

**Parameters:**
- `query` (str): Search term

**Returns:**
- List[Dict]: Matching events

**Example:**
```python
# Find all PowerShell events
ps_events = db.search_events("powershell")

# Find events by user
user_events = db.search_events("Alice")
```

###### `get_statistics() -> Dict`

Get database statistics.

**Returns:**
- Dict with keys:
  - `total_events` (int)
  - `high_risk_count` (int): Events with risk > 70
  - `analyzed_count` (int): AI-analyzed events
  - `unique_processes` (int)
  - `date_range` (Tuple[str, str]): First/last event timestamps

**Example:**
```python
stats = db.get_statistics()
print(f"Total events: {stats['total_events']}")
print(f"High risk: {stats['high_risk_count']}")
```

###### `cleanup(days: int = 30) -> int`

Delete old events from the database.

**Parameters:**
- `days` (int): Keep events from last N days. Default: 30

**Returns:**
- int: Number of events deleted

**Example:**
```python
# Delete events older than 7 days
deleted = db.cleanup(days=7)
print(f"Deleted {deleted} old events")
```

---

### Risk Scorer

**Module**: `nosp.risk_scorer`

#### Class: `RiskScorer`

Calculate risk scores for process events using multiple heuristics.

##### Constructor

```python
RiskScorer()
```

**Example:**
```python
from nosp.risk_scorer import RiskScorer

scorer = RiskScorer()
```

##### Methods

###### `calculate_risk(event: Dict) -> Tuple[int, List[Dict]]`

Calculate comprehensive risk score for an event.

**Parameters:**
- `event` (Dict): Event data with keys:
  - `image` (str): Process executable path
  - `command_line` (str): Process command line
  - `parent_image` (str): Parent process path
  - `user` (str): User account

**Returns:**
- Tuple[int, List[Dict]]:
  - `int`: Total risk score (0-100)
  - `List[Dict]`: Risk factors with structure:
    - `name` (str): Factor name
    - `value` (int): Points contributed
    - `description` (str): Explanation

**Score Ranges:**
- 0-25: Low risk (normal activity)
- 26-50: Medium risk (potentially suspicious)
- 51-75: High risk (likely malicious)
- 76-100: Critical risk (confirmed threat)

**Example:**
```python
event = {
    'image': 'C:\\Temp\\malware.exe',
    'command_line': 'malware.exe --silent',
    'parent_image': 'C:\\Windows\\System32\\cmd.exe',
    'user': 'SYSTEM'
}

risk_score, factors = scorer.calculate_risk(event)

print(f"Risk Score: {risk_score}")
for factor in factors:
    print(f"  - {factor['name']}: +{factor['value']} ({factor['description']})")

# Output:
# Risk Score: 85
#   - Suspicious Path: +20 (Temp directory execution)
#   - Suspicious Name: +30 (Known malware pattern)
#   - System Account: +15 (Running as SYSTEM)
#   - Unknown Parent: +20 (Uncommon parent process)
```

###### `check_suspicious_path(path: str) -> Tuple[bool, int]`

Check if a file path is suspicious.

**Parameters:**
- `path` (str): File path to check

**Returns:**
- Tuple[bool, int]: (is_suspicious, risk_points)

**Example:**
```python
is_susp, points = scorer.check_suspicious_path("C:\\Temp\\evil.exe")
print(f"Suspicious: {is_susp}, Points: {points}")
# Output: Suspicious: True, Points: 20
```

###### `check_command_line(cmdline: str) -> Tuple[bool, int]`

Check if a command line contains suspicious patterns.

**Parameters:**
- `cmdline` (str): Command line to analyze

**Returns:**
- Tuple[bool, int]: (is_suspicious, risk_points)

**Example:**
```python
is_susp, points = scorer.check_command_line(
    "powershell.exe -encodedCommand JABhAD..."
)
print(f"Suspicious: {is_susp}, Points: {points}")
# Output: Suspicious: True, Points: 25
```

---

### Forensics

**Module**: `nosp.forensics`

#### Class: `ProcessTree`

Build and analyze process parent-child relationships.

##### Constructor

```python
ProcessTree()
```

**Example:**
```python
from nosp.forensics import ProcessTree

tree = ProcessTree()
```

##### Methods

###### `add_process(event: Dict) -> None`

Add a process to the tree.

**Parameters:**
- `event` (Dict): Event data

**Example:**
```python
event = {
    'process_id': 1234,
    'image': 'C:\\Windows\\notepad.exe',
    'parent_image': 'C:\\Windows\\explorer.exe',
    'risk_score': 10
}

tree.add_process(event)
```

###### `get_tree_data() -> Dict`

Get tree data for visualization.

**Returns:**
- Dict with keys:
  - `nodes` (List[Dict]): Node data
  - `edges` (List[Dict]): Edge data

**Example:**
```python
data = tree.get_tree_data()

for node in data['nodes']:
    print(f"Process {node['id']}: {node['label']} (Risk: {node['risk']})")
```

###### `find_suspicious_chains() -> List[List[int]]`

Find process chains with escalating risk scores.

**Returns:**
- List[List[int]]: List of process ID chains

**Example:**
```python
chains = tree.find_suspicious_chains()

for chain in chains:
    print(f"Suspicious chain: {' -> '.join(map(str, chain))}")
```

#### Class: `ForensicReporter`

Generate comprehensive PDF forensic reports.

##### Constructor

```python
ForensicReporter()
```

**Example:**
```python
from nosp.forensics import ForensicReporter

reporter = ForensicReporter()
```

##### Methods

###### `generate_report(events: List[Dict], output_path: str) -> bool`

Generate a PDF forensic report.

**Parameters:**
- `events` (List[Dict]): Events to include in report
- `output_path` (str): Output PDF file path

**Returns:**
- bool: True if successful

**Example:**
```python
high_risk_events = db.get_events(min_risk=70)

reporter.generate_report(
    events=high_risk_events,
    output_path="forensic_report_2026-02-08.pdf"
)
```

---

### Alert System

**Module**: `nosp.alerts`

#### Class: `AudioAlertSystem`

Text-to-speech alert system for critical security events.

##### Constructor

```python
AudioAlertSystem()
```

**Example:**
```python
from nosp.alerts import AudioAlertSystem

alert_system = AudioAlertSystem()
```

##### Methods

###### `speak(message: str, priority: str = "medium") -> None`

Speak an alert message.

**Parameters:**
- `message` (str): Text to speak
- `priority` (str): "low", "medium", "high", or "critical"

**Example:**
```python
# Low priority
alert_system.speak("New event detected", priority="low")

# Critical alert
alert_system.speak("Critical threat detected!", priority="critical")
```

###### `speak_threat(event: Dict) -> None`

Speak a formatted threat alert.

**Parameters:**
- `event` (Dict): Event data

**Example:**
```python
event = {
    'image': 'malware.exe',
    'risk_score': 85,
    'user': 'Alice'
}

alert_system.speak_threat(event)
# Speaks: "Critical threat detected! Malware.exe with risk score 85 executed by user Alice"
```

###### `enable() -> None` / `disable() -> None`

Enable or disable the alert system.

**Example:**
```python
alert_system.disable()  # Silence alerts
alert_system.enable()   # Re-enable
```

---

### Rules Engine

**Module**: `nosp.rules_engine`

#### Class: `RulesEngine`

YAML-based detection rules with actions.

##### Constructor

```python
RulesEngine(rules_file: str = "rules.yaml")
```

**Parameters:**
- `rules_file` (str): Path to YAML rules file

**Example:**
```python
from nosp.rules_engine import RulesEngine

engine = RulesEngine()
# Or custom rules file
engine = RulesEngine(rules_file="custom_rules.yaml")
```

##### Methods

###### `evaluate(event: Dict) -> List[Dict]`

Evaluate an event against all enabled rules.

**Parameters:**
- `event` (Dict): Event to evaluate

**Returns:**
- List[Dict]: Matched rules with actions to execute

**Example:**
```python
event = {
    'image': 'C:\\malware.exe',
    'risk_score': 85
}

matches = engine.evaluate(event)

for match in matches:
    print(f"Rule matched: {match['name']}")
    print(f"Actions: {match['actions']}")
```

###### `add_rule(rule: Dict) -> bool`

Add a new rule programmatically.

**Parameters:**
- `rule` (Dict): Rule definition

**Returns:**
- bool: True if successful

**Example:**
```python
new_rule = {
    'name': 'Detect Ransomware',
    'description': 'Detects ransomware encryption activity',
    'enabled': True,
    'conditions': [
        {'field': 'image', 'operator': 'regex', 'value': r'.*\.encrypt.*'},
        {'field': 'risk_score', 'operator': 'greater_than', 'value': 80}
    ],
    'actions': [
        {'type': 'kill'},
        {'type': 'alert', 'priority': 'critical'}
    ]
}

engine.add_rule(new_rule)
```

###### `reload_rules() -> None`

Reload rules from YAML file.

**Example:**
```python
# After editing rules.yaml
engine.reload_rules()
```

---

## Rust API

**Module**: `nosp_core` (compiled Rust → Python bindings via PyO3)

### Event Processing

#### Function: `get_sysmon_events(count: int) -> List[Dict]`

Retrieve Sysmon events from Windows Event Log.

**Parameters:**
- `count` (int): Number of events to retrieve

**Returns:**
- List[Dict]: Event dictionaries

**Example:**
```python
import nosp_core

events = nosp_core.get_sysmon_events(count=100)

for event in events:
    print(f"PID {event['process_id']}: {event['image']}")
```

---

### System Control

#### Function: `terminate_process(pid: int) -> bool`

Terminate a process by PID.

**Parameters:**
- `pid` (int): Process ID

**Returns:**
- bool: True if successful

**Example:**
```python
import nosp_core

pid = 1234
if nosp_core.terminate_process(pid):
    print(f"Process {pid} terminated")
else:
    print(f"Failed to terminate process {pid}")
```

#### Function: `suspend_process(pid: int) -> bool`

Suspend a process by PID.

**Parameters:**
- `pid` (int): Process ID

**Returns:**
- bool: True if successful

**Example:**
```python
import nosp_core

# Freeze process for analysis
nosp_core.suspend_process(1234)

# ... analyze ...

# Resume not yet exposed, terminate or let OS handle
```

#### Function: `block_ip_firewall(ip: str) -> bool`

Block an IP address via Windows Firewall.

**Parameters:**
- `ip` (str): IP address to block

**Returns:**
- bool: True if successful

**Example:**
```python
import nosp_core

# Block malicious IP
if nosp_core.block_ip_firewall("192.168.1.100"):
    print("IP blocked in firewall")
```

---

### File Operations

#### Function: `calculate_file_hash(path: str) -> str`

Calculate SHA-256 hash of a file.

**Parameters:**
- `path` (str): File path

**Returns:**
- str: Hex-encoded SHA-256 hash

**Example:**
```python
import nosp_core

hash_value = nosp_core.calculate_file_hash("C:\\suspicious.exe")
print(f"SHA-256: {hash_value}")
```

#### Function: `quarantine_file(path: str) -> bool`

Quarantine a file with AES-256 encryption.

**Parameters:**
- `path` (str): File path to quarantine

**Returns:**
- bool: True if successful

**Example:**
```python
import nosp_core

# Quarantine malware
if nosp_core.quarantine_file("C:\\malware.exe"):
    print("File quarantined successfully")
```

#### Function: `scan_registry_autostart() -> List[Dict]`

Scan registry autostart locations.

**Returns:**
- List[Dict]: Autostart entries with keys:
  - `location` (str): Registry key path
  - `name` (str): Entry name
  - `value` (str): Entry value (executable path)

**Example:**
```python
import nosp_core

autostart_items = nosp_core.scan_registry_autostart()

for item in autostart_items:
    print(f"{item['location']}\\{item['name']} = {item['value']}")
```

---

## Integration Examples

### Complete Threat Detection Pipeline

```python
from nosp.database import NOSPDatabase
from nosp.risk_scorer import RiskScorer
from nosp.ai_engine import NOSPAIEngine
from nosp.rules_engine import RulesEngine
from nosp.alerts import AudioAlertSystem
import nosp_core

# Initialize components
db = NOSPDatabase()
scorer = RiskScorer()
ai = NOSPAIEngine()
rules = RulesEngine()
alerts = AudioAlertSystem()

# Fetch events
events = nosp_core.get_sysmon_events(count=100)

for event in events:
    # Calculate risk score
    risk_score, factors = scorer.calculate_risk(event)
    event['risk_score'] = risk_score
    
    # Store in database
    db.insert_event(event)
    
    # Evaluate rules
    matched_rules = rules.evaluate(event)
    
    if matched_rules:
        # Execute actions
        for rule in matched_rules:
            for action in rule['actions']:
                if action['type'] == 'kill':
                    nosp_core.terminate_process(event['process_id'])
                elif action['type'] == 'quarantine':
                    nosp_core.quarantine_file(event['image'])
                elif action['type'] == 'alert':
                    alerts.speak_threat(event)
        
        # AI analysis for critical events
        if risk_score > 70:
            analysis = ai.analyze_event(event)
            print(f"MITRE: {analysis['mitre_techniques']}")
            print(f"Analysis: {analysis['analysis']}")
```

### Custom Detection Rule

```python
from nosp.rules_engine import RulesEngine

engine = RulesEngine()

# Detect mimikatz
mimikatz_rule = {
    'name': 'Mimikatz Detection',
    'description': 'Detects mimikatz credential dumping',
    'enabled': True,
    'conditions': [
        {'field': 'image', 'operator': 'regex', 'value': r'mimikatz|mimi\.exe'},
        {'field': 'command_line', 'operator': 'contains', 'value': 'sekurlsa'}
    ],
    'actions': [
        {'type': 'kill'},
        {'type': 'quarantine'},
        {'type': 'alert', 'priority': 'critical'}
    ]
}

engine.add_rule(mimikatz_rule)
```

### Forensic Investigation

```python
from nosp.database import NOSPDatabase
from nosp.forensics import ProcessTree, ForensicReporter

db = NOSPDatabase()

# Build process tree
tree = ProcessTree()
events = db.get_events(limit=1000)

for event in events:
    tree.add_process(event)

# Find suspicious chains
chains = tree.find_suspicious_chains()

print(f"Found {len(chains)} suspicious process chains")

# Generate report
reporter = ForensicReporter()
high_risk = db.get_events(min_risk=70)

reporter.generate_report(
    events=high_risk,
    output_path="incident_report.pdf"
)
```

---

## Error Handling

All NOSP APIs use standard Python exceptions:

```python
from nosp.database import NOSPDatabase
import sqlite3

try:
    db = NOSPDatabase(db_path="/invalid/path/db.db")
except sqlite3.Error as e:
    print(f"Database error: {e}")

try:
    import nosp_core
    nosp_core.terminate_process(99999)  # Non-existent PID
except Exception as e:
    print(f"Operation failed: {e}")
```

---

## Type Hints

NOSP uses full type hints for better IDE support:

```python
from typing import Dict, List, Tuple, Optional

def analyze_event(event: Dict) -> Dict:
    """Type-hinted function."""
    pass

# Use with mypy for type checking
# mypy python/nosp/*.py
```

---

**Last Updated**: February 8, 2026  
**Version**: 1.0.0-APEX

[⬆ Back to Top](#api-reference)
