# NOSP - Neural Operating System Protector

## Overview

NOSP is a threat detection system combining kernel-level event monitoring with AI-powered behavioral analysis. It provides real-time protection through Python orchestration, Rust performance modules, and AI threat intelligence.

## Features

- Kernel-level ETW monitoring for Windows processes, registry, and network events
- AI-powered threat assessment with MITRE ATT&CK framework mapping
- Behavioral risk scoring with dynamic thresholds
- USB device control with allowlist/blocklist enforcement
- DNS sinkholing for malicious domains
- Registry protection and monitoring
- In-memory forensics and process scanning
- File integrity monitoring using SHA-256 verification
- VM/sandbox detection
- Self-defense mechanisms
- Clipboard monitoring
- Blockchain audit logging
- P2P threat intelligence sharing
- Virtual sandboxing for untrusted processes
- Network packet injection capabilities
- Web dashboard with real-time monitoring
- System tray integration
- Rule engine with PowerShell support

## Requirements

- **Windows 10/11** (Administrator privileges) or **Linux** (Debian/Ubuntu with root for full features)
- Python 3.8+
- Rust 1.70+ (if building from source)

## Installation

### Automated Setup (Windows)

```cmd
setup.bat
```

This installs Python dependencies, compiles Rust modules, and configures the database.

### Automated Setup (Linux - Debian/Ubuntu)

```bash
sudo ./setup_linux.sh
```

This installs system dependencies, Python packages, and configures monitoring capabilities.

### Manual Setup

```bash
pip install -r requirements.txt

cargo build --release

python main.py --init-db
```

## Quick Start

### Launch NOSP

**Windows:**
```cmd
run_nosp.bat
```

**Linux:**
```bash
sudo ./run_nosp_linux.sh
```

**Or manually:**

```bash
python main.py
```

### Access Web Interface

Navigate to `http://localhost:8080`

### Enable AI Analysis

```bash
pip install ollama
ollama pull mistral
```

## Usage

### Command Line

```bash
python main.py --scan          # Full system scan
python main.py --watch         # Real-time monitoring
python main.py --analyze PID   # Analyze specific process
```

### Python Module

```python
from nosp import forensics, usb_control

# Memory scan
forensics.scan_process_memory(pid=1234)

# USB control
usb_control.block_device("VID_1234&PID_5678")
```

### Web Interface

1. Launch NOSP
2. Open `http://localhost:8080`
3. Monitor events on Dashboard tab
4. Create rules in Rules tab
5. View AI analysis results

## Configuration

Environment variables or edit `main.py`:

```python
db_path = "nosp.db"
ai_model = "mistral"
host = "127.0.0.1"
port = 8080
log_level = "INFO"
```

## Architecture

### Tri-Language Design

```
Python Orchestrator (Flask, AI, Database, Alerts)
           ↓
Rust Core (ETW, Memory, USB, DNS, Registry)
```

- **Python**: AI engine (Ollama), web UI, database, system tray, alerts
- **Rust**: High-performance kernel event capture, memory forensics
- **Flow**: ETW events → Rust → Python → AI → Database → UI

## Project Structure

```
NOSP/
├── main.py                    Entry point
├── python/nosp/               Python modules
│   ├── ai_engine.py          AI integration
│   ├── database.py           SQLite backend
│   ├── forensics.py          Memory scanning
│   ├── risk_scorer.py        Threat scoring
│   ├── alerts.py             Notifications
│   └── system_tray.py        System tray
├── src/lib.rs                 Rust ETW code
├── Cargo.toml                 Rust config
└── requirements.txt           Python deps
```

## Troubleshooting

**Windows: ETW events not captured**: Run as Administrator

**Linux: Limited monitoring**: Run with `sudo` for full capabilities

**AI returns "Model not ready"**: Install Ollama and run `ollama pull mistral`

**Database errors**: Delete `nosp.db` and restart

**Rust import fails**: Rebuild with `cargo build --release` or `maturin develop`

## Platform Compatibility

### Windows (Full Support)
- ETW event tracing
- Registry monitoring
- USB device control
- Memory forensics
- All features available

### Linux (Debian/Ubuntu)
- Process monitoring via auditd/psutil
- USB device enumeration via pyudev
- Network capture via netfilterqueue
- File integrity monitoring
- AI threat analysis
- Web dashboard

**Note**: Windows-specific features (ETW, Registry) are not available on Linux but gracefully degrade.

## Performance

- Event throughput: ~10,000 events/second
- AI latency: ~2-5 seconds per analysis
- Memory usage: ~150-300 MB baseline
- Database growth: ~10 MB per 10,000 events

## License

MIT License - see [LICENSE](LICENSE) file.
