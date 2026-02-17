# NOSP — Network Observation Security Platform

## Overview

NOSP is a practical, production-focused threat detection platform. It combines event collection, heuristic scoring and optional AI analysis to provide real‑time monitoring and response. The implementation uses a Python orchestration layer with high‑performance Rust components for low‑level monitoring.

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

- Supported OS: **Windows 10/11** (Administrator privileges required for full feature set) or **Linux** (Debian/Ubuntu; root required for kernel/packet features)
- Python 3.8+ (3.11+ recommended)
- Rust 1.70+ (required only if building the Rust/pyo3 extension from source)
- Development headers for Python (e.g., `python3-dev` / `python-devel`) are required to build the Rust/Python extension (pyo3)

Notes:
- Many public Python APIs now provide `*_safe` variants that return a `Result` object; unhandled exceptions are logged to `nosp_error.log` (see Troubleshooting).
- Privileged operations (packet capture/injection, registry modifications, firewall/iptables changes) require elevated privileges and cannot be fully validated on unprivileged CI runners.
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

A small, purpose‑built CLI is available for headless use. Use `python -m nosp.cli` or the legacy `python main.py` entry points for simple tasks.

```bash
# Initialize database
python -m nosp.cli init-db --db ./nosp.db

# Run a heuristic process scan (top 10 suspicious)
python -m nosp.cli scan --top 10

# Run AI analysis for a running PID (best-effort)
python -m nosp.cli analyze --pid 1234

# Watch for new processes and report suspicious ones
python -m nosp.cli watch --duration 60
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

### Developer / Tests

- Unit tests: run `pytest -q` from the repository root (Python test-suite currently covers non-privileged code paths; current local suite: 30 tests).
- Rust: `cargo build --release` verifies Rust library builds; `cargo test` runs unit tests. Local `cargo test` may fail to link pyo3 tests unless `PYTHON_SYS_EXECUTABLE` is set to the interpreter used for the build.
- Build Python extension (pyo3): use `maturin develop` or `maturin build`.
- Continuous integration: GitHub Actions runs build and test jobs for both Linux and Windows; CI sets `PYTHON_SYS_EXECUTABLE` to ensure pyo3 tests link correctly.

Developer notes:
- Most public Python functions have `*_safe` counterparts that return a `Result` object rather than raising exceptions.
- Exception reporting is centralized; consult `nosp_error.log` for structured exception reports and remediation hints.
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

**Windows: ETW events not captured**: Run as Administrator.

**Linux: Limited monitoring**: Run with `sudo` for full capabilities.

**AI returns "Model not ready"**: Install Ollama and run `ollama pull mistral`.

**Database errors**: Stop NOSP, delete `nosp.db` (or remove the journal file `nosp.db-journal`) and restart.

**Rust import fails / pyo3 linkage errors**: Ensure Python development headers are installed and re-run `maturin develop` or `cargo build --release`.
- Local pyo3-linked tests may fail to link unless the build process is pointed at the exact Python executable. For local pyo3 test execution set the environment variable `PYTHON_SYS_EXECUTABLE` to your Python interpreter (example: `export PYTHON_SYS_EXECUTABLE=$(which python3)`). CI sets this variable automatically.

**Where exceptions are logged**: NOSP writes structured, developer-facing exception reports to `nosp_error.log` in the working directory. Use `tail -n 200 nosp_error.log` to inspect recent errors. Public APIs provide `*_safe` variants that return `Result` objects rather than raising unhandled exceptions.

**Privileged-feature limitations**: Packet capture/injection, firewall/iptables edits, and registry changes require elevated privileges and hardware/OS access; these operations require manual verification on suitably privileged test hosts.
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
