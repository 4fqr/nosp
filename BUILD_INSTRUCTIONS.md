# NOSP OMNI-CORE Build Instructions

## ⚠️ Platform Requirements

**NOSP OMNI-CORE is designed exclusively for Windows** due to deep OS integration:
- Windows API (SetupAPI, Configuration Manager, Registry, WinSock2)
- Sysmon event log access
- Windows-specific security features

**Supported Platforms:**
- ✅ Windows 10 (Build 19041+)
- ✅ Windows 11 (all builds)
- ❌ Linux (compilation will fail - Windows APIs not available)
- ❌ macOS (not supported)

---

## 🛠️ Build Prerequisites

### 1. Install Rust Toolchain (Windows)

```powershell
# Download and run rustup-init.exe from https://rustup.rs
rustup-init.exe

# Add Windows MSVC target (default)
rustup target add x86_64-pc-windows-msvc

# Verify installation
rustc --version  # Should show 1.70.0 or newer
cargo --version
```

### 2. Install C Compiler

**Option A: Visual Studio Build Tools (Recommended)**
```powershell
# Download from: https://visualstudio.microsoft.com/downloads/
# Select "Desktop development with C++"
# Includes MSVC, Windows SDK
```

**Option B: MinGW-w64 with GCC**
```powershell
# Download from: https://www.mingw-w64.org/downloads/
# Add to PATH: C:\mingw64\bin
gcc --version  # Should show 9.0.0 or newer
```

### 3. Install Python 3.8+

```powershell
# Download from https://www.python.org/downloads/
python --version  # Should show 3.8.0 or newer
pip --version
```

### 4. Install Npcap (for packet capture)

```powershell
# Download from: https://npcap.com/#download
# Required for C packet capture module
# Ensure "WinPcap API Compatibility Mode" is enabled
```

---

## 🔨 Building C Modules

### Pattern Matcher

```powershell
cd native\c

# With MSVC (Visual Studio)
cl /O2 /MD /LD pattern_matcher.c /Fepattern_matcher.dll

# With GCC (MinGW)
gcc -O3 -march=native -shared -o pattern_matcher.dll pattern_matcher.c

# Test
gcc -O3 -march=native -o test_pattern test_pattern.c pattern_matcher.c
.\test_pattern.exe
```

**Expected Output:**
```
Initializing Aho-Corasick matcher...
Added 10,000 patterns in 45ms
Building failure function...
Scanning 1MB text...
Found 234 matches in 0.8ms (1250 MB/s)
✅ PASS
```

### Packet Capture

```powershell
# With MSVC
cl /O2 /MD /LD packet_capture.c /Fepacket_capture.dll Ws2_32.lib

# With GCC
gcc -O3 -march=native -shared -o packet_capture.dll packet_capture.c -lws2_32

# Test (requires Administrator)
gcc -O3 -march=native -o test_capture test_capture.c packet_capture.c -lws2_32
.\test_capture.exe
```

**Expected Output:**
```
Initializing packet capture on 192.168.1.100...
Entering promiscuous mode...
Captured 10,245 packets in 60 seconds
  TCP: 8,123 packets
  UDP: 1,894 packets
  Other: 228 packets
✅ PASS
```

---

## 🦀 Building Rust Core

### Standard Build

```powershell
cd C:\path\to\NOSP

# Development build (faster compilation, no optimizations)
cargo build

# Release build (optimized, production-ready)
cargo build --release

# Output: target\release\nosp_core.pyd
```

**Expected Output:**
```
   Compiling nosp_core v0.1.0
    Finished release [optimized] target(s) in 142.34s
```

### Module-Specific Tests

```powershell
# Test memory analysis
cargo test --package nosp_core --lib memory_analysis::tests

# Test USB control
cargo test --package nosp_core --lib usb_control::tests

# Test DNS sinkhole
cargo test --package nosp_core --lib dns_sinkhole::tests

# Test all modules
cargo test --all
```

### Building with Maturin (Python Integration)

```powershell
# Install maturin
pip install maturin

# Development build (editable install)
maturin develop --release

# Production wheel
maturin build --release --out dist

# Install wheel
pip install dist\nosp_core-0.1.0-cp311-cp311-win_amd64.whl
```

**Verify Python Integration:**
```powershell
python -c "import nosp_core; print(nosp_core.list_usb_devices_py())"
```

---

## 🐍 Setting Up Python Environment

### Install Dependencies

```powershell
# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Install Ollama (for AI features)
# Download from: https://ollama.com/download
ollama pull llama3.2
```

### Install Sysmon

```powershell
# Download Sysmon from Microsoft Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with default config
sysmon64.exe -accepteula -i

# Or use custom config
sysmon64.exe -accepteula -i sysmon_config.xml
```

---

## 🚀 Running NOSP

### Quick Start

```powershell
# Run setup script
.\setup.bat

# Start NOSP
.\run_nosp.bat
```

### Manual Start

```powershell
# Activate virtual environment
.\venv\Scripts\activate

# Ensure Ollama is running
Start-Job { ollama serve }

# Start NOSP (requires Administrator)
python main.py
```

**Access UI:**
```
Open browser: http://localhost:8501
```

---

## 🧪 Testing

### Unit Tests

```powershell
# Rust tests
cargo test --all --release

# Python tests
pytest tests\ -v
```

### Integration Tests

```powershell
# Test memory analysis (scan current process)
python -c "import nosp_core; print(nosp_core.scan_process_memory_py(import os; os.getpid()))"

# Test USB enumeration
python -c "import nosp_core; print(nosp_core.list_usb_devices_py())"

# Test DNS sinkhole
python -c "import nosp_core; nosp_core.sinkhole_domain_py('evil.com')"

# Test FIM
python -c "import nosp_core; print(nosp_core.fim_check_changes_py('C:\\Windows\\System32'))"
```

---

## 📦 Distribution

### Create Portable Package

```powershell
# Build all components
cargo build --release
cd native\c && nmake clean && nmake all
cd ..\..

# Copy binaries
mkdir dist\nosp
copy target\release\nosp_core.pyd dist\nosp\
copy native\c\pattern_matcher.dll dist\nosp\
copy native\c\packet_capture.dll dist\nosp\
copy python\nosp\*.py dist\nosp\
copy main.py dist\nosp\

# Create ZIP
Compress-Archive -Path dist\nosp -DestinationPath NOSP-OMNI-CORE-v1.0.0.zip
```

---

## 🐛 Troubleshooting

### "Can't find crate for `core`"

**Cause:** Cross-compilation from Linux/macOS to Windows
**Solution:** Build on Windows natively, or use Docker with Windows containers

### "Administrator privileges required"

**Cause:** USB control, DNS sinkhole, registry access need elevation
**Solution:** Run Command Prompt as Administrator

### "Ollama connection refused"

**Cause:** Ollama server not running
**Solution:**
```powershell
ollama serve
# In new terminal:
python main.py
```

### "Sysmon events not appearing"

**Cause:** Sysmon not installed or not running
**Solution:**
```powershell
# Check service status
Get-Service Sysmon64

# Restart if needed
Restart-Service Sysmon64
```

### "Link error: Ws2_32.lib not found"

**Cause:** Windows SDK not installed
**Solution:** Install Visual Studio Build Tools with Windows SDK

---

## 🔧 Advanced Configuration

### Custom Rust Features

```powershell
# Build without Python bindings
cargo build --release --no-default-features

# Build with extra logging
cargo build --release --features verbose-logging
```

### Optimize for Your CPU

```powershell
# Auto-detect CPU and optimize
set RUSTFLAGS=-C target-cpu=native
cargo build --release

# For C modules
gcc -O3 -march=native -mtune=native ...
```

---

## 📞 Support

**Build Issues:**
- 📧 Email: 4fqr5@atomicmail.io
- 💬 Discord: https://dsc.gg/nullsec

**GitHub Issues:**
- 🐛 Bug reports: https://github.com/4fqr/nosp/issues
- 💡 Feature requests: https://github.com/4fqr/nosp/discussions

---

**NOSP OMNI-CORE** - *Built for Windows. Optimized for Security. Zero Compromises.*
