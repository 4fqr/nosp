# NOSP Quick Start Guide

⚡ **Get up and running with NOSP in 5 minutes!**

---

## Prerequisites

Before starting, ensure you have:

- [ ] Windows 10 or 11
- [ ] Administrator privileges
- [ ] Internet connection (for initial setup)
- [ ] 2 GB free disk space

---

## Step 1: Install Required Software (5-10 minutes)

### 1.1 Install Python

```powershell
# Option A: Download from python.org
# Visit: https://www.python.org/downloads/
# Download Python 3.8 or higher
# ✅ Check "Add Python to PATH" during installation

# Option B: Use winget
winget install Python.Python.3.11
```

### 1.2 Install Rust

```powershell
# Option A: Download from rustup.rs
# Visit: https://rustup.rs/
# Download and run rustup-init.exe

# Option B: Use winget
winget install Rustlang.Rust.MSVC
```

### 1.3 Install Ollama

```powershell
# Option A: Download from ollama.ai
# Visit: https://ollama.ai
# Download and install Ollama for Windows

# Option B: Use winget
winget install Ollama.Ollama
```

### 1.4 Install Sysmon (if not already installed)

```powershell
# Download Sysmon
# Visit: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

# Install with default config
.\Sysmon64.exe -accepteula -i
```

---

## Step 2: Download NOSP

Extract the NOSP folder to a location like:
```
C:\NOSP
```

---

## Step 3: Run Setup (2-3 minutes)

Open PowerShell **as Administrator** in the NOSP folder:

```powershell
cd C:\NOSP

# Run the setup script
.\setup.bat
```

The setup script will:
1. ✅ Check Python installation
2. ✅ Check Rust installation
3. ✅ Install Python dependencies
4. ✅ Build the Rust core module
5. ✅ Check Ollama and AI model

**Wait for "Setup Complete!" message**

---

## Step 4: Launch NOSP (<1 minute)

```powershell
.\run_nosp.bat
```

**NOSP will open in your browser at:** `http://localhost:8501`

---

## Step 5: Verify Everything Works

### Check the Sidebar
You should see:
- 🟢 **Rust Engine: ACTIVE**
- 🟢 **AI Engine: ACTIVE** (may take a minute on first run)
- 🟢 **Database: CONNECTED**

### Start Monitoring
1. Click **"▶️ Start Monitoring"** in the sidebar
2. Watch events appear in the dashboard
3. High-risk events will be automatically analyzed

---

## Common Issues & Quick Fixes

### Issue: "Rust core module not available"

**Fix:**
```powershell
# Make sure Rust is installed
rustc --version

# Rebuild the module
pip install maturin
maturin develop --release
```

### Issue: "AI Engine: OFFLINE"

**Fix:**
```powershell
# Check Ollama is running
ollama list

# Pull the model
ollama pull llama3
```

### Issue: "No events captured"

**Fix:**
1. Verify Sysmon is running:
   ```powershell
   Get-Service Sysmon64
   ```
2. Ensure running as Administrator
3. Check Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational

### Issue: Python/Rust not found

**Fix:**
- Close and reopen PowerShell after installing Rust/Python
- Restart your computer
- Check PATH environment variables

---

## What to Do Next

### 1. Monitor Security Events
- Watch the dashboard for new process creations
- Pay attention to high-risk events (orange/red)

### 2. Review AI Analysis
- Go to the **"Analysis"** tab
- Review AI assessments of suspicious processes
- Take recommended actions

### 3. Configure Settings
- Go to the **"Settings"** tab
- Adjust thresholds and preferences
- View system information

### 4. Learn More
- Read the full [README.md](README.md)
- Check [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md) for advanced usage
- Explore the codebase

---

## Performance Tips

### For Better Performance:
1. **Use an SSD**: Database operations are disk-intensive
2. **Allocate RAM**: 8GB+ recommended for AI analysis
3. **Adjust Thresholds**: Only analyze events above 70 risk score
4. **Clean Database**: Archive old events periodically

### For Lower Resource Usage:
1. **Reduce Event Count**: Lower the "Events to Display" slider
2. **Increase AI Threshold**: Only analyze critical events (75+)
3. **Disable Auto-Refresh**: Turn off if not actively monitoring
4. **Use Smaller Model**: Switch to `mistral:7b` instead of `llama3`

---

## Need Help?

1. Check the **Troubleshooting** section in [README.md](README.md)
2. Review logs in the terminal window
3. Check the **System Information** in Settings tab
4. Refer to [TECHNICAL_DOCS.md](TECHNICAL_DOCS.md) for detailed explanations

---

## Stopping NOSP

To stop NOSP:
1. Close the browser tab
2. Press `Ctrl+C` in the PowerShell window
3. Or click the X on the PowerShell window

---

## Uninstalling

To remove NOSP:
1. Delete the NOSP folder
2. (Optional) Uninstall Ollama if not needed
3. (Optional) Uninstall Rust if not needed
4. Keep Python and Sysmon (likely used by other programs)

---

**🎉 Congratulations! You're now running NOSP!**

🛡️ Stay safe. Stay monitored. Stay NOSP.

---

**Last Updated**: February 8, 2026
**Version**: 0.1.0
