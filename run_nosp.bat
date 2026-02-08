@echo off
REM NOSP Launcher Script
REM Runs the NOSP Streamlit application

echo ===============================================
echo    Starting NOSP - Null OS Security Program
echo ===============================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Not running as Administrator
    echo Some features may be limited
    echo Right-click and select "Run as Administrator" for full functionality
    echo.
    timeout /t 3
)

REM Launch Streamlit
streamlit run main.py --server.port 8501 --server.address localhost

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start NOSP
    echo Make sure you have run setup.bat first
    pause
)
