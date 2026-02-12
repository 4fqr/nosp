@echo off

echo ===============================================
echo    NOSP - Null OS Security Program
echo    Build and Setup Script
echo ===============================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)
echo [OK] Python is installed

rustc --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Rust is not installed
    echo NOSP will run in limited mode without real-time monitoring
    echo To install Rust, visit: https://rustup.rs
    echo.
    set RUST_AVAILABLE=0
) else (
    echo [OK] Rust is installed
    set RUST_AVAILABLE=1
)

echo.
echo ===============================================
echo Step 1: Installing Python dependencies
echo ===============================================
echo.

python -m pip install --upgrade pip
pip install -r requirements.txt

if errorlevel 1 (
    echo [ERROR] Failed to install Python dependencies
    pause
    exit /b 1
)
echo [OK] Python dependencies installed

if %RUST_AVAILABLE%==1 (
    echo.
    echo ===============================================
    echo Step 2: Building Rust core module
    echo ===============================================
    echo.
    
    pip install maturin
    
    maturin develop --release
    
    if errorlevel 1 (
        echo [WARNING] Rust module build failed
        echo NOSP will run in limited mode
    ) else (
        echo [OK] Rust core module built successfully
    )
) else (
    echo.
    echo [SKIPPED] Rust module build (Rust not available)
)

echo.
echo ===============================================
echo Step 3: Checking Ollama installation
echo ===============================================
echo.

ollama --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Ollama is not installed
    echo AI features will not be available
    echo To install Ollama, visit: https://ollama.ai
    echo.
) else (
    echo [OK] Ollama is installed
    
    echo Checking for llama3 model...
    ollama list | findstr "llama3" >nul 2>&1
    if errorlevel 1 (
        echo [INFO] llama3 model not found
        echo The application will automatically download it on first run
        echo This may take several minutes depending on your connection
    ) else (
        echo [OK] llama3 model is available
    )
)

echo.
echo ===============================================
echo Setup Complete!
echo ===============================================
echo.
echo To run NOSP, execute:
echo     run_nosp.bat
echo.
echo Or manually with:
echo     streamlit run main.py
echo.
pause
