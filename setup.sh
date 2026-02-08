#!/bin/bash
# NOSP Build and Setup Script for Linux/WSL
# This script automates the complete setup process

echo "==============================================="
echo "   NOSP - Null OS Security Program"
echo "   Build and Setup Script"
echo "==============================================="
echo ""

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 is not installed"
    echo "Please install Python 3.8+ from your package manager"
    exit 1
fi
echo "[OK] Python is installed"

# Check for Rust
if ! command -v rustc &> /dev/null; then
    echo "[WARNING] Rust is not installed"
    echo "NOSP will run in limited mode without real-time monitoring"
    echo "To install Rust, visit: https://rustup.rs"
    echo ""
    RUST_AVAILABLE=0
else
    echo "[OK] Rust is installed"
    RUST_AVAILABLE=1
fi

echo ""
echo "==============================================="
echo "Step 1: Installing Python dependencies"
echo "==============================================="
echo ""

python3 -m pip install --upgrade pip
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install Python dependencies"
    exit 1
fi
echo "[OK] Python dependencies installed"

if [ $RUST_AVAILABLE -eq 1 ]; then
    echo ""
    echo "==============================================="
    echo "Step 2: Building Rust core module"
    echo "==============================================="
    echo ""
    
    # Install maturin if not present
    pip3 install maturin
    
    # Build the Rust extension
    maturin develop --release
    
    if [ $? -ne 0 ]; then
        echo "[WARNING] Rust module build failed"
        echo "NOSP will run in limited mode"
    else
        echo "[OK] Rust core module built successfully"
    fi
else
    echo ""
    echo "[SKIPPED] Rust module build (Rust not available)"
fi

echo ""
echo "==============================================="
echo "Step 3: Checking Ollama installation"
echo "==============================================="
echo ""

if ! command -v ollama &> /dev/null; then
    echo "[WARNING] Ollama is not installed"
    echo "AI features will not be available"
    echo "To install Ollama, visit: https://ollama.ai"
    echo ""
else
    echo "[OK] Ollama is installed"
    
    echo "Checking for llama3 model..."
    if ! ollama list | grep -q "llama3"; then
        echo "[INFO] llama3 model not found"
        echo "The application will automatically download it on first run"
        echo "This may take several minutes depending on your connection"
    else
        echo "[OK] llama3 model is available"
    fi
fi

echo ""
echo "==============================================="
echo "Setup Complete!"
echo "==============================================="
echo ""
echo "To run NOSP, execute:"
echo "    ./run_nosp.sh"
echo ""
echo "Or manually with:"
echo "    streamlit run main.py"
echo ""
