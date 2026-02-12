#!/bin/bash

set -e

echo "=========================================="
echo "NOSP - Linux Setup (Debian/Ubuntu)"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "⚠ This script should be run as root for full functionality"
    echo "  Some features will be limited without root privileges"
    echo ""
fi

echo "[1/6] Checking system requirements..."
if ! command -v python3 &> /dev/null; then
    echo "✗ Python 3 not found"
    echo "  Installing Python 3..."
    apt-get update
    apt-get install -y python3 python3-pip python3-dev
fi

PYTHON_VERSION=$(python3 --version | grep -oP '\d+\.\d+' | head -1)
echo "✓ Python ${PYTHON_VERSION} found"

echo ""
echo "[2/6] Installing system dependencies..."
apt-get update
apt-get install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    curl \
    git \
    gcc \
    auditd \
    libpcap-dev \
    iptables \
    libnfnetlink-dev \
    libnetfilter-queue-dev \
    || echo "⚠ Some packages failed to install"

echo ""
echo "[3/6] Installing Rust (if needed)..."
if ! command -v cargo &> /dev/null; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    echo "✓ Rust installed"
else
    echo "✓ Rust already installed"
fi

echo ""
echo "[4/6] Installing Python dependencies..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo ""
echo "[5/6] Installing Linux-specific packages..."
pip3 install psutil pyudev netfilterqueue scapy --break-system-packages 2>/dev/null || \
    pip3 install psutil pyudev netfilterqueue scapy

echo ""
echo "[6/6] Setting up monitoring capabilities..."
if [ "$EUID" -eq 0 ]; then
    
    if command -v auditctl &> /dev/null; then
        systemctl enable auditd
        systemctl start auditd
        echo "✓ Auditd enabled"
    fi
    
    if [ -f /proc/sys/net/ipv4/ip_forward ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        echo "✓ IP forwarding enabled"
    fi
    
    echo "✓ Kernel capabilities configured"
else
    echo "⚠ Skipping kernel configuration (requires root)"
fi

echo ""
echo "=========================================="
echo "✓ Installation complete!"
echo "=========================================="
echo ""
echo "To start NOSP:"
echo "  python3 main.py"
echo ""
echo "For monitoring features, run with sudo:"
echo "  sudo python3 main.py"
echo ""
echo "Available features on Linux:"
echo "  ✓ Process monitoring (psutil/auditd)"
echo "  ✓ USB device enumeration"
echo "  ✓ Network capture (with root)"
echo "  ✓ File integrity monitoring"
echo "  ✓ AI threat analysis"
echo "  ✓ Web dashboard"
echo ""
echo "Windows-specific features (not available):"
echo "  ✗ ETW event tracing"
echo "  ✗ Registry monitoring"
echo "  ✗ Windows Driver integration"
echo ""
