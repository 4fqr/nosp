#!/bin/bash

echo "==============================================="
echo "   Starting NOSP - Null OS Security Program"
echo "==============================================="
echo ""

if [ "$EUID" -ne 0 ] && [ -f "/proc/sys/kernel/osrelease" ] && grep -q Microsoft /proc/sys/kernel/osrelease; then
    echo "[WARNING] Not running as administrator"
    echo "Some features may be limited in WSL"
    echo ""
fi

streamlit run main.py --server.port 8501 --server.address localhost

if [ $? -ne 0 ]; then
    echo ""
    echo "[ERROR] Failed to start NOSP"
    echo "Make sure you have run setup.sh first"
    exit 1
fi
