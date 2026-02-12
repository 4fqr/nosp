#!/bin/bash

echo "Starting NOSP on Linux..."
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "⚠ Running without root privileges"
    echo "  Some monitoring features will be limited"
    echo "  For full functionality, run: sudo ./run_nosp_linux.sh"
    echo ""
fi

export PYTHONPATH="${PYTHONPATH}:$(pwd)/python"

if command -v python3 &> /dev/null; then
    exec python3 main.py "$@"
else
    echo "✗ Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi
