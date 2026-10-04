#!/usr/bin/env bash
# ==============================================================================
# MTA:SA Server Shield - Linux x64 Build Script
# ==============================================================================
set -e

echo "======================================================="
echo "  MTA Server Shield - Build Script (Linux x64)"
echo "======================================================="

# Check compiler
if command -v g++ >/dev/null 2>&1; then
    COMPILER="g++"
elif command -v clang++ >/dev/null 2>&1; then
    COMPILER="clang++"
else
    echo "[ERROR] g++ or clang++ compiler not found!"
    echo "Install via: sudo apt update && sudo apt install -y build-essential"
    exit 1
fi

mkdir -p bin/x64

echo "[*] Compiling with ${COMPILER}..."
${COMPILER} -std=c++17 -O2 -fPIC -shared -pthread \
    src/mta_server_shield.cpp \
    -o bin/x64/mta_server_shield.so \
    -ldl -lpthread

if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded bin/x64/mta_server_shield.so
fi

echo "======================================================="
echo "  [SUCCESS] Built successfully:"
echo "  bin/x64/mta_server_shield.so"
echo "======================================================="
echo ""
echo "Installation:"
echo "1. Copy bin/x64/mta_server_shield.so to your server's x64/modules/ folder."
echo "2. Add to mtaserver.conf:"
echo "   <module src=\"mta_server_shield.so\" />"
echo "======================================================="
