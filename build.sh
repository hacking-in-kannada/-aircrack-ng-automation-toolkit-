#!/bin/bash
set -e

echo "[*] Checking dependencies..."
MISSING=()
for pkg in qt6-base-dev qt6-charts-dev libpcap-dev libnl-3-dev libnl-genl-3-dev pkgconf cmake; do
    dpkg -l "$pkg" &>/dev/null || MISSING+=("$pkg")
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "[!] Missing packages: ${MISSING[*]}"
    echo "[*] Installing..."
    apt-get install -y "${MISSING[@]}"
fi

echo "[*] Configuring..."
cmake -B /tmp/wifisec_build -S . -DCMAKE_BUILD_TYPE=Release

echo "[*] Compiling with $(nproc) cores..."
cmake --build /tmp/wifisec_build -j$(nproc)

cp /tmp/wifisec_build/wifisec ./wifisec
echo ""
echo "[+] Build complete: ./wifisec"
echo "[*] Run with: sudo ./wifisec"
