# WifiSec / Aircrack-ng Automation Toolkit

WifiSec is a Linux wireless-security testing toolkit with a Qt6 desktop
interface and a Python aircrack-ng automation script. Use it only on networks,
devices, and captures that you own or are explicitly authorized to test.

## Requirements

- Kali Linux or another Debian-based Linux distribution
- Root privileges for wireless interface and packet-capture operations
- A compatible Wi-Fi adapter and driver that support monitor mode
- Internet access for installing packages

### Build dependencies

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake pkgconf \
  qt6-base-dev qt6-charts-dev \
  libpcap-dev libnl-3-dev libnl-genl-3-dev \
  libssl-dev
```

### Wireless/runtime tools

```bash
sudo apt install -y aircrack-ng iw hostapd dnsmasq iptables
```

Optional tools used by some workflows:

```bash
sudo apt install -y hashcat reaver bully wordlists seclists
```

The Python script has no third-party Python package requirements. It uses the
Python 3 standard library.

For the bundled default wordlist, install `wordlists` and, if needed, unpack
the list:

```bash
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
```

## Build the Qt application

From the repository directory:

```bash
cd ~/wifisec
sudo ./build.sh
```

The script builds a release binary and writes it to `./wifisec`.

Run the desktop application:

```bash
sudo ./wifisec
```

If the graphical display is not available to root, use the appropriate display
session configuration for your desktop environment; do not disable system
security controls globally.

## Python tool

Show all commands and options:

```bash
python3 autocrack.py --help
```

Start the guided interface for an authorized lab:

```bash
sudo python3 autocrack.py interactive --iface wlan0
```

List nearby access points in an authorized test environment:

```bash
sudo python3 autocrack.py scan --iface wlan0 --time 15
```

Test an existing capture file with a wordlist you are authorized to use:

```bash
sudo python3 autocrack.py crack capture.cap \
  --wordlist /usr/share/wordlists/rockyou.txt
```

Outputs from the Python tool are written to `autocrack_output/` by default.

## Troubleshooting

Check that the adapter exists:

```bash
ip link
iw dev
```

Check required commands:

```bash
command -v airmon-ng airodump-ng aircrack-ng iw hostapd dnsmasq
```

If `./build.sh` reports missing packages, install the listed packages and run
it again. Do not use a managed or public network for testing, and restore your
NetworkManager state after any monitor-mode test.
