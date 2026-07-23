#include "MacSpoofer.h"
#include "Logger.h"
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>

std::string MacSpoofer::m_original = "";

std::string MacSpoofer::random() {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);
    std::ostringstream oss;
    // Locally administered, unicast
    oss << std::hex << std::setfill('0')
        << std::setw(2) << ((dist(rng) & 0xFE) | 0x02) << ":"
        << std::setw(2) << dist(rng) << ":"
        << std::setw(2) << dist(rng) << ":"
        << std::setw(2) << dist(rng) << ":"
        << std::setw(2) << dist(rng) << ":"
        << std::setw(2) << dist(rng);
    return oss.str();
}

std::string MacSpoofer::current(const std::string& iface) {
    std::string path = "/sys/class/net/" + iface + "/address";
    std::ifstream f(path);
    std::string mac;
    std::getline(f, mac);
    return mac;
}

bool MacSpoofer::spoof(const std::string& iface, const std::string& mac) {
    m_original = current(iface);
    std::string target = mac.empty() ? random() : mac;
    std::string cmd = "ip link set " + iface + " down && "
                    + "ip link set " + iface + " address " + target + " && "
                    + "ip link set " + iface + " up";
    LOG_INFO("Spoofing MAC on " + iface + " -> " + target);
    return std::system(cmd.c_str()) == 0;
}

bool MacSpoofer::restore(const std::string& iface) {
    if (m_original.empty()) return false;
    std::string cmd = "ip link set " + iface + " down && "
                    + "ip link set " + iface + " address " + m_original + " && "
                    + "ip link set " + iface + " up";
    LOG_INFO("Restoring MAC on " + iface + " -> " + m_original);
    return std::system(cmd.c_str()) == 0;
}

bool MacSpoofer::isValid(const std::string& mac) {
    if (mac.size() != 17) return false;
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) { if (mac[i] != ':') return false; }
        else if (!std::isxdigit(mac[i])) return false;
    }
    return true;
}
