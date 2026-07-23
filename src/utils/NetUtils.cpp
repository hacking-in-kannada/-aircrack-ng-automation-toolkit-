#include "NetUtils.h"
#include "Logger.h"
#include <cstdlib>
#include <array>
#include <memory>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unistd.h>

std::string NetUtils::runCommand(const std::string& cmd) {
    std::array<char, 256> buf;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buf.data(), buf.size(), pipe.get()) != nullptr)
        result += buf.data();
    return result;
}

std::vector<std::string> NetUtils::wirelessInterfaces() {
    std::vector<std::string> ifaces;
    for (const auto& entry : std::filesystem::directory_iterator("/sys/class/net")) {
        std::string name = entry.path().filename().string();
        if (std::filesystem::exists(entry.path() / "wireless") ||
            std::filesystem::exists(entry.path() / "phy80211")) {
            ifaces.push_back(name);
        }
    }
    return ifaces;
}

bool NetUtils::setMonitorMode(const std::string& iface) {
    LOG_INFO("Setting " + iface + " to monitor mode");
    std::string cmd = "ip link set " + iface + " down 2>/dev/null && "
                    + "iw dev " + iface + " set monitor none 2>/dev/null && "
                    + "ip link set " + iface + " up 2>/dev/null";
    if (std::system(cmd.c_str()) != 0) {
        // fallback to airmon-ng
        cmd = "airmon-ng start " + iface + " 2>/dev/null";
        std::system(cmd.c_str());
    }
    return isMonitorMode(iface);
}

bool NetUtils::setManagedMode(const std::string& iface) {
    LOG_INFO("Setting " + iface + " to managed mode");
    std::string cmd = "ip link set " + iface + " down && "
                    + "iw dev " + iface + " set type managed && "
                    + "ip link set " + iface + " up";
    return std::system(cmd.c_str()) == 0;
}

bool NetUtils::setChannel(const std::string& iface, int ch) {
    std::string cmd = "iw dev " + iface + " set channel " + std::to_string(ch) + " 2>/dev/null";
    return std::system(cmd.c_str()) == 0;
}

int NetUtils::currentChannel(const std::string& iface) {
    std::string out = runCommand("iw dev " + iface + " info 2>/dev/null | grep channel | awk '{print $2}'");
    try { return std::stoi(out); } catch (...) { return 0; }
}

bool NetUtils::isMonitorMode(const std::string& iface) {
    std::string out = runCommand("iw dev " + iface + " info 2>/dev/null | grep type");
    return out.find("monitor") != std::string::npos;
}

bool NetUtils::requiresRoot() {
    return geteuid() != 0;
}
