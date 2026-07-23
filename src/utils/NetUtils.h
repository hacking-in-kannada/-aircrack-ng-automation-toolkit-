#pragma once
#include <string>
#include <vector>

class NetUtils {
public:
    static std::vector<std::string> wirelessInterfaces();
    static bool   setMonitorMode(const std::string& iface);
    static bool   setManagedMode(const std::string& iface);
    static bool   setChannel(const std::string& iface, int channel);
    static int    currentChannel(const std::string& iface);
    static bool   isMonitorMode(const std::string& iface);
    static std::string runCommand(const std::string& cmd);
    static bool   requiresRoot();
};
