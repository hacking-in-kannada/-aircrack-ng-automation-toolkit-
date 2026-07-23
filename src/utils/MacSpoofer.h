#pragma once
#include <string>

class MacSpoofer {
public:
    static bool   spoof(const std::string& iface, const std::string& mac = "");
    static bool   restore(const std::string& iface);
    static std::string random();
    static std::string current(const std::string& iface);
    static bool   isValid(const std::string& mac);
private:
    static std::string m_original;
};
