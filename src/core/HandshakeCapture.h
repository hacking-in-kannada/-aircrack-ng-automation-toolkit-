#pragma once
#include <string>

class HandshakeCapture {
public:
    static bool verify(const std::string& capFile, const std::string& ssid = "");
    static bool convert22000(const std::string& capFile, const std::string& outFile);
    static std::string info(const std::string& capFile);
};
