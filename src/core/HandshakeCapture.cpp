#include "HandshakeCapture.h"
#include "utils/NetUtils.h"

bool HandshakeCapture::verify(const std::string& capFile, const std::string& ssid) {
    std::string cmd = "aircrack-ng " + capFile + " 2>/dev/null";
    if (!ssid.empty()) cmd += " -e \"" + ssid + "\"";
    std::string out = NetUtils::runCommand(cmd + " | grep -c 'handshake'");
    try { return std::stoi(out) > 0; } catch (...) { return false; }
}

bool HandshakeCapture::convert22000(const std::string& capFile, const std::string& outFile) {
    std::string cmd = "hcxpcapngtool -o " + outFile + " " + capFile + " 2>/dev/null";
    return std::system(cmd.c_str()) == 0;
}

std::string HandshakeCapture::info(const std::string& capFile) {
    return NetUtils::runCommand("aircrack-ng " + capFile + " 2>/dev/null | head -30");
}
