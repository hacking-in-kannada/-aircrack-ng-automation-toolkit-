#include "Scanner.h"
#include "utils/Logger.h"
#include "utils/NetUtils.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <filesystem>

Scanner::Scanner(const std::string& iface)
    : m_iface(iface), m_tmpPrefix("/tmp/wifisec_scan_" + iface) {}

Scanner::~Scanner() { stop(); }

void Scanner::start() {
    if (m_running) return;
    m_running = true;
    LOG_INFO("Scanner starting on " + m_iface);
    m_scanThread = std::thread(&Scanner::scanLoop, this);
    m_hopThread  = std::thread(&Scanner::channelHopLoop, this);
}

void Scanner::stop() {
    m_running = false;
    if (m_scanThread.joinable()) m_scanThread.join();
    if (m_hopThread.joinable())  m_hopThread.join();
    std::system(("pkill -f 'airodump-ng.*" + m_iface + "' 2>/dev/null").c_str());
    LOG_INFO("Scanner stopped");
}

void Scanner::scanLoop() {
    std::string cmd = "airodump-ng " + m_iface
                    + " --output-format csv --write " + m_tmpPrefix
                    + " --band abg 2>/dev/null &";
    std::system(cmd.c_str());

    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        parseAirodump();
    }
}

void Scanner::channelHopLoop() {
    static const int channels[] = {1,6,11,2,7,3,8,4,9,5,10,
                                   36,40,44,48,52,56,60,64,149,153,157,161};
    size_t idx = 0;
    while (m_running) {
        m_currentChannel = channels[idx % (sizeof(channels)/sizeof(channels[0]))];
        NetUtils::setChannel(m_iface, m_currentChannel);
        idx++;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void Scanner::parseAirodump() {
    std::string csvFile = m_tmpPrefix + "-01.csv";
    std::ifstream f(csvFile);
    if (!f.is_open()) return;

    std::string line;
    bool clientSection = false;

    while (std::getline(f, line)) {
        if (line.find("Station MAC") != std::string::npos) {
            clientSection = true;
            continue;
        }
        if (line.empty() || line[0] == ' ') continue;
        parseCsvLine(line, clientSection);
    }
}

void Scanner::parseCsvLine(const std::string& line, bool isClient) {
    std::vector<std::string> fields;
    std::istringstream ss(line);
    std::string field;
    while (std::getline(ss, field, ',')) {
        while (!field.empty() && field[0] == ' ') field.erase(0,1);
        while (!field.empty() && field.back() == ' ') field.pop_back();
        fields.push_back(field);
    }

    if (!isClient && fields.size() >= 14) {
        NetworkInfo net;
        net.bssid    = fields[0];
        net.channel  = fields[3].empty() ? 0 : std::atoi(fields[3].c_str());
        try { net.signal_dbm = std::stoi(fields[8]); } catch (...) { net.signal_dbm = -100; }
        net.security = parseSecurityStr(fields[5] + " " + fields[6]);
        net.wps_enabled = false;
        if (fields.size() > 13) net.ssid = fields[13];
        net.last_seen = fields[2];

        std::lock_guard<std::mutex> lock(m_mutex);
        bool isNew = m_networks.find(net.bssid) == m_networks.end();
        m_networks[net.bssid] = net;
        if (isNew && m_netCb) m_netCb(net);

    } else if (isClient && fields.size() >= 6) {
        ClientInfo cl;
        cl.mac      = fields[0];
        cl.bssid    = fields[5];
        try { cl.signal_dbm = std::stoi(fields[3]); } catch (...) { cl.signal_dbm = -100; }
        cl.last_seen = fields[2];
        if (cl.mac.empty() || cl.mac.size() < 17) return;

        std::lock_guard<std::mutex> lock(m_mutex);
        bool isNew = m_clients.find(cl.mac) == m_clients.end();
        m_clients[cl.mac] = cl;
        if (isNew && m_clientCb) m_clientCb(cl);
    }
}

Security Scanner::parseSecurityStr(const std::string& s) {
    bool wpa3 = s.find("WPA3") != std::string::npos || s.find("SAE") != std::string::npos;
    bool wpa2 = s.find("WPA2") != std::string::npos;
    bool wpa  = s.find("WPA")  != std::string::npos && !wpa2 && !wpa3;
    bool wep  = s.find("WEP")  != std::string::npos;
    if (wpa3 && wpa2) return Security::WPA2_WPA3;
    if (wpa3)         return Security::WPA3;
    if (wpa2)         return Security::WPA2;
    if (wpa)          return Security::WPA;
    if (wep)          return Security::WEP;
    return Security::OPEN;
}

std::vector<NetworkInfo> Scanner::networks() {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<NetworkInfo> result;
    for (auto& [k, v] : m_networks) result.push_back(v);
    std::sort(result.begin(), result.end(),
              [](const NetworkInfo& a, const NetworkInfo& b){
                  return a.signal_dbm > b.signal_dbm;
              });
    return result;
}

std::vector<ClientInfo> Scanner::clients(const std::string& bssid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<ClientInfo> result;
    for (auto& [k, v] : m_clients) {
        if (bssid.empty() || v.bssid == bssid)
            result.push_back(v);
    }
    return result;
}
