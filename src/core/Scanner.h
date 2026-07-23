#pragma once
#include "common/Types.h"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include <map>

class Scanner {
public:
    using NetworkCallback = std::function<void(const NetworkInfo&)>;
    using ClientCallback  = std::function<void(const ClientInfo&)>;

    explicit Scanner(const std::string& iface);
    ~Scanner();

    void start();
    void stop();
    bool isRunning() const { return m_running; }

    void onNetworkFound(NetworkCallback cb) { m_netCb = cb; }
    void onClientFound(ClientCallback cb)   { m_clientCb = cb; }

    std::vector<NetworkInfo> networks();
    std::vector<ClientInfo>  clients(const std::string& bssid = "");

private:
    void scanLoop();
    void channelHopLoop();
    void parseAirodump();
    void parseCsvLine(const std::string& line, bool isClient);
    Security parseSecurityStr(const std::string& s);

    std::string              m_iface;
    std::atomic<bool>        m_running{false};
    std::thread              m_scanThread;
    std::thread              m_hopThread;
    mutable std::mutex       m_mutex;
    std::map<std::string, NetworkInfo> m_networks;
    std::map<std::string, ClientInfo>  m_clients;
    NetworkCallback          m_netCb;
    ClientCallback           m_clientCb;
    std::string              m_tmpPrefix;
    int                      m_currentChannel{1};
};
