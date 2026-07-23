#pragma once
#include "common/Types.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>

class EvilTwin {
public:
    using LogCallback  = std::function<void(const std::string&)>;
    using CredCallback = std::function<void(const std::string& user, const std::string& pass)>;

    EvilTwin();
    ~EvilTwin();

    bool start(const EvilTwinConfig& cfg);
    void stop();
    bool isRunning() const { return m_running; }

    void onLog(LogCallback cb)   { m_logCb = cb; }
    void onCred(CredCallback cb) { m_credCb = cb; }

    std::vector<std::string> capturedCredentials() const { return m_creds; }

private:
    void setupAP(const EvilTwinConfig& cfg);
    void setupDHCP(const std::string& iface);
    void setupDNS();
    void startWebPortal(const EvilTwinConfig& cfg);
    void deauthLoop(const EvilTwinConfig& cfg);
    void monitorCredentials();
    void cleanup();
    void writeHostapdConf(const EvilTwinConfig& cfg, const std::string& apIface);
    void writeDnsmasqConf(const std::string& apIface);

    std::atomic<bool>       m_running{false};
    std::thread             m_apThread;
    std::thread             m_deauthThread;
    std::thread             m_credThread;
    LogCallback             m_logCb;
    CredCallback            m_credCb;
    std::vector<std::string> m_creds;
    std::string             m_apIface{"wlan0_ap"};
};
