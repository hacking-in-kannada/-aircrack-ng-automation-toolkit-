#pragma once
#include "common/Types.h"
#include "PacketEngine.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>

class Attacker {
public:
    using ResultCallback = std::function<void(const AttackResult&)>;

    explicit Attacker(const std::string& iface);
    ~Attacker();

    void setResultCallback(ResultCallback cb) { m_cb = cb; }

    void attackHandshake(const NetworkInfo& net, const StealthConfig& stealth);
    void attackPMKID(const NetworkInfo& net);
    void attackWPS(const NetworkInfo& net);
    void stopAttack();
    bool isRunning() const { return m_running; }

private:
    void handshakeWorker(NetworkInfo net, StealthConfig stealth);
    void pmkidWorker(NetworkInfo net);
    void wpsWorker(NetworkInfo net);
    bool waitForHandshake(const std::string& capFile, int timeoutSec);
    bool waitForPMKID(const std::string& capFile, int timeoutSec);

    std::string     m_iface;
    std::atomic<bool> m_running{false};
    std::thread     m_thread;
    ResultCallback  m_cb;
    PacketEngine    m_pkt;
};
