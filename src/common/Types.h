#pragma once
#include <string>
#include <vector>
#include <cstdint>

enum class Security { OPEN, WEP, WPA, WPA2, WPA3, WPA2_WPA3 };
enum class AttackType { DEAUTH, PMKID, HANDSHAKE, EVIL_TWIN, WPS_PIXIE, WPS_BRUTEFORCE };
enum class AttackStatus { IDLE, RUNNING, SUCCESS, FAILED };

struct NetworkInfo {
    std::string bssid;
    std::string ssid;
    int         channel;
    int         signal_dbm;
    Security    security;
    bool        wps_enabled;
    int         clients;
    std::string vendor;
    std::string last_seen;
};

struct ClientInfo {
    std::string mac;
    std::string bssid;
    int         signal_dbm;
    std::string last_seen;
};

struct AttackResult {
    AttackType   type;
    AttackStatus status;
    std::string  target_bssid;
    std::string  password;
    std::string  handshake_file;
    std::string  pmkid;
    std::string  message;
};

struct CrackJob {
    std::string handshake_file;
    std::string ssid;
    std::string wordlist;
    bool        use_rules;
    bool        use_gpu;
    int         progress;
    std::string status;
    std::string password;
};

struct EvilTwinConfig {
    std::string target_ssid;
    std::string target_bssid;
    int         channel;
    std::string interface;
    bool        capture_creds;
    bool        dns_spoof;
    std::string portal_template;
};

struct StealthConfig {
    bool  spoof_mac;
    bool  rate_limit_deauth;
    int   deauth_delay_ms;
    bool  random_intervals;
    bool  hop_channels;
};
