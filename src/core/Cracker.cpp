#include "Cracker.h"
#include "utils/Logger.h"
#include "utils/NetUtils.h"
#include <chrono>
#include <thread>
#include <cstdio>
#include <array>
#include <filesystem>
#include <algorithm>

Cracker::Cracker() {}
Cracker::~Cracker() { stop(); }

void Cracker::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
    std::system("pkill -f hashcat 2>/dev/null");
    std::system("pkill -f aircrack-ng 2>/dev/null");
}

void Cracker::crack(const CrackJob& job) {
    if (m_running) stop();
    m_running = true;
    m_thread = std::thread(&Cracker::crackWorker, this, job);
}

bool Cracker::hasGPU() {
    std::string out = NetUtils::runCommand("hashcat -I 2>/dev/null | grep -i 'cuda\\|opencl\\|gpu'");
    return !out.empty();
}

std::vector<std::string> Cracker::defaultWordlists() {
    std::vector<std::string> lists;
    static const char* paths[] = {
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/seclists/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
        nullptr
    };
    for (int i = 0; paths[i]; i++)
        if (std::filesystem::exists(paths[i]))
            lists.push_back(paths[i]);
    return lists;
}

std::string Cracker::buildHashcatCmd(const CrackJob& job) {
    // Determine hash mode: 22000 = WPA-PBKDF2-PMKID+EAPOL, 2500 = old WPA
    std::string ext = std::filesystem::path(job.handshake_file).extension().string();
    std::string mode = (ext == ".hash" || ext == ".hc22000") ? "22000" : "22000";

    std::string cmd = "hashcat -m " + mode;
    if (job.use_gpu) cmd += " -d 1";
    else             cmd += " --force"; // CPU mode
    if (job.use_rules) cmd += " -r /usr/share/hashcat/rules/best64.rule";

    cmd += " " + job.handshake_file;
    cmd += " " + job.wordlist;
    cmd += " --status --status-timer=5 --potfile-disable 2>&1";
    return cmd;
}

void Cracker::crackWorker(CrackJob job) {
    LOG_INFO("Starting crack: " + job.handshake_file + " with " + job.wordlist);

    // Try hashcat first, fallback to aircrack-ng
    bool useHashcat = !NetUtils::runCommand("which hashcat 2>/dev/null").empty();

    if (useHashcat) {
        std::string cmd = buildHashcatCmd(job);
        std::array<char, 256> buf;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) { m_running = false; return; }

        int progress = 0;
        while (fgets(buf.data(), buf.size(), pipe) && m_running) {
            std::string line(buf.data());
            parseHashcatOutput(line, progress);

            // Check for found password
            if (line.find("Status") != std::string::npos &&
                line.find("Cracked") != std::string::npos) {
                // Extract password
                std::string potOut = NetUtils::runCommand(
                    "hashcat -m 22000 " + job.handshake_file + " " + job.wordlist
                    + " --show 2>/dev/null | cut -d: -f5");
                if (!potOut.empty() && m_foundCb) {
                    potOut.erase(std::remove(potOut.begin(), potOut.end(), '\n'), potOut.end());
                    LOG_INFO("Password found: " + potOut);
                    m_foundCb(potOut);
                }
                break;
            }
        }
        pclose(pipe);
    } else {
        // Fallback: aircrack-ng
        std::string cmd = "aircrack-ng -w " + job.wordlist + " " + job.handshake_file
                        + " -e \"" + job.ssid + "\" 2>&1";
        std::array<char, 256> buf;
        FILE* pipe = popen(cmd.c_str(), "r");
        if (!pipe) { m_running = false; return; }

        int progress = 0;
        while (fgets(buf.data(), buf.size(), pipe) && m_running) {
            std::string line(buf.data());
            auto pos = line.find("KEY FOUND!");
            if (pos != std::string::npos) {
                auto start = line.find('[', pos);
                auto end   = line.find(']', start);
                if (start != std::string::npos && end != std::string::npos) {
                    std::string pwd = line.substr(start+1, end-start-1);
                    LOG_INFO("Password found: " + pwd);
                    if (m_foundCb) m_foundCb(pwd);
                }
                break;
            }
            // Parse percentage
            auto pct = line.find('%');
            if (pct != std::string::npos && pct > 3) {
                try {
                    progress = std::stoi(line.substr(pct-3, 3));
                    if (m_progressCb) m_progressCb(progress, line);
                } catch (...) {}
            }
        }
        pclose(pipe);
    }

    m_running = false;
}

void Cracker::parseHashcatOutput(const std::string& line, int& progress) {
    // Parse: "Progress.........: 12345/1000000 (1.23%)"
    auto pos = line.find("Progress");
    if (pos != std::string::npos) {
        auto pct = line.find('(', pos);
        if (pct != std::string::npos) {
            try {
                progress = (int)std::stod(line.substr(pct+1));
                if (m_progressCb) m_progressCb(progress, line);
            } catch (...) {}
        }
    }
}
