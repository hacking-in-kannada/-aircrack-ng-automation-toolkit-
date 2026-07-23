#pragma once
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <pcap.h>

class PacketEngine {
public:
    using PacketCallback = std::function<void(const uint8_t*, int)>;

    explicit PacketEngine(const std::string& iface);
    ~PacketEngine();

    bool open();
    void close();

    bool sendDeauth(const std::string& bssid, const std::string& client,
                    int count = 5, int delayMs = 100);
    bool sendPacket(const std::vector<uint8_t>& pkt);
    void capture(PacketCallback cb, int timeoutMs = 1000);
    bool injectRaw(const uint8_t* data, int len);

private:
    std::vector<uint8_t> buildDeauthFrame(const std::string& dst,
                                          const std::string& src,
                                          const std::string& bssid,
                                          uint16_t reason = 7);
    bool parseMac(const std::string& mac, uint8_t out[6]);

    std::string  m_iface;
    pcap_t*      m_handle{nullptr};
    char         m_errbuf[PCAP_ERRBUF_SIZE];
};
