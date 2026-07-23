#pragma once
#include "common/Types.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>

class Cracker {
public:
    using ProgressCallback = std::function<void(int percent, const std::string& status)>;
    using FoundCallback    = std::function<void(const std::string& password)>;

    Cracker();
    ~Cracker();

    void crack(const CrackJob& job);
    void stop();
    bool isRunning() const { return m_running; }

    void onProgress(ProgressCallback cb) { m_progressCb = cb; }
    void onFound(FoundCallback cb)       { m_foundCb = cb; }

    static bool hasGPU();
    static std::vector<std::string> defaultWordlists();

private:
    void crackWorker(CrackJob job);
    std::string buildHashcatCmd(const CrackJob& job);
    void parseHashcatOutput(const std::string& line, int& progress);

    std::atomic<bool>  m_running{false};
    std::thread        m_thread;
    ProgressCallback   m_progressCb;
    FoundCallback      m_foundCb;
};
