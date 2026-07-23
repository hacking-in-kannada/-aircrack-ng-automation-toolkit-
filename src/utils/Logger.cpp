#include "Logger.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() {
    m_file.open("/tmp/wifisec.log", std::ios::app);
}

void Logger::setCallback(std::function<void(LogLevel, const std::string&)> cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_callback = cb;
}

void Logger::log(LogLevel level, const std::string& msg) {
    auto now  = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << "[" << std::put_time(std::localtime(&time), "%H:%M:%S") << "] "
        << "[" << levelStr(level) << "] " << msg;

    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_file.is_open()) m_file << oss.str() << "\n", m_file.flush();
    if (m_callback)       m_callback(level, oss.str());
}

std::string Logger::levelStr(LogLevel l) {
    switch (l) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO ";
        case LogLevel::WARN:     return "WARN ";
        case LogLevel::ERROR_LVL:return "ERROR";
        case LogLevel::CRITICAL: return "CRIT ";
        default:                 return "?????";
    }
}
