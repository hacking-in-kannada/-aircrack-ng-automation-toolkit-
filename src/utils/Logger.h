#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <functional>

enum class LogLevel { DEBUG, INFO, WARN, ERROR_LVL, CRITICAL };

class Logger {
public:
    static Logger& instance();
    void setCallback(std::function<void(LogLevel, const std::string&)> cb);
    void log(LogLevel level, const std::string& msg);
    void debug(const std::string& msg)    { log(LogLevel::DEBUG,    msg); }
    void info(const std::string& msg)     { log(LogLevel::INFO,     msg); }
    void warn(const std::string& msg)     { log(LogLevel::WARN,     msg); }
    void error(const std::string& msg)    { log(LogLevel::ERROR_LVL,msg); }
    void critical(const std::string& msg) { log(LogLevel::CRITICAL, msg); }

private:
    Logger();
    std::ofstream m_file;
    std::mutex    m_mutex;
    std::function<void(LogLevel, const std::string&)> m_callback;
    std::string levelStr(LogLevel l);
};

#define LOG_DEBUG(msg)    Logger::instance().debug(msg)
#define LOG_INFO(msg)     Logger::instance().info(msg)
#define LOG_WARN(msg)     Logger::instance().warn(msg)
#define LOG_ERROR(msg)    Logger::instance().error(msg)
#define LOG_CRITICAL(msg) Logger::instance().critical(msg)
