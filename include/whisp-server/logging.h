#pragma once

#include <iostream>

extern int debug;

enum LogLevel {
    Info,
    Error,
    Debug,
};

struct LoggerProxy {
    LoggerProxy(LogLevel ll) : ll(ll) {
        switch (ll) {
        case Debug:
            if (debug) {
                std::cout << "[DEBUG] ";
            }
            break;
        case Info:
            std::cout << "[INFO] ";
            break;
        case Error:
            std::cerr << "[ERROR] ";
            break;
        }
    }

    template <typename T> LoggerProxy &operator<<(T &&t) {
        switch (ll) {
        case Debug:
            if (debug) {
                std::cout << t;
            }
            break;
        case Info:
            std::cout << t;
            break;
        case Error:
            std::cerr << t;
        }
        return *this;
    }

    LogLevel ll;
};

#define LOG_DEBUG                                                              \
    LoggerProxy { Debug }
#define LOG_INFO                                                               \
    LoggerProxy { Info }
#define LOG_ERROR                                                              \
    LoggerProxy { Info }
