#pragma once

#include <iostream>
#include <iomanip>
#include <fstream>
#include <ctime>
#include <cstring>
#include <cstdlib>

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <unistd.h>
#include <linux/limits.h>
#endif // _WIN32 || _WIN64

#include <stdarg.h>

extern const char * __ALPHA;

std::string random_string(size_t s = 8);

#if defined(_WIN32) || defined(_WIN64)
#define LOCAL_TIME(a, b) localtime_s(&a, &b);
#define _LOGGER_STR(a) L##a
#define GETPID() ::GetCurrentProcessId()
#define _PATH_MAX FILENAME_MAX
#else
#define LOCAL_TIME(a, b) localtime_r(&b, &a);
#define _LOGGER_STR(a) a
#define GETPID() ::getpid()
#define _PATH_MAX PATH_MAX
#endif // _WIN32 || _WIN64

namespace Logger {

enum LoggerLevel: uint8_t //{
{
    LOGGER_DEBUG = 0,
    LOGGER_INFO,
    LOGGER_WARN,
    LOGGER_ERROR
}; //}

class Logger //{
{
private:
	std::ostream* outputStream;
    std::string title;
    std::string fileName;
    uint32_t pid;

    bool m_enabled;

    void helloLogger();
    void initializeOutputFile();
    void initializeOutputStream();
    void initializeTitle(const char*);

    void begin_log(const std::string&);
    void new_line();
    void __logger(const std::string& level, const char* msg, va_list list);

public:
    inline std::ostream& ostream() { return *this->outputStream; }
    inline void setTitle(const std::string& t){ this->title = t;}

    LoggerLevel Level = LOGGER_DEBUG;

    // constructor
	Logger(const std::string& title, const char* filename, bool clean);
	Logger(const std::string& title, const char* filename);
	Logger(const std::string& title, const std::string& filename);
    Logger(const std::string& title, std::ostream& outstream);
    Logger(const std::string& title);
    Logger();

	~Logger();

    void vdebug(const char*, va_list);
    void vinfo (const char*, va_list);
    void vwarn (const char*, va_list);
    void verror(const char*, va_list);

    void debug(const char*, ...);
    void info (const char*, ...);
    void warn (const char*, ...);
    void error(const char*, ...);

    void disable();
    void enable();
}; //}

extern Logger* logger;

void logger_init_stdout();

void debug(const char* msg, ...);
void info (const char* msg, ...);
void warn (const char* msg, ...);
void error(const char* msg, ...);
}

