#pragma once

#include <stdint.h>

struct __attribute__((__packed__)) logger {
    uint8_t enable;
    char *name;
    char *color_name;
};

/*
 * List of log-ids.
 */
enum log_id {
    TIMER,
    TIMER_DETAIL,
    UPDATE,
    UPDATE_DETAIL,
    KEEPALIVE,
    FSM,
    IO,
    DEBUG,
    INFO,
    WARN,
    ERROR,
    LOG_ID_MAX
};

#define LOG(log_level, fmt_, ...)                                              \
    do {                                                                       \
        if (log_enabled(log_level)) {                                          \
            fprintf(                                                           \
                stderr,                                                        \
                "%s [%-6s]: " fmt_,                                            \
                fmt_timestamp(),                                               \
                log_name(log_level),                                           \
                ##__VA_ARGS__                                                  \
            );                                                                 \
        }                                                                      \
    } while (0)

/// Check if logger is enabled.
uint8_t
log_enabled(enum log_id lid);

/// Enable logger by id.
void
log_enable_id(enum log_id lid);

/// Enable logger by name.
void
log_enable_name(char *log_name);

void
log_reset();

const char *
log_name(enum log_id lid);

const char *
fmt_timestamp();

#ifdef LOG_IMPLEMENTATION

#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define LOG_RED "\x1b[31m"
#define LOG_GREEN "\x1b[32m"
#define LOG_YELLOW "\x1b[33m"
#define LOG_BLUE "\x1b[34m"
#define LOG_MAGENTA "\x1b[35m"
#define LOG_CYAN "\x1b[36m"
#define LOG_GRAY "\x1b[02;39m"
#define LOG_RESET "\x1b[0m"

static struct logger loggers[LOG_ID_MAX] = {
    [TIMER] = {.name = "TIMER"},
    [TIMER_DETAIL] = {.name = "TIMER2"},
    [UPDATE] = {.name = "UPD"},
    [UPDATE_DETAIL] = {.name = "UPD2"},
    [KEEPALIVE] = {.name = "KPALVE"},
    [FSM] = {.name = "FSM"},
    [IO] = {.name = "IO"},
    [DEBUG] = {.name = "DEBUG", .color_name = LOG_GRAY "DEBUG" LOG_RESET},
    [INFO] = {.name = "INFO", .color_name = LOG_BLUE "INFO" LOG_RESET},
    [WARN] = {.name = "WARN", .color_name = LOG_YELLOW "WARN" LOG_RESET},
    [ERROR] = {.name = "ERROR", .color_name = LOG_RED "ERROR" LOG_RESET},
};

const char *
fmt_timestamp() {
    static char ts_str[sizeof("2025-02-28T08:07:13.711541")];
    struct timespec now;
    struct tm tm;
    int len;

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm);

    len = strftime(ts_str, sizeof(ts_str), "%FT%T", &tm);
    snprintf(ts_str + len, sizeof(ts_str) - len, ".%06lu", now.tv_nsec / 1000);

    return ts_str;
}

inline const char *
log_name(enum log_id lid) {
    if (isatty(STDERR_FILENO) && loggers[lid].color_name) {
        return loggers[lid].color_name;
    } else {
        return loggers[lid].name;
    }
}

inline uint8_t
log_enabled(enum log_id lid) {
    return loggers[lid].enable;
}

inline void
log_enable_id(enum log_id lid) {
    loggers[lid].enable = 1;
}

void
log_reset() {
    for (uint64_t idx = 0; idx < sizeof(loggers) / sizeof(struct logger);
         idx++) {
        loggers[idx].enable = 0;
    }
}
inline void
log_enable_name(char *log_name) {
    enum log_id lid = -1;
    for (uint64_t idx = 0; idx < sizeof(loggers) / sizeof(struct logger);
         idx++) {
        if (strcasecmp(loggers[idx].name, log_name) == 0) {
            loggers[idx].enable = 1;
            lid = idx;
            break;
        }
    }
    // enable leveled logs
    switch (lid) {
    case DEBUG:
        loggers[DEBUG].enable = 1;
        // fallthrough
    case INFO:
        loggers[INFO].enable = 1;
        // fallthrough
    case WARN:
        loggers[WARN].enable = 1;
        // fallthrough
    case ERROR:
        loggers[ERROR].enable = 1;
    default:
    }
}
#endif // LOG_IMPLEMENTATION
