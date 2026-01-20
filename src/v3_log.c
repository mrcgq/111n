
/*
 * v3_log.c - v3 日志系统实现
 * 
 * 功能：
 * - 多级别日志
 * - 文件输出
 * - 控制台输出
 * - 日志轮转
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_log.h"
#include "v3_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

/* =========================================================
 * 配置
 * ========================================================= */

#define LOG_BUFFER_SIZE     4096
#define LOG_MAX_MSG_SIZE    2048
#define LOG_TIMESTAMP_SIZE  32

/* =========================================================
 * 全局状态
 * ========================================================= */

static struct {
    bool            initialized;
    v3_log_level_t  level;
    bool            to_console;
    bool            to_file;
    bool            use_colors;
    
    char            file_path[V3_MAX_PATH];
    FILE           *file_handle;
    size_t          file_size;
    size_t          max_file_size;
    int             max_files;
    int             current_file_idx;
    
    v3_mutex_t      mutex;
    
    v3_log_callback_t callback;
    void             *callback_arg;
} g_log = {
    .initialized = false,
    .level = V3_LOG_INFO,
    .to_console = true,
    .to_file = false,
    .use_colors = true,
    .file_handle = NULL,
    .file_size = 0,
    .max_file_size = 100 * 1024 * 1024,  /* 100MB */
    .max_files = 5,
    .current_file_idx = 0,
    .callback = NULL,
};

/* =========================================================
 * 颜色定义
 * ========================================================= */

#ifdef _WIN32
static const WORD g_level_colors[] = {
    FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED,        /* DEBUG - 白色 */
    FOREGROUND_GREEN,                                             /* INFO - 绿色 */
    FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,    /* WARN - 黄色 */
    FOREGROUND_RED | FOREGROUND_INTENSITY,                        /* ERROR - 红色 */
    FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,     /* FATAL - 紫色 */
};
#else
static const char* g_level_colors[] = {
    "\x1b[37m",     /* DEBUG - 白色 */
    "\x1b[32m",     /* INFO - 绿色 */
    "\x1b[33m",     /* WARN - 黄色 */
    "\x1b[31m",     /* ERROR - 红色 */
    "\x1b[35m",     /* FATAL - 紫色 */
};
static const char* g_color_reset = "\x1b[0m";
#endif

/* 日志级别名称 */
static const char* g_level_names[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL"
};

/* =========================================================
 * 辅助函数
 * ========================================================= */

static void log_get_timestamp(char *buf, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(buf, size, "????-??-?? ??:??:??");
    }
}

static void log_rotate(void) {
    if (!g_log.file_handle || !g_log.to_file) return;
    
    fclose(g_log.file_handle);
    g_log.file_handle = NULL;
    
    /* 轮转文件 */
    char old_path[V3_MAX_PATH];
    char new_path[V3_MAX_PATH];
    
    /* 删除最旧的文件 */
    snprintf(old_path, sizeof(old_path), "%s.%d", g_log.file_path, g_log.max_files);
    remove(old_path);
    
    /* 重命名其他文件 */
    for (int i = g_log.max_files - 1; i >= 1; i--) {
        snprintf(old_path, sizeof(old_path), "%s.%d", g_log.file_path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", g_log.file_path, i + 1);
        rename(old_path, new_path);
    }
    
    /* 重命名当前文件 */
    snprintf(new_path, sizeof(new_path), "%s.1", g_log.file_path);
    rename(g_log.file_path, new_path);
    
    /* 打开新文件 */
    g_log.file_handle = fopen(g_log.file_path, "a");
    g_log.file_size = 0;
}

static void log_write_console(v3_log_level_t level, const char *msg) {
    if (!g_log.to_console) return;
    
    FILE *out = (level >= V3_LOG_WARN) ? stderr : stdout;
    
#ifdef _WIN32
    if (g_log.use_colors && isatty(fileno(out))) {
        HANDLE console = GetStdHandle(level >= V3_LOG_WARN ? 
                                       STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO info;
        GetConsoleScreenBufferInfo(console, &info);
        
        SetConsoleTextAttribute(console, g_level_colors[level]);
        fprintf(out, "%s", msg);
        SetConsoleTextAttribute(console, info.wAttributes);
    } else {
        fprintf(out, "%s", msg);
    }
#else
    if (g_log.use_colors && isatty(fileno(out))) {
        fprintf(out, "%s%s%s", g_level_colors[level], msg, g_color_reset);
    } else {
        fprintf(out, "%s", msg);
    }
#endif
    
    fflush(out);
}

static void log_write_file(const char *msg, size_t len) {
    if (!g_log.to_file || !g_log.file_handle) return;
    
    fwrite(msg, 1, len, g_log.file_handle);
    fflush(g_log.file_handle);
    
    g_log.file_size += len;
    
    if (g_log.file_size >= g_log.max_file_size) {
        log_rotate();
    }
}

/* =========================================================
 * 公共 API
 * ========================================================= */

v3_error_t v3_log_init(const v3_log_config_t *config) {
    if (g_log.initialized) {
        return V3_OK;
    }
    
    v3_mutex_init(&g_log.mutex);
    
    if (config) {
        g_log.level = config->level;
        g_log.to_console = config->to_console;
        g_log.to_file = config->to_file;
        g_log.use_colors = config->use_colors;
        g_log.max_file_size = config->max_file_size;
        g_log.max_files = config->max_files;
        
        if (config->to_file && config->file_path[0]) {
            strncpy(g_log.file_path, config->file_path, sizeof(g_log.file_path) - 1);
            
            g_log.file_handle = fopen(g_log.file_path, "a");
            if (!g_log.file_handle) {
                g_log.to_file = false;
            } else {
                fseek(g_log.file_handle, 0, SEEK_END);
                g_log.file_size = ftell(g_log.file_handle);
            }
        }
    }
    
    g_log.initialized = true;
    return V3_OK;
}

void v3_log_cleanup(void) {
    if (!g_log.initialized) return;
    
    v3_mutex_lock(&g_log.mutex);
    
    if (g_log.file_handle) {
        fclose(g_log.file_handle);
        g_log.file_handle = NULL;
    }
    
    v3_mutex_unlock(&g_log.mutex);
    v3_mutex_destroy(&g_log.mutex);
    
    g_log.initialized = false;
}

void v3_log_set_level(v3_log_level_t level) {
    g_log.level = level;
}

v3_log_level_t v3_log_get_level(void) {
    return g_log.level;
}

void v3_log_set_callback(v3_log_callback_t callback, void *arg) {
    g_log.callback = callback;
    g_log.callback_arg = arg;
}

void v3_log_write(v3_log_level_t level, const char *file, int line,
                  const char *func, const char *fmt, ...) {
    if (level < g_log.level) return;
    if (!g_log.initialized) {
        /* 未初始化时直接输出到控制台 */
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
        return;
    }
    
    char timestamp[LOG_TIMESTAMP_SIZE];
    log_get_timestamp(timestamp, sizeof(timestamp));
    
    /* 格式化用户消息 */
    char user_msg[LOG_MAX_MSG_SIZE];
    va_list args;
    va_start(args, fmt);
    vsnprintf(user_msg, sizeof(user_msg), fmt, args);
    va_end(args);
    
    /* 构建完整日志行 */
    char log_line[LOG_BUFFER_SIZE];
    int len;
    
    /* 提取文件名 */
    const char *filename = file;
    const char *slash = strrchr(file, '/');
    if (!slash) slash = strrchr(file, '\\');
    if (slash) filename = slash + 1;
    
    if (level >= V3_LOG_DEBUG) {
        len = snprintf(log_line, sizeof(log_line),
                      "[%s] [%-5s] [%s:%d] %s\n",
                      timestamp, g_level_names[level], filename, line, user_msg);
    } else {
        len = snprintf(log_line, sizeof(log_line),
                      "[%s] [%-5s] %s\n",
                      timestamp, g_level_names[level], user_msg);
    }
    
    if (len < 0) return;
    if ((size_t)len >= sizeof(log_line)) {
        len = sizeof(log_line) - 1;
    }
    
    v3_mutex_lock(&g_log.mutex);
    
    /* 写入控制台 */
    log_write_console(level, log_line);
    
    /* 写入文件 */
    log_write_file(log_line, len);
    
    /* 回调 */
    if (g_log.callback) {
        g_log.callback(level, timestamp, filename, line, func, user_msg, g_log.callback_arg);
    }
    
    v3_mutex_unlock(&g_log.mutex);
}

void v3_log_hex(v3_log_level_t level, const char *prefix,
                const void *data, size_t len) {
    if (level < g_log.level) return;
    if (!data || len == 0) return;
    
    const uint8_t *bytes = (const uint8_t*)data;
    char line[128];
    char hex_part[64];
    char ascii_part[32];
    
    v3_mutex_lock(&g_log.mutex);
    
    if (prefix && prefix[0]) {
        char log_line[256];
        snprintf(log_line, sizeof(log_line), "%s (%zu bytes):\n", prefix, len);
        log_write_console(level, log_line);
        log_write_file(log_line, strlen(log_line));
    }
    
    for (size_t i = 0; i < len; i += 16) {
        int hex_pos = 0;
        int ascii_pos = 0;
        
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t b = bytes[i + j];
            hex_pos += snprintf(hex_part + hex_pos, sizeof(hex_part) - hex_pos,
                               "%02X ", b);
            ascii_part[ascii_pos++] = (b >= 32 && b < 127) ? b : '.';
        }
        ascii_part[ascii_pos] = '\0';
        
        snprintf(line, sizeof(line), "  %04zX: %-48s |%s|\n", i, hex_part, ascii_part);
        log_write_console(level, line);
        log_write_file(line, strlen(line));
    }
    
    v3_mutex_unlock(&g_log.mutex);
}

void v3_log_flush(void) {
    v3_mutex_lock(&g_log.mutex);
    
    if (g_log.file_handle) {
        fflush(g_log.file_handle);
    }
    
    v3_mutex_unlock(&g_log.mutex);
}

bool v3_log_is_enabled(v3_log_level_t level) {
    return level >= g_log.level;
}

/* =========================================================
 * 日志级别转换
 * ========================================================= */

const char* v3_log_level_name(v3_log_level_t level) {
    if (level >= 0 && level < sizeof(g_level_names) / sizeof(g_level_names[0])) {
        return g_level_names[level];
    }
    return "UNKNOWN";
}

v3_log_level_t v3_log_level_from_name(const char *name) {
    if (!name) return V3_LOG_INFO;
    
    for (size_t i = 0; i < sizeof(g_level_names) / sizeof(g_level_names[0]); i++) {
        if (strcasecmp(name, g_level_names[i]) == 0) {
            return (v3_log_level_t)i;
        }
    }
    
    return V3_LOG_INFO;
}
