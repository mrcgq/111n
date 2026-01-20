/**
 * @file v3_log.h
 * @brief v3 Core - 日志系统
 * 
 * 提供灵活的日志记录功能
 */

#ifndef V3_LOG_H
#define V3_LOG_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 日志配置
 * ========================================================= */

/**
 * @brief 日志输出目标
 */
typedef enum v3_log_target_e {
    V3_LOG_TARGET_NONE      = 0x00,
    V3_LOG_TARGET_CONSOLE   = 0x01,     /* 控制台 */
    V3_LOG_TARGET_FILE      = 0x02,     /* 文件 */
    V3_LOG_TARGET_CALLBACK  = 0x04,     /* 回调 */
    V3_LOG_TARGET_DEBUGGER  = 0x08,     /* 调试器（Windows OutputDebugString）*/
    V3_LOG_TARGET_ALL       = 0x0F,
} v3_log_target_t;

/**
 * @brief 日志配置
 */
typedef struct v3_log_config_s {
    v3_log_level_t      level;              /* 日志级别 */
    u32                 targets;            /* 输出目标位掩码 */
    const char         *file_path;          /* 日志文件路径 */
    usize               max_file_size;      /* 单文件最大大小 */
    u32                 max_files;          /* 最大文件数（轮转）*/
    bool                include_timestamp;  /* 包含时间戳 */
    bool                include_level;      /* 包含级别 */
    bool                include_source;     /* 包含源文件/行号 */
    bool                include_thread;     /* 包含线程 ID */
    bool                colorize;           /* 控制台彩色输出 */
    v3_log_callback_fn  callback;           /* 回调函数 */
    void               *callback_data;      /* 回调用户数据 */
} v3_log_config_t;

/* =========================================================
 * 日志模块 API
 * ========================================================= */

/**
 * @brief 初始化日志模块
 * @param config 配置（NULL 使用默认）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_log_init(const v3_log_config_t *config);

/**
 * @brief 关闭日志模块
 */
V3_API void v3_log_shutdown(void);

/**
 * @brief 获取默认配置
 * @param config 输出配置
 */
V3_API void v3_log_default_config(v3_log_config_t *config);

/**
 * @brief 设置日志级别
 * @param level 日志级别
 */
V3_API void v3_log_set_level(v3_log_level_t level);

/**
 * @brief 获取日志级别
 * @return 当前日志级别
 */
V3_API v3_log_level_t v3_log_get_level(void);

/**
 * @brief 设置回调
 * @param callback 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_log_set_callback(v3_log_callback_fn callback, void *user_data);

/**
 * @brief 刷新日志缓冲
 */
V3_API void v3_log_flush(void);

/* =========================================================
 * 日志记录 API
 * ========================================================= */

/**
 * @brief 记录日志
 * @param level 级别
 * @param file 源文件
 * @param line 行号
 * @param func 函数名
 * @param fmt 格式字符串
 * @param ... 参数
 */
V3_API void v3_log_write(
    v3_log_level_t level,
    const char *file,
    int line,
    const char *func,
    const char *fmt,
    ...
) V3_PRINTF_FMT(5, 6);

/**
 * @brief 记录日志（va_list 版本）
 */
V3_API void v3_log_writev(
    v3_log_level_t level,
    const char *file,
    int line,
    const char *func,
    const char *fmt,
    va_list args
);

/**
 * @brief 记录十六进制数据
 * @param level 级别
 * @param prefix 前缀
 * @param data 数据
 * @param len 长度
 */
V3_API void v3_log_hex(
    v3_log_level_t level,
    const char *prefix,
    const u8 *data,
    usize len
);

/* =========================================================
 * 日志宏
 * ========================================================= */

#define V3_LOG(level, ...) \
    v3_log_write(level, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define V3_LOG_TRACE(...)   V3_LOG(V3_LOG_TRACE, __VA_ARGS__)
#define V3_LOG_DEBUG(...)   V3_LOG(V3_LOG_DEBUG, __VA_ARGS__)
#define V3_LOG_INFO(...)    V3_LOG(V3_LOG_INFO, __VA_ARGS__)
#define V3_LOG_WARN(...)    V3_LOG(V3_LOG_WARN, __VA_ARGS__)
#define V3_LOG_ERROR(...)   V3_LOG(V3_LOG_ERROR, __VA_ARGS__)
#define V3_LOG_FATAL(...)   V3_LOG(V3_LOG_FATAL, __VA_ARGS__)

/* 条件日志 */
#define V3_LOG_IF(cond, level, ...) \
    do { if (cond) V3_LOG(level, __VA_ARGS__); } while(0)

/* 首次日志（只记录一次）*/
#define V3_LOG_ONCE(level, ...) \
    do { \
        static bool _logged = false; \
        if (!_logged) { _logged = true; V3_LOG(level, __VA_ARGS__); } \
    } while(0)

/* 速率限制日志 */
#define V3_LOG_EVERY_N(n, level, ...) \
    do { \
        static u32 _count = 0; \
        if (++_count % (n) == 0) V3_LOG(level, __VA_ARGS__); \
    } while(0)

/* =========================================================
 * 工具函数
 * ========================================================= */

/**
 * @brief 获取级别名称
 * @param level 级别
 * @return 级别名称字符串
 */
V3_API const char* v3_log_level_str(v3_log_level_t level);

/**
 * @brief 从字符串解析级别
 * @param str 字符串
 * @return 日志级别
 */
V3_API v3_log_level_t v3_log_level_from_str(const char *str);

/**
 * @brief 检查是否应该记录
 * @param level 级别
 * @return true 应该记录
 */
V3_API bool v3_log_should_log(v3_log_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* V3_LOG_H */
