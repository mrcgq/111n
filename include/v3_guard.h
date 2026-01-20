
/**
 * @file v3_guard.h
 * @brief v3 Core - 守护进程/保护模块
 * 
 * 提供进程守护、自动重启、看门狗等功能
 */

#ifndef V3_GUARD_H
#define V3_GUARD_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* 默认配置 */
#define V3_GUARD_DEFAULT_RESTART_DELAY_MS   1000    /* 重启延迟 */
#define V3_GUARD_DEFAULT_MAX_RESTARTS       10      /* 最大重启次数 */
#define V3_GUARD_DEFAULT_RESTART_WINDOW_SEC 60      /* 重启计数窗口 */
#define V3_GUARD_DEFAULT_WATCHDOG_TIMEOUT_MS 30000  /* 看门狗超时 */

/* =========================================================
 * 守护配置
 * ========================================================= */

typedef struct v3_guard_config_s {
    /* 重启配置 */
    bool        auto_restart;           /* 是否自动重启 */
    u32         restart_delay_ms;       /* 重启延迟毫秒 */
    u32         max_restarts;           /* 最大重启次数 */
    u32         restart_window_sec;     /* 重启计数窗口秒数 */
    
    /* 看门狗配置 */
    bool        watchdog_enabled;       /* 是否启用看门狗 */
    u32         watchdog_timeout_ms;    /* 看门狗超时毫秒 */
    
    /* 进程配置 */
    const char *process_name;           /* 子进程名称 */
    const char *working_dir;            /* 工作目录 */
    const char *log_file;               /* 日志文件 */
    
    /* 回调 */
    void       *user_data;              /* 用户数据 */
} v3_guard_config_t;

/* =========================================================
 * 守护状态
 * ========================================================= */

typedef enum v3_guard_state_e {
    V3_GUARD_STATE_IDLE = 0,            /* 空闲 */
    V3_GUARD_STATE_STARTING,            /* 正在启动 */
    V3_GUARD_STATE_RUNNING,             /* 运行中 */
    V3_GUARD_STATE_STOPPING,            /* 正在停止 */
    V3_GUARD_STATE_STOPPED,             /* 已停止 */
    V3_GUARD_STATE_RESTARTING,          /* 正在重启 */
    V3_GUARD_STATE_FAILED,              /* 失败 */
} v3_guard_state_t;

/* =========================================================
 * 守护统计
 * ========================================================= */

typedef struct v3_guard_stats_s {
    u32         restart_count;          /* 重启次数 */
    u64         last_restart_time;      /* 上次重启时间 */
    u64         uptime_sec;             /* 运行时长 */
    u64         total_uptime_sec;       /* 总运行时长 */
    v3_pid_t    child_pid;              /* 子进程 PID */
    int         last_exit_code;         /* 上次退出码 */
} v3_guard_stats_t;

/* =========================================================
 * 守护回调
 * ========================================================= */

/**
 * @brief 状态变更回调
 */
typedef void (*v3_guard_state_fn)(
    v3_guard_state_t old_state,
    v3_guard_state_t new_state,
    void *user_data
);

/**
 * @brief 子进程退出回调
 */
typedef void (*v3_guard_exit_fn)(
    v3_pid_t pid,
    int exit_code,
    bool crashed,
    void *user_data
);

/* =========================================================
 * 守护模块 API
 * ========================================================= */

/**
 * @brief 初始化守护模块
 * @param config 配置（NULL 使用默认）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_guard_init(const v3_guard_config_t *config);

/**
 * @brief 关闭守护模块
 */
V3_API void v3_guard_shutdown(void);

/**
 * @brief 获取默认配置
 * @param config 输出配置
 */
V3_API void v3_guard_default_config(v3_guard_config_t *config);

/**
 * @brief 启动守护
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_guard_start(void);

/**
 * @brief 停止守护
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_guard_stop(void);

/**
 * @brief 请求重启子进程
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_guard_restart(void);

/**
 * @brief 获取当前状态
 * @return 守护状态
 */
V3_API v3_guard_state_t v3_guard_get_state(void);

/**
 * @brief 获取状态名称
 * @param state 状态
 * @return 状态名称字符串
 */
V3_API const char* v3_guard_state_str(v3_guard_state_t state);

/**
 * @brief 获取统计信息
 * @param stats 输出统计
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_guard_get_stats(v3_guard_stats_t *stats);

/**
 * @brief 设置状态回调
 * @param fn 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_guard_set_state_callback(v3_guard_state_fn fn, void *user_data);

/**
 * @brief 设置退出回调
 * @param fn 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_guard_set_exit_callback(v3_guard_exit_fn fn, void *user_data);

/* =========================================================
 * 看门狗 API
 * ========================================================= */

/**
 * @brief 喂狗（重置看门狗计时器）
 */
V3_API void v3_guard_watchdog_kick(void);

/**
 * @brief 检查看门狗是否超时
 * @return true 已超时
 */
V3_API bool v3_guard_watchdog_expired(void);

/**
 * @brief 启用/禁用看门狗
 * @param enabled 是否启用
 */
V3_API void v3_guard_watchdog_enable(bool enabled);

/* =========================================================
 * 子进程管理
 * ========================================================= */

/**
 * @brief 检查是否是守护进程
 * @return true 是守护进程
 */
V3_API bool v3_guard_is_parent(void);

/**
 * @brief 检查是否是工作进程
 * @return true 是工作进程
 */
V3_API bool v3_guard_is_child(void);

/**
 * @brief 获取子进程 PID
 * @return 子进程 PID，无子进程返回 0
 */
V3_API v3_pid_t v3_guard_get_child_pid(void);

/**
 * @brief 向子进程发送信号
 * @param signal 信号
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_guard_signal_child(int signal);

#ifdef __cplusplus
}
#endif

#endif /* V3_GUARD_H */
