
/**
 * @file v3_exit.h
 * @brief v3 Core - 退出与清理
 * 
 * 提供安全的程序退出和资源清理机制
 */

#ifndef V3_EXIT_H
#define V3_EXIT_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 退出码定义
 * ========================================================= */

typedef enum v3_exit_code_e {
    V3_EXIT_SUCCESS             = 0,    /* 正常退出 */
    V3_EXIT_ERROR               = 1,    /* 一般错误 */
    V3_EXIT_INVALID_ARGS        = 2,    /* 无效参数 */
    V3_EXIT_CONFIG_ERROR        = 3,    /* 配置错误 */
    V3_EXIT_INIT_FAILED         = 4,    /* 初始化失败 */
    V3_EXIT_NETWORK_ERROR       = 5,    /* 网络错误 */
    V3_EXIT_CRYPTO_ERROR        = 6,    /* 加密错误 */
    V3_EXIT_PERMISSION_DENIED   = 7,    /* 权限不足 */
    V3_EXIT_RESOURCE_EXHAUSTED  = 8,    /* 资源耗尽 */
    V3_EXIT_FATAL_ERROR         = 9,    /* 致命错误 */
    V3_EXIT_SIGNAL              = 128,  /* 信号退出基值 */
    
    /* 信号退出码 = V3_EXIT_SIGNAL + 信号编号 */
    V3_EXIT_SIGINT              = 130,  /* SIGINT (Ctrl+C) */
    V3_EXIT_SIGTERM             = 143,  /* SIGTERM */
} v3_exit_code_t;

/* =========================================================
 * 退出原因
 * ========================================================= */

typedef enum v3_exit_reason_e {
    V3_EXIT_REASON_NONE = 0,            /* 未指定 */
    V3_EXIT_REASON_NORMAL,              /* 正常退出 */
    V3_EXIT_REASON_USER_REQUEST,        /* 用户请求 */
    V3_EXIT_REASON_SIGNAL,              /* 信号触发 */
    V3_EXIT_REASON_ERROR,               /* 错误发生 */
    V3_EXIT_REASON_FATAL,               /* 致命错误 */
    V3_EXIT_REASON_RESTART,             /* 请求重启 */
    V3_EXIT_REASON_UPDATE,              /* 更新退出 */
    V3_EXIT_REASON_PARENT_EXIT,         /* 父进程退出 */
    V3_EXIT_REASON_WATCHDOG,            /* 看门狗触发 */
} v3_exit_reason_t;

/* =========================================================
 * 清理回调
 * ========================================================= */

/**
 * @brief 清理回调函数类型
 * @param user_data 用户数据
 * @param reason 退出原因
 */
typedef void (*v3_cleanup_fn)(void *user_data, v3_exit_reason_t reason);

/**
 * @brief 清理回调优先级（数值越小越先执行）
 */
typedef enum v3_cleanup_priority_e {
    V3_CLEANUP_PRIORITY_FIRST   = 0,    /* 最先清理 */
    V3_CLEANUP_PRIORITY_NETWORK = 100,  /* 网络清理 */
    V3_CLEANUP_PRIORITY_SESSION = 200,  /* 会话清理 */
    V3_CLEANUP_PRIORITY_CRYPTO  = 300,  /* 加密清理 */
    V3_CLEANUP_PRIORITY_MEMORY  = 400,  /* 内存清理 */
    V3_CLEANUP_PRIORITY_LOG     = 500,  /* 日志清理 */
    V3_CLEANUP_PRIORITY_LAST    = 1000, /* 最后清理 */
} v3_cleanup_priority_t;

/**
 * @brief 清理回调句柄
 */
typedef struct v3_cleanup_handle_s v3_cleanup_handle_t;

/* =========================================================
 * 退出管理 API
 * ========================================================= */

/**
 * @brief 初始化退出管理器
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_exit_init(void);

/**
 * @brief 关闭退出管理器
 */
V3_API void v3_exit_shutdown(void);

/**
 * @brief 注册清理回调
 * @param fn 清理函数
 * @param user_data 用户数据
 * @param priority 优先级
 * @param handle_out 输出句柄（可选）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_exit_register_cleanup(
    v3_cleanup_fn fn,
    void *user_data,
    v3_cleanup_priority_t priority,
    v3_cleanup_handle_t **handle_out
);

/**
 * @brief 注销清理回调
 * @param handle 回调句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_exit_unregister_cleanup(v3_cleanup_handle_t *handle);

/**
 * @brief 请求退出
 * @param code 退出码
 * @param reason 退出原因
 * @param message 退出消息（可选）
 */
V3_API void v3_exit_request(
    v3_exit_code_t code,
    v3_exit_reason_t reason,
    const char *message
);

/**
 * @brief 检查是否已请求退出
 * @return true 如果已请求退出
 */
V3_API bool v3_exit_requested(void);

/**
 * @brief 获取请求的退出码
 * @return 退出码
 */
V3_API v3_exit_code_t v3_exit_get_code(void);

/**
 * @brief 获取退出原因
 * @return 退出原因
 */
V3_API v3_exit_reason_t v3_exit_get_reason(void);

/**
 * @brief 获取退出消息
 * @return 退出消息字符串（可能为 NULL）
 */
V3_API const char* v3_exit_get_message(void);

/**
 * @brief 执行所有清理回调
 * @param reason 退出原因
 * @return V3_OK 成功
 * 
 * 按优先级顺序调用所有已注册的清理回调
 */
V3_API v3_error_t v3_exit_run_cleanup(v3_exit_reason_t reason);

/**
 * @brief 立即退出程序
 * @param code 退出码
 * 
 * 调用此函数会：
 * 1. 设置退出标志
 * 2. 执行所有清理回调
 * 3. 调用 exit()
 */
V3_API V3_NORETURN void v3_exit_now(v3_exit_code_t code);

/**
 * @brief 紧急退出（不执行清理）
 * @param code 退出码
 */
V3_API V3_NORETURN void v3_exit_abort(v3_exit_code_t code);

/* =========================================================
 * 信号处理
 * ========================================================= */

/**
 * @brief 初始化信号处理
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_exit_setup_signals(void);

/**
 * @brief 阻止信号处理（用于子进程）
 */
V3_API void v3_exit_block_signals(void);

/**
 * @brief 恢复信号处理
 */
V3_API void v3_exit_restore_signals(void);

/**
 * @brief 发送退出信号给自己
 * @param signal_num 信号编号
 */
V3_API void v3_exit_raise_signal(int signal_num);

/* =========================================================
 * 等待退出
 * ========================================================= */

/**
 * @brief 等待退出信号
 * @param timeout_ms 超时毫秒数（0=永久等待）
 * @return true 如果收到退出信号，false 如果超时
 */
V3_API bool v3_exit_wait(u32 timeout_ms);

/**
 * @brief 创建用于等待的事件对象
 * @return 事件句柄
 */
V3_API v3_handle_t v3_exit_get_event(void);

/* =========================================================
 * 重启支持
 * ========================================================= */

/**
 * @brief 请求重启
 * @param delay_ms 延迟毫秒数
 */
V3_API void v3_exit_request_restart(u32 delay_ms);

/**
 * @brief 检查是否请求重启
 * @return true 如果请求重启
 */
V3_API bool v3_exit_restart_requested(void);

/* =========================================================
 * 调试支持
 * ========================================================= */

/**
 * @brief 打印清理回调列表（调试用）
 */
V3_API void v3_exit_dump_cleanups(void);

/**
 * @brief 获取退出原因的字符串描述
 * @param reason 退出原因
 * @return 描述字符串
 */
V3_API const char* v3_exit_reason_str(v3_exit_reason_t reason);

/**
 * @brief 获取退出码的字符串描述
 * @param code 退出码
 * @return 描述字符串
 */
V3_API const char* v3_exit_code_str(v3_exit_code_t code);

#ifdef __cplusplus
}
#endif

#endif /* V3_EXIT_H */
