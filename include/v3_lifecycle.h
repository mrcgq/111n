
/**
 * @file v3_lifecycle.h
 * @brief v3 Core - 生命周期管理
 * 
 * 管理 v3 Core 的启动、停止、重载等生命周期事件
 */

#ifndef V3_LIFECYCLE_H
#define V3_LIFECYCLE_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 生命周期阶段
 * ========================================================= */

typedef enum v3_lifecycle_phase_e {
    V3_PHASE_NONE = 0,
    
    /* 启动阶段 */
    V3_PHASE_PRE_INIT,          /* 初始化前 */
    V3_PHASE_INIT,              /* 初始化中 */
    V3_PHASE_POST_INIT,         /* 初始化后 */
    V3_PHASE_PRE_START,         /* 启动前 */
    V3_PHASE_START,             /* 启动中 */
    V3_PHASE_POST_START,        /* 启动后 */
    V3_PHASE_RUNNING,           /* 运行中 */
    
    /* 停止阶段 */
    V3_PHASE_PRE_STOP,          /* 停止前 */
    V3_PHASE_STOP,              /* 停止中 */
    V3_PHASE_POST_STOP,         /* 停止后 */
    V3_PHASE_PRE_SHUTDOWN,      /* 关闭前 */
    V3_PHASE_SHUTDOWN,          /* 关闭中 */
    V3_PHASE_POST_SHUTDOWN,     /* 关闭后 */
    
    /* 重载阶段 */
    V3_PHASE_PRE_RELOAD,        /* 重载前 */
    V3_PHASE_RELOAD,            /* 重载中 */
    V3_PHASE_POST_RELOAD,       /* 重载后 */
    
    V3_PHASE_MAX
} v3_lifecycle_phase_t;

/* =========================================================
 * 生命周期钩子
 * ========================================================= */

/**
 * @brief 生命周期钩子函数类型
 * @param phase 当前阶段
 * @param user_data 用户数据
 * @return V3_OK 继续，其他值中止
 */
typedef v3_error_t (*v3_lifecycle_hook_fn)(
    v3_lifecycle_phase_t phase,
    void *user_data
);

/**
 * @brief 钩子优先级
 */
typedef enum v3_hook_priority_e {
    V3_HOOK_PRIORITY_FIRST      = 0,
    V3_HOOK_PRIORITY_HIGH       = 100,
    V3_HOOK_PRIORITY_NORMAL     = 500,
    V3_HOOK_PRIORITY_LOW        = 900,
    V3_HOOK_PRIORITY_LAST       = 1000,
} v3_hook_priority_t;

/**
 * @brief 钩子句柄
 */
typedef struct v3_lifecycle_hook_s v3_lifecycle_hook_t;

/* =========================================================
 * 生命周期 API
 * ========================================================= */

/**
 * @brief 初始化生命周期管理器
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_init(void);

/**
 * @brief 关闭生命周期管理器
 */
V3_API void v3_lifecycle_shutdown(void);

/**
 * @brief 获取当前生命周期阶段
 * @return 当前阶段
 */
V3_API v3_lifecycle_phase_t v3_lifecycle_get_phase(void);

/**
 * @brief 获取阶段名称
 * @param phase 阶段
 * @return 阶段名称字符串
 */
V3_API const char* v3_lifecycle_phase_str(v3_lifecycle_phase_t phase);

/**
 * @brief 注册生命周期钩子
 * @param phase 阶段
 * @param fn 钩子函数
 * @param user_data 用户数据
 * @param priority 优先级
 * @param hook_out 输出钩子句柄（可选）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_register_hook(
    v3_lifecycle_phase_t phase,
    v3_lifecycle_hook_fn fn,
    void *user_data,
    v3_hook_priority_t priority,
    v3_lifecycle_hook_t **hook_out
);

/**
 * @brief 注销生命周期钩子
 * @param hook 钩子句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_unregister_hook(v3_lifecycle_hook_t *hook);

/**
 * @brief 触发生命周期阶段转换
 * @param target_phase 目标阶段
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_transition(v3_lifecycle_phase_t target_phase);

/**
 * @brief 执行完整启动序列
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_startup(void);

/**
 * @brief 执行完整停止序列
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_stop(void);

/**
 * @brief 执行完整关闭序列
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_shutdown_full(void);

/**
 * @brief 执行重载序列
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_reload(void);

/* =========================================================
 * 状态查询
 * ========================================================= */

/**
 * @brief 检查是否正在运行
 * @return true 正在运行
 */
V3_API bool v3_lifecycle_is_running(void);

/**
 * @brief 检查是否正在停止
 * @return true 正在停止
 */
V3_API bool v3_lifecycle_is_stopping(void);

/**
 * @brief 检查是否已初始化
 * @return true 已初始化
 */
V3_API bool v3_lifecycle_is_initialized(void);

/**
 * @brief 获取运行时长（秒）
 * @return 运行秒数
 */
V3_API u64 v3_lifecycle_uptime_sec(void);

/**
 * @brief 获取启动时间戳
 * @return Unix 时间戳
 */
V3_API u64 v3_lifecycle_start_time(void);

/* =========================================================
 * 健康检查
 * ========================================================= */

/**
 * @brief 健康检查回调类型
 * @param user_data 用户数据
 * @return V3_OK 健康，其他值不健康
 */
typedef v3_error_t (*v3_health_check_fn)(void *user_data);

/**
 * @brief 注册健康检查
 * @param name 检查名称
 * @param fn 检查函数
 * @param user_data 用户数据
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_lifecycle_register_health_check(
    const char *name,
    v3_health_check_fn fn,
    void *user_data
);

/**
 * @brief 执行所有健康检查
 * @return V3_OK 全部健康
 */
V3_API v3_error_t v3_lifecycle_check_health(void);

#ifdef __cplusplus
}
#endif

#endif /* V3_LIFECYCLE_H */




