
/**
 * @file v3_thread.h
 * @brief v3 Core - 线程抽象
 * 
 * 提供跨平台的线程和线程池 API
 */

#ifndef V3_THREAD_H
#define V3_THREAD_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 线程优先级
 * ========================================================= */

typedef enum v3_thread_priority_e {
    V3_THREAD_PRIORITY_LOW = -1,
    V3_THREAD_PRIORITY_NORMAL = 0,
    V3_THREAD_PRIORITY_HIGH = 1,
    V3_THREAD_PRIORITY_REALTIME = 2,
} v3_thread_priority_t;

/* =========================================================
 * 线程
 * ========================================================= */

/**
 * @brief 线程句柄
 */
typedef struct v3_thread_s v3_thread_t;

/**
 * @brief 线程函数类型
 * @param arg 参数
 * @return 返回值
 */
typedef void* (*v3_thread_fn)(void *arg);

/**
 * @brief 线程配置
 */
typedef struct v3_thread_config_s {
    const char             *name;           /* 线程名称 */
    usize                   stack_size;     /* 栈大小（0=默认）*/
    v3_thread_priority_t    priority;       /* 优先级 */
    bool                    detached;       /* 是否分离 */
} v3_thread_config_t;

/**
 * @brief 创建线程
 * @param config 配置（NULL 使用默认）
 * @param fn 线程函数
 * @param arg 参数
 * @param thread_out 输出线程句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_create(
    const v3_thread_config_t *config,
    v3_thread_fn fn,
    void *arg,
    v3_thread_t **thread_out
);

/**
 * @brief 等待线程结束
 * @param thread 线程句柄
 * @param result_out 输出返回值（可选）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_join(v3_thread_t *thread, void **result_out);

/**
 * @brief 分离线程
 * @param thread 线程句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_detach(v3_thread_t *thread);

/**
 * @brief 获取当前线程
 * @return 当前线程句柄
 */
V3_API v3_thread_t* v3_thread_self(void);

/**
 * @brief 获取线程 ID
 * @param thread 线程句柄
 * @return 线程 ID
 */
V3_API v3_tid_t v3_thread_get_id(v3_thread_t *thread);

/**
 * @brief 设置线程名称
 * @param thread 线程句柄
 * @param name 名称
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_set_name(v3_thread_t *thread, const char *name);

/**
 * @brief 设置当前线程名称
 * @param name 名称
 */
V3_API void v3_thread_set_current_name(const char *name);

/**
 * @brief 设置线程优先级
 * @param thread 线程句柄
 * @param priority 优先级
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_set_priority(v3_thread_t *thread, v3_thread_priority_t priority);

/**
 * @brief 设置 CPU 亲和性
 * @param thread 线程句柄
 * @param cpu_mask CPU 掩码
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_set_affinity(v3_thread_t *thread, u64 cpu_mask);

/* =========================================================
 * 线程池
 * ========================================================= */

/**
 * @brief 线程池句柄
 */
typedef struct v3_thread_pool_s v3_thread_pool_t;

/**
 * @brief 任务函数类型
 */
typedef void (*v3_task_fn)(void *arg);

/**
 * @brief 线程池配置
 */
typedef struct v3_thread_pool_config_s {
    u32     min_threads;            /* 最小线程数 */
    u32     max_threads;            /* 最大线程数 */
    u32     queue_size;             /* 任务队列大小 */
    u32     idle_timeout_ms;        /* 空闲线程超时 */
    const char *name_prefix;        /* 线程名称前缀 */
} v3_thread_pool_config_t;

/**
 * @brief 创建线程池
 * @param config 配置（NULL 使用默认）
 * @param pool_out 输出池句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_pool_create(
    const v3_thread_pool_config_t *config,
    v3_thread_pool_t **pool_out
);

/**
 * @brief 销毁线程池
 * @param pool 池句柄
 * @param wait_pending 是否等待待处理任务
 */
V3_API void v3_thread_pool_destroy(v3_thread_pool_t *pool, bool wait_pending);

/**
 * @brief 获取默认配置
 * @param config 输出配置
 */
V3_API void v3_thread_pool_default_config(v3_thread_pool_config_t *config);

/**
 * @brief 提交任务
 * @param pool 池句柄
 * @param fn 任务函数
 * @param arg 参数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_pool_submit(
    v3_thread_pool_t *pool,
    v3_task_fn fn,
    void *arg
);

/**
 * @brief 尝试提交任务（非阻塞）
 * @param pool 池句柄
 * @param fn 任务函数
 * @param arg 参数
 * @return V3_OK 成功，V3_ERR_BUFFER_FULL 队列已满
 */
V3_API v3_error_t v3_thread_pool_try_submit(
    v3_thread_pool_t *pool,
    v3_task_fn fn,
    void *arg
);

/**
 * @brief 获取待处理任务数
 * @param pool 池句柄
 * @return 待处理任务数
 */
V3_API u32 v3_thread_pool_pending(v3_thread_pool_t *pool);

/**
 * @brief 获取活跃线程数
 * @param pool 池句柄
 * @return 活跃线程数
 */
V3_API u32 v3_thread_pool_active(v3_thread_pool_t *pool);

/**
 * @brief 等待所有任务完成
 * @param pool 池句柄
 * @param timeout_ms 超时（0=无限）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_thread_pool_wait(v3_thread_pool_t *pool, u32 timeout_ms);

/* =========================================================
 * 一次性初始化
 * ========================================================= */

/**
 * @brief 一次性初始化控制
 */
typedef volatile s32 v3_once_t;

#define V3_ONCE_INIT    0

/**
 * @brief 执行一次性初始化
 * @param once 控制变量
 * @param init_fn 初始化函数
 */
V3_API void v3_once(v3_once_t *once, void (*init_fn)(void));

/* =========================================================
 * 工作窃取队列（高性能任务队列）
 * ========================================================= */

/**
 * @brief 工作队列句柄
 */
typedef struct v3_work_queue_s v3_work_queue_t;

/**
 * @brief 创建工作队列
 * @param capacity 容量
 * @param queue_out 输出队列句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_work_queue_create(u32 capacity, v3_work_queue_t **queue_out);

/**
 * @brief 销毁工作队列
 * @param queue 队列句柄
 */
V3_API void v3_work_queue_destroy(v3_work_queue_t *queue);

/**
 * @brief 推入任务
 * @param queue 队列句柄
 * @param fn 任务函数
 * @param arg 参数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_work_queue_push(v3_work_queue_t *queue, v3_task_fn fn, void *arg);

/**
 * @brief 弹出任务
 * @param queue 队列句柄
 * @param fn_out 输出任务函数
 * @param arg_out 输出参数
 * @return V3_OK 成功，V3_ERR_EMPTY 队列空
 */
V3_API v3_error_t v3_work_queue_pop(v3_work_queue_t *queue, v3_task_fn *fn_out, void **arg_out);

/**
 * @brief 窃取任务（从尾部）
 * @param queue 队列句柄
 * @param fn_out 输出任务函数
 * @param arg_out 输出参数
 * @return V3_OK 成功，V3_ERR_EMPTY 队列空
 */
V3_API v3_error_t v3_work_queue_steal(v3_work_queue_t *queue, v3_task_fn *fn_out, void **arg_out);

/**
 * @brief 检查队列是否为空
 * @param queue 队列句柄
 * @return true 为空
 */
V3_API bool v3_work_queue_empty(v3_work_queue_t *queue);

#ifdef __cplusplus
}
#endif

#endif /* V3_THREAD_H */
