/*
 * v3_thread.c - v3 线程池实现
 * 
 * 功能：
 * - 跨平台线程池
 * - 任务队列
 * - 工作线程管理
 * - 优雅关闭
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_thread.h"
#include "v3_log.h"
#include "v3_platform.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <pthread.h>
#include <unistd.h>
#include <sched.h>
#endif

/* =========================================================
 * 配置
 * ========================================================= */

#define TASK_QUEUE_INITIAL_SIZE     256
#define TASK_QUEUE_MAX_SIZE         65536

/* =========================================================
 * 任务结构
 * ========================================================= */

typedef struct {
    v3_task_fn func;
    void      *arg;
} v3_task_t;

/* =========================================================
 * 线程池结构
 * ========================================================= */

struct v3_thread_pool_s {
    /* 线程 */
#ifdef _WIN32
    HANDLE             *threads;
#else
    pthread_t          *threads;
#endif
    u32                 thread_count;
    
    /* 任务队列 */
    v3_task_t          *queue;
    u32                 queue_capacity;
    u32                 queue_size;
    u32                 queue_head;
    u32                 queue_tail;
    
    /* 同步 */
    v3_mutex_t         *mutex;
    v3_cond_t          *not_empty;
    v3_cond_t          *not_full;
    
    /* 状态 */
    volatile bool       running;
    volatile bool       shutdown;
    volatile u32        active_count;
    
    /* 统计 */
    u64                 tasks_submitted;
    u64                 tasks_completed;
    
    /* 名称 */
    char                name_prefix[32];
};

/* =========================================================
 * 工作线程函数
 * ========================================================= */

#ifdef _WIN32
static unsigned __stdcall worker_thread_func(void *arg) {
#else
static void* worker_thread_func(void *arg) {
#endif
    v3_thread_pool_t *pool = (v3_thread_pool_t*)arg;
    
    V3_LOG_DEBUG("Worker thread for pool '%s' started.", pool->name_prefix);
    
    while (true) {
        v3_mutex_lock(pool->mutex);
        
        // 等待任务或关闭信号
        while (pool->queue_size == 0 && !pool->shutdown) {
            v3_cond_wait(pool->not_empty, pool->mutex);
        }
        
        // 如果被唤醒是为了关闭且队列已空，则退出
        if (pool->shutdown && pool->queue_size == 0) {
            v3_mutex_unlock(pool->mutex);
            break;
        }
        
        // 取出任务
        v3_task_t task = pool->queue[pool->queue_head];
        pool->queue_head = (pool->queue_head + 1) % pool->queue_capacity;
        pool->queue_size--;
        pool->active_count++;
        
        // 通知队列有空位
        v3_cond_signal(pool->not_full);
        
        v3_mutex_unlock(pool->mutex);
        
        // 执行任务
        if (task.func) {
            task.func(task.arg);
        }
        
        // 更新统计
        v3_mutex_lock(pool->mutex);
        pool->active_count--;
        pool->tasks_completed++;
        v3_mutex_unlock(pool->mutex);
    }
    
    V3_LOG_DEBUG("Worker thread for pool '%s' exiting.", pool->name_prefix);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* =========================================================
 * 线程池 API
 * ========================================================= */

v3_error_t v3_thread_pool_create(const v3_thread_pool_config_t *config, v3_thread_pool_t **pool_out) {
    if (!pool_out || !config) return V3_ERR_INVALID_PARAM;
    
    v3_thread_pool_t *pool = (v3_thread_pool_t*)v3_calloc(1, sizeof(v3_thread_pool_t));
    if (!pool) return V3_ERR_MEM_ALLOC_FAILED;

    pool->thread_count = (config->max_threads > 0) ? config->max_threads : v3_cpu_count();
    pool->queue_capacity = (config->queue_size > 0) ? config->queue_size : TASK_QUEUE_INITIAL_SIZE;
    
    if (config->name_prefix) {
        strncpy(pool->name_prefix, config->name_prefix, sizeof(pool->name_prefix) - 1);
    } else {
        strcpy(pool->name_prefix, "v3_pool");
    }

    // 分配任务队列
    pool->queue = (v3_task_t*)v3_calloc(pool->queue_capacity, sizeof(v3_task_t));
    if (!pool->queue) {
        v3_free(pool);
        return V3_ERR_MEM_ALLOC_FAILED;
    }
    
    // 分配线程数组
#ifdef _WIN32
    pool->threads = (HANDLE*)v3_calloc(pool->thread_count, sizeof(HANDLE));
#else
    pool->threads = (pthread_t*)v3_calloc(pool->thread_count, sizeof(pthread_t));
#endif
    if (!pool->threads) {
        v3_free(pool->queue);
        v3_free(pool);
        return V3_ERR_MEM_ALLOC_FAILED;
    }
    
    // 初始化同步原语
    pool->mutex = v3_mutex_create();
    pool->not_empty = v3_cond_create();
    pool->not_full = v3_cond_create();
    if (!pool->mutex || !pool->not_empty || !pool->not_full) {
        if(pool->mutex) v3_mutex_destroy(pool->mutex);
        if(pool->not_empty) v3_cond_destroy(pool->not_empty);
        if(pool->not_full) v3_cond_destroy(pool->not_full);
        v3_free(pool->threads);
        v3_free(pool->queue);
        v3_free(pool);
        return V3_ERR_SYS_MUTEX_CREATE;
    }
    
    pool->running = true;
    pool->shutdown = false;
    
    // 创建工作线程
    for (u32 i = 0; i < pool->thread_count; i++) {
#ifdef _WIN32
        pool->threads[i] = (HANDLE)_beginthreadex(NULL, 0, worker_thread_func, pool, 0, NULL);
        if (!pool->threads[i]) {
            V3_LOG_ERROR("Failed to create worker thread %u for pool '%s'", i, pool->name_prefix);
        }
#else
        if (pthread_create(&pool->threads[i], NULL, worker_thread_func, pool) != 0) {
            V3_LOG_ERROR("Failed to create worker thread %u for pool '%s'", i, pool->name_prefix);
        }
#endif
    }
    
    V3_LOG_INFO("Thread pool '%s' created with %u threads.", pool->name_prefix, pool->thread_count);
    *pool_out = pool;
    return V3_OK;
}

void v3_thread_pool_destroy(v3_thread_pool_t *pool, bool wait_pending) {
    if (!pool) return;
    
    V3_LOG_INFO("Destroying thread pool '%s'...", pool->name_prefix);
    
    v3_mutex_lock(pool->mutex);
    if (!pool->running) {
        v3_mutex_unlock(pool->mutex);
        return;
    }
    
    // 如果不等待，清空队列
    if (!wait_pending) {
        pool->queue_size = 0;
        pool->queue_head = 0;
        pool->queue_tail = 0;
    }

    pool->shutdown = true;
    pool->running = false;
    v3_cond_broadcast(pool->not_empty);
    v3_mutex_unlock(pool->mutex);
    
    // 等待所有线程结束
    for (u32 i = 0; i < pool->thread_count; i++) {
#ifdef _WIN32
        if (pool->threads[i]) {
            WaitForSingleObject(pool->threads[i], INFINITE);
            CloseHandle(pool->threads[i]);
        }
#else
        if (pool->threads[i]) {
            pthread_join(pool->threads[i], NULL);
        }
#endif
    }
    
    V3_LOG_DEBUG("Thread pool stats for '%s': submitted=%llu, completed=%llu",
                 pool->name_prefix, (unsigned long long)pool->tasks_submitted, (unsigned long long)pool->tasks_completed);
    
    // 清理资源
    v3_mutex_destroy(pool->mutex);
    v3_cond_destroy(pool->not_empty);
    v3_cond_destroy(pool->not_full);
    
    v3_free(pool->threads);
    v3_free(pool->queue);
    v3_free(pool);
}

void v3_thread_pool_default_config(v3_thread_pool_config_t *config) {
    if (!config) return;
    config->min_threads = 1;
    config->max_threads = v3_cpu_count();
    config->queue_size = TASK_QUEUE_INITIAL_SIZE;
    config->idle_timeout_ms = 60000;
    config->name_prefix = "default_pool";
}

v3_error_t v3_thread_pool_submit(v3_thread_pool_t *pool, v3_task_fn fn, void *arg) {
    if (!pool || !fn) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(pool->mutex);
    
    if (pool->shutdown) {
        v3_mutex_unlock(pool->mutex);
        return V3_ERR_INVALID_STATE;
    }
    
    // 等待队列有空位
    while (pool->queue_size >= pool->queue_capacity) {
        v3_cond_wait(pool->not_full, pool->mutex);
    }
    
    // 添加任务
    pool->queue[pool->queue_tail].func = fn;
    pool->queue[pool->queue_tail].arg = arg;
    
    pool->queue_tail = (pool->queue_tail + 1) % pool->queue_capacity;
    pool->queue_size++;
    pool->tasks_submitted++;
    
    // 通知等待的工作线程
    v3_cond_signal(pool->not_empty);
    
    v3_mutex_unlock(pool->mutex);
    
    return V3_OK;
}

v3_error_t v3_thread_pool_try_submit(v3_thread_pool_t *pool, v3_task_fn fn, void *arg) {
    if (!pool || !fn) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(pool->mutex);
    
    if (pool->shutdown) {
        v3_mutex_unlock(pool->mutex);
        return V3_ERR_INVALID_STATE;
    }
    
    if (pool->queue_size >= pool->queue_capacity) {
        v3_mutex_unlock(pool->mutex);
        return V3_ERR_BUFFER_FULL;
    }
    
    // 添加任务
    pool->queue[pool->queue_tail].func = fn;
    pool->queue[pool->queue_tail].arg = arg;
    
    pool->queue_tail = (pool->queue_tail + 1) % pool->queue_capacity;
    pool->queue_size++;
    pool->tasks_submitted++;
    
    // 通知等待的工作线程
    v3_cond_signal(pool->not_empty);
    
    v3_mutex_unlock(pool->mutex);
    
    return V3_OK;
}

u32 v3_thread_pool_pending(v3_thread_pool_t *pool) {
    if (!pool) return 0;
    
    v3_mutex_lock(pool->mutex);
    u32 pending = pool->queue_size;
    v3_mutex_unlock(pool->mutex);
    
    return pending;
}

u32 v3_thread_pool_active(v3_thread_pool_t *pool) {
    if (!pool) return 0;
    
    v3_mutex_lock(pool->mutex);
    u32 active = pool->active_count;
    v3_mutex_unlock(pool->mutex);
    
    return active;
}

v3_error_t v3_thread_pool_wait(v3_thread_pool_t *pool, u32 timeout_ms) {
    if (!pool) return V3_ERR_INVALID_PARAM;
    
    u64 start_time = v3_time_ms();
    while (true) {
        v3_mutex_lock(pool->mutex);
        bool idle = (pool->queue_size == 0 && pool->active_count == 0);
        v3_mutex_unlock(pool->mutex);
        
        if (idle) {
            return V3_OK;
        }
        
        if (timeout_ms > 0 && (v3_time_ms() - start_time) > timeout_ms) {
            return V3_ERR_TIMEOUT;
        }
        
        v3_sleep_ms(10);
    }
}
