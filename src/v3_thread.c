
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
    v3_thread_task_func func;
    void               *arg;
    v3_thread_task_cb   callback;
    void               *callback_arg;
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
    size_t              thread_count;
    
    /* 任务队列 */
    v3_task_t          *queue;
    size_t              queue_capacity;
    size_t              queue_size;
    size_t              queue_head;
    size_t              queue_tail;
    
    /* 同步 */
    v3_mutex_t          mutex;
    v3_cond_t           not_empty;
    v3_cond_t           not_full;
    
    /* 状态 */
    volatile bool       running;
    volatile bool       shutdown;
    volatile size_t     active_count;
    
    /* 统计 */
    uint64_t            tasks_submitted;
    uint64_t            tasks_completed;
    
    /* 名称 */
    char                name[32];
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
    
    V3_LOG_DEBUG("Worker thread started: pool=%s", pool->name);
    
    while (1) {
        v3_mutex_lock(&pool->mutex);
        
        /* 等待任务 */
        while (pool->queue_size == 0 && !pool->shutdown) {
            v3_cond_wait(&pool->not_empty, &pool->mutex);
        }
        
        /* 检查关闭标志 */
        if (pool->shutdown && pool->queue_size == 0) {
            v3_mutex_unlock(&pool->mutex);
            break;
        }
        
        /* 取出任务 */
        v3_task_t task = pool->queue[pool->queue_head];
        pool->queue_head = (pool->queue_head + 1) % pool->queue_capacity;
        pool->queue_size--;
        pool->active_count++;
        
        /* 通知队列有空位 */
        v3_cond_signal(&pool->not_full);
        
        v3_mutex_unlock(&pool->mutex);
        
        /* 执行任务 */
        void *result = NULL;
        if (task.func) {
            result = task.func(task.arg);
        }
        
        /* 调用回调 */
        if (task.callback) {
            task.callback(result, task.callback_arg);
        }
        
        /* 更新统计 */
        v3_mutex_lock(&pool->mutex);
        pool->active_count--;
        pool->tasks_completed++;
        v3_mutex_unlock(&pool->mutex);
    }
    
    V3_LOG_DEBUG("Worker thread exiting: pool=%s", pool->name);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* =========================================================
 * 线程池 API
 * ========================================================= */

v3_thread_pool_t* v3_thread_pool_create(const char *name, size_t thread_count) {
    if (thread_count == 0) {
        /* 自动检测 CPU 核心数 */
#ifdef _WIN32
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        thread_count = si.dwNumberOfProcessors;
#else
        thread_count = sysconf(_SC_NPROCESSORS_ONLN);
#endif
        if (thread_count == 0) thread_count = 4;
    }
    
    v3_thread_pool_t *pool = (v3_thread_pool_t*)calloc(1, sizeof(v3_thread_pool_t));
    if (!pool) return NULL;
    
    /* 初始化名称 */
    if (name) {
        strncpy(pool->name, name, sizeof(pool->name) - 1);
    } else {
        snprintf(pool->name, sizeof(pool->name), "pool_%p", (void*)pool);
    }
    
    /* 分配任务队列 */
    pool->queue_capacity = TASK_QUEUE_INITIAL_SIZE;
    pool->queue = (v3_task_t*)calloc(pool->queue_capacity, sizeof(v3_task_t));
    if (!pool->queue) {
        free(pool);
        return NULL;
    }
    
    /* 分配线程数组 */
#ifdef _WIN32
    pool->threads = (HANDLE*)calloc(thread_count, sizeof(HANDLE));
#else
    pool->threads = (pthread_t*)calloc(thread_count, sizeof(pthread_t));
#endif
    if (!pool->threads) {
        free(pool->queue);
        free(pool);
        return NULL;
    }
    
    pool->thread_count = thread_count;
    
    /* 初始化同步原语 */
    v3_mutex_init(&pool->mutex);
    v3_cond_init(&pool->not_empty);
    v3_cond_init(&pool->not_full);
    
    pool->running = true;
    pool->shutdown = false;
    
    /* 创建工作线程 */
    for (size_t i = 0; i < thread_count; i++) {
#ifdef _WIN32
        pool->threads[i] = (HANDLE)_beginthreadex(
            NULL, 0, worker_thread_func, pool, 0, NULL);
        if (!pool->threads[i]) {
            V3_LOG_ERROR("Failed to create worker thread %zu", i);
        }
#else
        if (pthread_create(&pool->threads[i], NULL, worker_thread_func, pool) != 0) {
            V3_LOG_ERROR("Failed to create worker thread %zu", i);
        }
#endif
    }
    
    V3_LOG_INFO("Thread pool created: name=%s, threads=%zu", pool->name, thread_count);
    
    return pool;
}

void v3_thread_pool_destroy(v3_thread_pool_t *pool) {
    if (!pool) return;
    
    V3_LOG_INFO("Destroying thread pool: %s", pool->name);
    
    /* 设置关闭标志 */
    v3_mutex_lock(&pool->mutex);
    pool->shutdown = true;
    pool->running = false;
    v3_cond_broadcast(&pool->not_empty);  /* 唤醒所有等待的线程 */
    v3_mutex_unlock(&pool->mutex);
    
    /* 等待所有线程结束 */
    for (size_t i = 0; i < pool->thread_count; i++) {
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
    
    V3_LOG_DEBUG("Thread pool stats: submitted=%lu, completed=%lu",
                 (unsigned long)pool->tasks_submitted,
                 (unsigned long)pool->tasks_completed);
    
    /* 清理资源 */
    v3_mutex_destroy(&pool->mutex);
    v3_cond_destroy(&pool->not_empty);
    v3_cond_destroy(&pool->not_full);
    
    free(pool->threads);
    free(pool->queue);
    free(pool);
}

v3_error_t v3_thread_pool_submit(v3_thread_pool_t *pool, 
                                  v3_thread_task_func func, 
                                  void *arg) {
    return v3_thread_pool_submit_with_callback(pool, func, arg, NULL, NULL);
}

v3_error_t v3_thread_pool_submit_with_callback(v3_thread_pool_t *pool,
                                                v3_thread_task_func func,
                                                void *arg,
                                                v3_thread_task_cb callback,
                                                void *callback_arg) {
    if (!pool || !func) return V3_ERR_INVALID_PARAM;
    if (!pool->running) return V3_ERR_THREAD_POOL_SHUTDOWN;
    
    v3_mutex_lock(&pool->mutex);
    
    /* 队列已满，尝试扩展 */
    if (pool->queue_size >= pool->queue_capacity) {
        if (pool->queue_capacity >= TASK_QUEUE_MAX_SIZE) {
            v3_mutex_unlock(&pool->mutex);
            return V3_ERR_QUEUE_FULL;
        }
        
        /* 扩展队列 */
        size_t new_capacity = pool->queue_capacity * 2;
        if (new_capacity > TASK_QUEUE_MAX_SIZE) {
            new_capacity = TASK_QUEUE_MAX_SIZE;
        }
        
        v3_task_t *new_queue = (v3_task_t*)calloc(new_capacity, sizeof(v3_task_t));
        if (!new_queue) {
            v3_mutex_unlock(&pool->mutex);
            return V3_ERR_NO_MEMORY;
        }
        
        /* 复制任务（处理环形队列） */
        for (size_t i = 0; i < pool->queue_size; i++) {
            size_t idx = (pool->queue_head + i) % pool->queue_capacity;
            new_queue[i] = pool->queue[idx];
        }
        
        free(pool->queue);
        pool->queue = new_queue;
        pool->queue_capacity = new_capacity;
        pool->queue_head = 0;
        pool->queue_tail = pool->queue_size;
        
        V3_LOG_DEBUG("Task queue expanded: new_capacity=%zu", new_capacity);
    }
    
    /* 添加任务 */
    pool->queue[pool->queue_tail].func = func;
    pool->queue[pool->queue_tail].arg = arg;
    pool->queue[pool->queue_tail].callback = callback;
    pool->queue[pool->queue_tail].callback_arg = callback_arg;
    
    pool->queue_tail = (pool->queue_tail + 1) % pool->queue_capacity;
    pool->queue_size++;
    pool->tasks_submitted++;
    
    /* 通知等待的工作线程 */
    v3_cond_signal(&pool->not_empty);
    
    v3_mutex_unlock(&pool->mutex);
    
    return V3_OK;
}

void v3_thread_pool_wait(v3_thread_pool_t *pool) {
    if (!pool) return;
    
    while (1) {
        v3_mutex_lock(&pool->mutex);
        bool idle = (pool->queue_size == 0 && pool->active_count == 0);
        v3_mutex_unlock(&pool->mutex);
        
        if (idle) break;
        
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }
}

size_t v3_thread_pool_pending(v3_thread_pool_t *pool) {
    if (!pool) return 0;
    
    v3_mutex_lock(&pool->mutex);
    size_t pending = pool->queue_size;
    v3_mutex_unlock(&pool->mutex);
    
    return pending;
}

size_t v3_thread_pool_active(v3_thread_pool_t *pool) {
    if (!pool) return 0;
    
    v3_mutex_lock(&pool->mutex);
    size_t active = pool->active_count;
    v3_mutex_unlock(&pool->mutex);
    
    return active;
}

void v3_thread_pool_stats(v3_thread_pool_t *pool, v3_thread_pool_stats_t *stats) {
    if (!pool || !stats) return;
    
    v3_mutex_lock(&pool->mutex);
    
    stats->thread_count = pool->thread_count;
    stats->queue_size = pool->queue_size;
    stats->queue_capacity = pool->queue_capacity;
    stats->active_count = pool->active_count;
    stats->tasks_submitted = pool->tasks_submitted;
    stats->tasks_completed = pool->tasks_completed;
    
    v3_mutex_unlock(&pool->mutex);
}

/* =========================================================
 * 平台抽象层实现
 * ========================================================= */

void v3_mutex_init(v3_mutex_t *mutex) {
#ifdef _WIN32
    InitializeCriticalSection(&mutex->cs);
#else
    pthread_mutex_init(&mutex->mutex, NULL);
#endif
}

void v3_mutex_destroy(v3_mutex_t *mutex) {
#ifdef _WIN32
    DeleteCriticalSection(&mutex->cs);
#else
    pthread_mutex_destroy(&mutex->mutex);
#endif
}

void v3_mutex_lock(v3_mutex_t *mutex) {
#ifdef _WIN32
    EnterCriticalSection(&mutex->cs);
#else
    pthread_mutex_lock(&mutex->mutex);
#endif
}

void v3_mutex_unlock(v3_mutex_t *mutex) {
#ifdef _WIN32
    LeaveCriticalSection(&mutex->cs);
#else
    pthread_mutex_unlock(&mutex->mutex);
#endif
}

bool v3_mutex_trylock(v3_mutex_t *mutex) {
#ifdef _WIN32
    return TryEnterCriticalSection(&mutex->cs) != 0;
#else
    return pthread_mutex_trylock(&mutex->mutex) == 0;
#endif
}

void v3_cond_init(v3_cond_t *cond) {
#ifdef _WIN32
    InitializeConditionVariable(&cond->cv);
#else
    pthread_cond_init(&cond->cond, NULL);
#endif
}

void v3_cond_destroy(v3_cond_t *cond) {
#ifdef _WIN32
    /* Windows 条件变量不需要销毁 */
    (void)cond;
#else
    pthread_cond_destroy(&cond->cond);
#endif
}

void v3_cond_wait(v3_cond_t *cond, v3_mutex_t *mutex) {
#ifdef _WIN32
    SleepConditionVariableCS(&cond->cv, &mutex->cs, INFINITE);
#else
    pthread_cond_wait(&cond->cond, &mutex->mutex);
#endif
}

bool v3_cond_timedwait(v3_cond_t *cond, v3_mutex_t *mutex, uint32_t timeout_ms) {
#ifdef _WIN32
    return SleepConditionVariableCS(&cond->cv, &mutex->cs, timeout_ms) != 0;
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }
    return pthread_cond_timedwait(&cond->cond, &mutex->mutex, &ts) == 0;
#endif
}

void v3_cond_signal(v3_cond_t *cond) {
#ifdef _WIN32
    WakeConditionVariable(&cond->cv);
#else
    pthread_cond_signal(&cond->cond);
#endif
}

void v3_cond_broadcast(v3_cond_t *cond) {
#ifdef _WIN32
    WakeAllConditionVariable(&cond->cv);
#else
    pthread_cond_broadcast(&cond->cond);
#endif
}

/* =========================================================
 * 原子操作
 * ========================================================= */

int32_t v3_atomic_inc(volatile int32_t *ptr) {
#ifdef _WIN32
    return InterlockedIncrement((volatile LONG*)ptr);
#else
    return __sync_add_and_fetch(ptr, 1);
#endif
}

int32_t v3_atomic_dec(volatile int32_t *ptr) {
#ifdef _WIN32
    return InterlockedDecrement((volatile LONG*)ptr);
#else
    return __sync_sub_and_fetch(ptr, 1);
#endif
}

int32_t v3_atomic_add(volatile int32_t *ptr, int32_t val) {
#ifdef _WIN32
    return InterlockedExchangeAdd((volatile LONG*)ptr, val) + val;
#else
    return __sync_add_and_fetch(ptr, val);
#endif
}

bool v3_atomic_cas(volatile int32_t *ptr, int32_t expected, int32_t desired) {
#ifdef _WIN32
    return InterlockedCompareExchange((volatile LONG*)ptr, desired, expected) == expected;
#else
    return __sync_bool_compare_and_swap(ptr, expected, desired);
#endif
}
