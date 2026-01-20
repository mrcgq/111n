
/**
 * @file v3_lifecycle.c
 * @brief v3 Core - 生命周期管理
 * 
 * 实现 v3 Core 的启动、停止、重载等生命周期事件管理
 */

#include "v3_lifecycle.h"
#include "v3_platform.h"
#include "v3_log.h"
#include "v3_exit.h"

#include <stdlib.h>
#include <string.h>

/* =========================================================
 * 内部数据结构
 * ========================================================= */

/* 钩子节点 */
typedef struct hook_node_s {
    v3_lifecycle_hook_fn    fn;
    void                   *user_data;
    v3_hook_priority_t      priority;
    struct hook_node_s     *next;
} hook_node_t;

/* 健康检查节点 */
typedef struct health_check_node_s {
    char                        name[64];
    v3_health_check_fn          fn;
    void                       *user_data;
    struct health_check_node_s *next;
} health_check_node_t;

/* 生命周期管理器 */
typedef struct {
    volatile bool               initialized;
    volatile v3_lifecycle_phase_t current_phase;
    
    /* 钩子列表（每个阶段一个链表）*/
    hook_node_t                *hooks[V3_PHASE_MAX];
    v3_mutex_t                 *hooks_mutex;
    
    /* 健康检查 */
    health_check_node_t        *health_checks;
    v3_mutex_t                 *health_mutex;
    
    /* 时间记录 */
    u64                         start_time_ns;
    u64                         start_time_unix;
} lifecycle_manager_t;

static lifecycle_manager_t g_lifecycle = {0};

/* =========================================================
 * 初始化/关闭
 * ========================================================= */

v3_error_t v3_lifecycle_init(void) {
    if (g_lifecycle.initialized) {
        return V3_OK;
    }
    
    memset(&g_lifecycle, 0, sizeof(g_lifecycle));
    
    g_lifecycle.hooks_mutex = v3_mutex_create();
    if (!g_lifecycle.hooks_mutex) {
        return V3_ERR_SYS_MUTEX_CREATE;
    }
    
    g_lifecycle.health_mutex = v3_mutex_create();
    if (!g_lifecycle.health_mutex) {
        v3_mutex_destroy(g_lifecycle.hooks_mutex);
        return V3_ERR_SYS_MUTEX_CREATE;
    }
    
    g_lifecycle.current_phase = V3_PHASE_NONE;
    g_lifecycle.initialized = true;
    
    V3_LOG_DEBUG("Lifecycle manager initialized");
    return V3_OK;
}

void v3_lifecycle_shutdown(void) {
    if (!g_lifecycle.initialized) {
        return;
    }
    
    /* 释放钩子 */
    v3_mutex_lock(g_lifecycle.hooks_mutex);
    for (int i = 0; i < V3_PHASE_MAX; i++) {
        hook_node_t *node = g_lifecycle.hooks[i];
        while (node) {
            hook_node_t *next = node->next;
            v3_free(node);
            node = next;
        }
        g_lifecycle.hooks[i] = NULL;
    }
    v3_mutex_unlock(g_lifecycle.hooks_mutex);
    
    /* 释放健康检查 */
    v3_mutex_lock(g_lifecycle.health_mutex);
    health_check_node_t *hc = g_lifecycle.health_checks;
    while (hc) {
        health_check_node_t *next = hc->next;
        v3_free(hc);
        hc = next;
    }
    g_lifecycle.health_checks = NULL;
    v3_mutex_unlock(g_lifecycle.health_mutex);
    
    /* 释放互斥锁 */
    v3_mutex_destroy(g_lifecycle.hooks_mutex);
    v3_mutex_destroy(g_lifecycle.health_mutex);
    
    g_lifecycle.initialized = false;
    
    V3_LOG_DEBUG("Lifecycle manager shutdown");
}

/* =========================================================
 * 阶段管理
 * ========================================================= */

v3_lifecycle_phase_t v3_lifecycle_get_phase(void) {
    return g_lifecycle.current_phase;
}

const char* v3_lifecycle_phase_str(v3_lifecycle_phase_t phase) {
    switch (phase) {
        case V3_PHASE_NONE:             return "None";
        case V3_PHASE_PRE_INIT:         return "PreInit";
        case V3_PHASE_INIT:             return "Init";
        case V3_PHASE_POST_INIT:        return "PostInit";
        case V3_PHASE_PRE_START:        return "PreStart";
        case V3_PHASE_START:            return "Start";
        case V3_PHASE_POST_START:       return "PostStart";
        case V3_PHASE_RUNNING:          return "Running";
        case V3_PHASE_PRE_STOP:         return "PreStop";
        case V3_PHASE_STOP:             return "Stop";
        case V3_PHASE_POST_STOP:        return "PostStop";
        case V3_PHASE_PRE_SHUTDOWN:     return "PreShutdown";
        case V3_PHASE_SHUTDOWN:         return "Shutdown";
        case V3_PHASE_POST_SHUTDOWN:    return "PostShutdown";
        case V3_PHASE_PRE_RELOAD:       return "PreReload";
        case V3_PHASE_RELOAD:           return "Reload";
        case V3_PHASE_POST_RELOAD:      return "PostReload";
        default:                        return "Unknown";
    }
}

/* =========================================================
 * 钩子管理
 * ========================================================= */

v3_error_t v3_lifecycle_register_hook(
    v3_lifecycle_phase_t phase,
    v3_lifecycle_hook_fn fn,
    void *user_data,
    v3_hook_priority_t priority,
    v3_lifecycle_hook_t **hook_out
) {
    if (!fn || phase >= V3_PHASE_MAX) {
        return V3_ERR_INVALID_PARAM;
    }
    
    hook_node_t *node = (hook_node_t*)v3_calloc(1, sizeof(hook_node_t));
    if (!node) {
        return V3_ERR_MEM_ALLOC_FAILED;
    }
    
    node->fn = fn;
    node->user_data = user_data;
    node->priority = priority;
    
    v3_mutex_lock(g_lifecycle.hooks_mutex);
    
    /* 按优先级插入 */
    hook_node_t **pp = &g_lifecycle.hooks[phase];
    while (*pp && (*pp)->priority <= priority) {
        pp = &(*pp)->next;
    }
    node->next = *pp;
    *pp = node;
    
    v3_mutex_unlock(g_lifecycle.hooks_mutex);
    
    if (hook_out) {
        *hook_out = (v3_lifecycle_hook_t*)node;
    }
    
    V3_LOG_TRACE("Registered lifecycle hook for phase %s at priority %d",
                 v3_lifecycle_phase_str(phase), priority);
    
    return V3_OK;
}

v3_error_t v3_lifecycle_unregister_hook(v3_lifecycle_hook_t *hook) {
    if (!hook) {
        return V3_ERR_INVALID_PARAM;
    }
    
    hook_node_t *target = (hook_node_t*)hook;
    
    v3_mutex_lock(g_lifecycle.hooks_mutex);
    
    for (int i = 0; i < V3_PHASE_MAX; i++) {
        hook_node_t **pp = &g_lifecycle.hooks[i];
        while (*pp) {
            if (*pp == target) {
                *pp = target->next;
                v3_free(target);
                v3_mutex_unlock(g_lifecycle.hooks_mutex);
                return V3_OK;
            }
            pp = &(*pp)->next;
        }
    }
    
    v3_mutex_unlock(g_lifecycle.hooks_mutex);
    return V3_ERR_NOT_FOUND;
}

/* 执行指定阶段的所有钩子 */
static v3_error_t run_phase_hooks(v3_lifecycle_phase_t phase) {
    v3_mutex_lock(g_lifecycle.hooks_mutex);
    
    hook_node_t *node = g_lifecycle.hooks[phase];
    v3_error_t result = V3_OK;
    
    while (node) {
        V3_LOG_TRACE("Calling hook for phase %s (priority %d)",
                     v3_lifecycle_phase_str(phase), node->priority);
        
        v3_error_t err = node->fn(phase, node->user_data);
        if (V3_IS_ERROR(err)) {
            V3_LOG_ERROR("Hook failed for phase %s: %s",
                         v3_lifecycle_phase_str(phase), v3_error_str(err));
            result = err;
            /* 继续执行其他钩子，但记录错误 */
        }
        
        node = node->next;
    }
    
    v3_mutex_unlock(g_lifecycle.hooks_mutex);
    return result;
}

/* =========================================================
 * 阶段转换
 * ========================================================= */

v3_error_t v3_lifecycle_transition(v3_lifecycle_phase_t target_phase) {
    v3_lifecycle_phase_t old_phase = g_lifecycle.current_phase;
    
    V3_LOG_INFO("Lifecycle transition: %s -> %s",
                v3_lifecycle_phase_str(old_phase),
                v3_lifecycle_phase_str(target_phase));
    
    g_lifecycle.current_phase = target_phase;
    
    v3_error_t err = run_phase_hooks(target_phase);
    
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("Phase %s completed with errors", 
                    v3_lifecycle_phase_str(target_phase));
    }
    
    return err;
}

/* =========================================================
 * 完整生命周期序列
 * ========================================================= */

v3_error_t v3_lifecycle_startup(void) {
    v3_error_t err;
    
    V3_LOG_INFO("Starting lifecycle startup sequence...");
    
    /* 记录启动时间 */
    g_lifecycle.start_time_ns = v3_time_ns();
    g_lifecycle.start_time_unix = v3_time_unix();
    
    /* PreInit */
    err = v3_lifecycle_transition(V3_PHASE_PRE_INIT);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("PreInit phase failed");
        return err;
    }
    
    /* Init */
    err = v3_lifecycle_transition(V3_PHASE_INIT);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Init phase failed");
        return err;
    }
    
    /* PostInit */
    err = v3_lifecycle_transition(V3_PHASE_POST_INIT);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("PostInit phase failed");
        return err;
    }
    
    /* PreStart */
    err = v3_lifecycle_transition(V3_PHASE_PRE_START);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("PreStart phase failed");
        return err;
    }
    
    /* Start */
    err = v3_lifecycle_transition(V3_PHASE_START);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Start phase failed");
        return err;
    }
    
    /* PostStart */
    err = v3_lifecycle_transition(V3_PHASE_POST_START);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("PostStart phase failed");
        return err;
    }
    
    /* Running */
    err = v3_lifecycle_transition(V3_PHASE_RUNNING);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Running phase failed");
        return err;
    }
    
    V3_LOG_INFO("Lifecycle startup sequence completed");
    return V3_OK;
}

v3_error_t v3_lifecycle_stop(void) {
    v3_error_t err;
    
    V3_LOG_INFO("Starting lifecycle stop sequence...");
    
    /* PreStop */
    err = v3_lifecycle_transition(V3_PHASE_PRE_STOP);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("PreStop phase had errors");
    }
    
    /* Stop */
    err = v3_lifecycle_transition(V3_PHASE_STOP);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("Stop phase had errors");
    }
    
    /* PostStop */
    err = v3_lifecycle_transition(V3_PHASE_POST_STOP);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("PostStop phase had errors");
    }
    
    V3_LOG_INFO("Lifecycle stop sequence completed");
    return V3_OK;
}

v3_error_t v3_lifecycle_shutdown_full(void) {
    v3_error_t err;
    
    V3_LOG_INFO("Starting lifecycle shutdown sequence...");
    
    /* 如果还在运行，先停止 */
    if (g_lifecycle.current_phase == V3_PHASE_RUNNING) {
        v3_lifecycle_stop();
    }
    
    /* PreShutdown */
    err = v3_lifecycle_transition(V3_PHASE_PRE_SHUTDOWN);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("PreShutdown phase had errors");
    }
    
    /* Shutdown */
    err = v3_lifecycle_transition(V3_PHASE_SHUTDOWN);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("Shutdown phase had errors");
    }
    
    /* PostShutdown */
    err = v3_lifecycle_transition(V3_PHASE_POST_SHUTDOWN);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("PostShutdown phase had errors");
    }
    
    V3_LOG_INFO("Lifecycle shutdown sequence completed");
    return V3_OK;
}

v3_error_t v3_lifecycle_reload(void) {
    v3_error_t err;
    
    V3_LOG_INFO("Starting lifecycle reload sequence...");
    
    /* PreReload */
    err = v3_lifecycle_transition(V3_PHASE_PRE_RELOAD);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("PreReload phase failed");
        return err;
    }
    
    /* Reload */
    err = v3_lifecycle_transition(V3_PHASE_RELOAD);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Reload phase failed");
        return err;
    }
    
    /* PostReload */
    err = v3_lifecycle_transition(V3_PHASE_POST_RELOAD);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("PostReload phase failed");
        return err;
    }
    
    /* 回到运行状态 */
    g_lifecycle.current_phase = V3_PHASE_RUNNING;
    
    V3_LOG_INFO("Lifecycle reload sequence completed");
    return V3_OK;
}

/* =========================================================
 * 状态查询
 * ========================================================= */

bool v3_lifecycle_is_running(void) {
    return g_lifecycle.current_phase == V3_PHASE_RUNNING;
}

bool v3_lifecycle_is_stopping(void) {
    v3_lifecycle_phase_t phase = g_lifecycle.current_phase;
    return phase == V3_PHASE_PRE_STOP ||
           phase == V3_PHASE_STOP ||
           phase == V3_PHASE_POST_STOP ||
           phase == V3_PHASE_PRE_SHUTDOWN ||
           phase == V3_PHASE_SHUTDOWN ||
           phase == V3_PHASE_POST_SHUTDOWN;
}

bool v3_lifecycle_is_initialized(void) {
    return g_lifecycle.current_phase >= V3_PHASE_POST_INIT;
}

u64 v3_lifecycle_uptime_sec(void) {
    if (g_lifecycle.start_time_ns == 0) {
        return 0;
    }
    return (v3_time_ns() - g_lifecycle.start_time_ns) / 1000000000ULL;
}

u64 v3_lifecycle_start_time(void) {
    return g_lifecycle.start_time_unix;
}

/* =========================================================
 * 健康检查
 * ========================================================= */

v3_error_t v3_lifecycle_register_health_check(
    const char *name,
    v3_health_check_fn fn,
    void *user_data
) {
    if (!name || !fn) {
        return V3_ERR_INVALID_PARAM;
    }
    
    health_check_node_t *node = (health_check_node_t*)v3_calloc(1, sizeof(health_check_node_t));
    if (!node) {
        return V3_ERR_MEM_ALLOC_FAILED;
    }
    
    strncpy(node->name, name, sizeof(node->name) - 1);
    node->fn = fn;
    node->user_data = user_data;
    
    v3_mutex_lock(g_lifecycle.health_mutex);
    node->next = g_lifecycle.health_checks;
    g_lifecycle.health_checks = node;
    v3_mutex_unlock(g_lifecycle.health_mutex);
    
    V3_LOG_DEBUG("Registered health check: %s", name);
    return V3_OK;
}

v3_error_t v3_lifecycle_check_health(void) {
    v3_mutex_lock(g_lifecycle.health_mutex);
    
    health_check_node_t *node = g_lifecycle.health_checks;
    v3_error_t result = V3_OK;
    int passed = 0, failed = 0;
    
    while (node) {
        v3_error_t err = node->fn(node->user_data);
        if (V3_IS_ERROR(err)) {
            V3_LOG_WARN("Health check failed: %s (%s)", node->name, v3_error_str(err));
            result = err;
            failed++;
        } else {
            passed++;
        }
        node = node->next;
    }
    
    v3_mutex_unlock(g_lifecycle.health_mutex);
    
    V3_LOG_DEBUG("Health check complete: %d passed, %d failed", passed, failed);
    return result;
}

