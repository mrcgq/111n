
/**
 * @file v3_exit.c
 * @brief v3 Core - 退出与清理
 * 
 * 实现安全的程序退出和资源清理机制
 */

#include "v3_exit.h"
#include "v3_platform.h"
#include "v3_log.h"

#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* =========================================================
 * 内部数据结构
 * ========================================================= */

/* 清理回调节点 */
typedef struct cleanup_node_s {
    v3_cleanup_fn           fn;
    void                   *user_data;
    v3_cleanup_priority_t   priority;
    struct cleanup_node_s  *next;
} cleanup_node_t;

/* 退出管理器状态 */
typedef struct {
    volatile bool           initialized;
    volatile bool           exit_requested;
    volatile bool           restart_requested;
    volatile v3_exit_code_t exit_code;
    volatile v3_exit_reason_t exit_reason;
    char                    exit_message[256];
    
    cleanup_node_t         *cleanup_head;
    v3_mutex_t             *cleanup_mutex;
    
    v3_event_t             *exit_event;
    
    u32                     restart_delay_ms;
} exit_manager_t;

static exit_manager_t g_exit_mgr = {0};

/* =========================================================
 * 信号处理
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
            V3_LOG_INFO("Received CTRL+C, requesting exit...");
            v3_exit_request(V3_EXIT_SIGINT, V3_EXIT_REASON_SIGNAL, "CTRL+C");
            return TRUE;
            
        case CTRL_BREAK_EVENT:
            V3_LOG_INFO("Received CTRL+BREAK, requesting exit...");
            v3_exit_request(V3_EXIT_SIGTERM, V3_EXIT_REASON_SIGNAL, "CTRL+BREAK");
            return TRUE;
            
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            V3_LOG_INFO("Received system shutdown signal, requesting exit...");
            v3_exit_request(V3_EXIT_SIGTERM, V3_EXIT_REASON_SIGNAL, "System Shutdown");
            return TRUE;
    }
    return FALSE;
}

#else

static void signal_handler(int signum) {
    const char *sig_name = "Unknown";
    v3_exit_code_t code = V3_EXIT_SIGNAL + signum;
    
    switch (signum) {
        case SIGINT:
            sig_name = "SIGINT";
            code = V3_EXIT_SIGINT;
            break;
        case SIGTERM:
            sig_name = "SIGTERM";
            code = V3_EXIT_SIGTERM;
            break;
#ifdef SIGHUP
        case SIGHUP:
            sig_name = "SIGHUP";
            /* SIGHUP 可用于重载配置 */
            V3_LOG_INFO("Received SIGHUP, requesting reload...");
            /* 这里可以触发重载而不是退出 */
            return;
#endif
    }
    
    v3_exit_request(code, V3_EXIT_REASON_SIGNAL, sig_name);
}

#endif

/* =========================================================
 * 初始化/关闭
 * ========================================================= */

v3_error_t v3_exit_init(void) {
    if (g_exit_mgr.initialized) {
        return V3_OK;
    }
    
    memset(&g_exit_mgr, 0, sizeof(g_exit_mgr));
    
    /* 创建互斥锁 */
    g_exit_mgr.cleanup_mutex = v3_mutex_create();
    if (!g_exit_mgr.cleanup_mutex) {
        return V3_ERR_SYS_MUTEX_CREATE;
    }
    
    /* 创建退出事件 */
    g_exit_mgr.exit_event = v3_event_create(true, false);
    if (!g_exit_mgr.exit_event) {
        v3_mutex_destroy(g_exit_mgr.cleanup_mutex);
        return V3_ERR_SYS_EVENT_CREATE;
    }
    
    g_exit_mgr.initialized = true;
    
    V3_LOG_DEBUG("Exit manager initialized");
    return V3_OK;
}

void v3_exit_shutdown(void) {
    if (!g_exit_mgr.initialized) {
        return;
    }
    
    /* 释放清理回调链表 */
    v3_mutex_lock(g_exit_mgr.cleanup_mutex);
    cleanup_node_t *node = g_exit_mgr.cleanup_head;
    while (node) {
        cleanup_node_t *next = node->next;
        v3_free(node);
        node = next;
    }
    g_exit_mgr.cleanup_head = NULL;
    v3_mutex_unlock(g_exit_mgr.cleanup_mutex);
    
    /* 释放同步原语 */
    if (g_exit_mgr.exit_event) {
        v3_event_destroy(g_exit_mgr.exit_event);
        g_exit_mgr.exit_event = NULL;
    }
    
    if (g_exit_mgr.cleanup_mutex) {
        v3_mutex_destroy(g_exit_mgr.cleanup_mutex);
        g_exit_mgr.cleanup_mutex = NULL;
    }
    
    g_exit_mgr.initialized = false;
    
    V3_LOG_DEBUG("Exit manager shutdown");
}

/* =========================================================
 * 信号设置
 * ========================================================= */

v3_error_t v3_exit_setup_signals(void) {
#ifdef V3_PLATFORM_WINDOWS
    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        V3_LOG_WARN("Failed to set console control handler");
        return V3_ERR_SYS_SIGNAL;
    }
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        V3_LOG_WARN("Failed to set SIGINT handler");
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        V3_LOG_WARN("Failed to set SIGTERM handler");
    }
#ifdef SIGHUP
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        V3_LOG_WARN("Failed to set SIGHUP handler");
    }
#endif
    
    /* 忽略 SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
#endif
    
    V3_LOG_DEBUG("Signal handlers installed");
    return V3_OK;
}

void v3_exit_block_signals(void) {
#ifndef V3_PLATFORM_WINDOWS
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
#endif
}

void v3_exit_restore_signals(void) {
#ifndef V3_PLATFORM_WINDOWS
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    pthread_sigmask(SIG_UNBLOCK, &mask, NULL);
#endif
}

void v3_exit_raise_signal(int signal_num) {
#ifdef V3_PLATFORM_WINDOWS
    if (signal_num == SIGINT) {
        GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
    }
#else
    raise(signal_num);
#endif
}

/* =========================================================
 * 清理回调管理
 * ========================================================= */

v3_error_t v3_exit_register_cleanup(
    v3_cleanup_fn fn,
    void *user_data,
    v3_cleanup_priority_t priority,
    v3_cleanup_handle_t **handle_out
) {
    if (!fn) {
        return V3_ERR_INVALID_PARAM;
    }
    
    cleanup_node_t *node = (cleanup_node_t*)v3_calloc(1, sizeof(cleanup_node_t));
    if (!node) {
        return V3_ERR_MEM_ALLOC_FAILED;
    }
    
    node->fn = fn;
    node->user_data = user_data;
    node->priority = priority;
    
    v3_mutex_lock(g_exit_mgr.cleanup_mutex);
    
    /* 按优先级插入（升序，低优先级先执行）*/
    cleanup_node_t **pp = &g_exit_mgr.cleanup_head;
    while (*pp && (*pp)->priority <= priority) {
        pp = &(*pp)->next;
    }
    node->next = *pp;
    *pp = node;
    
    v3_mutex_unlock(g_exit_mgr.cleanup_mutex);
    
    if (handle_out) {
        *handle_out = (v3_cleanup_handle_t*)node;
    }
    
    V3_LOG_TRACE("Registered cleanup callback at priority %d", priority);
    return V3_OK;
}

v3_error_t v3_exit_unregister_cleanup(v3_cleanup_handle_t *handle) {
    if (!handle) {
        return V3_ERR_INVALID_PARAM;
    }
    
    cleanup_node_t *target = (cleanup_node_t*)handle;
    
    v3_mutex_lock(g_exit_mgr.cleanup_mutex);
    
    cleanup_node_t **pp = &g_exit_mgr.cleanup_head;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            v3_free(target);
            v3_mutex_unlock(g_exit_mgr.cleanup_mutex);
            return V3_OK;
        }
        pp = &(*pp)->next;
    }
    
    v3_mutex_unlock(g_exit_mgr.cleanup_mutex);
    return V3_ERR_NOT_FOUND;
}

/* =========================================================
 * 退出请求
 * ========================================================= */

void v3_exit_request(
    v3_exit_code_t code,
    v3_exit_reason_t reason,
    const char *message
) {
    /* 只接受第一次请求 */
    if (g_exit_mgr.exit_requested) {
        return;
    }
    
    g_exit_mgr.exit_code = code;
    g_exit_mgr.exit_reason = reason;
    
    if (message) {
        strncpy(g_exit_mgr.exit_message, message, sizeof(g_exit_mgr.exit_message) - 1);
    }
    
    g_exit_mgr.exit_requested = true;
    
    /* 触发退出事件 */
    if (g_exit_mgr.exit_event) {
        v3_event_set(g_exit_mgr.exit_event);
    }
    
    V3_LOG_INFO("Exit requested: code=%d, reason=%s, message=%s",
                code, v3_exit_reason_str(reason), message ? message : "(none)");
}

bool v3_exit_requested(void) {
    return g_exit_mgr.exit_requested;
}

v3_exit_code_t v3_exit_get_code(void) {
    return g_exit_mgr.exit_code;
}

v3_exit_reason_t v3_exit_get_reason(void) {
    return g_exit_mgr.exit_reason;
}

const char* v3_exit_get_message(void) {
    return g_exit_mgr.exit_message[0] ? g_exit_mgr.exit_message : NULL;
}

/* =========================================================
 * 清理执行
 * ========================================================= */

v3_error_t v3_exit_run_cleanup(v3_exit_reason_t reason) {
    V3_LOG_INFO("Running cleanup callbacks...");
    
    v3_mutex_lock(g_exit_mgr.cleanup_mutex);
    
    cleanup_node_t *node = g_exit_mgr.cleanup_head;
    int count = 0;
    
    while (node) {
        V3_LOG_TRACE("Calling cleanup callback %d (priority %d)", count, node->priority);
        
        /* 调用清理函数 */
        node->fn(node->user_data, reason);
        
        count++;
        node = node->next;
    }
    
    v3_mutex_unlock(g_exit_mgr.cleanup_mutex);
    
    V3_LOG_INFO("Executed %d cleanup callbacks", count);
    return V3_OK;
}

/* =========================================================
 * 退出执行
 * ========================================================= */

V3_NORETURN void v3_exit_now(v3_exit_code_t code) {
    if (!g_exit_mgr.exit_requested) {
        v3_exit_request(code, V3_EXIT_REASON_NORMAL, NULL);
    }
    
    /* 运行清理 */
    v3_exit_run_cleanup(g_exit_mgr.exit_reason);
    
    /* 关闭日志 */
    v3_log_flush();
    
    V3_LOG_INFO("Exiting with code %d", code);
    
    exit(code);
}

V3_NORETURN void v3_exit_abort(v3_exit_code_t code) {
    V3_LOG_FATAL("Aborting with code %d", code);
    
#ifdef V3_PLATFORM_WINDOWS
    TerminateProcess(GetCurrentProcess(), code);
#endif
    
    _exit(code);
}

/* =========================================================
 * 等待
 * ========================================================= */

bool v3_exit_wait(u32 timeout_ms) {
    if (!g_exit_mgr.exit_event) {
        return g_exit_mgr.exit_requested;
    }
    
    return v3_event_wait(g_exit_mgr.exit_event, timeout_ms);
}

v3_handle_t v3_exit_get_event(void) {
#ifdef V3_PLATFORM_WINDOWS
    /* Windows 事件可以直接用于 WaitForMultipleObjects */
    return g_exit_mgr.exit_event ? 
           ((v3_handle_t)g_exit_mgr.exit_event) : V3_INVALID_HANDLE;
#else
    return V3_INVALID_HANDLE;
#endif
}

/* =========================================================
 * 重启支持
 * ========================================================= */

void v3_exit_request_restart(u32 delay_ms) {
    g_exit_mgr.restart_requested = true;
    g_exit_mgr.restart_delay_ms = delay_ms;
    v3_exit_request(V3_EXIT_SUCCESS, V3_EXIT_REASON_RESTART, "Restart requested");
}

bool v3_exit_restart_requested(void) {
    return g_exit_mgr.restart_requested;
}

/* =========================================================
 * 调试
 * ========================================================= */

void v3_exit_dump_cleanups(void) {
    v3_mutex_lock(g_exit_mgr.cleanup_mutex);
    
    printf("Registered cleanup callbacks:\n");
    
    cleanup_node_t *node = g_exit_mgr.cleanup_head;
    int i = 0;
    
    while (node) {
        printf("  [%d] priority=%d fn=%p user_data=%p\n",
               i++, node->priority, (void*)node->fn, node->user_data);
        node = node->next;
    }
    
    v3_mutex_unlock(g_exit_mgr.cleanup_mutex);
}

const char* v3_exit_reason_str(v3_exit_reason_t reason) {
    switch (reason) {
        case V3_EXIT_REASON_NONE:           return "None";
        case V3_EXIT_REASON_NORMAL:         return "Normal";
        case V3_EXIT_REASON_USER_REQUEST:   return "User Request";
        case V3_EXIT_REASON_SIGNAL:         return "Signal";
        case V3_EXIT_REASON_ERROR:          return "Error";
        case V3_EXIT_REASON_FATAL:          return "Fatal Error";
        case V3_EXIT_REASON_RESTART:        return "Restart";
        case V3_EXIT_REASON_UPDATE:         return "Update";
        case V3_EXIT_REASON_PARENT_EXIT:    return "Parent Exit";
        case V3_EXIT_REASON_WATCHDOG:       return "Watchdog";
        default:                            return "Unknown";
    }
}

const char* v3_exit_code_str(v3_exit_code_t code) {
    switch (code) {
        case V3_EXIT_SUCCESS:               return "Success";
        case V3_EXIT_ERROR:                 return "Error";
        case V3_EXIT_INVALID_ARGS:          return "Invalid Arguments";
        case V3_EXIT_CONFIG_ERROR:          return "Configuration Error";
        case V3_EXIT_INIT_FAILED:           return "Initialization Failed";
        case V3_EXIT_NETWORK_ERROR:         return "Network Error";
        case V3_EXIT_CRYPTO_ERROR:          return "Crypto Error";
        case V3_EXIT_PERMISSION_DENIED:     return "Permission Denied";
        case V3_EXIT_RESOURCE_EXHAUSTED:    return "Resource Exhausted";
        case V3_EXIT_FATAL_ERROR:           return "Fatal Error";
        case V3_EXIT_SIGINT:                return "SIGINT";
        case V3_EXIT_SIGTERM:               return "SIGTERM";
        default:
            if (code >= V3_EXIT_SIGNAL) {
                return "Signal";
            }
            return "Unknown";
    }
}
