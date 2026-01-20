
#define _CRT_SECURE_NO_WARNINGS
#include "v3_guard.h"
#include "v3_log.h"
#include "v3_config.h"
#include "v3_platform.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#endif

/* =========================================================
 * 守护进程配置
 * ========================================================= */

#define GUARD_HEARTBEAT_INTERVAL_MS     5000
#define GUARD_HEARTBEAT_TIMEOUT_MS      15000
#define GUARD_DEFAULT_RESTART_DELAY_SEC 3
#define GUARD_MAX_RAPID_RESTARTS        5
#define GUARD_RAPID_RESTART_WINDOW_SEC  60

/* =========================================================
 * 守护进程状态
 * ========================================================= */

typedef enum {
    GUARD_STATE_IDLE,
    GUARD_STATE_STARTING,
    GUARD_STATE_RUNNING,
    GUARD_STATE_STOPPING,
    GUARD_STATE_CRASHED,
    GUARD_STATE_RESTARTING,
} guard_state_t;

struct v3_guard_s {
    guard_state_t       state;
    bool                running;
    bool                auto_restart;
    
    /* 进程信息 */
#ifdef _WIN32
    HANDLE              process;
    HANDLE              thread;
    DWORD               process_id;
    HANDLE              guard_thread;
#else
    pid_t               child_pid;
    pthread_t           guard_thread;
#endif
    
    /* 重启控制 */
    int                 restart_count;
    int                 max_restarts;
    int                 restart_delay_sec;
    time_t              restart_times[GUARD_MAX_RAPID_RESTARTS];
    int                 restart_time_idx;
    
    /* 心跳 */
    uint64_t            last_heartbeat_ns;
    bool                heartbeat_enabled;
    
    /* 回调 */
    v3_guard_callback_t callback;
    void               *callback_arg;
    
    /* 启动参数 */
    char                exec_path[V3_MAX_PATH];
    char              **argv;
    int                 argc;
    
    /* 同步 */
    v3_mutex_t          mutex;
    v3_cond_t           cond;
};

/* =========================================================
 * 辅助函数
 * ========================================================= */

static inline uint64_t guard_get_time_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000ULL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

static bool guard_check_rapid_restarts(v3_guard_t *guard) {
    time_t now = time(NULL);
    int count = 0;
    
    for (int i = 0; i < GUARD_MAX_RAPID_RESTARTS; i++) {
        if (guard->restart_times[i] > 0 &&
            now - guard->restart_times[i] < GUARD_RAPID_RESTART_WINDOW_SEC) {
            count++;
        }
    }
    
    return count >= GUARD_MAX_RAPID_RESTARTS;
}

static void guard_record_restart(v3_guard_t *guard) {
    guard->restart_times[guard->restart_time_idx] = time(NULL);
    guard->restart_time_idx = (guard->restart_time_idx + 1) % GUARD_MAX_RAPID_RESTARTS;
}

/* =========================================================
 * 进程管理 - Windows
 * ========================================================= */

#ifdef _WIN32

static v3_error_t guard_spawn_process_win(v3_guard_t *guard) {
    /* 构建命令行 */
    char cmdline[4096];
    int pos = 0;
    
    pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, "\"%s\"", guard->exec_path);
    
    for (int i = 1; i < guard->argc && guard->argv[i]; i++) {
        pos += snprintf(cmdline + pos, sizeof(cmdline) - pos, " \"%s\"", guard->argv[i]);
    }
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    
    if (!CreateProcessA(
            guard->exec_path,
            cmdline,
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_PROCESS_GROUP,
            NULL,
            NULL,
            &si,
            &pi)) {
        V3_LOG_ERROR("Failed to create process: %lu", GetLastError());
        return V3_ERR_PROCESS_SPAWN;
    }
    
    guard->process = pi.hProcess;
    guard->thread = pi.hThread;
    guard->process_id = pi.dwProcessId;
    
    V3_LOG_INFO("Process spawned: PID=%lu", guard->process_id);
    
    return V3_OK;
}

static bool guard_is_process_running_win(v3_guard_t *guard) {
    if (guard->process == NULL) return false;
    
    DWORD exit_code;
    if (!GetExitCodeProcess(guard->process, &exit_code)) {
        return false;
    }
    
    return exit_code == STILL_ACTIVE;
}

static int guard_get_exit_code_win(v3_guard_t *guard) {
    DWORD exit_code = 0;
    if (guard->process) {
        GetExitCodeProcess(guard->process, &exit_code);
    }
    return (int)exit_code;
}

static void guard_terminate_process_win(v3_guard_t *guard) {
    if (guard->process) {
        TerminateProcess(guard->process, 1);
        WaitForSingleObject(guard->process, 5000);
        CloseHandle(guard->process);
        guard->process = NULL;
    }
    if (guard->thread) {
        CloseHandle(guard->thread);
        guard->thread = NULL;
    }
}

static DWORD WINAPI guard_monitor_thread_win(LPVOID arg) {
    v3_guard_t *guard = (v3_guard_t*)arg;
    
    V3_LOG_INFO("Guard monitor thread started");
    
    while (guard->running) {
        v3_mutex_lock(&guard->mutex);
        
        if (guard->state == GUARD_STATE_RUNNING) {
            /* 检查进程状态 */
            if (!guard_is_process_running_win(guard)) {
                int exit_code = guard_get_exit_code_win(guard);
                
                V3_LOG_WARN("Process exited with code: %d", exit_code);
                
                if (guard->callback) {
                    guard->callback(V3_GUARD_EVENT_CRASHED, exit_code, guard->callback_arg);
                }
                
                if (guard->auto_restart && guard->restart_count < guard->max_restarts) {
                    if (guard_check_rapid_restarts(guard)) {
                        V3_LOG_ERROR("Too many rapid restarts, giving up");
                        guard->state = GUARD_STATE_CRASHED;
                        if (guard->callback) {
                            guard->callback(V3_GUARD_EVENT_FATAL, exit_code, guard->callback_arg);
                        }
                    } else {
                        guard->state = GUARD_STATE_RESTARTING;
                        guard->restart_count++;
                        guard_record_restart(guard);
                        
                        V3_LOG_INFO("Restarting in %d seconds... (attempt %d/%d)",
                                   guard->restart_delay_sec, guard->restart_count, guard->max_restarts);
                        
                        v3_mutex_unlock(&guard->mutex);
                        Sleep(guard->restart_delay_sec * 1000);
                        v3_mutex_lock(&guard->mutex);
                        
                        if (guard->running) {
                            if (guard_spawn_process_win(guard) == V3_OK) {
                                guard->state = GUARD_STATE_RUNNING;
                                if (guard->callback) {
                                    guard->callback(V3_GUARD_EVENT_RESTARTED, 0, guard->callback_arg);
                                }
                            } else {
                                guard->state = GUARD_STATE_CRASHED;
                            }
                        }
                    }
                } else {
                    guard->state = GUARD_STATE_CRASHED;
                }
            }
            
            /* 心跳检查 */
            if (guard->heartbeat_enabled && guard->state == GUARD_STATE_RUNNING) {
                uint64_t now = guard_get_time_ns();
                uint64_t elapsed = now - guard->last_heartbeat_ns;
                
                if (elapsed > GUARD_HEARTBEAT_TIMEOUT_MS * 1000000ULL) {
                    V3_LOG_WARN("Heartbeat timeout, process may be hung");
                    if (guard->callback) {
                        guard->callback(V3_GUARD_EVENT_TIMEOUT, 0, guard->callback_arg);
                    }
                }
            }
        }
        
        v3_mutex_unlock(&guard->mutex);
        Sleep(1000);  /* 每秒检查一次 */
    }
    
    V3_LOG_INFO("Guard monitor thread stopped");
    return 0;
}

#else

/* =========================================================
 * 进程管理 - Unix
 * ========================================================= */

static v3_error_t guard_spawn_process_unix(v3_guard_t *guard) {
    pid_t pid = fork();
    
    if (pid < 0) {
        V3_LOG_ERROR("Fork failed: %s", strerror(errno));
        return V3_ERR_PROCESS_SPAWN;
    }
    
    if (pid == 0) {
        /* 子进程 */
        
        /* 创建新会话 */
        setsid();
        
        /* 执行目标程序 */
        execv(guard->exec_path, guard->argv);
        
        /* exec 失败 */
        fprintf(stderr, "Failed to exec: %s\n", strerror(errno));
        _exit(127);
    }
    
    /* 父进程 */
    guard->child_pid = pid;
    
    V3_LOG_INFO("Process spawned: PID=%d", pid);
    
    return V3_OK;
}

static bool guard_is_process_running_unix(v3_guard_t *guard) {
    if (guard->child_pid <= 0) return false;
    
    int status;
    pid_t result = waitpid(guard->child_pid, &status, WNOHANG);
    
    if (result == 0) {
        return true;  /* 还在运行 */
    }
    
    return false;
}

static int guard_get_exit_code_unix(v3_guard_t *guard) {
    int status;
    pid_t result = waitpid(guard->child_pid, &status, WNOHANG);
    
    if (result > 0) {
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        }
    }
    
    return -1;
}

static void guard_terminate_process_unix(v3_guard_t *guard) {
    if (guard->child_pid > 0) {
        kill(guard->child_pid, SIGTERM);
        
        /* 等待 5 秒 */
        for (int i = 0; i < 50; i++) {
            if (waitpid(guard->child_pid, NULL, WNOHANG) > 0) {
                guard->child_pid = 0;
                return;
            }
            usleep(100000);
        }
        
        /* 强制杀死 */
        kill(guard->child_pid, SIGKILL);
        waitpid(guard->child_pid, NULL, 0);
        guard->child_pid = 0;
    }
}

static void* guard_monitor_thread_unix(void *arg) {
    v3_guard_t *guard = (v3_guard_t*)arg;
    
    V3_LOG_INFO("Guard monitor thread started");
    
    while (guard->running) {
        v3_mutex_lock(&guard->mutex);
        
        if (guard->state == GUARD_STATE_RUNNING) {
            int status;
            pid_t result = waitpid(guard->child_pid, &status, WNOHANG);
            
            if (result > 0) {
                /* 进程已退出 */
                int exit_code = 0;
                if (WIFEXITED(status)) {
                    exit_code = WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    exit_code = 128 + WTERMSIG(status);
                }
                
                V3_LOG_WARN("Process exited with code: %d", exit_code);
                guard->child_pid = 0;
                
                if (guard->callback) {
                    guard->callback(V3_GUARD_EVENT_CRASHED, exit_code, guard->callback_arg);
                }
                
                if (guard->auto_restart && guard->restart_count < guard->max_restarts) {
                    if (guard_check_rapid_restarts(guard)) {
                        V3_LOG_ERROR("Too many rapid restarts, giving up");
                        guard->state = GUARD_STATE_CRASHED;
                        if (guard->callback) {
                            guard->callback(V3_GUARD_EVENT_FATAL, exit_code, guard->callback_arg);
                        }
                    } else {
                        guard->state = GUARD_STATE_RESTARTING;
                        guard->restart_count++;
                        guard_record_restart(guard);
                        
                        V3_LOG_INFO("Restarting in %d seconds... (attempt %d/%d)",
                                   guard->restart_delay_sec, guard->restart_count, guard->max_restarts);
                        
                        v3_mutex_unlock(&guard->mutex);
                        sleep(guard->restart_delay_sec);
                        v3_mutex_lock(&guard->mutex);
                        
                        if (guard->running) {
                            if (guard_spawn_process_unix(guard) == V3_OK) {
                                guard->state = GUARD_STATE_RUNNING;
                                if (guard->callback) {
                                    guard->callback(V3_GUARD_EVENT_RESTARTED, 0, guard->callback_arg);
                                }
                            } else {
                                guard->state = GUARD_STATE_CRASHED;
                            }
                        }
                    }
                } else {
                    guard->state = GUARD_STATE_CRASHED;
                }
            }
            
            /* 心跳检查 */
            if (guard->heartbeat_enabled && guard->state == GUARD_STATE_RUNNING) {
                uint64_t now = guard_get_time_ns();
                uint64_t elapsed = now - guard->last_heartbeat_ns;
                
                if (elapsed > GUARD_HEARTBEAT_TIMEOUT_MS * 1000000ULL) {
                    V3_LOG_WARN("Heartbeat timeout, process may be hung");
                    if (guard->callback) {
                        guard->callback(V3_GUARD_EVENT_TIMEOUT, 0, guard->callback_arg);
                    }
                }
            }
        }
        
        v3_mutex_unlock(&guard->mutex);
        sleep(1);
    }
    
    V3_LOG_INFO("Guard monitor thread stopped");
    return NULL;
}

#endif

/* =========================================================
 * 公共 API
 * ========================================================= */

v3_guard_t* v3_guard_create(const char *exec_path, char **argv, int argc) {
    if (!exec_path) return NULL;
    
    v3_guard_t *guard = (v3_guard_t*)calloc(1, sizeof(v3_guard_t));
    if (!guard) return NULL;
    
    guard->state = GUARD_STATE_IDLE;
    guard->running = false;
    guard->auto_restart = true;
    guard->restart_count = 0;
    guard->max_restarts = 10;
    guard->restart_delay_sec = GUARD_DEFAULT_RESTART_DELAY_SEC;
    guard->heartbeat_enabled = false;
    
    strncpy(guard->exec_path, exec_path, sizeof(guard->exec_path) - 1);
    
    /* 复制参数 */
    if (argv && argc > 0) {
        guard->argc = argc;
        guard->argv = (char**)calloc(argc + 1, sizeof(char*));
        if (guard->argv) {
            for (int i = 0; i < argc; i++) {
                if (argv[i]) {
                    guard->argv[i] = strdup(argv[i]);
                }
            }
        }
    }
    
#ifdef _WIN32
    guard->process = NULL;
    guard->thread = NULL;
#else
    guard->child_pid = 0;
#endif
    
    v3_mutex_init(&guard->mutex);
    v3_cond_init(&guard->cond);
    
    return guard;
}

void v3_guard_destroy(v3_guard_t *guard) {
    if (!guard) return;
    
    v3_guard_stop(guard);
    
    if (guard->argv) {
        for (int i = 0; i < guard->argc; i++) {
            free(guard->argv[i]);
        }
        free(guard->argv);
    }
    
    v3_mutex_destroy(&guard->mutex);
    v3_cond_destroy(&guard->cond);
    
    free(guard);
}

v3_error_t v3_guard_start(v3_guard_t *guard) {
    if (!guard) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(&guard->mutex);
    
    if (guard->running) {
        v3_mutex_unlock(&guard->mutex);
        return V3_OK;
    }
    
    guard->state = GUARD_STATE_STARTING;
    guard->restart_count = 0;
    
    /* 启动子进程 */
    v3_error_t err;
#ifdef _WIN32
    err = guard_spawn_process_win(guard);
#else
    err = guard_spawn_process_unix(guard);
#endif
    
    if (err != V3_OK) {
        guard->state = GUARD_STATE_CRASHED;
        v3_mutex_unlock(&guard->mutex);
        return err;
    }
    
    guard->state = GUARD_STATE_RUNNING;
    guard->running = true;
    guard->last_heartbeat_ns = guard_get_time_ns();
    
    /* 启动监控线程 */
#ifdef _WIN32
    guard->guard_thread = CreateThread(NULL, 0, guard_monitor_thread_win, guard, 0, NULL);
    if (!guard->guard_thread) {
        guard->running = false;
        v3_mutex_unlock(&guard->mutex);
        return V3_ERR_THREAD_CREATE;
    }
#else
    if (pthread_create(&guard->guard_thread, NULL, guard_monitor_thread_unix, guard) != 0) {
        guard->running = false;
        v3_mutex_unlock(&guard->mutex);
        return V3_ERR_THREAD_CREATE;
    }
#endif
    
    if (guard->callback) {
        guard->callback(V3_GUARD_EVENT_STARTED, 0, guard->callback_arg);
    }
    
    v3_mutex_unlock(&guard->mutex);
    return V3_OK;
}

void v3_guard_stop(v3_guard_t *guard) {
    if (!guard) return;
    
    v3_mutex_lock(&guard->mutex);
    
    if (!guard->running) {
        v3_mutex_unlock(&guard->mutex);
        return;
    }
    
    guard->running = false;
    guard->state = GUARD_STATE_STOPPING;
    
    v3_mutex_unlock(&guard->mutex);
    
    /* 等待监控线程结束 */
#ifdef _WIN32
    if (guard->guard_thread) {
        WaitForSingleObject(guard->guard_thread, 5000);
        CloseHandle(guard->guard_thread);
        guard->guard_thread = NULL;
    }
    
    guard_terminate_process_win(guard);
#else
    pthread_join(guard->guard_thread, NULL);
    guard_terminate_process_unix(guard);
#endif
    
    guard->state = GUARD_STATE_IDLE;
    
    if (guard->callback) {
        guard->callback(V3_GUARD_EVENT_STOPPED, 0, guard->callback_arg);
    }
}

void v3_guard_set_callback(v3_guard_t *guard, v3_guard_callback_t callback, void *arg) {
    if (!guard) return;
    guard->callback = callback;
    guard->callback_arg = arg;
}

void v3_guard_set_auto_restart(v3_guard_t *guard, bool enabled, int max_restarts, int delay_sec) {
    if (!guard) return;
    
    v3_mutex_lock(&guard->mutex);
    guard->auto_restart = enabled;
    if (max_restarts > 0) guard->max_restarts = max_restarts;
    if (delay_sec > 0) guard->restart_delay_sec = delay_sec;
    v3_mutex_unlock(&guard->mutex);
}

void v3_guard_heartbeat(v3_guard_t *guard) {
    if (!guard) return;
    
    v3_mutex_lock(&guard->mutex);
    guard->last_heartbeat_ns = guard_get_time_ns();
    v3_mutex_unlock(&guard->mutex);
}

void v3_guard_enable_heartbeat(v3_guard_t *guard, bool enabled) {
    if (!guard) return;
    
    v3_mutex_lock(&guard->mutex);
    guard->heartbeat_enabled = enabled;
    if (enabled) {
        guard->last_heartbeat_ns = guard_get_time_ns();
    }
    v3_mutex_unlock(&guard->mutex);
}

bool v3_guard_is_running(v3_guard_t *guard) {
    if (!guard) return false;
    
    v3_mutex_lock(&guard->mutex);
    bool running = guard->running && guard->state == GUARD_STATE_RUNNING;
    v3_mutex_unlock(&guard->mutex);
    
    return running;
}

int v3_guard_get_restart_count(v3_guard_t *guard) {
    if (!guard) return 0;
    return guard->restart_count;
}
