
/*
 * win_process.c - Windows Process Management
 * 
 * 功能：
 * - 进程创建与终止
 * - 进程信息获取
 * - 句柄管理
 * - 守护进程支持
 * - 单实例检测
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#include "v3_core.h"
#ifdef _WIN32

#include "v3_platform.h"
#include "v3_guard.h"
#include "v3_error.h"
#include "v3_log.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

/* =========================================================
 * 常量定义
 * ========================================================= */

#define V3_MUTEX_PREFIX     "Global\\v3_instance_"
#define V3_MAX_PATH_LEN     32768

/* =========================================================
 * 进程信息结构
 * ========================================================= */

struct v3_process_s {
    HANDLE              handle;
    DWORD               pid;
    HANDLE              job;            /* 作业对象，用于子进程管理 */
    bool                auto_restart;
    char                executable[MAX_PATH];
    char                arguments[V3_MAX_PATH_LEN];
    char                working_dir[MAX_PATH];
};

/* =========================================================
 * 全局状态
 * ========================================================= */

static struct {
    HANDLE  instance_mutex;
    char    instance_name[128];
    bool    is_primary;
} g_instance = {0};

/* =========================================================
 * 单实例管理
 * ========================================================= */

int v3_process_ensure_single(const char *name) {
    char mutex_name[256];
    snprintf(mutex_name, sizeof(mutex_name), "%s%s", V3_MUTEX_PREFIX, name);
    strncpy(g_instance.instance_name, name, sizeof(g_instance.instance_name) - 1);

    /* 创建全局互斥量 */
    g_instance.instance_mutex = CreateMutexA(NULL, TRUE, mutex_name);
    
    if (g_instance.instance_mutex == NULL) {
        V3_LOG_ERROR("CreateMutex failed: %lu", GetLastError());
        return V3_ERR_SYSTEM;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        /* 已有实例运行 */
        CloseHandle(g_instance.instance_mutex);
        g_instance.instance_mutex = NULL;
        g_instance.is_primary = false;
        V3_LOG_WARN("Another instance is already running");
        return V3_ERR_ALREADY_RUNNING;
    }

    g_instance.is_primary = true;
    V3_LOG_INFO("Single instance lock acquired: %s", name);
    return V3_OK;
}

void v3_process_release_single(void) {
    if (g_instance.instance_mutex) {
        ReleaseMutex(g_instance.instance_mutex);
        CloseHandle(g_instance.instance_mutex);
        g_instance.instance_mutex = NULL;
        g_instance.is_primary = false;
        V3_LOG_DEBUG("Single instance lock released");
    }
}

bool v3_process_is_primary(void) {
    return g_instance.is_primary;
}

/* =========================================================
 * 进程创建
 * ========================================================= */

v3_process_t* v3_process_create(const v3_process_config_t *config) {
    if (!config || !config->executable) {
        return NULL;
    }

    v3_process_t *proc = (v3_process_t*)calloc(1, sizeof(v3_process_t));
    if (!proc) {
        return NULL;
    }

    strncpy(proc->executable, config->executable, MAX_PATH - 1);
    if (config->arguments) {
        strncpy(proc->arguments, config->arguments, V3_MAX_PATH_LEN - 1);
    }
    if (config->working_dir) {
        strncpy(proc->working_dir, config->working_dir, MAX_PATH - 1);
    } else {
        GetCurrentDirectoryA(MAX_PATH, proc->working_dir);
    }
    proc->auto_restart = config->auto_restart;

    /* 创建作业对象（用于子进程清理） */
    if (config->use_job_object) {
        proc->job = CreateJobObjectW(NULL, NULL);
        if (proc->job) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_info = {0};
            job_info.BasicLimitInformation.LimitFlags = 
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            
            SetInformationJobObject(proc->job, 
                JobObjectExtendedLimitInformation,
                &job_info, sizeof(job_info));
        }
    }

    return proc;
}

int v3_process_start(v3_process_t *proc) {
    if (!proc) {
        return V3_ERR_INVALID_PARAM;
    }

    /* 构建命令行 */
    char cmdline[V3_MAX_PATH_LEN + MAX_PATH + 2];
    if (proc->arguments[0]) {
        snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", 
                 proc->executable, proc->arguments);
    } else {
        snprintf(cmdline, sizeof(cmdline), "\"%s\"", proc->executable);
    }

    /* 启动进程 */
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    DWORD flags = CREATE_NEW_PROCESS_GROUP;
    
    BOOL result = CreateProcessA(
        NULL,
        cmdline,
        NULL,
        NULL,
        FALSE,
        flags,
        NULL,
        proc->working_dir[0] ? proc->working_dir : NULL,
        &si,
        &pi
    );

    if (!result) {
        V3_LOG_ERROR("CreateProcess failed: %lu", GetLastError());
        return V3_ERR_SYSTEM;
    }

    proc->handle = pi.hProcess;
    proc->pid = pi.dwProcessId;
    CloseHandle(pi.hThread);

    /* 关联到作业对象 */
    if (proc->job) {
        AssignProcessToJobObject(proc->job, proc->handle);
    }

    V3_LOG_INFO("Process started: PID=%lu, exe=%s", proc->pid, proc->executable);
    return V3_OK;
}

int v3_process_stop(v3_process_t *proc, uint32_t timeout_ms) {
    if (!proc || proc->handle == NULL) {
        return V3_ERR_INVALID_PARAM;
    }

    /* 首先尝试优雅关闭 */
    /* 发送 CTRL_BREAK_EVENT */
    GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, proc->pid);

    /* 等待进程退出 */
    DWORD wait_result = WaitForSingleObject(proc->handle, timeout_ms);
    
    if (wait_result == WAIT_TIMEOUT) {
        /* 超时，强制终止 */
        V3_LOG_WARN("Process did not exit gracefully, forcing termination");
        TerminateProcess(proc->handle, 1);
        WaitForSingleObject(proc->handle, 1000);
    }

    V3_LOG_INFO("Process stopped: PID=%lu", proc->pid);
    return V3_OK;
}

void v3_process_destroy(v3_process_t *proc) {
    if (!proc) return;

    if (proc->handle) {
        CloseHandle(proc->handle);
    }
    if (proc->job) {
        CloseHandle(proc->job);
    }

    free(proc);
}

/* =========================================================
 * 进程状态
 * ========================================================= */

bool v3_process_is_running(v3_process_t *proc) {
    if (!proc || !proc->handle) {
        return false;
    }

    DWORD exit_code;
    if (!GetExitCodeProcess(proc->handle, &exit_code)) {
        return false;
    }

    return exit_code == STILL_ACTIVE;
}

int v3_process_get_exit_code(v3_process_t *proc) {
    if (!proc || !proc->handle) {
        return -1;
    }

    DWORD exit_code;
    if (!GetExitCodeProcess(proc->handle, &exit_code)) {
        return -1;
    }

    if (exit_code == STILL_ACTIVE) {
        return -1;
    }

    return (int)exit_code;
}

uint32_t v3_process_get_pid(v3_process_t *proc) {
    return proc ? proc->pid : 0;
}

/* =========================================================
 * 当前进程信息
 * ========================================================= */

uint32_t v3_process_current_pid(void) {
    return GetCurrentProcessId();
}

int v3_process_get_executable(char *buf, size_t len) {
    DWORD result = GetModuleFileNameA(NULL, buf, (DWORD)len);
    if (result == 0 || result >= len) {
        return V3_ERR_SYSTEM;
    }
    return V3_OK;
}

int v3_process_get_directory(char *buf, size_t len) {
    if (v3_process_get_executable(buf, len) != V3_OK) {
        return V3_ERR_SYSTEM;
    }
    
    /* 移除文件名，保留目录 */
    PathRemoveFileSpecA(buf);
    return V3_OK;
}

/* =========================================================
 * 进程枚举
 * ========================================================= */

int v3_process_find_by_name(const char *name, uint32_t *pids, int max_count) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(pe);

    int count = 0;

    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                if (pids && count < max_count) {
                    pids[count] = pe.th32ProcessID;
                }
                count++;
            }
        } while (Process32Next(snapshot, &pe) && count < max_count);
    }

    CloseHandle(snapshot);
    return count;
}

bool v3_process_kill_by_pid(uint32_t pid) {
    HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!proc) {
        return false;
    }

    BOOL result = TerminateProcess(proc, 1);
    CloseHandle(proc);

    return result != 0;
}

/* =========================================================
 * 进程优先级
 * ========================================================= */

int v3_process_set_priority(v3_process_t *proc, v3_process_priority_t priority) {
    HANDLE handle = proc ? proc->handle : GetCurrentProcess();
    
    DWORD win_priority;
    switch (priority) {
        case V3_PRIORITY_LOW:
            win_priority = BELOW_NORMAL_PRIORITY_CLASS;
            break;
        case V3_PRIORITY_NORMAL:
            win_priority = NORMAL_PRIORITY_CLASS;
            break;
        case V3_PRIORITY_HIGH:
            win_priority = HIGH_PRIORITY_CLASS;
            break;
        case V3_PRIORITY_REALTIME:
            win_priority = REALTIME_PRIORITY_CLASS;
            break;
        default:
            return V3_ERR_INVALID_PARAM;
    }

    if (!SetPriorityClass(handle, win_priority)) {
        return V3_ERR_SYSTEM;
    }

    return V3_OK;
}

/* =========================================================
 * 进程亲和性
 * ========================================================= */

int v3_process_set_affinity(v3_process_t *proc, uint64_t mask) {
    HANDLE handle = proc ? proc->handle : GetCurrentProcess();
    
    if (!SetProcessAffinityMask(handle, (DWORD_PTR)mask)) {
        return V3_ERR_SYSTEM;
    }

    return V3_OK;
}

uint64_t v3_process_get_affinity(v3_process_t *proc) {
    HANDLE handle = proc ? proc->handle : GetCurrentProcess();
    
    DWORD_PTR proc_mask, sys_mask;
    if (!GetProcessAffinityMask(handle, &proc_mask, &sys_mask)) {
        return 0;
    }

    return (uint64_t)proc_mask;
}

/* =========================================================
 * 服务相关
 * ========================================================= */

bool v3_process_is_service(void) {
    /* 检查父进程是否为 services.exe */
    DWORD parent_pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {0};
        pe.dwSize = sizeof(pe);
        DWORD current_pid = GetCurrentProcessId();
        
        if (Process32First(snapshot, &pe)) {
            do {
                if (pe.th32ProcessID == current_pid) {
                    parent_pid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }

    if (parent_pid == 0) {
        return false;
    }

    /* 获取父进程名称 */
    HANDLE parent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_pid);
    if (!parent) {
        return false;
    }

    char parent_name[MAX_PATH];
    DWORD size = MAX_PATH;
    bool is_service = false;
    
    if (QueryFullProcessImageNameA(parent, 0, parent_name, &size)) {
        const char *filename = PathFindFileNameA(parent_name);
        is_service = (_stricmp(filename, "services.exe") == 0);
    }

    CloseHandle(parent);
    return is_service;
}

#endif /* _WIN32 */
