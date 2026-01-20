
/*
 * win_platform.c - Windows Platform Abstraction Layer
 * 
 * 功能：
 * - Windows 平台初始化
 * - 时间函数
 * - 随机数生成
 * - 错误处理
 * - 系统信息
 * - 线程同步原语
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#ifdef _WIN32

#include "v3_platform.h"
#include "v3_error.h"
#include "v3_log.h"

#include <windows.h>
#include <bcrypt.h>
#include <process.h>
#include <psapi.h>
#include <intrin.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

/* =========================================================
 * 全局状态
 * ========================================================= */

static struct {
    bool            initialized;
    LARGE_INTEGER   perf_freq;          /* 高精度计时器频率 */
    LARGE_INTEGER   start_time;         /* 启动时间 */
    DWORD           main_thread_id;     /* 主线程 ID */
    SYSTEM_INFO     sys_info;           /* 系统信息 */
    BCRYPT_ALG_HANDLE rng_handle;       /* 随机数算法句柄 */
    char            os_version[64];     /* 操作系统版本 */
} g_platform = {0};

/* =========================================================
 * 平台初始化
 * ========================================================= */

int v3_platform_init(void) {
    if (g_platform.initialized) {
        return V3_OK;
    }

    /* 获取性能计数器频率 */
    if (!QueryPerformanceFrequency(&g_platform.perf_freq)) {
        V3_LOG_ERROR("QueryPerformanceFrequency failed");
        return V3_ERR_SYSTEM;
    }

    /* 记录启动时间 */
    QueryPerformanceCounter(&g_platform.start_time);

    /* 获取主线程 ID */
    g_platform.main_thread_id = GetCurrentThreadId();

    /* 获取系统信息 */
    GetSystemInfo(&g_platform.sys_info);

    /* 初始化随机数生成器 */
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &g_platform.rng_handle,
        BCRYPT_RNG_ALGORITHM,
        NULL,
        0
    );
    if (!BCRYPT_SUCCESS(status)) {
        V3_LOG_ERROR("BCryptOpenAlgorithmProvider failed: 0x%08X", status);
        return V3_ERR_SYSTEM;
    }

    /* 获取操作系统版本信息 */
    OSVERSIONINFOEXW osvi = {0};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    
    typedef NTSTATUS (WINAPI *RtlGetVersionFunc)(PRTL_OSVERSIONINFOW);
    RtlGetVersionFunc RtlGetVersion = (RtlGetVersionFunc)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    
    if (RtlGetVersion) {
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
        snprintf(g_platform.os_version, sizeof(g_platform.os_version),
                 "Windows %lu.%lu.%lu",
                 osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    } else {
        strcpy(g_platform.os_version, "Windows (unknown version)");
    }

    /* 设置进程优先级 */
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    /* 禁用错误对话框 */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    g_platform.initialized = true;
    V3_LOG_INFO("Platform initialized: %s", g_platform.os_version);

    return V3_OK;
}

void v3_platform_cleanup(void) {
    if (!g_platform.initialized) {
        return;
    }

    if (g_platform.rng_handle) {
        BCryptCloseAlgorithmProvider(g_platform.rng_handle, 0);
        g_platform.rng_handle = NULL;
    }

    g_platform.initialized = false;
    V3_LOG_INFO("Platform cleaned up");
}

/* =========================================================
 * 时间函数
 * ========================================================= */

uint64_t v3_time_ns(void) {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    
    /* 转换为纳秒 */
    return (uint64_t)((counter.QuadPart * 1000000000LL) / g_platform.perf_freq.QuadPart);
}

uint64_t v3_time_us(void) {
    return v3_time_ns() / 1000;
}

uint64_t v3_time_ms(void) {
    return v3_time_ns() / 1000000;
}

uint64_t v3_time_sec(void) {
    return (uint64_t)time(NULL);
}

uint64_t v3_uptime_ms(void) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    
    LONGLONG elapsed = now.QuadPart - g_platform.start_time.QuadPart;
    return (uint64_t)((elapsed * 1000LL) / g_platform.perf_freq.QuadPart);
}

void v3_sleep_ms(uint32_t ms) {
    Sleep(ms);
}

void v3_sleep_us(uint32_t us) {
    /* Windows 没有微秒级 sleep，使用自旋等待 */
    if (us < 1000) {
        /* 微秒级：自旋等待 */
        uint64_t target = v3_time_us() + us;
        while (v3_time_us() < target) {
            YieldProcessor();
        }
    } else {
        /* 毫秒级：使用 Sleep */
        Sleep(us / 1000);
        uint32_t remaining = us % 1000;
        if (remaining > 0) {
            uint64_t target = v3_time_us() + remaining;
            while (v3_time_us() < target) {
                YieldProcessor();
            }
        }
    }
}

/* =========================================================
 * 随机数
 * ========================================================= */

int v3_random_bytes(void *buf, size_t len) {
    if (!g_platform.rng_handle) {
        return V3_ERR_NOT_INITIALIZED;
    }

    NTSTATUS status = BCryptGenRandom(
        g_platform.rng_handle,
        (PUCHAR)buf,
        (ULONG)len,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        return V3_ERR_SYSTEM;
    }

    return V3_OK;
}

uint32_t v3_random_u32(void) {
    uint32_t val;
    if (v3_random_bytes(&val, sizeof(val)) != V3_OK) {
        /* 回退到伪随机 */
        val = (uint32_t)__rdtsc() ^ (uint32_t)GetTickCount64();
    }
    return val;
}

uint64_t v3_random_u64(void) {
    uint64_t val;
    if (v3_random_bytes(&val, sizeof(val)) != V3_OK) {
        val = ((uint64_t)v3_random_u32() << 32) | v3_random_u32();
    }
    return val;
}

/* =========================================================
 * 互斥锁
 * ========================================================= */

int v3_mutex_init(v3_mutex_t *mutex) {
    if (!mutex) return V3_ERR_INVALID_PARAM;
    
    InitializeCriticalSectionAndSpinCount((CRITICAL_SECTION*)mutex->opaque, 4000);
    return V3_OK;
}

void v3_mutex_destroy(v3_mutex_t *mutex) {
    if (!mutex) return;
    DeleteCriticalSection((CRITICAL_SECTION*)mutex->opaque);
}

void v3_mutex_lock(v3_mutex_t *mutex) {
    if (!mutex) return;
    EnterCriticalSection((CRITICAL_SECTION*)mutex->opaque);
}

bool v3_mutex_trylock(v3_mutex_t *mutex) {
    if (!mutex) return false;
    return TryEnterCriticalSection((CRITICAL_SECTION*)mutex->opaque) != 0;
}

void v3_mutex_unlock(v3_mutex_t *mutex) {
    if (!mutex) return;
    LeaveCriticalSection((CRITICAL_SECTION*)mutex->opaque);
}

/* =========================================================
 * 读写锁
 * ========================================================= */

int v3_rwlock_init(v3_rwlock_t *rwlock) {
    if (!rwlock) return V3_ERR_INVALID_PARAM;
    InitializeSRWLock((SRWLOCK*)rwlock->opaque);
    return V3_OK;
}

void v3_rwlock_destroy(v3_rwlock_t *rwlock) {
    /* SRWLock 不需要销毁 */
    (void)rwlock;
}

void v3_rwlock_rdlock(v3_rwlock_t *rwlock) {
    if (!rwlock) return;
    AcquireSRWLockShared((SRWLOCK*)rwlock->opaque);
}

void v3_rwlock_wrlock(v3_rwlock_t *rwlock) {
    if (!rwlock) return;
    AcquireSRWLockExclusive((SRWLOCK*)rwlock->opaque);
}

void v3_rwlock_rdunlock(v3_rwlock_t *rwlock) {
    if (!rwlock) return;
    ReleaseSRWLockShared((SRWLOCK*)rwlock->opaque);
}

void v3_rwlock_wrunlock(v3_rwlock_t *rwlock) {
    if (!rwlock) return;
    ReleaseSRWLockExclusive((SRWLOCK*)rwlock->opaque);
}

/* =========================================================
 * 条件变量
 * ========================================================= */

int v3_cond_init(v3_cond_t *cond) {
    if (!cond) return V3_ERR_INVALID_PARAM;
    InitializeConditionVariable((CONDITION_VARIABLE*)cond->opaque);
    return V3_OK;
}

void v3_cond_destroy(v3_cond_t *cond) {
    /* Windows 条件变量不需要销毁 */
    (void)cond;
}

void v3_cond_signal(v3_cond_t *cond) {
    if (!cond) return;
    WakeConditionVariable((CONDITION_VARIABLE*)cond->opaque);
}

void v3_cond_broadcast(v3_cond_t *cond) {
    if (!cond) return;
    WakeAllConditionVariable((CONDITION_VARIABLE*)cond->opaque);
}

int v3_cond_wait(v3_cond_t *cond, v3_mutex_t *mutex) {
    if (!cond || !mutex) return V3_ERR_INVALID_PARAM;
    
    BOOL result = SleepConditionVariableCS(
        (CONDITION_VARIABLE*)cond->opaque,
        (CRITICAL_SECTION*)mutex->opaque,
        INFINITE
    );
    
    return result ? V3_OK : V3_ERR_SYSTEM;
}

int v3_cond_timedwait(v3_cond_t *cond, v3_mutex_t *mutex, uint32_t timeout_ms) {
    if (!cond || !mutex) return V3_ERR_INVALID_PARAM;
    
    BOOL result = SleepConditionVariableCS(
        (CONDITION_VARIABLE*)cond->opaque,
        (CRITICAL_SECTION*)mutex->opaque,
        timeout_ms
    );
    
    if (!result) {
        if (GetLastError() == ERROR_TIMEOUT) {
            return V3_ERR_TIMEOUT;
        }
        return V3_ERR_SYSTEM;
    }
    
    return V3_OK;
}

/* =========================================================
 * 原子操作
 * ========================================================= */

int32_t v3_atomic_add32(volatile int32_t *ptr, int32_t val) {
    return InterlockedAdd((volatile LONG*)ptr, val);
}

int64_t v3_atomic_add64(volatile int64_t *ptr, int64_t val) {
    return InterlockedAdd64((volatile LONG64*)ptr, val);
}

int32_t v3_atomic_load32(volatile int32_t *ptr) {
    return InterlockedCompareExchange((volatile LONG*)ptr, 0, 0);
}

int64_t v3_atomic_load64(volatile int64_t *ptr) {
    return InterlockedCompareExchange64((volatile LONG64*)ptr, 0, 0);
}

void v3_atomic_store32(volatile int32_t *ptr, int32_t val) {
    InterlockedExchange((volatile LONG*)ptr, val);
}

void v3_atomic_store64(volatile int64_t *ptr, int64_t val) {
    InterlockedExchange64((volatile LONG64*)ptr, val);
}

bool v3_atomic_cas32(volatile int32_t *ptr, int32_t expected, int32_t desired) {
    return InterlockedCompareExchange((volatile LONG*)ptr, desired, expected) == expected;
}

bool v3_atomic_cas64(volatile int64_t *ptr, int64_t expected, int64_t desired) {
    return InterlockedCompareExchange64((volatile LONG64*)ptr, desired, expected) == expected;
}

/* =========================================================
 * 系统信息
 * ========================================================= */

uint32_t v3_cpu_count(void) {
    return g_platform.sys_info.dwNumberOfProcessors;
}

uint64_t v3_memory_total(void) {
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    return mem.ullTotalPhys;
}

uint64_t v3_memory_available(void) {
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    return mem.ullAvailPhys;
}

uint64_t v3_memory_usage(void) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

const char* v3_os_version(void) {
    return g_platform.os_version;
}

const char* v3_hostname(void) {
    static char hostname[256] = {0};
    if (hostname[0] == '\0') {
        DWORD len = sizeof(hostname);
        GetComputerNameExA(ComputerNameDnsHostname, hostname, &len);
    }
    return hostname;
}

/* =========================================================
 * 错误处理
 * ========================================================= */

int v3_last_error(void) {
    return (int)GetLastError();
}

const char* v3_error_string(int err) {
    static __thread char buf[512];
    
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buf,
        sizeof(buf),
        NULL
    );
    
    /* 去除尾部换行 */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
        buf[--len] = '\0';
    }
    
    return buf;
}

/* =========================================================
 * CPU 特性检测
 * ========================================================= */

bool v3_cpu_has_feature(v3_cpu_feature_t feature) {
    int cpu_info[4];
    
    switch (feature) {
        case V3_CPU_SSE2:
            __cpuid(cpu_info, 1);
            return (cpu_info[3] & (1 << 26)) != 0;
            
        case V3_CPU_SSE42:
            __cpuid(cpu_info, 1);
            return (cpu_info[2] & (1 << 20)) != 0;
            
        case V3_CPU_AVX:
            __cpuid(cpu_info, 1);
            return (cpu_info[2] & (1 << 28)) != 0;
            
        case V3_CPU_AVX2:
            __cpuidex(cpu_info, 7, 0);
            return (cpu_info[1] & (1 << 5)) != 0;
            
        case V3_CPU_AVX512:
            __cpuidex(cpu_info, 7, 0);
            return (cpu_info[1] & (1 << 16)) != 0;
            
        case V3_CPU_AES_NI:
            __cpuid(cpu_info, 1);
            return (cpu_info[2] & (1 << 25)) != 0;
            
        default:
            return false;
    }
}

#endif /* _WIN32 */
