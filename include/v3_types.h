/**
 * @file v3_types.h
 * @brief v3 Core - 基础类型定义
 * 
 * 提供跨平台的类型定义，确保 Windows/Linux 兼容性
 * 与服务端 v3_portable.c, v3_fec_simd.h 等保持一致
 */

#ifndef V3_TYPES_H
#define V3_TYPES_H

/* =========================================================
 * 平台检测
 * ========================================================= */

#if defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__) || defined(__MINGW64__)
    #define V3_PLATFORM_WINDOWS 1
    #define V3_PLATFORM_NAME    "Windows"
#elif defined(__linux__)
    #define V3_PLATFORM_LINUX   1
    #define V3_PLATFORM_NAME    "Linux"
#elif defined(__APPLE__)
    #define V3_PLATFORM_MACOS   1
    #define V3_PLATFORM_NAME    "macOS"
#else
    #define V3_PLATFORM_UNKNOWN 1
    #define V3_PLATFORM_NAME    "Unknown"
#endif

/* 架构检测 */
#if defined(_M_X64) || defined(__x86_64__) || defined(__amd64__)
    #define V3_ARCH_X64         1
    #define V3_ARCH_NAME        "x86_64"
#elif defined(_M_IX86) || defined(__i386__)
    #define V3_ARCH_X86         1
    #define V3_ARCH_NAME        "x86"
#elif defined(_M_ARM64) || defined(__aarch64__)
    #define V3_ARCH_ARM64       1
    #define V3_ARCH_NAME        "ARM64"
#elif defined(_M_ARM) || defined(__arm__)
    #define V3_ARCH_ARM         1
    #define V3_ARCH_NAME        "ARM"
#else
    #define V3_ARCH_UNKNOWN     1
    #define V3_ARCH_NAME        "Unknown"
#endif

/* =========================================================
 * 编译器检测
 * ========================================================= */

#if defined(_MSC_VER)
    #define V3_COMPILER_MSVC    1
    #define V3_COMPILER_NAME    "MSVC"
    #define V3_COMPILER_VERSION _MSC_VER
#elif defined(__GNUC__)
    #define V3_COMPILER_GCC     1
    #define V3_COMPILER_NAME    "GCC"
    #define V3_COMPILER_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#elif defined(__clang__)
    #define V3_COMPILER_CLANG   1
    #define V3_COMPILER_NAME    "Clang"
    #define V3_COMPILER_VERSION (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#else
    #define V3_COMPILER_UNKNOWN 1
    #define V3_COMPILER_NAME    "Unknown"
    #define V3_COMPILER_VERSION 0
#endif

/* =========================================================
 * 固定宽度整数类型
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS
    #include <windows.h>
    
    /* Windows 下使用标准 stdint 或自定义 */
    #if defined(_MSC_VER) && (_MSC_VER < 1600)
        /* MSVC 2010 之前没有 stdint.h */
        typedef signed __int8      int8_t;
        typedef unsigned __int8    uint8_t;
        typedef signed __int16     int16_t;
        typedef unsigned __int16   uint16_t;
        typedef signed __int32     int32_t;
        typedef unsigned __int32   uint32_t;
        typedef signed __int64     int64_t;
        typedef unsigned __int64   uint64_t;
        
        typedef int64_t            intptr_t;
        typedef uint64_t           uintptr_t;
        typedef int64_t            ssize_t;
        
        #define INT8_MIN           (-127 - 1)
        #define INT8_MAX           127
        #define UINT8_MAX          255
        #define INT16_MIN          (-32767 - 1)
        #define INT16_MAX          32767
        #define UINT16_MAX         65535
        #define INT32_MIN          (-2147483647 - 1)
        #define INT32_MAX          2147483647
        #define UINT32_MAX         0xFFFFFFFFU
        #define INT64_MIN          (-9223372036854775807LL - 1)
        #define INT64_MAX          9223372036854775807LL
        #define UINT64_MAX         0xFFFFFFFFFFFFFFFFULL
    #else
        #include <stdint.h>
    #endif
    
    #include <stddef.h>
    
#else
    /* POSIX 系统 */
    #include <stdint.h>
    #include <stddef.h>
    #include <sys/types.h>
#endif

/* stdbool.h */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
    #include <stdbool.h>
#else
    #ifndef __cplusplus
        typedef int bool;
        #define true  1
        #define false 0
    #endif
#endif

/* =========================================================
 * 基础类型别名（与服务端一致）
 * ========================================================= */

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

typedef int8_t      s8;
typedef int16_t     s16;
typedef int32_t     s32;
typedef int64_t     s64;

typedef float       f32;
typedef double      f64;

typedef size_t      usize;
typedef ptrdiff_t   isize;

/* =========================================================
 * 句柄类型
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS
    typedef HANDLE      v3_handle_t;
    typedef SOCKET      v3_socket_t;
    typedef DWORD       v3_pid_t;
    typedef DWORD       v3_tid_t;
    
    #define V3_INVALID_HANDLE   INVALID_HANDLE_VALUE
    #define V3_INVALID_SOCKET   INVALID_SOCKET
#else
    typedef int         v3_handle_t;
    typedef int         v3_socket_t;
    typedef pid_t       v3_pid_t;
    typedef pthread_t   v3_tid_t;
    
    #define V3_INVALID_HANDLE   (-1)
    #define V3_INVALID_SOCKET   (-1)
#endif

/* =========================================================
 * 函数属性宏
 * ========================================================= */

/* 内联 */
#if defined(V3_COMPILER_MSVC)
    #define V3_INLINE           __forceinline
    #define V3_NOINLINE         __declspec(noinline)
#elif defined(V3_COMPILER_GCC) || defined(V3_COMPILER_CLANG)
    #define V3_INLINE           static inline __attribute__((always_inline))
    #define V3_NOINLINE         __attribute__((noinline))
#else
    #define V3_INLINE           static inline
    #define V3_NOINLINE
#endif

/* 导出/导入 */
#ifdef V3_PLATFORM_WINDOWS
    #ifdef V3_BUILDING_DLL
        #define V3_API          __declspec(dllexport)
    #elif defined(V3_USING_DLL)
        #define V3_API          __declspec(dllimport)
    #else
        #define V3_API
    #endif
#else
    #if defined(V3_COMPILER_GCC) || defined(V3_COMPILER_CLANG)
        #define V3_API          __attribute__((visibility("default")))
    #else
        #define V3_API
    #endif
#endif

/* 调用约定 */
#ifdef V3_PLATFORM_WINDOWS
    #define V3_CALL             __cdecl
    #define V3_CALLBACK         __stdcall
#else
    #define V3_CALL
    #define V3_CALLBACK
#endif

/* 未使用参数 */
#define V3_UNUSED(x)            ((void)(x))

/* 编译器提示 */
#if defined(V3_COMPILER_GCC) || defined(V3_COMPILER_CLANG)
    #define V3_LIKELY(x)        __builtin_expect(!!(x), 1)
    #define V3_UNLIKELY(x)      __builtin_expect(!!(x), 0)
    #define V3_DEPRECATED       __attribute__((deprecated))
    #define V3_NORETURN         __attribute__((noreturn))
    #define V3_PRINTF_FMT(f,a)  __attribute__((format(printf, f, a)))
    #define V3_ALIGNED(n)       __attribute__((aligned(n)))
    #define V3_PACKED           __attribute__((packed))
#elif defined(V3_COMPILER_MSVC)
    #define V3_LIKELY(x)        (x)
    #define V3_UNLIKELY(x)      (x)
    #define V3_DEPRECATED       __declspec(deprecated)
    #define V3_NORETURN         __declspec(noreturn)
    #define V3_PRINTF_FMT(f,a)
    #define V3_ALIGNED(n)       __declspec(align(n))
    #define V3_PACKED
    #pragma warning(disable: 4996)  /* 禁用弃用警告 */
#else
    #define V3_LIKELY(x)        (x)
    #define V3_UNLIKELY(x)      (x)
    #define V3_DEPRECATED
    #define V3_NORETURN
    #define V3_PRINTF_FMT(f,a)
    #define V3_ALIGNED(n)
    #define V3_PACKED
#endif

/* =========================================================
 * 结构体打包（跨平台）
 * ========================================================= */

#ifdef V3_COMPILER_MSVC
    #define V3_PACK_BEGIN       __pragma(pack(push, 1))
    #define V3_PACK_END         __pragma(pack(pop))
    #define V3_PACK_STRUCT
#else
    #define V3_PACK_BEGIN
    #define V3_PACK_END
    #define V3_PACK_STRUCT      __attribute__((packed))
#endif

/* =========================================================
 * 常用宏
 * ========================================================= */

/* 数组长度 */
#define V3_ARRAY_SIZE(arr)      (sizeof(arr) / sizeof((arr)[0]))

/* 最大/最小值 */
#ifndef V3_MAX
    #define V3_MAX(a, b)        (((a) > (b)) ? (a) : (b))
#endif
#ifndef V3_MIN
    #define V3_MIN(a, b)        (((a) < (b)) ? (a) : (b))
#endif

/* 限制范围 */
#define V3_CLAMP(val, min, max) V3_MAX((min), V3_MIN((val), (max)))

/* 对齐 */
#define V3_ALIGN_UP(x, align)   (((x) + ((align) - 1)) & ~((align) - 1))
#define V3_ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define V3_IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

/* 位操作 */
#define V3_BIT(n)               (1ULL << (n))
#define V3_BIT_SET(x, n)        ((x) |= V3_BIT(n))
#define V3_BIT_CLEAR(x, n)      ((x) &= ~V3_BIT(n))
#define V3_BIT_TOGGLE(x, n)     ((x) ^= V3_BIT(n))
#define V3_BIT_TEST(x, n)       (((x) & V3_BIT(n)) != 0)

/* 字节序转换 */
#if defined(V3_COMPILER_GCC) || defined(V3_COMPILER_CLANG)
    #define V3_BSWAP16(x)       __builtin_bswap16(x)
    #define V3_BSWAP32(x)       __builtin_bswap32(x)
    #define V3_BSWAP64(x)       __builtin_bswap64(x)
#elif defined(V3_COMPILER_MSVC)
    #include <stdlib.h>
    #define V3_BSWAP16(x)       _byteswap_ushort(x)
    #define V3_BSWAP32(x)       _byteswap_ulong(x)
    #define V3_BSWAP64(x)       _byteswap_uint64(x)
#else
    #define V3_BSWAP16(x)       ((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
    #define V3_BSWAP32(x)       ((((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8) | \
                                 (((x) & 0x0000FF00) << 8)  | (((x) & 0x000000FF) << 24))
    #define V3_BSWAP64(x)       ((V3_BSWAP32((x) & 0xFFFFFFFFULL) << 32) | \
                                 V3_BSWAP32(((x) >> 32) & 0xFFFFFFFFULL))
#endif

/* 大小端检测 */
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define V3_LITTLE_ENDIAN 1
    #else
        #define V3_BIG_ENDIAN    1
    #endif
#elif defined(V3_PLATFORM_WINDOWS)
    #define V3_LITTLE_ENDIAN     1
#else
    /* 假设小端 */
    #define V3_LITTLE_ENDIAN     1
#endif

/* 网络字节序转换 */
#ifdef V3_LITTLE_ENDIAN
    #define V3_HTONS(x)         V3_BSWAP16(x)
    #define V3_HTONL(x)         V3_BSWAP32(x)
    #define V3_HTONLL(x)        V3_BSWAP64(x)
    #define V3_NTOHS(x)         V3_BSWAP16(x)
    #define V3_NTOHL(x)         V3_BSWAP32(x)
    #define V3_NTOHLL(x)        V3_BSWAP64(x)
#else
    #define V3_HTONS(x)         (x)
    #define V3_HTONL(x)         (x)
    #define V3_HTONLL(x)        (x)
    #define V3_NTOHS(x)         (x)
    #define V3_NTOHL(x)         (x)
    #define V3_NTOHLL(x)        (x)
#endif

/* =========================================================
 * 协议常量（与服务端 v3_portable.c 一致）
 * ========================================================= */

#define V3_DEFAULT_PORT         51820
#define V3_HEADER_SIZE          52          /* v3_header_t 大小 */
#define V3_MAGIC_SLOTS          8           /* Magic 表槽位数量 */
#define V3_MAGIC_WINDOW_SEC     60          /* Magic 有效窗口（秒）*/
#define V3_MAGIC_TOLERANCE      1           /* 允许前后各 1 个窗口 */

#define V3_KEY_SIZE             32          /* 主密钥长度 */
#define V3_NONCE_SIZE           12          /* Nonce 长度 */
#define V3_TAG_SIZE             16          /* Poly1305 Tag 长度 */
#define V3_ENC_BLOCK_SIZE       16          /* 加密元数据块大小 */

#define V3_MTU_DEFAULT          1500
#define V3_MTU_MIN              576
#define V3_MTU_MAX              9000

#define V3_BUF_SIZE             2048        /* 默认缓冲区大小 */
#define V3_MAX_PACKET_SIZE      1500        /* 最大包大小 */

/* =========================================================
 * FEC 常量（与服务端 v3_fec_simd.h 一致）
 * ========================================================= */

#define V3_FEC_MAX_DATA_SHARDS      20
#define V3_FEC_MAX_PARITY_SHARDS    10
#define V3_FEC_MAX_TOTAL_SHARDS     30
#define V3_FEC_SHARD_SIZE           1400
#define V3_FEC_DECODE_CACHE_SIZE    128
#define V3_FEC_XOR_GROUP_SIZE       4

/* =========================================================
 * 连接常量
 * ========================================================= */

#define V3_MAX_CONNECTIONS      32768
#define V3_MAX_INTENTS          256
#define V3_SESSION_TIMEOUT_SEC  300         /* 5 分钟超时 */
#define V3_KEEPALIVE_SEC        30          /* 心跳间隔 */

/* =========================================================
 * 回调函数类型
 * ========================================================= */

/* 通用回调 */
typedef void (*v3_callback_fn)(void *user_data);

/* 数据回调 */
typedef void (*v3_data_callback_fn)(const u8 *data, usize len, void *user_data);

/* 事件回调 */
typedef void (*v3_event_callback_fn)(int event_type, void *event_data, void *user_data);

/* 日志回调 */
typedef void (*v3_log_callback_fn)(int level, const char *file, int line, 
                                    const char *func, const char *msg, void *user_data);

/* =========================================================
 * 前向声明（核心结构体）
 * ========================================================= */

/* 核心上下文 */
typedef struct v3_core_s            v3_core_t;

/* 配置 */
typedef struct v3_config_s          v3_config_t;

/* 连接 */
typedef struct v3_connection_s      v3_connection_t;

/* 会话 */
typedef struct v3_session_s         v3_session_t;

/* 缓冲区 */
typedef struct v3_buffer_s          v3_buffer_t;
typedef struct v3_buffer_pool_s     v3_buffer_pool_t;

/* 统计 */
typedef struct v3_stats_s           v3_stats_t;

/* =========================================================
 * 枚举类型
 * ========================================================= */

/**
 * @brief 运行状态
 */
typedef enum v3_state_e {
    V3_STATE_UNINITIALIZED = 0,     /* 未初始化 */
    V3_STATE_INITIALIZED,            /* 已初始化 */
    V3_STATE_STARTING,               /* 正在启动 */
    V3_STATE_RUNNING,                /* 运行中 */
    V3_STATE_STOPPING,               /* 正在停止 */
    V3_STATE_STOPPED,                /* 已停止 */
    V3_STATE_ERROR,                  /* 错误状态 */
} v3_state_t;

/**
 * @brief FEC 类型（与服务端 fec_type_t 一致）
 */
typedef enum v3_fec_type_e {
    V3_FEC_TYPE_NONE = 0,           /* 不使用 FEC */
    V3_FEC_TYPE_XOR,                /* 简单 XOR */
    V3_FEC_TYPE_RS,                 /* Reed-Solomon */
    V3_FEC_TYPE_AUTO,               /* 自动选择 */
} v3_fec_type_t;

/**
 * @brief Pacing 模式
 */
typedef enum v3_pacing_mode_e {
    V3_PACING_NONE = 0,             /* 不限速 */
    V3_PACING_BRUTAL,               /* Brutal 恒定速率 */
    V3_PACING_ADAPTIVE,             /* 自适应 */
    V3_PACING_BBR,                  /* BBR 风格 */
} v3_pacing_mode_t;

/**
 * @brief 流量伪装配置文件（与服务端 ad_profile_t 一致）
 */
typedef enum v3_profile_e {
    V3_PROFILE_NONE = 0,
    V3_PROFILE_HTTPS,
    V3_PROFILE_VIDEO,
    V3_PROFILE_VOIP,
    V3_PROFILE_GAMING,
} v3_profile_t;

/**
 * @brief 日志级别
 */
typedef enum v3_log_level_e {
    V3_LOG_TRACE = 0,
    V3_LOG_DEBUG,
    V3_LOG_INFO,
    V3_LOG_WARN,
    V3_LOG_ERROR,
    V3_LOG_FATAL,
    V3_LOG_OFF,
} v3_log_level_t;

/**
 * @brief 连接状态
 */
typedef enum v3_conn_state_e {
    V3_CONN_STATE_IDLE = 0,
    V3_CONN_STATE_CONNECTING,
    V3_CONN_STATE_HANDSHAKING,
    V3_CONN_STATE_ESTABLISHED,
    V3_CONN_STATE_CLOSING,
    V3_CONN_STATE_CLOSED,
    V3_CONN_STATE_ERROR,
} v3_conn_state_t;

/* =========================================================
 * 时间相关
 * ========================================================= */

/**
 * @brief 获取当前时间戳（纳秒）
 */
V3_INLINE u64 v3_time_ns(void) {
#ifdef V3_PLATFORM_WINDOWS
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (u64)((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
#endif
}

/**
 * @brief 获取当前时间戳（微秒）
 */
V3_INLINE u64 v3_time_us(void) {
    return v3_time_ns() / 1000ULL;
}

/**
 * @brief 获取当前时间戳（毫秒）
 */
V3_INLINE u64 v3_time_ms(void) {
    return v3_time_ns() / 1000000ULL;
}

/**
 * @brief 获取 Unix 时间戳（秒）
 */
V3_INLINE u64 v3_time_unix(void) {
#ifdef V3_PLATFORM_WINDOWS
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    u64 t = ((u64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ULL) / 10000000ULL;
#else
    return (u64)time(NULL);
#endif
}

#endif /* V3_TYPES_H */
