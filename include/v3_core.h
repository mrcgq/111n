
/**
 * @file v3_core.h
 * @brief v3 Core - 核心总头文件
 * 
 * 这是 v3 Core 的主入口头文件，包含所有必要的定义和 API。
 * 用户程序只需包含此文件即可使用 v3 Core 的所有功能。
 * 
 * @note 与服务端协议完全兼容：
 *   - v3_portable.c (ChaCha20-Poly1305)
 *   - v3_fec_simd.c (FEC 纠错)
 *   - v3_pacing_adaptive.c (流量控制)
 *   - v3_ultimate_optimized.c (协议处理)
 */

#ifndef V3_CORE_H
#define V3_CORE_H

/* =========================================================
 * 版本信息
 * ========================================================= */

#include "version.h"

/* =========================================================
 * 核心头文件
 * ========================================================= */

/* 基础定义 */
#include "v3_types.h"
#include "v3_error.h"

/* 退出管理 */
#include "v3_exit.h"

/* 平台抽象 */
#include "v3_platform.h"

/* 配置管理 */
#include "v3_config.h"

/* 生命周期 */
#include "v3_lifecycle.h"

/* 日志系统 */
#include "v3_log.h"

/* 线程管理 */
#include "v3_thread.h"

/* 缓冲区 */
#include "v3_buffer.h"

/* 网络层 */
#include "v3_network.h"

/* 加密模块 */
#include "v3_crypto.h"

/* 协议处理 */
#include "v3_protocol.h"

/* 连接管理 */
#include "v3_connection.h"

/* FEC 纠错 */
#include "v3_fec.h"

/* 流量控制 */
#include "v3_pacing.h"

/* IPC 通信 */
#include "v3_ipc.h"

/* 守护进程 */
#include "v3_guard.h"

/* 统计监控 */
#include "v3_stats.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * v3 Core 主配置结构
 * ========================================================= */

/**
 * @brief v3 Core 初始化选项
 */
typedef struct v3_init_options_s {
    /* 基础配置 */
    const char     *config_file;        /* 配置文件路径（可选）*/
    const char     *log_file;           /* 日志文件路径（可选）*/
    v3_log_level_t  log_level;          /* 日志级别 */
    
    /* 网络配置 */
    const char     *bind_address;       /* 绑定地址 */
    u16             bind_port;          /* 绑定端口 */
    
    /* 加密配置 */
    const u8       *master_key;         /* 主密钥（32字节）*/
    usize           master_key_len;     /* 密钥长度 */
    
    /* FEC 配置 */
    bool            fec_enabled;        /* 是否启用 FEC */
    v3_fec_type_t   fec_type;           /* FEC 类型 */
    u8              fec_data_shards;    /* 数据分片数 */
    u8              fec_parity_shards;  /* 校验分片数 */
    
    /* Pacing 配置 */
    bool            pacing_enabled;     /* 是否启用 Pacing */
    v3_pacing_mode_t pacing_mode;       /* Pacing 模式 */
    u64             pacing_rate_bps;    /* 初始速率 (bps) */
    
    /* 流量伪装 */
    v3_profile_t    traffic_profile;    /* 流量伪装配置 */
    u16             mtu;                /* MTU */
    
    /* IPC 配置 */
    bool            ipc_enabled;        /* 是否启用 IPC */
    const char     *ipc_pipe_name;      /* IPC 管道名称 */
    
    /* 守护配置 */
    bool            guard_enabled;      /* 是否启用守护 */
    u32             guard_restart_delay_ms; /* 重启延迟 */
    
    /* 连接限制 */
    u32             max_connections;    /* 最大连接数 */
    u32             connection_timeout_sec; /* 连接超时 */
    
    /* 回调函数 */
    v3_log_callback_fn    log_callback;     /* 日志回调 */
    v3_event_callback_fn  event_callback;   /* 事件回调 */
    void                 *callback_data;    /* 回调用户数据 */
    
    /* 扩展字段 */
    u32             flags;              /* 额外标志 */
    void           *reserved;           /* 保留字段 */
} v3_init_options_t;

/* 初始化选项标志 */
#define V3_INIT_FLAG_NONE           0x00000000
#define V3_INIT_FLAG_DAEMON         0x00000001  /* 守护进程模式 */
#define V3_INIT_FLAG_NO_SIGNALS     0x00000002  /* 不设置信号处理 */
#define V3_INIT_FLAG_VERBOSE        0x00000004  /* 详细输出 */
#define V3_INIT_FLAG_BENCHMARK      0x00000008  /* 基准测试模式 */
#define V3_INIT_FLAG_DRY_RUN        0x00000010  /* 测试运行（不实际启动）*/

/* =========================================================
 * 核心 API
 * ========================================================= */

/**
 * @brief 获取默认初始化选项
 * @param opts 输出选项结构
 */
V3_API void v3_core_default_options(v3_init_options_t *opts);

/**
 * @brief 初始化 v3 Core
 * @param opts 初始化选项
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_init(const v3_init_options_t *opts);

/**
 * @brief 关闭 v3 Core
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_shutdown(void);

/**
 * @brief 获取 v3 Core 上下文
 * @return 核心上下文指针
 */
V3_API v3_core_t* v3_core_get_context(void);

/**
 * @brief 获取当前状态
 * @return 运行状态
 */
V3_API v3_state_t v3_core_get_state(void);

/**
 * @brief 启动 v3 Core
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_start(void);

/**
 * @brief 停止 v3 Core
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_stop(void);

/**
 * @brief 运行主循环（阻塞）
 * @return 退出码
 */
V3_API int v3_core_run(void);

/**
 * @brief 处理一次事件（非阻塞）
 * @param timeout_ms 超时毫秒数
 * @return V3_OK 成功，V3_ERR_TIMEOUT 超时
 */
V3_API v3_error_t v3_core_poll(u32 timeout_ms);

/**
 * @brief 请求重新加载配置
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_reload(void);

/* =========================================================
 * 统计信息
 * ========================================================= */

/**
 * @brief 获取运行时统计
 * @param stats 输出统计结构
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_get_stats(v3_stats_t *stats);

/**
 * @brief 重置统计计数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_core_reset_stats(void);

/* =========================================================
 * 版本与信息
 * ========================================================= */

/**
 * @brief 获取版本字符串
 * @return 版本字符串
 */
V3_API const char* v3_core_version_string(void);

/**
 * @brief 获取版本号
 * @param major 主版本号
 * @param minor 次版本号
 * @param patch 补丁版本号
 */
V3_API void v3_core_version(int *major, int *minor, int *patch);

/**
 * @brief 获取编译信息
 * @return 编译信息字符串
 */
V3_API const char* v3_core_build_info(void);

/**
 * @brief 获取平台信息
 * @return 平台信息字符串
 */
V3_API const char* v3_core_platform_info(void);

/**
 * @brief 打印 Banner
 */
V3_API void v3_core_print_banner(void);

/**
 * @brief 打印版本信息
 */
V3_API void v3_core_print_version(void);

/* =========================================================
 * 实用工具
 * ========================================================= */

/**
 * @brief 安全内存清零
 * @param ptr 内存指针
 * @param size 大小
 */
V3_API void v3_secure_zero(void *ptr, usize size);

/**
 * @brief 恒定时间内存比较
 * @param a 第一个缓冲区
 * @param b 第二个缓冲区
 * @param size 比较大小
 * @return 0 相等，非0 不相等
 */
V3_API int v3_secure_compare(const void *a, const void *b, usize size);

/**
 * @brief 生成随机字节
 * @param buf 输出缓冲区
 * @param size 字节数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_random_bytes(u8 *buf, usize size);

/**
 * @brief 十六进制编码
 * @param out 输出缓冲区（需 len*2+1 字节）
 * @param data 输入数据
 * @param len 数据长度
 */
V3_API void v3_hex_encode(char *out, const u8 *data, usize len);

/**
 * @brief 十六进制解码
 * @param out 输出缓冲区（需 len/2 字节）
 * @param hex 十六进制字符串
 * @param len 字符串长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_hex_decode(u8 *out, const char *hex, usize len);

/* =========================================================
 * 调试支持
 * ========================================================= */

#ifdef V3_DEBUG

/**
 * @brief 断言宏（调试模式）
 */
#define V3_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            v3_assert_fail(#cond, __FILE__, __LINE__, __func__); \
        } \
    } while(0)

/**
 * @brief 断言失败处理
 */
V3_API V3_NORETURN void v3_assert_fail(
    const char *expr,
    const char *file,
    int line,
    const char *func
);

#else

#define V3_ASSERT(cond)  ((void)0)

#endif /* V3_DEBUG */

/* =========================================================
 * 协议结构体定义（与服务端 v3_portable.c 一致）
 * ========================================================= */

/**
 * @brief v3 协议头（52 字节）
 * 
 * 与服务端 v3_header_t 完全一致
 */
V3_PACK_BEGIN
typedef struct v3_header_s {
    u32     magic_derived;      /* 派生的 Magic 值 */
    u8      nonce[12];          /* AEAD Nonce */
    u8      enc_block[16];      /* 加密的元数据块 */
    u8      tag[16];            /* Poly1305 认证标签 */
    u16     early_len;          /* Early 数据长度（AAD）*/
    u16     pad;                /* 填充 */
} V3_PACK_STRUCT v3_header_t;
V3_PACK_END

/**
 * @brief v3 元数据（加密块内容）
 */
V3_PACK_BEGIN
typedef struct v3_meta_s {
    u64     session_token;      /* 会话令牌 */
    u16     intent_id;          /* Intent ID */
    u16     stream_id;          /* Stream ID */
    u16     flags;              /* 标志位 */
    u16     reserved;           /* 保留 */
} V3_PACK_STRUCT v3_meta_t;
V3_PACK_END

/* 编译时断言：确保结构体大小正确 */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
    _Static_assert(sizeof(v3_header_t) == V3_HEADER_SIZE, "v3_header_t size mismatch");
    _Static_assert(sizeof(v3_meta_t) == V3_ENC_BLOCK_SIZE, "v3_meta_t size mismatch");
#endif

/* =========================================================
 * 事件类型
 * ========================================================= */

typedef enum v3_event_type_e {
    V3_EVENT_NONE = 0,
    
    /* 生命周期事件 */
    V3_EVENT_STARTING,              /* 正在启动 */
    V3_EVENT_STARTED,               /* 已启动 */
    V3_EVENT_STOPPING,              /* 正在停止 */
    V3_EVENT_STOPPED,               /* 已停止 */
    V3_EVENT_RELOADING,             /* 正在重载 */
    V3_EVENT_RELOADED,              /* 已重载 */
    
    /* 连接事件 */
    V3_EVENT_CONN_NEW,              /* 新连接 */
    V3_EVENT_CONN_ESTABLISHED,      /* 连接已建立 */
    V3_EVENT_CONN_CLOSED,           /* 连接已关闭 */
    V3_EVENT_CONN_ERROR,            /* 连接错误 */
    V3_EVENT_CONN_TIMEOUT,          /* 连接超时 */
    
    /* 数据事件 */
    V3_EVENT_DATA_RECV,             /* 收到数据 */
    V3_EVENT_DATA_SEND,             /* 发送数据 */
    
    /* 错误事件 */
    V3_EVENT_ERROR,                 /* 一般错误 */
    V3_EVENT_FATAL_ERROR,           /* 致命错误 */
    
    /* IPC 事件 */
    V3_EVENT_IPC_CONNECTED,         /* IPC 已连接 */
    V3_EVENT_IPC_DISCONNECTED,      /* IPC 已断开 */
    V3_EVENT_IPC_MESSAGE,           /* IPC 消息 */
    
    V3_EVENT_MAX
} v3_event_type_t;

/* =========================================================
 * 全局常量
 * ========================================================= */

/* 验证协议头大小（编译时检查） */
#ifndef V3_HEADER_SIZE
    #define V3_HEADER_SIZE  52
#endif

#ifdef __cplusplus
}
#endif

#endif /* V3_CORE_H */
