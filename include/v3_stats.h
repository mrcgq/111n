
/**
 * @file v3_stats.h
 * @brief v3 Core - 统计监控
 * 
 * 提供运行时统计信息收集和查询
 * 与服务端 v3_health.h 兼容
 */

#ifndef V3_STATS_H
#define V3_STATS_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 统计结构
 * ========================================================= */

/**
 * @brief 流量统计
 */
typedef struct v3_traffic_stats_s {
    u64     packets_rx;             /* 接收数据包数 */
    u64     packets_tx;             /* 发送数据包数 */
    u64     bytes_rx;               /* 接收字节数 */
    u64     bytes_tx;               /* 发送字节数 */
    u64     packets_dropped;        /* 丢弃数据包数 */
    u64     packets_invalid;        /* 无效数据包数 */
    u64     packets_ratelimited;    /* 被限速数据包数 */
} v3_traffic_stats_t;

/**
 * @brief FEC 统计
 */
typedef struct v3_fec_stats_s {
    u64     groups_total;           /* FEC 组总数 */
    u64     groups_complete;        /* 完整组数 */
    u64     recoveries;             /* 恢复成功次数 */
    u64     failures;               /* 恢复失败次数 */
    f32     recovery_rate;          /* 恢复率 */
} v3_fec_stats_t;

/**
 * @brief 连接统计
 */
typedef struct v3_conn_stats_summary_s {
    u32     active;                 /* 活跃连接数 */
    u32     total;                  /* 历史连接总数 */
    u32     peak;                   /* 峰值连接数 */
    u64     handshake_success;      /* 握手成功数 */
    u64     handshake_failed;       /* 握手失败数 */
} v3_conn_stats_summary_t;

/**
 * @brief 性能统计
 */
typedef struct v3_perf_stats_s {
    u64     latency_avg_us;         /* 平均延迟（微秒）*/
    u64     latency_min_us;         /* 最小延迟 */
    u64     latency_max_us;         /* 最大延迟 */
    u64     latency_p50_us;         /* P50 延迟 */
    u64     latency_p99_us;         /* P99 延迟 */
    u64     packets_per_sec;        /* 每秒包数 */
    u64     bytes_per_sec;          /* 每秒字节数（吞吐量）*/
} v3_perf_stats_t;

/**
 * @brief 系统资源统计
 */
typedef struct v3_system_stats_s {
    f32     cpu_usage;              /* CPU 使用率 (0-100) */
    f32     memory_mb;              /* 内存使用 (MB) */
    f32     memory_percent;         /* 内存使用率 (0-100) */
    u32     thread_count;           /* 线程数 */
    u32     handle_count;           /* 句柄数（Windows）*/
} v3_system_stats_t;

/**
 * @brief 模块状态
 */
typedef struct v3_module_status_s {
    bool    crypto_ready;           /* 加密模块就绪 */
    bool    network_ready;          /* 网络模块就绪 */
    bool    fec_enabled;            /* FEC 已启用 */
    bool    pacing_enabled;         /* Pacing 已启用 */
    bool    ipc_connected;          /* IPC 已连接 */
    bool    guard_active;           /* 守护已激活 */
} v3_module_status_t;

/**
 * @brief 完整统计信息
 */
typedef struct v3_stats_s {
    /* 基础信息 */
    u64                     uptime_sec;         /* 运行时间（秒）*/
    u64                     start_time;         /* 启动时间戳 */
    char                    version[32];        /* 版本字符串 */
    char                    platform[32];       /* 平台信息 */
    
    /* 各类统计 */
    v3_traffic_stats_t      traffic;            /* 流量统计 */
    v3_fec_stats_t          fec;                /* FEC 统计 */
    v3_conn_stats_summary_t connections;        /* 连接统计 */
    v3_perf_stats_t         performance;        /* 性能统计 */
    v3_system_stats_t       system;             /* 系统资源 */
    v3_module_status_t      modules;            /* 模块状态 */
} v3_stats_t;

/* =========================================================
 * 统计模块 API
 * ========================================================= */

/**
 * @brief 初始化统计模块
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_stats_init(void);

/**
 * @brief 关闭统计模块
 */
V3_API void v3_stats_shutdown(void);

/**
 * @brief 获取完整统计快照
 * @param stats 输出统计
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_stats_snapshot(v3_stats_t *stats);

/**
 * @brief 重置统计计数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_stats_reset(void);

/* =========================================================
 * 记录接口
 * ========================================================= */

/**
 * @brief 记录接收数据包
 * @param bytes 字节数
 */
V3_API void v3_stats_record_rx(usize bytes);

/**
 * @brief 记录发送数据包
 * @param bytes 字节数
 */
V3_API void v3_stats_record_tx(usize bytes);

/**
 * @brief 记录丢弃数据包
 * @param reason 原因
 */
V3_API void v3_stats_record_drop(int reason);

/**
 * @brief 记录 FEC 操作
 * @param recovered 是否成功恢复
 */
V3_API void v3_stats_record_fec(bool recovered);

/**
 * @brief 记录延迟样本
 * @param latency_us 延迟（微秒）
 */
V3_API void v3_stats_record_latency(u64 latency_us);

/**
 * @brief 记录连接事件
 * @param connected true=新连接, false=断开
 */
V3_API void v3_stats_record_connection(bool connected);

/* =========================================================
 * 查询接口
 * ========================================================= */

/**
 * @brief 获取运行时间
 * @return 运行秒数
 */
V3_API u64 v3_stats_uptime(void);

/**
 * @brief 获取当前连接数
 * @return 活跃连接数
 */
V3_API u32 v3_stats_active_connections(void);

/**
 * @brief 获取当前吞吐量
 * @param rx_bps 输出接收速率
 * @param tx_bps 输出发送速率
 */
V3_API void v3_stats_throughput(u64 *rx_bps, u64 *tx_bps);

/* =========================================================
 * 输出接口
 * ========================================================= */

/**
 * @brief 打印统计信息到控制台
 * @param stats 统计信息
 */
V3_API void v3_stats_print(const v3_stats_t *stats);

/**
 * @brief 转换为 JSON 字符串
 * @param stats 统计信息
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 写入的字节数
 */
V3_API int v3_stats_to_json(const v3_stats_t *stats, char *buf, usize buf_size);

/**
 * @brief 获取统计信息的单行摘要
 * @param stats 统计信息
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 写入的字节数
 */
V3_API int v3_stats_summary(const v3_stats_t *stats, char *buf, usize buf_size);

/* =========================================================
 * 计数器接口（原子操作）
 * ========================================================= */

/**
 * @brief 计数器类型
 */
typedef enum v3_counter_type_e {
    V3_COUNTER_PACKETS_RX = 0,
    V3_COUNTER_PACKETS_TX,
    V3_COUNTER_BYTES_RX,
    V3_COUNTER_BYTES_TX,
    V3_COUNTER_PACKETS_DROPPED,
    V3_COUNTER_FEC_RECOVERIES,
    V3_COUNTER_FEC_FAILURES,
    V3_COUNTER_MAX
} v3_counter_type_t;

/**
 * @brief 增加计数器
 * @param type 计数器类型
 * @param value 增量
 */
V3_API void v3_counter_add(v3_counter_type_t type, u64 value);

/**
 * @brief 获取计数器值
 * @param type 计数器类型
 * @return 计数器值
 */
V3_API u64 v3_counter_get(v3_counter_type_t type);

/**
 * @brief 重置计数器
 * @param type 计数器类型
 */
V3_API void v3_counter_reset(v3_counter_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* V3_STATS_H */
