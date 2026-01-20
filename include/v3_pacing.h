
/**
 * @file v3_pacing.h
 * @brief v3 Core - 流量控制/Pacing
 * 
 * 实现 Brutal 模式和自适应 Pacing
 * 与服务端 v3_pacing_adaptive.h 兼容
 */

#ifndef V3_PACING_H
#define V3_PACING_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* 默认速率 */
#define V3_PACING_DEFAULT_RATE_BPS      (100 * 1000 * 1000ULL)  /* 100 Mbps */
#define V3_PACING_MIN_RATE_BPS          (1 * 1000 * 1000ULL)    /* 1 Mbps */
#define V3_PACING_MAX_RATE_BPS          (10000 * 1000 * 1000ULL)/* 10 Gbps */

/* 初始 RTT 假设 */
#define V3_PACING_INITIAL_RTT_US        100000  /* 100ms */

/* 最小发送间隔 */
#define V3_PACING_MIN_INTERVAL_NS       10000   /* 10µs */

/* =========================================================
 * Pacing 模式
 * ========================================================= */

/**
 * @brief Pacing 模式
 */
typedef enum v3_pacing_mode_e {
    V3_PACING_MODE_NONE = 0,        /* 不限速 */
    V3_PACING_MODE_BRUTAL,          /* Brutal 恒定速率 */
    V3_PACING_MODE_ADAPTIVE,        /* 自适应（基于 RTT）*/
    V3_PACING_MODE_BBR,             /* BBR 风格 */
} v3_pacing_mode_t;

/**
 * @brief Pacing 状态（自适应模式）
 */
typedef enum v3_pacing_state_e {
    V3_PACING_STATE_SLOW_START = 0, /* 慢启动 */
    V3_PACING_STATE_CONGESTION,     /* 拥塞避免 */
    V3_PACING_STATE_RECOVERY,       /* 恢复 */
} v3_pacing_state_t;

/* =========================================================
 * Pacing 配置
 * ========================================================= */

/**
 * @brief Pacing 配置
 */
typedef struct v3_pacing_config_s {
    v3_pacing_mode_t    mode;               /* 模式 */
    u64                 target_bps;         /* 目标速率 */
    u64                 min_bps;            /* 最小速率 */
    u64                 max_bps;            /* 最大速率 */
    bool                jitter_enabled;     /* 是否启用抖动 */
    u32                 jitter_range_ns;    /* 抖动范围（纳秒）*/
} v3_pacing_config_t;

/* =========================================================
 * Pacing 统计
 * ========================================================= */

/**
 * @brief Pacing 统计
 */
typedef struct v3_pacing_stats_s {
    u64                 total_bytes;        /* 总字节数 */
    u64                 total_packets;      /* 总包数 */
    u64                 throttled_count;    /* 被限速次数 */
    u64                 burst_count;        /* 突发次数 */
    
    u64                 current_rate_bps;   /* 当前速率 */
    u64                 estimated_bw_bps;   /* 估计带宽 */
    
    u64                 rtt_us;             /* 当前 RTT */
    u64                 rtt_min_us;         /* 最小 RTT */
    u64                 rtt_max_us;         /* 最大 RTT */
    
    u64                 cwnd;               /* 拥塞窗口 */
    u64                 bytes_in_flight;    /* 在途字节 */
    
    u32                 loss_count;         /* 丢包次数 */
    
    v3_pacing_state_t   state;              /* 当前状态 */
} v3_pacing_stats_t;

/* =========================================================
 * Pacer 句柄
 * ========================================================= */

/**
 * @brief Pacer 句柄
 */
typedef struct v3_pacer_s v3_pacer_t;

/* =========================================================
 * Pacer API
 * ========================================================= */

/**
 * @brief 创建 Pacer
 * @param config 配置（NULL 使用默认）
 * @param pacer_out 输出 Pacer 句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_pacer_create(
    const v3_pacing_config_t *config,
    v3_pacer_t **pacer_out
);

/**
 * @brief 销毁 Pacer
 * @param pacer Pacer 句柄
 */
V3_API void v3_pacer_destroy(v3_pacer_t *pacer);

/**
 * @brief 获取默认配置
 * @param config 输出配置
 */
V3_API void v3_pacer_default_config(v3_pacing_config_t *config);

/**
 * @brief 设置目标速率
 * @param pacer Pacer 句柄
 * @param target_bps 目标速率 (bps)
 */
V3_API void v3_pacer_set_rate(v3_pacer_t *pacer, u64 target_bps);

/**
 * @brief 设置速率范围
 * @param pacer Pacer 句柄
 * @param min_bps 最小速率
 * @param max_bps 最大速率
 */
V3_API void v3_pacer_set_range(v3_pacer_t *pacer, u64 min_bps, u64 max_bps);

/**
 * @brief 启用/禁用抖动
 * @param pacer Pacer 句柄
 * @param enabled 是否启用
 * @param range_ns 抖动范围（纳秒）
 */
V3_API void v3_pacer_enable_jitter(v3_pacer_t *pacer, bool enabled, u32 range_ns);

/**
 * @brief 请求发送权限
 * @param pacer Pacer 句柄
 * @param bytes 要发送的字节数
 * @return 需要等待的纳秒数（0 表示可立即发送）
 */
V3_API u64 v3_pacer_acquire(v3_pacer_t *pacer, usize bytes);

/**
 * @brief 确认发送
 * @param pacer Pacer 句柄
 * @param bytes 实际发送的字节数
 */
V3_API void v3_pacer_commit(v3_pacer_t *pacer, usize bytes);

/**
 * @brief 确认接收（ACK）
 * @param pacer Pacer 句柄
 * @param bytes 确认的字节数
 */
V3_API void v3_pacer_ack(v3_pacer_t *pacer, usize bytes);

/**
 * @brief 更新 RTT
 * @param pacer Pacer 句柄
 * @param rtt_us RTT 微秒
 */
V3_API void v3_pacer_update_rtt(v3_pacer_t *pacer, u64 rtt_us);

/**
 * @brief 报告丢包
 * @param pacer Pacer 句柄
 */
V3_API void v3_pacer_report_loss(v3_pacer_t *pacer);

/**
 * @brief 检查是否允许突发
 * @param pacer Pacer 句柄
 * @param bytes 要发送的字节数
 * @return true 允许突发
 */
V3_API bool v3_pacer_allow_burst(v3_pacer_t *pacer, usize bytes);

/**
 * @brief 获取当前估计带宽
 * @param pacer Pacer 句柄
 * @return 估计带宽 (bps)
 */
V3_API u64 v3_pacer_get_bandwidth(v3_pacer_t *pacer);

/**
 * @brief 获取统计信息
 * @param pacer Pacer 句柄
 * @param stats 输出统计
 */
V3_API void v3_pacer_get_stats(v3_pacer_t *pacer, v3_pacing_stats_t *stats);

/**
 * @brief 重置统计
 * @param pacer Pacer 句柄
 */
V3_API void v3_pacer_reset_stats(v3_pacer_t *pacer);

/* =========================================================
 * 工具函数
 * ========================================================= */

/**
 * @brief 获取 Pacing 模式名称
 * @param mode Pacing 模式
 * @return 模式名称字符串
 */
V3_API const char* v3_pacing_mode_str(v3_pacing_mode_t mode);

/**
 * @brief 获取 Pacing 状态名称
 * @param state Pacing 状态
 * @return 状态名称字符串
 */
V3_API const char* v3_pacing_state_str(v3_pacing_state_t state);

/**
 * @brief 计算发送间隔
 * @param rate_bps 速率 (bps)
 * @param packet_size 包大小
 * @return 发送间隔（纳秒）
 */
V3_API u64 v3_pacing_calc_interval(u64 rate_bps, usize packet_size);

#ifdef __cplusplus
}
#endif

#endif /* V3_PACING_H */

