
/*
 * v3_pacing.c - v3 流量控制 (Pacing) 实现
 * 
 * 功能：
 * - 令牌桶速率控制
 * - 自适应带宽估算
 * - Brutal 恒定速率模式
 * - 拥塞控制
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_pacing.h"
#include "v3_log.h"
#include "v3_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

/* =========================================================
 * 配置常量
 * ========================================================= */

#define PACING_MIN_RATE_BPS         100000          /* 100 Kbps */
#define PACING_MAX_RATE_BPS         10000000000ULL  /* 10 Gbps */
#define PACING_INITIAL_CWND         (10 * 1400)     /* 10 个 MTU */
#define PACING_MIN_RTT_US           1000            /* 1ms */
#define PACING_MAX_RTT_US           60000000        /* 60s */
#define PACING_ALPHA                0.125           /* SRTT alpha */
#define PACING_BETA                 0.25            /* RTTVAR beta */

/* =========================================================
 * Pacing 状态
 * ========================================================= */

typedef enum {
    PACING_STATE_SLOW_START,
    PACING_STATE_CONGESTION_AVOIDANCE,
    PACING_STATE_RECOVERY,
    PACING_STATE_BRUTAL,
} pacing_state_t;

static const char* pacing_state_names[] = {
    "SLOW_START",
    "CONGESTION_AVOIDANCE", 
    "RECOVERY",
    "BRUTAL"
};

/* =========================================================
 * Pacing 上下文
 * ========================================================= */

struct v3_pacing_s {
    /* 配置 */
    v3_pacing_mode_t    mode;
    uint64_t            target_bps;
    uint64_t            min_bps;
    uint64_t            max_bps;
    
    /* 令牌桶 */
    double              tokens;
    double              tokens_per_ns;
    uint64_t            last_refill_ns;
    double              max_burst;
    
    /* RTT 追踪 */
    uint64_t            rtt_us;
    uint64_t            rtt_min_us;
    uint64_t            rtt_max_us;
    double              srtt_us;
    double              rtt_var_us;
    
    /* 带宽估计 */
    uint64_t            bw_estimate_bps;
    uint64_t            bytes_in_flight;
    uint64_t            last_bw_sample_ns;
    
    /* 拥塞控制 */
    pacing_state_t      state;
    uint64_t            cwnd;
    uint64_t            ssthresh;
    
    /* 丢包检测 */
    uint64_t            last_loss_ns;
    uint32_t            loss_count;
    uint32_t            ack_count;
    
    /* 抖动 */
    bool                jitter_enabled;
    uint32_t            jitter_range_ns;
    uint64_t            rng_state;
    
    /* 统计 */
    uint64_t            total_bytes;
    uint64_t            total_packets;
    uint64_t            throttled_count;
    uint64_t            burst_count;
    
    /* 同步 */
    v3_mutex_t          mutex;
};

/* =========================================================
 * 辅助函数
 * ========================================================= */

static inline uint64_t pacing_get_time_ns(void) {
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

/* xorshift64 随机数生成器 */
static inline uint64_t pacing_random(v3_pacing_t *p) {
    uint64_t x = p->rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    p->rng_state = x;
    return x;
}

static void pacing_refill_tokens(v3_pacing_t *p, uint64_t now_ns) {
    uint64_t elapsed = now_ns - p->last_refill_ns;
    double new_tokens = elapsed * p->tokens_per_ns;
    
    p->tokens += new_tokens;
    
    /* 限制最大突发 */
    if (p->tokens > p->max_burst) {
        p->tokens = p->max_burst;
    }
    
    p->last_refill_ns = now_ns;
}

static void pacing_update_rate(v3_pacing_t *p) {
    /* 更新 tokens_per_ns */
    p->tokens_per_ns = (double)p->target_bps / 8.0 / 1e9;
    
    /* 更新最大突发 (1 个 RTT 或最小 64KB) */
    double rtt_burst = p->target_bps / 8.0 * p->rtt_us / 1e6;
    p->max_burst = rtt_burst > 65536 ? rtt_burst : 65536;
}

/* =========================================================
 * Pacing API
 * ========================================================= */

v3_pacing_t* v3_pacing_create(v3_pacing_mode_t mode, uint64_t initial_bps) {
    v3_pacing_t *p = (v3_pacing_t*)calloc(1, sizeof(v3_pacing_t));
    if (!p) return NULL;
    
    p->mode = mode;
    p->target_bps = initial_bps > 0 ? initial_bps : 100000000;  /* 默认 100 Mbps */
    p->min_bps = PACING_MIN_RATE_BPS;
    p->max_bps = PACING_MAX_RATE_BPS;
    
    uint64_t now = pacing_get_time_ns();
    p->last_refill_ns = now;
    p->rng_state = now ^ 0xDEADBEEF;
    
    p->tokens = 65536;  /* 初始突发 */
    p->tokens_per_ns = (double)p->target_bps / 8.0 / 1e9;
    p->max_burst = 65536;
    
    p->rtt_us = 100000;  /* 初始假设 100ms */
    p->rtt_min_us = UINT64_MAX;
    p->srtt_us = 100000;
    p->rtt_var_us = 50000;
    
    p->state = (mode == V3_PACING_BRUTAL) ? PACING_STATE_BRUTAL : PACING_STATE_SLOW_START;
    p->cwnd = PACING_INITIAL_CWND;
    p->ssthresh = UINT64_MAX;
    
    v3_mutex_init(&p->mutex);
    
    pacing_update_rate(p);
    
    return p;
}

void v3_pacing_destroy(v3_pacing_t *p) {
    if (!p) return;
    v3_mutex_destroy(&p->mutex);
    free(p);
}

void v3_pacing_set_rate(v3_pacing_t *p, uint64_t bps) {
    if (!p) return;
    
    v3_mutex_lock(&p->mutex);
    
    if (bps < p->min_bps) bps = p->min_bps;
    if (bps > p->max_bps) bps = p->max_bps;
    
    p->target_bps = bps;
    pacing_update_rate(p);
    
    v3_mutex_unlock(&p->mutex);
}

void v3_pacing_set_range(v3_pacing_t *p, uint64_t min_bps, uint64_t max_bps) {
    if (!p) return;
    
    v3_mutex_lock(&p->mutex);
    
    p->min_bps = min_bps > 0 ? min_bps : PACING_MIN_RATE_BPS;
    p->max_bps = max_bps > 0 ? max_bps : PACING_MAX_RATE_BPS;
    
    if (p->target_bps < p->min_bps) p->target_bps = p->min_bps;
    if (p->target_bps > p->max_bps) p->target_bps = p->max_bps;
    
    pacing_update_rate(p);
    
    v3_mutex_unlock(&p->mutex);
}

void v3_pacing_enable_jitter(v3_pacing_t *p, uint32_t range_ns) {
    if (!p) return;
    
    v3_mutex_lock(&p->mutex);
    p->jitter_enabled = (range_ns > 0);
    p->jitter_range_ns = range_ns;
    v3_mutex_unlock(&p->mutex);
}

void v3_pacing_update_rtt(v3_pacing_t *p, uint64_t rtt_us) {
    if (!p || rtt_us == 0) return;
    
    v3_mutex_lock(&p->mutex);
    
    /* 限制范围 */
    if (rtt_us < PACING_MIN_RTT_US) rtt_us = PACING_MIN_RTT_US;
    if (rtt_us > PACING_MAX_RTT_US) rtt_us = PACING_MAX_RTT_US;
    
    /* 更新最小/最大 */
    if (rtt_us < p->rtt_min_us) p->rtt_min_us = rtt_us;
    if (rtt_us > p->rtt_max_us) p->rtt_max_us = rtt_us;
    
    /* EWMA 更新 (RFC 6298) */
    if (p->srtt_us == 0) {
        p->srtt_us = rtt_us;
        p->rtt_var_us = rtt_us / 2.0;
    } else {
        double diff = (double)rtt_us - p->srtt_us;
        if (diff < 0) diff = -diff;
        
        p->rtt_var_us = p->rtt_var_us * (1 - PACING_BETA) + diff * PACING_BETA;
        p->srtt_us = p->srtt_us * (1 - PACING_ALPHA) + rtt_us * PACING_ALPHA;
    }
    
    p->rtt_us = (uint64_t)(p->srtt_us + 4 * p->rtt_var_us);
    
    /* 更新带宽估计 (BBR 风格) */
    if (p->bytes_in_flight > 0 && p->mode == V3_PACING_ADAPTIVE) {
        uint64_t bw = p->bytes_in_flight * 8 * 1000000 / rtt_us;
        
        if (p->bw_estimate_bps == 0) {
            p->bw_estimate_bps = bw;
        } else {
            p->bw_estimate_bps = (uint64_t)(p->bw_estimate_bps * 0.9 + bw * 0.1);
        }
        
        /* 调整发送速率 */
        uint64_t new_target = p->bw_estimate_bps;
        if (new_target < p->min_bps) new_target = p->min_bps;
        if (new_target > p->max_bps) new_target = p->max_bps;
        
        p->target_bps = new_target;
        pacing_update_rate(p);
    }
    
    v3_mutex_unlock(&p->mutex);
}

void v3_pacing_report_loss(v3_pacing_t *p) {
    if (!p) return;
    
    v3_mutex_lock(&p->mutex);
    
    uint64_t now = pacing_get_time_ns();
    p->loss_count++;
    
    /* 避免过于频繁反应 */
    if (now - p->last_loss_ns < p->rtt_us * 1000) {
        v3_mutex_unlock(&p->mutex);
        return;
    }
    p->last_loss_ns = now;
    
    /* Brutal 模式不响应丢包 */
    if (p->mode == V3_PACING_BRUTAL) {
        v3_mutex_unlock(&p->mutex);
        return;
    }
    
    /* 拥塞控制响应 */
    switch (p->state) {
        case PACING_STATE_SLOW_START:
            p->ssthresh = p->cwnd / 2;
            if (p->ssthresh < PACING_INITIAL_CWND) {
                p->ssthresh = PACING_INITIAL_CWND;
            }
            p->cwnd = p->ssthresh;
            p->state = PACING_STATE_RECOVERY;
            break;
            
        case PACING_STATE_CONGESTION_AVOIDANCE:
            p->ssthresh = p->cwnd / 2;
            if (p->ssthresh < PACING_INITIAL_CWND) {
                p->ssthresh = PACING_INITIAL_CWND;
            }
            p->cwnd = p->ssthresh;
            p->state = PACING_STATE_RECOVERY;
            break;
            
        case PACING_STATE_RECOVERY:
            /* 已经在恢复中 */
            break;
            
        default:
            break;
    }
    
    /* 降低发送速率 */
    p->target_bps = (uint64_t)(p->target_bps * 0.7);
    if (p->target_bps < p->min_bps) {
        p->target_bps = p->min_bps;
    }
    pacing_update_rate(p);
    
    V3_LOG_DEBUG("Pacing: loss detected, new rate=%llu bps, state=%s",
                 (unsigned long long)p->target_bps,
                 pacing_state_names[p->state]);
    
    v3_mutex_unlock(&p->mutex);
}

uint64_t v3_pacing_acquire(v3_pacing_t *p, size_t bytes) {
    if (!p) return 0;
    
    v3_mutex_lock(&p->mutex);
    
    uint64_t now = pacing_get_time_ns();
    pacing_refill_tokens(p, now);
    
    /* Brutal 模式：只检查令牌 */
    if (p->mode == V3_PACING_BRUTAL) {
        if (p->tokens >= (double)bytes) {
            v3_mutex_unlock(&p->mutex);
            return 0;
        }
        
        double deficit = (double)bytes - p->tokens;
        uint64_t wait_ns = (uint64_t)(deficit / p->tokens_per_ns);
        
        if (p->jitter_enabled && p->jitter_range_ns > 0) {
            wait_ns += pacing_random(p) % p->jitter_range_ns;
        }
        
        p->throttled_count++;
        v3_mutex_unlock(&p->mutex);
        return wait_ns;
    }
    
    /* 检查拥塞窗口 */
    if (p->bytes_in_flight + bytes > p->cwnd) {
        uint64_t wait = p->rtt_us * 1000 / 4;
        p->throttled_count++;
        v3_mutex_unlock(&p->mutex);
        return wait;
    }
    
    /* 检查令牌 */
    if (p->tokens >= (double)bytes) {
        v3_mutex_unlock(&p->mutex);
        return 0;
    }
    
    /* 计算等待时间 */
    double deficit = (double)bytes - p->tokens;
    uint64_t wait_ns = (uint64_t)(deficit / p->tokens_per_ns);
    
    /* 最小间隔 */
    if (wait_ns < 10000) wait_ns = 10000;  /* 最小 10µs */
    
    /* 添加抖动 */
    if (p->jitter_enabled && p->jitter_range_ns > 0) {
        wait_ns += pacing_random(p) % p->jitter_range_ns;
    }
    
    p->throttled_count++;
    v3_mutex_unlock(&p->mutex);
    return wait_ns;
}

void v3_pacing_commit(v3_pacing_t *p, size_t bytes) {
    if (!p) return;
    
    v3_mutex_lock(&p->mutex);
    
    p->tokens -= (double)bytes;
    if (p->tokens < 0) p->tokens = 0;
    
    p->bytes_in_flight += bytes;
    p->total_bytes += bytes;
    p->total_packets++;
    
    v3_mutex_unlock(&p->mutex);
}

void v3_pacing_ack(v3_pacing_t *p, size_t bytes) {
    if (!p) return;
    
    v3_mutex_lock(&p->mutex);
    
    if (bytes > p->bytes_in_flight) {
        p->bytes_in_flight = 0;
    } else {
        p->bytes_in_flight -= bytes;
    }
    
    p->ack_count++;
    
    /* 拥塞窗口增长 */
    if (p->mode != V3_PACING_BRUTAL) {
        switch (p->state) {
            case PACING_STATE_SLOW_START:
                /* 指数增长 */
                p->cwnd += bytes;
                if (p->cwnd >= p->ssthresh) {
                    p->state = PACING_STATE_CONGESTION_AVOIDANCE;
                }
                break;
                
            case PACING_STATE_CONGESTION_AVOIDANCE:
                /* 线性增长：每 RTT 增加 1 个 MSS */
                if (p->cwnd > 0) {
                    p->cwnd += 1400 * bytes / p->cwnd;
                }
                break;
                
            case PACING_STATE_RECOVERY:
                /* 恢复完成后进入拥塞避免 */
                if (p->bytes_in_flight < p->cwnd / 2) {
                    p->state = PACING_STATE_CONGESTION_AVOIDANCE;
                }
                break;
                
            default:
                break;
        }
    }
    
    v3_mutex_unlock(&p->mutex);
}

uint64_t v3_pacing_get_rate(v3_pacing_t *p) {
    if (!p) return 0;
    return p->target_bps;
}

uint64_t v3_pacing_get_rtt(v3_pacing_t *p) {
    if (!p) return 0;
    return (uint64_t)p->srtt_us;
}

uint64_t v3_pacing_get_bandwidth(v3_pacing_t *p) {
    if (!p) return 0;
    return p->bw_estimate_bps;
}

bool v3_pacing_allow_burst(v3_pacing_t *p, size_t bytes) {
    if (!p) return false;
    
    v3_mutex_lock(&p->mutex);
    
    bool allow = false;
    
    if (p->state == PACING_STATE_SLOW_START || p->mode == V3_PACING_BRUTAL) {
        allow = (p->bytes_in_flight + bytes <= p->cwnd);
    } else {
        /* 其他状态允许最多 2 个 MSS 的突发 */
        allow = (bytes <= 2 * 1400 && p->tokens >= bytes);
    }
    
    if (allow) {
        p->burst_count++;
    }
    
    v3_mutex_unlock(&p->mutex);
    return allow;
}

void v3_pacing_get_stats(v3_pacing_t *p, v3_pacing_stats_t *stats) {
    if (!p || !stats) return;
    
    v3_mutex_lock(&p->mutex);
    
    stats->mode = p->mode;
    stats->target_bps = p->target_bps;
    stats->actual_bps = p->bw_estimate_bps;
    stats->rtt_us = (uint64_t)p->srtt_us;
    stats->rtt_min_us = p->rtt_min_us;
    stats->rtt_max_us = p->rtt_max_us;
    stats->cwnd = p->cwnd;
    stats->bytes_in_flight = p->bytes_in_flight;
    stats->total_bytes = p->total_bytes;
    stats->total_packets = p->total_packets;
    stats->throttled_count = p->throttled_count;
    stats->loss_count = p->loss_count;
    
    v3_mutex_unlock(&p->mutex);
}

