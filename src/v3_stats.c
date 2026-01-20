
/*
 * v3_stats.c - v3 统计监控实现
 * 
 * 功能：
 * - 流量统计
 * - 连接统计
 * - 性能指标
 * - 导出接口
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_stats.h"
#include "v3_log.h"
#include "v3_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/resource.h>
#endif

/* =========================================================
 * 配置
 * ========================================================= */

#define STATS_HISTORY_SIZE      60      /* 保留 60 秒历史 */
#define STATS_LATENCY_SAMPLES   1000    /* 延迟采样数 */

/* =========================================================
 * 统计上下文
 * ========================================================= */

struct v3_stats_s {
    /* 基础计数器（原子操作） */
    volatile uint64_t   packets_rx;
    volatile uint64_t   packets_tx;
    volatile uint64_t   bytes_rx;
    volatile uint64_t   bytes_tx;
    volatile uint64_t   packets_dropped;
    volatile uint64_t   packets_invalid;
    
    /* FEC 统计 */
    volatile uint64_t   fec_groups;
    volatile uint64_t   fec_recovered;
    volatile uint64_t   fec_failed;
    
    /* 连接统计 */
    volatile uint32_t   connections_active;
    volatile uint32_t   connections_total;
    
    /* 启动时间 */
    uint64_t            start_time_ns;
    
    /* 速率计算 */
    uint64_t            last_sample_time_ns;
    uint64_t            last_packets_rx;
    uint64_t            last_bytes_rx;
    uint64_t            last_packets_tx;
    uint64_t            last_bytes_tx;
    
    /* 速率历史 */
    uint64_t            pps_history[STATS_HISTORY_SIZE];
    uint64_t            bps_history[STATS_HISTORY_SIZE];
    int                 history_idx;
    
    /* 延迟统计 */
    uint64_t            latency_samples[STATS_LATENCY_SAMPLES];
    int                 latency_idx;
    int                 latency_count;
    uint64_t            latency_sum;
    uint64_t            latency_min;
    uint64_t            latency_max;
    
    /* CPU 统计（上次采样） */
    uint64_t            last_cpu_time;
    uint64_t            last_user_time;
    uint64_t            last_kernel_time;
    
    /* 同步 */
    v3_mutex_t          mutex;
    
    /* 回调 */
    v3_stats_callback_t callback;
    void               *callback_arg;
    int                 callback_interval_sec;
    uint64_t            last_callback_time_ns;
};

/* =========================================================
 * 辅助函数
 * ========================================================= */

static inline uint64_t stats_get_time_ns(void) {
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

static inline void stats_atomic_add(volatile uint64_t *ptr, uint64_t val) {
#ifdef _WIN32
    InterlockedExchangeAdd64((volatile LONG64*)ptr, val);
#else
    __sync_fetch_and_add(ptr, val);
#endif
}

static inline void stats_atomic_add32(volatile uint32_t *ptr, uint32_t val) {
#ifdef _WIN32
    InterlockedExchangeAdd((volatile LONG*)ptr, val);
#else
    __sync_fetch_and_add(ptr, val);
#endif
}

static inline void stats_atomic_sub32(volatile uint32_t *ptr, uint32_t val) {
#ifdef _WIN32
    InterlockedExchangeAdd((volatile LONG*)ptr, -(LONG)val);
#else
    __sync_fetch_and_sub(ptr, val);
#endif
}

static int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t*)a;
    uint64_t vb = *(const uint64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

static uint64_t stats_calculate_percentile(uint64_t *samples, int count, int percentile) {
    if (count == 0) return 0;
    
    /* 复制并排序 */
    uint64_t *sorted = (uint64_t*)malloc(count * sizeof(uint64_t));
    if (!sorted) return 0;
    
    memcpy(sorted, samples, count * sizeof(uint64_t));
    qsort(sorted, count, sizeof(uint64_t), compare_uint64);
    
    int idx = (count * percentile) / 100;
    if (idx >= count) idx = count - 1;
    
    uint64_t result = sorted[idx];
    free(sorted);
    
    return result;
}

/* =========================================================
 * 系统资源统计
 * ========================================================= */

static void stats_get_memory_usage(uint64_t *rss_bytes, float *percent) {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        *rss_bytes = pmc.WorkingSetSize;
    } else {
        *rss_bytes = 0;
    }
    
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        *percent = (float)(*rss_bytes * 100.0 / mem_status.ullTotalPhys);
    } else {
        *percent = 0;
    }
#else
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        *rss_bytes = 0;
        *percent = 0;
        return;
    }
    
    char line[256];
    uint64_t vm_rss = 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%lu", &vm_rss);
            break;
        }
    }
    fclose(f);
    
    *rss_bytes = vm_rss * 1024;
    
    /* 获取总内存 */
    f = fopen("/proc/meminfo", "r");
    if (!f) {
        *percent = 0;
        return;
    }
    
    uint64_t mem_total = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, "%lu", &mem_total);
            break;
        }
    }
    fclose(f);
    
    if (mem_total > 0) {
        *percent = (float)(vm_rss * 100.0 / mem_total);
    } else {
        *percent = 0;
    }
#endif
}

static float stats_get_cpu_usage(v3_stats_t *stats) {
#ifdef _WIN32
    FILETIME creation_time, exit_time, kernel_time, user_time;
    if (!GetProcessTimes(GetCurrentProcess(), &creation_time, &exit_time,
                         &kernel_time, &user_time)) {
        return 0;
    }
    
    ULARGE_INTEGER kernel, user;
    kernel.LowPart = kernel_time.dwLowDateTime;
    kernel.HighPart = kernel_time.dwHighDateTime;
    user.LowPart = user_time.dwLowDateTime;
    user.HighPart = user_time.dwHighDateTime;
    
    uint64_t now = stats_get_time_ns();
    uint64_t cpu_time = (kernel.QuadPart + user.QuadPart) * 100;  /* 100ns -> ns */
    
    float usage = 0;
    if (stats->last_cpu_time > 0) {
        uint64_t cpu_delta = cpu_time - (stats->last_user_time + stats->last_kernel_time);
        uint64_t time_delta = now - stats->last_cpu_time;
        
        if (time_delta > 0) {
            usage = (float)(cpu_delta * 100.0 / time_delta);
        }
    }
    
    stats->last_cpu_time = now;
    stats->last_user_time = user.QuadPart * 100;
    stats->last_kernel_time = kernel.QuadPart * 100;
    
    return usage;
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0;
    }
    
    uint64_t now = stats_get_time_ns();
    uint64_t user_ns = usage.ru_utime.tv_sec * 1000000000ULL + usage.ru_utime.tv_usec * 1000;
    uint64_t sys_ns = usage.ru_stime.tv_sec * 1000000000ULL + usage.ru_stime.tv_usec * 1000;
    uint64_t cpu_time = user_ns + sys_ns;
    
    float cpu_usage = 0;
    if (stats->last_cpu_time > 0) {
        uint64_t cpu_delta = cpu_time - (stats->last_user_time + stats->last_kernel_time);
        uint64_t time_delta = now - stats->last_cpu_time;
        
        if (time_delta > 0) {
            cpu_usage = (float)(cpu_delta * 100.0 / time_delta);
        }
    }
    
    stats->last_cpu_time = now;
    stats->last_user_time = user_ns;
    stats->last_kernel_time = sys_ns;
    
    return cpu_usage;
#endif
}

/* =========================================================
 * 公共 API
 * ========================================================= */

v3_stats_t* v3_stats_create(void) {
    v3_stats_t *stats = (v3_stats_t*)calloc(1, sizeof(v3_stats_t));
    if (!stats) return NULL;
    
    stats->start_time_ns = stats_get_time_ns();
    stats->last_sample_time_ns = stats->start_time_ns;
    stats->latency_min = UINT64_MAX;
    
    v3_mutex_init(&stats->mutex);
    
    return stats;
}

void v3_stats_destroy(v3_stats_t *stats) {
    if (!stats) return;
    
    v3_mutex_destroy(&stats->mutex);
    free(stats);
}

void v3_stats_reset(v3_stats_t *stats) {
    if (!stats) return;
    
    v3_mutex_lock(&stats->mutex);
    
    stats->packets_rx = 0;
    stats->packets_tx = 0;
    stats->bytes_rx = 0;
    stats->bytes_tx = 0;
    stats->packets_dropped = 0;
    stats->packets_invalid = 0;
    
    stats->fec_groups = 0;
    stats->fec_recovered = 0;
    stats->fec_failed = 0;
    
    stats->connections_total = stats->connections_active;
    
    memset(stats->pps_history, 0, sizeof(stats->pps_history));
    memset(stats->bps_history, 0, sizeof(stats->bps_history));
    stats->history_idx = 0;
    
    memset(stats->latency_samples, 0, sizeof(stats->latency_samples));
    stats->latency_idx = 0;
    stats->latency_count = 0;
    stats->latency_sum = 0;
    stats->latency_min = UINT64_MAX;
    stats->latency_max = 0;
    
    stats->start_time_ns = stats_get_time_ns();
    stats->last_sample_time_ns = stats->start_time_ns;
    
    v3_mutex_unlock(&stats->mutex);
}

/* =========================================================
 * 记录接口
 * ========================================================= */

void v3_stats_record_rx(v3_stats_t *stats, size_t bytes) {
    if (!stats) return;
    stats_atomic_add(&stats->packets_rx, 1);
    stats_atomic_add(&stats->bytes_rx, bytes);
}

void v3_stats_record_tx(v3_stats_t *stats, size_t bytes) {
    if (!stats) return;
    stats_atomic_add(&stats->packets_tx, 1);
    stats_atomic_add(&stats->bytes_tx, bytes);
}

void v3_stats_record_drop(v3_stats_t *stats, int reason) {
    if (!stats) return;
    stats_atomic_add(&stats->packets_dropped, 1);
    if (reason == 1) {
        stats_atomic_add(&stats->packets_invalid, 1);
    }
}

void v3_stats_record_fec(v3_stats_t *stats, bool recovered) {
    if (!stats) return;
    stats_atomic_add(&stats->fec_groups, 1);
    if (recovered) {
        stats_atomic_add(&stats->fec_recovered, 1);
    } else {
        stats_atomic_add(&stats->fec_failed, 1);
    }
}

void v3_stats_record_latency(v3_stats_t *stats, uint64_t latency_us) {
    if (!stats) return;
    
    v3_mutex_lock(&stats->mutex);
    
    stats->latency_samples[stats->latency_idx] = latency_us;
    stats->latency_idx = (stats->latency_idx + 1) % STATS_LATENCY_SAMPLES;
    if (stats->latency_count < STATS_LATENCY_SAMPLES) {
        stats->latency_count++;
    }
    
    stats->latency_sum += latency_us;
    if (latency_us < stats->latency_min) stats->latency_min = latency_us;
    if (latency_us > stats->latency_max) stats->latency_max = latency_us;
    
    v3_mutex_unlock(&stats->mutex);
}

void v3_stats_record_connection(v3_stats_t *stats, bool connected) {
    if (!stats) return;
    
    if (connected) {
        stats_atomic_add32(&stats->connections_active, 1);
        stats_atomic_add32(&stats->connections_total, 1);
    } else {
        stats_atomic_sub32(&stats->connections_active, 1);
    }
}

/* =========================================================
 * 快照获取
 * ========================================================= */

void v3_stats_snapshot(v3_stats_t *stats, v3_stats_snapshot_t *snapshot) {
    if (!stats || !snapshot) return;
    
    memset(snapshot, 0, sizeof(*snapshot));
    
    uint64_t now = stats_get_time_ns();
    
    v3_mutex_lock(&stats->mutex);
    
    /* 基础信息 */
    snapshot->uptime_sec = (now - stats->start_time_ns) / 1000000000ULL;
    
    /* 流量统计 */
    snapshot->packets_rx = stats->packets_rx;
    snapshot->packets_tx = stats->packets_tx;
    snapshot->bytes_rx = stats->bytes_rx;
    snapshot->bytes_tx = stats->bytes_tx;
    snapshot->packets_dropped = stats->packets_dropped;
    snapshot->packets_invalid = stats->packets_invalid;
    
    /* 计算速率 */
    uint64_t elapsed_ns = now - stats->last_sample_time_ns;
    if (elapsed_ns > 0) {
        uint64_t pkt_delta = stats->packets_rx - stats->last_packets_rx +
                            stats->packets_tx - stats->last_packets_tx;
        uint64_t byte_delta = stats->bytes_rx - stats->last_bytes_rx +
                             stats->bytes_tx - stats->last_bytes_tx;
        
        snapshot->packets_per_sec = (pkt_delta * 1000000000ULL) / elapsed_ns;
        snapshot->bytes_per_sec = (byte_delta * 1000000000ULL) / elapsed_ns;
        
        /* 更新历史 */
        stats->pps_history[stats->history_idx] = snapshot->packets_per_sec;
        stats->bps_history[stats->history_idx] = snapshot->bytes_per_sec;
        stats->history_idx = (stats->history_idx + 1) % STATS_HISTORY_SIZE;
        
        /* 更新采样点 */
        stats->last_sample_time_ns = now;
        stats->last_packets_rx = stats->packets_rx;
        stats->last_bytes_rx = stats->bytes_rx;
        stats->last_packets_tx = stats->packets_tx;
        stats->last_bytes_tx = stats->bytes_tx;
    }
    
    /* FEC 统计 */
    snapshot->fec_groups = stats->fec_groups;
    snapshot->fec_recovered = stats->fec_recovered;
    snapshot->fec_failed = stats->fec_failed;
    if (stats->fec_groups > 0) {
        snapshot->fec_recovery_rate = (float)stats->fec_recovered * 100.0f / stats->fec_groups;
    }
    
    /* 连接统计 */
    snapshot->connections_active = stats->connections_active;
    snapshot->connections_total = stats->connections_total;
    
    /* 延迟统计 */
    if (stats->latency_count > 0) {
        snapshot->latency_avg_us = stats->latency_sum / stats->latency_count;
        snapshot->latency_min_us = stats->latency_min;
        snapshot->latency_max_us = stats->latency_max;
        snapshot->latency_p50_us = stats_calculate_percentile(
            stats->latency_samples, stats->latency_count, 50);
        snapshot->latency_p99_us = stats_calculate_percentile(
            stats->latency_samples, stats->latency_count, 99);
    }
    
    v3_mutex_unlock(&stats->mutex);
    
    /* 系统资源（不需要锁） */
    stats_get_memory_usage(&snapshot->memory_bytes, &snapshot->memory_percent);
    snapshot->cpu_usage = stats_get_cpu_usage(stats);
}

/* =========================================================
 * 输出接口
 * ========================================================= */

void v3_stats_print(v3_stats_t *stats) {
    v3_stats_snapshot_t snap;
    v3_stats_snapshot(stats, &snap);
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 Statistics                              ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    /* 运行时间 */
    int days = snap.uptime_sec / 86400;
    int hours = (snap.uptime_sec % 86400) / 3600;
    int mins = (snap.uptime_sec % 3600) / 60;
    int secs = snap.uptime_sec % 60;
    printf("║  Uptime:        %d days, %02d:%02d:%02d                            ║\n",
           days, hours, mins, secs);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Traffic                                                      ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    
    double rx_mb = snap.bytes_rx / (1024.0 * 1024.0);
    double tx_mb = snap.bytes_tx / (1024.0 * 1024.0);
    double throughput_mbps = (snap.bytes_per_sec * 8.0) / (1024.0 * 1024.0);
    
    printf("║  RX:            %10lu pkts  %10.2f MB                ║\n", 
           (unsigned long)snap.packets_rx, rx_mb);
    printf("║  TX:            %10lu pkts  %10.2f MB                ║\n",
           (unsigned long)snap.packets_tx, tx_mb);
    printf("║  Throughput:    %10.2f Mbps                              ║\n",
           throughput_mbps);
    printf("║  Dropped:       %10lu  Invalid: %10lu              ║\n",
           (unsigned long)snap.packets_dropped, (unsigned long)snap.packets_invalid);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  FEC                                                          ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Groups:        %10lu                                    ║\n",
           (unsigned long)snap.fec_groups);
    printf("║  Recovered:     %10lu  Failed: %10lu              ║\n",
           (unsigned long)snap.fec_recovered, (unsigned long)snap.fec_failed);
    printf("║  Recovery Rate: %6.2f%%                                       ║\n",
           snap.fec_recovery_rate);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Latency                                                      ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Avg:           %10lu µs                                 ║\n",
           (unsigned long)snap.latency_avg_us);
    printf("║  P50:           %10lu µs                                 ║\n",
           (unsigned long)snap.latency_p50_us);
    printf("║  P99:           %10lu µs                                 ║\n",
           (unsigned long)snap.latency_p99_us);
    
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  System                                                       ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  CPU Usage:     %6.2f%%                                       ║\n",
           snap.cpu_usage);
    printf("║  Memory:        %6.2f MB (%.2f%%)                            ║\n",
           snap.memory_bytes / (1024.0 * 1024.0), snap.memory_percent);
    printf("║  Connections:   %10u active / %10u total          ║\n",
           snap.connections_active, snap.connections_total);
    
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

int v3_stats_to_json(v3_stats_t *stats, char *buf, size_t buflen) {
    v3_stats_snapshot_t snap;
    v3_stats_snapshot(stats, &snap);
    
    return snprintf(buf, buflen,
        "{\n"
        "  \"uptime_sec\": %lu,\n"
        "  \"traffic\": {\n"
        "    \"packets_rx\": %lu,\n"
        "    \"packets_tx\": %lu,\n"
        "    \"bytes_rx\": %lu,\n"
        "    \"bytes_tx\": %lu,\n"
        "    \"packets_per_sec\": %lu,\n"
        "    \"bytes_per_sec\": %lu,\n"
        "    \"dropped\": %lu,\n"
        "    \"invalid\": %lu\n"
        "  },\n"
        "  \"fec\": {\n"
        "    \"groups\": %lu,\n"
        "    \"recovered\": %lu,\n"
        "    \"failed\": %lu,\n"
        "    \"recovery_rate\": %.2f\n"
        "  },\n"
        "  \"latency\": {\n"
        "    \"avg_us\": %lu,\n"
        "    \"min_us\": %lu,\n"
        "    \"max_us\": %lu,\n"
        "    \"p50_us\": %lu,\n"
        "    \"p99_us\": %lu\n"
        "  },\n"
        "  \"system\": {\n"
        "    \"cpu_usage\": %.2f,\n"
        "    \"memory_bytes\": %lu,\n"
        "    \"memory_percent\": %.2f\n"
        "  },\n"
        "  \"connections\": {\n"
        "    \"active\": %u,\n"
        "    \"total\": %u\n"
        "  }\n"
        "}\n",
        (unsigned long)snap.uptime_sec,
        (unsigned long)snap.packets_rx,
        (unsigned long)snap.packets_tx,
        (unsigned long)snap.bytes_rx,
        (unsigned long)snap.bytes_tx,
        (unsigned long)snap.packets_per_sec,
        (unsigned long)snap.bytes_per_sec,
        (unsigned long)snap.packets_dropped,
        (unsigned long)snap.packets_invalid,
        (unsigned long)snap.fec_groups,
        (unsigned long)snap.fec_recovered,
        (unsigned long)snap.fec_failed,
        snap.fec_recovery_rate,
        (unsigned long)snap.latency_avg_us,
        (unsigned long)snap.latency_min_us,
        (unsigned long)snap.latency_max_us,
        (unsigned long)snap.latency_p50_us,
        (unsigned long)snap.latency_p99_us,
        snap.cpu_usage,
        (unsigned long)snap.memory_bytes,
        snap.memory_percent,
        snap.connections_active,
        snap.connections_total
    );
}

void v3_stats_set_callback(v3_stats_t *stats, v3_stats_callback_t callback, 
                           void *arg, int interval_sec) {
    if (!stats) return;
    
    v3_mutex_lock(&stats->mutex);
    stats->callback = callback;
    stats->callback_arg = arg;
    stats->callback_interval_sec = interval_sec;
    stats->last_callback_time_ns = stats_get_time_ns();
    v3_mutex_unlock(&stats->mutex);
}

void v3_stats_tick(v3_stats_t *stats) {
    if (!stats || !stats->callback) return;
    
    uint64_t now = stats_get_time_ns();
    uint64_t elapsed = now - stats->last_callback_time_ns;
    
    if (elapsed >= (uint64_t)stats->callback_interval_sec * 1000000000ULL) {
        v3_stats_snapshot_t snap;
        v3_stats_snapshot(stats, &snap);
        
        stats->callback(&snap, stats->callback_arg);
        stats->last_callback_time_ns = now;
    }
}
