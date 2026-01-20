
/*
 * v3_connection.c - v3 连接管理实现
 * 
 * 功能：
 * - 连接状态机
 * - 会话管理
 * - 心跳保活
 * - 超时处理
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_connection.h"
#include "v3_protocol.h"
#include "v3_crypto.h"
#include "v3_log.h"
#include "v3_platform.h"
#include "v3_error.h"
#include "v3_buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

/* =========================================================
 * 配置常量
 * ========================================================= */

#define CONN_KEEPALIVE_INTERVAL_MS      30000       /* 30秒 */
#define CONN_TIMEOUT_MS                 300000      /* 5分钟 */
#define CONN_HANDSHAKE_TIMEOUT_MS       10000       /* 10秒 */
#define CONN_MAX_RETRIES                5
#define CONN_RETRY_INTERVAL_MS          1000
#define CONN_RECV_QUEUE_SIZE            256
#define CONN_SEND_QUEUE_SIZE            256

/* =========================================================
 * 连接状态
 * ========================================================= */

typedef enum {
    CONN_STATE_IDLE = 0,
    CONN_STATE_CONNECTING,
    CONN_STATE_HANDSHAKING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_CLOSING,
    CONN_STATE_CLOSED,
    CONN_STATE_ERROR,
} conn_state_t;

static const char* conn_state_names[] = {
    "IDLE",
    "CONNECTING",
    "HANDSHAKING",
    "ESTABLISHED",
    "CLOSING",
    "CLOSED",
    "ERROR"
};

/* =========================================================
 * 发送/接收队列项
 * ========================================================= */

typedef struct {
    v3_buffer_t    *buffer;
    uint64_t        timestamp_ns;
    uint32_t        seq;
    uint8_t         retries;
    bool            acked;
} send_queue_item_t;

typedef struct {
    v3_buffer_t    *buffer;
    uint64_t        timestamp_ns;
    uint32_t        seq;
} recv_queue_item_t;

/* =========================================================
 * 连接结构
 * ========================================================= */

struct v3_connection_s {
    /* 基本信息 */
    uint64_t            id;
    conn_state_t        state;
    v3_conn_type_t      type;
    
    /* 会话信息 */
    uint64_t            session_token;
    uint16_t            intent_id;
    uint16_t            stream_id;
    
    /* 协议上下文 */
    v3_protocol_ctx_t  *protocol;
    
    /* 缓冲区池 */
    v3_buffer_pool_t   *buffer_pool;
    
    /* 地址信息 */
    v3_addr_t           local_addr;
    v3_addr_t           remote_addr;
    
    /* 发送队列 */
    send_queue_item_t   send_queue[CONN_SEND_QUEUE_SIZE];
    size_t              send_queue_head;
    size_t              send_queue_tail;
    size_t              send_queue_count;
    uint32_t            send_seq;
    
    /* 接收队列 */
    recv_queue_item_t   recv_queue[CONN_RECV_QUEUE_SIZE];
    size_t              recv_queue_head;
    size_t              recv_queue_tail;
    size_t              recv_queue_count;
    uint32_t            recv_seq_expected;
    
    /* 时间戳 */
    uint64_t            created_time_ns;
    uint64_t            last_send_time_ns;
    uint64_t            last_recv_time_ns;
    uint64_t            last_keepalive_ns;
    
    /* RTT 估算 */
    uint64_t            rtt_us;
    uint64_t            rtt_var_us;
    uint64_t            srtt_us;
    
    /* 统计 */
    v3_conn_stats_t     stats;
    
    /* 回调 */
    v3_conn_callback_t  callback;
    void               *callback_arg;
    
    /* 用户数据 */
    void               *user_data;
    
    /* 同步 */
    v3_mutex_t          mutex;
    
    /* 错误信息 */
    v3_error_t          last_error;
    char                error_msg[256];
};

/* =========================================================
 * 连接管理器结构
 * ========================================================= */

struct v3_conn_manager_s {
    /* 连接表 */
    v3_connection_t   **connections;
    size_t              capacity;
    size_t              count;
    
    /* ID 生成 */
    uint64_t            next_id;
    
    /* 配置 */
    v3_conn_config_t    config;
    
    /* 缓冲区池 */
    v3_buffer_pool_t   *buffer_pool;
    
    /* 同步 */
    v3_mutex_t          mutex;
    
    /* 统计 */
    uint64_t            total_created;
    uint64_t            total_closed;
};

/* =========================================================
 * 辅助函数
 * ========================================================= */

static inline uint64_t conn_get_time_ns(void) {
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

static void conn_set_state(v3_connection_t *conn, conn_state_t new_state) {
    if (conn->state != new_state) {
        V3_LOG_DEBUG("Connection %llu: state %s -> %s",
                     (unsigned long long)conn->id,
                     conn_state_names[conn->state],
                     conn_state_names[new_state]);
        
        conn_state_t old_state = conn->state;
        conn->state = new_state;
        
        /* 触发回调 */
        if (conn->callback) {
            v3_conn_event_t event;
            switch (new_state) {
                case CONN_STATE_ESTABLISHED:
                    event = V3_CONN_EVENT_CONNECTED;
                    break;
                case CONN_STATE_CLOSED:
                    event = V3_CONN_EVENT_CLOSED;
                    break;
                case CONN_STATE_ERROR:
                    event = V3_CONN_EVENT_ERROR;
                    break;
                default:
                    return;
            }
            conn->callback(conn, event, conn->callback_arg);
        }
    }
}

static void conn_update_rtt(v3_connection_t *conn, uint64_t sample_us) {
    if (conn->srtt_us == 0) {
        /* 第一个样本 */
        conn->srtt_us = sample_us;
        conn->rtt_var_us = sample_us / 2;
    } else {
        /* EWMA 更新 (RFC 6298) */
        int64_t diff = (int64_t)sample_us - (int64_t)conn->srtt_us;
        if (diff < 0) diff = -diff;
        
        conn->rtt_var_us = (conn->rtt_var_us * 3 + diff) / 4;
        conn->srtt_us = (conn->srtt_us * 7 + sample_us) / 8;
    }
    
    /* RTO = SRTT + 4 * RTTVAR */
    conn->rtt_us = conn->srtt_us + 4 * conn->rtt_var_us;
    
    /* 限制范围 */
    if (conn->rtt_us < 10000) conn->rtt_us = 10000;      /* 最小 10ms */
    if (conn->rtt_us > 60000000) conn->rtt_us = 60000000; /* 最大 60s */
}

/* =========================================================
 * 连接管理器 API
 * ========================================================= */

v3_conn_manager_t* v3_conn_manager_create(const v3_conn_config_t *config) {
    v3_conn_manager_t *mgr = (v3_conn_manager_t*)calloc(1, sizeof(v3_conn_manager_t));
    if (!mgr) return NULL;
    
    /* 默认配置 */
    if (config) {
        memcpy(&mgr->config, config, sizeof(v3_conn_config_t));
    } else {
        mgr->config.max_connections = 1024;
        mgr->config.keepalive_interval_ms = CONN_KEEPALIVE_INTERVAL_MS;
        mgr->config.timeout_ms = CONN_TIMEOUT_MS;
        mgr->config.max_retries = CONN_MAX_RETRIES;
    }
    
    /* 分配连接表 */
    mgr->capacity = mgr->config.max_connections;
    mgr->connections = (v3_connection_t**)calloc(mgr->capacity, sizeof(v3_connection_t*));
    if (!mgr->connections) {
        free(mgr);
        return NULL;
    }
    
    /* 创建缓冲区池 */
    mgr->buffer_pool = v3_buffer_pool_create(2048, 256, 4096);
    
    mgr->next_id = 1;
    
    v3_mutex_init(&mgr->mutex);
    
    V3_LOG_INFO("Connection manager created: max=%zu", mgr->capacity);
    
    return mgr;
}

void v3_conn_manager_destroy(v3_conn_manager_t *mgr) {
    if (!mgr) return;
    
    v3_mutex_lock(&mgr->mutex);
    
    /* 关闭所有连接 */
    for (size_t i = 0; i < mgr->capacity; i++) {
        if (mgr->connections[i]) {
            v3_conn_close(mgr->connections[i]);
            v3_conn_destroy(mgr->connections[i]);
            mgr->connections[i] = NULL;
        }
    }
    
    v3_mutex_unlock(&mgr->mutex);
    
    if (mgr->buffer_pool) {
        v3_buffer_pool_destroy(mgr->buffer_pool);
    }
    
    free(mgr->connections);
    v3_mutex_destroy(&mgr->mutex);
    free(mgr);
    
    V3_LOG_INFO("Connection manager destroyed");
}

/* =========================================================
 * 连接创建/销毁
 * ========================================================= */

v3_connection_t* v3_conn_create(v3_conn_manager_t *mgr, v3_conn_type_t type) {
    if (!mgr) return NULL;
    
    v3_mutex_lock(&mgr->mutex);
    
    /* 检查容量 */
    if (mgr->count >= mgr->capacity) {
        v3_mutex_unlock(&mgr->mutex);
        V3_LOG_WARN("Connection limit reached: %zu", mgr->capacity);
        return NULL;
    }
    
    /* 查找空闲槽位 */
    size_t slot = 0;
    for (; slot < mgr->capacity; slot++) {
        if (!mgr->connections[slot]) break;
    }
    
    if (slot >= mgr->capacity) {
        v3_mutex_unlock(&mgr->mutex);
        return NULL;
    }
    
    /* 分配连接 */
    v3_connection_t *conn = (v3_connection_t*)calloc(1, sizeof(v3_connection_t));
    if (!conn) {
        v3_mutex_unlock(&mgr->mutex);
        return NULL;
    }
    
    conn->id = mgr->next_id++;
    conn->type = type;
    conn->state = CONN_STATE_IDLE;
    conn->buffer_pool = mgr->buffer_pool;
    
    /* 创建协议上下文 */
    conn->protocol = v3_protocol_create();
    if (!conn->protocol) {
        free(conn);
        v3_mutex_unlock(&mgr->mutex);
        return NULL;
    }
    
    /* 生成会话令牌 */
    v3_crypto_random((uint8_t*)&conn->session_token, sizeof(conn->session_token));
    
    conn->created_time_ns = conn_get_time_ns();
    conn->rtt_us = 100000;  /* 初始假设 100ms */
    
    v3_mutex_init(&conn->mutex);
    
    /* 加入管理器 */
    mgr->connections[slot] = conn;
    mgr->count++;
    mgr->total_created++;
    
    v3_mutex_unlock(&mgr->mutex);
    
    V3_LOG_DEBUG("Connection created: id=%llu, type=%d",
                 (unsigned long long)conn->id, type);
    
    return conn;
}

void v3_conn_destroy(v3_connection_t *conn) {
    if (!conn) return;
    
    /* 确保已关闭 */
    if (conn->state != CONN_STATE_CLOSED && conn->state != CONN_STATE_IDLE) {
        v3_conn_close(conn);
    }
    
    v3_mutex_lock(&conn->mutex);
    
    /* 清理发送队列 */
    for (size_t i = 0; i < CONN_SEND_QUEUE_SIZE; i++) {
        if (conn->send_queue[i].buffer) {
            v3_buffer_free(conn->send_queue[i].buffer);
            conn->send_queue[i].buffer = NULL;
        }
    }
    
    /* 清理接收队列 */
    for (size_t i = 0; i < CONN_RECV_QUEUE_SIZE; i++) {
        if (conn->recv_queue[i].buffer) {
            v3_buffer_free(conn->recv_queue[i].buffer);
            conn->recv_queue[i].buffer = NULL;
        }
    }
    
    /* 销毁协议上下文 */
    if (conn->protocol) {
        v3_protocol_destroy(conn->protocol);
        conn->protocol = NULL;
    }
    
    v3_mutex_unlock(&conn->mutex);
    v3_mutex_destroy(&conn->mutex);
    
    V3_LOG_DEBUG("Connection destroyed: id=%llu", (unsigned long long)conn->id);
    
    free(conn);
}

/* =========================================================
 * 连接操作
 * ========================================================= */

v3_error_t v3_conn_set_key(v3_connection_t *conn, const uint8_t *key, size_t len) {
    if (!conn || !key || len != 32) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&conn->mutex);
    v3_error_t err = v3_protocol_set_key(conn->protocol, key, len);
    v3_mutex_unlock(&conn->mutex);
    
    return err;
}

v3_error_t v3_conn_connect(v3_connection_t *conn, const v3_addr_t *remote) {
    if (!conn || !remote) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&conn->mutex);
    
    if (conn->state != CONN_STATE_IDLE) {
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_CONN_INVALID_STATE;
    }
    
    memcpy(&conn->remote_addr, remote, sizeof(v3_addr_t));
    conn_set_state(conn, CONN_STATE_CONNECTING);
    
    /* 设置会话信息 */
    v3_protocol_set_session(conn->protocol, conn->session_token,
                            conn->intent_id, conn->stream_id);
    
    v3_mutex_unlock(&conn->mutex);
    
    return V3_OK;
}

void v3_conn_close(v3_connection_t *conn) {
    if (!conn) return;
    
    v3_mutex_lock(&conn->mutex);
    
    if (conn->state == CONN_STATE_CLOSED || conn->state == CONN_STATE_IDLE) {
        v3_mutex_unlock(&conn->mutex);
        return;
    }
    
    conn_set_state(conn, CONN_STATE_CLOSING);
    
    /* TODO: 发送 FIN 包 */
    
    conn_set_state(conn, CONN_STATE_CLOSED);
    
    v3_mutex_unlock(&conn->mutex);
}

/* =========================================================
 * 数据发送/接收
 * ========================================================= */

v3_error_t v3_conn_send(v3_connection_t *conn, const uint8_t *data, size_t len) {
    if (!conn || !data || len == 0) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&conn->mutex);
    
    if (conn->state != CONN_STATE_ESTABLISHED) {
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_CONN_NOT_CONNECTED;
    }
    
    /* 检查发送队列 */
    if (conn->send_queue_count >= CONN_SEND_QUEUE_SIZE) {
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_QUEUE_FULL;
    }
    
    /* 分配缓冲区 */
    v3_buffer_t *buf = v3_buffer_alloc_size(conn->buffer_pool, len + 64);
    if (!buf) {
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_NO_MEMORY;
    }
    
    /* 构建数据包 */
    size_t packet_len;
    v3_error_t err = v3_protocol_build_packet(
        conn->protocol, data, len, 0,
        v3_buffer_data(buf), &packet_len
    );
    
    if (err != V3_OK) {
        v3_buffer_free(buf);
        v3_mutex_unlock(&conn->mutex);
        return err;
    }
    
    v3_buffer_set_size(buf, packet_len);
    
    /* 加入发送队列 */
    size_t idx = conn->send_queue_tail;
    conn->send_queue[idx].buffer = buf;
    conn->send_queue[idx].timestamp_ns = conn_get_time_ns();
    conn->send_queue[idx].seq = conn->send_seq++;
    conn->send_queue[idx].retries = 0;
    conn->send_queue[idx].acked = false;
    
    conn->send_queue_tail = (conn->send_queue_tail + 1) % CONN_SEND_QUEUE_SIZE;
    conn->send_queue_count++;
    
    conn->stats.packets_sent++;
    conn->stats.bytes_sent += packet_len;
    
    v3_mutex_unlock(&conn->mutex);
    
    return V3_OK;
}

v3_error_t v3_conn_recv(v3_connection_t *conn, uint8_t *data, size_t *len) {
    if (!conn || !data || !len) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&conn->mutex);
    
    if (conn->recv_queue_count == 0) {
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_WOULD_BLOCK;
    }
    
    /* 从接收队列取出 */
    size_t idx = conn->recv_queue_head;
    v3_buffer_t *buf = conn->recv_queue[idx].buffer;
    
    size_t copy_len = v3_buffer_size(buf);
    if (copy_len > *len) {
        copy_len = *len;
    }
    
    memcpy(data, v3_buffer_data(buf), copy_len);
    *len = copy_len;
    
    v3_buffer_free(buf);
    conn->recv_queue[idx].buffer = NULL;
    
    conn->recv_queue_head = (conn->recv_queue_head + 1) % CONN_RECV_QUEUE_SIZE;
    conn->recv_queue_count--;
    
    v3_mutex_unlock(&conn->mutex);
    
    return V3_OK;
}

/* =========================================================
 * 包处理
 * ========================================================= */

v3_error_t v3_conn_process_packet(v3_connection_t *conn, 
                                   const uint8_t *packet, 
                                   size_t len) {
    if (!conn || !packet) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&conn->mutex);
    
    uint64_t now = conn_get_time_ns();
    conn->last_recv_time_ns = now;
    
    /* 解析包 */
    v3_packet_info_t info;
    uint8_t payload[2048];
    size_t payload_len;
    
    v3_error_t err = v3_protocol_parse_packet(
        conn->protocol, packet, len,
        &info, payload, &payload_len
    );
    
    if (err != V3_OK) {
        conn->stats.packets_invalid++;
        v3_mutex_unlock(&conn->mutex);
        return err;
    }
    
    conn->stats.packets_recv++;
    conn->stats.bytes_recv += len;
    
    /* 处理控制包 */
    if (v3_protocol_is_keepalive(&info)) {
        /* 收到心跳，回复 */
        v3_mutex_unlock(&conn->mutex);
        return V3_OK;
    }
    
    if (v3_protocol_is_ack(&info)) {
        /* 处理 ACK */
        if (payload_len >= 4) {
            uint32_t ack_seq = payload[0] | (payload[1] << 8) | 
                              (payload[2] << 16) | (payload[3] << 24);
            
            /* 标记已确认的包 */
            for (size_t i = 0; i < CONN_SEND_QUEUE_SIZE; i++) {
                if (conn->send_queue[i].buffer && 
                    conn->send_queue[i].seq == ack_seq) {
                    
                    /* 更新 RTT */
                    uint64_t rtt = (now - conn->send_queue[i].timestamp_ns) / 1000;
                    conn_update_rtt(conn, rtt);
                    
                    conn->send_queue[i].acked = true;
                    break;
                }
            }
        }
        v3_mutex_unlock(&conn->mutex);
        return V3_OK;
    }
    
    /* 数据包 - 加入接收队列 */
    if (conn->recv_queue_count >= CONN_RECV_QUEUE_SIZE) {
        conn->stats.packets_dropped++;
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_QUEUE_FULL;
    }
    
    v3_buffer_t *buf = v3_buffer_alloc_size(conn->buffer_pool, payload_len);
    if (!buf) {
        v3_mutex_unlock(&conn->mutex);
        return V3_ERR_NO_MEMORY;
    }
    
    memcpy(v3_buffer_data(buf), payload, payload_len);
    v3_buffer_set_size(buf, payload_len);
    
    size_t idx = conn->recv_queue_tail;
    conn->recv_queue[idx].buffer = buf;
    conn->recv_queue[idx].timestamp_ns = now;
    
    conn->recv_queue_tail = (conn->recv_queue_tail + 1) % CONN_RECV_QUEUE_SIZE;
    conn->recv_queue_count++;
    
    /* 触发回调 */
    if (conn->callback) {
        conn->callback(conn, V3_CONN_EVENT_DATA, conn->callback_arg);
    }
    
    v3_mutex_unlock(&conn->mutex);
    
    return V3_OK;
}

/* =========================================================
 * 定时处理
 * ========================================================= */

void v3_conn_tick(v3_connection_t *conn) {
    if (!conn) return;
    
    v3_mutex_lock(&conn->mutex);
    
    uint64_t now = conn_get_time_ns();
    
    /* 检查超时 */
    if (conn->state == CONN_STATE_ESTABLISHED) {
        uint64_t idle_ms = (now - conn->last_recv_time_ns) / 1000000;
        
        if (idle_ms > CONN_TIMEOUT_MS) {
            V3_LOG_WARN("Connection %llu timeout", (unsigned long long)conn->id);
            conn_set_state(conn, CONN_STATE_ERROR);
            conn->last_error = V3_ERR_CONN_TIMEOUT;
            v3_mutex_unlock(&conn->mutex);
            return;
        }
        
        /* 发送心跳 */
        uint64_t keepalive_ms = (now - conn->last_keepalive_ns) / 1000000;
        if (keepalive_ms >= CONN_KEEPALIVE_INTERVAL_MS) {
            /* 构建心跳包 */
            uint8_t keepalive[64];
            size_t keepalive_len;
            
            v3_error_t err = v3_protocol_build_keepalive(
                conn->protocol, keepalive, &keepalive_len
            );
            
            if (err == V3_OK) {
                /* TODO: 发送心跳包 */
                conn->last_keepalive_ns = now;
            }
        }
    }
    
    /* 清理已确认的发送队列项 */
    while (conn->send_queue_count > 0) {
        size_t idx = conn->send_queue_head;
        if (!conn->send_queue[idx].acked) break;
        
        v3_buffer_free(conn->send_queue[idx].buffer);
        conn->send_queue[idx].buffer = NULL;
        
        conn->send_queue_head = (conn->send_queue_head + 1) % CONN_SEND_QUEUE_SIZE;
        conn->send_queue_count--;
    }
    
    /* 重传超时的包 */
    for (size_t i = 0; i < conn->send_queue_count; i++) {
        size_t idx = (conn->send_queue_head + i) % CONN_SEND_QUEUE_SIZE;
        send_queue_item_t *item = &conn->send_queue[idx];
        
        if (!item->buffer || item->acked) continue;
        
        uint64_t elapsed_us = (now - item->timestamp_ns) / 1000;
        if (elapsed_us > conn->rtt_us) {
            if (item->retries >= CONN_MAX_RETRIES) {
                V3_LOG_WARN("Packet seq=%u exceeded max retries", item->seq);
                conn_set_state(conn, CONN_STATE_ERROR);
                break;
            }
            
            item->retries++;
            item->timestamp_ns = now;
            conn->stats.retransmissions++;
            
            V3_LOG_DEBUG("Retransmitting packet seq=%u, retry=%d",
                        item->seq, item->retries);
            
            /* TODO: 重传包 */
        }
    }
    
    v3_mutex_unlock(&conn->mutex);
}

/* =========================================================
 * 属性访问
 * ========================================================= */

uint64_t v3_conn_get_id(v3_connection_t *conn) {
    return conn ? conn->id : 0;
}

v3_conn_state_t v3_conn_get_state(v3_connection_t *conn) {
    if (!conn) return V3_CONN_STATE_CLOSED;
    
    switch (conn->state) {
        case CONN_STATE_IDLE:       return V3_CONN_STATE_IDLE;
        case CONN_STATE_CONNECTING: return V3_CONN_STATE_CONNECTING;
        case CONN_STATE_HANDSHAKING:return V3_CONN_STATE_CONNECTING;
        case CONN_STATE_ESTABLISHED:return V3_CONN_STATE_CONNECTED;
        case CONN_STATE_CLOSING:    return V3_CONN_STATE_CLOSING;
        case CONN_STATE_CLOSED:     return V3_CONN_STATE_CLOSED;
        case CONN_STATE_ERROR:      return V3_CONN_STATE_ERROR;
        default:                    return V3_CONN_STATE_CLOSED;
    }
}

void v3_conn_get_stats(v3_connection_t *conn, v3_conn_stats_t *stats) {
    if (!conn || !stats) return;
    
    v3_mutex_lock(&conn->mutex);
    memcpy(stats, &conn->stats, sizeof(v3_conn_stats_t));
    stats->rtt_us = conn->srtt_us;
    v3_mutex_unlock(&conn->mutex);
}

void v3_conn_set_callback(v3_connection_t *conn, v3_conn_callback_t cb, void *arg) {
    if (!conn) return;
    
    v3_mutex_lock(&conn->mutex);
    conn->callback = cb;
    conn->callback_arg = arg;
    v3_mutex_unlock(&conn->mutex);
}

void v3_conn_set_user_data(v3_connection_t *conn, void *data) {
    if (conn) conn->user_data = data;
}

void* v3_conn_get_user_data(v3_connection_t *conn) {
    return conn ? conn->user_data : NULL;
}

v3_buffer_t* v3_conn_get_pending_send(v3_connection_t *conn) {
    if (!conn) return NULL;
    
    v3_mutex_lock(&conn->mutex);
    
    if (conn->send_queue_count == 0) {
        v3_mutex_unlock(&conn->mutex);
        return NULL;
    }
    
    /* 查找未发送的包 */
    for (size_t i = 0; i < conn->send_queue_count; i++) {
        size_t idx = (conn->send_queue_head + i) % CONN_SEND_QUEUE_SIZE;
        send_queue_item_t *item = &conn->send_queue[idx];
        
        if (item->buffer && !item->acked) {
            v3_buffer_t *buf = v3_buffer_ref(item->buffer);
            v3_mutex_unlock(&conn->mutex);
            return buf;
        }
    }
    
    v3_mutex_unlock(&conn->mutex);
    return NULL;
}

bool v3_conn_has_pending_recv(v3_connection_t *conn) {
    if (!conn) return false;
    
    v3_mutex_lock(&conn->mutex);
    bool has_data = conn->recv_queue_count > 0;
    v3_mutex_unlock(&conn->mutex);
    
    return has_data;
}

void v3_conn_mark_established(v3_connection_t *conn) {
    if (!conn) return;
    
    v3_mutex_lock(&conn->mutex);
    if (conn->state == CONN_STATE_CONNECTING || 
        conn->state == CONN_STATE_HANDSHAKING) {
        conn_set_state(conn, CONN_STATE_ESTABLISHED);
        conn->last_recv_time_ns = conn_get_time_ns();
        conn->last_keepalive_ns = conn->last_recv_time_ns;
    }
    v3_mutex_unlock(&conn->mutex);
}





