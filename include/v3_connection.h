/**
 * @file v3_connection.h
 * @brief v3 Core - 连接管理
 * 
 * 管理客户端连接、会话状态、路由等
 */

#ifndef V3_CONNECTION_H
#define V3_CONNECTION_H

#include "v3_types.h"
#include "v3_error.h"
#include "v3_protocol.h"
#include "v3_network.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* 连接限制 */
#define V3_CONN_DEFAULT_MAX         32768
#define V3_CONN_DEFAULT_TIMEOUT_SEC 300
#define V3_CONN_DEFAULT_KEEPALIVE   30

/* 会话限制 */
#define V3_SESSION_TOKEN_SIZE       8

/* =========================================================
 * 连接类型
 * ========================================================= */

/**
 * @brief 连接类型
 */
typedef enum v3_conn_type_e {
    V3_CONN_TYPE_CLIENT = 0,        /* 客户端连接 */
    V3_CONN_TYPE_SERVER,            /* 服务端连接 */
    V3_CONN_TYPE_RELAY,             /* 中继连接 */
} v3_conn_type_t;

/* =========================================================
 * 连接结构
 * ========================================================= */

/**
 * @brief 连接统计
 */
typedef struct v3_conn_stats_s {
    u64     bytes_sent;             /* 发送字节数 */
    u64     bytes_recv;             /* 接收字节数 */
    u64     packets_sent;           /* 发送包数 */
    u64     packets_recv;           /* 接收包数 */
    u64     packets_dropped;        /* 丢弃包数 */
    u64     retransmits;            /* 重传次数 */
    
    u64     rtt_us;                 /* 当前 RTT (微秒) */
    u64     rtt_min_us;             /* 最小 RTT */
    u64     rtt_max_us;             /* 最大 RTT */
    f64     rtt_var;                /* RTT 方差 */
    
    u64     create_time;            /* 创建时间 */
    u64     last_recv_time;         /* 最后接收时间 */
    u64     last_send_time;         /* 最后发送时间 */
} v3_conn_stats_t;

/**
 * @brief 连接信息
 */
typedef struct v3_conn_info_s {
    u32             id;             /* 连接 ID */
    v3_conn_state_t state;          /* 状态 */
    v3_conn_type_t  type;           /* 类型 */
    
    u64             session_token;  /* 会话令牌 */
    v3_address_t    remote_addr;    /* 远端地址 */
    v3_address_t    local_addr;     /* 本地地址 */
    
    u16             intent_id;      /* 当前 Intent */
    u16             stream_id;      /* 当前 Stream */
    
    v3_conn_stats_t stats;          /* 统计信息 */
} v3_conn_info_t;

/**
 * @brief 连接句柄
 */
typedef struct v3_connection_s v3_connection_t;

/* =========================================================
 * 连接管理器
 * ========================================================= */

/**
 * @brief 连接管理器配置
 */
typedef struct v3_conn_manager_config_s {
    u32     max_connections;        /* 最大连接数 */
    u32     timeout_sec;            /* 超时秒数 */
    u32     keepalive_sec;          /* 心跳间隔 */
    bool    auto_cleanup;           /* 自动清理超时连接 */
} v3_conn_manager_config_t;

/**
 * @brief 连接管理器句柄
 */
typedef struct v3_conn_manager_s v3_conn_manager_t;

/* =========================================================
 * 连接回调
 * ========================================================= */

/**
 * @brief 新连接回调
 */
typedef void (*v3_conn_new_fn)(
    v3_connection_t *conn,
    void *user_data
);

/**
 * @brief 连接关闭回调
 */
typedef void (*v3_conn_close_fn)(
    v3_connection_t *conn,
    v3_error_t reason,
    void *user_data
);

/**
 * @brief 数据接收回调
 */
typedef void (*v3_conn_data_fn)(
    v3_connection_t *conn,
    const v3_packet_t *packet,
    void *user_data
);

/**
 * @brief 状态变更回调
 */
typedef void (*v3_conn_state_fn)(
    v3_connection_t *conn,
    v3_conn_state_t old_state,
    v3_conn_state_t new_state,
    void *user_data
);

/* =========================================================
 * 连接管理器 API
 * ========================================================= */

/**
 * @brief 创建连接管理器
 * @param config 配置（NULL 使用默认）
 * @param manager_out 输出管理器句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_conn_manager_create(
    const v3_conn_manager_config_t *config,
    v3_conn_manager_t **manager_out
);

/**
 * @brief 销毁连接管理器
 * @param manager 管理器句柄
 */
V3_API void v3_conn_manager_destroy(v3_conn_manager_t *manager);

/**
 * @brief 获取默认配置
 * @param config 输出配置
 */
V3_API void v3_conn_manager_default_config(v3_conn_manager_config_t *config);

/**
 * @brief 设置回调函数
 * @param manager 管理器
 * @param on_new 新连接回调
 * @param on_close 关闭回调
 * @param on_data 数据回调
 * @param on_state 状态变更回调
 * @param user_data 用户数据
 */
V3_API void v3_conn_manager_set_callbacks(
    v3_conn_manager_t *manager,
    v3_conn_new_fn on_new,
    v3_conn_close_fn on_close,
    v3_conn_data_fn on_data,
    v3_conn_state_fn on_state,
    void *user_data
);

/**
 * @brief 处理收到的数据包
 * @param manager 管理器
 * @param packet 数据包
 * @param from 来源地址
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_conn_manager_process_packet(
    v3_conn_manager_t *manager,
    const v3_packet_t *packet,
    const v3_address_t *from
);

/**
 * @brief 定时处理（超时检查等）
 * @param manager 管理器
 */
V3_API void v3_conn_manager_tick(v3_conn_manager_t *manager);

/**
 * @brief 获取连接数量
 * @param manager 管理器
 * @return 当前连接数
 */
V3_API u32 v3_conn_manager_count(v3_conn_manager_t *manager);

/**
 * @brief 根据会话令牌查找连接
 * @param manager 管理器
 * @param session_token 会话令牌
 * @return 连接句柄，未找到返回 NULL
 */
V3_API v3_connection_t* v3_conn_manager_find_by_session(
    v3_conn_manager_t *manager,
    u64 session_token
);

/**
 * @brief 根据地址查找连接
 * @param manager 管理器
 * @param addr 地址
 * @return 连接句柄，未找到返回 NULL
 */
V3_API v3_connection_t* v3_conn_manager_find_by_address(
    v3_conn_manager_t *manager,
    const v3_address_t *addr
);

/**
 * @brief 遍历所有连接
 * @param manager 管理器
 * @param callback 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_conn_manager_foreach(
    v3_conn_manager_t *manager,
    void (*callback)(v3_connection_t *conn, void *user_data),
    void *user_data
);

/**
 * @brief 关闭所有连接
 * @param manager 管理器
 */
V3_API void v3_conn_manager_close_all(v3_conn_manager_t *manager);

/* =========================================================
 * 连接 API
 * ========================================================= */

/**
 * @brief 创建新连接
 * @param manager 管理器
 * @param remote_addr 远端地址
 * @param type 连接类型
 * @param conn_out 输出连接句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_connection_create(
    v3_conn_manager_t *manager,
    const v3_address_t *remote_addr,
    v3_conn_type_t type,
    v3_connection_t **conn_out
);

/**
 * @brief 关闭连接
 * @param conn 连接句柄
 * @param reason 关闭原因
 */
V3_API void v3_connection_close(v3_connection_t *conn, v3_error_t reason);

/**
 * @brief 获取连接 ID
 * @param conn 连接句柄
 * @return 连接 ID
 */
V3_API u32 v3_connection_get_id(v3_connection_t *conn);

/**
 * @brief 获取连接状态
 * @param conn 连接句柄
 * @return 连接状态
 */
V3_API v3_conn_state_t v3_connection_get_state(v3_connection_t *conn);

/**
 * @brief 获取会话令牌
 * @param conn 连接句柄
 * @return 会话令牌
 */
V3_API u64 v3_connection_get_session_token(v3_connection_t *conn);

/**
 * @brief 设置会话令牌
 * @param conn 连接句柄
 * @param token 会话令牌
 */
V3_API void v3_connection_set_session_token(v3_connection_t *conn, u64 token);

/**
 * @brief 获取远端地址
 * @param conn 连接句柄
 * @param addr 输出地址
 */
V3_API void v3_connection_get_remote_addr(v3_connection_t *conn, v3_address_t *addr);

/**
 * @brief 获取连接信息
 * @param conn 连接句柄
 * @param info 输出信息
 */
V3_API void v3_connection_get_info(v3_connection_t *conn, v3_conn_info_t *info);

/**
 * @brief 获取连接统计
 * @param conn 连接句柄
 * @param stats 输出统计
 */
V3_API void v3_connection_get_stats(v3_connection_t *conn, v3_conn_stats_t *stats);

/**
 * @brief 更新 RTT
 * @param conn 连接句柄
 * @param rtt_us RTT 微秒
 */
V3_API void v3_connection_update_rtt(v3_connection_t *conn, u64 rtt_us);

/**
 * @brief 记录发送
 * @param conn 连接句柄
 * @param bytes 字节数
 */
V3_API void v3_connection_record_send(v3_connection_t *conn, usize bytes);

/**
 * @brief 记录接收
 * @param conn 连接句柄
 * @param bytes 字节数
 */
V3_API void v3_connection_record_recv(v3_connection_t *conn, usize bytes);

/**
 * @brief 获取用户数据
 * @param conn 连接句柄
 * @return 用户数据指针
 */
V3_API void* v3_connection_get_user_data(v3_connection_t *conn);

/**
 * @brief 设置用户数据
 * @param conn 连接句柄
 * @param user_data 用户数据
 */
V3_API void v3_connection_set_user_data(v3_connection_t *conn, void *user_data);

/**
 * @brief 获取状态名称
 * @param state 状态
 * @return 状态名称字符串
 */
V3_API const char* v3_conn_state_str(v3_conn_state_t state);

#ifdef __cplusplus
}
#endif

#endif /* V3_CONNECTION_H */

