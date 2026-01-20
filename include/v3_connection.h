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

#endif /* V3_CONNECTION_H */```

---

### 3. `include/v3_protocol.h` (修改后)

**修改:** 删除了重复的 `#define V3_PROTOCOL_VERSION 1`。

```c
/**
 * @file v3_protocol.h
 * @brief v3 Core - 协议处理
 * 
 * 实现 v3 协议的编解码、验证和处理
 * 与服务端 v3_ultimate_optimized.c, v3_portable.c 完全兼容
 */

#ifndef V3_PROTOCOL_H
#define V3_PROTOCOL_H

#include "v3_types.h"
#include "v3_error.h"
#include "v3_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 协议常量
 * ========================================================= */

/* 包类型标志 */
#define V3_FLAG_NONE                0x0000
#define V3_FLAG_ACK                 0x0001      /* 确认包 */
#define V3_FLAG_FIN                 0x0002      /* 结束标志 */
#define V3_FLAG_RST                 0x0004      /* 重置 */
#define V3_FLAG_KEEPALIVE           0x0008      /* 心跳 */
#define V3_FLAG_FEC                 0x0010      /* FEC 数据 */
#define V3_FLAG_FRAGMENT            0x0020      /* 分片 */
#define V3_FLAG_FIRST_FRAGMENT      0x0040      /* 首个分片 */
#define V3_FLAG_LAST_FRAGMENT       0x0080      /* 最后分片 */
#define V3_FLAG_COMPRESSED          0x0100      /* 已压缩 */
#define V3_FLAG_PRIORITY            0x0200      /* 高优先级 */

/* Intent 范围 */
#define V3_INTENT_MIN               0
#define V3_INTENT_MAX               255
#define V3_INTENT_CONTROL           0           /* 控制通道 */

/* Stream 范围 */
#define V3_STREAM_MIN               0
#define V3_STREAM_MAX               65535

/* =========================================================
 * 协议结构体（与服务端一致）
 * ========================================================= */

/**
 * @brief v3 协议头（52 字节）
 * 
 * 与服务端 v3_header_t 完全一致
 */
V3_PACK_BEGIN
typedef struct v3_packet_header_s {
    u32     magic_derived;                      /* 派生的 Magic 值 */
    u8      nonce[V3_CRYPTO_NONCE_SIZE];        /* AEAD Nonce (12字节) */
    u8      enc_block[V3_ENC_BLOCK_SIZE];       /* 加密的元数据块 (16字节) */
    u8      tag[V3_CRYPTO_TAG_SIZE];            /* Poly1305 认证标签 (16字节) */
    u16     early_len;                          /* Early 数据长度（AAD）*/
    u16     pad;                                /* 填充/保留 */
} V3_PACK_STRUCT v3_packet_header_t;
V3_PACK_END

/**
 * @brief v3 元数据（加密块解密后内容）
 */
V3_PACK_BEGIN
typedef struct v3_packet_meta_s {
    u64     session_token;      /* 会话令牌 */
    u16     intent_id;          /* Intent ID */
    u16     stream_id;          /* Stream ID */
    u16     flags;              /* 标志位 */
    u16     reserved;           /* 保留 */
} V3_PACK_STRUCT v3_packet_meta_t;
V3_PACK_END

/* 编译时断言 */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
    _Static_assert(sizeof(v3_packet_header_t) == 52, "v3_packet_header_t size mismatch");
    _Static_assert(sizeof(v3_packet_meta_t) == 16, "v3_packet_meta_t size mismatch");
#endif

/**
 * @brief 解析后的数据包
 */
typedef struct v3_packet_s {
    /* 协议头 */
    v3_packet_header_t  header;
    
    /* 解密后的元数据 */
    v3_packet_meta_t    meta;
    bool                meta_decrypted;     /* 元数据是否已解密 */
    
    /* 载荷 */
    const u8           *payload;            /* 载荷指针 */
    usize               payload_len;        /* 载荷长度 */
    
    /* 解析信息 */
    usize               total_len;          /* 包总长度 */
    bool                valid;              /* 是否有效 */
    v3_error_t          parse_error;        /* 解析错误码 */
} v3_packet_t;

/* =========================================================
 * 协议上下文
 * ========================================================= */

/**
 * @brief 协议上下文
 */
typedef struct v3_protocol_ctx_s {
    /* 加密上下文 */
    v3_aead_ctx_t       aead_ctx;
    u8                  master_key[V3_CRYPTO_KEY_SIZE];
    bool                key_set;
    
    /* 统计 */
    u64                 packets_parsed;
    u64                 packets_created;
    u64                 packets_invalid;
    u64                 magic_failures;
    u64                 decrypt_failures;
    
    /* Nonce 计数器 */
    u64                 nonce_counter;
    
    /* 配置 */
    u32                 magic_tolerance;    /* Magic 时间窗口容差 */
} v3_protocol_ctx_t;

/* =========================================================
 * 协议模块 API
 * ========================================================= */

/**
 * @brief 初始化协议模块
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_init(void);

/**
 * @brief 关闭协议模块
 */
V3_API void v3_protocol_shutdown(void);

/* =========================================================
 * 协议上下文 API
 * ========================================================= */

/**
 * @brief 创建协议上下文
 * @param ctx_out 输出上下文
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_ctx_create(v3_protocol_ctx_t **ctx_out);

/**
 * @brief 销毁协议上下文
 * @param ctx 上下文
 */
V3_API void v3_protocol_ctx_destroy(v3_protocol_ctx_t *ctx);

/**
 * @brief 设置主密钥
 * @param ctx 上下文
 * @param key 密钥（32字节）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_ctx_set_key(
    v3_protocol_ctx_t *ctx,
    const u8 key[V3_CRYPTO_KEY_SIZE]
);

/**
 * @brief 设置 Magic 容差
 * @param ctx 上下文
 * @param tolerance 容差（时间窗口数）
 */
V3_API void v3_protocol_ctx_set_magic_tolerance(
    v3_protocol_ctx_t *ctx,
    u32 tolerance
);

/* =========================================================
 * 数据包解析
 * ========================================================= */

/**
 * @brief 解析数据包（仅解析头部，不解密）
 * @param packet 输出包结构
 * @param data 原始数据
 * @param len 数据长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_parse_header(
    v3_packet_t *packet,
    const u8 *data,
    usize len
);

/**
 * @brief 验证并解密数据包
 * @param ctx 协议上下文
 * @param packet 包结构（需先调用 parse_header）
 * @param data 原始数据
 * @param len 数据长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_decrypt(
    v3_protocol_ctx_t *ctx,
    v3_packet_t *packet,
    const u8 *data,
    usize len
);

/**
 * @brief 一步完成解析和解密
 * @param ctx 协议上下文
 * @param packet 输出包结构
 * @param data 原始数据
 * @param len 数据长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_parse(
    v3_protocol_ctx_t *ctx,
    v3_packet_t *packet,
    const u8 *data,
    usize len
);

/* =========================================================
 * 数据包构造
 * ========================================================= */

/**
 * @brief 构造数据包
 * @param ctx 协议上下文
 * @param out 输出缓冲区
 * @param out_len 输出长度（输入：缓冲区大小，输出：实际长度）
 * @param meta 元数据
 * @param payload 载荷数据
 * @param payload_len 载荷长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_build(
    v3_protocol_ctx_t *ctx,
    u8 *out,
    usize *out_len,
    const v3_packet_meta_t *meta,
    const u8 *payload,
    usize payload_len
);

/**
 * @brief 构造控制包
 * @param ctx 协议上下文
 * @param out 输出缓冲区
 * @param out_len 输出长度
 * @param session_token 会话令牌
 * @param flags 标志位
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_build_control(
    v3_protocol_ctx_t *ctx,
    u8 *out,
    usize *out_len,
    u64 session_token,
    u16 flags
);

/**
 * @brief 构造心跳包
 * @param ctx 协议上下文
 * @param out 输出缓冲区
 * @param out_len 输出长度
 * @param session_token 会话令牌
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_protocol_build_keepalive(
    v3_protocol_ctx_t *ctx,
    u8 *out,
    usize *out_len,
    u64 session_token
);

/* =========================================================
 * Magic 验证
 * ========================================================= */

/**
 * @brief 验证数据包 Magic
 * @param ctx 协议上下文
 * @param magic 收到的 Magic
 * @return true 有效
 */
V3_API bool v3_protocol_verify_magic(
    v3_protocol_ctx_t *ctx,
    u32 magic
);

/**
 * @brief 获取当前有效 Magic
 * @param ctx 协议上下文
 * @return Magic 值
 */
V3_API u32 v3_protocol_current_magic(v3_protocol_ctx_t *ctx);

/* =========================================================
 * 工具函数
 * ========================================================= */

/**
 * @brief 获取最小包大小
 * @return 最小包大小（仅头部）
 */
V3_API usize v3_protocol_min_packet_size(void);

/**
 * @brief 获取最大载荷大小
 * @param mtu MTU 值
 * @return 最大载荷大小
 */
V3_API usize v3_protocol_max_payload_size(u16 mtu);

/**
 * @brief 计算包含载荷的总包大小
 * @param payload_len 载荷长度
 * @return 总包大小
 */
V3_API usize v3_protocol_packet_size(usize payload_len);

/**
 * @brief 生成新会话令牌
 * @return 会话令牌
 */
V3_API u64 v3_protocol_generate_session_token(void);

/**
 * @brief 获取标志位名称
 * @param flags 标志位
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 描述字符串
 */
V3_API const char* v3_protocol_flags_str(u16 flags, char *buf, usize buf_size);

/* =========================================================
 * 统计
 * ========================================================= */

/**
 * @brief 获取协议统计
 * @param ctx 协议上下文
 * @param packets_parsed 输出解析包数
 * @param packets_created 输出创建包数
 * @param packets_invalid 输出无效包数
 */
V3_API void v3_protocol_get_stats(
    v3_protocol_ctx_t *ctx,
    u64 *packets_parsed,
    u64 *packets_created,
    u64 *packets_invalid
);

/**
 * @brief 重置统计
 * @param ctx 协议上下文
 */
V3_API void v3_protocol_reset_stats(v3_protocol_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* V3_PROTOCOL_H */
