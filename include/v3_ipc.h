
/**
 * @file v3_ipc.h
 * @brief v3 Core - 进程间通信
 * 
 * 提供与 GUI 或其他进程通信的 IPC 机制
 * Windows 使用命名管道 (Named Pipe)
 * 
 * 协议格式:
 *   [4 bytes: length] [length bytes: JSON message]
 */

#ifndef V3_IPC_H
#define V3_IPC_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* 默认管道名称 */
#define V3_IPC_PIPE_NAME_DEFAULT    "\\\\.\\pipe\\v3_core_ipc"

/* 消息限制 */
#define V3_IPC_MAX_MESSAGE_SIZE     (64 * 1024)     /* 64KB */
#define V3_IPC_BUFFER_SIZE          (8 * 1024)      /* 8KB */
#define V3_IPC_MAX_CLIENTS          16

/* 超时 */
#define V3_IPC_CONNECT_TIMEOUT_MS   5000
#define V3_IPC_READ_TIMEOUT_MS      1000
#define V3_IPC_WRITE_TIMEOUT_MS     1000

/* =========================================================
 * IPC 消息类型
 * ========================================================= */

typedef enum v3_ipc_msg_type_e {
    /* 系统消息 (0x00 - 0x0F) */
    V3_IPC_MSG_PING             = 0x00,     /* 心跳 */
    V3_IPC_MSG_PONG             = 0x01,     /* 心跳响应 */
    V3_IPC_MSG_HELLO            = 0x02,     /* 握手 */
    V3_IPC_MSG_HELLO_ACK        = 0x03,     /* 握手响应 */
    V3_IPC_MSG_BYE              = 0x04,     /* 断开 */
    V3_IPC_MSG_ERROR            = 0x0F,     /* 错误 */
    
    /* 控制消息 (0x10 - 0x1F) */
    V3_IPC_MSG_START            = 0x10,     /* 启动 */
    V3_IPC_MSG_STOP             = 0x11,     /* 停止 */
    V3_IPC_MSG_RESTART          = 0x12,     /* 重启 */
    V3_IPC_MSG_RELOAD           = 0x13,     /* 重载配置 */
    V3_IPC_MSG_STATUS           = 0x14,     /* 查询状态 */
    V3_IPC_MSG_STATUS_RESP      = 0x15,     /* 状态响应 */
    
    /* 配置消息 (0x20 - 0x2F) */
    V3_IPC_MSG_GET_CONFIG       = 0x20,     /* 获取配置 */
    V3_IPC_MSG_SET_CONFIG       = 0x21,     /* 设置配置 */
    V3_IPC_MSG_CONFIG_RESP      = 0x22,     /* 配置响应 */
    
    /* 统计消息 (0x30 - 0x3F) */
    V3_IPC_MSG_GET_STATS        = 0x30,     /* 获取统计 */
    V3_IPC_MSG_STATS_RESP       = 0x31,     /* 统计响应 */
    V3_IPC_MSG_RESET_STATS      = 0x32,     /* 重置统计 */
    
    /* 日志消息 (0x40 - 0x4F) */
    V3_IPC_MSG_LOG              = 0x40,     /* 日志推送 */
    V3_IPC_MSG_SET_LOG_LEVEL    = 0x41,     /* 设置日志级别 */
    
    /* 连接消息 (0x50 - 0x5F) */
    V3_IPC_MSG_LIST_CONNS       = 0x50,     /* 列出连接 */
    V3_IPC_MSG_CONNS_RESP       = 0x51,     /* 连接列表响应 */
    V3_IPC_MSG_KICK_CONN        = 0x52,     /* 踢出连接 */
    
    V3_IPC_MSG_MAX              = 0xFF
} v3_ipc_msg_type_t;

/* =========================================================
 * IPC 消息结构
 * ========================================================= */

/**
 * @brief IPC 消息头
 */
V3_PACK_BEGIN
typedef struct v3_ipc_header_s {
    u32     length;             /* 消息总长度（包含头） */
    u8      type;               /* 消息类型 */
    u8      flags;              /* 标志位 */
    u16     seq;                /* 序列号 */
} V3_PACK_STRUCT v3_ipc_header_t;
V3_PACK_END

#define V3_IPC_HEADER_SIZE      sizeof(v3_ipc_header_t)

/* 消息标志 */
#define V3_IPC_FLAG_NONE        0x00
#define V3_IPC_FLAG_REQUEST     0x01        /* 请求（需要响应） */
#define V3_IPC_FLAG_RESPONSE    0x02        /* 响应 */
#define V3_IPC_FLAG_NOTIFY      0x04        /* 通知（不需要响应） */
#define V3_IPC_FLAG_ERROR       0x80        /* 错误标志 */

/**
 * @brief IPC 消息
 */
typedef struct v3_ipc_message_s {
    v3_ipc_header_t header;     /* 消息头 */
    u8             *payload;    /* 载荷数据 */
    usize           payload_len;/* 载荷长度 */
} v3_ipc_message_t;

/* =========================================================
 * IPC 回调函数
 * ========================================================= */

/**
 * @brief 消息接收回调
 */
typedef void (*v3_ipc_message_fn)(
    const v3_ipc_message_t *msg,
    void *user_data
);

/**
 * @brief 客户端连接/断开回调
 */
typedef void (*v3_ipc_client_fn)(
    u32 client_id,
    bool connected,
    void *user_data
);

/**
 * @brief 错误回调
 */
typedef void (*v3_ipc_error_fn)(
    v3_error_t err,
    const char *msg,
    void *user_data
);

/* =========================================================
 * IPC 服务端 API
 * ========================================================= */

/**
 * @brief 创建 IPC 服务端
 * @param pipe_name 管道名称（NULL 使用默认）
 * @param server_out 输出服务端句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_server_create(
    const char *pipe_name,
    v3_ipc_server_t **server_out
);

/**
 * @brief 销毁 IPC 服务端
 * @param server 服务端句柄
 */
V3_API void v3_ipc_server_destroy(v3_ipc_server_t *server);

/**
 * @brief 启动 IPC 服务端
 * @param server 服务端句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_server_start(v3_ipc_server_t *server);

/**
 * @brief 停止 IPC 服务端
 * @param server 服务端句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_server_stop(v3_ipc_server_t *server);

/**
 * @brief 设置消息回调
 * @param server 服务端句柄
 * @param fn 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_ipc_server_set_message_callback(
    v3_ipc_server_t *server,
    v3_ipc_message_fn fn,
    void *user_data
);

/**
 * @brief 设置客户端回调
 * @param server 服务端句柄
 * @param fn 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_ipc_server_set_client_callback(
    v3_ipc_server_t *server,
    v3_ipc_client_fn fn,
    void *user_data
);

/**
 * @brief 发送消息给指定客户端
 * @param server 服务端句柄
 * @param client_id 客户端 ID
 * @param msg 消息
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_server_send(
    v3_ipc_server_t *server,
    u32 client_id,
    const v3_ipc_message_t *msg
);

/**
 * @brief 广播消息给所有客户端
 * @param server 服务端句柄
 * @param msg 消息
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_server_broadcast(
    v3_ipc_server_t *server,
    const v3_ipc_message_t *msg
);

/**
 * @brief 获取连接的客户端数量
 * @param server 服务端句柄
 * @return 客户端数量
 */
V3_API u32 v3_ipc_server_client_count(v3_ipc_server_t *server);

/* =========================================================
 * IPC 客户端 API
 * ========================================================= */

/**
 * @brief 创建 IPC 客户端
 * @param pipe_name 管道名称（NULL 使用默认）
 * @param client_out 输出客户端句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_client_create(
    const char *pipe_name,
    v3_ipc_client_t **client_out
);

/**
 * @brief 销毁 IPC 客户端
 * @param client 客户端句柄
 */
V3_API void v3_ipc_client_destroy(v3_ipc_client_t *client);

/**
 * @brief 连接到服务端
 * @param client 客户端句柄
 * @param timeout_ms 超时毫秒数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_client_connect(
    v3_ipc_client_t *client,
    u32 timeout_ms
);

/**
 * @brief 断开连接
 * @param client 客户端句柄
 */
V3_API void v3_ipc_client_disconnect(v3_ipc_client_t *client);

/**
 * @brief 检查是否已连接
 * @param client 客户端句柄
 * @return true 已连接
 */
V3_API bool v3_ipc_client_is_connected(v3_ipc_client_t *client);

/**
 * @brief 设置消息回调
 * @param client 客户端句柄
 * @param fn 回调函数
 * @param user_data 用户数据
 */
V3_API void v3_ipc_client_set_message_callback(
    v3_ipc_client_t *client,
    v3_ipc_message_fn fn,
    void *user_data
);

/**
 * @brief 发送消息
 * @param client 客户端句柄
 * @param msg 消息
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_client_send(
    v3_ipc_client_t *client,
    const v3_ipc_message_t *msg
);

/**
 * @brief 发送请求并等待响应
 * @param client 客户端句柄
 * @param request 请求消息
 * @param response_out 输出响应消息
 * @param timeout_ms 超时毫秒数
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_client_request(
    v3_ipc_client_t *client,
    const v3_ipc_message_t *request,
    v3_ipc_message_t *response_out,
    u32 timeout_ms
);

/* =========================================================
 * 消息辅助函数
 * ========================================================= */

/**
 * @brief 创建消息
 * @param type 消息类型
 * @param payload 载荷数据（可选）
 * @param payload_len 载荷长度
 * @param msg_out 输出消息
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_ipc_message_create(
    v3_ipc_msg_type_t type,
    const void *payload,
    usize payload_len,
    v3_ipc_message_t *msg_out
);

/**
 * @brief 释放消息
 * @param msg 消息
 */
V3_API void v3_ipc_message_free(v3_ipc_message_t *msg);

/**
 * @brief 获取消息类型名称
 * @param type 消息类型
 * @return 类型名称字符串
 */
V3_API const char* v3_ipc_msg_type_str(v3_ipc_msg_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* V3_IPC_H */

