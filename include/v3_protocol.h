
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

/* 协议版本 */
#define V3_PROTOCOL_VERSION         1

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

