
/*
 * v3_protocol.c - v3 协议处理实现
 * 
 * 功能：
 * - 协议包解析
 * - 协议包构建
 * - Magic 验证
 * - 元数据处理
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_protocol.h"
#include "v3_crypto.h"
#include "v3_log.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================
 * 协议常量
 * ========================================================= */

#define V3_PROTOCOL_VERSION     3
#define V3_HEADER_SIZE          52
#define V3_METADATA_SIZE        16
#define V3_MAGIC_TOLERANCE      1
#define V3_MAX_PAYLOAD_SIZE     65535
#define V3_NONCE_SIZE           12
#define V3_TAG_SIZE             16

/* =========================================================
 * 协议包头结构（与服务端对齐）
 * ========================================================= */

/*
 * v3 Header Layout (52 bytes):
 * 
 * Offset  Size  Field
 * ------  ----  -----
 * 0       4     magic_derived
 * 4       12    nonce
 * 16      16    enc_block (encrypted metadata)
 * 32      16    tag (authentication tag)
 * 48      2     early_len
 * 50      2     pad
 */

#pragma pack(push, 1)
typedef struct {
    uint32_t    magic_derived;
    uint8_t     nonce[12];
    uint8_t     enc_block[16];
    uint8_t     tag[16];
    uint16_t    early_len;
    uint16_t    pad;
} v3_wire_header_t;
#pragma pack(pop)

/* =========================================================
 * 协议上下文
 * ========================================================= */

struct v3_protocol_ctx_s {
    uint8_t             master_key[32];
    bool                key_set;
    
    /* 会话信息 */
    uint64_t            session_token;
    uint16_t            intent_id;
    uint16_t            stream_id;
    
    /* Nonce 计数器（防重放） */
    uint64_t            nonce_counter;
    
    /* 统计 */
    uint64_t            packets_sent;
    uint64_t            packets_recv;
    uint64_t            packets_invalid;
    
    v3_mutex_t          mutex;
};

/* =========================================================
 * 辅助函数
 * ========================================================= */

/* 大端/小端转换 */
static inline uint16_t read_u16_le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline void write_u16_le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline uint32_t read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | 
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint64_t read_u64_le(const uint8_t *p) {
    return (uint64_t)read_u32_le(p) | ((uint64_t)read_u32_le(p + 4) << 32);
}

static inline void write_u64_le(uint8_t *p, uint64_t v) {
    write_u32_le(p, (uint32_t)(v & 0xFFFFFFFF));
    write_u32_le(p + 4, (uint32_t)(v >> 32));
}

/* =========================================================
 * 协议上下文管理
 * ========================================================= */

v3_protocol_ctx_t* v3_protocol_create(void) {
    v3_protocol_ctx_t *ctx = (v3_protocol_ctx_t*)calloc(1, sizeof(v3_protocol_ctx_t));
    if (!ctx) return NULL;
    
    v3_mutex_init(&ctx->mutex);
    
    /* 生成随机会话令牌 */
    v3_crypto_random((uint8_t*)&ctx->session_token, sizeof(ctx->session_token));
    
    return ctx;
}

void v3_protocol_destroy(v3_protocol_ctx_t *ctx) {
    if (!ctx) return;
    
    /* 安全清除密钥 */
    memset(ctx->master_key, 0, sizeof(ctx->master_key));
    
    v3_mutex_destroy(&ctx->mutex);
    free(ctx);
}

v3_error_t v3_protocol_set_key(v3_protocol_ctx_t *ctx, const uint8_t *key, size_t len) {
    if (!ctx || !key || len != 32) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&ctx->mutex);
    memcpy(ctx->master_key, key, 32);
    ctx->key_set = true;
    v3_mutex_unlock(&ctx->mutex);
    
    return V3_OK;
}

void v3_protocol_set_session(v3_protocol_ctx_t *ctx, uint64_t session_token,
                              uint16_t intent_id, uint16_t stream_id) {
    if (!ctx) return;
    
    v3_mutex_lock(&ctx->mutex);
    ctx->session_token = session_token;
    ctx->intent_id = intent_id;
    ctx->stream_id = stream_id;
    v3_mutex_unlock(&ctx->mutex);
}

/* =========================================================
 * 包构建
 * ========================================================= */

v3_error_t v3_protocol_build_packet(v3_protocol_ctx_t *ctx,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     uint16_t flags,
                                     uint8_t *out_packet,
                                     size_t *out_len) {
    if (!ctx || !out_packet || !out_len) {
        return V3_ERR_INVALID_PARAM;
    }
    
    if (!ctx->key_set) {
        return V3_ERR_CRYPTO_NO_KEY;
    }
    
    if (payload_len > V3_MAX_PAYLOAD_SIZE) {
        return V3_ERR_PACKET_TOO_LARGE;
    }
    
    v3_mutex_lock(&ctx->mutex);
    
    /* 1. 获取当前 Magic */
    uint32_t magic = v3_crypto_get_current_magic(ctx->master_key);
    
    /* 2. 生成 Nonce */
    uint8_t nonce[V3_NONCE_SIZE];
    v3_crypto_random(nonce, 4);  /* 4 字节随机 */
    uint64_t counter = ctx->nonce_counter++;
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (counter >> (i * 8)) & 0xFF;
    }
    
    /* 3. 构建元数据 (16 bytes) */
    /* [Session(8)] [Intent(2)] [Stream(2)] [Flags(2)] [Pad(2)] */
    uint8_t metadata[V3_METADATA_SIZE];
    write_u64_le(metadata + 0, ctx->session_token);
    write_u16_le(metadata + 8, ctx->intent_id);
    write_u16_le(metadata + 10, ctx->stream_id);
    write_u16_le(metadata + 12, flags);
    write_u16_le(metadata + 14, 0);  /* 保留 */
    
    /* 4. 构建 AAD */
    /* AAD = early_len(2) + pad(2) + magic(4) = 8 bytes */
    uint8_t aad[8];
    uint16_t early_len = (payload_len > 255) ? 0 : (uint16_t)payload_len;
    write_u16_le(aad + 0, early_len);
    write_u16_le(aad + 2, 0);
    write_u32_le(aad + 4, magic);
    
    /* 5. 加密元数据 */
    uint8_t enc_metadata[V3_METADATA_SIZE];
    uint8_t tag[V3_TAG_SIZE];
    
    v3_error_t err = v3_crypto_aead_encrypt(
        enc_metadata, tag,
        metadata, V3_METADATA_SIZE,
        aad, sizeof(aad),
        nonce, ctx->master_key
    );
    
    if (err != V3_OK) {
        v3_mutex_unlock(&ctx->mutex);
        return err;
    }
    
    /* 6. 组装包头 */
    v3_wire_header_t *hdr = (v3_wire_header_t*)out_packet;
    hdr->magic_derived = magic;
    memcpy(hdr->nonce, nonce, V3_NONCE_SIZE);
    memcpy(hdr->enc_block, enc_metadata, V3_METADATA_SIZE);
    memcpy(hdr->tag, tag, V3_TAG_SIZE);
    hdr->early_len = early_len;
    hdr->pad = 0;
    
    /* 7. 复制 Payload */
    if (payload && payload_len > 0) {
        memcpy(out_packet + V3_HEADER_SIZE, payload, payload_len);
    }
    
    *out_len = V3_HEADER_SIZE + payload_len;
    ctx->packets_sent++;
    
    v3_mutex_unlock(&ctx->mutex);
    
    return V3_OK;
}

/* =========================================================
 * 包解析
 * ========================================================= */

v3_error_t v3_protocol_parse_packet(v3_protocol_ctx_t *ctx,
                                     const uint8_t *packet,
                                     size_t packet_len,
                                     v3_packet_info_t *info,
                                     uint8_t *out_payload,
                                     size_t *out_payload_len) {
    if (!ctx || !packet || !info) {
        return V3_ERR_INVALID_PARAM;
    }
    
    if (!ctx->key_set) {
        return V3_ERR_CRYPTO_NO_KEY;
    }
    
    /* 检查最小长度 */
    if (packet_len < V3_HEADER_SIZE) {
        ctx->packets_invalid++;
        return V3_ERR_PACKET_TOO_SHORT;
    }
    
    v3_mutex_lock(&ctx->mutex);
    
    const v3_wire_header_t *hdr = (const v3_wire_header_t*)packet;
    
    /* 1. 验证 Magic */
    if (!v3_crypto_verify_magic(ctx->master_key, hdr->magic_derived, V3_MAGIC_TOLERANCE)) {
        ctx->packets_invalid++;
        v3_mutex_unlock(&ctx->mutex);
        
        V3_LOG_DEBUG("Invalid magic: 0x%08X", hdr->magic_derived);
        return V3_ERR_PROTOCOL_MAGIC;
    }
    
    /* 2. 构建 AAD */
    uint8_t aad[8];
    write_u16_le(aad + 0, hdr->early_len);
    write_u16_le(aad + 2, hdr->pad);
    write_u32_le(aad + 4, hdr->magic_derived);
    
    /* 3. 解密元数据 */
    uint8_t metadata[V3_METADATA_SIZE];
    
    v3_error_t err = v3_crypto_aead_decrypt(
        metadata,
        hdr->enc_block, V3_METADATA_SIZE,
        hdr->tag,
        aad, sizeof(aad),
        hdr->nonce, ctx->master_key
    );
    
    if (err != V3_OK) {
        ctx->packets_invalid++;
        v3_mutex_unlock(&ctx->mutex);
        
        V3_LOG_DEBUG("AEAD decrypt failed");
        return V3_ERR_CRYPTO_AUTH;
    }
    
    /* 4. 解析元数据 */
    info->session_token = read_u64_le(metadata + 0);
    info->intent_id = read_u16_le(metadata + 8);
    info->stream_id = read_u16_le(metadata + 10);
    info->flags = read_u16_le(metadata + 12);
    
    /* 5. 提取 Payload */
    size_t payload_len = packet_len - V3_HEADER_SIZE;
    info->payload_len = payload_len;
    
    if (out_payload && out_payload_len) {
        if (payload_len > 0) {
            memcpy(out_payload, packet + V3_HEADER_SIZE, payload_len);
        }
        *out_payload_len = payload_len;
    }
    
    ctx->packets_recv++;
    
    v3_mutex_unlock(&ctx->mutex);
    
    return V3_OK;
}

/* =========================================================
 * 快速解析（仅头部）
 * ========================================================= */

v3_error_t v3_protocol_parse_header_only(v3_protocol_ctx_t *ctx,
                                          const uint8_t *packet,
                                          size_t packet_len,
                                          v3_packet_info_t *info) {
    return v3_protocol_parse_packet(ctx, packet, packet_len, info, NULL, NULL);
}

/* =========================================================
 * Magic 验证（无需解密）
 * ========================================================= */

bool v3_protocol_verify_magic_quick(const uint8_t *key,
                                     const uint8_t *packet,
                                     size_t packet_len) {
    if (!key || !packet || packet_len < V3_HEADER_SIZE) {
        return false;
    }
    
    const v3_wire_header_t *hdr = (const v3_wire_header_t*)packet;
    return v3_crypto_verify_magic(key, hdr->magic_derived, V3_MAGIC_TOLERANCE);
}

/* =========================================================
 * 控制包
 * ========================================================= */

v3_error_t v3_protocol_build_keepalive(v3_protocol_ctx_t *ctx,
                                        uint8_t *out_packet,
                                        size_t *out_len) {
    return v3_protocol_build_packet(ctx, NULL, 0, V3_FLAG_KEEPALIVE, out_packet, out_len);
}

v3_error_t v3_protocol_build_ack(v3_protocol_ctx_t *ctx,
                                  uint32_t ack_seq,
                                  uint8_t *out_packet,
                                  size_t *out_len) {
    uint8_t payload[4];
    write_u32_le(payload, ack_seq);
    return v3_protocol_build_packet(ctx, payload, 4, V3_FLAG_ACK, out_packet, out_len);
}

bool v3_protocol_is_keepalive(const v3_packet_info_t *info) {
    return info && (info->flags & V3_FLAG_KEEPALIVE) && info->payload_len == 0;
}

bool v3_protocol_is_ack(const v3_packet_info_t *info) {
    return info && (info->flags & V3_FLAG_ACK);
}

/* =========================================================
 * 统计信息
 * ========================================================= */

void v3_protocol_get_stats(v3_protocol_ctx_t *ctx, v3_protocol_stats_t *stats) {
    if (!ctx || !stats) return;
    
    v3_mutex_lock(&ctx->mutex);
    stats->packets_sent = ctx->packets_sent;
    stats->packets_recv = ctx->packets_recv;
    stats->packets_invalid = ctx->packets_invalid;
    v3_mutex_unlock(&ctx->mutex);
}

void v3_protocol_reset_stats(v3_protocol_ctx_t *ctx) {
    if (!ctx) return;
    
    v3_mutex_lock(&ctx->mutex);
    ctx->packets_sent = 0;
    ctx->packets_recv = 0;
    ctx->packets_invalid = 0;
    v3_mutex_unlock(&ctx->mutex);
}

/* =========================================================
 * 工具函数
 * ========================================================= */

size_t v3_protocol_header_size(void) {
    return V3_HEADER_SIZE;
}

size_t v3_protocol_max_payload_size(size_t mtu) {
    if (mtu <= V3_HEADER_SIZE + 28) {  /* IP(20) + UDP(8) */
        return 0;
    }
    
    size_t available = mtu - 28 - V3_HEADER_SIZE;
    if (available > V3_MAX_PAYLOAD_SIZE) {
        available = V3_MAX_PAYLOAD_SIZE;
    }
    
    return available;
}

void v3_protocol_print_packet(const uint8_t *packet, size_t len) {
    if (!packet || len < V3_HEADER_SIZE) {
        printf("Invalid packet\n");
        return;
    }
    
    const v3_wire_header_t *hdr = (const v3_wire_header_t*)packet;
    
    printf("v3 Packet (%zu bytes):\n", len);
    printf("  Magic:      0x%08X\n", hdr->magic_derived);
    printf("  Nonce:      ");
    for (int i = 0; i < V3_NONCE_SIZE; i++) {
        printf("%02X", hdr->nonce[i]);
    }
    printf("\n");
    printf("  Early Len:  %u\n", hdr->early_len);
    printf("  Payload:    %zu bytes\n", len - V3_HEADER_SIZE);
}

/* =========================================================
 * 包验证
 * ========================================================= */

v3_error_t v3_protocol_validate_packet(const uint8_t *packet, size_t len) {
    if (!packet) {
        return V3_ERR_INVALID_PARAM;
    }
    
    if (len < V3_HEADER_SIZE) {
        return V3_ERR_PACKET_TOO_SHORT;
    }
    
    if (len > V3_HEADER_SIZE + V3_MAX_PAYLOAD_SIZE) {
        return V3_ERR_PACKET_TOO_LARGE;
    }
    
    return V3_OK;
}
