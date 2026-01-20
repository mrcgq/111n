
/*
 * test_protocol.c - v3 Protocol Module Tests
 * 
 * 测试内容：
 * - 协议头构造与解析
 * - 元数据加密/解密
 * - 数据包完整性
 * - 边界条件
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_protocol.h"
#include "v3_crypto.h"
#include "v3_platform.h"
#include "v3_error.h"

/* 测试框架宏 */
#define V3_TEST_ASSERT(cond) \
    do { if (!(cond)) { printf("  ASSERT: %s (line %d)\n", #cond, __LINE__); return -1; } } while(0)
#define V3_TEST_ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { printf("  ASSERT: %s == %s (line %d)\n", #a, #b, __LINE__); return -1; } } while(0)

/* =========================================================
 * 测试数据
 * ========================================================= */

static uint8_t g_test_key[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static v3_protocol_ctx_t *g_proto_ctx = NULL;

/* =========================================================
 * 测试用例
 * ========================================================= */

static int test_protocol_init(void) {
    /* 先初始化加密模块 */
    int ret = v3_crypto_init();
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 创建协议上下文 */
    g_proto_ctx = v3_protocol_ctx_create(g_test_key);
    V3_TEST_ASSERT(g_proto_ctx != NULL);
    
    return 0;
}

static int test_header_size(void) {
    /* 验证头部大小 */
    V3_TEST_ASSERT_EQ(V3_HEADER_SIZE, 52);
    V3_TEST_ASSERT_EQ(sizeof(v3_header_t), 52);
    
    return 0;
}

static int test_build_header(void) {
    v3_header_t header;
    v3_metadata_t meta = {
        .session_token = 0x123456789ABCDEF0ULL,
        .intent_id = 1,
        .stream_id = 100,
        .flags = V3_FLAG_FEC_ENABLED,
        .sequence = 42
    };
    
    int ret = v3_protocol_build_header(g_proto_ctx, &header, &meta);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 验证 magic 不为 0 */
    V3_TEST_ASSERT(header.magic_derived != 0);
    
    /* nonce 应该被设置 */
    bool nonce_nonzero = false;
    for (int i = 0; i < 12; i++) {
        if (header.nonce[i] != 0) {
            nonce_nonzero = true;
            break;
        }
    }
    V3_TEST_ASSERT(nonce_nonzero);
    
    return 0;
}

static int test_parse_header(void) {
    v3_header_t header;
    v3_metadata_t meta_in = {
        .session_token = 0xDEADBEEFCAFEBABEULL,
        .intent_id = 5,
        .stream_id = 200,
        .flags = V3_FLAG_PACING_ENABLED | V3_FLAG_ANTIDETECT,
        .sequence = 1000
    };
    
    /* 构建头部 */
    int ret = v3_protocol_build_header(g_proto_ctx, &header, &meta_in);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 解析头部 */
    v3_metadata_t meta_out;
    ret = v3_protocol_parse_header(g_proto_ctx, &header, &meta_out);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 验证元数据 */
    V3_TEST_ASSERT_EQ(meta_out.session_token, meta_in.session_token);
    V3_TEST_ASSERT_EQ(meta_out.intent_id, meta_in.intent_id);
    V3_TEST_ASSERT_EQ(meta_out.stream_id, meta_in.stream_id);
    V3_TEST_ASSERT_EQ(meta_out.flags, meta_in.flags);
    
    return 0;
}

static int test_packet_build_parse(void) {
    uint8_t packet[V3_MAX_PACKET_SIZE];
    size_t packet_len;
    
    const char *payload = "Hello, v3 Protocol!";
    size_t payload_len = strlen(payload);
    
    v3_metadata_t meta_in = {
        .session_token = 0x1122334455667788ULL,
        .intent_id = 3,
        .stream_id = 50,
        .flags = 0,
        .sequence = 12345
    };
    
    /* 构建数据包 */
    int ret = v3_protocol_build_packet(
        g_proto_ctx,
        packet, &packet_len, sizeof(packet),
        (const uint8_t*)payload, payload_len,
        &meta_in
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT(packet_len >= V3_HEADER_SIZE + payload_len);
    
    /* 解析数据包 */
    v3_metadata_t meta_out;
    uint8_t *payload_out;
    size_t payload_out_len;
    
    ret = v3_protocol_parse_packet(
        g_proto_ctx,
        packet, packet_len,
        &meta_out,
        &payload_out, &payload_out_len
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 验证元数据 */
    V3_TEST_ASSERT_EQ(meta_out.session_token, meta_in.session_token);
    V3_TEST_ASSERT_EQ(meta_out.intent_id, meta_in.intent_id);
    V3_TEST_ASSERT_EQ(meta_out.stream_id, meta_in.stream_id);
    
    /* 验证载荷 */
    V3_TEST_ASSERT_EQ(payload_out_len, payload_len);
    V3_TEST_ASSERT(memcmp(payload_out, payload, payload_len) == 0);
    
    return 0;
}

static int test_invalid_magic(void) {
    v3_header_t header;
    v3_metadata_t meta = {
        .session_token = 0xAAAABBBBCCCCDDDDULL,
        .intent_id = 1,
        .stream_id = 1,
        .flags = 0,
        .sequence = 1
    };
    
    /* 构建有效头部 */
    int ret = v3_protocol_build_header(g_proto_ctx, &header, &meta);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 篡改 magic */
    header.magic_derived = 0xDEADC0DE;
    
    /* 解析应该失败 */
    v3_metadata_t meta_out;
    ret = v3_protocol_parse_header(g_proto_ctx, &header, &meta_out);
    V3_TEST_ASSERT(ret != V3_OK);
    
    return 0;
}

static int test_tampered_header(void) {
    v3_header_t header;
    v3_metadata_t meta = {
        .session_token = 0x1111222233334444ULL,
        .intent_id = 2,
        .stream_id = 2,
        .flags = 0,
        .sequence = 2
    };
    
    /* 构建有效头部 */
    int ret = v3_protocol_build_header(g_proto_ctx, &header, &meta);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 篡改加密块 */
    header.enc_block[0] ^= 0xFF;
    
    /* 解析应该失败（MAC 验证失败） */
    v3_metadata_t meta_out;
    ret = v3_protocol_parse_header(g_proto_ctx, &header, &meta_out);
    V3_TEST_ASSERT(ret != V3_OK);
    
    return 0;
}

static int test_minimum_packet(void) {
    uint8_t packet[V3_MAX_PACKET_SIZE];
    size_t packet_len;
    
    /* 空载荷 */
    v3_metadata_t meta = {
        .session_token = 1,
        .intent_id = 0,
        .stream_id = 0,
        .flags = 0,
        .sequence = 0
    };
    
    int ret = v3_protocol_build_packet(
        g_proto_ctx,
        packet, &packet_len, sizeof(packet),
        NULL, 0,
        &meta
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT_EQ(packet_len, V3_HEADER_SIZE);
    
    /* 解析最小包 */
    v3_metadata_t meta_out;
    uint8_t *payload_out;
    size_t payload_out_len;
    
    ret = v3_protocol_parse_packet(
        g_proto_ctx,
        packet, packet_len,
        &meta_out,
        &payload_out, &payload_out_len
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT_EQ(payload_out_len, 0);
    
    return 0;
}

static int test_maximum_packet(void) {
    uint8_t packet[V3_MAX_PACKET_SIZE];
    size_t packet_len;
    
    /* 最大载荷 */
    size_t max_payload = V3_MAX_PACKET_SIZE - V3_HEADER_SIZE;
    uint8_t *payload = (uint8_t*)malloc(max_payload);
    V3_TEST_ASSERT(payload != NULL);
    
    /* 填充随机数据 */
    v3_random_bytes(payload, max_payload);
    
    v3_metadata_t meta = {
        .session_token = 0xFFFFFFFFFFFFFFFFULL,
        .intent_id = 0xFFFF,
        .stream_id = 0xFFFF,
        .flags = 0xFFFF,
        .sequence = 0xFFFFFFFF
    };
    
    int ret = v3_protocol_build_packet(
        g_proto_ctx,
        packet, &packet_len, sizeof(packet),
        payload, max_payload,
        &meta
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 解析 */
    v3_metadata_t meta_out;
    uint8_t *payload_out;
    size_t payload_out_len;
    
    ret = v3_protocol_parse_packet(
        g_proto_ctx,
        packet, packet_len,
        &meta_out,
        &payload_out, &payload_out_len
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT_EQ(payload_out_len, max_payload);
    V3_TEST_ASSERT(memcmp(payload_out, payload, max_payload) == 0);
    
    free(payload);
    return 0;
}

static int test_packet_too_short(void) {
    uint8_t packet[10] = {0};  /* 远小于 V3_HEADER_SIZE */
    
    v3_metadata_t meta_out;
    uint8_t *payload_out;
    size_t payload_out_len;
    
    int ret = v3_protocol_parse_packet(
        g_proto_ctx,
        packet, sizeof(packet),
        &meta_out,
        &payload_out, &payload_out_len
    );
    V3_TEST_ASSERT(ret != V3_OK);
    
    return 0;
}

static int test_multiple_sessions(void) {
    /* 测试多个会话同时处理 */
    v3_header_t headers[10];
    v3_metadata_t metas[10];
    
    /* 创建多个会话的头部 */
    for (int i = 0; i < 10; i++) {
        metas[i].session_token = (uint64_t)i * 0x1000000000000000ULL;
        metas[i].intent_id = i;
        metas[i].stream_id = i * 10;
        metas[i].flags = 0;
        metas[i].sequence = i;
        
        int ret = v3_protocol_build_header(g_proto_ctx, &headers[i], &metas[i]);
        V3_TEST_ASSERT_EQ(ret, V3_OK);
    }
    
    /* 验证所有头部可以正确解析 */
    for (int i = 0; i < 10; i++) {
        v3_metadata_t meta_out;
        int ret = v3_protocol_parse_header(g_proto_ctx, &headers[i], &meta_out);
        V3_TEST_ASSERT_EQ(ret, V3_OK);
        V3_TEST_ASSERT_EQ(meta_out.session_token, metas[i].session_token);
        V3_TEST_ASSERT_EQ(meta_out.intent_id, metas[i].intent_id);
    }
    
    return 0;
}

static int test_protocol_cleanup(void) {
    if (g_proto_ctx) {
        v3_protocol_ctx_destroy(g_proto_ctx);
        g_proto_ctx = NULL;
    }
    
    v3_crypto_cleanup();
    
    return 0;
}

/* =========================================================
 * 测试注册
 * ========================================================= */

extern void v3_test_register(const char *name, int (*func)(void),
                              const char *file, int line);

void v3_test_protocol_register(void) {
    v3_test_register("protocol_init", test_protocol_init, __FILE__, __LINE__);
    v3_test_register("protocol_header_size", test_header_size, __FILE__, __LINE__);
    v3_test_register("protocol_build_header", test_build_header, __FILE__, __LINE__);
    v3_test_register("protocol_parse_header", test_parse_header, __FILE__, __LINE__);
    v3_test_register("protocol_packet_roundtrip", test_packet_build_parse, __FILE__, __LINE__);
    v3_test_register("protocol_invalid_magic", test_invalid_magic, __FILE__, __LINE__);
    v3_test_register("protocol_tampered_header", test_tampered_header, __FILE__, __LINE__);
    v3_test_register("protocol_minimum_packet", test_minimum_packet, __FILE__, __LINE__);
    v3_test_register("protocol_maximum_packet", test_maximum_packet, __FILE__, __LINE__);
    v3_test_register("protocol_too_short", test_packet_too_short, __FILE__, __LINE__);
    v3_test_register("protocol_multiple_sessions", test_multiple_sessions, __FILE__, __LINE__);
    v3_test_register("protocol_cleanup", test_protocol_cleanup, __FILE__, __LINE__);
}
