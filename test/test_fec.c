

/*
 * v3 Core - FEC Module Tests
 * 
 * 测试内容：
 * - XOR FEC 编码/解码
 * - RS FEC 编码/解码
 * - 丢包恢复
 * - 边界条件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "../include/v3_fec.h"
#include "../include/v3_error.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * 测试框架宏
 * ═══════════════════════════════════════════════════════════════════════════ */

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (!(cond)) { \
        printf("  [FAIL] %s: %s (line %d)\n", __func__, msg, __LINE__); \
        g_tests_failed++; \
        return false; \
    } \
    g_tests_passed++; \
} while(0)

#define TEST_BEGIN(name) \
    static bool name(void) { \
        printf("[TEST] %s\n", #name);

#define TEST_END() \
        printf("  [PASS]\n"); \
        return true; \
    }

#define RUN_TEST(test) do { \
    if (!test()) { \
        printf("  Test %s FAILED\n", #test); \
    } \
} while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * 辅助函数
 * ═══════════════════════════════════════════════════════════════════════════ */

static void fill_random_data(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

static bool compare_buffers(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * XOR FEC 测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_xor_fec_create)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_XOR, 4, 1);
    TEST_ASSERT(fec != NULL, "FEC creation failed");
    
    TEST_ASSERT(v3_fec_get_type(fec) == V3_FEC_TYPE_XOR, "Wrong FEC type");
    TEST_ASSERT(v3_fec_get_data_shards(fec) == 4, "Wrong data shards");
    TEST_ASSERT(v3_fec_get_parity_shards(fec) == 1, "Wrong parity shards");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_xor_fec_encode_decode)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_XOR, 4, 1);
    TEST_ASSERT(fec != NULL, "FEC creation failed");
    
    /* 准备测试数据 */
    uint8_t original_data[1400];
    fill_random_data(original_data, sizeof(original_data));
    
    /* 编码 */
    v3_fec_shard_t shards[5];  /* 4 data + 1 parity */
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode failed");
    TEST_ASSERT(shard_count == 5, "Wrong shard count");
    
    /* 模拟丢失第一个分片 */
    bool present[5] = {false, true, true, true, true};
    memset(shards[0].data, 0, shards[0].len);
    
    /* 解码恢复 */
    uint8_t recovered_data[2048];
    size_t recovered_len;
    
    err = v3_fec_decode(fec, shards, present, shard_count,
                        recovered_data, &recovered_len);
    TEST_ASSERT(err == V3_OK, "Decode failed");
    TEST_ASSERT(recovered_len >= sizeof(original_data), "Wrong recovered length");
    TEST_ASSERT(compare_buffers(original_data, recovered_data, sizeof(original_data)),
                "Data mismatch after recovery");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_xor_fec_no_loss)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_XOR, 4, 1);
    TEST_ASSERT(fec != NULL, "FEC creation failed");
    
    uint8_t original_data[560];  /* 4 * 140 */
    fill_random_data(original_data, sizeof(original_data));
    
    v3_fec_shard_t shards[5];
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode failed");
    
    /* 所有分片都在 */
    bool present[5] = {true, true, true, true, true};
    
    uint8_t recovered_data[1024];
    size_t recovered_len;
    
    err = v3_fec_decode(fec, shards, present, shard_count,
                        recovered_data, &recovered_len);
    TEST_ASSERT(err == V3_OK, "Decode failed");
    TEST_ASSERT(compare_buffers(original_data, recovered_data, sizeof(original_data)),
                "Data mismatch");
    
    v3_fec_destroy(fec);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * RS FEC 测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_rs_fec_create)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_RS, 10, 4);
    TEST_ASSERT(fec != NULL, "RS FEC creation failed");
    
    TEST_ASSERT(v3_fec_get_type(fec) == V3_FEC_TYPE_RS, "Wrong FEC type");
    TEST_ASSERT(v3_fec_get_data_shards(fec) == 10, "Wrong data shards");
    TEST_ASSERT(v3_fec_get_parity_shards(fec) == 4, "Wrong parity shards");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_rs_fec_single_loss)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_RS, 5, 2);
    TEST_ASSERT(fec != NULL, "RS FEC creation failed");
    
    uint8_t original_data[700];  /* 5 * 140 */
    fill_random_data(original_data, sizeof(original_data));
    
    v3_fec_shard_t shards[7];  /* 5 data + 2 parity */
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode failed");
    TEST_ASSERT(shard_count == 7, "Wrong shard count");
    
    /* 丢失一个数据分片 */
    bool present[7] = {true, false, true, true, true, true, true};
    memset(shards[1].data, 0, shards[1].len);
    
    uint8_t recovered_data[1024];
    size_t recovered_len;
    
    err = v3_fec_decode(fec, shards, present, shard_count,
                        recovered_data, &recovered_len);
    TEST_ASSERT(err == V3_OK, "Decode failed");
    TEST_ASSERT(compare_buffers(original_data, recovered_data, sizeof(original_data)),
                "Data mismatch after recovery");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_rs_fec_multiple_loss)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_RS, 5, 3);
    TEST_ASSERT(fec != NULL, "RS FEC creation failed");
    
    uint8_t original_data[700];
    fill_random_data(original_data, sizeof(original_data));
    
    v3_fec_shard_t shards[8];  /* 5 data + 3 parity */
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode failed");
    
    /* 丢失2个数据分片和1个校验分片（共3个，刚好可恢复） */
    bool present[8] = {false, true, false, true, true, true, false, true};
    memset(shards[0].data, 0, shards[0].len);
    memset(shards[2].data, 0, shards[2].len);
    memset(shards[6].data, 0, shards[6].len);
    
    uint8_t recovered_data[1024];
    size_t recovered_len;
    
    err = v3_fec_decode(fec, shards, present, shard_count,
                        recovered_data, &recovered_len);
    TEST_ASSERT(err == V3_OK, "Decode with 3 losses failed");
    TEST_ASSERT(compare_buffers(original_data, recovered_data, sizeof(original_data)),
                "Data mismatch after recovery");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_rs_fec_too_many_losses)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_RS, 5, 2);
    TEST_ASSERT(fec != NULL, "RS FEC creation failed");
    
    uint8_t original_data[700];
    fill_random_data(original_data, sizeof(original_data));
    
    v3_fec_shard_t shards[7];
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode failed");
    
    /* 丢失3个分片（超过2个校验分片，无法恢复） */
    bool present[7] = {false, false, false, true, true, true, true};
    
    uint8_t recovered_data[1024];
    size_t recovered_len;
    
    err = v3_fec_decode(fec, shards, present, shard_count,
                        recovered_data, &recovered_len);
    TEST_ASSERT(err == V3_ERR_FEC_UNRECOVERABLE, "Should fail with too many losses");
    
    v3_fec_destroy(fec);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 边界条件测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_fec_small_data)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_XOR, 4, 1);
    TEST_ASSERT(fec != NULL, "FEC creation failed");
    
    /* 非常小的数据 */
    uint8_t original_data[16];
    fill_random_data(original_data, sizeof(original_data));
    
    v3_fec_shard_t shards[5];
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode small data failed");
    
    bool present[5] = {true, true, true, true, true};
    uint8_t recovered_data[256];
    size_t recovered_len;
    
    err = v3_fec_decode(fec, shards, present, shard_count,
                        recovered_data, &recovered_len);
    TEST_ASSERT(err == V3_OK, "Decode small data failed");
    TEST_ASSERT(compare_buffers(original_data, recovered_data, sizeof(original_data)),
                "Small data mismatch");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_fec_max_data)
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_XOR, 4, 1);
    TEST_ASSERT(fec != NULL, "FEC creation failed");
    
    /* 接近最大分片大小的数据 */
    uint8_t original_data[V3_FEC_MAX_SHARD_SIZE * 4 - 100];
    fill_random_data(original_data, sizeof(original_data));
    
    v3_fec_shard_t shards[5];
    int shard_count;
    uint32_t group_id;
    
    v3_error_t err = v3_fec_encode(fec, original_data, sizeof(original_data),
                                    shards, &shard_count, &group_id);
    TEST_ASSERT(err == V3_OK, "Encode max data failed");
    
    v3_fec_destroy(fec);
TEST_END()

TEST_BEGIN(test_fec_null_params)
    /* 空指针测试 */
    v3_fec_t *fec = v3_fec_create(V3_FEC_TYPE_XOR, 4, 1);
    TEST_ASSERT(fec != NULL, "FEC creation failed");
    
    v3_error_t err = v3_fec_encode(fec, NULL, 100, NULL, NULL, NULL);
    TEST_ASSERT(err == V3_ERR_INVALID_PARAM, "Should fail with null params");
    
    v3_fec_destroy(fec);
    
    /* 无效参数测试 */
    fec = v3_fec_create(V3_FEC_TYPE_XOR, 0, 1);
    TEST_ASSERT(fec == NULL, "Should fail with 0 data shards");
    
    fec = v3_fec_create(V3_FEC_TYPE_RS, 100, 1);
    TEST_ASSERT(fec == NULL, "Should fail with too many shards");
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 主函数
 * ═══════════════════════════════════════════════════════════════════════════ */

int test_fec_main(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    FEC Module Tests                           ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* XOR FEC 测试 */
    printf("─── XOR FEC Tests ───\n");
    RUN_TEST(test_xor_fec_create);
    RUN_TEST(test_xor_fec_encode_decode);
    RUN_TEST(test_xor_fec_no_loss);
    
    /* RS FEC 测试 */
    printf("\n─── RS FEC Tests ───\n");
    RUN_TEST(test_rs_fec_create);
    RUN_TEST(test_rs_fec_single_loss);
    RUN_TEST(test_rs_fec_multiple_loss);
    RUN_TEST(test_rs_fec_too_many_losses);
    
    /* 边界条件测试 */
    printf("\n─── Boundary Tests ───\n");
    RUN_TEST(test_fec_small_data);
    RUN_TEST(test_fec_max_data);
    RUN_TEST(test_fec_null_params);
    
    /* 结果汇总 */
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total: %d | Passed: %d | Failed: %d\n",
           g_tests_run, g_tests_passed, g_tests_failed);
    printf("═══════════════════════════════════════════════════════════════\n");
    
    return g_tests_failed > 0 ? 1 : 0;
}

#ifdef TEST_FEC_STANDALONE
int main(void) {
    return test_fec_main();
}
#endif
