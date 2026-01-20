
/*
 * test_crypto.c - v3 Crypto Module Tests
 * 
 * 测试内容：
 * - ChaCha20 加密/解密
 * - Poly1305 MAC
 * - ChaCha20-Poly1305 AEAD
 * - Magic 派生
 * - 密钥生成
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "v3_crypto.h"
#include "v3_platform.h"
#include "v3_error.h"

/* 测试框架宏（与 test_main.c 一致） */
#define V3_TEST_ASSERT(cond) \
    do { if (!(cond)) { printf("  ASSERT: %s (line %d)\n", #cond, __LINE__); return -1; } } while(0)
#define V3_TEST_ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { printf("  ASSERT: %s == %s (line %d)\n", #a, #b, __LINE__); return -1; } } while(0)

/* =========================================================
 * 测试向量（RFC 7539）
 * ========================================================= */

/* ChaCha20 测试向量 */
static const uint8_t chacha20_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const uint8_t chacha20_nonce[12] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
    0x00, 0x00, 0x00, 0x00
};

static const char *chacha20_plaintext = 
    "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.";

/* Poly1305 测试向量 */
static const uint8_t poly1305_key[32] = {
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
    0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
    0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
};

static const char *poly1305_message = "Cryptographic Forum Research Group";

static const uint8_t poly1305_expected_tag[16] = {
    0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
    0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
};

/* AEAD 测试向量 */
static const uint8_t aead_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

static const uint8_t aead_nonce[12] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
    0x44, 0x45, 0x46, 0x47
};

static const uint8_t aead_aad[] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
    0xc4, 0xc5, 0xc6, 0xc7
};

static const char *aead_plaintext = 
    "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.";

/* =========================================================
 * 测试用例
 * ========================================================= */

static int test_crypto_init(void) {
    int ret = v3_crypto_init();
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    return 0;
}

static int test_random_bytes(void) {
    uint8_t buf1[32], buf2[32];
    
    int ret = v3_random_bytes(buf1, sizeof(buf1));
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    ret = v3_random_bytes(buf2, sizeof(buf2));
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 两次生成的随机数应该不同 */
    V3_TEST_ASSERT(memcmp(buf1, buf2, sizeof(buf1)) != 0);
    
    return 0;
}

static int test_chacha20_encrypt(void) {
    size_t plaintext_len = strlen(chacha20_plaintext);
    uint8_t *ciphertext = (uint8_t*)malloc(plaintext_len);
    uint8_t *decrypted = (uint8_t*)malloc(plaintext_len);
    
    V3_TEST_ASSERT(ciphertext != NULL);
    V3_TEST_ASSERT(decrypted != NULL);
    
    /* 加密 */
    int ret = v3_chacha20_xor(
        ciphertext,
        (const uint8_t*)chacha20_plaintext,
        plaintext_len,
        chacha20_key,
        chacha20_nonce,
        1  /* counter */
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 密文应该与明文不同 */
    V3_TEST_ASSERT(memcmp(ciphertext, chacha20_plaintext, plaintext_len) != 0);
    
    /* 解密 */
    ret = v3_chacha20_xor(
        decrypted,
        ciphertext,
        plaintext_len,
        chacha20_key,
        chacha20_nonce,
        1
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 解密后应该与原文相同 */
    V3_TEST_ASSERT(memcmp(decrypted, chacha20_plaintext, plaintext_len) == 0);
    
    free(ciphertext);
    free(decrypted);
    
    return 0;
}

static int test_poly1305_mac(void) {
    uint8_t tag[16];
    
    int ret = v3_poly1305_auth(
        tag,
        (const uint8_t*)poly1305_message,
        strlen(poly1305_message),
        poly1305_key
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 验证标签 */
    V3_TEST_ASSERT(memcmp(tag, poly1305_expected_tag, 16) == 0);
    
    /* 验证函数 */
    ret = v3_poly1305_verify(
        poly1305_expected_tag,
        (const uint8_t*)poly1305_message,
        strlen(poly1305_message),
        poly1305_key
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 篡改的消息应该验证失败 */
    uint8_t tampered[100];
    memcpy(tampered, poly1305_message, strlen(poly1305_message));
    tampered[0] ^= 0x01;  /* 修改一个字节 */
    
    ret = v3_poly1305_verify(
        poly1305_expected_tag,
        tampered,
        strlen(poly1305_message),
        poly1305_key
    );
    V3_TEST_ASSERT(ret != V3_OK);
    
    return 0;
}

static int test_aead_encrypt_decrypt(void) {
    size_t plaintext_len = strlen(aead_plaintext);
    size_t ciphertext_len = plaintext_len + V3_AEAD_TAG_SIZE;
    
    uint8_t *ciphertext = (uint8_t*)malloc(ciphertext_len);
    uint8_t *decrypted = (uint8_t*)malloc(plaintext_len);
    
    V3_TEST_ASSERT(ciphertext != NULL);
    V3_TEST_ASSERT(decrypted != NULL);
    
    /* 加密 */
    size_t actual_len;
    int ret = v3_aead_encrypt(
        ciphertext, &actual_len,
        (const uint8_t*)aead_plaintext, plaintext_len,
        aead_aad, sizeof(aead_aad),
        aead_nonce,
        aead_key
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT_EQ(actual_len, ciphertext_len);
    
    /* 解密 */
    size_t decrypted_len;
    ret = v3_aead_decrypt(
        decrypted, &decrypted_len,
        ciphertext, actual_len,
        aead_aad, sizeof(aead_aad),
        aead_nonce,
        aead_key
    );
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT_EQ(decrypted_len, plaintext_len);
    
    /* 验证解密结果 */
    V3_TEST_ASSERT(memcmp(decrypted, aead_plaintext, plaintext_len) == 0);
    
    /* 测试篡改检测 */
    ciphertext[10] ^= 0x01;  /* 篡改密文 */
    
    ret = v3_aead_decrypt(
        decrypted, &decrypted_len,
        ciphertext, actual_len,
        aead_aad, sizeof(aead_aad),
        aead_nonce,
        aead_key
    );
    V3_TEST_ASSERT(ret != V3_OK);  /* 应该解密失败 */
    
    free(ciphertext);
    free(decrypted);
    
    return 0;
}

static int test_magic_derivation(void) {
    uint8_t key[32];
    memset(key, 0x42, sizeof(key));
    
    /* 相同的窗口应该产生相同的 magic */
    uint32_t magic1 = v3_derive_magic(key, 1000);
    uint32_t magic2 = v3_derive_magic(key, 1000);
    V3_TEST_ASSERT_EQ(magic1, magic2);
    
    /* 不同的窗口应该产生不同的 magic */
    uint32_t magic3 = v3_derive_magic(key, 1001);
    V3_TEST_ASSERT(magic1 != magic3);
    
    /* 不同的密钥应该产生不同的 magic */
    uint8_t key2[32];
    memset(key2, 0x43, sizeof(key2));
    uint32_t magic4 = v3_derive_magic(key2, 1000);
    V3_TEST_ASSERT(magic1 != magic4);
    
    return 0;
}

static int test_magic_verification(void) {
    uint8_t key[32];
    v3_random_bytes(key, sizeof(key));
    
    v3_crypto_ctx_t *ctx = v3_crypto_ctx_create(key);
    V3_TEST_ASSERT(ctx != NULL);
    
    /* 获取当前 magic 列表 */
    uint32_t magics[8];
    v3_crypto_get_valid_magics(ctx, magics, 8);
    
    /* 当前窗口的 magic 应该验证通过 */
    V3_TEST_ASSERT(v3_crypto_verify_magic(ctx, magics[3]) == true);  /* 当前窗口 */
    V3_TEST_ASSERT(v3_crypto_verify_magic(ctx, magics[2]) == true);  /* 前一窗口 */
    V3_TEST_ASSERT(v3_crypto_verify_magic(ctx, magics[4]) == true);  /* 后一窗口 */
    
    /* 随机值应该验证失败 */
    V3_TEST_ASSERT(v3_crypto_verify_magic(ctx, 0x12345678) == false);
    
    v3_crypto_ctx_destroy(ctx);
    
    return 0;
}

static int test_key_derivation(void) {
    uint8_t master_key[32];
    uint8_t derived_key1[32];
    uint8_t derived_key2[32];
    
    v3_random_bytes(master_key, sizeof(master_key));
    
    /* 派生密钥 */
    int ret = v3_derive_key(derived_key1, sizeof(derived_key1),
                            master_key, sizeof(master_key),
                            "context1", 8);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    
    /* 相同上下文应该产生相同密钥 */
    ret = v3_derive_key(derived_key2, sizeof(derived_key2),
                        master_key, sizeof(master_key),
                        "context1", 8);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT(memcmp(derived_key1, derived_key2, 32) == 0);
    
    /* 不同上下文应该产生不同密钥 */
    ret = v3_derive_key(derived_key2, sizeof(derived_key2),
                        master_key, sizeof(master_key),
                        "context2", 8);
    V3_TEST_ASSERT_EQ(ret, V3_OK);
    V3_TEST_ASSERT(memcmp(derived_key1, derived_key2, 32) != 0);
    
    return 0;
}

static int test_crypto_cleanup(void) {
    v3_crypto_cleanup();
    return 0;
}

/* =========================================================
 * 测试注册
 * ========================================================= */

extern void v3_test_register(const char *name, int (*func)(void),
                              const char *file, int line);

void v3_test_crypto_register(void) {
    v3_test_register("crypto_init", test_crypto_init, __FILE__, __LINE__);
    v3_test_register("crypto_random_bytes", test_random_bytes, __FILE__, __LINE__);
    v3_test_register("crypto_chacha20", test_chacha20_encrypt, __FILE__, __LINE__);
    v3_test_register("crypto_poly1305", test_poly1305_mac, __FILE__, __LINE__);
    v3_test_register("crypto_aead", test_aead_encrypt_decrypt, __FILE__, __LINE__);
    v3_test_register("crypto_magic_derive", test_magic_derivation, __FILE__, __LINE__);
    v3_test_register("crypto_magic_verify", test_magic_verification, __FILE__, __LINE__);
    v3_test_register("crypto_key_derive", test_key_derivation, __FILE__, __LINE__);
    v3_test_register("crypto_cleanup", test_crypto_cleanup, __FILE__, __LINE__);
}
