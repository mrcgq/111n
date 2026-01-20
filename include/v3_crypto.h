
/**
 * @file v3_crypto.h
 * @brief v3 Core - 加密模块
 * 
 * 实现 ChaCha20-Poly1305 AEAD 加密（RFC 7539）
 * 与服务端 v3_portable.c 完全兼容
 * 
 * 特性：
 * - 零依赖实现（不依赖 OpenSSL/libsodium）
 * - 恒定时间比较（防止时序攻击）
 * - 安全内存清零
 */

#ifndef V3_CRYPTO_H
#define V3_CRYPTO_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义（与服务端一致）
 * ========================================================= */

#define V3_CRYPTO_KEY_SIZE          32      /* ChaCha20 密钥长度 */
#define V3_CRYPTO_NONCE_SIZE        12      /* IETF ChaCha20 Nonce 长度 */
#define V3_CRYPTO_TAG_SIZE          16      /* Poly1305 Tag 长度 */
#define V3_CRYPTO_BLOCK_SIZE        64      /* ChaCha20 块大小 */

/* AEAD 开销 */
#define V3_CRYPTO_AEAD_OVERHEAD     V3_CRYPTO_TAG_SIZE

/* 哈希长度 */
#define V3_CRYPTO_HASH_SIZE         32      /* BLAKE2b-256 / 简单哈希 */

/* Magic 派生相关 */
#define V3_CRYPTO_MAGIC_INPUT_SIZE  40      /* Key(32) + Window(8) */

/* =========================================================
 * 加密上下文
 * ========================================================= */

/**
 * @brief ChaCha20 上下文
 */
typedef struct v3_chacha20_ctx_s {
    u32     state[16];      /* ChaCha20 状态 */
    u32     counter;        /* 块计数器 */
} v3_chacha20_ctx_t;

/**
 * @brief Poly1305 上下文
 */
typedef struct v3_poly1305_ctx_s {
    u32     r[5];           /* 密钥 r */
    u32     h[5];           /* 累加器 */
    u32     pad[4];         /* 密钥 s */
    u8      buffer[16];     /* 缓冲区 */
    usize   leftover;       /* 剩余字节 */
    bool    final;          /* 是否最终块 */
} v3_poly1305_ctx_t;

/**
 * @brief AEAD 加密上下文
 */
typedef struct v3_aead_ctx_s {
    u8      key[V3_CRYPTO_KEY_SIZE];    /* 主密钥 */
    bool    initialized;                 /* 是否已初始化 */
} v3_aead_ctx_t;

/* =========================================================
 * 加密模块 API
 * ========================================================= */

/**
 * @brief 初始化加密模块
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_crypto_init(void);

/**
 * @brief 关闭加密模块
 */
V3_API void v3_crypto_shutdown(void);

/* =========================================================
 * ChaCha20 流密码
 * ========================================================= */

/**
 * @brief 初始化 ChaCha20
 * @param ctx 上下文
 * @param key 密钥（32字节）
 * @param nonce Nonce（12字节）
 * @param counter 初始计数器
 */
V3_API void v3_chacha20_init(
    v3_chacha20_ctx_t *ctx,
    const u8 key[V3_CRYPTO_KEY_SIZE],
    const u8 nonce[V3_CRYPTO_NONCE_SIZE],
    u32 counter
);

/**
 * @brief ChaCha20 加密/解密
 * @param ctx 上下文
 * @param out 输出缓冲区
 * @param in 输入数据（可与 out 相同）
 * @param len 数据长度
 */
V3_API void v3_chacha20_xor(
    v3_chacha20_ctx_t *ctx,
    u8 *out,
    const u8 *in,
    usize len
);

/**
 * @brief ChaCha20 生成密钥流
 * @param ctx 上下文
 * @param out 输出缓冲区
 * @param len 长度
 */
V3_API void v3_chacha20_keystream(
    v3_chacha20_ctx_t *ctx,
    u8 *out,
    usize len
);

/* =========================================================
 * Poly1305 MAC
 * ========================================================= */

/**
 * @brief 初始化 Poly1305
 * @param ctx 上下文
 * @param key 一次性密钥（32字节）
 */
V3_API void v3_poly1305_init(
    v3_poly1305_ctx_t *ctx,
    const u8 key[V3_CRYPTO_KEY_SIZE]
);

/**
 * @brief 更新 Poly1305
 * @param ctx 上下文
 * @param data 数据
 * @param len 长度
 */
V3_API void v3_poly1305_update(
    v3_poly1305_ctx_t *ctx,
    const u8 *data,
    usize len
);

/**
 * @brief 完成 Poly1305 计算
 * @param ctx 上下文
 * @param mac 输出 MAC（16字节）
 */
V3_API void v3_poly1305_final(
    v3_poly1305_ctx_t *ctx,
    u8 mac[V3_CRYPTO_TAG_SIZE]
);

/**
 * @brief 一次性计算 Poly1305
 * @param mac 输出 MAC
 * @param data 数据
 * @param len 长度
 * @param key 密钥
 */
V3_API void v3_poly1305(
    u8 mac[V3_CRYPTO_TAG_SIZE],
    const u8 *data,
    usize len,
    const u8 key[V3_CRYPTO_KEY_SIZE]
);

/* =========================================================
 * ChaCha20-Poly1305 AEAD
 * ========================================================= */

/**
 * @brief 初始化 AEAD 上下文
 * @param ctx 上下文
 * @param key 主密钥（32字节）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_aead_init(
    v3_aead_ctx_t *ctx,
    const u8 key[V3_CRYPTO_KEY_SIZE]
);

/**
 * @brief 清理 AEAD 上下文
 * @param ctx 上下文
 */
V3_API void v3_aead_cleanup(v3_aead_ctx_t *ctx);

/**
 * @brief AEAD 加密
 * @param ctx 上下文
 * @param ciphertext 输出密文
 * @param tag 输出认证标签（16字节）
 * @param plaintext 明文
 * @param plaintext_len 明文长度
 * @param aad 附加认证数据
 * @param aad_len AAD 长度
 * @param nonce Nonce（12字节）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_aead_encrypt(
    v3_aead_ctx_t *ctx,
    u8 *ciphertext,
    u8 tag[V3_CRYPTO_TAG_SIZE],
    const u8 *plaintext,
    usize plaintext_len,
    const u8 *aad,
    usize aad_len,
    const u8 nonce[V3_CRYPTO_NONCE_SIZE]
);

/**
 * @brief AEAD 解密
 * @param ctx 上下文
 * @param plaintext 输出明文
 * @param ciphertext 密文
 * @param ciphertext_len 密文长度
 * @param tag 认证标签
 * @param aad 附加认证数据
 * @param aad_len AAD 长度
 * @param nonce Nonce
 * @return V3_OK 成功，V3_ERR_CRYPTO_AUTH_FAILED 认证失败
 */
V3_API v3_error_t v3_aead_decrypt(
    v3_aead_ctx_t *ctx,
    u8 *plaintext,
    const u8 *ciphertext,
    usize ciphertext_len,
    const u8 tag[V3_CRYPTO_TAG_SIZE],
    const u8 *aad,
    usize aad_len,
    const u8 nonce[V3_CRYPTO_NONCE_SIZE]
);

/**
 * @brief 无上下文 AEAD 加密
 */
V3_API v3_error_t v3_aead_encrypt_oneshot(
    u8 *ciphertext,
    u8 tag[V3_CRYPTO_TAG_SIZE],
    const u8 *plaintext,
    usize plaintext_len,
    const u8 *aad,
    usize aad_len,
    const u8 nonce[V3_CRYPTO_NONCE_SIZE],
    const u8 key[V3_CRYPTO_KEY_SIZE]
);

/**
 * @brief 无上下文 AEAD 解密
 */
V3_API v3_error_t v3_aead_decrypt_oneshot(
    u8 *plaintext,
    const u8 *ciphertext,
    usize ciphertext_len,
    const u8 tag[V3_CRYPTO_TAG_SIZE],
    const u8 *aad,
    usize aad_len,
    const u8 nonce[V3_CRYPTO_NONCE_SIZE],
    const u8 key[V3_CRYPTO_KEY_SIZE]
);

/* =========================================================
 * Magic 派生（与服务端 derive_magic 一致）
 * ========================================================= */

/**
 * @brief 派生 Magic 值
 * @param key 主密钥（32字节）
 * @param window 时间窗口
 * @return 4字节 Magic 值
 */
V3_API u32 v3_crypto_derive_magic(
    const u8 key[V3_CRYPTO_KEY_SIZE],
    u64 window
);

/**
 * @brief 获取当前 Magic
 * @param key 主密钥
 * @return 当前时间窗口的 Magic
 */
V3_API u32 v3_crypto_current_magic(const u8 key[V3_CRYPTO_KEY_SIZE]);

/**
 * @brief 验证 Magic
 * @param key 主密钥
 * @param magic 收到的 Magic
 * @param tolerance 允许的时间窗口偏差
 * @return true 有效
 */
V3_API bool v3_crypto_verify_magic(
    const u8 key[V3_CRYPTO_KEY_SIZE],
    u32 magic,
    u32 tolerance
);

/**
 * @brief 获取有效 Magic 列表
 * @param key 主密钥
 * @param magics 输出数组
 * @param count 数组大小
 * @return 实际填充数量
 */
V3_API u32 v3_crypto_get_valid_magics(
    const u8 key[V3_CRYPTO_KEY_SIZE],
    u32 *magics,
    u32 count
);

/* =========================================================
 * 哈希函数
 * ========================================================= */

/**
 * @brief 简单哈希（用于 Magic 派生）
 * @param out 输出（32字节）
 * @param data 输入数据
 * @param len 数据长度
 */
V3_API void v3_crypto_hash(
    u8 out[V3_CRYPTO_HASH_SIZE],
    const u8 *data,
    usize len
);

/* =========================================================
 * 安全工具函数
 * ========================================================= */

/**
 * @brief 安全内存清零
 * @param ptr 内存指针
 * @param len 长度
 */
V3_API void v3_crypto_zero(void *ptr, usize len);

/**
 * @brief 恒定时间比较
 * @param a 第一个缓冲区
 * @param b 第二个缓冲区
 * @param len 比较长度
 * @return 0 相等，非0 不相等
 */
V3_API int v3_crypto_verify(const void *a, const void *b, usize len);

/**
 * @brief 恒定时间比较 16 字节
 * @param a 第一个缓冲区
 * @param b 第二个缓冲区
 * @return 0 相等，-1 不相等
 */
V3_API int v3_crypto_verify16(const u8 a[16], const u8 b[16]);

/**
 * @brief 恒定时间比较 32 字节
 * @param a 第一个缓冲区
 * @param b 第二个缓冲区
 * @return 0 相等，-1 不相等
 */
V3_API int v3_crypto_verify32(const u8 a[32], const u8 b[32]);

/**
 * @brief 生成加密安全随机字节
 * @param buf 输出缓冲区
 * @param len 长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_crypto_random(u8 *buf, usize len);

/**
 * @brief 生成随机 Nonce
 * @param nonce 输出 Nonce
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_crypto_random_nonce(u8 nonce[V3_CRYPTO_NONCE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* V3_CRYPTO_H */
