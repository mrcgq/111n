
/*
 * v3_crypto.c - v3 加密模块实现
 * 
 * 功能：
 * - ChaCha20-Poly1305 AEAD (RFC 7539)
 * - BLAKE2b Hash
 * - Magic 派生与验证
 * - 密钥管理
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_crypto.h"
#include "v3_log.h"
#include "v3_platform.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

/* =========================================================
 * 配置
 * ========================================================= */

#define CHACHA20_BLOCK_SIZE     64
#define CHACHA20_KEY_SIZE       32
#define CHACHA20_NONCE_SIZE     12
#define POLY1305_KEY_SIZE       32
#define POLY1305_TAG_SIZE       16
#define BLAKE2B_BLOCK_SIZE      128
#define MAGIC_WINDOW_SEC        60

/* =========================================================
 * 工具宏
 * ========================================================= */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define U8TO32_LE(p) \
    (((uint32_t)(p)[0]) | ((uint32_t)(p)[1] << 8) | \
     ((uint32_t)(p)[2] << 16) | ((uint32_t)(p)[3] << 24))
#define U32TO8_LE(p, v) do { \
    (p)[0] = (uint8_t)((v)); \
    (p)[1] = (uint8_t)((v) >> 8); \
    (p)[2] = (uint8_t)((v) >> 16); \
    (p)[3] = (uint8_t)((v) >> 24); \
} while (0)

/* =========================================================
 * ChaCha20 实现
 * ========================================================= */

#define QUARTERROUND(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    
    for (int i = 0; i < 16; i++) {
        x[i] = in[i];
    }
    
    for (int i = 0; i < 10; i++) {
        /* 列轮 */
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* 对角轮 */
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        out[i] = x[i] + in[i];
    }
}

static void chacha20_init_state(uint32_t state[16], const uint8_t key[32],
                                 const uint8_t nonce[12], uint32_t counter) {
    /* 常量 "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    /* 密钥 */
    state[4]  = U8TO32_LE(key + 0);
    state[5]  = U8TO32_LE(key + 4);
    state[6]  = U8TO32_LE(key + 8);
    state[7]  = U8TO32_LE(key + 12);
    state[8]  = U8TO32_LE(key + 16);
    state[9]  = U8TO32_LE(key + 20);
    state[10] = U8TO32_LE(key + 24);
    state[11] = U8TO32_LE(key + 28);
    
    /* 计数器 */
    state[12] = counter;
    
    /* Nonce */
    state[13] = U8TO32_LE(nonce + 0);
    state[14] = U8TO32_LE(nonce + 4);
    state[15] = U8TO32_LE(nonce + 8);
}

static void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t key[32], const uint8_t nonce[12],
                          uint32_t counter) {
    uint32_t state[16];
    uint32_t block[16];
    uint8_t keystream[CHACHA20_BLOCK_SIZE];
    
    chacha20_init_state(state, key, nonce, counter);
    
    size_t offset = 0;
    while (offset < len) {
        chacha20_block(block, state);
        
        /* 转换为字节流 */
        for (int i = 0; i < 16; i++) {
            U32TO8_LE(keystream + i * 4, block[i]);
        }
        
        /* XOR */
        size_t chunk = (len - offset > CHACHA20_BLOCK_SIZE) ? 
                       CHACHA20_BLOCK_SIZE : (len - offset);
        
        for (size_t i = 0; i < chunk; i++) {
            if (in) {
                out[offset + i] = in[offset + i] ^ keystream[i];
            } else {
                out[offset + i] = keystream[i];
            }
        }
        
        offset += chunk;
        state[12]++;  /* 增加计数器 */
    }
    
    /* 清理敏感数据 */
    memset(state, 0, sizeof(state));
    memset(block, 0, sizeof(block));
    memset(keystream, 0, sizeof(keystream));
}

/* =========================================================
 * Poly1305 实现
 * ========================================================= */

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_state;

static void poly1305_init(poly1305_state *st, const uint8_t key[32]) {
    /* r = key[0..15] clamped */
    st->r[0] = (U8TO32_LE(key + 0)) & 0x3ffffff;
    st->r[1] = (U8TO32_LE(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (U8TO32_LE(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (U8TO32_LE(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (U8TO32_LE(key + 12) >> 8) & 0x00fffff;
    
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;
    
    st->pad[0] = U8TO32_LE(key + 16);
    st->pad[1] = U8TO32_LE(key + 20);
    st->pad[2] = U8TO32_LE(key + 24);
    st->pad[3] = U8TO32_LE(key + 28);
    
    st->leftover = 0;
    st->final = 0;
}

static void poly1305_blocks(poly1305_state *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1 << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    
    while (bytes >= 16) {
        h0 += (U8TO32_LE(m + 0)) & 0x3ffffff;
        h1 += (U8TO32_LE(m + 3) >> 2) & 0x3ffffff;
        h2 += (U8TO32_LE(m + 6) >> 4) & 0x3ffffff;
        h3 += (U8TO32_LE(m + 9) >> 6) & 0x3ffffff;
        h4 += (U8TO32_LE(m + 12) >> 8) | hibit;
        
        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;
        
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        
        m += 16;
        bytes -= 16;
    }
    
    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static void poly1305_update(poly1305_state *st, const uint8_t *m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        memcpy(st->buffer + st->leftover, m, want);
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    
    if (bytes >= 16) {
        size_t want = bytes & ~15;
        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }
    
    if (bytes) {
        memcpy(st->buffer, m, bytes);
        st->leftover = bytes;
    }
}

static void poly1305_finish(poly1305_state *st, uint8_t mac[16]) {
    if (st->leftover) {
        st->buffer[st->leftover++] = 1;
        while (st->leftover < 16) {
            st->buffer[st->leftover++] = 0;
        }
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }
    
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;
    
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);
    
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;
    
    uint64_t f;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;
    
    U32TO8_LE(mac + 0, h0 | (h1 << 26));
    U32TO8_LE(mac + 4, (h1 >> 6) | (h2 << 20));
    U32TO8_LE(mac + 8, (h2 >> 12) | (h3 << 14));
    U32TO8_LE(mac + 12, (h3 >> 18) | (h4 << 8));
    
    /* 清理 */
    memset(st, 0, sizeof(*st));
}

/* =========================================================
 * BLAKE2b 实现（简化版，用于 Magic 派生）
 * ========================================================= */

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define G(r, i, a, b, c, d, m) do { \
    a += b + m[blake2b_sigma[r][2*i]]; \
    d = ROTR64(d ^ a, 32); \
    c += d; \
    b = ROTR64(b ^ c, 24); \
    a += b + m[blake2b_sigma[r][2*i+1]]; \
    d = ROTR64(d ^ a, 16); \
    c += d; \
    b = ROTR64(b ^ c, 63); \
} while (0)

static void blake2b_compress(uint64_t h[8], const uint8_t block[128], 
                              uint64_t t, bool last) {
    uint64_t v[16];
    uint64_t m[16];
    
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[i + 8] = blake2b_iv[i];
    
    v[12] ^= t;
    if (last) v[14] ^= ~0ULL;
    
    for (int i = 0; i < 16; i++) {
        m[i] = ((uint64_t)block[i*8 + 0]) |
               ((uint64_t)block[i*8 + 1] << 8) |
               ((uint64_t)block[i*8 + 2] << 16) |
               ((uint64_t)block[i*8 + 3] << 24) |
               ((uint64_t)block[i*8 + 4] << 32) |
               ((uint64_t)block[i*8 + 5] << 40) |
               ((uint64_t)block[i*8 + 6] << 48) |
               ((uint64_t)block[i*8 + 7] << 56);
    }
    
    for (int r = 0; r < 12; r++) {
        G(r, 0, v[0], v[4], v[8],  v[12], m);
        G(r, 1, v[1], v[5], v[9],  v[13], m);
        G(r, 2, v[2], v[6], v[10], v[14], m);
        G(r, 3, v[3], v[7], v[11], v[15], m);
        G(r, 4, v[0], v[5], v[10], v[15], m);
        G(r, 5, v[1], v[6], v[11], v[12], m);
        G(r, 6, v[2], v[7], v[8],  v[13], m);
        G(r, 7, v[3], v[4], v[9],  v[14], m);
    }
    
    for (int i = 0; i < 8; i++) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2b(uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen,
                    const uint8_t *key, size_t keylen) {
    uint64_t h[8];
    uint8_t block[128];
    size_t offset = 0;
    
    for (int i = 0; i < 8; i++) h[i] = blake2b_iv[i];
    h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    
    if (keylen > 0) {
        memset(block, 0, 128);
        memcpy(block, key, keylen);
        blake2b_compress(h, block, 128, false);
        offset = 128;
    }
    
    while (inlen > 128) {
        memcpy(block, in, 128);
        blake2b_compress(h, block, offset + 128, false);
        offset += 128;
        in += 128;
        inlen -= 128;
    }
    
    memset(block, 0, 128);
    memcpy(block, in, inlen);
    blake2b_compress(h, block, offset + inlen, true);
    
    for (size_t i = 0; i < outlen; i++) {
        out[i] = (h[i / 8] >> (8 * (i % 8))) & 0xFF;
    }
}

/* =========================================================
 * 恒定时间比较
 * ========================================================= */

static int crypto_verify_16(const uint8_t *x, const uint8_t *y) {
    uint32_t d = 0;
    for (int i = 0; i < 16; i++) {
        d |= x[i] ^ y[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

/* =========================================================
 * 随机数生成
 * ========================================================= */

v3_error_t v3_crypto_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return V3_ERR_INVALID_PARAM;
    
#ifdef _WIN32
    HCRYPTPROV hProv;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, 
                               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        return V3_ERR_CRYPTO_RANDOM;
    }
    
    BOOL result = CryptGenRandom(hProv, (DWORD)len, buf);
    CryptReleaseContext(hProv, 0);
    
    if (!result) {
        return V3_ERR_CRYPTO_RANDOM;
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return V3_ERR_CRYPTO_RANDOM;
    }
    
    ssize_t n = read(fd, buf, len);
    close(fd);
    
    if (n != (ssize_t)len) {
        return V3_ERR_CRYPTO_RANDOM;
    }
#endif
    
    return V3_OK;
}

/* =========================================================
 * AEAD 加密/解密（RFC 7539）
 * ========================================================= */

v3_error_t v3_crypto_aead_encrypt(uint8_t *ciphertext,
                                   uint8_t tag[16],
                                   const uint8_t *plaintext,
                                   size_t plaintext_len,
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t nonce[12],
                                   const uint8_t key[32]) {
    if (!ciphertext || !tag || !nonce || !key) {
        return V3_ERR_INVALID_PARAM;
    }
    
    /* 1. 生成 Poly1305 一次性密钥（Counter = 0） */
    uint8_t poly_key[64];
    memset(poly_key, 0, sizeof(poly_key));
    chacha20_xor(poly_key, poly_key, 64, key, nonce, 0);
    
    /* 2. 加密数据（Counter 从 1 开始） */
    if (plaintext && plaintext_len > 0) {
        chacha20_xor(ciphertext, plaintext, plaintext_len, key, nonce, 1);
    }
    
    /* 3. 计算 MAC */
    /* Input: AAD | pad16(AAD) | Ciphertext | pad16(Ciphertext) | len(AAD) | len(CT) */
    poly1305_state st;
    poly1305_init(&st, poly_key);
    
    if (aad && aad_len > 0) {
        poly1305_update(&st, aad, aad_len);
        if (aad_len % 16 != 0) {
            uint8_t padding[16] = {0};
            poly1305_update(&st, padding, 16 - (aad_len % 16));
        }
    }
    
    if (plaintext_len > 0) {
        poly1305_update(&st, ciphertext, plaintext_len);
        if (plaintext_len % 16 != 0) {
            uint8_t padding[16] = {0};
            poly1305_update(&st, padding, 16 - (plaintext_len % 16));
        }
    }
    
    uint8_t lens[16];
    memset(lens, 0, 16);
    for (int i = 0; i < 8; i++) {
        lens[i] = (aad_len >> (i * 8)) & 0xFF;
        lens[i + 8] = (plaintext_len >> (i * 8)) & 0xFF;
    }
    poly1305_update(&st, lens, 16);
    
    poly1305_finish(&st, tag);
    
    /* 清理 */
    memset(poly_key, 0, sizeof(poly_key));
    
    return V3_OK;
}

v3_error_t v3_crypto_aead_decrypt(uint8_t *plaintext,
                                   const uint8_t *ciphertext,
                                   size_t ciphertext_len,
                                   const uint8_t tag[16],
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t nonce[12],
                                   const uint8_t key[32]) {
    if (!tag || !nonce || !key) {
        return V3_ERR_INVALID_PARAM;
    }
    
    /* 1. 生成 Poly1305 一次性密钥 */
    uint8_t poly_key[64];
    memset(poly_key, 0, sizeof(poly_key));
    chacha20_xor(poly_key, poly_key, 64, key, nonce, 0);
    
    /* 2. 重新计算 MAC */
    uint8_t computed_tag[16];
    poly1305_state st;
    poly1305_init(&st, poly_key);
    
    if (aad && aad_len > 0) {
        poly1305_update(&st, aad, aad_len);
        if (aad_len % 16 != 0) {
            uint8_t padding[16] = {0};
            poly1305_update(&st, padding, 16 - (aad_len % 16));
        }
    }
    
    if (ciphertext && ciphertext_len > 0) {
        poly1305_update(&st, ciphertext, ciphertext_len);
        if (ciphertext_len % 16 != 0) {
            uint8_t padding[16] = {0};
            poly1305_update(&st, padding, 16 - (ciphertext_len % 16));
        }
    }
    
    uint8_t lens[16];
    memset(lens, 0, 16);
    for (int i = 0; i < 8; i++) {
        lens[i] = (aad_len >> (i * 8)) & 0xFF;
        lens[i + 8] = (ciphertext_len >> (i * 8)) & 0xFF;
    }
    poly1305_update(&st, lens, 16);
    
    poly1305_finish(&st, computed_tag);
    
    /* 3. 验证 Tag（恒定时间） */
    if (crypto_verify_16(tag, computed_tag) != 0) {
        memset(poly_key, 0, sizeof(poly_key));
        return V3_ERR_CRYPTO_AUTH;
    }
    
    /* 4. 解密 */
    if (plaintext && ciphertext && ciphertext_len > 0) {
        chacha20_xor(plaintext, ciphertext, ciphertext_len, key, nonce, 1);
    }
    
    /* 清理 */
    memset(poly_key, 0, sizeof(poly_key));
    
    return V3_OK;
}

/* =========================================================
 * Magic 派生与验证
 * ========================================================= */

uint32_t v3_crypto_derive_magic(const uint8_t key[32], uint64_t window) {
    /* 构造输入：Key (32 bytes) + Window (8 bytes) */
    uint8_t input[40];
    memcpy(input, key, 32);
    
    /* 小端序写入窗口值 */
    for (int i = 0; i < 8; i++) {
        input[32 + i] = (window >> (i * 8)) & 0xFF;
    }
    
    /* BLAKE2b Hash */
    uint8_t hash[32];
    blake2b(hash, 32, input, 40, NULL, 0);
    
    /* 取前 4 字节作为 Magic */
    uint32_t magic = U8TO32_LE(hash);
    
    /* 清理 */
    memset(input, 0, sizeof(input));
    memset(hash, 0, sizeof(hash));
    
    return magic;
}

uint32_t v3_crypto_get_current_magic(const uint8_t key[32]) {
    time_t now = time(NULL);
    uint64_t window = now / MAGIC_WINDOW_SEC;
    return v3_crypto_derive_magic(key, window);
}

bool v3_crypto_verify_magic(const uint8_t key[32], uint32_t received, int tolerance) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    
    /* 检查当前窗口 */
    if (received == v3_crypto_derive_magic(key, current_window)) {
        return true;
    }
    
    /* 检查前后窗口 */
    for (int offset = 1; offset <= tolerance; offset++) {
        if (received == v3_crypto_derive_magic(key, current_window - offset)) {
            return true;
        }
        if (received == v3_crypto_derive_magic(key, current_window + offset)) {
            return true;
        }
    }
    
    return false;
}

void v3_crypto_get_valid_magics(const uint8_t key[32], uint32_t *magics, int count) {
    time_t now = time(NULL);
    uint64_t current_window = now / MAGIC_WINDOW_SEC;
    
    int half = count / 2;
    for (int i = 0; i < count; i++) {
        int64_t offset = i - half;
        magics[i] = v3_crypto_derive_magic(key, current_window + offset);
    }
}

/* =========================================================
 * 哈希
 * ========================================================= */

void v3_crypto_hash(uint8_t *out, size_t outlen,
                    const uint8_t *in, size_t inlen) {
    blake2b(out, outlen, in, inlen, NULL, 0);
}

/* =========================================================
 * 密钥派生
 * ========================================================= */

v3_error_t v3_crypto_derive_key(uint8_t *derived_key, size_t key_len,
                                 const uint8_t *master_key, size_t master_len,
                                 const uint8_t *salt, size_t salt_len,
                                 const uint8_t *info, size_t info_len) {
    if (!derived_key || key_len == 0 || !master_key || master_len == 0) {
        return V3_ERR_INVALID_PARAM;
    }
    
    /* 简化的 HKDF-like 派生 */
    uint8_t input[256];
    size_t input_len = 0;
    
    /* PRK = BLAKE2b(salt || master_key) */
    if (salt && salt_len > 0) {
        memcpy(input + input_len, salt, salt_len < 64 ? salt_len : 64);
        input_len += salt_len < 64 ? salt_len : 64;
    }
    memcpy(input + input_len, master_key, master_len < 64 ? master_len : 64);
    input_len += master_len < 64 ? master_len : 64;
    
    uint8_t prk[32];
    blake2b(prk, 32, input, input_len, NULL, 0);
    
    /* OKM = BLAKE2b(prk || info || counter) */
    input_len = 0;
    memcpy(input, prk, 32);
    input_len = 32;
    
    if (info && info_len > 0) {
        memcpy(input + input_len, info, info_len < 64 ? info_len : 64);
        input_len += info_len < 64 ? info_len : 64;
    }
    
    size_t generated = 0;
    uint8_t counter = 1;
    
    while (generated < key_len) {
        input[input_len] = counter++;
        
        uint8_t block[32];
        blake2b(block, 32, input, input_len + 1, NULL, 0);
        
        size_t copy = (key_len - generated) < 32 ? (key_len - generated) : 32;
        memcpy(derived_key + generated, block, copy);
        generated += copy;
    }
    
    /* 清理 */
    memset(prk, 0, sizeof(prk));
    memset(input, 0, sizeof(input));
    
    return V3_OK;
}

/* =========================================================
 * 加密上下文管理
 * ========================================================= */

struct v3_crypto_ctx_s {
    uint8_t     master_key[32];
    bool        key_set;
    uint64_t    nonce_counter;
    v3_mutex_t  mutex;
};

v3_crypto_ctx_t* v3_crypto_create(void) {
    v3_crypto_ctx_t *ctx = (v3_crypto_ctx_t*)calloc(1, sizeof(v3_crypto_ctx_t));
    if (!ctx) return NULL;
    
    v3_mutex_init(&ctx->mutex);
    return ctx;
}

void v3_crypto_destroy(v3_crypto_ctx_t *ctx) {
    if (!ctx) return;
    
    /* 安全清除密钥 */
    memset(ctx->master_key, 0, sizeof(ctx->master_key));
    
    v3_mutex_destroy(&ctx->mutex);
    free(ctx);
}

v3_error_t v3_crypto_set_key(v3_crypto_ctx_t *ctx, const uint8_t *key, size_t len) {
    if (!ctx || !key || len != 32) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_mutex_lock(&ctx->mutex);
    memcpy(ctx->master_key, key, 32);
    ctx->key_set = true;
    ctx->nonce_counter = 0;
    v3_mutex_unlock(&ctx->mutex);
    
    return V3_OK;
}

v3_error_t v3_crypto_generate_nonce(v3_crypto_ctx_t *ctx, uint8_t nonce[12]) {
    if (!ctx || !nonce) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(&ctx->mutex);
    
    /* 组合随机数和计数器 */
    uint8_t random_part[4];
    v3_crypto_random(random_part, 4);
    
    /* Nonce 格式: [4 bytes random] [8 bytes counter] */
    memcpy(nonce, random_part, 4);
    
    uint64_t counter = ctx->nonce_counter++;
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] = (counter >> (i * 8)) & 0xFF;
    }
    
    v3_mutex_unlock(&ctx->mutex);
    
    return V3_OK;
}
