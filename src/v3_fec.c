
/*
 * v3_fec.c - v3 FEC (前向纠错) 实现
 * 
 * 功能：
 * - XOR FEC（低 CPU）
 * - Reed-Solomon FEC（高恢复率）
 * - 自动模式选择
 * - 与服务端 v3_fec_simd.c 协议兼容
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_fec.h"
#include "v3_log.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================
 * 配置常量
 * ========================================================= */

#define FEC_MAX_DATA_SHARDS     20
#define FEC_MAX_PARITY_SHARDS   10
#define FEC_MAX_TOTAL_SHARDS    30
#define FEC_SHARD_SIZE          1400
#define FEC_DECODE_CACHE_SIZE   64
#define FEC_XOR_GROUP_SIZE      4

/* =========================================================
 * GF(2^8) 基础运算
 * ========================================================= */

static uint8_t gf_exp[512];
static uint8_t gf_log[256];
static bool gf_initialized = false;

static void gf_init(void) {
    if (gf_initialized) return;
    
    int x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        gf_log[x] = i;
        x <<= 1;
        if (x & 0x100) x ^= 0x11d;  /* 不可约多项式 */
    }
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
    gf_log[0] = 0;
    
    gf_initialized = true;
}

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp[gf_log[a] + gf_log[b]];
}

static inline uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) return 0;
    if (b == 0) return 0;  /* 错误：除以零 */
    return gf_exp[gf_log[a] + 255 - gf_log[b]];
}

static inline uint8_t gf_inv(uint8_t a) {
    if (a == 0) return 0;
    return gf_exp[255 - gf_log[a]];
}

/* GF(2^8) 向量运算 */
static void gf_mul_add_region(uint8_t *dst, const uint8_t *src, uint8_t coef, size_t len) {
    if (coef == 0) return;
    
    if (coef == 1) {
        for (size_t i = 0; i < len; i++) {
            dst[i] ^= src[i];
        }
        return;
    }
    
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= gf_mul(src[i], coef);
    }
}

/* =========================================================
 * XOR FEC 实现
 * ========================================================= */

typedef struct {
    uint32_t group_id;
    uint8_t  shards[FEC_XOR_GROUP_SIZE + 1][FEC_SHARD_SIZE];
    bool     present[FEC_XOR_GROUP_SIZE + 1];
    size_t   shard_len;
    uint64_t create_time;
} xor_decode_cache_t;

typedef struct {
    uint32_t            next_group_id;
    uint8_t             group_size;
    xor_decode_cache_t  cache[32];
    int                 cache_count;
} xor_fec_ctx_t;

static int xor_encode(xor_fec_ctx_t *ctx,
                      const uint8_t *data, size_t len,
                      uint8_t out[][FEC_SHARD_SIZE],
                      size_t out_lens[],
                      uint32_t *group_id) {
    uint8_t gs = ctx->group_size;
    *group_id = ctx->next_group_id++;
    
    size_t shard_size = (len + gs - 1) / gs;
    if (shard_size > FEC_SHARD_SIZE - 8) shard_size = FEC_SHARD_SIZE - 8;
    
    /* 数据分片 */
    for (int i = 0; i < gs; i++) {
        /* 头部: [GroupID(4)] [ShardIdx(1)] [GroupSize(1)] [ShardSize(2)] */
        out[i][0] = (*group_id >> 24) & 0xFF;
        out[i][1] = (*group_id >> 16) & 0xFF;
        out[i][2] = (*group_id >> 8) & 0xFF;
        out[i][3] = *group_id & 0xFF;
        out[i][4] = i;
        out[i][5] = gs;
        out[i][6] = (shard_size >> 8) & 0xFF;
        out[i][7] = shard_size & 0xFF;
        
        size_t offset = i * shard_size;
        size_t copy_len = (offset + shard_size <= len) ? shard_size :
                          (offset < len ? len - offset : 0);
        
        if (copy_len > 0) {
            memcpy(out[i] + 8, data + offset, copy_len);
        }
        if (copy_len < shard_size) {
            memset(out[i] + 8 + copy_len, 0, shard_size - copy_len);
        }
        out_lens[i] = shard_size + 8;
    }
    
    /* 校验分片 (XOR) */
    out[gs][0] = (*group_id >> 24) & 0xFF;
    out[gs][1] = (*group_id >> 16) & 0xFF;
    out[gs][2] = (*group_id >> 8) & 0xFF;
    out[gs][3] = *group_id & 0xFF;
    out[gs][4] = gs;  /* 校验分片索引 = 组大小 */
    out[gs][5] = gs;
    out[gs][6] = (shard_size >> 8) & 0xFF;
    out[gs][7] = shard_size & 0xFF;
    
    memset(out[gs] + 8, 0, shard_size);
    
    /* XOR 所有数据分片 */
    for (int i = 0; i < gs; i++) {
        for (size_t j = 0; j < shard_size; j++) {
            out[gs][8 + j] ^= out[i][8 + j];
        }
    }
    out_lens[gs] = shard_size + 8;
    
    return gs + 1;
}

static int xor_decode(xor_fec_ctx_t *ctx, 
                      uint32_t group_id, uint8_t shard_idx,
                      const uint8_t *data, size_t len,
                      uint8_t *out_data, size_t *out_len) {
    if (len < 8) return -1;
    
    uint8_t gs = data[5];
    size_t shard_size = (data[6] << 8) | data[7];
    
    /* 查找或创建缓存条目 */
    int cache_idx = -1;
    for (int i = 0; i < ctx->cache_count; i++) {
        if (ctx->cache[i].group_id == group_id) {
            cache_idx = i;
            break;
        }
    }
    
    if (cache_idx < 0) {
        if (ctx->cache_count >= 32) {
            memmove(&ctx->cache[0], &ctx->cache[1], 31 * sizeof(xor_decode_cache_t));
            ctx->cache_count = 31;
        }
        cache_idx = ctx->cache_count++;
        memset(&ctx->cache[cache_idx], 0, sizeof(xor_decode_cache_t));
        ctx->cache[cache_idx].group_id = group_id;
        ctx->cache[cache_idx].shard_len = shard_size;
    }
    
    /* 存储分片 */
    if (shard_idx <= gs) {
        memcpy(ctx->cache[cache_idx].shards[shard_idx], data + 8, shard_size);
        ctx->cache[cache_idx].present[shard_idx] = true;
    }
    
    /* 检查是否可以恢复 */
    int present_count = 0;
    int missing_idx = -1;
    for (int i = 0; i <= gs; i++) {
        if (ctx->cache[cache_idx].present[i]) {
            present_count++;
        } else {
            missing_idx = i;
        }
    }
    
    if (present_count < gs) {
        return 0;  /* 等待更多分片 */
    }
    
    /* 恢复丢失的数据分片 */
    if (present_count == gs && missing_idx >= 0 && missing_idx < gs) {
        memset(ctx->cache[cache_idx].shards[missing_idx], 0, shard_size);
        
        for (int i = 0; i <= gs; i++) {
            if (i != missing_idx && ctx->cache[cache_idx].present[i]) {
                for (size_t j = 0; j < shard_size; j++) {
                    ctx->cache[cache_idx].shards[missing_idx][j] ^=
                        ctx->cache[cache_idx].shards[i][j];
                }
            }
        }
        ctx->cache[cache_idx].present[missing_idx] = true;
    }
    
    /* 组装输出 */
    *out_len = 0;
    for (int i = 0; i < gs; i++) {
        memcpy(out_data + *out_len, ctx->cache[cache_idx].shards[i], shard_size);
        *out_len += shard_size;
    }
    
    /* 清除缓存条目 */
    ctx->cache[cache_idx].group_id = 0;
    
    return 1;  /* 成功 */
}

/* =========================================================
 * Reed-Solomon 实现
 * ========================================================= */

typedef struct {
    uint32_t group_id;
    uint8_t  shards[FEC_MAX_TOTAL_SHARDS][FEC_SHARD_SIZE];
    bool     present[FEC_MAX_TOTAL_SHARDS];
    size_t   shard_size;
    uint8_t  data_count;
    uint8_t  parity_count;
} rs_decode_cache_t;

typedef struct {
    uint8_t             data_shards;
    uint8_t             parity_shards;
    uint32_t            next_group_id;
    rs_decode_cache_t   cache[FEC_DECODE_CACHE_SIZE];
    int                 cache_count;
} rs_fec_ctx_t;

/* 生成 Vandermonde 矩阵 */
static void rs_generate_matrix(uint8_t *matrix, int data_count, int parity_count) {
    for (int p = 0; p < parity_count; p++) {
        uint8_t x = data_count + p + 1;
        matrix[p * data_count] = 1;
        for (int j = 1; j < data_count; j++) {
            matrix[p * data_count + j] = gf_mul(matrix[p * data_count + j - 1], x);
        }
    }
}

static void rs_encode(rs_fec_ctx_t *ctx,
                      const uint8_t *data, size_t len,
                      uint8_t out[][FEC_SHARD_SIZE],
                      size_t out_lens[],
                      uint32_t *group_id) {
    uint8_t ds = ctx->data_shards;
    uint8_t ps = ctx->parity_shards;
    *group_id = ctx->next_group_id++;
    
    size_t shard_size = (len + ds - 1) / ds;
    if (shard_size > FEC_SHARD_SIZE - 8) shard_size = FEC_SHARD_SIZE - 8;
    
    /* 对齐到 16 字节 */
    shard_size = (shard_size + 15) & ~15;
    if (shard_size > FEC_SHARD_SIZE - 8) shard_size = (FEC_SHARD_SIZE - 8) & ~15;
    
    /* 准备数据分片 */
    uint8_t data_buf[FEC_MAX_DATA_SHARDS][FEC_SHARD_SIZE];
    memset(data_buf, 0, sizeof(data_buf));
    
    size_t offset = 0;
    for (int i = 0; i < ds; i++) {
        size_t copy = (len > offset) ? (len - offset) : 0;
        if (copy > shard_size) copy = shard_size;
        if (copy > 0) memcpy(data_buf[i], data + offset, copy);
        offset += shard_size;
    }
    
    /* 生成矩阵 */
    uint8_t matrix[FEC_MAX_PARITY_SHARDS * FEC_MAX_DATA_SHARDS];
    rs_generate_matrix(matrix, ds, ps);
    
    /* 计算校验分片 */
    uint8_t parity_buf[FEC_MAX_PARITY_SHARDS][FEC_SHARD_SIZE];
    memset(parity_buf, 0, sizeof(parity_buf));
    
    for (int p = 0; p < ps; p++) {
        for (int d = 0; d < ds; d++) {
            gf_mul_add_region(parity_buf[p], data_buf[d], 
                             matrix[p * ds + d], shard_size);
        }
    }
    
    /* 打包数据分片 */
    for (int i = 0; i < ds; i++) {
        out[i][0] = (*group_id >> 24) & 0xFF;
        out[i][1] = (*group_id >> 16) & 0xFF;
        out[i][2] = (*group_id >> 8) & 0xFF;
        out[i][3] = *group_id & 0xFF;
        out[i][4] = i;
        out[i][5] = ds;
        out[i][6] = ps;
        out[i][7] = (shard_size >> 4) & 0xFF;
        memcpy(out[i] + 8, data_buf[i], shard_size);
        out_lens[i] = shard_size + 8;
    }
    
    /* 打包校验分片 */
    for (int i = 0; i < ps; i++) {
        int idx = ds + i;
        out[idx][0] = (*group_id >> 24) & 0xFF;
        out[idx][1] = (*group_id >> 16) & 0xFF;
        out[idx][2] = (*group_id >> 8) & 0xFF;
        out[idx][3] = *group_id & 0xFF;
        out[idx][4] = idx;
        out[idx][5] = ds;
        out[idx][6] = ps;
        out[idx][7] = (shard_size >> 4) & 0xFF;
        memcpy(out[idx] + 8, parity_buf[i], shard_size);
        out_lens[idx] = shard_size + 8;
    }
}

/* 高斯消元求逆 */
static int rs_invert_matrix(uint8_t *matrix, uint8_t *inv, int n) {
    /* 初始化单位矩阵 */
    memset(inv, 0, n * n);
    for (int i = 0; i < n; i++) {
        inv[i * n + i] = 1;
    }
    
    for (int col = 0; col < n; col++) {
        /* 找主元 */
        int pivot = -1;
        for (int row = col; row < n; row++) {
            if (matrix[row * n + col] != 0) {
                pivot = row;
                break;
            }
        }
        if (pivot < 0) return -1;  /* 奇异矩阵 */
        
        /* 交换行 */
        if (pivot != col) {
            for (int j = 0; j < n; j++) {
                uint8_t t = matrix[col * n + j];
                matrix[col * n + j] = matrix[pivot * n + j];
                matrix[pivot * n + j] = t;
                
                t = inv[col * n + j];
                inv[col * n + j] = inv[pivot * n + j];
                inv[pivot * n + j] = t;
            }
        }
        
        /* 归一化 */
        uint8_t scale = gf_inv(matrix[col * n + col]);
        for (int j = 0; j < n; j++) {
            matrix[col * n + j] = gf_mul(matrix[col * n + j], scale);
            inv[col * n + j] = gf_mul(inv[col * n + j], scale);
        }
        
        /* 消元 */
        for (int row = 0; row < n; row++) {
            if (row != col && matrix[row * n + col] != 0) {
                uint8_t factor = matrix[row * n + col];
                for (int j = 0; j < n; j++) {
                    matrix[row * n + j] ^= gf_mul(matrix[col * n + j], factor);
                    inv[row * n + j] ^= gf_mul(inv[col * n + j], factor);
                }
            }
        }
    }
    
    return 0;
}

static int rs_decode(rs_fec_ctx_t *ctx,
                     uint32_t group_id, uint8_t shard_idx,
                     const uint8_t *data, size_t len,
                     uint8_t *out_data, size_t *out_len) {
    if (len < 8) return -1;
    
    uint8_t ds = data[5];
    uint8_t ps = data[6];
    size_t shard_size = data[7] << 4;
    int total = ds + ps;
    
    /* 查找或创建缓存 */
    int cache_idx = -1;
    for (int i = 0; i < ctx->cache_count; i++) {
        if (ctx->cache[i].group_id == group_id) {
            cache_idx = i;
            break;
        }
    }
    
    if (cache_idx < 0) {
        if (ctx->cache_count >= FEC_DECODE_CACHE_SIZE) {
            memmove(&ctx->cache[0], &ctx->cache[1], 
                   (FEC_DECODE_CACHE_SIZE - 1) * sizeof(rs_decode_cache_t));
            ctx->cache_count = FEC_DECODE_CACHE_SIZE - 1;
        }
        cache_idx = ctx->cache_count++;
        memset(&ctx->cache[cache_idx], 0, sizeof(rs_decode_cache_t));
        ctx->cache[cache_idx].group_id = group_id;
        ctx->cache[cache_idx].shard_size = shard_size;
        ctx->cache[cache_idx].data_count = ds;
        ctx->cache[cache_idx].parity_count = ps;
    }
    
    /* 存储分片 */
    if (shard_idx < total) {
        memcpy(ctx->cache[cache_idx].shards[shard_idx], data + 8, shard_size);
        ctx->cache[cache_idx].present[shard_idx] = true;
    }
    
    /* 检查是否有足够分片 */
    int present_count = 0;
    for (int i = 0; i < total; i++) {
        if (ctx->cache[cache_idx].present[i]) present_count++;
    }
    
    if (present_count < ds) {
        return 0;  /* 等待更多分片 */
    }
    
    /* 检查是否需要恢复 */
    bool need_recovery = false;
    for (int i = 0; i < ds; i++) {
        if (!ctx->cache[cache_idx].present[i]) {
            need_recovery = true;
            break;
        }
    }
    
    if (need_recovery) {
        /* 构建解码矩阵 */
        uint8_t matrix[FEC_MAX_DATA_SHARDS * FEC_MAX_DATA_SHARDS];
        uint8_t *shard_ptrs[FEC_MAX_DATA_SHARDS];
        
        int idx = 0;
        for (int i = 0; i < total && idx < ds; i++) {
            if (ctx->cache[cache_idx].present[i]) {
                if (i < ds) {
                    /* 数据分片：单位行 */
                    memset(matrix + idx * ds, 0, ds);
                    matrix[idx * ds + i] = 1;
                } else {
                    /* 校验分片：Vandermonde 行 */
                    int p = i - ds;
                    uint8_t x = ds + p + 1;
                    matrix[idx * ds] = 1;
                    for (int j = 1; j < ds; j++) {
                        matrix[idx * ds + j] = gf_mul(matrix[idx * ds + j - 1], x);
                    }
                }
                shard_ptrs[idx] = ctx->cache[cache_idx].shards[i];
                idx++;
            }
        }
        
        /* 求逆矩阵 */
        uint8_t inv[FEC_MAX_DATA_SHARDS * FEC_MAX_DATA_SHARDS];
        if (rs_invert_matrix(matrix, inv, ds) < 0) {
            return -1;
        }
        
        /* 恢复丢失的数据分片 */
        for (int i = 0; i < ds; i++) {
            if (!ctx->cache[cache_idx].present[i]) {
                memset(ctx->cache[cache_idx].shards[i], 0, shard_size);
                for (int j = 0; j < ds; j++) {
                    gf_mul_add_region(ctx->cache[cache_idx].shards[i],
                                     shard_ptrs[j], inv[i * ds + j], shard_size);
                }
                ctx->cache[cache_idx].present[i] = true;
            }
        }
    }
    
    /* 组装输出 */
    *out_len = 0;
    for (int i = 0; i < ds; i++) {
        memcpy(out_data + *out_len, ctx->cache[cache_idx].shards[i], shard_size);
        *out_len += shard_size;
    }
    
    /* 清除缓存 */
    ctx->cache[cache_idx].group_id = 0;
    
    return 1;
}

/* =========================================================
 * FEC 引擎
 * ========================================================= */

struct v3_fec_s {
    v3_fec_type_t   type;
    uint8_t         data_shards;
    uint8_t         parity_shards;
    float           loss_rate;
    
    union {
        xor_fec_ctx_t   xor_ctx;
        rs_fec_ctx_t    rs_ctx;
    };
    
    /* 统计 */
    uint64_t        encode_count;
    uint64_t        decode_count;
    uint64_t        recovery_count;
    uint64_t        failure_count;
};

v3_fec_t* v3_fec_create(v3_fec_type_t type, uint8_t data_shards, uint8_t parity_shards) {
    gf_init();
    
    v3_fec_t *fec = (v3_fec_t*)calloc(1, sizeof(v3_fec_t));
    if (!fec) return NULL;
    
    if (type == V3_FEC_TYPE_AUTO) {
        if (data_shards <= 4 && parity_shards == 1) {
            type = V3_FEC_TYPE_XOR;
        } else {
            type = V3_FEC_TYPE_RS;
        }
    }
    
    fec->type = type;
    fec->data_shards = data_shards > 0 ? data_shards : 5;
    fec->parity_shards = parity_shards > 0 ? parity_shards : 2;
    
    if (type == V3_FEC_TYPE_XOR) {
        fec->xor_ctx.group_size = fec->data_shards;
    } else {
        fec->rs_ctx.data_shards = fec->data_shards;
        fec->rs_ctx.parity_shards = fec->parity_shards;
    }
    
    return fec;
}

void v3_fec_destroy(v3_fec_t *fec) {
    if (fec) free(fec);
}

int v3_fec_encode(v3_fec_t *fec,
                  const uint8_t *data, size_t len,
                  uint8_t out_shards[][FEC_SHARD_SIZE],
                  size_t out_lens[],
                  uint32_t *group_id) {
    if (!fec || !data || !out_shards || !out_lens || !group_id) {
        return -1;
    }
    
    fec->encode_count++;
    
    if (fec->type == V3_FEC_TYPE_XOR) {
        return xor_encode(&fec->xor_ctx, data, len, out_shards, out_lens, group_id);
    } else {
        rs_encode(&fec->rs_ctx, data, len, out_shards, out_lens, group_id);
        return fec->data_shards + fec->parity_shards;
    }
}

int v3_fec_decode(v3_fec_t *fec,
                  uint32_t group_id,
                  uint8_t shard_idx,
                  const uint8_t *shard_data, size_t shard_len,
                  uint8_t *out_data, size_t *out_len) {
    if (!fec || !shard_data || !out_data || !out_len) {
        return -1;
    }
    
    fec->decode_count++;
    
    int result;
    if (fec->type == V3_FEC_TYPE_XOR) {
        result = xor_decode(&fec->xor_ctx, group_id, shard_idx, 
                           shard_data, shard_len, out_data, out_len);
    } else {
        result = rs_decode(&fec->rs_ctx, group_id, shard_idx,
                          shard_data, shard_len, out_data, out_len);
    }
    
    if (result > 0) {
        fec->recovery_count++;
    } else if (result < 0) {
        fec->failure_count++;
    }
    
    return result;
}

void v3_fec_set_loss_rate(v3_fec_t *fec, float loss_rate) {
    if (!fec) return;
    
    fec->loss_rate = loss_rate;
    
    if (fec->type == V3_FEC_TYPE_XOR) return;
    
    /* 动态调整冗余率 */
    if (loss_rate < 0.05f) {
        fec->parity_shards = 2;
    } else if (loss_rate < 0.10f) {
        fec->parity_shards = 3;
    } else if (loss_rate < 0.20f) {
        fec->parity_shards = 4;
    } else if (loss_rate < 0.30f) {
        fec->parity_shards = 6;
    } else {
        fec->parity_shards = fec->data_shards;
    }
    
    fec->rs_ctx.parity_shards = fec->parity_shards;
}

v3_fec_type_t v3_fec_get_type(v3_fec_t *fec) {
    return fec ? fec->type : V3_FEC_TYPE_NONE;
}

void v3_fec_get_stats(v3_fec_t *fec, v3_fec_stats_t *stats) {
    if (!fec || !stats) return;
    
    stats->type = fec->type;
    stats->data_shards = fec->data_shards;
    stats->parity_shards = fec->parity_shards;
    stats->encode_count = fec->encode_count;
    stats->decode_count = fec->decode_count;
    stats->recovery_count = fec->recovery_count;
    stats->failure_count = fec->failure_count;
    
    if (fec->decode_count > 0) {
        stats->recovery_rate = (float)fec->recovery_count / fec->decode_count;
    } else {
        stats->recovery_rate = 0;
    }
}

size_t v3_fec_shard_size(void) {
    return FEC_SHARD_SIZE;
}

int v3_fec_max_data_shards(void) {
    return FEC_MAX_DATA_SHARDS;
}

int v3_fec_max_parity_shards(void) {
    return FEC_MAX_PARITY_SHARDS;
}







