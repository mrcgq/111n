
/**
 * @file v3_fec.h
 * @brief v3 Core - FEC 前向纠错
 * 
 * 实现 XOR 和 Reed-Solomon 纠错编码
 * 与服务端 v3_fec_simd.h 接口兼容
 * 
 * 注意：Windows 版本使用纯 C 实现，不依赖 SIMD
 */

#ifndef V3_FEC_H
#define V3_FEC_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * FEC 常量（与服务端一致）
 * ========================================================= */

#define V3_FEC_MAX_DATA_SHARDS      20
#define V3_FEC_MAX_PARITY_SHARDS    10
#define V3_FEC_MAX_TOTAL_SHARDS     30
#define V3_FEC_SHARD_SIZE           1400
#define V3_FEC_DECODE_CACHE_SIZE    128
#define V3_FEC_XOR_GROUP_SIZE       4

/* =========================================================
 * FEC 类型
 * ========================================================= */

/**
 * @brief FEC 类型（与服务端 fec_type_t 一致）
 */
typedef enum v3_fec_type_e {
    V3_FEC_TYPE_NONE = 0,           /* 不使用 FEC */
    V3_FEC_TYPE_XOR,                /* 简单 XOR（低 CPU，低恢复能力）*/
    V3_FEC_TYPE_RS,                 /* Reed-Solomon（高恢复能力）*/
    V3_FEC_TYPE_AUTO,               /* 自动选择 */
} v3_fec_type_t;

/* =========================================================
 * FEC 分片结构
 * ========================================================= */

/**
 * @brief FEC 分片头
 */
V3_PACK_BEGIN
typedef struct v3_fec_shard_header_s {
    u32     group_id;               /* 组 ID */
    u8      shard_index;            /* 分片索引 */
    u8      data_shards;            /* 数据分片数 */
    u8      parity_shards;          /* 校验分片数（RS）或 1（XOR）*/
    u8      shard_size_div16;       /* 分片大小 / 16 */
} V3_PACK_STRUCT v3_fec_shard_header_t;
V3_PACK_END

#define V3_FEC_SHARD_HEADER_SIZE    sizeof(v3_fec_shard_header_t)

/**
 * @brief FEC 分片
 */
typedef struct v3_fec_shard_s {
    v3_fec_shard_header_t   header;
    u8                      data[V3_FEC_SHARD_SIZE];
    usize                   data_len;
    bool                    present;        /* 是否已收到 */
} v3_fec_shard_t;

/* =========================================================
 * FEC 编码器
 * ========================================================= */

/**
 * @brief FEC 编码器配置
 */
typedef struct v3_fec_encoder_config_s {
    v3_fec_type_t   type;               /* FEC 类型 */
    u8              data_shards;        /* 数据分片数 */
    u8              parity_shards;      /* 校验分片数 */
} v3_fec_encoder_config_t;

/**
 * @brief FEC 编码器句柄
 */
typedef struct v3_fec_encoder_s v3_fec_encoder_t;

/**
 * @brief 创建 FEC 编码器
 * @param config 配置
 * @param encoder_out 输出编码器句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_fec_encoder_create(
    const v3_fec_encoder_config_t *config,
    v3_fec_encoder_t **encoder_out
);

/**
 * @brief 销毁 FEC 编码器
 * @param encoder 编码器句柄
 */
V3_API void v3_fec_encoder_destroy(v3_fec_encoder_t *encoder);

/**
 * @brief 编码数据
 * @param encoder 编码器句柄
 * @param data 输入数据
 * @param len 数据长度
 * @param shards 输出分片数组
 * @param shard_lens 输出各分片长度
 * @param group_id 输出组 ID
 * @return 分片总数（数据+校验），失败返回负值
 */
V3_API int v3_fec_encode(
    v3_fec_encoder_t *encoder,
    const u8 *data,
    usize len,
    u8 shards[][V3_FEC_SHARD_SIZE],
    usize shard_lens[],
    u32 *group_id
);

/**
 * @brief 获取编码器类型
 * @param encoder 编码器句柄
 * @return FEC 类型
 */
V3_API v3_fec_type_t v3_fec_encoder_get_type(v3_fec_encoder_t *encoder);

/**
 * @brief 设置丢包率（自动调整冗余）
 * @param encoder 编码器句柄
 * @param loss_rate 丢包率 (0.0 - 1.0)
 */
V3_API void v3_fec_encoder_set_loss_rate(v3_fec_encoder_t *encoder, f32 loss_rate);

/* =========================================================
 * FEC 解码器
 * ========================================================= */

/**
 * @brief FEC 解码器句柄
 */
typedef struct v3_fec_decoder_s v3_fec_decoder_t;

/**
 * @brief 创建 FEC 解码器
 * @param type FEC 类型
 * @param decoder_out 输出解码器句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_fec_decoder_create(
    v3_fec_type_t type,
    v3_fec_decoder_t **decoder_out
);

/**
 * @brief 销毁 FEC 解码器
 * @param decoder 解码器句柄
 */
V3_API void v3_fec_decoder_destroy(v3_fec_decoder_t *decoder);

/**
 * @brief 解码分片
 * @param decoder 解码器句柄
 * @param group_id 组 ID
 * @param shard_index 分片索引
 * @param shard_data 分片数据
 * @param shard_len 分片长度
 * @param out_data 输出恢复的数据
 * @param out_len 输出数据长度
 * @return 0=等待更多分片, 1=恢复成功, -1=失败
 */
V3_API int v3_fec_decode(
    v3_fec_decoder_t *decoder,
    u32 group_id,
    u8 shard_index,
    const u8 *shard_data,
    usize shard_len,
    u8 *out_data,
    usize *out_len
);

/**
 * @brief 清除解码缓存
 * @param decoder 解码器句柄
 */
V3_API void v3_fec_decoder_clear_cache(v3_fec_decoder_t *decoder);

/**
 * @brief 获取解码器统计
 * @param decoder 解码器句柄
 * @param groups_total 输出组总数
 * @param recoveries 输出恢复成功数
 * @param failures 输出恢复失败数
 */
V3_API void v3_fec_decoder_get_stats(
    v3_fec_decoder_t *decoder,
    u64 *groups_total,
    u64 *recoveries,
    u64 *failures
);

/* =========================================================
 * FEC 工具函数
 * ========================================================= */

/**
 * @brief 获取 FEC 类型名称
 * @param type FEC 类型
 * @return 类型名称字符串
 */
V3_API const char* v3_fec_type_str(v3_fec_type_t type);

/**
 * @brief 计算推荐的校验分片数
 * @param data_shards 数据分片数
 * @param loss_rate 预期丢包率
 * @return 推荐的校验分片数
 */
V3_API u8 v3_fec_recommended_parity(u8 data_shards, f32 loss_rate);

/**
 * @brief 检查 FEC 参数有效性
 * @param type FEC 类型
 * @param data_shards 数据分片数
 * @param parity_shards 校验分片数
 * @return V3_OK 有效
 */
V3_API v3_error_t v3_fec_validate_params(
    v3_fec_type_t type,
    u8 data_shards,
    u8 parity_shards
);

/* =========================================================
 * GF(2^8) 运算（内部使用，但暴露供测试）
 * ========================================================= */

/**
 * @brief 初始化 GF 表
 */
V3_API void v3_fec_gf_init(void);

/**
 * @brief GF(2^8) 乘法
 * @param a 操作数 a
 * @param b 操作数 b
 * @return a * b in GF(2^8)
 */
V3_API u8 v3_fec_gf_mul(u8 a, u8 b);

/**
 * @brief GF(2^8) 除法
 * @param a 被除数
 * @param b 除数
 * @return a / b in GF(2^8)
 */
V3_API u8 v3_fec_gf_div(u8 a, u8 b);

/**
 * @brief GF(2^8) 求逆
 * @param a 操作数
 * @return 1/a in GF(2^8)
 */
V3_API u8 v3_fec_gf_inv(u8 a);

#ifdef __cplusplus
}
#endif

#endif /* V3_FEC_H */
