
/**
 * @file v3_buffer.h
 * @brief v3 Core - 缓冲区管理
 * 
 * 提供高效的缓冲区池和引用计数缓冲区
 */

#ifndef V3_BUFFER_H
#define V3_BUFFER_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* 默认缓冲区大小 */
#define V3_BUFFER_DEFAULT_SIZE      2048
#define V3_BUFFER_SMALL_SIZE        256
#define V3_BUFFER_MEDIUM_SIZE       1500
#define V3_BUFFER_LARGE_SIZE        8192

/* 池配置 */
#define V3_BUFFER_POOL_SMALL_COUNT  1024
#define V3_BUFFER_POOL_MEDIUM_COUNT 512
#define V3_BUFFER_POOL_LARGE_COUNT  128

/* =========================================================
 * 缓冲区结构
 * ========================================================= */

/**
 * @brief 缓冲区
 */
typedef struct v3_buffer_s {
    u8             *data;           /* 数据指针 */
    usize           size;           /* 分配大小 */
    usize           len;            /* 有效数据长度 */
    usize           offset;         /* 当前读取偏移 */
    volatile s32    ref_count;      /* 引用计数 */
    struct v3_buffer_pool_s *pool;  /* 所属池（可选）*/
    void           *user_data;      /* 用户数据 */
} v3_buffer_t;

/**
 * @brief 缓冲区池
 */
typedef struct v3_buffer_pool_s v3_buffer_pool_t;

/* =========================================================
 * 缓冲区 API
 * ========================================================= */

/**
 * @brief 创建缓冲区
 * @param size 大小
 * @return 缓冲区指针，失败返回 NULL
 */
V3_API v3_buffer_t* v3_buffer_create(usize size);

/**
 * @brief 创建并初始化缓冲区
 * @param data 初始数据
 * @param len 数据长度
 * @return 缓冲区指针
 */
V3_API v3_buffer_t* v3_buffer_create_from(const u8 *data, usize len);

/**
 * @brief 增加引用计数
 * @param buf 缓冲区
 * @return 缓冲区（方便链式调用）
 */
V3_API v3_buffer_t* v3_buffer_ref(v3_buffer_t *buf);

/**
 * @brief 减少引用计数（可能释放）
 * @param buf 缓冲区
 */
V3_API void v3_buffer_unref(v3_buffer_t *buf);

/**
 * @brief 获取引用计数
 * @param buf 缓冲区
 * @return 引用计数
 */
V3_API s32 v3_buffer_ref_count(v3_buffer_t *buf);

/**
 * @brief 重置缓冲区
 * @param buf 缓冲区
 */
V3_API void v3_buffer_reset(v3_buffer_t *buf);

/**
 * @brief 清空缓冲区数据
 * @param buf 缓冲区
 */
V3_API void v3_buffer_clear(v3_buffer_t *buf);

/**
 * @brief 确保容量
 * @param buf 缓冲区
 * @param capacity 需要的容量
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_buffer_reserve(v3_buffer_t *buf, usize capacity);

/**
 * @brief 调整大小
 * @param buf 缓冲区
 * @param new_size 新大小
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_buffer_resize(v3_buffer_t *buf, usize new_size);

/**
 * @brief 追加数据
 * @param buf 缓冲区
 * @param data 数据
 * @param len 长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_buffer_append(v3_buffer_t *buf, const u8 *data, usize len);

/**
 * @brief 在开头插入数据
 * @param buf 缓冲区
 * @param data 数据
 * @param len 长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_buffer_prepend(v3_buffer_t *buf, const u8 *data, usize len);

/**
 * @brief 读取数据（移动偏移）
 * @param buf 缓冲区
 * @param out 输出缓冲区
 * @param len 读取长度
 * @return 实际读取长度
 */
V3_API usize v3_buffer_read(v3_buffer_t *buf, u8 *out, usize len);

/**
 * @brief 查看数据（不移动偏移）
 * @param buf 缓冲区
 * @param out 输出缓冲区
 * @param offset 偏移
 * @param len 长度
 * @return 实际读取长度
 */
V3_API usize v3_buffer_peek(v3_buffer_t *buf, u8 *out, usize offset, usize len);

/**
 * @brief 跳过数据
 * @param buf 缓冲区
 * @param len 跳过长度
 * @return 实际跳过长度
 */
V3_API usize v3_buffer_skip(v3_buffer_t *buf, usize len);

/**
 * @brief 获取剩余可读长度
 * @param buf 缓冲区
 * @return 剩余长度
 */
V3_API usize v3_buffer_remaining(v3_buffer_t *buf);

/**
 * @brief 获取可写指针
 * @param buf 缓冲区
 * @return 可写位置指针
 */
V3_API u8* v3_buffer_write_ptr(v3_buffer_t *buf);

/**
 * @brief 获取可读指针
 * @param buf 缓冲区
 * @return 可读位置指针
 */
V3_API const u8* v3_buffer_read_ptr(v3_buffer_t *buf);

/**
 * @brief 确认写入
 * @param buf 缓冲区
 * @param len 写入长度
 */
V3_API void v3_buffer_commit_write(v3_buffer_t *buf, usize len);

/* =========================================================
 * 缓冲区池 API
 * ========================================================= */

/**
 * @brief 缓冲区池配置
 */
typedef struct v3_buffer_pool_config_s {
    usize   buffer_size;        /* 缓冲区大小 */
    u32     initial_count;      /* 初始数量 */
    u32     max_count;          /* 最大数量 */
    bool    thread_safe;        /* 是否线程安全 */
} v3_buffer_pool_config_t;

/**
 * @brief 创建缓冲区池
 * @param config 配置
 * @param pool_out 输出池句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_buffer_pool_create(
    const v3_buffer_pool_config_t *config,
    v3_buffer_pool_t **pool_out
);

/**
 * @brief 销毁缓冲区池
 * @param pool 池句柄
 */
V3_API void v3_buffer_pool_destroy(v3_buffer_pool_t *pool);

/**
 * @brief 从池获取缓冲区
 * @param pool 池句柄
 * @return 缓冲区指针
 */
V3_API v3_buffer_t* v3_buffer_pool_get(v3_buffer_pool_t *pool);

/**
 * @brief 归还缓冲区到池
 * @param buf 缓冲区
 */
V3_API void v3_buffer_pool_put(v3_buffer_t *buf);

/**
 * @brief 获取池统计
 * @param pool 池句柄
 * @param total 输出总数
 * @param available 输出可用数
 * @param in_use 输出使用中数量
 */
V3_API void v3_buffer_pool_stats(
    v3_buffer_pool_t *pool,
    u32 *total,
    u32 *available,
    u32 *in_use
);

/* =========================================================
 * 全局缓冲区池
 * ========================================================= */

/**
 * @brief 初始化全局缓冲区池
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_buffer_global_init(void);

/**
 * @brief 关闭全局缓冲区池
 */
V3_API void v3_buffer_global_shutdown(void);

/**
 * @brief 从全局池获取小缓冲区
 * @return 缓冲区
 */
V3_API v3_buffer_t* v3_buffer_alloc_small(void);

/**
 * @brief 从全局池获取中等缓冲区
 * @return 缓冲区
 */
V3_API v3_buffer_t* v3_buffer_alloc_medium(void);

/**
 * @brief 从全局池获取大缓冲区
 * @return 缓冲区
 */
V3_API v3_buffer_t* v3_buffer_alloc_large(void);

/**
 * @brief 根据大小自动选择池
 * @param min_size 最小需要大小
 * @return 缓冲区
 */
V3_API v3_buffer_t* v3_buffer_alloc(usize min_size);

#ifdef __cplusplus
}
#endif

#endif /* V3_BUFFER_H */

