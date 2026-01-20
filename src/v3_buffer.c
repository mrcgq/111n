
/*
 * v3_buffer.c - v3 缓冲区池管理实现
 * 
 * 功能：
 * - 预分配缓冲区池
 * - 快速分配/释放
 * - 引用计数
 * - 内存对齐
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_buffer.h"
#include "v3_log.h"
#include "v3_platform.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

/* =========================================================
 * 配置
 * ========================================================= */

#define BUFFER_ALIGNMENT        64      /* 缓存行对齐 */
#define BUFFER_MAGIC            0x56334246  /* "V3BF" */
#define BUFFER_DEFAULT_SIZE     2048
#define BUFFER_POOL_GROW_SIZE   64

/* =========================================================
 * 缓冲区结构
 * ========================================================= */

typedef struct v3_buffer_s {
    uint32_t            magic;
    volatile int32_t    ref_count;
    size_t              capacity;
    size_t              size;
    size_t              offset;
    struct v3_buffer_s *next;       /* 空闲链表 */
    v3_buffer_pool_t   *pool;       /* 所属池 */
    uint8_t             data[];     /* 柔性数组 */
} v3_buffer_t;

struct v3_buffer_pool_s {
    size_t              buffer_size;
    size_t              total_count;
    size_t              free_count;
    size_t              max_count;
    
    v3_buffer_t        *free_list;
    v3_mutex_t          mutex;
    
    /* 统计 */
    uint64_t            alloc_count;
    uint64_t            free_count_stat;
    uint64_t            miss_count;     /* 池中无可用缓冲区 */
};

/* =========================================================
 * 内存分配
 * ========================================================= */

static void* buffer_alloc_aligned(size_t size, size_t alignment) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    void *ptr = NULL;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
#endif
}

static void buffer_free_aligned(void *ptr) {
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

/* =========================================================
 * 缓冲区池 API
 * ========================================================= */

v3_buffer_pool_t* v3_buffer_pool_create(size_t buffer_size, size_t initial_count, size_t max_count) {
    if (buffer_size == 0) buffer_size = BUFFER_DEFAULT_SIZE;
    if (max_count == 0) max_count = 10000;
    if (initial_count > max_count) initial_count = max_count;
    
    v3_buffer_pool_t *pool = (v3_buffer_pool_t*)calloc(1, sizeof(v3_buffer_pool_t));
    if (!pool) return NULL;
    
    pool->buffer_size = buffer_size;
    pool->max_count = max_count;
    pool->free_list = NULL;
    
    v3_mutex_init(&pool->mutex);
    
    /* 预分配缓冲区 */
    for (size_t i = 0; i < initial_count; i++) {
        size_t alloc_size = sizeof(v3_buffer_t) + buffer_size;
        v3_buffer_t *buf = (v3_buffer_t*)buffer_alloc_aligned(alloc_size, BUFFER_ALIGNMENT);
        
        if (!buf) {
            V3_LOG_WARN("Buffer pool: failed to preallocate buffer %zu", i);
            break;
        }
        
        memset(buf, 0, sizeof(v3_buffer_t));
        buf->magic = BUFFER_MAGIC;
        buf->ref_count = 0;
        buf->capacity = buffer_size;
        buf->size = 0;
        buf->offset = 0;
        buf->pool = pool;
        buf->next = pool->free_list;
        pool->free_list = buf;
        
        pool->total_count++;
        pool->free_count++;
    }
    
    V3_LOG_DEBUG("Buffer pool created: size=%zu, initial=%zu, max=%zu",
                 buffer_size, pool->total_count, max_count);
    
    return pool;
}

void v3_buffer_pool_destroy(v3_buffer_pool_t *pool) {
    if (!pool) return;
    
    v3_mutex_lock(&pool->mutex);
    
    /* 释放所有空闲缓冲区 */
    v3_buffer_t *buf = pool->free_list;
    while (buf) {
        v3_buffer_t *next = buf->next;
        buffer_free_aligned(buf);
        buf = next;
    }
    
    v3_mutex_unlock(&pool->mutex);
    v3_mutex_destroy(&pool->mutex);
    
    V3_LOG_DEBUG("Buffer pool destroyed: total=%zu, allocs=%lu, misses=%lu",
                 pool->total_count, 
                 (unsigned long)pool->alloc_count,
                 (unsigned long)pool->miss_count);
    
    free(pool);
}

v3_buffer_t* v3_buffer_alloc(v3_buffer_pool_t *pool) {
    if (!pool) return NULL;
    
    v3_mutex_lock(&pool->mutex);
    
    v3_buffer_t *buf = pool->free_list;
    
    if (buf) {
        /* 从空闲链表取出 */
        pool->free_list = buf->next;
        pool->free_count--;
    } else if (pool->total_count < pool->max_count) {
        /* 分配新缓冲区 */
        size_t alloc_size = sizeof(v3_buffer_t) + pool->buffer_size;
        buf = (v3_buffer_t*)buffer_alloc_aligned(alloc_size, BUFFER_ALIGNMENT);
        
        if (buf) {
            memset(buf, 0, sizeof(v3_buffer_t));
            buf->magic = BUFFER_MAGIC;
            buf->capacity = pool->buffer_size;
            buf->pool = pool;
            pool->total_count++;
        }
        pool->miss_count++;
    } else {
        pool->miss_count++;
    }
    
    pool->alloc_count++;
    
    v3_mutex_unlock(&pool->mutex);
    
    if (buf) {
        buf->ref_count = 1;
        buf->size = 0;
        buf->offset = 0;
        buf->next = NULL;
    }
    
    return buf;
}

v3_buffer_t* v3_buffer_alloc_size(v3_buffer_pool_t *pool, size_t min_size) {
    /* 如果池的缓冲区足够大，使用池 */
    if (pool && pool->buffer_size >= min_size) {
        return v3_buffer_alloc(pool);
    }
    
    /* 分配独立缓冲区 */
    size_t alloc_size = sizeof(v3_buffer_t) + min_size;
    v3_buffer_t *buf = (v3_buffer_t*)buffer_alloc_aligned(alloc_size, BUFFER_ALIGNMENT);
    
    if (!buf) return NULL;
    
    memset(buf, 0, sizeof(v3_buffer_t));
    buf->magic = BUFFER_MAGIC;
    buf->ref_count = 1;
    buf->capacity = min_size;
    buf->size = 0;
    buf->offset = 0;
    buf->pool = NULL;  /* 不属于任何池 */
    buf->next = NULL;
    
    return buf;
}

void v3_buffer_free(v3_buffer_t *buf) {
    if (!buf) return;
    
    if (buf->magic != BUFFER_MAGIC) {
        V3_LOG_ERROR("Buffer corruption detected!");
        return;
    }
    
    /* 减少引用计数 */
#ifdef _WIN32
    int32_t ref = InterlockedDecrement((volatile LONG*)&buf->ref_count);
#else
    int32_t ref = __sync_sub_and_fetch(&buf->ref_count, 1);
#endif
    
    if (ref > 0) return;  /* 还有其他引用 */
    
    if (ref < 0) {
        V3_LOG_ERROR("Buffer double free detected!");
        return;
    }
    
    v3_buffer_pool_t *pool = buf->pool;
    
    if (pool) {
        /* 归还到池中 */
        v3_mutex_lock(&pool->mutex);
        
        buf->size = 0;
        buf->offset = 0;
        buf->next = pool->free_list;
        pool->free_list = buf;
        pool->free_count++;
        pool->free_count_stat++;
        
        v3_mutex_unlock(&pool->mutex);
    } else {
        /* 独立缓冲区，直接释放 */
        buf->magic = 0;
        buffer_free_aligned(buf);
    }
}

v3_buffer_t* v3_buffer_ref(v3_buffer_t *buf) {
    if (!buf) return NULL;
    
    if (buf->magic != BUFFER_MAGIC) {
        V3_LOG_ERROR("Buffer corruption detected!");
        return NULL;
    }
    
#ifdef _WIN32
    InterlockedIncrement((volatile LONG*)&buf->ref_count);
#else
    __sync_fetch_and_add(&buf->ref_count, 1);
#endif
    
    return buf;
}

/* =========================================================
 * 缓冲区操作
 * ========================================================= */

uint8_t* v3_buffer_data(v3_buffer_t *buf) {
    return buf ? buf->data + buf->offset : NULL;
}

size_t v3_buffer_size(v3_buffer_t *buf) {
    return buf ? buf->size : 0;
}

size_t v3_buffer_capacity(v3_buffer_t *buf) {
    return buf ? buf->capacity - buf->offset : 0;
}

size_t v3_buffer_headroom(v3_buffer_t *buf) {
    return buf ? buf->offset : 0;
}

void v3_buffer_set_size(v3_buffer_t *buf, size_t size) {
    if (!buf) return;
    if (size > buf->capacity - buf->offset) {
        size = buf->capacity - buf->offset;
    }
    buf->size = size;
}

v3_error_t v3_buffer_append(v3_buffer_t *buf, const void *data, size_t len) {
    if (!buf || !data) return V3_ERR_INVALID_PARAM;
    
    size_t available = buf->capacity - buf->offset - buf->size;
    if (len > available) {
        return V3_ERR_BUFFER_FULL;
    }
    
    memcpy(buf->data + buf->offset + buf->size, data, len);
    buf->size += len;
    
    return V3_OK;
}

v3_error_t v3_buffer_prepend(v3_buffer_t *buf, const void *data, size_t len) {
    if (!buf || !data) return V3_ERR_INVALID_PARAM;
    
    if (len > buf->offset) {
        return V3_ERR_BUFFER_FULL;
    }
    
    buf->offset -= len;
    buf->size += len;
    memcpy(buf->data + buf->offset, data, len);
    
    return V3_OK;
}

void v3_buffer_consume(v3_buffer_t *buf, size_t len) {
    if (!buf) return;
    
    if (len >= buf->size) {
        buf->offset = 0;
        buf->size = 0;
    } else {
        buf->offset += len;
        buf->size -= len;
    }
}

void v3_buffer_reserve_head(v3_buffer_t *buf, size_t len) {
    if (!buf) return;
    if (len > buf->capacity) len = buf->capacity;
    buf->offset = len;
}

void v3_buffer_reset(v3_buffer_t *buf) {
    if (!buf) return;
    buf->offset = 0;
    buf->size = 0;
}

v3_buffer_t* v3_buffer_copy(v3_buffer_t *buf) {
    if (!buf) return NULL;
    
    v3_buffer_t *copy = v3_buffer_alloc_size(buf->pool, buf->size);
    if (!copy) return NULL;
    
    memcpy(copy->data, buf->data + buf->offset, buf->size);
    copy->size = buf->size;
    
    return copy;
}

/* =========================================================
 * 池统计
 * ========================================================= */

void v3_buffer_pool_stats(v3_buffer_pool_t *pool, v3_buffer_pool_stats_t *stats) {
    if (!pool || !stats) return;
    
    v3_mutex_lock(&pool->mutex);
    
    stats->buffer_size = pool->buffer_size;
    stats->total_count = pool->total_count;
    stats->free_count = pool->free_count;
    stats->used_count = pool->total_count - pool->free_count;
    stats->max_count = pool->max_count;
    stats->alloc_count = pool->alloc_count;
    stats->free_count_stat = pool->free_count_stat;
    stats->miss_count = pool->miss_count;
    
    v3_mutex_unlock(&pool->mutex);
}
