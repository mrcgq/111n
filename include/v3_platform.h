

/**
 * @file v3_platform.h
 * @brief v3 Core - 平台抽象层
 * 
 * 封装 Windows 和 POSIX 平台差异，提供统一 API
 */

#ifndef V3_PLATFORM_H
#define V3_PLATFORM_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 平台初始化
 * ========================================================= */

/**
 * @brief 初始化平台层
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_platform_init(void);

/**
 * @brief 关闭平台层
 */
V3_API void v3_platform_shutdown(void);

/**
 * @brief 获取平台名称
 * @return 平台名称字符串
 */
V3_API const char* v3_platform_name(void);

/**
 * @brief 获取平台版本
 * @param major 主版本号（可选）
 * @param minor 次版本号（可选）
 * @param build 构建号（可选）
 * @return 版本字符串
 */
V3_API const char* v3_platform_version(int *major, int *minor, int *build);

/* =========================================================
 * 内存管理
 * ========================================================= */

/**
 * @brief 分配内存
 * @param size 大小
 * @return 内存指针，失败返回 NULL
 */
V3_API void* v3_malloc(usize size);

/**
 * @brief 分配并清零内存
 * @param count 元素数量
 * @param size 元素大小
 * @return 内存指针，失败返回 NULL
 */
V3_API void* v3_calloc(usize count, usize size);

/**
 * @brief 重新分配内存
 * @param ptr 原指针
 * @param new_size 新大小
 * @return 新内存指针，失败返回 NULL
 */
V3_API void* v3_realloc(void *ptr, usize new_size);

/**
 * @brief 释放内存
 * @param ptr 内存指针
 */
V3_API void v3_free(void *ptr);

/**
 * @brief 分配对齐内存
 * @param alignment 对齐边界
 * @param size 大小
 * @return 内存指针，失败返回 NULL
 */
V3_API void* v3_aligned_alloc(usize alignment, usize size);

/**
 * @brief 释放对齐内存
 * @param ptr 内存指针
 */
V3_API void v3_aligned_free(void *ptr);

/**
 * @brief 获取系统总内存
 * @return 字节数
 */
V3_API u64 v3_total_memory(void);

/**
 * @brief 获取可用内存
 * @return 字节数
 */
V3_API u64 v3_available_memory(void);

/* =========================================================
 * 互斥锁
 * ========================================================= */

typedef struct v3_mutex_s v3_mutex_t;

/**
 * @brief 创建互斥锁
 * @return 互斥锁句柄，失败返回 NULL
 */
V3_API v3_mutex_t* v3_mutex_create(void);

/**
 * @brief 销毁互斥锁
 * @param mutex 互斥锁句柄
 */
V3_API void v3_mutex_destroy(v3_mutex_t *mutex);

/**
 * @brief 加锁
 * @param mutex 互斥锁句柄
 */
V3_API void v3_mutex_lock(v3_mutex_t *mutex);

/**
 * @brief 尝试加锁
 * @param mutex 互斥锁句柄
 * @return true 成功，false 失败
 */
V3_API bool v3_mutex_trylock(v3_mutex_t *mutex);

/**
 * @brief 解锁
 * @param mutex 互斥锁句柄
 */
V3_API void v3_mutex_unlock(v3_mutex_t *mutex);

/* =========================================================
 * 读写锁
 * ========================================================= */

typedef struct v3_rwlock_s v3_rwlock_t;

/**
 * @brief 创建读写锁
 * @return 读写锁句柄
 */
V3_API v3_rwlock_t* v3_rwlock_create(void);

/**
 * @brief 销毁读写锁
 * @param rwlock 读写锁句柄
 */
V3_API void v3_rwlock_destroy(v3_rwlock_t *rwlock);

/**
 * @brief 读锁定
 * @param rwlock 读写锁句柄
 */
V3_API void v3_rwlock_rdlock(v3_rwlock_t *rwlock);

/**
 * @brief 写锁定
 * @param rwlock 读写锁句柄
 */
V3_API void v3_rwlock_wrlock(v3_rwlock_t *rwlock);

/**
 * @brief 解锁
 * @param rwlock 读写锁句柄
 */
V3_API void v3_rwlock_unlock(v3_rwlock_t *rwlock);

/* =========================================================
 * 条件变量
 * ========================================================= */

typedef struct v3_cond_s v3_cond_t;

/**
 * @brief 创建条件变量
 * @return 条件变量句柄
 */
V3_API v3_cond_t* v3_cond_create(void);

/**
 * @brief 销毁条件变量
 * @param cond 条件变量句柄
 */
V3_API void v3_cond_destroy(v3_cond_t *cond);

/**
 * @brief 等待条件变量
 * @param cond 条件变量句柄
 * @param mutex 关联的互斥锁
 */
V3_API void v3_cond_wait(v3_cond_t *cond, v3_mutex_t *mutex);

/**
 * @brief 带超时等待
 * @param cond 条件变量句柄
 * @param mutex 关联的互斥锁
 * @param timeout_ms 超时毫秒数
 * @return true 成功，false 超时
 */
V3_API bool v3_cond_timedwait(v3_cond_t *cond, v3_mutex_t *mutex, u32 timeout_ms);

/**
 * @brief 唤醒一个等待者
 * @param cond 条件变量句柄
 */
V3_API void v3_cond_signal(v3_cond_t *cond);

/**
 * @brief 唤醒所有等待者
 * @param cond 条件变量句柄
 */
V3_API void v3_cond_broadcast(v3_cond_t *cond);

/* =========================================================
 * 事件
 * ========================================================= */

typedef struct v3_event_s v3_event_t;

/**
 * @brief 创建事件
 * @param manual_reset 是否手动重置
 * @param initial_state 初始状态（是否已触发）
 * @return 事件句柄
 */
V3_API v3_event_t* v3_event_create(bool manual_reset, bool initial_state);

/**
 * @brief 销毁事件
 * @param event 事件句柄
 */
V3_API void v3_event_destroy(v3_event_t *event);

/**
 * @brief 等待事件
 * @param event 事件句柄
 * @param timeout_ms 超时毫秒数（0=无限）
 * @return true 成功，false 超时
 */
V3_API bool v3_event_wait(v3_event_t *event, u32 timeout_ms);

/**
 * @brief 设置事件（触发）
 * @param event 事件句柄
 */
V3_API void v3_event_set(v3_event_t *event);

/**
 * @brief 重置事件
 * @param event 事件句柄
 */
V3_API void v3_event_reset(v3_event_t *event);

/* =========================================================
 * 原子操作
 * ========================================================= */

/**
 * @brief 原子加载 32 位
 * @param ptr 指针
 * @return 值
 */
V3_API s32 v3_atomic_load32(volatile s32 *ptr);

/**
 * @brief 原子存储 32 位
 * @param ptr 指针
 * @param value 值
 */
V3_API void v3_atomic_store32(volatile s32 *ptr, s32 value);

/**
 * @brief 原子加法 32 位
 * @param ptr 指针
 * @param value 增量
 * @return 旧值
 */
V3_API s32 v3_atomic_add32(volatile s32 *ptr, s32 value);

/**
 * @brief 原子比较交换 32 位
 * @param ptr 指针
 * @param expected 期望值
 * @param desired 期望写入值
 * @return true 成功，false 失败
 */
V3_API bool v3_atomic_cas32(volatile s32 *ptr, s32 expected, s32 desired);

/**
 * @brief 原子加载 64 位
 * @param ptr 指针
 * @return 值
 */
V3_API s64 v3_atomic_load64(volatile s64 *ptr);

/**
 * @brief 原子存储 64 位
 * @param ptr 指针
 * @param value 值
 */
V3_API void v3_atomic_store64(volatile s64 *ptr, s64 value);

/**
 * @brief 原子加法 64 位
 * @param ptr 指针
 * @param value 增量
 * @return 旧值
 */
V3_API s64 v3_atomic_add64(volatile s64 *ptr, s64 value);

/**
 * @brief 原子比较交换 64 位
 * @param ptr 指针
 * @param expected 期望值
 * @param desired 期望写入值
 * @return true 成功，false 失败
 */
V3_API bool v3_atomic_cas64(volatile s64 *ptr, s64 expected, s64 desired);

/* =========================================================
 * 线程本地存储
 * ========================================================= */

typedef u32 v3_tls_key_t;

#define V3_TLS_INVALID_KEY  ((v3_tls_key_t)-1)

/**
 * @brief 创建 TLS 键
 * @param key_out 输出键
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_tls_create(v3_tls_key_t *key_out);

/**
 * @brief 删除 TLS 键
 * @param key 键
 */
V3_API void v3_tls_delete(v3_tls_key_t key);

/**
 * @brief 获取 TLS 值
 * @param key 键
 * @return 值
 */
V3_API void* v3_tls_get(v3_tls_key_t key);

/**
 * @brief 设置 TLS 值
 * @param key 键
 * @param value 值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_tls_set(v3_tls_key_t key, void *value);

/* =========================================================
 * 进程相关
 * ========================================================= */

/**
 * @brief 获取当前进程 ID
 * @return 进程 ID
 */
V3_API v3_pid_t v3_getpid(void);

/**
 * @brief 获取父进程 ID
 * @return 父进程 ID
 */
V3_API v3_pid_t v3_getppid(void);

/**
 * @brief 获取当前线程 ID
 * @return 线程 ID
 */
V3_API v3_tid_t v3_gettid(void);

/**
 * @brief 获取 CPU 核心数
 * @return 核心数
 */
V3_API u32 v3_cpu_count(void);

/**
 * @brief 睡眠
 * @param ms 毫秒数
 */
V3_API void v3_sleep_ms(u32 ms);

/**
 * @brief 微秒睡眠
 * @param us 微秒数
 */
V3_API void v3_sleep_us(u32 us);

/**
 * @brief 让出 CPU
 */
V3_API void v3_yield(void);

/* =========================================================
 * 文件系统
 * ========================================================= */

/**
 * @brief 检查文件是否存在
 * @param path 路径
 * @return true 存在
 */
V3_API bool v3_file_exists(const char *path);

/**
 * @brief 检查目录是否存在
 * @param path 路径
 * @return true 存在
 */
V3_API bool v3_dir_exists(const char *path);

/**
 * @brief 创建目录
 * @param path 路径
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_mkdir(const char *path);

/**
 * @brief 递归创建目录
 * @param path 路径
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_mkdir_recursive(const char *path);

/**
 * @brief 删除文件
 * @param path 路径
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_remove(const char *path);

/**
 * @brief 获取可执行文件路径
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_get_exe_path(char *buf, usize buf_size);

/**
 * @brief 获取当前工作目录
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_getcwd(char *buf, usize buf_size);

/**
 * @brief 设置当前工作目录
 * @param path 路径
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_chdir(const char *path);

/* =========================================================
 * 环境变量
 * ========================================================= */

/**
 * @brief 获取环境变量
 * @param name 变量名
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_getenv(const char *name, char *buf, usize buf_size);

/**
 * @brief 设置环境变量
 * @param name 变量名
 * @param value 值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_setenv(const char *name, const char *value);

/* =========================================================
 * 随机数
 * ========================================================= */

/**
 * @brief 生成加密安全随机字节
 * @param buf 输出缓冲区
 * @param len 长度
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_random(u8 *buf, usize len);

/**
 * @brief 生成随机 32 位整数
 * @return 随机值
 */
V3_API u32 v3_random32(void);

/**
 * @brief 生成随机 64 位整数
 * @return 随机值
 */
V3_API u64 v3_random64(void);

/* =========================================================
 * 高精度计时器
 * ========================================================= */

/**
 * @brief 获取高精度计数器频率
 * @return 每秒计数
 */
V3_API u64 v3_perf_freq(void);

/**
 * @brief 获取高精度计数器当前值
 * @return 计数值
 */
V3_API u64 v3_perf_counter(void);

/* =========================================================
 * 动态库加载
 * ========================================================= */

typedef void* v3_lib_t;

/**
 * @brief 加载动态库
 * @param path 库路径
 * @return 库句柄，失败返回 NULL
 */
V3_API v3_lib_t v3_lib_load(const char *path);

/**
 * @brief 卸载动态库
 * @param lib 库句柄
 */
V3_API void v3_lib_unload(v3_lib_t lib);

/**
 * @brief 获取符号地址
 * @param lib 库句柄
 * @param name 符号名
 * @return 符号地址，失败返回 NULL
 */
V3_API void* v3_lib_symbol(v3_lib_t lib, const char *name);

/* =========================================================
 * CPU 特性检测
 * ========================================================= */

/**
 * @brief CPU 特性标志
 */
typedef enum v3_cpu_feature_e {
    V3_CPU_FEATURE_SSE2     = (1 << 0),
    V3_CPU_FEATURE_SSE3     = (1 << 1),
    V3_CPU_FEATURE_SSSE3    = (1 << 2),
    V3_CPU_FEATURE_SSE41    = (1 << 3),
    V3_CPU_FEATURE_SSE42    = (1 << 4),
    V3_CPU_FEATURE_AVX      = (1 << 5),
    V3_CPU_FEATURE_AVX2     = (1 << 6),
    V3_CPU_FEATURE_AVX512F  = (1 << 7),
    V3_CPU_FEATURE_AVX512BW = (1 << 8),
    V3_CPU_FEATURE_AES      = (1 << 9),
    V3_CPU_FEATURE_PCLMUL   = (1 << 10),
    V3_CPU_FEATURE_NEON     = (1 << 11),
} v3_cpu_feature_t;

/**
 * @brief 检测 CPU 特性
 * @return 特性位掩码
 */
V3_API u32 v3_cpu_features(void);

/**
 * @brief 检查是否支持指定特性
 * @param feature 特性
 * @return true 支持
 */
V3_API bool v3_cpu_has_feature(v3_cpu_feature_t feature);

/**
 * @brief 获取 CPU 名称
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 */
V3_API void v3_cpu_name(char *buf, usize buf_size);

#ifdef __cplusplus
}
#endif

#endif /* V3_PLATFORM_H */
