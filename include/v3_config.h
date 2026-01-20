
/**
 * @file v3_config.h
 * @brief v3 Core - 配置管理
 * 
 * 提供配置文件加载、保存和运行时配置管理
 * 支持 JSON 格式配置文件
 */

#ifndef V3_CONFIG_H
#define V3_CONFIG_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* 配置键最大长度 */
#define V3_CONFIG_KEY_MAX_LEN       128

/* 配置值最大长度 */
#define V3_CONFIG_VALUE_MAX_LEN     4096

/* 配置路径分隔符 */
#define V3_CONFIG_PATH_SEP          '.'

/* 默认配置文件名 */
#define V3_CONFIG_DEFAULT_FILE      "v3_config.json"

/* =========================================================
 * 配置值类型
 * ========================================================= */

typedef enum v3_config_type_e {
    V3_CONFIG_TYPE_NULL = 0,
    V3_CONFIG_TYPE_BOOL,
    V3_CONFIG_TYPE_INT,
    V3_CONFIG_TYPE_UINT,
    V3_CONFIG_TYPE_FLOAT,
    V3_CONFIG_TYPE_STRING,
    V3_CONFIG_TYPE_ARRAY,
    V3_CONFIG_TYPE_OBJECT,
} v3_config_type_t;

/* =========================================================
 * 配置值结构
 * ========================================================= */

typedef struct v3_config_value_s v3_config_value_t;

struct v3_config_value_s {
    v3_config_type_t    type;
    union {
        bool            bool_val;
        s64             int_val;
        u64             uint_val;
        f64             float_val;
        char           *string_val;
        struct {
            v3_config_value_t **items;
            usize               count;
        } array_val;
        struct {
            char               **keys;
            v3_config_value_t  **values;
            usize                count;
        } object_val;
    } data;
};

/* =========================================================
 * 配置模块 API
 * ========================================================= */

/**
 * @brief 初始化配置模块
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_init(void);

/**
 * @brief 关闭配置模块
 */
V3_API void v3_config_shutdown(void);

/**
 * @brief 从文件加载配置
 * @param filepath 配置文件路径
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_load(const char *filepath);

/**
 * @brief 从字符串加载配置
 * @param json_str JSON 字符串
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_load_string(const char *json_str);

/**
 * @brief 保存配置到文件
 * @param filepath 配置文件路径
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_save(const char *filepath);

/**
 * @brief 导出配置为 JSON 字符串
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 写入的字节数，错误返回 -1
 */
V3_API int v3_config_to_json(char *buf, usize buf_size);

/**
 * @brief 重置为默认配置
 */
V3_API void v3_config_reset_defaults(void);

/* =========================================================
 * 配置读取 API
 * ========================================================= */

/**
 * @brief 检查配置键是否存在
 * @param key 配置键（支持点分隔路径）
 * @return true 存在
 */
V3_API bool v3_config_exists(const char *key);

/**
 * @brief 获取配置值类型
 * @param key 配置键
 * @return 配置类型
 */
V3_API v3_config_type_t v3_config_get_type(const char *key);

/**
 * @brief 获取布尔值
 * @param key 配置键
 * @param default_val 默认值
 * @return 配置值
 */
V3_API bool v3_config_get_bool(const char *key, bool default_val);

/**
 * @brief 获取整数值
 * @param key 配置键
 * @param default_val 默认值
 * @return 配置值
 */
V3_API s64 v3_config_get_int(const char *key, s64 default_val);

/**
 * @brief 获取无符号整数值
 * @param key 配置键
 * @param default_val 默认值
 * @return 配置值
 */
V3_API u64 v3_config_get_uint(const char *key, u64 default_val);

/**
 * @brief 获取浮点值
 * @param key 配置键
 * @param default_val 默认值
 * @return 配置值
 */
V3_API f64 v3_config_get_float(const char *key, f64 default_val);

/**
 * @brief 获取字符串值
 * @param key 配置键
 * @param default_val 默认值
 * @return 配置值（不要释放）
 */
V3_API const char* v3_config_get_string(const char *key, const char *default_val);

/**
 * @brief 获取字符串值（复制）
 * @param key 配置键
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @param default_val 默认值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_get_string_copy(
    const char *key,
    char *buf,
    usize buf_size,
    const char *default_val
);

/**
 * @brief 获取数组大小
 * @param key 配置键
 * @return 数组大小，不存在返回 0
 */
V3_API usize v3_config_get_array_size(const char *key);

/* =========================================================
 * 配置写入 API
 * ========================================================= */

/**
 * @brief 设置布尔值
 * @param key 配置键
 * @param value 配置值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_set_bool(const char *key, bool value);

/**
 * @brief 设置整数值
 * @param key 配置键
 * @param value 配置值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_set_int(const char *key, s64 value);

/**
 * @brief 设置无符号整数值
 * @param key 配置键
 * @param value 配置值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_set_uint(const char *key, u64 value);

/**
 * @brief 设置浮点值
 * @param key 配置键
 * @param value 配置值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_set_float(const char *key, f64 value);

/**
 * @brief 设置字符串值
 * @param key 配置键
 * @param value 配置值
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_set_string(const char *key, const char *value);

/**
 * @brief 删除配置项
 * @param key 配置键
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_remove(const char *key);

/* =========================================================
 * 预定义配置键
 * ========================================================= */

/* 网络配置 */
#define V3_CONFIG_BIND_ADDRESS      "network.bind_address"
#define V3_CONFIG_BIND_PORT         "network.bind_port"
#define V3_CONFIG_MTU               "network.mtu"

/* 加密配置 */
#define V3_CONFIG_MASTER_KEY        "crypto.master_key"
#define V3_CONFIG_KEY_FILE          "crypto.key_file"

/* FEC 配置 */
#define V3_CONFIG_FEC_ENABLED       "fec.enabled"
#define V3_CONFIG_FEC_TYPE          "fec.type"
#define V3_CONFIG_FEC_DATA_SHARDS   "fec.data_shards"
#define V3_CONFIG_FEC_PARITY_SHARDS "fec.parity_shards"

/* Pacing 配置 */
#define V3_CONFIG_PACING_ENABLED    "pacing.enabled"
#define V3_CONFIG_PACING_MODE       "pacing.mode"
#define V3_CONFIG_PACING_RATE       "pacing.rate_bps"
#define V3_CONFIG_PACING_MIN_RATE   "pacing.min_rate_bps"
#define V3_CONFIG_PACING_MAX_RATE   "pacing.max_rate_bps"

/* 流量伪装 */
#define V3_CONFIG_PROFILE           "traffic.profile"

/* 连接配置 */
#define V3_CONFIG_MAX_CONNECTIONS   "connection.max_connections"
#define V3_CONFIG_CONN_TIMEOUT      "connection.timeout_sec"
#define V3_CONFIG_KEEPALIVE         "connection.keepalive_sec"

/* IPC 配置 */
#define V3_CONFIG_IPC_ENABLED       "ipc.enabled"
#define V3_CONFIG_IPC_PIPE_NAME     "ipc.pipe_name"

/* 日志配置 */
#define V3_CONFIG_LOG_LEVEL         "log.level"
#define V3_CONFIG_LOG_FILE          "log.file"
#define V3_CONFIG_LOG_MAX_SIZE      "log.max_size_mb"
#define V3_CONFIG_LOG_MAX_FILES     "log.max_files"

/* 守护配置 */
#define V3_CONFIG_GUARD_ENABLED     "guard.enabled"
#define V3_CONFIG_GUARD_RESTART_DELAY "guard.restart_delay_ms"

/* =========================================================
 * 配置验证
 * ========================================================= */

/**
 * @brief 验证配置有效性
 * @param error_msg 输出错误消息缓冲区（可选）
 * @param error_msg_size 缓冲区大小
 * @return V3_OK 配置有效
 */
V3_API v3_error_t v3_config_validate(char *error_msg, usize error_msg_size);

/**
 * @brief 配置变更回调类型
 */
typedef void (*v3_config_change_fn)(
    const char *key,
    v3_config_type_t old_type,
    v3_config_type_t new_type,
    void *user_data
);

/**
 * @brief 注册配置变更回调
 * @param fn 回调函数
 * @param user_data 用户数据
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_on_change(v3_config_change_fn fn, void *user_data);

/* =========================================================
 * 配置快照
 * ========================================================= */

/**
 * @brief 配置快照句柄
 */
typedef struct v3_config_snapshot_s v3_config_snapshot_t;

/**
 * @brief 创建配置快照
 * @return 快照句柄
 */
V3_API v3_config_snapshot_t* v3_config_snapshot_create(void);

/**
 * @brief 恢复配置快照
 * @param snapshot 快照句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_config_snapshot_restore(v3_config_snapshot_t *snapshot);

/**
 * @brief 释放配置快照
 * @param snapshot 快照句柄
 */
V3_API void v3_config_snapshot_free(v3_config_snapshot_t *snapshot);

#ifdef __cplusplus
}
#endif

#endif /* V3_CONFIG_H */

