
/*
 * v3_config.c - v3 核心配置管理实现
 * 
 * 功能：
 * - 配置文件解析（JSON 格式）
 * - 命令行参数解析
 * - 配置验证与默认值
 * - 配置热更新支持
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_config.h"
#include "v3_log.h"
#include "v3_platform.h"
#include "v3_error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#endif

/* =========================================================
 * 默认配置值
 * ========================================================= */

static const v3_config_t g_default_config = {
    /* 网络配置 */
    .server_host        = "127.0.0.1",
    .server_port        = 51820,
    .local_port         = 0,                /* 自动分配 */
    .mtu                = 1400,
    .recv_buffer_size   = 4 * 1024 * 1024,  /* 4MB */
    .send_buffer_size   = 4 * 1024 * 1024,
    
    /* 协议配置 */
    .protocol_version   = 3,
    .magic_window_sec   = 60,
    .session_timeout_sec = 300,
    .keepalive_interval_sec = 30,
    
    /* FEC 配置 */
    .fec_enabled        = true,
    .fec_type           = V3_FEC_TYPE_AUTO,
    .fec_data_shards    = 10,
    .fec_parity_shards  = 4,
    
    /* Pacing 配置 */
    .pacing_enabled     = true,
    .pacing_initial_bps = 100 * 1000 * 1000ULL,  /* 100 Mbps */
    .pacing_min_bps     = 1 * 1000 * 1000ULL,    /* 1 Mbps */
    .pacing_max_bps     = 1000 * 1000 * 1000ULL, /* 1 Gbps */
    .brutal_mode        = false,
    
    /* 加密配置 */
    .master_key         = {0},
    .master_key_len     = 0,
    
    /* 日志配置 */
    .log_level          = V3_LOG_INFO,
    .log_file           = "",
    .log_max_size_mb    = 100,
    .log_max_files      = 5,
    
    /* 守护配置 */
    .daemon_mode        = false,
    .auto_restart       = true,
    .restart_delay_sec  = 3,
    .max_restart_count  = 10,
    
    /* IPC 配置 */
    .ipc_enabled        = true,
    .ipc_path           = "",
    
    /* 高级配置 */
    .worker_threads     = 0,                /* 自动检测 */
    .connection_pool_size = 1024,
    .stats_interval_sec = 60,
};

/* =========================================================
 * 内部状态
 * ========================================================= */

static v3_config_t g_config;
static bool g_config_initialized = false;
static v3_mutex_t g_config_mutex;
static char g_config_path[V3_MAX_PATH] = {0};
static v3_config_change_cb g_change_callback = NULL;
static void *g_change_callback_arg = NULL;

/* =========================================================
 * JSON 简易解析器（轻量级实现）
 * ========================================================= */

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

typedef struct json_value_s {
    json_type_t type;
    union {
        bool        bool_val;
        double      num_val;
        char       *str_val;
        struct {
            struct json_value_s **items;
            size_t count;
        } array;
        struct {
            char **keys;
            struct json_value_s **values;
            size_t count;
        } object;
    };
} json_value_t;

/* 跳过空白 */
static const char* json_skip_whitespace(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/* 解析字符串 */
static const char* json_parse_string(const char *p, char **out) {
    if (*p != '"') return NULL;
    p++;
    
    const char *start = p;
    size_t len = 0;
    
    while (*p && *p != '"') {
        if (*p == '\\' && *(p+1)) {
            p += 2;
            len++;
        } else {
            p++;
            len++;
        }
    }
    
    if (*p != '"') return NULL;
    
    *out = (char*)malloc(len + 1);
    if (!*out) return NULL;
    
    /* 复制并处理转义 */
    char *dst = *out;
    p = start;
    while (*p && *p != '"') {
        if (*p == '\\' && *(p+1)) {
            p++;
            switch (*p) {
                case 'n': *dst++ = '\n'; break;
                case 'r': *dst++ = '\r'; break;
                case 't': *dst++ = '\t'; break;
                case '\\': *dst++ = '\\'; break;
                case '"': *dst++ = '"'; break;
                default: *dst++ = *p; break;
            }
            p++;
        } else {
            *dst++ = *p++;
        }
    }
    *dst = '\0';
    
    return p + 1;  /* 跳过结束的引号 */
}

/* 解析数字 */
static const char* json_parse_number(const char *p, double *out) {
    char *end;
    *out = strtod(p, &end);
    if (end == p) return NULL;
    return end;
}

/* 前向声明 */
static const char* json_parse_value(const char *p, json_value_t **out);

/* 解析数组 */
static const char* json_parse_array(const char *p, json_value_t *val) {
    if (*p != '[') return NULL;
    p = json_skip_whitespace(p + 1);
    
    val->type = JSON_ARRAY;
    val->array.items = NULL;
    val->array.count = 0;
    
    if (*p == ']') return p + 1;
    
    size_t capacity = 8;
    val->array.items = (json_value_t**)malloc(capacity * sizeof(json_value_t*));
    if (!val->array.items) return NULL;
    
    while (1) {
        json_value_t *item = NULL;
        p = json_parse_value(p, &item);
        if (!p || !item) return NULL;
        
        if (val->array.count >= capacity) {
            capacity *= 2;
            json_value_t **new_items = (json_value_t**)realloc(
                val->array.items, capacity * sizeof(json_value_t*));
            if (!new_items) return NULL;
            val->array.items = new_items;
        }
        val->array.items[val->array.count++] = item;
        
        p = json_skip_whitespace(p);
        if (*p == ']') return p + 1;
        if (*p != ',') return NULL;
        p = json_skip_whitespace(p + 1);
    }
}

/* 解析对象 */
static const char* json_parse_object(const char *p, json_value_t *val) {
    if (*p != '{') return NULL;
    p = json_skip_whitespace(p + 1);
    
    val->type = JSON_OBJECT;
    val->object.keys = NULL;
    val->object.values = NULL;
    val->object.count = 0;
    
    if (*p == '}') return p + 1;
    
    size_t capacity = 16;
    val->object.keys = (char**)malloc(capacity * sizeof(char*));
    val->object.values = (json_value_t**)malloc(capacity * sizeof(json_value_t*));
    if (!val->object.keys || !val->object.values) return NULL;
    
    while (1) {
        /* 解析键 */
        p = json_skip_whitespace(p);
        char *key = NULL;
        p = json_parse_string(p, &key);
        if (!p || !key) return NULL;
        
        /* 冒号 */
        p = json_skip_whitespace(p);
        if (*p != ':') { free(key); return NULL; }
        p = json_skip_whitespace(p + 1);
        
        /* 解析值 */
        json_value_t *value = NULL;
        p = json_parse_value(p, &value);
        if (!p || !value) { free(key); return NULL; }
        
        /* 添加到对象 */
        if (val->object.count >= capacity) {
            capacity *= 2;
            char **new_keys = (char**)realloc(val->object.keys, capacity * sizeof(char*));
            json_value_t **new_values = (json_value_t**)realloc(
                val->object.values, capacity * sizeof(json_value_t*));
            if (!new_keys || !new_values) return NULL;
            val->object.keys = new_keys;
            val->object.values = new_values;
        }
        val->object.keys[val->object.count] = key;
        val->object.values[val->object.count] = value;
        val->object.count++;
        
        p = json_skip_whitespace(p);
        if (*p == '}') return p + 1;
        if (*p != ',') return NULL;
        p = json_skip_whitespace(p + 1);
    }
}

/* 解析任意值 */
static const char* json_parse_value(const char *p, json_value_t **out) {
    p = json_skip_whitespace(p);
    if (!*p) return NULL;
    
    *out = (json_value_t*)calloc(1, sizeof(json_value_t));
    if (!*out) return NULL;
    
    if (*p == '"') {
        (*out)->type = JSON_STRING;
        return json_parse_string(p, &(*out)->str_val);
    }
    
    if (*p == '[') {
        return json_parse_array(p, *out);
    }
    
    if (*p == '{') {
        return json_parse_object(p, *out);
    }
    
    if (strncmp(p, "true", 4) == 0) {
        (*out)->type = JSON_BOOL;
        (*out)->bool_val = true;
        return p + 4;
    }
    
    if (strncmp(p, "false", 5) == 0) {
        (*out)->type = JSON_BOOL;
        (*out)->bool_val = false;
        return p + 5;
    }
    
    if (strncmp(p, "null", 4) == 0) {
        (*out)->type = JSON_NULL;
        return p + 4;
    }
    
    if (*p == '-' || isdigit((unsigned char)*p)) {
        (*out)->type = JSON_NUMBER;
        return json_parse_number(p, &(*out)->num_val);
    }
    
    free(*out);
    *out = NULL;
    return NULL;
}

/* 释放 JSON 值 */
static void json_free(json_value_t *val) {
    if (!val) return;
    
    switch (val->type) {
        case JSON_STRING:
            free(val->str_val);
            break;
        case JSON_ARRAY:
            for (size_t i = 0; i < val->array.count; i++) {
                json_free(val->array.items[i]);
            }
            free(val->array.items);
            break;
        case JSON_OBJECT:
            for (size_t i = 0; i < val->object.count; i++) {
                free(val->object.keys[i]);
                json_free(val->object.values[i]);
            }
            free(val->object.keys);
            free(val->object.values);
            break;
        default:
            break;
    }
    free(val);
}

/* 从对象获取值 */
static json_value_t* json_object_get(json_value_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJECT) return NULL;
    
    for (size_t i = 0; i < obj->object.count; i++) {
        if (strcmp(obj->object.keys[i], key) == 0) {
            return obj->object.values[i];
        }
    }
    return NULL;
}

/* =========================================================
 * 配置文件路径
 * ========================================================= */

static void config_get_default_path(char *path, size_t size) {
#ifdef _WIN32
    char appdata[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata))) {
        snprintf(path, size, "%s\\v3\\config.json", appdata);
    } else {
        snprintf(path, size, "v3_config.json");
    }
#else
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (home) {
        snprintf(path, size, "%s/.config/v3/config.json", home);
    } else {
        snprintf(path, size, "/etc/v3/config.json");
    }
#endif
}

/* 确保目录存在 */
static int config_ensure_dir(const char *path) {
    char dir[V3_MAX_PATH];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    
    /* 找到最后的路径分隔符 */
    char *last_sep = strrchr(dir, V3_PATH_SEP);
    if (!last_sep) return 0;
    *last_sep = '\0';
    
#ifdef _WIN32
    return SHCreateDirectoryExA(NULL, dir, NULL) == ERROR_SUCCESS ? 0 : -1;
#else
    char *p = dir + 1;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            mkdir(dir, 0755);
            *p = '/';
        }
        p++;
    }
    return mkdir(dir, 0755) == 0 || errno == EEXIST ? 0 : -1;
#endif
}

/* =========================================================
 * 配置加载与保存
 * ========================================================= */

static v3_error_t config_load_from_json(json_value_t *root) {
    if (!root || root->type != JSON_OBJECT) {
        return V3_ERR_CONFIG_INVALID;
    }
    
    json_value_t *val;
    
    /* 网络配置 */
    if ((val = json_object_get(root, "server_host")) && val->type == JSON_STRING) {
        strncpy(g_config.server_host, val->str_val, sizeof(g_config.server_host) - 1);
    }
    if ((val = json_object_get(root, "server_port")) && val->type == JSON_NUMBER) {
        g_config.server_port = (uint16_t)val->num_val;
    }
    if ((val = json_object_get(root, "local_port")) && val->type == JSON_NUMBER) {
        g_config.local_port = (uint16_t)val->num_val;
    }
    if ((val = json_object_get(root, "mtu")) && val->type == JSON_NUMBER) {
        g_config.mtu = (uint16_t)val->num_val;
    }
    
    /* FEC 配置 */
    if ((val = json_object_get(root, "fec_enabled")) && val->type == JSON_BOOL) {
        g_config.fec_enabled = val->bool_val;
    }
    if ((val = json_object_get(root, "fec_data_shards")) && val->type == JSON_NUMBER) {
        g_config.fec_data_shards = (uint8_t)val->num_val;
    }
    if ((val = json_object_get(root, "fec_parity_shards")) && val->type == JSON_NUMBER) {
        g_config.fec_parity_shards = (uint8_t)val->num_val;
    }
    
    /* Pacing 配置 */
    if ((val = json_object_get(root, "pacing_enabled")) && val->type == JSON_BOOL) {
        g_config.pacing_enabled = val->bool_val;
    }
    if ((val = json_object_get(root, "pacing_rate_mbps")) && val->type == JSON_NUMBER) {
        g_config.pacing_initial_bps = (uint64_t)(val->num_val * 1000000);
    }
    if ((val = json_object_get(root, "brutal_mode")) && val->type == JSON_BOOL) {
        g_config.brutal_mode = val->bool_val;
    }
    
    /* 日志配置 */
    if ((val = json_object_get(root, "log_level")) && val->type == JSON_STRING) {
        if (strcmp(val->str_val, "debug") == 0) g_config.log_level = V3_LOG_DEBUG;
        else if (strcmp(val->str_val, "info") == 0) g_config.log_level = V3_LOG_INFO;
        else if (strcmp(val->str_val, "warn") == 0) g_config.log_level = V3_LOG_WARN;
        else if (strcmp(val->str_val, "error") == 0) g_config.log_level = V3_LOG_ERROR;
    }
    if ((val = json_object_get(root, "log_file")) && val->type == JSON_STRING) {
        strncpy(g_config.log_file, val->str_val, sizeof(g_config.log_file) - 1);
    }
    
    /* 守护配置 */
    if ((val = json_object_get(root, "daemon_mode")) && val->type == JSON_BOOL) {
        g_config.daemon_mode = val->bool_val;
    }
    if ((val = json_object_get(root, "auto_restart")) && val->type == JSON_BOOL) {
        g_config.auto_restart = val->bool_val;
    }
    
    /* Master Key (hex 编码) */
    if ((val = json_object_get(root, "master_key")) && val->type == JSON_STRING) {
        size_t hex_len = strlen(val->str_val);
        if (hex_len == 64) {  /* 32 bytes = 64 hex chars */
            for (size_t i = 0; i < 32; i++) {
                unsigned int byte;
                if (sscanf(val->str_val + i*2, "%02x", &byte) == 1) {
                    g_config.master_key[i] = (uint8_t)byte;
                }
            }
            g_config.master_key_len = 32;
        }
    }
    
    return V3_OK;
}

v3_error_t v3_config_load(const char *path) {
    v3_mutex_lock(&g_config_mutex);
    
    /* 确定配置路径 */
    if (path && path[0]) {
        strncpy(g_config_path, path, sizeof(g_config_path) - 1);
    } else if (!g_config_path[0]) {
        config_get_default_path(g_config_path, sizeof(g_config_path));
    }
    
    /* 读取文件 */
    FILE *fp = fopen(g_config_path, "r");
    if (!fp) {
        V3_LOG_WARN("Config file not found: %s, using defaults", g_config_path);
        v3_mutex_unlock(&g_config_mutex);
        return V3_ERR_CONFIG_NOT_FOUND;
    }
    
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (size <= 0 || size > 1024 * 1024) {  /* 最大 1MB */
        fclose(fp);
        v3_mutex_unlock(&g_config_mutex);
        return V3_ERR_CONFIG_INVALID;
    }
    
    char *content = (char*)malloc(size + 1);
    if (!content) {
        fclose(fp);
        v3_mutex_unlock(&g_config_mutex);
        return V3_ERR_NO_MEMORY;
    }
    
    size_t read_size = fread(content, 1, size, fp);
    fclose(fp);
    content[read_size] = '\0';
    
    /* 解析 JSON */
    json_value_t *root = NULL;
    if (!json_parse_value(content, &root) || !root) {
        free(content);
        v3_mutex_unlock(&g_config_mutex);
        return V3_ERR_CONFIG_INVALID;
    }
    
    v3_error_t err = config_load_from_json(root);
    
    json_free(root);
    free(content);
    
    if (err == V3_OK) {
        V3_LOG_INFO("Config loaded from: %s", g_config_path);
    }
    
    v3_mutex_unlock(&g_config_mutex);
    return err;
}

v3_error_t v3_config_save(const char *path) {
    v3_mutex_lock(&g_config_mutex);
    
    const char *save_path = (path && path[0]) ? path : g_config_path;
    if (!save_path[0]) {
        config_get_default_path(g_config_path, sizeof(g_config_path));
        save_path = g_config_path;
    }
    
    /* 确保目录存在 */
    config_ensure_dir(save_path);
    
    FILE *fp = fopen(save_path, "w");
    if (!fp) {
        v3_mutex_unlock(&g_config_mutex);
        return V3_ERR_FILE_OPEN;
    }
    
    /* 写入 JSON */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"server_host\": \"%s\",\n", g_config.server_host);
    fprintf(fp, "  \"server_port\": %u,\n", g_config.server_port);
    fprintf(fp, "  \"local_port\": %u,\n", g_config.local_port);
    fprintf(fp, "  \"mtu\": %u,\n", g_config.mtu);
    fprintf(fp, "\n");
    fprintf(fp, "  \"fec_enabled\": %s,\n", g_config.fec_enabled ? "true" : "false");
    fprintf(fp, "  \"fec_data_shards\": %u,\n", g_config.fec_data_shards);
    fprintf(fp, "  \"fec_parity_shards\": %u,\n", g_config.fec_parity_shards);
    fprintf(fp, "\n");
    fprintf(fp, "  \"pacing_enabled\": %s,\n", g_config.pacing_enabled ? "true" : "false");
    fprintf(fp, "  \"pacing_rate_mbps\": %llu,\n", 
            (unsigned long long)(g_config.pacing_initial_bps / 1000000));
    fprintf(fp, "  \"brutal_mode\": %s,\n", g_config.brutal_mode ? "true" : "false");
    fprintf(fp, "\n");
    fprintf(fp, "  \"log_level\": \"%s\",\n",
            g_config.log_level == V3_LOG_DEBUG ? "debug" :
            g_config.log_level == V3_LOG_INFO ? "info" :
            g_config.log_level == V3_LOG_WARN ? "warn" : "error");
    fprintf(fp, "  \"log_file\": \"%s\",\n", g_config.log_file);
    fprintf(fp, "\n");
    fprintf(fp, "  \"daemon_mode\": %s,\n", g_config.daemon_mode ? "true" : "false");
    fprintf(fp, "  \"auto_restart\": %s\n", g_config.auto_restart ? "true" : "false");
    fprintf(fp, "}\n");
    
    fclose(fp);
    
    V3_LOG_INFO("Config saved to: %s", save_path);
    
    v3_mutex_unlock(&g_config_mutex);
    return V3_OK;
}

/* =========================================================
 * 配置初始化与获取
 * ========================================================= */

v3_error_t v3_config_init(void) {
    if (g_config_initialized) {
        return V3_OK;
    }
    
    v3_mutex_init(&g_config_mutex);
    
    /* 复制默认配置 */
    memcpy(&g_config, &g_default_config, sizeof(v3_config_t));
    
    g_config_initialized = true;
    return V3_OK;
}

void v3_config_cleanup(void) {
    if (!g_config_initialized) return;
    
    v3_mutex_destroy(&g_config_mutex);
    g_config_initialized = false;
}

const v3_config_t* v3_config_get(void) {
    return &g_config;
}

v3_error_t v3_config_set(const v3_config_t *config) {
    if (!config) return V3_ERR_INVALID_PARAM;
    
    v3_mutex_lock(&g_config_mutex);
    
    v3_config_t old_config;
    memcpy(&old_config, &g_config, sizeof(v3_config_t));
    memcpy(&g_config, config, sizeof(v3_config_t));
    
    /* 通知变更 */
    if (g_change_callback) {
        g_change_callback(&old_config, &g_config, g_change_callback_arg);
    }
    
    v3_mutex_unlock(&g_config_mutex);
    return V3_OK;
}

/* =========================================================
 * 配置验证
 * ========================================================= */

v3_error_t v3_config_validate(const v3_config_t *config) {
    if (!config) return V3_ERR_INVALID_PARAM;
    
    /* 端口验证 */
    if (config->server_port == 0) {
        V3_LOG_ERROR("Invalid server port: 0");
        return V3_ERR_CONFIG_INVALID;
    }
    
    /* MTU 验证 */
    if (config->mtu < 576 || config->mtu > 65535) {
        V3_LOG_ERROR("Invalid MTU: %u (must be 576-65535)", config->mtu);
        return V3_ERR_CONFIG_INVALID;
    }
    
    /* FEC 验证 */
    if (config->fec_enabled) {
        if (config->fec_data_shards == 0 || config->fec_data_shards > 20) {
            V3_LOG_ERROR("Invalid FEC data shards: %u", config->fec_data_shards);
            return V3_ERR_CONFIG_INVALID;
        }
        if (config->fec_parity_shards == 0 || config->fec_parity_shards > 10) {
            V3_LOG_ERROR("Invalid FEC parity shards: %u", config->fec_parity_shards);
            return V3_ERR_CONFIG_INVALID;
        }
    }
    
    /* Pacing 验证 */
    if (config->pacing_enabled) {
        if (config->pacing_initial_bps < 100000) {
            V3_LOG_ERROR("Pacing rate too low: %llu bps", 
                        (unsigned long long)config->pacing_initial_bps);
            return V3_ERR_CONFIG_INVALID;
        }
    }
    
    return V3_OK;
}

/* =========================================================
 * 配置变更回调
 * ========================================================= */

void v3_config_set_change_callback(v3_config_change_cb cb, void *arg) {
    v3_mutex_lock(&g_config_mutex);
    g_change_callback = cb;
    g_change_callback_arg = arg;
    v3_mutex_unlock(&g_config_mutex);
}

/* =========================================================
 * 配置打印
 * ========================================================= */

void v3_config_print(const v3_config_t *config) {
    if (!config) config = &g_config;
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                    v3 Configuration                           ║\n");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Server:        %s:%u%*s║\n", 
           config->server_host, config->server_port,
           (int)(40 - strlen(config->server_host) - 6), "");
    printf("║  Local Port:    %-45u ║\n", config->local_port);
    printf("║  MTU:           %-45u ║\n", config->mtu);
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  FEC:           %-5s  Shards: %u:%u%*s║\n",
           config->fec_enabled ? "ON" : "OFF",
           config->fec_data_shards, config->fec_parity_shards,
           30, "");
    printf("║  Pacing:        %-5s  Rate: %llu Mbps%*s║\n",
           config->pacing_enabled ? "ON" : "OFF",
           (unsigned long long)(config->pacing_initial_bps / 1000000),
           20, "");
    printf("║  Brutal Mode:   %-45s ║\n", config->brutal_mode ? "ON" : "OFF");
    printf("╠═══════════════════════════════════════════════════════════════╣\n");
    printf("║  Daemon Mode:   %-45s ║\n", config->daemon_mode ? "ON" : "OFF");
    printf("║  Auto Restart:  %-45s ║\n", config->auto_restart ? "ON" : "OFF");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}
