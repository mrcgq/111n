
/**
 * @file v3_core_impl.c
 * @brief v3 Core - 核心逻辑实现
 * 
 * 实现主事件循环、数据包处理、模块协调
 */

#include "v3_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================
 * 核心上下文结构
 * ========================================================= */

struct v3_core_s {
    /* 状态 */
    volatile v3_state_t     state;
    volatile bool           should_stop;
    
    /* 配置 */
    v3_init_options_t       options;
    u8                      master_key[V3_CRYPTO_KEY_SIZE];
    
    /* 网络 */
    v3_socket_t             udp_socket;
    v3_address_t            bind_addr;
    
#ifdef V3_PLATFORM_WINDOWS
    v3_iocp_t              *iocp;
#endif
    
    /* 协议 */
    v3_protocol_ctx_t      *protocol_ctx;
    
    /* 连接管理 */
    v3_conn_manager_t      *conn_manager;
    
    /* FEC */
    v3_fec_encoder_t       *fec_encoder;
    v3_fec_decoder_t       *fec_decoder;
    
    /* Pacing */
    v3_pacer_t             *pacer;
    
    /* IPC */
    v3_ipc_server_t        *ipc_server;
    
    /* 缓冲区 */
    v3_buffer_pool_t       *buffer_pool;
    
    /* 统计 */
    u64                     start_time;
    u64                     last_stats_time;
    
    /* 接收缓冲区 */
    u8                      recv_buf[V3_BUF_SIZE];
};

/* 全局核心上下文 */
static v3_core_t *g_core = NULL;

/* =========================================================
 * 默认选项
 * ========================================================= */

void v3_core_default_options(v3_init_options_t *opts) {
    if (!opts) return;
    
    memset(opts, 0, sizeof(*opts));
    
    opts->log_level = V3_LOG_INFO;
    opts->bind_address = "0.0.0.0";
    opts->bind_port = V3_DEFAULT_PORT;
    
    opts->fec_enabled = false;
    opts->fec_type = V3_FEC_TYPE_AUTO;
    opts->fec_data_shards = 5;
    opts->fec_parity_shards = 2;
    
    opts->pacing_enabled = false;
    opts->pacing_mode = V3_PACING_MODE_BRUTAL;
    opts->pacing_rate_bps = 100 * 1000 * 1000; /* 100 Mbps */
    
    opts->traffic_profile = V3_PROFILE_NONE;
    opts->mtu = V3_MTU_DEFAULT;
    
    opts->ipc_enabled = true;
    opts->ipc_pipe_name = NULL;
    
    opts->guard_enabled = false;
    opts->guard_restart_delay_ms = 1000;
    
    opts->max_connections = V3_MAX_CONNECTIONS;
    opts->connection_timeout_sec = V3_SESSION_TIMEOUT_SEC;
    
    opts->flags = V3_INIT_FLAG_NONE;
}

/* =========================================================
 * 模块初始化
 * ========================================================= */

static v3_error_t init_platform(void) {
    v3_error_t err;
    
    err = v3_platform_init();
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to initialize platform: %s", v3_error_str(err));
        return err;
    }
    
    return V3_OK;
}

static v3_error_t init_logging(const v3_init_options_t *opts) {
    v3_log_config_t log_cfg;
    v3_log_default_config(&log_cfg);
    
    log_cfg.level = opts->log_level;
    log_cfg.file_path = opts->log_file;
    log_cfg.callback = opts->log_callback;
    log_cfg.callback_data = opts->callback_data;
    
    if (opts->flags & V3_INIT_FLAG_VERBOSE) {
        log_cfg.include_source = true;
        log_cfg.include_thread = true;
    }
    
    return v3_log_init(&log_cfg);
}

static v3_error_t init_crypto(v3_core_t *core, const v3_init_options_t *opts) {
    v3_error_t err;
    
    err = v3_crypto_init();
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to initialize crypto: %s", v3_error_str(err));
        return err;
    }
    
    /* 复制主密钥 */
    if (opts->master_key && opts->master_key_len == V3_CRYPTO_KEY_SIZE) {
        memcpy(core->master_key, opts->master_key, V3_CRYPTO_KEY_SIZE);
    } else {
        /* 生成随机密钥 */
        err = v3_crypto_random(core->master_key, V3_CRYPTO_KEY_SIZE);
        if (V3_IS_ERROR(err)) {
            V3_LOG_ERROR("Failed to generate master key");
            return err;
        }
        V3_LOG_WARN("Generated random master key");
    }
    
    V3_LOG_INFO("Crypto module initialized");
    return V3_OK;
}

static v3_error_t init_network(v3_core_t *core, const v3_init_options_t *opts) {
    v3_error_t err;
    
    err = v3_net_init();
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to initialize network: %s", v3_error_str(err));
        return err;
    }
    
    /* 解析绑定地址 */
    err = v3_address_init_ipv4(&core->bind_addr, opts->bind_address, opts->bind_port);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Invalid bind address: %s", opts->bind_address);
        return err;
    }
    
    /* 创建 UDP Socket */
    u32 sock_flags = V3_SOCK_NONBLOCK | V3_SOCK_REUSEADDR;
    err = v3_udp_create(V3_AF_INET, sock_flags, &core->udp_socket);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create UDP socket: %s", v3_error_str(err));
        return err;
    }
    
    /* 设置缓冲区大小 */
    v3_socket_set_rcvbuf(core->udp_socket, V3_NET_DEFAULT_RCVBUF);
    v3_socket_set_sndbuf(core->udp_socket, V3_NET_DEFAULT_SNDBUF);
    
    /* 绑定 */
    err = v3_udp_bind(core->udp_socket, &core->bind_addr);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to bind UDP socket: %s", v3_error_str(err));
        v3_socket_close(core->udp_socket);
        return err;
    }
    
    char addr_str[V3_ADDRESS_MAX_STR_LEN];
    v3_address_to_string(&core->bind_addr, addr_str, sizeof(addr_str));
    V3_LOG_INFO("UDP socket bound to %s", addr_str);
    
#ifdef V3_PLATFORM_WINDOWS
    /* 创建 IOCP */
    err = v3_iocp_create(&core->iocp);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create IOCP: %s", v3_error_str(err));
        v3_socket_close(core->udp_socket);
        return err;
    }
    
    /* 关联 Socket 到 IOCP */
    err = v3_iocp_associate(core->iocp, core->udp_socket, core);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to associate socket with IOCP");
        v3_iocp_destroy(core->iocp);
        v3_socket_close(core->udp_socket);
        return err;
    }
    
    V3_LOG_INFO("IOCP initialized");
#endif
    
    return V3_OK;
}

static v3_error_t init_protocol(v3_core_t *core) {
    v3_error_t err;
    
    err = v3_protocol_ctx_create(&core->protocol_ctx);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create protocol context");
        return err;
    }
    
    err = v3_protocol_ctx_set_key(core->protocol_ctx, core->master_key);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to set protocol key");
        return err;
    }
    
    V3_LOG_INFO("Protocol module initialized");
    return V3_OK;
}

static v3_error_t init_connections(v3_core_t *core, const v3_init_options_t *opts) {
    v3_conn_manager_config_t cfg;
    v3_conn_manager_default_config(&cfg);
    
    cfg.max_connections = opts->max_connections;
    cfg.timeout_sec = opts->connection_timeout_sec;
    
    v3_error_t err = v3_conn_manager_create(&cfg, &core->conn_manager);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create connection manager");
        return err;
    }
    
    V3_LOG_INFO("Connection manager initialized (max: %u)", cfg.max_connections);
    return V3_OK;
}

static v3_error_t init_fec(v3_core_t *core, const v3_init_options_t *opts) {
    if (!opts->fec_enabled) {
        V3_LOG_INFO("FEC disabled");
        return V3_OK;
    }
    
    v3_fec_encoder_config_t enc_cfg = {
        .type = opts->fec_type,
        .data_shards = opts->fec_data_shards,
        .parity_shards = opts->fec_parity_shards,
    };
    
    v3_error_t err = v3_fec_encoder_create(&enc_cfg, &core->fec_encoder);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create FEC encoder");
        return err;
    }
    
    err = v3_fec_decoder_create(opts->fec_type, &core->fec_decoder);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create FEC decoder");
        v3_fec_encoder_destroy(core->fec_encoder);
        return err;
    }
    
    V3_LOG_INFO("FEC initialized (type: %s, %d:%d)",
                v3_fec_type_str(opts->fec_type),
                opts->fec_data_shards, opts->fec_parity_shards);
    
    return V3_OK;
}

static v3_error_t init_pacing(v3_core_t *core, const v3_init_options_t *opts) {
    if (!opts->pacing_enabled) {
        V3_LOG_INFO("Pacing disabled");
        return V3_OK;
    }
    
    v3_pacing_config_t cfg;
    v3_pacer_default_config(&cfg);
    
    cfg.mode = opts->pacing_mode;
    cfg.target_bps = opts->pacing_rate_bps;
    
    v3_error_t err = v3_pacer_create(&cfg, &core->pacer);
    if (V3_IS_ERROR(err)) {
        V3_LOG_ERROR("Failed to create pacer");
        return err;
    }
    
    V3_LOG_INFO("Pacing initialized (mode: %s, rate: %lu Mbps)",
                v3_pacing_mode_str(cfg.mode), cfg.target_bps / 1000000);
    
    return V3_OK;
}

static v3_error_t init_ipc(v3_core_t *core, const v3_init_options_t *opts) {
    if (!opts->ipc_enabled) {
        V3_LOG_INFO("IPC disabled");
        return V3_OK;
    }
    
    v3_error_t err = v3_ipc_server_create(opts->ipc_pipe_name, &core->ipc_server);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("Failed to create IPC server: %s", v3_error_str(err));
        /* IPC 失败不是致命错误 */
        return V3_OK;
    }
    
    err = v3_ipc_server_start(core->ipc_server);
    if (V3_IS_ERROR(err)) {
        V3_LOG_WARN("Failed to start IPC server");
        v3_ipc_server_destroy(core->ipc_server);
        core->ipc_server = NULL;
        return V3_OK;
    }
    
    V3_LOG_INFO("IPC server started");
    return V3_OK;
}

/* =========================================================
 * 核心初始化/关闭
 * ========================================================= */

v3_error_t v3_core_init(const v3_init_options_t *opts) {
    v3_error_t err;
    
    if (g_core != NULL) {
        return V3_ERR_ALREADY_EXISTS;
    }
    
    /* 分配核心上下文 */
    g_core = (v3_core_t*)v3_calloc(1, sizeof(v3_core_t));
    if (!g_core) {
        return V3_ERR_MEM_ALLOC_FAILED;
    }
    
    g_core->state = V3_STATE_UNINITIALIZED;
    g_core->udp_socket = V3_INVALID_SOCKET;
    
    /* 复制选项 */
    if (opts) {
        memcpy(&g_core->options, opts, sizeof(v3_init_options_t));
    } else {
        v3_core_default_options(&g_core->options);
    }
    
    /* 初始化各模块 */
    V3_TRY_GOTO(init_platform(), cleanup);
    V3_TRY_GOTO(init_logging(&g_core->options), cleanup);
    
    V3_LOG_INFO("Initializing v3 Core %s...", V3_VERSION_STRING);
    
    V3_TRY_GOTO(v3_exit_init(), cleanup);
    V3_TRY_GOTO(v3_lifecycle_init(), cleanup);
    V3_TRY_GOTO(v3_stats_init(), cleanup);
    V3_TRY_GOTO(v3_buffer_global_init(), cleanup);
    
    V3_TRY_GOTO(init_crypto(g_core, &g_core->options), cleanup);
    V3_TRY_GOTO(init_network(g_core, &g_core->options), cleanup);
    V3_TRY_GOTO(init_protocol(g_core), cleanup);
    V3_TRY_GOTO(init_connections(g_core, &g_core->options), cleanup);
    V3_TRY_GOTO(init_fec(g_core, &g_core->options), cleanup);
    V3_TRY_GOTO(init_pacing(g_core, &g_core->options), cleanup);
    V3_TRY_GOTO(init_ipc(g_core, &g_core->options), cleanup);
    
    /* 设置信号处理 */
    if (!(g_core->options.flags & V3_INIT_FLAG_NO_SIGNALS)) {
        v3_exit_setup_signals();
    }
    
    g_core->state = V3_STATE_INITIALIZED;
    g_core->start_time = v3_time_unix();
    
    V3_LOG_INFO("v3 Core initialized successfully");
    return V3_OK;
    
cleanup:
    V3_LOG_ERROR("v3 Core initialization failed");
    v3_core_shutdown();
    return err;
}

v3_error_t v3_core_shutdown(void) {
    if (!g_core) {
        return V3_OK;
    }
    
    V3_LOG_INFO("Shutting down v3 Core...");
    
    g_core->state = V3_STATE_STOPPING;
    
    /* 停止 IPC */
    if (g_core->ipc_server) {
        v3_ipc_server_stop(g_core->ipc_server);
        v3_ipc_server_destroy(g_core->ipc_server);
        g_core->ipc_server = NULL;
    }
    
    /* 关闭连接 */
    if (g_core->conn_manager) {
        v3_conn_manager_close_all(g_core->conn_manager);
        v3_conn_manager_destroy(g_core->conn_manager);
        g_core->conn_manager = NULL;
    }
    
    /* 销毁 Pacer */
    if (g_core->pacer) {
        v3_pacer_destroy(g_core->pacer);
        g_core->pacer = NULL;
    }
    
    /* 销毁 FEC */
    if (g_core->fec_encoder) {
        v3_fec_encoder_destroy(g_core->fec_encoder);
        g_core->fec_encoder = NULL;
    }
    if (g_core->fec_decoder) {
        v3_fec_decoder_destroy(g_core->fec_decoder);
        g_core->fec_decoder = NULL;
    }
    
    /* 销毁协议上下文 */
    if (g_core->protocol_ctx) {
        v3_protocol_ctx_destroy(g_core->protocol_ctx);
        g_core->protocol_ctx = NULL;
    }
    
#ifdef V3_PLATFORM_WINDOWS
    /* 销毁 IOCP */
    if (g_core->iocp) {
        v3_iocp_destroy(g_core->iocp);
        g_core->iocp = NULL;
    }
#endif
    
    /* 关闭 Socket */
    if (g_core->udp_socket != V3_INVALID_SOCKET) {
        v3_socket_close(g_core->udp_socket);
        g_core->udp_socket = V3_INVALID_SOCKET;
    }
    
    /* 清除密钥 */
    v3_crypto_zero(g_core->master_key, sizeof(g_core->master_key));
    
    /* 关闭各模块 */
    v3_buffer_global_shutdown();
    v3_stats_shutdown();
    v3_lifecycle_shutdown();
    v3_exit_shutdown();
    v3_crypto_shutdown();
    v3_net_shutdown();
    v3_log_shutdown();
    v3_platform_shutdown();
    
    g_core->state = V3_STATE_STOPPED;
    
    /* 释放核心上下文 */
    v3_free(g_core);
    g_core = NULL;
    
    return V3_OK;
}

/* =========================================================
 * 状态查询
 * ========================================================= */

v3_core_t* v3_core_get_context(void) {
    return g_core;
}

v3_state_t v3_core_get_state(void) {
    return g_core ? g_core->state : V3_STATE_UNINITIALIZED;
}

/* =========================================================
 * 数据包处理
 * ========================================================= */

static void handle_packet(v3_core_t *core, 
                          const u8 *data, usize len,
                          const v3_address_t *from) {
    /* 记录接收统计 */
    v3_stats_record_rx(len);
    
    /* 解析数据包 */
    v3_packet_t packet;
    v3_error_t err = v3_protocol_parse(core->protocol_ctx, &packet, data, len);
    
    if (V3_IS_ERROR(err)) {
        v3_stats_record_drop(1);  /* 无效包 */
        
        if (core->options.flags & V3_INIT_FLAG_VERBOSE) {
            char addr_str[V3_ADDRESS_MAX_STR_LEN];
            v3_address_to_string(from, addr_str, sizeof(addr_str));
            V3_LOG_DEBUG("Invalid packet from %s: %s", addr_str, v3_error_str(err));
        }
        return;
    }
    
    /* 处理 FEC */
    if (core->fec_decoder && (packet.meta.flags & V3_FLAG_FEC)) {
        /* FEC 分片处理 */
        u8 recovered_data[V3_FEC_SHARD_SIZE * V3_FEC_MAX_DATA_SHARDS];
        usize recovered_len;
        
        int result = v3_fec_decode(
            core->fec_decoder,
            packet.header.magic_derived,  /* 使用 magic 作为 group_id */
            (u8)(packet.meta.stream_id & 0xFF),  /* shard index */
            packet.payload,
            packet.payload_len,
            recovered_data,
            &recovered_len
        );
        
        if (result == 1) {
            /* 恢复成功 */
            v3_stats_record_fec(true);
            V3_LOG_TRACE("FEC recovery successful, %zu bytes", recovered_len);
            /* 继续处理恢复的数据... */
        } else if (result < 0) {
            v3_stats_record_fec(false);
        }
        /* result == 0: 等待更多分片 */
    }
    
    /* 查找或创建连接 */
    v3_connection_t *conn = v3_conn_manager_find_by_session(
        core->conn_manager, packet.meta.session_token);
    
    if (!conn) {
        /* 新连接 */
        err = v3_connection_create(core->conn_manager, from, 
                                   V3_CONN_TYPE_CLIENT, &conn);
        if (V3_IS_ERROR(err)) {
            V3_LOG_WARN("Failed to create connection");
            return;
        }
        
        v3_connection_set_session_token(conn, packet.meta.session_token);
        
        if (core->options.flags & V3_INIT_FLAG_VERBOSE) {
            char addr_str[V3_ADDRESS_MAX_STR_LEN];
            v3_address_to_string(from, addr_str, sizeof(addr_str));
            V3_LOG_INFO("New connection from %s, session: 0x%llX",
                        addr_str, (unsigned long long)packet.meta.session_token);
        }
    }
    
    /* 更新连接统计 */
    v3_connection_record_recv(conn, len);
    
    /* 传递给连接管理器处理 */
    v3_conn_manager_process_packet(core->conn_manager, &packet, from);
}

/* =========================================================
 * 主事件循环
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS

/* Windows IOCP 事件循环 */
static void io_completion_callback(
    v3_io_op_t op,
    v3_error_t error,
    usize bytes_transferred,
    void *user_data
) {
    v3_core_t *core = (v3_core_t*)user_data;
    
    if (op == V3_IO_OP_READ) {
        if (V3_IS_OK(error) && bytes_transferred > 0) {
            v3_address_t from;  /* TODO: 从 IOCP 获取源地址 */
            handle_packet(core, core->recv_buf, bytes_transferred, &from);
        }
        
        /* 重新投递接收请求 */
        if (!core->should_stop) {
            v3_iocp_recv(core->iocp, core->udp_socket,
                        core->recv_buf, sizeof(core->recv_buf),
                        io_completion_callback, core);
        }
    }
}

static int run_windows_loop(v3_core_t *core) {
    /* 投递初始接收请求 */
    v3_iocp_recv(core->iocp, core->udp_socket,
                 core->recv_buf, sizeof(core->recv_buf),
                 io_completion_callback, core);
    
    while (!core->should_stop && !v3_exit_requested()) {
        /* 处理 IOCP 完成 */
        int count = v3_iocp_poll(core->iocp, 100);
        
        /* 定时任务 */
        v3_conn_manager_tick(core->conn_manager);
        
        /* 每秒更新统计 */
        u64 now = v3_time_ms();
        if (now - core->last_stats_time >= 1000) {
            core->last_stats_time = now;
            /* 可以在这里打印统计或推送到 IPC */
        }
    }
    
    return v3_exit_get_code();
}

#else

/* POSIX select/poll 事件循环 */
static int run_posix_loop(v3_core_t *core) {
    fd_set read_fds;
    struct timeval tv;
    
    while (!core->should_stop && !v3_exit_requested()) {
        FD_ZERO(&read_fds);
        FD_SET(core->udp_socket, &read_fds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000;  /* 100ms */
        
        int ready = select(core->udp_socket + 1, &read_fds, NULL, NULL, &tv);
        
        if (ready > 0 && FD_ISSET(core->udp_socket, &read_fds)) {
            v3_address_t from;
            isize len = v3_udp_recvfrom(core->udp_socket, 
                                        core->recv_buf, sizeof(core->recv_buf),
                                        &from);
            if (len > 0) {
                handle_packet(core, core->recv_buf, (usize)len, &from);
            }
        }
        
        /* 定时任务 */
        v3_conn_manager_tick(core->conn_manager);
        
        /* 统计更新 */
        u64 now = v3_time_ms();
        if (now - core->last_stats_time >= 1000) {
            core->last_stats_time = now;
        }
    }
    
    return v3_exit_get_code();
}

#endif

/* =========================================================
 * 启动/停止/运行
 * ========================================================= */

v3_error_t v3_core_start(void) {
    if (!g_core) {
        return V3_ERR_INVALID_STATE;
    }
    
    if (g_core->state != V3_STATE_INITIALIZED) {
        return V3_ERR_INVALID_STATE;
    }
    
    V3_LOG_INFO("Starting v3 Core...");
    
    g_core->state = V3_STATE_STARTING;
    
    /* 执行启动序列 */
    v3_error_t err = v3_lifecycle_startup();
    if (V3_IS_ERROR(err)) {
        g_core->state = V3_STATE_ERROR;
        return err;
    }
    
    g_core->state = V3_STATE_RUNNING;
    g_core->should_stop = false;
    g_core->last_stats_time = v3_time_ms();
    
    V3_LOG_INFO("v3 Core started successfully");
    return V3_OK;
}

v3_error_t v3_core_stop(void) {
    if (!g_core || g_core->state != V3_STATE_RUNNING) {
        return V3_ERR_INVALID_STATE;
    }
    
    V3_LOG_INFO("Stopping v3 Core...");
    
    g_core->should_stop = true;
    g_core->state = V3_STATE_STOPPING;
    
    /* 执行停止序列 */
    v3_lifecycle_stop();
    
    g_core->state = V3_STATE_STOPPED;
    
    V3_LOG_INFO("v3 Core stopped");
    return V3_OK;
}

int v3_core_run(void) {
    if (!g_core) {
        return V3_EXIT_INIT_FAILED;
    }
    
    /* 如果还没启动，先启动 */
    if (g_core->state == V3_STATE_INITIALIZED) {
        v3_error_t err = v3_core_start();
        if (V3_IS_ERROR(err)) {
            return V3_EXIT_INIT_FAILED;
        }
    }
    
    if (g_core->state != V3_STATE_RUNNING) {
        return V3_EXIT_INIT_FAILED;
    }
    
    V3_LOG_INFO("Entering main event loop...");
    
    int exit_code;
    
#ifdef V3_PLATFORM_WINDOWS
    exit_code = run_windows_loop(g_core);
#else
    exit_code = run_posix_loop(g_core);
#endif
    
    V3_LOG_INFO("Main event loop exited with code %d", exit_code);
    
    /* 停止 */
    if (g_core->state == V3_STATE_RUNNING) {
        v3_core_stop();
    }
    
    return exit_code;
}

v3_error_t v3_core_poll(u32 timeout_ms) {
    if (!g_core || g_core->state != V3_STATE_RUNNING) {
        return V3_ERR_INVALID_STATE;
    }
    
#ifdef V3_PLATFORM_WINDOWS
    int count = v3_iocp_poll(g_core->iocp, timeout_ms);
    return count > 0 ? V3_OK : V3_ERR_TIMEOUT;
#else
    /* 简化实现 */
    v3_sleep_ms(timeout_ms);
    return V3_ERR_TIMEOUT;
#endif
}

v3_error_t v3_core_reload(void) {
    if (!g_core) {
        return V3_ERR_INVALID_STATE;
    }
    
    V3_LOG_INFO("Reloading configuration...");
    
    return v3_lifecycle_reload();
}

/* =========================================================
 * 版本信息
 * ========================================================= */

const char* v3_core_version_string(void) {
    return V3_VERSION_STRING;
}

void v3_core_version(int *major, int *minor, int *patch) {
    if (major) *major = V3_VERSION_MAJOR;
    if (minor) *minor = V3_VERSION_MINOR;
    if (patch) *patch = V3_VERSION_PATCH;
}

const char* v3_core_build_info(void) {
    static char buf[256];
    snprintf(buf, sizeof(buf), "Built %s with %s for %s",
             V3_BUILD_TIME, V3_BUILD_COMPILER, V3_BUILD_PLATFORM);
    return buf;
}

const char* v3_core_platform_info(void) {
    return V3_BUILD_PLATFORM;
}

void v3_core_print_banner(void) {
    printf("%s\n\n", V3_BANNER);
}

void v3_core_print_version(void) {
    print_version();
}

/* =========================================================
 * 统计
 * ========================================================= */

v3_error_t v3_core_get_stats(v3_stats_t *stats) {
    return v3_stats_snapshot(stats);
}

v3_error_t v3_core_reset_stats(void) {
    return v3_stats_reset();
}

/* =========================================================
 * 工具函数
 * ========================================================= */

void v3_secure_zero(void *ptr, usize size) {
    v3_crypto_zero(ptr, size);
}

int v3_secure_compare(const void *a, const void *b, usize size) {
    return v3_crypto_verify(a, b, size);
}

v3_error_t v3_random_bytes(u8 *buf, usize size) {
    return v3_crypto_random(buf, size);
}

void v3_hex_encode(char *out, const u8 *data, usize len) {
    static const char hex[] = "0123456789abcdef";
    for (usize i = 0; i < len; i++) {
        out[i * 2]     = hex[(data[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[data[i] & 0xF];
    }
    out[len * 2] = '\0';
}

v3_error_t v3_hex_decode(u8 *out, const char *hex, usize len) {
    if (len % 2 != 0) {
        return V3_ERR_INVALID_PARAM;
    }
    
    for (usize i = 0; i < len / 2; i++) {
        char hi = hex[i * 2];
        char lo = hex[i * 2 + 1];
        
        u8 val = 0;
        
        if (hi >= '0' && hi <= '9') val = (hi - '0') << 4;
        else if (hi >= 'a' && hi <= 'f') val = (hi - 'a' + 10) << 4;
        else if (hi >= 'A' && hi <= 'F') val = (hi - 'A' + 10) << 4;
        else return V3_ERR_INVALID_PARAM;
        
        if (lo >= '0' && lo <= '9') val |= lo - '0';
        else if (lo >= 'a' && lo <= 'f') val |= lo - 'a' + 10;
        else if (lo >= 'A' && lo <= 'F') val |= lo - 'A' + 10;
        else return V3_ERR_INVALID_PARAM;
        
        out[i] = val;
    }
    
    return V3_OK;
}

/* =========================================================
 * 调试支持
 * ========================================================= */

#ifdef V3_DEBUG
V3_NORETURN void v3_assert_fail(
    const char *expr,
    const char *file,
    int line,
    const char *func
) {
    V3_LOG_FATAL("Assertion failed: %s", expr);
    V3_LOG_FATAL("  at %s:%d in %s()", file, line, func);
    
    v3_exit_abort(V3_EXIT_FATAL_ERROR);
}
#endif
