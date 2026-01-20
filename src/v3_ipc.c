
/*
 * v3_ipc.c - v3 进程间通信实现
 * 
 * 功能：
 * - Windows: 命名管道
 * - Unix: Unix Domain Socket
 * - 命令传递
 * - 状态查询
 * 
 * Copyright (c) 2024 v3 Project
 */

#define _CRT_SECURE_NO_WARNINGS
#include "v3_ipc.h"
#include "v3_log.h"
#include "v3_error.h"
#include "v3_platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#endif

/* =========================================================
 * IPC 协议定义
 * ========================================================= */

#define IPC_MAGIC           0x56335049  /* "V3PI" */
#define IPC_VERSION         1
#define IPC_MAX_PAYLOAD     65536
#define IPC_TIMEOUT_MS      5000

/* IPC 消息头 */
typedef struct {
    uint32_t    magic;
    uint16_t    version;
    uint16_t    type;
    uint32_t    payload_len;
    uint32_t    seq;
} ipc_header_t;

/* 消息类型 */
typedef enum {
    IPC_MSG_PING        = 0,
    IPC_MSG_PONG        = 1,
    IPC_MSG_STATUS_REQ  = 2,
    IPC_MSG_STATUS_RESP = 3,
    IPC_MSG_COMMAND     = 4,
    IPC_MSG_COMMAND_ACK = 5,
    IPC_MSG_SHUTDOWN    = 6,
    IPC_MSG_RELOAD      = 7,
    IPC_MSG_STATS_REQ   = 8,
    IPC_MSG_STATS_RESP  = 9,
    IPC_MSG_ERROR       = 255,
} ipc_msg_type_t;

/* =========================================================
 * IPC 上下文
 * ========================================================= */

struct v3_ipc_s {
    bool            is_server;
    bool            running;
    char            path[V3_MAX_PATH];
    uint32_t        seq;
    
    /* 回调 */
    v3_ipc_handler_t handler;
    void            *handler_arg;
    
#ifdef _WIN32
    HANDLE          pipe;
    HANDLE          thread;
    OVERLAPPED      overlap;
#else
    int             sock_fd;
    int             client_fd;
    pthread_t       thread;
#endif
};

/* =========================================================
 * 平台相关实现 - Windows
 * ========================================================= */

#ifdef _WIN32

static const char* ipc_get_default_path(void) {
    static char path[256];
    snprintf(path, sizeof(path), "\\\\.\\pipe\\v3_control");
    return path;
}

static v3_error_t ipc_create_server_win(v3_ipc_t *ipc) {
    ipc->pipe = CreateNamedPipeA(
        ipc->path,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,                      /* 最大实例数 */
        IPC_MAX_PAYLOAD,
        IPC_MAX_PAYLOAD,
        IPC_TIMEOUT_MS,
        NULL
    );
    
    if (ipc->pipe == INVALID_HANDLE_VALUE) {
        V3_LOG_ERROR("Failed to create named pipe: %lu", GetLastError());
        return V3_ERR_IPC_CREATE;
    }
    
    memset(&ipc->overlap, 0, sizeof(ipc->overlap));
    ipc->overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    return V3_OK;
}

static v3_error_t ipc_connect_client_win(v3_ipc_t *ipc) {
    ipc->pipe = CreateFileA(
        ipc->path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL
    );
    
    if (ipc->pipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipeA(ipc->path, IPC_TIMEOUT_MS)) {
                return V3_ERR_IPC_TIMEOUT;
            }
            /* 重试 */
            ipc->pipe = CreateFileA(
                ipc->path,
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL
            );
        }
        
        if (ipc->pipe == INVALID_HANDLE_VALUE) {
            return V3_ERR_IPC_CONNECT;
        }
    }
    
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(ipc->pipe, &mode, NULL, NULL);
    
    memset(&ipc->overlap, 0, sizeof(ipc->overlap));
    ipc->overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    
    return V3_OK;
}

static v3_error_t ipc_send_win(v3_ipc_t *ipc, const void *data, size_t len) {
    DWORD written;
    ResetEvent(ipc->overlap.hEvent);
    
    if (!WriteFile(ipc->pipe, data, (DWORD)len, &written, &ipc->overlap)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            return V3_ERR_IPC_WRITE;
        }
        
        DWORD result = WaitForSingleObject(ipc->overlap.hEvent, IPC_TIMEOUT_MS);
        if (result != WAIT_OBJECT_0) {
            CancelIo(ipc->pipe);
            return V3_ERR_IPC_TIMEOUT;
        }
        
        if (!GetOverlappedResult(ipc->pipe, &ipc->overlap, &written, FALSE)) {
            return V3_ERR_IPC_WRITE;
        }
    }
    
    return V3_OK;
}

static v3_error_t ipc_recv_win(v3_ipc_t *ipc, void *data, size_t max_len, size_t *out_len) {
    DWORD read_bytes;
    ResetEvent(ipc->overlap.hEvent);
    
    if (!ReadFile(ipc->pipe, data, (DWORD)max_len, &read_bytes, &ipc->overlap)) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING && err != ERROR_MORE_DATA) {
            return V3_ERR_IPC_READ;
        }
        
        DWORD result = WaitForSingleObject(ipc->overlap.hEvent, IPC_TIMEOUT_MS);
        if (result != WAIT_OBJECT_0) {
            CancelIo(ipc->pipe);
            return V3_ERR_IPC_TIMEOUT;
        }
        
        if (!GetOverlappedResult(ipc->pipe, &ipc->overlap, &read_bytes, FALSE)) {
            return V3_ERR_IPC_READ;
        }
    }
    
    *out_len = read_bytes;
    return V3_OK;
}

static void ipc_close_win(v3_ipc_t *ipc) {
    if (ipc->overlap.hEvent) {
        CloseHandle(ipc->overlap.hEvent);
        ipc->overlap.hEvent = NULL;
    }
    if (ipc->pipe != INVALID_HANDLE_VALUE) {
        if (ipc->is_server) {
            DisconnectNamedPipe(ipc->pipe);
        }
        CloseHandle(ipc->pipe);
        ipc->pipe = INVALID_HANDLE_VALUE;
    }
}

#else

/* =========================================================
 * 平台相关实现 - Unix
 * ========================================================= */

static const char* ipc_get_default_path(void) {
    static char path[256];
    snprintf(path, sizeof(path), "/tmp/v3_control.sock");
    return path;
}

static v3_error_t ipc_create_server_unix(v3_ipc_t *ipc) {
    /* 删除已存在的 socket 文件 */
    unlink(ipc->path);
    
    ipc->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc->sock_fd < 0) {
        V3_LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return V3_ERR_IPC_CREATE;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ipc->path, sizeof(addr.sun_path) - 1);
    
    if (bind(ipc->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        V3_LOG_ERROR("Failed to bind socket: %s", strerror(errno));
        close(ipc->sock_fd);
        return V3_ERR_IPC_CREATE;
    }
    
    /* 设置权限 */
    chmod(ipc->path, 0600);
    
    if (listen(ipc->sock_fd, 5) < 0) {
        V3_LOG_ERROR("Failed to listen: %s", strerror(errno));
        close(ipc->sock_fd);
        unlink(ipc->path);
        return V3_ERR_IPC_CREATE;
    }
    
    ipc->client_fd = -1;
    return V3_OK;
}

static v3_error_t ipc_connect_client_unix(v3_ipc_t *ipc) {
    ipc->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ipc->sock_fd < 0) {
        return V3_ERR_IPC_CONNECT;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, ipc->path, sizeof(addr.sun_path) - 1);
    
    if (connect(ipc->sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(ipc->sock_fd);
        ipc->sock_fd = -1;
        return V3_ERR_IPC_CONNECT;
    }
    
    return V3_OK;
}

static v3_error_t ipc_send_unix(v3_ipc_t *ipc, const void *data, size_t len) {
    int fd = ipc->is_server ? ipc->client_fd : ipc->sock_fd;
    if (fd < 0) return V3_ERR_IPC_NOT_CONNECTED;
    
    ssize_t sent = 0;
    while ((size_t)sent < len) {
        ssize_t n = send(fd, (const char*)data + sent, len - sent, 0);
        if (n <= 0) {
            if (errno == EINTR) continue;
            return V3_ERR_IPC_WRITE;
        }
        sent += n;
    }
    
    return V3_OK;
}

static v3_error_t ipc_recv_unix(v3_ipc_t *ipc, void *data, size_t max_len, size_t *out_len) {
    int fd = ipc->is_server ? ipc->client_fd : ipc->sock_fd;
    if (fd < 0) return V3_ERR_IPC_NOT_CONNECTED;
    
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ret = poll(&pfd, 1, IPC_TIMEOUT_MS);
    
    if (ret <= 0) {
        return ret == 0 ? V3_ERR_IPC_TIMEOUT : V3_ERR_IPC_READ;
    }
    
    ssize_t n = recv(fd, data, max_len, 0);
    if (n <= 0) {
        return V3_ERR_IPC_READ;
    }
    
    *out_len = n;
    return V3_OK;
}

static void ipc_close_unix(v3_ipc_t *ipc) {
    if (ipc->client_fd >= 0) {
        close(ipc->client_fd);
        ipc->client_fd = -1;
    }
    if (ipc->sock_fd >= 0) {
        close(ipc->sock_fd);
        ipc->sock_fd = -1;
    }
    if (ipc->is_server && ipc->path[0]) {
        unlink(ipc->path);
    }
}

#endif

/* =========================================================
 * 消息收发
 * ========================================================= */

static v3_error_t ipc_send_message(v3_ipc_t *ipc, uint16_t type, 
                                   const void *payload, size_t payload_len) {
    if (payload_len > IPC_MAX_PAYLOAD) {
        return V3_ERR_IPC_MSG_TOO_LARGE;
    }
    
    size_t total_len = sizeof(ipc_header_t) + payload_len;
    uint8_t *buf = (uint8_t*)malloc(total_len);
    if (!buf) return V3_ERR_NO_MEMORY;
    
    ipc_header_t *hdr = (ipc_header_t*)buf;
    hdr->magic = IPC_MAGIC;
    hdr->version = IPC_VERSION;
    hdr->type = type;
    hdr->payload_len = (uint32_t)payload_len;
    hdr->seq = ++ipc->seq;
    
    if (payload && payload_len > 0) {
        memcpy(buf + sizeof(ipc_header_t), payload, payload_len);
    }
    
#ifdef _WIN32
    v3_error_t err = ipc_send_win(ipc, buf, total_len);
#else
    v3_error_t err = ipc_send_unix(ipc, buf, total_len);
#endif
    
    free(buf);
    return err;
}

static v3_error_t ipc_recv_message(v3_ipc_t *ipc, uint16_t *type,
                                   void *payload, size_t max_len, size_t *out_len) {
    uint8_t buf[sizeof(ipc_header_t) + IPC_MAX_PAYLOAD];
    size_t recv_len;
    
#ifdef _WIN32
    v3_error_t err = ipc_recv_win(ipc, buf, sizeof(buf), &recv_len);
#else
    v3_error_t err = ipc_recv_unix(ipc, buf, sizeof(buf), &recv_len);
#endif
    
    if (err != V3_OK) return err;
    
    if (recv_len < sizeof(ipc_header_t)) {
        return V3_ERR_IPC_PROTOCOL;
    }
    
    ipc_header_t *hdr = (ipc_header_t*)buf;
    
    if (hdr->magic != IPC_MAGIC) {
        return V3_ERR_IPC_PROTOCOL;
    }
    
    if (hdr->version != IPC_VERSION) {
        return V3_ERR_IPC_VERSION;
    }
    
    if (recv_len < sizeof(ipc_header_t) + hdr->payload_len) {
        return V3_ERR_IPC_PROTOCOL;
    }
    
    *type = hdr->type;
    
    if (hdr->payload_len > 0) {
        size_t copy_len = hdr->payload_len;
        if (copy_len > max_len) copy_len = max_len;
        memcpy(payload, buf + sizeof(ipc_header_t), copy_len);
        *out_len = copy_len;
    } else {
        *out_len = 0;
    }
    
    return V3_OK;
}

/* =========================================================
 * 服务器线程
 * ========================================================= */

#ifdef _WIN32
static DWORD WINAPI ipc_server_thread(LPVOID arg) {
#else
static void* ipc_server_thread(void *arg) {
#endif
    v3_ipc_t *ipc = (v3_ipc_t*)arg;
    
    V3_LOG_INFO("IPC server started on: %s", ipc->path);
    
    while (ipc->running) {
#ifdef _WIN32
        /* 等待客户端连接 */
        ResetEvent(ipc->overlap.hEvent);
        if (!ConnectNamedPipe(ipc->pipe, &ipc->overlap)) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                DWORD result = WaitForSingleObject(ipc->overlap.hEvent, 1000);
                if (result == WAIT_TIMEOUT) continue;
                if (result != WAIT_OBJECT_0) break;
            } else if (err != ERROR_PIPE_CONNECTED) {
                break;
            }
        }
#else
        /* 等待客户端连接 */
        struct pollfd pfd = { .fd = ipc->sock_fd, .events = POLLIN };
        int ret = poll(&pfd, 1, 1000);
        if (ret <= 0) continue;
        
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        ipc->client_fd = accept(ipc->sock_fd, (struct sockaddr*)&client_addr, &client_len);
        if (ipc->client_fd < 0) continue;
#endif
        
        V3_LOG_DEBUG("IPC client connected");
        
        /* 处理消息 */
        while (ipc->running) {
            uint16_t msg_type;
            uint8_t payload[IPC_MAX_PAYLOAD];
            size_t payload_len;
            
            v3_error_t err = ipc_recv_message(ipc, &msg_type, payload, sizeof(payload), &payload_len);
            if (err != V3_OK) {
                V3_LOG_DEBUG("IPC recv error: %d", err);
                break;
            }
            
            /* 处理消息 */
            if (ipc->handler) {
                v3_ipc_message_t msg = {
                    .type = msg_type,
                    .payload = payload,
                    .payload_len = payload_len,
                };
                
                v3_ipc_message_t resp = {0};
                ipc->handler(&msg, &resp, ipc->handler_arg);
                
                if (resp.type != 0 || resp.payload_len > 0) {
                    ipc_send_message(ipc, resp.type, resp.payload, resp.payload_len);
                }
            } else {
                /* 默认处理 */
                switch (msg_type) {
                    case IPC_MSG_PING:
                        ipc_send_message(ipc, IPC_MSG_PONG, NULL, 0);
                        break;
                    default:
                        ipc_send_message(ipc, IPC_MSG_ERROR, "Unknown command", 15);
                        break;
                }
            }
        }
        
        /* 断开客户端 */
#ifdef _WIN32
        DisconnectNamedPipe(ipc->pipe);
#else
        if (ipc->client_fd >= 0) {
            close(ipc->client_fd);
            ipc->client_fd = -1;
        }
#endif
        
        V3_LOG_DEBUG("IPC client disconnected");
    }
    
    V3_LOG_INFO("IPC server stopped");
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* =========================================================
 * 公共 API
 * ========================================================= */

v3_ipc_t* v3_ipc_create(bool is_server, const char *path) {
    v3_ipc_t *ipc = (v3_ipc_t*)calloc(1, sizeof(v3_ipc_t));
    if (!ipc) return NULL;
    
    ipc->is_server = is_server;
    ipc->running = false;
    ipc->seq = 0;
    
    if (path && path[0]) {
        strncpy(ipc->path, path, sizeof(ipc->path) - 1);
    } else {
        strncpy(ipc->path, ipc_get_default_path(), sizeof(ipc->path) - 1);
    }
    
#ifdef _WIN32
    ipc->pipe = INVALID_HANDLE_VALUE;
#else
    ipc->sock_fd = -1;
    ipc->client_fd = -1;
#endif
    
    return ipc;
}

void v3_ipc_destroy(v3_ipc_t *ipc) {
    if (!ipc) return;
    
    v3_ipc_stop(ipc);
    
#ifdef _WIN32
    ipc_close_win(ipc);
#else
    ipc_close_unix(ipc);
#endif
    
    free(ipc);
}

v3_error_t v3_ipc_start(v3_ipc_t *ipc) {
    if (!ipc) return V3_ERR_INVALID_PARAM;
    if (ipc->running) return V3_OK;
    
    v3_error_t err;
    
    if (ipc->is_server) {
#ifdef _WIN32
        err = ipc_create_server_win(ipc);
#else
        err = ipc_create_server_unix(ipc);
#endif
        if (err != V3_OK) return err;
        
        ipc->running = true;
        
#ifdef _WIN32
        ipc->thread = CreateThread(NULL, 0, ipc_server_thread, ipc, 0, NULL);
        if (!ipc->thread) {
            ipc->running = false;
            return V3_ERR_THREAD_CREATE;
        }
#else
        if (pthread_create(&ipc->thread, NULL, ipc_server_thread, ipc) != 0) {
            ipc->running = false;
            return V3_ERR_THREAD_CREATE;
        }
#endif
    } else {
#ifdef _WIN32
        err = ipc_connect_client_win(ipc);
#else
        err = ipc_connect_client_unix(ipc);
#endif
        if (err != V3_OK) return err;
        ipc->running = true;
    }
    
    return V3_OK;
}

void v3_ipc_stop(v3_ipc_t *ipc) {
    if (!ipc || !ipc->running) return;
    
    ipc->running = false;
    
    if (ipc->is_server) {
#ifdef _WIN32
        if (ipc->thread) {
            /* 触发事件使线程退出 */
            SetEvent(ipc->overlap.hEvent);
            WaitForSingleObject(ipc->thread, 3000);
            CloseHandle(ipc->thread);
            ipc->thread = NULL;
        }
#else
        /* 关闭 socket 使 accept 返回 */
        if (ipc->sock_fd >= 0) {
            shutdown(ipc->sock_fd, SHUT_RDWR);
        }
        pthread_join(ipc->thread, NULL);
#endif
    }
    
#ifdef _WIN32
    ipc_close_win(ipc);
#else
    ipc_close_unix(ipc);
#endif
}

void v3_ipc_set_handler(v3_ipc_t *ipc, v3_ipc_handler_t handler, void *arg) {
    if (!ipc) return;
    ipc->handler = handler;
    ipc->handler_arg = arg;
}

v3_error_t v3_ipc_send_command(v3_ipc_t *ipc, const char *command, 
                                char *response, size_t resp_size) {
    if (!ipc || !command) return V3_ERR_INVALID_PARAM;
    if (ipc->is_server) return V3_ERR_IPC_WRONG_MODE;
    
    v3_error_t err = ipc_send_message(ipc, IPC_MSG_COMMAND, 
                                       command, strlen(command));
    if (err != V3_OK) return err;
    
    uint16_t resp_type;
    size_t resp_len;
    err = ipc_recv_message(ipc, &resp_type, response, resp_size - 1, &resp_len);
    if (err != V3_OK) return err;
    
    if (response) {
        response[resp_len] = '\0';
    }
    
    return (resp_type == IPC_MSG_COMMAND_ACK) ? V3_OK : V3_ERR_IPC_COMMAND_FAILED;
}

v3_error_t v3_ipc_ping(v3_ipc_t *ipc) {
    if (!ipc) return V3_ERR_INVALID_PARAM;
    if (ipc->is_server) return V3_ERR_IPC_WRONG_MODE;
    
    v3_error_t err = ipc_send_message(ipc, IPC_MSG_PING, NULL, 0);
    if (err != V3_OK) return err;
    
    uint16_t resp_type;
    size_t resp_len;
    uint8_t buf[64];
    err = ipc_recv_message(ipc, &resp_type, buf, sizeof(buf), &resp_len);
    if (err != V3_OK) return err;
    
    return (resp_type == IPC_MSG_PONG) ? V3_OK : V3_ERR_IPC_PROTOCOL;
}
