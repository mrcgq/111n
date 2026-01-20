
/*
 * win_pipe.c - Windows Named Pipe Implementation
 * 
 * 功能：
 * - 命名管道服务端/客户端
 * - 异步 I/O 支持
 * - 用于进程间通信 (IPC)
 * - 支持多实例
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#ifdef _WIN32

#include "v3_ipc.h"
#include "v3_platform.h"
#include "v3_error.h"
#include "v3_log.h"

#include <windows.h>
#include <strsafe.h>

/* =========================================================
 * 常量定义
 * ========================================================= */

#define V3_PIPE_PREFIX          L"\\\\.\\pipe\\v3_"
#define V3_PIPE_BUFFER_SIZE     (64 * 1024)
#define V3_PIPE_TIMEOUT_MS      5000
#define V3_PIPE_MAX_INSTANCES   8

/* =========================================================
 * 管道结构
 * ========================================================= */

struct v3_pipe_s {
    HANDLE          handle;
    wchar_t         name[256];
    bool            is_server;
    bool            connected;
    bool            async_mode;
    OVERLAPPED      overlapped;
    uint8_t         read_buffer[V3_PIPE_BUFFER_SIZE];
    size_t          read_pending;
    v3_pipe_callback_t callback;
    void           *user_data;
};

/* =========================================================
 * 管道创建
 * ========================================================= */

static void build_pipe_name(wchar_t *out, size_t out_len, const char *name) {
    wchar_t wide_name[128];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wide_name, 128);
    StringCbPrintfW(out, out_len * sizeof(wchar_t), L"%s%s", V3_PIPE_PREFIX, wide_name);
}

v3_pipe_t* v3_pipe_create_server(const char *name, bool async) {
    v3_pipe_t *pipe = (v3_pipe_t*)calloc(1, sizeof(v3_pipe_t));
    if (!pipe) {
        return NULL;
    }

    build_pipe_name(pipe->name, 256, name);
    pipe->is_server = true;
    pipe->async_mode = async;

    /* 创建命名管道 */
    DWORD open_mode = PIPE_ACCESS_DUPLEX;
    if (async) {
        open_mode |= FILE_FLAG_OVERLAPPED;
    }

    DWORD pipe_mode = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT;
    if (!async) {
        pipe_mode |= PIPE_NOWAIT;
    }

    pipe->handle = CreateNamedPipeW(
        pipe->name,
        open_mode,
        pipe_mode,
        V3_PIPE_MAX_INSTANCES,
        V3_PIPE_BUFFER_SIZE,
        V3_PIPE_BUFFER_SIZE,
        V3_PIPE_TIMEOUT_MS,
        NULL    /* 默认安全属性 */
    );

    if (pipe->handle == INVALID_HANDLE_VALUE) {
        V3_LOG_ERROR("CreateNamedPipe failed: %lu", GetLastError());
        free(pipe);
        return NULL;
    }

    /* 初始化异步结构 */
    if (async) {
        pipe->overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (pipe->overlapped.hEvent == NULL) {
            CloseHandle(pipe->handle);
            free(pipe);
            return NULL;
        }
    }

    V3_LOG_DEBUG("Pipe server created: %ls", pipe->name);
    return pipe;
}

v3_pipe_t* v3_pipe_create_client(const char *name, bool async) {
    v3_pipe_t *pipe = (v3_pipe_t*)calloc(1, sizeof(v3_pipe_t));
    if (!pipe) {
        return NULL;
    }

    build_pipe_name(pipe->name, 256, name);
    pipe->is_server = false;
    pipe->async_mode = async;

    /* 等待管道可用 */
    if (!WaitNamedPipeW(pipe->name, V3_PIPE_TIMEOUT_MS)) {
        DWORD err = GetLastError();
        if (err != ERROR_SEM_TIMEOUT) {
            V3_LOG_ERROR("WaitNamedPipe failed: %lu", err);
        }
        free(pipe);
        return NULL;
    }

    /* 打开管道 */
    DWORD flags = async ? FILE_FLAG_OVERLAPPED : 0;
    
    pipe->handle = CreateFileW(
        pipe->name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        flags,
        NULL
    );

    if (pipe->handle == INVALID_HANDLE_VALUE) {
        V3_LOG_ERROR("CreateFile for pipe failed: %lu", GetLastError());
        free(pipe);
        return NULL;
    }

    /* 设置消息模式 */
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe->handle, &mode, NULL, NULL);

    /* 初始化异步结构 */
    if (async) {
        pipe->overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (pipe->overlapped.hEvent == NULL) {
            CloseHandle(pipe->handle);
            free(pipe);
            return NULL;
        }
    }

    pipe->connected = true;
    V3_LOG_DEBUG("Pipe client connected: %ls", pipe->name);

    return pipe;
}

void v3_pipe_destroy(v3_pipe_t *pipe) {
    if (!pipe) return;

    if (pipe->is_server && pipe->connected) {
        DisconnectNamedPipe(pipe->handle);
    }

    if (pipe->overlapped.hEvent) {
        CloseHandle(pipe->overlapped.hEvent);
    }

    if (pipe->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe->handle);
    }

    V3_LOG_DEBUG("Pipe destroyed: %ls", pipe->name);
    free(pipe);
}

/* =========================================================
 * 连接管理
 * ========================================================= */

int v3_pipe_accept(v3_pipe_t *pipe, uint32_t timeout_ms) {
    if (!pipe || !pipe->is_server) {
        return V3_ERR_INVALID_PARAM;
    }

    if (pipe->connected) {
        return V3_OK;
    }

    if (pipe->async_mode) {
        /* 异步模式 */
        BOOL result = ConnectNamedPipe(pipe->handle, &pipe->overlapped);
        if (!result) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* 等待连接 */
                DWORD wait_result = WaitForSingleObject(
                    pipe->overlapped.hEvent,
                    timeout_ms == 0 ? INFINITE : timeout_ms
                );
                
                if (wait_result == WAIT_TIMEOUT) {
                    CancelIo(pipe->handle);
                    return V3_ERR_TIMEOUT;
                }
                
                if (wait_result != WAIT_OBJECT_0) {
                    return V3_ERR_IPC;
                }
            } else if (err == ERROR_PIPE_CONNECTED) {
                /* 已连接 */
                pipe->connected = true;
                return V3_OK;
            } else {
                return V3_ERR_IPC;
            }
        }
    } else {
        /* 同步模式 */
        BOOL result = ConnectNamedPipe(pipe->handle, NULL);
        if (!result) {
            DWORD err = GetLastError();
            if (err != ERROR_PIPE_CONNECTED) {
                if (err == ERROR_PIPE_LISTENING) {
                    return V3_ERR_WOULD_BLOCK;
                }
                return V3_ERR_IPC;
            }
        }
    }

    pipe->connected = true;
    V3_LOG_DEBUG("Pipe client connected");
    return V3_OK;
}

int v3_pipe_disconnect(v3_pipe_t *pipe) {
    if (!pipe || !pipe->is_server) {
        return V3_ERR_INVALID_PARAM;
    }

    if (!pipe->connected) {
        return V3_OK;
    }

    FlushFileBuffers(pipe->handle);
    DisconnectNamedPipe(pipe->handle);
    pipe->connected = false;

    V3_LOG_DEBUG("Pipe client disconnected");
    return V3_OK;
}

bool v3_pipe_is_connected(v3_pipe_t *pipe) {
    if (!pipe) return false;
    return pipe->connected;
}

/* =========================================================
 * 读写操作
 * ========================================================= */

ssize_t v3_pipe_write(v3_pipe_t *pipe, const void *data, size_t len) {
    if (!pipe || !data || len == 0) {
        return V3_ERR_INVALID_PARAM;
    }

    if (!pipe->connected && !pipe->is_server) {
        return V3_ERR_NOT_CONNECTED;
    }

    DWORD written = 0;
    BOOL result;

    if (pipe->async_mode) {
        ResetEvent(pipe->overlapped.hEvent);
        result = WriteFile(pipe->handle, data, (DWORD)len, &written, &pipe->overlapped);
        
        if (!result) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* 等待完成 */
                if (!GetOverlappedResult(pipe->handle, &pipe->overlapped, &written, TRUE)) {
                    return V3_ERR_IPC;
                }
            } else if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                pipe->connected = false;
                return V3_ERR_DISCONNECTED;
            } else {
                return V3_ERR_IPC;
            }
        }
    } else {
        result = WriteFile(pipe->handle, data, (DWORD)len, &written, NULL);
        if (!result) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                pipe->connected = false;
                return V3_ERR_DISCONNECTED;
            }
            return V3_ERR_IPC;
        }
    }

    return (ssize_t)written;
}

ssize_t v3_pipe_read(v3_pipe_t *pipe, void *buf, size_t len) {
    if (!pipe || !buf || len == 0) {
        return V3_ERR_INVALID_PARAM;
    }

    if (!pipe->connected && !pipe->is_server) {
        return V3_ERR_NOT_CONNECTED;
    }

    DWORD read_bytes = 0;
    BOOL result;

    if (pipe->async_mode) {
        ResetEvent(pipe->overlapped.hEvent);
        result = ReadFile(pipe->handle, buf, (DWORD)len, &read_bytes, &pipe->overlapped);
        
        if (!result) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                /* 等待完成 */
                if (!GetOverlappedResult(pipe->handle, &pipe->overlapped, &read_bytes, TRUE)) {
                    err = GetLastError();
                    if (err == ERROR_BROKEN_PIPE) {
                        pipe->connected = false;
                        return V3_ERR_DISCONNECTED;
                    }
                    return V3_ERR_IPC;
                }
            } else if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                pipe->connected = false;
                return V3_ERR_DISCONNECTED;
            } else if (err == ERROR_MORE_DATA) {
                /* 消息被截断，但仍返回已读数据 */
            } else {
                return V3_ERR_IPC;
            }
        }
    } else {
        result = ReadFile(pipe->handle, buf, (DWORD)len, &read_bytes, NULL);
        if (!result) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                pipe->connected = false;
                return V3_ERR_DISCONNECTED;
            }
            if (err == ERROR_MORE_DATA) {
                /* 消息被截断 */
            } else {
                return V3_ERR_IPC;
            }
        }
    }

    if (read_bytes == 0) {
        return V3_ERR_WOULD_BLOCK;
    }

    return (ssize_t)read_bytes;
}

/* =========================================================
 * 非阻塞读取
 * ========================================================= */

ssize_t v3_pipe_read_nonblock(v3_pipe_t *pipe, void *buf, size_t len) {
    if (!pipe || !buf || len == 0) {
        return V3_ERR_INVALID_PARAM;
    }

    /* 检查是否有数据 */
    DWORD available = 0;
    if (!PeekNamedPipe(pipe->handle, NULL, 0, NULL, &available, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE) {
            pipe->connected = false;
            return V3_ERR_DISCONNECTED;
        }
        return V3_ERR_IPC;
    }

    if (available == 0) {
        return V3_ERR_WOULD_BLOCK;
    }

    return v3_pipe_read(pipe, buf, len);
}

/* =========================================================
 * 事件等待
 * ========================================================= */

HANDLE v3_pipe_get_event(v3_pipe_t *pipe) {
    if (!pipe || !pipe->async_mode) {
        return NULL;
    }
    return pipe->overlapped.hEvent;
}

HANDLE v3_pipe_get_handle(v3_pipe_t *pipe) {
    return pipe ? pipe->handle : INVALID_HANDLE_VALUE;
}

/* =========================================================
 * 回调设置
 * ========================================================= */

void v3_pipe_set_callback(v3_pipe_t *pipe, v3_pipe_callback_t callback, void *user_data) {
    if (!pipe) return;
    pipe->callback = callback;
    pipe->user_data = user_data;
}

/* =========================================================
 * 辅助函数
 * ========================================================= */

bool v3_pipe_exists(const char *name) {
    wchar_t pipe_name[256];
    build_pipe_name(pipe_name, 256, name);
    
    HANDLE handle = CreateFileW(
        pipe_name,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
        return true;
    }
    
    return GetLastError() == ERROR_PIPE_BUSY;
}

int v3_pipe_send_message(const char *name, const void *data, size_t len) {
    v3_pipe_t *pipe = v3_pipe_create_client(name, false);
    if (!pipe) {
        return V3_ERR_IPC;
    }

    ssize_t result = v3_pipe_write(pipe, data, len);
    v3_pipe_destroy(pipe);

    return result > 0 ? V3_OK : (int)result;
}

#endif /* _WIN32 */
