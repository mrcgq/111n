
/*
 * win_iocp.c - Windows I/O Completion Port Implementation
 * 
 * 功能：
 * - IOCP 事件循环
 * - 异步 UDP 收发
 * - 高性能并发处理
 * - 对应服务端 io_uring
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#ifdef _WIN32

#include "v3_network.h"
#include "v3_platform.h"
#include "v3_buffer.h"
#include "v3_error.h"
#include "v3_log.h"

#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>

#pragma comment(lib, "ws2_32.lib")

/* =========================================================
 * 常量定义
 * ========================================================= */

#define V3_IOCP_MAX_CONCURRENT      0       /* 0 = 系统决定 */
#define V3_IOCP_BUFFER_SIZE         2048
#define V3_IOCP_MAX_PENDING_OPS     4096
#define V3_IOCP_SHUTDOWN_KEY        ((ULONG_PTR)-1)

/* =========================================================
 * 操作类型
 * ========================================================= */

typedef enum {
    V3_IOCP_OP_RECV,
    V3_IOCP_OP_SEND,
    V3_IOCP_OP_CONNECT,
    V3_IOCP_OP_ACCEPT,
    V3_IOCP_OP_DISCONNECT,
    V3_IOCP_OP_TIMEOUT,
} v3_iocp_op_type_t;

/* =========================================================
 * 操作上下文
 * ========================================================= */

typedef struct v3_iocp_op_s {
    OVERLAPPED          overlapped;     /* 必须是第一个成员 */
    v3_iocp_op_type_t   type;
    SOCKET              socket;
    WSABUF              wsabuf;
    uint8_t             buffer[V3_IOCP_BUFFER_SIZE];
    v3_address_t        remote_addr;
    int                 remote_addr_len;
    void               *user_data;
    struct v3_iocp_op_s *next;          /* 用于空闲链表 */
    uint64_t            start_time;     /* 用于超时检测 */
} v3_iocp_op_t;

/* =========================================================
 * IOCP 上下文
 * ========================================================= */

struct v3_iocp_s {
    HANDLE              handle;             /* IOCP 句柄 */
    volatile bool       running;
    volatile bool       shutdown;
    
    /* 操作池 */
    v3_iocp_op_t       *op_pool;            /* 预分配的操作数组 */
    v3_iocp_op_t       *free_list;          /* 空闲操作链表 */
    CRITICAL_SECTION    pool_lock;
    int                 pool_size;
    int                 active_ops;
    
    /* 回调 */
    v3_io_callback_fn  recv_callback;
    v3_io_callback_fn  send_callback;
    void               *callback_data;
    
    /* 统计 */
    volatile LONG64     total_recv;
    volatile LONG64     total_send;
    volatile LONG64     bytes_recv;
    volatile LONG64     bytes_send;
    volatile LONG64     errors;
    
    /* 工作线程 */
    HANDLE             *worker_threads;
    int                 worker_count;
};

/* =========================================================
 * 操作池管理
 * ========================================================= */

static v3_iocp_op_t* iocp_alloc_op(v3_iocp_t *iocp) {
    v3_iocp_op_t *op = NULL;
    
    EnterCriticalSection(&iocp->pool_lock);
    
    if (iocp->free_list) {
        op = iocp->free_list;
        iocp->free_list = op->next;
        iocp->active_ops++;
    }
    
    LeaveCriticalSection(&iocp->pool_lock);
    
    if (op) {
        memset(&op->overlapped, 0, sizeof(OVERLAPPED));
        op->next = NULL;
        op->start_time = v3_time_ms();
    }
    
    return op;
}

static void iocp_free_op(v3_iocp_t *iocp, v3_iocp_op_t *op) {
    if (!op) return;
    
    EnterCriticalSection(&iocp->pool_lock);
    
    op->next = iocp->free_list;
    iocp->free_list = op;
    iocp->active_ops--;
    
    LeaveCriticalSection(&iocp->pool_lock);
}

/* =========================================================
 * IOCP 创建与销毁
 * ========================================================= */

v3_iocp_t* v3_iocp_create(int max_pending) {
    v3_iocp_t *iocp = (v3_iocp_t*)calloc(1, sizeof(v3_iocp_t));
    if (!iocp) {
        return NULL;
    }
    
    if (max_pending <= 0) {
        max_pending = V3_IOCP_MAX_PENDING_OPS;
    }
    
    /* 创建 IOCP */
    iocp->handle = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE,
        NULL,
        0,
        V3_IOCP_MAX_CONCURRENT
    );
    
    if (iocp->handle == NULL) {
        V3_LOG_ERROR("CreateIoCompletionPort failed: %lu", GetLastError());
        free(iocp);
        return NULL;
    }
    
    /* 初始化临界区 */
    InitializeCriticalSectionAndSpinCount(&iocp->pool_lock, 4000);
    
    /* 分配操作池 */
    iocp->pool_size = max_pending;
    iocp->op_pool = (v3_iocp_op_t*)calloc(max_pending, sizeof(v3_iocp_op_t));
    if (!iocp->op_pool) {
        CloseHandle(iocp->handle);
        DeleteCriticalSection(&iocp->pool_lock);
        free(iocp);
        return NULL;
    }
    
    /* 构建空闲链表 */
    for (int i = 0; i < max_pending - 1; i++) {
        iocp->op_pool[i].next = &iocp->op_pool[i + 1];
    }
    iocp->op_pool[max_pending - 1].next = NULL;
    iocp->free_list = &iocp->op_pool[0];
    
    iocp->running = true;
    
    V3_LOG_INFO("IOCP created with pool size %d", max_pending);
    return iocp;
}

void v3_iocp_destroy(v3_iocp_t *iocp) {
    if (!iocp) return;
    
    iocp->shutdown = true;
    iocp->running = false;
    
    /* 停止工作线程 */
    if (iocp->worker_threads) {
        for (int i = 0; i < iocp->worker_count; i++) {
            PostQueuedCompletionStatus(iocp->handle, 0, V3_IOCP_SHUTDOWN_KEY, NULL);
        }
        
        WaitForMultipleObjects(iocp->worker_count, iocp->worker_threads, TRUE, 5000);
        
        for (int i = 0; i < iocp->worker_count; i++) {
            CloseHandle(iocp->worker_threads[i]);
        }
        free(iocp->worker_threads);
    }
    
    /* 清理资源 */
    if (iocp->op_pool) {
        free(iocp->op_pool);
    }
    
    DeleteCriticalSection(&iocp->pool_lock);
    
    if (iocp->handle) {
        CloseHandle(iocp->handle);
    }
    
    V3_LOG_INFO("IOCP destroyed: recv=%lld send=%lld errors=%lld",
                iocp->total_recv, iocp->total_send, iocp->errors);
    
    free(iocp);
}

/* =========================================================
 * Socket 关联
 * ========================================================= */

int v3_iocp_associate(v3_iocp_t *iocp, SOCKET socket, ULONG_PTR key) {
    if (!iocp || socket == INVALID_SOCKET) {
        return V3_ERR_INVALID_PARAM;
    }
    
    HANDLE result = CreateIoCompletionPort(
        (HANDLE)socket,
        iocp->handle,
        key,
        0
    );
    
    if (result == NULL) {
        V3_LOG_ERROR("Failed to associate socket with IOCP: %lu", GetLastError());
        return V3_ERR_NETWORK;
    }
    
    return V3_OK;
}

/* =========================================================
 * 异步接收
 * ========================================================= */

int v3_iocp_post_recv(v3_iocp_t *iocp, SOCKET socket, void *user_data) {
    if (!iocp || socket == INVALID_SOCKET) {
        return V3_ERR_INVALID_PARAM;
    }
    
    v3_iocp_op_t *op = iocp_alloc_op(iocp);
    if (!op) {
        V3_LOG_WARN("IOCP operation pool exhausted");
        return V3_ERR_NO_MEMORY;
    }
    
    op->type = V3_IOCP_OP_RECV;
    op->socket = socket;
    op->user_data = user_data;
    op->wsabuf.buf = (char*)op->buffer;
    op->wsabuf.len = V3_IOCP_BUFFER_SIZE;
    op->remote_addr_len = sizeof(op->remote_addr.storage);
    
    DWORD flags = 0;
    DWORD received = 0;
    
    int result = WSARecvFrom(
        socket,
        &op->wsabuf,
        1,
        &received,
        &flags,
        (struct sockaddr*)&op->remote_addr.storage,
        &op->remote_addr_len,
        &op->overlapped,
        NULL
    );
    
    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            V3_LOG_ERROR("WSARecvFrom failed: %d", err);
            iocp_free_op(iocp, op);
            InterlockedIncrement64(&iocp->errors);
            return V3_ERR_NETWORK;
        }
    }
    
    return V3_OK;
}

int v3_iocp_post_recv_batch(v3_iocp_t *iocp, SOCKET socket,
                             void *user_data, int count) {
    int posted = 0;
    
    for (int i = 0; i < count; i++) {
        if (v3_iocp_post_recv(iocp, socket, user_data) == V3_OK) {
            posted++;
        } else {
            break;
        }
    }
    
    return posted;
}

/* =========================================================
 * 异步发送
 * ========================================================= */

int v3_iocp_post_send(v3_iocp_t *iocp, SOCKET socket,
                       const void *data, size_t len,
                       const v3_address_t *dest, void *user_data) {
    if (!iocp || socket == INVALID_SOCKET || !data || len == 0 || !dest) {
        return V3_ERR_INVALID_PARAM;
    }
    
    if (len > V3_IOCP_BUFFER_SIZE) {
        return V3_ERR_BUFFER_TOO_SMALL;
    }
    
    v3_iocp_op_t *op = iocp_alloc_op(iocp);
    if (!op) {
        return V3_ERR_NO_MEMORY;
    }
    
    op->type = V3_IOCP_OP_SEND;
    op->socket = socket;
    op->user_data = user_data;
    
    /* 复制数据到操作缓冲区 */
    memcpy(op->buffer, data, len);
    op->wsabuf.buf = (char*)op->buffer;
    op->wsabuf.len = (ULONG)len;
    
    /* 复制目标地址 */
    memcpy(&op->remote_addr, dest, sizeof(v3_address_t));
    
    DWORD sent = 0;
    
    int result = WSASendTo(
        socket,
        &op->wsabuf,
        1,
        &sent,
        0,
        (struct sockaddr*)&op->remote_addr.storage,
        op->remote_addr.len,
        &op->overlapped,
        NULL
    );
    
    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSA_IO_PENDING) {
            V3_LOG_ERROR("WSASendTo failed: %d", err);
            iocp_free_op(iocp, op);
            InterlockedIncrement64(&iocp->errors);
            return V3_ERR_NETWORK;
        }
    }
    
    return V3_OK;
}

/* =========================================================
 * 回调设置
 * ========================================================= */

void v3_iocp_set_callbacks(v3_iocp_t *iocp,
                            v3_io_callback_fn recv_cb,
                            v3_io_callback_fn send_cb,
                            void *user_data) {
    if (!iocp) return;
    
    iocp->recv_callback = recv_cb;
    iocp->send_callback = send_cb;
    iocp->callback_data = user_data;
}

/* =========================================================
 * 事件处理
 * ========================================================= */

static void iocp_handle_completion(v3_iocp_t *iocp, v3_iocp_op_t *op,
                                    DWORD bytes_transferred, int error) {
    if (!op) return;
    
    v3_iocp_result_t result;
    memset(&result, 0, sizeof(result));
    
    result.type = op->type;
    result.socket = op->socket;
    result.user_data = op->user_data;
    result.error = error;
    result.bytes_transferred = bytes_transferred;
    
    if (op->type == V3_IOCP_OP_RECV) {
        result.data = op->buffer;
        result.data_len = bytes_transferred;
        memcpy(&result.remote_addr, &op->remote_addr, sizeof(v3_address_t));
        result.remote_addr.len = op->remote_addr_len;
        
        if (error == 0 && bytes_transferred > 0) {
            InterlockedIncrement64(&iocp->total_recv);
            InterlockedAdd64(&iocp->bytes_recv, bytes_transferred);
        }
        
        if (iocp->recv_callback) {
            iocp->recv_callback(&result, iocp->callback_data);
        }
    } else if (op->type == V3_IOCP_OP_SEND) {
        if (error == 0) {
            InterlockedIncrement64(&iocp->total_send);
            InterlockedAdd64(&iocp->bytes_send, bytes_transferred);
        }
        
        if (iocp->send_callback) {
            iocp->send_callback(&result, iocp->callback_data);
        }
    }
    
    /* 释放操作 */
    iocp_free_op(iocp, op);
}

int v3_iocp_poll(v3_iocp_t *iocp, DWORD timeout_ms) {
    if (!iocp) return V3_ERR_INVALID_PARAM;
    
    DWORD bytes_transferred;
    ULONG_PTR completion_key;
    OVERLAPPED *overlapped = NULL;
    
    BOOL result = GetQueuedCompletionStatus(
        iocp->handle,
        &bytes_transferred,
        &completion_key,
        &overlapped,
        timeout_ms
    );
    
    if (completion_key == V3_IOCP_SHUTDOWN_KEY) {
        return V3_ERR_SHUTDOWN;
    }
    
    if (!result) {
        DWORD error = GetLastError();
        
        if (error == WAIT_TIMEOUT) {
            return V3_ERR_TIMEOUT;
        }
        
        if (overlapped) {
            /* 操作完成但有错误 */
            v3_iocp_op_t *op = (v3_iocp_op_t*)overlapped;
            iocp_handle_completion(iocp, op, 0, error);
            return V3_OK;
        }
        
        return V3_ERR_NETWORK;
    }
    
    /* 成功完成 */
    if (overlapped) {
        v3_iocp_op_t *op = (v3_iocp_op_t*)overlapped;
        iocp_handle_completion(iocp, op, bytes_transferred, 0);
    }
    
    return V3_OK;
}

int v3_iocp_poll_batch(v3_iocp_t *iocp, int max_events, DWORD timeout_ms) {
    if (!iocp) return V3_ERR_INVALID_PARAM;
    
    OVERLAPPED_ENTRY entries[64];
    ULONG count = (max_events > 64) ? 64 : max_events;
    ULONG removed = 0;
    
    BOOL result = GetQueuedCompletionStatusEx(
        iocp->handle,
        entries,
        count,
        &removed,
        timeout_ms,
        FALSE
    );
    
    if (!result) {
        DWORD error = GetLastError();
        if (error == WAIT_TIMEOUT) {
            return 0;
        }
        return V3_ERR_NETWORK;
    }
    
    for (ULONG i = 0; i < removed; i++) {
        if (entries[i].lpCompletionKey == V3_IOCP_SHUTDOWN_KEY) {
            return V3_ERR_SHUTDOWN;
        }
        
        v3_iocp_op_t *op = (v3_iocp_op_t*)entries[i].lpOverlapped;
        if (op) {
            DWORD bytes = entries[i].dwNumberOfBytesTransferred;
            
            /* 检查是否有错误 */
            DWORD error = 0;
            DWORD flags;
            if (!WSAGetOverlappedResult(op->socket, &op->overlapped, &bytes, FALSE, &flags)) {
                error = WSAGetLastError();
            }
            
            iocp_handle_completion(iocp, op, bytes, error);
        }
    }
    
    return (int)removed;
}

/* =========================================================
 * 工作线程
 * ========================================================= */

static DWORD WINAPI iocp_worker_thread(LPVOID param) {
    v3_iocp_t *iocp = (v3_iocp_t*)param;
    
    V3_LOG_DEBUG("IOCP worker thread started");
    
    while (iocp->running) {
        int result = v3_iocp_poll(iocp, 1000);
        
        if (result == V3_ERR_SHUTDOWN) {
            break;
        }
    }
    
    V3_LOG_DEBUG("IOCP worker thread exiting");
    return 0;
}

int v3_iocp_start_workers(v3_iocp_t *iocp, int thread_count) {
    if (!iocp) return V3_ERR_INVALID_PARAM;
    
    if (thread_count <= 0) {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        thread_count = si.dwNumberOfProcessors * 2;
    }
    
    iocp->worker_threads = (HANDLE*)calloc(thread_count, sizeof(HANDLE));
    if (!iocp->worker_threads) {
        return V3_ERR_NO_MEMORY;
    }
    
    iocp->worker_count = thread_count;
    
    for (int i = 0; i < thread_count; i++) {
        iocp->worker_threads[i] = CreateThread(
            NULL,
            0,
            iocp_worker_thread,
            iocp,
            0,
            NULL
        );
        
        if (iocp->worker_threads[i] == NULL) {
            V3_LOG_ERROR("Failed to create worker thread: %lu", GetLastError());
            return V3_ERR_SYSTEM;
        }
    }
    
    V3_LOG_INFO("Started %d IOCP worker threads", thread_count);
    return V3_OK;
}

void v3_iocp_stop_workers(v3_iocp_t *iocp) {
    if (!iocp || !iocp->worker_threads) return;
    
    iocp->running = false;
    
    /* 发送关闭通知 */
    for (int i = 0; i < iocp->worker_count; i++) {
        PostQueuedCompletionStatus(iocp->handle, 0, V3_IOCP_SHUTDOWN_KEY, NULL);
    }
    
    /* 等待线程退出 */
    WaitForMultipleObjects(iocp->worker_count, iocp->worker_threads, TRUE, 5000);
    
    for (int i = 0; i < iocp->worker_count; i++) {
        if (iocp->worker_threads[i]) {
            CloseHandle(iocp->worker_threads[i]);
        }
    }
    
    free(iocp->worker_threads);
    iocp->worker_threads = NULL;
    iocp->worker_count = 0;
}

/* =========================================================
 * 统计信息
 * ========================================================= */

void v3_iocp_get_stats(v3_iocp_t *iocp, v3_iocp_stats_t *stats) {
    if (!iocp || !stats) return;
    
    stats->total_recv = iocp->total_recv;
    stats->total_send = iocp->total_send;
    stats->bytes_recv = iocp->bytes_recv;
    stats->bytes_send = iocp->bytes_send;
    stats->errors = iocp->errors;
    stats->active_ops = iocp->active_ops;
    stats->pool_size = iocp->pool_size;
}

void v3_iocp_reset_stats(v3_iocp_t *iocp) {
    if (!iocp) return;
    
    InterlockedExchange64(&iocp->total_recv, 0);
    InterlockedExchange64(&iocp->total_send, 0);
    InterlockedExchange64(&iocp->bytes_recv, 0);
    InterlockedExchange64(&iocp->bytes_send, 0);
    InterlockedExchange64(&iocp->errors, 0);
}

/* =========================================================
 * 辅助函数
 * ========================================================= */

HANDLE v3_iocp_get_handle(v3_iocp_t *iocp) {
    return iocp ? iocp->handle : NULL;
}

bool v3_iocp_is_running(v3_iocp_t *iocp) {
    return iocp ? iocp->running : false;
}

int v3_iocp_get_pending_count(v3_iocp_t *iocp) {
    return iocp ? iocp->active_ops : 0;
}

#endif /* _WIN32 */
