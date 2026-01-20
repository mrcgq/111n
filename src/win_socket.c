
/*
 * win_socket.c - Windows Socket Wrapper
 * 
 * 功能：
 * - Winsock2 封装
 * - 异步 Socket 支持
 * - UDP/TCP 操作
 * - 连接管理
 * - 选项配置
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#ifdef _WIN32

#include "v3_network.h"
#include "v3_platform.h"
#include "v3_error.h"
#include "v3_log.h"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

/* =========================================================
 * 常量定义
 * ========================================================= */

#define V3_SOCKET_RECV_TIMEOUT_MS   5000
#define V3_SOCKET_SEND_TIMEOUT_MS   5000
#define V3_SOCKET_CONNECT_TIMEOUT   10000

/* =========================================================
 * 扩展函数指针
 * ========================================================= */

static LPFN_CONNECTEX           g_ConnectEx = NULL;
static LPFN_ACCEPTEX            g_AcceptEx = NULL;
static LPFN_GETACCEPTEXSOCKADDRS g_GetAcceptExSockaddrs = NULL;
static LPFN_DISCONNECTEX        g_DisconnectEx = NULL;
static LPFN_TRANSMITFILE        g_TransmitFile = NULL;

/* =========================================================
 * Socket 结构
 * ========================================================= */

struct v3_socket_ctx_s {
    SOCKET          socket;
    int             type;           /* SOCK_DGRAM / SOCK_STREAM */
    int             family;         /* AF_INET / AF_INET6 */
    bool            nonblocking;
    bool            connected;
    bool            bound;
    v3_address_t    local_addr;
    v3_address_t    remote_addr;
    WSAEVENT        event;          /* 用于 WSAEventSelect */
    
    /* 统计 */
    uint64_t        bytes_sent;
    uint64_t        bytes_recv;
    uint64_t        packets_sent;
    uint64_t        packets_recv;
};

/* =========================================================
 * 扩展函数加载
 * ========================================================= */

static int load_extension_functions(SOCKET sock) {
    DWORD bytes;
    GUID guid;

    /* ConnectEx */
    if (!g_ConnectEx) {
        guid = WSAID_CONNECTEX;
        WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &g_ConnectEx, sizeof(g_ConnectEx),
                 &bytes, NULL, NULL);
    }

    /* AcceptEx */
    if (!g_AcceptEx) {
        guid = WSAID_ACCEPTEX;
        WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &g_AcceptEx, sizeof(g_AcceptEx),
                 &bytes, NULL, NULL);
    }

    /* GetAcceptExSockaddrs */
    if (!g_GetAcceptExSockaddrs) {
        guid = WSAID_GETACCEPTEXSOCKADDRS;
        WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &g_GetAcceptExSockaddrs, sizeof(g_GetAcceptExSockaddrs),
                 &bytes, NULL, NULL);
    }

    /* DisconnectEx */
    if (!g_DisconnectEx) {
        guid = WSAID_DISCONNECTEX;
        WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &g_DisconnectEx, sizeof(g_DisconnectEx),
                 &bytes, NULL, NULL);
    }

    /* TransmitFile */
    if (!g_TransmitFile) {
        guid = WSAID_TRANSMITFILE;
        WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guid, sizeof(guid),
                 &g_TransmitFile, sizeof(g_TransmitFile),
                 &bytes, NULL, NULL);
    }

    return V3_OK;
}

/* =========================================================
 * Socket 创建与销毁
 * ========================================================= */

v3_socket_ctx_t* v3_socket_ctx_create(int family, int type, int protocol) {
    v3_socket_ctx_t *ctx = (v3_socket_ctx_t*)calloc(1, sizeof(v3_socket_ctx_t));
    if (!ctx) {
        return NULL;
    }

    ctx->family = family;
    ctx->type = type;

    /* 创建 Socket */
    ctx->socket = WSASocketW(
        family,
        type,
        protocol,
        NULL,
        0,
        WSA_FLAG_OVERLAPPED
    );

    if (ctx->socket == INVALID_SOCKET) {
        V3_LOG_ERROR("WSASocket failed: %d", WSAGetLastError());
        free(ctx);
        return NULL;
    }

    /* 加载扩展函数 */
    load_extension_functions(ctx->socket);

    /* 创建事件对象 */
    ctx->event = WSACreateEvent();
    if (ctx->event == WSA_INVALID_EVENT) {
        closesocket(ctx->socket);
        free(ctx);
        return NULL;
    }

    return ctx;
}

v3_socket_ctx_t* v3_socket_ctx_create_udp(int family) {
    return v3_socket_ctx_create(family, SOCK_DGRAM, IPPROTO_UDP);
}

v3_socket_ctx_t* v3_socket_ctx_create_tcp(int family) {
    return v3_socket_ctx_create(family, SOCK_STREAM, IPPROTO_TCP);
}

void v3_socket_ctx_destroy(v3_socket_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->event != WSA_INVALID_EVENT) {
        WSACloseEvent(ctx->event);
    }

    if (ctx->socket != INVALID_SOCKET) {
        closesocket(ctx->socket);
    }

    free(ctx);
}

SOCKET v3_socket_ctx_get_handle(v3_socket_ctx_t *ctx) {
    return ctx ? ctx->socket : INVALID_SOCKET;
}

/* =========================================================
 * Socket 配置
 * ========================================================= */

int v3_socket_ctx_set_nonblocking(v3_socket_ctx_t *ctx, bool nonblocking) {
    if (!ctx) return V3_ERR_INVALID_PARAM;

    u_long mode = nonblocking ? 1 : 0;
    if (ioctlsocket(ctx->socket, FIONBIO, &mode) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }

    ctx->nonblocking = nonblocking;
    return V3_OK;
}

int v3_socket_ctx_set_reuse_addr(v3_socket_ctx_t *ctx, bool enable) {
    if (!ctx) return V3_ERR_INVALID_PARAM;

    BOOL val = enable ? TRUE : FALSE;
    if (setsockopt(ctx->socket, SOL_SOCKET, SO_REUSEADDR,
                   (const char*)&val, sizeof(val)) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }

    return V3_OK;
}

int v3_socket_ctx_set_buffer_sizes(v3_socket_ctx_t *ctx,
                                    int recv_size, int send_size) {
    if (!ctx) return V3_ERR_INVALID_PARAM;

    if (recv_size > 0) {
        setsockopt(ctx->socket, SOL_SOCKET, SO_RCVBUF,
                   (const char*)&recv_size, sizeof(recv_size));
    }

    if (send_size > 0) {
        setsockopt(ctx->socket, SOL_SOCKET, SO_SNDBUF,
                   (const char*)&send_size, sizeof(send_size));
    }

    return V3_OK;
}

int v3_socket_ctx_set_timeout(v3_socket_ctx_t *ctx,
                               int recv_ms, int send_ms) {
    if (!ctx) return V3_ERR_INVALID_PARAM;

    if (recv_ms > 0) {
        DWORD timeout = recv_ms;
        setsockopt(ctx->socket, SOL_SOCKET, SO_RCVTIMEO,
                   (const char*)&timeout, sizeof(timeout));
    }

    if (send_ms > 0) {
        DWORD timeout = send_ms;
        setsockopt(ctx->socket, SOL_SOCKET, SO_SNDTIMEO,
                   (const char*)&timeout, sizeof(timeout));
    }

    return V3_OK;
}

int v3_socket_ctx_disable_udp_connreset(v3_socket_ctx_t *ctx) {
    if (!ctx || ctx->type != SOCK_DGRAM) {
        return V3_ERR_INVALID_PARAM;
    }

    /* 禁用 ICMP 错误导致的连接重置 */
    BOOL new_behavior = FALSE;
    DWORD bytes_returned = 0;
    
    WSAIoctl(ctx->socket, SIO_UDP_CONNRESET,
             &new_behavior, sizeof(new_behavior),
             NULL, 0, &bytes_returned, NULL, NULL);

    return V3_OK;
}

int v3_socket_ctx_enable_broadcast(v3_socket_ctx_t *ctx) {
    if (!ctx || ctx->type != SOCK_DGRAM) {
        return V3_ERR_INVALID_PARAM;
    }

    BOOL val = TRUE;
    if (setsockopt(ctx->socket, SOL_SOCKET, SO_BROADCAST,
                   (const char*)&val, sizeof(val)) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }

    return V3_OK;
}

/* =========================================================
 * 绑定与连接
 * ========================================================= */

int v3_socket_ctx_bind(v3_socket_ctx_t *ctx, const v3_address_t *addr) {
    if (!ctx || !addr) return V3_ERR_INVALID_PARAM;

    if (bind(ctx->socket, (struct sockaddr*)&addr->storage, addr->len) == SOCKET_ERROR) {
        V3_LOG_ERROR("bind failed: %d", WSAGetLastError());
        return V3_ERR_NETWORK;
    }

    memcpy(&ctx->local_addr, addr, sizeof(v3_address_t));
    ctx->bound = true;

    return V3_OK;
}

int v3_socket_ctx_bind_any(v3_socket_ctx_t *ctx, uint16_t port) {
    v3_address_t addr;
    memset(&addr, 0, sizeof(addr));

    if (ctx->family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&addr.storage;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        sin6->sin6_addr = in6addr_any;
        addr.len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in*)&addr.storage;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        sin->sin_addr.s_addr = INADDR_ANY;
        addr.len = sizeof(struct sockaddr_in);
    }

    return v3_socket_ctx_bind(ctx, &addr);
}

int v3_socket_ctx_connect(v3_socket_ctx_t *ctx, const v3_address_t *addr) {
    if (!ctx || !addr) return V3_ERR_INVALID_PARAM;

    if (connect(ctx->socket, (struct sockaddr*)&addr->storage, addr->len) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        V3_LOG_ERROR("connect failed: %d", err);
        return V3_ERR_NETWORK;
    }

    memcpy(&ctx->remote_addr, addr, sizeof(v3_address_t));
    ctx->connected = true;

    return V3_OK;
}

int v3_socket_ctx_connect_async(v3_socket_ctx_t *ctx, const v3_address_t *addr,
                                 OVERLAPPED *overlapped) {
    if (!ctx || !addr || !overlapped || !g_ConnectEx) {
        return V3_ERR_INVALID_PARAM;
    }

    /* ConnectEx 需要先绑定 */
    if (!ctx->bound) {
        int ret = v3_socket_ctx_bind_any(ctx, 0);
        if (ret != V3_OK) return ret;
    }

    BOOL result = g_ConnectEx(
        ctx->socket,
        (struct sockaddr*)&addr->storage,
        addr->len,
        NULL, 0, NULL,
        overlapped
    );

    if (!result) {
        int err = WSAGetLastError();
        if (err == ERROR_IO_PENDING) {
            return V3_ERR_PENDING;
        }
        return V3_ERR_NETWORK;
    }

    memcpy(&ctx->remote_addr, addr, sizeof(v3_address_t));
    ctx->connected = true;

    return V3_OK;
}

/* =========================================================
 * 发送操作
 * ========================================================= */

ssize_t v3_socket_ctx_send(v3_socket_ctx_t *ctx, const void *data, size_t len) {
    if (!ctx || !data || len == 0) return V3_ERR_INVALID_PARAM;

    int sent = send(ctx->socket, (const char*)data, (int)len, 0);
    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        return V3_ERR_NETWORK;
    }

    ctx->bytes_sent += sent;
    ctx->packets_sent++;

    return sent;
}

ssize_t v3_socket_ctx_sendto(v3_socket_ctx_t *ctx, const void *data, size_t len,
                              const v3_address_t *dest) {
    if (!ctx || !data || len == 0 || !dest) return V3_ERR_INVALID_PARAM;

    int sent = sendto(ctx->socket, (const char*)data, (int)len, 0,
                      (struct sockaddr*)&dest->storage, dest->len);
    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        return V3_ERR_NETWORK;
    }

    ctx->bytes_sent += sent;
    ctx->packets_sent++;

    return sent;
}

int v3_socket_ctx_sendto_async(v3_socket_ctx_t *ctx, WSABUF *buffers, DWORD count,
                                const v3_address_t *dest, OVERLAPPED *overlapped) {
    if (!ctx || !buffers || count == 0 || !dest || !overlapped) {
        return V3_ERR_INVALID_PARAM;
    }

    DWORD sent = 0;
    int result = WSASendTo(
        ctx->socket,
        buffers,
        count,
        &sent,
        0,
        (struct sockaddr*)&dest->storage,
        dest->len,
        overlapped,
        NULL
    );

    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            return V3_ERR_PENDING;
        }
        return V3_ERR_NETWORK;
    }

    return V3_OK;
}

/* =========================================================
 * 接收操作
 * ========================================================= */

ssize_t v3_socket_ctx_recv(v3_socket_ctx_t *ctx, void *buf, size_t len) {
    if (!ctx || !buf || len == 0) return V3_ERR_INVALID_PARAM;

    int received = recv(ctx->socket, (char*)buf, (int)len, 0);
    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        if (err == WSAECONNRESET) {
            return V3_ERR_DISCONNECTED;
        }
        return V3_ERR_NETWORK;
    }

    if (received == 0) {
        return V3_ERR_DISCONNECTED;
    }

    ctx->bytes_recv += received;
    ctx->packets_recv++;

    return received;
}

ssize_t v3_socket_ctx_recvfrom(v3_socket_ctx_t *ctx, void *buf, size_t len,
                                v3_address_t *src) {
    if (!ctx || !buf || len == 0) return V3_ERR_INVALID_PARAM;

    struct sockaddr_storage addr;
    int addr_len = sizeof(addr);

    int received = recvfrom(ctx->socket, (char*)buf, (int)len, 0,
                            (struct sockaddr*)&addr, &addr_len);
    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        if (err == WSAECONNRESET) {
            /* UDP ICMP 错误，忽略 */
            return V3_ERR_WOULD_BLOCK;
        }
        return V3_ERR_NETWORK;
    }

    if (src) {
        memcpy(&src->storage, &addr, addr_len);
        src->len = addr_len;
    }

    ctx->bytes_recv += received;
    ctx->packets_recv++;

    return received;
}

int v3_socket_ctx_recvfrom_async(v3_socket_ctx_t *ctx, WSABUF *buffers, DWORD count,
                                  v3_address_t *src, OVERLAPPED *overlapped) {
    if (!ctx || !buffers || count == 0 || !overlapped) {
        return V3_ERR_INVALID_PARAM;
    }

    DWORD received = 0;
    DWORD flags = 0;
    int src_len = src ? sizeof(src->storage) : 0;

    int result = WSARecvFrom(
        ctx->socket,
        buffers,
        count,
        &received,
        &flags,
        src ? (struct sockaddr*)&src->storage : NULL,
        src ? &src_len : NULL,
        overlapped,
        NULL
    );

    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSA_IO_PENDING) {
            return V3_ERR_PENDING;
        }
        return V3_ERR_NETWORK;
    }

    if (src) {
        src->len = src_len;
    }

    return V3_OK;
}

/* =========================================================
 * 事件操作
 * ========================================================= */

int v3_socket_ctx_select_events(v3_socket_ctx_t *ctx, long events) {
    if (!ctx) return V3_ERR_INVALID_PARAM;

    if (WSAEventSelect(ctx->socket, ctx->event, events) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }

    return V3_OK;
}

int v3_socket_ctx_wait_event(v3_socket_ctx_t *ctx, DWORD timeout_ms,
                              WSANETWORKEVENTS *events) {
    if (!ctx || !events) return V3_ERR_INVALID_PARAM;

    DWORD result = WSAWaitForMultipleEvents(1, &ctx->event, FALSE, timeout_ms, FALSE);
    
    if (result == WSA_WAIT_TIMEOUT) {
        return V3_ERR_TIMEOUT;
    }
    
    if (result == WSA_WAIT_FAILED) {
        return V3_ERR_NETWORK;
    }

    if (WSAEnumNetworkEvents(ctx->socket, ctx->event, events) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }

    return V3_OK;
}

WSAEVENT v3_socket_ctx_get_event(v3_socket_ctx_t *ctx) {
    return ctx ? ctx->event : WSA_INVALID_EVENT;
}

/* =========================================================
 * 状态查询
 * ========================================================= */

bool v3_socket_ctx_is_connected(v3_socket_ctx_t *ctx) {
    return ctx ? ctx->connected : false;
}

bool v3_socket_ctx_is_bound(v3_socket_ctx_t *ctx) {
    return ctx ? ctx->bound : false;
}

int v3_socket_ctx_get_local_addr(v3_socket_ctx_t *ctx, v3_address_t *addr) {
    if (!ctx || !addr) return V3_ERR_INVALID_PARAM;

    socklen_t len = sizeof(addr->storage);
    if (getsockname(ctx->socket, (struct sockaddr*)&addr->storage, &len) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }
    addr->len = len;

    return V3_OK;
}

int v3_socket_ctx_get_remote_addr(v3_socket_ctx_t *ctx, v3_address_t *addr) {
    if (!ctx || !addr) return V3_ERR_INVALID_PARAM;

    if (!ctx->connected) {
        return V3_ERR_NOT_CONNECTED;
    }

    memcpy(addr, &ctx->remote_addr, sizeof(v3_address_t));
    return V3_OK;
}

void v3_socket_ctx_get_stats(v3_socket_ctx_t *ctx, v3_socket_stats_t *stats) {
    if (!ctx || !stats) return;

    stats->bytes_sent = ctx->bytes_sent;
    stats->bytes_recv = ctx->bytes_recv;
    stats->packets_sent = ctx->packets_sent;
    stats->packets_recv = ctx->packets_recv;
}

/* =========================================================
 * 多播支持
 * ========================================================= */

int v3_socket_ctx_join_multicast(v3_socket_ctx_t *ctx, const char *group,
                                  const char *iface) {
    if (!ctx || !group) return V3_ERR_INVALID_PARAM;

    if (ctx->family == AF_INET) {
        struct ip_mreq mreq;
        inet_pton(AF_INET, group, &mreq.imr_multiaddr);
        
        if (iface) {
            inet_pton(AF_INET, iface, &mreq.imr_interface);
        } else {
            mreq.imr_interface.s_addr = INADDR_ANY;
        }

        if (setsockopt(ctx->socket, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                       (const char*)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            return V3_ERR_NETWORK;
        }
    } else {
        struct ipv6_mreq mreq;
        inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = 0;

        if (setsockopt(ctx->socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                       (const char*)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            return V3_ERR_NETWORK;
        }
    }

    return V3_OK;
}

int v3_socket_ctx_leave_multicast(v3_socket_ctx_t *ctx, const char *group) {
    if (!ctx || !group) return V3_ERR_INVALID_PARAM;

    if (ctx->family == AF_INET) {
        struct ip_mreq mreq;
        inet_pton(AF_INET, group, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;

        setsockopt(ctx->socket, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                   (const char*)&mreq, sizeof(mreq));
    } else {
        struct ipv6_mreq mreq;
        inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr);
        mreq.ipv6mr_interface = 0;

        setsockopt(ctx->socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                   (const char*)&mreq, sizeof(mreq));
    }

    return V3_OK;
}

#endif /* _WIN32 */
