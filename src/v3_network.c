
/*
 * v3_network.c - v3 Network Abstraction Layer
 * 
 * 功能：
 * - 网络初始化/清理
 * - 地址解析与转换
 * - 套接字选项管理
 * - 通用收发封装
 * - MTU 检测
 * - 网络状态监控
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#include "v3_network.h"
#include "v3_platform.h"
#include "v3_log.h"
#include "v3_error.h"
#include "v3_buffer.h"

#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

#define V3_NET_DEFAULT_MTU          1500
#define V3_NET_MIN_MTU              576
#define V3_NET_MAX_MTU              9000
#define V3_NET_UDP_OVERHEAD         28      /* IP(20) + UDP(8) */
#define V3_NET_DEFAULT_RECV_BUF     (4 * 1024 * 1024)
#define V3_NET_DEFAULT_SEND_BUF     (4 * 1024 * 1024)

/* =========================================================
 * 全局状态
 * ========================================================= */

static struct {
    bool            initialized;
    v3_net_stats_t  stats;
    uint16_t        detected_mtu;
    v3_mutex_t      stats_lock;
} g_network = {0};

/* =========================================================
 * 平台兼容层
 * ========================================================= */

#ifdef _WIN32

static int v3_net_get_last_error(void) {
    return WSAGetLastError();
}

static const char* v3_net_error_string(int err) {
    static char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, sizeof(buf), NULL);
    return buf;
}

static int v3_net_set_nonblocking(v3_socket_t sock) {
    u_long mode = 1;
    return ioctlsocket(sock, FIONBIO, &mode) == 0 ? V3_OK : V3_ERR_NETWORK;
}

static int v3_net_set_blocking(v3_socket_t sock) {
    u_long mode = 0;
    return ioctlsocket(sock, FIONBIO, &mode) == 0 ? V3_OK : V3_ERR_NETWORK;
}

#else /* POSIX */

static int v3_net_get_last_error(void) {
    return errno;
}

static const char* v3_net_error_string(int err) {
    return strerror(err);
}

static int v3_net_set_nonblocking(v3_socket_t sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return V3_ERR_NETWORK;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0 ? V3_OK : V3_ERR_NETWORK;
}

static int v3_net_set_blocking(v3_socket_t sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) return V3_ERR_NETWORK;
    return fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) == 0 ? V3_OK : V3_ERR_NETWORK;
}

#endif

/* =========================================================
 * 初始化与清理
 * ========================================================= */

int v3_network_init(void) {
    if (g_network.initialized) {
        return V3_OK;
    }

#ifdef _WIN32
    WSADATA wsa_data;
    int result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0) {
        V3_LOG_ERROR("WSAStartup failed: %d", result);
        return V3_ERR_NETWORK;
    }
    
    if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
        V3_LOG_ERROR("Winsock version mismatch");
        WSACleanup();
        return V3_ERR_NETWORK;
    }
#endif

    /* 初始化统计锁 */
    if (v3_mutex_init(&g_network.stats_lock) != V3_OK) {
        V3_LOG_ERROR("Failed to init stats lock");
#ifdef _WIN32
        WSACleanup();
#endif
        return V3_ERR_SYSTEM;
    }

    /* 初始化统计数据 */
    memset(&g_network.stats, 0, sizeof(g_network.stats));
    g_network.detected_mtu = V3_NET_DEFAULT_MTU;
    g_network.initialized = true;

    V3_LOG_INFO("Network layer initialized");
    return V3_OK;
}

void v3_network_cleanup(void) {
    if (!g_network.initialized) {
        return;
    }

    v3_mutex_destroy(&g_network.stats_lock);

#ifdef _WIN32
    WSACleanup();
#endif

    g_network.initialized = false;
    V3_LOG_INFO("Network layer cleaned up");
}

bool v3_network_is_initialized(void) {
    return g_network.initialized;
}

/* =========================================================
 * 套接字创建与配置
 * ========================================================= */

v3_socket_t v3_socket_create(int domain, int type, int protocol) {
    v3_socket_t sock;

#ifdef _WIN32
    sock = WSASocketW(domain, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {
        V3_LOG_ERROR("WSASocket failed: %d", WSAGetLastError());
        return V3_INVALID_SOCKET;
    }
#else
    sock = socket(domain, type, protocol);
    if (sock < 0) {
        V3_LOG_ERROR("socket failed: %s", strerror(errno));
        return V3_INVALID_SOCKET;
    }
#endif

    return sock;
}

int v3_socket_close(v3_socket_t sock) {
    if (sock == V3_INVALID_SOCKET) {
        return V3_OK;
    }

#ifdef _WIN32
    if (closesocket(sock) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }
#else
    if (close(sock) < 0) {
        return V3_ERR_NETWORK;
    }
#endif

    return V3_OK;
}

int v3_socket_set_option(v3_socket_t sock, int level, int optname,
                          const void *optval, int optlen) {
#ifdef _WIN32
    if (setsockopt(sock, level, optname, (const char*)optval, optlen) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }
#else
    if (setsockopt(sock, level, optname, optval, optlen) < 0) {
        return V3_ERR_NETWORK;
    }
#endif
    return V3_OK;
}

int v3_socket_get_option(v3_socket_t sock, int level, int optname,
                          void *optval, int *optlen) {
#ifdef _WIN32
    if (getsockopt(sock, level, optname, (char*)optval, optlen) == SOCKET_ERROR) {
        return V3_ERR_NETWORK;
    }
#else
    socklen_t len = *optlen;
    if (getsockopt(sock, level, optname, optval, &len) < 0) {
        return V3_ERR_NETWORK;
    }
    *optlen = len;
#endif
    return V3_OK;
}

int v3_socket_configure_udp(v3_socket_t sock, const v3_socket_config_t *config) {
    int ret;
    int val;

    /* 设置非阻塞模式 */
    if (config->nonblocking) {
        ret = v3_net_set_nonblocking(sock);
        if (ret != V3_OK) {
            V3_LOG_WARN("Failed to set nonblocking mode");
        }
    }

    /* 地址重用 */
    val = config->reuse_addr ? 1 : 0;
    v3_socket_set_option(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

#ifdef SO_REUSEPORT
    val = config->reuse_port ? 1 : 0;
    v3_socket_set_option(sock, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
#endif

    /* 接收缓冲区 */
    if (config->recv_buffer_size > 0) {
        val = config->recv_buffer_size;
        ret = v3_socket_set_option(sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));
        if (ret != V3_OK) {
            V3_LOG_WARN("Failed to set recv buffer size to %d", val);
        }
    }

    /* 发送缓冲区 */
    if (config->send_buffer_size > 0) {
        val = config->send_buffer_size;
        ret = v3_socket_set_option(sock, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
        if (ret != V3_OK) {
            V3_LOG_WARN("Failed to set send buffer size to %d", val);
        }
    }

#ifdef IP_DONTFRAG
    /* 禁止分片 (Linux) */
    if (config->dont_fragment) {
        val = IP_PMTUDISC_DO;
        v3_socket_set_option(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    }
#endif

#ifdef _WIN32
    /* Windows: 禁止 ICMP 错误触发连接重置 */
    BOOL new_behavior = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior),
             NULL, 0, &bytes_returned, NULL, NULL);
#endif

    return V3_OK;
}

/* =========================================================
 * 地址操作
 * ========================================================= */

int v3_address_parse(const char *str, uint16_t default_port, v3_address_t *addr) {
    if (!str || !addr) {
        return V3_ERR_INVALID_PARAM;
    }

    memset(addr, 0, sizeof(*addr));

    /* 检查是否为 IPv6 */
    if (strchr(str, ':') != NULL && str[0] == '[') {
        /* IPv6 格式: [addr]:port */
        const char *bracket = strchr(str, ']');
        if (!bracket) {
            return V3_ERR_INVALID_PARAM;
        }

        size_t addr_len = bracket - str - 1;
        char addr_buf[INET6_ADDRSTRLEN];
        if (addr_len >= sizeof(addr_buf)) {
            return V3_ERR_INVALID_PARAM;
        }
        memcpy(addr_buf, str + 1, addr_len);
        addr_buf[addr_len] = '\0';

        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&addr->storage;
        sin6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, addr_buf, &sin6->sin6_addr) != 1) {
            return V3_ERR_INVALID_PARAM;
        }

        if (bracket[1] == ':') {
            sin6->sin6_port = htons((uint16_t)atoi(bracket + 2));
        } else {
            sin6->sin6_port = htons(default_port);
        }

        addr->len = sizeof(struct sockaddr_in6);
    } else {
        /* IPv4 格式: addr:port 或 addr */
        char addr_buf[64];
        strncpy(addr_buf, str, sizeof(addr_buf) - 1);
        addr_buf[sizeof(addr_buf) - 1] = '\0';

        char *colon = strrchr(addr_buf, ':');
        uint16_t port = default_port;
        if (colon) {
            *colon = '\0';
            port = (uint16_t)atoi(colon + 1);
        }

        struct sockaddr_in *sin = (struct sockaddr_in*)&addr->storage;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);

        if (inet_pton(AF_INET, addr_buf, &sin->sin_addr) != 1) {
            /* 尝试 DNS 解析 */
            struct addrinfo hints = {0};
            struct addrinfo *res = NULL;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_DGRAM;

            if (getaddrinfo(addr_buf, NULL, &hints, &res) != 0 || !res) {
                return V3_ERR_INVALID_PARAM;
            }

            memcpy(sin, res->ai_addr, res->ai_addrlen);
            sin->sin_port = htons(port);
            freeaddrinfo(res);
        }

        addr->len = sizeof(struct sockaddr_in);
    }

    return V3_OK;
}

int v3_address_to_string(const v3_address_t *addr, char *buf, size_t buflen) {
    if (!addr || !buf || buflen == 0) {
        return V3_ERR_INVALID_PARAM;
    }

    struct sockaddr *sa = (struct sockaddr*)&addr->storage;

    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "%s:%d", ip, ntohs(sin->sin_port));
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, buflen, "[%s]:%d", ip, ntohs(sin6->sin6_port));
    } else {
        strncpy(buf, "<unknown>", buflen);
        return V3_ERR_INVALID_PARAM;
    }

    return V3_OK;
}

bool v3_address_equals(const v3_address_t *a, const v3_address_t *b) {
    if (!a || !b) return false;
    if (a->len != b->len) return false;
    return memcmp(&a->storage, &b->storage, a->len) == 0;
}

uint16_t v3_address_get_port(const v3_address_t *addr) {
    if (!addr) return 0;
    
    struct sockaddr *sa = (struct sockaddr*)&addr->storage;
    if (sa->sa_family == AF_INET) {
        return ntohs(((struct sockaddr_in*)sa)->sin_port);
    } else if (sa->sa_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6*)sa)->sin6_port);
    }
    return 0;
}

/* =========================================================
 * 收发操作
 * ========================================================= */

ssize_t v3_socket_sendto(v3_socket_t sock, const void *buf, size_t len,
                          const v3_address_t *dest) {
    ssize_t sent;

#ifdef _WIN32
    sent = sendto(sock, (const char*)buf, (int)len, 0,
                  (struct sockaddr*)&dest->storage, dest->len);
    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        return V3_ERR_NETWORK;
    }
#else
    sent = sendto(sock, buf, len, 0,
                  (struct sockaddr*)&dest->storage, dest->len);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        return V3_ERR_NETWORK;
    }
#endif

    /* 更新统计 */
    v3_mutex_lock(&g_network.stats_lock);
    g_network.stats.packets_sent++;
    g_network.stats.bytes_sent += sent;
    v3_mutex_unlock(&g_network.stats_lock);

    return sent;
}

ssize_t v3_socket_recvfrom(v3_socket_t sock, void *buf, size_t len,
                            v3_address_t *src) {
    ssize_t received;
    socklen_t src_len = sizeof(src->storage);

#ifdef _WIN32
    received = recvfrom(sock, (char*)buf, (int)len, 0,
                        (struct sockaddr*)&src->storage, (int*)&src_len);
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
#else
    received = recvfrom(sock, buf, len, 0,
                        (struct sockaddr*)&src->storage, &src_len);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return V3_ERR_WOULD_BLOCK;
        }
        return V3_ERR_NETWORK;
    }
#endif

    src->len = src_len;

    /* 更新统计 */
    v3_mutex_lock(&g_network.stats_lock);
    g_network.stats.packets_received++;
    g_network.stats.bytes_received += received;
    v3_mutex_unlock(&g_network.stats_lock);

    return received;
}

int v3_socket_bind(v3_socket_t sock, const v3_address_t *addr) {
#ifdef _WIN32
    if (bind(sock, (struct sockaddr*)&addr->storage, addr->len) == SOCKET_ERROR) {
        V3_LOG_ERROR("bind failed: %d", WSAGetLastError());
        return V3_ERR_NETWORK;
    }
#else
    if (bind(sock, (struct sockaddr*)&addr->storage, addr->len) < 0) {
        V3_LOG_ERROR("bind failed: %s", strerror(errno));
        return V3_ERR_NETWORK;
    }
#endif
    return V3_OK;
}

/* =========================================================
 * MTU 检测
 * ========================================================= */

uint16_t v3_network_detect_mtu(v3_socket_t sock, const v3_address_t *dest) {
    /* 
     * MTU 路径发现简化实现
     * 完整版应该使用 PMTUD 或二分探测
     */
    (void)sock;
    (void)dest;

#ifdef _WIN32
    /* Windows: 尝试获取接口 MTU */
    /* 简化版，直接返回保守值 */
    return 1400;
#else
    /* Linux: 可以尝试读取 /sys/class/net/xxx/mtu */
    return 1400;
#endif
}

uint16_t v3_network_get_mss(uint16_t mtu) {
    /* MSS = MTU - IP头 - UDP头 - v3协议头 */
    uint16_t overhead = V3_NET_UDP_OVERHEAD + 52;  /* v3 header ~52 bytes */
    if (mtu <= overhead) {
        return 1200;  /* 安全默认值 */
    }
    return mtu - overhead;
}

/* =========================================================
 * 统计信息
 * ========================================================= */

void v3_network_get_stats(v3_net_stats_t *stats) {
    if (!stats) return;

    v3_mutex_lock(&g_network.stats_lock);
    memcpy(stats, &g_network.stats, sizeof(*stats));
    v3_mutex_unlock(&g_network.stats_lock);
}

void v3_network_reset_stats(void) {
    v3_mutex_lock(&g_network.stats_lock);
    memset(&g_network.stats, 0, sizeof(g_network.stats));
    v3_mutex_unlock(&g_network.stats_lock);
}

void v3_network_record_error(v3_net_error_type_t type) {
    v3_mutex_lock(&g_network.stats_lock);
    switch (type) {
        case V3_NET_ERR_SEND:
            g_network.stats.send_errors++;
            break;
        case V3_NET_ERR_RECV:
            g_network.stats.recv_errors++;
            break;
        case V3_NET_ERR_TIMEOUT:
            g_network.stats.timeouts++;
            break;
        default:
            break;
    }
    v3_mutex_unlock(&g_network.stats_lock);
}

/* =========================================================
 * 辅助函数
 * ========================================================= */

const char* v3_network_last_error_string(void) {
    return v3_net_error_string(v3_net_get_last_error());
}

int v3_network_last_error_code(void) {
    return v3_net_get_last_error();
}

bool v3_network_is_temporary_error(int err) {
#ifdef _WIN32
    return err == WSAEWOULDBLOCK || err == WSAEINTR || err == WSAEINPROGRESS;
#else
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR || err == EINPROGRESS;
#endif
}
