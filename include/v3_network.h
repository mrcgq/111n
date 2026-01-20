
/**
 * @file v3_network.h
 * @brief v3 Core - 网络抽象层
 * 
 * 提供跨平台的网络 API 封装
 * Windows: Winsock2 + IOCP
 * Linux: BSD Socket + epoll/io_uring
 */

#ifndef V3_NETWORK_H
#define V3_NETWORK_H

#include "v3_types.h"
#include "v3_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================
 * 常量定义
 * ========================================================= */

/* Socket 选项 */
#define V3_SOCK_NONBLOCK        0x0001
#define V3_SOCK_REUSEADDR       0x0002
#define V3_SOCK_REUSEPORT       0x0004
#define V3_SOCK_BROADCAST       0x0008
#define V3_SOCK_NODELAY         0x0010
#define V3_SOCK_KEEPALIVE       0x0020

/* 地址族 */
#define V3_AF_INET              2       /* IPv4 */
#define V3_AF_INET6             23      /* IPv6 (Windows) / 10 (Linux) */

/* Socket 类型 */
#define V3_SOCK_DGRAM           1       /* UDP */
#define V3_SOCK_STREAM          2       /* TCP */

/* 缓冲区大小 */
#define V3_NET_DEFAULT_RCVBUF   (4 * 1024 * 1024)   /* 4MB */
#define V3_NET_DEFAULT_SNDBUF   (4 * 1024 * 1024)   /* 4MB */

/* =========================================================
 * 地址结构
 * ========================================================= */

/**
 * @brief 网络地址
 */
typedef struct v3_address_s {
    u8      family;             /* 地址族 (V3_AF_INET/V3_AF_INET6) */
    u8      _pad[3];
    u16     port;               /* 端口（主机字节序）*/
    union {
        u8      v4[4];          /* IPv4 地址 */
        u8      v6[16];         /* IPv6 地址 */
        u32     v4_u32;         /* IPv4 作为 u32 */
    } addr;
} v3_address_t;

#define V3_ADDRESS_MAX_STR_LEN  64  /* "xxxx:xxxx:...:xxxx:port" */

/* =========================================================
 * 网络模块 API
 * ========================================================= */

/**
 * @brief 初始化网络模块
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_net_init(void);

/**
 * @brief 关闭网络模块
 */
V3_API void v3_net_shutdown(void);

/**
 * @brief 检查网络是否已初始化
 * @return true 已初始化
 */
V3_API bool v3_net_is_initialized(void);

/* =========================================================
 * 地址操作
 * ========================================================= */

/**
 * @brief 初始化 IPv4 地址
 * @param addr 地址结构
 * @param ip IP 地址（点分十进制或 NULL 表示 0.0.0.0）
 * @param port 端口
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_address_init_ipv4(v3_address_t *addr, const char *ip, u16 port);

/**
 * @brief 初始化 IPv6 地址
 * @param addr 地址结构
 * @param ip IP 地址（冒号分隔或 NULL 表示 ::）
 * @param port 端口
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_address_init_ipv6(v3_address_t *addr, const char *ip, u16 port);

/**
 * @brief 从字符串解析地址
 * @param addr 输出地址
 * @param str 地址字符串（如 "1.2.3.4:5678" 或 "[::1]:5678"）
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_address_parse(v3_address_t *addr, const char *str);

/**
 * @brief 地址转字符串
 * @param addr 地址
 * @param buf 输出缓冲区
 * @param buf_size 缓冲区大小
 * @return 写入的字节数
 */
V3_API int v3_address_to_string(const v3_address_t *addr, char *buf, usize buf_size);

/**
 * @brief 比较两个地址
 * @param a 地址 a
 * @param b 地址 b
 * @return 0 相等，非0 不相等
 */
V3_API int v3_address_compare(const v3_address_t *a, const v3_address_t *b);

/**
 * @brief 复制地址
 * @param dst 目标
 * @param src 源
 */
V3_API void v3_address_copy(v3_address_t *dst, const v3_address_t *src);

/**
 * @brief 检查是否为任意地址（0.0.0.0 或 ::）
 * @param addr 地址
 * @return true 是任意地址
 */
V3_API bool v3_address_is_any(const v3_address_t *addr);

/**
 * @brief 检查是否为回环地址
 * @param addr 地址
 * @return true 是回环地址
 */
V3_API bool v3_address_is_loopback(const v3_address_t *addr);

/* =========================================================
 * UDP Socket API
 * ========================================================= */

/**
 * @brief 创建 UDP Socket
 * @param family 地址族 (V3_AF_INET/V3_AF_INET6)
 * @param flags Socket 选项
 * @param sock_out 输出 Socket 句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_udp_create(int family, u32 flags, v3_socket_t *sock_out);

/**
 * @brief 绑定 UDP Socket
 * @param sock Socket 句柄
 * @param addr 绑定地址
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_udp_bind(v3_socket_t sock, const v3_address_t *addr);

/**
 * @brief 发送 UDP 数据
 * @param sock Socket 句柄
 * @param data 数据
 * @param len 长度
 * @param to 目标地址
 * @return 发送的字节数，失败返回负值
 */
V3_API isize v3_udp_sendto(
    v3_socket_t sock,
    const u8 *data,
    usize len,
    const v3_address_t *to
);

/**
 * @brief 接收 UDP 数据
 * @param sock Socket 句柄
 * @param buf 接收缓冲区
 * @param buf_size 缓冲区大小
 * @param from 输出来源地址（可选）
 * @return 接收的字节数，失败返回负值
 */
V3_API isize v3_udp_recvfrom(
    v3_socket_t sock,
    u8 *buf,
    usize buf_size,
    v3_address_t *from
);

/**
 * @brief 关闭 Socket
 * @param sock Socket 句柄
 */
V3_API void v3_socket_close(v3_socket_t sock);

/**
 * @brief 设置 Socket 选项
 * @param sock Socket 句柄
 * @param flags 选项标志
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_socket_set_options(v3_socket_t sock, u32 flags);

/**
 * @brief 设置接收缓冲区大小
 * @param sock Socket 句柄
 * @param size 缓冲区大小
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_socket_set_rcvbuf(v3_socket_t sock, u32 size);

/**
 * @brief 设置发送缓冲区大小
 * @param sock Socket 句柄
 * @param size 缓冲区大小
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_socket_set_sndbuf(v3_socket_t sock, u32 size);

/**
 * @brief 设置非阻塞模式
 * @param sock Socket 句柄
 * @param nonblock 是否非阻塞
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_socket_set_nonblock(v3_socket_t sock, bool nonblock);

/**
 * @brief 获取 Socket 本地地址
 * @param sock Socket 句柄
 * @param addr 输出地址
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_socket_get_local_addr(v3_socket_t sock, v3_address_t *addr);

/* =========================================================
 * IOCP/异步 I/O（Windows 专用）
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS

/**
 * @brief IOCP 上下文
 */
typedef struct v3_iocp_s v3_iocp_t;

/**
 * @brief I/O 操作类型
 */
typedef enum v3_io_op_e {
    V3_IO_OP_READ = 0,
    V3_IO_OP_WRITE,
    V3_IO_OP_ACCEPT,
    V3_IO_OP_CONNECT,
} v3_io_op_t;

/**
 * @brief I/O 完成回调
 */
typedef void (*v3_io_callback_fn)(
    v3_io_op_t op,
    v3_error_t error,
    usize bytes_transferred,
    void *user_data
);

/**
 * @brief 创建 IOCP
 * @param iocp_out 输出 IOCP 句柄
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_iocp_create(v3_iocp_t **iocp_out);

/**
 * @brief 销毁 IOCP
 * @param iocp IOCP 句柄
 */
V3_API void v3_iocp_destroy(v3_iocp_t *iocp);

/**
 * @brief 关联 Socket 到 IOCP
 * @param iocp IOCP 句柄
 * @param sock Socket 句柄
 * @param user_data 用户数据
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_iocp_associate(v3_iocp_t *iocp, v3_socket_t sock, void *user_data);

/**
 * @brief 投递异步接收
 * @param iocp IOCP 句柄
 * @param sock Socket 句柄
 * @param buf 缓冲区
 * @param buf_size 缓冲区大小
 * @param callback 完成回调
 * @param user_data 用户数据
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_iocp_recv(
    v3_iocp_t *iocp,
    v3_socket_t sock,
    u8 *buf,
    usize buf_size,
    v3_io_callback_fn callback,
    void *user_data
);

/**
 * @brief 投递异步发送
 * @param iocp IOCP 句柄
 * @param sock Socket 句柄
 * @param data 数据
 * @param len 长度
 * @param to 目标地址
 * @param callback 完成回调
 * @param user_data 用户数据
 * @return V3_OK 成功
 */
V3_API v3_error_t v3_iocp_sendto(
    v3_iocp_t *iocp,
    v3_socket_t sock,
    const u8 *data,
    usize len,
    const v3_address_t *to,
    v3_io_callback_fn callback,
    void *user_data
);

/**
 * @brief 等待 I/O 完成
 * @param iocp IOCP 句柄
 * @param timeout_ms 超时毫秒数
 * @return 完成的操作数，超时返回 0
 */
V3_API int v3_iocp_poll(v3_iocp_t *iocp, u32 timeout_ms);

#endif /* V3_PLATFORM_WINDOWS */

/* =========================================================
 * 主机名解析
 * ========================================================= */

/**
 * @brief 解析主机名
 * @param hostname 主机名
 * @param port 端口
 * @param addrs 输出地址数组
 * @param max_addrs 数组大小
 * @return 解析到的地址数，失败返回负值
 */
V3_API int v3_resolve_hostname(
    const char *hostname,
    u16 port,
    v3_address_t *addrs,
    int max_addrs
);

/**
 * @brief 获取本机 IP 地址
 * @param addrs 输出地址数组
 * @param max_addrs 数组大小
 * @param include_loopback 是否包含回环地址
 * @return 获取的地址数
 */
V3_API int v3_get_local_addresses(
    v3_address_t *addrs,
    int max_addrs,
    bool include_loopback
);

#ifdef __cplusplus
}
#endif

#endif /* V3_NETWORK_H */
