
/**
 * @file v3_error.h
 * @brief v3 Core - 错误码定义
 * 
 * 统一的错误码系统，便于调试和日志记录
 */

#ifndef V3_ERROR_H
#define V3_ERROR_H

#include "v3_types.h"

/* =========================================================
 * 错误码分类
 * 
 * 格式: 0xCCNNNNNN
 *   CC = 类别 (00-FF)
 *   NNNNNN = 序号 (000000-FFFFFF)
 * 
 * 类别:
 *   0x00 = 成功/通用
 *   0x01 = 系统错误
 *   0x02 = 内存错误
 *   0x03 = 网络错误
 *   0x04 = 协议错误
 *   0x05 = 加密错误
 *   0x06 = FEC 错误
 *   0x07 = 配置错误
 *   0x08 = IPC 错误
 *   0x09 = 连接错误
 *   0x0A = 文件/IO 错误
 * ========================================================= */

typedef s32 v3_error_t;

/* 错误码构造宏 */
#define V3_MAKE_ERROR(category, code)   ((v3_error_t)(((category) << 24) | ((code) & 0x00FFFFFF)))
#define V3_ERROR_CATEGORY(err)          (((err) >> 24) & 0xFF)
#define V3_ERROR_CODE(err)              ((err) & 0x00FFFFFF)

/* =========================================================
 * 成功/通用 (0x00)
 * ========================================================= */

#define V3_OK                           0                           /* 成功 */
#define V3_SUCCESS                      V3_OK
#define V3_ERR_UNKNOWN                  V3_MAKE_ERROR(0x00, 0x0001) /* 未知错误 */
#define V3_ERR_NOT_IMPLEMENTED          V3_MAKE_ERROR(0x00, 0x0002) /* 未实现 */
#define V3_ERR_INVALID_PARAM            V3_MAKE_ERROR(0x00, 0x0003) /* 无效参数 */
#define V3_ERR_NULL_POINTER             V3_MAKE_ERROR(0x00, 0x0004) /* 空指针 */
#define V3_ERR_INVALID_STATE            V3_MAKE_ERROR(0x00, 0x0005) /* 无效状态 */
#define V3_ERR_TIMEOUT                  V3_MAKE_ERROR(0x00, 0x0006) /* 超时 */
#define V3_ERR_BUSY                     V3_MAKE_ERROR(0x00, 0x0007) /* 繁忙 */
#define V3_ERR_CANCELLED                V3_MAKE_ERROR(0x00, 0x0008) /* 已取消 */
#define V3_ERR_ALREADY_EXISTS           V3_MAKE_ERROR(0x00, 0x0009) /* 已存在 */
#define V3_ERR_NOT_FOUND                V3_MAKE_ERROR(0x00, 0x000A) /* 未找到 */
#define V3_ERR_PERMISSION_DENIED        V3_MAKE_ERROR(0x00, 0x000B) /* 权限拒绝 */
#define V3_ERR_BUFFER_TOO_SMALL         V3_MAKE_ERROR(0x00, 0x000C) /* 缓冲区太小 */
#define V3_ERR_BUFFER_FULL              V3_MAKE_ERROR(0x00, 0x000D) /* 缓冲区已满 */
#define V3_ERR_EMPTY                    V3_MAKE_ERROR(0x00, 0x000E) /* 为空 */
#define V3_ERR_OVERFLOW                 V3_MAKE_ERROR(0x00, 0x000F) /* 溢出 */
#define V3_ERR_UNDERFLOW                V3_MAKE_ERROR(0x00, 0x0010) /* 下溢 */
#define V3_ERR_AGAIN                    V3_MAKE_ERROR(0x00, 0x0011) /* 重试 */
#define V3_ERR_WOULD_BLOCK              V3_MAKE_ERROR(0x00, 0x0012) /* 会阻塞 */
#define V3_ERR_INTERRUPTED              V3_MAKE_ERROR(0x00, 0x0013) /* 被中断 */

/* =========================================================
 * 系统错误 (0x01)
 * ========================================================= */

#define V3_ERR_SYS_UNKNOWN              V3_MAKE_ERROR(0x01, 0x0001) /* 系统未知错误 */
#define V3_ERR_SYS_INIT_FAILED          V3_MAKE_ERROR(0x01, 0x0002) /* 系统初始化失败 */
#define V3_ERR_SYS_SHUTDOWN_FAILED      V3_MAKE_ERROR(0x01, 0x0003) /* 系统关闭失败 */
#define V3_ERR_SYS_THREAD_CREATE        V3_MAKE_ERROR(0x01, 0x0004) /* 线程创建失败 */
#define V3_ERR_SYS_THREAD_JOIN          V3_MAKE_ERROR(0x01, 0x0005) /* 线程加入失败 */
#define V3_ERR_SYS_MUTEX_CREATE         V3_MAKE_ERROR(0x01, 0x0006) /* 互斥锁创建失败 */
#define V3_ERR_SYS_MUTEX_LOCK           V3_MAKE_ERROR(0x01, 0x0007) /* 互斥锁加锁失败 */
#define V3_ERR_SYS_EVENT_CREATE         V3_MAKE_ERROR(0x01, 0x0008) /* 事件创建失败 */
#define V3_ERR_SYS_PROCESS_CREATE       V3_MAKE_ERROR(0x01, 0x0009) /* 进程创建失败 */
#define V3_ERR_SYS_SIGNAL               V3_MAKE_ERROR(0x01, 0x000A) /* 信号处理错误 */
#define V3_ERR_SYS_RESOURCE_LIMIT       V3_MAKE_ERROR(0x01, 0x000B) /* 资源限制 */

/* =========================================================
 * 内存错误 (0x02)
 * ========================================================= */

#define V3_ERR_MEM_ALLOC_FAILED         V3_MAKE_ERROR(0x02, 0x0001) /* 内存分配失败 */
#define V3_ERR_MEM_REALLOC_FAILED       V3_MAKE_ERROR(0x02, 0x0002) /* 内存重分配失败 */
#define V3_ERR_MEM_POOL_EXHAUSTED       V3_MAKE_ERROR(0x02, 0x0003) /* 内存池耗尽 */
#define V3_ERR_MEM_ALIGNMENT            V3_MAKE_ERROR(0x02, 0x0004) /* 内存对齐错误 */
#define V3_ERR_MEM_CORRUPTION           V3_MAKE_ERROR(0x02, 0x0005) /* 内存损坏 */
#define V3_ERR_MEM_DOUBLE_FREE          V3_MAKE_ERROR(0x02, 0x0006) /* 重复释放 */
#define V3_ERR_MEM_USE_AFTER_FREE       V3_MAKE_ERROR(0x02, 0x0007) /* 释放后使用 */
#define V3_ERR_MEM_LEAK                 V3_MAKE_ERROR(0x02, 0x0008) /* 内存泄漏 */

/* =========================================================
 * 网络错误 (0x03)
 * ========================================================= */

#define V3_ERR_NET_INIT_FAILED          V3_MAKE_ERROR(0x03, 0x0001) /* 网络初始化失败 */
#define V3_ERR_NET_SOCKET_CREATE        V3_MAKE_ERROR(0x03, 0x0002) /* Socket创建失败 */
#define V3_ERR_NET_SOCKET_BIND          V3_MAKE_ERROR(0x03, 0x0003) /* Socket绑定失败 */
#define V3_ERR_NET_SOCKET_LISTEN        V3_MAKE_ERROR(0x03, 0x0004) /* Socket监听失败 */
#define V3_ERR_NET_SOCKET_CONNECT       V3_MAKE_ERROR(0x03, 0x0005) /* Socket连接失败 */
#define V3_ERR_NET_SOCKET_ACCEPT        V3_MAKE_ERROR(0x03, 0x0006) /* Socket接受失败 */
#define V3_ERR_NET_SOCKET_SEND          V3_MAKE_ERROR(0x03, 0x0007) /* Socket发送失败 */
#define V3_ERR_NET_SOCKET_RECV          V3_MAKE_ERROR(0x03, 0x0008) /* Socket接收失败 */
#define V3_ERR_NET_SOCKET_CLOSE         V3_MAKE_ERROR(0x03, 0x0009) /* Socket关闭失败 */
#define V3_ERR_NET_SOCKET_OPTION        V3_MAKE_ERROR(0x03, 0x000A) /* Socket选项失败 */
#define V3_ERR_NET_ADDRESS_INVALID      V3_MAKE_ERROR(0x03, 0x000B) /* 无效地址 */
#define V3_ERR_NET_ADDRESS_RESOLVE      V3_MAKE_ERROR(0x03, 0x000C) /* 地址解析失败 */
#define V3_ERR_NET_UNREACHABLE          V3_MAKE_ERROR(0x03, 0x000D) /* 网络不可达 */
#define V3_ERR_NET_HOST_UNREACHABLE     V3_MAKE_ERROR(0x03, 0x000E) /* 主机不可达 */
#define V3_ERR_NET_PORT_IN_USE          V3_MAKE_ERROR(0x03, 0x000F) /* 端口已被占用 */
#define V3_ERR_NET_CONNECTION_RESET     V3_MAKE_ERROR(0x03, 0x0010) /* 连接被重置 */
#define V3_ERR_NET_CONNECTION_REFUSED   V3_MAKE_ERROR(0x03, 0x0011) /* 连接被拒绝 */
#define V3_ERR_NET_CONNECTION_CLOSED    V3_MAKE_ERROR(0x03, 0x0012) /* 连接已关闭 */
#define V3_ERR_NET_IOCP_CREATE          V3_MAKE_ERROR(0x03, 0x0013) /* IOCP创建失败 */
#define V3_ERR_NET_IOCP_ASSOCIATE       V3_MAKE_ERROR(0x03, 0x0014) /* IOCP关联失败 */
#define V3_ERR_NET_IOCP_POST            V3_MAKE_ERROR(0x03, 0x0015) /* IOCP投递失败 */

/* =========================================================
 * 协议错误 (0x04)
 * ========================================================= */

#define V3_ERR_PROTO_INVALID_MAGIC      V3_MAKE_ERROR(0x04, 0x0001) /* 无效Magic */
#define V3_ERR_PROTO_INVALID_HEADER     V3_MAKE_ERROR(0x04, 0x0002) /* 无效协议头 */
#define V3_ERR_PROTO_INVALID_VERSION    V3_MAKE_ERROR(0x04, 0x0003) /* 无效版本 */
#define V3_ERR_PROTO_INVALID_LENGTH     V3_MAKE_ERROR(0x04, 0x0004) /* 无效长度 */
#define V3_ERR_PROTO_PACKET_TOO_SHORT   V3_MAKE_ERROR(0x04, 0x0005) /* 包太短 */
#define V3_ERR_PROTO_PACKET_TOO_LONG    V3_MAKE_ERROR(0x04, 0x0006) /* 包太长 */
#define V3_ERR_PROTO_INVALID_SESSION    V3_MAKE_ERROR(0x04, 0x0007) /* 无效会话 */
#define V3_ERR_PROTO_SESSION_EXPIRED    V3_MAKE_ERROR(0x04, 0x0008) /* 会话过期 */
#define V3_ERR_PROTO_REPLAY_DETECTED    V3_MAKE_ERROR(0x04, 0x0009) /* 检测到重放 */
#define V3_ERR_PROTO_INVALID_INTENT     V3_MAKE_ERROR(0x04, 0x000A) /* 无效Intent */
#define V3_ERR_PROTO_INVALID_STREAM     V3_MAKE_ERROR(0x04, 0x000B) /* 无效Stream */
#define V3_ERR_PROTO_MALFORMED          V3_MAKE_ERROR(0x04, 0x000C) /* 格式错误 */
#define V3_ERR_PROTO_UNSUPPORTED        V3_MAKE_ERROR(0x04, 0x000D) /* 不支持的协议 */

/* =========================================================
 * 加密错误 (0x05)
 * ========================================================= */

#define V3_ERR_CRYPTO_INIT_FAILED       V3_MAKE_ERROR(0x05, 0x0001) /* 加密初始化失败 */
#define V3_ERR_CRYPTO_INVALID_KEY       V3_MAKE_ERROR(0x05, 0x0002) /* 无效密钥 */
#define V3_ERR_CRYPTO_INVALID_NONCE     V3_MAKE_ERROR(0x05, 0x0003) /* 无效Nonce */
#define V3_ERR_CRYPTO_ENCRYPT_FAILED    V3_MAKE_ERROR(0x05, 0x0004) /* 加密失败 */
#define V3_ERR_CRYPTO_DECRYPT_FAILED    V3_MAKE_ERROR(0x05, 0x0005) /* 解密失败 */
#define V3_ERR_CRYPTO_AUTH_FAILED       V3_MAKE_ERROR(0x05, 0x0006) /* 认证失败 */
#define V3_ERR_CRYPTO_TAG_MISMATCH      V3_MAKE_ERROR(0x05, 0x0007) /* Tag不匹配 */
#define V3_ERR_CRYPTO_RNG_FAILED        V3_MAKE_ERROR(0x05, 0x0008) /* 随机数生成失败 */
#define V3_ERR_CRYPTO_HASH_FAILED       V3_MAKE_ERROR(0x05, 0x0009) /* 哈希计算失败 */
#define V3_ERR_CRYPTO_KEY_DERIVE        V3_MAKE_ERROR(0x05, 0x000A) /* 密钥派生失败 */

/* =========================================================
 * FEC 错误 (0x06)
 * ========================================================= */

#define V3_ERR_FEC_INIT_FAILED          V3_MAKE_ERROR(0x06, 0x0001) /* FEC初始化失败 */
#define V3_ERR_FEC_ENCODE_FAILED        V3_MAKE_ERROR(0x06, 0x0002) /* FEC编码失败 */
#define V3_ERR_FEC_DECODE_FAILED        V3_MAKE_ERROR(0x06, 0x0003) /* FEC解码失败 */
#define V3_ERR_FEC_TOO_MANY_LOSSES      V3_MAKE_ERROR(0x06, 0x0004) /* 丢失太多分片 */
#define V3_ERR_FEC_INVALID_SHARD        V3_MAKE_ERROR(0x06, 0x0005) /* 无效分片 */
#define V3_ERR_FEC_SHARD_MISMATCH       V3_MAKE_ERROR(0x06, 0x0006) /* 分片不匹配 */
#define V3_ERR_FEC_GROUP_INCOMPLETE     V3_MAKE_ERROR(0x06, 0x0007) /* 组不完整 */
#define V3_ERR_FEC_MATRIX_SINGULAR      V3_MAKE_ERROR(0x06, 0x0008) /* 矩阵奇异 */
#define V3_ERR_FEC_CACHE_FULL           V3_MAKE_ERROR(0x06, 0x0009) /* 缓存已满 */

/* =========================================================
 * 配置错误 (0x07)
 * ========================================================= */

#define V3_ERR_CONFIG_LOAD_FAILED       V3_MAKE_ERROR(0x07, 0x0001) /* 配置加载失败 */
#define V3_ERR_CONFIG_SAVE_FAILED       V3_MAKE_ERROR(0x07, 0x0002) /* 配置保存失败 */
#define V3_ERR_CONFIG_PARSE_FAILED      V3_MAKE_ERROR(0x07, 0x0003) /* 配置解析失败 */
#define V3_ERR_CONFIG_INVALID_VALUE     V3_MAKE_ERROR(0x07, 0x0004) /* 无效配置值 */
#define V3_ERR_CONFIG_MISSING_KEY       V3_MAKE_ERROR(0x07, 0x0005) /* 缺少配置项 */
#define V3_ERR_CONFIG_TYPE_MISMATCH     V3_MAKE_ERROR(0x07, 0x0006) /* 配置类型不匹配 */
#define V3_ERR_CONFIG_FILE_NOT_FOUND    V3_MAKE_ERROR(0x07, 0x0007) /* 配置文件未找到 */
#define V3_ERR_CONFIG_READ_ONLY         V3_MAKE_ERROR(0x07, 0x0008) /* 配置只读 */

/* =========================================================
 * IPC 错误 (0x08)
 * ========================================================= */

#define V3_ERR_IPC_INIT_FAILED          V3_MAKE_ERROR(0x08, 0x0001) /* IPC初始化失败 */
#define V3_ERR_IPC_CREATE_PIPE          V3_MAKE_ERROR(0x08, 0x0002) /* 创建管道失败 */
#define V3_ERR_IPC_CONNECT_FAILED       V3_MAKE_ERROR(0x08, 0x0003) /* IPC连接失败 */
#define V3_ERR_IPC_SEND_FAILED          V3_MAKE_ERROR(0x08, 0x0004) /* IPC发送失败 */
#define V3_ERR_IPC_RECV_FAILED          V3_MAKE_ERROR(0x08, 0x0005) /* IPC接收失败 */
#define V3_ERR_IPC_DISCONNECTED         V3_MAKE_ERROR(0x08, 0x0006) /* IPC断开连接 */
#define V3_ERR_IPC_INVALID_MESSAGE      V3_MAKE_ERROR(0x08, 0x0007) /* 无效IPC消息 */
#define V3_ERR_IPC_QUEUE_FULL           V3_MAKE_ERROR(0x08, 0x0008) /* IPC队列已满 */

/* =========================================================
 * 连接错误 (0x09)
 * ========================================================= */

#define V3_ERR_CONN_LIMIT_REACHED       V3_MAKE_ERROR(0x09, 0x0001) /* 达到连接限制 */
#define V3_ERR_CONN_ALREADY_EXISTS      V3_MAKE_ERROR(0x09, 0x0002) /* 连接已存在 */
#define V3_ERR_CONN_NOT_FOUND           V3_MAKE_ERROR(0x09, 0x0003) /* 连接未找到 */
#define V3_ERR_CONN_CLOSED              V3_MAKE_ERROR(0x09, 0x0004) /* 连接已关闭 */
#define V3_ERR_CONN_TIMEOUT             V3_MAKE_ERROR(0x09, 0x0005) /* 连接超时 */
#define V3_ERR_CONN_HANDSHAKE_FAILED    V3_MAKE_ERROR(0x09, 0x0006) /* 握手失败 */
#define V3_ERR_CONN_RATE_LIMITED        V3_MAKE_ERROR(0x09, 0x0007) /* 被限速 */
#define V3_ERR_CONN_BLACKLISTED         V3_MAKE_ERROR(0x09, 0x0008) /* 被拉黑 */

/* =========================================================
 * 文件/IO 错误 (0x0A)
 * ========================================================= */

#define V3_ERR_IO_OPEN_FAILED           V3_MAKE_ERROR(0x0A, 0x0001) /* 打开失败 */
#define V3_ERR_IO_READ_FAILED           V3_MAKE_ERROR(0x0A, 0x0002) /* 读取失败 */
#define V3_ERR_IO_WRITE_FAILED          V3_MAKE_ERROR(0x0A, 0x0003) /* 写入失败 */
#define V3_ERR_IO_SEEK_FAILED           V3_MAKE_ERROR(0x0A, 0x0004) /* 定位失败 */
#define V3_ERR_IO_CLOSE_FAILED          V3_MAKE_ERROR(0x0A, 0x0005) /* 关闭失败 */
#define V3_ERR_IO_FILE_NOT_FOUND        V3_MAKE_ERROR(0x0A, 0x0006) /* 文件未找到 */
#define V3_ERR_IO_FILE_EXISTS           V3_MAKE_ERROR(0x0A, 0x0007) /* 文件已存在 */
#define V3_ERR_IO_PERMISSION_DENIED     V3_MAKE_ERROR(0x0A, 0x0008) /* 权限拒绝 */
#define V3_ERR_IO_DISK_FULL             V3_MAKE_ERROR(0x0A, 0x0009) /* 磁盘已满 */
#define V3_ERR_IO_EOF                   V3_MAKE_ERROR(0x0A, 0x000A) /* 文件结束 */

/* =========================================================
 * 错误处理函数
 * ========================================================= */

/**
 * @brief 检查是否成功
 */
#define V3_IS_OK(err)       ((err) == V3_OK)
#define V3_IS_ERROR(err)    ((err) != V3_OK)

/**
 * @brief 错误传播宏
 */
#define V3_TRY(expr)        do { v3_error_t _err = (expr); if (V3_IS_ERROR(_err)) return _err; } while(0)

/**
 * @brief 错误传播并跳转
 */
#define V3_TRY_GOTO(expr, label) do { err = (expr); if (V3_IS_ERROR(err)) goto label; } while(0)

/**
 * @brief 获取错误描述字符串
 * @param err 错误码
 * @return 错误描述字符串
 */
V3_API const char* v3_error_str(v3_error_t err);

/**
 * @brief 获取错误类别名称
 * @param err 错误码
 * @return 类别名称字符串
 */
V3_API const char* v3_error_category_str(v3_error_t err);

/**
 * @brief 将系统错误码转换为 v3 错误码
 * @param sys_err 系统错误码（errno 或 GetLastError()）
 * @return v3 错误码
 */
V3_API v3_error_t v3_error_from_system(int sys_err);

/**
 * @brief 获取最后一个系统错误的 v3 表示
 * @return v3 错误码
 */
V3_API v3_error_t v3_error_last_system(void);

/**
 * @brief 设置线程局部错误信息
 * @param err 错误码
 * @param msg 错误消息（可选）
 */
V3_API void v3_error_set(v3_error_t err, const char *msg);

/**
 * @brief 获取线程局部错误信息
 * @param msg_out 输出错误消息的缓冲区（可选）
 * @param msg_size 缓冲区大小
 * @return 最后一个错误码
 */
V3_API v3_error_t v3_error_get(char *msg_out, usize msg_size);

/**
 * @brief 清除线程局部错误信息
 */
V3_API void v3_error_clear(void);

#endif /* V3_ERROR_H */

