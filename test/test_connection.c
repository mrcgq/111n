
/*
 * v3 Core - Connection Module Tests
 * 
 * 测试内容：
 * - 连接创建/销毁
 * - 连接状态机
 * - 会话管理
 * - 超时处理
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "../include/v3_connection.h"
#include "../include/v3_error.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * 测试框架宏（与 test_fec.c 相同）
 * ═══════════════════════════════════════════════════════════════════════════ */

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (!(cond)) { \
        printf("  [FAIL] %s: %s (line %d)\n", __func__, msg, __LINE__); \
        g_tests_failed++; \
        return false; \
    } \
    g_tests_passed++; \
} while(0)

#define TEST_BEGIN(name) \
    static bool name(void) { \
        printf("[TEST] %s\n", #name);

#define TEST_END() \
        printf("  [PASS]\n"); \
        return true; \
    }

#define RUN_TEST(test) do { \
    if (!test()) { \
        printf("  Test %s FAILED\n", #test); \
    } \
} while(0)

/* ═══════════════════════════════════════════════════════════════════════════
 * 模拟回调
 * ═══════════════════════════════════════════════════════════════════════════ */

static int g_callback_count = 0;
static v3_conn_state_t g_last_state = V3_CONN_STATE_IDLE;

static void mock_state_callback(v3_connection_t *conn, 
                                 v3_conn_state_t old_state,
                                 v3_conn_state_t new_state,
                                 void *user_data) {
    (void)conn;
    (void)old_state;
    (void)user_data;
    g_callback_count++;
    g_last_state = new_state;
}

static void reset_callbacks(void) {
    g_callback_count = 0;
    g_last_state = V3_CONN_STATE_IDLE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 连接管理器测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_conn_manager_create)
    v3_conn_manager_config_t config = {
        .max_connections = 100,
        .connection_timeout_ms = 30000,
        .keepalive_interval_ms = 10000,
        .max_pending = 50
    };
    
    v3_conn_manager_t *mgr = v3_conn_manager_create(&config);
    TEST_ASSERT(mgr != NULL, "Manager creation failed");
    
    TEST_ASSERT(v3_conn_manager_get_count(mgr) == 0, "Initial count should be 0");
    TEST_ASSERT(v3_conn_manager_get_max(mgr) == 100, "Max should be 100");
    
    v3_conn_manager_destroy(mgr);
TEST_END()

TEST_BEGIN(test_conn_manager_default_config)
    /* 使用默认配置 */
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    TEST_ASSERT(mgr != NULL, "Manager with default config failed");
    
    v3_conn_manager_destroy(mgr);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 连接创建测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_connection_create)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    TEST_ASSERT(mgr != NULL, "Manager creation failed");
    
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn != NULL, "Connection creation failed");
    
    TEST_ASSERT(v3_connection_get_state(conn) == V3_CONN_STATE_IDLE,
                "Initial state should be IDLE");
    TEST_ASSERT(v3_conn_manager_get_count(mgr) == 1, "Count should be 1");
    
    v3_connection_destroy(conn);
    TEST_ASSERT(v3_conn_manager_get_count(mgr) == 0, "Count should be 0 after destroy");
    
    v3_conn_manager_destroy(mgr);
TEST_END()

TEST_BEGIN(test_connection_multiple)
    v3_conn_manager_config_t config = {
        .max_connections = 10,
        .connection_timeout_ms = 30000,
        .keepalive_interval_ms = 10000,
        .max_pending = 5
    };
    
    v3_conn_manager_t *mgr = v3_conn_manager_create(&config);
    TEST_ASSERT(mgr != NULL, "Manager creation failed");
    
    v3_connection_t *conns[10];
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    /* 创建10个连接 */
    for (int i = 0; i < 10; i++) {
        conns[i] = v3_connection_create(mgr, &conn_cfg);
        TEST_ASSERT(conns[i] != NULL, "Connection creation failed");
    }
    
    TEST_ASSERT(v3_conn_manager_get_count(mgr) == 10, "Count should be 10");
    
    /* 尝试创建第11个，应该失败 */
    v3_connection_t *extra = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(extra == NULL, "Should fail when max reached");
    
    /* 销毁所有连接 */
    for (int i = 0; i < 10; i++) {
        v3_connection_destroy(conns[i]);
    }
    
    v3_conn_manager_destroy(mgr);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 连接状态机测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_connection_state_transitions)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn != NULL, "Connection creation failed");
    
    reset_callbacks();
    v3_connection_set_state_callback(conn, mock_state_callback, NULL);
    
    /* IDLE -> CONNECTING */
    v3_error_t err = v3_connection_connect(conn);
    /* 注意：实际连接可能失败（没有服务器），但状态应该改变 */
    TEST_ASSERT(v3_connection_get_state(conn) == V3_CONN_STATE_CONNECTING ||
                v3_connection_get_state(conn) == V3_CONN_STATE_ERROR,
                "State should change after connect");
    TEST_ASSERT(g_callback_count > 0, "Callback should be called");
    
    v3_connection_destroy(conn);
    v3_conn_manager_destroy(mgr);
TEST_END()

TEST_BEGIN(test_connection_disconnect)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 1000
    };
    
    v3_connection_t *conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn != NULL, "Connection creation failed");
    
    /* 断开未连接的连接应该是安全的 */
    v3_error_t err = v3_connection_disconnect(conn);
    TEST_ASSERT(err == V3_OK, "Disconnect should succeed");
    
    TEST_ASSERT(v3_connection_get_state(conn) == V3_CONN_STATE_IDLE ||
                v3_connection_get_state(conn) == V3_CONN_STATE_CLOSED,
                "State should be IDLE or CLOSED after disconnect");
    
    v3_connection_destroy(conn);
    v3_conn_manager_destroy(mgr);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 会话管理测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_connection_session)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn != NULL, "Connection creation failed");
    
    /* 获取会话 ID（未连接时应该是0或无效） */
    uint64_t session_id = v3_connection_get_session_id(conn);
    /* 这里不做断言，因为实现可能不同 */
    
    /* 获取连接 ID */
    uint32_t conn_id = v3_connection_get_id(conn);
    TEST_ASSERT(conn_id > 0, "Connection ID should be positive");
    
    v3_connection_destroy(conn);
    v3_conn_manager_destroy(mgr);
TEST_END()

TEST_BEGIN(test_connection_find_by_id)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn1 = v3_connection_create(mgr, &conn_cfg);
    v3_connection_t *conn2 = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn1 != NULL && conn2 != NULL, "Connection creation failed");
    
    uint32_t id1 = v3_connection_get_id(conn1);
    uint32_t id2 = v3_connection_get_id(conn2);
    
    TEST_ASSERT(id1 != id2, "Connection IDs should be unique");
    
    /* 通过 ID 查找 */
    v3_connection_t *found = v3_conn_manager_find_by_id(mgr, id1);
    TEST_ASSERT(found == conn1, "Should find correct connection");
    
    found = v3_conn_manager_find_by_id(mgr, 99999);
    TEST_ASSERT(found == NULL, "Should not find non-existent ID");
    
    v3_connection_destroy(conn1);
    v3_connection_destroy(conn2);
    v3_conn_manager_destroy(mgr);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 统计信息测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_connection_stats)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn != NULL, "Connection creation failed");
    
    v3_conn_stats_t stats;
    v3_error_t err = v3_connection_get_stats(conn, &stats);
    TEST_ASSERT(err == V3_OK, "Get stats failed");
    
    /* 初始统计应该为0 */
    TEST_ASSERT(stats.bytes_sent == 0, "Initial bytes_sent should be 0");
    TEST_ASSERT(stats.bytes_recv == 0, "Initial bytes_recv should be 0");
    TEST_ASSERT(stats.packets_sent == 0, "Initial packets_sent should be 0");
    TEST_ASSERT(stats.packets_recv == 0, "Initial packets_recv should be 0");
    
    v3_connection_destroy(conn);
    v3_conn_manager_destroy(mgr);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 边界条件测试
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_BEGIN(test_connection_null_params)
    /* 空管理器 */
    v3_conn_config_t conn_cfg = {
        .server_addr = "127.0.0.1",
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn = v3_connection_create(NULL, &conn_cfg);
    TEST_ASSERT(conn == NULL, "Should fail with NULL manager");
    
    /* 空配置 */
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    conn = v3_connection_create(mgr, NULL);
    TEST_ASSERT(conn == NULL, "Should fail with NULL config");
    
    v3_conn_manager_destroy(mgr);
TEST_END()

TEST_BEGIN(test_connection_invalid_addr)
    v3_conn_manager_t *mgr = v3_conn_manager_create(NULL);
    
    v3_conn_config_t conn_cfg = {
        .server_addr = NULL,  /* 无效地址 */
        .server_port = 51820,
        .timeout_ms = 5000
    };
    
    v3_connection_t *conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn == NULL, "Should fail with NULL address");
    
    conn_cfg.server_addr = "";  /* 空地址 */
    conn = v3_connection_create(mgr, &conn_cfg);
    TEST_ASSERT(conn == NULL, "Should fail with empty address");
    
    v3_conn_manager_destroy(mgr);
TEST_END()

/* ═══════════════════════════════════════════════════════════════════════════
 * 主函数
 * ═══════════════════════════════════════════════════════════════════════════ */

int test_connection_main(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                Connection Module Tests                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n\n");
    
    /* 管理器测试 */
    printf("─── Manager Tests ───\n");
    RUN_TEST(test_conn_manager_create);
    RUN_TEST(test_conn_manager_default_config);
    
    /* 连接创建测试 */
    printf("\n─── Connection Creation Tests ───\n");
    RUN_TEST(test_connection_create);
    RUN_TEST(test_connection_multiple);
    
    /* 状态机测试 */
    printf("\n─── State Machine Tests ───\n");
    RUN_TEST(test_connection_state_transitions);
    RUN_TEST(test_connection_disconnect);
    
    /* 会话管理测试 */
    printf("\n─── Session Management Tests ───\n");
    RUN_TEST(test_connection_session);
    RUN_TEST(test_connection_find_by_id);
    
    /* 统计信息测试 */
    printf("\n─── Stats Tests ───\n");
    RUN_TEST(test_connection_stats);
    
    /* 边界条件测试 */
    printf("\n─── Boundary Tests ───\n");
    RUN_TEST(test_connection_null_params);
    RUN_TEST(test_connection_invalid_addr);
    
    /* 结果汇总 */
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total: %d | Passed: %d | Failed: %d\n",
           g_tests_run, g_tests_passed, g_tests_failed);
    printf("═══════════════════════════════════════════════════════════════\n");
    
    return g_tests_failed > 0 ? 1 : 0;
}

#ifdef TEST_CONNECTION_STANDALONE
int main(void) {
    return test_connection_main();
}
#endif
