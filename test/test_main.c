
/*
 * test_main.c - v3 Core Test Entry Point
 * 
 * 功能：
 * - 测试框架初始化
 * - 测试用例注册与执行
 * - 结果统计与报告
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "v3_platform.h"
#include "v3_error.h"

/* =========================================================
 * 测试框架
 * ========================================================= */

#define V3_TEST_MAX_CASES   256
#define V3_TEST_MAX_NAME    64

typedef int (*v3_test_func_t)(void);

typedef struct {
    char                name[V3_TEST_MAX_NAME];
    v3_test_func_t      func;
    const char         *file;
    int                 line;
} v3_test_case_t;

typedef struct {
    v3_test_case_t      cases[V3_TEST_MAX_CASES];
    int                 count;
    int                 passed;
    int                 failed;
    int                 skipped;
    uint64_t            start_time;
    uint64_t            end_time;
} v3_test_suite_t;

static v3_test_suite_t g_suite = {0};

/* =========================================================
 * 测试注册宏
 * ========================================================= */

#define V3_TEST_REGISTER(name, func) \
    v3_test_register(name, func, __FILE__, __LINE__)

#define V3_TEST_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            printf("  ASSERT FAILED: %s (line %d)\n", #cond, __LINE__); \
            return -1; \
        } \
    } while(0)

#define V3_TEST_ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            printf("  ASSERT FAILED: %s == %s (line %d)\n", #a, #b, __LINE__); \
            return -1; \
        } \
    } while(0)

#define V3_TEST_ASSERT_NE(a, b) \
    do { \
        if ((a) == (b)) { \
            printf("  ASSERT FAILED: %s != %s (line %d)\n", #a, #b, __LINE__); \
            return -1; \
        } \
    } while(0)

#define V3_TEST_ASSERT_NULL(ptr) \
    V3_TEST_ASSERT((ptr) == NULL)

#define V3_TEST_ASSERT_NOT_NULL(ptr) \
    V3_TEST_ASSERT((ptr) != NULL)

/* =========================================================
 * 测试注册
 * ========================================================= */

void v3_test_register(const char *name, v3_test_func_t func,
                       const char *file, int line) {
    if (g_suite.count >= V3_TEST_MAX_CASES) {
        fprintf(stderr, "Too many test cases\n");
        return;
    }
    
    v3_test_case_t *tc = &g_suite.cases[g_suite.count++];
    strncpy(tc->name, name, V3_TEST_MAX_NAME - 1);
    tc->func = func;
    tc->file = file;
    tc->line = line;
}

/* =========================================================
 * 外部测试模块声明
 * ========================================================= */

extern void v3_test_crypto_register(void);
extern void v3_test_protocol_register(void);
extern void v3_test_fec_register(void);
extern void v3_test_connection_register(void);

/* =========================================================
 * 测试执行
 * ========================================================= */

static void print_banner(void) {
    printf("\n");
    printf("================================================================\n");
    printf("                    v3 Core Test Suite                         \n");
    printf("================================================================\n");
    printf("\n");
}

static void print_result(const char *name, int result, uint64_t elapsed_ms) {
    const char *status;
    const char *color;
    
    if (result == 0) {
        status = "PASS";
        color = "\033[32m";  /* 绿色 */
    } else if (result == 1) {
        status = "SKIP";
        color = "\033[33m";  /* 黄色 */
    } else {
        status = "FAIL";
        color = "\033[31m";  /* 红色 */
    }
    
#ifdef _WIN32
    printf("  [%s] %s (%llu ms)\n", status, name, elapsed_ms);
#else
    printf("  [%s%s\033[0m] %s (%llu ms)\n", color, status, name, elapsed_ms);
#endif
}

static void print_summary(void) {
    uint64_t total_time = g_suite.end_time - g_suite.start_time;
    
    printf("\n");
    printf("================================================================\n");
    printf("                         Summary                               \n");
    printf("================================================================\n");
    printf("\n");
    printf("  Total:    %d\n", g_suite.count);
    printf("  Passed:   %d\n", g_suite.passed);
    printf("  Failed:   %d\n", g_suite.failed);
    printf("  Skipped:  %d\n", g_suite.skipped);
    printf("  Time:     %llu ms\n", (unsigned long long)total_time);
    printf("\n");
    
    if (g_suite.failed == 0) {
        printf("  Result: ALL TESTS PASSED\n");
    } else {
        printf("  Result: SOME TESTS FAILED\n");
    }
    printf("\n");
}

int v3_test_run_all(void) {
    g_suite.start_time = v3_time_ms();
    
    printf("Running %d test cases...\n\n", g_suite.count);
    
    for (int i = 0; i < g_suite.count; i++) {
        v3_test_case_t *tc = &g_suite.cases[i];
        
        uint64_t start = v3_time_ms();
        int result = tc->func();
        uint64_t elapsed = v3_time_ms() - start;
        
        print_result(tc->name, result, elapsed);
        
        if (result == 0) {
            g_suite.passed++;
        } else if (result == 1) {
            g_suite.skipped++;
        } else {
            g_suite.failed++;
        }
    }
    
    g_suite.end_time = v3_time_ms();
    
    print_summary();
    
    return g_suite.failed;
}

/* =========================================================
 * 主函数
 * ========================================================= */

int main(int argc, char **argv) {
    int result;
    
    /* 初始化平台 */
    if (v3_platform_init() != V3_OK) {
        fprintf(stderr, "Failed to initialize platform\n");
        return 1;
    }
    
    print_banner();
    
    /* 解析参数 */
    bool verbose = false;
    const char *filter = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strncmp(argv[i], "--filter=", 9) == 0) {
            filter = argv[i] + 9;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  -v, --verbose      Verbose output\n");
            printf("  --filter=PATTERN   Run only matching tests\n");
            printf("  -h, --help         Show this help\n");
            return 0;
        }
    }
    
    (void)verbose;
    (void)filter;
    
    /* 注册测试用例 */
    v3_test_crypto_register();
    v3_test_protocol_register();
    /* v3_test_fec_register(); */      /* 可选 */
    /* v3_test_connection_register(); */ /* 可选 */
    
    /* 运行测试 */
    result = v3_test_run_all();
    
    /* 清理 */
    v3_platform_cleanup();
    
    return result;
}
