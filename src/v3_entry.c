
/**
 * @file v3_entry.c
 * @brief v3 Core - 程序入口点
 * 
 * 提供 main() 函数、命令行解析和初始化流程
 */

#include "v3_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef V3_PLATFORM_WINDOWS
    #include <windows.h>
    #include <io.h>
    #include <fcntl.h>
#else
    #include <unistd.h>
    #include <getopt.h>
#endif

/* =========================================================
 * 命令行选项
 * ========================================================= */

typedef struct v3_cmdline_s {
    /* 基础配置 */
    const char     *config_file;
    const char     *log_file;
    v3_log_level_t  log_level;
    bool            verbose;
    bool            daemon;
    bool            version;
    bool            help;
    
    /* 网络配置 */
    const char     *bind_address;
    u16             bind_port;
    
    /* 加密配置 */
    const char     *key_file;
    const char     *key_hex;
    
    /* FEC 配置 */
    bool            fec_enabled;
    const char     *fec_config;     /* "data:parity" 格式 */
    
    /* Pacing 配置 */
    bool            pacing_enabled;
    u64             pacing_rate;    /* Mbps */
    
    /* IPC 配置 */
    bool            ipc_enabled;
    const char     *ipc_pipe;
    
    /* 其他 */
    bool            benchmark;
    bool            test_config;
} v3_cmdline_t;

/* 默认值 */
static v3_cmdline_t g_cmdline = {
    .config_file = NULL,
    .log_file = NULL,
    .log_level = V3_LOG_INFO,
    .verbose = false,
    .daemon = false,
    .version = false,
    .help = false,
    .bind_address = "0.0.0.0",
    .bind_port = V3_DEFAULT_PORT,
    .key_file = NULL,
    .key_hex = NULL,
    .fec_enabled = false,
    .fec_config = "5:2",
    .pacing_enabled = false,
    .pacing_rate = 100,
    .ipc_enabled = true,
    .ipc_pipe = NULL,
    .benchmark = false,
    .test_config = false,
};

/* =========================================================
 * 帮助信息
 * ========================================================= */

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("v3 Core - High-Performance UDP Protocol Engine\n\n");
    printf("Options:\n");
    printf("  -c, --config=FILE       Configuration file path\n");
    printf("  -l, --log=FILE          Log file path\n");
    printf("  -L, --log-level=LEVEL   Log level (trace,debug,info,warn,error,fatal)\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -d, --daemon            Run as daemon (background)\n");
    printf("  -V, --version           Show version and exit\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Network:\n");
    printf("  -b, --bind=ADDR         Bind address (default: 0.0.0.0)\n");
    printf("  -p, --port=PORT         Bind port (default: %d)\n", V3_DEFAULT_PORT);
    printf("\n");
    printf("Security:\n");
    printf("  -k, --key-file=FILE     Master key file (32 bytes binary)\n");
    printf("  -K, --key=HEX           Master key (64 hex characters)\n");
    printf("\n");
    printf("FEC:\n");
    printf("  -f, --fec               Enable FEC\n");
    printf("  -F, --fec-config=D:P    FEC data:parity shards (default: 5:2)\n");
    printf("\n");
    printf("Pacing:\n");
    printf("  -P, --pacing=MBPS       Enable pacing with rate (Mbps)\n");
    printf("\n");
    printf("IPC:\n");
    printf("  --ipc=PIPE              IPC pipe name\n");
    printf("  --no-ipc                Disable IPC\n");
    printf("\n");
    printf("Debug:\n");
    printf("  --benchmark             Run benchmark and exit\n");
    printf("  --test-config           Test configuration and exit\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -p 51820 -f -P 100\n", prog);
    printf("  %s -c config.json -v\n", prog);
    printf("  %s --key-file=master.key --fec\n", prog);
    printf("\n");
}

static void print_version(void) {
    printf("%s\n", V3_BANNER);
    printf("\n");
    printf("Version:   %s\n", V3_VERSION_STRING);
    printf("Build:     %s\n", V3_BUILD_TIME);
    printf("Platform:  %s\n", V3_BUILD_PLATFORM);
    printf("Compiler:  %s\n", V3_BUILD_COMPILER);
    printf("\n");
}

/* =========================================================
 * 命令行解析
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS

/* Windows 简化版命令行解析 */
static int parse_cmdline_windows(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            g_cmdline.help = true;
        }
        else if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
            g_cmdline.version = true;
        }
        else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            g_cmdline.verbose = true;
            g_cmdline.log_level = V3_LOG_DEBUG;
        }
        else if (strcmp(arg, "-d") == 0 || strcmp(arg, "--daemon") == 0) {
            g_cmdline.daemon = true;
        }
        else if (strcmp(arg, "-f") == 0 || strcmp(arg, "--fec") == 0) {
            g_cmdline.fec_enabled = true;
        }
        else if (strcmp(arg, "--no-ipc") == 0) {
            g_cmdline.ipc_enabled = false;
        }
        else if (strcmp(arg, "--benchmark") == 0) {
            g_cmdline.benchmark = true;
        }
        else if (strcmp(arg, "--test-config") == 0) {
            g_cmdline.test_config = true;
        }
        else if (strncmp(arg, "-c=", 3) == 0 || strncmp(arg, "--config=", 9) == 0) {
            g_cmdline.config_file = strchr(arg, '=') + 1;
        }
        else if (strncmp(arg, "-p=", 3) == 0 || strncmp(arg, "--port=", 7) == 0) {
            g_cmdline.bind_port = (u16)atoi(strchr(arg, '=') + 1);
        }
        else if (strncmp(arg, "-b=", 3) == 0 || strncmp(arg, "--bind=", 7) == 0) {
            g_cmdline.bind_address = strchr(arg, '=') + 1;
        }
        else if (strncmp(arg, "-l=", 3) == 0 || strncmp(arg, "--log=", 6) == 0) {
            g_cmdline.log_file = strchr(arg, '=') + 1;
        }
        else if (strncmp(arg, "-L=", 3) == 0 || strncmp(arg, "--log-level=", 12) == 0) {
            const char *level_str = strchr(arg, '=') + 1;
            g_cmdline.log_level = v3_log_level_from_str(level_str);
        }
        else if (strncmp(arg, "-k=", 3) == 0 || strncmp(arg, "--key-file=", 11) == 0) {
            g_cmdline.key_file = strchr(arg, '=') + 1;
        }
        else if (strncmp(arg, "-K=", 3) == 0 || strncmp(arg, "--key=", 6) == 0) {
            g_cmdline.key_hex = strchr(arg, '=') + 1;
        }
        else if (strncmp(arg, "-F=", 3) == 0 || strncmp(arg, "--fec-config=", 13) == 0) {
            g_cmdline.fec_config = strchr(arg, '=') + 1;
            g_cmdline.fec_enabled = true;
        }
        else if (strncmp(arg, "-P=", 3) == 0 || strncmp(arg, "--pacing=", 9) == 0) {
            g_cmdline.pacing_rate = (u64)atoll(strchr(arg, '=') + 1);
            g_cmdline.pacing_enabled = true;
        }
        else if (strncmp(arg, "--ipc=", 6) == 0) {
            g_cmdline.ipc_pipe = strchr(arg, '=') + 1;
        }
        else if (arg[0] == '-') {
            /* 处理短选项带参数 */
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (strcmp(arg, "-c") == 0) { g_cmdline.config_file = argv[++i]; }
                else if (strcmp(arg, "-p") == 0) { g_cmdline.bind_port = (u16)atoi(argv[++i]); }
                else if (strcmp(arg, "-b") == 0) { g_cmdline.bind_address = argv[++i]; }
                else if (strcmp(arg, "-l") == 0) { g_cmdline.log_file = argv[++i]; }
                else if (strcmp(arg, "-L") == 0) { g_cmdline.log_level = v3_log_level_from_str(argv[++i]); }
                else if (strcmp(arg, "-k") == 0) { g_cmdline.key_file = argv[++i]; }
                else if (strcmp(arg, "-K") == 0) { g_cmdline.key_hex = argv[++i]; }
                else if (strcmp(arg, "-F") == 0) { g_cmdline.fec_config = argv[++i]; g_cmdline.fec_enabled = true; }
                else if (strcmp(arg, "-P") == 0) { g_cmdline.pacing_rate = (u64)atoll(argv[++i]); g_cmdline.pacing_enabled = true; }
                else {
                    fprintf(stderr, "Unknown option: %s\n", arg);
                    return -1;
                }
            } else {
                fprintf(stderr, "Unknown option: %s\n", arg);
                return -1;
            }
        }
    }
    return 0;
}

#else

/* POSIX getopt_long 版本 */
static int parse_cmdline_posix(int argc, char **argv) {
    static struct option long_opts[] = {
        {"config",      required_argument, 0, 'c'},
        {"log",         required_argument, 0, 'l'},
        {"log-level",   required_argument, 0, 'L'},
        {"verbose",     no_argument,       0, 'v'},
        {"daemon",      no_argument,       0, 'd'},
        {"version",     no_argument,       0, 'V'},
        {"help",        no_argument,       0, 'h'},
        {"bind",        required_argument, 0, 'b'},
        {"port",        required_argument, 0, 'p'},
        {"key-file",    required_argument, 0, 'k'},
        {"key",         required_argument, 0, 'K'},
        {"fec",         no_argument,       0, 'f'},
        {"fec-config",  required_argument, 0, 'F'},
        {"pacing",      required_argument, 0, 'P'},
        {"ipc",         required_argument, 0, 1001},
        {"no-ipc",      no_argument,       0, 1002},
        {"benchmark",   no_argument,       0, 1003},
        {"test-config", no_argument,       0, 1004},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "c:l:L:vdVhb:p:k:K:fF:P:", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c': g_cmdline.config_file = optarg; break;
            case 'l': g_cmdline.log_file = optarg; break;
            case 'L': g_cmdline.log_level = v3_log_level_from_str(optarg); break;
            case 'v': g_cmdline.verbose = true; g_cmdline.log_level = V3_LOG_DEBUG; break;
            case 'd': g_cmdline.daemon = true; break;
            case 'V': g_cmdline.version = true; break;
            case 'h': g_cmdline.help = true; break;
            case 'b': g_cmdline.bind_address = optarg; break;
            case 'p': g_cmdline.bind_port = (u16)atoi(optarg); break;
            case 'k': g_cmdline.key_file = optarg; break;
            case 'K': g_cmdline.key_hex = optarg; break;
            case 'f': g_cmdline.fec_enabled = true; break;
            case 'F': g_cmdline.fec_config = optarg; g_cmdline.fec_enabled = true; break;
            case 'P': g_cmdline.pacing_rate = (u64)atoll(optarg); g_cmdline.pacing_enabled = true; break;
            case 1001: g_cmdline.ipc_pipe = optarg; break;
            case 1002: g_cmdline.ipc_enabled = false; break;
            case 1003: g_cmdline.benchmark = true; break;
            case 1004: g_cmdline.test_config = true; break;
            default:
                return -1;
        }
    }
    return 0;
}

#endif

static int parse_cmdline(int argc, char **argv) {
#ifdef V3_PLATFORM_WINDOWS
    return parse_cmdline_windows(argc, argv);
#else
    return parse_cmdline_posix(argc, argv);
#endif
}

/* =========================================================
 * 密钥加载
 * ========================================================= */

static v3_error_t load_master_key(u8 key[V3_CRYPTO_KEY_SIZE]) {
    /* 优先使用 hex 密钥 */
    if (g_cmdline.key_hex != NULL) {
        if (strlen(g_cmdline.key_hex) != 64) {
            V3_LOG_ERROR("Invalid key length: expected 64 hex chars, got %zu", 
                         strlen(g_cmdline.key_hex));
            return V3_ERR_CRYPTO_INVALID_KEY;
        }
        
        v3_error_t err = v3_hex_decode(key, g_cmdline.key_hex, 64);
        if (V3_IS_ERROR(err)) {
            V3_LOG_ERROR("Failed to decode hex key");
            return err;
        }
        
        V3_LOG_INFO("Master key loaded from command line");
        return V3_OK;
    }
    
    /* 从文件加载 */
    if (g_cmdline.key_file != NULL) {
        FILE *f = fopen(g_cmdline.key_file, "rb");
        if (!f) {
            V3_LOG_ERROR("Failed to open key file: %s", g_cmdline.key_file);
            return V3_ERR_IO_OPEN_FAILED;
        }
        
        size_t read = fread(key, 1, V3_CRYPTO_KEY_SIZE, f);
        fclose(f);
        
        if (read != V3_CRYPTO_KEY_SIZE) {
            V3_LOG_ERROR("Invalid key file size: expected %d, got %zu", 
                         V3_CRYPTO_KEY_SIZE, read);
            return V3_ERR_CRYPTO_INVALID_KEY;
        }
        
        V3_LOG_INFO("Master key loaded from file: %s", g_cmdline.key_file);
        return V3_OK;
    }
    
    /* 生成随机密钥 */
    V3_LOG_WARN("No master key specified, generating random key");
    V3_LOG_WARN("This key will be lost on restart!");
    
    return v3_crypto_random(key, V3_CRYPTO_KEY_SIZE);
}

/* =========================================================
 * 初始化选项构建
 * ========================================================= */

static v3_error_t build_init_options(v3_init_options_t *opts) {
    v3_core_default_options(opts);
    
    /* 基础配置 */
    opts->config_file = g_cmdline.config_file;
    opts->log_file = g_cmdline.log_file;
    opts->log_level = g_cmdline.log_level;
    
    /* 网络配置 */
    opts->bind_address = g_cmdline.bind_address;
    opts->bind_port = g_cmdline.bind_port;
    
    /* FEC 配置 */
    opts->fec_enabled = g_cmdline.fec_enabled;
    if (g_cmdline.fec_enabled && g_cmdline.fec_config) {
        u8 data = 5, parity = 2;
        if (sscanf(g_cmdline.fec_config, "%hhu:%hhu", &data, &parity) == 2) {
            opts->fec_data_shards = data;
            opts->fec_parity_shards = parity;
        }
    }
    
    /* Pacing 配置 */
    opts->pacing_enabled = g_cmdline.pacing_enabled;
    if (g_cmdline.pacing_enabled) {
        opts->pacing_rate_bps = g_cmdline.pacing_rate * 1000000ULL;
    }
    
    /* IPC 配置 */
    opts->ipc_enabled = g_cmdline.ipc_enabled;
    opts->ipc_pipe_name = g_cmdline.ipc_pipe;
    
    /* 标志 */
    if (g_cmdline.daemon) {
        opts->flags |= V3_INIT_FLAG_DAEMON;
    }
    if (g_cmdline.verbose) {
        opts->flags |= V3_INIT_FLAG_VERBOSE;
    }
    if (g_cmdline.benchmark) {
        opts->flags |= V3_INIT_FLAG_BENCHMARK;
    }
    if (g_cmdline.test_config) {
        opts->flags |= V3_INIT_FLAG_DRY_RUN;
    }
    
    /* 加载主密钥 */
    static u8 master_key[V3_CRYPTO_KEY_SIZE];
    v3_error_t err = load_master_key(master_key);
    if (V3_IS_ERROR(err)) {
        return err;
    }
    opts->master_key = master_key;
    opts->master_key_len = V3_CRYPTO_KEY_SIZE;
    
    return V3_OK;
}

/* =========================================================
 * Windows 控制台设置
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS
static void setup_windows_console(void) {
    /* 启用 ANSI 转义序列（彩色输出）*/
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) {
            mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, mode);
        }
    }
    
    /* 设置 UTF-8 输出 */
    SetConsoleOutputCP(CP_UTF8);
    
    /* 设置控制台标题 */
    SetConsoleTitleA("v3 Core");
}
#endif

/* =========================================================
 * 主函数
 * ========================================================= */

int main(int argc, char **argv) {
#ifdef V3_PLATFORM_WINDOWS
    setup_windows_console();
#endif
    
    /* 解析命令行 */
    if (parse_cmdline(argc, argv) != 0) {
        print_usage(argv[0]);
        return V3_EXIT_INVALID_ARGS;
    }
    
    /* 处理特殊选项 */
    if (g_cmdline.help) {
        print_usage(argv[0]);
        return V3_EXIT_SUCCESS;
    }
    
    if (g_cmdline.version) {
        print_version();
        return V3_EXIT_SUCCESS;
    }
    
    /* 打印 Banner */
    if (!g_cmdline.daemon) {
        v3_core_print_banner();
    }
    
    /* 构建初始化选项 */
    v3_init_options_t opts;
    v3_error_t err = build_init_options(&opts);
    if (V3_IS_ERROR(err)) {
        fprintf(stderr, "Failed to build init options: %s\n", v3_error_str(err));
        return V3_EXIT_CONFIG_ERROR;
    }
    
    /* 初始化核心 */
    err = v3_core_init(&opts);
    if (V3_IS_ERROR(err)) {
        fprintf(stderr, "Failed to initialize v3 core: %s\n", v3_error_str(err));
        return V3_EXIT_INIT_FAILED;
    }
    
    /* 测试配置模式 */
    if (g_cmdline.test_config) {
        printf("Configuration test passed.\n");
        v3_core_shutdown();
        return V3_EXIT_SUCCESS;
    }
    
    /* 运行主循环 */
    int exit_code = v3_core_run();
    
    /* 清理 */
    v3_core_shutdown();
    
    return exit_code;
}

/* =========================================================
 * Windows 入口点（GUI 模式）
 * ========================================================= */

#ifdef V3_PLATFORM_WINDOWS
#ifdef V3_BUILD_GUI

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
                   LPSTR lpCmdLine, int nCmdShow) {
    V3_UNUSED(hInstance);
    V3_UNUSED(hPrevInstance);
    V3_UNUSED(lpCmdLine);
    V3_UNUSED(nCmdShow);
    
    return main(__argc, __argv);
}

#endif /* V3_BUILD_GUI */
#endif /* V3_PLATFORM_WINDOWS */
