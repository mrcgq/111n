

# ═══════════════════════════════════════════════════════════════════════════
# v3 Core - Makefile
# 
# 支持：
# - Unix/Linux (GCC/Clang)
# - Windows (MinGW-w64)
# - 交叉编译
# ═══════════════════════════════════════════════════════════════════════════

# 项目信息
PROJECT_NAME := v3_core
VERSION := 1.0.0

# 检测操作系统
ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    EXE_EXT := .exe
    DLL_EXT := .dll
    LIB_EXT := .a
    RM := del /Q
    MKDIR := mkdir
    SEP := \\
else
    PLATFORM := unix
    EXE_EXT :=
    DLL_EXT := .so
    LIB_EXT := .a
    RM := rm -f
    MKDIR := mkdir -p
    SEP := /
endif

# 编译器设置
CC := gcc
AR := ar
WINDRES := windres

# 目录
SRC_DIR := src
INC_DIR := include
BUILD_DIR := build
TEST_DIR := test

# 编译选项
CFLAGS_COMMON := -Wall -Wextra -I$(INC_DIR)
CFLAGS_DEBUG := -g -O0 -DDEBUG -DV3_DEBUG
CFLAGS_RELEASE := -O2 -DNDEBUG

# 链接选项
ifeq ($(PLATFORM),windows)
    LDFLAGS := -lws2_32 -lmswsock
else
    LDFLAGS := -lpthread
endif

# 默认构建类型
BUILD_TYPE ?= Release

ifeq ($(BUILD_TYPE),Debug)
    CFLAGS := $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
else
    CFLAGS := $(CFLAGS_COMMON) $(CFLAGS_RELEASE)
endif

# ═══════════════════════════════════════════════════════════════════════════
# 源文件列表
# ═══════════════════════════════════════════════════════════════════════════

# 核心源文件
CORE_SRCS := \
    $(SRC_DIR)/v3_entry.c \
    $(SRC_DIR)/v3_exit.c \
    $(SRC_DIR)/v3_lifecycle.c \
    $(SRC_DIR)/v3_core_impl.c \
    $(SRC_DIR)/v3_config.c \
    $(SRC_DIR)/v3_ipc.c \
    $(SRC_DIR)/v3_guard.c \
    $(SRC_DIR)/v3_log.c \
    $(SRC_DIR)/v3_stats.c \
    $(SRC_DIR)/v3_buffer.c \
    $(SRC_DIR)/v3_thread.c \
    $(SRC_DIR)/v3_crypto.c \
    $(SRC_DIR)/v3_protocol.c \
    $(SRC_DIR)/v3_connection.c \
    $(SRC_DIR)/v3_fec.c \
    $(SRC_DIR)/v3_pacing.c \
    $(SRC_DIR)/v3_network.c

# Windows 平台特定源文件
ifeq ($(PLATFORM),windows)
WIN_SRCS := \
    $(SRC_DIR)/win_platform.c \
    $(SRC_DIR)/win_pipe.c \
    $(SRC_DIR)/win_process.c \
    $(SRC_DIR)/win_memory.c \
    $(SRC_DIR)/win_socket.c \
    $(SRC_DIR)/win_iocp.c

SRCS := $(CORE_SRCS) $(WIN_SRCS)
else
SRCS := $(CORE_SRCS)
endif

# 目标文件
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# 测试源文件
TEST_SRCS := \
    $(TEST_DIR)/test_main.c \
    $(TEST_DIR)/test_crypto.c \
    $(TEST_DIR)/test_protocol.c \
    $(TEST_DIR)/test_fec.c \
    $(TEST_DIR)/test_connection.c

TEST_OBJS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/test_%.o,$(TEST_SRCS))

# ═══════════════════════════════════════════════════════════════════════════
# 目标定义
# ═══════════════════════════════════════════════════════════════════════════

# 输出文件
STATIC_LIB := $(BUILD_DIR)/lib$(PROJECT_NAME)$(LIB_EXT)
SHARED_LIB := $(BUILD_DIR)/$(PROJECT_NAME)$(DLL_EXT)
TEST_EXE := $(BUILD_DIR)/v3_test$(EXE_EXT)

.PHONY: all clean static shared test dirs help

# 默认目标
all: dirs static shared

# 创建目录
dirs:
	@$(MKDIR) $(BUILD_DIR) 2>$(if $(filter windows,$(PLATFORM)),NUL,/dev/null) || true

# 静态库
static: dirs $(STATIC_LIB)
	@echo "[OK] Static library: $(STATIC_LIB)"

$(STATIC_LIB): $(OBJS)
	$(AR) rcs $@ $^

# 动态库
shared: dirs $(SHARED_LIB)
	@echo "[OK] Shared library: $(SHARED_LIB)"

$(SHARED_LIB): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# 编译源文件
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 编译测试文件
$(BUILD_DIR)/test_%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 测试程序
test: dirs $(TEST_EXE)
	@echo "[RUN] Running tests..."
	@$(TEST_EXE)

$(TEST_EXE): $(TEST_OBJS) $(STATIC_LIB)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) -L$(BUILD_DIR) -l$(PROJECT_NAME) $(LDFLAGS)

# 清理
clean:
ifeq ($(PLATFORM),windows)
	@if exist $(BUILD_DIR) rmdir /S /Q $(BUILD_DIR)
else
	@rm -rf $(BUILD_DIR)
endif
	@echo "[OK] Clean complete"

# 帮助
help:
	@echo ""
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "  v3 Core Makefile"
	@echo "═══════════════════════════════════════════════════════════════"
	@echo ""
	@echo "Usage: make [target] [BUILD_TYPE=Debug|Release]"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build static and shared libraries (default)"
	@echo "  static   - Build static library only"
	@echo "  shared   - Build shared library only"
	@echo "  test     - Build and run tests"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Release build"
	@echo "  make BUILD_TYPE=Debug   # Debug build"
	@echo "  make test               # Run tests"
	@echo ""

# ═══════════════════════════════════════════════════════════════════════════
# 依赖关系（自动生成）
# ═══════════════════════════════════════════════════════════════════════════

-include $(OBJS:.o=.d)

$(BUILD_DIR)/%.d: $(SRC_DIR)/%.c
	@$(CC) $(CFLAGS) -MM -MT '$(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$<)' $< > $@
