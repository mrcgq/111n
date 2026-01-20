
# v3 Core - 构建指南

## 目录

- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [构建选项](#构建选项)
- [平台特定说明](#平台特定说明)
- [测试](#测试)
- [故障排除](#故障排除)

---

## 系统要求

### Windows

| 工具 | 最低版本 | 推荐版本 |
|------|----------|----------|
| Visual Studio | 2019 | 2022 |
| 或 MinGW-w64 | 8.0 | 13.0+ |
| CMake | 3.16 | 3.28+ |
| Windows SDK | 10.0.17763 | 最新 |

### Linux/Unix

| 工具 | 最低版本 |
|------|----------|
| GCC | 7.0 |
| Clang | 8.0 |
| CMake | 3.16 |

---

## 快速开始

### Windows (MSVC)


REM 方式 1: 使用批处理脚本
build_windows.bat release x64

REM 方式 2: 手动 CMake
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release


### Windows (MinGW)


REM 方式 1: 使用批处理脚本
build_mingw.bat release

REM 方式 2: 手动 CMake
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build .


### Linux/macOS


mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)




## 构建选项

### CMake 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `V3_BUILD_SHARED` | ON | 构建动态库 |
| `V3_BUILD_STATIC` | ON | 构建静态库 |
| `V3_BUILD_TESTS` | ON | 构建测试程序 |
| `V3_ENABLE_DEBUG` | OFF | 启用调试功能 |

### 使用示例


# 只构建静态库，不构建测试
cmake .. -DV3_BUILD_SHARED=OFF -DV3_BUILD_TESTS=OFF

# 启用调试模式
cmake .. -DCMAKE_BUILD_TYPE=Debug -DV3_ENABLE_DEBUG=ON


### Makefile 变量

# Debug 构建
make BUILD_TYPE=Debug

# 只构建静态库
make static

# 只构建测试
make test




## 平台特定说明

### Windows - MSVC

1. **安装 Visual Studio**
   - 安装 "Desktop development with C++" 工作负载
   - 确保包含 Windows 10/11 SDK

2. **使用开发者命令提示符**
   ```batch
   REM 打开 "Developer Command Prompt for VS 2022"
   cd path\to\v3_core
   build_windows.bat
   ```

3. **IDE 集成**
   - Visual Studio 可直接打开 CMakeLists.txt
   - 选择 "Open Folder" -> 选择 v3_core 目录

### Windows - MinGW

1. **安装 MinGW-w64**
   - 推荐下载: https://winlibs.com/
   - 选择 UCRT 版本（兼容性更好）
   - 解压到 `C:\mingw64`

2. **配置 PATH**

   set PATH=C:\mingw64\bin;%PATH%


3. **验证安装**

   gcc --version
   cmake --version


### Linux

1. **安装依赖**

   # Debian/Ubuntu
   sudo apt install build-essential cmake
   
   # RHEL/CentOS
   sudo yum groupinstall "Development Tools"
   sudo yum install cmake


2. **构建**

   make
   # 或
   cmake -B build && cmake --build build




## 测试

### 运行所有测试


# CMake 方式
cd build
ctest --output-on-failure

# Makefile 方式
make test


### 运行特定测试


# 直接运行测试程序
./build/v3_test

# 只运行 FEC 测试（需要修改 test_main.c）
./build/v3_test --filter=fec


### 测试覆盖率（仅 GCC）


cmake .. -DCMAKE_BUILD_TYPE=Debug \
         -DCMAKE_C_FLAGS="--coverage"
make
make test
gcov src/*.c




## 故障排除

### 常见问题

#### 1. CMake 找不到编译器

**Windows MSVC:**

REM 确保使用 Developer Command Prompt
REM 或手动运行 vcvarsall.bat
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64


**MinGW:**

REM 确保 gcc 在 PATH 中
set PATH=C:\mingw64\bin;%PATH%


#### 2. 链接错误 - 找不到 ws2_32

确保 Windows SDK 已正确安装，或手动指定：

target_link_libraries(your_target PRIVATE ws2_32 mswsock)


#### 3. 头文件找不到


# 确保 include 目录正确
cmake .. -I../include


#### 4. 运行时找不到 DLL

**Windows:**

REM 将 DLL 复制到可执行文件目录
copy build\Release\v3_core.dll build\Release\

REM 或添加到 PATH
set PATH=%CD%\build\Release;%PATH%


### 调试构建问题


# 详细输出
cmake .. -DCMAKE_VERBOSE_MAKEFILE=ON
make VERBOSE=1

# CMake 调试
cmake .. --debug-output




## 输出文件

构建成功后，输出文件位于 `build/` 目录：

| 文件 | 说明 |
|------|------|
| `v3_core.dll` / `libv3_core.so` | 动态库 |
| `v3_core.lib` / `libv3_core.a` | 静态库（或导入库） |
| `v3_test.exe` / `v3_test` | 测试程序 |



## 集成到您的项目

### CMake 项目


# 方式 1: add_subdirectory
add_subdirectory(path/to/v3_core)
target_link_libraries(your_app PRIVATE v3_core_static)

# 方式 2: find_package (需要安装)
find_package(v3_core REQUIRED)
target_link_libraries(your_app PRIVATE v3_core::v3_core)


### 手动链接


# GCC/MinGW
gcc -o myapp myapp.c -I/path/to/v3_core/include -L/path/to/v3_core/build -lv3_core -lws2_32

# MSVC
cl myapp.c /I path\to\v3_core\include /link path\to\v3_core\build\Release\v3_core.lib ws2_32.lib




## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| 1.0.0 | 2024-XX | 初始版本 |



## 获取帮助

- 查看 `make help` 获取 Makefile 帮助
- 查看 `cmake --help` 获取 CMake 帮助
- 提交 Issue 报告问题


