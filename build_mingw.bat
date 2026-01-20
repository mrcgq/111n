
@echo off
REM ═══════════════════════════════════════════════════════════════════════════
REM v3 Core - MinGW Build Script
REM ═══════════════════════════════════════════════════════════════════════════

setlocal EnableDelayedExpansion

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║               v3 Core - MinGW Build Script                    ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM 默认参数
set BUILD_TYPE=Release
set RUN_TESTS=0

REM 解析参数
:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="debug" set BUILD_TYPE=Debug
if /i "%~1"=="release" set BUILD_TYPE=Release
if /i "%~1"=="test" set RUN_TESTS=1
shift
goto :parse_args
:done_args

echo [INFO] Build Type: %BUILD_TYPE%
echo.

REM 检查 MinGW
where gcc >nul 2>&1
if errorlevel 1 (
    echo [ERROR] GCC not found in PATH.
    echo [INFO] Please install MinGW-w64 and add it to PATH.
    echo [INFO] Download: https://winlibs.com/
    exit /b 1
)

REM 显示编译器版本
for /f "tokens=*" %%i in ('gcc --version ^| findstr /n "^" ^| findstr "^1:"') do (
    set GCC_VER=%%i
    set GCC_VER=!GCC_VER:~2!
)
echo [INFO] Compiler: !GCC_VER!
echo.

REM 创建构建目录
if not exist build mkdir build
cd build

REM 配置 CMake
echo [INFO] Configuring CMake...
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

REM 构建
echo [INFO] Building...
cmake --build . -- -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo [OK] Build completed successfully!
echo [INFO] Output: build\

REM 运行测试
if %RUN_TESTS%==1 (
    echo.
    echo [INFO] Running tests...
    ctest --output-on-failure
)

cd ..
endlocal
