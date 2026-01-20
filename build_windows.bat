
@echo off
REM ═══════════════════════════════════════════════════════════════════════════
REM v3 Core - MSVC Build Script
REM ═══════════════════════════════════════════════════════════════════════════

setlocal EnableDelayedExpansion

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║                v3 Core - MSVC Build Script                    ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM 默认参数
set BUILD_TYPE=Release
set ARCH=x64
set RUN_TESTS=0

REM 解析参数
:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="debug" set BUILD_TYPE=Debug
if /i "%~1"=="release" set BUILD_TYPE=Release
if /i "%~1"=="x86" set ARCH=Win32
if /i "%~1"=="x64" set ARCH=x64
if /i "%~1"=="test" set RUN_TESTS=1
shift
goto :parse_args
:done_args

echo [INFO] Build Type: %BUILD_TYPE%
echo [INFO] Architecture: %ARCH%
echo.

REM 查找 Visual Studio
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
    echo [ERROR] vswhere not found. Please install Visual Studio 2019 or later.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`%VSWHERE% -latest -property installationPath`) do set VS_PATH=%%i
if "%VS_PATH%"=="" (
    echo [ERROR] Visual Studio not found.
    exit /b 1
)

echo [INFO] Visual Studio: %VS_PATH%

REM 设置 VC 环境
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" %ARCH% >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to initialize VC environment.
    exit /b 1
)

REM 创建构建目录
if not exist build mkdir build
cd build

REM 配置 CMake
echo [INFO] Configuring CMake...
cmake .. -G "Visual Studio 17 2022" -A %ARCH% -DCMAKE_BUILD_TYPE=%BUILD_TYPE%
if errorlevel 1 (
    echo [ERROR] CMake configuration failed.
    exit /b 1
)

REM 构建
echo [INFO] Building...
cmake --build . --config %BUILD_TYPE%
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo [OK] Build completed successfully!
echo [INFO] Output: build\%BUILD_TYPE%\

REM 运行测试
if %RUN_TESTS%==1 (
    echo.
    echo [INFO] Running tests...
    ctest -C %BUILD_TYPE% --output-on-failure
)

cd ..
endlocal
