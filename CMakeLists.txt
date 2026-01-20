
# ═══════════════════════════════════════════════════════════════════════════
# v3 Core - CMake Build System
# 
# 支持：
# - MSVC (Visual Studio)
# - MinGW-w64
# - GCC/Clang (Unix)
# ═══════════════════════════════════════════════════════════════════════════

cmake_minimum_required(VERSION 3.16)

project(v3_core
    VERSION 1.0.0
    DESCRIPTION "v3 Protocol Core Library"
    LANGUAGES C
)

# ═══════════════════════════════════════════════════════════════════════════
# 选项
# ═══════════════════════════════════════════════════════════════════════════

option(V3_BUILD_SHARED "Build shared library" ON)
option(V3_BUILD_STATIC "Build static library" ON)
option(V3_BUILD_TESTS "Build tests" ON)
option(V3_ENABLE_DEBUG "Enable debug features" OFF)

# ═══════════════════════════════════════════════════════════════════════════
# 编译器设置
# ═══════════════════════════════════════════════════════════════════════════

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
if(MSVC)
    add_compile_options(/W4 /WX-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_definitions(_WINSOCK_DEPRECATED_NO_WARNINGS)
    
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Zi /Od)
    else()
        add_compile_options(/O2)
    endif()
else()
    add_compile_options(-Wall -Wextra)
    
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O2)
    endif()
endif()

if(V3_ENABLE_DEBUG)
    add_compile_definitions(V3_DEBUG)
endif()

# ═══════════════════════════════════════════════════════════════════════════
# 源文件
# ═══════════════════════════════════════════════════════════════════════════

set(V3_CORE_SOURCES
    src/v3_entry.c
    src/v3_exit.c
    src/v3_lifecycle.c
    src/v3_core_impl.c
    src/v3_config.c
    src/v3_ipc.c
    src/v3_guard.c
    src/v3_log.c
    src/v3_stats.c
    src/v3_buffer.c
    src/v3_thread.c
    src/v3_crypto.c
    src/v3_protocol.c
    src/v3_connection.c
    src/v3_fec.c
    src/v3_pacing.c
    src/v3_network.c
)

# Windows 平台特定源文件
if(WIN32)
    list(APPEND V3_CORE_SOURCES
        src/win_platform.c
        src/win_pipe.c
        src/win_process.c
        src/win_memory.c
        src/win_socket.c
        src/win_iocp.c
    )
endif()

set(V3_HEADERS
    include/v3_core.h
    include/v3_types.h
    include/v3_error.h
    include/v3_exit.h
    include/v3_ipc.h
    include/v3_config.h
    include/v3_lifecycle.h
    include/v3_platform.h
    include/v3_guard.h
    include/v3_crypto.h
    include/v3_protocol.h
    include/v3_connection.h
    include/v3_fec.h
    include/v3_pacing.h
    include/v3_network.h
    include/v3_buffer.h
    include/v3_log.h
    include/v3_stats.h
    include/v3_thread.h
)

# ═══════════════════════════════════════════════════════════════════════════
# 库目标
# ═══════════════════════════════════════════════════════════════════════════

# 静态库
if(V3_BUILD_STATIC)
    add_library(v3_core_static STATIC ${V3_CORE_SOURCES})
    target_include_directories(v3_core_static PUBLIC include)
    set_target_properties(v3_core_static PROPERTIES OUTPUT_NAME v3_core)
    
    if(WIN32)
        target_link_libraries(v3_core_static PRIVATE ws2_32 mswsock)
    else()
        target_link_libraries(v3_core_static PRIVATE pthread)
    endif()
endif()

# 动态库
if(V3_BUILD_SHARED)
    add_library(v3_core_shared SHARED ${V3_CORE_SOURCES})
    target_include_directories(v3_core_shared PUBLIC include)
    set_target_properties(v3_core_shared PROPERTIES OUTPUT_NAME v3_core)
    
    # Windows DLL 导出
    if(WIN32)
        target_compile_definitions(v3_core_shared PRIVATE V3_BUILD_DLL)
        target_link_libraries(v3_core_shared PRIVATE ws2_32 mswsock)
    else()
        target_link_libraries(v3_core_shared PRIVATE pthread)
    endif()
endif()

# ═══════════════════════════════════════════════════════════════════════════
# 测试
# ═══════════════════════════════════════════════════════════════════════════

if(V3_BUILD_TESTS)
    enable_testing()
    
    set(V3_TEST_SOURCES
        test/test_main.c
        test/test_crypto.c
        test/test_protocol.c
        test/test_fec.c
        test/test_connection.c
    )
    
    add_executable(v3_test ${V3_TEST_SOURCES})
    target_include_directories(v3_test PRIVATE include)
    
    if(V3_BUILD_STATIC)
        target_link_libraries(v3_test PRIVATE v3_core_static)
    else()
        target_link_libraries(v3_test PRIVATE v3_core_shared)
    endif()
    
    # CTest 集成
    add_test(NAME v3_core_tests COMMAND v3_test)
    
    # 单独的测试目标
    add_custom_target(run_tests
        COMMAND v3_test
        DEPENDS v3_test
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running v3 core tests..."
    )
endif()

# ═══════════════════════════════════════════════════════════════════════════
# 安装
# ═══════════════════════════════════════════════════════════════════════════

include(GNUInstallDirs)

if(V3_BUILD_STATIC)
    install(TARGETS v3_core_static
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()

if(V3_BUILD_SHARED)
    install(TARGETS v3_core_shared
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

install(FILES ${V3_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/v3_core
)

# ═══════════════════════════════════════════════════════════════════════════
# 信息输出
# ═══════════════════════════════════════════════════════════════════════════

message(STATUS "")
message(STATUS "╔═══════════════════════════════════════════════════════════════╗")
message(STATUS "║                    v3 Core Configuration                      ║")
message(STATUS "╚═══════════════════════════════════════════════════════════════╝")
message(STATUS "")
message(STATUS "  Version:       ${PROJECT_VERSION}")
message(STATUS "  Build Type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler:      ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Platform:      ${CMAKE_SYSTEM_NAME}")
message(STATUS "")
message(STATUS "  Build Shared:  ${V3_BUILD_SHARED}")
message(STATUS "  Build Static:  ${V3_BUILD_STATIC}")
message(STATUS "  Build Tests:   ${V3_BUILD_TESTS}")
message(STATUS "  Debug Mode:    ${V3_ENABLE_DEBUG}")
message(STATUS "")
