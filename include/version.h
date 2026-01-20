
/*
 * v3 Core - Version Information
 * 
 * 版本信息头文件
 * 此文件由构建系统自动更新，也可手动修改
 */

#ifndef V3_VERSION_H
#define V3_VERSION_H

/* ═══════════════════════════════════════════════════════════════════════════
 * 版本号定义
 * ═══════════════════════════════════════════════════════════════════════════ */

#define V3_VERSION_MAJOR        1
#define V3_VERSION_MINOR        0
#define V3_VERSION_PATCH        0
#define V3_VERSION_BUILD        1

/* 版本字符串 */
#define V3_VERSION_STRING       "1.0.0"
#define V3_VERSION_FULL         "1.0.0.1"

/* 构建信息 */
#define V3_BUILD_DATE           __DATE__
#define V3_BUILD_TIME           __TIME__

/* 协议版本（必须与服务端一致） */
#define V3_PROTOCOL_VERSION     3
#define V3_PROTOCOL_MIN_VERSION 3

/* ═══════════════════════════════════════════════════════════════════════════
 * 产品信息
 * ═══════════════════════════════════════════════════════════════════════════ */

#define V3_PRODUCT_NAME         "v3 Core"
#define V3_PRODUCT_DESCRIPTION  "v3 Protocol Core Library"
#define V3_COMPANY_NAME         "v3 Project"
#define V3_COPYRIGHT            "Copyright (C) 2024"

/* ═══════════════════════════════════════════════════════════════════════════
 * 构建配置标识
 * ═══════════════════════════════════════════════════════════════════════════ */

#ifdef _DEBUG
#define V3_BUILD_TYPE           "Debug"
#else
#define V3_BUILD_TYPE           "Release"
#endif

#ifdef _WIN64
#define V3_ARCH                 "x64"
#else
#define V3_ARCH                 "x86"
#endif

/* 编译器标识 */
#if defined(_MSC_VER)
#define V3_COMPILER             "MSVC"
#define V3_COMPILER_VERSION     _MSC_VER
#elif defined(__MINGW64__)
#define V3_COMPILER             "MinGW-w64"
#define V3_COMPILER_VERSION     __GNUC__
#elif defined(__MINGW32__)
#define V3_COMPILER             "MinGW"
#define V3_COMPILER_VERSION     __GNUC__
#elif defined(__GNUC__)
#define V3_COMPILER             "GCC"
#define V3_COMPILER_VERSION     __GNUC__
#elif defined(__clang__)
#define V3_COMPILER             "Clang"
#define V3_COMPILER_VERSION     __clang_major__
#else
#define V3_COMPILER             "Unknown"
#define V3_COMPILER_VERSION     0
#endif

#endif /* V3_VERSION_H */
