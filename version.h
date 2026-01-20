
/**
 * @file version.h
 * @brief v3 Core - 版本信息
 */

#ifndef V3_VERSION_H
#define V3_VERSION_H

/* 版本号 */
#define V3_VERSION_MAJOR    1
#define V3_VERSION_MINOR    0
#define V3_VERSION_PATCH    0

/* 版本字符串 */
#define V3_VERSION_STRING   "1.0.0"

/* 完整版本（带构建信息）*/
#define V3_VERSION_FULL     V3_VERSION_STRING

/* 构建时间（由编译器填充）*/
#ifndef V3_BUILD_TIME
    #define V3_BUILD_TIME   __DATE__ " " __TIME__
#endif

/* 构建平台 */
#if defined(_WIN64)
    #define V3_BUILD_PLATFORM   "Windows x64"
#elif defined(_WIN32)
    #define V3_BUILD_PLATFORM   "Windows x86"
#elif defined(__linux__)
    #if defined(__x86_64__)
        #define V3_BUILD_PLATFORM   "Linux x64"
    #elif defined(__aarch64__)
        #define V3_BUILD_PLATFORM   "Linux ARM64"
    #else
        #define V3_BUILD_PLATFORM   "Linux"
    #endif
#elif defined(__APPLE__)
    #define V3_BUILD_PLATFORM   "macOS"
#else
    #define V3_BUILD_PLATFORM   "Unknown"
#endif

/* 编译器信息 */
#if defined(_MSC_VER)
    #define V3_BUILD_COMPILER   "MSVC " V3_STRINGIFY(_MSC_VER)
#elif defined(__clang__)
    #define V3_BUILD_COMPILER   "Clang " __clang_version__
#elif defined(__GNUC__)
    #define V3_BUILD_COMPILER   "GCC " __VERSION__
#else
    #define V3_BUILD_COMPILER   "Unknown"
#endif

/* 辅助宏 */
#define V3_STRINGIFY_(x)    #x
#define V3_STRINGIFY(x)     V3_STRINGIFY_(x)

/* 版本号数值（用于比较）*/
#define V3_VERSION_NUMBER   ((V3_VERSION_MAJOR * 10000) + \
                             (V3_VERSION_MINOR * 100) + \
                             V3_VERSION_PATCH)

/* Banner */
#define V3_BANNER \
    "╔═══════════════════════════════════════════════════════════════╗\n" \
    "║                    v3 Core for Windows                        ║\n" \
    "║               High-Performance UDP Protocol                   ║\n" \
    "╚═══════════════════════════════════════════════════════════════╝"

#endif /* V3_VERSION_H */

