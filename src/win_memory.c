
/*
 * win_memory.c - Windows Memory Management
 * 
 * 功能：
 * - 内存分配/释放
 * - 对齐内存分配
 * - 内存映射
 * - 大页面支持
 * - 内存池
 * 
 * 版权所有 (c) 2024 v3 项目
 */

#ifdef _WIN32

#include "v3_platform.h"
#include "v3_buffer.h"
#include "v3_error.h"
#include "v3_log.h"

#include <windows.h>

/* =========================================================
 * 常量定义
 * ========================================================= */

#define V3_DEFAULT_ALIGNMENT    16
#define V3_CACHE_LINE_SIZE      64
#define V3_PAGE_SIZE            4096

/* =========================================================
 * 全局状态
 * ========================================================= */

static struct {
    bool        large_pages_enabled;
    SIZE_T      large_page_min;
    SIZE_T      total_allocated;
    SIZE_T      peak_allocated;
    v3_mutex_t  stats_lock;
} g_memory = {0};

/* =========================================================
 * 初始化
 * ========================================================= */

int v3_memory_init(void) {
    /* 初始化统计锁 */
    if (v3_mutex_init(&g_memory.stats_lock) != V3_OK) {
        return V3_ERR_SYSTEM;
    }

    /* 尝试启用大页面支持 */
    g_memory.large_page_min = GetLargePageMinimum();
    
    if (g_memory.large_page_min > 0) {
        /* 需要 SeLockMemoryPrivilege 权限 */
        HANDLE token;
        if (OpenProcessToken(GetCurrentProcess(), 
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            
            if (LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, 
                                     &tp.Privileges[0].Luid)) {
                if (AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL)) {
                    if (GetLastError() == ERROR_SUCCESS) {
                        g_memory.large_pages_enabled = true;
                        V3_LOG_INFO("Large pages enabled (min size: %zu KB)",
                                    g_memory.large_page_min / 1024);
                    }
                }
            }
            CloseHandle(token);
        }
    }

    return V3_OK;
}

void v3_memory_cleanup(void) {
    v3_mutex_destroy(&g_memory.stats_lock);
    
    V3_LOG_INFO("Memory stats: peak=%zu KB, current=%zu KB",
                g_memory.peak_allocated / 1024,
                g_memory.total_allocated / 1024);
}

/* =========================================================
 * 统计更新
 * ========================================================= */

static void update_stats_alloc(size_t size) {
    v3_mutex_lock(&g_memory.stats_lock);
    g_memory.total_allocated += size;
    if (g_memory.total_allocated > g_memory.peak_allocated) {
        g_memory.peak_allocated = g_memory.total_allocated;
    }
    v3_mutex_unlock(&g_memory.stats_lock);
}

static void update_stats_free(size_t size) {
    v3_mutex_lock(&g_memory.stats_lock);
    if (size <= g_memory.total_allocated) {
        g_memory.total_allocated -= size;
    }
    v3_mutex_unlock(&g_memory.stats_lock);
}

/* =========================================================
 * 基础内存分配
 * ========================================================= */

void* v3_malloc(size_t size) {
    if (size == 0) return NULL;
    
    void *ptr = HeapAlloc(GetProcessHeap(), 0, size);
    if (ptr) {
        update_stats_alloc(size);
    }
    return ptr;
}

void* v3_calloc(size_t count, size_t size) {
    size_t total = count * size;
    if (total == 0) return NULL;
    
    void *ptr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (ptr) {
        update_stats_alloc(total);
    }
    return ptr;
}

void* v3_realloc(void *ptr, size_t new_size) {
    if (!ptr) {
        return v3_malloc(new_size);
    }
    if (new_size == 0) {
        v3_free(ptr);
        return NULL;
    }
    
    SIZE_T old_size = HeapSize(GetProcessHeap(), 0, ptr);
    void *new_ptr = HeapReAlloc(GetProcessHeap(), 0, ptr, new_size);
    
    if (new_ptr) {
        update_stats_free(old_size);
        update_stats_alloc(new_size);
    }
    
    return new_ptr;
}

void v3_free(void *ptr) {
    if (!ptr) return;
    
    SIZE_T size = HeapSize(GetProcessHeap(), 0, ptr);
    HeapFree(GetProcessHeap(), 0, ptr);
    update_stats_free(size);
}

/* =========================================================
 * 对齐内存分配
 * ========================================================= */

void* v3_aligned_alloc(size_t alignment, size_t size) {
    if (size == 0) return NULL;
    if (alignment == 0) alignment = V3_DEFAULT_ALIGNMENT;
    
    /* 确保 alignment 是 2 的幂 */
    if ((alignment & (alignment - 1)) != 0) {
        return NULL;
    }
    
    void *ptr = _aligned_malloc(size, alignment);
    if (ptr) {
        update_stats_alloc(size);
    }
    return ptr;
}

void v3_aligned_free(void *ptr) {
    if (!ptr) return;
    
    /* 获取实际大小比较困难，这里简化处理 */
    _aligned_free(ptr);
}

/* =========================================================
 * 缓存对齐分配
 * ========================================================= */

void* v3_cache_aligned_alloc(size_t size) {
    return v3_aligned_alloc(V3_CACHE_LINE_SIZE, size);
}

/* =========================================================
 * 大页面分配
 * ========================================================= */

void* v3_large_page_alloc(size_t size) {
    if (!g_memory.large_pages_enabled || size < g_memory.large_page_min) {
        /* 回退到普通分配 */
        return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    
    /* 对齐到大页面大小 */
    SIZE_T aligned_size = (size + g_memory.large_page_min - 1) & 
                          ~(g_memory.large_page_min - 1);
    
    void *ptr = VirtualAlloc(
        NULL,
        aligned_size,
        MEM_COMMIT | MEM_RESERVE | MEM_LARGE_PAGES,
        PAGE_READWRITE
    );
    
    if (!ptr) {
        /* 回退到普通分配 */
        ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    
    if (ptr) {
        update_stats_alloc(aligned_size);
    }
    
    return ptr;
}

void v3_large_page_free(void *ptr, size_t size) {
    if (!ptr) return;
    
    VirtualFree(ptr, 0, MEM_RELEASE);
    update_stats_free(size);
}

/* =========================================================
 * 虚拟内存
 * ========================================================= */

void* v3_virtual_alloc(size_t size, uint32_t flags) {
    DWORD alloc_type = MEM_COMMIT | MEM_RESERVE;
    DWORD protect = PAGE_READWRITE;
    
    if (flags & V3_MEM_EXECUTABLE) {
        protect = PAGE_EXECUTE_READWRITE;
    }
    if (flags & V3_MEM_READONLY) {
        protect = PAGE_READONLY;
    }
    if (flags & V3_MEM_GUARD) {
        protect |= PAGE_GUARD;
    }
    
    return VirtualAlloc(NULL, size, alloc_type, protect);
}

void v3_virtual_free(void *ptr, size_t size) {
    (void)size;
    if (ptr) {
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

int v3_virtual_protect(void *ptr, size_t size, uint32_t flags) {
    DWORD protect = PAGE_READWRITE;
    DWORD old_protect;
    
    if (flags & V3_MEM_EXECUTABLE) {
        protect = PAGE_EXECUTE_READWRITE;
    }
    if (flags & V3_MEM_READONLY) {
        protect = PAGE_READONLY;
    }
    if (flags & V3_MEM_NOACCESS) {
        protect = PAGE_NOACCESS;
    }
    
    if (!VirtualProtect(ptr, size, protect, &old_protect)) {
        return V3_ERR_SYSTEM;
    }
    
    return V3_OK;
}

/* =========================================================
 * 内存锁定
 * ========================================================= */

int v3_memory_lock(void *ptr, size_t size) {
    if (!VirtualLock(ptr, size)) {
        return V3_ERR_SYSTEM;
    }
    return V3_OK;
}

int v3_memory_unlock(void *ptr, size_t size) {
    if (!VirtualUnlock(ptr, size)) {
        return V3_ERR_SYSTEM;
    }
    return V3_OK;
}

/* =========================================================
 * 内存映射文件
 * ========================================================= */

v3_mmap_t* v3_mmap_create(const char *filename, size_t size, bool writable) {
    v3_mmap_t *mmap = (v3_mmap_t*)v3_calloc(1, sizeof(v3_mmap_t));
    if (!mmap) return NULL;

    /* 打开或创建文件 */
    DWORD access = GENERIC_READ;
    DWORD share = FILE_SHARE_READ;
    DWORD create = OPEN_EXISTING;
    
    if (writable) {
        access |= GENERIC_WRITE;
        share |= FILE_SHARE_WRITE;
        create = OPEN_ALWAYS;
    }

    HANDLE file = CreateFileA(
        filename,
        access,
        share,
        NULL,
        create,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file == INVALID_HANDLE_VALUE) {
        v3_free(mmap);
        return NULL;
    }

    /* 获取或设置文件大小 */
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file, &file_size)) {
        CloseHandle(file);
        v3_free(mmap);
        return NULL;
    }

    if (file_size.QuadPart == 0 && size > 0) {
        /* 新文件，设置大小 */
        LARGE_INTEGER new_size;
        new_size.QuadPart = size;
        SetFilePointerEx(file, new_size, NULL, FILE_BEGIN);
        SetEndOfFile(file);
        file_size.QuadPart = size;
    }

    mmap->size = (size_t)file_size.QuadPart;

    /* 创建文件映射 */
    DWORD protect = writable ? PAGE_READWRITE : PAGE_READONLY;
    
    mmap->file_handle = file;
    mmap->map_handle = CreateFileMappingA(
        file,
        NULL,
        protect,
        0,
        0,
        NULL
    );

    if (!mmap->map_handle) {
        CloseHandle(file);
        v3_free(mmap);
        return NULL;
    }

    /* 映射视图 */
    DWORD map_access = writable ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ;
    
    mmap->data = MapViewOfFile(
        mmap->map_handle,
        map_access,
        0,
        0,
        0
    );

    if (!mmap->data) {
        CloseHandle(mmap->map_handle);
        CloseHandle(file);
        v3_free(mmap);
        return NULL;
    }

    mmap->writable = writable;
    return mmap;
}

void v3_mmap_destroy(v3_mmap_t *mmap) {
    if (!mmap) return;

    if (mmap->data) {
        UnmapViewOfFile(mmap->data);
    }
    if (mmap->map_handle) {
        CloseHandle(mmap->map_handle);
    }
    if (mmap->file_handle) {
        CloseHandle(mmap->file_handle);
    }

    v3_free(mmap);
}

int v3_mmap_sync(v3_mmap_t *mmap) {
    if (!mmap || !mmap->data) {
        return V3_ERR_INVALID_PARAM;
    }

    if (!FlushViewOfFile(mmap->data, mmap->size)) {
        return V3_ERR_SYSTEM;
    }

    return V3_OK;
}

/* =========================================================
 * 内存信息
 * ========================================================= */

void v3_memory_get_stats(v3_memory_stats_t *stats) {
    if (!stats) return;

    v3_mutex_lock(&g_memory.stats_lock);
    stats->total_allocated = g_memory.total_allocated;
    stats->peak_allocated = g_memory.peak_allocated;
    v3_mutex_unlock(&g_memory.stats_lock);

    /* 获取系统内存信息 */
    MEMORYSTATUSEX mem = {0};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);

    stats->system_total = mem.ullTotalPhys;
    stats->system_available = mem.ullAvailPhys;

    /* 获取进程内存信息 */
    PROCESS_MEMORY_COUNTERS pmc = {0};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        stats->process_working_set = pmc.WorkingSetSize;
        stats->process_peak_working_set = pmc.PeakWorkingSetSize;
    }

    stats->large_pages_enabled = g_memory.large_pages_enabled;
    stats->large_page_size = g_memory.large_page_min;
}

bool v3_memory_large_pages_available(void) {
    return g_memory.large_pages_enabled;
}

size_t v3_memory_page_size(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
}

#endif /* _WIN32 */
