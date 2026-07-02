// native/src/pal_windows.cpp
#include "pal.h"
#include <windows.h>
#include <dpapi.h>
#include <iostream>
#include <vector>
#include <random>
#include <algorithm>

struct CppMemorySlot {
    void* write_ptr;
    void* read_ptr;
    size_t size;
    bool in_use;
    HANDLE hMapping;
};

// Ensure DPAPI buffer requirements (must be multiple of 16 bytes)
#define DPAPI_BLOCK_SIZE 16

extern "C" {

void* pal_alloc_secure(size_t size) {
    // VirtualAlloc allocates page-aligned memory. We start with PAGE_NOACCESS.
    void* ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    return ptr;
}

bool pal_unlock(void* ptr, size_t size) {
    DWORD oldProtect;
    return VirtualProtect(ptr, size, PAGE_READWRITE, &oldProtect) != 0;
}

bool pal_lock(void* ptr, size_t size) {
    DWORD oldProtect;
    return VirtualProtect(ptr, size, PAGE_NOACCESS, &oldProtect) != 0;
}

void pal_secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        SecureZeroMemory(ptr, size);
    }
}

void pal_free_secure(void* ptr, size_t size) {
    if (ptr) {
        // Zero memory before release to ensure no residue in virtual space
        // Note: VirtualFree releases the whole allocation, so size is ignored for release
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

bool pal_is_debugger_attached(void) {
    // 1. Basic Win32 Check
    if (IsDebuggerPresent()) {
        return true;
    }

    // 2. Check Remote Debugger
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        return true;
    }

    // 3. Hardware Breakpoints check (DR0 - DR3)
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true; // Debugger has set a hardware breakpoint
        }
    }

    return false;
}

bool pal_timing_check(uint64_t* start_time) {
    LARGE_INTEGER li;
    if (start_time == NULL) return false;

    if (*start_time == 0) {
        // Record starting time
        QueryPerformanceCounter(&li);
        *start_time = static_cast<uint64_t>(li.QuadPart);
        return false;
    } else {
        // Measure elapsed time
        QueryPerformanceCounter(&li);
        uint64_t end = static_cast<uint64_t>(li.QuadPart);
        
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        
        double elapsed_ms = (double)(end - *start_time) * 1000.0 / (double)freq.QuadPart;
        
        // If execution between steps took more than 500ms, it implies timing side-channel
        // or a human debugger single-stepping through code.
        if (elapsed_ms > 500.0) {
            return true;
        }
        return false;
    }
}

void pal_kill_if_debugged(void) {
    // Force crash using a status violation to prevent standard OS exception handling
    ExitProcess(0xC0000005); 
}

// Global encrypted buffer for key storage allocated dynamically via VirtualAlloc to avoid BSS/data scan
static uint8_t* g_encrypted_key_ptr = nullptr;
static size_t g_allocated_size = 0;
static size_t g_key_len = 0;

bool pal_store_key(const uint8_t* key, size_t len) {
    // Size must be aligned to 16 bytes for CryptProtectMemory
    size_t aligned_len = ((len + DPAPI_BLOCK_SIZE - 1) / DPAPI_BLOCK_SIZE) * DPAPI_BLOCK_SIZE;
    
    if (g_encrypted_key_ptr == nullptr) {
        g_allocated_size = 4096; // 1 page (isolated in virtual memory)
        g_encrypted_key_ptr = (uint8_t*)VirtualAlloc(NULL, g_allocated_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (g_encrypted_key_ptr == nullptr) return false;
    } else {
        // Zero out old key storage
        SecureZeroMemory(g_encrypted_key_ptr, g_allocated_size);
    }
    
    if (aligned_len > g_allocated_size) return false;
    
    // Copy key to aligned global storage
    memcpy(g_encrypted_key_ptr, key, len);
    g_key_len = len;

    // Encrypt in memory. CRYPTPROTECTMEMORY_SAME_PROCESS ensures it only decrypts in this process space.
    BOOL success = CryptProtectMemory(g_encrypted_key_ptr, static_cast<DWORD>(aligned_len), CRYPTPROTECTMEMORY_SAME_PROCESS);
    return success != 0;
}

bool pal_retrieve_key(uint8_t* buf, size_t len) {
    if (g_key_len == 0 || len < g_key_len || g_encrypted_key_ptr == nullptr) return false;

    size_t aligned_len = ((g_key_len + DPAPI_BLOCK_SIZE - 1) / DPAPI_BLOCK_SIZE) * DPAPI_BLOCK_SIZE;
    
    // Temp buffer to decrypt
    uint8_t temp_buf[256] = {0};
    if (aligned_len > sizeof(temp_buf)) return false;
    memcpy(temp_buf, g_encrypted_key_ptr, aligned_len);

    // Decrypt in memory
    BOOL success = CryptUnprotectMemory(temp_buf, static_cast<DWORD>(aligned_len), CRYPTPROTECTMEMORY_SAME_PROCESS);
    if (!success) {
        SecureZeroMemory(temp_buf, sizeof(temp_buf));
        return false;
    }

    // Copy original key length back to user buffer
    memcpy(buf, temp_buf, g_key_len);
    
    // Immediately clean up stack
    SecureZeroMemory(temp_buf, sizeof(temp_buf));
    return true;
}

// ==========================================
// C++ Page Memory Pool Implementation
// ==========================================
static bool g_use_shuffling = false;
static bool g_use_tiered = false;
static size_t g_capped_pool_size = 0;
static bool g_use_hybrid = false;
static size_t g_max_layer_size = 0;
static size_t g_avail_ram = 0;

static std::vector<CppMemorySlot> g_pool;
static bool g_pool_initialized = false;

bool pal_configure_pool(bool use_shuffling, bool use_tiered, size_t capped_size, bool use_hybrid, size_t max_layer_size, size_t avail_ram) {
    g_use_shuffling = use_shuffling;
    g_use_tiered = use_tiered;
    g_capped_pool_size = capped_size;
    g_use_hybrid = use_hybrid;
    g_max_layer_size = max_layer_size;
    g_avail_ram = avail_ram;

    // Determine if we should use the pool based on Hybrid Mode
    bool use_pool = g_use_shuffling;
    if (g_use_shuffling && g_use_hybrid) {
        size_t pool_cost = g_max_layer_size * 4;
        if (g_use_tiered) {
            pool_cost = (3 * 4 * 1024 * 1024) + (2 * 32 * 1024 * 1024) + (2 * g_max_layer_size);
        }
        if (g_max_layer_size > g_capped_pool_size || pool_cost > (g_avail_ram * 0.20)) {
            use_pool = false; // Fallback to standard JIT
        }
    }

    // Clean up old pool if exists
    for (auto& slot : g_pool) {
        if (slot.write_ptr) UnmapViewOfFile(slot.write_ptr);
        if (slot.read_ptr) UnmapViewOfFile(slot.read_ptr);
        if (slot.hMapping) CloseHandle(slot.hMapping);
    }
    g_pool.clear();
    g_pool_initialized = false;

    if (use_pool && g_max_layer_size > 0) {
        auto create_slot = [](size_t sz, std::vector<CppMemorySlot>& pool) {
            CppMemorySlot slot = { nullptr, nullptr, sz, false, NULL };
            slot.hMapping = CreateFileMapping(
                INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, static_cast<DWORD>(sz), NULL
            );
            if (!slot.hMapping) return;
            slot.write_ptr = MapViewOfFile(slot.hMapping, FILE_MAP_WRITE, 0, 0, sz);
            slot.read_ptr = MapViewOfFile(slot.hMapping, FILE_MAP_READ, 0, 0, sz);
            if (slot.write_ptr && slot.read_ptr) {
                DWORD oldProtect;
                VirtualProtect(slot.write_ptr, sz, PAGE_NOACCESS, &oldProtect);
                VirtualProtect(slot.read_ptr, sz, PAGE_NOACCESS, &oldProtect);
                pool.push_back(slot);
            } else {
                if (slot.write_ptr) UnmapViewOfFile(slot.write_ptr);
                if (slot.read_ptr) UnmapViewOfFile(slot.read_ptr);
                CloseHandle(slot.hMapping);
            }
        };

        if (g_use_tiered) {
            // Tier 1 (Small): 4MB slots (3 slots)
            for (int i = 0; i < 3; ++i) {
                create_slot(4 * 1024 * 1024, g_pool);
            }
            // Tier 2 (Medium): 32MB slots (2 slots)
            for (int i = 0; i < 2; ++i) {
                create_slot(32 * 1024 * 1024, g_pool);
            }
            // Tier 3 (Large): max_layer_size slots (2 slots)
            size_t large_size = g_max_layer_size;
            if (large_size < 32 * 1024 * 1024) {
                large_size = 32 * 1024 * 1024;
            }
            for (int i = 0; i < 2; ++i) {
                create_slot(large_size, g_pool);
            }
        } else {
            // Uniform pool: 4 slots of max_layer_size
            for (int i = 0; i < 4; ++i) {
                create_slot(g_max_layer_size, g_pool);
            }
        }
        g_pool_initialized = true;
    }

    return true;
}

void* pal_lease_secure_slot(size_t required_size, size_t* allocated_size) {
    if (g_pool_initialized && !g_pool.empty()) {
        std::vector<CppMemorySlot*> available;
        for (auto& slot : g_pool) {
            if (!slot.in_use && slot.size >= required_size) {
                available.push_back(&slot);
            }
        }

        if (!available.empty()) {
            CppMemorySlot* leased = nullptr;
            if (g_use_shuffling) {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(0, static_cast<int>(available.size()) - 1);
                leased = available[dis(gen)];
            } else {
                leased = available[0];
            }

            leased->in_use = true;
            if (allocated_size) {
                *allocated_size = leased->size;
            }
            
            // Unlock write view to PAGE_READWRITE for decryption
            DWORD oldProtect;
            VirtualProtect(leased->write_ptr, leased->size, PAGE_READWRITE, &oldProtect);
            return leased->write_ptr;
        }
    }

    // Fallback: Allocate dynamically (standard JIT allocation)
    void* ptr = pal_alloc_secure(required_size);
    if (ptr) {
        DWORD oldProtect;
        VirtualProtect(ptr, required_size, PAGE_READWRITE, &oldProtect);
        if (allocated_size) {
            *allocated_size = required_size;
        }
    }
    return ptr;
}

void* pal_get_read_view(void* write_ptr, size_t allocated_size) {
    if (write_ptr == nullptr) return nullptr;

    if (g_pool_initialized) {
        for (auto& slot : g_pool) {
            if (slot.write_ptr == write_ptr) {
                DWORD oldProtect;
                // Transition write view to PAGE_NOACCESS
                VirtualProtect(slot.write_ptr, slot.size, PAGE_NOACCESS, &oldProtect);
                // Transition read view to PAGE_READONLY
                VirtualProtect(slot.read_ptr, slot.size, PAGE_READONLY, &oldProtect);
                return slot.read_ptr;
            }
        }
    }

    // Fallback: Dynamic allocation is not double-mapped, return write_ptr itself
    return write_ptr;
}

void pal_release_secure_slot(void* ptr, size_t allocated_size) {
    if (ptr == nullptr) return;

    if (g_pool_initialized) {
        for (auto& slot : g_pool) {
            if (slot.write_ptr == ptr || slot.read_ptr == ptr) {
                DWORD oldProtect;
                // Lock read view
                VirtualProtect(slot.read_ptr, slot.size, PAGE_NOACCESS, &oldProtect);
                // Unlock write view to PAGE_READWRITE to zero-wipe
                VirtualProtect(slot.write_ptr, slot.size, PAGE_READWRITE, &oldProtect);
                SecureZeroMemory(slot.write_ptr, slot.size);
                // Lock write view back
                VirtualProtect(slot.write_ptr, slot.size, PAGE_NOACCESS, &oldProtect);
                slot.in_use = false;
                return;
            }
        }
    }

    // Fallback: Standard JIT free
    DWORD oldProtect;
    VirtualProtect(ptr, allocated_size, PAGE_READWRITE, &oldProtect);
    SecureZeroMemory(ptr, allocated_size);
    pal_free_secure(ptr, allocated_size);
}

bool pal_compact_pool() {
    std::vector<CppMemorySlot> active_slots;
    for (auto& slot : g_pool) {
        if (slot.in_use) {
            active_slots.push_back(slot);
        } else {
            if (slot.write_ptr) UnmapViewOfFile(slot.write_ptr);
            if (slot.read_ptr) UnmapViewOfFile(slot.read_ptr);
            if (slot.hMapping) CloseHandle(slot.hMapping);
        }
    }
    g_pool = active_slots;
    if (g_pool.empty()) {
        g_pool_initialized = false;
    }
    return true;
}

} // extern "C"
