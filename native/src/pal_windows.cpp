// native/src/pal_windows.cpp
#include "pal.h"
#include <windows.h>
#include <dpapi.h>
#include <iostream>

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

} // extern "C"
