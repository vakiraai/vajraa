// native/src/pal_macos.cpp
#include "pal.h"
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/sysctl.h>

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

extern "C" {

void* pal_alloc_secure(size_t size) {
    void* ptr = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (ptr == MAP_FAILED) return NULL;
    return ptr;
}

bool pal_unlock(void* ptr, size_t size) {
    return mprotect(ptr, size, PROT_READ | PROT_WRITE) == 0;
}

bool pal_lock(void* ptr, size_t size) {
    return mprotect(ptr, size, PROT_NONE) == 0;
}

void pal_secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        memset_s(ptr, size, 0, size); // macOS standard secure memory wipe
    }
}

void pal_free_secure(void* ptr, size_t size) {
    if (ptr) {
        munmap(ptr, size);
    }
}

bool pal_is_debugger_attached(void) {
    // 1. Check KERN_PROC sysctl to see if the process is traced
    int mib[4];
    struct kinfo_proc info;
    size_t size;
    info.kp_proc.p_flag = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    size = sizeof(info);
    
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if ((info.kp_proc.p_flag & P_TRACED) != 0) {
            return true;
        }
    }

    // 2. Call ptrace(PT_DENY_ATTACH) to prevent debuggers from attaching.
    // Note: If a debugger is already attached, this will immediately terminate the process.
    // If no debugger is attached, it denies any future attachment.
    ptrace(PT_DENY_ATTACH, 0, 0, 0);

    return false;
}

bool pal_timing_check(uint64_t* start_time) {
    if (start_time == NULL) return false;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;

    if (*start_time == 0) {
        *start_time = now;
        return false;
    } else {
        uint64_t elapsed_ms = now - *start_time;
        if (elapsed_ms > 500) {
            return true;
        }
        return false;
    }
}

void pal_kill_if_debugged(void) {
    _exit(1);
}

static uint8_t g_share1[256] = {0};
static uint8_t g_share2[256] = {0};
static size_t g_key_len = 0;

bool pal_store_key(const uint8_t* key, size_t len) {
    if (len > sizeof(g_share1)) return false;

    g_key_len = len;
    srand(time(NULL));

    for (size_t i = 0; i < len; ++i) {
        g_share1[i] = rand() % 256;
        g_share2[i] = key[i] ^ g_share1[i];
    }
    return true;
}

bool pal_retrieve_key(uint8_t* buf, size_t len) {
    if (g_key_len == 0 || len < g_key_len) return false;

    for (size_t i = 0; i < g_key_len; ++i) {
        buf[i] = g_share1[i] ^ g_share2[i];
    }
    return true;
}

} // extern "C"
