// native/src/pal_android.cpp
#include "pal.h"
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <stdio.h>

extern "C" {

void* pal_alloc_secure(size_t size) {
    void* ptr = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
        // explicit_bzero is supported in Android NDK API 24+
        #if __ANDROID_API__ >= 24
            explicit_bzero(ptr, size);
        #else
            volatile unsigned char* p = (volatile unsigned char*)ptr;
            while (size--) *p++ = 0;
        #endif
    }
}

void pal_free_secure(void* ptr, size_t size) {
    if (ptr) {
        munmap(ptr, size);
    }
}

bool pal_is_debugger_attached(void) {
    // 1. TracerPid check via /proc/self/status
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd != -1) {
        char buf[4096];
        ssize_t num_read = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (num_read > 0) {
            buf[num_read] = '\0';
            char* tracer_pid_line = strstr(buf, "TracerPid:");
            if (tracer_pid_line) {
                int tracer_pid = 0;
                sscanf(tracer_pid_line, "TracerPid:\t%d", &tracer_pid);
                if (tracer_pid != 0) {
                    return true;
                }
            }
        }
    }

    // 2. Try ptrace self-attach to block external debuggers
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return true;
    }
    ptrace(PTRACE_DETACH, 0, 1, 0);

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

// In-Memory Key Obfuscation Fallback for Android (XOR Splitting)
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
