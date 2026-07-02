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
#include <vector>
#include <random>
#include <algorithm>

struct CppMemorySlot {
    void* write_ptr;
    void* read_ptr;
    size_t size;
    bool in_use;
    int fd;
};

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
        if (slot.write_ptr) munmap(slot.write_ptr, slot.size);
        if (slot.read_ptr) munmap(slot.read_ptr, slot.size);
        if (slot.fd >= 0) close(slot.fd);
    }
    g_pool.clear();
    g_pool_initialized = false;

    if (use_pool && g_max_layer_size > 0) {
        auto create_slot = [](size_t sz, std::vector<CppMemorySlot>& pool) {
            CppMemorySlot slot = { nullptr, nullptr, sz, false, -1 };
            char shm_name[64];
            snprintf(shm_name, sizeof(shm_name), "/vajra_shm_%d_%ld", getpid(), random());
            slot.fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
            if (slot.fd >= 0) {
                shm_unlink(shm_name); // Unlink immediately so no other process can access it
                if (ftruncate(slot.fd, sz) >= 0) {
                    slot.write_ptr = mmap(NULL, sz, PROT_NONE, MAP_SHARED, slot.fd, 0);
                    slot.read_ptr = mmap(NULL, sz, PROT_NONE, MAP_SHARED, slot.fd, 0);
                    if (slot.write_ptr != MAP_FAILED && slot.read_ptr != MAP_FAILED) {
                        pool.push_back(slot);
                        return;
                    }
                    if (slot.write_ptr != MAP_FAILED) munmap(slot.write_ptr, sz);
                    if (slot.read_ptr != MAP_FAILED) munmap(slot.read_ptr, sz);
                }
                close(slot.fd);
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
            
            // Unlock write view to writable for decryption
            mprotect(leased->write_ptr, leased->size, PROT_READ | PROT_WRITE);
            return leased->write_ptr;
        }
    }

    // Fallback: Allocate dynamically (standard JIT allocation)
    void* ptr = pal_alloc_secure(required_size);
    if (ptr) {
        mprotect(ptr, required_size, PROT_READ | PROT_WRITE);
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
                // Transition write view to PROT_NONE
                mprotect(slot.write_ptr, slot.size, PROT_NONE);
                // Transition read view to PROT_READ
                mprotect(slot.read_ptr, slot.size, PROT_READ);
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
                // Lock read view
                mprotect(slot.read_ptr, slot.size, PROT_NONE);
                // Unlock write view to PROT_READ | PROT_WRITE to zero-wipe
                mprotect(slot.write_ptr, slot.size, PROT_READ | PROT_WRITE);
                pal_secure_zero(slot.write_ptr, slot.size);
                // Lock write view back
                mprotect(slot.write_ptr, slot.size, PROT_NONE);
                slot.in_use = false;
                return;
            }
        }
    }

    // Fallback: Standard JIT free
    mprotect(ptr, allocated_size, PROT_READ | PROT_WRITE);
    pal_secure_zero(ptr, allocated_size);
    pal_free_secure(ptr, allocated_size);
}

bool pal_compact_pool() {
    std::vector<CppMemorySlot> active_slots;
    for (auto& slot : g_pool) {
        if (slot.in_use) {
            active_slots.push_back(slot);
        } else {
            if (slot.write_ptr) munmap(slot.write_ptr, slot.size);
            if (slot.read_ptr) munmap(slot.read_ptr, slot.size);
            if (slot.fd >= 0) close(slot.fd);
        }
    }
    g_pool = active_slots;
    if (g_pool.empty()) {
        g_pool_initialized = false;
    }
    return true;
}

} // extern "C"
