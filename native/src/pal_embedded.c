// native/src/pal_embedded.c
#include "pal.h"
#include <string.h>

// Static buffer fallback for memory-constrained embedded environments
#define EMBEDDED_BUFFER_SIZE (1024 * 1024) // 1MB buffer limit
static uint8_t g_secure_pool[EMBEDDED_BUFFER_SIZE];
static bool g_pool_allocated = false;

void* pal_alloc_secure(size_t size) {
    if (size > EMBEDDED_BUFFER_SIZE || g_pool_allocated) {
        return NULL;
    }
    g_pool_allocated = true;
    return g_secure_pool;
}

bool pal_unlock(void* ptr, size_t size) {
    // On bare-metal, there is no virtual memory protection unless MPU is used.
    // Return true as a placeholder fallback.
    return true;
}

bool pal_lock(void* ptr, size_t size) {
    return true;
}

void pal_secure_zero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        volatile unsigned char* p = (volatile unsigned char*)ptr;
        while (size--) *p++ = 0;
    }
}

void pal_free_secure(void* ptr, size_t size) {
    if (ptr == g_secure_pool) {
        pal_secure_zero(g_secure_pool, EMBEDDED_BUFFER_SIZE);
        g_pool_allocated = false;
    }
}

bool pal_is_debugger_attached(void) {
    // Bare-metal checks depend heavily on MCU architecture (e.g. checking CoreDebug->DHCSR on ARM Cortex-M)
    return false;
}

bool pal_timing_check(uint64_t* start_time) {
    // Embedded timestamp checking (e.g. DWT cycle counter on Cortex-M)
    return false;
}

void pal_kill_if_debugged(void) {
    // Trigger system reset or infinite loop
    while (1);
}

static uint8_t g_stored_key[32] = {0};
static size_t g_key_len = 0;

bool pal_store_key(const uint8_t* key, size_t len) {
    if (len > sizeof(g_stored_key)) return false;
    memcpy(g_stored_key, key, len);
    g_key_len = len;
    return true;
}

bool pal_retrieve_key(uint8_t* buf, size_t len) {
    if (g_key_len == 0 || len < g_key_len) return false;
    memcpy(buf, g_stored_key, g_key_len);
    return true;
}
