// native/include/pal.h
#ifndef MODEL_SHIELD_PAL_H
#define MODEL_SHIELD_PAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==========================================
// 1. Secure Memory Allocation & Protection
// ==========================================

/**
 * Allocates page-aligned memory and sets it to be inaccessible (PAGE_NOACCESS / PROT_NONE).
 * @param size Size in bytes of memory to allocate (will be rounded up to page boundary).
 * @return Pointer to allocated memory, or NULL on failure.
 */
void* pal_alloc_secure(size_t size);

/**
 * Marks memory as readable and writable (PAGE_READWRITE / PROT_READ | PROT_WRITE).
 * @param ptr Pointer to the allocated memory.
 * @param size Size in bytes.
 * @return true on success, false on failure.
 */
bool pal_unlock(void* ptr, size_t size);

/**
 * Restores memory to be inaccessible (PAGE_NOACCESS / PROT_NONE).
 * @param ptr Pointer to the allocated memory.
 * @param size Size in bytes.
 * @return true on success, false on failure.
 */
bool pal_lock(void* ptr, size_t size);

/**
 * Securely overwrites memory with zeroes and guarantees the compiler will not optimize it out.
 * @param ptr Pointer to the memory to clear.
 * @param size Size in bytes.
 */
void pal_secure_zero(void* ptr, size_t size);

/**
 * Deallocates secure memory.
 * @param ptr Pointer to the memory to deallocate.
 * @param size Size in bytes.
 */
void pal_free_secure(void* ptr, size_t size);


// ==========================================
// 2. Anti-Debugging & Tamper Detection
// ==========================================

/**
 * Detects if a debugger is attached using native OS calls.
 * @return true if a debugger is detected, false otherwise.
 */
bool pal_is_debugger_attached(void);

/**
 * Checks for hardware timing anomalies indicative of step-through debugging.
 * Call this before and after critical blocks.
 * @param start_time Pass a pointer to a uint64_t to record the start, or 0 to verify delta.
 * @return true if timing anomaly detected, false otherwise.
 */
bool pal_timing_check(uint64_t* start_time);

/**
 * Wipes all session keys from memory and immediately terminates the process.
 */
void pal_kill_if_debugged(void);


// ==========================================
// 3. Secure Key Storage
// ==========================================

/**
 * Stores a key securely using OS-level protection (e.g. DPAPI on Windows, Keychain on macOS).
 * @param key Pointer to key buffer.
 * @param len Key length in bytes.
 * @return true on success, false on failure.
 */
bool pal_store_key(const uint8_t* key, size_t len);

/**
 * Retrieves a key previously stored using pal_store_key.
 * @param buf Output buffer for the key.
 * @param len Buffer length in bytes.
 * @return true on success, false on failure.
 */
bool pal_retrieve_key(uint8_t* buf, size_t len);

/**
 * Configures the native page memory pool.
 */
bool pal_configure_pool(bool use_shuffling, bool use_tiered, size_t capped_size, bool use_hybrid, size_t max_layer_size, size_t avail_ram);

/**
 * Leases a secure memory slot or allocates dynamically if pooling is disabled/fallback.
 */
void* pal_lease_secure_slot(size_t required_size, size_t* allocated_size);

/**
 * Releases a leased slot back to the pool, or frees it if dynamically allocated.
 */
void pal_release_secure_slot(void* ptr, size_t allocated_size);

#ifdef __cplusplus
}
#endif

#endif // MODEL_SHIELD_PAL_H
