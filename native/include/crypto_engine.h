// native/include/crypto_engine.h
#ifndef VAJRAA_CRYPTO_ENGINE_H
#define VAJRAA_CRYPTO_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decrypts a buffer using AES-256-GCM.
 * @param ciphertext Pointer to the ciphertext buffer.
 * @param ciphertext_len Length of ciphertext in bytes.
 * @param key Pointer to the 32-byte AES key.
 * @param iv Pointer to the 12-byte initialization vector.
 * @param tag Pointer to the 16-byte authentication tag.
 * @param aad Pointer to the Associated Authenticated Data.
 * @param aad_len Length of AAD in bytes.
 * @param plaintext_out Pointer to the output buffer for decrypted plaintext. Must be at least ciphertext_len bytes.
 * @return true on success, false on failure.
 */
bool vajraa_decrypt_gcm(const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* key, const uint8_t* iv, const uint8_t* tag,
                       const uint8_t* aad, size_t aad_len,
                       uint8_t* plaintext_out);

#ifdef __cplusplus
}
#endif

#endif // VAJRAA_CRYPTO_ENGINE_H
