// native/src/crypto_engine.cpp
#include "crypto_engine.h"
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

extern "C" {

bool vajraa_decrypt_gcm(const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* key, const uint8_t* iv, const uint8_t* tag,
                       uint8_t* plaintext_out) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // 1. Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    // 2. Set GCM chaining mode
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 3. Construct Key Data Blob to import raw key bytes (AES-256 = 32 bytes)
    DWORD keyBlobLen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + 32;
    PUCHAR pKeyBlob = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, keyBlobLen);
    if (!pKeyBlob) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    PBCRYPT_KEY_DATA_BLOB_HEADER pHeader = (PBCRYPT_KEY_DATA_BLOB_HEADER)pKeyBlob;
    pHeader->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    pHeader->dwVersion = 1; // BCRYPT_KEY_DATA_BLOB_VERSION_1
    pHeader->cbKeyData = 32;
    memcpy(pKeyBlob + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), key, 32);

    status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0, pKeyBlob, keyBlobLen, 0);
    SecureZeroMemory(pKeyBlob, keyBlobLen);
    HeapFree(GetProcessHeap(), 0, pKeyBlob);

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // 4. Configure Authenticated Cipher Mode Info struct for GCM decryption
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    memset(&authInfo, 0, sizeof(authInfo));
    authInfo.cbSize = sizeof(authInfo);
    authInfo.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = 16;

    // 5. Decrypt
    DWORD cbPlaintext = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)ciphertext_len, &authInfo, NULL, 0, plaintext_out, (ULONG)ciphertext_len, &cbPlaintext, 0);

    // Clean up
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
}

} // extern "C"

#else
// POSIX (Linux/macOS) production implementation using OpenSSL
#include <openssl/evp.h>

extern "C" {

bool vajraa_decrypt_gcm(const uint8_t* ciphertext, size_t ciphertext_len,
                       const uint8_t* key, const uint8_t* iv, const uint8_t* tag,
                       uint8_t* plaintext_out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int plaintext_len = 0;

    // 1. Initialize decryption context and GCM algorithm
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 2. Set GCM IV length (12 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 3. Initialize decryption with actual key and IV
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 4. Perform decryption update
    if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // 5. Provide the tag to EVP for authentication verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // 6. Finalize decryption. Checks the cryptographic authentication tag integrity.
    int ret = EVP_DecryptFinal_ex(ctx, plaintext_out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    return ret > 0;
}

} // extern "C"
#endif
