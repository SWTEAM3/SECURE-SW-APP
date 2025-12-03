#pragma once   // 🔴 이 한 줄이 없어서 무한 include 난 거야

#include <stdint.h>
#include <stddef.h>

#include "crypto/core/blockcipher.h"
#include "crypto/mode/mode_ctr.h"
#include "crypto/hash/hash_sha512.h"
#include "crypto/hash/hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

    // 0 = OK, 그 외 = 에러코드

    int stream_encrypt_ctr_file(const blockcipher_vtable_t* engine,
        const char* in_path,
        const char* out_path,
        const unsigned char* key,
        int key_len,
        const unsigned char iv[16]);

    int stream_decrypt_ctr_file(const blockcipher_vtable_t* engine,
        const char* in_path,
        const char* out_path,
        const unsigned char* key,
        int key_len,
        const unsigned char iv[16]);

    int stream_hash_sha512_file(const char* in_path,
        unsigned char out_digest[64]);

    int stream_hmac_sha512_file(const char* in_path,
        const unsigned char* key,
        size_t key_len,
        unsigned char out_mac[64]);

#ifdef __cplusplus
}
#endif
