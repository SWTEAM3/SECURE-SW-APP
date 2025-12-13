#pragma once   // 헤더 중복 include 방지

#include <stdint.h>
#include <stddef.h>

#include "crypto/core/blockcipher.h"
#include "crypto/mode/mode_ctr.h"
#include "crypto/hash/hash_sha512.h"
#include "crypto/hash/hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

    // 0 = OK, 음수 = 오류 코드

    int stream_encrypt_ctr_file(const blockcipher_vtable_t* engine,
        const char* in_path,
        const char* out_path,
        const unsigned char* key,
        int key_len,
        const unsigned char iv[CTR_BLOCK_BYTES]);

    int stream_decrypt_ctr_file(const blockcipher_vtable_t* engine,
        const char* in_path,
        const char* out_path,
        const unsigned char* key,
        int key_len,
        const unsigned char iv[CTR_BLOCK_BYTES]);

    int stream_hash_sha512_file(const char* in_path,
        unsigned char out_digest[64]);

    int stream_hmac_sha512_file(const char* in_path,
        const unsigned char* key,
        size_t key_len,
        unsigned char out_mac[64]);

#ifdef __cplusplus
}
#endif
