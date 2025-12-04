#pragma once
#include "crypto/core/blockcipher.h"

#ifdef __cplusplus
extern "C" {
#endif

    // CTR(CountER) mode context
    // 블록암호 엔진(blockcipher_vtable)만 주입받고,
    // 내부 동작은 AES 등 특정 알고리즘을 몰라도 됨.

    typedef struct ctr_mode_ctx_t {
        blockcipher_t* bc;      // 블록암호 엔진
        unsigned char counter[16]; // 현재 카운터 블록
    } ctr_mode_ctx_t;

    // CTR 초기화: iv는 반드시 16바이트(블록 크기)
    ctr_mode_ctx_t* ctr_mode_init(const blockcipher_vtable_t* engine,
        const unsigned char* key,
        int key_len,
        const unsigned char iv[16]);

    // CTR update: in/out 버퍼는 같은 곳 가능 (XOR 기반)
    void ctr_mode_update(ctr_mode_ctx_t* ctx,
        const unsigned char* in,
        unsigned char* out,
        int len);

    // 해제
    void ctr_mode_free(ctr_mode_ctx_t* ctx);

#ifdef __cplusplus
}
#endif
