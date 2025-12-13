#pragma once
#include "crypto/core/blockcipher.h"

#ifndef CTR_BLOCK_BYTES
#define CTR_BLOCK_BYTES 16
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // CTR(CountER) mode context
    // 블록암호 엔진(blockcipher_vtable)을 주입받고,
    // 모드 동작은 AES 같은 알고리즘 구현과 분리해 모듈화한다.

    typedef struct ctr_mode_ctx_t {
        blockcipher_t* bc;          // 블록암호 엔진
        unsigned char counter[CTR_BLOCK_BYTES]; // 현재 카운터 블록
    } ctr_mode_ctx_t;

    // CTR 초기화: iv는 반드시 CTR_BLOCK_BYTES(블록 크기)
    ctr_mode_ctx_t* ctr_mode_init(const blockcipher_vtable_t* engine,
        const unsigned char* key,
        int key_len,
        const unsigned char iv[CTR_BLOCK_BYTES]);

    // CTR update: in/out 버퍼가 같아도 동작(XOR 기반)
    void ctr_mode_update(ctr_mode_ctx_t* ctx,
        const unsigned char* in,
        unsigned char* out,
        int len);

    // 해제
    void ctr_mode_free(ctr_mode_ctx_t* ctx);

#ifdef __cplusplus
}
#endif
