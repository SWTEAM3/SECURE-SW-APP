#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    // 최대 256비트 키까지 관리하는 간단한 키 컨텍스트
    typedef struct key_context_t {
        unsigned char master_key[32];  // 256-bit
        unsigned char enc_key[32];     // 파생된 키
        unsigned int  enc_key_len;     // enc_key 길이(바이트)
    } key_context_t;

    // 랜덤 master_key 생성
    void key_context_init_random(key_context_t* kc);

    // seed 기반으로 master_key 생성(테스트/재현용)
    void key_context_init_seed(key_context_t* kc,
        const unsigned char* seed,
        unsigned int seed_len);

    // master_key에서 enc_key 파생
    // key_len_bytes: 16(128) / 24(192) / 32(256)
    void key_context_derive(key_context_t* kc, unsigned int key_len_bytes);

    // 메모리 지우기
    void key_context_clear(key_context_t* kc);

#ifdef __cplusplus
}
#endif
