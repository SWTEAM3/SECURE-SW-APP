#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    // 블록 암호 엔진 공용 vtable 구조체
    typedef struct blockcipher_vtable_t {
        void* (*init)(const unsigned char* key, int key_len);
        void  (*encrypt_block)(void* ctx, const unsigned char in[16], unsigned char out[16]);
        void  (*decrypt_block)(void* ctx, const unsigned char in[16], unsigned char out[16]);
        void  (*free)(void* ctx);
    } blockcipher_vtable_t;

    // 엔진 컨텍스트
    typedef struct blockcipher_t {
        const blockcipher_vtable_t* vtable;
        void* ctx;
    } blockcipher_t;

    // blockcipher 초기화/해제
    blockcipher_t* blockcipher_init(const blockcipher_vtable_t* engine,
        const unsigned char* key,
        int key_len);

    void blockcipher_free(blockcipher_t* bc);

#ifdef __cplusplus
}
#endif
