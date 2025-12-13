#include "crypto/mode/mode_ctr.h"
#include "crypto/bytes.h"
#include <stdlib.h>
#include <string.h>

#ifndef CTR_BLOCK_BYTES
#define CTR_BLOCK_BYTES 16
#endif

// CTR 모드 카운터 (big-endian). counter[15]가 LSB이며 128비트 값을 1씩 증가시킨다.
static void ctr_increment(unsigned char counter[CTR_BLOCK_BYTES])
{
    for (int i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break; // 자리올림이 없으면 종료
    }
}

// CTR 초기화: 블록암호를 생성하고 초기 카운터(IV)를 설정한다.
ctr_mode_ctx_t* ctr_mode_init(const blockcipher_vtable_t* engine,
    const unsigned char* key,
    int key_len,
    const unsigned char iv[CTR_BLOCK_BYTES])
{
    if (!engine || !key || !iv) return NULL;

    ctr_mode_ctx_t* ctx = (ctr_mode_ctx_t*)calloc(1, sizeof(ctr_mode_ctx_t));
    if (!ctx) return NULL;

    ctx->bc = blockcipher_init(engine, key, key_len);
    if (!ctx->bc) {
        free(ctx);
        return NULL;
    }

    memcpy(ctx->counter, iv, CTR_BLOCK_BYTES);
    return ctx;
}

// CTR update: keystream을 생성해 입력과 XOR하여 암/복호화한다.
// in/out이 같은 버퍼여도 안전하며 len은 바이트 단위다.
void ctr_mode_update(ctr_mode_ctx_t* ctx,
    const unsigned char* in,
    unsigned char* out,
    int len)
{
    if (!ctx || !ctx->bc || !in || !out || len <= 0) return;
    if (!ctx->bc->vtable || !ctx->bc->vtable->encrypt_block || !ctx->bc->ctx) return;

    unsigned char ks[CTR_BLOCK_BYTES]; // keystream 블록
    int offset = 0;

    while (offset < len) {
        // 1) 카운터를 암호화해 keystream 생성
        ctx->bc->vtable->encrypt_block(ctx->bc->ctx, ctx->counter, ks);

        // 2) 입력과 XOR
        int chunk = (len - offset >= CTR_BLOCK_BYTES) ? CTR_BLOCK_BYTES : (len - offset);
        for (int i = 0; i < chunk; i++) {
            out[offset + i] = in[offset + i] ^ ks[i];
        }

        offset += chunk;

        // 3) 카운터 증가
        ctr_increment(ctx->counter);
    }
}

// CTR 컨텍스트를 정리하고 내용을 지운다.
void ctr_mode_free(ctr_mode_ctx_t* ctx)
{
    if (!ctx) return;
    if (ctx->bc) blockcipher_free(ctx->bc);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}
