#include "crypto/mode/mode_ctr.h"
#include "crypto/bytes.h"
#include <stdlib.h>
#include <string.h>

// CTR 모드 카운터 (big-endian counter)
// counter[15]가 LSB
static void ctr_increment(unsigned char counter[16])
{
    for (int i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) break; // carry 발생 시 중단
    }
}

// CTR 초기화
ctr_mode_ctx_t* ctr_mode_init(const blockcipher_vtable_t* engine,
    const unsigned char* key,
    int key_len,
    const unsigned char iv[16])
{
    if (!engine || !key || !iv) return NULL;

    ctr_mode_ctx_t* ctx = (ctr_mode_ctx_t*)calloc(1, sizeof(ctr_mode_ctx_t));
    if (!ctx) return NULL;

    ctx->bc = blockcipher_init(engine, key, key_len);
    if (!ctx->bc) {
        free(ctx);
        return NULL;
    }

    memcpy(ctx->counter, iv, 16);
    return ctx;
}

// CTR update (암/복호화 처리)
// len은 바이트 단위, 처리 후 counter 증가
void ctr_mode_update(ctr_mode_ctx_t* ctx,
    const unsigned char* in,
    unsigned char* out,
    int len)
{
    if (!ctx || !ctx->bc || !in || !out || len <= 0) return;
    
    // vtable과 함수 포인터 NULL 체크 추가
    if (!ctx->bc->vtable || !ctx->bc->vtable->encrypt_block || !ctx->bc->ctx) return;

    unsigned char ks[16]; // keystream block
    int offset = 0;

    while (offset < len) {
        // 1) counter를 AES로 암호화하여 keystream 생성
        ctx->bc->vtable->encrypt_block(ctx->bc->ctx, ctx->counter, ks);

        // 2) keystream과 XOR
        int chunk = (len - offset >= 16) ? 16 : (len - offset);
        for (int i = 0; i < chunk; i++) {
            out[offset + i] = in[offset + i] ^ ks[i];
        }

        offset += chunk;

        // 3) counter 증가
        ctr_increment(ctx->counter);
    }
}

// 해제
void ctr_mode_free(ctr_mode_ctx_t* ctx)
{
    if (!ctx) return;
    if (ctx->bc) blockcipher_free(ctx->bc);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}
