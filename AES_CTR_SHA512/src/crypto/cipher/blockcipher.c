#include "crypto/core/blockcipher.h"
#include "crypto/status.h"

#include <stdlib.h>

// blockcipher_init:
// - 엔진의 init 함수(vtable->init)를 호출
// - 실패하면 NULL 반환
blockcipher_t* blockcipher_init(const blockcipher_vtable_t* engine,
    const unsigned char* key,
    int key_len)
{
    if (!engine || !engine->init || !key || key_len <= 0)
        return NULL;

    blockcipher_t* bc = (blockcipher_t*)malloc(sizeof(blockcipher_t));
    if (!bc) return NULL;

    bc->vtable = engine;
    bc->ctx = engine->init(key, key_len);

    if (!bc->ctx) {
        free(bc);
        return NULL;
    }

    return bc;
}

// blockcipher_free:
// - 내부 ctx free
// - 구조체 free
void blockcipher_free(blockcipher_t* bc)
{
    if (!bc) return;
    if (bc->vtable && bc->vtable->free && bc->ctx)
        bc->vtable->free(bc->ctx);
    free(bc);
}
