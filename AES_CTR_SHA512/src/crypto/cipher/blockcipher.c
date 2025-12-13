#include "crypto/core/blockcipher.h"
#include "crypto/status.h"

#include <stdlib.h>

#define BLOCKCIPHER_MIN_KEY_LEN 1

// blockcipher_init:
// - 엔진 vtable을 받아 AES 등 구체 구현을 초기화하고 공통 래퍼 객체를 만든다.
// - vtable->init 에게 키/키길이만 위임하며, 실패 시 전체 생성도 실패.
blockcipher_t* blockcipher_init(const blockcipher_vtable_t* engine,
    const unsigned char* key,
    int key_len)
{
    if (!engine || !engine->init || !key || key_len < BLOCKCIPHER_MIN_KEY_LEN)
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
// - 엔진별 free를 먼저 호출한 뒤 래퍼를 해제한다.
void blockcipher_free(blockcipher_t* bc)
{
    if (!bc) return;
    if (bc->vtable && bc->vtable->free && bc->ctx)
        bc->vtable->free(bc->ctx);
    free(bc);
}
