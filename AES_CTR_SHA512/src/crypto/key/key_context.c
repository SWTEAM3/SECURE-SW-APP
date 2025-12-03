#include "crypto/key/key_context.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

static void fill_random(unsigned char* out, size_t len)
{
    // 데모용 단순 난수. 실제로는 반드시 CSPRNG 써야 함.
    static int inited = 0;
    if (!inited) {
        srand((unsigned int)(time(NULL) ^ (uintptr_t)out));
        inited = 1;
    }
    for (size_t i = 0; i < len; i++) {
        out[i] = (unsigned char)(rand() & 0xFF);
    }
}

void key_context_init_random(key_context_t* kc)
{
    if (!kc) return;
    fill_random(kc->master_key, sizeof(kc->master_key));
    kc->enc_key_len = 0;
    memset(kc->enc_key, 0, sizeof(kc->enc_key));
}

void key_context_init_seed(key_context_t* kc,
    const unsigned char* seed,
    unsigned int seed_len)
{
    if (!kc) return;
    memset(kc->master_key, 0, sizeof(kc->master_key));

    // 아주 단순한 seed→master_key 확산 (데모용)
    for (unsigned int i = 0; i < seed_len; i++) {
        kc->master_key[i % sizeof(kc->master_key)] ^= seed[i];
        kc->master_key[(i * 7u) % sizeof(kc->master_key)] += (unsigned char)(seed[i] + i);
    }
    kc->enc_key_len = 0;
    memset(kc->enc_key, 0, sizeof(kc->enc_key));
}

void key_context_derive(key_context_t* kc, unsigned int key_len_bytes)
{
    if (!kc) return;
    if (key_len_bytes > sizeof(kc->master_key)) {
        key_len_bytes = (unsigned int)sizeof(kc->master_key);
    }
    kc->enc_key_len = key_len_bytes;

    // 여기서는 그냥 master_key 앞부분을 enc_key로 사용 (데모)
    memcpy(kc->enc_key, kc->master_key, key_len_bytes);
    if (key_len_bytes < sizeof(kc->enc_key)) {
        memset(kc->enc_key + key_len_bytes, 0, sizeof(kc->enc_key) - key_len_bytes);
    }
}

void key_context_clear(key_context_t* kc)
{
    if (!kc) return;
    memset(kc, 0, sizeof(*kc));
}
