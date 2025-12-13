#include "crypto/key/key_context.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define KC_MASTER_KEY_BYTES 32
#define KC_MAX_ENC_KEY_BYTES 32

static void fill_random(unsigned char* out, size_t len)
{
    // 데모용 단순 난수. 실제 배포에서는 /dev/urandom, BCryptGenRandom 등 CSPRNG를 사용해야 안전하다.
    // seed는 호출 포인터 주소와 현재 시각을 XOR해 단순 초기화한다.
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
    // master_key만 채우고 enc_key/len은 비워둔다.
    // 이후 derive 호출로 실제 사용 키를 확정한다.
    if (!kc) return;
    fill_random(kc->master_key, sizeof(kc->master_key));
    kc->enc_key_len = 0;
    memset(kc->enc_key, 0, KC_MAX_ENC_KEY_BYTES);
}

void key_context_init_seed(key_context_t* kc,
    const unsigned char* seed,
    unsigned int seed_len)
{
    // seed 바이트들을 단순히 XOR/덧셈으로 확산하는 데모용 파생.
    // 충돌 방지나 예측불가성이 부족하므로 실제 KDF(HKDF 등)로 교체해야 한다.
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
    // master_key 앞부분을 잘라 enc_key로 사용한다(데모).
    // 실제 환경에서는 KDF를 사용해 key_len_bytes 만큼 생성해야 한다.
    if (!kc) return;
    if (key_len_bytes > sizeof(kc->master_key)) {
        key_len_bytes = (unsigned int)KC_MASTER_KEY_BYTES;
    }
    kc->enc_key_len = key_len_bytes;

    // 여기서는 그냥 master_key 앞부분을 enc_key로 사용 (데모)
    memcpy(kc->enc_key, kc->master_key, key_len_bytes);
    if (key_len_bytes < KC_MAX_ENC_KEY_BYTES) {
        memset(kc->enc_key + key_len_bytes, 0, KC_MAX_ENC_KEY_BYTES - key_len_bytes);
    }
}

void key_context_clear(key_context_t* kc)
{
    // 구조체 전체를 0으로 덮어 민감 데이터 잔존을 최소화한다.
    if (!kc) return;
    memset(kc, 0, sizeof(*kc));
}
