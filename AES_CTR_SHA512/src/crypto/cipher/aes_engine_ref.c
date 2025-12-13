// ===============================================================
// AES Reference Engine (표준문서 스타일 AES 구현)
//  - S-box 수학적 구현 + 표준 라운드 구조
//  - 메모리 절약을 위해 on-the-fly 확장키 계산 방식을 사용
// ===============================================================

#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_sbox_math.h"
#include "crypto/cipher/gf256_math.h"
#include "crypto/core/blockcipher.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define AES_BLOCK_BYTES     16
#define AES_WORD_BYTES      4
#define AES_BLOCK_WORDS     (AES_BLOCK_BYTES / AES_WORD_BYTES) // 4
#define AES128_KEY_BYTES    16
#define AES192_KEY_BYTES    24
#define AES256_KEY_BYTES    32
#define AES_MAX_NK          8   // 256비트 키 -> 8 words
#define AES_MAX_NR          14  // Nk + 6
#define AES_MAX_EXP_WORDS   (AES_BLOCK_WORDS * (AES_MAX_NR + 1)) // 4*(14+1)=60
#define AES_RCON_LEN        10

// ---------------------------------------------------------------
// 내부 컨텍스트
// ---------------------------------------------------------------
typedef struct aes_ref_ctx_t {
    int Nk;                      // 키 길이를 32bit word 단위로 표현 (4/6/8)
    int Nr;                      // 라운드 수 (Nk + 6) -> 10/12/14
    unsigned char key[32];       // 원본 키 (round key를 매 라운드 계산할 때 사용)
    unsigned char sbox[256];     // SubBytes 테이블
    unsigned char inv_sbox[256]; // InvSubBytes 테이블
} aes_ref_ctx_t;

// =======================================================
// AES Key Expansion (표준 AES Key Schedule)
//  - 여기 구현은 on-the-fly 방식으로 동작하여
//    전체 확장키를 메모리에 보관하지 않아도 됨
// =======================================================

// Rcon 테이블
static const uint32_t RCON[AES_RCON_LEN] = {
    0x01000000U, 0x02000000U, 0x04000000U, 0x08000000U,
    0x10000000U, 0x20000000U, 0x40000000U, 0x80000000U,
    0x1B000000U, 0x36000000U
};

static uint32_t rot_word(uint32_t x) {
    return (x << 8) | (x >> 24);
}

static uint32_t sub_word(uint32_t x, const unsigned char sbox[256]) {
    return ((uint32_t)sbox[(x >> 24) & 0xFF] << 24) |
        ((uint32_t)sbox[(x >> 16) & 0xFF] << 16) |
        ((uint32_t)sbox[(x >> 8) & 0xFF] << 8) |
        ((uint32_t)sbox[(x >> 0) & 0xFF]);
}

// ---------------------------------------------------------------
// 특정 라운드 r 의 4워드 라운드 키를 on-the-fly 로 계산
//  - 표준 AES Key Schedule을 그대로 따르되, 필요한 구간만 즉석 계산
//  - round: 0..Nr, round_key[0..3] 에 해당 라운드 키를 채움
//  - 전체 확장키를 들고 있지 않아 메모리 사용량을 줄임 (대신 라운드마다 계산)
// ---------------------------------------------------------------
static void compute_round_key(uint32_t round_key[AES_BLOCK_WORDS],
    int round,
    const unsigned char* key,
    int Nk,
    int Nr,
    const unsigned char sbox[256]) {
    uint32_t w[AES_MAX_EXP_WORDS];   // 확장키 임시 버퍼 (AES-256 기준 최대 60워드)
    int total_words = AES_BLOCK_WORDS * (Nr + 1); // 전체 확장키 워드 수

    // 1) W[0..Nk-1] 에 원본 키를 채움 (big-endian 워드 구성)
    for (int i = 0; i < Nk; i++) {
        w[i] = ((uint32_t)key[AES_WORD_BYTES * i + 0] << 24) |
            ((uint32_t)key[AES_WORD_BYTES * i + 1] << 16) |
            ((uint32_t)key[AES_WORD_BYTES * i + 2] << 8) |
            ((uint32_t)key[AES_WORD_BYTES * i + 3]);
    }

    // 2) 라운드 r 에 필요한 W[4*r .. 4*r+3] 까지 계산
    int target_start = AES_BLOCK_WORDS * round;
    int target_end = target_start + AES_BLOCK_WORDS;

    if (target_start >= total_words) {
        // 범위 벗어나는 경우: 마지막 라운드 기준으로 조정
        target_start = AES_BLOCK_WORDS * Nr;
        target_end = target_start + AES_BLOCK_WORDS;
    }

    for (int i = Nk; i < target_end && i < total_words; i++) {
        uint32_t temp = w[i - 1];

        if (i % Nk == 0) {
            temp = rot_word(temp);
            temp = sub_word(temp, sbox);
            temp ^= RCON[(i / Nk) - 1];
        }
        else if (Nk > 6 && i % Nk == 4) {
            temp = sub_word(temp, sbox);
        }

        w[i] = w[i - Nk] ^ temp;
    }

    // 3) 해당 라운드의 4워드 반환
    round_key[0] = w[target_start + 0];
    round_key[1] = w[target_start + 1];
    round_key[2] = w[target_start + 2];
    round_key[3] = w[target_start + 3];
}

// =======================================================
// AES 라운드 연산 (표준 참고 구현)
// =======================================================

static inline unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static inline unsigned char mul2(unsigned char x) { return xtime(x); }
static inline unsigned char mul3(unsigned char x) { return (unsigned char)(xtime(x) ^ x); }

static inline unsigned char mul9(unsigned char x) {
    unsigned char a = xtime(xtime(xtime(x)));
    return (unsigned char)(a ^ x);
}
static inline unsigned char mul11(unsigned char x) {
    unsigned char a = xtime(xtime(xtime(x)));
    unsigned char b = xtime(x);
    return (unsigned char)(a ^ b ^ x);
}
static inline unsigned char mul13(unsigned char x) {
    unsigned char a = xtime(xtime(xtime(x)));
    unsigned char b = xtime(xtime(x));
    return (unsigned char)(a ^ b ^ x);
}
static inline unsigned char mul14(unsigned char x) {
    unsigned char a = xtime(xtime(xtime(x)));
    unsigned char b = xtime(xtime(x));
    unsigned char c = xtime(x);
    return (unsigned char)(a ^ b ^ c);
}

static void add_round_key(unsigned char state[16],
    const uint32_t* rk_words) {
    // rk_words: 4워드 = 16바이트 (big-endian 레이아웃)
    for (int c = 0; c < AES_BLOCK_WORDS; c++) {
        uint32_t w = rk_words[c];
        state[AES_BLOCK_WORDS * c + 0] ^= (unsigned char)(w >> 24);
        state[AES_BLOCK_WORDS * c + 1] ^= (unsigned char)(w >> 16);
        state[AES_BLOCK_WORDS * c + 2] ^= (unsigned char)(w >> 8);
        state[AES_BLOCK_WORDS * c + 3] ^= (unsigned char)(w);
    }
}

static void sub_bytes(unsigned char state[16],
    const unsigned char sbox[256]) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void inv_sub_bytes(unsigned char state[16],
    const unsigned char inv_sbox[256]) {
    for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];
}

static void shift_rows(unsigned char s[16]) {
    unsigned char t[16];
    // AES state: column-major
    t[0] = s[0];  t[4] = s[4];  t[8] = s[8];  t[12] = s[12];          // row0 no shift
    t[1] = s[5];  t[5] = s[9];  t[9] = s[13]; t[13] = s[1];          // row1 shift 1
    t[2] = s[10]; t[6] = s[14]; t[10] = s[2]; t[14] = s[6];          // row2 shift 2
    t[3] = s[15]; t[7] = s[3];  t[11] = s[7]; t[15] = s[11];         // row3 shift 3
    memcpy(s, t, 16);
}

static void inv_shift_rows(unsigned char s[16]) {
    unsigned char t[16];
    t[0] = s[0];  t[4] = s[4];  t[8] = s[8];  t[12] = s[12];
    t[1] = s[13]; t[5] = s[1];  t[9] = s[5];  t[13] = s[9];           // 오른쪽으로 1
    t[2] = s[10]; t[6] = s[14]; t[10] = s[2]; t[14] = s[6];           // 오른쪽 2
    t[3] = s[7];  t[7] = s[11]; t[11] = s[15]; t[15] = s[3];          // 오른쪽 3
    memcpy(s, t, 16);
}

static void mix_columns(unsigned char s[16]) {
    for (int c = 0; c < AES_BLOCK_WORDS; c++) {
        unsigned char a0 = s[AES_BLOCK_WORDS * c + 0];
        unsigned char a1 = s[AES_BLOCK_WORDS * c + 1];
        unsigned char a2 = s[AES_BLOCK_WORDS * c + 2];
        unsigned char a3 = s[AES_BLOCK_WORDS * c + 3];

        s[AES_BLOCK_WORDS * c + 0] = (unsigned char)(mul2(a0) ^ mul3(a1) ^ a2 ^ a3);
        s[AES_BLOCK_WORDS * c + 1] = (unsigned char)(a0 ^ mul2(a1) ^ mul3(a2) ^ a3);
        s[AES_BLOCK_WORDS * c + 2] = (unsigned char)(a0 ^ a1 ^ mul2(a2) ^ mul3(a3));
        s[AES_BLOCK_WORDS * c + 3] = (unsigned char)(mul3(a0) ^ a1 ^ a2 ^ mul2(a3));
    }
}

static void inv_mix_columns(unsigned char s[16]) {
    for (int c = 0; c < AES_BLOCK_WORDS; c++) {
        unsigned char a0 = s[AES_BLOCK_WORDS * c + 0];
        unsigned char a1 = s[AES_BLOCK_WORDS * c + 1];
        unsigned char a2 = s[AES_BLOCK_WORDS * c + 2];
        unsigned char a3 = s[AES_BLOCK_WORDS * c + 3];

        s[AES_BLOCK_WORDS * c + 0] = (unsigned char)(mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3));
        s[AES_BLOCK_WORDS * c + 1] = (unsigned char)(mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3));
        s[AES_BLOCK_WORDS * c + 2] = (unsigned char)(mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3));
        s[AES_BLOCK_WORDS * c + 3] = (unsigned char)(mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3));
    }
}

// =======================================================
// vtable에서 사용하는 reference AES 엔진 구현
//  - init: 테이블 빌드 후 원본 키 저장 (확장키는 미리 계산하지 않음)
//  - encrypt: 각 라운드마다 compute_round_key() 호출 → 메모리 대신 CPU 사용
//  - decrypt: 역라운드 순서로 동일하게 on-the-fly 키를 뽑아 적용
// =======================================================

static void* aes_ref_init_impl(const unsigned char* key, int key_len) {
    if (!key) return NULL;
    if (!(key_len == AES128_KEY_BYTES || key_len == AES192_KEY_BYTES || key_len == AES256_KEY_BYTES)) return NULL;

    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)calloc(1, sizeof(aes_ref_ctx_t));
    if (!ctx) return NULL;

    ctx->Nk = key_len / AES_WORD_BYTES;
    ctx->Nr = ctx->Nk + 6;

    aes_sbox_build_tables(ctx->sbox, ctx->inv_sbox);

    // 원본 키 저장 (on-the-fly Key Schedule용)
    memcpy(ctx->key, key, key_len);
    if (key_len < AES256_KEY_BYTES) {
        memset(ctx->key + key_len, 0, AES256_KEY_BYTES - key_len);
    }

    return ctx;
}

static void aes_ref_encrypt_block_impl(void* vctx,
    const unsigned char in[16],
    unsigned char out[16]) {
    // AES 표준 라운드 순서를 그대로 따르며, state 는 column-major(4x4) 배열.
    // 전체 확장키를 들고 있지 않고, compute_round_key()로 매 라운드 키를 생성해 적용.
    // => 메모리를 아끼지만 반복 암호화 시 키스케줄 계산 비용이 매 라운드 발생.
    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)vctx;
    if (!ctx || !in || !out) return;

    unsigned char state[AES_BLOCK_BYTES];
    memcpy(state, in, AES_BLOCK_BYTES);

    uint32_t round_key[AES_BLOCK_WORDS];  // 현재 라운드의 확장키

    // round 0
    compute_round_key(round_key, 0, ctx->key, ctx->Nk, ctx->Nr, ctx->sbox);
    add_round_key(state, round_key);

    // round 1..Nr-1
    for (int r = 1; r < ctx->Nr; r++) {
        sub_bytes(state, ctx->sbox);
        shift_rows(state);
        mix_columns(state);

        // 라운드 r 확장키
        compute_round_key(round_key, r, ctx->key, ctx->Nk, ctx->Nr, ctx->sbox);
        add_round_key(state, round_key);
    }

    // final round (mix_columns 없음)
    sub_bytes(state, ctx->sbox);
    shift_rows(state);

    compute_round_key(round_key, ctx->Nr, ctx->key, ctx->Nk, ctx->Nr, ctx->sbox);
    add_round_key(state, round_key);

    memcpy(out, state, 16);
}

static void aes_ref_decrypt_block_impl(void* vctx,
    const unsigned char in[16],
    unsigned char out[16]) {
    // 암호화의 역순: (AddRoundKey -> InvMixColumns -> InvShiftRows -> InvSubBytes) 흐름.
    // round key 역시 compute_round_key()로 매 라운드마다 생성해 적용한다.
    // CTR 등 대칭모드에서는 decrypt가 거의 호출되지 않지만, CBC 같은 모드 확장 시 재사용 가능.
    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)vctx;
    if (!ctx || !in || !out) return;

    unsigned char state[AES_BLOCK_BYTES];
    memcpy(state, in, AES_BLOCK_BYTES);

    uint32_t round_key[AES_BLOCK_WORDS];

    // round Nr
    compute_round_key(round_key, ctx->Nr, ctx->key, ctx->Nk, ctx->Nr, ctx->sbox);
    add_round_key(state, round_key);

    // round Nr-1 .. 1
    for (int r = ctx->Nr - 1; r >= 1; r--) {
        inv_shift_rows(state);
        inv_sub_bytes(state, ctx->inv_sbox);

        compute_round_key(round_key, r, ctx->key, ctx->Nk, ctx->Nr, ctx->sbox);
        add_round_key(state, round_key);

        inv_mix_columns(state);
    }

    // round 0
    inv_shift_rows(state);
    inv_sub_bytes(state, ctx->inv_sbox);

    compute_round_key(round_key, 0, ctx->key, ctx->Nk, ctx->Nr, ctx->sbox);
    add_round_key(state, round_key);

    memcpy(out, state, 16);
}

static void aes_ref_free_impl(void* vctx) {
    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)vctx;
    if (!ctx) return;

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

// =========================
// 외부로 노출되는 vtable
// =========================
const blockcipher_vtable_t AES_REF_ENGINE = {
    aes_ref_init_impl,
    aes_ref_encrypt_block_impl,
    aes_ref_decrypt_block_impl,
    aes_ref_free_impl
};
