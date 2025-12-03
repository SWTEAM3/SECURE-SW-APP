#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_sbox_math.h"
#include "crypto/cipher/gf256_math.h"
#include "crypto/core/blockcipher.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// =========================
// 내부 컨텍스트(레퍼런스 AES)
// =========================
typedef struct aes_ref_ctx_t {
    int Nk;                 // key words (4/6/8)
    int Nr;                 // rounds (10/12/14)
    uint32_t rk[60];        // round keys 최대(4*(14+1)=60)
    unsigned char sbox[256];
    unsigned char inv_sbox[256];
} aes_ref_ctx_t;


// =======================================================
// AES Key Expansion (동적 Nk/Nr 대응)
// =======================================================

// Rcon 테이블
static const uint32_t RCON[10] = {
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

static void aes_key_expand(uint32_t* out_rk,
    const unsigned char* key,
    int Nk,
    int Nr,
    const unsigned char sbox[256])
{
    int Nb = 4;
    int total_words = Nb * (Nr + 1);

    // 초기 Nk words
    for (int i = 0; i < Nk; i++) {
        out_rk[i] = ((uint32_t)key[4 * i + 0] << 24) |
            ((uint32_t)key[4 * i + 1] << 16) |
            ((uint32_t)key[4 * i + 2] << 8) |
            ((uint32_t)key[4 * i + 3] << 0);
    }

    for (int i = Nk; i < total_words; i++) {
        uint32_t temp = out_rk[i - 1];

        if (i % Nk == 0) {
            temp = rot_word(temp);
            temp = sub_word(temp, sbox);
            temp ^= RCON[(i / Nk) - 1];
        }
        else if (Nk > 6 && i % Nk == 4) {
            temp = sub_word(temp, sbox);
        }

        out_rk[i] = out_rk[i - Nk] ^ temp;
    }
}


// =======================================================
// AES 내부 연산(레퍼런스)
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
    const uint32_t* rk_words)
{
    // rk_words: 4워드 = 16바이트 (big-endian로 rk에 저장되어 있음)
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk_words[c];
        state[4 * c + 0] ^= (unsigned char)(w >> 24);
        state[4 * c + 1] ^= (unsigned char)(w >> 16);
        state[4 * c + 2] ^= (unsigned char)(w >> 8);
        state[4 * c + 3] ^= (unsigned char)(w);
    }
}

static void sub_bytes(unsigned char state[16],
    const unsigned char sbox[256])
{
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

static void inv_sub_bytes(unsigned char state[16],
    const unsigned char inv_sbox[256])
{
    for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];
}

static void shift_rows(unsigned char s[16])
{
    unsigned char t[16];
    // state는 column-major (AES 표준)
    t[0] = s[0];  t[4] = s[4];  t[8] = s[8];  t[12] = s[12];          // row0 no shift
    t[1] = s[5];  t[5] = s[9];  t[9] = s[13]; t[13] = s[1];          // row1 shift 1
    t[2] = s[10]; t[6] = s[14]; t[10] = s[2]; t[14] = s[6];          // row2 shift 2
    t[3] = s[15]; t[7] = s[3];  t[11] = s[7]; t[15] = s[11];         // row3 shift 3
    memcpy(s, t, 16);
}

static void inv_shift_rows(unsigned char s[16])
{
    unsigned char t[16];
    t[0] = s[0];  t[4] = s[4];  t[8] = s[8];  t[12] = s[12];          // row0 no shift
    t[1] = s[13]; t[5] = s[1];  t[9] = s[5];  t[13] = s[9];           // row1 shift right 1
    t[2] = s[10]; t[6] = s[14]; t[10] = s[2]; t[14] = s[6];           // row2 shift right 2 (same as left 2)
    t[3] = s[7];  t[7] = s[11]; t[11] = s[15]; t[15] = s[3];          // row3 shift right 3
    memcpy(s, t, 16);
}

static void mix_columns(unsigned char s[16])
{
    for (int c = 0; c < 4; c++) {
        unsigned char a0 = s[4 * c + 0];
        unsigned char a1 = s[4 * c + 1];
        unsigned char a2 = s[4 * c + 2];
        unsigned char a3 = s[4 * c + 3];

        s[4 * c + 0] = (unsigned char)(mul2(a0) ^ mul3(a1) ^ a2 ^ a3);
        s[4 * c + 1] = (unsigned char)(a0 ^ mul2(a1) ^ mul3(a2) ^ a3);
        s[4 * c + 2] = (unsigned char)(a0 ^ a1 ^ mul2(a2) ^ mul3(a3));
        s[4 * c + 3] = (unsigned char)(mul3(a0) ^ a1 ^ a2 ^ mul2(a3));
    }
}

static void inv_mix_columns(unsigned char s[16])
{
    for (int c = 0; c < 4; c++) {
        unsigned char a0 = s[4 * c + 0];
        unsigned char a1 = s[4 * c + 1];
        unsigned char a2 = s[4 * c + 2];
        unsigned char a3 = s[4 * c + 3];

        s[4 * c + 0] = (unsigned char)(mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3));
        s[4 * c + 1] = (unsigned char)(mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3));
        s[4 * c + 2] = (unsigned char)(mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3));
        s[4 * c + 3] = (unsigned char)(mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3));
    }
}


// =======================================================
// vtable용 AES ref 구현
// =======================================================

static void* aes_ref_init_impl(const unsigned char* key, int key_len)
{
    if (!key) return NULL;
    if (!(key_len == 16 || key_len == 24 || key_len == 32)) return NULL;

    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)calloc(1, sizeof(aes_ref_ctx_t));
    if (!ctx) return NULL;

    ctx->Nk = key_len / 4;
    ctx->Nr = ctx->Nk + 6;

    aes_sbox_build_tables(ctx->sbox, ctx->inv_sbox);
    aes_key_expand(ctx->rk, key, ctx->Nk, ctx->Nr, ctx->sbox);

    return ctx;
}

static void aes_ref_encrypt_block_impl(void* vctx,
    const unsigned char in[16],
    unsigned char out[16])
{
    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)vctx;
    if (!ctx || !in || !out) return;

    unsigned char state[16];
    memcpy(state, in, 16);

    // round 0
    add_round_key(state, &ctx->rk[0]);

    // round 1..Nr-1
    for (int r = 1; r < ctx->Nr; r++) {
        sub_bytes(state, ctx->sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->rk[4 * r]);
    }

    // final round (no mix_columns)
    sub_bytes(state, ctx->sbox);
    shift_rows(state);
    add_round_key(state, &ctx->rk[4 * ctx->Nr]);

    memcpy(out, state, 16);
}

static void aes_ref_decrypt_block_impl(void* vctx,
    const unsigned char in[16],
    unsigned char out[16])
{
    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)vctx;
    if (!ctx || !in || !out) return;

    unsigned char state[16];
    memcpy(state, in, 16);

    // round Nr
    add_round_key(state, &ctx->rk[4 * ctx->Nr]);

    // round Nr-1 .. 1
    for (int r = ctx->Nr - 1; r >= 1; r--) {
        inv_shift_rows(state);
        inv_sub_bytes(state, ctx->inv_sbox);
        add_round_key(state, &ctx->rk[4 * r]);
        inv_mix_columns(state);
    }

    // round 0
    inv_shift_rows(state);
    inv_sub_bytes(state, ctx->inv_sbox);
    add_round_key(state, &ctx->rk[0]);

    memcpy(out, state, 16);
}

static void aes_ref_free_impl(void* vctx)
{
    aes_ref_ctx_t* ctx = (aes_ref_ctx_t*)vctx;
    if (!ctx) return;

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}


// =========================
// 외부로 공개되는 엔진 vtable
// =========================
const blockcipher_vtable_t AES_REF_ENGINE = {
    aes_ref_init_impl,
    aes_ref_encrypt_block_impl,
    aes_ref_decrypt_block_impl,
    aes_ref_free_impl
};
