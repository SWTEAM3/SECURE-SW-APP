// ===============================================================
// AES T-Table Engine (테이블 기반 AES 엔진)
//  - 라운드 키를 미리 모두 계산해 rk[60]에 저장하는 방식
//  - on-the-fly 키스케줄은 사용하지 않음
//  - 순/역 T-테이블을 미리 만들어 테이블 기반 최적화도 가능하도록 설계
// ===============================================================

#include "crypto/cipher/aes_engine_ttable.h"
#include "crypto/cipher/aes_sbox_math.h"
#include "crypto/bytes.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
typedef struct aes_ttab_ctx_t {
    int Nk;                     // key words (4/6/8)
    int Nr;                     // rounds (10/12/14)
    uint32_t rk[AES_MAX_EXP_WORDS]; // 미리 확장한 라운드 키 (4*(Nr+1) words, 최대 60)

    // 순방향/역방향 T-테이블: SubBytes + MixColumns 조합을 1테이블로 압축
    uint32_t Te0[256], Te1[256], Te2[256], Te3[256];
    uint32_t Td0[256], Td1[256], Td2[256], Td3[256];

    unsigned char sbox[256];     // SubBytes 테이블
    unsigned char inv_sbox[256]; // InvSubBytes 테이블
} aes_ttab_ctx_t;

// ---------------------------------------------------------------
// RCON 상수
// ---------------------------------------------------------------
static const uint32_t RCON[AES_RCON_LEN] = {
    0x01000000,0x02000000,0x04000000,0x08000000,
    0x10000000,0x20000000,0x40000000,0x80000000,
    0x1B000000,0x36000000
};

static inline uint32_t rot_word(uint32_t x) { return (x << 8) | (x >> 24); }

static uint32_t sub_word(uint32_t x, const unsigned char s[256]) {
    return ((uint32_t)s[(x >> 24) & 0xFF] << 24) |
        ((uint32_t)s[(x >> 16) & 0xFF] << 16) |
        ((uint32_t)s[(x >> 8) & 0xFF] << 8) |
        ((uint32_t)s[(x >> 0) & 0xFF]);
}

// ---------------------------------------------------------------
// 키 확장 (표준 AES Key Schedule)
// ---------------------------------------------------------------
static void aes_key_expand(uint32_t* rk,
    const unsigned char* key,
    int Nk, int Nr,
    const unsigned char sbox[256])
{
    // 표준 AES Key Schedule. 입력 키는 big-endian으로 워드를 구성하여 rk[]에 채운다.
    // 이후 워드를 순차 확장해 4*(Nr+1)개 워드를 모두 확보한다.
    int total = AES_BLOCK_WORDS * (Nr + 1);

    for (int i = 0; i < Nk; i++) {
        rk[i] = ((uint32_t)key[AES_WORD_BYTES * i + 0] << 24) |
            ((uint32_t)key[AES_WORD_BYTES * i + 1] << 16) |
            ((uint32_t)key[AES_WORD_BYTES * i + 2] << 8) |
            ((uint32_t)key[AES_WORD_BYTES * i + 3]);
    }

    for (int i = Nk; i < total; i++) {
        uint32_t temp = rk[i - 1];

        if (i % Nk == 0) {
            temp = rot_word(temp);
            temp = sub_word(temp, sbox);
            temp ^= RCON[(i / Nk) - 1];
        }
        else if (Nk > 6 && (i % Nk) == 4) {
            temp = sub_word(temp, sbox);
        }
        rk[i] = rk[i - Nk] ^ temp;
    }
}

// ---------------------------------------------------------------
// GF(2^8) 기본 연산
// ---------------------------------------------------------------
static inline unsigned char xt(unsigned char x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1);
}
static inline unsigned char m2(unsigned char x) { return xt(x); }
static inline unsigned char m3(unsigned char x) { return xt(x) ^ x; }

static inline unsigned char m9(unsigned char x) {
    unsigned char t = xt(xt(xt(x)));
    return t ^ x;
}
static inline unsigned char m11(unsigned char x) {
    unsigned char t = xt(xt(xt(x)));
    return t ^ xt(x) ^ x;
}
static inline unsigned char m13(unsigned char x) {
    unsigned char t = xt(xt(xt(x)));
    return t ^ xt(xt(x)) ^ x;
}
static inline unsigned char m14(unsigned char x) {
    unsigned char t = xt(xt(xt(x)));
    return t ^ xt(xt(x)) ^ xt(x);
}

static inline uint32_t rotl8(uint32_t x) {
    return (x << 8) | (x >> 24);
}

// ---------------------------------------------------------------
// T-Table 빌드
// ---------------------------------------------------------------
static void aes_ttable_build(aes_ttab_ctx_t* c)
{
    // 암/복호화용 T-테이블을 한 번만 만들어 엔진 전반에서 재사용.
    // Te* : SubBytes + ShiftRows + MixColumns 순방향을 합친 32bit 테이블
    // Td* : 역방향용 (InvSubBytes + InvShiftRows + InvMixColumns)
    for (int i = 0; i < 256; i++) {
        unsigned char s  = c->sbox[i];
        unsigned char is = c->inv_sbox[i];

        uint32_t te0 =
            ((uint32_t)m2(s) << 24) |
            ((uint32_t)s << 16) |
            ((uint32_t)s << 8) |
            ((uint32_t)m3(s));

        c->Te0[i] = te0;
        c->Te1[i] = rotl8(te0);
        c->Te2[i] = rotl8(c->Te1[i]);
        c->Te3[i] = rotl8(c->Te2[i]);

        uint32_t td0 =
            ((uint32_t)m14(is) << 24) |
            ((uint32_t)m9(is)  << 16) |
            ((uint32_t)m13(is) << 8)  |
            ((uint32_t)m11(is));

        c->Td0[i] = td0;
        c->Td1[i] = rotl8(td0);
        c->Td2[i] = rotl8(c->Td1[i]);
        c->Td3[i] = rotl8(c->Td2[i]);
    }
}

// ---------------------------------------------------------------
// 초기화
// ---------------------------------------------------------------
static void* aes_ttab_init_impl(const unsigned char* key, int key_len)
{
    if (!key) return NULL;
    if (!(key_len == AES128_KEY_BYTES || key_len == AES192_KEY_BYTES || key_len == AES256_KEY_BYTES)) return NULL;

    aes_ttab_ctx_t* c = (aes_ttab_ctx_t*)calloc(1, sizeof(*c));
    if (!c) return NULL;

    c->Nk = key_len / AES_WORD_BYTES;
    c->Nr = c->Nk + 6;

    // 순/역 S-box 테이블 생성 → 이를 기반으로 T-테이블 생성
    aes_sbox_build_tables(c->sbox, c->inv_sbox);
    aes_ttable_build(c);
    // 모든 라운드 키를 한 번에 확장해 rk[]에 저장 (암복호화 시 키스케줄 비용 0)
    aes_key_expand(c->rk, key, c->Nk, c->Nr, c->sbox);

    return c;
}

// ---------------------------------------------------------------------
// AES T-table 엔진: 암호화
//  - 표준 AES 라운드를 그대로 구현하되, 라운드 키는 rk[]에서 꺼내 사용
// ---------------------------------------------------------------------
static void aes_ttab_encrypt_block_impl(void* vctx,
    const unsigned char in[16],
    unsigned char out[16])
{
    // 표준 AES 라운드를 그대로 구현하되, 라운드 키는 rk[]에서 바로 읽어온다.
    // (테이블 기반으로 변형 가능하도록 Te*/Td*를 준비했지만, 여기서는 S-box + MixColumns를 직접 수행)
    // 키스케줄이 초기화 시 모두 끝났으므로 암호화 시 반복 비용이 적음.
    aes_ttab_ctx_t* ctx = (aes_ttab_ctx_t*)vctx;
    if (!ctx || !in || !out) return;

    unsigned char state[AES_BLOCK_BYTES];
    memcpy(state, in, AES_BLOCK_BYTES);

    const unsigned char* sbox = ctx->sbox;
    uint32_t* rk = ctx->rk;
    int Nr = ctx->Nr;

    // -------- Round 0: AddRoundKey --------
    for (int c = 0; c < AES_BLOCK_WORDS; c++) {
        uint32_t k = rk[c];
        state[AES_BLOCK_WORDS * c + 0] ^= (unsigned char)(k >> 24);
        state[AES_BLOCK_WORDS * c + 1] ^= (unsigned char)(k >> 16);
        state[AES_BLOCK_WORDS * c + 2] ^= (unsigned char)(k >> 8);
        state[AES_BLOCK_WORDS * c + 3] ^= (unsigned char)(k);
    }

    // -------- Round 1 .. Nr-1 --------
    for (int round = 1; round < Nr; round++) {
        // SubBytes
        for (int i = 0; i < 16; i++)
            state[i] = sbox[state[i]];

        // ShiftRows (column-major 인덱스 기준)
        unsigned char t;

        // row1: [1,5,9,13] -> [5,9,13,1]
        t = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = t;

        // row2: [2,6,10,14] -> [10,14,2,6]
        t = state[2];
        state[2] = state[10];
        state[10] = t;
        t = state[6];
        state[6] = state[14];
        state[14] = t;

        // row3: [3,7,11,15] -> [15,3,7,11]
        t = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = t;

        // MixColumns
        for (int c = 0; c < AES_BLOCK_WORDS; c++) {
            int idx = AES_BLOCK_WORDS * c;
            unsigned char a0 = state[idx + 0];
            unsigned char a1 = state[idx + 1];
            unsigned char a2 = state[idx + 2];
            unsigned char a3 = state[idx + 3];

            unsigned char r0 = (unsigned char)(m2(a0) ^ m3(a1) ^ a2 ^ a3);
            unsigned char r1 = (unsigned char)(a0 ^ m2(a1) ^ m3(a2) ^ a3);
            unsigned char r2 = (unsigned char)(a0 ^ a1 ^ m2(a2) ^ m3(a3));
            unsigned char r3 = (unsigned char)(m3(a0) ^ a1 ^ a2 ^ m2(a3));

            state[idx + 0] = r0;
            state[idx + 1] = r1;
            state[idx + 2] = r2;
            state[idx + 3] = r3;
        }

        // AddRoundKey
        for (int c = 0; c < AES_BLOCK_WORDS; c++) {
            uint32_t k = rk[AES_BLOCK_WORDS * round + c];
            state[AES_BLOCK_WORDS * c + 0] ^= (unsigned char)(k >> 24);
            state[AES_BLOCK_WORDS * c + 1] ^= (unsigned char)(k >> 16);
            state[AES_BLOCK_WORDS * c + 2] ^= (unsigned char)(k >> 8);
            state[AES_BLOCK_WORDS * c + 3] ^= (unsigned char)(k);
        }
    }

    // -------- Final round (No MixColumns) --------
    // SubBytes
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];

    // ShiftRows
    unsigned char t;

    // row1
    t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    // row2
    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;

    // row3
    t = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t;

    // AddRoundKey (마지막 라운드 키)
    for (int c = 0; c < AES_BLOCK_WORDS; c++) {
        uint32_t k = rk[AES_BLOCK_WORDS * Nr + c];
        state[AES_BLOCK_WORDS * c + 0] ^= (unsigned char)(k >> 24);
        state[AES_BLOCK_WORDS * c + 1] ^= (unsigned char)(k >> 16);
        state[AES_BLOCK_WORDS * c + 2] ^= (unsigned char)(k >> 8);
        state[AES_BLOCK_WORDS * c + 3] ^= (unsigned char)(k);
    }

    memcpy(out, state, 16);
}

// ---------------------------------------------------------------------
// CTR 모드에서는 decrypt = encrypt 이므로, decrypt 는 encrypt 를 그대로 사용
// ---------------------------------------------------------------------
static void aes_ttab_decrypt_block_impl(void* vctx,
    const unsigned char in[16],
    unsigned char out[16])
{
    // CTR 등에서는 decrypt = encrypt. 필요 시 Td* 기반 역방향 최적화로 교체 가능.
    aes_ttab_encrypt_block_impl(vctx, in, out);
}

// ---------------------------------------------------------------
static void aes_ttab_free_impl(void* v) {
    if (!v) return;
    memset(v, 0, sizeof(aes_ttab_ctx_t));
    free(v);
}

// ---------------------------------------------------------------
const blockcipher_vtable_t AES_TTABLE_ENGINE = {
    aes_ttab_init_impl,
    aes_ttab_encrypt_block_impl,
    aes_ttab_decrypt_block_impl,
    aes_ttab_free_impl
};
