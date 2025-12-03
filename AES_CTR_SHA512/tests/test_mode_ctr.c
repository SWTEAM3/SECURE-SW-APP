#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto/mode/mode_ctr.h"
#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_engine_ttable.h"
#include "crypto/bytes.h"

// 헥스 유틸
static int hexval(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int hex_to_bytes(const char* hex, unsigned char* out, size_t outlen) {
    size_t n = strlen(hex);
    if (n != outlen * 2) return 0;
    for (size_t i = 0; i < outlen; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}
static int bytes_eq(const unsigned char* a, const unsigned char* b, size_t n) {
    return memcmp(a, b, n) == 0;
}
static void dump_hex(const unsigned char* x, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02X", x[i]);
    printf("\n");
}

// 벡터 정의
typedef struct ctr_vec_t {
    const char* name;
    const char* key_hex;
    int key_len;
    const char* iv_hex;
    const char* pt_hex;
    const char* ct_hex;
} ctr_vec_t;

// NIST CTR 벡터
static const ctr_vec_t VECTORS[] = {
    {
        "AES-CTR-128",
        "2b7e151628aed2a6abf7158809cf4f3c",
        16,
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    },
    {
        "AES-CTR-192",
        "8e73b0f7da0e6452c810f32b809079e5"
        "62f8ead2522c6b7b",
        24,
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "1abc932417521ca24f2b0459fe7e6e0b"
        "090339ec0aa6faefd5ccc2c6f4ce8e94"
        "1e36b26bd1ebc670d1bd1d665620abf7"
        "4f78a7f6d29809585a97daec58c6b050"
    },
    {
        "AES-CTR-256",
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4",
        32,
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "601ec313775789a5b7a7f504bbf3d228"
        "f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988d"
        "dfc9c58db67aada613c2dd08457941a6"
    }
};

static int run_one_vector(const ctr_vec_t* v,
    const blockcipher_vtable_t* engine,
    const char* engine_name)
{
    unsigned char key[32], iv[16], pt[64], ct_exp[64];
    unsigned char ct_out[64], pt_out[64];

    if (!hex_to_bytes(v->key_hex, key, v->key_len)) return 0;
    if (!hex_to_bytes(v->iv_hex, iv, 16)) return 0;
    if (!hex_to_bytes(v->pt_hex, pt, 64)) return 0;
    if (!hex_to_bytes(v->ct_hex, ct_exp, 64)) return 0;

    ctr_mode_ctx_t* ctx_enc = ctr_mode_init(engine, key, v->key_len, iv);
    if (!ctx_enc) {
        printf("[FAIL] %s (%s): init enc NULL\n", v->name, engine_name);
        return 0;
    }
    ctr_mode_update(ctx_enc, pt, ct_out, 64);
    ctr_mode_free(ctx_enc);

    if (!bytes_eq(ct_out, ct_exp, 64)) {
        printf("[FAIL] %s (%s): ciphertext mismatch\n", v->name, engine_name);
        printf(" expected: "); dump_hex(ct_exp, 64);
        printf(" got     : "); dump_hex(ct_out, 64);
        return 0;
    }

    ctr_mode_ctx_t* ctx_dec = ctr_mode_init(engine, key, v->key_len, iv);
    if (!ctx_dec) {
        printf("[FAIL] %s (%s): init dec NULL\n", v->name, engine_name);
        return 0;
    }
    ctr_mode_update(ctx_dec, ct_out, pt_out, 64);
    ctr_mode_free(ctx_dec);

    if (!bytes_eq(pt_out, pt, 64)) {
        printf("[FAIL] %s (%s): plaintext mismatch\n", v->name, engine_name);
        printf(" expected: "); dump_hex(pt, 64);
        printf(" got     : "); dump_hex(pt_out, 64);
        return 0;
    }

    printf("[OK] %s (%s)\n", v->name, engine_name);
    return 1;
}

static int run_negative_tests(void)
{
    unsigned char key16[16] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char in[16] = { 0 };
    unsigned char out[16] = { 0 };

    ctr_mode_ctx_t* bad = ctr_mode_init(&AES_REF_ENGINE, key16, 15, iv);
    if (bad) { printf("[FAIL] NEG invalid key len\n"); ctr_mode_free(bad); return 0; }

    bad = ctr_mode_init(NULL, key16, 16, iv);
    if (bad) { printf("[FAIL] NEG NULL engine\n"); ctr_mode_free(bad); return 0; }

    bad = ctr_mode_init(&AES_REF_ENGINE, NULL, 16, iv);
    if (bad) { printf("[FAIL] NEG NULL key\n"); ctr_mode_free(bad); return 0; }

    ctr_mode_ctx_t* ctx = ctr_mode_init(&AES_REF_ENGINE, key16, 16, iv);
    if (!ctx) { printf("[FAIL] NEG ctx init\n"); return 0; }
    ctr_mode_update(ctx, in, out, 0);
    ctr_mode_free(ctx);

    printf("[OK] NEG tests\n");
    return 1;
}

// 더 이상 main이 아님. 테스트용 함수.
int test_mode_ctr_main(void)
{
    int ok = 1;
    const blockcipher_vtable_t* engines[] = { &AES_REF_ENGINE, &AES_TTABLE_ENGINE };
    const char* names[] = { "ref", "ttable" };

    for (int e = 0; e < 2; e++) {
        for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
            if (!run_one_vector(&VECTORS[i], engines[e], names[e])) ok = 0;
        }
    }

    if (!run_negative_tests()) ok = 0;

    if (ok) {
        printf("\n=== ALL CTR TESTS PASSED ===\n");
        return 0;
    }
    else {
        printf("\n=== CTR TESTS FAILED ===\n");
        return 1;
    }
}