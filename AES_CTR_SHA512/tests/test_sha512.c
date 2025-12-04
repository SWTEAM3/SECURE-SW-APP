#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "crypto/hash/hash_sha512.h"

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
static void dump_hex(const unsigned char* x, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02X", x[i]);
    printf("\n");
}
static int bytes_eq(const unsigned char* a, const unsigned char* b, size_t n) {
    return memcmp(a, b, n) == 0;
}

// 벡터
typedef struct sha_vec_t {
    const char* name;
    const unsigned char* msg;
    size_t msg_len;
    const char* digest_hex;
} sha_vec_t;

static const unsigned char MSG0[] = "";
static const unsigned char MSG1[] = "abc";
static const unsigned char MSG2[] =
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static unsigned char MSG3[1000000];

static const sha_vec_t VECTORS[] = {
    {
        "SHA-512(\"\")",
        MSG0, 0,
        "cf83e1357eefb8bdf1542850d66d8007"
        "d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"
    },
    {
        "SHA-512(\"abc\")",
        MSG1, 3,
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f"
    },
    {
        "SHA-512(long abcdbcde...)",
        MSG2, sizeof(MSG2) - 1,
        "204a8fc6dda82f0a0ced7beb8e08a416"
        "57c16ef468b228a8279be331a703c335"
        "96fd15c13b1b07f9aa1d3bea57789ca0"
        "31ad85c7a71dd70354ec631238ca3445"
    }
};

static int run_one_vector(const sha_vec_t* v)
{
    unsigned char digest[64];
    unsigned char expect[64];

    if (!hex_to_bytes(v->digest_hex, expect, 64)) {
        printf("[FAIL] %s : expected hex parse failed\n", v->name);
        return 0;
    }

    sha512_ctx_t ctx;
    sha512_init(&ctx);

    size_t offset = 0;
    while (offset < v->msg_len) {
        size_t chunk = (v->msg_len - offset > 7) ? 7 : (v->msg_len - offset);
        sha512_update(&ctx, v->msg + offset, chunk);
        offset += chunk;
    }

    sha512_final(&ctx, digest);

    if (!bytes_eq(digest, expect, 64)) {
        printf("[FAIL] %s : digest mismatch\n", v->name);
        printf(" expected: "); dump_hex(expect, 64);
        printf(" got     : "); dump_hex(digest, 64);
        return 0;
    }

    printf("[OK] %s\n", v->name);
    return 1;
}

static int run_million_a_test(void)
{
    for (int i = 0; i < 1000000; i++) MSG3[i] = 'a';

    const char* expect_hex =
        "e718483d0ce769644e2e42c7bc15b463"
        "8e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31b"
        "eb009c5c2c49aa2e4eadb217ad8cc09b";

    unsigned char expect[64];
    unsigned char digest[64];
    if (!hex_to_bytes(expect_hex, expect, 64)) return 0;

    sha512_ctx_t ctx;
    sha512_init(&ctx);

    size_t offset = 0;
    while (offset < 1000000) {
        size_t chunk = (1000000 - offset > 4096) ? 4096 : (1000000 - offset);
        sha512_update(&ctx, MSG3 + offset, chunk);
        offset += chunk;
    }

    sha512_final(&ctx, digest);

    if (!bytes_eq(digest, expect, 64)) {
        printf("[FAIL] SHA-512(1,000,000 'a') mismatch\n");
        printf(" expected: "); dump_hex(expect, 64);
        printf(" got     : "); dump_hex(digest, 64);
        return 0;
    }

    printf("[OK] SHA-512(1,000,000 'a')\n");
    return 1;
}

// 더 이상 main이 아님. 테스트용 함수.
int test_sha512_main(void)
{
    int ok = 1;

    for (size_t i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
        if (!run_one_vector(&VECTORS[i])) ok = 0;
    }
    if (!run_million_a_test()) ok = 0;

    if (ok) {
        printf("\n=== ALL SHA-512 TESTS PASSED ===\n");
        return 0;
    }
    else {
        printf("\n=== SHA-512 TESTS FAILED ===\n");
        return 1;
    }
}