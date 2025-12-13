#include "crypto/hash/hash_sha512.h"
#include "crypto/bytes.h"
#include <string.h>
#include <stdint.h>

// =====================================================
// SHA-512 Constants K[0..79]
// =====================================================
static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// =====================================================
// ARX helpers (64-bit)
// =====================================================
static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}
static inline uint64_t shr64(uint64_t x, int n) {
    return x >> n;
}

// Big sigma (Σ) and small sigma (σ)
static inline uint64_t SIGMA0(uint64_t x) {
    return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39);
}
static inline uint64_t SIGMA1(uint64_t x) {
    return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41);
}
static inline uint64_t sigma0(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ shr64(x, 7);
}
static inline uint64_t sigma1(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ shr64(x, 6);
}

// Choice / Majority
static inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}
static inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// =====================================================
// Message schedule W[0..79] expansion
// =====================================================
static void sha512_msg_schedule(uint64_t W[80],
    const unsigned char block[SHA512_BLOCK_SIZE])
{
    // W[0..15] : 16 words from block (big-endian)
    for (int i = 0; i < 16; i++) {
        W[i] = load_be64(block + 8 * i);
    }

    // W[16..79] expansion
    for (int t = 16; t < 80; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }
}

// =====================================================
// Compression function (Merkle?Damg?rd core)
// =====================================================
static void sha512_compress(sha512_ctx_t* ctx,
    const unsigned char block[128])
{
    uint64_t W[80];
    sha512_msg_schedule(W, block);

    // Working variables
    uint64_t a = ctx->H[0], b = ctx->H[1], c = ctx->H[2], d = ctx->H[3];
    uint64_t e = ctx->H[4], f = ctx->H[5], g = ctx->H[6], h = ctx->H[7];

    // 80 rounds
    for (int t = 0; t < 80; t++) {
        uint64_t T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
        uint64_t T2 = SIGMA0(a) + Maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Update chaining values
    ctx->H[0] += a; ctx->H[1] += b; ctx->H[2] += c; ctx->H[3] += d;
    ctx->H[4] += e; ctx->H[5] += f; ctx->H[6] += g; ctx->H[7] += h;
}

// =====================================================
// Public API
// =====================================================
void sha512_init(sha512_ctx_t* ctx)
{
    static const uint64_t H0[8] = {
        0x6a09e667f3bcc908ULL,
        0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL,
        0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL,
        0x5be0cd19137e2179ULL
    };

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->H, H0, sizeof(H0));
}

void sha512_update(sha512_ctx_t* ctx,
    const unsigned char* data,
    size_t len)
{
    if (!ctx || !data || len == 0) return;

    // total_bits += len*8 (128-bit counter)
    uint64_t bits = (uint64_t)len * 8;
    ctx->total_bits_lo += bits;
    if (ctx->total_bits_lo < bits) ctx->total_bits_hi++;

    // buffer fill & compress
    size_t offset = 0;
    while (len > 0) {
        size_t space = SHA512_BLOCK_SIZE - ctx->buffer_len;
        size_t take = (len < space) ? len : space;

        memcpy(ctx->buffer + ctx->buffer_len, data + offset, take);
        ctx->buffer_len += take;
        offset += take;
        len -= take;

        if (ctx->buffer_len == SHA512_BLOCK_SIZE) {
            sha512_compress(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void sha512_final(sha512_ctx_t* ctx,
    unsigned char digest[SHA512_DIGEST_LENGTH])
{
    if (!ctx || !digest) return;

    // 1) append 0x80
    ctx->buffer[ctx->buffer_len++] = 0x80;

    // 2) pad zeros until length field fits (16 bytes)
    if (ctx->buffer_len > 112) {
        while (ctx->buffer_len < SHA512_BLOCK_SIZE) ctx->buffer[ctx->buffer_len++] = 0x00;
        sha512_compress(ctx, ctx->buffer);
        ctx->buffer_len = 0;
    }
    while (ctx->buffer_len < 112) ctx->buffer[ctx->buffer_len++] = 0x00;

    // 3) append 128-bit length in big-endian
    store_be64(ctx->buffer + 112, ctx->total_bits_hi);
    store_be64(ctx->buffer + 120, ctx->total_bits_lo);

    // 4) final compress
    sha512_compress(ctx, ctx->buffer);

    // 5) output digest big-endian
    for (int i = 0; i < 8; i++) {
        store_be64(digest + 8 * i, ctx->H[i]);
    }
}
