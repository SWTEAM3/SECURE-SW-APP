#include "crypto/cipher/gf256_math.h"

// AES에서 쓰는 GF(2^8) 다항식: x^8 + x^4 + x^3 + x + 1  (0x11B)

// gf256_mul:
// - 러시안 피전트 방식(shift+xor)
// - MixColumns, xtime, 역원 계산의 기반
unsigned char gf256_mul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;

        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1B;  // 0x11B에서 x^8 항 제거한 값이 0x1B

        b >>= 1;
    }
    return p;
}

// gf256_pow:
// - 거듭제곱 (라그랑주식 역원 계산에 사용)
// - power는 일반 정수(바이트/워드 단위 의미 X)
unsigned char gf256_pow(unsigned char a, unsigned int power)
{
    unsigned char r = 1;
    while (power) {
        if (power & 1) r = gf256_mul(r, a);
        a = gf256_mul(a, a);
        power >>= 1;
    }
    return r;
}

// gf256_inv:
// - a^(2^8-2) = a^254
// - 0의 역원은 AES 정의상 0
unsigned char gf256_inv(unsigned char a)
{
    if (a == 0) return 0;
    return gf256_pow(a, 254);
}
