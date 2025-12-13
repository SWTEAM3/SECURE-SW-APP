#include "crypto/cipher/gf256_math.h"

// AES에서 쓰는 GF(2^8) 다항식: x^8 + x^4 + x^3 + x + 1  (0x11B)
//  - 바이트 연산을 다항식 연산으로 해석해 MixColumns, S-box 등을 구성한다.

#define GF256_MOD_POLY   0x1B   // 0x11B 에서 x^8 항 제거한 감소 다항식
#define GF256_FIELD_BITS 8
#define GF256_INV_EXP    254    // 2^8 - 2

// gf256_mul:
// - 러시안 피전트 방식(shift+xor)으로 8비트 곱을 구현.
// - 매 스텝마다 x를 한 비트 왼쪽으로 올리고, 최고차항이 1이면 0x1B(=0x11B 모듈러)로 줄인다.
// - MixColumns, xtime, 역원 계산 등 AES 대부분의 GF 연산에 공통 사용.
unsigned char gf256_mul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for (int i = 0; i < GF256_FIELD_BITS; i++) {
        if (b & 1) p ^= a;

        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= GF256_MOD_POLY;  // 0x11B에서 x^8 항 제거한 값이 0x1B

        b >>= 1;
    }
    return p;
}

// gf256_pow:
// - 거듭제곱 계산. 제곱-곱(binary exponentiation)으로 8비트 거듭제곱을 빠르게 계산한다.
// - power는 일반 정수 지수이며, 역원 계산(a^254) 등에 사용된다.
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
// - 제곱-곱으로 a^(2^8-2) = a^254 를 계산해 역원을 얻는다.
// - 0의 역원은 AES 정의상 0으로 취급한다.
unsigned char gf256_inv(unsigned char a)
{
    if (a == 0) return 0;
    return gf256_pow(a, GF256_INV_EXP);
}
