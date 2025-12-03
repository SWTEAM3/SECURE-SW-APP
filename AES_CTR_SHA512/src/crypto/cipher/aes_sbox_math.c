#include "crypto/cipher/aes_sbox_math.h"

// AES 아핀 변환에서 사용하는 상수
// 0x63 = 0110 0011₂
static unsigned char aes_affine(unsigned char x)
{
    unsigned char y = 0;
    // 아핀 변환: y = M*x + c (GF(2) 행렬 연산)
    y ^= (x << 1) | (x >> 7);
    y ^= (x << 2) | (x >> 6);
    y ^= (x << 3) | (x >> 5);
    y ^= (x << 4) | (x >> 4);
    y ^= x ^ 0x63;
    return y;
}

// S-box = affine( inv(x) )
unsigned char aes_sbox_eval(unsigned char x)
{
    unsigned char inv = gf256_inv(x);
    return aes_affine(inv);
}

// Inv S-box 계산 (역아핀 + 역원)
static unsigned char aes_inv_affine(unsigned char y)
{
    unsigned char x = 0;
    // 아핀 역변환(행렬 역 + 상수 제거)
    x ^= (y << 1) | (y >> 7);
    x ^= (y << 3) | (y >> 5);
    x ^= (y << 6) | (y >> 2);
    x ^= 0x05; // 역변환 상수
    return x;
}

unsigned char aes_inv_sbox_eval(unsigned char y)
{
    unsigned char xa = aes_inv_affine(y);
    return gf256_inv(xa);  // 역원
}

// 전체 256바이트 테이블 생성
void aes_sbox_build_tables(unsigned char sbox[256],
    unsigned char inv_sbox[256])
{
    for (int i = 0; i < 256; i++) {
        sbox[i] = aes_sbox_eval((unsigned char)i);
        inv_sbox[sbox[i]] = (unsigned char)i;
    }
}
