#include "crypto/cipher/aes_sbox_math.h"

#define AES_SBOX_SIZE         256
#define AES_AFFINE_CONST      0x63
#define AES_INV_AFFINE_CONST  0x05

// AES 아핀 변환에서 사용하는 상수(0x63 = 0110 0011₂).
// 인풋 x 는 GF(2^8) 원소(1바이트). 행렬-벡터 곱과 상수 더하기를 비트연산으로 전개.
static unsigned char aes_affine(unsigned char x)
{
    unsigned char y = 0;
    // 아핀 변환: y = M*x + c (GF(2) 행렬 연산)
    y ^= (x << 1) | (x >> 7);
    y ^= (x << 2) | (x >> 6);
    y ^= (x << 3) | (x >> 5);
    y ^= (x << 4) | (x >> 4);
    y ^= x ^ AES_AFFINE_CONST;
    return y;
}

// S-box = affine( inv(x) )
//  - 0 입력은 역원이 정의상 0 (Rijndael 규약)
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
    x ^= AES_INV_AFFINE_CONST; // 역변환 상수
    return x;
}

unsigned char aes_inv_sbox_eval(unsigned char y)
{
    unsigned char xa = aes_inv_affine(y);
    return gf256_inv(xa);  // 역원
}

// 전체 256바이트 테이블 생성
//  - sbox[i] 는 SubBytes용 순방향 테이블
//  - inv_sbox[v] 에는 역함수를 바로 찾을 수 있게 역치환을 채움
void aes_sbox_build_tables(unsigned char sbox[256],
    unsigned char inv_sbox[256])
{
    for (int i = 0; i < AES_SBOX_SIZE; i++) {
        sbox[i] = aes_sbox_eval((unsigned char)i);
        inv_sbox[sbox[i]] = (unsigned char)i;
    }
}
