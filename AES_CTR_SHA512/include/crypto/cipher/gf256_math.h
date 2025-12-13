#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GF256_FIELD_BITS
#define GF256_FIELD_BITS 8
#endif

#ifndef GF256_MOD_POLY
#define GF256_MOD_POLY 0x1B
#endif

#ifndef GF256_INV_EXP
#define GF256_INV_EXP 254
#endif

	// GF(2^8) 유한체 연산 선언
	// AES S-box 계산 및 MixColumns 등에서 사용됨

	// 곱셈: AES에서 xtime(), MixColumns에 필수
	unsigned char gf256_mul(unsigned char a, unsigned char b);

	// 거듭제곱 (주로 역원 계산용)
	unsigned char gf256_pow(unsigned char a, unsigned int power);

	// 역원: AES S-box = a^{-1} 에 기반
	unsigned char gf256_inv(unsigned char a);

#ifdef __cplusplus
}
#endif
