#pragma once
#include "gf256_math.h"

#ifdef __cplusplus
extern "C" {
#endif

    // AES S-box를 “수학적으로” 계산/생성하기 위한 레이어
    // (ref AES / ttable AES 모두 여기 의존)

    // 단일 바이트 S-box 계산: 역원 + 아핀 변환
    unsigned char aes_sbox_eval(unsigned char x);

    // 단일 바이트 Inv S-box 계산 (필요 시)
    unsigned char aes_inv_sbox_eval(unsigned char y);

    // 256 엔트리 S-box / InvS-box 테이블 생성
    void aes_sbox_build_tables(unsigned char sbox[256],
        unsigned char inv_sbox[256]);

#ifdef __cplusplus
}
#endif