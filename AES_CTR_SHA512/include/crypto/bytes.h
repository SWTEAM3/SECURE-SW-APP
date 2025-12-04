#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    // ===============================
    // Big-Endian load/store helpers
    // ===============================
    // AES 키스케줄/라운드키, SHA-512 메시지 디코딩에서
    // “바이트 배열 ↔ 워드(uint32/uint64)” 변환을 통일하기 위한 공용 함수들

    static inline uint32_t load_be32(const unsigned char b[4]) {
        return ((uint32_t)b[0] << 24) |
            ((uint32_t)b[1] << 16) |
            ((uint32_t)b[2] << 8) |
            ((uint32_t)b[3]);
    }

    static inline void store_be32(unsigned char b[4], uint32_t x) {
        b[0] = (unsigned char)(x >> 24);
        b[1] = (unsigned char)(x >> 16);
        b[2] = (unsigned char)(x >> 8);
        b[3] = (unsigned char)(x);
    }

    static inline uint64_t load_be64(const unsigned char b[8]) {
        return ((uint64_t)b[0] << 56) |
            ((uint64_t)b[1] << 48) |
            ((uint64_t)b[2] << 40) |
            ((uint64_t)b[3] << 32) |
            ((uint64_t)b[4] << 24) |
            ((uint64_t)b[5] << 16) |
            ((uint64_t)b[6] << 8) |
            ((uint64_t)b[7]);
    }

    static inline void store_be64(unsigned char b[8], uint64_t x) {
        b[0] = (unsigned char)(x >> 56);
        b[1] = (unsigned char)(x >> 48);
        b[2] = (unsigned char)(x >> 40);
        b[3] = (unsigned char)(x >> 32);
        b[4] = (unsigned char)(x >> 24);
        b[5] = (unsigned char)(x >> 16);
        b[6] = (unsigned char)(x >> 8);
        b[7] = (unsigned char)(x);
    }

#ifdef __cplusplus
}
#endif
