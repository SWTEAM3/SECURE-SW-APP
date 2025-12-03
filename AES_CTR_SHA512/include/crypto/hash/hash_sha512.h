#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 블록 크기: 1024비트(128바이트)
#define SHA512_BLOCK_SIZE      128
// 출력 해시 크기: 512비트(64바이트)
#define SHA512_DIGEST_LENGTH   64
// 중간 상태 배열 개수 (a..h, 8개)
#define SHA_WORD_NUMBER        8

// 스트림 처리용 기본 버퍼 크기
#define BUF_SIZE 4096

    // SHA-512 컨텍스트
    // - 64바이트의 출력 값을 만들기 위한 중간 상태를 버퍼에 저장
    // - 1024비트(128바이트)의 블록 단위로 처리
    typedef struct sha512_ctx_t {
        uint64_t H[SHA_WORD_NUMBER];              // 현재 해시 상태 (8 x 64bit)
        uint64_t total_bits_hi;                   // 처리된 전체 비트 수(상위 64비트)
        uint64_t total_bits_lo;                   // 처리된 전체 비트 수(하위 64비트)
        unsigned char buffer[SHA512_BLOCK_SIZE];  // 남은 데이터(블록 미만)를 임시 저장
        size_t buffer_len;                        // buffer에 저장된 실제 바이트 수
    } sha512_ctx_t;

    // 초기화: H0..H7 초기값으로 설정
    void sha512_init(sha512_ctx_t* ctx);

    // 업데이트(비트스트림 입력): data[0..len-1] 추가
    void sha512_update(sha512_ctx_t* ctx,
        const unsigned char* data,
        size_t len);

    // 최종 처리:
    // - SHA-512 패딩(0x80, 0 패딩, 128비트 크기 빅엔디안)을 적용
    // - 남은 블록을 모두 처리
    // - digest[64]를 big-endian(상위바이트 우선)으로 결과 저장
    void sha512_final(sha512_ctx_t* ctx,
        unsigned char digest[64]);

#ifdef __cplusplus
}
#endif
