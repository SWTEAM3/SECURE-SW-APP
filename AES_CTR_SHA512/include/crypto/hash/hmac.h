#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "crypto/hash/hash_sha512.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* -------------------------------- Annotations (no-op) ---------------------------------- */
#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif
#ifndef INOUT
#define INOUT
#endif

/* =========================================================================================
    * HMAC — Message Authentication Code (HMAC-SHA-512)
    * ========================================================================================= */

    /* HMAC-SHA-512 컨텍스트 구조체 */
    typedef struct {
        sha512_ctx_t ctx;                    /* 내부 SHA-512 연산 상태 저장 */
        uint8_t      key[SHA512_BLOCK_SIZE]; /* 블록 크기(128바이트)로 확장된 키 */
    } hmac_ctx;

    /* HMAC 초기화 함수
        - 긴 키는 SHA-512로 해시하여 사용
        - 짧은 키는 블록 크기까지 0으로 패딩 */
    void hmac_init(OUT hmac_ctx* c, IN const uint8_t* key, IN size_t key_len);

    /* HMAC 입력 데이터 추가
        - 여러 번 호출 가능 (스트리밍 처리) */
    void hmac_update(INOUT hmac_ctx* c, IN const void* data, IN size_t len);

    /* HMAC 계산 종료
        - 최종 MAC(64바이트)을 mac 버퍼에 저장 */
    void hmac_final(INOUT hmac_ctx* c, OUT uint8_t mac[SHA512_DIGEST_LENGTH]);

    /* HMAC-SHA-512 계산 후 결과를 바로 출력하는 함수 */
    void hmac_print(void);

    /* HMAC-SHA-512 테스트 벡터 비교 함수
        - expected_tag와 실제 계산값을 비교하여 일치 여부 출력 */
    void test_vector_check_hmac_sha512(
        IN const uint8_t* key,
        IN size_t key_len,
        IN const char* msg,
        IN const uint8_t* expected_tag,
        IN size_t tag_len);

#ifdef __cplusplus
}
#endif
