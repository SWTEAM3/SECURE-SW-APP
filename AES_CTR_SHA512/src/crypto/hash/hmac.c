#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "crypto/hash/hash_sha512.h"
#include "crypto/hash/hmac.h"
//#include "util1122.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* =========================================================================================
     * HMAC — Message Authentication Code Implementation (HMAC-SHA-512)
     * ========================================================================================= */

    void hmac_init(OUT hmac_ctx* c, IN const uint8_t* key, IN size_t key_len) {
        if (!c || !key) return;                           // HMAC 컨텍스트 또는 키가 NULL이면 종료

        uint8_t processed_key[SHA512_BLOCK_SIZE];        // 블록 크기에 맞춘 처리된 키

        // 키가 블록 크기보다 길면 SHA-512로 한 번 해시해서 사용
        if (key_len > SHA512_BLOCK_SIZE) {
            uint8_t key_hash[SHA512_DIGEST_LENGTH];      // 긴 키를 해시한 결과
            sha512_ctx_t temp_ctx;
            sha512_init(&temp_ctx);                      // 임시 SHA-512 컨텍스트 초기화
            sha512_update(&temp_ctx, key, key_len);      // 긴 키 전체 입력
            sha512_final(&temp_ctx, key_hash);           // 해시 완료 → key_hash에 저장
            memcpy(processed_key, key_hash, SHA512_DIGEST_LENGTH);
            memset(processed_key + SHA512_DIGEST_LENGTH,
                0,
                SHA512_BLOCK_SIZE - SHA512_DIGEST_LENGTH);   // 남는 부분 0 패딩
        }
        else {
            // 키가 블록 이하일 때는 그대로 복사
            memcpy(processed_key, key, key_len);
        }

        // 키가 블록보다 짧으면 나머지를 0으로 패딩
        if (key_len < SHA512_BLOCK_SIZE) {
            memset(processed_key + key_len,
                0,
                SHA512_BLOCK_SIZE - key_len);
        }

        // (K ⊕ ipad) 계산
        uint8_t ipad_key[SHA512_BLOCK_SIZE];
        for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
            ipad_key[i] = processed_key[i] ^ 0x36;        // ipad(0x36)와 XOR
        }

        // 내부 해시: H( (K ⊕ ipad) || 메시지 )
        sha512_init(&c->ctx);                            // 내부 SHA-512 해시 초기화
        sha512_update(&c->ctx, ipad_key, SHA512_BLOCK_SIZE); // (K ⊕ ipad) 입력

        // 나중에 (K ⊕ opad)를 만들기 위해 처리된 키를 보관
        memcpy(c->key, processed_key, SHA512_BLOCK_SIZE);
    }

    void hmac_update(INOUT hmac_ctx* c, IN const void* data, IN size_t len) {
        if (!c || !data || len == 0) return;             // 유효성 검사
        sha512_update(&c->ctx, data, len);               // 메시지 데이터 업데이트
    }

    void hmac_final(INOUT hmac_ctx* c, OUT uint8_t mac[SHA512_DIGEST_LENGTH]) {
        if (!c || !mac) return;                           // NULL 검사

        uint8_t inner_hash[SHA512_DIGEST_LENGTH];         // 내부 해시 결과 저장
        sha512_final(&c->ctx, inner_hash);                // 내부 해시 완료 → inner_hash

        // (K ⊕ opad) 계산
        uint8_t opad_key[SHA512_BLOCK_SIZE];
        for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
            opad_key[i] = c->key[i] ^ 0x5C;               // opad(0x5C)와 XOR
        }

        // 외부 해시: H( (K ⊕ opad) || inner_hash )
        sha512_ctx_t outer_ctx;                           // 외부 SHA-512 컨텍스트
        sha512_init(&outer_ctx);                          // 외부 해시 초기화
        sha512_update(&outer_ctx, opad_key, SHA512_BLOCK_SIZE);          // (K ⊕ opad)
        sha512_update(&outer_ctx, inner_hash, SHA512_DIGEST_LENGTH);     // 내부 해시값
        sha512_final(&outer_ctx, mac);                    // 최종 MAC 출력
    }

    void hmac_sha512(IN const uint8_t* key,
        IN size_t key_len,
        IN const void* data,
        IN size_t len,
        OUT uint8_t mac[SHA512_DIGEST_LENGTH]) {

        if (!key || !mac) return;                         // 필수 포인터 검사
        if (!data && len > 0) return;                     // NULL 데이터 + 길이>0 → 잘못된 입력

        hmac_ctx ctx;                                      // 로컬 HMAC 컨텍스트 생성
        hmac_init(&ctx, key, key_len);                     // HMAC 초기화(K ⊕ ipad까지 처리)

        if (data && len > 0) {
            hmac_update(&ctx, data, len);                  // 메시지 입력
        }

        hmac_final(&ctx, mac);                             // HMAC 최종값 계산
    }

    /*
    void hmac_print(void) {
        printf("===== HMAC (Hash Message Authentication Code) =====\n");   // HMAC 모드 시작 안내

        printf("Enter key:\n> ");
        char* key_buf = read_line_dynamic();               // 한 줄 키 입력 (malloc 사용)
        if (!key_buf) {
            printf("Key input error.\n");
            return;
        }

        printf("Enter message:\n> ");
        char* msg_buf = read_line_dynamic();               // 한 줄 메시지 입력
        if (!msg_buf) {
            printf("Message input error.\n");
            free(key_buf);
            return;
        }

        size_t key_len = strlen(key_buf);                  // 키 문자열 길이
        size_t msg_len = strlen(msg_buf);                  // 메시지 문자열 길이

        const uint8_t* key = (const uint8_t*)key_buf;
        const uint8_t* data = (const uint8_t*)msg_buf;

        uint8_t mac[SHA512_DIGEST_LENGTH];                 // 최종 HMAC 결과 버퍼

        hmac_sha512(key, key_len, data, msg_len, mac);     // HMAC 계산

        printf("\nHMAC-SHA512 = ");
        for (size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
            printf("%02X", mac[i]);
        }
        printf("\n");

        free(key_buf);
        free(msg_buf);
    }

    void test_vector_check_hmac_sha512(
        IN const uint8_t* key,
        IN size_t key_len,
        IN const char* msg,
        IN const uint8_t* expected_tag,
        IN size_t tag_len
    ) {
        uint8_t tag[SHA512_DIGEST_LENGTH];                // 계산된 태그 저장
        hmac_ctx ctx;

        hmac_init(&ctx, key, key_len);                    // HMAC 초기화
        hmac_update(&ctx, (const uint8_t*)msg, strlen(msg)); // 메시지 업데이트
        hmac_final(&ctx, tag);                            // 최종 MAC 생성

        printf("Test Vector (HMAC-SHA-512)\n");
        printf("Key length : %zu bytes\n", key_len);
        printf("Message    : %s\n", msg);

        printf("=== Computed HMAC-SHA-512 Test Vector ===\n");
        print_hex(tag, tag_len);                          // 계산된 태그 출력

        printf("=== Expected HMAC-SHA-512 Test Vector ===\n");
        print_hex(expected_tag, tag_len);                 // 기대되는 태그 출력

        printf("=== HMAC Test Vector Comparison Result ===\n");
        if (memcmp(tag, expected_tag, tag_len) == 0) {
            printf("True!\n\n\n");
        }
        else {
            printf("False!\n\n\n");
        }
    }*/

#ifdef __cplusplus
}
#endif