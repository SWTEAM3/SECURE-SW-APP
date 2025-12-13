#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "crypto/hash/hash_sha512.h"
#include "crypto/hash/hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* =========================================================================================
     * HMAC 메시지 인증 코드 구현 (HMAC-SHA-512)
     *  - 키 전처리: 긴 키는 SHA-512로 해시해 64바이트로 압축, 짧은 키는 블록 크기(128바이트)까지 0 패딩
     *  - 내부 해시: H( (K ⊕ ipad) || 메시지 )
     *  - 외부 해시: H( (K ⊕ opad) || 내부 해시 결과 )
     * ========================================================================================= */

    // HMAC 초기화: 키를 블록 크기에 맞춰 전처리하고 (K ⊕ ipad)를 넣어 내부 해시를 시작
    void hmac_init(OUT hmac_ctx* c, IN const uint8_t* key, IN size_t key_len) {
        if (!c || !key) return;

        uint8_t processed_key[SHA512_BLOCK_SIZE];

        // 키가 블록 크기보다 길면 SHA-512로 해시해 64바이트로 압축
        if (key_len > SHA512_BLOCK_SIZE) {
            uint8_t key_hash[SHA512_DIGEST_LENGTH];
            sha512_ctx_t temp_ctx;
            sha512_init(&temp_ctx);
            sha512_update(&temp_ctx, key, key_len);
            sha512_final(&temp_ctx, key_hash);
            memcpy(processed_key, key_hash, SHA512_DIGEST_LENGTH);
            memset(processed_key + SHA512_DIGEST_LENGTH, 0,
                SHA512_BLOCK_SIZE - SHA512_DIGEST_LENGTH);
        }
        else {
            // 키가 블록 이하일 때는 그대로 복사
            memcpy(processed_key, key, key_len);
        }

        // 키가 블록보다 짧으면 나머지를 0으로 패딩
        if (key_len < SHA512_BLOCK_SIZE) {
            memset(processed_key + key_len, 0, SHA512_BLOCK_SIZE - key_len);
        }

        // (K ⊕ ipad) 계산
        uint8_t ipad_key[SHA512_BLOCK_SIZE];
        for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
            ipad_key[i] = processed_key[i] ^ 0x36;
        }

        // 내부 해시 시작: H( (K ⊕ ipad) || 메시지 )
        sha512_init(&c->ctx);
        sha512_update(&c->ctx, ipad_key, SHA512_BLOCK_SIZE);

        // (K ⊕ opad)를 만들기 위해 처리된 키를 보관
        memcpy(c->key, processed_key, SHA512_BLOCK_SIZE);
    }

    // 메시지 입력 (여러 번 호출 가능)
    void hmac_update(INOUT hmac_ctx* c, IN const void* data, IN size_t len) {
        if (!c || !data || len == 0) return;
        sha512_update(&c->ctx, data, len);
    }

    // HMAC 계산 완료: (K ⊕ opad)와 내부 해시 결과를 합쳐 최종 MAC 생성
    void hmac_final(INOUT hmac_ctx* c, OUT uint8_t mac[SHA512_DIGEST_LENGTH]) {
        if (!c || !mac) return;

        uint8_t inner_hash[SHA512_DIGEST_LENGTH];
        sha512_final(&c->ctx, inner_hash);

        uint8_t opad_key[SHA512_BLOCK_SIZE];
        for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
            opad_key[i] = c->key[i] ^ 0x5C;
        }

        sha512_ctx_t outer_ctx;
        sha512_init(&outer_ctx);
        sha512_update(&outer_ctx, opad_key, SHA512_BLOCK_SIZE);
        sha512_update(&outer_ctx, inner_hash, SHA512_DIGEST_LENGTH);
        sha512_final(&outer_ctx, mac);
    }

    // 편의 함수: 한 번에 HMAC-SHA512 계산
    void hmac_sha512(IN const uint8_t* key,
        IN size_t key_len,
        IN const void* data,
        IN size_t len,
        OUT uint8_t mac[SHA512_DIGEST_LENGTH]) {

        if (!key || !mac) return;
        if (!data && len > 0) return;

        hmac_ctx ctx;
        hmac_init(&ctx, key, key_len);
        if (data && len > 0) {
            hmac_update(&ctx, data, len);
        }
        hmac_final(&ctx, mac);
    }

    // 간단한 콘솔 데모: 키와 메시지를 입력받아 HMAC-SHA512를 출력
    void hmac_print(void) {
        printf("===== HMAC (Hash Message Authentication Code) =====\n");

        printf("Enter key:\n> ");
        char key_buf[256];
        if (!fgets(key_buf, sizeof(key_buf), stdin)) {
            printf("Key input error.\n");
            return;
        }
        key_buf[strcspn(key_buf, "\r\n")] = '\0';

        printf("Enter message:\n> ");
        char msg_buf[512];
        if (!fgets(msg_buf, sizeof(msg_buf), stdin)) {
            printf("Message input error.\n");
            return;
        }
        msg_buf[strcspn(msg_buf, "\r\n")] = '\0';

        size_t key_len = strlen(key_buf);
        size_t msg_len = strlen(msg_buf);

        uint8_t mac[SHA512_DIGEST_LENGTH];
        hmac_sha512((const uint8_t*)key_buf, key_len, msg_buf, msg_len, mac);

        printf("\nHMAC-SHA512 = ");
        for (size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
            printf("%02X", mac[i]);
        }
        printf("\n");
    }

    // 테스트 벡터 비교 헬퍼
    static void print_hex_local(const uint8_t* buf, size_t n) {
        for (size_t i = 0; i < n; i++) printf("%02X", buf[i]);
        printf("\n");
    }

    void test_vector_check_hmac_sha512(
        IN const uint8_t* key,
        IN size_t key_len,
        IN const char* msg,
        IN const uint8_t* expected_tag,
        IN size_t tag_len
    ) {
        uint8_t tag[SHA512_DIGEST_LENGTH];
        hmac_ctx ctx;

        hmac_init(&ctx, key, key_len);
        hmac_update(&ctx, (const uint8_t*)msg, strlen(msg));
        hmac_final(&ctx, tag);

        printf("Test Vector (HMAC-SHA-512)\n");
        printf("Key length : %zu bytes\n", key_len);
        printf("Message    : %s\n", msg);

        printf("=== Computed HMAC-SHA-512 ===\n");
        print_hex_local(tag, tag_len);

        printf("=== Expected HMAC-SHA-512 ===\n");
        print_hex_local(expected_tag, tag_len);

        printf("=== HMAC Test Vector Comparison Result ===\n");
        if (memcmp(tag, expected_tag, tag_len) == 0) {
            printf("True!\n\n\n");
        }
        else {
            printf("False!\n\n\n");
        }
    }

#ifdef __cplusplus
}
#endif
