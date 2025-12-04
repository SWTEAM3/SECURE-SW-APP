#pragma once

#ifdef __cplusplus
extern "C" {
#endif

    // 표준 에러/성공 코드
    // 모든 API가 동일한 규약을 사용하도록 통일

    typedef enum crypto_status_t {
        CRYPTO_OK = 0,          // 성공
        CRYPTO_ERR_NULL = -1,   // NULL 포인터 전달
        CRYPTO_ERR_IO = -2,     // 파일 I/O 실패
        CRYPTO_ERR_KEY = -3,    // 잘못된 키 또는 길이
        CRYPTO_ERR_INVALID = -4,// 잘못된 입력 인자
        CRYPTO_ERR_MEMORY = -5, // 메모리 할당 실패
        CRYPTO_ERR_STATE = -6   // 잘못된 상태
    } crypto_status_t;

#ifdef __cplusplus
}
#endif
