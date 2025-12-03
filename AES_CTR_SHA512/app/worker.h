#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

    // 메인 윈도우와 작업 스레드가 공통으로 사용하는 사용자 정의 메시지
#define WM_WORKER_COMPLETE  (WM_USER + 1)
#define WM_WORKER_ERROR     (WM_USER + 2)
#define WM_WORKER_PROGRESS  (WM_USER + 3)
#define WM_HMAC_VERIFIED    (WM_USER + 4)

// 작업 스레드에 전달할 데이터 구조체
    typedef struct {
        int methodIndex;     // 0 = AES-CTR, 1 = AES-CTR+HMAC-SHA512, 2 = SHA-512
        int isEncrypt;       // 1 = 암호화, 0 = 복호화
        int engineIndex;     // 0 = T-table, 1 = Reference
        int aesKeyLen;       // AES 키 길이 (바이트): 16/24/32

        unsigned char aes_key[32];   // AES 키 (최대 256비트)
        unsigned char hmac_key[32];  // HMAC 키 (256비트)

        char inputFile[MAX_PATH];    // 입력 파일 경로
        char outputFile[MAX_PATH];   // 출력 파일 경로

        HWND hwnd;                   // 메인 윈도우 핸들 (메시지 전달용)
    } worker_data_t;

    // 작업 진행 여부 플래그 (메인/워커/모니터 스레드가 공유)
    extern volatile int g_workerRunning;

    // 작업 스레드 함수 (CreateThread에서 사용)
    DWORD WINAPI WorkerThreadProc(LPVOID lpParam);

#ifdef __cplusplus
}
#endif
