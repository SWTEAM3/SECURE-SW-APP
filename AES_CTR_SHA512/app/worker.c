#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/stream/stream_api.h"
#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_engine_ttable.h"
#include "crypto/mode/mode_ctr.h"
#include "crypto/hash/hash_sha512.h"
#include "crypto/hash/hmac.h"
#include "ui_helpers.h"
#include "perf_utils.h"

#include "worker.h"

// 이 파일이 g_workerRunning의 실제 정의를 가짐
volatile int g_workerRunning = 0;

// 전체 파일 크기 (필요하면 진행률 계산에 활용 가능)
static volatile long long g_totalFileSize = 0;

// 평균 메모리 사용량 계산용 (500ms마다 샘플링)
static volatile SIZE_T g_memSum = 0;      // 누적합
static volatile DWORD g_memSampleCount = 0;  // 샘플 수
static volatile DWORD g_lastMemCheck = 0;    // 마지막 메모리 체크 시각

// 진행률 모니터 스레드 데이터
typedef struct {
    HWND hwnd;
    const char* outputFile;
    long long totalSize;
    volatile int* running;
    int isHashMode;  // SHA-512 해시 모드인지 여부
} monitor_data_t;

/* --------------------------------------------------------------------
 * 진행률 모니터 스레드
 *  - AES-CTR / AES-CTR+HMAC 모드에서 출력 파일 크기(or 추정 시간)을
 *    기반으로 진행률을 메인 윈도우에 WM_WORKER_PROGRESS로 전달
 * ------------------------------------------------------------------*/
static DWORD WINAPI MonitorThreadProc(LPVOID lpParam) {
    monitor_data_t* mdata = (monitor_data_t*)lpParam;
    if (!mdata) return 1;

    // 초기 진행률 0% 설정
    PostMessageA(mdata->hwnd, WM_WORKER_PROGRESS, 0, 0);

    DWORD startTime = GetTickCount();
    int lastPercent = 0;
    
    // 메모리 샘플링 초기화
    g_memSum = 0;
    g_memSampleCount = 0;
    g_lastMemCheck = GetTickCount();

    while (*mdata->running) {
        // 500ms마다 메모리 샘플링
        DWORD now = GetTickCount();
        if (now - g_lastMemCheck >= 500) {
            SIZE_T mem = GetProcessMemoryUsageKB();
            if (mem > 0) {
                g_memSum += mem;
                g_memSampleCount++;
            }
            g_lastMemCheck = now;
        }
        
        if (mdata->isHashMode) {
            // SHA-512 해시 모드: 시간 기반 추정 (현재는 사용 안 함)
            DWORD elapsed = GetTickCount() - startTime;
            long long estimatedTimeMs =
                (mdata->totalSize / (100 * 1024 * 1024)) * 1000;  // 100MB/s 가정

            if (estimatedTimeMs < 1000)
                estimatedTimeMs = 1000;  // 최소 1초

            int percent = (int)((elapsed * 95) / estimatedTimeMs);  // 95%까지만
            if (percent > 95) percent = 95;

            if (percent > lastPercent) {
                PostMessageA(mdata->hwnd, WM_WORKER_PROGRESS, percent, 0);
                lastPercent = percent;
            }
        }
        else {
            // 일반 모드: 출력 파일 크기를 기반으로 진행률 계산
            long long currentSize = GetFileSizeBytes(mdata->outputFile);
            if (mdata->totalSize > 0) {
                int percent = 0;
                if (currentSize > 0) {
                    percent = (int)((currentSize * 100) / mdata->totalSize);
                    if (percent > 100) percent = 100;
                }
                PostMessageA(mdata->hwnd, WM_WORKER_PROGRESS, percent, 0);
            }
        }
        Sleep(100);  // 100ms마다 확인
    }

    free(mdata);
    return 0;
}

/* --------------------------------------------------------------------
 * 작업 스레드 함수
 *  - AES-CTR
 *  - AES-CTR + HMAC-SHA512 (형태: IV || CT || HMAC)
 *  - SHA-512 파일 해시
 * ------------------------------------------------------------------*/
DWORD WINAPI WorkerThreadProc(LPVOID lpParam) {
    worker_data_t* data = (worker_data_t*)lpParam;
    if (!data) return 1;

    // 시간 및 메모리 측정용 변수
    ULONGLONG start_ms = GetTickCount64();
    ULONGLONG elapsed_ms = 0;
    SIZE_T mem_kb = 0;

    // 파일 크기
    long long totalSize = GetFileSizeBytes(data->inputFile);
    if (totalSize > 0) {
        g_totalFileSize = totalSize;
        PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 0, 0);  // 0% 시작
    }

    int rc = 0;
    const blockcipher_vtable_t* engine =
        (data->engineIndex == 1) ? &AES_REF_ENGINE : &AES_TTABLE_ENGINE;

    int useAesCtr = (data->methodIndex == 0 || data->methodIndex == 1);
    int useHmac = (data->methodIndex == 1);

    unsigned char iv[16] = { 0 };
    char encryptedFile[MAX_PATH + 20] = { 0 };
    char msg[512];

    /* ===============================================================
     * 1) AES-CTR + HMAC-SHA512 (iv || ct || hmac)
     * =============================================================*/
    if (useAesCtr && useHmac) {
        if (data->isEncrypt) {
            // 암호화: iv||ct||hmac 형태로 저장
            // 1. 랜덤 IV 생성
            GenerateRandomBytes(iv, 16);

            // 2. 임시 파일에 암호문 저장
            char tempFile[MAX_PATH + 20];
            strncpy(tempFile, data->outputFile, MAX_PATH - 1);
            tempFile[MAX_PATH - 1] = '\0';
            char* ext = strrchr(tempFile, '.');
            if (ext) *ext = '\0';
            size_t tlen = strlen(tempFile);
            if (tlen + 10 < MAX_PATH) {
                strcat(tempFile, ".tmp");
            }

            // 진행률 모니터 스레드 시작
            if (totalSize > 0) {
                monitor_data_t* monitorData =
                    (monitor_data_t*)malloc(sizeof(monitor_data_t));
                if (monitorData) {
                    monitorData->hwnd = data->hwnd;
                    monitorData->outputFile = tempFile;
                    monitorData->totalSize = totalSize;
                    monitorData->running = &g_workerRunning;
                    monitorData->isHashMode = 0;

                    HANDLE hMonitorThread =
                        CreateThread(NULL, 0, MonitorThreadProc, monitorData, 0, NULL);
                    if (hMonitorThread) {
                        // 스레드는 detach 형태로 동작 (핸들만 닫고 기다리지 않음)
                        CloseHandle(hMonitorThread);
                    }
                }
            }

            rc = stream_encrypt_ctr_file(engine,
                data->inputFile,
                tempFile,
                data->aes_key,
                data->aesKeyLen,
                iv);
            if (rc != 0) {
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, rc, 0);
                free(data);
                return 1;
            }

            // 3. IV + 암호문에 대해 HMAC 계산
            PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 90, 0);

            FILE* f_temp = fopen(tempFile, "rb");
            if (!f_temp) {
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -104, 0);
                free(data);
                return 1;
            }

            hmac_ctx hmac_ctx_obj;
            hmac_init(&hmac_ctx_obj, data->hmac_key, 32);

            // IV 추가
            hmac_update(&hmac_ctx_obj, iv, 16);

            // 암호문 추가
            size_t buf_size = 1024 * 1024;
            unsigned char* buf = (unsigned char*)malloc(buf_size);
            if (!buf) {
                fclose(f_temp);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -202, 0);
                free(data);
                return 1;
            }

            size_t n;
            while ((n = fread(buf, 1, buf_size, f_temp)) > 0) {
                hmac_update(&hmac_ctx_obj, buf, n);
            }
            fclose(f_temp);
            free(buf);

            unsigned char hmac_mac[64];
            hmac_final(&hmac_ctx_obj, hmac_mac);

            // HMAC 계산 완료, 최종 파일 작성 시작 (95%)
            PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 95, 0);

            // 4. 최종 파일: IV(16) + 암호문 + HMAC(64)
            FILE* f_out = fopen(data->outputFile, "wb");
            if (!f_out) {
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -105, 0);
                free(data);
                return 1;
            }

            // IV 쓰기
            if (fwrite(iv, 1, 16, f_out) != 16) {
                fclose(f_out);
                remove(data->outputFile);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -111, 0);
                free(data);
                return 1;
            }

            // 암호문 복사
            f_temp = fopen(tempFile, "rb");
            if (!f_temp) {
                fclose(f_out);
                remove(data->outputFile);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -104, 0);
                free(data);
                return 1;
            }

            buf = (unsigned char*)malloc(buf_size);
            if (!buf) {
                fclose(f_temp);
                fclose(f_out);
                remove(data->outputFile);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -202, 0);
                free(data);
                return 1;
            }

            while ((n = fread(buf, 1, buf_size, f_temp)) > 0) {
                if (fwrite(buf, 1, n, f_out) != n) {
                    free(buf);
                    fclose(f_temp);
                    fclose(f_out);
                    remove(data->outputFile);
                    remove(tempFile);
                    PostMessageA(data->hwnd, WM_WORKER_ERROR, -112, 0);
                    free(data);
                    return 1;
                }
            }
            free(buf);
            fclose(f_temp);

            // HMAC 쓰기
            if (fwrite(hmac_mac, 1, 64, f_out) != 64) {
                fclose(f_out);
                remove(data->outputFile);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -113, 0);
                free(data);
                return 1;
            }

            // 플러시 및 닫기
            fflush(f_out);
            if (fclose(f_out) != 0) {
                remove(data->outputFile);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -114, 0);
                free(data);
                return 1;
            }

            // 임시 파일 삭제
            remove(tempFile);

            // 최종 파일 존재 확인
            FILE* f_check = fopen(data->outputFile, "rb");
            if (!f_check) {
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -115, 0);
                free(data);
                return 1;
            }
            fclose(f_check);

            strncpy(encryptedFile, data->outputFile, MAX_PATH);

            // 100% 완료 표시
            PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 100, 0);
        }
        else {
            // 복호화: iv||ct||hmac 형태
            FILE* f_in = fopen(data->inputFile, "rb");
            if (!f_in) {
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -106, 0);
                free(data);
                return 1;
            }

            // 1. IV 읽기 (16 bytes)
            if (fread(iv, 1, 16, f_in) != 16) {
                fclose(f_in);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -107, 0);
                free(data);
                return 1;
            }

            // 2. 파일 크기 확인
            _fseeki64(f_in, 0, SEEK_END);
            long long fileSize = _ftelli64(f_in);
            if (fileSize < 16 + 64) {
                fclose(f_in);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -108, 0);
                free(data);
                return 1;
            }

            long long ctSize = fileSize - 16 - 64;  // 암호문 크기

            // 3. HMAC 읽기 (마지막 64 bytes)
            _fseeki64(f_in, fileSize - 64, SEEK_SET);
            unsigned char hmac_expected[64];
            if (fread(hmac_expected, 1, 64, f_in) != 64) {
                fclose(f_in);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -109, 0);
                free(data);
                return 1;
            }

            // 4. IV + 암호문에 대해 HMAC 검증
            _fseeki64(f_in, 0, SEEK_SET);
            hmac_ctx hmac_ctx_obj;
            hmac_init(&hmac_ctx_obj, data->hmac_key, 32);

            hmac_update(&hmac_ctx_obj, iv, 16);

            size_t buf_size = 1024 * 1024;
            unsigned char* buf = (unsigned char*)malloc(buf_size);
            if (!buf) {
                fclose(f_in);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -202, 0);
                free(data);
                return 1;
            }

            _fseeki64(f_in, 16, SEEK_SET);  // IV 다음부터
            long long remaining = ctSize;
            while (remaining > 0) {
                size_t to_read =
                    (remaining > (long long)buf_size) ? buf_size : (size_t)remaining;
                size_t n = fread(buf, 1, to_read, f_in);
                if (n == 0) break;
                hmac_update(&hmac_ctx_obj, buf, n);
                remaining -= (long long)n;
            }
            free(buf);

            unsigned char hmac_actual[64];
            hmac_final(&hmac_ctx_obj, hmac_actual);

            // HMAC 검증
            if (memcmp(hmac_expected, hmac_actual, 64) != 0) {
                fclose(f_in);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -103, 0);
                free(data);
                return 1;
            }

            // HMAC 검증 성공 후, 복호화 진행 여부를 메인 윈도우에 질의
            LRESULT userChoice = IDYES;
            if (IsWindow(data->hwnd)) {
                userChoice = SendMessageA(data->hwnd, WM_HMAC_VERIFIED, 0, 0);
            }

            if (userChoice != IDYES) {
                fclose(f_in);

                const char* doneMsg =
                    "인증에는 성공했지만, 사용자가 복호화를 취소했습니다.";
                char* msgCopy = (char*)malloc(strlen(doneMsg) + 1);
                if (msgCopy) {
                    strcpy(msgCopy, doneMsg);
                    PostMessageA(data->hwnd, WM_WORKER_COMPLETE, (WPARAM)msgCopy, 0);
                }
                else {
                    PostMessageA(data->hwnd, WM_WORKER_COMPLETE, 0, 0);
                }

                free(data);
                return 0;
            }

            // 5. 복호화 수행 (암호문을 임시 파일로 추출 후 복호화)
            char tempFile[MAX_PATH + 20];
            strncpy(tempFile, data->outputFile, MAX_PATH - 1);
            tempFile[MAX_PATH - 1] = '\0';
            char* ext = strrchr(tempFile, '.');
            if (ext) *ext = '\0';
            size_t tlen = strlen(tempFile);
            if (tlen + 10 < MAX_PATH) {
                strcat(tempFile, ".tmp");
            }

            FILE* f_temp = fopen(tempFile, "wb");
            if (!f_temp) {
                fclose(f_in);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -110, 0);
                free(data);
                return 1;
            }

            buf = (unsigned char*)malloc(buf_size);
            if (!buf) {
                fclose(f_in);
                fclose(f_temp);
                remove(tempFile);
                PostMessageA(data->hwnd, WM_WORKER_ERROR, -202, 0);
                free(data);
                return 1;
            }

            _fseeki64(f_in, 16, SEEK_SET);  // IV 다음부터
            remaining = ctSize;
            while (remaining > 0) {
                size_t to_read =
                    (remaining > (long long)buf_size) ? buf_size : (size_t)remaining;
                size_t n = fread(buf, 1, to_read, f_in);
                if (n == 0) break;
                fwrite(buf, 1, n, f_temp);
                remaining -= (long long)n;
            }
            free(buf);
            fclose(f_in);
            fclose(f_temp);

            // 진행률 모니터 스레드 시작 (복호화 출력 파일 기준)
            long long tempSize = GetFileSizeBytes(tempFile);
            if (tempSize > 0) {
                monitor_data_t* monitorData =
                    (monitor_data_t*)malloc(sizeof(monitor_data_t));
                if (monitorData) {
                    monitorData->hwnd = data->hwnd;
                    monitorData->outputFile = data->outputFile;
                    monitorData->totalSize = tempSize;
                    monitorData->running = &g_workerRunning;
                    monitorData->isHashMode = 0;

                    HANDLE hMonitorThread =
                        CreateThread(NULL, 0, MonitorThreadProc, monitorData, 0, NULL);
                    if (hMonitorThread) {
                        CloseHandle(hMonitorThread); // detach
                    }
                }
            }

            rc = stream_decrypt_ctr_file(engine,
                tempFile,
                data->outputFile,
                data->aes_key,
                data->aesKeyLen,
                iv);
            remove(tempFile);

            if (rc != 0) {
                PostMessageA(data->hwnd, WM_WORKER_ERROR, rc, 0);
                free(data);
                return 1;
            }

            PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 100, 0);
        }
    }
    /* ===============================================================
     * 2) AES-CTR (HMAC 없음)
     * =============================================================*/
    else if (useAesCtr) {
        // 출력 파일이 이미 존재하면 삭제 (진행률 계산을 위해)
        FILE* f = fopen(data->outputFile, "rb");
        if (f) {
            fclose(f);
            remove(data->outputFile);
        }

        // 진행률 모니터 스레드 시작
        if (totalSize > 0) {
            monitor_data_t* monitorData =
                (monitor_data_t*)malloc(sizeof(monitor_data_t));
            if (monitorData) {
                monitorData->hwnd = data->hwnd;
                monitorData->outputFile = data->outputFile;
                monitorData->totalSize = totalSize;
                monitorData->running = &g_workerRunning;
                monitorData->isHashMode = 0;

                HANDLE hMonitorThread =
                    CreateThread(NULL, 0, MonitorThreadProc, monitorData, 0, NULL);
                if (hMonitorThread) {
                    CloseHandle(hMonitorThread); // detach
                }
            }
        }

        if (data->isEncrypt) {
            // IV 생성
            GenerateRandomBytes(iv, 16);

            rc = stream_encrypt_ctr_file(engine,
                data->inputFile,
                data->outputFile,
                data->aes_key,
                data->aesKeyLen,
                iv);
            if (rc != 0) {
                PostMessageA(data->hwnd, WM_WORKER_ERROR, rc, 0);
                free(data);
                return 1;
            }
            strncpy(encryptedFile, data->outputFile, MAX_PATH);
        }
        else {
            rc = stream_decrypt_ctr_file(engine,
                data->inputFile,
                data->outputFile,
                data->aes_key,
                data->aesKeyLen,
                iv);
            if (rc != 0) {
                PostMessageA(data->hwnd, WM_WORKER_ERROR, rc, 0);
                free(data);
                return 1;
            }
        }

        PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 100, 0);
    }

    /* ===============================================================
     * 3) SHA-512 (파일 해시 계산)
     * =============================================================*/
    if (data->methodIndex == 2) {
        unsigned char hash[64];
        size_t buf_size = 1024 * 1024;  // 1MB
        unsigned char* file_buf = (unsigned char*)malloc(buf_size);
        if (!file_buf) {
            PostMessageA(data->hwnd, WM_WORKER_ERROR, -202, 0);
            free(data);
            return 1;
        }

        FILE* fp = fopen(data->inputFile, "rb");
        if (!fp) {
            free(file_buf);
            PostMessageA(data->hwnd, WM_WORKER_ERROR, -200, 0);
            free(data);
            return 1;
        }

        sha512_ctx_t ctx;
        sha512_init(&ctx);

        long long processed = 0;
        long long totalSize2 = GetFileSizeBytes(data->inputFile);
        int last_percent = -1;
        
        // SHA-512 모드 메모리 샘플링 초기화
        g_memSum = 0;
        g_memSampleCount = 0;
        g_lastMemCheck = GetTickCount();

        if (totalSize2 > 0) {
            PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 0, 0);
            last_percent = 0;
        }

        while (1) {
            // 500ms마다 메모리 샘플링
            DWORD now = GetTickCount();
            if (now - g_lastMemCheck >= 500) {
                SIZE_T mem = GetProcessMemoryUsageKB();
                if (mem > 0) {
                    g_memSum += mem;
                    g_memSampleCount++;
                }
                g_lastMemCheck = now;
            }
            
            size_t read_bytes = fread(file_buf, 1, buf_size, fp);

            if (read_bytes > 0) {
                sha512_update(&ctx, file_buf, read_bytes);
                processed += (long long)read_bytes;

                if (totalSize2 > 0) {
                    int percent = (int)(processed * 100 / totalSize2);
                    if (percent > 100) percent = 100;
                    if (percent != last_percent) {
                        PostMessageA(data->hwnd, WM_WORKER_PROGRESS, percent, 0);
                        last_percent = percent;
                    }
                }
            }

            if (read_bytes < buf_size) {
                if (feof(fp)) {
                    break;
                }
                if (ferror(fp)) {
                    free(file_buf);
                    fclose(fp);
                    PostMessageA(data->hwnd, WM_WORKER_ERROR, -201, 0);
                    free(data);
                    return 1;
                }
                if (read_bytes == 0) {
                    break;
                }
            }
        }

        free(file_buf);
        fclose(fp);

        // 최종 해시 계산
        sha512_final(&ctx, hash);

        // 진행률 100% 보정
        if (totalSize2 > 0 && last_percent < 100) {
            PostMessageA(data->hwnd, WM_WORKER_PROGRESS, 100, 0);
        }

        // 시간 / 메모리 측정
        elapsed_ms = GetTickCount64() - start_ms;
        
        // 평균 메모리 계산 (샘플이 있으면 평균, 없으면 현재값)
        if (g_memSampleCount > 0) {
            mem_kb = g_memSum / g_memSampleCount;
        } else {
            mem_kb = GetProcessMemoryUsageKB();
        }

        // 해시 → hex 문자열
        char hashStr[129] = { 0 };
        for (int i = 0; i < 64; i++) {
            sprintf(hashStr + (i * 2), "%02X", hash[i]);
        }

        // "해시|elapsed_ms|mem_kb" 형태로 포맷
        char payload[256] = { 0 };
        snprintf(payload, sizeof(payload),
            "%s|%llu|%zu",
            hashStr,
            (unsigned long long)elapsed_ms,
            (size_t)mem_kb);

        char* payloadCopy = (char*)malloc(strlen(payload) + 1);
        if (payloadCopy) {
            strcpy(payloadCopy, payload);
            if (IsWindow(data->hwnd)) {
                if (!PostMessageA(data->hwnd, WM_WORKER_COMPLETE, (WPARAM)payloadCopy, 0)) {
                    SendMessageA(data->hwnd, WM_WORKER_COMPLETE, (WPARAM)payloadCopy, 0);
                }
            }
            else {
                free(payloadCopy);
            }
        }
        else {
            if (IsWindow(data->hwnd)) {
                if (!PostMessageA(data->hwnd, WM_WORKER_COMPLETE, 0, 0)) {
                    SendMessageA(data->hwnd, WM_WORKER_COMPLETE, 0, 0);
                }
            }
        }

        free(data);
        return 0;
    }

    /* ===============================================================
     * 여기까지 내려왔으면 AES-CTR / AES-CTR+HMAC 경로 정상 종료
     *  → AES 관련 시간 / 메모리 측정 후 완료 메시지 전송
     * =============================================================*/
    elapsed_ms = GetTickCount64() - start_ms;
    
    // 평균 메모리 계산 (샘플이 있으면 평균, 없으면 현재값)
    if (g_memSampleCount > 0) {
        mem_kb = g_memSum / g_memSampleCount;
    } else {
        mem_kb = GetProcessMemoryUsageKB();
    }

    char timeStr[64];
    char memStr[64];
    FormatElapsedTime(elapsed_ms, timeStr, sizeof(timeStr));
    FormatMemorySize(mem_kb, memStr, sizeof(memStr));

    if (useAesCtr && useHmac) {
        snprintf(msg, sizeof(msg),
            "작업 완료!\n\n%s: %s\n\n"
            "파일 구조: IV(16) || 암호문 || HMAC(64)\n\n"
            "소요 시간: %s\n"
            "평균 메모리 사용량: %s",
            data->isEncrypt ? "암호화된 파일" : "복호화된 파일",
            data->outputFile,
            timeStr,
            memStr);
    }
    else if (useAesCtr) {
        snprintf(msg, sizeof(msg),
            "%s 완료!\n\n파일: %s\n\n"
            "소요 시간: %s\n"
            "평균 메모리 사용량: %s",
            data->isEncrypt ? "암호화" : "복호화",
            data->outputFile,
            timeStr,
            memStr);
    }
    else {
        snprintf(msg, sizeof(msg),
            "작업이 완료되었습니다!\n\n"
            "소요 시간: %s\n"
            "평균 메모리 사용량: %s",
            timeStr,
            memStr);
    }

    char* msgCopy = (char*)malloc(strlen(msg) + 1);
    if (msgCopy) {
        strcpy(msgCopy, msg);
        if (IsWindow(data->hwnd)) {
            if (!PostMessageA(data->hwnd, WM_WORKER_COMPLETE, (WPARAM)msgCopy, 0)) {
                SendMessageA(data->hwnd, WM_WORKER_COMPLETE, (WPARAM)msgCopy, 0);
            }
        }
        else {
            free(msgCopy);
        }
    }
    else {
        if (IsWindow(data->hwnd)) {
            if (!PostMessageA(data->hwnd, WM_WORKER_COMPLETE, 0, 0)) {
                SendMessageA(data->hwnd, WM_WORKER_COMPLETE, 0, 0);
            }
        }
    }

    free(data);
    return 0;
}
