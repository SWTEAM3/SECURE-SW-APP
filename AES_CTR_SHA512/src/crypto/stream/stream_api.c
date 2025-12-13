#include "crypto/stream/stream_api.h"

#include <stdio.h>
#include <stdlib.h>
#include "crypto/hash/hmac.h"

#ifndef CTR_BLOCK_BYTES
#define CTR_BLOCK_BYTES 16
#endif

#ifdef _WIN32
#include <windows.h>
#endif

// 스트림 I/O용 버퍼 크기 (1MB). 큰 파일도 일정 크기씩 잘라 처리한다.
#define STREAM_BUF_SIZE (1u << 20)

// 안전한 free 헬퍼 (Windows에서 힙이 손상된 경우 크래시 방지)
static void safe_free(void* ptr) {
    if (!ptr) return;
#ifdef _WIN32
    __try {
        free(ptr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 힙이 깨진 경우 free를 건너뛰어 크래시를 막는다.
    }
#else
    free(ptr);
#endif
}

// 파일 단위 AES-CTR 암호화/복호화 공통 처리
static int ctr_process_file(const blockcipher_vtable_t* engine,
                            const char* in_path,
                            const char* out_path,
                            const unsigned char* key,
                            int key_len,
                            const unsigned char iv[CTR_BLOCK_BYTES])
{
    // 입력/출력 경로, 키, IV 유효성 확인
    if (!engine || !in_path || !out_path || !key || key_len <= 0 || !iv)
        return -1;

    // 입력/출력 파일 열기
    FILE* fin = fopen(in_path, "rb");
    if (!fin) return -2;

    FILE* fout = fopen(out_path, "wb");
    if (!fout) {
        fclose(fin);
        return -3;
    }

    // CTR 컨텍스트 준비 (블록암호 핸들 + 카운터)
    ctr_mode_ctx_t* ctx = ctr_mode_init(engine, key, key_len, iv);
    if (!ctx) {
        fclose(fin);
        fclose(fout);
        return -4;
    }

    // 스택이 작은 환경(GUI)에서 스택 오버플로우를 피하기 위해 힙 버퍼를 사용
    unsigned char* inbuf = (unsigned char*)malloc(STREAM_BUF_SIZE);
    if (!inbuf) {
        ctr_mode_free(ctx);
        fclose(fin);
        fclose(fout);
        return -5;
    }

    unsigned char* outbuf = (unsigned char*)malloc(STREAM_BUF_SIZE);
    if (!outbuf) {
        safe_free(inbuf);
        ctr_mode_free(ctx);
        fclose(fin);
        fclose(fout);
        return -5;
    }

    size_t n;
    while ((n = fread(inbuf, 1, STREAM_BUF_SIZE, fin)) > 0) {
        // 1) 입력 버퍼 읽기 성공 여부 확인
        if (ferror(fin)) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -7;
        }

        // 2) 읽은 길이 범위 확인
        if (n > STREAM_BUF_SIZE) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -8;
        }

        // 3) CTR 컨텍스트와 vtable 유효성 재확인
        if (!ctx || !ctx->bc || !ctx->bc->vtable || !ctx->bc->vtable->encrypt_block || !ctx->bc->ctx) {
            safe_free(inbuf);
            safe_free(outbuf);
            if (ctx) ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -9;
        }

        // 4) size_t → int 변환 안전성 체크
        int n_int = (int)n;
        if (n_int <= 0 || (size_t)n_int != n) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -10;
        }

        // 5) 버퍼 포인터 NULL 여부 확인
        if (!inbuf || !outbuf) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -13;
        }

        // 6) 처리 길이 범위 확인
        if (n_int > (int)STREAM_BUF_SIZE) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -14;
        }

        // 7) CTR 암/복호화 수행
        ctr_mode_update(ctx, inbuf, outbuf, n_int);

        // 8) 출력 파일에 기록
        if (fwrite(outbuf, 1, n, fout) != n) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -6;
        }

        // 9) fwrite 오류 확인
        if (ferror(fout)) {
            safe_free(inbuf);
            safe_free(outbuf);
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -11;
        }
    }

    // 루프 종료 후 fread 에러 확인
    if (ferror(fin)) {
        safe_free(inbuf);
        safe_free(outbuf);
        ctr_mode_free(ctx);
        fclose(fin);
        fclose(fout);
        return -7;
    }

    // 자원 정리
    safe_free(inbuf);
    safe_free(outbuf);
    ctr_mode_free(ctx);
    fclose(fin);
    fclose(fout);
    return 0;
}

int stream_encrypt_ctr_file(const blockcipher_vtable_t* engine,
                            const char* in_path,
                            const char* out_path,
                            const unsigned char* key,
                            int key_len,
                            const unsigned char iv[CTR_BLOCK_BYTES])
{
    // CTR은 암호화/복호화 연산이 동일하므로 같은 함수 재사용
    return ctr_process_file(engine, in_path, out_path, key, key_len, iv);
}

int stream_decrypt_ctr_file(const blockcipher_vtable_t* engine,
                            const char* in_path,
                            const char* out_path,
                            const unsigned char* key,
                            int key_len,
                            const unsigned char iv[CTR_BLOCK_BYTES])
{
    // CTR은 암호화/복호화 연산이 동일하므로 같은 함수 재사용
    return ctr_process_file(engine, in_path, out_path, key, key_len, iv);
}

int stream_hash_sha512_file(const char* in_path,
                            unsigned char out_digest[64])
{
    // 파일을 스트리밍으로 읽어 SHA-512를 계산한다.
    if (!in_path || !out_digest) return -1;

    FILE* f = fopen(in_path, "rb");
    if (!f) return -2;

    sha512_ctx_t ctx;
    sha512_init(&ctx);

    // 큰 버퍼는 힙에 할당해 스택 사용을 줄인다.
    unsigned char* buf = (unsigned char*)malloc(STREAM_BUF_SIZE);
    if (!buf) {
        fclose(f);
        return -3;
    }

    size_t n;
    while ((n = fread(buf, 1, STREAM_BUF_SIZE, f)) > 0) {
        sha512_update(&ctx, buf, n);
    }

    if (ferror(f)) {
        free(buf);
        fclose(f);
        return -4;
    }

    free(buf);
    fclose(f);
    sha512_final(&ctx, out_digest);
    return 0;
}

int stream_hmac_sha512_file(const char* in_path,
                            const unsigned char* key,
                            size_t key_len,
                            unsigned char out_mac[64])
{
    // 파일을 스트리밍으로 읽으며 HMAC-SHA512를 계산한다.
    if (!in_path || !key || !out_mac) return -1;

    FILE* f = fopen(in_path, "rb");
    if (!f) return -2;

    hmac_ctx ctx;
    hmac_init(&ctx, key, key_len);

    // 큰 버퍼는 힙에 할당해 스택 사용을 줄인다.
    unsigned char* buf = (unsigned char*)malloc(STREAM_BUF_SIZE);
    if (!buf) {
        fclose(f);
        return -3;
    }

    size_t n;
    while ((n = fread(buf, 1, STREAM_BUF_SIZE, f)) > 0) {
        hmac_update(&ctx, buf, n);
    }

    if (ferror(f)) {
        free(buf);
        fclose(f);
        return -4;
    }

    free(buf);
    fclose(f);
    hmac_final(&ctx, out_mac);
    return 0;
}
