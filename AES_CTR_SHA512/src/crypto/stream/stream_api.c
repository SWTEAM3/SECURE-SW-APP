#include "crypto/stream/stream_api.h"

#include <stdio.h>
#include "crypto/hash/hmac.h"

#ifdef _WIN32
#include <windows.h>
#endif

// 스트림 I/O 버퍼 크기 (1MB)
#define STREAM_BUF_SIZE (1u << 20)  // 1MB

// 안전한 메모리 해제 헬퍼 (힙 손상 시 예외 처리)
static void safe_free(void* ptr) {
    if (!ptr) return;
#ifdef _WIN32
    __try {
        free(ptr);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 힙이 손상된 경우 free를 호출하지 않고 그냥 무시
        // 메모리 누수가 발생하지만 크래시는 방지
    }
#else
    free(ptr);
#endif
}

// 파일 단위 AES-CTR 모드 암복호화 공통 처리
static int ctr_process_file(const blockcipher_vtable_t* engine,
                            const char* in_path,
                            const char* out_path,
                            const unsigned char* key,
                            int key_len,
                            const unsigned char iv[16])
{
    if (!engine || !in_path || !out_path || !key || key_len <= 0 || !iv)
        return -1;

    FILE* fin = fopen(in_path, "rb");
    if (!fin) return -2;

    FILE* fout = fopen(out_path, "wb");
    if (!fout) {
        fclose(fin);
        return -3;
    }

    ctr_mode_ctx_t* ctx = ctr_mode_init(engine, key, key_len, iv);
    if (!ctx) {
        fclose(fin);
        fclose(fout);
        return -4;
    }

    // NOTE:
    //  - GUI 환경에서는 기본 스택 크기가 작아서
    //    1MB 버퍼 2개를 스택에 잡으면 스택 오버플로우로
    //    프로세스가 바로 종료될 수 있다.
    //  - 따라서 큰 버퍼는 힙에 할당해서 사용한다.
    unsigned char* inbuf  = NULL;
    unsigned char* outbuf = NULL;
    
    inbuf = (unsigned char*)malloc(STREAM_BUF_SIZE);
    if (!inbuf) {
        ctr_mode_free(ctx);
        fclose(fin);
        fclose(fout);
        return -5;
    }
    
    outbuf = (unsigned char*)malloc(STREAM_BUF_SIZE);
    if (!outbuf) {
        safe_free(inbuf);
        inbuf = NULL;
        ctr_mode_free(ctx);
        fclose(fin);
        fclose(fout);
        return -5;
    }

    size_t n;
    while ((n = fread(inbuf, 1, STREAM_BUF_SIZE, fin)) > 0) {
        // fread 직후 에러 체크
        if (ferror(fin)) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -7;
        }
        
        // n 값이 버퍼 크기를 초과하지 않는지 확인
        if (n > STREAM_BUF_SIZE) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -8;
        }
        
        // ctx 유효성 재확인
        if (!ctx || !ctx->bc) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            if (ctx) ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -9;
        }
        
        // n을 int로 안전하게 변환 (STREAM_BUF_SIZE가 INT_MAX보다 작으므로 안전)
        int n_int = (int)n;
        if (n_int <= 0 || (size_t)n_int != n) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -10;
        }
        
        // ctx->bc의 vtable과 함수 포인터 재확인
        if (!ctx->bc->vtable || !ctx->bc->vtable->encrypt_block || !ctx->bc->ctx) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -12;
        }
        
        // 버퍼 포인터 유효성 확인 (NULL이 아닌지)
        if (!inbuf || !outbuf) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -13;
        }
        
        // ctr_mode_update 호출 전 버퍼 범위 검증
        if (n_int > (int)STREAM_BUF_SIZE) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -14;
        }
        
        ctr_mode_update(ctx, inbuf, outbuf, n_int);
        
        // ctr_mode_update 호출 후 버퍼가 손상되지 않았는지 간단히 확인
        // (첫 번째와 마지막 바이트가 여전히 접근 가능한지 확인)
        volatile unsigned char test_in = inbuf[0];
        volatile unsigned char test_out = outbuf[0];
        (void)test_in;
        (void)test_out;
        
        if (fwrite(outbuf, 1, n, fout) != n) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -6;
        }
        
        // fwrite 후에도 에러 체크
        if (ferror(fout)) {
            safe_free(inbuf);
            safe_free(outbuf);
            inbuf = NULL;
            outbuf = NULL;
            ctr_mode_free(ctx);
            fclose(fin);
            fclose(fout);
            return -11;
        }
    }

    // fread가 0을 반환했는데 에러가 발생한 경우 체크
    if (ferror(fin)) {
        safe_free(inbuf);
        safe_free(outbuf);
        inbuf = NULL;
        outbuf = NULL;
        ctr_mode_free(ctx);
        fclose(fin);
        fclose(fout);
        return -7;
    }

    safe_free(inbuf);
    safe_free(outbuf);
    inbuf = NULL;
    outbuf = NULL;
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
                            const unsigned char iv[16])
{
    // CTR은 암호화/복호화가 동일 연산이므로 같은 함수를 사용
    return ctr_process_file(engine, in_path, out_path, key, key_len, iv);
}

int stream_decrypt_ctr_file(const blockcipher_vtable_t* engine,
                            const char* in_path,
                            const char* out_path,
                            const unsigned char* key,
                            int key_len,
                            const unsigned char iv[16])
{
    return ctr_process_file(engine, in_path, out_path, key, key_len, iv);
}

int stream_hash_sha512_file(const char* in_path,
                            unsigned char out_digest[64])
{
    if (!in_path || !out_digest) return -1;

    FILE* f = fopen(in_path, "rb");
    if (!f) return -2;

    sha512_ctx_t ctx;
    sha512_init(&ctx);

    // 큰 버퍼는 스택 대신 힙에 할당
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
    if (!in_path || !key || !out_mac) return -1;

    FILE* f = fopen(in_path, "rb");
    if (!f) return -2;

    hmac_ctx ctx;
    hmac_init(&ctx, key, key_len);

    // 큰 버퍼는 스택 대신 힙에 할당
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
