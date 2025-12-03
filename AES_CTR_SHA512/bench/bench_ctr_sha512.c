#include <stdio.h>
#include <stdint.h>

#include "crypto/stream/stream_api.h"
#include "crypto/key/key_context.h"
#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_engine_ttable.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#else
#include <time.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

static double now_seconds(void)
{
#ifdef _WIN32
    static LARGE_INTEGER freq;
    static int inited = 0;
    if (!inited) {
        QueryPerformanceFrequency(&freq);
        inited = 1;
    }
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
#endif
}

static size_t peak_memory_bytes(void)
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return (size_t)pmc.PeakWorkingSetSize;
    }
    return 0;
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return (size_t)ru.ru_maxrss * 1024;
    }
    return 0;
#endif
}

static uint64_t file_size_bytes(const char* path)
{
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
#ifdef _WIN32
    _fseeki64(f, 0, SEEK_END);
    uint64_t sz = (uint64_t)_ftelli64(f);
#else
    fseeko(f, 0, SEEK_END);
    uint64_t sz = (uint64_t)ftello(f);
#endif
    fclose(f);
    return sz;
}

static void bench_ctr_file(const blockcipher_vtable_t* engine,
    const char* engine_name,
    const char* in_path,
    const char* out_path,
    int key_bits)
{
    key_context_t kc;
    key_context_init_random(&kc);
    int key_len = key_bits / 8;
    key_context_derive(&kc, (unsigned int)key_len);

    unsigned char iv[16] = { 0 };

    uint64_t sz = file_size_bytes(in_path);
    printf("\n[CTR BENCH] engine=%s key=%d-bit file=%s (%.3f MB)\n",
        engine_name, key_bits, in_path, (double)sz / (1024.0 * 1024.0));

    double t0 = now_seconds();
    int rc = stream_encrypt_ctr_file(engine, in_path, out_path,
        kc.enc_key, key_len, iv);
    double t1 = now_seconds();

    if (rc != 0) {
        printf("  -> encrypt failed (rc=%d)\n", rc);
        key_context_clear(&kc);
        return;
    }

    double sec = t1 - t0;
    double mbps = (sec > 0.0) ? ((double)sz / (1024.0 * 1024.0)) / sec : 0.0;

    printf("  time: %.6f sec\n", sec);
    printf("  throughput: %.2f MB/s\n", mbps);
    printf("  peak memory: %.2f MB\n", peak_memory_bytes() / (1024.0 * 1024.0));

    key_context_clear(&kc);
}

static void bench_sha512_file(const char* in_path)
{
    unsigned char digest[64];
    uint64_t sz = file_size_bytes(in_path);

    printf("\n[SHA-512 BENCH] file=%s (%.3f MB)\n",
        in_path, (double)sz / (1024.0 * 1024.0));

    double t0 = now_seconds();
    int rc = stream_hash_sha512_file(in_path, digest);
    double t1 = now_seconds();

    if (rc != 0) {
        printf("  -> hash failed (rc=%d)\n", rc);
        return;
    }

    double sec = t1 - t0;
    double mbps = (sec > 0.0) ? ((double)sz / (1024.0 * 1024.0)) / sec : 0.0;

    printf("  time: %.6f sec\n", sec);
    printf("  throughput: %.2f MB/s\n", mbps);
    printf("  peak memory: %.2f MB\n", peak_memory_bytes() / (1024.0 * 1024.0));

    printf("  digest (first 8 bytes): ");
    for (int i = 0; i < 8; i++) printf("%02X", digest[i]);
    printf("...\n");
}

int bench_ctr_sha512_main(int argc, char** argv)
{
    if (argc < 3) {
        printf("Usage: bench_ctr_sha512 <input_file> <tmp_out_file>\n");
        return 1;
    }

    const char* in_path = argv[1];
    const char* out_path = argv[2];

    bench_ctr_file(&AES_REF_ENGINE, "ref", in_path, out_path, 128);
    bench_ctr_file(&AES_REF_ENGINE, "ref", in_path, out_path, 192);
    bench_ctr_file(&AES_REF_ENGINE, "ref", in_path, out_path, 256);

    bench_ctr_file(&AES_TTABLE_ENGINE, "ttable", in_path, out_path, 128);
    bench_ctr_file(&AES_TTABLE_ENGINE, "ttable", in_path, out_path, 192);
    bench_ctr_file(&AES_TTABLE_ENGINE, "ttable", in_path, out_path, 256);

    bench_sha512_file(in_path);

    printf("\n=== BENCH DONE ===\n");
    return 0;
}
