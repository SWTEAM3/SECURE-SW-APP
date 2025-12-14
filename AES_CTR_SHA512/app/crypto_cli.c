#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "crypto/stream/stream_api.h"
#include "crypto/key/key_context.h"
#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_engine_ttable.h"
#include "crypto/mode/mode_ctr.h"
#include "crypto/hash/hash_sha512.h"


// 깃허브 공개 링크 "https://github.com/SWTEAM3/SECURE-SW-APP.git"

// ===================== 공통 유틸 =====================

static void trim_newline(char* s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

static void dump_hex(const unsigned char* buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) printf(" ");
    }
    printf("\n");
}

static int hexval(char c)
{
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char* hex, unsigned char* out, size_t out_len)
{
    size_t n = strlen(hex);
    if (n != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(hex[2 * i]);
        int lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static size_t read_prefix(const char* path, unsigned char* buf, size_t buf_size)
{
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, buf_size, f);
    fclose(f);
    return n;
}

static int ask_int(const char* prompt)
{
    char buf[128];
    printf("%s", prompt);
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    trim_newline(buf);
    return atoi(buf);
}

static void ask_line(const char* prompt, char* dst, size_t dst_size)
{
    printf("%s", prompt);
    if (!fgets(dst, (int)dst_size, stdin)) {
        dst[0] = '\0';
        return;
    }
    trim_newline(dst);
}

// ===================== CLI 설정 구조체 =====================

typedef struct cli_cfg_t {
    int  mode_type;   // 1=파일 모드, 2=NIST 정답, 3=NIST 일부러 틀린 기대값
    int  file_enc;    // 파일 모드에서 1=enc, 0=dec

    const blockcipher_vtable_t* engine; // ref / ttable
    int  key_bits;     // 128 / 192 / 256

    int  key_random;   // 파일 모드에서 1=random, 0=seed
    char key_seed[256];

    char in_path[512];
    char out_path[512];
} cli_cfg_t;

// ===================== NIST CTR 테스트 벡터 구조체 =====================
// SP 800-38A CTR-AES128/192/256.Encrypt 벡터  [oai_citation:1‡NIST Publications](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf?utm_source=chatgpt.com)

typedef struct nist_ctr_vec_t {
    int         key_bits;
    const char* key_hex;
    const char* iv_hex;
    const char* pt_hex;
    const char* ct_hex;
} nist_ctr_vec_t;

static const nist_ctr_vec_t NIST_CTR_VECS[] = {
    // 128-bit
    {
        128,
        "2b7e151628aed2a6abf7158809cf4f3c",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    },
    // 192-bit
    {
        192,
        "8e73b0f7da0e6452c810f32b809079e5"
        "62f8ead2522c6b7b",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "1abc932417521ca24f2b0459fe7e6e0b"
        "090339ec0aa6faefd5ccc2c6f4ce8e94"
        "1e36b26bd1ebc670d1bd1d665620abf7"
        "4f78a7f6d29809585a97daec58c6b050"
    },
    // 256-bit
    {
        256,
        "603deb1015ca71be2b73aef0857d7781"
        "1f352c073b6108d72d9810a30914dff4",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "601ec313775789a5b7a7f504bbf3d228"
        "f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988d"
        "dfc9c58db67aada613c2dd08457941a6"
    }
};

static const nist_ctr_vec_t* find_nist_vec(int key_bits)
{
    for (size_t i = 0; i < sizeof(NIST_CTR_VECS) / sizeof(NIST_CTR_VECS[0]); i++) {
        if (NIST_CTR_VECS[i].key_bits == key_bits) {
            return &NIST_CTR_VECS[i];
        }
    }
    return NULL;
}

// ===================== 대화형 설정 =====================

static int interactive_config(cli_cfg_t* cfg)
{
    memset(cfg, 0, sizeof(*cfg));

    printf("=== AES-CTR + SHA-512 테스트 CLI ===\n");
    printf("1) 파일 입력 모드 (암호화/복호화 + 평문/암호문/인증값)\n");
    printf("2) NIST CTR 테스트 벡터 (정상)\n");
    printf("3) NIST CTR 테스트 벡터 (일부러 틀린 기대값)\n");

    int m = ask_int("모드 선택 (1/2/3): ");
    if (m < 1 || m > 3) {
        printf("잘못된 선택.\n");
        return 0;
    }
    cfg->mode_type = m;

    // 키 길이
    int bits = ask_int("키 길이 선택 (128/192/256): ");
    if (bits != 128 && bits != 192 && bits != 256) {
        printf("지원하지 않는 키 길이.\n");
        return 0;
    }
    cfg->key_bits = bits;

    // AES 엔진 선택
    printf("\nAES 엔진 선택:\n");
    printf("  1) ref (레퍼런스 엔진)\n");
    printf("  2) ttable (T-Table 엔진)\n");
    int e = ask_int("엔진 선택 (1/2): ");
    if (e == 1) cfg->engine = &AES_REF_ENGINE;
    else if (e == 2) cfg->engine = &AES_TTABLE_ENGINE;
    else {
        printf("잘못된 선택.\n");
        return 0;
    }

    if (cfg->mode_type == 1) {
        // 파일 모드 상세
        printf("\n파일 모드: 1) 암호화  2) 복호화\n");
        int fe = ask_int("선택 (1/2): ");
        if (fe == 1) cfg->file_enc = 1;
        else if (fe == 2) cfg->file_enc = 0;
        else {
            printf("잘못된 선택.\n");
            return 0;
        }

        ask_line("입력 파일 경로: ", cfg->in_path, sizeof(cfg->in_path));
        ask_line("출력 파일 경로: ", cfg->out_path, sizeof(cfg->out_path));

        printf("\n키 생성 방식:\n");
        printf("  1) 랜덤 키\n");
        printf("  2) seed 기반 결정적 키\n");
        int k = ask_int("선택 (1/2): ");
        if (k == 1) {
            cfg->key_random = 1;
        }
        else if (k == 2) {
            cfg->key_random = 0;
            ask_line("seed 문자열 입력: ", cfg->key_seed, sizeof(cfg->key_seed));
            if (cfg->key_seed[0] == '\0') {
                printf("seed가 비었음.\n");
                return 0;
            }
        }
        else {
            printf("잘못된 선택.\n");
            return 0;
        }
    }

    return 1;
}

// ===================== 파일 모드: 평문/암호문/인증값 =====================

static void print_file_pt_ct_auth(const cli_cfg_t* cfg)
{
    unsigned char buf_pt[64];
    unsigned char buf_ct[64];
    unsigned char digest[64];

    if (cfg->file_enc) {
        size_t n_pt = read_prefix(cfg->in_path, buf_pt, sizeof(buf_pt));
        size_t n_ct = read_prefix(cfg->out_path, buf_ct, sizeof(buf_ct));

        printf("\n[평문 앞부분] (%zu bytes from %s)\n", n_pt, cfg->in_path);
        dump_hex(buf_pt, n_pt);

        printf("\n[암호문 앞부분] (%zu bytes from %s)\n", n_ct, cfg->out_path);
        dump_hex(buf_ct, n_ct);

        if (stream_hash_sha512_file(cfg->out_path, digest) == 0) {
            printf("\n[암호문 파일 SHA-512 (인증값)]\n");
            dump_hex(digest, sizeof(digest));
        }
        else {
            printf("\n[인증값] 암호문 파일을 열 수 없음.\n");
        }
    }
    else {
        size_t n_ct = read_prefix(cfg->in_path, buf_ct, sizeof(buf_ct));
        size_t n_pt = read_prefix(cfg->out_path, buf_pt, sizeof(buf_pt));

        printf("\n[암호문 앞부분] (%zu bytes from %s)\n", n_ct, cfg->in_path);
        dump_hex(buf_ct, n_ct);

        printf("\n[복호 평문 앞부분] (%zu bytes from %s)\n", n_pt, cfg->out_path);
        dump_hex(buf_pt, n_pt);

        if (stream_hash_sha512_file(cfg->in_path, digest) == 0) {
            printf("\n[암호문 파일 SHA-512 (인증값)]\n");
            dump_hex(digest, sizeof(digest));
        }
        else {
            printf("\n[인증값] 암호문 파일을 열 수 없음.\n");
        }
    }
}

static int run_file_mode(const cli_cfg_t* cfg)
{
    key_context_t kc;
    unsigned char iv[16] = { 0 };
    int key_len = cfg->key_bits / 8;

    if (cfg->key_random) {
        key_context_init_random(&kc);
    }
    else {
        key_context_init_seed(&kc,
            (const unsigned char*)cfg->key_seed,
            (unsigned int)strlen(cfg->key_seed));
    }
    key_context_derive(&kc, (unsigned int)key_len);

    int rc;
    if (cfg->file_enc) {
        rc = stream_encrypt_ctr_file(cfg->engine,
            cfg->in_path,
            cfg->out_path,
            kc.enc_key,
            key_len,
            iv);
        if (rc != 0) {
            printf("[ERR] 암호화 실패 (rc=%d)\n", rc);
            key_context_clear(&kc);
            return 1;
        }
        printf("\n[OK] 암호화 완료: %s -> %s (AES-%d-CTR, engine=%s)\n",
            cfg->in_path, cfg->out_path, cfg->key_bits,
            (cfg->engine == &AES_REF_ENGINE) ? "ref" : "ttable");
    }
    else {
        rc = stream_decrypt_ctr_file(cfg->engine,
            cfg->in_path,
            cfg->out_path,
            kc.enc_key,
            key_len,
            iv);
        if (rc != 0) {
            printf("[ERR] 복호화 실패 (rc=%d)\n", rc);
            key_context_clear(&kc);
            return 1;
        }
        printf("\n[OK] 복호화 완료: %s -> %s (AES-%d-CTR, engine=%s)\n",
            cfg->in_path, cfg->out_path, cfg->key_bits,
            (cfg->engine == &AES_REF_ENGINE) ? "ref" : "ttable");
    }

    print_file_pt_ct_auth(cfg);
    key_context_clear(&kc);
    return 0;
}

// ===================== NIST CTR 테스트 =====================

static void compare_and_report_ct(const unsigned char* actual,
    const unsigned char* expect,
    size_t len,
    int wrong_expected)
{
    size_t first_diff = (size_t)-1;
    for (size_t i = 0; i < len; i++) {
        if (actual[i] != expect[i]) {
            first_diff = i;
            break;
        }
    }

    if (first_diff == (size_t)-1) {
        printf("\n[TESTVEC] OK: 기대 암호문과 실제 암호문이 완전히 일치합니다. (비교 %zu bytes)\n", len);
        if (wrong_expected) {
            printf("  (하지만 이 모드는 기대값을 일부러 깨뜨려야 하는 모드라,\n");
            printf("   구현이 맞다면 여기서 OK가 나오면 안 됨 → 기대값 수정 확인 필요)\n");
        }
    }
    else {
        size_t block = first_diff / 16;
        size_t offset = first_diff % 16;
        printf("\n[TESTVEC] FAIL: 암호문 불일치\n");
        printf("  첫 차이 위치: index=%zu (블록 index=%zu, 블록 내 offset=%zu)\n",
            first_diff, block, offset);
        printf("  expected=%02X, actual=%02X\n",
            expect[first_diff], actual[first_diff]);

        printf("\n  [expected 첫 블록]\n");
        dump_hex(expect, len < 16 ? len : 16);
        printf("\n  [actual   첫 블록]\n");
        dump_hex(actual, len < 16 ? len : 16);
    }
}

static int run_nist_ctr(const cli_cfg_t* cfg, int wrong_expected)
{
    const nist_ctr_vec_t* v = find_nist_vec(cfg->key_bits);
    if (!v) {
        printf("\n[ERR] 이 키 길이에 대한 NIST CTR 벡터가 정의되어 있지 않음.\n");
        return 1;
    }

    int key_len_bytes = cfg->key_bits / 8;
    unsigned char key[32], iv[16];
    unsigned char pt[16 * 4];
    unsigned char ct_expect[16 * 4];
    unsigned char ct_calc[16 * 4];

    if (!hex_to_bytes(v->key_hex, key, key_len_bytes) ||
        !hex_to_bytes(v->iv_hex, iv, sizeof(iv)) ||
        !hex_to_bytes(v->pt_hex, pt, sizeof(pt)) ||
        !hex_to_bytes(v->ct_hex, ct_expect, sizeof(ct_expect))) {
        printf("[ERR] NIST 벡터 헥스 파싱 실패 (key_bits=%d)\n", v->key_bits);
        return 1;
    }

    // 일부러 틀린 테스트 벡터 모드면 기대값을 인위적으로 깨뜨리기
    if (wrong_expected) {
        ct_expect[0] ^= 0x01;
    }

    // CTR 암호문 계산
    ctr_mode_ctx_t* ctx = ctr_mode_init(cfg->engine, key, key_len_bytes, iv);
    if (!ctx) {
        printf("[ERR] CTR 컨텍스트 초기화 실패\n");
        return 1;
    }
    ctr_mode_update(ctx, pt, ct_calc, (int)sizeof(pt));
    ctr_mode_free(ctx);

    printf("\n=== NIST CTR-AES-%d 테스트 (engine=%s, wrong_expected=%s) ===\n",
        cfg->key_bits,
        (cfg->engine == &AES_REF_ENGINE) ? "ref" : "ttable",
        wrong_expected ? "YES" : "NO");

    printf("\n[키]\n");
    dump_hex(key, key_len_bytes);

    printf("\n[IV (counter block)]\n");
    dump_hex(iv, sizeof(iv));

    printf("\n[평문 전체]\n");
    dump_hex(pt, sizeof(pt));

    printf("\n[실제 암호문 전체]\n");
    dump_hex(ct_calc, sizeof(ct_calc));

    // SHA-512 인증값 (실제 암호문에 대해)
    unsigned char digest[64];
    sha512_ctx_t hctx;
    sha512_init(&hctx);
    sha512_update(&hctx, ct_calc, sizeof(ct_calc));
    sha512_final(&hctx, digest);
    printf("\n[실제 암호문 SHA-512 (인증값)]\n");
    dump_hex(digest, sizeof(digest));

    // 기대값과 비교
    compare_and_report_ct(ct_calc, ct_expect, sizeof(ct_calc), wrong_expected);

    if (wrong_expected) {
        printf("\n(참고: 이 모드는 기대 암호문을 일부러 틀리게 만든것으로,\n");
        printf("       어디서 불일치가 나는지 디버깅에 쓰라고 만든 모드입니다.)\n");
    }

    return 0;
}

// ===================== main =====================

/*int main(void)
{
    cli_cfg_t cfg;
    if (!interactive_config(&cfg)) {
        printf("설정 실패.\n");
        return 1;
    }

    if (cfg.mode_type == 1) {
        // 파일 모드
        return run_file_mode(&cfg);
    }
    else if (cfg.mode_type == 2) {
        // NIST CTR: 올바른 기대값
        return run_nist_ctr(&cfg, 0);
    }
    else {
        // NIST CTR: 일부러 틀린 기대값
        return run_nist_ctr(&cfg, 1);
    }
}*/
