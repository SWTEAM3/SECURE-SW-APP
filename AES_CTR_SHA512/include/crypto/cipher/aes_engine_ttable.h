#pragma once
#include "crypto/core/blockcipher.h"

#ifndef AES_BLOCK_BYTES
#define AES_BLOCK_BYTES     16
#endif
#ifndef AES_WORD_BYTES
#define AES_WORD_BYTES      4
#endif
#ifndef AES_BLOCK_WORDS
#define AES_BLOCK_WORDS     (AES_BLOCK_BYTES / AES_WORD_BYTES)
#endif
#ifndef AES128_KEY_BYTES
#define AES128_KEY_BYTES    16
#endif
#ifndef AES192_KEY_BYTES
#define AES192_KEY_BYTES    24
#endif
#ifndef AES256_KEY_BYTES
#define AES256_KEY_BYTES    32
#endif
#ifndef AES_MAX_NK
#define AES_MAX_NK          8
#endif
#ifndef AES_MAX_NR
#define AES_MAX_NR          14
#endif
#ifndef AES_MAX_EXP_WORDS
#define AES_MAX_EXP_WORDS   (AES_BLOCK_WORDS * (AES_MAX_NR + 1))
#endif
#ifndef AES_RCON_LEN
#define AES_RCON_LEN        10
#endif

#ifdef __cplusplus
extern "C" {
#endif

	// T-table AES 엔진(vtable)
	// 레퍼런스 엔진과 완전히 동일한 인터페이스를 제공해야 교체 가능
	extern const blockcipher_vtable_t AES_TTABLE_ENGINE;

#ifdef __cplusplus
}
#endif
