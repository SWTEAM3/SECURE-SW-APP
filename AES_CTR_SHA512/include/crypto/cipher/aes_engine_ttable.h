#pragma once
#include "crypto/core/blockcipher.h"

#ifdef __cplusplus
extern "C" {
#endif

	// T-table AES 엔진(vtable)
	// 레퍼런스 엔진과 완전히 동일한 인터페이스를 제공해야 교체 가능
	extern const blockcipher_vtable_t AES_TTABLE_ENGINE;

#ifdef __cplusplus
}
#endif