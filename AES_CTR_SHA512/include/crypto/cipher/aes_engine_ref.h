#pragma once

#include "crypto/core/blockcipher.h"

#ifdef __cplusplus
extern "C" {
#endif

	// 레퍼런스 AES 엔진(vtable)
	// CTR이나 다른 모드는 이 엔진의 존재를 'vtable'로만 알게 됨
	extern const blockcipher_vtable_t AES_REF_ENGINE;

#ifdef __cplusplus
}
#endif
