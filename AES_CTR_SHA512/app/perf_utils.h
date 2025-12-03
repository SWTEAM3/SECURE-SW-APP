#pragma once

#include <windows.h>
#include <Psapi.h>

// 현재 프로세스의 메모리 사용량(KB 단위, Working Set 기준) 조회
SIZE_T GetProcessMemoryUsageKB(void);

// ms → "X.X초" 또는 "Y분 Z초" 문자열로 변환
void FormatElapsedTime(ULONGLONG ms, char* out, size_t outSize);

// 메모리 크기를 사람이 읽기 좋은 문자열로 변환
void FormatMemorySize(SIZE_T kb, char* out, size_t outSize);

