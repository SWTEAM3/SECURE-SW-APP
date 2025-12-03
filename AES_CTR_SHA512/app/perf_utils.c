#include <windows.h>
#include <Psapi.h>
#include <stdio.h>

#include "perf_utils.h"

// 현재 프로세스의 메모리 사용량(KB 단위, Working Set 기준) 조회
SIZE_T GetProcessMemoryUsageKB(void) {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / 1024;  // 바이트 → KB
    }
    return 0;
}

// ms → "X.X초" 또는 "Y분 Z초" 문자열로 변환
void FormatElapsedTime(ULONGLONG ms, char* out, size_t outSize) {
    if (!out || outSize == 0) return;

    double sec = (double)ms / 1000.0;

    if (sec < 60.0) {
        // 1분 미만 → 소수점 1자리까지
        snprintf(out, outSize, "%.1f초", sec);
    }
    else {
        // 1분 이상 → 정수 분 + 정수 초
        unsigned long long total_sec = (unsigned long long)sec;
        unsigned long long minutes = total_sec / 60ULL;
        unsigned long long seconds = total_sec % 60ULL;
        snprintf(out, outSize, "%llu분 %llu초", minutes, seconds);
    }
}

// 메모리 포맷 함수
void FormatMemorySize(SIZE_T kb, char* out, size_t outSize) {
    double m = (double)kb;
    if (m < 1024.0) snprintf(out, outSize, "%.0f KB", m);
    else if (m < 1024.0 * 1024.0) snprintf(out, outSize, "%.1f MB", m / 1024.0);
    else snprintf(out, outSize, "%.2f GB", m / 1024.0 / 1024.0);
}


