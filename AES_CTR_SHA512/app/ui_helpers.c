#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>   // PROGRESS_CLASSA, PBS_SMOOTH, PBM_SETRANGE, PBM_SETPOS
#include "ui_helpers.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

// 컨트롤 생성 헬퍼
HWND CreateControl(HINSTANCE hInst, HWND hParent, const char* className, 
                   const char* text, DWORD style, int x, int y, int w, int h, HMENU id) {
    return CreateWindowA(className, text, style, x, y, w, h, hParent, id, hInst, NULL);
}

// 컨트롤 표시/숨김 및 이동 헬퍼
void ShowAndMoveControl(HWND hCtrl, HWND hParent, int show, int originalY, int offsetY) {
    if (!hCtrl) return;
    
    ShowWindow(hCtrl, show ? SW_SHOW : SW_HIDE);
    EnableWindow(hCtrl, show);
    
    if (show && originalY >= 0) {
        MoveControlToOriginalY(hCtrl, hParent, originalY, offsetY);
    }
}

// 컨트롤을 원래 위치 기준으로 이동
void MoveControlToOriginalY(HWND hCtrl, HWND hParent, int originalY, int offsetY) {
    if (!hCtrl) return;
    
    RECT rc;
    GetWindowRect(hCtrl, &rc);
    POINT pt = { rc.left, 0 };
    ScreenToClient(hParent, &pt);
    SetWindowPos(hCtrl, NULL, pt.x, originalY + offsetY, 0, 0,
        SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

// 클립보드 복사 헬퍼
void CopyToClipboard(HWND hwnd, HWND hEdit) {
    if (!hEdit) return;
    
    int len = GetWindowTextLengthA(hEdit);
    if (len <= 0) return;
    
    char* text = (char*)malloc(len + 1);
    if (!text) return;
    
    GetWindowTextA(hEdit, text, len + 1);
    
    if (OpenClipboard(hwnd)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len + 1);
        if (hMem) {
            char* pMem = (char*)GlobalLock(hMem);
            if (pMem) {
                strcpy(pMem, text);
                GlobalUnlock(hMem);
                SetClipboardData(CF_TEXT, hMem);
            }
        }
        CloseClipboard();
    }
    
    free(text);
}

// 진행률 다이얼로그 프로시저
static INT_PTR CALLBACK ProgressDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_INITDIALOG:
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            // 취소 버튼은 비활성화 (작업 중에는 취소 불가)
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// 진행률 다이얼로그 생성
HWND CreateProgressDialog(HWND hParent)
{
    // 외부 전역 사용
    extern HFONT g_hFont;
    extern HWND g_hProgressBar;
    extern HWND g_hProgressText;

    // 다이얼로그 템플릿을 동적으로 생성
    HWND hDlg = CreateWindowExA(
        WS_EX_DLGMODALFRAME,
        "#32770",  // Dialog class
        "작업 진행 중...",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 150,
        hParent, NULL, GetModuleHandle(NULL), NULL);

    if (!hDlg) return NULL;

    // 프로그레스 바 생성
    g_hProgressBar = CreateWindowExA(0, PROGRESS_CLASSA, NULL,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        20, 40, 360, 25,
        hDlg, NULL, GetModuleHandle(NULL), NULL);

    // 진행률 텍스트
    g_hProgressText = CreateWindowA("STATIC", "0%",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        20, 75, 360, 20,
        hDlg, NULL, GetModuleHandle(NULL), NULL);

    // 폰트 설정
    if (g_hFont) {
        SendMessage(g_hProgressBar, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessage(g_hProgressText, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    }

    // 프로그레스 바 범위 설정 (0-100)
    SendMessage(g_hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);

    // 다이얼로그 중앙에 배치
    RECT rcParent, rcDlg;
    GetWindowRect(hParent, &rcParent);
    GetWindowRect(hDlg, &rcDlg);
    int x = (rcParent.left + rcParent.right - (rcDlg.right - rcDlg.left)) / 2;
    int y = (rcParent.top + rcParent.bottom - (rcDlg.bottom - rcDlg.top)) / 2;
    SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    return hDlg;
}

// 진행률 업데이트
void UpdateProgress(int percent)
{
    extern HWND g_hProgressBar;
    extern HWND g_hProgressText;

    if (g_hProgressBar) {
        SendMessage(g_hProgressBar, PBM_SETPOS, percent, 0);
    }
    if (g_hProgressText) {
        char text[32];
        snprintf(text, sizeof(text), "%d%%", percent);
        SetWindowTextA(g_hProgressText, text);
    }
}

// STATIC에 현재 경로 표시
void UpdatePathLabels(void)
{
    extern HWND g_hInPathStatic;
    extern HWND g_hOutPathStatic;
    extern char g_selectedFile[MAX_PATH];
    extern char g_outputFile[MAX_PATH];

    if (g_hInPathStatic) {
        SetWindowTextA(g_hInPathStatic,
            (g_selectedFile[0] != '\0') ? g_selectedFile : "(입력 파일 없음)");
    }
    if (g_hOutPathStatic) {
        SetWindowTextA(g_hOutPathStatic,
            (g_outputFile[0] != '\0') ? g_outputFile : "(출력 파일 없음 - 자동 생성)");
    }
}

// 입력 파일 기반으로 기본 출력 파일 경로 생성
void EnsureDefaultOutputFromInput(void)
{
    extern char g_selectedFile[MAX_PATH];
    extern char g_outputFile[MAX_PATH];
    extern int  g_isEncrypt; // 1: 암호화, 0: 복호화

    if (g_outputFile[0] != '\0' || g_selectedFile[0] == '\0')
        return;

    // 모드에 따라 확장자 결정: 암호화 → .encrypted, 복호화 → .decrypted
    const char* suffix = g_isEncrypt ? ".encrypted" : ".decrypted";

    // 기본은 "입력파일명.<suffix>"
    strncpy(g_outputFile, g_selectedFile, MAX_PATH - 1);
    g_outputFile[MAX_PATH - 1] = '\0';

    char* ext = strrchr(g_outputFile, '.');
    if (ext) {
        *ext = '\0';
    }
    // 버퍼 오버플로우 방지
    size_t len = strlen(g_outputFile);
    size_t suf_len = strlen(suffix);
    if (len + suf_len < MAX_PATH) {
        strcat(g_outputFile, suffix);
    }
}

// 파일 크기 확인 함수 (64비트, 실패 시 0)
long long GetFileSizeBytes(const char* filepath)
{
    FILE* f = fopen(filepath, "rb");
    if (!f) return 0;

    _fseeki64(f, 0, SEEK_END);
    long long size = _ftelli64(f);
    fclose(f);
    return size;
}

// 랜덤 바이트 생성 (Windows rand_s 사용, 없으면 rand)
void GenerateRandomBytes(unsigned char* buf, size_t len)
{
    if (!buf || len == 0) return;

#ifdef _WIN32
    // rand_s는 보다 안전한 난수 생성기
    unsigned int v = 0;
    for (size_t i = 0; i < len; i++) {
        if (i % sizeof(unsigned int) == 0) {
            if (rand_s(&v) != 0) {
                v = (unsigned int)rand();
            }
        }
        buf[i] = (unsigned char)((v >> ((i % sizeof(unsigned int)) * 8)) & 0xFF);
    }
#else
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len; i++) {
        buf[i] = (unsigned char)(rand() & 0xFF);
    }
#endif
}

// 바이트 배열을 HEX 문자열로 변환하여 EDIT 컨트롤에 표시
void SetEditHexFromBytes(HWND hEdit, const unsigned char* buf, size_t len)
{
    if (!hEdit || !buf || len == 0) return;

    char tmp[256] = { 0 };
    size_t maxBytes = (sizeof(tmp) - 1) / 2; // 2 chars per byte
    if (len > maxBytes) len = maxBytes;

    for (size_t i = 0; i < len; i++) {
        sprintf(tmp + (i * 2), "%02X", buf[i]);
    }
    SetWindowTextA(hEdit, tmp);
}

// 문자열이 HEX 문자열인지 확인 (0-9A-Fa-f, 길이는 짝수)
int IsHexString(const char* s)
{
    if (!s || *s == '\0') return 0;
    size_t len = strlen(s);
    if (len % 2 != 0) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

// EDIT에서 AES/HMAC 키 읽어서 바이트 배열로 변환
int GetKeyBytesFromEdit(HWND hEdit,
    unsigned char* out_key,
    size_t out_key_len,
    const char* fieldName)
{
    if (!hEdit || !out_key || out_key_len == 0) return 0;

    char buf[256] = { 0 };
    GetWindowTextA(hEdit, buf, (int)sizeof(buf));

    // 앞뒤 공백 제거
    char* p = buf;
    while (*p && isspace((unsigned char)*p)) p++;
    char* end = p + strlen(p);
    while (end > p && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }

    if (*p == '\0') {
        // 비어 있음
        return 0;
    }

    memset(out_key, 0, out_key_len);

    if (IsHexString(p)) {
        size_t hexLen = strlen(p);
        size_t bytes = hexLen / 2;

        // HEX 문자열 길이 검증: 정확히 일치해야 함
        if (bytes != out_key_len) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "%s 키의 길이가 올바르지 않습니다.\n입력된 키 길이: %zu 바이트\n필요한 키 길이: %zu 바이트\n\nHEX 문자열은 정확히 %zu 바이트(즉, %zu 자리)여야 합니다.",
                fieldName ? fieldName : "입력", bytes, out_key_len, out_key_len, out_key_len * 2);
            MessageBoxA(NULL, msg, "키 길이 오류", MB_OK | MB_ICONERROR);
            return -1;
        }

        for (size_t i = 0; i < bytes; i++) {
            char h[3] = { p[i * 2], p[i * 2 + 1], '\0' };
            unsigned int v = 0;
            if (sscanf(h, "%02X", &v) != 1) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                    "%s 키의 HEX 파싱에 실패했습니다.", fieldName ? fieldName : "입력");
                MessageBoxA(NULL, msg, "오류", MB_OK | MB_ICONERROR);
                return -1;
            }
            out_key[i] = (unsigned char)v;
        }
        return 1;
    }
    else {
        // 일반 문자열을 그대로 사용
        size_t slen = strlen(p);

        // 일반 문자열 길이 검증: 정확히 일치해야 함
        if (slen != out_key_len) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                "%s 키의 길이가 올바르지 않습니다.\n입력된 키 길이: %zu 바이트\n필요한 키 길이: %zu 바이트\n\n키는 정확히 %zu 바이트여야 합니다.",
                fieldName ? fieldName : "입력", slen, out_key_len, out_key_len);
            MessageBoxA(NULL, msg, "키 길이 오류", MB_OK | MB_ICONERROR);
            return -1;
        }

        memcpy(out_key, p, slen);
        return 1;
    }
}

// 자식 윈도우에 폰트 설정 (EnumChildWindows 콜백)
BOOL CALLBACK SetFontToChild(HWND hChild, LPARAM lParam)
{
    SendMessage(hChild, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}
