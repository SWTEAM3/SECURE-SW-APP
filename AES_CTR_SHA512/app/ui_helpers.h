#ifndef UI_HELPERS_H
#define UI_HELPERS_H

#include <windows.h>

// UI 레이아웃 상수
#define UI_X_LEFT      20
#define UI_X_RIGHT     200
#define UI_Y_START     20
#define UI_ROW_HEIGHT  30
#define UI_GROUP_HEIGHT_BASE  200
#define UI_GROUP_HEIGHT_SHA512 80
#define UI_GROUP_HEIGHT_NO_HMAC 170

// 컨트롤 생성 헬퍼
HWND CreateControl(HINSTANCE hInst, HWND hParent, const char* className, 
                   const char* text, DWORD style, int x, int y, int w, int h, HMENU id);

// 컨트롤 표시/숨김 및 이동 헬퍼
void ShowAndMoveControl(HWND hCtrl, HWND hParent, int show, int originalY, int offsetY);

// 컨트롤을 원래 위치 기준으로 이동
void MoveControlToOriginalY(HWND hCtrl, HWND hParent, int originalY, int offsetY);

// 클립보드 복사 헬퍼
void CopyToClipboard(HWND hwnd, HWND hEdit);

// 파일 크기 확인 함수 (64비트, 실패 시 0)
long long GetFileSizeBytes(const char* filepath);

// 진행률 다이얼로그 생성
extern HWND CreateProgressDialog(HWND hParent);

// 진행률 업데이트
void UpdateProgress(int percent);

// STATIC에 현재 경로 표시
void UpdatePathLabels(void);

// 입력 파일 기반으로 기본 출력 파일 경로 생성
void EnsureDefaultOutputFromInput(void);

// 랜덤 바이트 생성 (Windows rand_s 사용)
void GenerateRandomBytes(unsigned char* buf, size_t len);

// 바이트 배열을 HEX 문자열로 변환하여 EDIT 컨트롤에 표시
void SetEditHexFromBytes(HWND hEdit, const unsigned char* buf, size_t len);

// 문자열이 HEX 문자열인지 확인 (0-9A-Fa-f, 길이는 짝수)
int IsHexString(const char* s);

// EDIT에서 AES/HMAC 키 읽어서 바이트 배열로 변환
// - HEX(짝수 길이, 0-9A-Fa-f)면 HEX로 파싱
// - 아니면 입력 문자열을 그대로 바이트로 사용 (길이 정확히 out_key_len이어야 함)
// - 성공 시 1, 실패 시 0 또는 -1 리턴
int GetKeyBytesFromEdit(HWND hEdit,
    unsigned char* out_key,
    size_t out_key_len,
    const char* fieldName);

// 자식 윈도우에 폰트 설정 (EnumChildWindows 콜백)
BOOL CALLBACK SetFontToChild(HWND hChild, LPARAM lParam);

#endif

