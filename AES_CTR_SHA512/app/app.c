#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S  // rand_s 사용을 위해 필요
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>    // GetOpenFileName
#include <commctrl.h>   // PROGRESS_CLASS
#include <stdio.h>
#include <stdlib.h>     // malloc, free, rand_s
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "crypto/stream/stream_api.h"
#include "crypto/cipher/aes_engine_ref.h"
#include "crypto/cipher/aes_engine_ttable.h"
#include "crypto/mode/mode_ctr.h"
#include "crypto/hash/hash_sha512.h"
#include "crypto/hash/hmac.h"
#include "ui_helpers.h"
#include "perf_utils.h"
#include "worker.h"      // ← 작업 스레드 관련 선언/메시지 공통 사용

// 컨트롤 ID
#define ID_BUTTON_FILE      1001
#define ID_BUTTON_RUN       1002
#define ID_BUTTON_OUTFILE   1003
#define ID_STATIC_INPATH    1005
#define ID_STATIC_OUTPATH   1006
#define ID_COMBO_ENGINE     1007
#define ID_EDIT_AES_KEY     1008
#define ID_BUTTON_AES_RAND  1009
#define ID_BUTTON_AES_COPY  1014
#define ID_EDIT_HMAC_KEY    1010
#define ID_BUTTON_HMAC_RAND 1011
#define ID_BUTTON_HMAC_COPY 1015
#define ID_EDIT_SHA512_HASH 1012
#define ID_COMBO_METHOD     1013
#define ID_RADIO_ENCRYPT    1016
#define ID_RADIO_DECRYPT    1017
#define ID_RADIO_KEY128     1018
#define ID_RADIO_KEY192     1019
#define ID_RADIO_KEY256     1020

// 상태 저장용 전역 변수
char g_selectedFile[MAX_PATH] = { 0 };     // 입력 파일 경로
char g_outputFile[MAX_PATH] = { 0 };     // 출력(기본: 암호문) 파일 경로
int  g_methodIndex = 0;  // 0=AES-CTR, 1=AES-CTR+HMAC-SHA512, 2=SHA-512
int  g_isEncrypt = 1;  // 1=암호화, 0=복호화
int  g_engineIndex = 0;  // 0=T-table, 1=Reference
int  g_aesKeyLen = 32; // AES 키 길이 (바이트): 16=128비트, 24=192비트, 32=256비트

// 경로 표시용 STATIC 핸들
HWND g_hInPathStatic = NULL;
HWND g_hOutPathStatic = NULL;
HWND g_hMethodCombo = NULL;
HWND g_hModeLabel = NULL;
HWND g_hAesKeyLenLabel = NULL;
HWND g_hEngineCombo = NULL;
HWND g_hEngineLabel = NULL;
HWND g_hRadioKey128 = NULL;
HWND g_hRadioKey192 = NULL;
HWND g_hRadioKey256 = NULL;
HWND g_hAesKeyEdit = NULL;
HWND g_hAesKeyLabel = NULL;
HWND g_hAesRandBtn = NULL;
HWND g_hAesCopyBtn = NULL;
HWND g_hHmacKeyEdit = NULL;
HWND g_hHmacKeyLabel = NULL;
HWND g_hHmacRandBtn = NULL;
HWND g_hHmacCopyBtn = NULL;
HWND g_hSha512HashEdit = NULL;  // SHA-512 해시 표시용
HWND g_hSha512Label = NULL;   // SHA-512 해시 레이블
HWND g_hRadioEncrypt = NULL;
HWND g_hRadioDecrypt = NULL;
HWND g_hOptionsGroupBox = NULL;  // 옵션 그룹박스
HWND g_hRunBtn = NULL;  // 실행 버튼

// 컨트롤의 원래 Y 위치 저장
int g_originalY_EngineLabel = 0;
int g_originalY_EngineCombo = 0;
int g_originalY_AesKeyLabel = 0;
int g_originalY_AesKeyEdit = 0;
int g_originalY_AesRandBtn = 0;
int g_originalY_HmacKeyLabel = 0;
int g_originalY_HmacKeyEdit = 0;
int g_originalY_HmacRandBtn = 0;
int g_originalY_Sha512Label = 0;
int g_originalY_Sha512HashEdit = 0;

// 폰트 핸들
HFONT g_hFont = NULL;
// 배경 브러시 핸들
HBRUSH g_hBgBrush = NULL;
// 흰색 브러시 (입력 필드 배경용)
HBRUSH g_hWhiteBrush = NULL;

// 작업 스레드 관련
static HANDLE g_hWorkerThread = NULL;
static HWND g_hProgressDlg = NULL;  // 진행률 다이얼로그
HWND g_hProgressBar = NULL;  // 프로그레스 바 (ui_helpers.c에서 사용)
HWND g_hProgressText = NULL; // 진행률 텍스트 (ui_helpers.c에서 사용)

// --- 함수 선언 (구현은 이 파일 다른 부분/별도 C에서) ---

// 윈도우 프로시저
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = GetModuleHandle(NULL);

        // 폰트 생성 (맑은 고딕, 9pt)
        g_hFont = CreateFontA(
            -12,                    // 높이 (음수 = 문자 높이 기준)
            0,                      // 너비 (0 = 비율 유지)
            0,                      // 각도
            0,                      // 기울기
            FW_NORMAL,              // 굵기
            FALSE,                  // 이탤릭
            FALSE,                  // 밑줄
            FALSE,                  // 취소선
            DEFAULT_CHARSET,        // 문자셋
            OUT_DEFAULT_PRECIS,     // 출력 정밀도
            CLIP_DEFAULT_PRECIS,    // 클리핑 정밀도
            DEFAULT_QUALITY,        // 출력 품질
            DEFAULT_PITCH | FF_DONTCARE, // 피치 및 패밀리
            "Malgun Gothic"         // 폰트 이름 (맑은 고딕)
        );

        // 맑은 고딕이 없으면 시스템 기본 폰트 사용
        if (!g_hFont) {
            g_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        }

        // 흰색 브러시 생성 (입력 필드 배경용)
        g_hWhiteBrush = CreateSolidBrush(RGB(255, 255, 255));

        int yPos = 20; // 시작 Y 위치
        int xLeft = 20; // 왼쪽 여백
        int xRight = 200; // 오른쪽 컨트롤 시작 위치

        // ========== 입력/출력 파일 그룹박스 ==========
        CreateWindowA("BUTTON", "입력/출력 파일",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            xLeft, yPos, 540, 90,
            hwnd, NULL, hInst, NULL);
        int fileGroupY = yPos; // 그룹박스 시작 Y 위치 저장
        yPos += 20;

        // 입력 파일
        CreateWindowA("STATIC", "입력 파일:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);
        g_hInPathStatic = CreateWindowA("STATIC", "(입력 파일 없음)",
            WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | WS_BORDER,
            xRight, yPos - 2, 260, 22,
            hwnd, (HMENU)ID_STATIC_INPATH, hInst, NULL);
        CreateWindowA("BUTTON", "찾기",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            xRight + 270, yPos - 2, 60, 24,
            hwnd, (HMENU)ID_BUTTON_FILE, hInst, NULL);
        yPos += 30;

        // 출력 파일
        CreateWindowA("STATIC", "출력 파일:",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);
        g_hOutPathStatic = CreateWindowA("STATIC", "(출력 파일 없음 - 자동 생성)",
            WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | WS_BORDER,
            xRight, yPos - 2, 260, 22,
            hwnd, (HMENU)ID_STATIC_OUTPATH, hInst, NULL);
        CreateWindowA("BUTTON", "찾기",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            xRight + 270, yPos - 2, 60, 24,
            hwnd, (HMENU)ID_BUTTON_OUTFILE, hInst, NULL);
        yPos += 40;

        // 실행 버튼을 그룹박스 바깥쪽 우측에 배치
        int runBtnX = xLeft + 540 + 10; // 그룹박스 오른쪽 바깥
        int runBtnY = fileGroupY; // 그룹박스와 같은 높이 시작
        g_hRunBtn = CreateWindowA("BUTTON", "실행",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            runBtnX, runBtnY, 120, 35,
            hwnd, (HMENU)ID_BUTTON_RUN, hInst, NULL);

        // ========== 옵션 그룹박스 ==========
        g_hOptionsGroupBox = CreateWindowA("BUTTON", "옵션",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
            xLeft, yPos, 540, 200,
            hwnd, NULL, hInst, NULL);
        yPos += 20;

        // 암호화 방식 선택 (콤보박스)
        CreateWindowA("STATIC", "암호화 방식:",
            WS_CHILD | WS_VISIBLE,
            xLeft + 10, yPos, 100, 20,
            hwnd, NULL, hInst, NULL);
        g_hMethodCombo = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            xRight, yPos - 2, 260, 200,
            hwnd, (HMENU)ID_COMBO_METHOD, hInst, NULL);
        SendMessageA(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)"AES-CTR");
        SendMessageA(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)"AES-CTR + HMAC-SHA512");
        SendMessageA(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)"SHA-512");
        SendMessageA(g_hMethodCombo, CB_SETCURSEL, 0, 0);
        yPos += 30;

        // 암호화/복호화 선택 (라디오 버튼)
        g_hModeLabel = CreateWindowA("STATIC", "모드:",
            WS_CHILD | WS_VISIBLE,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);

        g_hRadioEncrypt = CreateWindowA("BUTTON", "암호화",
            WS_CHILD | BS_AUTORADIOBUTTON | WS_GROUP,
            xRight, yPos, 80, 20,
            hwnd, (HMENU)ID_RADIO_ENCRYPT, hInst, NULL);
        g_hRadioDecrypt = CreateWindowA("BUTTON", "복호화",
            WS_CHILD | BS_AUTORADIOBUTTON,
            xRight + 90, yPos, 80, 20,
            hwnd, (HMENU)ID_RADIO_DECRYPT, hInst, NULL);
        SendMessageA(g_hRadioEncrypt, BM_SETCHECK, BST_CHECKED, 0);
        ShowWindow(g_hRadioEncrypt, SW_SHOW);
        ShowWindow(g_hRadioDecrypt, SW_SHOW);
        yPos += 30;

        // AES 키 길이 선택
        g_hAesKeyLenLabel = CreateWindowA("STATIC", "AES 키 길이:",
            WS_CHILD | WS_VISIBLE,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);
        g_hRadioKey128 = CreateWindowA("BUTTON", "128비트",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
            xRight, yPos, 80, 20,
            hwnd, (HMENU)ID_RADIO_KEY128, hInst, NULL);
        g_hRadioKey192 = CreateWindowA("BUTTON", "192비트",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            xRight + 90, yPos, 80, 20,
            hwnd, (HMENU)ID_RADIO_KEY192, hInst, NULL);
        g_hRadioKey256 = CreateWindowA("BUTTON", "256비트",
            WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
            xRight + 180, yPos, 80, 20,
            hwnd, (HMENU)ID_RADIO_KEY256, hInst, NULL);
        SendMessageA(g_hRadioKey256, BM_SETCHECK, BST_CHECKED, 0);
        yPos += 30;

        // AES 엔진 선택
        g_hEngineLabel = CreateWindowA("STATIC", "AES 엔진:",
            WS_CHILD | WS_VISIBLE,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);
        g_hEngineCombo = CreateWindowA("COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            xRight, yPos - 2, 260, 100,
            hwnd, (HMENU)ID_COMBO_ENGINE, hInst, NULL);
        SendMessageA(g_hEngineCombo, CB_ADDSTRING, 0, (LPARAM)"T-table (속도 빠름, 메모리 차지 큼)");
        SendMessageA(g_hEngineCombo, CB_ADDSTRING, 0, (LPARAM)"Reference (속도 느림, 메모리 차지 작음)");
        SendMessageA(g_hEngineCombo, CB_SETCURSEL, 0, 0);
        g_originalY_EngineLabel = yPos;
        g_originalY_EngineCombo = yPos - 2;
        yPos += 30;

        // AES 키
        g_hAesKeyLabel = CreateWindowA("STATIC", "AES 키:",
            WS_CHILD | WS_VISIBLE,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);
        g_hAesKeyEdit = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            xRight, yPos - 2, 200, 22,
            hwnd, (HMENU)ID_EDIT_AES_KEY, hInst, NULL);
        g_hAesRandBtn = CreateWindowA("BUTTON", "랜덤 생성",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            xRight + 210, yPos - 2, 70, 24,
            hwnd, (HMENU)ID_BUTTON_AES_RAND, hInst, NULL);
        g_hAesCopyBtn = CreateWindowA("BUTTON", "복사",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            xRight + 290, yPos - 2, 50, 24,
            hwnd, (HMENU)ID_BUTTON_AES_COPY, hInst, NULL);
        g_originalY_AesKeyLabel = yPos;
        g_originalY_AesKeyEdit = yPos - 2;
        g_originalY_AesRandBtn = yPos - 2;
        yPos += 30;

        // HMAC 키
        g_hHmacKeyLabel = CreateWindowA("STATIC", "HMAC 키:",
            WS_CHILD | WS_VISIBLE,
            xLeft + 10, yPos, 80, 20,
            hwnd, NULL, hInst, NULL);
        g_hHmacKeyEdit = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            xRight, yPos - 2, 200, 22,
            hwnd, (HMENU)ID_EDIT_HMAC_KEY, hInst, NULL);
        g_hHmacRandBtn = CreateWindowA("BUTTON", "랜덤 생성",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            xRight + 210, yPos - 2, 70, 24,
            hwnd, (HMENU)ID_BUTTON_HMAC_RAND, hInst, NULL);
        g_hHmacCopyBtn = CreateWindowA("BUTTON", "복사",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            xRight + 290, yPos - 2, 50, 24,
            hwnd, (HMENU)ID_BUTTON_HMAC_COPY, hInst, NULL);
        g_originalY_HmacKeyLabel = yPos;
        g_originalY_HmacKeyEdit = yPos - 2;
        g_originalY_HmacRandBtn = yPos - 2;
        // 초기에는 숨김 (AES-CTR 기본이라)
        ShowWindow(g_hHmacKeyLabel, SW_HIDE);
        ShowWindow(g_hHmacKeyEdit, SW_HIDE);
        ShowWindow(g_hHmacRandBtn, SW_HIDE);
        ShowWindow(g_hHmacCopyBtn, SW_HIDE);
        yPos += 40;

        // SHA-512 해시 표시 박스 (초기 숨김)
        g_hSha512Label = CreateWindowA("STATIC", "SHA-512 해시값:",
            WS_CHILD | WS_VISIBLE,
            xLeft, yPos, 100, 20,
            hwnd, NULL, hInst, NULL);
        g_hSha512HashEdit = CreateWindowA("EDIT", "",
            WS_CHILD | WS_BORDER | ES_READONLY | ES_MULTILINE |
            ES_AUTOVSCROLL | WS_VSCROLL,
            xLeft, yPos + 25, 540, 100,
            hwnd, (HMENU)ID_EDIT_SHA512_HASH, hInst, NULL);
        g_originalY_Sha512Label = yPos;
        g_originalY_Sha512HashEdit = yPos + 25;
        ShowWindow(g_hSha512HashEdit, SW_HIDE);
        ShowWindow(g_hSha512Label, SW_HIDE);
        yPos += 130;

        // 모든 자식 컨트롤에 폰트 적용
        if (g_hFont) {
            EnumChildWindows(hwnd, SetFontToChild, (LPARAM)g_hFont);
        }

        UpdatePathLabels();
        break;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;

        if (hCtrl == g_hAesKeyEdit ||
            hCtrl == g_hHmacKeyEdit ||
            hCtrl == g_hSha512HashEdit) {
            SetBkColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, OPAQUE);
            return (LRESULT)g_hWhiteBrush;
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;

        if (hCtrl == g_hInPathStatic ||
            hCtrl == g_hOutPathStatic ||
            hCtrl == g_hSha512HashEdit) {
            SetBkColor(hdc, RGB(255, 255, 255));
            SetBkMode(hdc, OPAQUE);
            return (LRESULT)g_hWhiteBrush;
        }
        break;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(255, 255, 255));
        SetBkMode(hdc, OPAQUE);
        return (LRESULT)g_hWhiteBrush;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* pDraw = (DRAWITEMSTRUCT*)lParam;

        if (pDraw->CtlType == ODT_BUTTON) {
            HDC hdc = pDraw->hDC;
            RECT rc = pDraw->rcItem;

            COLORREF bgColor = RGB(240, 240, 240);
            COLORREF borderColor = RGB(180, 180, 180);
            COLORREF textColor = RGB(0, 0, 0);

            if (pDraw->itemState & ODS_SELECTED) {
                bgColor = RGB(200, 200, 200);
            }
            else if (pDraw->itemState & ODS_HOTLIGHT) {
                bgColor = RGB(220, 220, 220);
            }

            int radius = 5;
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);

            HBRUSH hOldBrush = (HBRUSH)SelectObject(hdc, hBrush);
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);

            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom,
                radius * 2, radius * 2);

            char text[64] = { 0 };
            GetWindowTextA(pDraw->hwndItem, text, sizeof(text));

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, textColor);
            DrawTextA(hdc, text, -1, &rc,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            SelectObject(hdc, hOldBrush);
            SelectObject(hdc, hOldPen);
            DeleteObject(hBrush);
            DeleteObject(hPen);

            return TRUE;
        }
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);

        // 암호화 방식 콤보박스 변경
        if (id == ID_COMBO_METHOD && code == CBN_SELCHANGE) {
            if (g_hMethodCombo) {
                g_methodIndex = (int)SendMessageA(g_hMethodCombo, CB_GETCURSEL, 0, 0);
                if (g_methodIndex < 0) g_methodIndex = 0;

                int showRadioButtons = (g_methodIndex == 0 || g_methodIndex == 1);
                int isSha512Only = (g_methodIndex == 2);
                int showHmacKey = (g_methodIndex == 1);

                // 모드 라디오
                if (g_hRadioEncrypt) {
                    ShowWindow(g_hRadioEncrypt, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hRadioEncrypt, showRadioButtons);
                }
                if (g_hRadioDecrypt) {
                    ShowWindow(g_hRadioDecrypt, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hRadioDecrypt, showRadioButtons);
                }
                if (g_hModeLabel) {
                    ShowWindow(g_hModeLabel, showRadioButtons ? SW_SHOW : SW_HIDE);
                }

                // AES 키 길이
                if (g_hAesKeyLenLabel) {
                    ShowWindow(g_hAesKeyLenLabel, showRadioButtons ? SW_SHOW : SW_HIDE);
                }
                if (g_hRadioKey128) {
                    ShowWindow(g_hRadioKey128, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hRadioKey128, showRadioButtons);
                }
                if (g_hRadioKey192) {
                    ShowWindow(g_hRadioKey192, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hRadioKey192, showRadioButtons);
                }
                if (g_hRadioKey256) {
                    ShowWindow(g_hRadioKey256, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hRadioKey256, showRadioButtons);
                }

                // AES 엔진
                if (g_hEngineLabel) {
                    ShowWindow(g_hEngineLabel, showRadioButtons ? SW_SHOW : SW_HIDE);
                }
                if (g_hEngineCombo) {
                    ShowWindow(g_hEngineCombo, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hEngineCombo, showRadioButtons);
                }

                // AES 키 입력
                if (g_hAesKeyLabel) {
                    ShowWindow(g_hAesKeyLabel, showRadioButtons ? SW_SHOW : SW_HIDE);
                }
                if (g_hAesKeyEdit) {
                    ShowWindow(g_hAesKeyEdit, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hAesKeyEdit, showRadioButtons);
                }
                if (g_hAesRandBtn) {
                    ShowWindow(g_hAesRandBtn, showRadioButtons ? SW_SHOW : SW_HIDE);
                    EnableWindow(g_hAesRandBtn, showRadioButtons);
                }

                // SHA-512 선택 시 위로 땡기는 오프셋
                int offsetY = showRadioButtons ? 0 : -120;

                if (showRadioButtons) {
                    MoveControlToOriginalY(g_hEngineLabel, hwnd,
                        g_originalY_EngineLabel, offsetY);
                    MoveControlToOriginalY(g_hEngineCombo, hwnd,
                        g_originalY_EngineCombo, offsetY);
                    MoveControlToOriginalY(g_hAesKeyLabel, hwnd,
                        g_originalY_AesKeyLabel, offsetY);
                    MoveControlToOriginalY(g_hAesKeyEdit, hwnd,
                        g_originalY_AesKeyEdit, offsetY);
                    MoveControlToOriginalY(g_hAesRandBtn, hwnd,
                        g_originalY_AesRandBtn, offsetY);
                }
                ShowAndMoveControl(g_hAesCopyBtn, hwnd, showRadioButtons,
                    g_originalY_AesRandBtn, offsetY);

                // HMAC 키
                ShowAndMoveControl(g_hHmacKeyLabel, hwnd, showHmacKey,
                    g_originalY_HmacKeyLabel, offsetY);
                ShowAndMoveControl(g_hHmacKeyEdit, hwnd, showHmacKey,
                    g_originalY_HmacKeyEdit, offsetY);
                ShowAndMoveControl(g_hHmacRandBtn, hwnd, showHmacKey,
                    g_originalY_HmacRandBtn, offsetY);
                ShowAndMoveControl(g_hHmacCopyBtn, hwnd, showHmacKey,
                    g_originalY_HmacRandBtn, offsetY);

                // SHA-512 해시 박스
                if (isSha512Only) {
                    if (g_hSha512HashEdit) {
                        ShowWindow(g_hSha512HashEdit, SW_SHOW);
                        RECT rc;
                        GetWindowRect(g_hSha512HashEdit, &rc);
                        POINT pt = { rc.left, 0 };
                        ScreenToClient(hwnd, &pt);
                        SetWindowPos(g_hSha512HashEdit, NULL,
                            pt.x,
                            g_originalY_Sha512HashEdit + offsetY,
                            0, 0,
                            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                    }
                    if (g_hSha512Label) {
                        ShowWindow(g_hSha512Label, SW_SHOW);
                        RECT rc;
                        GetWindowRect(g_hSha512Label, &rc);
                        POINT pt = { rc.left, 0 };
                        ScreenToClient(hwnd, &pt);
                        SetWindowPos(g_hSha512Label, NULL,
                            pt.x,
                            g_originalY_Sha512Label + offsetY,
                            0, 0,
                            SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                    }
                }
                else {
                    if (g_hSha512HashEdit) ShowWindow(g_hSha512HashEdit, SW_HIDE);
                    if (g_hSha512Label)    ShowWindow(g_hSha512Label, SW_HIDE);
                    if (g_hRadioEncrypt && showRadioButtons) {
                        SendMessageA(g_hRadioEncrypt, BM_SETCHECK, BST_CHECKED, 0);
                        g_isEncrypt = 1;
                    }
                }

                // 옵션 그룹박스 크기 조정
                if (g_hOptionsGroupBox) {
                    RECT rc;
                    GetWindowRect(g_hOptionsGroupBox, &rc);
                    POINT pt = { rc.left, rc.top };
                    ScreenToClient(hwnd, &pt);
                    int groupHeight = 200;
                    if (isSha512Only) groupHeight = 80;
                    else if (!showHmacKey) groupHeight = 170;

                    SetWindowPos(g_hOptionsGroupBox, NULL,
                        pt.x, pt.y,
                        540, groupHeight,
                        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);

                    if (isSha512Only && g_hSha512HashEdit) {
                        RECT rcGroupBox;
                        GetWindowRect(g_hOptionsGroupBox, &rcGroupBox);
                        POINT ptGroupBox = { rcGroupBox.left, rcGroupBox.bottom };
                        ScreenToClient(hwnd, &ptGroupBox);

                        SetWindowPos(g_hSha512HashEdit, NULL,
                            ptGroupBox.x, ptGroupBox.y + 10,
                            540, 100,
                            SWP_NOZORDER | SWP_NOACTIVATE);
                        if (g_hSha512Label) {
                            SetWindowPos(g_hSha512Label, NULL,
                                ptGroupBox.x, ptGroupBox.y - 15,
                                0, 0,
                                SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
                        }
                    }
                }
            }
            return 0;
        }

        if (id == ID_RADIO_ENCRYPT && code == BN_CLICKED) {
            g_isEncrypt = 1;
            return 0;
        }
        if (id == ID_RADIO_DECRYPT && code == BN_CLICKED) {
            g_isEncrypt = 0;
            return 0;
        }

        switch (id) {
        case ID_BUTTON_FILE: {
            OPENFILENAMEA ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ZeroMemory(g_selectedFile, sizeof(g_selectedFile));
            ZeroMemory(g_outputFile, sizeof(g_outputFile));

            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = g_selectedFile;
            ofn.nMaxFile = sizeof(g_selectedFile);
            ofn.lpstrFilter = "All Files\0*.*\0\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

            if (GetOpenFileNameA(&ofn)) {
                EnsureDefaultOutputFromInput();
                UpdatePathLabels();
            }
            break;
        }
        case ID_BUTTON_AES_RAND: {
            int keyLenBytes = 32;
            if (g_hRadioKey128 &&
                SendMessageA(g_hRadioKey128, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                keyLenBytes = 16;
            }
            else if (g_hRadioKey192 &&
                SendMessageA(g_hRadioKey192, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                keyLenBytes = 24;
            }
            else if (g_hRadioKey256 &&
                SendMessageA(g_hRadioKey256, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                keyLenBytes = 32;
            }

            unsigned char aes_key[32];
            GenerateRandomBytes(aes_key, keyLenBytes);
            if (g_hAesKeyEdit) {
                SetEditHexFromBytes(g_hAesKeyEdit, aes_key, keyLenBytes);
            }
            break;
        }
        case ID_BUTTON_HMAC_RAND: {
            unsigned char hmac_key[32];
            GenerateRandomBytes(hmac_key, sizeof(hmac_key));
            if (g_hHmacKeyEdit) {
                SetEditHexFromBytes(g_hHmacKeyEdit, hmac_key, sizeof(hmac_key));
            }
            break;
        }
        case ID_BUTTON_AES_COPY:
            CopyToClipboard(hwnd, g_hAesKeyEdit);
            break;
        case ID_BUTTON_HMAC_COPY:
            CopyToClipboard(hwnd, g_hHmacKeyEdit);
            break;
        case ID_BUTTON_OUTFILE: {
            if (g_selectedFile[0] == '\0') {
                MessageBoxA(hwnd, "먼저 입력 파일을 선택하세요.",
                    "알림", MB_OK | MB_ICONINFORMATION);
                break;
            }

            char outPath[MAX_PATH] = { 0 };
            if (g_outputFile[0] != '\0') {
                strncpy(outPath, g_outputFile, MAX_PATH);
            }
            else {
                strncpy(outPath, g_selectedFile, MAX_PATH);
            }

            OPENFILENAMEA ofn;
            ZeroMemory(&ofn, sizeof(ofn));
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = hwnd;
            ofn.lpstrFile = outPath;
            ofn.nMaxFile = sizeof(outPath);
            ofn.lpstrFilter = "All Files\0*.*\0\0";
            ofn.nFilterIndex = 1;
            ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

            if (GetSaveFileNameA(&ofn)) {
                strncpy(g_outputFile, outPath, MAX_PATH);
                UpdatePathLabels();
            }
            break;
        }
        case ID_BUTTON_RUN: {
            if (g_workerRunning) {
                MessageBoxA(hwnd, "작업이 이미 실행 중입니다. 잠시 기다려주세요.",
                    "알림", MB_OK | MB_ICONINFORMATION);
                break;
            }
            if (g_selectedFile[0] == '\0') {
                MessageBoxA(hwnd, "파일을 먼저 선택하세요.",
                    "오류", MB_OK | MB_ICONWARNING);
                break;
            }

            if (g_hMethodCombo) {
                g_methodIndex = (int)SendMessageA(g_hMethodCombo, CB_GETCURSEL, 0, 0);
                if (g_methodIndex < 0) g_methodIndex = 0;
            }
            if (g_hRadioEncrypt) {
                g_isEncrypt = (SendMessageA(g_hRadioEncrypt, BM_GETCHECK, 0, 0)
                    == BST_CHECKED);
            }
            if (g_hEngineCombo) {
                g_engineIndex = (int)SendMessageA(g_hEngineCombo, CB_GETCURSEL, 0, 0);
                if (g_engineIndex < 0) g_engineIndex = 0;
            }

            g_aesKeyLen = 32;
            if (g_hRadioKey128 &&
                SendMessageA(g_hRadioKey128, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                g_aesKeyLen = 16;
            }
            else if (g_hRadioKey192 &&
                SendMessageA(g_hRadioKey192, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                g_aesKeyLen = 24;
            }
            else if (g_hRadioKey256 &&
                SendMessageA(g_hRadioKey256, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                g_aesKeyLen = 32;
            }

            EnsureDefaultOutputFromInput();
            UpdatePathLabels();

            unsigned char aes_key[32] = { 0 };
            unsigned char hmac_key[32] = { 0 };
            int aes_key_ready = 0;
            int hmac_key_ready = 0;

            int useAesCtr = (g_methodIndex == 0 || g_methodIndex == 1);
            int useHmac = (g_methodIndex == 1);

            if (useAesCtr) {
                unsigned char temp_key[32] = { 0 };
                int r = GetKeyBytesFromEdit(g_hAesKeyEdit, temp_key,
                    g_aesKeyLen, "AES");
                int actualKeyLen = 0;
                if (r > 0) {
                    char buf[256] = { 0 };
                    GetWindowTextA(g_hAesKeyEdit, buf, (int)sizeof(buf));
                    char* p = buf;
                    while (*p && isspace((unsigned char)*p)) p++;
                    if (IsHexString(p)) {
                        actualKeyLen = (int)(strlen(p) / 2);
                    }
                    else {
                        actualKeyLen = (int)strlen(p);
                    }
                }

                if (r <= 0 || actualKeyLen != g_aesKeyLen) {
                    char keyLenStr[32];
                    if (g_aesKeyLen == 16) strcpy(keyLenStr, "128비트 (16바이트)");
                    else if (g_aesKeyLen == 24) strcpy(keyLenStr, "192비트 (24바이트)");
                    else strcpy(keyLenStr, "256비트 (32바이트)");

                    char msg[256];
                    snprintf(msg, sizeof(msg),
                        "AES 키가 비어 있거나 길이가 맞지 않습니다.\n"
                        "선택한 키 길이: %s\n랜덤으로 키를 생성할까요?",
                        keyLenStr);
                    int ans = MessageBoxA(hwnd, msg,
                        "AES 키 없음",
                        MB_YESNO | MB_ICONQUESTION);
                    if (ans == IDYES) {
                        GenerateRandomBytes(aes_key, g_aesKeyLen);
                        aes_key_ready = 1;
                        if (g_hAesKeyEdit) {
                            SetEditHexFromBytes(g_hAesKeyEdit,
                                aes_key, g_aesKeyLen);
                        }
                    }
                    else {
                        MessageBoxA(hwnd,
                            "AES 키를 입력하거나 랜덤 생성을 선택해야 합니다.",
                            "오류", MB_OK | MB_ICONERROR);
                        break;
                    }
                }
                else {
                    memcpy(aes_key, temp_key, g_aesKeyLen);
                    aes_key_ready = 1;
                }
            }

            if (useHmac) {
                int r = GetKeyBytesFromEdit(g_hHmacKeyEdit,
                    hmac_key,
                    sizeof(hmac_key),
                    "HMAC");
                if (r <= 0) {
                    int ans = MessageBoxA(hwnd,
                        "HMAC 키가 비어 있습니다.\n랜덤으로 256비트 키를 생성할까요?",
                        "HMAC 키 없음",
                        MB_YESNO | MB_ICONQUESTION);
                    if (ans == IDYES) {
                        GenerateRandomBytes(hmac_key, sizeof(hmac_key));
                        hmac_key_ready = 1;
                        if (g_hHmacKeyEdit) {
                            SetEditHexFromBytes(g_hHmacKeyEdit,
                                hmac_key, sizeof(hmac_key));
                        }
                    }
                    else {
                        MessageBoxA(hwnd,
                            "HMAC 키를 입력하거나 랜덤 생성을 선택해야 합니다.",
                            "오류", MB_OK | MB_ICONERROR);
                        break;
                    }
                }
                else {
                    hmac_key_ready = 1;
                }
            }

            if (g_isEncrypt) {
                if (g_outputFile[0] == '\0') {
                    EnsureDefaultOutputFromInput();
                }
            }
            else {
                if (g_outputFile[0] == '\0') {
                    strncpy(g_outputFile, g_selectedFile, MAX_PATH - 1);
                    g_outputFile[MAX_PATH - 1] = '\0';
                    char* ext = strrchr(g_outputFile, '.');
                    if (ext) *ext = '\0';
                    size_t len = strlen(g_outputFile);
                    if (len + 11 < MAX_PATH) {
                        strcat(g_outputFile, ".decrypted");
                    }
                }
            }

            if (strlen(g_selectedFile) == 0 ||
                ((useAesCtr || useHmac) && strlen(g_outputFile) == 0)) {
                MessageBoxA(hwnd, "파일 경로가 유효하지 않습니다.",
                    "오류", MB_OK | MB_ICONERROR);
                break;
            }

            worker_data_t* data =
                (worker_data_t*)malloc(sizeof(worker_data_t));
            if (!data) {
                MessageBoxA(hwnd, "메모리 할당 실패",
                    "오류", MB_OK | MB_ICONERROR);
                break;
            }
            memset(data, 0, sizeof(worker_data_t));
            data->methodIndex = g_methodIndex;
            data->isEncrypt = g_isEncrypt;
            data->engineIndex = g_engineIndex;
            data->aesKeyLen = g_aesKeyLen;
            strncpy(data->inputFile, g_selectedFile, MAX_PATH - 1);
            strncpy(data->outputFile, g_outputFile, MAX_PATH - 1);
            data->hwnd = hwnd;
            if (useAesCtr && aes_key_ready) {
                memcpy(data->aes_key, aes_key, g_aesKeyLen);
            }
            if (useHmac && hmac_key_ready) {
                memcpy(data->hmac_key, hmac_key, sizeof(hmac_key));
            }

            if (g_hRunBtn) {
                EnableWindow(g_hRunBtn, FALSE);
                SetWindowTextA(g_hRunBtn, "처리 중...");
            }

            g_hProgressDlg = CreateProgressDialog(hwnd);

            g_workerRunning = 1;
            g_hWorkerThread = CreateThread(NULL, 0,
                WorkerThreadProc, data,
                0, NULL);
            if (!g_hWorkerThread) {
                g_workerRunning = 0;
                if (g_hProgressDlg) {
                    DestroyWindow(g_hProgressDlg);
                    g_hProgressDlg = NULL;
                    g_hProgressBar = NULL;
                    g_hProgressText = NULL;
                }
                if (g_hRunBtn) {
                    EnableWindow(g_hRunBtn, TRUE);
                    SetWindowTextA(g_hRunBtn, "실행");
                }
                free(data);
                MessageBoxA(hwnd, "작업 스레드 생성 실패",
                    "오류", MB_OK | MB_ICONERROR);
                break;
            }

            memset(aes_key, 0, sizeof(aes_key));
            memset(hmac_key, 0, sizeof(hmac_key));
            break;
        }
        default:
            break;
        }
        break;
    }
    case WM_WORKER_PROGRESS: {
        int percent = (int)wParam;
        UpdateProgress(percent);
        break;
    }
    case WM_WORKER_COMPLETE: {
        g_workerRunning = 0;

        if (g_hProgressDlg) {
            DestroyWindow(g_hProgressDlg);
            g_hProgressDlg = NULL;
            g_hProgressBar = NULL;
            g_hProgressText = NULL;
        }

        if (g_hRunBtn) {
            EnableWindow(g_hRunBtn, TRUE);
            SetWindowTextA(g_hRunBtn, "실행");
        }

        char* msg = (char*)wParam;
        if (msg && strlen(msg) > 0) {
            if (g_methodIndex == 2) {
                char* hashPart = msg;
                char* p1 = strchr(msg, '|');
                char* p2 = NULL;
                unsigned long long elapsed_ms_val = 0;
                unsigned long long mem_kb_val = 0;

                if (p1) {
                    *p1 = '\0';
                    p2 = strchr(p1 + 1, '|');
                    if (p2) {
                        *p2 = '\0';
                        elapsed_ms_val = _strtoui64(p1 + 1, NULL, 10);
                        mem_kb_val = _strtoui64(p2 + 1, NULL, 10);
                    }
                }

                if (g_hSha512HashEdit) {
                    SetWindowTextA(g_hSha512HashEdit, hashPart);
                }

                char infoBuf[256];
                if (elapsed_ms_val > 0 || mem_kb_val > 0) {
                    char timeStr[64];
                    char memStr[64];
                    FormatElapsedTime(elapsed_ms_val, timeStr, sizeof(timeStr));
                    FormatMemorySize((SIZE_T)mem_kb_val, memStr, sizeof(memStr));

                    snprintf(infoBuf, sizeof(infoBuf),
                        "SHA-512 해시 계산 완료!\n\n"
                        "소요 시간: %s\n"
                        "평균 메모리 사용량: %s",
                        timeStr, memStr);
                }
                else {
                    strcpy(infoBuf, "SHA-512 해시 계산 완료!");
                }

                MessageBoxA(hwnd, infoBuf, "완료", MB_OK | MB_ICONINFORMATION);
            }
            else {
                MessageBoxA(hwnd, msg, "완료", MB_OK | MB_ICONINFORMATION);
            }
            free(msg);
        }
        else {
            MessageBoxA(hwnd, "작업이 완료되었습니다!",
                "완료", MB_OK | MB_ICONINFORMATION);
        }
        return 0;
    }
    case WM_WORKER_ERROR: {
        g_workerRunning = 0;

        if (g_hProgressDlg) {
            DestroyWindow(g_hProgressDlg);
            g_hProgressDlg = NULL;
            g_hProgressBar = NULL;
            g_hProgressText = NULL;
        }

        if (g_hRunBtn) {
            EnableWindow(g_hRunBtn, TRUE);
            SetWindowTextA(g_hRunBtn, "실행");
        }

        int errorCode = (int)wParam;
        char err_msg[256];
        if (errorCode == -100) {
            strcpy(err_msg, "HMAC 파일 저장 실패");
        }
        else if (errorCode == -101) {
            strcpy(err_msg, "HMAC 파일을 찾을 수 없습니다");
        }
        else if (errorCode == -102) {
            strcpy(err_msg, "HMAC 파일 읽기 실패");
        }
        else if (errorCode == -103) {
            strcpy(err_msg,
                "HMAC 검증 실패!\n\n파일이 변조되었거나 키가 잘못되었습니다.");
        }
        else if (errorCode == -104) {
            strcpy(err_msg, "임시 파일 열기 실패");
        }
        else if (errorCode == -105) {
            strcpy(err_msg, "출력 파일 생성 실패");
        }
        else if (errorCode == -106) {
            strcpy(err_msg, "입력 파일을 열 수 없습니다");
        }
        else if (errorCode == -107) {
            strcpy(err_msg, "IV 읽기 실패 (파일이 너무 짧습니다)");
        }
        else if (errorCode == -108) {
            strcpy(err_msg,
                "파일 크기가 올바르지 않습니다 (최소 80바이트 필요: IV 16 + HMAC 64)");
        }
        else if (errorCode == -109) {
            strcpy(err_msg, "HMAC 읽기 실패");
        }
        else if (errorCode == -110) {
            strcpy(err_msg, "임시 파일 생성 실패");
        }
        else if (errorCode == -111) {
            strcpy(err_msg, "IV 쓰기 실패");
        }
        else if (errorCode == -112) {
            strcpy(err_msg, "암호문 쓰기 실패");
        }
        else if (errorCode == -113) {
            strcpy(err_msg, "HMAC 쓰기 실패");
        }
        else if (errorCode == -114) {
            strcpy(err_msg, "파일 닫기 실패");
        }
        else if (errorCode == -115) {
            strcpy(err_msg, "출력 파일 생성 확인 실패");
        }
        else if (errorCode == -200) {
            strcpy(err_msg,
                "SHA-512 해시 계산: 입력 파일을 열 수 없습니다.");
        }
        else if (errorCode == -201) {
            strcpy(err_msg,
                "SHA-512 해시 계산: 파일 읽기 중 오류가 발생했습니다.");
        }
        else if (errorCode == -202) {
            strcpy(err_msg,
                "메모리 할당 실패 (버퍼 할당 불가).");
        }
        else {
            snprintf(err_msg, sizeof(err_msg),
                "작업 실패 (오류 코드: %d)", errorCode);
        }
        MessageBoxA(hwnd, err_msg, "오류", MB_OK | MB_ICONERROR);
        break;
    }
    case WM_HMAC_VERIFIED: {
        int res = MessageBoxA(
            hwnd,
            "인증 성공!\n\n이어서 복호화를 진행할까요?",
            "HMAC 검증",
            MB_YESNO | MB_ICONQUESTION
        );
        return res;
    }
    case WM_DESTROY:
        if (g_workerRunning && g_hWorkerThread) {
            WaitForSingleObject(g_hWorkerThread, INFINITE);
            CloseHandle(g_hWorkerThread);
            g_hWorkerThread = NULL;
        }
        if (g_hFont && g_hFont != (HFONT)GetStockObject(DEFAULT_GUI_FONT)) {
            DeleteObject(g_hFont);
            g_hFont = NULL;
        }
        if (g_hBgBrush) {
            DeleteObject(g_hBgBrush);
            g_hBgBrush = NULL;
        }
        if (g_hWhiteBrush) {
            DeleteObject(g_hWhiteBrush);
            g_hWhiteBrush = NULL;
        }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;

    const wchar_t CLASS_NAME[] = L"CryptoFileToolWindowClass";

    g_hBgBrush = CreateSolidBrush(RGB(240, 240, 240));

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = g_hBgBrush;

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(
        CLASS_NAME,
        L"파일 암호화 도구",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        700, 500,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd) {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}
