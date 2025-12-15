# AES_CTR_SHA512

AES 블록 암호를 CTR 모드로 구현하고, SHA-512 / HMAC-SHA512 해시를 더한 파일 암호화 도구입니다. Win32 GUI(`app/app.c`)를 중심으로 스트리밍 암호화 API(`src/crypto/stream/stream_api.c`), AES 엔진(레퍼런스 / T-table), NIST 테스트 벡터 기반 테스트 코드가 포함되어 있습니다.

## 주요 기능
- AES-CTR 파일 암호화/복호화: 128/192/256비트 키, 레퍼런스/티테이블 엔진 선택.
- AES-CTR + HMAC-SHA512: `IV(16) || Ciphertext || HMAC(64)` 포맷으로 저장, 복호화 시 인증값 검증.
- SHA-512 파일 해시: 대용량도 스트리밍 처리, 경과 시간/평균 메모리 사용량 표시.
- Win32 GUI: 입력/출력 파일 선택, 키 길이/엔진/모드 선택, HEX·바이너리 키 입력 또는 랜덤 생성, 진행률 다이얼로그, 결과 메시지.
- CLI 데모(`app/crypto_cli.c`): NIST CTR 테스트 벡터 검증 및 파일 암·복호화(기본 `main`은 주석 처리).
- 테스트 벡터: CTR 모드, SHA-512, HMAC-SHA512에 대해 NIST/표준 벡터 기반 검증 함수 제공.

## 폴더 구조
- `app/` : Win32 GUI, CLI 데모, 진행률/키 파싱 유틸, 워커 스레드 로직.
- `include/crypto/` : AES, CTR 모드, SHA-512, HMAC, 키 컨텍스트, 스트림 API 헤더.
- `src/crypto/` : 암호 구현(AES 레퍼런스/T-table, CTR 모드, SHA-512, HMAC, 스트림 파일 처리).
- `tests/` : `test_mode_ctr_main`, `test_sha512_main`, `test_hmac_main` 테스트 함수가 들어 있는 벡터 기반 검증 코드.
- `AES_CTR_SHA512.sln` : Visual Studio 2022 솔루션(툴셋 v143).

## 엔트리 포인트와 빌드 타깃 분리
한 번에 하나의 `main`/`WinMain`만 링크되어야 합니다. 용도별로 타깃을 분리하세요.
- **GUI 실행(기본)**: `app/app.c`의 `WinMain`이 엔트리. `tests/` 파일은 `test_*_main`만 존재해 충돌 없음. `app/crypto_cli.c`의 `main`은 기본 주석 처리.
- **CLI/테스트용 콘솔 타깃**을 만들 때:
  1) 콘솔 서브시스템 프로젝트를 별도로 만들고, 필요한 파일만 포함합니다(예: `tests/*.c`, `src/crypto/**`, `include/**` 등).
  2) 이 타깃에서는 `app/app.c`(WinMain 포함)를 **제외**해 링크 충돌을 막습니다. CLI를 쓰려면 `app/crypto_cli.c`의 `main` 주석을 해제합니다.
  3) 테스트를 돌리려면 아래처럼 간단한 `main` 스텁을 만들고 `test_*_main()`을 호출합니다.
     ```c
     int main(void) {
         int rc = 0;
         rc |= test_mode_ctr_main();
         rc |= test_sha512_main();
         rc |= test_hmac_main();
         return rc;
     }
     ```
  4) GUI 타깃과 콘솔 타깃을 서로 다른 구성/프로젝트로 유지하면 엔트리 충돌을 피할 수 있습니다.

## 빌드 방법 (Windows)
1) Visual Studio 2022(또는 v143 호환)와 Windows 10 SDK 이상을 설치합니다.  
2) 루트의 `AES_CTR_SHA512.sln`을 열고 구성/플랫폼을 선택합니다.  
   - GUI 실행을 위해 `Release|x64`(링커 서브시스템: Windows)를 권장합니다.  
   - 콘솔 타깃을 만들 경우 서브시스템을 Console로 설정하고 위의 엔트리 분리 지침을 따릅니다.  
3) `AES_CTR_SHA512` 프로젝트를 빌드하면 `x64/Release/AES_CTR_SHA512.exe`(또는 선택한 구성/플랫폼)로 실행 파일이 생성됩니다.

## GUI 사용법 요약
1) 입력 파일을 선택하면 기본 출력 경로가 자동 설정됩니다(`.encrypted` / `.decrypted`). 필요 시 `출력 파일` 버튼으로 직접 지정.  
2) 방식 선택  
   - `AES-CTR`: 선택한 AES 키로 암·복호화.  
   - `AES-CTR + HMAC-SHA512`: 암호문에 HMAC(64바이트)을 덧붙여 무결성을 확인.  
   - `SHA-512`: 입력 파일 해시만 계산(암·복호화 옵션 숨김).  
3) 키 설정  
   - AES 키 길이: 128/192/256비트 라디오 버튼.  
   - AES 엔진: `T-table(빠름, 메모리 큼)` / `Reference(느림, 메모리 적음)`.  
   - 키 입력: HEX(짝수 길이) 또는 동일 길이 바이너리 문자열. `랜덤 생성` 버튼은 `rand_s` 기반 난수를 HEX로 채움.  
   - HMAC 모드에서는 HMAC 키 입력 필드가 보이며 기본 1024비트(128바이트) 랜덤 키를 만들 수 있고, 1024비트 미만이면 경고가 표시됩니다.  
4) 실행을 누르면 워커 스레드가 동작하며 진행률 다이얼로그가 표시됩니다. 완료 시 경과 시간과 평균 메모리 사용량이 메시지로 안내됩니다.  
   - AES-CTR+HMAC 복호화 시 HMAC가 성공하면 계속 진행 여부 확인 창이 나타납니다.  
   - SHA-512 모드에서는 계산된 해시가 결과 창과 메시지로 제공됩니다.

## CLI 데모(`app/crypto_cli.c`)
- 기본적으로 `main`이 주석 처리되어 있어 GUI와 충돌하지 않습니다. 콘솔에서 테스트하려면 주석을 해제하거나 별도 콘솔 프로젝트에서 이 파일을 단독 빌드하세요.  
- 모드
  - 파일 암복호화: AES 엔진(ref/ttable), 키 길이, 입력/출력 경로, 랜덤/seed 기반 키 파생 선택. 암호문 SHA-512 인증값과 평문/암호문 앞부분을 출력합니다.
  - NIST CTR 벡터 검증: 128/192/256비트 벡터 실행, 일부러 기대값을 깨뜨리는 모드로 디버깅 지원.

## 테스트 실행
- 제공 테스트 함수: `tests/test_mode_ctr.c`(CTR), `tests/test_sha512.c`(SHA-512), `tests/test_hmac.c`(HMAC-SHA512). 각각 `test_*_main()` 형태입니다.  
- 실행 방법 예시(임시 콘솔 `main` 사용):
  ```c
  int main(void) {
      int rc = 0;
      rc |= test_mode_ctr_main();
      rc |= test_sha512_main();
      rc |= test_hmac_main();
      return rc;
  }
  ```
  위 스텁을 추가한 뒤 콘솔 서브시스템으로 빌드하거나, 원하는 테스트 함수만 호출하는 별도 소규모 프로젝트를 만들어도 됩니다.
