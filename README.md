# AES_CTR_SHA512

AES 블록 암호를 CTR 모드로 구현하고, SHA-512 / HMAC-SHA512를 더한 파일 암호화 도구입니다. Win32 GUI(`app/app.c`)가 기본 실행 엔트리이며, 스트리밍 암호화 API(`src/crypto/stream/stream_api.c`), AES 엔진(레퍼런스 / T-table), NIST 기반 테스트 코드가 포함됩니다.

## 주요 기능
- AES-CTR 파일 암·복호화: 128/192/256비트 키, 레퍼런스/티테이블 엔진 선택.
- AES-CTR + HMAC-SHA512: `IV(16) || Ciphertext || HMAC(64)` 포맷으로 무결성까지 확인.
- SHA-512 파일 해시: 대용량도 스트리밍 처리, 경과 시간/평균 메모리 사용량 표시.
- Win32 GUI: 파일 선택, 키 길이/엔진/모드 선택, HEX·바이너리 키 입력 또는 랜덤 생성, 진행률 다이얼로그.
- CLI 데모 및 테스트 벡터: NIST CTR 벡터, SHA-512/HMAC-SHA512 검증 함수 제공.

## 기능 상세
- **AES-CTR 암·복호화**: 128/192/256비트 키를 지원하고, 엔진을 `T-table(속도)` 또는 `Reference(메모리)`로 선택.
- **AES-CTR + HMAC-SHA512**: 암호문에 HMAC(64바이트)를 붙여 저장. 복호화 시 HMAC 검증 후 진행 여부를 묻는 확인 창 제공.
- **SHA-512 파일 해시**: 파일을 스트리밍으로 읽어 해시를 계산하고, 경과 시간/평균 메모리 사용량을 함께 안내.
- **Win32 GUI**: 입력/출력 파일 선택, 키 길이/엔진/모드 선택, HEX(짝수 길이) 또는 동일 길이 바이너리 문자열 입력, `rand_s` 기반 랜덤 키 생성 버튼 제공.
- **CLI 데모(`app/crypto_cli.c`)**: NIST CTR 벡터 검증, 파일 암·복호화/인증값 출력. 기본 `main`은 주석 처리되어 GUI와 충돌하지 않음.
- **테스트 코드**: `tests/test_mode_ctr_main`, `tests/test_sha512_main`, `tests/test_hmac_main`으로 CTR/SHA-512/HMAC-SHA512를 검증.

## 폴더 구조
- `app/` : Win32 GUI, CLI 데모, 진행률/키 파싱 유틸, 워커 스레드 로직.
- `include/crypto/` : AES, CTR 모드, SHA-512, HMAC, 키 컨텍스트, 스트림 API 헤더.
- `src/crypto/` : AES 레퍼런스/T-table 구현, CTR 모드, SHA-512, HMAC, 스트림 파일 처리.
- `tests/` : CTR/SHA-512/HMAC-SHA512 테스트 벡터 기반 검증 코드.
- `AES_CTR_SHA512.sln` : Visual Studio 2022 솔루션(툴셋 v143).

## 엔트리 포인트 및 빌드 타깃 분리
한 번에 하나의 `main`/`WinMain`만 링크되어야 합니다. 용도별로 타깃을 나누거나 파일을 선택적으로 포함하세요.
- **GUI 실행(기본)**: `app/app.c`의 `WinMain`이 엔트리. `tests/`는 `test_*_main`만 있어 충돌 없음. `app/crypto_cli.c`의 `main`은 기본 주석 처리.
- **CLI/테스트 콘솔 타깃**:
  1) 콘솔 서브시스템 프로젝트를 별도로 만들고 필요한 파일만 포함(`tests/*.c`, `src/crypto/**`, `include/**` 등).
  2) 이 타깃에서는 `app/app.c`(WinMain 포함)를 **빌드에서 제외**해 링크 충돌을 막습니다. CLI를 쓰려면 `app/crypto_cli.c`의 `main` 주석을 해제합니다.
  3) 테스트 실행 방법은 아래 “테스트 실행” 절을 참고하세요(콘솔 타깃에서 스텁 `main` 추가).
  4) GUI 타깃과 콘솔 타깃을 서로 다른 구성/프로젝트로 유지하면 엔트리 충돌을 피할 수 있습니다.

## 빌드 방법 (Windows)
1) Visual Studio 2022(또는 v143 호환)와 Windows 10 SDK 이상 설치.  
2) 루트의 `AES_CTR_SHA512.sln`을 열고 구성/플랫폼 선택.  
   - GUI 실행: `Release|x64`(링커 서브시스템: Windows) 권장.  
   - 콘솔 타깃: 서브시스템을 Console로 설정하고 위 엔트리 분리 지침 적용.  
3) 빌드하면 `x64/Release/AES_CTR_SHA512.exe`(또는 선택한 구성/플랫폼) 생성.

## GUI 사용법 요약
1) 입력 파일을 선택하면 기본 출력 경로가 자동 설정됩니다(`.encrypted` / `.decrypted`). 필요 시 `출력 파일` 버튼으로 직접 지정.  
2) 방식 선택  
   - `AES-CTR`: 선택한 AES 키로 암·복호화.  
   - `AES-CTR + HMAC-SHA512`: 암호문에 HMAC(64바이트)을 덧붙여 무결성을 확인.  
   - `SHA-512`: 입력 파일 해시만 계산.  
3) 키 설정  
   - AES 키 길이: 128/192/256비트 버튼.  
   - AES 엔진: `T-table(빠름, 메모리 사용 큼)` / `Reference(느림, 메모리 사용 적음)`.  
   - 키 입력: HEX(짝수 길이) 또는 동일 길이 바이너리 문자열. `랜덤 생성` 버튼은 `rand_s` 기반 난수를 HEX로 채움.  
   - HMAC 모드에서는 HMAC 키 입력 필드가 보이며 기본 1024비트(128바이트) 랜덤 키를 만들 수 있고, 1024비트 미만이면 경고가 표시됩니다.  
4) 실행을 누르면 워커 스레드가 동작하며 진행률 다이얼로그가 표시됩니다. 완료 시 경과 시간과 평균 메모리 사용량이 메시지로 안내됩니다.  
   - AES-CTR+HMAC 복호화 시 HMAC가 성공하면 계속 진행 여부 확인 창이 나타납니다.  
   - SHA-512 모드에서는 계산된 해시가 결과 창과 메시지로 제공됩니다.

## 보안 주의사항
- CTR 모드에서는 **nonce/IV(카운터 블록)를 절대 재사용하면 안 됩니다**. 동일 키로 같은 IV를 두 번 쓰면 평문이 노출됩니다. 현재 샘플은 0으로 초기화된 IV를 사용하므로 실사용 시 고유 IV 생성/관리 정책을 반드시 추가하세요.
- AES-CTR+HMAC에서 HMAC 키는 충분히 길고 예측 불가능해야 합니다. 최소 1024비트(128바이트) 이상을 권장하며, 파일마다 독립된 키/IV를 사용하세요.
- AES-CTR+HMAC은 `IV||CT||HMAC` 포맷을 사용하지만 AEAD는 아니므로 키/IV 관리와 HMAC 검증 실패 처리 흐름을 신중히 설계해야 합니다.

## CLI 데모 메모
- 기본 `main`이 주석 처리되어 GUI와 충돌하지 않습니다. 콘솔에서 테스트하려면 `main` 주석을 해제하거나 별도 콘솔 프로젝트에서 이 파일을 단독 빌드하세요.
- 지원 모드: 파일 암·복호화(ref/ttable 엔진, 랜덤/seed 기반 키 파생), NIST CTR 벡터 검증(올바른 기대값 / 일부러 틀린 기대값 모드).

## 테스트 실행
- 테스트 함수: `tests/test_mode_ctr.c`, `tests/test_sha512.c`, `tests/test_hmac.c`의 `test_*_main()`.  
- 실행 예시(콘솔 `main` 스텁):
  ```c
  int main(void) {
      int rc = 0;
      rc |= test_mode_ctr_main();
      rc |= test_sha512_main();
      rc |= test_hmac_main();
      return rc;
  }
  ```
  원하는 테스트만 호출하도록 수정해도 됩니다.
