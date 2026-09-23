# XMem 미래 작업 목록

> v0.1.2 기준으로 확인된 **기능적 문제와 부족한 점**을 기록한다.
> 실측 근거가 있는 항목은 측정값을 함께 남긴다. (기준일: 2026-09-23)
> v0.1.2에서 해소된 항목은 취소선 대신 "(v0.1.2 해소)"로 표시한다.
> 관련 문서: `docs/architecture.md`, `docs/plans/`, `docs/gui-design.md`

---

## 1. 오작동 (실측 확인)

### 1.1 XMEM-003 오탐 폭발 — 수정됨 (v0.1.1)

- **증상(v0.1.0)**: 정상 프로세스(pwsh.exe)에서 findings 86건 중 **84건이 XMEM-003**. `detect`/`snapshot`/`dump analyze`/`report`의 findings가 노이즈에 묻힌다.
- **원인**: XMEM-003이 "executable 영역이 로드된 모듈의 `[base, base+size)` 범위 밖이면 unbacked"로만 판정했다.
  - 실측 84건 구성: ① 49건 = `MEM_IMAGE` + `mapped_file` 있음(`srpapi.dll` 등)이며 그 파일은 **이미 모듈 목록에도 존재**(같은 파일의 두 번째 매핑) ② 35건 = `MEM_MAPPED` + 파일명 없음 ③ 1건 = private RWX(XMEM-001과 중복)
- **수정(v0.1.1, 커밋 135288c)**: 백킹 판정 추가 — `mapped_file` basename이 로드된 모듈명과 일치하거나 `MEM_IMAGE`면 제외, private executable은 XMEM-001/002가 담당하므로 제외, 남은 `MEM_MAPPED`(파일명 없음)는 Medium/Low, file-mapped는 Low/Low로 보고.
- **검증(실측, 동일 pwsh.exe)**: findings 83 → **54**(XMEM-003 81 → 52, 남은 52건 전부 Low confidence · backing=`mapped-no-file` · `MEM_MAPPED`/R-X). lab target 회귀: `experiment run remote-alloc` baseline findings **8 → 0** → post 2(detections +2, XMEM-001 observed 유지). `cargo test --workspace` 269 green.

### 1.2 XMEM-001 정상 케이스 포함

- **증상**: .NET JIT 힙 같은 정상 private RWX가 Medium으로 보고된다(실측 1건).
- **수정 방향**: JIT 힌트(영역 내 실행 코드 밀도, 동일 할당 내 다수 소형 RWX 등) 또는 억제 목록(1.4)으로 관리. 최소한 confidence 하향 근거를 evidence에 남긴다.

### 1.3 mapped_file 드라이브 경로 변환 없음

- **증상**: `mapped_file`이 `\Device\HarddiskVolume3\Windows\System32\...` 형태로 표시된다.
- **영향**: 사람이 읽기 어렵고, 모듈 경로(`C:\...`)와 문자열 매칭이 불가능 → 1.1의 근본 원인 중 하나.
- **수정 방향**: `QueryDosDeviceW`로 드라이브 문자 ↔ 디바이스 경로 테이블을 만들어 `C:\...`로 정규화. 모듈 경로 매칭·표시 개선에 함께 사용.

---

## 2. 기능 갭

### 2.1 탐지

| # | 항목 | 현재 동작 | 기대 |
|---|---|---|---|
| D1 | 사용자 규칙 | 규칙 5개 고정(XMEM-001~005) | 규칙 파일(예: TOML)로 추가/수정 |
| D2 | 억제(allowlist) | 없음 | 경로/모듈/휴리스틱 단위 억제 + 사유 기록 |
| D3 | 위험도 스코어 | severity/confidence만 | finding 우선순위 점수, 정렬 옵션 |
| D4 | XMEM-004 in minidump | start address를 못 얻으면 침묵 | 덤프에서도 시작 주소 추정 또는 "평가 불가" 명시 |

### 2.2 메모리 분석

| # | 항목 | 현재 동작 | 기대 |
|---|---|---|---|
| M1 | `allocation_base` | 필드 추가됨(v0.1.2) — `memory map` ALLOC 컬럼 + GUI 영역 상세의 할당 오프셋 | (해소) 할당 단위 상관관계 분석은 후속 |
| M2 | 모듈별 arch | 기본 목록은 프로세스 arch 상속(`--pe`/GUI 상세는 실제 machine) | 모듈 헤더에서 항상 실제 machine 읽기 |
| M3 | 스레드 상태 | TID/priority/시작 주소 + CPU 시간(`GetThreadTimes`, v0.1.2 GUI 상세) | Wait/Running 상태, 컨텍스트 |
| M4 | 언로드 모듈 | 없음 | unloaded module list(가능한 범위) |
| M5 | 읽기 실패 상세 | `read_failures` 카운트만 | 실패 주소/사유 목록 |
| M6 | 스캔 진행률 | 스피너/통계는 종료 후 | 진행률(영역 수 기준) 표시 |
| M7 | 결과 내보내기 | `--json`/리다이렉트만 | 스캔/맵 결과 파일 저장(JSON/CSV) |
| M8 | 검색 옵션 | 대소문자 구분, 리터럴/와일드카드만 | 대소문자 무시, regex, 추가 인코딩(UTF-16BE 등) |
| M9 | 영역 경계 패턴 | 영역 내부만(청크 경계는 overlap 처리) | 영역 경계 교차 검색(선택적) |

### 2.3 스냅샷 / 덤프

| # | 항목 | 현재 동작 | 기대 |
|---|---|---|---|
| S1 | content diff 범위 | 해시 예산(64 MiB) 안 영역만 | 예산 상향 옵션, 영역 지정 해싱 |
| S2 | 바이트 수준 diff | 해시 변화만 표시 | 변경 바이트 범위/패치 뷰 |
| S3 | 오프라인 재분석 | 스냅샷에 메모리 내용 미저장(해시만) | MemoryImage 소스(후속 계획) |
| S4 | `--full` 덤프 | 취소 불가, 진행률 없음 | 진행률 표시(취소는 MiniDumpWriteDump 한계로 불가 시 명시) |

### 2.4 GUI

| # | 항목 | 현재 동작 | 기대 |
|---|---|---|---|
| G1 | 맵 영역 내용 보기 | **hex 뷰어 추가됨(v0.1.2)** — 맵 상세 패널에서 4 KiB 페이지 단위 열람 | (해소) |
| G2 | 주소 점프 | 영역 상세 내 페이지 이동·할당 시작 이동(v0.1.2) | 임의 주소 입력 → 해당 영역으로 이동 |
| G3 | 결과 내보내기 | 리포트 저장만 | 맵/스캔/탐지 결과 내보내기 |
| G4 | 로그 지속 | 세션 내 200줄 | 파일 저장, 레벨 필터 |
| G5 | 다국어 | 한국어 고정 | 리소스 분리(영어 등) |

### 2.5 실험

| # | 항목 | 현재 동작 | 기대 |
|---|---|---|---|
| E1 | 실험 정의 | 4개 고정(remote-alloc 등) | 사용자 정의 실험 스펙 파일 |
| E2 | 대상 | XMem이 spawn한 xmem-target 한정(설계) | (유지) — 문서로 명확히 |
| E3 | 결과 비교 | baseline/post findings 비교 | 반복 실행 추세, 회귀 감지 |

---

## 3. 비기능 · 품질

| # | 항목 | 상태 |
|---|---|---|
| Q1 | 검증 다양성 | 전부 개발 노트북(Win11 x64) + self/lab target. Win10·ARM64·WOW64 자동화 미비 |
| Q2 | 벤치마크 | 0개. 스캔 처리량/스냅샷 수집 시간 등 수치 미공개 |
| Q3 | fuzz | 0개. pattern/PE 파서 랜덤 입력 검증 없음 |
| Q4 | soak/누수 | 장시간 구동·반복 실행 시 핸들/RSS 안정성 미측정 |
| Q5 | CI | **사용자 결정으로 제외**(2026-09-23) |
| Q6 | 코드 서명 | 없음 → SmartScreen 경고. 인증서 구매 필요(연 $200~400) |
| Q7 | 설치본 | zip + 개별 exe만. Inno Setup/WiX/설치 스크립트 없음 |
| Q8 | 커널/PPL | 설계상 비목표(user-mode 한정). PPL 프로세스는 관리자도 접근 불가 |

---

## 4. 우선순위 제안

| 순위 | 항목 | 예상 비용 | 이유 |
|---|---|---|---|
| P0 | 1.3 mapped_file 경로 변환(`\Device\...` → `C:\...`) | 0.5일 | 표시 가독성 + 모듈 경로 매칭 정확도 |
| P0 | 1.2 XMEM-001 노이즈 완화 | 0.5일 | 정상 프로세스 기본 노이즈 제거 |
| P1 | Q2 벤치마크 + 수치 공개 | 0.5일 | 성능 주장의 근거 확보 |
| P1 | Q4 soak/누수 테스트 | 1일 | 장시간 사용 신뢰 |
| P1 | M6/M7/G3 등 GUI·CLI 사용성 갭 | 1~2일 | 진행률·내보내기 (G1 hex 뷰어·G2 영역 내 이동은 v0.1.2에서 해소) |
| P2 | Q3 fuzz(pattern/PE) | 0.5~1일 | 파서 견고성 |
| P2 | S1/S2 스냅샷 diff 심화 | 1~2일 | 포렌식 가치 |
| P2 | D1/D2 규칙 파일·억제 목록 | 1~2일 | 운영 시 노이즈 관리 |
| P3 | Q7 설치본 | 0.5~1일 | 배포 편의 |
| P3 | Q6 코드 서명 | 인증서 구매 선행 | SmartScreen 경고 제거 |

---

## 5. 보류 · 결정 필요

| 항목 | 필요한 결정 |
|---|---|
| 코드 서명(Q6) | 인증서 구매 여부. 미구매 시 "자체서명/무서명 + SmartScreen 경고"를 문서로 유지 |
| Win10 VM 검증(Q1) | VM 환경 구성 여부(VirtualBox 등 무료 도구 가능) |
| ARM64 검증(Q1) | 실기 확보 또는 GitHub Actions `windows-11-arm` 러너 사용 여부 |
| CI(Q5) | 제외 결정됨. 재개 시 `gh auth refresh -s workflow` 필요 |
| 탐지 정확도 평가 | 실제 악성 샘플 코퍼스 없이는 "랩 양성 탐지 + 정상 프로세스 오탐 측정"까지가 한계임을 유지 |
