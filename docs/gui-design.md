# XMem GUI 설계 스펙

> 상태: 구현 완료(M13, 2026-09-23) · 상세 뷰어 추가(v0.1.2, 2026-09-23) · 가이드 개편(v0.1.3, 2026-09-23) · 내용 영역 크기 조절(v0.1.4, 2026-09-24) · 가독성 개선(v0.1.5, 2026-09-24) · 표/패널 사용성 수정(v0.1.6, 2026-09-24) · UI/UX 후속 수정(v0.1.7, 2026-09-24)
> 관련 문서: `docs/architecture.md`(Core Analyzer 스펙), `docs/plans/milestone-13-gui.md`(구현 계획), `docs/plans/v0.1.2-detail-viewer.md`(상세 뷰어 계획)
> 원칙: 이 스펙은 "무엇을/왜"를 정의한다. "어떻게"는 구현 계획이 담당한다.

## 1. 목표

처음 쓰는 사용자가 GUI만으로 XMem의 분석 기능 전체를 사용할 수 있게 한다.
CLI 기능을 그대로 노출하되 가이드 페이지와 실패 사유 안내로 학습 비용을 없앤다.
분석은 read-only이며, 메모리를 변경하는 실험(experiment)은 CLI 전용으로 남긴다.

## 2. 범위

### 포함 (v1)

- 프로세스 목록/정보, 메모리 맵, 메모리 검색(+주소 미리보기), 모듈, 스레드, 탐지,
  스냅샷 생성/diff, 덤프 생성/분석, 리포트 저장
- **상세 패널(v0.1.2)**: 메모리맵/모듈/스레드 표에서 행을 클릭하면 하단 리사이즈 패널이
  열려 식별·보호·백킹·hex(4 KiB 페이지)·PE(디스크/메모리)·스레드 시간을 보여준다.
  조회 실패는 `error_label`로 원인을 표시한다.
- 관리자 상승(재시작), 실패 사유 구분, 진행 표시/취소, 설정 저장, 가이드 페이지,
  오류 로그 패널

### 제외 (v1)

- 실험(experiment) GUI — CLI 유지 (안전 원칙: 변경 작업은 명시적 실험 경로만)
- 커널/드라이버, PPL 우회, 32비트 전용 빌드, 자동 업데이트, 다국어(한국어 고정)

## 3. 아키텍처

- 새 crate `crates/xmem-gui` (bin `xmem-gui`), workspace member.
- 의존: `xmem-core`, `xmem-memory`, `xmem-detection`, `xmem-forensics`, `xmem-windows`
  (기존 함수를 직접 호출 — IPC 계층 없음), `eframe`/`egui`, `egui_extras`(가상화 표),
  `rfd`(네이티브 파일 대화상자), `serde`/`serde_json`, `tracing`.
- 파일 구조:
  - `main.rs` — eframe 부팅, `--pid <PID>` 인자, 창 최소 크기
  - `app.rs` — `XMemApp`: 선택 PID, 현재 탭, 태스크 상태, 오류 로그, 설정
  - `theme.rs` — 무채색 팔레트 + 강조색 3, 다크/라이트 비주얼
  - `config.rs` — `%APPDATA%\XMem\gui.json` 로드/저장 (theme, window, guide_seen)
  - `elevate.rs` — `is_elevated()`, `restart_elevated(pid)` (ShellExecuteW runas)
  - `task.rs` — `BackgroundTask<T>`: 스레드 + `Arc<AtomicBool>` 취소 + mpsc + 상태
    (Idle/Running/Done/Failed/Cancelled)
  - `views/` — `process`, `overview`, `map`(+`region` 상세), `scan`, `modules`(+`module` 상세),
    `threads`(+`thread` 상세), `detect`, `snapshot`, `dump`, `report`, `guide`, `log`
  - `error.rs` — `XmemError` → 사람이 읽는 오류 라벨(`error_label`)
- 모든 분석 호출은 태스크 스레드에서 **자체 `LiveProcess::open(pid)`**를 열어 수행한다.
  UI 스레드는 상태/결과만 그린다 (핸들 공유 없음 → 수명 문제 회피).
- 새 분석 로직을 만들지 않는다. CLI와 동일한 모델(ProcessInfo/MemoryRegion/Finding/
  SnapshotDiff…)을 그대로 그린다.

## 4. 화면 구조 (반응형)

```
┌─ 상단 바: [XMem] [관리자 배지 | 관리자로 재시작] [가이드] [테마 토글] ──────┐
├──────────────┬────────────────────────────────────────────────────────────┤
│ 프로세스 목록 │ 탭: 개요 | 메모리맵 | 검색 | 모듈 | 스레드 | 탐지 |        │
│ 검색 필터     │      스냅샷 | 덤프 | 리포트                               │
│ 가상화 표     │                                                            │
├──────────────┴────────────────────────────────────────────────────────────┤
│ (하단 접이식) 오류 로그 패널 — 최근 200건                                   │
└───────────────────────────────────────────────────────────────────────────┘
```

### 화면별 내용

- **프로세스**: 검색(이름/PID), 표(PID/PPID/이름/아치/세션/스레드/모듈/경로), 새로고침.
  행 선택 시 오른쪽 탭이 해당 프로세스로 전환.
- **개요**: `ProcessInfo` 전체(경로, arch, session, 생성 시각, 사용자, 명령줄, 메모리
  통계, 스레드/모듈 수) + 빠른 액션(탐지/스냅샷/덤프/리포트).
- **메모리맵**: 열거 표(BASE/SIZE/STATE/TYPE/PROTECTION/CLASS/HEURISTICS/MAPPED FILE),
  정렬(주소/크기), 필터(executable/private/writable), heuristic 강조, truncated 경고.
- **검색**: needle 라디오(pattern/ASCII/wide), 필터(exec/private/writable/range/max-region),
  max-results/threads, 결과 표. 행 클릭 → **주소 ±64바이트 hex+ASCII 미리보기 패널**.
- **모듈**: 표(BASE/SIZE/NAME/PATH/ARCH) + `--pe` 토글(MACHINE/ENTRY/SECTIONS).
- **스레드**: 표(TID/PRIORITY/START ADDRESS/REGION/MODULE).
- **탐지**: findings 목록(severity 색 배지) + 상세(evidence observed, heuristic,
  interpretation). 0건이면 "absence of findings is not proof of safety" 문구.
- **스냅샷**: create(경로 선택, 진행/취소) + diff(파일 2개 선택, 요약 카드 + 변화 목록:
  regions/content/modules/threads/detections).
- **덤프**: create(`--full` 체크, 예상 크기·디스크 여유 표시) + analyze(요약 + findings).
- **리포트**: JSON/Markdown 선택 + 저장.
- **가이드**: 5단계 워크스루(§10).
- **로그**: 하단 접이식 오류 로그(§11).

## 5. 디자인 시스템

- 기반: 중립 회색조(무채색) 다크/라이트 팔레트. 폰트는 시스템 기본(맑은 고딕).
- 강조색 3종만 사용:
  - `accent` 파랑 — 선택/주요 버튼
  - `warn` 주황 — 주의(Medium)
  - `danger` 빨강 — 위험(High/Critical)
- Severity 매핑: Info/Low=회색, Medium=주황, High/Critical=빨강.
  Confidence는 점(●) 3단계로 표현.
- 표·패널·경계는 전부 무채색. 색은 "의미가 있을 때만" 쓴다.

## 6. 반응형 규칙

- 창 최소 820×600(드롭다운 전환이 실제로 도달 가능하도록). 좌측 패널 폭 220~360px 드래그 조절.
- 창 폭 < 900px → 좌측 목록을 상단 드롭다운으로 전환(선택 PID 유지).
- 표는 `egui_extras::TableBuilder` 가상화. 폭이 부족하면 정의된 우선순위의 뒤 열부터
  숨긴다(예: 경로 → 세션 → PPID).

## 7. 작업/취소 규칙

- 스캔/스냅샷: 취소 가능(`AtomicBool`). 진행률은 스피너 — 엔진이 실시간 진행을
  제공하지 않으므로 엔진을 변경하지 않는다.
- 덤프 생성: **취소 불가**(M9 한계). 시작 전에 "완료까지 대기" 문구를 표시한다.
- 모든 태스크는 UI 스레드를 블록하지 않는다.

## 8. 권한

- 시작 시 관리자 권한 자동 요청(구현): 관리자 권한이 아니면 `ShellExecuteW` "runas"로
  자신을 다시 띄우고(`--pid`·`--elevated` 전달) 기존 인스턴스는 종료한다.
  UAC를 취소하면 표준 권한으로 계속 실행된다. 상단 배지로 "관리자"/"표준 사용자" 표시.
- "관리자로 재시작" 버튼: 표준 권한으로 실행 중일 때만 표시. `--pid`를 유지해 재실행.
- 실패 사유 구분:
  | 상황 | 표시 |
  |---|---|
  | PID 0/4 (System Idle/System) | "시스템 프로세스 — 열 수 없음" |
  | AccessDenied + 표준 사용자 | "관리자로 재시작" 액션 버튼 |
  | AccessDenied + 관리자 | "PPL 보호 프로세스 — 관리자도 열 수 없음" |
  | ProcessExited | "프로세스가 종료됨" |
  | 기타 | 오류 배너(원문 메시지) |

## 9. 파일 저장

- 기본 디렉터리 `%USERPROFILE%\Documents\XMem\` (없으면 생성).
- 파일명 `xmem-<종류>-<pid>-<YYYYMMDD-HHMMSS>.<ext>`.
- `rfd` 네이티브 대화상자로 경로 변경 가능.
- 덤프 `--full`: 예상 크기(commit)와 디스크 여유를 표시하고, 부족하면 차단한다
  (CLI의 디스크 사전 검사 로직 재사용).

## 10. 가이드 페이지

- 첫 실행 시 자동 표시(config의 `guide_seen`), 상단 "가이드" 버튼으로 재열기.
- 5단계: ① 프로세스 고르기 → ② "탐지" 실행 → ③ 결과 읽는 법(Observed/Evidence/
  Heuristic/Confidence 구분, "0건 ≠ 안전") → ④ 스냅샷 전/후 Diff → ⑤ 리포트 저장.
- 안전 안내: read-only 도구, 실험은 CLI 전용, 관리자 필요 시 재시작 버튼,
  PPL 프로세스는 관리자도 열 수 없음.

## 11. 오류 로그 패널

- 하단 접이식. 최근 200건 ring buffer(시각, 수준, 메시지).
- 태스크 실패와 `tracing` 이벤트(warn 이상)를 수집한다.

## 12. 테스트 전략

- 단위 테스트(view-model 분리):
  - severity/confidence 색·라벨 매핑
  - 설정 로드/저장 왕복, 파일명 생성
  - `BackgroundTask` 상태 전이(Idle→Running→Done/Failed/Cancelled)
  - 실패 사유 분류 함수(PID 0/4, AccessDenied±관리자, ProcessExited)
  - 맵 필터/정렬, 로그 ring buffer 용량
  - 가이드 콘텐츠(5단계 존재, 안전 문구 존재)
- 스모크(실행): 창 부팅, 프로세스 목록 로드, 자기 PID로 탐지/맵/검색/스냅샷/리포트,
  관리자 배지 표시.
- GUI 렌더 자체는 자동 테스트하지 않는다(egui 특성). 로직은 view-model로 끌어내 커버.

## 13. 구현 전 검증 필요 (추측 금지, 실측할 것)

- eframe/egui/egui_extras/rfd 최신 stable 버전과 API(TableBuilder 가상화, 폰트 로드,
  `ViewportBuilder` 최소 크기).
- `ShellExecuteW` "runas" 시그니처(windows crate)와 반환값 검사.
- 관리자 판별 API(`GetTokenInformation` + `TokenElevation`) 상수/구조체.
- rfd Windows 백엔드 요구사항(COM 초기화 여부).
- egui에서 한글 렌더(시스템 폰트 로드 방식, 맑은 고딕 경로).

## 14. 리스크

| 리스크 | 완화 |
|---|---|
| egui API 버전 변동 | 구현 전 최신 버전 실측, 버전 고정 |
| 대형 표(수천 행) 성능 | TableBuilder 가상화 + 필터 기본값 |
| 상승 재시작 UX(상태 유실) | `--pid` 전달, 성공 시에만 기존 종료 |
| rfd COM/스레드 이슈 | 대화상자는 UI 스레드에서만 호출 |
| 한글 폰트 미로드 | 폰트 로드 실패 시 기본 폰트 폴백 + 로그 |

## 15. 한계 (문서화 대상)

- PPL 보호 프로세스(lsass 등)는 관리자도 분석할 수 없다(커널 제약).
- 덤프 생성은 진행 중 취소할 수 없다.
- 검색 진행률은 표시할 수 없다(엔진이 최종 통계만 제공).
- 실험(메모리 변경)은 GUI에서 제공하지 않는다.
- GUI는 x64 Windows 전용이다.
