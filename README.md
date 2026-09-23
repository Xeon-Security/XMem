# XMem

> **Windows Memory Attack & Forensics Research Platform**

XMem은 Windows 프로세스의 메모리 구조, PE 이미지, 모듈, 스레드, 메모리 보호 속성, 메모리 영역 변화, Snapshot, Minidump 및 메모리 기반 행위를 종합적으로 분석하는 **User-mode 연구 플랫폼**이다.

핵심 질문:

> 특정 Windows 프로세스에서 메모리 관련 실험을 수행했을 때, 프로세스의 메모리·모듈·스레드·PE·보호 속성에 어떤 변화가 발생했는가?

핵심 Workflow (장기 목표):

```text
Baseline → Controlled Experiment → Post-state → Snapshot Diff → Detection → Forensic Evidence → Report
```

---

## Status

현재 **Milestone 4 (Memory Scanner)** 완료. 프로세스 열거·메타데이터 분석, 가상 메모리 영역 맵 분석, 메모리 패턴/문자열 검색을 지원한다.

| 구성 요소 | 상태 |
|---|---|
| Cargo workspace / 빌드·lint 게이트 | Implemented |
| Core Data Model (Process/Memory/Module/Thread/Protection/Evidence) | Implemented |
| Error Model (`XmemError`) | Implemented |
| 보호 프로세스 정책 (`xmem-core::guard`) | Implemented |
| `MemorySource` 추상화 (trait) | Implemented |
| Windows 추상화 (Win32 오류 매핑, RAII `OwnedHandle`, 프로세스 primitive) | Implemented |
| CLI 골격 (전체 명령 트리, `--json`, 로깅 분리, exit code 계약) | Implemented |
| `process list` / `process info` (경로, arch, session, 생성시각, 사용자, 명령줄, 메모리, 스레드/모듈 수) | Implemented |
| `memory map` (VirtualQueryEx, MEM_* state/type, PAGE_* 보호 속성, R/W/X, class, heuristic, mapped file, `--json`) | Implemented |
| `memory scan` (패턴/ASCII/UTF-16, 필터, chunked 병렬, 취소, `--json`) | Implemented |
| `modules` / `threads` | Planned (M5) |
| PE 분석 | Planned (M6) |
| Snapshot 생성/Diff | Planned (M7) |
| Detection Engine (XMEM-001~005) | Planned (M8) |
| Minidump 생성/분석 | Planned (M9) |
| Test Target + 실험 프레임워크 | Planned (M10~M11) |

세부 설계는 [`docs/architecture.md`](docs/architecture.md), 마일스톤 실행 계획은 [`docs/plans/`](docs/plans/) 참고.

---

## Requirements

- Windows 10 / 11 (x86-64)
- Rust stable 1.98+ (edition 2024)
- MSVC Build Tools (link.exe) — `rustup` 기본 toolchain `x86_64-pc-windows-msvc`

## Build

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build --release
# 산출물: target\release\xmem.exe
```

## Quick Start

```powershell
xmem --version
xmem --help
xmem process list                 # 프로세스 목록 (접근 불가 필드는 '-'로 표시)
xmem process info --pid <PID>     # 상세 메타데이터
xmem memory map --pid <PID>       # 가상 메모리 영역 맵 (분류/heuristic/mapped file)
xmem memory scan --pid <PID> --string pwsh --max-results 3      # ASCII 문자열 검색
xmem memory scan --pid <PID> --pattern "4D 5A" --executable-only  # 실행 영역에서 PE 시그니처
xmem --json process list          # JSON envelope (schema_version 포함)
xmem --json memory map --pid <PID>  # 영역 상세 JSON
xmem --json memory scan --pid <PID> --wide-string pwsh  # UTF-16LE 검색 JSON
```

## CLI Usage (계약)

```text
xmem process list
xmem process info --pid <PID>

xmem memory map --pid <PID>
xmem memory scan --pid <PID>

xmem modules --pid <PID>
xmem threads --pid <PID>

xmem snapshot create --pid <PID> --output before.xmem
xmem snapshot diff before.xmem after.xmem

xmem dump create --pid <PID> --output target.dmp
xmem dump analyze target.dmp

xmem detect --pid <PID>
xmem report --pid <PID> --output report.json

xmem experiment list
xmem experiment run <NAME>
```

전역 옵션: `--json`, `-v/-vv/-vvv`, `-q`, `--no-color`.

`memory scan` 옵션 (needle 중 정확히 1개 필수):

| 옵션 | 설명 |
|---|---|
| `--pattern <HEX>` | 16진 바이트 패턴. `??`(전체 와일드카드), `4?`/`?8`(니블 마스크) 지원 |
| `--string <S>` / `--wide-string <S>` | ASCII / UTF-16LE 문자열 |
| `--executable-only` / `--private-only` / `--writable-only` | 영역 필터 |
| `--range <START:END>` | 주소 범위 (예: `0x1000:0x2000`) |
| `--max-region-size <SIZE>` | 초과 영역 스킵 (예: `8Mi`) |
| `--offset <N>` | 영역 내 상대 오프셋이 정확히 N인 매치만 보고 |
| `--max-results <N>` | 최대 결과 수 (0 = 무제한, 기본 1024) |
| `--chunk-size <SIZE>` | 청크 크기 (기본 1Mi, 허용 4Ki~16Mi) |
| `--threads <N>` | worker 스레드 수 (기본 min(논리CPU-1, 4)) |
| `--all` | committed > 4 GiB 정책 해제 |

Exit code: `0` 성공, `1` 실행 오류, `2` 사용법 오류, `3` 정책 거부(보호 프로세스 등), `130` 취소(Ctrl+C).

## Architecture

- 2계층 구조: **Core Analyzer (read-only)** + **Research/Experiment Layer**
- `unsafe`는 `xmem-windows` 크레이트에만 허용 (workspace lint로 강제)
- 모든 분석 명령은 기본적으로 read-only이며, 대상 프로세스 상태 변경은 별도 Experiment로만 수행

자세한 내용: [`docs/architecture.md`](docs/architecture.md)

## Testing

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Limitations

- **User-mode 전용**: Kernel driver, 물리 메모리 접근, 커널 패칭은 범위 밖(Non-Goal).
- M4 기준 `process list` / `process info` / `memory map` / `memory scan`만 구현되어 있다. 나머지 분석 명령은 스텁(오류 반환)이며 마일스톤에 따라 추가된다.
- `memory map`의 mapped file 경로는 NT 디바이스 경로(`\Device\...`)로 표시된다(드라이브 문자 변환 미구현).
- `memory scan`은 guard(no-access) 및 non-readable 영역을 사전 스킵하며(카운트됨), 결과는 기본 1024개 상한(초과 시 `truncated: true` 보고, `--max-results 0`으로 해제).
- committed > 4 GiB 대형 프로세스는 기본적으로 executable/private 영역만 스캔한다(`--all`로 해제, `policy_restricted`로 보고).
- 문자열 검색은 대소문자를 구분하며, 패턴 매처는 naive 구현이다(벤치마크 후 최적화 예정).
- `executable_anonymous` / `private_executable_pe_like` heuristic은 M5/M6 예정이다.
- region 목록은 `MAX_REGIONS`(1,048,576) 상한을 가지며, 초과 시 `truncated: true`로 보고된다.
- 비관리자 권한으로 실행 가능하지만, 일부 시스템 프로세스는 접근이 제한된다(설계상 정상 동작).
- 실험 기능은 XMem이 직접 spawn한 전용 Test Target에만 수행한다(호스트 보호).

## Roadmap

| Milestone | 내용 | 상태 |
|---|---|---|
| M1 | Workspace, CLI 골격, Core Data Model, Error Model, Logging, Windows 추상화 | 완료 |
| M2 | Process (`process list` / `process info`) | 완료 |
| M3 | Virtual Memory (`memory map`) | 완료 |
| M4 | Memory Scanner (패턴 엔진, chunked read, 필터) | 완료 |
| M5 | Module / Thread + 주소 상관관계 | 예정 |
| M6 | PE 분석 | 예정 |
| M7 | Snapshot 생성 / Diff | 예정 |
| M8 | Detection Engine | 예정 |
| M9 | Minidump 생성 / 분석 | 예정 |
| M10 | Research Lab (Test Target + Ground Truth) | 예정 |
| M11 | Experiment 자동화 | 예정 |
| M12 | 완성도 (JSON, Report, 문서, 성능, UX) | 예정 |

## License

MIT — [LICENSE](LICENSE)
