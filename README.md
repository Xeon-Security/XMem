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

현재 **Milestone 3 (Virtual Memory)** 완료. 프로세스 열거·메타데이터 분석과 가상 메모리 영역 맵 분석을 지원한다.

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
| `memory scan` (패턴/문자열, chunked read) | Planned (M4) |
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
xmem --json process list          # JSON envelope (schema_version 포함)
xmem --json memory map --pid <PID>  # 영역 상세 JSON
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

Exit code: `0` 성공, `1` 실행 오류, `2` 사용법 오류, `3` 정책 거부(보호 프로세스 등).

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
- M3 기준 `process list` / `process info` / `memory map`만 구현되어 있다. 나머지 분석 명령은 스텁(오류 반환)이며 마일스톤에 따라 추가된다.
- `memory map`의 mapped file 경로는 NT 디바이스 경로(`\Device\...`)로 표시된다(드라이브 문자 변환 미구현).
- `memory scan`은 M4, `executable_anonymous` / `private_executable_pe_like` heuristic은 M5/M6 예정이다.
- region 목록은 `MAX_REGIONS`(1,048,576) 상한을 가지며, 초과 시 `truncated: true`로 보고된다.
- 비관리자 권한으로 실행 가능하지만, 일부 시스템 프로세스는 접근이 제한된다(설계상 정상 동작).
- 실험 기능은 XMem이 직접 spawn한 전용 Test Target에만 수행한다(호스트 보호).

## Roadmap

| Milestone | 내용 | 상태 |
|---|---|---|
| M1 | Workspace, CLI 골격, Core Data Model, Error Model, Logging, Windows 추상화 | 완료 |
| M2 | Process (`process list` / `process info`) | 완료 |
| M3 | Virtual Memory (`memory map`) | 완료 |
| M4 | Memory Scanner (패턴 엔진, chunked read, 필터) | 예정 |
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
