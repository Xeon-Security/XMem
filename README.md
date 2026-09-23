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

현재 **Milestone 10 (Research Lab)** 완료. Minidump 생성/분석에 이어 deterministic한 전용 Test Target(`lab/targets/xmem-target`)과 Ground Truth 회귀 테스트를 제공한다. 실험 자동화는 M11에서 추가된다.

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
| `memory map` (VirtualQueryEx, MEM_* state/type, PAGE_* 보호 속성, R/W/X, class, PE 프로브 heuristic 포함, mapped file, `--json`) | Implemented |
| `memory scan` (패턴/ASCII/UTF-16, 필터, chunked 병렬, 취소, `--json`) | Implemented |
| `modules --pid` (Toolhelp 모듈 열거: base/size/path/arch, `--json`) | Implemented |
| `threads --pid` (TID, priority, start address → region/module 상관관계, `--json`) | Implemented |
| `modules --pid --pe` (모듈 메모리 헤더 PE 요약: machine/entry/sections, `--json`) | Implemented |
| PE 분석 (`xmem-pe`: 파서/메모리 PE 분류, `memory map` heuristic 활성화) | Implemented |
| `snapshot create` (포맷 v1, 메타데이터 + 영역 blake3 + findings, 디스크 사전 검사, atomic rename, `--json`) | Implemented |
| `snapshot diff` (region/module/thread/protection/content/detection 변화, `--json`) | Implemented |
| `detect --pid` (Rule 기반 XMEM-001~005, Observed/Evidence/Heuristic/Confidence 분리, `--json`) | Implemented |
| `dump create --pid <PID> --output <FILE> [--full]` (MiniDumpWriteDump, metadata+FullMemoryInfo 기본, `--full`은 전체 메모리·디스크 사전 검사, temp→검증→rename, `--json`) | Implemented |
| `dump analyze <FILE>` (minidump 파싱: os/cpu/arch/pid/modules/threads/regions/findings, 오프라인 Detection, `--json`) | Implemented |
| Test Target (`lab/targets/xmem-target`) (deterministic 시나리오 normal/pattern/private/private-exec/pe-like/threads/protection/all, Ground Truth JSON report, 회귀 테스트) | Implemented |
| Experiment 자동화 (`experiment list` / `experiment run`) | Planned (M11) |

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
xmem modules --pid <PID>          # 로드된 모듈 (base/size/path)
xmem modules --pid <PID> --pe     # 모듈별 PE 요약 (machine/entry/sections)
xmem threads --pid <PID>          # 스레드 + 시작 주소 → region/module 상관관계
xmem snapshot create --pid <PID> --output before.xmem   # Baseline 스냅샷 (XMEM 포맷 v1)
xmem snapshot diff before.xmem after.xmem               # 변화 분석 (region/module/thread/content/detection)
xmem detect --pid <PID>                                 # Detection Rule 실행 (findings + evidence)
xmem dump create --pid <PID> --output target.dmp        # 미니덤프 생성 (기본 metadata + FullMemoryInfo)
xmem dump analyze target.dmp                            # 오프라인 분석 (regions/modules/threads + findings)
cargo build -p xmem-target                              # Research Lab Test Target 빌드
.\target\debug\xmem-target.exe run all --hold-secs 60 --report report.json  # 알려진 아티팩트 프로세스
xmem detect --pid <TARGET-PID>                          # 타깃에서 XMEM-001/002/004 등 관찰
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

`snapshot create`는 XMEM 포맷 v1(`magic "XMEM" | format_version | flags | payload_len | JSON`)로 저장하며, committed + readable 영역을 executable/private 우선으로 최대 64 MiB까지 blake3 해싱한다(예산 초과 영역은 `partial: true`). 파일은 temp → 재파싱 검증 → atomic rename으로 기록되고, 생성 전 가용 디스크 공간(예상 크기 + 16 MiB)을 검사한다.

`snapshot diff`는 region(base 키), module(name 키), thread(tid 키), content hash(base 키), finding(rule + 위치 키)을 매칭해 Added/Removed/Changed를 보고한다. 양쪽 모두 해시가 있는 영역만 content 변화로 보고된다.

`detect`는 Rule을 `xmem-detection` 크레이트에만 두고 CLI에는 하드코딩하지 않는다. 모든 finding은 Observed Fact → Evidence → Heuristic → Confidence → Interpretation 구조이며 악성 확정 표현을 쓰지 않는다. **finding 0건이 안전을 증명하지 않는다** — 출력에 이 문구가 포함된다.

`dump create`는 `MiniDumpWriteDump`로 덤프를 생성한다. 기본은 `MiniDumpNormal | MiniDumpWithFullMemoryInfo`(영역 정보 포함, 작음)이고 `--full`은 전체 메모리를 포함한다(대상의 commit 바이트 + 16 MiB 여유를 생성 전에 검사). 파일은 temp → `MDMP` 시그니처 검증 → atomic rename으로 기록되며 실패 시 temp를 제거한다.

`dump analyze`는 `minidump` crate로 덤프를 파싱해 os/cpu/arch/pid, modules, threads, regions(MemoryInfoList), 메모리 범위를 보고하고, **라이브 프로세스와 동일한 Detection Rule**을 오프라인에서 실행해 findings를 포함한다(덤프 자체는 변경되지 않는다).

Test Target(`lab/targets/xmem-target`)은 XMem이 알려진 상태를 분석하도록 deterministic한 아티팩트를 자기 프로세스에 구성한다: `normal`, `pattern`(ASCII/UTF-16/바이트 패턴), `private`, `private-exec`(RWX), `pe-like`(가짜 PE 헤더), `threads`(suspended 스레드), `protection`(RW→RWX), `all`. `--report <FILE>`로 각 아티팩트의 주소/크기/TID를 Ground Truth JSON으로 기록하며, 이 주소는 실행마다 달라진다. `cargo test --workspace`에 포함된 Ground Truth 회귀 테스트가 타깃을 spawn해 detect/scan 결과와 report를 대조한다.

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
- M10 기준 `process list` / `process info` / `memory map` / `memory scan` / `modules` / `threads` / `snapshot create` / `snapshot diff` / `detect` / `dump create` / `dump analyze`만 구현되어 있다. 나머지 분석 명령은 스텁(오류 반환)이며 마일스톤에 따라 추가된다.
- `memory map`의 mapped file 경로는 NT 디바이스 경로(`\Device\...`)로 표시된다(드라이브 문자 변환 미구현).
- `memory scan`은 guard(no-access) 및 non-readable 영역을 사전 스킵하며(카운트됨), 결과는 기본 1024개 상한(초과 시 `truncated: true` 보고, `--max-results 0`으로 해제).
- committed > 4 GiB 대형 프로세스는 기본적으로 executable/private 영역만 스캔한다(`--all`로 해제, `policy_restricted`로 보고).
- 문자열 검색은 대소문자를 구분하며, 패턴 매처는 naive 구현이다(벤치마크 후 최적화 예정).
- `executable_anonymous` / `private_executable_pe_like` heuristic은 private executable 영역의 헤더 prefix(4 KiB)를 읽어 판정한다(읽기 실패/부분 읽기에서는 heuristic을 추가하지 않는다).
- `modules --pe`는 메모리 헤더 prefix(4 KiB) 기준이라 imports/exports/relocations/TLS는 0으로 표시되며, VM_READ 권한이 없거나 파싱에 실패한 모듈은 `-`로 표시된다(Malformed PE는 pe-like로 취급). `modules` 기본 출력의 모듈별 arch는 프로세스 arch를 상속한다.
- `threads`의 priority는 동적 우선순위(조회 실패 시 `-`)이며, 스레드 시간 통계(`GetThreadTimes`)와 Wait 상태는 후속 마일스톤이다.
- Snapshot 해싱은 기본 64 MiB 예산이며, 해시가 없는 영역은 content diff로 보고되지 않는다. `SnapshotSource`의 메모리 내용 read는 후속(MemoryImage)에서 지원 예정이다.
- `dump analyze`는 MemoryInfoList 스트림에 의존한다(XMem이 만든 덤프에는 항상 포함). minidump에는 thread start address가 없어 XMEM-004는 침묵하고, mapped file 이름은 module 목록 기반 근사이며, 모듈 목록이 없는 덤프에서는 XMEM-003/004가 침묵한다. `--full`은 진행 중 취소를 지원하지 않는다(Ctrl+C는 XMem을 종료하며, 콜백 기반 취소는 후속).
- `detect`의 finding은 관찰 기반 heuristic이며 **악성 판정이 아니다**. XMEM-002는 `memory map`의 4 KiB 헤더 프로브 결과에 의존하고, XMEM-003은 모듈 목록 밖 executable 영역을 보고하므로 JIT·.NET R2R 이미지 등 정상 소프트웨어에서도 발생한다. 모듈 조회가 실패하면 XMEM-003/004는 침묵한다(skip).
- region 목록은 `MAX_REGIONS`(1,048,576) 상한을 가지며, 초과 시 `truncated: true`로 보고된다.
- 비관리자 권한으로 실행 가능하지만, 일부 시스템 프로세스는 접근이 제한된다(설계상 정상 동작).
- 실험 기능은 XMem이 직접 spawn한 전용 Test Target에만 수행한다(호스트 보호).
- Test Target은 자기 프로세스의 메모리만 변경하며(x64 Windows 전용), `threads` 시나리오의 스레드는 suspended 상태로 생성되어 실제로 실행되지 않는다. 아티팩트 주소는 실행마다 달라지므로 테스트/스모크는 `--report`의 주소를 사용해야 한다.

## Roadmap

| Milestone | 내용 | 상태 |
|---|---|---|
| M1 | Workspace, CLI 골격, Core Data Model, Error Model, Logging, Windows 추상화 | 완료 |
| M2 | Process (`process list` / `process info`) | 완료 |
| M3 | Virtual Memory (`memory map`) | 완료 |
| M4 | Memory Scanner (패턴 엔진, chunked read, 필터) | 완료 |
| M5 | Module / Thread + 주소 상관관계 | 완료 |
| M6 | PE 분석 (`xmem-pe`, 메모리 PE artifact 탐지, `modules --pe`) | 완료 |
| M7 | Snapshot 생성 / Diff | 완료 |
| M8 | Detection Engine (XMEM-001~005, `detect`, Snapshot findings/diff) | 완료 |
| M9 | Minidump 생성 / 분석 | 완료 |
| M10 | Research Lab (Test Target + Ground Truth) | 완료 |
| M11 | Experiment 자동화 | 예정 |
| M12 | 완성도 (JSON, Report, 문서, 성능, UX) | 예정 |

## License

MIT — [LICENSE](LICENSE)
