# XMem Architecture

> 상태: **설계 문서 (Design Spec)**. 컴포넌트별 구현 상태는 [Status](#14-status) 표와 README를 따른다.
> 검증되지 않은 동작을 사실처럼 기술하지 않는다. 구현이 진행되면 이 문서를 갱신한다.

## 1. 목표

XMem은 Windows 프로세스의 메모리 구조와 메모리 기반 행위를 종합적으로 분석하는 **User-mode Memory Attack & Forensics Research Platform**이다.

핵심 질문:

> 특정 Windows 프로세스에서 메모리 관련 실험을 수행했을 때, 프로세스의 메모리·모듈·스레드·PE·보호 속성에 어떤 변화가 발생했는가?

핵심 차별화 기능: **Baseline → Controlled Experiment → Post-state → Diff → Detection → Forensic Evidence → Report**.

## 2. 계층 구조

```text
┌──────────────────────────────────────────────────────────────┐
│ Research / Experiment Layer (xmem-experiments)               │
│  Target Discovery → Baseline Snapshot → Action → Post        │
│  Snapshot → Diff → Detection → Report                        │
│  · 실험 코드는 이 계층에만 존재한다.                          │
│  · 변경 API(VirtualAllocEx 등)는 이 계층에만 존재한다.        │
└──────────────────────────────────────────────────────────────┘
                             │
┌──────────────────────────────────────────────────────────────┐
│ Core Analyzer (read-only)                                    │
│  xmem-cli → xmem-forensics / xmem-detection / xmem-memory /  │
│             xmem-pe → xmem-windows → Win32                   │
│  xmem-core: 모델·에러·Evidence·Guard·MemorySource trait      │
└──────────────────────────────────────────────────────────────┘
```

의존성 규칙:

- 의존 방향은 단방향이며 순환 의존을 금지한다.
- `xmem-core`는 다른 프로젝트 crate에 의존하지 않는다.
- Win32 FFI는 `xmem-windows`에만 존재한다. 다른 crate는 `windows` crate를 직접 사용하지 않는다.
- `unsafe`는 `xmem-windows`에서만 허용한다(workspace lint `unsafe_code = "deny"`, crate 단위 `allow` + SAFETY 주석).
- 변경(Write) Win32 API는 `xmem-experiments`에만 존재한다.
- 라이브러리 crate는 `anyhow`를 사용하지 않는다. `anyhow`는 `xmem-cli`/`xmem-experiments` 오케스트레이션에서만 허용한다.

## 3. Crate 구조와 생성 시점

빈 껍데기 crate를 미리 만들지 않고, **첫 실내용이 생기는 Milestone에서 생성**한다.

| Crate | 책임 | 생성 |
|---|---|---|
| `xmem-core` | 데이터 모델, 에러, Evidence/Finding, Guard, MemorySource trait, 버전 상수 | M1 |
| `xmem-windows` | Win32 FFI, RAII Handle, Win32→XmemError 매핑 | M1 |
| `xmem-cli` | clap 트리, human/JSON 출력, exit code | M1 |
| `xmem-memory` | region 분류, MemorySource 구현(LiveProcess), Pattern 엔진, chunked scanner | M3 |
| `xmem-pe` | goblin 기반 PE 파싱, 메모리 PE artifact 탐지 | M6 |
| `xmem-forensics` | Snapshot 포맷/직렬화, Diff, Report(JSON/Markdown), MemoryImage 소스 | M7 |
| `xmem-detection` | Rule trait + 초기 Rule(XMEM-001~005) | M8 |
| `xmem-experiments` | 실험 프레임워크, lab target 오케스트레이션, Guard 강제 | M11 |
| `lab/targets/xmem-target` | 결정적 Test Target (bin crate, workspace member) | M10 |

## 4. Dependency 정책

| Crate | 도입 | 용도 | 비고 |
|---|---|---|---|
| `windows` 0.62.x | M1 | Win32 FFI | crate별 최소 feature만. 버전 pin |
| `clap` 4 (derive) | M1 | CLI | |
| `serde` / `serde_json` | M1 | JSON 계약 | 외부 포맷 = 직렬화 구조체 (schema_version envelope) |
| `thiserror` 2 | M1 | 에러 enum | |
| `anyhow` | M1 | CLI/experiments 전용 | 라이브러리 금지 |
| `tracing` / `tracing-subscriber` | M1 | stderr 진단 로그 | stdout은 사용자 출력 전용 |
| `chrono` | M2 | CLI 타임스탬프 표시 | M7 예정이었으나 M2로 앞당김 |
| `uuid` | M7 | ID | |
| `rayon` | M4 | region 단위 bounded 병렬 스캔 | thread pool 크기 고정 |
| `ctrlc` | M4 | Ctrl+C cooperative cancel | |
| `goblin` | M6 | PE 파싱 | |
| `blake3` | M7 | region 내용 해시 | |
| `minidump` | M9 | dump analyze | |
| `memmap2` | M7+ | MemoryImage 소스 | 필요 시점 도입 |

미도입(의도적): `tokio`(비동기 불필요), `winapi`(windows-rs로 단일화), 테이블 포매팅 crate(수동 정렬로 충분).

추가 Dependency는 실제 필요성이 확인된 경우에만 도입하고 이 표를 갱신한다.

## 5. Core Data Model

외부 JSON 계약은 `xmem-core`의 serde 직렬화 구조체를 기준으로 한다. 모든 JSON envelope에 `schema_version`을 포함한다.

```rust
pub struct ProcessInfo {
    pub pid: u32, pub ppid: Option<u32>, pub name: String,
    pub image_path: Option<String>, pub arch: ProcessArch,
    pub session_id: Option<u32>, pub creation_time: Option<DateTime<Utc>>,
    pub command_line: Option<String>,          // 실패 시 None + reason은 로그/필드로
    pub user: Option<String>,
    pub memory_stats: Option<MemoryStats>,     // working set, private bytes 등
    pub thread_count: Option<u32>, pub module_count: Option<u32>,
}

pub struct MemoryRegion {
    pub base: u64, pub size: u64,
    pub state: MemoryState,                    // Commit | Reserve | Free
    pub protection: Protection,                // 사람이 읽는 형태 + 플래그
    pub allocation_protection: Option<Protection>,
    pub region_type: MemoryType,               // Image | Mapped | Private
    pub readable: bool, pub writable: bool, pub executable: bool,
    pub classification: RegionClass,           // Image | Mapped | Private | Free | Reserved | Unknown
    pub heuristics: Vec<Heuristic>,
    pub mapped_file: Option<String>,           // GetMappedFileNameW 결과(M3+)
}
```

`Protection`은 raw `u32` 위에 읽기/쓰기/실행 플래그와 `Display`("RWX" 등)를 제공하는 뉴타입이다. raw flag만 출력하지 않는다.

## 6. Evidence 모델 (사실과 해석의 분리)

```text
ObservedFact → Evidence → Heuristic → Confidence → Interpretation
```

모든 Detection 결과는 `Finding`이며 아래 필드를 강제한다. "MALWARE DETECTED" 같은 단정은 타입 수준에서 표현하지 않는다.

```rust
pub enum Severity { Info, Low, Medium, High, Critical }
pub enum Confidence { Low, Medium, High }

pub struct Evidence {
    pub kind: String,                          // "region", "thread", "module", "pe"
    pub address: Option<u64>,
    pub region_base: Option<u64>,
    pub observed: BTreeMap<String, String>,    // 관찰값 (raw)
}

pub struct Finding {
    pub rule_id: String,                       // "XMEM-001"
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub heuristic: String,                     // 판단 규칙 요약
    pub interpretation: String,                // "Potentially Suspicious ..." 수준 표현만
}
```

## 7. MemorySource 추상화

상위 분석 계층은 데이터 출처를 모른다.

```rust
pub trait MemorySource {
    fn process(&self) -> &ProcessInfo;
    fn regions(&self) -> Result<Vec<MemoryRegion>>;              // 전체 스냅샷
    fn read(&self, addr: u64, buf: &mut [u8]) -> Result<ReadOutcome>;
    fn modules(&self) -> Result<Vec<ModuleInfo>>;
    fn threads(&self) -> Result<Vec<ThreadInfo>>;
}

pub struct ReadOutcome { pub bytes_read: usize, pub partial: bool }  // Partial Read를 정상 반환
```

구현: `LiveProcess`(xmem-memory, M3), `Snapshot`(xmem-forensics, M7), `Minidump`·`MemoryImage`(M9+).

## 8. Snapshot 포맷 v1 (M7 구현 예정)

```text
offset  size  field
0       4     magic  = b"XMEM"
4       2     format_version: u16 LE (=1)
6       2     flags: u16 LE (bit0: payload deflate 예약, 현재 0)
8       4     payload_len: u32 LE
12      ..    payload: UTF-8 JSON (SnapshotEnvelope)
```

```rust
pub struct SnapshotEnvelope {
    pub schema_version: u32,
    pub xmem_version: String,
    pub format_version: u16,
    pub timestamp: DateTime<Utc>,
    pub process: ProcessInfo,
    pub regions: Vec<MemoryRegion>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub content_hashes: Vec<RegionHash>,       // 선택 수집 영역의 blake3
    pub findings: Vec<Finding>,
    pub acquisition: AcquisitionMeta,          // 소스 종류, 권한, 실패 통계
}
```

- 쓰기: 임시파일 → 검증(재파싱 + 길이 확인) → atomic rename. 불완전 파일을 정상 Snapshot으로 남기지 않는다.
- `format_version`으로 migration 지점을 명시한다.

## 9. Detection Rules (M8 구현 예정)

| Rule | 조건(관찰) | Severity | Confidence | 비고 |
|---|---|---|---|---|
| XMEM-001 Executable Private Memory | committed + MEM_PRIVATE + executable(X/RWX/WCX) | Medium | High | 사실 기반 |
| XMEM-002 PE Header in Private Executable Region | XMEM-001 영역에서 `MZ` + (범위 내) `PE\0\0` | High | Medium | JIT/데이터 오탐 가능 |
| XMEM-003 Executable Memory Without Backing Module | executable 영역이 로드된 모듈 [base, base+size) 밖 | Medium | Medium | JIT 정상 사례 존재 |
| XMEM-004 Suspicious Thread Start Address | start address가 private executable 영역 또는 모듈 밖 | High | Medium | 스레드 종료/조회 실패 시 skip |
| XMEM-005 Memory Protection Anomaly | RWX/EXECUTE_WRITECOPY (private=Medium→High, image=Low) | Medium | High | 사실 기반 |

Rule은 `xmem-detection`에만 존재하며 CLI에 하드코딩하지 않는다.

## 10. Experiment Framework (M11 구현 예정)

- `xmem experiment run <NAME>`은 **XMem이 직접 spawn한 `xmem-target`에만** 실험한다. 임의 PID 실험은 v1에서 지원하지 않는다.
- Target 검증: spawn 직후 image path + 생성 시각 + PID를 기록하고 실험 내내 신원을 재검증한다(PID 재사용 방지).
- Guard: `System, Registry, smss, csrss, wininit, services, lsass, svchost, winlogon, dwm, explorer` 는 이름 단독이 아니라 (이름 + 경로 + 세션 + PID) 조합으로 평가하고, 변경 작업을 거부한다. read-only 분석은 허용한다.
- Cleanup: Ctrl+C/패닉 시에도 XMem이 만든 child만 종료한다. 임시 리소스 제거.
- 실험 정의: Name, Description, Target Requirements, Baseline, Action, Expected Artifacts, Cleanup.

## 11. Windows API 계획

| M | API | 비고 |
|---|---|---|
| M2 | `CreateToolhelp32Snapshot`, `Process32FirstW/NextW`, `OpenProcess`, `QueryFullProcessImageNameW`, `GetProcessTimes`, `IsWow64Process2`, `ProcessIdToSessionId`, `GetProcessMemoryInfo`, `OpenProcessToken`+`GetTokenInformation(TokenUser)`+`LookupAccountSidW`, `NtQueryInformationProcess`+PEB read (CommandLine) | 서명은 구현 시 windows-rs 문서로 검증. PEB는 WOW64/보호 프로세스에서 실패 가능 → `None` degrade |
| M3 | `VirtualQueryEx` (주소 전진 루프, `ERROR_INVALID_PARAMETER`로 종료), `GetNativeSystemInfo`, `GetMappedFileNameW` | region 상태 변화/레이스는 정상 경로로 처리 |
| M4 | `ReadProcessMemory` chunked(기본 1 MiB) | `ERROR_PARTIAL_COPY(299)`, `ERROR_ACCESS_DENIED(5)`, `ERROR_NOACCESS(998)` 매핑 |
| M5 | `TH32CS_SNAPMODULE(_32)`, `Module32FirstW/NextW`, `EnumProcessModulesEx`(fallback), `Thread32First/Next`, `OpenThread`, `GetThreadTimes`, `GetThreadPriority`, `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` | StartAddress는 반문서화 → 실패 시 skip |
| M6 | 신규 없음 | goblin + 메모리 헤더 read |
| M7 | 신규 없음 | 파일 I/O |
| M9 | `MiniDumpWriteDump`(dbghelp) | 기본은 metadata dump, `--full`은 사전 크기/디스크 검사 후 |
| M11 | `VirtualAllocEx`, `VirtualProtectEx`, `WriteProcessMemory`, `CreateRemoteThread`, `FlushInstructionCache` | **xmem-experiments 전용, lab target 한정** |

## 12. CLI 계약

```text
전역 플래그: --json, -v/-q, --no-color  (--threads N은 M4에서 추가)
exit code:  0 정상 / 1 오류 / 2 사용법 오류(clap) / 3 정책 거부(보호 프로세스)
stdout: 사용자 출력(사람용 또는 --json)  /  stderr: tracing 로그
```

```text
xmem process list | info --pid <PID>
xmem memory map --pid <PID> | scan --pid <PID>
xmem modules --pid <PID> | threads --pid <PID>
xmem snapshot create --pid <PID> --output <FILE> | snapshot diff <A> <B>
xmem dump create --pid <PID> --output <FILE> | dump analyze <FILE>
xmem detect --pid <PID> | report --pid <PID> --output <FILE>
xmem experiment list | run <NAME>
```

## 13. Safety / Host Stability

- **Read-only 기본**: 분석 명령은 대상 프로세스 상태를 절대 변경하지 않는다(스레드 suspend/resume 포함 금지).
- **실험 격리**: 변경 API는 XMem이 spawn한 `xmem-target`에만 사용한다. 임의 PID 실험 금지.
- **자원 상한**: scan worker `min(논리CPU-1, 4)`(최소 1), chunk 1 MiB(4 KiB~16 MiB), region당 기본 상한 64 MiB(`--max-region-size`), 무제한 `Vec` 누적 금지, bounded buffer 재사용.
- **스캔 우선순위**: Executable → Private Executable → Writable → 기타. committed > 4 GiB 프로세스는 기본적으로 executable+private만(`--all`로 확장).
- **자원 모니터링**: bytes/regions scanned/skipped, read failures, elapsed, peak RSS를 요약 출력.
- **Disk 보호**: snapshot/dump 생성 전 예상 크기 계산 + 여유 공간 확인, 부족 시 거부. temp → validate → atomic rename.
- **Ctrl+C**: cooperative cancel(atomic flag) → handle/임시파일 정리 → XMem이 만든 프로세스만 종료.
- **정책 거부(exit 3)**: 보호 프로세스에 대한 변경 작업 거부.

## 14. Status

| 컴포넌트 | 상태 |
|---|---|
| M1 기반 구조(workspace/core/windows/cli) | Done |
| M2 Process(`process list`/`process info`) | Done |
| M3~M12 | Planned |

## 15. Non-Goals

- Kernel driver, physical memory, DMA, MSR, kernel patching/modification
- 비동기 런타임, GUI, 네트워크 기능
- 탐지를 악성 확정으로 표현하는 것

## 16. Risk Register

| Risk | 영향 | 대응 |
|---|---|---|
| 비관리자 권한으로 타 프로세스 조회 제한 | 일부 필드 `None` | degrade, 정상 경로 처리, README 명시 |
| WOW64/보호 프로세스 PEB·CommandLine 실패 | 메타 누락 | `None` + reason, 크래시 금지 |
| `NtQueryInformationThread` 반문서화 | StartAddress 누락 | 서명 문서 검증, 실패 skip |
| Defender가 RWX/CreateRemoteThread 실험을 탐지 | 실험 실패/오탐 | lab target 한정, 로컬 제외는 문서 안내만(자동 변경 금지) |
| 대형 프로세스 스캔 자원 폭주 | 호스트 부하 | 필터/상한/카운터, worker 제한 |
| 스냅샷 포맷 드리프트 | offline 분석 불가 | format_version + schema_version + roundtrip 테스트 |
| PID 재사용으로 다른 프로세스 실험 | 호스트 안정성 | spawn 시각+경로 재검증 |
| 메인 노트북 직접 개발 | 호스트 안정성 | read-only 기본 + lab target 격리, VM 권장 문서화 |

## 17. Testing 전략

- **Unit**: pattern parser/matcher, protection 디코드, region 분류, PE 파서(합성 버퍼), snapshot roundtrip, diff(합성 snapshot), rule, guard, PEB 오프셋 계산.
- **Integration (lab)**: `xmem-target` spawn → CLI `--json` → 절대 주소 비의존 단언(분류/플래그/관계).
- **Fixture 모드**: `normal / executable-private / pe-memory / thread-anomaly / memory-protection`.
- 관리자 권한 필요 테스트는 `#[ignore]`로 분리.
- 완료 기준: `cargo fmt` + `cargo check` + `cargo test` + `cargo clippy -D warnings` + 실제 Windows 실행 검증(실패 경로, 반복 실행, Ctrl+C 포함).
