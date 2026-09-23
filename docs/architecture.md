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
| `xmem-core` | 데이터 모델, 에러, Evidence/Finding, Guard, MemorySource trait, Pattern 파서/매처, 버전 상수 | M1 |
| `xmem-windows` | Win32 FFI, RAII Handle, Win32→XmemError 매핑 | M1 |
| `xmem-cli` | clap 트리, human/JSON 출력, exit code | M1 |
| `xmem-memory` | region 분류, MemorySource 구현(LiveProcess), chunked 병렬 scanner, 모듈/스레드 상관관계 | M3 (생성됨; scan 엔진 M4, 모듈/스레드 M5) |
| `xmem-pe` | PE 파싱(bounds-checked 헤더 파서 + 전체 파일 goblin 보강), 메모리 PE artifact 분류 | M6 (생성됨) |
| `xmem-forensics` | Snapshot 포맷/직렬화, SnapshotSource, collect(해싱), Diff, Minidump 분석(MinidumpSource), Report(JSON/Markdown), MemoryImage 소스 | M7 (생성됨; Minidump M9, Report M12, MemoryImage는 후속) |
| `xmem-detection` | Rule trait + 초기 Rule(XMEM-001~005) | M8 (생성됨) |
| `xmem-experiments` | Experiment Framework(TargetGuard + 4개 실험 + 파이프라인). 변경 Win32 API 호출은 여기서만, lab target 한정 | M11 (생성됨) |
| `lab/targets/xmem-target` | 결정적 Test Target (bin crate, workspace member): 자기 프로세스 한정 메모리 아티팩트, Ground Truth JSON report. `xmem-windows`만 의존 | M10 (생성됨) |
| `xmem-gui` | egui 단일 exe 데스크톱 GUI: CLI와 동일한 crate를 직접 호출(IPC 없음), 분석 탭 + **맵/모듈/스레드 상세 패널**(v0.1.2) + 가이드 + 로그 패널. 실험은 제외(CLI 전용). `unsafe` 금지 | M13 (생성됨; 상세 패널 v0.1.2) |

## 4. Dependency 정책

| Crate | 도입 | 용도 | 비고 |
|---|---|---|---|
| `windows` 0.62.x | M1 | Win32 FFI | crate별 최소 feature만. 버전 pin |
| `clap` 4 (derive) | M1 | CLI | |
| `serde` / `serde_json` | M1 | JSON 계약 | 외부 포맷 = 직렬화 구조체 (schema_version envelope) |
| `thiserror` 2 | M1 | 에러 enum | |
| `anyhow` | M1 | CLI/experiments 전용 | 라이브러리 금지 |
| `tracing` / `tracing-subscriber` | M1 | stderr 진단 로그 | stdout은 사용자 출력 전용 |
| `chrono` | M2 | CLI 타임스탬프 표시 | M7에서 features `std,serde,clock`으로 확장(Snapshot timestamp 직렬화) |
| `uuid` | — | ID | 미도입: 스냅샷 식별은 파일명+타임스탬프로 충분, 필요 시 도입 |
| `rayon` 1 | M4 | region 단위 bounded 병렬 스캔 | 도입됨(M4). thread pool 크기 고정 |
| `ctrlc` 3 | M4 | Ctrl+C cooperative cancel | 도입됨(M4) |
| `goblin` 0.10 | M6 | PE 파싱(전체 파일일 때 imports/exports/relocations/TLS 보강) | `default-features = false`, features `std,pe32,pe64`. 헤더 prefix는 bounds-checked 수동 파서 사용(프리픽스에서 goblin은 하드 에러) |
| `blake3` | M7 | region 내용 해시 | 도입됨(M7) |
| `minidump` 0.27 | M9 | dump analyze 파싱(SystemInfo/Module/Thread/MemoryInfo/Misc 스트림, 메모리 범위) | 도입됨(M9). `MinidumpMemoryInfoList::iter()`는 `&MinidumpMemoryInfo`를 반환(주의). memmap2는 이 crate의 전이 의존으로 들어옴 |
| `memmap2` | M9+ | MemoryImage 소스 | 필요 시점 도입 |
| `eframe` / `egui` / `egui_extras` 0.36.2 | M13 | GUI(창/위젯/표) | `xmem-gui` 전용. 0.36은 `eframe::App::ui(&mut Ui, ...)`(구 `update` 없음), `egui::Panel` 통합 API |
| `rfd` 0.17.2 | M13 | 네이티브 파일 대화상자 | `xmem-gui` 전용 |

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
    pub allocation_base: Option<u64>,          // VirtualQueryEx AllocationBase (v0.1.2)
    pub state: MemoryState,                    // Commit | Reserve | Free
    pub protection: Protection,                // 사람이 읽는 형태 + 플래그
    pub allocation_protection: Option<Protection>,
    pub region_type: Option<MemoryType>,       // Image | Mapped | Private; Free/Reserve는 None
    pub readable: bool, pub writable: bool, pub executable: bool,
    pub classification: RegionClass,           // Image | Mapped | Private | Free | Reserved | Unknown
    pub heuristics: Vec<Heuristic>,
    pub mapped_file: Option<String>,           // GetMappedFileNameW 결과(M3+)
}
```

`Protection`은 raw `u32` 위에 읽기/쓰기/실행 플래그와 `Display`("RWX" 등)를 제공하는 뉴타입이다. raw flag만 출력하지 않는다.

`allocation_base`는 `#[serde(default)]`로 추가되어(M12 이전 스냅샷과 호환) `memory map`의 ALLOC 컬럼과 GUI 영역 상세 패널에서 할당 시작 주소·할당 내 오프셋 표시에 사용된다. PE 분석(M6)은 `xmem-pe`의 `PeInfo`/`PeSection`/`MemoryPeClass`를 사용한다. `parse_pe`는 헤더를 bounds-checked로 먼저 파싱하고(4 KiB 프리픽스에서도 유효), 전체 파일이면 goblin으로 imports/exports/relocations/TLS를 보강한다. `PeInfo.time_date_stamp`(COFF 타임스탬프)와 디스크 파일 전체 파싱 `parse_pe_file(path)`(64 MiB 상한, `MAX_FILE_PARSE_BYTES`)가 v0.1.2에서 추가되어 GUI 모듈 상세 패널이 디스크 PE(imports/exports/relocations/TLS/컴파일 시각)와 메모리 헤더를 비교해 보여준다. `MemoryPeClass`(None/NormalLoadedModule/MappedImage/PrivatePeLike/Malformed/Unknown)는 region 분류와 헤더 바이트로 결정되며, private executable 영역 프로브 결과가 `private_executable_pe_like`/`executable_anonymous` heuristic으로 반영된다. GUI 스레드 상세 패널은 `xmem-windows::threads::thread_times`(`GetThreadTimes` → `ThreadTimes{creation, exit, kernel_100ns, user_100ns}`)를 사용한다.

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

구현: `LiveProcess`(xmem-memory, M3), `Snapshot`(xmem-forensics, M7), `Minidump`(xmem-forensics, M9), `MemoryImage`(후속).

Minidump 소스(M9 구현됨): `MinidumpSource`가 `MemorySource`를 구현하므로 `detect_source` 등 상위 계층이 라이브 프로세스와 동일하게 동작한다(Offline Forensics). `MinidumpSource::open`이 minidump 스트림(SystemInfo/ModuleList/ThreadList/MemoryInfoList/MiscInfo)과 메모리 범위를 1회 파싱해 보관하고, `read`는 메모리 범위를 선형 탐색한다(범위 밖 → `InvalidAddress`, 메모리 스트림 없음 → `DumpError`). minidump에는 thread start address가 없어 `ThreadInfo.start_address`는 `None`이다(XMEM-004는 침묵). `mapped_file`은 모듈 목록 기반 근사다. 파일 생성(`xmem-windows::write_minidump_file`)은 temp → `MDMP` 시그니처 검증 → atomic rename이며 실패 시 temp를 제거한다.

## 8. Snapshot 포맷 v1 (M7 구현됨)

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

pub struct RegionHash { base, size, bytes_hashed, hash, partial }
pub struct AcquisitionMeta {
    source, pid, hashed_regions, hashed_bytes,
    hash_budget_bytes, read_failures, region_truncated,
}
```

- 쓰기: 임시파일 → 검증(재파싱 + 길이 확인) → atomic rename. 불완전 파일을 정상 Snapshot으로 남기지 않는다.
- `format_version`으로 migration 지점을 명시한다.
- 해싱 정책(M7): committed + readable 영역만, executable → private 우선 정렬, `hash_budget_bytes`(기본 64 MiB)·`MAX_HASH_REGIONS`(8192) 상한, 1 MiB chunk 재사용 버퍼. 예산/읽기 실패로 일부만 해싱한 영역은 `partial: true`로 정직하게 보고한다.
- Diff(M7): region은 base, module은 name, thread는 tid, content hash는 base로 매칭. 양쪽 해시가 모두 있는 영역만 content 변화로 보고. findings diff(Detection Appeared/Disappeared/Changed)는 M8에서 추가됨(`detections_added`/`detections_removed`/`detections_changed`, 매칭 키 = rule_id + region_base + address).

## 9. Detection Rules (M8 구현됨)

| Rule | 조건(관찰) | Severity | Confidence | 비고 |
|---|---|---|---|---|
| XMEM-001 Executable Private Memory | committed + MEM_PRIVATE + executable(X/RWX/WCX) | Medium | High | 사실 기반 |
| XMEM-002 PE Header in Private Executable Region | XMEM-001 영역에서 `MZ` + (범위 내) `PE\0\0` | High | Medium | JIT/데이터 오탐 가능 |
| XMEM-003 Executable Memory Without Backing Module | executable + 모듈 범위 밖 + 백킹 없음(`mapped_file` basename이 모듈명과 일치하거나 `MEM_IMAGE`면 제외, private은 001/002 담당) | Medium(`MEM_MAPPED` 무파일) / Low(file-mapped) | Low | v0.1.1 백킹 판정 |
| XMEM-004 Suspicious Thread Start Address | start address가 private executable 영역 또는 모듈 밖 | High | Medium | 스레드 종료/조회 실패 시 skip |
| XMEM-005 Memory Protection Anomaly | RWX/EXECUTE_WRITECOPY (private=Medium→High, image=Low) | Medium | High | 사실 기반 |

Rule은 `xmem-detection`에만 존재하며 CLI에 하드코딩하지 않는다.

구현 노트(M8): `xmem-detection`은 `xmem-core`에만 의존하고(외부 dependency 추가 없음), `DetectionContext`로 수집된 관찰 데이터만 받아 평가한다. XMEM-001/002/005는 heuristic/보호 속성만으로 동작하고, XMEM-003/004는 모듈 목록이 비어 있으면 침묵한다(불완전 데이터로 오판하지 않음). XMEM-003은 v0.1.1부터 백킹 판정(`mapped_file` basename ↔ 모듈명, `MEM_IMAGE`, private 제외)을 적용하고 남은 `MEM_MAPPED` 무파일 영역만 Low confidence로 보고한다. findings는 (rule_id, region_base, address)로 정렬해 결정적으로 출력한다. Snapshot `collect`는 findings를 저장하고, `xmem-forensics`가 `xmem-detection`에 의존한다.

## 10. Experiment Framework (M11 구현됨)

- `xmem experiment run <NAME>`은 **XMem이 직접 spawn한 `xmem-target`에만** 실험한다. 임의 PID 실험은 v1에서 지원하지 않는다.
- Target 검증: spawn 직후 image path + 생성 시각 + PID를 기록하고 실험 내내 신원을 재검증한다(PID 재사용 방지).
- Guard: `System, Registry, smss, csrss, wininit, services, lsass, svchost, winlogon, dwm, explorer` 는 이름 단독이 아니라 (이름 + 경로 + 세션 + PID) 조합으로 평가하고, 변경 작업을 거부한다. read-only 분석은 허용한다.
- Cleanup: Ctrl+C/패닉 시에도 XMem이 만든 child만 종료한다. 임시 리소스 제거.
- 실험 정의: Name, Description, Target Requirements, Baseline, Action, Expected Artifacts, Cleanup.

구현 노트(M11): `TargetGuard`가 `xmem-target run <scenario> --hold-secs N --report <FILE>`를 spawn하고 report의 pid가 child pid와 일치할 때까지 폴링한다. spawn 직후 image path가 `xmem-target.exe`인지 확인하고 `xmem_core::guard::check_state_change`로 보호 정책을 재검증하며, 실패 시 child를 종료하고 임시 파일을 제거한다. 파이프라인은 `xmem-forensics::collect`/`diff`와 `xmem-detection`을 그대로 재사용하고, 판정은 `expected_observed`(post findings 중 기대 rule + 기대 영역)로 한다. 테스트는 `RunOptions::target_binary`로 바이너리를 지정한다(환경 변수 조작 회피).

## 11. Windows API 계획

| M | API | 비고 |
|---|---|---|
| M2 | `CreateToolhelp32Snapshot`, `Process32FirstW/NextW`, `OpenProcess`, `QueryFullProcessImageNameW`, `GetProcessTimes`, `IsWow64Process2`, `ProcessIdToSessionId`, `GetProcessMemoryInfo`, `OpenProcessToken`+`GetTokenInformation(TokenUser)`+`LookupAccountSidW`, `NtQueryInformationProcess`+PEB read (CommandLine) | 서명은 구현 시 windows-rs 문서로 검증. PEB는 WOW64/보호 프로세스에서 실패 가능 → `None` degrade |
| M3 | `VirtualQueryEx` (주소 전진 루프, `ERROR_INVALID_PARAMETER`로 종료), `GetNativeSystemInfo`, `GetMappedFileNameW` | 구현됨(`xmem-windows` feature `Win32_System_Memory`). region 상태 변화/레이스는 정상 경로로 처리 |
| M4 | `ReadProcessMemory` chunked(기본 1 MiB) | 구현됨(`xmem-windows` feature `Win32_System_Diagnostics_Debug`). `ERROR_PARTIAL_COPY(299)`→PartialRead, `ERROR_ACCESS_DENIED(5)`, `ERROR_NOACCESS(998)`/`ERROR_INVALID_ADDRESS(487)` 매핑 |
| M5 | `TH32CS_SNAPMODULE(_32)`, `Module32FirstW/NextW`, `Thread32First/Next`, `OpenThread`, `GetThreadPriority`, `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` | 구현됨. StartAddress는 반문서화 → 실패 시 `None` degrade. `GetThreadTimes`/`EnumProcessModulesEx` fallback은 후속 |
| M6 | 신규 없음 | 기존 `ReadProcessMemory` 재사용(영역/모듈 헤더 prefix 4 KiB). 파싱 실패는 `InvalidPe`/`None` degrade |
| M7 | `GetDiskFreeSpaceExW` (feature `Win32_Storage_FileSystem`) | 구현됨. snapshot 생성 전 예상 크기 + 16 MiB 여유 검사 |
| M9 | `MiniDumpWriteDump`(dbghelp), `CreateFileW` (feature `Win32_System_Kernel` 추가) | 구현됨. 기본 `MiniDumpNormal \| MiniDumpWithFullMemoryInfo`, `--full`은 `MiniDumpWithFullMemory \| FullMemoryInfo` + commit 바이트·16 MiB 디스크 사전 검사. temp → `MDMP` 검증 → atomic rename |
| M10 | `VirtualAlloc`, `VirtualProtect`, `VirtualFree`, `CreateThread`, `GetThreadId` | 구현됨(`xmem-windows::selfmem`). lab target 전용, 자기 프로세스 한정. 외부 프로세스 조작(`VirtualAllocEx` 등)은 M11 `xmem-experiments` |
| M11 | `VirtualAllocEx`, `VirtualProtectEx`, `WriteProcessMemory`, `CreateRemoteThread`, `FlushInstructionCache` | 구현됨(`xmem-windows::remotemem` + `threads::create_remote_thread`). 호출은 `xmem-experiments`만, lab target 한정 |
| M13 | `ShellExecuteW`(`runas`), `OpenProcessToken`+`GetTokenInformation(TokenElevation)` (feature `Win32_UI_Shell`/`Win32_UI_WindowsAndMessaging` 추가) | 구현됨(`xmem-windows::elevate`). GUI는 시작 시 runas로 자신을 재실행(`--pid`·`--elevated` 유지), UAC 취소 시 표준 권한으로 계속. 아이콘은 build.rs에서 rc.exe로 리소스 컴파일(`-bins` 한정) |
| v0.1.2 | `GetThreadTimes` (기존 feature), `VirtualQueryEx`의 `AllocationBase` 노출 | 구현됨(`xmem-windows::threads::thread_times` → `ThreadTimes`; `MemoryRegion.allocation_base`). GUI 스레드/영역 상세 패널에서 사용 |

## 12. CLI 계약

```text
전역 플래그: --json, -v/-q, --no-color  (memory scan: --threads N)
exit code:  0 정상 / 1 오류 / 2 사용법 오류(clap) / 3 정책 거부(보호 프로세스) / 130 취소(Ctrl+C)
stdout: 사용자 출력(사람용 또는 --json)  /  stderr: tracing 로그
```

```text
xmem process list | info --pid <PID>
xmem memory map --pid <PID> | scan --pid <PID>
xmem modules --pid <PID> | threads --pid <PID>
xmem snapshot create --pid <PID> --output <FILE> | snapshot diff <A> <B>
xmem dump create --pid <PID> --output <FILE> [--full] | dump analyze <FILE>
xmem detect --pid <PID> | report --pid <PID> --output <FILE>
xmem experiment list | run <NAME>
```

## 13. Safety / Host Stability

- **Read-only 기본**: 분석 명령은 대상 프로세스 상태를 절대 변경하지 않는다(스레드 suspend/resume 포함 금지).
- **실험 격리**: 변경 API는 XMem이 spawn한 `xmem-target`에만 사용한다. 임의 PID 실험 금지.
- **자원 상한**: scan worker `min(논리CPU-1, 4)`(최소 1), chunk 1 MiB(4 KiB~16 MiB), `--max-region-size`(기본 없음), 무제한 `Vec` 누적 금지, bounded buffer 재사용.
- **스캔 우선순위**: Executable → Private Executable → Writable → 기타. committed > 4 GiB 프로세스는 기본적으로 executable+private만(`--all`로 확장).
- **자원 모니터링**: bytes/regions scanned/skipped, read failures, partial reads, elapsed, XMem 자신의 RSS(작업 집합) 요약 출력(`rss_bytes`, M12 구현; peak 샘플링은 후속).
- **Disk 보호**: snapshot/dump 생성 전 예상 크기 계산 + 여유 공간 확인, 부족 시 거부. temp → validate → atomic rename.
- **Ctrl+C**: cooperative cancel(atomic flag) → handle/임시파일 정리 → XMem이 만든 프로세스만 종료.
- **정책 거부(exit 3)**: 보호 프로세스에 대한 변경 작업 거부.

## 14. Status

| 컴포넌트 | 상태 |
|---|---|
| M1 기반 구조(workspace/core/windows/cli) | Done |
| M2 Process(`process list`/`process info`) | Done |
| M3 Virtual Memory(`memory map`, `LiveProcess` MemorySource) | Done |
| M4 Memory Scanner(`memory scan`, Pattern 파서/매처, chunked 병렬 scan, Ctrl+C) | Done |
| M5 Module / Thread(`modules`/`threads`, 시작 주소 → region/module 상관관계) | Done |
| M6 PE Analysis(`xmem-pe` 파서/메모리 PE 분류, `modules --pe`, heuristic 활성화) | Done |
| M7 Snapshot(`xmem-forensics` 포맷 v1, `snapshot create`/`snapshot diff`, collect 해싱, Disk 사전 검사) | Done |
| M8 Detection(`xmem-detection` Rule 엔진, XMEM-001~005, `detect`, Snapshot findings/detection diff) | Done |
| M9 Minidump(`dump create`/`dump analyze`, `MinidumpSource` MemorySource, 오프라인 Detection) | Done |
| M10 Research Lab(`lab/targets/xmem-target` deterministic 시나리오, Ground Truth 회귀 테스트, `xmem-windows::selfmem`) | Done |
| M11 Experiment Automation(`xmem-experiments` TargetGuard/4개 실험/파이프라인, `experiment list`/`experiment run`, e2e 검증) | Done |
| M12 완성도(`report` JSON/Markdown, `ScanStats.rss_bytes`, 문서 6종, UX) | Done |
| M13 GUI(`xmem-gui` egui 단일 exe, 분석 탭 전체, 관리자 재시작, 가이드, 로그 패널, 다크/라이트) | Done |
| v0.1.2 상세 뷰어(`MemoryRegion.allocation_base`, `PeInfo.time_date_stamp`+`parse_pe_file`, `thread_times`, ALLOC 컬럼, GUI 맵/모듈/스레드 상세 패널, `error_label`) | Done |
| 이후 | 계획 없음 (v0.1.2까지 완료) |

## 15. Non-Goals

- Kernel driver, physical memory, DMA, MSR, kernel patching/modification
- 비동기 런타임, 네트워크 기능
- GUI에서의 Experiment 실행(실험은 CLI 전용 유지)
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
