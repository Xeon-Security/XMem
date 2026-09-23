# M9 Minidump 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** `xmem dump create --pid <PID> --output <FILE> [--full]`와 `xmem dump analyze <FILE>`를 구현한다. 덤프는 Win32 `MiniDumpWriteDump`로 생성하고, 분석은 `minidump` crate로 파싱해 기존 Detection/Evidence 파이프라인을 그대로 재사용한다.

**Architecture:** Win32 primitive는 `xmem-windows`(dump.rs)에만 둔다. 파싱/분석과 `MemorySource` 구현은 `xmem-forensics`(dump.rs)에 두고, CLI는 오케스트레이션과 렌더링만 담당한다. `MinidumpSource`가 `MemorySource`를 구현하므로 `detect_source`가 라이브 프로세스와 동일하게 동작한다(Offline Forensics).

**Tech Stack:** Rust stable, windows 0.62(`MiniDumpWriteDump`, `CreateFileW`), minidump 0.27(파싱), 기존 xmem-core/detection/forensics/cli 재사용.

**Spec:** `docs/architecture.md` §10(Minidump), §17(MemorySource), §14(Windows API 계획 M9), §7(CLI 계약)

## Global Constraints

- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.
- `unsafe`는 `xmem-windows`에만(`#![allow(unsafe_code)]`), 다른 crate는 금지. runtime `unwrap()`/`expect()` 금지(테스트는 `#![cfg_attr(test, allow(...))]`).
- Windows API 시그니처는 추측하지 않는다. 아래 코드는 레지스트리 소스(windows-0.62.2)에서 검증된 것이다.
- 오류는 `XmemError` 구조화 variant로. `DumpError{reason}` 사용. anyhow는 CLI에서만.
- read-only 원칙: 덤프 생성은 대상 프로세스를 변경하지 않는다. `MiniDumpWriteDump` 외 쓰기 API 금지.
- 파일 생성은 temp → 검증(시그니처) → atomic rename. 실패 시 temp 제거(불완전 덤프를 정상 파일로 남기지 않는다).
- 디스크 사전 검사: 생성 전 `free_space_bytes`로 필요량 + 16 MiB 여유 확인. `--full`은 필요량 = commit 바이트.
- CLI exit code: 성공 0, 실패 1, 사용법 2, 정책 거부 3, 취소 130.
- 문서·커밋 메시지는 한국어. 커밋 prefix feat/fix/docs/style/refactor/test/chore.
- `--full`은 진행 중 취소를 지원하지 않는다(콜백 미구현) — Limitations에 명시한다.

## Review Focus

1. **불완전 덤프 금지**: 생성 실패/검증 실패 시 temp 파일이 남지 않고, 대상 경로에 잘린 파일이 생기지 않는다.
2. **비정상 파일 내성**: minidump가 아닌 파일·잘린 파일·0바이트 파일을 analyze해도 panic 없이 구조화 `DumpError`가 나온다.
3. **정직한 오프라인 한계**: minidump에는 thread start address가 없다 → XMEM-004는 침묵해야 하고, mapped file 이름도 module 목록 기반 근사임을 문서화한다.
4. **디스크 보호**: `--full`이 commit 바이트 + 16 MiB 여유보다 큰 파일을 만들 상황이면 작업을 거부한다.
5. **메모리 스트림 부재 내성**: `MiniDumpNormal` 덤프에서도 regions(MemoryInfoList)가 나오고, memory 스트림이 없으면 `read`가 panic 대신 오류를 반환한다.

---

### Task 1: xmem-windows — MiniDumpWriteDump와 덤프 파일 생성

**Files:**
- Modify: `crates/xmem-windows/Cargo.toml` (feature `Win32_System_Kernel` 추가)
- Modify: `crates/xmem-windows/src/process.rs` (`open_for_dump` 추가)
- Create: `crates/xmem-windows/src/dump.rs`
- Modify: `crates/xmem-windows/src/lib.rs` (모듈·재수출)
- Test: 각 파일 내 `#[cfg(test)]` 모듈

**Interfaces:**
- Consumes: `OwnedHandle`(handle.rs), `error_from_win32`(error.rs), `open_process`(process.rs), `current_pid`.
- Produces (Task 3이 사용):
  - `open_for_dump(pid: u32) -> Result<OwnedHandle>`
  - `create_file_for_write(path: &str) -> Result<OwnedHandle>`
  - `write_minidump(process: &OwnedHandle, pid: u32, file: &OwnedHandle, full: bool) -> Result<()>`
  - `validate_minidump(path: &Path) -> Result<()>`
  - `write_minidump_file(process: &OwnedHandle, pid: u32, path: &Path, full: bool) -> Result<u64>`

검증된 시그니처(windows-0.62.2 레지스트리 소스):
- `MiniDumpWriteDump(hprocess: HANDLE, processid: u32, hfile: HANDLE, dumptype: MINIDUMP_TYPE, exceptionparam: Option<*const MINIDUMP_EXCEPTION_INFORMATION>, userstreamparam: Option<*const MINIDUMP_USER_STREAM_INFORMATION>, callbackparam: Option<*const MINIDUMP_CALLBACK_INFORMATION>) -> windows_core::Result<()>` — cfg gate: `Win32_Storage_FileSystem` + `Win32_System_Kernel` + `Win32_System_Memory` feature 필요.
- `MINIDUMP_TYPE(pub i32)` + `BitOr`; `MiniDumpNormal = 0`, `MiniDumpWithFullMemory = 2`, `MiniDumpWithFullMemoryInfo = 2048`.
- `CreateFileW<P0: Param<PCWSTR>>(lpfilename: P0, dwdesiredaccess: u32, dwsharemode: FILE_SHARE_MODE, lpsecurityattributes: Option<*const SECURITY_ATTRIBUTES>, dwcreationdisposition: FILE_CREATION_DISPOSITION, dwflagsandattributes: FILE_FLAGS_AND_ATTRIBUTES, htemplatefile: Option<HANDLE>) -> Result<HANDLE>`; `CREATE_ALWAYS = FILE_CREATION_DISPOSITION(2)`, `FILE_ATTRIBUTE_NORMAL = FILE_FLAGS_AND_ATTRIBUTES(128)`, `FILE_SHARE_READ = FILE_SHARE_MODE(1)`, `FILE_SHARE_WRITE = FILE_SHARE_MODE(2)`, `GENERIC_WRITE = GENERIC_ACCESS_RIGHTS(1073741824)`(Win32::Foundation).

- [x] **Step 1: 실패하는 테스트 작성 (process.rs)**

`crates/xmem-windows/src/process.rs` 테스트 모듈에 추가:

```rust
#[test]
fn open_for_dump_self_succeeds() {
    let handle = open_for_dump(current_pid()).expect("open_for_dump");
    assert!(!handle.raw().is_invalid());
}
```

import에 `open_for_dump` 추가(같은 파일이므로 불필요). `use` 라인은 기존 테스트 모듈 참고.

- [x] **Step 2: 실패 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `cannot find function open_for_dump`

- [x] **Step 3: open_for_dump 구현 (process.rs)**

`open_for_read` 아래에 추가:

```rust
/// 덤프 생성용 핸들(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ).
/// QUERY_INFORMATION이 거부되면 QUERY_LIMITED로 재시도한다(제한 덤프만 가능할 수 있음).
pub fn open_for_dump(pid: u32) -> Result<OwnedHandle> {
    match open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) {
        Ok(handle) => Ok(handle),
        Err(XmemError::AccessDenied { .. }) => {
            open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
        }
        Err(e) => Err(e),
    }
}
```

import에 `PROCESS_QUERY_INFORMATION`이 이미 있는지 확인(없으면 추가).

- [x] **Step 4: 실패하는 테스트 작성 (dump.rs)**

`crates/xmem-windows/src/dump.rs` 생성:

```rust
//! MiniDumpWriteDump 기반 덤프 파일 생성.

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::GENERIC_WRITE;
use windows::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Diagnostics::Debug::{
    MINIDUMP_TYPE, MiniDumpNormal, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
    MiniDumpWriteDump,
};
use windows::core::HSTRING;
use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{current_pid, open_for_dump};

    #[test]
    fn write_minidump_file_of_self_is_valid() {
        let dir = std::env::temp_dir().join(format!("xmem-dump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.dmp");
        let pid = current_pid();
        let handle = open_for_dump(pid).unwrap();

        let size = write_minidump_file(&handle, pid, &path, false).unwrap();
        assert!(size > 0);
        validate_minidump(&path).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp 파일이 남았다");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_minidump_rejects_non_dump() {
        let dir = std::env::temp_dir().join(format!("xmem-dump-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.dmp");
        std::fs::write(&path, b"not a minidump").unwrap();

        let err = validate_minidump(&path).unwrap_err();
        assert!(matches!(err, XmemError::DumpError { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [x] **Step 5: 실패 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `cannot find function write_minidump_file`, `validate_minidump` (E0425) 및 import 오류

- [x] **Step 6: dump.rs 구현**

테스트 모듈 위에 추가:

```rust
/// 쓰기용 파일 핸들 생성(없으면 만들고, 있으면 덮어쓴다).
pub fn create_file_for_write(path: &str) -> Result<OwnedHandle> {
    let wide = HSTRING::from(path);
    let handle = unsafe {
        CreateFileW(
            &wide,
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| error_from_win32("CreateFileW", &e))?;
    OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 })
}

/// MiniDumpWriteDump 호출. `full`이면 전체 메모리를 포함한다.
pub fn write_minidump(process: &OwnedHandle, pid: u32, file: &OwnedHandle, full: bool) -> Result<()> {
    let dump_type: MINIDUMP_TYPE = if full {
        MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo
    } else {
        MiniDumpNormal | MiniDumpWithFullMemoryInfo
    };
    unsafe { MiniDumpWriteDump(process.raw(), pid, file.raw(), dump_type, None, None, None) }
        .map_err(|e| error_from_win32("MiniDumpWriteDump", &e))
}

/// minidump 시그니처("MDMP")를 확인한다.
pub fn validate_minidump(path: &Path) -> Result<()> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(XmemError::Io)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| XmemError::DumpError {
        reason: format!("dump 헤더 읽기 실패: {} ({e})", path.display()),
    })?;
    if &magic != b"MDMP" {
        return Err(XmemError::DumpError {
            reason: format!("minidump 시그니처가 아님: {}", path.display()),
        });
    }
    Ok(())
}

fn temp_path(path: &Path, pid: u32) -> PathBuf {
    PathBuf::from(format!("{}.tmp-{}", path.display(), pid))
}

/// temp 파일에 덤프를 쓰고 시그니처 검증 후 atomic rename. 생성된 파일 크기를 반환한다.
pub fn write_minidump_file(
    process: &OwnedHandle,
    pid: u32,
    path: &Path,
    full: bool,
) -> Result<u64> {
    let temp = temp_path(path, pid);
    let result = (|| -> Result<u64> {
        let file = create_file_for_write(&temp.to_string_lossy())?;
        write_minidump(process, pid, &file, full)?;
        drop(file);
        validate_minidump(&temp)?;
        std::fs::rename(&temp, path).map_err(|e| XmemError::DumpError {
            reason: format!("dump rename 실패: {} ({e})", path.display()),
        })?;
        let size = std::fs::metadata(path).map_err(XmemError::Io)?.len();
        Ok(size)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
```

- [x] **Step 7: feature 추가 + lib.rs 등록**

`crates/xmem-windows/Cargo.toml` features에 `"Win32_System_Kernel"` 추가(`Win32_System_Diagnostics_ToolHelp` 다음, 알파벳 순서 유지).

`crates/xmem-windows/src/lib.rs`:
- `pub mod dump;` 추가(`disk` 다음).
- 재수출에 `open_for_dump` 추가 + `pub use dump::{create_file_for_write, validate_minidump, write_minidump, write_minidump_file};`

- [x] **Step 8: 테스트 통과 확인**

Run: `cargo test -p xmem-windows`
Expected: PASS — 기존 50 + 신규 3 = 53

- [x] **Step 9: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows Cargo.lock
git commit -m "feat(windows): MiniDumpWriteDump 덤프 생성 primitive"
```

---

### Task 2: xmem-forensics — minidump 분석과 MinidumpSource

**Files:**
- Modify: `Cargo.toml` (workspace deps: `minidump = "0.27"`)
- Modify: `crates/xmem-forensics/Cargo.toml` (minidump dep, dev-dep xmem-windows)
- Modify: `crates/xmem-core/src/model/memory.rs` (`Protection::from_win32` + 테스트)
- Modify: `crates/xmem-windows/src/memory.rs` (`protection_from_raw` 위임)
- Create: `crates/xmem-forensics/src/dump.rs`
- Modify: `crates/xmem-forensics/src/lib.rs`
- Test: 각 파일 내 테스트 모듈

**Interfaces:**
- Consumes: `Protection::new`, `classify`/`heuristics`(core), `MemorySource`(core), `write_minidump_file`/`open_for_dump`(Task 1, dev-dep).
- Produces (Task 3이 사용):
  - `DumpAnalysis { path: String, os: String, cpu: String, arch: ProcessArch, process: ProcessInfo, modules: Vec<ModuleInfo>, threads: Vec<ThreadInfo>, regions: Vec<MemoryRegion>, memory_ranges: usize, memory_bytes: u64 }`
  - `MinidumpSource::open(path: &Path) -> Result<MinidumpSource>` / `.analysis() -> DumpAnalysis` / `impl MemorySource`
  - `analyze_dump(path: &Path) -> Result<DumpAnalysis>`

검증된 minidump 0.27.0 API:
- `minidump::Minidump::read_path(path) -> Result<MmapMinidump, minidump::Error>`, `MmapMinidump = Minidump<'static, Mmap>`.
- `dump.get_stream::<S>() -> Result<S, Error>` (MinidumpSystemInfo/MinidumpModuleList/MinidumpThreadList/MinidumpMemoryInfoList/MinidumpMiscInfo), `dump.get_memory() -> Option<UnifiedMemoryList>`.
- `MinidumpSystemInfo { os: Os, cpu: Cpu, .. }` (`minidump::system_info::{Os, Cpu}`; `Cpu::{X86, X86_64, Arm64, ...}`).
- `MinidumpModuleList::iter() -> impl Iterator<Item=&MinidumpModule>`; `MinidumpModule { raw, name: String, .. }`; `minidump::Module` trait: `base_address() -> u64`, `size() -> u64`.
- `MinidumpThreadList { threads: Vec<MinidumpThread> }`; `MinidumpThread { raw: MINIDUMP_THREAD, .. }`; `raw.thread_id: u32`.
- `MinidumpMemoryInfoList::iter() -> impl Iterator<Item=UnifiedMemoryInfo>`; `UnifiedMemoryInfo::Info(&MinidumpMemoryInfo)`; `MinidumpMemoryInfo { raw: MINIDUMP_MEMORY_INFO, .. }`.
- `MINIDUMP_MEMORY_INFO { base_address: u64, allocation_base: u64, allocation_protection: u32, region_size: u64, state: u32, protection: u32, _type: u32, .. }` — state: 0x1000 COMMIT/0x2000 RESERVE/0x10000 FREE, type: 0x20000 PRIVATE/0x40000 MAPPED/0x1000000 IMAGE.
- `MinidumpMiscInfo { raw: RawMiscInfo }` — `raw.process_id()`, `raw.process_create_time()` (각 `Option<&u32>`; 구현 시 정확한 반환형 확인).
- 메모리: `UnifiedMemory::{base_address(), size(), bytes()}`, `UnifiedMemoryList::iter()`.

- [x] **Step 1: 실패하는 테스트 작성 (core Protection::from_win32)**

`crates/xmem-core/src/model/memory.rs` 테스트 모듈에 추가:

```rust
#[test]
fn protection_from_win32_decodes_flags() {
    let cases = [
        (0x01u32, false, false, false),
        (0x02, true, false, false),
        (0x04, true, true, false),
        (0x08, true, true, false),
        (0x10, false, false, true),
        (0x20, true, false, true),
        (0x40, true, true, true),
        (0x80, true, true, true),
    ];
    for (raw, r, w, x) in cases {
        let p = Protection::from_win32(raw);
        assert_eq!((p.readable, p.writable, p.executable), (r, w, x), "raw={raw:#x}");
    }
    let guarded = Protection::from_win32(0x140);
    assert_eq!(guarded.raw, 0x140, "guard 비트는 raw에 보존");
}
```

- [x] **Step 2: 실패 확인**

Run: `cargo check -p xmem-core --tests`
Expected: FAIL — `no function or associated item named 'from_win32'`

- [x] **Step 3: core 구현 + xmem-windows 위임**

`crates/xmem-core/src/model/memory.rs`의 `impl Protection`에 추가:

```rust
/// Win32 PAGE_* 보호 비트를 해석한다(하위 8비트). GUARD/NOCACHE 등은 raw에 보존된다.
pub fn from_win32(raw: u32) -> Self {
    let base = raw & 0xff;
    let (readable, writable, executable) = match base {
        0x02 => (true, false, false),
        0x04 | 0x08 => (true, true, false),
        0x10 => (false, false, true),
        0x20 => (true, false, true),
        0x40 | 0x80 => (true, true, true),
        _ => (false, false, false),
    };
    Self::new(raw, readable, writable, executable)
}
```

`crates/xmem-windows/src/memory.rs`의 `protection_from_raw` 본문을 위임으로 교체:

```rust
pub fn protection_from_raw(raw: u32) -> Protection {
    Protection::from_win32(raw)
}
```

미사용이 된 `PAGE_*` import 정리(테스트에서 쓰는 것은 tests 모듈로 이동). 기존 보호 속성 테스트가 그대로 통과해야 한다.

- [x] **Step 4: core/windows 테스트 통과 확인**

Run: `cargo test -p xmem-core -p xmem-windows`
Expected: PASS — core 34, windows 53

- [x] **Step 5: 실패하는 테스트 작성 (forensics dump.rs)**

`crates/xmem-forensics/Cargo.toml`에 `minidump = "0.27"` 추가, `[dev-dependencies] xmem-windows.workspace = true` 추가. 루트 `Cargo.toml` `[workspace.dependencies]`에 `minidump = "0.27"` 추가 후 forensics에서 `minidump.workspace = true`.

`crates/xmem-forensics/src/dump.rs` 생성(테스트만):

```rust
//! Minidump 파일 파싱과 MemorySource 구현.

use std::path::Path;

use minidump::Module as _;
use minidump::{
    Minidump, MinidumpMemoryInfoList, MinidumpMiscInfo, MinidumpModule, MinidumpModuleList,
    MinidumpSystemInfo, MinidumpThreadList, system_info::Cpu,
};
use xmem_core::{
    MemoryRegion, MemorySource, MemoryState, MemoryType, ModuleInfo, ProcessArch, ProcessInfo,
    Protection, ReadOutcome, Result, ThreadInfo, XmemError, classify, heuristics,
};

// 구현 후 수정(실측): `MinidumpMemoryInfoList::iter()`는 `UnifiedMemoryInfo`가 아니라
// `&MinidumpMemoryInfo<'_>`를 직접 돌려준다(UnifiedMemoryInfoList와 혼동 주의).
// `info.raw`는 Copy가 아니므로 `&info.raw`로 빌려 쓴다.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use xmem_windows::{current_pid, open_for_dump, write_minidump_file};

    fn self_dump(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xmem-fx-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.dmp");
        let pid = current_pid();
        let handle = open_for_dump(pid).unwrap();
        write_minidump_file(&handle, pid, &path, false).unwrap();
        path
    }

    #[test]
    fn analyze_dump_of_self_returns_metadata() {
        let path = self_dump("meta");
        let analysis = analyze_dump(&path).unwrap();
        assert_eq!(analysis.process.pid, current_pid());
        assert_ne!(analysis.arch, ProcessArch::Unknown);
        assert!(!analysis.modules.is_empty());
        assert!(!analysis.regions.is_empty());
        assert!(!analysis.threads.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn minidump_source_reads_memory_from_dump() {
        let path = self_dump("read");
        let source = MinidumpSource::open(&path).unwrap();
        let raw = Minidump::read_path(&path).unwrap();
        let memory = raw.get_memory().unwrap();
        // 구현 후 수정(실측): MiniDumpNormal의 앞쪽 range는 4바이트(스레드 컨텍스트)이므로
        // 16바이트 이상인 첫 range를 고른다.
        let first = memory.iter().find(|r| r.bytes().len() >= 16).unwrap();
        let base = first.base_address();

        let mut buf = [0u8; 16];
        let outcome = source.read(base, &mut buf).unwrap();
        assert_eq!(outcome.bytes_read, 16);
        assert!(!outcome.partial);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn minidump_source_read_invalid_address_errors() {
        let path = self_dump("bad-addr");
        let source = MinidumpSource::open(&path).unwrap();
        let mut buf = [0u8; 16];
        let err = source.read(u64::MAX - 4096, &mut buf).unwrap_err();
        assert!(matches!(err, XmemError::InvalidAddress { .. }));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn analyze_rejects_garbage_file() {
        let dir = std::env::temp_dir().join(format!("xmem-fx-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.dmp");
        std::fs::write(&path, b"not a minidump").unwrap();

        let err = analyze_dump(&path).unwrap_err();
        assert!(matches!(err, XmemError::DumpError { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [x] **Step 6: 실패 확인**

Run: `cargo check -p xmem-forensics --tests`
Expected: FAIL — `DumpAnalysis`/`MinidumpSource`/`analyze_dump` 미정의

- [x] **Step 7: dump.rs 구현**

테스트 모듈 위에 추가:

```rust
/// FILETIME(1601)과 Unix epoch(1970)의 100ns 단위 차이.
const EPOCH_DIFFERENCE_100NS: u64 = 116_444_736_000_000_000;

/// 덤프에서 수집한 오프라인 분석 결과.
#[derive(Debug, Clone)]
pub struct DumpAnalysis {
    pub path: String,
    pub os: String,
    pub cpu: String,
    pub arch: ProcessArch,
    pub process: ProcessInfo,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub regions: Vec<MemoryRegion>,
    pub memory_ranges: usize,
    pub memory_bytes: u64,
}

/// Minidump 파일을 MemorySource로 노출한다(Offline Forensics).
pub struct MinidumpSource {
    dump: minidump::MmapMinidump,
    path: String,
    os: String,
    cpu: String,
    info: ProcessInfo,
    modules: Vec<ModuleInfo>,
    threads: Vec<ThreadInfo>,
    regions: Vec<MemoryRegion>,
    memory_ranges: usize,
    memory_bytes: u64,
}

impl MinidumpSource {
    pub fn open(path: &Path) -> Result<Self> {
        let dump = Minidump::read_path(path).map_err(|e| dump_error(path, &e))?;

        let system = dump.get_stream::<MinidumpSystemInfo>().ok();
        let (os, cpu, arch) = match &system {
            Some(s) => (
                format!("{:?}", s.os),
                format!("{:?}", s.cpu),
                arch_from_cpu(s.cpu),
            ),
            None => (
                "unknown".to_string(),
                "unknown".to_string(),
                ProcessArch::Unknown,
            ),
        };

        let modules: Vec<ModuleInfo> = dump
            .get_stream::<MinidumpModuleList>()
            .map(|list| list.iter().map(|m| module_from(m, arch)).collect())
            .unwrap_or_default();

        let (pid, creation_time) = misc_info(&dump);
        let threads: Vec<ThreadInfo> = dump
            .get_stream::<MinidumpThreadList>()
            .map(|list| {
                list.threads
                    .iter()
                    .map(|t| ThreadInfo {
                        tid: t.raw.thread_id,
                        pid,
                        priority: None,
                        start_address: None,
                        start_region_base: None,
                        start_module: None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let regions: Vec<MemoryRegion> = dump
            .get_stream::<MinidumpMemoryInfoList>()
            .map(|list| {
                list.iter()
                    .filter_map(|info| region_from_info(info, &modules))
                    .collect()
            })
            .unwrap_or_default();

        let (memory_ranges, memory_bytes) = match dump.get_memory() {
            Some(memory) => {
                let mut count = 0usize;
                let mut bytes = 0u64;
                for region in memory.iter() {
                    count += 1;
                    bytes = bytes.saturating_add(region.size());
                }
                (count, bytes)
            }
            None => (0, 0),
        };

        let main_module = modules.first();
        let info = ProcessInfo {
            pid,
            ppid: None,
            name: main_module
                .map(|m| m.name.clone())
                .unwrap_or_else(|| file_name(path)),
            image_path: main_module.and_then(|m| m.path.clone()),
            arch,
            session_id: None,
            creation_time,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: Some(threads.len() as u32),
            module_count: Some(modules.len() as u32),
        };

        Ok(Self {
            dump,
            path: path.display().to_string(),
            os,
            cpu,
            info,
            modules,
            threads,
            regions,
            memory_ranges,
            memory_bytes,
        })
    }

    pub fn analysis(&self) -> DumpAnalysis {
        DumpAnalysis {
            path: self.path.clone(),
            os: self.os.clone(),
            cpu: self.cpu.clone(),
            arch: self.info.arch,
            process: self.info.clone(),
            modules: self.modules.clone(),
            threads: self.threads.clone(),
            regions: self.regions.clone(),
            memory_ranges: self.memory_ranges,
            memory_bytes: self.memory_bytes,
        }
    }
}

impl MemorySource for MinidumpSource {
    fn process(&self) -> &ProcessInfo {
        &self.info
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>> {
        Ok(self.regions.clone())
    }

    fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
        let Some(memory) = self.dump.get_memory() else {
            return Err(XmemError::DumpError {
                reason: "덤프에 메모리 스트림이 없습니다".to_string(),
            });
        };
        for region in memory.iter() {
            let base = region.base_address();
            let end = base.saturating_add(region.size());
            if address < base || address >= end {
                continue;
            }
            let start = (address - base) as usize;
            let bytes = region.bytes();
            let available = bytes.len().saturating_sub(start);
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            return Ok(ReadOutcome {
                bytes_read: n,
                partial: n < buf.len(),
            });
        }
        Err(XmemError::InvalidAddress { address })
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(self.modules.clone())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.threads.clone())
    }
}

pub fn analyze_dump(path: &Path) -> Result<DumpAnalysis> {
    Ok(MinidumpSource::open(path)?.analysis())
}

fn dump_error(path: &Path, e: &minidump::Error) -> XmemError {
    XmemError::DumpError {
        reason: format!("minidump 파싱 실패: {} ({e})", path.display()),
    }
}

fn misc_info(dump: &minidump::MmapMinidump) -> (u32, Option<u64>) {
    let Ok(misc) = dump.get_stream::<MinidumpMiscInfo>() else {
        return (0, None);
    };
    let pid = misc.raw.process_id().copied().unwrap_or(0);
    let creation = misc.raw.process_create_time().map(|secs| {
        (*secs as u64)
            .saturating_mul(10_000_000)
            .saturating_add(EPOCH_DIFFERENCE_100NS)
    });
    (pid, creation)
}

fn arch_from_cpu(cpu: Cpu) -> ProcessArch {
    match cpu {
        Cpu::X86_64 => ProcessArch::X64,
        Cpu::X86 => ProcessArch::X86,
        Cpu::Arm64 => ProcessArch::Arm64,
        _ => ProcessArch::Unknown,
    }
}

fn module_from(module: &MinidumpModule, arch: ProcessArch) -> ModuleInfo {
    let full = module.name.clone();
    let name = full
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(full.as_str())
        .to_string();
    ModuleInfo {
        name,
        base: module.base_address(),
        size: module.size(),
        path: Some(full),
        arch: Some(arch),
    }
}

fn region_from_info(
    info: &minidump::MinidumpMemoryInfo<'_>,
    modules: &[ModuleInfo],
) -> Option<MemoryRegion> {
    let raw = &info.raw;
    let state = match raw.state {
        0x1000 => MemoryState::Commit,
        0x2000 => MemoryState::Reserve,
        0x10000 => MemoryState::Free,
        _ => return None,
    };
    let region_type = match raw._type {
        0x0002_0000 => Some(MemoryType::Private),
        0x0004_0000 => Some(MemoryType::Mapped),
        0x0100_0000 => Some(MemoryType::Image),
        _ => None,
    };
    let protection = Protection::from_win32(raw.protection);
    let classification = classify(state, region_type);
    let heuristics = heuristics(state, &protection, region_type);
    let mapped_file = modules
        .iter()
        .find(|m| {
            raw.base_address >= m.base && raw.base_address < m.base.saturating_add(m.size)
        })
        .and_then(|m| m.path.clone());
    Some(MemoryRegion {
        base: raw.base_address,
        size: raw.region_size,
        state,
        protection,
        allocation_protection: if raw.allocation_protection != 0 {
            Some(Protection::from_win32(raw.allocation_protection))
        } else {
            None
        },
        region_type,
        readable: protection.readable,
        writable: protection.writable,
        executable: protection.executable,
        classification,
        heuristics,
        mapped_file,
    })
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}
```

`crates/xmem-forensics/src/lib.rs`: `pub mod dump;` 추가 + `pub use dump::{DumpAnalysis, MinidumpSource, analyze_dump};`

- [x] **Step 8: 테스트 통과 확인**

Run: `cargo test -p xmem-forensics`
Expected: PASS — 기존 20 + 신규 4 = 24

- [x] **Step 9: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-forensics --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-core crates/xmem-windows crates/xmem-forensics
git commit -m "feat(forensics): Minidump 파싱과 MinidumpSource MemorySource"
```

---

### Task 3: CLI — dump create / dump analyze

**Files:**
- Modify: `crates/xmem-cli/src/cli.rs` (`DumpCmd::Create`에 `--full`, 테스트 1개)
- Modify: `crates/xmem-cli/src/commands/dump.rs` (스텁 → 구현)
- Modify: `crates/xmem-cli/src/commands/process.rs` (`arch_str` → `pub(crate)`)
- Modify: `crates/xmem-cli/src/commands/memory.rs` (`MapSummary`/`summarize` → `pub(crate)`, 요약행 헬퍼 재사용)
- Test: dump.rs 내 테스트 4개

**Interfaces:**
- Consumes: `xmem_forensics::{DumpAnalysis, MinidumpSource}`, `xmem_detection::detect_source`, `xmem_windows::{free_space_bytes, open_for_dump, process_info, write_minidump_file}`, `commands::detect::{render_findings, detect_json_payload}`, `commands::memory::{cancel_flag, MapSummary, summarize}`, `commands::render::human_size`.
- Produces: `pub(crate) fn create_dump_file(pid: u32, output: &str, full: bool) -> Result<CreateSummary>`, `pub(crate) fn render_dump(analysis: &DumpAnalysis, findings: &[Finding]) -> String`, `pub(crate) fn dump_json_payload(analysis: &DumpAnalysis, findings: &[Finding]) -> Value`.

기존 확인된 사실:
- `SnapshotCmd`와 `DumpCmd`는 cli.rs에서 별도 enum. `DumpCmd::Create { pid: PidArg(flatten), output: String }`, `DumpCmd::Analyze { file: String }`.
- `emit_json(&Value)`는 `()` 반환 — `?` 금지.
- `ensure_disk_space`는 snapshot.rs에 있으나 SnapshotError kind를 쓰므로 dump는 로컬 검사(6줄)를 쓴다.
- `ProcessInfo.memory_stats: Option<MemoryStats>`, `MemoryStats.commit: u64`.

- [x] **Step 1: 실패하는 테스트 작성 (cli.rs 파싱)**

`crates/xmem-cli/src/cli.rs` 테스트 모듈에 추가:

```rust
#[test]
fn parses_dump_create_with_full_flag() {
    let cli = parse(&["xmem", "dump", "create", "--pid", "42", "--output", "t.dmp", "--full"]).unwrap();
    match cli.command {
        Command::Dump { cmd } => match cmd {
            DumpCmd::Create { pid, output, full } => {
                assert_eq!(pid.pid, 42);
                assert_eq!(output, "t.dmp");
                assert!(full);
            }
            _ => panic!("create가 아님"),
        },
        _ => panic!("dump가 아님"),
    }
}
```

- [x] **Step 2: 실패 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — `DumpCmd::Create`에 `full` 필드 없음(E0026/E0559)

- [x] **Step 3: cli.rs 수정**

```rust
pub enum DumpCmd {
    /// 미니덤프 생성
    Create {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 (.dmp)
        #[arg(long)]
        output: String,
        /// 전체 메모리 포함 (크고 느림, 디스크 사전 검사)
        #[arg(long)]
        full: bool,
    },
    /// 미니덤프 분석
    Analyze { file: String },
}
```

- [x] **Step 4: 실패하는 테스트 작성 (dump.rs)**

`crates/xmem-cli/src/commands/dump.rs` 전면 교체(테스트 + import + 스텁 함수 시그니처):

```rust
use std::path::Path;

use serde_json::{Value, json};
use xmem_core::{Finding, ProcessInfo, Result, XmemError};
use xmem_forensics::{DumpAnalysis, MinidumpSource};
use xmem_windows::{free_space_bytes, open_for_dump, process_info, write_minidump_file};

use crate::cli::{DumpCmd, GlobalArgs};
use crate::commands::detect::render_findings;
use crate::commands::memory::cancel_flag;
use crate::commands::process::arch_str;
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, ProcessArch, Severity};

    fn sample_analysis() -> DumpAnalysis {
        DumpAnalysis {
            path: "self.dmp".to_string(),
            os: "Windows".to_string(),
            cpu: "X86_64".to_string(),
            arch: ProcessArch::X64,
            process: ProcessInfo {
                pid: 4242,
                ppid: None,
                name: "sample.exe".to_string(),
                image_path: None,
                arch: ProcessArch::X64,
                session_id: None,
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: Some(3),
                module_count: Some(2),
            },
            modules: Vec::new(),
            threads: Vec::new(),
            regions: Vec::new(),
            memory_ranges: 7,
            memory_bytes: 4096,
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region")],
            heuristic: "Executable Private Memory".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }
    }

    #[test]
    fn create_dump_of_self_writes_valid_file() {
        let dir = std::env::temp_dir().join(format!("xmem-cli-dump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.dmp");

        let summary = create_dump_file(std::process::id(), &path.to_string_lossy(), false).unwrap();
        assert!(summary.file_bytes > 0);
        let magic = std::fs::read(&path).unwrap();
        assert_eq!(&magic[..4], b"MDMP");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_dump_lists_summary_and_findings() {
        let text = render_dump(&sample_analysis(), &[sample_finding()]);
        assert!(text.contains("dump self.dmp"));
        assert!(text.contains("os: Windows cpu: X86_64 arch: x64"));
        assert!(text.contains("regions: 0"));
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("finding"));
    }

    #[test]
    fn dump_json_payload_has_summary_and_findings() {
        let value = dump_json_payload(&sample_analysis(), &[sample_finding()]);
        assert_eq!(value["file"], "self.dmp");
        assert_eq!(value["process"]["pid"], 4242);
        assert_eq!(value["memory_ranges"], 7);
        assert_eq!(value["finding_count"], 1);
        assert_eq!(value["findings"][0]["rule_id"], "XMEM-001");
    }

    #[test]
    fn analyze_missing_file_errors() {
        let err = MinidumpSource::open(Path::new("no-such-file.dmp")).unwrap_err();
        assert!(matches!(err, XmemError::DumpError { .. }));
    }
}
```

- [x] **Step 5: 실패 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — `create_dump_file`/`render_dump`/`dump_json_payload` 미정의, `arch_str` 비공개

- [x] **Step 6: 구현 (dump.rs + process.rs/memory.rs 가시성)**

`process.rs`: `fn arch_str` → `pub(crate) fn arch_str`.
`memory.rs`: `struct MapSummary` → `pub(crate) struct MapSummary`, `fn summarize` → `pub(crate) fn summarize`.

dump.rs 테스트 모듈 위에 추가:

```rust
const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CreateSummary {
    pub output: String,
    pub file_bytes: u64,
    pub full: bool,
    pub pid: u32,
    pub name: String,
    pub elapsed_ms: u64,
}

pub fn run(cmd: &DumpCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        DumpCmd::Create { pid, output, full } => run_create(pid.pid, output, *full, global),
        DumpCmd::Analyze { file } => run_analyze(file, global),
    }
}

fn run_create(pid: u32, output: &str, full: bool, global: &GlobalArgs) -> Result<()> {
    let _cancel = cancel_flag();
    let started = std::time::Instant::now();
    let mut summary = create_dump_file(pid, output, full)?;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;

    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "output": summary.output,
                "file_bytes": summary.file_bytes,
                "full": summary.full,
                "process": { "pid": summary.pid, "name": summary.name },
                "elapsed_ms": summary.elapsed_ms,
            })));
            Ok(())
        }
        OutputMode::Human => {
            println!(
                "dump written: {} ({}){}",
                summary.output,
                human_size(summary.file_bytes),
                if summary.full { " [full]" } else { "" }
            );
            println!(
                "  process {} ({}) in {} ms",
                summary.name, summary.pid, summary.elapsed_ms
            );
            Ok(())
        }
    }
}

pub(crate) fn create_dump_file(pid: u32, output: &str, full: bool) -> Result<CreateSummary> {
    let handle = open_for_dump(pid)?;
    let info = process_info(pid)?;
    let path = Path::new(output);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let needed = if full {
        info.memory_stats.as_ref().map(|s| s.commit).unwrap_or(0)
    } else {
        0
    };
    ensure_disk_space(parent, needed)?;

    let file_bytes = write_minidump_file(&handle, pid, path, full)?;
    Ok(CreateSummary {
        output: output.to_string(),
        file_bytes,
        full,
        pid,
        name: info.name,
        elapsed_ms: 0,
    })
}

fn ensure_disk_space(dir: &Path, needed: u64) -> Result<()> {
    let free = free_space_bytes(&dir.to_string_lossy())?;
    if free < needed.saturating_add(DISK_MARGIN_BYTES) {
        return Err(XmemError::DumpError {
            reason: format!(
                "디스크 공간 부족: 필요 {needed} + 여유 {DISK_MARGIN_BYTES}, 가용 {free} ({})",
                dir.display()
            ),
        });
    }
    Ok(())
}

fn run_analyze(file: &str, global: &GlobalArgs) -> Result<()> {
    let source = MinidumpSource::open(Path::new(file))?;
    let findings = xmem_detection::detect_source(&source)?;
    let analysis = source.analysis();

    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(dump_json_payload(&analysis, &findings)));
            Ok(())
        }
        OutputMode::Human => {
            print!("{}", render_dump(&analysis, &findings));
            Ok(())
        }
    }
}

pub(crate) fn render_dump(analysis: &DumpAnalysis, findings: &[Finding]) -> String {
    let summary = super::memory::summarize(&analysis.regions);
    let mut out = String::new();
    out.push_str(&format!("dump {}\n", analysis.path));
    out.push_str(&format!(
        "  os: {} cpu: {} arch: {}\n",
        analysis.os,
        analysis.cpu,
        arch_str(analysis.arch)
    ));
    out.push_str(&format!(
        "  pid: {} name: {}\n",
        analysis.process.pid, analysis.process.name
    ));
    out.push_str(&format!(
        "  regions: {} (committed {} ({}), reserved {}, free {}; executable {}), modules: {}, threads: {}, memory ranges: {} ({})\n",
        summary.total,
        summary.committed,
        human_size(summary.committed_bytes),
        summary.reserved,
        summary.free,
        summary.executable,
        analysis.modules.len(),
        analysis.threads.len(),
        analysis.memory_ranges,
        human_size(analysis.memory_bytes),
    ));
    out.push_str(&render_findings(&analysis.process, findings));
    out
}

pub(crate) fn dump_json_payload(analysis: &DumpAnalysis, findings: &[Finding]) -> Value {
    json!({
        "file": analysis.path,
        "os": analysis.os,
        "cpu": analysis.cpu,
        "arch": arch_str(analysis.arch),
        "process": { "pid": analysis.process.pid, "name": analysis.process.name },
        "region_count": analysis.regions.len(),
        "module_count": analysis.modules.len(),
        "thread_count": analysis.threads.len(),
        "memory_ranges": analysis.memory_ranges,
        "memory_bytes": analysis.memory_bytes,
        "finding_count": findings.len(),
        "findings": findings,
    })
}
```

`crates/xmem-cli/Cargo.toml`에 `xmem-forensics.workspace = true`가 이미 있는지 확인(있음 — M7에서 추가). `xmem-detection`도 이미 있음(M8).

- [x] **Step 7: 테스트 통과 확인**

Run: `cargo test -p xmem-cli`
Expected: PASS — 기존 50 + 신규 4 = 54

- [x] **Step 8: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add crates/xmem-cli
git commit -m "feat(cli): dump create/analyze 명령"
```

---

### Task 4: 문서 + 전체 게이트 + Windows 스모크

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-09-minidump.md` (체크박스)

- [x] **Step 1: README 갱신**

- Status 문구: "현재 **Milestone 9 (Minidump)** 완료. ..." (M8 문구 교체).
- Status 표에 두 행 추가(Planned (M9) 행이 있으면 교체):
  - `dump create --pid <PID> --output <FILE> [--full] | Implemented (MiniDumpWriteDump, metadata+FullMemoryInfo 기본, --full은 전체 메모리·디스크 사전 검사, temp→검증→rename, --json)`
  - `dump analyze <FILE> | Implemented (minidump 파싱: os/cpu/arch/pid/modules/threads/regions(MemoryInfoList)/findings, MinidumpSource, --json)`
- Quick Start에 2줄:
  ```powershell
  xmem dump create --pid <PID> --output target.dmp
  xmem dump analyze target.dmp
  ```
- CLI Usage의 dump 항목 설명 교체(create 옵션, analyze가 detect와 동일한 Rule을 오프라인에서 실행한다는 점, findings ≠ 증명).
- Limitations에 M9 문단 추가: analyze는 MemoryInfoList 필요(XMem이 만든 덤프에는 항상 포함), minidump에는 thread start address가 없어 XMEM-004는 침묵, mapped file 이름은 module 목록 기반 근사, `--full`은 진행 중 취소 미지원(Ctrl+C는 프로세스 종료), module 없는 덤프에서는 XMEM-003/004 침묵.
- Roadmap M9=완료.

- [x] **Step 2: architecture.md 갱신**

- dependency 표에 minidump 행 추가(도입 시점 M9, 비고: "파싱 전용, PE와 무관").
- crate 표 `xmem-forensics` 비고에 "Minidump 분석(M9)" 추가.
- Windows API 표 M9 행: `MiniDumpWriteDump`(feature `Win32_System_Kernel` 추가) / `CreateFileW` / `GetDiskFreeSpaceExW` 재사용 — "구현됨. metadata 덤프는 MiniDumpWithFullMemoryInfo 포함, --full은 디스크 사전 검사".
- §10(Minidump) 제목에 "(M9 구현됨)" + 구현 노트: MinidumpSource가 MemorySource를 구현해 detect_source 재사용, thread start address 없음, temp→MDMP 검증→rename.
- §14 Status 표: M9 Done, M10~M12 Planned.

- [x] **Step 3: 전체 게이트**

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0. 테스트 합계 **203** = cli 54 + core 34 + detection 8 + forensics 24 + memory 21 + pe 9 + windows 53.

- [x] **Step 4: Windows 스모크**

```powershell
$dir = Join-Path $env:TEMP "xmem-m9"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = ".\target\debug\xmem.exe"
cargo build -q -p xmem-cli

# 1) metadata 덤프 생성 + 분석
& $exe dump create --pid $PID --output "$dir\self.dmp"; Write-Output "exit=$LASTEXITCODE"
& $exe dump analyze "$dir\self.dmp"; Write-Output "exit=$LASTEXITCODE"

# 2) JSON
& $exe --json dump analyze "$dir\self.dmp"; Write-Output "exit=$LASTEXITCODE"

# 3) full 덤프(작은 자식 프로세스)
$child = Start-Process cmd -ArgumentList "/c","timeout","20" -PassThru
& $exe dump create --pid $child.Id --output "$dir\child-full.dmp" --full; Write-Output "exit=$LASTEXITCODE"
& $exe dump analyze "$dir\child-full.dmp" | Select-Object -First 6
Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue

# 4) 오류 경로
& $exe dump create --pid 4294967294 --output "$dir\x.dmp"; Write-Output "exit=$LASTEXITCODE"
& $exe dump analyze "$dir\no-such.dmp"; Write-Output "exit=$LASTEXITCODE"

# 5) temp 잔존 확인 + 반복
Get-ChildItem $dir | Select-Object -ExpandProperty Name
1..3 | ForEach-Object { & $exe dump analyze "$dir\self.dmp" > $null; Write-Output "repeat=$LASTEXITCODE" }
Remove-Item -Recurse -Force $dir
```

기록할 것: 덤프 크기, analyze의 regions/modules/threads/finding 수, `--full` 파일 크기, exit code 전부, `.tmp-` 잔존 없음, 반복 3회 0.

- [x] **Step 5: 계획서 체크박스 + 커밋**

`docs/plans/milestone-09-minidump.md`의 모든 `- [x]` → `- [x]` (replaceAll).

```powershell
git add README.md docs/architecture.md docs/plans/milestone-09-minidump.md
git commit -m "docs: M9 Minidump 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지**: `dump create`(§18), `dump analyze`(§18), MemorySource 확장(§17), 디스크 보호(§34), 오류 Context(§36), RAII(§37), read-only(§28), CLI --json(§23), 게이트(§41) 모두 Task에 매핑됨.
- **의존성 최소성**: minidump는 자체 파서 작성 대비 수백 줄을 대체한다. uuid/memmap2는 직접 도입하지 않는다(memmap2는 minidump의 전이 의존).
- **미구현으로 남기는 것**: `--full` 진행 중 취소(콜백), thread start address 복원(컨텍스트 파싱), PE 프로브(덤프 메모리 read 기반 XMEM-002) — M12 또는 후속. 문서에 명시.
- **타입 일관성**: `DumpAnalysis`/`MinidumpSource`/`create_dump_file`/`render_dump`/`dump_json_payload` 이름이 Task 2·3에서 동일.
