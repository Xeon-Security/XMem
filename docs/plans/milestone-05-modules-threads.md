# M5 Module / Thread Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xmem modules --pid`와 `xmem threads --pid`를 구현한다. 로드된 모듈을 열거하고, 스레드 시작 주소를 메모리 영역/모듈과 상관관계 분석해 구조화된 Evidence로 노출한다.

**Architecture:** `xmem-windows`에 Toolhelp 기반 모듈/스레드 열거 primitive와 `OpenThread`/`GetThreadPriority`/`NtQueryInformationThread` 래퍼를 추가한다. `xmem-memory::LiveProcess`가 `MemorySource::modules()/threads()`를 실제 구현으로 채우고, 시작 주소 → 영역/모듈 상관관계를 계산한다. CLI는 기존 `resolve_mode` 4-arm 패턴으로 Human 표/JSON envelope을 출력한다. 모두 read-only이며 대상 프로세스 상태를 변경하지 않는다.

**Tech Stack:** Rust stable 1.98 (edition 2024), windows-rs 0.62, clap 4, serde/serde_json, tracing.

**Spec:** [`docs/architecture.md`](../architecture.md) — M5 행(Module32/Thread32, OpenThread, GetThreadPriority, NtQueryInformationThread), `ThreadInfo` Data Model, Detection Rule XMEM-004(후속).

## Global Constraints

- Windows 10/11 x86-64, Rust stable 1.98+, MSVC Build Tools, edition 2024.
- `unsafe`는 `xmem-windows` 크레이트에만 허용(workspace lint `unsafe_code = "deny"` + crate 단위 allow).
- Runtime 경로에서 `unwrap()`/`expect()` 금지(테스트는 `#![cfg_attr(test, allow(...))]`).
- 모든 Windows API 실패는 `XmemError`로 구조화한다. 무시하거나 panic 금지.
- `cargo fmt` / `cargo clippy -D warnings` / `cargo test`를 각 Task 종료 시 통과시킨다.
- 모든 cargo 명령 앞에 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` (pwsh).
- 분석 명령은 read-only. 대상 프로세스의 메모리/보호 속성을 변경하지 않는다.
- 커밋 prefix: `feat`/`fix`/`docs`/`style`/`refactor`/`test`/`chore`. 메시지는 한국어.

## Review Focus

1. **TH32CS_SNAPTHREAD는 시스템 전체 스냅샷** — `th32OwnerProcessID == pid` 필터가 빠지면 다른 프로세스 스레드가 섞인다. 테스트는 `t.pid == pid`를 전부 검증한다(Task 2/3).
2. **OpenThread 권한 실패 degrade** — 개별 스레드 핸들 열기 실패가 전체 목록을 실패시키면 안 된다. priority/start_address만 `None`이 되고 목록은 유지된다(Task 3 테스트 `threads_of_self_have_address_correlation`가 아니고, 별도로 `open_thread_bogus_tid_fails_structured`가 구조화 오류를 검증).
3. **시작 주소가 모듈/영역 밖** — 커널 시작 주소(`RtlUserThreadStart`) 등 어떤 모듈에도 속하지 않으면 `start_module: None`이 정상이다. panic 없이 `None`으로 남는다(Task 3 `contains`/`contains_module` 경계 검증).
4. **WOW64 모듈** — 32비트 프로세스에서 `TH32CS_SNAPMODULE32` 누락 시 모듈 열거가 실패한다. `SNAPMODULE | SNAPMODULE32` 조합을 유지하고, 모듈 0개여도 오류가 아니다(Task 1).
5. **GetThreadPriority 실패값** — `i32::MAX`(THREAD_PRIORITY_ERROR_RETURN)를 그대로 노출하면 가짜 우선순위가 된다. `None`으로 변환한다(Task 2 테스트).

---

### Task 1: xmem-windows — 모듈 열거

**Files:**
- Modify: `crates/xmem-windows/src/toolhelp.rs`
- Modify: `crates/xmem-windows/src/lib.rs`

**Interfaces:**
- Consumes: `toolhelp::snapshot`, `toolhelp::is_no_more_files`, `crate::error::error_from_win32`, `crate::util::utf16_z_to_string` (모두 기존).
- Produces:
  - `pub struct RawModuleEntry { pub name: String, pub path: Option<String>, pub base: u64, pub size: u64 }`
  - `pub fn list_raw_modules(pid: u32) -> Result<Vec<RawModuleEntry>>`
  - `pub fn count_modules(pid: u32) -> Result<u32>` — `list_raw_modules` 기반으로 리팩터(동작 동일).

- [ ] **Step 1: 테스트 먼저 (red)**

`crates/xmem-windows/src/toolhelp.rs`의 기존 `#[cfg(test)] mod tests`에 추가:

```rust
    #[test]
    fn list_raw_modules_of_self_is_populated() {
        let modules = list_raw_modules(crate::process::current_pid()).unwrap();
        assert!(!modules.is_empty());
        assert!(
            modules
                .iter()
                .all(|m| !m.name.is_empty() && m.base > 0 && m.size > 0)
        );
        assert!(modules.iter().any(|m| m.path.is_some()));
    }

    #[test]
    fn list_raw_modules_has_unique_bases() {
        let modules = list_raw_modules(crate::process::current_pid()).unwrap();
        let mut bases: Vec<u64> = modules.iter().map(|m| m.base).collect();
        bases.sort_unstable();
        bases.dedup();
        assert_eq!(bases.len(), modules.len());
    }

    #[test]
    fn count_modules_matches_list_len() {
        let pid = crate::process::current_pid();
        assert_eq!(
            count_modules(pid).unwrap() as usize,
            list_raw_modules(pid).unwrap().len()
        );
    }
```

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `RawModuleEntry`/`list_raw_modules` 없음(E0422/E0425).

- [ ] **Step 3: 구현**

`crates/xmem-windows/src/toolhelp.rs`에 추가(기존 `count_modules`는 삭제하고 아래로 교체):

```rust
/// Toolhelp 모듈 항목(원시 값).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawModuleEntry {
    pub name: String,
    pub path: Option<String>,
    pub base: u64,
    pub size: u64,
}

/// 대상 프로세스의 로드된 모듈을 열거한다. 32/64비트 모듈을 모두 포함한다.
pub fn list_raw_modules(pid: u32) -> Result<Vec<RawModuleEntry>> {
    let snap = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    let mut modules = Vec::new();
    if let Err(err) = unsafe { Module32FirstW(&snap, &mut entry) } {
        if is_no_more_files(&err) {
            return Ok(modules);
        }
        return Err(error_from_win32("Module32FirstW", &err));
    }
    loop {
        let path = utf16_z_to_string(&entry.szExePath);
        modules.push(RawModuleEntry {
            name: utf16_z_to_string(&entry.szModule),
            path: (!path.is_empty()).then_some(path),
            base: entry.modBaseAddr as u64,
            size: entry.modBaseSize as u64,
        });
        match unsafe { Module32NextW(&snap, &mut entry) } {
            Ok(()) => {}
            Err(err) if is_no_more_files(&err) => break,
            Err(err) => return Err(error_from_win32("Module32NextW", &err)),
        }
    }
    Ok(modules)
}

/// 로드된 모듈 수(32/64비트 포함).
pub fn count_modules(pid: u32) -> Result<u32> {
    Ok(list_raw_modules(pid)?.len() as u32)
}
```

`crates/xmem-windows/src/lib.rs` 재수출에 추가:

```rust
pub use toolhelp::{RawModuleEntry, count_modules, list_raw_modules};
```

- [ ] **Step 4: green 확인**

Run: `cargo test -p xmem-windows`
Expected: PASS — 기존 42 + 3 = 45. `count_modules_matches_list_len`가 리팩터 동등성을 보증한다.

- [ ] **Step 5: 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows
git commit -m "feat(windows): Toolhelp 모듈 열거"
```

---

### Task 2: xmem-windows — 스레드 열거/쿼리

**Files:**
- Modify: `crates/xmem-windows/src/toolhelp.rs` (snapshot/is_no_more_files를 `pub(crate)`로)
- Create: `crates/xmem-windows/src/threads.rs`
- Modify: `crates/xmem-windows/src/lib.rs`

**Interfaces:**
- Consumes: `toolhelp::{snapshot, is_no_more_files}`, `error::{error_from_win32}`, `handle::OwnedHandle`.
- Produces:
  - `pub struct RawThreadEntry { pub tid: u32, pub pid: u32, pub base_priority: i32 }`
  - `pub fn list_raw_threads(pid: u32) -> Result<Vec<RawThreadEntry>>`
  - `pub fn open_thread(tid: u32, access: THREAD_ACCESS_RIGHTS) -> Result<OwnedHandle>`
  - `pub fn open_thread_for_query(tid: u32) -> Result<OwnedHandle>`
  - `pub fn thread_priority(handle: &OwnedHandle) -> Option<i32>`
  - `pub fn thread_start_address(handle: &OwnedHandle) -> Option<u64>`

- [ ] **Step 1: 테스트 먼저 (red)**

`crates/xmem-windows/src/threads.rs`:

```rust
use std::ffi::c_void;
use std::mem::size_of;

use windows::Win32::System::Diagnostics::ToolHelp::{
    TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::Threading::{
    GetCurrentThreadId, GetThreadPriority, OpenThread, THREAD_ACCESS_RIGHTS, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION,
};
use windows::Wdk::System::Threading::{NtQueryInformationThread, ThreadQuerySetWin32StartAddress};

use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;
use crate::toolhelp::{is_no_more_files, snapshot};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_raw_threads_of_self_is_populated() {
        let pid = crate::process::current_pid();
        let threads = list_raw_threads(pid).unwrap();
        assert!(!threads.is_empty());
        assert!(threads.iter().all(|t| t.pid == pid && t.tid != 0));
    }

    #[test]
    fn open_thread_and_query_priority_and_start_address() {
        let tid = unsafe { GetCurrentThreadId() };
        let handle = open_thread_for_query(tid).unwrap();
        assert!(thread_priority(&handle).is_some());
        assert!(thread_start_address(&handle).is_some());
    }

    #[test]
    fn open_thread_bogus_tid_fails_structured() {
        let err = open_thread(0xFFFF_FFFE, THREAD_QUERY_LIMITED_INFORMATION).unwrap_err();
        assert!(
            matches!(
                err,
                XmemError::AccessDenied { .. }
                    | XmemError::InvalidHandle { .. }
                    | XmemError::WindowsApi { .. }
            ),
            "예상 밖 오류: {err:?}"
        );
    }
}
```

`crates/xmem-windows/src/lib.rs`에 `pub mod threads;` 추가.

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `list_raw_threads`/`open_thread_for_query` 등 없음(E0425). `GetCurrentThreadId`가 Threading에 없으면 E0432 — 이 경우 `windows::Win32::System::Threading::GetCurrentThreadId`를 grep으로 확인하고, 없으면 테스트에서 `list_raw_threads(current_pid())` 첫 항목의 tid를 사용한다.

- [ ] **Step 3: 구현**

`crates/xmem-windows/src/toolhelp.rs`에서 `fn snapshot`과 `fn is_no_more_files`를 `pub(crate) fn`으로 변경(본문 동일).

`crates/xmem-windows/src/threads.rs`의 테스트 모듈 **위**에 추가:

```rust
/// Toolhelp 스레드 항목(원시 값).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawThreadEntry {
    pub tid: u32,
    pub pid: u32,
    pub base_priority: i32,
}

/// 대상 프로세스 소유 스레드만 열거한다. TH32CS_SNAPTHREAD는 시스템 전체 스냅샷이다.
pub fn list_raw_threads(pid: u32) -> Result<Vec<RawThreadEntry>> {
    let snap = snapshot(TH32CS_SNAPTHREAD, 0)?;
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut threads = Vec::new();
    if let Err(err) = unsafe { Thread32First(&snap, &mut entry) } {
        if is_no_more_files(&err) {
            return Ok(threads);
        }
        return Err(error_from_win32("Thread32First", &err));
    }
    loop {
        if entry.th32OwnerProcessID == pid {
            threads.push(RawThreadEntry {
                tid: entry.th32ThreadID,
                pid: entry.th32OwnerProcessID,
                base_priority: entry.tpBasePri,
            });
        }
        match unsafe { Thread32Next(&snap, &mut entry) } {
            Ok(()) => {}
            Err(err) if is_no_more_files(&err) => break,
            Err(err) => return Err(error_from_win32("Thread32Next", &err)),
        }
    }
    Ok(threads)
}

/// 스레드 핸들. 접근 권한이 거부되면 AccessDenied.
pub fn open_thread(tid: u32, access: THREAD_ACCESS_RIGHTS) -> Result<OwnedHandle> {
    match unsafe { OpenThread(access, false, tid) } {
        Ok(handle) => OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(err) => Err(error_from_win32("OpenThread", &err)),
    }
}

/// 쿼리용 스레드 핸들. QUERY_INFORMATION 실패 시 LIMITED로 재시도한다.
pub fn open_thread_for_query(tid: u32) -> Result<OwnedHandle> {
    match open_thread(tid, THREAD_QUERY_INFORMATION) {
        Ok(handle) => Ok(handle),
        Err(XmemError::AccessDenied { .. }) => open_thread(tid, THREAD_QUERY_LIMITED_INFORMATION),
        Err(err) => Err(err),
    }
}

/// 동적 우선순위. 조회 실패값(i32::MAX)은 None.
pub fn thread_priority(handle: &OwnedHandle) -> Option<i32> {
    let value = unsafe { GetThreadPriority(handle.raw()) };
    (value != i32::MAX).then_some(value)
}

/// 스레드 시작 주소(ThreadQuerySetWin32StartAddress). best-effort.
pub fn thread_start_address(handle: &OwnedHandle) -> Option<u64> {
    let mut address: u64 = 0;
    let status = unsafe {
        NtQueryInformationThread(
            handle.raw(),
            ThreadQuerySetWin32StartAddress,
            (&mut address as *mut u64).cast::<c_void>(),
            size_of::<u64>() as u32,
            std::ptr::null_mut(),
        )
    };
    (status.0 >= 0).then_some(address)
}
```

`crates/xmem-windows/src/lib.rs` 재수출 추가:

```rust
pub use threads::{
    RawThreadEntry, list_raw_threads, open_thread, open_thread_for_query, thread_priority,
    thread_start_address,
};
```

- [ ] **Step 4: green 확인**

Run: `cargo test -p xmem-windows`
Expected: PASS — 45 + 3 = 48.

- [ ] **Step 5: 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows
git commit -m "feat(windows): Toolhelp 스레드 열거와 시작 주소 조회"
```

---

### Task 3: xmem-memory — LiveProcess modules/threads + 상관관계

**Files:**
- Modify: `crates/xmem-memory/src/live.rs`

**Interfaces:**
- Consumes: `xmem_windows::{list_raw_modules, list_raw_threads, open_thread_for_query, thread_priority, thread_start_address}`, 기존 `region_map()`.
- Produces:
  - `LiveProcess::modules(&self) -> Result<Vec<ModuleInfo>>`
  - `LiveProcess::threads(&self) -> Result<Vec<ThreadInfo>>` — `start_region_base`/`start_module` 상관관계 포함.
  - `MemorySource::modules()/threads()`가 위를 반환.

- [ ] **Step 1: 테스트 먼저 (red)**

`crates/xmem-memory/src/live.rs` 테스트 모듈에서 `unimplemented_methods_are_explicit`를 **삭제**하고 추가:

```rust
    #[test]
    fn modules_of_self_are_populated() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let modules = live.modules().unwrap();
        assert!(!modules.is_empty());
        assert!(
            modules
                .iter()
                .all(|m| !m.name.is_empty() && m.base > 0 && m.size > 0)
        );
        assert!(modules.iter().any(|m| m.path.is_some()));
    }

    #[test]
    fn threads_of_self_have_address_correlation() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let threads = live.threads().unwrap();
        assert!(!threads.is_empty());
        assert!(threads.iter().all(|t| t.pid == xmem_windows::current_pid()));
        assert!(threads.iter().any(|t| t.start_address.is_some()));
        assert!(threads.iter().any(|t| t.start_region_base.is_some()));
        assert!(threads.iter().any(|t| t.start_module.is_some()));
    }

    #[test]
    fn memory_source_modules_and_threads_match() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        assert!(!live.modules().unwrap().is_empty());
        assert!(!live.threads().unwrap().is_empty());
    }
```

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-memory --tests`
Expected: FAIL — `modules`/`threads`가 `Unimplemented`를 반환하므로 테스트는 컴파일되지만 **실행 시 실패**한다(`cargo test`로 확인). 컴파일 오류가 아니라 실행 실패가 red다.

Run: `cargo test -p xmem-memory`
Expected: FAIL — `modules_of_self_are_populated` 등 3개 실패(Unimplemented).

- [ ] **Step 3: 구현**

`crates/xmem-memory/src/live.rs` import를 다음으로 교체:

```rust
use xmem_core::{
    MemoryRegion, MemorySource, ModuleInfo, ProcessInfo, ReadOutcome, Result, ThreadInfo, XmemError,
};
use xmem_windows::{
    OwnedHandle, list_raw_modules, list_raw_threads, memory, open_for_query, open_for_read,
    open_thread_for_query, process_info, thread_priority, thread_start_address,
};
```

`LiveProcess` impl에 추가(`region_map` 아래):

```rust
    /// 로드된 모듈 목록. arch는 프로세스 arch를 상속한다(모듈별 arch는 PE 분석에서).
    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(list_raw_modules(self.pid)?
            .into_iter()
            .map(|raw| ModuleInfo {
                name: raw.name,
                base: raw.base,
                size: raw.size,
                path: raw.path,
                arch: Some(self.info.arch),
            })
            .collect())
    }

    /// 스레드 목록 + 시작 주소의 영역/모듈 상관관계. 개별 조회 실패는 None degrade.
    pub fn threads(&self) -> Result<Vec<ThreadInfo>> {
        let raw_threads = list_raw_threads(self.pid)?;
        let regions = self.region_map()?.regions;
        let modules = self.modules()?;
        let mut threads = Vec::with_capacity(raw_threads.len());
        for raw in raw_threads {
            let (priority, start_address) = match open_thread_for_query(raw.tid) {
                Ok(handle) => (thread_priority(&handle), thread_start_address(&handle)),
                Err(_) => (None, None),
            };
            let start_region_base = start_address.and_then(|address| {
                regions
                    .iter()
                    .find(|region| contains(region, address))
                    .map(|region| region.base)
            });
            let start_module = start_address.and_then(|address| {
                modules
                    .iter()
                    .find(|module| contains_module(module, address))
                    .map(|module| module.name.clone())
            });
            threads.push(ThreadInfo {
                tid: raw.tid,
                pid: raw.pid,
                priority,
                start_address,
                start_region_base,
                start_module,
            });
        }
        Ok(threads)
    }
```

파일 하단(impl 밖)에 private 헬퍼 추가:

```rust
fn contains(region: &MemoryRegion, address: u64) -> bool {
    address >= region.base && address < region.base.saturating_add(region.size)
}

fn contains_module(module: &ModuleInfo, address: u64) -> bool {
    address >= module.base && address < module.base.saturating_add(module.size)
}
```

`MemorySource` impl의 `modules`/`threads` 교체:

```rust
    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        self.modules()
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        self.threads()
    }
```

- [ ] **Step 4: green 확인**

Run: `cargo test -p xmem-memory`
Expected: PASS — 기존 17 − 1(unimplemented 삭제) + 3 = 19.

- [ ] **Step 5: 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-memory --all-targets -- -D warnings
git add crates/xmem-memory
git commit -m "feat(memory): LiveProcess 모듈/스레드와 시작 주소 상관관계"
```

---

### Task 4: CLI — `modules` / `threads` 명령

**Files:**
- Modify: `crates/xmem-cli/src/commands/render.rs` (`opt_hex`, `opt_num` 이동)
- Modify: `crates/xmem-cli/src/commands/process.rs` (`opt_num` 제거 + import)
- Modify: `crates/xmem-cli/src/commands/modules.rs`
- Modify: `crates/xmem-cli/src/commands/threads.rs`

**Interfaces:**
- Consumes: `xmem_memory::LiveProcess`, `crate::output::{emit_json, resolve_mode, success_envelope, OutputMode}`, `crate::commands::render::{human_size, truncate, truncate_tail, opt_hex, opt_num}`.
- Produces: `modules::run(&PidArg, &GlobalArgs)`, `threads::run(&PidArg, &GlobalArgs)` — Human 표 + JSON envelope.

- [ ] **Step 1: 테스트 먼저 (red)**

`crates/xmem-cli/src/commands/render.rs` 테스트에 추가:

```rust
    #[test]
    fn opt_hex_formats_optional_addresses() {
        assert_eq!(opt_hex(Some(0x7ffb_1234_5678)), "0x00007ffb12345678");
        assert_eq!(opt_hex(None), "-");
    }
```

`crates/xmem-cli/src/commands/modules.rs`에 테스트 모듈 추가:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::ProcessArch;

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: Some(1),
            name: "target.exe".to_string(),
            image_path: Some(r"C:\lab\target.exe".to_string()),
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_module(name: &str, base: u64, path: Option<&str>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base,
            size: 0x1000,
            path: path.map(str::to_string),
            arch: Some(ProcessArch::X64),
        }
    }

    #[test]
    fn render_modules_lists_rows_and_summary() {
        let modules = vec![
            sample_module("target.exe", 0x0001_4000_0000, Some(r"C:\lab\target.exe")),
            sample_module("kernel32.dll", 0x7ffb_0000, None),
        ];
        let text = render_modules(&sample_info(), &modules);
        assert!(text.contains("2 modules"));
        assert!(text.contains("0x0000000140000000"));
        assert!(text.contains("target.exe"));
        assert!(text.contains("kernel32.dll"));
    }

    #[test]
    fn modules_json_payload_shape() {
        let modules = vec![sample_module("target.exe", 0x0001_4000_0000, None)];
        let value = json_payload(&sample_info(), &modules);
        assert_eq!(value["process"]["pid"], 1234);
        assert_eq!(value["module_count"], 1);
        assert_eq!(value["modules"][0]["name"], "target.exe");
        assert_eq!(value["modules"][0]["base"], 0x0001_4000_0000u64);
    }
}
```

`crates/xmem-cli/src/commands/threads.rs`에 테스트 모듈 추가:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::ProcessArch;

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: Some(1),
            name: "target.exe".to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_thread(tid: u32, start: Option<u64>, module: Option<&str>) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1234,
            priority: Some(8),
            start_address: start,
            start_region_base: start.map(|a| a & !0xfff),
            start_module: module.map(str::to_string),
        }
    }

    #[test]
    fn render_threads_shows_correlation() {
        let threads = vec![
            sample_thread(100, Some(0x0001_4000_1234), Some("target.exe")),
            sample_thread(200, None, None),
        ];
        let text = render_threads(&sample_info(), &threads);
        assert!(text.contains("2 threads"));
        assert!(text.contains("target.exe"));
        assert!(text.contains("0x0000000140001234"));
        assert!(text.contains('-'));
    }

    #[test]
    fn threads_json_payload_shape() {
        let threads = vec![sample_thread(100, Some(0x0001_4000_1234), Some("target.exe"))];
        let value = json_payload(&sample_info(), &threads);
        assert_eq!(value["process"]["pid"], 1234);
        assert_eq!(value["thread_count"], 1);
        assert_eq!(value["threads"][0]["tid"], 100);
        assert_eq!(value["threads"][0]["start_module"], "target.exe");
    }
}
```

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — `opt_hex`/`render_modules`/`json_payload`/`render_threads` 없음(E0425/E0422).

- [ ] **Step 3: 구현**

`crates/xmem-cli/src/commands/render.rs`에 추가:

```rust
/// 주소 옵션을 `0x…` 또는 `-`로 렌더한다.
pub(crate) fn opt_hex(value: Option<u64>) -> String {
    value
        .map(|v| format!("0x{v:016x}"))
        .unwrap_or_else(|| "-".to_string())
}

/// 숫자 옵션을 문자열 또는 `-`로 렌더한다.
pub(crate) fn opt_num<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string())
}
```

`crates/xmem-cli/src/commands/process.rs`: `fn opt_num` 정의를 삭제하고 `use crate::commands::render::{opt_num, truncate};`로 교체(기존 truncate import에 합침).

`crates/xmem-cli/src/commands/modules.rs` 전체:

```rust
use xmem_core::{ModuleInfo, ProcessInfo, Result, XmemError};
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::{human_size, truncate, truncate_tail};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(args: &PidArg, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid)?;
    let modules = live.modules()?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value = serde_json::to_value(json_payload(&live.info, &modules))
                .map_err(|e| XmemError::JsonError { reason: e.to_string() })?;
            emit_json(&success_envelope(value));
        }
        OutputMode::Human => print!("{}", render_modules(&live.info, &modules)),
    }
    Ok(())
}

fn render_modules(info: &ProcessInfo, modules: &[ModuleInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}): {} modules\n",
        info.pid,
        info.name,
        modules.len()
    ));
    out.push_str("BASE                SIZE        NAME                 PATH\n");
    for module in modules {
        let path = module
            .path
            .as_deref()
            .map(|p| truncate_tail(p, 60))
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "0x{:016x} {:>10} {:20} {}\n",
            module.base,
            human_size(module.size),
            truncate(&module.name, 20),
            path,
        ));
    }
    out
}

fn json_payload(info: &ProcessInfo, modules: &[ModuleInfo]) -> serde_json::Value {
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "module_count": modules.len(),
        "modules": modules,
    })
}
```

`crates/xmem-cli/src/commands/threads.rs` 전체:

```rust
use xmem_core::{ProcessInfo, Result, ThreadInfo, XmemError};
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::{opt_hex, opt_num};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(args: &PidArg, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid)?;
    let threads = live.threads()?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value = serde_json::to_value(json_payload(&live.info, &threads))
                .map_err(|e| XmemError::JsonError { reason: e.to_string() })?;
            emit_json(&success_envelope(value));
        }
        OutputMode::Human => print!("{}", render_threads(&live.info, &threads)),
    }
    Ok(())
}

fn render_threads(info: &ProcessInfo, threads: &[ThreadInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}): {} threads\n",
        info.pid,
        info.name,
        threads.len()
    ));
    out.push_str("TID      PRIORITY START ADDRESS       REGION              MODULE\n");
    for thread in threads {
        out.push_str(&format!(
            "{:<8} {:>8} {:<20} {:<19} {}\n",
            thread.tid,
            opt_num(thread.priority),
            opt_hex(thread.start_address),
            opt_hex(thread.start_region_base),
            thread.start_module.as_deref().unwrap_or("-"),
        ));
    }
    out
}

fn json_payload(info: &ProcessInfo, threads: &[ThreadInfo]) -> serde_json::Value {
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "thread_count": threads.len(),
        "threads": threads,
    })
}
```

주의: `resolve_mode`/`success_envelope`/`emit_json`의 실제 모듈 경로는 `crates/xmem-cli/src/output.rs`다. `crate::output::` 경로가 컴파일 오류면 memory.rs의 기존 import를 확인해 동일하게 맞춘다.

- [ ] **Step 4: green 확인**

Run: `cargo test -p xmem-cli`
Expected: PASS — 기존 32 + 5 = 37.

- [ ] **Step 5: 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add crates/xmem-cli
git commit -m "feat(cli): modules/threads 명령과 주소 상관관계 출력"
```

---

### Task 5: 문서 + 최종 게이트 + Windows 실검증

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-05-modules-threads.md` (체크박스)

- [ ] **Step 1: README 갱신**

- Status 문구: "현재 **Milestone 5 (Module / Thread)** 완료. 모듈 열거와 스레드 시작 주소 상관관계 분석을 지원한다."
- Status 표에서 `modules` / `threads` 행을 분리해 Implemented로:
  - `modules --pid` (Toolhelp 모듈 열거: base/size/path/arch, `--json`)
  - `threads --pid` (TID, priority, start address → region/module 상관관계, `--json`)
- Quick Start에 `xmem modules --pid <PID>`, `xmem threads --pid <PID>` 추가.
- Limitations: "M5 기준 process/memory/modules/threads 구현"으로 갱신, `GetThreadTimes`(스레드 시간 통계) 미포함 명시, 모듈별 arch는 프로세스 arch 상속(모듈별 정확 arch는 PE 분석 M6), `threads`의 priority는 동적 우선순위이며 조회 실패 시 `-`.
- Roadmap M5 = 완료.

- [ ] **Step 2: architecture.md 갱신**

- Status 표: M5 Module / Thread (modules/threads, 시작 주소 상관관계) Done, M6~M12 Planned.
- Windows API 표 M5 행: 구현됨(`Module32FirstW/NextW`, `Thread32First/Next`, `OpenThread`, `GetThreadPriority`, `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`; `GetThreadTimes`는 후속).
- crate 책임 표: `xmem-memory` 행에 "모듈/스레드 상관관계" 추가.

- [ ] **Step 3: 전체 게이트**

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0; 테스트 합계 123 + 3(windows) + 2(memory 순증) + 5(cli) = **133**: core 32 + windows 48 + memory 19 + cli 37.

- [ ] **Step 4: Windows 실검증**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
# 1) 자기 프로세스 모듈/스레드
cargo run -q -p xmem-cli -- modules --pid $PID
cargo run -q -p xmem-cli -- --json modules --pid $PID
cargo run -q -p xmem-cli -- threads --pid $PID
cargo run -q -p xmem-cli -- --json threads --pid $PID
# 2) 오류 경로 (비관리자)
$lsass = (Get-Process lsass).Id
cargo run -q -p xmem-cli -- modules --pid $lsass
cargo run -q -p xmem-cli -- threads --pid $lsass
cargo run -q -p xmem-cli -- modules --pid 4294967294
# 3) 반복 3회 안정성
```

확인:
1. `modules` ≥1행 + kernel32.dll/ntdll.dll 등 존재, `--json`의 `module_count` > 0.
2. `threads` ≥1행, 일부 행에 `START ADDRESS`/`REGION`/`MODULE`이 채워짐(메인 스레드는 exe 모듈).
3. lsass → `error: access denied: ...` exit 1; bogus PID → `error: process ... has exited` exit 1.
4. 반복 3회 모두 exit 0, 출력 구조 동일.

- [ ] **Step 5: 체크박스 갱신 + 커밋**

이 계획서의 모든 `- [ ]`를 `- [x]`로 바꾸고:

```bash
git add README.md docs/architecture.md docs/plans/milestone-05-modules-threads.md
git commit -m "docs: M5 모듈/스레드 분석 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지:** Module Name/Base/Image Size/Path/Architecture(Task 1/3), Thread TID/PID/State(동적 우선순위)/Start Address(Task 2/3), 시작 주소 → 영역/모듈 상관관계(Task 3), CLI `modules`/`threads` + `--json`(Task 4), 문서/게이트/실검증(Task 5). Detection Rule XMEM-004(Suspicious Thread Start Address)는 M8 Detection Engine에서 이 데이터를 소비한다 — M5 범위 밖.
- **의도적 범위 제외:** `GetThreadTimes`(스레드 시간), Thread State(WaitReason — NtQuerySystemInformation 필요), 모듈별 arch(PE 분석 M6), 모듈 언로드 이력, VAD/PE Section 상세.
- **타입 일관성:** `RawModuleEntry`/`list_raw_modules`(Task 1) → `RawThreadEntry`/`list_raw_threads`/`open_thread_for_query`/`thread_priority`/`thread_start_address`(Task 2) → `LiveProcess::modules/threads`(Task 3) → `render_modules`/`render_threads`/`json_payload`(Task 4). core `ModuleInfo`/`ThreadInfo` 필드는 기존 모델 그대로(M2에서 정의됨, JSON schema 변경 없음).
- **검증 완료 사항:** windows-0.62.2 레지스트리 소스에서 `Module32FirstW/NextW`, `Thread32First/Next`, `THREADENTRY32`/`MODULEENTRY32W` 레이아웃, `OpenThread`, `GetThreadPriority`(Result 아님, 실패값 i32::MAX), `NtQueryInformationThread`+`ThreadQuerySetWin32StartAddress(9)` 시그니처를 확인함.
