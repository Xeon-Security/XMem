# Milestone 2 — Process 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** `xmem process list`와 `xmem process info --pid <PID>`를 구현해 Windows 프로세스 열거·메타데이터 수집을 제공한다.

**Architecture:** Win32 호출은 전부 `xmem-windows`에만 둔다. Toolhelp32 스냅샷 열거(`toolhelp.rs`), 핸들 기반 메타데이터 조회(`process.rs`), 토큰 사용자 조회(`token.rs`)를 저수준 primitive로 만들고, 그 위에 `process_info(pid) -> Result<ProcessInfo>` / `list_processes() -> Result<Vec<ProcessInfo>>` 고수준 API를 올린다. CLI는 고수준 API만 호출하며 사람용 렌더링과 JSON envelope만 담당한다. 모든 조회는 read-only다.

**Tech Stack:** Rust stable (edition 2024, rust-version 1.98), windows 0.62 (기존 + ToolHelp/ProcessStatus/RemoteDesktop/Security/SystemInformation/Wdk feature 추가), chrono 0.4(CLI 날짜 표시), clap/serde/serde_json (기존).

**Spec:** `docs/architecture.md` (M2 Windows API 계획, Data Model, CLI 계약, Host Stability)

## Global Constraints

- 대상: Windows 10/11 x86-64. Rust stable, edition 2024, rust-version 1.98.
- `unsafe`는 `xmem-windows`에만 둔다(workspace lint `unsafe_code = "deny"` + crate 단위 allow). 다른 crate에서 unsafe 금지.
- 일반 분석 명령은 read-only. M2는 프로세스 상태를 변경하지 않는다.
- 런타임 경로에서 `unwrap()`/`expect()` 금지. 실패는 `XmemError`로 구조화해 Context를 포함한다.
- Windows API 서명·상수는 추측하지 않는다. 이 계획의 코드는 windows-0.62.2 레지스트리 소스에서 검증된 시그니처만 사용한다.
- 새 dependency는 정당화된 것만 추가한다. M2에서 `chrono 0.4`(default-features=false, features=["std"])만 추가한다 — FILETIME을 사람이 읽는 UTC 시각으로 표시하기 위함이며, 원래 M7 예정이었으나 M2로 앞당긴다.
- Windows API 호출은 반환값을 검증하고 마지막 오류를 `error_from_win32`/`last_win32_error`로 매핑한다.
- 권한 부족/프로세스 종료/보호된 프로세스에서도 panic하지 않고 구조화된 오류 또는 `None` 필드로 degrade한다.
- CLI: 성공 JSON은 `{schema_version, ok: true, data}` envelope, 오류 JSON은 M1의 기존 envelope. 사람용 출력은 stdout, 로그는 stderr.
- 모든 cargo 명령은 PATH 프리픽스가 필요하다: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH";`
- red 확인은 `cargo check -p <crate> --tests`로 한다 (`cargo check`는 `#[cfg(test)]`를 컴파일하지 않음).
- 각 Task 종료 시 `cargo fmt --all`, `cargo clippy -p <crate> --all-targets -- -D warnings`, `cargo test -p <crate>`를 통과해야 한다.

## Review Focus

스펙이 명시적으로 다루지 않지만 깨지면 사용자가 바로 겪는 입력/실패 모드 5개. 각 항목의 테스트를 담당 Task에 둔다.

1. **권한 부족 프로세스(비관리자에서 lsass/system)** — `process info`는 panic 없이 `access_denied` 구조화 오류로 실패해야 한다. (Task 4 테스트 + Task 6 스모크)
2. **열거 도중 프로세스 종료** — Toolhelp 열거의 `ERROR_NO_MORE_FILES`(18)는 오류가 아니라 정상 종료로 처리해야 한다. (Task 2 테스트)
3. **WOW64(32-bit) 프로세스** — arch가 `x86`으로 보고되고 모듈 스냅샷이 실패로 끝나지 않아야 한다(TH32CS_SNAPMODULE32 동반). (Task 3/4 테스트, Task 6 스모크)
4. **command line/user의 best-effort 조회** — `UNICODE_STRING` 버퍼가 잘못된 offset/홀수 길이여도 bounds check로 `None`이 되어야 하며 UB/panic이 없어야 한다. (Task 3 순수 함수 테스트)
5. **비정상 입력** — 존재하지 않는 PID(0xFFFFFFFE 등)와 이름/경로가 매우 긴 프로세스가 panic 없이 처리되어야 한다. (Task 4 테스트 + Task 5 렌더링 테스트)

---

### Task 1: core — FILETIME → Unix 초 변환

**Files:**
- Modify: `crates/xmem-core/src/model/process.rs` (파일 끝에 함수 추가)

**Interfaces:**
- Consumes: 없음
- Produces: `xmem_core::model::process::filetime_to_unix_secs(ft: u64) -> i64` (model::* 재수출로 `xmem_core::filetime_to_unix_secs` 사용 가능)

- [x] **Step 1: 실패 테스트 작성**

`crates/xmem-core/src/model/process.rs` 끝에 추가:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
    const HUNDRED_NS: u64 = 10_000_000;

    #[test]
    fn unix_epoch_maps_to_zero() {
        assert_eq!(filetime_to_unix_secs(UNIX_EPOCH_FILETIME), 0);
    }

    #[test]
    fn one_second_after_epoch() {
        assert_eq!(filetime_to_unix_secs(UNIX_EPOCH_FILETIME + HUNDRED_NS), 1);
    }

    #[test]
    fn one_second_before_epoch_is_negative() {
        assert_eq!(filetime_to_unix_secs(UNIX_EPOCH_FILETIME - HUNDRED_NS), -1);
    }

    #[test]
    fn zero_filetime_is_1601_epoch() {
        assert_eq!(filetime_to_unix_secs(0), -11_644_473_600);
    }
}
```

- [x] **Step 2: 실패 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo check -p xmem-core --tests`
Expected: FAIL — `cannot find function filetime_to_unix_secs`

- [x] **Step 3: 구현**

`crates/xmem-core/src/model/process.rs`의 `ProcessInfo` 정의 아래(테스트 모듈 위)에 추가:

```rust
/// Windows FILETIME(1601-01-01 기준 100ns 단위)을 Unix epoch 초로 변환한다.
///
/// FILETIME은 unsigned지만 1601~1969 구간은 음수가 되므로 i64로 반환한다.
pub fn filetime_to_unix_secs(ft: u64) -> i64 {
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;
    if ft < UNIX_EPOCH_FILETIME {
        -(((UNIX_EPOCH_FILETIME - ft) / HUNDRED_NS_PER_SEC) as i64)
    } else {
        ((ft - UNIX_EPOCH_FILETIME) / HUNDRED_NS_PER_SEC) as i64
    }
}
```

- [x] **Step 4: 통과 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-core`
Expected: PASS (기존 11개 + 신규 4개)

- [x] **Step 5: 커밋**

```bash
git add crates/xmem-core/src/model/process.rs
git commit -m "feat(core): FILETIME을 Unix 초로 변환하는 헬퍼"
```

---

### Task 2: xmem-windows — Toolhelp 열거와 UTF-16 유틸

**Files:**
- Modify: `crates/xmem-windows/Cargo.toml` (features 추가)
- Create: `crates/xmem-windows/src/util.rs`
- Create: `crates/xmem-windows/src/toolhelp.rs`
- Modify: `crates/xmem-windows/src/lib.rs` (모듈 등록)

**Interfaces:**
- Consumes: `crate::error::{error_from_win32, win32_code_from_hresult}`, `crate::handle::OwnedHandle`
- Produces:
  - `xmem_windows::toolhelp::RawProcessEntry { pub pid: u32, pub ppid: u32, pub name: String, pub thread_count: u32 }`
  - `xmem_windows::toolhelp::list_raw_processes() -> xmem_core::Result<Vec<RawProcessEntry>>`
  - `xmem_windows::toolhelp::count_modules(pid: u32) -> xmem_core::Result<u32>`
  - `xmem_windows::util::utf16_z_to_string(buf: &[u16]) -> String`

- [x] **Step 1: Cargo feature 추가**

`crates/xmem-windows/Cargo.toml`의 `windows` 의존성을 교체:

```toml
windows = { version = "0.62", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_ProcessStatus",
    "Win32_System_RemoteDesktop",
    "Win32_System_SystemInformation",
    "Win32_System_Threading",
    "Wdk_System_SystemServices",
    "Wdk_System_Threading",
] }
```

- [x] **Step 2: 실패 테스트 작성**

`crates/xmem-windows/src/util.rs` 생성:

```rust
//! Windows API 경계에서 쓰는 소형 유틸.

/// NUL 종료 UTF-16 버퍼를 String으로 변환한다(손상된 입력은 lossy 치환).
pub fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_at_nul() {
        let buf = [0x48u16, 0x69, 0x00, 0x58];
        assert_eq!(utf16_z_to_string(&buf), "Hi");
    }

    #[test]
    fn no_nul_uses_whole_buffer() {
        let buf = [0x48u16, 0x69];
        assert_eq!(utf16_z_to_string(&buf), "Hi");
    }

    #[test]
    fn empty_buffer_is_empty_string() {
        assert_eq!(utf16_z_to_string(&[]), "");
    }
}
```

`crates/xmem-windows/src/toolhelp.rs` 생성:

```rust
//! Toolhelp32 스냅샷 기반 열거(read-only).

use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use xmem_core::{Result, XmemError};

use crate::error::{error_from_win32, win32_code_from_hresult};
use crate::handle::OwnedHandle;
use crate::util::utf16_z_to_string;

/// 열거 시점의 최소 프로세스 정보.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub thread_count: u32,
}

fn snapshot(flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, pid: u32) -> Result<OwnedHandle> {
    // SAFETY: flags/pid는 값 타입이고 반환 핸들의 수명은 OwnedHandle이 관리한다.
    let handle = unsafe { CreateToolhelp32Snapshot(flags, pid) };
    match handle {
        Ok(h) => OwnedHandle::new(h).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(e) => Err(error_from_win32("CreateToolhelp32Snapshot", &e)),
    }
}

fn is_no_more_files(err: &windows::core::Error) -> bool {
    win32_code_from_hresult(err.code().0) == ERROR_NO_MORE_FILES.0
}

/// 시스템 전체 프로세스를 열거한다. ERROR_NO_MORE_FILES는 정상 종료다.
pub fn list_raw_processes() -> Result<Vec<RawProcessEntry>> {
    let snap = snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: snap은 유효한 스냅샷 핸들이고 entry는 유효한 포인터다.
    match unsafe { Process32FirstW(snap.raw(), &mut entry) } {
        Ok(()) => {}
        Err(e) if is_no_more_files(&e) => return Ok(out),
        Err(e) => return Err(error_from_win32("Process32FirstW", &e)),
    }
    loop {
        out.push(RawProcessEntry {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name: utf16_z_to_string(&entry.szExeFile),
            thread_count: entry.cntThreads,
        });
        // SAFETY: 위와 동일한 유효 핸들/포인터다.
        match unsafe { Process32NextW(snap.raw(), &mut entry) } {
            Ok(()) => {}
            Err(e) if is_no_more_files(&e) => break,
            Err(e) => return Err(error_from_win32("Process32NextW", &e)),
        }
    }
    Ok(out)
}

/// 대상 프로세스의 로드된 모듈 수를 센다. 32-bit 프로세스도 조회되도록
/// TH32CS_SNAPMODULE32를 함께 요청한다.
pub fn count_modules(pid: u32) -> Result<u32> {
    let snap = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: snap은 유효한 스냅샷 핸들이고 entry는 유효한 포인터다.
    match unsafe { Module32FirstW(snap.raw(), &mut entry) } {
        Ok(()) => {}
        Err(e) if is_no_more_files(&e) => return Ok(0),
        Err(e) => return Err(error_from_win32("Module32FirstW", &e)),
    }
    let mut count = 1u32;
    loop {
        // SAFETY: 위와 동일하다.
        match unsafe { Module32NextW(snap.raw(), &mut entry) } {
            Ok(()) => count += 1,
            Err(e) if is_no_more_files(&e) => break,
            Err(e) => return Err(error_from_win32("Module32NextW", &e)),
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::current_pid;

    #[test]
    fn enumeration_contains_current_process() {
        let pid = current_pid();
        let procs = list_raw_processes().expect("snapshot must succeed");
        assert!(procs.len() > 1, "system must have multiple processes");
        let me = procs.iter().find(|p| p.pid == pid).expect("self must appear");
        assert!(!me.name.is_empty());
        assert!(me.thread_count >= 1);
    }

    #[test]
    fn enumeration_terminates_cleanly() {
        let first = list_raw_processes().expect("first enumeration");
        let second = list_raw_processes().expect("second enumeration");
        assert!(!first.is_empty() && !second.is_empty());
    }

    #[test]
    fn count_modules_of_self_at_least_one() {
        let count = count_modules(current_pid()).expect("module snapshot of self");
        assert!(count >= 1);
    }
}
```

- [x] **Step 3: lib.rs에 모듈 등록**

`crates/xmem-windows/src/lib.rs`에 `pub mod toolhelp;`와 `pub mod util;`을 추가한다 (기존 `pub mod error/handle/process;` 유지, re-export는 기존 것 유지).

- [x] **Step 4: 실패 확인 후 구현 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo check -p xmem-windows --tests`
Expected: Step 2 코드가 전부 있으므로 이 시점에 컴파일 성공해야 한다. (테스트를 먼저 쓰고 구현을 나중에 하는 순서를 지키려면 util.rs 테스트만 먼저 쓰고 check로 실패를 확인한 뒤 나머지를 추가해도 된다.)

- [x] **Step 5: 테스트 + clippy**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-windows; cargo clippy -p xmem-windows --all-targets -- -D warnings`
Expected: PASS (기존 9개 + 신규 6개), clippy 클린

- [x] **Step 6: 커밋**

```bash
git add crates/xmem-windows/Cargo.toml crates/xmem-windows/src/util.rs crates/xmem-windows/src/toolhelp.rs crates/xmem-windows/src/lib.rs
git commit -m "feat(windows): Toolhelp 열거와 UTF-16 유틸"
```

---

### Task 3: xmem-windows — 프로세스 메타데이터 조회

**Files:**
- Modify: `crates/xmem-windows/src/process.rs` (기존 함수 유지 + 추가)
- Create: `crates/xmem-windows/src/token.rs`
- Modify: `crates/xmem-windows/src/lib.rs` (모듈 등록)

**Interfaces:**
- Consumes: `OwnedHandle`, `error_from_win32`, `last_win32_error`
- Produces:
  - `process::open_for_query(pid: u32) -> Result<OwnedHandle>`
  - `process::process_image_path(h: &OwnedHandle) -> Result<String>`
  - `process::process_creation_time(h: &OwnedHandle) -> Result<u64>`
  - `process::map_image_file_machine(machine: u16) -> ProcessArch`
  - `process::process_arch(h: &OwnedHandle) -> Result<ProcessArch>`
  - `process::session_id(pid: u32) -> Result<u32>`
  - `process::memory_counters(h: &OwnedHandle) -> Result<MemoryStats>`
  - `process::process_command_line(h: &OwnedHandle) -> Result<String>`
  - `token::process_user(h: &OwnedHandle) -> Result<String>`

- [x] **Step 1: 실패 테스트 작성**

`crates/xmem-windows/src/process.rs`의 기존 `mod tests`에 추가:

```rust
    #[test]
    fn image_path_of_self_ends_with_exe() {
        let handle = open_process(current_pid(), PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let path = process_image_path(&handle).expect("own image path");
        assert!(path.to_lowercase().ends_with(".exe"), "unexpected path: {path}");
    }

    #[test]
    fn arch_of_self_matches_build_target() {
        let handle = open_for_query(current_pid()).unwrap();
        let arch = process_arch(&handle).expect("IsWow64Process2");
        let expected = if cfg!(target_arch = "x86_64") {
            ProcessArch::X64
        } else if cfg!(target_arch = "x86") {
            ProcessArch::X86
        } else {
            ProcessArch::Unknown
        };
        assert_eq!(arch, expected);
    }

    #[test]
    fn map_machine_values() {
        assert_eq!(map_image_file_machine(34404), ProcessArch::X64);
        assert_eq!(map_image_file_machine(332), ProcessArch::X86);
        assert_eq!(map_image_file_machine(43620), ProcessArch::Arm64);
        assert_eq!(map_image_file_machine(0), ProcessArch::Unknown);
        assert_eq!(map_image_file_machine(0xFFFF), ProcessArch::Unknown);
    }

    #[test]
    fn session_id_of_self_succeeds() {
        session_id(current_pid()).expect("ProcessIdToSessionId must work for self");
    }

    #[test]
    fn memory_counters_of_self_nonzero() {
        let handle = open_for_query(current_pid()).unwrap();
        let stats = memory_counters(&handle).expect("memory counters");
        assert!(stats.working_set > 0);
    }

    #[test]
    fn creation_time_of_self_is_after_1970() {
        let handle = open_for_query(current_pid()).unwrap();
        let ft = process_creation_time(&handle).expect("GetProcessTimes");
        assert!(ft > 116_444_736_000_000_000, "FILETIME before unix epoch: {ft}");
    }

    #[test]
    fn command_line_of_self_best_effort() {
        let handle = open_for_query(current_pid()).unwrap();
        if let Ok(cmd) = process_command_line(&handle) {
            assert!(cmd.to_lowercase().contains(".exe"), "unexpected cmdline: {cmd}");
        }
    }

    #[test]
    fn read_unicode_string_bounds() {
        let text: Vec<u16> = "hello".encode_utf16().collect();
        let base = text.as_ptr() as usize;
        let us = UNICODE_STRING {
            Length: (text.len() * 2) as u16,
            MaximumLength: (text.len() * 2) as u16,
            Buffer: windows::core::PWSTR(text.as_ptr() as *mut u16),
        };
        assert_eq!(read_unicode_string(&us, base, text.len() * 2).as_deref(), Some("hello"));
        assert_eq!(read_unicode_string(&us, base + 4096, text.len() * 2), None);
        let odd = UNICODE_STRING { Length: 3, ..us };
        assert_eq!(read_unicode_string(&odd, base, text.len() * 2), None);
    }
```

`crates/xmem-windows/src/token.rs` 생성:

```rust
//! 프로세스 토큰 사용자 조회(read-only).

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows::core::PCWSTR;
use xmem_core::{Result, XmemError};

use crate::error::last_win32_error;
use crate::handle::OwnedHandle;

/// 프로세스 토큰의 사용자 SID를 "DOMAIN\\user" 형태로 돌려준다.
pub fn process_user(handle: &OwnedHandle) -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: handle은 유효한 프로세스 핸들이고 token은 유효한 포인터다.
    unsafe { OpenProcessToken(handle.raw(), TOKEN_QUERY, &mut token) }
        .map_err(|_| last_win32_error("OpenProcessToken"))?;
    let token = OwnedHandle::new(token).ok_or(XmemError::InvalidHandle { handle: 0 })?;

    let mut len = 0u32;
    // 첫 호출은 ERROR_INSUFFICIENT_BUFFER로 실패하는 것이 정상 흐름이다.
    // SAFETY: null 버퍼 + 0 길이 질의는 표준 패턴이다.
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut len) };
    if len == 0 {
        return Err(last_win32_error("GetTokenInformation"));
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buf는 8바이트 정렬되어 있고 len 이상의 크기를 가진다.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            len,
            &mut len,
        )
    }
    .map_err(|_| last_win32_error("GetTokenInformation"))?;
    // SAFETY: 성공 시 buf 선두에 TOKEN_USER가 기록되어 있다.
    let user: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = SID_NAME_USE(0);
    // SAFETY: user.User.Sid는 위 호출이 채운 유효한 SID다. 길이 질의 호출이다.
    let _ = unsafe {
        LookupAccountSidW(
            None::<&PCWSTR>,
            user.User.Sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut sid_type,
        )
    };
    if name_len == 0 {
        return Err(last_win32_error("LookupAccountSidW"));
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: 두 버퍼는 질의한 길이만큼 확보되어 있다.
    unsafe {
        LookupAccountSidW(
            None::<&PCWSTR>,
            user.User.Sid,
            Some(windows::core::PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(windows::core::PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    }
    .map_err(|_| last_win32_error("LookupAccountSidW"))?;
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{current_pid, open_for_query};

    #[test]
    fn user_of_self_is_nonempty() {
        let handle = open_for_query(current_pid()).unwrap();
        let user = process_user(&handle).expect("token user of self");
        assert!(!user.is_empty());
    }
}
```

- [x] **Step 2: 실패 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo check -p xmem-windows --tests`
Expected: FAIL — `cannot find function process_image_path / open_for_query / ...` (token.rs 미등록 시 모듈 오류 포함)

- [x] **Step 3: 구현**

`crates/xmem-windows/src/process.rs`에 use 추가:

```rust
use std::mem::size_of;

use windows::Win32::Foundation::{
    FILETIME, STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::SystemInformation::{
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_MACHINE_UNKNOWN,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, IsWow64Process2, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::Wdk::System::SystemServices::VM_COUNTERS_EX;
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation, ProcessVmCounters};
use windows::core::{PWSTR, PCWSTR};
use xmem_core::{MemoryStats, ProcessArch};
```

함수 추가:

```rust
/// QUERY_INFORMATION으로 열고, 거부되면 LIMITED로 재시도한다.
pub fn open_for_query(pid: u32) -> Result<OwnedHandle> {
    match open_process(
        pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
    ) {
        Ok(h) => Ok(h),
        Err(XmemError::AccessDenied { .. }) => {
            open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
        }
        Err(e) => Err(e),
    }
}

pub fn process_image_path(handle: &OwnedHandle) -> Result<String> {
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: handle은 유효하고 buf/len은 유효한 버퍼와 길이다.
    unsafe {
        QueryFullProcessImageNameW(handle.raw(), PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
    }
    .map_err(|_| last_win32_error("QueryFullProcessImageNameW"))?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

pub fn process_creation_time(handle: &OwnedHandle) -> Result<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: handle은 유효하고 네 포인터 모두 유효하다.
    unsafe { GetProcessTimes(handle.raw(), &mut creation, &mut exit, &mut kernel, &mut user) }
        .map_err(|_| last_win32_error("GetProcessTimes"))?;
    Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
}

/// IMAGE_FILE_MACHINE 값을 XMem 아키텍처 분류로 매핑한다.
pub fn map_image_file_machine(machine: u16) -> ProcessArch {
    match machine {
        m if m == IMAGE_FILE_MACHINE_AMD64.0 => ProcessArch::X64,
        m if m == IMAGE_FILE_MACHINE_I386.0 => ProcessArch::X86,
        m if m == IMAGE_FILE_MACHINE_ARM64.0 => ProcessArch::Arm64,
        _ => ProcessArch::Unknown,
    }
}

pub fn process_arch(handle: &OwnedHandle) -> Result<ProcessArch> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: handle은 유효하고 두 포인터 모두 유효하다.
    unsafe { IsWow64Process2(handle.raw(), &mut process_machine, Some(&mut native_machine)) }
        .map_err(|_| last_win32_error("IsWow64Process2"))?;
    let effective = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    };
    Ok(map_image_file_machine(effective.0))
}

pub fn session_id(pid: u32) -> Result<u32> {
    let mut session = 0u32;
    // SAFETY: 값 인자와 유효 포인터만 사용한다.
    unsafe { ProcessIdToSessionId(pid, &mut session) }
        .map_err(|_| last_win32_error("ProcessIdToSessionId"))?;
    Ok(session)
}

/// VM 카운터(NtQueryInformationProcess)를 우선 사용하고, 실패하면
/// GetProcessMemoryInfo로 fallback한다. fallback 경로에서는 VirtualSize를
/// 알 수 없어 0으로 둔다.
pub fn memory_counters(handle: &OwnedHandle) -> Result<MemoryStats> {
    if let Some(stats) = vm_counters(handle) {
        return Ok(stats);
    }
    get_process_memory_info(handle)
}

fn vm_counters(handle: &OwnedHandle) -> Option<MemoryStats> {
    let mut counters = VM_COUNTERS_EX::default();
    let mut len = 0u32;
    // SAFETY: handle은 유효하고 counters/len은 유효하다.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessVmCounters,
            &mut counters as *mut _ as *mut core::ffi::c_void,
            size_of::<VM_COUNTERS_EX>() as u32,
            &mut len,
        )
    };
    if status.0 < 0 {
        return None;
    }
    Some(MemoryStats {
        working_set: counters.WorkingSetSize as u64,
        private_bytes: counters.PrivateUsage as u64,
        commit: counters.PagefileUsage as u64,
        virtual_size: counters.VirtualSize as u64,
    })
}

fn get_process_memory_info(handle: &OwnedHandle) -> Result<MemoryStats> {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: handle은 유효하고 counters는 cb가 설정된 유효 버퍼다.
    unsafe {
        GetProcessMemoryInfo(
            handle.raw(),
            &mut counters as *mut _ as *mut _,
            size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
    }
    .map_err(|_| last_win32_error("GetProcessMemoryInfo"))?;
    Ok(MemoryStats {
        working_set: counters.WorkingSetSize as u64,
        private_bytes: counters.PrivateUsage as u64,
        commit: counters.PagefileUsage as u64,
        virtual_size: 0,
    })
}

/// NtQueryInformationProcess(ProcessCommandLineInformation)으로 명령줄을 읽는다.
pub fn process_command_line(handle: &OwnedHandle) -> Result<String> {
    let mut len = 0u32;
    // SAFETY: 길이 질의 호출(null 버퍼)이다.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    if status != STATUS_INFO_LENGTH_MISMATCH || len == 0 {
        return Err(XmemError::WindowsApi {
            api: "NtQueryInformationProcess(ProcessCommandLineInformation)",
            code: status.0 as u32,
            message: format!("unexpected NTSTATUS 0x{:08X}", status.0 as u32),
        });
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buf는 8바이트 정렬이고 len 이상의 바이트를 담는다.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessCommandLineInformation,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            (buf.len() * 8) as u32,
            &mut len,
        )
    };
    if status.0 < 0 {
        return Err(XmemError::WindowsApi {
            api: "NtQueryInformationProcess(ProcessCommandLineInformation)",
            code: status.0 as u32,
            message: format!("NTSTATUS 0x{:08X}", status.0 as u32),
        });
    }
    // SAFETY: 성공 시 buf 선두에 UNICODE_STRING 헤더가 기록되어 있다(8바이트 정렬).
    let us: &UNICODE_STRING = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
    read_unicode_string(us, buf.as_ptr() as usize, buf.len() * 8).ok_or(XmemError::WindowsApi {
        api: "NtQueryInformationProcess(ProcessCommandLineInformation)",
        code: 0,
        message: "UNICODE_STRING이 버퍼 범위를 벗어남".to_string(),
    })
}

/// 버퍼 [base, base+byte_len) 안을 가리키는 UNICODE_STRING만 안전하게 해석한다.
fn read_unicode_string(us: &UNICODE_STRING, base: usize, byte_len: usize) -> Option<String> {
    let start = us.Buffer.0 as usize;
    let len = us.Length as usize;
    if len == 0 {
        return Some(String::new());
    }
    if !len.is_multiple_of(2) || start < base {
        return None;
    }
    let offset = start - base;
    if offset + len > byte_len {
        return None;
    }
    // SAFETY: 위에서 [offset, offset+len)이 버퍼 범위 안임을 확인했다.
    let units = unsafe { std::slice::from_raw_parts((base as *const u16).add(offset / 2), len / 2) };
    Some(String::from_utf16_lossy(units))
}
```

- [x] **Step 4: 테스트 + clippy**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-windows; cargo clippy -p xmem-windows --all-targets -- -D warnings`
Expected: PASS, clippy 클린

주의: `read_unicode_string`은 `#[cfg(test)]`에서 직접 호출하므로 테스트 모듈에서 `use super::*;`로 접근 가능해야 한다(비공개 함수 OK).

- [x] **Step 5: 커밋**

```bash
git add crates/xmem-windows/src/process.rs crates/xmem-windows/src/token.rs crates/xmem-windows/src/lib.rs
git commit -m "feat(windows): 프로세스 경로/arch/session/메모리/명령줄/사용자 조회"
```

---

### Task 4: xmem-windows — 고수준 process_info / list_processes

**Files:**
- Modify: `crates/xmem-windows/src/process.rs`

**Interfaces:**
- Consumes: Task 2의 `toolhelp::{list_raw_processes, count_modules}`, Task 3의 조회 함수들
- Produces:
  - `process::process_info(pid: u32) -> Result<ProcessInfo>`
  - `process::list_processes() -> Result<Vec<ProcessInfo>>`

- [x] **Step 1: 실패 테스트 작성**

`crates/xmem-windows/src/process.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn process_info_of_self_is_populated() {
        let pid = current_pid();
        let info = process_info(pid).expect("info of self");
        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty());
        assert!(info.image_path.as_deref().unwrap_or("").to_lowercase().ends_with(".exe"));
        assert!(info.ppid.is_some());
        assert!(info.thread_count.unwrap_or(0) >= 1);
        assert!(info.module_count.unwrap_or(0) >= 1);
        assert!(info.session_id.is_some());
        assert!(info.memory_stats.map(|m| m.working_set > 0).unwrap_or(false));
        assert!(info.creation_time.is_some());
        assert!(info.user.is_some());
    }

    #[test]
    fn process_info_bogus_pid_errs_structured() {
        let err = match process_info(0xFFFF_FFFE) {
            Ok(_) => panic!("bogus pid must fail"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            XmemError::AccessDenied { .. }
                | XmemError::WindowsApi { .. }
                | XmemError::ProcessExited { .. }
        ));
    }

    #[test]
    fn list_processes_is_sorted_and_contains_self() {
        let pid = current_pid();
        let list = list_processes().expect("list");
        assert!(list.windows(2).all(|w| w[0].pid <= w[1].pid), "must be pid-sorted");
        assert!(list.iter().any(|p| p.pid == pid));
    }
```

- [x] **Step 2: 실패 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo check -p xmem-windows --tests`
Expected: FAIL — `cannot find function process_info / list_processes`

- [x] **Step 3: 구현**

`crates/xmem-windows/src/process.rs`에 추가:

```rust
use xmem_core::ProcessInfo;
use crate::toolhelp;

/// 단일 프로세스의 메타데이터를 수집한다. 열거에 없으면 ProcessExited,
/// 열 수 없으면 AccessDenied를 돌려준다. 핸들이 열린 뒤의 개별 조회 실패는
/// None 필드로 degrade한다.
pub fn process_info(pid: u32) -> Result<ProcessInfo> {
    let raw = toolhelp::list_raw_processes()?
        .into_iter()
        .find(|e| e.pid == pid)
        .ok_or(XmemError::ProcessExited { pid })?;
    let handle = match open_for_query(pid) {
        Ok(h) => h,
        Err(XmemError::WindowsApi { code: 87, .. }) => return Err(XmemError::ProcessExited { pid }),
        Err(e) => return Err(e),
    };
    Ok(ProcessInfo {
        pid,
        ppid: Some(raw.ppid),
        name: raw.name,
        image_path: process_image_path(&handle).ok(),
        arch: process_arch(&handle).unwrap_or(ProcessArch::Unknown),
        session_id: session_id(pid).ok(),
        creation_time: process_creation_time(&handle).ok(),
        command_line: process_command_line(&handle).ok(),
        user: crate::token::process_user(&handle).ok(),
        memory_stats: memory_counters(&handle).ok(),
        thread_count: Some(raw.thread_count),
        module_count: toolhelp::count_modules(pid).ok(),
    })
}

/// 시스템 전체 프로세스를 ProcessInfo로 열거한다. 개별 프로세스의
/// 메타데이터 조회 실패는 None 필드로 degrade하고 전체를 중단하지 않는다.
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    let mut raws = toolhelp::list_raw_processes()?;
    raws.sort_by_key(|e| e.pid);
    Ok(raws
        .into_iter()
        .map(|raw| {
            let mut info = ProcessInfo {
                pid: raw.pid,
                ppid: Some(raw.ppid),
                name: raw.name,
                image_path: None,
                arch: ProcessArch::Unknown,
                session_id: session_id(raw.pid).ok(),
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: Some(raw.thread_count),
                module_count: None,
            };
            if let Ok(handle) = open_for_query(raw.pid) {
                info.image_path = process_image_path(&handle).ok();
                info.arch = process_arch(&handle).unwrap_or(ProcessArch::Unknown);
            }
            info
        })
        .collect())
}
```

- [x] **Step 4: 테스트 + clippy**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-windows; cargo clippy -p xmem-windows --all-targets -- -D warnings`
Expected: PASS (Task 3까지 합쳐 windows crate 테스트 22개 안팎), clippy 클린

- [x] **Step 5: 커밋**

```bash
git add crates/xmem-windows/src/process.rs
git commit -m "feat(windows): process_info/list_processes 고수준 API"
```

---

### Task 5: xmem-cli — process list/info 구현

**Files:**
- Modify: `Cargo.toml` (workspace deps에 chrono)
- Modify: `crates/xmem-cli/Cargo.toml` (chrono 추가)
- Modify: `crates/xmem-core/src/error.rs` (`JsonError` variant 추가)
- Modify: `crates/xmem-cli/src/output.rs` (success_envelope/emit_json/error_kind)
- Modify: `crates/xmem-cli/src/commands/process.rs` (run/render 구현)

**Interfaces:**
- Consumes: `xmem_windows::{process_info, list_processes}`, `xmem_core::filetime_to_unix_secs`
- Produces:
  - `output::success_envelope(data: serde_json::Value) -> serde_json::Value`
  - `output::emit_json(value: &serde_json::Value)`
  - `process::render_list(infos: &[ProcessInfo]) -> String`
  - `process::render_info(info: &ProcessInfo) -> String`

- [x] **Step 1: 실패 테스트 작성**

`crates/xmem-cli/src/commands/process.rs`를 테스트 포함 스켈레톤으로 교체(구현은 다음 Step):

```rust
use crate::cli::{GlobalArgs, ProcessCmd};
use crate::output::{emit_json, resolve_mode, success_envelope, OutputMode};
use xmem_core::{ProcessArch, ProcessInfo, Result, XmemError};

pub fn run(_cmd: &ProcessCmd, _global: &GlobalArgs) -> Result<()> {
    Err(XmemError::Unimplemented { feature: "process" })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(1000),
            name: format!("proc{pid}.exe"),
            image_path: Some(format!("C:\\Windows\\System32\\proc{pid}.exe")),
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: Some(116_444_736_000_000_000),
            command_line: Some(format!("\"C:\\Windows\\System32\\proc{pid}.exe\"")),
            user: Some("DOMAIN\\user".to_string()),
            memory_stats: Some(xmem_core::MemoryStats {
                working_set: 1024 * 1024,
                private_bytes: 512 * 1024,
                commit: 768 * 1024,
                virtual_size: 2 * 1024 * 1024,
            }),
            thread_count: Some(4),
            module_count: Some(30),
        }
    }

    #[test]
    fn render_list_has_header_and_rows() {
        let out = render_list(&[sample(10), sample(20)]);
        assert!(out.contains("PID"));
        assert!(out.contains("proc10.exe"));
        assert!(out.contains("proc20.exe"));
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn render_list_dashes_missing_fields() {
        let mut info = sample(10);
        info.image_path = None;
        info.session_id = None;
        info.thread_count = None;
        let out = render_list(&[info]);
        assert!(out.contains('-'));
    }

    #[test]
    fn render_list_truncates_long_name() {
        let mut info = sample(10);
        info.name = "a".repeat(80);
        let out = render_list(&[info]);
        assert!(out.contains("..."));
    }

    #[test]
    fn render_info_formats_creation_time_as_utc() {
        let out = render_info(&sample(10));
        assert!(out.contains("1970-01-01 00:00:00 UTC"), "{out}");
        assert!(out.contains("DOMAIN\\user"));
        assert!(out.contains("1.0 MiB"));
    }

    #[test]
    fn render_info_dashes_missing_memory() {
        let mut info = sample(10);
        info.memory_stats = None;
        info.command_line = None;
        let out = render_info(&info);
        assert!(out.contains('-'));
    }
}
```

`crates/xmem-cli/src/output.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn success_envelope_has_data_and_ok_true() {
        let v = success_envelope(serde_json::json!({"x": 1}));
        assert_eq!(v["ok"], true);
        assert_eq!(v["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(v["data"]["x"], 1);
    }

    #[test]
    fn json_error_kind_is_mapped() {
        let err = XmemError::JsonError { reason: "boom".to_string() };
        assert_eq!(error_envelope(&err)["error"]["kind"], "json_error");
    }
```

`crates/xmem-core/src/error.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn json_error_display_contains_reason() {
        let err = XmemError::JsonError { reason: "unexpected token".to_string() };
        assert!(err.to_string().contains("unexpected token"));
    }
```

- [x] **Step 2: 실패 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo check -p xmem-cli --tests; cargo check -p xmem-core --tests`
Expected: FAIL — `cannot find function render_list / render_info / success_envelope / variant JsonError`

- [x] **Step 3: 구현**

`Cargo.toml` workspace dependencies에 추가:

```toml
chrono = { version = "0.4", default-features = false, features = ["std"] }
```

`crates/xmem-cli/Cargo.toml` dependencies에 추가:

```toml
chrono.workspace = true
```

`crates/xmem-core/src/error.rs`의 `XmemError` enum에 variant 추가(`Io` 위 등 자연스러운 위치):

```rust
    #[error("json serialization failed: {reason}")]
    JsonError { reason: String },
```

`crates/xmem-cli/src/output.rs`에 추가 + `error_kind`에 arm 추가:

```rust
pub fn success_envelope(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "ok": true,
        "data": data,
    })
}

pub fn emit_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(e) => println!("{{\"ok\":false,\"error\":{{\"kind\":\"json_error\",\"message\":\"{e}\"}}}}"),
    }
}
```

```rust
        XmemError::JsonError { .. } => "json_error",
```

`crates/xmem-cli/src/commands/process.rs` 구현부 교체:

```rust
pub fn run(cmd: &ProcessCmd, global: &GlobalArgs) -> Result<()> {
    match (cmd, resolve_mode(global.json)) {
        (ProcessCmd::List, OutputMode::Json) => {
            let infos = xmem_windows::list_processes()?;
            let value = serde_json::to_value(&infos)
                .map_err(|e| XmemError::JsonError { reason: e.to_string() })?;
            emit_json(&success_envelope(serde_json::json!({ "processes": value })));
        }
        (ProcessCmd::List, OutputMode::Human) => {
            let infos = xmem_windows::list_processes()?;
            println!("{}", render_list(&infos));
        }
        (ProcessCmd::Info(args), OutputMode::Json) => {
            let info = xmem_windows::process_info(args.pid)?;
            let value = serde_json::to_value(&info)
                .map_err(|e| XmemError::JsonError { reason: e.to_string() })?;
            emit_json(&success_envelope(value));
        }
        (ProcessCmd::Info(args), OutputMode::Human) => {
            let info = xmem_windows::process_info(args.pid)?;
            println!("{}", render_info(&info));
        }
    }
    Ok(())
}

fn opt_num<T: std::fmt::Display>(v: Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "-".to_string(),
    }
}

fn arch_str(arch: ProcessArch) -> &'static str {
    match arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "-",
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

pub fn render_list(infos: &[ProcessInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:>6}  {:>6}  {:>7}  {:>7}  {:<5}  {:<24}  {}\n",
        "PID", "PPID", "THREADS", "SESSION", "ARCH", "NAME", "PATH"
    ));
    for info in infos {
        out.push_str(&format!(
            "{:>6}  {:>6}  {:>7}  {:>7}  {:<5}  {:<24}  {}\n",
            info.pid,
            opt_num(info.ppid),
            opt_num(info.thread_count),
            opt_num(info.session_id),
            arch_str(info.arch),
            truncate(&info.name, 24),
            truncate(info.image_path.as_deref().unwrap_or("-"), 60),
        ));
    }
    out.trim_end().to_string()
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn format_filetime(ft: u64) -> String {
    let secs = xmem_core::filetime_to_unix_secs(ft);
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{secs} (unix secs)"),
    }
}

fn field(name: &str, value: String) -> String {
    format!("{:<14} {}\n", format!("{name}:"), value)
}

pub fn render_info(info: &ProcessInfo) -> String {
    let mut out = String::new();
    out.push_str(&field("PID", info.pid.to_string()));
    out.push_str(&field("Name", info.name.clone()));
    out.push_str(&field("Path", info.image_path.clone().unwrap_or_else(|| "-".to_string())));
    out.push_str(&field("Architecture", arch_str(info.arch).to_string()));
    out.push_str(&field("Session", opt_num(info.session_id)));
    out.push_str(&field(
        "Created",
        info.creation_time
            .map(format_filetime)
            .unwrap_or_else(|| "-".to_string()),
    ));
    out.push_str(&field("Parent PID", opt_num(info.ppid)));
    out.push_str(&field("User", info.user.clone().unwrap_or_else(|| "-".to_string())));
    out.push_str(&field(
        "Command Line",
        info.command_line.clone().unwrap_or_else(|| "-".to_string()),
    ));
    match &info.memory_stats {
        Some(stats) => {
            out.push_str(&field("Working Set", mib(stats.working_set)));
            out.push_str(&field("Private", mib(stats.private_bytes)));
            out.push_str(&field("Commit", mib(stats.commit)));
            let virtual_size = if stats.virtual_size == 0 {
                "-".to_string()
            } else {
                mib(stats.virtual_size)
            };
            out.push_str(&field("Virtual", virtual_size));
        }
        None => out.push_str(&field("Memory", "-".to_string())),
    }
    out.push_str(&field("Threads", opt_num(info.thread_count)));
    out.push_str(&field("Modules", opt_num(info.module_count)));
    out.trim_end().to_string()
}
```

- [x] **Step 4: 테스트 + clippy**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-core -p xmem-cli; cargo clippy -p xmem-cli --all-targets -- -D warnings`
Expected: PASS (cli 기존 8 + 신규 7), clippy 클린

- [x] **Step 5: 스모크 확인 (Windows 실검증)**

Run:
```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo run -q -p xmem-cli -- process list
cargo run -q -p xmem-cli -- process info --pid $PID
cargo run -q -p xmem-cli -- --json process list | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty processes | Measure-Object
```
Expected: 표가 출력되고, 자기 PID 정보에 Created/User/Command Line/Memory가 채워지며, JSON은 파싱되어 프로세스 수가 1 이상.

- [x] **Step 6: 커밋**

```bash
git add Cargo.toml Cargo.lock crates/xmem-cli/Cargo.toml crates/xmem-core/src/error.rs crates/xmem-cli/src/output.rs crates/xmem-cli/src/commands/process.rs
git commit -m "feat(cli): process list/info 구현과 JSON envelope"
```

---

### Task 6: 문서 갱신 + 최종 게이트 + Windows 검증

**Files:**
- Modify: `README.md` (Status 표 M2 행)
- Modify: `docs/architecture.md` (chrono 도입 시점, M2 상태)

**Interfaces:**
- Consumes: Task 1~5 전체
- Produces: 없음 (검증/문서)

- [x] **Step 1: README Status 갱신**

`README.md`의 Status 표에서 M2 행을 `Implemented`로 바꾸고, 구현 범위에 `process list`, `process info`(경로/arch/session/생성시각/사용자/명령줄/메모리/스레드/모듈 수)를 명시한다. 아직 없는 기능(M3~)은 `Planned` 유지.

- [x] **Step 2: architecture.md 갱신**

`docs/architecture.md`의 dependency 표에서 chrono 도입 시점을 M7 → M2로 수정하고, M2 섹션에 "구현 완료(process list/info)"를 반영한다.

- [x] **Step 3: 전체 게이트**

Run:
```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```
Expected: 전부 exit 0, 테스트 전부 green.

- [x] **Step 4: Windows 실검증 (오류 경로 포함)**

Run:
```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$lsass = (Get-Process lsass).Id
cargo run -q -p xmem-cli -- process info --pid $lsass; "exit=$LASTEXITCODE"
cargo run -q -p xmem-cli -- --json process info --pid $lsass; "exit=$LASTEXITCODE"
cargo run -q -p xmem-cli -- process info --pid 4294967294; "exit=$LASTEXITCODE"
cargo run -q -p xmem-cli -- process list > $null; "exit=$LASTEXITCODE"
cargo run -q -p xmem-cli -- process list > $null; "exit=$LASTEXITCODE"
cargo run -q -p xmem-cli -- process list > $null; "exit=$LASTEXITCODE"
```
Expected: lsass(비관리자)는 `access denied` 구조화 오류 + exit=1 (panic 없음), 존재하지 않는 PID는 오류 + exit=1, list 반복 3회 모두 exit=0. WOW64 프로세스가 있으면 `xmem process list`에서 arch가 `x86`으로 보이는지 눈으로 확인한다(예: `Get-Process`로 32-bit 프로세스 하나 지정해 `process info`).

- [x] **Step 5: 계획서 체크박스 갱신 + 커밋**

이 파일의 체크박스를 전부 `- [x]`로 바꾼다.

```bash
git add README.md docs/architecture.md docs/plans/milestone-02-process.md
git commit -m "docs: M2 프로세스 분석 상태 반영"
```

---

## Self-Review Notes

- 스펙 커버리지: M2 API 계획(Toolhelp 열거, QueryFullProcessImageNameW, GetProcessTimes, IsWow64Process2, ProcessIdToSessionId, GetProcessMemoryInfo/VM counters, 토큰 사용자, NtQueryInformationProcess command line) 전부 Task 2~4에 매핑됨. CLI `process list/info`와 `--json`은 Task 5.
- 검증한 시그니처: `OpenProcess(PROCESS_ACCESS_RIGHTS, bool, u32) -> Result<HANDLE>`, `CreateToolhelp32Snapshot(CREATE_TOOLHELP_SNAPSHOT_FLAGS, u32) -> Result<HANDLE>`, `Process32FirstW/NextW(HANDLE, *mut PROCESSENTRY32W) -> Result<()>`, `Module32FirstW/NextW(HANDLE, *mut MODULEENTRY32W) -> Result<()>`, `QueryFullProcessImageNameW(HANDLE, PROCESS_NAME_FORMAT, PWSTR, *mut u32) -> Result<()>`, `IsWow64Process2(HANDLE, *mut IMAGE_FILE_MACHINE, Option<*mut IMAGE_FILE_MACHINE>) -> Result<()>`, `GetProcessTimes(HANDLE, *mut FILETIME x4) -> Result<()>`, `ProcessIdToSessionId(u32, *mut u32) -> Result<()>`, `GetProcessMemoryInfo(HANDLE, *mut PROCESS_MEMORY_COUNTERS, u32) -> Result<()>`, `OpenProcessToken(HANDLE, TOKEN_ACCESS_MASK, *mut HANDLE) -> Result<()>`, `GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, Option<*mut c_void>, u32, *mut u32) -> Result<()>`, `LookupAccountSidW<P0>(P0, PSID, Option<PWSTR>, *mut u32, Option<PWSTR>, *mut u32, *mut SID_NAME_USE) -> Result<()>`, `NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS, *mut c_void, u32, *mut u32) -> NTSTATUS`.
- 상수 검증: `ERROR_NO_MORE_FILES=18`, `ERROR_INSUFFICIENT_BUFFER=122`, `STATUS_INFO_LENGTH_MISMATCH=0xC0000004`, `STATUS_SUCCESS=0`, `TH32CS_SNAPPROCESS=2`, `TH32CS_SNAPMODULE=8`, `TH32CS_SNAPMODULE32=16`, `IMAGE_FILE_MACHINE_AMD64=34404`, `I386=332`, `ARM64=43620`, `PROCESS_NAME_WIN32=0`, `PROCESS_QUERY_INFORMATION=1024`, `TOKEN_QUERY=8`, `ProcessCommandLineInformation=60`, `ProcessVmCounters=3`. `PROCESS_ACCESS_RIGHTS`는 `BitOr` 구현이 있음. `VM_COUNTERS_EX`는 `Wdk::System::SystemServices`에 있음.
- Review Focus 5항목의 테스트가 각각 Task 2(항목 2), Task 3(항목 3 일부/4), Task 4(항목 1/3/5), Task 5(항목 5), Task 6(항목 1/3 실검증)에 배치됨.
