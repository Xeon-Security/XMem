# M11 Experiment Automation 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** `xmem experiment list` / `xmem experiment run <NAME>`를 구현한다. XMem이 직접 spawn한 lab target에 대해 Baseline → Controlled Action → Post-state → Diff → Detection → Forensic Report 파이프라인을 자동 실행한다.

**Architecture:** 변경(Write) Win32 API 래퍼는 `xmem-windows`(remotemem.rs, threads.rs)에 두고, 실험 오케스트레이션은 새 crate `xmem-experiments`가 담당한다(unsafe 없음). 파이프라인은 `xmem-forensics::collect`/`diff`와 `xmem-detection::detect_source`를 재사용한다. CLI는 렌더링만 한다.

**Tech Stack:** Rust stable, windows 0.62(VirtualAllocEx/VirtualProtectEx/WriteProcessMemory/CreateRemoteThread/FlushInstructionCache), 기존 xmem-memory/forensics/detection 재사용.

**Spec:** `docs/architecture.md` §10(Experiment Framework, §11 M11 API 행, §1 unsafe 정책)

## Global Constraints

- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.
- `unsafe`는 `xmem-windows`에만. 변경 API는 `xmem-experiments`에서만 호출하며, **대상은 XMem이 spawn한 xmem-target뿐**(임의 PID 금지).
- 실험 시작 전 `xmem_core::guard::check_state_change`로 대상 신원 검증(Deny면 중단). PID 재사용 방지: spawn 직후 report.pid == child pid 확인 + image path가 `xmem-target.exe`인지 확인.
- Cleanup: `TargetGuard::drop`이 child kill+wait + temp dir 제거. Ctrl+C 시에도 동일하게 정리(guard drop).
- 주소는 실행마다 달라진다. 실험 보고서/테스트는 `--report`의 베이스 주소와 스레드 tid를 Ground Truth로 사용한다.
- 오류는 `XmemError`. `--json`은 success_envelope/error_envelope 형식 유지.
- 검증된 API(추측 금지): `VirtualAllocEx(HANDLE, Option<*const c_void>, usize, VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS) -> *mut c_void`(실패 null); `VirtualFreeEx(HANDLE, *mut c_void, usize, VIRTUAL_FREE_TYPE) -> Result<()>`; `VirtualProtectEx(HANDLE, *const c_void, usize, PAGE_PROTECTION_FLAGS, *mut PAGE_PROTECTION_FLAGS) -> Result<()>`; `WriteProcessMemory(HANDLE, *const c_void, *const c_void, usize, Option<*mut usize>) -> Result<()>`; `CreateRemoteThread(HANDLE, Option<*const SECURITY_ATTRIBUTES>, usize, LPTHREAD_START_ROUTINE, Option<*const c_void>, u32, Option<*mut u32>) -> Result<HANDLE>`(suspended는 `THREAD_CREATE_SUSPENDED.0`=4); `FlushInstructionCache(HANDLE, Option<*const c_void>, usize) -> Result<()>`.
- PAGE 상수: RW=0x04, RX=0x20, RWX=0x40. 접근 권한: `PROCESS_CREATE_THREAD`(2) | `PROCESS_VM_OPERATION`(8) | `PROCESS_VM_WRITE`(32) | `PROCESS_QUERY_LIMITED_INFORMATION`(4096).

## Review Focus

1. **임의 PID 금지**: 실험은 오직 XMem이 spawn한 child에만 작동한다. spawn 실패/report 불일치 시 아무 것도 변경하지 않는다.
2. **PID 재사용/신원 검증**: report.pid == child.id() && image path가 xmem-target.exe가 아니면 중단. guard Deny(name 매칭)면 변경 거부.
3. **Cleanup 보장**: 정상/오류/취소 어느 경로에서도 child가 종료되고 temp dir이 제거된다.
4. **Ground Truth 정합**: `expected_observed`는 report의 base/tid와 일치하는 finding으로만 판정한다(다른 영역의 유사 finding 금지).
5. **취소 경로**: phase 사이 cancel 확인 → `Cancelled` + guard drop(kill) + exit 130.

---

### Task 1: xmem-windows — 원격 메모리 primitive

**Files:**
- Create: `crates/xmem-windows/src/remotemem.rs`
- Modify: `crates/xmem-windows/src/threads.rs` (create_remote_thread)
- Modify: `crates/xmem-windows/src/lib.rs`
- Test: 각 파일 내 `#[cfg(test)]`

**Interfaces:**
- Consumes: `OwnedHandle`, `read_process_memory`(read.rs), `open_process`(process.rs), `current_pid`, `thread_id`(selfmem).
- Produces (Task 2가 사용):
  - `alloc_remote(handle: &OwnedHandle, size: usize, protection: u32) -> Result<u64>`
  - `free_remote(handle: &OwnedHandle, address: u64) -> Result<()>`
  - `write_remote(handle: &OwnedHandle, address: u64, bytes: &[u8]) -> Result<usize>`
  - `protect_remote(handle: &OwnedHandle, address: u64, size: usize, new_protection: u32) -> Result<u32>`
  - `flush_instruction_cache(handle: &OwnedHandle, address: u64, size: usize) -> Result<()>`
  - `create_remote_thread(process: &OwnedHandle, start_address: u64, suspended: bool) -> Result<OwnedHandle>`

- [x] **Step 1: 실패하는 테스트 작성 (remotemem.rs)**

```rust
//! 원격 프로세스 메모리 조작 primitive. lab target 전용(xmem-experiments).

use std::ffi::c_void;

use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAllocEx, VirtualFreeEx,
    VirtualProtectEx,
};
use xmem_core::Result;

use crate::error::{error_from_win32, last_win32_error};
use crate::handle::OwnedHandle;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{current_pid, open_process};
    use crate::read::read_process_memory;
    use windows::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_WRITE,
    };

    const SELF_RIGHTS: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS =
        unsafe { /* placeholder */ };

    fn self_handle() -> OwnedHandle {
        open_process(
            current_pid(),
            PROCESS_CREATE_THREAD
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_QUERY_LIMITED_INFORMATION,
        )
        .unwrap()
    }

    #[test]
    fn alloc_write_protect_and_free_remote_self() {
        let handle = self_handle();
        let base = alloc_remote(&handle, 4096, 0x04).unwrap();
        assert_eq!(write_remote(&handle, base, b"xmem-experiment").unwrap(), 15);

        let mut buf = [0u8; 15];
        read_process_memory(&handle, base, &mut buf).unwrap();
        assert_eq!(&buf, b"xmem-experiment");

        let old = protect_remote(&handle, base, 4096, 0x20).unwrap();
        assert_eq!(old & 0xff, 0x04);
        free_remote(&handle, base).unwrap();
    }

    #[test]
    fn write_remote_invalid_address_errors() {
        let handle = self_handle();
        assert!(write_remote(&handle, 1, b"x").is_err());
    }

    #[test]
    fn create_remote_thread_suspended_self_reports_tid() {
        let handle = self_handle();
        let base = alloc_remote(&handle, 4096, 0x20).unwrap();
        write_remote(&handle, base, &[0xC3]).unwrap();
        flush_instruction_cache(&handle, base, 1).unwrap();

        let thread = crate::threads::create_remote_thread(&handle, base, true).unwrap();
        let tid = crate::selfmem::thread_id(&thread).unwrap_or(0);
        assert!(tid > 0, "tid를 얻지 못했다");
        // suspended 스레드는 실행되지 않으며, 테스트 프로세스 종료 시 함께 정리된다.
    }

    #[test]
    fn flush_instruction_cache_self_ok() {
        let handle = self_handle();
        let base = alloc_remote(&handle, 4096, 0x04).unwrap();
        flush_instruction_cache(&handle, base, 4096).unwrap();
        free_remote(&handle, base).unwrap();
    }
}
```

주의: `self_handle`의 placeholder 상수 정의는 불필요하므로 삭제하고 위 `open_process(...)` 호출만 남긴다. `thread_id`는 `selfmem::thread_id`가 `&OwnedHandle`을 받고 `u32`를 반환한다(`Result` 아님) — 실제 시그니처에 맞춰 `let tid = crate::selfmem::thread_id(&thread); assert!(tid > 0);`로 쓴다.

- [x] **Step 2: 실패 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `alloc_remote`/`write_remote`/`protect_remote`/`free_remote`/`flush_instruction_cache`/`create_remote_thread` 미정의

- [x] **Step 3: 구현**

remotemem.rs 테스트 모듈 위에 추가:

```rust
/// 원격 VirtualAllocEx(MEM_COMMIT|MEM_RESERVE). 할당 주소를 반환한다.
pub fn alloc_remote(handle: &OwnedHandle, size: usize, protection: u32) -> Result<u64> {
    let ptr = unsafe {
        VirtualAllocEx(
            handle.raw(),
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_PROTECTION_FLAGS(protection),
        )
    };
    if ptr.is_null() {
        return Err(last_win32_error("VirtualAllocEx"));
    }
    Ok(ptr as u64)
}

/// 원격 VirtualFreeEx(MEM_RELEASE).
pub fn free_remote(handle: &OwnedHandle, address: u64) -> Result<()> {
    unsafe { VirtualFreeEx(handle.raw(), address as *mut c_void, 0, MEM_RELEASE) }
        .map_err(|e| error_from_win32("VirtualFreeEx", &e))
}

/// 원격 WriteProcessMemory. 쓴 바이트 수를 반환한다.
pub fn write_remote(handle: &OwnedHandle, address: u64, bytes: &[u8]) -> Result<usize> {
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle.raw(),
            address as *const c_void,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            Some(&mut written),
        )
    }
    .map_err(|e| error_from_win32("WriteProcessMemory", &e))?;
    Ok(written)
}

/// 원격 VirtualProtectEx. 이전 보호 속성(raw)을 반환한다.
pub fn protect_remote(
    handle: &OwnedHandle,
    address: u64,
    size: usize,
    new_protection: u32,
) -> Result<u32> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            handle.raw(),
            address as *const c_void,
            size,
            PAGE_PROTECTION_FLAGS(new_protection),
            &mut old,
        )
    }
    .map_err(|e| error_from_win32("VirtualProtectEx", &e))?;
    Ok(old.0)
}

/// 원격 FlushInstructionCache(코드 변경 후 호출).
pub fn flush_instruction_cache(handle: &OwnedHandle, address: u64, size: usize) -> Result<()> {
    unsafe { FlushInstructionCache(handle.raw(), Some(address as *const c_void), size) }
        .map_err(|e| error_from_win32("FlushInstructionCache", &e))
}
```

threads.rs에 추가:

```rust
/// 원격 스레드 생성(VirtualAllocEx로 준비한 시작 주소). `suspended`면 실행되지 않는다.
pub fn create_remote_thread(
    process: &OwnedHandle,
    start_address: u64,
    suspended: bool,
) -> Result<OwnedHandle> {
    let start: LPTHREAD_START_ROUTINE = unsafe { std::mem::transmute(start_address) };
    let flags = if suspended {
        THREAD_CREATE_SUSPENDED.0
    } else {
        0
    };
    let handle = unsafe { CreateRemoteThread(process.raw(), None, 0, start, None, flags, None) }
        .map_err(|e| error_from_win32("CreateRemoteThread", &e))?;
    OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 })
}
```

import 추가: `CreateRemoteThread, LPTHREAD_START_ROUTINE, THREAD_CREATE_SUSPENDED`, `XmemError`, `error_from_win32`, `OwnedHandle`(이미 있으면 생략).

- [x] **Step 4: lib.rs 등록 + 테스트 통과 확인**

`pub mod remotemem;`(read 다음) + 재수출 `remotemem::{alloc_remote, flush_instruction_cache, free_remote, protect_remote, write_remote}`; threads 재수출에 `create_remote_thread` 추가.

Run: `cargo test -p xmem-windows`
Expected: PASS — 기존 57 + 신규 4 = 61

- [x] **Step 5: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows && git commit -m "feat(windows): 원격 메모리 조작 primitive (lab target 전용)"
```

---

### Task 2: xmem-experiments crate — TargetGuard + Experiment 파이프라인

**Files:**
- Modify: `Cargo.toml` (members + workspace.deps `xmem-experiments`)
- Create: `crates/xmem-experiments/Cargo.toml`
- Create: `crates/xmem-experiments/src/lib.rs`
- Create: `crates/xmem-experiments/src/target.rs`
- Create: `crates/xmem-experiments/src/experiments.rs`
- Create: `crates/xmem-experiments/src/runner.rs`
- Test: 각 파일 내 `#[cfg(test)]`

**Interfaces:**
- Consumes: Task 1 primitive, `xmem_core::guard::{check_state_change, ProcessIdentity}`, `xmem_memory::LiveProcess`, `xmem_forensics::{CollectOptions, SnapshotEnvelope, diff, collect}`, `xmem_windows::{open_process, process_info, thread_id}`.
- Produces (Task 3·4가 사용):
  - `RunOptions { target_binary: Option<PathBuf>, hold_secs: u32 }` + `Default`(hold 30)
  - `TargetGuard::spawn(options: &RunOptions, scenario: &str) -> Result<TargetGuard>` (pid/report/report_path 접근자)
  - `ExperimentMeta { name: &'static str, description: &'static str, scenario: &'static str, expected_rule: &'static str, expected: Expectation }`; `EXPERIMENTS: &[ExperimentMeta]`
  - `Expectation { Region(u64), Tid(u32) }` (report 기반 판정 값)
  - `ExperimentReport { name, description, scenario, target_pid, target_image, expected_rule, expected_present, expected_observed, expected_region: Option<u64>, baseline_findings, post_findings, detections_added, detections_removed, elapsed_ms, cleanup }`(Serialize+Debug+Clone)
  - `run_experiment(name: &str, options: &RunOptions, cancel: &AtomicBool) -> Result<ExperimentReport>`
  - `finding_matches(finding: &Finding, rule_id: &str, expectation: Expectation) -> bool`

- [x] **Step 1: Cargo 등록**

루트 Cargo.toml: members에 `"crates/xmem-experiments"`(xmem-forensics 다음), workspace.deps에 `xmem-experiments = { path = "crates/xmem-experiments" }`.

`crates/xmem-experiments/Cargo.toml`: package(workspace 상속) + `[lints] workspace = true` + deps xmem-core/xmem-windows/xmem-memory/xmem-forensics/xmem-detection/serde/serde_json/tracing(전부 workspace).

- [x] **Step 2: 실패하는 테스트 작성**

`src/experiments.rs` 테스트:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, Severity};
    use xmem_core::model::Finding;

    fn finding(rule: &str, region_base: Option<u64>, tid: Option<u32>) -> Finding {
        let mut evidence = Evidence::new("region");
        if let Some(base) = region_base {
            evidence = evidence.with_region_base(base);
        }
        if let Some(tid) = tid {
            evidence = evidence.observe("tid", tid.to_string());
        }
        Finding {
            rule_id: rule.to_string(),
            name: "test".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![evidence],
            heuristic: "test".to_string(),
            interpretation: "test".to_string(),
        }
    }

    #[test]
    fn registry_names_are_unique_and_expected_rules_valid() {
        let mut names: Vec<&str> = EXPERIMENTS.iter().map(|e| e.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "실험 이름 중복");
        for e in EXPERIMENTS {
            assert!(e.expected_rule.starts_with("XMEM-0"), "{}", e.name);
            assert!(!e.scenario.is_empty());
        }
    }

    #[test]
    fn finding_matches_region_and_tid() {
        let f = finding("XMEM-001", Some(0x1000), None);
        assert!(finding_matches(&f, "XMEM-001", Expectation::Region(0x1000)));
        assert!(!finding_matches(&f, "XMEM-001", Expectation::Region(0x2000)));
        assert!(!finding_matches(&f, "XMEM-005", Expectation::Region(0x1000)));

        let t = finding("XMEM-004", Some(0x1000), Some(777));
        assert!(finding_matches(&t, "XMEM-004", Expectation::Tid(777)));
        assert!(!finding_matches(&t, "XMEM-004", Expectation::Tid(778)));
    }
}
```

`src/runner.rs` 테스트:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_experiment_name_lists_available() {
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let err = run_experiment("no-such", &RunOptions::default(), &cancel).unwrap_err();
        match err {
            XmemError::InvalidInput { reason } => {
                assert!(reason.contains("no-such"));
                assert!(reason.contains("remote-alloc"), "가능 목록이 없다: {reason}");
            }
            other => panic!("InvalidInput이 아님: {other}"),
        }
    }
}
```

- [x] **Step 3: 실패 확인**

Run: `cargo check -p xmem-experiments --tests`
Expected: FAIL — 파일/타입 미정의

- [x] **Step 4: target.rs 구현**

```rust
//! XMem이 spawn한 lab target의 수명/신원 관리.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use xmem_core::guard::{check_state_change, ProcessIdentity};
use xmem_core::{Result, XmemError};
use xmem_windows::process_info;

/// 실험 실행 옵션.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub target_binary: Option<PathBuf>,
    pub hold_secs: u32,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            target_binary: None,
            hold_secs: 30,
        }
    }
}

/// xmem-target 바이너리를 찾는다. XMEM_TARGET → 실행 파일 옆 → 상위 두 단계.
pub fn locate_target_binary(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(XmemError::InvalidInput {
            reason: format!("지정한 target 바이너리가 없습니다: {}", path.display()),
        });
    }
    if let Ok(env_path) = std::env::var("XMEM_TARGET") {
        if Path::new(&env_path).is_file() {
            return Ok(PathBuf::from(env_path));
        }
    }
    let exe = std::env::current_exe().map_err(XmemError::Io)?;
    let dir = exe
        .parent()
        .ok_or_else(|| XmemError::InvalidInput {
            reason: "현재 실행 파일의 디렉터리를 찾지 못했습니다".to_string(),
        })?
        .to_path_buf();
    let candidates = [
        dir.join("xmem-target.exe"),
        dir.join("../xmem-target.exe").into(),
        dir.join("../../xmem-target.exe").into(),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(XmemError::InvalidInput {
        reason: format!(
            "xmem-target 바이너리를 찾지 못했습니다. XMEM_TARGET 환경 변수를 설정하세요 (시도: {})",
            dir.display()
        ),
    })
}

/// spawn한 lab target의 신원과 종료를 보장한다.
pub struct TargetGuard {
    child: Child,
    pub pid: u32,
    pub report: Value,
    report_path: PathBuf,
    temp_dir: PathBuf,
}

impl TargetGuard {
    /// 시나리오를 실행하는 lab target을 spawn하고 report가 준비될 때까지 기다린다.
    pub fn spawn(options: &RunOptions, scenario: &str) -> Result<Self> {
        let binary = locate_target_binary(options.target_binary.as_deref())?;
        let temp_dir = std::env::temp_dir().join(format!(
            "xmem-exp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&temp_dir).map_err(XmemError::Io)?;
        let report_path = temp_dir.join("report.json");

        let mut child = Command::new(&binary)
            .args([
                "run",
                scenario,
                "--hold-secs",
                &options.hold_secs.to_string(),
                "--report",
            ])
            .arg(&report_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| XmemError::InvalidInput {
                reason: format!("xmem-target spawn 실패: {} ({e})", binary.display()),
            })?;
        let pid = child.id();

        let report = match wait_for_report(&report_path, pid) {
            Ok(report) => report,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&temp_dir);
                return Err(e);
            }
        };

        // 신원 검증: 이미지 경로가 xmem-target.exe인지 + guard 정책.
        let info = process_info(pid)?;
        let image_ok = info
            .image_path
            .as_deref()
            .is_some_and(|p| p.to_ascii_lowercase().ends_with("xmem-target.exe"));
        if !image_ok {
            let _ = child.kill();
            let _ = child.wait();
            return Err(XmemError::PolicyDenied {
                reason: format!("spawn한 target의 이미지가 xmem-target.exe가 아닙니다: pid {pid}"),
            });
        }
        let identity = ProcessIdentity::from_process_info(&info);
        if let xmem_core::guard::PolicyDecision::Deny { reason, .. } = check_state_change(&identity) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(XmemError::PolicyDenied { reason });
        }

        Ok(Self {
            child,
            pid,
            report,
            report_path,
            temp_dir,
        })
    }

    /// report에서 시나리오 아티팩트의 u64 필드를 읽는다.
    pub fn artifact_u64(&self, scenario: &str, field: &str) -> Result<u64> {
        self.report["artifacts"][scenario][field]
            .as_u64()
            .ok_or_else(|| XmemError::InvalidInput {
                reason: format!("report에 artifacts.{scenario}.{field}가 없습니다"),
            })
    }

    /// report에서 시나리오 아티팩트의 u32 필드를 읽는다.
    pub fn artifact_u32(&self, scenario: &str, field: &str) -> Result<u32> {
        self.artifact_u64(scenario, field).map(|v| v as u32)
    }

    pub fn report_path(&self) -> &Path {
        &self.report_path
    }
}

impl Drop for TargetGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn wait_for_report(path: &Path, pid: u32) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                if value["pid"].as_u64() == Some(pid as u64) {
                    return Ok(value);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(XmemError::Timeout?);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
```

주의: `XmemError`에 Timeout variant가 없다면 `XmemError::InvalidInput { reason: "target report 대기 시간 초과".to_string() }`로 쓴다(실제 enum 확인 후).

- [x] **Step 5: experiments.rs 구현**

```rust
//! 알려진 실험 정의와 판정 로직.

use std::sync::atomic::AtomicBool;

use serde::Serialize;
use xmem_core::model::Finding;
use xmem_core::{Result, XmemError};
use xmem_windows::{
    alloc_remote, create_remote_thread, flush_instruction_cache, open_process, protect_remote,
    thread_id, write_remote,
};
use windows-없이: xmem_windows::OwnedHandle 사용.

use crate::target::TargetGuard;

/// 판정 기준(주소 기반).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    Region(u64),
    Tid(u32),
}

pub struct ExperimentMeta {
    pub name: &'static str,
    pub description: &'static str,
    pub scenario: &'static str,
    pub expected_rule: &'static str,
}

pub const EXPERIMENTS: &[ExperimentMeta] = &[
    ExperimentMeta {
        name: "remote-alloc",
        description: "VirtualAllocEx(RWX) 할당 → Executable Private Memory (XMEM-001/005)",
        scenario: "normal",
        expected_rule: "XMEM-001",
    },
    ExperimentMeta {
        name: "protection-flip",
        description: "기존 private RW 영역을 VirtualProtectEx로 RWX로 변경 (XMEM-005)",
        scenario: "private",
        expected_rule: "XMEM-005",
    },
    ExperimentMeta {
        name: "pe-staging",
        description: "원격 메모리에 PE 헤더 기록 후 RX로 보호 변경 (XMEM-002)",
        scenario: "normal",
        expected_rule: "XMEM-002",
    },
    ExperimentMeta {
        name: "remote-thread",
        description: "원격 RX 메모리에 스텁 기록 + suspended CreateRemoteThread (XMEM-004)",
        scenario: "normal",
        expected_rule: "XMEM-004",
    },
];

pub fn experiment(name: &str) -> Result<&'static ExperimentMeta> {
    EXPERIMENTS.iter().find(|e| e.name == name).ok_or_else(|| XmemError::InvalidInput {
        reason: format!(
            "알 수 없는 실험: {name} (가능: {})",
            EXPERIMENTS.iter().map(|e| e.name).collect::<Vec<_>>().join(", ")
        ),
    })
}

pub fn finding_matches(finding: &Finding, rule_id: &str, expectation: Expectation) -> bool {
    if finding.rule_id != rule_id {
        return false;
    }
    finding.evidence.iter().any(|e| match expectation {
        Expectation::Region(base) => e.region_base == Some(base),
        Expectation::Tid(tid) => e
            .observed
            .get("tid")
            .and_then(|v| v.parse::<u32>().ok())
            == Some(tid),
    })
}
```

이어서 액션 실행(같은 파일):

```rust
/// 프로세스 핸들을 얻는다(실험 전용 권한).
pub fn open_experiment_target(pid: u32) -> Result<xmem_windows::OwnedHandle> {
    use windows 안 쓰고 xmem_windows 상수 재노출이 없으면:
}
```

문제: PROCESS_* 상수는 windows crate에 있으므로 xmem-experiments에서 직접 쓸 수 없다(unsafe 없이도 상수는 쓸 수 있지만 windows crate에 의존하게 됨). 해결: xmem-windows에 `open_for_experiment(pid)`를 추가한다(Task 1에 포함):

```rust
/// 실험용 핸들(CREATE_THREAD | VM_OPERATION | VM_WRITE | QUERY_LIMITED).
pub fn open_for_experiment(pid: u32) -> Result<OwnedHandle> {
    open_process(
        pid,
        PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_QUERY_LIMITED_INFORMATION,
    )
}
```

experiments.rs의 액션:

```rust
/// 실험별 Action. report의 Ground Truth 주소를 반환한다.
pub fn execute_action(
    meta: &ExperimentMeta,
    handle: &xmem_windows::OwnedHandle,
    report: &TargetGuard,
) -> Result<Expectation> {
    match meta.name {
        "remote-alloc" => {
            let base = alloc_remote(handle, 4096, 0x40)?;
            Ok(Expectation::Region(base))
        }
        "protection-flip" => {
            let base = report.artifact_u64("private", "base")?;
            let old = protect_remote(handle, base, 4096, 0x40)?;
            if old & 0xff != 0x04 {
                return Err(XmemError::InvalidInput {
                    reason: format!("private 영역 보호 속성이 RW가 아닙니다: {old:#x}"),
                });
            }
            Ok(Expectation::Region(base))
        }
        "pe-staging" => {
            let base = alloc_remote(handle, 4096, 0x04)?;
            let pe = fake_pe_bytes();
            write_remote(handle, base, &pe)?;
            protect_remote(handle, base, 4096, 0x20)?;
            flush_instruction_cache(handle, base, pe.len())?;
            Ok(Expectation::Region(base))
        }
        "remote-thread" => {
            let base = alloc_remote(handle, 4096, 0x20)?;
            write_remote(handle, base, &[0xC3])?;
            flush_instruction_cache(handle, base, 1)?;
            let thread = create_remote_thread(handle, base, true)?;
            let tid = thread_id(&thread);
            Ok(Expectation::Tid(tid))
        }
        other => Err(XmemError::Unimplemented { feature: "unknown experiment action" })
            .map_err(|_| XmemError::InvalidInput { reason: format!("액션 미구현: {other}") }),
    }
}

/// XMEM-002 판정용 최소 PE 헤더(MZ + PE\0\0 + PE32+).
pub fn fake_pe_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; 4096];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    bytes[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // COFF machine
    bytes[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // 섹션 수
    bytes[0x54..0x56].copy_from_slice(&0xF0u16.to_le_bytes()); // optional header 크기
    bytes[0x58..0x5a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
    bytes[0x98..0x9c].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
    bytes
}
```

주의(정확한 오프셋은 xmem-target의 `fake_pe_bytes()`와 일치해야 한다): xmem-target이 만드는 fake PE와 동일한 배치를 쓴다. 구현 시 `lab/targets/xmem-target/src/scenarios.rs`의 `fake_pe_bytes()`를 읽고 그 오프셋을 그대로 옮긴다(추측 금지).

- [x] **Step 6: runner.rs 구현**

```rust
//! Baseline → Action → Post → Diff → 판정 파이프라인.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::Serialize;
use xmem_core::{Result, XmemError};
use xmem_forensics::{CollectOptions, collect, diff};
use xmem_memory::LiveProcess;

use crate::experiments::{Expectation, execute_action, experiment, finding_matches};
use crate::target::{RunOptions, TargetGuard};

#[derive(Debug, Clone, Serialize)]
pub struct ExperimentReport {
    pub name: String,
    pub description: String,
    pub scenario: String,
    pub target_pid: u32,
    pub expected_rule: String,
    pub expected_present: bool,
    pub expected_observed: bool,
    pub expected_region: Option<u64>,
    pub baseline_findings: usize,
    pub post_findings: usize,
    pub detections_added: usize,
    pub detections_removed: usize,
    pub elapsed_ms: u64,
    pub cleanup: String,
}

/// 실험을 실행한다. 대상은 XMem이 spawn한 lab target뿐이다.
pub fn run_experiment(
    name: &str,
    options: &RunOptions,
    cancel: &AtomicBool,
) -> Result<ExperimentReport> {
    let meta = experiment(name)?;
    let started = Instant::now();
    let guard = TargetGuard::spawn(options, meta.scenario)?;
    check_cancel(cancel)?;

    let live = LiveProcess::open(guard.pid)?;
    let baseline = collect(&live, &CollectOptions::default(), cancel)?;
    check_cancel(cancel)?;

    let handle = xmem_windows::open_for_experiment(guard.pid)?;
    let expectation = execute_action(meta, &handle, &guard)?;
    check_cancel(cancel)?;

    let post = collect(&live, &CollectOptions::default(), cancel)?;
    let delta = diff(&baseline, &post);

    let expected_present = baseline
        .findings
        .iter()
        .any(|f| finding_matches(f, meta.expected_rule, expectation));
    let expected_observed = post
        .findings
        .iter()
        .any(|f| finding_matches(f, meta.expected_rule, expectation));

    let expected_region = match expectation {
        Expectation::Region(base) => Some(base),
        Expectation::Tid(_) => None,
    };

    let report = ExperimentReport {
        name: meta.name.to_string(),
        description: meta.description.to_string(),
        scenario: meta.scenario.to_string(),
        target_pid: guard.pid,
        expected_rule: meta.expected_rule.to_string(),
        expected_present,
        expected_observed,
        expected_region,
        baseline_findings: baseline.findings.len(),
        post_findings: post.findings.len(),
        detections_added: delta.summary.detections_added,
        detections_removed: delta.summary.detections_removed,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cleanup: String::new(),
    };

    drop(handle);
    drop(live);
    drop(guard); // kill + temp 정리

    let mut report = report;
    report.cleanup = "target terminated, temp files removed".to_string();
    Ok(report)
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(XmemError::Cancelled {
            reason: "user interrupt".to_string(),
        });
    }
    Ok(())
}
```

주의: DiffSummary 필드명(detections_added/removed)은 실제 코드와 일치한다(M8). `LiveProcess::open`이 실패하면 guard drop으로 target이 정리된다.

- [x] **Step 7: lib.rs + 테스트 통과 확인**

`src/lib.rs`: `pub mod experiments; pub mod runner; pub mod target;` + 재수출(EXPERIMENTS, ExperimentMeta, Expectation, finding_matches, run_experiment, ExperimentReport, RunOptions, TargetGuard).

Run: `cargo test -p xmem-experiments`
Expected: PASS — 신규 3 (registry 1 + matches 1 + unknown name 1)

- [x] **Step 8: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-experiments --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-experiments crates/xmem-windows
git commit -m "feat(experiments): TargetGuard와 경험 자동화 파이프라인"
```

(open_for_experiment 추가분은 xmem-windows에 포함해 같은 커밋으로.)

---

### Task 3: lab e2e 테스트 — 실험 → 아티팩트 검증

**Files:**
- Modify: `lab/targets/xmem-target/Cargo.toml` (dev-dep `xmem-experiments`)
- Create: `lab/targets/xmem-target/tests/experiment_e2e.rs`

**Interfaces:**
- Consumes: `RunOptions{target_binary: Some(...)}`, `run_experiment`, `EXPERIMENTS`.
- Produces: 없음(테스트).

- [x] **Step 1: 테스트 작성**

```rust
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! M11 파이프라인 e2e: Baseline → Action → Post → 판정.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use xmem_experiments::experiments::EXPERIMENTS;
use xmem_experiments::runner::run_experiment;
use xmem_experiments::target::RunOptions;

#[test]
fn all_experiments_produce_expected_artifacts() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_xmem-target"));
    let options = RunOptions {
        target_binary: Some(binary),
        hold_secs: 30,
    };
    let cancel = AtomicBool::new(false);

    for meta in EXPERIMENTS {
        let report = run_experiment(meta.name, &options, &cancel)
            .unwrap_or_else(|e| panic!("{} 실패: {e}", meta.name));
        assert!(
            !report.expected_present,
            "{}: baseline에 이미 {} finding이 있었다",
            meta.name, meta.expected_rule
        );
        assert!(
            report.expected_observed,
            "{}: post에서 {} finding을 기대 영역에서 찾지 못했다",
            meta.name, meta.expected_rule
        );
        assert!(report.cleanup.contains("terminated"), "{}", meta.name);
        assert!(
            report.post_findings >= 1,
            "{}: post finding이 없다",
            meta.name
        );
    }
}

#[test]
fn experiment_target_is_terminated_after_run() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_xmem-target"));
    let options = RunOptions {
        target_binary: Some(binary),
        hold_secs: 30,
    };
    let cancel = AtomicBool::new(false);
    let report = run_experiment("remote-alloc", &options, &cancel).unwrap();
    let pid = report.target_pid;
    // 종료 대기 여유
    std::thread::sleep(std::time::Duration::from_millis(300));
    let alive = xmem_windows::process_info(pid).is_ok();
    assert!(!alive, "target {pid}가 아직 살아 있다");
}
```

주의: 통합 테스트에서 xmem-windows 사용을 위해 dev-deps에 xmem-windows 추가 필요.

- [x] **Step 2: red → green 확인**

Run: `cargo check -p xmem-target --tests` → FAIL(모듈 없음) → 구현/의존 추가 후 `cargo test -p xmem-target`
Expected: PASS — target 5 + 신규 2 = 7 (runner 실동작 포함, ~10초)

- [x] **Step 3: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-target --all-targets -- -D warnings
git add lab/targets/xmem-target && git commit -m "test(lab): 실험 자동화 e2e — 4개 실험 아티팩트 검증"
```

---

### Task 4: CLI experiment list/run + 문서 + 게이트 + 스모크

**Files:**
- Modify: `crates/xmem-cli/Cargo.toml` (xmem-experiments)
- Modify: `crates/xmem-cli/src/commands/experiment.rs`
- Modify: `README.md`, `docs/architecture.md`, `docs/plans/milestone-11-experiments.md`

**Interfaces:**
- Consumes: `xmem_experiments::{EXPERIMENTS, ExperimentReport, RunOptions, run_experiment}`, `commands::memory::cancel_flag`, `output::{emit, emit_json, resolve_mode, success_envelope}`.
- Produces: `pub(crate) fn render_experiment_list() -> String`, `pub(crate) fn render_experiment_report(&ExperimentReport) -> String`.

- [x] **Step 1: 실패하는 테스트 작성 (experiment.rs)**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> ExperimentReport {
        ExperimentReport {
            name: "remote-alloc".to_string(),
            description: "desc".to_string(),
            scenario: "normal".to_string(),
            target_pid: 777,
            expected_rule: "XMEM-001".to_string(),
            expected_present: false,
            expected_observed: true,
            expected_region: Some(0x1000),
            baseline_findings: 0,
            post_findings: 2,
            detections_added: 1,
            detections_removed: 0,
            elapsed_ms: 42,
            cleanup: "target terminated, temp files removed".to_string(),
        }
    }

    #[test]
    fn render_experiment_list_lists_all() {
        let text = render_experiment_list();
        for meta in xmem_experiments::EXPERIMENTS {
            assert!(text.contains(meta.name), "{} 없음", meta.name);
        }
        assert!(text.contains("XMEM-001"));
    }

    #[test]
    fn render_experiment_report_shows_verification() {
        let text = render_experiment_report(&sample_report());
        assert!(text.contains("remote-alloc"));
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("observed"));
        assert!(text.contains("terminated"));
    }
}
```

- [x] **Step 2: red 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — xmem_experiments 미해결/함수 미정의

- [x] **Step 3: 구현 (experiment.rs)**

```rust
use serde_json::json;
use xmem_core::Result;
use xmem_experiments::{ExperimentReport, RunOptions, run_experiment};

use crate::cli::{ExperimentCmd, GlobalArgs};
use crate::commands::memory::cancel_flag;
use crate::commands::render::truncate;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(cmd: &ExperimentCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        ExperimentCmd::List => {
            match resolve_mode(global.json) {
                OutputMode::Json => {
                    let items: Vec<_> = xmem_experiments::EXPERIMENTS
                        .iter()
                        .map(|e| {
                            json!({
                                "name": e.name,
                                "description": e.description,
                                "scenario": e.scenario,
                                "expected_rule": e.expected_rule,
                            })
                        })
                        .collect();
                    emit_json(&success_envelope(json!({ "experiments": items })));
                }
                OutputMode::Human => emit(&render_experiment_list()),
            }
            Ok(())
        }
        ExperimentCmd::Run { name } => {
            let cancel = cancel_flag();
            let report = run_experiment(name, &RunOptions::default(), &cancel)?;
            match resolve_mode(global.json) {
                OutputMode::Json => {
                    emit_json(&success_envelope(serde_json::to_value(&report).map_err(
                        |e| xmem_core::XmemError::JsonError { reason: e.to_string() },
                    )?));
                }
                OutputMode::Human => emit(&render_experiment_report(&report)),
            }
            Ok(())
        }
    }
}

pub(crate) fn render_experiment_list() -> String {
    let mut out = String::from("experiments:\n");
    for meta in xmem_experiments::EXPERIMENTS {
        out.push_str(&format!(
            "  {:<16} {:<26} scenario {:<8} expects {}\n",
            meta.name, meta.description, meta.scenario, meta.expected_rule
        ));
    }
    out
}

pub(crate) fn render_experiment_report(report: &ExperimentReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("experiment {}\n", report.name));
    out.push_str(&format!("  {}\n", report.description));
    out.push_str(&format!(
        "  target pid {} ({}) in {} ms\n",
        report.target_pid, report.scenario, report.elapsed_ms
    ));
    out.push_str(&format!(
        "  baseline findings {} -> post findings {} (detections +{} -{})\n",
        report.baseline_findings,
        report.post_findings,
        report.detections_added,
        report.detections_removed
    ));
    out.push_str(&format!(
        "  expected {}: baseline {} / post {}\n",
        report.expected_rule,
        if report.expected_present { "present" } else { "absent" },
        if report.expected_observed { "observed" } else { "missing" }
    ));
    if let Some(base) = report.expected_region {
        out.push_str(&format!("  artifact region {:#018x}\n", base));
    }
    out.push_str(&format!("  cleanup: {}\n", report.cleanup));
    let _ = truncate; // 사용 예정이 없으면 import에서 제거
    out
}
```

주의: `truncate`가 불필요하면 import와 `let _ = truncate;` 줄을 제거한다(파일 상단 사용 목록 정리는 구현 시).

- [x] **Step 4: 테스트 통과 확인 + 게이트**

Run: `cargo test -p xmem-cli`
Expected: PASS — 55 + 2 = 57

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | Out-File -Encoding utf8 "$env:TEMP\opencode\xmem-m11-tests.log"
```

Expected: 전부 0. 테스트 합계 = cli 57 + core 34 + detection 8 + experiments 3 + forensics 24 + memory 21 + pe 9 + windows 61(또는 62) + xmem-target(unit 4 + ground_truth 1 + e2e 2) + 기타 = **약 228** (계획 산술 오차 가능, 로그에서 확인).

- [x] **Step 5: Windows 스모크**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build -q -p xmem-cli -p xmem-target
$exe = ".\target\debug\xmem.exe"

& $exe experiment list; Write-Output "exit=$LASTEXITCODE"
& $exe experiment run remote-alloc; Write-Output "exit=$LASTEXITCODE"
& $exe --json experiment run protection-flip | Select-Object -First 5; Write-Output "exit=$LASTEXITCODE"
& $exe experiment run bogus-name; Write-Output "exit=$LASTEXITCODE"

Get-Process xmem-target -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id
Get-ChildItem $env:TEMP -Directory -Filter "xmem-exp-*" | Select-Object -ExpandProperty Name
1..3 | ForEach-Object { & $exe experiment run remote-alloc > $null; Write-Output "repeat=$LASTEXITCODE" }
```

기록: 4개 실험의 baseline→post finding 수, expected rule observed 여부, artifact region, target 종료(프로세스 없음), temp 디렉터리 없음, 반복 3회 0, bogus exit 1.

- [x] **Step 6: 문서 갱신**

README:
- Status 문구: "현재 **Milestone 11 (Experiment Automation)** 완료. ... `xmem experiment list` / `xmem experiment run <NAME>`로 XMem이 spawn한 lab target에 대해 Baseline → Action → Post → Diff → Detection → Report 파이프라인을 실행한다."
- Status 표: `Experiment 자동화 | Planned (M11)` 행 → Implemented(4개 정의 실험 remote-alloc/protection-flip/pe-staging/remote-thread, spawn한 xmem-target 한정, guard/신원 검증, cleanup, `--json`).
- Quick Start에 3줄: `cargo build -p xmem-target`, `xmem experiment list`, `xmem experiment run remote-alloc`.
- CLI Usage에 Experiment 문단(실험 목록 표, 파이프라인, 대상은 spawn한 xmem-target뿐, report의 Ground Truth로 판정).
- Limitations에 M11 bullet(실험은 xmem-target 전용, 원격 스레드는 suspended, 변경 API는 xmem-experiments 경로에서만, target 바이너리 탐색에 XMEM_TARGET 사용 가능).
- Roadmap M11 = 완료.

architecture.md:
- crate 표 `xmem-experiments` 행 → "Experiment Framework (TargetGuard + 4개 실험 + 파이프라인). 변경 Win32 API 호출은 여기서만, lab target 한정 | M11 (생성됨)".
- §10 제목 → "(M11 구현됨)" + 구현 노트(spawn 전용, 신원 검증, guard, cleanup, Ground Truth 판정, `RunOptions::target_binary`로 테스트가 바이너리 지정, 파이프라인은 forensics collect/diff + detection 재사용).
- §11 M11 행 → "구현됨(xmem-windows::remotemem + threads::create_remote_thread, 호출은 xmem-experiments만)".
- §14 Status: M11 Done + M12 Planned.

- [x] **Step 7: 체크박스 + 커밋**

계획서 `- [x]` → `- [x]` replaceAll 후:

```powershell
git add README.md docs/architecture.md docs/plans/milestone-11-experiments.md
git commit -m "docs: M11 Experiment Automation 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지**: §10 파이프라인/신원 검증/guard/cleanup/메타데이터 전부 Task에 매핑. §11 M11 API 행 → Task 1. CLI list/run → Task 4.
- **unsafe 경계**: 모든 변경 API 래퍼는 xmem-windows, 호출자는 xmem-experiments뿐(§1 정책).
- **미구현으로 남기는 것**: 실험 정의의 사용자 확장(외부 TOML), 임의 PID 실험(v1 금지), 실험 결과의 Snapshot 파일 저장(JSON report만).
- **타입 일관성**: `RunOptions`/`TargetGuard`/`ExperimentMeta`/`Expected`/`ExperimentReport`/`run_experiment`/`finding_matches` 이름이 Task 2·3·4에서 동일. `execute_action`의 `&TargetGuard` 인자는 `artifact_u64` 사용 목적.
- **실측 리스크**: `XmemError`에 Timeout 없음(→ InvalidInput 사용), `LPTHREAD_START_ROUTINE`/`THREAD_CREATE_SUSPENDED` import 경로, `thread_id` 반환형(Result 아님), `Evidence::observe` 시그니처 — 구현 중 실제 코드로 확인하고 계획서도 패치한다.
