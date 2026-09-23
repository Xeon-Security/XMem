# M10 Research Lab (Test Target + Ground Truth) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `lab/targets/xmem-target`에 deterministic한 전용 Test Target을 만들고, 그 Ground Truth를 XMem 라이브 분석(detect/scan)으로 검증하는 회귀 테스트를 추가한다.

**Architecture:** 자기 프로세스 메모리 조작 primitive(VirtualAlloc/VirtualProtect/VirtualFree/CreateThread)는 `xmem-windows::selfmem`에 둔다(unsafe는 xmem-windows에만). Test Target은 `xmem-windows`만 사용하는 bin crate(제품 스택의 leaf)이며, 자기 프로세스 메모리만 변경한다. 회귀 테스트는 타깃을 spawn하고 `xmem-memory`/`xmem-detection` 라이브러리로 분석해 Ground Truth와 대조한다.

**Tech Stack:** Rust stable, windows 0.62(VirtualAlloc/VirtualProtect/VirtualFree/CreateThread/GetThreadId), 기존 xmem-memory/xmem-detection/xmem-pe 재사용(테스트 전용 dev-dependency).

**Spec:** `docs/architecture.md` §13(Thread), §15(Snapshot — 실험 타깃 원칙), §19~22(Test Target), §27(Host 보호), §40(Regression Fixture)

## Global Constraints

- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.
- `unsafe`는 `xmem-windows`에만. Test Target과 테스트는 safe API만 사용.
- Test Target은 **자기 프로세스 메모리만** 변경한다. 외부 프로세스 API(VirtualAllocEx 등) 사용 금지.
- deterministic: 크기·패턴·오프셋은 상수로 고정. 실행마다 주소만 달라진다.
- runtime `unwrap()`/`expect()` 금지(테스트는 `#![cfg_attr(test, allow(...))]`).
- Ground Truth는 JSON으로 stdout + `--report <path>` 파일에 기록한다.
- 회귀 테스트는 타깃을 반드시 kill+wait으로 정리하고, report 대기에는 timeout을 둔다.
- 커밋 메시지·문서는 한국어. 커밋 prefix feat/fix/docs/style/refactor/test/chore.
- 문서는 `README.md`(Status 표/Quick Start/Limitations/Roadmap)와 `docs/architecture.md`(crate 표/Windows API/Status)를 갱신한다.

## Review Focus

1. **타깃 격리**: Test Target이 자기 프로세스 외부를 변경하지 않는다(외부 프로세스 API 없음).
2. **테스트 정리**: 회귀 테스트가 실패해도 타깃 프로세스를 남기지 않는다(kill+wait), report 대기는 timeout으로 hang하지 않는다.
3. **회귀 고정**: fake PE 바이트가 실제 `parse_pe`/`classify_memory_pe`에서 `PrivatePeLike`로 분류된다(헤더 오프셋 회귀 방지).
4. **CPU 안전**: thread 실험은 CREATE_SUSPENDED 스레드라 대기 중 CPU를 소모하지 않는다.
5. **Ground Truth 정합**: report의 base/tid가 라이브 분석 결과(region/finding)와 정확히 일치한다.

---

### Task 1: xmem-windows — 자기 프로세스 메모리 primitive (`selfmem.rs`)

**Files:**
- Create: `crates/xmem-windows/src/selfmem.rs`
- Modify: `crates/xmem-windows/src/lib.rs`
- Test: `selfmem.rs` 내 `#[cfg(test)]` 모듈

**Interfaces:**
- Consumes: `OwnedHandle`(handle.rs), `error_from_win32`/`last_win32_error`(error.rs).
- Produces (Task 2가 사용):
  - `PrivateRegion::alloc(size: usize) -> Result<PrivateRegion>` / `.base() -> u64` / `.size() -> usize` / `.protection() -> u32`
  - `.write(bytes: &[u8]) -> Result<()>` / `.write_at(offset: usize, bytes: &[u8]) -> Result<()>` / `.protect(new_protect: u32) -> Result<u32>`
  - `alloc_executable(bytes: &[u8], final_protect: u32) -> Result<PrivateRegion>`
  - `spawn_suspended_thread(start_address: u64) -> Result<OwnedHandle>` / `thread_id(handle: &OwnedHandle) -> u32`
  - 상수 `SELF_PAGE_RW=0x04`, `SELF_PAGE_RX=0x20`, `SELF_PAGE_RWX=0x40`

검증된 시그니처(windows-0.62.2 레지스트리 소스):
- `VirtualAlloc(Option<*const c_void>, usize, VIRTUAL_ALLOCATION_TYPE, PAGE_PROTECTION_FLAGS) -> *mut c_void` — 실패 시 null(Result 아님).
- `VirtualProtect(*const c_void, usize, PAGE_PROTECTION_FLAGS, *mut PAGE_PROTECTION_FLAGS) -> Result<()>`
- `VirtualFree(*mut c_void, usize, VIRTUAL_FREE_TYPE) -> Result<()>` (MEM_RELEASE는 dwsize=0)
- `CreateThread(Option<*const SECURITY_ATTRIBUTES>, usize, LPTHREAD_START_ROUTINE, Option<*const c_void>, THREAD_CREATION_FLAGS, Option<*mut u32>) -> Result<HANDLE>`
- `LPTHREAD_START_ROUTINE = Option<unsafe extern "system" fn(*mut c_void) -> u32>`
- `GetThreadId(HANDLE) -> u32` (Result 아님)
- 상수: `MEM_COMMIT`/`MEM_RESERVE: VIRTUAL_ALLOCATION_TYPE(4096/8192)`, `MEM_RELEASE: VIRTUAL_FREE_TYPE(32768)`, `PAGE_READWRITE/EXECUTE_READ/EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS(4/32/64)`, `THREAD_CREATE_SUSPENDED: THREAD_CREATION_FLAGS(4)` (CREATE_SUSPENDED는 PROCESS_CREATION_FLAGS라 사용 금지).

- [ ] **Step 1: 실패하는 테스트 작성**

`crates/xmem-windows/src/selfmem.rs` 생성(테스트만):

```rust
//! 자기 프로세스 메모리 조작(lab target 전용).

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAlloc, VirtualFree,
    VirtualProtect,
};
use windows::Win32::System::Threading::{
    CreateThread, GetThreadId, LPTHREAD_START_ROUTINE, THREAD_CREATE_SUSPENDED,
};
use xmem_core::{Result, XmemError};

use crate::error::{error_from_win32, last_win32_error};
use crate::handle::OwnedHandle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_write_and_drop() {
        let mut region = PrivateRegion::alloc(4096).unwrap();
        assert_ne!(region.base(), 0);
        assert_eq!(region.size(), 4096);
        region.write(b"XMEM_SELFTEST").unwrap();
        assert_eq!(region.protection(), SELF_PAGE_RW);
    }

    #[test]
    fn protect_reports_old_and_gates_writes() {
        let mut region = PrivateRegion::alloc(4096).unwrap();
        region.write(b"before").unwrap();
        let old = region.protect(SELF_PAGE_RX).unwrap();
        assert_eq!(old, SELF_PAGE_RW);
        assert_eq!(region.protection(), SELF_PAGE_RX);
        let err = region.write(b"after").unwrap_err();
        assert!(matches!(err, XmemError::InvalidInput { .. }));
    }

    #[test]
    fn alloc_executable_writes_and_protects() {
        let region = alloc_executable(&[0xC3], SELF_PAGE_RX).unwrap();
        assert_ne!(region.base(), 0);
        assert_eq!(region.protection(), SELF_PAGE_RX);
    }

    #[test]
    fn spawn_suspended_thread_reports_id() {
        let region = alloc_executable(&[0xC3], SELF_PAGE_RX).unwrap();
        let handle = spawn_suspended_thread(region.base()).unwrap();
        assert_ne!(thread_id(&handle), 0);
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `PrivateRegion`/`alloc_executable`/`spawn_suspended_thread`/`thread_id`/`SELF_PAGE_*` 미정의

- [ ] **Step 3: 구현**

테스트 모듈 위에 추가:

```rust
/// PAGE_READWRITE (자기 프로세스 할당용).
pub const SELF_PAGE_RW: u32 = 0x04;
/// PAGE_EXECUTE_READ.
pub const SELF_PAGE_RX: u32 = 0x20;
/// PAGE_EXECUTE_READWRITE.
pub const SELF_PAGE_RWX: u32 = 0x40;

/// 자기 프로세스의 커밋된 private 영역. Drop 시 VirtualFree(MEM_RELEASE).
pub struct PrivateRegion {
    base: *mut core::ffi::c_void,
    size: usize,
    protection: u32,
}

impl PrivateRegion {
    /// PAGE_READWRITE로 size 바이트를 커밋한다(최소 1 페이지).
    pub fn alloc(size: usize) -> Result<Self> {
        let size = size.max(4096);
        let base = unsafe {
            VirtualAlloc(
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_PROTECTION_FLAGS(SELF_PAGE_RW),
            )
        };
        if base.is_null() {
            return Err(last_win32_error("VirtualAlloc"));
        }
        Ok(Self {
            base,
            size,
            protection: SELF_PAGE_RW,
        })
    }

    pub fn base(&self) -> u64 {
        self.base as u64
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// 현재 보호 속성(raw PAGE_*).
    pub fn protection(&self) -> u32 {
        self.protection
    }

    /// 현재 보호 속성을 바꾸고 이전 값을 반환한다.
    pub fn protect(&mut self, new_protect: u32) -> Result<u32> {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtect(
                self.base,
                self.size,
                PAGE_PROTECTION_FLAGS(new_protect),
                &mut old,
            )
        }
        .map_err(|e| error_from_win32("VirtualProtect", &e))?;
        self.protection = new_protect & 0xff;
        Ok(old.0)
    }

    /// 앞에서부터 복사한다. 현재 보호 속성이 쓰기 가능할 때만 허용한다.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_at(0, bytes)
    }

    /// offset 위치에 복사한다. 범위를 벗어나거나 쓰기 불가면 InvalidInput.
    pub fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        if !matches!(self.protection, 0x04 | 0x08 | 0x40 | 0x80) {
            return Err(XmemError::InvalidInput {
                reason: format!("region is not writable (protect {:#x})", self.protection),
            });
        }
        if offset.saturating_add(bytes.len()) > self.size {
            return Err(XmemError::InvalidInput {
                reason: format!(
                    "write out of range: offset {offset:#x} + len {:#x} > size {:#x}",
                    bytes.len(),
                    self.size
                ),
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.base.cast::<u8>().add(offset),
                bytes.len(),
            );
        }
        Ok(())
    }
}

impl Drop for PrivateRegion {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.base, 0, MEM_RELEASE);
        }
    }
}

/// RW로 할당하고 bytes를 쓰고 final_protect로 보호 속성을 바꾼다.
pub fn alloc_executable(bytes: &[u8], final_protect: u32) -> Result<PrivateRegion> {
    let mut region = PrivateRegion::alloc(bytes.len())?;
    region.write(bytes)?;
    region.protect(final_protect)?;
    Ok(region)
}

/// start_address에서 CREATE_SUSPENDED 스레드를 만든다(lab target 전용).
///
/// 호출자는 start_address가 유효한 실행 가능 메모리임을 보장해야 한다.
pub fn spawn_suspended_thread(start_address: u64) -> Result<OwnedHandle> {
    let start: LPTHREAD_START_ROUTINE = Some(unsafe {
        std::mem::transmute::<u64, unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>(
            start_address,
        )
    });
    let handle = unsafe { CreateThread(None, 0, start, None, THREAD_CREATE_SUSPENDED, None) }
        .map_err(|e| error_from_win32("CreateThread", &e))?;
    OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 })
}

/// 스레드 ID를 조회한다.
pub fn thread_id(handle: &OwnedHandle) -> u32 {
    unsafe { GetThreadId(handle.raw()) }
}
```

- [ ] **Step 4: lib.rs 등록**

`crates/xmem-windows/src/lib.rs`:
- `pub mod selfmem;` 추가(read 다음).
- 재수출: `pub use selfmem::{PrivateRegion, SELF_PAGE_RW, SELF_PAGE_RX, SELF_PAGE_RWX, alloc_executable, spawn_suspended_thread, thread_id};`

- [ ] **Step 5: 테스트 통과 확인**

Run: `cargo test -p xmem-windows`
Expected: PASS — 기존 53 + 신규 4 = 57

- [ ] **Step 6: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows
git commit -m "feat(windows): 자기 프로세스 메모리 primitive (lab target용)"
```

---

### Task 2: xmem-target crate (lab/targets/xmem-target)

**Files:**
- Modify: `Cargo.toml` (members에 `"lab/targets/xmem-target"` 추가)
- Create: `lab/targets/xmem-target/Cargo.toml`
- Create: `lab/targets/xmem-target/src/main.rs`
- Create: `lab/targets/xmem-target/src/scenarios.rs`
- Test: `scenarios.rs`·`main.rs` 내 `#[cfg(test)]` 모듈

**Interfaces:**
- Consumes: Task 1의 selfmem API, `xmem_windows::current_pid`, `OwnedHandle`.
- Produces (Task 3이 사용):
  - bin `xmem-target` (`run <scenario> [--hold-secs N] [--report PATH]`)
  - 시나리오: `normal | pattern | private | private-exec | pe-like | threads | protection | all`
  - `scenarios::fake_pe_bytes() -> Vec<u8>`, `scenarios::PATTERN_ASCII/PATTERN_WIDE/PATTERN_BYTES/WIDE_OFFSET/BYTES_OFFSET`
  - report JSON: `{ "scenario", "pid", "artifacts": { <name>: { "base", "size", ... } } }`

- [ ] **Step 1: Cargo.toml 작성**

루트 `Cargo.toml` members에 `"lab/targets/xmem-target",` 추가(xmem-cli 다음).

`lab/targets/xmem-target/Cargo.toml`:

```toml
[package]
name = "xmem-target"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
xmem-windows.workspace = true
serde_json.workspace = true

[dev-dependencies]
xmem-core.workspace = true
xmem-memory.workspace = true
xmem-detection.workspace = true
xmem-pe.workspace = true
```

- [ ] **Step 2: 실패하는 테스트 작성 (scenarios.rs)**

`lab/targets/xmem-target/src/scenarios.rs` 생성(테스트만):

```rust
//! 시나리오별 메모리 아티팩트와 Ground Truth.

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_pe::{MemoryPeClass, classify_memory_pe};
    use xmem_core::RegionClass;

    #[test]
    fn fake_pe_is_classified_private_pe_like() {
        let bytes = fake_pe_bytes();
        assert!(xmem_pe::looks_like_pe(&bytes));
        assert_eq!(
            classify_memory_pe(RegionClass::Private, &bytes),
            MemoryPeClass::PrivatePeLike
        );
    }

    #[test]
    fn all_scenario_sets_up_every_artifact() {
        let (_lab, artifacts) = setup("all").unwrap();
        for name in [
            "normal",
            "pattern",
            "private",
            "private-exec",
            "pe-like",
            "threads",
            "protection",
        ] {
            let base = artifacts[name]["base"].as_u64().unwrap_or(0);
            assert_ne!(base, 0, "{name} base");
        }
        assert_ne!(artifacts["threads"]["tid"].as_u64().unwrap_or(0), 0);
        assert_eq!(artifacts["protection"]["before"], "RW");
        assert_eq!(artifacts["protection"]["after"], "RWX");
    }
}
```

- [ ] **Step 3: 실패 확인**

Run: `cargo check -p xmem-target --tests`
Expected: FAIL — `fake_pe_bytes`/`setup` 미정의

- [ ] **Step 4: scenarios.rs 구현**

테스트 모듈 위에 추가:

```rust
use serde_json::{Value, json};
use xmem_windows::OwnedHandle;
use xmem_windows::selfmem::{
    PrivateRegion, SELF_PAGE_RX, SELF_PAGE_RWX, alloc_executable, spawn_suspended_thread,
    thread_id,
};

/// pattern 시나리오에서 쓰는 ASCII 문자열.
pub const PATTERN_ASCII: &[u8] = b"XMEM_PATTERN_ALPHA_0123456789";
/// pattern 시나리오에서 쓰는 UTF-16 문자열.
pub const PATTERN_WIDE: &str = "XMEM_WIDE_PATTERN";
/// pattern 시나리오에서 쓰는 바이트 패턴.
pub const PATTERN_BYTES: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
const PATTERN_SIZE: usize = 64 * 1024;
/// UTF-16 패턴 오프셋.
pub const WIDE_OFFSET: usize = 0x1000;
/// 바이트 패턴 오프셋.
pub const BYTES_OFFSET: usize = 0x2000;

/// 아티팩트를 살아 있게 유지하는 컨테이너. Drop 시 전부 해제된다.
pub struct Lab {
    pub regions: Vec<PrivateRegion>,
    pub threads: Vec<OwnedHandle>,
}

impl Lab {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            threads: Vec::new(),
        }
    }

    fn push(&mut self, region: PrivateRegion) -> usize {
        self.regions.push(region);
        self.regions.len() - 1
    }

    fn region(&self, index: usize) -> &PrivateRegion {
        &self.regions[index]
    }
}

impl Default for Lab {
    fn default() -> Self {
        Self::new()
    }
}

/// 시나리오를 구성하고 Ground Truth 아티팩트를 반환한다.
pub fn setup(scenario: &str) -> Result<(Lab, Value), String> {
    let names: Vec<&str> = if scenario == "all" {
        vec![
            "normal",
            "pattern",
            "private",
            "private-exec",
            "pe-like",
            "threads",
            "protection",
        ]
    } else {
        vec![scenario]
    };

    let mut lab = Lab::new();
    let mut artifacts = serde_json::Map::new();
    for name in names {
        let value = match name {
            "normal" => normal(&mut lab)?,
            "pattern" => pattern(&mut lab)?,
            "private" => private(&mut lab)?,
            "private-exec" => private_exec(&mut lab)?,
            "pe-like" => pe_like(&mut lab)?,
            "threads" => threads(&mut lab)?,
            "protection" => protection(&mut lab)?,
            other => return Err(format!("알 수 없는 시나리오: {other}")),
        };
        artifacts.insert(name.to_string(), value);
    }
    Ok((lab, Value::Object(artifacts)))
}

fn normal(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(4096).map_err(|e| e.to_string())?;
    region.write(b"XMEM_BENIGN_MEMORY").map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
    }))
}

fn pattern(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(PATTERN_SIZE).map_err(|e| e.to_string())?;
    region.write(PATTERN_ASCII).map_err(|e| e.to_string())?;
    let wide: Vec<u8> = PATTERN_WIDE
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    region.write_at(WIDE_OFFSET, &wide).map_err(|e| e.to_string())?;
    region
        .write_at(BYTES_OFFSET, PATTERN_BYTES)
        .map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "ascii_offset": 0,
        "wide_offset": WIDE_OFFSET,
        "bytes_offset": BYTES_OFFSET,
        "ascii": std::str::from_utf8(PATTERN_ASCII).unwrap_or(""),
        "wide": PATTERN_WIDE,
    }))
}

fn private(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(8192).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_PRIVATE_BENIGN_DATA")
        .map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "protection": "RW",
    }))
}

fn private_exec(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(16 * 1024).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_PRIVATE_EXEC_BENIGN")
        .map_err(|e| e.to_string())?;
    region.protect(SELF_PAGE_RWX).map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "protection": "RWX",
    }))
}

fn pe_like(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(16 * 1024).map_err(|e| e.to_string())?;
    region
        .write(&fake_pe_bytes())
        .map_err(|e| e.to_string())?;
    region.protect(SELF_PAGE_RX).map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "protection": "RX",
    }))
}

fn threads(lab: &mut Lab) -> Result<Value, String> {
    let region = alloc_executable(&[0xC3], SELF_PAGE_RX).map_err(|e| e.to_string())?;
    let start_address = region.base();
    let index = lab.push(region);
    let handle = spawn_suspended_thread(start_address).map_err(|e| e.to_string())?;
    let tid = thread_id(&handle);
    lab.threads.push(handle);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "start_address": start_address,
        "tid": tid,
    }))
}

fn protection(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(8192).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_PROTECTION_EXPERIMENT")
        .map_err(|e| e.to_string())?;
    let old = region.protect(SELF_PAGE_RWX).map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "before": "RW",
        "after": "RWX",
        "old_raw": old,
    }))
}

/// private executable 메모리에 넣는 최소 PE (MZ + PE\0\0 + COFF + optional + .text).
pub fn fake_pe_bytes() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_offset = 0x40usize;
    buf[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

    let coff = pe_offset + 4;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0x00f0u16.to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());

    let section = opt + 0x00f0;
    buf[section..section + 5].copy_from_slice(b".text");
    buf[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    buf
}
```

- [ ] **Step 5: 실패하는 테스트 작성 (main.rs)**

`lab/targets/xmem-target/src/main.rs` 생성(테스트만):

```rust
//! XMem 연구용 Test Target.
//!
//! 사용: `xmem-target run <scenario> [--hold-secs N] [--report PATH]`
//! 시나리오: normal | pattern | private | private-exec | pe-like | threads | protection | all

mod scenarios;

use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde_json::json;

struct Args {
    scenario: String,
    hold_secs: u64,
    report: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let usage = "usage: xmem-target run <scenario> [--hold-secs N] [--report PATH]";
    let mut it = args.iter().skip(1);
    let scenario = match (it.next(), it.next()) {
        (Some(cmd), Some(name)) if cmd == "run" => name.clone(),
        _ => return Err(usage.to_string()),
    };
    let mut hold_secs = 30u64;
    let mut report = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--hold-secs" => {
                let value = it.next().ok_or("--hold-secs 값 필요")?;
                hold_secs = value.parse().map_err(|_| "--hold-secs는 정수")?;
            }
            "--report" => report = Some(it.next().ok_or("--report 값 필요")?.clone()),
            other => return Err(format!("알 수 없는 인자: {other}")),
        }
    }
    Ok(Args {
        scenario,
        hold_secs,
        report,
    })
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().collect();
    let args = match parse_args(&raw) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let (lab, artifacts) = match scenarios::setup(&args.scenario) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let report = json!({
        "scenario": args.scenario,
        "pid": xmem_windows::current_pid(),
        "artifacts": artifacts,
    });
    let text = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    let _ = writeln!(std::io::stdout(), "{text}");
    if let Some(path) = &args.report
        && let Err(e) = std::fs::write(path, &text)
    {
        eprintln!("error: report 쓰기 실패: {e}");
        return ExitCode::from(1);
    }

    let deadline = Instant::now() + Duration::from_secs(args.hold_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(lab);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_and_flags() {
        let parsed = parse_args(&args(&["xmem-target", "run", "all"])).unwrap();
        assert_eq!(parsed.scenario, "all");
        assert_eq!(parsed.hold_secs, 30);
        assert!(parsed.report.is_none());

        let parsed = parse_args(&args(&[
            "xmem-target",
            "run",
            "pattern",
            "--hold-secs",
            "5",
            "--report",
            "r.json",
        ]))
        .unwrap();
        assert_eq!(parsed.scenario, "pattern");
        assert_eq!(parsed.hold_secs, 5);
        assert_eq!(parsed.report.as_deref(), Some("r.json"));
    }

    #[test]
    fn parse_args_rejects_bad_input() {
        assert!(parse_args(&args(&["xmem-target"])).is_err());
        assert!(parse_args(&args(&["xmem-target", "run"])).is_err());
        assert!(parse_args(&args(&["xmem-target", "run", "x", "--hold-secs", "z"])).is_err());
        assert!(parse_args(&args(&["xmem-target", "run", "x", "--bogus"])).is_err());
    }
}
```

- [ ] **Step 6: 테스트 통과 확인**

Run: `cargo test -p xmem-target`
Expected: PASS — 4 (scenarios 2 + main 2)

- [ ] **Step 7: 스모크 (수동 실행)**

```powershell
cargo build -q -p xmem-target
$dir = Join-Path $env:TEMP "xmem-m10"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$p = Start-Process ".\target\debug\xmem-target.exe" -ArgumentList "run","all","--hold-secs","60","--report","$dir\report.json" -PassThru
Start-Sleep -Seconds 1
Get-Content "$dir\report.json" | Select-Object -First 12
Stop-Process -Id $p.Id -Force
```

기록: report의 pid/각 base/tid가 출력되는지.

- [ ] **Step 8: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-target --all-targets -- -D warnings
git add Cargo.toml Cargo.lock lab/targets/xmem-target
git commit -m "feat(lab): deterministic Test Target (xmem-target)"
```

---

### Task 3: Ground Truth 회귀 테스트

**Files:**
- Create: `lab/targets/xmem-target/tests/ground_truth.rs`
- Test: 이 파일 자체

**Interfaces:**
- Consumes: Task 2의 bin/report, `xmem_memory::{LiveProcess, ScanOptions, scan}`, `xmem_detection::detect_source`, `xmem_core::{MemorySource, ScanPattern, RegionClass}`.
- Produces: 회귀 fixture (`cargo test --workspace`에 포함).

- [ ] **Step 1: 실패하는 테스트 작성**

`lab/targets/xmem-target/tests/ground_truth.rs` 생성:

```rust
//! Ground Truth 회귀 테스트: xmem-target을 spawn하고 라이브 분석 결과를 대조한다.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use xmem_core::{MemorySource, RegionClass, ScanPattern};
use xmem_memory::{LiveProcess, ScanOptions, scan};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xmem-gt-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn_target(scenario: &str, report: &PathBuf) -> Child {
    Command::new(env!("CARGO_BIN_EXE_xmem-target"))
        .args([
            "run",
            scenario,
            "--hold-secs",
            "30",
            "--report",
            report.to_str().unwrap(),
        ])
        .spawn()
        .unwrap()
}

fn wait_for_report(path: &PathBuf) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(value) = serde_json::from_str(&text)
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "ground truth report가 생성되지 않았다"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn all_scenario_matches_ground_truth() {
    let dir = temp_dir("all");
    let report_path = dir.join("report.json");
    let mut child = spawn_target("all", &report_path);
    let report = wait_for_report(&report_path);
    let pid = report["pid"].as_u64().unwrap() as u32;

    let live = LiveProcess::open(pid).unwrap();
    let regions = live.regions().unwrap();
    let findings = xmem_detection::detect_source(&live).unwrap();

    // 1) pattern 영역: private RW, ASCII 패턴이 base에 존재
    let pattern = &report["artifacts"]["pattern"];
    let pattern_base = pattern["base"].as_u64().unwrap();
    let region = regions
        .iter()
        .find(|r| r.base == pattern_base)
        .expect("pattern region");
    assert_eq!(region.classification, RegionClass::Private);
    assert!(region.writable && !region.executable);

    let needle = ScanPattern::ascii(pattern["ascii"].as_str().unwrap()).unwrap();
    let cancel = AtomicBool::new(false);
    let scan_report = scan(&live, &needle, &ScanOptions::default(), &cancel).unwrap();
    assert!(
        scan_report.matches.iter().any(|m| m.address == pattern_base),
        "ascii 패턴이 pattern base에서 발견되어야 한다"
    );

    // 2) private-exec: executable private + XMEM-001
    let exec_base = report["artifacts"]["private-exec"]["base"].as_u64().unwrap();
    let exec_region = regions
        .iter()
        .find(|r| r.base == exec_base)
        .expect("private-exec region");
    assert!(exec_region.executable);
    assert_eq!(exec_region.classification, RegionClass::Private);
    assert!(
        findings.iter().any(|f| f.rule_id == "XMEM-001"
            && f.evidence[0].region_base == Some(exec_base)),
        "XMEM-001 at private-exec"
    );

    // 3) pe-like: XMEM-002
    let pe_base = report["artifacts"]["pe-like"]["base"].as_u64().unwrap();
    assert!(
        findings.iter().any(|f| f.rule_id == "XMEM-002"
            && f.evidence[0].region_base == Some(pe_base)),
        "XMEM-002 at pe-like"
    );

    // 4) suspended thread: XMEM-004 (tid 일치)
    let tid = report["artifacts"]["threads"]["tid"].as_u64().unwrap() as u32;
    let tid_text = tid.to_string();
    assert!(
        findings.iter().any(|f| f.rule_id == "XMEM-004"
            && f.evidence[0].observed.get("tid").map(String::as_str) == Some(tid_text.as_str())),
        "XMEM-004 for target thread {tid}"
    );

    child.kill().unwrap();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
```

- [ ] **Step 2: 테스트 통과 확인**

Run: `cargo test -p xmem-target`
Expected: PASS — 기존 4 + 신규 1 = 5

실패 시 진단 순서: report의 base가 실제 region인지(`xmem memory map --pid <target-pid>`), XMEM-002는 4 KiB 프로브 범위 안에 fake PE가 있는지, XMEM-004는 start address가 private executable로 잡히는지.

- [ ] **Step 3: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-target --all-targets -- -D warnings
git add lab/targets/xmem-target
git commit -m "test(lab): Ground Truth 회귀 테스트"
```

---

### Task 4: 문서 + 전체 게이트 + Windows 스모크

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-10-research-lab.md` (체크박스)

- [ ] **Step 1: README 갱신**

- Status 문구: "현재 **Milestone 10 (Research Lab)** 완료. ..." (M9 문구 교체).
- Status 표의 "Test Target + 실험 프레임워크 | Planned (M10~M11)" 행을 두 행으로 교체:
  - `Test Target (lab/targets/xmem-target) | Implemented (deterministic 시나리오: normal/pattern/private/private-exec/pe-like/threads/protection/all, Ground Truth JSON, Ground Truth 회귀 테스트)`
  - `Experiment 자동화 | Planned (M11)`
- Quick Start에 3줄 추가:
  ```powershell
  cargo build -p xmem-target
  .\target\debug\xmem-target.exe run all --hold-secs 60 --report report.json
  xmem detect --pid <TARGET-PID>
  ```
- CLI Usage 아래 Test Target 문단 추가(시나리오 목록, `--report`, 자기 프로세스만 변경, 회귀 테스트가 `cargo test --workspace`에 포함).
- Limitations: "M9 기준" → "M10 기준", M10 bullet 추가(타깃은 자기 프로세스만 변경, x64 Windows 전용, thread 실험은 suspended 스레드라 실행되지 않음, 주소는 실행마다 달라짐 — 테스트는 report의 주소를 사용).
- Roadmap: M10 → 완료.

- [ ] **Step 2: architecture.md 갱신**

- crate 표에 `xmem-target` 행 추가(`lab/targets/xmem-target`, M10 (생성됨), "research fixture; xmem-windows만 의존, 자기 프로세스 메모리만 변경").
- Windows API 표 M10 행 추가: `VirtualAlloc`/`VirtualProtect`/`VirtualFree`/`CreateThread`/`GetThreadId` (feature `Win32_System_Memory` 기존 + `Win32_System_Threading` 기존) — "구현됨(`xmem-windows::selfmem`). lab target 전용, 자기 프로세스 한정. 외부 프로세스 조작(VirtualAllocEx 등)은 M11 `xmem-experiments`."
- §14 Status 표: "M10 Research Lab(Test Target + Ground Truth 회귀 테스트) | Done" + "M11~M12 | Planned".

- [ ] **Step 3: 전체 게이트**

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0. 테스트 합계 **212** = cli 55 + core 34 + detection 8 + forensics 24 + memory 21 + pe 9 + windows 57 + target 4 + ground_truth 1.

- [ ] **Step 4: Windows 스모크 (타깃 + CLI 교차 검증)**

```powershell
$dir = Join-Path $env:TEMP "xmem-m10"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = ".\target\debug\xmem.exe"
$p = Start-Process ".\target\debug\xmem-target.exe" -ArgumentList "run","all","--hold-secs","60","--report","$dir\report.json" -PassThru
Start-Sleep -Seconds 1

# detect: XMEM-001/002/004가 report 주소와 일치하는지
& $exe detect --pid $p.Id | Select-String -Pattern "XMEM-00[124]" | Select-Object -First 6
# memory scan: ASCII 패턴 주소 확인
$base = (Get-Content "$dir\report.json" | ConvertFrom-Json).artifacts.pattern.base
& $exe memory scan --pid $p.Id --string "XMEM_PATTERN_ALPHA_0123456789" --max-results 3
# modules/threads: target 프로세스
& $exe threads --pid $p.Id | Select-Object -First 6

Stop-Process -Id $p.Id -Force
Get-ChildItem $dir | Select-Object -ExpandProperty Name
Remove-Item -Recurse -Force $dir
```

기록: report의 pattern/private-exec/pe-like base와 detect finding의 region base 일치, thread tid 일치, scan 매치 주소 = pattern base.

- [ ] **Step 5: 계획서 체크박스 + 커밋**

`docs/plans/milestone-10-research-lab.md`의 모든 `- [ ]` → `- [x]` (replaceAll).

```powershell
git add README.md docs/architecture.md docs/plans/milestone-10-research-lab.md
git commit -m "docs: M10 Research Lab 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지**: §22 Test Target(시나리오 7종), §40 Regression Fixture(Ground Truth 회귀 테스트), §27 Host 보호(자기 프로세스만), §19~21 실험 타깃 요구(deterministic, cleanup) 모두 Task에 매핑됨. M11(Experiment 자동화)은 별도 마일스톤으로 남김.
- **의존성**: xmem-target은 `xmem-windows`+`serde_json`만 런타임 의존, 분석 라이브러리는 dev-dependency(테스트 전용). 새 외부 crate 없음.
- **타입 일관성**: `PrivateRegion`/`alloc_executable`/`spawn_suspended_thread`/`thread_id`/`setup`/`fake_pe_bytes` 이름이 Task 1~3에서 동일. `xmem_memory::scan` 시그니처는 M4 구현 그대로(`scan(&source, &pattern, &options, &cancel)`).
- **미구현으로 남기는 것**: `xmem experiment list/run`(M11), 실험 격리 검증 자동화(M11), GUI/시각화(후속).
