# XMem Milestone 3 — Virtual Memory Map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xmem memory map --pid <PID>`가 `VirtualQueryEx` 기반으로 대상 프로세스의 가상 메모리 영역을 수집·분류·표시하고, 이후 스캐너/스냅샷이 재사용할 `LiveProcess` MemorySource 첫 구현을 만든다.

**Architecture:** 3계층 — (1) core에 순수 분류 로직(`classify.rs`: state/type → RegionClass, protection → Heuristic), (2) xmem-windows에 `VirtualQueryEx` 래핑(`memory.rs`, unsafe는 여기에만), (3) 새 crate `xmem-memory`가 `LiveProcess`로 둘을 묶고 CLI가 표시한다. 모델 변경은 `MemoryRegion.region_type: Option<MemoryType>` 하나뿐이다(Free/Reserve 영역은 Type이 0이므로).

**Tech Stack:** Rust 1.98 / edition 2024, windows 0.62 (`Win32_System_Memory` feature 추가), clap 4, serde/serde_json, tracing. **새 외부 dependency 없음.**

**Spec:** `docs/architecture.md` — MemorySource 추상화, Data Model, Safety/Host Stability, M3 계획 섹션.

## Global Constraints

- Rust stable 1.98+, edition 2024. `cargo fmt --all -- --check`, `cargo clippy -q --workspace --all-targets -- -D warnings` 통과.
- `unsafe`는 `xmem-windows`에만 허용(workspace lint `unsafe_code = "deny"`, xmem-windows만 `allow`). core/memory/cli에 unsafe 금지.
- 분석 명령은 read-only. M3에서 쓰기 Win32 API를 호출하지 않는다(VirtualQueryEx / GetMappedFileNameW / GetNativeSystemInfo만).
- bounded resources: region walk는 `MAX_REGIONS`(1_048_576) 상한, mapped file 버퍼(32KiB UTF-16)는 재사용, 프로세스 메모리를 한 번에 올리지 않는다.
- 오류는 `XmemError`로 구조화한다. CLI exit code 계약 유지: 0 성공 / 1 런타임 오류 / 2 사용법 오류 / 3 정책 거부.
- JSON 출력은 `{"ok":true,"schema_version":1,...}` envelope(`output::success_envelope`), human 출력은 고정폭 표.
- 한글 문서/커밋 메시지 유지. 커밋 prefix: feat/fix/docs/style/refactor/test/chore.
- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`(check는 `#[cfg(test)]`를 컴파일하지 않음).

## Review Focus

테스트가 못 잡기 쉬운 5개 실패 모드. 각 항목은 담당 Task에 테스트가 배치되어 있다.

1. **권한 부족 프로세스**(예: lsass, 비관리자 셸): map 시 panic/부분 출력 없이 구조화된 `access_denied` 오류 → Task 3 테스트 + Task 5 스모크.
2. **walk 종료**: `ERROR_INVALID_PARAMETER(87)` / `RegionSize == 0` / 주소 비진행 시 무한루프 없이 정상 종료 → Task 2 테스트(진행 보장 코드 포함).
3. **MAX_REGIONS 도달**: 조용히 잘리지 않고 `truncated: true`로 정직하게 보고(JSON·human 경고) → Task 2 테스트 + Task 4 테스트.
4. **Free/Reserve 영역**: `region_type: None`, mapped file 조회를 시도하지 않음(가짜 파일명 없음) → Task 2·3 테스트.
5. **매우 긴 mapped file 경로 / 작은 버퍼**: panic·깨진 문자열 없이 `None` 또는 lossy prefix → Task 2 테스트.

## File Structure

- Modify: `crates/xmem-core/src/model/memory.rs` — `region_type: Option<MemoryType>`, Display 4종
- Create: `crates/xmem-core/src/classify.rs` — classify/heuristics + 테스트
- Modify: `crates/xmem-core/src/lib.rs` — `pub mod classify; pub use classify::{classify, heuristics};`
- Modify: `crates/xmem-windows/Cargo.toml` — `Win32_System_Memory` feature
- Create: `crates/xmem-windows/src/memory.rs` — RawRegion/walk/mapped file/region_from_raw + 테스트
- Modify: `crates/xmem-windows/src/lib.rs` — `pub mod memory;` + 재수출
- Create: `crates/xmem-memory/Cargo.toml`, `crates/xmem-memory/src/lib.rs`, `crates/xmem-memory/src/live.rs`
- Modify: `Cargo.toml` — members + workspace.dependencies에 xmem-memory
- Modify: `crates/xmem-cli/Cargo.toml` — xmem-memory 의존
- Create: `crates/xmem-cli/src/commands/render.rs` — truncate 이동 + 표시 헬퍼
- Modify: `crates/xmem-cli/src/commands/mod.rs` — `pub(crate) mod render;`
- Modify: `crates/xmem-cli/src/commands/process.rs` — truncate 제거, render 사용
- Modify: `crates/xmem-cli/src/commands/memory.rs` — map 구현
- Modify: `README.md`, `docs/architecture.md` — M3 상태 반영

---

### Task 1: core — region_type Option + classify/heuristics + Display

**Files:**
- Create: `crates/xmem-core/src/classify.rs`
- Modify: `crates/xmem-core/src/lib.rs`
- Modify: `crates/xmem-core/src/model/memory.rs`

**Interfaces:**
- Consumes: 기존 `MemoryState`, `MemoryType`, `Protection`, `RegionClass`, `Heuristic`.
- Produces:
  - `pub fn classify(state: MemoryState, region_type: Option<MemoryType>) -> RegionClass`
  - `pub fn heuristics(state: MemoryState, protection: &Protection, region_type: Option<MemoryType>) -> Vec<Heuristic>`
  - `impl fmt::Display for MemoryState / MemoryType / RegionClass / Heuristic`
  - `MemoryRegion.region_type` 타입이 `Option<MemoryType>`로 변경

- [x] **Step 1: classify.rs 테스트 먼저 작성 (red)**

`crates/xmem-core/src/classify.rs`:

```rust
use crate::model::{Heuristic, MemoryState, MemoryType, Protection, RegionClass};

#[cfg(test)]
mod tests {
    use super::*;

    fn prot(raw: u32, r: bool, w: bool, x: bool) -> Protection {
        Protection::new(raw, r, w, x)
    }

    #[test]
    fn classify_maps_state_and_type() {
        assert_eq!(classify(MemoryState::Free, None), RegionClass::Free);
        assert_eq!(classify(MemoryState::Reserve, None), RegionClass::Reserved);
        assert_eq!(
            classify(MemoryState::Commit, Some(MemoryType::Image)),
            RegionClass::Image
        );
        assert_eq!(
            classify(MemoryState::Commit, Some(MemoryType::Mapped)),
            RegionClass::Mapped
        );
        assert_eq!(
            classify(MemoryState::Commit, Some(MemoryType::Private)),
            RegionClass::Private
        );
        assert_eq!(classify(MemoryState::Commit, None), RegionClass::Unknown);
    }

    #[test]
    fn heuristics_flags_private_executable_first() {
        let hs = heuristics(
            MemoryState::Commit,
            &prot(0x40, true, true, true),
            Some(MemoryType::Private),
        );
        assert_eq!(
            hs,
            vec![Heuristic::ExecutablePrivate, Heuristic::WritableExecutable]
        );
    }

    #[test]
    fn heuristics_executable_private_without_write() {
        let hs = heuristics(
            MemoryState::Commit,
            &prot(0x20, true, false, true),
            Some(MemoryType::Private),
        );
        assert_eq!(hs, vec![Heuristic::ExecutablePrivate]);
    }

    #[test]
    fn heuristics_writable_executable_for_image() {
        let hs = heuristics(
            MemoryState::Commit,
            &prot(0x40, true, true, true),
            Some(MemoryType::Image),
        );
        assert_eq!(hs, vec![Heuristic::WritableExecutable]);
    }

    #[test]
    fn heuristics_ignore_non_executable_and_non_commit() {
        assert!(
            heuristics(
                MemoryState::Commit,
                &prot(0x04, true, true, false),
                Some(MemoryType::Private)
            )
            .is_empty()
        );
        assert!(
            heuristics(
                MemoryState::Reserve,
                &prot(0x40, true, true, true),
                Some(MemoryType::Private)
            )
            .is_empty()
        );
        assert!(heuristics(MemoryState::Free, &prot(0x01, false, false, false), None).is_empty());
    }
}
```

`crates/xmem-core/src/lib.rs`의 `pub mod version;` 아래에 `pub mod classify;`와 재수출을 추가:

```rust
pub mod classify;
```

```rust
pub use classify::{classify, heuristics};
```

- [x] **Step 2: red 확인**

Run: `cargo check -p xmem-core --tests`
Expected: FAIL — `cannot find function classify` (E0425), `cannot find function heuristics` (E0425).

- [x] **Step 3: classify.rs 구현**

테스트 모듈 위에 추가:

```rust
/// Windows state/type 조합을 연구용 분류로 변환한다. 사실(관찰)이며 해석이 아니다.
pub fn classify(state: MemoryState, region_type: Option<MemoryType>) -> RegionClass {
    match state {
        MemoryState::Free => RegionClass::Free,
        MemoryState::Reserve => RegionClass::Reserved,
        MemoryState::Commit => match region_type {
            Some(MemoryType::Image) => RegionClass::Image,
            Some(MemoryType::Mapped) => RegionClass::Mapped,
            Some(MemoryType::Private) => RegionClass::Private,
            None => RegionClass::Unknown,
        },
    }
}

/// 분류 힌트. Detection Rule의 입력으로만 사용하며 악성 판정이 아니다.
pub fn heuristics(
    state: MemoryState,
    protection: &Protection,
    region_type: Option<MemoryType>,
) -> Vec<Heuristic> {
    let mut out = Vec::new();
    if state == MemoryState::Commit && protection.executable {
        if region_type == Some(MemoryType::Private) {
            out.push(Heuristic::ExecutablePrivate);
        }
        if protection.writable {
            out.push(Heuristic::WritableExecutable);
        }
    }
    out
}
```

- [x] **Step 4: memory.rs 모델 변경 + Display + 테스트**

`region_type: MemoryType` → `region_type: Option<MemoryType>` (line 78). 그리고 `impl fmt::Display for Protection` 아래에 Display 4종 추가:

```rust
impl fmt::Display for MemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MemoryState::Commit => "MEM_COMMIT",
            MemoryState::Reserve => "MEM_RESERVE",
            MemoryState::Free => "MEM_FREE",
        };
        f.write_str(name)
    }
}

impl fmt::Display for MemoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MemoryType::Image => "MEM_IMAGE",
            MemoryType::Mapped => "MEM_MAPPED",
            MemoryType::Private => "MEM_PRIVATE",
        };
        f.write_str(name)
    }
}

impl fmt::Display for RegionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            RegionClass::Image => "image",
            RegionClass::Mapped => "mapped",
            RegionClass::Private => "private",
            RegionClass::Free => "free",
            RegionClass::Reserved => "reserved",
            RegionClass::Unknown => "unknown",
        };
        f.write_str(name)
    }
}

impl fmt::Display for Heuristic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Heuristic::ExecutablePrivate => "executable_private",
            Heuristic::ExecutableAnonymous => "executable_anonymous",
            Heuristic::PrivateExecutablePeLike => "private_executable_pe_like",
            Heuristic::WritableExecutable => "writable_executable",
        };
        f.write_str(name)
    }
}
```

파일 끝에 테스트 모듈 추가:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_match_windows_flags() {
        assert_eq!(MemoryState::Commit.to_string(), "MEM_COMMIT");
        assert_eq!(MemoryState::Reserve.to_string(), "MEM_RESERVE");
        assert_eq!(MemoryState::Free.to_string(), "MEM_FREE");
        assert_eq!(MemoryType::Image.to_string(), "MEM_IMAGE");
        assert_eq!(MemoryType::Mapped.to_string(), "MEM_MAPPED");
        assert_eq!(MemoryType::Private.to_string(), "MEM_PRIVATE");
        assert_eq!(RegionClass::Reserved.to_string(), "reserved");
        assert_eq!(RegionClass::Unknown.to_string(), "unknown");
        assert_eq!(Heuristic::ExecutablePrivate.to_string(), "executable_private");
        assert_eq!(
            Heuristic::PrivateExecutablePeLike.to_string(),
            "private_executable_pe_like"
        );
    }

    #[test]
    fn protection_display_includes_flags_and_raw() {
        assert_eq!(Protection::new(0x40, true, true, true).to_string(), "RWX (0x40)");
        assert_eq!(Protection::new(0x01, false, false, false).to_string(), "--- (0x01)");
    }
}
```

- [x] **Step 5: green + workspace 영향 확인**

Run: `cargo test -p xmem-core`
Expected: PASS — 기존 16 + 신규 7 = 23 tests.

Run: `cargo check --workspace --tests`
Expected: PASS (region_type 리터럴 사용처가 memory.rs 외에 없음을 확인).

- [x] **Step 6: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-core --all-targets -- -D warnings
git add crates/xmem-core
git commit -m "feat(core): 메모리 영역 분류 로직과 region_type Option화"
```

---

### Task 2: xmem-windows — VirtualQueryEx 래핑

**Files:**
- Modify: `crates/xmem-windows/Cargo.toml` (features에 `"Win32_System_Memory"` 추가)
- Create: `crates/xmem-windows/src/memory.rs`
- Modify: `crates/xmem-windows/src/lib.rs`

**Interfaces:**
- Consumes: `crate::error::{last_win32_error, win32_code_from_hresult}`, `crate::handle::OwnedHandle`, `crate::util::utf16_z_to_string`, core의 `classify/heuristics/모델`.
- Produces:
  - `pub const MAX_REGIONS: usize = 1_048_576;`
  - `pub struct RawRegion { pub base: u64, pub allocation_base: u64, pub size: u64, pub state: u32, pub protect: u32, pub allocation_protect: u32, pub region_type: u32 }`
  - `pub struct RegionWalk { pub regions: Vec<RawRegion>, pub truncated: bool }`
  - `pub fn protection_from_raw(raw: u32) -> Protection`
  - `pub fn memory_state(raw: u32) -> Option<MemoryState>`
  - `pub fn memory_type(raw: u32) -> Option<MemoryType>`
  - `pub fn is_file_backed(region: &RawRegion) -> bool`
  - `pub fn walk_regions(handle: &OwnedHandle, max_address: u64, max_regions: usize) -> Result<RegionWalk>`
  - `pub fn mapped_file_name(handle: &OwnedHandle, base: u64, buf: &mut [u16]) -> Option<String>`
  - `pub fn native_max_user_address() -> u64`
  - `pub fn region_from_raw(raw: &RawRegion, mapped_file: Option<String>) -> Option<MemoryRegion>`

- [x] **Step 1: 테스트 먼저 작성 (red)**

`crates/xmem-windows/src/memory.rs`:

```rust
use std::ffi::c_void;
use std::mem::size_of;

use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use xmem_core::{
    MemoryRegion, MemoryState, MemoryType, Protection, RegionClass, classify, heuristics,
};

use crate::error::{last_win32_error, win32_code_from_hresult};
use crate::handle::OwnedHandle;
use crate::util::utf16_z_to_string;

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_region(state: u32, protect: u32, region_type: u32) -> RawRegion {
        RawRegion {
            base: 0x1000_0000,
            allocation_base: 0x1000_0000,
            size: 0x1000,
            state,
            protect,
            allocation_protect: 0,
            region_type,
        }
    }

    #[test]
    fn protection_flags_decode_known_values() {
        let cases = [
            (PAGE_NOACCESS.0, false, false, false),
            (PAGE_READONLY.0, true, false, false),
            (PAGE_READWRITE.0, true, true, false),
            (PAGE_WRITECOPY.0, true, true, false),
            (PAGE_EXECUTE.0, false, false, true),
            (PAGE_EXECUTE_READ.0, true, false, true),
            (PAGE_EXECUTE_READWRITE.0, true, true, true),
            (PAGE_EXECUTE_WRITECOPY.0, true, true, true),
        ];
        for (raw, r, w, x) in cases {
            let p = protection_from_raw(raw);
            assert_eq!((p.readable, p.writable, p.executable), (r, w, x), "raw={raw:#x}");
        }
    }

    #[test]
    fn protection_keeps_guard_bits_in_raw() {
        let p = protection_from_raw(PAGE_EXECUTE_READ.0 | 0x100);
        assert_eq!(p.raw, PAGE_EXECUTE_READ.0 | 0x100);
        assert!(p.executable && p.readable && !p.writable);
    }

    #[test]
    fn state_and_type_unknown_values_are_none() {
        assert_eq!(memory_state(MEM_COMMIT.0), Some(MemoryState::Commit));
        assert_eq!(memory_state(MEM_RESERVE.0), Some(MemoryState::Reserve));
        assert_eq!(memory_state(MEM_FREE.0), Some(MemoryState::Free));
        assert_eq!(memory_state(0), None);
        assert_eq!(memory_state(0xDEAD), None);
        assert_eq!(memory_type(MEM_IMAGE.0), Some(MemoryType::Image));
        assert_eq!(memory_type(MEM_MAPPED.0), Some(MemoryType::Mapped));
        assert_eq!(memory_type(MEM_PRIVATE.0), Some(MemoryType::Private));
        assert_eq!(memory_type(0), None);
    }

    #[test]
    fn region_from_raw_free_has_no_type_or_allocation_protection() {
        let region = region_from_raw(&raw_region(MEM_FREE.0, 0, 0), None).unwrap();
        assert_eq!(region.state, MemoryState::Free);
        assert_eq!(region.region_type, None);
        assert_eq!(region.classification, RegionClass::Free);
        assert!(region.heuristics.is_empty());
        assert_eq!(region.allocation_protection, None);
    }

    #[test]
    fn region_from_raw_private_rwx_flags_heuristics() {
        let region =
            region_from_raw(&raw_region(MEM_COMMIT.0, PAGE_EXECUTE_READWRITE.0, MEM_PRIVATE.0), None)
                .unwrap();
        assert_eq!(region.classification, RegionClass::Private);
        assert!(region.executable && region.writable);
        assert_eq!(region.heuristics.len(), 2);
    }

    #[test]
    fn region_from_raw_unknown_state_is_none() {
        assert!(region_from_raw(&raw_region(0, PAGE_READONLY.0, 0), None).is_none());
    }

    #[test]
    fn walk_regions_of_self_is_monotonic() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        assert!(!walk.regions.is_empty());
        assert!(!walk.truncated);
        assert!(walk.regions.iter().all(|r| r.size > 0));
        assert!(walk.regions.windows(2).all(|w| w[0].base < w[1].base));
    }

    #[test]
    fn walk_regions_honors_cap_and_reports_truncation() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), 3).unwrap();
        assert_eq!(walk.regions.len(), 3);
        assert!(walk.truncated);
    }

    #[test]
    fn mapped_file_name_of_self_image_region() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        let image = walk.regions.iter().find(|r| is_file_backed(r)).unwrap();
        let mut buf = vec![0u16; 32 * 1024];
        let name = mapped_file_name(&handle, image.base, &mut buf).unwrap();
        assert!(!name.is_empty());
        assert!(!name.contains('\0'));
    }

    #[test]
    fn mapped_file_name_small_buffer_does_not_panic() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        let image = walk.regions.iter().find(|r| is_file_backed(r)).unwrap();
        let mut buf = vec![0u16; 2];
        let name = mapped_file_name(&handle, image.base, &mut buf);
        assert!(name.is_none_or(|n| n.chars().count() <= 2));
    }
}
```

`crates/xmem-windows/src/lib.rs`에 모듈 등록:

```rust
pub mod memory;
```

- [x] **Step 2: red 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — E0433/E0425 (RawRegion, walk_regions, MAX_REGIONS 등 없음).

- [x] **Step 3: memory.rs 구현**

테스트 모듈 위에 추가:

```rust
/// region walk 상한. 초과 시 truncated로 보고한다.
pub const MAX_REGIONS: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRegion {
    pub base: u64,
    pub allocation_base: u64,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub allocation_protect: u32,
    pub region_type: u32,
}

#[derive(Debug, Default)]
pub struct RegionWalk {
    pub regions: Vec<RawRegion>,
    pub truncated: bool,
}

/// PAGE_* 값을 R/W/X 플래그로 디코드한다. guard/nocache는 raw에 보존된다.
pub fn protection_from_raw(raw: u32) -> Protection {
    let base = raw & 0xff;
    let (readable, writable, executable) =
        if base == PAGE_EXECUTE_READWRITE.0 || base == PAGE_EXECUTE_WRITECOPY.0 {
            (true, true, true)
        } else if base == PAGE_EXECUTE_READ.0 {
            (true, false, true)
        } else if base == PAGE_EXECUTE.0 {
            (false, false, true)
        } else if base == PAGE_READWRITE.0 || base == PAGE_WRITECOPY.0 {
            (true, true, false)
        } else if base == PAGE_READONLY.0 {
            (true, false, false)
        } else {
            (false, false, false)
        };
    Protection::new(raw, readable, writable, executable)
}

pub fn memory_state(raw: u32) -> Option<MemoryState> {
    if raw == MEM_COMMIT.0 {
        Some(MemoryState::Commit)
    } else if raw == MEM_RESERVE.0 {
        Some(MemoryState::Reserve)
    } else if raw == MEM_FREE.0 {
        Some(MemoryState::Free)
    } else {
        None
    }
}

pub fn memory_type(raw: u32) -> Option<MemoryType> {
    if raw == MEM_IMAGE.0 {
        Some(MemoryType::Image)
    } else if raw == MEM_MAPPED.0 {
        Some(MemoryType::Mapped)
    } else if raw == MEM_PRIVATE.0 {
        Some(MemoryType::Private)
    } else {
        None
    }
}

/// 파일(이미지/매핑) 기반 commit 영역인지. Free/Reserve/Private에는 file name이 없다.
pub fn is_file_backed(region: &RawRegion) -> bool {
    region.state == MEM_COMMIT.0
        && (region.region_type == MEM_IMAGE.0 || region.region_type == MEM_MAPPED.0)
}

/// VirtualQueryEx를 max_address까지 반복한다. 정상 종료 조건: 87(INVALID_PARAMETER), RegionSize==0, 주소 비진행.
pub fn walk_regions(
    handle: &OwnedHandle,
    max_address: u64,
    max_regions: usize,
) -> Result<RegionWalk> {
    let mut regions = Vec::new();
    let mut address: u64 = 0;
    let mut truncated = false;
    loop {
        if address >= max_address {
            break;
        }
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                handle.raw(),
                Some(address as *const c_void),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            let err = windows::core::Error::from_thread();
            if win32_code_from_hresult(err.code().0) == ERROR_INVALID_PARAMETER.0 {
                break;
            }
            return Err(last_win32_error("VirtualQueryEx"));
        }
        let size = mbi.RegionSize as u64;
        if size == 0 {
            break;
        }
        if regions.len() >= max_regions {
            truncated = true;
            break;
        }
        regions.push(RawRegion {
            base: mbi.BaseAddress as u64,
            allocation_base: mbi.AllocationBase as u64,
            size,
            state: mbi.State.0,
            protect: mbi.Protect.0,
            allocation_protect: mbi.AllocationProtect.0,
            region_type: mbi.Type.0,
        });
        let next = (mbi.BaseAddress as u64).max(address).saturating_add(size);
        if next <= address {
            break;
        }
        address = next;
    }
    Ok(RegionWalk { regions, truncated })
}

/// 매핑된 파일 이름(디바이스 경로). 실패(0)면 None. buf는 재사용 가능한 UTF-16 버퍼.
pub fn mapped_file_name(handle: &OwnedHandle, base: u64, buf: &mut [u16]) -> Option<String> {
    let len = unsafe { GetMappedFileNameW(handle.raw(), base as *const c_void, buf) };
    if len == 0 {
        return None;
    }
    let len = (len as usize).min(buf.len());
    Some(utf16_z_to_string(&buf[..len]))
}

/// 사용자 주소 공간 상한(GetNativeSystemInfo). walk 종료 조건으로 사용한다.
pub fn native_max_user_address() -> u64 {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    info.lpMaximumApplicationAddress as u64
}

/// RawRegion을 core 모델로 변환한다. 알 수 없는 state는 None(호출자가 skip).
pub fn region_from_raw(raw: &RawRegion, mapped_file: Option<String>) -> Option<MemoryRegion> {
    let state = memory_state(raw.state)?;
    let region_type = memory_type(raw.region_type);
    let protection = protection_from_raw(raw.protect);
    let allocation_protection =
        (raw.allocation_protect != 0).then(|| protection_from_raw(raw.allocation_protect));
    let classification = classify(state, region_type);
    let hs = heuristics(state, &protection, region_type);
    Some(MemoryRegion {
        base: raw.base,
        size: raw.size,
        state,
        protection,
        allocation_protection,
        region_type,
        readable: protection.readable,
        writable: protection.writable,
        executable: protection.executable,
        classification,
        heuristics: hs,
        mapped_file,
    })
}
```

- [x] **Step 4: green 확인**

Run: `cargo test -p xmem-windows`
Expected: PASS — 기존 27 + 신규 10 = 37 tests.

- [x] **Step 5: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows
git commit -m "feat(windows): VirtualQueryEx 메모리 영역 walk와 매핑 파일 조회"
```

---

### Task 3: xmem-memory crate — LiveProcess MemorySource

**Files:**
- Create: `crates/xmem-memory/Cargo.toml`
- Create: `crates/xmem-memory/src/lib.rs`
- Create: `crates/xmem-memory/src/live.rs`
- Modify: `Cargo.toml` (workspace)

**Interfaces:**
- Consumes: `xmem_windows::{OwnedHandle, open_for_query, process_info, memory::{...}, current_pid}`, core `MemorySource` trait.
- Produces:
  - `pub struct RegionMap { pub regions: Vec<MemoryRegion>, pub truncated: bool }`
  - `pub struct LiveProcess { pub pid: u32, pub handle: OwnedHandle, pub info: ProcessInfo }`
  - `LiveProcess::open(pid: u32) -> Result<LiveProcess>`
  - `LiveProcess::region_map(&self) -> Result<RegionMap>`
  - `impl MemorySource for LiveProcess`

- [x] **Step 1: workspace 등록 + crate 골격 + 테스트 (red)**

`Cargo.toml`(루트): members에 `"crates/xmem-memory"` 추가, `[workspace.dependencies]`에 추가:

```toml
xmem-memory = { path = "crates/xmem-memory" }
```

`crates/xmem-memory/Cargo.toml`:

```toml
[package]
name = "xmem-memory"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
xmem-windows.workspace = true
tracing.workspace = true
```

`crates/xmem-memory/src/lib.rs`:

```rust
//! MemorySource 구현: LiveProcess / Snapshot / Minidump / MemoryImage.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod live;

pub use live::{LiveProcess, RegionMap};
```

`crates/xmem-memory/src/live.rs`:

```rust
use xmem_core::{
    MemoryRegion, MemorySource, ModuleInfo, ProcessInfo, ReadOutcome, Result, ThreadInfo, XmemError,
};
use xmem_windows::{
    OwnedHandle, memory, open_for_query, process_info,
};

#[derive(Debug, Clone)]
pub struct RegionMap {
    pub regions: Vec<MemoryRegion>,
    pub truncated: bool,
}

/// 실행 중 프로세스. handle은 RAII로 닫힌다.
pub struct LiveProcess {
    pub pid: u32,
    pub handle: OwnedHandle,
    pub info: ProcessInfo,
}

impl LiveProcess {
    pub fn open(pid: u32) -> Result<Self> {
        let info = process_info(pid)?;
        let handle = open_for_query(pid)?;
        Ok(Self { pid, handle, info })
    }

    /// VirtualQueryEx walk + 매핑 파일 이름 조회. 버퍼는 1회 할당 후 재사용한다.
    pub fn region_map(&self) -> Result<RegionMap> {
        let walk = memory::walk_regions(
            &self.handle,
            memory::native_max_user_address(),
            memory::MAX_REGIONS,
        )?;
        let mut regions = Vec::with_capacity(walk.regions.len());
        let mut buf = vec![0u16; 32 * 1024];
        for raw in &walk.regions {
            let mapped_file = if memory::is_file_backed(raw) {
                memory::mapped_file_name(&self.handle, raw.base, &mut buf)
            } else {
                None
            };
            match memory::region_from_raw(raw, mapped_file) {
                Some(region) => regions.push(region),
                None => tracing::warn!(
                    base = format_args!("{:#x}", raw.base),
                    state = raw.state,
                    "알 수 없는 memory state, 영역 건너뜀"
                ),
            }
        }
        Ok(RegionMap {
            regions,
            truncated: walk.truncated,
        })
    }
}

impl MemorySource for LiveProcess {
    fn process(&self) -> &ProcessInfo {
        &self.info
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>> {
        Ok(self.region_map()?.regions)
    }

    fn read(&self, _address: u64, _buf: &mut [u8]) -> Result<ReadOutcome> {
        Err(XmemError::Unimplemented {
            feature: "memory read",
        })
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Err(XmemError::Unimplemented {
            feature: "module enumeration",
        })
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Err(XmemError::Unimplemented {
            feature: "thread enumeration",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_self_and_map_regions() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let map = live.region_map().unwrap();
        assert!(!map.regions.is_empty());
        assert!(map.regions.iter().all(|r| r.size > 0));
        assert!(map.regions.iter().any(|r| r.classification == xmem_core::RegionClass::Image));
        assert!(
            map.regions
                .iter()
                .all(|r| r.mapped_file.is_none() || r.region_type.is_some())
        );
        assert!(
            map.regions
                .iter()
                .filter(|r| r.classification == xmem_core::RegionClass::Free)
                .all(|r| r.region_type.is_none())
        );
    }

    #[test]
    fn open_bogus_pid_fails_structured() {
        let err = LiveProcess::open(0xFFFF_FFFE).unwrap_err();
        assert!(matches!(err, XmemError::ProcessExited { .. }));
    }

    #[test]
    fn memory_source_impl_matches_region_map() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let direct = live.region_map().unwrap();
        let via_trait = live.regions().unwrap();
        assert_eq!(direct.regions.len(), via_trait.len());
        assert_eq!(live.process().pid, xmem_windows::current_pid());
    }

    #[test]
    fn unimplemented_methods_are_explicit() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        assert!(matches!(
            live.read(0, &mut [0u8; 4]).unwrap_err(),
            XmemError::Unimplemented { .. }
        ));
        assert!(matches!(
            live.modules().unwrap_err(),
            XmemError::Unimplemented { .. }
        ));
        assert!(matches!(
            live.threads().unwrap_err(),
            XmemError::Unimplemented { .. }
        ));
    }
}
```

- [x] **Step 2: red 확인**

Run: `cargo check -p xmem-memory --tests`
Expected: FAIL — crate 미등록/모듈 없음 오류(E0433 등).

- [x] **Step 3: green 확인**

Run: `cargo test -p xmem-memory`
Expected: PASS — 4 tests. (LiveProcess::open이 self 프로세스에 대해 동작)

- [x] **Step 4: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-memory --all-targets -- -D warnings
git add Cargo.toml crates/xmem-memory
git commit -m "feat(memory): LiveProcess MemorySource와 region map 수집"
```

---

### Task 4: CLI — `memory map` 구현과 표시 헬퍼

**Files:**
- Create: `crates/xmem-cli/src/commands/render.rs`
- Modify: `crates/xmem-cli/src/commands/mod.rs`
- Modify: `crates/xmem-cli/src/commands/process.rs` (truncate 이동)
- Modify: `crates/xmem-cli/src/commands/memory.rs`
- Modify: `crates/xmem-cli/Cargo.toml` (xmem-memory 추가)

**Interfaces:**
- Consumes: `xmem_memory::LiveProcess`, `output::{emit_json, resolve_mode, success_envelope, OutputMode}`, `cli::{GlobalArgs, MemoryCmd}`.
- Produces:
  - `render::{truncate, truncate_tail, human_size, heur_short}`
  - `memory::run(cmd: &MemoryCmd, global: &GlobalArgs) -> Result<()>` (Map 구현, Scan은 unimplemented 유지)

- [x] **Step 1: render.rs 작성 (truncate 이동) + 테스트**

`crates/xmem-cli/src/commands/render.rs`:

```rust
use xmem_core::Heuristic;

/// 앞을 남기고 자른다. process 표에서 사용.
pub(crate) fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

/// 뒤(파일명/경로 끝)를 남기고 자른다. mapped file 경로에서 사용.
pub(crate) fn truncate_tail(text: &str, max: usize) -> String {
    let count = text.chars().count();
    if count <= max {
        return text.to_string();
    }
    let mut out = String::from("...");
    out.extend(text.chars().skip(count - max.saturating_sub(3)));
    out
}

/// 사람이 읽는 크기. 1024 미만은 B, 이상은 KiB/MiB/GiB (소수 1자리).
pub(crate) fn human_size(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub(crate) fn heur_short(h: Heuristic) -> &'static str {
    match h {
        Heuristic::ExecutablePrivate => "exec-private",
        Heuristic::ExecutableAnonymous => "exec-anon",
        Heuristic::PrivateExecutablePeLike => "pe-like",
        Heuristic::WritableExecutable => "wx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_head() {
        assert_eq!(truncate("abcdef", 6), "abcdef");
        assert_eq!(truncate("abcdefgh", 6), "abc...");
    }

    #[test]
    fn truncate_tail_keeps_tail() {
        assert_eq!(truncate_tail("abcdef", 6), "abcdef");
        assert_eq!(truncate_tail("abcdefgh", 6), "...fgh");
    }

    #[test]
    fn human_size_scales_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn heur_short_tags() {
        assert_eq!(heur_short(Heuristic::ExecutablePrivate), "exec-private");
        assert_eq!(heur_short(Heuristic::WritableExecutable), "wx");
    }
}
```

`commands/mod.rs`의 모듈 선언 목록에 추가: `pub(crate) mod render;`

`process.rs`: `fn truncate` 정의와 truncate 관련 테스트를 삭제하고 `use super::render::truncate;`로 교체(다른 헬퍼는 그대로).

- [x] **Step 2: memory.rs 구현 + 테스트**

`crates/xmem-cli/src/commands/memory.rs` 전체 교체:

```rust
use xmem_core::{MemoryRegion, ProcessInfo, RegionClass, Result, XmemError};
use xmem_memory::{LiveProcess, RegionMap};

use crate::cli::{GlobalArgs, MemoryCmd};
use crate::commands::render::{heur_short, human_size, truncate, truncate_tail};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(cmd: &MemoryCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        MemoryCmd::Map(pid_arg) => {
            let live = LiveProcess::open(pid_arg.pid)?;
            let map = live.region_map()?;
            match resolve_mode(global.json) {
                OutputMode::Json => {
                    let value = serde_json::to_value(json_payload(&live.info, &map))
                        .map_err(|e| XmemError::JsonError {
                            reason: e.to_string(),
                        })?;
                    emit_json(&success_envelope(value))
                }
                OutputMode::Human => {
                    print!("{}", render_map(&map));
                    Ok(())
                }
            }
        }
        MemoryCmd::Scan(_) => super::unimplemented("memory scan"),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct MapSummary {
    total: usize,
    committed: usize,
    reserved: usize,
    free: usize,
    image: usize,
    mapped: usize,
    private: usize,
    executable: usize,
    heuristics: usize,
    committed_bytes: u64,
}

fn summarize(regions: &[MemoryRegion]) -> MapSummary {
    let mut s = MapSummary::default();
    for r in regions {
        s.total += 1;
        match r.classification {
            RegionClass::Image => {
                s.image += 1;
                s.committed += 1;
            }
            RegionClass::Mapped => {
                s.mapped += 1;
                s.committed += 1;
            }
            RegionClass::Private => {
                s.private += 1;
                s.committed += 1;
            }
            RegionClass::Free => s.free += 1,
            RegionClass::Reserved => s.reserved += 1,
            RegionClass::Unknown => {}
        }
        if r.classification != RegionClass::Free && r.classification != RegionClass::Reserved {
            s.committed_bytes = s.committed_bytes.saturating_add(r.size);
        }
        if r.executable {
            s.executable += 1;
        }
        s.heuristics += r.heuristics.len();
    }
    s
}

fn heur_list(region: &MemoryRegion) -> String {
    if region.heuristics.is_empty() {
        return "-".to_string();
    }
    region
        .heuristics
        .iter()
        .map(|h| heur_short(*h))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_map(map: &RegionMap) -> String {
    let mut out = String::new();
    out.push_str(
        "BASE               SIZE       STATE       TYPE        PROTECTION     CLASS      HEURISTICS     MAPPED FILE\n",
    );
    for r in &map.regions {
        let ty = match r.region_type {
            Some(t) => t.to_string(),
            None => "-".to_string(),
        };
        let mapped = match &r.mapped_file {
            Some(p) => truncate_tail(p, 48),
            None => "-".to_string(),
        };
        out.push_str(&format!(
            "0x{:016x} {:>10} {:11} {:11} {:14} {:10} {:14} {}\n",
            r.base,
            human_size(r.size),
            r.state.to_string(),
            ty,
            r.protection.to_string(),
            r.classification.to_string(),
            heur_list(r),
            mapped,
        ));
    }
    let s = summarize(&map.regions);
    out.push_str(&format!(
        "{} regions: committed {} ({}), reserved {}, free {}; image {}, mapped {}, private {}; executable {}; heuristics {}\n",
        s.total,
        s.committed,
        human_size(s.committed_bytes),
        s.reserved,
        s.free,
        s.image,
        s.mapped,
        s.private,
        s.executable,
        s.heuristics,
    ));
    if map.truncated {
        out.push_str("warning: region list truncated at MAX_REGIONS; results are incomplete\n");
    }
    out
}

fn json_payload(info: &ProcessInfo, map: &RegionMap) -> serde_json::Value {
    let s = summarize(&map.regions);
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "region_count": map.regions.len(),
        "truncated": map.truncated,
        "summary": {
            "total": s.total,
            "committed_count": s.committed,
            "reserved_count": s.reserved,
            "free_count": s.free,
            "image_count": s.image,
            "mapped_count": s.mapped,
            "private_count": s.private,
            "executable_count": s.executable,
            "heuristic_count": s.heuristics,
            "committed_bytes": s.committed_bytes,
        },
        "regions": map.regions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Heuristic, MemoryState, MemoryType, Protection};

    fn region(base: u64, state: MemoryState, ty: Option<MemoryType>, raw: u32) -> MemoryRegion {
        let (r, w, x) = match raw {
            0x40 => (true, true, true),
            0x20 => (true, false, true),
            _ => (false, false, false),
        };
        let p = Protection::new(raw, r, w, x);
        MemoryRegion {
            base,
            size: 0x1000,
            state,
            protection: p,
            allocation_protection: None,
            region_type: ty,
            readable: p.readable,
            writable: p.writable,
            executable: p.executable,
            classification: xmem_core::classify(state, ty),
            heuristics: xmem_core::heuristics(state, &p, ty),
            mapped_file: None,
        }
    }

    fn sample_map() -> RegionMap {
        RegionMap {
            regions: vec![
                region(0x1000, MemoryState::Commit, Some(MemoryType::Private), 0x40),
                region(0x2000, MemoryState::Commit, Some(MemoryType::Image), 0x20),
                region(0x3000, MemoryState::Reserve, None, 0),
                region(0x4000, MemoryState::Free, None, 0),
            ],
            truncated: false,
        }
    }

    #[test]
    fn summary_counts_by_class() {
        let s = summarize(&sample_map().regions);
        assert_eq!(s.total, 4);
        assert_eq!((s.private, s.image, s.reserved, s.free), (1, 1, 1, 1));
        assert_eq!(s.executable, 2);
        assert_eq!(s.heuristics, 2);
        assert_eq!(s.committed_bytes, 0x2000);
    }

    #[test]
    fn render_map_has_header_rows_and_summary() {
        let out = render_map(&sample_map());
        assert!(out.contains("BASE"));
        assert!(out.contains("0x0000000000001000"));
        assert!(out.contains("MEM_PRIVATE"));
        assert!(out.contains("exec-private,wx"));
        assert!(out.contains("4 regions:"));
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn render_map_warns_when_truncated() {
        let mut map = sample_map();
        map.truncated = true;
        assert!(render_map(&map).contains("truncated at MAX_REGIONS"));
    }

    #[test]
    fn json_payload_shape() {
        let info = ProcessInfo {
            pid: 42,
            ppid: None,
            name: "demo.exe".to_string(),
            image_path: None,
            arch: xmem_core::ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        };
        let value = json_payload(&info, &sample_map());
        assert_eq!(value["process"]["pid"], 42);
        assert_eq!(value["region_count"], 4);
        assert_eq!(value["truncated"], false);
        assert_eq!(value["summary"]["image_count"], 1);
        assert_eq!(value["regions"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn heur_list_renders_tags() {
        let r = region(0x1000, MemoryState::Commit, Some(MemoryType::Private), 0x40);
        assert_eq!(heur_list(&r), "exec-private,wx");
    }

    #[test]
    fn free_region_row_has_no_type_or_mapped_file() {
        let out = render_map(&sample_map());
        let line = out.lines().find(|l| l.contains("0x0000000000004000")).unwrap();
        assert!(line.contains("MEM_FREE"));
        assert!(line.contains(" free "));
    }
}
```

`crates/xmem-cli/Cargo.toml`에 `xmem-memory.workspace = true` 추가.

- [x] **Step 3: red → green 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — xmem_memory 미의존/미구현 상태에서 오류 확인 후, 위 코드 작성으로 해소.

Run: `cargo test -p xmem-cli`
Expected: PASS — 기존 15 + 신규 10 = 25 tests.

- [x] **Step 4: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add crates/xmem-cli
git commit -m "feat(cli): memory map 표시와 JSON payload"
```

---

### Task 5: 문서 + 최종 게이트 + Windows 실검증

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-03-memory-map.md` (체크박스)

- [x] **Step 1: README 갱신**

- Status 표에 `memory map` 행을 **Implemented**로 추가(M3): "VirtualQueryEx 기반 영역 열거, MEM_* state/type, PAGE_* 보호 속성, R/W/X, region class, heuristic tag, mapped file 경로(디바이스 경로), `--json`".
- Quick Start에 `xmem memory map --pid <PID>` 예시 추가.
- Limitations 갱신: `memory scan`은 M4 예정, `executable_anonymous`/`private_executable_pe_like` heuristic은 M5/M6 예정, mapped file 경로는 `\Device\...` 형식이며 드라이브 문자 변환은 미구현, region 목록은 `MAX_REGIONS` 상한으로 truncated 가능.
- Roadmap 표의 M3를 완료로 표시.

- [x] **Step 2: architecture.md 갱신**

- Status 표: M1 Done / M2 Done / **M3 Done** / M4~M12 Planned.
- crate 표에 `xmem-memory`를 M3 생성으로 추가(의존: xmem-core, xmem-windows).
- windows feature 목록에 `Win32_System_Memory`(M3) 추가.
- 모델 표의 `MemoryRegion.region_type`을 `Option<MemoryType>`로 갱신(Free/Reserve는 type 없음).

- [x] **Step 3: 전체 게이트**

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: fmt/check/clippy exit 0; tests — core 23 + windows 37 + memory 4 + cli 25 = 89 green.

- [x] **Step 4: Windows 실검증 (오류 경로 포함)**

```powershell
cargo run -q -p xmem-cli -- memory map --pid $PID          # 표 출력, rows > 0
cargo run -q -p xmem-cli -- --json memory map --pid $PID   # ok=true, region_count > 0
cargo run -q -p xmem-cli -- memory map --pid 1288          # lsass(비관리자): exit 1, access denied
cargo run -q -p xmem-cli -- memory map --pid 4294967294    # exit 1, process exited
cargo run -q -p xmem-cli -- memory map --pid $PID          # 3회 반복 모두 exit 0, 출력 동일 구조
```

확인 항목: Free 행의 TYPE `-`, 이미지 행 MAPPED FILE에 `\Device\...`, PROTECTION 열이 `R-X (0x20)` 형식, `--json`의 `truncated: false`.

- [x] **Step 5: 체크박스 갱신 + 커밋**

이 계획서의 모든 `- [ ]`를 `- [x]`로 바꾸고:

```bash
git add README.md docs/architecture.md docs/plans/milestone-03-memory-map.md
git commit -m "docs: M3 메모리 맵 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지:** VirtualQueryEx(M3), MEM_* state/type 표시, PAGE_* 보호 속성, 분류(Image/Mapped/Private/Free/Reserved/Unknown), heuristic 분리(Observed≠Interpretation), read-only, bounded walk, 구조화 오류, JSON+human, MemorySource 추상화 첫 구현 — 전부 Task 1~5에 매핑됨.
- **의도적 범위 제외:** `ExecutableAnonymous`/`PrivateExecutablePeLike` heuristic(M5/M6 — 모듈/PE 정보 필요), `--json` region 상세 필드 추가 없음(현행 모델 직렬화 그대로), 드라이브 문자 경로 변환 없음.
- **타입 일관성:** `region_type: Option<MemoryType>`(Task 1) → `region_from_raw`/`classify`/`heuristics`(Task 2) → `LiveProcess`(Task 3) → CLI 표시(Task 4) 모두 동일 시그니처 사용.
- **검증 완료 사항:** windows-0.62.2 소스에서 `VirtualQueryEx`/`GetMappedFileNameW`/`GetNativeSystemInfo`/`MEMORY_BASIC_INFORMATION`/상수 시그니처를 grep으로 확인함(계획 코드에 반영). `MemorySource::process()`는 `Result`가 아니라 `&ProcessInfo`를 반환(실제 trait 확인).
