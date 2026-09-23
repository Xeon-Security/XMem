# M6 — PE Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xmem-pe` crate로 PE 구조를 파싱하고, 메모리의 private executable 영역에서 PE artifact를 탐지해 `private_executable_pe_like`/`executable_anonymous` heuristic을 활성화하며, `xmem modules --pid <PID> --pe`로 모듈 PE 요약을 출력한다.

**Architecture:** `xmem-pe`는 순수 파서 계층(goblin 기반)으로 Windows API에 의존하지 않는다. `xmem-memory`가 `ReadProcessMemory`(기존 `LiveProcess::read`)로 private executable 영역의 헤더 prefix(4 KiB)만 읽어 `classify_memory_pe`에 전달하고, 그 결과를 `MemoryRegion.heuristics`에 반영한다. CLI는 모듈별 헤더 prefix를 읽어 PE 요약을 사람/JSON 출력에 추가한다.

**Tech Stack:** Rust stable (edition 2024), goblin 0.10 (pe32/pe64, default-features off), serde, 기존 workspace crate (xmem-core/xmem-windows/xmem-memory/xmem-cli).

**Spec:** `docs/architecture.md` (Milestone 6: PE Analysis, Detection Rules XMEM-002, Data Model, Dependency Policy)

## Global Constraints

- Rust stable, edition 2024, `rust-version = "1.98"`, license MIT (`[workspace.package]` 그대로).
- workspace lints 그대로: `unsafe_code = "deny"` (예외는 `xmem-windows` crate의 `#![allow(unsafe_code)]`뿐), `clippy::unwrap_used`/`expect_used`는 warn (테스트는 `#![cfg_attr(test, allow(...))]`).
- 새 dependency는 **goblin 0.10만** 추가한다: `goblin = { version = "0.10", default-features = false, features = ["std", "pe32", "pe64"] }`. 그 외 dependency 추가 금지.
- 일반 분석 명령은 read-only 유지. PE 프로브는 기존 `ReadProcessMemory` 경로만 사용하고 어떤 쓰기 API도 도입하지 않는다.
- Bounded buffer 원칙: PE 프로브/모듈 헤더 읽기는 `PE_HEADER_PREFIX = 4096` 바이트 고정 버퍼 재사용. 무제한 `Vec` 증가 금지.
- JSON 계약: envelope `{ok, schema_version, data}` (`JSON_SCHEMA_VERSION = 1` 유지), error kind는 snake_case. 새 필드는 additive만 허용.
- 오류는 `XmemError`로 구조화한다. PE 파싱 실패는 `XmemError::InvalidPe { reason }`. 런타임 경로 `unwrap()`/`expect()` 금지.
- 한글 문서/주석/커밋 메시지 스타일 유지. 코드 주석은 필요한 곳에만.
- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.

## Review Focus

1. **헤더 prefix만으로 goblin 파싱이 실패하면 안 된다** — 임포트/익스포트 데이터 디렉터리의 file offset이 4 KiB 버퍼 밖이어도 `PE::parse`는 성공해야 한다(부분 실패 허용). 실패하면 유효한 in-memory PE가 `Malformed`로 오분류된다. Task 2의 `parse_header_prefix_of_own_exe` 테스트로 고정한다.
2. **프로브 읽기 실패는 heuristic을 오염시키지 않는다** — 읽기 실패/0바이트 partial read에서는 `executable_anonymous`를 단정하지 않고 아무 heuristic도 추가하지 않는다. Task 3에서 early-return으로 고정하고 `pe_probe_heuristics` 순수 함수 테스트로 매핑을 검증한다.
3. **PE 섹션 권한 비트 매핑** — `IMAGE_SCN_MEM_EXECUTE(0x2000_0000)`/`READ(0x4000_0000)`/`WRITE(0x8000_0000)` 디코딩이 정확해야 한다. Task 2의 `section_permissions_decode`로 고정한다.
4. **모듈별 PE 읽기/파싱 실패 degrade** — `modules --pe`에서 개별 모듈이 읽히지 않거나 파싱에 실패해도 명령 전체는 성공하고 해당 모듈만 `-`로 표시되어야 한다. Task 4의 `json_payload_merges_pe_when_present`/render 테스트로 고정한다.
5. **`MemoryPeClass` 매핑 정확성** — `RegionClass::Image → NormalLoadedModule`, `Mapped → MappedImage`, `Private → PrivatePeLike`, 그 외 → `Unknown`, 비 PE 바이트 → `None`. Task 2의 `classify_memory_pe_maps_region_classes`로 고정한다.

---

### Task 1: xmem-core — `ProcessArch::from_machine` + xmem-windows 위임

**Files:**
- Modify: `crates/xmem-core/src/model/process.rs`
- Modify: `crates/xmem-windows/src/process.rs`
- Test: `crates/xmem-core/src/model/process.rs` (기존 tests 모듈)

**Interfaces:**
- Consumes: 없음 (기존 `ProcessArch` enum).
- Produces: `ProcessArch::from_machine(machine: u16) -> ProcessArch` — PE/COFF `IMAGE_FILE_MACHINE_*` 값(0x8664/0x014c/0xaa64)을 매핑, 그 외 `Unknown`. xmem-pe와 xmem-windows가 공유한다.

- [ ] **Step 1: Write the failing test**

`crates/xmem-core/src/model/process.rs`의 기존 `#[cfg(test)] mod tests`에 추가:

```rust
    #[test]
    fn process_arch_from_machine_maps_known_values() {
        assert_eq!(ProcessArch::from_machine(0x8664), ProcessArch::X64);
        assert_eq!(ProcessArch::from_machine(0x014c), ProcessArch::X86);
        assert_eq!(ProcessArch::from_machine(0xaa64), ProcessArch::Arm64);
        assert_eq!(ProcessArch::from_machine(0x0000), ProcessArch::Unknown);
        assert_eq!(ProcessArch::from_machine(0x1234), ProcessArch::Unknown);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo check -p xmem-core --tests`
Expected: FAIL — E0599 `no function or associated item named 'from_machine'`.

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-core/src/model/process.rs`에서 `ProcessArch` enum 정의 아래에 추가:

```rust
impl ProcessArch {
    /// PE/COFF machine 값(IMAGE_FILE_MACHINE_*)을 ProcessArch로 변환한다.
    pub fn from_machine(machine: u16) -> Self {
        match machine {
            0x8664 => ProcessArch::X64,
            0x014c => ProcessArch::X86,
            0xaa64 => ProcessArch::Arm64,
            _ => ProcessArch::Unknown,
        }
    }
}
```

`crates/xmem-windows/src/process.rs`의 `map_image_file_machine` 본문을 위임으로 교체(기존 시그니처·테스트 유지, `IMAGE_FILE_MACHINE_*` import 제거):

```rust
pub fn map_image_file_machine(machine: u16) -> ProcessArch {
    ProcessArch::from_machine(machine)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-core -p xmem-windows`
Expected: PASS — core 33 (32 + 1), windows 48 (변경 없음).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-core -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-core crates/xmem-windows
git commit -m "refactor(core): ProcessArch machine 매핑을 코어로 승격"
```

---

### Task 2: xmem-pe crate — PE 파서와 메모리 PE 분류

**Files:**
- Create: `crates/xmem-pe/Cargo.toml`
- Create: `crates/xmem-pe/src/lib.rs`
- Create: `crates/xmem-pe/src/image.rs`
- Modify: `Cargo.toml` (workspace members + `[workspace.dependencies]`)

**Interfaces:**
- Consumes: `xmem_core::{ProcessArch, RegionClass, Result, XmemError}`.
- Produces:
  - `xmem_pe::PE_HEADER_PREFIX: usize = 4096`
  - `xmem_pe::MemoryPeClass { None, NormalLoadedModule, MappedImage, PrivatePeLike, Malformed, Unknown }` + `as_str()`
  - `xmem_pe::PeSection { name, virtual_address, virtual_size, raw_size, characteristics, readable, writable, executable }`
  - `xmem_pe::PeInfo { is_64, machine, arch, image_base, entry_point, size_of_image, subsystem, characteristics, sections, import_count, import_library_count, libraries, export_count, relocation_count, tls_callback_count }`
  - `xmem_pe::looks_like_pe(bytes: &[u8]) -> bool`
  - `xmem_pe::parse_pe(bytes: &[u8]) -> Result<PeInfo>`
  - `xmem_pe::classify_memory_pe(region_class: RegionClass, bytes: &[u8]) -> MemoryPeClass`

- [ ] **Step 1: Write the failing tests**

`crates/xmem-pe/src/image.rs` 생성(테스트만, 구현은 Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn own_exe_bytes() -> Vec<u8> {
        let path = std::env::current_exe().unwrap();
        std::fs::read(path).unwrap()
    }

    fn e_lfanew(bytes: &[u8]) -> usize {
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize
    }

    #[test]
    fn looks_like_pe_detects_own_exe() {
        let bytes = own_exe_bytes();
        assert!(looks_like_pe(&bytes));
        assert!(!looks_like_pe(b""));
        assert!(!looks_like_pe(b"hello world"));
        assert!(!looks_like_pe(b"MZ"));
    }

    #[test]
    fn parse_own_exe_full() {
        let bytes = own_exe_bytes();
        let pe = parse_pe(&bytes).unwrap();
        assert!(pe.image_base > 0);
        assert!(pe.entry_point >= pe.image_base);
        assert!(!pe.sections.is_empty());
        assert!(pe.sections.iter().any(|section| !section.name.is_empty()));
        assert!(pe.import_count > 0);
        assert!(!pe.libraries.is_empty());
        assert!(pe.is_64);
        assert_eq!(pe.arch, ProcessArch::X64);
    }

    #[test]
    fn parse_header_prefix_of_own_exe() {
        let bytes = own_exe_bytes();
        let prefix = &bytes[..PE_HEADER_PREFIX.min(bytes.len())];
        let pe = parse_pe(prefix).unwrap();
        assert!(pe.image_base > 0);
        assert!(!pe.sections.is_empty());
        assert!(pe.size_of_image > 0);
    }

    #[test]
    fn parse_rejects_non_pe_and_truncated_prefix() {
        assert!(matches!(
            parse_pe(b"not a pe at all"),
            Err(XmemError::InvalidPe { .. })
        ));
        let bytes = own_exe_bytes();
        let truncated = &bytes[..64];
        assert!(matches!(
            parse_pe(truncated),
            Err(XmemError::InvalidPe { .. })
        ));
    }

    #[test]
    fn section_permissions_decode() {
        let bytes = own_exe_bytes();
        let pe = parse_pe(&bytes).unwrap();
        assert!(pe.sections.iter().any(|section| section.executable));
        assert!(pe.sections.iter().any(|section| section.writable));
        assert!(
            pe.sections
                .iter()
                .all(|section| !section.executable || section.readable)
        );
    }

    #[test]
    fn classify_memory_pe_maps_region_classes() {
        let bytes = own_exe_bytes();
        let prefix = &bytes[..PE_HEADER_PREFIX.min(bytes.len())];
        assert_eq!(
            classify_memory_pe(RegionClass::Private, prefix),
            MemoryPeClass::PrivatePeLike
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Image, prefix),
            MemoryPeClass::NormalLoadedModule
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Mapped, prefix),
            MemoryPeClass::MappedImage
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Free, prefix),
            MemoryPeClass::Unknown
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Private, b"garbage"),
            MemoryPeClass::None
        );
    }

    #[test]
    fn classify_memory_pe_reports_malformed() {
        let bytes = own_exe_bytes();
        let sig_end = e_lfanew(&bytes) + 6;
        let broken = &bytes[..sig_end];
        assert!(looks_like_pe(broken));
        assert_eq!(
            classify_memory_pe(RegionClass::Private, broken),
            MemoryPeClass::Malformed
        );
    }

    #[test]
    fn memory_pe_class_names() {
        assert_eq!(MemoryPeClass::None.as_str(), "none");
        assert_eq!(
            MemoryPeClass::NormalLoadedModule.as_str(),
            "normal_loaded_module"
        );
        assert_eq!(MemoryPeClass::PrivatePeLike.as_str(), "private_pe_like");
        assert_eq!(MemoryPeClass::Malformed.as_str(), "malformed");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-pe --tests`
Expected: FAIL — crate가 없어 `error: package ID specification 'xmem-pe' did not match` (또는 workspace 등록 전이면 매니페스트 없음). workspace 등록(Step 3) 후에는 E0425/E0433로 red가 보인다.

- [ ] **Step 3: Write minimal implementation**

> **구현 후 수정 (실측):** goblin 0.10.7은 프리픽스 파싱에서 임포트 디렉터리가 파일 범위를 벗어나면
> `Malformed entity ... extends beyond file bounds` 하드 에러를 낸다(부분 실패 허용 안 함).
> 따라서 실제 구현은 **bounds-checked 수동 헤더 파서(`parse_header`) + 전체 파일일 때만 goblin 보강**
> 구조로 바뀌었다(`parse_pe`는 헤더 파싱 성공이면 Ok, 데이터 디렉터리만 손상돼도 헤더 정보 반환).
> 테스트 `header_parse_matches_full_parse`가 수동 파서 오프셋을 goblin 전체 파싱과 교차 검증한다.
> 최종 코드는 `crates/xmem-pe/src/image.rs` 참조.

`crates/xmem-pe/Cargo.toml`:

```toml
[package]
name = "xmem-pe"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
goblin.workspace = true
serde.workspace = true
```

루트 `Cargo.toml`의 `members`에 `"crates/xmem-pe"` 추가하고 `[workspace.dependencies]`에 추가:

```toml
xmem-pe = { path = "crates/xmem-pe" }
goblin = { version = "0.10", default-features = false, features = ["std", "pe32", "pe64"] }
```

`crates/xmem-pe/src/lib.rs`:

```rust
//! PE 이미지 분석: 헤더/섹션/임포트/익스포트/relocation/TLS와 메모리 PE artifact 분류.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod image;

pub use image::{
    MemoryPeClass, PE_HEADER_PREFIX, PeInfo, PeSection, classify_memory_pe, looks_like_pe, parse_pe,
};
```

`crates/xmem-pe/src/image.rs`의 테스트 모듈 위에 구현 추가:

```rust
use serde::Serialize;
use xmem_core::{ProcessArch, RegionClass, Result, XmemError};

/// 메모리 PE 프로브 시 읽는 헤더 prefix 크기.
pub const PE_HEADER_PREFIX: usize = 4096;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// 메모리에서 관찰한 PE artifact 분류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryPeClass {
    None,
    NormalLoadedModule,
    MappedImage,
    PrivatePeLike,
    Malformed,
    Unknown,
}

impl MemoryPeClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryPeClass::None => "none",
            MemoryPeClass::NormalLoadedModule => "normal_loaded_module",
            MemoryPeClass::MappedImage => "mapped_image",
            MemoryPeClass::PrivatePeLike => "private_pe_like",
            MemoryPeClass::Malformed => "malformed",
            MemoryPeClass::Unknown => "unknown",
        }
    }
}

/// PE 섹션 요약.
#[derive(Debug, Clone, Serialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// PE 이미지 요약. 헤더 prefix만 파싱한 경우 임포트/익스포트/relocation/TLS는 0/빈 값이다.
#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub is_64: bool,
    pub machine: u16,
    pub arch: ProcessArch,
    pub image_base: u64,
    pub entry_point: u64,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub characteristics: u16,
    pub sections: Vec<PeSection>,
    pub import_count: usize,
    pub import_library_count: usize,
    pub libraries: Vec<String>,
    pub export_count: usize,
    pub relocation_count: usize,
    pub tls_callback_count: usize,
}

/// DOS 'MZ' + e_lfanew 범위 + 'PE\0\0' 시그니처 검사.
pub fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let Some(sig_end) = e_lfanew.checked_add(4) else {
        return false;
    };
    sig_end <= bytes.len() && &bytes[e_lfanew..sig_end] == b"PE\0\0"
}

/// PE 바이트(전체 파일 또는 헤더 prefix)를 파싱한다.
pub fn parse_pe(bytes: &[u8]) -> Result<PeInfo> {
    if !looks_like_pe(bytes) {
        return Err(XmemError::InvalidPe {
            reason: "PE 시그니처 없음".to_string(),
        });
    }
    let pe = goblin::pe::PE::parse(bytes).map_err(|error| XmemError::InvalidPe {
        reason: format!("goblin: {error}"),
    })?;
    let sections: Vec<PeSection> = pe
        .sections
        .iter()
        .map(|section| {
            let name_bytes: Vec<u8> = section
                .name
                .iter()
                .take_while(|byte| **byte != 0)
                .copied()
                .collect();
            let characteristics = section.characteristics;
            PeSection {
                name: String::from_utf8_lossy(&name_bytes).into_owned(),
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_size: section.size_of_raw_data,
                characteristics,
                readable: characteristics & IMAGE_SCN_MEM_READ != 0,
                writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
                executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            }
        })
        .collect();
    let (size_of_image, subsystem) = pe
        .header
        .optional_header
        .as_ref()
        .map_or((0, 0), |header| {
            (
                header.windows_fields.size_of_image,
                header.windows_fields.subsystem,
            )
        });
    let relocation_count = pe.relocation_data.as_ref().map_or(0, |data| {
        data.blocks()
            .flatten()
            .map(|block| block.words().filter(|word| word.is_ok()).count())
            .sum()
    });
    let libraries: Vec<String> = pe.libraries.iter().map(|name| (*name).to_string()).collect();
    let tls_callback_count = pe.tls_data.as_ref().map_or(0, |tls| tls.callbacks.len());
    Ok(PeInfo {
        is_64: pe.is_64,
        machine: pe.header.coff_header.machine,
        arch: ProcessArch::from_machine(pe.header.coff_header.machine),
        image_base: pe.image_base,
        entry_point: pe.image_base.saturating_add(u64::from(pe.entry)),
        size_of_image,
        subsystem,
        characteristics: pe.header.coff_header.characteristics,
        sections,
        import_count: pe.imports.len(),
        import_library_count: libraries.len(),
        libraries,
        export_count: pe.exports.len(),
        relocation_count,
        tls_callback_count,
    })
}

/// 메모리 영역 분류와 PE 헤더 바이트로 PE artifact를 분류한다.
pub fn classify_memory_pe(region_class: RegionClass, bytes: &[u8]) -> MemoryPeClass {
    if !looks_like_pe(bytes) {
        return MemoryPeClass::None;
    }
    match parse_pe(bytes) {
        Ok(_) => match region_class {
            RegionClass::Image => MemoryPeClass::NormalLoadedModule,
            RegionClass::Mapped => MemoryPeClass::MappedImage,
            RegionClass::Private => MemoryPeClass::PrivatePeLike,
            _ => MemoryPeClass::Unknown,
        },
        Err(_) => MemoryPeClass::Malformed,
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-pe`
Expected: PASS — 8/8.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-pe --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-pe
git commit -m "feat(pe): PE 파서와 메모리 PE artifact 분류"
```

---

### Task 3: xmem-memory — private executable 영역 PE 프로브

**Files:**
- Modify: `crates/xmem-memory/Cargo.toml`
- Modify: `crates/xmem-memory/src/live.rs`

**Interfaces:**
- Consumes: `xmem_pe::{PE_HEADER_PREFIX, MemoryPeClass, classify_memory_pe}`, 기존 `LiveProcess::read`, `xmem_core::Heuristic`.
- Produces: `LiveProcess::region_map()`가 private executable 커밋 영역에 대해 `private_executable_pe_like`/`executable_anonymous` heuristic을 채운다. 새 public API 없음(내부 통합).

- [ ] **Step 1: Write the failing tests**

`crates/xmem-memory/src/live.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn pe_probe_heuristics_maps_classes() {
        assert_eq!(
            pe_probe_heuristics(MemoryPeClass::None),
            Some(Heuristic::ExecutableAnonymous)
        );
        assert_eq!(
            pe_probe_heuristics(MemoryPeClass::PrivatePeLike),
            Some(Heuristic::PrivateExecutablePeLike)
        );
        assert_eq!(
            pe_probe_heuristics(MemoryPeClass::Malformed),
            Some(Heuristic::PrivateExecutablePeLike)
        );
        assert_eq!(pe_probe_heuristics(MemoryPeClass::NormalLoadedModule), None);
        assert_eq!(pe_probe_heuristics(MemoryPeClass::MappedImage), None);
        assert_eq!(pe_probe_heuristics(MemoryPeClass::Unknown), None);
    }

    #[test]
    fn region_map_probes_private_executable_regions() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let map = live.region_map().unwrap();
        assert!(!map.regions.is_empty());
        for region in map
            .regions
            .iter()
            .filter(|region| region.classification == RegionClass::Private && region.executable)
        {
            assert!(region.heuristics.contains(&Heuristic::ExecutablePrivate));
        }
    }
```

테스트 모듈 import에 `use xmem_core::{Heuristic, RegionClass};`가 없으면 추가한다(이미 있으면 유지).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p xmem-memory`
Expected: FAIL — E0425 `cannot find function pe_probe_heuristics` (컴파일 오류).

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-memory/Cargo.toml` deps에 추가:

```toml
xmem-pe.workspace = true
```

`crates/xmem-memory/src/live.rs` 상단 import에 `xmem_core::{..., Heuristic, ...}`(없으면)와 `xmem_pe::{PE_HEADER_PREFIX, MemoryPeClass, classify_memory_pe};`를 추가하고, `region_map()`의 regions 빌드 루프를 다음과 같이 수정한다(기존 루프 구조 유지, private executable 커밋 영역만 프로브):

```rust
    pub fn region_map(&self) -> Result<RegionMap> {
        let walk = memory::walk_regions(
            &self.handle,
            memory::native_max_user_address(),
            memory::MAX_REGIONS,
        )?;
        let mut path_buf = vec![0u16; 32 * 1024];
        let mut header_buf = vec![0u8; PE_HEADER_PREFIX];
        let mut regions = Vec::with_capacity(walk.regions.len());
        for raw in &walk.regions {
            let mapped_file = if memory::is_file_backed(raw) {
                memory::mapped_file_name(&self.handle, raw.base, &mut path_buf)
            } else {
                None
            };
            let Some(mut region) = memory::region_from_raw(raw, mapped_file) else {
                tracing::warn!(base = format_args!("{:#x}", raw.base), "unknown memory state; skipping region");
                continue;
            };
            if region.classification == RegionClass::Private && region.executable {
                self.probe_region_pe(&mut region, &mut header_buf);
            }
            regions.push(region);
        }
        Ok(RegionMap {
            regions,
            truncated: walk.truncated,
        })
    }

    /// private executable 영역의 헤더 prefix를 읽어 PE artifact heuristic을 보강한다.
    /// 읽기 실패/부분 읽기에서는 heuristic을 추가하지 않는다(오단정 금지).
    fn probe_region_pe(&self, region: &mut MemoryRegion, buf: &mut [u8]) {
        if region.state != MemoryState::Commit {
            return;
        }
        let len = region.size.min(buf.len() as u64) as usize;
        if len < 64 {
            return;
        }
        let Ok(outcome) = self.read(region.base, &mut buf[..len]) else {
            return;
        };
        if outcome.bytes_read < 64 {
            return;
        }
        let Some(heuristic) = pe_probe_heuristics(classify_memory_pe(
            region.classification,
            &buf[..outcome.bytes_read],
        )) else {
            return;
        };
        if !region.heuristics.contains(&heuristic) {
            region.heuristics.push(heuristic);
        }
    }
```

파일 하단(private 헬퍼 구역, `contains`/`contains_module` 근처)에 추가:

```rust
fn pe_probe_heuristics(class: MemoryPeClass) -> Option<Heuristic> {
    match class {
        MemoryPeClass::None => Some(Heuristic::ExecutableAnonymous),
        MemoryPeClass::PrivatePeLike | MemoryPeClass::Malformed => {
            Some(Heuristic::PrivateExecutablePeLike)
        }
        MemoryPeClass::NormalLoadedModule
        | MemoryPeClass::MappedImage
        | MemoryPeClass::Unknown => None,
    }
}
```

import에 `MemoryState`가 없으면 추가한다(`xmem_core::{Heuristic, MemoryRegion, MemorySource, MemoryState, ModuleInfo, ...}`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-memory`
Expected: PASS — 19 + 2 = 21.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-memory --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-memory
git commit -m "feat(memory): private executable 영역 PE 프로브 heuristic"
```

---

### Task 4: CLI — `modules --pid <PID> --pe`

**Files:**
- Modify: `crates/xmem-cli/Cargo.toml`
- Modify: `crates/xmem-cli/src/cli.rs`
- Modify: `crates/xmem-cli/src/commands/modules.rs`

**Interfaces:**
- Consumes: `xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe}`, 기존 `LiveProcess::{open, modules, read}`, `commands::render::{arch_str?}` — arch_str은 process.rs의 private이므로 modules.rs에는 `xmem_core::ProcessArch` 표시용 로컬 헬퍼를 두거나 `render`로 옮긴다(아래 구현은 로컬 `pe_arch` 사용).
- Produces:
  - `cli::ModulesArgs { pid: PidArg, pe: bool }`, `Command::Modules(ModulesArgs)`.
  - `xmem modules --pid <PID> --pe` 사람 출력에 `MACHINE ENTRY SECTIONS` 컬럼, JSON 모듈 객체에 `"pe"` 필드(파싱 실패 시 `null`).

- [ ] **Step 1: Write the failing tests**

`crates/xmem-cli/src/cli.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn modules_pe_flag_parses() {
        let cli = parse(&["xmem", "modules", "--pid", "42", "--pe"]).unwrap();
        match cli.command {
            Command::Modules(args) => {
                assert_eq!(args.pid.pid, 42);
                assert!(args.pe);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn modules_pe_defaults_to_false() {
        let cli = parse(&["xmem", "modules", "--pid", "42"]).unwrap();
        match cli.command {
            Command::Modules(args) => assert!(!args.pe),
            other => panic!("unexpected command: {other:?}"),
        }
    }
```

`crates/xmem-cli/src/commands/modules.rs` 테스트 모듈에 추가(기존 `render_modules`/`json_payload` 테스트는 새 시그니처에 맞게 `None` 전달로 수정):

```rust
    fn sample_pe() -> xmem_pe::PeInfo {
        xmem_pe::PeInfo {
            is_64: true,
            machine: 0x8664,
            arch: xmem_core::ProcessArch::X64,
            image_base: 0x0001_4000_0000,
            entry_point: 0x0001_4000_1234,
            size_of_image: 0x0002_0000,
            subsystem: 3,
            characteristics: 0x0022,
            sections: Vec::new(),
            import_count: 0,
            import_library_count: 0,
            libraries: Vec::new(),
            export_count: 0,
            relocation_count: 0,
            tls_callback_count: 0,
        }
    }

    #[test]
    fn render_modules_with_pe_shows_machine_entry_sections() {
        let info = sample_info();
        let modules = vec![sample_module("target.exe", 0x0001_4000_0000, Some("C:\\t.exe"))];
        let pe = vec![Some(sample_pe())];
        let text = render_modules(&info, &modules, Some(&pe));
        assert!(text.contains("MACHINE"));
        assert!(text.contains("ENTRY"));
        assert!(text.contains("SECTIONS"));
        assert!(text.contains("x64"));
        assert!(text.contains("0x140001234"));
    }

    #[test]
    fn json_payload_merges_pe_when_present() {
        let info = sample_info();
        let modules = vec![
            sample_module("a.dll", 0x1000, None),
            sample_module("b.dll", 0x2000, None),
        ];
        let pe = vec![Some(sample_pe()), None];
        let payload = json_payload(&info, &modules, Some(&pe));
        assert_eq!(payload["module_count"], 2);
        assert_eq!(payload["modules"][0]["pe"]["arch"], "x64");
        assert!(payload["modules"][1]["pe"].is_null());
        let payload_without = json_payload(&info, &modules, None);
        assert!(payload_without["modules"][0].get("pe").is_none());
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — E0422/E0425 `ModulesArgs`, `pe`, `xmem_pe` 등.

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-cli/Cargo.toml` deps에 추가:

```toml
xmem-pe.workspace = true
```

`crates/xmem-cli/src/cli.rs`: `PidArg` 근처에 추가하고 `Command` enum의 `Modules(PidArg)`를 교체:

```rust
#[derive(Args, Debug)]
pub struct ModulesArgs {
    #[command(flatten)]
    pub pid: PidArg,
    /// 모듈 메모리 헤더에서 PE 정보(arch/entry/sections)를 파싱해 함께 표시한다
    #[arg(long)]
    pub pe: bool,
}
```

```rust
    /// 로드된 모듈 목록
    Modules(ModulesArgs),
```

`crates/xmem-cli/src/commands/mod.rs`의 dispatch는 기존 arm을 유지한다(타입만 바뀜): `Command::Modules(args) => modules::run(args, &cli.global),`.

`crates/xmem-cli/src/commands/modules.rs` 구현 교체:

```rust
use serde_json::{Value, json};
use xmem_core::{ModuleInfo, ProcessArch, ProcessInfo, Result};
use xmem_memory::LiveProcess;
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe};

use crate::cli::{GlobalArgs, ModulesArgs};
use crate::commands::render::{human_size, truncate, truncate_tail};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(args: &ModulesArgs, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid.pid)?;
    let modules = live.modules()?;
    let pe = if args.pe {
        Some(collect_pe(&live, &modules))
    } else {
        None
    };
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let payload = json_payload(&live.info, &modules, pe.as_deref());
            emit_json(&success_envelope(payload));
            Ok(())
        }
        OutputMode::Human => {
            print!("{}", render_modules(&live.info, &modules, pe.as_deref()));
            Ok(())
        }
    }
}

/// 모듈별 PE 헤더 prefix 파싱. 개별 실패는 None으로 degrade한다.
fn collect_pe(live: &LiveProcess, modules: &[ModuleInfo]) -> Vec<Option<PeInfo>> {
    let mut buf = vec![0u8; PE_HEADER_PREFIX];
    modules
        .iter()
        .map(|module| {
            let len = module.size.min(buf.len() as u64) as usize;
            if len < 64 {
                return None;
            }
            let outcome = live.read(module.base, &mut buf[..len]).ok()?;
            if outcome.bytes_read < 64 {
                return None;
            }
            parse_pe(&buf[..outcome.bytes_read]).ok()
        })
        .collect()
}

fn pe_arch(pe: &PeInfo) -> &'static str {
    match pe.arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
    }
}

fn render_modules(
    info: &ProcessInfo,
    modules: &[ModuleInfo],
    pe: Option<&[Option<PeInfo>]>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}) - {} modules\n",
        info.pid,
        info.name,
        modules.len()
    ));
    if let Some(pe_list) = pe {
        out.push_str("BASE SIZE MACHINE ENTRY SECTIONS NAME PATH\n");
        for (index, module) in modules.iter().enumerate() {
            let (machine, entry, sections) = match pe_list.get(index).and_then(Option::as_ref) {
                Some(pe) => (
                    pe_arch(pe),
                    format!("{:#x}", pe.entry_point),
                    pe.sections.len().to_string(),
                ),
                None => ("-".to_string(), "-".to_string(), "-".to_string()),
            };
            out.push_str(&format!(
                "0x{:016x} {:>10} {:8} {} {:>8} {:20} {}\n",
                module.base,
                human_size(module.size),
                machine,
                entry,
                sections,
                truncate(&module.name, 20),
                truncate_tail(module.path.as_deref().unwrap_or("-"), 60),
            ));
        }
    } else {
        out.push_str("BASE SIZE NAME PATH\n");
        for module in modules {
            out.push_str(&format!(
                "0x{:016x} {:>10} {:20} {}\n",
                module.base,
                human_size(module.size),
                truncate(&module.name, 20),
                truncate_tail(module.path.as_deref().unwrap_or("-"), 60),
            ));
        }
    }
    out
}

fn json_payload(
    info: &ProcessInfo,
    modules: &[ModuleInfo],
    pe: Option<&[Option<PeInfo>]>,
) -> Value {
    let items: Vec<Value> = modules
        .iter()
        .enumerate()
        .map(|(index, module)| {
            let mut value = serde_json::to_value(module).unwrap_or(Value::Null);
            if let Some(pe_list) = pe {
                value["pe"] = pe_list
                    .get(index)
                    .and_then(Option::as_ref)
                    .and_then(|pe| serde_json::to_value(pe).ok())
                    .unwrap_or(Value::Null);
            }
            value
        })
        .collect();
    json!({
        "process": {"pid": info.pid, "name": info.name},
        "module_count": modules.len(),
        "modules": items,
    })
}
```

(기존 테스트의 `render_modules(&info, &modules)` 호출은 `render_modules(&info, &modules, None)`, `json_payload(&info, &modules)`는 `json_payload(&info, &modules, None)`으로 수정한다.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-cli`
Expected: PASS — 37 + 4 = 41 (기존 2 테스트는 시그니처 수정, 신규 4: cli 2 + modules 2).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-cli
git commit -m "feat(cli): modules --pe 모듈 PE 요약"
```

---

### Task 5: 문서, 전체 게이트, Windows 실검증

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-06-pe-analysis.md` (체크박스)

**Interfaces:**
- Consumes: Task 1~4 결과.
- Produces: 문서 상태 갱신 + 검증 기록. 코드 변경 없음.

- [ ] **Step 1: README 갱신**

- Status 문구를 "Milestone 6 (PE Analysis) 완료"로 갱신.
- Status 표에 `modules --pe`(모듈 메모리 헤더 PE 요약: arch/entry/sections, `--json`) 행 추가, `memory map` 행에 `private_executable_pe_like`/`executable_anonymous` heuristic 활성화 명기.
- Quick Start에 `xmem modules --pid <PID> --pe` 한 줄 추가.
- Limitations 갱신: `--pe`는 메모리 헤더 prefix(4 KiB) 기준이라 imports/exports/relocations/TLS는 0으로 표시, 디스크 파일 전체 파싱은 후속; `--pe`는 VM_READ 필요(권한 없으면 `-` degrade); `Malformed` PE는 pe-like로 취급.
- Roadmap M6 = 완료.

- [ ] **Step 2: architecture.md 갱신**

- crate 표에 `xmem-pe` 행(책임: PE 파서/메모리 PE 분류, 생성열 "M6 (생성됨)", 의존: core + goblin).
- dependency 표에 `goblin 0.10` 행 추가(도입 M6, features `std,pe32,pe64`, 사용 이유: 검증된 PE 파서).
- Windows API 표 M6 행: "추가 API 없음 — 메모리 헤더는 기존 `ReadProcessMemory` 경로 재사용".
- Data Model에 `PeInfo`/`PeSection`/`MemoryPeClass`, heuristic `private_executable_pe_like`/`executable_anonymous` 활성화(M6) 명기.
- Status 표 M6 Done, M7~M12 Planned.

- [ ] **Step 3: 전체 게이트**

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0. 테스트 합계 = core 33 + windows 48 + xmem-pe 8 + memory 21 + cli 41 = **151**.

- [ ] **Step 4: Windows 실검증 (스모크)**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
cargo run -q -p xmem-cli -- modules --pid $PID --pe | Select-Object -First 8
cargo run -q -p xmem-cli -- --json modules --pid $PID --pe | ConvertFrom-Json | Select-Object ok, module_count
cargo run -q -p xmem-cli -- memory map --pid $PID | Select-String -Pattern "pe-like|exec-anon"
cargo run -q -p xmem-cli -- modules --pid 4294967294 --pe
cargo run -q -p xmem-cli -- modules --pid $PID --pe > $null; Write-Output "exit=$LASTEXITCODE"
```

확인 항목:
1. `modules --pe` 표에 `MACHINE ENTRY SECTIONS` 컬럼, x64/entry 주소/섹션 수 표시, exit 0.
2. `--json`에서 `ok=true`, 모듈 객체에 `pe` 키 존재.
3. `memory map`에서 pe-like/exec-anon heuristic이 하나 이상 관찰되면 기록(없으면 "관찰되지 않음"으로 기록 — vacuous 가능).
4. bogus PID는 `process ... has exited` exit 1.
5. 3회 반복 실행 시 모두 exit 0, panic/leak 없음.

- [ ] **Step 5: 체크박스 갱신 + 커밋**

`docs/plans/milestone-06-pe-analysis.md`의 `- [ ]`를 전부 `- [x]`로 바꾸고:

```bash
git add README.md docs/architecture.md docs/plans/milestone-06-pe-analysis.md
git commit -m "docs: M6 PE 분석 상태 반영"
```

---

## Self-Review Notes

- **Spec coverage:** PE 구조 파싱(DOS/COFF/Optional/Sections/Imports/Exports/Relocations/TLS/Characteristics) → Task 2 `parse_pe`; 메모리 PE-like 탐지 → Task 3; 분류(NormalLoadedModule/MappedImage/PrivatePeLike/Malformed/Unknown) → Task 2 `classify_memory_pe`; heuristic 활성화 → Task 3; 모듈 PE 메타데이터/섹션 → Task 4. 커널/쓰기 API 없음.
- **Type consistency:** `PeInfo.arch: ProcessArch`(core) — Task 1의 `from_machine`을 Task 2가 사용. `MemoryPeClass`는 Task 2 정의 → Task 3에서 매핑. `ModulesArgs`는 Task 4 내부 일관.
- **알려진 한계(문서화 대상):** 헤더 prefix 파싱은 imports/exports/relocations/TLS를 채우지 못한다(0). 디스크 전체 파일 파싱 배선은 M7(snapshot)/M9(minidump analyze)에서 사용 예정.
- **예상 테스트:** 151 (core 33, windows 48, pe 8, memory 21, cli 41). 계획서 예상치는 실행 후 실제 값으로 README/게이트에 기록한다.
