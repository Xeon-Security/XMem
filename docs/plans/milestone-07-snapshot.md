# M7 — Snapshot create / diff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xmem snapshot create --pid <PID> --output <FILE>`로 프로세스 상태(메타데이터/region/module/thread/선택 영역 blake3 해시)를 버전드 바이너리 포맷 v1로 저장하고, `xmem snapshot diff <A> <B>`로 region/module/thread/보호 속성/내용 변화를 사람/JSON으로 보고한다.

**Architecture:** 새 `xmem-forensics` crate가 Snapshot 포맷(encode/decode/파일 쓰기: temp → validate → atomic rename), `SnapshotEnvelope`, `SnapshotSource`(MemorySource 구현), `collect`(라이브 소스 → envelope + bounded 해싱), `diff`(envelope 두 개 → 구조화된 변화)를 소유한다. CLI는 `LiveProcess`를 소스로 create를, 파일 두 개를 diff에 사용한다. Windows API는 여유 공간 조회(`GetDiskFreeSpaceExW`) 하나만 추가하며 `xmem-windows`에 둔다.

**Tech Stack:** Rust stable (edition 2024), blake3 1.8, chrono 0.4(`serde`/`clock` feature 추가), serde/serde_json, 기존 workspace crate.

**Spec:** `docs/architecture.md` §8 Snapshot 포맷 v1, §7 MemorySource, §13 Safety(Disk 보호), §14 Status

## Global Constraints

- Rust stable, edition 2024, `rust-version = "1.98"`, license MIT.
- workspace lints: `unsafe_code = "deny"`(예외 `xmem-windows`), clippy `unwrap_used`/`expect_used` warn(테스트는 `#![cfg_attr(test, allow(...))]`).
- 새 dependency는 **blake3 1.8**만 추가한다. `uuid`/`memmap2`는 도입하지 않는다(스냅샷 식별은 파일명+타임스탬프로 충분, MemoryImage는 M9+; architecture.md dependency 표를 이 결정에 맞게 갱신).
- chrono는 workspace에서 `features = ["std", "serde", "clock"]`로 확장한다(기존 cli 사용처는 영향 없음).
- 포맷 계약 고정: `magic "XMEM"(4) | format_version u16 LE | flags u16 LE(0) | payload_len u32 LE | UTF-8 JSON payload`. `SNAPSHOT_FORMAT_VERSION = 1`, `JSON_SCHEMA_VERSION = 1` 유지. 미지원 version/flags/길이 불일치는 `SnapshotError`.
- 파일 쓰기는 반드시 **temp → 재파싱 검증 → atomic rename**. 실패 시 temp 제거. 불완전 파일을 정상 Snapshot으로 남기지 않는다.
- 대형 파일 보호: 생성 전 `12 + payload_len` 예상 크기 + 16 MiB 여유를 요구하고, 부족하면 거부.
- 해싱은 bounded: committed+readable 영역만, executable/private 우선 정렬, `hash_budget_bytes`(기본 64 MiB) 상한, 1 MiB chunk 재사용 버퍼, 영역 수 상한 8192. 무제한 `Vec` 누적 금지.
- 일반 분석은 read-only 유지. Ctrl+C cooperative cancel 지원(취소 시 Err(Cancelled), 파일 미생성).
- 오류는 `XmemError`(SnapshotError/Io/Cancelled). 런타임 `unwrap()`/`expect()` 금지.
- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.

## Review Focus

1. **불완전 파일 금지** — 검증 실패/rename 실패 시 temp가 남지 않고 대상 파일이 손상되지 않아야 한다. Task 2의 `write_file_replaces_existing_and_cleans_temp`로 고정한다.
2. **payload 길이/버전 엄격성** — 짧은 파일, magic 불일치, format_version 불일치, payload_len 불일치(잘림/꼬리 바이트)는 모두 구조화 오류여야 한다. Task 2의 decode 테스트 4종으로 고정한다.
3. **해싱 예산 초과 금지** — `hash_budget_bytes`를 넘겨 읽지 않는다(디스크/시간 보호). Task 3의 `hash_budget_limits_hashing`으로 고정한다.
4. **읽기 실패 영역은 해시에서 제외하고 계속** — 개별 read 실패가 전체 snapshot을 실패시키지 않고 `read_failures`로 보고된다. Task 3의 `skips_unreadable_regions_and_counts_failures`로 고정한다.
5. **diff 정직성** — 변화가 없는 스냅샷 쌍은 빈 diff여야 하고, content 변화는 양쪽 해시가 모두 있을 때만 보고한다. Task 3의 `identical_snapshots_produce_empty_diff`로 고정한다.

---

### Task 1: xmem-windows — 여유 디스크 공간 조회

**Files:**
- Modify: `crates/xmem-windows/Cargo.toml` (feature 추가)
- Create: `crates/xmem-windows/src/disk.rs`
- Modify: `crates/xmem-windows/src/lib.rs`

**Interfaces:**
- Consumes: `crate::error::error_from_win32`.
- Produces: `xmem_windows::free_space_bytes(path: &str) -> Result<u64>` — 경로가 속한 볼륨의 가용 바이트. 실패는 `WindowsApi`/`AccessDenied` 구조화 오류.

- [ ] **Step 1: Write the failing test**

`crates/xmem-windows/src/disk.rs` 생성(테스트만):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_of_temp_dir_is_positive() {
        let dir = std::env::temp_dir().to_string_lossy().into_owned();
        let free = free_space_bytes(&dir).unwrap();
        assert!(free > 0);
    }

    #[test]
    fn free_space_of_invalid_path_fails_structured() {
        let err = free_space_bytes("").unwrap_err();
        assert!(matches!(
            err,
            XmemError::WindowsApi { .. } | XmemError::AccessDenied { .. }
        ));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — E0425 `cannot find function free_space_bytes`.

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-windows/Cargo.toml`의 windows features에 `"Win32_Storage_FileSystem"` 추가(Win32_Security 다음, 알파벳 순).

`crates/xmem-windows/src/disk.rs` 테스트 모듈 위에 추가:

```rust
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::core::HSTRING;
use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;

/// 경로가 속한 볼륨의 가용 바이트. `path`는 디렉터리 경로를 권장한다.
pub fn free_space_bytes(path: &str) -> Result<u64> {
    let dir = HSTRING::from(path);
    let mut free: u64 = 0;
    unsafe { GetDiskFreeSpaceExW(&dir, None, None, Some(&mut free)) }
        .map_err(|error| error_from_win32("GetDiskFreeSpaceExW", &error))?;
    Ok(free)
}
```

`crates/xmem-windows/src/lib.rs`: `pub mod disk;` 추가 + 재수출 `pub use disk::free_space_bytes;`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-windows`
Expected: PASS — 50 (48 + 2).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows
git commit -m "feat(windows): 디스크 여유 공간 조회"
```

---

### Task 2: xmem-forensics — 포맷 v1, envelope, SnapshotSource

**Files:**
- Create: `crates/xmem-forensics/Cargo.toml`
- Create: `crates/xmem-forensics/src/lib.rs`
- Create: `crates/xmem-forensics/src/envelope.rs`
- Create: `crates/xmem-forensics/src/format.rs`
- Create: `crates/xmem-forensics/src/source.rs`
- Modify: `Cargo.toml` (members, workspace.deps, chrono features)

**Interfaces:**
- Consumes: `xmem_core::{Finding, MemoryRegion, MemorySource, ModuleInfo, ProcessInfo, ReadOutcome, Result, ThreadInfo, XmemError, JSON_SCHEMA_VERSION, SNAPSHOT_FORMAT_VERSION, VERSION}`.
- Produces:
  - `SnapshotEnvelope { schema_version, xmem_version, format_version, timestamp, process, regions, modules, threads, content_hashes, findings, acquisition }`
  - `RegionHash { base, size, bytes_hashed, hash, partial }`
  - `AcquisitionMeta { source, pid, hashed_regions, hashed_bytes, hash_budget_bytes, read_failures, region_truncated }`
  - `format::{MAGIC, HEADER_LEN, encode(&SnapshotEnvelope) -> Result<Vec<u8>>, decode(&[u8]) -> Result<SnapshotEnvelope>, write_file(&Path, &[u8]) -> Result<()>, read_file(&Path) -> Result<SnapshotEnvelope>}`
  - `SnapshotSource { envelope }` + `impl MemorySource`(read는 `Unimplemented`).

- [ ] **Step 1: Write the failing tests**

`crates/xmem-forensics/src/envelope.rs` 생성(테스트 모듈 + 합성 envelope 빌더):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, ProcessArch, Protection, RegionClass};

    pub(crate) fn sample_envelope(pid: u32, region_base: u64, protection_raw: u32) -> SnapshotEnvelope {
        SnapshotEnvelope {
            schema_version: xmem_core::JSON_SCHEMA_VERSION,
            xmem_version: xmem_core::VERSION.to_string(),
            format_version: xmem_core::SNAPSHOT_FORMAT_VERSION,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            process: ProcessInfo {
                pid,
                ppid: Some(1),
                name: "sample.exe".to_string(),
                image_path: Some("C:\\sample.exe".to_string()),
                arch: ProcessArch::X64,
                session_id: Some(1),
                creation_time: Some(0),
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: Some(1),
                module_count: Some(1),
            },
            regions: vec![MemoryRegion {
                base: region_base,
                size: 0x1000,
                state: MemoryState::Commit,
                protection: Protection::new(protection_raw, true, true, protection_raw == 0x40),
                allocation_protection: None,
                region_type: Some(MemoryType::Private),
                readable: true,
                writable: true,
                executable: protection_raw == 0x40,
                classification: RegionClass::Private,
                heuristics: Vec::new(),
                mapped_file: None,
            }],
            modules: Vec::new(),
            threads: Vec::new(),
            content_hashes: Vec::new(),
            findings: Vec::new(),
            acquisition: AcquisitionMeta {
                source: "test".to_string(),
                pid,
                hashed_regions: 0,
                hashed_bytes: 0,
                hash_budget_bytes: 0,
                read_failures: 0,
                region_truncated: false,
            },
        }
    }

    #[test]
    fn envelope_roundtrips_through_json() {
        let envelope = sample_envelope(42, 0x1000, 0x04);
        let json = serde_json::to_vec(&envelope).unwrap();
        let back: SnapshotEnvelope = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.process.pid, 42);
        assert_eq!(back.regions[0].base, 0x1000);
        assert_eq!(back.format_version, xmem_core::SNAPSHOT_FORMAT_VERSION);
    }
}
```

`crates/xmem-forensics/src/format.rs` 생성(테스트만):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::sample_envelope;

    #[test]
    fn encode_decode_roundtrip() {
        let envelope = sample_envelope(7, 0x2000, 0x40);
        let bytes = encode(&envelope).unwrap();
        assert_eq!(&bytes[0..4], b"XMEM");
        let back = decode(&bytes).unwrap();
        assert_eq!(back.process.pid, 7);
        assert_eq!(back.regions[0].base, 0x2000);
    }

    #[test]
    fn decode_rejects_short_bad_magic_and_version() {
        assert!(matches!(decode(b"XM"), Err(XmemError::SnapshotError { .. })));
        let envelope = sample_envelope(1, 0x1000, 0x04);
        let mut bytes = encode(&envelope).unwrap();
        bytes[0] = b'Y';
        assert!(matches!(decode(&bytes), Err(XmemError::SnapshotError { .. })));
        let mut bytes = encode(&envelope).unwrap();
        bytes[4] = 99;
        assert!(matches!(decode(&bytes), Err(XmemError::SnapshotError { .. })));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let envelope = sample_envelope(1, 0x1000, 0x04);
        let bytes = encode(&envelope).unwrap();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            decode(truncated),
            Err(XmemError::SnapshotError { .. })
        ));
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(matches!(
            decode(&extended),
            Err(XmemError::SnapshotError { .. })
        ));
    }

    #[test]
    fn write_read_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("xmem-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("roundtrip.xmem");
        let envelope = sample_envelope(9, 0x3000, 0x20);
        let bytes = encode(&envelope).unwrap();
        write_file(&path, &bytes).unwrap();
        let back = read_file(&path).unwrap();
        assert_eq!(back.process.pid, 9);
        assert_eq!(back.regions[0].base, 0x3000);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_file_replaces_existing_and_cleans_temp() {
        let dir = std::env::temp_dir().join(format!("xmem-test-replace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("replace.xmem");
        let first = encode(&sample_envelope(1, 0x1000, 0x04)).unwrap();
        write_file(&path, &first).unwrap();
        let second = encode(&sample_envelope(2, 0x4000, 0x40)).unwrap();
        write_file(&path, &second).unwrap();
        let back = read_file(&path).unwrap();
        assert_eq!(back.process.pid, 2);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
```

`crates/xmem-forensics/src/source.rs` 생성(테스트만):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::sample_envelope;
    use xmem_core::MemorySource;

    #[test]
    fn snapshot_source_exposes_metadata_and_refuses_read() {
        let source = SnapshotSource::new(sample_envelope(11, 0x5000, 0x04));
        assert_eq!(source.process().pid, 11);
        assert_eq!(source.regions().unwrap().len(), 1);
        assert!(source.modules().unwrap().is_empty());
        assert!(source.threads().unwrap().is_empty());
        assert!(matches!(
            source.read(0x5000, &mut [0u8; 4]),
            Err(XmemError::Unimplemented { .. })
        ));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-forensics --tests`
Expected: FAIL — crate 미등록으로 매니페스트 오류, 등록 후 E0425/E0433 다수.

- [ ] **Step 3: Write minimal implementation**

루트 `Cargo.toml`: members에 `"crates/xmem-forensics"` 추가, `[workspace.dependencies]`에 추가하고 chrono features 확장:

```toml
xmem-forensics = { path = "crates/xmem-forensics" }
blake3 = "1.8"
chrono = { version = "0.4", default-features = false, features = ["std", "serde", "clock"] }
```

`crates/xmem-forensics/Cargo.toml`:

```toml
[package]
name = "xmem-forensics"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
blake3.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true

[dev-dependencies]
```

`crates/xmem-forensics/src/lib.rs`:

```rust
//! Snapshot 포맷/직렬화, SnapshotSource, Diff. (M7)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod envelope;
pub mod format;
pub mod source;

pub use envelope::{AcquisitionMeta, RegionHash, SnapshotEnvelope};
pub use format::{HEADER_LEN, MAGIC, decode, encode, read_file, write_file};
pub use source::SnapshotSource;
```

`crates/xmem-forensics/src/envelope.rs` 구현(테스트 모듈 위):

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use xmem_core::{Finding, MemoryRegion, ModuleInfo, ProcessInfo, ThreadInfo};

/// Snapshot payload(JSON). 포맷 버전과 스키마 버전을 모두 기록한다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEnvelope {
    pub schema_version: u32,
    pub xmem_version: String,
    pub format_version: u16,
    pub timestamp: DateTime<Utc>,
    pub process: ProcessInfo,
    pub regions: Vec<MemoryRegion>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub content_hashes: Vec<RegionHash>,
    pub findings: Vec<Finding>,
    pub acquisition: AcquisitionMeta,
}

/// 선택 수집 영역의 blake3 해시.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionHash {
    pub base: u64,
    pub size: u64,
    pub bytes_hashed: u64,
    pub hash: String,
    pub partial: bool,
}

/// 수집 메타데이터(출처/권한/실패 통계).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcquisitionMeta {
    pub source: String,
    pub pid: u32,
    pub hashed_regions: usize,
    pub hashed_bytes: u64,
    pub hash_budget_bytes: u64,
    pub read_failures: u64,
    pub region_truncated: bool,
}
```

`crates/xmem-forensics/src/format.rs` 구현:

```rust
use std::path::{Path, PathBuf};

use xmem_core::{Result, SNAPSHOT_FORMAT_VERSION, XmemError};

use crate::envelope::SnapshotEnvelope;

pub const MAGIC: [u8; 4] = *b"XMEM";
pub const HEADER_LEN: usize = 12;

fn snapshot_error(reason: impl Into<String>) -> XmemError {
    XmemError::SnapshotError {
        reason: reason.into(),
    }
}

/// envelope → `header + UTF-8 JSON payload` 바이트.
pub fn encode(envelope: &SnapshotEnvelope) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec_pretty(envelope).map_err(|error| {
        snapshot_error(format!("JSON 직렬화 실패: {error}"))
    })?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| snapshot_error(format!("payload가 너무 큼: {} bytes", payload.len())))?;
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&SNAPSHOT_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// 바이트 → envelope. magic/version/flags/길이를 엄격히 검사한다.
pub fn decode(bytes: &[u8]) -> Result<SnapshotEnvelope> {
    if bytes.len() < HEADER_LEN {
        return Err(snapshot_error(format!(
            "파일이 너무 짧음: {} bytes",
            bytes.len()
        )));
    }
    if bytes[0..4] != MAGIC {
        return Err(snapshot_error("magic 불일치 (XMEM 파일 아님)"));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(snapshot_error(format!(
            "지원하지 않는 format_version: {version} (현재 {SNAPSHOT_FORMAT_VERSION})"
        )));
    }
    let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
    if flags != 0 {
        return Err(snapshot_error(format!("알 수 없는 flags: {flags:#06x}")));
    }
    let payload_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    let end = HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| snapshot_error("payload 길이 오버플로"))?;
    if bytes.len() != end {
        return Err(snapshot_error(format!(
            "payload 길이 불일치: header {payload_len}, 실제 {}",
            bytes.len().saturating_sub(HEADER_LEN)
        )));
    }
    let envelope: SnapshotEnvelope = serde_json::from_slice(&bytes[HEADER_LEN..end])
        .map_err(|error| snapshot_error(format!("JSON 파싱 실패: {error}")))?;
    if envelope.format_version != version {
        return Err(snapshot_error(format!(
            "payload format_version 불일치: {} vs {version}",
            envelope.format_version
        )));
    }
    Ok(envelope)
}

/// temp 파일에 쓰고 재파싱으로 검증한 뒤 atomic rename. 실패 시 temp를 제거한다.
pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = temp_path(path);
    let write_result = std::fs::write(&temp, bytes).map_err(|error| XmemError::Io(error));
    if let Err(err) = write_result {
        std::fs::remove_file(&temp).ok();
        return Err(err);
    }
    let validate = (|| -> Result<()> {
        let read_back = std::fs::read(&temp).map_err(XmemError::Io)?;
        if read_back != bytes {
            return Err(snapshot_error("검증 실패: 기록 내용 불일치"));
        }
        decode(&read_back)?;
        Ok(())
    })();
    if let Err(err) = validate {
        std::fs::remove_file(&temp).ok();
        return Err(err);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    Ok(())
}

/// 파일 → envelope.
pub fn read_file(path: &Path) -> Result<SnapshotEnvelope> {
    let bytes = std::fs::read(path).map_err(XmemError::Io)?;
    decode(&bytes)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "snapshot.xmem".into());
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}
```

`crates/xmem-forensics/src/source.rs` 구현:

```rust
use xmem_core::{
    MemoryRegion, MemorySource, ModuleInfo, ProcessInfo, ReadOutcome, Result, ThreadInfo, XmemError,
};

use crate::envelope::SnapshotEnvelope;

/// 저장된 Snapshot을 MemorySource로 노출한다. 내용 read는 M9 MemoryImage에서 지원한다.
#[derive(Debug, Clone)]
pub struct SnapshotSource {
    envelope: SnapshotEnvelope,
}

impl SnapshotSource {
    pub fn new(envelope: SnapshotEnvelope) -> Self {
        Self { envelope }
    }

    pub fn envelope(&self) -> &SnapshotEnvelope {
        &self.envelope
    }
}

impl MemorySource for SnapshotSource {
    fn process(&self) -> &ProcessInfo {
        &self.envelope.process
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>> {
        Ok(self.envelope.regions.clone())
    }

    fn read(&self, _address: u64, _buf: &mut [u8]) -> Result<ReadOutcome> {
        Err(XmemError::Unimplemented {
            feature: "snapshot content read (M9 MemoryImage)",
        })
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(self.envelope.modules.clone())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.envelope.threads.clone())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-forensics`
Expected: PASS — 7 (envelope 1 + format 5 + source 1).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-forensics --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-forensics
git commit -m "feat(forensics): Snapshot 포맷 v1과 SnapshotSource"
```

---

### Task 3: xmem-forensics — collect(해싱)와 diff

**Files:**
- Create: `crates/xmem-forensics/src/collect.rs`
- Create: `crates/xmem-forensics/src/diff.rs`
- Modify: `crates/xmem-forensics/src/lib.rs`

**Interfaces:**
- Consumes: `xmem_core::{Heuristic, MemoryRegion, MemorySource, MemoryState, ModuleInfo, ProcessArch, RegionClass, Result, ThreadInfo, XmemError, VERSION, JSON_SCHEMA_VERSION, SNAPSHOT_FORMAT_VERSION}`, `crate::envelope::*`.
- Produces:
  - `CollectOptions { hash_budget_bytes: u64, hash_chunk_size: usize }` + `Default`(64 MiB / 1 MiB)
  - `collect<S: MemorySource>(source: &S, options: &CollectOptions, cancel: &AtomicBool) -> Result<SnapshotEnvelope>`
  - `diff(before: &SnapshotEnvelope, after: &SnapshotEnvelope) -> SnapshotDiff`
  - `SnapshotDiff { before, after, regions_added, regions_removed, regions_changed, content_changed, modules_added, modules_removed, modules_changed, threads_added, threads_removed, threads_changed, summary }`
  - `RegionChange/ModuleChange/ThreadChange { before, after, changes: Vec<String> }`, `ContentChange { base, before_hash, after_hash }`, `SnapshotRef { pid, name, timestamp }`, `DiffSummary { counts }`

- [ ] **Step 1: Write the failing tests**

`crates/xmem-forensics/src/collect.rs` 생성(테스트만):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicBool;
    use xmem_core::{
        MemoryRegion, MemorySource, MemoryState, MemoryType, ModuleInfo, ProcessArch, ProcessInfo,
        Protection, ReadOutcome, RegionClass, Result, ThreadInfo, XmemError,
    };

    struct MockSource {
        info: ProcessInfo,
        regions: Vec<MemoryRegion>,
        content: BTreeMap<u64, Vec<u8>>,
        fail: Vec<u64>,
    }

    impl MemorySource for MockSource {
        fn process(&self) -> &ProcessInfo {
            &self.info
        }
        fn regions(&self) -> Result<Vec<MemoryRegion>> {
            Ok(self.regions.clone())
        }
        fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
            if self.fail.contains(&address) {
                return Err(XmemError::AccessDenied {
                    context: format!("mock read at {address:#x}"),
                });
            }
            let Some((base, bytes)) = self
                .content
                .iter()
                .find(|(base, bytes)| address >= **base && address < **base + bytes.len() as u64)
            else {
                return Err(XmemError::InvalidAddress { address });
            };
            let start = (address - *base) as usize;
            let n = buf.len().min(bytes.len() - start);
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(ReadOutcome {
                bytes_read: n,
                partial: n < buf.len(),
            })
        }
        fn modules(&self) -> Result<Vec<ModuleInfo>> {
            Ok(Vec::new())
        }
        fn threads(&self) -> Result<Vec<ThreadInfo>> {
            Ok(Vec::new())
        }
    }

    fn mock_info() -> ProcessInfo {
        ProcessInfo {
            pid: 4242,
            ppid: None,
            name: "mock.exe".to_string(),
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

    fn mock_region(base: u64, size: u64, executable: bool, readable: bool) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            state: MemoryState::Commit,
            protection: Protection::new(
                if executable { 0x40 } else { 0x04 },
                readable,
                true,
                executable,
            ),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable,
            writable: true,
            executable,
            classification: RegionClass::Private,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    fn mock_source() -> MockSource {
        let mut content = BTreeMap::new();
        content.insert(0x1000, vec![0xAAu8; 0x2000]);
        content.insert(0x4000, vec![0xBBu8; 0x1000]);
        MockSource {
            info: mock_info(),
            regions: vec![mock_region(0x1000, 0x2000, true, true), mock_region(0x4000, 0x1000, false, true)],
            content,
            fail: Vec::new(),
        }
    }

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn collects_metadata_and_hashes_readable_regions() {
        let source = mock_source();
        let envelope = collect(&source, &CollectOptions::default(), &no_cancel()).unwrap();
        assert_eq!(envelope.process.pid, 4242);
        assert_eq!(envelope.regions.len(), 2);
        assert_eq!(envelope.content_hashes.len(), 2);
        assert_eq!(envelope.acquisition.hashed_bytes, 0x3000);
        assert_eq!(envelope.acquisition.read_failures, 0);
        assert_eq!(envelope.format_version, xmem_core::SNAPSHOT_FORMAT_VERSION);
        assert!(envelope.content_hashes.iter().all(|h| h.hash.len() == 64));
    }

    #[test]
    fn hash_budget_limits_hashing() {
        let source = mock_source();
        let options = CollectOptions {
            hash_budget_bytes: 4,
            hash_chunk_size: 4,
        };
        let envelope = collect(&source, &options, &no_cancel()).unwrap();
        assert_eq!(envelope.acquisition.hashed_bytes, 4);
        assert_eq!(envelope.content_hashes.len(), 1);
        assert!(envelope.content_hashes[0].partial);
    }

    #[test]
    fn skips_unreadable_regions_and_counts_failures() {
        let mut source = mock_source();
        source.fail.push(0x1000);
        source.regions[1].readable = false;
        let envelope = collect(&source, &CollectOptions::default(), &no_cancel()).unwrap();
        assert!(envelope.content_hashes.is_empty());
        assert_eq!(envelope.acquisition.read_failures, 1);
    }

    #[test]
    fn cancel_stops_collection() {
        let source = mock_source();
        let cancel = AtomicBool::new(true);
        let err = collect(&source, &CollectOptions::default(), &cancel).unwrap_err();
        assert!(matches!(err, XmemError::Cancelled { .. }));
    }
}
```

`crates/xmem-forensics/src/diff.rs` 생성(테스트만):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::sample_envelope;

    #[test]
    fn identical_snapshots_produce_empty_diff() {
        let envelope = sample_envelope(1, 0x1000, 0x04);
        let diff = diff(&envelope, &envelope);
        assert!(diff.regions_added.is_empty());
        assert!(diff.regions_removed.is_empty());
        assert!(diff.regions_changed.is_empty());
        assert!(diff.content_changed.is_empty());
        assert_eq!(diff.summary.regions_changed, 0);
    }

    #[test]
    fn detects_region_add_remove_and_protection_change() {
        let before = sample_envelope(1, 0x1000, 0x04);
        let mut after = sample_envelope(1, 0x1000, 0x40);
        after.regions.push(MemoryRegion {
            base: 0x9000,
            ..after.regions[0].clone()
        });
        let diff = diff(&before, &after);
        assert_eq!(diff.regions_added.len(), 1);
        assert_eq!(diff.regions_added[0].base, 0x9000);
        assert!(diff.regions_removed.is_empty());
        assert_eq!(diff.regions_changed.len(), 1);
        assert!(
            diff.regions_changed[0]
                .changes
                .iter()
                .any(|change| change.starts_with("protection:"))
        );
    }

    #[test]
    fn detects_region_removed() {
        let before = sample_envelope(1, 0x1000, 0x04);
        let after = sample_envelope(1, 0x2000, 0x04);
        let diff = diff(&before, &after);
        assert_eq!(diff.regions_removed.len(), 1);
        assert_eq!(diff.regions_removed[0].base, 0x1000);
        assert_eq!(diff.regions_added.len(), 1);
    }

    #[test]
    fn detects_content_hash_change() {
        let mut before = sample_envelope(1, 0x1000, 0x04);
        before.content_hashes.push(RegionHash {
            base: 0x1000,
            size: 0x1000,
            bytes_hashed: 0x1000,
            hash: "aa".repeat(32),
            partial: false,
        });
        let mut after = before.clone();
        after.content_hashes[0].hash = "bb".repeat(32);
        let diff = diff(&before, &after);
        assert_eq!(diff.content_changed.len(), 1);
        assert_eq!(diff.content_changed[0].base, 0x1000);
        let same = diff(&before, &before);
        assert!(same.content_changed.is_empty());
    }

    #[test]
    fn detects_module_and_thread_changes() {
        let mut before = sample_envelope(1, 0x1000, 0x04);
        before.modules.push(ModuleInfo {
            name: "old.dll".to_string(),
            base: 0x1000,
            size: 0x1000,
            path: None,
            arch: None,
        });
        before.threads.push(ThreadInfo {
            tid: 100,
            pid: 1,
            priority: Some(0),
            start_address: Some(0x1000),
            start_region_base: Some(0x1000),
            start_module: Some("old.dll".to_string()),
        });
        let mut after = sample_envelope(1, 0x1000, 0x04);
        after.modules.push(ModuleInfo {
            name: "new.dll".to_string(),
            base: 0x2000,
            size: 0x1000,
            path: None,
            arch: None,
        });
        after.threads.push(ThreadInfo {
            tid: 100,
            pid: 1,
            priority: Some(0),
            start_address: Some(0x9000),
            start_region_base: Some(0x9000),
            start_module: None,
        });
        let diff = diff(&before, &after);
        assert_eq!(diff.modules_added.len(), 1);
        assert_eq!(diff.modules_removed.len(), 1);
        assert_eq!(diff.threads_changed.len(), 1);
        assert!(
            diff.threads_changed[0]
                .changes
                .iter()
                .any(|change| change.starts_with("start_address:"))
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-forensics --tests`
Expected: FAIL — E0433/E0425 `collect`, `CollectOptions`, `diff`, `RegionHash` 등.

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-forensics/src/collect.rs` 구현(테스트 모듈 위):

```rust
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use xmem_core::{
    JSON_SCHEMA_VERSION, MemoryRegion, MemorySource, MemoryState, Result, SNAPSHOT_FORMAT_VERSION,
    VERSION, XmemError,
};

use crate::envelope::{AcquisitionMeta, RegionHash, SnapshotEnvelope};

pub const DEFAULT_HASH_BUDGET_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_HASH_CHUNK_SIZE: usize = 1024 * 1024;
pub const MAX_HASH_REGIONS: usize = 8192;

#[derive(Debug, Clone)]
pub struct CollectOptions {
    pub hash_budget_bytes: u64,
    pub hash_chunk_size: usize,
}

impl Default for CollectOptions {
    fn default() -> Self {
        Self {
            hash_budget_bytes: DEFAULT_HASH_BUDGET_BYTES,
            hash_chunk_size: DEFAULT_HASH_CHUNK_SIZE,
        }
    }
}

/// 소스에서 메타데이터를 모으고, 선택된 영역의 blake3 해시를 bounded하게 수집한다.
pub fn collect<S: MemorySource>(
    source: &S,
    options: &CollectOptions,
    cancel: &AtomicBool,
) -> Result<SnapshotEnvelope> {
    let regions = source.regions()?;
    let modules = source.modules()?;
    let threads = source.threads()?;
    let mut candidates: Vec<&MemoryRegion> = regions
        .iter()
        .filter(|region| region.state == MemoryState::Commit && region.readable)
        .collect();
    candidates.sort_by_key(|region| {
        (
            !region.executable,
            region.classification != xmem_core::RegionClass::Private,
            region.base,
        )
    });
    candidates.truncate(MAX_HASH_REGIONS);
    let mut content_hashes = Vec::new();
    let mut hashed_bytes: u64 = 0;
    let mut read_failures: u64 = 0;
    let mut chunk = vec![0u8; options.hash_chunk_size.max(1)];
    'regions: for region in candidates {
        if cancel.load(Ordering::Relaxed) {
            return Err(XmemError::Cancelled {
                reason: "snapshot collection interrupted".to_string(),
            });
        }
        if hashed_bytes >= options.hash_budget_bytes {
            break;
        }
        let mut hasher = blake3::Hasher::new();
        let mut region_hashed: u64 = 0;
        let mut partial = false;
        let mut offset: u64 = 0;
        while offset < region.size {
            if cancel.load(Ordering::Relaxed) {
                return Err(XmemError::Cancelled {
                    reason: "snapshot collection interrupted".to_string(),
                });
            }
            let remaining_budget = options.hash_budget_bytes.saturating_sub(hashed_bytes);
            if remaining_budget == 0 {
                partial = true;
                break;
            }
            let want = (region.size - offset)
                .min(chunk.len() as u64)
                .min(remaining_budget) as usize;
            match source.read(region.base + offset, &mut chunk[..want]) {
                Ok(outcome) if outcome.bytes_read > 0 => {
                    let n = outcome.bytes_read.min(want);
                    hasher.update(&chunk[..n]);
                    region_hashed += n as u64;
                    hashed_bytes += n as u64;
                    if outcome.partial || n < want {
                        partial = true;
                        break;
                    }
                    offset += n as u64;
                }
                Ok(_) => {
                    read_failures += 1;
                    partial = true;
                    break;
                }
                Err(XmemError::Cancelled { .. }) => {
                    return Err(XmemError::Cancelled {
                        reason: "snapshot collection interrupted".to_string(),
                    });
                }
                Err(_) => {
                    read_failures += 1;
                    partial = true;
                    break;
                }
            }
        }
        if region_hashed > 0 {
            content_hashes.push(RegionHash {
                base: region.base,
                size: region.size,
                bytes_hashed: region_hashed,
                hash: hasher.finalize().to_hex().to_string(),
                partial,
            });
        }
        if hashed_bytes >= options.hash_budget_bytes {
            if let Some(last) = content_hashes.last_mut() {
                last.partial = true;
            }
            break 'regions;
        }
    }
    Ok(SnapshotEnvelope {
        schema_version: JSON_SCHEMA_VERSION,
        xmem_version: VERSION.to_string(),
        format_version: SNAPSHOT_FORMAT_VERSION,
        timestamp: Utc::now(),
        process: source.process().clone(),
        regions,
        modules,
        threads,
        content_hashes,
        findings: Vec::new(),
        acquisition: AcquisitionMeta {
            source: "live_process".to_string(),
            pid: source.process().pid,
            hashed_regions: 0,
            hashed_bytes: 0,
            hash_budget_bytes: options.hash_budget_bytes,
            read_failures: 0,
            region_truncated: false,
        },
    })
}
```

주의: 위 `acquisition` 값은 실제 집계로 채운다(아래 수정본 사용):

```rust
        acquisition: AcquisitionMeta {
            source: "live_process".to_string(),
            pid: source.process().pid,
            hashed_regions: content_hashes.len(),
            hashed_bytes,
            hash_budget_bytes: options.hash_budget_bytes,
            read_failures,
            region_truncated: false,
        },
```

`crates/xmem-forensics/src/diff.rs` 구현(테스트 모듈 위):

```rust
use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use xmem_core::{MemoryRegion, ModuleInfo, ProcessArch, ThreadInfo};

use crate::envelope::SnapshotEnvelope;

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotRef {
    pub pid: u32,
    pub name: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionChange {
    pub before: MemoryRegion,
    pub after: MemoryRegion,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentChange {
    pub base: u64,
    pub before_hash: String,
    pub after_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleChange {
    pub before: ModuleInfo,
    pub after: ModuleInfo,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadChange {
    pub before: ThreadInfo,
    pub after: ThreadInfo,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiffSummary {
    pub regions_added: usize,
    pub regions_removed: usize,
    pub regions_changed: usize,
    pub content_changed: usize,
    pub modules_added: usize,
    pub modules_removed: usize,
    pub modules_changed: usize,
    pub threads_added: usize,
    pub threads_removed: usize,
    pub threads_changed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotDiff {
    pub before: SnapshotRef,
    pub after: SnapshotRef,
    pub regions_added: Vec<MemoryRegion>,
    pub regions_removed: Vec<MemoryRegion>,
    pub regions_changed: Vec<RegionChange>,
    pub content_changed: Vec<ContentChange>,
    pub modules_added: Vec<ModuleInfo>,
    pub modules_removed: Vec<ModuleInfo>,
    pub modules_changed: Vec<ModuleChange>,
    pub threads_added: Vec<ThreadInfo>,
    pub threads_removed: Vec<ThreadInfo>,
    pub threads_changed: Vec<ThreadChange>,
    pub summary: DiffSummary,
}

fn snapshot_ref(envelope: &SnapshotEnvelope) -> SnapshotRef {
    SnapshotRef {
        pid: envelope.process.pid,
        name: envelope.process.name.clone(),
        timestamp: envelope.timestamp,
    }
}

fn heuristics_text(heuristics: &[xmem_core::Heuristic]) -> String {
    if heuristics.is_empty() {
        "-".to_string()
    } else {
        heuristics
            .iter()
            .map(|heuristic| heuristic.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn opt_text(value: Option<&str>) -> String {
    value.unwrap_or("-").to_string()
}

fn arch_text(arch: Option<ProcessArch>) -> String {
    match arch {
        Some(ProcessArch::X64) => "x64".to_string(),
        Some(ProcessArch::X86) => "x86".to_string(),
        Some(ProcessArch::Arm64) => "arm64".to_string(),
        Some(ProcessArch::Unknown) => "unknown".to_string(),
        None => "-".to_string(),
    }
}

fn region_changes(before: &MemoryRegion, after: &MemoryRegion) -> Vec<String> {
    let mut changes = Vec::new();
    if before.size != after.size {
        changes.push(format!("size: {:#x} -> {:#x}", before.size, after.size));
    }
    if before.state != after.state {
        changes.push(format!("state: {} -> {}", before.state, after.state));
    }
    if before.protection.raw != after.protection.raw {
        changes.push(format!(
            "protection: {} -> {}",
            before.protection, after.protection
        ));
    }
    if before.classification != after.classification {
        changes.push(format!(
            "classification: {} -> {}",
            before.classification, after.classification
        ));
    }
    if before.heuristics != after.heuristics {
        changes.push(format!(
            "heuristics: {} -> {}",
            heuristics_text(&before.heuristics),
            heuristics_text(&after.heuristics)
        ));
    }
    if before.mapped_file != after.mapped_file {
        changes.push(format!(
            "mapped_file: {} -> {}",
            opt_text(before.mapped_file.as_deref()),
            opt_text(after.mapped_file.as_deref())
        ));
    }
    changes
}

fn module_changes(before: &ModuleInfo, after: &ModuleInfo) -> Vec<String> {
    let mut changes = Vec::new();
    if before.base != after.base {
        changes.push(format!("base: {:#x} -> {:#x}", before.base, after.base));
    }
    if before.size != after.size {
        changes.push(format!("size: {:#x} -> {:#x}", before.size, after.size));
    }
    if before.path != after.path {
        changes.push(format!(
            "path: {} -> {}",
            opt_text(before.path.as_deref()),
            opt_text(after.path.as_deref())
        ));
    }
    if before.arch != after.arch {
        changes.push(format!(
            "arch: {} -> {}",
            arch_text(before.arch),
            arch_text(after.arch)
        ));
    }
    changes
}

fn opt_hex(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_string(), |value| format!("{value:#x}"))
}

fn thread_changes(before: &ThreadInfo, after: &ThreadInfo) -> Vec<String> {
    let mut changes = Vec::new();
    if before.priority != after.priority {
        changes.push(format!(
            "priority: {} -> {}",
            before.priority.map_or_else(|| "-".to_string(), |value| value.to_string()),
            after.priority.map_or_else(|| "-".to_string(), |value| value.to_string())
        ));
    }
    if before.start_address != after.start_address {
        changes.push(format!(
            "start_address: {} -> {}",
            opt_hex(before.start_address),
            opt_hex(after.start_address)
        ));
    }
    if before.start_module != after.start_module {
        changes.push(format!(
            "start_module: {} -> {}",
            opt_text(before.start_module.as_deref()),
            opt_text(after.start_module.as_deref())
        ));
    }
    if before.start_region_base != after.start_region_base {
        changes.push(format!(
            "start_region: {} -> {}",
            opt_hex(before.start_region_base),
            opt_hex(after.start_region_base)
        ));
    }
    changes
}

/// 두 envelope의 구조적 차이를 계산한다. 변화가 없으면 빈 diff를 반환한다.
pub fn diff(before: &SnapshotEnvelope, after: &SnapshotEnvelope) -> SnapshotDiff {
    let before_regions: BTreeMap<u64, &MemoryRegion> =
        before.regions.iter().map(|region| (region.base, region)).collect();
    let after_regions: BTreeMap<u64, &MemoryRegion> =
        after.regions.iter().map(|region| (region.base, region)).collect();
    let mut regions_added = Vec::new();
    let mut regions_changed = Vec::new();
    for (base, region) in &after_regions {
        match before_regions.get(base) {
            None => regions_added.push((*region).clone()),
            Some(old) => {
                let changes = region_changes(old, region);
                if !changes.is_empty() {
                    regions_changed.push(RegionChange {
                        before: (*old).clone(),
                        after: (*region).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut regions_removed = Vec::new();
    for (base, region) in &before_regions {
        if !after_regions.contains_key(base) {
            regions_removed.push((*region).clone());
        }
    }
    let before_hashes: BTreeMap<u64, &crate::envelope::RegionHash> = before
        .content_hashes
        .iter()
        .map(|hash| (hash.base, hash))
        .collect();
    let mut content_changed = Vec::new();
    for hash in &after.content_hashes {
        if let Some(old) = before_hashes.get(&hash.base) {
            if old.hash != hash.hash {
                content_changed.push(ContentChange {
                    base: hash.base,
                    before_hash: old.hash.clone(),
                    after_hash: hash.hash.clone(),
                });
            }
        }
    }
    let before_modules: BTreeMap<&str, &ModuleInfo> = before
        .modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect();
    let after_modules: BTreeMap<&str, &ModuleInfo> = after
        .modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect();
    let mut modules_added = Vec::new();
    let mut modules_changed = Vec::new();
    for (name, module) in &after_modules {
        match before_modules.get(name) {
            None => modules_added.push((*module).clone()),
            Some(old) => {
                let changes = module_changes(old, module);
                if !changes.is_empty() {
                    modules_changed.push(ModuleChange {
                        before: (*old).clone(),
                        after: (*module).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut modules_removed = Vec::new();
    for (name, module) in &before_modules {
        if !after_modules.contains_key(name) {
            modules_removed.push((*module).clone());
        }
    }
    let before_threads: BTreeMap<u32, &ThreadInfo> =
        before.threads.iter().map(|thread| (thread.tid, thread)).collect();
    let after_threads: BTreeMap<u32, &ThreadInfo> =
        after.threads.iter().map(|thread| (thread.tid, thread)).collect();
    let mut threads_added = Vec::new();
    let mut threads_changed = Vec::new();
    for (tid, thread) in &after_threads {
        match before_threads.get(tid) {
            None => threads_added.push((*thread).clone()),
            Some(old) => {
                let changes = thread_changes(old, thread);
                if !changes.is_empty() {
                    threads_changed.push(ThreadChange {
                        before: (*old).clone(),
                        after: (*thread).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut threads_removed = Vec::new();
    for (tid, thread) in &before_threads {
        if !after_threads.contains_key(tid) {
            threads_removed.push((*thread).clone());
        }
    }
    let summary = DiffSummary {
        regions_added: regions_added.len(),
        regions_removed: regions_removed.len(),
        regions_changed: regions_changed.len(),
        content_changed: content_changed.len(),
        modules_added: modules_added.len(),
        modules_removed: modules_removed.len(),
        modules_changed: modules_changed.len(),
        threads_added: threads_added.len(),
        threads_removed: threads_removed.len(),
        threads_changed: threads_changed.len(),
    };
    SnapshotDiff {
        before: snapshot_ref(before),
        after: snapshot_ref(after),
        regions_added,
        regions_removed,
        regions_changed,
        content_changed,
        modules_added,
        modules_removed,
        modules_changed,
        threads_added,
        threads_removed,
        threads_changed,
        summary,
    }
}
```

`crates/xmem-forensics/src/lib.rs`에 `pub mod collect; pub mod diff;` + 재수출 추가:

```rust
pub use collect::{CollectOptions, DEFAULT_HASH_BUDGET_BYTES, collect};
pub use diff::{
    ContentChange, DiffSummary, ModuleChange, RegionChange, SnapshotDiff, SnapshotRef, ThreadChange,
    diff,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-forensics`
Expected: PASS — 16 (format 5 + envelope 1 + source 1 + collect 4 + diff 5).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-forensics --all-targets -- -D warnings
git add crates/xmem-forensics
git commit -m "feat(forensics): Snapshot 수집(해싱)과 diff"
```

---

### Task 4: CLI — snapshot create / diff

**Files:**
- Modify: `crates/xmem-cli/Cargo.toml`
- Modify: `crates/xmem-cli/src/commands/memory.rs` (cancel_flag 가시성)
- Rewrite: `crates/xmem-cli/src/commands/snapshot.rs`

**Interfaces:**
- Consumes: `xmem_forensics::{CollectOptions, SnapshotDiff, collect, diff, encode, read_file, write_file}`, `xmem_windows::free_space_bytes`, `xmem_memory::LiveProcess`, `commands::memory::cancel_flag`.
- Produces:
  - `create_snapshot_file(pid: u32, output: &Path, cancel: &AtomicBool) -> Result<CreateSummary>` (pub(crate), 테스트 가능)
  - `render_diff(&SnapshotDiff) -> String`, `diff_json_payload(&SnapshotDiff) -> serde_json::Value`
  - 사람 출력 요약 + `--json` envelope

- [ ] **Step 1: Write the failing tests**

`crates/xmem-cli/src/commands/snapshot.rs`에 테스트 모듈 추가(구현은 Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("xmem-cli-snapshot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_snapshot_of_self_writes_valid_file() {
        let dir = temp_dir();
        let path = dir.join("self.xmem");
        let cancel = AtomicBool::new(false);
        let summary =
            create_snapshot_file(xmem_windows::current_pid(), &path, &cancel).unwrap();
        assert!(summary.file_bytes > 0);
        assert!(summary.region_count > 0);
        assert_eq!(summary.hashed_regions > 0, summary.hashed_bytes > 0);
        let envelope = xmem_forensics::read_file(&path).unwrap();
        assert_eq!(envelope.process.pid, xmem_windows::current_pid());
        assert!(!envelope.regions.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_space_guard_rejects_huge_requests() {
        let dir = temp_dir();
        let err = ensure_disk_space(&dir, u64::MAX / 2).unwrap_err();
        assert!(matches!(err, XmemError::SnapshotError { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn render_diff_lists_changes_and_summary() {
        let before = sample_envelope_for_diff(0x1000, 0x04, 100);
        let mut after = sample_envelope_for_diff(0x1000, 0x40, 101);
        after.regions.push(xmem_core::MemoryRegion {
            base: 0x9000,
            ..after.regions[0].clone()
        });
        let diff = xmem_forensics::diff(&before, &after);
        let text = render_diff(&diff);
        assert!(text.contains("protection:"));
        assert!(text.contains("+"));
        assert!(text.contains("regions:"));
    }

    #[test]
    fn diff_json_payload_has_summary_and_sections() {
        let before = sample_envelope_for_diff(0x1000, 0x04, 100);
        let after = sample_envelope_for_diff(0x2000, 0x04, 100);
        let diff = xmem_forensics::diff(&before, &after);
        let payload = diff_json_payload(&diff);
        assert_eq!(payload["summary"]["regions_added"], 1);
        assert_eq!(payload["summary"]["regions_removed"], 1);
        assert!(payload["regions_added"].is_array());
    }

    fn sample_envelope_for_diff(
        region_base: u64,
        protection_raw: u32,
        tid: u32,
    ) -> xmem_forensics::SnapshotEnvelope {
        use xmem_core::{MemoryState, MemoryType, ProcessArch, ProcessInfo, Protection, RegionClass};
        xmem_forensics::SnapshotEnvelope {
            schema_version: xmem_core::JSON_SCHEMA_VERSION,
            xmem_version: xmem_core::VERSION.to_string(),
            format_version: xmem_core::SNAPSHOT_FORMAT_VERSION,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            process: ProcessInfo {
                pid: 555,
                ppid: None,
                name: "diff.exe".to_string(),
                image_path: None,
                arch: ProcessArch::X64,
                session_id: None,
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: None,
                module_count: None,
            },
            regions: vec![xmem_core::MemoryRegion {
                base: region_base,
                size: 0x1000,
                state: MemoryState::Commit,
                protection: Protection::new(protection_raw, true, true, protection_raw == 0x40),
                allocation_protection: None,
                region_type: Some(MemoryType::Private),
                readable: true,
                writable: true,
                executable: protection_raw == 0x40,
                classification: RegionClass::Private,
                heuristics: Vec::new(),
                mapped_file: None,
            }],
            modules: Vec::new(),
            threads: vec![xmem_core::ThreadInfo {
                tid,
                pid: 555,
                priority: None,
                start_address: None,
                start_region_base: None,
                start_module: None,
            }],
            content_hashes: Vec::new(),
            findings: Vec::new(),
            acquisition: xmem_forensics::AcquisitionMeta {
                source: "test".to_string(),
                pid: 555,
                hashed_regions: 0,
                hashed_bytes: 0,
                hash_budget_bytes: 0,
                read_failures: 0,
                region_truncated: false,
            },
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — E0425 `create_snapshot_file`, `ensure_disk_space`, `render_diff`, `diff_json_payload`, `xmem_forensics` 등.

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-cli/Cargo.toml` deps에 추가:

```toml
xmem-forensics.workspace = true
```

`crates/xmem-cli/src/commands/memory.rs`: `fn cancel_flag()` → `pub(crate) fn cancel_flag()`로 가시성 확장(주석 유지).

`crates/xmem-cli/src/commands/snapshot.rs` 전면 교체:

```rust
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use serde_json::{Value, json};
use xmem_core::{Result, XmemError};
use xmem_forensics::{
    CollectOptions, SnapshotDiff, collect, diff, encode, read_file, write_file,
};
use xmem_memory::LiveProcess;
use xmem_windows::free_space_bytes;

use crate::cli::{GlobalArgs, SnapshotCmd};
use crate::commands::memory::cancel_flag;
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

pub fn run(cmd: &SnapshotCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        SnapshotCmd::Create { pid, output } => run_create(pid.pid, output, global),
        SnapshotCmd::Diff { before, after } => run_diff(before, after, global),
    }
}

#[derive(Debug)]
pub(crate) struct CreateSummary {
    pub output: String,
    pub file_bytes: u64,
    pub region_count: usize,
    pub module_count: usize,
    pub thread_count: usize,
    pub hashed_regions: usize,
    pub hashed_bytes: u64,
    pub elapsed_ms: u64,
}

fn run_create(pid: u32, output: &str, global: &GlobalArgs) -> Result<()> {
    let started = Instant::now();
    let cancel = cancel_flag();
    let path = Path::new(output);
    let mut summary = create_snapshot_file(pid, path, &cancel)?;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "output": summary.output,
                "file_bytes": summary.file_bytes,
                "region_count": summary.region_count,
                "module_count": summary.module_count,
                "thread_count": summary.thread_count,
                "hashed_regions": summary.hashed_regions,
                "hashed_bytes": summary.hashed_bytes,
                "elapsed_ms": summary.elapsed_ms,
            })));
            Ok(())
        }
        OutputMode::Human => {
            println!(
                "snapshot written: {} ({})",
                summary.output,
                human_size(summary.file_bytes)
            );
            println!(
                "  regions {} / modules {} / threads {} / hashed {} regions ({}) in {} ms",
                summary.region_count,
                summary.module_count,
                summary.thread_count,
                summary.hashed_regions,
                human_size(summary.hashed_bytes),
                summary.elapsed_ms,
            );
            Ok(())
        }
    }
}

/// 라이브 프로세스를 수집해 검증된 Snapshot 파일로 저장한다.
pub(crate) fn create_snapshot_file(
    pid: u32,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<CreateSummary> {
    let live = LiveProcess::open(pid)?;
    let envelope = collect(&live, &CollectOptions::default(), cancel)?;
    let bytes = encode(&envelope)?;
    let dir = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    ensure_disk_space(&dir, bytes.len() as u64)?;
    write_file(output, &bytes)?;
    Ok(CreateSummary {
        output: output.display().to_string(),
        file_bytes: bytes.len() as u64,
        region_count: envelope.regions.len(),
        module_count: envelope.modules.len(),
        thread_count: envelope.threads.len(),
        hashed_regions: envelope.acquisition.hashed_regions,
        hashed_bytes: envelope.acquisition.hashed_bytes,
        elapsed_ms: 0,
    })
}

/// 예상 크기 + 여유 마진이 가용 공간을 넘으면 거부한다.
pub(crate) fn ensure_disk_space(dir: &Path, needed: u64) -> Result<()> {
    let free = free_space_bytes(&dir.to_string_lossy())?;
    if free < needed.saturating_add(DISK_MARGIN_BYTES) {
        return Err(XmemError::SnapshotError {
            reason: format!(
                "디스크 공간 부족: 필요 {needed} + 여유 {DISK_MARGIN_BYTES}, 가용 {free} ({})",
                dir.display()
            ),
        });
    }
    Ok(())
}

fn run_diff(before: &str, after: &str, global: &GlobalArgs) -> Result<()> {
    let before_envelope = read_file(Path::new(before))?;
    let after_envelope = read_file(Path::new(after))?;
    let result = diff(&before_envelope, &after_envelope);
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(diff_json_payload(&result)));
            Ok(())
        }
        OutputMode::Human => {
            print!("{}", render_diff(&result));
            Ok(())
        }
    }
}

pub(crate) fn render_diff(diff: &SnapshotDiff) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "before: pid {} {} @ {}\n",
        diff.before.pid, diff.before.name, diff.before.timestamp
    ));
    out.push_str(&format!(
        "after:  pid {} {} @ {}\n",
        diff.after.pid, diff.after.name, diff.after.timestamp
    ));
    let summary = &diff.summary;
    out.push_str(&format!(
        "regions: +{} -{} ~{} | content ~{} | modules: +{} -{} ~{} | threads: +{} -{} ~{}\n",
        summary.regions_added,
        summary.regions_removed,
        summary.regions_changed,
        summary.content_changed,
        summary.modules_added,
        summary.modules_removed,
        summary.modules_changed,
        summary.threads_added,
        summary.threads_removed,
        summary.threads_changed,
    ));
    for region in &diff.regions_added {
        out.push_str(&format!(
            "+ {:#018x} {:>10} {} {} {}\n",
            region.base,
            human_size(region.size),
            region.state,
            region.protection,
            region.classification
        ));
    }
    for region in &diff.regions_removed {
        out.push_str(&format!(
            "- {:#018x} {:>10} {} {} {}\n",
            region.base,
            human_size(region.size),
            region.state,
            region.protection,
            region.classification
        ));
    }
    for change in &diff.regions_changed {
        out.push_str(&format!("~ {:#018x} {}\n", change.after.base, change.changes.join(", ")));
    }
    for change in &diff.content_changed {
        out.push_str(&format!(
            "* {:#018x} content: {} -> {}\n",
            change.base,
            &change.before_hash[..16.min(change.before_hash.len())],
            &change.after_hash[..16.min(change.after_hash.len())],
        ));
    }
    for module in &diff.modules_added {
        out.push_str(&format!("+ module {} {:#x}\n", module.name, module.base));
    }
    for module in &diff.modules_removed {
        out.push_str(&format!("- module {} {:#x}\n", module.name, module.base));
    }
    for change in &diff.modules_changed {
        out.push_str(&format!(
            "~ module {} {}\n",
            change.after.name,
            change.changes.join(", ")
        ));
    }
    for thread in &diff.threads_added {
        out.push_str(&format!("+ thread tid {}\n", thread.tid));
    }
    for thread in &diff.threads_removed {
        out.push_str(&format!("- thread tid {}\n", thread.tid));
    }
    for change in &diff.threads_changed {
        out.push_str(&format!(
            "~ thread tid {} {}\n",
            change.after.tid,
            change.changes.join(", ")
        ));
    }
    out
}

pub(crate) fn diff_json_payload(diff: &SnapshotDiff) -> Value {
    serde_json::to_value(diff).unwrap_or(Value::Null)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-cli`
Expected: PASS — 41 + 4 = 45.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-cli
git commit -m "feat(cli): snapshot create/diff 명령"
```

---

### Task 5: 문서, 전체 게이트, Windows 실검증

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-07-snapshot.md` (체크박스)

**Interfaces:**
- Consumes: Task 1~4 결과.
- Produces: 문서 상태 갱신 + 검증 기록. 코드 변경 없음.

- [ ] **Step 1: README 갱신**

- Status 문구 "Milestone 7 (Snapshot) 완료".
- Status 표: `snapshot create`(포맷 v1, 메타데이터+선택 영역 blake3, 디스크 사전 검사, atomic rename, `--json`), `snapshot diff`(region/module/thread/protection/content 변화, `--json`) Implemented; Snapshot 행 Planned → Implemented; `memory map`/`memory scan`/`modules`/`threads` 유지.
- Quick Start에 `xmem snapshot create --pid <PID> --output before.xmem` / `xmem snapshot diff before.xmem after.xmem` 2줄.
- CLI Usage에 `snapshot` 옵션/동작 설명 1~2줄(해싱 예산 64 MiB 기본, 해시는 committed+readable 영역, executable/private 우선).
- Limitations: 해시는 64 MiB 예산(초과 시 `partial: true`), 해시 없는 영역은 content diff 불가, SnapshotSource read는 M9(MemoryImage) 예정, region/module/thread 매칭 키(base/name/tid) 명시.
- Roadmap M7 완료.

- [ ] **Step 2: architecture.md 갱신**

- dependency 표: `blake3` M7 도입됨; `chrono` features(std, serde, clock) 명기; `uuid` 행을 "미도입(스냅샷 식별은 파일명+타임스탬프로 충분, 필요 시 도입)"로 수정; `memmap2`는 M9+ 유지.
- §8 Snapshot 포맷에서 "M7 구현 예정" → "M7 구현됨" + 실제 필드(`content_hashes: Vec<RegionHash{base,size,bytes_hashed,hash,partial}>`, `acquisition: AcquisitionMeta{...}`) 반영 + 해싱 정책(committed+readable, executable/private 우선, 64 MiB 예산, 8192 영역 상한) 명기.
- crate 표 `xmem-forensics` 행 "M7 (생성됨)".
- Windows API 표 M7 행: `GetDiskFreeSpaceExW`(feature `Win32_Storage_FileSystem`) 구현됨.
- Status 표 M7 Done, M8~M12 Planned.

- [ ] **Step 3: 전체 게이트**

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0. 테스트 합계 = core 33 + windows 50 + pe 9 + memory 21 + forensics 16 + cli 45 = **174** (실측으로 확정).

- [ ] **Step 4: Windows 실검증 (스모크)**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$tmp = Join-Path $env:TEMP "xmem-m7"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
cargo run -q -p xmem-cli -- snapshot create --pid $PID --output "$tmp\a.xmem"
Start-Sleep -Milliseconds 300
cargo run -q -p xmem-cli -- snapshot create --pid $PID --output "$tmp\b.xmem"
cargo run -q -p xmem-cli -- snapshot diff "$tmp\a.xmem" "$tmp\b.xmem"
cargo run -q -p xmem-cli -- snapshot diff "$tmp\a.xmem" "$tmp\a.xmem"
cargo run -q -p xmem-cli -- --json snapshot diff "$tmp\a.xmem" "$tmp\b.xmem" | ConvertFrom-Json | Select-Object ok
cargo run -q -p xmem-cli -- snapshot diff "$tmp\missing.xmem" "$tmp\b.xmem"; Write-Output "exit=$LASTEXITCODE"
Get-ChildItem $tmp
Remove-Item -Recurse -Force $tmp
```

확인 항목:
1. create 2회 exit 0, 파일 생성(`a.xmem`, `b.xmem`), temp 파일 잔존 없음.
2. diff(a,b)에서 region/thread/content 변화가 최소 1건 이상 관찰(라이브 프로세스 특성), exit 0.
3. 자기 자신과의 diff는 모든 카운트 0, exit 0.
4. `--json` diff ok=true, `summary` 키 존재.
5. 없는 파일 diff → SnapshotError/Io 오류 메시지 + exit 1.
6. create/diff 반복 3회 모두 exit 0, panic 없음.

- [ ] **Step 5: 체크박스 갱신 + 커밋**

`docs/plans/milestone-07-snapshot.md`의 `- [ ]`를 전부 `- [x]`로 바꾸고:

```bash
git add README.md docs/architecture.md docs/plans/milestone-07-snapshot.md
git commit -m "docs: M7 Snapshot 상태 반영"
```

---

## Self-Review Notes

- **Spec coverage:** 포맷 v1(§8) → Task 2; MemorySource의 Snapshot 구현(§7) → Task 2; Snapshot Diff 항목(Region Added/Removed/Changed, Protection Changed, Module/Thread Added/Removed/Changed, Thread Start Address Changed, Content Changed) → Task 3; Detection/PE artifact diff 필드는 `findings`가 envelope에 포함되어 M8에서 채워지면 diff 확장 지점이 명확(현재 `findings`는 빈 배열로 저장); Disk 보호(§13) → Task 4 `ensure_disk_space`; atomic rename → Task 2 `write_file`.
- **미구현으로 명시:** Memory Content Changed는 해시가 수집된 영역에서만 보고된다(문서화). `findings` diff(Detection Appeared/Disappeared)는 M8에서 추가.
- **Type consistency:** `collect`는 `&AtomicBool` 취소 플래그를 받고 CLI가 `commands::memory::cancel_flag()`(OnceLock 핸들러)를 재사용한다. `SnapshotDiff`는 전부 `Serialize`만 derive(역직렬화는 불필요).
- **예상 테스트:** 174 (core 33, windows 50, pe 9, memory 21, forensics 16, cli 45). 실행 후 실제 값으로 확정한다.
