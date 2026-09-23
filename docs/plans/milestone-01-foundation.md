# XMem Milestone 1 — 기반 구조 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** XMem의 Cargo workspace와 Core 계층(모델·에러·Evidence·Guard), Win32 추상화(RAII Handle), CLI 골격, 로깅을 구현하고 `fmt/check/test/clippy` 게이트를 통과한다.

**Architecture:** `xmem-core`(의존성 없는 모델/에러/정책) ← `xmem-windows`(Win32 FFI, unsafe 격리) ← `xmem-cli`(clap, 출력/exit code). 변경 API는 도입하지 않으며 모든 명령은 read-only 기본이다.

**Tech Stack:** Rust 1.98.1 stable (edition 2024), windows 0.62.x, clap 4(derive), serde/serde_json, thiserror 2, tracing/tracing-subscriber, anyhow(CLI 전용).

**Spec:** `docs/architecture.md`

## Global Constraints

- 셸 PATH에 cargo가 없을 수 있으므로 모든 명령은 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스로 실행한다.
- workspace lint: `unsafe_code = "deny"`, `unsafe_op_in_unsafe_fn = "deny"`, `clippy::unwrap_used/expect_used = "warn"`. 테스트 모듈은 `#![cfg_attr(test, allow(...))]` 또는 파일 단위 allow.
- `unsafe`는 `xmem-windows`에만 존재하며 각 block에 SAFETY 주석 필수.
- 라이브러리 crate(`xmem-core`, `xmem-windows`)는 `anyhow` 금지. `XmemError`만 반환.
- 런타임 경로 `unwrap()/expect()` 금지. 불변조건이 타입으로 보장될 때만 예외.
- 변경(Win32 Write) API는 이 Milestone에서 도입 금지.
- 커밋 메시지: `feat:`, `test:`, `docs:`, `chore:` 접두사(conventional commits, 한국어 본문 허용).
- 검증 게이트: `cargo fmt --all -- --check` && `cargo check --workspace` && `cargo test --workspace` && `cargo clippy --workspace --all-targets -- -D warnings`.

## Review Focus

1. 알 수 없는 PID/접근 거부 PID를 열었을 때 CLI 전체가 죽지 않고 구조화된 에러로 끝나는가 (non-admin 셸 기준).
2. `OwnedHandle`이 모든 경로(early return 포함)에서 누수 없이 닫히는가.
3. 보호 프로세스 이름 변형(`lsass`, `LSASS.EXE`, 위장 경로)이 모두 거부되는가.
4. `--json` 출력이 stdout에만, 로그가 stderr에만 나가는가(stderr/stdout 분리).
5. clap 파싱 실패가 exit 2, 정책 거부가 exit 3으로 구분되는가.

---

### Task 1: Workspace 골격 + 3개 crate

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`
- Create: `crates/xmem-core/Cargo.toml`, `crates/xmem-core/src/lib.rs`
- Create: `crates/xmem-windows/Cargo.toml`, `crates/xmem-windows/src/lib.rs`
- Create: `crates/xmem-cli/Cargo.toml`, `crates/xmem-cli/src/main.rs`

**Interfaces:**
- Produces: workspace members `xmem-core`, `xmem-windows`, `xmem-cli`, bin 이름 `xmem`.

- [ ] **Step 1: workspace 파일 작성**

`Cargo.toml`:
```toml
[workspace]
resolver = "3"
members = ["crates/xmem-core", "crates/xmem-windows", "crates/xmem-cli"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.98"
license = "MIT"
authors = ["kalpha <dev@kalpha.kr>"]

[workspace.dependencies]
xmem-core = { path = "crates/xmem-core" }
xmem-windows = { path = "crates/xmem-windows" }
anyhow = "1"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[workspace.lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"

[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
```

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
targets = ["x86_64-pc-windows-msvc"]
```

`.gitignore`:
```gitignore
/target
**/*.rs.bk
*.xmem
*.dmp
*.pdb
```

- [ ] **Step 2: crate 골격 작성**

`crates/xmem-core/Cargo.toml`:
```toml
[package]
name = "xmem-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
serde.workspace = true
thiserror.workspace = true

[dev-dependencies]
serde_json.workspace = true
```

`crates/xmem-core/src/lib.rs`:
```rust
//! XMem core: shared models, errors, evidence, and policy.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
```
(모듈 선언은 이후 Task에서 추가)

`crates/xmem-windows/Cargo.toml`:
```toml
[package]
name = "xmem-windows"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
windows = { version = "0.62", features = ["Win32_Foundation", "Win32_System_Threading"] }
```

`crates/xmem-windows/src/lib.rs`:
```rust
//! XMem Win32 abstraction layer. All `unsafe` in XMem lives here.
#![allow(unsafe_code)] // SAFETY: Win32 FFI 경계는 이 crate로 격리한다.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
```

`crates/xmem-cli/Cargo.toml`:
```toml
[package]
name = "xmem-cli"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "xmem"
path = "src/main.rs"

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
anyhow.workspace = true
clap.workspace = true
serde_json.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

`crates/xmem-cli/src/main.rs` (Task 6에서 확장하는 임시 골격):
```rust
fn main() {
    println!("xmem {}", xmem_core::VERSION);
}
```
> Task 2에서 `xmem_core::VERSION`을 추가하기 전까지는 `env!("CARGO_PKG_VERSION")`로 대체한다.

- [ ] **Step 3: 빌드 확인**

Run: `cargo check --workspace`
Expected: `Finished` (windows crate 최초 컴파일로 수 분 소요 가능)

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml rust-toolchain.toml .gitignore crates
git commit -m "chore: cargo workspace 골격 (core/windows/cli)"
```

---

### Task 2: xmem-core — 버전 + 에러 모델

**Files:**
- Create: `crates/xmem-core/src/version.rs`, `crates/xmem-core/src/error.rs`
- Modify: `crates/xmem-core/src/lib.rs`

**Interfaces:**
- Produces: `xmem_core::VERSION: &str`, `SNAPSHOT_FORMAT_VERSION: u16`, `JSON_SCHEMA_VERSION: u32`, `XmemError` enum, `xmem_core::Result<T>`, 재수출 `XmemError`, `Result`.

- [ ] **Step 1: 실패하는 테스트 작성**

`crates/xmem-core/src/error.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_keeps_context() {
        let err = XmemError::AccessDenied { context: "OpenProcess(pid=4)".into() };
        assert!(err.to_string().contains("OpenProcess(pid=4)"));
    }

    #[test]
    fn windows_api_error_shows_api_and_code() {
        let err = XmemError::WindowsApi {
            api: "VirtualQueryEx",
            code: 998,
            message: "invalid access to memory location".into(),
        };
        let text = err.to_string();
        assert!(text.contains("VirtualQueryEx"));
        assert!(text.contains("998"));
    }

    #[test]
    fn partial_read_reports_sizes() {
        let err = XmemError::PartialRead { address: 0x1_0000, requested: 4096, read: 512 };
        let text = err.to_string();
        assert!(text.contains("0x"));
        assert!(text.contains("4096"));
        assert!(text.contains("512"));
    }

    #[test]
    fn io_error_converts() {
        let err: XmemError = std::io::Error::new(std::io::ErrorKind::NotFound, "no file").into();
        assert!(matches!(err, XmemError::Io(_)));
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo test -p xmem-core error`
Expected: 컴파일 실패(`error.rs` 없음)

- [ ] **Step 3: 구현**

`crates/xmem-core/src/version.rs`:
```rust
//! XMem version and format version constants.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;
pub const JSON_SCHEMA_VERSION: u32 = 1;
```

`crates/xmem-core/src/error.rs`:
```rust
//! Structured error model. 모든 실패는 원인과 context를 포함한다.
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum XmemError {
    #[error("access denied: {context}")]
    AccessDenied { context: String },

    #[error("process {pid} has exited")]
    ProcessExited { pid: u32 },

    #[error("invalid handle {handle:#x}")]
    InvalidHandle { handle: u64 },

    #[error("invalid address {address:#018x}")]
    InvalidAddress { address: u64 },

    #[error("partial read at {address:#018x}: requested {requested} bytes, read {read}")]
    PartialRead { address: u64, requested: usize, read: usize },

    #[error("unsupported architecture: {detail}")]
    UnsupportedArchitecture { detail: String },

    #[error("invalid PE: {reason}")]
    InvalidPe { reason: String },

    #[error("dump error: {reason}")]
    DumpError { reason: String },

    #[error("snapshot error: {reason}")]
    SnapshotError { reason: String },

    #[error("policy denied: {reason}")]
    PolicyDenied { reason: String },

    #[error("not implemented yet: {feature}")]
    Unimplemented { feature: &'static str },

    #[error("windows api {api} failed (code {code}): {message}")]
    WindowsApi { api: &'static str, code: u32, message: String },

    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, XmemError>;
```

`crates/xmem-core/src/lib.rs`:
```rust
//! XMem core: shared models, errors, evidence, and policy.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod version;

pub use error::{Result, XmemError};
pub use version::{JSON_SCHEMA_VERSION, SNAPSHOT_FORMAT_VERSION, VERSION};
```

- [ ] **Step 4: 통과 확인**

Run: `cargo test -p xmem-core`
Expected: `test result: ok. 4 passed`

- [ ] **Step 5: Commit**

```bash
git add crates/xmem-core
git commit -m "feat(core): 버전 상수와 구조화 에러 모델"
```

---

### Task 3: xmem-core — 모델 + Evidence

**Files:**
- Create: `crates/xmem-core/src/model/mod.rs`, `model/process.rs`, `model/memory.rs`, `model/module.rs`, `model/thread.rs`, `src/evidence.rs`
- Modify: `crates/xmem-core/src/lib.rs`

**Interfaces:**
- Produces: `ProcessArch`, `MemoryStats`, `ProcessInfo`, `MemoryState`, `MemoryType`, `Protection`, `RegionClass`, `Heuristic`, `MemoryRegion`, `ModuleInfo`, `ThreadInfo`, `Severity`, `Confidence`, `Evidence`, `Finding` (모두 serde roundtrip 가능).

- [ ] **Step 1: 실패하는 테스트 작성**

`crates/xmem-core/src/evidence.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_serde_roundtrip() {
        let finding = Finding {
            rule_id: "XMEM-001".into(),
            name: "Executable Private Memory".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region")
                .with_address(0x7ff6_0000)
                .observe("protection", "EXECUTE_READWRITE")
                .observe("type", "MEM_PRIVATE")],
            heuristic: "private + executable".into(),
            interpretation: "Potentially suspicious memory region".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
        assert!(json.contains("\"severity\":\"medium\""));
    }

    #[test]
    fn observed_values_are_deterministically_ordered() {
        let ev = Evidence::new("region").observe("b", "2").observe("a", "1");
        let keys: Vec<&String> = ev.observed.keys().collect();
        assert_eq!(keys, vec!["a", "b"]);
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo test -p xmem-core evidence`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`crates/xmem-core/src/evidence.rs`:
```rust
//! Evidence model: 관찰(Observed)→Evidence→Heuristic→Confidence→Interpretation.
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence { Low, Medium, High }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub address: Option<u64>,
    pub region_base: Option<u64>,
    pub observed: BTreeMap<String, String>,
}

impl Evidence {
    pub fn new(kind: impl Into<String>) -> Self {
        Self { kind: kind.into(), address: None, region_base: None, observed: BTreeMap::new() }
    }
    pub fn with_address(mut self, address: u64) -> Self { self.address = Some(address); self }
    pub fn with_region_base(mut self, base: u64) -> Self { self.region_base = Some(base); self }
    pub fn observe(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.observed.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub heuristic: String,
    pub interpretation: String,
}
```

`crates/xmem-core/src/model/process.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessArch { X64, X86, Arm64, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MemoryStats {
    pub working_set: u64,
    pub private_bytes: u64,
    pub commit: u64,
    pub virtual_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub image_path: Option<String>,
    pub arch: ProcessArch,
    pub session_id: Option<u32>,
    /// Windows FILETIME (100ns since 1601-01-01 UTC). M2에서 사람이 읽는 형태로 변환.
    pub creation_time: Option<u64>,
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub memory_stats: Option<MemoryStats>,
    pub thread_count: Option<u32>,
    pub module_count: Option<u32>,
}
```

`crates/xmem-core/src/model/memory.rs`:
```rust
use std::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState { Commit, Reserve, Free }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryType { Image, Mapped, Private }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protection {
    pub raw: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Protection {
    pub fn new(raw: u32, readable: bool, writable: bool, executable: bool) -> Self {
        Self { raw, readable, writable, executable }
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rwx = [
            if self.readable { 'R' } else { '-' },
            if self.writable { 'W' } else { '-' },
            if self.executable { 'X' } else { '-' },
        ];
        write!(f, "{}{}{} (0x{:02x})", rwx[0], rwx[1], rwx[2], self.raw & 0xff)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionClass { Image, Mapped, Private, Free, Reserved, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Heuristic {
    ExecutablePrivate,
    ExecutableAnonymous,
    PrivateExecutablePeLike,
    WritableExecutable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
    pub state: MemoryState,
    pub protection: Protection,
    pub allocation_protection: Option<Protection>,
    pub region_type: MemoryType,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub classification: RegionClass,
    pub heuristics: Vec<Heuristic>,
    pub mapped_file: Option<String>,
}
```

`crates/xmem-core/src/model/module.rs`:
```rust
use serde::{Deserialize, Serialize};
use super::process::ProcessArch;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: Option<String>,
    pub arch: Option<ProcessArch>,
}
```

`crates/xmem-core/src/model/thread.rs`:
```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub pid: u32,
    pub priority: Option<i32>,
    pub start_address: Option<u64>,
    /// start_address가 속한 메모리 영역의 base (M5 상관관계 분석).
    pub start_region_base: Option<u64>,
    /// start_address가 속한 로드된 모듈 이름 (있으면).
    pub start_module: Option<String>,
}
```

`crates/xmem-core/src/model/mod.rs`:
```rust
pub mod memory;
pub mod module;
pub mod process;
pub mod thread;

pub use memory::{Heuristic, MemoryRegion, MemoryState, MemoryType, Protection, RegionClass};
pub use module::ModuleInfo;
pub use process::{MemoryStats, ProcessArch, ProcessInfo};
pub use thread::ThreadInfo;
```

`lib.rs`에 추가:
```rust
pub mod evidence;
pub mod model;

pub use evidence::{Confidence, Evidence, Finding, Severity};
pub use model::*;
```

- [ ] **Step 4: 통과 확인**

Run: `cargo test -p xmem-core`
Expected: 모든 테스트 통과

- [ ] **Step 5: Commit**

```bash
git add crates/xmem-core
git commit -m "feat(core): 프로세스/메모리/모듈/스레드 모델과 Evidence 타입"
```

---

### Task 4: xmem-core — Guard 정책 + MemorySource trait

**Files:**
- Create: `crates/xmem-core/src/guard.rs`, `src/source.rs`
- Modify: `crates/xmem-core/src/lib.rs`

**Interfaces:**
- Produces: `ProcessIdentity<'a>`, `PolicyDecision`, `check_state_change(&ProcessIdentity) -> PolicyDecision`, `ReadOutcome`, `MemorySource`(object-safe).
- Consumes: `ProcessInfo`, `MemoryRegion`, `ModuleInfo`, `ThreadInfo`, `XmemError`.

- [ ] **Step 1: 실패하는 테스트 작성**

`guard.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ident<'a>(name: Option<&'a str>, path: Option<&'a str>) -> ProcessIdentity<'a> {
        ProcessIdentity { pid: 1234, name, image_path: path, session_id: Some(1) }
    }

    #[test]
    fn allows_normal_process() {
        assert_eq!(check_state_change(&ident(Some("notepad.exe"), None)), PolicyDecision::Allow);
    }

    #[test]
    fn denies_critical_by_exact_name() {
        assert!(matches!(check_state_change(&ident(Some("lsass.exe"), None)), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn denies_name_variants_case_and_suffix() {
        assert!(matches!(check_state_change(&ident(Some("LSASS.EXE"), None)), PolicyDecision::Deny { .. }));
        assert!(matches!(check_state_change(&ident(Some("lsass"), None)), PolicyDecision::Deny { .. }));
    }

    #[test]
    fn denies_masqueraded_name_with_user_path_and_records_facts() {
        let decision = check_state_change(&ident(Some("lsass.exe"), Some("C:\\Users\\kalpha\\lsass.exe")));
        match decision {
            PolicyDecision::Deny { reason, matched } => {
                assert_eq!(matched, "lsass.exe");
                assert!(reason.contains("C:\\Users\\kalpha\\lsass.exe"));
            }
            PolicyDecision::Allow => panic!("must deny"),
        }
    }

    #[test]
    fn allow_when_name_missing() {
        assert_eq!(check_state_change(&ident(None, None)), PolicyDecision::Allow);
    }
}
```

`source.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_object_safe(_: &dyn MemorySource) {}
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo test -p xmem-core guard`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`crates/xmem-core/src/guard.rs`:
```rust
//! 중요 프로세스 보호 정책. 변경 작업(state-changing)에만 적용한다. read-only 분석은 허용.
use crate::model::ProcessInfo;

pub const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "winlogon.exe", "dwm.exe", "explorer.exe",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String, matched: String },
}

impl PartialEq for PolicyDecision { /* derive 대신 수동 구현 금지: 위 derive로 충분하므로 제거 */
}

/// 이름은 확장자 유무/대소문자를 정규화해 비교한다.
pub fn normalize_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    lower.strip_suffix(".exe").map(str::to_string).unwrap_or(lower)
}

pub fn is_protected_name(name: &str) -> bool {
    let norm = normalize_name(name);
    PROTECTED_PROCESS_NAMES.iter().any(|p| normalize_name(p) == norm)
}

pub struct ProcessIdentity<'a> {
    pub pid: u32,
    pub name: Option<&'a str>,
    pub image_path: Option<&'a str>,
    pub session_id: Option<u32>,
}

impl ProcessIdentity<'_> {
    pub fn from_process_info(info: &ProcessInfo) -> ProcessIdentity<'_> {
        ProcessIdentity {
            pid: info.pid,
            name: Some(info.name.as_str()),
            image_path: info.image_path.as_deref(),
            session_id: info.session_id,
        }
    }
}

pub fn check_state_change(identity: &ProcessIdentity<'_>) -> PolicyDecision {
    let Some(name) = identity.name else { return PolicyDecision::Allow };
    if !is_protected_name(name) {
        return PolicyDecision::Allow;
    }
    let path = identity.image_path.unwrap_or("<unknown>");
    let reason = format!(
        "protected process (name={name}, pid={}, path={path}, session={:?}); state-changing operations are refused",
        identity.pid, identity.session_id
    );
    PolicyDecision::Deny { reason, matched: normalize_name(name) }
}
```
> 주의: `PolicyDecision`은 `#[derive(PartialEq, Eq)]`만 필요하므로 수동 impl 금지.

`crates/xmem-core/src/source.rs`:
```rust
//! 데이터 출처 추상화: LiveProcess / Snapshot / Minidump / MemoryImage.
use crate::error::Result;
use crate::model::{MemoryRegion, ModuleInfo, ProcessInfo, ThreadInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadOutcome {
    pub bytes_read: usize,
    pub partial: bool,
}

pub trait MemorySource {
    fn process(&self) -> &ProcessInfo;
    fn regions(&self) -> Result<Vec<MemoryRegion>>;
    fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome>;
    fn modules(&self) -> Result<Vec<ModuleInfo>>;
    fn threads(&self) -> Result<Vec<ThreadInfo>>;
}
```

`lib.rs`에 추가: `pub mod guard; pub mod source;`

- [ ] **Step 4: 통과 확인**

Run: `cargo test -p xmem-core`
Expected: 모든 테스트 통과

- [ ] **Step 5: Commit**

```bash
git add crates/xmem-core
git commit -m "feat(core): 보호 프로세스 guard 정책과 MemorySource 추상화"
```

---

### Task 5: xmem-windows — 에러 매핑 + RAII Handle + 프로세스 primitive

**Files:**
- Create: `crates/xmem-windows/src/error.rs`, `src/handle.rs`, `src/process.rs`
- Modify: `crates/xmem-windows/src/lib.rs`

**Interfaces:**
- Produces: `win32_code_from_hresult(i32) -> u32`, `map_win32(&'static str, u32, impl Into<String>) -> XmemError`, `last_win32_error(&'static str) -> XmemError`, `OwnedHandle::{new, raw, into_raw}`, `current_pid() -> u32`, `open_process(u32, PROCESS_ACCESS_RIGHTS) -> Result<OwnedHandle>`, `is_alive(&OwnedHandle) -> Result<bool>`.
- Consumes: `xmem_core::{XmemError, Result}`.

> `cargo test -p xmem-windows`는 링크가 필요하므로 MSVC Build Tools 설치 완료 후 실행한다. 설치 전에는 `cargo check -p xmem-windows`까지만.

- [ ] **Step 1: 실패하는 테스트 작성**

`error.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::XmemError;

    #[test]
    fn hresult_win32_facility_extracts_code() {
        assert_eq!(win32_code_from_hresult(0x8007_0005u32 as i32), 5);
        assert_eq!(win32_code_from_hresult(87), 87);
    }

    #[test]
    fn access_denied_maps_to_structured_error() {
        let err = map_win32("OpenProcess", 5, "Access is denied.");
        assert!(matches!(err, XmemError::AccessDenied { .. }));
        assert!(err.to_string().contains("Access is denied."));
    }

    #[test]
    fn other_codes_map_to_windows_api_error() {
        let err = map_win32("OpenProcess", 87, "The parameter is incorrect.");
        match err {
            XmemError::WindowsApi { api, code, .. } => {
                assert_eq!(api, "OpenProcess");
                assert_eq!(code, 87);
            }
            other => panic!("unexpected: {other}"),
        }
    }
}
```

`handle.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

    #[test]
    fn rejects_null_and_invalid_handles() {
        assert!(OwnedHandle::new(HANDLE::default()).is_none());
        assert!(OwnedHandle::new(INVALID_HANDLE_VALUE).is_none());
    }

    #[test]
    fn into_raw_forgets_close() {
        // 현재 프로세스 핸들은 CloseHandle 대상이 아니므로 into_raw로 소유권을 포기한다.
        let handle = probe_handle();
        let raw = handle.into_raw();
        assert!(!raw.is_invalid());
    }

    fn probe_handle() -> OwnedHandle {
        use windows::Win32::System::Threading::{GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        // GetCurrentProcess 의사 핸들은 닫으면 안 되지만, 여기서는 검증 목적으로만 감싸지 않는다.
        let _ = PROCESS_QUERY_LIMITED_INFORMATION;
        OwnedHandle::from_raw(GetCurrentProcess())
    }
}
```
> 위 테스트는 의사 핸들(PSEUDO handle)을 CloseHandle 하는 위험이 있으므로 구현 시 다음으로 대체한다: `open_process(current_pid())`로 실제 핸들을 얻어 `into_raw()`로 포기하지 말고 `raw()` 비교만 검증한다. 최종 테스트:
```rust
#[test]
fn open_and_drop_own_process_handle() {
    let handle = crate::process::open_process(
        crate::process::current_pid(),
        windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
    )
    .expect("own process must open");
    assert!(!handle.raw().is_invalid());
} // drop → CloseHandle
```

`process.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

    #[test]
    fn current_pid_is_nonzero() {
        assert_ne!(current_pid(), 0);
    }

    #[test]
    fn open_own_process_and_check_alive() {
        let handle = open_process(current_pid(), PROCESS_QUERY_LIMITED_INFORMATION)
            .expect("own process must open");
        assert!(is_alive(&handle).expect("GetExitCodeProcess must succeed"));
    }

    #[test]
    fn open_bogus_pid_fails_structured() {
        let err = match open_process(0xFFFF_FFFE, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(_) => panic!("bogus pid must fail"),
            Err(e) => e,
        };
        assert!(matches!(err, xmem_core::XmemError::WindowsApi { .. } | xmem_core::XmemError::AccessDenied { .. }));
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo check -p xmem-windows`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`error.rs`:
```rust
//! Win32 오류 → XmemError 매핑. 반환값 검증 없는 API 호출 금지.
use xmem_core::XmemError;

const FACILITY_WIN32_MASK: u32 = 0xFFFF_0000;
const HRESULT_WIN32_FACILITY: u32 = 0x8007_0000;

pub fn win32_code_from_hresult(hresult: i32) -> u32 {
    let raw = hresult as u32;
    if raw & FACILITY_WIN32_MASK == HRESULT_WIN32_FACILITY {
        raw & 0xFFFF
    } else {
        raw
    }
}

pub fn map_win32(api: &'static str, code: u32, message: impl Into<String>) -> XmemError {
    let message = message.into();
    if code == ERROR_ACCESS_DENIED {
        return XmemError::AccessDenied { context: format!("{api}: {message}") };
    }
    XmemError::WindowsApi { api, code, message }
}

pub const ERROR_ACCESS_DENIED: u32 = 5;

/// GetLastError 기반 오류 생성. 실패한 API 호출 직후에만 사용한다.
pub fn last_win32_error(api: &'static str) -> XmemError {
    let err = windows::core::Error::from_win32();
    let code = win32_code_from_hresult(err.code().0);
    map_win32(api, code, err.message())
}
```

`handle.rs`:
```rust
//! RAII HANDLE. Drop에서 정확히 한 번 CloseHandle 한다.
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// null / INVALID_HANDLE_VALUE는 소유하지 않는다(None).
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_invalid() || handle.0.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: self.0은 new()에서 null/invalid를 배제했고, 소유권은 이 구조체에만 있다.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

const _: () = {
    // INVALID_HANDLE_VALUE 상수가 실제로 동작하는지 컴파일 타임 참조.
    let _ = INVALID_HANDLE_VALUE;
};
```
> `INVALID_HANDLE_VALUE` 참조는 테스트/구현에 이미 사용되므로 위 const 블록은 넣지 않는다.

`process.rs`:
```rust
//! M1 최소 프로세스 primitive. 열거/메타데이터는 M2에서 확장한다.
use windows::Win32::Foundation::STILL_ACTIVE;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetExitCodeProcess, OpenProcess, PROCESS_ACCESS_RIGHTS,
};
use xmem_core::{Result, XmemError};

use crate::error::last_win32_error;
use crate::handle::OwnedHandle;

pub fn current_pid() -> u32 {
    // SAFETY: 인자 없는 쿼리 API이며 반환값은 항상 유효한 PID다.
    unsafe { GetCurrentProcessId() }
}

pub fn open_process(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<OwnedHandle> {
    // SAFETY: pid/access는 값 타입이며 반환 핸들의 수명은 OwnedHandle이 관리한다.
    let handle = unsafe { OpenProcess(access, false, pid) };
    match handle {
        Ok(h) => OwnedHandle::new(h).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(_) => Err(last_win32_error("OpenProcess")),
    }
}

pub fn is_alive(handle: &OwnedHandle) -> Result<bool> {
    let mut code = 0u32;
    // SAFETY: handle은 OwnedHandle이 보장하는 유효 핸들이고 code는 유효 포인터다.
    unsafe { GetExitCodeProcess(handle.raw(), &mut code) }
        .map_err(|_| last_win32_error("GetExitCodeProcess"))?;
    Ok(code == STILL_ACTIVE.0 as u32)
}
```
> 구현 시 `STILL_ACTIVE`의 실제 위치/타입(`windows::Win32::Foundation::STILL_ACTIVE`, `EXITCODE`=Wait가 아닌 `u32` 래퍼일 수 있음)을 rustdoc으로 확인하고 맞춘다. `OpenProcess`의 시그니처(`Result<HANDLE>`)도 확인한다.

`lib.rs`:
```rust
//! XMem Win32 abstraction layer. All `unsafe` in XMem lives here.
#![allow(unsafe_code)] // SAFETY: Win32 FFI 경계는 이 crate로 격리한다.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod handle;
pub mod process;

pub use error::{last_win32_error, map_win32, win32_code_from_hresult};
pub use handle::OwnedHandle;
```

- [ ] **Step 4: 통과 확인 (MSVC 설치 후)**

Run: `cargo test -p xmem-windows`
Expected: `test result: ok`

- [ ] **Step 5: Commit**

```bash
git add crates/xmem-windows
git commit -m "feat(windows): Win32 에러 매핑, RAII handle, 프로세스 primitive"
```

---

### Task 6: xmem-cli — 전체 명령 트리 + 로깅 + 스텁

**Files:**
- Create: `crates/xmem-cli/src/cli.rs`, `output.rs`, `commands/mod.rs` + `commands/{process,memory,modules,threads,snapshot,dump,detect,report,experiment}.rs`
- Modify: `crates/xmem-cli/src/main.rs`

**Interfaces:**
- Produces: `Cli`, `GlobalArgs`, `Command`(clap), `OutputMode`, `commands::dispatch(&Cli) -> Result<()>`, `exit_code_for(&XmemError) -> ExitCode`.
- Consumes: `xmem_core::{XmemError, VERSION, JSON_SCHEMA_VERSION}`.

- [ ] **Step 1: 실패하는 테스트 작성**

`cli.rs` 하단:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn parses_process_list() {
        let cli = parse(&["xmem", "process", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Process { .. }));
        assert!(!cli.global.json);
    }

    #[test]
    fn parses_memory_map_with_pid() {
        let cli = parse(&["xmem", "memory", "map", "--pid", "123"]).unwrap();
        let Command::Memory { cmd: MemoryCmd::Map(args) } = cli.command else {
            panic!("expected memory map");
        };
        assert_eq!(args.pid, 123);
    }

    #[test]
    fn missing_pid_is_usage_error() {
        let err = parse(&["xmem", "memory", "map"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn global_json_flag_is_global() {
        let cli = parse(&["xmem", "--json", "detect", "--pid", "1"]).unwrap();
        assert!(cli.global.json);
    }

    #[test]
    fn parses_snapshot_diff_paths() {
        let cli = parse(&["xmem", "snapshot", "diff", "a.xmem", "b.xmem"]).unwrap();
        let Command::Snapshot { cmd: SnapshotCmd::Diff { before, after } } = cli.command else {
            panic!("expected snapshot diff");
        };
        assert_eq!(before, "a.xmem");
        assert_eq!(after, "b.xmem");
    }

    #[test]
    fn parses_verbose_count() {
        let cli = parse(&["xmem", "-vv", "process", "list"]).unwrap();
        assert_eq!(cli.global.verbose, 2);
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo check -p xmem-cli`
Expected: 컴파일 실패

- [ ] **Step 3: 구현**

`cli.rs`:
```rust
//! CLI 트리. 전 명령의 인터페이스 계약을 여기서 확정한다.
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "xmem",
    version = env!("CARGO_PKG_VERSION"),
    about = "XMem - Windows Memory Attack & Forensics Research Platform"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// machine-readable JSON 출력
    #[arg(long, global = true)]
    pub json: bool,
    /// 진단 로그 레벨 상향 (반복 지정 가능)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// 경고/오류만 출력
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// 색상 비활성화
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Debug, Args)]
pub struct PidArg {
    /// 대상 프로세스 PID
    #[arg(long)]
    pub pid: u32,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 프로세스 열거/조회
    Process {
        #[command(subcommand)]
        cmd: ProcessCmd,
    },
    /// 가상 메모리 분석
    Memory {
        #[command(subcommand)]
        cmd: MemoryCmd,
    },
    /// 로드된 모듈 분석
    Modules(PidArg),
    /// 스레드 분석
    Threads(PidArg),
    /// 메모리 스냅샷
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCmd,
    },
    /// 미니덤프
    Dump {
        #[command(subcommand)]
        cmd: DumpCmd,
    },
    /// Detection Rule 실행
    Detect(PidArg),
    /// 분석 리포트 생성
    Report {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 경로
        #[arg(long)]
        output: String,
    },
    /// 연구 실험
    Experiment {
        #[command(subcommand)]
        cmd: ExperimentCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProcessCmd {
    /// 프로세스 목록
    List,
    /// 단일 프로세스 정보
    Info(PidArg),
}

#[derive(Debug, Subcommand)]
pub enum MemoryCmd {
    /// Virtual Memory Map
    Map(PidArg),
    /// 메모리 패턴/문자열 검색
    Scan(PidArg),
}

#[derive(Debug, Subcommand)]
pub enum SnapshotCmd {
    /// 스냅샷 생성
    Create {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 (.xmem)
        #[arg(long)]
        output: String,
    },
    /// 스냅샷 비교
    Diff { before: String, after: String },
}

#[derive(Debug, Subcommand)]
pub enum DumpCmd {
    /// 미니덤프 생성
    Create {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 (.dmp)
        #[arg(long)]
        output: String,
    },
    /// 미니덤프 분석
    Analyze { file: String },
}

#[derive(Debug, Subcommand)]
pub enum ExperimentCmd {
    /// 실험 목록
    List,
    /// 실험 실행
    Run { name: String },
}
```

`output.rs`:
```rust
//! 출력 모드와 사용자 오류 표시. 로그(tracing)와 분리한다.
use xmem_core::{JSON_SCHEMA_VERSION, XmemError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

pub fn resolve_mode(json: bool) -> OutputMode {
    if json { OutputMode::Json } else { OutputMode::Human }
}

pub fn error_envelope(err: &XmemError) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "ok": false,
        "error": {
            "kind": error_kind(err),
            "message": err.to_string(),
        }
    })
}

fn error_kind(err: &XmemError) -> &'static str {
    match err {
        XmemError::AccessDenied { .. } => "access_denied",
        XmemError::ProcessExited { .. } => "process_exited",
        XmemError::InvalidHandle { .. } => "invalid_handle",
        XmemError::InvalidAddress { .. } => "invalid_address",
        XmemError::PartialRead { .. } => "partial_read",
        XmemError::UnsupportedArchitecture { .. } => "unsupported_architecture",
        XmemError::InvalidPe { .. } => "invalid_pe",
        XmemError::DumpError { .. } => "dump_error",
        XmemError::SnapshotError { .. } => "snapshot_error",
        XmemError::PolicyDenied { .. } => "policy_denied",
        XmemError::Unimplemented { .. } => "unimplemented",
        XmemError::WindowsApi { .. } => "windows_api",
        XmemError::Io(_) => "io",
    }
}
```

`commands/mod.rs`:
```rust
pub mod detect;
pub mod dump;
pub mod experiment;
pub mod memory;
pub mod modules;
pub mod process;
pub mod report;
pub mod snapshot;
pub mod threads;

use xmem_core::{Result, XmemError};

use crate::cli::{Cli, Command};

pub fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Process { cmd } => process::run(cmd, &cli.global),
        Command::Memory { cmd } => memory::run(cmd, &cli.global),
        Command::Modules(args) => modules::run(args, &cli.global),
        Command::Threads(args) => threads::run(args, &cli.global),
        Command::Snapshot { cmd } => snapshot::run(cmd, &cli.global),
        Command::Dump { cmd } => dump::run(cmd, &cli.global),
        Command::Detect(args) => detect::run(args, &cli.global),
        Command::Report { pid, output } => report::run(pid, output, &cli.global),
        Command::Experiment { cmd } => experiment::run(cmd, &cli.global),
    }
}

pub(crate) fn unimplemented(feature: &'static str) -> Result<()> {
    Err(XmemError::Unimplemented { feature })
}
```

각 스텁 파일 예 (`commands/process.rs`):
```rust
use xmem_core::Result;
use crate::cli::{GlobalArgs, ProcessCmd};

pub fn run(cmd: &ProcessCmd, _global: &GlobalArgs) -> Result<()> {
    let feature = match cmd {
        ProcessCmd::List => "process list",
        ProcessCmd::Info(_) => "process info",
    };
    super::unimplemented(feature)
}
```
나머지 명령도 동일 패턴(`memory map|scan`, `modules`, `threads`, `snapshot create|diff`, `dump create|analyze`, `detect`, `report`, `experiment list|run`).

`main.rs`:
```rust
mod cli;
mod commands;
mod output;

use clap::Parser;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;
use xmem_core::XmemError;

use cli::Cli;
use output::{error_envelope, resolve_mode, OutputMode};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli);

    match commands::dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report_error(&err, resolve_mode(cli.global.json));
            exit_code_for(&err)
        }
    }
}

fn init_tracing(cli: &Cli) {
    let default_level = if cli.global.quiet {
        "error"
    } else {
        match cli.global.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn report_error(err: &XmemError, mode: OutputMode) {
    match mode {
        OutputMode::Json => {
            println!("{}", error_envelope(err));
        }
        OutputMode::Human => {
            eprintln!("error: {err}");
            let mut source = std::error::Error::source(err);
            while let Some(inner) = source {
                eprintln!("  caused by: {inner}");
                source = inner.source();
            }
        }
    }
}

fn exit_code_for(err: &XmemError) -> ExitCode {
    match err {
        XmemError::PolicyDenied { .. } => ExitCode::from(3),
        _ => ExitCode::from(1),
    }
}
```
> `init_tracing`의 `EnvFilter::try_from_default_env` 실패는 `unwrap_or_else`로 처리(런타임 unwrap 금지). `try_init` 실패는 무시(테스트에서 중복 init 방지).

- [ ] **Step 4: 통과 확인**

Run: `cargo test -p xmem-cli`
Expected: 파싱 테스트 6개 통과

- [ ] **Step 5: 스모크 실행**

Run: `cargo run -p xmem-cli -- --version` → `xmem 0.1.0`
Run: `cargo run -p xmem-cli -- process list` → stderr `error: not implemented yet: process list`, exit code 1
Run: `cargo run -p xmem-cli -- --json process list` → stdout JSON envelope(`"ok":false`), exit 1

- [ ] **Step 6: Commit**

```bash
git add crates/xmem-cli
git commit -m "feat(cli): 전체 명령 트리, 로깅 분리, JSON 오류 envelope"
```

---

### Task 7: README/CONTRIBUTING + 최종 검증

**Files:**
- Create: `README.md`, `CONTRIBUTING.md`
- Modify: 없음

- [ ] **Step 1: README 작성**

포함: Overview, Status 표(Implemented/Experimental/Planned), Requirements(Rust 1.98+, MSVC Build Tools, Windows 10/11 x64), Build, Quick Start, CLI Usage, Architecture 링크(`docs/architecture.md`), Testing, Limitations(비관리자 제약, user-mode 한정), Roadmap(M1~M12 요약).
**구현되지 않은 기능을 구현된 것처럼 쓰지 않는다.** M1 시점 표기: workspace/core/windows/cli 골격 = Implemented, 나머지 = Planned.

- [ ] **Step 2: CONTRIBUTING 작성**

포함: build/lint/test 명령, 커밋 규칙, unsafe 규칙(xmem-windows만), 에러 모델 규칙(XmemError, anyhow 제한), 문서 규칙(미검증 내용 금지), 성능/자원 규칙(bounded buffer, read-only 기본).

- [ ] **Step 3: 전체 게이트 실행**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: 전부 성공, warning 0.

- [ ] **Step 4: 반복 실행 검증 (누수/안정성)**

```powershell
1..3 | ForEach-Object { cargo run -q -p xmem-cli -- process list; "exit=$LASTEXITCODE" }
```
Expected: 매회 동일한 결과(exit 1), panic 없음.

- [ ] **Step 5: Commit**

```bash
git add README.md CONTRIBUTING.md
git commit -m "docs: README와 CONTRIBUTING (M1 상태 반영)"
```

---

## Self-Review Notes

- **Spec coverage**: M1 항목(workspace, CLI skeleton, core data model, error model, logging, windows abstraction) 전부 Task 1~6에 매핑. `docs/architecture.md`가 설계 스펙을, 이 문서가 실행 계획을 담당한다.
- **Type consistency**: `XmemError` variant 이름은 error_kind 매핑(Task 6)과 일치. `Protection` 생성자는 `new(raw, r, w, x)`로 고정. `ReadOutcome`은 core 소유.
- **알려진 확인 지점(구현 시 rustdoc 검증)**: `GetExitCodeProcess`/`OpenProcess` 시그니처, `STILL_ACTIVE` 위치, `windows::core::Error::message()` 반환형, `HANDLE::is_invalid()` API.
- **TODO 게이트**: none. 모든 Step에 코드/명령이 있다.
