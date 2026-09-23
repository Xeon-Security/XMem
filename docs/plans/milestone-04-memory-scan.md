# XMem Milestone 4 — Memory Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xmem memory scan --pid <PID>`가 ReadProcessMemory chunked 읽기로 바이트 패턴(리터럴/와일드카드/니블 마스크), ASCII/UTF-16 문자열을 검색하고, 필터·bounded worker·취소·자원 카운터를 갖춘 결과를 human/JSON으로 출력한다.

**Architecture:** 패턴 파서/매처는 core(순수 로직, `pattern.rs`), chunked 병렬 스캔 엔진은 xmem-memory(`scan.rs`, `MemorySource` trait 위에서 동작 — LiveProcess/Snapshot 공용), Win32 읽기는 xmem-windows(`read.rs`). CLI는 옵션 파싱·ctrlc wiring·표시만 담당한다.

**Tech Stack:** Rust 1.98 / edition 2024, windows 0.62 (`Win32_System_Diagnostics_Debug` feature 추가), rayon 1 (bounded pool), ctrlc 3, clap 4, serde/serde_json.

**Spec:** `docs/architecture.md` — Memory Scanner(M4), Host Stability(청크/worker/정책), Error Model, CLI 계약. M3 계획서(`docs/plans/milestone-03-memory-map.md`)의 스타일을 따른다.

## Global Constraints

- Rust stable 1.98+, edition 2024. `cargo fmt --all -- --check`, `cargo clippy -q --workspace --all-targets -- -D warnings` 통과.
- `unsafe`는 `xmem-windows`에만 허용. core/memory/cli에 unsafe 금지.
- Read-only: M4에서도 쓰기 Win32 API 금지(ReadProcessMemory는 읽기 전용).
- bounded resources: chunk 기본 1 MiB(허용 4 KiB~16 MiB), worker `min(논리CPU-1, 4)`(상한 64), worker별 재사용 버퍼(총 ≈ threads × (chunk+패턴)), 결과 상한 기본 1024(`--max-results 0`=무제한). 프로세스 메모리를 통째로 올리지 않는다.
- 스캔 대상 선정: committed + readable + non-guard 영역만. Free/Reserve/NOACCESS/guard는 skip하고 카운트한다.
- 대형 프로세스 정책: committed 합계 > 4 GiB이면 기본적으로 executable 또는 private 영역만 스캔(`--all`로 해제). 정책 적용 여부를 출력에 명시한다.
- 취소: ctrlc 핸들러가 `AtomicBool` 설정 → 엔진이 chunk 경계마다 확인. 취소 시 부분 결과 + `cancelled: true` 출력 후 `XmemError::Cancelled` 반환, exit code 130.
- 오류는 구조화: `ERROR_PARTIAL_COPY(299)`→`PartialRead`→ `ReadOutcome{partial:true}`(정상 흐름), `ACCESS_DENIED(5)`→`AccessDenied`, `NOACCESS(998)/INVALID_ADDRESS(487)`→`InvalidAddress`, 그 외→`WindowsApi`.
- JSON은 `success_envelope`(ok/schema_version), human은 고정폭 표. exit code 계약: 0/1/2/3 + **130(cancelled 추가)**.
- 한글 문서/커밋 메시지. 커밋 prefix feat/fix/docs/style/refactor/test/chore.
- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"`; red는 `cargo check -p <crate> --tests`.

## Review Focus

테스트가 못 잡기 쉬운 5개 실패 모드. 각 항목은 담당 Task에 테스트가 배치되어 있다.

1. **청크 경계를 걸치는 패턴**: overlap(패턴 길이-1) 없이는 조용한 거짓 음성이 발생 → Task 3 테스트(경계 스트래들 매치).
2. **부분 읽기(partial)가 매치를 잃지 않음**: 299는 실패가 아니라 읽힌 바이트를 스캔해야 함 → Task 2 + Task 3 테스트.
3. **보호 영역에서 실패 폭증 대신 정직한 스킵**: guard/NOACCESS/non-readable은 사전 스킵하고 regions_skipped에 카운트 → Task 3 테스트 + Task 4 요약 표시.
4. **`--max-results` 도달 시 조용한 절단 금지**: `truncated: true` + human 경고 → Task 3 테스트 + Task 4 테스트.
5. **취소 경로의 일관성**: 부분 결과 출력, handle RAII 정리, exit 130 → Task 3 cancel 테스트 + Task 4 `execute_scan` 테스트 + Task 5 main exit code.

## File Structure

- Modify: `crates/xmem-core/src/error.rs` — `InvalidInput`, `Cancelled` variant
- Create: `crates/xmem-core/src/pattern.rs` — `BytePattern`(파서/매처), `PatternKind`, `ScanPattern`
- Modify: `crates/xmem-core/src/lib.rs` — pattern 등록·재수출
- Modify: `crates/xmem-windows/Cargo.toml` — `Win32_System_Diagnostics_Debug` feature
- Create: `crates/xmem-windows/src/read.rs` — `read_process_memory`
- Modify: `crates/xmem-windows/src/lib.rs` — `pub mod read;` + 재수출
- Modify: `crates/xmem-memory/Cargo.toml` — serde, rayon
- Create: `crates/xmem-memory/src/scan.rs` — 필터/선정/엔진/리포트 + mock-source 테스트
- Modify: `crates/xmem-memory/src/live.rs` — `MemorySource::read` 구현 + 테스트 조정
- Modify: `crates/xmem-memory/src/lib.rs` — scan 등록·재수출
- Modify: `Cargo.toml` — `rayon`, `ctrlc` workspace deps
- Modify: `crates/xmem-cli/Cargo.toml` — ctrlc
- Modify: `crates/xmem-cli/src/cli.rs` — `ScanArgs` (ArgGroup)
- Modify: `crates/xmem-cli/src/commands/memory.rs` — scan 구현(파서 헬퍼·render·JSON)
- Modify: `crates/xmem-cli/src/main.rs` — cancelled exit 130 + 출력 억제
- Modify: `README.md`, `docs/architecture.md` — M4 상태·exit code 130·deps

---

### Task 1: core — 에러 variant + pattern 모듈

**Files:**
- Modify: `crates/xmem-core/src/error.rs`
- Create: `crates/xmem-core/src/pattern.rs`
- Modify: `crates/xmem-core/src/lib.rs`

**Interfaces:**
- Produces:
  - `XmemError::InvalidInput { reason: String }`, `XmemError::Cancelled { reason: String }`
  - `pub struct BytePattern` — `parse_hex(&str)`, `from_ascii(&str)`, `from_wide(&str)`, `len()`, `is_empty()`, `find_in(&[u8], limit: usize) -> Vec<usize>`
  - `pub enum PatternKind { Hex, Ascii, Wide }` (serde snake_case, `as_str()`)
  - `pub struct ScanPattern { pub pattern: BytePattern, pub kind: PatternKind, pub source: String }` — `hex()/ascii()/wide()/len()`
  - `pub const MAX_PATTERN_LEN: usize = 4096;`

- [ ] **Step 1: error.rs에 variant 추가 + 테스트**

`crates/xmem-core/src/error.rs`의 `Unimplemented` 아래, `WindowsApi` 위(또는 Io 앞)에 추가:

```rust
    #[error("invalid input: {reason}")]
    InvalidInput { reason: String },

    #[error("cancelled: {reason}")]
    Cancelled { reason: String },
```

기존 에러 테스트 모듈에 추가(파일 아래쪽 테스트 모듈에 이어서):

```rust
    #[test]
    fn invalid_input_and_cancelled_display() {
        assert_eq!(
            XmemError::InvalidInput {
                reason: "bad pattern".into()
            }
            .to_string(),
            "invalid input: bad pattern"
        );
        assert_eq!(
            XmemError::Cancelled {
                reason: "Ctrl+C".into()
            }
            .to_string(),
            "cancelled: Ctrl+C"
        );
    }
```

- [ ] **Step 2: pattern.rs 테스트 먼저 작성 (red)**

`crates/xmem-core/src/pattern.rs`:

```rust
use crate::{Result, XmemError};

#[cfg(test)]
mod tests {
    use super::*;

    fn err(input: &str, f: impl Fn(&str) -> Result<BytePattern>) {
        assert!(
            matches!(f(input), Err(XmemError::InvalidInput { .. })),
            "input {input:?}는 InvalidInput이어야 함"
        );
    }

    #[test]
    fn parse_hex_literals_and_wildcards() {
        let p = BytePattern::parse_hex("48 8B ?? C0").unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.bytes, vec![0x48, 0x8B, 0x00, 0xC0]);
        assert_eq!(p.mask, vec![0xFF, 0xFF, 0x00, 0xFF]);
        let p = BytePattern::parse_hex("8").unwrap();
        assert_eq!(p.bytes, vec![0x08]);
        assert_eq!(p.mask, vec![0xFF]);
    }

    #[test]
    fn parse_hex_nibble_masks() {
        let p = BytePattern::parse_hex("4? ?8 ?? ?").unwrap();
        assert_eq!(p.bytes, vec![0x40, 0x08, 0x00, 0x00]);
        assert_eq!(p.mask, vec![0xF0, 0x0F, 0x00, 0x00]);
        assert_eq!(p.len(), 4);
    }

    #[test]
    fn parse_hex_rejects_bad_input() {
        err("", BytePattern::parse_hex);
        err("   ", BytePattern::parse_hex);
        err("GG", BytePattern::parse_hex);
        err("4?8", BytePattern::parse_hex);
    }

    #[test]
    fn parse_hex_rejects_over_max_len() {
        let long = "AA ".repeat(MAX_PATTERN_LEN + 1);
        err(&long, BytePattern::parse_hex);
    }

    #[test]
    fn from_ascii_and_wide_encode_bytes() {
        let a = BytePattern::from_ascii("AB").unwrap();
        assert_eq!(a.bytes, vec![0x41, 0x42]);
        assert_eq!(a.mask, vec![0xFF, 0xFF]);
        let w = BytePattern::from_wide("AB").unwrap();
        assert_eq!(w.bytes, vec![0x41, 0x00, 0x42, 0x00]);
        err("", BytePattern::from_ascii);
        err("", BytePattern::from_wide);
    }

    #[test]
    fn find_in_exact_and_mask() {
        let hay = [0x00, 0x48, 0x8B, 0x11, 0xC0, 0x48, 0x8B, 0x22, 0xC0];
        let p = BytePattern::parse_hex("48 8B ?? C0").unwrap();
        assert_eq!(p.find_in(&hay, usize::MAX), vec![1, 5]);
        let p = BytePattern::parse_hex("4? 8B").unwrap();
        assert_eq!(p.find_in(&hay, usize::MAX), vec![1, 5]);
    }

    #[test]
    fn find_in_limits_and_edges() {
        let hay = [0x7A, 0x7A, 0x7A];
        let p = BytePattern::parse_hex("7A").unwrap();
        assert_eq!(p.find_in(&hay, 2), vec![0, 1]);
        assert_eq!(p.find_in(&hay, 0), Vec::<usize>::new());
        let long = BytePattern::parse_hex("7A 7A 7A 7A").unwrap();
        assert!(long.find_in(&hay, usize::MAX).is_empty());
    }

    #[test]
    fn scan_pattern_kinds() {
        let p = ScanPattern::hex("48 8B").unwrap();
        assert_eq!(p.kind, PatternKind::Hex);
        assert_eq!(p.kind.as_str(), "hex");
        assert_eq!(p.len(), 2);
        assert_eq!(p.source, "48 8B");
        assert_eq!(ScanPattern::ascii("hi").unwrap().kind, PatternKind::Ascii);
        assert_eq!(ScanPattern::wide("hi").unwrap().len(), 4);
    }
}
```

`crates/xmem-core/src/lib.rs`에 `pub mod pattern;`(classify 아래) + 재수출:

```rust
pub use pattern::{BytePattern, MAX_PATTERN_LEN, PatternKind, ScanPattern};
```

- [ ] **Step 3: red 확인**

Run: `cargo check -p xmem-core --tests`
Expected: FAIL — `cannot find type BytePattern`(E0433), `ScanPattern` 등.

- [ ] **Step 4: pattern.rs 구현**

테스트 모듈 위에 추가:

```rust
/// 패턴 최대 길이(바이트).
pub const MAX_PATTERN_LEN: usize = 4096;

/// 바이트 패턴. mask가 0xFF면 정확 일치, 0xF0/0x0F면 니블 일치, 0x00이면 무시.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    bytes: Vec<u8>,
    mask: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    Hex,
    Ascii,
    Wide,
}

impl PatternKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternKind::Hex => "hex",
            PatternKind::Ascii => "ascii",
            PatternKind::Wide => "wide",
        }
    }
}

/// 사용자 입력에서 만든 검색 패턴.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPattern {
    pub pattern: BytePattern,
    pub kind: PatternKind,
    pub source: String,
}

impl ScanPattern {
    pub fn hex(source: &str) -> Result<Self> {
        Ok(Self {
            pattern: BytePattern::parse_hex(source)?,
            kind: PatternKind::Hex,
            source: source.to_string(),
        })
    }

    pub fn ascii(source: &str) -> Result<Self> {
        Ok(Self {
            pattern: BytePattern::from_ascii(source)?,
            kind: PatternKind::Ascii,
            source: source.to_string(),
        })
    }

    pub fn wide(source: &str) -> Result<Self> {
        Ok(Self {
            pattern: BytePattern::from_wide(source)?,
            kind: PatternKind::Wide,
            source: source.to_string(),
        })
    }

    pub fn len(&self) -> usize {
        self.pattern.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }
}

fn invalid(reason: impl Into<String>) -> XmemError {
    XmemError::InvalidInput {
        reason: reason.into(),
    }
}

fn hex_digit(c: char) -> Option<u8> {
    c.to_digit(16).map(|d| d as u8)
}

impl BytePattern {
    /// 공백 구분 16진 토큰. `??`는 임의 바이트, `4?`/`?8`은 니블 마스크, 한 자리는 0x0v.
    pub fn parse_hex(input: &str) -> Result<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();
        for token in input.split_whitespace() {
            let chars: Vec<char> = token.chars().collect();
            match chars.as_slice() {
                ['?'] => {
                    bytes.push(0);
                    mask.push(0x00);
                }
                [c] => {
                    let v = hex_digit(*c).ok_or_else(|| {
                        invalid(format!("패턴 토큰 '{token}'이(가) 16진수가 아님"))
                    })?;
                    bytes.push(v);
                    mask.push(0xFF);
                }
                [hi, lo] => {
                    let (mut value, mut m) = (0u8, 0u8);
                    if *hi != '?' {
                        value |= hex_digit(*hi).ok_or_else(|| {
                            invalid(format!("패턴 토큰 '{token}'이(가) 16진수가 아님"))
                        })? << 4;
                        m |= 0xF0;
                    }
                    if *lo != '?' {
                        value |= hex_digit(*lo).ok_or_else(|| {
                            invalid(format!("패턴 토큰 '{token}'이(가) 16진수가 아님"))
                        })?;
                        m |= 0x0F;
                    }
                    bytes.push(value);
                    mask.push(m);
                }
                _ => {
                    return Err(invalid(format!("패턴 토큰 '{token}'이(가) 너무 김(1~2자)")));
                }
            }
            if bytes.len() > MAX_PATTERN_LEN {
                return Err(invalid(format!("패턴이 너무 김(최대 {MAX_PATTERN_LEN}바이트)")));
            }
        }
        if bytes.is_empty() {
            return Err(invalid("빈 패턴"));
        }
        Ok(Self { bytes, mask })
    }

    pub fn from_ascii(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid("빈 문자열 패턴"));
        }
        let bytes = input.as_bytes().to_vec();
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(invalid(format!("패턴이 너무 김(최대 {MAX_PATTERN_LEN}바이트)")));
        }
        Ok(Self {
            mask: vec![0xFF; bytes.len()],
            bytes,
        })
    }

    pub fn from_wide(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(invalid("빈 문자열 패턴"));
        }
        let mut bytes = Vec::new();
        for unit in input.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(invalid(format!("패턴이 너무 김(최대 {MAX_PATTERN_LEN}바이트)")));
        }
        Ok(Self {
            mask: vec![0xFF; bytes.len()],
            bytes,
        })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// hay에서 패턴이 시작하는 위치들. limit개까지만 수집(0이면 0개, usize::MAX=무제한).
    pub fn find_in(&self, hay: &[u8], limit: usize) -> Vec<usize> {
        let n = self.len();
        let mut out = Vec::new();
        if n == 0 || hay.len() < n || limit == 0 {
            return out;
        }
        'outer: for i in 0..=hay.len() - n {
            for j in 0..n {
                if hay[i + j] & self.mask[j] != self.bytes[j] {
                    continue 'outer;
                }
            }
            out.push(i);
            if out.len() >= limit {
                break;
            }
        }
        out
    }
}
```

- [ ] **Step 5: green 확인**

Run: `cargo test -p xmem-core`
Expected: PASS — 기존 23 + 신규 9 = 32 tests.

- [ ] **Step 6: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-core --all-targets -- -D warnings
git add crates/xmem-core
git commit -m "feat(core): 패턴 파서/매처와 InvalidInput·Cancelled 에러"
```

---

### Task 2: xmem-windows — ReadProcessMemory 래퍼

**Files:**
- Modify: `crates/xmem-windows/Cargo.toml`
- Create: `crates/xmem-windows/src/read.rs`
- Modify: `crates/xmem-windows/src/lib.rs`

**Interfaces:**
- Consumes: `crate::error::win32_code_from_hresult`, `crate::handle::OwnedHandle`, `crate::memory::{walk_regions, native_max_user_address, MAX_REGIONS}`, `crate::process::{current_pid, open_for_query}` (테스트).
- Produces: `pub fn read_process_memory(handle: &OwnedHandle, address: u64, buf: &mut [u8]) -> Result<usize>` — 성공 시 읽은 바이트 수, 299는 `XmemError::PartialRead { read }`.

- [ ] **Step 1: Cargo feature + 테스트 먼저 (red)**

`crates/xmem-windows/Cargo.toml`의 windows features에 `"Win32_System_Diagnostics_Debug"` 추가.

`crates/xmem-windows/src/read.rs`:

```rust
use std::ffi::c_void;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_ADDRESS, ERROR_NOACCESS, ERROR_PARTIAL_COPY,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_FREE};

use xmem_core::{Result, XmemError};

use crate::error::win32_code_from_hresult;
use crate::handle::OwnedHandle;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MAX_REGIONS, native_max_user_address, walk_regions};
    use crate::process::{current_pid, open_for_query};

    #[test]
    fn read_own_stack_value() {
        let value: u64 = 0x1122_3344_5566_7788;
        let handle = open_for_query(current_pid()).unwrap();
        let mut buf = [0u8; 8];
        let n = read_process_memory(&handle, (&value as *const u64) as u64, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(u64::from_ne_bytes(buf), value);
    }

    #[test]
    fn empty_buffer_returns_zero() {
        let handle = open_for_query(current_pid()).unwrap();
        assert_eq!(read_process_memory(&handle, 0, &mut []).unwrap(), 0);
    }

    #[test]
    fn null_address_fails_structured() {
        let handle = open_for_query(current_pid()).unwrap();
        let mut buf = [0u8; 8];
        let err = read_process_memory(&handle, 0, &mut buf).unwrap_err();
        assert!(
            matches!(err, XmemError::InvalidAddress { .. } | XmemError::PartialRead { .. }),
            "예상 밖 오류: {err:?}"
        );
    }

    #[test]
    fn crossing_into_free_region_is_partial_or_error() {
        let handle = open_for_query(current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        let boundary = walk.regions.windows(2).find_map(|w| {
            (w[0].state == MEM_COMMIT.0 && w[1].state == MEM_FREE.0)
                .then_some(w[0].base + w[0].size)
        });
        let Some(boundary) = boundary else {
            panic!("committed→free 경계를 찾지 못함");
        };
        let mut buf = [0u8; 8];
        match read_process_memory(&handle, boundary - 4, &mut buf) {
            Err(XmemError::PartialRead { read, .. }) => assert!(read <= 4),
            Err(XmemError::InvalidAddress { .. }) | Err(XmemError::WindowsApi { .. }) => {}
            Ok(n) => assert!(n <= 4),
            other => panic!("예상 밖 결과: {other:?}"),
        }
    }
}
```

`crates/xmem-windows/src/lib.rs`에 `pub mod read;` 추가.

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `cannot find function read_process_memory`(E0425).

- [ ] **Step 3: 구현**

테스트 모듈 위에 추가:

```rust
/// ReadProcessMemory 단일 호출. 성공 시 실제 읽은 바이트 수.
/// `ERROR_PARTIAL_COPY`는 실패가 아니라 부분 읽기로 보고한다(XmemError::PartialRead).
pub fn read_process_memory(handle: &OwnedHandle, address: u64, buf: &mut [u8]) -> Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let requested = buf.len();
    let mut read: usize = 0;
    let result = unsafe {
        ReadProcessMemory(
            handle.raw(),
            address as *const c_void,
            buf.as_mut_ptr().cast(),
            requested,
            Some(&mut read),
        )
    };
    match result {
        Ok(()) => Ok(read.min(requested)),
        Err(e) => {
            let code = win32_code_from_hresult(e.code().0);
            if code == ERROR_PARTIAL_COPY.0 {
                Err(XmemError::PartialRead {
                    address,
                    requested,
                    read: read.min(requested),
                })
            } else if code == ERROR_ACCESS_DENIED.0 {
                Err(XmemError::AccessDenied {
                    context: format!("ReadProcessMemory at {address:#x}: {}", e.message()),
                })
            } else if code == ERROR_NOACCESS.0 || code == ERROR_INVALID_ADDRESS.0 {
                Err(XmemError::InvalidAddress { address })
            } else {
                Err(XmemError::WindowsApi {
                    api: "ReadProcessMemory",
                    code,
                    message: e.message(),
                })
            }
        }
    }
}
```

- [ ] **Step 4: green 확인**

Run: `cargo test -p xmem-windows`
Expected: PASS — 기존 38 + 신규 4 = 42 tests.

- [ ] **Step 5: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-windows --all-targets -- -D warnings
git add crates/xmem-windows
git commit -m "feat(windows): ReadProcessMemory 청크 읽기 래퍼"
```

---

### Task 3: xmem-memory — 스캔 엔진 + LiveProcess::read

**Files:**
- Modify: `Cargo.toml` (rayon)
- Modify: `crates/xmem-memory/Cargo.toml` (serde, rayon)
- Create: `crates/xmem-memory/src/scan.rs`
- Modify: `crates/xmem-memory/src/live.rs`
- Modify: `crates/xmem-memory/src/lib.rs`

**Interfaces:**
- Consumes: `xmem_windows::read::read_process_memory`, core `MemorySource`, `ScanPattern`, `MemoryState`, `RegionClass`.
- Produces:
  - `pub struct RegionFilters { executable_only, private_only, writable_only, range: Option<(u64,u64)>, max_region_size: Option<u64>, all }`
  - `pub struct ScanOptions { filters, chunk_size, threads, max_results, offset: Option<u64> }` (+Default)
  - `pub struct ScanMatch { address, region_base, region_size, offset, class, protection, mapped_file }`
  - `pub struct ScanStats { regions_total, regions_scanned, regions_skipped, bytes_scanned, read_failures, partial_reads, matches, threads, elapsed_ms }`
  - `pub struct ScanReport { matches, stats, cancelled, truncated, policy_restricted }`
  - `pub fn scan<S: MemorySource + Sync>(source, pattern, options, cancel: &AtomicBool) -> Result<ScanReport>`
  - `impl MemorySource for LiveProcess`의 `read`가 실제 읽기로 동작

- [ ] **Step 1: workspace/crate deps + LiveProcess::read + 테스트 조정 (red)**

`Cargo.toml`(루트) `[workspace.dependencies]`에 추가:

```toml
rayon = "1"
ctrlc = "3"
```

(ctrlc는 Task 4에서 사용)

`crates/xmem-memory/Cargo.toml`에 추가:

```toml
rayon.workspace = true
serde.workspace = true
```

`crates/xmem-memory/src/live.rs`의 `read` 구현 교체:

```rust
    fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
        match xmem_windows::read::read_process_memory(&self.handle, address, buf) {
            Ok(n) => Ok(ReadOutcome {
                bytes_read: n,
                partial: n < buf.len(),
            }),
            Err(XmemError::PartialRead { read, .. }) => Ok(ReadOutcome {
                bytes_read: read,
                partial: true,
            }),
            Err(e) => Err(e),
        }
    }
```

`unimplemented_methods_are_explicit` 테스트에서 `read` 부분을 제거하고, 별도 테스트 추가:

```rust
    #[test]
    fn read_self_stack_value() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let value: u64 = 0x0102_0304_0506_0708;
        let mut buf = [0u8; 8];
        let outcome = live.read((&value as *const u64) as u64, &mut buf).unwrap();
        assert_eq!(outcome.bytes_read, 8);
        assert!(!outcome.partial);
        assert_eq!(u64::from_ne_bytes(buf), value);
    }
```

- [ ] **Step 2: scan.rs 테스트 먼저 작성 (red)**

`crates/xmem-memory/src/scan.rs` — mock source 기반 테스트 모듈(테스트가 스펙):

```rust
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;

use xmem_core::{
    MemoryRegion, MemorySource, MemoryState, ModuleInfo, ProcessArch, ProcessInfo, Protection,
    ReadOutcome, RegionClass, Result, ScanPattern, ThreadInfo, XmemError,
};

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_COMMIT: u32 = 0x1000;
    const PAGE_PRIVATE: u32 = 0x20000;
    const PAGE_RW: u32 = 0x04;
    const PAGE_RWX: u32 = 0x40;

    fn make_region(base: u64, size: u64, protect: u32, region_type: u32) -> MemoryRegion {
        let p = xmem_core::Protection::new(protect, true, true, protect == PAGE_RWX);
        MemoryRegion {
            base,
            size,
            state: MemoryState::Commit,
            protection: p,
            allocation_protection: None,
            region_type: Some(xmem_core::MemoryType::Private),
            readable: true,
            writable: true,
            executable: protect == PAGE_RWX,
            classification: RegionClass::Private,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    struct MockSource {
        info: ProcessInfo,
        regions: Vec<MemoryRegion>,
        content: BTreeMap<u64, Vec<u8>>,
        fail: BTreeMap<u64, XmemError>,
    }
    ...
}
```

(전체 파일은 Step 3 구현과 함께 완성한다 — 테스트는 아래 시나리오 커버: 청크 경계 스트래들, offset 필터, 필터 선정, 실패 카운트, 취소, max_results/truncated, partial, guard/non-readable 스킵, 대형 프로세스 정책.)

- [ ] **Step 3: 엔진 구현**

핵심 구현(테스트 모듈 위):

```rust
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_RESULTS: usize = 1024;
pub const MAX_THREADS: usize = 64;
pub const HUGE_COMMIT_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024;
const PAGE_GUARD_BIT: u32 = 0x100;

#[derive(Debug, Clone, Default)]
pub struct RegionFilters {
    pub executable_only: bool,
    pub private_only: bool,
    pub writable_only: bool,
    pub range: Option<(u64, u64)>,
    pub max_region_size: Option<u64>,
    pub all: bool,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub filters: RegionFilters,
    pub chunk_size: usize,
    pub threads: usize,
    pub max_results: usize,
    pub offset: Option<u64>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            filters: RegionFilters::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            threads: 1,
            max_results: DEFAULT_MAX_RESULTS,
            offset: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanMatch {
    pub address: u64,
    pub region_base: u64,
    pub region_size: u64,
    pub offset: u64,
    pub class: RegionClass,
    pub protection: Protection,
    pub mapped_file: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ScanStats {
    pub regions_total: usize,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub bytes_scanned: u64,
    pub read_failures: u64,
    pub partial_reads: u64,
    pub matches: usize,
    pub threads: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub matches: Vec<ScanMatch>,
    pub stats: ScanStats,
    pub cancelled: bool,
    pub truncated: bool,
    pub policy_restricted: bool,
}

#[derive(Debug, Default)]
struct RegionScan {
    matches: Vec<ScanMatch>,
    bytes: u64,
    failures: u64,
    partials: u64,
    attempted: bool,
}

/// 스캔 대상 선정. (선택된 region 인덱스, 대형 프로세스 정책 적용 여부)
fn select_regions(regions: &[MemoryRegion], f: &RegionFilters) -> (Vec<usize>, bool) {
    let committed_total = regions
        .iter()
        .filter(|r| r.state == MemoryState::Commit)
        .map(|r| r.size)
        .fold(0u64, u64::saturating_add);
    let huge = !f.all && committed_total > HUGE_COMMIT_THRESHOLD;
    let mut selected = Vec::new();
    for (i, r) in regions.iter().enumerate() {
        if r.state != MemoryState::Commit || !r.readable || r.protection.raw & PAGE_GUARD_BIT != 0 {
            continue;
        }
        if f.executable_only && !r.executable {
            continue;
        }
        if f.private_only && r.classification != RegionClass::Private {
            continue;
        }
        if f.writable_only && !r.writable {
            continue;
        }
        if let Some((start, end)) = f.range {
            if r.base.saturating_add(r.size) <= start || r.base >= end {
                continue;
            }
        }
        if let Some(max) = f.max_region_size {
            if r.size > max {
                continue;
            }
        }
        if huge && !(r.executable || r.classification == RegionClass::Private) {
            continue;
        }
        selected.push(i);
    }
    (selected, huge)
}

fn accept(found: &std::sync::atomic::AtomicUsize, max_results: usize) -> bool {
    let old = found.fetch_add(1, Ordering::SeqCst);
    max_results == 0 || old < max_results
}

#[allow(clippy::too_many_arguments)]
fn scan_region<S: MemorySource + Sync>(
    source: &S,
    region: &MemoryRegion,
    pattern: &ScanPattern,
    chunk: usize,
    overlap: usize,
    offset_filter: Option<u64>,
    max_results: usize,
    cancel: &AtomicBool,
    stop: &AtomicBool,
    budget_hit: &AtomicBool,
    found: &std::sync::atomic::AtomicUsize,
    buf: &mut [u8],
) -> RegionScan {
    let mut out = RegionScan::default();
    if cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
        return out;
    }
    out.attempted = true;
    let limit = if max_results == 0 {
        usize::MAX
    } else {
        max_results
    };
    let mut off: u64 = 0;
    while off < region.size {
        if cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            break;
        }
        let end = off
            .saturating_add(chunk as u64)
            .min(region.size);
        let read_end = end.saturating_add(overlap as u64).min(region.size);
        let read_len = (read_end - off) as usize;
        let addr = region.base + off;
        match source.read(addr, &mut buf[..read_len]) {
            Ok(o) if o.bytes_read > 0 => {
                out.bytes += o.bytes_read as u64;
                if o.partial {
                    out.partials += 1;
                }
                let hay = &buf[..o.bytes_read.min(read_len)];
                for pos in pattern.pattern.find_in(hay, limit) {
                    let abs = addr + pos as u64;
                    let rel = abs - region.base;
                    if let Some(want) = offset_filter {
                        if rel != want {
                            continue;
                        }
                    }
                    if !accept(found, max_results) {
                        budget_hit.store(true, Ordering::SeqCst);
                        stop.store(true, Ordering::SeqCst);
                        return out;
                    }
                    out.matches.push(ScanMatch {
                        address: abs,
                        region_base: region.base,
                        region_size: region.size,
                        offset: rel,
                        class: region.classification,
                        protection: region.protection,
                        mapped_file: region.mapped_file.clone(),
                    });
                }
            }
            Ok(_) => out.failures += 1,
            Err(_) => out.failures += 1,
        }
        off = end;
    }
    out
}

pub fn scan<S: MemorySource + Sync>(
    source: &S,
    pattern: &ScanPattern,
    options: &ScanOptions,
    cancel: &AtomicBool,
) -> Result<ScanReport> {
    let started = Instant::now();
    let all_regions = source.regions()?;
    let regions_total = all_regions.len();
    let (selected, policy_restricted) = select_regions(&all_regions, &options.filters);
    let chunk = options.chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
    let threads = options.threads.clamp(1, MAX_THREADS);
    let overlap = pattern.pattern.len().saturating_sub(1);
    let buf_len = chunk + overlap;
    let stop = AtomicBool::new(false);
    let budget_hit = AtomicBool::new(false);
    let found = std::sync::atomic::AtomicUsize::new(0);
    let results: Vec<RegionScan> = {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| XmemError::InvalidInput {
                reason: format!("스레드 풀 생성 실패: {e}"),
            })?;
        pool.install(|| {
            selected
                .par_iter()
                .map_init(
                    || vec![0u8; buf_len],
                    |buf, &index| {
                        scan_region(
                            source,
                            &all_regions[index],
                            pattern,
                            chunk,
                            overlap,
                            options.offset,
                            options.max_results,
                            cancel,
                            &stop,
                            &budget_hit,
                            &found,
                            buf,
                        )
                    },
                )
                .collect()
        })
    };
    let regions_scanned = results.iter().filter(|r| r.attempted).count();
    let matches: Vec<ScanMatch> = results.into_iter().flat_map(|r| r.matches).collect();
    let stats = ScanStats {
        regions_total,
        regions_scanned,
        regions_skipped: regions_total - regions_scanned,
        bytes_scanned: 0,
        read_failures: 0,
        partial_reads: 0,
        matches: matches.len(),
        threads,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    Ok(ScanReport {
        matches,
        stats,
        cancelled: cancel.load(Ordering::Relaxed),
        truncated: budget_hit.load(Ordering::Relaxed),
        policy_restricted,
    })
}
```

주의: 위의 `stats.bytes_scanned/read_failures/partial_reads`는 `results` 소비 전에 집계해야 한다(구현 시 `results.iter()`로 합산). `RegionScan` 소유권 이동 순서만 지키면 된다.

`crates/xmem-memory/src/lib.rs`:

```rust
pub mod scan;

pub use scan::{
    DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, HUGE_COMMIT_THRESHOLD, MAX_CHUNK_SIZE,
    MAX_THREADS, MIN_CHUNK_SIZE, RegionFilters, ScanMatch, ScanOptions, ScanReport, ScanStats,
    scan,
};
```

- [ ] **Step 4: 테스트 시나리오 완성 + green**

`scan.rs` 테스트 모듈에 mock + 시나리오(~12개)를 완성한다:

```rust
    impl MemorySource for MockSource {
        fn process(&self) -> &ProcessInfo {
            &self.info
        }
        fn regions(&self) -> Result<Vec<MemoryRegion>> {
            Ok(self.regions.clone())
        }
        fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
            if let Some(e) = self.fail.get(&address) {
                return Err(e.clone());   // XmemError: Clone 필요 → error.rs가 Clone? 아니면 맞춤형.
            }
            let region = self
                .regions
                .iter()
                .find(|r| address >= r.base && address < r.base + r.size)
                .ok_or(XmemError::InvalidAddress { address })?;
            let Some(content) = self.content.get(&region.base) else {
                return Err(XmemError::PartialRead { address, requested: buf.len(), read: 0 });
            };
            let start = (address - region.base) as usize;
            let n = buf.len().min(content.len().saturating_sub(start));
            buf[..n].copy_from_slice(&content[start..start + n]);
            Ok(ReadOutcome { bytes_read: n, partial: n < buf.len() })
        }
        fn modules(&self) -> Result<Vec<ModuleInfo>> {
            Err(XmemError::Unimplemented { feature: "modules" })
        }
        fn threads(&self) -> Result<Vec<ThreadInfo>> {
            Err(XmemError::Unimplemented { feature: "threads" })
        }
    }
```

(`fail` 맵은 `fail: Vec<u64>`(읽기 실패 시작 주소)로 단순화해도 된다 — 구현 시 선택.)

시나리오:
1. `finds_pattern_in_single_region` — 리터럴 바이트 2개 매치, 주소/offset 검증.
2. `match_across_chunk_boundary` — chunk 4096, region 8192+, 패턴이 4096 경계에 걸침 → 매치 1개(조용한 거짓 음성 없음).
3. `offset_filter_matches_only_exact_offset` — offset Some(4) → rel==4인 매치만.
4. `filters_select_regions` — executable_only/private_only/writable_only 각각 regions_scanned 검증.
5. `range_filter_limits_regions`.
6. `max_region_size_skips_large_region`.
7. `huge_process_policy_restricts_unless_all` — committed 합계 > 4 GiB(메타데이터만, content 없음) → policy_restricted true + 선택 축소, `all=true`면 해제.
8. `read_failures_counted_and_scan_continues` — 실패 region 1 + 성공 region 1 → failures ≥ 1, 매치 유지.
9. `cancel_flag_stops_scan` — cancel=true 사전 설정 → cancelled=true, regions_scanned 0, matches 0.
10. `max_results_caps_and_reports_truncated` — max_results 3, 매치 다수 → matches.len()==3, truncated=true.
11. `partial_read_scans_returned_bytes` — mock이 partial(4바이트) 반환 → 매치 발견 + partial_reads==1.
12. `non_readable_and_guard_regions_skipped` — readable=false, raw|0x100 → regions_scanned에서 제외.

Run: `cargo test -p xmem-memory`
Expected: PASS — 기존 4(1개 수정) + live 1 + scan ~12 = 약 17 tests.

- [ ] **Step 5: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-memory --all-targets -- -D warnings
git add Cargo.toml crates/xmem-memory
git commit -m "feat(memory): chunked 병렬 메모리 스캔 엔진"
```

---

### Task 4: CLI — `memory scan`

**Files:**
- Modify: `crates/xmem-cli/Cargo.toml` (ctrlc)
- Modify: `crates/xmem-cli/src/cli.rs` (`ScanArgs` + ArgGroup)
- Modify: `crates/xmem-cli/src/commands/memory.rs`
- Modify: `crates/xmem-cli/src/main.rs` (exit 130)

**Interfaces:**
- Consumes: `xmem_memory::{scan, ScanOptions, RegionFilters, ScanReport}`, `xmem_core::{ScanPattern, XmemError}`.
- Produces: `MemoryCmd::Scan(ScanArgs)` 파싱, `commands::memory::run`의 Scan arm, `execute_scan(pid, pattern, opts, cancel) -> Result<(LiveProcess, ScanReport)>`(테스트용 pub(crate)).

- [ ] **Step 1: cli.rs — ScanArgs + 테스트 (red)**

`crates/xmem-cli/src/cli.rs`:

```rust
use clap::{ArgGroup, Args, Parser, Subcommand};
```

`MemoryCmd`를 다음으로 교체:

```rust
#[derive(Debug, Subcommand)]
pub enum MemoryCmd {
    /// 가상 메모리 영역을 나열한다.
    Map(PidArg),
    /// 메모리에서 패턴/문자열을 검색한다.
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("needle").required(true).multiple(false).args(["pattern", "string", "wide_string"])))]
pub struct ScanArgs {
    #[command(flatten)]
    pub pid: PidArg,
    /// 16진 바이트 패턴 (예: "48 8B ?? ?? C0")
    #[arg(long)]
    pub pattern: Option<String>,
    /// ASCII 문자열
    #[arg(long)]
    pub string: Option<String>,
    /// UTF-16LE 문자열
    #[arg(long = "wide-string")]
    pub wide_string: Option<String>,
    #[arg(long = "executable-only")]
    pub executable_only: bool,
    #[arg(long = "private-only")]
    pub private_only: bool,
    #[arg(long = "writable-only")]
    pub writable_only: bool,
    /// 검색할 주소 범위 (예: "0x1000:0x2000")
    #[arg(long)]
    pub range: Option<String>,
    /// 이 크기를 초과하는 영역은 건너뛴다 (예: "8Mi")
    #[arg(long = "max-region-size")]
    pub max_region_size: Option<String>,
    /// 영역 내 상대 오프셋이 정확히 N인 매치만 보고
    #[arg(long)]
    pub offset: Option<u64>,
    /// 최대 결과 수 (0 = 무제한, 기본 1024)
    #[arg(long = "max-results")]
    pub max_results: Option<usize>,
    /// 청크 크기 (기본 1Mi, 허용 4Ki~16Mi)
    #[arg(long = "chunk-size")]
    pub chunk_size: Option<String>,
    /// worker 스레드 수 (기본 min(논리CPU-1, 4))
    #[arg(long)]
    pub threads: Option<usize>,
    /// 대형 프로세스 정책을 해제하고 모든 committed 영역을 스캔
    #[arg(long)]
    pub all: bool,
}
```

cli.rs 테스트 추가:

```rust
    #[test]
    fn memory_scan_parses_pattern_and_filters() {
        let cli = Cli::try_parse_from([
            "xmem",
            "memory",
            "scan",
            "--pid",
            "42",
            "--pattern",
            "48 8B ??",
            "--executable-only",
            "--threads",
            "2",
        ])
        .unwrap();
        let Command::Memory { cmd } = cli.command else {
            panic!("memory 명령이 아님");
        };
        let MemoryCmd::Scan(args) = cmd else {
            panic!("scan 명령이 아님");
        };
        assert_eq!(args.pid.pid, 42);
        assert_eq!(args.pattern.as_deref(), Some("48 8B ??"));
        assert!(args.executable_only);
        assert_eq!(args.threads, Some(2));
    }

    #[test]
    fn memory_scan_requires_exactly_one_needle() {
        assert!(Cli::try_parse_from(["xmem", "memory", "scan", "--pid", "42"]).is_err());
        assert!(
            Cli::try_parse_from([
                "xmem", "memory", "scan", "--pid", "42", "--pattern", "90", "--string", "hi"
            ])
            .is_err()
        );
    }
```

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — `ScanArgs` 없음(E0422/E0433).

- [ ] **Step 3: memory.rs — scan 구현 + 헬퍼 테스트**

`crates/xmem-cli/src/commands/memory.rs`에 추가/수정:

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use xmem_core::{ProcessInfo, RegionClass, Result, ScanPattern, XmemError};
use xmem_memory::{
    DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE, RegionFilters,
    ScanOptions, ScanReport, scan,
};

use crate::cli::{GlobalArgs, MemoryCmd, ScanArgs};
```

`run`의 Scan arm:

```rust
        MemoryCmd::Scan(args) => run_scan(args, global),
```

추가 함수:

```rust
fn cancel_flag() -> Arc<AtomicBool> {
    static CANCEL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    CANCEL
        .get_or_init(|| {
            let flag = Arc::new(AtomicBool::new(false));
            let handler_flag = Arc::clone(&flag);
            if ctrlc::set_handler(move || handler_flag.store(true, Ordering::SeqCst)).is_err() {
                tracing::warn!("Ctrl+C 핸들러 설치 실패");
            }
            flag
        })
        .clone()
}

pub(crate) fn execute_scan(
    pid: u32,
    pattern: &ScanPattern,
    options: &ScanOptions,
    cancelled: &AtomicBool,
) -> Result<(LiveProcess, ScanReport)> {
    let live = LiveProcess::open(pid)?;
    let report = scan(&live, pattern, options, cancelled)?;
    Ok((live, report))
}

fn run_scan(args: &ScanArgs, global: &GlobalArgs) -> Result<()> {
    let pattern = build_pattern(args)?;
    let options = build_options(args)?;
    let cancelled = cancel_flag();
    cancelled.store(false, Ordering::SeqCst);
    let (live, report) = execute_scan(args.pid.pid, &pattern, &options, &cancelled)?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value = serde_json::to_value(scan_json_payload(&live.info, &pattern, &options, &report))
                .map_err(|e| XmemError::JsonError { reason: e.to_string() })?;
            emit_json(&success_envelope(value))?;
        }
        OutputMode::Human => print!("{}", render_scan(&live.info, &pattern, &options, &report)),
    }
    if report.cancelled {
        tracing::warn!("scan cancelled by user");
        return Err(XmemError::Cancelled {
            reason: "user interrupt".to_string(),
        });
    }
    Ok(())
}

fn build_pattern(args: &ScanArgs) -> Result<ScanPattern> {
    if let Some(p) = &args.pattern {
        ScanPattern::hex(p)
    } else if let Some(s) = &args.string {
        ScanPattern::ascii(s)
    } else if let Some(s) = &args.wide_string {
        ScanPattern::wide(s)
    } else {
        Err(XmemError::InvalidInput {
            reason: "--pattern/--string/--wide-string 중 하나가 필요함".to_string(),
        })
    }
}

fn parse_size(input: &str) -> Result<u64> {
    let lower = input.trim().to_ascii_lowercase();
    let lower = lower.strip_suffix('i').unwrap_or(&lower);
    let (digits, mult) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1024u64),
        Some('m') => (&lower[..lower.len() - 1], 1024 * 1024),
        Some('g') => (&lower[..lower.len() - 1], 1024 * 1024 * 1024),
        _ => (lower, 1),
    };
    let value: u64 = digits.trim().parse().map_err(|_| XmemError::InvalidInput {
        reason: format!("크기 파싱 실패: '{input}'"),
    })?;
    value
        .checked_mul(mult)
        .ok_or_else(|| XmemError::InvalidInput {
            reason: format!("크기가 너무 큼: '{input}'"),
        })
}

fn parse_addr(input: &str) -> Result<u64> {
    let t = input.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        t.parse::<u64>()
    }
    .map_err(|_| XmemError::InvalidInput {
        reason: format!("주소 파싱 실패: '{input}'"),
    })
}

fn parse_range(input: &str) -> Result<(u64, u64)> {
    let (a, b) = input.split_once(':').ok_or_else(|| XmemError::InvalidInput {
        reason: format!("--range 형식은 START:END: '{input}'"),
    })?;
    let start = parse_addr(a)?;
    let end = parse_addr(b)?;
    if end <= start {
        return Err(XmemError::InvalidInput {
            reason: format!("--range의 END는 START보다 커야 함: '{input}'"),
        });
    }
    Ok((start, end))
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1))
        .unwrap_or(1)
        .clamp(1, 4)
}

fn build_options(args: &ScanArgs) -> Result<ScanOptions> {
    let chunk_size = match &args.chunk_size {
        Some(s) => {
            let v = parse_size(s)? as usize;
            if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&v) {
                return Err(XmemError::InvalidInput {
                    reason: format!("--chunk-size는 {MIN_CHUNK_SIZE}~{MAX_CHUNK_SIZE} 바이트"),
                });
            }
            v
        }
        None => DEFAULT_CHUNK_SIZE,
    };
    let threads = match args.threads {
        Some(0) => {
            return Err(XmemError::InvalidInput {
                reason: "--threads는 1 이상".to_string(),
            });
        }
        Some(n) => n,
        None => default_threads(),
    };
    let filters = RegionFilters {
        executable_only: args.executable_only,
        private_only: args.private_only,
        writable_only: args.writable_only,
        range: args.range.as_deref().map(parse_range).transpose()?,
        max_region_size: args.max_region_size.as_deref().map(parse_size).transpose()?,
        all: args.all,
    };
    Ok(ScanOptions {
        filters,
        chunk_size,
        threads,
        max_results: args.max_results.unwrap_or(DEFAULT_MAX_RESULTS),
        offset: args.offset,
    })
}

fn render_scan(info: &ProcessInfo, pattern: &ScanPattern, options: &ScanOptions, report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}), pattern {} \"{}\" ({} bytes), chunk {}, threads {}\n",
        info.pid, info.name, pattern.kind.as_str(), truncate(&pattern.source, 48), pattern.len(),
        options.chunk_size, report.stats.threads,
    ));
    if report.policy_restricted {
        out.push_str("policy: committed > 4 GiB — executable/private 영역만 스캔 (--all로 해제)\n");
    }
    out.push_str("ADDRESS             OFFSET    CLASS      PROTECTION     REGION              MAPPED FILE\n");
    for m in &report.matches {
        let mapped = match &m.mapped_file {
            Some(p) => truncate_tail(p, 40),
            None => "-".to_string(),
        };
        out.push_str(&format!(
            "0x{:016x} +0x{:<6x} {:10} {:14} 0x{:016x} {}\n",
            m.address, m.offset, m.class.to_string(), m.protection.to_string(), m.region_base, mapped,
        ));
    }
    out.push_str(&format!(
        "{} matches; regions {}/{} scanned ({} skipped); bytes {}; read_failures {}; partial {}; elapsed {} ms\n",
        report.matches.len(),
        report.stats.regions_scanned,
        report.stats.regions_total,
        report.stats.regions_skipped,
        human_size(report.stats.bytes_scanned),
        report.stats.read_failures,
        report.stats.partial_reads,
        report.stats.elapsed_ms,
    ));
    if report.truncated {
        out.push_str("warning: result cap reached (use --max-results 0 for unlimited)\n");
    }
    if report.cancelled {
        out.push_str("warning: scan cancelled by user\n");
    } else if report.stats.bytes_scanned == 0 && report.stats.read_failures > 0 {
        out.push_str("warning: all reads failed (process may have exited or be protected)\n");
    }
    out
}

fn scan_json_payload(
    info: &ProcessInfo,
    pattern: &ScanPattern,
    options: &ScanOptions,
    report: &ScanReport,
) -> serde_json::Value {
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "pattern": { "kind": pattern.kind.as_str(), "source": pattern.source, "length": pattern.len() },
        "options": {
            "chunk_size": options.chunk_size,
            "threads": options.threads,
            "max_results": options.max_results,
            "offset": options.offset,
        },
        "policy_restricted": report.policy_restricted,
        "cancelled": report.cancelled,
        "truncated": report.truncated,
        "stats": report.stats,
        "matches": report.matches,
    })
}
```

테스트 추가(같은 파일 테스트 모듈):

```rust
    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("4k").unwrap(), 4096);
        assert_eq!(parse_size("16Mi").unwrap(), 16 * 1024 * 1024);
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn parse_range_and_addr() {
        assert_eq!(parse_range("0x1000:0x2000").unwrap(), (0x1000, 0x2000));
        assert_eq!(parse_range("4096:8192").unwrap(), (4096, 8192));
        assert!(parse_range("0x2000:0x1000").is_err());
        assert!(parse_range("0x1000").is_err());
    }

    #[test]
    fn cancelled_flag_yields_cancelled_report() {
        let pattern = ScanPattern::ascii("xmem").unwrap();
        let options = ScanOptions {
            max_results: 1,
            ..ScanOptions::default()
        };
        let cancelled = AtomicBool::new(true);
        let (_live, report) =
            execute_scan(xmem_windows::current_pid(), &pattern, &options, &cancelled).unwrap();
        assert!(report.cancelled);
        assert!(report.matches.is_empty());
    }

    #[test]
    fn render_scan_lists_matches_and_stats() {
        // ScanReport fixture를 만들고(수동 struct) render_scan의 헤더/행/경고 검증
    }

    #[test]
    fn scan_json_payload_shape() {
        // fixture report → process/pattern/options/stats/matches 키 검증
    }
```

(렌더/JSON 테스트는 Task 3 스타일의 수동 fixture로 작성; `ScanMatch`/`ScanStats`/`ScanReport`는 전 필드 pub이므로 리터럴 생성 가능.)

- [ ] **Step 4: main.rs — exit 130**

`exit_code_for`에 arm 추가:

```rust
        XmemError::Cancelled { .. } => 130,
```

에러 출력을 Cancelled만 건너뛰도록 조정(기존 `report_error` 호출 지점):

```rust
    if let Err(err) = result {
        if !matches!(err, XmemError::Cancelled { .. }) {
            report_error(&err, mode);
        }
        std::process::exit(exit_code_for(&err));
    }
```

- [ ] **Step 5: green 확인**

Run: `cargo test -p xmem-cli`
Expected: PASS — 기존 25 + 신규 약 7 = 약 32 tests.

- [ ] **Step 6: fmt + clippy + 커밋**

```bash
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add crates/xmem-cli
git commit -m "feat(cli): memory scan 명령과 취소 처리"
```

---

### Task 5: 문서 + 최종 게이트 + Windows 실검증

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-04-memory-scan.md` (체크박스)

- [ ] **Step 1: README 갱신**

- Status 표에 `memory scan (패턴/ASCII/UTF-16, 필터, chunked 병렬, 취소, --json) | Implemented` 추가, Status 문구 M4 완료로.
- CLI Usage에 `memory scan` 옵션 표(패턴/필터/성능) 추가.
- Exit code 표에 **130 = cancelled(Ctrl+C)** 추가.
- Limitations: guard/non-readable 영역은 스킵(카운트됨), 결과 기본 1024 상한, committed>4 GiB 정책, 문자열 검색은 대소문자 구분, 패턴 매처는 naive(벤치마크 후 최적화 예정).
- Roadmap M4 완료.

- [ ] **Step 2: architecture.md 갱신**

- dependency 표: `rayon 1`(M4), `ctrlc 3`(M4) 도입 명기.
- Status 표 M4 Done.
- Windows API 표 M4 행: 구현됨(`ReadProcessMemory`, feature `Win32_System_Diagnostics_Debug`; 299=PartialRead 매핑).
- CLI 계약에 exit 130 추가.
- xmem-memory 책임에 scan 엔진, core에 pattern 모듈 명기.

- [ ] **Step 3: 전체 게이트**

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0; 테스트 합계 약 130(core ≈32 + windows 42 + memory ≈17 + cli ≈32).

- [ ] **Step 4: Windows 실검증**

```powershell
# 1) 자기(사실상 pwsh) 메모리에서 고유 문자열 검색 — 결정적: pwsh는 자기 경로/이름을 메모리에 갖고 있음
cargo run -q -p xmem-cli -- memory scan --pid $PID --string pwsh --max-results 3
cargo run -q -p xmem-cli -- --json memory scan --pid $PID --wide-string pwsh --max-results 3
# 2) 임의 바이트 패턴 + 캡
cargo run -q -p xmem-cli -- memory scan --pid $PID --pattern "?? ?? ?? ?? ?? ?? ?? ??" --max-results 5
# 3) 실행 영역 한정
cargo run -q -p xmem-cli -- memory scan --pid $PID --pattern "4D 5A" --executable-only --max-results 3
# 4) 오류 경로
$lsass = (Get-Process lsass).Id; cargo run -q -p xmem-cli -- memory scan --pid $lsass --string test
cargo run -q -p xmem-cli -- memory scan --pid 4294967294 --string test
# 5) 반복 3회 안정성
```

확인: 1) 매치 ≥1 + 표/JSON 구조 정상(JSON: stats/regions/matches), 2) 5매치 + truncated 경고, 3) MZ 매치 ≥1(PE 이미지) 또는 0이면 executable 영역 스킵 아님을 stats로 확인, 4) lsass exit 1 access denied, bogus exit 1, 5) 3회 exit 0 + 출력 구조 동일.

취소 경로는 단위 테스트(`cancelled_flag_yields_cancelled_report`)로 검증됨. 실제 Ctrl+C 수동 확인은 선택(Task 5 완료 조건 아님).

- [ ] **Step 5: 체크박스 갱신 + 커밋**

이 계획서의 모든 `- [ ]`를 `- [x]`로 바꾸고:

```bash
git add README.md docs/architecture.md docs/plans/milestone-04-memory-scan.md
git commit -m "docs: M4 메모리 스캐너 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지:** Literal/Wildcard/Mask(니블)/Offset(상대 오프셋 필터)/Address Range(`--range`)/Region Filter(executable·private·writable)/ASCII/UTF-16/`--max-region-size`/`--threads`/`--all`, chunked read(1 MiB 기본)·bounded buffer·worker 상한·executable 우선·대형 프로세스 정책·자원 카운터(regions/bytes/failures/elapsed)·JSON·Ctrl+C 전부 Task 1~4에 매핑.
- **의도적 범위 제외:** 매처 최적화(BM/memchr)는 벤치마크 후(M4는 naive + 조기 종료), progress UI 없음(tracing debug만), case-insensitive 검색 없음, `--json` matches의 context 바이트 미포함.
- **타입 일관성:** `XmemError::InvalidInput/Cancelled`(Task 1) → `ScanPattern/BytePattern`(Task 1) → `read_process_memory`(Task 2) → `ScanOptions/ScanReport`(Task 3) → `ScanArgs/execute_scan`(Task 4) 시그니처 일치.
- **검증 완료 사항:** windows-0.62.2 소스에서 `ReadProcessMemory` 시그니처(lpnumberofbytesread `Option<*mut usize>`, 에러 시에도 값 기록)와 ERROR_PARTIAL_COPY/NOACCESS/INVALID_ADDRESS 상수 위치를 확인함. rayon 1.12.0 / ctrlc 3.5.2 최신 stable 확인.
