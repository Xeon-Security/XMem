use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryType {
    Image,
    Mapped,
    Private,
}

/// Windows protection 값. raw flag와 사람이 읽는 R/W/X 플래그를 함께 보존한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protection {
    pub raw: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl Protection {
    pub fn new(raw: u32, readable: bool, writable: bool, executable: bool) -> Self {
        Self {
            raw,
            readable,
            writable,
            executable,
        }
    }

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
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = if self.readable { 'R' } else { '-' };
        let w = if self.writable { 'W' } else { '-' };
        let x = if self.executable { 'X' } else { '-' };
        write!(f, "{r}{w}{x} (0x{:02x})", self.raw & 0xff)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionClass {
    Image,
    Mapped,
    Private,
    Free,
    Reserved,
    Unknown,
}

/// 해석 계층이 아닌 분류 힌트. Detection Rule의 입력으로만 사용한다.
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
    /// VirtualQueryEx의 AllocationBase. Free 영역 등 할당이 없으면 None.
    #[serde(default)]
    pub allocation_base: Option<u64>,
    pub state: MemoryState,
    pub protection: Protection,
    pub allocation_protection: Option<Protection>,
    pub region_type: Option<MemoryType>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub classification: RegionClass,
    pub heuristics: Vec<Heuristic>,
    pub mapped_file: Option<String>,
}

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
        assert_eq!(
            Heuristic::ExecutablePrivate.to_string(),
            "executable_private"
        );
        assert_eq!(
            Heuristic::PrivateExecutablePeLike.to_string(),
            "private_executable_pe_like"
        );
    }

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
            assert_eq!(
                (p.readable, p.writable, p.executable),
                (r, w, x),
                "raw={raw:#x}"
            );
        }
        let guarded = Protection::from_win32(0x140);
        assert_eq!(guarded.raw, 0x140, "guard 비트는 raw에 보존");
    }

    #[test]
    fn protection_display_includes_flags_and_raw() {
        assert_eq!(
            Protection::new(0x40, true, true, true).to_string(),
            "RWX (0x40)"
        );
        assert_eq!(
            Protection::new(0x01, false, false, false).to_string(),
            "--- (0x01)"
        );
    }

    #[test]
    fn allocation_base_deserializes_when_missing() {
        let old = r#"{
            "base": 4096, "size": 4096, "state": "commit",
            "protection": {"raw": 4, "readable": true, "writable": true, "executable": false},
            "allocation_protection": null, "region_type": "private",
            "readable": true, "writable": true, "executable": false,
            "classification": "private", "heuristics": [], "mapped_file": null
        }"#;
        let region: MemoryRegion = serde_json::from_str(old).unwrap();
        assert_eq!(region.allocation_base, None, "구 스냅샷은 None으로 복원");

        let with_alloc = old.replace(
            "\"base\": 4096,",
            "\"base\": 4096, \"allocation_base\": 8192,",
        );
        let region: MemoryRegion = serde_json::from_str(&with_alloc).unwrap();
        assert_eq!(region.allocation_base, Some(8192));
    }
}
