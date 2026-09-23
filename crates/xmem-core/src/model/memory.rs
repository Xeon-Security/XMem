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
