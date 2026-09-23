use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessArch {
    X64,
    X86,
    Arm64,
    Unknown,
}

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
