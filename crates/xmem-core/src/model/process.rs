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

/// Windows FILETIME(1601-01-01 기준 100ns 단위)을 Unix epoch 초로 변환한다.
///
/// FILETIME은 unsigned지만 1601~1969 구간은 음수가 되므로 i64로 반환한다.
pub fn filetime_to_unix_secs(ft: u64) -> i64 {
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;
    if ft < UNIX_EPOCH_FILETIME {
        -(((UNIX_EPOCH_FILETIME - ft) / HUNDRED_NS_PER_SEC) as i64)
    } else {
        ((ft - UNIX_EPOCH_FILETIME) / HUNDRED_NS_PER_SEC) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
    const HUNDRED_NS: u64 = 10_000_000;

    #[test]
    fn unix_epoch_maps_to_zero() {
        assert_eq!(filetime_to_unix_secs(UNIX_EPOCH_FILETIME), 0);
    }

    #[test]
    fn one_second_after_epoch() {
        assert_eq!(filetime_to_unix_secs(UNIX_EPOCH_FILETIME + HUNDRED_NS), 1);
    }

    #[test]
    fn one_second_before_epoch_is_negative() {
        assert_eq!(filetime_to_unix_secs(UNIX_EPOCH_FILETIME - HUNDRED_NS), -1);
    }

    #[test]
    fn zero_filetime_is_1601_epoch() {
        assert_eq!(filetime_to_unix_secs(0), -11_644_473_600);
    }
}
