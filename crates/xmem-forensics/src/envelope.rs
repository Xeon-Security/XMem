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

/// 수집 메타데이터(출처/예산/실패 통계).
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, ProcessArch, Protection, RegionClass};

    pub(crate) fn sample_envelope(
        pid: u32,
        region_base: u64,
        protection_raw: u32,
    ) -> SnapshotEnvelope {
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
                allocation_base: Some(region_base),
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
