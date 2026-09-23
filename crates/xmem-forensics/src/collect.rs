use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Utc;
use xmem_core::{
    JSON_SCHEMA_VERSION, MemoryRegion, MemorySource, MemoryState, RegionClass, Result,
    SNAPSHOT_FORMAT_VERSION, VERSION, XmemError,
};
use xmem_detection::{DetectionContext, detect};

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
            region.classification != RegionClass::Private,
            region.base,
        )
    });
    candidates.truncate(MAX_HASH_REGIONS);
    let mut content_hashes = Vec::new();
    let mut hashed_bytes: u64 = 0;
    let mut read_failures: u64 = 0;
    let mut chunk = vec![0u8; options.hash_chunk_size.max(1)];
    for region in candidates {
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
            break;
        }
    }
    let hashed_regions = content_hashes.len();
    let findings = detect(&DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    });
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
        findings,
        acquisition: AcquisitionMeta {
            source: "live_process".to_string(),
            pid: source.process().pid,
            hashed_regions,
            hashed_bytes,
            hash_budget_bytes: options.hash_budget_bytes,
            read_failures,
            region_truncated: false,
        },
    })
}

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
            regions: vec![
                mock_region(0x1000, 0x2000, true, true),
                mock_region(0x4000, 0x1000, false, true),
            ],
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

    #[test]
    fn collect_includes_findings_from_heuristics() {
        use xmem_core::Heuristic;
        let mut source = mock_source();
        source.regions[0].heuristics = vec![Heuristic::ExecutablePrivate];
        let envelope = collect(&source, &CollectOptions::default(), &no_cancel()).unwrap();
        assert!(
            envelope
                .findings
                .iter()
                .any(|finding| finding.rule_id == "XMEM-001")
        );
    }
}
