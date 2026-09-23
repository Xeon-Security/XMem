use xmem_core::{Finding, MemorySource, Result};

use crate::rules::{DetectionContext, detect};

/// MemorySource에서 관찰 데이터를 모아 detection을 실행한다.
pub fn detect_source<S: MemorySource>(source: &S) -> Result<Vec<Finding>> {
    let regions = source.regions()?;
    let modules = source.modules()?;
    let threads = source.threads()?;
    Ok(detect(&DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        Heuristic, MemoryRegion, MemorySource, MemoryState, MemoryType, ModuleInfo, ProcessArch,
        ProcessInfo, Protection, ReadOutcome, RegionClass, Result, ThreadInfo, XmemError,
    };

    struct MockSource {
        info: ProcessInfo,
        regions: Vec<MemoryRegion>,
    }

    impl MemorySource for MockSource {
        fn process(&self) -> &ProcessInfo {
            &self.info
        }
        fn regions(&self) -> Result<Vec<MemoryRegion>> {
            Ok(self.regions.clone())
        }
        fn read(&self, address: u64, _buf: &mut [u8]) -> Result<ReadOutcome> {
            Err(XmemError::InvalidAddress { address })
        }
        fn modules(&self) -> Result<Vec<ModuleInfo>> {
            Ok(Vec::new())
        }
        fn threads(&self) -> Result<Vec<ThreadInfo>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn detect_source_reads_metadata_and_skips_unknown_modules() {
        let source = MockSource {
            info: ProcessInfo {
                pid: 77,
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
            },
            regions: vec![MemoryRegion {
                base: 0x1000,
                size: 0x1000,
                allocation_base: Some(0x1000),
                state: MemoryState::Commit,
                protection: Protection::new(0x40, true, true, true),
                allocation_protection: None,
                region_type: Some(MemoryType::Private),
                readable: true,
                writable: true,
                executable: true,
                classification: RegionClass::Private,
                heuristics: vec![Heuristic::ExecutablePrivate],
                mapped_file: None,
            }],
        };
        let findings = detect_source(&source).unwrap();
        assert!(findings.iter().any(|finding| finding.rule_id == "XMEM-001"));
        assert!(!findings.iter().any(|finding| finding.rule_id == "XMEM-003"));
    }
}
