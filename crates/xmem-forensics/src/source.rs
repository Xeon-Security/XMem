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
