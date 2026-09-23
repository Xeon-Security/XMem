//! 데이터 출처 추상화: LiveProcess / Snapshot / Minidump / MemoryImage.
use crate::error::Result;
use crate::model::{MemoryRegion, ModuleInfo, ProcessInfo, ThreadInfo};

/// 읽기 결과. Partial Read는 오류가 아니라 정상 결과로 반환한다.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_object_safe(_: &dyn MemorySource) {}
}
