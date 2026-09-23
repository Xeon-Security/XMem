use xmem_core::{
    MemoryRegion, MemorySource, ModuleInfo, ProcessInfo, ReadOutcome, Result, ThreadInfo, XmemError,
};
use xmem_windows::{OwnedHandle, memory, open_for_query, open_for_read, process_info};

#[derive(Debug, Clone)]
pub struct RegionMap {
    pub regions: Vec<MemoryRegion>,
    pub truncated: bool,
}

/// 실행 중 프로세스. handle은 RAII로 닫힌다.
#[derive(Debug)]
pub struct LiveProcess {
    pub pid: u32,
    pub handle: OwnedHandle,
    pub info: ProcessInfo,
}

impl LiveProcess {
    pub fn open(pid: u32) -> Result<Self> {
        let info = process_info(pid)?;
        // scan에는 VM_READ가 필요하다. VM_READ가 거부되면 QUERY 전용 핸들로
        // fallback한다(이 경우 memory map은 동작하지만 read는 AccessDenied).
        let handle = match open_for_read(pid) {
            Ok(handle) => handle,
            Err(XmemError::AccessDenied { .. }) => open_for_query(pid)?,
            Err(err) => return Err(err),
        };
        Ok(Self { pid, handle, info })
    }

    /// VirtualQueryEx walk + 매핑 파일 이름 조회. 버퍼는 1회 할당 후 재사용한다.
    pub fn region_map(&self) -> Result<RegionMap> {
        let walk = memory::walk_regions(
            &self.handle,
            memory::native_max_user_address(),
            memory::MAX_REGIONS,
        )?;
        let mut regions = Vec::with_capacity(walk.regions.len());
        let mut buf = vec![0u16; 32 * 1024];
        for raw in &walk.regions {
            let mapped_file = if memory::is_file_backed(raw) {
                memory::mapped_file_name(&self.handle, raw.base, &mut buf)
            } else {
                None
            };
            match memory::region_from_raw(raw, mapped_file) {
                Some(region) => regions.push(region),
                None => tracing::warn!(
                    base = format_args!("{:#x}", raw.base),
                    state = raw.state,
                    "알 수 없는 memory state, 영역 건너뜀"
                ),
            }
        }
        Ok(RegionMap {
            regions,
            truncated: walk.truncated,
        })
    }
}

impl MemorySource for LiveProcess {
    fn process(&self) -> &ProcessInfo {
        &self.info
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>> {
        Ok(self.region_map()?.regions)
    }

    fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
        match xmem_windows::read::read_process_memory(&self.handle, address, buf) {
            Ok(bytes_read) => Ok(ReadOutcome {
                bytes_read,
                partial: bytes_read < buf.len(),
            }),
            Err(XmemError::PartialRead { read, .. }) => Ok(ReadOutcome {
                bytes_read: read,
                partial: true,
            }),
            Err(err) => Err(err),
        }
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Err(XmemError::Unimplemented {
            feature: "module enumeration",
        })
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Err(XmemError::Unimplemented {
            feature: "thread enumeration",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_self_and_map_regions() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let map = live.region_map().unwrap();
        assert!(!map.regions.is_empty());
        assert!(map.regions.iter().all(|r| r.size > 0));
        assert!(
            map.regions
                .iter()
                .any(|r| r.classification == xmem_core::RegionClass::Image)
        );
        assert!(
            map.regions
                .iter()
                .all(|r| r.mapped_file.is_none() || r.region_type.is_some())
        );
        assert!(
            map.regions
                .iter()
                .filter(|r| r.classification == xmem_core::RegionClass::Free)
                .all(|r| r.region_type.is_none())
        );
    }

    #[test]
    fn open_bogus_pid_fails_structured() {
        let err = LiveProcess::open(0xFFFF_FFFE).unwrap_err();
        assert!(matches!(err, XmemError::ProcessExited { .. }));
    }

    #[test]
    fn memory_source_impl_matches_region_map() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        // 라이브 map은 호출 간 변할 수 있으므로(테스트 프로세스의 동시 할당) 개수 동일성은 요구하지 않는다.
        let direct = live.region_map().unwrap();
        let via_trait = live.regions().unwrap();
        assert!(!direct.regions.is_empty());
        assert!(!via_trait.is_empty());
        assert_eq!(live.process().pid, xmem_windows::current_pid());
    }

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

    #[test]
    fn unimplemented_methods_are_explicit() {
        let live = LiveProcess::open(xmem_windows::current_pid()).unwrap();
        assert!(matches!(
            live.modules().unwrap_err(),
            XmemError::Unimplemented { .. }
        ));
        assert!(matches!(
            live.threads().unwrap_err(),
            XmemError::Unimplemented { .. }
        ));
    }
}
