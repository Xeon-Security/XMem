//! Minidump 파일 파싱과 MemorySource 구현.

use std::path::Path;

use minidump::Module as _;
use minidump::{
    Minidump, MinidumpMemoryInfoList, MinidumpMiscInfo, MinidumpModule, MinidumpModuleList,
    MinidumpSystemInfo, MinidumpThreadList, system_info::Cpu,
};
use xmem_core::{
    MemoryRegion, MemorySource, MemoryState, MemoryType, ModuleInfo, ProcessArch, ProcessInfo,
    Protection, ReadOutcome, Result, ThreadInfo, XmemError, classify, heuristics,
};

/// FILETIME(1601)과 Unix epoch(1970)의 100ns 단위 차이.
const EPOCH_DIFFERENCE_100NS: u64 = 116_444_736_000_000_000;

/// 덤프에서 수집한 오프라인 분석 결과.
#[derive(Debug, Clone)]
pub struct DumpAnalysis {
    pub path: String,
    pub os: String,
    pub cpu: String,
    pub arch: ProcessArch,
    pub process: ProcessInfo,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub regions: Vec<MemoryRegion>,
    pub memory_ranges: usize,
    pub memory_bytes: u64,
}

/// Minidump 파일을 MemorySource로 노출한다(Offline Forensics).
pub struct MinidumpSource {
    dump: minidump::MmapMinidump,
    path: String,
    os: String,
    cpu: String,
    info: ProcessInfo,
    modules: Vec<ModuleInfo>,
    threads: Vec<ThreadInfo>,
    regions: Vec<MemoryRegion>,
    memory_ranges: usize,
    memory_bytes: u64,
}

impl MinidumpSource {
    pub fn open(path: &Path) -> Result<Self> {
        let dump = Minidump::read_path(path).map_err(|e| dump_error(path, &e))?;

        let system = dump.get_stream::<MinidumpSystemInfo>().ok();
        let misc = dump.get_stream::<MinidumpMiscInfo>().ok();
        let (os, cpu, arch) = match &system {
            Some(s) => (
                format!("{:?}", s.os),
                format!("{:?}", s.cpu),
                arch_from_cpu(s.cpu),
            ),
            None => (
                "unknown".to_string(),
                "unknown".to_string(),
                ProcessArch::Unknown,
            ),
        };

        let modules: Vec<ModuleInfo> = dump
            .get_stream::<MinidumpModuleList>()
            .map(|list| list.iter().map(|m| module_from(m, arch)).collect())
            .unwrap_or_default();

        let regions: Vec<MemoryRegion> = dump
            .get_stream::<MinidumpMemoryInfoList>()
            .map(|list| {
                list.iter()
                    .filter_map(|info| region_from_info(info, &modules))
                    .collect()
            })
            .unwrap_or_default();

        let (pid, creation_time) = misc_info(misc.as_ref());
        // minidump에는 실측 start address가 없어 컨텍스트의 instruction pointer를 근사값으로 쓴다.
        // 컨텍스트가 없는 덤프는 기존처럼 start_address None을 유지한다.
        let threads: Vec<ThreadInfo> = dump
            .get_stream::<MinidumpThreadList>()
            .map(|list| {
                list.threads
                    .iter()
                    .map(|t| {
                        let ip = system
                            .as_ref()
                            .and_then(|s| t.context(s, misc.as_ref()))
                            .map(|context| context.get_instruction_pointer())
                            .filter(|address| *address != 0);
                        ThreadInfo {
                            tid: t.raw.thread_id,
                            pid,
                            priority: None,
                            start_address: ip,
                            start_region_base: ip.and_then(|address| {
                                regions
                                    .iter()
                                    .find(|region| {
                                        address >= region.base
                                            && address < region.base.saturating_add(region.size)
                                    })
                                    .map(|region| region.base)
                            }),
                            start_module: ip.and_then(|address| {
                                modules
                                    .iter()
                                    .find(|module| {
                                        address >= module.base
                                            && address < module.base.saturating_add(module.size)
                                    })
                                    .map(|module| module.name.clone())
                            }),
                            start_address_source: ip.map(|_| "minidump-context-rip".to_string()),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let (memory_ranges, memory_bytes) = match dump.get_memory() {
            Some(memory) => {
                let mut count = 0usize;
                let mut bytes = 0u64;
                for region in memory.iter() {
                    count += 1;
                    bytes = bytes.saturating_add(region.size());
                }
                (count, bytes)
            }
            None => (0, 0),
        };

        let main_module = modules.first();
        let info = ProcessInfo {
            pid,
            ppid: None,
            name: main_module
                .map(|m| m.name.clone())
                .unwrap_or_else(|| file_name(path)),
            image_path: main_module.and_then(|m| m.path.clone()),
            arch,
            session_id: None,
            creation_time,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: Some(threads.len() as u32),
            module_count: Some(modules.len() as u32),
        };

        Ok(Self {
            dump,
            path: path.display().to_string(),
            os,
            cpu,
            info,
            modules,
            threads,
            regions,
            memory_ranges,
            memory_bytes,
        })
    }

    pub fn analysis(&self) -> DumpAnalysis {
        DumpAnalysis {
            path: self.path.clone(),
            os: self.os.clone(),
            cpu: self.cpu.clone(),
            arch: self.info.arch,
            process: self.info.clone(),
            modules: self.modules.clone(),
            threads: self.threads.clone(),
            regions: self.regions.clone(),
            memory_ranges: self.memory_ranges,
            memory_bytes: self.memory_bytes,
        }
    }
}

impl MemorySource for MinidumpSource {
    fn process(&self) -> &ProcessInfo {
        &self.info
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>> {
        Ok(self.regions.clone())
    }

    fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
        let Some(memory) = self.dump.get_memory() else {
            return Err(XmemError::DumpError {
                reason: "덤프에 메모리 스트림이 없습니다".to_string(),
            });
        };
        for region in memory.iter() {
            let base = region.base_address();
            let end = base.saturating_add(region.size());
            if address < base || address >= end {
                continue;
            }
            let start = (address - base) as usize;
            let bytes = region.bytes();
            let available = bytes.len().saturating_sub(start);
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            return Ok(ReadOutcome {
                bytes_read: n,
                partial: n < buf.len(),
            });
        }
        Err(XmemError::InvalidAddress { address })
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(self.modules.clone())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.threads.clone())
    }
}

pub fn analyze_dump(path: &Path) -> Result<DumpAnalysis> {
    Ok(MinidumpSource::open(path)?.analysis())
}

fn dump_error(path: &Path, e: &minidump::Error) -> XmemError {
    XmemError::DumpError {
        reason: format!("minidump 파싱 실패: {} ({e})", path.display()),
    }
}

fn misc_info(misc: Option<&MinidumpMiscInfo>) -> (u32, Option<u64>) {
    let Some(misc) = misc else {
        return (0, None);
    };
    let pid = misc.raw.process_id().copied().unwrap_or(0);
    let creation = misc.process_create_time().and_then(|t| {
        t.duration_since(std::time::SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| {
                d.as_secs()
                    .saturating_mul(10_000_000)
                    .saturating_add(EPOCH_DIFFERENCE_100NS)
            })
    });
    (pid, creation)
}

fn arch_from_cpu(cpu: Cpu) -> ProcessArch {
    match cpu {
        Cpu::X86_64 => ProcessArch::X64,
        Cpu::X86 => ProcessArch::X86,
        Cpu::Arm64 => ProcessArch::Arm64,
        _ => ProcessArch::Unknown,
    }
}

fn module_from(module: &MinidumpModule, arch: ProcessArch) -> ModuleInfo {
    let full = module.name.clone();
    let name = full
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(full.as_str())
        .to_string();
    ModuleInfo {
        name,
        base: module.base_address(),
        size: module.size(),
        path: Some(full),
        arch: Some(arch),
    }
}

fn region_from_info(
    info: &minidump::MinidumpMemoryInfo<'_>,
    modules: &[ModuleInfo],
) -> Option<MemoryRegion> {
    let raw = &info.raw;
    let state = match raw.state {
        0x1000 => MemoryState::Commit,
        0x2000 => MemoryState::Reserve,
        0x10000 => MemoryState::Free,
        _ => return None,
    };
    let region_type = match raw._type {
        0x0002_0000 => Some(MemoryType::Private),
        0x0004_0000 => Some(MemoryType::Mapped),
        0x0100_0000 => Some(MemoryType::Image),
        _ => None,
    };
    let protection = Protection::from_win32(raw.protection);
    let classification = classify(state, region_type);
    let heuristics = heuristics(state, &protection, region_type);
    let mapped_file = modules
        .iter()
        .find(|m| raw.base_address >= m.base && raw.base_address < m.base.saturating_add(m.size))
        .and_then(|m| m.path.clone());
    Some(MemoryRegion {
        base: raw.base_address,
        size: raw.region_size,
        allocation_base: (raw.allocation_base != 0).then_some(raw.allocation_base),
        state,
        protection,
        allocation_protection: if raw.allocation_protection != 0 {
            Some(Protection::from_win32(raw.allocation_protection))
        } else {
            None
        },
        region_type,
        readable: protection.readable,
        writable: protection.writable,
        executable: protection.executable,
        classification,
        heuristics,
        mapped_file,
    })
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn analyze_rejects_garbage_file() {
        let dir = std::env::temp_dir().join(format!("xmem-fx-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.dmp");
        std::fs::write(&path, b"not a minidump").unwrap();

        let err = analyze_dump(&path).unwrap_err();
        assert!(matches!(err, XmemError::DumpError { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
