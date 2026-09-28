use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;

use xmem_core::{
    MemoryRegion, MemorySource, MemoryState, Protection, RegionClass, Result, ScanPattern,
    XmemError,
};

/// 기본 청크 크기 1 MiB.
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
/// 최소 청크 크기 4 KiB.
pub const MIN_CHUNK_SIZE: usize = 4 * 1024;
/// 최대 청크 크기 16 MiB.
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// 기본 최대 결과 수. 0이면 무제한.
pub const DEFAULT_MAX_RESULTS: usize = 1024;
/// 스캔 worker 최대 수.
pub const MAX_THREADS: usize = 64;
/// 이 값보다 큰 committed 메모리를 가진 프로세스는 기본 정책으로 축소 스캔한다.
pub const HUGE_COMMIT_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024;

const PAGE_GUARD_BIT: u32 = 0x100;

/// 스캔 대상 region 필터.
#[derive(Debug, Clone, Default)]
pub struct RegionFilters {
    pub executable_only: bool,
    pub private_only: bool,
    pub writable_only: bool,
    pub range: Option<(u64, u64)>,
    pub max_region_size: Option<u64>,
    pub all: bool,
}

/// 스캔 동작 옵션.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub filters: RegionFilters,
    pub chunk_size: usize,
    pub threads: usize,
    pub max_results: usize,
    pub offset: Option<u64>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            filters: RegionFilters::default(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            threads: 1,
            max_results: DEFAULT_MAX_RESULTS,
            offset: None,
        }
    }
}

/// 패턴 매치 1건.
#[derive(Debug, Clone, Serialize)]
pub struct ScanMatch {
    pub address: u64,
    pub region_base: u64,
    pub region_size: u64,
    pub offset: u64,
    pub class: RegionClass,
    pub protection: Protection,
    pub mapped_file: Option<String>,
}

/// 스캔 자원 사용 통계.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ScanStats {
    pub regions_total: usize,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub bytes_scanned: u64,
    pub read_failures: u64,
    /// 읽기 실패 사유별 집계(AccessDenied).
    pub access_denied: u64,
    /// 읽기 실패 사유별 집계(InvalidAddress).
    pub invalid_address: u64,
    /// 그 외 읽기 실패(0바이트 읽기 포함).
    pub other_failures: u64,
    pub partial_reads: u64,
    pub matches: usize,
    pub threads: usize,
    pub elapsed_ms: u64,
    pub rss_bytes: u64,
}

/// 스캔 결과 보고서.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub matches: Vec<ScanMatch>,
    pub stats: ScanStats,
    pub cancelled: bool,
    pub truncated: bool,
    pub policy_restricted: bool,
}

/// 스캔 진행 상황 카운터. CLI/GUI가 `Arc`로 공유해 폴링한다.
///
/// `regions_total`은 스캔 시작 시 선택된 영역 수로 갱신된다(호출자는 미리
/// 알 수 없으므로 0으로 만들어도 된다). 영역 1개를 끝낼 때마다(성공·실패·
/// 0바이트 모두) `regions_done`이 1씩 증가한다.
#[derive(Debug, Default)]
pub struct ScanProgress {
    regions_done: AtomicUsize,
    regions_total: AtomicUsize,
    bytes_scanned: AtomicU64,
}

impl ScanProgress {
    pub fn new(regions_total: usize) -> Self {
        Self {
            regions_done: AtomicUsize::new(0),
            regions_total: AtomicUsize::new(regions_total),
            bytes_scanned: AtomicU64::new(0),
        }
    }

    /// 완료한 영역 수.
    pub fn regions_done(&self) -> usize {
        self.regions_done.load(Ordering::Relaxed)
    }

    /// 스캔 대상 영역 수(시작 전에는 `new`에 준 값).
    pub fn regions_total(&self) -> usize {
        self.regions_total.load(Ordering::Relaxed)
    }

    /// 회수한 바이트 수.
    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned.load(Ordering::Relaxed)
    }

    /// 진행률 0.0~1.0. 전체 영역이 0이면 0.0.
    pub fn fraction(&self) -> f32 {
        let total = self.regions_total();
        if total == 0 {
            0.0
        } else {
            (self.regions_done() as f32 / total as f32).min(1.0)
        }
    }
}

#[derive(Debug, Default)]
struct RegionScan {
    matches: Vec<ScanMatch>,
    bytes: u64,
    access_denied: u64,
    invalid_address: u64,
    other_failures: u64,
    partials: u64,
    attempted: bool,
}

/// 스캔 대상 region 인덱스와 huge 정책 적용 여부를 고른다.
fn select_regions(regions: &[MemoryRegion], filters: &RegionFilters) -> (Vec<usize>, bool) {
    let committed_total: u64 = regions
        .iter()
        .filter(|r| r.state == MemoryState::Commit)
        .map(|r| r.size)
        .fold(0u64, u64::saturating_add);
    let huge = !filters.all && committed_total > HUGE_COMMIT_THRESHOLD;
    let mut selected = Vec::new();
    for (index, r) in regions.iter().enumerate() {
        if r.state != MemoryState::Commit || !r.readable || r.protection.raw & PAGE_GUARD_BIT != 0 {
            continue;
        }
        if filters.executable_only && !r.executable {
            continue;
        }
        if filters.private_only && r.classification != RegionClass::Private {
            continue;
        }
        if filters.writable_only && !r.writable {
            continue;
        }
        if let Some((start, end)) = filters.range
            && (r.base.saturating_add(r.size) <= start || r.base >= end)
        {
            continue;
        }
        if let Some(max) = filters.max_region_size
            && r.size > max
        {
            continue;
        }
        if huge && !(r.executable || r.classification == RegionClass::Private) {
            continue;
        }
        selected.push(index);
    }
    (selected, huge)
}

fn accept(found: &AtomicUsize, max_results: usize) -> bool {
    let old = found.fetch_add(1, Ordering::SeqCst);
    max_results == 0 || old < max_results
}

#[allow(clippy::too_many_arguments)]
fn scan_region<S: MemorySource + Sync>(
    source: &S,
    region: &MemoryRegion,
    pattern: &ScanPattern,
    chunk: usize,
    overlap: usize,
    offset_filter: Option<u64>,
    max_results: usize,
    cancel: &AtomicBool,
    stop: &AtomicBool,
    budget_hit: &AtomicBool,
    found: &AtomicUsize,
    progress: Option<&ScanProgress>,
    buf: &mut [u8],
) -> RegionScan {
    let mut out = RegionScan::default();
    if cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
        return out;
    }
    out.attempted = true;
    // 전역 예산 + 1: 초과 1건을 관측해야 truncated를 정직하게 보고할 수 있다.
    let limit = if max_results == 0 {
        usize::MAX
    } else {
        max_results.saturating_add(1)
    };
    let mut off: u64 = 0;
    while off < region.size {
        if cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
            break;
        }
        let end = (off + chunk as u64).min(region.size);
        let read_end = (end + overlap as u64).min(region.size);
        let read_len = (read_end - off) as usize;
        let addr = region.base + off;
        match source.read(addr, &mut buf[..read_len]) {
            Ok(outcome) if outcome.bytes_read > 0 => {
                out.bytes += outcome.bytes_read as u64;
                if outcome.partial {
                    out.partials += 1;
                }
                let hay = &buf[..outcome.bytes_read.min(read_len)];
                for pos in pattern.pattern.find_in(hay, limit) {
                    let abs = addr + pos as u64;
                    let rel = abs - region.base;
                    if offset_filter.is_some_and(|want| want != rel) {
                        continue;
                    }
                    if !accept(found, max_results) {
                        budget_hit.store(true, Ordering::SeqCst);
                        stop.store(true, Ordering::SeqCst);
                        // 아래 while 상단의 stop 검사로 빠져나가 진행 카운터를 남긴다.
                        break;
                    }
                    out.matches.push(ScanMatch {
                        address: abs,
                        region_base: region.base,
                        region_size: region.size,
                        offset: rel,
                        class: region.classification,
                        protection: region.protection,
                        mapped_file: region.mapped_file.clone(),
                    });
                }
            }
            Ok(_) => out.other_failures += 1,
            Err(XmemError::AccessDenied { .. }) => out.access_denied += 1,
            Err(XmemError::InvalidAddress { .. }) => out.invalid_address += 1,
            Err(_) => out.other_failures += 1,
        }
        off = end;
    }
    if let Some(progress) = progress {
        progress.regions_done.fetch_add(1, Ordering::Relaxed);
        progress
            .bytes_scanned
            .fetch_add(out.bytes, Ordering::Relaxed);
    }
    out
}

/// 진행 카운터를 받는 스캔. `progress`가 None이면 `scan`과 동일하다.
pub fn scan_with_progress<S: MemorySource + Sync>(
    source: &S,
    pattern: &ScanPattern,
    options: &ScanOptions,
    cancel: &AtomicBool,
    progress: Option<&ScanProgress>,
) -> Result<ScanReport> {
    let started = Instant::now();
    let all_regions = source.regions()?;
    let regions_total = all_regions.len();
    let (selected, policy_restricted) = select_regions(&all_regions, &options.filters);
    if let Some(progress) = progress {
        progress
            .regions_total
            .store(selected.len(), Ordering::Relaxed);
    }
    let chunk = options.chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE);
    let threads = options.threads.clamp(1, MAX_THREADS);
    let overlap = pattern.pattern.len().saturating_sub(1);
    let buf_len = chunk + overlap;
    let stop = AtomicBool::new(false);
    let budget_hit = AtomicBool::new(false);
    let found = AtomicUsize::new(0);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| XmemError::InvalidInput {
            reason: format!("스레드 풀 생성 실패: {e}"),
        })?;

    let results: Vec<RegionScan> = pool.install(|| {
        selected
            .par_iter()
            .map_init(
                || vec![0u8; buf_len],
                |buf, &index| {
                    scan_region(
                        source,
                        &all_regions[index],
                        pattern,
                        chunk,
                        overlap,
                        options.offset,
                        options.max_results,
                        cancel,
                        &stop,
                        &budget_hit,
                        &found,
                        progress,
                        buf,
                    )
                },
            )
            .collect()
    });

    let regions_scanned = results.iter().filter(|r| r.attempted).count();
    let bytes_scanned = results.iter().map(|r| r.bytes).sum();
    let access_denied: u64 = results.iter().map(|r| r.access_denied).sum();
    let invalid_address: u64 = results.iter().map(|r| r.invalid_address).sum();
    let other_failures: u64 = results.iter().map(|r| r.other_failures).sum();
    let read_failures = access_denied + invalid_address + other_failures;
    let partial_reads = results.iter().map(|r| r.partials).sum();
    let matches: Vec<ScanMatch> = results.into_iter().flat_map(|r| r.matches).collect();

    let stats = ScanStats {
        regions_total,
        regions_scanned,
        regions_skipped: regions_total.saturating_sub(regions_scanned),
        bytes_scanned,
        read_failures,
        access_denied,
        invalid_address,
        other_failures,
        partial_reads,
        matches: matches.len(),
        threads,
        elapsed_ms: started.elapsed().as_millis() as u64,
        rss_bytes: xmem_windows::current_rss_bytes().unwrap_or(0),
    };
    Ok(ScanReport {
        matches,
        stats,
        cancelled: cancel.load(Ordering::Relaxed),
        truncated: budget_hit.load(Ordering::Relaxed),
        policy_restricted,
    })
}

/// chunked 읽기 + bounded 병렬 스캔. 취소 시 부분 결과를 반환한다.
pub fn scan<S: MemorySource + Sync>(
    source: &S,
    pattern: &ScanPattern,
    options: &ScanOptions,
    cancel: &AtomicBool,
) -> Result<ScanReport> {
    scan_with_progress(source, pattern, options, cancel, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use xmem_core::{
        MemoryType, ModuleInfo, ProcessArch, ProcessInfo, ReadOutcome, ThreadInfo, classify,
        heuristics,
    };

    const PAGE_RW: u32 = 0x04;
    const PAGE_RWX: u32 = 0x40;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    fn decode(protect: u32) -> (bool, bool, bool) {
        match protect {
            PAGE_RWX => (true, true, true),
            PAGE_RW => (true, true, false),
            PAGE_EXECUTE_READ => (true, false, true),
            _ => (false, false, false),
        }
    }

    fn make_region(base: u64, size: u64, protect: u32, ty: MemoryType) -> MemoryRegion {
        let state = MemoryState::Commit;
        let (readable, writable, executable) = decode(protect);
        let p = Protection::new(protect, readable, writable, executable);
        MemoryRegion {
            base,
            size,
            allocation_base: Some(base),
            state,
            protection: p,
            allocation_protection: None,
            region_type: Some(ty),
            readable,
            writable,
            executable,
            classification: classify(state, Some(ty)),
            heuristics: heuristics(state, &p, Some(ty)),
            mapped_file: None,
        }
    }

    /// 주입한 실패 종류. `other`는 PartialRead로 대표한다.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FailKind {
        AccessDenied,
        InvalidAddress,
        Other,
    }

    struct MockSource {
        info: ProcessInfo,
        regions: Vec<MemoryRegion>,
        content: BTreeMap<u64, Vec<u8>>,
        fail: Vec<(u64, FailKind)>,
    }

    impl MockSource {
        fn new(regions: Vec<MemoryRegion>, content: BTreeMap<u64, Vec<u8>>) -> Self {
            Self {
                info: ProcessInfo {
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
                },
                regions,
                content,
                fail: Vec::new(),
            }
        }
    }

    impl MemorySource for MockSource {
        fn process(&self) -> &ProcessInfo {
            &self.info
        }

        fn regions(&self) -> Result<Vec<MemoryRegion>> {
            Ok(self.regions.clone())
        }

        fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
            if let Some((_, kind)) = self.fail.iter().find(|(addr, _)| *addr == address) {
                return Err(match kind {
                    FailKind::AccessDenied => XmemError::AccessDenied {
                        context: "mock failure".to_string(),
                    },
                    FailKind::InvalidAddress => XmemError::InvalidAddress { address },
                    FailKind::Other => XmemError::PartialRead {
                        address,
                        requested: buf.len(),
                        read: 0,
                    },
                });
            }
            let Some(region) = self
                .regions
                .iter()
                .find(|r| address >= r.base && address < r.base + r.size)
            else {
                return Err(XmemError::InvalidAddress { address });
            };
            let Some(data) = self.content.get(&region.base) else {
                return Err(XmemError::PartialRead {
                    address,
                    requested: buf.len(),
                    read: 0,
                });
            };
            let start = (address - region.base) as usize;
            if start >= data.len() {
                return Err(XmemError::PartialRead {
                    address,
                    requested: buf.len(),
                    read: 0,
                });
            }
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            Ok(ReadOutcome {
                bytes_read: n,
                partial: n < buf.len(),
            })
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

    fn pattern() -> ScanPattern {
        ScanPattern::hex("41 42 43 44").unwrap()
    }

    fn no_cancel() -> AtomicBool {
        AtomicBool::new(false)
    }

    #[test]
    fn progress_counts_regions_and_bytes() {
        let a = make_region(0x1000_0000, 0x2000, PAGE_RW, MemoryType::Private);
        let b = make_region(0x2000_0000, 0x2000, PAGE_RW, MemoryType::Private);
        let mut content = BTreeMap::new();
        content.insert(a.base, vec![0x41u8; 0x100]);
        content.insert(b.base, vec![0x42u8; 0x100]);
        let source = MockSource::new(vec![a, b], content);
        let progress = ScanProgress::new(0);

        let report = scan_with_progress(
            &source,
            &pattern(),
            &ScanOptions::default(),
            &no_cancel(),
            Some(&progress),
        )
        .unwrap();

        assert_eq!(report.stats.regions_scanned, 2);
        assert_eq!(progress.regions_done(), 2);
        assert_eq!(progress.regions_total(), 2);
        assert_eq!(progress.fraction(), 1.0);
        assert!(progress.bytes_scanned() > 0);
    }

    #[test]
    fn progress_is_monotone_with_parallel_scan() {
        let regions: Vec<MemoryRegion> = (0..4u64)
            .map(|i| {
                make_region(
                    0x1000_0000 + i * 0x10000,
                    0x1000,
                    PAGE_RW,
                    MemoryType::Private,
                )
            })
            .collect();
        let mut content = BTreeMap::new();
        for region in &regions {
            content.insert(region.base, vec![0u8; 0x100]);
        }
        let source = MockSource::new(regions, content);
        let options = ScanOptions {
            threads: 2,
            ..ScanOptions::default()
        };
        let progress = ScanProgress::new(0);

        scan_with_progress(&source, &pattern(), &options, &no_cancel(), Some(&progress)).unwrap();

        assert_eq!(progress.regions_done(), 4);
        assert_eq!(progress.regions_total(), 4);
        assert_eq!(progress.fraction(), 1.0);
    }

    #[test]
    fn progress_zero_total_is_safe() {
        let source = MockSource::new(Vec::new(), BTreeMap::new());
        let progress = ScanProgress::new(0);

        scan_with_progress(
            &source,
            &pattern(),
            &ScanOptions::default(),
            &no_cancel(),
            Some(&progress),
        )
        .unwrap();

        assert_eq!(progress.regions_total(), 0);
        assert_eq!(progress.fraction(), 0.0);
    }

    #[test]
    fn finds_pattern_in_single_region() {
        let region = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut data = vec![0u8; 0x100];
        data[0x10..0x14].copy_from_slice(b"ABCD");
        data[0x80..0x84].copy_from_slice(b"ABCD");
        let mut content = BTreeMap::new();
        content.insert(region.base, data);
        let source = MockSource::new(vec![region], content);

        let report = scan(&source, &pattern(), &ScanOptions::default(), &no_cancel()).unwrap();

        assert_eq!(report.matches.len(), 2);
        assert_eq!(report.matches[0].address, 0x1000_0010);
        assert_eq!(report.matches[0].offset, 0x10);
        assert_eq!(report.matches[1].address, 0x1000_0080);
        assert_eq!(report.matches[0].region_base, 0x1000_0000);
        assert_eq!(report.matches[0].class, RegionClass::Private);
        assert!(!report.cancelled);
        assert!(!report.truncated);
        assert!(!report.policy_restricted);
        assert_eq!(report.stats.matches, 2);
        assert_eq!(report.stats.regions_scanned, 1);
    }

    #[test]
    fn match_across_chunk_boundary() {
        let region = make_region(0x2000_0000, 0x2000, PAGE_RW, MemoryType::Private);
        let mut data = vec![0u8; 0x2000];
        data[0x0FFE..0x1002].copy_from_slice(b"ABCD");
        let mut content = BTreeMap::new();
        content.insert(region.base, data);
        let source = MockSource::new(vec![region], content);
        let options = ScanOptions {
            chunk_size: 4096,
            ..ScanOptions::default()
        };

        let report = scan(&source, &pattern(), &options, &no_cancel()).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].offset, 0x0FFE);
    }

    #[test]
    fn offset_filter_matches_only_exact_offset() {
        let region = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut data = vec![0u8; 0x100];
        data[0x10..0x14].copy_from_slice(b"ABCD");
        data[0x80..0x84].copy_from_slice(b"ABCD");
        let mut content = BTreeMap::new();
        content.insert(region.base, data);
        let source = MockSource::new(vec![region], content);
        let options = ScanOptions {
            offset: Some(0x80),
            ..ScanOptions::default()
        };

        let report = scan(&source, &pattern(), &options, &no_cancel()).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].offset, 0x80);
    }

    #[test]
    fn filters_select_regions() {
        let regions = vec![
            make_region(0x1000_0000, 0x1000, PAGE_RWX, MemoryType::Private),
            make_region(0x2000_0000, 0x1000, PAGE_EXECUTE_READ, MemoryType::Image),
            make_region(0x3000_0000, 0x1000, PAGE_RW, MemoryType::Private),
        ];
        let source = MockSource::new(regions, BTreeMap::new());

        let exec_only = ScanOptions {
            filters: RegionFilters {
                executable_only: true,
                ..RegionFilters::default()
            },
            ..ScanOptions::default()
        };
        let report = scan(&source, &pattern(), &exec_only, &no_cancel()).unwrap();
        assert_eq!(report.stats.regions_scanned, 2);

        let private_only = ScanOptions {
            filters: RegionFilters {
                private_only: true,
                ..RegionFilters::default()
            },
            ..ScanOptions::default()
        };
        let report = scan(&source, &pattern(), &private_only, &no_cancel()).unwrap();
        assert_eq!(report.stats.regions_scanned, 2);

        let writable_only = ScanOptions {
            filters: RegionFilters {
                writable_only: true,
                ..RegionFilters::default()
            },
            ..ScanOptions::default()
        };
        let report = scan(&source, &pattern(), &writable_only, &no_cancel()).unwrap();
        assert_eq!(report.stats.regions_scanned, 2);
    }

    #[test]
    fn range_filter_limits_regions() {
        let regions = vec![
            make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private),
            make_region(0x2000_0000, 0x1000, PAGE_RW, MemoryType::Private),
            make_region(0x3000_0000, 0x1000, PAGE_RW, MemoryType::Private),
        ];
        let source = MockSource::new(regions, BTreeMap::new());
        let options = ScanOptions {
            filters: RegionFilters {
                range: Some((0x2000_0000, 0x3000_0000)),
                ..RegionFilters::default()
            },
            ..ScanOptions::default()
        };

        let report = scan(&source, &pattern(), &options, &no_cancel()).unwrap();

        assert_eq!(report.stats.regions_scanned, 1);
    }

    #[test]
    fn max_region_size_skips_large_region() {
        let regions = vec![make_region(
            0x1000_0000,
            0x8000,
            PAGE_RW,
            MemoryType::Private,
        )];
        let source = MockSource::new(regions, BTreeMap::new());
        let options = ScanOptions {
            filters: RegionFilters {
                max_region_size: Some(0x1000),
                ..RegionFilters::default()
            },
            ..ScanOptions::default()
        };

        let report = scan(&source, &pattern(), &options, &no_cancel()).unwrap();

        assert_eq!(report.stats.regions_scanned, 0);
        assert_eq!(report.stats.regions_skipped, 1);
    }

    #[test]
    fn huge_process_policy_restricts_unless_all() {
        let regions = vec![
            make_region(
                0x1_0000_0000,
                2 * 1024 * 1024 * 1024,
                PAGE_RWX,
                MemoryType::Private,
            ),
            make_region(
                0x2_0000_0000,
                3 * 1024 * 1024 * 1024,
                PAGE_RW,
                MemoryType::Image,
            ),
        ];
        let source = MockSource::new(regions, BTreeMap::new());

        let report = scan(&source, &pattern(), &ScanOptions::default(), &no_cancel()).unwrap();
        assert!(report.policy_restricted);
        assert_eq!(report.stats.regions_scanned, 1);

        let options = ScanOptions {
            filters: RegionFilters {
                all: true,
                ..RegionFilters::default()
            },
            ..ScanOptions::default()
        };
        let report = scan(&source, &pattern(), &options, &no_cancel()).unwrap();
        assert!(!report.policy_restricted);
        assert_eq!(report.stats.regions_scanned, 2);
    }

    #[test]
    fn read_failures_counted_and_scan_continues() {
        let a = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let b = make_region(0x2000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut content = BTreeMap::new();
        content.insert(a.base, vec![0u8; 0x100]);
        let mut data = vec![0u8; 0x100];
        data[0x40..0x44].copy_from_slice(b"ABCD");
        content.insert(b.base, data);
        let mut source = MockSource::new(vec![a.clone(), b], content);
        source.fail.push((a.base, FailKind::AccessDenied));

        let report = scan(&source, &pattern(), &ScanOptions::default(), &no_cancel()).unwrap();

        assert!(report.stats.read_failures >= 1);
        assert_eq!(report.stats.access_denied, 1);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].region_base, 0x2000_0000);
    }

    #[test]
    fn read_failures_counted_by_reason() {
        let a = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let b = make_region(0x2000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let c = make_region(0x3000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut source = MockSource::new(vec![a.clone(), b.clone(), c.clone()], BTreeMap::new());
        source.fail = vec![
            (a.base, FailKind::AccessDenied),
            (b.base, FailKind::InvalidAddress),
            (c.base, FailKind::Other),
        ];

        let report = scan(&source, &pattern(), &ScanOptions::default(), &no_cancel()).unwrap();

        assert_eq!(report.stats.access_denied, 1);
        assert_eq!(report.stats.invalid_address, 1);
        assert_eq!(report.stats.other_failures, 1);
        assert_eq!(report.stats.read_failures, 3);
        assert!(report.matches.is_empty());
    }

    #[test]
    fn cancel_flag_stops_scan() {
        let region = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut data = vec![0u8; 0x100];
        data[0x10..0x14].copy_from_slice(b"ABCD");
        let mut content = BTreeMap::new();
        content.insert(region.base, data);
        let source = MockSource::new(vec![region], content);
        let cancel = AtomicBool::new(true);

        let report = scan(&source, &pattern(), &ScanOptions::default(), &cancel).unwrap();

        assert!(report.cancelled);
        assert_eq!(report.stats.regions_scanned, 0);
        assert!(report.matches.is_empty());
    }

    #[test]
    fn max_results_caps_and_reports_truncated() {
        let region = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut data = vec![0u8; 0x100];
        for off in [0x10usize, 0x20, 0x30, 0x40, 0x50] {
            data[off..off + 4].copy_from_slice(b"ABCD");
        }
        let mut content = BTreeMap::new();
        content.insert(region.base, data);
        let source = MockSource::new(vec![region], content);
        let options = ScanOptions {
            max_results: 3,
            ..ScanOptions::default()
        };

        let report = scan(&source, &pattern(), &options, &no_cancel()).unwrap();

        assert_eq!(report.matches.len(), 3);
        assert!(report.truncated);
    }

    #[test]
    fn partial_read_scans_returned_bytes() {
        let region = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut content = BTreeMap::new();
        content.insert(region.base, b"ABCD".to_vec());
        let source = MockSource::new(vec![region], content);

        let report = scan(&source, &pattern(), &ScanOptions::default(), &no_cancel()).unwrap();

        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].address, 0x1000_0000);
        assert_eq!(report.stats.partial_reads, 1);
    }

    #[test]
    fn non_readable_and_guard_regions_skipped() {
        let normal = make_region(0x1000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        let mut non_readable = make_region(0x2000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        non_readable.readable = false;
        let mut guard = make_region(0x3000_0000, 0x1000, PAGE_RW, MemoryType::Private);
        guard.protection.raw |= 0x100;
        let source = MockSource::new(vec![normal, non_readable, guard], BTreeMap::new());

        let report = scan(&source, &pattern(), &ScanOptions::default(), &no_cancel()).unwrap();

        assert_eq!(report.stats.regions_scanned, 1);
        assert_eq!(report.stats.regions_skipped, 2);
    }
}
