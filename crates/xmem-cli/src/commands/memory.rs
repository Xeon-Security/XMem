use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use xmem_core::{MemoryRegion, ProcessInfo, RegionClass, Result, ScanPattern, XmemError};
use xmem_memory::{
    DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, LiveProcess, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    RegionFilters, RegionMap, ScanOptions, ScanReport, scan,
};

use crate::cli::{GlobalArgs, MemoryCmd, ScanArgs};
use crate::commands::render::{heur_short, human_size, truncate, truncate_tail};
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(cmd: &MemoryCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        MemoryCmd::Map(pid_arg) => {
            let live = LiveProcess::open(pid_arg.pid)?;
            let map = live.region_map()?;
            match resolve_mode(global.json) {
                OutputMode::Json => {
                    let value =
                        serde_json::to_value(json_payload(&live.info, &map)).map_err(|e| {
                            XmemError::JsonError {
                                reason: e.to_string(),
                            }
                        })?;
                    emit_json(&success_envelope(value));
                    Ok(())
                }
                OutputMode::Human => {
                    emit(&render_map(&map));
                    Ok(())
                }
            }
        }
        MemoryCmd::Scan(args) => run_scan(args, global),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MapSummary {
    pub(crate) total: usize,
    pub(crate) committed: usize,
    pub(crate) reserved: usize,
    pub(crate) free: usize,
    pub(crate) image: usize,
    pub(crate) mapped: usize,
    pub(crate) private: usize,
    pub(crate) executable: usize,
    pub(crate) heuristics: usize,
    pub(crate) committed_bytes: u64,
}

pub(crate) fn summarize(regions: &[MemoryRegion]) -> MapSummary {
    let mut s = MapSummary::default();
    for r in regions {
        s.total += 1;
        match r.classification {
            RegionClass::Image => {
                s.image += 1;
                s.committed += 1;
            }
            RegionClass::Mapped => {
                s.mapped += 1;
                s.committed += 1;
            }
            RegionClass::Private => {
                s.private += 1;
                s.committed += 1;
            }
            RegionClass::Free => s.free += 1,
            RegionClass::Reserved => s.reserved += 1,
            RegionClass::Unknown => {}
        }
        if r.classification != RegionClass::Free && r.classification != RegionClass::Reserved {
            s.committed_bytes = s.committed_bytes.saturating_add(r.size);
        }
        if r.executable {
            s.executable += 1;
        }
        s.heuristics += r.heuristics.len();
    }
    s
}

fn heur_list(region: &MemoryRegion) -> String {
    if region.heuristics.is_empty() {
        return "-".to_string();
    }
    region
        .heuristics
        .iter()
        .map(|h| heur_short(*h))
        .collect::<Vec<_>>()
        .join(",")
}

fn render_map(map: &RegionMap) -> String {
    let mut out = String::new();
    out.push_str(
        "BASE               SIZE       STATE       TYPE        PROTECTION     CLASS      HEURISTICS     MAPPED FILE\n",
    );
    for r in &map.regions {
        let ty = match r.region_type {
            Some(t) => t.to_string(),
            None => "-".to_string(),
        };
        let mapped = match &r.mapped_file {
            Some(p) => truncate_tail(p, 48),
            None => "-".to_string(),
        };
        out.push_str(&format!(
            "0x{:016x} {:>10} {:11} {:11} {:14} {:10} {:14} {}\n",
            r.base,
            human_size(r.size),
            r.state.to_string(),
            ty,
            r.protection.to_string(),
            r.classification.to_string(),
            heur_list(r),
            mapped,
        ));
    }
    let s = summarize(&map.regions);
    out.push_str(&format!(
        "{} regions: committed {} ({}), reserved {}, free {}; image {}, mapped {}, private {}; executable {}; heuristics {}\n",
        s.total,
        s.committed,
        human_size(s.committed_bytes),
        s.reserved,
        s.free,
        s.image,
        s.mapped,
        s.private,
        s.executable,
        s.heuristics,
    ));
    if map.truncated {
        out.push_str("warning: region list truncated at MAX_REGIONS; results are incomplete\n");
    }
    out
}

fn json_payload(info: &ProcessInfo, map: &RegionMap) -> serde_json::Value {
    let s = summarize(&map.regions);
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "region_count": map.regions.len(),
        "truncated": map.truncated,
        "summary": {
            "total": s.total,
            "committed_count": s.committed,
            "reserved_count": s.reserved,
            "free_count": s.free,
            "image_count": s.image,
            "mapped_count": s.mapped,
            "private_count": s.private,
            "executable_count": s.executable,
            "heuristic_count": s.heuristics,
            "committed_bytes": s.committed_bytes,
        },
        "regions": map.regions,
    })
}

pub(crate) fn cancel_flag() -> Arc<AtomicBool> {
    static CANCEL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    CANCEL
        .get_or_init(|| {
            let flag = Arc::new(AtomicBool::new(false));
            let handler_flag = Arc::clone(&flag);
            if ctrlc::set_handler(move || handler_flag.store(true, Ordering::SeqCst)).is_err() {
                tracing::warn!("Ctrl+C 핸들러 설치 실패");
            }
            flag
        })
        .clone()
}

pub(crate) fn execute_scan(
    pid: u32,
    pattern: &ScanPattern,
    options: &ScanOptions,
    cancelled: &AtomicBool,
) -> Result<(LiveProcess, ScanReport)> {
    let live = LiveProcess::open(pid)?;
    let report = scan(&live, pattern, options, cancelled)?;
    Ok((live, report))
}

fn run_scan(args: &ScanArgs, global: &GlobalArgs) -> Result<()> {
    let pattern = build_pattern(args)?;
    let options = build_options(args)?;
    let cancelled = cancel_flag();
    cancelled.store(false, Ordering::SeqCst);
    let (live, report) = execute_scan(args.pid.pid, &pattern, &options, &cancelled)?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value =
                serde_json::to_value(scan_json_payload(&live.info, &pattern, &options, &report))
                    .map_err(|e| XmemError::JsonError {
                        reason: e.to_string(),
                    })?;
            emit_json(&success_envelope(value));
        }
        OutputMode::Human => emit(&render_scan(&live.info, &pattern, &options, &report)),
    }
    if report.cancelled {
        tracing::warn!("scan cancelled by user");
        return Err(XmemError::Cancelled {
            reason: "user interrupt".to_string(),
        });
    }
    Ok(())
}

fn build_pattern(args: &ScanArgs) -> Result<ScanPattern> {
    if let Some(p) = &args.pattern {
        ScanPattern::hex(p)
    } else if let Some(s) = &args.string {
        ScanPattern::ascii(s)
    } else if let Some(s) = &args.wide_string {
        ScanPattern::wide(s)
    } else {
        Err(XmemError::InvalidInput {
            reason: "--pattern/--string/--wide-string 중 하나가 필요함".to_string(),
        })
    }
}

fn parse_size(input: &str) -> Result<u64> {
    let lower = input.trim().to_ascii_lowercase();
    let lower = lower.strip_suffix('i').unwrap_or(&lower);
    let (digits, mult) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1024u64),
        Some('m') => (&lower[..lower.len() - 1], 1024 * 1024),
        Some('g') => (&lower[..lower.len() - 1], 1024 * 1024 * 1024),
        _ => (lower, 1),
    };
    let value: u64 = digits.trim().parse().map_err(|_| XmemError::InvalidInput {
        reason: format!("크기 파싱 실패: '{input}'"),
    })?;
    value
        .checked_mul(mult)
        .ok_or_else(|| XmemError::InvalidInput {
            reason: format!("크기가 너무 큼: '{input}'"),
        })
}

fn parse_addr(input: &str) -> Result<u64> {
    let t = input.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        t.parse::<u64>()
    }
    .map_err(|_| XmemError::InvalidInput {
        reason: format!("주소 파싱 실패: '{input}'"),
    })
}

fn parse_range(input: &str) -> Result<(u64, u64)> {
    let (a, b) = input
        .split_once(':')
        .ok_or_else(|| XmemError::InvalidInput {
            reason: format!("--range 형식은 START:END: '{input}'"),
        })?;
    let start = parse_addr(a)?;
    let end = parse_addr(b)?;
    if end <= start {
        return Err(XmemError::InvalidInput {
            reason: format!("--range의 END는 START보다 커야 함: '{input}'"),
        });
    }
    Ok((start, end))
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1))
        .unwrap_or(1)
        .clamp(1, 4)
}

fn build_options(args: &ScanArgs) -> Result<ScanOptions> {
    let chunk_size = match &args.chunk_size {
        Some(s) => {
            let v = parse_size(s)? as usize;
            if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&v) {
                return Err(XmemError::InvalidInput {
                    reason: format!("--chunk-size는 {MIN_CHUNK_SIZE}~{MAX_CHUNK_SIZE} 바이트"),
                });
            }
            v
        }
        None => DEFAULT_CHUNK_SIZE,
    };
    let threads = match args.threads {
        Some(0) => {
            return Err(XmemError::InvalidInput {
                reason: "--threads는 1 이상".to_string(),
            });
        }
        Some(n) => n,
        None => default_threads(),
    };
    let filters = RegionFilters {
        executable_only: args.executable_only,
        private_only: args.private_only,
        writable_only: args.writable_only,
        range: args.range.as_deref().map(parse_range).transpose()?,
        max_region_size: args
            .max_region_size
            .as_deref()
            .map(parse_size)
            .transpose()?,
        all: args.all,
    };
    Ok(ScanOptions {
        filters,
        chunk_size,
        threads,
        max_results: args.max_results.unwrap_or(DEFAULT_MAX_RESULTS),
        offset: args.offset,
    })
}

fn render_scan(
    info: &ProcessInfo,
    pattern: &ScanPattern,
    options: &ScanOptions,
    report: &ScanReport,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}), pattern {} \"{}\" ({} bytes), chunk {}, threads {}\n",
        info.pid,
        info.name,
        pattern.kind.as_str(),
        truncate(&pattern.source, 48),
        pattern.len(),
        options.chunk_size,
        report.stats.threads,
    ));
    if report.policy_restricted {
        out.push_str("policy: committed > 4 GiB — executable/private 영역만 스캔 (--all로 해제)\n");
    }
    out.push_str(
        "ADDRESS             OFFSET    CLASS      PROTECTION     REGION              MAPPED FILE\n",
    );
    for m in &report.matches {
        let mapped = match &m.mapped_file {
            Some(p) => truncate_tail(p, 40),
            None => "-".to_string(),
        };
        out.push_str(&format!(
            "0x{:016x} +0x{:<6x} {:10} {:14} 0x{:016x} {}\n",
            m.address,
            m.offset,
            m.class.to_string(),
            m.protection.to_string(),
            m.region_base,
            mapped,
        ));
    }
    out.push_str(&format!(
        "{} matches; regions {}/{} scanned ({} skipped); bytes {}; read_failures {}; partial {}; elapsed {} ms; rss {}\n",
        report.matches.len(),
        report.stats.regions_scanned,
        report.stats.regions_total,
        report.stats.regions_skipped,
        human_size(report.stats.bytes_scanned),
        report.stats.read_failures,
        report.stats.partial_reads,
        report.stats.elapsed_ms,
        human_size(report.stats.rss_bytes),
    ));
    if report.truncated {
        out.push_str("warning: result cap reached (use --max-results 0 for unlimited)\n");
    }
    if report.cancelled {
        out.push_str("warning: scan cancelled by user\n");
    } else if report.stats.bytes_scanned == 0 && report.stats.read_failures > 0 {
        out.push_str("warning: all reads failed (process may have exited or be protected)\n");
    }
    out
}

fn scan_json_payload(
    info: &ProcessInfo,
    pattern: &ScanPattern,
    options: &ScanOptions,
    report: &ScanReport,
) -> serde_json::Value {
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "pattern": { "kind": pattern.kind.as_str(), "source": pattern.source, "length": pattern.len() },
        "options": {
            "chunk_size": options.chunk_size,
            "threads": options.threads,
            "max_results": options.max_results,
            "offset": options.offset,
        },
        "policy_restricted": report.policy_restricted,
        "cancelled": report.cancelled,
        "truncated": report.truncated,
        "stats": report.stats,
        "matches": report.matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, Protection};

    fn region(base: u64, state: MemoryState, ty: Option<MemoryType>, raw: u32) -> MemoryRegion {
        let (r, w, x) = match raw {
            0x40 => (true, true, true),
            0x20 => (true, false, true),
            _ => (false, false, false),
        };
        let p = Protection::new(raw, r, w, x);
        MemoryRegion {
            base,
            size: 0x1000,
            state,
            protection: p,
            allocation_protection: None,
            region_type: ty,
            readable: p.readable,
            writable: p.writable,
            executable: p.executable,
            classification: xmem_core::classify(state, ty),
            heuristics: xmem_core::heuristics(state, &p, ty),
            mapped_file: None,
        }
    }

    fn sample_map() -> RegionMap {
        RegionMap {
            regions: vec![
                region(0x1000, MemoryState::Commit, Some(MemoryType::Private), 0x40),
                region(0x2000, MemoryState::Commit, Some(MemoryType::Image), 0x20),
                region(0x3000, MemoryState::Reserve, None, 0),
                region(0x4000, MemoryState::Free, None, 0),
            ],
            truncated: false,
        }
    }

    #[test]
    fn summary_counts_by_class() {
        let s = summarize(&sample_map().regions);
        assert_eq!(s.total, 4);
        assert_eq!((s.private, s.image, s.reserved, s.free), (1, 1, 1, 1));
        assert_eq!(s.executable, 2);
        assert_eq!(s.heuristics, 2);
        assert_eq!(s.committed_bytes, 0x2000);
    }

    #[test]
    fn render_map_has_header_rows_and_summary() {
        let out = render_map(&sample_map());
        assert!(out.contains("BASE"));
        assert!(out.contains("0x0000000000001000"));
        assert!(out.contains("MEM_PRIVATE"));
        assert!(out.contains("exec-private,wx"));
        assert!(out.contains("4 regions:"));
        assert!(!out.contains("truncated"));
    }

    #[test]
    fn render_map_warns_when_truncated() {
        let mut map = sample_map();
        map.truncated = true;
        assert!(render_map(&map).contains("truncated at MAX_REGIONS"));
    }

    #[test]
    fn json_payload_shape() {
        let info = ProcessInfo {
            pid: 42,
            ppid: None,
            name: "demo.exe".to_string(),
            image_path: None,
            arch: xmem_core::ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        };
        let value = json_payload(&info, &sample_map());
        assert_eq!(value["process"]["pid"], 42);
        assert_eq!(value["region_count"], 4);
        assert_eq!(value["truncated"], false);
        assert_eq!(value["summary"]["image_count"], 1);
        assert_eq!(value["regions"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn heur_list_renders_tags() {
        let r = region(0x1000, MemoryState::Commit, Some(MemoryType::Private), 0x40);
        assert_eq!(heur_list(&r), "exec-private,wx");
    }

    #[test]
    fn free_region_row_has_no_type_or_mapped_file() {
        let out = render_map(&sample_map());
        let line = out
            .lines()
            .find(|l| l.contains("0x0000000000004000"))
            .unwrap();
        assert!(line.contains("MEM_FREE"));
        assert!(line.contains(" free "));
    }

    #[test]
    fn parse_size_units() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("4k").unwrap(), 4096);
        assert_eq!(parse_size("16Mi").unwrap(), 16 * 1024 * 1024);
        assert!(parse_size("abc").is_err());
    }

    #[test]
    fn parse_range_and_addr() {
        assert_eq!(parse_range("0x1000:0x2000").unwrap(), (0x1000, 0x2000));
        assert_eq!(parse_range("4096:8192").unwrap(), (4096, 8192));
        assert!(parse_range("0x2000:0x1000").is_err());
        assert!(parse_range("0x1000").is_err());
    }

    #[test]
    fn cancelled_flag_yields_cancelled_report() {
        let pattern = ScanPattern::ascii("xmem").unwrap();
        let options = ScanOptions {
            max_results: 1,
            ..ScanOptions::default()
        };
        let cancelled = AtomicBool::new(true);
        let (_live, report) =
            execute_scan(xmem_windows::current_pid(), &pattern, &options, &cancelled).unwrap();
        assert!(report.cancelled);
        assert!(report.matches.is_empty());
    }

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 42,
            ppid: None,
            name: "demo.exe".to_string(),
            image_path: None,
            arch: xmem_core::ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_match() -> xmem_memory::ScanMatch {
        xmem_memory::ScanMatch {
            address: 0x1004,
            region_base: 0x1000,
            region_size: 0x1000,
            offset: 4,
            class: RegionClass::Private,
            protection: Protection::new(0x40, true, true, true),
            mapped_file: None,
        }
    }

    fn sample_report() -> ScanReport {
        let matches = vec![sample_match()];
        ScanReport {
            stats: xmem_memory::ScanStats {
                regions_total: 4,
                regions_scanned: 3,
                regions_skipped: 1,
                bytes_scanned: 0x3000,
                read_failures: 0,
                partial_reads: 0,
                matches: matches.len(),
                threads: 2,
                elapsed_ms: 7,
                rss_bytes: 0,
            },
            matches,
            cancelled: false,
            truncated: false,
            policy_restricted: false,
        }
    }

    #[test]
    fn render_scan_lists_matches_and_stats() {
        let pattern = ScanPattern::hex("48 8B ?? ?? C0").unwrap();
        let options = ScanOptions {
            max_results: 5,
            ..ScanOptions::default()
        };
        let mut report = sample_report();
        report.truncated = true;
        let out = render_scan(&sample_info(), &pattern, &options, &report);
        assert!(out.contains("hex"));
        assert!(out.contains("ADDRESS"));
        assert!(out.contains("0x0000000000001000"));
        assert!(out.contains("+0x4"));
        assert!(out.contains("1 matches;"));
        assert!(out.contains("result cap reached"));
        assert!(!out.contains("cancelled"));
    }

    #[test]
    fn scan_json_payload_shape() {
        let value = scan_json_payload(
            &sample_info(),
            &ScanPattern::ascii("xmem").unwrap(),
            &ScanOptions::default(),
            &sample_report(),
        );
        assert_eq!(value["process"]["pid"], 42);
        assert_eq!(value["pattern"]["kind"], "ascii");
        assert_eq!(value["truncated"], false);
        assert_eq!(value["stats"]["regions_scanned"], 3);
        assert_eq!(value["matches"].as_array().unwrap().len(), 1);
        assert_eq!(value["matches"][0]["offset"], 4);
    }
}
