//! `xmem image` — `.xmemimg` 생성/요약/오프라인 분석·검색.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::{Value, json};
use xmem_core::{MemorySource, Result, ScanPattern, XmemError};
use xmem_forensics::{
    ImageMeta, ImageOptions, MemoryImageSource, ReportData, collect_image, encode_image,
    write_image, write_report,
};
use xmem_memory::{DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, RegionFilters, ScanOptions, scan};

use crate::cli::{GlobalArgs, ImageAnalyzeArgs, ImageCmd, ImageCreateArgs, ImageScanArgs};
use crate::commands::memory::{cancel_flag, parse_size, render_scan};
use crate::commands::render::human_size;
use crate::commands::snapshot::ensure_disk_space;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(cmd: &ImageCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        ImageCmd::Create(args) => run_create(args, global),
        ImageCmd::Info { file } => run_info(file, global),
        ImageCmd::Analyze(args) => run_analyze(args, global),
        ImageCmd::Scan(args) => run_scan(args, global),
    }
}

fn image_options(args: &ImageCreateArgs) -> Result<ImageOptions> {
    let mut options = ImageOptions::default();
    if let Some(text) = args.max_bytes.as_deref() {
        let value = parse_size(text)?;
        if value == 0 {
            return Err(XmemError::InvalidInput {
                reason: "--max-bytes는 1 이상이어야 합니다".into(),
            });
        }
        options.budget_bytes = value;
    }
    if let Some(text) = args.max_region_size.as_deref() {
        let value = parse_size(text)?;
        if value == 0 {
            return Err(XmemError::InvalidInput {
                reason: "--max-region-size는 1 이상이어야 합니다".into(),
            });
        }
        options.max_region_bytes = value;
    }
    options.executable_only = args.executable_only;
    options.private_only = args.private_only;
    Ok(options)
}

fn run_create(args: &ImageCreateArgs, global: &GlobalArgs) -> Result<()> {
    let options = image_options(args)?;
    let live = xmem_memory::LiveProcess::open(args.pid.pid)?;
    let cancel = cancel_flag();
    cancel.store(false, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let image = collect_image(&live, &options, &cancel)?;
    let bytes = encode_image(&image)?;
    let output = Path::new(&args.output);
    let dir = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_disk_space(dir, options.budget_bytes)?;
    let file_bytes = write_image(output, &image)?;
    let acquisition = &image.meta.acquisition;
    match resolve_mode(global.json) {
        OutputMode::Json => emit_json(&success_envelope(json!({
            "output": args.output,
            "file_bytes": file_bytes,
            "encoded_bytes": bytes.len(),
            "process": { "pid": live.info.pid, "name": live.info.name },
            "stored_regions": acquisition.stored_regions,
            "stored_bytes": acquisition.stored_bytes,
            "budget_bytes": acquisition.budget_bytes,
            "read_failures": acquisition.read_failures,
            "elapsed_ms": started.elapsed().as_millis() as u64,
        }))),
        OutputMode::Human => emit(&format!(
            "image written: {} ({})\n  {} regions stored ({}), read failures {}, elapsed {} ms\n",
            args.output,
            human_size(file_bytes),
            acquisition.stored_regions,
            human_size(acquisition.stored_bytes),
            acquisition.read_failures,
            started.elapsed().as_millis() as u64,
        )),
    }
    Ok(())
}

pub(crate) fn image_summary_json(meta: &ImageMeta) -> Value {
    json!({
        "format": { "magic": "XMEMIMG", "format_version": meta.format_version },
        "schema_version": meta.schema_version,
        "xmem_version": meta.xmem_version,
        "timestamp": meta.timestamp,
        "process": { "pid": meta.process.pid, "name": meta.process.name, "arch": meta.process.arch },
        "region_count": meta.regions.len(),
        "module_count": meta.modules.len(),
        "thread_count": meta.threads.len(),
        "finding_count": meta.findings.len(),
        "risk": xmem_detection::risk_score(&meta.findings),
        "stored_regions": meta.contents.len(),
        "stored_bytes": meta.acquisition.stored_bytes,
        "budget_bytes": meta.acquisition.budget_bytes,
        "read_failures": meta.acquisition.read_failures,
        "skipped_unreadable": meta.acquisition.skipped_unreadable,
        "partial_regions": meta.contents.iter().filter(|stored| stored.partial).count(),
    })
}

fn render_info(meta: &ImageMeta, file: &str) -> String {
    let risk = xmem_detection::risk_score(&meta.findings);
    let mut out = String::new();
    out.push_str(&format!("image: {file}\n"));
    out.push_str(&format!(
        "  format XMEMIMG v{}, schema {}, xmem {}\n",
        meta.format_version, meta.schema_version, meta.xmem_version
    ));
    out.push_str(&format!(
        "  captured {}, process {} ({}, {:?})\n",
        meta.timestamp, meta.process.name, meta.process.pid, meta.process.arch
    ));
    out.push_str(&format!(
        "  regions {} / modules {} / threads {} / findings {} (risk {}/100 {})\n",
        meta.regions.len(),
        meta.modules.len(),
        meta.threads.len(),
        meta.findings.len(),
        risk.score,
        risk.level.as_str()
    ));
    out.push_str(&format!(
        "  stored {} regions, {} of budget {} (read failures {}, skipped {}, partial {})\n",
        meta.contents.len(),
        human_size(meta.acquisition.stored_bytes),
        human_size(meta.acquisition.budget_bytes),
        meta.acquisition.read_failures,
        meta.acquisition.skipped_unreadable,
        meta.contents.iter().filter(|stored| stored.partial).count(),
    ));
    out
}

fn run_info(file: &str, global: &GlobalArgs) -> Result<()> {
    let source = MemoryImageSource::open(Path::new(file))?;
    let meta = source.meta();
    match resolve_mode(global.json) {
        OutputMode::Json => emit_json(&success_envelope(image_summary_json(meta))),
        OutputMode::Human => emit(&render_info(meta, file)),
    }
    Ok(())
}

fn run_analyze(args: &ImageAnalyzeArgs, global: &GlobalArgs) -> Result<()> {
    let source = MemoryImageSource::open(Path::new(&args.file))?;
    let meta = source.meta();
    let findings = &meta.findings;
    if let Some(output) = args.output.as_deref() {
        let data = ReportData::new(
            meta.process.clone(),
            meta.regions.clone(),
            meta.modules.clone(),
            meta.threads.clone(),
            findings.clone(),
        );
        write_report(&data, Path::new(output))?;
        return match resolve_mode(global.json) {
            OutputMode::Json => {
                emit_json(&success_envelope(json!({
                    "output": output,
                    "finding_count": findings.len(),
                })));
                Ok(())
            }
            OutputMode::Human => {
                emit(&format!(
                    "report written: {output} ({} findings)\n",
                    findings.len()
                ));
                Ok(())
            }
        };
    }
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "file": args.file,
                "finding_count": findings.len(),
                "findings": findings,
                "risk": xmem_detection::risk_score(findings),
            })));
            Ok(())
        }
        OutputMode::Human => {
            emit(&crate::commands::detect::render_findings(
                &meta.process,
                findings,
            ));
            Ok(())
        }
    }
}

fn build_pattern(args: &ImageScanArgs) -> Result<ScanPattern> {
    if let Some(value) = args.pattern.as_deref() {
        ScanPattern::hex(value)
    } else if let Some(value) = args.needle_string.as_deref() {
        if value.trim().is_empty() {
            return Err(XmemError::InvalidInput {
                reason: "빈 문자열 패턴".to_string(),
            });
        }
        ScanPattern::ascii(value)
    } else if let Some(value) = args.wide_string.as_deref() {
        if value.trim().is_empty() {
            return Err(XmemError::InvalidInput {
                reason: "빈 문자열 패턴".to_string(),
            });
        }
        ScanPattern::wide(value)
    } else {
        Err(XmemError::InvalidInput {
            reason: "--pattern/--string/--wide-string 중 하나가 필요함".to_string(),
        })
    }
}

pub(crate) fn build_scan_options(args: &ImageScanArgs) -> ScanOptions {
    ScanOptions {
        filters: RegionFilters {
            executable_only: args.executable_only,
            private_only: args.private_only,
            writable_only: args.writable_only,
            range: None,
            max_region_size: None,
            all: false,
        },
        chunk_size: DEFAULT_CHUNK_SIZE,
        threads: 1,
        max_results: args.max_results.unwrap_or(DEFAULT_MAX_RESULTS),
        offset: args.offset,
    }
}

fn run_scan(args: &ImageScanArgs, global: &GlobalArgs) -> Result<()> {
    let pattern = build_pattern(args)?;
    let options = build_scan_options(args);
    let source = MemoryImageSource::open(Path::new(&args.file))?;
    let cancel = cancel_flag();
    cancel.store(false, Ordering::SeqCst);
    let report = scan(&source, &pattern, &options, &cancel)?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "file": args.file,
                "process": { "pid": source.process().pid, "name": source.process().name },
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
            })));
        }
        OutputMode::Human => emit(&render_scan(source.process(), &pattern, &options, &report)),
    }
    if report.cancelled {
        return Err(XmemError::Cancelled {
            reason: "user interrupt".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        MemoryRegion, MemoryState, MemoryType, ProcessArch, ProcessInfo, Protection, RegionClass,
    };
    use xmem_forensics::{ImageAcquisition, ImageMeta, StoredRegion};

    fn sample_args() -> ImageScanArgs {
        ImageScanArgs {
            file: "a.xmemimg".into(),
            pattern: None,
            needle_string: Some("abc".into()),
            wide_string: None,
            executable_only: false,
            private_only: false,
            writable_only: false,
            offset: None,
            max_results: None,
        }
    }

    fn sample_meta() -> ImageMeta {
        ImageMeta {
            schema_version: 1,
            xmem_version: "0.2.5".into(),
            format_version: 1,
            timestamp: chrono::Utc::now(),
            process: ProcessInfo {
                pid: 9,
                ppid: None,
                name: "mock.exe".into(),
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
                protection: Protection::new(0x04, true, true, false),
                allocation_protection: None,
                region_type: Some(MemoryType::Private),
                readable: true,
                writable: true,
                executable: false,
                classification: RegionClass::Private,
                heuristics: Vec::new(),
                mapped_file: None,
            }],
            modules: Vec::new(),
            threads: Vec::new(),
            findings: Vec::new(),
            contents: vec![StoredRegion {
                base: 0x1000,
                region_size: 0x1000,
                offset: 0,
                len: 0x10,
                partial: false,
            }],
            acquisition: ImageAcquisition {
                stored_regions: 1,
                stored_bytes: 0x10,
                budget_bytes: 0x1000,
                read_failures: 0,
                skipped_unreadable: 0,
            },
        }
    }

    #[test]
    fn build_scan_options_maps_flags() {
        let args = ImageScanArgs {
            file: "a.xmemimg".into(),
            pattern: None,
            needle_string: Some("abc".into()),
            wide_string: None,
            executable_only: true,
            private_only: false,
            writable_only: false,
            offset: Some(4),
            max_results: Some(3),
        };
        let options = build_scan_options(&args);
        assert_eq!(options.max_results, 3);
        assert_eq!(options.offset, Some(4));
        assert!(options.filters.executable_only);
    }

    #[test]
    fn image_summary_json_has_expected_shape() {
        let meta = sample_meta();
        let payload = image_summary_json(&meta);
        assert_eq!(payload["process"]["pid"], 9);
        assert_eq!(payload["region_count"], 1);
        assert_eq!(payload["stored_regions"], 1);
    }

    #[test]
    fn local_pattern_builder_rejects_empty_needle() {
        let args = ImageScanArgs {
            needle_string: Some("   ".into()),
            ..sample_args()
        };
        assert!(build_pattern(&args).is_err());
    }
}
