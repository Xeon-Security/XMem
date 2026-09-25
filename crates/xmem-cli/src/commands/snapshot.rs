use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use serde_json::{Value, json};
use xmem_core::{Result, XmemError};
use xmem_forensics::{CollectOptions, SnapshotDiff, collect, diff, encode, read_file, write_file};
use xmem_memory::LiveProcess;
use xmem_windows::free_space_bytes;

use crate::cli::{GlobalArgs, SnapshotCmd};
use crate::commands::memory::cancel_flag;
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

pub fn run(cmd: &SnapshotCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        SnapshotCmd::Create { pid, output } => run_create(pid.pid, output, global),
        SnapshotCmd::Diff {
            before,
            after,
            only,
        } => run_diff(before, after, only, global),
    }
}

/// `--only`가 고른 섹션. 미지정(빈 목록)이면 전체.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiffSections {
    pub regions: bool,
    pub content: bool,
    pub modules: bool,
    pub threads: bool,
    pub detections: bool,
}

/// 콤마 목록을 파싱한다. 빈 토큰만 있으면 None(전체 표시)을 돌려준다.
pub(crate) fn parse_only(only: &[String]) -> Result<Option<DiffSections>> {
    let mut sections = DiffSections {
        regions: false,
        content: false,
        modules: false,
        threads: false,
        detections: false,
    };
    let mut any = false;
    for value in only {
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            match token.to_ascii_lowercase().as_str() {
                "regions" => sections.regions = true,
                "content" => sections.content = true,
                "modules" => sections.modules = true,
                "threads" => sections.threads = true,
                "detections" => sections.detections = true,
                other => {
                    return Err(XmemError::InvalidInput {
                        reason: format!(
                            "--only 값이 알 수 없음: '{other}' (regions,content,modules,threads,detections)"
                        ),
                    });
                }
            }
            any = true;
        }
    }
    Ok(any.then_some(sections))
}

/// 고르지 않은 섹션은 비우고 summary 카운터도 맞춰 0으로 만든다(JSON 키는 유지).
pub(crate) fn apply_only(diff: &mut SnapshotDiff, sections: &DiffSections) {
    if !sections.regions {
        diff.regions_added.clear();
        diff.regions_removed.clear();
        diff.regions_changed.clear();
        diff.summary.regions_added = 0;
        diff.summary.regions_removed = 0;
        diff.summary.regions_changed = 0;
    }
    if !sections.content {
        diff.content_changed.clear();
        diff.summary.content_changed = 0;
    }
    if !sections.modules {
        diff.modules_added.clear();
        diff.modules_removed.clear();
        diff.modules_changed.clear();
        diff.summary.modules_added = 0;
        diff.summary.modules_removed = 0;
        diff.summary.modules_changed = 0;
    }
    if !sections.threads {
        diff.threads_added.clear();
        diff.threads_removed.clear();
        diff.threads_changed.clear();
        diff.summary.threads_added = 0;
        diff.summary.threads_removed = 0;
        diff.summary.threads_changed = 0;
    }
    if !sections.detections {
        diff.detections_added.clear();
        diff.detections_removed.clear();
        diff.detections_changed.clear();
        diff.summary.detections_added = 0;
        diff.summary.detections_removed = 0;
        diff.summary.detections_changed = 0;
    }
}

#[derive(Debug)]
pub(crate) struct CreateSummary {
    pub output: String,
    pub file_bytes: u64,
    pub region_count: usize,
    pub module_count: usize,
    pub thread_count: usize,
    pub hashed_regions: usize,
    pub hashed_bytes: u64,
    pub elapsed_ms: u64,
}

fn run_create(pid: u32, output: &str, global: &GlobalArgs) -> Result<()> {
    let started = Instant::now();
    let cancel = cancel_flag();
    let path = Path::new(output);
    let mut summary = create_snapshot_file(pid, path, &cancel)?;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "output": summary.output,
                "file_bytes": summary.file_bytes,
                "region_count": summary.region_count,
                "module_count": summary.module_count,
                "thread_count": summary.thread_count,
                "hashed_regions": summary.hashed_regions,
                "hashed_bytes": summary.hashed_bytes,
                "elapsed_ms": summary.elapsed_ms,
            })));
            Ok(())
        }
        OutputMode::Human => {
            emit(&format!(
                "snapshot written: {} ({})\n",
                summary.output,
                human_size(summary.file_bytes)
            ));
            emit(&format!(
                "  regions {} / modules {} / threads {} / hashed {} regions ({}) in {} ms\n",
                summary.region_count,
                summary.module_count,
                summary.thread_count,
                summary.hashed_regions,
                human_size(summary.hashed_bytes),
                summary.elapsed_ms,
            ));
            Ok(())
        }
    }
}

/// 라이브 프로세스를 수집해 검증된 Snapshot 파일로 저장한다.
pub(crate) fn create_snapshot_file(
    pid: u32,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<CreateSummary> {
    let live = LiveProcess::open(pid)?;
    let envelope = collect(&live, &CollectOptions::default(), cancel)?;
    let bytes = encode(&envelope)?;
    let dir = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    ensure_disk_space(&dir, bytes.len() as u64)?;
    write_file(output, &bytes)?;
    Ok(CreateSummary {
        output: output.display().to_string(),
        file_bytes: bytes.len() as u64,
        region_count: envelope.regions.len(),
        module_count: envelope.modules.len(),
        thread_count: envelope.threads.len(),
        hashed_regions: envelope.acquisition.hashed_regions,
        hashed_bytes: envelope.acquisition.hashed_bytes,
        elapsed_ms: 0,
    })
}

/// 예상 크기 + 여유 마진이 가용 공간을 넘으면 거부한다.
pub(crate) fn ensure_disk_space(dir: &Path, needed: u64) -> Result<()> {
    let free = free_space_bytes(&dir.to_string_lossy())?;
    if free < needed.saturating_add(DISK_MARGIN_BYTES) {
        return Err(XmemError::SnapshotError {
            reason: format!(
                "디스크 공간 부족: 필요 {needed} + 여유 {DISK_MARGIN_BYTES}, 가용 {free} ({})",
                dir.display()
            ),
        });
    }
    Ok(())
}

fn run_diff(before: &str, after: &str, only: &[String], global: &GlobalArgs) -> Result<()> {
    let before_envelope = read_file(Path::new(before))?;
    let after_envelope = read_file(Path::new(after))?;
    let mut result = diff(&before_envelope, &after_envelope);
    if let Some(sections) = parse_only(only)? {
        apply_only(&mut result, &sections);
    }
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(diff_json_payload(&result)));
            Ok(())
        }
        OutputMode::Human => {
            emit(&render_diff(&result));
            Ok(())
        }
    }
}

pub(crate) fn render_diff(diff: &SnapshotDiff) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "before: pid {} {} @ {}\n",
        diff.before.pid, diff.before.name, diff.before.timestamp
    ));
    out.push_str(&format!(
        "after:  pid {} {} @ {}\n",
        diff.after.pid, diff.after.name, diff.after.timestamp
    ));
    let summary = &diff.summary;
    out.push_str(&format!(
        "regions: +{} -{} ~{} | content ~{} | modules: +{} -{} ~{} | threads: +{} -{} ~{} | detections: +{} -{} ~{}\n",
        summary.regions_added,
        summary.regions_removed,
        summary.regions_changed,
        summary.content_changed,
        summary.modules_added,
        summary.modules_removed,
        summary.modules_changed,
        summary.threads_added,
        summary.threads_removed,
        summary.threads_changed,
        summary.detections_added,
        summary.detections_removed,
        summary.detections_changed,
    ));
    for region in &diff.regions_added {
        out.push_str(&format!(
            "+ {:#018x} {:>10} {} {} {}\n",
            region.base,
            human_size(region.size),
            region.state,
            region.protection,
            region.classification
        ));
    }
    for region in &diff.regions_removed {
        out.push_str(&format!(
            "- {:#018x} {:>10} {} {} {}\n",
            region.base,
            human_size(region.size),
            region.state,
            region.protection,
            region.classification
        ));
    }
    for change in &diff.regions_changed {
        out.push_str(&format!(
            "~ {:#018x} {}\n",
            change.after.base,
            change.changes.join(", ")
        ));
    }
    for change in &diff.content_changed {
        out.push_str(&format!(
            "* {:#018x} content: {} -> {}\n",
            change.base,
            &change.before_hash[..16.min(change.before_hash.len())],
            &change.after_hash[..16.min(change.after_hash.len())],
        ));
    }
    for module in &diff.modules_added {
        out.push_str(&format!("+ module {} {:#x}\n", module.name, module.base));
    }
    for module in &diff.modules_removed {
        out.push_str(&format!("- module {} {:#x}\n", module.name, module.base));
    }
    for change in &diff.modules_changed {
        out.push_str(&format!(
            "~ module {} {}\n",
            change.after.name,
            change.changes.join(", ")
        ));
    }
    for thread in &diff.threads_added {
        out.push_str(&format!("+ thread tid {}\n", thread.tid));
    }
    for thread in &diff.threads_removed {
        out.push_str(&format!("- thread tid {}\n", thread.tid));
    }
    for change in &diff.threads_changed {
        out.push_str(&format!(
            "~ thread tid {} {}\n",
            change.after.tid,
            change.changes.join(", ")
        ));
    }
    for finding in &diff.detections_added {
        out.push_str(&format!(
            "+ detection {} {}\n",
            finding.rule_id, finding.name
        ));
    }
    for finding in &diff.detections_removed {
        out.push_str(&format!(
            "- detection {} {}\n",
            finding.rule_id, finding.name
        ));
    }
    for change in &diff.detections_changed {
        out.push_str(&format!(
            "~ detection {} {}\n",
            change.after.rule_id,
            change.changes.join(", ")
        ));
    }
    out
}

pub(crate) fn diff_json_payload(diff: &SnapshotDiff) -> Value {
    serde_json::to_value(diff).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("xmem-cli-snapshot-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_snapshot_of_self_writes_valid_file() {
        let dir = temp_dir("create");
        let path = dir.join("self.xmem");
        let cancel = AtomicBool::new(false);
        let summary = create_snapshot_file(xmem_windows::current_pid(), &path, &cancel).unwrap();
        assert!(summary.file_bytes > 0);
        assert!(summary.region_count > 0);
        assert_eq!(summary.hashed_regions > 0, summary.hashed_bytes > 0);
        let envelope = xmem_forensics::read_file(&path).unwrap();
        assert_eq!(envelope.process.pid, xmem_windows::current_pid());
        assert!(!envelope.regions.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disk_space_guard_rejects_huge_requests() {
        let dir = temp_dir("disk-guard");
        let err = ensure_disk_space(&dir, u64::MAX / 2).unwrap_err();
        assert!(matches!(err, XmemError::SnapshotError { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn render_diff_lists_changes_and_summary() {
        let before = sample_envelope_for_diff(0x1000, 0x04, 100);
        let mut after = sample_envelope_for_diff(0x1000, 0x40, 101);
        after.regions.push(xmem_core::MemoryRegion {
            base: 0x9000,
            ..after.regions[0].clone()
        });
        let result = xmem_forensics::diff(&before, &after);
        let text = render_diff(&result);
        assert!(text.contains("protection:"));
        assert!(text.contains("+"));
        assert!(text.contains("regions:"));
    }

    #[test]
    fn diff_json_payload_has_summary_and_sections() {
        let before = sample_envelope_for_diff(0x1000, 0x04, 100);
        let after = sample_envelope_for_diff(0x2000, 0x04, 100);
        let result = xmem_forensics::diff(&before, &after);
        let payload = diff_json_payload(&result);
        assert_eq!(payload["summary"]["regions_added"], 1);
        assert_eq!(payload["summary"]["regions_removed"], 1);
        assert!(payload["regions_added"].is_array());
    }

    #[test]
    fn parse_only_handles_lists_empties_and_unknown_values() {
        assert_eq!(parse_only(&[]).unwrap(), None, "미지정은 전체");
        assert_eq!(parse_only(&[String::new()]).unwrap(), None, "빈 값도 전체");

        let sections = parse_only(&["regions,content".to_string()])
            .unwrap()
            .expect("섹션이 있어야 함");
        assert!(sections.regions && sections.content);
        assert!(!sections.modules && !sections.threads && !sections.detections);

        assert!(parse_only(&["bogus".to_string()]).is_err());
    }

    #[test]
    fn apply_only_clears_unselected_sections_and_summary() {
        let before = sample_envelope_for_diff(0x1000, 0x04, 100);
        let mut after = sample_envelope_for_diff(0x1000, 0x40, 101);
        after.regions.push(xmem_core::MemoryRegion {
            base: 0x9000,
            ..after.regions[0].clone()
        });
        let mut result = xmem_forensics::diff(&before, &after);
        assert!(!result.regions_added.is_empty());
        assert!(!result.regions_changed.is_empty());
        assert!(!result.threads_added.is_empty());

        let sections = parse_only(&["regions".to_string()])
            .unwrap()
            .expect("섹션이 있어야 함");
        apply_only(&mut result, &sections);
        assert!(!result.regions_added.is_empty(), "선택된 섹션은 유지");
        assert!(result.modules_added.is_empty());
        assert!(result.threads_added.is_empty());
        assert!(result.threads_removed.is_empty());
        assert!(result.detections_added.is_empty());
        assert_eq!(result.summary.threads_added, 0);
        assert_eq!(result.summary.modules_added, 0);
        assert!(result.summary.regions_changed > 0);

        let value = diff_json_payload(&result);
        assert!(!value["regions_changed"].as_array().unwrap().is_empty());
        assert!(value["threads_added"].as_array().unwrap().is_empty());
        assert!(value["threads_removed"].as_array().unwrap().is_empty());
        assert!(value.get("summary").is_some(), "JSON 키는 유지된다");
    }

    #[test]
    fn render_diff_includes_detection_lines() {
        let before = sample_envelope_for_diff(0x1000, 0x40, 100);
        let mut after = sample_envelope_for_diff(0x1000, 0x40, 100);
        after.findings.push(xmem_core::Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: xmem_core::Severity::Medium,
            confidence: xmem_core::Confidence::High,
            evidence: vec![xmem_core::Evidence::new("region").with_region_base(0x1000)],
            heuristic: "private memory with executable protection".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        });
        let result = xmem_forensics::diff(&before, &after);
        let text = render_diff(&result);
        assert!(text.contains("+ detection XMEM-001"));
        assert!(text.contains("detections:"));
    }

    fn sample_envelope_for_diff(
        region_base: u64,
        protection_raw: u32,
        tid: u32,
    ) -> xmem_forensics::SnapshotEnvelope {
        use xmem_core::{
            MemoryState, MemoryType, ProcessArch, ProcessInfo, Protection, RegionClass,
        };
        xmem_forensics::SnapshotEnvelope {
            schema_version: xmem_core::JSON_SCHEMA_VERSION,
            xmem_version: xmem_core::VERSION.to_string(),
            format_version: xmem_core::SNAPSHOT_FORMAT_VERSION,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            process: ProcessInfo {
                pid: 555,
                ppid: None,
                name: "diff.exe".to_string(),
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
            regions: vec![xmem_core::MemoryRegion {
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
            threads: vec![xmem_core::ThreadInfo {
                tid,
                pid: 555,
                priority: None,
                start_address: None,
                start_region_base: None,
                start_module: None,
            }],
            content_hashes: Vec::new(),
            findings: Vec::new(),
            acquisition: xmem_forensics::AcquisitionMeta {
                source: "test".to_string(),
                pid: 555,
                hashed_regions: 0,
                hashed_bytes: 0,
                hash_budget_bytes: 0,
                read_failures: 0,
                region_truncated: false,
            },
        }
    }
}
