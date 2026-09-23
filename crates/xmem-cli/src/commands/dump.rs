use std::path::Path;

use serde_json::{Value, json};
use xmem_core::{Finding, Result, XmemError};
use xmem_forensics::{DumpAnalysis, MinidumpSource};
use xmem_windows::{free_space_bytes, open_for_dump, process_info, write_minidump_file};

use crate::cli::{DumpCmd, GlobalArgs};
use crate::commands::detect::render_findings;
use crate::commands::memory::cancel_flag;
use crate::commands::process::arch_str;
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct CreateSummary {
    pub output: String,
    pub file_bytes: u64,
    pub full: bool,
    pub pid: u32,
    pub name: String,
    pub elapsed_ms: u64,
}

pub fn run(cmd: &DumpCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        DumpCmd::Create { pid, output, full } => run_create(pid.pid, output, *full, global),
        DumpCmd::Analyze { file } => run_analyze(file, global),
    }
}

fn run_create(pid: u32, output: &str, full: bool, global: &GlobalArgs) -> Result<()> {
    let _cancel = cancel_flag();
    let started = std::time::Instant::now();
    let mut summary = create_dump_file(pid, output, full)?;
    summary.elapsed_ms = started.elapsed().as_millis() as u64;

    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "output": summary.output,
                "file_bytes": summary.file_bytes,
                "full": summary.full,
                "process": { "pid": summary.pid, "name": summary.name },
                "elapsed_ms": summary.elapsed_ms,
            })));
            Ok(())
        }
        OutputMode::Human => {
            emit(&format!(
                "dump written: {} ({}){}\n",
                summary.output,
                human_size(summary.file_bytes),
                if summary.full { " [full]" } else { "" }
            ));
            emit(&format!(
                "  process {} ({}) in {} ms\n",
                summary.name, summary.pid, summary.elapsed_ms
            ));
            Ok(())
        }
    }
}

pub(crate) fn create_dump_file(pid: u32, output: &str, full: bool) -> Result<CreateSummary> {
    let handle = open_for_dump(pid)?;
    let info = process_info(pid)?;
    let path = Path::new(output);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let needed = if full {
        info.memory_stats.as_ref().map(|s| s.commit).unwrap_or(0)
    } else {
        0
    };
    ensure_disk_space(parent, needed)?;

    let file_bytes = write_minidump_file(&handle, pid, path, full)?;
    Ok(CreateSummary {
        output: output.to_string(),
        file_bytes,
        full,
        pid,
        name: info.name,
        elapsed_ms: 0,
    })
}

fn ensure_disk_space(dir: &Path, needed: u64) -> Result<()> {
    let free = free_space_bytes(&dir.to_string_lossy())?;
    if free < needed.saturating_add(DISK_MARGIN_BYTES) {
        return Err(XmemError::DumpError {
            reason: format!(
                "디스크 공간 부족: 필요 {needed} + 여유 {DISK_MARGIN_BYTES}, 가용 {free} ({})",
                dir.display()
            ),
        });
    }
    Ok(())
}

fn run_analyze(file: &str, global: &GlobalArgs) -> Result<()> {
    let source = MinidumpSource::open(Path::new(file))?;
    let findings = xmem_detection::detect_source(&source)?;
    let analysis = source.analysis();

    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(dump_json_payload(&analysis, &findings)));
            Ok(())
        }
        OutputMode::Human => {
            emit(&render_dump(&analysis, &findings));
            Ok(())
        }
    }
}

pub(crate) fn render_dump(analysis: &DumpAnalysis, findings: &[Finding]) -> String {
    let summary = super::memory::summarize(&analysis.regions);
    let mut out = String::new();
    out.push_str(&format!("dump {}\n", analysis.path));
    out.push_str(&format!(
        "  os: {} cpu: {} arch: {}\n",
        analysis.os,
        analysis.cpu,
        arch_str(analysis.arch)
    ));
    out.push_str(&format!(
        "  pid: {} name: {}\n",
        analysis.process.pid, analysis.process.name
    ));
    out.push_str(&format!(
        "  regions: {} (committed {} ({}), reserved {}, free {}; executable {}), modules: {}, threads: {}, memory ranges: {} ({})\n",
        summary.total,
        summary.committed,
        human_size(summary.committed_bytes),
        summary.reserved,
        summary.free,
        summary.executable,
        analysis.modules.len(),
        analysis.threads.len(),
        analysis.memory_ranges,
        human_size(analysis.memory_bytes),
    ));
    out.push_str(&render_findings(&analysis.process, findings));
    out
}

pub(crate) fn dump_json_payload(analysis: &DumpAnalysis, findings: &[Finding]) -> Value {
    json!({
        "file": analysis.path,
        "os": analysis.os,
        "cpu": analysis.cpu,
        "arch": arch_str(analysis.arch),
        "process": { "pid": analysis.process.pid, "name": analysis.process.name },
        "region_count": analysis.regions.len(),
        "module_count": analysis.modules.len(),
        "thread_count": analysis.threads.len(),
        "memory_ranges": analysis.memory_ranges,
        "memory_bytes": analysis.memory_bytes,
        "finding_count": findings.len(),
        "findings": findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, ProcessArch, ProcessInfo, Severity};

    fn sample_analysis() -> DumpAnalysis {
        DumpAnalysis {
            path: "self.dmp".to_string(),
            os: "Windows".to_string(),
            cpu: "X86_64".to_string(),
            arch: ProcessArch::X64,
            process: ProcessInfo {
                pid: 4242,
                ppid: None,
                name: "sample.exe".to_string(),
                image_path: None,
                arch: ProcessArch::X64,
                session_id: None,
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: Some(3),
                module_count: Some(2),
            },
            modules: Vec::new(),
            threads: Vec::new(),
            regions: Vec::new(),
            memory_ranges: 7,
            memory_bytes: 4096,
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region")],
            heuristic: "Executable Private Memory".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }
    }

    #[test]
    fn create_dump_of_self_writes_valid_file() {
        let dir = std::env::temp_dir().join(format!("xmem-cli-dump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.dmp");

        let summary = create_dump_file(std::process::id(), &path.to_string_lossy(), false).unwrap();
        assert!(summary.file_bytes > 0);
        let magic = std::fs::read(&path).unwrap();
        assert_eq!(&magic[..4], b"MDMP");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_dump_lists_summary_and_findings() {
        let text = render_dump(&sample_analysis(), &[sample_finding()]);
        assert!(text.contains("dump self.dmp"));
        assert!(text.contains("os: Windows cpu: X86_64 arch: x64"));
        assert!(text.contains("regions: 0"));
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("finding"));
    }

    #[test]
    fn dump_json_payload_has_summary_and_findings() {
        let value = dump_json_payload(&sample_analysis(), &[sample_finding()]);
        assert_eq!(value["file"], "self.dmp");
        assert_eq!(value["process"]["pid"], 4242);
        assert_eq!(value["memory_ranges"], 7);
        assert_eq!(value["finding_count"], 1);
        assert_eq!(value["findings"][0]["rule_id"], "XMEM-001");
    }

    #[test]
    fn analyze_missing_file_errors() {
        let Err(err) = MinidumpSource::open(Path::new("no-such-file.dmp")) else {
            panic!("오류가 나야 함");
        };
        assert!(matches!(err, XmemError::DumpError { .. }));
    }
}
