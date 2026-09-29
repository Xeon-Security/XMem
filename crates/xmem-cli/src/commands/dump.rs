use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use xmem_core::{Finding, Result, XmemError};
use xmem_forensics::{DumpAnalysis, MinidumpSource};
use xmem_windows::{
    DumpProgress, free_space_bytes, open_for_dump, process_info, write_minidump_file,
    write_minidump_file_with_progress,
};

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
        DumpCmd::Create {
            pid,
            output,
            full,
            progress,
        } => run_create(pid.pid, output, *full, *progress, global),
        DumpCmd::Analyze { file } => run_analyze(file, global),
    }
}

/// 덤프는 취소할 수 없고, 별도 스레드가 진행 카운터를 폴링해 10% 단위로 stderr에 찍는다.
/// 일반 덤프는 예상(commit) 대비 크기가 작아 10%를 못 넘기므로, 끝나면 요약 한 줄을 보장한다.
fn spawn_dump_monitor(
    progress: Arc<DumpProgress>,
    done: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last_bucket = 0u32;
        let mut printed = false;
        loop {
            let finished = done.load(Ordering::Relaxed);
            let pct = progress
                .fraction()
                .map(|fraction| (fraction * 100.0).round().clamp(0.0, 100.0) as u32);
            let bucket = pct.map_or(0, |pct| pct / 10);
            if bucket > last_bucket {
                if let Some(pct) = pct {
                    eprintln!(
                        "dumping... {pct}% ({})",
                        human_size(progress.bytes_written())
                    );
                    printed = true;
                }
                last_bucket = bucket;
            }
            if finished {
                if !printed || last_bucket < 10 {
                    eprintln!("dumping... done ({})", human_size(progress.bytes_written()));
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    })
}

fn run_create(
    pid: u32,
    output: &str,
    full: bool,
    progress_flag: bool,
    global: &GlobalArgs,
) -> Result<()> {
    let _cancel = cancel_flag();
    let started = std::time::Instant::now();
    // 진행 표시용 예상 크기는 프로세스 commit이다. 조회 실패는 indeterminate(0)로 둔다.
    let progress = progress_flag.then(|| {
        let commit = process_info(pid)
            .ok()
            .and_then(|info| info.memory_stats.map(|stats| stats.commit))
            .unwrap_or(0);
        Arc::new(DumpProgress::new(commit))
    });
    let done = Arc::new(AtomicBool::new(false));
    let monitor = progress
        .as_ref()
        .map(|progress| spawn_dump_monitor(Arc::clone(progress), Arc::clone(&done)));
    let result = create_dump_file(pid, output, full, progress.as_deref());
    done.store(true, Ordering::SeqCst);
    // 마지막 진행 줄이 프로세스 종료와 함께 사라지지 않도록 모니터를 합류시킨다.
    if let Some(monitor) = monitor {
        let _ = monitor.join();
    }
    let mut summary = result?;
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

pub(crate) fn create_dump_file(
    pid: u32,
    output: &str,
    full: bool,
    progress: Option<&DumpProgress>,
) -> Result<CreateSummary> {
    // 존재하지 않는 PID를 ProcessExited로 보고하기 위해 process_info를 먼저 호출한다.
    let info = process_info(pid)?;
    let handle = open_for_dump(pid)?;
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

    let file_bytes = match progress {
        Some(progress) => write_minidump_file_with_progress(&handle, pid, path, full, progress)?,
        None => write_minidump_file(&handle, pid, path, full)?,
    };
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
    if analysis.modules.is_empty() {
        out.push_str(
            "  note: 모듈 목록 없음 — 미니덤프에 모듈 정보가 포함되지 않아 상세가 제한됩니다\n",
        );
    }
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
        // 오프라인 분석에서도 스레드 시작 주소와 출처(start_address_source)를 볼 수 있게 한다.
        "threads": analysis.threads,
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
    fn render_dump_notes_missing_module_list() {
        let analysis = sample_analysis();
        let text = render_dump(&analysis, &[]);
        assert!(text.contains("모듈 목록 없음"), "{text}");
    }

    #[test]
    fn render_dump_omits_module_note_when_modules_exist() {
        let mut analysis = sample_analysis();
        analysis.modules.push(xmem_core::ModuleInfo {
            name: "ntdll.dll".into(),
            base: 0x7ffc_0000,
            size: 0x1000,
            path: None,
            arch: None,
        });
        let text = render_dump(&analysis, &[]);
        assert!(!text.contains("모듈 목록 없음"), "{text}");
    }

    #[test]
    fn create_dump_of_self_writes_valid_file() {
        let dir = std::env::temp_dir().join(format!("xmem-cli-dump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.dmp");

        let summary =
            create_dump_file(std::process::id(), &path.to_string_lossy(), false, None).unwrap();
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
    fn dump_json_payload_includes_threads_with_source() {
        let mut analysis = sample_analysis();
        analysis.threads.push(xmem_core::ThreadInfo {
            tid: 77,
            pid: 4242,
            priority: None,
            start_address: Some(0x1000),
            start_region_base: Some(0x1000),
            start_module: None,
            start_address_source: Some("minidump-context-rip".to_string()),
        });
        let value = dump_json_payload(&analysis, &[]);
        assert_eq!(value["thread_count"], 1);
        assert_eq!(value["threads"][0]["tid"], 77);
        assert_eq!(
            value["threads"][0]["start_address_source"],
            "minidump-context-rip"
        );
    }

    #[test]
    fn analyze_missing_file_errors() {
        let Err(err) = MinidumpSource::open(Path::new("no-such-file.dmp")) else {
            panic!("오류가 나야 함");
        };
        assert!(matches!(err, XmemError::DumpError { .. }));
    }
}
