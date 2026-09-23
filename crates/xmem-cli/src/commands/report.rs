//! `xmem report` — 분석 리포트(JSON/Markdown) 생성.

use std::path::Path;

use serde_json::json;
use xmem_core::Result;
use xmem_detection::{DetectionContext, detect};
use xmem_forensics::{ReportData, is_markdown, write_report};
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

/// 프로세스의 현재 관찰 상태로 리포트 데이터를 만든다(읽기 전용).
pub(crate) fn build_report(pid: u32) -> Result<ReportData> {
    let live = LiveProcess::open(pid)?;
    let regions = live.region_map()?.regions;
    let modules = live.modules()?;
    let threads = live.threads()?;
    let findings = detect(&DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    });
    Ok(ReportData::new(
        live.info.clone(),
        regions,
        modules,
        threads,
        findings,
    ))
}

pub fn run(pid: &PidArg, output: &str, global: &GlobalArgs) -> Result<()> {
    let data = build_report(pid.pid)?;
    let path = Path::new(output);
    let file_bytes = write_report(&data, path)?;
    let format = if is_markdown(path) {
        "markdown"
    } else {
        "json"
    };

    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "output": output,
                "format": format,
                "file_bytes": file_bytes,
                "process": { "pid": data.process.pid, "name": data.process.name },
                "region_count": data.regions.len(),
                "module_count": data.modules.len(),
                "thread_count": data.threads.len(),
                "finding_count": data.findings.len(),
            })));
            Ok(())
        }
        OutputMode::Human => {
            emit(&format!(
                "report written: {output} ({format}, {})\n",
                human_size(file_bytes)
            ));
            emit(&format!(
                "  process {} ({}) - regions {} / modules {} / threads {} / findings {}\n",
                data.process.name,
                data.process.pid,
                data.regions.len(),
                data.modules.len(),
                data.threads.len(),
                data.findings.len()
            ));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_report_of_self_is_populated() {
        let data = build_report(std::process::id()).expect("build report");
        assert_eq!(data.process.pid, std::process::id());
        assert!(!data.regions.is_empty());
        assert!(!data.modules.is_empty());
        assert_eq!(data.summary.regions_total, data.regions.len());
    }

    #[test]
    fn report_writes_markdown_for_md_extension() {
        let data = build_report(std::process::id()).expect("build report");
        let dir = std::env::temp_dir().join(format!("xmem-cli-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.md");

        let bytes = write_report(&data, &path).unwrap();
        assert!(bytes > 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# XMem Report"));
        assert!(text.contains("## Findings"));
        assert!(xmem_forensics::is_markdown(&path));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
