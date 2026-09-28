//! 분석 리포트(JSON/Markdown) 생성과 저장.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;
use xmem_core::{
    Confidence, Evidence, Finding, JSON_SCHEMA_VERSION, MemoryRegion, MemoryState, ModuleInfo,
    ProcessArch, ProcessInfo, RegionClass, Result, Severity, ThreadInfo, VERSION, XmemError,
};
use xmem_detection::{RiskScore, risk_score};

/// 리포트 요약 카운트.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportSummary {
    pub regions_total: usize,
    pub committed: usize,
    pub reserved: usize,
    pub free: usize,
    pub image: usize,
    pub mapped: usize,
    pub private: usize,
    pub executable: usize,
    pub committed_bytes: u64,
    pub module_count: usize,
    pub thread_count: usize,
    pub finding_count: usize,
}

/// 분석 리포트 데이터(JSON/Markdown 공통 소스).
#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    pub generated_at: DateTime<Utc>,
    pub xmem_version: String,
    pub schema_version: u32,
    pub process: ProcessInfo,
    pub regions: Vec<MemoryRegion>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub findings: Vec<Finding>,
    /// findings에서 계산한 위험도 요약(휴리스틱).
    pub risk: RiskScore,
    pub summary: ReportSummary,
}

impl ReportData {
    pub fn new(
        process: ProcessInfo,
        regions: Vec<MemoryRegion>,
        modules: Vec<ModuleInfo>,
        threads: Vec<ThreadInfo>,
        findings: Vec<Finding>,
    ) -> Self {
        let mut summary = ReportSummary {
            regions_total: regions.len(),
            module_count: modules.len(),
            thread_count: threads.len(),
            finding_count: findings.len(),
            ..Default::default()
        };
        for region in &regions {
            match region.state {
                MemoryState::Commit => {
                    summary.committed += 1;
                    summary.committed_bytes = summary.committed_bytes.saturating_add(region.size);
                }
                MemoryState::Reserve => summary.reserved += 1,
                MemoryState::Free => summary.free += 1,
            }
            match region.classification {
                RegionClass::Image => summary.image += 1,
                RegionClass::Mapped => summary.mapped += 1,
                RegionClass::Private => summary.private += 1,
                _ => {}
            }
            if region.executable {
                summary.executable += 1;
            }
        }
        Self {
            generated_at: Utc::now(),
            xmem_version: VERSION.to_string(),
            schema_version: JSON_SCHEMA_VERSION,
            process,
            regions,
            modules,
            threads,
            risk: risk_score(&findings),
            findings,
            summary,
        }
    }
}

/// 출력 경로의 확장자가 `md`면 Markdown 리포트로 저장한다.
pub fn is_markdown(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("md"))
}

pub fn to_json(data: &ReportData) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(data).map_err(|e| XmemError::JsonError {
        reason: e.to_string(),
    })
}

pub fn to_markdown(data: &ReportData) -> String {
    let mut out = String::new();
    out.push_str("# XMem Report\n\n");
    out.push_str(&format!(
        "- generated: {}\n",
        data.generated_at.to_rfc3339()
    ));
    out.push_str(&format!("- xmem version: {}\n", data.xmem_version));
    out.push_str(&format!("- schema version: {}\n\n", data.schema_version));

    out.push_str("## Process\n\n");
    out.push_str(&format!("- pid: {}\n", data.process.pid));
    out.push_str(&format!("- name: {}\n", data.process.name));
    out.push_str(&format!("- arch: {}\n", arch_text(data.process.arch)));
    if let Some(path) = &data.process.image_path {
        out.push_str(&format!("- image: {path}\n"));
    }
    out.push('\n');

    out.push_str("## Memory Summary\n\n");
    out.push_str("| metric | value |\n|---|---|\n");
    out.push_str(&format!("| regions | {} |\n", data.summary.regions_total));
    out.push_str(&format!("| committed | {} |\n", data.summary.committed));
    out.push_str(&format!("| reserved | {} |\n", data.summary.reserved));
    out.push_str(&format!("| free | {} |\n", data.summary.free));
    out.push_str(&format!("| image | {} |\n", data.summary.image));
    out.push_str(&format!("| mapped | {} |\n", data.summary.mapped));
    out.push_str(&format!("| private | {} |\n", data.summary.private));
    out.push_str(&format!("| executable | {} |\n", data.summary.executable));
    out.push_str(&format!(
        "| committed bytes | {} |\n\n",
        data.summary.committed_bytes
    ));

    out.push_str("## Risk\n\n");
    out.push_str(&format!(
        "Score: {} / 100 ({})\n",
        data.risk.score,
        data.risk.level.as_str()
    ));
    out.push_str(&format!(
        "- findings: {}, by severity: info {} / low {} / medium {} / high {} / critical {}\n\n",
        data.risk.findings,
        data.risk.by_severity.info,
        data.risk.by_severity.low,
        data.risk.by_severity.medium,
        data.risk.by_severity.high,
        data.risk.by_severity.critical,
    ));

    out.push_str("## Findings\n\n");
    if data.findings.is_empty() {
        out.push_str("No findings. Absence of findings is not proof of safety.\n\n");
    } else {
        for finding in &data.findings {
            out.push_str(&format!(
                "### {} {} [{}/{}]\n\n",
                finding.rule_id,
                finding.name,
                severity_text(finding.severity),
                confidence_text(finding.confidence)
            ));
            out.push_str(&format!("- heuristic: {}\n", finding.heuristic));
            out.push_str(&format!("- interpretation: {}\n", finding.interpretation));
            for evidence in &finding.evidence {
                out.push_str(&format!(
                    "- evidence: {} {}\n",
                    evidence.kind,
                    evidence_location(evidence)
                ));
            }
            out.push('\n');
        }
    }

    out.push_str("## Regions\n\n");
    out.push_str(
        "| base | size | state | type | protection | class | mapped file |\n|---|---|---|---|---|---|---|\n",
    );
    for region in &data.regions {
        if region.classification == RegionClass::Free {
            continue;
        }
        out.push_str(&format!(
            "| {:#x} | {} | {} | {} | {} | {} | {} |\n",
            region.base,
            region.size,
            region.state,
            region
                .region_type
                .map(|ty| ty.to_string())
                .unwrap_or_else(|| "-".to_string()),
            region.protection,
            region.classification,
            region.mapped_file.as_deref().unwrap_or("-"),
        ));
    }
    out.push('\n');

    out.push_str("## Modules\n\n");
    if data.modules.is_empty() {
        out.push_str("No modules collected.\n\n");
    } else {
        out.push_str("| name | base | size | path |\n|---|---|---|---|\n");
        for module in &data.modules {
            out.push_str(&format!(
                "| {} | {:#x} | {} | {} |\n",
                module.name,
                module.base,
                module.size,
                module.path.as_deref().unwrap_or("-")
            ));
        }
        out.push('\n');
    }

    out.push_str("## Threads\n\n");
    if data.threads.is_empty() {
        out.push_str("No threads collected.\n");
    } else {
        out.push_str(
            "| tid | priority | start address | region | module |\n|---|---|---|---|---|\n",
        );
        for thread in &data.threads {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                thread.tid,
                thread
                    .priority
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                thread
                    .start_address
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "-".to_string()),
                thread
                    .start_region_base
                    .map(|a| format!("{a:#x}"))
                    .unwrap_or_else(|| "-".to_string()),
                thread.start_module.as_deref().unwrap_or("-"),
            ));
        }
    }

    out
}

/// 리포트를 저장한다(temp → rename). 저장된 파일 크기를 반환한다.
pub fn write_report(data: &ReportData, path: &Path) -> Result<u64> {
    let temp = PathBuf::from(format!("{}.tmp-{}", path.display(), std::process::id()));
    let result = (|| -> Result<u64> {
        let bytes = if is_markdown(path) {
            to_markdown(data).into_bytes()
        } else {
            to_json(data)?
        };
        std::fs::write(&temp, &bytes).map_err(XmemError::Io)?;
        std::fs::rename(&temp, path).map_err(XmemError::Io)?;
        Ok(bytes.len() as u64)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn arch_text(arch: ProcessArch) -> &'static str {
    match arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
    }
}

fn evidence_location(evidence: &Evidence) -> String {
    let mut location = String::new();
    if let Some(region) = evidence.region_base {
        location.push_str(&format!("region {region:#x}"));
    }
    if let Some(address) = evidence.address {
        if !location.is_empty() {
            location.push(' ');
        }
        location.push_str(&format!("address {address:#x}"));
    }
    if location.is_empty() {
        location.push('-');
    }
    location
}

fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn confidence_text(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        Confidence, Evidence, Finding, MemoryRegion, MemoryState, MemoryType, ModuleInfo,
        ProcessArch, ProcessInfo, Protection, RegionClass, Severity, ThreadInfo,
    };

    fn sample_region(base: u64, size: u64, class: RegionClass, executable: bool) -> MemoryRegion {
        let raw = if executable { 0x20 } else { 0x04 };
        let protection = Protection::new(raw, true, !executable, executable);
        MemoryRegion {
            base,
            size,
            allocation_base: Some(base),
            state: if class == RegionClass::Free {
                MemoryState::Free
            } else {
                MemoryState::Commit
            },
            protection,
            allocation_protection: None,
            region_type: match class {
                RegionClass::Image => Some(MemoryType::Image),
                RegionClass::Private => Some(MemoryType::Private),
                RegionClass::Mapped => Some(MemoryType::Mapped),
                _ => None,
            },
            readable: protection.readable,
            writable: protection.writable,
            executable: protection.executable,
            classification: class,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    fn sample_process() -> ProcessInfo {
        ProcessInfo {
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
            thread_count: Some(1),
            module_count: Some(1),
        }
    }

    fn sample_report() -> ReportData {
        let regions = vec![
            sample_region(0x1000, 0x1000, RegionClass::Private, false),
            sample_region(0x4000, 0x2000, RegionClass::Image, true),
            sample_region(0x8000, 0x1000, RegionClass::Free, false),
        ];
        let modules = vec![ModuleInfo {
            name: "sample.exe".to_string(),
            base: 0x4000,
            size: 0x1000,
            path: Some(r"C:\x\sample.exe".to_string()),
            arch: Some(ProcessArch::X64),
        }];
        let threads = vec![ThreadInfo {
            tid: 77,
            pid: 4242,
            priority: Some(8),
            start_address: Some(0x4000),
            start_region_base: Some(0x4000),
            start_module: Some("sample.exe".to_string()),
        }];
        let findings = vec![Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "Executable Private Memory".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }];
        ReportData::new(sample_process(), regions, modules, threads, findings)
    }

    #[test]
    fn new_builds_summary_counts() {
        let report = sample_report();
        assert_eq!(report.summary.regions_total, 3);
        assert_eq!(report.summary.committed, 2);
        assert_eq!(report.summary.free, 1);
        assert_eq!(report.summary.private, 1);
        assert_eq!(report.summary.image, 1);
        assert_eq!(report.summary.executable, 1);
        assert_eq!(report.summary.committed_bytes, 0x3000);
        assert_eq!(report.summary.module_count, 1);
        assert_eq!(report.summary.thread_count, 1);
        assert_eq!(report.summary.finding_count, 1);
    }

    #[test]
    fn markdown_contains_sections_and_findings() {
        let text = to_markdown(&sample_report());
        for needle in [
            "# XMem Report",
            "## Process",
            "## Memory Summary",
            "## Risk",
            "## Findings",
            "XMEM-001",
            "sample.exe",
        ] {
            assert!(text.contains(needle), "missing: {needle}");
        }
    }

    #[test]
    fn report_risk_matches_findings() {
        let report = sample_report();
        assert_eq!(
            report.risk,
            xmem_detection::risk_score(&report.findings),
            "risk는 findings에서 계산된다"
        );
        assert_eq!(report.risk.score, 13, "Medium+High confidence");
        assert_eq!(report.risk.level, xmem_detection::RiskLevel::Low);
        let text = to_markdown(&report);
        assert!(text.contains("## Risk"), "{text}");
        assert!(text.contains("Score: 13 / 100 (low)"), "{text}");
    }

    #[test]
    fn write_report_writes_json_and_markdown() {
        let dir = std::env::temp_dir().join(format!("xmem-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let json_path = dir.join("report.json");
        let md_path = dir.join("report.md");

        let json_bytes = write_report(&sample_report(), &json_path).unwrap();
        assert!(json_bytes > 0);
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
        assert_eq!(parsed["process"]["pid"], 4242);

        write_report(&sample_report(), &md_path).unwrap();
        let md = std::fs::read_to_string(&md_path).unwrap();
        assert!(md.contains("## Findings"));

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp 파일이 남았다");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
