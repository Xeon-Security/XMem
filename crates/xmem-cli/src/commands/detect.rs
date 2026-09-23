use serde_json::{Value, json};
use xmem_core::{Finding, ProcessInfo, Result};
use xmem_detection::detect_source;
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::opt_hex;
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(args: &PidArg, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid)?;
    let findings = detect_source(&live)?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(detect_json_payload(
                &live.info, &findings,
            )));
            Ok(())
        }
        OutputMode::Human => {
            print!("{}", render_findings(&live.info, &findings));
            Ok(())
        }
    }
}

pub(crate) fn render_findings(info: &ProcessInfo, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}) - {} findings\n",
        info.name,
        info.pid,
        findings.len()
    ));
    if findings.is_empty() {
        out.push_str("no findings (absence of findings is not proof of safety)\n");
        return out;
    }
    for finding in findings {
        out.push_str(&format!(
            "\n{} {} [{}/{}]\n",
            finding.rule_id,
            finding.name,
            severity_text(finding.severity),
            confidence_text(finding.confidence),
        ));
        for evidence in &finding.evidence {
            let location = match (evidence.region_base, evidence.address) {
                (Some(base), _) => format!("region {}", opt_hex(Some(base))),
                (None, Some(address)) => format!("address {}", opt_hex(Some(address))),
                (None, None) => "evidence".to_string(),
            };
            out.push_str(&format!("  {} ({})\n", location, evidence.kind));
            for (key, value) in &evidence.observed {
                out.push_str(&format!("    {key}: {value}\n"));
            }
        }
        out.push_str(&format!("  heuristic: {}\n", finding.heuristic));
        out.push_str(&format!("  interpretation: {}\n", finding.interpretation));
    }
    out
}

pub(crate) fn detect_json_payload(info: &ProcessInfo, findings: &[Finding]) -> Value {
    json!({
        "process": { "pid": info.pid, "name": info.name },
        "finding_count": findings.len(),
        "findings": findings,
    })
}

fn severity_text(severity: xmem_core::Severity) -> &'static str {
    match severity {
        xmem_core::Severity::Info => "info",
        xmem_core::Severity::Low => "low",
        xmem_core::Severity::Medium => "medium",
        xmem_core::Severity::High => "high",
        xmem_core::Severity::Critical => "critical",
    }
}

fn confidence_text(confidence: xmem_core::Confidence) -> &'static str {
    match confidence {
        xmem_core::Confidence::Low => "low",
        xmem_core::Confidence::Medium => "medium",
        xmem_core::Confidence::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, Finding, ProcessArch, ProcessInfo, Severity};

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 321,
            ppid: None,
            name: "sample.exe".to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![
                Evidence::new("region")
                    .with_region_base(0x1000)
                    .observe("protection", "RWX (0x40)")
                    .observe("state", "MEM_COMMIT"),
            ],
            heuristic: "private memory with executable protection".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }
    }

    #[test]
    fn render_findings_lists_rules_evidence_and_summary() {
        let text = render_findings(&sample_info(), &[sample_finding()]);
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("medium"));
        assert!(text.contains("high"));
        assert!(text.contains("protection"));
        assert!(text.contains("Potentially suspicious"));
        assert!(text.contains("1 findings"));
    }

    #[test]
    fn render_findings_reports_zero_case_not_proof() {
        let text = render_findings(&sample_info(), &[]);
        assert!(text.contains("0 findings"));
        assert!(text.contains("not proof"));
    }

    #[test]
    fn detect_json_payload_shape() {
        let payload = detect_json_payload(&sample_info(), &[sample_finding()]);
        assert_eq!(payload["process"]["pid"], 321);
        assert_eq!(payload["finding_count"], 1);
        assert!(payload["findings"].is_array());
        assert_eq!(payload["findings"][0]["rule_id"], "XMEM-001");
    }

    #[test]
    fn detect_self_returns_findings_without_panic() {
        let live = xmem_memory::LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let findings = xmem_detection::detect_source(&live).unwrap();
        let text = render_findings(&live.info, &findings);
        assert!(text.contains("findings"));
    }
}
