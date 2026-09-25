use std::path::Path;

use serde_json::{Value, json};
use xmem_core::{Finding, FindingFilter, ProcessInfo, Result, severity_rank};
use xmem_detection::detect_source;
use xmem_memory::LiveProcess;

use crate::cli::{ConfidenceArg, DetectArgs, DetectSortArg, GlobalArgs, SeverityArg};
use crate::commands::export::{ExportPayload, emit_export_saved, write_export};
use crate::commands::render::opt_hex;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(args: &DetectArgs, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid.pid)?;
    let filter = FindingFilter {
        min_severity: args.min_severity.map(SeverityArg::to_severity),
        min_confidence: args.min_confidence.map(ConfidenceArg::to_confidence),
        rule_id: args.rule.clone(),
    };
    let mut findings: Vec<Finding> = detect_source(&live)?
        .into_iter()
        .filter(|finding| filter.matches(finding))
        .collect();
    sort_findings(&mut findings, args.sort);
    if let Some(output) = args.output.output.as_deref() {
        let bytes = write_export(
            Path::new(output),
            args.output.format,
            &ExportPayload::Detect(&findings),
        )?;
        emit_export_saved(
            output,
            args.output.format,
            bytes,
            findings.len(),
            "detect",
            global,
        );
        return Ok(());
    }
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(detect_json_payload(
                &live.info, &findings,
            )));
            Ok(())
        }
        OutputMode::Human => {
            emit(&render_findings(&live.info, &findings));
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

/// 첫 evidence의 address(없으면 region_base)를 정렬 기준 주소로 쓴다.
fn finding_address(finding: &Finding) -> u64 {
    finding
        .evidence
        .first()
        .and_then(|evidence| evidence.address.or(evidence.region_base))
        .unwrap_or(u64::MAX)
}

/// `--sort`. rule은 기존 detect()의 rule→주소 순서를 안정 정렬로 유지한다.
pub(crate) fn sort_findings(findings: &mut [Finding], sort: DetectSortArg) {
    match sort {
        DetectSortArg::Rule => findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id)),
        DetectSortArg::Address => findings.sort_by(|a, b| {
            finding_address(a)
                .cmp(&finding_address(b))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        }),
        DetectSortArg::Severity => findings.sort_by(|a, b| {
            severity_rank(b.severity)
                .cmp(&severity_rank(a.severity))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| finding_address(a).cmp(&finding_address(b)))
        }),
    }
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

    fn finding_at(
        rule: &str,
        severity: Severity,
        confidence: Confidence,
        region_base: u64,
    ) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            name: "Executable Private Memory".to_string(),
            severity,
            confidence,
            evidence: vec![
                Evidence::new("region")
                    .with_region_base(region_base)
                    .observe("protection", "RWX (0x40)")
                    .observe("state", "MEM_COMMIT"),
            ],
            heuristic: "private memory with executable protection".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }
    }

    fn sample_finding() -> Finding {
        finding_at("XMEM-001", Severity::Medium, Confidence::High, 0x1000)
    }

    #[test]
    fn finding_filter_reduces_findings_and_keeps_json_shape() {
        let findings = vec![
            sample_finding(),
            finding_at("XMEM-002", Severity::High, Confidence::Medium, 0x2000),
        ];
        let filter = FindingFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        let filtered: Vec<Finding> = findings
            .into_iter()
            .filter(|finding| filter.matches(finding))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].rule_id, "XMEM-002");
        let payload = detect_json_payload(&sample_info(), &filtered);
        assert_eq!(payload["finding_count"], 1);
        assert_eq!(payload["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sort_findings_orders_by_requested_key() {
        let mut findings = vec![
            finding_at("XMEM-005", Severity::High, Confidence::High, 0x3000),
            finding_at("XMEM-001", Severity::Medium, Confidence::High, 0x1000),
            finding_at("XMEM-003", Severity::High, Confidence::Medium, 0x2000),
        ];
        sort_findings(&mut findings, DetectSortArg::Severity);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(rules, vec!["XMEM-003", "XMEM-005", "XMEM-001"]);

        sort_findings(&mut findings, DetectSortArg::Address);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(rules, vec!["XMEM-001", "XMEM-003", "XMEM-005"]);

        sort_findings(&mut findings, DetectSortArg::Rule);
        let rules: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(rules, vec!["XMEM-001", "XMEM-003", "XMEM-005"]);
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
