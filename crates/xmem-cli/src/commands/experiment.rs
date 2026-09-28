use serde_json::json;
use xmem_core::{Result, XmemError};
use xmem_experiments::{
    EXPERIMENTS, ExperimentReport, RunOptions, append, history_path, load, regressions,
    run_experiment,
};

use crate::cli::{ExperimentCmd, GlobalArgs};
use crate::commands::memory::cancel_flag;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(cmd: &ExperimentCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        ExperimentCmd::List => match resolve_mode(global.json) {
            OutputMode::Json => {
                let items: Vec<serde_json::Value> = EXPERIMENTS
                    .iter()
                    .map(|meta| {
                        json!({
                            "name": meta.name,
                            "description": meta.description,
                            "scenario": meta.scenario,
                            "expected_rule": meta.expected_rule,
                        })
                    })
                    .collect();
                emit_json(&success_envelope(json!({ "experiments": items })));
                Ok(())
            }
            OutputMode::Human => {
                emit(&render_experiment_list());
                Ok(())
            }
        },
        ExperimentCmd::Run { name } => {
            let cancel = cancel_flag();
            let report = run_experiment(name, &RunOptions::default(), &cancel)?;
            // 이력 기록 실패가 실험 결과를 뒤집지 않는다(경고만).
            let path = history_path();
            let logged = match append(&report, &path) {
                Ok(()) => Some(path),
                Err(err) => {
                    tracing::warn!("실험 이력 기록 실패: {err}");
                    None
                }
            };
            match resolve_mode(global.json) {
                OutputMode::Json => {
                    let value =
                        serde_json::to_value(&report).map_err(|e| XmemError::JsonError {
                            reason: e.to_string(),
                        })?;
                    emit_json(&success_envelope(value));
                    Ok(())
                }
                OutputMode::Human => {
                    let mut text = render_experiment_report(&report);
                    if let Some(path) = logged {
                        text.push_str(&format!("  logged to {}\n", path.display()));
                    }
                    emit(&text);
                    Ok(())
                }
            }
        }
        ExperimentCmd::History { json } => run_history(*json, global),
    }
}

fn run_history(json_flag: bool, global: &GlobalArgs) -> Result<()> {
    let reports = load(&history_path());
    match resolve_mode(json_flag || global.json) {
        OutputMode::Json => {
            let items: Vec<serde_json::Value> = reports
                .iter()
                .filter_map(|report| serde_json::to_value(report).ok())
                .collect();
            emit_json(&success_envelope(json!({ "history": items })));
            Ok(())
        }
        OutputMode::Human => {
            emit(&render_history(&reports, &regressions(&reports)));
            Ok(())
        }
    }
}

pub(crate) fn render_experiment_list() -> String {
    let mut out = String::from("experiments:\n");
    for meta in EXPERIMENTS {
        out.push_str(&format!(
            "  {:<16} {:<26} scenario {:<8} expects {}\n",
            meta.name, meta.description, meta.scenario, meta.expected_rule
        ));
    }
    out
}

pub(crate) fn render_experiment_report(report: &ExperimentReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("experiment {}\n", report.name));
    out.push_str(&format!("  {}\n", report.description));
    out.push_str(&format!(
        "  target pid {} ({}) in {} ms\n",
        report.target_pid, report.scenario, report.elapsed_ms
    ));
    out.push_str(&format!(
        "  baseline findings {} -> post findings {} (detections +{} -{})\n",
        report.baseline_findings,
        report.post_findings,
        report.detections_added,
        report.detections_removed
    ));
    out.push_str(&format!(
        "  expected {}: baseline {} / post {}\n",
        report.expected_rule,
        if report.expected_present {
            "present"
        } else {
            "absent"
        },
        if report.expected_observed {
            "observed"
        } else {
            "missing"
        },
    ));
    if let Some(base) = report.expected_region {
        out.push_str(&format!("  artifact region {base:#018x}\n"));
    }
    out.push_str(&format!("  cleanup: {}\n", report.cleanup));
    out
}

/// 이력 표. ExperimentReport에 실행 시각 필드가 없어 순서가 곧 시간 순서다.
pub(crate) fn render_history(reports: &[ExperimentReport], regressions: &[String]) -> String {
    let mut out = String::new();
    out.push_str(&format!("experiment history ({} runs)\n", reports.len()));
    if reports.is_empty() {
        out.push_str("  no runs recorded\n");
        return out;
    }
    out.push_str(&format!(
        "{:<16} {:>6} {:>9} {:>6} {:>10} {:>10}  {}\n",
        "NAME", "PID", "BASELINE", "POST", "ELAPSED", "EXPECTED", "RESULT"
    ));
    for report in reports {
        out.push_str(&format!(
            "{:<16} {:>6} {:>9} {:>6} {:>7}ms {:>10}  {}\n",
            report.name,
            report.target_pid,
            report.baseline_findings,
            report.post_findings,
            report.elapsed_ms,
            report.expected_rule,
            if report.expected_observed {
                "observed"
            } else {
                "missing"
            },
        ));
    }
    for regression in regressions {
        out.push_str(&format!("WARN: {regression}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_experiments::{EXPERIMENTS, ExperimentReport};

    fn sample_report() -> ExperimentReport {
        ExperimentReport {
            name: "remote-alloc".to_string(),
            description: "desc".to_string(),
            scenario: "normal".to_string(),
            target_pid: 777,
            expected_rule: "XMEM-001".to_string(),
            expected_present: false,
            expected_observed: true,
            expected_region: Some(0x1000),
            baseline_findings: 0,
            post_findings: 2,
            detections_added: 1,
            detections_removed: 0,
            elapsed_ms: 42,
            cleanup: "target terminated, temp files removed".to_string(),
        }
    }

    #[test]
    fn render_experiment_list_lists_all() {
        let text = render_experiment_list();
        for meta in EXPERIMENTS {
            assert!(text.contains(meta.name), "{} 누락", meta.name);
        }
        assert!(text.contains("XMEM-001"));
    }

    #[test]
    fn render_experiment_report_shows_verification() {
        let text = render_experiment_report(&sample_report());
        assert!(text.contains("remote-alloc"));
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("observed"));
        assert!(text.contains("terminated"));
    }

    #[test]
    fn history_renders_runs_and_warnings() {
        let mut missed = sample_report();
        missed.expected_observed = false;
        let text = render_history(
            &[sample_report(), missed],
            &["회귀: remote-alloc".to_string()],
        );
        assert!(text.contains("2 runs"));
        assert!(text.contains("remote-alloc"));
        assert!(text.contains("observed"));
        assert!(text.contains("missing"));
        assert!(text.contains("WARN: 회귀: remote-alloc"));
        let empty = render_history(&[], &[]);
        assert!(empty.contains("no runs recorded"));
    }
}
