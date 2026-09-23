use serde_json::json;
use xmem_core::{Result, XmemError};
use xmem_experiments::{EXPERIMENTS, ExperimentReport, RunOptions, run_experiment};

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
                    emit(&render_experiment_report(&report));
                    Ok(())
                }
            }
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
}
