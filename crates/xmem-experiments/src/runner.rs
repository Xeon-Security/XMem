//! Baseline → Action → Post → Diff → Detection 실험 파이프라인.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::Serialize;
use xmem_core::{Result, XmemError};
use xmem_forensics::{CollectOptions, collect, diff};
use xmem_memory::LiveProcess;
use xmem_windows::open_for_experiment;

use crate::experiments::{Expectation, execute_action, experiment, finding_matches};
use crate::target::{RunOptions, TargetGuard};

/// 실험 실행 결과.
#[derive(Debug, Clone, Serialize)]
pub struct ExperimentReport {
    pub name: String,
    pub description: String,
    pub scenario: String,
    pub target_pid: u32,
    pub expected_rule: String,
    pub expected_present: bool,
    pub expected_observed: bool,
    pub expected_region: Option<u64>,
    pub baseline_findings: usize,
    pub post_findings: usize,
    pub detections_added: usize,
    pub detections_removed: usize,
    pub elapsed_ms: u64,
    pub cleanup: String,
}

/// 실험 파이프라인을 실행한다: spawn → baseline → action → post → diff.
pub fn run_experiment(
    name: &str,
    options: &RunOptions,
    cancel: &AtomicBool,
) -> Result<ExperimentReport> {
    let meta = experiment(name)?;
    let started = Instant::now();
    let guard = TargetGuard::spawn(options, meta.scenario)?;
    check_cancel(cancel)?;

    let live = LiveProcess::open(guard.pid)?;
    let baseline = collect(&live, &CollectOptions::default(), cancel)?;
    check_cancel(cancel)?;

    let handle = open_for_experiment(guard.pid)?;
    let expectation = execute_action(meta, &handle, &guard)?;
    check_cancel(cancel)?;

    let post = collect(&live, &CollectOptions::default(), cancel)?;
    let delta = diff(&baseline, &post);

    let expected_present = baseline
        .findings
        .iter()
        .any(|f| finding_matches(f, meta.expected_rule, expectation));
    let expected_observed = post
        .findings
        .iter()
        .any(|f| finding_matches(f, meta.expected_rule, expectation));

    let report = ExperimentReport {
        name: meta.name.to_string(),
        description: meta.description.to_string(),
        scenario: meta.scenario.to_string(),
        target_pid: guard.pid,
        expected_rule: meta.expected_rule.to_string(),
        expected_present,
        expected_observed,
        expected_region: match expectation {
            Expectation::Region(base) => Some(base),
            Expectation::Tid(_) => None,
        },
        baseline_findings: baseline.findings.len(),
        post_findings: post.findings.len(),
        detections_added: delta.summary.detections_added,
        detections_removed: delta.summary.detections_removed,
        elapsed_ms: started.elapsed().as_millis() as u64,
        cleanup: String::new(),
    };

    drop(handle);
    drop(live);
    drop(guard);

    Ok(ExperimentReport {
        cleanup: "target terminated, temp files removed".to_string(),
        ..report
    })
}

fn check_cancel(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::Relaxed) {
        return Err(XmemError::Cancelled {
            reason: "user interrupt".to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::XmemError;

    #[test]
    fn unknown_experiment_name_lists_available() {
        let err =
            run_experiment("no-such", &RunOptions::default(), &AtomicBool::new(false)).unwrap_err();
        match err {
            XmemError::InvalidInput { reason } => {
                assert!(reason.contains("no-such"));
                assert!(reason.contains("remote-alloc"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
