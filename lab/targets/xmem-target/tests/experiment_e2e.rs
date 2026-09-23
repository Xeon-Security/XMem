#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! M11 파이프라인 e2e: Baseline → Action → Post → 판정.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use xmem_experiments::experiments::EXPERIMENTS;
use xmem_experiments::runner::run_experiment;
use xmem_experiments::target::RunOptions;

#[test]
fn all_experiments_produce_expected_artifacts() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_xmem-target"));
    let options = RunOptions {
        target_binary: Some(binary),
        hold_secs: 30,
    };
    let cancel = AtomicBool::new(false);
    for meta in EXPERIMENTS {
        let report = run_experiment(meta.name, &options, &cancel)
            .unwrap_or_else(|e| panic!("{} 실패: {e}", meta.name));
        assert!(
            !report.expected_present,
            "{}: baseline에 이미 {} finding이 있었다",
            meta.name, meta.expected_rule
        );
        assert!(
            report.expected_observed,
            "{}: post에서 {} finding을 기대 영역에서 찾지 못했다",
            meta.name, meta.expected_rule
        );
        assert!(report.cleanup.contains("terminated"), "{}", meta.name);
        assert!(
            report.post_findings >= 1,
            "{}: post finding이 없다",
            meta.name
        );
    }
}

#[test]
fn experiment_target_is_terminated_after_run() {
    let binary = PathBuf::from(env!("CARGO_BIN_EXE_xmem-target"));
    let options = RunOptions {
        target_binary: Some(binary),
        hold_secs: 30,
    };
    let cancel = AtomicBool::new(false);
    let report = run_experiment("remote-alloc", &options, &cancel).unwrap();
    let pid = report.target_pid;
    std::thread::sleep(std::time::Duration::from_millis(300));
    let alive = xmem_windows::process_info(pid).is_ok();
    assert!(!alive, "target {pid}가 아직 살아 있다");
}
