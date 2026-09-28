//! Ground Truth 회귀 테스트: xmem-target을 spawn하고 라이브 분석 결과를 대조한다.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use xmem_core::{MemorySource, RegionClass, ScanPattern};
use xmem_memory::{LiveProcess, ScanOptions, scan};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xmem-gt-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn_target(scenario: &str, report: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_xmem-target"))
        .args([
            "run",
            scenario,
            "--hold-secs",
            "30",
            "--report",
            report.to_str().unwrap(),
        ])
        .spawn()
        .unwrap()
}

fn wait_for_report(path: &Path) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(value) = serde_json::from_str(&text)
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "ground truth report가 생성되지 않았다"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn unloaded_candidates_detect_pe_like_scenario() {
    let dir = temp_dir("unloaded");
    let report_path = dir.join("report.json");
    let mut child = spawn_target("pe-like", &report_path);
    let report = wait_for_report(&report_path);
    let pid = report["pid"].as_u64().unwrap() as u32;
    let pe_base = report["artifacts"]["pe-like"]["base"].as_u64().unwrap();

    let live = LiveProcess::open(pid).unwrap();
    let candidates = live.unloaded_module_candidates().unwrap();
    assert!(
        candidates.iter().any(|candidate| candidate.base == pe_base),
        "pe-like base {pe_base:#x}가 언로드 후보에 없다: {candidates:?}"
    );

    child.kill().unwrap();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn all_scenario_matches_ground_truth() {
    let dir = temp_dir("all");
    let report_path = dir.join("report.json");
    let mut child = spawn_target("all", &report_path);
    let report = wait_for_report(&report_path);
    let pid = report["pid"].as_u64().unwrap() as u32;

    let live = LiveProcess::open(pid).unwrap();
    let regions = live.regions().unwrap();
    let findings = xmem_detection::detect_source(&live).unwrap();

    // 1) pattern 영역: private RW, ASCII 패턴이 base에 존재
    let pattern = &report["artifacts"]["pattern"];
    let pattern_base = pattern["base"].as_u64().unwrap();
    let region = regions
        .iter()
        .find(|r| r.base == pattern_base)
        .expect("pattern region");
    assert_eq!(region.classification, RegionClass::Private);
    assert!(region.writable && !region.executable);

    let needle = ScanPattern::ascii(pattern["ascii"].as_str().unwrap()).unwrap();
    let cancel = AtomicBool::new(false);
    let scan_report = scan(&live, &needle, &ScanOptions::default(), &cancel).unwrap();
    assert!(
        scan_report
            .matches
            .iter()
            .any(|m| m.address == pattern_base),
        "ascii 패턴이 pattern base에서 발견되어야 한다"
    );

    // 2) private-exec: executable private + XMEM-001
    let exec_base = report["artifacts"]["private-exec"]["base"]
        .as_u64()
        .unwrap();
    let exec_region = regions
        .iter()
        .find(|r| r.base == exec_base)
        .expect("private-exec region");
    assert!(exec_region.executable);
    assert_eq!(exec_region.classification, RegionClass::Private);
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "XMEM-001" && f.evidence[0].region_base == Some(exec_base)),
        "XMEM-001 at private-exec"
    );

    // 3) pe-like: XMEM-002
    let pe_base = report["artifacts"]["pe-like"]["base"].as_u64().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.rule_id == "XMEM-002" && f.evidence[0].region_base == Some(pe_base)),
        "XMEM-002 at pe-like"
    );

    // 4) suspended thread: XMEM-004 (tid 일치)
    let tid = report["artifacts"]["threads"]["tid"].as_u64().unwrap() as u32;
    let tid_text = tid.to_string();
    assert!(
        findings.iter().any(|f| f.rule_id == "XMEM-004"
            && f.evidence[0].observed.get("tid").map(String::as_str) == Some(tid_text.as_str())),
        "XMEM-004 for target thread {tid}"
    );

    child.kill().unwrap();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
