//! `xmem bench` — (개발용) 주요 분석 경로의 반복 실행 시간 측정.

use std::sync::atomic::AtomicBool;
use std::time::Instant;

use serde_json::{Value, json};
use xmem_core::{Result, ScanPattern, XmemError};
use xmem_forensics::{CollectOptions, collect};
use xmem_memory::{LiveProcess, ScanOptions, scan};

use crate::cli::{BenchArgs, GlobalArgs};
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub const SCENARIOS: [&str; 6] = ["map", "scan", "detect", "modules", "threads", "snapshot"];

#[derive(Debug, Clone)]
pub struct BenchRow {
    pub scenario: String,
    pub min_ms: f64,
    pub median_ms: f64,
    pub max_ms: f64,
    pub detail: String,
}

/// 측정값(ms)의 최소/중앙/최대를 돌려준다.
/// 중앙값은 정렬 후 가운데 값이며, 짝수 개면 상위 가운데 값을 쓴다.
pub fn summarize(samples: &mut [f64]) -> (f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let min = samples.first().copied().unwrap_or(0.0);
    let max = samples.last().copied().unwrap_or(0.0);
    let median = if samples.is_empty() {
        0.0
    } else {
        samples[samples.len() / 2]
    };
    (min, median, max)
}

/// `iterations`번 실행하며 각 실행 시간을 모아 요약한다. 마지막 실행의 상세 문자열을 함께 돌려준다.
fn measure(
    iterations: u32,
    mut body: impl FnMut() -> Result<String>,
) -> Result<(f64, f64, f64, String)> {
    let mut samples = Vec::with_capacity(iterations as usize);
    let mut detail = String::new();
    for _ in 0..iterations {
        let started = Instant::now();
        detail = body()?;
        samples.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    let (min, median, max) = summarize(&mut samples);
    Ok((min, median, max, detail))
}

fn known_scenarios(name: &str) -> Result<Vec<&'static str>> {
    if name == "all" {
        return Ok(SCENARIOS.to_vec());
    }
    if let Some(found) = SCENARIOS.iter().find(|scenario| **scenario == name) {
        return Ok(vec![*found]);
    }
    Err(XmemError::InvalidInput {
        reason: format!(
            "알 수 없는 시나리오: {name} (가능: all, {})",
            SCENARIOS.join(", ")
        ),
    })
}

pub fn run(args: &BenchArgs, global: &GlobalArgs) -> Result<()> {
    if args.iterations == 0 {
        return Err(XmemError::InvalidInput {
            reason: "--iterations는 1 이상이어야 합니다".to_string(),
        });
    }
    let scenarios = known_scenarios(&args.scenario)?;
    let live = LiveProcess::open(args.pid.pid)?;
    let cancel = AtomicBool::new(false);
    let pattern = ScanPattern::ascii("XMEM_PATTERN_ALPHA_0123456789")?;
    let scan_options = ScanOptions {
        max_results: 32,
        ..ScanOptions::default()
    };
    let collect_options = CollectOptions::default();

    let mut rows: Vec<BenchRow> = Vec::new();
    for scenario in scenarios {
        let (min_ms, median_ms, max_ms, detail) = match scenario {
            "map" => measure(args.iterations, || {
                let map = live.region_map()?;
                Ok(format!("{} regions", map.regions.len()))
            })?,
            "scan" => measure(args.iterations, || {
                let report = scan(&live, &pattern, &scan_options, &cancel)?;
                Ok(format!(
                    "{} matches / {} regions",
                    report.matches.len(),
                    report.stats.regions_scanned
                ))
            })?,
            "detect" => measure(args.iterations, || {
                let findings = xmem_detection::detect_source(&live)?;
                Ok(format!("{} findings", findings.len()))
            })?,
            "modules" => measure(args.iterations, || {
                let modules = live.modules()?;
                Ok(format!("{} modules", modules.len()))
            })?,
            "threads" => measure(args.iterations, || {
                let threads = live.threads()?;
                Ok(format!("{} threads", threads.len()))
            })?,
            "snapshot" => measure(args.iterations, || {
                let envelope = collect(&live, &collect_options, &cancel)?;
                Ok(format!("{} hashed regions", envelope.content_hashes.len()))
            })?,
            other => {
                return Err(XmemError::InvalidInput {
                    reason: format!("시나리오 미구현: {other}"),
                });
            }
        };
        rows.push(BenchRow {
            scenario: scenario.to_string(),
            min_ms,
            median_ms,
            max_ms,
            detail,
        });
    }

    match resolve_mode(global.json) {
        OutputMode::Json => emit_json(&success_envelope(json!({
            "pid": live.info.pid,
            "name": live.info.name,
            "iterations": args.iterations,
            "rows": rows
                .iter()
                .map(|row| json!({
                    "scenario": row.scenario,
                    "min_ms": row.min_ms,
                    "median_ms": row.median_ms,
                    "max_ms": row.max_ms,
                    "detail": row.detail,
                }))
                .collect::<Vec<Value>>(),
        }))),
        OutputMode::Human => emit(&render_bench(&rows, args.iterations)),
    }
    Ok(())
}

pub fn render_bench(rows: &[BenchRow], iterations: u32) -> String {
    let mut out = format!("bench ({iterations} iterations per scenario)\n");
    for row in rows {
        out.push_str(&format!(
            "  {:<9} min {:>8.1} ms  median {:>8.1} ms  max {:>8.1} ms  {}\n",
            row.scenario, row.min_ms, row.median_ms, row.max_ms, row.detail
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarize_reports_min_median_max() {
        let mut samples = vec![5.0, 1.0, 3.0];
        assert_eq!(summarize(&mut samples), (1.0, 3.0, 5.0));
        let mut even = vec![4.0, 2.0];
        assert_eq!(summarize(&mut even), (2.0, 4.0, 4.0));
    }

    #[test]
    fn measure_runs_each_iteration_and_propagates_errors() {
        let mut calls = 0;
        let (_min, _median, _max, detail) = measure(3, || {
            calls += 1;
            Ok(format!("run {calls}"))
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(detail, "run 3");

        let err = measure(2, || -> Result<String> {
            Err(XmemError::InvalidAddress { address: 1 })
        })
        .unwrap_err();
        assert!(matches!(err, XmemError::InvalidAddress { .. }));
    }

    #[test]
    fn unknown_scenario_lists_available_names() {
        let err = known_scenarios("no-such").unwrap_err();
        assert!(matches!(err, XmemError::InvalidInput { .. }));
        assert_eq!(known_scenarios("all").unwrap().len(), SCENARIOS.len());
        assert_eq!(known_scenarios("map").unwrap(), vec!["map"]);
    }

    #[test]
    fn render_bench_lists_rows() {
        let rows = vec![BenchRow {
            scenario: "map".into(),
            min_ms: 1.0,
            median_ms: 2.0,
            max_ms: 3.0,
            detail: "10 regions".into(),
        }];
        let text = render_bench(&rows, 2);
        assert!(text.contains("map"));
        assert!(text.contains("10 regions"));
    }
}
