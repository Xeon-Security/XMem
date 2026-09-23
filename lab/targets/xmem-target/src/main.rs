//! XMem 연구용 Test Target.
//!
//! 사용: `xmem-target run <scenario> [--hold-secs N] [--report PATH]`
//! 시나리오: normal | pattern | private | private-exec | pe-like | threads | protection | all

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod scenarios;

use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde_json::json;

struct Args {
    scenario: String,
    hold_secs: u64,
    report: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let usage = "usage: xmem-target run <scenario> [--hold-secs N] [--report PATH]";
    let mut it = args.iter().skip(1);
    let scenario = match (it.next(), it.next()) {
        (Some(cmd), Some(name)) if cmd == "run" => name.clone(),
        _ => return Err(usage.to_string()),
    };
    let mut hold_secs = 30u64;
    let mut report = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--hold-secs" => {
                let value = it.next().ok_or("--hold-secs 값 필요")?;
                hold_secs = value.parse().map_err(|_| "--hold-secs는 정수")?;
            }
            "--report" => report = Some(it.next().ok_or("--report 값 필요")?.clone()),
            other => return Err(format!("알 수 없는 인자: {other}")),
        }
    }
    Ok(Args {
        scenario,
        hold_secs,
        report,
    })
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().collect();
    let args = match parse_args(&raw) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let (lab, artifacts) = match scenarios::setup(&args.scenario) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let report = json!({
        "scenario": args.scenario,
        "pid": xmem_windows::current_pid(),
        "artifacts": artifacts,
    });
    let text = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
    let _ = writeln!(std::io::stdout(), "{text}");
    if let Some(path) = &args.report
        && let Err(e) = std::fs::write(path, &text)
    {
        eprintln!("error: report 쓰기 실패: {e}");
        return ExitCode::from(1);
    }

    let deadline = Instant::now() + Duration::from_secs(args.hold_secs);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(lab);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_args_defaults_and_flags() {
        let parsed = parse_args(&args(&["xmem-target", "run", "all"])).unwrap();
        assert_eq!(parsed.scenario, "all");
        assert_eq!(parsed.hold_secs, 30);
        assert!(parsed.report.is_none());

        let parsed = parse_args(&args(&[
            "xmem-target",
            "run",
            "pattern",
            "--hold-secs",
            "5",
            "--report",
            "r.json",
        ]))
        .unwrap();
        assert_eq!(parsed.scenario, "pattern");
        assert_eq!(parsed.hold_secs, 5);
        assert_eq!(parsed.report.as_deref(), Some("r.json"));
    }

    #[test]
    fn parse_args_rejects_bad_input() {
        assert!(parse_args(&args(&["xmem-target"])).is_err());
        assert!(parse_args(&args(&["xmem-target", "run"])).is_err());
        assert!(parse_args(&args(&["xmem-target", "run", "x", "--hold-secs", "z"])).is_err());
        assert!(parse_args(&args(&["xmem-target", "run", "x", "--bogus"])).is_err());
    }
}
