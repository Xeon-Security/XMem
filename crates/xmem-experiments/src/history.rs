//! 실험 이력 JSONL: append-only 로그, 손상 줄은 건너뛴다(절대 실패하지 않음).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use xmem_core::{Result, XmemError};

use crate::runner::ExperimentReport;

/// 이력 파일 경로: `%APPDATA%\XMem\experiments.jsonl`, APPDATA가 없으면 temp.
pub fn history_path() -> PathBuf {
    match std::env::var_os("APPDATA") {
        Some(appdata) if !appdata.is_empty() => PathBuf::from(appdata)
            .join("XMem")
            .join("experiments.jsonl"),
        _ => std::env::temp_dir().join("XMem").join("experiments.jsonl"),
    }
}

/// 한 줄 JSON으로 append한다(디렉터리 자동 생성).
pub fn append(report: &ExperimentReport, path: &Path) -> Result<()> {
    if let Some(dir) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(XmemError::Io)?;
    }
    let line = serde_json::to_string(report).map_err(|e| XmemError::JsonError {
        reason: e.to_string(),
    })?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(XmemError::Io)?;
    writeln!(file, "{line}").map_err(XmemError::Io)
}

/// 이력을 로드한다. 파일이 없거나 줄이 손상되어도 실패하지 않는다(손상 줄 건너뜀).
pub fn load(path: &Path) -> Vec<ExperimentReport> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// 같은 name의 직전 실행 대비 `expected_observed` true→false면 회귀 문자열을 낸다.
pub fn regressions(reports: &[ExperimentReport]) -> Vec<String> {
    let mut previous: HashMap<&str, bool> = HashMap::new();
    let mut found = Vec::new();
    for report in reports {
        if let Some(&before) = previous.get(report.name.as_str())
            && before
            && !report.expected_observed
        {
            found.push(format!("회귀: {}", report.name));
        }
        previous.insert(report.name.as_str(), report.expected_observed);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::ExperimentReport;

    fn report(name: &str, observed: bool) -> ExperimentReport {
        ExperimentReport {
            name: name.to_string(),
            description: "desc".to_string(),
            scenario: "normal".to_string(),
            target_pid: 42,
            expected_rule: "XMEM-001".to_string(),
            expected_present: false,
            expected_observed: observed,
            expected_region: Some(0x1000),
            baseline_findings: 0,
            post_findings: 1,
            detections_added: 1,
            detections_removed: 0,
            elapsed_ms: 10,
            cleanup: "target terminated".to_string(),
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xmem-history-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("experiments.jsonl")
    }

    #[test]
    fn load_missing_file_is_empty() {
        let path = temp_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(load(&path).is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_skips_corrupt_lines() {
        let path = temp_path("corrupt");
        let good = serde_json::to_string(&report("remote-alloc", true)).unwrap();
        std::fs::write(&path, format!("{good}\n{{ not json\n{good}\n")).unwrap();
        let loaded = load(&path);
        assert_eq!(loaded.len(), 2, "손상 줄 1개는 건너뛴다");
        assert!(loaded.iter().all(|item| item.name == "remote-alloc"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn append_then_load_roundtrip() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        append(&report("multi-alloc", true), &path).unwrap();
        append(&report("multi-alloc", false), &path).unwrap();
        let loaded = load(&path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "multi-alloc");
        assert!(loaded[0].expected_observed);
        assert!(!loaded[1].expected_observed);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn regressions_detects_true_to_false() {
        let reports = vec![
            report("multi-alloc", true),
            report("remote-alloc", true),
            report("multi-alloc", true),
            report("multi-alloc", false),
            report("remote-alloc", false),
        ];
        assert_eq!(
            regressions(&reports),
            vec![
                "회귀: multi-alloc".to_string(),
                "회귀: remote-alloc".to_string()
            ]
        );
    }
}
