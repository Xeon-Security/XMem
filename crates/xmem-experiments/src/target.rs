//! lab target 프로세스의 spawn, 신원 검증, cleanup을 담당한다.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use xmem_core::guard::{PolicyDecision, ProcessIdentity, check_state_change};
use xmem_core::{Result, XmemError};
use xmem_windows::process_info;

/// target 실행 옵션.
#[derive(Debug, Clone)]
pub struct RunOptions {
    pub target_binary: Option<PathBuf>,
    pub hold_secs: u32,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            target_binary: None,
            hold_secs: 30,
        }
    }
}

/// xmem-target 바이너리를 찾는다: 명시 경로 → `XMEM_TARGET` → 실행 파일 디렉터리와 상위 디렉터리.
pub fn locate_target_binary(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
        return Err(XmemError::InvalidInput {
            reason: format!("지정한 target 바이너리가 없습니다: {}", path.display()),
        });
    }
    if let Some(from_env) = std::env::var_os("XMEM_TARGET") {
        let path = PathBuf::from(from_env);
        if path.is_file() {
            return Ok(path);
        }
    }
    let exe = std::env::current_exe().map_err(XmemError::Io)?;
    let dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    let candidates = [
        dir.join("xmem-target.exe"),
        dir.join("..").join("xmem-target.exe"),
        dir.join("..").join("..").join("xmem-target.exe"),
    ];
    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    Err(XmemError::InvalidInput {
        reason: format!(
            "xmem-target 바이너리를 찾지 못했습니다. XMEM_TARGET 환경 변수를 설정하세요 (시도: {})",
            dir.display()
        ),
    })
}

/// spawn한 lab target을 유지하며 실험 동안 신원을 검증하고 종료 시 정리한다.
#[derive(Debug)]
pub struct TargetGuard {
    child: Child,
    pub pid: u32,
    pub report: Value,
    report_path: PathBuf,
    temp_dir: PathBuf,
}

impl TargetGuard {
    /// target을 spawn하고 report를 기다린 뒤 신원을 검증한다. 실패하면 즉시 정리한다.
    pub fn spawn(options: &RunOptions, scenario: &str) -> Result<Self> {
        let binary = locate_target_binary(options.target_binary.as_deref())?;
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let temp_dir =
            std::env::temp_dir().join(format!("xmem-exp-{}-{millis}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).map_err(XmemError::Io)?;
        let report_path = temp_dir.join("report.json");

        let child = Command::new(&binary)
            .args([
                "run",
                scenario,
                "--hold-secs",
                &options.hold_secs.to_string(),
                "--report",
            ])
            .arg(&report_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| XmemError::InvalidInput {
                reason: format!("target 실행 실패: {} ({e})", binary.display()),
            })?;
        let pid = child.id();

        let (report, info) = match wait_for_report(&report_path, pid)
            .and_then(|report| process_info(pid).map(|info| (report, info)))
        {
            Ok(pair) => pair,
            Err(e) => {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&temp_dir);
                return Err(e);
            }
        };

        // target 신원 검증: xmem-target.exe가 아니거나 보호 대상이면 거부한다.
        let is_target = info
            .image_path
            .as_deref()
            .map(|path| path.to_lowercase().ends_with("xmem-target.exe"))
            .unwrap_or(false);
        let denied = if is_target {
            let identity = ProcessIdentity::from_process_info(&info);
            match check_state_change(&identity) {
                PolicyDecision::Allow => None,
                PolicyDecision::Deny { reason, matched } => {
                    Some(format!("보호 프로세스로 판정됨({matched}): {reason}"))
                }
            }
        } else {
            Some(format!("xmem-target이 아닌 프로세스: pid {pid}"))
        };
        if let Some(reason) = denied {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(XmemError::PolicyDenied { reason });
        }

        Ok(Self {
            child,
            pid,
            report,
            report_path,
            temp_dir,
        })
    }

    /// target report의 `artifacts[scenario][field]`를 u64로 읽는다.
    pub fn artifact_u64(&self, scenario: &str, field: &str) -> Result<u64> {
        self.report["artifacts"][scenario][field]
            .as_u64()
            .ok_or_else(|| XmemError::InvalidInput {
                reason: format!("target report에서 {scenario}.{field}를 찾지 못했습니다"),
            })
    }

    /// target report의 `artifacts[scenario][field]`를 u32로 읽는다.
    pub fn artifact_u32(&self, scenario: &str, field: &str) -> Result<u32> {
        Ok(self.artifact_u64(scenario, field)? as u32)
    }

    /// target report 파일 경로.
    pub fn report_path(&self) -> &Path {
        &self.report_path
    }
}

impl Drop for TargetGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn wait_for_report(path: &Path, pid: u32) -> Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(value) = serde_json::from_str::<Value>(&text)
            && value["pid"].as_u64() == Some(pid as u64)
        {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(XmemError::InvalidInput {
                reason: "target report 대기 시간 초과".to_string(),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
