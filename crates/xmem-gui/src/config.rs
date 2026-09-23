//! `%APPDATA%\XMem\gui.json` 설정 저장/로드.

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use xmem_core::{Result, XmemError};

use crate::theme::ThemeMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    pub theme: ThemeMode,
    pub window_width: f32,
    pub window_height: f32,
    pub guide_seen: bool,
    pub last_output_dir: Option<PathBuf>,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            window_width: 1200.0,
            window_height: 800.0,
            guide_seen: false,
            last_output_dir: None,
        }
    }
}

pub fn config_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("XMem").join("gui.json")
}

pub fn load() -> GuiConfig {
    let Ok(bytes) = std::fs::read(config_path()) else {
        return GuiConfig::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(config: &GuiConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(XmemError::Io)?;
    }
    let bytes = serde_json::to_vec_pretty(config).map_err(|e| XmemError::JsonError {
        reason: e.to_string(),
    })?;
    std::fs::write(&path, bytes).map_err(XmemError::Io)
}

/// 기본 출력 디렉터리: `%USERPROFILE%\Documents\XMem` (없으면 생성).
pub fn default_output_dir() -> PathBuf {
    let base = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("Documents").join("XMem");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// `xmem-<kind>-<pid>-<YYYYMMDD-HHMMSS>.<ext>`
pub fn output_file_name(kind: &str, pid: u32, ext: &str, now: DateTime<Local>) -> String {
    format!("xmem-{kind}-{pid}-{}.{ext}", now.format("%Y%m%d-%H%M%S"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_file_name_is_deterministic() {
        let ts = DateTime::parse_from_rfc3339("2026-09-23T10:20:30+09:00")
            .unwrap()
            .with_timezone(&Local);
        let name = output_file_name("snapshot", 4242, "xmem", ts);
        assert_eq!(
            name,
            format!("xmem-snapshot-4242-{}.xmem", ts.format("%Y%m%d-%H%M%S"))
        );
    }

    #[test]
    fn config_roundtrips_through_json() {
        let config = GuiConfig {
            theme: ThemeMode::Light,
            guide_seen: true,
            ..GuiConfig::default()
        };
        let bytes = serde_json::to_vec(&config).unwrap();
        let back: GuiConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.theme, ThemeMode::Light);
        assert!(back.guide_seen);
        assert_eq!(back.window_width, 1200.0);
    }

    #[test]
    fn corrupt_config_falls_back_to_default() {
        let parsed: std::result::Result<GuiConfig, _> = serde_json::from_slice(b"{not json");
        assert!(parsed.is_err());
    }
}
