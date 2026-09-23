use serde::{Deserialize, Serialize};

use super::process::ProcessArch;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: Option<String>,
    pub arch: Option<ProcessArch>,
}
