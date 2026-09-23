use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub pid: u32,
    pub priority: Option<i32>,
    pub start_address: Option<u64>,
    /// start_address가 속한 메모리 영역의 base (M5 상관관계 분석).
    pub start_region_base: Option<u64>,
    /// start_address가 속한 로드된 모듈 이름 (있으면).
    pub start_module: Option<String>,
}
