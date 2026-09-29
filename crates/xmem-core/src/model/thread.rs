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
    /// 시작 주소가 실측값인지 근사값인지 구분하는 출처.
    /// live: `NtQueryInformationThread`(ThreadQuerySetWin32StartAddress)면 `None`(실측).
    /// minidump: 컨텍스트의 instruction pointer면 `Some("minidump-context-rip")`(근사).
    #[serde(default)]
    pub start_address_source: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_info_deserializes_without_start_address_source() {
        let json = r#"{"tid":1,"pid":2,"priority":null,"start_address":null,
            "start_region_base":null,"start_module":null}"#;
        let thread: ThreadInfo = serde_json::from_str(json).unwrap();
        assert_eq!(thread.start_address_source, None, "구 스냅샷 호환");
    }
}
