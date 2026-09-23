//! Evidence model: 관찰(Observed)→Evidence→Heuristic→Confidence→Interpretation.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// 관찰된 사실 하나. 해석은 `Finding`의 heuristic/interpretation에만 존재한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: String,
    pub address: Option<u64>,
    pub region_base: Option<u64>,
    pub observed: BTreeMap<String, String>,
}

impl Evidence {
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            address: None,
            region_base: None,
            observed: BTreeMap::new(),
        }
    }

    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    pub fn with_region_base(mut self, base: u64) -> Self {
        self.region_base = Some(base);
        self
    }

    pub fn observe(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.observed.insert(key.into(), value.into());
        self
    }
}

/// Detection 결과. 악성 확정 표현은 금지하며 interpretation은 잠재성 수준으로 제한한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub heuristic: String,
    pub interpretation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_serde_roundtrip() {
        let finding = Finding {
            rule_id: "XMEM-001".into(),
            name: "Executable Private Memory".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![
                Evidence::new("region")
                    .with_address(0x7ff6_0000)
                    .observe("protection", "EXECUTE_READWRITE")
                    .observe("type", "MEM_PRIVATE"),
            ],
            heuristic: "private + executable".into(),
            interpretation: "Potentially suspicious memory region".into(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
        assert!(json.contains("\"severity\":\"medium\""));
    }

    #[test]
    fn observed_values_are_deterministically_ordered() {
        let ev = Evidence::new("region").observe("b", "2").observe("a", "1");
        let keys: Vec<&String> = ev.observed.keys().collect();
        assert_eq!(keys, vec!["a", "b"]);
    }
}
