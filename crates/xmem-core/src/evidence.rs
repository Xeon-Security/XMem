//! Evidence model: 관찰(Observed)→Evidence→Heuristic→Confidence→Interpretation.

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
