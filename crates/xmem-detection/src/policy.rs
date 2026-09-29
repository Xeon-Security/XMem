//! 사용자 규칙·억제 정책(JSON). 관찰 데이터만 사용하며 소스 접근이 없다.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use xmem_core::{
    Confidence, Heuristic, MemoryRegion, MemoryState, MemoryType, ModuleInfo, RegionClass, Result,
    Severity, XmemError,
};

use crate::rules::{DetectionContext, finding_key, overlaps, region_evidence};

/// JSON 정책 파일 루트. `{}`(빈 파일)는 아무 것도 바꾸지 않는다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectionPolicy {
    #[serde(default)]
    pub user_rules: Vec<UserRule>,
    #[serde(default)]
    pub suppress: Vec<Suppression>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default)]
    pub heuristic: String,
    #[serde(default)]
    pub interpretation: String,
    #[serde(default)]
    pub r#match: RegionMatch,
}

/// 관찰된 영역 필드만으로 구성된 매처. 전부 AND이며 `None`은 조건 없음이다.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionMatch {
    pub classification: Option<RegionClass>,
    pub state: Option<MemoryState>,
    pub region_type: Option<MemoryType>,
    pub executable: Option<bool>,
    pub writable: Option<bool>,
    pub readable: Option<bool>,
    #[serde(default)]
    pub heuristics: Vec<Heuristic>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    #[serde(default)]
    pub outside_modules: bool,
}

impl RegionMatch {
    /// `outside_modules`는 모듈 목록이 비면 매칭하지 않는다(침묵 원칙, core 필터와 동일).
    pub fn matches(&self, region: &MemoryRegion, modules: &[ModuleInfo]) -> bool {
        if let Some(value) = self.classification
            && region.classification != value
        {
            return false;
        }
        if let Some(value) = self.state
            && region.state != value
        {
            return false;
        }
        if let Some(value) = self.region_type
            && region.region_type != Some(value)
        {
            return false;
        }
        if let Some(value) = self.executable
            && region.executable != value
        {
            return false;
        }
        if let Some(value) = self.writable
            && region.writable != value
        {
            return false;
        }
        if let Some(value) = self.readable
            && region.readable != value
        {
            return false;
        }
        if !self
            .heuristics
            .iter()
            .all(|h| region.heuristics.contains(h))
        {
            return false;
        }
        if let Some(min) = self.min_size
            && region.size < min
        {
            return false;
        }
        if let Some(max) = self.max_size
            && region.size > max
        {
            return false;
        }
        if self.outside_modules {
            if modules.is_empty() {
                return false;
            }
            if modules.iter().any(|m| overlaps(m, region)) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Suppression {
    pub rule_id: String,
    pub reason: String,
    /// observed key → 값(대소문자 무시, `*` 와일드카드). 모든 쌍이 일치해야 억제.
    #[serde(default)]
    pub observed: BTreeMap<String, String>,
    pub region_base: Option<u64>,
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuppressedFinding {
    pub finding: xmem_core::Finding,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyOutcome {
    pub findings: Vec<xmem_core::Finding>,
    pub suppressed: Vec<SuppressedFinding>,
}

/// 바이트 → 정책. JSON 오류는 `JsonError`, 검증 실패는 `InvalidInput`(사유 포함).
pub fn parse_policy(bytes: &[u8], source: &str) -> Result<DetectionPolicy> {
    let policy: DetectionPolicy =
        serde_json::from_slice(bytes).map_err(|error| XmemError::JsonError {
            reason: format!("정책 파일 파싱 실패: {source} ({error})"),
        })?;
    validate_policy(&policy)?;
    Ok(policy)
}

/// 파일 → 정책. 읽기 실패는 경로를 포함한 오류.
pub fn load_policy(path: &Path) -> Result<DetectionPolicy> {
    let bytes = std::fs::read(path).map_err(|error| XmemError::InvalidInput {
        reason: format!("정책 파일 읽기 실패: {} ({error})", path.display()),
    })?;
    parse_policy(&bytes, &path.display().to_string())
}

fn validate_policy(policy: &DetectionPolicy) -> Result<()> {
    const BUILTIN: [&str; 5] = ["XMEM-001", "XMEM-002", "XMEM-003", "XMEM-004", "XMEM-005"];
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for rule in &policy.user_rules {
        let id = rule.id.trim();
        if id.is_empty() {
            return Err(invalid("사용자 규칙 id가 비어 있습니다"));
        }
        if BUILTIN.contains(&id) {
            return Err(invalid(format!(
                "내장 규칙 id는 재정의할 수 없습니다: {id}"
            )));
        }
        if !seen.insert(id) {
            return Err(invalid(format!("중복된 규칙 id: {id}")));
        }
        if rule.name.trim().is_empty() {
            return Err(invalid(format!("규칙 이름이 비어 있습니다: {id}")));
        }
    }
    for suppression in &policy.suppress {
        if suppression.rule_id.trim().is_empty() {
            return Err(invalid("억제 항목의 rule_id가 비어 있습니다"));
        }
        if suppression.reason.trim().is_empty() {
            return Err(invalid(format!(
                "억제 사유가 비어 있습니다: {}",
                suppression.rule_id
            )));
        }
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> XmemError {
    XmemError::InvalidInput {
        reason: reason.into(),
    }
}

/// 내장 판정 + 사용자 규칙을 합친 뒤 억제를 적용한다.
pub fn apply_policy(
    policy: &DetectionPolicy,
    context: &DetectionContext<'_>,
    mut findings: Vec<xmem_core::Finding>,
) -> PolicyOutcome {
    for rule in &policy.user_rules {
        for region in context.regions {
            if !rule.r#match.matches(region, context.modules) {
                continue;
            }
            findings.push(user_rule_finding(rule, region, context.modules));
        }
    }
    findings.sort_by_key(finding_key);
    let mut kept = Vec::with_capacity(findings.len());
    let mut suppressed = Vec::new();
    for finding in findings {
        match policy
            .suppress
            .iter()
            .find(|suppression| suppression.matches(&finding))
        {
            Some(suppression) => suppressed.push(SuppressedFinding {
                finding,
                reason: suppression.reason.clone(),
            }),
            None => kept.push(finding),
        }
    }
    PolicyOutcome {
        findings: kept,
        suppressed,
    }
}

fn user_rule_finding(
    rule: &UserRule,
    region: &MemoryRegion,
    modules: &[ModuleInfo],
) -> xmem_core::Finding {
    let module_overlap = if modules.iter().any(|m| overlaps(m, region)) {
        "some"
    } else {
        "none"
    };
    xmem_core::Finding {
        rule_id: rule.id.clone(),
        name: rule.name.clone(),
        severity: rule.severity,
        confidence: rule.confidence,
        evidence: vec![
            region_evidence(region)
                .observe("classification", region.classification.to_string())
                .observe(
                    "region_type",
                    region
                        .region_type
                        .map_or_else(|| "unknown".to_string(), |value| value.to_string()),
                )
                .observe("module_overlap", module_overlap)
                .observe("source", "user-rule"),
        ],
        heuristic: if rule.heuristic.trim().is_empty() {
            "user supplied rule matched".to_string()
        } else {
            rule.heuristic.clone()
        },
        interpretation: if rule.interpretation.trim().is_empty() {
            format!("User rule {} matched observed region fields", rule.id)
        } else {
            rule.interpretation.clone()
        },
    }
}

impl Suppression {
    fn matches(&self, finding: &xmem_core::Finding) -> bool {
        if finding.rule_id != self.rule_id {
            return false;
        }
        if let Some(base) = self.region_base
            && finding.evidence.iter().all(|e| e.region_base != Some(base))
        {
            return false;
        }
        if let Some(address) = self.address
            && finding.evidence.iter().all(|e| e.address != Some(address))
        {
            return false;
        }
        self.observed.iter().all(|(key, pattern)| {
            finding.evidence.iter().any(|e| {
                e.observed
                    .get(key)
                    .is_some_and(|value| glob_eq(pattern, value))
            })
        })
    }
}

/// `*` 와일드카드만 지원하는 대소문자 무시 글롭. 와일드카드가 없으면 정확 일치.
pub fn glob_eq(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();
    let (mut p, mut v) = (0usize, 0usize);
    let (pbytes, vbytes) = (pattern.as_bytes(), value.as_bytes());
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while v < vbytes.len() {
        if p < pbytes.len() && pbytes[p] == b'*' {
            star = Some(p);
            mark = v;
            p += 1;
        } else if p < pbytes.len() && pbytes[p] == vbytes[v] {
            p += 1;
            v += 1;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pbytes.len() && pbytes[p] == b'*' {
        p += 1;
    }
    p == pbytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::detect;
    use xmem_core::{MemoryRegion, MemoryState, MemoryType, Protection, RegionClass};

    fn lcg(seed: &mut u64) -> u32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 33) as u32
    }

    fn region(base: u64, heuristics: Vec<Heuristic>) -> MemoryRegion {
        MemoryRegion {
            base,
            size: 0x2000,
            allocation_base: Some(base),
            state: MemoryState::Commit,
            protection: Protection::new(0x40, true, true, true),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: true,
            executable: true,
            classification: RegionClass::Private,
            heuristics,
            mapped_file: None,
        }
    }

    #[test]
    fn parse_policy_accepts_empty_object_and_ignores_unknown_fields() {
        let policy = parse_policy(b"{}", "inline").unwrap();
        assert!(policy.user_rules.is_empty());
        assert!(policy.suppress.is_empty());
    }

    #[test]
    fn parse_policy_rejects_bad_json_with_source() {
        let err = parse_policy(b"{", "policy.json").unwrap_err();
        assert!(err.to_string().contains("policy.json"), "경로 문맥: {err}");
        assert!(matches!(err, XmemError::JsonError { .. }));
    }

    #[test]
    fn parse_policy_rejects_blank_duplicate_and_builtin_ids() {
        let blank = br#"{"user_rules":[{"id":"","name":"x","severity":"low","confidence":"low"}]}"#;
        assert!(matches!(
            parse_policy(blank, "p.json"),
            Err(XmemError::InvalidInput { .. })
        ));
        let dup = br#"{"user_rules":[
            {"id":"XMEM-U1","name":"a","severity":"low","confidence":"low"},
            {"id":"XMEM-U1","name":"b","severity":"low","confidence":"low"}]}"#;
        assert!(matches!(
            parse_policy(dup, "p.json"),
            Err(XmemError::InvalidInput { .. })
        ));
        let builtin =
            br#"{"user_rules":[{"id":"XMEM-001","name":"a","severity":"low","confidence":"low"}]}"#;
        assert!(matches!(
            parse_policy(builtin, "p.json"),
            Err(XmemError::InvalidInput { .. })
        ));
        let blank_reason = br#"{"suppress":[{"rule_id":"XMEM-003","reason":""}]}"#;
        assert!(matches!(
            parse_policy(blank_reason, "p.json"),
            Err(XmemError::InvalidInput { .. })
        ));
    }

    #[test]
    fn user_rule_matches_region_fields_and_heuristics() {
        let rule = UserRule {
            id: "XMEM-U1".into(),
            name: "rwx private".into(),
            description: String::new(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            heuristic: String::new(),
            interpretation: String::new(),
            r#match: RegionMatch {
                classification: Some(RegionClass::Private),
                executable: Some(true),
                min_size: Some(0x1000),
                ..RegionMatch::default()
            },
        };
        let region = region(0x1000, vec![Heuristic::ExecutablePrivate]);
        assert!(rule.r#match.matches(&region, &[]));
        let mut other = region.clone();
        other.executable = false;
        assert!(!rule.r#match.matches(&other, &[]), "executable 불일치");
    }

    #[test]
    fn user_rule_outside_modules_stays_silent_without_modules() {
        let filter = RegionMatch {
            outside_modules: true,
            ..RegionMatch::default()
        };
        assert!(
            !filter.matches(&region(0x1000, Vec::new()), &[]),
            "모듈 목록 없으면 침묵"
        );
    }

    #[test]
    fn glob_is_case_insensitive_and_exact_otherwise() {
        assert!(glob_eq("r-x*", "R-X (0x20)"));
        assert!(!glob_eq("r-x*", "RWX (0x40)"));
        assert!(glob_eq("mapped-no-file", "MAPPED-NO-FILE"));
        assert!(!glob_eq("mapped", "mapped-no-file"), "부분일치 금지");
        assert!(glob_eq("*", "아무거나"));
        assert!(!glob_eq("a*b*c", "aXc"));
    }

    #[test]
    fn apply_policy_appends_sorted_user_findings_and_suppresses() {
        let context = DetectionContext {
            regions: &[
                region(0x1000, vec![Heuristic::ExecutablePrivate]),
                region(0x2000, vec![Heuristic::ExecutablePrivate]),
            ],
            modules: &[],
            threads: &[],
        };
        let policy = DetectionPolicy {
            user_rules: vec![UserRule {
                id: "XMEM-U1".into(),
                name: "second region".into(),
                description: String::new(),
                severity: Severity::High,
                confidence: Confidence::High,
                heuristic: "user rule".into(),
                interpretation: "user supplied".into(),
                r#match: RegionMatch {
                    min_size: Some(0x2000),
                    ..RegionMatch::default()
                },
            }],
            suppress: vec![Suppression {
                rule_id: "XMEM-001".into(),
                reason: "known JIT allocation".into(),
                observed: BTreeMap::from([("protection".to_string(), "rwx*".to_string())]),
                region_base: Some(0x1000),
                address: None,
            }],
        };
        // 내장 findings는 억제되지 않는 것만 남는다.
        let builtins = detect(&context);
        assert_eq!(
            builtins.iter().filter(|f| f.rule_id == "XMEM-001").count(),
            2
        );
        let outcome = apply_policy(&policy, &context, builtins);
        let builtin_left = outcome
            .findings
            .iter()
            .filter(|f| f.rule_id == "XMEM-001")
            .count();
        assert_eq!(builtin_left, 1, "region_base 0x1000 억제");
        assert_eq!(outcome.suppressed.len(), 1);
        assert_eq!(outcome.suppressed[0].reason, "known JIT allocation");
        assert!(outcome.findings.iter().any(|f| f.rule_id == "XMEM-U1"));
        // 결정적 정렬: (rule_id, region_base)
        let keys: Vec<(String, u64)> = outcome
            .findings
            .iter()
            .map(|f| (f.rule_id.clone(), f.evidence[0].region_base.unwrap_or(0)))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = DetectionPolicy {
            user_rules: vec![],
            suppress: vec![Suppression {
                rule_id: "XMEM-003".into(),
                reason: "noise".into(),
                observed: BTreeMap::from([("backing".to_string(), "mapped-no-file".to_string())]),
                region_base: None,
                address: None,
            }],
        };
        let json = serde_json::to_vec(&policy).unwrap();
        let back: DetectionPolicy = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.suppress.len(), 1);
        assert_eq!(back.suppress[0].observed["backing"], "mapped-no-file");
    }

    #[test]
    fn parse_policy_never_panics_on_random_input() {
        let alphabet = b"{}[]\":,abcXY?*0123456789 \n\t\\";
        let mut seed = 0x0f0f_1234_abcd_0001_u64;
        for _ in 0..2000 {
            let len = (lcg(&mut seed) % 256) as usize;
            let text: String = (0..len)
                .map(|_| alphabet[(lcg(&mut seed) as usize) % alphabet.len()] as char)
                .collect();
            let _ = parse_policy(text.as_bytes(), "fuzz");
        }
    }
}
