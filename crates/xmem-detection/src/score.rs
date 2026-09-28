//! 위험도 스코어: findings의 심각도·신뢰도를 결정적 휴리스틱으로 하나의 숫자로 요약한다.
//!
//! **악성 확정 지표가 아니다.** 공식(심각도 가중 × 신뢰도 계수 합 → 포화 곡선)은
//! 연구용 휴리스틱이며, 같은 findings에는 항상 같은 점수를 낸다(결정적).

use serde::Serialize;
use xmem_core::{Confidence, Finding, Severity};

/// 위험도 등급. `score` 임계값: 0=None, ≤15 Low, ≤40 Medium, ≤70 High, 그 외 Critical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskLevel::None => "none",
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// 심각도별 finding 수.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SeverityCounts {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// findings 요약 점수.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskScore {
    pub score: u32,
    pub level: RiskLevel,
    pub findings: usize,
    pub by_severity: SeverityCounts,
}

/// 포화 곡선 상수: raw가 이 값일 때 score 50.
const HALF_SCORE_RAW: f64 = 40.0;

fn severity_weight(severity: Severity) -> f64 {
    match severity {
        Severity::Info => 1.0,
        Severity::Low => 2.0,
        Severity::Medium => 6.0,
        Severity::High => 15.0,
        Severity::Critical => 30.0,
    }
}

fn confidence_factor(confidence: Confidence) -> f64 {
    match confidence {
        Confidence::Low => 0.5,
        Confidence::Medium => 0.75,
        Confidence::High => 1.0,
    }
}

fn level_for(score: u32) -> RiskLevel {
    match score {
        0 => RiskLevel::None,
        1..=15 => RiskLevel::Low,
        16..=40 => RiskLevel::Medium,
        41..=70 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

/// findings의 심각도·신뢰도 가중 합을 0~100 포화 곡선으로 사상한다(결정적 휴리스틱).
pub fn risk_score(findings: &[Finding]) -> RiskScore {
    let mut counts = SeverityCounts::default();
    let mut raw = 0.0f64;
    for finding in findings {
        match finding.severity {
            Severity::Info => counts.info += 1,
            Severity::Low => counts.low += 1,
            Severity::Medium => counts.medium += 1,
            Severity::High => counts.high += 1,
            Severity::Critical => counts.critical += 1,
        }
        raw += severity_weight(finding.severity) * confidence_factor(finding.confidence);
    }
    let score = (100.0 * raw / (raw + HALF_SCORE_RAW)).round() as u32;
    RiskScore {
        score,
        level: level_for(score),
        findings: findings.len(),
        by_severity: counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Finding, Severity};

    fn finding(severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            rule_id: "XMEM-001".to_string(),
            name: "test".to_string(),
            severity,
            confidence,
            evidence: Vec::new(),
            heuristic: "test".to_string(),
            interpretation: "test".to_string(),
        }
    }

    fn findings(severity: Severity, confidence: Confidence, count: usize) -> Vec<Finding> {
        (0..count).map(|_| finding(severity, confidence)).collect()
    }

    #[test]
    fn empty_findings_score_zero() {
        let risk = risk_score(&[]);
        assert_eq!(risk.score, 0);
        assert_eq!(risk.level, RiskLevel::None);
        assert_eq!(risk.findings, 0);
        assert_eq!(risk.by_severity, SeverityCounts::default());
        assert_eq!(risk.by_severity.info, 0);
        assert_eq!(risk.by_severity.low, 0);
        assert_eq!(risk.by_severity.medium, 0);
        assert_eq!(risk.by_severity.high, 0);
        assert_eq!(risk.by_severity.critical, 0);
    }

    #[test]
    fn low_finding_is_low() {
        let risk = risk_score(&[finding(Severity::Low, Confidence::High)]);
        assert_eq!(risk.score, 5, "Low×1.0 = raw 2 → round(200/42) = 5");
        assert_eq!(risk.level, RiskLevel::Low);
        assert_eq!(risk.findings, 1);
        assert_eq!(risk.by_severity.low, 1);
    }

    #[test]
    fn severity_and_confidence_raise_score() {
        let low = risk_score(&findings(Severity::Low, Confidence::High, 2));
        let medium = risk_score(&findings(Severity::Medium, Confidence::High, 2));
        let high = risk_score(&findings(Severity::High, Confidence::High, 2));
        assert!(
            high.score > medium.score,
            "{} > {}",
            high.score,
            medium.score
        );
        assert!(medium.score > low.score, "{} > {}", medium.score, low.score);
        assert_eq!(high.level, RiskLevel::High, "raw 30 → round(3000/70) = 43");
        assert_eq!(high.score, 43);

        let low_confidence = risk_score(&[finding(Severity::High, Confidence::Low)]);
        let high_confidence = risk_score(&[finding(Severity::High, Confidence::High)]);
        assert!(high_confidence.score > low_confidence.score);

        let critical = risk_score(&findings(Severity::Critical, Confidence::High, 4));
        assert_eq!(critical.level, RiskLevel::Critical, "raw 120 → 75");
        assert_eq!(critical.score, 75);
    }

    #[test]
    fn deterministic_for_same_input() {
        let input = vec![
            finding(Severity::Critical, Confidence::Medium),
            finding(Severity::Low, Confidence::High),
        ];
        let first = risk_score(&input);
        let second = risk_score(&input);
        assert_eq!(first, second);
        assert_eq!(first.by_severity.critical, 1);
        assert_eq!(first.by_severity.low, 1);
    }
}
