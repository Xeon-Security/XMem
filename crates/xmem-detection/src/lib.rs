//! Rule 기반 Detection Engine. 관찰 데이터만 사용하므로 Live/Snapshot 모두에서 동작한다. (M8)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod policy;
pub mod rules;
pub mod score;
pub mod source;

pub use policy::{
    DetectionPolicy, PolicyOutcome, RegionMatch, SuppressedFinding, Suppression, UserRule,
    apply_policy, glob_eq, load_policy, parse_policy,
};
pub use rules::{DetectionContext, Rule, default_rules, detect};
pub use score::{RiskLevel, RiskScore, SeverityCounts, risk_score};
pub use source::detect_source;
