//! Rule 기반 Detection Engine. 관찰 데이터만 사용하므로 Live/Snapshot 모두에서 동작한다. (M8)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod rules;
pub mod source;

pub use rules::{DetectionContext, Rule, default_rules, detect};
pub use source::detect_source;
