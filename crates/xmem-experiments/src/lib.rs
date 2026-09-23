//! 실험 자동화: lab target 한정 변경 실험과 Baseline→Action→Post→Diff→Detection 파이프라인.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod experiments;
pub mod runner;
pub mod target;

pub use experiments::{EXPERIMENTS, Expectation, ExperimentMeta, experiment, finding_matches};
pub use runner::{ExperimentReport, run_experiment};
pub use target::{RunOptions, TargetGuard, locate_target_binary};
