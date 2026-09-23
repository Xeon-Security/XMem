//! XMem core: shared models, errors, evidence, and policy.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod classify;
pub mod error;
pub mod evidence;
pub mod guard;
pub mod model;
pub mod source;
pub mod version;

pub use classify::{classify, heuristics};
pub use error::{Result, XmemError};
pub use evidence::{Confidence, Evidence, Finding, Severity};
pub use model::*;
pub use source::{MemorySource, ReadOutcome};
pub use version::{JSON_SCHEMA_VERSION, SNAPSHOT_FORMAT_VERSION, VERSION};
