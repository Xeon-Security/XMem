//! XMem core: shared models, errors, evidence, and policy.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod evidence;
pub mod version;

pub use error::{Result, XmemError};
pub use version::{JSON_SCHEMA_VERSION, SNAPSHOT_FORMAT_VERSION, VERSION};
