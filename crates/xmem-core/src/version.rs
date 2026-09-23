//! XMem version and format version constants.

/// Cargo package version (single source of truth).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Snapshot binary format version (`docs/architecture.md` §8).
pub const SNAPSHOT_FORMAT_VERSION: u16 = 1;

/// JSON envelope schema version for stable machine-readable output.
pub const JSON_SCHEMA_VERSION: u32 = 1;
