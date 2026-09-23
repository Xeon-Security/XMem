//! Snapshot 포맷/직렬화, SnapshotSource, Diff. (M7)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod envelope;
pub mod format;
pub mod source;

pub use envelope::{AcquisitionMeta, RegionHash, SnapshotEnvelope};
pub use format::{HEADER_LEN, MAGIC, decode, encode, read_file, write_file};
pub use source::SnapshotSource;
