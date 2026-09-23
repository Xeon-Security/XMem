//! Snapshot 포맷/직렬화, SnapshotSource, Diff, Minidump 분석. (M7, M9)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod collect;
pub mod diff;
pub mod dump;
pub mod envelope;
pub mod format;
pub mod source;

pub use collect::{CollectOptions, DEFAULT_HASH_BUDGET_BYTES, collect};
pub use diff::{
    ContentChange, DiffSummary, FindingChange, ModuleChange, RegionChange, SnapshotDiff,
    SnapshotRef, ThreadChange, diff,
};
pub use dump::{DumpAnalysis, MinidumpSource, analyze_dump};
pub use envelope::{AcquisitionMeta, RegionHash, SnapshotEnvelope};
pub use format::{HEADER_LEN, MAGIC, decode, encode, read_file, write_file};
pub use source::SnapshotSource;
