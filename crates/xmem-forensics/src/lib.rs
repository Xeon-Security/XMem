//! Snapshot 포맷/직렬화, SnapshotSource, Diff, Minidump 분석. (M7, M9)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod collect;
pub mod diff;
pub mod dump;
pub mod envelope;
pub mod format;
pub mod image;
pub mod report;
pub mod source;

pub use collect::{CollectOptions, DEFAULT_HASH_BUDGET_BYTES, collect};
pub use diff::{
    ContentChange, DiffSummary, FindingChange, ModuleChange, RegionChange, SnapshotDiff,
    SnapshotRef, ThreadChange, diff,
};
pub use dump::{DumpAnalysis, MinidumpSource, analyze_dump};
pub use envelope::{AcquisitionMeta, RegionHash, SnapshotEnvelope};
pub use format::{HEADER_LEN, MAGIC, decode, encode, read_file, write_file};
pub use image::{
    ByteChange, IMAGE_FORMAT_VERSION, IMAGE_MAGIC, ImageAcquisition, ImageDiff, ImageDiffRef,
    ImageMeta, ImageOptions, MemoryImage, MemoryImageSource, RegionByteDiff, StoredRegion,
    collect_image, decode_image, diff_images, encode_image, read_image, write_image,
};
pub use report::{ReportData, ReportSummary, is_markdown, write_report};
pub use source::SnapshotSource;
