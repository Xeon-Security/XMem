//! MemorySource 구현: LiveProcess / Snapshot / Minidump / MemoryImage.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod live;
pub mod scan;

pub use live::{LiveProcess, RegionMap};
pub use scan::{
    DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, HUGE_COMMIT_THRESHOLD, MAX_CHUNK_SIZE, MAX_THREADS,
    MIN_CHUNK_SIZE, RegionFilters, ScanMatch, ScanOptions, ScanProgress, ScanReport, ScanStats,
    scan, scan_with_progress,
};
