//! PE 이미지 분석: 헤더/섹션/임포트/익스포트/relocation/TLS와 메모리 PE artifact 분류.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod image;

pub use image::{
    MemoryPeClass, PE_HEADER_PREFIX, PeInfo, PeSection, classify_memory_pe, looks_like_pe, parse_pe,
};
