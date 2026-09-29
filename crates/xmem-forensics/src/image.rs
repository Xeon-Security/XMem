//! `.xmemimg` 메모리 이미지(오프라인 재분석). 스냅샷 `.xmem`과 독립된 포맷이다.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use xmem_core::{
    Finding, JSON_SCHEMA_VERSION, MemoryRegion, MemorySource, ModuleInfo, ProcessInfo, ReadOutcome,
    Result, ThreadInfo, VERSION, XmemError,
};

use crate::format::temp_path;

pub const IMAGE_MAGIC: [u8; 7] = *b"XMEMIMG";
pub const IMAGE_FORMAT_VERSION: u16 = 1;
pub const IMAGE_HEADER_LEN: usize = 19;

#[derive(Debug, Clone)]
pub struct ImageOptions {
    pub budget_bytes: u64,
    pub max_region_bytes: u64,
    pub chunk_size: usize,
    pub executable_only: bool,
    pub private_only: bool,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            budget_bytes: 256 * 1024 * 1024,
            max_region_bytes: 16 * 1024 * 1024,
            chunk_size: 1024 * 1024,
            executable_only: false,
            private_only: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRegion {
    pub base: u64,
    pub region_size: u64,
    pub offset: u64,
    pub len: u64,
    pub partial: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageAcquisition {
    pub stored_regions: usize,
    pub stored_bytes: u64,
    pub budget_bytes: u64,
    pub read_failures: u64,
    pub skipped_unreadable: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageMeta {
    pub schema_version: u32,
    pub xmem_version: String,
    pub format_version: u16,
    pub timestamp: DateTime<Utc>,
    pub process: ProcessInfo,
    pub regions: Vec<MemoryRegion>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub findings: Vec<Finding>,
    pub contents: Vec<StoredRegion>,
    pub acquisition: ImageAcquisition,
}

#[derive(Debug, Clone)]
pub struct MemoryImage {
    pub meta: ImageMeta,
    pub content: Vec<u8>,
}

fn image_error(reason: impl Into<String>) -> XmemError {
    XmemError::SnapshotError {
        reason: reason.into(),
    }
}

/// committed+readable 영역을 정렬(executable desc, private 우선, base asc)해
/// 영역당 `max_region_bytes`, 총 `budget_bytes` 한도로 내용을 저장한다.
pub fn collect_image<S: MemorySource>(
    source: &S,
    options: &ImageOptions,
    cancel: &AtomicBool,
) -> Result<MemoryImage> {
    let regions = source.regions()?;
    let modules = source.modules()?;
    let threads = source.threads()?;
    let context = xmem_detection::DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    };
    let findings = xmem_detection::detect(&context);

    let mut candidates: Vec<usize> = regions
        .iter()
        .enumerate()
        .filter(|(_, region)| region.state == xmem_core::MemoryState::Commit && region.readable)
        .filter(|(_, region)| !options.executable_only || region.executable)
        .filter(|(_, region)| {
            !options.private_only || region.classification == xmem_core::RegionClass::Private
        })
        .map(|(index, _)| index)
        .collect();
    candidates.sort_by_key(|&index| {
        let region = &regions[index];
        (
            !region.executable,
            region.classification != xmem_core::RegionClass::Private,
            region.base,
        )
    });

    let mut content: Vec<u8> = Vec::new();
    let mut contents: Vec<StoredRegion> = Vec::new();
    let mut read_failures = 0u64;
    let mut skipped_unreadable = 0u64;
    let mut chunk = vec![0u8; options.chunk_size.max(4096)];
    for index in candidates {
        if content.len() as u64 >= options.budget_bytes {
            break;
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(XmemError::Cancelled {
                reason: "user interrupt".to_string(),
            });
        }
        let region = &regions[index];
        let limit = region.size.min(options.max_region_bytes);
        let mut stored: Vec<u8> = Vec::new();
        let mut offset = 0u64;
        let mut partial = region.size > limit;
        while offset < limit {
            if cancel.load(Ordering::Relaxed) {
                return Err(XmemError::Cancelled {
                    reason: "user interrupt".to_string(),
                });
            }
            let want = ((limit - offset).min(chunk.len() as u64)) as usize;
            match source.read(region.base + offset, &mut chunk[..want]) {
                Ok(outcome) if outcome.bytes_read > 0 => {
                    stored.extend_from_slice(&chunk[..outcome.bytes_read]);
                    offset += outcome.bytes_read as u64;
                    if outcome.partial || outcome.bytes_read < want {
                        partial = true;
                        break;
                    }
                }
                Ok(_) => {
                    read_failures += 1;
                    partial = true;
                    break;
                }
                Err(_) => {
                    read_failures += 1;
                    partial = true;
                    break;
                }
            }
        }
        if stored.is_empty() {
            skipped_unreadable += 1;
            continue;
        }
        let remaining = options.budget_bytes.saturating_sub(content.len() as u64);
        if stored.len() as u64 > remaining {
            stored.truncate(remaining as usize);
            partial = true;
        }
        contents.push(StoredRegion {
            base: region.base,
            region_size: region.size,
            offset: content.len() as u64,
            len: stored.len() as u64,
            partial,
        });
        content.extend_from_slice(&stored);
    }

    let stored_regions = contents.len();
    let stored_bytes = content.len() as u64;
    Ok(MemoryImage {
        meta: ImageMeta {
            schema_version: JSON_SCHEMA_VERSION,
            xmem_version: VERSION.to_string(),
            format_version: IMAGE_FORMAT_VERSION,
            timestamp: Utc::now(),
            process: source.process().clone(),
            regions,
            modules,
            threads,
            findings,
            contents,
            acquisition: ImageAcquisition {
                stored_regions,
                stored_bytes,
                budget_bytes: options.budget_bytes,
                read_failures,
                skipped_unreadable,
            },
        },
        content,
    })
}

pub fn encode_image(image: &MemoryImage) -> Result<Vec<u8>> {
    let meta = serde_json::to_vec_pretty(&image.meta)
        .map_err(|error| image_error(format!("JSON 직렬화 실패: {error}")))?;
    let meta_len = u32::try_from(meta.len())
        .map_err(|_| image_error(format!("meta가 너무 큼: {} bytes", meta.len())))?;
    let content_len = u32::try_from(image.content.len())
        .map_err(|_| image_error(format!("content가 너무 큼: {} bytes", image.content.len())))?;
    let mut out = Vec::with_capacity(IMAGE_HEADER_LEN + meta.len() + image.content.len());
    out.extend_from_slice(&IMAGE_MAGIC);
    out.extend_from_slice(&IMAGE_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&meta_len.to_le_bytes());
    out.extend_from_slice(&content_len.to_le_bytes());
    out.extend_from_slice(&meta);
    out.extend_from_slice(&image.content);
    Ok(out)
}

pub fn decode_image(bytes: &[u8]) -> Result<MemoryImage> {
    if bytes.len() < IMAGE_HEADER_LEN {
        return Err(image_error(format!(
            "파일이 너무 짧음: {} bytes",
            bytes.len()
        )));
    }
    if bytes[0..7] != IMAGE_MAGIC {
        return Err(image_error("magic 불일치 (XMEMIMG 파일 아님)"));
    }
    let version = u16::from_le_bytes([bytes[7], bytes[8]]);
    if version != IMAGE_FORMAT_VERSION {
        return Err(image_error(format!(
            "지원하지 않는 format_version: {version} (현재 {IMAGE_FORMAT_VERSION})"
        )));
    }
    let flags = u16::from_le_bytes([bytes[9], bytes[10]]);
    if flags != 0 {
        return Err(image_error(format!("알 수 없는 flags: {flags:#06x}")));
    }
    let meta_len = u32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]) as usize;
    let content_len = u32::from_le_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]) as usize;
    let expected = IMAGE_HEADER_LEN
        .checked_add(meta_len)
        .and_then(|value| value.checked_add(content_len))
        .ok_or_else(|| image_error("길이 오버플로"))?;
    if bytes.len() != expected {
        return Err(image_error(format!(
            "파일 길이 불일치: header {expected}, 실제 {}",
            bytes.len()
        )));
    }
    let meta: ImageMeta =
        serde_json::from_slice(&bytes[IMAGE_HEADER_LEN..IMAGE_HEADER_LEN + meta_len])
            .map_err(|error| image_error(format!("meta JSON 파싱 실패: {error}")))?;
    if meta.format_version != version {
        return Err(image_error(format!(
            "meta format_version 불일치: {} vs {version}",
            meta.format_version
        )));
    }
    for stored in &meta.contents {
        let end = stored
            .offset
            .checked_add(stored.len)
            .ok_or_else(|| image_error("영역 오프셋 오버플로"))?;
        if end > content_len as u64 {
            return Err(image_error(format!(
                "영역 {} 오프셋 초과: {end} > {content_len}",
                stored.base
            )));
        }
    }
    let content = bytes[IMAGE_HEADER_LEN + meta_len..].to_vec();
    Ok(MemoryImage { meta, content })
}

/// temp 파일에 쓰고 재파싱으로 검증한 뒤 atomic rename. 실패 시 temp를 제거한다.
pub fn write_image(path: &Path, image: &MemoryImage) -> Result<u64> {
    let bytes = encode_image(image)?;
    let file_bytes = bytes.len() as u64;
    let temp = temp_path(path);
    if let Err(error) = std::fs::write(&temp, &bytes) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    let validate = (|| -> Result<()> {
        let read_back = std::fs::read(&temp).map_err(XmemError::Io)?;
        if read_back != bytes {
            return Err(image_error("검증 실패: 기록 내용 불일치"));
        }
        decode_image(&read_back)?;
        Ok(())
    })();
    if let Err(err) = validate {
        std::fs::remove_file(&temp).ok();
        return Err(err);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    Ok(file_bytes)
}

pub fn read_image(path: &Path) -> Result<MemoryImage> {
    let bytes = std::fs::read(path).map_err(|error| XmemError::SnapshotError {
        reason: format!("이미지 파일 읽기 실패: {} ({error})", path.display()),
    })?;
    decode_image(&bytes)
}

/// 이미지 파일을 MemorySource로 노출한다. read는 저장된 영역만 대상으로 한다.
pub struct MemoryImageSource {
    meta: ImageMeta,
    content: Vec<u8>,
}

impl MemoryImageSource {
    pub fn open(path: &Path) -> Result<Self> {
        let image = read_image(path)?;
        Ok(Self {
            meta: image.meta,
            content: image.content,
        })
    }

    pub fn meta(&self) -> &ImageMeta {
        &self.meta
    }
}

impl MemorySource for MemoryImageSource {
    fn process(&self) -> &ProcessInfo {
        &self.meta.process
    }

    fn regions(&self) -> Result<Vec<MemoryRegion>> {
        Ok(self.meta.regions.clone())
    }

    fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
        for stored in &self.meta.contents {
            let base = stored.base;
            let end = base.saturating_add(stored.len);
            if address < base || address >= end {
                continue;
            }
            let skip = address - base;
            let start = stored.offset as usize + skip as usize;
            let available = (stored.len - skip).min(buf.len() as u64) as usize;
            buf[..available].copy_from_slice(&self.content[start..start + available]);
            return Ok(ReadOutcome {
                bytes_read: available,
                partial: (available as u64) < buf.len() as u64,
            });
        }
        Err(XmemError::InvalidAddress { address })
    }

    fn modules(&self) -> Result<Vec<ModuleInfo>> {
        Ok(self.meta.modules.clone())
    }

    fn threads(&self) -> Result<Vec<ThreadInfo>> {
        Ok(self.meta.threads.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicBool;
    use xmem_core::{MemoryState, MemoryType, ProcessArch, Protection, ReadOutcome, RegionClass};

    struct MockSource {
        info: ProcessInfo,
        regions: Vec<MemoryRegion>,
        content: BTreeMap<u64, Vec<u8>>,
    }

    impl MemorySource for MockSource {
        fn process(&self) -> &ProcessInfo {
            &self.info
        }
        fn regions(&self) -> Result<Vec<MemoryRegion>> {
            Ok(self.regions.clone())
        }
        fn read(&self, address: u64, buf: &mut [u8]) -> Result<ReadOutcome> {
            let Some((base, bytes)) = self
                .content
                .iter()
                .find(|(base, bytes)| address >= **base && address < **base + bytes.len() as u64)
            else {
                return Err(XmemError::InvalidAddress { address });
            };
            let start = (address - *base) as usize;
            let n = (bytes.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(ReadOutcome {
                bytes_read: n,
                partial: n < buf.len(),
            })
        }
        fn modules(&self) -> Result<Vec<ModuleInfo>> {
            Ok(Vec::new())
        }
        fn threads(&self) -> Result<Vec<ThreadInfo>> {
            Ok(Vec::new())
        }
    }

    fn mock(base: u64, size: u64, bytes: usize) -> MockSource {
        MockSource {
            info: ProcessInfo {
                pid: 9,
                ppid: None,
                name: "mock.exe".into(),
                image_path: None,
                arch: ProcessArch::X64,
                session_id: None,
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: None,
                module_count: None,
            },
            regions: vec![MemoryRegion {
                base,
                size,
                allocation_base: Some(base),
                state: MemoryState::Commit,
                protection: Protection::new(0x04, true, true, false),
                allocation_protection: None,
                region_type: Some(MemoryType::Private),
                readable: true,
                writable: true,
                executable: false,
                classification: RegionClass::Private,
                heuristics: Vec::new(),
                mapped_file: None,
            }],
            content: BTreeMap::from([(base, (0..bytes as u8).collect())]),
        }
    }

    #[test]
    fn encode_decode_roundtrip_keeps_meta_and_content() {
        let source = mock(0x1000, 0x100, 0x40);
        let image =
            collect_image(&source, &ImageOptions::default(), &AtomicBool::new(false)).unwrap();
        let bytes = encode_image(&image).unwrap();
        assert_eq!(&bytes[0..7], b"XMEMIMG");
        let back = decode_image(&bytes).unwrap();
        assert_eq!(back.meta.process.pid, 9);
        assert_eq!(back.meta.contents.len(), 1);
        assert_eq!(back.content, image.content);
        assert_eq!(back.meta.acquisition.stored_bytes, 0x40);
    }

    #[test]
    fn decode_rejects_bad_header_and_offsets() {
        let source = mock(0x1000, 0x100, 0x10);
        let image =
            collect_image(&source, &ImageOptions::default(), &AtomicBool::new(false)).unwrap();
        let bytes = encode_image(&image).unwrap();
        assert!(matches!(
            decode_image(b"XM"),
            Err(XmemError::SnapshotError { .. })
        ));
        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'Y';
        assert!(matches!(
            decode_image(&bad_magic),
            Err(XmemError::SnapshotError { .. })
        ));
        let mut bad_version = bytes.clone();
        bad_version[7] = 99;
        assert!(matches!(
            decode_image(&bad_version),
            Err(XmemError::SnapshotError { .. })
        ));
        let mut overflow = bytes.clone();
        // content_len을 1 줄여 저장 오프셋이 범위를 벗어나게 만든다
        let len = overflow.len();
        overflow.truncate(len - 1);
        assert!(matches!(
            decode_image(&overflow),
            Err(XmemError::SnapshotError { .. })
        ));
    }

    #[test]
    fn image_source_reads_full_partial_and_rejects_outside() {
        let source = mock(0x1000, 0x100, 0x20);
        let image =
            collect_image(&source, &ImageOptions::default(), &AtomicBool::new(false)).unwrap();
        let dir = std::env::temp_dir().join(format!("xmem-img-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.xmemimg");
        write_image(&path, &image).unwrap();
        let loaded = MemoryImageSource::open(&path).unwrap();

        let mut buf = [0u8; 0x20];
        let outcome = loaded.read(0x1000, &mut buf).unwrap();
        assert_eq!(outcome.bytes_read, 0x20);
        assert!(!outcome.partial);

        let mut small = [0u8; 0x40];
        let outcome = loaded.read(0x1010, &mut small).unwrap();
        assert_eq!(outcome.bytes_read, 0x10);
        assert!(outcome.partial, "남은 바이트보다 크게 요청");

        assert!(matches!(
            loaded.read(0x9000, &mut buf),
            Err(XmemError::InvalidAddress { .. })
        ));
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn collect_respects_budget_flags_and_cancel() {
        let source = mock(0x1000, 0x100, 0x80);
        let options = ImageOptions {
            budget_bytes: 0x20,
            ..ImageOptions::default()
        };
        let image = collect_image(&source, &options, &AtomicBool::new(false)).unwrap();
        assert_eq!(image.meta.acquisition.stored_bytes, 0x20);
        assert!(image.meta.contents[0].partial);

        let options = ImageOptions {
            executable_only: true,
            ..ImageOptions::default()
        };
        let image = collect_image(&source, &options, &AtomicBool::new(false)).unwrap();
        assert_eq!(image.meta.contents.len(), 0);

        let cancel = AtomicBool::new(true);
        assert!(matches!(
            collect_image(&source, &ImageOptions::default(), &cancel),
            Err(XmemError::Cancelled { .. })
        ));
    }
}
