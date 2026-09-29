use std::path::Path;

use serde::Serialize;
use xmem_core::{ProcessArch, RegionClass, Result, XmemError};

/// 메모리 PE 프로브 시 읽는 헤더 prefix 크기.
pub const PE_HEADER_PREFIX: usize = 4096;

/// 파일 전체 파싱 상한. 초과 시 헤더 prefix만 파싱한다.
pub const MAX_FILE_PARSE_BYTES: u64 = 64 * 1024 * 1024;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const PE32_MAGIC: u16 = 0x10b;
const PE32_PLUS_MAGIC: u16 = 0x20b;

/// 메모리에서 관찰한 PE artifact 분류.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryPeClass {
    None,
    NormalLoadedModule,
    MappedImage,
    PrivatePeLike,
    Malformed,
    Unknown,
}

impl MemoryPeClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryPeClass::None => "none",
            MemoryPeClass::NormalLoadedModule => "normal_loaded_module",
            MemoryPeClass::MappedImage => "mapped_image",
            MemoryPeClass::PrivatePeLike => "private_pe_like",
            MemoryPeClass::Malformed => "malformed",
            MemoryPeClass::Unknown => "unknown",
        }
    }
}

/// PE 섹션 요약.
#[derive(Debug, Clone, Serialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// PE 이미지 요약. 헤더 prefix만 파싱한 경우 임포트/익스포트/relocation/TLS는 0/빈 값이다.
#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub is_64: bool,
    pub machine: u16,
    pub arch: ProcessArch,
    pub image_base: u64,
    pub entry_point: u64,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub characteristics: u16,
    /// COFF 헤더의 TimeDateStamp(Unix epoch 초). 링커가 기록한다.
    pub time_date_stamp: u32,
    pub sections: Vec<PeSection>,
    pub import_count: usize,
    pub import_library_count: usize,
    pub libraries: Vec<String>,
    pub export_count: usize,
    pub relocation_count: usize,
    pub tls_callback_count: usize,
}

struct HeaderFields {
    machine: u16,
    characteristics: u16,
    time_date_stamp: u32,
    is_64: bool,
    image_base: u64,
    entry_point: u64,
    size_of_image: u32,
    subsystem: u16,
    sections: Vec<PeSection>,
}

fn invalid(reason: &str) -> XmemError {
    XmemError::InvalidPe {
        reason: reason.to_string(),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|raw| u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes.get(offset..offset + 8).map(|raw| {
        u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ])
    })
}

fn decode_section_permissions(characteristics: u32) -> (bool, bool, bool) {
    (
        characteristics & IMAGE_SCN_MEM_READ != 0,
        characteristics & IMAGE_SCN_MEM_WRITE != 0,
        characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
    )
}

/// DOS 'MZ' + e_lfanew 범위 + 'PE\0\0' 시그니처 검사.
pub fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return false;
    }
    let e_lfanew =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let Some(sig_end) = e_lfanew.checked_add(4) else {
        return false;
    };
    sig_end <= bytes.len() && &bytes[e_lfanew..sig_end] == b"PE\0\0"
}

/// 헤더(COFF/optional/section table)를 직접 파싱한다.
///
/// goblin은 전체 파일을 요구하므로(데이터 디렉터리가 파일 범위를 벗어나면 오류),
/// 메모리에서 읽은 4 KiB prefix에도 동작하는 bounds-checked 파서를 둔다.
fn parse_header(bytes: &[u8]) -> Result<HeaderFields> {
    if !looks_like_pe(bytes) {
        return Err(invalid("PE 시그니처 없음"));
    }
    let e_lfanew =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let coff = e_lfanew + 4;
    let machine = read_u16(bytes, coff).ok_or_else(|| invalid("COFF 헤더가 잘렸습니다"))?;
    let section_count =
        read_u16(bytes, coff + 2).ok_or_else(|| invalid("COFF 헤더가 잘렸습니다"))?;
    let optional_size =
        read_u16(bytes, coff + 16).ok_or_else(|| invalid("COFF 헤더가 잘렸습니다"))? as usize;
    let characteristics =
        read_u16(bytes, coff + 18).ok_or_else(|| invalid("COFF 헤더가 잘렸습니다"))?;
    let time_date_stamp =
        read_u32(bytes, coff + 4).ok_or_else(|| invalid("COFF 헤더가 잘렸습니다"))?;
    let optional = coff + 20;
    let magic = read_u16(bytes, optional).ok_or_else(|| invalid("optional 헤더가 잘렸습니다"))?;
    let is_64 = match magic {
        PE32_PLUS_MAGIC => true,
        PE32_MAGIC => false,
        _ => return Err(invalid("알 수 없는 optional 헤더 magic")),
    };
    let entry_rva =
        read_u32(bytes, optional + 16).ok_or_else(|| invalid("optional 헤더가 잘렸습니다"))?;
    let image_base = if is_64 {
        read_u64(bytes, optional + 24)
    } else {
        read_u32(bytes, optional + 28).map(u64::from)
    }
    .ok_or_else(|| invalid("optional 헤더가 잘렸습니다"))?;
    let size_of_image =
        read_u32(bytes, optional + 56).ok_or_else(|| invalid("optional 헤더가 잘렸습니다"))?;
    let subsystem =
        read_u16(bytes, optional + 68).ok_or_else(|| invalid("optional 헤더가 잘렸습니다"))?;
    let table = optional + optional_size;
    let mut sections = Vec::with_capacity(section_count as usize);
    for index in 0..section_count as usize {
        let base = table + index * 40;
        let name_raw = bytes
            .get(base..base + 8)
            .ok_or_else(|| invalid("섹션 테이블이 잘렸습니다"))?;
        let name: Vec<u8> = name_raw
            .iter()
            .take_while(|byte| **byte != 0)
            .copied()
            .collect();
        let section_characteristics =
            read_u32(bytes, base + 36).ok_or_else(|| invalid("섹션 테이블이 잘렸습니다"))?;
        let (readable, writable, executable) = decode_section_permissions(section_characteristics);
        sections.push(PeSection {
            name: String::from_utf8_lossy(&name).into_owned(),
            virtual_address: read_u32(bytes, base + 12)
                .ok_or_else(|| invalid("섹션 테이블이 잘렸습니다"))?,
            virtual_size: read_u32(bytes, base + 8)
                .ok_or_else(|| invalid("섹션 테이블이 잘렸습니다"))?,
            raw_size: read_u32(bytes, base + 16)
                .ok_or_else(|| invalid("섹션 테이블이 잘렸습니다"))?,
            characteristics: section_characteristics,
            readable,
            writable,
            executable,
        });
    }
    Ok(HeaderFields {
        machine,
        characteristics,
        time_date_stamp,
        is_64,
        image_base,
        entry_point: image_base.saturating_add(u64::from(entry_rva)),
        size_of_image,
        subsystem,
        sections,
    })
}

/// PE 바이트(전체 파일 또는 헤더 prefix)를 파싱한다.
///
/// 헤더는 항상 직접 파싱하고, 전체 파일 바이트인 경우에만 goblin으로 임포트/익스포트/
/// relocation/TLS를 보강한다. 헤더가 무효면 `InvalidPe`, 데이터 디렉터리만 손상된 경우에는
/// 헤더 정보만 담아 성공한다(메모리 아티팩트 분석 관점).
pub fn parse_pe(bytes: &[u8]) -> Result<PeInfo> {
    let header = parse_header(bytes)?;
    let mut info = PeInfo {
        is_64: header.is_64,
        machine: header.machine,
        arch: ProcessArch::from_machine(header.machine),
        image_base: header.image_base,
        entry_point: header.entry_point,
        size_of_image: header.size_of_image,
        subsystem: header.subsystem,
        characteristics: header.characteristics,
        time_date_stamp: header.time_date_stamp,
        sections: header.sections,
        import_count: 0,
        import_library_count: 0,
        libraries: Vec::new(),
        export_count: 0,
        relocation_count: 0,
        tls_callback_count: 0,
    };
    if let Ok(pe) = goblin::pe::PE::parse(bytes) {
        info.import_count = pe.imports.len();
        info.libraries = pe
            .libraries
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        info.import_library_count = info.libraries.len();
        info.export_count = pe.exports.len();
        info.relocation_count = pe.relocation_data.as_ref().map_or(0, |data| {
            data.blocks()
                .flatten()
                .map(|block| block.words().filter(|word| word.is_ok()).count())
                .sum()
        });
        info.tls_callback_count = pe.tls_data.as_ref().map_or(0, |tls| tls.callbacks.len());
    }
    Ok(info)
}

/// 디스크의 PE 파일을 파싱한다. 전체 파일을 읽어 임포트/익스포트/relocation/TLS까지 채운다.
///
/// `MAX_FILE_PARSE_BYTES`를 넘는 대형 파일은 헤더 prefix만 파싱한다(임포트 등은 0).
pub fn parse_pe_file(path: &Path) -> Result<PeInfo> {
    let metadata = std::fs::metadata(path).map_err(XmemError::Io)?;
    if metadata.len() > MAX_FILE_PARSE_BYTES {
        let mut file = std::fs::File::open(path).map_err(XmemError::Io)?;
        let mut buf = vec![0u8; PE_HEADER_PREFIX];
        let read = std::io::Read::read(&mut file, &mut buf).map_err(XmemError::Io)?;
        buf.truncate(read);
        return parse_pe(&buf);
    }
    let bytes = std::fs::read(path).map_err(XmemError::Io)?;
    parse_pe(&bytes)
}

/// 메모리 영역 분류와 PE 헤더 바이트로 PE artifact를 분류한다.
pub fn classify_memory_pe(region_class: RegionClass, bytes: &[u8]) -> MemoryPeClass {
    if !looks_like_pe(bytes) {
        return MemoryPeClass::None;
    }
    match parse_pe(bytes) {
        Ok(_) => match region_class {
            RegionClass::Image => MemoryPeClass::NormalLoadedModule,
            RegionClass::Mapped => MemoryPeClass::MappedImage,
            RegionClass::Private => MemoryPeClass::PrivatePeLike,
            _ => MemoryPeClass::Unknown,
        },
        Err(_) => MemoryPeClass::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcg(seed: &mut u64) -> u32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 33) as u32
    }

    fn own_exe_bytes() -> Vec<u8> {
        let path = std::env::current_exe().unwrap();
        std::fs::read(path).unwrap()
    }

    fn e_lfanew(bytes: &[u8]) -> usize {
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize
    }

    #[test]
    fn looks_like_pe_detects_own_exe() {
        let bytes = own_exe_bytes();
        assert!(looks_like_pe(&bytes));
        assert!(!looks_like_pe(b""));
        assert!(!looks_like_pe(b"hello world"));
        assert!(!looks_like_pe(b"MZ"));
    }

    #[test]
    fn parse_own_exe_full() {
        let bytes = own_exe_bytes();
        let pe = parse_pe(&bytes).unwrap();
        assert!(pe.image_base > 0);
        assert!(pe.entry_point >= pe.image_base);
        assert!(!pe.sections.is_empty());
        assert!(pe.sections.iter().any(|section| !section.name.is_empty()));
        assert!(pe.import_count > 0);
        assert!(!pe.libraries.is_empty());
        assert!(pe.is_64);
        assert_eq!(pe.arch, ProcessArch::X64);
    }

    #[test]
    fn parse_header_prefix_of_own_exe() {
        let bytes = own_exe_bytes();
        let prefix = &bytes[..PE_HEADER_PREFIX.min(bytes.len())];
        let pe = parse_pe(prefix).unwrap();
        assert!(pe.image_base > 0);
        assert!(!pe.sections.is_empty());
        assert!(pe.size_of_image > 0);
        assert_eq!(pe.import_count, 0);
        assert!(pe.time_date_stamp > 0, "COFF 타임스탬프");
    }

    #[test]
    fn parse_pe_file_of_own_exe_reads_imports_and_timestamp() {
        let path = std::env::current_exe().unwrap();
        let pe = parse_pe_file(&path).unwrap();
        assert!(pe.import_count > 0);
        assert!(!pe.libraries.is_empty());
        assert!(pe.time_date_stamp > 0);
        assert!(!pe.sections.is_empty());
        let header_only = parse_pe(&own_exe_bytes()[..PE_HEADER_PREFIX]).unwrap();
        assert_eq!(pe.time_date_stamp, header_only.time_date_stamp);
    }

    #[test]
    fn parse_pe_file_rejects_missing_file() {
        let path = Path::new(r"C:\xmem-does-not-exist\xmem.exe");
        assert!(matches!(parse_pe_file(path), Err(XmemError::Io(_))));
    }

    #[test]
    fn header_parse_matches_full_parse() {
        let bytes = own_exe_bytes();
        let prefix = &bytes[..PE_HEADER_PREFIX.min(bytes.len())];
        let full = parse_pe(&bytes).unwrap();
        let head = parse_pe(prefix).unwrap();
        assert_eq!(full.image_base, head.image_base);
        assert_eq!(full.entry_point, head.entry_point);
        assert_eq!(full.machine, head.machine);
        assert_eq!(full.is_64, head.is_64);
        assert_eq!(full.size_of_image, head.size_of_image);
        assert_eq!(full.subsystem, head.subsystem);
        assert_eq!(full.characteristics, head.characteristics);
        assert_eq!(full.sections.len(), head.sections.len());
        assert_eq!(full.sections[0].name, head.sections[0].name);
        assert_eq!(
            full.sections[0].characteristics,
            head.sections[0].characteristics
        );
        assert!(full.import_count > 0);
    }

    #[test]
    fn parse_rejects_non_pe_and_truncated_prefix() {
        assert!(matches!(
            parse_pe(b"not a pe at all"),
            Err(XmemError::InvalidPe { .. })
        ));
        let bytes = own_exe_bytes();
        let truncated = &bytes[..64];
        assert!(matches!(
            parse_pe(truncated),
            Err(XmemError::InvalidPe { .. })
        ));
    }

    #[test]
    fn section_permissions_decode() {
        let bytes = own_exe_bytes();
        let pe = parse_pe(&bytes).unwrap();
        assert!(pe.sections.iter().any(|section| section.executable));
        assert!(pe.sections.iter().any(|section| section.writable));
        assert!(
            pe.sections
                .iter()
                .all(|section| !section.executable || section.readable)
        );
    }

    #[test]
    fn classify_memory_pe_maps_region_classes() {
        let bytes = own_exe_bytes();
        let prefix = &bytes[..PE_HEADER_PREFIX.min(bytes.len())];
        assert_eq!(
            classify_memory_pe(RegionClass::Private, prefix),
            MemoryPeClass::PrivatePeLike
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Image, prefix),
            MemoryPeClass::NormalLoadedModule
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Mapped, prefix),
            MemoryPeClass::MappedImage
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Free, prefix),
            MemoryPeClass::Unknown
        );
        assert_eq!(
            classify_memory_pe(RegionClass::Private, b"garbage"),
            MemoryPeClass::None
        );
    }

    #[test]
    fn classify_memory_pe_reports_malformed() {
        let bytes = own_exe_bytes();
        let sig_end = e_lfanew(&bytes) + 6;
        let broken = &bytes[..sig_end];
        assert!(looks_like_pe(broken));
        assert_eq!(
            classify_memory_pe(RegionClass::Private, broken),
            MemoryPeClass::Malformed
        );
    }

    #[test]
    fn memory_pe_class_names() {
        assert_eq!(MemoryPeClass::None.as_str(), "none");
        assert_eq!(
            MemoryPeClass::NormalLoadedModule.as_str(),
            "normal_loaded_module"
        );
        assert_eq!(MemoryPeClass::PrivatePeLike.as_str(), "private_pe_like");
        assert_eq!(MemoryPeClass::Malformed.as_str(), "malformed");
    }

    #[test]
    fn parse_pe_never_panics_on_random_and_seeded_input() {
        let mut seed = 0xdead_beef_0bad_f00d_u64;
        for round in 0..2000 {
            let len = (lcg(&mut seed) % 4096) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| (lcg(&mut seed) & 0xff) as u8).collect();
            if round % 2 == 0 && bytes.len() >= 0x48 {
                bytes[0] = b'M';
                bytes[1] = b'Z';
                bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
                bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
            }
            let _ = looks_like_pe(&bytes);
            let _ = parse_pe(&bytes);
        }
    }
}
