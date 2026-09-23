//! 시나리오별 메모리 아티팩트와 Ground Truth.

use serde_json::{Value, json};
use xmem_windows::OwnedHandle;
use xmem_windows::selfmem::{
    PrivateRegion, SELF_PAGE_RWX, SELF_PAGE_RX, alloc_executable, spawn_suspended_thread, thread_id,
};

/// pattern 시나리오에서 쓰는 ASCII 문자열.
pub const PATTERN_ASCII: &[u8] = b"XMEM_PATTERN_ALPHA_0123456789";
/// pattern 시나리오에서 쓰는 UTF-16 문자열.
pub const PATTERN_WIDE: &str = "XMEM_WIDE_PATTERN";
/// pattern 시나리오에서 쓰는 바이트 패턴.
pub const PATTERN_BYTES: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
const PATTERN_SIZE: usize = 64 * 1024;
/// UTF-16 패턴 오프셋.
pub const WIDE_OFFSET: usize = 0x1000;
/// 바이트 패턴 오프셋.
pub const BYTES_OFFSET: usize = 0x2000;

/// 아티팩트를 살아 있게 유지하는 컨테이너. Drop 시 전부 해제된다.
pub struct Lab {
    pub regions: Vec<PrivateRegion>,
    pub threads: Vec<OwnedHandle>,
}

impl Lab {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            threads: Vec::new(),
        }
    }

    fn push(&mut self, region: PrivateRegion) -> usize {
        self.regions.push(region);
        self.regions.len() - 1
    }

    fn region(&self, index: usize) -> &PrivateRegion {
        &self.regions[index]
    }
}

impl Default for Lab {
    fn default() -> Self {
        Self::new()
    }
}

/// 시나리오를 구성하고 Ground Truth 아티팩트를 반환한다.
pub fn setup(scenario: &str) -> Result<(Lab, Value), String> {
    let names: Vec<&str> = if scenario == "all" {
        vec![
            "normal",
            "pattern",
            "private",
            "private-exec",
            "pe-like",
            "threads",
            "protection",
        ]
    } else {
        vec![scenario]
    };

    let mut lab = Lab::new();
    let mut artifacts = serde_json::Map::new();
    for name in names {
        let value = match name {
            "normal" => normal(&mut lab)?,
            "pattern" => pattern(&mut lab)?,
            "private" => private(&mut lab)?,
            "private-exec" => private_exec(&mut lab)?,
            "pe-like" => pe_like(&mut lab)?,
            "threads" => threads(&mut lab)?,
            "protection" => protection(&mut lab)?,
            other => return Err(format!("알 수 없는 시나리오: {other}")),
        };
        artifacts.insert(name.to_string(), value);
    }
    Ok((lab, Value::Object(artifacts)))
}

fn normal(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(4096).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_BENIGN_MEMORY")
        .map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
    }))
}

fn pattern(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(PATTERN_SIZE).map_err(|e| e.to_string())?;
    region.write(PATTERN_ASCII).map_err(|e| e.to_string())?;
    let wide: Vec<u8> = PATTERN_WIDE
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    region
        .write_at(WIDE_OFFSET, &wide)
        .map_err(|e| e.to_string())?;
    region
        .write_at(BYTES_OFFSET, PATTERN_BYTES)
        .map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "ascii_offset": 0,
        "wide_offset": WIDE_OFFSET,
        "bytes_offset": BYTES_OFFSET,
        "ascii": std::str::from_utf8(PATTERN_ASCII).unwrap_or(""),
        "wide": PATTERN_WIDE,
    }))
}

fn private(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(8192).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_PRIVATE_BENIGN_DATA")
        .map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "protection": "RW",
    }))
}

fn private_exec(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(16 * 1024).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_PRIVATE_EXEC_BENIGN")
        .map_err(|e| e.to_string())?;
    region.protect(SELF_PAGE_RWX).map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "protection": "RWX",
    }))
}

fn pe_like(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(16 * 1024).map_err(|e| e.to_string())?;
    region.write(&fake_pe_bytes()).map_err(|e| e.to_string())?;
    region.protect(SELF_PAGE_RX).map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "protection": "RX",
    }))
}

fn threads(lab: &mut Lab) -> Result<Value, String> {
    let region = alloc_executable(&[0xC3], SELF_PAGE_RX).map_err(|e| e.to_string())?;
    let start_address = region.base();
    let index = lab.push(region);
    let handle = spawn_suspended_thread(start_address).map_err(|e| e.to_string())?;
    let tid = thread_id(&handle);
    lab.threads.push(handle);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "start_address": start_address,
        "tid": tid,
    }))
}

fn protection(lab: &mut Lab) -> Result<Value, String> {
    let mut region = PrivateRegion::alloc(8192).map_err(|e| e.to_string())?;
    region
        .write(b"XMEM_PROTECTION_EXPERIMENT")
        .map_err(|e| e.to_string())?;
    let old = region.protect(SELF_PAGE_RWX).map_err(|e| e.to_string())?;
    let index = lab.push(region);
    Ok(json!({
        "base": lab.region(index).base(),
        "size": lab.region(index).size(),
        "before": "RW",
        "after": "RWX",
        "old_raw": old,
    }))
}

/// private executable 메모리에 넣는 최소 PE (MZ + PE\0\0 + COFF + optional + .text).
pub fn fake_pe_bytes() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    buf[0] = b'M';
    buf[1] = b'Z';
    let pe_offset = 0x40usize;
    buf[0x3c..0x40].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    buf[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");

    let coff = pe_offset + 4;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0x00f0u16.to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());

    let section = opt + 0x00f0;
    buf[section..section + 5].copy_from_slice(b".text");
    buf[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::RegionClass;
    use xmem_pe::{MemoryPeClass, classify_memory_pe};

    #[test]
    fn fake_pe_is_classified_private_pe_like() {
        let bytes = fake_pe_bytes();
        assert!(xmem_pe::looks_like_pe(&bytes));
        assert_eq!(
            classify_memory_pe(RegionClass::Private, &bytes),
            MemoryPeClass::PrivatePeLike
        );
    }

    #[test]
    fn all_scenario_sets_up_every_artifact() {
        let (_lab, artifacts) = setup("all").unwrap();
        for name in [
            "normal",
            "pattern",
            "private",
            "private-exec",
            "pe-like",
            "threads",
            "protection",
        ] {
            let base = artifacts[name]["base"].as_u64().unwrap_or(0);
            assert_ne!(base, 0, "{name} base");
        }
        assert_ne!(artifacts["threads"]["tid"].as_u64().unwrap_or(0), 0);
        assert_eq!(artifacts["protection"]["before"], "RW");
        assert_eq!(artifacts["protection"]["after"], "RWX");
    }
}
