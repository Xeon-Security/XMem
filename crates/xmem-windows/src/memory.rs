use std::ffi::c_void;
use std::mem::size_of;

use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE,
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualQueryEx,
};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use xmem_core::{MemoryRegion, MemoryState, MemoryType, Protection, Result, classify, heuristics};

use crate::error::{last_win32_error, win32_code_from_hresult};
use crate::handle::OwnedHandle;
use crate::util::utf16_z_to_string;

/// region walk 상한. 초과 시 truncated로 보고한다.
pub const MAX_REGIONS: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRegion {
    pub base: u64,
    pub allocation_base: u64,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub allocation_protect: u32,
    pub region_type: u32,
}

#[derive(Debug, Default)]
pub struct RegionWalk {
    pub regions: Vec<RawRegion>,
    pub truncated: bool,
}

/// PAGE_* 값을 R/W/X 플래그로 디코드한다. guard/nocache는 raw에 보존된다.
pub fn protection_from_raw(raw: u32) -> Protection {
    let base = raw & 0xff;
    let (readable, writable, executable) =
        if base == PAGE_EXECUTE_READWRITE.0 || base == PAGE_EXECUTE_WRITECOPY.0 {
            (true, true, true)
        } else if base == PAGE_EXECUTE_READ.0 {
            (true, false, true)
        } else if base == PAGE_EXECUTE.0 {
            (false, false, true)
        } else if base == PAGE_READWRITE.0 || base == PAGE_WRITECOPY.0 {
            (true, true, false)
        } else if base == PAGE_READONLY.0 {
            (true, false, false)
        } else {
            (false, false, false)
        };
    Protection::new(raw, readable, writable, executable)
}

pub fn memory_state(raw: u32) -> Option<MemoryState> {
    if raw == MEM_COMMIT.0 {
        Some(MemoryState::Commit)
    } else if raw == MEM_RESERVE.0 {
        Some(MemoryState::Reserve)
    } else if raw == MEM_FREE.0 {
        Some(MemoryState::Free)
    } else {
        None
    }
}

pub fn memory_type(raw: u32) -> Option<MemoryType> {
    if raw == MEM_IMAGE.0 {
        Some(MemoryType::Image)
    } else if raw == MEM_MAPPED.0 {
        Some(MemoryType::Mapped)
    } else if raw == MEM_PRIVATE.0 {
        Some(MemoryType::Private)
    } else {
        None
    }
}

/// 파일(이미지/매핑) 기반 commit 영역인지. Free/Reserve/Private에는 file name이 없다.
pub fn is_file_backed(region: &RawRegion) -> bool {
    region.state == MEM_COMMIT.0
        && (region.region_type == MEM_IMAGE.0 || region.region_type == MEM_MAPPED.0)
}

/// VirtualQueryEx를 max_address까지 반복한다. 정상 종료 조건: 87(INVALID_PARAMETER), RegionSize==0, 주소 비진행.
pub fn walk_regions(
    handle: &OwnedHandle,
    max_address: u64,
    max_regions: usize,
) -> Result<RegionWalk> {
    let mut regions = Vec::new();
    let mut address: u64 = 0;
    let mut truncated = false;
    loop {
        if address >= max_address {
            break;
        }
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                handle.raw(),
                Some(address as *const c_void),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            let err = windows::core::Error::from_thread();
            if win32_code_from_hresult(err.code().0) == ERROR_INVALID_PARAMETER.0 {
                break;
            }
            return Err(last_win32_error("VirtualQueryEx"));
        }
        let size = mbi.RegionSize as u64;
        if size == 0 {
            break;
        }
        if regions.len() >= max_regions {
            truncated = true;
            break;
        }
        regions.push(RawRegion {
            base: mbi.BaseAddress as u64,
            allocation_base: mbi.AllocationBase as u64,
            size,
            state: mbi.State.0,
            protect: mbi.Protect.0,
            allocation_protect: mbi.AllocationProtect.0,
            region_type: mbi.Type.0,
        });
        let next = (mbi.BaseAddress as u64).max(address).saturating_add(size);
        if next <= address {
            break;
        }
        address = next;
    }
    Ok(RegionWalk { regions, truncated })
}

/// 매핑된 파일 이름(디바이스 경로). 실패(0)면 None. buf는 재사용 가능한 UTF-16 버퍼.
pub fn mapped_file_name(handle: &OwnedHandle, base: u64, buf: &mut [u16]) -> Option<String> {
    let len = unsafe { GetMappedFileNameW(handle.raw(), base as *const c_void, buf) };
    if len == 0 {
        return None;
    }
    let len = (len as usize).min(buf.len());
    Some(utf16_z_to_string(&buf[..len]))
}

/// 사용자 주소 공간 상한(GetNativeSystemInfo). walk 종료 조건으로 사용한다.
pub fn native_max_user_address() -> u64 {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut info) };
    info.lpMaximumApplicationAddress as u64
}

/// RawRegion을 core 모델로 변환한다. 알 수 없는 state는 None(호출자가 skip).
pub fn region_from_raw(raw: &RawRegion, mapped_file: Option<String>) -> Option<MemoryRegion> {
    let state = memory_state(raw.state)?;
    let region_type = memory_type(raw.region_type);
    let protection = protection_from_raw(raw.protect);
    let allocation_protection =
        (raw.allocation_protect != 0).then(|| protection_from_raw(raw.allocation_protect));
    let classification = classify(state, region_type);
    let hs = heuristics(state, &protection, region_type);
    Some(MemoryRegion {
        base: raw.base,
        size: raw.size,
        state,
        protection,
        allocation_protection,
        region_type,
        readable: protection.readable,
        writable: protection.writable,
        executable: protection.executable,
        classification,
        heuristics: hs,
        mapped_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Memory::PAGE_NOACCESS;
    use xmem_core::RegionClass;

    fn raw_region(state: u32, protect: u32, region_type: u32) -> RawRegion {
        RawRegion {
            base: 0x1000_0000,
            allocation_base: 0x1000_0000,
            size: 0x1000,
            state,
            protect,
            allocation_protect: 0,
            region_type,
        }
    }

    #[test]
    fn protection_flags_decode_known_values() {
        let cases = [
            (PAGE_NOACCESS.0, false, false, false),
            (PAGE_READONLY.0, true, false, false),
            (PAGE_READWRITE.0, true, true, false),
            (PAGE_WRITECOPY.0, true, true, false),
            (PAGE_EXECUTE.0, false, false, true),
            (PAGE_EXECUTE_READ.0, true, false, true),
            (PAGE_EXECUTE_READWRITE.0, true, true, true),
            (PAGE_EXECUTE_WRITECOPY.0, true, true, true),
        ];
        for (raw, r, w, x) in cases {
            let p = protection_from_raw(raw);
            assert_eq!(
                (p.readable, p.writable, p.executable),
                (r, w, x),
                "raw={raw:#x}"
            );
        }
    }

    #[test]
    fn protection_keeps_guard_bits_in_raw() {
        let p = protection_from_raw(PAGE_EXECUTE_READ.0 | 0x100);
        assert_eq!(p.raw, PAGE_EXECUTE_READ.0 | 0x100);
        assert!(p.executable && p.readable && !p.writable);
    }

    #[test]
    fn state_and_type_unknown_values_are_none() {
        assert_eq!(memory_state(MEM_COMMIT.0), Some(MemoryState::Commit));
        assert_eq!(memory_state(MEM_RESERVE.0), Some(MemoryState::Reserve));
        assert_eq!(memory_state(MEM_FREE.0), Some(MemoryState::Free));
        assert_eq!(memory_state(0), None);
        assert_eq!(memory_state(0xDEAD), None);
        assert_eq!(memory_type(MEM_IMAGE.0), Some(MemoryType::Image));
        assert_eq!(memory_type(MEM_MAPPED.0), Some(MemoryType::Mapped));
        assert_eq!(memory_type(MEM_PRIVATE.0), Some(MemoryType::Private));
        assert_eq!(memory_type(0), None);
    }

    #[test]
    fn region_from_raw_free_has_no_type_or_allocation_protection() {
        let region = region_from_raw(&raw_region(MEM_FREE.0, 0, 0), None).unwrap();
        assert_eq!(region.state, MemoryState::Free);
        assert_eq!(region.region_type, None);
        assert_eq!(region.classification, RegionClass::Free);
        assert!(region.heuristics.is_empty());
        assert_eq!(region.allocation_protection, None);
    }

    #[test]
    fn region_from_raw_private_rwx_flags_heuristics() {
        let region = region_from_raw(
            &raw_region(MEM_COMMIT.0, PAGE_EXECUTE_READWRITE.0, MEM_PRIVATE.0),
            None,
        )
        .unwrap();
        assert_eq!(region.classification, RegionClass::Private);
        assert!(region.executable && region.writable);
        assert_eq!(region.heuristics.len(), 2);
    }

    #[test]
    fn region_from_raw_unknown_state_is_none() {
        assert!(region_from_raw(&raw_region(0, PAGE_READONLY.0, 0), None).is_none());
    }

    #[test]
    fn walk_regions_of_self_is_monotonic() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        assert!(!walk.regions.is_empty());
        assert!(!walk.truncated);
        assert!(walk.regions.iter().all(|r| r.size > 0));
        assert!(walk.regions.windows(2).all(|w| w[0].base < w[1].base));
    }

    #[test]
    fn walk_regions_honors_cap_and_reports_truncation() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), 3).unwrap();
        assert_eq!(walk.regions.len(), 3);
        assert!(walk.truncated);
    }

    #[test]
    fn mapped_file_name_of_self_image_region() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        let mut buf = vec![0u16; 32 * 1024];
        let name = walk
            .regions
            .iter()
            .filter(|r| is_file_backed(r))
            .find_map(|r| mapped_file_name(&handle, r.base, &mut buf))
            .expect("적어도 하나의 file-backed 영역은 이름이 해석되어야 함");
        assert!(!name.is_empty());
        assert!(!name.contains('\0'));
    }

    #[test]
    fn mapped_file_name_returns_none_for_non_mapped_address() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let mut buf = vec![0u16; 1024];
        assert!(mapped_file_name(&handle, 0, &mut buf).is_none());
    }

    #[test]
    fn mapped_file_name_small_buffer_does_not_panic() {
        let handle = crate::process::open_for_query(crate::process::current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        let mut big = vec![0u16; 32 * 1024];
        let base = walk
            .regions
            .iter()
            .filter(|r| is_file_backed(r))
            .find(|r| mapped_file_name(&handle, r.base, &mut big).is_some())
            .map(|r| r.base)
            .expect("해석 가능한 file-backed 영역 필요");
        let mut small = vec![0u16; 2];
        let name = mapped_file_name(&handle, base, &mut small);
        assert!(name.is_none_or(|n| n.chars().count() <= 2));
    }
}
