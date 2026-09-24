//! 자기 프로세스 메모리 조작(lab target 전용).

use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAlloc, VirtualFree,
    VirtualProtect,
};
use windows::Win32::System::Threading::{
    CreateThread, GetThreadId, LPTHREAD_START_ROUTINE, THREAD_CREATE_SUSPENDED,
};
use xmem_core::{Result, XmemError};

use crate::error::{error_from_win32, last_win32_error};
use crate::handle::OwnedHandle;

/// PAGE_READWRITE (자기 프로세스 할당용).
pub const SELF_PAGE_RW: u32 = 0x04;
/// PAGE_EXECUTE_READ.
pub const SELF_PAGE_RX: u32 = 0x20;
/// PAGE_EXECUTE_READWRITE.
pub const SELF_PAGE_RWX: u32 = 0x40;

/// 자기 프로세스의 커밋된 private 영역. Drop 시 VirtualFree(MEM_RELEASE).
pub struct PrivateRegion {
    base: *mut core::ffi::c_void,
    size: usize,
    protection: u32,
}

impl PrivateRegion {
    /// PAGE_READWRITE로 size 바이트를 커밋한다(최소 1 페이지).
    pub fn alloc(size: usize) -> Result<Self> {
        let size = size.max(4096);
        let base = unsafe {
            VirtualAlloc(
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_PROTECTION_FLAGS(SELF_PAGE_RW),
            )
        };
        if base.is_null() {
            return Err(last_win32_error("VirtualAlloc"));
        }
        Ok(Self {
            base,
            size,
            protection: SELF_PAGE_RW,
        })
    }

    pub fn base(&self) -> u64 {
        self.base as u64
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// 현재 보호 속성(raw PAGE_*).
    pub fn protection(&self) -> u32 {
        self.protection
    }

    /// 현재 보호 속성을 바꾸고 이전 값을 반환한다.
    pub fn protect(&mut self, new_protect: u32) -> Result<u32> {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        unsafe {
            VirtualProtect(
                self.base,
                self.size,
                PAGE_PROTECTION_FLAGS(new_protect),
                &mut old,
            )
        }
        .map_err(|e| error_from_win32("VirtualProtect", &e))?;
        self.protection = new_protect & 0xff;
        Ok(old.0)
    }

    /// 앞에서부터 복사한다. 현재 보호 속성이 쓰기 가능할 때만 허용한다.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.write_at(0, bytes)
    }

    /// offset 위치에 복사한다. 범위를 벗어나거나 쓰기 불가면 InvalidInput.
    pub fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        if !matches!(self.protection, 0x04 | 0x08 | 0x40 | 0x80) {
            return Err(XmemError::InvalidInput {
                reason: format!("region is not writable (protect {:#x})", self.protection),
            });
        }
        if offset.saturating_add(bytes.len()) > self.size {
            return Err(XmemError::InvalidInput {
                reason: format!(
                    "write out of range: offset {offset:#x} + len {:#x} > size {:#x}",
                    bytes.len(),
                    self.size
                ),
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.base.cast::<u8>().add(offset),
                bytes.len(),
            );
        }
        Ok(())
    }
}

impl Drop for PrivateRegion {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.base, 0, MEM_RELEASE);
        }
    }
}

/// RW로 할당하고 bytes를 쓰고 final_protect로 보호 속성을 바꾼다.
pub fn alloc_executable(bytes: &[u8], final_protect: u32) -> Result<PrivateRegion> {
    let mut region = PrivateRegion::alloc(bytes.len())?;
    region.write(bytes)?;
    region.protect(final_protect)?;
    Ok(region)
}

/// start_address에서 CREATE_SUSPENDED 스레드를 만든다(lab target 전용).
///
/// 호출자는 start_address가 유효한 실행 가능 메모리임을 보장해야 한다.
pub fn spawn_suspended_thread(start_address: u64) -> Result<OwnedHandle> {
    let start: LPTHREAD_START_ROUTINE = Some(unsafe {
        std::mem::transmute::<u64, unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>(
            start_address,
        )
    });
    let handle = unsafe { CreateThread(None, 0, start, None, THREAD_CREATE_SUSPENDED, None) }
        .map_err(|e| error_from_win32("CreateThread", &e))?;
    OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 })
}

/// 스레드 ID를 조회한다.
pub fn thread_id(handle: &OwnedHandle) -> u32 {
    unsafe { GetThreadId(handle.raw()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_write_and_drop() {
        let _guard = crate::test_support::process_lock();
        let mut region = PrivateRegion::alloc(4096).unwrap();
        assert_ne!(region.base(), 0);
        assert_eq!(region.size(), 4096);
        region.write(b"XMEM_SELFTEST").unwrap();
        assert_eq!(region.protection(), SELF_PAGE_RW);
    }

    #[test]
    fn protect_reports_old_and_gates_writes() {
        let _guard = crate::test_support::process_lock();
        let mut region = PrivateRegion::alloc(4096).unwrap();
        region.write(b"before").unwrap();
        let old = region.protect(SELF_PAGE_RX).unwrap();
        assert_eq!(old, SELF_PAGE_RW);
        assert_eq!(region.protection(), SELF_PAGE_RX);
        let err = region.write(b"after").unwrap_err();
        assert!(matches!(err, XmemError::InvalidInput { .. }));
    }

    #[test]
    fn alloc_executable_writes_and_protects() {
        let _guard = crate::test_support::process_lock();
        let region = alloc_executable(&[0xC3], SELF_PAGE_RX).unwrap();
        assert_ne!(region.base(), 0);
        assert_eq!(region.protection(), SELF_PAGE_RX);
    }

    #[test]
    fn spawn_suspended_thread_reports_id() {
        let _guard = crate::test_support::process_lock();
        let region = alloc_executable(&[0xC3], SELF_PAGE_RX).unwrap();
        let handle = spawn_suspended_thread(region.base()).unwrap();
        assert_ne!(thread_id(&handle), 0);
    }
}
