//! 원격 프로세스 메모리 조작 primitive (lab target 전용, xmem-experiments에서만 사용).
//!
//! 대상은 XMem이 직접 spawn한 lab target으로 한정한다. 임의 프로세스에 사용하지 않는다.

use std::ffi::c_void;

use windows::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_PROTECTION_FLAGS, VirtualAllocEx, VirtualFreeEx,
    VirtualProtectEx,
};
use xmem_core::Result;

use crate::error::{error_from_win32, last_win32_error};
use crate::handle::OwnedHandle;

/// 대상 프로세스에 커밋된 메모리를 할당하고 주소를 반환한다.
pub fn alloc_remote(handle: &OwnedHandle, size: usize, protection: u32) -> Result<u64> {
    let address = unsafe {
        VirtualAllocEx(
            handle.raw(),
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_PROTECTION_FLAGS(protection),
        )
    };
    if address.is_null() {
        return Err(last_win32_error("VirtualAllocEx"));
    }
    Ok(address as u64)
}

/// `alloc_remote`로 할당한 메모리를 해제한다(dwsize=0, MEM_RELEASE).
pub fn free_remote(handle: &OwnedHandle, address: u64) -> Result<()> {
    unsafe { VirtualFreeEx(handle.raw(), address as *mut c_void, 0, MEM_RELEASE) }
        .map_err(|e| error_from_win32("VirtualFreeEx", &e))
}

/// 대상 프로세스 메모리에 바이트를 쓴다. 실제로 쓰인 바이트 수를 반환한다.
pub fn write_remote(handle: &OwnedHandle, address: u64, bytes: &[u8]) -> Result<usize> {
    let mut written = 0usize;
    unsafe {
        WriteProcessMemory(
            handle.raw(),
            address as *const c_void,
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            Some(&mut written),
        )
    }
    .map_err(|e| error_from_win32("WriteProcessMemory", &e))?;
    Ok(written)
}

/// 대상 프로세스 메모리의 보호 속성을 변경하고 이전 속성(원시 값)을 반환한다.
pub fn protect_remote(
    handle: &OwnedHandle,
    address: u64,
    size: usize,
    new_protection: u32,
) -> Result<u32> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            handle.raw(),
            address as *const c_void,
            size,
            PAGE_PROTECTION_FLAGS(new_protection),
            &mut old,
        )
    }
    .map_err(|e| error_from_win32("VirtualProtectEx", &e))?;
    Ok(old.0)
}

/// 명령 캐시를 무효화한다(원격 메모리에 쓴 코드 반영).
pub fn flush_instruction_cache(handle: &OwnedHandle, address: u64, size: usize) -> Result<()> {
    unsafe { FlushInstructionCache(handle.raw(), Some(address as *const c_void), size) }
        .map_err(|e| error_from_win32("FlushInstructionCache", &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{current_pid, open_process};
    use crate::read::read_process_memory;
    use crate::selfmem::thread_id;
    use crate::threads::create_remote_thread;
    use windows::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    fn self_handle() -> OwnedHandle {
        open_process(
            current_pid(),
            PROCESS_CREATE_THREAD
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ
                | PROCESS_QUERY_LIMITED_INFORMATION,
        )
        .unwrap()
    }

    #[test]
    fn alloc_write_protect_and_free_remote_self() {
        let handle = self_handle();
        let address = alloc_remote(&handle, 4096, 0x04).unwrap();
        assert_ne!(address, 0);

        let written = write_remote(&handle, address, b"xmem-experiment").unwrap();
        assert_eq!(written, 15);

        let mut buf = [0u8; 15];
        read_process_memory(&handle, address, &mut buf).unwrap();
        assert_eq!(&buf, b"xmem-experiment");

        let old = protect_remote(&handle, address, 4096, 0x20).unwrap();
        assert_eq!(old & 0xff, 0x04);

        free_remote(&handle, address).unwrap();
    }

    #[test]
    fn write_remote_invalid_address_errors() {
        let handle = self_handle();
        assert!(write_remote(&handle, 1, b"x").is_err());
    }

    #[test]
    fn create_remote_thread_suspended_self_reports_tid() {
        let handle = self_handle();
        let address = alloc_remote(&handle, 4096, 0x20).unwrap();
        write_remote(&handle, address, &[0xC3]).unwrap();
        flush_instruction_cache(&handle, address, 1).unwrap();

        let thread = create_remote_thread(&handle, address, true).unwrap();
        let tid = thread_id(&thread);
        assert!(tid > 0);

        free_remote(&handle, address).unwrap();
    }

    #[test]
    fn flush_instruction_cache_self_ok() {
        let handle = self_handle();
        let address = alloc_remote(&handle, 4096, 0x04).unwrap();
        flush_instruction_cache(&handle, address, 4096).unwrap();
        free_remote(&handle, address).unwrap();
    }
}
