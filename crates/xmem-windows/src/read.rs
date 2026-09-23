use std::ffi::c_void;

use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_ADDRESS, ERROR_NOACCESS, ERROR_PARTIAL_COPY,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use xmem_core::{Result, XmemError};

use crate::error::win32_code_from_hresult;
use crate::handle::OwnedHandle;

/// ReadProcessMemory 단일 호출. 성공 시 실제 읽은 바이트 수.
/// `ERROR_PARTIAL_COPY`는 실패가 아니라 부분 읽기로 보고한다(XmemError::PartialRead).
pub fn read_process_memory(handle: &OwnedHandle, address: u64, buf: &mut [u8]) -> Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let requested = buf.len();
    let mut read: usize = 0;
    let result = unsafe {
        ReadProcessMemory(
            handle.raw(),
            address as *const c_void,
            buf.as_mut_ptr().cast(),
            requested,
            Some(&mut read),
        )
    };
    match result {
        Ok(()) => Ok(read.min(requested)),
        Err(e) => {
            let code = win32_code_from_hresult(e.code().0);
            if code == ERROR_PARTIAL_COPY.0 {
                Err(XmemError::PartialRead {
                    address,
                    requested,
                    read: read.min(requested),
                })
            } else if code == ERROR_ACCESS_DENIED.0 {
                Err(XmemError::AccessDenied {
                    context: format!("ReadProcessMemory at {address:#x}: {}", e.message()),
                })
            } else if code == ERROR_NOACCESS.0 || code == ERROR_INVALID_ADDRESS.0 {
                Err(XmemError::InvalidAddress { address })
            } else {
                Err(XmemError::WindowsApi {
                    api: "ReadProcessMemory",
                    code,
                    message: e.message(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{MAX_REGIONS, native_max_user_address, walk_regions};
    use crate::process::{current_pid, open_for_read};
    use windows::Win32::System::Memory::{MEM_COMMIT, MEM_FREE};

    #[test]
    fn read_own_stack_value() {
        let value: u64 = 0x1122_3344_5566_7788;
        let handle = open_for_read(current_pid()).unwrap();
        let mut buf = [0u8; 8];
        let n = read_process_memory(&handle, (&value as *const u64) as u64, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(u64::from_ne_bytes(buf), value);
    }

    #[test]
    fn empty_buffer_returns_zero() {
        let handle = open_for_read(current_pid()).unwrap();
        assert_eq!(read_process_memory(&handle, 0, &mut []).unwrap(), 0);
    }

    #[test]
    fn null_address_fails_structured() {
        let handle = open_for_read(current_pid()).unwrap();
        let mut buf = [0u8; 8];
        let err = read_process_memory(&handle, 0, &mut buf).unwrap_err();
        assert!(
            matches!(
                err,
                XmemError::InvalidAddress { .. } | XmemError::PartialRead { .. }
            ),
            "예상 밖 오류: {err:?}"
        );
    }

    #[test]
    fn crossing_into_free_region_is_partial_or_error() {
        let handle = open_for_read(current_pid()).unwrap();
        let walk = walk_regions(&handle, native_max_user_address(), MAX_REGIONS).unwrap();
        let boundary = walk.regions.windows(2).find_map(|w| {
            (w[0].state == MEM_COMMIT.0 && w[1].state == MEM_FREE.0)
                .then_some(w[0].base + w[0].size)
        });
        let Some(boundary) = boundary else {
            panic!("committed→free 경계를 찾지 못함");
        };
        let mut buf = [0u8; 8];
        match read_process_memory(&handle, boundary - 4, &mut buf) {
            Err(XmemError::PartialRead { read, .. }) => assert!(read <= 4),
            Err(XmemError::InvalidAddress { .. }) | Err(XmemError::WindowsApi { .. }) => {}
            Ok(n) => assert!(n <= 4),
            other => panic!("예상 밖 결과: {other:?}"),
        }
    }
}
