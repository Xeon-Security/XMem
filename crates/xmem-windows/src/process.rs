//! M1 최소 프로세스 primitive. 열거/메타데이터는 M2에서 확장한다.
use windows::Win32::Foundation::STILL_ACTIVE;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetExitCodeProcess, OpenProcess, PROCESS_ACCESS_RIGHTS,
};
use xmem_core::{Result, XmemError};

use crate::error::{error_from_win32, last_win32_error};
use crate::handle::OwnedHandle;

pub fn current_pid() -> u32 {
    // SAFETY: 인자 없는 쿼리 API이며 반환값은 항상 유효한 PID다.
    unsafe { GetCurrentProcessId() }
}

pub fn open_process(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<OwnedHandle> {
    // SAFETY: pid/access는 값 타입이고, 반환 핸들의 수명은 OwnedHandle이 관리한다.
    let handle = unsafe { OpenProcess(access, false, pid) };
    match handle {
        Ok(h) => OwnedHandle::new(h).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(e) => Err(error_from_win32("OpenProcess", &e)),
    }
}

pub fn is_alive(handle: &OwnedHandle) -> Result<bool> {
    let mut code = 0u32;
    // SAFETY: handle은 OwnedHandle이 보장하는 유효 핸들이고 code는 유효 포인터다.
    unsafe { GetExitCodeProcess(handle.raw(), &mut code) }
        .map_err(|_| last_win32_error("GetExitCodeProcess"))?;
    Ok(code == STILL_ACTIVE.0 as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

    #[test]
    fn current_pid_is_nonzero() {
        assert_ne!(current_pid(), 0);
    }

    #[test]
    fn open_own_process_and_check_alive() {
        let handle = open_process(current_pid(), PROCESS_QUERY_LIMITED_INFORMATION)
            .expect("own process must open");
        assert!(is_alive(&handle).expect("GetExitCodeProcess must succeed"));
    }

    #[test]
    fn open_bogus_pid_fails_structured() {
        let err = match open_process(0xFFFF_FFFE, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(_) => panic!("bogus pid must fail"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            xmem_core::XmemError::WindowsApi { .. } | xmem_core::XmemError::AccessDenied { .. }
        ));
    }
}
