//! 관리자 권한 판별과 UAC 상승 재시작(runas). GUI의 "관리자로 재시작" 전용.

use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::HSTRING;
use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;

/// 현재 프로세스 토큰의 상승 여부를 반환한다.
pub fn is_elevated() -> Result<bool> {
    unsafe {
        let mut raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)
            .map_err(|e| error_from_win32("OpenProcessToken", &e))?;
        let token = OwnedHandle::new(raw).ok_or(XmemError::InvalidHandle { handle: 0 })?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .map_err(|e| error_from_win32("GetTokenInformation", &e))?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

/// "runas" 동사로 file을 실행한다(파라미터 포함). UAC 취소/실패 시 Err.
/// ShellExecuteW는 32 이하 반환값이 실패 코드다.
pub fn runas(file: &str, parameters: &str) -> Result<()> {
    let verb = HSTRING::from("runas");
    let file_w = HSTRING::from(file);
    let params_w = HSTRING::from(parameters);
    let result = unsafe { ShellExecuteW(None, &verb, &file_w, &params_w, None, SW_SHOWNORMAL) };
    let code = result.0 as isize;
    if code <= 32 {
        Err(XmemError::WindowsApi {
            api: "ShellExecuteW",
            code: code as u32,
            message: format!("runas 실패 (code {code})"),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_elevated_returns_bool() {
        let elevated = is_elevated().unwrap();
        let _ = elevated;
    }

    #[test]
    fn runas_rejects_missing_file() {
        let result = runas("C:\\xmem-no-such-file-9f8e7d.exe", "");
        assert!(result.is_err(), "없는 파일에 대한 runas는 실패해야 한다");
    }
}
