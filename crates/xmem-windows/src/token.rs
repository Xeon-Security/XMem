//! 프로세스 토큰 사용자 조회(read-only).

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Threading::OpenProcessToken;
use windows::core::PCWSTR;
use xmem_core::{Result, XmemError};

use crate::error::last_win32_error;
use crate::handle::OwnedHandle;

/// 프로세스 토큰의 사용자 SID를 "DOMAIN\\user" 형태로 돌려준다.
pub fn process_user(handle: &OwnedHandle) -> Result<String> {
    let mut token = HANDLE::default();
    // SAFETY: handle은 유효한 프로세스 핸들이고 token은 유효한 포인터다.
    unsafe { OpenProcessToken(handle.raw(), TOKEN_QUERY, &mut token) }
        .map_err(|_| last_win32_error("OpenProcessToken"))?;
    let token = OwnedHandle::new(token).ok_or(XmemError::InvalidHandle { handle: 0 })?;

    let mut len = 0u32;
    // 첫 호출은 ERROR_INSUFFICIENT_BUFFER로 실패하는 것이 정상 흐름이다.
    // SAFETY: null 버퍼 + 0 길이 질의는 표준 패턴이다.
    let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &mut len) };
    if len == 0 {
        return Err(last_win32_error("GetTokenInformation"));
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buf는 8바이트 정렬되어 있고 len 이상의 크기를 가진다.
    unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            len,
            &mut len,
        )
    }
    .map_err(|_| last_win32_error("GetTokenInformation"))?;
    // SAFETY: 성공 시 buf 선두에 TOKEN_USER가 기록되어 있다.
    let user: &TOKEN_USER = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };

    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut sid_type = SID_NAME_USE(0);
    // SAFETY: user.User.Sid는 위 호출이 채운 유효한 SID다. 길이 질의 호출이다.
    let _ = unsafe {
        LookupAccountSidW(
            None::<&PCWSTR>,
            user.User.Sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut sid_type,
        )
    };
    if name_len == 0 {
        return Err(last_win32_error("LookupAccountSidW"));
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: 두 버퍼는 질의한 길이만큼 확보되어 있다.
    unsafe {
        LookupAccountSidW(
            None::<&PCWSTR>,
            user.User.Sid,
            Some(windows::core::PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(windows::core::PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut sid_type,
        )
    }
    .map_err(|_| last_win32_error("LookupAccountSidW"))?;
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::{current_pid, open_for_query};

    #[test]
    fn user_of_self_is_nonempty() {
        let handle = open_for_query(current_pid()).unwrap();
        let user = process_user(&handle).expect("token user of self");
        assert!(!user.is_empty());
    }
}
