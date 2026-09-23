//! Win32 오류 → XmemError 매핑. 반환값 검증 없는 API 호출 금지.
use xmem_core::XmemError;

const FACILITY_WIN32_MASK: u32 = 0xFFFF_0000;
const HRESULT_WIN32_FACILITY: u32 = 0x8007_0000;

pub const ERROR_ACCESS_DENIED: u32 = 5;

/// HRESULT_FROM_WIN32(0x8007xxxx) 형태에서 원래 Win32 오류 코드를 복원한다.
pub fn win32_code_from_hresult(hresult: i32) -> u32 {
    let raw = hresult as u32;
    if (raw & FACILITY_WIN32_MASK) == HRESULT_WIN32_FACILITY {
        raw & 0xFFFF
    } else {
        raw
    }
}

pub fn map_win32(api: &'static str, code: u32, message: impl Into<String>) -> XmemError {
    let message = message.into();
    if code == ERROR_ACCESS_DENIED {
        return XmemError::AccessDenied {
            context: format!("{api}: {message}"),
        };
    }
    XmemError::WindowsApi { api, code, message }
}

/// windows-rs가 반환한 `Error`를 XmemError로 변환한다.
pub fn error_from_win32(api: &'static str, err: &windows::core::Error) -> XmemError {
    map_win32(api, win32_code_from_hresult(err.code().0), err.message())
}

/// GetLastError 기반 오류 생성. 실패한 API 호출 직후에만 사용한다.
pub fn last_win32_error(api: &'static str) -> XmemError {
    error_from_win32(api, &windows::core::Error::from_thread())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::XmemError;

    #[test]
    fn hresult_win32_facility_extracts_code() {
        assert_eq!(win32_code_from_hresult(0x8007_0005u32 as i32), 5);
        assert_eq!(win32_code_from_hresult(87), 87);
    }

    #[test]
    fn access_denied_maps_to_structured_error() {
        let err = map_win32("OpenProcess", 5, "Access is denied.");
        assert!(matches!(err, XmemError::AccessDenied { .. }));
        assert!(err.to_string().contains("Access is denied."));
    }

    #[test]
    fn other_codes_map_to_windows_api_error() {
        let err = map_win32("OpenProcess", 87, "The parameter is incorrect.");
        match err {
            XmemError::WindowsApi { api, code, .. } => {
                assert_eq!(api, "OpenProcess");
                assert_eq!(code, 87);
            }
            other => panic!("unexpected: {other}"),
        }
    }
}
