//! XmemError를 사람이 읽을 수 있는 문구로 변환한다.

use xmem_core::XmemError;

pub fn error_label(err: &XmemError) -> String {
    match err {
        XmemError::AccessDenied { context } => {
            format!("접근 거부 (AccessDenied): {context}")
        }
        XmemError::ProcessExited { pid } => {
            format!("프로세스가 종료되었습니다 (ProcessExited, PID {pid})")
        }
        XmemError::InvalidHandle { handle } => {
            format!("유효하지 않은 핸들 (InvalidHandle: {handle})")
        }
        XmemError::InvalidAddress { address } => {
            format!("유효하지 않은 주소 (InvalidAddress: {address:#x})")
        }
        XmemError::PartialRead {
            address,
            requested,
            read,
        } => format!("부분 읽기 (PartialRead: {address:#x}에서 {read}/{requested} 바이트)"),
        XmemError::UnsupportedArchitecture { detail } => {
            format!("지원하지 않는 아키텍처 (UnsupportedArchitecture): {detail}")
        }
        XmemError::InvalidPe { reason } => format!("PE 파싱 실패 (InvalidPe): {reason}"),
        XmemError::DumpError { reason } => format!("덤프 오류 (DumpError): {reason}"),
        XmemError::SnapshotError { reason } => format!("스냅샷 오류 (SnapshotError): {reason}"),
        XmemError::PolicyDenied { reason } => format!("정책 거부 (PolicyDenied): {reason}"),
        XmemError::Unimplemented { feature } => {
            format!("아직 구현되지 않은 기능 (Unimplemented): {feature}")
        }
        XmemError::InvalidInput { reason } => format!("잘못된 입력 (InvalidInput): {reason}"),
        XmemError::Cancelled { reason } => format!("취소됨 (Cancelled): {reason}"),
        XmemError::WindowsApi { api, code, message } => {
            format!("Windows API 오류 (WindowsApi): {api} code={code} {message}")
        }
        XmemError::JsonError { reason } => format!("JSON 오류 (JsonError): {reason}"),
        XmemError::Io(err) => format!("입출력 오류 (Io): {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_label_includes_context() {
        let err = XmemError::AccessDenied {
            context: "OpenProcess".into(),
        };
        let text = error_label(&err);
        assert!(text.contains("접근 거부"));
        assert!(text.contains("OpenProcess"));
    }

    #[test]
    fn invalid_address_label_is_hex() {
        let err = XmemError::InvalidAddress { address: 0x1234 };
        assert!(error_label(&err).contains("0x1234"));
    }

    #[test]
    fn windows_api_label_includes_api_and_code() {
        let err = XmemError::WindowsApi {
            api: "ReadProcessMemory",
            code: 299,
            message: "partial".into(),
        };
        let text = error_label(&err);
        assert!(text.contains("ReadProcessMemory"));
        assert!(text.contains("299"));
    }
}
