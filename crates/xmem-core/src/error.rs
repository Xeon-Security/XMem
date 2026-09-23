//! Structured error model. 모든 실패는 원인과 context를 포함한다.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_denied_keeps_context() {
        let err = XmemError::AccessDenied {
            context: "OpenProcess(pid=4)".into(),
        };
        assert!(err.to_string().contains("OpenProcess(pid=4)"));
    }

    #[test]
    fn windows_api_error_shows_api_and_code() {
        let err = XmemError::WindowsApi {
            api: "VirtualQueryEx",
            code: 998,
            message: "invalid access to memory location".into(),
        };
        let text = err.to_string();
        assert!(text.contains("VirtualQueryEx"));
        assert!(text.contains("998"));
    }

    #[test]
    fn partial_read_reports_sizes() {
        let err = XmemError::PartialRead {
            address: 0x1_0000,
            requested: 4096,
            read: 512,
        };
        let text = err.to_string();
        assert!(text.contains("0x"));
        assert!(text.contains("4096"));
        assert!(text.contains("512"));
    }

    #[test]
    fn io_error_converts() {
        let err: XmemError = std::io::Error::new(std::io::ErrorKind::NotFound, "no file").into();
        assert!(matches!(err, XmemError::Io(_)));
    }
}
