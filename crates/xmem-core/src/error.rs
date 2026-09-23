//! Structured error model. 모든 실패는 원인과 context를 포함한다.
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum XmemError {
    #[error("access denied: {context}")]
    AccessDenied { context: String },

    #[error("process {pid} has exited")]
    ProcessExited { pid: u32 },

    #[error("invalid handle {handle:#x}")]
    InvalidHandle { handle: u64 },

    #[error("invalid address {address:#018x}")]
    InvalidAddress { address: u64 },

    #[error("partial read at {address:#018x}: requested {requested} bytes, read {read}")]
    PartialRead {
        address: u64,
        requested: usize,
        read: usize,
    },

    #[error("unsupported architecture: {detail}")]
    UnsupportedArchitecture { detail: String },

    #[error("invalid PE: {reason}")]
    InvalidPe { reason: String },

    #[error("dump error: {reason}")]
    DumpError { reason: String },

    #[error("snapshot error: {reason}")]
    SnapshotError { reason: String },

    #[error("policy denied: {reason}")]
    PolicyDenied { reason: String },

    #[error("not implemented yet: {feature}")]
    Unimplemented { feature: &'static str },

    #[error("windows api {api} failed (code {code}): {message}")]
    WindowsApi {
        api: &'static str,
        code: u32,
        message: String,
    },

    #[error("json serialization failed: {reason}")]
    JsonError { reason: String },

    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, XmemError>;

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

    #[test]
    fn json_error_display_contains_reason() {
        let err = XmemError::JsonError {
            reason: "unexpected token".to_string(),
        };
        assert!(err.to_string().contains("unexpected token"));
    }
}
