//! 출력 모드와 사용자 오류 표시. 로그(tracing)와 분리한다.
use xmem_core::{JSON_SCHEMA_VERSION, XmemError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Human,
    Json,
}

pub fn resolve_mode(json: bool) -> OutputMode {
    if json {
        OutputMode::Json
    } else {
        OutputMode::Human
    }
}

pub fn error_envelope(err: &XmemError) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "ok": false,
        "error": {
            "kind": error_kind(err),
            "message": err.to_string(),
        }
    })
}

pub fn success_envelope(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": JSON_SCHEMA_VERSION,
        "ok": true,
        "data": data,
    })
}

/// stdout에 쓴다. 소비자가 파이프를 먼저 닫아도 panic하지 않는다(EPIPE 무시).
pub fn emit(text: &str) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(text.as_bytes());
}

pub fn emit_json(value: &serde_json::Value) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => emit(&format!("{text}\n")),
        Err(e) => emit(&format!(
            "{{\"ok\":false,\"error\":{{\"kind\":\"json_error\",\"message\":\"{e}\"}}}}\n"
        )),
    }
}

fn error_kind(err: &XmemError) -> &'static str {
    match err {
        XmemError::AccessDenied { .. } => "access_denied",
        XmemError::ProcessExited { .. } => "process_exited",
        XmemError::InvalidHandle { .. } => "invalid_handle",
        XmemError::InvalidAddress { .. } => "invalid_address",
        XmemError::PartialRead { .. } => "partial_read",
        XmemError::UnsupportedArchitecture { .. } => "unsupported_architecture",
        XmemError::InvalidPe { .. } => "invalid_pe",
        XmemError::DumpError { .. } => "dump_error",
        XmemError::SnapshotError { .. } => "snapshot_error",
        XmemError::PolicyDenied { .. } => "policy_denied",
        XmemError::Unimplemented { .. } => "unimplemented",
        XmemError::InvalidInput { .. } => "invalid_input",
        XmemError::Cancelled { .. } => "cancelled",
        XmemError::WindowsApi { .. } => "windows_api",
        XmemError::JsonError { .. } => "json_error",
        XmemError::Io(_) => "io",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_mode_maps_to_json_output() {
        assert_eq!(resolve_mode(true), OutputMode::Json);
        assert_eq!(resolve_mode(false), OutputMode::Human);
    }

    #[test]
    fn error_envelope_has_kind_and_schema_version() {
        let err = XmemError::PolicyDenied {
            reason: "protected process".to_string(),
        };
        let value = error_envelope(&err);
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["kind"], "policy_denied");
        assert_eq!(value["schema_version"], JSON_SCHEMA_VERSION);
    }

    #[test]
    fn success_envelope_has_data_and_ok_true() {
        let v = success_envelope(serde_json::json!({"x": 1}));
        assert_eq!(v["ok"], true);
        assert_eq!(v["schema_version"], JSON_SCHEMA_VERSION);
        assert_eq!(v["data"]["x"], 1);
    }

    #[test]
    fn json_error_kind_is_mapped() {
        let err = XmemError::JsonError {
            reason: "boom".to_string(),
        };
        assert_eq!(error_envelope(&err)["error"]["kind"], "json_error");
    }
}
