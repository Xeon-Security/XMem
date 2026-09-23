//! 중요 프로세스 보호 정책. 변경 작업(state-changing)에만 적용한다. read-only 분석은 허용.
use crate::model::ProcessInfo;

pub const PROTECTED_PROCESS_NAMES: &[&str] = &[
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String, matched: String },
}

/// 이름은 확장자 유무/대소문자를 정규화해 비교한다.
pub fn normalize_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    lower
        .strip_suffix(".exe")
        .map(str::to_string)
        .unwrap_or(lower)
}

pub fn is_protected_name(name: &str) -> bool {
    let norm = normalize_name(name);
    PROTECTED_PROCESS_NAMES
        .iter()
        .any(|p| normalize_name(p) == norm)
}

/// Guard 판단에 필요한 최소 신원 정보. 이름만 믿지 않도록 경로/세션을 함께 받는다.
#[derive(Debug, Clone, Copy)]
pub struct ProcessIdentity<'a> {
    pub pid: u32,
    pub name: Option<&'a str>,
    pub image_path: Option<&'a str>,
    pub session_id: Option<u32>,
}

impl ProcessIdentity<'_> {
    pub fn from_process_info(info: &ProcessInfo) -> ProcessIdentity<'_> {
        ProcessIdentity {
            pid: info.pid,
            name: Some(info.name.as_str()),
            image_path: info.image_path.as_deref(),
            session_id: info.session_id,
        }
    }
}

/// 변경 작업 허용 여부. 이름이 보호 목록과 일치하면 경로가 위장이어도 거부한다(보수적).
pub fn check_state_change(identity: &ProcessIdentity<'_>) -> PolicyDecision {
    let Some(name) = identity.name else {
        return PolicyDecision::Allow;
    };
    if !is_protected_name(name) {
        return PolicyDecision::Allow;
    }
    let path = identity.image_path.unwrap_or("<unknown>");
    let reason = format!(
        "protected process (name={name}, pid={}, path={path}, session={:?}); state-changing operations are refused",
        identity.pid, identity.session_id
    );
    PolicyDecision::Deny {
        reason,
        matched: normalize_name(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident<'a>(name: Option<&'a str>, path: Option<&'a str>) -> ProcessIdentity<'a> {
        ProcessIdentity {
            pid: 1234,
            name,
            image_path: path,
            session_id: Some(1),
        }
    }

    #[test]
    fn allows_normal_process() {
        assert_eq!(
            check_state_change(&ident(Some("notepad.exe"), None)),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn denies_critical_by_exact_name() {
        assert!(matches!(
            check_state_change(&ident(Some("lsass.exe"), None)),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn denies_name_variants_case_and_suffix() {
        assert!(matches!(
            check_state_change(&ident(Some("LSASS.EXE"), None)),
            PolicyDecision::Deny { .. }
        ));
        assert!(matches!(
            check_state_change(&ident(Some("lsass"), None)),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn denies_masqueraded_name_with_user_path_and_records_facts() {
        let decision = check_state_change(&ident(
            Some("lsass.exe"),
            Some("C:\\Users\\kalpha\\lsass.exe"),
        ));
        match decision {
            PolicyDecision::Deny { reason, matched } => {
                assert_eq!(matched, "lsass");
                assert!(reason.contains("C:\\Users\\kalpha\\lsass.exe"));
            }
            PolicyDecision::Allow => panic!("must deny"),
        }
    }

    #[test]
    fn allow_when_name_missing() {
        assert_eq!(
            check_state_change(&ident(None, None)),
            PolicyDecision::Allow
        );
    }
}
