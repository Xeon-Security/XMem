//! 중요 프로세스 보호 정책. 변경 작업(state-changing)에만 적용한다. read-only 분석은 허용.

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
        let decision =
            check_state_change(&ident(Some("lsass.exe"), Some("C:\\Users\\kalpha\\lsass.exe")));
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
        assert_eq!(check_state_change(&ident(None, None)), PolicyDecision::Allow);
    }
}
