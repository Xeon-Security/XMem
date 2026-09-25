//! CLI/GUI가 공유하는 필터 값 타입과 매칭 로직.

use serde::{Deserialize, Serialize};

use crate::evidence::{Confidence, Finding, Severity};
use crate::guard::is_protected_name;
use crate::model::{
    Heuristic, MemoryRegion, MemoryState, ModuleInfo, ProcessArch, ProcessInfo, RegionClass,
    ThreadInfo,
};

/// Windows 보호 비트의 하위 8비트를 R/W/X 조합으로 디코딩한 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMask {
    Rwx,
    Rx,
    Rw,
    R,
    None,
}

impl ProtectionMask {
    /// GUARD/NOCACHE 등 상위 비트는 무시하고 하위 8비트만 해석한다.
    pub fn from_win32(raw: u32) -> Self {
        match raw & 0xff {
            0x40 | 0x80 => Self::Rwx,
            0x20 => Self::Rx,
            0x04 | 0x08 => Self::Rw,
            0x02 => Self::R,
            _ => Self::None,
        }
    }
}

/// 메모리 영역 필터. bool은 true일 때만 조건을 적용하며 모두 AND로 결합된다.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegionFilter {
    pub readable_only: bool,
    pub writable_only: bool,
    pub executable_only: bool,
    pub class: Option<RegionClass>,
    pub state: Option<MemoryState>,
    pub protection: Option<ProtectionMask>,
    pub heuristic: Option<Heuristic>,
    pub pe_like_only: bool,
    pub outside_modules_only: bool,
    pub mapped_only: bool,
    pub range: Option<(u64, u64)>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
}

impl RegionFilter {
    /// 모듈 범위·파일 백킹이 필요한 조건은 `modules`가 비면 매칭하지 않는다(침묵 원칙).
    pub fn matches(&self, region: &MemoryRegion, modules: &[ModuleInfo]) -> bool {
        if self.readable_only && !region.readable {
            return false;
        }
        if self.writable_only && !region.writable {
            return false;
        }
        if self.executable_only && !region.executable {
            return false;
        }
        if let Some(class) = self.class
            && region.classification != class
        {
            return false;
        }
        if let Some(state) = self.state
            && region.state != state
        {
            return false;
        }
        if let Some(mask) = self.protection
            && ProtectionMask::from_win32(region.protection.raw) != mask
        {
            return false;
        }
        if let Some(heuristic) = self.heuristic
            && !region.heuristics.contains(&heuristic)
        {
            return false;
        }
        if self.pe_like_only
            && !region
                .heuristics
                .contains(&Heuristic::PrivateExecutablePeLike)
        {
            return false;
        }
        if self.outside_modules_only {
            if modules.is_empty() {
                return false;
            }
            if modules.iter().any(|module| overlaps(module, region)) {
                return false;
            }
        }
        if self.mapped_only && region.mapped_file.is_none() {
            return false;
        }
        if let Some((start, end)) = self.range
            && !(region.base < end && region.base.saturating_add(region.size) > start)
        {
            return false;
        }
        if let Some(min) = self.min_size
            && region.size < min
        {
            return false;
        }
        if let Some(max) = self.max_size
            && region.size > max
        {
            return false;
        }
        true
    }
}

fn overlaps(module: &ModuleInfo, region: &MemoryRegion) -> bool {
    let module_end = module.base.saturating_add(module.size);
    let region_end = region.base.saturating_add(region.size);
    module.base < region_end && region.base < module_end
}

/// 프로세스 필터. 이름/사용자 검색은 대소문자를 구분하지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessFilter {
    pub accessible_only: bool,
    pub name_contains: Option<String>,
    pub arch: Option<ProcessArch>,
    pub session: Option<u32>,
    pub user_contains: Option<String>,
    pub protected_only: bool,
    pub parent_pid: Option<u32>,
}

impl ProcessFilter {
    pub fn matches(&self, process: &ProcessInfo, accessible: bool) -> bool {
        if self.accessible_only && !accessible {
            return false;
        }
        if let Some(needle) = &self.name_contains
            && !contains_ci(&process.name, needle)
        {
            return false;
        }
        if let Some(arch) = self.arch
            && process.arch != arch
        {
            return false;
        }
        if let Some(session) = self.session
            && process.session_id != Some(session)
        {
            return false;
        }
        if let Some(needle) = &self.user_contains {
            let Some(user) = process.user.as_deref() else {
                return false;
            };
            if !contains_ci(user, needle) {
                return false;
            }
        }
        if self.protected_only && !is_protected_name(&process.name) {
            return false;
        }
        if let Some(ppid) = self.parent_pid
            && process.ppid != Some(ppid)
        {
            return false;
        }
        true
    }
}

/// 스레드 필터.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreadFilter {
    pub with_start_only: bool,
    pub suspicious_only: bool,
    pub tid: Option<u32>,
}

impl ThreadFilter {
    pub fn matches(&self, thread: &ThreadInfo) -> bool {
        if self.with_start_only && thread.start_address.is_none() {
            return false;
        }
        if self.suspicious_only
            && !(thread.start_address.is_some() && thread.start_module.is_none())
        {
            return false;
        }
        if let Some(tid) = self.tid
            && thread.tid != tid
        {
            return false;
        }
        true
    }
}

/// 탐지 결과 필터. rule_id는 대소문자를 구분하지 않고 정확히 일치해야 한다.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FindingFilter {
    pub min_severity: Option<Severity>,
    pub min_confidence: Option<Confidence>,
    pub rule_id: Option<String>,
}

impl FindingFilter {
    pub fn matches(&self, finding: &Finding) -> bool {
        if let Some(min) = self.min_severity
            && severity_rank(finding.severity) < severity_rank(min)
        {
            return false;
        }
        if let Some(min) = self.min_confidence
            && confidence_rank(finding.confidence) < confidence_rank(min)
        {
            return false;
        }
        if let Some(rule) = &self.rule_id
            && !finding.rule_id.eq_ignore_ascii_case(rule)
        {
            return false;
        }
        true
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

/// Severity 순위: Info=0 … Critical=4.
pub fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Confidence 순위: Low=0, Medium=1, High=2.
pub fn confidence_rank(confidence: Confidence) -> u8 {
    match confidence {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

/// 터미널 표시 폭. CJK 전각 문자는 2칸, 그 외는 1칸.
pub fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn char_width(c: char) -> usize {
    const WIDE: [(u32, u32); 7] = [
        (0x1100, 0x115f),
        (0x2e80, 0xa4cf),
        (0xac00, 0xd7a3),
        (0xf900, 0xfaff),
        (0xfe30, 0xfe4f),
        (0xff00, 0xff60),
        (0xffe0, 0xffe6),
    ];
    let code = c as u32;
    if WIDE.iter().any(|(low, high)| code >= *low && code <= *high) {
        2
    } else {
        1
    }
}

/// 표시 폭 기준 좌측 정렬 패딩. 이미 넓이 이상이면 그대로 둔다.
pub fn pad_display(text: &str, width: usize) -> String {
    let current = display_width(text);
    let mut out = String::with_capacity(text.len() + width.saturating_sub(current));
    out.push_str(text);
    for _ in current..width {
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        FindingFilter, ProcessFilter, ProtectionMask, RegionFilter, ThreadFilter, confidence_rank,
        display_width, pad_display, severity_rank,
    };
    use crate::evidence::{Confidence, Evidence, Finding, Severity};
    use crate::model::RegionClass;
    use crate::model::{
        Heuristic, MemoryRegion, MemoryState, MemoryType, ModuleInfo, ProcessArch, ProcessInfo,
        Protection, ThreadInfo,
    };

    fn region(base: u64, size: u64, raw: u32, class: RegionClass) -> MemoryRegion {
        let protection = Protection::from_win32(raw);
        MemoryRegion {
            base,
            size,
            allocation_base: Some(base),
            state: MemoryState::Commit,
            protection,
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: protection.readable,
            writable: protection.writable,
            executable: protection.executable,
            classification: class,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    fn module(base: u64, size: u64) -> ModuleInfo {
        ModuleInfo {
            name: "mod.dll".to_string(),
            base,
            size,
            path: None,
            arch: Some(ProcessArch::X64),
        }
    }

    fn process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(4),
            name: name.to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: None,
            command_line: None,
            user: Some("DOMAIN\\User".to_string()),
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn thread(tid: u32, start: Option<u64>, module: Option<&str>) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1,
            priority: Some(8),
            start_address: start,
            start_region_base: start.map(|address| address & !0xfff),
            start_module: module.map(str::to_string),
        }
    }

    fn finding(rule: &str, severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            name: "n".to_string(),
            severity,
            confidence,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "h".to_string(),
            interpretation: "i".to_string(),
        }
    }

    #[test]
    fn default_region_filter_matches_everything() {
        let r = region(0x5000, 0x1000, 0x40, RegionClass::Image);
        assert!(RegionFilter::default().matches(&r, &[]));
    }

    #[test]
    fn region_access_flags_filter_on_region_properties() {
        let rwx = region(0x1000, 0x1000, 0x40, RegionClass::Private);
        let rx = region(0x2000, 0x1000, 0x20, RegionClass::Image);
        let rw = region(0x3000, 0x1000, 0x04, RegionClass::Mapped);
        let none = region(0x4000, 0x1000, 0x01, RegionClass::Reserved);
        let readable = RegionFilter {
            readable_only: true,
            ..Default::default()
        };
        assert!(
            readable.matches(&rwx, &[]) && readable.matches(&rx, &[]) && readable.matches(&rw, &[])
        );
        assert!(!readable.matches(&none, &[]));
        let writable = RegionFilter {
            writable_only: true,
            ..Default::default()
        };
        assert!(writable.matches(&rwx, &[]) && writable.matches(&rw, &[]));
        assert!(!writable.matches(&rx, &[]));
        let executable = RegionFilter {
            executable_only: true,
            ..Default::default()
        };
        assert!(executable.matches(&rwx, &[]) && executable.matches(&rx, &[]));
        assert!(!executable.matches(&rw, &[]));
    }

    #[test]
    fn region_class_and_state_filters() {
        let private = region(0x1000, 0x1000, 0x04, RegionClass::Private);
        let image = region(0x2000, 0x1000, 0x04, RegionClass::Image);
        let by_class = RegionFilter {
            class: Some(RegionClass::Private),
            ..Default::default()
        };
        assert!(by_class.matches(&private, &[]) && !by_class.matches(&image, &[]));
        let by_state = RegionFilter {
            state: Some(MemoryState::Reserve),
            ..Default::default()
        };
        assert!(!by_state.matches(&private, &[]));
        let mut reserved = private.clone();
        reserved.state = MemoryState::Reserve;
        assert!(by_state.matches(&reserved, &[]));
    }

    #[test]
    fn protection_mask_decodes_low_byte() {
        let cases = [
            (0x40, ProtectionMask::Rwx),
            (0x80, ProtectionMask::Rwx),
            (0x20, ProtectionMask::Rx),
            (0x04, ProtectionMask::Rw),
            (0x08, ProtectionMask::Rw),
            (0x02, ProtectionMask::R),
            (0x01, ProtectionMask::None),
            (0x00, ProtectionMask::None),
            (0x140, ProtectionMask::Rwx),
        ];
        for (raw, expected) in cases {
            assert_eq!(ProtectionMask::from_win32(raw), expected, "raw={raw:#x}");
        }
    }

    #[test]
    fn protection_filter_matches_decoded_mask() {
        let rx = region(0x1000, 0x1000, 0x20, RegionClass::Image);
        let filter = RegionFilter {
            protection: Some(ProtectionMask::Rx),
            ..Default::default()
        };
        assert!(filter.matches(&rx, &[]));
        assert!(
            !RegionFilter {
                protection: Some(ProtectionMask::Rw),
                ..Default::default()
            }
            .matches(&rx, &[])
        );
        let guarded = region(0x2000, 0x1000, 0x140, RegionClass::Image);
        assert!(
            RegionFilter {
                protection: Some(ProtectionMask::Rwx),
                ..Default::default()
            }
            .matches(&guarded, &[]),
            "GUARD 비트는 무시하고 하위 8비트만 본다"
        );
        let none = region(0x3000, 0x1000, 0x01, RegionClass::Reserved);
        assert!(
            RegionFilter {
                protection: Some(ProtectionMask::None),
                ..Default::default()
            }
            .matches(&none, &[])
        );
    }

    #[test]
    fn heuristic_filter_and_pe_like_require_tag() {
        let mut tagged = region(0x1000, 0x1000, 0x40, RegionClass::Private);
        tagged.heuristics = vec![
            Heuristic::ExecutablePrivate,
            Heuristic::PrivateExecutablePeLike,
        ];
        let plain = region(0x2000, 0x1000, 0x40, RegionClass::Private);
        let pe_like = RegionFilter {
            pe_like_only: true,
            ..Default::default()
        };
        assert!(pe_like.matches(&tagged, &[]) && !pe_like.matches(&plain, &[]));
        let exec_private = RegionFilter {
            heuristic: Some(Heuristic::ExecutablePrivate),
            ..Default::default()
        };
        assert!(exec_private.matches(&tagged, &[]) && !exec_private.matches(&plain, &[]));
        assert!(
            !RegionFilter {
                heuristic: Some(Heuristic::WritableExecutable),
                ..Default::default()
            }
            .matches(&tagged, &[])
        );
    }

    #[test]
    fn outside_modules_silent_when_module_list_empty() {
        let filter = RegionFilter {
            outside_modules_only: true,
            ..Default::default()
        };
        let r = region(0x1000, 0x1000, 0x04, RegionClass::Private);
        assert!(
            !filter.matches(&r, &[]),
            "모듈 목록이 비면 아무것도 매칭하지 않는다"
        );
    }

    #[test]
    fn outside_modules_requires_no_module_overlap() {
        let filter = RegionFilter {
            outside_modules_only: true,
            ..Default::default()
        };
        let inside = region(0x1000, 0x1000, 0x04, RegionClass::Private);
        let partial = region(0x1800, 0x1000, 0x04, RegionClass::Private);
        let outside = region(0x5000, 0x1000, 0x04, RegionClass::Private);
        let modules = [module(0x1000, 0x1000)];
        assert!(!filter.matches(&inside, &modules));
        assert!(
            !filter.matches(&partial, &modules),
            "부분 겹침도 모듈 내부로 본다"
        );
        assert!(filter.matches(&outside, &modules));
    }

    #[test]
    fn mapped_only_requires_mapped_file() {
        let mut mapped = region(0x1000, 0x1000, 0x20, RegionClass::Mapped);
        mapped.mapped_file = Some(r"\Device\HarddiskVolume3\data.bin".to_string());
        let unnamed = region(0x2000, 0x1000, 0x20, RegionClass::Mapped);
        let filter = RegionFilter {
            mapped_only: true,
            ..Default::default()
        };
        assert!(filter.matches(&mapped, &[]) && !filter.matches(&unnamed, &[]));
    }

    #[test]
    fn range_filter_uses_overlap_semantics() {
        let filter = |range| RegionFilter {
            range: Some(range),
            ..Default::default()
        };
        let r = region(0x1000, 0x1000, 0x04, RegionClass::Private);
        assert!(filter((0x1800, 0x2800)).matches(&r, &[]));
        assert!(
            !filter((0x2000, 0x3000)).matches(&r, &[]),
            "끝=시작은 불포함"
        );
        assert!(
            !filter((0x0, 0x1000)).matches(&r, &[]),
            "앞쪽 인접도 불포함"
        );
        assert!(filter((0x1000, 0x1001)).matches(&r, &[]));
    }

    #[test]
    fn range_overlap_saturates_at_address_space_end() {
        let filter = RegionFilter {
            range: Some((u64::MAX - 1, u64::MAX)),
            ..Default::default()
        };
        let r = region(u64::MAX - 0x1000, 0x1000, 0x04, RegionClass::Private);
        assert!(filter.matches(&r, &[]));
    }

    #[test]
    fn size_bounds_are_inclusive() {
        let r = region(0x1000, 0x1000, 0x04, RegionClass::Private);
        assert!(
            RegionFilter {
                min_size: Some(0x1000),
                max_size: Some(0x1000),
                ..Default::default()
            }
            .matches(&r, &[])
        );
        assert!(
            !RegionFilter {
                min_size: Some(0x1001),
                ..Default::default()
            }
            .matches(&r, &[])
        );
        assert!(
            !RegionFilter {
                max_size: Some(0xfff),
                ..Default::default()
            }
            .matches(&r, &[])
        );
    }

    #[test]
    fn combined_filters_are_conjunctive() {
        let filter = RegionFilter {
            readable_only: true,
            class: Some(RegionClass::Private),
            range: Some((0x1000, 0x2000)),
            ..Default::default()
        };
        let hit = region(0x1000, 0x1000, 0x04, RegionClass::Private);
        let wrong_class = region(0x1000, 0x1000, 0x04, RegionClass::Image);
        let out_of_range = region(0x3000, 0x1000, 0x04, RegionClass::Private);
        let not_readable = region(0x1000, 0x1000, 0x01, RegionClass::Private);
        assert!(filter.matches(&hit, &[]));
        assert!(!filter.matches(&wrong_class, &[]));
        assert!(!filter.matches(&out_of_range, &[]));
        assert!(!filter.matches(&not_readable, &[]));
    }

    #[test]
    fn process_filter_matches_fields() {
        let p = process(100, "Target.EXE");
        let filter = ProcessFilter {
            name_contains: Some("target".to_string()),
            arch: Some(ProcessArch::X64),
            session: Some(1),
            user_contains: Some("user".to_string()),
            ..Default::default()
        };
        assert!(filter.matches(&p, true));
        assert!(
            filter.matches(&p, false),
            "accessible_only가 아니면 접근성 무관"
        );
        assert!(
            ProcessFilter {
                accessible_only: true,
                ..Default::default()
            }
            .matches(&p, true)
        );
        assert!(
            !ProcessFilter {
                accessible_only: true,
                ..Default::default()
            }
            .matches(&p, false)
        );
        assert!(
            ProcessFilter {
                parent_pid: Some(4),
                ..Default::default()
            }
            .matches(&p, false)
        );
        assert!(
            !ProcessFilter {
                parent_pid: Some(5),
                ..Default::default()
            }
            .matches(&p, false)
        );
        assert!(
            !ProcessFilter {
                session: Some(2),
                ..Default::default()
            }
            .matches(&p, false)
        );
        assert!(
            !ProcessFilter {
                arch: Some(ProcessArch::X86),
                ..Default::default()
            }
            .matches(&p, false)
        );
        assert!(
            !ProcessFilter {
                name_contains: Some("other".to_string()),
                ..Default::default()
            }
            .matches(&p, false)
        );
        let mut no_user = p.clone();
        no_user.user = None;
        assert!(
            !ProcessFilter {
                user_contains: Some("user".to_string()),
                ..Default::default()
            }
            .matches(&no_user, false)
        );
    }

    #[test]
    fn process_filter_protected_uses_guard_names() {
        let filter = ProcessFilter {
            protected_only: true,
            ..Default::default()
        };
        assert!(filter.matches(&process(1, "lsass.exe"), false));
        assert!(!filter.matches(&process(2, "notepad.exe"), false));
    }

    #[test]
    fn thread_filter_matches_fields() {
        let with_start = ThreadFilter {
            with_start_only: true,
            ..Default::default()
        };
        assert!(with_start.matches(&thread(1, Some(0x1000), Some("mod.dll"))));
        assert!(!with_start.matches(&thread(2, None, None)));

        let suspicious = ThreadFilter {
            suspicious_only: true,
            ..Default::default()
        };
        assert!(suspicious.matches(&thread(3, Some(0x9000), None)));
        assert!(!suspicious.matches(&thread(4, Some(0x1000), Some("mod.dll"))));
        assert!(!suspicious.matches(&thread(5, None, None)));

        let by_tid = ThreadFilter {
            tid: Some(7),
            ..Default::default()
        };
        assert!(by_tid.matches(&thread(7, None, None)));
        assert!(!by_tid.matches(&thread(8, None, None)));
    }

    #[test]
    fn finding_filter_thresholds_and_rule() {
        let medium = finding("XMEM-003", Severity::Medium, Confidence::Low);
        let filter = FindingFilter {
            min_severity: Some(Severity::Medium),
            min_confidence: Some(Confidence::Low),
            rule_id: Some("xmem-003".to_string()),
        };
        assert!(filter.matches(&medium));
        assert!(
            !FindingFilter {
                min_severity: Some(Severity::High),
                ..Default::default()
            }
            .matches(&medium)
        );
        assert!(
            !FindingFilter {
                min_confidence: Some(Confidence::Medium),
                ..Default::default()
            }
            .matches(&medium)
        );
        assert!(
            !FindingFilter {
                rule_id: Some("XMEM-001".to_string()),
                ..Default::default()
            }
            .matches(&medium)
        );
        assert!(FindingFilter::default().matches(&medium));
    }

    #[test]
    fn severity_and_confidence_ranks_are_ordered() {
        let severities = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        assert_eq!(severities.map(severity_rank), [0, 1, 2, 3, 4]);
        let confidences = [Confidence::Low, Confidence::Medium, Confidence::High];
        assert_eq!(confidences.map(confidence_rank), [0, 1, 2]);
    }

    #[test]
    fn display_width_counts_wide_chars_as_two() {
        assert_eq!(display_width(""), 0);
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("가"), 2);
        assert_eq!(display_width("권한 필요"), 9);
        assert_eq!(display_width("한글abc"), 7);
    }

    #[test]
    fn pad_display_aligns_by_display_width() {
        assert_eq!(pad_display("abc", 3), "abc");
        assert_eq!(pad_display("abc", 2), "abc", "넓이를 넘기면 그대로 둔다");
        assert_eq!(pad_display("", 3), "   ");
        let padded = pad_display("권한 필요", 12);
        assert_eq!(display_width(&padded), 12);
        assert!(padded.starts_with("권한 필요"));
    }

    #[test]
    fn protection_mask_serde_uses_snake_case() {
        let json = serde_json::to_string(&ProtectionMask::Rwx).unwrap();
        assert_eq!(json, "\"rwx\"");
        let parsed: ProtectionMask = serde_json::from_str("\"none\"").unwrap();
        assert_eq!(parsed, ProtectionMask::None);
    }
}
