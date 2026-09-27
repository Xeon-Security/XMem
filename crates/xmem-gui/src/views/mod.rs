//! 탭별 화면.
//!
//! 필터 텍스트 파서와 "필터" 팝업은 탭들이 공유한다. 좁은 창(<900px)에서도
//! 모든 필터에 접근할 수 있도록 각 탭 툴바에 팝업을 둔다.
pub mod detect;
pub mod dump;
pub mod export;
pub mod guide;
pub mod log;
pub mod map;
pub mod module;
pub mod modules;
pub mod overview;
pub mod process;
pub mod region;
pub mod report;
pub mod scan;
pub mod snapshot;
pub mod thread;
pub mod threads;

/// 좁은 창(뷰포트 폭 < 900px) 기준. 앱 셸과 같은 값을 쓴다.
pub const NARROW_WIDTH: f32 = 900.0;

/// 좁은 창 여부.
pub fn narrow(ui: &egui::Ui) -> bool {
    ui.ctx().input(|i| i.viewport_rect().width()) < NARROW_WIDTH
}

/// "0x"/"0X" 접두 hex 또는 10진 주소 파싱.
pub fn parse_addr_text(input: &str) -> Option<u64> {
    let text = input.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

/// 크기 텍스트 파싱. 빈 값은 미지정(None), k/m/g(선택 `i`) 접미사는 1024 배수.
pub fn parse_size_text(input: &str) -> Result<Option<u64>, String> {
    let text = input.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let lower = text.to_ascii_lowercase();
    let lower = lower.strip_suffix('i').unwrap_or(&lower);
    let (digits, mult) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1024u64),
        Some('m') => (&lower[..lower.len() - 1], 1024 * 1024),
        Some('g') => (&lower[..lower.len() - 1], 1024 * 1024 * 1024),
        _ => (lower, 1),
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("크기 파싱 실패: '{input}'"))?;
    value
        .checked_mul(mult)
        .map(Some)
        .ok_or_else(|| format!("크기가 너무 큼: '{input}'"))
}

/// START:END 범위 파싱. 둘 다 비면 미지정(None), 한쪽만 있으면 오류.
pub fn parse_range_text(start: &str, end: &str) -> Result<Option<(u64, u64)>, String> {
    let (start, end) = (start.trim(), end.trim());
    if start.is_empty() && end.is_empty() {
        return Ok(None);
    }
    let parse = |text: &str, label: &str| {
        parse_addr_text(text).ok_or_else(|| format!("{label} 주소 파싱 실패: '{text}'"))
    };
    let begin = parse(start, "시작")?;
    let finish = parse(end, "끝")?;
    if finish <= begin {
        return Err(format!("끝 주소는 시작보다 커야 합니다: '{start}:{end}'"));
    }
    Ok(Some((begin, finish)))
}

/// u32 텍스트 파싱. 빈 값은 미지정(None).
pub fn parse_u32_text(input: &str) -> Result<Option<u32>, String> {
    parse_opt_text(input, str::parse::<u32>)
}

/// u64 텍스트 파싱. 빈 값은 미지정(None).
pub fn parse_u64_text(input: &str) -> Result<Option<u64>, String> {
    parse_opt_text(input, str::parse::<u64>)
}

fn parse_opt_text<T>(
    input: &str,
    parse: impl Fn(&str) -> Result<T, std::num::ParseIntError>,
) -> Result<Option<T>, String> {
    let text = input.trim();
    if text.is_empty() {
        return Ok(None);
    }
    parse(text)
        .map(Some)
        .map_err(|_| format!("숫자 파싱 실패: '{input}'"))
}

/// 툴바의 "필터" 팝업 버튼. 좁은 창에서도 모든 필터에 접근할 수 있게 한다.
///
/// 기본 메뉴는 클릭 한 번에 닫히므로 `CloseOnClickOutside`로 두어 체크박스를
/// 여러 개 켜도 팝업이 유지된다.
pub fn filter_popup<R>(
    ui: &mut egui::Ui,
    id_salt: &str,
    active: bool,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::Response {
    let label = if active { "필터 ●" } else { "필터" };
    let button = ui.button(label);
    egui::Popup::menu(&button)
        .id(ui.id().with(id_salt).with("filter_popup"))
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .show(|ui| {
            ui.set_min_width(240.0);
            ui.label(egui::RichText::new("필터").strong());
            add_contents(ui);
        });
    button
}

/// 마우스로 크기를 조절할 수 있는 내용 영역(오른쪽 아래 모서리 드래그).
///
/// 내용은 전용 배경/테두리 상자(`content_frame`) 안에 들어가며, 크기 조절
/// 테두리는 Resize 기본 스트로크 대신 이 상자가 담당한다(내용 침범 방지).
pub fn resizable_pane<R>(
    ui: &mut egui::Ui,
    id_salt: &str,
    default_height: f32,
    min_height: f32,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Resize::default()
        .id_salt(id_salt)
        .default_height(default_height)
        .min_height(min_height)
        .resizable(true)
        .with_stroke(false)
        .show(ui, |ui| content_frame(ui, add_contents))
}

/// 내용 영역 전용 상자(배경 + 테두리 + 여백). 내용과 주변 UI를 구분한다.
pub fn content_frame<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let visuals = ui.visuals();
    let fill = visuals.extreme_bg_color;
    let stroke = visuals.widgets.noninteractive.bg_stroke;
    egui::Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(4.0)
        .inner_margin(8.0)
        .show(ui, add_contents)
        .inner
}

/// 표 셀에서 줄바꿈을 끈다(고정 행 높이에서 긴 값이 다음 행을 침범하지 않도록).
pub fn truncate_cells(ui: &mut egui::Ui) {
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
}

/// 표 행 높이(px). 셀 내용도 이 높이에 맞춘다.
pub const ROW_HEIGHT: f32 = 20.0;

/// 표 셀을 한 줄 고정 높이로 그린다. 셀 영역이 클릭되면 `true`를 돌려준다.
///
/// 셀 내용이 길어 줄바꿈되면 셀 min_rect가 행 높이를 넘겨 행 클릭 영역이 어긋난다.
/// 또한 egui_extras 셀 위젯은 포인터가 셀 안에 있어도 히트테스트에서 제외되어
/// hover/click이 잡히지 않으므로, 입력에서 직접 클릭을 판정한다.
pub fn table_cell(ui: &mut egui::Ui, text: egui::RichText) -> bool {
    // 가로 ScrollArea 안에서 표가 패널보다 넓어질 수 있으므로 보이는 영역만 클릭 밴드로 쓴다.
    // 이렇게 하지 않으면 좌측 목록 행의 밴드가 중앙 패널까지 걸쳐, 맵을 클릭했는데
    // 프로세스 선택이 바뀌는 문제가 생긴다.
    let band = ui.max_rect().intersect(ui.clip_rect());
    // 콤보박스 팝업 등 다른 레이어가 표 위에 떠 있으면 그 클릭은 행 클릭이 아니다.
    // 최상위 레이어(egui 0.36 `Context::layer_id_at`)가 이 위젯의 레이어일 때만 인정한다.
    let pos = ui.input(|i| i.pointer.latest_pos());
    let on_table_layer = pos
        .is_some_and(|pos| band.contains(pos) && ui.ctx().layer_id_at(pos) == Some(ui.layer_id()));
    let clicked = on_table_layer && ui.input(|i| i.pointer.primary_clicked());
    // 포커스 위젯은 추가적인 것이다. egui_extras 셀은 히트테스트가 불안정해
    // 마우스 클릭은 위 입력 판정을 그대로 신뢰하고, 이 위젯은 Enter 활성화만 담당한다.
    let resp = ui.interact(band, ui.id().with("cell_focus"), egui::Sense::click());
    let activated = resp.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if clicked || activated {
        resp.request_focus();
    }
    ui.add_sized(
        [ui.available_width(), ROW_HEIGHT],
        egui::Label::new(text).truncate(),
    );
    clicked || activated
}

/// `truncate_cells`로 바꾼 줄바꿈 모드를 기본값으로 되돌린다.
pub fn wrap_default(ui: &mut egui::Ui) {
    ui.style_mut().wrap_mode = None;
}

/// 내용 영역 크기 조절 안내 문구.
pub fn pane_hint(ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("↘ 오른쪽 아래 모서리를 끌어 크기를 조절할 수 있습니다")
            .weak()
            .small(),
    );
}

/// 표를 가로 스크롤로 감쌀지 판단한다. 가용 폭이 표 최소 폭 이상일 때만 감싼다.
pub fn should_hscroll(available: f32, min_w: f32) -> bool {
    available >= min_w
}

/// ↑/↓ 키로 표 선택 행을 한 칸 옮긴다.
///
/// `current`는 현재 선택의 데이터 인덱스, `filtered_indices`는 표시 행 → 데이터
/// 인덱스 매핑이다. 이동한 행의 데이터 인덱스를 돌려준다. 텍스트 입력 중이면
/// None(검색어 입력 등에서 커서 이동을 가로채지 않는다).
pub fn arrow_step(
    ctx: &egui::Context,
    len: usize,
    current: Option<usize>,
    filtered_indices: &[usize],
) -> Option<usize> {
    let len = len.min(filtered_indices.len());
    if len == 0 || ctx.text_edit_focused() {
        return None;
    }
    let up = ctx.input(|i| i.key_pressed(egui::Key::ArrowUp));
    let down = ctx.input(|i| i.key_pressed(egui::Key::ArrowDown));
    if up == down {
        return None;
    }
    let row = current.and_then(|index| filtered_indices.iter().position(|&i| i == index));
    let next = match (up, row) {
        (true, Some(row)) => row.saturating_sub(1),
        (false, Some(row)) => (row + 1).min(len - 1),
        (_, None) => 0,
    };
    filtered_indices.get(next).copied()
}

/// 가용 폭이 넉넉하면 표를 가로 ScrollArea에 담고, 좁으면 패널 폭에 맞춰 그린다.
///
/// 항상 가로 스크롤로 감싸면 좁은 창에서 표가 패널보다 넓어져 표 자신의 세로
/// 스크롤바가 보이는 영역 밖으로 밀려난다. 좁을 때는 감싸지 않아 세로
/// 스크롤바가 항상 보이게 한다(가로로는 열이 잘릴 수 있다).
pub fn wrap_hscroll_if_wide<R>(
    ui: &mut egui::Ui,
    id_salt: &str,
    min_w: f32,
    auto_shrink: [bool; 2],
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    if should_hscroll(ui.available_width(), min_w) {
        egui::ScrollArea::horizontal()
            .id_salt(id_salt)
            .auto_shrink(auto_shrink)
            .show(ui, |ui| {
                ui.set_min_width(min_w);
                add_contents(ui)
            })
            .inner
    } else {
        add_contents(ui)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_key(key: egui::Key) -> egui::Context {
        let ctx = egui::Context::default();
        ctx.input_mut(|input| {
            input.events.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::default(),
            });
        });
        ctx
    }

    #[test]
    fn should_hscroll_only_when_available_width_sufficient() {
        assert!(should_hscroll(910.0, 910.0));
        assert!(should_hscroll(1200.0, 910.0));
        assert!(!should_hscroll(909.9, 910.0));
        assert!(!should_hscroll(400.0, 910.0));
    }

    #[test]
    fn arrow_step_moves_between_filtered_rows() {
        let rows = [5usize, 3, 7];
        let none = egui::Context::default();
        assert_eq!(arrow_step(&none, rows.len(), None, &rows), None);
        assert_eq!(
            arrow_step(&ctx_with_key(egui::Key::ArrowDown), rows.len(), None, &rows),
            Some(5)
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowUp),
                rows.len(),
                Some(5),
                &rows
            ),
            Some(5)
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowDown),
                rows.len(),
                Some(5),
                &rows
            ),
            Some(3)
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowDown),
                rows.len(),
                Some(7),
                &rows
            ),
            Some(7)
        );
    }

    #[test]
    fn arrow_step_ignores_empty_rows_and_other_keys() {
        let rows = [1usize, 2];
        assert_eq!(
            arrow_step(&ctx_with_key(egui::Key::ArrowDown), 0, None, &[]),
            None
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowLeft),
                rows.len(),
                Some(1),
                &rows
            ),
            None
        );
    }

    #[test]
    fn parse_addr_text_accepts_hex_and_decimal() {
        assert_eq!(parse_addr_text("0x1000"), Some(0x1000));
        assert_eq!(parse_addr_text("0X20"), Some(0x20));
        assert_eq!(parse_addr_text("4096"), Some(4096));
        assert_eq!(parse_addr_text(""), None);
        assert_eq!(parse_addr_text("zz"), None);
    }

    #[test]
    fn parse_size_text_units_and_errors() {
        assert_eq!(parse_size_text(""), Ok(None));
        assert_eq!(parse_size_text("512"), Ok(Some(512)));
        assert_eq!(parse_size_text("4k"), Ok(Some(4096)));
        assert_eq!(parse_size_text("2M"), Ok(Some(2 * 1024 * 1024)));
        assert_eq!(parse_size_text("16Mi"), Ok(Some(16 * 1024 * 1024)));
        assert!(parse_size_text("abc").is_err());
    }

    #[test]
    fn parse_range_text_requires_both_ends_and_ascending() {
        assert_eq!(parse_range_text("", ""), Ok(None));
        assert_eq!(
            parse_range_text("0x1000", "0x2000"),
            Ok(Some((0x1000, 0x2000)))
        );
        assert!(parse_range_text("0x1000", "").is_err());
        assert!(parse_range_text("0x2000", "0x1000").is_err());
    }

    #[test]
    fn parse_u32_text_handles_empty_and_invalid() {
        assert_eq!(parse_u32_text(""), Ok(None));
        assert_eq!(parse_u32_text("42"), Ok(Some(42)));
        assert!(parse_u32_text("x").is_err());
    }
}

/// GUI 경로(컨트롤 → core 필터 → `matches()`)가 대표 fixture에서 내는 행 수.
/// 같은 fixture·조건을 쓰는 CLI 테스트(`xmem-cli` `commands::equivalence_tests`)와
/// 수치가 같아야 한다.
#[cfg(test)]
mod equivalence_tests {
    use std::collections::HashSet;

    use xmem_core::{
        Confidence, Evidence, Finding, FindingFilter, MemoryRegion, MemoryState, MemoryType,
        ModuleFilter, ModuleInfo, ProcessArch, ProcessFilter, ProcessInfo, Protection, RegionClass,
        RegionFilter, Severity, ThreadFilter, ThreadInfo,
    };

    use crate::views::detect::{DetectSort, select_and_sort_findings};
    use crate::views::map::{MapSort, select_and_sort};
    use crate::views::modules::{build_module_filter, select_modules};
    use crate::views::process::filter_processes_core;
    use crate::views::threads::select_threads;

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

    fn process(value: u32, name: &str, arch: ProcessArch, session: u32, ppid: u32) -> ProcessInfo {
        ProcessInfo {
            pid: value,
            ppid: Some(ppid),
            name: name.to_string(),
            image_path: Some(format!(r"C:\lab\{name}")),
            arch,
            session_id: Some(session),
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
            name: "fixture".to_string(),
            severity,
            confidence,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "fixture".to_string(),
            interpretation: "fixture".to_string(),
        }
    }

    fn module(name: &str, path: Option<&str>, arch: ProcessArch) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base: 0x1000,
            size: 0x1000,
            path: path.map(str::to_string),
            arch: Some(arch),
        }
    }

    #[test]
    fn filter_equivalence_counts_use_shared_core() {
        let regions = [
            region(0x1000, 0x1000, 0x40, RegionClass::Private),
            region(0x2000, 0x2000, 0x20, RegionClass::Image),
            region(0x1_0000, 0x1000, 0x04, RegionClass::Mapped),
            region(0x2_0000, 0x100, 0x02, RegionClass::Private),
            region(0x3_0000, 0x2000, 0x01, RegionClass::Reserved),
        ];
        let filter = RegionFilter {
            readable_only: true,
            executable_only: true,
            ..RegionFilter::default()
        };
        assert_eq!(
            select_and_sort(&regions, &filter, MapSort::AddressAsc, &[]).len(),
            2,
            "readable+executable"
        );

        let rows = vec![
            (process(1, "target.exe", ProcessArch::X64, 1, 4), true),
            (process(2, "svc.exe", ProcessArch::X64, 2, 4), false),
            (process(3, "legacy.exe", ProcessArch::X86, 1, 7), true),
        ];
        let accessible: HashSet<u32> = rows
            .iter()
            .filter(|(_, accessible)| *accessible)
            .map(|(info, _)| info.pid)
            .collect();
        let filter = ProcessFilter {
            accessible_only: true,
            arch: Some(ProcessArch::X64),
            parent_pid: Some(4),
            ..ProcessFilter::default()
        };
        let processes: Vec<ProcessInfo> = rows.into_iter().map(|(info, _)| info).collect();
        assert_eq!(
            filter_processes_core(&processes, "", &accessible, &filter).len(),
            1,
            "x64+ppid4+접근"
        );

        let threads = [
            thread(100, Some(0x1000), Some("mod.dll")),
            thread(200, Some(0x9000), None),
            thread(300, None, None),
        ];
        let filter = ThreadFilter {
            with_start_only: true,
            suspicious_only: true,
            ..ThreadFilter::default()
        };
        assert_eq!(select_threads(&threads, &filter).len(), 1, "의심 스레드");

        let findings = [
            finding("XMEM-001", Severity::High, Confidence::High),
            finding("XMEM-002", Severity::Medium, Confidence::Medium),
            finding("XMEM-003", Severity::Low, Confidence::Low),
        ];
        let filter = FindingFilter {
            min_severity: Some(Severity::Medium),
            ..FindingFilter::default()
        };
        assert_eq!(
            select_and_sort_findings(&findings, &filter, DetectSort::Rule).len(),
            2,
            "Medium 이상"
        );

        let modules = [
            module(
                "kernel32.dll",
                Some(r"C:\Windows\System32\kernel32.dll"),
                ProcessArch::X64,
            ),
            module("legacy.dll", None, ProcessArch::X86),
            module(
                "user32.dll",
                Some(r"C:\Windows\System32\user32.dll"),
                ProcessArch::X64,
            ),
        ];
        let filter: ModuleFilter = build_module_filter("dll", Some(ProcessArch::X64), false);
        assert_eq!(
            select_modules(&modules, None, &filter).len(),
            2,
            "x64 이름 일치"
        );
    }
}
