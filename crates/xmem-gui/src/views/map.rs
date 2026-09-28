//! 메모리맵 탭.

use xmem_core::{
    Heuristic, MemoryRegion, MemoryState, ModuleInfo, ProtectionMask, RegionClass, RegionFilter,
};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::export::{ExportFormat, ExportPayload};
use crate::views::overview::failure_banner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSort {
    AddressAsc,
    AddressDesc,
    SizeDesc,
}

pub fn heur_tag(h: Heuristic) -> &'static str {
    match h {
        Heuristic::ExecutablePrivate => "exec-private",
        Heuristic::ExecutableAnonymous => "exec-anon",
        Heuristic::PrivateExecutablePeLike => "pe-like",
        Heuristic::WritableExecutable => "wx",
    }
}

pub fn human_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value < KIB {
        format!("{bytes} B")
    } else if value < KIB * KIB {
        format!("{:.1} KiB", value / KIB)
    } else if value < KIB * KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else {
        format!("{:.1} GiB", value / (KIB * KIB * KIB))
    }
}

pub fn opt_hex(value: Option<u64>) -> String {
    value
        .map(|v| format!("{v:#018x}"))
        .unwrap_or_else(|| "-".into())
}

pub fn opt_num<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}

/// core `RegionFilter::matches`로 행을 고르고 기존 정렬을 적용한다.
pub fn select_and_sort(
    regions: &[MemoryRegion],
    filter: &RegionFilter,
    sort: MapSort,
    modules: &[ModuleInfo],
) -> Vec<usize> {
    let mut indices: Vec<usize> = regions
        .iter()
        .enumerate()
        .filter(|(_, region)| filter.matches(region, modules))
        .map(|(index, _)| index)
        .collect();
    match sort {
        MapSort::AddressAsc => indices.sort_by_key(|&i| regions[i].base),
        MapSort::AddressDesc => {
            indices.sort_by_key(|&i| std::cmp::Reverse(regions[i].base));
        }
        MapSort::SizeDesc => {
            indices.sort_by_key(|&i| (std::cmp::Reverse(regions[i].size), regions[i].base));
        }
    }
    indices
}

/// 팝업 버튼 활성 개수: 구조화 필터 항목 수 + 텍스트(범위/크기) 조건 수.
fn filter_count(
    filter: &RegionFilter,
    range_start: &str,
    range_end: &str,
    min_size: &str,
    max_size: &str,
) -> usize {
    let structured = [
        filter.readable_only,
        filter.writable_only,
        filter.executable_only,
        filter.class.is_some(),
        filter.state.is_some(),
        filter.protection.is_some(),
        filter.heuristic.is_some(),
        filter.pe_like_only,
        filter.outside_modules_only,
        filter.mapped_only,
    ]
    .into_iter()
    .filter(|set| *set)
    .count();
    let text = [range_start, range_end, min_size, max_size]
        .into_iter()
        .filter(|text| !text.trim().is_empty())
        .count();
    structured + text
}

/// [필터 초기화]: 구조화 필터와 텍스트 조건을 모두 기본값으로 되돌린다.
pub fn reset_region_filter(
    filter: &mut RegionFilter,
    range_start: &mut String,
    range_end: &mut String,
    min_size: &mut String,
    max_size: &mut String,
) {
    *filter = RegionFilter::default();
    range_start.clear();
    range_end.clear();
    min_size.clear();
    max_size.clear();
}

/// 텍스트 입력(주소 범위/최소·최대 크기)을 반영한 실제 적용 필터.
/// 잘못된 텍스트는 그 조건만 무시하고 오류 메시지를 함께 돌려준다.
pub fn build_region_filter(
    base: &RegionFilter,
    range_start: &str,
    range_end: &str,
    min_size: &str,
    max_size: &str,
) -> (RegionFilter, Vec<String>) {
    let mut filter = base.clone();
    let mut errors = Vec::new();
    match crate::views::parse_range_text(range_start, range_end) {
        Ok(range) => filter.range = range,
        Err(err) => {
            errors.push(err);
            filter.range = None;
        }
    }
    match crate::views::parse_size_text(min_size) {
        Ok(size) => filter.min_size = size,
        Err(err) => {
            errors.push(err);
            filter.min_size = None;
        }
    }
    match crate::views::parse_size_text(max_size) {
        Ok(size) => filter.max_size = size,
        Err(err) => {
            errors.push(err);
            filter.max_size = None;
        }
    }
    (filter, errors)
}

fn class_label(filter: Option<RegionClass>) -> &'static str {
    match filter {
        None => "분류: 전체",
        Some(RegionClass::Image) => "분류: Image",
        Some(RegionClass::Mapped) => "분류: Mapped",
        Some(RegionClass::Private) => "분류: Private",
        _ => "분류: 기타",
    }
}

fn state_label(filter: Option<MemoryState>) -> &'static str {
    match filter {
        None => "상태: 전체",
        Some(MemoryState::Commit) => "상태: Commit",
        Some(MemoryState::Reserve) => "상태: Reserve",
        Some(MemoryState::Free) => "상태: Free",
    }
}

/// 보호 속성 표기는 CLI `--prot ---`와 맞춘다.
fn protection_label(filter: Option<ProtectionMask>) -> &'static str {
    match filter {
        None => "보호: 전체",
        Some(ProtectionMask::Rwx) => "보호: RWX",
        Some(ProtectionMask::Rx) => "보호: RX",
        Some(ProtectionMask::Rw) => "보호: RW",
        Some(ProtectionMask::R) => "보호: R",
        Some(ProtectionMask::X) => "보호: X",
        Some(ProtectionMask::None) => "보호: --- (none)",
    }
}

fn heuristic_label(filter: Option<Heuristic>) -> &'static str {
    match filter {
        None => "휴리스틱: 전체",
        Some(Heuristic::ExecutablePrivate) => "휴리스틱: exec-private",
        Some(Heuristic::ExecutableAnonymous) => "휴리스틱: exec-anon",
        Some(Heuristic::PrivateExecutablePeLike) => "휴리스틱: pe-like",
        Some(Heuristic::WritableExecutable) => "휴리스틱: wx",
    }
}

fn class_options() -> [(Option<RegionClass>, &'static str); 4] {
    [
        (None, "전체"),
        (Some(RegionClass::Image), "Image"),
        (Some(RegionClass::Mapped), "Mapped"),
        (Some(RegionClass::Private), "Private"),
    ]
}

fn state_options() -> [(Option<MemoryState>, &'static str); 4] {
    [
        (None, "전체"),
        (Some(MemoryState::Commit), "Commit"),
        (Some(MemoryState::Reserve), "Reserve"),
        (Some(MemoryState::Free), "Free"),
    ]
}

fn protection_options() -> [(Option<ProtectionMask>, &'static str); 7] {
    [
        (None, "전체"),
        (Some(ProtectionMask::Rwx), "RWX"),
        (Some(ProtectionMask::Rx), "RX"),
        (Some(ProtectionMask::Rw), "RW"),
        (Some(ProtectionMask::R), "R"),
        (Some(ProtectionMask::X), "X"),
        (Some(ProtectionMask::None), "--- (none)"),
    ]
}

fn heuristic_options() -> [(Option<Heuristic>, &'static str); 5] {
    [
        (None, "전체"),
        (Some(Heuristic::ExecutablePrivate), "exec-private"),
        (Some(Heuristic::ExecutableAnonymous), "exec-anon"),
        (Some(Heuristic::PrivateExecutablePeLike), "pe-like"),
        (Some(Heuristic::WritableExecutable), "wx"),
    ]
}

fn sort_label(sort: MapSort) -> &'static str {
    match sort {
        MapSort::AddressAsc => "정렬: 주소 ↑",
        MapSort::AddressDesc => "정렬: 주소 ↓",
        MapSort::SizeDesc => "정렬: 크기 ↓",
    }
}

fn sort_options() -> [(MapSort, &'static str); 3] {
    [
        (MapSort::AddressAsc, "주소 ↑"),
        (MapSort::AddressDesc, "주소 ↓"),
        (MapSort::SizeDesc, "크기 ↓"),
    ]
}

fn class_menu(ui: &mut egui::Ui, filter: &mut RegionFilter) {
    crate::views::choice_menu(
        ui,
        class_label(filter.class),
        &class_options(),
        &mut filter.class,
    );
}

fn state_menu(ui: &mut egui::Ui, filter: &mut RegionFilter) {
    crate::views::choice_menu(
        ui,
        state_label(filter.state),
        &state_options(),
        &mut filter.state,
    );
}

fn protection_menu(ui: &mut egui::Ui, filter: &mut RegionFilter) {
    crate::views::choice_menu(
        ui,
        protection_label(filter.protection),
        &protection_options(),
        &mut filter.protection,
    );
}

fn heuristic_menu(ui: &mut egui::Ui, filter: &mut RegionFilter) {
    crate::views::choice_menu(
        ui,
        heuristic_label(filter.heuristic),
        &heuristic_options(),
        &mut filter.heuristic,
    );
}

fn sort_menu(ui: &mut egui::Ui, sort: &mut MapSort) {
    crate::views::choice_menu(ui, sort_label(*sort), &sort_options(), sort);
}

fn module_required_controls(ui: &mut egui::Ui, app: &mut XMemApp, pid: u32, has_modules: bool) {
    ui.checkbox(&mut app.map_filter.pe_like_only, "PE-like만");
    if has_modules {
        ui.checkbox(&mut app.map_filter.outside_modules_only, "모듈 범위 밖만");
        return;
    }
    let hint = "모듈 목록이 없어 이 조건은 매칭하지 않습니다 — 자동으로 불러오는 중이며, \
                실패하면 모듈 탭에서 다시 불러오세요";
    ui.add_enabled(
        false,
        egui::Checkbox::new(&mut app.map_filter.outside_modules_only, "모듈 범위 밖만"),
    )
    .on_disabled_hover_text(hint);
    if ui.small_button("모듈 불러오기").clicked() {
        app.start_modules(pid);
        ui.close();
    }
}

fn filter_contents(ui: &mut egui::Ui, app: &mut XMemApp, pid: u32, has_modules: bool) {
    ui.checkbox(&mut app.map_filter.readable_only, "읽기 가능만");
    ui.checkbox(&mut app.map_filter.writable_only, "쓰기 가능만");
    ui.checkbox(&mut app.map_filter.executable_only, "실행 가능만");
    class_menu(ui, &mut app.map_filter);
    state_menu(ui, &mut app.map_filter);
    protection_menu(ui, &mut app.map_filter);
    heuristic_menu(ui, &mut app.map_filter);
    module_required_controls(ui, app, pid, has_modules);
    ui.checkbox(&mut app.map_filter.mapped_only, "파일 백킹 관찰")
        .on_hover_text("CLI --mapped-only와 동일: mapped_file이 관찰된 영역만");
    ui.horizontal(|ui| {
        ui.label("주소 범위");
        ui.add(
            egui::TextEdit::singleline(&mut app.map_range_start)
                .hint_text("시작")
                .desired_width(80.0),
        );
        ui.label("~");
        ui.add(
            egui::TextEdit::singleline(&mut app.map_range_end)
                .hint_text("끝")
                .desired_width(80.0),
        );
    });
    ui.horizontal(|ui| {
        ui.label("최소 크기");
        ui.add(
            egui::TextEdit::singleline(&mut app.map_min_size)
                .hint_text("4Ki")
                .desired_width(60.0),
        );
        ui.label("최대");
        ui.add(
            egui::TextEdit::singleline(&mut app.map_max_size)
                .hint_text("8Mi")
                .desired_width(60.0),
        );
    });
    ui.separator();
    ui.label(egui::RichText::new("정렬").weak());
    sort_menu(ui, &mut app.map_sort);
    let (filter, range_start, range_end, min_size, max_size) = (
        &mut app.map_filter,
        &mut app.map_range_start,
        &mut app.map_range_end,
        &mut app.map_min_size,
        &mut app.map_max_size,
    );
    crate::views::filter_reset_button(ui, || {
        reset_region_filter(filter, range_start, range_end, min_size, max_size);
    });
}

/// 모듈 목록이 필요한 필터의 상태. 조용히 해제하는 대신 자동 재수집/안내한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleFilterStatus {
    Ready,
    NeedsCollect,
    Collecting,
    Failed,
}

pub fn module_filter_status(
    filter_on: bool,
    has_modules: bool,
    collecting: bool,
    failed: bool,
) -> ModuleFilterStatus {
    if !filter_on || has_modules {
        return ModuleFilterStatus::Ready;
    }
    if collecting {
        ModuleFilterStatus::Collecting
    } else if failed {
        ModuleFilterStatus::Failed
    } else {
        ModuleFilterStatus::NeedsCollect
    }
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    let has_modules = app.modules_bundle.is_some();
    let (effective, errors) = build_region_filter(
        &app.map_filter,
        &app.map_range_start,
        &app.map_range_end,
        &app.map_min_size,
        &app.map_max_size,
    );
    ui.horizontal(|ui| {
        if ui
            .add_enabled(!app.map_task.is_running(), egui::Button::new("맵 새로고침"))
            .clicked()
        {
            app.start_map(pid);
        }
        if app.map_task.is_running() {
            ui.spinner();
            ui.label("메모리 영역 열거 중...");
            if ui.button("취소").clicked() {
                app.map_task.cancel();
            }
        }
        ui.separator();
        if !crate::views::narrow(ui) {
            ui.checkbox(&mut app.map_filter.readable_only, "읽기 가능만");
            ui.checkbox(&mut app.map_filter.writable_only, "쓰기 가능만");
            ui.checkbox(&mut app.map_filter.executable_only, "실행 가능만");
            class_menu(ui, &mut app.map_filter);
            ui.separator();
            sort_menu(ui, &mut app.map_sort);
        }
        let active = filter_count(
            &app.map_filter,
            &app.map_range_start,
            &app.map_range_end,
            &app.map_min_size,
            &app.map_max_size,
        );
        crate::views::filter_popup(ui, "map_filter_popup", active, |ui| {
            filter_contents(ui, app, pid, has_modules);
        });
    });
    match module_filter_status(
        app.map_filter.outside_modules_only,
        has_modules,
        app.modules_task.is_running(),
        matches!(app.modules_task.state(), TaskState::Failed(_)),
    ) {
        ModuleFilterStatus::NeedsCollect => {
            app.start_modules(pid);
            ui.label(
                egui::RichText::new("모듈 범위 밖 필터에 필요한 모듈 목록을 불러오는 중...").weak(),
            );
        }
        ModuleFilterStatus::Collecting => {
            ui.label(
                egui::RichText::new("모듈 범위 밖 필터에 필요한 모듈 목록을 불러오는 중...").weak(),
            );
        }
        ModuleFilterStatus::Failed => {
            ui.colored_label(
                palette(app.theme).warn,
                "모듈 범위 밖 필터를 평가할 수 없습니다 — 모듈 탭에서 모듈을 다시 불러오세요",
            );
        }
        ModuleFilterStatus::Ready => {}
    }
    for err in &errors {
        ui.colored_label(palette(app.theme).danger, err);
    }
    match app.map_task.state() {
        TaskState::Failed(err) => {
            let failure = crate::app::classify_open_failure(
                err,
                app.is_elevated,
                app.map_task.pid().unwrap_or(pid),
            );
            failure_banner(ui, app, &failure, |app| app.start_map(pid));
            return;
        }
        TaskState::Cancelled => {
            ui.label(egui::RichText::new("취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    if app.map.is_none() {
        ui.label(egui::RichText::new("맵을 불러오는 중...").weak());
        return;
    }
    if app.map_selected.is_some() {
        // 표가 최소 높이를 유지하도록 패널 최대 높이를 가용 공간에서 제한한다.
        // (패널이 가용 공간을 모두 차지하면 표 헤더/행이 패널 위로 겹쳐 그려진다)
        let max_panel = (ui.available_height() - 160.0).max(140.0);
        egui::Panel::bottom(egui::Id::new("region_detail"))
            .resizable(true)
            .default_size(320.0)
            .size_range(140.0..=max_panel)
            .show(ui, |ui| crate::views::region::panel(ui, app));
    }
    let Some(map) = app.map.as_ref() else {
        return;
    };
    if map.truncated {
        ui.label(
            egui::RichText::new("영역 수 상한(1,048,576)에 도달해 일부만 표시됩니다")
                .color(palette(app.theme).warn),
        );
    }
    let modules: &[ModuleInfo] = app
        .modules_bundle
        .as_ref()
        .map(|bundle| bundle.modules.as_slice())
        .unwrap_or(&[]);
    let selected = select_and_sort(&map.regions, &effective, app.map_sort, modules);
    let mut export: Option<ExportFormat> = None;
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("{}개 영역 표시", selected.len())).weak());
        if ui.button("JSON 내보내기").clicked() {
            export = Some(ExportFormat::Json);
        }
        if ui.button("CSV 내보내기").clicked() {
            export = Some(ExportFormat::Csv);
        }
    });
    if selected.is_empty() {
        let message = if map.regions.is_empty() {
            "메모리 영역이 없습니다"
        } else {
            "필터에 맞는 영역이 없습니다 — 필터 팝업에서 조건을 바꾸거나 [필터 초기화]를 누르세요"
        };
        ui.label(egui::RichText::new(message).color(palette(app.theme).muted));
        crate::views::export_error(ui, app, crate::app::Tab::Map);
        return;
    }
    let colors = palette(app.theme);
    let selected_base = app.map_selected;
    let mut clicked_region: Option<MemoryRegion> = None;
    let mut moved_region: Option<MemoryRegion> = None;
    let mut moved_row: Option<usize> = None;
    if let Some(next) = crate::views::arrow_step(
        ui.ctx(),
        selected.len(),
        selected_base.and_then(|base| map.regions.iter().position(|region| region.base == base)),
        &selected,
    ) {
        moved_row = selected.iter().position(|&index| index == next);
        if let Some(region) = map.regions.get(next) {
            moved_region = Some(region.clone());
        }
    }
    crate::views::truncate_cells(ui);
    crate::views::wrap_hscroll(ui, "map_table_hscroll", 910.0, [false, false], |ui| {
        let mut builder = egui_extras::TableBuilder::new(ui)
            .min_scrolled_height(0.0)
            .striped(true)
            .drag_to_scroll(egui::scroll_area::DragScroll::Never)
            .sense(egui::Sense::click())
            .column(egui_extras::Column::exact(140.0))
            .column(egui_extras::Column::exact(80.0))
            .column(egui_extras::Column::exact(90.0))
            .column(egui_extras::Column::exact(90.0))
            .column(egui_extras::Column::exact(120.0))
            .column(egui_extras::Column::exact(90.0))
            .column(egui_extras::Column::remainder().clip(true));
        if let Some(row) = moved_row {
            builder = builder.scroll_to_row(row, None);
        }
        builder
            .header(18.0, |mut header| {
                for title in [
                    "BASE",
                    "SIZE",
                    "STATE",
                    "TYPE",
                    "PROTECTION",
                    "CLASS",
                    "HEURISTICS / FILE",
                ] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, selected.len(), |mut row| {
                    let index = row.index();
                    let region = &map.regions[selected[index]];
                    row.set_selected(selected_base == Some(region.base));
                    let mut row_clicked = false;
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell_focusable(
                            ui,
                            egui::RichText::new(opt_hex(Some(region.base))),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(human_size(region.size)),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(format!("{:?}", region.state).to_uppercase()),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(
                                region
                                    .region_type
                                    .map(|t| format!("{t:?}").to_uppercase())
                                    .unwrap_or_else(|| "-".into()),
                            ),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(region.protection.to_string()),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(
                                format!("{:?}", region.classification).to_lowercase(),
                            ),
                        );
                    });
                    row.col(|ui| {
                        let mut text = region
                            .heuristics
                            .iter()
                            .map(|h| heur_tag(*h))
                            .collect::<Vec<_>>()
                            .join(",");
                        if let Some(file) = &region.mapped_file {
                            if !text.is_empty() {
                                text.push(' ');
                            }
                            text.push_str(file);
                        }
                        if text.is_empty() {
                            text = "-".into();
                        }
                        let color = if region.heuristics.is_empty() {
                            colors.muted
                        } else {
                            colors.warn
                        };
                        row_clicked |=
                            crate::views::table_cell(ui, egui::RichText::new(text).color(color));
                    });
                    if row_clicked {
                        clicked_region = Some(region.clone());
                    }
                });
            });
    });
    if let Some(format) = export {
        app.export_error = None;
        let payload = ExportPayload::Map(map.regions.as_slice());
        match crate::views::export::save_with_dialog(
            pid,
            "map",
            format,
            &payload,
            app.config.last_output_dir.clone(),
            &mut app.log,
        ) {
            Ok(Some(dir)) => app.config.last_output_dir = Some(dir),
            Ok(None) => {}
            Err(err) => {
                app.export_error = Some((
                    crate::app::Tab::Map,
                    format!("내보내기 실패: {}", crate::error::error_label(&err)),
                ));
            }
        }
    }
    crate::views::export_error(ui, app, crate::app::Tab::Map);
    if let Some(region) = clicked_region.or(moved_region) {
        app.select_region(pid, region);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        MemoryState, MemoryType, ModuleInfo, ProcessArch, Protection, ProtectionMask, RegionFilter,
    };

    fn region(base: u64, size: u64, class: RegionClass, exec: bool) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            allocation_base: Some(base),
            state: MemoryState::Commit,
            protection: Protection::new(if exec { 0x20 } else { 0x04 }, true, !exec, exec),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: !exec,
            executable: exec,
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

    #[test]
    fn heur_tags_are_short() {
        assert_eq!(heur_tag(Heuristic::ExecutablePrivate), "exec-private");
        assert_eq!(heur_tag(Heuristic::ExecutableAnonymous), "exec-anon");
        assert_eq!(heur_tag(Heuristic::PrivateExecutablePeLike), "pe-like");
        assert_eq!(heur_tag(Heuristic::WritableExecutable), "wx");
    }

    #[test]
    fn human_size_scales_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn select_and_sort_filters_and_orders() {
        let regions = vec![
            region(0x3000, 0x1000, RegionClass::Private, false),
            region(0x1000, 0x4000, RegionClass::Image, true),
            region(0x2000, 0x2000, RegionClass::Private, true),
        ];
        let all = RegionFilter::default();
        assert_eq!(
            select_and_sort(&regions, &all, MapSort::AddressAsc, &[]),
            vec![1, 2, 0]
        );
        assert_eq!(
            select_and_sort(&regions, &all, MapSort::AddressDesc, &[]),
            vec![0, 2, 1]
        );
        assert_eq!(
            select_and_sort(&regions, &all, MapSort::SizeDesc, &[]),
            vec![1, 2, 0]
        );
        let exec_only = RegionFilter {
            executable_only: true,
            ..RegionFilter::default()
        };
        assert_eq!(
            select_and_sort(&regions, &exec_only, MapSort::AddressAsc, &[]),
            vec![1, 2]
        );
    }

    #[test]
    fn select_and_sort_uses_core_filter_fields() {
        let mut pe_like = region(0x1000, 0x1000, RegionClass::Private, true);
        pe_like.heuristics = vec![Heuristic::PrivateExecutablePeLike];
        let mut mapped = region(0x2000, 0x8000, RegionClass::Mapped, false);
        mapped.mapped_file = Some(r"\Device\HarddiskVolume3\data.bin".into());
        let reserved = MemoryRegion {
            state: MemoryState::Reserve,
            protection: Protection::new(0x01, false, false, false),
            readable: false,
            writable: false,
            executable: false,
            ..region(0x4000, 0x1000, RegionClass::Reserved, false)
        };
        let regions = vec![pe_like, mapped, reserved];
        let filter = RegionFilter {
            writable_only: true,
            class: Some(RegionClass::Mapped),
            protection: Some(ProtectionMask::Rw),
            mapped_only: true,
            range: Some((0x1000, 0x3000)),
            min_size: Some(0x1000),
            max_size: Some(0x10000),
            ..RegionFilter::default()
        };
        assert_eq!(
            select_and_sort(&regions, &filter, MapSort::AddressAsc, &[]),
            vec![1],
            "분류/보호/백킹/범위/크기 조건이 모두 AND"
        );
        let by_state = RegionFilter {
            state: Some(MemoryState::Reserve),
            ..RegionFilter::default()
        };
        assert_eq!(
            select_and_sort(&regions, &by_state, MapSort::AddressAsc, &[]),
            vec![2]
        );
        let pe_only = RegionFilter {
            pe_like_only: true,
            ..RegionFilter::default()
        };
        assert_eq!(
            select_and_sort(&regions, &pe_only, MapSort::AddressAsc, &[]),
            vec![0]
        );
    }

    #[test]
    fn outside_modules_requires_modules_and_excludes_overlap() {
        let inside = region(0x1000, 0x1000, RegionClass::Private, false);
        let outside = region(0x5000, 0x1000, RegionClass::Private, false);
        let regions = vec![inside, outside];
        let filter = RegionFilter {
            outside_modules_only: true,
            ..RegionFilter::default()
        };
        assert!(
            select_and_sort(&regions, &filter, MapSort::AddressAsc, &[]).is_empty(),
            "모듈 목록이 비면 아무것도 매칭하지 않는다"
        );
        let modules = [module(0x1000, 0x1000)];
        assert_eq!(
            select_and_sort(&regions, &filter, MapSort::AddressAsc, &modules),
            vec![1]
        );
    }

    #[test]
    fn module_filter_status_never_silently_resets() {
        assert_eq!(
            module_filter_status(false, false, false, false),
            ModuleFilterStatus::Ready
        );
        assert_eq!(
            module_filter_status(true, true, false, false),
            ModuleFilterStatus::Ready
        );
        assert_eq!(
            module_filter_status(true, false, false, false),
            ModuleFilterStatus::NeedsCollect,
            "모듈이 없으면 조용히 끄지 않고 자동 재수집"
        );
        assert_eq!(
            module_filter_status(true, false, true, false),
            ModuleFilterStatus::Collecting
        );
        assert_eq!(
            module_filter_status(true, false, false, true),
            ModuleFilterStatus::Failed,
            "수집 실패는 안내"
        );
    }

    #[test]
    fn filter_count_counts_structured_and_text_conditions() {
        let base = RegionFilter::default();
        assert_eq!(filter_count(&base, "", "", "", ""), 0);
        assert_eq!(filter_count(&base, "0x1000", "", "", ""), 1);
        assert_eq!(filter_count(&base, "", "0x2000", "4Ki", "8Mi"), 3);
        assert_eq!(
            filter_count(&base, "  ", " ", " ", "  "),
            0,
            "공백만이면 비활성"
        );
        let structured = RegionFilter {
            readable_only: true,
            mapped_only: true,
            ..RegionFilter::default()
        };
        assert_eq!(filter_count(&structured, "", "", "", ""), 2);
    }

    #[test]
    fn reset_region_filter_clears_defaults_and_texts() {
        let mut filter = RegionFilter {
            readable_only: true,
            outside_modules_only: true,
            ..RegionFilter::default()
        };
        let mut start = "0x1000".to_string();
        let mut end = "0x2000".to_string();
        let mut min = "4Ki".to_string();
        let mut max = "8Mi".to_string();
        reset_region_filter(&mut filter, &mut start, &mut end, &mut min, &mut max);
        assert_eq!(filter, RegionFilter::default());
        assert!(start.is_empty() && end.is_empty() && min.is_empty() && max.is_empty());
    }

    #[test]
    fn menu_option_labels_cover_selected_texts() {
        for (value, label) in protection_options() {
            assert_eq!(protection_label(value), format!("보호: {label}"));
        }
        assert_eq!(
            protection_label(Some(ProtectionMask::None)),
            "보호: --- (none)",
            "CLI --prot ---와 표기 통일"
        );
        for (value, label) in class_options() {
            assert_eq!(
                class_label(value).strip_prefix("분류: "),
                Some(label),
                "선택 문구와 옵션 라벨이 일치"
            );
        }
        for (value, label) in state_options() {
            assert_eq!(state_label(value).strip_prefix("상태: "), Some(label));
        }
        for (value, label) in heuristic_options() {
            assert_eq!(
                heuristic_label(value).strip_prefix("휴리스틱: "),
                Some(label)
            );
        }
        for (value, label) in sort_options() {
            assert_eq!(sort_label(value).strip_prefix("정렬: "), Some(label));
        }
    }
}
