//! 모듈 탭 (PE 요약 포함).

use xmem_core::{MemorySource, ModuleFilter, ModuleInfo, ProcessArch};
use xmem_memory::{LiveProcess, UnloadedModule};
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::views::map::{human_size, opt_hex};
use crate::views::overview::failure_banner;

pub struct ModuleBundle {
    pub modules: Vec<ModuleInfo>,
    pub pe: Option<Vec<Option<PeInfo>>>,
    pub unloaded: Option<Vec<UnloadedModule>>,
}

/// 언로드 후보 섹션 라벨: 수집 여부와 후보 수를 한 줄로 요약한다.
pub fn unloaded_summary(unloaded: Option<&[UnloadedModule]>) -> String {
    match unloaded {
        None => "언로드 모듈 후보: 수집 안 함".to_string(),
        Some([]) => "언로드 모듈 후보: 후보 없음".to_string(),
        Some(list) => format!("언로드 모듈 후보: {}개", list.len()),
    }
}

/// app 상태에서 core `ModuleFilter`를 만든다. 공백뿐인 검색어는 조건 없음으로 본다.
pub fn build_module_filter(
    query: &str,
    arch: Option<ProcessArch>,
    unparsed_only: bool,
) -> ModuleFilter {
    let query = query.trim();
    ModuleFilter {
        name_contains: (!query.is_empty()).then(|| query.to_string()),
        arch,
        unparsed_only,
    }
}

/// 필터를 통과한 모듈 인덱스 목록. PE를 수집하지 않았으면 파싱 실패로 본다.
pub fn select_modules(
    modules: &[ModuleInfo],
    pe: Option<&Vec<Option<PeInfo>>>,
    filter: &ModuleFilter,
) -> Vec<usize> {
    modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            let pe_ok = pe
                .and_then(|list| list.get(*index))
                .is_some_and(|item| item.is_some());
            filter.matches(module, pe_ok)
        })
        .map(|(index, _)| index)
        .collect()
}

fn filter_count(app: &crate::app::XMemApp) -> usize {
    usize::from(!app.module_query.trim().is_empty())
        + usize::from(app.module_arch_filter.is_some())
        + usize::from(app.module_unparsed_only)
}

fn reset_filter(query: &mut String, arch: &mut Option<ProcessArch>, unparsed_only: &mut bool) {
    query.clear();
    *arch = None;
    *unparsed_only = false;
}

fn arch_label(filter: Option<ProcessArch>) -> &'static str {
    match filter {
        None => "아키텍처: 전체",
        Some(ProcessArch::X64) => "아키텍처: x64",
        Some(ProcessArch::X86) => "아키텍처: x86",
        Some(ProcessArch::Arm64) => "아키텍처: arm64",
        Some(ProcessArch::Unknown) => "아키텍처: 기타",
    }
}

fn arch_options() -> [(Option<ProcessArch>, &'static str); 4] {
    [
        (None, "전체"),
        (Some(ProcessArch::X64), "x64"),
        (Some(ProcessArch::X86), "x86"),
        (Some(ProcessArch::Arm64), "arm64"),
    ]
}

fn arch_menu(ui: &mut egui::Ui, filter: &mut Option<ProcessArch>) {
    crate::views::choice_menu(ui, arch_label(*filter), &arch_options(), filter);
}

fn filter_contents(ui: &mut egui::Ui, app: &mut crate::app::XMemApp) {
    ui.horizontal(|ui| {
        ui.label("이름/경로");
        ui.add(
            egui::TextEdit::singleline(&mut app.module_query)
                .hint_text("부분일치")
                .desired_width(140.0),
        );
    });
    arch_menu(ui, &mut app.module_arch_filter);
    ui.checkbox(&mut app.module_unparsed_only, "PE 파싱 실패만")
        .on_hover_text("PE 요약 수집이 필요합니다(자동으로 켜집니다)");
    crate::views::filter_reset_button(ui, || {
        reset_filter(
            &mut app.module_query,
            &mut app.module_arch_filter,
            &mut app.module_unparsed_only,
        );
    });
}

/// 모듈별 PE 헤더 prefix 파싱. 개별 실패는 None으로 degrade한다.
pub fn collect_pe(live: &LiveProcess, modules: &[ModuleInfo]) -> Vec<Option<PeInfo>> {
    let mut buf = vec![0u8; PE_HEADER_PREFIX];
    modules
        .iter()
        .map(|module| {
            let len = module.size.min(buf.len() as u64) as usize;
            if len < 64 {
                return None;
            }
            let outcome = live.read(module.base, &mut buf[..len]).ok()?;
            if outcome.bytes_read < 64 {
                return None;
            }
            parse_pe(&buf[..outcome.bytes_read]).ok()
        })
        .collect()
}

pub(crate) fn pe_arch(pe: &PeInfo) -> &'static str {
    arch_name(pe.arch)
}

pub(crate) fn arch_name(arch: ProcessArch) -> &'static str {
    match arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
    }
}

/// 언로드 후보 섹션. 수집하지 않았으면 아무것도 그리지 않는다.
fn unloaded_section(ui: &mut egui::Ui, unloaded: Option<&[UnloadedModule]>) {
    let Some(list) = unloaded else {
        return;
    };
    ui.separator();
    ui.label(egui::RichText::new(unloaded_summary(Some(list))).strong());
    for candidate in list.iter().take(200) {
        ui.label(format!(
            "{:#018x}  {:>10}  {}  entry {:#x}  sections {}  imports {}  timestamp {:#010x}",
            candidate.base,
            human_size(candidate.size),
            arch_name(candidate.arch),
            candidate.entry_point,
            candidate.sections,
            candidate.imports,
            candidate.timestamp,
        ));
    }
    if list.len() > 200 {
        ui.label(egui::RichText::new(format!("... {}개 더 있음", list.len() - 200)).weak());
    }
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.modules_task.is_running(),
                egui::Button::new("모듈 새로고침"),
            )
            .clicked()
        {
            app.start_modules(pid);
        }
        if app.modules_task.is_running() {
            ui.spinner();
            if ui.button("취소").clicked() {
                app.modules_task.cancel();
            }
        }
        let mut pe = app.modules_pe;
        if ui
            .add_enabled(
                !app.modules_task.is_running(),
                egui::Checkbox::new(&mut pe, "PE 요약"),
            )
            .changed()
        {
            app.modules_pe = pe;
            app.start_modules(pid);
        }
        let mut unloaded = app.modules_unloaded;
        if ui
            .add_enabled(
                !app.modules_task.is_running(),
                egui::Checkbox::new(&mut unloaded, "언로드 모듈 후보"),
            )
            .on_hover_text("모듈 범위 밖 PE-like private executable 영역")
            .changed()
        {
            app.modules_unloaded = unloaded;
            app.start_modules(pid);
        }
        if !crate::views::narrow(ui) {
            ui.separator();
            ui.add(
                egui::TextEdit::singleline(&mut app.module_query)
                    .hint_text("이름/경로")
                    .desired_width(120.0),
            );
            arch_menu(ui, &mut app.module_arch_filter);
            ui.checkbox(&mut app.module_unparsed_only, "PE 파싱 실패만");
        }
        crate::views::filter_popup(ui, "module_filter_popup", filter_count(app), |ui| {
            filter_contents(ui, app);
        });
    });
    // PE 파싱 실패 필터는 PE 수집이 없으면 평가할 수 없다 — 자동으로 켜고 다시 수집한다.
    // 진행 중 수집이 있으면 `start_modules`가 취소하고 새로 시작한다.
    if app.module_unparsed_only && !app.modules_pe {
        app.modules_pe = true;
        app.start_modules(pid);
    }
    match app.modules_task.state() {
        TaskState::Failed(err) => {
            let failure = crate::app::classify_open_failure(
                err,
                app.is_elevated,
                app.modules_task.pid().unwrap_or(pid),
            );
            failure_banner(ui, app, &failure, |app| app.start_modules(pid));
            return;
        }
        TaskState::Cancelled => {
            ui.label(egui::RichText::new("취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    if app.module_selected.is_some() {
        // 표가 최소 높이를 유지하도록 패널 최대 높이를 가용 공간에서 제한한다.
        let max_panel = (ui.available_height() - 160.0).max(140.0);
        egui::Panel::bottom(egui::Id::new("module_detail"))
            .resizable(true)
            .default_size(320.0)
            .size_range(140.0..=max_panel)
            .show(ui, |ui| crate::views::module::panel(ui, app));
    }
    let Some(bundle) = app.modules_bundle.as_ref() else {
        ui.label(egui::RichText::new("모듈을 불러오는 중...").weak());
        return;
    };
    let filter = build_module_filter(
        &app.module_query,
        app.module_arch_filter,
        app.module_unparsed_only,
    );
    let rows = select_modules(&bundle.modules, bundle.pe.as_ref(), &filter);
    ui.label(
        egui::RichText::new(if rows.len() == bundle.modules.len() {
            format!("{}개 모듈", rows.len())
        } else {
            format!("{}개 / 전체 {}개 모듈", rows.len(), bundle.modules.len())
        })
        .weak(),
    );
    if rows.is_empty() {
        ui.label(
            egui::RichText::new(
                "필터에 맞는 모듈이 없습니다 — 필터 팝업에서 조건을 바꾸거나 [필터 초기화]를 누르세요",
            )
            .color(crate::theme::palette(app.theme).muted),
        );
        unloaded_section(ui, bundle.unloaded.as_deref());
        return;
    }
    let show_pe = bundle.pe.is_some();
    let selected_base = app.module_selected;
    let mut clicked_module: Option<ModuleInfo> = None;
    let mut moved_module: Option<ModuleInfo> = None;
    let mut moved_row: Option<usize> = None;
    if let Some(next) = crate::views::arrow_step(
        ui.ctx(),
        rows.len(),
        selected_base.and_then(|base| bundle.modules.iter().position(|module| module.base == base)),
        &rows,
    ) {
        moved_row = rows.iter().position(|&index| index == next);
        if let Some(module) = bundle.modules.get(next) {
            moved_module = Some(module.clone());
        }
    }
    crate::views::truncate_cells(ui);
    let min_w = if show_pe { 790.0 } else { 520.0 };
    crate::views::wrap_hscroll(ui, "modules_table_hscroll", min_w, [false, false], |ui| {
        let mut builder = egui_extras::TableBuilder::new(ui)
            .min_scrolled_height(0.0)
            .striped(true)
            .sense(egui::Sense::click())
            .column(egui_extras::Column::exact(140.0))
            .column(egui_extras::Column::exact(80.0));
        if show_pe {
            builder = builder
                .column(egui_extras::Column::exact(70.0))
                .column(egui_extras::Column::exact(130.0))
                .column(egui_extras::Column::exact(70.0));
        }
        builder = builder
            .column(egui_extras::Column::initial(160.0).clip(true))
            .column(egui_extras::Column::remainder().clip(true));
        if let Some(row) = moved_row {
            builder = builder.scroll_to_row(row, None);
        }
        builder
            .header(18.0, |mut header| {
                for title in ["BASE", "SIZE"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
                if show_pe {
                    for title in ["MACHINE", "ENTRY", "SECTIONS"] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                }
                for title in ["NAME", "PATH"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let index = rows[row.index()];
                    let module = &bundle.modules[index];
                    row.set_selected(selected_base == Some(module.base));
                    let mut row_clicked = false;
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell_focusable(
                            ui,
                            egui::RichText::new(opt_hex(Some(module.base))),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(human_size(module.size)),
                        );
                    });
                    if let Some(pe_list) = bundle.pe.as_ref() {
                        match pe_list.get(index).and_then(Option::as_ref) {
                            Some(pe) => {
                                row.col(|ui| {
                                    row_clicked |= crate::views::table_cell(
                                        ui,
                                        egui::RichText::new(pe_arch(pe)),
                                    );
                                });
                                row.col(|ui| {
                                    row_clicked |= crate::views::table_cell(
                                        ui,
                                        egui::RichText::new(format!("{:#x}", pe.entry_point)),
                                    );
                                });
                                row.col(|ui| {
                                    row_clicked |= crate::views::table_cell(
                                        ui,
                                        egui::RichText::new(pe.sections.len().to_string()),
                                    );
                                });
                            }
                            None => {
                                for _ in 0..3 {
                                    row.col(|ui| {
                                        row_clicked |=
                                            crate::views::table_cell(ui, egui::RichText::new("-"));
                                    });
                                }
                            }
                        }
                    }
                    row.col(|ui| {
                        row_clicked |=
                            crate::views::table_cell(ui, egui::RichText::new(module.name.as_str()));
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(module.path.as_deref().unwrap_or("-")).weak(),
                        );
                    });
                    if row_clicked {
                        clicked_module = Some(module.clone());
                    }
                });
            });
    });
    if let Some(module) = clicked_module.or(moved_module) {
        app.select_module(pid, module);
    }
    unloaded_section(
        ui,
        app.modules_bundle
            .as_ref()
            .and_then(|bundle| bundle.unloaded.as_deref()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{ModuleInfo, ProcessArch};

    fn module(name: &str, path: Option<&str>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base: 0x1000,
            size: 0x1000,
            path: path.map(str::to_string),
            arch: Some(ProcessArch::X64),
        }
    }

    #[test]
    fn build_module_filter_trims_query_and_maps_fields() {
        assert_eq!(
            build_module_filter("   ", None, false),
            ModuleFilter::default(),
            "공백뿐인 검색어는 조건 없음"
        );
        assert_eq!(
            build_module_filter(" kernel ", Some(ProcessArch::X64), true),
            ModuleFilter {
                name_contains: Some("kernel".to_string()),
                arch: Some(ProcessArch::X64),
                unparsed_only: true,
            }
        );
    }

    #[test]
    fn select_modules_maps_filtered_rows() {
        let mut x86 = module("legacy.dll", None);
        x86.arch = Some(ProcessArch::X86);
        let modules = vec![
            module("kernel32.dll", Some(r"C:\Windows\System32\kernel32.dll")),
            x86,
            module("user32.dll", None),
        ];
        let filter = build_module_filter("kernel", Some(ProcessArch::X64), false);
        assert_eq!(select_modules(&modules, None, &filter), vec![0]);
        let x86_filter = build_module_filter("legacy", Some(ProcessArch::X86), false);
        assert_eq!(select_modules(&modules, None, &x86_filter), vec![1]);
    }

    #[test]
    fn select_modules_unparsed_only_uses_pe_success() {
        let modules = vec![module("kernel32.dll", None), module("other.dll", None)];
        let pe = vec![None, None];
        let filter = build_module_filter("", None, true);
        assert_eq!(select_modules(&modules, Some(&pe), &filter), vec![0, 1]);
        let pe = vec![Some(sample_pe()), None];
        assert_eq!(select_modules(&modules, Some(&pe), &filter), vec![1]);
    }

    fn sample_pe() -> xmem_pe::PeInfo {
        xmem_pe::PeInfo {
            is_64: true,
            machine: 0x8664,
            arch: ProcessArch::X64,
            image_base: 0x1000,
            entry_point: 0x1000,
            size_of_image: 0x1000,
            subsystem: 3,
            characteristics: 0,
            time_date_stamp: 0,
            sections: Vec::new(),
            import_count: 0,
            import_library_count: 0,
            libraries: Vec::new(),
            export_count: 0,
            relocation_count: 0,
            tls_callback_count: 0,
        }
    }

    #[test]
    fn pe_arch_labels_match_cli() {
        let pe = xmem_pe::PeInfo {
            is_64: true,
            machine: 0x8664,
            arch: ProcessArch::X64,
            image_base: 0x0001_4000_0000,
            entry_point: 0x0001_4000_1234,
            size_of_image: 0x2000,
            subsystem: 3,
            characteristics: 0x22,
            time_date_stamp: 0,
            sections: Vec::new(),
            import_count: 0,
            import_library_count: 0,
            libraries: Vec::new(),
            export_count: 0,
            relocation_count: 0,
            tls_callback_count: 0,
        };
        assert_eq!(pe_arch(&pe), "x64");
    }

    #[test]
    fn menu_labels_and_reset_cover_filter_fields() {
        for (value, label) in arch_options() {
            assert_eq!(arch_label(value).strip_prefix("아키텍처: "), Some(label));
        }
        let mut query = "kernel".to_string();
        let mut arch = Some(ProcessArch::X64);
        let mut unparsed = true;
        reset_filter(&mut query, &mut arch, &mut unparsed);
        assert!(query.is_empty() && arch.is_none() && !unparsed);
    }

    #[test]
    fn unloaded_summary_reports_collection_state() {
        assert_eq!(unloaded_summary(None), "언로드 모듈 후보: 수집 안 함");
        assert_eq!(unloaded_summary(Some(&[])), "언로드 모듈 후보: 후보 없음");
        let list = vec![xmem_memory::UnloadedModule {
            base: 0x1000,
            size: 0x1000,
            arch: ProcessArch::X64,
            entry_point: 0x1000,
            image_size: 0x2000,
            timestamp: 0,
            sections: 1,
            imports: 0,
        }];
        assert!(unloaded_summary(Some(&list)).contains('1'));
    }
}
