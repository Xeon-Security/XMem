//! 모듈 탭 (PE 요약 포함).

use xmem_core::{MemorySource, ModuleInfo, ProcessArch};
use xmem_memory::LiveProcess;
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::views::map::{human_size, opt_hex};
use crate::views::overview::failure_banner;

pub struct ModuleBundle {
    pub modules: Vec<ModuleInfo>,
    pub pe: Option<Vec<Option<PeInfo>>>,
}

/// 모듈 탭 필터. CLI `modules`의 `module_matches`와 같은 의미를 GUI에 옮긴 것
/// (core에 ModuleFilter 타입이 없고 CLI/코어 수정이 금지되어 GUI에 둔다).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModuleFilter {
    pub query: String,
    pub arch: Option<ProcessArch>,
    pub unparsed_only: bool,
}

impl ModuleFilter {
    /// 이름/경로 부분일치(대소문자 무시), 아키텍처, PE 파싱 실패만.
    /// `pe`가 없으면(미수집) 파싱 실패로 간주한다 — CLI의 `--unparsed`와 동일.
    pub fn matches(&self, module: &ModuleInfo, pe: Option<&Option<PeInfo>>) -> bool {
        let needle = self.query.trim().to_lowercase();
        if !needle.is_empty() {
            let name_hit = module.name.to_lowercase().contains(&needle);
            let path_hit = module
                .path
                .as_deref()
                .is_some_and(|path| path.to_lowercase().contains(&needle));
            if !name_hit && !path_hit {
                return false;
            }
        }
        if let Some(arch) = self.arch
            && module.arch != Some(arch)
        {
            return false;
        }
        if self.unparsed_only && pe.is_some_and(|item| item.is_some()) {
            return false;
        }
        true
    }
}

/// 필터를 통과한 모듈 인덱스 목록.
pub fn select_modules(
    modules: &[ModuleInfo],
    pe: Option<&Vec<Option<PeInfo>>>,
    filter: &ModuleFilter,
) -> Vec<usize> {
    modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            let item = pe.and_then(|list| list.get(*index));
            filter.matches(module, item)
        })
        .map(|(index, _)| index)
        .collect()
}

fn filter_active(app: &crate::app::XMemApp) -> bool {
    !app.module_query.trim().is_empty()
        || app.module_arch_filter.is_some()
        || app.module_unparsed_only
}

fn arch_combo(ui: &mut egui::Ui, filter: &mut Option<ProcessArch>, id_salt: &str) {
    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(match filter {
            None => "아키텍처: 전체",
            Some(ProcessArch::X64) => "아키텍처: x64",
            Some(ProcessArch::X86) => "아키텍처: x86",
            Some(ProcessArch::Arm64) => "아키텍처: arm64",
            Some(ProcessArch::Unknown) => "아키텍처: 기타",
        })
        .show_ui(ui, |ui| {
            ui.selectable_value(filter, None, "전체");
            ui.selectable_value(filter, Some(ProcessArch::X64), "x64");
            ui.selectable_value(filter, Some(ProcessArch::X86), "x86");
        });
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
    arch_combo(ui, &mut app.module_arch_filter, "module_arch_filter_popup");
    ui.checkbox(&mut app.module_unparsed_only, "PE 파싱 실패만")
        .on_hover_text("PE 요약 수집이 필요합니다(자동으로 켜집니다)");
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
    match pe.arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
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
        if !crate::views::narrow(ui) {
            ui.separator();
            ui.add(
                egui::TextEdit::singleline(&mut app.module_query)
                    .hint_text("이름/경로")
                    .desired_width(120.0),
            );
            arch_combo(ui, &mut app.module_arch_filter, "module_arch_filter_inline");
            ui.checkbox(&mut app.module_unparsed_only, "PE 파싱 실패만");
        }
        crate::views::filter_popup(ui, "module_filter_popup", filter_active(app), |ui| {
            filter_contents(ui, app);
        });
    });
    // PE 파싱 실패 필터는 PE 수집이 없으면 평가할 수 없다 — 자동으로 켜고 다시 수집한다.
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
    let filter = ModuleFilter {
        query: app.module_query.clone(),
        arch: app.module_arch_filter,
        unparsed_only: app.module_unparsed_only,
    };
    let rows = select_modules(&bundle.modules, bundle.pe.as_ref(), &filter);
    ui.label(
        egui::RichText::new(if rows.len() == bundle.modules.len() {
            format!("{}개 모듈", rows.len())
        } else {
            format!("{}개 / 전체 {}개 모듈", rows.len(), bundle.modules.len())
        })
        .weak(),
    );
    let show_pe = bundle.pe.is_some();
    let selected_base = app.module_selected;
    let mut clicked_module: Option<ModuleInfo> = None;
    let mut moved_module: Option<ModuleInfo> = None;
    if let Some(next) = crate::views::arrow_step(
        ui.ctx(),
        rows.len(),
        selected_base.and_then(|base| bundle.modules.iter().position(|module| module.base == base)),
        &rows,
    ) && let Some(module) = bundle.modules.get(next)
    {
        moved_module = Some(module.clone());
    }
    crate::views::truncate_cells(ui);
    let min_w = if show_pe { 790.0 } else { 520.0 };
    crate::views::wrap_hscroll_if_wide(ui, "modules_table_hscroll", min_w, [false, false], |ui| {
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
                        row_clicked |= crate::views::table_cell(
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
    fn module_filter_matches_name_path_arch_and_unparsed() {
        let kernel = module("kernel32.dll", Some(r"C:\Windows\System32\kernel32.dll"));
        assert!(ModuleFilter::default().matches(&kernel, None));
        let by_name = ModuleFilter {
            query: "KERNEL".into(),
            ..ModuleFilter::default()
        };
        assert!(by_name.matches(&kernel, None));
        let by_path = ModuleFilter {
            query: "system32".into(),
            ..ModuleFilter::default()
        };
        assert!(by_path.matches(&kernel, None));
        assert!(
            !ModuleFilter {
                query: "user32".into(),
                ..ModuleFilter::default()
            }
            .matches(&kernel, None)
        );
        assert!(
            !ModuleFilter {
                arch: Some(ProcessArch::X86),
                ..ModuleFilter::default()
            }
            .matches(&kernel, None)
        );

        let parsed = Some(xmem_pe::PeInfo {
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
        });
        let unparsed = ModuleFilter {
            unparsed_only: true,
            ..ModuleFilter::default()
        };
        assert!(!unparsed.matches(&kernel, Some(&parsed)));
        let failed: Option<xmem_pe::PeInfo> = None;
        assert!(unparsed.matches(&kernel, Some(&failed)));
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
        let filter = ModuleFilter {
            query: "kernel".into(),
            arch: Some(ProcessArch::X64),
            ..ModuleFilter::default()
        };
        assert_eq!(select_modules(&modules, None, &filter), vec![0]);
        assert_eq!(
            select_modules(
                &modules,
                None,
                &ModuleFilter {
                    arch: Some(ProcessArch::X86),
                    ..ModuleFilter::default()
                }
            ),
            vec![1]
        );
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
}
