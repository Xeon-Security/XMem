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
    });
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
    ui.label(egui::RichText::new(format!("{}개 모듈", bundle.modules.len())).weak());
    let show_pe = bundle.pe.is_some();
    let selected_base = app.module_selected;
    let mut clicked_module: Option<ModuleInfo> = None;
    let mut moved_module: Option<ModuleInfo> = None;
    let rows: Vec<usize> = (0..bundle.modules.len()).collect();
    if let Some(next) = crate::views::arrow_step(
        ui.ctx(),
        bundle.modules.len(),
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
                body.rows(20.0, bundle.modules.len(), |mut row| {
                    let index = row.index();
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
