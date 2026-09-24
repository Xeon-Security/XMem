//! 스레드 탭.

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::views::map::{opt_hex, opt_num};
use crate::views::overview::failure_banner;

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.threads_task.is_running(),
                egui::Button::new("스레드 새로고침"),
            )
            .clicked()
        {
            app.start_threads(pid);
        }
        if app.threads_task.is_running() {
            ui.spinner();
        }
    });
    match app.threads_task.state() {
        TaskState::Failed(err) => {
            let failure = crate::app::classify_open_failure(err, app.is_elevated, pid);
            failure_banner(ui, app, &failure);
            return;
        }
        TaskState::Cancelled => {
            ui.label(egui::RichText::new("취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    if app.thread_selected.is_some() {
        // 표가 최소 높이를 유지하도록 패널 최대 높이를 가용 공간에서 제한한다.
        let max_panel = (ui.available_height() - 160.0).max(140.0);
        egui::Panel::bottom(egui::Id::new("thread_detail"))
            .resizable(true)
            .default_size(320.0)
            .size_range(140.0..=max_panel)
            .show(ui, |ui| crate::views::thread::panel(ui, app));
    }
    let Some(threads) = app.threads.as_ref() else {
        ui.label(egui::RichText::new("스레드를 불러오는 중...").weak());
        return;
    };
    ui.label(egui::RichText::new(format!("{}개 스레드", threads.len())).weak());
    let selected_tid = app.thread_selected;
    let mut clicked_thread: Option<xmem_core::ThreadInfo> = None;
    crate::views::truncate_cells(ui);
    egui_extras::TableBuilder::new(ui)
        .min_scrolled_height(0.0)
        .striped(true)
        .sense(egui::Sense::click())
        .column(egui_extras::Column::exact(70.0))
        .column(egui_extras::Column::exact(80.0))
        .column(egui_extras::Column::exact(150.0))
        .column(egui_extras::Column::exact(150.0))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            for title in ["TID", "PRIORITY", "START ADDRESS", "REGION", "MODULE"] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, threads.len(), |mut row| {
                let thread = &threads[row.index()];
                row.set_selected(selected_tid == Some(thread.tid));
                let mut row_clicked = false;
                row.col(|ui| {
                    row_clicked |=
                        crate::views::table_cell(ui, egui::RichText::new(thread.tid.to_string()));
                });
                row.col(|ui| {
                    row_clicked |=
                        crate::views::table_cell(ui, egui::RichText::new(opt_num(thread.priority)));
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(opt_hex(thread.start_address)),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(opt_hex(thread.start_region_base)),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(thread.start_module.as_deref().unwrap_or("-")),
                    );
                });
                if row_clicked {
                    clicked_thread = Some(thread.clone());
                }
            });
        });
    if let Some(thread) = clicked_thread {
        app.select_thread(pid, thread);
    }
}
