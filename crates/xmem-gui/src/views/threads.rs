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
        if ui.button("스레드 새로고침").clicked() {
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
    let Some(threads) = app.threads.as_ref() else {
        ui.label(egui::RichText::new("스레드를 불러오는 중...").weak());
        return;
    };
    ui.label(egui::RichText::new(format!("{}개 스레드", threads.len())).weak());
    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
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
                row.col(|ui| {
                    ui.label(thread.tid.to_string());
                });
                row.col(|ui| {
                    ui.label(opt_num(thread.priority));
                });
                row.col(|ui| {
                    ui.label(opt_hex(thread.start_address));
                });
                row.col(|ui| {
                    ui.label(opt_hex(thread.start_region_base));
                });
                row.col(|ui| {
                    ui.label(thread.start_module.as_deref().unwrap_or("-"));
                });
            });
        });
}
