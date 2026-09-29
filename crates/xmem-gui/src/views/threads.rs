//! 스레드 탭.

use xmem_core::ThreadFilter;

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::views::map::{opt_hex, opt_num};
use crate::views::overview::failure_banner;

/// core `ThreadFilter::matches`로 스레드 행을 고른다.
pub fn select_threads(threads: &[xmem_core::ThreadInfo], filter: &ThreadFilter) -> Vec<usize> {
    threads
        .iter()
        .enumerate()
        .filter(|(_, thread)| filter.matches(thread))
        .map(|(index, _)| index)
        .collect()
}

fn effective_filter(app: &XMemApp) -> ThreadFilter {
    ThreadFilter {
        with_start_only: app.thread_filter.with_start_only,
        suspicious_only: app.thread_filter.suspicious_only,
        tid: crate::views::parse_u32_text(&app.thread_tid_filter).unwrap_or(None),
    }
}

fn filter_count(with_start_only: bool, suspicious_only: bool, tid: &str) -> usize {
    usize::from(with_start_only)
        + usize::from(suspicious_only)
        + usize::from(!tid.trim().is_empty())
}

fn reset_filter(filter: &mut ThreadFilter, tid: &mut String) {
    *filter = ThreadFilter::default();
    tid.clear();
}

fn filter_contents(ui: &mut egui::Ui, app: &mut XMemApp) {
    ui.checkbox(&mut app.thread_filter.with_start_only, "시작 주소 있음만");
    ui.checkbox(
        &mut app.thread_filter.suspicious_only,
        "의심(시작 주소 있고 모듈 없음)",
    )
    .on_hover_text("시작 주소가 조회되지만 소유 모듈이 없는 스레드");
    ui.horizontal(|ui| {
        ui.label("TID");
        ui.add(
            egui::TextEdit::singleline(&mut app.thread_tid_filter)
                .hint_text("숫자")
                .desired_width(60.0),
        );
    });
    if let Err(err) = crate::views::parse_u32_text(&app.thread_tid_filter)
        && !app.thread_tid_filter.trim().is_empty()
    {
        ui.colored_label(crate::theme::palette(app.theme).danger, err);
    }
    crate::views::filter_reset_button(ui, || {
        reset_filter(&mut app.thread_filter, &mut app.thread_tid_filter);
    });
}

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
            if ui.button("취소").clicked() {
                app.threads_task.cancel();
            }
        }
        if !crate::views::narrow(ui) {
            ui.separator();
            ui.checkbox(&mut app.thread_filter.with_start_only, "시작 주소 있음만");
            ui.checkbox(&mut app.thread_filter.suspicious_only, "의심만");
            ui.label("TID");
            ui.add(
                egui::TextEdit::singleline(&mut app.thread_tid_filter)
                    .hint_text("숫자")
                    .desired_width(50.0),
            );
        }
        crate::views::filter_popup(
            ui,
            "thread_filter_popup",
            filter_count(
                app.thread_filter.with_start_only,
                app.thread_filter.suspicious_only,
                &app.thread_tid_filter,
            ),
            |ui| {
                filter_contents(ui, app);
            },
        );
    });
    match app.threads_task.state() {
        TaskState::Failed(err) => {
            let failure = crate::app::classify_open_failure(
                err,
                app.is_elevated,
                app.threads_task.pid().unwrap_or(pid),
            );
            failure_banner(ui, app, &failure, |app| app.start_threads(pid));
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
    let rows = select_threads(threads, &effective_filter(app));
    ui.label(
        egui::RichText::new(if rows.len() == threads.len() {
            format!("{}개 스레드", rows.len())
        } else {
            format!("{}개 / 전체 {}개 스레드", rows.len(), threads.len())
        })
        .weak(),
    );
    if rows.is_empty() {
        ui.label(
            egui::RichText::new(
                "필터에 맞는 스레드가 없습니다 — 필터 팝업에서 조건을 바꾸거나 [필터 초기화]를 누르세요",
            )
            .color(crate::theme::palette(app.theme).muted),
        );
        return;
    }
    let selected_tid = app.thread_selected;
    let mut clicked_thread: Option<xmem_core::ThreadInfo> = None;
    let mut moved_thread: Option<xmem_core::ThreadInfo> = None;
    let mut moved_row: Option<usize> = None;
    if let Some(next) = crate::views::arrow_step(
        ui.ctx(),
        rows.len(),
        selected_tid.and_then(|tid| threads.iter().position(|thread| thread.tid == tid)),
        &rows,
    ) {
        moved_row = rows.iter().position(|&index| index == next);
        if let Some(thread) = threads.get(next) {
            moved_thread = Some(thread.clone());
        }
    }
    crate::views::truncate_cells(ui);
    crate::views::wrap_hscroll(ui, "threads_table_hscroll", 760.0, [false, false], |ui| {
        let mut builder = egui_extras::TableBuilder::new(ui)
            .min_scrolled_height(0.0)
            .striped(true)
            .sense(egui::Sense::click())
            .column(egui_extras::Column::exact(70.0))
            .column(egui_extras::Column::exact(80.0))
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::remainder().clip(true));
        if let Some(row) = moved_row {
            builder = builder.scroll_to_row(row, None);
        }
        builder
            .header(18.0, |mut header| {
                for title in ["TID", "PRIORITY", "START ADDRESS", "REGION", "MODULE"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let thread = &threads[rows[row.index()]];
                    row.set_selected(selected_tid == Some(thread.tid));
                    let mut row_clicked = false;
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell_focusable(
                            ui,
                            egui::RichText::new(thread.tid.to_string()),
                        );
                    });
                    row.col(|ui| {
                        row_clicked |= crate::views::table_cell(
                            ui,
                            egui::RichText::new(opt_num(thread.priority)),
                        );
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
    });
    if let Some(thread) = clicked_thread.or(moved_thread) {
        app.select_thread(pid, thread);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{ThreadFilter, ThreadInfo};

    fn thread(tid: u32, start: Option<u64>, module: Option<&str>) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1,
            priority: Some(8),
            start_address: start,
            start_region_base: start.map(|address| address & !0xfff),
            start_module: module.map(str::to_string),
            start_address_source: None,
        }
    }

    #[test]
    fn select_threads_uses_core_filter() {
        let threads = vec![
            thread(100, Some(0x1000), Some("mod.dll")),
            thread(200, Some(0x9000), None),
            thread(300, None, None),
        ];
        assert_eq!(
            select_threads(&threads, &ThreadFilter::default()),
            vec![0, 1, 2]
        );
        assert_eq!(
            select_threads(
                &threads,
                &ThreadFilter {
                    suspicious_only: true,
                    ..ThreadFilter::default()
                }
            ),
            vec![1],
            "의심 = 시작 주소가 있고 소유 모듈이 없음"
        );
        assert_eq!(
            select_threads(
                &threads,
                &ThreadFilter {
                    with_start_only: true,
                    tid: Some(100),
                    ..ThreadFilter::default()
                }
            ),
            vec![0]
        );
        assert!(
            select_threads(
                &threads,
                &ThreadFilter {
                    tid: Some(999),
                    ..ThreadFilter::default()
                }
            )
            .is_empty()
        );
    }

    #[test]
    fn filter_count_and_reset_cover_conditions() {
        assert_eq!(filter_count(false, false, ""), 0);
        assert_eq!(filter_count(false, false, " "), 0, "공백만이면 비활성");
        assert_eq!(filter_count(true, true, "100"), 3);
        let mut filter = ThreadFilter {
            with_start_only: true,
            suspicious_only: true,
            tid: Some(100),
        };
        let mut tid = "100".to_string();
        reset_filter(&mut filter, &mut tid);
        assert_eq!(filter, ThreadFilter::default());
        assert!(tid.is_empty());
    }
}
