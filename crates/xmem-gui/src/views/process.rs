//! 좌측 프로세스 목록 패널.

use std::collections::HashSet;

use xmem_core::{ProcessArch, ProcessInfo};

use crate::app::XMemApp;
use crate::task::TaskState;

pub fn filter_processes(
    list: &[ProcessInfo],
    query: &str,
    accessible: &HashSet<u32>,
    accessible_only: bool,
    arch_filter: Option<ProcessArch>,
) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    list.iter()
        .enumerate()
        .filter(|(_, info)| {
            (query.is_empty()
                || info.name.to_lowercase().contains(&query)
                || info.pid.to_string() == query)
                && (!accessible_only || accessible.contains(&info.pid))
                && arch_filter.is_none_or(|arch| info.arch == arch)
        })
        .map(|(index, _)| index)
        .collect()
}

/// 아키텍처 필터 콤보 표시 문구.
fn arch_filter_label(filter: Option<ProcessArch>) -> &'static str {
    match filter {
        None => "아키텍처: 전체",
        Some(ProcessArch::X64) => "아키텍처: x64",
        Some(ProcessArch::X86) => "아키텍처: x86",
        Some(ProcessArch::Arm64) => "아키텍처: arm64",
        Some(ProcessArch::Unknown) => "아키텍처: 기타",
    }
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    ui.horizontal(|ui| {
        ui.label("프로세스");
        if ui
            .add_enabled(
                !app.list_task.is_running(),
                egui::Button::new("새로고침").small(),
            )
            .clicked()
        {
            app.refresh_processes();
        }
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
    let list_failure = match app.list_task.state() {
        TaskState::Failed(err) => Some(crate::error::error_label(err)),
        _ => None,
    };
    if let Some(message) = list_failure {
        ui.label(egui::RichText::new(message).color(crate::theme::palette(app.theme).danger));
        if ui.button("다시 시도").clicked() {
            app.refresh_processes();
        }
        return;
    }
    ui.add(
        egui::TextEdit::singleline(&mut app.process_filter)
            .hint_text("이름 또는 PID 검색")
            .desired_width(f32::INFINITY),
    );
    ui.horizontal(|ui| {
        ui.checkbox(&mut app.process_accessible_only, "접근 가능만 보기");
        egui::ComboBox::from_id_salt("process_arch_filter")
            .selected_text(arch_filter_label(app.process_arch_filter))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.process_arch_filter, None, "전체");
                ui.selectable_value(&mut app.process_arch_filter, Some(ProcessArch::X64), "x64");
                ui.selectable_value(&mut app.process_arch_filter, Some(ProcessArch::X86), "x86");
            });
    });
    let filtered = filter_processes(
        &app.processes,
        &app.process_filter,
        &app.list_accessible,
        app.process_accessible_only,
        app.process_arch_filter,
    );
    ui.label(
        egui::RichText::new(format!(
            "{}개 / 전체 {}개",
            filtered.len(),
            app.processes.len()
        ))
        .weak(),
    );
    ui.separator();
    let row_height = 20.0;
    crate::views::truncate_cells(ui);
    egui_extras::TableBuilder::new(ui)
        .min_scrolled_height(0.0)
        .striped(true)
        .sense(egui::Sense::click())
        .column(egui_extras::Column::exact(56.0))
        .column(egui_extras::Column::exact(64.0))
        .column(egui_extras::Column::initial(150.0).clip(true))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            header.col(|ui| {
                ui.strong("PID");
            });
            header.col(|ui| {
                ui.strong("접근");
            });
            header.col(|ui| {
                ui.strong("이름");
            });
            header.col(|ui| {
                ui.strong("경로");
            });
        })
        .body(|body| {
            body.rows(row_height, filtered.len(), |mut row| {
                let index = filtered[row.index()];
                let pid = app.processes[index].pid;
                row.set_selected(app.selected_pid == Some(pid));
                let mut row_clicked = false;
                row.col(|ui| {
                    row_clicked |=
                        crate::views::table_cell(ui, egui::RichText::new(pid.to_string()));
                });
                row.col(|ui| {
                    let accessible = app.list_accessible.contains(&pid);
                    let text = if accessible {
                        "가능"
                    } else {
                        "권한 필요"
                    };
                    let rich = if accessible {
                        egui::RichText::new(text)
                    } else {
                        egui::RichText::new(text).color(crate::theme::palette(app.theme).warn)
                    };
                    row_clicked |= crate::views::table_cell(ui, rich);
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(app.processes[index].name.as_str()),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(
                            app.processes[index].image_path.as_deref().unwrap_or("-"),
                        )
                        .weak(),
                    );
                });
                if row_clicked {
                    app.select_process(pid);
                }
            });
        });
}

/// 좁은 창(<900px)에서 쓰는 프로세스 드롭다운.
pub fn dropdown(ui: &mut egui::Ui, app: &mut XMemApp) {
    // 좁은 레이아웃에서도 필터를 보이게 한다 — 숨은 필터 때문에 목록이 비어 보이는 것을 막는다.
    ui.add(
        egui::TextEdit::singleline(&mut app.process_filter)
            .hint_text("이름 또는 PID 검색")
            .desired_width(f32::INFINITY),
    );
    let selected_text = app
        .selected_pid
        .and_then(|pid| app.processes.iter().find(|p| p.pid == pid))
        .map(|p| format!("{} ({})", p.name, p.pid))
        .unwrap_or_else(|| "프로세스 선택".into());
    ui.horizontal(|ui| {
        ui.label("프로세스");
        egui::ComboBox::from_id_salt("process_dropdown")
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                let filtered = filter_processes(
                    &app.processes,
                    &app.process_filter,
                    &app.list_accessible,
                    app.process_accessible_only,
                    app.process_arch_filter,
                );
                let filtered_len = filtered.len();
                for index in filtered.into_iter().take(200) {
                    let (name, pid) = (app.processes[index].name.clone(), app.processes[index].pid);
                    let selected = app.selected_pid == Some(pid);
                    if ui
                        .selectable_label(selected, format!("{name} ({pid})"))
                        .clicked()
                    {
                        app.select_process(pid);
                    }
                }
                if filtered_len > 200 {
                    ui.label(egui::RichText::new("상위 200개만 표시 (필터를 사용하세요)").weak());
                }
            });
        if ui
            .add_enabled(
                !app.list_task.is_running(),
                egui::Button::new("새로고침").small(),
            )
            .clicked()
        {
            app.refresh_processes();
        }
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
    let list_failure = match app.list_task.state() {
        TaskState::Failed(err) => Some(crate::error::error_label(err)),
        _ => None,
    };
    if let Some(message) = list_failure {
        ui.label(egui::RichText::new(message).color(crate::theme::palette(app.theme).danger));
        if ui.button("다시 시도").clicked() {
            app.refresh_processes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: None,
            name: name.to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    #[test]
    fn filter_matches_name_case_insensitive_and_pid() {
        let list = vec![sample(10, "pwsh.exe"), sample(20, "explorer.exe")];
        let none = HashSet::new();
        assert_eq!(filter_processes(&list, "PWSH", &none, false, None), vec![0]);
        assert_eq!(
            filter_processes(&list, "explorer", &none, false, None),
            vec![1]
        );
        assert_eq!(filter_processes(&list, "20", &none, false, None), vec![1]);
        assert_eq!(filter_processes(&list, "", &none, false, None), vec![0, 1]);
        assert!(filter_processes(&list, "없는이름", &none, false, None).is_empty());
    }

    #[test]
    fn filter_processes_applies_access_and_arch_filters() {
        let mut x86 = sample(20, "two.exe");
        x86.arch = ProcessArch::X86;
        let list = vec![sample(10, "one.exe"), x86, sample(30, "three.exe")];
        let accessible = HashSet::from([10]);
        assert_eq!(
            filter_processes(&list, "", &accessible, true, None),
            vec![0]
        );
        assert_eq!(
            filter_processes(&list, "", &accessible, false, None),
            vec![0, 1, 2]
        );
        assert_eq!(
            filter_processes(&list, "", &accessible, false, Some(ProcessArch::X86)),
            vec![1]
        );
        assert_eq!(
            filter_processes(&list, "", &accessible, true, Some(ProcessArch::X64)),
            vec![0]
        );
    }
}
