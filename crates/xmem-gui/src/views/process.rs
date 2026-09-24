//! 좌측 프로세스 목록 패널.

use xmem_core::ProcessInfo;

use crate::app::XMemApp;

pub fn filter_processes(list: &[ProcessInfo], query: &str) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return (0..list.len()).collect();
    }
    list.iter()
        .enumerate()
        .filter(|(_, info)| {
            info.name.to_lowercase().contains(&query) || info.pid.to_string() == query
        })
        .map(|(index, _)| index)
        .collect()
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    ui.horizontal(|ui| {
        ui.label("프로세스");
        if ui.small_button("새로고침").clicked() {
            app.refresh_processes();
        }
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
    ui.add(
        egui::TextEdit::singleline(&mut app.process_filter)
            .hint_text("이름 또는 PID 검색")
            .desired_width(f32::INFINITY),
    );
    let filtered = filter_processes(&app.processes, &app.process_filter);
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
        .column(egui_extras::Column::initial(150.0).clip(true))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            header.col(|ui| {
                ui.strong("PID");
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
                let filtered = filter_processes(&app.processes, &app.process_filter);
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
            });
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::ProcessArch;

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
        assert_eq!(filter_processes(&list, "PWSH"), vec![0]);
        assert_eq!(filter_processes(&list, "explorer"), vec![1]);
        assert_eq!(filter_processes(&list, "20"), vec![1]);
        assert_eq!(filter_processes(&list, ""), vec![0, 1]);
        assert!(filter_processes(&list, "없는이름").is_empty());
    }
}
