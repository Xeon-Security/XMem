//! 리포트 탭.

use xmem_core::Result;

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::map::human_size;

pub fn build_report_data(pid: u32) -> Result<xmem_forensics::ReportData> {
    let live = xmem_memory::LiveProcess::open(pid)?;
    let regions = live.region_map()?.regions;
    let modules = live.modules()?;
    let threads = live.threads()?;
    let findings = xmem_detection::detect_source(&live)?;
    Ok(xmem_forensics::ReportData::new(
        live.info.clone(),
        regions,
        modules,
        threads,
        findings,
    ))
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    let colors = palette(app.theme);
    ui.heading("리포트");
    ui.label(
        egui::RichText::new(
            "프로세스 메모리/모듈/스레드/탐지 결과를 JSON 또는 Markdown 리포트로 저장합니다.",
        )
        .weak(),
    );
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("형식:");
        ui.radio_value(&mut app.report_markdown, false, "JSON");
        ui.radio_value(&mut app.report_markdown, true, "Markdown");
    });
    ui.horizontal(|ui| {
        ui.label("출력:");
        ui.add(
            egui::TextEdit::singleline(&mut app.report_output)
                .desired_width(320.0)
                .hint_text("비우면 Documents\\XMem 아래 기본 이름"),
        );
        if ui.button("찾아보기").clicked() {
            let (ext, label) = if app.report_markdown {
                ("md", "Markdown")
            } else {
                ("json", "JSON")
            };
            if let Some(path) = rfd::FileDialog::new()
                .set_file_name(crate::config::output_file_name(
                    "report",
                    pid,
                    ext,
                    chrono::Local::now(),
                ))
                .set_directory(
                    app.config
                        .last_output_dir
                        .clone()
                        .unwrap_or_else(crate::config::default_output_dir),
                )
                .add_filter(label, &[ext])
                .save_file()
            {
                app.report_output = path.to_string_lossy().into_owned();
            }
        }
    });
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.report_task.is_running(),
                egui::Button::new("리포트 저장"),
            )
            .clicked()
        {
            app.start_report_save(pid);
        }
        if app.report_task.is_running() {
            ui.spinner();
            ui.label("수집 및 저장 중...");
        }
    });
    if let TaskState::Failed(err) = app.report_task.state() {
        ui.label(egui::RichText::new(err.to_string()).color(colors.danger));
    }
    if let Some((path, bytes)) = app.report_saved.clone() {
        ui.label(format!("저장 완료: {path} ({})", human_size(bytes)));
    }
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(
            "탐지 결과 0건은 안전을 의미하지 않습니다. Evidence와 Heuristic을 함께 확인하세요.",
        )
        .color(colors.muted),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_of_self_has_regions_and_summary() {
        let data = build_report_data(std::process::id()).unwrap();
        assert!(!data.regions.is_empty());
        assert_eq!(data.summary.regions_total, data.regions.len());
    }
}
