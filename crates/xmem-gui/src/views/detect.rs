//! 탐지 탭: findings 목록과 상세.

use xmem_core::{Evidence, Finding};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::{confidence_dots, palette, severity_color, severity_label};
use crate::views::export::{ExportFormat, ExportPayload};
use crate::views::overview::failure_banner;

fn evidence_location(evidence: &Evidence) -> String {
    let mut parts = Vec::new();
    if let Some(base) = evidence.region_base {
        parts.push(format!("region {base:#018x}"));
    }
    if let Some(address) = evidence.address {
        parts.push(format!("address {address:#018x}"));
    }
    if parts.is_empty() {
        parts.push("evidence".into());
    }
    parts.join(", ")
}

fn observed_text(evidence: &Evidence) -> String {
    evidence
        .observed
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    ui.horizontal(|ui| {
        let running = app.detect_task.is_running();
        if ui
            .add_enabled(!running, egui::Button::new("탐지 실행"))
            .clicked()
        {
            app.start_detect(pid);
        }
        if running {
            ui.spinner();
            ui.label("규칙 평가 중...");
            if ui.button("취소").clicked() {
                app.detect_task.cancel();
            }
        }
    });
    if let TaskState::Failed(err) = app.detect_task.state() {
        let failure = crate::app::classify_open_failure(
            err,
            app.is_elevated,
            app.detect_task.pid().unwrap_or(pid),
        );
        failure_banner(ui, app, &failure, |app| app.start_detect(pid));
        return;
    }
    let colors = palette(app.theme);
    let selected = app.detect_selected;
    let mut clicked: Option<usize> = None;
    let mut export: Option<ExportFormat> = None;
    if let Some(findings) = app.findings.as_ref() {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("{} findings", findings.len())).weak());
            if ui.button("JSON 내보내기").clicked() {
                export = Some(ExportFormat::Json);
            }
            if ui.button("CSV 내보내기").clicked() {
                export = Some(ExportFormat::Csv);
            }
        });
        if findings.is_empty() {
            ui.label(
                egui::RichText::new("no findings (absence of findings is not proof of safety)")
                    .color(colors.muted),
            );
            return;
        }
        crate::views::truncate_cells(ui);
        // finding 상세가 표 아래에 남아야 하므로 높이는 내용에 맞춘다.
        crate::views::wrap_hscroll_if_wide(
            ui,
            "detect_findings_hscroll",
            500.0,
            [false, true],
            |ui| {
                egui_extras::TableBuilder::new(ui)
                    .min_scrolled_height(0.0)
                    .striped(true)
                    .sense(egui::Sense::click())
                    .column(egui_extras::Column::exact(90.0))
                    .column(egui_extras::Column::exact(100.0))
                    .column(egui_extras::Column::remainder().clip(true))
                    .header(18.0, |mut header| {
                        for title in ["SEVERITY", "RULE", "NAME"] {
                            header.col(|ui| {
                                ui.strong(title);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, findings.len(), |mut row| {
                            let index = row.index();
                            let finding = &findings[index];
                            if Some(index) == selected {
                                row.set_selected(true);
                            }
                            let mut row_clicked = false;
                            row.col(|ui| {
                                row_clicked |= crate::views::table_cell(
                                    ui,
                                    egui::RichText::new(severity_label(finding.severity))
                                        .color(severity_color(finding.severity, &colors)),
                                );
                            });
                            row.col(|ui| {
                                row_clicked |= crate::views::table_cell(
                                    ui,
                                    egui::RichText::new(finding.rule_id.as_str()),
                                );
                            });
                            row.col(|ui| {
                                row_clicked |= crate::views::table_cell(
                                    ui,
                                    egui::RichText::new(finding.name.as_str()),
                                );
                            });
                            if row_clicked {
                                clicked = Some(index);
                            }
                        });
                    });
            },
        );
        crate::views::wrap_default(ui);
        if let Some(format) = export {
            let payload = ExportPayload::Detect(findings.as_slice());
            if let Some(dir) = crate::views::export::save_with_dialog(
                pid,
                "detect",
                format,
                &payload,
                app.config.last_output_dir.clone(),
                &mut app.log,
            ) {
                app.config.last_output_dir = Some(dir);
            }
        }
    } else if !app.detect_task.is_running() {
        ui.label(egui::RichText::new("탐지를 실행하면 규칙 평가 결과가 표시됩니다").weak());
    } else {
        ui.label(egui::RichText::new("평가 중...").weak());
    }
    let detail: Option<Finding> = clicked
        .and_then(|index| app.findings.as_ref()?.get(index).cloned())
        .or_else(|| selected.and_then(|index| app.findings.as_ref()?.get(index).cloned()));
    if let Some(index) = clicked {
        app.detect_selected = Some(index);
    }
    if let Some(finding) = detail {
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!("[{}]", severity_label(finding.severity)))
                    .color(severity_color(finding.severity, &colors))
                    .strong(),
            );
            ui.label(egui::RichText::new(format!("{} {}", finding.rule_id, finding.name)).strong());
            ui.label(egui::RichText::new(confidence_dots(finding.confidence)).weak());
        });
        ui.label(format!("heuristic: {}", finding.heuristic));
        ui.label(format!("interpretation: {}", finding.interpretation));
        if !finding.evidence.is_empty() {
            crate::views::truncate_cells(ui);
            crate::views::wrap_hscroll_if_wide(
                ui,
                "detect_evidence_hscroll",
                680.0,
                [false, false],
                |ui| {
                    egui_extras::TableBuilder::new(ui)
                        .min_scrolled_height(0.0)
                        .striped(true)
                        .column(egui_extras::Column::exact(130.0))
                        .column(egui_extras::Column::exact(250.0))
                        .column(egui_extras::Column::remainder().clip(true))
                        .header(18.0, |mut header| {
                            for title in ["KIND", "LOCATION", "OBSERVED"] {
                                header.col(|ui| {
                                    ui.strong(title);
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(20.0, finding.evidence.len(), |mut row| {
                                let evidence = &finding.evidence[row.index()];
                                row.col(|ui| {
                                    crate::views::table_cell(
                                        ui,
                                        egui::RichText::new(evidence.kind.as_str()),
                                    );
                                });
                                row.col(|ui| {
                                    crate::views::table_cell(
                                        ui,
                                        egui::RichText::new(evidence_location(evidence)),
                                    );
                                });
                                row.col(|ui| {
                                    crate::views::table_cell(
                                        ui,
                                        egui::RichText::new(observed_text(evidence)),
                                    );
                                });
                            });
                        });
                },
            );
        }
    }
}
