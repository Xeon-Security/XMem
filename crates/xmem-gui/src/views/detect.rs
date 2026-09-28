//! 탐지 탭: findings 목록과 상세.

use xmem_core::{Confidence, Evidence, Finding, FindingFilter, Severity, severity_rank};
use xmem_detection::{RiskLevel, RiskScore, risk_score};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::{Palette, confidence_dots, palette, severity_color, severity_label};
use crate::views::export::{ExportFormat, ExportPayload};
use crate::views::overview::failure_banner;

/// 위험도 배지 문구: `risk 13/100 (low)`.
pub fn risk_text(risk: &RiskScore) -> String {
    format!("risk {}/100 ({})", risk.score, risk.level.as_str())
}

/// level별 배지 색: None/Low muted, Medium warn, High/Critical danger.
pub fn risk_color(level: RiskLevel, p: &Palette) -> egui::Color32 {
    match level {
        RiskLevel::None | RiskLevel::Low => p.muted,
        RiskLevel::Medium => p.warn,
        RiskLevel::High | RiskLevel::Critical => p.danger,
    }
}

/// `detect --sort`와 같은 정렬. 기본 Rule은 기존 rule→주소 순서를 유지한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectSort {
    Rule,
    Address,
    Severity,
}

/// 첫 evidence의 address(없으면 region_base)를 정렬 기준 주소로 쓴다(CLI와 동일).
fn finding_address(finding: &Finding) -> u64 {
    finding
        .evidence
        .first()
        .and_then(|evidence| evidence.address.or(evidence.region_base))
        .unwrap_or(u64::MAX)
}

/// core `FindingFilter::matches`로 거르고 CLI와 같은 순서로 정렬한 행 인덱스.
pub fn select_and_sort_findings(
    findings: &[Finding],
    filter: &FindingFilter,
    sort: DetectSort,
) -> Vec<usize> {
    let mut indices: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| filter.matches(finding))
        .map(|(index, _)| index)
        .collect();
    match sort {
        DetectSort::Rule => {
            indices.sort_by(|&a, &b| findings[a].rule_id.cmp(&findings[b].rule_id));
        }
        DetectSort::Address => indices.sort_by(|&a, &b| {
            finding_address(&findings[a])
                .cmp(&finding_address(&findings[b]))
                .then_with(|| findings[a].rule_id.cmp(&findings[b].rule_id))
        }),
        DetectSort::Severity => indices.sort_by(|&a, &b| {
            severity_rank(findings[b].severity)
                .cmp(&severity_rank(findings[a].severity))
                .then_with(|| findings[a].rule_id.cmp(&findings[b].rule_id))
                .then_with(|| finding_address(&findings[a]).cmp(&finding_address(&findings[b])))
        }),
    }
    indices
}

/// 최소 심각도 라벨. "HIGH"가 아니라 "HIGH 이상"으로 범위를 명시한다.
fn severity_min_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO 이상",
        Severity::Low => "LOW 이상",
        Severity::Medium => "MEDIUM 이상",
        Severity::High => "HIGH 이상",
        Severity::Critical => "CRITICAL 이상",
    }
}

fn severity_option_label(severity: Option<Severity>) -> &'static str {
    match severity {
        None => "심각도: 전체",
        Some(Severity::Info) => "심각도: INFO 이상",
        Some(Severity::Low) => "심각도: LOW 이상",
        Some(Severity::Medium) => "심각도: MEDIUM 이상",
        Some(Severity::High) => "심각도: HIGH 이상",
        Some(Severity::Critical) => "심각도: CRITICAL 이상",
    }
}

fn confidence_min_label(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "LOW 이상",
        Confidence::Medium => "MEDIUM 이상",
        Confidence::High => "HIGH 이상",
    }
}

fn confidence_option_label(confidence: Option<Confidence>) -> &'static str {
    match confidence {
        None => "신뢰도: 전체",
        Some(Confidence::Low) => "신뢰도: LOW 이상",
        Some(Confidence::Medium) => "신뢰도: MEDIUM 이상",
        Some(Confidence::High) => "신뢰도: HIGH 이상",
    }
}

fn severity_options() -> [(Option<Severity>, &'static str); 6] {
    [
        (None, "전체"),
        (Some(Severity::Info), severity_min_label(Severity::Info)),
        (Some(Severity::Low), severity_min_label(Severity::Low)),
        (Some(Severity::Medium), severity_min_label(Severity::Medium)),
        (Some(Severity::High), severity_min_label(Severity::High)),
        (
            Some(Severity::Critical),
            severity_min_label(Severity::Critical),
        ),
    ]
}

fn confidence_options() -> [(Option<Confidence>, &'static str); 4] {
    [
        (None, "전체"),
        (Some(Confidence::Low), confidence_min_label(Confidence::Low)),
        (
            Some(Confidence::Medium),
            confidence_min_label(Confidence::Medium),
        ),
        (
            Some(Confidence::High),
            confidence_min_label(Confidence::High),
        ),
    ]
}

fn sort_label(sort: DetectSort) -> &'static str {
    match sort {
        DetectSort::Rule => "정렬: 규칙",
        DetectSort::Address => "정렬: 주소",
        DetectSort::Severity => "정렬: 심각도 ↓",
    }
}

fn sort_options() -> [(DetectSort, &'static str); 3] {
    [
        (DetectSort::Rule, "규칙"),
        (DetectSort::Address, "주소"),
        (DetectSort::Severity, "심각도 ↓"),
    ]
}

/// 팝업 버튼 활성 개수(구조화 조건 + 규칙 텍스트).
fn filter_count(
    min_severity: Option<Severity>,
    min_confidence: Option<Confidence>,
    rule: &str,
) -> usize {
    usize::from(min_severity.is_some())
        + usize::from(min_confidence.is_some())
        + usize::from(!rule.trim().is_empty())
}

fn severity_menu(ui: &mut egui::Ui, app: &mut XMemApp) {
    crate::views::choice_menu(
        ui,
        severity_option_label(app.detect_filter.min_severity),
        &severity_options(),
        &mut app.detect_filter.min_severity,
    );
}

fn confidence_menu(ui: &mut egui::Ui, app: &mut XMemApp) {
    crate::views::choice_menu(
        ui,
        confidence_option_label(app.detect_filter.min_confidence),
        &confidence_options(),
        &mut app.detect_filter.min_confidence,
    );
}

fn sort_menu(ui: &mut egui::Ui, sort: &mut DetectSort) {
    crate::views::choice_menu(ui, sort_label(*sort), &sort_options(), sort);
}

fn reset_filter(filter: &mut FindingFilter, rule: &mut String) {
    *filter = FindingFilter::default();
    rule.clear();
}

fn filter_contents(ui: &mut egui::Ui, app: &mut XMemApp) {
    severity_menu(ui, app);
    confidence_menu(ui, app);
    ui.horizontal(|ui| {
        ui.label("규칙 ID");
        ui.add(
            egui::TextEdit::singleline(&mut app.detect_rule_filter)
                .hint_text("예: XMEM-003")
                .desired_width(110.0),
        );
    });
    ui.separator();
    ui.label(egui::RichText::new("정렬").weak());
    sort_menu(ui, &mut app.detect_sort);
    crate::views::filter_reset_button(ui, || {
        reset_filter(&mut app.detect_filter, &mut app.detect_rule_filter);
    });
}

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
        if !crate::views::narrow(ui) {
            ui.separator();
            severity_menu(ui, app);
            sort_menu(ui, &mut app.detect_sort);
        }
        crate::views::filter_popup(
            ui,
            "detect_filter_popup",
            filter_count(
                app.detect_filter.min_severity,
                app.detect_filter.min_confidence,
                &app.detect_rule_filter,
            ),
            |ui| {
                filter_contents(ui, app);
            },
        );
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
        let filter = FindingFilter {
            min_severity: app.detect_filter.min_severity,
            min_confidence: app.detect_filter.min_confidence,
            rule_id: Some(app.detect_rule_filter.trim().to_string())
                .filter(|rule| !rule.is_empty()),
        };
        let rows = select_and_sort_findings(findings, &filter, app.detect_sort);
        ui.horizontal(|ui| {
            let count = if rows.len() == findings.len() {
                format!("{} findings", rows.len())
            } else {
                format!("{} / 전체 {} findings", rows.len(), findings.len())
            };
            ui.label(egui::RichText::new(count).weak());
            let risk = risk_score(findings);
            ui.label(
                egui::RichText::new(risk_text(&risk))
                    .color(risk_color(risk.level, &colors))
                    .strong(),
            )
            .on_hover_text("휴리스틱 요약이며 악성 확정이 아닙니다");
            if ui.button("JSON 내보내기").clicked() {
                export = Some(ExportFormat::Json);
            }
            if ui.button("CSV 내보내기").clicked() {
                export = Some(ExportFormat::Csv);
            }
        });
        if let Some(format) = export {
            app.export_error = None;
            let payload = ExportPayload::Detect(findings.as_slice());
            match crate::views::export::save_with_dialog(
                pid,
                "detect",
                format,
                &payload,
                app.config.last_output_dir.clone(),
                &mut app.log,
            ) {
                Ok(Some(dir)) => app.config.last_output_dir = Some(dir),
                Ok(None) => {}
                Err(err) => {
                    app.export_error = Some((
                        crate::app::Tab::Detect,
                        format!("내보내기 실패: {}", crate::error::error_label(&err)),
                    ));
                }
            }
        }
        crate::views::export_error(ui, app, crate::app::Tab::Detect);
        if findings.is_empty() {
            ui.label(
                egui::RichText::new("no findings (absence of findings is not proof of safety)")
                    .color(colors.muted),
            );
            return;
        }
        if rows.is_empty() {
            ui.label(
                egui::RichText::new(
                    "필터에 맞는 finding이 없습니다 — 필터 팝업에서 조건을 바꾸거나 [필터 초기화]를 누르세요",
                )
                .color(colors.muted),
            );
            return;
        }
        crate::views::truncate_cells(ui);
        // finding 상세가 표 아래에 남아야 하므로 높이는 내용에 맞춘다.
        crate::views::wrap_hscroll(ui, "detect_findings_hscroll", 500.0, [false, true], |ui| {
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
                    body.rows(20.0, rows.len(), |mut row| {
                        let index = rows[row.index()];
                        let finding = &findings[index];
                        if Some(index) == selected {
                            row.set_selected(true);
                        }
                        let mut row_clicked = false;
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell_focusable(
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
        });
        crate::views::wrap_default(ui);
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
            crate::views::wrap_hscroll(
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

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, Finding, FindingFilter, Severity};

    fn finding(rule: &str, severity: Severity, base: u64) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            name: "n".to_string(),
            severity,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region").with_region_base(base)],
            heuristic: "h".to_string(),
            interpretation: "i".to_string(),
        }
    }

    #[test]
    fn select_and_sort_findings_filters_and_orders() {
        let findings = vec![
            finding("XMEM-005", Severity::High, 0x3000),
            finding("XMEM-001", Severity::Medium, 0x1000),
            finding("XMEM-003", Severity::High, 0x2000),
        ];
        let all = FindingFilter::default();
        assert_eq!(
            select_and_sort_findings(&findings, &all, DetectSort::Rule),
            vec![1, 2, 0],
            "기본 rule 정렬은 rule→주소 순서"
        );
        assert_eq!(
            select_and_sort_findings(&findings, &all, DetectSort::Address),
            vec![1, 2, 0]
        );
        assert_eq!(
            select_and_sort_findings(&findings, &all, DetectSort::Severity),
            vec![2, 0, 1],
            "severity는 내림차순"
        );
        let high = FindingFilter {
            min_severity: Some(Severity::High),
            ..FindingFilter::default()
        };
        assert_eq!(
            select_and_sort_findings(&findings, &high, DetectSort::Severity),
            vec![2, 0]
        );
        let by_rule = FindingFilter {
            rule_id: Some("xmem-001".into()),
            ..FindingFilter::default()
        };
        assert_eq!(
            select_and_sort_findings(&findings, &by_rule, DetectSort::Rule),
            vec![1]
        );
    }

    #[test]
    fn risk_text_and_color_follow_level() {
        let risk = risk_score(&[finding("XMEM-001", Severity::Medium, 0x1000)]);
        assert_eq!(risk_text(&risk), "risk 13/100 (low)");
        let p = palette(crate::theme::ThemeMode::Dark);
        assert_eq!(risk_color(RiskLevel::None, &p), p.muted);
        assert_eq!(risk_color(RiskLevel::Low, &p), p.muted);
        assert_eq!(risk_color(RiskLevel::Medium, &p), p.warn);
        assert_eq!(risk_color(RiskLevel::High, &p), p.danger);
        assert_eq!(risk_color(RiskLevel::Critical, &p), p.danger);
    }

    #[test]
    fn menu_option_labels_cover_selected_texts() {
        for (value, label) in severity_options() {
            assert_eq!(
                severity_option_label(value).strip_prefix("심각도: "),
                Some(label),
                "심각도 선택 문구는 '... 이상' 형식"
            );
        }
        for (value, label) in confidence_options() {
            assert_eq!(
                confidence_option_label(value).strip_prefix("신뢰도: "),
                Some(label)
            );
        }
        for (value, label) in sort_options() {
            assert_eq!(sort_label(value).strip_prefix("정렬: "), Some(label));
        }
        assert_eq!(severity_min_label(Severity::High), "HIGH 이상");
        assert_eq!(confidence_min_label(Confidence::High), "HIGH 이상");
    }

    #[test]
    fn filter_count_and_reset_cover_all_conditions() {
        assert_eq!(filter_count(None, None, ""), 0);
        assert_eq!(filter_count(None, None, "  "), 0, "공백만이면 비활성");
        assert_eq!(
            filter_count(Some(Severity::High), Some(Confidence::Medium), "XMEM-003"),
            3
        );
        let mut filter = FindingFilter {
            min_severity: Some(Severity::High),
            min_confidence: Some(Confidence::Medium),
            rule_id: Some("XMEM-003".into()),
        };
        let mut rule = "XMEM-003".to_string();
        reset_filter(&mut filter, &mut rule);
        assert_eq!(filter, FindingFilter::default());
        assert!(rule.is_empty());
    }
}
