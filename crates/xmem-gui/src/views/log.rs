//! 하단 접이식 로그 패널. 레벨 필터(보기 전용)와 파일 저장을 제공한다.

use std::path::Path;

use crate::log::{LogBuffer, LogLevel};
use crate::theme::{ThemeMode, palette};

fn level_label(filter: Option<LogLevel>) -> &'static str {
    match filter {
        None => "레벨: 전체",
        Some(LogLevel::Info) => "레벨: INFO 이상",
        Some(LogLevel::Warn) => "레벨: WARN 이상",
        Some(LogLevel::Error) => "레벨: ERROR만",
    }
}

pub fn ui(ui: &mut egui::Ui, log: &mut LogBuffer, theme: ThemeMode, default_dir: &Path) {
    let colors = palette(theme);
    egui::CollapsingHeader::new(format!("로그 ({}/{})", log.visible_len(), log.len()))
        .default_open(true)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if !log.is_empty() && ui.small_button("지우기").clicked() {
                    log.clear();
                }
                egui::ComboBox::from_id_salt("log_level_filter")
                    .selected_text(level_label(log.filter()))
                    .show_ui(ui, |ui| {
                        let mut filter = log.filter();
                        for (value, label) in [
                            (None, "전체"),
                            (Some(LogLevel::Info), "INFO 이상"),
                            (Some(LogLevel::Warn), "WARN 이상"),
                            (Some(LogLevel::Error), "ERROR만"),
                        ] {
                            ui.selectable_value(&mut filter, value, label);
                        }
                        log.set_filter(filter);
                    });
                if ui
                    .small_button("파일로 저장")
                    .on_hover_text("필터와 무관하게 전체 로그를 저장합니다")
                    .clicked()
                {
                    let suggested = format!(
                        "xmem-log-{}.txt",
                        chrono::Local::now().format("%Y%m%d-%H%M%S")
                    );
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("로그 저장")
                        .set_file_name(suggested)
                        .set_directory(default_dir)
                        .save_file()
                    {
                        match log.save(&path) {
                            Ok(bytes) => log.push(
                                LogLevel::Info,
                                format!("로그 저장됨: {} ({} bytes)", path.display(), bytes),
                            ),
                            Err(error) => log.push(
                                LogLevel::Error,
                                format!("로그 저장 실패: {} ({error})", path.display()),
                            ),
                        }
                    }
                }
            });
            crate::views::pane_hint(ui);
            crate::views::resizable_pane(ui, "log_pane", 160.0, 80.0, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if log.visible_len() == 0 {
                            let message = if log.is_empty() {
                                "기록된 로그가 없습니다"
                            } else {
                                "필터에 맞는 로그가 없습니다 (레벨 필터를 확인하세요)"
                            };
                            ui.label(egui::RichText::new(message).weak());
                        }
                        for entry in log.iter_visible() {
                            let (severity, color) = match entry.level {
                                LogLevel::Info => ("INFO", colors.muted),
                                LogLevel::Warn => ("WARN", colors.warn),
                                LogLevel::Error => ("ERROR", colors.danger),
                            };
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&entry.time).monospace().weak());
                                ui.label(egui::RichText::new(severity).monospace().color(color));
                                ui.label(egui::RichText::new(&entry.message).color(color));
                            });
                        }
                    });
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_labels_cover_all_filters() {
        assert_eq!(level_label(None), "레벨: 전체");
        assert_eq!(level_label(Some(LogLevel::Info)), "레벨: INFO 이상");
        assert_eq!(level_label(Some(LogLevel::Warn)), "레벨: WARN 이상");
        assert_eq!(level_label(Some(LogLevel::Error)), "레벨: ERROR만");
    }
}
