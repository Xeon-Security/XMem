//! 하단 접이식 로그 패널.

use crate::log::{LogBuffer, LogLevel};
use crate::theme::{ThemeMode, palette};

pub fn ui(ui: &mut egui::Ui, log: &mut LogBuffer, theme: ThemeMode) {
    let colors = palette(theme);
    egui::CollapsingHeader::new(format!("로그 ({})", log.len()))
        .default_open(true)
        .show(ui, |ui| {
            if !log.is_empty() && ui.small_button("지우기").clicked() {
                log.clear();
            }
            crate::views::pane_hint(ui);
            crate::views::resizable_pane(ui, "log_pane", 160.0, 80.0, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        if log.is_empty() {
                            ui.label(egui::RichText::new("기록된 로그가 없습니다").weak());
                        }
                        for entry in log.iter() {
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
