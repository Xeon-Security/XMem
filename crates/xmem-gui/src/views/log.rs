//! 하단 접이식 로그 패널.

use crate::log::{LogBuffer, LogLevel};

pub fn ui(ui: &mut egui::Ui, log: &mut LogBuffer) {
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
                    .show(ui, |ui| {
                        if log.is_empty() {
                            ui.label(egui::RichText::new("기록된 로그가 없습니다").weak());
                        }
                        for entry in log.iter() {
                            let color = match entry.level {
                                LogLevel::Info => ui.visuals().weak_text_color(),
                                LogLevel::Warn => egui::Color32::from_rgb(0xE8, 0xA3, 0x3D),
                                LogLevel::Error => egui::Color32::from_rgb(0xE5, 0x48, 0x4D),
                            };
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(&entry.time).monospace().weak());
                                ui.label(egui::RichText::new(&entry.message).color(color));
                            });
                        }
                    });
            });
        });
}
