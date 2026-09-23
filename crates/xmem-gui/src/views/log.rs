//! 하단 접이식 로그 패널.

use crate::log::{LogBuffer, LogLevel};

pub fn ui(ui: &mut egui::Ui, log: &LogBuffer) {
    egui::CollapsingHeader::new(format!("로그 ({})", log.len()))
        .default_open(true)
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(140.0)
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
}
