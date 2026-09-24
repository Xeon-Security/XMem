//! 무채색 팔레트 + 강조색 3종. 스펙 §5의 토큰 그대로.

use egui::{Color32, Context, Visuals};
use serde::{Deserialize, Serialize};
use xmem_core::{Confidence, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub card: Color32,
    pub border: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub accent: Color32,
    pub warn: Color32,
    pub danger: Color32,
}

fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb(
        (hex >> 16) as u8,
        ((hex >> 8) & 0xff) as u8,
        (hex & 0xff) as u8,
    )
}

pub fn palette(mode: ThemeMode) -> Palette {
    match mode {
        ThemeMode::Dark => Palette {
            bg: rgb(0x141517),
            panel: rgb(0x1B1D20),
            card: rgb(0x23262A),
            border: rgb(0x33373D),
            text: rgb(0xE8EAED),
            muted: rgb(0x9AA0A6),
            accent: rgb(0x4C8DFF),
            warn: rgb(0xE8A33D),
            danger: rgb(0xE5484D),
        },
        ThemeMode::Light => Palette {
            bg: rgb(0xF7F8FA),
            panel: rgb(0xFFFFFF),
            card: rgb(0xF1F3F5),
            border: rgb(0xD7DBE0),
            text: rgb(0x1F2328),
            muted: rgb(0x61676D),
            accent: rgb(0x2563EB),
            warn: rgb(0xB45309),
            danger: rgb(0xDC2626),
        },
    }
}

pub fn apply(ctx: &Context, mode: ThemeMode) {
    let p = palette(mode);
    let mut visuals = match mode {
        ThemeMode::Dark => Visuals::dark(),
        ThemeMode::Light => Visuals::light(),
    };
    visuals.panel_fill = p.panel;
    visuals.window_fill = p.panel;
    visuals.extreme_bg_color = p.bg;
    visuals.faint_bg_color = p.card;
    visuals.override_text_color = Some(p.text);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, p.border);
    visuals.selection.bg_fill = p.accent.gamma_multiply(0.35);
    visuals.selection.stroke = egui::Stroke::new(1.0, p.accent);
    visuals.hyperlink_color = p.accent;
    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(4.0, 4.0);
        style.spacing.button_padding = egui::vec2(8.0, 2.0);
        style.spacing.interact_size.y = 20.0;
        // 스크롤바가 내용 위에 떠서 글자를 가리지 않도록 공간을 차지하게 한다.
        style.spacing.scroll = egui::style::ScrollStyle::solid();
    });
}

pub fn severity_color(severity: Severity, p: &Palette) -> Color32 {
    match severity {
        Severity::Info | Severity::Low => p.muted,
        Severity::Medium => p.warn,
        Severity::High | Severity::Critical => p.danger,
    }
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

pub fn confidence_dots(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "●○○",
        Confidence::Medium => "●●○",
        Confidence::High => "●●●",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_colors_map_monochrome_plus_accents() {
        let p = palette(ThemeMode::Dark);
        assert_eq!(severity_color(Severity::Low, &p), p.muted);
        assert_eq!(severity_color(Severity::Medium, &p), p.warn);
        assert_eq!(severity_color(Severity::High, &p), p.danger);
        assert_eq!(severity_color(Severity::Critical, &p), p.danger);
    }

    #[test]
    fn labels_and_dots_are_stable() {
        assert_eq!(severity_label(Severity::Critical), "CRITICAL");
        assert_eq!(confidence_dots(Confidence::Medium), "●●○");
    }

    #[test]
    fn themes_roundtrip_through_serde() {
        let json = serde_json::to_string(&ThemeMode::Light).unwrap();
        assert_eq!(json, "\"light\"");
        let back: ThemeMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ThemeMode::Light);
    }
}
