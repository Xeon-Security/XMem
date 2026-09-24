//! 검색 탭: needle 입력 + 필터 + 결과 표 + 주소 미리보기.

use xmem_core::{MemorySource, ScanPattern, XmemError};
use xmem_memory::{
    DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, LiveProcess, RegionFilters, ScanOptions,
};

use crate::app::XMemApp;
use crate::log::LogLevel;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::map::{human_size, opt_hex};
use crate::views::overview::failure_banner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedleKind {
    Pattern,
    Ascii,
    Wide,
}

pub struct ScanUiState {
    pub needle: String,
    pub kind: NeedleKind,
    pub executable_only: bool,
    pub private_only: bool,
    pub writable_only: bool,
    pub max_results: usize,
    pub threads: usize,
    pub selected_match: Option<usize>,
    pub preview: Option<(u64, String)>,
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1).clamp(1, 4))
        .unwrap_or(1)
}

impl Default for ScanUiState {
    fn default() -> Self {
        Self {
            needle: String::new(),
            kind: NeedleKind::Ascii,
            executable_only: false,
            private_only: false,
            writable_only: false,
            max_results: DEFAULT_MAX_RESULTS,
            threads: default_threads(),
            selected_match: None,
            preview: None,
        }
    }
}

pub fn hex_dump(bytes: &[u8], base: u64) -> String {
    let mut out = String::new();
    for (index, chunk) in bytes.chunks(16).enumerate() {
        let address = base + (index * 16) as u64;
        out.push_str(&format!("{address:#018x}  "));
        for i in 0..16 {
            match chunk.get(i) {
                Some(byte) => out.push_str(&format!("{byte:02x} ")),
                None => out.push_str("   "),
            }
        }
        out.push(' ');
        for byte in chunk {
            let ch = if (0x20..0x7f).contains(byte) {
                *byte as char
            } else {
                '.'
            };
            out.push(ch);
        }
        out.push('\n');
    }
    out
}

/// 미리보기 범위: 주소 ±64바이트(총 128), 영역 경계로 클램프.
/// 창이 영역을 벗어나면 크기를 줄이지 않고 안쪽으로 밀어 넣는다.
pub fn preview_range(address: u64, region_base: u64, region_size: u64) -> (u64, usize) {
    let region_end = region_base.saturating_add(region_size);
    let size = region_size.min(128);
    let last_start = region_end.saturating_sub(size).max(region_base);
    let start = address.saturating_sub(64).clamp(region_base, last_start);
    (start, size as usize)
}

pub fn build_pattern(state: &ScanUiState) -> xmem_core::Result<ScanPattern> {
    let needle = state.needle.trim();
    if needle.is_empty() {
        return Err(XmemError::InvalidInput {
            reason: "검색어를 입력하세요".into(),
        });
    }
    match state.kind {
        NeedleKind::Pattern => ScanPattern::hex(needle),
        NeedleKind::Ascii => ScanPattern::ascii(needle),
        NeedleKind::Wide => ScanPattern::wide(needle),
    }
}

pub fn build_options(state: &ScanUiState) -> ScanOptions {
    ScanOptions {
        filters: RegionFilters {
            executable_only: state.executable_only,
            private_only: state.private_only,
            writable_only: state.writable_only,
            range: None,
            max_region_size: None,
            all: false,
        },
        chunk_size: DEFAULT_CHUNK_SIZE,
        threads: state.threads.max(1),
        max_results: state.max_results,
        offset: None,
    }
}

fn load_preview(app: &mut XMemApp, pid: u32, address: u64, region_base: u64, region_size: u64) {
    let (start, len) = preview_range(address, region_base, region_size);
    if len == 0 {
        return;
    }
    let Ok(live) = LiveProcess::open(pid) else {
        app.log
            .push(LogLevel::Warn, "미리보기: 프로세스를 열 수 없습니다");
        return;
    };
    let mut buf = vec![0u8; len];
    match live.read(start, &mut buf) {
        Ok(outcome) if outcome.bytes_read > 0 => {
            app.scan_state.preview = Some((start, hex_dump(&buf[..outcome.bytes_read], start)));
        }
        Ok(_) => app
            .log
            .push(LogLevel::Warn, "미리보기: 0바이트를 읽었습니다"),
        Err(err) => app
            .log
            .push(LogLevel::Warn, format!("미리보기 실패: {err}")),
    }
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    ui.horizontal(|ui| {
        ui.label("검색어");
        ui.add(
            egui::TextEdit::singleline(&mut app.scan_state.needle)
                .hint_text("pwsh / 48 8B ?? ?? / 문자열"),
        );
        ui.label("형식");
        ui.radio_value(&mut app.scan_state.kind, NeedleKind::Pattern, "패턴(hex)");
        ui.radio_value(&mut app.scan_state.kind, NeedleKind::Ascii, "ASCII");
        ui.radio_value(&mut app.scan_state.kind, NeedleKind::Wide, "UTF-16");
    });
    ui.horizontal(|ui| {
        ui.checkbox(&mut app.scan_state.executable_only, "실행 가능만");
        ui.checkbox(&mut app.scan_state.private_only, "Private만");
        ui.checkbox(&mut app.scan_state.writable_only, "쓰기 가능만");
        ui.separator();
        ui.label("최대 결과");
        ui.add(
            egui::DragValue::new(&mut app.scan_state.max_results)
                .range(0..=1_000_000)
                .speed(8.0),
        );
        ui.label("스레드");
        ui.add(
            egui::DragValue::new(&mut app.scan_state.threads)
                .range(1..=64)
                .speed(0.2),
        );
    });
    ui.horizontal(|ui| {
        let running = app.scan_task.is_running();
        if ui
            .add_enabled(!running, egui::Button::new("검색"))
            .clicked()
        {
            app.start_scan(pid);
        }
        if running {
            ui.spinner();
            if ui.button("취소").clicked() {
                app.scan_task.cancel();
            }
        }
    });
    if let TaskState::Failed(err) = app.scan_task.state() {
        let failure = crate::app::classify_open_failure(err, app.is_elevated, pid);
        failure_banner(ui, app, &failure);
        return;
    }
    let colors = palette(app.theme);
    let mut clicked: Option<usize> = None;
    if let Some(report) = app.scan_report.as_ref() {
        if report.cancelled {
            ui.label(
                egui::RichText::new(format!("취소됨(부분 결과 {}건)", report.matches.len()))
                    .color(colors.warn),
            );
        }
        if report.truncated {
            ui.label(
                egui::RichText::new("최대 결과 수에 도달했습니다(결과 일부 생략)")
                    .color(colors.warn),
            );
        }
        if report.policy_restricted {
            ui.label(
                egui::RichText::new("대형 프로세스 정책: executable/private 영역만 검색했습니다")
                    .weak(),
            );
        }
        ui.label(
            egui::RichText::new(format!(
                "{}건 · {}개 영역 검색({}개 건너뜀) · {} · {}ms · rss {}",
                report.matches.len(),
                report.stats.regions_scanned,
                report.stats.regions_skipped,
                human_size(report.stats.bytes_scanned),
                report.stats.elapsed_ms,
                human_size(report.stats.rss_bytes),
            ))
            .weak(),
        );
        let selected = app.scan_state.selected_match;
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(egui_extras::Column::exact(150.0))
            .column(egui_extras::Column::exact(80.0))
            .column(egui_extras::Column::exact(80.0))
            .column(egui_extras::Column::exact(120.0))
            .column(egui_extras::Column::exact(140.0))
            .column(egui_extras::Column::remainder().clip(true))
            .header(18.0, |mut header| {
                for title in ["ADDRESS", "OFFSET", "CLASS", "PROTECTION", "REGION", "FILE"] {
                    header.col(|ui| {
                        ui.strong(title);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, report.matches.len(), |mut row| {
                    let index = row.index();
                    let found = &report.matches[index];
                    if Some(index) == selected {
                        row.set_selected(true);
                    }
                    row.col(|ui| {
                        ui.label(opt_hex(Some(found.address)));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:#x}", found.offset));
                    });
                    row.col(|ui| {
                        ui.label(format!("{:?}", found.class).to_lowercase());
                    });
                    row.col(|ui| {
                        ui.label(found.protection.to_string());
                    });
                    row.col(|ui| {
                        ui.label(format!(
                            "{} {}",
                            opt_hex(Some(found.region_base)),
                            human_size(found.region_size)
                        ));
                    });
                    row.col(|ui| {
                        ui.label(found.mapped_file.as_deref().unwrap_or("-"));
                    });
                    if row.response().clicked() {
                        clicked = Some(index);
                    }
                });
            });
    } else if !app.scan_task.is_running() {
        ui.label(egui::RichText::new("검색어를 입력하고 검색을 누르세요").weak());
    } else {
        ui.label(egui::RichText::new("검색 중...").weak());
    }
    if let Some(index) = clicked {
        let selected = app
            .scan_report
            .as_ref()
            .and_then(|report| report.matches.get(index))
            .cloned();
        if let Some(found) = selected {
            app.scan_state.selected_match = Some(index);
            load_preview(
                app,
                pid,
                found.address,
                found.region_base,
                found.region_size,
            );
        }
    }
    if let Some((base, text)) = app.scan_state.preview.as_ref() {
        ui.separator();
        ui.label(egui::RichText::new(format!("미리보기 {base:#018x}")).weak());
        crate::views::pane_hint(ui);
        crate::views::resizable_pane(ui, "scan_preview_pane", 280.0, 120.0, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(text).monospace());
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_dump_renders_offsets_hex_and_ascii() {
        let bytes = b"ABCD\x00\x01\x02\x03";
        let text = hex_dump(bytes, 0x1000);
        assert!(text.contains("0x0000000000001000"), "{text}");
        assert!(text.contains("41 42 43 44"), "{text}");
        assert!(text.contains("ABCD"), "{text}");
    }

    #[test]
    fn preview_range_clamps_to_region() {
        let (start, len) = preview_range(0x1000, 0x1000, 0x100);
        assert_eq!(start, 0x1000);
        assert_eq!(len, 64 + 64);
        let (start, len) = preview_range(0x1040, 0x1000, 0x50);
        assert_eq!(start, 0x1000);
        assert_eq!(len, 0x50);
    }

    #[test]
    fn build_pattern_rejects_empty_and_parses_kinds() {
        let mut state = ScanUiState::default();
        assert!(build_pattern(&state).is_err());
        state.needle = "41 42".into();
        state.kind = NeedleKind::Pattern;
        assert!(build_pattern(&state).is_ok());
        state.needle = "pwsh".into();
        state.kind = NeedleKind::Wide;
        let pattern = build_pattern(&state).unwrap();
        assert_eq!(pattern.kind, xmem_core::PatternKind::Wide);
    }
}
