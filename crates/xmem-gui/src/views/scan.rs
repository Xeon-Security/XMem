//! 검색 탭: needle 입력 + 필터 + 결과 표 + 주소 미리보기.

use xmem_core::{MemorySource, ScanPattern, XmemError};
use xmem_memory::{
    DEFAULT_CHUNK_SIZE, DEFAULT_MAX_RESULTS, LiveProcess, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    RegionFilters, ScanOptions,
};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::export::{ExportFormat, ExportPayload};
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
    pub range_start: String,
    pub range_end: String,
    pub max_region_size: String,
    pub offset: String,
    pub chunk_size: String,
    pub all: bool,
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
            range_start: String::new(),
            range_end: String::new(),
            max_region_size: String::new(),
            offset: String::new(),
            chunk_size: String::new(),
            all: false,
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

/// UI 상태를 CLI `memory scan`과 같은 의미의 옵션으로 만든다. 잘못된 텍스트는 오류.
pub fn build_options(state: &ScanUiState) -> xmem_core::Result<ScanOptions> {
    let invalid = |reason: String| XmemError::InvalidInput { reason };
    let range =
        crate::views::parse_range_text(&state.range_start, &state.range_end).map_err(invalid)?;
    let max_region_size = crate::views::parse_size_text(&state.max_region_size).map_err(invalid)?;
    let offset = crate::views::parse_u64_text(&state.offset).map_err(invalid)?;
    let chunk_size = match crate::views::parse_size_text(&state.chunk_size).map_err(invalid)? {
        Some(size) => {
            let size = size as usize;
            if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) {
                return Err(invalid(format!(
                    "청크 크기는 {MIN_CHUNK_SIZE}~{MAX_CHUNK_SIZE} 바이트",
                )));
            }
            size
        }
        None => DEFAULT_CHUNK_SIZE,
    };
    Ok(ScanOptions {
        filters: RegionFilters {
            executable_only: state.executable_only,
            private_only: state.private_only,
            writable_only: state.writable_only,
            range,
            max_region_size,
            all: state.all,
        },
        chunk_size,
        threads: state.threads.max(1),
        max_results: state.max_results.max(1),
        offset,
    })
}

fn filter_active(state: &ScanUiState) -> bool {
    state.executable_only
        || state.private_only
        || state.writable_only
        || state.all
        || !state.range_start.trim().is_empty()
        || !state.range_end.trim().is_empty()
        || !state.max_region_size.trim().is_empty()
        || !state.offset.trim().is_empty()
        || !state.chunk_size.trim().is_empty()
}

fn filter_contents(ui: &mut egui::Ui, state: &mut ScanUiState) {
    ui.checkbox(&mut state.executable_only, "실행 가능만");
    ui.checkbox(&mut state.private_only, "Private만");
    ui.checkbox(&mut state.writable_only, "쓰기 가능만");
    ui.checkbox(&mut state.all, "대형 프로세스 정책 해제")
        .on_hover_text("모든 committed 영역을 검색합니다(느림)");
    ui.horizontal(|ui| {
        ui.label("주소 범위");
        ui.add(
            egui::TextEdit::singleline(&mut state.range_start)
                .hint_text("시작")
                .desired_width(80.0),
        );
        ui.label("~");
        ui.add(
            egui::TextEdit::singleline(&mut state.range_end)
                .hint_text("끝")
                .desired_width(80.0),
        );
    });
    ui.horizontal(|ui| {
        ui.label("최대 영역 크기");
        ui.add(
            egui::TextEdit::singleline(&mut state.max_region_size)
                .hint_text("8Mi")
                .desired_width(70.0),
        );
    });
    ui.horizontal(|ui| {
        ui.label("오프셋");
        ui.add(
            egui::TextEdit::singleline(&mut state.offset)
                .hint_text("N")
                .desired_width(70.0),
        );
    });
    ui.horizontal(|ui| {
        ui.label("청크 크기");
        ui.add(
            egui::TextEdit::singleline(&mut state.chunk_size)
                .hint_text("1Mi")
                .desired_width(70.0),
        );
    });
}

/// 미리보기 바이트를 읽어 hex dump를 만든다(백그라운드 태스크에서 호출).
pub fn collect_preview(
    pid: u32,
    address: u64,
    region_base: u64,
    region_size: u64,
) -> xmem_core::Result<(u64, String)> {
    let (start, len) = preview_range(address, region_base, region_size);
    if len == 0 {
        return Err(XmemError::InvalidInput {
            reason: "미리보기 범위가 비어 있습니다".into(),
        });
    }
    let live = LiveProcess::open(pid)?;
    let mut buf = vec![0u8; len];
    match live.read(start, &mut buf) {
        Ok(outcome) if outcome.bytes_read > 0 => {
            Ok((start, hex_dump(&buf[..outcome.bytes_read], start)))
        }
        Ok(_) => Err(XmemError::InvalidInput {
            reason: "0바이트를 읽었습니다".into(),
        }),
        Err(err) => Err(err),
    }
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    let mut submit = false;
    ui.horizontal(|ui| {
        ui.label("검색어");
        let needle = ui.add(
            egui::TextEdit::singleline(&mut app.scan_state.needle)
                .hint_text("pwsh / 48 8B ?? ?? / 문자열"),
        );
        if needle.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            submit = true;
        }
        ui.label("형식");
        ui.radio_value(&mut app.scan_state.kind, NeedleKind::Pattern, "패턴(hex)");
        ui.radio_value(&mut app.scan_state.kind, NeedleKind::Ascii, "ASCII");
        ui.radio_value(&mut app.scan_state.kind, NeedleKind::Wide, "UTF-16");
    });
    ui.horizontal(|ui| {
        if !crate::views::narrow(ui) {
            ui.checkbox(&mut app.scan_state.executable_only, "실행 가능만");
            ui.checkbox(&mut app.scan_state.private_only, "Private만");
            ui.checkbox(&mut app.scan_state.writable_only, "쓰기 가능만");
            ui.separator();
        }
        ui.checkbox(&mut app.scan_state.all, "대형 프로세스 정책 해제");
        ui.separator();
        ui.label("최대 결과")
            .on_hover_text("최대 결과 수 (최대 1,000,000)");
        ui.add(
            egui::DragValue::new(&mut app.scan_state.max_results)
                .range(1..=1_000_000)
                .speed(8.0),
        );
        ui.label("스레드");
        ui.add(
            egui::DragValue::new(&mut app.scan_state.threads)
                .range(1..=64)
                .speed(0.2),
        );
        let active = filter_active(&app.scan_state);
        let state = &mut app.scan_state;
        crate::views::filter_popup(ui, "scan_filter_popup", active, |ui| {
            filter_contents(ui, state);
        });
    });
    ui.horizontal(|ui| {
        let running = app.scan_task.is_running();
        let clicked = ui
            .add_enabled(!running, egui::Button::new("검색"))
            .clicked();
        if (clicked || submit) && !running {
            app.start_scan(pid);
        }
        if running {
            ui.spinner();
            if ui.button("취소").clicked() {
                app.scan_task.cancel();
            }
        }
    });
    if let Err(err) = build_options(&app.scan_state) {
        ui.colored_label(palette(app.theme).danger, err.to_string());
    }
    if let TaskState::Failed(err) = app.scan_task.state() {
        let failure = crate::app::classify_open_failure(
            err,
            app.is_elevated,
            app.scan_task.pid().unwrap_or(pid),
        );
        failure_banner(ui, app, &failure, |app| app.start_scan(pid));
        return;
    }
    let colors = palette(app.theme);
    let mut clicked: Option<usize> = None;
    let mut export: Option<ExportFormat> = None;
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
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "{}건 · {}개 영역 검색({}개 건너뜀) · 읽기 실패 {} (denied {} / invalid {} / other {}) · {} · {}ms · rss {}",
                    report.matches.len(),
                    report.stats.regions_scanned,
                    report.stats.regions_skipped,
                    report.stats.read_failures,
                    report.stats.access_denied,
                    report.stats.invalid_address,
                    report.stats.other_failures,
                    human_size(report.stats.bytes_scanned),
                    report.stats.elapsed_ms,
                    human_size(report.stats.rss_bytes),
                ))
                .weak(),
            );
            if ui.button("JSON 내보내기").clicked() {
                export = Some(ExportFormat::Json);
            }
            if ui.button("CSV 내보내기").clicked() {
                export = Some(ExportFormat::Csv);
            }
        });
        let selected = app.scan_state.selected_match;
        crate::views::truncate_cells(ui);
        // 미리보기가 표 아래에 남아야 하므로 높이는 내용에 맞춘다.
        crate::views::wrap_hscroll_if_wide(ui, "scan_table_hscroll", 880.0, [false, true], |ui| {
            egui_extras::TableBuilder::new(ui)
                .min_scrolled_height(0.0)
                .striped(true)
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
                        let mut row_clicked = false;
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell(
                                ui,
                                egui::RichText::new(opt_hex(Some(found.address))),
                            );
                        });
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell(
                                ui,
                                egui::RichText::new(format!("{:#x}", found.offset)),
                            );
                        });
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell(
                                ui,
                                egui::RichText::new(format!("{:?}", found.class).to_lowercase()),
                            );
                        });
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell(
                                ui,
                                egui::RichText::new(found.protection.to_string()),
                            );
                        });
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell(
                                ui,
                                egui::RichText::new(format!(
                                    "{} {}",
                                    opt_hex(Some(found.region_base)),
                                    human_size(found.region_size)
                                )),
                            );
                        });
                        row.col(|ui| {
                            row_clicked |= crate::views::table_cell(
                                ui,
                                egui::RichText::new(found.mapped_file.as_deref().unwrap_or("-")),
                            );
                        });
                        if row_clicked {
                            clicked = Some(index);
                        }
                    });
                });
        });
        crate::views::wrap_default(ui);
        if let Some(format) = export {
            let payload = ExportPayload::Scan(report);
            if let Some(dir) = crate::views::export::save_with_dialog(
                pid,
                "scan",
                format,
                &payload,
                app.config.last_output_dir.clone(),
                &mut app.log,
            ) {
                app.config.last_output_dir = Some(dir);
            }
        }
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
            app.request_scan_preview(pid, found.address, found.region_base, found.region_size);
        }
    }
    if app.scan_preview_task.is_running() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(egui::RichText::new("미리보기를 불러오는 중...").weak());
        });
    }
    if let Some((base, text)) = app.scan_state.preview.as_ref() {
        ui.separator();
        ui.label(egui::RichText::new(format!("미리보기 {base:#018x}")).weak());
        crate::views::pane_hint(ui);
        crate::views::resizable_pane(ui, "scan_preview_pane", 280.0, 120.0, |ui| {
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
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

    #[test]
    fn build_options_maps_cli_equivalent_fields() {
        let state = ScanUiState {
            range_start: "0x1000".into(),
            range_end: "0x2000".into(),
            max_region_size: "8Mi".into(),
            offset: "4".into(),
            chunk_size: "64Ki".into(),
            all: true,
            executable_only: true,
            ..ScanUiState::default()
        };
        let options = build_options(&state).unwrap();
        assert_eq!(options.filters.range, Some((0x1000, 0x2000)));
        assert_eq!(options.filters.max_region_size, Some(8 * 1024 * 1024));
        assert_eq!(options.offset, Some(4));
        assert_eq!(options.chunk_size, 64 * 1024);
        assert!(options.filters.all && options.filters.executable_only);
        assert_eq!(build_options(&ScanUiState::default()).unwrap().offset, None);
    }

    #[test]
    fn build_options_rejects_bad_range_and_chunk() {
        let bad_range = ScanUiState {
            range_start: "0x2000".into(),
            range_end: "0x1000".into(),
            ..ScanUiState::default()
        };
        assert!(build_options(&bad_range).is_err());
        assert!(
            build_options(&ScanUiState {
                chunk_size: "2Ki".into(),
                ..ScanUiState::default()
            })
            .is_err(),
            "최소 4Ki 미만은 거부"
        );
        assert!(
            build_options(&ScanUiState {
                chunk_size: "32Mi".into(),
                ..ScanUiState::default()
            })
            .is_err(),
            "최대 16Mi 초과는 거부"
        );
        assert!(
            build_options(&ScanUiState {
                offset: "zz".into(),
                ..ScanUiState::default()
            })
            .is_err()
        );
    }
}
