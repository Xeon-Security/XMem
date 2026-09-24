//! 스레드 상세 패널.

use xmem_core::{MemoryRegion, MemorySource, ThreadInfo};
use xmem_memory::LiveProcess;

use crate::app::XMemApp;
use crate::error::error_label;
use crate::task::TaskState;
use crate::views::map::{human_size, opt_hex, opt_num};
use crate::views::scan::hex_dump;

pub const PREVIEW_BYTES: usize = 64;

pub struct ThreadDetail {
    pub thread: ThreadInfo,
    pub start_region: Option<MemoryRegion>,
    pub times: Option<xmem_windows::ThreadTimes>,
    pub times_error: Option<String>,
    pub preview: Option<(u64, String)>,
    pub preview_error: Option<String>,
    pub notes: Vec<String>,
}

/// Windows 스레드 우선순위 라벨.
pub fn priority_label(priority: i32) -> &'static str {
    match priority {
        15 => "TIME_CRITICAL",
        2 => "HIGHEST",
        1 => "ABOVE_NORMAL",
        0 => "NORMAL",
        -1 => "BELOW_NORMAL",
        -2 => "LOWEST",
        -15 => "IDLE",
        _ => "기타",
    }
}

/// 100ns 단위 CPU 시간을 사람이 읽는 문구로.
pub fn duration_text(ticks_100ns: u64) -> String {
    let ms = ticks_100ns / 10_000;
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.2} s", ms as f64 / 1000.0)
    }
}

/// FILETIME(100ns since 1601)을 UTC 문구로. 0이면 "-".
pub fn filetime_text(filetime: u64) -> String {
    if filetime == 0 {
        return "-".to_string();
    }
    let secs = (filetime / 10_000_000) as i64 - 11_644_473_600;
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{secs} (unix)"),
    }
}

pub fn thread_summary_text(detail: &ThreadDetail) -> String {
    let thread = &detail.thread;
    let mut text = String::new();
    text.push_str(&format!("thread {}\n", thread.tid));
    text.push_str(&format!("  pid {}\n", thread.pid));
    text.push_str(&format!("  priority {}\n", opt_num(thread.priority)));
    if let Some(priority) = thread.priority {
        text.push_str(&format!("  priority label {}\n", priority_label(priority)));
    }
    text.push_str(&format!(
        "  start address {}\n",
        opt_hex(thread.start_address)
    ));
    text.push_str(&format!(
        "  start region {}\n",
        opt_hex(thread.start_region_base)
    ));
    text.push_str(&format!(
        "  start module {}\n",
        thread.start_module.as_deref().unwrap_or("-")
    ));
    match detail.times.as_ref() {
        Some(times) => {
            text.push_str(&format!("  created {}\n", filetime_text(times.creation)));
            text.push_str(&format!(
                "  exited {}\n",
                if times.exit == 0 {
                    "실행 중".to_string()
                } else {
                    filetime_text(times.exit)
                }
            ));
            text.push_str(&format!("  kernel {}\n", duration_text(times.kernel_100ns)));
            text.push_str(&format!("  user {}\n", duration_text(times.user_100ns)));
        }
        None => {
            if let Some(error) = detail.times_error.as_deref() {
                text.push_str(&format!("  times error {error}\n"));
            }
        }
    }
    if let Some((address, dump)) = detail.preview.as_ref() {
        text.push_str(&format!("  preview at {address:#x}\n{dump}"));
    } else if let Some(error) = detail.preview_error.as_deref() {
        text.push_str(&format!("  preview error {error}\n"));
    }
    text
}

/// 스레드 상세 수집. 실패는 각 항목의 오류 문구로 남기고 계속한다.
pub fn collect_thread_detail(pid: u32, thread: ThreadInfo) -> ThreadDetail {
    let mut notes = Vec::new();
    let mut start_region = None;
    let mut times = None;
    let mut times_error = None;
    let mut preview = None;
    let mut preview_error = None;

    match LiveProcess::open(pid) {
        Ok(live) => {
            let lookup = thread.start_address.or(thread.start_region_base);
            if let Some(address) = lookup {
                match live.region_map() {
                    Ok(map) => {
                        start_region = map.regions.into_iter().find(|region| {
                            address >= region.base
                                && address < region.base.saturating_add(region.size)
                        });
                    }
                    Err(err) => notes.push(format!("메모리 맵 조회 실패: {}", error_label(&err))),
                }
            }
            match thread.start_address {
                Some(address) => {
                    let mut buf = vec![0u8; PREVIEW_BYTES];
                    match live.read(address, &mut buf) {
                        Ok(outcome) if outcome.bytes_read > 0 => {
                            preview =
                                Some((address, hex_dump(&buf[..outcome.bytes_read], address)));
                        }
                        Ok(_) => {
                            preview_error = Some("시작 주소에서 0 바이트를 읽었습니다".to_string());
                        }
                        Err(err) => preview_error = Some(error_label(&err)),
                    }
                }
                None => {
                    preview_error = Some("시작 주소를 조회하지 못했습니다".to_string());
                    notes.push(
                        "시작 주소가 없어 이 스레드는 XMEM-004 판정에서 제외됩니다".to_string(),
                    );
                }
            }
        }
        Err(err) => notes.push(format!("프로세스 열기 실패: {}", error_label(&err))),
    }

    match xmem_windows::open_thread_for_query(thread.tid) {
        Ok(handle) => match xmem_windows::thread_times(&handle) {
            Ok(value) => times = Some(value),
            Err(err) => times_error = Some(error_label(&err)),
        },
        Err(err) => times_error = Some(error_label(&err)),
    }

    ThreadDetail {
        thread,
        start_region,
        times,
        times_error,
        preview,
        preview_error,
        notes,
    }
}

pub fn panel(ui: &mut egui::Ui, app: &mut XMemApp) {
    let colors = crate::theme::palette(app.theme);
    match app.thread_detail_task.state() {
        TaskState::Running => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("스레드 상세를 불러오는 중...");
            });
            return;
        }
        TaskState::Failed(err) => {
            ui.label(
                egui::RichText::new(format!("스레드 상세 실패: {}", error_label(err)))
                    .color(colors.danger),
            );
            return;
        }
        _ => {}
    }
    let Some(detail) = app.thread_detail.as_ref() else {
        ui.label(egui::RichText::new("스레드를 클릭하면 상세 정보가 표시됩니다").weak());
        return;
    };
    let pid = app.selected_pid;
    let thread = detail.thread.clone();
    let start_region = detail.start_region.clone();

    let mut close = false;
    let mut copy: Option<String> = None;
    let mut goto_map = false;
    ui.horizontal(|ui| {
        ui.strong(format!("TID {}", thread.tid));
        ui.label(
            egui::RichText::new(format!(
                "{} · {} · {}",
                thread
                    .priority
                    .map(|priority| format!("우선순위 {priority} ({})", priority_label(priority)))
                    .unwrap_or_else(|| "우선순위 -".to_string()),
                opt_hex(thread.start_address),
                thread.start_module.as_deref().unwrap_or("-")
            ))
            .weak(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("닫기").clicked() {
                close = true;
            }
            if ui.button("맵에서 보기").clicked() {
                goto_map = true;
            }
            if ui.button("요약 복사").clicked() {
                copy = Some(thread_summary_text(detail));
            }
        });
    });
    for note in &detail.notes {
        ui.label(egui::RichText::new(note).color(colors.warn));
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("thread_detail_scroll")
        .show(ui, |ui| {
            egui::CollapsingHeader::new("식별")
                .default_open(true)
                .show(ui, |ui| {
                    egui::Grid::new("thread_ident_grid")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for (key, value) in [
                                ("TID", thread.tid.to_string()),
                                ("PID", thread.pid.to_string()),
                                ("우선순위", opt_num(thread.priority)),
                                (
                                    "우선순위 라벨",
                                    thread
                                        .priority
                                        .map(priority_label)
                                        .unwrap_or("-")
                                        .to_string(),
                                ),
                                ("시작 주소", opt_hex(thread.start_address)),
                                ("시작 영역", opt_hex(thread.start_region_base)),
                                (
                                    "시작 모듈",
                                    thread.start_module.clone().unwrap_or_else(|| "-".into()),
                                ),
                            ] {
                                ui.label(egui::RichText::new(key).weak());
                                ui.label(value);
                                ui.end_row();
                            }
                        });
                });
            egui::CollapsingHeader::new("스레드 시간")
                .default_open(true)
                .show(ui, |ui| match detail.times.as_ref() {
                    Some(times) => {
                        egui::Grid::new("thread_times_grid")
                            .num_columns(2)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                for (key, value) in [
                                    ("생성 시각", filetime_text(times.creation)),
                                    (
                                        "종료 시각",
                                        if times.exit == 0 {
                                            "실행 중".to_string()
                                        } else {
                                            filetime_text(times.exit)
                                        },
                                    ),
                                    ("커널 시간", duration_text(times.kernel_100ns)),
                                    ("사용자 시간", duration_text(times.user_100ns)),
                                ] {
                                    ui.label(egui::RichText::new(key).weak());
                                    ui.label(value);
                                    ui.end_row();
                                }
                            });
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                detail
                                    .times_error
                                    .as_deref()
                                    .unwrap_or("스레드 시간을 얻지 못했습니다"),
                            )
                            .color(colors.danger),
                        );
                    }
                });
            egui::CollapsingHeader::new(format!("시작 주소 미리보기 ({PREVIEW_BYTES} 바이트)"))
                .default_open(true)
                .show(ui, |ui| match detail.preview.as_ref() {
                    Some((_, dump)) => {
                        crate::views::pane_hint(ui);
                        crate::views::resizable_pane(ui, "thread_hex_pane", 220.0, 120.0, |ui| {
                            egui::ScrollArea::both()
                                .auto_shrink([false, false])
                                .id_salt("thread_hex")
                                .show(ui, |ui| {
                                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                                    ui.label(egui::RichText::new(dump).monospace());
                                });
                        });
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                detail
                                    .preview_error
                                    .as_deref()
                                    .unwrap_or("미리보기를 읽지 못했습니다"),
                            )
                            .color(colors.danger),
                        );
                    }
                });
            egui::CollapsingHeader::new("시작 영역")
                .default_open(true)
                .show(ui, |ui| match detail.start_region.as_ref() {
                    Some(region) => {
                        ui.label(
                            egui::RichText::new(crate::views::region::summary_text(
                                region,
                                thread.start_module.as_deref(),
                            ))
                            .monospace(),
                        );
                        ui.label(
                            egui::RichText::new(format!("크기 {}", human_size(region.size))).weak(),
                        );
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(
                                "시작 주소를 포함하는 메모리 영역을 찾지 못했습니다",
                            )
                            .weak(),
                        );
                    }
                });
        });

    if close {
        app.thread_selected = None;
        app.thread_detail = None;
    }
    if let Some(text) = copy {
        ui.ctx().copy_text(text);
        app.log.push(
            crate::log::LogLevel::Info,
            "스레드 요약을 클립보드에 복사했습니다",
        );
    }
    if goto_map && let Some(pid) = pid {
        match start_region {
            Some(region) => {
                app.tab = crate::app::Tab::Map;
                app.select_region(pid, region);
            }
            None => {
                if app.map.is_none() {
                    app.start_map(pid);
                    app.log.push(
                        crate::log::LogLevel::Warn,
                        "맵을 불러오는 중입니다. 잠시 후 다시 시도하세요",
                    );
                } else {
                    app.log.push(
                        crate::log::LogLevel::Warn,
                        "이 스레드의 시작 영역을 맵에서 찾지 못했습니다",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_thread(start_address: Option<u64>) -> ThreadInfo {
        ThreadInfo {
            tid: 4242,
            pid: 777,
            priority: Some(2),
            start_address,
            start_region_base: Some(0x0001_4000_0000),
            start_module: Some("sample.dll".into()),
        }
    }

    #[test]
    fn priority_labels_cover_windows_values() {
        assert_eq!(priority_label(15), "TIME_CRITICAL");
        assert_eq!(priority_label(2), "HIGHEST");
        assert_eq!(priority_label(0), "NORMAL");
        assert_eq!(priority_label(-15), "IDLE");
        assert_eq!(priority_label(99), "기타");
    }

    #[test]
    fn duration_text_units() {
        assert_eq!(duration_text(0), "0 ms");
        assert_eq!(duration_text(20_000), "2 ms");
        assert_eq!(duration_text(10_000_000), "1.00 s");
        assert_eq!(duration_text(12_345_000), "1.23 s");
    }

    #[test]
    fn filetime_text_formats_utc() {
        assert_eq!(filetime_text(0), "-");
        assert_eq!(
            filetime_text(133_485_408_000_000_000),
            "2024-01-01 00:00:00 UTC"
        );
    }

    #[test]
    fn collect_reports_open_failure_for_bogus_pid() {
        let detail = collect_thread_detail(0xFFFF_FFFE, sample_thread(Some(0x1000)));
        assert!(
            detail
                .notes
                .iter()
                .any(|note| note.contains("프로세스 열기 실패")),
            "notes: {:?}",
            detail.notes
        );
    }

    #[test]
    fn summary_text_includes_identity_and_errors() {
        let mut detail = collect_thread_detail(0xFFFF_FFFE, sample_thread(None));
        detail.times_error = Some("접근 거부 (AccessDenied): denied".into());
        detail.preview_error = Some("시작 주소를 조회하지 못했습니다".into());
        let text = thread_summary_text(&detail);
        assert!(text.contains("thread 4242"));
        assert!(text.contains("sample.dll"));
        assert!(text.contains("AccessDenied"));
        assert!(text.contains("XMEM-004") || text.contains("시작 주소"));
    }
}
