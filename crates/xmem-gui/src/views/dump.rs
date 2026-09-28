//! 덤프 탭.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use xmem_core::{Finding, Result, XmemError};
use xmem_forensics::{DumpAnalysis, MinidumpSource};
use xmem_windows::{
    DumpProgress, free_space_bytes, open_for_dump, process_info, write_minidump_file,
    write_minidump_file_with_progress,
};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::{palette, severity_color, severity_label};
use crate::views::map::human_size;

pub const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

/// --full 시작 전 검사: 부족하면 차단 사유 문자열.
pub fn full_dump_blocked(commit_bytes: u64, free_bytes: u64) -> Option<String> {
    let needed = commit_bytes.saturating_add(DISK_MARGIN_BYTES);
    if free_bytes < needed {
        Some(format!(
            "전체 메모리 덤프에는 약 {} 필요(가용 {}). 디스크 공간이 부족합니다",
            human_size(needed),
            human_size(free_bytes)
        ))
    } else {
        None
    }
}

/// 지정한 출력 디렉터리 기준 --full 사전 검사.
pub fn full_dump_warning(pid: u32, output_dir: &Path) -> Option<String> {
    let info = process_info(pid).ok()?;
    let commit = info.memory_stats.as_ref().map(|s| s.commit).unwrap_or(0);
    let free = free_space_bytes(&output_dir.to_string_lossy()).ok()?;
    full_dump_blocked(commit, free)
}

/// 출력 경로에서 검사에 쓸 디렉터리를 고른다(비어 있으면 기본 출력 위치).
fn output_dir(app: &XMemApp) -> std::path::PathBuf {
    let trimmed = app.dump_output.trim();
    if trimmed.is_empty() {
        return crate::config::default_output_dir();
    }
    std::path::PathBuf::from(trimmed)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(crate::config::default_output_dir)
}

pub fn create_dump_file(
    pid: u32,
    output: &Path,
    full: bool,
    progress: Option<&DumpProgress>,
) -> Result<u64> {
    // 존재하지 않는 PID를 ProcessExited로 보고하기 위해 process_info를 먼저 호출한다.
    let info = process_info(pid)?;
    let handle = open_for_dump(pid)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let needed = if full {
        info.memory_stats.as_ref().map(|s| s.commit).unwrap_or(0)
    } else {
        0
    };
    let free = free_space_bytes(&parent.to_string_lossy())?;
    if free < needed.saturating_add(DISK_MARGIN_BYTES) {
        return Err(XmemError::DumpError {
            reason: format!(
                "디스크 공간 부족: 필요 {} + 여유 {}, 가용 {} ({})",
                human_size(needed),
                human_size(DISK_MARGIN_BYTES),
                human_size(free),
                parent.display()
            ),
        });
    }
    match progress {
        Some(progress) => write_minidump_file_with_progress(&handle, pid, output, full, progress),
        None => write_minidump_file(&handle, pid, output, full),
    }
}

/// 진행바 옆 라벨. 예상 크기를 모르면 기록 바이트만 보여준다.
pub fn dump_progress_text(progress: &DumpProgress) -> String {
    let written = human_size(progress.bytes_written());
    match progress.estimated_total() {
        0 => format!("기록 {written} (예상 크기 미상)"),
        total => format!("기록 {written} / 예상 {}", human_size(total)),
    }
}

/// 덤프에 모듈 정보가 없을 때만 표시할 안내 문구.
pub fn missing_modules_note(module_count: usize) -> Option<&'static str> {
    (module_count == 0)
        .then_some("모듈 목록 없음 — 미니덤프에 모듈 정보가 없어 모듈 상세를 표시할 수 없습니다")
}

pub fn analyze_dump_file(path: &Path, cancel: &AtomicBool) -> Result<(DumpAnalysis, Vec<Finding>)> {
    let source = MinidumpSource::open(path)?;
    crate::task::ensure_not_cancelled(cancel)?;
    let findings = xmem_detection::detect_source(&source)?;
    crate::task::ensure_not_cancelled(cancel)?;
    Ok((source.analysis(), findings))
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    let colors = palette(app.theme);
    ui.heading("덤프");
    ui.label(
        egui::RichText::new(
            "MiniDumpWriteDump로 미니덤프를 생성하거나, 덤프 파일을 오프라인으로 분석합니다.",
        )
        .weak(),
    );
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("출력:");
        ui.add(
            egui::TextEdit::singleline(&mut app.dump_output)
                .desired_width(320.0)
                .hint_text("비우면 Documents\\XMem 아래 기본 이름"),
        );
        if ui.button("찾아보기").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .set_file_name(crate::config::output_file_name(
                    "dump",
                    pid,
                    "dmp",
                    chrono::Local::now(),
                ))
                .set_directory(
                    app.config
                        .last_output_dir
                        .clone()
                        .unwrap_or_else(crate::config::default_output_dir),
                )
                .add_filter("Minidump", &["dmp"])
                .save_file()
        {
            app.dump_output = path.to_string_lossy().into_owned();
        }
    });
    let mut full = app.dump_full;
    if ui
        .checkbox(&mut full, "전체 메모리 포함 (--full, 크고 느림)")
        .changed()
    {
        app.dump_full = full;
    }
    let warning_dir = output_dir(app);
    // 매 프레임 process_info/free_space를 호출하지 않는다 — 체크박스/출력 경로가
    // 바뀔 때만 다시 계산한다(M8).
    let warning_key = (pid, app.dump_full, warning_dir.clone());
    if app.dump_full_warning_key.as_ref() != Some(&warning_key) {
        app.dump_full_warning_key = Some(warning_key);
        app.dump_full_warning = if app.dump_full {
            full_dump_warning(pid, &warning_dir)
        } else {
            None
        };
    }
    if let Some(warning) = app.dump_full_warning.clone() {
        ui.label(egui::RichText::new(warning).color(colors.danger));
    }
    let blocked = app.dump_full && app.dump_full_warning.is_some();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.dump_create_task.is_running() && !blocked,
                egui::Button::new("덤프 생성"),
            )
            .clicked()
        {
            app.start_dump_create(pid);
        }
        if app.dump_create_task.is_running() {
            ui.spinner();
            ui.label(
                egui::RichText::new("취소할 수 없습니다. 완료까지 기다려 주세요")
                    .color(colors.warn),
            );
        }
    });
    if app.dump_create_task.is_running()
        && let Some(progress) = app.dump_progress.as_ref()
    {
        ui.horizontal(|ui| {
            match progress.fraction() {
                Some(fraction) => {
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .desired_width(240.0)
                            .show_percentage(),
                    );
                }
                None => {
                    ui.spinner();
                }
            }
            ui.label(egui::RichText::new(dump_progress_text(progress)).weak());
        });
    }
    if let TaskState::Failed(err) = app.dump_create_task.state() {
        ui.label(egui::RichText::new(err.to_string()).color(colors.danger));
    }
    if let Some((path, bytes)) = app.dump_created.clone() {
        ui.label(format!("생성 완료: {path} ({})", human_size(bytes)));
    }

    ui.separator();
    ui.label(egui::RichText::new("덤프 분석").strong());
    let mut analyze_submit = false;
    ui.horizontal(|ui| {
        ui.label("파일:");
        let input = ui.add(
            egui::TextEdit::singleline(&mut app.dump_analyze_input)
                .desired_width(320.0)
                .hint_text("분석할 .dmp 파일 경로"),
        );
        if input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            analyze_submit = true;
        }
        if ui.button("열기").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("Minidump", &["dmp"])
                .pick_file()
        {
            app.dump_analyze_input = path.to_string_lossy().into_owned();
        }
    });
    ui.horizontal(|ui| {
        let running = app.dump_analyze_task.is_running();
        let clicked = ui
            .add_enabled(!running, egui::Button::new("분석"))
            .clicked();
        if (clicked || analyze_submit) && !running {
            app.start_dump_analyze();
        }
        if running {
            ui.spinner();
            if ui.button("취소").clicked() {
                app.dump_analyze_task.cancel();
            }
        }
    });
    match app.dump_analyze_task.state() {
        TaskState::Failed(err) => {
            ui.label(egui::RichText::new(err.to_string()).color(colors.danger));
        }
        TaskState::Cancelled => {
            ui.label(egui::RichText::new("취소되었습니다").weak());
        }
        _ => {}
    }
    if let Some((path, analysis, findings)) = app.dump_analysis.as_ref() {
        ui.label(
            egui::RichText::new(format!(
                "{path} · os {} · cpu {} · regions {} · modules {} · threads {} · ranges {} ({}) · findings {}",
                analysis.os,
                analysis.cpu,
                analysis.regions.len(),
                analysis.modules.len(),
                analysis.threads.len(),
                analysis.memory_ranges,
                human_size(analysis.memory_bytes),
                findings.len(),
            ))
            .weak(),
        );
        if let Some(note) = missing_modules_note(analysis.modules.len()) {
            ui.label(egui::RichText::new(note).color(colors.warn));
        }
        if findings.is_empty() {
            ui.label("no findings (absence of findings is not proof of safety)");
        } else {
            crate::views::pane_hint(ui);
            crate::views::resizable_pane(ui, "dump_findings_pane", 220.0, 120.0, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for finding in findings {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new(severity_label(finding.severity))
                                        .color(severity_color(finding.severity, &colors)),
                                );
                                ui.label(format!("{} {}", finding.rule_id, finding.name));
                            });
                        }
                    });
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_dump_blocks_when_disk_is_tight() {
        assert!(full_dump_blocked(100 * 1024 * 1024, 50 * 1024 * 1024).is_some());
        assert!(full_dump_blocked(100 * 1024 * 1024, 200 * 1024 * 1024).is_none());
    }

    #[test]
    fn dump_progress_text_shows_written_and_estimate() {
        let unknown = DumpProgress::new(0);
        let text = dump_progress_text(&unknown);
        assert!(text.contains("기록 0 B"), "{text}");
        assert!(text.contains("예상 크기 미상"), "{text}");

        let estimated = DumpProgress::new(1024);
        assert_eq!(estimated.fraction(), Some(0.0));
        let text = dump_progress_text(&estimated);
        assert!(text.contains("기록 0 B"), "{text}");
        assert!(text.contains("예상 1.0 KiB"), "{text}");
    }

    #[test]
    fn missing_modules_note_only_when_empty() {
        let note = missing_modules_note(0).expect("모듈 0개 안내가 있어야 함");
        assert!(note.contains("모듈 목록 없음"), "{note}");
        assert!(missing_modules_note(1).is_none());
    }
}
