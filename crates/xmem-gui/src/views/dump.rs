//! 덤프 탭.

use std::path::Path;

use xmem_core::{Finding, Result, XmemError};
use xmem_forensics::{DumpAnalysis, MinidumpSource};
use xmem_windows::{free_space_bytes, open_for_dump, process_info, write_minidump_file};

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

/// 현재 기본 출력 위치 기준 --full 사전 검사(체크박스 토글 시 1회 호출).
pub fn full_dump_warning(pid: u32) -> Option<String> {
    let info = process_info(pid).ok()?;
    let commit = info.memory_stats.as_ref().map(|s| s.commit).unwrap_or(0);
    let free = free_space_bytes(&crate::config::default_output_dir().to_string_lossy()).ok()?;
    full_dump_blocked(commit, free)
}

pub fn create_dump_file(pid: u32, output: &Path, full: bool) -> Result<u64> {
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
    write_minidump_file(&handle, pid, output, full)
}

pub fn analyze_dump_file(path: &Path) -> Result<(DumpAnalysis, Vec<Finding>)> {
    let source = MinidumpSource::open(path)?;
    let findings = xmem_detection::detect_source(&source)?;
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
                .set_directory(crate::config::default_output_dir())
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
        app.dump_full_warning = if full { full_dump_warning(pid) } else { None };
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
    if let TaskState::Failed(err) = app.dump_create_task.state() {
        ui.label(egui::RichText::new(err.to_string()).color(colors.danger));
    }
    if let Some((path, bytes)) = app.dump_created.clone() {
        ui.label(format!("생성 완료: {path} ({})", human_size(bytes)));
    }

    ui.separator();
    ui.label(egui::RichText::new("덤프 분석").strong());
    ui.horizontal(|ui| {
        ui.label("파일:");
        ui.add(
            egui::TextEdit::singleline(&mut app.dump_analyze_input)
                .desired_width(320.0)
                .hint_text("분석할 .dmp 파일 경로"),
        );
        if ui.button("열기").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("Minidump", &["dmp"])
                .pick_file()
        {
            app.dump_analyze_input = path.to_string_lossy().into_owned();
        }
    });
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.dump_analyze_task.is_running(),
                egui::Button::new("분석"),
            )
            .clicked()
        {
            app.start_dump_analyze();
        }
        if app.dump_analyze_task.is_running() {
            ui.spinner();
        }
    });
    if let TaskState::Failed(err) = app.dump_analyze_task.state() {
        ui.label(egui::RichText::new(err.to_string()).color(colors.danger));
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
        if findings.is_empty() {
            ui.label("no findings (absence of findings is not proof of safety)");
        } else {
            egui::ScrollArea::vertical()
                .max_height(160.0)
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
}
