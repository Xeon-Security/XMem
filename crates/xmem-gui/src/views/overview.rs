//! 개요 탭: 선택 프로세스의 전체 정보 + 열기 실패 배너.

use xmem_core::{ProcessArch, ProcessInfo};

use crate::app::{OpenFailure, XMemApp, classify_open_failure};
use crate::task::TaskState;

pub fn info_rows(info: &ProcessInfo) -> Vec<(String, String)> {
    fn opt<T: std::fmt::Display>(value: &Option<T>) -> String {
        value
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    }
    fn arch_text(arch: ProcessArch) -> &'static str {
        match arch {
            ProcessArch::X64 => "x64",
            ProcessArch::X86 => "x86",
            ProcessArch::Arm64 => "arm64",
            ProcessArch::Unknown => "unknown",
        }
    }
    fn mib(bytes: u64) -> String {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
    let mut rows = vec![
        ("PID".into(), info.pid.to_string()),
        ("부모 PID".into(), opt(&info.ppid)),
        ("이름".into(), info.name.clone()),
        (
            "경로".into(),
            info.image_path.clone().unwrap_or_else(|| "-".into()),
        ),
        ("아키텍처".into(), arch_text(info.arch).into()),
        ("세션".into(), opt(&info.session_id)),
        ("사용자".into(), opt(&info.user)),
        ("명령줄".into(), opt(&info.command_line)),
        ("스레드".into(), opt(&info.thread_count)),
        ("모듈".into(), opt(&info.module_count)),
    ];
    if let Some(stats) = &info.memory_stats {
        rows.push(("Working Set".into(), mib(stats.working_set)));
        rows.push(("Private".into(), mib(stats.private_bytes)));
        rows.push(("Commit".into(), mib(stats.commit)));
    }
    rows
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    if app.overview_info.is_none()
        && !app.overview_task.is_running()
        && matches!(app.overview_task.state(), TaskState::Idle)
    {
        app.start_overview(pid);
    }
    if app.overview_task.is_running() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(format!("PID {pid} 정보 조회 중..."));
        });
        return;
    }
    match app.overview_task.state() {
        TaskState::Failed(err) => {
            let failure =
                classify_open_failure(err, app.is_elevated, app.overview_task.pid().unwrap_or(pid));
            failure_banner(ui, app, &failure, |app| app.start_overview(pid));
            return;
        }
        TaskState::Cancelled => {
            ui.label(egui::RichText::new("조회가 취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    let Some(info) = app.overview_info.clone() else {
        ui.label(egui::RichText::new("정보를 불러오는 중...").weak());
        return;
    };
    ui.heading(format!("{} ({})", info.name, info.pid));
    ui.add_space(4.0);
    egui::Grid::new("overview_grid")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for (label, value) in info_rows(&info) {
                ui.label(egui::RichText::new(label).weak());
                ui.label(value);
                ui.end_row();
            }
        });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                !app.detect_task.is_running(),
                egui::Button::new("탐지 실행"),
            )
            .clicked()
        {
            app.tab = crate::app::Tab::Detect;
            app.start_detect(pid);
        }
        if ui
            .add_enabled(
                !app.snapshot_create_task.is_running(),
                egui::Button::new("스냅샷 생성"),
            )
            .clicked()
        {
            app.tab = crate::app::Tab::Snapshot;
            app.start_snapshot_create(pid);
        }
        if ui
            .add_enabled(
                !app.dump_create_task.is_running(),
                egui::Button::new("덤프 생성"),
            )
            .clicked()
        {
            app.tab = crate::app::Tab::Dump;
            app.start_dump_create(pid);
        }
        if ui
            .add_enabled(
                !app.report_task.is_running(),
                egui::Button::new("리포트 저장"),
            )
            .clicked()
        {
            app.tab = crate::app::Tab::Report;
            app.start_report_save(pid);
        }
    });
}

pub fn failure_banner(
    ui: &mut egui::Ui,
    app: &mut XMemApp,
    failure: &OpenFailure,
    retry: impl FnOnce(&mut XMemApp),
) {
    let palette = crate::theme::palette(app.theme);
    ui.label(egui::RichText::new(failure.message()).color(palette.danger));
    ui.horizontal(|ui| {
        if matches!(failure, OpenFailure::NeedsElevation) && ui.button("관리자로 재시작").clicked()
        {
            app.restart_elevated();
        }
        if ui.button("다시 시도").clicked() {
            retry(app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_rows_include_core_fields() {
        let info = ProcessInfo {
            pid: 42,
            ppid: Some(4),
            name: "sample.exe".into(),
            image_path: Some("C:\\x\\sample.exe".into()),
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: None,
            command_line: None,
            user: Some("KALPHA\\comma".into()),
            memory_stats: None,
            thread_count: Some(3),
            module_count: Some(9),
        };
        let rows = info_rows(&info);
        let find = |key: &str| rows.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        assert_eq!(find("PID"), Some("42".into()));
        assert_eq!(find("아키텍처"), Some("x64".into()));
        assert_eq!(find("부모 PID"), Some("4".into()));
        assert_eq!(find("경로"), Some("C:\\x\\sample.exe".into()));
    }
}
