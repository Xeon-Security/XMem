//! 좌측 프로세스 목록 패널.

use std::collections::HashSet;

use xmem_core::{ProcessArch, ProcessFilter, ProcessInfo};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::palette;

/// GUI 검색어(이름 부분일치 또는 PID 정확 일치)와 core 필터를 함께 적용한다.
/// CLI `--name`과 달리 GUI 검색창은 기존처럼 PID도 받는다.
pub fn filter_processes_core(
    list: &[ProcessInfo],
    query: &str,
    accessible: &HashSet<u32>,
    filter: &ProcessFilter,
) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    list.iter()
        .enumerate()
        .filter(|(_, info)| {
            (query.is_empty()
                || info.name.to_lowercase().contains(&query)
                || info.pid.to_string() == query)
                && filter.matches(info, accessible.contains(&info.pid))
        })
        .map(|(index, _)| index)
        .collect()
}

/// 아키텍처 필터 콤보 표시 문구.
fn arch_filter_label(filter: Option<ProcessArch>) -> &'static str {
    match filter {
        None => "아키텍처: 전체",
        Some(ProcessArch::X64) => "아키텍처: x64",
        Some(ProcessArch::X86) => "아키텍처: x86",
        Some(ProcessArch::Arm64) => "아키텍처: arm64",
        Some(ProcessArch::Unknown) => "아키텍처: 기타",
    }
}

fn arch_options() -> [(Option<ProcessArch>, &'static str); 4] {
    [
        (None, "전체"),
        (Some(ProcessArch::X64), "x64"),
        (Some(ProcessArch::X86), "x86"),
        (Some(ProcessArch::Arm64), "arm64"),
    ]
}

fn arch_menu(ui: &mut egui::Ui, filter: &mut Option<ProcessArch>) {
    crate::views::choice_menu(ui, arch_filter_label(*filter), &arch_options(), filter);
}

/// app 상태에서 core 필터를 만든다. 검색어는 `filter_processes_core`가 따로 처리한다.
fn core_filter(app: &XMemApp) -> ProcessFilter {
    ProcessFilter {
        accessible_only: app.process_accessible_only,
        name_contains: None,
        arch: app.process_arch_filter,
        session: crate::views::parse_u32_text(&app.process_session_filter).unwrap_or(None),
        user_contains: Some(app.process_user_filter.trim().to_string())
            .filter(|user| !user.is_empty()),
        protected_only: app.process_protected_only,
        parent_pid: crate::views::parse_u32_text(&app.process_ppid_filter).unwrap_or(None),
    }
}

fn filter_count(
    accessible_only: bool,
    arch: Option<ProcessArch>,
    session: &str,
    user: &str,
    protected_only: bool,
    parent_pid: &str,
) -> usize {
    [
        accessible_only,
        arch.is_some(),
        !session.trim().is_empty(),
        !user.trim().is_empty(),
        protected_only,
        !parent_pid.trim().is_empty(),
    ]
    .into_iter()
    .filter(|set| *set)
    .count()
}

/// 현재 앱 상태의 필터 활성 개수(팝업 버튼 툴팁/표시용).
fn app_filter_count(app: &XMemApp) -> usize {
    filter_count(
        app.process_accessible_only,
        app.process_arch_filter,
        &app.process_session_filter,
        &app.process_user_filter,
        app.process_protected_only,
        &app.process_ppid_filter,
    )
}

fn reset_filter(
    accessible_only: &mut bool,
    arch: &mut Option<ProcessArch>,
    session: &mut String,
    user: &mut String,
    protected_only: &mut bool,
    parent_pid: &mut String,
) {
    *accessible_only = false;
    *arch = None;
    session.clear();
    user.clear();
    *protected_only = false;
    parent_pid.clear();
}

fn filter_errors(app: &XMemApp) -> Vec<String> {
    [&app.process_session_filter, &app.process_ppid_filter]
        .into_iter()
        .filter(|text| !text.trim().is_empty())
        .filter_map(|text| crate::views::parse_u32_text(text).err())
        .collect()
}

fn filter_contents(ui: &mut egui::Ui, app: &mut XMemApp) {
    ui.checkbox(&mut app.process_accessible_only, "접근 가능만 보기");
    arch_menu(ui, &mut app.process_arch_filter);
    ui.horizontal(|ui| {
        ui.label("세션");
        ui.add(
            egui::TextEdit::singleline(&mut app.process_session_filter)
                .hint_text("숫자")
                .desired_width(60.0),
        );
    });
    ui.horizontal(|ui| {
        ui.label("사용자");
        ui.add(
            egui::TextEdit::singleline(&mut app.process_user_filter)
                .hint_text("부분일치")
                .desired_width(120.0),
        );
    });
    ui.checkbox(
        &mut app.process_protected_only,
        "중요 프로세스만(이름 목록)",
    )
    .on_hover_text(format!(
        "가드 이름 목록 기준(이름만 비교, PPL 보호 비트와 무관): {}",
        xmem_core::guard::PROTECTED_PROCESS_NAMES.join(", ")
    ));
    ui.horizontal(|ui| {
        ui.label("부모 PID");
        ui.add(
            egui::TextEdit::singleline(&mut app.process_ppid_filter)
                .hint_text("숫자")
                .desired_width(60.0),
        );
    });
    let danger = palette(app.theme).danger;
    for err in filter_errors(app) {
        ui.colored_label(danger, err);
    }
    crate::views::filter_reset_button(ui, || {
        reset_filter(
            &mut app.process_accessible_only,
            &mut app.process_arch_filter,
            &mut app.process_session_filter,
            &mut app.process_user_filter,
            &mut app.process_protected_only,
            &mut app.process_ppid_filter,
        );
    });
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    ui.horizontal(|ui| {
        ui.label("프로세스");
        if ui
            .add_enabled(
                !app.list_task.is_running(),
                egui::Button::new("새로고침").small(),
            )
            .clicked()
        {
            app.refresh_processes();
        }
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
    let list_failure = match app.list_task.state() {
        TaskState::Failed(err) => Some(crate::error::error_label(err)),
        _ => None,
    };
    // 목록 로드가 실패해도 검색/필터 UI는 유지한다 — 필터가 숨겨져 비어 보이는 것을 막는다.
    ui.add(
        egui::TextEdit::singleline(&mut app.process_filter)
            .hint_text("이름 또는 PID 검색")
            .desired_width(f32::INFINITY),
    );
    ui.horizontal(|ui| {
        ui.checkbox(&mut app.process_accessible_only, "접근 가능만 보기");
        arch_menu(ui, &mut app.process_arch_filter);
        crate::views::filter_popup(ui, "process_filter_popup", app_filter_count(app), |ui| {
            filter_contents(ui, app);
        });
    });
    for err in filter_errors(app) {
        ui.colored_label(palette(app.theme).danger, err);
    }
    if let Some(message) = list_failure {
        ui.label(egui::RichText::new(message).color(crate::theme::palette(app.theme).danger));
        if ui.button("다시 시도").clicked() {
            app.refresh_processes();
        }
        return;
    }
    let filtered = filter_processes_core(
        &app.processes,
        &app.process_filter,
        &app.list_accessible,
        &core_filter(app),
    );
    ui.label(
        egui::RichText::new(format!(
            "{}개 / 전체 {}개",
            filtered.len(),
            app.processes.len()
        ))
        .weak(),
    );
    if filtered.is_empty() {
        ui.label(
            egui::RichText::new(
                "필터에 맞는 프로세스가 없습니다 — 검색어를 지우거나 필터 팝업에서 [필터 초기화]를 누르세요",
            )
            .color(palette(app.theme).muted),
        );
        return;
    }
    ui.separator();
    let row_height = 20.0;
    crate::views::truncate_cells(ui);
    egui_extras::TableBuilder::new(ui)
        .min_scrolled_height(0.0)
        .striped(true)
        .sense(egui::Sense::click())
        .column(egui_extras::Column::exact(56.0))
        .column(egui_extras::Column::exact(64.0))
        .column(egui_extras::Column::initial(150.0).clip(true))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            header.col(|ui| {
                ui.strong("PID");
            });
            header.col(|ui| {
                ui.strong("접근");
            });
            header.col(|ui| {
                ui.strong("이름");
            });
            header.col(|ui| {
                ui.strong("경로");
            });
        })
        .body(|body| {
            body.rows(row_height, filtered.len(), |mut row| {
                let index = filtered[row.index()];
                let pid = app.processes[index].pid;
                row.set_selected(app.selected_pid == Some(pid));
                let mut row_clicked = false;
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell_focusable(
                        ui,
                        egui::RichText::new(pid.to_string()),
                    );
                });
                row.col(|ui| {
                    let accessible = app.list_accessible.contains(&pid);
                    let text = if accessible {
                        "가능"
                    } else {
                        "권한 필요"
                    };
                    let rich = if accessible {
                        egui::RichText::new(text)
                    } else {
                        egui::RichText::new(text).color(crate::theme::palette(app.theme).warn)
                    };
                    row_clicked |= crate::views::table_cell(ui, rich);
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(app.processes[index].name.as_str()),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(
                            app.processes[index].image_path.as_deref().unwrap_or("-"),
                        )
                        .weak(),
                    );
                });
                if row_clicked {
                    app.select_process(pid);
                }
            });
        });
}

/// 좁은 창(<900px)에서 쓰는 프로세스 드롭다운.
pub fn dropdown(ui: &mut egui::Ui, app: &mut XMemApp) {
    // 좁은 레이아웃에서도 필터를 보이게 한다 — 숨은 필터 때문에 목록이 비어 보이는 것을 막는다.
    ui.add(
        egui::TextEdit::singleline(&mut app.process_filter)
            .hint_text("이름 또는 PID 검색")
            .desired_width(f32::INFINITY),
    );
    let selected_text = app
        .selected_pid
        .and_then(|pid| app.processes.iter().find(|p| p.pid == pid))
        .map(|p| format!("{} ({})", p.name, p.pid))
        .unwrap_or_else(|| "프로세스 선택".into());
    let filtered = filter_processes_core(
        &app.processes,
        &app.process_filter,
        &app.list_accessible,
        &core_filter(app),
    );
    let filtered_count = filtered.len();
    ui.horizontal(|ui| {
        ui.label("프로세스");
        egui::ComboBox::from_id_salt("process_dropdown")
            .selected_text(selected_text)
            .show_ui(ui, |ui| {
                let filtered_len = filtered_count;
                for index in filtered.into_iter().take(200) {
                    let (name, pid) = (app.processes[index].name.clone(), app.processes[index].pid);
                    let selected = app.selected_pid == Some(pid);
                    if ui
                        .selectable_label(selected, format!("{name} ({pid})"))
                        .clicked()
                    {
                        app.select_process(pid);
                    }
                }
                if filtered_len > 200 {
                    ui.label(egui::RichText::new("상위 200개만 표시 (필터를 사용하세요)").weak());
                }
                if filtered_len == 0 {
                    ui.label(egui::RichText::new("필터에 맞는 프로세스가 없습니다").weak());
                }
            });
        // 좁은 레이아웃에도 같은 필터를 미러링한다.
        crate::views::filter_popup(
            ui,
            "process_dropdown_filter_popup",
            app_filter_count(app),
            |ui| {
                filter_contents(ui, app);
            },
        );
        if ui
            .add_enabled(
                !app.list_task.is_running(),
                egui::Button::new("새로고침").small(),
            )
            .clicked()
        {
            app.refresh_processes();
        }
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
    ui.label(
        egui::RichText::new(format!(
            "{}개 / 전체 {}개",
            filtered_count,
            app.processes.len()
        ))
        .weak(),
    );
    if filtered_count == 0 && !app.processes.is_empty() {
        ui.label(
            egui::RichText::new(
                "필터에 맞는 프로세스가 없습니다 — 검색어를 지우거나 필터 팝업에서 [필터 초기화]를 누르세요",
            )
            .color(palette(app.theme).muted),
        );
    }
    for err in filter_errors(app) {
        ui.colored_label(palette(app.theme).danger, err);
    }
    let list_failure = match app.list_task.state() {
        TaskState::Failed(err) => Some(crate::error::error_label(err)),
        _ => None,
    };
    if let Some(message) = list_failure {
        ui.label(egui::RichText::new(message).color(crate::theme::palette(app.theme).danger));
        if ui.button("다시 시도").clicked() {
            app.refresh_processes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: None,
            name: name.to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    /// 접근성/아키텍처만 지정한 core 필터로 기존 동작을 검증한다.
    fn filter_simple(
        list: &[ProcessInfo],
        query: &str,
        accessible: &HashSet<u32>,
        accessible_only: bool,
        arch_filter: Option<ProcessArch>,
    ) -> Vec<usize> {
        filter_processes_core(
            list,
            query,
            accessible,
            &ProcessFilter {
                accessible_only,
                arch: arch_filter,
                ..ProcessFilter::default()
            },
        )
    }

    #[test]
    fn filter_matches_name_case_insensitive_and_pid() {
        let list = vec![sample(10, "pwsh.exe"), sample(20, "explorer.exe")];
        let none = HashSet::new();
        assert_eq!(filter_simple(&list, "PWSH", &none, false, None), vec![0]);
        assert_eq!(
            filter_simple(&list, "explorer", &none, false, None),
            vec![1]
        );
        assert_eq!(filter_simple(&list, "20", &none, false, None), vec![1]);
        assert_eq!(filter_simple(&list, "", &none, false, None), vec![0, 1]);
        assert!(filter_simple(&list, "없는이름", &none, false, None).is_empty());
    }

    #[test]
    fn filter_processes_applies_access_and_arch_filters() {
        let mut x86 = sample(20, "two.exe");
        x86.arch = ProcessArch::X86;
        let list = vec![sample(10, "one.exe"), x86, sample(30, "three.exe")];
        let accessible = HashSet::from([10]);
        assert_eq!(filter_simple(&list, "", &accessible, true, None), vec![0]);
        assert_eq!(
            filter_simple(&list, "", &accessible, false, None),
            vec![0, 1, 2]
        );
        assert_eq!(
            filter_simple(&list, "", &accessible, false, Some(ProcessArch::X86)),
            vec![1]
        );
        assert_eq!(
            filter_simple(&list, "", &accessible, true, Some(ProcessArch::X64)),
            vec![0]
        );
    }

    #[test]
    fn core_filter_applies_session_user_protected_and_ppid() {
        let mut lsass = sample(10, "lsass.exe");
        lsass.session_id = Some(1);
        lsass.user = Some("NT AUTHORITY\\SYSTEM".into());
        lsass.ppid = Some(4);
        let mut other = sample(20, "other.exe");
        other.session_id = Some(2);
        other.user = Some("DOMAIN\\user".into());
        other.ppid = Some(500);
        let mut no_user = sample(30, "ghost.exe");
        no_user.session_id = Some(1);
        no_user.ppid = Some(4);
        let list = vec![lsass, other, no_user];
        let accessible = HashSet::from([10]);

        let filter = ProcessFilter {
            session: Some(1),
            user_contains: Some("system".into()),
            protected_only: true,
            parent_pid: Some(4),
            accessible_only: true,
            ..ProcessFilter::default()
        };
        assert_eq!(
            filter_processes_core(&list, "", &accessible, &filter),
            vec![0],
            "세션·사용자·보호·부모 PID·접근성이 모두 AND"
        );
        let by_ppid = ProcessFilter {
            parent_pid: Some(4),
            ..ProcessFilter::default()
        };
        assert_eq!(
            filter_processes_core(&list, "", &accessible, &by_ppid),
            vec![0, 2],
            "사용자 정보가 없는 프로세스는 user 조건에서만 탈락"
        );
        assert!(
            filter_processes_core(
                &list,
                "",
                &accessible,
                &ProcessFilter {
                    session: Some(2),
                    ..ProcessFilter::default()
                }
            ) == vec![1]
        );
    }

    #[test]
    fn menu_labels_cover_arch_options() {
        for (value, label) in arch_options() {
            assert_eq!(
                arch_filter_label(value).strip_prefix("아키텍처: "),
                Some(label)
            );
        }
    }

    #[test]
    fn filter_count_and_reset_clear_all_conditions() {
        assert_eq!(filter_count(false, None, "", "", false, ""), 0);
        assert_eq!(filter_count(false, None, "  ", " ", false, " "), 0);
        assert_eq!(
            filter_count(true, Some(ProcessArch::X64), "1", "SYSTEM", true, "4"),
            6
        );
        let mut accessible = true;
        let mut arch = Some(ProcessArch::X64);
        let mut session = "1".to_string();
        let mut user = "SYSTEM".to_string();
        let mut protected = true;
        let mut ppid = "4".to_string();
        reset_filter(
            &mut accessible,
            &mut arch,
            &mut session,
            &mut user,
            &mut protected,
            &mut ppid,
        );
        assert!(
            !accessible
                && arch.is_none()
                && session.is_empty()
                && user.is_empty()
                && !protected
                && ppid.is_empty()
        );
    }
}
