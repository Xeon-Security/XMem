//! 앱 셸: 상단 바 + 탭 + 하단 로그.

use xmem_core::XmemError;

use crate::config::GuiConfig;
use crate::log::{LogBuffer, LogLevel};
use crate::task::BackgroundTask;
use crate::theme::{self, ThemeMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Map,
    Scan,
    Modules,
    Threads,
    Detect,
    Snapshot,
    Dump,
    Report,
    Guide,
}

impl Tab {
    pub const ALL: [Tab; 10] = [
        Tab::Overview,
        Tab::Map,
        Tab::Scan,
        Tab::Modules,
        Tab::Threads,
        Tab::Detect,
        Tab::Snapshot,
        Tab::Dump,
        Tab::Report,
        Tab::Guide,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "개요",
            Tab::Map => "메모리맵",
            Tab::Scan => "검색",
            Tab::Modules => "모듈",
            Tab::Threads => "스레드",
            Tab::Detect => "탐지",
            Tab::Snapshot => "스냅샷",
            Tab::Dump => "덤프",
            Tab::Report => "리포트",
            Tab::Guide => "가이드",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenFailure {
    SystemProcess,
    NeedsElevation,
    Protected,
    Exited,
    Other(String),
}

impl OpenFailure {
    pub fn message(&self) -> String {
        match self {
            OpenFailure::SystemProcess => "시스템 프로세스(PID 0/4)는 열 수 없습니다".into(),
            OpenFailure::NeedsElevation => "권한이 부족합니다. 관리자로 재시작하세요".into(),
            OpenFailure::Protected => "PPL 보호 프로세스입니다. 관리자도 열 수 없습니다".into(),
            OpenFailure::Exited => "프로세스가 종료되었습니다".into(),
            OpenFailure::Other(text) => text.clone(),
        }
    }
}

pub fn classify_open_failure(err: &XmemError, is_elevated: bool, pid: u32) -> OpenFailure {
    if pid <= 4 {
        return OpenFailure::SystemProcess;
    }
    match err {
        XmemError::AccessDenied { .. } => {
            if is_elevated {
                OpenFailure::Protected
            } else {
                OpenFailure::NeedsElevation
            }
        }
        XmemError::ProcessExited { .. } => OpenFailure::Exited,
        other => OpenFailure::Other(other.to_string()),
    }
}

/// runas에 넘길 파라미터 문자열(`--pid 123` 또는 빈 문자열).
pub fn restart_params(pid: Option<u32>) -> String {
    pid.map(|p| format!("--pid {p}")).unwrap_or_default()
}

pub struct XMemApp {
    pub config: GuiConfig,
    pub theme: ThemeMode,
    pub is_elevated: bool,
    pub tab: Tab,
    pub selected_pid: Option<u32>,
    pub log: LogBuffer,
    pub list_task: BackgroundTask<Vec<xmem_core::ProcessInfo>>,
    pub process_filter: String,
    pub processes: Vec<xmem_core::ProcessInfo>,
}

impl XMemApp {
    pub fn new(config: GuiConfig, initial_pid: Option<u32>) -> Self {
        let mut log = LogBuffer::new(200);
        let elevated = xmem_windows::is_elevated().unwrap_or(false);
        log.push(
            LogLevel::Info,
            if elevated {
                "관리자 권한으로 실행 중"
            } else {
                "표준 사용자 권한"
            },
        );
        let mut app = Self {
            theme: config.theme,
            config,
            is_elevated: elevated,
            tab: Tab::Overview,
            selected_pid: initial_pid,
            log,
            list_task: BackgroundTask::idle(),
            process_filter: String::new(),
            processes: Vec::new(),
        };
        app.refresh_processes();
        app
    }

    pub fn refresh_processes(&mut self) {
        self.list_task =
            BackgroundTask::spawn("프로세스 목록", |_| xmem_windows::list_processes());
    }

    pub fn restart_elevated(&mut self) {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let params = restart_params(self.selected_pid);
        match xmem_windows::runas(&exe, &params) {
            Ok(()) => {
                self.log
                    .push(LogLevel::Info, "관리자 권한으로 재시작했습니다");
                std::process::exit(0);
            }
            Err(err) => {
                self.log
                    .push(LogLevel::Error, format!("관리자 재시작 실패: {err}"));
            }
        }
    }
}

impl eframe::App for XMemApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if self.list_task.poll()
            && let Some(list) = self.list_task.take_done()
        {
            self.processes = list;
        }
        let palette = theme::palette(self.theme);

        egui::Panel::top(egui::Id::new("top")).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("XMem").strong().size(16.0));
                let (badge, color) = if self.is_elevated {
                    ("관리자", palette.accent)
                } else {
                    ("표준 사용자", palette.muted)
                };
                ui.label(egui::RichText::new(badge).color(color));
                if !self.is_elevated && ui.button("관리자로 재시작").clicked() {
                    self.restart_elevated();
                }
                ui.separator();
                if ui.button("가이드").clicked() {
                    self.tab = Tab::Guide;
                }
                let theme_label = match self.theme {
                    ThemeMode::Dark => "라이트 모드",
                    ThemeMode::Light => "다크 모드",
                };
                if ui.button(theme_label).clicked() {
                    self.theme = match self.theme {
                        ThemeMode::Dark => ThemeMode::Light,
                        ThemeMode::Light => ThemeMode::Dark,
                    };
                    self.config.theme = self.theme;
                    theme::apply(&ctx, self.theme);
                    let _ = crate::config::save(&self.config);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(format!("v{}", xmem_core::VERSION)).weak());
                });
            });
        });

        egui::Panel::bottom(egui::Id::new("log")).show(ui, |ui| {
            crate::views::log::ui(ui, &self.log);
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                for tab in Tab::ALL {
                    if ui.selectable_label(self.tab == tab, tab.title()).clicked() {
                        self.tab = tab;
                    }
                }
            });
            ui.separator();
            ui.label(format!(
                "선택된 PID: {}",
                self.selected_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into())
            ));
            ui.label(egui::RichText::new("(Task 3~7에서 각 탭 화면이 채워집니다)").weak());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_covers_system_elevation_protected_exit() {
        let denied = XmemError::AccessDenied {
            context: "OpenProcess".into(),
        };
        assert_eq!(
            classify_open_failure(&denied, false, 100),
            OpenFailure::NeedsElevation
        );
        assert_eq!(
            classify_open_failure(&denied, true, 100),
            OpenFailure::Protected
        );
        assert_eq!(
            classify_open_failure(&denied, true, 4),
            OpenFailure::SystemProcess
        );
        let exited = XmemError::ProcessExited { pid: 7 };
        assert_eq!(classify_open_failure(&exited, true, 7), OpenFailure::Exited);
        let other = XmemError::InvalidAddress { address: 1 };
        assert!(matches!(
            classify_open_failure(&other, true, 7),
            OpenFailure::Other(_)
        ));
    }

    #[test]
    fn restart_params_formats_pid() {
        assert_eq!(restart_params(Some(1234)), "--pid 1234");
        assert_eq!(restart_params(None), "");
    }

    #[test]
    fn tab_titles_are_korean_and_unique() {
        let mut titles: Vec<_> = Tab::ALL.iter().map(|t| t.title()).collect();
        titles.sort();
        titles.dedup();
        assert_eq!(titles.len(), Tab::ALL.len());
    }
}
