//! 앱 셸: 상단 바 + 탭 + 하단 로그.

use xmem_core::XmemError;

use crate::config::GuiConfig;
use crate::log::{LogBuffer, LogLevel};
use crate::task::{BackgroundTask, TaskState};
use crate::theme::{self, ThemeMode};
use crate::views::map::MapSort;
use crate::views::module::ModuleDetail;
use crate::views::modules::ModuleBundle;
use crate::views::region::RegionDetail;
use crate::views::thread::ThreadDetail;

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
    pub overview_task: BackgroundTask<(u32, xmem_core::ProcessInfo)>,
    pub overview_info: Option<xmem_core::ProcessInfo>,
    pub map_task: BackgroundTask<(u32, xmem_memory::RegionMap)>,
    pub map: Option<xmem_memory::RegionMap>,
    pub map_filters: xmem_memory::RegionFilters,
    pub map_sort: MapSort,
    pub map_selected: Option<u64>,
    pub region_detail: Option<RegionDetail>,
    pub region_detail_task: BackgroundTask<(u64, RegionDetail)>,
    pub region_page_task: BackgroundTask<(u64, u64, Vec<u8>, Option<String>)>,
    pub region_page_pending: Option<u64>,
    pub modules_task: BackgroundTask<(u32, ModuleBundle)>,
    pub modules_bundle: Option<ModuleBundle>,
    pub module_selected: Option<u64>,
    pub module_detail: Option<ModuleDetail>,
    pub module_detail_task: BackgroundTask<(u64, ModuleDetail)>,
    pub modules_pe: bool,
    pub threads_task: BackgroundTask<(u32, Vec<xmem_core::ThreadInfo>)>,
    pub threads: Option<Vec<xmem_core::ThreadInfo>>,
    pub thread_selected: Option<u32>,
    pub thread_detail: Option<ThreadDetail>,
    pub thread_detail_task: BackgroundTask<(u32, ThreadDetail)>,
    pub scan_state: crate::views::scan::ScanUiState,
    pub scan_task: BackgroundTask<(u32, xmem_memory::ScanReport)>,
    pub scan_preview_task: BackgroundTask<(u64, u64, String)>,
    pub scan_report: Option<xmem_memory::ScanReport>,
    pub detect_task: BackgroundTask<(u32, Vec<xmem_core::Finding>)>,
    pub findings: Option<Vec<xmem_core::Finding>>,
    pub detect_selected: Option<usize>,
    pub snapshot_output: String,
    pub snapshot_output_pid: Option<u32>,
    pub snapshot_before: String,
    pub snapshot_after: String,
    pub snapshot_create_task: BackgroundTask<(u32, (String, u64))>,
    pub snapshot_created: Option<(String, u64)>,
    pub snapshot_diff_task: BackgroundTask<xmem_forensics::SnapshotDiff>,
    pub snapshot_diff: Option<xmem_forensics::SnapshotDiff>,
    pub dump_output: String,
    pub dump_output_pid: Option<u32>,
    pub dump_full: bool,
    pub dump_full_warning: Option<String>,
    pub dump_create_task: BackgroundTask<(u32, (String, u64))>,
    pub dump_created: Option<(String, u64)>,
    pub dump_analyze_input: String,
    pub dump_analyze_task: BackgroundTask<(
        String,
        xmem_forensics::DumpAnalysis,
        Vec<xmem_core::Finding>,
    )>,
    pub dump_analysis: Option<(
        String,
        xmem_forensics::DumpAnalysis,
        Vec<xmem_core::Finding>,
    )>,
    pub report_markdown: bool,
    pub report_output: String,
    pub report_output_pid: Option<u32>,
    pub report_task: BackgroundTask<(u32, (String, u64))>,
    pub report_saved: Option<(String, u64)>,
    pub guide_query: String,
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
        let tab = if config.guide_seen {
            Tab::Overview
        } else {
            Tab::Guide
        };
        let mut app = Self {
            theme: config.theme,
            config,
            is_elevated: elevated,
            tab,
            selected_pid: None,
            log,
            list_task: BackgroundTask::idle(),
            process_filter: String::new(),
            processes: Vec::new(),
            overview_task: BackgroundTask::idle(),
            overview_info: None,
            map_task: BackgroundTask::idle(),
            map: None,
            map_filters: xmem_memory::RegionFilters::default(),
            map_sort: MapSort::AddressAsc,
            map_selected: None,
            region_detail: None,
            region_detail_task: BackgroundTask::idle(),
            region_page_task: BackgroundTask::idle(),
            region_page_pending: None,
            modules_task: BackgroundTask::idle(),
            modules_bundle: None,
            module_selected: None,
            module_detail: None,
            module_detail_task: BackgroundTask::idle(),
            modules_pe: false,
            threads_task: BackgroundTask::idle(),
            threads: None,
            thread_selected: None,
            thread_detail: None,
            thread_detail_task: BackgroundTask::idle(),
            scan_state: crate::views::scan::ScanUiState::default(),
            scan_task: BackgroundTask::idle(),
            scan_preview_task: BackgroundTask::idle(),
            scan_report: None,
            detect_task: BackgroundTask::idle(),
            findings: None,
            detect_selected: None,
            snapshot_output: String::new(),
            snapshot_output_pid: None,
            snapshot_before: String::new(),
            snapshot_after: String::new(),
            snapshot_create_task: BackgroundTask::idle(),
            snapshot_created: None,
            snapshot_diff_task: BackgroundTask::idle(),
            snapshot_diff: None,
            dump_output: String::new(),
            dump_output_pid: None,
            dump_full: false,
            dump_full_warning: None,
            dump_create_task: BackgroundTask::idle(),
            dump_created: None,
            dump_analyze_input: String::new(),
            dump_analyze_task: BackgroundTask::idle(),
            dump_analysis: None,
            report_markdown: false,
            report_output: String::new(),
            report_output_pid: None,
            report_task: BackgroundTask::idle(),
            report_saved: None,
            guide_query: String::new(),
        };
        app.refresh_processes();
        if let Some(pid) = initial_pid {
            app.select_process(pid);
        }
        app
    }

    pub fn refresh_processes(&mut self) {
        self.list_task =
            BackgroundTask::spawn("프로세스 목록", |_| xmem_windows::list_processes());
    }

    /// 실행 중인 태스크 라벨(상단 바 표시용).
    pub fn running_labels(&self) -> Vec<&str> {
        let tasks = [
            (self.list_task.label(), self.list_task.is_running()),
            (self.overview_task.label(), self.overview_task.is_running()),
            (self.map_task.label(), self.map_task.is_running()),
            (self.modules_task.label(), self.modules_task.is_running()),
            (self.threads_task.label(), self.threads_task.is_running()),
            (self.scan_task.label(), self.scan_task.is_running()),
            (self.detect_task.label(), self.detect_task.is_running()),
            (
                self.snapshot_create_task.label(),
                self.snapshot_create_task.is_running(),
            ),
            (
                self.snapshot_diff_task.label(),
                self.snapshot_diff_task.is_running(),
            ),
            (
                self.dump_create_task.label(),
                self.dump_create_task.is_running(),
            ),
            (
                self.dump_analyze_task.label(),
                self.dump_analyze_task.is_running(),
            ),
            (self.report_task.label(), self.report_task.is_running()),
        ];
        tasks
            .into_iter()
            .filter(|(_, running)| *running)
            .map(|(label, _)| label)
            .collect()
    }

    pub fn select_process(&mut self, pid: u32) {
        // 같은 프로세스를 다시 클릭해도 진행 중 태스크/상세 패널을 날리지 않는다.
        if self.selected_pid == Some(pid) {
            return;
        }
        self.selected_pid = Some(pid);
        // 이전 프로세스의 진행 중 태스크를 취소하고 Idle로 되돌린다 — 새 프로세스의 자동 로딩을 막지 않도록.
        self.map_task.reset();
        self.region_detail_task.reset();
        self.region_page_task.reset();
        self.modules_task.reset();
        self.module_detail_task.reset();
        self.threads_task.reset();
        self.thread_detail_task.reset();
        self.scan_task.reset();
        self.scan_preview_task.reset();
        self.detect_task.reset();
        self.snapshot_create_task.reset();
        self.dump_create_task.reset();
        self.report_task.reset();
        self.start_overview(pid);
        self.map = None;
        self.map_selected = None;
        self.region_detail = None;
        self.region_page_pending = None;
        self.modules_bundle = None;
        self.module_selected = None;
        self.module_detail = None;
        self.threads = None;
        self.thread_selected = None;
        self.thread_detail = None;
        self.scan_report = None;
        self.scan_state.selected_match = None;
        self.scan_state.preview = None;
        self.findings = None;
        self.detect_selected = None;
        self.snapshot_created = None;
        self.snapshot_diff = None;
        self.dump_created = None;
        self.dump_analysis = None;
        self.dump_full_warning = None;
        self.report_saved = None;
    }

    pub fn start_overview(&mut self, pid: u32) {
        self.overview_info = None;
        self.overview_task = BackgroundTask::spawn("프로세스 정보", move |_| {
            Ok((pid, xmem_windows::process_info(pid)?))
        })
        .with_pid(pid);
    }

    pub fn start_map(&mut self, pid: u32) {
        self.map_task.cancel();
        self.region_detail_task.cancel();
        self.map = None;
        self.map_selected = None;
        self.region_detail = None;
        self.region_page_task.cancel();
        self.region_page_pending = None;
        self.map_task = BackgroundTask::spawn("메모리맵", move |cancel| {
            Ok((
                pid,
                xmem_memory::LiveProcess::open(pid)?.region_map_cancellable(cancel)?,
            ))
        })
        .with_pid(pid);
    }

    pub fn select_region(&mut self, pid: u32, region: xmem_core::MemoryRegion) {
        let base = region.base;
        self.map_selected = Some(base);
        self.region_detail = None;
        self.region_page_task.cancel();
        self.region_page_pending = None;
        self.region_detail_task = BackgroundTask::spawn("영역 상세", move |_| {
            let detail = crate::views::region::collect_region_detail(pid, region)?;
            Ok((base, detail))
        });
    }

    /// 4 KiB 페이지 읽기를 UI 스레드 밖에서 수행한다.
    pub fn request_region_page(&mut self, pid: u32, region: xmem_core::MemoryRegion, address: u64) {
        let base = region.base;
        let requested = crate::views::region::clamp_page(address, &region);
        self.region_page_pending = Some(requested);
        self.region_page_task = BackgroundTask::spawn("영역 페이지", move |_| {
            let (page, bytes, error) = crate::views::region::load_page(pid, &region, requested);
            Ok((base, page, bytes, error))
        });
    }

    pub fn retry_region_detail(&mut self) {
        let Some(pid) = self.selected_pid else {
            self.log
                .push(LogLevel::Warn, "다시 시도할 데이터가 없습니다");
            return;
        };
        let region = self.map_selected.and_then(|base| {
            self.map
                .as_ref()?
                .regions
                .iter()
                .find(|region| region.base == base)
                .cloned()
        });
        match region {
            Some(region) => self.select_region(pid, region),
            None => self
                .log
                .push(LogLevel::Warn, "다시 시도할 데이터가 없습니다"),
        }
    }

    pub fn select_module(&mut self, pid: u32, module: xmem_core::ModuleInfo) {
        let base = module.base;
        self.module_selected = Some(base);
        self.module_detail = None;
        self.module_detail_task = BackgroundTask::spawn("모듈 상세", move |_| {
            let detail = crate::views::module::collect_module_detail(pid, module);
            Ok((base, detail))
        });
    }

    pub fn retry_module_detail(&mut self) {
        let Some(pid) = self.selected_pid else {
            self.log
                .push(LogLevel::Warn, "다시 시도할 데이터가 없습니다");
            return;
        };
        let module = self.module_selected.and_then(|base| {
            self.modules_bundle
                .as_ref()?
                .modules
                .iter()
                .find(|module| module.base == base)
                .cloned()
        });
        match module {
            Some(module) => self.select_module(pid, module),
            None => self
                .log
                .push(LogLevel::Warn, "다시 시도할 데이터가 없습니다"),
        }
    }

    pub fn start_modules(&mut self, pid: u32) {
        self.modules_bundle = None;
        self.module_selected = None;
        self.module_detail = None;
        let with_pe = self.modules_pe;
        self.modules_task = BackgroundTask::spawn("모듈", move |cancel| {
            let live = xmem_memory::LiveProcess::open(pid)?;
            let modules = live.modules()?;
            crate::task::ensure_not_cancelled(cancel)?;
            let pe = if with_pe {
                let pe = crate::views::modules::collect_pe(&live, &modules);
                crate::task::ensure_not_cancelled(cancel)?;
                Some(pe)
            } else {
                None
            };
            Ok((pid, ModuleBundle { modules, pe }))
        })
        .with_pid(pid);
    }

    pub fn start_threads(&mut self, pid: u32) {
        self.threads = None;
        self.thread_selected = None;
        self.thread_detail = None;
        self.threads_task = BackgroundTask::spawn("스레드", move |cancel| {
            let live = xmem_memory::LiveProcess::open(pid)?;
            let threads = live.threads()?;
            crate::task::ensure_not_cancelled(cancel)?;
            Ok((pid, threads))
        })
        .with_pid(pid);
    }

    pub fn select_thread(&mut self, pid: u32, thread: xmem_core::ThreadInfo) {
        let tid = thread.tid;
        self.thread_selected = Some(tid);
        self.thread_detail = None;
        self.thread_detail_task = BackgroundTask::spawn("스레드 상세", move |_| {
            let detail = crate::views::thread::collect_thread_detail(pid, thread);
            Ok((tid, detail))
        });
    }

    pub fn retry_thread_detail(&mut self) {
        let Some(pid) = self.selected_pid else {
            self.log
                .push(LogLevel::Warn, "다시 시도할 데이터가 없습니다");
            return;
        };
        let thread = self.thread_selected.and_then(|tid| {
            self.threads
                .as_ref()?
                .iter()
                .find(|thread| thread.tid == tid)
                .cloned()
        });
        match thread {
            Some(thread) => self.select_thread(pid, thread),
            None => self
                .log
                .push(LogLevel::Warn, "다시 시도할 데이터가 없습니다"),
        }
    }

    pub fn start_scan(&mut self, pid: u32) {
        let pattern = match crate::views::scan::build_pattern(&self.scan_state) {
            Ok(pattern) => pattern,
            Err(err) => {
                self.log.push(LogLevel::Warn, err.to_string());
                return;
            }
        };
        let options = crate::views::scan::build_options(&self.scan_state);
        self.scan_report = None;
        self.scan_state.selected_match = None;
        self.scan_state.preview = None;
        self.scan_preview_task.cancel();
        self.scan_task = BackgroundTask::spawn("검색", move |cancel| {
            let live = xmem_memory::LiveProcess::open(pid)?;
            Ok((pid, xmem_memory::scan(&live, &pattern, &options, cancel)?))
        })
        .with_pid(pid);
    }

    /// 매치 주변 미리보기 읽기를 UI 스레드 밖에서 수행한다.
    pub fn request_scan_preview(
        &mut self,
        pid: u32,
        address: u64,
        region_base: u64,
        region_size: u64,
    ) {
        self.scan_preview_task = BackgroundTask::spawn("미리보기", move |_| {
            let (start, dump) =
                crate::views::scan::collect_preview(pid, address, region_base, region_size)?;
            Ok((address, start, dump))
        });
    }

    pub fn start_detect(&mut self, pid: u32) {
        self.findings = None;
        self.detect_selected = None;
        self.detect_task = BackgroundTask::spawn("탐지", move |cancel| {
            let live = xmem_memory::LiveProcess::open(pid)?;
            let regions = live.region_map_cancellable(cancel)?.regions;
            crate::task::ensure_not_cancelled(cancel)?;
            let modules = live.modules()?;
            crate::task::ensure_not_cancelled(cancel)?;
            let threads = live.threads()?;
            crate::task::ensure_not_cancelled(cancel)?;
            Ok((
                pid,
                xmem_detection::detect(&xmem_detection::DetectionContext {
                    regions: &regions,
                    modules: &modules,
                    threads: &threads,
                }),
            ))
        })
        .with_pid(pid);
    }

    pub fn start_snapshot_create(&mut self, pid: u32) {
        let trimmed = self.snapshot_output.trim();
        // 다른 프로세스용으로 만든 기본 파일명이면 새 PID 기준으로 다시 만든다(덮어쓰기 방지).
        let output = if trimmed.is_empty() || self.snapshot_output_pid != Some(pid) {
            crate::config::default_output_dir().join(crate::config::output_file_name(
                "snapshot",
                pid,
                "xmem",
                chrono::Local::now(),
            ))
        } else {
            std::path::PathBuf::from(trimmed)
        };
        if let Some(dir) = output.parent().filter(|p| !p.as_os_str().is_empty())
            && let Err(err) = std::fs::create_dir_all(dir)
        {
            self.log
                .push(LogLevel::Warn, format!("출력 디렉터리 생성 실패: {err}"));
            return;
        }
        self.snapshot_output = output.to_string_lossy().into_owned();
        self.snapshot_output_pid = Some(pid);
        if let Some(dir) = output.parent() {
            self.config.last_output_dir = Some(dir.to_path_buf());
        }
        self.snapshot_created = None;
        self.snapshot_create_task = BackgroundTask::spawn("스냅샷 생성", move |cancel| {
            let bytes = crate::views::snapshot::create_snapshot_file(pid, &output, cancel)?;
            Ok((pid, (output.to_string_lossy().into_owned(), bytes)))
        });
    }

    pub fn start_snapshot_diff(&mut self) {
        let before = self.snapshot_before.trim();
        let after = self.snapshot_after.trim();
        if before.is_empty() || after.is_empty() {
            self.log
                .push(LogLevel::Warn, "비교할 스냅샷 두 개를 지정하세요");
            return;
        }
        let before = std::path::PathBuf::from(before);
        let after = std::path::PathBuf::from(after);
        self.snapshot_diff = None;
        self.snapshot_diff_task = BackgroundTask::spawn("스냅샷 비교", move |_| {
            let before = xmem_forensics::read_file(&before)?;
            let after = xmem_forensics::read_file(&after)?;
            Ok(xmem_forensics::diff(&before, &after))
        });
    }

    pub fn start_dump_create(&mut self, pid: u32) {
        let trimmed = self.dump_output.trim();
        // 다른 프로세스용으로 만든 기본 파일명이면 새 PID 기준으로 다시 만든다(덮어쓰기 방지).
        let output = if trimmed.is_empty() || self.dump_output_pid != Some(pid) {
            crate::config::default_output_dir().join(crate::config::output_file_name(
                "dump",
                pid,
                "dmp",
                chrono::Local::now(),
            ))
        } else {
            std::path::PathBuf::from(trimmed)
        };
        if let Some(dir) = output.parent().filter(|p| !p.as_os_str().is_empty())
            && let Err(err) = std::fs::create_dir_all(dir)
        {
            self.log
                .push(LogLevel::Warn, format!("출력 디렉터리 생성 실패: {err}"));
            return;
        }
        self.dump_output = output.to_string_lossy().into_owned();
        self.dump_output_pid = Some(pid);
        if let Some(dir) = output.parent() {
            self.config.last_output_dir = Some(dir.to_path_buf());
        }
        self.dump_created = None;
        let full = self.dump_full;
        self.dump_create_task = BackgroundTask::spawn("덤프 생성", move |_| {
            let bytes = crate::views::dump::create_dump_file(pid, &output, full)?;
            Ok((pid, (output.to_string_lossy().into_owned(), bytes)))
        });
    }

    pub fn start_dump_analyze(&mut self) {
        let trimmed = self.dump_analyze_input.trim();
        if trimmed.is_empty() {
            self.log
                .push(LogLevel::Warn, "분석할 덤프 파일을 지정하세요");
            return;
        }
        let path = std::path::PathBuf::from(trimmed);
        self.dump_analysis = None;
        self.dump_analyze_task = BackgroundTask::spawn("덤프 분석", move |_| {
            let (analysis, findings) = crate::views::dump::analyze_dump_file(&path)?;
            Ok((path.to_string_lossy().into_owned(), analysis, findings))
        });
    }

    pub fn start_report_save(&mut self, pid: u32) {
        let ext = if self.report_markdown { "md" } else { "json" };
        let trimmed = self.report_output.trim();
        // 다른 프로세스용으로 만든 기본 파일명이면 새 PID 기준으로 다시 만든다(덮어쓰기 방지).
        let output = if trimmed.is_empty() || self.report_output_pid != Some(pid) {
            crate::config::default_output_dir().join(crate::config::output_file_name(
                "report",
                pid,
                ext,
                chrono::Local::now(),
            ))
        } else {
            std::path::PathBuf::from(trimmed)
        };
        if let Some(dir) = output.parent().filter(|p| !p.as_os_str().is_empty())
            && let Err(err) = std::fs::create_dir_all(dir)
        {
            self.log
                .push(LogLevel::Warn, format!("출력 디렉터리 생성 실패: {err}"));
            return;
        }
        self.report_output = output.to_string_lossy().into_owned();
        self.report_output_pid = Some(pid);
        if let Some(dir) = output.parent() {
            self.config.last_output_dir = Some(dir.to_path_buf());
        }
        self.report_saved = None;
        self.report_task = BackgroundTask::spawn("리포트 저장", move |_| {
            let data = crate::views::report::build_report_data(pid)?;
            let bytes = xmem_forensics::write_report(&data, &output)?;
            Ok((pid, (output.to_string_lossy().into_owned(), bytes)))
        });
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
        if self.overview_task.poll()
            && let Some((task_pid, info)) = self.overview_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.overview_info = Some(info);
        }
        if self.map_task.poll()
            && let Some((task_pid, map)) = self.map_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.map = Some(map);
        }
        if self.region_detail_task.poll()
            && let Some((base, detail)) = self.region_detail_task.take_done()
            && Some(base) == self.map_selected
        {
            self.region_detail = Some(detail);
        }
        if self.region_page_task.poll()
            && let Some((base, page, bytes, error)) = self.region_page_task.take_done()
            && Some(base) == self.map_selected
            && Some(page) == self.region_page_pending
            && let Some(detail) = self.region_detail.as_mut()
        {
            detail.page_start = page;
            detail.page_bytes = bytes;
            detail.page_error = error;
            self.region_page_pending = None;
        }
        if self.modules_task.poll()
            && let Some((task_pid, bundle)) = self.modules_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.modules_bundle = Some(bundle);
        }
        if self.module_detail_task.poll()
            && let Some((base, detail)) = self.module_detail_task.take_done()
            && Some(base) == self.module_selected
        {
            self.module_detail = Some(detail);
        }
        if self.threads_task.poll()
            && let Some((task_pid, threads)) = self.threads_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.threads = Some(threads);
        }
        if self.thread_detail_task.poll()
            && let Some((tid, detail)) = self.thread_detail_task.take_done()
            && Some(tid) == self.thread_selected
        {
            self.thread_detail = Some(detail);
        }
        if self.scan_task.poll()
            && let Some((task_pid, report)) = self.scan_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.scan_report = Some(report);
        }
        if self.scan_preview_task.poll() {
            if let Some((address, start, dump)) = self.scan_preview_task.take_done() {
                let still_selected = self
                    .scan_state
                    .selected_match
                    .and_then(|index| self.scan_report.as_ref()?.matches.get(index))
                    .is_some_and(|found| found.address == address);
                if still_selected {
                    self.scan_state.preview = Some((start, dump));
                }
            } else if let TaskState::Failed(err) = self.scan_preview_task.state() {
                let label = crate::error::error_label(err);
                self.log
                    .push(LogLevel::Warn, format!("미리보기 실패: {label}"));
            }
        }
        if self.detect_task.poll()
            && let Some((task_pid, findings)) = self.detect_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.findings = Some(findings);
        }
        if self.snapshot_create_task.poll()
            && let Some((task_pid, created)) = self.snapshot_create_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.snapshot_created = Some(created);
        }
        if self.snapshot_diff_task.poll()
            && let Some(diff) = self.snapshot_diff_task.take_done()
        {
            self.snapshot_diff = Some(diff);
        }
        if self.dump_create_task.poll()
            && let Some((task_pid, created)) = self.dump_create_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.dump_created = Some(created);
        }
        if self.dump_analyze_task.poll()
            && let Some(analysis) = self.dump_analyze_task.take_done()
        {
            self.dump_analysis = Some(analysis);
        }
        if self.report_task.poll()
            && let Some((task_pid, saved)) = self.report_task.take_done()
            && Some(task_pid) == self.selected_pid
        {
            self.report_saved = Some(saved);
        }
        if self.tab == Tab::Guide && !self.config.guide_seen {
            self.config.guide_seen = true;
        }
        if ctx.input(|i| i.viewport().close_requested()) {
            let size = ctx.input(|i| i.viewport_rect().size());
            self.config.window_width = size.x;
            self.config.window_height = size.y;
            if let Err(err) = crate::config::save(&self.config) {
                self.log
                    .push(LogLevel::Warn, format!("설정 저장 실패: {err}"));
            }
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
                    if let Err(err) = crate::config::save(&self.config) {
                        self.log
                            .push(LogLevel::Warn, format!("설정 저장 실패: {err}"));
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(egui::RichText::new(format!("v{}", xmem_core::VERSION)).weak());
                    let running = self.running_labels();
                    if !running.is_empty() {
                        ui.label(egui::RichText::new(running.join(", ")).weak());
                        ui.spinner();
                    }
                });
            });
        });

        egui::Panel::bottom(egui::Id::new("log")).show(ui, |ui| {
            crate::views::log::ui(ui, &mut self.log, self.theme);
        });

        let narrow = ui.ctx().input(|i| i.viewport_rect().width()) < 900.0;
        if !narrow {
            egui::Panel::left(egui::Id::new("processes"))
                .resizable(true)
                .default_size(300.0)
                .size_range(240.0..=1200.0)
                .show(ui, |ui| {
                    crate::views::process::ui(ui, self);
                });
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                for tab in Tab::ALL {
                    if ui.selectable_label(self.tab == tab, tab.title()).clicked() {
                        self.tab = tab;
                    }
                }
            });
            if narrow {
                crate::views::process::dropdown(ui, self);
            }
            ui.separator();
            if let Some(pid) = self.selected_pid {
                // Idle/취소 상태일 때만 자동 시작한다 — 실패한 태스크를 매 프레임 다시 시작하면
                // 오류가 화면에 남지 않고 CPU만 소모된다.
                match self.tab {
                    Tab::Map
                        if self.map.is_none()
                            && matches!(
                                self.map_task.state(),
                                TaskState::Idle | TaskState::Cancelled
                            ) =>
                    {
                        self.start_map(pid);
                    }
                    Tab::Modules
                        if self.modules_bundle.is_none()
                            && matches!(
                                self.modules_task.state(),
                                TaskState::Idle | TaskState::Cancelled
                            ) =>
                    {
                        self.start_modules(pid);
                    }
                    Tab::Threads
                        if self.threads.is_none()
                            && matches!(
                                self.threads_task.state(),
                                TaskState::Idle | TaskState::Cancelled
                            ) =>
                    {
                        self.start_threads(pid);
                    }
                    _ => {}
                }
            }
            match self.tab {
                Tab::Overview => crate::views::overview::ui(ui, self),
                Tab::Map => crate::views::map::ui(ui, self),
                Tab::Modules => crate::views::modules::ui(ui, self),
                Tab::Threads => crate::views::threads::ui(ui, self),
                Tab::Scan => crate::views::scan::ui(ui, self),
                Tab::Detect => crate::views::detect::ui(ui, self),
                Tab::Snapshot => crate::views::snapshot::ui(ui, self),
                Tab::Dump => crate::views::dump::ui(ui, self),
                Tab::Report => crate::views::report::ui(ui, self),
                Tab::Guide => crate::views::guide::ui(ui, self),
            }
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
