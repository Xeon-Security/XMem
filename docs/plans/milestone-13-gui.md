# XMem GUI (Milestone 13) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CLI 전용이던 XMem 분석 기능 전체(프로세스→탐지→스냅샷→덤프→리포트)를 egui 기반 단일 exe GUI로 제공하고, 처음 쓰는 사용자를 가이드·실패 사유 안내·로그 패널로 안내한다.

**Architecture:** `crates/xmem-gui` (bin `xmem-gui`)가 기존 crate(xmem-core/memory/detection/forensics/windows)를 직접 호출한다(IPC 없음). 모든 분석은 태스크 스레드에서 자체 `LiveProcess`를 열어 수행하고 UI는 상태만 그린다. unsafe는 기존 규칙대로 `xmem-windows`에만 두고, GUI는 그 래퍼만 호출한다.

**Tech Stack:** Rust 1.98 (edition 2024), eframe 0.36.2, egui 0.36.2, egui_extras 0.36.2, rfd 0.17.2, serde/serde_json, chrono, tracing. 기존 workspace crate 전부.

**Spec:** `docs/gui-design.md` (설계 스펙 — 반드시 함께 읽을 것)

## Global Constraints

- Rust stable 1.98, edition 2024. workspace lints 그대로: `unsafe_code = deny` (xmem-gui는 `#![allow(unsafe_code)]` 금지 — unsafe 없이 작성), clippy `unwrap_used`/`expect_used` = warn (테스트는 `#![cfg_attr(test, allow(...))]`).
- 버전 고정: eframe 0.36.2, egui_extras 0.36.2, rfd 0.17.2 (실측 완료. workspace가 아니라 crate Cargo.toml에 직접 기입 — `windows` crate 패턴과 동일).
- UI 텍스트는 한국어. 분석 명령은 read-only 유지. 실험(experiment)은 GUI에 넣지 않는다.
- 새 분석 로직 금지 — 기존 함수(`xmem_windows::process_info/list_processes`, `xmem_memory::{LiveProcess, scan, ScanOptions, RegionFilters}`, `xmem_detection::detect_source`, `xmem_forensics::{collect, encode, write_file, read_file, diff, MinidumpSource, analyze_dump, ReportData, write_report}`, `xmem_windows::{free_space_bytes, write_minidump_file, open_for_dump}`)를 그대로 호출한다.
- 디자인 토큰(스펙 §5, 이 값 그대로): 다크 bg `#141517` panel `#1B1D20` card `#23262A` border `#33373D` text `#E8EAED` muted `#9AA0A6` / 라이트 bg `#F7F8FA` panel `#FFFFFF` card `#F1F3F5` border `#D7DBE0` text `#1F2328` muted `#61676D` / accent `#4C8DFF`(라이트 `#2563EB`) warn `#E8A33D`(라이트 `#B45309`) danger `#E5484D`(라이트 `#DC2626`).
- 밀도: 행 높이 20.0, item spacing (4, 4), 패널 패딩 8, 섹션 간격 12 (4/8/12/16 리듬).
- 창 최소 820×600, 기본 1200×800. 폭 < 900px → 좌측 프로세스 목록을 상단 드롭다운으로 전환.
- 종료 게이트: 각 Task 끝에 `cargo fmt --all`, `cargo check --workspace`, `cargo clippy -q --workspace --all-targets -- -D warnings`, `cargo test --workspace` 전부 통과 후 커밋.
- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스.
- 커밋 prefix: feat/fix/docs/style/test/chore + 한국어 메시지.

## Review Focus

1. **UAC 취소** — "관리자로 재시작"에서 사용자가 UAC를 거부하면 기존 창이 살아 있어야 하고 로그에 실패가 남아야 한다(크래시·창 소실 금지). → Task 1 `runas_rejects_missing_file` + Task 2 `restart_params` + Task 2 앱 배선에서 `Err`를 로그로만 처리.
2. **선택 프로세스가 조회 전에 종료** — 목록 새로고침 후 선택 PID가 사라지면 "프로세스가 종료됨"으로 표시하고 이전 화면 데이터를 비워야 한다. → Task 2 `classify_open_failure` 테스트 + Task 3 선택 처리에서 `ProcessExited` → 배너.
3. **PPL 프로세스(lsass)를 관리자로 열기** — AccessDenied가 "권한 상승 필요"가 아니라 "PPL 보호 — 관리자도 열 수 없음"으로 안내되어야 한다. → Task 2 `classify_open_failure(.., is_elevated=true)` 테스트.
4. **스캔 취소 직후** — 취소된 스캔은 부분 결과를 보여주되 "취소됨"을 표기하고, 패닉 없이 Idle로 돌아와야 한다. → Task 2 `cancelled_error_maps_to_cancelled_state` + Task 5 취소 표기.
5. **대형 프로세스 맵** — 수천 영역에서도 표는 가상화로 렌더되고, `truncated`면 경고가 보여야 한다. → Task 4 `map_shows_truncated_warning`(데이터 기반) + TableBuilder `rows` 가상화 사용.

---

### Task 1: xmem-windows — 관리자 판별과 runas 실행

**Files:**
- Create: `crates/xmem-windows/src/elevate.rs`
- Modify: `crates/xmem-windows/Cargo.toml` (feature `Win32_UI_Shell` 추가)
- Modify: `crates/xmem-windows/src/lib.rs` (모듈 등록 + 재수출)

**Interfaces:**
- Consumes: `crate::error::error_from_win32`, `crate::handle::OwnedHandle`, `windows::core::HSTRING`
- Produces (Task 2가 사용):
  - `pub fn is_elevated() -> xmem_core::Result<bool>`
  - `pub fn runas(file: &str, parameters: &str) -> xmem_core::Result<()>`

- [ ] **Step 1: Cargo feature 추가**

`crates/xmem-windows/Cargo.toml`의 windows features에 `"Win32_UI_Shell"` 추가 (`"Win32_System_Threading"` 다음, 알파벳 순서).

- [ ] **Step 2: 실패 테스트 작성**

`crates/xmem-windows/src/elevate.rs` 생성:

```rust
//! 관리자 권한 판별과 UAC 상승 재시작(runas). GUI의 "관리자로 재시작" 전용.

use std::mem::size_of;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::HSTRING;
use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_elevated_returns_bool() {
        let elevated = is_elevated().unwrap();
        let _ = elevated;
    }

    #[test]
    fn runas_rejects_missing_file() {
        let result = runas("C:\\xmem-no-such-file-9f8e7d.exe", "");
        assert!(result.is_err(), "없는 파일에 대한 runas는 실패해야 한다");
    }
}
```

- [ ] **Step 3: red 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `cannot find function is_elevated` / `runas` (E0425 ×2)

- [ ] **Step 4: 구현**

테스트 모듈 위에 추가:

```rust
/// 현재 프로세스 토큰의 상승 여부를 반환한다.
pub fn is_elevated() -> Result<bool> {
    unsafe {
        let mut raw = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw)
            .map_err(|e| error_from_win32("OpenProcessToken", &e))?;
        let token = OwnedHandle::new(raw)
            .ok_or(XmemError::InvalidHandle { handle: 0 })?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .map_err(|e| error_from_win32("GetTokenInformation", &e))?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

/// "runas" 동사로 file을 실행한다(파라미터 포함). UAC 취소/실패 시 Err.
/// ShellExecuteW는 32 이하 반환값이 실패 코드다.
pub fn runas(file: &str, parameters: &str) -> Result<()> {
    let verb = HSTRING::from("runas");
    let file_w = HSTRING::from(file);
    let params_w = HSTRING::from(parameters);
    let result = unsafe { ShellExecuteW(None, &verb, &file_w, &params_w, None, SW_SHOWNORMAL) };
    let code = result.0 as isize;
    if code <= 32 {
        Err(XmemError::WindowsApi {
            api: "ShellExecuteW",
            code: code as u32,
            message: format!("runas 실패 (code {code})"),
        })
    } else {
        Ok(())
    }
}
```

`lib.rs`에 `pub mod elevate;` (disk 다음) + 재수출 `pub use elevate::{is_elevated, runas};`

- [ ] **Step 5: green + 게이트**

Run: `cargo test -p xmem-windows` → 64/64 (기존 62 + 2), `cargo fmt --all`, `cargo clippy -q -p xmem-windows --all-targets -- -D warnings`

- [ ] **Step 6: 커밋**

```bash
git add crates/xmem-windows && git commit -m "feat(windows): 관리자 판별과 runas 실행"
```

---

### Task 2: xmem-gui 골격 — 테마·설정·태스크·앱 셸

**Files:**
- Create: `crates/xmem-gui/Cargo.toml`
- Create: `crates/xmem-gui/src/main.rs`
- Create: `crates/xmem-gui/src/app.rs`
- Create: `crates/xmem-gui/src/theme.rs`
- Create: `crates/xmem-gui/src/config.rs`
- Create: `crates/xmem-gui/src/task.rs`
- Create: `crates/xmem-gui/src/log.rs`
- Create: `crates/xmem-gui/src/views/mod.rs` (빈 모듈 선언만: `pub mod log;`)
- Modify: 루트 `Cargo.toml` (members + workspace.deps)

**Interfaces:**
- Consumes: `xmem_windows::{is_elevated, runas}`, `xmem_core::{ProcessInfo, XmemError, Result, Severity, Confidence}`
- Produces (Task 3~7이 사용):
  - `theme::{ThemeMode, Palette, palette, apply, severity_color, severity_label, confidence_dots}`
  - `config::{GuiConfig, load, save, default_output_dir, output_file_name, config_path}`
  - `task::{TaskState, BackgroundTask}` — `spawn(label, f)`, `poll()`, `take_done()`, `cancel()`, `is_running()`, `state()`
  - `log::{LogBuffer, LogEntry, LogLevel}`
  - `app::{XMemApp, Tab, OpenFailure, classify_open_failure, restart_params}`

- [ ] **Step 1: Cargo 등록**

루트 `Cargo.toml`: members에 `"crates/xmem-gui",` 추가(xmem-cli 다음), workspace.deps에 `xmem-gui = { path = "crates/xmem-gui" }` 추가.

`crates/xmem-gui/Cargo.toml`:

```toml
[package]
name = "xmem-gui"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[[bin]]
name = "xmem-gui"
path = "src/main.rs"

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
xmem-memory.workspace = true
xmem-detection.workspace = true
xmem-forensics.workspace = true
xmem-windows.workspace = true
chrono.workspace = true
serde.workspace = true
serde_json.workspace = true
tracing.workspace = true
eframe = "0.36.2"
egui_extras = "0.36.2"
rfd = "0.17.2"
```

- [ ] **Step 2: theme.rs 작성(테스트 포함)**

```rust
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
    Color32::from_rgb((hex >> 16) as u8, ((hex >> 8) & 0xff) as u8, (hex & 0xff) as u8)
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
    visuals.override_text_color = Some(p.text);
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, p.border);
    visuals.selection.bg_fill = p.accent.gamma_multiply(0.35);
    visuals.selection.stroke = egui::Stroke::new(1.0, p.accent);
    visuals.hyperlink_color = p.accent;
    ctx.set_visuals(visuals);
    ctx.style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(4.0, 4.0);
        style.spacing.button_padding = egui::vec2(8.0, 2.0);
        style.spacing.interact_size.y = 20.0;
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
```

- [ ] **Step 3: config.rs 작성(테스트 포함)**

```rust
//! `%APPDATA%\XMem\gui.json` 설정 저장/로드.

use std::path::PathBuf;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use xmem_core::{Result, XmemError};

use crate::theme::ThemeMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    pub theme: ThemeMode,
    pub window_width: f32,
    pub window_height: f32,
    pub guide_seen: bool,
    pub last_output_dir: Option<PathBuf>,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            window_width: 1200.0,
            window_height: 800.0,
            guide_seen: false,
            last_output_dir: None,
        }
    }
}

pub fn config_path() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("XMem").join("gui.json")
}

pub fn load() -> GuiConfig {
    let Ok(bytes) = std::fs::read(config_path()) else {
        return GuiConfig::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(config: &GuiConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| XmemError::Io(e))?;
    }
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|e| XmemError::JsonError { reason: e.to_string() })?;
    std::fs::write(&path, bytes).map_err(XmemError::Io)
}

/// 기본 출력 디렉터리: `%USERPROFILE%\Documents\XMem` (없으면 생성).
pub fn default_output_dir() -> PathBuf {
    let base = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("Documents").join("XMem");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// `xmem-<kind>-<pid>-<YYYYMMDD-HHMMSS>.<ext>`
pub fn output_file_name(kind: &str, pid: u32, ext: &str, now: DateTime<Local>) -> String {
    format!("xmem-{kind}-{pid}-{}.{ext}", now.format("%Y%m%d-%H%M%S"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_file_name_is_deterministic() {
        let ts = DateTime::parse_from_rfc3339("2026-09-23T10:20:30+09:00")
            .unwrap()
            .with_timezone(&Local);
        let name = output_file_name("snapshot", 4242, "xmem", ts);
        assert_eq!(name, format!("xmem-snapshot-4242-{}.xmem", ts.format("%Y%m%d-%H%M%S")));
    }

    #[test]
    fn config_roundtrips_through_json() {
        let config = GuiConfig { theme: ThemeMode::Light, guide_seen: true, ..GuiConfig::default() };
        let bytes = serde_json::to_vec(&config).unwrap();
        let back: GuiConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.theme, ThemeMode::Light);
        assert!(back.guide_seen);
        assert_eq!(back.window_width, 1200.0);
    }

    #[test]
    fn corrupt_config_falls_back_to_default() {
        let parsed: std::result::Result<GuiConfig, _> = serde_json::from_slice(b"{not json");
        assert!(parsed.is_err());
        // load()는 손상 파일에서 default를 돌려준다(위 파싱 실패가 그 근거).
    }
}
```

- [ ] **Step 4: task.rs 작성(테스트 포함)**

```rust
//! 백그라운드 태스크: 스레드 + 취소 플래그 + mpsc. UI는 poll만 한다.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use xmem_core::{Result, XmemError};

pub enum TaskState<T> {
    Idle,
    Running,
    Done(T),
    Failed(XmemError),
    Cancelled,
}

enum TaskMessage<T> {
    Done(T),
    Failed(XmemError),
}

pub struct BackgroundTask<T> {
    label: String,
    state: TaskState<T>,
    cancel: Arc<AtomicBool>,
    rx: Option<Receiver<TaskMessage<T>>>,
}

impl<T: Send + 'static> BackgroundTask<T> {
    pub fn idle() -> Self {
        Self {
            label: String::new(),
            state: TaskState::Idle,
            cancel: Arc::new(AtomicBool::new(false)),
            rx: None,
        }
    }

    pub fn spawn(label: impl Into<String>, f: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let flag = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let message = match f(&flag) {
                Ok(value) => TaskMessage::Done(value),
                Err(err) => TaskMessage::Failed(err),
            };
            let _ = tx.send(message);
        });
        Self { label: label.into(), state: TaskState::Running, cancel, rx: Some(rx) }
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn state(&self) -> &TaskState<T> {
        &self.state
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, TaskState::Running)
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// 논블로킹으로 결과를 반영한다. 상태가 바뀌면 true.
    pub fn poll(&mut self) -> bool {
        let Some(rx) = &self.rx else {
            return false;
        };
        match rx.try_recv() {
            Ok(TaskMessage::Done(value)) => {
                self.state = TaskState::Done(value);
                self.rx = None;
                true
            }
            Ok(TaskMessage::Failed(XmemError::Cancelled { .. })) => {
                self.state = TaskState::Cancelled;
                self.rx = None;
                true
            }
            Ok(TaskMessage::Failed(err)) => {
                self.state = TaskState::Failed(err);
                self.rx = None;
                true
            }
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Disconnected) => {
                self.state = TaskState::Cancelled;
                self.rx = None;
                true
            }
        }
    }

    /// Done이면 값을 꺼내고 Idle로 되돌린다.
    pub fn take_done(&mut self) -> Option<T> {
        if matches!(self.state, TaskState::Done(_)) {
            match std::mem::replace(&mut self.state, TaskState::Idle) {
                TaskState::Done(value) => Some(value),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Failed/Cancelled를 Idle로 되돌린다(사용자가 확인했을 때).
    pub fn reset(&mut self) {
        self.state = TaskState::Idle;
        self.rx = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_polled(task: &mut BackgroundTask<u32>) {
        for _ in 0..100 {
            if task.poll() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("태스크가 시간 안에 끝나지 않았다");
    }

    #[test]
    fn done_task_transitions_and_yields_value() {
        let mut task = BackgroundTask::spawn("test", |_| Ok(7u32));
        wait_polled(&mut task);
        assert!(!task.is_running());
        assert_eq!(task.take_done(), Some(7));
        assert!(matches!(task.state(), TaskState::Idle));
    }

    #[test]
    fn failed_task_stores_error() {
        let mut task: BackgroundTask<u32> =
            BackgroundTask::spawn("fail", |_| Err(XmemError::InvalidInput { reason: "x".into() }));
        wait_polled(&mut task);
        assert!(matches!(task.state(), TaskState::Failed(_)));
    }

    #[test]
    fn cancelled_error_maps_to_cancelled_state() {
        let mut task: BackgroundTask<u32> =
            BackgroundTask::spawn("cancel", |_| Err(XmemError::Cancelled { reason: "user".into() }));
        wait_polled(&mut task);
        assert!(matches!(task.state(), TaskState::Cancelled));
    }

    #[test]
    fn cancel_flag_is_visible_to_worker() {
        let mut task = BackgroundTask::spawn("flag", |flag| {
            std::thread::sleep(std::time::Duration::from_millis(30));
            Ok(flag.load(Ordering::Relaxed))
        });
        task.cancel();
        wait_polled(&mut task);
        assert_eq!(task.take_done(), Some(true));
    }
}
```

- [ ] **Step 5: log.rs 작성(테스트 포함)**

```rust
//! 오류 로그 ring buffer (최근 200건).

use std::collections::VecDeque;
use chrono::Local;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub time: String,
    pub level: LogLevel,
    pub message: String,
}

pub struct LogBuffer {
    entries: VecDeque<LogEntry>,
    capacity: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self { entries: VecDeque::new(), capacity }
    }

    pub fn push(&mut self, level: LogLevel, message: impl Into<String>) {
        self.entries.push_back(LogEntry {
            time: Local::now().format("%H:%M:%S").to_string(),
            level,
            message: message.into(),
        });
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &LogEntry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_buffer_drops_oldest() {
        let mut log = LogBuffer::new(3);
        for i in 0..5 {
            log.push(LogLevel::Info, format!("msg {i}"));
        }
        assert_eq!(log.len(), 3);
        let messages: Vec<_> = log.iter().map(|e| e.message.clone()).collect();
        assert_eq!(messages, vec!["msg 2", "msg 3", "msg 4"]);
    }

    #[test]
    fn clear_empties_buffer() {
        let mut log = LogBuffer::new(10);
        log.push(LogLevel::Error, "x");
        log.clear();
        assert!(log.is_empty());
    }
}
```

- [ ] **Step 6: app.rs + main.rs + views/mod.rs 작성(테스트 포함)**

`views/mod.rs`:

```rust
//! 탭별 화면. M13 Task 3~7에서 추가된다.
pub mod log;
```

`views/log.rs`:

```rust
//! 하단 접이식 로그 패널.

use crate::log::LogBuffer;

pub fn ui(ui: &mut egui::Ui, log: &LogBuffer, open: &mut bool) {
    egui::CollapsingHeader::new(format!("로그 ({})", log.len()))
        .open(Some(*open))
        .show(ui, |ui| {
            *open = true;
            egui::ScrollArea::vertical().max_height(140.0).show(ui, |ui| {
                if log.is_empty() {
                    ui.label(egui::RichText::new("기록된 로그가 없습니다").weak());
                }
                for entry in log.iter() {
                    let color = match entry.level {
                        crate::log::LogLevel::Info => ui.visuals().weak_text_color(),
                        crate::log::LogLevel::Warn => egui::Color32::from_rgb(0xE8, 0xA3, 0x3D),
                        crate::log::LogLevel::Error => egui::Color32::from_rgb(0xE5, 0x48, 0x4D),
                    };
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&entry.time).monospace().weak());
                        ui.label(egui::RichText::new(&entry.message).color(color));
                    });
                }
            });
        });
}
```

`app.rs`:

```rust
//! 앱 셸: 상단 바 + 좌측 프로세스 목록 자리 + 탭 + 하단 로그.

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
        Tab::Overview, Tab::Map, Tab::Scan, Tab::Modules, Tab::Threads,
        Tab::Detect, Tab::Snapshot, Tab::Dump, Tab::Report, Tab::Guide,
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
            if is_elevated { OpenFailure::Protected } else { OpenFailure::NeedsElevation }
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
    pub log_open: bool,
    pub list_task: BackgroundTask<Vec<xmem_core::ProcessInfo>>,
    pub process_filter: String,
    pub processes: Vec<xmem_core::ProcessInfo>,
}

impl XMemApp {
    pub fn new(config: GuiConfig, initial_pid: Option<u32>) -> Self {
        let mut log = LogBuffer::new(200);
        let elevated = xmem_windows::is_elevated().unwrap_or(false);
        log.push(LogLevel::Info, if elevated { "관리자 권한으로 실행 중" } else { "표준 사용자 권한" });
        let mut app = Self {
            theme: config.theme,
            config,
            is_elevated: elevated,
            tab: Tab::Overview,
            selected_pid: initial_pid,
            log,
            log_open: true,
            list_task: BackgroundTask::idle(),
            process_filter: String::new(),
            processes: Vec::new(),
        };
        app.refresh_processes();
        app
    }

    pub fn refresh_processes(&mut self) {
        self.list_task = BackgroundTask::spawn("프로세스 목록", |_| xmem_windows::list_processes());
    }

    pub fn restart_elevated(&mut self) {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let params = restart_params(self.selected_pid);
        match xmem_windows::runas(&exe, &params) {
            Ok(()) => {
                self.log.push(LogLevel::Info, "관리자 권한으로 재시작했습니다");
                std::process::exit(0);
            }
            Err(err) => {
                self.log.push(LogLevel::Error, format!("관리자 재시작 실패: {err}"));
            }
        }
    }
}

impl eframe::App for XMemApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.list_task.poll()
            && let Some(list) = self.list_task.take_done()
        {
            self.processes = list;
        }
        let palette = theme::palette(self.theme);

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("XMem").strong().size(16.0));
                let (badge, color) = if self.is_elevated {
                    ("관리자", palette.accent)
                } else {
                    ("표준 사용자", palette.muted)
                };
                ui.label(egui::RichText::new(badge).color(color));
                if !self.is_elevated
                    && ui.button("관리자로 재시작").clicked()
                {
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
                    theme::apply(ctx, self.theme);
                    let _ = crate::config::save(&self.config);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(format!("v{}", xmem_core::VERSION)).weak(),
                    );
                });
            });
        });

        egui::TopBottomPanel::bottom("log").show(ctx, |ui| {
            crate::views::log::ui(ui, &self.log, &mut self.log_open);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
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
                self.selected_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
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
        let denied = XmemError::AccessDenied { context: "OpenProcess".into() };
        assert_eq!(classify_open_failure(&denied, false, 100), OpenFailure::NeedsElevation);
        assert_eq!(classify_open_failure(&denied, true, 100), OpenFailure::Protected);
        assert_eq!(classify_open_failure(&denied, true, 4), OpenFailure::SystemProcess);
        let exited = XmemError::ProcessExited { pid: 7 };
        assert_eq!(classify_open_failure(&exited, true, 7), OpenFailure::Exited);
        let other = XmemError::InvalidAddress { address: 1 };
        assert!(matches!(classify_open_failure(&other, true, 7), OpenFailure::Other(_)));
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
```

`main.rs`:

```rust
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! XMem GUI 진입점.

mod app;
mod config;
mod log;
mod task;
mod theme;
mod views;

fn parse_pid_arg(args: &[String]) -> Option<u32> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--pid" {
            return iter.next().and_then(|value| value.parse().ok());
        }
    }
    None
}

fn load_korean_font(ctx: &egui::Context) {
    let path = std::path::Path::new("C:\\Windows\\Fonts\\malgun.ttf");
    let Ok(bytes) = std::fs::read(path) else {
        tracing::warn!("맑은 고딕을 찾지 못해 기본 폰트를 사용합니다");
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert("malgun".to_owned(), std::sync::Arc::new(egui::FontData::from_owned(bytes)));
    fonts
        .families
        .get_mut(&egui::FontFamily::Proportional)
        .expect("기본 Proportional 패밀리는 항상 존재한다")
        .insert(0, "malgun".to_owned());
    fonts
        .families
        .get_mut(&egui::FontFamily::Monospace)
        .expect("기본 Monospace 패밀리는 항상 존재한다")
        .push("malgun".to_owned());
    ctx.set_fonts(fonts);
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let initial_pid = parse_pid_arg(&args);
    let config = config::load();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("XMem — Windows Memory Analysis")
            .with_inner_size([config.window_width, config.window_height])
            .with_min_inner_size([820.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "xmem-gui",
        options,
        Box::new(move |cc| {
            load_korean_font(&cc.egui_ctx);
            theme::apply(&cc.egui_ctx, config.theme);
            Ok(Box::new(app::XMemApp::new(config, initial_pid)))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pid_arg_reads_pid() {
        let args: Vec<String> = ["xmem-gui", "--pid", "4321"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_pid_arg(&args), Some(4321));
    }

    #[test]
    fn parse_pid_arg_handles_missing_and_invalid() {
        let args: Vec<String> = ["xmem-gui"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_pid_arg(&args), None);
        let args: Vec<String> = ["xmem-gui", "--pid", "abc"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_pid_arg(&args), None);
    }
}
```

- [ ] **Step 7: 빌드·테스트·스모크**

Run: `cargo test -p xmem-gui` → theme 3 + config 3 + task 4 + log 2 + app 3 + main 2 = 17 green
Run: `cargo run -p xmem-gui` → 창이 뜨고 상단 바/탭/로그 패널이 보이는지 확인(수동), 프로세스 목록 task는 아직 표시 안 함
Run: `cargo fmt --all`, `cargo clippy -q --workspace --all-targets -- -D warnings`

- [ ] **Step 8: 커밋**

```bash
git add Cargo.toml Cargo.lock crates/xmem-gui && git commit -m "feat(gui): 앱 셸·테마·설정·태스크 기반"
```

---

### Task 3: 프로세스 목록 + 개요 탭

**Files:**
- Create: `crates/xmem-gui/src/views/process.rs`
- Create: `crates/xmem-gui/src/views/overview.rs`
- Modify: `crates/xmem-gui/src/views/mod.rs`
- Modify: `crates/xmem-gui/src/app.rs` (좌측 패널 배선, 개요 task)

**Interfaces:**
- Consumes: `app::{XMemApp, Tab, classify_open_failure}`, `task::BackgroundTask`, `config::output_file_name`
- Produces (Task 4~7이 사용):
  - `process::filter_processes(list: &[ProcessInfo], query: &str) -> Vec<usize>`
  - `process::ui(ui, app: &mut XMemApp)` — 좌측 패널(필터 + 표 + 새로고침)
  - `overview::info_rows(info: &ProcessInfo) -> Vec<(String, String)>`
  - `overview::ui(ui, app: &mut XMemApp)` — 개요 탭 + 열기 실패 배너
  - `XMemApp::open_selected(&mut self)` / `overview_task: BackgroundTask<ProcessInfo>`

- [ ] **Step 1: filter 테스트 작성**

`views/process.rs` 생성(테스트 먼저):

```rust
//! 좌측 프로세스 목록 패널.

use xmem_core::ProcessInfo;

use crate::app::XMemApp;

pub fn filter_processes(list: &[ProcessInfo], query: &str) -> Vec<usize> {
    todo!()
}

pub fn ui(_ui: &mut egui::Ui, _app: &mut XMemApp) {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::ProcessArch;

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

    #[test]
    fn filter_matches_name_case_insensitive_and_pid() {
        let list = vec![sample(10, "pwsh.exe"), sample(20, "explorer.exe")];
        assert_eq!(filter_processes(&list, "PWSH"), vec![0]);
        assert_eq!(filter_processes(&list, "explorer"), vec![1]);
        assert_eq!(filter_processes(&list, "20"), vec![1]);
        assert_eq!(filter_processes(&list, ""), vec![0, 1]);
        assert!(filter_processes(&list, "없는이름").is_empty());
    }
}
```

- [ ] **Step 2: red 확인**

Run: `cargo check -p xmem-gui --tests`
Expected: FAIL — `todo!()`는 컴파일되므로 **테스트 실행에서 실패**: `cargo test -p xmem-gui filter` → panicked at `not yet implemented`

- [ ] **Step 3: 구현**

```rust
pub fn filter_processes(list: &[ProcessInfo], query: &str) -> Vec<usize> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return (0..list.len()).collect();
    }
    list.iter()
        .enumerate()
        .filter(|(_, info)| {
            info.name.to_lowercase().contains(&query) || info.pid.to_string() == query
        })
        .map(|(index, _)| index)
        .collect()
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    ui.horizontal(|ui| {
        ui.label("프로세스");
        if ui.small_button("새로고침").clicked() {
            app.refresh_processes();
        }
        if app.list_task.is_running() {
            ui.spinner();
        }
    });
    ui.add(
        egui::TextEdit::singleline(&mut app.process_filter)
            .hint_text("이름 또는 PID 검색")
            .desired_width(f32::INFINITY),
    );
    let filtered = filter_processes(&app.processes, &app.process_filter);
    ui.label(
        egui::RichText::new(format!("{}개 / 전체 {}개", filtered.len(), app.processes.len()))
            .weak(),
    );
    ui.separator();
    let row_height = 20.0;
    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(egui_extras::Column::exact(56.0))
        .column(egui_extras::Column::initial(150.0).clip(true))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            header.col(|ui| { ui.strong("PID"); });
            header.col(|ui| { ui.strong("이름"); });
            header.col(|ui| { ui.strong("경로"); });
        })
        .body(|body| {
            body.rows(row_height, filtered.len(), |mut row| {
                let info = &app.processes[filtered[row.index()]];
                let selected = app.selected_pid == Some(info.pid);
                row.set_selected(selected);
                row.col(|ui| { ui.label(info.pid.to_string()); });
                row.col(|ui| { ui.label(&info.name); });
                row.col(|ui| {
                    ui.label(egui::RichText::new(info.image_path.as_deref().unwrap_or("-")).weak());
                });
                if row.response().clicked() {
                    app.select_process(info.pid);
                }
            });
        });
}
```

`overview.rs`:

```rust
//! 개요 탭: 선택 프로세스의 전체 정보 + 열기 실패 배너.

use xmem_core::{MemorySource, ProcessInfo, ProcessArch};

use crate::app::{classify_open_failure, OpenFailure, XMemApp};

pub fn info_rows(info: &ProcessInfo) -> Vec<(String, String)> {
    fn opt<T: std::fmt::Display>(value: &Option<T>) -> String {
        value.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "-".into())
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
        ("경로".into(), info.image_path.clone().unwrap_or_else(|| "-".into())),
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
    if app.overview_task.is_running() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(format!("PID {pid} 정보 조회 중..."));
        });
        return;
    }
    match app.overview_task.state() {
        crate::task::TaskState::Failed(err) => {
            let failure = classify_open_failure(err, app.is_elevated, pid);
            failure_banner(ui, app, &failure);
            return;
        }
        crate::task::TaskState::Cancelled => {
            ui.label(egui::RichText::new("조회가 취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    let Some(info) = app.overview_info.as_ref() else {
        ui.label(egui::RichText::new("정보를 불러오는 중...").weak());
        return;
    };
    ui.heading(format!("{} ({})", info.name, info.pid));
    ui.add_space(4.0);
    egui::Grid::new("overview_grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        for (label, value) in info_rows(info) {
            ui.label(egui::RichText::new(label).weak());
            ui.label(value);
            ui.end_row();
        }
    });
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("탐지 실행").clicked() {
            app.tab = crate::app::Tab::Detect;
            app.start_detect();
        }
        if ui.button("스냅샷 생성").clicked() {
            app.tab = crate::app::Tab::Snapshot;
        }
        if ui.button("덤프 생성").clicked() {
            app.tab = crate::app::Tab::Dump;
        }
        if ui.button("리포트 저장").clicked() {
            app.tab = crate::app::Tab::Report;
        }
    });
}

pub fn failure_banner(ui: &mut egui::Ui, app: &mut XMemApp, failure: &OpenFailure) {
    let palette = crate::theme::palette(app.theme);
    ui.label(egui::RichText::new(failure.message()).color(palette.danger));
    if matches!(failure, OpenFailure::NeedsElevation) && ui.button("관리자로 재시작").clicked() {
        app.restart_elevated();
    }
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
```

- [ ] **Step 4: app.rs 배선**

`XMemApp`에 필드 추가:

```rust
pub overview_task: BackgroundTask<xmem_core::ProcessInfo>,
pub overview_info: Option<xmem_core::ProcessInfo>,
```

`XMemApp::new`에서 `overview_task: BackgroundTask::idle(), overview_info: None,` 초기화. `new` 끝에서 `if let Some(pid) = initial_pid { app.select_process(pid); }`.

메서드 추가:

```rust
pub fn select_process(&mut self, pid: u32) {
    self.selected_pid = Some(pid);
    self.overview_info = None;
    self.overview_task = BackgroundTask::spawn("프로세스 정보", move |_| xmem_windows::process_info(pid));
}

pub fn start_detect(&mut self) {
    self.detect_task = BackgroundTask::spawn("탐지", move |_| {
        let live = xmem_memory::LiveProcess::open(pid)?;
        xmem_detection::detect_source(&live)
    });
}
```

(위 `start_detect`는 Task 6에서 정의할 `detect_task` 필드를 먼저 추가하는 것이므로, Task 6에서 완성한다. **Task 3에서는 `start_detect`/`detect_task` 없이 개요의 빠른 액션 버튼은 탭 전환만 한다.**)

`update()`의 `list_task.poll()` 블록 뒤에 추가:

```rust
if self.overview_task.poll()
    && let Some(info) = self.overview_task.take_done()
{
    self.overview_info = Some(info);
}
```

좌측 패널 추가 (`CentralPanel` 앞):

```rust
egui::SidePanel::left("processes")
    .resizable(true)
    .default_width(300.0)
    .width_range(220.0..=360.0)
    .show(ctx, |ui| {
        crate::views::process::ui(ui, self);
    });
```

좁은 창 대응: `ctx.screen_rect().width() < 900.0`이면 SidePanel 대신 중앙 패널 상단에 `egui::ComboBox`로 프로세스 선택을 표시:

```rust
let narrow = ctx.screen_rect().width() < 900.0;
```

(좁은 경우 `ComboBox::from_label("프로세스")`에서 `selected_text`를 현재 프로세스 이름으로, 각 항목 클릭 시 `select_process`.)

중앙 패널 탭 렌더링:

```rust
match self.tab {
    Tab::Overview => crate::views::overview::ui(ui, self),
    _ => {
        ui.label(egui::RichText::new("이 탭은 다음 Task에서 채워집니다").weak());
    }
}
```

- [ ] **Step 5: 테스트 + 스모크**

Run: `cargo test -p xmem-gui` → 17 + 2(filter 1 + info_rows 1) = 19 green
Run: `cargo run -p xmem-gui` → 목록 로드·검색·선택 → 개요 표시(수동). 관리자 아닐 때 lsass 선택 → "관리자로 재시작" 배너 확인.
Run: `cargo fmt --all`, `cargo clippy -q --workspace --all-targets -- -D warnings`

- [ ] **Step 6: 커밋**

```bash
git add crates/xmem-gui && git commit -m "feat(gui): 프로세스 목록과 개요 탭"
```

---

### Task 4: 메모리맵·모듈·스레드 탭

**Files:**
- Create: `crates/xmem-gui/src/views/map.rs`
- Create: `crates/xmem-gui/src/views/modules.rs`
- Create: `crates/xmem-gui/src/views/threads.rs`
- Modify: `crates/xmem-gui/src/views/mod.rs`, `crates/xmem-gui/src/app.rs`

**Interfaces:**
- Consumes: `xmem_memory::{LiveProcess, RegionFilters, RegionMap}`, `xmem_core::{MemorySource, MemoryRegion, RegionClass, Heuristic, ModuleInfo, ThreadInfo}`
- Produces (Task 5~7이 사용):
  - `map::{MapSort, select_and_sort(regions, &RegionFilters, MapSort) -> Vec<usize>, heur_tag(Heuristic) -> &'static str, human_size(u64) -> String, opt_hex(Option<u64>) -> String}`
  - `map::ui`, `modules::ui`, `threads::ui`
  - `XMemApp` 필드: `map_task: BackgroundTask<RegionMap>`, `map: Option<RegionMap>`, `map_filters: RegionFilters`, `map_sort: MapSort`, `modules_task/modules`, `threads_task/threads`

- [ ] **Step 1: map.rs 테스트 먼저 작성**

```rust
//! 메모리맵 탭.

use xmem_core::{Heuristic, MemoryRegion, RegionClass};
use xmem_memory::RegionFilters;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSort {
    AddressAsc,
    AddressDesc,
    SizeDesc,
}

pub fn heur_tag(h: Heuristic) -> &'static str {
    todo!()
}

pub fn human_size(bytes: u64) -> String {
    todo!()
}

pub fn opt_hex(value: Option<u64>) -> String {
    todo!()
}

pub fn select_and_sort(regions: &[MemoryRegion], filters: &RegionFilters, sort: MapSort) -> Vec<usize> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, Protection};

    fn region(base: u64, size: u64, class: RegionClass, exec: bool) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            state: MemoryState::Commit,
            protection: Protection::new(if exec { 0x20 } else { 0x04 }, true, !exec, exec),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: !exec,
            executable: exec,
            classification: class,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    #[test]
    fn heur_tags_are_short() {
        assert_eq!(heur_tag(Heuristic::ExecutablePrivate), "exec-private");
        assert_eq!(heur_tag(Heuristic::ExecutableAnonymous), "exec-anon");
        assert_eq!(heur_tag(Heuristic::PrivateExecutablePeLike), "pe-like");
        assert_eq!(heur_tag(Heuristic::WritableExecutable), "wx");
    }

    #[test]
    fn human_size_scales_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(4096), "4.0 KiB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn select_and_sort_filters_and_orders() {
        let regions = vec![
            region(0x3000, 0x1000, RegionClass::Private, false),
            region(0x1000, 0x4000, RegionClass::Image, true),
            region(0x2000, 0x2000, RegionClass::Private, true),
        ];
        let all = RegionFilters::default();
        assert_eq!(select_and_sort(&regions, &all, MapSort::AddressAsc), vec![1, 2, 0]);
        assert_eq!(select_and_sort(&regions, &all, MapSort::AddressDesc), vec![0, 2, 1]);
        assert_eq!(select_and_sort(&regions, &all, MapSort::SizeDesc), vec![1, 2, 0]);
        let exec_only = RegionFilters { executable_only: true, ..RegionFilters::default() };
        assert_eq!(select_and_sort(&regions, &exec_only, MapSort::AddressAsc), vec![1, 2]);
    }
}
```

- [ ] **Step 2: red 확인 → 구현**

Run: `cargo test -p xmem-gui map` → FAIL(`todo!`)

구현:

```rust
pub fn heur_tag(h: Heuristic) -> &'static str {
    match h {
        Heuristic::ExecutablePrivate => "exec-private",
        Heuristic::ExecutableAnonymous => "exec-anon",
        Heuristic::PrivateExecutablePeLike => "pe-like",
        Heuristic::WritableExecutable => "wx",
    }
}

pub fn human_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let value = bytes as f64;
    if value < KIB {
        format!("{bytes} B")
    } else if value < KIB * KIB {
        format!("{:.1} KiB", value / KIB)
    } else if value < KIB * KIB * KIB {
        format!("{:.1} MiB", value / (KIB * KIB))
    } else {
        format!("{:.1} GiB", value / (KIB * KIB * KIB))
    }
}

pub fn opt_hex(value: Option<u64>) -> String {
    value.map(|v| format!("{v:#018x}")).unwrap_or_else(|| "-".into())
}

pub fn select_and_sort(regions: &[MemoryRegion], filters: &RegionFilters, sort: MapSort) -> Vec<usize> {
    let mut indices: Vec<usize> = regions
        .iter()
        .enumerate()
        .filter(|(_, region)| {
            if filters.executable_only && !region.executable {
                return false;
            }
            if filters.private_only && region.classification != RegionClass::Private {
                return false;
            }
            if filters.writable_only && !region.writable {
                return false;
            }
            if let Some((start, end)) = filters.range
                && (region.base.saturating_add(region.size) <= start || region.base >= end)
            {
                return false;
            }
            if let Some(max) = filters.max_region_size
                && region.size > max
            {
                return false;
            }
            true
        })
        .map(|(index, _)| index)
        .collect();
    match sort {
        MapSort::AddressAsc => indices.sort_by_key(|&i| regions[i].base),
        MapSort::AddressDesc => {
            indices.sort_by_key(|&i| std::cmp::Reverse(regions[i].base));
        }
        MapSort::SizeDesc => {
            indices.sort_by_key(|&i| (std::cmp::Reverse(regions[i].size), regions[i].base));
        }
    }
    indices
}
```

- [ ] **Step 3: map::ui + modules::ui + threads::ui**

`map::ui(ui, app)` — 툴바(새로고침/필터 체크박스/정렬 ComboBox) + 요약 행 + `truncated` 경고 + 표:

```rust
pub fn ui(ui: &mut egui::Ui, app: &mut crate::app::XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    ui.horizontal(|ui| {
        if ui.button("맵 새로고침").clicked() {
            app.start_map(pid);
        }
        if app.map_task.is_running() {
            ui.spinner();
            ui.label("메모리 영역 열거 중...");
        }
        ui.separator();
        ui.checkbox(&mut app.map_filters.executable_only, "실행 가능만");
        ui.checkbox(&mut app.map_filters.private_only, "Private만");
        ui.checkbox(&mut app.map_filters.writable_only, "쓰기 가능만");
        ui.separator();
        egui::ComboBox::from_id_salt("map_sort")
            .selected_text(match app.map_sort {
                MapSort::AddressAsc => "주소 ↑",
                MapSort::AddressDesc => "주소 ↓",
                MapSort::SizeDesc => "크기 ↓",
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut app.map_sort, MapSort::AddressAsc, "주소 ↑");
                ui.selectable_value(&mut app.map_sort, MapSort::AddressDesc, "주소 ↓");
                ui.selectable_value(&mut app.map_sort, MapSort::SizeDesc, "크기 ↓");
            });
    });
    match app.map_task.state() {
        crate::task::TaskState::Failed(err) => {
            let failure = crate::app::classify_open_failure(err, app.is_elevated, pid);
            crate::views::overview::failure_banner(ui, app, &failure);
            return;
        }
        crate::task::TaskState::Cancelled => {
            ui.label(egui::RichText::new("취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    let Some(map) = app.map.as_ref() else {
        ui.label(egui::RichText::new("맵을 불러오는 중...").weak());
        return;
    };
    if map.truncated {
        ui.label(
            egui::RichText::new("영역 수 상한(1,048,576)에 도달해 일부만 표시됩니다")
                .color(crate::theme::palette(app.theme).warn),
        );
    }
    let selected = select_and_sort(&map.regions, &app.map_filters, app.map_sort);
    ui.label(egui::RichText::new(format!("{}개 영역 표시", selected.len())).weak());
    let palette = crate::theme::palette(app.theme);
    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(egui_extras::Column::exact(140.0))
        .column(egui_extras::Column::exact(80.0))
        .column(egui_extras::Column::exact(90.0))
        .column(egui_extras::Column::exact(90.0))
        .column(egui_extras::Column::exact(120.0))
        .column(egui_extras::Column::exact(90.0))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            for title in ["BASE", "SIZE", "STATE", "TYPE", "PROTECTION", "CLASS", "HEURISTICS / FILE"] {
                header.col(|ui| { ui.strong(title); });
            }
        })
        .body(|body| {
            body.rows(20.0, selected.len(), |mut row| {
                let region = &map.regions[selected[row.index()]];
                row.col(|ui| { ui.label(opt_hex(Some(region.base))); });
                row.col(|ui| { ui.label(human_size(region.size)); });
                row.col(|ui| { ui.label(format!("{:?}", region.state).to_uppercase()); });
                row.col(|ui| {
                    ui.label(region.region_type.map(|t| format!("{t:?}").to_uppercase()).unwrap_or_else(|| "-".into()));
                });
                row.col(|ui| { ui.label(region.protection.to_string()); });
                row.col(|ui| { ui.label(format!("{:?}", region.classification).to_lowercase()); });
                row.col(|ui| {
                    let mut text = region
                        .heuristics
                        .iter()
                        .map(|h| heur_tag(*h))
                        .collect::<Vec<_>>()
                        .join(",");
                    if text.is_empty() {
                        text = "-".into();
                    }
                    let color = if region.heuristics.is_empty() { palette.muted } else { palette.warn };
                    ui.label(egui::RichText::new(text).color(color));
                });
            });
        });
}
```

`modules::ui` — 표(BASE/SIZE/NAME/PATH) + `--pe` 체크박스(체크 시 PE 요약 열: MACHINE/ENTRY/SECTIONS). PE 수집은 `xmem_pe::parse_pe`로 4 KiB 프리픽스 파싱(CLI `collect_pe`와 동일 로직을 gui에 복제 — 20줄). `threads::ui` — 표(TID/PRIORITY/START ADDRESS/REGION/MODULE), `opt_hex`/숫자 포맷 재사용.

`views/mod.rs`:

```rust
pub mod log;
pub mod map;
pub mod modules;
pub mod overview;
pub mod process;
pub mod threads;
```

- [ ] **Step 4: app.rs 배선**

필드/초기화/폴링 추가:

```rust
pub map_task: BackgroundTask<xmem_memory::RegionMap>,
pub map: Option<xmem_memory::RegionMap>,
pub map_filters: xmem_memory::RegionFilters,
pub map_sort: MapSort,
pub modules_task: BackgroundTask<Vec<xmem_core::ModuleInfo>>,
pub modules: Option<Vec<xmem_core::ModuleInfo>>,
pub threads_task: BackgroundTask<Vec<xmem_core::ThreadInfo>>,
pub threads: Option<Vec<xmem_core::ThreadInfo>>,
```

```rust
pub fn start_map(&mut self, pid: u32) {
    self.map = None;
    self.map_task = BackgroundTask::spawn("메모리맵", move |_| {
        xmem_memory::LiveProcess::open(pid)?.region_map()
    });
}
pub fn start_modules(&mut self, pid: u32) { /* LiveProcess::open(pid)?.modules() */ }
pub fn start_threads(&mut self, pid: u32) { /* LiveProcess::open(pid)?.threads() */ }
```

탭 전환 시 자동 시작(각 탭에서 데이터가 None이고 task가 Idle이면 시작):

```rust
match self.tab {
    Tab::Map if self.map.is_none() && !self.map_task.is_running() => self.start_map(pid),
    Tab::Modules if self.modules.is_none() && !self.modules_task.is_running() => self.start_modules(pid),
    Tab::Threads if self.threads.is_none() && !self.threads_task.is_running() => self.start_threads(pid),
    _ => {}
}
```

- [ ] **Step 5: 테스트 + 스모크**

Run: `cargo test -p xmem-gui` → 19 + 3 = 22 green
Run: `cargo run -p xmem-gui` → 자기 PID 선택 → 메모리맵(수천 영역, 필터/정렬), 모듈 156개, 스레드 표시(수동)
Run: `cargo fmt --all`, `cargo clippy -q --workspace --all-targets -- -D warnings`

- [ ] **Step 6: 커밋**

```bash
git add crates/xmem-gui && git commit -m "feat(gui): 메모리맵·모듈·스레드 탭"
```

---

### Task 5: 검색 탭 + 주소 미리보기

**Files:**
- Create: `crates/xmem-gui/src/views/scan.rs`
- Modify: `crates/xmem-gui/src/views/mod.rs`, `crates/xmem-gui/src/app.rs`

**Interfaces:**
- Consumes: `xmem_memory::{scan, ScanOptions, ScanReport, ScanMatch, LiveProcess, DEFAULT_MAX_RESULTS}`, `xmem_core::{ScanPattern, MemorySource}`, `map::{human_size, opt_hex}`
- Produces:
  - `scan::{hex_dump(bytes: &[u8], base: u64) -> String, preview_range(address: u64, region_size: u64) -> (u64, usize), build_options(ui_state) -> Result<ScanOptions>}`
  - `scan::ui`, `XMemApp::{scan_task, scan_report, start_scan, scan_pattern_text, scan_kind, scan_preview}`

- [ ] **Step 1: 테스트 먼저**

```rust
//! 검색 탭: needle 입력 + 필터 + 결과 표 + 주소 미리보기.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedleKind {
    Pattern,
    Ascii,
    Wide,
}

pub fn hex_dump(bytes: &[u8], base: u64) -> String {
    todo!()
}

/// 미리보기 범위: 주소 ±64바이트, 영역 경계로 클램프.
pub fn preview_range(address: u64, region_base: u64, region_size: u64) -> (u64, usize) {
    todo!()
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
}
```

- [ ] **Step 2: red → 구현**

```rust
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
            let ch = if (0x20..0x7f).contains(byte) { *byte as char } else { '.' };
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
```

- [ ] **Step 3: scan::ui 구현**

UI 상태 → 옵션:

```rust
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

pub fn build_pattern(state: &ScanUiState) -> xmem_core::Result<xmem_core::ScanPattern> {
    let needle = state.needle.trim();
    if needle.is_empty() {
        return Err(xmem_core::XmemError::InvalidInput { reason: "검색어를 입력하세요".into() });
    }
    match state.kind {
        NeedleKind::Pattern => xmem_core::ScanPattern::hex(needle),
        NeedleKind::Ascii => xmem_core::ScanPattern::ascii(needle),
        NeedleKind::Wide => xmem_core::ScanPattern::wide(needle),
    }
}

pub fn build_options(state: &ScanUiState) -> xmem_memory::ScanOptions {
    xmem_memory::ScanOptions {
        filters: xmem_memory::RegionFilters {
            executable_only: state.executable_only,
            private_only: state.private_only,
            writable_only: state.writable_only,
            range: None,
            max_region_size: None,
            all: false,
        },
        chunk_size: xmem_memory::DEFAULT_CHUNK_SIZE,
        threads: state.threads.max(1),
        max_results: state.max_results,
        offset: None,
    }
}
```

`ui`: needle `TextEdit` + 라디오 3종 + 필터 체크박스 + max-results/threads `DragValue` + "검색" 버튼(태스크 spawn) + 취소 버튼(스피너와 함께) + 결과 표(ADDRESS/OFFSET/CLASS/PROTECTION/REGION/FILE — CLI `render_scan`과 동일 열) + 행 클릭 시:

```rust
let (start, len) = preview_range(match_.address, match_.region_base, match_.region_size);
if len > 0
    && let Ok(live) = xmem_memory::LiveProcess::open(pid)
{
    let mut buf = vec![0u8; len];
    match live.read(start, &mut buf) {
        Ok(outcome) if outcome.bytes_read > 0 => {
            state.preview = Some((start, hex_dump(&buf[..outcome.bytes_read], start)));
        }
        Ok(_) => app.log.push(LogLevel::Warn, "미리보기: 0바이트를 읽었습니다"),
        Err(err) => app.log.push(LogLevel::Warn, format!("미리보기 실패: {err}")),
    }
}
```

미리보기 패널: `egui::ScrollArea::vertical().max_height(180.0)` + monospace `Label`(`hex_dump` 문자열).

취소: `app.scan_task.cancel()` → `scan()`이 `Cancelled` 반환 → TaskState::Cancelled → "취소됨(부분 결과 N건)" 표기.

- [ ] **Step 4: app.rs 배선 + 테스트 + 스모크**

Run: `cargo test -p xmem-gui` → 22 + 2 = 24 green
Run: `cargo run -p xmem-gui` → 자기 PID → 검색 `pwsh`(ASCII) → 결과 클릭 → hex 미리보기, 취소 동작(수동)
Run: `cargo fmt --all`, `cargo clippy -q --workspace --all-targets -- -D warnings`

- [ ] **Step 5: 커밋**

```bash
git add crates/xmem-gui && git commit -m "feat(gui): 메모리 검색과 주소 미리보기"
```

---

### Task 6: 탐지·스냅샷 탭

**Files:**
- Create: `crates/xmem-gui/src/views/detect.rs`
- Create: `crates/xmem-gui/src/views/snapshot.rs`
- Modify: `crates/xmem-gui/src/views/mod.rs`, `crates/xmem-gui/src/app.rs`

**Interfaces:**
- Consumes: `xmem_detection::detect_source`, `xmem_forensics::{collect, CollectOptions, encode, write_file, read_file, diff, SnapshotDiff}`, `xmem_windows::free_space_bytes`, `xmem_memory::LiveProcess`, `theme::{severity_color, severity_label, confidence_dots}`, `config::{default_output_dir, output_file_name}`
- Produces:
  - `detect::ui(ui, app)` + `XMemApp::{detect_task, findings, start_detect}`
  - `snapshot::{create_snapshot_file(pid, path, cancel) -> Result<u64>, ui(ui, app)}` + `XMemApp::{snapshot_create_task, snapshot_diff_task, snapshot_output, snapshot_before, snapshot_after, snapshot_diff}`

- [ ] **Step 1: create_snapshot_file 테스트 먼저**

`snapshot.rs`:

```rust
//! 스냅샷 탭: 생성(진행/취소) + diff.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use xmem_core::{Result, XmemError};
use xmem_forensics::{CollectOptions, collect, encode, write_file};

const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

/// CLI `create_snapshot_file`과 동일한 파이프라인(수집→인코딩→디스크 검사→원자적 저장).
pub fn create_snapshot_file(pid: u32, output: &Path, cancel: &AtomicBool) -> Result<u64> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_snapshot_of_self_writes_valid_file() {
        let dir = std::env::temp_dir().join(format!("xmem-gui-snap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.xmem");
        let cancel = AtomicBool::new(false);
        let bytes = create_snapshot_file(std::process::id(), &path, &cancel).unwrap();
        assert!(bytes > 0);
        let envelope = xmem_forensics::read_file(&path).unwrap();
        assert_eq!(envelope.process.pid, std::process::id());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 2: red → 구현**

Run: `cargo test -p xmem-gui snapshot` → FAIL(`todo!`)

```rust
pub fn create_snapshot_file(pid: u32, output: &Path, cancel: &AtomicBool) -> Result<u64> {
    let live = xmem_memory::LiveProcess::open(pid)?;
    let envelope = collect(&live, &CollectOptions::default(), cancel)?;
    let bytes = encode(&envelope)?;
    let dir = output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let free = xmem_windows::free_space_bytes(&dir.to_string_lossy())?;
    let needed = bytes.len() as u64 + DISK_MARGIN_BYTES;
    if free < needed {
        return Err(XmemError::SnapshotError {
            reason: format!("디스크 공간 부족: 필요 {needed}, 가용 {free}"),
        });
    }
    write_file(&envelope, output)
}
```

- [ ] **Step 3: detect::ui + snapshot::ui**

`detect::ui`: 스피너/취소 + findings 수 요약 + "0건 ≠ 안전" 문구 + 목록(severity 색 배지 + rule/name + confidence dots) + 선택 상세(evidence observed 표, heuristic, interpretation). severity 색은 `theme::severity_color`.

`snapshot::ui`: 
- 생성: 출력 경로 `TextEdit` + "찾아보기"(rfd save_file, 기본 파일명 `output_file_name("snapshot", pid, "xmem", Local::now())`, 기본 디렉터리 `default_output_dir()`) + "생성" 버튼 + 스피너/취소 + 완료 시 로그+요약.
- diff: before/after 경로 각각 `TextEdit` + rfd `pick_file` + "비교" 버튼 + 요약 행(`regions: +N -N ~N | content ~N | modules ... | threads ... | detections ...`) + 변화 목록(CLI `render_diff`와 동일 라인 포맷: `+`/`-`/`~`).

- [ ] **Step 4: app.rs 배선 + 테스트 + 스모크**

Run: `cargo test -p xmem-gui` → 24 + 1 = 25 green
Run: `cargo run -p xmem-gui` → 자기 PID 탐지(100여 findings), 스냅샷 2회 생성 → diff(수동)
Run: `cargo fmt --all`, `cargo clippy -q --workspace --all-targets -- -D warnings`

- [ ] **Step 5: 커밋**

```bash
git add crates/xmem-gui && git commit -m "feat(gui): 탐지와 스냅샷 탭"
```

---

### Task 7: 덤프·리포트·가이드 탭

**Files:**
- Create: `crates/xmem-gui/src/views/dump.rs`
- Create: `crates/xmem-gui/src/views/report.rs`
- Create: `crates/xmem-gui/src/views/guide.rs`
- Modify: `crates/xmem-gui/src/views/mod.rs`, `crates/xmem-gui/src/app.rs`

**Interfaces:**
- Consumes: `xmem_windows::{open_for_dump, process_info, write_minidump_file, free_space_bytes}`, `xmem_forensics::{MinidumpSource, analyze_dump, ReportData, write_report, detect?}`, `xmem_detection::detect_source`, `config::{default_output_dir, output_file_name}`
- Produces:
  - `dump::{full_dump_blocked(commit_bytes: u64, free_bytes: u64) -> Option<String>, ui(ui, app)}`
  - `report::{build_report_data(pid) -> Result<ReportData>, ui(ui, app)}`
  - `guide::{guide_steps() -> Vec<(&'static str, &'static str)>, SAFETY_LINES: [&'static str; 4], ui(ui, app)}`

- [ ] **Step 1: 테스트 먼저(3종)**

```rust
// dump.rs
/// --full 시작 전 검사: 부족하면 차단 사유 문자열.
pub fn full_dump_blocked(commit_bytes: u64, free_bytes: u64) -> Option<String> {
    todo!()
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
```

```rust
// guide.rs
pub fn guide_steps() -> Vec<(&'static str, &'static str)> {
    todo!()
}
pub const SAFETY_LINES: [&str; 4] = [
    "XMem은 분석 도구입니다. 메모리를 변경하지 않습니다(실험은 CLI 전용).",
    "보호 프로세스는 관리자 권한으로도 열 수 없습니다(PPL).",
    "탐지 결과 0건은 안전을 의미하지 않습니다.",
    "분석 대상은 신뢰할 수 있는 프로세스로 한정하세요.",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guide_has_five_steps_and_safety() {
        let steps = guide_steps();
        assert_eq!(steps.len(), 5);
        assert!(steps.iter().any(|(title, _)| title.contains("프로세스")));
        assert!(SAFETY_LINES.iter().any(|line| line.contains("0건")));
    }
}
```

```rust
// report.rs
#[test]
fn report_data_of_self_has_regions_and_summary() {
    let data = build_report_data(std::process::id()).unwrap();
    assert!(!data.regions.is_empty());
    assert_eq!(data.summary.regions_total, data.regions.len());
}
```

- [ ] **Step 2: red → 구현**

```rust
// dump.rs
pub fn full_dump_blocked(commit_bytes: u64, free_bytes: u64) -> Option<String> {
    let needed = commit_bytes.saturating_add(DISK_MARGIN_BYTES);
    if free_bytes < needed {
        Some(format!(
            "전체 메모리 덤프에는 약 {} 필요(가용 {}). 디스크 공간이 부족합니다",
            crate::views::map::human_size(needed),
            crate::views::map::human_size(free_bytes)
        ))
    } else {
        None
    }
}
```

```rust
// report.rs
pub fn build_report_data(pid: u32) -> Result<xmem_forensics::ReportData> {
    let live = xmem_memory::LiveProcess::open(pid)?;
    let regions = live.region_map()?.regions;
    let modules = live.modules()?;
    let threads = live.threads()?;
    let findings = xmem_detection::detect_source(&live)?;
    Ok(xmem_forensics::ReportData::new(
        live.info.clone(), regions, modules, threads, findings,
    ))
}
```

`guide::guide_steps()` — 5단계(스펙 §10): ① 프로세스 고르기 ② "탐지" 실행 ③ 결과 읽는 법(Observed/Evidence/Heuristic/Confidence, 0건≠안전) ④ 스냅샷 전/후 Diff ⑤ 리포트 저장.

`dump::ui`: 
- 생성: `--full` 체크박스 + 경고(체크 시 `process_info(pid).memory_stats.commit`과 `free_space_bytes`로 `full_dump_blocked` → Some이면 danger 색 문구 + 생성 버튼 비활성) + 경로(기본 `output_file_name("dump", pid, "dmp", now)`) + "생성" 버튼 + **진행 중에는 "취소 불가(완료까지 대기)" 문구 + 스피너** + 완료 요약.
- 분석: 경로 + rfd `pick_file` + "분석" → `MinidumpSource::open` → `detect_source` + `analysis()` 요약(regions/modules/threads/findings) 표시.

`report::ui`: 형식 라디오(JSON/Markdown) + 경로(기본 `output_file_name("report", pid, "json"|"md", now)`) + "저장" → `build_report_data` → `write_report`(백그라운드) + 완료 시 크기 로그.

- [ ] **Step 3: app.rs 배선 + 테스트 + 스모크**

Run: `cargo test -p xmem-gui` → 25 + 4 = 29 green
Run: `cargo run -p xmem-gui` → 덤프 생성/분석, 리포트 json/md 저장, 가이드 5단계(수동)
Run: `cargo fmt --all`, `cargo clippy -q --workspace --all-targets -- -D warnings`

- [ ] **Step 4: 커밋**

```bash
git add crates/xmem-gui && git commit -m "feat(gui): 덤프·리포트·가이드 탭"
```

---

### Task 8: 문서 + 전체 게이트 + GUI 스모크

**Files:**
- Modify: `README.md`, `docs/architecture.md`, `docs/gui-design.md` (상태 갱신), 이 계획서(체크박스)

**Interfaces:**
- Consumes: 전체
- Produces: 최종 문서·게이트

- [ ] **Step 1: README 갱신**

- Status 문구 → "Milestone 13 (GUI) 완료. `xmem-gui`로 분석 기능 전체를 GUI에서 사용할 수 있다."
- Status 표에 `GUI (xmem-gui)` 행 Implemented: 프로세스 목록/개요·메모리맵·검색(+hex 미리보기)·모듈·스레드·탐지·스냅샷·덤프·리포트, 관리자 재시작, 가이드, 로그 패널, 다크/라이트.
- Quick Start에 `cargo run -p xmem-gui --release` (또는 `cargo build --release -p xmem-gui`) 1줄.
- Limitations에 GUI 항목: 실험 없음(CLI 전용), 덤프 생성 취소 불가, PPL은 관리자도 불가, 검색 진행률 미표시.
- Roadmap M13 완료.

- [ ] **Step 2: architecture.md 갱신**

- crate 표에 `crates/xmem-gui` 행 추가(책임: egui GUI, 기존 crate 직접 호출, unsafe 없음 / M13 생성됨).
- dependency 표: eframe/egui_extras/rfd 0.36/0.17 도입(M13, xmem-gui 전용), windows feature `Win32_UI_Shell` 추가(M13).
- Windows API M13 행: `ShellExecuteW(runas)`, `GetTokenInformation(TokenElevation)` — 구현됨(xmem-windows::elevate).
- §14 Status: M13 Done + "M14+ | 계획 없음".

- [ ] **Step 3: gui-design.md 상태 갱신**

`> 상태: 설계 승인 완료(2026-09-23) → 구현 계획 작성 대기` → `> 상태: 구현 완료(M13, 2026-09-23)` + 계획 링크.

- [ ] **Step 4: 전체 게이트**

Run:
```
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | Out-File -Encoding utf8 "$env:TEMP\opencode\xmem-m13-tests.log"
```
Expected: 전부 통과. 테스트 총계 = 기존 230 + windows 2 + gui 29 = **261** (로그에서 확인).

- [ ] **Step 5: GUI 스모크(수동, 실측 기록)**

Run: `cargo build --release -p xmem-gui` 후 `.\target\release\xmem-gui.exe`
확인 항목: ① 창 부팅(한글 폰트 정상) ② 목록 로드 ③ 자기 PID 선택 → 개요/맵/모듈/스레드/검색/탐지/스냅샷/덤프/리포트/가이드 각 탭 ④ 관리자 배지 ⑤ 로그 패널 ⑥ 창 폭 900px 미만 드롭다운 전환 ⑦ 종료 시 `%APPDATA%\XMem\gui.json` 생성 확인.
Run: `.\target\release\xmem-gui.exe --pid <자기PID>` → 개요에 해당 PID 표시.

- [ ] **Step 6: 체크박스 + 커밋**

이 계획서의 `- [ ]` → `- [x]` 치환 후:

```bash
git add README.md docs/architecture.md docs/gui-design.md docs/plans/milestone-13-gui.md
git commit -m "docs: M13 GUI 상태 반영"
```

---

## Self-Review Notes

- **Spec coverage**: 스펙 §2 포함 항목 전부 Task 3~7에 매핑(프로세스/개요/맵/검색+미리보기/모듈/스레드/탐지/스냅샷/dump/리포트/가이드/로그/설정/권한/반응형). §7 취소 규칙 → Task 5(스캔)·Task 6(스냅샷) + Task 7 덤프 취소 불가 문구. §8 실패 사유 → Task 2 `classify_open_failure` + Task 3 배너. §9 파일 저장 → Task 2 `output_file_name` + Task 6/7 rfd. §11 로그 → Task 2. §13 실측 목록 → 계획 작성 전 전부 검증 완료(eframe/egui/egui_extras/rfd 버전, TableBuilder `rows`/`Column` API, `run_native`/`AppCreator`/`ViewportBuilder`, `FontData::from_owned`/`FontDefinitions.font_data: BTreeMap<String, Arc<FontData>>`, `ShellExecuteW`/`SW_SHOWNORMAL`/`TOKEN_ELEVATION`, rfd `FileDialog`).
- **Placeholder scan**: `todo!()`는 TDD red 단계의 의도된 실패 구현이며 각 Step에서 즉시 실제 구현으로 교체된다. 그 외 TBD/TODO 없음. Task 4 Step 3의 modules PE 수집은 "CLI collect_pe와 동일 로직 복제(20줄)"로 명시했으나 구현 시 CLI `crates/xmem-cli/src/commands/modules.rs::collect_pe`를 읽고 그대로 옮긴다.
- **Type consistency**: `BackgroundTask<T>`/`TaskState<T>`, `OpenFailure`, `MapSort`, `NeedleKind`, `create_snapshot_file`, `full_dump_blocked`, `build_report_data`, `guide_steps` 시그니처가 Task 간 일치. `RegionFilters`는 `xmem_memory`의 실제 구조체(executable_only/private_only/writable_only/range/max_region_size/all)를 사용.
- **Review Focus 테스트 배치**: ① Task 1 `runas_rejects_missing_file` + Task 2 `restart_params` ② Task 2 `classify_open_failure`(Exited) ③ Task 2 `classify_open_failure`(elevated→Protected) ④ Task 2 `cancelled_error_maps_to_cancelled_state` ⑤ Task 4 map `truncated` 경고 + Task 4 `select_and_sort`(수천 영역에서도 O(n log n)).
