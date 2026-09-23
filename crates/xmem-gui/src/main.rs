#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![windows_subsystem = "windows"]
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
    fonts.font_data.insert(
        "malgun".to_owned(),
        std::sync::Arc::new(egui::FontData::from_owned(bytes)),
    );
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        family.insert(0, "malgun".to_owned());
    }
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
        family.push("malgun".to_owned());
    }
    ctx.set_fonts(fonts);
}

/// 관리자 권한이 없으면 runas로 자신을 다시 띄우고 종료한다. 재실행을 시작했으면 Some(종료 코드).
fn ensure_elevated(args: &[String], pid: Option<u32>) -> Option<i32> {
    let elevated = xmem_windows::is_elevated().unwrap_or(false);
    if elevated || args.iter().any(|arg| arg == "--elevated") {
        return None;
    }
    let Ok(exe) = std::env::current_exe() else {
        return None;
    };
    let mut params = String::from("--elevated");
    if let Some(pid) = pid {
        params.push_str(&format!(" --pid {pid}"));
    }
    match xmem_windows::runas(&exe.to_string_lossy(), &params) {
        // 자식이 관리자 권한으로 뜨는 중이므로 이 인스턴스는 종료한다.
        Ok(()) => Some(0),
        // UAC 취소 등: 권한 없이 그대로 진행한다(UI가 표준 권한으로 표시).
        Err(_) => None,
    }
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    let initial_pid = parse_pid_arg(&args);
    if let Some(code) = ensure_elevated(&args, initial_pid) {
        std::process::exit(code);
    }
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
        let args: Vec<String> = ["xmem-gui", "--pid", "4321"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(parse_pid_arg(&args), Some(4321));
    }

    #[test]
    fn parse_pid_arg_handles_missing_and_invalid() {
        let args: Vec<String> = ["xmem-gui"].iter().map(|s| s.to_string()).collect();
        assert_eq!(parse_pid_arg(&args), None);
        let args: Vec<String> = ["xmem-gui", "--pid", "abc"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(parse_pid_arg(&args), None);
    }
}
