//! 탭별 화면.
pub mod detect;
pub mod dump;
pub mod guide;
pub mod log;
pub mod map;
pub mod module;
pub mod modules;
pub mod overview;
pub mod process;
pub mod region;
pub mod report;
pub mod scan;
pub mod snapshot;
pub mod thread;
pub mod threads;

/// 마우스로 크기를 조절할 수 있는 내용 영역(오른쪽 아래 모서리 드래그).
pub fn resizable_pane<R>(
    ui: &mut egui::Ui,
    id_salt: &str,
    default_height: f32,
    min_height: f32,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Resize::default()
        .id_salt(id_salt)
        .default_height(default_height)
        .min_height(min_height)
        .resizable(true)
        .show(ui, add_contents)
}

/// 내용 영역 크기 조절 안내 문구.
pub fn pane_hint(ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("↘ 오른쪽 아래 모서리를 끌어 크기를 조절할 수 있습니다")
            .weak()
            .small(),
    );
}
