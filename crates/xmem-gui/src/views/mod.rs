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
///
/// 내용은 전용 배경/테두리 상자(`content_frame`) 안에 들어가며, 크기 조절
/// 테두리는 Resize 기본 스트로크 대신 이 상자가 담당한다(내용 침범 방지).
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
        .with_stroke(false)
        .show(ui, |ui| content_frame(ui, add_contents))
}

/// 내용 영역 전용 상자(배경 + 테두리 + 여백). 내용과 주변 UI를 구분한다.
pub fn content_frame<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let visuals = ui.visuals();
    let fill = visuals.extreme_bg_color;
    let stroke = visuals.widgets.noninteractive.bg_stroke;
    egui::Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(4.0)
        .inner_margin(8.0)
        .show(ui, add_contents)
        .inner
}

/// 표 셀에서 줄바꿈을 끈다(고정 행 높이에서 긴 값이 다음 행을 침범하지 않도록).
pub fn truncate_cells(ui: &mut egui::Ui) {
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
}

/// 표 행 높이(px). 셀 내용도 이 높이에 맞춘다.
pub const ROW_HEIGHT: f32 = 20.0;

/// 표 셀을 한 줄 고정 높이로 그린다. 셀 영역이 클릭되면 `true`를 돌려준다.
///
/// 셀 내용이 길어 줄바꿈되면 셀 min_rect가 행 높이를 넘겨 행 클릭 영역이 어긋난다.
/// 또한 egui_extras 셀 위젯은 포인터가 셀 안에 있어도 히트테스트에서 제외되어
/// hover/click이 잡히지 않으므로, 입력에서 직접 클릭을 판정한다.
pub fn table_cell(ui: &mut egui::Ui, text: egui::RichText) -> bool {
    let band = ui.max_rect();
    let clicked = ui.input(|i| {
        i.pointer.primary_clicked() && i.pointer.latest_pos().is_some_and(|pos| band.contains(pos))
    });
    ui.add_sized(
        [ui.available_width(), ROW_HEIGHT],
        egui::Label::new(text).truncate(),
    );
    clicked
}

/// `truncate_cells`로 바꾼 줄바꿈 모드를 기본값으로 되돌린다.
pub fn wrap_default(ui: &mut egui::Ui) {
    ui.style_mut().wrap_mode = None;
}

/// 내용 영역 크기 조절 안내 문구.
pub fn pane_hint(ui: &mut egui::Ui) {
    ui.label(
        egui::RichText::new("↘ 오른쪽 아래 모서리를 끌어 크기를 조절할 수 있습니다")
            .weak()
            .small(),
    );
}
