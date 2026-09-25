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
    // 가로 ScrollArea 안에서 표가 패널보다 넓어질 수 있으므로 보이는 영역만 클릭 밴드로 쓴다.
    // 이렇게 하지 않으면 좌측 목록 행의 밴드가 중앙 패널까지 걸쳐, 맵을 클릭했는데
    // 프로세스 선택이 바뀌는 문제가 생긴다.
    let band = ui.max_rect().intersect(ui.clip_rect());
    // 콤보박스 팝업 등 다른 레이어가 표 위에 떠 있으면 그 클릭은 행 클릭이 아니다.
    // 최상위 레이어(egui 0.36 `Context::layer_id_at`)가 이 위젯의 레이어일 때만 인정한다.
    let pos = ui.input(|i| i.pointer.latest_pos());
    let on_table_layer = pos
        .is_some_and(|pos| band.contains(pos) && ui.ctx().layer_id_at(pos) == Some(ui.layer_id()));
    let clicked = on_table_layer && ui.input(|i| i.pointer.primary_clicked());
    // 포커스 위젯은 추가적인 것이다. egui_extras 셀은 히트테스트가 불안정해
    // 마우스 클릭은 위 입력 판정을 그대로 신뢰하고, 이 위젯은 Enter 활성화만 담당한다.
    let resp = ui.interact(band, ui.id().with("cell_focus"), egui::Sense::click());
    let activated = resp.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
    if clicked || activated {
        resp.request_focus();
    }
    ui.add_sized(
        [ui.available_width(), ROW_HEIGHT],
        egui::Label::new(text).truncate(),
    );
    clicked || activated
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

/// 표를 가로 스크롤로 감쌀지 판단한다. 가용 폭이 표 최소 폭 이상일 때만 감싼다.
pub fn should_hscroll(available: f32, min_w: f32) -> bool {
    available >= min_w
}

/// ↑/↓ 키로 표 선택 행을 한 칸 옮긴다.
///
/// `current`는 현재 선택의 데이터 인덱스, `filtered_indices`는 표시 행 → 데이터
/// 인덱스 매핑이다. 이동한 행의 데이터 인덱스를 돌려준다. 텍스트 입력 중이면
/// None(검색어 입력 등에서 커서 이동을 가로채지 않는다).
pub fn arrow_step(
    ctx: &egui::Context,
    len: usize,
    current: Option<usize>,
    filtered_indices: &[usize],
) -> Option<usize> {
    let len = len.min(filtered_indices.len());
    if len == 0 || ctx.text_edit_focused() {
        return None;
    }
    let up = ctx.input(|i| i.key_pressed(egui::Key::ArrowUp));
    let down = ctx.input(|i| i.key_pressed(egui::Key::ArrowDown));
    if up == down {
        return None;
    }
    let row = current.and_then(|index| filtered_indices.iter().position(|&i| i == index));
    let next = match (up, row) {
        (true, Some(row)) => row.saturating_sub(1),
        (false, Some(row)) => (row + 1).min(len - 1),
        (_, None) => 0,
    };
    filtered_indices.get(next).copied()
}

/// 가용 폭이 넉넉하면 표를 가로 ScrollArea에 담고, 좁으면 패널 폭에 맞춰 그린다.
///
/// 항상 가로 스크롤로 감싸면 좁은 창에서 표가 패널보다 넓어져 표 자신의 세로
/// 스크롤바가 보이는 영역 밖으로 밀려난다. 좁을 때는 감싸지 않아 세로
/// 스크롤바가 항상 보이게 한다(가로로는 열이 잘릴 수 있다).
pub fn wrap_hscroll_if_wide<R>(
    ui: &mut egui::Ui,
    id_salt: &str,
    min_w: f32,
    auto_shrink: [bool; 2],
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    if should_hscroll(ui.available_width(), min_w) {
        egui::ScrollArea::horizontal()
            .id_salt(id_salt)
            .auto_shrink(auto_shrink)
            .show(ui, |ui| {
                ui.set_min_width(min_w);
                add_contents(ui)
            })
            .inner
    } else {
        add_contents(ui)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_key(key: egui::Key) -> egui::Context {
        let ctx = egui::Context::default();
        ctx.input_mut(|input| {
            input.events.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::default(),
            });
        });
        ctx
    }

    #[test]
    fn should_hscroll_only_when_available_width_sufficient() {
        assert!(should_hscroll(910.0, 910.0));
        assert!(should_hscroll(1200.0, 910.0));
        assert!(!should_hscroll(909.9, 910.0));
        assert!(!should_hscroll(400.0, 910.0));
    }

    #[test]
    fn arrow_step_moves_between_filtered_rows() {
        let rows = [5usize, 3, 7];
        let none = egui::Context::default();
        assert_eq!(arrow_step(&none, rows.len(), None, &rows), None);
        assert_eq!(
            arrow_step(&ctx_with_key(egui::Key::ArrowDown), rows.len(), None, &rows),
            Some(5)
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowUp),
                rows.len(),
                Some(5),
                &rows
            ),
            Some(5)
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowDown),
                rows.len(),
                Some(5),
                &rows
            ),
            Some(3)
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowDown),
                rows.len(),
                Some(7),
                &rows
            ),
            Some(7)
        );
    }

    #[test]
    fn arrow_step_ignores_empty_rows_and_other_keys() {
        let rows = [1usize, 2];
        assert_eq!(
            arrow_step(&ctx_with_key(egui::Key::ArrowDown), 0, None, &[]),
            None
        );
        assert_eq!(
            arrow_step(
                &ctx_with_key(egui::Key::ArrowLeft),
                rows.len(),
                Some(1),
                &rows
            ),
            None
        );
    }
}
