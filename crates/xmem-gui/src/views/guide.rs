//! 가이드 탭.

use crate::app::XMemApp;
use crate::theme::palette;

pub const SAFETY_LINES: [&str; 4] = [
    "XMem은 분석 도구입니다. 메모리를 변경하지 않습니다(실험은 CLI 전용).",
    "보호 프로세스는 관리자 권한으로도 열 수 없습니다(PPL).",
    "탐지 결과 0건은 안전을 의미하지 않습니다.",
    "분석 대상은 신뢰할 수 있는 프로세스로 한정하세요.",
];

pub fn guide_steps() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "1. 프로세스 고르기",
            "왼쪽 목록에서 분석할 프로세스를 클릭하거나, 창이 좁으면 상단 드롭다운을 사용하세요. \
             접근이 거부되면 배지의 \"관리자로 재시작\" 버튼으로 권한을 올릴 수 있습니다.",
        ),
        (
            "2. 탐지 실행",
            "\"탐지\" 탭에서 실행하면 규칙(XMEM-001~005) 기반 finding을 보여줍니다. \
             자세한 수집은 \"리포트\"로 저장해 CLI로도 재확인할 수 있습니다.",
        ),
        (
            "3. 결과 읽는 법",
            "finding은 Observed(관찰) → Evidence(근거) → Heuristic(추정) → Confidence(신뢰도) → Interpretation(해석) \
             순서로 읽습니다. 추정은 단정이 아니며, 0건이어도 안전을 뜻하지 않습니다.",
        ),
        (
            "4. 스냅샷 전/후 비교",
            "\"스냅샷\" 탭에서 기준 스냅샷을 만들고, 실험 후 다시 만들어 두 파일을 비교하면 \
             영역·보호 속성·모듈·스레드·탐지 변화가 나타납니다.",
        ),
        (
            "5. 리포트 저장",
            "\"리포트\" 탭에서 JSON 또는 Markdown으로 저장합니다. \
             덤프가 필요하면 \"덤프\" 탭에서 미니덤프를 생성하고 오프라인으로 분석하세요.",
        ),
    ]
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let colors = palette(app.theme);
    ui.heading("가이드");
    ui.label(egui::RichText::new("처음이라면 이 순서대로 따라 하세요.").weak());
    ui.add_space(6.0);
    for (title, body) in guide_steps() {
        ui.label(egui::RichText::new(title).strong());
        ui.label(body);
        ui.add_space(6.0);
    }
    ui.separator();
    ui.label(egui::RichText::new("안전 원칙").strong());
    for line in SAFETY_LINES {
        ui.label(egui::RichText::new(format!("· {line}")).color(colors.warn));
    }
}

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
