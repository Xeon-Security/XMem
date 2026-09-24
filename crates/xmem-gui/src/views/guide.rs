//! 가이드 탭 — 처음 사용하는 사용자를 위한 안내.

use crate::app::{Tab, XMemApp};
use crate::theme::palette;

pub const SAFETY_LINES: [&str; 4] = [
    "XMem은 분석 도구입니다. 메모리를 변경하지 않습니다(실험은 CLI 전용).",
    "보호 프로세스는 관리자 권한으로도 열 수 없습니다(PPL).",
    "탐지 결과 0건은 안전을 의미하지 않습니다.",
    "분석 대상은 신뢰할 수 있는 프로세스로 한정하세요.",
];

/// 빠른 시작 단계: (제목, 설명, 이동할 탭).
pub const QUICK_START: [(&str, &str, Tab); 5] = [
    (
        "1. 프로세스 고르기",
        "왼쪽 목록에서 클릭하거나(창이 좁으면 상단 드롭다운) 이름·PID로 검색하세요. \
         접근이 거부되면 상단 배지의 [관리자로 재시작]을 누르면 같은 프로세스 선택 상태로 다시 열립니다.",
        Tab::Overview,
    ),
    (
        "2. 기본 정보 확인",
        "개요 탭에서 경로·아키텍처·사용자·메모리 통계·스레드/모듈 수를 확인합니다. \
         경로가 '-'로 보이면 권한이 부족할 수 있습니다.",
        Tab::Overview,
    ),
    (
        "3. 탐지 실행",
        "탐지 탭에서 [탐지 실행]을 누르면 XMEM-001~005 규칙 결과가 나옵니다. \
         finding 행을 클릭하면 관찰 사실(Observed)과 근거(Evidence)가 펼쳐집니다.",
        Tab::Detect,
    ),
    (
        "4. 의심 영역 깊이 보기",
        "메모리맵·모듈·스레드 탭에서 행을 클릭하면 하단 상세 패널이 열립니다 — \
         hex 뷰어(4 KiB 페이지 이동), 할당 오프셋, PE 여부, 관련 스레드·finding까지 한 화면에서 확인합니다.",
        Tab::Map,
    ),
    (
        "5. 스냅샷·리포트 저장",
        "스냅샷 탭에서 기준(before)과 이후(after)를 만들어 비교하고, \
         리포트 탭에서 JSON/Markdown으로 저장하세요. 미니덤프는 덤프 탭에서 생성·분석합니다.",
        Tab::Snapshot,
    ),
];

pub struct GuideSection {
    pub title: &'static str,
    pub body: &'static str,
    pub tab: Tab,
}

/// 탭별 안내.
pub const GUIDE_SECTIONS: [GuideSection; 9] = [
    GuideSection {
        title: "개요",
        body: "선택한 프로세스의 기본 정보와 메모리 통계(Working Set/Private/Commit)를 보여줍니다. \
               아래 빠른 액션 버튼으로 다른 탭으로 이동할 수 있습니다. \
               값이 갱신되지 않으면 [프로세스 새로고침]을 누르세요.",
        tab: Tab::Overview,
    },
    GuideSection {
        title: "메모리맵",
        body: "VirtualQueryEx로 수집한 전체 가상 메모리 영역 목록입니다. \
               STATE/TYPE/PROTECTION/CLASS/HEURISTICS 열로 영역을 분류하고, \
               executable/private/writable 필터와 정렬로 좁힐 수 있습니다. \
               행을 클릭하면 하단 패널에서 식별 정보·보호 속성·백킹·hex 내용·관련 스레드/finding을 확인합니다. \
               'allocation base'는 영역이 속한 할당의 시작 주소이고, 상세 패널의 [할당 시작으로 이동]으로 그 위치를 볼 수 있습니다.",
        tab: Tab::Map,
    },
    GuideSection {
        title: "검색",
        body: "패턴(예: 4D 5A ?? ??), ASCII 문자열, UTF-16 문자열을 프로세스 메모리에서 찾습니다. \
               executable-only/private-only/writable-only 필터로 범위를 줄이면 훨씬 빠릅니다. \
               결과 행을 클릭하면 그 주소의 hex 미리보기가 열립니다. \
               큰 프로세스는 시간이 걸리므로 [취소]로 언제든 중단할 수 있습니다(부분 결과 유지).",
        tab: Tab::Scan,
    },
    GuideSection {
        title: "모듈",
        body: "로드된 DLL/EXE 목록입니다. [PE 요약]을 켜면 아키텍처·엔트리·섹션 수를 표에 표시합니다. \
               행을 클릭하면 디스크 파일 PE와 메모리 PE를 나란히 비교합니다 — \
               임포트/익스포트/재배치/TLS 수, 섹션 권한, 컴파일 시각, 라이브러리 목록까지 볼 수 있습니다. \
               [맵에서 보기]로 이 모듈이 차지하는 메모리 영역으로 이동합니다.",
        tab: Tab::Modules,
    },
    GuideSection {
        title: "스레드",
        body: "TID·우선순위·시작 주소와 시작 주소가 속한 영역/모듈을 보여줍니다. \
               행을 클릭하면 상세 패널에서 생성/종료 시각과 kernel/user CPU 시간(GetThreadTimes), \
               시작 주소의 64바이트 hex를 확인합니다. \
               시작 주소가 모듈 밖 사적 실행 영역이면 XMEM-004 finding과 연결됩니다.",
        tab: Tab::Threads,
    },
    GuideSection {
        title: "탐지",
        body: "규칙 기반 분석 결과입니다. XMEM-001(사적 실행 메모리), XMEM-002(사적 영역의 PE 헤더), \
               XMEM-003(백킹 없는 실행 영역), XMEM-004(의심스러운 스레드 시작 주소), XMEM-005(보호 속성 이상). \
               심각도·신뢰도와 Evidence(관찰 값)를 함께 읽고, 해석(Interpretation)은 단정이 아님을 기억하세요. \
               finding 행을 클릭하면 근거 표가 펼쳐집니다.",
        tab: Tab::Detect,
    },
    GuideSection {
        title: "스냅샷",
        body: "현재 상태(영역·모듈·스레드·finding + 영역 해시)를 .xmem 파일로 저장하고 두 스냅샷을 비교합니다. \
               diff 표기: + 추가 / - 제거 / ~ 변경(보호 속성·모듈·스레드·탐지) / * 내용 해시 변화. \
               해시는 예산(기본 64 MiB) 안에서만 저장되므로 해시가 없는 영역은 내용 변화를 비교할 수 없습니다.",
        tab: Tab::Snapshot,
    },
    GuideSection {
        title: "덤프",
        body: "MiniDumpWriteDump로 미니덤프를 만들고(선택: 전체 메모리 포함) \
               오프라인에서 분석합니다. 분석은 라이브 분석과 같은 규칙을 실행합니다. \
               전체 메모리 덤프는 크고 느리며 진행 중 취소할 수 없습니다(디스크 공간 사전 검사).",
        tab: Tab::Dump,
    },
    GuideSection {
        title: "리포트",
        body: "프로세스·영역·모듈·스레드·finding을 JSON 또는 Markdown 한 파일로 저장합니다. \
               기본 저장 위치는 Documents\\XMem이고, 파일명은 자동 생성됩니다. \
               CLI(`xmem report --pid <PID> --output report.md`)로 같은 내용을 만들 수 있습니다.",
        tab: Tab::Report,
    },
];

/// 오류 대처: (오류 라벨, 대처 방법).
pub const ERROR_HINTS: [(&str, &str); 5] = [
    (
        "접근 거부 (AccessDenied)",
        "관리자 권한이 필요합니다. 상단 배지의 [관리자로 재시작]을 사용하세요. \
         보호 프로세스(PPL, 예: 일부 안티치트/보안 제품)는 관리자로도 열 수 없습니다.",
    ),
    (
        "프로세스가 종료됨 (ProcessExited)",
        "대상이 이미 종료되었습니다. [프로세스 새로고침] 후 다시 선택하세요.",
    ),
    (
        "부분 읽기 / 잘못된 주소",
        "영역이 도중에 바뀌었습니다. 새로고침 후 다시 시도하세요. \
         상세 패널과 검색 통계에는 실패 사유가 그대로 표시됩니다.",
    ),
    (
        "Windows API 오류 (code=...)",
        "메시지의 api 이름과 code를 확인하세요. 하단 로그 패널에 최근 오류가 남습니다.",
    ),
    (
        "디스크 공간 부족",
        "스냅샷/덤프 출력 위치를 여유가 있는 드라이브로 바꾸세요(기본: Documents\\XMem).",
    ),
];

/// 용어·표기: (용어, 설명).
pub const GLOSSARY: [(&str, &str); 8] = [
    (
        "영역 (region)",
        "VirtualQueryEx가 보고하는 메모리 구간. BASE(시작)·SIZE·STATE·TYPE·PROTECTION으로 표시됩니다.",
    ),
    (
        "ALLOC (allocation base)",
        "영역이 속한 할당의 시작 주소. 상세 패널에서 할당 시작까지의 오프셋을 보여줍니다.",
    ),
    (
        "STATE",
        "MEM_COMMIT(사용 중) / MEM_RESERVE(예약) / MEM_FREE(비어 있음).",
    ),
    (
        "TYPE",
        "MEM_IMAGE(실행 이미지) / MEM_MAPPED(파일 매핑) / MEM_PRIVATE(사적 메모리).",
    ),
    (
        "PROTECTION",
        "R/W/X 요약 + 원시 값. 예: RWX (0x40)은 읽기·쓰기·실행 모두 가능. GUARD/NOCACHE는 추가 비트로 상세 패널에 표시됩니다.",
    ),
    (
        "휴리스틱 태그",
        "exec-private(사적+실행) / exec-anon(파일 백킹 없는 실행) / pe-like(PE 헤더로 보임) / wx(쓰기+실행). 추정이며 단정이 아닙니다.",
    ),
    (
        "finding",
        "규칙이 관찰한 사실과 근거 묶음. 심각도(Severity)·신뢰도(Confidence)와 함께 표시됩니다.",
    ),
    (
        "스냅샷 해시",
        "스냅샷은 예산(기본 64 MiB) 안에서 영역 해시를 저장합니다. 해시가 없는 영역은 내용 변화를 비교할 수 없습니다.",
    ),
];

pub const SEVERITY_LEGEND: [(&str, &str); 5] = [
    ("Info", "참고 정보"),
    ("Low", "낮음 — 노이즈일 가능성이 큼(예: .NET 내부 매핑)"),
    ("Medium", "중간 — 확인 권장"),
    ("High", "높음 — 우선 확인"),
    (
        "Critical",
        "치명 — 즉시 확인(현재 기본 규칙은 사용하지 않음)",
    ),
];

pub const CONFIDENCE_LEGEND: [(&str, &str); 3] = [
    ("Low", "추정 — 오탐 가능"),
    ("Medium", "근거 있음"),
    ("High", "관찰 사실 기반"),
];

/// 검색어가 섹션 제목/본문에 포함되는지(대소문자 무시).
pub fn matches_query(section: &GuideSection, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    section.title.to_lowercase().contains(&query) || section.body.to_lowercase().contains(&query)
}

#[allow(clippy::too_many_lines)]
pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let colors = palette(app.theme);
    let mut goto: Option<Tab> = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("guide_scroll")
        .show(ui, |ui| {
            ui.heading("가이드");
            ui.label(
                egui::RichText::new(
                    "처음 사용하는 분을 위한 안내입니다. 빠른 시작을 순서대로 따라 하면 됩니다.",
                )
                .weak(),
            );
            if app.selected_pid.is_none() {
                ui.label(
                    egui::RichText::new(
                        "아직 프로세스를 선택하지 않았습니다 — 1단계부터 시작하세요.",
                    )
                    .color(colors.warn),
                );
            }
            ui.add_space(8.0);

            ui.strong("빠른 시작");
            ui.add_space(4.0);
            for (title, body, tab) in QUICK_START {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(title).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button(format!("{} 탭 열기", tab.title()))
                            .clicked()
                        {
                            goto = Some(tab);
                        }
                    });
                });
                ui.label(body);
                ui.add_space(6.0);
            }
            ui.separator();

            ui.horizontal(|ui| {
                ui.strong("탭별 안내");
                ui.add(
                    egui::TextEdit::singleline(&mut app.guide_query)
                        .hint_text("검색 (예: hex, 스냅샷, RWX, 오류)")
                        .desired_width(240.0),
                );
            });
            ui.add_space(4.0);
            let mut shown = 0usize;
            for section in &GUIDE_SECTIONS {
                if !matches_query(section, &app.guide_query) {
                    continue;
                }
                shown += 1;
                egui::CollapsingHeader::new(section.title)
                    .default_open(!app.guide_query.trim().is_empty())
                    .show(ui, |ui| {
                        ui.label(section.body);
                        ui.add_space(2.0);
                        if ui
                            .small_button(format!("{} 탭 열기", section.tab.title()))
                            .clicked()
                        {
                            goto = Some(section.tab);
                        }
                    });
            }
            if shown == 0 {
                ui.label(egui::RichText::new("검색 결과가 없습니다").weak());
            }
            ui.separator();

            ui.strong("용어·표기");
            egui::Grid::new("guide_glossary_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    for (term, description) in GLOSSARY {
                        ui.label(egui::RichText::new(term).strong());
                        ui.label(description);
                        ui.end_row();
                    }
                });
            ui.add_space(8.0);

            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.strong("심각도 (Severity)");
                    egui::Grid::new("guide_severity_grid")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for (level, meaning) in SEVERITY_LEGEND {
                                ui.label(egui::RichText::new(level).strong());
                                ui.label(meaning);
                                ui.end_row();
                            }
                        });
                });
                ui.add_space(24.0);
                ui.vertical(|ui| {
                    ui.strong("신뢰도 (Confidence)");
                    egui::Grid::new("guide_confidence_grid")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for (level, meaning) in CONFIDENCE_LEGEND {
                                ui.label(egui::RichText::new(level).strong());
                                ui.label(meaning);
                                ui.end_row();
                            }
                        });
                });
            });
            ui.separator();

            ui.strong("오류 대처");
            egui::Grid::new("guide_errors_grid")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .striped(true)
                .show(ui, |ui| {
                    for (error, hint) in ERROR_HINTS {
                        ui.label(egui::RichText::new(error).strong());
                        ui.label(hint);
                        ui.end_row();
                    }
                });
            ui.separator();

            ui.strong("안전 원칙");
            for line in SAFETY_LINES {
                ui.label(egui::RichText::new(format!("· {line}")).color(colors.warn));
            }
        });
    if let Some(tab) = goto {
        app.tab = tab;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_start_has_five_steps_with_target_tabs() {
        assert_eq!(QUICK_START.len(), 5);
        assert!(
            QUICK_START
                .iter()
                .all(|(title, body, _)| !title.is_empty() && !body.is_empty())
        );
        assert!(QUICK_START.iter().any(|(_, _, tab)| *tab == Tab::Detect));
        assert!(QUICK_START.iter().any(|(_, _, tab)| *tab == Tab::Snapshot));
    }

    #[test]
    fn sections_cover_every_analysis_tab() {
        for tab in Tab::ALL {
            if tab == Tab::Guide {
                continue;
            }
            assert!(
                GUIDE_SECTIONS.iter().any(|section| section.tab == tab),
                "{} 탭 안내가 없습니다",
                tab.title()
            );
        }
    }

    #[test]
    fn matches_query_is_case_insensitive_and_matches_body() {
        let map_section = GUIDE_SECTIONS
            .iter()
            .find(|section| section.tab == Tab::Map)
            .expect("map section");
        assert!(matches_query(map_section, ""));
        assert!(matches_query(map_section, "HEX"));
        assert!(matches_query(map_section, "allocation"));
        assert!(!matches_query(map_section, "zzz-없는단어"));
    }

    #[test]
    fn glossary_covers_core_terms() {
        for term in ["ALLOC", "PROTECTION", "STATE", "TYPE", "finding"] {
            assert!(
                GLOSSARY.iter().any(|(name, _)| name.contains(term)),
                "용어 '{term}' 누락"
            );
        }
    }

    #[test]
    fn error_hints_cover_common_failures() {
        for key in ["AccessDenied", "ProcessExited", "디스크"] {
            assert!(
                ERROR_HINTS.iter().any(|(error, _)| error.contains(key)),
                "오류 항목 '{key}' 누락"
            );
        }
    }

    #[test]
    fn safety_lines_include_zero_findings_note() {
        assert!(SAFETY_LINES.iter().any(|line| line.contains("0건")));
    }
}
