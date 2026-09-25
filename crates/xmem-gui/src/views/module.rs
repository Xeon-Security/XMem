//! 모듈 상세 패널.

use std::path::Path;

use xmem_core::{MemorySource, ModuleInfo, ProcessArch};
use xmem_memory::LiveProcess;
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe, parse_pe_file};

use crate::app::XMemApp;
use crate::error::error_label;
use crate::task::TaskState;
use crate::views::map::{human_size, opt_hex};
use crate::views::region::format_timestamp;

pub struct ModuleDetail {
    pub module: ModuleInfo,
    pub pe_disk: Option<PeInfo>,
    pub pe_disk_error: Option<String>,
    pub pe_memory: Option<PeInfo>,
    pub pe_memory_error: Option<String>,
    pub notes: Vec<String>,
}

/// COFF characteristics 해석.
pub fn characteristics_text(characteristics: u16) -> String {
    let mut flags = Vec::new();
    if characteristics & 0x0002 != 0 {
        flags.push("EXECUTABLE");
    }
    if characteristics & 0x0020 != 0 {
        flags.push("LARGE_ADDRESS_AWARE");
    }
    if characteristics & 0x0100 != 0 {
        flags.push("32BIT");
    }
    if characteristics & 0x1000 != 0 {
        flags.push("SYSTEM");
    }
    if characteristics & 0x2000 != 0 {
        flags.push("DLL");
    }
    if flags.is_empty() {
        "-".to_string()
    } else {
        flags.join(", ")
    }
}

/// 서브시스템 해석.
pub fn subsystem_text(subsystem: u16) -> String {
    match subsystem {
        0 => "Unknown".to_string(),
        1 => "Native".to_string(),
        2 => "Windows GUI".to_string(),
        3 => "Windows Console".to_string(),
        9 => "Windows CE GUI".to_string(),
        10 => "EFI Application".to_string(),
        14 => "Xbox".to_string(),
        other => format!("기타({other})"),
    }
}

/// 섹션 권한 문자열 (R/W/X).
pub fn section_perm_text(section: &xmem_pe::PeSection) -> String {
    let r = if section.readable { 'R' } else { '-' };
    let w = if section.writable { 'W' } else { '-' };
    let x = if section.executable { 'X' } else { '-' };
    format!("{r}{w}{x}")
}

/// PE 정보 출처 라벨.
pub fn pe_source_text(detail: &ModuleDetail) -> &'static str {
    match (detail.pe_disk.is_some(), detail.pe_memory.is_some()) {
        (true, true) => "디스크 + 메모리",
        (true, false) => "디스크",
        (false, true) => "메모리",
        (false, false) => "-",
    }
}

/// 디스크 PE 파싱 실패 사유를 담은 라이브러리 섹션 안내 문구.
pub fn disk_library_unavailable_text(error: Option<&str>) -> String {
    match error {
        Some(reason) => {
            format!("디스크 PE를 파싱하지 못해 라이브러리 목록이 없습니다: {reason}")
        }
        None => "디스크 PE를 파싱하지 못해 라이브러리 목록이 없습니다".to_string(),
    }
}

fn read_memory_pe(live: &LiveProcess, module: &ModuleInfo) -> (Option<PeInfo>, Option<String>) {
    let len = module.size.min(PE_HEADER_PREFIX as u64) as usize;
    if len < 64 {
        return (
            None,
            Some(format!(
                "모듈 크기가 너무 작습니다 ({} 바이트)",
                module.size
            )),
        );
    }
    let mut buf = vec![0u8; len];
    match live.read(module.base, &mut buf) {
        Ok(outcome) if outcome.bytes_read >= 64 => match parse_pe(&buf[..outcome.bytes_read]) {
            Ok(pe) => (Some(pe), None),
            Err(err) => (None, Some(error_label(&err))),
        },
        Ok(outcome) if outcome.bytes_read == 0 => (
            None,
            Some("메모리를 읽을 수 없습니다 (0 바이트)".to_string()),
        ),
        Ok(outcome) => (
            None,
            Some(format!(
                "부분 읽기: {} / {} 바이트만 읽었습니다",
                outcome.bytes_read, len
            )),
        ),
        Err(err) => (None, Some(error_label(&err))),
    }
}

/// 모듈 상세 수집. 실패는 각 출처의 오류 문구로 남기고 계속한다.
pub fn collect_module_detail(pid: u32, module: ModuleInfo) -> ModuleDetail {
    let mut notes = Vec::new();
    let (pe_disk, pe_disk_error) = match module.path.as_deref() {
        Some(path) if !path.is_empty() => match parse_pe_file(Path::new(path)) {
            Ok(pe) => (Some(pe), None),
            Err(err) => (None, Some(error_label(&err))),
        },
        _ => (None, Some("모듈 경로를 알 수 없습니다".to_string())),
    };
    let (pe_memory, pe_memory_error) = match LiveProcess::open(pid) {
        Ok(live) => read_memory_pe(&live, &module),
        Err(err) => (None, Some(error_label(&err))),
    };
    if pe_disk.is_none() && pe_memory.is_none() {
        notes.push("PE 정보를 얻지 못했습니다. 출처별 사유를 확인하세요.".to_string());
    }
    ModuleDetail {
        module,
        pe_disk,
        pe_disk_error,
        pe_memory,
        pe_memory_error,
        notes,
    }
}

fn pe_summary_rows(pe: &PeInfo) -> Vec<(String, String)> {
    vec![
        (
            "아키텍처".into(),
            format!("{} ({:#x})", pe.arch_text(), pe.machine),
        ),
        (
            "64비트".into(),
            if pe.is_64 { "예" } else { "아니오" }.into(),
        ),
        ("엔트리 포인트".into(), format!("{:#x}", pe.entry_point)),
        ("이미지 베이스".into(), format!("{:#x}", pe.image_base)),
        (
            "이미지 크기".into(),
            format!(
                "{} ({:#x})",
                human_size(pe.size_of_image as u64),
                pe.size_of_image
            ),
        ),
        ("서브시스템".into(), subsystem_text(pe.subsystem)),
        ("특성".into(), characteristics_text(pe.characteristics)),
        ("컴파일 시각".into(), format_timestamp(pe.time_date_stamp)),
        ("섹션 수".into(), pe.sections.len().to_string()),
        (
            "임포트".into(),
            format!(
                "{}개 함수 / {}개 라이브러리",
                pe.import_count, pe.import_library_count
            ),
        ),
        ("익스포트".into(), pe.export_count.to_string()),
        ("재배치".into(), pe.relocation_count.to_string()),
        ("TLS 콜백".into(), pe.tls_callback_count.to_string()),
    ]
}

fn arch_text(pe: &PeInfo) -> &'static str {
    match pe.arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
    }
}

trait PeArchText {
    fn arch_text(&self) -> &'static str;
}

impl PeArchText for PeInfo {
    fn arch_text(&self) -> &'static str {
        arch_text(self)
    }
}

pub fn panel(ui: &mut egui::Ui, app: &mut XMemApp) {
    let colors = crate::theme::palette(app.theme);

    let mut close = false;
    let mut copy: Option<String> = None;
    let mut goto_map = false;

    // 헤더는 상태와 무관하게 항상 그린다 — 로딩/실패 중에도 닫을 수 있도록.
    let header_module = app
        .module_detail
        .as_ref()
        .map(|detail| detail.module.clone())
        .or_else(|| {
            let base = app.module_selected?;
            app.modules_bundle
                .as_ref()?
                .modules
                .iter()
                .find(|module| module.base == base)
                .cloned()
        });
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("닫기").clicked() {
                close = true;
            }
            if ui
                .add_enabled(header_module.is_some(), egui::Button::new("맵에서 보기"))
                .clicked()
            {
                goto_map = true;
            }
            if ui
                .add_enabled(app.module_detail.is_some(), egui::Button::new("요약 복사"))
                .clicked()
                && let Some(detail) = app.module_detail.as_ref()
            {
                copy = Some(module_summary_text(detail));
            }
            if app.module_detail_task.is_running() {
                ui.spinner();
            }
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                match &header_module {
                    Some(module) => {
                        ui.add(
                            egui::Label::new(egui::RichText::new(module.name.as_str()).strong())
                                .truncate(),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!(
                                    "{} · {} · {}",
                                    opt_hex(Some(module.base)),
                                    human_size(module.size),
                                    module
                                        .path
                                        .as_deref()
                                        .map(crate::views::region::short_path)
                                        .unwrap_or_else(|| "-".to_string())
                                ))
                                .weak(),
                            )
                            .truncate(),
                        );
                    }
                    None => {
                        ui.strong("모듈 상세");
                    }
                }
            });
        });
    });

    if close {
        app.module_selected = None;
        app.module_detail = None;
    }
    if let Some(text) = copy {
        ui.ctx().copy_text(text);
        app.log.push(
            crate::log::LogLevel::Info,
            "모듈 요약을 클립보드에 복사했습니다",
        );
    }
    if goto_map && let Some(pid) = app.selected_pid {
        let region = header_module.as_ref().and_then(|module| {
            app.map.as_ref().and_then(|map| {
                map.regions
                    .iter()
                    .find(|region| {
                        module.base >= region.base
                            && module.base < region.base.saturating_add(region.size)
                    })
                    .cloned()
            })
        });
        match region {
            Some(region) => {
                app.tab = crate::app::Tab::Map;
                app.select_region(pid, region);
            }
            None => {
                if app.map.is_none() {
                    app.start_map(pid);
                    app.log.push(
                        crate::log::LogLevel::Warn,
                        "맵을 불러오는 중입니다. 잠시 후 다시 시도하세요",
                    );
                } else {
                    app.log.push(
                        crate::log::LogLevel::Warn,
                        "이 모듈을 포함하는 메모리 영역을 찾지 못했습니다",
                    );
                }
            }
        }
    }

    match app.module_detail_task.state() {
        TaskState::Running => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("모듈 상세를 불러오는 중...");
            });
            return;
        }
        TaskState::Failed(err) => {
            let label = format!("모듈 상세 실패: {}", error_label(err));
            ui.label(egui::RichText::new(label).color(colors.danger));
            if ui.button("다시 시도").clicked() {
                app.retry_module_detail();
            }
            return;
        }
        _ => {}
    }
    let Some(detail) = app.module_detail.as_ref() else {
        ui.label(egui::RichText::new("모듈을 클릭하면 상세 정보가 표시됩니다").weak());
        return;
    };
    let module = detail.module.clone();

    for note in &detail.notes {
        ui.label(egui::RichText::new(note).color(colors.warn));
    }
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("module_detail_scroll")
        .show(ui, |ui| {
            egui::CollapsingHeader::new("식별")
                .default_open(true)
                .show(ui, |ui| {
                    egui::Grid::new("module_ident_grid")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for (key, value) in [
                                ("이름", module.name.clone()),
                                ("경로", module.path.clone().unwrap_or_else(|| "-".into())),
                                ("베이스", opt_hex(Some(module.base))),
                                ("크기", human_size(module.size)),
                                (
                                    "아키텍처",
                                    module
                                        .arch
                                        .map(|a| match a {
                                            ProcessArch::X64 => "x64",
                                            ProcessArch::X86 => "x86",
                                            ProcessArch::Arm64 => "arm64",
                                            ProcessArch::Unknown => "unknown",
                                        })
                                        .unwrap_or("-")
                                        .to_string(),
                                ),
                                ("PE 출처", pe_source_text(detail).to_string()),
                            ] {
                                ui.label(egui::RichText::new(key).weak());
                                ui.label(value);
                                ui.end_row();
                            }
                        });
                });
            for (title, pe, error) in [
                (
                    "PE 요약 (디스크)",
                    detail.pe_disk.as_ref(),
                    detail.pe_disk_error.as_deref(),
                ),
                (
                    "PE 요약 (메모리)",
                    detail.pe_memory.as_ref(),
                    detail.pe_memory_error.as_deref(),
                ),
            ] {
                egui::CollapsingHeader::new(title)
                    .default_open(true)
                    .show(ui, |ui| match pe {
                        Some(pe) => {
                            egui::Grid::new(format!("module_pe_grid_{title}"))
                                .num_columns(2)
                                .spacing([12.0, 4.0])
                                .show(ui, |ui| {
                                    for (key, value) in pe_summary_rows(pe) {
                                        ui.label(egui::RichText::new(key).weak());
                                        ui.label(value);
                                        ui.end_row();
                                    }
                                });
                        }
                        None => {
                            ui.label(
                                egui::RichText::new(error.unwrap_or("사용할 수 없음"))
                                    .color(colors.danger),
                            );
                        }
                    });
            }
            let (section_pe, section_source) =
                match (detail.pe_disk.as_ref(), detail.pe_memory.as_ref()) {
                    (Some(pe), _) => (Some(pe), "디스크"),
                    (None, Some(pe)) => (Some(pe), "메모리"),
                    (None, None) => (None, "-"),
                };
            egui::CollapsingHeader::new(format!("섹션 ({section_source})"))
                .default_open(true)
                .show(ui, |ui| match section_pe {
                    Some(pe) if !pe.sections.is_empty() => {
                        egui::Grid::new("module_sections_grid")
                            .num_columns(5)
                            .spacing([12.0, 4.0])
                            .show(ui, |ui| {
                                for header in ["NAME", "VA", "VIRTUAL", "RAW", "PERM"] {
                                    ui.strong(header);
                                }
                                ui.end_row();
                                for section in &pe.sections {
                                    ui.label(&section.name);
                                    ui.label(format!("{:#x}", section.virtual_address));
                                    ui.label(human_size(section.virtual_size as u64));
                                    ui.label(human_size(section.raw_size as u64));
                                    ui.label(section_perm_text(section));
                                    ui.end_row();
                                }
                            });
                    }
                    Some(_) => {
                        ui.label("섹션 정보가 없습니다");
                    }
                    None => {
                        ui.label(
                            egui::RichText::new("PE를 파싱하지 못해 섹션을 표시할 수 없습니다")
                                .color(colors.danger),
                        );
                    }
                });
            egui::CollapsingHeader::new("라이브러리")
                .default_open(false)
                .show(ui, |ui| match detail.pe_disk.as_ref() {
                    Some(pe) if !pe.libraries.is_empty() => {
                        for library in &pe.libraries {
                            ui.label(library);
                        }
                    }
                    Some(_) => {
                        ui.label("임포트 라이브러리가 없습니다");
                    }
                    None => {
                        ui.label(
                            egui::RichText::new(disk_library_unavailable_text(
                                detail.pe_disk_error.as_deref(),
                            ))
                            .color(colors.warn),
                        );
                    }
                });
        });
}

pub fn module_summary_text(detail: &ModuleDetail) -> String {
    let module = &detail.module;
    let mut text = String::new();
    text.push_str(&format!("module {}\n", module.name));
    text.push_str(&format!("  base {}\n", opt_hex(Some(module.base))));
    text.push_str(&format!("  size {}\n", human_size(module.size)));
    text.push_str(&format!(
        "  path {}\n",
        module.path.as_deref().unwrap_or("-")
    ));
    text.push_str(&format!("  pe source {}\n", pe_source_text(detail)));
    if let Some(pe) = detail.pe_disk.as_ref().or(detail.pe_memory.as_ref()) {
        text.push_str(&format!("  entry {:#x}\n", pe.entry_point));
        text.push_str(&format!("  image base {:#x}\n", pe.image_base));
        text.push_str(&format!(
            "  characteristics {}\n",
            characteristics_text(pe.characteristics)
        ));
        text.push_str(&format!(
            "  compiled {}\n",
            format_timestamp(pe.time_date_stamp)
        ));
        text.push_str(&format!(
            "  imports {} / libraries {}\n",
            pe.import_count, pe.import_library_count
        ));
        text.push_str(&format!(
            "  exports {} / relocations {}\n",
            pe.export_count, pe.relocation_count
        ));
        text.push_str(&format!("  tls callbacks {}\n", pe.tls_callback_count));
    }
    if let Some(error) = detail.pe_disk_error.as_deref() {
        text.push_str(&format!("  disk error {error}\n"));
    }
    if let Some(error) = detail.pe_memory_error.as_deref() {
        text.push_str(&format!("  memory error {error}\n"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::ModuleInfo;

    fn sample_detail() -> ModuleDetail {
        ModuleDetail {
            module: ModuleInfo {
                name: "sample.exe".into(),
                base: 0x0001_4000_0000,
                size: 0x2000,
                path: Some("C:\\x\\sample.exe".into()),
                arch: Some(ProcessArch::X64),
            },
            pe_disk: None,
            pe_disk_error: Some("접근 거부 (AccessDenied): denied".into()),
            pe_memory: None,
            pe_memory_error: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn characteristics_decode_flags() {
        assert_eq!(
            characteristics_text(0x0022),
            "EXECUTABLE, LARGE_ADDRESS_AWARE"
        );
        assert_eq!(characteristics_text(0x2102), "EXECUTABLE, 32BIT, DLL");
        assert_eq!(characteristics_text(0), "-");
    }

    #[test]
    fn subsystem_labels() {
        assert_eq!(subsystem_text(3), "Windows Console");
        assert_eq!(subsystem_text(2), "Windows GUI");
        assert_eq!(subsystem_text(1234), "기타(1234)");
    }

    #[test]
    fn section_permissions_render() {
        let section = xmem_pe::PeSection {
            name: ".text".into(),
            virtual_address: 0x1000,
            virtual_size: 0x100,
            raw_size: 0x200,
            characteristics: 0x6000_0020,
            readable: true,
            writable: false,
            executable: true,
        };
        assert_eq!(section_perm_text(&section), "R-X");
    }

    fn sample_pe() -> PeInfo {
        PeInfo {
            is_64: true,
            machine: 0x8664,
            arch: ProcessArch::X64,
            image_base: 0x0001_4000_0000,
            entry_point: 0x0001_4000_1234,
            size_of_image: 0x2000,
            subsystem: 3,
            characteristics: 0x22,
            time_date_stamp: 0,
            sections: Vec::new(),
            import_count: 0,
            import_library_count: 0,
            libraries: Vec::new(),
            export_count: 0,
            relocation_count: 0,
            tls_callback_count: 0,
        }
    }

    #[test]
    fn pe_source_reflects_available_sources() {
        let mut detail = sample_detail();
        assert_eq!(pe_source_text(&detail), "-");
        detail.pe_disk_error = None;
        detail.pe_disk = Some(sample_pe());
        assert_eq!(pe_source_text(&detail), "디스크");
        detail.pe_memory = Some(sample_pe());
        assert_eq!(pe_source_text(&detail), "디스크 + 메모리");
    }

    #[test]
    fn summary_text_includes_errors_and_identity() {
        let text = module_summary_text(&sample_detail());
        assert!(text.contains("module sample.exe"));
        assert!(!text.contains("0x0000000000000000"));
        assert!(text.contains("AccessDenied"));
    }

    #[test]
    fn disk_parse_failure_reason_in_library_hint() {
        let text = disk_library_unavailable_text(Some("접근 거부 (AccessDenied): denied"));
        assert!(text.contains("AccessDenied"), "{text}");
        let text = disk_library_unavailable_text(None);
        assert!(text.contains("디스크 PE"), "{text}");
    }
}
