//! 메모리 영역 상세 패널.

use xmem_core::{Finding, MemoryRegion, MemorySource, MemoryState, ThreadInfo};
use xmem_memory::LiveProcess;
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, classify_memory_pe, looks_like_pe, parse_pe};

use crate::app::{Tab, XMemApp};
use crate::error::error_label;
use crate::log::LogLevel;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::map::{heur_tag, human_size, opt_hex};
use crate::views::modules::pe_arch;
use crate::views::scan::hex_dump;

pub const PAGE_SIZE: u64 = 4096;

pub struct RegionDetail {
    pub region: MemoryRegion,
    pub module: Option<String>,
    pub findings: Vec<Finding>,
    pub threads: Vec<ThreadInfo>,
    pub pe_class: Option<xmem_pe::MemoryPeClass>,
    pub pe: Option<PeInfo>,
    pub notes: Vec<String>,
    pub page_start: u64,
    pub page_bytes: Vec<u8>,
    pub page_error: Option<String>,
}

pub fn region_end(region: &MemoryRegion) -> u64 {
    region.base.saturating_add(region.size)
}

pub fn page_count(region: &MemoryRegion) -> u64 {
    region.size.div_ceil(PAGE_SIZE).max(1)
}

pub fn last_page_start(region: &MemoryRegion) -> u64 {
    region.base + region.size.saturating_sub(1) / PAGE_SIZE * PAGE_SIZE
}

pub fn clamp_page(address: u64, region: &MemoryRegion) -> u64 {
    address.clamp(region.base, last_page_start(region))
}

pub fn extra_protection_flags(raw: u32) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if raw & 0x100 != 0 {
        flags.push("GUARD");
    }
    if raw & 0x200 != 0 {
        flags.push("NOCACHE");
    }
    if raw & 0x400 != 0 {
        flags.push("WRITECOMBINE");
    }
    flags
}

pub fn alloc_offset(region: &MemoryRegion) -> Option<u64> {
    region
        .allocation_base
        .map(|allocation| region.base.saturating_sub(allocation))
}

pub fn summary_text(region: &MemoryRegion, module: Option<&str>) -> String {
    let mut text = String::new();
    text.push_str(&format!("base {:#x}\n", region.base));
    text.push_str(&format!(
        "end {:#x}\n",
        region_end(region).saturating_sub(1)
    ));
    text.push_str(&format!(
        "size {} ({} bytes)\n",
        human_size(region.size),
        region.size
    ));
    if let Some(allocation) = region.allocation_base {
        text.push_str(&format!("allocation_base {allocation:#x}\n"));
    }
    text.push_str(&format!("state {}\n", region.state));
    if let Some(region_type) = region.region_type {
        text.push_str(&format!("type {region_type}\n"));
    }
    text.push_str(&format!("protection {}\n", region.protection));
    if let Some(allocation) = region.allocation_protection {
        text.push_str(&format!("allocation_protection {allocation}\n"));
    }
    text.push_str(&format!("classification {}\n", region.classification));
    text.push_str(&format!(
        "flags read={} write={} execute={}\n",
        region.readable, region.writable, region.executable
    ));
    if let Some(file) = &region.mapped_file {
        text.push_str(&format!("mapped_file {file}\n"));
    }
    if let Some(module) = module {
        text.push_str(&format!("module {module}\n"));
    }
    if !region.heuristics.is_empty() {
        let tags: Vec<&str> = region.heuristics.iter().map(|h| heur_tag(*h)).collect();
        text.push_str(&format!("heuristics {}\n", tags.join(",")));
    }
    text
}

fn contains(base: u64, size: u64, address: u64) -> bool {
    address >= base && address < base.saturating_add(size)
}

fn read_page(live: &LiveProcess, address: u64, region: &MemoryRegion) -> (Vec<u8>, Option<String>) {
    if address < region.base || address >= region_end(region) {
        return (
            Vec::new(),
            Some("주소가 영역 범위를 벗어났습니다".to_string()),
        );
    }
    let len = (region_end(region) - address).min(PAGE_SIZE) as usize;
    let mut buf = vec![0u8; len];
    match live.read(address, &mut buf) {
        Ok(outcome) if outcome.bytes_read > 0 => {
            buf.truncate(outcome.bytes_read);
            let note = outcome.partial.then(|| {
                format!(
                    "부분 읽기: {}/{len} 바이트만 읽었습니다",
                    outcome.bytes_read
                )
            });
            (buf, note)
        }
        Ok(_) => (Vec::new(), Some("0 바이트를 읽었습니다".to_string())),
        Err(err) => (Vec::new(), Some(error_label(&err))),
    }
}

pub fn load_page(pid: u32, region: &MemoryRegion, address: u64) -> (u64, Vec<u8>, Option<String>) {
    let page = clamp_page(address, region);
    let live = match LiveProcess::open(pid) {
        Ok(live) => live,
        Err(err) => return (page, Vec::new(), Some(error_label(&err))),
    };
    let (bytes, error) = read_page(&live, page, region);
    (page, bytes, error)
}

fn probe_pe(
    live: &LiveProcess,
    region: &MemoryRegion,
) -> (Option<xmem_pe::MemoryPeClass>, Option<PeInfo>) {
    if !region.executable || region.size < 64 {
        return (None, None);
    }
    let len = region.size.min(PE_HEADER_PREFIX as u64) as usize;
    let mut buf = vec![0u8; len];
    let Ok(outcome) = live.read(region.base, &mut buf) else {
        return (None, None);
    };
    if outcome.bytes_read < 64 {
        return (None, None);
    }
    let bytes = &buf[..outcome.bytes_read];
    let class = classify_memory_pe(region.classification, bytes);
    let pe = if looks_like_pe(bytes) {
        parse_pe(bytes).ok()
    } else {
        None
    };
    (Some(class), pe)
}

pub fn collect_region_detail(pid: u32, region: MemoryRegion) -> xmem_core::Result<RegionDetail> {
    let live = LiveProcess::open(pid)?;
    let mut notes = Vec::new();

    let modules = match live.modules() {
        Ok(modules) => modules,
        Err(err) => {
            notes.push(format!(
                "모듈 목록을 가져오지 못했습니다 — {}",
                error_label(&err)
            ));
            Vec::new()
        }
    };
    let threads = match live.threads() {
        Ok(threads) => threads,
        Err(err) => {
            notes.push(format!(
                "스레드 목록을 가져오지 못했습니다 — {}",
                error_label(&err)
            ));
            Vec::new()
        }
    };
    let findings = match xmem_detection::detect_source(&live) {
        Ok(findings) => findings,
        Err(err) => {
            notes.push(format!("탐지 실행에 실패했습니다 — {}", error_label(&err)));
            Vec::new()
        }
    };

    let module = modules
        .iter()
        .find(|module| contains(module.base, module.size, region.base))
        .map(|module| module.name.clone());
    let findings: Vec<Finding> = findings
        .into_iter()
        .filter(|finding| {
            finding.evidence.iter().any(|evidence| {
                evidence.region_base == Some(region.base)
                    || evidence
                        .address
                        .is_some_and(|address| contains(region.base, region.size, address))
            })
        })
        .collect();
    let threads: Vec<ThreadInfo> = threads
        .into_iter()
        .filter(|thread| {
            thread
                .start_address
                .is_some_and(|address| contains(region.base, region.size, address))
        })
        .collect();

    let (pe_class, pe) = probe_pe(&live, &region);
    let (page_bytes, page_error) = read_page(&live, region.base, &region);

    Ok(RegionDetail {
        page_start: region.base,
        region,
        module,
        findings,
        threads,
        pe_class,
        pe,
        notes,
        page_bytes,
        page_error,
    })
}

fn field(ui: &mut egui::Ui, label: &str, value: impl Into<String>) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(format!("{label}:")).weak());
        ui.label(value.into());
    });
}

pub fn panel(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        return;
    };
    let colors = palette(app.theme);
    match app.region_detail_task.state() {
        TaskState::Running => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("영역 상세 정보를 불러오는 중...");
            });
            return;
        }
        TaskState::Failed(err) => {
            ui.colored_label(
                colors.danger,
                format!(
                    "영역 상세 정보를 불러오지 못했습니다 — {}",
                    error_label(err)
                ),
            );
            return;
        }
        _ => {}
    }
    let Some(detail) = app.region_detail.as_ref() else {
        ui.label(egui::RichText::new("표에서 영역을 클릭하면 상세 정보가 표시됩니다").weak());
        return;
    };

    let mut goto_page: Option<u64> = None;
    let mut copy_text: Option<String> = None;
    let mut run_detect = false;
    let mut close = false;

    ui.horizontal(|ui| {
        ui.strong(format!("영역 {}", opt_hex(Some(detail.region.base))));
        ui.label(
            egui::RichText::new(format!(
                "{} · {} · {}",
                human_size(detail.region.size),
                detail.region.protection,
                detail.region.classification
            ))
            .weak(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("닫기").clicked() {
                close = true;
            }
            if ui.small_button("탐지 실행").clicked() {
                run_detect = true;
            }
            if ui.small_button("요약 복사").clicked() {
                copy_text = Some(summary_text(&detail.region, detail.module.as_deref()));
            }
        });
    });

    for note in &detail.notes {
        ui.colored_label(colors.warn, format!("주의: {note}"));
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("region_detail_scroll")
        .show(ui, |ui| {
            egui::CollapsingHeader::new("식별")
                .default_open(true)
                .show(ui, |ui| {
                    let region = &detail.region;
                    field(ui, "시작", format!("{:#018x}", region.base));
                    field(
                        ui,
                        "끝",
                        format!("{:#018x}", region_end(region).saturating_sub(1)),
                    );
                    field(
                        ui,
                        "크기",
                        format!(
                            "{} ({} 바이트, {} 페이지)",
                            human_size(region.size),
                            region.size,
                            page_count(region)
                        ),
                    );
                    match region.allocation_base {
                        Some(allocation) => {
                            field(ui, "할당 시작", format!("{allocation:#018x}"));
                            let offset = alloc_offset(region).unwrap_or(0);
                            field(ui, "할당 내 오프셋", format!("{offset:#x}"));
                            if offset > 0 && ui.small_button("할당 시작으로 이동").clicked()
                            {
                                goto_page = Some(allocation);
                            }
                        }
                        None => field(ui, "할당 시작", "-"),
                    }
                    field(ui, "상태", region.state.to_string());
                    field(
                        ui,
                        "종류",
                        region
                            .region_type
                            .map(|region_type| region_type.to_string())
                            .unwrap_or_else(|| "-".into()),
                    );
                    field(ui, "분류", region.classification.to_string());
                    field(
                        ui,
                        "플래그",
                        format!(
                            "읽기 {} · 쓰기 {} · 실행 {}",
                            yes_no(region.readable),
                            yes_no(region.writable),
                            yes_no(region.executable)
                        ),
                    );
                });

            egui::CollapsingHeader::new("보호")
                .default_open(true)
                .show(ui, |ui| {
                    let region = &detail.region;
                    field(ui, "보호", region.protection.to_string());
                    field(ui, "보호 raw", format!("{:#x}", region.protection.raw));
                    let extra = extra_protection_flags(region.protection.raw);
                    field(
                        ui,
                        "추가 비트",
                        if extra.is_empty() {
                            "-".to_string()
                        } else {
                            extra.join(", ")
                        },
                    );
                    match region.allocation_protection {
                        Some(allocation) => {
                            field(ui, "할당 보호", allocation.to_string());
                            field(ui, "할당 보호 raw", format!("{:#x}", allocation.raw));
                        }
                        None => field(ui, "할당 보호", "-"),
                    }
                });

            egui::CollapsingHeader::new("백킹")
                .default_open(true)
                .show(ui, |ui| {
                    let region = &detail.region;
                    field(
                        ui,
                        "매핑 파일",
                        region.mapped_file.as_deref().unwrap_or("-"),
                    );
                    field(ui, "소유 모듈", detail.module.as_deref().unwrap_or("-"));
                    let heuristics = if region.heuristics.is_empty() {
                        "-".to_string()
                    } else {
                        region
                            .heuristics
                            .iter()
                            .map(|heuristic| heur_tag(*heuristic))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    field(ui, "휴리스틱", heuristics);
                    match &detail.pe_class {
                        Some(class) => field(ui, "메모리 PE 판정", class.as_str()),
                        None => field(ui, "메모리 PE 판정", "-"),
                    }
                    if let Some(pe) = &detail.pe {
                        field(ui, "PE 아키텍처", pe_arch(pe));
                        field(ui, "PE 엔트리", format!("{:#x}", pe.entry_point));
                        field(ui, "PE 이미지 크기", human_size(pe.size_of_image as u64));
                        field(ui, "PE 섹션 수", pe.sections.len().to_string());
                        field(ui, "PE 타임스탬프", format_timestamp(pe.time_date_stamp));
                    }
                });

            egui::CollapsingHeader::new("상관 (스레드·탐지)")
                .default_open(false)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(format!(
                            "시작 주소가 이 영역인 스레드 {}개",
                            detail.threads.len()
                        ))
                        .weak(),
                    );
                    for thread in &detail.threads {
                        field(
                            ui,
                            "스레드",
                            format!(
                                "TID {} · 우선순위 {} · 시작 {}",
                                thread.tid,
                                thread
                                    .priority
                                    .map(|p| p.to_string())
                                    .unwrap_or_else(|| "-".into()),
                                opt_hex(thread.start_address)
                            ),
                        );
                    }
                    ui.separator();
                    ui.label(
                        egui::RichText::new(format!(
                            "이 영역을 근거로 한 탐지 {}건",
                            detail.findings.len()
                        ))
                        .weak(),
                    );
                    for finding in &detail.findings {
                        field(
                            ui,
                            &finding.rule_id,
                            format!(
                                "{} [{}/{}]",
                                finding.name,
                                crate::theme::severity_label(finding.severity),
                                crate::theme::confidence_dots(finding.confidence)
                            ),
                        );
                        ui.label(
                            egui::RichText::new(format!("  {}", finding.interpretation)).weak(),
                        );
                    }
                });

            egui::CollapsingHeader::new("메모리 내용 (4 KiB 페이지)")
                .default_open(true)
                .show(ui, |ui| {
                    let region = &detail.region;
                    if region.state != MemoryState::Commit || !region.readable {
                        ui.label(
                            egui::RichText::new(
                                "이 영역은 읽을 수 없습니다 (미커밋이거나 읽기 불가 보호)",
                            )
                            .color(colors.muted),
                        );
                        return;
                    }
                    let first = region.base;
                    let last = last_page_start(region);
                    ui.horizontal(|ui| {
                        if ui.small_button("|◀ 처음").clicked() {
                            goto_page = Some(first);
                        }
                        if ui.small_button("◀ 이전").clicked() {
                            goto_page =
                                Some(detail.page_start.saturating_sub(PAGE_SIZE).max(first));
                        }
                        if ui.small_button("다음 ▶").clicked() {
                            goto_page = Some((detail.page_start + PAGE_SIZE).min(last));
                        }
                        if ui.small_button("끝 ▶|").clicked() {
                            goto_page = Some(last);
                        }
                        ui.label(
                            egui::RichText::new(format!(
                                "{} / {} 페이지",
                                (detail.page_start.saturating_sub(first)) / PAGE_SIZE + 1,
                                page_count(region)
                            ))
                            .weak(),
                        );
                    });
                    if let Some(error) = &detail.page_error {
                        ui.colored_label(colors.danger, format!("읽기 실패 — {error}"));
                    }
                    if detail.page_bytes.is_empty() {
                        ui.label(egui::RichText::new("내용 없음").weak());
                    } else {
                        let text = hex_dump(&detail.page_bytes, detail.page_start);
                        egui::ScrollArea::vertical()
                            .max_height(180.0)
                            .id_salt("region_hex")
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(text).monospace());
                            });
                    }
                });
        });

    if close {
        app.map_selected = None;
        app.region_detail = None;
    }
    if run_detect {
        app.tab = Tab::Detect;
        app.start_detect(pid);
    }
    if let Some(text) = copy_text {
        ui.ctx().copy_text(text);
        app.log
            .push(LogLevel::Info, "영역 요약을 클립보드에 복사했습니다");
    }
    if let Some(address) = goto_page
        && let Some(detail) = app.region_detail.as_mut()
    {
        let region = detail.region.clone();
        let (page, bytes, error) = load_page(pid, &region, address);
        detail.page_start = page;
        detail.page_bytes = bytes;
        detail.page_error = error;
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "가능" } else { "불가" }
}

pub fn format_timestamp(timestamp: u32) -> String {
    if timestamp == 0 {
        return "-".to_string();
    }
    match chrono::DateTime::from_timestamp(timestamp as i64, 0) {
        Some(time) => time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{timestamp} (unix)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryType, Protection, RegionClass};

    fn region(base: u64, size: u64) -> MemoryRegion {
        MemoryRegion {
            base,
            allocation_base: Some(base),
            size,
            state: MemoryState::Commit,
            protection: Protection::new(0x20, true, false, true),
            allocation_protection: Some(Protection::new(0x04, true, true, false)),
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: false,
            executable: true,
            classification: RegionClass::Private,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    #[test]
    fn clamp_page_keeps_address_inside_region() {
        let region = region(0x1000, 3 * PAGE_SIZE);
        assert_eq!(clamp_page(0x0, &region), 0x1000);
        assert_eq!(clamp_page(0x1000 + PAGE_SIZE, &region), 0x1000 + PAGE_SIZE);
        assert_eq!(clamp_page(u64::MAX, &region), 0x1000 + 2 * PAGE_SIZE);
    }

    #[test]
    fn page_count_and_last_page_match_region_end() {
        let region = region(0x2000, PAGE_SIZE + 1);
        assert_eq!(page_count(&region), 2);
        assert_eq!(last_page_start(&region), 0x2000 + PAGE_SIZE);
        assert_eq!(region_end(&region), 0x2000 + PAGE_SIZE + 1);
    }

    #[test]
    fn extra_protection_flags_decode_bits() {
        assert!(extra_protection_flags(0x20).is_empty());
        assert_eq!(extra_protection_flags(0x120), vec!["GUARD"]);
        assert_eq!(extra_protection_flags(0x320), vec!["GUARD", "NOCACHE"]);
    }

    #[test]
    fn alloc_offset_uses_allocation_base() {
        let mut region = region(0x3000, PAGE_SIZE);
        assert_eq!(alloc_offset(&region), Some(0));
        region.allocation_base = Some(0x1000);
        assert_eq!(alloc_offset(&region), Some(0x2000));
        region.allocation_base = None;
        assert_eq!(alloc_offset(&region), None);
    }

    #[test]
    fn summary_text_includes_key_fields() {
        let region = region(0x1000, PAGE_SIZE);
        let text = summary_text(&region, Some("sample.dll"));
        assert!(text.contains("base 0x1000"));
        assert!(text.contains("allocation_base 0x1000"));
        assert!(text.contains("sample.dll"));
        assert!(text.contains("execute=true"));
    }

    #[test]
    fn timestamp_formats_unix_epoch() {
        assert_eq!(format_timestamp(0), "-");
        assert!(format_timestamp(1_700_000_000).contains("2023-11-14"));
    }
}
