//! 메모리맵 탭.

use xmem_core::{Heuristic, MemoryRegion, RegionClass};
use xmem_memory::RegionFilters;

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::overview::failure_banner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSort {
    AddressAsc,
    AddressDesc,
    SizeDesc,
}

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
    value
        .map(|v| format!("{v:#018x}"))
        .unwrap_or_else(|| "-".into())
}

pub fn opt_num<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
}

pub fn select_and_sort(
    regions: &[MemoryRegion],
    filters: &RegionFilters,
    sort: MapSort,
) -> Vec<usize> {
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

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
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
        TaskState::Failed(err) => {
            let failure = crate::app::classify_open_failure(err, app.is_elevated, pid);
            failure_banner(ui, app, &failure);
            return;
        }
        TaskState::Cancelled => {
            ui.label(egui::RichText::new("취소되었습니다").weak());
            return;
        }
        _ => {}
    }
    if app.map.is_none() {
        ui.label(egui::RichText::new("맵을 불러오는 중...").weak());
        return;
    }
    if app.map_selected.is_some() {
        egui::Panel::bottom(egui::Id::new("region_detail"))
            .resizable(true)
            .default_size(320.0)
            .size_range(140.0..=900.0)
            .show(ui, |ui| crate::views::region::panel(ui, app));
    }
    let Some(map) = app.map.as_ref() else {
        return;
    };
    if map.truncated {
        ui.label(
            egui::RichText::new("영역 수 상한(1,048,576)에 도달해 일부만 표시됩니다")
                .color(palette(app.theme).warn),
        );
    }
    let selected = select_and_sort(&map.regions, &app.map_filters, app.map_sort);
    ui.label(egui::RichText::new(format!("{}개 영역 표시", selected.len())).weak());
    let colors = palette(app.theme);
    let selected_base = app.map_selected;
    let mut clicked_region: Option<MemoryRegion> = None;
    crate::views::truncate_cells(ui);
    egui_extras::TableBuilder::new(ui)
        .striped(true)
        .drag_to_scroll(egui::scroll_area::DragScroll::Never)
        .sense(egui::Sense::click())
        .column(egui_extras::Column::exact(140.0))
        .column(egui_extras::Column::exact(80.0))
        .column(egui_extras::Column::exact(90.0))
        .column(egui_extras::Column::exact(90.0))
        .column(egui_extras::Column::exact(120.0))
        .column(egui_extras::Column::exact(90.0))
        .column(egui_extras::Column::remainder().clip(true))
        .header(18.0, |mut header| {
            for title in [
                "BASE",
                "SIZE",
                "STATE",
                "TYPE",
                "PROTECTION",
                "CLASS",
                "HEURISTICS / FILE",
            ] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(20.0, selected.len(), |mut row| {
                let index = row.index();
                let region = &map.regions[selected[index]];
                row.set_selected(selected_base == Some(region.base));
                let mut row_clicked = false;
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(opt_hex(Some(region.base))),
                    );
                });
                row.col(|ui| {
                    row_clicked |=
                        crate::views::table_cell(ui, egui::RichText::new(human_size(region.size)));
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(format!("{:?}", region.state).to_uppercase()),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(
                            region
                                .region_type
                                .map(|t| format!("{t:?}").to_uppercase())
                                .unwrap_or_else(|| "-".into()),
                        ),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(region.protection.to_string()),
                    );
                });
                row.col(|ui| {
                    row_clicked |= crate::views::table_cell(
                        ui,
                        egui::RichText::new(format!("{:?}", region.classification).to_lowercase()),
                    );
                });
                row.col(|ui| {
                    let mut text = region
                        .heuristics
                        .iter()
                        .map(|h| heur_tag(*h))
                        .collect::<Vec<_>>()
                        .join(",");
                    if let Some(file) = &region.mapped_file {
                        if !text.is_empty() {
                            text.push(' ');
                        }
                        text.push_str(file);
                    }
                    if text.is_empty() {
                        text = "-".into();
                    }
                    let color = if region.heuristics.is_empty() {
                        colors.muted
                    } else {
                        colors.warn
                    };
                    row_clicked |=
                        crate::views::table_cell(ui, egui::RichText::new(text).color(color));
                });
                if row_clicked {
                    clicked_region = Some(region.clone());
                }
            });
        });
    if let Some(region) = clicked_region {
        app.select_region(pid, region);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, Protection};

    fn region(base: u64, size: u64, class: RegionClass, exec: bool) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
            allocation_base: Some(base),
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
        assert_eq!(
            select_and_sort(&regions, &all, MapSort::AddressAsc),
            vec![1, 2, 0]
        );
        assert_eq!(
            select_and_sort(&regions, &all, MapSort::AddressDesc),
            vec![0, 2, 1]
        );
        assert_eq!(
            select_and_sort(&regions, &all, MapSort::SizeDesc),
            vec![1, 2, 0]
        );
        let exec_only = RegionFilters {
            executable_only: true,
            ..RegionFilters::default()
        };
        assert_eq!(
            select_and_sort(&regions, &exec_only, MapSort::AddressAsc),
            vec![1, 2]
        );
    }
}
