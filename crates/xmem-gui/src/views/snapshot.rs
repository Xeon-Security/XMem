//! 스냅샷 탭: 생성(진행/취소) + diff.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use xmem_core::{Result, XmemError};
use xmem_forensics::{CollectOptions, SnapshotDiff, collect, encode, write_file};

use crate::app::XMemApp;
use crate::task::TaskState;
use crate::theme::palette;
use crate::views::map::human_size;

const DISK_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

/// CLI `create_snapshot_file`과 동일한 파이프라인(수집→인코딩→디스크 검사→원자적 저장).
pub fn create_snapshot_file(pid: u32, output: &Path, cancel: &AtomicBool) -> Result<u64> {
    let live = xmem_memory::LiveProcess::open(pid)?;
    let envelope = collect(&live, &CollectOptions::default(), cancel)?;
    let bytes = encode(&envelope)?;
    let dir = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let free = xmem_windows::free_space_bytes(&dir.to_string_lossy())?;
    let needed = bytes.len() as u64 + DISK_MARGIN_BYTES;
    if free < needed {
        return Err(XmemError::SnapshotError {
            reason: format!("디스크 공간 부족: 필요 {needed}, 가용 {free}"),
        });
    }
    write_file(output, &bytes)?;
    Ok(bytes.len() as u64)
}

fn short_hash(hash: &str) -> &str {
    &hash[..hash.len().min(16)]
}

/// CLI `render_diff`와 같은 라인 포맷의 요약 텍스트.
pub fn render_diff(diff: &SnapshotDiff) -> String {
    let s = &diff.summary;
    let mut out = format!(
        "before: {} ({}) {}\nafter: {} ({}) {}\nregions: +{} -{} ~{} | content ~{} | modules: +{} -{} ~{} | threads: +{} -{} ~{} | detections: +{} -{} ~{}\n",
        diff.before.name,
        diff.before.pid,
        diff.before.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        diff.after.name,
        diff.after.pid,
        diff.after.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        s.regions_added,
        s.regions_removed,
        s.regions_changed,
        s.content_changed,
        s.modules_added,
        s.modules_removed,
        s.modules_changed,
        s.threads_added,
        s.threads_removed,
        s.threads_changed,
        s.detections_added,
        s.detections_removed,
        s.detections_changed,
    );
    for region in &diff.regions_added {
        out.push_str(&format!(
            "+ region {:#018x} {} {} {}\n",
            region.base,
            human_size(region.size),
            format!("{:?}", region.state).to_uppercase(),
            region.protection
        ));
    }
    for region in &diff.regions_removed {
        out.push_str(&format!(
            "- region {:#018x} {} {} {}\n",
            region.base,
            human_size(region.size),
            format!("{:?}", region.state).to_uppercase(),
            region.protection
        ));
    }
    for change in &diff.regions_changed {
        out.push_str(&format!(
            "~ region {:#018x} {}\n",
            change.after.base,
            change.changes.join(", ")
        ));
    }
    for change in &diff.content_changed {
        out.push_str(&format!(
            "* content {:#018x} {} -> {}\n",
            change.base,
            short_hash(&change.before_hash),
            short_hash(&change.after_hash)
        ));
    }
    for module in &diff.modules_added {
        out.push_str(&format!("+ module {} {:#018x}\n", module.name, module.base));
    }
    for module in &diff.modules_removed {
        out.push_str(&format!("- module {} {:#018x}\n", module.name, module.base));
    }
    for change in &diff.modules_changed {
        out.push_str(&format!(
            "~ module {} {}\n",
            change.after.name,
            change.changes.join(", ")
        ));
    }
    for thread in &diff.threads_added {
        out.push_str(&format!("+ thread tid {}\n", thread.tid));
    }
    for thread in &diff.threads_removed {
        out.push_str(&format!("- thread tid {}\n", thread.tid));
    }
    for change in &diff.threads_changed {
        out.push_str(&format!(
            "~ thread tid {} {}\n",
            change.after.tid,
            change.changes.join(", ")
        ));
    }
    for finding in &diff.detections_added {
        out.push_str(&format!(
            "+ detection {} {}\n",
            finding.rule_id, finding.name
        ));
    }
    for finding in &diff.detections_removed {
        out.push_str(&format!(
            "- detection {} {}\n",
            finding.rule_id, finding.name
        ));
    }
    for change in &diff.detections_changed {
        out.push_str(&format!(
            "~ detection {} {}\n",
            change.after.rule_id,
            change.changes.join(", ")
        ));
    }
    out
}

fn error_label(ui: &mut egui::Ui, app: &XMemApp, err: &XmemError) {
    ui.label(egui::RichText::new(err.to_string()).color(palette(app.theme).danger));
}

pub fn ui(ui: &mut egui::Ui, app: &mut XMemApp) {
    let Some(pid) = app.selected_pid else {
        ui.label(egui::RichText::new("왼쪽에서 프로세스를 선택하세요").weak());
        return;
    };
    ui.label(egui::RichText::new("스냅샷 생성").strong());
    ui.horizontal(|ui| {
        ui.label("출력 파일");
        ui.add(
            egui::TextEdit::singleline(&mut app.snapshot_output)
                .hint_text("비우면 Documents\\XMem 아래 기본 이름으로 저장")
                .desired_width(360.0),
        );
        if ui.button("찾아보기").clicked() {
            let name =
                crate::config::output_file_name("snapshot", pid, "xmem", chrono::Local::now());
            let dir = app
                .config
                .last_output_dir
                .clone()
                .unwrap_or_else(crate::config::default_output_dir);
            let mut dialog = rfd::FileDialog::new()
                .add_filter("XMem snapshot", &["xmem"])
                .set_file_name(&name)
                .set_directory(&dir);
            if !app.snapshot_output.trim().is_empty() {
                dialog = dialog.set_file_name(app.snapshot_output.trim());
            }
            if let Some(path) = dialog.save_file() {
                app.snapshot_output = path.to_string_lossy().into_owned();
            }
        }
        let running = app.snapshot_create_task.is_running();
        if ui
            .add_enabled(!running, egui::Button::new("생성"))
            .clicked()
        {
            app.start_snapshot_create(pid);
        }
        if running {
            ui.spinner();
            ui.label("수집/해싱 중...");
            if ui.button("취소").clicked() {
                app.snapshot_create_task.cancel();
            }
        }
    });
    if let TaskState::Failed(err) = app.snapshot_create_task.state() {
        error_label(ui, app, err);
    }
    if let TaskState::Cancelled = app.snapshot_create_task.state() {
        ui.label(egui::RichText::new("취소되었습니다").color(palette(app.theme).warn));
    }
    if let Some((path, bytes)) = app.snapshot_created.as_ref() {
        ui.label(egui::RichText::new(format!("생성됨: {path} ({})", human_size(*bytes))).weak());
    }
    ui.separator();
    ui.label(egui::RichText::new("스냅샷 비교").strong());
    ui.horizontal(|ui| {
        ui.label("이전");
        ui.add(
            egui::TextEdit::singleline(&mut app.snapshot_before)
                .hint_text("before.xmem")
                .desired_width(320.0),
        );
        if ui.button("열기").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("XMem snapshot", &["xmem"])
                .pick_file()
        {
            app.snapshot_before = path.to_string_lossy().into_owned();
        }
    });
    ui.horizontal(|ui| {
        ui.label("이후");
        ui.add(
            egui::TextEdit::singleline(&mut app.snapshot_after)
                .hint_text("after.xmem")
                .desired_width(320.0),
        );
        if ui.button("열기").clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter("XMem snapshot", &["xmem"])
                .pick_file()
        {
            app.snapshot_after = path.to_string_lossy().into_owned();
        }
    });
    ui.horizontal(|ui| {
        let running = app.snapshot_diff_task.is_running();
        if ui
            .add_enabled(!running, egui::Button::new("비교"))
            .clicked()
        {
            app.start_snapshot_diff();
        }
        if running {
            ui.spinner();
        }
    });
    if let TaskState::Failed(err) = app.snapshot_diff_task.state() {
        error_label(ui, app, err);
    }
    if let Some(diff) = app.snapshot_diff.as_ref() {
        let text = render_diff(diff);
        crate::views::pane_hint(ui);
        crate::views::resizable_pane(ui, "snapshot_diff_pane", 360.0, 160.0, |ui| {
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    ui.label(egui::RichText::new(text).monospace());
                });
        });
    }
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

    #[test]
    fn render_diff_of_identical_files_has_zero_summary() {
        let dir = std::env::temp_dir().join(format!("xmem-gui-snap2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.xmem");
        let cancel = AtomicBool::new(false);
        create_snapshot_file(std::process::id(), &path, &cancel).unwrap();
        let envelope = xmem_forensics::read_file(&path).unwrap();
        let diff = xmem_forensics::diff(&envelope, &envelope);
        let text = render_diff(&diff);
        assert!(text.contains("regions: +0 -0 ~0"), "{text}");
        assert!(text.contains("detections: +0 -0 ~0"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
