//! 맵·스캔·탐지 결과 내보내기(JSON/CSV)와 저장 대화상자.
//!
//! xmem-cli와 같은 스키마를 쓰지만 GUI는 CLI 크레이트에 의존할 수 없어
//! 쓰기 로직을 이곳에 둔다. 파일은 temp → 재읽기 검증 → rename 순서로 기록한다.

use std::path::{Path, PathBuf};

use serde::Serialize;
use xmem_core::{Finding, MemoryRegion, Result, XmemError};
use xmem_memory::ScanReport;

use crate::log::{LogBuffer, LogLevel};
use crate::views::map::human_size;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
}

impl ExportFormat {
    pub fn label(self) -> &'static str {
        match self {
            ExportFormat::Json => "JSON",
            ExportFormat::Csv => "CSV",
        }
    }

    pub fn ext(self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
        }
    }
}

/// 내보낼 결과. 참조만 보관해 대용량 결과의 복사를 피한다.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ExportPayload<'a> {
    Map(&'a [MemoryRegion]),
    Scan(&'a ScanReport),
    Detect(&'a [Finding]),
}

/// 결과를 `path`에 쓰고 기록한 바이트 수를 돌려준다.
pub fn write_export(path: &Path, format: ExportFormat, payload: &ExportPayload<'_>) -> Result<u64> {
    let bytes = match format {
        ExportFormat::Json => {
            serde_json::to_vec_pretty(payload).map_err(|e| XmemError::JsonError {
                reason: e.to_string(),
            })?
        }
        ExportFormat::Csv => csv_text(payload).into_bytes(),
    };
    write_atomic(path, &bytes)?;
    Ok(bytes.len() as u64)
}

/// 저장 대화상자를 띄우고 선택한 경로에 결과를 쓴다.
/// 성공하면 저장한 폴더를 돌려준다(다음 대화상자 시작 위치 기억용).
pub fn save_with_dialog(
    pid: u32,
    kind: &str,
    format: ExportFormat,
    payload: &ExportPayload<'_>,
    last_dir: Option<PathBuf>,
    log: &mut LogBuffer,
) -> Option<PathBuf> {
    let path = rfd::FileDialog::new()
        .set_file_name(crate::config::output_file_name(
            kind,
            pid,
            format.ext(),
            chrono::Local::now(),
        ))
        .set_directory(last_dir.unwrap_or_else(crate::config::default_output_dir))
        .add_filter(format.label(), &[format.ext()])
        .save_file()?;
    match write_export(&path, format, payload) {
        Ok(bytes) => {
            log.push(
                LogLevel::Info,
                format!(
                    "내보냄: {} ({}, {})",
                    path.display(),
                    format.label(),
                    human_size(bytes)
                ),
            );
            path.parent().map(Path::to_path_buf)
        }
        Err(err) => {
            log.push(LogLevel::Error, format!("내보내기 실패: {err}"));
            None
        }
    }
}

fn csv_text(payload: &ExportPayload<'_>) -> String {
    let mut out = String::new();
    match payload {
        ExportPayload::Map(regions) => {
            out.push_str(
                "base,size,allocation_base,state,protection,allocation_protection,region_type,readable,writable,executable,classification,heuristics,mapped_file\n",
            );
            for region in *regions {
                let fields = [
                    format!("{:#018x}", region.base),
                    region.size.to_string(),
                    region
                        .allocation_base
                        .map(|base| format!("{base:#018x}"))
                        .unwrap_or_default(),
                    region.state.to_string(),
                    region.protection.to_string(),
                    region
                        .allocation_protection
                        .map(|protection| protection.to_string())
                        .unwrap_or_default(),
                    region
                        .region_type
                        .map(|ty| ty.to_string())
                        .unwrap_or_default(),
                    region.readable.to_string(),
                    region.writable.to_string(),
                    region.executable.to_string(),
                    region.classification.to_string(),
                    region
                        .heuristics
                        .iter()
                        .map(|heuristic| heuristic.to_string())
                        .collect::<Vec<_>>()
                        .join("|"),
                    region.mapped_file.clone().unwrap_or_default(),
                ];
                push_csv_row(&mut out, &fields);
            }
        }
        ExportPayload::Scan(report) => {
            out.push_str("address,region_base,region_size,offset,class,protection,mapped_file\n");
            for found in &report.matches {
                let fields = [
                    format!("{:#018x}", found.address),
                    format!("{:#018x}", found.region_base),
                    found.region_size.to_string(),
                    found.offset.to_string(),
                    found.class.to_string(),
                    found.protection.to_string(),
                    found.mapped_file.clone().unwrap_or_default(),
                ];
                push_csv_row(&mut out, &fields);
            }
        }
        ExportPayload::Detect(findings) => {
            out.push_str(
                "rule_id,name,severity,confidence,evidence_count,heuristic,interpretation\n",
            );
            for finding in *findings {
                let fields = [
                    finding.rule_id.clone(),
                    finding.name.clone(),
                    format!("{:?}", finding.severity).to_lowercase(),
                    format!("{:?}", finding.confidence).to_lowercase(),
                    finding.evidence.len().to_string(),
                    finding.heuristic.clone(),
                    finding.interpretation.clone(),
                ];
                push_csv_row(&mut out, &fields);
            }
        }
    }
    out
}

fn push_csv_row(out: &mut String, fields: &[String]) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&csv_field(field));
    }
    out.push('\n');
}

/// 쉼표·따옴표·줄바꿈이 있으면 따옴표로 감싸고 내부 따옴표를 두 번 반복한다.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = temp_path(path);
    if let Err(error) = std::fs::write(&temp, bytes) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    let validate = std::fs::read(&temp)
        .map_err(XmemError::Io)
        .and_then(|read_back| {
            if read_back == bytes {
                Ok(())
            } else {
                Err(XmemError::InvalidInput {
                    reason: "내보내기 검증 실패: 기록한 내용과 다시 읽은 내용이 다릅니다".into(),
                })
            }
        });
    if let Err(err) = validate {
        std::fs::remove_file(&temp).ok();
        return Err(err);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        std::fs::remove_file(&temp).ok();
        return Err(XmemError::Io(error));
    }
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "export.tmp".into());
    name.push(format!(".tmp-{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{MemoryState, MemoryType, Protection, RegionClass};

    fn sample_region(base: u64, mapped_file: Option<&str>) -> MemoryRegion {
        MemoryRegion {
            base,
            size: 0x1000,
            allocation_base: Some(base),
            state: MemoryState::Commit,
            protection: Protection::new(0x04, true, true, false),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: true,
            executable: false,
            classification: RegionClass::Private,
            heuristics: Vec::new(),
            mapped_file: mapped_file.map(str::to_string),
        }
    }

    #[test]
    fn map_json_roundtrips_regions() {
        let dir = std::env::temp_dir().join(format!("xmem-gui-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("map.json");
        let regions = vec![sample_region(0x1000, Some("C:\\x.dll"))];
        write_export(&path, ExportFormat::Json, &ExportPayload::Map(&regions)).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let back: Vec<MemoryRegion> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, regions);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn map_csv_quotes_separators() {
        let dir = std::env::temp_dir().join(format!("xmem-gui-csv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("map.csv");
        let regions = vec![sample_region(0x1000, Some("C:\\a,b.dll"))];
        write_export(&path, ExportFormat::Csv, &ExportPayload::Map(&regions)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].starts_with("base,size,"), "{}", lines[0]);
        assert!(lines[1].contains("\"C:\\a,b.dll\""), "{}", lines[1]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
