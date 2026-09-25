//! 맵·스캔·탐지 결과를 JSON/CSV 파일로 내보낸다.
//!
//! 파일은 temp → 재읽기 검증 → rename 순서로 기록하며, 실패 시 temp를 남기지 않는다.

use std::path::{Path, PathBuf};

use xmem_core::{Finding, MemoryRegion, Result, XmemError};
use xmem_memory::ScanReport;

use crate::cli::{ExportFormat, GlobalArgs};
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

/// 내보낼 결과. 참조만 보관해 대용량 결과의 복사를 피한다.
#[derive(Debug)]
pub enum ExportPayload<'a> {
    Map(&'a [MemoryRegion]),
    Scan(&'a ScanReport),
    Detect(&'a [Finding]),
}

/// 결과를 `path`에 쓰고 기록한 바이트 수를 돌려준다.
pub fn write_export(path: &Path, format: ExportFormat, payload: &ExportPayload<'_>) -> Result<u64> {
    let bytes = match format {
        ExportFormat::Json => json_bytes(payload)?,
        ExportFormat::Csv => csv_text(payload).into_bytes(),
    };
    write_atomic(path, &bytes)?;
    Ok(bytes.len() as u64)
}

fn json_bytes(payload: &ExportPayload<'_>) -> Result<Vec<u8>> {
    let value = match payload {
        ExportPayload::Map(regions) => serde_json::to_value(regions),
        ExportPayload::Scan(report) => serde_json::to_value(report),
        ExportPayload::Detect(findings) => serde_json::to_value(findings),
    }
    .map_err(|e| XmemError::JsonError {
        reason: e.to_string(),
    })?;
    serde_json::to_vec_pretty(&value).map_err(|e| XmemError::JsonError {
        reason: e.to_string(),
    })
}

/// 저장 완료를 stdout 계약(--json/사람용)에 맞게 알린다.
pub fn emit_export_saved(
    output: &str,
    format: ExportFormat,
    bytes: u64,
    count: usize,
    kind: &str,
    global: &GlobalArgs,
) {
    match resolve_mode(global.json) {
        OutputMode::Json => emit_json(&success_envelope(serde_json::json!({
            "output": output,
            "format": format.as_str(),
            "kind": kind,
            "file_bytes": bytes,
            "count": count,
        }))),
        OutputMode::Human => emit(&format!(
            "내보냄: {output} ({}, {count}건, {})\n",
            format.as_str(),
            human_size(bytes)
        )),
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
    use std::path::PathBuf;
    use xmem_core::{
        Confidence, Evidence, MemoryState, MemoryType, Protection, RegionClass, Severity,
    };
    use xmem_memory::ScanMatch;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xmem-export-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn sample_region(base: u64, mapped_file: Option<&str>) -> MemoryRegion {
        MemoryRegion {
            base,
            size: 0x1000,
            allocation_base: Some(base),
            state: MemoryState::Commit,
            protection: Protection::new(0x40, true, true, true),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: true,
            executable: true,
            classification: RegionClass::Private,
            heuristics: vec![xmem_core::Heuristic::WritableExecutable],
            mapped_file: mapped_file.map(str::to_string),
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "XMEM-001".into(),
            name: "Executable Private Memory".into(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![
                Evidence::new("region")
                    .with_region_base(0x1000)
                    .observe("protection", "RWX (0x40)"),
            ],
            heuristic: "private memory with executable protection".into(),
            interpretation: "Potentially suspicious memory region".into(),
        }
    }

    fn sample_report() -> ScanReport {
        ScanReport {
            matches: vec![ScanMatch {
                address: 0x1004,
                region_base: 0x1000,
                region_size: 0x1000,
                offset: 4,
                class: RegionClass::Private,
                protection: Protection::new(0x40, true, true, true),
                mapped_file: None,
            }],
            stats: xmem_memory::ScanStats {
                regions_total: 4,
                regions_scanned: 3,
                regions_skipped: 1,
                bytes_scanned: 0x3000,
                read_failures: 0,
                access_denied: 0,
                invalid_address: 0,
                other_failures: 0,
                partial_reads: 0,
                matches: 1,
                threads: 2,
                elapsed_ms: 7,
                rss_bytes: 0,
            },
            cancelled: false,
            truncated: false,
            policy_restricted: false,
        }
    }

    #[test]
    fn map_csv_has_header_and_row_per_region() {
        let dir = temp_dir("map-csv");
        let path = dir.join("map.csv");
        let regions = vec![sample_region(0x1000, Some("C:\\a,b.dll"))];
        let bytes = write_export(&path, ExportFormat::Csv, &ExportPayload::Map(&regions)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(bytes, text.len() as u64);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].starts_with("base,size,"), "{}", lines[0]);
        assert!(lines[0].contains("mapped_file"), "{}", lines[0]);
        assert!(lines[1].contains("\"C:\\a,b.dll\""), "{}", lines[1]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn map_json_roundtrips_regions() {
        let dir = temp_dir("map-json");
        let path = dir.join("map.json");
        let regions = vec![
            sample_region(0x1000, None),
            sample_region(0x2000, Some("C:\\x.dll")),
        ];
        write_export(&path, ExportFormat::Json, &ExportPayload::Map(&regions)).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let back: Vec<MemoryRegion> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, regions);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_json_has_stats_and_matches() {
        let dir = temp_dir("scan-json");
        let path = dir.join("scan.json");
        let report = sample_report();
        write_export(&path, ExportFormat::Json, &ExportPayload::Scan(&report)).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["stats"]["regions_scanned"], 3);
        assert_eq!(value["matches"].as_array().unwrap().len(), 1);
        assert_eq!(value["matches"][0]["address"], 0x1004);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_json_roundtrips_findings() {
        let dir = temp_dir("detect-json");
        let path = dir.join("detect.json");
        let findings = vec![sample_finding()];
        write_export(&path, ExportFormat::Json, &ExportPayload::Detect(&findings)).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let back: Vec<Finding> = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, findings);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_csv_escapes_quotes() {
        let dir = temp_dir("detect-csv");
        let path = dir.join("detect.csv");
        let mut finding = sample_finding();
        finding.heuristic = "say \"hello\", twice".into();
        let findings = vec![finding];
        write_export(&path, ExportFormat::Csv, &ExportPayload::Detect(&findings)).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"say \"\"hello\"\", twice\""), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_rename_removes_temp_file() {
        let dir = temp_dir("fail");
        let target = dir.join("out.csv");
        std::fs::create_dir(&target).unwrap();
        let regions = [sample_region(0x1000, None)];
        assert!(write_export(&target, ExportFormat::Csv, &ExportPayload::Map(&regions)).is_err());
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
