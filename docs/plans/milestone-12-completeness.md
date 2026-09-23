# M12 완성도(Report, 문서, 자원 모니터링) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xmem report --pid <PID> --output <FILE>`(JSON/Markdown)를 구현하고, 스펙 §42의 미작성 문서 6종을 추가하며, 스캔 자원 통계에 XMem 자신의 RSS를 포함한다.

**Architecture:** 리포트 조립은 `xmem-forensics::report`(ReportData + JSON/Markdown 렌더 + temp→rename 저장)에, 대상 수집은 CLI가 기존 `LiveProcess`/`detect`로 조합한다. 문서는 검증된 사실만 담는다. RSS는 `xmem-windows`에서 조회해 `xmem-memory` 스캔 통계에 붙인다.

**Tech Stack:** 기존 workspace 그대로. 새 dependency 없음.

**Spec:** `docs/architecture.md` §5(forensics 책임), §11(CLI 계약 report), §14(Status), 스펙 §42(문서), §50(M12)

## Global Constraints

- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.
- 새 dependency 금지. `unsafe`는 `xmem-windows`에만. runtime `unwrap()`/`expect()` 금지(테스트 제외).
- CLI 사용자 출력은 반드시 `crate::output::emit`/`emit_json`(EPIPE 안전). `print!`/`println!` 금지.
- 오류는 구조화 `XmemError`. read-only 원칙 유지(리포트는 대상 프로세스를 변경하지 않는다).
- 파일 쓰기는 temp(`{path}.tmp-{pid}`) → rename, 실패 시 temp 제거.
- 문서·커밋 메시지는 한국어. 커밋 prefix feat/fix/docs/style/refactor/test/chore.
- 문서에 검증되지 않은 내용을 사실처럼 쓰지 않는다. 불확실한 것은 "개념" 또는 "한계"로 표기.

## Review Focus

1. **리포트 원자성**: 저장 실패/중단 시 `.tmp-` 파일이 남지 않고, 기존 파일이 잘린 상태로 남지 않는다.
2. **비정상 입력**: 존재하지 않는 PID·권한 없는 PID(`lsass`)·쓰기 불가 경로에서 panic 없이 구조화 오류.
3. **문서 정확성**: 6개 문서가 실제 구현(명령/규칙/포맷)과 어긋나지 않는다(미구현 기능을 구현된 것처럼 쓰지 않는다).
4. **RSS 통계 정직성**: RSS 조회 실패 시 0으로 표기(panic 금지), 값의 의미(스캔 후 XMem 자신)를 문서에 명시.
5. **JSON 스키마 불변**: 기존 envelope(schema_version/ok/data)과 필드가 깨지지 않는다. report JSON도 envelope로 감싼다.

---

### Task 1: xmem-forensics — Report 데이터와 JSON/Markdown 렌더

**Files:**
- Create: `crates/xmem-forensics/src/report.rs`
- Modify: `crates/xmem-forensics/src/lib.rs` (`pub mod report;` + 재수출)
- Test: report.rs 내 테스트 3

**Interfaces:**
- Consumes: `xmem_core::{JSON_SCHEMA_VERSION, VERSION, Finding, MemoryRegion, MemoryState, ModuleInfo, ProcessInfo, RegionClass, ThreadInfo, XmemError, Result}`, `chrono::{DateTime, Utc}`.
- Produces (Task 2가 사용):
  - `ReportSummary` / `ReportData` (Serialize)
  - `ReportData::new(process, regions, modules, threads, findings) -> ReportData`
  - `is_markdown(path: &Path) -> bool`
  - `to_json(&ReportData) -> Result<Vec<u8>>`
  - `to_markdown(&ReportData) -> String`
  - `write_report(&ReportData, path: &Path) -> Result<u64>`

- [ ] **Step 1: 실패하는 테스트 작성**

`crates/xmem-forensics/src/report.rs` 생성(테스트만):

```rust
//! 분석 리포트(JSON/Markdown) 조립과 저장.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;
use xmem_core::{
    Finding, JSON_SCHEMA_VERSION, MemoryRegion, MemoryState, ModuleInfo, ProcessInfo, RegionClass,
    Result, ThreadInfo, VERSION, XmemError,
};

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        Confidence, Evidence, MemoryType, ModuleInfo, ProcessArch, Protection, Severity, ThreadInfo,
    };

    fn sample_region(base: u64, size: u64, class: RegionClass, exec: bool) -> MemoryRegion {
        MemoryRegion {
            base,
            size,
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

    fn sample_report() -> ReportData {
        let process = ProcessInfo {
            pid: 4242,
            ppid: Some(1),
            name: "sample.exe".to_string(),
            image_path: Some("C:\\sample.exe".to_string()),
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: Some(1),
            module_count: Some(1),
        };
        let regions = vec![
            sample_region(0x1000, 0x2000, RegionClass::Private, true),
            sample_region(0x4000, 0x1000, RegionClass::Image, false),
        ];
        let modules = vec![ModuleInfo {
            name: "sample.exe".to_string(),
            base: 0x4000,
            size: 0x1000,
            path: Some("C:\\sample.exe".to_string()),
            arch: Some(ProcessArch::X64),
        }];
        let threads = vec![ThreadInfo {
            tid: 77,
            pid: 4242,
            priority: Some(0),
            start_address: Some(0x1000),
            start_region_base: Some(0x1000),
            start_module: None,
        }];
        let findings = vec![Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "Executable Private Memory".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }];
        ReportData::new(process, regions, modules, threads, findings)
    }

    #[test]
    fn new_builds_summary_counts() {
        let report = sample_report();
        assert_eq!(report.summary.regions_total, 2);
        assert_eq!(report.summary.private, 1);
        assert_eq!(report.summary.image, 1);
        assert_eq!(report.summary.executable, 1);
        assert_eq!(report.summary.committed, 2);
        assert_eq!(report.summary.committed_bytes, 0x3000);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.xmem_version, VERSION);
        assert_eq!(report.schema_version, JSON_SCHEMA_VERSION);
    }

    #[test]
    fn markdown_contains_sections_and_findings() {
        let text = to_markdown(&sample_report());
        assert!(text.contains("# XMem Report"));
        assert!(text.contains("## Process"));
        assert!(text.contains("## Findings"));
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("| Base |"));
        assert!(text.contains("sample.exe"));
    }

    #[test]
    fn write_report_writes_json_and_markdown() {
        let dir = std::env::temp_dir().join(format!("xmem-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = sample_report();

        let json_path = dir.join("report.json");
        let json_bytes = write_report(&report, &json_path).unwrap();
        assert!(json_bytes > 0);
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
        assert_eq!(value["process"]["pid"], 4242);

        let md_path = dir.join("report.md");
        assert!(is_markdown(&md_path));
        let md_bytes = write_report(&report, &md_path).unwrap();
        assert!(md_bytes > 0);
        let text = std::fs::read_to_string(&md_path).unwrap();
        assert!(text.contains("## Findings"));

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp 파일이 남았다");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo check -p xmem-forensics --tests`
Expected: FAIL — `ReportData`/`to_markdown`/`write_report`/`is_markdown` 미정의(E0425/E0432/E0433)

- [ ] **Step 3: 구현**

테스트 모듈 위에 추가:

```rust
/// regions/modules/threads/findings 요약 카운트.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReportSummary {
    pub regions_total: usize,
    pub committed: usize,
    pub reserved: usize,
    pub free: usize,
    pub image: usize,
    pub mapped: usize,
    pub private: usize,
    pub executable: usize,
    pub committed_bytes: u64,
    pub module_count: usize,
    pub thread_count: usize,
    pub finding_count: usize,
}

/// 리포트 한 건의 전체 데이터(JSON 직렬화 가능).
#[derive(Debug, Clone, Serialize)]
pub struct ReportData {
    pub generated_at: DateTime<Utc>,
    pub xmem_version: String,
    pub schema_version: u32,
    pub process: ProcessInfo,
    pub regions: Vec<MemoryRegion>,
    pub modules: Vec<ModuleInfo>,
    pub threads: Vec<ThreadInfo>,
    pub findings: Vec<Finding>,
    pub summary: ReportSummary,
}

impl ReportData {
    pub fn new(
        process: ProcessInfo,
        regions: Vec<MemoryRegion>,
        modules: Vec<ModuleInfo>,
        threads: Vec<ThreadInfo>,
        findings: Vec<Finding>,
    ) -> Self {
        let mut summary = ReportSummary {
            regions_total: regions.len(),
            module_count: modules.len(),
            thread_count: threads.len(),
            finding_count: findings.len(),
            ..Default::default()
        };
        for region in &regions {
            match region.classification {
                RegionClass::Image => summary.image += 1,
                RegionClass::Mapped => summary.mapped += 1,
                RegionClass::Private => summary.private += 1,
                RegionClass::Free => summary.free += 1,
                RegionClass::Reserved => summary.reserved += 1,
                RegionClass::Unknown => {}
            }
            if region.state == MemoryState::Commit {
                summary.committed += 1;
                if region.classification != RegionClass::Free {
                    summary.committed_bytes = summary.committed_bytes.saturating_add(region.size);
                }
            }
            if region.executable {
                summary.executable += 1;
            }
        }
        Self {
            generated_at: Utc::now(),
            xmem_version: VERSION.to_string(),
            schema_version: JSON_SCHEMA_VERSION,
            process,
            regions,
            modules,
            threads,
            findings,
            summary,
        }
    }
}

/// `.md` 확장자면 Markdown으로 저장한다.
pub fn is_markdown(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"))
}

pub fn to_json(report: &ReportData) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(report).map_err(|e| XmemError::JsonError {
        reason: e.to_string(),
    })
}

pub fn to_markdown(report: &ReportData) -> String {
    let mut out = String::new();
    out.push_str("# XMem Report\n\n");
    out.push_str(&format!(
        "- Generated: {}\n- XMem: {} (schema {})\n\n",
        report.generated_at.to_rfc3339(),
        report.xmem_version,
        report.schema_version
    ));

    out.push_str("## Process\n\n");
    out.push_str(&format!("- PID: {}\n", report.process.pid));
    out.push_str(&format!("- Name: {}\n", report.process.name));
    out.push_str(&format!(
        "- Image: {}\n",
        report.process.image_path.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!("- Arch: {:?}\n", report.process.arch));
    out.push_str(&format!(
        "- Session: {}\n",
        report
            .process
            .session_id
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    out.push_str(&format!(
        "- User: {}\n\n",
        report.process.user.as_deref().unwrap_or("-")
    ));

    out.push_str("## Memory Summary\n\n");
    out.push_str("| Metric | Value |\n|---|---|\n");
    out.push_str(&format!("| Regions | {} |\n", report.summary.regions_total));
    out.push_str(&format!("| Committed | {} |\n", report.summary.committed));
    out.push_str(&format!("| Reserved | {} |\n", report.summary.reserved));
    out.push_str(&format!("| Free | {} |\n", report.summary.free));
    out.push_str(&format!("| Image | {} |\n", report.summary.image));
    out.push_str(&format!("| Mapped | {} |\n", report.summary.mapped));
    out.push_str(&format!("| Private | {} |\n", report.summary.private));
    out.push_str(&format!("| Executable | {} |\n", report.summary.executable));
    out.push_str(&format!(
        "| Committed bytes | {} |\n",
        report.summary.committed_bytes
    ));
    out.push_str(&format!("| Modules | {} |\n", report.summary.module_count));
    out.push_str(&format!("| Threads | {} |\n\n", report.summary.thread_count));

    out.push_str(&format!("## Findings ({})\n\n", report.findings.len()));
    if report.findings.is_empty() {
        out.push_str("No findings. Absence of findings is not proof of safety.\n\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "### {} {} ({}/{})\n\n",
                finding.rule_id,
                finding.name,
                severity_text(finding.severity),
                confidence_text(finding.confidence)
            ));
            for evidence in &finding.evidence {
                out.push_str(&format!("- evidence({})", evidence.kind));
                if let Some(base) = evidence.region_base {
                    out.push_str(&format!(" region {base:#018x}"));
                }
                if let Some(address) = evidence.address {
                    out.push_str(&format!(" address {address:#018x}"));
                }
                out.push('\n');
                for (key, value) in &evidence.observed {
                    out.push_str(&format!("  - {key}: {value}\n"));
                }
            }
            out.push_str(&format!("- heuristic: {}\n", finding.heuristic));
            out.push_str(&format!("- interpretation: {}\n\n", finding.interpretation));
        }
    }

    out.push_str(&format!("## Regions ({})\n\n", report.regions.len()));
    out.push_str("| Base | Size | State | Type | Protection | Class | Mapped file |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for region in &report.regions {
        if region.classification == RegionClass::Free {
            continue;
        }
        out.push_str(&format!(
            "| {:#018x} | {:#x} | {:?} | {} | {} | {:?} | {} |\n",
            region.base,
            region.size,
            region.state,
            region
                .region_type
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "-".to_string()),
            region.protection,
            region.classification,
            region.mapped_file.as_deref().unwrap_or("-")
        ));
    }

    out.push_str(&format!("\n## Modules ({})\n\n", report.modules.len()));
    out.push_str("| Base | Size | Name | Path |\n|---|---|---|---|\n");
    for module in &report.modules {
        out.push_str(&format!(
            "| {:#018x} | {:#x} | {} | {} |\n",
            module.base,
            module.size,
            module.name,
            module.path.as_deref().unwrap_or("-")
        ));
    }

    out.push_str(&format!("\n## Threads ({})\n\n", report.threads.len()));
    out.push_str("| TID | Priority | Start | Module |\n|---|---|---|---|\n");
    for thread in &report.threads {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            thread.tid,
            thread
                .priority
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            thread
                .start_address
                .map(|a| format!("{a:#018x}"))
                .unwrap_or_else(|| "-".to_string()),
            thread.start_module.as_deref().unwrap_or("-")
        ));
    }

    out
}

/// temp 파일에 쓰고 rename한다(실패 시 temp 제거). 저장된 바이트 수를 반환한다.
pub fn write_report(report: &ReportData, path: &Path) -> Result<u64> {
    let bytes = if is_markdown(path) {
        to_markdown(report).into_bytes()
    } else {
        to_json(report)?
    };
    let temp: PathBuf = PathBuf::from(format!("{}.tmp-{}", path.display(), std::process::id()));
    if let Err(e) = std::fs::write(&temp, &bytes) {
        let _ = std::fs::remove_file(&temp);
        return Err(XmemError::Io(e));
    }
    if let Err(e) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(XmemError::Io(e));
    }
    Ok(bytes.len() as u64)
}

fn severity_text(severity: xmem_core::Severity) -> &'static str {
    match severity {
        xmem_core::Severity::Info => "info",
        xmem_core::Severity::Low => "low",
        xmem_core::Severity::Medium => "medium",
        xmem_core::Severity::High => "high",
        xmem_core::Severity::Critical => "critical",
    }
}

fn confidence_text(confidence: xmem_core::Confidence) -> &'static str {
    match confidence {
        xmem_core::Confidence::Low => "low",
        xmem_core::Confidence::Medium => "medium",
        xmem_core::Confidence::High => "high",
    }
}
```

`crates/xmem-forensics/src/lib.rs`: `pub mod report;`(format 다음) + 재수출 `pub use report::{ReportData, ReportSummary, is_markdown, to_json, to_markdown, write_report};`

주의: `MemoryRegion` 필드 리터럴은 xmem-core 실제 정의와 일치해야 한다(기존 다른 테스트 픽스처 참고). `region.protection`은 `Display`가 있으므로 `{}`로 출력.

- [ ] **Step 4: 테스트 통과 확인**

Run: `cargo test -p xmem-forensics`
Expected: PASS — 기존 24 + 신규 3 = 27

- [ ] **Step 5: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-forensics --all-targets -- -D warnings
git add crates/xmem-forensics
git commit -m "feat(forensics): 분석 리포트(JSON/Markdown) 생성"
```

---

### Task 2: CLI — report 명령

**Files:**
- Modify: `crates/xmem-cli/src/commands/report.rs` (스텀 → 구현)
- Test: report.rs 내 테스트 2

**Interfaces:**
- Consumes: `xmem_forensics::report::{ReportData, is_markdown, write_report}`, `xmem_detection::{DetectionContext, detect}`, `xmem_memory::LiveProcess`, `crate::commands::render::human_size`, `crate::output::{emit, emit_json, resolve_mode, success_envelope}`.
- Produces: `pub(crate) fn build_report(pid: u32) -> Result<ReportData>`.

- [ ] **Step 1: 실패하는 테스트 작성**

`crates/xmem-cli/src/commands/report.rs`:

```rust
use std::path::Path;

use serde_json::json;
use xmem_core::Result;
use xmem_detection::{DetectionContext, detect};
use xmem_forensics::report::{ReportData, is_markdown, write_report};
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::human_size;
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_report_of_self_is_populated() {
        let report = build_report(std::process::id()).unwrap();
        assert_eq!(report.process.pid, std::process::id());
        assert!(!report.regions.is_empty());
        assert!(!report.modules.is_empty());
        assert_eq!(report.summary.regions_total, report.regions.len());
    }

    #[test]
    fn report_writes_markdown_for_md_extension() {
        let dir = std::env::temp_dir().join(format!("xmem-cli-report-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.md");
        let report = build_report(std::process::id()).unwrap();

        let bytes = write_report(&report, &path).unwrap();
        assert!(bytes > 0);
        assert!(is_markdown(&path));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("# XMem Report"));
        assert!(text.contains("## Findings"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — `build_report` 미정의(E0425)

- [ ] **Step 3: 구현**

테스트 모듈 위에 추가:

```rust
pub fn run(pid: &PidArg, output: &str, global: &GlobalArgs) -> Result<()> {
    let report = build_report(pid.pid)?;
    let path = Path::new(output);
    let bytes = write_report(&report, path)?;
    let markdown = is_markdown(path);

    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(json!({
                "output": output,
                "format": if markdown { "markdown" } else { "json" },
                "file_bytes": bytes,
                "process": { "pid": report.process.pid, "name": report.process.name },
                "region_count": report.regions.len(),
                "module_count": report.modules.len(),
                "thread_count": report.threads.len(),
                "finding_count": report.findings.len(),
            })));
            Ok(())
        }
        OutputMode::Human => {
            emit(&format!(
                "report written: {} ({}, {})\n",
                output,
                if markdown { "markdown" } else { "json" },
                human_size(bytes)
            ));
            emit(&format!(
                "  process {} ({}) - regions {} / modules {} / threads {} / findings {}\n",
                report.process.name,
                report.process.pid,
                report.regions.len(),
                report.modules.len(),
                report.threads.len(),
                report.findings.len()
            ));
            Ok(())
        }
    }
}

/// 대상에서 수집(읽기 전용)해 리포트 데이터를 조립한다.
pub(crate) fn build_report(pid: u32) -> Result<ReportData> {
    let live = LiveProcess::open(pid)?;
    let regions = live.region_map()?.regions;
    let modules = live.modules()?;
    let threads = live.threads()?;
    let findings = detect(&DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    });
    Ok(ReportData::new(
        live.info.clone(),
        regions,
        modules,
        threads,
        findings,
    ))
}
```

- [ ] **Step 4: 테스트 통과 확인**

Run: `cargo test -p xmem-cli`
Expected: PASS — 기존 57 + 신규 2 = 59

- [ ] **Step 5: fmt/clippy/커밋**

```powershell
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add crates/xmem-cli
git commit -m "feat(cli): report 명령(JSON/Markdown)"
```

---

### Task 3: 문서 6종 (스펙 §42)

**Files:**
- Create: `docs/windows-memory.md`, `docs/vad.md`, `docs/pe.md`, `docs/detection.md`, `docs/experiments.md`, `docs/format.md`

각 문서는 40~80행. 검증된 구현 사실과 개념 설명만 담는다. 미구현 기능은 "계획/한계"로 표기한다.

- [ ] **Step 1: `docs/windows-memory.md`**

포함할 내용:
- Virtual Address Space 개념(예약/커밋, 4 KiB 페이지, allocation granularity 64 KiB(x64)).
- State: `MEM_COMMIT`/`MEM_RESERVE`/`MEM_FREE` 의미.
- Type: `MEM_IMAGE`/`MEM_MAPPED`/`MEM_PRIVATE` 의미.
- Protection: `PAGE_*` 8종 + `PAGE_GUARD(0x100)`/`PAGE_NOCACHE(0x200)` 비트, readable/writable/executable 해석 규칙(구현 `Protection::from_win32` 표).
- `VirtualQueryEx` 기반 열거(영역 경계·RegionSize·무한 루프 방지)와 한계(race, VAD와 1:1 아님).
- `GetMappedFileNameW` 디바이스 경로(`\Device\...`), pagefile 매핑은 조회 실패 가능.
- XMem 매핑: `xmem-windows::memory`(walk), `xmem-memory::LiveProcess::region_map`, `xmem memory map` 출력 필드.

- [ ] **Step 2: `docs/vad.md`**

- VAD 개념: 커널 `EPROCESS`의 VAD 트리(NT 내부 자료구조)가 프로세스 주소 공간 영역을 기술한다는 것(개념 설명).
- 사용자 모드에서 VAD를 직접 읽을 수 없음 → XMem은 `VirtualQueryEx`로 근사한다.
- VAD와 `VirtualQueryEx` 차이: 병합/분할 표현 차이, 보호 속성 표현, 예약 영역 세부.
- 이 근사가 Detector/Report에 미치는 영향(분류는 커밋된 영역 기준).
- 향후 연구 방향(ETW/커널 없음 — Non-Goals 준수).

- [ ] **Step 3: `docs/pe.md`**

- PE 구조 요약: DOS Header(`MZ`, `e_lfanew`), PE Signature(`PE\0\0`), COFF Header(machine/sections/characteristics), Optional Header(PE32/PE32+ magic, entry RVA, image base, size_of_image, subsystem), Section Table(이름/VA/크기/특성), Data Directories(imports/exports/relocations/TLS).
- 메모리에서의 PE: 로더가 매핑한 이미지 vs 디스크 레이아웃 차이(섹션 정렬).
- XMem 분류(`classify_memory_pe`): NormalLoadedModule/MappedImage/PrivatePeLike/Malformed/Unknown + 입력 조건.
- 구현: bounds-checked 헤더 파서(`PE_HEADER_PREFIX` 4 KiB) + 전체 파일일 때만 goblin 보강; imports/exports/relocations/TLS는 전체 파일에서만 채워짐.
- 탐지 연계: XMEM-002(4 KiB 프로브 기반, 한계 명시).

- [ ] **Step 4: `docs/detection.md`**

- Evidence 모델: Observed Fact → Evidence → Heuristic → Confidence → Interpretation, 악성 단정 금지.
- 규칙 표 XMEM-001~005: 조건/severity/confidence(구현 코드 기준).
- finding 정렬 키 `(rule_id, region_base, address)`.
- 오탐 요인: JIT/`.NET R2R`(XMEM-003), suspended thread(XMEM-004), 보호 속성만 보고 판단(XMEM-005).
- 0 findings ≠ 안전 문구.
- Snapshot/Report에서의 findings(diff detections, report findings).

- [ ] **Step 5: `docs/experiments.md`**

- 방법론: Baseline → Action → Post → Diff → Detection → Report.
- 안전 원칙: XMem이 spawn한 `xmem-target`만, 변경 API(`VirtualAllocEx`/`VirtualProtectEx`/`WriteProcessMemory`/`CreateRemoteThread`)는 `xmem-experiments` 경로에서만, guard/신원 검증, Drop cleanup.
- 4개 실험 표(remote-alloc/protection-flip/pe-staging/remote-thread: 시나리오/기대 규칙).
- 판정: expected_present(baseline)/expected_observed(post) + report Ground Truth 대조.
- 한계: suspended thread는 실제 실행되지 않음, 주소는 실행마다 다름(`--report` 참조), VM 권장.

- [ ] **Step 6: `docs/format.md`**

- Snapshot v1: 헤더 `magic "XMEM"(4) | u16 format_version | u16 flags | u32 payload_len` + JSON payload, `SNAPSHOT_FORMAT_VERSION=1`, payload의 `format_version` 교차 검증, temp→재파싱 검증→rename.
- payload 필드: schema_version/xmem_version/timestamp/process/regions/modules/threads/content_hashes(blake3, RegionHash)/findings/acquisition(AcquisitionMeta — 64 MiB 예산).
- Diff 매칭 키: region=base, module=name, thread=tid, finding=(rule_id, region_base, address), content=base.
- Minidump: `MDMP` 시그니처, MemoryInfoList/Memory/Module/Thread/MiscInfo 스트림 사용, `--full`은 MiniDumpWithFullMemory|FullMemoryInfo.
- Report(JSON/Markdown): envelope 없이 파일 자체가 ReportData(JSON), Markdown은 동일 데이터 렌더.
- 버전 관리 원칙: format_version/magic, 향후 migration.

- [ ] **Step 7: 검증 + 커밋**

문서 6종이 실제 코드와 일치하는지 육안 검증(규칙 ID, 포맷 바이트, 예산 64 MiB 등).

```powershell
git add docs/windows-memory.md docs/vad.md docs/pe.md docs/detection.md docs/experiments.md docs/format.md
git commit -m "docs: 메모리/VAD/PE/탐지/실험/포맷 문서 추가"
```

---

### Task 4: RSS 통계 + 최종 문서 + 게이트 + 스모크

**Files:**
- Modify: `crates/xmem-windows/src/process.rs` (`current_rss_bytes`)
- Modify: `crates/xmem-windows/src/lib.rs` (재수출)
- Modify: `crates/xmem-memory/src/scan.rs` (`ScanStats.rss_bytes`)
- Modify: `crates/xmem-cli/src/commands/memory.rs` (render_scan 통계 줄)
- Modify: `README.md`, `docs/architecture.md`, `docs/plans/milestone-12-completeness.md`

**Interfaces:**
- Consumes: `xmem-windows::memory_counters`(기존 구현), `open_for_query`, `current_pid`.
- Produces: `xmem_windows::current_rss_bytes() -> Result<u64>`; `ScanStats.rss_bytes: u64`.

- [ ] **Step 1: 테스트 작성 (xmem-windows)**

`crates/xmem-windows/src/process.rs` 테스트 모듈에 추가:

```rust
#[test]
fn current_rss_bytes_is_positive() {
    let rss = current_rss_bytes().unwrap();
    assert!(rss > 0);
}
```

- [ ] **Step 2: 실패 확인**

Run: `cargo check -p xmem-windows --tests`
Expected: FAIL — `current_rss_bytes` 미정의

- [ ] **Step 3: 구현 (xmem-windows)**

`memory_counters`의 실제 시그니처(기존 코드)를 확인하고 아래를 추가:

```rust
/// 현재 프로세스(XMem 자신)의 working set 바이트(스캔 자원 통계용).
pub fn current_rss_bytes() -> Result<u64> {
    let pid = current_pid();
    let handle = open_for_query(pid)?;
    let Some(stats) = memory_counters(&handle)? else {
        return Ok(0);
    };
    Ok(stats.working_set)
}
```

(기존 `memory_counters`가 다른 시그니처면 그에 맞춘다. 실제 반환형이 `Option<MemoryStats>`가 아니면 그에 맞게 `unwrap_or` 등으로 조정.)

`lib.rs` 재수출에 `current_rss_bytes` 추가.

- [ ] **Step 4: 스캔 통계에 연결 (xmem-memory)**

`crates/xmem-memory/src/scan.rs`:
- `ScanStats`에 `pub rss_bytes: u64,` 추가(Default로 0).
- `scan()`의 stats 생성 뒤: `stats.rss_bytes = xmem_windows::current_rss_bytes().unwrap_or(0);`

- [ ] **Step 5: CLI 통계 출력 (xmem-cli/memory.rs)**

`render_scan`의 통계 줄을 확인해 `rss` 항목 추가:
- 기존 사람용 통계 줄 끝에 `, rss {}`(human_size(report.stats.rss_bytes)) 추가.
- JSON은 `stats`가 직렬화되어 자동 포함됨(수동 필드 추가 없음).

- [ ] **Step 6: 테스트/게이트**

Run: `cargo test -p xmem-windows -p xmem-memory -p xmem-cli`
Expected: windows 62(61+1), memory 21, cli 59 — 전부 green

- [ ] **Step 7: README/architecture.md 갱신**

README:
- Status 문구 → "현재 **Milestone 12 (완성도)** 완료. ... `xmem report`(JSON/Markdown), 문서 6종, 스캔 RSS 통계까지 포함한다."
- Status 표: `report --pid <PID> --output <FILE>` 행 추가(JSON/Markdown, Process/Memory summary/Findings/Regions/Modules/Threads, findings 포함, `--json`).
- Limitations에서 "`report` 명령은 스텀(미구현)이며 M12에서 추가된다" 문구 삭제/갱신.
- Documentation 섹션 추가: docs/architecture.md + 6개 문서 링크 + docs/plans.
- Roadmap M12 → 완료.
- Limitations에 "RSS는 스캔 후 XMem 자신의 working set(peak 아님)" 1줄.

architecture.md:
- §5 forensics 책임의 Report → 구현 표기.
- §11/§14: 자원 모니터링 문구를 "peak RSS는 M12" → "`rss_bytes`: 스캔 후 XMem 자신의 working set(M12 구현; peak 샘플링은 후속)"으로 수정.
- §14 Status: M12 Done + "M13+ | 없음(계획 없음)".
- CLI 계약에 report 라인 이미 있음(유지).

- [ ] **Step 8: 전체 게이트**

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | Out-File -Encoding utf8 "$env:TEMP\opencode\xmem-m12-tests.log"
```

Expected: fmt/check/clippy=0; 테스트 **229** = cli 59 + core 34 + detection 8 + experiments 3 + forensics 27 + memory 21 + pe 9 + windows 62 + xmem-target 7.

- [ ] **Step 9: Windows 스모크**

```powershell
$dir = Join-Path $env:TEMP "xmem-m12"; Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$exe = ".\target\debug\xmem.exe"
cargo build -q -p xmem-cli

& $exe report --pid $PID --output "$dir\report.json"; Write-Output "exit=$LASTEXITCODE"
Get-Item "$dir\report.json" | Select-Object -ExpandProperty Length
(Get-Content "$dir\report.json" -Raw | ConvertFrom-Json).process.pid

& $exe report --pid $PID --output "$dir\report.md"; Write-Output "exit=$LASTEXITCODE"
Select-String -Path "$dir\report.md" -Pattern "## (Process|Findings|Regions|Modules|Threads)" | Select-Object -ExpandProperty Line

$lsass = (Get-Process lsass).Id
& $exe report --pid $lsass --output "$dir\nope.json"; Write-Output "exit=$LASTEXITCODE"
& $exe report --pid 4294967294 --output "$dir\nope.json"; Write-Output "exit=$LASTEXITCODE"
& $exe --json report --pid $PID --output "$dir\report.json"; Write-Output "exit=$LASTEXITCODE"

Get-ChildItem $dir | Select-Object -ExpandProperty Name
1..3 | ForEach-Object { & $exe report --pid $PID --output "$dir\report.json" > $null; Write-Output "repeat=$LASTEXITCODE" }
& $exe memory scan --pid $PID --string XMEM --max-results 1 | Select-String "rss" | Select-Object -First 1
Remove-Item -Recurse -Force $dir
```

기록: JSON/MD 크기, 섹션 존재, lsass/bogus PID exit 1, `.tmp-` 없음, 반복 3회 0, 스캔 통계의 rss 값.

- [ ] **Step 10: 체크박스 + 커밋**

계획서 체크박스 `- [ ]` → `- [x]` replaceAll.

```powershell
git add README.md docs/architecture.md docs/plans/milestone-12-completeness.md Cargo.lock
git commit -m "docs: M12 완성도 상태 반영"
```

---

## Self-Review Notes

- **스펙 커버리지**: §42 문서 6종(Task 3), §50 M12의 Report(§53 "JSON / Markdown Report" → Task 1·2), Resource Monitoring(Task 4), 나머지(JSON/문서/성능/UX)는 기존 마일스톤에서 충족.
- **정직성**: RSS는 "스캔 후 XMem 자신의 working set"으로 한정 표기(peak 아님). Markdown regions 표는 free 영역을 생략하고 총계는 요약에 남긴다.
- **타입 일관성**: `ReportData`/`write_report`/`is_markdown`/`build_report`/`current_rss_bytes`/`ScanStats.rss_bytes` 이름이 Task 간 동일.
- **미구현으로 남기는 것**: peak RSS 샘플링, MemoryImage 소스, report의 PDF/HTML 렌더, 커널/VAD 직접 열람 — 문서에 계획/한계로만 표기.
