# M8 — Detection Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rule 기반 Detection Engine(`xmem-detection`)을 만들고, `xmem detect --pid <PID>`를 구현하며, Snapshot의 `findings`를 채우고 Snapshot Diff가 Detection Appeared/Disappeared/Changed를 보고하도록 한다.

**Architecture:** `xmem-detection`은 수집된 관찰 데이터(regions/modules/threads)만 받는 순수 함수형 엔진이다(`DetectionContext`). 소스 read가 없으므로 LiveProcess와 Snapshot 모두에서 동작한다. XMEM-001~005는 `MemoryRegion.heuristics`(M3/M6에서 계산됨)와 module 범위·thread 상관관계만 사용한다. `xmem-forensics::collect`가 findings를 채우고, `diff`가 detections를 비교한다. CLI `detect`는 렌더링만 담당하며 rule은 CLI에 하드코딩하지 않는다.

**Tech Stack:** Rust stable (edition 2024), 기존 workspace crate, serde(기존 모델 재사용). 신규 dependency 없음.

**Spec:** `docs/architecture.md` §9 Detection Rules, §8 Snapshot `findings`, §7 Evidence 모델

## Global Constraints

- 신규 dependency 없음. `xmem-detection`은 `xmem-core`에만 의존한다.
- Rule은 `xmem-detection`에만 존재하고 CLI에 하드코딩하지 않는다.
- Detection은 **관찰 데이터만** 사용한다: 소스 read/Windows API 호출 금지(오프라인 Snapshot에서도 동작해야 함).
- Evidence는 관찰 사실만 담는다(protection/state/size/heuristic/tid 등). 해석은 `heuristic`/`interpretation` 필드에만. 악성 확정 표현("malware", "detected") 금지. `interpretation`은 "Potentially ..." 수준으로 제한.
- 0 findings는 안전의 증명이 아니다 — CLI 사람 출력에 그 취지를 명시한다.
- 불완전 데이터는 skip한다: `modules`가 비어 있으면 XMEM-003/004를 평가하지 않고, thread `start_address`가 None이면 XMEM-004에서 skip한다.
- `detect` 결과는 결정적으로 정렬한다(rule_id, region_base, address) — Snapshot diff 안정성을 위해.
- Severity/Confidence는 architecture §9 표를 그대로 따른다: 001 Medium/High, 002 High/Medium, 003 Medium/Medium, 004 High/Medium, 005 private·mapped→High, image→Low, 그 외 Medium / Confidence High.
- 기존 read-only 원칙 유지. `detect`는 프로세스를 변경하지 않는다.
- 모든 cargo 명령 전 `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"` 프리픽스. red 확인은 `cargo check -p <crate> --tests`.

## Review Focus

1. **오탐 정직성** — `interpretation`에 악성 단정이 없고, 0 findings 출력이 "안전"으로 읽히지 않아야 한다. Task 3의 `render_findings_reports_zero_case_not_proof`로 고정한다.
2. **불완전 데이터 skip** — modules 목록이 비어 있으면 XMEM-003/004가 침묵해야 한다(조회 실패를 finding으로 승격 금지). Task 1의 `xmem003_skips_when_modules_unknown`으로 고정한다.
3. **결정성** — 같은 입력은 같은 순서의 findings를 낸다. Task 1의 `detect_is_deterministic`으로 고정한다.
4. **severity 규칙 준수** — XMEM-005는 private→High, image→Low. Task 1의 `xmem005_severity_depends_on_classification`으로 고정한다.
5. **Snapshot 배선** — collect가 findings를 채우고 diff가 detections 변화를 보고한다. Task 2의 `collect_includes_findings`와 `detects_finding_appeared_and_disappeared`로 고정한다.

---

### Task 1: xmem-detection crate — Rule trait + XMEM-001~005

**Files:**
- Create: `crates/xmem-detection/Cargo.toml`
- Create: `crates/xmem-detection/src/lib.rs`
- Create: `crates/xmem-detection/src/rules.rs`
- Create: `crates/xmem-detection/src/source.rs`
- Modify: `Cargo.toml` (members, workspace.deps)

**Interfaces:**
- Consumes: `xmem_core::{Confidence, Evidence, Finding, Heuristic, MemoryRegion, MemorySource, MemoryState, ModuleInfo, RegionClass, Result, Severity, ThreadInfo}`.
- Produces:
  - `DetectionContext<'a> { regions: &'a [MemoryRegion], modules: &'a [ModuleInfo], threads: &'a [ThreadInfo] }`
  - `trait Rule { fn id(&self) -> &'static str; fn name(&self) -> &'static str; fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding>; }`
  - `default_rules() -> Vec<Box<dyn Rule>>`, `detect(&DetectionContext<'_>) -> Vec<Finding>`
  - `detect_source<S: MemorySource>(source: &S) -> Result<Vec<Finding>>`

- [ ] **Step 1: Write the failing tests**

`crates/xmem-detection/src/rules.rs` 생성(테스트 모듈만):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        Heuristic, MemoryRegion, MemoryState, MemoryType, ModuleInfo, Protection, RegionClass,
        ThreadInfo,
    };

    fn region(
        base: u64,
        heuristics: Vec<Heuristic>,
        classification: RegionClass,
        protection_raw: u32,
    ) -> MemoryRegion {
        MemoryRegion {
            base,
            size: 0x1000,
            state: MemoryState::Commit,
            protection: Protection::new(protection_raw, true, true, protection_raw & 0x10 != 0),
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: true,
            writable: protection_raw & 0x04 != 0 || protection_raw == 0x40,
            executable: protection_raw & 0x10 != 0 || protection_raw == 0x40,
            classification,
            heuristics,
            mapped_file: None,
        }
    }

    fn module(name: &str, base: u64, size: u64) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base,
            size,
            path: None,
            arch: None,
        }
    }

    fn thread(tid: u32, start: Option<u64>, region_base: Option<u64>, module: Option<&str>) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1,
            priority: None,
            start_address: start,
            start_region_base: region_base,
            start_module: module.map(str::to_string),
        }
    }

    fn evaluate(rule: &dyn Rule, regions: &[MemoryRegion], modules: &[ModuleInfo], threads: &[ThreadInfo]) -> Vec<Finding> {
        rule.evaluate(&DetectionContext { regions, modules, threads })
    }

    #[test]
    fn xmem001_fires_on_private_executable_heuristic() {
        let regions = vec![
            region(0x1000, vec![Heuristic::ExecutablePrivate], RegionClass::Private, 0x40),
            region(0x5000, Vec::new(), RegionClass::Private, 0x04),
        ];
        let findings = evaluate(&ExecutablePrivateMemory, &regions, &[], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "XMEM-001");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].evidence[0].region_base, Some(0x1000));
        assert!(findings[0].evidence[0].observed.contains_key("protection"));
        assert!(!findings[0].interpretation.to_lowercase().contains("malware"));
    }

    #[test]
    fn xmem002_fires_on_pe_like_heuristic() {
        let regions = vec![region(
            0x2000,
            vec![Heuristic::ExecutablePrivate, Heuristic::PrivateExecutablePeLike],
            RegionClass::Private,
            0x40,
        )];
        let findings = evaluate(&PeInPrivateExecutableRegion, &regions, &[], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "XMEM-002");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert!(findings[0].evidence[0]
            .observed
            .values()
            .any(|value| value.contains("private_executable_pe_like")));
    }

    #[test]
    fn xmem003_fires_outside_modules_and_skips_when_modules_unknown() {
        let regions = vec![
            region(0x1000, Vec::new(), RegionClass::Private, 0x20),
            region(0x8000_0000, Vec::new(), RegionClass::Private, 0x20),
        ];
        let modules = vec![module("mod.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].region_base, Some(0x8000_0000));
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        let skipped = evaluate(&ExecutableWithoutBackingModule, &regions, &[], &[]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn xmem004_fires_for_unbacked_start_and_skips_missing_address() {
        let regions = vec![region(
            0x3000,
            vec![Heuristic::ExecutablePrivate],
            RegionClass::Private,
            0x40,
        )];
        let threads = vec![
            thread(10, Some(0x3000), Some(0x3000), None),
            thread(11, Some(0x9000), None, None),
            thread(12, Some(0x1000), Some(0x1000), Some("mod.dll")),
            thread(13, None, None, None),
        ];
        let findings = evaluate(&SuspiciousThreadStartAddress, &regions, &[], &threads);
        let tids: Vec<&String> = findings
            .iter()
            .map(|finding| finding.evidence[0].observed.get("tid").unwrap())
            .collect();
        assert_eq!(findings.len(), 2);
        assert_eq!(tids, vec!["10", "11"]);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn xmem005_severity_depends_on_classification() {
        let regions = vec![
            region(0x1000, Vec::new(), RegionClass::Private, 0x40),
            region(0x2000, Vec::new(), RegionClass::Image, 0x40),
            region(0x3000, Vec::new(), RegionClass::Mapped, 0x80),
            region(0x4000, Vec::new(), RegionClass::Private, 0x04),
        ];
        let findings = evaluate(&ProtectionAnomaly, &regions, &[], &[]);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Low);
        assert_eq!(findings[2].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn default_rules_have_unique_ids() {
        let ids: Vec<&str> = default_rules().iter().map(|rule| rule.id()).collect();
        assert_eq!(ids, vec!["XMEM-001", "XMEM-002", "XMEM-003", "XMEM-004", "XMEM-005"]);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn detect_is_deterministic_and_sorted() {
        let regions = vec![
            region(0x8000, vec![Heuristic::ExecutablePrivate], RegionClass::Private, 0x40),
            region(0x1000, vec![Heuristic::ExecutablePrivate], RegionClass::Private, 0x40),
        ];
        let first = detect(&DetectionContext { regions: &regions, modules: &[], threads: &[] });
        let second = detect(&DetectionContext { regions: &regions, modules: &[], threads: &[] });
        assert_eq!(first, second);
        let keys: Vec<&str> = first.iter().map(|finding| finding.rule_id.as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted);
        let bases: Vec<Option<u64>> = first
            .iter()
            .filter(|finding| finding.rule_id == "XMEM-001")
            .map(|finding| finding.evidence[0].region_base)
            .collect();
        assert_eq!(bases, vec![Some(0x1000), Some(0x8000)]);
    }
}
```

`crates/xmem-detection/src/source.rs` 생성(테스트만):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{
        Heuristic, MemoryRegion, MemorySource, MemoryState, MemoryType, ModuleInfo, ProcessArch,
        ProcessInfo, Protection, ReadOutcome, RegionClass, Result, ThreadInfo, XmemError,
    };

    struct MockSource {
        info: ProcessInfo,
        regions: Vec<MemoryRegion>,
    }

    impl MemorySource for MockSource {
        fn process(&self) -> &ProcessInfo {
            &self.info
        }
        fn regions(&self) -> Result<Vec<MemoryRegion>> {
            Ok(self.regions.clone())
        }
        fn read(&self, address: u64, _buf: &mut [u8]) -> Result<ReadOutcome> {
            Err(XmemError::InvalidAddress { address })
        }
        fn modules(&self) -> Result<Vec<ModuleInfo>> {
            Ok(Vec::new())
        }
        fn threads(&self) -> Result<Vec<ThreadInfo>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn detect_source_reads_metadata_and_skips_unknown_modules() {
        let source = MockSource {
            info: ProcessInfo {
                pid: 77,
                ppid: None,
                name: "mock.exe".to_string(),
                image_path: None,
                arch: ProcessArch::X64,
                session_id: None,
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: None,
                module_count: None,
            },
            regions: vec![MemoryRegion {
                base: 0x1000,
                size: 0x1000,
                state: MemoryState::Commit,
                protection: Protection::new(0x40, true, true, true),
                allocation_protection: None,
                region_type: Some(MemoryType::Private),
                readable: true,
                writable: true,
                executable: true,
                classification: RegionClass::Private,
                heuristics: vec![Heuristic::ExecutablePrivate],
                mapped_file: None,
            }],
        };
        let findings = detect_source(&source).unwrap();
        assert!(findings.iter().any(|finding| finding.rule_id == "XMEM-001"));
        assert!(!findings.iter().any(|finding| finding.rule_id == "XMEM-003"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-detection --tests`
Expected: FAIL — crate 미등록 매니페스트 오류, 등록 후 E0425/E0422/E0433 다수.

- [ ] **Step 3: Write minimal implementation**

루트 `Cargo.toml`: members에 `"crates/xmem-detection"` 추가, workspace.deps에 `xmem-detection = { path = "crates/xmem-detection" }` 추가.

`crates/xmem-detection/Cargo.toml`:

```toml
[package]
name = "xmem-detection"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true

[lints]
workspace = true

[dependencies]
xmem-core.workspace = true
```

`crates/xmem-detection/src/lib.rs`:

```rust
//! Rule 기반 Detection Engine. 관찰 데이터만 사용하므로 Live/Snapshot 모두에서 동작한다. (M8)
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod rules;
pub mod source;

pub use rules::{DetectionContext, Rule, default_rules, detect};
pub use source::detect_source;
```

`crates/xmem-detection/src/rules.rs` 구현(테스트 모듈 위):

```rust
use xmem_core::{
    Confidence, Evidence, Finding, Heuristic, MemoryRegion, ModuleInfo, MemoryState, RegionClass,
    Severity, ThreadInfo,
};

/// Detection 컨텍스트: 수집된 관찰 데이터만 사용한다(소스 접근 없음).
pub struct DetectionContext<'a> {
    pub regions: &'a [MemoryRegion],
    pub modules: &'a [ModuleInfo],
    pub threads: &'a [ThreadInfo],
}

pub trait Rule {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding>;
}

pub fn default_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ExecutablePrivateMemory),
        Box::new(PeInPrivateExecutableRegion),
        Box::new(ExecutableWithoutBackingModule),
        Box::new(SuspiciousThreadStartAddress),
        Box::new(ProtectionAnomaly),
    ]
}

/// 모든 rule을 실행하고 (rule_id, region_base, address)로 결정적으로 정렬한다.
pub fn detect(context: &DetectionContext<'_>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = default_rules()
        .iter()
        .flat_map(|rule| rule.evaluate(context))
        .collect();
    findings.sort_by(|left, right| {
        finding_key(left).cmp(&finding_key(right))
    });
    findings
}

fn finding_key(finding: &Finding) -> (String, u64, u64) {
    let evidence = finding.evidence.first();
    (
        finding.rule_id.clone(),
        evidence.and_then(|item| item.region_base).unwrap_or(u64::MAX),
        evidence.and_then(|item| item.address).unwrap_or(u64::MAX),
    )
}

fn region_evidence(region: &MemoryRegion) -> Evidence {
    Evidence::new("region")
        .with_region_base(region.base)
        .observe("size", format!("{:#x}", region.size))
        .observe("state", region.state.to_string())
        .observe("protection", region.protection.to_string())
}

fn overlaps(module: &ModuleInfo, region: &MemoryRegion) -> bool {
    let module_end = module.base.saturating_add(module.size);
    let region_end = region.base.saturating_add(region.size);
    module.base < region_end && region.base < module_end
}

/// XMEM-001: committed + MEM_PRIVATE + executable.
pub struct ExecutablePrivateMemory;

impl Rule for ExecutablePrivateMemory {
    fn id(&self) -> &'static str {
        "XMEM-001"
    }

    fn name(&self) -> &'static str {
        "Executable Private Memory"
    }

    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding> {
        context
            .regions
            .iter()
            .filter(|region| region.heuristics.contains(&Heuristic::ExecutablePrivate))
            .map(|region| Finding {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                evidence: vec![region_evidence(region)],
                heuristic: "private memory with executable protection".to_string(),
                interpretation: "Potentially suspicious memory region".to_string(),
            })
            .collect()
    }
}

/// XMEM-002: private executable 영역에서 PE-like 헤더가 관찰됨(M6 probe heuristic).
pub struct PeInPrivateExecutableRegion;

impl Rule for PeInPrivateExecutableRegion {
    fn id(&self) -> &'static str {
        "XMEM-002"
    }

    fn name(&self) -> &'static str {
        "PE Header in Private Executable Region"
    }

    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding> {
        context
            .regions
            .iter()
            .filter(|region| region.heuristics.contains(&Heuristic::PrivateExecutablePeLike))
            .map(|region| Finding {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                evidence: vec![region_evidence(region).observe(
                    "heuristic",
                    Heuristic::PrivateExecutablePeLike.to_string(),
                )],
                heuristic: "PE-like header bytes in private executable region".to_string(),
                interpretation: "Possibly an injected PE image; JIT engines and packed software can produce the same pattern".to_string(),
            })
            .collect()
    }
}

/// XMEM-003: executable 영역이 어떤 로드된 모듈 범위에도 속하지 않음.
pub struct ExecutableWithoutBackingModule;

impl Rule for ExecutableWithoutBackingModule {
    fn id(&self) -> &'static str {
        "XMEM-003"
    }

    fn name(&self) -> &'static str {
        "Executable Memory Without Backing Module"
    }

    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding> {
        if context.modules.is_empty() {
            return Vec::new();
        }
        context
            .regions
            .iter()
            .filter(|region| region.state == MemoryState::Commit && region.executable)
            .filter(|region| !context.modules.iter().any(|module| overlaps(module, region)))
            .map(|region| Finding {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                evidence: vec![region_evidence(region)
                    .observe("classification", region.classification.to_string())
                    .observe("module_overlap", "none")],
                heuristic: "executable region outside any loaded module range".to_string(),
                interpretation: "Potentially unbacked executable memory; JIT engines and mapped images can also appear outside module ranges".to_string(),
            })
            .collect()
    }
}

/// XMEM-004: thread start address가 private executable 영역이거나 모듈 밖.
pub struct SuspiciousThreadStartAddress;

impl Rule for SuspiciousThreadStartAddress {
    fn id(&self) -> &'static str {
        "XMEM-004"
    }

    fn name(&self) -> &'static str {
        "Suspicious Thread Start Address"
    }

    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding> {
        context
            .threads
            .iter()
            .filter(|thread| thread.start_address.is_some())
            .filter(|thread| thread.start_module.is_none())
            .filter(|thread| match thread.start_region_base {
                Some(base) => context.regions.iter().any(|region| {
                    region.base == base
                        && region.classification == RegionClass::Private
                        && region.executable
                }),
                None => true,
            })
            .map(|thread| Finding {
                rule_id: self.id().to_string(),
                name: self.name().to_string(),
                severity: Severity::High,
                confidence: Confidence::Medium,
                evidence: vec![Evidence::new("thread")
                    .with_address(thread.start_address.unwrap_or(0))
                    .observe("tid", thread.tid.to_string())
                    .observe(
                        "start_address",
                        thread
                            .start_address
                            .map_or_else(|| "-".to_string(), |value| format!("{value:#x}")),
                    )
                    .observe(
                        "start_region",
                        thread
                            .start_region_base
                            .map_or_else(|| "none".to_string(), |value| format!("{value:#x}")),
                    )
                    .observe("start_module", "none")],
                heuristic: "thread start address outside loaded modules".to_string(),
                interpretation: "Potentially suspicious thread origin; JIT, hooks, and unloaded modules can also produce this".to_string(),
            })
            .collect()
    }
}

/// XMEM-005: RWX / EXECUTE_WRITECOPY 보호 속성.
pub struct ProtectionAnomaly;

impl Rule for ProtectionAnomaly {
    fn id(&self) -> &'static str {
        "XMEM-005"
    }

    fn name(&self) -> &'static str {
        "Memory Protection Anomaly"
    }

    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding> {
        context
            .regions
            .iter()
            .filter(|region| matches!(region.protection.raw & 0xff, 0x40 | 0x80))
            .map(|region| {
                let severity = match region.classification {
                    RegionClass::Private | RegionClass::Mapped => Severity::High,
                    RegionClass::Image => Severity::Low,
                    _ => Severity::Medium,
                };
                Finding {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity,
                    confidence: Confidence::High,
                    evidence: vec![region_evidence(region)
                        .observe("classification", region.classification.to_string())],
                    heuristic: "writable and executable protection".to_string(),
                    interpretation: "Potentially suspicious protection; JIT engines and some system components also use RWX".to_string(),
                }
            })
            .collect()
    }
}
```

주의: `thread.start_address.unwrap_or(0)`은 위에서 `is_some()` 필터를 통과한 뒤라 안전하지만, `let Some(address) = thread.start_address else { ... }` 패턴이 더 명확하면 그렇게 바꿔도 된다(클리피 통과 조건).

`crates/xmem-detection/src/source.rs` 구현(테스트 모듈 위):

```rust
use xmem_core::{Finding, MemorySource, Result};

use crate::rules::{DetectionContext, detect};

/// MemorySource에서 관찰 데이터를 모아 detection을 실행한다.
pub fn detect_source<S: MemorySource>(source: &S) -> Result<Vec<Finding>> {
    let regions = source.regions()?;
    let modules = source.modules()?;
    let threads = source.threads()?;
    Ok(detect(&DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    }))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-detection`
Expected: PASS — 8 (rules 7 + source 1).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-detection --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-detection
git commit -m "feat(detection): Rule 엔진과 XMEM-001~005"
```

---

### Task 2: xmem-forensics — findings 채우기 + diff detections

**Files:**
- Modify: `crates/xmem-forensics/Cargo.toml`
- Modify: `crates/xmem-forensics/src/collect.rs`
- Modify: `crates/xmem-forensics/src/diff.rs`
- Modify: `crates/xmem-forensics/src/lib.rs`

**Interfaces:**
- Consumes: `xmem_detection::{DetectionContext, detect}`, 기존 `Finding`.
- Produces:
  - `collect`이 `envelope.findings`를 채운다(수집된 regions/modules/threads에 대해 detect 실행).
  - `SnapshotDiff`에 `detections_added: Vec<Finding>`, `detections_removed: Vec<Finding>`, `detections_changed: Vec<FindingChange>` 추가; `DiffSummary`에 `detections_added/removed/changed: usize` 추가.
  - `FindingChange { before: Finding, after: Finding, changes: Vec<String> }` (changes: "severity: medium -> high", "confidence: ...", "name: ...").

- [ ] **Step 1: Write the failing tests**

`crates/xmem-forensics/src/collect.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn collect_includes_findings_from_heuristics() {
        use xmem_core::Heuristic;
        let mut source = mock_source();
        source.regions[0].heuristics = vec![Heuristic::ExecutablePrivate];
        let envelope = collect(&source, &CollectOptions::default(), &no_cancel()).unwrap();
        assert!(envelope.findings.iter().any(|finding| finding.rule_id == "XMEM-001"));
    }
```

`crates/xmem-forensics/src/diff.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn detects_finding_appeared_and_disappeared() {
        use xmem_core::{Confidence, Evidence, Finding, Severity};
        let before = sample_envelope(1, 0x1000, 0x40);
        let mut after = sample_envelope(1, 0x1000, 0x40);
        after.findings.push(Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "private memory with executable protection".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        });
        let appeared = diff(&before, &after);
        assert_eq!(appeared.detections_added.len(), 1);
        assert_eq!(appeared.summary.detections_added, 1);
        let disappeared = diff(&after, &before);
        assert_eq!(disappeared.detections_removed.len(), 1);
        assert_eq!(disappeared.summary.detections_removed, 1);
    }

    #[test]
    fn detects_finding_severity_change() {
        use xmem_core::{Confidence, Evidence, Finding, Severity};
        let finding = |severity: Severity| Finding {
            rule_id: "XMEM-005".to_string(),
            name: "Memory Protection Anomaly".to_string(),
            severity,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "writable and executable protection".to_string(),
            interpretation: "Potentially suspicious protection".to_string(),
        };
        let mut before = sample_envelope(1, 0x1000, 0x40);
        before.findings.push(finding(Severity::Low));
        let mut after = sample_envelope(1, 0x1000, 0x40);
        after.findings.push(finding(Severity::High));
        let result = diff(&before, &after);
        assert_eq!(result.detections_changed.len(), 1);
        assert_eq!(result.summary.detections_changed, 1);
        assert!(result.detections_changed[0]
            .changes
            .iter()
            .any(|change| change.starts_with("severity:")));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-forensics --tests`
Expected: FAIL — E0609 `no field detections_added`, E0433 `xmem_detection`, E0425 등.

- [ ] **Step 3: Write minimal implementation**

루트 `Cargo.toml` workspace.deps에 `xmem-detection = { path = "crates/xmem-detection" }`(Task 1에서 추가됨) 확인.

`crates/xmem-forensics/Cargo.toml` deps에 추가:

```toml
xmem-detection.workspace = true
```

`crates/xmem-forensics/src/collect.rs`: import에 `use xmem_detection::{DetectionContext, detect};` 추가, envelope 리터럴의 `findings: Vec::new(),`를 다음으로 교체:

```rust
        findings: detect(&DetectionContext {
            regions: &regions,
            modules: &modules,
            threads: &threads,
        }),
```

주의: `regions`/`modules`/`threads`는 envelope로 move되기 전에 borrow해야 한다 — envelope 리터럴보다 **앞**에서 findings를 계산해 변수로 두고 리터럴에서 사용한다:

```rust
    let findings = detect(&DetectionContext {
        regions: &regions,
        modules: &modules,
        threads: &threads,
    });
    Ok(SnapshotEnvelope {
        ...
        findings,
        ...
    })
```

`crates/xmem-forensics/src/diff.rs`:
- import에 `use xmem_core::Finding;` 추가(기존 `use xmem_core::{MemoryRegion, ModuleInfo, ProcessArch, ThreadInfo};`에 Finding 추가).
- 새 타입:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct FindingChange {
    pub before: Finding,
    pub after: Finding,
    pub changes: Vec<String>,
}
```

- `DiffSummary`에 필드 추가: `pub detections_added: usize, pub detections_removed: usize, pub detections_changed: usize`.
- `SnapshotDiff`에 필드 추가: `pub detections_added: Vec<Finding>, pub detections_removed: Vec<Finding>, pub detections_changed: Vec<FindingChange>`.
- 헬퍼 + 매칭 로직(threads 블록 뒤, summary 계산 앞):

```rust
fn finding_key(finding: &Finding) -> (String, u64, u64) {
    let evidence = finding.evidence.first();
    (
        finding.rule_id.clone(),
        evidence.and_then(|item| item.region_base).unwrap_or(u64::MAX),
        evidence.and_then(|item| item.address).unwrap_or(u64::MAX),
    )
}

fn finding_changes(before: &Finding, after: &Finding) -> Vec<String> {
    let mut changes = Vec::new();
    if before.severity != after.severity {
        changes.push(format!(
            "severity: {} -> {}",
            severity_text(before.severity),
            severity_text(after.severity)
        ));
    }
    if before.confidence != after.confidence {
        changes.push(format!(
            "confidence: {} -> {}",
            confidence_text(before.confidence),
            confidence_text(after.confidence)
        ));
    }
    if before.name != after.name {
        changes.push(format!("name: {} -> {}", before.name, after.name));
    }
    changes
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

매칭(region/module/thread 블록과 같은 패턴):

```rust
    let before_findings: BTreeMap<(String, u64, u64), &Finding> =
        before.findings.iter().map(|finding| (finding_key(finding), finding)).collect();
    let after_findings: BTreeMap<(String, u64, u64), &Finding> =
        after.findings.iter().map(|finding| (finding_key(finding), finding)).collect();
    let mut detections_added = Vec::new();
    let mut detections_changed = Vec::new();
    for (key, finding) in &after_findings {
        match before_findings.get(key) {
            None => detections_added.push((*finding).clone()),
            Some(old) => {
                let changes = finding_changes(old, finding);
                if !changes.is_empty() {
                    detections_changed.push(FindingChange {
                        before: (*old).clone(),
                        after: (*finding).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut detections_removed = Vec::new();
    for (key, finding) in &before_findings {
        if !after_findings.contains_key(key) {
            detections_removed.push((*finding).clone());
        }
    }
```

summary/DiffSummary 리터럴에 3개 카운트 추가, SnapshotDiff 리터럴에 3개 필드 추가.

`crates/xmem-forensics/src/lib.rs` 재수출에 `FindingChange` 추가:

```rust
pub use diff::{
    ContentChange, DiffSummary, FindingChange, ModuleChange, RegionChange, SnapshotDiff,
    SnapshotRef, ThreadChange, diff,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-forensics`
Expected: PASS — 20 (기존 17 + collect 1 + diff 2).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-forensics --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-forensics
git commit -m "feat(forensics): Snapshot findings와 detection diff"
```

---

### Task 3: CLI — detect 명령 + snapshot diff 렌더 확장

**Files:**
- Modify: `crates/xmem-cli/Cargo.toml`
- Rewrite: `crates/xmem-cli/src/commands/detect.rs`
- Modify: `crates/xmem-cli/src/commands/snapshot.rs` (render_diff에 detections 추가)

**Interfaces:**
- Consumes: `xmem_detection::{detect_source}`, `xmem_memory::LiveProcess`, 기존 output/render 헬퍼.
- Produces:
  - `xmem detect --pid <PID>` (Human: findings 블록 + 요약 / `--json`: `{"process": {...}, "finding_count": n, "findings": [...]}`)
  - `render_findings(&ProcessInfo, &[Finding]) -> String`
  - `detect_json_payload(&ProcessInfo, &[Finding]) -> Value`
  - `render_diff`가 `+ detection`/`- detection`/`~ detection` 라인과 요약에 detections 카운트를 포함.

- [ ] **Step 1: Write the failing tests**

`crates/xmem-cli/src/commands/detect.rs`에 테스트 모듈 추가(구현은 Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, Finding, ProcessArch, ProcessInfo, Severity};

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 321,
            ppid: None,
            name: "sample.exe".to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![Evidence::new("region")
                .with_region_base(0x1000)
                .observe("protection", "RWX (0x40)")
                .observe("state", "MEM_COMMIT")],
            heuristic: "private memory with executable protection".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        }
    }

    #[test]
    fn render_findings_lists_rules_evidence_and_summary() {
        let text = render_findings(&sample_info(), &[sample_finding()]);
        assert!(text.contains("XMEM-001"));
        assert!(text.contains("medium"));
        assert!(text.contains("high"));
        assert!(text.contains("protection"));
        assert!(text.contains("Potentially suspicious"));
        assert!(text.contains("1 findings"));
    }

    #[test]
    fn render_findings_reports_zero_case_not_proof() {
        let text = render_findings(&sample_info(), &[]);
        assert!(text.contains("0 findings"));
        assert!(text.contains("not proof"));
    }

    #[test]
    fn detect_json_payload_shape() {
        let payload = detect_json_payload(&sample_info(), &[sample_finding()]);
        assert_eq!(payload["process"]["pid"], 321);
        assert_eq!(payload["finding_count"], 1);
        assert!(payload["findings"].is_array());
        assert_eq!(payload["findings"][0]["rule_id"], "XMEM-001");
    }

    #[test]
    fn detect_self_returns_findings_without_panic() {
        let live = xmem_memory::LiveProcess::open(xmem_windows::current_pid()).unwrap();
        let findings = xmem_detection::detect_source(&live).unwrap();
        let text = render_findings(&live.info, &findings);
        assert!(text.contains("findings"));
    }
}
```

`crates/xmem-cli/src/commands/snapshot.rs` 테스트 모듈에 추가:

```rust
    #[test]
    fn render_diff_includes_detection_lines() {
        let before = sample_envelope_for_diff(0x1000, 0x40, 100);
        let mut after = sample_envelope_for_diff(0x1000, 0x40, 100);
        after.findings.push(xmem_core::Finding {
            rule_id: "XMEM-001".to_string(),
            name: "Executable Private Memory".to_string(),
            severity: xmem_core::Severity::Medium,
            confidence: xmem_core::Confidence::High,
            evidence: vec![xmem_core::Evidence::new("region").with_region_base(0x1000)],
            heuristic: "private memory with executable protection".to_string(),
            interpretation: "Potentially suspicious memory region".to_string(),
        });
        let result = xmem_forensics::diff(&before, &after);
        let text = render_diff(&result);
        assert!(text.contains("+ detection XMEM-001"));
        assert!(text.contains("detections:"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo check -p xmem-cli --tests`
Expected: FAIL — E0425 `render_findings`/`detect_json_payload`, E0609 `findings` 관련 등.

- [ ] **Step 3: Write minimal implementation**

`crates/xmem-cli/Cargo.toml` deps에 추가:

```toml
xmem-detection.workspace = true
```

`crates/xmem-cli/src/commands/detect.rs` 전면 교체:

```rust
use serde_json::{Value, json};
use xmem_core::{Finding, ProcessInfo, Result};
use xmem_detection::detect_source;
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::{heur_short, opt_hex};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(args: &PidArg, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid)?;
    let findings = detect_source(&live)?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            emit_json(&success_envelope(detect_json_payload(&live.info, &findings)));
            Ok(())
        }
        OutputMode::Human => {
            print!("{}", render_findings(&live.info, &findings));
            Ok(())
        }
    }
}

pub(crate) fn render_findings(info: &ProcessInfo, findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}) - {} findings\n",
        info.name,
        info.pid,
        findings.len()
    ));
    if findings.is_empty() {
        out.push_str("no findings (absence of findings is not proof of safety)\n");
        return out;
    }
    for finding in findings {
        out.push_str(&format!(
            "\n{} {} [{}/{}]\n",
            finding.rule_id,
            finding.name,
            severity_text(finding.severity),
            confidence_text(finding.confidence),
        ));
        for evidence in &finding.evidence {
            let location = match (evidence.region_base, evidence.address) {
                (Some(base), _) => format!("region {}", opt_hex(Some(base))),
                (None, Some(address)) => format!("address {}", opt_hex(Some(address))),
                (None, None) => "evidence".to_string(),
            };
            out.push_str(&format!("  {} ({})\n", location, evidence.kind));
            for (key, value) in &evidence.observed {
                out.push_str(&format!("    {key}: {value}\n"));
            }
        }
        out.push_str(&format!("  heuristic: {}\n", finding.heuristic));
        out.push_str(&format!("  interpretation: {}\n", finding.interpretation));
    }
    out
}

pub(crate) fn detect_json_payload(info: &ProcessInfo, findings: &[Finding]) -> Value {
    json!({
        "process": { "pid": info.pid, "name": info.name },
        "finding_count": findings.len(),
        "findings": findings,
    })
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

주의: `heur_short` import가 실제로 안 쓰이면 제거한다(계획 시점의 잔재 — 클리피 -D warnings가 잡아준다).

`crates/xmem-cli/src/commands/snapshot.rs`의 `render_diff`:
- 요약행을 다음으로 교체(마지막에 detections 추가):

```rust
    out.push_str(&format!(
        "regions: +{} -{} ~{} | content ~{} | modules: +{} -{} ~{} | threads: +{} -{} ~{} | detections: +{} -{} ~{}\n",
        summary.regions_added, summary.regions_removed, summary.regions_changed,
        summary.content_changed,
        summary.modules_added, summary.modules_removed, summary.modules_changed,
        summary.threads_added, summary.threads_removed, summary.threads_changed,
        summary.detections_added, summary.detections_removed, summary.detections_changed,
    ));
```

- thread 라인 뒤에 detections 라인 추가:

```rust
    for finding in &diff.detections_added {
        out.push_str(&format!("+ detection {} {}\n", finding.rule_id, finding.name));
    }
    for finding in &diff.detections_removed {
        out.push_str(&format!("- detection {} {}\n", finding.rule_id, finding.name));
    }
    for change in &diff.detections_changed {
        out.push_str(&format!(
            "~ detection {} {}\n",
            change.after.rule_id,
            change.changes.join(", ")
        ));
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p xmem-cli`
Expected: PASS — 45 + 5 = 50.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
cargo clippy -q -p xmem-cli --all-targets -- -D warnings
git add Cargo.toml Cargo.lock crates/xmem-cli
git commit -m "feat(cli): detect 명령과 detection diff 렌더"
```

---

### Task 4: 문서, 전체 게이트, Windows 실검증

**Files:**
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/plans/milestone-08-detection.md` (체크박스)

**Interfaces:**
- Consumes: Task 1~3 결과.
- Produces: 문서 상태 갱신 + 검증 기록. 코드 변경 없음.

- [ ] **Step 1: README 갱신**

- Status 문구 "Milestone 8 (Detection Engine) 완료".
- Status 표: `detect --pid` 행 Implemented(Rule 기반, Evidence 분리, `--json`); `snapshot create` 행에 "findings 포함" 추가; `snapshot diff` 행에 "detections 변화" 추가.
- Quick Start에 `xmem detect --pid <PID>` 1줄.
- CLI Usage에 detect 설명: rule은 xmem-detection에만 존재, findings는 증명이 아님, 0 findings 문구.
- Limitations: XMEM-002는 4 KiB 헤더 probe heuristic 기반(imports/exports 미검증), JIT/정상 소프트웨어 오탐 가능, modules 조회 실패 시 003/004 skip.
- Roadmap M8 완료.

- [ ] **Step 2: architecture.md 갱신**

- §9 제목 "(M8 구현됨)" + 구현 노트: `xmem-detection` crate, `DetectionContext`(관찰 데이터만), heuristics 기반 판정, modules 비면 003/004 skip, findings 정렬 규칙.
- §8의 "`findings` diff(Detection Appeared/Disappeared)는 M8에서 추가" → "M8에서 추가됨(`detections_added/removed/changed`)".
- dependency 표: `xmem-detection` 도입됨(M8), `xmem-forensics → xmem-detection` edge 명기.
- crate 표 `xmem-detection` → "M8 (생성됨; Rule trait + XMEM-001~005)".
- Status 표 M8 Done, M9~M12 Planned.

- [ ] **Step 3: 전체 게이트**

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: 전부 exit 0. 테스트 합계 = core 33 + windows 50 + pe 9 + memory 21 + detection 8 + forensics 20 + cli 50 = **191** (실측으로 확정).

- [ ] **Step 4: Windows 실검증 (스모크)**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
cargo run -q -p xmem-cli -- detect --pid $PID
cargo run -q -p xmem-cli -- --json detect --pid $PID | ConvertFrom-Json | Select-Object ok
$tmp = Join-Path $env:TEMP "xmem-m8"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
cargo run -q -p xmem-cli -- snapshot create --pid $PID --output "$tmp\a.xmem"
cargo run -q -p xmem-cli -- --json snapshot create --pid $PID --output "$tmp\b.xmem" | ConvertFrom-Json | Select-Object ok
cargo run -q -p xmem-cli -- snapshot diff "$tmp\a.xmem" "$tmp\b.xmem"
cargo run -q -p xmem-cli -- detect --pid 1288; Write-Output "exit=$LASTEXITCODE"   # lsass PID는 Get-Process lsass로 조회
cargo run -q -p xmem-cli -- detect --pid 4294967294; Write-Output "exit=$LASTEXITCODE"
Remove-Item -Recurse -Force $tmp
```

확인 항목:
1. `detect` self → findings 1건 이상(exec-private/RWX 관찰) + 요약행, exit 0. findings가 0이면 그 사실을 그대로 기록.
2. `--json detect` ok=true, `finding_count`/`findings` 키 존재.
3. snapshot create 2회 exit 0, `--json` ok=true; diff 출력 요약에 `detections:` 카운트 존재.
4. lsass(비관리자) → access denied + exit 1, bogus PID → exited + exit 1.
5. `detect` 반복 3회 모두 exit 0, panic 없음. temp 정리.

- [ ] **Step 5: 체크박스 갱신 + 커밋**

`docs/plans/milestone-08-detection.md`의 `- [ ]`를 전부 `- [x]`로 바꾸고:

```bash
git add README.md docs/architecture.md docs/plans/milestone-08-detection.md
git commit -m "docs: M8 Detection Engine 상태 반영"
```

---

## Self-Review Notes

- **Spec coverage:** XMEM-001~005(§9 표) → Task 1; Evidence 구조 유지(§7) → 모든 rule이 `Evidence::new` + observed만 사용; Snapshot `findings` 채우기(§8) → Task 2; Detection Appeared/Disappeared(§16) → Task 2 diff + Task 3 렌더; CLI 하드코딩 금지(§9 마지막 줄) → Task 3은 렌더만.
- **의도적 단순화:** XMEM-002는 M6 probe heuristic(`private_executable_pe_like`)을 신뢰한다 — detection이 소스 read를 하지 않는다는 제약(오프라인 snapshot 지원) 때문. 더 강한 evidence가 필요하면 M9 MemoryImage에서 raw 바이트 기반 rule로 확장.
- **Type consistency:** `FindingChange`는 forensics 소유(Serialize), CLI는 렌더만. `detect_source`는 detection crate 소유. `severity_text`/`confidence_text`는 forensics(diff 문자열)와 cli(표시) 양쪽에 각각 존재 — crate 경계를 넘는 공유 타입을 만들지 않기 위한 의도적 중복(3줄).
- **예상 테스트:** 191 (core 33, windows 50, pe 9, memory 21, detection 8, forensics 20, cli 50). 실행 후 실제 값으로 확정한다.
