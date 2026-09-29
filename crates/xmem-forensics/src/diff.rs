use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use xmem_core::{Finding, Heuristic, MemoryRegion, ModuleInfo, ProcessArch, ThreadInfo};

use crate::envelope::{RegionHash, SnapshotEnvelope};

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotRef {
    pub pid: u32,
    pub name: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionChange {
    pub before: MemoryRegion,
    pub after: MemoryRegion,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentChange {
    pub base: u64,
    pub before_hash: String,
    pub after_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleChange {
    pub before: ModuleInfo,
    pub after: ModuleInfo,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadChange {
    pub before: ThreadInfo,
    pub after: ThreadInfo,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingChange {
    pub before: Finding,
    pub after: Finding,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiffSummary {
    pub regions_added: usize,
    pub regions_removed: usize,
    pub regions_changed: usize,
    pub content_changed: usize,
    pub modules_added: usize,
    pub modules_removed: usize,
    pub modules_changed: usize,
    pub threads_added: usize,
    pub threads_removed: usize,
    pub threads_changed: usize,
    pub detections_added: usize,
    pub detections_removed: usize,
    pub detections_changed: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotDiff {
    pub before: SnapshotRef,
    pub after: SnapshotRef,
    pub regions_added: Vec<MemoryRegion>,
    pub regions_removed: Vec<MemoryRegion>,
    pub regions_changed: Vec<RegionChange>,
    pub content_changed: Vec<ContentChange>,
    pub modules_added: Vec<ModuleInfo>,
    pub modules_removed: Vec<ModuleInfo>,
    pub modules_changed: Vec<ModuleChange>,
    pub threads_added: Vec<ThreadInfo>,
    pub threads_removed: Vec<ThreadInfo>,
    pub threads_changed: Vec<ThreadChange>,
    pub detections_added: Vec<Finding>,
    pub detections_removed: Vec<Finding>,
    pub detections_changed: Vec<FindingChange>,
    pub summary: DiffSummary,
}

fn snapshot_ref(envelope: &SnapshotEnvelope) -> SnapshotRef {
    SnapshotRef {
        pid: envelope.process.pid,
        name: envelope.process.name.clone(),
        timestamp: envelope.timestamp,
    }
}

fn heuristics_text(heuristics: &[Heuristic]) -> String {
    if heuristics.is_empty() {
        "-".to_string()
    } else {
        heuristics
            .iter()
            .map(|heuristic| heuristic.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn opt_text(value: Option<&str>) -> String {
    value.unwrap_or("-").to_string()
}

fn arch_text(arch: Option<ProcessArch>) -> String {
    match arch {
        Some(ProcessArch::X64) => "x64".to_string(),
        Some(ProcessArch::X86) => "x86".to_string(),
        Some(ProcessArch::Arm64) => "arm64".to_string(),
        Some(ProcessArch::Unknown) => "unknown".to_string(),
        None => "-".to_string(),
    }
}

fn region_changes(before: &MemoryRegion, after: &MemoryRegion) -> Vec<String> {
    let mut changes = Vec::new();
    if before.size != after.size {
        changes.push(format!("size: {:#x} -> {:#x}", before.size, after.size));
    }
    if before.state != after.state {
        changes.push(format!("state: {} -> {}", before.state, after.state));
    }
    if before.protection.raw != after.protection.raw {
        changes.push(format!(
            "protection: {} -> {}",
            before.protection, after.protection
        ));
    }
    if before.classification != after.classification {
        changes.push(format!(
            "classification: {} -> {}",
            before.classification, after.classification
        ));
    }
    if before.heuristics != after.heuristics {
        changes.push(format!(
            "heuristics: {} -> {}",
            heuristics_text(&before.heuristics),
            heuristics_text(&after.heuristics)
        ));
    }
    if before.mapped_file != after.mapped_file {
        changes.push(format!(
            "mapped_file: {} -> {}",
            opt_text(before.mapped_file.as_deref()),
            opt_text(after.mapped_file.as_deref())
        ));
    }
    changes
}

fn module_changes(before: &ModuleInfo, after: &ModuleInfo) -> Vec<String> {
    let mut changes = Vec::new();
    if before.base != after.base {
        changes.push(format!("base: {:#x} -> {:#x}", before.base, after.base));
    }
    if before.size != after.size {
        changes.push(format!("size: {:#x} -> {:#x}", before.size, after.size));
    }
    if before.path != after.path {
        changes.push(format!(
            "path: {} -> {}",
            opt_text(before.path.as_deref()),
            opt_text(after.path.as_deref())
        ));
    }
    if before.arch != after.arch {
        changes.push(format!(
            "arch: {} -> {}",
            arch_text(before.arch),
            arch_text(after.arch)
        ));
    }
    changes
}

fn opt_hex(value: Option<u64>) -> String {
    value.map_or_else(|| "-".to_string(), |value| format!("{value:#x}"))
}

fn thread_changes(before: &ThreadInfo, after: &ThreadInfo) -> Vec<String> {
    let mut changes = Vec::new();
    if before.priority != after.priority {
        changes.push(format!(
            "priority: {} -> {}",
            before
                .priority
                .map_or_else(|| "-".to_string(), |value| value.to_string()),
            after
                .priority
                .map_or_else(|| "-".to_string(), |value| value.to_string())
        ));
    }
    if before.start_address != after.start_address {
        changes.push(format!(
            "start_address: {} -> {}",
            opt_hex(before.start_address),
            opt_hex(after.start_address)
        ));
    }
    if before.start_module != after.start_module {
        changes.push(format!(
            "start_module: {} -> {}",
            opt_text(before.start_module.as_deref()),
            opt_text(after.start_module.as_deref())
        ));
    }
    if before.start_region_base != after.start_region_base {
        changes.push(format!(
            "start_region: {} -> {}",
            opt_hex(before.start_region_base),
            opt_hex(after.start_region_base)
        ));
    }
    changes
}

fn finding_key(finding: &Finding) -> (String, u64, u64) {
    let evidence = finding.evidence.first();
    (
        finding.rule_id.clone(),
        evidence
            .and_then(|item| item.region_base)
            .unwrap_or(u64::MAX),
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

/// 두 envelope의 구조적 차이를 계산한다. 변화가 없으면 빈 diff를 반환한다.
pub fn diff(before: &SnapshotEnvelope, after: &SnapshotEnvelope) -> SnapshotDiff {
    let before_regions: BTreeMap<u64, &MemoryRegion> = before
        .regions
        .iter()
        .map(|region| (region.base, region))
        .collect();
    let after_regions: BTreeMap<u64, &MemoryRegion> = after
        .regions
        .iter()
        .map(|region| (region.base, region))
        .collect();
    let mut regions_added = Vec::new();
    let mut regions_changed = Vec::new();
    for (base, region) in &after_regions {
        match before_regions.get(base) {
            None => regions_added.push((*region).clone()),
            Some(old) => {
                let changes = region_changes(old, region);
                if !changes.is_empty() {
                    regions_changed.push(RegionChange {
                        before: (*old).clone(),
                        after: (*region).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut regions_removed = Vec::new();
    for (base, region) in &before_regions {
        if !after_regions.contains_key(base) {
            regions_removed.push((*region).clone());
        }
    }
    let before_hashes: BTreeMap<u64, &RegionHash> = before
        .content_hashes
        .iter()
        .map(|hash| (hash.base, hash))
        .collect();
    let mut content_changed = Vec::new();
    for hash in &after.content_hashes {
        if let Some(old) = before_hashes.get(&hash.base)
            && old.hash != hash.hash
        {
            content_changed.push(ContentChange {
                base: hash.base,
                before_hash: old.hash.clone(),
                after_hash: hash.hash.clone(),
            });
        }
    }
    let before_modules: BTreeMap<&str, &ModuleInfo> = before
        .modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect();
    let after_modules: BTreeMap<&str, &ModuleInfo> = after
        .modules
        .iter()
        .map(|module| (module.name.as_str(), module))
        .collect();
    let mut modules_added = Vec::new();
    let mut modules_changed = Vec::new();
    for (name, module) in &after_modules {
        match before_modules.get(name) {
            None => modules_added.push((*module).clone()),
            Some(old) => {
                let changes = module_changes(old, module);
                if !changes.is_empty() {
                    modules_changed.push(ModuleChange {
                        before: (*old).clone(),
                        after: (*module).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut modules_removed = Vec::new();
    for (name, module) in &before_modules {
        if !after_modules.contains_key(name) {
            modules_removed.push((*module).clone());
        }
    }
    let before_threads: BTreeMap<u32, &ThreadInfo> = before
        .threads
        .iter()
        .map(|thread| (thread.tid, thread))
        .collect();
    let after_threads: BTreeMap<u32, &ThreadInfo> = after
        .threads
        .iter()
        .map(|thread| (thread.tid, thread))
        .collect();
    let mut threads_added = Vec::new();
    let mut threads_changed = Vec::new();
    for (tid, thread) in &after_threads {
        match before_threads.get(tid) {
            None => threads_added.push((*thread).clone()),
            Some(old) => {
                let changes = thread_changes(old, thread);
                if !changes.is_empty() {
                    threads_changed.push(ThreadChange {
                        before: (*old).clone(),
                        after: (*thread).clone(),
                        changes,
                    });
                }
            }
        }
    }
    let mut threads_removed = Vec::new();
    for (tid, thread) in &before_threads {
        if !after_threads.contains_key(tid) {
            threads_removed.push((*thread).clone());
        }
    }
    let before_findings: BTreeMap<(String, u64, u64), &Finding> = before
        .findings
        .iter()
        .map(|finding| (finding_key(finding), finding))
        .collect();
    let after_findings: BTreeMap<(String, u64, u64), &Finding> = after
        .findings
        .iter()
        .map(|finding| (finding_key(finding), finding))
        .collect();
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
    let summary = DiffSummary {
        regions_added: regions_added.len(),
        regions_removed: regions_removed.len(),
        regions_changed: regions_changed.len(),
        content_changed: content_changed.len(),
        modules_added: modules_added.len(),
        modules_removed: modules_removed.len(),
        modules_changed: modules_changed.len(),
        threads_added: threads_added.len(),
        threads_removed: threads_removed.len(),
        threads_changed: threads_changed.len(),
        detections_added: detections_added.len(),
        detections_removed: detections_removed.len(),
        detections_changed: detections_changed.len(),
    };
    SnapshotDiff {
        before: snapshot_ref(before),
        after: snapshot_ref(after),
        regions_added,
        regions_removed,
        regions_changed,
        content_changed,
        modules_added,
        modules_removed,
        modules_changed,
        threads_added,
        threads_removed,
        threads_changed,
        detections_added,
        detections_removed,
        detections_changed,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::sample_envelope;

    #[test]
    fn identical_snapshots_produce_empty_diff() {
        let envelope = sample_envelope(1, 0x1000, 0x04);
        let diff = diff(&envelope, &envelope);
        assert!(diff.regions_added.is_empty());
        assert!(diff.regions_removed.is_empty());
        assert!(diff.regions_changed.is_empty());
        assert!(diff.content_changed.is_empty());
        assert_eq!(diff.summary.regions_changed, 0);
    }

    #[test]
    fn detects_region_add_remove_and_protection_change() {
        let before = sample_envelope(1, 0x1000, 0x04);
        let mut after = sample_envelope(1, 0x1000, 0x40);
        after.regions.push(MemoryRegion {
            base: 0x9000,
            ..after.regions[0].clone()
        });
        let diff = diff(&before, &after);
        assert_eq!(diff.regions_added.len(), 1);
        assert_eq!(diff.regions_added[0].base, 0x9000);
        assert!(diff.regions_removed.is_empty());
        assert_eq!(diff.regions_changed.len(), 1);
        assert!(
            diff.regions_changed[0]
                .changes
                .iter()
                .any(|change| change.starts_with("protection:"))
        );
    }

    #[test]
    fn detects_region_removed() {
        let before = sample_envelope(1, 0x1000, 0x04);
        let after = sample_envelope(1, 0x2000, 0x04);
        let diff = diff(&before, &after);
        assert_eq!(diff.regions_removed.len(), 1);
        assert_eq!(diff.regions_removed[0].base, 0x1000);
        assert_eq!(diff.regions_added.len(), 1);
    }

    #[test]
    fn detects_content_hash_change() {
        let mut before = sample_envelope(1, 0x1000, 0x04);
        before.content_hashes.push(RegionHash {
            base: 0x1000,
            size: 0x1000,
            bytes_hashed: 0x1000,
            hash: "aa".repeat(32),
            partial: false,
        });
        let mut after = before.clone();
        after.content_hashes[0].hash = "bb".repeat(32);
        let result = diff(&before, &after);
        assert_eq!(result.content_changed.len(), 1);
        assert_eq!(result.content_changed[0].base, 0x1000);
        let same = diff(&before, &before);
        assert!(same.content_changed.is_empty());
    }

    #[test]
    fn detects_module_and_thread_changes() {
        let mut before = sample_envelope(1, 0x1000, 0x04);
        before.modules.push(ModuleInfo {
            name: "old.dll".to_string(),
            base: 0x1000,
            size: 0x1000,
            path: None,
            arch: None,
        });
        before.threads.push(ThreadInfo {
            tid: 100,
            pid: 1,
            priority: Some(0),
            start_address: Some(0x1000),
            start_region_base: Some(0x1000),
            start_module: Some("old.dll".to_string()),
            start_address_source: None,
        });
        let mut after = sample_envelope(1, 0x1000, 0x04);
        after.modules.push(ModuleInfo {
            name: "new.dll".to_string(),
            base: 0x2000,
            size: 0x1000,
            path: None,
            arch: None,
        });
        after.threads.push(ThreadInfo {
            tid: 100,
            pid: 1,
            priority: Some(0),
            start_address: Some(0x9000),
            start_region_base: Some(0x9000),
            start_module: None,
            start_address_source: None,
        });
        let diff = diff(&before, &after);
        assert_eq!(diff.modules_added.len(), 1);
        assert_eq!(diff.modules_removed.len(), 1);
        assert_eq!(diff.threads_changed.len(), 1);
        assert!(
            diff.threads_changed[0]
                .changes
                .iter()
                .any(|change| change.starts_with("start_address:"))
        );
    }

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
        assert!(
            result.detections_changed[0]
                .changes
                .iter()
                .any(|change| change.starts_with("severity:"))
        );
    }
}
