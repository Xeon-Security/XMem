use xmem_core::{
    Confidence, Evidence, Finding, Heuristic, MemoryRegion, MemoryState, ModuleInfo, RegionClass,
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
    findings.sort_by_key(finding_key);
    findings
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
                evidence: vec![
                    region_evidence(region)
                        .observe("classification", region.classification.to_string())
                        .observe("module_overlap", "none"),
                ],
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
                evidence: vec![
                    Evidence::new("thread")
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
                        .observe("start_module", "none"),
                ],
                heuristic: "thread start address outside loaded modules".to_string(),
                interpretation:
                    "Potentially suspicious thread origin; JIT, hooks, and unloaded modules can also produce this"
                        .to_string(),
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
                    evidence: vec![
                        region_evidence(region)
                            .observe("classification", region.classification.to_string()),
                    ],
                    heuristic: "writable and executable protection".to_string(),
                    interpretation:
                        "Potentially suspicious protection; JIT engines and some system components also use RWX"
                            .to_string(),
                }
            })
            .collect()
    }
}

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
            writable: matches!(protection_raw & 0xf0, 0x04 | 0x08 | 0x40 | 0x80),
            executable: matches!(protection_raw & 0xf0, 0x10 | 0x20 | 0x40 | 0x80),
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

    fn thread(
        tid: u32,
        start: Option<u64>,
        region_base: Option<u64>,
        module: Option<&str>,
    ) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1,
            priority: None,
            start_address: start,
            start_region_base: region_base,
            start_module: module.map(str::to_string),
        }
    }

    fn evaluate(
        rule: &dyn Rule,
        regions: &[MemoryRegion],
        modules: &[ModuleInfo],
        threads: &[ThreadInfo],
    ) -> Vec<Finding> {
        rule.evaluate(&DetectionContext {
            regions,
            modules,
            threads,
        })
    }

    #[test]
    fn xmem001_fires_on_private_executable_heuristic() {
        let regions = vec![
            region(
                0x1000,
                vec![Heuristic::ExecutablePrivate],
                RegionClass::Private,
                0x40,
            ),
            region(0x5000, Vec::new(), RegionClass::Private, 0x04),
        ];
        let findings = evaluate(&ExecutablePrivateMemory, &regions, &[], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "XMEM-001");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].evidence[0].region_base, Some(0x1000));
        assert!(findings[0].evidence[0].observed.contains_key("protection"));
        assert!(
            !findings[0]
                .interpretation
                .to_lowercase()
                .contains("malware")
        );
    }

    #[test]
    fn xmem002_fires_on_pe_like_heuristic() {
        let regions = vec![region(
            0x2000,
            vec![
                Heuristic::ExecutablePrivate,
                Heuristic::PrivateExecutablePeLike,
            ],
            RegionClass::Private,
            0x40,
        )];
        let findings = evaluate(&PeInPrivateExecutableRegion, &regions, &[], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "XMEM-002");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert!(
            findings[0].evidence[0]
                .observed
                .values()
                .any(|value| value.contains("private_executable_pe_like"))
        );
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
        assert_eq!(
            ids,
            vec!["XMEM-001", "XMEM-002", "XMEM-003", "XMEM-004", "XMEM-005"]
        );
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn detect_is_deterministic_and_sorted() {
        let regions = vec![
            region(
                0x8000,
                vec![Heuristic::ExecutablePrivate],
                RegionClass::Private,
                0x40,
            ),
            region(
                0x1000,
                vec![Heuristic::ExecutablePrivate],
                RegionClass::Private,
                0x40,
            ),
        ];
        let first = detect(&DetectionContext {
            regions: &regions,
            modules: &[],
            threads: &[],
        });
        let second = detect(&DetectionContext {
            regions: &regions,
            modules: &[],
            threads: &[],
        });
        assert_eq!(first, second);
        let keys: Vec<&str> = first
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
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
