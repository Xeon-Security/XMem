//! 실험 정의 registry, 기대 아티팩트 판정, 액션 실행.

use xmem_core::{Finding, Result, XmemError};
use xmem_windows::{
    OwnedHandle, alloc_remote, create_remote_thread, flush_instruction_cache, protect_remote,
    thread_id, write_remote,
};

use crate::TargetGuard;

/// 액션 성공 시 관찰되어야 하는 아티팩트.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    Region(u64),
    Tid(u32),
}

/// 실험 정의 메타데이터.
#[derive(Debug, Clone, Copy)]
pub struct ExperimentMeta {
    pub name: &'static str,
    pub description: &'static str,
    pub scenario: &'static str,
    pub expected_rule: &'static str,
}

/// 사용 가능한 실험 목록.
pub const EXPERIMENTS: &[ExperimentMeta] = &[
    ExperimentMeta {
        name: "remote-alloc",
        description: "VirtualAllocEx(RWX) 할당 → Executable Private Memory (XMEM-001/005)",
        scenario: "normal",
        expected_rule: "XMEM-001",
    },
    ExperimentMeta {
        name: "protection-flip",
        description: "기존 private RW 영역을 VirtualProtectEx로 RWX로 변경 (XMEM-005)",
        scenario: "private",
        expected_rule: "XMEM-005",
    },
    ExperimentMeta {
        name: "pe-staging",
        description: "원격 메모리에 PE 헤더 기록 후 RX로 보호 변경 (XMEM-002)",
        scenario: "normal",
        expected_rule: "XMEM-002",
    },
    ExperimentMeta {
        name: "remote-thread",
        description: "원격 RX 메모리에 스텁 기록 + suspended CreateRemoteThread (XMEM-004)",
        scenario: "normal",
        expected_rule: "XMEM-004",
    },
];

/// 이름으로 실험 정의를 찾는다.
pub fn experiment(name: &str) -> Result<&'static ExperimentMeta> {
    EXPERIMENTS
        .iter()
        .find(|meta| meta.name == name)
        .ok_or_else(|| {
            let available = EXPERIMENTS
                .iter()
                .map(|meta| meta.name)
                .collect::<Vec<_>>()
                .join(", ");
            XmemError::InvalidInput {
                reason: format!("알 수 없는 실험: {name} (가능: {available})"),
            }
        })
}

/// finding이 기대 rule과 아티팩트 위치를 모두 만족하는지 판정한다.
pub fn finding_matches(finding: &Finding, rule_id: &str, expectation: Expectation) -> bool {
    if finding.rule_id != rule_id {
        return false;
    }
    finding.evidence.iter().any(|evidence| match expectation {
        Expectation::Region(base) => evidence.region_base == Some(base),
        Expectation::Tid(tid) => {
            evidence
                .observed
                .get("tid")
                .and_then(|value| value.parse::<u32>().ok())
                == Some(tid)
        }
    })
}

/// 실험 액션을 실행하고 기대 아티팩트를 반환한다.
pub fn execute_action(
    meta: &ExperimentMeta,
    handle: &OwnedHandle,
    report: &TargetGuard,
) -> Result<Expectation> {
    match meta.name {
        "remote-alloc" => {
            let base = alloc_remote(handle, 4096, 0x40)?;
            Ok(Expectation::Region(base))
        }
        "protection-flip" => {
            let base = report.artifact_u64("private", "base")?;
            let old = protect_remote(handle, base, 4096, 0x40)?;
            if old & 0xff != 0x04 {
                return Err(XmemError::InvalidInput {
                    reason: format!("예상한 RW(0x04)가 아닌 보호 속성: {old:#x}"),
                });
            }
            Ok(Expectation::Region(base))
        }
        "pe-staging" => {
            let bytes = fake_pe_bytes();
            let base = alloc_remote(handle, 4096, 0x04)?;
            write_remote(handle, base, &bytes)?;
            protect_remote(handle, base, 4096, 0x20)?;
            flush_instruction_cache(handle, base, bytes.len())?;
            Ok(Expectation::Region(base))
        }
        "remote-thread" => {
            let base = alloc_remote(handle, 4096, 0x20)?;
            write_remote(handle, base, &[0xC3])?;
            flush_instruction_cache(handle, base, 1)?;
            let thread = create_remote_thread(handle, base, true)?;
            Ok(Expectation::Tid(thread_id(&thread)))
        }
        other => Err(XmemError::InvalidInput {
            reason: format!("액션 미구현: {other}"),
        }),
    }
}

/// xmem-target의 PE-like 아티팩트와 동일한 최소 PE32+ 이미지를 만든다.
pub fn fake_pe_bytes() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    buf[0..2].copy_from_slice(b"MZ");
    let pe_offset = 0x40u32;
    buf[0x3c..0x40].copy_from_slice(&pe_offset.to_le_bytes());
    let pe = pe_offset as usize;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    let coff = pe + 4;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0x00F0u16.to_le_bytes());
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[opt + 24..opt + 32].copy_from_slice(&0x0000_0001_4000_0000u64.to_le_bytes());
    buf[opt + 56..opt + 60].copy_from_slice(&0x2000u32.to_le_bytes());
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    let section = opt + 0xF0;
    buf[section..section + 5].copy_from_slice(b".text");
    buf[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    buf[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    buf[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::{Confidence, Evidence, Finding, Severity};

    fn finding(rule_id: &str, region_base: u64, tid: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            name: "test".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            evidence: vec![
                Evidence::new("region")
                    .with_region_base(region_base)
                    .observe("tid", tid),
            ],
            heuristic: "test".to_string(),
            interpretation: "test".to_string(),
        }
    }

    #[test]
    fn registry_names_are_unique_and_expected_rules_valid() {
        let mut names: Vec<&str> = EXPERIMENTS.iter().map(|e| e.name).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "실험 이름 중복");
        for meta in EXPERIMENTS {
            assert!(meta.expected_rule.starts_with("XMEM-0"), "{}", meta.name);
            assert!(!meta.scenario.is_empty(), "{}", meta.name);
            assert!(!meta.description.is_empty(), "{}", meta.name);
        }
    }

    #[test]
    fn finding_matches_region_and_tid() {
        let region_finding = finding("XMEM-001", 0x1000, "777");
        assert!(finding_matches(
            &region_finding,
            "XMEM-001",
            Expectation::Region(0x1000)
        ));
        assert!(!finding_matches(
            &region_finding,
            "XMEM-001",
            Expectation::Region(0x2000)
        ));
        assert!(!finding_matches(
            &region_finding,
            "XMEM-005",
            Expectation::Region(0x1000)
        ));

        let thread_finding = finding("XMEM-004", 0x1000, "777");
        assert!(finding_matches(
            &thread_finding,
            "XMEM-004",
            Expectation::Tid(777)
        ));
        assert!(!finding_matches(
            &thread_finding,
            "XMEM-004",
            Expectation::Tid(778)
        ));
        assert!(!finding_matches(
            &thread_finding,
            "XMEM-001",
            Expectation::Tid(777)
        ));
    }
}
