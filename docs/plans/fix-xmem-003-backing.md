# XMEM-003 백킹 판정 수정 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** XMEM-003이 파일/이미지 백킹이 관찰된 executable 영역을 오탐하지 않도록 백킹 판정을 추가하고, 남은 매핑 영역은 Low confidence로 하향한다.

**Architecture:** `xmem-detection::rules::ExecutableWithoutBackingModule`에 `Backing` 판정(모듈 파일명 일치 / `MEM_IMAGE` / 기타 파일 / 백킹 없음)을 추가한다. private 실행 영역은 XMEM-001/002가 더 나은 근거로 보고하므로 003에서 제외한다. 규칙 외 변경 없음(스키마·CLI·GUI 불변).

**Tech Stack:** Rust 2024(기존 workspace), 신규 dependency 없음.

**Spec:** `docs/future-work.md` §1.1(실측 근거·수정 방향), `docs/architecture.md` §9

## Global Constraints

- Rust stable(1.98). `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo clippy -q --workspace --all-targets -- -D warnings`, `cargo test --workspace` 전부 exit 0.
- 새 dependency 금지. `unsafe` 금지(xmem-detection은 workspace lint `unsafe_code = deny`).
- Rule은 `xmem-detection`에만 존재. CLI/GUI에 하드코딩 금지.
- Evidence 구조 유지(Observed Fact → Evidence → Heuristic → Confidence → Interpretation). 악성 단정 표현 금지.
- findings 정렬 키 `(rule_id, region_base, address)` 불변.
- lab target 양성(XMEM-001/002/004) 불변. 기존 테스트는 대체되는 003 테스트 1건 외 전부 green 유지.
- 실측 기준(v0.1.0 release, pwsh.exe): findings 86 = XMEM-003 84 + XMEM-001 1 + XMEM-005 1. 수정 후 기대: 84 → 약 35(전부 Low confidence), XMEM-001/005 유지.

## Review Focus

1. 모듈명 매칭은 대소문자 무시 + 경로 구분자 `\`/`/` 양쪽 지원 — `\Device\HarddiskVolume3\...\srpapi.dll` ↔ 모듈 `srpapi.dll`.
2. `mapped_file`이 있지만 모듈명과 불일치하면 제외하지 말고 Low로 유지(수동 매핑 이미지 신호 보존).
3. `region_type`이 `None`인 알 수 없는 영역도 판정 누락 없이 처리(`mapped-no-file`로 취급).
4. private 실행 영역 제외가 XMEM-001/002 양성을 가리지 않아야 함 — 테스트로 고정.
5. modules 조회 실패(빈 목록) 시 003 침묵 유지.

---

### Task 1: XMEM-003 백킹 판정 구현

**Files:**
- Modify: `crates/xmem-detection/src/rules.rs` (import 1줄 + `Backing`/`file_name`/`backing_of` 추가 + `ExecutableWithoutBackingModule::evaluate` 교체 + 테스트 7종)

**Interfaces:**
- Consumes: `xmem_core::{MemoryRegion, MemoryType, ModuleInfo, RegionClass}` (기존 정의)
- Produces: `ExecutableWithoutBackingModule`(rule id `XMEM-003`)의 동작 변경만. 시그니처·공개 타입 변경 없음.

- [x] **Step 1: 실패 테스트 작성**

`rules.rs`의 테스트 모듈에서 기존 `xmem003_fires_outside_modules_and_skips_when_modules_unknown`를 삭제하고 아래로 교체한다. 또한 헬퍼 `typed_region`을 `region` 헬퍼 아래에 추가한다.

```rust
    fn typed_region(
        base: u64,
        classification: RegionClass,
        region_type: Option<MemoryType>,
        protection_raw: u32,
        mapped_file: Option<&str>,
    ) -> MemoryRegion {
        MemoryRegion {
            base,
            size: 0x1000,
            state: MemoryState::Commit,
            protection: Protection::new(protection_raw, true, true, protection_raw & 0x10 != 0),
            allocation_protection: None,
            region_type,
            readable: true,
            writable: matches!(protection_raw & 0xf0, 0x04 | 0x08 | 0x40 | 0x80),
            executable: matches!(protection_raw & 0xf0, 0x10 | 0x20 | 0x40 | 0x80),
            classification,
            heuristics: Vec::new(),
            mapped_file: mapped_file.map(str::to_string),
        }
    }

    fn backing_observed(finding: &Finding) -> &str {
        finding.evidence[0]
            .observed
            .get("backing")
            .expect("backing evidence")
    }

    #[test]
    fn xmem003_skips_module_name_matched_mapping() {
        let regions = vec![typed_region(
            0x8000_0000,
            RegionClass::Mapped,
            Some(MemoryType::Mapped),
            0x20,
            Some(r"\Device\HarddiskVolume3\Windows\System32\srpapi.dll"),
        )];
        let modules = vec![module("srpapi.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn xmem003_skips_image_regions() {
        let regions = vec![typed_region(
            0x8000_0000,
            RegionClass::Image,
            Some(MemoryType::Image),
            0x20,
            None,
        )];
        let modules = vec![module("mod.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn xmem003_skips_private_executable_regions() {
        let regions = vec![region(0x8000_0000, Vec::new(), RegionClass::Private, 0x40)];
        let modules = vec![module("mod.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn xmem003_downgrades_other_file_mapping() {
        let regions = vec![typed_region(
            0x8000_0000,
            RegionClass::Mapped,
            Some(MemoryType::Mapped),
            0x20,
            Some(r"\Device\HarddiskVolume3\tmp\unknown.bin"),
        )];
        let modules = vec![module("mod.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(backing_observed(&findings[0]), "file-mapped");
        assert_eq!(
            findings[0].evidence[0].observed.get("mapped_file").map(String::as_str),
            Some(r"\Device\HarddiskVolume3\tmp\unknown.bin")
        );
    }

    #[test]
    fn xmem003_reports_mapped_without_file_backing() {
        let regions = vec![typed_region(
            0x8000_0000,
            RegionClass::Mapped,
            Some(MemoryType::Mapped),
            0x20,
            None,
        )];
        let modules = vec![module("mod.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].confidence, Confidence::Low);
        assert_eq!(backing_observed(&findings[0]), "mapped-no-file");
        assert_eq!(
            findings[0].evidence[0].observed.get("region_type").map(String::as_str),
            Some("MEM_MAPPED")
        );
        assert_eq!(
            findings[0].evidence[0].observed.get("mapped_file").map(String::as_str),
            Some("none")
        );
    }

    #[test]
    fn xmem003_unknown_region_type_is_treated_as_no_backing() {
        let regions = vec![typed_region(
            0x8000_0000,
            RegionClass::Unknown,
            None,
            0x20,
            None,
        )];
        let modules = vec![module("mod.dll", 0x1000, 0x2000)];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &modules, &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(backing_observed(&findings[0]), "mapped-no-file");
        assert_eq!(
            findings[0].evidence[0].observed.get("region_type").map(String::as_str),
            Some("unknown")
        );
    }

    #[test]
    fn xmem003_skips_when_modules_unknown() {
        let regions = vec![typed_region(
            0x8000_0000,
            RegionClass::Mapped,
            Some(MemoryType::Mapped),
            0x20,
            None,
        )];
        let findings = evaluate(&ExecutableWithoutBackingModule, &regions, &[], &[]);
        assert!(findings.is_empty());
    }
```

- [x] **Step 2: 실패 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-detection 2>&1 | Select-Object -Last 25`
Expected: 컴파일 성공 후 `xmem003_*` 다수 FAIL(예: `xmem003_skips_module_name_matched_mapping`는 finding 1건, `xmem003_reports_mapped_without_file_backing`는 severity Medium≠Low) — 기존 로직이 백킹을 보지 않기 때문.

- [x] **Step 3: 구현**

`rules.rs` 상단 import에 `MemoryType` 추가:

```rust
use xmem_core::{
    Confidence, Evidence, Finding, Heuristic, MemoryRegion, MemoryState, MemoryType, ModuleInfo,
    RegionClass, Severity, ThreadInfo,
};
```

`overlaps` 헬퍼 아래에 백킹 판정을 추가:

```rust
/// executable 영역의 백킹(파일/이미지) 판정 결과.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backing {
    /// 로드된 모듈 이름과 일치하는 파일이 백킹한다.
    ModuleFile,
    /// `MEM_IMAGE`(이미지 섹션).
    Image,
    /// 파일이 백킹하지만 로드된 모듈 이름과 일치하지 않는다.
    OtherFile,
    /// 파일 백킹이 관찰되지 않았다.
    None,
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn backing_of(region: &MemoryRegion, modules: &[ModuleInfo]) -> Backing {
    if region.region_type == Some(MemoryType::Image) {
        return Backing::Image;
    }
    let Some(path) = region.mapped_file.as_deref() else {
        return Backing::None;
    };
    let base = file_name(path);
    if modules
        .iter()
        .any(|module| module.name.eq_ignore_ascii_case(base))
    {
        Backing::ModuleFile
    } else {
        Backing::OtherFile
    }
}
```

`ExecutableWithoutBackingModule::evaluate`를 교체:

```rust
    fn evaluate(&self, context: &DetectionContext<'_>) -> Vec<Finding> {
        if context.modules.is_empty() {
            return Vec::new();
        }
        context
            .regions
            .iter()
            .filter(|region| region.state == MemoryState::Commit && region.executable)
            .filter(|region| !context.modules.iter().any(|module| overlaps(module, region)))
            .filter_map(|region| {
                // private 실행 영역은 XMEM-001/002가 더 나은 근거로 보고한다(중복 방지).
                if region.classification == RegionClass::Private {
                    return None;
                }
                let (backing, severity, confidence, heuristic, interpretation) =
                    match backing_of(region, context.modules) {
                        Backing::ModuleFile | Backing::Image => return None,
                        Backing::OtherFile => (
                            "file-mapped",
                            Severity::Low,
                            Confidence::Low,
                            "executable mapping outside any loaded module range",
                            "Disk-backed executable mapping outside the module list; manually mapped images and unusual data mappings can appear here",
                        ),
                        Backing::None => (
                            "mapped-no-file",
                            Severity::Medium,
                            Confidence::Low,
                            "executable memory without file backing or module overlap",
                            "Executable memory outside modules and without observed file backing; JIT engines and .NET runtimes can also produce this",
                        ),
                    };
                Some(Finding {
                    rule_id: self.id().to_string(),
                    name: self.name().to_string(),
                    severity,
                    confidence,
                    evidence: vec![
                        region_evidence(region)
                            .observe("classification", region.classification.to_string())
                            .observe(
                                "region_type",
                                region.region_type.map_or_else(
                                    || "unknown".to_string(),
                                    |value| value.to_string(),
                                ),
                            )
                            .observe(
                                "mapped_file",
                                region
                                    .mapped_file
                                    .clone()
                                    .unwrap_or_else(|| "none".to_string()),
                            )
                            .observe("module_overlap", "none")
                            .observe("backing", backing),
                    ],
                    heuristic: heuristic.to_string(),
                    interpretation: interpretation.to_string(),
                })
            })
            .collect()
    }
```

- [x] **Step 4: 통과 확인**

Run: `$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"; cargo test -p xmem-detection 2>&1 | Select-Object -Last 25`
Expected: `14 passed`(기존 8 − 대체 1 + 신규 7 = 14), 0 failed.

- [x] **Step 5: 게이트 + 커밋**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all
cargo clippy -q -p xmem-detection --all-targets -- -D warnings
cargo test --workspace 2>&1 | Out-File -Encoding utf8 "$env:TEMP\opencode\xmem-003-fix-tests.log"
git add crates/xmem-detection
git commit -m "fix(detection): XMEM-003 백킹 판정 추가로 오탐 제거"
```

Expected: clippy exit 0, workspace 테스트 269 green(263 − 0 + 6), 로그에서 `0 failed` 확인.

---

### Task 2: 문서 반영 + 라이브 검증

**Files:**
- Modify: `docs/detection.md`, `docs/architecture.md`(§9 표), `README.md`(Limitations), `docs/future-work.md`(§1.1·우선순위 표)
- Test: 라이브 스모크(release CLI, pwsh.exe)

**Interfaces:**
- Consumes: Task 1의 XMEM-003 동작.
- Produces: 문서와 실측 수치(수정 후 findings 수).

- [x] **Step 1: 문서 갱신**

`docs/detection.md` 표의 XMEM-003 행:

```
| XMEM-003 Executable Memory Without Backing Module | executable이 모듈 범위 밖 + 백킹 없음. 모듈명 일치 파일/`MEM_IMAGE`는 제외, 기타 파일 매핑은 Low, 백킹 없음은 Medium/Low | Low~Medium | Low |
```

`docs/detection.md` 한계 목록에 추가:

```
- XMEM-003은 `mapped_file` basename이 로드된 모듈명과 일치하거나 `MEM_IMAGE`이면 보고하지 않는다(같은 파일의 2차 매핑·이미지 섹션 오탐 제거). private 실행 영역은 XMEM-001/002가 담당한다.
```

`docs/architecture.md` §9 표의 XMEM-003 행 → `| XMEM-003 Executable Memory Without Backing Module | executable이 모듈 범위 밖이며 파일/이미지 백킹이 관찰되지 않음(private 제외, 기타 파일 매핑은 Low) | Low~Medium | Low | 백킹 판정(M13.x) |`

README Limitations의 XMEM-003 문구를 교체:

```
- `detect`의 finding은 전부 heuristic이며 **탐지 확정이 아니다**. XMEM-002는 `memory map`의 4 KiB 프로브 결과에 의존하고, XMEM-003은 백킹 판정(모듈명 일치/이미지 제외) 후에도 `MEM_MAPPED` 무파일 영역에서 JIT·.NET 런타임에 의해 발생할 수 있다. 모듈 조회에 실패하면 XMEM-003/004는 침묵한다(skip).
```

`docs/future-work.md` §1.1 제목/본문: `수정됨(v0.1.1)`로 바꾸고 수정 후 실측 수치(Step 3 결과)와 변경 요약(모듈명 매칭·이미지 제외·private 제외·Low 하향)을 기재. 우선순위 표 P0 행에서 XMEM-003 부분 제거(경로 변환 1.3만 잔류).

- [x] **Step 2: release 빌드 + 사전/사후 카운트 비교**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build --release -q -p xmem-cli
$exe = ".\target\release\xmem.exe"
$pwshPid = (Get-Process pwsh | Select-Object -First 1).Id
& $exe detect --pid $pwshPid > "$env:TEMP\opencode\detect-after.txt"
& $exe --json detect --pid $pwshPid > "$env:TEMP\opencode\detect-after.json"
Select-String -Path "$env:TEMP\opencode\detect-after.txt" -Pattern 'findings$'
```

Expected: findings 총계가 기존 86 대비 대폭 감소(약 35±10), XMEM-001/005 유지. JSON에서 XMEM-003 confidence가 전부 `low`이고 `backing` observed가 `mapped-no-file`/`file-mapped`만 존재.

- [x] **Step 3: 실측 수치를 문서에 반영**

Step 2 출력에서 뽑은 수치(총 findings, 규칙별 건수, confidence 분포)를 `docs/future-work.md` §1.1과 위 README 문구에 기입.

- [x] **Step 4: lab target 양성 회귀 확인**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo test -p xmem-target 2>&1 | Select-Object -Last 8
& $exe experiment run remote-alloc
```

Expected: xmem-target 7 passed(ground_truth·experiment_e2e 포함), `experiment run remote-alloc` → `expected XMEM-001: baseline absent / post observed`.

- [x] **Step 5: 최종 게이트 + 커밋·push**

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo fmt --all -- --check
cargo check --workspace
cargo clippy -q --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | Out-File -Encoding utf8 "$env:TEMP\opencode\xmem-003-fix-final.log"
git add README.md docs/detection.md docs/architecture.md docs/future-work.md docs/plans/fix-xmem-003-backing.md
git commit -m "docs: XMEM-003 백킹 판정 반영"
git push origin main
```

Expected: 전부 exit 0, 로그에서 `0 failed`, push 성공.

---

## Self-Review Notes

- 스펙 커버리지: future-work §1.1의 4가지 수정 방향(모듈명 매칭 제외 / file-backed 하향 / mapped-no-file 유지 / 검증)을 Task 1·2에 매핑. 1.3(경로 변환)은 이번 범위 밖(별도 작업).
- 타입 일관성: `Backing`은 private enum, `backing_of`/`file_name`은 모듈 내부 함수 — 공개 API 변경 없음. `MemoryType`은 기존 `xmem_core` 재수출 타입.
- Review Focus 5항목은 각각 `xmem003_skips_module_name_matched_mapping` / `xmem003_downgrades_other_file_mapping` / `xmem003_unknown_region_type_is_treated_as_no_backing` / `xmem003_skips_private_executable_regions` / `xmem003_skips_when_modules_unknown` 테스트로 고정.
- 기존 `xmem003_fires_outside_modules_and_skips_when_modules_unknown`는 새 동작(private 제외·Low 하향)과 모순되므로 7개 테스트로 대체한다.
