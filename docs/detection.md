# Detection 방법론

XMem은 관찰과 해석을 분리하는 Evidence 기반 탐지를 지향한다.
이 문서는 Detection Engine의 구조, 규칙, 출력 해석 방법을 정리한다.

## Evidence 모델

```text
Observed Fact  →  Evidence  →  Heuristic  →  Confidence  →  Interpretation
```

- **Observed Fact**: `VirtualQueryEx`/`GetMappedFileNameW`/Toolhelp/PE 파서가 수집한 원시 값.
- **Evidence**: 사실을 구조화한 레코드. `kind`(region/thread/module 등), 주소,
  `observed: BTreeMap<String, String>`(예: `protection = "RWX (0x40)"`, `state = "MEM_COMMIT"`).
- **Heuristic**: 사실의 분류(예: `executable_private`, `private_executable_pe_like`).
- **Confidence**: 근거의 신뢰도(low/medium/high).
- **Interpretation**: 제한된 해석. XMem은 "악성"을 단정하지 않고 "Potentially ..." 수준으로 쓴다.

`Finding`은 `rule_id`, `name`, `severity`, `confidence`, `evidence`, `heuristic`,
`interpretation`으로 구성되며 JSON/Markdown으로 직렬화된다.

## 기본 규칙 (XMEM-001~005)

| Rule | 조건 | Severity | Confidence |
|---|---|---|---|
| XMEM-001 Executable Private Memory | committed + `MEM_PRIVATE` + executable (heuristic `executable_private`) | Medium | High |
| XMEM-002 PE Header in Private Executable Region | private executable 영역 첫 4 KiB가 PE-like/깨진 헤더 | High | Medium |
| XMEM-003 Executable Memory Without Backing Module | executable이지만 모듈 범위에 없음(모듈 목록이 비면 침묵) | Medium | Medium |
| XMEM-004 Suspicious Thread Start Address | start address가 private executable 또는 모듈 밖(주소 미상이면 침묵) | High | Medium |
| XMEM-005 Memory Protection Anomaly | RWX/WRITE_COPY-EXECUTE 계열; private/mapped=High, image=Low | Medium | High |

- 규칙은 `xmem-detection` crate에만 존재하며 CLI에 하드코딩하지 않는다.
- 결과는 `(rule_id, region_base, address)`로 정렬해 결정적으로 출력한다.
- modules 조회에 실패하면 XMEM-003/004는 침묵한다(불완전 데이터로 오탐하지 않기 위해).
- XMEM-002는 4 KiB 프리픽스 프로브 기반이라 전체 헤더 검증보다 약하다.

## 오탐 요인 (알려진 한계)

- JIT 컴파일러(.NET, V8), .NET ReadyToRun, 패커, DRM은 private executable 메모리를
  정상적으로 만든다 → XMEM-001/002/005는 정상 소프트웨어에서도 자주 발생한다.
- suspended 스레드는 start address가 실행 파일의 스텁을 가리키지 않아 XMEM-004에 걸릴 수 있다.
- `MEM_MAPPED` 이미지(예: 메모리 매핑된 DLL)는 모듈 목록에 없어 XMEM-003에 걸릴 수 있다.
- 시그니처 문자열(`MZ`)은 우연히 나타날 수 있다.

## 해석 원칙

- **0 findings ≠ 안전**. XMem은 알려진 상태만 검사한다.
- finding 1건도 증명이 아니라 evidence다. 커널 수준 기법, 정상 소프트웨어, 데이터 손상이
  같은 패턴을 만들 수 있다.
- Snapshot Diff는 baseline 대비 **변화**를 보여준다. 변화는 의도(실험, 정상 업데이트)와
  비의도(주입, 보호 변경)를 구분하지 않는다.

## 사용 지점

- `xmem detect --pid <PID>`: 라이브 프로세스 탐지.
- `xmem dump analyze <FILE>`: minidump에 동일 규칙 적용(오프라인; XMEM-004는 침묵).
- `xmem snapshot create`: 스냅샷에 findings 저장.
- `xmem snapshot diff`: detections 추가/삭제/변경을 보고.
- `xmem experiment run`: 실험 전후 findings로 예상 아티팩트를 판정.
- `xmem report`: findings를 JSON/Markdown으로 저장.
