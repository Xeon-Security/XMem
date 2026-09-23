# Experiment 방법론

XMem의 실험 계층은 "Baseline → Controlled Experiment → Post-state → Diff → Detection →
Report" 파이프라인으로 메모리 변화를 관찰한다. 이 문서는 방법론, 안전 원칙, 실험 목록을 정리한다.

## 파이프라인

```text
Target Discovery (XMem이 xmem-target을 spawn)
      ↓
Baseline Snapshot (collect: 메타데이터 + blake3 해시)
      ↓
Controlled Experiment (정의된 원격 메모리 조작 1회)
      ↓
Post Snapshot (동일 옵션으로 재수집)
      ↓
Snapshot Diff (region/module/thread/content/finding 변화)
      ↓
Detection (XMEM-001~005 판정)
      ↓
Forensic Report (ExperimentReport, --json)
```

## 안전 원칙

- **임의 PID 금지**: v1 실험은 XMem이 직접 spawn한 `xmem-target` 프로세스에만 적용한다.
  사용자가 지정한 PID는 대상이 될 수 없다.
- **신원 검증**: spawn 직후 image path가 `xmem-target.exe`인지 확인하고,
  보호 프로세스 목록(name+path+session 조합)과 대조한다. PID 재사용 공격을 방지하기 위해
  실험 전후로 신원을 확인한다.
- **Cleanup**: 정상 종료, 오류, 패닉, Ctrl+C 어느 경로에서도 XMem이 만든 child를
  kill+wait하고 임시 파일/디렉터리를 제거한다. 사용자 프로세스는 절대 종료하지 않는다.
- **변경 API 격리**: `VirtualAllocEx`/`VirtualProtectEx`/`WriteProcessMemory`/
  `CreateRemoteThread`/`FlushInstructionCache` 호출은 `xmem-experiments` 경로에서만 일어난다.
  일반 분석 명령(process/memory/modules/threads/detect/report/snapshot/dump)은 read-only다.

## 실험 목록

| 이름 | scenario | 동작 | 기대 규칙 |
|---|---|---|---|
| remote-alloc | normal | 대상에 `VirtualAllocEx`로 RWX 4 KiB 할당 | XMEM-001 |
| protection-flip | private | 대상의 private RW 영역을 RXW(`0x40`)로 보호 변경 | XMEM-005 |
| pe-staging | normal | 원격 RW 메모리에 PE 헤더 기록 후 RX로 보호 변경 | XMEM-002 |
| remote-thread | normal | 원격 RX 메모리에 `ret` 스텁 기록 + suspended 스레드 생성 | XMEM-004 |

각 실험은 `--report` Ground Truth(시나리오별 아티팩트 주소/tid)를 사용한다.
예를 들어 protection-flip은 report의 `artifacts.private.base` 영역을 변경한다.

## 판정 (Ground Truth)

- `expected_present`: baseline findings에 기대 규칙 finding이 있었는가(보통 false).
- `expected_observed`: post findings에서 기대 규칙 + 기대 주소/tid 조합이 발견됐는가.
  - `Expectation::Region(base)`: evidence의 `region_base == base`.
  - `Expectation::Tid(tid)`: evidence observed의 `tid == tid`.
- `detections_added/removed`: diff 요약에서 계산.
- 판정은 "파이프라인이 예상 아티팩트를 관찰했다"는 사실이지, 악성 여부 판정이 아니다.

## Ground Truth Fixture

- `lab/targets/xmem-target`은 deterministic 시나리오(normal/pattern/private/
  private-exec/pe-like/threads/protection/all)를 만들고 `--report`로 주소/tid를 남긴다.
- 회귀 테스트(`ground_truth.rs`, `experiment_e2e.rs`)는 report의 주소와 XMem 관찰 결과를
  대조한다. 절대 주소는 실행마다 달라지므로 항상 report 값을 사용한다.

## 취소

- 장시간 단계 사이에 취소 플래그를 확인한다. 취소 시 `Cancelled` 오류로 종료하고
  exit code 130을 반환한다. guard의 `Drop`이 child 종료와 temp 정리를 수행한다.
- `--full` 덤프 생성(M9)은 진행 중 취소를 지원하지 않는다(알려진 한계).

## 한계

- 실험은 v1에서 `xmem-target` 전용이다. Windows VM에서 임의 타깃으로 확장하려면
  별도 설계(권한, 신원 검증, 복구 전략)가 필요하다.
- remote-thread 실험은 suspended 스레드를 만든다(실행하지 않음). 실행 아티팩트는
  후속 실험에서 다룬다.
- 스냅샷 해싱은 기본 64 MiB 예산이라 대형 변화는 해시로 잡히지 않을 수 있다.
