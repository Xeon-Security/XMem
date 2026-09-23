# 파일 포맷

이 문서는 XMem이 생성/소비하는 산출물(Snapshot, Minidump, Report, JSON envelope)의
포맷과 버전 관리 규칙을 정리한다.

## Snapshot v1 (.xmem)

### 바이트 레이아웃

| 오프셋 | 크기 | 내용 |
|---|---|---|
| 0 | 4 | magic `XMEM` |
| 4 | 2 | format_version (u16 LE, 현재 1) |
| 8 | 2 | flags (u16 LE, 현재 0; 0이 아니면 거부) |
| 10 | 4 | payload_len (u32 LE, JSON 바이트 수) |
| 12 | payload_len | UTF-8 JSON payload |

헤더 길이는 12바이트(`HEADER_LEN`)다. `decode`는 짧은 파일, magic/version 불일치,
flags ≠ 0, payload_len 불일치(잘림/꼬리), payload 내 `format_version` 불일치를 모두
구조화 오류로 거부한다.

### 쓰기 절차

```text
temp 파일(<path>.tmp-<pid>) → write → 재파싱 검증 → atomic rename
```

실패 시 temp 파일을 제거한다. 잘린 스냅샷을 정상 파일로 남기지 않는다.
생성 전 디스크 여유 공간을 검사한다(필요량 + 16 MiB 마진).

### JSON payload (SnapshotEnvelope)

| 필드 | 내용 |
|---|---|
| `schema_version` | JSON 스키마 버전(현재 1) |
| `xmem_version` | 생성한 XMem 버전 |
| `format_version` | 1 |
| `timestamp` | 생성 시각(UTC) |
| `process` | ProcessInfo |
| `regions` | MemoryRegion 배열 |
| `modules` / `threads` | ModuleInfo / ThreadInfo 배열 |
| `content_hashes` | RegionHash 배열 |
| `findings` | XMEM-001~005 결과 |
| `acquisition` | AcquisitionMeta |

`RegionHash { base, size, bytes_hashed, hash(blake3 hex 64자), partial }`.
해싱 정책: committed+readable 영역을 `(executable desc, private 우선, base asc)`로 정렬,
최대 8192 영역(`MAX_HASH_REGIONS`), 기본 64 MiB 예산(`hash_budget_bytes`),
chunk 1 MiB. 예산 초과 시 `partial = true`. 읽기 실패 영역은 제외하고
`read_failures`로 집계한다.

`AcquisitionMeta { source, pid, hashed_regions, hashed_bytes, hash_budget_bytes,
read_failures, region_truncated }`.

### Diff 매칭 키

| 대상 | 키 |
|---|---|
| region | `base` |
| content hash | `base`(양쪽에 해시가 있을 때만 비교) |
| module | `name` |
| thread | `tid` |
| finding | `(rule_id, evidence[0].region_base, address)` |

## Minidump (.dmp)

- `dump create`는 `MiniDumpWriteDump`로 생성한다.
  - 기본: `MiniDumpNormal | MiniDumpWithFullMemoryInfo`(메타데이터+메모리 영역 정보).
  - `--full`: `MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo`(전체 메모리; 디스크 사전 검사).
- 시그니처는 `MDMP`(4바이트). 생성은 temp → MDMP 검증 → rename.
- 분석은 `minidump` crate로 스트림(SystemInfo/ModuleList/ThreadList/MemoryInfoList/
  MiscInfo/메모리)을 읽는다. 메모리 스트림이 없으면 `read`는 오류를 반환한다.
- Minidump에는 thread start address가 없어 XMEM-004는 침묵한다.

## Report (JSON / Markdown)

- `xmem report --pid <PID> --output <FILE>`는 확장자로 형식을 정한다
  (`.md` → Markdown, 그 외 → JSON pretty).
- JSON: `ReportData { generated_at, xmem_version, schema_version, process, regions,
  modules, threads, findings, summary }`.
- Markdown 섹션: Process / Memory Summary / Findings / Regions(Free 제외) / Modules / Threads.
- 저장도 temp → rename이며, 임시 파일명은 `<path>.tmp-<pid>`다.

## CLI JSON envelope

모든 `--json` 출력은 다음 envelope를 쓴다.

```json
{ "schema_version": 1, "ok": true, "data": { ... } }
```

오류 시:

```json
{ "schema_version": 1, "ok": false, "error": { "kind": "access_denied", "message": "..." } }
```

- `schema_version`은 `JSON_SCHEMA_VERSION`(현재 1)으로 추적한다.
- 내부 Rust 구조체 변경이 JSON 포맷을 깨지 않도록 외부 스키마 버전을 별도 관리한다.

## 버전 관리 규칙

- Snapshot `format_version`(u16)과 JSON `schema_version`(u32)은 독립적으로 올린다.
- 하위 호환 불가 변경은 버전을 올리고, `decode`는 알 수 없는 버전을 거부한다.
- 향후 마이그레이션을 위해 payload는 자기 서술적 JSON으로 유지한다(필드 추가는 호환).
