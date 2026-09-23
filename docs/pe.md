# PE 구조와 메모리 PE 분석

이 문서는 XMem의 PE(PE32/PE32+) 분석 계층과 메모리에서 PE-like 구조를 탐지·분류하는
방법을 정리한다.

## PE 파일 구조

| 구조 | 내용 |
|---|---|
| DOS Header | `MZ`(0x5A4D) 시그니처, `e_lfanew`(PE 헤더 오프셋) |
| PE Signature | `PE\0\0` |
| COFF Header | machine(0x8664=x64, 0x014C=x86, 0xAA64=ARM64), 섹션 수, characteristics |
| Optional Header | magic(0x10B=PE32, 0x20B=PE32+), entry RVA, image base, size_of_image, subsystem |
| Section Table | 섹션별 이름, virtual size/address, raw size, characteristics |
| Data Directories | imports, exports, relocations, TLS, resources, CLR 등 |

섹션 characteristics 비트: `MEM_EXECUTE` 0x2000_0000, `MEM_READ` 0x4000_0000,
`MEM_WRITE` 0x8000_0000.

## xmem-pe crate

- `parse_pe(bytes)`: **bounds-checked 수동 헤더 파서**로 DOS/COFF/Optional/섹션을 파싱한다.
  4 KiB 프리픽스처럼 잘린 데이터에서도 panic 없이 헤더 정보를 반환한다.
- 전체 파일이 있고 데이터 디렉터리가 파일 범위 안이면 `goblin`으로 보강해
  imports/exports/relocations/TLS 개수를 채운다.
  - goblin은 프리픽스만 주면 임포트 디렉터리가 범위를 벗어나는 순간 하드 오류를 낸다.
    그래서 "프리픽스 = 수동 파서, 전체 = goblin 보강" 구조를 쓴다.
- 결과: `PeInfo { is_64, machine, arch, image_base, entry_point(= image_base + entry RVA),
  size_of_image, subsystem, characteristics, sections, import_count, import_library_count,
  libraries, export_count, relocation_count, tls_callback_count }`.

## 메모리 PE 분류: classify_memory_pe

메모리에서 발견한 바이트가 PE로 보이는지와 영역 성격을 결합해 분류한다.

| 조건 | 분류 |
|---|---|
| `MZ` + `PE\0\0` 아님 | `None` |
| 헤더 파싱 실패 | `Malformed` |
| `MEM_IMAGE` 영역 | `NormalLoadedModule` |
| `MEM_MAPPED` 영역 | `MappedImage` |
| `MEM_PRIVATE` 영역 | `PrivatePeLike` |
| 그 외 | `Unknown` |

- 정상 로더는 PE 이미지를 `MEM_IMAGE`로 매핑한다. 따라서 `MEM_PRIVATE`에서 발견된
  PE는 정상 모듈 매핑이 아닐 가능성이 높다(단, JIT/패커/인젝터 모두 해당 가능).
- `Malformed`는 헤더가 깨졌거나 잘린 PE-like 데이터다. 회피 기법일 수 있으나
  데이터 손상일 수도 있다.

## XMem 연결 지점

- `xmem-windows`의 `live.region_map()`은 **private + executable** 영역의 첫 4 KiB를
  읽어 `MemoryPeClass`를 확인하고 heuristic을 추가한다.
  - PE 아님 → `executable_anonymous`
  - PE-like/깨진 헤더 → `private_executable_pe_like`
- `xmem modules --pid <PID> --pe`: 모듈별 PE 요약(machine, entry, 섹션 수)을 표시한다.
  프리픽스 파싱이므로 imports/exports/relocations/TLS는 0으로 보고된다.
- Snapshot/Minidump 분석도 동일한 분류를 사용한다.

## 한계

- 4 KiB 프리픽스만 읽으면 데이터 디렉터리(imports 등)를 볼 수 없다. 전체 이미지를
  덤프에서 읽는 경우에만 goblin 보강 정보가 채워진다.
- PE 헤더 존재는 실행/악성의 증거가 아니다. 셸코드 스테이징, JIT, 패커, .NET R2R 등
  정상 소프트웨어에서도 private executable 메모리가 나타난다.
- `MZ` 시그니처는 우연히 나타날 수 있다(오탐). XMEM-002는 확률적 evidence다.
