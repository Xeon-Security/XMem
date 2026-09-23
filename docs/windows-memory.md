# Windows 메모리 기초

이 문서는 XMem이 사용자 모드에서 관찰하는 Windows 가상 메모리 개념을 정리한다.
모든 내용은 Windows 10/11 x64에서 `VirtualQueryEx` 기반으로 관찰 가능한 사실 범위다.

## 가상 주소 공간

- 각 프로세스는 독립된 가상 주소 공간을 가진다. x64 사용자 공간은 일반적으로
  `0x0000_0000_0000_0000` ~ `0x0000_7FFF_FFFF_FFFF` 범위다(시스템 구성에 따라 다름).
- 주소 공간은 페이지(4 KiB, 대형 페이지는 2 MiB/1 GiB) 단위로 관리된다.
- XMem은 `GetNativeSystemInfo`의 `lpMaximumApplicationAddress`로 상한을 구해
  열거에 사용한다(`xmem-windows::memory::native_max_user_address`).

## State (MEM_*)

| 값 | 의미 |
|---|---|
| `MEM_COMMIT` (0x1000) | 물리 저장소(또는 페이지 파일)가 할당된 페이지 |
| `MEM_RESERVE` (0x2000) | 주소만 예약되고 아직 커밋되지 않음 |
| `MEM_FREE` (0x10000) | 미사용 영역 |

## Type (MEM_*)

| 값 | 의미 |
|---|---|
| `MEM_IMAGE` (0x1000000) | PE 이미지가 매핑된 영역(실행 파일, DLL) |
| `MEM_MAPPED` (0x40000) | 파일/섹션이 매핑된 영역(데이터 파일, 페이지 파일) |
| `MEM_PRIVATE` (0x20000) | 사설(힙, 스택, 동적 할당) |

`MEM_FREE` 영역에는 Type이 없다. XMem 모델에서는 `region_type: Option<MemoryType>`으로
표현하고 Free/Reserve 기본값은 `None`이다.

## Protection (PAGE_*)

기본 보호 8종과 수식 비트(GUARD 0x100, NOCACHE 0x200)로 구성된다.

| 값 | 의미 |
|---|---|
| `PAGE_NOACCESS` (0x01) | 접근 불가 |
| `PAGE_READONLY` (0x02) | 읽기 |
| `PAGE_READWRITE` (0x04) | 읽기/쓰기 |
| `PAGE_WRITECOPY` (0x08) | 쓰기 시 복사 |
| `PAGE_EXECUTE` (0x10) | 실행 |
| `PAGE_EXECUTE_READ` (0x20) | 실행/읽기 |
| `PAGE_EXECUTE_READWRITE` (0x40) | 실행/읽기/쓰기 |
| `PAGE_EXECUTE_WRITECOPY` (0x80) | 실행/쓰기 시 복사 |

XMem은 `Protection::from_win32(raw)`로 하위 8비트를 해석해
`readable`/`writable`/`executable`을 계산하고, 원본 raw 값은 그대로 보존한다
(GUARD/NOCACHE 비트 손실 없음). 표시 형식은 `RWX (0x40)`처럼 플래그와 raw 값을 함께 보여준다.

## 열거: VirtualQueryEx

- `VirtualQueryEx(handle, address, &mut MEMORY_BASIC_INFORMATION, size)`를 반복 호출해
  `BaseAddress + RegionSize`로 다음 주소로 진행한다.
- 반환값 0(실패)이면 `ERROR_INVALID_PARAMETER`(87)인 경우 정상 종료로 처리한다.
  실제로 주소 공간 끝을 지나면 이 오류가 온다.
- `RegionSize == 0`이면 무한 루프 방지를 위해 중단한다.
- XMem은 비관리자에서도 동작을 보장하기 위해 `PROCESS_QUERY_LIMITED_INFORMATION`을
  우선 사용하고, 필요 시 `PROCESS_QUERY_INFORMATION`으로 재시도한다.
- 안전 상한: 최대 1,048,576 영역(`MAX_REGIONS`). 도달하면 `truncated = true`로 보고한다.

## 파일 매핑 이름: GetMappedFileNameW

- `MEM_IMAGE`/`MEM_MAPPED` 영역에 대해 `GetMappedFileNameW`로 백업 파일 경로를 얻는다.
- 반환 경로는 NT 형식(`\Device\HarddiskVolume3\Windows\System32\ntdll.dll`)이며
  XMem은 드라이브 문자 변환을 하지 않는다.
- 페이지 파일/무효 매핑(`ERROR_FILE_INVALID` = 0x800703EE, HRESULT 0x800703EE)에서는
  함수가 실패한다. 이는 정상 케이스로 `None` 처리한다.

## 분류와 Heuristic

- `classify(state, region_type)`는 `RegionClass`(image/mapped/private/free/reserved/unknown)를
  결정한다(관찰된 값의 단순 매핑).
- `heuristics(state, protection, region_type)`는 커밋 + 실행 가능 영역에서만:
  - `MEM_PRIVATE` + executable → `executable_private`
  - writable + executable → `writable_executable`
- XMem은 관찰(obserevd)과 해석(heuristic)을 분리한다. Heuristic은 "악성" 판정이 아니다.

## 한계

- 커밋된 영역 크기는 실제 물리 메모리 사용량과 다르다(공유/페이지 아웃).
- 매핑 파일 이름은 영역 시작 주소 기준이며, 대형 이미지의 분할 영역에서는 반복된다.
- 보호 속성은 스냅샷 시점의 값이며, 이후 변경될 수 있다(레이스).
- VAD 구조 자체는 커널 전용이다. 자세한 내용은 `docs/vad.md` 참고.
