# VAD (Virtual Address Descriptor)

이 문서는 VAD의 개념과 XMem이 사용자 모드에서 VAD를 어떻게 근사하는지, 그리고
그 근사의 한계를 정리한다.

## VAD란

- Windows 커널은 각 프로세스의 가상 주소 공간 사용 내역을 **VAD 트리**(`EPROCESS.VadRoot`)로
  관리한다. 각 VAD 노드는 다음 정보를 담는다.
  - 주소 범위(시작/끝)
  - 보호 속성(Protection)
  - 커밋 여부
  - 백업 파일(매핑된 경우)과 파일 내 오프셋
  - Private/Image/Mapped 구분
- 커밋, 예약, 이미지 매핑, 섹션 매핑, 스택/힙 예약 등 모든 메모리 관리 결정이
  VAD 단위로 이루어진다.

## 사용자 모드에서 VAD를 직접 읽을 수 없는 이유

- VAD는 커널 주소 공간의 비문서화 구조체다. 사용자 모드에서 읽으려면
  커널 드라이버(`NtQueryVirtualMemory`의 일부 정보 포함)나 커널 디버깅이 필요하다.
- XMem은 **사용자 모드 연구 플랫폼**으로 한정한다(커널 드라이버/물리 메모리 접근 금지).
  따라서 VAD 트리를 직접 열거하지 않는다.

## 물리적 근사: VirtualQueryEx

- `VirtualQueryEx`는 커널이 VAD를 순회해 만든 결과를 `MEMORY_BASIC_INFORMATION`으로 돌려준다.
  실질적으로 VAD 기반 정보의 사용자 모드 투영이다.
- 차이점:
  - VAD 노드 하나가 여러 `MEMORY_BASIC_INFORMATION` 영역으로 나뉠 수 있다(보호 속성이 다른
    페이지 단위 분할, guard 페이지 경계 등).
  - `VirtualQueryEx`는 한 번에 주소 하나를 기준으로 다음 영역만 알려주므로, 전체 공간을
    보려면 루프가 필요하다(XMem: `xmem-windows::memory::walk_regions`).
  - `MEM_FREE` 영역도 영역으로 보고된다(VAD에는 없음).
- 파일 매핑 이름은 VAD에 있으나 `VirtualQueryEx`의 `Type`만으로는 알 수 없다. XMem은
  `GetMappedFileNameW`로 별도 조회한다.

## XMem에서의 활용

- `xmem memory map`은 `VirtualQueryEx` 기반 열거 결과를 그대로 보여준다. "VAD"라는 이름은
  쓰지 않는다(관찰 사실과 커널 구조를 혼동하지 않기 위해).
- 스냅샷의 `regions`와 Detection의 XMEM-001/003/005는 이 영역 모델을 기반으로 한다.
- 향후 VAD 수준 비교가 필요하면 커널 모듈(비목표) 또는 ETW/커널 디버거 연동이 필요하다.

## 한계

- VAD와 XMem 영역은 1:1 대응이 아니다. 영역 경계는 보호 속성 변화 기준이다.
- 보호 속성 변경(`VirtualProtectEx`)은 같은 VAD 안에서 `VirtualQueryEx` 결과만 바꾼다.
  Snapshot Diff는 영역 단위 변화로 이를 탐지한다.
- 대형 프로세스에서 영역 수가 많아(`MAX_REGIONS` 상한) 열거가 잘릴 수 있다.
