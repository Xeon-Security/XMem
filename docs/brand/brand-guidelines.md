# XMem — 로고 사용 가이드 (compact)

> 상태: 최종(Axis Map, 2026-09-30). 마스터 파일은 저장소 `docs/brand/`.

## 1. 로고
- **아이디어**: 왼쪽 주소 축에 영역들이 길이별로 붙은 메모리 맵 — 정밀한 계측기의 태도.
- **버전**: 기본 심볼(4영역) · 소형 심볼(3영역) · 가로 락업 · 세로 락업 · 워드마크 · 앱 아이콘(타일)
- **파일**: `docs/brand/` — `xmem-symbol.svg`(4영역) / `xmem-symbol-small.svg`(3영역, 16–32px용) / `xmem-horizontal-black|white.svg` / `xmem-stacked-black|white.svg` / `xmem-app-icon.svg` · `xmem-app-icon-accent.svg` / `xmem-favicon-source.svg` / favicon·웹아이콘 세트 / `brand-guidelines.md`. 화면은 RGB 기준.

## 2. 클리어 스페이스
- 로고 둘레에 **막대 하나 높이(심볼 높이의 약 1/5)** 이상 여백을 둔다. 여백은 로고 크기에 비례해 함께 확대한다.

## 3. 최소 크기
| 버전 | 화면 | 인쇄 |
|---|---|---|
| 가로 락업 | 96 px 너비 | 25 mm |
| 세로 락업 | 72 px 너비 | 20 mm |
| 심볼(4영역) | 24 px | 7 mm |
| 소형 심볼(3영역) | 16 px | 5 mm |
| 앱 아이콘(타일) | 16 px | 5 mm |

## 4. 색
| 이름 | HEX | RGB | CMYK | 참고 |
|---|---|---|---|---|
| 그래파이트 | #1B1D20 | 27 / 29 / 32 | 15 / 9 / 0 / 88 | GUI 다크 패널색과 동일 (Pantone Black 6 C 근사) |
| 어센트 | #4C8DFF | 76 / 141 / 255 | 70 / 45 / 0 / 0 | GUI accent — 가장 짧은 막대에만 (Pantone 2727 C 근사) |
| 페이퍼 | #FFFFFF | 255 / 255 / 255 | 0 / 0 / 0 / 0 | |

**승인 조합**: 그래파이트 on 흰색 · 흰색 on 그래파이트 · 단색 검정/흰색(반전) · 타일 위 흰 심볼(+어센트 한 막대).
사진 위에는 차분한 영역에 흰/검정 버전을, 복잡한 배경에는 타일 버전을 쓴다.

## 5. 타이포그래피
- 워드마크: 리뷰본은 Segoe UI Semibold(락업 SVG). 배포·인쇄용은 Inter / IBM Plex Sans SemiBold 등 OFL 폰트로 아웃라인 제작 권장.
- 웹 폴백 스택: `system-ui, "Segoe UI", "Malgun Gothic", sans-serif`
- 라이선스: Microsoft 폰트는 재배포 불가 — 아웃라인 파일을 만들 때는 OFL 폰트를 사용한다.

## 6. 금지
늘리거나 눌러 변형 금지 · 팔레트 밖 색 금지 · 회전 금지 · 그림자/외곽선/그라데이션 금지 · **축·막대의 순서와 길이 임의 변경 금지(이 비율이 정체성)** · 막대를 축에서 떼거나 재배열 금지 · 어센트를 두 곳 이상 사용 금지 · 어두운/사진 배경에 컨테이너 없이 그래파이트 버전 사용 금지 · 워드마크를 타이핑으로 재현 금지.

## 7. 문의
- kalpha — dev@kalpha.kr · 마스터 파일: 저장소 `docs/brand/`
