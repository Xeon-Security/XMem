# Contributing

XMem 개발 규칙. 모든 기여는 아래 게이트를 통과해야 한다.

## Build / Lint / Test

```powershell
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

- `cargo fmt` 없이 커밋하지 않는다.
- clippy warning은 이유 없이 무시하지 않는다(`-D warnings` 게이트).
- `cargo check`는 `#[cfg(test)]`를 컴파일하지 않는다. 테스트 코드의 red 확인은 `cargo check -p <crate> --tests`를 사용한다.

## Commit 규칙

- Conventional prefix 사용: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`.
- 한 커밋 = 한 논리적 변경. 크레이트 단위로 스테이징한다.
- 커밋 메시지는 한국어 또는 영어 모두 가능하나 일관성을 유지한다.

## Rust / unsafe 규칙

- `unsafe`는 **`xmem-windows` 크레이트에만** 허용된다(workspace lint `unsafe_code = "deny"` + 해당 크레이트 `allow`).
  - 사용 이유를 명시하고, 포인터·크기를 검증하며, Win32 반환값을 확인하고, RAII로 lifetime을 관리한다.
- `forbid` 대신 `deny`를 사용한다(크레이트 내부 예외 허용 목적).
- Runtime path에서 `unwrap()` / `expect()` 금지. 불변조건이 보장된 경우에만 사용한다.
  - 테스트 코드는 `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]`로 예외.
- Windows API 시그니처를 추측하지 않는다. rustdoc 또는 `windows` crate 소스로 검증한 뒤 구현한다.

## Error Model 규칙

- 라이브러리 크레이트는 구조화된 `xmem_core::XmemError`를 사용한다.
- `anyhow`는 `xmem-cli` / `xmem-experiments` 경계에서만 사용한다.
- 오류는 원인과 context를 포함해야 한다("Something went wrong" 금지).

## 문서 규칙

- 검증되지 않은 내용을 사실처럼 쓰지 않는다.
- Detection은 **Observed Fact → Evidence → Heuristic → Confidence → Interpretation** 구조를 유지한다.
- 구현되지 않은 기능을 구현된 것처럼 쓰지 않는다(README Status 표 갱신 필수).
- 관찰된 사실과 해석(Heuristic)을 혼동하지 않는다.

## 안정성 / 자원 규칙

- 분석 명령은 기본적으로 **read-only**다. 대상 프로세스 상태 변경은 Experiment로만 수행한다.
- Memory Scan은 chunked/bounded buffer를 사용한다. 전체 메모리를 한 번에 올리지 않는다.
- Worker 수는 제한한다(`min(논리 CPU - 1, 4)` 기본).
- 실험은 XMem이 spawn한 전용 Test Target에만 수행한다. 임의 PID에 대한 상태 변경 금지.
- 보호 프로세스(`xmem-core::guard`)에 대한 상태 변경은 거부한다(exit code 3).

## TDD

- 기능 구현은 실패하는 테스트 → 실패 확인 → 최소 구현 → 통과 → 커밋 순서를 따른다.
- Milestone 완료 판정: `cargo fmt/check/test/clippy` 전부 성공 + 실제 Windows 동작 검증.
