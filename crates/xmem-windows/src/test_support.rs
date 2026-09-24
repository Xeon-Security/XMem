//! 테스트 전용 동기화 도구.
//!
//! xmem-windows의 테스트는 자기 프로세스의 모듈·메모리·스레드를 그대로 관찰한다.
//! 어떤 테스트가 자기 프로세스의 상태를 바꾸면(예: MiniDumpWriteDump가 dbghelp.dll을
//! 로드하거나, selfmem/remotemem이 메모리를 할당/보호/해제하거나 스레드를 만들면),
//! 동시에 도는 다른 테스트의 스냅샷이 흔들려 간헐 실패가 난다. 자기 프로세스를 바꾸거나
//! 두 스냅샷을 비교하는 테스트는 `process_lock()`으로 직렬화한다.

use std::sync::{Mutex, MutexGuard, OnceLock};

/// 자기 프로세스를 바꾸거나 스냅샷을 비교하는 테스트를 직렬화한다.
pub(crate) fn process_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
