//! RAII HANDLE. Drop에서 정확히 한 번 CloseHandle 한다.
use windows::Win32::Foundation::{CloseHandle, HANDLE};

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// null / INVALID_HANDLE_VALUE(-1)는 소유하지 않는다(None).
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_invalid() {
            None
        } else {
            Some(Self(handle))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// 소유권을 포기하고 raw handle을 반환한다. CloseHandle은 호출하지 않는다.
    pub fn into_raw(self) -> HANDLE {
        let raw = self.0;
        std::mem::forget(self);
        raw
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: new()가 null/invalid를 배제했고, 소유권은 이 구조체에만 있다.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

    #[test]
    fn rejects_null_and_invalid_handles() {
        assert!(OwnedHandle::new(HANDLE::default()).is_none());
        assert!(OwnedHandle::new(INVALID_HANDLE_VALUE).is_none());
    }

    #[test]
    fn open_and_drop_own_process_handle() {
        let handle = crate::process::open_process(
            crate::process::current_pid(),
            windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
        )
        .expect("own process must open");
        assert!(!handle.raw().is_invalid());
    } // drop → CloseHandle

    #[test]
    fn into_raw_keeps_handle_open() {
        let handle = crate::process::open_process(
            crate::process::current_pid(),
            windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
        )
        .expect("own process must open");
        let raw = handle.into_raw();
        assert!(!raw.is_invalid());
        // SAFETY: 테스트에서 소유권을 회수해 직접 닫는다.
        let _ = unsafe { CloseHandle(raw) };
    }
}
