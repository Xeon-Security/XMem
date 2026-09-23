//! Toolhelp32 스레드 열거와 스레드 쿼리(read-only) + 원격 스레드 생성(lab target 전용).

use std::ffi::c_void;
use std::mem::size_of;

use windows::Wdk::System::Threading::{NtQueryInformationThread, ThreadQuerySetWin32StartAddress};
use windows::Win32::System::Diagnostics::ToolHelp::{
    TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetThreadPriority, GetThreadTimes, LPTHREAD_START_ROUTINE, OpenThread,
    THREAD_ACCESS_RIGHTS, THREAD_CREATE_SUSPENDED, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION,
};

use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;
use crate::toolhelp::{is_no_more_files, snapshot};

/// 열거 시점의 최소 스레드 정보.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawThreadEntry {
    pub tid: u32,
    pub pid: u32,
    pub base_priority: i32,
}

/// 대상 프로세스 소유 스레드만 열거한다. TH32CS_SNAPTHREAD는 시스템 전체 스냅샷이다.
pub fn list_raw_threads(pid: u32) -> Result<Vec<RawThreadEntry>> {
    let snap = snapshot(TH32CS_SNAPTHREAD, 0)?;
    let mut entry = THREADENTRY32 {
        dwSize: size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut threads = Vec::new();
    // SAFETY: snap은 유효한 스냅샷 핸들이고 entry는 유효한 포인터다.
    match unsafe { Thread32First(snap.raw(), &mut entry) } {
        Ok(()) => {}
        Err(e) if is_no_more_files(&e) => return Ok(threads),
        Err(e) => return Err(error_from_win32("Thread32First", &e)),
    }
    loop {
        if entry.th32OwnerProcessID == pid {
            threads.push(RawThreadEntry {
                tid: entry.th32ThreadID,
                pid: entry.th32OwnerProcessID,
                base_priority: entry.tpBasePri,
            });
        }
        // SAFETY: 위와 동일한 유효 핸들/포인터다.
        match unsafe { Thread32Next(snap.raw(), &mut entry) } {
            Ok(()) => {}
            Err(e) if is_no_more_files(&e) => break,
            Err(e) => return Err(error_from_win32("Thread32Next", &e)),
        }
    }
    Ok(threads)
}

/// 스레드 핸들. 접근이 거부되면 AccessDenied.
pub fn open_thread(tid: u32, access: THREAD_ACCESS_RIGHTS) -> Result<OwnedHandle> {
    // SAFETY: tid는 값 타입이고 반환 핸들의 수명은 OwnedHandle이 관리한다.
    match unsafe { OpenThread(access, false, tid) } {
        Ok(handle) => OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(e) => Err(error_from_win32("OpenThread", &e)),
    }
}

/// 쿼리용 스레드 핸들. QUERY_INFORMATION 실패 시 LIMITED로 재시도한다.
pub fn open_thread_for_query(tid: u32) -> Result<OwnedHandle> {
    match open_thread(tid, THREAD_QUERY_INFORMATION) {
        Ok(handle) => Ok(handle),
        Err(XmemError::AccessDenied { .. }) => open_thread(tid, THREAD_QUERY_LIMITED_INFORMATION),
        Err(e) => Err(e),
    }
}

/// 동적 우선순위. 조회 실패값(i32::MAX)은 None.
pub fn thread_priority(handle: &OwnedHandle) -> Option<i32> {
    // SAFETY: handle은 OwnedHandle이 소유한 유효 핸들이다.
    let value = unsafe { GetThreadPriority(handle.raw()) };
    (value != i32::MAX).then_some(value)
}

/// 스레드 시작 주소(ThreadQuerySetWin32StartAddress). best-effort.
pub fn thread_start_address(handle: &OwnedHandle) -> Option<u64> {
    let mut address: u64 = 0;
    // SAFETY: handle은 유효하고 address는 8바이트 출력 버퍼다.
    let status = unsafe {
        NtQueryInformationThread(
            handle.raw(),
            ThreadQuerySetWin32StartAddress,
            (&mut address as *mut u64).cast::<c_void>(),
            size_of::<u64>() as u32,
            std::ptr::null_mut(),
        )
    };
    (status.0 >= 0).then_some(address)
}

/// 대상 프로세스에 원격 스레드를 생성한다(lab target 전용). suspended면 시작하지 않는다.
pub fn create_remote_thread(
    process: &OwnedHandle,
    start_address: u64,
    suspended: bool,
) -> Result<OwnedHandle> {
    // SAFETY: start_address는 대상 프로세스의 실행 가능한 주소여야 한다(호출자 계약).
    let start: LPTHREAD_START_ROUTINE = unsafe { std::mem::transmute(start_address) };
    let flags = if suspended {
        THREAD_CREATE_SUSPENDED.0
    } else {
        0
    };
    // SAFETY: process는 유효한 핸들이며 start는 실행 가능한 원격 주소다.
    let handle = unsafe { CreateRemoteThread(process.raw(), None, 0, start, None, flags, None) }
        .map_err(|e| error_from_win32("CreateRemoteThread", &e))?;
    OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 })
}

/// GetThreadTimes로 얻은 스레드 시간(FILETIME 100ns 단위).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadTimes {
    pub creation: u64,
    pub exit: u64,
    pub kernel_100ns: u64,
    pub user_100ns: u64,
}

fn filetime_to_u64(time: windows::Win32::Foundation::FILETIME) -> u64 {
    ((time.dwHighDateTime as u64) << 32) | time.dwLowDateTime as u64
}

/// 스레드 생성/종료 시각과 kernel/user 시간을 조회한다.
pub fn thread_times(thread: &OwnedHandle) -> Result<ThreadTimes> {
    let mut creation = windows::Win32::Foundation::FILETIME::default();
    let mut exit = windows::Win32::Foundation::FILETIME::default();
    let mut kernel = windows::Win32::Foundation::FILETIME::default();
    let mut user = windows::Win32::Foundation::FILETIME::default();
    // SAFETY: thread는 유효한 핸들이고 네 FILETIME 모두 유효한 포인터다.
    unsafe {
        GetThreadTimes(
            thread.raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|e| error_from_win32("GetThreadTimes", &e))?;
    Ok(ThreadTimes {
        creation: filetime_to_u64(creation),
        exit: filetime_to_u64(exit),
        kernel_100ns: filetime_to_u64(kernel),
        user_100ns: filetime_to_u64(user),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentThreadId;

    #[test]
    fn list_raw_threads_of_self_is_populated() {
        let pid = crate::process::current_pid();
        let threads = list_raw_threads(pid).unwrap();
        assert!(!threads.is_empty());
        assert!(threads.iter().all(|t| t.pid == pid && t.tid != 0));
    }

    #[test]
    fn open_thread_and_query_priority_and_start_address() {
        let tid = unsafe { GetCurrentThreadId() };
        let handle = open_thread_for_query(tid).unwrap();
        assert!(thread_priority(&handle).is_some());
        assert!(thread_start_address(&handle).is_some());
    }

    #[test]
    fn thread_times_of_current_thread_are_reported() {
        let tid = unsafe { GetCurrentThreadId() };
        let handle = open_thread_for_query(tid).unwrap();
        let times = thread_times(&handle).unwrap();
        assert!(times.creation > 0);
        assert_eq!(times.exit, 0, "실행 중 스레드의 exit time은 0이어야 합니다");
        // 스레드 CPU 시간은 시스템 타이머 틱(기본 ~15.6ms) 단위로 갱신되므로
        // 갓 시작한 테스트 스레드는 0으로 보일 수 있다. 틱이 오를 때까지 짧게 소비한다.
        let mut total = times.user_100ns + times.kernel_100ns;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while total == 0 && std::time::Instant::now() < deadline {
            let mut spin: u64 = 0;
            for i in 0..200_000u64 {
                spin = spin.wrapping_add(i);
            }
            std::hint::black_box(spin);
            let ticked = thread_times(&handle).unwrap();
            total = ticked.user_100ns + ticked.kernel_100ns;
        }
        assert!(total > 0, "스레드 CPU 시간이 2초 안에 갱신되지 않았습니다");
    }

    #[test]
    fn open_thread_bogus_tid_fails_structured() {
        let err = open_thread(0xFFFF_FFFE, THREAD_QUERY_LIMITED_INFORMATION).unwrap_err();
        assert!(
            matches!(
                err,
                XmemError::AccessDenied { .. }
                    | XmemError::InvalidHandle { .. }
                    | XmemError::WindowsApi { .. }
            ),
            "예상 밖 오류: {err:?}"
        );
    }
}
