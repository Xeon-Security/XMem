//! Toolhelp32 스냅샷 기반 열거(read-only).

use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW,
    CREATE_TOOLHELP_SNAPSHOT_FLAGS, MODULEENTRY32W, PROCESSENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use xmem_core::{Result, XmemError};

use crate::error::{error_from_win32, win32_code_from_hresult};
use crate::handle::OwnedHandle;
use crate::util::utf16_z_to_string;

/// 열거 시점의 최소 프로세스 정보.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub thread_count: u32,
}

fn snapshot(flags: CREATE_TOOLHELP_SNAPSHOT_FLAGS, pid: u32) -> Result<OwnedHandle> {
    // SAFETY: flags/pid는 값 타입이고 반환 핸들의 수명은 OwnedHandle이 관리한다.
    let handle = unsafe { CreateToolhelp32Snapshot(flags, pid) };
    match handle {
        Ok(h) => OwnedHandle::new(h).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(e) => Err(error_from_win32("CreateToolhelp32Snapshot", &e)),
    }
}

fn is_no_more_files(err: &windows::core::Error) -> bool {
    win32_code_from_hresult(err.code().0) == ERROR_NO_MORE_FILES.0
}

/// 시스템 전체 프로세스를 열거한다. ERROR_NO_MORE_FILES는 정상 종료다.
pub fn list_raw_processes() -> Result<Vec<RawProcessEntry>> {
    let snap = snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: snap은 유효한 스냅샷 핸들이고 entry는 유효한 포인터다.
    match unsafe { Process32FirstW(snap.raw(), &mut entry) } {
        Ok(()) => {}
        Err(e) if is_no_more_files(&e) => return Ok(out),
        Err(e) => return Err(error_from_win32("Process32FirstW", &e)),
    }
    loop {
        out.push(RawProcessEntry {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name: utf16_z_to_string(&entry.szExeFile),
            thread_count: entry.cntThreads,
        });
        // SAFETY: 위와 동일한 유효 핸들/포인터다.
        match unsafe { Process32NextW(snap.raw(), &mut entry) } {
            Ok(()) => {}
            Err(e) if is_no_more_files(&e) => break,
            Err(e) => return Err(error_from_win32("Process32NextW", &e)),
        }
    }
    Ok(out)
}

/// 대상 프로세스의 로드된 모듈 수를 센다. 32-bit 프로세스도 조회되도록
/// TH32CS_SNAPMODULE32를 함께 요청한다.
pub fn count_modules(pid: u32) -> Result<u32> {
    let snap = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)?;
    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: snap은 유효한 스냅샷 핸들이고 entry는 유효한 포인터다.
    match unsafe { Module32FirstW(snap.raw(), &mut entry) } {
        Ok(()) => {}
        Err(e) if is_no_more_files(&e) => return Ok(0),
        Err(e) => return Err(error_from_win32("Module32FirstW", &e)),
    }
    let mut count = 1u32;
    loop {
        // SAFETY: 위와 동일하다.
        match unsafe { Module32NextW(snap.raw(), &mut entry) } {
            Ok(()) => count += 1,
            Err(e) if is_no_more_files(&e) => break,
            Err(e) => return Err(error_from_win32("Module32NextW", &e)),
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::current_pid;

    #[test]
    fn enumeration_contains_current_process() {
        let pid = current_pid();
        let procs = list_raw_processes().expect("snapshot must succeed");
        assert!(procs.len() > 1, "system must have multiple processes");
        let me = procs.iter().find(|p| p.pid == pid).expect("self must appear");
        assert!(!me.name.is_empty());
        assert!(me.thread_count >= 1);
    }

    #[test]
    fn enumeration_terminates_cleanly() {
        let first = list_raw_processes().expect("first enumeration");
        let second = list_raw_processes().expect("second enumeration");
        assert!(!first.is_empty() && !second.is_empty());
    }

    #[test]
    fn count_modules_of_self_at_least_one() {
        let count = count_modules(current_pid()).expect("module snapshot of self");
        assert!(count >= 1);
    }
}
