//! 프로세스 primitive와 메타데이터 조회.
use std::mem::size_of;

use windows::Wdk::System::SystemServices::VM_COUNTERS_EX;
use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation, ProcessVmCounters,
};
use windows::Win32::Foundation::{
    FILETIME, STATUS_INFO_LENGTH_MISMATCH, STILL_ACTIVE, UNICODE_STRING,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_UNKNOWN;
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetExitCodeProcess, GetProcessTimes, IsWow64Process2, OpenProcess,
    PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;
use xmem_core::{MemoryStats, ProcessArch, ProcessInfo, Result, XmemError};

use crate::error::{error_from_win32, last_win32_error};
use crate::handle::OwnedHandle;
use crate::toolhelp;

pub fn current_pid() -> u32 {
    // SAFETY: 인자 없는 쿼리 API이며 반환값은 항상 유효한 PID다.
    unsafe { GetCurrentProcessId() }
}

pub fn open_process(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<OwnedHandle> {
    // SAFETY: pid/access는 값 타입이고, 반환 핸들의 수명은 OwnedHandle이 관리한다.
    let handle = unsafe { OpenProcess(access, false, pid) };
    match handle {
        Ok(h) => OwnedHandle::new(h).ok_or(XmemError::InvalidHandle { handle: 0 }),
        Err(e) => Err(error_from_win32("OpenProcess", &e)),
    }
}

pub fn is_alive(handle: &OwnedHandle) -> Result<bool> {
    let mut code = 0u32;
    // SAFETY: handle은 OwnedHandle이 보장하는 유효 핸들이고 code는 유효 포인터다.
    unsafe { GetExitCodeProcess(handle.raw(), &mut code) }
        .map_err(|_| last_win32_error("GetExitCodeProcess"))?;
    Ok(code == STILL_ACTIVE.0 as u32)
}

/// QUERY_INFORMATION으로 열고, 거부되면 LIMITED로 재시도한다.
pub fn open_for_query(pid: u32) -> Result<OwnedHandle> {
    match open_process(
        pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION,
    ) {
        Ok(h) => Ok(h),
        Err(XmemError::AccessDenied { .. }) => open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION),
        Err(e) => Err(e),
    }
}

/// 메모리 읽기용 핸들(PROCESS_VM_READ 포함). VM_READ가 거부되면 AccessDenied.
pub fn open_for_read(pid: u32) -> Result<OwnedHandle> {
    open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
}

pub fn process_image_path(handle: &OwnedHandle) -> Result<String> {
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: handle은 유효하고 buf/len은 유효한 버퍼와 길이다.
    unsafe {
        QueryFullProcessImageNameW(
            handle.raw(),
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .map_err(|_| last_win32_error("QueryFullProcessImageNameW"))?;
    Ok(String::from_utf16_lossy(&buf[..len as usize]))
}

pub fn process_creation_time(handle: &OwnedHandle) -> Result<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: handle은 유효하고 네 포인터 모두 유효하다.
    unsafe {
        GetProcessTimes(
            handle.raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .map_err(|_| last_win32_error("GetProcessTimes"))?;
    Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
}

/// IMAGE_FILE_MACHINE 값을 XMem 아키텍처 분류로 매핑한다.
pub fn map_image_file_machine(machine: u16) -> ProcessArch {
    ProcessArch::from_machine(machine)
}

pub fn process_arch(handle: &OwnedHandle) -> Result<ProcessArch> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: handle은 유효하고 두 포인터 모두 유효하다.
    unsafe {
        IsWow64Process2(
            handle.raw(),
            &mut process_machine,
            Some(&mut native_machine),
        )
    }
    .map_err(|_| last_win32_error("IsWow64Process2"))?;
    let effective = if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        native_machine
    } else {
        process_machine
    };
    Ok(map_image_file_machine(effective.0))
}

pub fn session_id(pid: u32) -> Result<u32> {
    let mut session = 0u32;
    // SAFETY: 값 인자와 유효 포인터만 사용한다.
    unsafe { ProcessIdToSessionId(pid, &mut session) }
        .map_err(|_| last_win32_error("ProcessIdToSessionId"))?;
    Ok(session)
}

/// VM 카운터(NtQueryInformationProcess)를 우선 사용하고, 실패하면
/// GetProcessMemoryInfo로 fallback한다. fallback 경로에서는 VirtualSize를
/// 알 수 없어 0으로 둔다.
pub fn memory_counters(handle: &OwnedHandle) -> Result<MemoryStats> {
    if let Some(stats) = vm_counters(handle) {
        return Ok(stats);
    }
    get_process_memory_info(handle)
}

fn vm_counters(handle: &OwnedHandle) -> Option<MemoryStats> {
    let mut counters = VM_COUNTERS_EX::default();
    let mut len = 0u32;
    // SAFETY: handle은 유효하고 counters/len은 유효하다.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessVmCounters,
            &mut counters as *mut _ as *mut core::ffi::c_void,
            size_of::<VM_COUNTERS_EX>() as u32,
            &mut len,
        )
    };
    if status.0 < 0 {
        return None;
    }
    Some(MemoryStats {
        working_set: counters.WorkingSetSize as u64,
        private_bytes: counters.PrivateUsage as u64,
        commit: counters.PagefileUsage as u64,
        virtual_size: counters.VirtualSize as u64,
    })
}

fn get_process_memory_info(handle: &OwnedHandle) -> Result<MemoryStats> {
    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: handle은 유효하고 counters는 cb가 설정된 유효 버퍼다.
    unsafe {
        GetProcessMemoryInfo(
            handle.raw(),
            &mut counters as *mut _ as *mut _,
            size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
    }
    .map_err(|_| last_win32_error("GetProcessMemoryInfo"))?;
    Ok(MemoryStats {
        working_set: counters.WorkingSetSize as u64,
        private_bytes: counters.PrivateUsage as u64,
        commit: counters.PagefileUsage as u64,
        virtual_size: 0,
    })
}

/// NtQueryInformationProcess(ProcessCommandLineInformation)으로 명령줄을 읽는다.
pub fn process_command_line(handle: &OwnedHandle) -> Result<String> {
    let mut len = 0u32;
    // SAFETY: 길이 질의 호출(null 버퍼)이다.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    if status != STATUS_INFO_LENGTH_MISMATCH || len == 0 {
        return Err(XmemError::WindowsApi {
            api: "NtQueryInformationProcess(ProcessCommandLineInformation)",
            code: status.0 as u32,
            message: format!("unexpected NTSTATUS 0x{:08X}", status.0 as u32),
        });
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buf는 8바이트 정렬이고 len 이상의 바이트를 담는다.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.raw(),
            ProcessCommandLineInformation,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            (buf.len() * 8) as u32,
            &mut len,
        )
    };
    if status.0 < 0 {
        return Err(XmemError::WindowsApi {
            api: "NtQueryInformationProcess(ProcessCommandLineInformation)",
            code: status.0 as u32,
            message: format!("NTSTATUS 0x{:08X}", status.0 as u32),
        });
    }
    // SAFETY: 성공 시 buf 선두에 UNICODE_STRING 헤더가 기록되어 있다(8바이트 정렬).
    let us: &UNICODE_STRING = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
    read_unicode_string(us, buf.as_ptr() as usize, buf.len() * 8).ok_or(XmemError::WindowsApi {
        api: "NtQueryInformationProcess(ProcessCommandLineInformation)",
        code: 0,
        message: "UNICODE_STRING이 버퍼 범위를 벗어남".to_string(),
    })
}

/// 버퍼 [base, base+byte_len) 안을 가리키는 UNICODE_STRING만 안전하게 해석한다.
fn read_unicode_string(us: &UNICODE_STRING, base: usize, byte_len: usize) -> Option<String> {
    let start = us.Buffer.0 as usize;
    let len = us.Length as usize;
    if len == 0 {
        return Some(String::new());
    }
    if !len.is_multiple_of(2) || start < base {
        return None;
    }
    let offset = start - base;
    if offset + len > byte_len {
        return None;
    }
    // SAFETY: 위에서 [offset, offset+len)이 버퍼 범위 안임을 확인했다.
    let units =
        unsafe { std::slice::from_raw_parts((base as *const u16).add(offset / 2), len / 2) };
    Some(String::from_utf16_lossy(units))
}

/// 단일 프로세스의 메타데이터를 수집한다. 열거에 없으면 ProcessExited,
/// 열 수 없으면 AccessDenied를 돌려준다. 핸들이 열린 뒤의 개별 조회 실패는
/// None 필드로 degrade한다.
pub fn process_info(pid: u32) -> Result<ProcessInfo> {
    let raw = toolhelp::list_raw_processes()?
        .into_iter()
        .find(|e| e.pid == pid)
        .ok_or(XmemError::ProcessExited { pid })?;
    let handle = match open_for_query(pid) {
        Ok(h) => h,
        Err(XmemError::WindowsApi { code: 87, .. }) => {
            return Err(XmemError::ProcessExited { pid });
        }
        Err(e) => return Err(e),
    };
    Ok(ProcessInfo {
        pid,
        ppid: Some(raw.ppid),
        name: raw.name,
        image_path: process_image_path(&handle).ok(),
        arch: process_arch(&handle).unwrap_or(ProcessArch::Unknown),
        session_id: session_id(pid).ok(),
        creation_time: process_creation_time(&handle).ok(),
        command_line: process_command_line(&handle).ok(),
        user: crate::token::process_user(&handle).ok(),
        memory_stats: memory_counters(&handle).ok(),
        thread_count: Some(raw.thread_count),
        module_count: toolhelp::count_modules(pid).ok(),
    })
}

/// 시스템 전체 프로세스를 ProcessInfo로 열거한다. 개별 프로세스의
/// 메타데이터 조회 실패는 None 필드로 degrade하고 전체를 중단하지 않는다.
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    let mut raws = toolhelp::list_raw_processes()?;
    raws.sort_by_key(|e| e.pid);
    Ok(raws
        .into_iter()
        .map(|raw| {
            let mut info = ProcessInfo {
                pid: raw.pid,
                ppid: Some(raw.ppid),
                name: raw.name,
                image_path: None,
                arch: ProcessArch::Unknown,
                session_id: session_id(raw.pid).ok(),
                creation_time: None,
                command_line: None,
                user: None,
                memory_stats: None,
                thread_count: Some(raw.thread_count),
                module_count: None,
            };
            if let Ok(handle) = open_for_query(raw.pid) {
                info.image_path = process_image_path(&handle).ok();
                info.arch = process_arch(&handle).unwrap_or(ProcessArch::Unknown);
            }
            info
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_pid_is_nonzero() {
        assert_ne!(current_pid(), 0);
    }

    #[test]
    fn open_own_process_and_check_alive() {
        let handle = open_process(current_pid(), PROCESS_QUERY_LIMITED_INFORMATION)
            .expect("own process must open");
        assert!(is_alive(&handle).expect("GetExitCodeProcess must succeed"));
    }

    #[test]
    fn open_bogus_pid_fails_structured() {
        let err = match open_process(0xFFFF_FFFE, PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(_) => panic!("bogus pid must fail"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            xmem_core::XmemError::WindowsApi { .. } | xmem_core::XmemError::AccessDenied { .. }
        ));
    }

    #[test]
    fn image_path_of_self_ends_with_exe() {
        let handle = open_process(current_pid(), PROCESS_QUERY_LIMITED_INFORMATION).unwrap();
        let path = process_image_path(&handle).expect("own image path");
        assert!(
            path.to_lowercase().ends_with(".exe"),
            "unexpected path: {path}"
        );
    }

    #[test]
    fn arch_of_self_matches_build_target() {
        let handle = open_for_query(current_pid()).unwrap();
        let arch = process_arch(&handle).expect("IsWow64Process2");
        let expected = if cfg!(target_arch = "x86_64") {
            ProcessArch::X64
        } else if cfg!(target_arch = "x86") {
            ProcessArch::X86
        } else {
            ProcessArch::Unknown
        };
        assert_eq!(arch, expected);
    }

    #[test]
    fn map_machine_values() {
        assert_eq!(map_image_file_machine(34404), ProcessArch::X64);
        assert_eq!(map_image_file_machine(332), ProcessArch::X86);
        assert_eq!(map_image_file_machine(43620), ProcessArch::Arm64);
        assert_eq!(map_image_file_machine(0), ProcessArch::Unknown);
        assert_eq!(map_image_file_machine(0xFFFF), ProcessArch::Unknown);
    }

    #[test]
    fn session_id_of_self_succeeds() {
        session_id(current_pid()).expect("ProcessIdToSessionId must work for self");
    }

    #[test]
    fn memory_counters_of_self_nonzero() {
        let handle = open_for_query(current_pid()).unwrap();
        let stats = memory_counters(&handle).expect("memory counters");
        assert!(stats.working_set > 0);
    }

    #[test]
    fn creation_time_of_self_is_after_1970() {
        let handle = open_for_query(current_pid()).unwrap();
        let ft = process_creation_time(&handle).expect("GetProcessTimes");
        assert!(
            ft > 116_444_736_000_000_000,
            "FILETIME before unix epoch: {ft}"
        );
    }

    #[test]
    fn command_line_of_self_best_effort() {
        let handle = open_for_query(current_pid()).unwrap();
        if let Ok(cmd) = process_command_line(&handle) {
            assert!(
                cmd.to_lowercase().contains(".exe"),
                "unexpected cmdline: {cmd}"
            );
        }
    }

    #[test]
    fn read_unicode_string_bounds() {
        let text: Vec<u16> = "hello".encode_utf16().collect();
        let base = text.as_ptr() as usize;
        let us = UNICODE_STRING {
            Length: (text.len() * 2) as u16,
            MaximumLength: (text.len() * 2) as u16,
            Buffer: windows::core::PWSTR(text.as_ptr() as *mut u16),
        };
        assert_eq!(
            read_unicode_string(&us, base, text.len() * 2).as_deref(),
            Some("hello")
        );
        assert_eq!(read_unicode_string(&us, base + 4096, text.len() * 2), None);
        let odd = UNICODE_STRING { Length: 3, ..us };
        assert_eq!(read_unicode_string(&odd, base, text.len() * 2), None);
    }

    #[test]
    fn process_info_of_self_is_populated() {
        let pid = current_pid();
        let info = process_info(pid).expect("info of self");
        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty());
        assert!(
            info.image_path
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .ends_with(".exe")
        );
        assert!(info.ppid.is_some());
        assert!(info.thread_count.unwrap_or(0) >= 1);
        assert!(info.module_count.unwrap_or(0) >= 1);
        assert!(info.session_id.is_some());
        assert!(
            info.memory_stats
                .map(|m| m.working_set > 0)
                .unwrap_or(false)
        );
        assert!(info.creation_time.is_some());
        assert!(info.user.is_some());
    }

    #[test]
    fn process_info_bogus_pid_errs_structured() {
        let err = match process_info(0xFFFF_FFFE) {
            Ok(_) => panic!("bogus pid must fail"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            XmemError::AccessDenied { .. }
                | XmemError::WindowsApi { .. }
                | XmemError::ProcessExited { .. }
        ));
    }

    #[test]
    fn list_processes_is_sorted_and_contains_self() {
        let pid = current_pid();
        let list = list_processes().expect("list");
        assert!(
            list.windows(2).all(|w| w[0].pid <= w[1].pid),
            "must be pid-sorted"
        );
        assert!(list.iter().any(|p| p.pid == pid));
    }
}
