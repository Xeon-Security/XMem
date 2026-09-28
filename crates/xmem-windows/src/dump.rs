//! MiniDumpWriteDump 기반 덤프 파일 생성.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE, S_FALSE, S_OK, TRUE};
use windows::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Diagnostics::Debug::{
    IoFinishCallback, IoStartCallback, IoWriteAllCallback, MINIDUMP_CALLBACK_INFORMATION,
    MINIDUMP_CALLBACK_INPUT, MINIDUMP_CALLBACK_OUTPUT, MINIDUMP_TYPE, MiniDumpNormal,
    MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo, MiniDumpWriteDump,
};
use windows::core::{BOOL, HSTRING};
use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;

/// 미니덤프 진행 상황. Windows가 호출하는 `IoWriteAllCallback`이 기록한
/// 최대 파일 오프셋(=기록 완료 바이트)을 추적한다.
#[derive(Debug, Default)]
pub struct DumpProgress {
    bytes_written: AtomicU64,
    estimated_total: AtomicU64,
    /// 콜백 I/O에서 마지막으로 실패한 Win32 오류 코드(0 = 없음).
    write_error: AtomicU32,
}

impl DumpProgress {
    /// `estimated_total`은 호출자가 아는 예상 크기(프로세스 commit 등). 0이면 미상.
    pub fn new(estimated_total: u64) -> Self {
        Self {
            bytes_written: AtomicU64::new(0),
            estimated_total: AtomicU64::new(estimated_total),
            write_error: AtomicU32::new(0),
        }
    }

    /// 기록 완료한 바이트 수(최대 오프셋).
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// 호출자가 준 예상 크기. 0이면 미상.
    pub fn estimated_total(&self) -> u64 {
        self.estimated_total.load(Ordering::Relaxed)
    }

    /// 진행률 0.0~1.0. 예상 크기가 0이면 None(indeterminate).
    pub fn fraction(&self) -> Option<f32> {
        let total = self.estimated_total();
        if total == 0 {
            None
        } else {
            Some((self.bytes_written() as f32 / total as f32).min(1.0))
        }
    }

    fn observe_write_end(&self, end_offset: u64) {
        self.bytes_written.fetch_max(end_offset, Ordering::Relaxed);
    }

    fn observe_write_error(&self, code: u32) {
        self.write_error.store(code, Ordering::Relaxed);
    }

    /// 콜백이 남긴 쓰기 오류를 꺼낸다(있으면 0이 아님).
    fn take_write_error(&self) -> Option<u32> {
        match self.write_error.swap(0, Ordering::Relaxed) {
            0 => None,
            code => Some(code),
        }
    }
}

/// 지정 오프셋에 바이트를 전부 쓴다. 실패는 Win32 오류 코드로 돌려준다.
///
/// SAFETY: `handle`은 유효한 파일 핸들이고 `buffer`/`len`은 콜백이 준
/// 유효한 버퍼다(호출부에서 널/0 검사). `BorrowedHandle`로 만든 `File`은
/// 핸들을 소유하지 않으므로 drop 시 닫히지 않는다.
unsafe fn write_all_at(
    handle: HANDLE,
    offset: u64,
    buffer: *mut core::ffi::c_void,
    len: u32,
) -> std::result::Result<(), u32> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::windows::io::{FromRawHandle, RawHandle};

    let bytes: &[u8] = if buffer.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(buffer as *const u8, len as usize) }
    };
    let mut file = std::mem::ManuallyDrop::new(unsafe {
        std::fs::File::from_raw_handle(handle.0 as RawHandle)
    });
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.write_all(bytes))
        .map_err(|e| e.raw_os_error().unwrap_or(0) as u32)
}

/// MiniDumpWriteDump 진행 콜백.
///
/// Windows가 덤프 도중 직접 호출하므로 **절대 패닉하면 안 된다** — 널 포인터는
/// 무시하고, 어떤 실패가 있어도 TRUE를 반환해 덤프를 계속 진행시킨다(여기서
/// 예외가 나가면 덤프 전체가 실패한다). 다만 IoWriteAllCallback은 dbghelp의
/// 쓰기를 대신 수행하는 자리라, 실패는 `write_error`에 남기고 호출자가
/// MiniDumpWriteDump 반환 후 오류로 바꾼다.
unsafe extern "system" fn minidump_progress_callback(
    callback_param: *mut core::ffi::c_void,
    input: *const MINIDUMP_CALLBACK_INPUT,
    output: *mut MINIDUMP_CALLBACK_OUTPUT,
) -> BOOL {
    if callback_param.is_null() || input.is_null() || output.is_null() {
        return TRUE;
    }
    let progress = unsafe { &*(callback_param as *const DumpProgress) };
    let callback_type = unsafe { (*input).CallbackType };
    if callback_type == IoStartCallback.0 as u32 {
        // Status=S_FALSE가 "파일 I/O를 콜백으로 넘긴다"는 신호다.
        unsafe { (*output).Anonymous.Status = S_FALSE };
    } else if callback_type == IoWriteAllCallback.0 as u32 {
        let io = unsafe { (*input).Anonymous.Io };
        match unsafe { write_all_at(io.Handle, io.Offset, io.Buffer, io.BufferBytes) } {
            Ok(()) => {
                progress.observe_write_end(io.Offset.saturating_add(io.BufferBytes as u64));
                unsafe { (*output).Anonymous.Status = S_OK };
            }
            Err(code) => progress.observe_write_error(code),
        }
    } else if callback_type == IoFinishCallback.0 as u32 {
        unsafe { (*output).Anonymous.Status = S_OK };
    }
    TRUE
}

/// 쓰기용 파일 핸들 생성(없으면 만들고, 있으면 덮어쓴다).
pub fn create_file_for_write(path: &str) -> Result<OwnedHandle> {
    let wide = HSTRING::from(path);
    let handle = unsafe {
        CreateFileW(
            &wide,
            GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| error_from_win32("CreateFileW", &e))?;
    OwnedHandle::new(handle).ok_or(XmemError::InvalidHandle { handle: 0 })
}

/// MiniDumpWriteDump 호출. `full`이면 전체 메모리를 포함한다.
pub fn write_minidump(
    process: &OwnedHandle,
    pid: u32,
    file: &OwnedHandle,
    full: bool,
) -> Result<()> {
    write_minidump_inner(process, pid, file, full, None)
}

fn write_minidump_inner(
    process: &OwnedHandle,
    pid: u32,
    file: &OwnedHandle,
    full: bool,
    progress: Option<&DumpProgress>,
) -> Result<()> {
    let dump_type: MINIDUMP_TYPE = if full {
        MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo
    } else {
        MiniDumpNormal | MiniDumpWithFullMemoryInfo
    };
    let callback = progress.map(|progress| MINIDUMP_CALLBACK_INFORMATION {
        CallbackRoutine: Some(minidump_progress_callback),
        CallbackParam: progress as *const DumpProgress as *mut core::ffi::c_void,
    });
    // SAFETY: process/file은 유효한 OwnedHandle이다. callback은 이 동기 호출
    // 동안만 살아 있고, CallbackParam은 같은 수명의 DumpProgress를 가리킨다.
    unsafe {
        MiniDumpWriteDump(
            process.raw(),
            pid,
            file.raw(),
            dump_type,
            None,
            None,
            callback
                .as_ref()
                .map(|c| c as *const MINIDUMP_CALLBACK_INFORMATION),
        )
    }
    .map_err(|e| error_from_win32("MiniDumpWriteDump", &e))?;
    // 콜백 I/O에서 실패한 쓰기가 있으면(항상 TRUE를 반환했으므로) 여기서 오류로 만든다.
    if let Some(progress) = progress
        && let Some(code) = progress.take_write_error()
    {
        return Err(XmemError::DumpError {
            reason: format!("minidump 콜백 쓰기 실패: Win32 오류 {code}"),
        });
    }
    Ok(())
}

/// minidump 시그니처("MDMP")를 확인한다.
pub fn validate_minidump(path: &Path) -> Result<()> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(XmemError::Io)?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map_err(|e| XmemError::DumpError {
            reason: format!("dump 헤더 읽기 실패: {} ({e})", path.display()),
        })?;
    if &magic != b"MDMP" {
        return Err(XmemError::DumpError {
            reason: format!("minidump 시그니처가 아님: {}", path.display()),
        });
    }
    Ok(())
}

fn temp_path(path: &Path, pid: u32) -> PathBuf {
    PathBuf::from(format!("{}.tmp-{}", path.display(), pid))
}

/// temp 파일에 덤프를 쓰고 시그니처 검증 후 atomic rename. 생성된 파일 크기를 반환한다.
pub fn write_minidump_file(
    process: &OwnedHandle,
    pid: u32,
    path: &Path,
    full: bool,
) -> Result<u64> {
    write_minidump_file_inner(process, pid, path, full, None)
}

/// `write_minidump_file`과 같고, 진행 콜백으로 기록 바이트를 `progress`에 남긴다.
pub fn write_minidump_file_with_progress(
    process: &OwnedHandle,
    pid: u32,
    path: &Path,
    full: bool,
    progress: &DumpProgress,
) -> Result<u64> {
    write_minidump_file_inner(process, pid, path, full, Some(progress))
}

fn write_minidump_file_inner(
    process: &OwnedHandle,
    pid: u32,
    path: &Path,
    full: bool,
    progress: Option<&DumpProgress>,
) -> Result<u64> {
    let temp = temp_path(path, pid);
    let result = (|| -> Result<u64> {
        let file = create_file_for_write(&temp.to_string_lossy())?;
        write_minidump_inner(process, pid, &file, full, progress)?;
        drop(file);
        validate_minidump(&temp)?;
        std::fs::rename(&temp, path).map_err(|e| XmemError::DumpError {
            reason: format!("dump rename 실패: {} ({e})", path.display()),
        })?;
        let size = std::fs::metadata(path).map_err(XmemError::Io)?.len();
        Ok(size)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_minidump_rejects_non_dump() {
        let dir = std::env::temp_dir().join(format!("xmem-dump-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("garbage.dmp");
        std::fs::write(&path, b"not a minidump").unwrap();

        let err = validate_minidump(&path).unwrap_err();
        assert!(matches!(err, XmemError::DumpError { .. }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
