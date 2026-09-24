//! MiniDumpWriteDump 기반 덤프 파일 생성.

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::GENERIC_WRITE;
use windows::Win32::Storage::FileSystem::{
    CREATE_ALWAYS, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows::Win32::System::Diagnostics::Debug::{
    MINIDUMP_TYPE, MiniDumpNormal, MiniDumpWithFullMemory, MiniDumpWithFullMemoryInfo,
    MiniDumpWriteDump,
};
use windows::core::HSTRING;
use xmem_core::{Result, XmemError};

use crate::error::error_from_win32;
use crate::handle::OwnedHandle;

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
    let dump_type: MINIDUMP_TYPE = if full {
        MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo
    } else {
        MiniDumpNormal | MiniDumpWithFullMemoryInfo
    };
    // SAFETY: process/file은 유효한 OwnedHandle이고 나머지 인자는 None이다.
    unsafe { MiniDumpWriteDump(process.raw(), pid, file.raw(), dump_type, None, None, None) }
        .map_err(|e| error_from_win32("MiniDumpWriteDump", &e))
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
    let temp = temp_path(path, pid);
    let result = (|| -> Result<u64> {
        let file = create_file_for_write(&temp.to_string_lossy())?;
        write_minidump(process, pid, &file, full)?;
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
    use crate::process::{current_pid, open_for_dump};

    #[test]
    fn write_minidump_file_of_self_is_valid() {
        // MiniDumpWriteDump는 덤프 중 프로세스의 모듈/메모리/스레드가 바뀌면 실패할 수 있다.
        // 자기 프로세스를 바꾸는 다른 테스트와 직렬화한다.
        let _guard = crate::test_support::process_lock();
        let dir = std::env::temp_dir().join(format!("xmem-dump-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("self.dmp");
        let pid = current_pid();
        let handle = open_for_dump(pid).unwrap();

        let size = write_minidump_file(&handle, pid, &path, false).unwrap();
        assert!(size > 0);
        validate_minidump(&path).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp 파일이 남았다");

        let _ = std::fs::remove_dir_all(&dir);
    }

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
