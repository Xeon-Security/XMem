use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::core::HSTRING;
use xmem_core::Result;

use crate::error::error_from_win32;

/// 경로가 속한 볼륨의 가용 바이트. `path`는 디렉터리 경로를 권장한다.
pub fn free_space_bytes(path: &str) -> Result<u64> {
    let dir = HSTRING::from(path);
    let mut free: u64 = 0;
    unsafe { GetDiskFreeSpaceExW(&dir, None, None, Some(&mut free)) }
        .map_err(|error| error_from_win32("GetDiskFreeSpaceExW", &error))?;
    Ok(free)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::XmemError;

    #[test]
    fn free_space_of_temp_dir_is_positive() {
        let dir = std::env::temp_dir().to_string_lossy().into_owned();
        let free = free_space_bytes(&dir).unwrap();
        assert!(free > 0);
    }

    #[test]
    fn free_space_of_invalid_path_fails_structured() {
        let err = free_space_bytes("").unwrap_err();
        assert!(matches!(
            err,
            XmemError::WindowsApi { .. } | XmemError::AccessDenied { .. }
        ));
    }
}
