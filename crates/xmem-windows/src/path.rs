//! 장치 경로(`\Device\...`)를 드라이브 문자 경로로 정규화한다.

use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows::core::PCWSTR;

use crate::util::utf16_z_to_string;

/// `QueryDosDeviceW`로 드라이브 문자의 장치 경로(`\Device\HarddiskVolumeN`)를 조회한다.
/// 드라이브가 없거나 조회에 실패하면 None.
pub fn query_dos_device(drive: &str) -> Option<String> {
    let name: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
    let mut buf = [0u16; 1024];
    let len = unsafe { QueryDosDeviceW(PCWSTR(name.as_ptr()), Some(&mut buf)) };
    (len > 0).then(|| utf16_z_to_string(&buf))
}

/// `\Device\HarddiskVolumeN\...` → `C:\...` (볼륨 문자를 찾지 못하면 원본 유지)
pub fn normalize_device_path(path: &str) -> String {
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let Some(device) = query_dos_device(&drive) else {
            continue;
        };
        let matched = path
            .as_bytes()
            .get(..device.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(device.as_bytes()));
        // 같은 볼륨 번호의 상위 자릿수(Volume1 vs Volume10)를 오인하지 않도록
        // 경로 구분자 경계일 때만 변환한다.
        if matched {
            let rest = &path[device.len()..];
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{drive}{rest}");
            }
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system_drive_device_prefix() -> Option<String> {
        query_dos_device("C:")
    }

    #[test]
    fn normalize_replaces_system_drive_prefix() {
        let device = system_drive_device_prefix().expect("C: device prefix");
        let input = format!("{device}\\Windows\\System32\\ntdll.dll");
        let out = normalize_device_path(&input);
        assert!(out.to_ascii_uppercase().starts_with("C:\\"), "got {out}");
        assert!(out.ends_with("ntdll.dll"));
    }

    #[test]
    fn normalize_keeps_unmapped_paths() {
        assert_eq!(
            normalize_device_path("\\Device\\ImaginaryVolume\\x.dll"),
            "\\Device\\ImaginaryVolume\\x.dll"
        );
        assert_eq!(normalize_device_path("C:\\Windows"), "C:\\Windows");
    }

    #[test]
    fn normalize_is_case_insensitive() {
        let device = system_drive_device_prefix().unwrap();
        let upper = device.to_ascii_uppercase();
        assert!(
            normalize_device_path(&format!("{upper}\\x.dll"))
                .to_ascii_uppercase()
                .starts_with("C:\\")
        );
    }

    #[test]
    fn normalize_does_not_misread_longer_volume_number() {
        let device = system_drive_device_prefix().unwrap();
        let path = format!("{device}0\\x.dll");
        assert_eq!(normalize_device_path(&path), path);
    }

    #[test]
    fn normalize_handles_non_ascii_without_panic() {
        assert_eq!(
            normalize_device_path("\\Device\\볼륨\\x.dll"),
            "\\Device\\볼륨\\x.dll"
        );
    }
}
