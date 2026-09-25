//! 자기 프로세스 미니덤프 생성 통합 테스트.
//!
//! MiniDumpWriteDump는 덤프 중 프로세스의 스레드를 일시 중단하고 로더/모듈 정보를
//! 읽는다. 단위 테스트 바이너리에서 다른 테스트들과 병렬로 실행하면 로더 락 경합으로
//! 멈출 수 있어(간헐적 데드락) 별도 프로세스에서 단독으로 실행한다.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use xmem_windows::{current_pid, open_for_dump, validate_minidump, write_minidump_file};

#[test]
fn write_minidump_file_of_self_is_valid() {
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
