//! 진행 콜백을 쓰는 자기 프로세스 미니덤프 생성 통합 테스트.
//!
//! minidump_self.rs와 같은 이유로 별도 프로세스에서 단독으로 실행한다 —
//! MiniDumpWriteDump는 덤프 중 프로세스의 스레드를 일시 중단하고 로더/모듈
//! 정보를 읽어, 단위 테스트 병렬 실행 시 로더 락 경합으로 멈출 수 있다.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use xmem_windows::{
    DumpProgress, current_pid, open_for_dump, validate_minidump, write_minidump_file_with_progress,
};

#[test]
fn write_minidump_file_with_progress_of_self_is_valid() {
    let dir = std::env::temp_dir().join(format!("xmem-dump-progress-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("self.dmp");
    let pid = current_pid();
    let handle = open_for_dump(pid).unwrap();
    let progress = DumpProgress::new(0);

    let size = write_minidump_file_with_progress(&handle, pid, &path, false, &progress).unwrap();

    assert!(size > 0);
    assert!(
        progress.bytes_written() > 0,
        "IoWriteAllCallback이 기록 바이트를 관측해야 한다"
    );
    assert!(
        progress.fraction().is_none(),
        "estimate 0이면 진행률 없음(indeterminate)"
    );
    validate_minidump(&path).unwrap();

    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "temp 파일이 남았다");

    let _ = std::fs::remove_dir_all(&dir);
}
