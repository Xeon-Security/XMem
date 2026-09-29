#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! 자기 프로세스 미니덤프를 사용하는 테스트.
//!
//! `MiniDumpWriteDump`는 덤프하는 동안 프로세스의 모든 스레드를 중단하고 로더 정보를 읽는다.
//! 단위 테스트 바이너리에서 병렬로 실행하면 다른 테스트 스레드가 DLL을 로드하는 중일 때
//! 로더 락 경합으로 멈출 수 있어(간헐적 타임아웃), 별도 프로세스에서 단독으로 실행되도록
//! 통합 테스트로 분리했다.

use minidump::Minidump;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use xmem_core::{MemorySource, ProcessArch, XmemError};
use xmem_forensics::{MinidumpSource, analyze_dump};
use xmem_windows::{current_pid, open_for_dump, write_minidump_file};

/// 통합 테스트 바이너리 안에서도 `cargo test`는 테스트를 병렬로 돌린다.
/// `MiniDumpWriteDump`는 덤프 중 프로세스의 모든 스레드를 중단하므로, 동시에 자기 덤프를
/// 뜨면(다른 테스트가 DLL을 로드하는 중이면) 로더 락 경합으로 멈출 수 있어 직렬화한다.
static SELF_DUMP_LOCK: Mutex<()> = Mutex::new(());

fn lock_self_dump() -> MutexGuard<'static, ()> {
    SELF_DUMP_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn self_dump(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("xmem-fx-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("self.dmp");
    let pid = current_pid();
    let handle = open_for_dump(pid).unwrap();
    write_minidump_file(&handle, pid, &path, false).unwrap();
    path
}

#[test]
fn analyze_dump_of_self_returns_metadata() {
    let _guard = lock_self_dump();
    let path = self_dump("meta");
    let analysis = analyze_dump(&path).unwrap();
    assert_eq!(analysis.process.pid, current_pid());
    assert_ne!(analysis.arch, ProcessArch::Unknown);
    assert!(!analysis.modules.is_empty());
    assert!(!analysis.regions.is_empty());
    assert!(!analysis.threads.is_empty());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn minidump_source_reads_memory_from_dump() {
    let _guard = lock_self_dump();
    let path = self_dump("read");
    let source = MinidumpSource::open(&path).unwrap();
    let raw = Minidump::read_path(&path).unwrap();
    let memory = raw.get_memory().unwrap();
    let first = memory.iter().find(|r| r.bytes().len() >= 16).unwrap();
    let base = first.base_address();

    let mut buf = [0u8; 16];
    let outcome = source.read(base, &mut buf).unwrap();
    assert_eq!(outcome.bytes_read, 16);
    assert!(!outcome.partial);
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn minidump_source_read_invalid_address_errors() {
    let _guard = lock_self_dump();
    let path = self_dump("bad-addr");
    let source = MinidumpSource::open(&path).unwrap();
    let mut buf = [0u8; 16];
    let err = source.read(u64::MAX - 4096, &mut buf).unwrap_err();
    assert!(matches!(err, XmemError::InvalidAddress { .. }));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn minidump_threads_report_context_instruction_pointer() {
    let _guard = lock_self_dump();
    let path = self_dump("rip");

    let source = MinidumpSource::open(&path).unwrap();
    let threads = xmem_core::MemorySource::threads(&source).unwrap();
    assert!(!threads.is_empty(), "스레드 목록");
    assert!(
        threads.iter().any(|t| t.start_address.is_some()),
        "MiniDumpNormal은 스레드 컨텍스트를 포함한다"
    );
    assert!(
        threads.iter().all(|t| t.start_address.is_none()
            || t.start_address_source.as_deref() == Some("minidump-context-rip")),
        "출처 표기"
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
