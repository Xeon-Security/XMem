#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! soak(장시간 반복) 스모크: 반복 실행해도 RSS가 한도 이상 증가하지 않는지 확인한다.
//!
//! 기본 테스트에는 포함하지 않는다(`#[ignore]`). 실행:
//! `cargo test -p xmem-memory --test soak -- --ignored --nocapture`
//! 임계 32 MiB는 회당 0.5 MiB 누수(60회 = 30 MiB)를 잡는 수준이다.

use std::sync::atomic::AtomicBool;

use xmem_core::ScanPattern;
use xmem_memory::{LiveProcess, ScanOptions, scan};

#[test]
#[ignore = "soak: 반복 map/scan 후 RSS 증가 한도 확인"]
fn repeated_map_and_scan_do_not_leak() {
    let live = LiveProcess::open(std::process::id()).unwrap();
    let pattern = ScanPattern::ascii("xmem").unwrap();
    let options = ScanOptions {
        max_results: 16,
        ..ScanOptions::default()
    };
    let cancel = AtomicBool::new(false);

    // 예열: 첫 실행의 캐시·버퍼 할당을 baseline에서 제외한다.
    let warm = live.region_map().unwrap();
    assert!(
        !warm.regions.is_empty(),
        "자기 프로세스 영역이 비어 있으면 안 된다"
    );
    let _ = scan(&live, &pattern, &options, &cancel).unwrap();
    let baseline = xmem_windows::current_rss_bytes().unwrap();

    for round in 0..60 {
        let map = live.region_map().unwrap();
        assert!(!map.regions.is_empty(), "round {round}: 영역이 비었다");
        let report = scan(&live, &pattern, &options, &cancel).unwrap();
        assert!(!report.cancelled, "round {round}: 스캔이 취소되었다");
    }

    let after = xmem_windows::current_rss_bytes().unwrap();
    let growth = after.saturating_sub(baseline);
    println!("soak: 60 rounds, RSS {baseline} -> {after} (growth {growth} bytes)");
    assert!(
        growth < 32 * 1024 * 1024,
        "RSS가 {growth} bytes 증가 (한도 32 MiB)"
    );
}
