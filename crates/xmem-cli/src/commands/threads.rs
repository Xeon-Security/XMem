use xmem_core::{ProcessInfo, Result, ThreadFilter, ThreadInfo, XmemError};
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, ThreadsArgs};
use crate::commands::render::{opt_hex, opt_num};
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(args: &ThreadsArgs, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid.pid)?;
    let filter = ThreadFilter {
        with_start_only: args.with_start,
        suspicious_only: args.suspicious,
        tid: args.tid,
    };
    let threads: Vec<ThreadInfo> = live
        .threads()?
        .into_iter()
        .filter(|thread| filter.matches(thread))
        .collect();
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value = serde_json::to_value(json_payload(&live.info, &threads)).map_err(|e| {
                XmemError::JsonError {
                    reason: e.to_string(),
                }
            })?;
            emit_json(&success_envelope(value));
        }
        OutputMode::Human => emit(&render_threads(&live.info, &threads)),
    }
    Ok(())
}

fn render_threads(info: &ProcessInfo, threads: &[ThreadInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}): {} threads\n",
        info.pid,
        info.name,
        threads.len()
    ));
    out.push_str("TID      PRIORITY START ADDRESS       REGION              MODULE\n");
    for thread in threads {
        out.push_str(&format!(
            "{:<8} {:>8} {:<20} {:<19} {}\n",
            thread.tid,
            opt_num(thread.priority),
            opt_hex(thread.start_address),
            opt_hex(thread.start_region_base),
            thread.start_module.as_deref().unwrap_or("-"),
        ));
    }
    out
}

fn json_payload(info: &ProcessInfo, threads: &[ThreadInfo]) -> serde_json::Value {
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "thread_count": threads.len(),
        "threads": threads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmem_core::ProcessArch;

    fn sample_info() -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            ppid: Some(1),
            name: "target.exe".to_string(),
            image_path: None,
            arch: ProcessArch::X64,
            session_id: None,
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_thread(tid: u32, start: Option<u64>, module: Option<&str>) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1234,
            priority: Some(8),
            start_address: start,
            start_region_base: start.map(|a| a & !0xfff),
            start_module: module.map(str::to_string),
        }
    }

    #[test]
    fn render_threads_shows_correlation() {
        let threads = vec![
            sample_thread(100, Some(0x0001_4000_1234), Some("target.exe")),
            sample_thread(200, None, None),
        ];
        let text = render_threads(&sample_info(), &threads);
        assert!(text.contains("2 threads"));
        assert!(text.contains("target.exe"));
        assert!(text.contains("0x0000000140001234"));
        assert!(text.contains('-'));
    }

    #[test]
    fn thread_filter_reduces_rows() {
        let threads = vec![
            sample_thread(100, Some(0x0001_4000_1234), Some("target.exe")),
            sample_thread(200, Some(0x9000), None),
            sample_thread(300, None, None),
        ];
        let suspicious = ThreadFilter {
            suspicious_only: true,
            ..Default::default()
        };
        let filtered: Vec<ThreadInfo> = threads
            .into_iter()
            .filter(|thread| suspicious.matches(thread))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].tid, 200);
        let value = json_payload(&sample_info(), &filtered);
        assert_eq!(value["thread_count"], 1);
        assert_eq!(value["threads"].as_array().unwrap().len(), 1);

        let by_tid = ThreadFilter {
            tid: Some(999),
            ..Default::default()
        };
        let empty: Vec<ThreadInfo> = Vec::new();
        assert!(empty.iter().all(|thread| !by_tid.matches(thread)));
    }

    #[test]
    fn threads_json_payload_shape() {
        let threads = vec![sample_thread(
            100,
            Some(0x0001_4000_1234),
            Some("target.exe"),
        )];
        let value = json_payload(&sample_info(), &threads);
        assert_eq!(value["process"]["pid"], 1234);
        assert_eq!(value["thread_count"], 1);
        assert_eq!(value["threads"][0]["tid"], 100);
        assert_eq!(value["threads"][0]["start_module"], "target.exe");
    }
}
