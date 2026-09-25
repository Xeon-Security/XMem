use crate::cli::{ArchArg, GlobalArgs, PidArg, ProcessCmd, ProcessListArgs};
use crate::commands::render::{opt_num, truncate};
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};
use xmem_core::{ProcessArch, ProcessFilter, ProcessInfo, Result, XmemError, pad_display};

pub fn run(cmd: &ProcessCmd, global: &GlobalArgs) -> Result<()> {
    match cmd {
        ProcessCmd::List(args) => run_list(args, global),
        ProcessCmd::Info(args) => run_info(args, global),
    }
}

fn build_filter(args: &ProcessListArgs) -> ProcessFilter {
    ProcessFilter {
        accessible_only: args.accessible_only,
        name_contains: args.name.clone(),
        arch: args.arch.map(ArchArg::to_arch),
        session: args.session,
        user_contains: args.user.clone(),
        protected_only: args.protected,
        parent_pid: args.ppid,
    }
}

fn run_list(args: &ProcessListArgs, global: &GlobalArgs) -> Result<()> {
    let rows = list_rows(&build_filter(args))?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let processes = rows
                .iter()
                .map(|(info, accessible)| {
                    let mut value =
                        serde_json::to_value(info).map_err(|e| XmemError::JsonError {
                            reason: e.to_string(),
                        })?;
                    value["accessible"] = (*accessible).into();
                    Ok(value)
                })
                .collect::<Result<Vec<_>>>()?;
            emit_json(&success_envelope(
                serde_json::json!({ "processes": processes }),
            ));
        }
        OutputMode::Human => emit(&render_list(&rows)),
    }
    Ok(())
}

fn run_info(args: &PidArg, global: &GlobalArgs) -> Result<()> {
    let info = xmem_windows::process_info(args.pid)?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value = serde_json::to_value(&info).map_err(|e| XmemError::JsonError {
                reason: e.to_string(),
            })?;
            emit_json(&success_envelope(value));
        }
        OutputMode::Human => emit(&render_info(&info)),
    }
    Ok(())
}

pub(crate) fn arch_str(arch: ProcessArch) -> &'static str {
    match arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "-",
    }
}

/// 각 프로세스를 접근성(메모리 읽기 가능 여부)과 함께 나열하고 필터를 적용한다.
fn list_rows(filter: &ProcessFilter) -> Result<Vec<(ProcessInfo, bool)>> {
    let infos = xmem_windows::list_processes()?;
    Ok(infos
        .into_iter()
        .map(|info| {
            let accessible = xmem_windows::is_memory_readable(info.pid);
            (info, accessible)
        })
        .filter(|(info, accessible)| filter.matches(info, *accessible))
        .collect())
}

#[cfg(test)]
fn filter_rows(rows: Vec<(ProcessInfo, bool)>, filter: &ProcessFilter) -> Vec<(ProcessInfo, bool)> {
    rows.into_iter()
        .filter(|(info, accessible)| filter.matches(info, *accessible))
        .collect()
}

fn access_str(accessible: bool) -> &'static str {
    if accessible {
        "가능"
    } else {
        "권한 필요"
    }
}

/// ACCESS 열 표시 폭. "권한 필요"가 전각 2칸×4 + 공백 1 = 9칸이다.
const ACCESS_WIDTH: usize = 9;

pub fn render_list(rows: &[(ProcessInfo, bool)]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:>6}  {}  {:>6}  {:>7}  {:>7}  {:<5}  {:<24}  {}\n",
        "PID",
        pad_display("ACCESS", ACCESS_WIDTH),
        "PPID",
        "THREADS",
        "SESSION",
        "ARCH",
        "NAME",
        "PATH"
    ));
    for (info, accessible) in rows {
        out.push_str(&format!(
            "{:>6}  {}  {:>6}  {:>7}  {:>7}  {:<5}  {:<24}  {}\n",
            info.pid,
            pad_display(access_str(*accessible), ACCESS_WIDTH),
            opt_num(info.ppid),
            opt_num(info.thread_count),
            opt_num(info.session_id),
            arch_str(info.arch),
            truncate(&info.name, 24),
            truncate(info.image_path.as_deref().unwrap_or("-"), 60),
        ));
    }
    out.trim_end().to_string()
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn format_filetime(ft: u64) -> String {
    let secs = xmem_core::filetime_to_unix_secs(ft);
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        None => format!("{secs} (unix secs)"),
    }
}

fn field(name: &str, value: String) -> String {
    format!("{:<14} {}\n", format!("{name}:"), value)
}

pub fn render_info(info: &ProcessInfo) -> String {
    let mut out = String::new();
    out.push_str(&field("PID", info.pid.to_string()));
    out.push_str(&field("Name", info.name.clone()));
    out.push_str(&field(
        "Path",
        info.image_path.clone().unwrap_or_else(|| "-".to_string()),
    ));
    out.push_str(&field("Architecture", arch_str(info.arch).to_string()));
    out.push_str(&field("Session", opt_num(info.session_id)));
    out.push_str(&field(
        "Created",
        info.creation_time
            .map(format_filetime)
            .unwrap_or_else(|| "-".to_string()),
    ));
    out.push_str(&field("Parent PID", opt_num(info.ppid)));
    out.push_str(&field(
        "User",
        info.user.clone().unwrap_or_else(|| "-".to_string()),
    ));
    out.push_str(&field(
        "Command Line",
        info.command_line.clone().unwrap_or_else(|| "-".to_string()),
    ));
    match &info.memory_stats {
        Some(stats) => {
            out.push_str(&field("Working Set", mib(stats.working_set)));
            out.push_str(&field("Private", mib(stats.private_bytes)));
            out.push_str(&field("Commit", mib(stats.commit)));
            let virtual_size = if stats.virtual_size == 0 {
                "-".to_string()
            } else {
                mib(stats.virtual_size)
            };
            out.push_str(&field("Virtual", virtual_size));
        }
        None => out.push_str(&field("Memory", "-".to_string())),
    }
    out.push_str(&field("Threads", opt_num(info.thread_count)));
    out.push_str(&field("Modules", opt_num(info.module_count)));
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(1000),
            name: format!("proc{pid}.exe"),
            image_path: Some(format!("C:\\Windows\\System32\\proc{pid}.exe")),
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: Some(116_444_736_000_000_000),
            command_line: Some(format!("\"C:\\Windows\\System32\\proc{pid}.exe\"")),
            user: Some("DOMAIN\\user".to_string()),
            memory_stats: Some(xmem_core::MemoryStats {
                working_set: 1024 * 1024,
                private_bytes: 512 * 1024,
                commit: 768 * 1024,
                virtual_size: 2 * 1024 * 1024,
            }),
            thread_count: Some(4),
            module_count: Some(30),
        }
    }

    fn row(pid: u32, accessible: bool) -> (ProcessInfo, bool) {
        (sample(pid), accessible)
    }

    #[test]
    fn render_list_has_header_and_rows() {
        let out = render_list(&[row(10, true), row(20, true)]);
        assert!(out.contains("PID"));
        assert!(out.contains("proc10.exe"));
        assert!(out.contains("proc20.exe"));
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn render_list_dashes_missing_fields() {
        let mut info = sample(10);
        info.image_path = None;
        info.session_id = None;
        info.thread_count = None;
        let out = render_list(&[(info, false)]);
        assert!(out.contains('-'));
    }

    #[test]
    fn render_list_truncates_long_name() {
        let mut info = sample(10);
        info.name = "a".repeat(80);
        let out = render_list(&[(info, true)]);
        assert!(out.contains("..."));
    }

    #[test]
    fn render_list_marks_access() {
        let out = render_list(&[row(10, true), row(20, false)]);
        assert!(out.contains("가능"), "{out}");
        assert!(out.contains("권한 필요"), "{out}");
    }

    #[test]
    fn render_list_aligns_columns_with_wide_korean_access() {
        let out = render_list(&[row(10, true), row(20, false)]);
        let ppid_column = |line: &str| {
            let index = line.find("1000").expect("PPID 1000이 표시되어야 함");
            xmem_core::display_width(&line[..index])
        };
        let rows: Vec<&str> = out.lines().skip(1).collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            ppid_column(rows[0]),
            ppid_column(rows[1]),
            "'권한 필요'(전각)가 다음 열을 밀지 않는다"
        );
        let header = out.lines().next().expect("헤더");
        let header_ppid = xmem_core::display_width(&header[..header.find("PPID").unwrap()]);
        assert_eq!(header_ppid, ppid_column(rows[0]), "헤더도 같은 열에 정렬");
    }

    #[test]
    fn accessible_only_filters_rows() {
        let rows = vec![row(10, true), row(20, false)];
        let accessible = ProcessFilter {
            accessible_only: true,
            ..Default::default()
        };
        let filtered = filter_rows(rows.clone(), &accessible);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0.pid, 10);
        assert_eq!(filter_rows(rows, &ProcessFilter::default()).len(), 2);
    }

    #[test]
    fn filters_rows_by_name_arch_and_ppid() {
        let mut rows = vec![(sample(10), true), (sample(20), true)];
        rows[1].0.name = "other.exe".to_string();
        let by_name = ProcessFilter {
            name_contains: Some("PROC10".to_string()),
            ..Default::default()
        };
        let filtered = filter_rows(rows.clone(), &by_name);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0.pid, 10);

        let all_parents = ProcessFilter {
            parent_pid: Some(1000),
            ..Default::default()
        };
        assert_eq!(filter_rows(rows.clone(), &all_parents).len(), 2);

        let x86 = ProcessFilter {
            arch: Some(ProcessArch::X86),
            ..Default::default()
        };
        assert_eq!(filter_rows(rows, &x86).len(), 0);
    }

    #[test]
    fn render_info_formats_creation_time_as_utc() {
        let out = render_info(&sample(10));
        assert!(out.contains("1970-01-01 00:00:00 UTC"), "{out}");
        assert!(out.contains("DOMAIN\\user"));
        assert!(out.contains("1.0 MiB"));
    }

    #[test]
    fn render_info_dashes_missing_memory() {
        let mut info = sample(10);
        info.memory_stats = None;
        info.command_line = None;
        let out = render_info(&info);
        assert!(out.contains('-'));
    }
}
