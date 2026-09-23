use crate::cli::{GlobalArgs, ProcessCmd};
use crate::commands::render::{opt_num, truncate};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};
use xmem_core::{ProcessArch, ProcessInfo, Result, XmemError};

pub fn run(cmd: &ProcessCmd, global: &GlobalArgs) -> Result<()> {
    match (cmd, resolve_mode(global.json)) {
        (ProcessCmd::List, OutputMode::Json) => {
            let infos = xmem_windows::list_processes()?;
            let value = serde_json::to_value(&infos).map_err(|e| XmemError::JsonError {
                reason: e.to_string(),
            })?;
            emit_json(&success_envelope(serde_json::json!({ "processes": value })));
        }
        (ProcessCmd::List, OutputMode::Human) => {
            let infos = xmem_windows::list_processes()?;
            println!("{}", render_list(&infos));
        }
        (ProcessCmd::Info(args), OutputMode::Json) => {
            let info = xmem_windows::process_info(args.pid)?;
            let value = serde_json::to_value(&info).map_err(|e| XmemError::JsonError {
                reason: e.to_string(),
            })?;
            emit_json(&success_envelope(value));
        }
        (ProcessCmd::Info(args), OutputMode::Human) => {
            let info = xmem_windows::process_info(args.pid)?;
            println!("{}", render_info(&info));
        }
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

pub fn render_list(infos: &[ProcessInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:>6}  {:>6}  {:>7}  {:>7}  {:<5}  {:<24}  {}\n",
        "PID", "PPID", "THREADS", "SESSION", "ARCH", "NAME", "PATH"
    ));
    for info in infos {
        out.push_str(&format!(
            "{:>6}  {:>6}  {:>7}  {:>7}  {:<5}  {:<24}  {}\n",
            info.pid,
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

    #[test]
    fn render_list_has_header_and_rows() {
        let out = render_list(&[sample(10), sample(20)]);
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
        let out = render_list(&[info]);
        assert!(out.contains('-'));
    }

    #[test]
    fn render_list_truncates_long_name() {
        let mut info = sample(10);
        info.name = "a".repeat(80);
        let out = render_list(&[info]);
        assert!(out.contains("..."));
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
