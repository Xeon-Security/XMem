use xmem_core::{ModuleInfo, ProcessInfo, Result, XmemError};
use xmem_memory::LiveProcess;

use crate::cli::{GlobalArgs, PidArg};
use crate::commands::render::{human_size, truncate, truncate_tail};
use crate::output::{OutputMode, emit_json, resolve_mode, success_envelope};

pub fn run(args: &PidArg, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid)?;
    let modules = live.modules()?;
    match resolve_mode(global.json) {
        OutputMode::Json => {
            let value = serde_json::to_value(json_payload(&live.info, &modules)).map_err(|e| {
                XmemError::JsonError {
                    reason: e.to_string(),
                }
            })?;
            emit_json(&success_envelope(value));
        }
        OutputMode::Human => print!("{}", render_modules(&live.info, &modules)),
    }
    Ok(())
}

fn render_modules(info: &ProcessInfo, modules: &[ModuleInfo]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}): {} modules\n",
        info.pid,
        info.name,
        modules.len()
    ));
    out.push_str("BASE                SIZE        NAME                 PATH\n");
    for module in modules {
        let path = module
            .path
            .as_deref()
            .map(|p| truncate_tail(p, 60))
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "0x{:016x} {:>10} {:20} {}\n",
            module.base,
            human_size(module.size),
            truncate(&module.name, 20),
            path,
        ));
    }
    out
}

fn json_payload(info: &ProcessInfo, modules: &[ModuleInfo]) -> serde_json::Value {
    serde_json::json!({
        "process": { "pid": info.pid, "name": info.name },
        "module_count": modules.len(),
        "modules": modules,
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
            image_path: Some(r"C:\lab\target.exe".to_string()),
            arch: ProcessArch::X64,
            session_id: Some(1),
            creation_time: None,
            command_line: None,
            user: None,
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn sample_module(name: &str, base: u64, path: Option<&str>) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base,
            size: 0x1000,
            path: path.map(str::to_string),
            arch: Some(ProcessArch::X64),
        }
    }

    #[test]
    fn render_modules_lists_rows_and_summary() {
        let modules = vec![
            sample_module("target.exe", 0x14000_0000, Some(r"C:\lab\target.exe")),
            sample_module("kernel32.dll", 0x7ffb_0000, None),
        ];
        let text = render_modules(&sample_info(), &modules);
        assert!(text.contains("2 modules"));
        assert!(text.contains("0x0000000140000000"));
        assert!(text.contains("target.exe"));
        assert!(text.contains("kernel32.dll"));
    }

    #[test]
    fn modules_json_payload_shape() {
        let modules = vec![sample_module("target.exe", 0x14000_0000, None)];
        let value = json_payload(&sample_info(), &modules);
        assert_eq!(value["process"]["pid"], 1234);
        assert_eq!(value["module_count"], 1);
        assert_eq!(value["modules"][0]["name"], "target.exe");
        assert_eq!(value["modules"][0]["base"], 0x14000_0000u64);
    }
}
