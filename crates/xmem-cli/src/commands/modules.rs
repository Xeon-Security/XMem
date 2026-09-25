use serde_json::{Value, json};
use xmem_core::{MemorySource, ModuleInfo, ProcessArch, ProcessInfo, Result};
use xmem_memory::LiveProcess;
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe};

use crate::cli::{GlobalArgs, ModulesArgs};
use crate::commands::render::{human_size, truncate, truncate_tail};
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(args: &ModulesArgs, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid.pid)?;
    let modules = live.modules()?;
    // --unparsed는 PE 파싱 결과가 필요하므로 --pe 없이도 수집만 수행한다(표시 컬럼은 --pe일 때만).
    let all_pe = (args.pe || args.unparsed).then(|| collect_pe(&live, &modules));
    let selected: Vec<usize> = modules
        .iter()
        .enumerate()
        .filter(|(index, module)| {
            module_matches(
                module,
                all_pe.as_ref().and_then(|list| list.get(*index)),
                args,
            )
        })
        .map(|(index, _)| index)
        .collect();
    let filtered: Vec<ModuleInfo> = selected
        .iter()
        .map(|&index| modules[index].clone())
        .collect();
    let pe = if args.pe {
        Some(
            selected
                .iter()
                .map(|&index| {
                    all_pe
                        .as_ref()
                        .and_then(|list| list.get(index).cloned())
                        .flatten()
                })
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    match resolve_mode(global.json) {
        OutputMode::Json => emit_json(&success_envelope(json_payload(
            &live.info,
            &filtered,
            pe.as_deref(),
        ))),
        OutputMode::Human => emit(&render_modules(&live.info, &filtered, pe.as_deref())),
    }
    Ok(())
}

/// 수집 후 필터. `--unparsed`는 PE 파싱 결과가 없으면(실패) 매칭한다.
fn module_matches(module: &ModuleInfo, pe: Option<&Option<PeInfo>>, args: &ModulesArgs) -> bool {
    if let Some(needle) = args.filter.as_deref() {
        let needle = needle.to_lowercase();
        let name_hit = module.name.to_lowercase().contains(&needle);
        let path_hit = module
            .path
            .as_deref()
            .is_some_and(|path| path.to_lowercase().contains(&needle));
        if !name_hit && !path_hit {
            return false;
        }
    }
    if let Some(arch) = args.arch
        && module.arch != Some(arch.to_arch())
    {
        return false;
    }
    if args.unparsed && pe.is_some_and(|item| item.is_some()) {
        return false;
    }
    true
}

/// 모듈별 PE 헤더 prefix 파싱. 개별 실패는 None으로 degrade한다.
fn collect_pe(live: &LiveProcess, modules: &[ModuleInfo]) -> Vec<Option<PeInfo>> {
    let mut buf = vec![0u8; PE_HEADER_PREFIX];
    modules
        .iter()
        .map(|module| {
            let len = module.size.min(buf.len() as u64) as usize;
            if len < 64 {
                return None;
            }
            let outcome = live.read(module.base, &mut buf[..len]).ok()?;
            if outcome.bytes_read < 64 {
                return None;
            }
            parse_pe(&buf[..outcome.bytes_read]).ok()
        })
        .collect()
}

fn pe_arch(pe: &PeInfo) -> &'static str {
    match pe.arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
    }
}

fn render_modules(
    info: &ProcessInfo,
    modules: &[ModuleInfo],
    pe: Option<&[Option<PeInfo>]>,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "process {} ({}): {} modules\n",
        info.pid,
        info.name,
        modules.len()
    ));
    if let Some(pe_list) = pe {
        out.push_str("BASE                SIZE        MACHINE  ENTRY              SECTIONS NAME                 PATH\n");
        for (index, module) in modules.iter().enumerate() {
            let (machine, entry, sections) = match pe_list.get(index).and_then(Option::as_ref) {
                Some(pe) => (
                    pe_arch(pe).to_string(),
                    format!("{:#x}", pe.entry_point),
                    pe.sections.len().to_string(),
                ),
                None => ("-".to_string(), "-".to_string(), "-".to_string()),
            };
            let path = module
                .path
                .as_deref()
                .map(|p| truncate_tail(p, 60))
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "0x{:016x} {:>10} {:8} {:18} {:>8} {:20} {}\n",
                module.base,
                human_size(module.size),
                machine,
                entry,
                sections,
                truncate(&module.name, 20),
                path,
            ));
        }
    } else {
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
    }
    out
}

fn json_payload(
    info: &ProcessInfo,
    modules: &[ModuleInfo],
    pe: Option<&[Option<PeInfo>]>,
) -> Value {
    let items: Vec<Value> = modules
        .iter()
        .enumerate()
        .map(|(index, module)| {
            let mut value = serde_json::to_value(module).unwrap_or(Value::Null);
            if let Some(pe_list) = pe {
                value["pe"] = pe_list
                    .get(index)
                    .and_then(Option::as_ref)
                    .and_then(|pe| serde_json::to_value(pe).ok())
                    .unwrap_or(Value::Null);
            }
            value
        })
        .collect();
    json!({
        "process": { "pid": info.pid, "name": info.name },
        "module_count": modules.len(),
        "modules": items,
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
            sample_module("target.exe", 0x0001_4000_0000, Some(r"C:\lab\target.exe")),
            sample_module("kernel32.dll", 0x7ffb_0000, None),
        ];
        let text = render_modules(&sample_info(), &modules, None);
        assert!(text.contains("2 modules"));
        assert!(text.contains("0x0000000140000000"));
        assert!(text.contains("target.exe"));
        assert!(text.contains("kernel32.dll"));
    }

    #[test]
    fn modules_json_payload_shape() {
        let modules = vec![sample_module("target.exe", 0x0001_4000_0000, None)];
        let value = json_payload(&sample_info(), &modules, None);
        assert_eq!(value["process"]["pid"], 1234);
        assert_eq!(value["module_count"], 1);
        assert_eq!(value["modules"][0]["name"], "target.exe");
        assert_eq!(value["modules"][0]["base"], 0x0001_4000_0000u64);
    }

    fn sample_pe() -> xmem_pe::PeInfo {
        xmem_pe::PeInfo {
            is_64: true,
            machine: 0x8664,
            arch: ProcessArch::X64,
            image_base: 0x0001_4000_0000,
            entry_point: 0x0001_4000_1234,
            size_of_image: 0x0002_0000,
            time_date_stamp: 0,
            subsystem: 3,
            characteristics: 0x0022,
            sections: Vec::new(),
            import_count: 0,
            import_library_count: 0,
            libraries: Vec::new(),
            export_count: 0,
            relocation_count: 0,
            tls_callback_count: 0,
        }
    }

    #[test]
    fn render_modules_with_pe_shows_machine_entry_sections() {
        let info = sample_info();
        let modules = vec![sample_module(
            "target.exe",
            0x0001_4000_0000,
            Some(r"C:\lab\target.exe"),
        )];
        let pe = vec![Some(sample_pe())];
        let text = render_modules(&info, &modules, Some(&pe));
        assert!(text.contains("MACHINE"));
        assert!(text.contains("ENTRY"));
        assert!(text.contains("SECTIONS"));
        assert!(text.contains("x64"));
        assert!(text.contains("0x140001234"));
    }

    fn filter_args(
        filter: Option<&str>,
        arch: Option<crate::cli::ArchArg>,
        unparsed: bool,
    ) -> ModulesArgs {
        ModulesArgs {
            pid: crate::cli::PidArg { pid: 1 },
            pe: false,
            filter: filter.map(str::to_string),
            arch,
            unparsed,
        }
    }

    #[test]
    fn module_matches_name_path_arch_and_unparsed() {
        let module = sample_module(
            "kernel32.dll",
            0x7ffb_0000,
            Some(r"C:\Windows\System32\kernel32.dll"),
        );
        assert!(module_matches(
            &module,
            None,
            &filter_args(Some("KERNEL"), None, false)
        ));
        assert!(module_matches(
            &module,
            None,
            &filter_args(Some("system32"), None, false)
        ));
        assert!(!module_matches(
            &module,
            None,
            &filter_args(Some("user32"), None, false)
        ));

        use crate::cli::ArchArg;
        assert!(module_matches(
            &module,
            None,
            &filter_args(None, Some(ArchArg::X64), false)
        ));
        assert!(!module_matches(
            &module,
            None,
            &filter_args(None, Some(ArchArg::X86), false)
        ));

        let parsed = Some(sample_pe());
        assert!(module_matches(
            &module,
            Some(&parsed),
            &filter_args(None, None, false)
        ));
        assert!(!module_matches(
            &module,
            Some(&parsed),
            &filter_args(None, None, true)
        ));
        let unparsed: Option<xmem_pe::PeInfo> = None;
        assert!(module_matches(
            &module,
            Some(&unparsed),
            &filter_args(None, None, true)
        ));
    }

    #[test]
    fn filtered_modules_json_keeps_schema_keys() {
        let filtered = vec![sample_module("a.dll", 0x1000, None)];
        let value = json_payload(&sample_info(), &filtered, None);
        assert_eq!(value["module_count"], 1);
        assert_eq!(value["modules"].as_array().unwrap().len(), 1);
        assert!(
            value["modules"][0].get("pe").is_none(),
            "--pe 없이는 pe 키도 없다"
        );
    }

    #[test]
    fn json_payload_merges_pe_when_present() {
        let info = sample_info();
        let modules = vec![
            sample_module("a.dll", 0x1000, None),
            sample_module("b.dll", 0x2000, None),
        ];
        let pe = vec![Some(sample_pe()), None];
        let payload = json_payload(&info, &modules, Some(&pe));
        assert_eq!(payload["module_count"], 2);
        assert_eq!(payload["modules"][0]["pe"]["arch"], "x64");
        assert!(payload["modules"][1]["pe"].is_null());
        let payload_without = json_payload(&info, &modules, None);
        assert!(payload_without["modules"][0].get("pe").is_none());
    }
}
