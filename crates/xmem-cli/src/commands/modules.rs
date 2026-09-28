use serde_json::{Value, json};
use xmem_core::{
    MemorySource, ModuleFilter, ModuleInfo, ProcessArch, ProcessInfo, Result, pad_display,
    truncate_display,
};
use xmem_memory::{LiveProcess, UnloadedModule};
use xmem_pe::{PE_HEADER_PREFIX, PeInfo, parse_pe};

use crate::cli::{GlobalArgs, ModulesArgs};
use crate::commands::render::{human_size, truncate_tail};
use crate::output::{OutputMode, emit, emit_json, resolve_mode, success_envelope};

pub fn run(args: &ModulesArgs, global: &GlobalArgs) -> Result<()> {
    let live = LiveProcess::open(args.pid.pid)?;
    let modules = live.modules()?;
    // --unparsed는 PE 파싱 결과가 필요하므로 --pe 없이도 수집만 수행한다(표시 컬럼은 --pe일 때만).
    let all_pe = (args.pe || args.unparsed).then(|| collect_pe(&live, &modules));
    let filter = build_filter(args);
    let pe_ok = |index: usize| {
        all_pe
            .as_ref()
            .and_then(|list| list.get(index))
            .is_some_and(|item| item.is_some())
    };
    let selected: Vec<usize> = modules
        .iter()
        .enumerate()
        .filter(|(index, module)| filter.matches(module, pe_ok(*index)))
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
    let unloaded = if args.unloaded {
        // 후보 수집 실패는 모듈 목록 자체를 막지 않는다(경고 후 빈 목록).
        match live.unloaded_module_candidates() {
            Ok(candidates) => Some(candidates),
            Err(err) => {
                tracing::warn!("언로드 모듈 후보 수집 실패: {err}");
                Some(Vec::new())
            }
        }
    } else {
        None
    };
    match resolve_mode(global.json) {
        OutputMode::Json => emit_json(&success_envelope(json_payload(
            &live.info,
            &filtered,
            pe.as_deref(),
            unloaded.as_deref(),
        ))),
        OutputMode::Human => {
            let mut text = render_modules(&live.info, &filtered, pe.as_deref());
            if let Some(candidates) = unloaded.as_deref() {
                text.push_str(&render_unloaded_section(candidates));
            }
            emit(&text);
        }
    }
    Ok(())
}

/// CLI 플래그를 core `ModuleFilter`로 변환한다.
pub(crate) fn build_filter(args: &ModulesArgs) -> ModuleFilter {
    ModuleFilter {
        name_contains: args.filter.clone(),
        arch: args.arch.map(|arch| arch.to_arch()),
        unparsed_only: args.unparsed,
    }
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
    arch_label(pe.arch)
}

fn arch_label(arch: ProcessArch) -> &'static str {
    match arch {
        ProcessArch::X64 => "x64",
        ProcessArch::X86 => "x86",
        ProcessArch::Arm64 => "arm64",
        ProcessArch::Unknown => "unknown",
    }
}

/// 언로드 모듈 후보 섹션(사람 출력). 후보가 없으면 안내 한 줄만 낸다.
pub(crate) fn render_unloaded_section(candidates: &[UnloadedModule]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\nUNLOADED IMAGE CANDIDATES ({})\n",
        candidates.len()
    ));
    if candidates.is_empty() {
        out.push_str("no candidates\n");
        return out;
    }
    out.push_str(&format!(
        "{:<18} {:>10} {:6} {:18} {:>8} {:>7} {:>10}\n",
        "BASE", "SIZE", "ARCH", "ENTRY", "SECTIONS", "IMPORTS", "TIMESTAMP"
    ));
    for candidate in candidates {
        out.push_str(&format!(
            "0x{:016x} {:>10} {:6} {:#18x} {:>8} {:>7} {:#010x}\n",
            candidate.base,
            human_size(candidate.size),
            arch_label(candidate.arch),
            candidate.entry_point,
            candidate.sections,
            candidate.imports,
            candidate.timestamp,
        ));
    }
    out
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
        out.push_str(&format!(
            "{:<18} {:>10} {:8} {:18} {:>8} {} {}\n",
            "BASE",
            "SIZE",
            "MACHINE",
            "ENTRY",
            "SECTIONS",
            pad_display("NAME", 20),
            "PATH"
        ));
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
                "0x{:016x} {:>10} {:8} {:18} {:>8} {} {}\n",
                module.base,
                human_size(module.size),
                machine,
                entry,
                sections,
                pad_display(&truncate_display(&module.name, 20), 20),
                path,
            ));
        }
    } else {
        out.push_str(&format!(
            "{:<18} {:>10} {} {}\n",
            "BASE",
            "SIZE",
            pad_display("NAME", 20),
            "PATH"
        ));
        for module in modules {
            let path = module
                .path
                .as_deref()
                .map(|p| truncate_tail(p, 60))
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "0x{:016x} {:>10} {} {}\n",
                module.base,
                human_size(module.size),
                pad_display(&truncate_display(&module.name, 20), 20),
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
    unloaded: Option<&[UnloadedModule]>,
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
    let mut payload = json!({
        "process": { "pid": info.pid, "name": info.name },
        "module_count": modules.len(),
        "modules": items,
    });
    if let Some(candidates) = unloaded {
        payload["unloaded"] = json!(candidates);
    }
    payload
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
        let value = json_payload(&sample_info(), &modules, None, None);
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
            unloaded: false,
        }
    }

    #[test]
    fn module_filter_matches_name_path_arch_and_unparsed() {
        let module = sample_module(
            "kernel32.dll",
            0x7ffb_0000,
            Some(r"C:\Windows\System32\kernel32.dll"),
        );
        let matches = |filter: &ModuleFilter, pe_ok: bool| filter.matches(&module, pe_ok);
        assert!(matches(
            &build_filter(&filter_args(Some("KERNEL"), None, false)),
            false
        ));
        assert!(matches(
            &build_filter(&filter_args(Some("system32"), None, false)),
            false
        ));
        assert!(!matches(
            &build_filter(&filter_args(Some("user32"), None, false)),
            false
        ));

        use crate::cli::ArchArg;
        assert!(matches(
            &build_filter(&filter_args(None, Some(ArchArg::X64), false)),
            false
        ));
        assert!(!matches(
            &build_filter(&filter_args(None, Some(ArchArg::X86), false)),
            false
        ));

        assert!(matches(
            &build_filter(&filter_args(None, None, false)),
            true
        ));
        assert!(!matches(
            &build_filter(&filter_args(None, None, true)),
            true
        ));
        assert!(matches(
            &build_filter(&filter_args(None, None, true)),
            false
        ));
    }

    #[test]
    fn filtered_modules_json_keeps_schema_keys() {
        let filtered = vec![sample_module("a.dll", 0x1000, None)];
        let value = json_payload(&sample_info(), &filtered, None, None);
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
        let payload = json_payload(&info, &modules, Some(&pe), None);
        assert_eq!(payload["module_count"], 2);
        assert_eq!(payload["modules"][0]["pe"]["arch"], "x64");
        assert!(payload["modules"][1]["pe"].is_null());
        let payload_without = json_payload(&info, &modules, None, None);
        assert!(payload_without["modules"][0].get("pe").is_none());
    }

    fn sample_unloaded() -> UnloadedModule {
        UnloadedModule {
            base: 0x0000_0001_4000_0000,
            size: 0x1000,
            arch: ProcessArch::X64,
            entry_point: 0x0000_0001_4000_1234,
            image_size: 0x2000,
            timestamp: 0x1234_5678,
            sections: 3,
            imports: 5,
        }
    }

    #[test]
    fn render_unloaded_section_lists_rows() {
        let text = render_unloaded_section(&[sample_unloaded()]);
        assert!(text.contains("UNLOADED IMAGE CANDIDATES"));
        assert!(text.contains("BASE"));
        assert!(text.contains("TIMESTAMP"));
        assert!(text.contains("0x0000000140000000"));
        assert!(text.contains("x64"));
        assert!(text.contains("0x140001234"));
        assert!(text.contains("0x12345678"));
        let empty = render_unloaded_section(&[]);
        assert!(empty.contains("UNLOADED IMAGE CANDIDATES"));
        assert!(empty.contains("no candidates"));
    }

    #[test]
    fn modules_json_includes_unloaded_only_when_flag() {
        let modules = vec![sample_module("a.dll", 0x1000, None)];
        let unloaded = vec![sample_unloaded()];
        let with = json_payload(&sample_info(), &modules, None, Some(&unloaded));
        assert_eq!(with["unloaded"].as_array().unwrap().len(), 1);
        assert_eq!(with["unloaded"][0]["base"], 0x0000_0001_4000_0000u64);
        assert_eq!(with["unloaded"][0]["sections"], 3);
        let without = json_payload(&sample_info(), &modules, None, None);
        assert!(
            without.get("unloaded").is_none(),
            "--unloaded 없이는 키도 없다"
        );
    }
}
