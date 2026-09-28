pub mod detect;
pub mod dump;
pub mod experiment;
pub mod export;
pub mod memory;
pub mod modules;
pub mod process;
pub(crate) mod render;
pub mod report;
pub mod snapshot;
pub mod threads;

use xmem_core::Result;

use crate::cli::{Cli, Command};

pub fn dispatch(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Process { cmd } => process::run(cmd, &cli.global),
        Command::Memory { cmd } => memory::run(cmd, &cli.global),
        Command::Modules(args) => modules::run(args, &cli.global),
        Command::Threads(args) => threads::run(args, &cli.global),
        Command::Snapshot { cmd } => snapshot::run(cmd, &cli.global),
        Command::Dump { cmd } => dump::run(cmd, &cli.global),
        Command::Detect(args) => detect::run(args, &cli.global),
        Command::Report { pid, output } => report::run(pid, output, &cli.global),
        Command::Experiment { cmd } => experiment::run(cmd, &cli.global),
    }
}

/// CLI 경로(플래그 → core 필터 → `matches()`)가 대표 fixture에서 내는 행 수.
/// 같은 fixture·조건을 쓰는 GUI 테스트(`xmem-gui` `views::equivalence_tests`)와
/// 수치가 같아야 한다.
#[cfg(test)]
mod equivalence_tests {
    use super::*;
    use crate::cli::{
        ArchArg, DetectArgs, DetectSortArg, ExportFormat, MapArgs, ModulesArgs, OutputArgs, PidArg,
        ProcessListArgs, SeverityArg, ThreadsArgs,
    };
    use xmem_core::{
        Confidence, Evidence, Finding, MemoryRegion, MemoryState, MemoryType, ModuleInfo,
        ProcessArch, ProcessInfo, Protection, RegionClass, Severity, ThreadInfo,
    };

    fn pid(value: u32) -> PidArg {
        PidArg { pid: value }
    }

    fn output() -> OutputArgs {
        OutputArgs {
            output: None,
            format: ExportFormat::Json,
        }
    }

    fn region(base: u64, size: u64, raw: u32, class: RegionClass) -> MemoryRegion {
        let protection = Protection::from_win32(raw);
        MemoryRegion {
            base,
            size,
            allocation_base: Some(base),
            state: MemoryState::Commit,
            protection,
            allocation_protection: None,
            region_type: Some(MemoryType::Private),
            readable: protection.readable,
            writable: protection.writable,
            executable: protection.executable,
            classification: class,
            heuristics: Vec::new(),
            mapped_file: None,
        }
    }

    fn process(value: u32, name: &str, arch: ProcessArch, session: u32, ppid: u32) -> ProcessInfo {
        ProcessInfo {
            pid: value,
            ppid: Some(ppid),
            name: name.to_string(),
            image_path: Some(format!(r"C:\lab\{name}")),
            arch,
            session_id: Some(session),
            creation_time: None,
            command_line: None,
            user: Some("DOMAIN\\User".to_string()),
            memory_stats: None,
            thread_count: None,
            module_count: None,
        }
    }

    fn thread(tid: u32, start: Option<u64>, module: Option<&str>) -> ThreadInfo {
        ThreadInfo {
            tid,
            pid: 1,
            priority: Some(8),
            start_address: start,
            start_region_base: start.map(|address| address & !0xfff),
            start_module: module.map(str::to_string),
        }
    }

    fn finding(rule: &str, severity: Severity, confidence: Confidence) -> Finding {
        Finding {
            rule_id: rule.to_string(),
            name: "fixture".to_string(),
            severity,
            confidence,
            evidence: vec![Evidence::new("region").with_region_base(0x1000)],
            heuristic: "fixture".to_string(),
            interpretation: "fixture".to_string(),
        }
    }

    fn module(name: &str, path: Option<&str>, arch: ProcessArch) -> ModuleInfo {
        ModuleInfo {
            name: name.to_string(),
            base: 0x1000,
            size: 0x1000,
            path: path.map(str::to_string),
            arch: Some(arch),
        }
    }

    #[test]
    fn filter_equivalence_counts_use_shared_core() {
        let regions = [
            region(0x1000, 0x1000, 0x40, RegionClass::Private),
            region(0x2000, 0x2000, 0x20, RegionClass::Image),
            region(0x1_0000, 0x1000, 0x04, RegionClass::Mapped),
            region(0x2_0000, 0x100, 0x02, RegionClass::Private),
            region(0x3_0000, 0x2000, 0x01, RegionClass::Reserved),
        ];
        let filter = memory::build_map_filter(&MapArgs {
            pid: pid(1),
            output: output(),
            readable_only: true,
            writable_only: false,
            executable_only: true,
            state: None,
            class: None,
            protection: None,
            heuristic: None,
            pe_like: false,
            outside_modules: false,
            mapped_only: false,
            range: None,
            min_size: None,
            max_size: None,
            sort: crate::cli::MapSortArg::Addr,
        })
        .unwrap();
        assert_eq!(
            regions.iter().filter(|r| filter.matches(r, &[])).count(),
            2,
            "readable+executable"
        );

        let rows = vec![
            (process(1, "target.exe", ProcessArch::X64, 1, 4), true),
            (process(2, "svc.exe", ProcessArch::X64, 2, 4), false),
            (process(3, "legacy.exe", ProcessArch::X86, 1, 7), true),
        ];
        let filter = process::build_filter(&ProcessListArgs {
            accessible_only: true,
            name: None,
            arch: Some(ArchArg::X64),
            session: None,
            user: None,
            protected: false,
            ppid: Some(4),
        });
        assert_eq!(
            process::filter_rows(rows, &filter).len(),
            1,
            "x64+ppid4+접근"
        );

        let threads = [
            thread(100, Some(0x1000), Some("mod.dll")),
            thread(200, Some(0x9000), None),
            thread(300, None, None),
        ];
        let filter = threads::build_filter(&ThreadsArgs {
            pid: pid(1),
            with_start: true,
            suspicious: true,
            tid: None,
        });
        assert_eq!(
            threads.iter().filter(|t| filter.matches(t)).count(),
            1,
            "의심 스레드"
        );

        let findings = [
            finding("XMEM-001", Severity::High, Confidence::High),
            finding("XMEM-002", Severity::Medium, Confidence::Medium),
            finding("XMEM-003", Severity::Low, Confidence::Low),
        ];
        let filter = detect::build_filter(&DetectArgs {
            pid: pid(1),
            output: output(),
            min_severity: Some(SeverityArg::Medium),
            min_confidence: None,
            rule: None,
            sort: DetectSortArg::Rule,
        });
        assert_eq!(
            findings.iter().filter(|f| filter.matches(f)).count(),
            2,
            "Medium 이상"
        );

        let modules = [
            module(
                "kernel32.dll",
                Some(r"C:\Windows\System32\kernel32.dll"),
                ProcessArch::X64,
            ),
            module("legacy.dll", None, ProcessArch::X86),
            module(
                "user32.dll",
                Some(r"C:\Windows\System32\user32.dll"),
                ProcessArch::X64,
            ),
        ];
        let filter = modules::build_filter(&ModulesArgs {
            pid: pid(1),
            pe: false,
            filter: Some("dll".to_string()),
            arch: Some(ArchArg::X64),
            unparsed: false,
            unloaded: false,
        });
        let pe_ok = [true, false, true];
        assert_eq!(
            modules
                .iter()
                .zip(pe_ok)
                .filter(|(module, ok)| filter.matches(module, *ok))
                .count(),
            2,
            "x64 이름 일치"
        );
    }
}
