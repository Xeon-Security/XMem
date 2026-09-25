//! CLI 트리. 전 명령의 인터페이스 계약을 여기서 확정한다.
use clap::{ArgGroup, Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "xmem",
    version = env!("CARGO_PKG_VERSION"),
    about = "XMem - Windows Memory Attack & Forensics Research Platform"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// machine-readable JSON 출력
    #[arg(long, global = true)]
    pub json: bool,
    /// 진단 로그 레벨 상향 (반복 지정 가능)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// 경고/오류만 출력
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// 색상 비활성화
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Debug, Args)]
pub struct PidArg {
    /// 대상 프로세스 PID
    #[arg(long)]
    pub pid: u32,
}

/// 결과 파일 내보내기 형식.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
}

impl ExportFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
        }
    }
}

/// 결과 파일 저장 옵션. 미지정 시 기존처럼 표준 출력으로 보낸다.
#[derive(Debug, Args)]
pub struct OutputArgs {
    /// 결과를 저장할 파일 (미지정 시 표준 출력)
    #[arg(long)]
    pub output: Option<String>,
    /// 파일 저장 형식
    #[arg(long, value_enum, default_value = "json")]
    pub format: ExportFormat,
}

#[derive(Debug, Args)]
pub struct MapArgs {
    #[command(flatten)]
    pub pid: PidArg,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct DetectArgs {
    #[command(flatten)]
    pub pid: PidArg,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct ModulesArgs {
    #[command(flatten)]
    pub pid: PidArg,
    /// 모듈 메모리 헤더에서 PE 정보(arch/entry/sections)를 파싱해 함께 표시한다
    #[arg(long)]
    pub pe: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 프로세스 열거/조회
    Process {
        #[command(subcommand)]
        cmd: ProcessCmd,
    },
    /// 가상 메모리 분석
    Memory {
        #[command(subcommand)]
        cmd: MemoryCmd,
    },
    /// 로드된 모듈 분석
    Modules(ModulesArgs),
    /// 스레드 분석
    Threads(PidArg),
    /// 메모리 스냅샷
    Snapshot {
        #[command(subcommand)]
        cmd: SnapshotCmd,
    },
    /// 미니덤프
    Dump {
        #[command(subcommand)]
        cmd: DumpCmd,
    },
    /// Detection Rule 실행
    Detect(DetectArgs),
    /// 분석 리포트 생성
    Report {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 경로
        #[arg(long)]
        output: String,
    },
    /// 연구 실험
    Experiment {
        #[command(subcommand)]
        cmd: ExperimentCmd,
    },
}

#[derive(Debug, Subcommand)]
pub enum ProcessCmd {
    /// 프로세스 목록
    List,
    /// 단일 프로세스 정보
    Info(PidArg),
}

#[derive(Debug, Subcommand)]
pub enum MemoryCmd {
    /// Virtual Memory Map
    Map(MapArgs),
    /// 메모리에서 패턴/문자열을 검색한다.
    Scan(ScanArgs),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("needle").required(true).multiple(false).args(["pattern", "string", "wide_string"])))]
pub struct ScanArgs {
    #[command(flatten)]
    pub pid: PidArg,
    /// 16진 바이트 패턴 (예: "48 8B ?? ?? C0")
    #[arg(long)]
    pub pattern: Option<String>,
    /// ASCII 문자열
    #[arg(long)]
    pub string: Option<String>,
    /// UTF-16LE 문자열
    #[arg(long = "wide-string")]
    pub wide_string: Option<String>,
    #[arg(long = "executable-only")]
    pub executable_only: bool,
    #[arg(long = "private-only")]
    pub private_only: bool,
    #[arg(long = "writable-only")]
    pub writable_only: bool,
    /// 검색할 주소 범위 (예: "0x1000:0x2000")
    #[arg(long)]
    pub range: Option<String>,
    /// 이 크기를 초과하는 영역은 건너뛴다 (예: "8Mi")
    #[arg(long = "max-region-size")]
    pub max_region_size: Option<String>,
    /// 영역 내 상대 오프셋이 정확히 N인 매치만 보고
    #[arg(long)]
    pub offset: Option<u64>,
    /// 최대 결과 수 (0 = 무제한, 기본 1024)
    #[arg(long = "max-results")]
    pub max_results: Option<usize>,
    /// 청크 크기 (기본 1Mi, 허용 4Ki~16Mi)
    #[arg(long = "chunk-size")]
    pub chunk_size: Option<String>,
    /// worker 스레드 수 (기본 min(논리CPU-1, 4))
    #[arg(long)]
    pub threads: Option<usize>,
    /// 대형 프로세스 정책을 해제하고 모든 committed 영역을 스캔
    #[arg(long)]
    pub all: bool,
    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Subcommand)]
pub enum SnapshotCmd {
    /// 스냅샷 생성
    Create {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 (.xmem)
        #[arg(long)]
        output: String,
    },
    /// 스냅샷 비교
    Diff { before: String, after: String },
}

#[derive(Debug, Subcommand)]
pub enum DumpCmd {
    /// 미니덤프 생성
    Create {
        #[command(flatten)]
        pid: PidArg,
        /// 출력 파일 (.dmp)
        #[arg(long)]
        output: String,
        /// 전체 메모리 포함 (크고 느림, 디스크 사전 검사)
        #[arg(long)]
        full: bool,
    },
    /// 미니덤프 분석
    Analyze { file: String },
}

#[derive(Debug, Subcommand)]
pub enum ExperimentCmd {
    /// 실험 목록
    List,
    /// 실험 실행
    Run { name: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn parses_process_list() {
        let cli = parse(&["xmem", "process", "list"]).unwrap();
        assert!(matches!(cli.command, Command::Process { .. }));
        assert!(!cli.global.json);
    }

    #[test]
    fn parses_memory_map_with_pid() {
        let cli = parse(&["xmem", "memory", "map", "--pid", "123"]).unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Map(args),
        } = cli.command
        else {
            panic!("expected memory map");
        };
        assert_eq!(args.pid.pid, 123);
        assert!(args.output.output.is_none());
        assert_eq!(args.output.format, ExportFormat::Json);
    }

    #[test]
    fn memory_map_parses_output_and_format() {
        let cli = parse(&[
            "xmem", "memory", "map", "--pid", "123", "--output", "out.csv", "--format", "csv",
        ])
        .unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Map(args),
        } = cli.command
        else {
            panic!("expected memory map");
        };
        assert_eq!(args.output.output.as_deref(), Some("out.csv"));
        assert_eq!(args.output.format, ExportFormat::Csv);
        assert_eq!(args.output.format.as_str(), "csv");
    }

    #[test]
    fn scan_and_detect_parse_output_flags() {
        let cli = parse(&[
            "xmem", "memory", "scan", "--pid", "42", "--string", "hi", "--output", "s.json",
        ])
        .unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Scan(args),
        } = cli.command
        else {
            panic!("expected scan");
        };
        assert_eq!(args.output.output.as_deref(), Some("s.json"));
        assert_eq!(args.output.format, ExportFormat::Json);

        let cli = parse(&[
            "xmem", "detect", "--pid", "42", "--output", "d.csv", "--format", "csv",
        ])
        .unwrap();
        let Command::Detect(args) = cli.command else {
            panic!("expected detect");
        };
        assert_eq!(args.pid.pid, 42);
        assert_eq!(args.output.output.as_deref(), Some("d.csv"));
        assert_eq!(args.output.format, ExportFormat::Csv);
    }

    #[test]
    fn missing_pid_is_usage_error() {
        let err = parse(&["xmem", "memory", "map"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn global_json_flag_is_global() {
        let cli = parse(&["xmem", "--json", "detect", "--pid", "1"]).unwrap();
        assert!(cli.global.json);
    }

    #[test]
    fn parses_snapshot_diff_paths() {
        let cli = parse(&["xmem", "snapshot", "diff", "a.xmem", "b.xmem"]).unwrap();
        let Command::Snapshot {
            cmd: SnapshotCmd::Diff { before, after },
        } = cli.command
        else {
            panic!("expected snapshot diff");
        };
        assert_eq!(before, "a.xmem");
        assert_eq!(after, "b.xmem");
    }

    #[test]
    fn parses_verbose_count() {
        let cli = parse(&["xmem", "-vv", "process", "list"]).unwrap();
        assert_eq!(cli.global.verbose, 2);
    }

    #[test]
    fn memory_scan_parses_pattern_and_filters() {
        let cli = Cli::try_parse_from([
            "xmem",
            "memory",
            "scan",
            "--pid",
            "42",
            "--pattern",
            "48 8B ??",
            "--executable-only",
            "--threads",
            "2",
        ])
        .unwrap();
        let Command::Memory { cmd } = cli.command else {
            panic!("memory 명령이 아님");
        };
        let MemoryCmd::Scan(args) = cmd else {
            panic!("scan 명령이 아님");
        };
        assert_eq!(args.pid.pid, 42);
        assert_eq!(args.pattern.as_deref(), Some("48 8B ??"));
        assert!(args.executable_only);
        assert_eq!(args.threads, Some(2));
    }

    #[test]
    fn memory_scan_requires_exactly_one_needle() {
        assert!(Cli::try_parse_from(["xmem", "memory", "scan", "--pid", "42"]).is_err());
        assert!(
            Cli::try_parse_from([
                "xmem",
                "memory",
                "scan",
                "--pid",
                "42",
                "--pattern",
                "90",
                "--string",
                "hi"
            ])
            .is_err()
        );
    }

    #[test]
    fn modules_pe_flag_parses() {
        let cli = parse(&["xmem", "modules", "--pid", "42", "--pe"]).unwrap();
        let Command::Modules(args) = cli.command else {
            panic!("modules 명령이 아님");
        };
        assert_eq!(args.pid.pid, 42);
        assert!(args.pe);
    }

    #[test]
    fn modules_pe_defaults_to_false() {
        let cli = parse(&["xmem", "modules", "--pid", "42"]).unwrap();
        let Command::Modules(args) = cli.command else {
            panic!("modules 명령이 아님");
        };
        assert!(!args.pe);
    }

    #[test]
    fn parses_dump_create_with_full_flag() {
        let cli = parse(&[
            "xmem", "dump", "create", "--pid", "42", "--output", "t.dmp", "--full",
        ])
        .unwrap();
        let Command::Dump { cmd } = cli.command else {
            panic!("dump가 아님");
        };
        let DumpCmd::Create { pid, output, full } = cmd else {
            panic!("create가 아님");
        };
        assert_eq!(pid.pid, 42);
        assert_eq!(output, "t.dmp");
        assert!(full);
    }
}
