//! CLI 트리. 전 명령의 인터페이스 계약을 여기서 확정한다.
use clap::{ArgGroup, Args, Parser, Subcommand};
use xmem_core::{
    Confidence, Heuristic, MemoryState, ProcessArch, ProtectionMask, RegionClass, Severity,
};

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

/// `--state` 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum StateArg {
    #[value(name = "commit")]
    Commit,
    #[value(name = "reserve")]
    Reserve,
    #[value(name = "free")]
    Free,
}

impl StateArg {
    pub fn to_state(self) -> MemoryState {
        match self {
            StateArg::Commit => MemoryState::Commit,
            StateArg::Reserve => MemoryState::Reserve,
            StateArg::Free => MemoryState::Free,
        }
    }
}

/// `--class` 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ClassArg {
    #[value(name = "image")]
    Image,
    #[value(name = "mapped")]
    Mapped,
    #[value(name = "private")]
    Private,
}

impl ClassArg {
    pub fn to_class(self) -> RegionClass {
        match self {
            ClassArg::Image => RegionClass::Image,
            ClassArg::Mapped => RegionClass::Mapped,
            ClassArg::Private => RegionClass::Private,
        }
    }
}

/// `--prot` 값. Windows 보호 비트의 R/W/X 표기를 그대로 받는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProtArg {
    #[value(name = "rwx")]
    Rwx,
    #[value(name = "r-x")]
    Rx,
    #[value(name = "rw-")]
    Rw,
    #[value(name = "r--")]
    R,
    #[value(name = "x")]
    X,
    #[value(name = "---")]
    None,
}

impl ProtArg {
    pub fn to_mask(self) -> ProtectionMask {
        match self {
            ProtArg::Rwx => ProtectionMask::Rwx,
            ProtArg::Rx => ProtectionMask::Rx,
            ProtArg::Rw => ProtectionMask::Rw,
            ProtArg::R => ProtectionMask::R,
            ProtArg::X => ProtectionMask::X,
            ProtArg::None => ProtectionMask::None,
        }
    }
}

/// `--heuristic` 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HeuristicArg {
    #[value(name = "exec-private")]
    ExecPrivate,
    #[value(name = "exec-anon")]
    ExecAnon,
    #[value(name = "pe-like")]
    PeLike,
    #[value(name = "wx")]
    Wx,
}

impl HeuristicArg {
    pub fn to_heuristic(self) -> Heuristic {
        match self {
            HeuristicArg::ExecPrivate => Heuristic::ExecutablePrivate,
            HeuristicArg::ExecAnon => Heuristic::ExecutableAnonymous,
            HeuristicArg::PeLike => Heuristic::PrivateExecutablePeLike,
            HeuristicArg::Wx => Heuristic::WritableExecutable,
        }
    }
}

/// 프로세스/모듈 아키텍처 값. x64/x86만 지원한다(ARM64는 범위 밖).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ArchArg {
    #[value(name = "x64")]
    X64,
    #[value(name = "x86")]
    X86,
}

impl ArchArg {
    pub fn to_arch(self) -> ProcessArch {
        match self {
            ArchArg::X64 => ProcessArch::X64,
            ArchArg::X86 => ProcessArch::X86,
        }
    }
}

/// `memory map --sort` 값. GUI `MapSort`와 같은 순서를 만든다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MapSortArg {
    #[value(name = "addr")]
    Addr,
    #[value(name = "addr-desc")]
    AddrDesc,
    #[value(name = "size-desc")]
    SizeDesc,
}

/// `detect --sort` 값. 기본 rule은 기존 rule→주소 순서를 유지한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DetectSortArg {
    #[value(name = "severity")]
    Severity,
    #[value(name = "address")]
    Address,
    #[value(name = "rule")]
    Rule,
}

/// `--min-severity` 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SeverityArg {
    #[value(name = "info")]
    Info,
    #[value(name = "low")]
    Low,
    #[value(name = "medium")]
    Medium,
    #[value(name = "high")]
    High,
    #[value(name = "critical")]
    Critical,
}

impl SeverityArg {
    pub fn to_severity(self) -> Severity {
        match self {
            SeverityArg::Info => Severity::Info,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

/// `--min-confidence` 값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConfidenceArg {
    #[value(name = "low")]
    Low,
    #[value(name = "medium")]
    Medium,
    #[value(name = "high")]
    High,
}

impl ConfidenceArg {
    pub fn to_confidence(self) -> Confidence {
        match self {
            ConfidenceArg::Low => Confidence::Low,
            ConfidenceArg::Medium => Confidence::Medium,
            ConfidenceArg::High => Confidence::High,
        }
    }
}

#[derive(Debug, Args)]
pub struct MapArgs {
    #[command(flatten)]
    pub pid: PidArg,
    #[command(flatten)]
    pub output: OutputArgs,
    /// 읽기 가능 영역만
    #[arg(long = "readable-only")]
    pub readable_only: bool,
    /// 쓰기 가능 영역만
    #[arg(long = "writable-only")]
    pub writable_only: bool,
    /// 실행 가능 영역만
    #[arg(long = "executable-only")]
    pub executable_only: bool,
    /// 메모리 상태 필터
    #[arg(long, value_enum)]
    pub state: Option<StateArg>,
    /// 분류 필터
    #[arg(long, value_enum)]
    pub class: Option<ClassArg>,
    /// 보호 속성 필터 (rwx|r-x|rw-|r--|x|---)
    #[arg(long = "prot", value_enum, allow_hyphen_values = true)]
    pub protection: Option<ProtArg>,
    /// heuristic 태그 필터
    #[arg(long, value_enum)]
    pub heuristic: Option<HeuristicArg>,
    /// PE-like private executable 영역만
    #[arg(long = "pe-like")]
    pub pe_like: bool,
    /// 로드된 모듈 범위 밖 영역만 (모듈 목록이 비면 매칭 없음)
    #[arg(long = "outside-modules")]
    pub outside_modules: bool,
    /// 파일 백킹이 관찰된 영역만
    #[arg(long = "mapped-only")]
    pub mapped_only: bool,
    /// 주소 범위 겹침 필터 (예: "0x1000:0x2000")
    #[arg(long)]
    pub range: Option<String>,
    /// 최소 영역 크기 (접미사 허용: 4096, 4Ki, 8Mi)
    #[arg(long = "min-size")]
    pub min_size: Option<String>,
    /// 최대 영역 크기 (접미사 허용: 4096, 4Ki, 8Mi)
    #[arg(long = "max-size")]
    pub max_size: Option<String>,
    /// 정렬 순서
    #[arg(long, value_enum, default_value = "addr")]
    pub sort: MapSortArg,
}

#[derive(Debug, Args)]
pub struct DetectArgs {
    #[command(flatten)]
    pub pid: PidArg,
    #[command(flatten)]
    pub output: OutputArgs,
    /// 최소 severity
    #[arg(long = "min-severity", value_enum)]
    pub min_severity: Option<SeverityArg>,
    /// 최소 confidence
    #[arg(long = "min-confidence", value_enum)]
    pub min_confidence: Option<ConfidenceArg>,
    /// 특정 rule ID만
    #[arg(long)]
    pub rule: Option<String>,
    /// 정렬 순서
    #[arg(long, value_enum, default_value = "rule")]
    pub sort: DetectSortArg,
}

#[derive(Debug, Args)]
pub struct ModulesArgs {
    #[command(flatten)]
    pub pid: PidArg,
    /// 모듈 메모리 헤더에서 PE 정보(arch/entry/sections)를 파싱해 함께 표시한다
    #[arg(long)]
    pub pe: bool,
    /// 이름/경로에 SUBSTR이 포함된 모듈만
    #[arg(long = "filter")]
    pub filter: Option<String>,
    /// 모듈 아키텍처 필터
    #[arg(long, value_enum)]
    pub arch: Option<ArchArg>,
    /// PE 파싱에 실패한 모듈만
    #[arg(long)]
    pub unparsed: bool,
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
    Threads(ThreadsArgs),
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

#[derive(Debug, Args)]
pub struct ProcessListArgs {
    /// 메모리를 읽을 수 있는 프로세스만 표시
    #[arg(long)]
    pub accessible_only: bool,
    /// 이름에 SUBSTR이 포함된 프로세스만
    #[arg(long)]
    pub name: Option<String>,
    /// 아키텍처 필터
    #[arg(long, value_enum)]
    pub arch: Option<ArchArg>,
    /// 세션 ID 필터
    #[arg(long)]
    pub session: Option<u32>,
    /// 사용자 이름에 SUBSTR이 포함된 프로세스만
    #[arg(long)]
    pub user: Option<String>,
    /// 중요 프로세스 보호 목록에 있는 프로세스만
    #[arg(long)]
    pub protected: bool,
    /// 부모 PID 필터
    #[arg(long)]
    pub ppid: Option<u32>,
}

#[derive(Debug, Args)]
pub struct ThreadsArgs {
    #[command(flatten)]
    pub pid: PidArg,
    /// 시작 주소를 조회할 수 있는 스레드만
    #[arg(long = "with-start")]
    pub with_start: bool,
    /// 모듈 밖 시작 주소를 가진 스레드만 (suspicious)
    #[arg(long)]
    pub suspicious: bool,
    /// 특정 TID만
    #[arg(long)]
    pub tid: Option<u32>,
}

#[derive(Debug, Subcommand)]
pub enum ProcessCmd {
    /// 프로세스 목록
    List(ProcessListArgs),
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
    Diff {
        before: String,
        after: String,
        /// 표시할 섹션 (콤마 목록: regions,content,modules,threads,detections; 미지정 시 전체)
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
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
        let Command::Process { cmd } = cli.command else {
            panic!("process 명령이 아님");
        };
        let ProcessCmd::List(args) = cmd else {
            panic!("list 명령이 아님");
        };
        assert!(!args.accessible_only);
        assert!(!cli.global.json);
    }

    #[test]
    fn parses_process_list_accessible_only() {
        let cli = parse(&["xmem", "process", "list", "--accessible-only"]).unwrap();
        let Command::Process { cmd } = cli.command else {
            panic!("process 명령이 아님");
        };
        let ProcessCmd::List(args) = cmd else {
            panic!("list 명령이 아님");
        };
        assert!(args.accessible_only);
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
    fn parses_snapshot_diff_paths_and_only_sections() {
        let cli = parse(&["xmem", "snapshot", "diff", "a.xmem", "b.xmem"]).unwrap();
        let Command::Snapshot {
            cmd:
                SnapshotCmd::Diff {
                    before,
                    after,
                    only,
                },
        } = cli.command
        else {
            panic!("expected snapshot diff");
        };
        assert_eq!(before, "a.xmem");
        assert_eq!(after, "b.xmem");
        assert!(only.is_empty(), "미지정이면 전체");

        let cli = parse(&[
            "xmem",
            "snapshot",
            "diff",
            "a.xmem",
            "b.xmem",
            "--only",
            "regions,content",
        ])
        .unwrap();
        let Command::Snapshot {
            cmd: SnapshotCmd::Diff { only, .. },
        } = cli.command
        else {
            panic!("expected snapshot diff");
        };
        assert_eq!(only, vec!["regions".to_string(), "content".to_string()]);
    }

    #[test]
    fn memory_map_parses_filter_flags_and_sort() {
        let cli = parse(&[
            "xmem",
            "memory",
            "map",
            "--pid",
            "7",
            "--readable-only",
            "--writable-only",
            "--executable-only",
            "--state",
            "commit",
            "--class",
            "image",
            "--prot",
            "r-x",
            "--heuristic",
            "pe-like",
            "--pe-like",
            "--outside-modules",
            "--mapped-only",
            "--range",
            "0x1000:0x2000",
            "--min-size",
            "4096",
            "--max-size",
            "1048576",
            "--sort",
            "size-desc",
        ])
        .unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Map(args),
        } = cli.command
        else {
            panic!("expected memory map");
        };
        assert!(args.readable_only && args.writable_only && args.executable_only);
        assert_eq!(args.state, Some(StateArg::Commit));
        assert_eq!(args.class, Some(ClassArg::Image));
        assert_eq!(args.protection, Some(ProtArg::Rx));
        assert_eq!(args.heuristic, Some(HeuristicArg::PeLike));
        assert!(args.pe_like && args.outside_modules && args.mapped_only);
        assert_eq!(args.range.as_deref(), Some("0x1000:0x2000"));
        assert_eq!(args.min_size.as_deref(), Some("4096"));
        assert_eq!(args.max_size.as_deref(), Some("1048576"));
        assert_eq!(args.sort, MapSortArg::SizeDesc);
    }

    #[test]
    fn memory_map_defaults_to_unfiltered_address_sort() {
        let cli = parse(&["xmem", "memory", "map", "--pid", "7"]).unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Map(args),
        } = cli.command
        else {
            panic!("expected memory map");
        };
        assert!(!args.readable_only && !args.writable_only && !args.executable_only);
        assert!(!args.pe_like && !args.outside_modules && !args.mapped_only);
        assert_eq!(args.state, None);
        assert_eq!(args.class, None);
        assert_eq!(args.protection, None);
        assert_eq!(args.heuristic, None);
        assert_eq!(args.range, None);
        assert_eq!(args.min_size, None);
        assert_eq!(args.max_size, None);
        assert_eq!(args.sort, MapSortArg::Addr);
    }

    #[test]
    fn memory_map_prot_accepts_no_access_and_rejects_unknown() {
        let cli = parse(&["xmem", "memory", "map", "--pid", "7", "--prot", "---"]).unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Map(args),
        } = cli.command
        else {
            panic!("expected memory map");
        };
        assert_eq!(args.protection, Some(ProtArg::None));

        let cli = parse(&["xmem", "memory", "map", "--pid", "7", "--prot", "x"]).unwrap();
        let Command::Memory {
            cmd: MemoryCmd::Map(args),
        } = cli.command
        else {
            panic!("expected memory map");
        };
        assert_eq!(args.protection, Some(ProtArg::X));

        assert!(parse(&["xmem", "memory", "map", "--pid", "7", "--prot", "xx"]).is_err());
        assert!(parse(&["xmem", "memory", "map", "--pid", "7", "--state", "bogus"]).is_err());
        assert!(parse(&["xmem", "memory", "map", "--pid", "7", "--class", "bogus"]).is_err());
        assert!(
            parse(&[
                "xmem",
                "memory",
                "map",
                "--pid",
                "7",
                "--heuristic",
                "bogus"
            ])
            .is_err()
        );
        assert!(parse(&["xmem", "memory", "map", "--pid", "7", "--sort", "bogus"]).is_err());
    }

    #[test]
    fn process_list_parses_filters() {
        let cli = parse(&[
            "xmem",
            "process",
            "list",
            "--name",
            "svc",
            "--arch",
            "x86",
            "--session",
            "2",
            "--user",
            "sys",
            "--protected",
            "--ppid",
            "4",
            "--accessible-only",
        ])
        .unwrap();
        let Command::Process { cmd } = cli.command else {
            panic!("process 명령이 아님");
        };
        let ProcessCmd::List(args) = cmd else {
            panic!("list 명령이 아님");
        };
        assert_eq!(args.name.as_deref(), Some("svc"));
        assert_eq!(args.arch, Some(ArchArg::X86));
        assert_eq!(args.session, Some(2));
        assert_eq!(args.user.as_deref(), Some("sys"));
        assert!(args.protected);
        assert_eq!(args.ppid, Some(4));
        assert!(args.accessible_only);
        assert!(parse(&["xmem", "process", "list", "--arch", "arm64"]).is_err());
    }

    #[test]
    fn modules_parses_filters() {
        let cli = parse(&[
            "xmem",
            "modules",
            "--pid",
            "42",
            "--filter",
            "kernel",
            "--arch",
            "x64",
            "--unparsed",
        ])
        .unwrap();
        let Command::Modules(args) = cli.command else {
            panic!("modules 명령이 아님");
        };
        assert_eq!(args.filter.as_deref(), Some("kernel"));
        assert_eq!(args.arch, Some(ArchArg::X64));
        assert!(args.unparsed);
    }

    #[test]
    fn threads_parses_filters() {
        let cli = parse(&[
            "xmem",
            "threads",
            "--pid",
            "5",
            "--with-start",
            "--suspicious",
            "--tid",
            "9",
        ])
        .unwrap();
        let Command::Threads(args) = cli.command else {
            panic!("threads 명령이 아님");
        };
        assert_eq!(args.pid.pid, 5);
        assert!(args.with_start);
        assert!(args.suspicious);
        assert_eq!(args.tid, Some(9));
    }

    #[test]
    fn detect_parses_filters_and_sort() {
        let cli = parse(&[
            "xmem",
            "detect",
            "--pid",
            "42",
            "--min-severity",
            "high",
            "--min-confidence",
            "medium",
            "--rule",
            "XMEM-003",
            "--sort",
            "severity",
        ])
        .unwrap();
        let Command::Detect(args) = cli.command else {
            panic!("detect 명령이 아님");
        };
        assert_eq!(args.min_severity, Some(SeverityArg::High));
        assert_eq!(args.min_confidence, Some(ConfidenceArg::Medium));
        assert_eq!(args.rule.as_deref(), Some("XMEM-003"));
        assert_eq!(args.sort, DetectSortArg::Severity);
        assert!(parse(&["xmem", "detect", "--pid", "42", "--min-severity", "bogus"]).is_err());
        assert!(parse(&["xmem", "detect", "--pid", "42", "--min-confidence", "bogus"]).is_err());
        assert!(parse(&["xmem", "detect", "--pid", "42", "--sort", "bogus"]).is_err());
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
