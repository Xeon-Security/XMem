//! CLI 트리. 전 명령의 인터페이스 계약을 여기서 확정한다.
use clap::{Args, Parser, Subcommand};

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
    Modules(PidArg),
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
    Detect(PidArg),
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
    Map(PidArg),
    /// 메모리 패턴/문자열 검색
    Scan(PidArg),
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
        assert_eq!(args.pid, 123);
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
}
