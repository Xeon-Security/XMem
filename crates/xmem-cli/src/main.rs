#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod cli;
mod commands;
mod output;

use clap::Parser;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;
use xmem_core::XmemError;

use cli::Cli;
use output::{OutputMode, error_envelope, resolve_mode};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli);

    match commands::dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            report_error(&err, resolve_mode(cli.global.json));
            exit_code_for(&err)
        }
    }
}

fn init_tracing(cli: &Cli) {
    let default_level = if cli.global.quiet {
        "error"
    } else {
        match cli.global.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn report_error(err: &XmemError, mode: OutputMode) {
    match mode {
        OutputMode::Json => {
            println!("{}", error_envelope(err));
        }
        OutputMode::Human => {
            eprintln!("error: {err}");
            let mut source = std::error::Error::source(err);
            while let Some(inner) = source {
                eprintln!("  caused by: {inner}");
                source = inner.source();
            }
        }
    }
}

fn exit_code_for(err: &XmemError) -> ExitCode {
    match err {
        XmemError::PolicyDenied { .. } => ExitCode::from(3),
        _ => ExitCode::from(1),
    }
}
