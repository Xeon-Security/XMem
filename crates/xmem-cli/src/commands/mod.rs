pub mod detect;
pub mod dump;
pub mod experiment;
pub mod memory;
pub mod modules;
pub mod process;
pub(crate) mod render;
pub mod report;
pub mod snapshot;
pub mod threads;

use xmem_core::{Result, XmemError};

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

pub(crate) fn unimplemented(feature: &'static str) -> Result<()> {
    Err(XmemError::Unimplemented { feature })
}
