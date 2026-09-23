use crate::cli::{ExperimentCmd, GlobalArgs};
use xmem_core::Result;

pub fn run(cmd: &ExperimentCmd, _global: &GlobalArgs) -> Result<()> {
    let feature = match cmd {
        ExperimentCmd::List => "experiment list",
        ExperimentCmd::Run { .. } => "experiment run",
    };
    super::unimplemented(feature)
}
