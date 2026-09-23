use crate::cli::{GlobalArgs, ProcessCmd};
use xmem_core::Result;

pub fn run(cmd: &ProcessCmd, _global: &GlobalArgs) -> Result<()> {
    let feature = match cmd {
        ProcessCmd::List => "process list",
        ProcessCmd::Info(_) => "process info",
    };
    super::unimplemented(feature)
}
