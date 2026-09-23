use crate::cli::{DumpCmd, GlobalArgs};
use xmem_core::Result;

pub fn run(cmd: &DumpCmd, _global: &GlobalArgs) -> Result<()> {
    let feature = match cmd {
        DumpCmd::Create { .. } => "dump create",
        DumpCmd::Analyze { .. } => "dump analyze",
    };
    super::unimplemented(feature)
}
