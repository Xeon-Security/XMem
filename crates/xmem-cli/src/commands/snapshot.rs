use crate::cli::{GlobalArgs, SnapshotCmd};
use xmem_core::Result;

pub fn run(cmd: &SnapshotCmd, _global: &GlobalArgs) -> Result<()> {
    let feature = match cmd {
        SnapshotCmd::Create { .. } => "snapshot create",
        SnapshotCmd::Diff { .. } => "snapshot diff",
    };
    super::unimplemented(feature)
}
