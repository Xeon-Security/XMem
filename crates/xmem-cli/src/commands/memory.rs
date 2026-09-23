use crate::cli::{GlobalArgs, MemoryCmd};
use xmem_core::Result;

pub fn run(cmd: &MemoryCmd, _global: &GlobalArgs) -> Result<()> {
    let feature = match cmd {
        MemoryCmd::Map(_) => "memory map",
        MemoryCmd::Scan(_) => "memory scan",
    };
    super::unimplemented(feature)
}
