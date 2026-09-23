use crate::cli::{GlobalArgs, PidArg};
use xmem_core::Result;

pub fn run(_pid: &PidArg, _output: &str, _global: &GlobalArgs) -> Result<()> {
    super::unimplemented("report")
}
