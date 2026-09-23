//! XMem Win32 abstraction layer. All `unsafe` in XMem lives here.
#![allow(unsafe_code)] // SAFETY: Win32 FFI 경계는 이 crate로 격리한다.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod handle;
pub mod memory;
pub mod process;
pub mod read;
pub mod token;
pub mod toolhelp;
pub mod util;

pub use error::{error_from_win32, last_win32_error, map_win32, win32_code_from_hresult};
pub use handle::OwnedHandle;
pub use process::{
    current_pid, is_alive, list_processes, open_for_query, open_for_read, open_process,
    process_info,
};
pub use toolhelp::{RawModuleEntry, count_modules, list_raw_modules};
