//! XMem Win32 abstraction layer. All `unsafe` in XMem lives here.
#![allow(unsafe_code)] // SAFETY: Win32 FFI 경계는 이 crate로 격리한다.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod disk;
pub mod dump;
pub mod error;
pub mod handle;
pub mod memory;
pub mod process;
pub mod read;
pub mod remotemem;
pub mod selfmem;
pub mod threads;
pub mod token;
pub mod toolhelp;
pub mod util;

pub use disk::free_space_bytes;
pub use dump::{create_file_for_write, validate_minidump, write_minidump, write_minidump_file};
pub use error::{error_from_win32, last_win32_error, map_win32, win32_code_from_hresult};
pub use handle::OwnedHandle;
pub use process::{
    current_pid, current_rss_bytes, is_alive, list_processes, open_for_dump, open_for_experiment,
    open_for_query, open_for_read, open_process, process_info,
};
pub use remotemem::{
    alloc_remote, flush_instruction_cache, free_remote, protect_remote, write_remote,
};
pub use selfmem::{
    PrivateRegion, SELF_PAGE_RW, SELF_PAGE_RWX, SELF_PAGE_RX, alloc_executable,
    spawn_suspended_thread, thread_id,
};
pub use threads::{
    RawThreadEntry, create_remote_thread, list_raw_threads, open_thread, open_thread_for_query,
    thread_priority, thread_start_address,
};
pub use toolhelp::{RawModuleEntry, count_modules, list_raw_modules};
