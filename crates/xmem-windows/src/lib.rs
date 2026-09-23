//! XMem Win32 abstraction layer. All `unsafe` in XMem lives here.
#![allow(unsafe_code)] // SAFETY: Win32 FFI 경계는 이 crate로 격리한다.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod handle;
pub mod process;

pub use error::{error_from_win32, last_win32_error, map_win32, win32_code_from_hresult};
pub use handle::OwnedHandle;
