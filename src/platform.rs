//! Platform / arch detection mirroring `platform.hpp`.

pub const IS_WINDOWS: bool = cfg!(windows);
pub const IS_WINDOWS_64: bool = cfg!(all(windows, target_pointer_width = "64"));
pub const IS_WINDOWS_32: bool = cfg!(all(windows, target_pointer_width = "32"));

#[cfg(not(windows))]
compile_error!("syscalls-rs only supports Windows targets.");
