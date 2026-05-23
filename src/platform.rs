//! Platform / arch detection mirroring `platform.hpp`.

pub const IS_WINDOWS: bool = cfg!(windows);
pub const IS_WINDOWS_64: bool = cfg!(all(windows, target_pointer_width = "64"));
pub const IS_WINDOWS_32: bool = cfg!(all(windows, target_pointer_width = "32"));

pub const IS_LINUX: bool = cfg!(target_os = "linux");
pub const IS_LINUX_64: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("syscalls-rs only supports Windows and Linux targets.");

#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
compile_error!("syscalls-rs on Linux only supports x86_64.");
