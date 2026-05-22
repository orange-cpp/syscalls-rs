//! Public value types (mirrors `types.hpp`).

use crate::shared::{ImageExportDirectory, ImageNtHeaders};

#[cfg(not(feature = "no_hash"))]
pub type SyscallKey = crate::hash::Hash;

#[cfg(feature = "no_hash")]
pub type SyscallKey = std::string::String;

/// Snapshot of a loaded PE module's important pointers.
#[derive(Copy, Clone)]
pub struct ModuleInfo {
    pub base: *mut u8,
    pub nt_headers: *const ImageNtHeaders,
    pub export_dir: *const ImageExportDirectory,
}

unsafe impl Send for ModuleInfo {}
unsafe impl Sync for ModuleInfo {}

#[derive(Clone, Debug)]
pub struct SyscallEntry {
    pub key: SyscallKey,
    pub syscall_number: u32,
    pub offset: u32,
}
