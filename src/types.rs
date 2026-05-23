//! Public value types (mirrors `types.hpp`).

#[cfg(not(feature = "no_hash"))]
pub type SyscallKey = crate::hash::Hash;

#[cfg(feature = "no_hash")]
pub type SyscallKey = std::string::String;

/// Snapshot of a loaded PE module's important pointers (Windows only).
#[cfg(windows)]
#[derive(Copy, Clone)]
pub struct ModuleInfo {
    pub base: *mut u8,
    pub nt_headers: *const crate::shared::ImageNtHeaders,
    pub export_dir: *const crate::shared::ImageExportDirectory,
}

#[cfg(windows)]
unsafe impl Send for ModuleInfo {}
#[cfg(windows)]
unsafe impl Sync for ModuleInfo {}

/// Placeholder on Linux — syscall numbers come from a static table.
#[cfg(target_os = "linux")]
#[derive(Copy, Clone)]
pub struct ModuleInfo;

#[cfg(target_os = "linux")]
unsafe impl Send for ModuleInfo {}
#[cfg(target_os = "linux")]
unsafe impl Sync for ModuleInfo {}

#[derive(Clone, Debug)]
pub struct SyscallEntry {
    pub key: SyscallKey,
    pub syscall_number: u32,
    pub offset: u32,
}
