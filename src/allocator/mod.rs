//! Allocator policies.
//!
//! Each policy provides a way to obtain an executable buffer holding the
//! generated syscall stubs.

use core::ffi::c_void;

#[cfg(windows)]
pub mod heap;
pub mod memory;
#[cfg(windows)]
pub mod section;

#[cfg(windows)]
pub use heap::Heap;
pub use memory::Memory;
#[cfg(windows)]
pub use section::Section;

/// On Linux, `Section` is an alias for `Memory` (mmap-based).
#[cfg(target_os = "linux")]
pub type Section = Memory;
/// On Linux, `Heap` is an alias for `Memory` (mmap-based).
#[cfg(target_os = "linux")]
pub type Heap = Memory;

/// Handle pair returned by an allocator and consumed on release.
pub struct AllocatedRegion {
    pub region: *mut c_void,
    /// On Windows: NT HANDLE. On Linux: region size (needed for munmap).
    pub aux: usize,
}

unsafe impl Send for AllocatedRegion {}
unsafe impl Sync for AllocatedRegion {}

pub trait Allocator {
    fn allocate(buffer: &[u8]) -> Option<AllocatedRegion>;
    fn release(region: AllocatedRegion);
}
