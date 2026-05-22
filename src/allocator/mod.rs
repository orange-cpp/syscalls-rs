//! Allocator policies.
//!
//! Each policy provides a way to obtain an executable buffer holding the
//! generated syscall stubs. Implementations mirror `allocator/{section,heap,memory}.hpp`.

use core::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;

pub mod heap;
pub mod memory;
pub mod section;

pub use heap::Heap;
pub use memory::Memory;
pub use section::Section;

/// Handle pair returned by an allocator and consumed on release.
pub struct AllocatedRegion {
    pub region: *mut c_void,
    pub handle: HANDLE,
}

unsafe impl Send for AllocatedRegion {}
unsafe impl Sync for AllocatedRegion {}

pub trait Allocator {
    fn allocate(buffer: &[u8]) -> Option<AllocatedRegion>;
    fn release(region: AllocatedRegion);
}
