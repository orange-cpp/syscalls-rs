//! Stub generation policies (mirrors `generator/{direct,gadget,exception}.hpp`).

use core::ffi::c_void;

pub mod direct;
#[cfg(windows)]
pub mod exception;
#[cfg(all(windows, target_pointer_width = "64"))]
pub mod gadget;

pub use direct::Direct;
#[cfg(windows)]
pub use exception::Exception;
#[cfg(all(windows, target_pointer_width = "64"))]
pub use gadget::Gadget;

pub trait StubGenerator {
    /// Whether the manager must locate `syscall; ret` gadgets in ntdll.
    const REQUIRES_GADGET: bool;
    /// Whether invocations route through the vectored exception handler.
    const IS_EXCEPTION: bool = false;
    /// Stub size in bytes.
    fn stub_size() -> usize;
    /// Write a stub into `buffer` (`buffer.len() == stub_size()`).
    fn generate(buffer: &mut [u8], syscall_number: u32, gadget: *mut c_void);
}
