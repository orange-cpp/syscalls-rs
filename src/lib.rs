//! syscalls-rs — Rust port of [syscalls-cpp](https://github.com/sapdragon/syscalls-cpp).
//!
//! Policy-based framework for crafting direct syscalls.
//!
//! - **Windows** (x86/x64): Parses syscall numbers from ntdll.dll at runtime.
//!   Supports Direct, Gadget, and Exception stub generators with Section, Heap,
//!   and Memory allocators.
//! - **Linux** (x86_64): Uses a built-in syscall number table with Direct stubs
//!   and mmap-based memory allocation.
//!
//! # Quick start (Windows)
//! ```no_run,ignore
//! use core::ffi::c_void;
//! use windows_sys::Win32::Foundation::NTSTATUS;
//! use syscalls_rs::prelude::*;
//!
//! type Mgr = Manager<Section, Direct>;
//! let mgr = Mgr::new();
//! assert!(mgr.initialize());
//!
//! let inv = mgr.invoke(syscalls_rs::syscall_id!("NtAllocateVirtualMemory")).unwrap();
//! type NtAlloc = unsafe extern "C" fn(
//!     isize, *mut *mut c_void, usize, *mut usize, u32, u32,
//! ) -> NTSTATUS;
//! let f: NtAlloc = unsafe { inv.as_fn() };
//! ```
//!
//! # Quick start (Linux)
//! ```no_run,ignore
//! use syscalls_rs::prelude::*;
//!
//! type Mgr = Manager<Memory, Direct>;
//! let mgr = Mgr::new();
//! assert!(mgr.initialize());
//!
//! let inv = mgr.invoke(syscalls_rs::syscall_id!("write")).unwrap();
//! type WriteFn = unsafe extern "C" fn(u64, *const u8, u64, u64, u64, u64) -> i64;
//! let f: WriteFn = unsafe { inv.as_fn() };
//! let _ = unsafe { f(1, b"hello\n".as_ptr(), 6, 0, 0, 0) };
//! ```
//!
//! Configuration:
//! - Enable the `no_hash` Cargo feature to use `String` syscall keys
//!   instead of compile-time `u64` hashes (mirrors `-DSYSCALLS_NO_HASH`).

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

pub mod allocator;
pub mod generator;
pub mod hash;
pub mod manager;
pub mod native;
pub mod parser;
pub mod platform;
pub mod shared;
pub mod types;

pub use manager::{Invocation, Manager};

/// Default policy aliases.
pub mod aliases {
    use crate::allocator::{Memory, Section};
    use crate::generator::Direct;
    use crate::manager::Manager;
    use crate::parser::DefaultChain;

    pub type SectionDirectManager = Manager<Section, Direct, DefaultChain>;
    pub type MemoryDirectManager = Manager<Memory, Direct, DefaultChain>;

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub type SectionGadgetManager = Manager<Section, crate::generator::Gadget, DefaultChain>;

    #[cfg(all(windows, target_pointer_width = "64"))]
    pub type HeapGadgetManager =
        Manager<crate::allocator::Heap, crate::generator::Gadget, DefaultChain>;
}

/// Re-exports for typical usage.
pub mod prelude {
    pub use crate::aliases::*;
    pub use crate::allocator::{Heap, Memory, Section};
    pub use crate::generator::Direct;
    #[cfg(windows)]
    pub use crate::generator::Exception;
    #[cfg(all(windows, target_pointer_width = "64"))]
    pub use crate::generator::Gadget;
    pub use crate::manager::Manager;
    pub use crate::parser::DefaultChain;
    pub use crate::parser::Table;
    #[cfg(windows)]
    pub use crate::parser::{Directory, Signature};
}
