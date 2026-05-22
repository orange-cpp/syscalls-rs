//! syscalls-rs — Rust port of [syscalls-cpp](https://github.com/sapdragon/syscalls-cpp).
//!
//! Policy-based framework for crafting undetectable/protected Windows
//! syscalls (x86 / x64). Mix and match an allocator, a stub generator, and
//! one or more parsers via the generic [`Manager`] type.
//!
//! # Quick start
//! ```no_run
//! use core::ffi::c_void;
//! use windows_sys::Win32::Foundation::NTSTATUS;
//! use syscalls_rs::prelude::*;
//!
//! type Mgr = Manager<Section, Direct>;
//! let mgr = Mgr::new();
//! assert!(mgr.initialize());
//!
//! let inv = mgr.invoke(syscalls_rs::syscall_id!("NtAllocateVirtualMemory")).unwrap();
//! type NtAlloc = unsafe extern "system" fn(
//!     isize, *mut *mut c_void, usize, *mut usize, u32, u32,
//! ) -> NTSTATUS;
//! let f: NtAlloc = unsafe { inv.as_fn() };
//! ```
//!
//! Configuration:
//! - Enable the `no_hash` Cargo feature to use `String` syscall keys
//!   instead of compile-time `u64` hashes (mirrors `-DSYSCALLS_NO_HASH`).

#![allow(clippy::missing_safety_doc)]

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

/// Default policy aliases (mirrors `aliases.hpp`).
pub mod aliases {
    use crate::allocator::{Section, /* Heap, */};
    use crate::generator::Direct;
    #[cfg(target_pointer_width = "64")]
    use crate::generator::Gadget;
    use crate::manager::Manager;
    use crate::parser::DefaultChain;

    pub type SectionDirectManager = Manager<Section, Direct, DefaultChain>;

    #[cfg(target_pointer_width = "64")]
    pub type SectionGadgetManager = Manager<Section, Gadget, DefaultChain>;

    #[cfg(target_pointer_width = "64")]
    pub type HeapGadgetManager = Manager<crate::allocator::Heap, Gadget, DefaultChain>;
}

/// Re-exports for typical usage.
pub mod prelude {
    pub use crate::aliases::*;
    pub use crate::allocator::{Heap, Memory, Section};
    pub use crate::generator::{Direct, Exception};
    #[cfg(target_pointer_width = "64")]
    pub use crate::generator::Gadget;
    pub use crate::manager::Manager;
    pub use crate::parser::{DefaultChain, Directory, Signature};
}
