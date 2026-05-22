# syscalls-rs

Rust port of [syscalls-cpp](https://github.com/sapdragon/syscalls-cpp): a
policy-based framework for crafting undetectable/protected Windows syscalls
(x86 / x64).

You mix and match three policies at compile time:

| Allocator        | What it uses                                              |
| ---------------- | --------------------------------------------------------- |
| `Section`        | `NtCreateSection` + `SEC_NO_CHANGE`                       |
| `Heap`           | `RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE)`               |
| `Memory`         | `NtAllocateVirtualMemory` (RW → RX)                       |

| Stub generator   | What it emits                                             |
| ---------------- | --------------------------------------------------------- |
| `Direct`         | Self-contained `syscall` instruction                      |
| `Gadget` (x64)   | Jumps to a `syscall; ret` gadget found in ntdll           |
| `Exception`      | Triggers `ud2`; resolves via a vectored exception handler |

| Parser           | How it finds syscall numbers                              |
| ---------------- | --------------------------------------------------------- |
| `Directory`      | x64: walks `.pdata` ordered by RVA; x86: sorts `Zw*` exports |
| `Signature`      | Scans function prologues with hook detection              |

## Quick start

```rust
use core::ffi::c_void;
use syscalls_rs::prelude::*;
use syscalls_rs::shared::{current_process, NTSTATUS};
use syscalls_rs::syscall_id;

type NtAlloc = unsafe extern "system" fn(
    isize, *mut *mut c_void, usize, *mut usize, u32, u32,
) -> NTSTATUS;

let mgr: SectionDirectManager = Manager::new();
assert!(mgr.initialize());

let inv = mgr.invoke(syscall_id!("NtAllocateVirtualMemory")).unwrap();
let f: NtAlloc = unsafe { inv.as_fn() };
```

## Features

- `no_hash` — use `String` syscall keys instead of compile-time `u64`
  hashes (mirrors `-DSYSCALLS_NO_HASH`).

## Requirements

- Windows x86 or x64 target
- Rust 1.75+ (for the `const fn` features used in `hash.rs`)

## License

MIT (same as upstream).
