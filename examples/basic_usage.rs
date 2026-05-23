#[cfg(windows)]
fn main() {
    use core::ffi::c_void;

    use syscalls_rs::prelude::*;
    use syscalls_rs::shared::{current_process, is_success, NTSTATUS};
    use syscalls_rs::syscall_id;

    type NtAllocateVirtualMemory = unsafe extern "C" fn(
        process: isize,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> NTSTATUS;

    let mgr: SectionDirectManager = Manager::new();
    if !mgr.initialize() {
        eprintln!("initialization failed!");
        std::process::exit(1);
    }

    let mut base: *mut c_void = core::ptr::null_mut();
    let mut size: usize = 0x1000;

    let inv = mgr
        .invoke(syscall_id!("NtAllocateVirtualMemory"))
        .expect("syscall not found");

    let status = unsafe {
        let f: NtAllocateVirtualMemory = inv.as_fn();
        f(
            current_process() as isize,
            &mut base,
            0,
            &mut size,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x04,            // PAGE_READWRITE
        )
    };

    if is_success(status) && !base.is_null() {
        println!("allocation successful at {:p}", base);
    } else {
        println!("allocation failed: status=0x{:08X}", status);
    }
}

#[cfg(target_os = "linux")]
fn main() {
    use syscalls_rs::prelude::*;
    use syscalls_rs::syscall_id;

    let mgr: MemoryDirectManager = Manager::new();
    if !mgr.initialize() {
        eprintln!("initialization failed!");
        std::process::exit(1);
    }

    let inv = mgr.invoke(syscall_id!("write")).expect("syscall not found");

    // Linux write(2): fd, buf, count — remaining args unused but must be present
    // since the stub is a fixed 6-argument trampoline.
    type WriteFn = unsafe extern "C" fn(u64, *const u8, u64, u64, u64, u64) -> i64;
    let msg = b"Hello from a direct Linux syscall!\n";
    let ret = unsafe {
        let f: WriteFn = inv.as_fn();
        f(1, msg.as_ptr(), msg.len() as u64, 0, 0, 0)
    };
    println!("write() returned {ret}");
}
