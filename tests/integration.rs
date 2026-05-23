// ---------------------------------------------------------------------------
// Windows integration tests.
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod windows_tests {
    use core::ffi::c_void;

    use syscalls_rs::hash::hash_str;
    use syscalls_rs::native::{
        get_export_by_name, get_module_base_by_hash, get_module_base_str, rdtscp,
    };
    use syscalls_rs::prelude::*;
    use syscalls_rs::shared::{current_process, is_success, NTSTATUS, STATUS_PROCEDURE_NOT_FOUND};
    use syscalls_rs::syscall_id;

    type NtAlloc =
        unsafe extern "C" fn(isize, *mut *mut c_void, usize, *mut usize, u32, u32) -> NTSTATUS;
    type NtFree = unsafe extern "C" fn(isize, *mut *mut c_void, *mut usize, u32) -> NTSTATUS;
    type NtClose = unsafe extern "C" fn(isize) -> NTSTATUS;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008u32 as i32;

    fn alloc_then_free<
        A: syscalls_rs::allocator::Allocator,
        G: syscalls_rs::generator::StubGenerator,
        C: syscalls_rs::parser::ParserChain,
    >(
        mgr: &Manager<A, G, C>,
    ) -> bool {
        let mut base: *mut c_void = core::ptr::null_mut();
        let mut size: usize = 0x1000;

        let alloc_inv = mgr.invoke(syscall_id!("NtAllocateVirtualMemory")).unwrap();
        let f: NtAlloc = unsafe { alloc_inv.as_fn() };
        let status = unsafe {
            f(
                current_process() as isize,
                &mut base,
                0,
                &mut size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if !is_success(status) || base.is_null() {
            return false;
        }
        let free_inv = mgr.invoke(syscall_id!("NtFreeVirtualMemory")).unwrap();
        let f: NtFree = unsafe { free_inv.as_fn() };
        let mut z: usize = 0;
        let _ = unsafe { f(current_process() as isize, &mut base, &mut z, MEM_RELEASE) };
        true
    }

    #[test]
    fn section_direct_initializes() {
        let m: Manager<Section, Direct> = Manager::new();
        assert!(m.initialize());
    }

    #[test]
    fn heap_direct_initializes() {
        let m: Manager<Heap, Direct> = Manager::new();
        assert!(m.initialize());
    }

    #[test]
    fn memory_direct_initializes() {
        let m: Manager<Memory, Direct> = Manager::new();
        assert!(m.initialize());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn gadget_invokes_real_syscall() {
        let m: Manager<Section, Gadget> = Manager::new();
        assert!(m.initialize());
        let inv = m.invoke(syscall_id!("NtClose")).unwrap();
        let f: NtClose = unsafe { inv.as_fn() };
        assert_eq!(unsafe { f(0xDEADBEEFu32 as isize) }, STATUS_INVALID_HANDLE);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn exception_invokes_real_syscall() {
        let m: Manager<Section, Exception> = Manager::new();
        assert!(m.initialize());
        let inv = m.invoke(syscall_id!("NtClose")).unwrap();
        let f: NtClose = unsafe { inv.as_fn() };
        assert_eq!(unsafe { f(0xDEADBEEFu32 as isize) }, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn double_init_succeeds() {
        let m: SectionDirectManager = Manager::new();
        assert!(m.initialize());
        assert!(m.initialize());
    }

    #[test]
    fn alloc_and_free_via_section_direct() {
        let m: SectionDirectManager = Manager::new();
        assert!(m.initialize());
        assert!(alloc_then_free(&m));
    }

    #[test]
    fn invalid_syscall_returns_not_found() {
        let m: SectionDirectManager = Manager::new();
        assert!(m.initialize());
        assert!(m
            .invoke(syscall_id!("NtThisDoesNotExist1234567890"))
            .is_none());
        assert_eq!(STATUS_PROCEDURE_NOT_FOUND, 0xC000007Au32 as i32);
    }

    #[test]
    fn nt_close_invalid_handle() {
        let m: SectionDirectManager = Manager::new();
        assert!(m.initialize());
        let inv = m.invoke(syscall_id!("NtClose")).unwrap();
        let f: NtClose = unsafe { inv.as_fn() };
        let status = unsafe { f(0xDEADBEEFu32 as isize) };
        assert_eq!(status, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn signature_parser_alone() {
        let m: Manager<Section, Direct, (Signature,)> = Manager::new();
        assert!(m.initialize());
        assert!(alloc_then_free(&m));
    }

    #[test]
    fn directory_parser_alone() {
        let m: Manager<Section, Direct, (Directory,)> = Manager::new();
        assert!(m.initialize());
        let inv = m.invoke(syscall_id!("NtClose")).unwrap();
        let f: NtClose = unsafe { inv.as_fn() };
        assert_eq!(unsafe { f(0xDEADBEEFu32 as isize) }, STATUS_INVALID_HANDLE);
    }

    #[test]
    fn many_syscalls_sequentially() {
        let m: SectionDirectManager = Manager::new();
        assert!(m.initialize());
        for _ in 0..100 {
            assert!(alloc_then_free(&m));
        }
    }

    #[test]
    fn module_base_lookups() {
        assert!(!get_module_base_by_hash(hash_str("ntdll.dll")).is_null());
        assert!(!get_module_base_str("ntdll.dll").is_null());
        assert!(get_module_base_str("this_dll_does_not_exist.dll").is_null());
    }

    #[test]
    fn export_lookups() {
        let ntdll = get_module_base_str("ntdll.dll");
        assert!(!ntdll.is_null());
        assert!(!get_export_by_name(ntdll, "NtClose").is_null());
        assert!(get_export_by_name(ntdll, "ThisExportDoesNotExist123").is_null());
    }

    #[test]
    fn forwarded_export() {
        let k32 = get_module_base_str("kernel32.dll");
        assert!(!k32.is_null());
        assert!(!get_export_by_name(k32, "HeapAlloc").is_null());
    }

    #[test]
    fn rdtscp_increasing() {
        let a = rdtscp();
        let b = rdtscp();
        assert_ne!(a, b);
    }
}

// ---------------------------------------------------------------------------
// Linux integration tests.
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod linux_tests {
    use syscalls_rs::native::rdtscp;
    use syscalls_rs::prelude::*;
    use syscalls_rs::syscall_id;

    #[test]
    fn memory_direct_initializes() {
        let m: Manager<Memory, Direct> = Manager::new();
        assert!(m.initialize());
    }

    #[test]
    fn double_init_succeeds() {
        let m: MemoryDirectManager = Manager::new();
        assert!(m.initialize());
        assert!(m.initialize());
    }

    #[test]
    fn invalid_syscall_returns_none() {
        let m: MemoryDirectManager = Manager::new();
        assert!(m.initialize());
        assert!(m
            .invoke(syscall_id!("this_syscall_does_not_exist"))
            .is_none());
    }

    #[test]
    fn write_syscall() {
        let m: MemoryDirectManager = Manager::new();
        assert!(m.initialize());
        let inv = m.invoke(syscall_id!("write")).unwrap();
        // write(fd=1, buf, count, ...) -> bytes written
        type WriteFn = unsafe extern "C" fn(u64, *const u8, u64, u64, u64, u64) -> i64;
        let msg = b"test output from direct syscall\n";
        let ret = unsafe {
            let f: WriteFn = inv.as_fn();
            f(1, msg.as_ptr(), msg.len() as u64, 0, 0, 0)
        };
        assert_eq!(ret, msg.len() as i64);
    }

    #[test]
    fn getpid_syscall() {
        let m: MemoryDirectManager = Manager::new();
        assert!(m.initialize());
        let inv = m.invoke(syscall_id!("getpid")).unwrap();
        type GetpidFn = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;
        let pid = unsafe {
            let f: GetpidFn = inv.as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        assert!(pid > 0);
        // Verify against libc getpid.
        assert_eq!(pid, unsafe { libc_getpid() } as i64);
    }

    // Raw getpid via inline asm for verification (no libc dependency).
    unsafe fn libc_getpid() -> i32 {
        let ret: i64;
        core::arch::asm!(
            "syscall",
            in("rax") 39u64, // __NR_getpid
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        ret as i32
    }

    #[test]
    fn table_parser_alone() {
        let m: Manager<Memory, Direct, (Table,)> = Manager::new();
        assert!(m.initialize());
        assert!(m.invoke(syscall_id!("read")).is_some());
        assert!(m.invoke(syscall_id!("write")).is_some());
        assert!(m.invoke(syscall_id!("close")).is_some());
        assert!(m.invoke(syscall_id!("mmap")).is_some());
    }

    #[test]
    fn many_syscalls_sequentially() {
        let m: MemoryDirectManager = Manager::new();
        assert!(m.initialize());
        for _ in 0..100 {
            let inv = m.invoke(syscall_id!("getpid")).unwrap();
            type GetpidFn = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;
            let pid = unsafe {
                let f: GetpidFn = inv.as_fn();
                f(0, 0, 0, 0, 0, 0)
            };
            assert!(pid > 0);
        }
    }

    #[test]
    fn rdtscp_increasing() {
        let a = rdtscp();
        let b = rdtscp();
        assert_ne!(a, b);
    }

    #[test]
    fn section_and_heap_aliases_work() {
        // On Linux, Section and Heap are aliases for Memory.
        let m1: Manager<Section, Direct> = Manager::new();
        assert!(m1.initialize());
        let m2: Manager<Heap, Direct> = Manager::new();
        assert!(m2.initialize());
    }

    // Syscall fn-pointer type aliases used across tests.
    // Linux syscall stubs use the C calling convention with 6 args.
    type Syscall0 = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;
    type Syscall1 = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;
    type Syscall2 = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;
    type Syscall3 = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;
    type Syscall6 = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;

    /// Helper: create + initialize a default manager.
    fn mgr() -> MemoryDirectManager {
        let m = Manager::new();
        assert!(m.initialize());
        m
    }

    // -- close / error-path tests ------------------------------------------

    #[test]
    fn close_invalid_fd_returns_ebadf() {
        let m = mgr();
        let inv = m.invoke(syscall_id!("close")).unwrap();
        let f: Syscall1 = unsafe { inv.as_fn() };
        // fd 9999 should not be open → EBADF (-9).
        let ret = unsafe { f(9999, 0, 0, 0, 0, 0) };
        assert_eq!(ret, -9); // -EBADF
    }

    // -- pipe + read / write round-trip ------------------------------------

    #[test]
    fn pipe_read_write_round_trip() {
        let m = mgr();

        // pipe(fds)
        let mut fds: [i32; 2] = [0; 2];
        let inv = m.invoke(syscall_id!("pipe")).unwrap();
        let pipe_fn: Syscall1 = unsafe { inv.as_fn() };
        let ret = unsafe { pipe_fn(fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
        assert!(fds[0] > 0 && fds[1] > 0);

        // write(fds[1], "hello", 5)
        let msg = b"hello";
        let inv_w = m.invoke(syscall_id!("write")).unwrap();
        let write_fn: Syscall3 = unsafe { inv_w.as_fn() };
        let n = unsafe { write_fn(fds[1] as u64, msg.as_ptr() as u64, 5, 0, 0, 0) };
        assert_eq!(n, 5);

        // read(fds[0], buf, 5)
        let mut buf = [0u8; 16];
        let inv_r = m.invoke(syscall_id!("read")).unwrap();
        let read_fn: Syscall3 = unsafe { inv_r.as_fn() };
        let n = unsafe { read_fn(fds[0] as u64, buf.as_mut_ptr() as u64, 16, 0, 0, 0) };
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");

        // close both ends
        let inv_c = m.invoke(syscall_id!("close")).unwrap();
        let close_fn: Syscall1 = unsafe { inv_c.as_fn() };
        unsafe {
            close_fn(fds[0] as u64, 0, 0, 0, 0, 0);
            close_fn(fds[1] as u64, 0, 0, 0, 0, 0);
        }
    }

    // -- mmap / munmap via stubs -------------------------------------------

    #[test]
    fn mmap_and_munmap() {
        let m = mgr();

        // mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
        const PROT_RW: u64 = 0x1 | 0x2;
        const MAP_PRIV_ANON: u64 = 0x02 | 0x20;
        let inv = m.invoke(syscall_id!("mmap")).unwrap();
        let mmap_fn: Syscall6 = unsafe { inv.as_fn() };
        let addr = unsafe { mmap_fn(0, 4096, PROT_RW, MAP_PRIV_ANON, (-1i64) as u64, 0) };
        assert!(addr > 0);
        // touch the mapping
        unsafe { *(addr as *mut u8) = 0x42 };

        // munmap
        let inv = m.invoke(syscall_id!("munmap")).unwrap();
        let munmap_fn: Syscall2 = unsafe { inv.as_fn() };
        let ret = unsafe { munmap_fn(addr as u64, 4096, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
    }

    // -- identity syscalls -------------------------------------------------

    #[test]
    fn getuid_returns_nonzero_or_root() {
        let m = mgr();
        let inv = m.invoke(syscall_id!("getuid")).unwrap();
        let f: Syscall0 = unsafe { inv.as_fn() };
        let uid = unsafe { f(0, 0, 0, 0, 0, 0) };
        // uid is >= 0 (0 for root, positive otherwise)
        assert!(uid >= 0);
    }

    #[test]
    fn geteuid_returns_nonzero_or_root() {
        let m = mgr();
        let inv = m.invoke(syscall_id!("geteuid")).unwrap();
        let f: Syscall0 = unsafe { inv.as_fn() };
        let euid = unsafe { f(0, 0, 0, 0, 0, 0) };
        assert!(euid >= 0);
    }

    #[test]
    fn getgid_and_getegid() {
        let m = mgr();
        let gid = unsafe {
            let f: Syscall0 = m.invoke(syscall_id!("getgid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        let egid = unsafe {
            let f: Syscall0 = m.invoke(syscall_id!("getegid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        assert!(gid >= 0);
        assert!(egid >= 0);
    }

    #[test]
    fn getppid_returns_positive() {
        let m = mgr();
        let inv = m.invoke(syscall_id!("getppid")).unwrap();
        let f: Syscall0 = unsafe { inv.as_fn() };
        let ppid = unsafe { f(0, 0, 0, 0, 0, 0) };
        assert!(ppid > 0);
    }

    #[test]
    fn gettid_returns_positive() {
        let m = mgr();
        let inv = m.invoke(syscall_id!("gettid")).unwrap();
        let f: Syscall0 = unsafe { inv.as_fn() };
        let tid = unsafe { f(0, 0, 0, 0, 0, 0) };
        assert!(tid > 0);
    }

    // -- dup / dup2 --------------------------------------------------------

    #[test]
    fn dup_and_close() {
        let m = mgr();

        // dup(stdout=1)
        let inv = m.invoke(syscall_id!("dup")).unwrap();
        let dup_fn: Syscall1 = unsafe { inv.as_fn() };
        let new_fd = unsafe { dup_fn(1, 0, 0, 0, 0, 0) };
        assert!(new_fd > 2); // should be > stderr

        // close the dup'd fd
        let inv = m.invoke(syscall_id!("close")).unwrap();
        let close_fn: Syscall1 = unsafe { inv.as_fn() };
        let ret = unsafe { close_fn(new_fd as u64, 0, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
    }

    // -- getcwd ------------------------------------------------------------

    #[test]
    fn getcwd_returns_absolute_path() {
        let m = mgr();
        let mut buf = [0u8; 4096];
        let inv = m.invoke(syscall_id!("getcwd")).unwrap();
        let f: Syscall2 = unsafe { inv.as_fn() };
        let ret = unsafe { f(buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0) };
        assert!(ret > 0);
        // the result should start with '/'
        assert_eq!(buf[0], b'/');
    }

    // -- uname -------------------------------------------------------------

    #[test]
    fn uname_succeeds() {
        let m = mgr();
        // struct utsname is 390 bytes on x86_64 (5 × 65 + padding, but
        // allocate generously)
        let mut buf = [0u8; 512];
        let inv = m.invoke(syscall_id!("uname")).unwrap();
        let f: Syscall1 = unsafe { inv.as_fn() };
        let ret = unsafe { f(buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
        // sysname field starts at offset 0 and should be "Linux\0..."
        assert_eq!(&buf[..5], b"Linux");
    }

    // -- kill(pid, 0) — signal 0 checks permissions -----------------------

    #[test]
    fn kill_signal_zero_on_self() {
        let m = mgr();
        let pid = unsafe {
            let f: Syscall0 = m.invoke(syscall_id!("getpid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        let inv = m.invoke(syscall_id!("kill")).unwrap();
        let kill_fn: Syscall2 = unsafe { inv.as_fn() };
        // signal 0 doesn't actually send a signal, just checks permissions
        let ret = unsafe { kill_fn(pid as u64, 0, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
    }

    // -- nanosleep ---------------------------------------------------------

    #[test]
    fn nanosleep_short_sleep() {
        let m = mgr();

        #[repr(C)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }
        let req = Timespec {
            tv_sec: 0,
            tv_nsec: 1_000, // 1 microsecond
        };
        let inv = m.invoke(syscall_id!("nanosleep")).unwrap();
        let f: Syscall2 = unsafe { inv.as_fn() };
        let ret = unsafe {
            f(
                &req as *const _ as u64,
                core::ptr::null::<Timespec>() as u64,
                0,
                0,
                0,
                0,
            )
        };
        assert_eq!(ret, 0);
    }

    // -- getrandom ---------------------------------------------------------

    #[test]
    fn getrandom_fills_buffer() {
        let m = mgr();
        let mut buf = [0u8; 32];
        let inv = m.invoke(syscall_id!("getrandom")).unwrap();
        let f: Syscall3 = unsafe { inv.as_fn() };
        let ret = unsafe { f(buf.as_mut_ptr() as u64, 32, 0, 0, 0, 0) };
        assert_eq!(ret, 32);
        // extremely unlikely to be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    // -- openat / fstat / close --------------------------------------------

    #[test]
    fn openat_fstat_close() {
        let m = mgr();

        // openat(AT_FDCWD, "/dev/null", O_RDONLY, 0)
        const AT_FDCWD: u64 = (-100i64) as u64;
        const O_RDONLY: u64 = 0;
        let path = b"/dev/null\0";
        let inv = m.invoke(syscall_id!("openat")).unwrap();
        let openat_fn: Syscall6 = unsafe { inv.as_fn() };
        let fd = unsafe { openat_fn(AT_FDCWD, path.as_ptr() as u64, O_RDONLY, 0, 0, 0) };
        assert!(fd >= 0, "openat failed: {fd}");

        // fstat(fd, &statbuf) — struct stat is ~144 bytes on x86_64
        let mut statbuf = [0u8; 256];
        let inv = m.invoke(syscall_id!("fstat")).unwrap();
        let fstat_fn: Syscall2 = unsafe { inv.as_fn() };
        let ret = unsafe { fstat_fn(fd as u64, statbuf.as_mut_ptr() as u64, 0, 0, 0, 0) };
        assert_eq!(ret, 0);

        // close
        let inv = m.invoke(syscall_id!("close")).unwrap();
        let close_fn: Syscall1 = unsafe { inv.as_fn() };
        let ret = unsafe { close_fn(fd as u64, 0, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
    }

    // -- access ------------------------------------------------------------

    #[test]
    fn access_dev_null() {
        let m = mgr();
        let path = b"/dev/null\0";
        const F_OK: u64 = 0;
        let inv = m.invoke(syscall_id!("access")).unwrap();
        let f: Syscall2 = unsafe { inv.as_fn() };
        let ret = unsafe { f(path.as_ptr() as u64, F_OK, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
    }

    #[test]
    fn access_nonexistent_returns_enoent() {
        let m = mgr();
        let path = b"/this/path/does/not/exist/at/all\0";
        const F_OK: u64 = 0;
        let inv = m.invoke(syscall_id!("access")).unwrap();
        let f: Syscall2 = unsafe { inv.as_fn() };
        let ret = unsafe { f(path.as_ptr() as u64, F_OK, 0, 0, 0, 0) };
        assert_eq!(ret, -2); // -ENOENT
    }

    // -- sysinfo -----------------------------------------------------------

    #[test]
    fn sysinfo_succeeds() {
        let m = mgr();
        // struct sysinfo is 112 bytes on x86_64
        let mut buf = [0u8; 128];
        let inv = m.invoke(syscall_id!("sysinfo")).unwrap();
        let f: Syscall1 = unsafe { inv.as_fn() };
        let ret = unsafe { f(buf.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
        assert_eq!(ret, 0);
        // uptime (first i64) should be > 0
        let uptime = i64::from_ne_bytes(buf[..8].try_into().unwrap());
        assert!(uptime > 0);
    }

    // -- multiple managers coexist -----------------------------------------

    #[test]
    fn multiple_managers_coexist() {
        let m1 = mgr();
        let m2 = mgr();
        let pid1 = unsafe {
            let f: Syscall0 = m1.invoke(syscall_id!("getpid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        let pid2 = unsafe {
            let f: Syscall0 = m2.invoke(syscall_id!("getpid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        assert_eq!(pid1, pid2);
        assert!(pid1 > 0);
    }

    // -- manager drop + recreate ------------------------------------------

    #[test]
    fn drop_and_recreate_manager() {
        {
            let m = mgr();
            let pid = unsafe {
                let f: Syscall0 = m.invoke(syscall_id!("getpid")).unwrap().as_fn();
                f(0, 0, 0, 0, 0, 0)
            };
            assert!(pid > 0);
            // m is dropped here
        }
        // create a new one — the old mmap region should have been munmap'd
        let m = mgr();
        let pid = unsafe {
            let f: Syscall0 = m.invoke(syscall_id!("getpid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        assert!(pid > 0);
    }

    // -- mixed syscalls from single manager --------------------------------

    #[test]
    fn mixed_syscalls_single_manager() {
        let m = mgr();

        // getpid
        let pid = unsafe {
            let f: Syscall0 = m.invoke(syscall_id!("getpid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        assert!(pid > 0);

        // getuid
        let uid = unsafe {
            let f: Syscall0 = m.invoke(syscall_id!("getuid")).unwrap().as_fn();
            f(0, 0, 0, 0, 0, 0)
        };
        assert!(uid >= 0);

        // write
        let msg = b"mixed\n";
        let n = unsafe {
            let f: Syscall3 = m.invoke(syscall_id!("write")).unwrap().as_fn();
            f(1, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0)
        };
        assert_eq!(n, msg.len() as i64);

        // getcwd
        let mut buf = [0u8; 4096];
        let ret = unsafe {
            let f: Syscall2 = m.invoke(syscall_id!("getcwd")).unwrap().as_fn();
            f(buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0)
        };
        assert!(ret > 0);
        assert_eq!(buf[0], b'/');
    }

    // -- table covers all common syscalls ----------------------------------

    #[test]
    fn table_has_essential_syscalls() {
        let m = mgr();
        let names = [
            "read",
            "write",
            "open",
            "close",
            "stat",
            "fstat",
            "lstat",
            "poll",
            "lseek",
            "mmap",
            "mprotect",
            "munmap",
            "brk",
            "ioctl",
            "access",
            "pipe",
            "dup",
            "dup2",
            "nanosleep",
            "getpid",
            "socket",
            "connect",
            "accept",
            "sendto",
            "recvfrom",
            "bind",
            "listen",
            "clone",
            "fork",
            "execve",
            "exit",
            "kill",
            "fcntl",
            "getcwd",
            "mkdir",
            "rmdir",
            "unlink",
            "chmod",
            "chown",
            "getuid",
            "getgid",
            "geteuid",
            "getegid",
            "getppid",
            "setsid",
            "openat",
            "epoll_create1",
            "epoll_ctl",
            "epoll_wait",
            "pipe2",
            "dup3",
            "accept4",
            "getrandom",
            "memfd_create",
            "io_uring_setup",
            "io_uring_enter",
            "io_uring_register",
            "clone3",
            "close_range",
            "openat2",
        ];
        for name in names {
            assert!(
                m.invoke(syscalls_rs::syscall_id_rt!(name)).is_some(),
                "missing syscall: {name}",
            );
        }
    }
}
