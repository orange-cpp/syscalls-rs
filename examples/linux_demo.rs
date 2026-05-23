//! Linux-only example demonstrating direct syscalls without libc.
//!
//! Showcases: file I/O (openat/write/close), memory mapping (mmap/munmap),
//! system info (uname, getpid, getrandom), and pipe-based IPC — all via
//! raw `syscall` instruction stubs, completely bypassing libc.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example is Linux-only.");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    use syscalls_rs::prelude::*;
    use syscalls_rs::syscall_id;

    // A single 6-arg type covers every syscall — unused trailing args are 0.
    type SysFn = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64;

    let mgr: MemoryDirectManager = Manager::new();
    if !mgr.initialize() {
        eprintln!("manager initialization failed");
        std::process::exit(1);
    }

    // Helper: look up a syscall or panic.
    macro_rules! sys {
        ($name:expr) => {
            unsafe {
                mgr.invoke(syscall_id!($name))
                    .expect($name)
                    .as_fn::<SysFn>()
            }
        };
    }

    // ------------------------------------------------------------------
    // 1. getpid / gettid / getuid
    // ------------------------------------------------------------------
    let getpid = sys!("getpid");
    let gettid = sys!("gettid");
    let getuid = sys!("getuid");

    let pid = unsafe { getpid(0, 0, 0, 0, 0, 0) };
    let tid = unsafe { gettid(0, 0, 0, 0, 0, 0) };
    let uid = unsafe { getuid(0, 0, 0, 0, 0, 0) };
    println!("[identity]  pid={pid}  tid={tid}  uid={uid}");

    // ------------------------------------------------------------------
    // 2. uname — print kernel version
    // ------------------------------------------------------------------
    let uname = sys!("uname");
    let mut uts = [0u8; 390]; // struct utsname on x86_64
    let ret = unsafe { uname(uts.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
    if ret == 0 {
        // Fields are at fixed 65-byte offsets: sysname, nodename, release, ...
        let sysname = std::str::from_utf8(&uts[..65])
            .unwrap_or("?")
            .trim_end_matches('\0');
        let release = std::str::from_utf8(&uts[130..195])
            .unwrap_or("?")
            .trim_end_matches('\0');
        println!("[uname]     {sysname} {release}");
    }

    // ------------------------------------------------------------------
    // 3. getrandom — fill a buffer with random bytes
    // ------------------------------------------------------------------
    let getrandom = sys!("getrandom");
    let mut rng_buf = [0u8; 16];
    let n = unsafe { getrandom(rng_buf.as_mut_ptr() as u64, 16, 0, 0, 0, 0) };
    print!("[getrandom] {n} bytes: ");
    for b in &rng_buf[..n as usize] {
        print!("{b:02x}");
    }
    println!();

    // ------------------------------------------------------------------
    // 4. mmap + write to memory + munmap
    // ------------------------------------------------------------------
    let mmap = sys!("mmap");
    let munmap = sys!("munmap");

    const PROT_RW: u64 = 0x1 | 0x2; // PROT_READ | PROT_WRITE
    const MAP_PRIV_ANON: u64 = 0x02 | 0x20; // MAP_PRIVATE | MAP_ANONYMOUS
    let page_size: u64 = 4096;

    let addr = unsafe { mmap(0, page_size, PROT_RW, MAP_PRIV_ANON, (-1i64) as u64, 0) };
    if addr > 0 {
        // Write a marker and read it back.
        unsafe {
            let ptr = addr as *mut u8;
            *ptr = 0xDE;
            *ptr.add(1) = 0xAD;
            assert_eq!(*ptr, 0xDE);
            assert_eq!(*ptr.add(1), 0xAD);
        }
        println!("[mmap]      mapped page at 0x{addr:x}, wrote 0xDEAD, verified");

        let ret = unsafe { munmap(addr as u64, page_size, 0, 0, 0, 0) };
        println!("[munmap]    unmapped: ret={ret}");
    }

    // ------------------------------------------------------------------
    // 5. pipe → write → read round-trip
    // ------------------------------------------------------------------
    let pipe = sys!("pipe");
    let write = sys!("write");
    let read = sys!("read");
    let close = sys!("close");

    let mut fds = [0i32; 2];
    let ret = unsafe { pipe(fds.as_mut_ptr() as u64, 0, 0, 0, 0, 0) };
    if ret == 0 {
        let msg = b"hello from pipe!";
        let n = unsafe {
            write(
                fds[1] as u64,
                msg.as_ptr() as u64,
                msg.len() as u64,
                0,
                0,
                0,
            )
        };
        println!("[pipe]      wrote {n} bytes into pipe");

        let mut buf = [0u8; 64];
        let n = unsafe { read(fds[0] as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0) };
        let received = std::str::from_utf8(&buf[..n as usize]).unwrap_or("?");
        println!("[pipe]      read back: \"{received}\"");

        unsafe {
            close(fds[0] as u64, 0, 0, 0, 0, 0);
            close(fds[1] as u64, 0, 0, 0, 0, 0);
        }
    }

    // ------------------------------------------------------------------
    // 6. File I/O: openat → write → close (create a temp file)
    // ------------------------------------------------------------------
    let openat = sys!("openat");

    const AT_FDCWD: u64 = (-100i64) as u64;
    const O_WRONLY_CREAT_TRUNC: u64 = 0x01 | 0x40 | 0x200; // O_WRONLY | O_CREAT | O_TRUNC
    let path = b"/tmp/syscalls_rs_demo.txt\0";

    let fd = unsafe {
        openat(
            AT_FDCWD,
            path.as_ptr() as u64,
            O_WRONLY_CREAT_TRUNC,
            0o644,
            0,
            0,
        )
    };
    if fd >= 0 {
        let content = b"Written entirely via direct syscalls.\n";
        let n = unsafe {
            write(
                fd as u64,
                content.as_ptr() as u64,
                content.len() as u64,
                0,
                0,
                0,
            )
        };
        unsafe { close(fd as u64, 0, 0, 0, 0, 0) };
        println!("[file]      wrote {n} bytes to /tmp/syscalls_rs_demo.txt");
    } else {
        println!("[file]      openat failed: {fd}");
    }

    // ------------------------------------------------------------------
    // 7. nanosleep — sleep 10ms
    // ------------------------------------------------------------------
    let nanosleep = sys!("nanosleep");

    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    let req = Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000, // 10ms
    };
    let ret = unsafe {
        nanosleep(
            &req as *const _ as u64,
            core::ptr::null::<Timespec>() as u64,
            0,
            0,
            0,
            0,
        )
    };
    println!("[nanosleep] slept 10ms: ret={ret}");

    println!("\nAll done — no libc calls were made for any of the above.");
}
