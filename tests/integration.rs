#![cfg(windows)]

use core::ffi::c_void;

use syscalls_rs::hash::hash_str;
use syscalls_rs::native::{get_export_by_name, get_module_base_by_hash, get_module_base_str, rdtscp};
use syscalls_rs::prelude::*;
use syscalls_rs::shared::{current_process, is_success, NTSTATUS, STATUS_PROCEDURE_NOT_FOUND};
use syscalls_rs::syscall_id;

type NtAlloc = unsafe extern "system" fn(
    isize, *mut *mut c_void, usize, *mut usize, u32, u32,
) -> NTSTATUS;
type NtFree =
    unsafe extern "system" fn(isize, *mut *mut c_void, *mut usize, u32) -> NTSTATUS;
type NtClose = unsafe extern "system" fn(isize) -> NTSTATUS;

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
    assert!(m.invoke(syscall_id!("NtThisDoesNotExist1234567890")).is_none());
    // C++ behavior returns STATUS_PROCEDURE_NOT_FOUND; here we expose None.
    // Confirm the constant still has its expected value for parity:
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
    // HeapAlloc is forwarded to ntdll!RtlAllocateHeap.
    assert!(!get_export_by_name(k32, "HeapAlloc").is_null());
}

#[test]
fn rdtscp_increasing() {
    let a = rdtscp();
    let b = rdtscp();
    assert_ne!(a, b);
}
