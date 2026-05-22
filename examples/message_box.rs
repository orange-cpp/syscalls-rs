//! Displays a dialog box via a single direct syscall — `NtRaiseHardError`
//! with `STATUS_SERVICE_NOTIFICATION` and a `UNICODE_STRING` parameter.
//!
//! No `user32` or `kernel32` import is involved, so the binary's import
//! table contains only `ntdll` (or nothing at all, depending on the runtime).
//! The resulting `MessageBoxA` symbol does not appear anywhere in the
//! compiled artifact.

use syscalls_rs::hash::hash_str;
use syscalls_rs::native::{get_export_by_hash, get_module_base_by_hash};
use syscalls_rs::prelude::*;
use syscalls_rs::shared::NTSTATUS;
use syscalls_rs::syscall_id;

#[repr(C)]
struct UnicodeString {
    length: u16,
    max_length: u16,
    buffer: *const u16,
}

type NtRaiseHardError = unsafe extern "system" fn(
    error_status: NTSTATUS,
    number_of_parameters: u32,
    unicode_string_parameter_mask: u32,
    parameters: *const usize,
    valid_response_option: u32,
    response: *mut u32,
) -> NTSTATUS;

type RtlAdjustPrivilege = unsafe extern "system" fn(
    privilege: u32,
    enable: u8,
    current_thread: u8,
    enabled: *mut u8,
) -> NTSTATUS;

// Severity = warning (0x4), Customer bit = 1 (0x2 << 28 → 0x1 set in high nibble
// when combined). The "customer" bit tells the formatter to treat parameter 0
// as a literal UNICODE_STRING instead of looking up a system message.
const STATUS_SERVICE_NOTIFICATION: NTSTATUS = 0x5000_0018u32 as i32;
const SE_SHUTDOWN_PRIVILEGE: u32 = 19;
const RESPONSE_OPTION_OK: u32 = 1;

fn main() {
    let mgr: SectionDirectManager = Manager::new();
    if !mgr.initialize() {
        std::process::exit(1);
    }

    // NtRaiseHardError requires SeShutdownPrivilege to render an interactive
    // dialog on most Windows builds. RtlAdjustPrivilege is a regular ntdll
    // export (not a syscall), so we resolve it manually rather than going
    // through the syscall manager.
    unsafe {
        let ntdll = get_module_base_by_hash(hash_str("ntdll.dll"));
        let f = get_export_by_hash(ntdll, hash_str("RtlAdjustPrivilege"));
        if !f.is_null() {
            let adjust: RtlAdjustPrivilege = core::mem::transmute(f);
            let mut prev: u8 = 0;
            let _ = adjust(SE_SHUTDOWN_PRIVILEGE, 1, 0, &mut prev);
        }
    }

    let msg_w: Vec<u16> = "Hello from a direct NtRaiseHardError syscall!"
        .encode_utf16()
        .collect();
    let title_w: Vec<u16> = "syscalls-rs".encode_utf16().collect();

    let msg_us = UnicodeString {
        length: (msg_w.len() * 2) as u16,
        max_length: (msg_w.len() * 2) as u16,
        buffer: msg_w.as_ptr(),
    };
    let title_us = UnicodeString {
        length: (title_w.len() * 2) as u16,
        max_length: (title_w.len() * 2) as u16,
        buffer: title_w.as_ptr(),
    };

    // Hard-error code 0x50000018 with three parameters (message, title, flags)
    // is the canonical "render a MessageBox" form. The mask 0b011 marks
    // parameters 0 and 1 as UNICODE_STRING pointers; parameter 2 is a raw
    // MB_* flags ULONG.
    const MB_OK: usize = 0x0;
    const MB_ICONINFORMATION: usize = 0x40;

    let params: [usize; 3] = [
        &msg_us as *const _ as usize,
        &title_us as *const _ as usize,
        MB_OK | MB_ICONINFORMATION,
    ];
    let mut response: u32 = 0;

    let inv = mgr
        .invoke(syscall_id!("NtRaiseHardError"))
        .expect("NtRaiseHardError not resolved");
    let status = unsafe {
        let f: NtRaiseHardError = inv.as_fn();
        f(
            STATUS_SERVICE_NOTIFICATION,
            params.len() as u32,
            0b011,
            params.as_ptr(),
            RESPONSE_OPTION_OK,
            &mut response,
        )
    };
    println!(
        "NtRaiseHardError -> status=0x{:08X} response={}",
        status as u32, response
    );
}
