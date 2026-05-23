use core::ffi::c_void;

use super::StubGenerator;

pub struct Direct;

// ---------------------------------------------------------------------------
// Windows x64: push rcx; pop r10; mov eax, <num>; syscall; add rsp,8; jmp [rsp-8]
// ---------------------------------------------------------------------------
#[cfg(all(windows, target_pointer_width = "64"))]
const SHELLCODE: [u8; 18] = [
    0x51, // push rcx
    0x41, 0x5A, // pop r10
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <number>
    0x0F, 0x05, // syscall
    0x48, 0x83, 0xC4, 0x08, // add rsp, 8
    0xFF, 0x64, 0x24, 0xF8, // jmp qword ptr [rsp-8]
];

// ---------------------------------------------------------------------------
// Windows x86: mov eax, <num>; mov edx, esp; call fs:[0xC0]; ret
// ---------------------------------------------------------------------------
#[cfg(all(windows, target_pointer_width = "32"))]
const SHELLCODE: [u8; 15] = [
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <number>
    0x89, 0xE2, // mov edx, esp
    0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, // call fs:[0xC0]
    0xC3, // ret
];

// ---------------------------------------------------------------------------
// Linux x86_64: mov r10, rcx; mov eax, <num>; syscall; ret
// The `mov r10, rcx` translates the C ABI 4th arg (rcx) to the syscall ABI
// 4th arg (r10). All other arg registers (rdi, rsi, rdx, r8, r9) are the same.
// ---------------------------------------------------------------------------
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SHELLCODE: [u8; 11] = [
    0x49, 0x89, 0xCA, // mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <number>
    0x0F, 0x05, // syscall
    0xC3, // ret
];

impl StubGenerator for Direct {
    const REQUIRES_GADGET: bool = false;

    fn stub_size() -> usize {
        SHELLCODE.len()
    }

    fn generate(buffer: &mut [u8], syscall_number: u32, _gadget: *mut c_void) {
        buffer[..SHELLCODE.len()].copy_from_slice(&SHELLCODE);

        // Patch the syscall number into the `mov eax, <number>` immediate.
        #[cfg(all(windows, target_pointer_width = "64"))]
        buffer[4..8].copy_from_slice(&syscall_number.to_le_bytes());

        #[cfg(all(windows, target_pointer_width = "32"))]
        buffer[1..5].copy_from_slice(&syscall_number.to_le_bytes());

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        buffer[4..8].copy_from_slice(&syscall_number.to_le_bytes());
    }
}
