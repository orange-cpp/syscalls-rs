use core::ffi::c_void;

use super::StubGenerator;

pub struct Direct;

#[cfg(target_pointer_width = "64")]
const SHELLCODE: [u8; 18] = [
    0x51,                                     // push rcx
    0x41, 0x5A,                               // pop r10
    0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax, <number>
    0x0F, 0x05,                               // syscall
    0x48, 0x83, 0xC4, 0x08,                   // add rsp, 8
    0xFF, 0x64, 0x24, 0xF8,                   // jmp qword ptr [rsp-8]
];

#[cfg(target_pointer_width = "32")]
const SHELLCODE: [u8; 15] = [
    0xB8, 0x00, 0x00, 0x00, 0x00,             // mov eax, <number>
    0x89, 0xE2,                               // mov edx, esp
    0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00, // call fs:[0xC0]
    0xC3,                                     // ret
];

impl StubGenerator for Direct {
    const REQUIRES_GADGET: bool = false;

    fn stub_size() -> usize {
        SHELLCODE.len()
    }

    fn generate(buffer: &mut [u8], syscall_number: u32, _gadget: *mut c_void) {
        buffer[..SHELLCODE.len()].copy_from_slice(&SHELLCODE);
        #[cfg(target_pointer_width = "64")]
        buffer[4..8].copy_from_slice(&syscall_number.to_le_bytes());
        #[cfg(target_pointer_width = "32")]
        buffer[1..5].copy_from_slice(&syscall_number.to_le_bytes());
    }
}
