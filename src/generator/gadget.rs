//! x64-only: route execution to a `syscall; ret` gadget inside ntdll.

use core::ffi::c_void;

use super::StubGenerator;

pub struct Gadget;

impl StubGenerator for Gadget {
    const REQUIRES_GADGET: bool = true;

    fn stub_size() -> usize {
        32
    }

    fn generate(buffer: &mut [u8], syscall_number: u32, gadget: *mut c_void) {
        // mov r10, rcx
        buffer[0] = 0x49;
        buffer[1] = 0x89;
        buffer[2] = 0xCA;
        // mov eax, <number>
        buffer[3] = 0xB8;
        buffer[4..8].copy_from_slice(&syscall_number.to_le_bytes());
        // mov r11, <gadget>
        buffer[8] = 0x49;
        buffer[9] = 0xBB;
        buffer[10..18].copy_from_slice(&(gadget as u64).to_le_bytes());
        // push r11
        buffer[18] = 0x41;
        buffer[19] = 0x53;
        // ret
        buffer[20] = 0xC3;
        // remainder left zeroed by caller
    }
}
