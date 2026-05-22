//! `ud2; ret; nop...` — invocation routes through the vectored exception handler.

use core::ffi::c_void;

use super::StubGenerator;

pub struct Exception;

impl StubGenerator for Exception {
    const REQUIRES_GADGET: bool = true;
    const IS_EXCEPTION: bool = true;

    fn stub_size() -> usize {
        8
    }

    fn generate(buffer: &mut [u8], _syscall_number: u32, _gadget: *mut c_void) {
        buffer[0] = 0x0F;
        buffer[1] = 0x0B; // ud2
        buffer[2] = 0xC3; // ret
        for b in &mut buffer[3..] {
            *b = 0x90;
        }
    }
}
