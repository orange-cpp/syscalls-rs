//! Scans `Nt*` exports for the canonical syscall prologue
//! (`4C 8B D1 B8 <num>` on x64, `B8 <num>` on x86). Falls back to neighbor
//! search on x64 when a function is hooked.

use core::slice;

use crate::hash::{hash_bytes_len, hash_str};
use crate::types::{ModuleInfo, SyscallEntry, SyscallKey};

use super::Parser;

pub struct Signature;

impl Parser for Signature {
    fn parse(module: &ModuleInfo) -> Vec<SyscallEntry> {
        unsafe { do_parse(module) }
    }
}

unsafe fn do_parse(module: &ModuleInfo) -> Vec<SyscallEntry> {
    use crate::shared::IMAGE_DIRECTORY_ENTRY_EXPORT;

    let mut out = Vec::new();
    let nt = &*module.nt_headers;
    let exp = &*module.export_dir;
    let funcs = module.base.offset(exp.AddressOfFunctions as isize) as *const u32;
    let names = module.base.offset(exp.AddressOfNames as isize) as *const u32;
    let ords = module.base.offset(exp.AddressOfNameOrdinals as isize) as *const u16;

    let export_start = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    let export_end =
        export_start + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    #[cfg(target_pointer_width = "64")]
    let module_end = module.base as usize + nt.OptionalHeader.SizeOfImage as usize;

    let nt_prefix = hash_str("Nt");

    for i in 0..exp.NumberOfNames {
        let name_ptr = module.base.offset(*names.offset(i as isize) as isize);
        let name = cstr(name_ptr);
        if hash_bytes_len(name, 2) != nt_prefix {
            continue;
        }
        let ord = *ords.offset(i as isize) as isize;
        let rva = *funcs.offset(ord);
        if rva >= export_start && rva < export_end {
            continue;
        }
        let func = module.base.offset(rva as isize);
        let mut syscall_number = 0u32;
        let mut found = false;

        #[cfg(target_pointer_width = "64")]
        {
            // 4C 8B D1 B8 = mov r10, rcx ; mov eax,
            if read_u32(func) == 0xB8D18B4Cu32 {
                syscall_number = read_u32(func.offset(4));
                found = true;
            }
        }
        #[cfg(target_pointer_width = "32")]
        {
            if *func == 0xB8 {
                syscall_number = read_u32(func.offset(1));
                found = true;
            }
        }

        // Hook-aware neighbor search (x64 only).
        #[cfg(target_pointer_width = "64")]
        {
            if !found && is_hooked(func) {
                for j in 1..20 {
                    let p = func.offset(-(j * 0x20) as isize);
                    if (p as usize) < (module.base as usize) {
                        break;
                    }
                    if read_u32(p) == 0xB8D18B4Cu32 {
                        let n = read_u32(p.offset(4));
                        syscall_number = n + j as u32;
                        found = true;
                        break;
                    }
                }
                if !found {
                    for j in 1..20 {
                        let p = func.offset((j * 0x20) as isize);
                        if (p as usize) > module_end {
                            break;
                        }
                        if read_u32(p) == 0xB8D18B4Cu32 {
                            let n = read_u32(p.offset(4));
                            syscall_number = n.wrapping_sub(j as u32);
                            found = true;
                            break;
                        }
                    }
                }
            }
        }

        if found {
            out.push(SyscallEntry {
                key: name_key(name),
                syscall_number,
                offset: 0,
            });
        }
    }
    out
}

#[cfg(target_pointer_width = "64")]
unsafe fn is_hooked(start: *const u8) -> bool {
    let mut p = start;
    while *p == 0x90 {
        p = p.add(1);
    }
    match *p {
        0xE9 | 0xEB | 0x68 | 0xCC => true,
        0xFF => *p.add(1) == 0x25,
        0x0F => *p.add(1) == 0x0B,
        0xCD => *p.add(1) == 0x03,
        _ => false,
    }
}

#[inline]
unsafe fn read_u32(p: *const u8) -> u32 {
    (p as *const u32).read_unaligned()
}

unsafe fn cstr<'a>(ptr: *const u8) -> &'a [u8] {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    slice::from_raw_parts(ptr, len)
}

#[allow(unused_variables)]
fn name_key(name: &[u8]) -> SyscallKey {
    #[cfg(not(feature = "no_hash"))]
    {
        crate::hash::hash_bytes(name)
    }
    #[cfg(feature = "no_hash")]
    {
        unsafe { std::str::from_utf8_unchecked(name).to_owned() }
    }
}
