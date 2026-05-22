//! On x64, maps the exception directory (.pdata) RVAs to exported names,
//! counts `Zw*` entries to assign syscall numbers.
//! On x86, sorts `Zw*` exports by address.

use core::slice;
use std::collections::HashMap;

use crate::hash::{hash_bytes_len, hash_str};
use crate::types::{ModuleInfo, SyscallEntry, SyscallKey};

use super::Parser;

pub struct Directory;

impl Parser for Directory {
    fn parse(module: &ModuleInfo) -> Vec<SyscallEntry> {
        #[cfg(target_pointer_width = "64")]
        unsafe {
            parse_x64(module)
        }
        #[cfg(target_pointer_width = "32")]
        unsafe {
            parse_x86(module)
        }
    }
}

#[cfg(target_pointer_width = "64")]
unsafe fn parse_x64(module: &ModuleInfo) -> Vec<SyscallEntry> {
    use crate::shared::{IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_RUNTIME_FUNCTION_ENTRY};

    let mut out = Vec::new();
    let nt = &*module.nt_headers;
    let dir = &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if dir.VirtualAddress == 0 {
        return out;
    }
    let runtime =
        module.base.offset(dir.VirtualAddress as isize) as *const IMAGE_RUNTIME_FUNCTION_ENTRY;
    let count = dir.Size as usize / core::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>();
    let runtime = slice::from_raw_parts(runtime, count);

    let map = rva_to_name(module);

    let mut syscall_number: u32 = 0;
    for func in runtime {
        if func.BeginAddress == 0 {
            break;
        }
        let Some(&name_ptr) = map.get(&func.BeginAddress) else {
            continue;
        };
        let name = cstr(name_ptr);
        if hash_bytes_len(name, 2) != hash_str("Zw") {
            continue;
        }
        out.push(SyscallEntry {
            key: make_nt_key(name),
            syscall_number,
            offset: 0,
        });
        syscall_number += 1;
    }
    out
}

#[cfg(target_pointer_width = "32")]
unsafe fn parse_x86(module: &ModuleInfo) -> Vec<SyscallEntry> {
    use crate::shared::IMAGE_DIRECTORY_ENTRY_EXPORT;

    let nt = &*module.nt_headers;
    let exp = &*module.export_dir;
    let funcs = module.base.offset(exp.AddressOfFunctions as isize) as *const u32;
    let names = module.base.offset(exp.AddressOfNames as isize) as *const u32;
    let ords = module.base.offset(exp.AddressOfNameOrdinals as isize) as *const u16;

    let export_start = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    let export_end =
        export_start + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    let mut zw: Vec<(usize, *const u8)> = Vec::new();
    for i in 0..exp.NumberOfNames {
        let name_ptr = module.base.offset(*names.offset(i as isize) as isize);
        if *name_ptr != b'Z' || *name_ptr.offset(1) != b'w' {
            continue;
        }
        let ord = *ords.offset(i as isize) as isize;
        let rva = *funcs.offset(ord);
        if rva >= export_start && rva < export_end {
            continue;
        }
        let addr = module.base as usize + rva as usize;
        zw.push((addr, name_ptr));
    }
    if zw.is_empty() {
        return Vec::new();
    }
    zw.sort_by_key(|&(a, _)| a);

    let mut out = Vec::with_capacity(zw.len());
    for (i, (_, name_ptr)) in zw.iter().enumerate() {
        out.push(SyscallEntry {
            key: make_nt_key(cstr(*name_ptr)),
            syscall_number: i as u32,
            offset: 0,
        });
    }
    out
}

#[cfg(target_pointer_width = "64")]
unsafe fn rva_to_name(module: &ModuleInfo) -> HashMap<u32, *const u8> {
    let exp = &*module.export_dir;
    let funcs = module.base.offset(exp.AddressOfFunctions as isize) as *const u32;
    let names = module.base.offset(exp.AddressOfNames as isize) as *const u32;
    let ords = module.base.offset(exp.AddressOfNameOrdinals as isize) as *const u16;

    let mut map = HashMap::with_capacity(exp.NumberOfNames as usize);
    for i in 0..exp.NumberOfNames {
        let name = module.base.offset(*names.offset(i as isize) as isize);
        let ord = *ords.offset(i as isize) as isize;
        let rva = *funcs.offset(ord);
        map.insert(rva, name as *const u8);
    }
    map
}

unsafe fn cstr<'a>(ptr: *const u8) -> &'a [u8] {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    slice::from_raw_parts(ptr, len)
}

/// Convert `Zw...` (or any 2-byte prefixed export) into the corresponding
/// `Nt...` syscall key. Replicates the two-byte overwrite in the C++ code.
unsafe fn make_nt_key(name: &[u8]) -> SyscallKey {
    let mut buf = [0u8; 128];
    let n = name.len().min(buf.len() - 1);
    buf[..n].copy_from_slice(&name[..n]);
    buf[0] = b'N';
    buf[1] = b't';
    let cstr = &buf[..n];
    #[cfg(not(feature = "no_hash"))]
    {
        crate::hash::hash_bytes(cstr)
    }
    #[cfg(feature = "no_hash")]
    {
        std::str::from_utf8_unchecked(cstr).to_owned()
    }
}

