//! PEB walking, module/export resolution, rdtscp (mirrors `native_api.hpp`).

use core::arch::asm;
use core::ffi::c_void;
use core::slice;

use crate::hash::{self, append_dll_hash, hash_runtime_ci, hash_runtime_ci_wide, Hash};
use crate::shared::{
    ImageExportDirectory, ImageNtHeaders, LdrDataTableEntry, ListEntry, Peb,
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

/// Fetch the current process's PEB via gs:[0x60] (x64) or fs:[0x30] (x86).
#[inline]
pub fn current_peb() -> *mut Peb {
    let peb: *mut Peb;
    unsafe {
        #[cfg(target_pointer_width = "64")]
        {
            asm!("mov {0}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
        }
        #[cfg(target_pointer_width = "32")]
        {
            asm!("mov {0}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
        }
    }
    peb
}

/// Read TSC + processor id; used as a non-cryptographic randomness source.
#[inline]
pub fn rdtscp() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let mut aux: u32 = 0;
        unsafe { core::arch::x86_64::__rdtscp(&mut aux as *mut u32) }
    }
    #[cfg(target_arch = "x86")]
    {
        let mut aux: u32 = 0;
        unsafe { core::arch::x86::__rdtscp(&mut aux as *mut u32) }
    }
}

/// Look up a loaded module by case-insensitive hash of its BaseDllName.
pub fn get_module_base_by_hash(name_hash: Hash) -> *mut c_void {
    let peb = current_peb();
    if peb.is_null() {
        return core::ptr::null_mut();
    }
    unsafe {
        let ldr = (*peb).Ldr;
        if ldr.is_null() {
            return core::ptr::null_mut();
        }
        let list_head: *mut ListEntry = &mut (*ldr).InMemoryOrderModuleList;
        let mut current = (*list_head).Flink;
        while !current.is_null() && current != list_head {
            // CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)
            // InMemoryOrderLinks is the second field; offset = sizeof(ListEntry).
            let entry = (current as *mut u8).sub(core::mem::size_of::<ListEntry>())
                as *mut LdrDataTableEntry;
            let buf = (*entry).BaseDllName.Buffer;
            let len_bytes = (*entry).BaseDllName.Length as usize;
            if !buf.is_null() && len_bytes >= 2 {
                let slice_u16 = slice::from_raw_parts(buf, len_bytes / 2);
                if hash_runtime_ci_wide(slice_u16) == name_hash {
                    return (*entry).DllBase;
                }
            }
            current = (*current).Flink;
        }
    }
    core::ptr::null_mut()
}

#[inline]
pub fn get_module_base_str(name: &str) -> *mut c_void {
    get_module_base_by_hash(hash_runtime_ci(name.as_bytes()))
}

#[inline]
pub fn get_module_base_wstr(name: &[u16]) -> *mut c_void {
    get_module_base_by_hash(hash_runtime_ci_wide(name))
}

fn module_export_dir(
    base: *mut c_void,
) -> Option<(*mut u8, *const ImageNtHeaders, *const ImageExportDirectory, u32, u32)> {
    if base.is_null() {
        return None;
    }
    unsafe {
        let base_u8 = base as *mut u8;
        let dos = base_u8 as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }
        let nt = base_u8.offset((*dos).e_lfanew as isize) as *const ImageNtHeaders;
        if (*nt).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        let dir = &(*nt).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if dir.VirtualAddress == 0 {
            return None;
        }
        let exp = base_u8.offset(dir.VirtualAddress as isize) as *const ImageExportDirectory;
        Some((base_u8, nt, exp, dir.VirtualAddress, dir.Size))
    }
}

/// Resolve an export by case-sensitive hash. Follows forwarded exports across
/// modules.
pub fn get_export_by_hash(module: *mut c_void, export_hash: Hash) -> *mut c_void {
    let Some((base, _nt, exp, export_rva, export_size)) = module_export_dir(module) else {
        return core::ptr::null_mut();
    };
    unsafe {
        let names = base.offset((*exp).AddressOfNames as isize) as *const u32;
        let ords = base.offset((*exp).AddressOfNameOrdinals as isize) as *const u16;
        let funcs = base.offset((*exp).AddressOfFunctions as isize) as *const u32;
        let count = (*exp).NumberOfNames;

        for i in 0..count {
            let name_ptr = base.offset(*names.offset(i as isize) as isize) as *const u8;
            if hash::hash_bytes(cstr_slice(name_ptr)) != export_hash {
                continue;
            }
            let ord = *ords.offset(i as isize) as isize;
            let func_rva = *funcs.offset(ord);
            if func_rva < export_rva || func_rva >= export_rva + export_size {
                return base.offset(func_rva as isize) as *mut c_void;
            }
            // Forwarder string: "OtherDll.OtherFunc"
            return resolve_forwarder(base, func_rva);
        }
    }
    core::ptr::null_mut()
}

/// Resolve an export by case-sensitive name (ANSI).
pub fn get_export_by_name(module: *mut c_void, name: &str) -> *mut c_void {
    get_export_by_hash(module, hash::hash_bytes(name.as_bytes()))
}

unsafe fn cstr_slice<'a>(ptr: *const u8) -> &'a [u8] {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    slice::from_raw_parts(ptr, len)
}

unsafe fn resolve_forwarder(base: *mut u8, func_rva: u32) -> *mut c_void {
    let s = cstr_slice(base.offset(func_rva as isize));
    let Some(dot) = s.iter().position(|&b| b == b'.') else {
        return core::ptr::null_mut();
    };
    if dot == 0 || dot == s.len() - 1 {
        return core::ptr::null_mut();
    }
    let (dll, func) = s.split_at(dot);
    let func = &func[1..];

    let mut dll_hash = hash_runtime_ci(dll);
    if dll_hash == 0 {
        return core::ptr::null_mut();
    }
    dll_hash = append_dll_hash(dll_hash);
    let forwarded = get_module_base_by_hash(dll_hash);
    if forwarded.is_null() {
        return core::ptr::null_mut();
    }
    get_export_by_hash(forwarded, hash::hash_bytes(func))
}
