//! `RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE)` allocator.

use core::ffi::c_void;
use core::ptr;

use crate::hash::hash_str;
use crate::native::{get_export_by_hash, get_module_base_by_hash};
use crate::shared::{
    RtlAllocateHeap, RtlCreateHeap, RtlDestroyHeap, HEAP_CREATE_ENABLE_EXECUTE, HEAP_GROWABLE,
};

use super::{AllocatedRegion, Allocator};

pub struct Heap;

impl Allocator for Heap {
    fn allocate(buffer: &[u8]) -> Option<AllocatedRegion> {
        unsafe {
            let ntdll = get_module_base_by_hash(hash_str("ntdll.dll"));
            if ntdll.is_null() {
                return None;
            }
            let f_create = get_export_by_hash(ntdll, hash_str("RtlCreateHeap"));
            let f_alloc = get_export_by_hash(ntdll, hash_str("RtlAllocateHeap"));
            if f_create.is_null() || f_alloc.is_null() {
                return None;
            }
            let create: RtlCreateHeap = core::mem::transmute(f_create);
            let alloc: RtlAllocateHeap = core::mem::transmute(f_alloc);

            let heap = create(
                HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE,
                ptr::null_mut(),
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if heap.is_null() {
                return None;
            }
            let region = alloc(heap, 0, buffer.len());
            if region.is_null() {
                destroy_heap(heap);
                return None;
            }
            core::ptr::copy_nonoverlapping(buffer.as_ptr(), region as *mut u8, buffer.len());
            Some(AllocatedRegion {
                region,
                aux: heap as usize,
            })
        }
    }

    fn release(r: AllocatedRegion) {
        if r.aux == 0 {
            return;
        }
        destroy_heap(r.aux as *mut c_void);
    }
}

fn destroy_heap(heap: *mut c_void) {
    unsafe {
        let ntdll = get_module_base_by_hash(hash_str("ntdll.dll"));
        if ntdll.is_null() {
            return;
        }
        let f = get_export_by_hash(ntdll, hash_str("RtlDestroyHeap"));
        if !f.is_null() {
            let destroy: RtlDestroyHeap = core::mem::transmute(f);
            destroy(heap);
        }
    }
}
