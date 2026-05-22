//! NT-level constants, structs, and helpers (mirrors `shared.hpp`).
//!
//! Most public symbols are re-exports of `windows-sys` types under our own
//! ergonomic aliases. Internal PE/NT structs that aren't exposed by
//! `windows-sys` are redefined here.

use core::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;
pub use windows_sys::Win32::Foundation::NTSTATUS;
pub use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64, IMAGE_RUNTIME_FUNCTION_ENTRY,
    IMAGE_SECTION_HEADER,
};
pub use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};

#[cfg(target_pointer_width = "64")]
pub type ImageNtHeaders = IMAGE_NT_HEADERS64;
#[cfg(target_pointer_width = "32")]
pub type ImageNtHeaders = IMAGE_NT_HEADERS32;

pub type ImageExportDirectory = IMAGE_EXPORT_DIRECTORY;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;

pub const STATUS_SUCCESS: NTSTATUS = 0x0000_0000;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC000_0001u32 as i32;
pub const STATUS_PROCEDURE_NOT_FOUND: NTSTATUS = 0xC000_007Au32 as i32;

#[inline]
pub const fn is_success(status: NTSTATUS) -> bool {
    status >= 0
}

#[inline]
pub const fn current_process() -> HANDLE {
    -1isize as HANDLE
}

#[allow(non_snake_case, dead_code)]
#[repr(C)]
pub struct UnicodeString {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct ListEntry {
    pub Flink: *mut ListEntry,
    pub Blink: *mut ListEntry,
}

#[allow(non_snake_case, dead_code)]
#[repr(C)]
pub struct LdrDataTableEntry {
    pub InLoadOrderLinks: ListEntry,
    pub InMemoryOrderLinks: ListEntry,
    pub InInitializationOrderLinks: ListEntry,
    pub DllBase: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UnicodeString,
    pub BaseDllName: UnicodeString,
    // ...rest of fields omitted — we never reach past here.
}

#[allow(non_snake_case, dead_code)]
#[repr(C)]
pub struct PebLdrData {
    pub Length: u32,
    pub Initialized: u8,
    pub SsHandle: *mut c_void,
    pub InLoadOrderModuleList: ListEntry,
    pub InMemoryOrderModuleList: ListEntry,
    pub InInitializationOrderModuleList: ListEntry,
}

#[allow(non_snake_case, dead_code)]
#[repr(C)]
pub struct Peb {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    #[cfg(target_pointer_width = "64")]
    pub _pad: u32,
    pub Mutant: *mut c_void,
    pub ImageBaseAddress: *mut c_void,
    pub Ldr: *mut PebLdrData,
}

// ---- NT API function-pointer typedefs ---------------------------------------

pub type LargeInteger = i64;
pub type SizeT = usize;
pub type AccessMask = u32;

pub const SECTION_ALL_ACCESS: u32 = 0xF001F;
pub const SEC_COMMIT: u32 = 0x0800_0000;
pub const SECTION_NO_CHANGE: u32 = 0x0040_0000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub const MEM_COMMIT: u32 = 0x0000_1000;
pub const MEM_RESERVE: u32 = 0x0000_2000;
pub const MEM_RELEASE: u32 = 0x0000_8000;

pub const HEAP_CREATE_ENABLE_EXECUTE: u32 = 0x0004_0000;
pub const HEAP_GROWABLE: u32 = 0x0000_0002;

pub const VIEW_SHARE: u32 = 1;

pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
pub const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;

pub type NtCreateSection = unsafe extern "system" fn(
    section_handle: *mut HANDLE,
    desired_access: AccessMask,
    object_attributes: *mut c_void,
    maximum_size: *mut LargeInteger,
    section_page_protection: u32,
    allocation_attributes: u32,
    file_handle: HANDLE,
) -> NTSTATUS;

pub type NtMapViewOfSection = unsafe extern "system" fn(
    section_handle: HANDLE,
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    commit_size: SizeT,
    section_offset: *mut LargeInteger,
    view_size: *mut SizeT,
    inherit_disposition: u32,
    allocation_type: u32,
    win32_protect: u32,
) -> NTSTATUS;

pub type NtUnmapViewOfSection =
    unsafe extern "system" fn(process_handle: HANDLE, base_address: *mut c_void) -> NTSTATUS;

pub type NtAllocateVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    zero_bits: usize,
    region_size: *mut SizeT,
    allocation_type: u32,
    protect: u32,
) -> NTSTATUS;

pub type NtProtectVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut SizeT,
    new_protect: u32,
    old_protect: *mut u32,
) -> NTSTATUS;

pub type NtFreeVirtualMemory = unsafe extern "system" fn(
    process_handle: HANDLE,
    base_address: *mut *mut c_void,
    region_size: *mut SizeT,
    free_type: u32,
) -> NTSTATUS;

pub type NtClose = unsafe extern "system" fn(handle: HANDLE) -> NTSTATUS;

pub type RtlCreateHeap = unsafe extern "system" fn(
    flags: u32,
    heap_base: *mut c_void,
    reserve_size: SizeT,
    commit_size: SizeT,
    lock: *mut c_void,
    parameters: *mut c_void,
) -> *mut c_void;

pub type RtlAllocateHeap =
    unsafe extern "system" fn(heap_handle: *mut c_void, flags: u32, size: SizeT) -> *mut c_void;

pub type RtlDestroyHeap = unsafe extern "system" fn(heap_handle: *mut c_void) -> *mut c_void;
