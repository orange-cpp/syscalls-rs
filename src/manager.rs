//! Generic syscall manager — generic over Allocator, StubGenerator, and
//! ParserChain (mirrors `ManagerImpl` + `Manager` + `aliases.hpp`).

use core::ffi::c_void;
use core::marker::PhantomData;
use std::cell::Cell;
use std::sync::Mutex;

use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, EXCEPTION_POINTERS,
};

use crate::allocator::{AllocatedRegion, Allocator};
use crate::generator::StubGenerator;
use crate::hash::hash_str;
use crate::native::{get_module_base_by_hash, rdtscp};
use crate::parser::ParserChain;
use crate::shared::{
    is_success, ImageNtHeaders, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
    EXCEPTION_ILLEGAL_INSTRUCTION, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
    IMAGE_NT_SIGNATURE, NTSTATUS, STATUS_PROCEDURE_NOT_FOUND, STATUS_UNSUCCESSFUL,
};
use crate::types::{ModuleInfo, SyscallEntry, SyscallKey};

// ---------------------------------------------------------------------------
// Vectored Exception Handler (mirrors syscall.hpp top-level VEH code).

#[derive(Default, Clone, Copy)]
struct ExceptionContext {
    should_handle: bool,
    expected_address: *const c_void,
    syscall_gadget: *mut c_void,
    syscall_number: u32,
}

thread_local! {
    static EXC_CTX: Cell<ExceptionContext> = const { Cell::new(ExceptionContext {
        should_handle: false,
        expected_address: core::ptr::null(),
        syscall_gadget: core::ptr::null_mut(),
        syscall_number: 0,
    }) };
}

/// RAII guard installing per-thread exception state.
pub struct ExceptionGuard;

impl ExceptionGuard {
    fn new(addr: *const c_void, gadget: *mut c_void, number: u32) -> Self {
        EXC_CTX.with(|c| {
            c.set(ExceptionContext {
                should_handle: true,
                expected_address: addr,
                syscall_gadget: gadget,
                syscall_number: number,
            });
        });
        Self
    }
}

impl Drop for ExceptionGuard {
    fn drop(&mut self) {
        EXC_CTX.with(|c| {
            let mut ctx = c.get();
            ctx.should_handle = false;
            c.set(ctx);
        });
    }
}

unsafe extern "system" fn veh(info: *mut EXCEPTION_POINTERS) -> i32 {
    let ctx = EXC_CTX.with(|c| c.get());
    if !ctx.should_handle {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    let rec = (*info).ExceptionRecord;
    let context = (*info).ContextRecord;
    if (*rec).ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION as i32 {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (*rec).ExceptionAddress as *const c_void != ctx.expected_address {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    EXC_CTX.with(|c| {
        let mut new = c.get();
        new.should_handle = false;
        c.set(new);
    });

    #[cfg(target_pointer_width = "64")]
    {
        (*context).R10 = (*context).Rcx;
        (*context).Rax = ctx.syscall_number as u64;
        (*context).Rip = ctx.syscall_gadget as u64;
    }
    #[cfg(target_pointer_width = "32")]
    {
        let ret_after = (*rec).ExceptionAddress as usize + 2;
        (*context).Edx = (*context).Esp;
        (*context).Esp -= core::mem::size_of::<usize>() as u32;
        *((*context).Esp as *mut usize) = ret_after;
        (*context).Eip = ctx.syscall_gadget as u32;
        (*context).Eax = ctx.syscall_number;
    }

    EXCEPTION_CONTINUE_EXECUTION
}

// ---------------------------------------------------------------------------
// Manager.

pub struct Manager<A: Allocator, G: StubGenerator, C: ParserChain = crate::parser::DefaultChain> {
    state: Mutex<Option<State>>,
    _marker: PhantomData<(A, G, C)>,
}

struct State {
    entries: Vec<SyscallEntry>,
    region: AllocatedRegion,
    gadgets: Vec<*mut c_void>,
    veh_handle: *mut c_void,
}

unsafe impl Send for State {}

impl<A: Allocator, G: StubGenerator, C: ParserChain> Default for Manager<A, G, C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Allocator, G: StubGenerator, C: ParserChain> Manager<A, G, C> {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(None),
            _marker: PhantomData,
        }
    }

    /// Parse + allocate executable region. Idempotent.
    /// `module_keys` defaults to `["ntdll.dll"]`.
    pub fn initialize(&self) -> bool {
        self.initialize_with(&[hash_str("ntdll.dll")])
    }

    pub fn initialize_with(&self, module_keys: &[u64]) -> bool {
        let mut guard = self.state.lock().unwrap();
        if guard.is_some() {
            return true;
        }

        #[cfg(target_pointer_width = "64")]
        let gadgets = if G::REQUIRES_GADGET {
            match find_syscall_gadgets() {
                Some(g) if !g.is_empty() => g,
                _ => return false,
            }
        } else {
            Vec::new()
        };
        #[cfg(target_pointer_width = "32")]
        let gadgets: Vec<*mut c_void> = Vec::new();

        let mut all = Vec::<SyscallEntry>::new();
        for &k in module_keys {
            if let Some(info) = unsafe { module_info(k) } {
                let v = C::parse(&info);
                all.extend(v);
            }
        }
        if all.is_empty() {
            return false;
        }

        // Fisher-Yates–style shuffle keyed by rdtscp (parity with C++).
        if all.len() > 1 {
            for i in (1..all.len()).rev() {
                let j = (rdtscp() as usize) % (i + 1);
                all.swap(i, j);
            }
        }
        let stub_size = G::stub_size();
        for (i, e) in all.iter_mut().enumerate() {
            e.offset = (i * stub_size) as u32;
        }
        all.sort_by(|a, b| key_cmp(&a.key, &b.key));

        // Build stubs into a temp buffer, then hand to allocator.
        let region_size = all.len() * stub_size;
        let mut buf = vec![0u8; region_size];
        for entry in &all {
            let off = entry.offset as usize;
            let slot = &mut buf[off..off + stub_size];
            let gadget = if G::REQUIRES_GADGET && !gadgets.is_empty() {
                gadgets[(rdtscp() as usize) % gadgets.len()]
            } else {
                core::ptr::null_mut()
            };
            G::generate(slot, entry.syscall_number, gadget);
        }
        let Some(region) = A::allocate(&buf) else {
            return false;
        };

        let mut veh_handle: *mut c_void = core::ptr::null_mut();
        if G::IS_EXCEPTION {
            let h = unsafe { AddVectoredExceptionHandler(1, Some(veh)) };
            if h.is_null() {
                A::release(region);
                return false;
            }
            veh_handle = h;
        }

        *guard = Some(State {
            entries: all,
            region,
            gadgets,
            veh_handle,
        });
        true
    }

    /// Look up a syscall stub address by key. Initializes lazily.
    /// Returns the executable stub pointer plus an optional VEH guard that
    /// must outlive the call.
    pub fn invoke(&self, key: SyscallKey) -> Option<Invocation<'_, G>> {
        if self.state.lock().unwrap().is_none() && !self.initialize() {
            return None;
        }
        let guard = self.state.lock().unwrap();
        let state = guard.as_ref()?;
        let idx = state
            .entries
            .binary_search_by(|e| key_cmp(&e.key, &key))
            .ok()?;
        let entry = &state.entries[idx];
        let stub = unsafe {
            (state.region.region as *mut u8).offset(entry.offset as isize) as *const c_void
        };

        let veh_guard = if G::IS_EXCEPTION {
            #[cfg(target_pointer_width = "64")]
            {
                if state.gadgets.is_empty() {
                    return None;
                }
                let g = state.gadgets[(rdtscp() as usize) % state.gadgets.len()];
                Some(ExceptionGuard::new(stub, g, entry.syscall_number))
            }
            #[cfg(target_pointer_width = "32")]
            {
                // On x86, the gadget is fs:[0xC0] (KiFastSystemCall pointer).
                let g = unsafe {
                    let v: usize;
                    core::arch::asm!("mov {0}, fs:[0xC0]", out(reg) v);
                    v as *mut c_void
                };
                Some(ExceptionGuard::new(stub, g, entry.syscall_number))
            }
        } else {
            None
        };

        Some(Invocation {
            stub,
            _veh: veh_guard,
            _marker: PhantomData,
        })
    }
}

impl<A: Allocator, G: StubGenerator, C: ParserChain> Drop for Manager<A, G, C> {
    fn drop(&mut self) {
        let mut guard = self.state.lock().unwrap();
        if let Some(state) = guard.take() {
            if !state.veh_handle.is_null() {
                unsafe { RemoveVectoredExceptionHandler(state.veh_handle) };
            }
            A::release(state.region);
        }
    }
}

/// Holds a stub pointer and (if needed) keeps a VEH guard alive for the call.
pub struct Invocation<'a, G: StubGenerator> {
    stub: *const c_void,
    _veh: Option<ExceptionGuard>,
    _marker: PhantomData<&'a G>,
}

impl<'a, G: StubGenerator> Invocation<'a, G> {
    /// Raw stub pointer; cast to the appropriate `extern "system" fn`.
    pub fn as_ptr(&self) -> *const c_void {
        self.stub
    }

    /// Transmute the stub into a typed function pointer.
    ///
    /// # Safety
    /// `F` must be a `Copy` function pointer matching the syscall's ABI.
    pub unsafe fn as_fn<F: Copy>(&self) -> F {
        debug_assert_eq!(core::mem::size_of::<F>(), core::mem::size_of::<*const c_void>());
        core::mem::transmute_copy(&self.stub)
    }
}

// ---------------------------------------------------------------------------
// Sort/compare helpers — works for both u64 and String keys.

#[cfg(not(feature = "no_hash"))]
fn key_cmp(a: &SyscallKey, b: &SyscallKey) -> core::cmp::Ordering {
    a.cmp(b)
}
#[cfg(feature = "no_hash")]
fn key_cmp(a: &SyscallKey, b: &SyscallKey) -> core::cmp::Ordering {
    a.as_str().cmp(b.as_str())
}

// ---------------------------------------------------------------------------
// PE helpers.

unsafe fn module_info(name_hash: u64) -> Option<ModuleInfo> {
    let base = get_module_base_by_hash(name_hash);
    if base.is_null() {
        return None;
    }
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }
    let nt =
        (base as *const u8).offset((*dos).e_lfanew as isize) as *const ImageNtHeaders;
    if (*nt).Signature != IMAGE_NT_SIGNATURE {
        return None;
    }
    let export_rva =
        (*nt).OptionalHeader.DataDirectory[crate::shared::IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    if export_rva == 0 {
        return None;
    }
    let exp =
        (base as *const u8).offset(export_rva as isize) as *const crate::shared::ImageExportDirectory;
    Some(ModuleInfo {
        base: base as *mut u8,
        nt_headers: nt,
        export_dir: exp,
    })
}

#[cfg(target_pointer_width = "64")]
fn find_syscall_gadgets() -> Option<Vec<*mut c_void>> {
    use crate::shared::IMAGE_SECTION_HEADER;
    let info = unsafe { module_info(hash_str("ntdll.dll")) }?;
    let nt = unsafe { &*info.nt_headers };

    // IMAGE_FIRST_SECTION = (BYTE*)nt + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + SizeOfOptionalHeader
    let sections_ptr = unsafe {
        (info.nt_headers as *const u8)
            .add(core::mem::size_of::<u32>() + core::mem::size_of::<windows_sys::Win32::System::Diagnostics::Debug::IMAGE_FILE_HEADER>())
            .add(nt.FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER
    };
    let sections = unsafe {
        core::slice::from_raw_parts(sections_ptr, nt.FileHeader.NumberOfSections as usize)
    };

    let mut text: Option<(*mut u8, usize)> = None;
    for s in sections {
        if &s.Name[..5] == b".text" && s.Name[5] == 0 {
            text = Some((
                unsafe { info.base.offset(s.VirtualAddress as isize) },
                unsafe { s.Misc.VirtualSize as usize },
            ));
            break;
        }
    }
    let (text_ptr, text_size) = text?;
    let mut gadgets = Vec::new();
    unsafe {
        let bytes = core::slice::from_raw_parts(text_ptr, text_size);
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3 {
                gadgets.push(text_ptr.add(i) as *mut c_void);
            }
        }
    }
    if gadgets.is_empty() {
        None
    } else {
        Some(gadgets)
    }
}

// ---------------------------------------------------------------------------
// Suppress the unused-import warning in builds where STATUS_* aren't used by
// public API but are kept for parity.

#[allow(dead_code)]
const _UNUSED: NTSTATUS = STATUS_UNSUCCESSFUL ^ STATUS_PROCEDURE_NOT_FOUND;

#[allow(dead_code)]
fn _is_success_used(s: NTSTATUS) -> bool {
    is_success(s)
}
