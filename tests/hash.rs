use syscalls_rs::hash::*;

#[test]
fn compile_time_hash_non_zero() {
    const H: Hash = hash_str("NtAllocateVirtualMemory");
    assert_ne!(H, 0);
}

#[test]
fn different_strings_different_hashes() {
    assert_ne!(
        hash_str("NtAllocateVirtualMemory"),
        hash_str("NtFreeVirtualMemory")
    );
}

#[test]
fn same_string_same_hash() {
    assert_eq!(hash_str("ntdll.dll"), hash_str("ntdll.dll"));
}

#[test]
fn partial_with_length() {
    let full = hash_str("Nt");
    let partial = hash_bytes_len(b"NtAllocateVirtualMemory", 2);
    assert_eq!(full, partial);
}

#[test]
fn case_insensitive_hash() {
    assert_eq!(hash_runtime_ci(b"ntdll.dll"), hash_runtime_ci(b"NTDLL.DLL"));
    assert_eq!(hash_runtime_ci(b"ntdll.dll"), hash_runtime_ci(b"NtDlL.DlL"));
}

#[test]
fn ci_wide_matches_ci_byte() {
    let wide: Vec<u16> = "kernel32.dll".encode_utf16().collect();
    assert_eq!(
        hash_runtime_ci(b"kernel32.dll"),
        hash_runtime_ci_wide(&wide)
    );
}

#[test]
fn empty_string_is_poly_key_1() {
    assert_eq!(hash_runtime_ci(b""), POLY_KEY_1);
}

#[test]
fn common_nt_functions_unique() {
    let h = [
        hash_str("NtClose"),
        hash_str("NtOpenProcess"),
        hash_str("NtReadFile"),
        hash_str("NtWriteFile"),
        hash_str("NtCreateFile"),
    ];
    for i in 0..h.len() {
        for j in (i + 1)..h.len() {
            assert_ne!(h[i], h[j]);
        }
    }
}
