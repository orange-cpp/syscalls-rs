//! Compile-time and runtime string hashing (mirrors `hash.hpp`).
//!
//! Same polynomial as the C++ side so generated hashes are bit-identical.

pub type Hash = u64;

// Mirrors `#define SYSCALLS_HASH_SEED 0`. Override via env var at build time
// is *not* supported here — pick whatever you need by editing this constant
// (parity with the macro is identical in practice since `0` is the default).
pub const CONFIGURED_SEED: Hash = 0;
pub const CURRENT_SEED: Hash = CONFIGURED_SEED;

pub const POLY_KEY_1: Hash = 0xAF6F01BD5B2D7583u64 ^ CURRENT_SEED;
pub const POLY_KEY_2: Hash = 0xB4F281729182741Du64 ^ CURRENT_SEED.rotate_right(7);

#[inline]
const fn step(mut hash: Hash, byte: u8) -> Hash {
    hash ^= byte as Hash;
    hash = hash.wrapping_add(hash.rotate_right(11)).wrapping_add(POLY_KEY_2);
    hash
}

/// Hash a NUL-terminated byte string (callable in `const` context).
pub const fn hash_bytes(data: &[u8]) -> Hash {
    let mut hash = POLY_KEY_1;
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == 0 {
            break;
        }
        hash = step(hash, b);
        i += 1;
    }
    hash
}

/// Hash up to `len` bytes of `data`, stopping early at NUL — mirrors
/// `calculateHash(const char*, size_t)`.
pub const fn hash_bytes_len(data: &[u8], len: usize) -> Hash {
    let mut hash = POLY_KEY_1;
    let mut i = 0;
    let cap = if len < data.len() { len } else { data.len() };
    while i < cap {
        let b = data[i];
        if b == 0 {
            break;
        }
        hash = step(hash, b);
        i += 1;
    }
    hash
}

/// Const-friendly `&str` hash.
pub const fn hash_str(s: &str) -> Hash {
    hash_bytes(s.as_bytes())
}

/// Runtime case-insensitive ANSI hash (mirrors `calculateHashRuntimeCi`).
#[inline]
pub fn hash_runtime_ci(data: &[u8]) -> Hash {
    let mut hash = POLY_KEY_1;
    for &b in data {
        if b == 0 {
            break;
        }
        let lower = if b.is_ascii_uppercase() { b + 0x20 } else { b };
        hash = step(hash, lower);
    }
    hash
}

/// Runtime case-insensitive UTF-16 hash. Non-ASCII chars are truncated to a
/// byte — matches the C++ `static_cast<char>(toLower(wchar_t))` behavior.
#[inline]
pub fn hash_runtime_ci_wide(data: &[u16]) -> Hash {
    let mut hash = POLY_KEY_1;
    for &wc in data {
        if wc == 0 {
            break;
        }
        let lower = if (b'A' as u16..=b'Z' as u16).contains(&wc) {
            (wc + 0x20) as u8
        } else {
            wc as u8
        };
        hash = step(hash, lower);
    }
    hash
}

/// Append the literal ".dll" to an existing hash.
#[inline]
pub fn append_dll_hash(mut hash: Hash) -> Hash {
    for &b in b".dll" {
        hash = step(hash, b);
    }
    hash
}

/// `SYSCALL_ID!("...")` — compile-time hash of a string literal.
#[cfg(not(feature = "no_hash"))]
#[macro_export]
macro_rules! syscall_id {
    ($s:expr) => {{
        const __H: $crate::hash::Hash = $crate::hash::hash_str($s);
        __H
    }};
}

/// `SYSCALL_ID!("...")` — under `no_hash`, returns the string itself.
#[cfg(feature = "no_hash")]
#[macro_export]
macro_rules! syscall_id {
    ($s:expr) => {
        ::core::convert::Into::<::std::string::String>::into($s)
    };
}

/// `SYSCALL_ID_RT!(...)` — runtime equivalent (ASCII, case-sensitive).
#[cfg(not(feature = "no_hash"))]
#[macro_export]
macro_rules! syscall_id_rt {
    ($s:expr) => {
        $crate::hash::hash_bytes(::core::convert::AsRef::<[u8]>::as_ref(&$s))
    };
}

#[cfg(feature = "no_hash")]
#[macro_export]
macro_rules! syscall_id_rt {
    ($s:expr) => {
        ::std::string::String::from($s)
    };
}
