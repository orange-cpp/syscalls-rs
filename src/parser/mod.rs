//! Syscall-number parsing policies.
//!
//! On Windows: `Directory` and `Signature` parsers extract syscall numbers
//! from loaded PE modules (ntdll.dll).
//! On Linux: `Table` parser provides syscall numbers from a built-in table.

use crate::types::{ModuleInfo, SyscallEntry};

#[cfg(windows)]
pub mod directory;
#[cfg(windows)]
pub mod signature;
pub mod table;

#[cfg(windows)]
pub use directory::Directory;
#[cfg(windows)]
pub use signature::Signature;
pub use table::Table;

pub trait Parser {
    fn parse(module: &ModuleInfo) -> Vec<SyscallEntry>;
}

/// Chain of parser policies — earlier entries are tried first; on empty
/// result, the next one is attempted (mirrors `ParserChain_t`).
pub trait ParserChain {
    fn parse(module: &ModuleInfo) -> Vec<SyscallEntry>;
}

impl<P: Parser> ParserChain for (P,) {
    fn parse(m: &ModuleInfo) -> Vec<SyscallEntry> {
        P::parse(m)
    }
}

impl<P1: Parser, P2: Parser> ParserChain for (P1, P2) {
    fn parse(m: &ModuleInfo) -> Vec<SyscallEntry> {
        let v = P1::parse(m);
        if !v.is_empty() {
            v
        } else {
            P2::parse(m)
        }
    }
}

impl<P1: Parser, P2: Parser, P3: Parser> ParserChain for (P1, P2, P3) {
    fn parse(m: &ModuleInfo) -> Vec<SyscallEntry> {
        let v = P1::parse(m);
        if !v.is_empty() {
            return v;
        }
        let v = P2::parse(m);
        if !v.is_empty() {
            return v;
        }
        P3::parse(m)
    }
}

/// Default parser chain — platform-specific.
#[cfg(windows)]
pub type DefaultChain = (Directory, Signature);

#[cfg(target_os = "linux")]
pub type DefaultChain = (Table,);
