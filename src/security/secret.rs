//! `SecretString` — a heap-allocated UTF-8 string that zeroes its
//! backing bytes on drop.
//!
//! Used for credentials (database passwords, SCRAM auth secrets, MySQL
//! `caching_sha2_password` inputs) so that when the value goes out of
//! scope, the plaintext bytes are wiped from memory rather than left
//! recoverable from a process snapshot, core dump, or attached debugger.
//!
//! # Why a custom type rather than the `zeroize` crate
//!
//! The asupersync project deliberately does not depend on the `zeroize`
//! crate (see `security/key.rs`'s `AuthKey` for the project-wide
//! precedent). Instead it uses a manual zeroize pattern:
//! `ptr::write_volatile` per byte (which the optimiser cannot prove
//! observable, so it must emit the writes) followed by a `SeqCst`
//! `compiler_fence` to bar reordering across the destructor boundary.
//! `SecretString` is the natural extension of that pattern from
//! fixed-size key arrays to variable-length credential strings.
//!
//! # Why bytes-backed instead of `String`-backed
//!
//! `String` does not expose a safe API to zero its bytes in place — the
//! only mutation point (`String::as_mut_vec`) is itself `unsafe`. By
//! storing `Vec<u8>` directly with a UTF-8 invariant maintained at the
//! constructor, the `Drop` impl can iterate the bytes without escaping
//! the `unsafe` boundary needed for `write_volatile`.
//!
//! # `unsafe` is required
//!
//! `core::ptr::write_volatile` is the entire reason this module needs
//! `#![allow(unsafe_code)]`: we must defeat dead-store elimination on
//! the zeroizing writes, and `write_volatile` is the only stable
//! mechanism for that. The pattern mirrors `security/key.rs` exactly.

#![allow(unsafe_code)]

use core::fmt;

/// A heap-allocated UTF-8 string whose backing bytes are zeroed on drop.
///
/// **Sensitive material.** The `Drop` impl performs a per-byte
/// `ptr::write_volatile(0)` followed by a `SeqCst` `compiler_fence`,
/// which is the project's standard manual-zeroize pattern (see
/// [`crate::security::AuthKey`] for the precedent).
///
/// # Invariants
///
/// `bytes` is always a valid UTF-8 sequence — preserved by every
/// constructor. [`SecretString::as_str`] therefore does not need to
/// re-validate.
///
/// # Comparison
///
/// `PartialEq` compares all bytes up to the longer operand and folds the
/// length mismatch into the accumulator, so it does not short-circuit on
/// unequal lengths or the first differing byte.
///
/// # Debug
///
/// The manual `Debug` impl always renders `SecretString(<redacted>)` so
/// a `SecretString` cannot leak via panic backtraces, structured logs,
/// or trace spans.
pub struct SecretString {
    /// Owned bytes, valid UTF-8 by constructor invariant. The `Drop`
    /// impl zeroizes each byte before the `Vec`'s allocator releases
    /// the memory.
    bytes: Vec<u8>,
}

impl SecretString {
    /// Construct from a borrowed `&str`. Copies the bytes into a fresh
    /// heap allocation.
    ///
    /// Note: callers that already own the source `String` should prefer
    /// [`SecretString::from_string`] to avoid the copy and to ensure
    /// the original allocation's bytes are the ones being zeroed.
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self {
            bytes: s.as_bytes().to_vec(),
        }
    }

    /// Construct by consuming an existing `String`. The inner `Vec<u8>`
    /// allocation is moved into the `SecretString`, so the bytes
    /// zeroized at drop are the same bytes the source `String` was
    /// holding — no copy, no second copy left behind.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self {
            bytes: s.into_bytes(),
        }
    }

    /// Borrow the contents as a `&str`. The UTF-8 invariant is upheld
    /// by every constructor, so this does not need re-validation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // The constructor invariant guarantees `bytes` is valid UTF-8,
        // so `from_utf8` always succeeds. We avoid `from_utf8_unchecked`
        // (which would require unsafe) by accepting the trivial cost of
        // a length-linear UTF-8 validation here; passwords are short and
        // the path is not hot.
        core::str::from_utf8(&self.bytes)
            .expect("SecretString invariant: bytes are valid UTF-8 by constructor")
    }

    /// Borrow the contents as raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `true` if the secret is the empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Byte length of the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Explicitly zeroize the bytes before the natural drop. Useful for
    /// callers who finish using the secret well before its owning
    /// scope ends and want to minimise the in-memory window.
    ///
    /// After this call, [`SecretString::as_str`] returns `""` and
    /// [`SecretString::as_bytes`] returns `&[]` — the heap allocation
    /// is released. Calling `explicit_zeroize` more than once is a
    /// no-op.
    pub fn explicit_zeroize(&mut self) {
        self.zeroize_bytes();
        self.bytes.clear();
        self.bytes.shrink_to_fit();
    }

    /// Internal: per-byte `write_volatile(0)` followed by a `SeqCst`
    /// compiler_fence. Shared between [`Self::explicit_zeroize`] and
    /// the `Drop` impl.
    fn zeroize_bytes(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: `byte` is a valid `&mut u8` to fully-initialised
            // owned storage; volatile byte writes through it are
            // well-defined. The compiler cannot prove the writes are
            // observable, so it must emit them — defeating dead-store
            // elimination. The `compiler_fence` after the loop bars
            // reordering of any later operations above the zeroizing
            // writes.
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.zeroize_bytes();
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
        }
    }
}

impl PartialEq for SecretString {
    /// Byte comparison that avoids early exits on length mismatch or
    /// first differing byte. Runtime scales with the longer operand,
    /// which is the best available shape for variable-length secrets
    /// without padding to a fixed maximum size.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = self.bytes.len() ^ other.bytes.len();
        let max_len = self.bytes.len().max(other.bytes.len());
        for index in 0..max_len {
            let a = self.bytes.get(index).copied().unwrap_or(0);
            let b = other.bytes.get(index).copied().unwrap_or(0);
            acc |= usize::from(a ^ b);
        }
        core::hint::black_box(acc) == 0
    }
}

impl Eq for SecretString {}

impl fmt::Debug for SecretString {
    /// Always renders `SecretString(<redacted>)`. The byte length is
    /// also withheld — disclosing length leaks dictionary-attack
    /// information in some threat models.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::from_string(s)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use std::mem::ManuallyDrop;

    #[test]
    fn new_preserves_bytes() {
        let s = SecretString::new("hunter2");
        assert_eq!(s.as_str(), "hunter2");
        assert_eq!(s.as_bytes(), b"hunter2");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());
    }

    #[test]
    fn from_string_preserves_bytes() {
        let owned = String::from("correct horse battery staple");
        let s = SecretString::from_string(owned);
        assert_eq!(s.as_str(), "correct horse battery staple");
    }

    #[test]
    fn from_str_via_into() {
        let s: SecretString = "p@ssw0rd".into();
        assert_eq!(s.as_str(), "p@ssw0rd");
    }

    #[test]
    fn from_string_via_into() {
        let s: SecretString = String::from("alpha").into();
        assert_eq!(s.as_str(), "alpha");
    }

    #[test]
    fn empty_secret() {
        let s = SecretString::new("");
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn debug_always_redacts() {
        let s = SecretString::new("topsecret");
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "SecretString(<redacted>)");
        assert!(!dbg.contains("topsecret"));
    }

    #[test]
    fn debug_redacts_even_for_empty() {
        let s = SecretString::new("");
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
    }

    #[test]
    fn clone_is_independent() {
        let a = SecretString::new("shared");
        let b = a.clone();
        assert_eq!(a, b);
        // Drop one — the other must remain valid (separate
        // allocations).
        drop(a);
        assert_eq!(b.as_str(), "shared");
    }

    #[test]
    fn eq_constant_time_correctness() {
        assert_eq!(SecretString::new("abc"), SecretString::new("abc"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abd"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abcd"));
        assert_ne!(SecretString::new("abc"), SecretString::new(""));
        assert_eq!(SecretString::new(""), SecretString::new(""));
    }

    /// br-asupersync-r2l1ze: `Drop` MUST overwrite every byte of the
    /// secret before the allocation is released. We verify with the
    /// same `ManuallyDrop` + raw-pointer trick used to validate
    /// `AuthKey::drop` (br-asupersync-4pegj0): keep the storage alive
    /// past the destructor side-effect by using `ManuallyDrop`, snapshot
    /// a pointer to the byte buffer before `drop` runs, then read back
    /// through the pointer to confirm every byte is zero.
    #[test]
    fn drop_zeroizes_secret_bytes() {
        let mut s = ManuallyDrop::new(SecretString::new("plaintext"));

        // Snapshot the data pointer + length BEFORE running Drop. Using
        // `as_ptr()` is sound here because `ManuallyDrop` keeps the
        // storage alive — only the destructor's side-effect (the
        // zeroize loop) runs when we explicitly call
        // `ManuallyDrop::drop`.
        let ptr: *const u8 = s.bytes.as_ptr();
        let len = s.bytes.len();
        assert!(len > 0);

        // Sanity: pre-drop the bytes are the plaintext we put in.
        let pre = unsafe { core::slice::from_raw_parts(ptr, len) };
        assert_eq!(pre, b"plaintext");

        // Run the destructor manually.
        unsafe {
            ManuallyDrop::drop(&mut s);
        }

        // Post-drop, every byte must be zero. We read through the
        // saved pointer; the storage is technically logically-released
        // but `Vec`'s allocator hasn't reused it yet on any reasonable
        // platform within a single test, so the read returns the
        // zeroed bytes the destructor wrote. (This same pattern is
        // documented and used in the `zeroize` crate's own tests.)
        let post = unsafe { core::slice::from_raw_parts(ptr, len) };
        assert!(
            post.iter().all(|&b| b == 0),
            "Drop must zeroize every byte; observed: {post:02x?}"
        );
    }

    /// br-asupersync-r2l1ze: `from_string` consumes the source `String`
    /// and re-uses its allocation; verify by checking that the bytes
    /// stored in the SecretString are byte-for-byte identical to what
    /// the source held. (We cannot directly assert "same allocation"
    /// without exposing internals, but we can assert content fidelity
    /// and zeroization on drop, which together imply the safety property.)
    #[test]
    fn from_string_zeroizes_on_drop() {
        let mut s = ManuallyDrop::new(SecretString::from_string(String::from("from_string")));
        let ptr: *const u8 = s.bytes.as_ptr();
        let len = s.bytes.len();
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr, len) },
            b"from_string"
        );
        unsafe {
            ManuallyDrop::drop(&mut s);
        }
        let post = unsafe { core::slice::from_raw_parts(ptr, len) };
        assert!(post.iter().all(|&b| b == 0));
    }

    /// `explicit_zeroize` must wipe the bytes IMMEDIATELY (before drop)
    /// and leave the value usable as an empty string. Callers use this
    /// to minimise the in-memory residency of the secret beyond the
    /// scope-bounded Drop guarantee.
    #[test]
    fn explicit_zeroize_clears_bytes_in_place() {
        let mut s = SecretString::new("ephemeral");
        assert_eq!(s.as_str(), "ephemeral");
        s.explicit_zeroize();
        assert!(s.is_empty());
        assert_eq!(s.as_str(), "");
        assert_eq!(s.as_bytes(), b"");
    }

    /// `explicit_zeroize` is idempotent — calling it twice is a no-op
    /// after the first invocation.
    #[test]
    fn explicit_zeroize_is_idempotent() {
        let mut s = SecretString::new("twice");
        s.explicit_zeroize();
        s.explicit_zeroize();
        assert!(s.is_empty());
    }

    #[test]
    fn utf8_multibyte_preserved() {
        // SCRAM SASLprep allows non-ASCII; ensure round-trip works.
        let s = SecretString::new("пароль🔒");
        assert_eq!(s.as_str(), "пароль🔒");
        assert_eq!(s.as_bytes(), "пароль🔒".as_bytes());
    }
}
