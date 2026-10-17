//! `SecretString` — a heap-allocated UTF-8 string that zeroes its
//! backing bytes on drop.
//!
//! Used for credentials (database passwords, SCRAM auth secrets, MySQL
//! `caching_sha2_password` inputs) so that when the value goes out of
//! scope, the plaintext bytes are wiped from memory rather than left
//! recoverable from a process snapshot, core dump, or attached debugger.
//!
//! # How the bytes are wiped
//!
//! `security/key.rs`'s `AuthKey` uses the `zeroize` crate
//! (`ZeroizeOnDrop`). `SecretString` wipes by hand instead:
//! `ptr::write_volatile` per byte over the whole allocation, spare
//! capacity included (the optimiser cannot prove the writes observable,
//! so it must emit them), then a `SeqCst` `compiler_fence` to bar
//! reordering across the destructor boundary. The spare capacity counts
//! because a `String` handed to `from_string` can still hold an earlier,
//! longer value there.
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
//! mechanism for that without the `zeroize` crate.

#![allow(unsafe_code)]

use core::fmt;

/// A heap-allocated UTF-8 string whose backing bytes are zeroed on drop.
///
/// **Sensitive material.** The `Drop` impl performs a per-byte
/// `ptr::write_volatile(0)` over the whole allocation, spare capacity
/// included, followed by a `SeqCst` `compiler_fence`
/// ([`crate::security::AuthKey`] gets the same from `zeroize`).
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
        // Span the spare capacity too; callers then clear or drop the bytes.
        self.bytes.resize(self.bytes.capacity(), 0);
        for byte in &mut self.bytes {
            // SAFETY: `byte` is a valid `&mut u8` to fully-initialised owned
            // storage; volatile byte writes through it are well-defined. The
            // compiler cannot prove the writes are observable, so it must emit
            // them, which defeats dead-store elimination. The `compiler_fence`
            // after the loop bars reordering of later operations above them.
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
#[path = "secret_inline_tests.rs"]
mod tests;
