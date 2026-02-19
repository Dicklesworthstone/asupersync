//! Cache-line alignment utilities for hot-path data structures.
//!
//! Provides [`CachePadded<T>`] to prevent false sharing between data accessed
//! by different threads. On most x86-64 and ARM platforms, a cache line is 64 bytes.
//!
//! # When to Use
//!
//! Use `CachePadded` for:
//! - Per-worker counters or state that would otherwise share a cache line
//! - Queue head/tail pointers accessed by multiple threads
//! - Any hot field that is written frequently by one thread and read by others
//!
//! # Example
//!
//! ```ignore
//! use asupersync::util::CachePadded;
//!
//! struct PerWorker {
//!     counter: CachePadded<u64>,
//!     // Each worker's counter lives on its own cache line.
//! }
//! ```

use core::ops::{Deref, DerefMut};

/// The cache line size in bytes for the target platform.
///
/// 64 bytes is correct for x86-64, ARM Cortex-A, and Apple Silicon.
/// Some POWER and z/Architecture CPUs use 128 bytes, but 64 is the
/// common denominator and sufficient for preventing most false sharing.
pub const CACHE_LINE_SIZE: usize = 64;

/// A wrapper that aligns and pads its contents to a cache line boundary.
///
/// This prevents false sharing by ensuring that the wrapped value occupies
/// at least one full cache line and starts on a cache-line boundary.
///
/// # Memory Layout
///
/// The struct is `#[repr(C, align(64))]`, guaranteeing:
/// - The start address is 64-byte aligned
/// - The total size is a multiple of 64 bytes (due to alignment padding)
///
/// For small types (e.g., `u64`, `AtomicUsize`), this wastes some memory
/// in exchange for eliminating false sharing entirely.
#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct CachePadded<T> {
    value: T,
}

impl<T> CachePadded<T> {
    /// Creates a new cache-padded value.
    #[must_use]
    #[inline]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Consumes the wrapper and returns the inner value.
    #[must_use]
    #[inline]
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T> Deref for CachePadded<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: Default> Default for CachePadded<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: PartialEq> PartialEq for CachePadded<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for CachePadded<T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn alignment_is_cache_line() {
        assert_eq!(mem::align_of::<CachePadded<u8>>(), CACHE_LINE_SIZE);
        assert_eq!(mem::align_of::<CachePadded<u64>>(), CACHE_LINE_SIZE);
        assert_eq!(mem::align_of::<CachePadded<[u8; 128]>>(), CACHE_LINE_SIZE);
    }

    #[test]
    fn size_is_multiple_of_cache_line() {
        assert_eq!(mem::size_of::<CachePadded<u8>>() % CACHE_LINE_SIZE, 0);
        assert_eq!(mem::size_of::<CachePadded<u64>>() % CACHE_LINE_SIZE, 0);
    }

    #[test]
    fn deref_works() {
        let padded = CachePadded::new(42u64);
        assert_eq!(*padded, 42);
    }

    #[test]
    fn deref_mut_works() {
        let mut padded = CachePadded::new(0u64);
        *padded = 99;
        assert_eq!(*padded, 99);
    }

    #[test]
    fn into_inner() {
        let padded = CachePadded::new(String::from("hello"));
        let s = padded.into_inner();
        assert_eq!(s, "hello");
    }

    #[test]
    fn default_works() {
        let padded: CachePadded<u64> = CachePadded::default();
        assert_eq!(*padded, 0);
    }

    #[test]
    fn cache_padded_debug_clone_copy() {
        let p = CachePadded::new(42u64);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("42"), "{dbg}");

        let copied: CachePadded<u64> = p;
        let cloned = p.clone();
        assert_eq!(*copied, 42);
        assert_eq!(*cloned, 42);
    }

    #[test]
    fn two_padded_values_dont_share_cache_line() {
        let a = CachePadded::new(1u64);
        let b = CachePadded::new(2u64);
        let a_addr = core::ptr::addr_of!(*a) as usize;
        let b_addr = core::ptr::addr_of!(*b) as usize;
        // They must be at least CACHE_LINE_SIZE apart
        let diff = a_addr.abs_diff(b_addr);
        assert!(
            diff >= CACHE_LINE_SIZE,
            "values are only {diff} bytes apart, need >= {CACHE_LINE_SIZE}"
        );
    }
}
