//! Portable atomic integer re-exports for 32-bit and 64-bit targets (`P05` / `ffw-ipz`).
//!
//! On targets with native 64-bit atomics (`#[cfg(target_has_atomic = "64")]`),
//! [`AtomicU64`] and [`AtomicI64`] are direct re-exports of [`core::sync::atomic::AtomicU64`]
//! and [`core::sync::atomic::AtomicI64`], preserving exact type identity for existing
//! desktop and server consumers.
//!
//! On 32-bit targets without native 64-bit atomics (`powerpc-unknown-linux-musl`,
//! `mips-unknown-linux-musl`), [`AtomicU64`] and [`AtomicI64`] are provided by
//! [`portable_atomic`] using its sharded lock-table `fallback` feature (never
//! `unsafe-assume-single-core` or interrupt disabling in userspace).

pub use core::sync::atomic::{
    AtomicBool, AtomicI8, AtomicI16, AtomicI32, AtomicIsize, AtomicPtr, AtomicU8, AtomicU16,
    AtomicU32, AtomicUsize, Ordering, compiler_fence, fence,
};

#[cfg(target_has_atomic = "64")]
pub use core::sync::atomic::{AtomicI64, AtomicU64};

#[cfg(not(target_has_atomic = "64"))]
pub use portable_atomic::{AtomicI64, AtomicU64};

/// Returns `true` when 64-bit atomics are backed by lock-free hardware instructions,
/// or `false` when backed by `portable-atomic`'s sharded seq-lock/spinlock fallback.
#[must_use]
pub const fn has_native_atomic_64() -> bool {
    cfg!(target_has_atomic = "64")
}

#[cfg(test)]
mod tests {
    use super::{AtomicI64, AtomicU64, Ordering, has_native_atomic_64};

    #[test]
    fn atomic_u64_uniqueness_and_wrap_around() {
        let counter = AtomicU64::new(u64::MAX - 2);
        assert_eq!(counter.fetch_add(1, Ordering::SeqCst), u64::MAX - 2);
        assert_eq!(counter.fetch_add(1, Ordering::SeqCst), u64::MAX - 1);
        assert_eq!(counter.fetch_add(1, Ordering::SeqCst), u64::MAX);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        let cas = counter.compare_exchange(0, 0x0102_0304_0506_0708, Ordering::AcqRel, Ordering::Acquire);
        assert_eq!(cas, Ok(0));
        assert_eq!(counter.load(Ordering::Acquire), 0x0102_0304_0506_0708);

        let signed = AtomicI64::new(-42);
        assert_eq!(signed.fetch_sub(8, Ordering::SeqCst), -42);
        assert_eq!(signed.load(Ordering::SeqCst), -50);
        let _ = has_native_atomic_64();
    }
}
