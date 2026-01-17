//! Synchronization primitives with two-phase semantics.
//!
//! This module provides cancel-safe synchronization primitives where
//! guards and permits are tracked as obligations that must be released.
//!
//! # Primitives
//!
//! - [`Mutex`]: Mutual exclusion with guard obligations
//! - [`Semaphore`]: Counting semaphore with permit obligations
//!
//! # Two-Phase Pattern
//!
//! All primitives in this module follow a two-phase pattern:
//!
//! - **Phase 1 (Wait)**: Wait for the resource to become available.
//!   This phase is cancel-safe - cancellation during wait is clean.
//! - **Phase 2 (Hold)**: Hold the resource (guard/permit). The guard
//!   is an obligation that must be released (via drop).
//!
//! # Cancel Safety
//!
//! - Cancellation during wait: Clean abort, no resource held
//! - Cancellation while holding: Guard dropped, resource released
//! - Panic while holding: Guard dropped via unwind (unwind safety)

mod mutex;
mod semaphore;

pub use mutex::{LockError, Mutex, MutexGuard, OwnedMutexGuard, TryLockError};
pub use semaphore::{
    AcquireError, OwnedSemaphorePermit, Semaphore, SemaphorePermit, TryAcquireError,
};
