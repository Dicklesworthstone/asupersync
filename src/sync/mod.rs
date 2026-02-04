//! Synchronization primitives with two-phase semantics.
//!
//! This module provides cancel-safe synchronization primitives where
//! guards and permits are tracked as obligations that must be released.
//!
//! # Primitives
//!
//! - [`Mutex`]: Mutual exclusion with guard obligations
//! - [`RwLock`]: Read-write lock with cancel-aware acquisition
//! - [`Semaphore`]: Counting semaphore with permit obligations
//! - [`Pool`]: Resource pooling with obligation-based return semantics
//! - [`Barrier`]: N-way rendezvous with leader election
//! - [`Notify`]: Event signaling (one-shot or broadcast)
//! - [`OnceCell`]: Lazy initialization cell
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

mod barrier;
mod contended_mutex;
mod mutex;
mod notify;
mod once_cell;
mod pool;
mod rwlock;
mod semaphore;

pub use barrier::{Barrier, BarrierWaitError, BarrierWaitResult};
pub use contended_mutex::{ContendedMutex, ContendedMutexGuard, LockMetricsSnapshot};
pub use mutex::{LockError, Mutex, MutexGuard, OwnedMutexGuard, TryLockError};
pub use notify::{Notified, Notify};
pub use once_cell::{OnceCell, OnceCellError};
pub use pool::{
    AsyncResourceFactory, DestroyReason, GenericPool, Pool, PoolConfig, PoolError, PoolFuture,
    PoolReturn, PoolReturnReceiver, PoolReturnSender, PoolStats, PooledResource, WarmupStrategy,
};
#[cfg(feature = "metrics")]
pub use pool::{PoolMetrics, PoolMetricsHandle, PoolMetricsState};
pub use rwlock::{
    OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, RwLockError, RwLockReadGuard,
    RwLockWriteGuard, TryReadError, TryWriteError,
};
pub use semaphore::{
    AcquireError, OwnedSemaphorePermit, Semaphore, SemaphorePermit, TryAcquireError,
};
