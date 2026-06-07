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

/// Redacted, deterministic pressure telemetry for synchronization primitives.
///
/// The caller supplies `primitive_id` so the runtime does not need ambient
/// global registration. Snapshots intentionally report only aggregate pressure,
/// waiters, lifecycle state, and cancellation counts, never protected values or
/// task-local payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTelemetrySnapshot {
    /// Caller-provided stable primitive identifier.
    pub primitive_id: u64,
    /// Primitive kind, for example `semaphore`, `barrier`, or `once_cell`.
    pub primitive_kind: &'static str,
    /// Maximum useful units for the primitive.
    pub capacity: usize,
    /// Units currently occupied by holders, arrivals, or initialization state.
    pub occupied_units: usize,
    /// Units immediately available for new work.
    pub available_units: usize,
    /// Number of registered waiters.
    pub waiter_count: usize,
    /// Deterministic generation counter when the primitive has one.
    pub generation: u64,
    /// Redacted lifecycle or pressure state.
    pub state: &'static str,
    /// Number of cancelled or dropped wait operations observed by the primitive.
    pub cancellation_count: u64,
    /// Whether the primitive has reached a terminal closed or initialized state.
    pub closed: bool,
}

mod barrier;
mod contended_mutex;
#[cfg(test)]
mod cross_module_lock_ordering_test;
pub mod lock_ordering;
mod lock_ordering_test;
mod mutex;
mod notify;
#[cfg(test)]
mod notify_bug_test;
#[cfg(test)]
mod notify_metamorphic;

mod once_cell;
#[cfg(test)]
mod once_cell_metamorphic;
mod pool;
#[cfg(test)]
mod pool_metamorphic_tests;
mod rwlock;
#[cfg(test)]
mod rwlock_lost_wakeup_test;
#[cfg(test)]
mod scope_cancellation_metamorphic;
pub mod semaphore;
#[cfg(test)]
mod semaphore_metamorphic_tests;
mod waiter;

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
#[cfg(test)]
mod barrier_metamorphic;
#[cfg(test)]
mod mock_code_finder_clean_sweep_audit_test;
#[cfg(test)]
mod mutex_deadlock_test;
#[cfg(test)]
mod mutex_metamorphic;
