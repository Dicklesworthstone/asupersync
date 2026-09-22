//! All-ready observation and exact-generation invalidation for worker dependencies.
//!
//! This module inherits the readiness module's validation feature gate. It does
//! not own the prerequisite workers, grant resource leases, or build a graph.

use super::{Cancellation, Cx, ManagedGeneration, ReadyWorker, WorkerReadiness};
use super::{WorkerReadinessError, WorkerReadinessPhase, WorkerReadinessState};
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

/// Dependency configuration or observation refusal. Indices use input order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DependencyError {
    /// The supplied dependency count exceeds the explicit caller-owned ceiling.
    #[error("worker dependency count {requested} exceeds limit {limit}")]
    Capacity {
        /// Number supplied by the caller.
        requested: usize,
        /// Maximum permitted by the caller.
        limit: usize,
    },
    /// A factory is repeated, including through cloned observation capabilities.
    #[error("duplicate worker dependency at index {index}")]
    Duplicate {
        /// Earliest repeated input index, not an allocation-dependent ordering.
        index: usize,
    },
    /// This factory can no longer satisfy the barrier.
    #[error("worker dependency {index}: {cause}")]
    Worker {
        /// Original input index.
        index: usize,
        /// The prerequisite's terminal observation error, not its application error.
        cause: WorkerReadinessError,
    },
    /// Cancels this observer only; prerequisites are not stopped.
    #[error("worker dependency observation cancelled")]
    Cancelled,
    /// Bounded observer metadata could not be reserved.
    #[error("worker dependency metadata allocation failed")]
    Allocation,
}

#[derive(Debug)]
struct Set {
    workers: Vec<WorkerReadiness>,
}

/// Immutable, cloneable set of readiness prerequisites with an explicit ceiling.
///
/// Registration order is preserved in snapshots and error indices. Metadata is
/// O(dependencies), and every live wait has its own O(dependencies) registrations.
/// The ceiling is not a bound on the prerequisite workers or their resources.
#[derive(Clone, Debug)]
pub struct WorkerDependencies {
    set: Arc<Set>,
}

/// One complete ready-generation vector. Its observations do not own resources.
///
/// Ready is entered at most once for an exact managed generation. A double
/// collect therefore establishes that all returned generations were Ready at
/// one common instant: each first-pass observation stayed Ready through its
/// second-pass validation. They can become stale immediately after that instant.
#[derive(Clone)]
pub struct ReadyDependencies {
    set: Arc<Set>,
    ready: Vec<ReadyWorker>,
}

impl fmt::Debug for ReadyDependencies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadyDependencies")
            .field("generations", &self.ready)
            .finish_non_exhaustive()
    }
}

/// One exact prerequisite generation is no longer Ready.
///
/// This is the first invalid input index observed by a scan, not a timestamped
/// first-cause log. The latest state may already describe a replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DependencyLoss {
    /// Original dependency input index.
    pub index: usize,
    /// Generation selected by the barrier.
    pub expected: ManagedGeneration,
    /// Latest state when invalidation was detected.
    pub observed: WorkerReadinessState,
}

fn vector<T>(capacity: usize) -> Result<Vec<T>, DependencyError> {
    let mut values = Vec::new();
    values.try_reserve_exact(capacity).map_err(|_| DependencyError::Allocation)?;
    Ok(values)
}

impl WorkerDependencies {
    /// Validate count and factory uniqueness before any wait or runtime effect.
    ///
    /// The input allocation already belongs to the caller. Rejection drops only
    /// observer owners; it neither cancels workers nor invokes their factories.
    /// An empty set is immediately ready, including with a zero ceiling.
    pub fn new(
        workers: Vec<WorkerReadiness>,
        max_dependencies: usize,
    ) -> Result<Self, DependencyError> {
        if workers.len() > max_dependencies {
            return Err(DependencyError::Capacity {
                requested: workers.len(), limit: max_dependencies,
            });
        }
        let mut identities = vector(workers.len())?;
        for (index, worker) in workers.iter().enumerate() {
            identities.push((Arc::as_ptr(&worker.shared) as usize, index));
        }
        identities.sort_unstable();
        let duplicate = identities.windows(2)
            .filter(|pair| pair[0].0 == pair[1].0)
            .map(|pair| pair[1].1)
            .min();
        if let Some(index) = duplicate {
            return Err(DependencyError::Duplicate { index });
        }
        Ok(Self { set: Arc::new(Set { workers }) })
    }

    /// Number of immutable prerequisites.
    #[must_use]
    pub fn len(&self) -> usize { self.set.workers.len() }

    /// Whether startup has no readiness prerequisites.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.set.workers.is_empty() }

    /// Observe all prerequisites without registering waiters or touching a Cx.
    ///
    /// Never accumulates Ready observations from disjoint periods. Every worker
    /// is inspected even after a pending one, so a later closed prerequisite
    /// refuses rather than hiding behind an earlier worker that never starts.
    /// No two state locks are held together; no callback runs under a state lock.
    pub fn try_ready(&self) -> Result<Option<ReadyDependencies>, DependencyError> {
        let mut ready = vector(self.len())?;
        let mut pending = false;
        for (index, worker) in self.set.workers.iter().enumerate() {
            match worker.try_ready().map_err(|cause| DependencyError::Worker { index, cause })? {
                Some(observation) => ready.push(observation),
                None => pending = true,
            }
        }
        if pending { return Ok(None); }
        let snapshot = ReadyDependencies { set: Arc::clone(&self.set), ready };
        Ok(snapshot.is_current().then_some(snapshot))
    }

    /// Wait for a common all-ready observation without sequential startup waits.
    ///
    /// Registers every dependency before checking state. A prerequisite changing
    /// while another initializes invalidates its old observation. Cancellation
    /// acknowledges only the observer's Cx; no prerequisite is stopped.
    pub async fn wait_ready(&self, cx: &Cx) -> Result<ReadyDependencies, DependencyError> {
        self.wait_until(cx, || self.try_ready()).await
    }

    async fn wait_until<T>(
        &self,
        cx: &Cx,
        mut predicate: impl FnMut() -> Result<Option<T>, DependencyError>,
    ) -> Result<T, DependencyError> {
        let mut cancellation = Cancellation { cx, token: None };
        let mut notifications = vector(self.len())?;
        for worker in &self.set.workers {
            notifications.push(worker.shared.changed.notified());
        }
        poll_fn(|task| {
            cancellation.token = Some(cx.refresh_cancel_waker(cancellation.token, task.waker()));
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(DependencyError::Cancelled));
            }
            // Arm before the predicate. Two polls per entry bound broadcast
            // storms; a second ready notification schedules another turn.
            for (notified, worker) in notifications.iter_mut().zip(&self.set.workers) {
                if Pin::new(&mut *notified).poll(task).is_ready() {
                    *notified = worker.shared.changed.notified();
                    if Pin::new(notified).poll(task).is_ready() {
                        task.waker().wake_by_ref();
                    }
                }
            }
            match predicate() {
                Ok(Some(value)) => Poll::Ready(Ok(value)),
                Ok(None) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            }
        }).await
    }
}

impl ReadyDependencies {
    /// Number of generations in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize { self.ready.len() }

    /// Whether this snapshot has no prerequisites.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.ready.is_empty() }

    /// Full managed identities, in dependency input order.
    pub fn generations(&self) -> impl ExactSizeIterator<Item = ManagedGeneration> + '_ {
        self.ready.iter().map(ReadyWorker::generation)
    }

    /// True while this exact generation vector is observed as Ready.
    /// A replacement is never accepted as the previous generation becoming ready.
    #[must_use]
    pub fn is_current(&self) -> bool { self.first_lost().is_none() }

    /// Inspect invalidation without changing any task or registration.
    #[must_use]
    pub fn first_lost(&self) -> Option<DependencyLoss> {
        self.set.workers.iter().zip(&self.ready).enumerate()
            .find_map(|(index, (worker, expected))| {
                let observed = worker.state();
                (observed.phase != WorkerReadinessPhase::Ready
                    || observed.generation != Some(expected.generation))
                    .then_some(DependencyLoss { index, expected: expected.generation, observed })
            })
    }

    /// Wait until ANY selected generation leaves Ready, including a restart that
    /// finished before this wait was first polled. Loss cannot be repaired by a
    /// newer generation; obtain a fresh all-ready snapshot explicitly.
    ///
    /// An empty snapshot waits only for observer cancellation. Dropping this
    /// borrowing wait unregisters its own waiters and does not stop any worker.
    pub async fn wait_lost(&self, cx: &Cx) -> Result<DependencyLoss, DependencyError> {
        let dependencies = WorkerDependencies { set: Arc::clone(&self.set) };
        dependencies.wait_until(cx, || Ok(self.first_lost())).await
    }
}

#[cfg(test)]
mod tests;

mod scope;
pub use scope::{
    DependencyRegionOutcome, DependencyScopeConfig, DependencyScopeError,
    DependencyScopeReport, DependencyStop,
};
