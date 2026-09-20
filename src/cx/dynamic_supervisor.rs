//! Bounded runtime admission of independently supervised child trees.
//!
//! [`DynamicSupervisor`] owns a set of named [`ManagedSupervisor`] instances.
//! Children can be added, stopped and reaped while other trees keep running.
//! Each tree retains its compiled restart strategy, intensity and backoff;
//! there are no implicit restart dependencies between different dynamic names.
//!
//! The collection is a single-owner control surface, not a detached actor or a
//! global name registry. Its mutating operations borrow the owner exclusively.
//! Child controllers execute on the ordinary runtime while the owner is idle.
//! A successful start means region admission and controller submission, NOT
//! application readiness; later task-admission failures remain typed results.
//!
//! # Ownership
//!
//! Each name has an additional child-region boundary around its controller.
//! Reaping joins the controller AND closes this boundary before releasing the
//! name or capacity. This also drains descendants after a controller panic.
//! Dropping a wait/terminate future retains its join result and in-progress
//! close in the collection. A new wait resumes that same operation.
//!
//! Explicit shutdown stops all controllers before awaiting any of them. Drop
//! only requests cancellation/close; the enclosing region is the final owner
//! and must be drained by the caller. There is no synchronous Drop-quiescence
//! claim or arbitrary-future termination guarantee.

use super::{CancelWakerToken, ChildRegion, ChildRegionError, ChildRegionSpec, Cx};
use crate::record::region::RegionCloseOutcome;
use crate::record::task::TaskOutcome;
use crate::runtime::{JoinError, SpawnError};
use crate::supervision::{ChildName, ManagedSupervisor, ManagedSupervisorHandle, ManagedSupervisorReport};
use crate::types::{CancelReason, RegionId};
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Explicit resource and region limits for a dynamic owner.
#[derive(Debug, Clone)]
pub struct DynamicSupervisorConfig {
    /// Reserved names, including stopped-but-unreaped and quarantined children.
    /// Zero admits no children. Completed results are not retained after reaping.
    pub max_children: usize,
    /// Root region envelope, met with the caller's existing authority and budget.
    pub region: ChildRegionSpec,
}

impl DynamicSupervisorConfig {
    /// Use an explicit child ceiling and inherit the caller's region envelope.
    #[must_use]
    pub const fn new(max_children: usize) -> Self {
        Self { max_children, region: ChildRegionSpec::inherit() }
    }
}

/// Exact admission identity; a reused name is never the same child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicChildId {
    owner: RegionId,
    region: RegionId,
    generation: u64,
    name: ChildName,
}

impl DynamicChildId {
    /// Dynamic owner's region, including its arena generation.
    #[must_use]
    pub const fn owner_region(&self) -> RegionId { self.owner }
    /// Region enclosing this admitted controller and all its descendants.
    #[must_use]
    pub const fn region_id(&self) -> RegionId { self.region }
    /// Monotone admission sequence within this owner (not a worker restart count).
    #[must_use]
    pub const fn generation(&self) -> u64 { self.generation }
    /// Name reserved until this exact child is quiescent and reaped.
    #[must_use]
    pub fn name(&self) -> &str { self.name.as_str() }
}

/// A child's control-plane state, not an application-readiness assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicChildState {
    /// Controller submitted; it may still be awaiting runtime admission.
    Submitted,
    /// Stop requested; the controller still needs to join.
    Stopping,
    /// Controller joined; the enclosing region is being closed.
    Draining,
    /// Closure or cleanup failed; name and capacity remain reserved until shutdown.
    Quarantined,
}

/// A bounded, non-consuming view of one reserved dynamic name.
#[derive(Debug, Clone)]
pub struct DynamicChildInfo {
    /// Exact identity accepted by lifecycle operations.
    pub id: DynamicChildId,
    /// Latest observed control-plane state.
    pub state: DynamicChildState,
}

/// Quiescent region outcomes; cancellation and cleanup are distinct facts.
#[derive(Debug, Clone)]
pub struct DynamicRegionOutcome {
    /// Aggregate task/region outcome, possibly ordinary shutdown cancellation.
    pub outcome: TaskOutcome,
    /// Explicit finalizer/cleanup outcome, when present.
    pub cleanup_outcome: Option<TaskOutcome>,
}

impl DynamicRegionOutcome {
    fn from_close(value: RegionCloseOutcome) -> Self {
        Self { outcome: value.outcome, cleanup_outcome: value.cleanup_outcome }
    }
}

/// An exact child's retained result, never just a count or success flag.
#[derive(Debug)]
#[must_use = "inspect both the supervisor result and enclosing region closure"]
pub struct DynamicChildCompletion<E> {
    /// Identity of the child whose name was reserved.
    pub id: DynamicChildId,
    /// Whether this dynamic owner explicitly requested a stop.
    pub stop_requested: bool,
    /// Full managed report, or the actual controller join failure.
    pub supervisor: Result<ManagedSupervisorReport<E>, JoinError>,
    /// Enclosing boundary closure. Err is not evidence of quiescence.
    pub close: Result<DynamicRegionOutcome, Arc<ChildRegionError>>,
}

/// Terminal report after attempting every child drain and the root close.
#[derive(Debug)]
#[must_use = "failed close or cleanup must not be treated as successful shutdown"]
pub struct DynamicSupervisorReport<E> {
    /// Dynamic root region.
    pub region: RegionId,
    /// All children still retained at shutdown, in stable name order.
    /// Previously reaped reports belong to the caller and are not duplicated.
    pub children: Vec<DynamicChildCompletion<E>>,
    /// Actual root close result, separate from child domain outcomes.
    pub close: Result<DynamicRegionOutcome, Arc<ChildRegionError>>,
}

/// One child result in a multi-child termination, in the requested order.
/// Failed cleanup retains that child's reservation for explicit owner shutdown.
pub type DynamicChildResult<E> = Result<DynamicChildCompletion<E>, DynamicSupervisorError>;

/// Fail-closed lifecycle refusal. No refusal fabricates a started worker.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DynamicSupervisorError {
    /// Empty or excessively long names are refused before region admission.
    #[error("dynamic child name must contain 1..=255 UTF-8 bytes")]
    InvalidName,
    /// Includes completed-but-unreaped and quarantined children.
    #[error("dynamic child capacity is exhausted")]
    Capacity,
    /// The name is still reserved by an earlier admission.
    #[error("dynamic child name is already reserved")]
    DuplicateName,
    /// Admission was sealed by shutdown or a failed admission cleanup.
    #[error("dynamic supervisor is closing")]
    Closing,
    /// The owning context observed cancellation.
    #[error("dynamic supervisor owner is cancelled: {0:?}")]
    Cancelled(CancelReason),
    /// The ID belongs to another owner, was reaped, or names an older admission.
    #[error("unknown or stale dynamic child identity")]
    StaleChild,
    /// A group operation named the same child more than once; no stop was sent.
    #[error("duplicate child identity in group termination")]
    DuplicateChild,
    /// A direct worker's restart/topology configuration failed before admission.
    #[error("invalid dynamic worker configuration: {0:?}")]
    WorkerConfiguration(crate::supervision::ManagedSupervisorBindError),
    /// No wrapped admission sequence is ever reused.
    #[error("dynamic child admission generation exhausted")]
    GenerationExhausted,
    /// Original root/child admission or close refusal.
    #[error("dynamic supervisor region operation failed: {0}")]
    Region(#[source] Arc<ChildRegionError>),
    /// Controller submission failed. Any admitted empty boundary is closed first.
    #[error("dynamic child controller submission failed: {0:?}")]
    Spawn(SpawnError),
    /// Cleanup did not establish a safely reusable name. The full result is retained.
    #[error("dynamic child cleanup requires shutdown before name reuse")]
    UncleanChild,
}

impl From<ChildRegionError> for DynamicSupervisorError {
    fn from(error: ChildRegionError) -> Self { Self::Region(Arc::new(error)) }
}

type CloseFuture = Pin<Box<dyn Future<Output = Result<RegionCloseOutcome, ChildRegionError>> + Send>>;

struct Child<E> {
    id: DynamicChildId,
    handle: Option<ManagedSupervisorHandle<E>>,
    region: Option<ChildRegion>,
    joined: Option<Result<ManagedSupervisorReport<E>, JoinError>>,
    closing: Option<CloseFuture>,
    closed: Option<Result<DynamicRegionOutcome, Arc<ChildRegionError>>>,
    stop_requested: bool,
}

impl<E> Child<E> {
    fn stop(&mut self) {
        self.stop_requested = true;
        if let Some(handle) = &self.handle { handle.abort(); }
    }

    fn reusable(&self) -> bool {
        let Some(Ok(close)) = &self.closed else { return false; };
        if close.cleanup_outcome.as_ref().is_some_and(|outcome| !outcome.is_ok()) {
            return false;
        }
        match &self.joined {
            Some(Ok(report)) => {
                (report.region.is_none() || report.region_outcome.is_some())
                    && !report.cleanup_outcome.as_ref().is_some_and(|outcome| !outcome.is_ok())
                    && report.children.iter().all(|child| {
                        child.region_outcome.is_some()
                            && !child.cleanup_outcome.as_ref().is_some_and(|outcome| !outcome.is_ok())
                    })
            }
            // A before-first-poll cancellation may have no managed report.
            // Its enclosing region must still close before capacity is released.
            Some(Err(JoinError::Cancelled(_))) => true,
            _ => false,
        }
    }

    fn state(&self) -> DynamicChildState {
        if self.closed.is_some() && !self.reusable() {
            DynamicChildState::Quarantined
        } else if self.joined.is_some() {
            DynamicChildState::Draining
        } else if self.stop_requested {
            DynamicChildState::Stopping
        } else {
            DynamicChildState::Submitted
        }
    }

    fn poll_terminal(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.joined.is_none() {
            let terminal = {
                let handle = self.handle.as_mut().expect("unjoined dynamic controller");
                // join's only pending state is its retained task handle. Dropping
                // this borrowing future on Pending does not consume the report.
                let mut join = std::pin::pin!(handle.join());
                join.as_mut().poll(cx)
            };
            let result = std::task::ready!(terminal);
            self.joined = Some(result);
            drop(self.handle.take());
        }
        if self.closed.is_none() {
            if self.closing.is_none() {
                let region = self.region.take().expect("unclosed dynamic boundary");
                self.closing = Some(Box::pin(region.close_with_outcome()));
            }
            let result = std::task::ready!(
                self.closing.as_mut().expect("retained close future").as_mut().poll(cx)
            );
            self.closed = Some(result.map(DynamicRegionOutcome::from_close).map_err(Arc::new));
            drop(self.closing.take());
        }
        Poll::Ready(())
    }

    fn into_completion(self) -> DynamicChildCompletion<E> {
        DynamicChildCompletion {
            id: self.id,
            stop_requested: self.stop_requested,
            supervisor: self.joined.expect("joined before completion publication"),
            close: self.closed.expect("close attempted before completion publication"),
        }
    }
}

/// Single-owner runtime collection of independently restarting supervisor trees.
///
/// Capacity covers retained names, not tasks inside each tree; each tree and the
/// underlying region admission retain their own limits. Nothing is spawned by
/// merely creating this owner. Methods do not hold a runtime or application lock
/// while polling a child, waiting for closure or invoking user code.
#[must_use = "explicitly shut down or let the enclosing region drain this owner"]
pub struct DynamicSupervisor<E> {
    owner: Cx,
    root: Option<ChildRegion>,
    region: RegionId,
    max_children: usize,
    generation: u64,
    sealed: bool,
    cancel_waker: Option<CancelWakerToken>,
    children: BTreeMap<ChildName, Child<E>>,
}

impl<E> fmt::Debug for DynamicSupervisor<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicSupervisor")
            .field("region", &self.region)
            .field("reserved_children", &self.children.len())
            .field("max_children", &self.max_children)
            .field("closing", &self.sealed)
            .finish_non_exhaustive()
    }
}

impl Cx {
    /// Open a region-owned dynamic supervision collection without starting workers.
    pub async fn open_dynamic_supervisor<E: Send + 'static>(
        &self, config: DynamicSupervisorConfig,
    ) -> Result<DynamicSupervisor<E>, DynamicSupervisorError> {
        if self.checkpoint().is_err() {
            return Err(DynamicSupervisorError::Cancelled(
                self.cancel_reason().unwrap_or_else(|| CancelReason::user("dynamic owner cancelled")),
            ));
        }
        let root = self.open_child_region(config.region).await?;
        Ok(DynamicSupervisor {
            owner: self.clone(), region: root.region_id(), root: Some(root),
            max_children: config.max_children, generation: 0, sealed: false, cancel_waker: None,
            children: BTreeMap::new(),
        })
    }
}

impl<E> DynamicSupervisor<E> {
    /// Root region that owns every admitted controller and its tree.
    #[must_use]
    pub const fn region_id(&self) -> RegionId { self.region }
    /// Reserved names, including completed-but-unreaped children.
    #[must_use]
    pub fn len(&self) -> usize { self.children.len() }
    /// Whether there are no reserved names.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.children.is_empty() }
    /// Configured reservation ceiling.
    #[must_use]
    pub const fn capacity(&self) -> usize { self.max_children }
    /// Whether explicit shutdown has sealed admission.
    #[must_use]
    pub const fn is_closing(&self) -> bool { self.sealed }
    /// Snapshot of reserved names in stable lexical order; never consumes results.
    #[must_use]
    pub fn children(&self) -> Vec<DynamicChildInfo> {
        self.children.values().map(|child| DynamicChildInfo {
            id: child.id.clone(), state: child.state(),
        }).collect()
    }

    fn child(&self, id: &DynamicChildId) -> Result<&Child<E>, DynamicSupervisorError> {
        self.children.get(id.name.as_str()).filter(|child| &child.id == id)
            .ok_or(DynamicSupervisorError::StaleChild)
    }

    /// Inspect a retained controller result, including one quarantined by cleanup.
    /// Does not poll the controller or consume the result.
    pub fn child_result(
        &self, id: &DynamicChildId,
    ) -> Result<Option<&Result<ManagedSupervisorReport<E>, JoinError>>, DynamicSupervisorError> {
        Ok(self.child(id)?.joined.as_ref())
    }

    fn observe_cancellation(&mut self, cx: &Context<'_>) {
        if !self.sealed {
            self.cancel_waker = Some(self.owner.refresh_cancel_waker(self.cancel_waker, cx.waker()));
            if self.owner.checkpoint().is_err() { self.begin_shutdown(); }
        }
    }

    fn check_admission(&mut self, name: &ChildName) -> Result<(), DynamicSupervisorError> {
        if self.sealed { return Err(DynamicSupervisorError::Closing); }
        if self.owner.checkpoint().is_err() {
            self.begin_shutdown();
            return Err(DynamicSupervisorError::Cancelled(
                self.owner.cancel_reason().unwrap_or_else(|| CancelReason::user("dynamic owner cancelled")),
            ));
        }
        if name.is_empty() || name.len() > 255 { return Err(DynamicSupervisorError::InvalidName); }
        if self.children.contains_key(name.as_str()) { return Err(DynamicSupervisorError::DuplicateName); }
        if self.children.len() >= self.max_children { return Err(DynamicSupervisorError::Capacity); }
        Ok(())
    }

    /// Idempotently request a stop for exactly this admission, never a reused name.
    /// Call `wait_child` or `terminate_child` to observe actual quiescence.
    pub fn request_stop(&mut self, id: &DynamicChildId) -> Result<(), DynamicSupervisorError> {
        self.child(id)?;
        self.children.get_mut(id.name.as_str()).expect("validated child").stop();
        Ok(())
    }

    /// Seal admission and notify EVERY controller before waiting for any drain.
    /// This is idempotent and remains in effect if a subsequent wait is dropped.
    pub fn begin_shutdown(&mut self) {
        self.sealed = true;
        for child in self.children.values_mut() { child.stop(); }
    }
}

impl<E: Send + 'static> DynamicSupervisor<E> {
    /// Admit a new named supervisor tree while existing trees keep executing.
    ///
    /// This submits the managed controller; it does not assert that its workers
    /// are ready. Use application-specific readiness and the typed completion.
    /// No existing topology or restart tracker is mutated. A reused name receives
    /// a new owner-local generation AND a new generational region identity.
    pub async fn start_child(
        &mut self, name: impl Into<ChildName>, supervisor: ManagedSupervisor<E>,
    ) -> Result<DynamicChildId, DynamicSupervisorError> {
        let name = name.into();
        self.check_admission(&name)?;
        let generation = self.generation.checked_add(1)
            .ok_or(DynamicSupervisorError::GenerationExhausted)?;
        self.generation = generation;
        let region = self.root.as_ref().expect("open dynamic root").cx()
            .open_child_region(ChildRegionSpec::inherit()).await?;
        // An admission can finish after cancellation was published. Refuse to
        // submit user code, but still account for and close the admitted region.
        if self.owner.checkpoint().is_err() {
            self.begin_shutdown();
            region.close_with_outcome().await?;
            return Err(DynamicSupervisorError::Cancelled(
                self.owner.cancel_reason().unwrap_or_else(|| CancelReason::user("dynamic owner cancelled")),
            ));
        }
        let handle = match supervisor.spawn(region.cx()) {
            Ok(handle) => handle,
            Err(error) => {
                if let Err(close_error) = region.close_with_outcome().await {
                    self.begin_shutdown();
                    return Err(close_error.into());
                }
                return Err(DynamicSupervisorError::Spawn(error));
            }
        };
        let id = DynamicChildId { owner: self.region, region: region.region_id(), generation, name: name.clone() };
        // No await after submission and before retaining ownership/publication.
        self.children.insert(name, Child {
            id: id.clone(), handle: Some(handle), region: Some(region), joined: None,
            closing: None, closed: None, stop_requested: false,
        });
        Ok(id)
    }

    fn reap(&mut self, id: &DynamicChildId) -> Result<DynamicChildCompletion<E>, DynamicSupervisorError> {
        let child = self.child(id)?;
        if let Some(Err(error)) = &child.closed {
            return Err(DynamicSupervisorError::Region(Arc::clone(error)));
        }
        if !child.reusable() { return Err(DynamicSupervisorError::UncleanChild); }
        Ok(self.children.remove(id.name.as_str()).expect("validated terminal child").into_completion())
    }

    /// Join and close one exact child, then release its name and capacity.
    ///
    /// Dropping this wait does NOT stop the child or discard a joined result.
    /// Observed owner cancellation seals admission and stops every child; the
    /// selected child is still joined and drained, never abandoned early.
    /// Repeating it resumes the stored close. Cleanup failure quarantines the
    /// reservation; inspect `child_result` and shut down the owner for its report.
    pub async fn wait_child(
        &mut self, id: &DynamicChildId,
    ) -> Result<DynamicChildCompletion<E>, DynamicSupervisorError> {
        self.child(id)?;
        poll_fn(|cx| {
            self.observe_cancellation(cx);
            self.children.get_mut(id.name.as_str()).expect("retained child").poll_terminal(cx)
        }).await;
        self.reap(id)
    }

    /// Request cancellation, then await actual controller AND region termination.
    /// Dropping this future leaves the stop request and in-progress drain intact.
    pub async fn terminate_child(
        &mut self, id: &DynamicChildId,
    ) -> Result<DynamicChildCompletion<E>, DynamicSupervisorError> {
        self.request_stop(id)?;
        self.wait_child(id).await
    }

    /// Stop a selected group, then drive every controller and boundary close together.
    ///
    /// All IDs (including uniqueness) are validated BEFORE any stop request.
    /// A stale/foreign/duplicate ID therefore cannot partially stop a group.
    /// All stop requests precede all awaits, and every close is polled even when
    /// another is Pending, allowing interdependent finalizers to make progress.
    ///
    /// The returned vector follows `ids` order. Each child has its own result:
    /// successful reaps release capacity, failed cleanup remains quarantined.
    /// Dropping the future retains ALL selected children and their current drain
    /// state; it does not undo stop requests or discard completed reports.
    /// The temporary owner-side work is bounded by the admitted child ceiling.
    pub async fn terminate_children(
        &mut self, ids: &[DynamicChildId],
    ) -> Result<Vec<DynamicChildResult<E>>, DynamicSupervisorError> {
        let mut unique = std::collections::BTreeSet::new();
        for id in ids {
            self.child(id)?;
            if !unique.insert(id.name.as_str()) {
                return Err(DynamicSupervisorError::DuplicateChild);
            }
        }
        for id in ids {
            self.children.get_mut(id.name.as_str()).expect("validated group member").stop();
        }
        poll_fn(|cx| {
            self.observe_cancellation(cx);
            let mut all_ready = true;
            for id in ids {
                let child = self.children.get_mut(id.name.as_str()).expect("retained group member");
                if child.poll_terminal(cx).is_pending() { all_ready = false; }
            }
            if all_ready { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        Ok(ids.iter().map(|id| self.reap(id)).collect())
    }

    /// Wait for a reaped completion; an empty collection returns None immediately.
    /// Ready ties use lexical name order. Each poll scans at most the configured
    /// child ceiling. Every pending join/close registers the current waker.
    pub async fn next_completed(
        &mut self,
    ) -> Result<Option<DynamicChildCompletion<E>>, DynamicSupervisorError> {
        let id = poll_fn(|cx| {
            self.observe_cancellation(cx);
            if self.children.is_empty() { return Poll::Ready(None); }
            for child in self.children.values_mut() {
                if child.poll_terminal(cx).is_ready() { return Poll::Ready(Some(child.id.clone())); }
            }
            Poll::Pending
        }).await;
        id.as_ref().map(|id| self.reap(id)).transpose()
    }

    /// Stop every tree, attempt EVERY drain, then close the enclosing root.
    ///
    /// All stop requests precede all awaits. A failed child close never prevents
    /// attempting the remaining closes. Reports preserve application errors,
    /// cancellation, panic and explicit cleanup failures separately.
    pub async fn shutdown(mut self) -> DynamicSupervisorReport<E> {
        self.begin_shutdown();
        poll_fn(|cx| {
            let mut all_ready = true;
            for child in self.children.values_mut() {
                // Never short-circuit on Pending: another boundary's finalizer
                // may be the event this one needs in order to finish closing.
                if child.poll_terminal(cx).is_pending() { all_ready = false; }
            }
            if all_ready { Poll::Ready(()) } else { Poll::Pending }
        }).await;
        let root = self.root.take().expect("owned dynamic root");
        let close = root.close_with_outcome().await.map(DynamicRegionOutcome::from_close).map_err(Arc::new);
        let children = std::mem::take(&mut self.children).into_values().map(Child::into_completion).collect();
        DynamicSupervisorReport { region: self.region, children, close }
    }
}

impl<E> Drop for DynamicSupervisor<E> {
    fn drop(&mut self) {
        self.begin_shutdown();
        if let Some(token) = self.cancel_waker.take() { self.owner.clear_cancel_waker(token); }
        // Child handles and the root's Drop request close. Neither can claim
        // completion; only the runtime's parent-region barrier supplies that.
    }
}

mod worker;
pub use worker::DynamicWorkerConfig;

#[cfg(test)]
mod tests;
