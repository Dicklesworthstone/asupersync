//! Two-phase semaphore with permit obligations.
//!
//! A semaphore controls access to a finite number of resources through permits.
//! Each acquired permit is tracked as an obligation that must be released.
//!
//! # Cancel Safety
//!
//! The acquire operation is split into two phases:
//! - **Phase 1**: Wait for permit availability (cancel-safe)
//! - **Phase 2**: Acquire the complete permit set and create its obligation.
//!   Checked acquisition returns an admission error if the region cannot accept
//!   another obligation, restoring capacity before returning.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::sync::Semaphore;
//!
//! // Create semaphore with 10 permits
//! let sem = Semaphore::new(10);
//!
//! // Acquire a permit (awaits until available)
//! let permit = sem.acquire(&cx, 1).await?;
//!
//! // Permit is automatically released when dropped
//! drop(permit);
//! ```

use parking_lot::Mutex as ParkingMutex;
use slab::Slab;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use crate::cx::Cx;
use crate::obligation::graded::{ObligationToken, SemaphorePermitKind};
use crate::sync::lock_ordering::{self, LockRank};
use crate::types::RegionId;

/// Error returned when semaphore acquisition fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// The semaphore was closed.
    Closed,
    /// Cancelled while waiting.
    Cancelled,
    /// The acquire future was polled after it had already completed.
    PolledAfterCompletion,
}

impl std::fmt::Display for AcquireError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "semaphore closed"),
            Self::Cancelled => write!(f, "semaphore acquire cancelled"),
            Self::PolledAfterCompletion => {
                write!(f, "semaphore acquire future polled after completion")
            }
        }
    }
}

impl std::error::Error for AcquireError {}

/// Error returned when trying to acquire more permits than available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryAcquireError;

impl std::fmt::Display for TryAcquireError {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[ASUP-E204] no semaphore permits available")
    }
}

impl std::error::Error for TryAcquireError {}

/// Failure of an explicitly checked semaphore acquisition.
///
/// Existing acquisition methods keep their original error types and admission
/// behavior. Checked methods require an explicit context and admit one runtime
/// obligation per nonempty permit set, regardless of its number of units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CheckedAcquireError {
    /// The semaphore acquisition failed before obligation admission.
    #[error(transparent)]
    Semaphore(#[from] AcquireError),
    /// A try-acquire would wait for capacity or an earlier FIFO waiter.
    #[error(transparent)]
    Unavailable(#[from] TryAcquireError),
    /// The runtime refused the obligation; no permit is returned.
    #[error(transparent)]
    Admission(#[from] crate::runtime::obligation_mailbox::ObligationAdmissionError),
}

#[inline]
fn reserve_permit_obligation(region: RegionId) -> Option<ObligationToken<SemaphorePermitKind>> {
    if region.as_u64() == 0 {
        None
    } else {
        Some(ObligationToken::reserve("semaphore-permit", region))
    }
}

/// Mint the runtime-visible twin of [`reserve_permit_obligation`].
///
/// The graded token above is type-level only — it never reaches
/// `RuntimeState`, so the runtime's obligation table, its leak policy and
/// `is_quiescent` cannot see an outstanding permit. This one goes through the
/// D1 mailbox (`br-asupersync-bi2462.13`), so a permit held across a
/// cancelled task shows up as the capacity leak it is. Returns `None` for a
/// `Cx` built without a runtime, which keeps `Cx::for_testing` and the
/// host-boundary paths untracked exactly as before.
#[inline]
fn reserve_runtime_permit_obligation<Caps>(
    cx: &Cx<Caps>,
) -> Option<crate::runtime::obligation_mailbox::ObligationToken> {
    cx.try_register_obligation(crate::record::ObligationKind::SemaphorePermit, cx.task_id())
}

/// A counting semaphore for limiting concurrent access.
#[derive(Debug)]
pub struct Semaphore {
    /// Internal state for permits and waiters.
    state: ParkingMutex<SemaphoreState>,
    /// Lock-free shadow of available permits for read-heavy diagnostics.
    permits_shadow: AtomicUsize,
    /// Lock-free shadow of closed state for read-heavy checks.
    closed_shadow: AtomicBool,
    /// Maximum permits (initial count).
    max_permits: usize,
    /// Human-readable name for lock ordering (e.g., "tasks", "regions").
    name: &'static str,
    /// Lock rank for deadlock prevention.
    rank: Option<LockRank>,
}

#[derive(Debug)]
struct SemaphoreState {
    /// Number of available permits.
    permits: usize,
    /// Whether the semaphore is closed.
    closed: bool,
    /// Queue of waiters stored in a slab for O(1) targeted removal.
    waiters: Slab<Waiter>,
    /// Head of the FIFO waiter queue.
    waiter_head: Option<usize>,
    /// Tail of the FIFO waiter queue.
    waiter_tail: Option<usize>,
    /// Next waiter id for de-duplication.
    next_waiter_id: u64,
    /// Cancelled or dropped acquire waiters observed by telemetry.
    cancellation_count: u64,
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    count: usize,
    waker: Arc<RegisteredWaker>,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Arc-owned executor waker registration stored beneath semaphore state.
///
/// Cloning an `Arc<RegisteredWaker>` while the mutex is held cannot invoke the
/// user-provided RawWaker callbacks. Construction, wake dispatch, and final
/// destruction are kept outside the mutex.
#[derive(Debug)]
struct RegisteredWaker {
    waker: Waker,
}

impl RegisteredWaker {
    #[inline]
    fn new(waker: &Waker) -> Arc<Self> {
        Arc::new(Self {
            waker: waker.clone(),
        })
    }

    #[inline]
    fn will_wake(&self, waker: &Waker) -> bool {
        self.waker.will_wake(waker)
    }

    #[inline]
    fn wake_by_ref(&self) {
        self.waker.wake_by_ref();
    }
}

#[inline]
fn waiter_waker_if_runnable(state: &SemaphoreState, slot: usize) -> Option<Arc<RegisteredWaker>> {
    let waiter = state.waiters.get(slot)?;
    (state.permits >= waiter.count).then(|| Arc::clone(&waiter.waker))
}

#[inline]
fn front_waiter_waker_if_runnable(state: &SemaphoreState) -> Option<Arc<RegisteredWaker>> {
    state
        .waiter_head
        .and_then(|slot| waiter_waker_if_runnable(state, slot))
}

#[inline]
fn allocate_waiter_id(state: &mut SemaphoreState) -> u64 {
    let id = state.next_waiter_id;
    state.next_waiter_id = state.next_waiter_id.wrapping_add(1);
    id
}

#[inline]
fn waiter_by_handle(state: &SemaphoreState, handle: WaiterHandle) -> Option<&Waiter> {
    let waiter = state.waiters.get(handle.slot)?;
    (waiter.id == handle.id).then_some(waiter)
}

#[inline]
fn waiter_by_handle_mut(state: &mut SemaphoreState, handle: WaiterHandle) -> Option<&mut Waiter> {
    let waiter = state.waiters.get_mut(handle.slot)?;
    (waiter.id == handle.id).then_some(waiter)
}

#[inline]
fn is_front_waiter(state: &SemaphoreState, handle: WaiterHandle) -> bool {
    state.waiter_head == Some(handle.slot) && waiter_by_handle(state, handle).is_some()
}

#[inline]
fn enqueue_waiter(
    state: &mut SemaphoreState,
    count: usize,
    waker: Arc<RegisteredWaker>,
) -> WaiterHandle {
    let id = allocate_waiter_id(state);
    let prev = state.waiter_tail;
    let slot = state.waiters.insert(Waiter {
        id,
        count,
        waker,
        prev,
        next: None,
    });
    if let Some(prev_slot) = prev {
        state.waiters[prev_slot].next = Some(slot);
    } else {
        state.waiter_head = Some(slot);
    }
    state.waiter_tail = Some(slot);
    WaiterHandle { slot, id }
}

#[inline]
fn unlink_waiter(state: &mut SemaphoreState, handle: WaiterHandle) -> Option<Waiter> {
    let waiter = waiter_by_handle(state, handle)?;
    let prev = waiter.prev;
    let next = waiter.next;
    if let Some(prev_slot) = prev {
        state.waiters[prev_slot].next = next;
    } else {
        state.waiter_head = next;
    }
    if let Some(next_slot) = next {
        state.waiters[next_slot].prev = prev;
    } else {
        state.waiter_tail = prev;
    }
    Some(state.waiters.remove(handle.slot))
}

#[inline]
fn pop_front_waiter(state: &mut SemaphoreState) -> Option<Waiter> {
    let slot = state.waiter_head?;
    let id = state.waiters.get(slot)?.id;
    unlink_waiter(state, WaiterHandle { slot, id })
}

#[inline]
fn remove_waiter_and_take_next_waker(
    state: &mut SemaphoreState,
    handle: WaiterHandle,
) -> (Option<Waiter>, Option<Arc<RegisteredWaker>>) {
    if is_front_waiter(state, handle) {
        // Clone only the Arc-owned registration before unlinking. This keeps
        // arbitrary RawWaker clone callbacks outside semaphore state.
        let next_waker = waiter_by_handle(state, handle)
            .and_then(|waiter| waiter.next)
            .and_then(|slot| waiter_waker_if_runnable(state, slot));
        (unlink_waiter(state, handle), next_waker)
    } else {
        (unlink_waiter(state, handle), None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WaiterHandle {
    slot: usize,
    id: u64,
}

impl Semaphore {
    /// Creates a new semaphore with the given number of permits.
    #[inline]
    /// Creates a new semaphore with the given permits and name for lock ordering.
    #[must_use]
    pub fn with_name(name: &'static str, permits: usize) -> Self {
        let rank = lock_ordering::rank_for_lock_name(name);
        Self {
            state: ParkingMutex::new(SemaphoreState {
                permits,
                closed: false,
                waiters: Slab::with_capacity(4),
                waiter_head: None,
                waiter_tail: None,
                next_waiter_id: 0,
                cancellation_count: 0,
            }),
            permits_shadow: AtomicUsize::new(permits),
            closed_shadow: AtomicBool::new(false),
            max_permits: permits,
            name,
            rank,
        }
    }

    /// Creates a new semaphore with the given permits using default naming.
    ///
    /// Note: For proper deadlock prevention, prefer `with_name()` to specify
    /// the semaphore's role in the lock hierarchy (e.g., "tasks", "regions").
    #[must_use]
    pub fn new(permits: usize) -> Self {
        Self::with_name("unknown", permits)
    }

    /// Returns the number of currently available permits.
    #[inline]
    #[must_use]
    pub fn available_permits(&self) -> usize {
        // Relaxed: advisory fast-path hint only. Stale reads are benign —
        // callers fall back to the mutex-protected path for correctness.
        self.permits_shadow.load(Ordering::Relaxed)
    }

    /// Returns the maximum number of permits (initial count).
    #[inline]
    #[must_use]
    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    /// Returns true if the semaphore is closed.
    #[inline]
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed_shadow.load(Ordering::Acquire)
    }

    /// Returns a deterministic, redacted snapshot of semaphore pressure.
    #[inline]
    #[must_use]
    pub fn telemetry_snapshot(&self, primitive_id: u64) -> crate::sync::SyncTelemetrySnapshot {
        let state = self.state.lock();
        let state_label = if state.closed {
            "closed"
        } else if state.waiter_head.is_some() {
            "waiting"
        } else if state.permits == 0 {
            "saturated"
        } else {
            "open"
        };
        crate::sync::SyncTelemetrySnapshot {
            primitive_id,
            primitive_kind: "semaphore",
            capacity: self.max_permits,
            occupied_units: self.max_permits.saturating_sub(state.permits),
            available_units: state.permits,
            waiter_count: state.waiters.len(),
            generation: 0,
            state: state_label,
            cancellation_count: state.cancellation_count,
            closed: state.closed,
        }
    }

    /// Closes the semaphore.
    #[inline]
    pub fn close(&self) {
        let taken = {
            let mut state = self.state.lock();
            state.closed = true;
            // Closed semaphores do not advertise reusable capacity.
            state.permits = 0;
            self.closed_shadow.store(true, Ordering::Release);
            self.permits_shadow.store(0, Ordering::Relaxed);
            state.waiter_head = None;
            state.waiter_tail = None;
            std::mem::take(&mut state.waiters)
        };
        // Isolate each detached wake so one hostile safe Waker cannot strand the
        // later waiters: they have already been removed from the slab and must
        // be woken to observe the closed state (br-asupersync-dl9wc3). Retain
        // the first panic, finish the fanout, then resume it once so exactly one
        // payload propagates and no second panic is raised mid-unwind.
        let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;
        for (_, waiter) in taken {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    waiter.waker.wake_by_ref();
                }))
            {
                if first_panic.is_none() {
                    first_panic = Some(payload);
                }
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }

    /// Acquires the given number of permits asynchronously.
    #[inline]
    pub fn acquire<'a, 'b, Caps>(
        &'a self,
        cx: &'b Cx<Caps>,
        count: usize,
    ) -> AcquireFuture<'a, 'b, Caps> {
        AcquireFuture {
            semaphore: self,
            cx,
            count,
            waiter: None,
            completed: false,
        }
    }

    /// Acquires `count` permits asynchronously as one all-or-nothing operation.
    ///
    /// This is named for parity with semaphore APIs that distinguish single and
    /// bulk acquisition. It delegates to [`Semaphore::acquire`], whose `count`
    /// argument is already atomic and cancel-safe.
    ///
    /// # Example
    ///
    /// ```
    /// # async fn example(cx: &asupersync::Cx) {
    /// use asupersync::sync::Semaphore;
    ///
    /// let semaphore = Semaphore::new(3);
    /// let permit = semaphore.acquire_many(cx, 2).await.unwrap();
    /// assert_eq!(permit.count(), 2);
    /// # }
    /// ```
    #[inline]
    pub fn acquire_many<'a, 'b, Caps>(
        &'a self,
        cx: &'b Cx<Caps>,
        count: usize,
    ) -> AcquireFuture<'a, 'b, Caps> {
        self.acquire(cx, count)
    }

    /// Acquires a permit set only after checked runtime obligation admission.
    ///
    /// FIFO, cancellation and all-or-nothing capacity rules match
    /// [`Self::acquire`]. A deliberately stateless context stays untracked;
    /// a stale or runtime-associated context without admission authority fails.
    /// Acquiring zero units needs no obligation and succeeds even after close
    /// or cancellation, matching the existing zero-unit operation.
    pub fn acquire_checked<'a, 'b, Caps>(
        &'a self,
        cx: &'b Cx<Caps>,
        count: usize,
    ) -> CheckedAcquireFuture<'a, 'b, Caps> {
        CheckedAcquireFuture {
            inner: self.acquire(cx, count),
        }
    }

    /// Checked all-or-nothing acquisition of `count` units.
    pub fn acquire_many_checked<'a, 'b, Caps>(
        &'a self,
        cx: &'b Cx<Caps>,
        count: usize,
    ) -> CheckedAcquireFuture<'a, 'b, Caps> {
        self.acquire_checked(cx, count)
    }

    /// Tries to acquire capacity and checked admission without waiting.
    ///
    /// Returns the semaphore's capacity unchanged on admission refusal.
    /// Zero units succeed without checking cancellation or minting a token.
    pub fn try_acquire_checked<Caps>(
        &self,
        cx: &Cx<Caps>,
        count: usize,
    ) -> Result<SemaphorePermit<'_>, CheckedAcquireError> {
        if count == 0 {
            return Ok(SemaphorePermit {
                semaphore: self,
                count: 0,
                obligation: None,
                runtime_obligation: None,
                lock_order: Default::default(),
            });
        }
        cx.checkpoint().map_err(|_| AcquireError::Cancelled)?;
        let mut rollback = AcquisitionRollbackGuard::new(self, count);
        rollback.notify_on_rollback = true;
        let mut state = self.state.lock();
        if state.closed {
            return Err(AcquireError::Closed.into());
        }
        if state.waiter_head.is_some() || state.permits < count {
            return Err(TryAcquireError.into());
        }
        if let Some(rank) = self.rank {
            lock_ordering::check_acquire(self.name, rank);
        }
        state.permits -= count;
        self.permits_shadow.store(state.permits, Ordering::Relaxed);
        rollback.arm();
        rollback.record_lock_acquire();
        drop(state);

        // Arm capacity rollback before arbitrary notifier callbacks, and admit
        // before minting the graded token so refusal cannot trip its drop bomb.
        rollback.runtime_obligation = cx.try_register_obligation_checked(
            crate::record::ObligationKind::SemaphorePermit,
            cx.task_id(),
        )?;
        rollback.obligation = reserve_permit_obligation(cx.region_id());
        Ok(rollback.into_borrowed_permit())
    }

    /// Checked nonblocking all-or-nothing acquisition of `count` units.
    pub fn try_acquire_many_checked<Caps>(
        &self,
        cx: &Cx<Caps>,
        count: usize,
    ) -> Result<SemaphorePermit<'_>, CheckedAcquireError> {
        self.try_acquire_checked(cx, count)
    }

    /// Tries to acquire the given number of permits without waiting.
    #[inline]
    pub fn try_acquire(&self, count: usize) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        // Acquiring 0 permits succeeds immediately (no resources needed)
        if count == 0 {
            return Ok(SemaphorePermit {
                semaphore: self,
                count: 0,
                obligation: None,
                runtime_obligation: None,
                lock_order: Default::default(),
            });
        }

        let mut rollback = AcquisitionRollbackGuard::new(self, count);
        rollback.notify_on_rollback = true;
        let mut state = self.state.lock();
        // Closed, FIFO-blocked (a waiter is queued) or short of permits.
        if state.closed || state.waiter_head.is_some() || state.permits < count {
            return Err(TryAcquireError);
        }
        // Enforce lock ordering only on the success path, under the state
        // guard and immediately before the transition, mirroring the async
        // acquisition path. A failed try_acquire (closed, FIFO-blocked, or
        // insufficient permits) must return Err rather than panic ASUP-E205
        // or record a phantom acquisition edge (br-asupersync-btp04i).
        if let Some(rank) = self.rank {
            lock_ordering::check_acquire(self.name, rank);
        }

        state.permits -= count;
        // Relaxed: permits_shadow is an advisory fast-path hint. A stale
        // read in available_permits() just skips the fast path or causes a
        // benign try_acquire miss — the real count is protected by the lock.
        // On ARM this avoids a store-release barrier per acquisition.
        self.permits_shadow.store(state.permits, Ordering::Relaxed);
        rollback.arm();
        rollback.record_lock_acquire();
        drop(state);

        // Register the obligations only after the lock is released, with the
        // rollback armed, as try_acquire_checked does. Registering wakes a
        // runtime worker and runs the gateway notifier: under the lock, a
        // notifier that touched this semaphore deadlocked, and one that
        // panicked lost the permits for good.
        //
        // One task-local lookup for both obligations: this is the
        // synchronization-critical path.
        let current_cx = crate::cx::Cx::current();
        rollback.runtime_obligation = current_cx
            .as_ref()
            .and_then(reserve_runtime_permit_obligation);
        // br-asupersync-13jmt3: the obligation's static description avoids a
        // per-acquire String allocation; the count is on the permit.
        rollback.obligation = current_cx
            .as_ref()
            .and_then(|cx| reserve_permit_obligation(cx.region_id()));
        Ok(rollback.into_borrowed_permit())
    }

    /// Tries to acquire `count` permits without waiting.
    ///
    /// The operation is all-or-nothing: it either returns a permit holding all
    /// requested units or leaves the semaphore unchanged.
    #[inline]
    pub fn try_acquire_many(&self, count: usize) -> Result<SemaphorePermit<'_>, TryAcquireError> {
        self.try_acquire(count)
    }

    /// Adds permits back to the semaphore.
    ///
    /// Saturates at `usize::MAX` if adding would overflow.
    #[inline]
    pub fn add_permits(&self, count: usize) {
        if let Some(waiter) = self.add_permits_deferred(count) {
            waiter.wake_by_ref();
        }
    }

    /// Return physical capacity before running any notifier or Waker callback.
    fn add_permits_deferred(&self, count: usize) -> Option<Arc<RegisteredWaker>> {
        if count == 0 {
            return None;
        }
        let mut state = self.state.lock();
        if state.closed {
            return None;
        }
        state.permits = state.permits.saturating_add(count);
        self.permits_shadow.store(state.permits, Ordering::Relaxed);
        // Only wake the first waiter since FIFO ordering means only it can acquire.
        // Waking all waiters wastes CPU when only the front can make progress.
        // If the first waiter acquires and releases, it will wake the next.
        let waiter_to_wake = front_waiter_waker_if_runnable(&state);
        drop(state);
        waiter_to_wake
    }
}

/// Keeps an already-runnable waiter notified even if obligation settlement
/// unwinds. A secondary callback panic must not replace the primary panic.
struct ReleasedSemaphoreWake(Option<Arc<RegisteredWaker>>);

impl Drop for ReleasedSemaphoreWake {
    fn drop(&mut self) {
        let Some(waker) = self.0.take() else {
            return;
        };
        let already_unwinding = std::thread::panicking();
        let notified =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake_by_ref()));
        let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker)));
        let failure = match (notified, retired) {
            (Err(primary), Err(secondary)) => {
                std::mem::forget(secondary);
                Some(primary)
            }
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Some(error),
            (Ok(()), Ok(())) => None,
        };
        if let Some(payload) = failure {
            if already_unwinding {
                std::mem::forget(payload);
            } else {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

/// Restores an acquisition that unwinds before ownership reaches a permit.
///
/// This guard is declared before the semaphore state guard in each poll loop,
/// so the state mutex is released before rollback runs during unwinding. The
/// Checked refusal also notifies a successor after restoring capacity. Once a
/// cascade callback has been dispatched, rollback must not dispatch it again.
struct AcquisitionRollbackGuard<'a> {
    semaphore: &'a Semaphore,
    count: usize,
    obligation: Option<ObligationToken<SemaphorePermitKind>>,
    /// Runtime-visible twin of `obligation` (D1 mailbox).
    runtime_obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
    lock_order: lock_ordering::GuardLockOrder,
    armed: bool,
    notify_on_rollback: bool,
}

impl<'a> AcquisitionRollbackGuard<'a> {
    #[inline]
    fn new(semaphore: &'a Semaphore, count: usize) -> Self {
        Self {
            semaphore,
            count,
            obligation: None,
            runtime_obligation: None,
            lock_order: Default::default(),
            armed: false,
            notify_on_rollback: false,
        }
    }

    #[inline]
    fn arm(&mut self) {
        self.armed = true;
    }

    #[inline]
    fn record_lock_acquire(&mut self) {
        if let Some(rank) = self.semaphore.rank {
            self.lock_order = lock_ordering::record_guard_acquire(self.semaphore.name, Some(rank));
        }
    }

    #[inline]
    fn set_obligation(
        &mut self,
        obligation: Option<ObligationToken<SemaphorePermitKind>>,
        runtime_obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
    ) {
        debug_assert!(self.obligation.is_none());
        debug_assert!(self.runtime_obligation.is_none());
        self.obligation = obligation;
        self.runtime_obligation = runtime_obligation;
    }

    #[inline]
    fn into_borrowed_permit(mut self) -> SemaphorePermit<'a> {
        let permit = SemaphorePermit {
            obligation: self.obligation.take(),
            runtime_obligation: self.runtime_obligation.take(),
            semaphore: self.semaphore,
            count: self.count,
            lock_order: lock_ordering::take_guard_lock_order(&mut self.lock_order),
        };
        self.armed = false;
        permit
    }

    #[inline]
    fn into_owned_permit(mut self, semaphore: Arc<Semaphore>) -> OwnedSemaphorePermit {
        let permit = OwnedSemaphorePermit {
            obligation: self.obligation.take(),
            runtime_obligation: self.runtime_obligation.take(),
            semaphore,
            count: self.count,
            lock_order: lock_ordering::take_guard_lock_order(&mut self.lock_order),
        };
        self.armed = false;
        permit
    }
}

impl Drop for AcquisitionRollbackGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        lock_ordering::record_guard_release(&mut self.lock_order);
        let waker = self.semaphore.add_permits_deferred(self.count);
        let _wake = ReleasedSemaphoreWake(if self.notify_on_rollback { waker } else { None });
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.commit();
        }
        // No permit reached the caller. Physical rollback and its successor
        // wake are already protected before the runtime notifier can unwind.
        if let Some(runtime_obligation) = self.runtime_obligation.take() {
            let _ = runtime_obligation.abort(crate::record::ObligationAbortReason::Cancel);
        }
    }
}

/// Future returned by `Semaphore::acquire`.
pub struct AcquireFuture<'a, 'b, Caps = crate::cx::cap::All> {
    semaphore: &'a Semaphore,
    cx: &'b Cx<Caps>,
    count: usize,
    waiter: Option<WaiterHandle>,
    completed: bool,
}

impl<Caps> Drop for AcquireFuture<'_, '_, Caps> {
    fn drop(&mut self) {
        if let Some(waiter) = self.waiter.take() {
            let (retired_waiter, next_waker) = {
                let mut state = self.semaphore.state.lock();
                state.cancellation_count = state.cancellation_count.saturating_add(1);
                // If we are at the front, we need to wake the next waiter when we leave,
                // otherwise the signal (permits available) might be lost.
                remove_waiter_and_take_next_waker(&mut state, waiter)
            };
            // A stored Waker may own a safe user-provided payload whose Drop
            // re-enters the semaphore. Retire it only after releasing state.
            drop(retired_waiter);
            if let Some(next) = next_waker {
                next.wake_by_ref();
            }
        }
    }
}

impl<'a, Caps> Future for AcquireFuture<'a, '_, Caps> {
    type Output = Result<SemaphorePermit<'a>, AcquireError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.poll_with_registration(context, |cx| Ok(reserve_runtime_permit_obligation(cx)))
    }
}

impl<'a, Caps> AcquireFuture<'a, '_, Caps> {
    fn poll_with_registration<E: From<AcquireError>>(
        &mut self,
        context: &mut Context<'_>,
        register: impl FnOnce(
            &Cx<Caps>,
        )
            -> Result<Option<crate::runtime::obligation_mailbox::ObligationToken>, E>,
    ) -> Poll<Result<SemaphorePermit<'a>, E>> {
        if self.completed {
            return Poll::Ready(Err(AcquireError::PolledAfterCompletion.into()));
        }

        // Acquiring 0 permits succeeds immediately (no resources needed)
        if self.count == 0 {
            self.completed = true;
            return Poll::Ready(Ok(SemaphorePermit {
                semaphore: self.semaphore,
                count: 0,
                obligation: None,
                runtime_obligation: None,
                lock_order: Default::default(),
            }));
        }

        if self.cx.checkpoint().is_err() {
            let waiter = self.waiter.take();
            let (retired_waiter, next_waker) = {
                let mut state = self.semaphore.state.lock();
                state.cancellation_count = state.cancellation_count.saturating_add(1);
                if let Some(waiter) = waiter {
                    // If we are at the front, we need to wake the next waiter when we leave,
                    // otherwise the signal (permits available) might be lost.
                    remove_waiter_and_take_next_waker(&mut state, waiter)
                } else {
                    (None, None)
                }
            };
            self.completed = true;
            drop(retired_waiter);
            if let Some(next) = next_waker {
                next.wake_by_ref();
            }
            return Poll::Ready(Err(AcquireError::Cancelled.into()));
        }

        // Prepare a registration lazily. The uncontended acquisition path
        // keeps its allocation-free behavior; only a poll that actually needs
        // to enqueue or replace a waker releases state, clones the RawWaker,
        // and retries the authoritative check.
        let mut incoming_waker = None;
        loop {
            // This must be declared before `state`: unwind drops locals in
            // reverse order, releasing the mutex before rollback re-locks it.
            let mut rollback = AcquisitionRollbackGuard::new(self.semaphore, self.count);
            // A rollback wakes the waiter its restored permits make runnable,
            // for the unchecked path too. Without the wake, an unwind after
            // the permits were taken (a stored Waker whose Drop panics) left
            // the next waiter parked with capacity available.
            rollback.notify_on_rollback = true;
            let mut state = self.semaphore.state.lock();

            if state.closed {
                let retired_waiter = self
                    .waiter
                    .and_then(|waiter| unlink_waiter(&mut state, waiter));
                drop(state);
                self.waiter = None;
                self.completed = true;
                drop(retired_waiter);
                drop(incoming_waker);
                return Poll::Ready(Err(AcquireError::Closed.into()));
            }

            // FIFO fairness: only acquire if queue is empty or we are at the front.
            // This prevents queue jumping where a new arrival grabs permits before
            // earlier-waiting tasks get their turn.
            let is_next_in_line = self.waiter.map_or(state.waiter_head.is_none(), |waiter| {
                is_front_waiter(&state, waiter)
            });

            if is_next_in_line && state.permits >= self.count {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = self.semaphore.rank {
                    lock_ordering::check_acquire(self.semaphore.name, rank);
                }

                state.permits -= self.count;
                self.semaphore
                    .permits_shadow
                    .store(state.permits, Ordering::Relaxed);
                rollback.arm();

                // Record lock acquisition for ordering tracking
                rollback.record_lock_acquire();

                // Optimization: Since we verified we are next in line, we are either
                // at the front of the queue or the queue is empty. We can just pop
                // the front instead of scanning the whole deque with retain (O(N)).
                let retired_waiter = if let Some(waiter) = self.waiter {
                    debug_assert!(is_front_waiter(&state, waiter));
                    let removed = pop_front_waiter(&mut state);
                    debug_assert!(removed.is_some());
                    removed
                } else {
                    None
                };

                // Wake next waiter if there are still permits available.
                // Without this, add_permits(N) where N satisfies multiple waiters
                // would only wake the first, leaving others sleeping indefinitely.
                let next_waker = front_waiter_waker_if_runnable(&state);
                drop(state);
                // Clear the waiter handle after releasing state guard to avoid borrow conflicts.
                self.waiter = None;
                self.completed = true;
                drop(retired_waiter);
                drop(incoming_waker);
                // Reserve before dispatching the next waiter so rollback also
                // consumes the obligation if that callback unwinds.
                rollback.runtime_obligation = match register(self.cx) {
                    Ok(token) => token,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                rollback.obligation = reserve_permit_obligation(self.cx.region_id());
                if let Some(next) = next_waker {
                    rollback.notify_on_rollback = false;
                    next.wake_by_ref();
                }
                return Poll::Ready(Ok(rollback.into_borrowed_permit()));
            }

            if let Some(waiter) = self.waiter
                && let Some(existing) = waiter_by_handle_mut(&mut state, waiter)
            {
                debug_assert_eq!(existing.count, self.count);
                if existing.waker.will_wake(context.waker()) {
                    drop(state);
                    drop(incoming_waker);
                    return Poll::Pending;
                }
                if let Some(incoming) = incoming_waker.take() {
                    let retired_waker = std::mem::replace(&mut existing.waker, incoming);
                    drop(state);
                    drop(retired_waker);
                    return Poll::Pending;
                }
            }

            if incoming_waker.is_none() {
                drop(state);
                incoming_waker = Some(RegisteredWaker::new(context.waker()));
                continue;
            }

            // Reserve before transferring the prepared registration. If
            // growth panics, the state guard unwinds before the still-local
            // registration can run arbitrary RawWaker destruction.
            state.waiters.reserve(1);
            self.waiter = Some(enqueue_waiter(
                &mut state,
                self.count,
                incoming_waker
                    .take()
                    .expect("prepared semaphore Waker must be available"),
            ));
            drop(state);
            return Poll::Pending;
        }
    }
}

/// Future returned by [`Semaphore::acquire_checked`].
/// Uses the existing FIFO waiter and cancellation path with checked admission.
pub struct CheckedAcquireFuture<'a, 'b, Caps = crate::cx::cap::All> {
    inner: AcquireFuture<'a, 'b, Caps>,
}

impl<'a, Caps> Future for CheckedAcquireFuture<'a, '_, Caps> {
    type Output = Result<SemaphorePermit<'a>, CheckedAcquireError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.poll_with_registration(context, |cx| {
            cx.try_register_obligation_checked(
                crate::record::ObligationKind::SemaphorePermit,
                cx.task_id(),
            )
            .map_err(CheckedAcquireError::Admission)
        })
    }
}

/// A permit from a semaphore.
///
/// Fields are ordered so that `obligation` drops first (firing the panic if leaked)
/// and then semaphore drops (releasing permits back to the semaphore).
#[derive(Debug)]
#[must_use = "permit will be immediately released if not held"]
pub struct SemaphorePermit<'a> {
    obligation: Option<ObligationToken<SemaphorePermitKind>>,
    /// Runtime-visible twin of `obligation`, minted through the acquiring
    /// `Cx`'s obligation mailbox and resolved wherever `obligation` is.
    runtime_obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
    semaphore: &'a Semaphore,
    count: usize,
    lock_order: lock_ordering::GuardLockOrder,
}

impl SemaphorePermit<'_> {
    /// Returns the number of permits held.
    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Forgets the permit without releasing it back to the semaphore.
    /// This aborts the underlying obligation to indicate the permit was intentionally leaked.
    #[inline]
    pub fn forget(mut self) {
        self.count = 0;
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.abort();
        }
        if let Some(runtime_obligation) = self.runtime_obligation.take() {
            let _ = runtime_obligation.abort(crate::record::ObligationAbortReason::Explicit);
        }
    }

    /// Extracts the obligation token without releasing the permit back to the semaphore.
    /// This transfers ownership of the obligation to the caller.
    /// The permit is consumed and will not release permits back to the semaphore.
    #[inline]
    pub(crate) fn into_parts(
        mut self,
    ) -> (
        usize,
        Option<ObligationToken<SemaphorePermitKind>>,
        Option<crate::runtime::obligation_mailbox::ObligationToken>,
        lock_ordering::GuardLockOrder,
    ) {
        let count = self.count;
        let obligation = self.obligation.take();
        let runtime_obligation = self.runtime_obligation.take();
        let lock_order = lock_ordering::take_guard_lock_order(&mut self.lock_order);
        self.count = 0; // Prevent Drop from releasing permits
        (count, obligation, runtime_obligation, lock_order)
    }

    /// Commits the permit explicitly, releasing it back to the semaphore.
    /// This consumes the permit and commits the underlying obligation, preventing
    /// the drop bomb from firing.
    #[inline]
    pub fn commit(self) {
        drop(self);
    }
}

impl Drop for SemaphorePermit<'_> {
    fn drop(&mut self) {
        // Restore physical ownership and arm its wake before token settlement
        // can invoke a user-supplied runtime notifier.
        lock_ordering::record_guard_release(&mut self.lock_order);
        let _wake = ReleasedSemaphoreWake(self.semaphore.add_permits_deferred(self.count));
        self.count = 0;
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.commit();
        }
        // Releasing capacity back to the semaphore discharges the runtime
        // obligation; a permit dropped without release is `forget`, which
        // aborts instead.
        if let Some(runtime_obligation) = self.runtime_obligation.take() {
            let _ = runtime_obligation.commit();
        }
        // Ordinary RAII drop is the normal release path for semaphore permits.
    }
}

/// An owned permit from a semaphore.
///
/// Fields are ordered so that `obligation` drops first (firing the panic if leaked)
/// and then semaphore drops (releasing permits back to the semaphore).
#[derive(Debug)]
#[must_use = "permit will be immediately released if not held"]
pub struct OwnedSemaphorePermit {
    obligation: Option<ObligationToken<SemaphorePermitKind>>,
    /// Runtime-visible twin of `obligation`, carried over from the borrowed
    /// permit so converting one does not drop the runtime's view of it.
    runtime_obligation: Option<crate::runtime::obligation_mailbox::ObligationToken>,
    semaphore: std::sync::Arc<Semaphore>,
    count: usize,
    lock_order: lock_ordering::GuardLockOrder,
}

impl OwnedSemaphorePermit {
    /// Acquires an owned permit with checked runtime obligation admission.
    ///
    /// Ownership conversion preserves the one admitted token. No second
    /// obligation is minted. Zero units follow [`Semaphore::acquire_checked`].
    pub async fn acquire_checked<Caps>(
        semaphore: Arc<Semaphore>,
        cx: &Cx<Caps>,
        count: usize,
    ) -> Result<Self, CheckedAcquireError> {
        let permit = semaphore.acquire_checked(cx, count).await?;
        let (count, obligation, runtime_obligation, lock_order) = permit.into_parts();
        Ok(Self {
            obligation,
            runtime_obligation,
            semaphore,
            count,
            lock_order,
        })
    }

    /// Tries to acquire an owned permit with checked admission and explicit
    /// cancellation authority.
    pub fn try_acquire_checked<Caps>(
        semaphore: Arc<Semaphore>,
        cx: &Cx<Caps>,
        count: usize,
    ) -> Result<Self, CheckedAcquireError> {
        let permit = semaphore.try_acquire_checked(cx, count)?;
        let (count, obligation, runtime_obligation, lock_order) = permit.into_parts();
        Ok(Self {
            obligation,
            runtime_obligation,
            semaphore,
            count,
            lock_order,
        })
    }

    /// Checked try-acquire that clones the semaphore `Arc` only on success.
    pub fn try_acquire_arc_checked<Caps>(
        semaphore: &Arc<Semaphore>,
        cx: &Cx<Caps>,
        count: usize,
    ) -> Result<Self, CheckedAcquireError> {
        let permit = semaphore.try_acquire_checked(cx, count)?;
        let (count, obligation, runtime_obligation, lock_order) = permit.into_parts();
        Ok(Self {
            obligation,
            runtime_obligation,
            semaphore: Arc::clone(semaphore),
            count,
            lock_order,
        })
    }

    /// Acquires an owned permit asynchronously.
    pub async fn acquire<Caps>(
        semaphore: std::sync::Arc<Semaphore>,
        cx: &Cx<Caps>,
        count: usize,
    ) -> Result<Self, AcquireError> {
        // Acquiring 0 permits succeeds immediately (no resources needed)
        if count == 0 {
            return Ok(Self {
                obligation: None,
                runtime_obligation: None,
                semaphore,
                count: 0,
                lock_order: Default::default(),
            });
        }
        OwnedAcquireFuture {
            semaphore,
            cx: Some(cx.clone()),
            count,
            waiter: None,
            completed: false,
        }
        .await
    }

    /// Tries to acquire an owned permit without waiting.
    #[inline]
    pub fn try_acquire(
        semaphore: std::sync::Arc<Semaphore>,
        count: usize,
    ) -> Result<Self, TryAcquireError> {
        let permit = semaphore.try_acquire(count)?;
        // Transfer ownership: extract the obligation token so the OwnedSemaphorePermit
        // will handle both permit release and obligation lifecycle in its own Drop.
        let (count, obligation, runtime_obligation, lock_order) = permit.into_parts();
        Ok(Self {
            obligation,
            runtime_obligation,
            semaphore,
            count,
            lock_order,
        })
    }

    /// Tries to acquire an owned permit without waiting, cloning the `Arc`
    /// only on success.
    ///
    /// This avoids an `Arc::clone` + refcount round-trip when the semaphore
    /// has no available permits (the common contended case).
    #[inline]
    pub fn try_acquire_arc(
        semaphore: &std::sync::Arc<Semaphore>,
        count: usize,
    ) -> Result<Self, TryAcquireError> {
        // Acquire permits via the semaphore's internal state directly.
        // We extract the obligation token from the SemaphorePermit to avoid its Drop
        // releasing permits, since OwnedSemaphorePermit's Drop will handle the release instead.
        let permit = semaphore.try_acquire(count)?;
        // Transfer ownership: extract the obligation token so the OwnedSemaphorePermit
        // will handle both permit release and obligation lifecycle in its own Drop.
        let (count, obligation, runtime_obligation, lock_order) = permit.into_parts();
        Ok(Self {
            obligation,
            runtime_obligation,
            semaphore: semaphore.clone(),
            count,
            lock_order,
        })
    }

    /// Returns the number of permits held.
    #[inline]
    #[must_use]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Forgets the permit without releasing it back to the semaphore.
    #[inline]
    pub fn forget(mut self) {
        // Forgetting leaks capacity but ends this guard's lock-order lifetime.
        lock_ordering::record_guard_release(&mut self.lock_order);
        self.count = 0;
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.abort();
        }
        if let Some(runtime_obligation) = self.runtime_obligation.take() {
            let _ = runtime_obligation.abort(crate::record::ObligationAbortReason::Explicit);
        }
    }

    /// Commits the permit explicitly, releasing it back to the semaphore.
    /// This is equivalent to dropping the permit but provides explicit control.
    #[inline]
    pub fn commit(self) {
        // The Drop implementation will handle both permit release and obligation commit
        drop(self);
    }
}

impl Drop for OwnedSemaphorePermit {
    fn drop(&mut self) {
        lock_ordering::record_guard_release(&mut self.lock_order);
        let _wake = ReleasedSemaphoreWake(self.semaphore.add_permits_deferred(self.count));
        self.count = 0;
        if let Some(obligation) = self.obligation.take() {
            let _proof = obligation.commit();
        }
        if let Some(runtime_obligation) = self.runtime_obligation.take() {
            let _ = runtime_obligation.commit();
        }
    }
}

/// Future returned by `OwnedSemaphorePermit::acquire`.
pub struct OwnedAcquireFuture<Caps = crate::cx::cap::All> {
    semaphore: Arc<Semaphore>,
    cx: Option<Cx<Caps>>,
    count: usize,
    waiter: Option<WaiterHandle>,
    completed: bool,
}

impl<Caps> OwnedAcquireFuture<Caps> {
    /// Construct a new acquire future with an owned `Cx`.
    ///
    /// This avoids the lifetime issue with the `async fn acquire` signature
    /// which borrows `&Cx` (and thus ties the future's lifetime to the borrow).
    pub(crate) fn new(semaphore: Arc<Semaphore>, cx: Cx<Caps>, count: usize) -> Self {
        // Note: count=0 is handled at the future poll level
        Self {
            semaphore,
            cx: Some(cx),
            count,
            waiter: None,
            completed: false,
        }
    }
}

impl OwnedAcquireFuture {
    /// Construct a new acquire future that waits without cancellation support.
    ///
    /// This is used by `Service::poll_ready` middleware paths that must still
    /// register a real semaphore waiter even when no task-local [`Cx`] is
    /// available.
    pub(crate) fn new_uncancelable(semaphore: Arc<Semaphore>, count: usize) -> Self {
        // Note: count=0 is handled at the future poll level
        Self {
            semaphore,
            cx: None,
            count,
            waiter: None,
            completed: false,
        }
    }
}

impl<Caps> Drop for OwnedAcquireFuture<Caps> {
    fn drop(&mut self) {
        if let Some(waiter) = self.waiter.take() {
            let (retired_waiter, next_waker) = {
                let mut state = self.semaphore.state.lock();
                state.cancellation_count = state.cancellation_count.saturating_add(1);
                // If we are at the front, we need to wake the next waiter when we leave,
                // otherwise the signal (permits available) might be lost.
                remove_waiter_and_take_next_waker(&mut state, waiter)
            };
            // Keep arbitrary Waker payload destruction outside semaphore state.
            drop(retired_waiter);
            if let Some(next) = next_waker {
                next.wake_by_ref();
            }
        }
    }
}

impl<Caps> Future for OwnedAcquireFuture<Caps> {
    type Output = Result<OwnedSemaphorePermit, AcquireError>;

    #[inline]
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.completed {
            return Poll::Ready(Err(AcquireError::PolledAfterCompletion));
        }

        // Acquiring 0 permits succeeds immediately (no resources needed)
        if this.count == 0 {
            this.completed = true;
            return Poll::Ready(Ok(OwnedSemaphorePermit {
                obligation: None,
                runtime_obligation: None,
                semaphore: this.semaphore.clone(),
                count: 0,
                lock_order: Default::default(),
            }));
        }

        if this.cx.as_ref().is_some_and(|cx| cx.checkpoint().is_err()) {
            let waiter = this.waiter.take();
            let (retired_waiter, next_waker) = {
                let mut state = this.semaphore.state.lock();
                state.cancellation_count = state.cancellation_count.saturating_add(1);
                if let Some(waiter) = waiter {
                    // If we are at the front, we need to wake the next waiter when we leave,
                    // otherwise the signal (permits available) might be lost.
                    remove_waiter_and_take_next_waker(&mut state, waiter)
                } else {
                    (None, None)
                }
            };
            this.completed = true;
            drop(retired_waiter);
            if let Some(next) = next_waker {
                next.wake_by_ref();
            }
            return Poll::Ready(Err(AcquireError::Cancelled));
        }

        // Keep the uncontended path allocation-free. A registration is built
        // only after an authoritative locked check proves that this poll must
        // enqueue or replace a waker, then the state is rechecked before use.
        let mut incoming_waker = None;
        loop {
            // See the borrowed path: the declaration order guarantees that
            // rollback never attempts to re-lock while `state` is held.
            let mut rollback = AcquisitionRollbackGuard::new(&this.semaphore, this.count);
            let mut state = this.semaphore.state.lock();

            if state.closed {
                let retired_waiter = this
                    .waiter
                    .and_then(|waiter| unlink_waiter(&mut state, waiter));
                drop(state);
                this.waiter = None;
                this.completed = true;
                drop(retired_waiter);
                drop(incoming_waker);
                return Poll::Ready(Err(AcquireError::Closed));
            }

            // FIFO fairness: only acquire if queue is empty or we are at the front.
            let is_next_in_line = this.waiter.map_or(state.waiter_head.is_none(), |waiter| {
                is_front_waiter(&state, waiter)
            });

            if is_next_in_line && state.permits >= this.count {
                // Check lock ordering before acquisition (debug builds only)
                if let Some(rank) = this.semaphore.rank {
                    lock_ordering::check_acquire(this.semaphore.name, rank);
                }

                state.permits -= this.count;
                this.semaphore
                    .permits_shadow
                    .store(state.permits, Ordering::Relaxed);
                rollback.arm();

                // Record lock acquisition for ordering tracking
                rollback.record_lock_acquire();

                // Optimization: O(1) removal instead of O(N) retain
                let retired_waiter = if let Some(waiter) = this.waiter {
                    debug_assert!(is_front_waiter(&state, waiter));
                    let removed = pop_front_waiter(&mut state);
                    debug_assert!(removed.is_some());
                    removed
                } else {
                    None
                };

                // Wake next waiter if there are still permits available.
                // Without this, add_permits(N) where N satisfies multiple waiters
                // would only wake the first, leaving others sleeping indefinitely.
                let next_waker = front_waiter_waker_if_runnable(&state);
                drop(state);
                // Prevent redundant Drop cleanup after releasing state guard.
                this.waiter = None;
                this.completed = true;
                drop(retired_waiter);
                drop(incoming_waker);
                // The uncancelable host-boundary path has no task-local region,
                // so it intentionally carries no obligation, as before.
                rollback.set_obligation(
                    this.cx
                        .as_ref()
                        .and_then(|cx| reserve_permit_obligation(cx.region_id())),
                    this.cx.as_ref().and_then(reserve_runtime_permit_obligation),
                );
                if let Some(next) = next_waker {
                    next.wake_by_ref();
                }
                return Poll::Ready(Ok(rollback.into_owned_permit(Arc::clone(&this.semaphore))));
            }

            if let Some(waiter) = this.waiter
                && let Some(existing) = waiter_by_handle_mut(&mut state, waiter)
            {
                debug_assert_eq!(existing.count, this.count);
                if existing.waker.will_wake(context.waker()) {
                    drop(state);
                    drop(incoming_waker);
                    return Poll::Pending;
                }
                if let Some(incoming) = incoming_waker.take() {
                    let retired_waker = std::mem::replace(&mut existing.waker, incoming);
                    drop(state);
                    drop(retired_waker);
                    return Poll::Pending;
                }
            }

            if incoming_waker.is_none() {
                drop(state);
                incoming_waker = Some(RegisteredWaker::new(context.waker()));
                continue;
            }

            // Reserve before transferring the prepared registration. If
            // growth panics, the state guard unwinds before the still-local
            // registration can run arbitrary RawWaker destruction.
            state.waiters.reserve(1);
            this.waiter = Some(enqueue_waiter(
                &mut state,
                this.count,
                incoming_waker
                    .take()
                    .expect("prepared semaphore Waker must be available"),
            ));
            drop(state);
            return Poll::Pending;
        }
    }
}

#[cfg(test)]
#[path = "semaphore_inline_tests.rs"]
mod tests;
