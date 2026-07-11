//! Spawn mailbox: lock-free spawn-request intake decoupled from `RuntimeState`.
//!
//! Today every spawn must hold the global `RuntimeState` lock while
//! `create_task` runs. The spawn mailbox is the first half of the fix
//! (br-asupersync-dx-core-api-v2-u1z5hn.1): callers pre-allocate a
//! *provisional* [`TaskId`] from a sharded allocator, package the erased
//! future plus its spawn parameters into a [`SpawnRequest`], and enqueue it
//! onto the [`SpawnMailbox`] **without touching `RuntimeState`**. The
//! scheduler performs admission (region liveness check, task-record
//! insertion, obligation hookup) at dispatch time under the state lock it
//! already holds; that half lands separately
//! (br-asupersync-dx-core-api-v2-u1z5hn.1.3), as does region pending-spawn
//! quiescence accounting (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
//!
//! # Provisional task-id namespace
//!
//! Arena-allocated `TaskId`s carry small generations: fresh slots start at
//! generation 0 and the generation increments once per slot reuse. The
//! mailbox mints ids in a disjoint namespace by setting the generation MSB
//! ([`SPAWN_ID_GENERATION_TAG`]): an arena id would need 2^31 reuses of a
//! single slot to collide, which is unreachable in practice. Layout:
//!
//! ```text
//! generation = TAG(bit 31) | shard(bits 30..24) | epoch(bits 23..0)
//! index      = low 32 bits of the per-shard allocation counter
//! ```
//!
//! Uniqueness proof sketch: distinct shards produce distinct generations, so
//! ids from different shards never collide; within one shard a single atomic
//! `fetch_add` produces a strictly increasing 56-bit (epoch, index) pair, so
//! ids from the same shard never collide before 2^56 allocations per shard.
//! Admission maps a provisional id to its canonical arena id (or adopts it,
//! once the sharded task table lands); the mapping policy is owned by the
//! admission bead.
//!
//! # Capacity and backpressure
//!
//! The mailbox is **unbounded** ([`GlobalFifoQueue`] wraps a lock-free
//! `SegQueue` on native targets, a mutexed `VecDeque` on wasm). `enqueue`
//! never blocks and never drops a request — silent drop is forbidden by the
//! spawn-mailbox contract. Backpressure is an *admission-side* concern:
//! region quotas reject requests with an explicit `SpawnError` when they are
//! admitted, and region close resolves every pending request through
//! [`SpawnRequest::resolve_cancelled`] so the completion slot always learns
//! the outcome. Memory growth is therefore bounded by the same quota that
//! bounds live tasks, just observed at admission instead of enqueue.
//!
//! # Trace ordering
//!
//! [`SpawnMailbox::enqueue`] emits [`TraceEventKind::TaskSpawnEnqueued`]
//! *before* the request is published to the queue. The trace buffer
//! serializes sequence allocation with insertion, so the enqueue event's
//! sequence number is always ordered before any admission-side event for the
//! same request (a consumer can only observe the request after the push).

use crate::runtime::scheduler::global_queue::GlobalFifoQueue;
use crate::runtime::state::SpawnError;
use crate::runtime::stored_task::StoredTask;
use crate::trace::TraceBufferHandle;
use crate::trace::event::TraceEvent;
use crate::types::Outcome;
use crate::types::{Budget, CancelReason, RegionId, TaskId, Time};
use crate::util::{ArenaIndex, CachePadded};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};

pub use crate::record::region::{PendingSpawnCounter, PendingSpawnReservation};

/// Generation tag (MSB) marking a provisional spawn-mailbox `TaskId`.
///
/// Arena generations start at 0 and increment once per slot reuse, so an
/// arena id reaches this bit only after 2^31 reuses of one slot.
pub const SPAWN_ID_GENERATION_TAG: u32 = 0x8000_0000;

/// Number of bits in the generation reserved for the epoch counter.
const SPAWN_ID_EPOCH_BITS: u32 = 24;

/// Maximum epoch value before a shard is exhausted (2^24 epochs of 2^32 ids).
const SPAWN_ID_EPOCH_MAX: u64 = (1 << SPAWN_ID_EPOCH_BITS) - 1;

/// Number of allocation shards. Must stay ≤ 128 so the shard index fits the
/// 7-bit field between the tag bit and the epoch bits.
pub const SPAWN_ID_SHARDS: usize = 8;

/// Round-robin seed handing each new thread a home shard.
static NEXT_SHARD_HINT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Home shard for the current thread (round-robin assigned on first use).
    static SHARD_HINT: usize =
        NEXT_SHARD_HINT.fetch_add(1, Ordering::Relaxed) % SPAWN_ID_SHARDS;
}

/// Returns true if `id` was minted by a [`SpawnIdAllocator`] (provisional
/// spawn-mailbox namespace) rather than by the runtime's task arena.
#[inline]
#[must_use]
pub fn is_spawn_mailbox_id(id: TaskId) -> bool {
    id.arena_index().generation() & SPAWN_ID_GENERATION_TAG != 0
}

/// Sharded allocator for provisional spawn-mailbox [`TaskId`]s.
///
/// Allocation is a single relaxed `fetch_add` on the calling thread's home
/// shard; no locks, no `RuntimeState`. See the module docs for the id layout
/// and the uniqueness argument.
pub struct SpawnIdAllocator {
    shards: [CachePadded<AtomicU64>; SPAWN_ID_SHARDS],
}

impl SpawnIdAllocator {
    /// Creates a new allocator with all shard counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| CachePadded::new(AtomicU64::new(0))),
        }
    }

    /// Allocates a provisional `TaskId` on the calling thread's home shard.
    #[inline]
    #[must_use]
    pub fn allocate(&self) -> TaskId {
        self.allocate_on(SHARD_HINT.with(|shard| *shard))
    }

    /// Allocates a provisional `TaskId` on an explicit shard.
    ///
    /// # Panics
    ///
    /// Panics if `shard >= SPAWN_ID_SHARDS` or if the shard has exhausted its
    /// 2^56 id space (unreachable in any realistic process lifetime).
    #[must_use]
    pub fn allocate_on(&self, shard: usize) -> TaskId {
        assert!(
            shard < SPAWN_ID_SHARDS,
            "spawn-id shard {shard} out of range (max {SPAWN_ID_SHARDS})"
        );
        let n = self.shards[shard].fetch_add(1, Ordering::Relaxed);
        let epoch = n >> 32;
        assert!(
            epoch <= SPAWN_ID_EPOCH_MAX,
            "spawn-id shard {shard} exhausted after 2^56 allocations"
        );
        let index = u32::try_from(n & u64::from(u32::MAX)).expect("masked to 32 bits");
        let shard_bits = u32::try_from(shard).expect("shard fits in u32") << SPAWN_ID_EPOCH_BITS;
        let epoch_bits = u32::try_from(epoch).expect("epoch fits in 24 bits");
        let generation = SPAWN_ID_GENERATION_TAG | shard_bits | epoch_bits;
        TaskId::from_arena(ArenaIndex::new(index, generation))
    }
}

impl Default for SpawnIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SpawnIdAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnIdAllocator")
            .field("shards", &SPAWN_ID_SHARDS)
            .finish_non_exhaustive()
    }
}

/// Completion slot invoked when a spawn request is cancelled before
/// admission (for example, its region closed while the request was queued).
///
/// The slot must resolve the caller-visible join handle with
/// `Outcome::Cancelled(reason)`; it is invoked at most once.
pub type UnadmittedCancelFn = Box<dyn FnOnce(CancelReason) + Send>;

/// Completion slot invoked when admission rejects a spawn request with a
/// non-cancellation error (for example, the region is at capacity).
///
/// The slot must resolve the caller-visible join handle with
/// `Err(SpawnError)`; it is invoked at most once. Slots run after the
/// admission path releases the `RuntimeState` lock and must not re-enter
/// the runtime state.
pub type AdmissionErrorFn = Box<dyn FnOnce(SpawnError) + Send>;

/// Erased future type produced by a spawn factory.
pub type SpawnBoxFuture = Pin<Box<dyn Future<Output = Outcome<(), ()>> + Send>>;

/// Erased spawn factory (br-asupersync-4h8lye / A2.1).
///
/// Receives the child capability context that **admission** builds (canonical
/// arena task id, full driver handles) and returns the task future. The
/// factory is invoked by [`LazyFactoryTask`] at the task's *first poll* — on
/// a worker, outside the `RuntimeState` lock — never during admission.
pub type SpawnFactoryFn = Box<dyn FnOnce(crate::cx::Cx) -> SpawnBoxFuture + Send>;

/// Identity of an admitted task, published to producers via
/// [`SpawnRequest::with_admitted_slot`].
#[derive(Debug, Clone)]
pub struct AdmittedTask {
    /// Canonical arena task id (replaces the provisional mailbox id).
    pub task_id: TaskId,
    /// Weak handle to the admission-built capability context, for
    /// handle-side abort plumbing (A2.2).
    pub cx_inner: std::sync::Weak<parking_lot::RwLock<crate::types::task_context::CxInner>>,
}

/// Public source-compatible name for the existing admission identity slot.
pub type AdmittedTaskSlot = OnceLock<AdmittedTask>;

pub(crate) type PendingCancelReason = Arc<RwLock<Option<CancelReason>>>;

struct PendingCancelRendezvous {
    slot: Weak<AdmittedTaskSlot>,
    reason: PendingCancelReason,
}

static PENDING_CANCEL_RENDEZVOUS: OnceLock<Mutex<HashMap<usize, PendingCancelRendezvous>>> =
    OnceLock::new();
static PENDING_CANCEL_REGISTRATIONS: AtomicUsize = AtomicUsize::new(0);
const RENDEZVOUS_PURGE_INTERVAL: usize = 1024;

fn pending_cancel_registry() -> &'static Mutex<HashMap<usize, PendingCancelRendezvous>> {
    PENDING_CANCEL_RENDEZVOUS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn admitted_slot_key(slot: &Arc<AdmittedTaskSlot>) -> usize {
    Arc::as_ptr(slot) as usize
}

fn purge_stale_rendezvous(entries: &mut HashMap<usize, PendingCancelRendezvous>) {
    entries.retain(|_, entry| entry.slot.strong_count() > 0);
}

/// Returns the shared strongest-reason cache for `slot`, creating it when the
/// producer has not registered the slot yet.
pub(crate) fn register_pending_cancel_rendezvous(
    slot: &Arc<AdmittedTaskSlot>,
) -> PendingCancelReason {
    let key = admitted_slot_key(slot);
    let mut entries = pending_cancel_registry().lock();
    if PENDING_CANCEL_REGISTRATIONS.fetch_add(1, Ordering::Relaxed) % RENDEZVOUS_PURGE_INTERVAL == 0
    {
        purge_stale_rendezvous(&mut entries);
    }
    if let Some(entry) = entries.get(&key) {
        if let Some(existing_slot) = entry.slot.upgrade() {
            if Arc::ptr_eq(&existing_slot, slot) {
                return Arc::clone(&entry.reason);
            }
        }
    }

    let reason = Arc::new(RwLock::new(None));
    entries.insert(
        key,
        PendingCancelRendezvous {
            slot: Arc::downgrade(slot),
            reason: Arc::clone(&reason),
        },
    );
    reason
}

/// Retires and returns the cache registered for this exact slot allocation.
/// Pointer equality prevents a stale key from binding to a reused address.
pub(crate) fn retire_pending_cancel_rendezvous(
    slot: &Arc<AdmittedTaskSlot>,
) -> Option<PendingCancelReason> {
    let key = admitted_slot_key(slot);
    let mut entries = pending_cancel_registry().lock();
    let matches_slot = entries
        .get(&key)
        .and_then(|entry| entry.slot.upgrade())
        .is_some_and(|registered| Arc::ptr_eq(&registered, slot));
    if !matches_slot {
        entries.remove(&key);
        return None;
    }
    entries.remove(&key).map(|entry| entry.reason)
}

fn strengthen_with_requested_reason(
    mut reason: CancelReason,
    requested: Option<&PendingCancelReason>,
) -> CancelReason {
    if let Some(requested) = requested.and_then(|slot| slot.read().clone()) {
        reason.strengthen(&requested);
    }
    reason
}

fn requested_admission_failure_reason(
    error: &SpawnError,
    requested: Option<&PendingCancelReason>,
) -> Option<CancelReason> {
    let requested = requested.and_then(|slot| slot.read().clone())?;
    let mut reason = CancelReason::user("spawn admission failed");
    reason.message = Some(error.to_string());
    reason.strengthen(&requested);
    Some(reason)
}

/// What a [`SpawnRequest`] carries to admission.
pub enum SpawnPayload {
    /// A pre-erased future, wrapped by the producer (A1 path; the producer
    /// already had everything it needed — e.g. `RuntimeInner::spawn`).
    Task(StoredTask),
    /// A factory awaiting the admission-built child `Cx` (A2 path; the
    /// factory-receives-its-own-Cx discipline with the canonical task id).
    Factory(SpawnFactoryFn),
}

impl fmt::Debug for SpawnPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Task(_) => f.write_str("SpawnPayload::Task"),
            Self::Factory(_) => f.write_str("SpawnPayload::Factory"),
        }
    }
}

/// Adapter stored for factory spawns: first poll invokes the factory with
/// the admission-built `Cx` (worker thread, no runtime lock held), then
/// delegates every poll to the produced future.
pub struct LazyFactoryTask {
    factory: Option<(SpawnFactoryFn, crate::cx::Cx)>,
    inner: Option<SpawnBoxFuture>,
}

impl LazyFactoryTask {
    /// Pairs a factory with the admission-built child context.
    #[must_use]
    pub fn new(factory: SpawnFactoryFn, cx: crate::cx::Cx) -> Self {
        Self {
            factory: Some((factory, cx)),
            inner: None,
        }
    }
}

impl Future for LazyFactoryTask {
    type Output = Outcome<(), ()>;

    fn poll(mut self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.inner.is_none() {
            let Some((factory, cx)) = self.factory.take() else {
                return Poll::Ready(Outcome::Ok(()));
            };
            self.inner = Some(factory(cx));
        }
        self.inner
            .as_mut()
            .expect("inner future set above")
            .as_mut()
            .poll(task_cx)
    }
}

// === Owner-pinned local spawn lane (br-asupersync-i9y5wb / A2.2a) ===
//
// `spawn_local` futures are `!Send`, so they cannot ride the shared
// mailbox. But a local spawn is by definition issued ON the owner worker
// thread, so the factory never needs to cross threads: producers push
// onto a thread-local lane and the same worker drains it at the same
// dispatch point where it drains the shared mailbox. Admission still goes
// through `RuntimeState` (same record/region/counter discipline); only
// storage and scheduling differ (TLS `LocalStoredTask` + the worker's
// non-stealable local queue).

/// `!Send` mirror of [`SpawnBoxFuture`] for owner-pinned local spawns.
pub type LocalSpawnBoxFuture = Pin<Box<dyn Future<Output = Outcome<(), ()>>>>;

/// `!Send` mirror of [`SpawnFactoryFn`]: runs at first poll on the owner
/// worker, receiving the admission-built child context.
pub type LocalSpawnFactoryFn = Box<dyn FnOnce(crate::cx::Cx) -> LocalSpawnBoxFuture>;

/// `!Send` mirror of [`LazyFactoryTask`]: defers the user factory to the
/// first poll on the owner worker — never under the state lock.
pub struct LocalLazyFactoryTask {
    factory: Option<(LocalSpawnFactoryFn, crate::cx::Cx)>,
    inner: Option<LocalSpawnBoxFuture>,
}

impl LocalLazyFactoryTask {
    /// Pairs a local factory with the admission-built child context.
    #[must_use]
    pub fn new(factory: LocalSpawnFactoryFn, cx: crate::cx::Cx) -> Self {
        Self {
            factory: Some((factory, cx)),
            inner: None,
        }
    }
}

impl Future for LocalLazyFactoryTask {
    type Output = Outcome<(), ()>;

    fn poll(mut self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.inner.is_none() {
            let Some((factory, cx)) = self.factory.take() else {
                return Poll::Ready(Outcome::Ok(()));
            };
            self.inner = Some(factory(cx));
        }
        self.inner
            .as_mut()
            .expect("inner future set above")
            .as_mut()
            .poll(task_cx)
    }
}

/// A local spawn request parked on the owner thread's lane.
///
/// Mirrors [`SpawnRequestParts`] for the `!Send` lane: provisional id,
/// owning region, budget, the local factory, the cancel/error completion
/// slots, the pending-spawn credit, and the producer-shared admitted slot.
pub struct LocalSpawnRequest {
    /// Provisional task id (spawn-mailbox namespace).
    pub task_id: TaskId,
    /// Region that will own the task.
    pub region: RegionId,
    /// Budget the task starts with.
    pub budget: Budget,
    /// The local factory awaiting its admission-built Cx.
    pub factory: LocalSpawnFactoryFn,
    /// Completion slot for cancel-before-admission.
    pub on_unadmitted_cancel: Option<UnadmittedCancelFn>,
    /// Completion slot for non-cancellation admission failures.
    pub on_admission_error: Option<AdmissionErrorFn>,
    /// Pending-spawn credit on the owning region; released only after the
    /// task is visible in the region's task list (or on denial, last).
    pub pending_reservation: Option<crate::record::region::PendingSpawnReservation>,
    /// Producer-shared slot admission fills with the canonical identity.
    pub admitted_slot: Option<Arc<std::sync::OnceLock<AdmittedTask>>>,
}

impl LocalSpawnRequest {
    /// Resolves a request that will never be admitted (region cancelled
    /// before drain). Factory dropped uninvoked, cancel slot fired at most
    /// once, pending-spawn credit released last — the same contract as
    /// [`SpawnRequestParts::resolve_cancelled`].
    pub fn resolve_cancelled(self, reason: CancelReason) {
        let Self {
            factory,
            on_unadmitted_cancel,
            pending_reservation,
            admitted_slot,
            ..
        } = self;
        drop(factory);
        let requested = admitted_slot
            .as_ref()
            .and_then(retire_pending_cancel_rendezvous);
        if let Some(slot) = on_unadmitted_cancel {
            slot(strengthen_with_requested_reason(reason, requested.as_ref()));
        }
        drop(pending_reservation);
    }

    /// Resolves a request rejected by admission with `error`. Factory
    /// dropped uninvoked; the admission-error slot fires, falling back to
    /// the cancel slot so the caller-visible handle always resolves; the
    /// pending-spawn credit is released last — the same contract as
    /// [`SpawnRequestParts::resolve_failed`].
    pub fn resolve_failed(self, error: SpawnError) {
        let Self {
            factory,
            on_unadmitted_cancel,
            on_admission_error,
            pending_reservation,
            admitted_slot,
            ..
        } = self;
        drop(factory);
        let requested = admitted_slot
            .as_ref()
            .and_then(retire_pending_cancel_rendezvous);
        let requested_failure = requested_admission_failure_reason(&error, requested.as_ref());
        match (requested_failure, on_unadmitted_cancel, on_admission_error) {
            (Some(reason), Some(slot), _) => slot(reason),
            (_, _, Some(slot)) => slot(error),
            (None, Some(slot), None) => {
                let mut reason = CancelReason::user("spawn admission failed");
                reason.message = Some(error.to_string());
                slot(reason);
            }
            (_, None, None) => {}
        }
        drop(pending_reservation);
    }
}

thread_local! {
    /// Owner-thread lane of pending local spawn requests. Filled by
    /// `Cx::spawn_local[_in]` (worker threads only — producers fail closed
    /// off-worker), drained by the same worker in `next_task` alongside
    /// the shared mailbox.
    static LOCAL_SPAWN_LANE: std::cell::RefCell<std::collections::VecDeque<LocalSpawnRequest>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// Parks a local spawn request on the current thread's lane.
pub(crate) fn enqueue_local_spawn(request: LocalSpawnRequest) {
    LOCAL_SPAWN_LANE.with(|lane| lane.borrow_mut().push_back(request));
}

/// Returns true when the current thread has no parked local spawns.
pub(crate) fn local_spawn_lane_is_empty() -> bool {
    LOCAL_SPAWN_LANE.with(|lane| lane.borrow().is_empty())
}

/// Moves up to `max` parked local requests into `into`, returning the
/// number moved.
pub(crate) fn drain_local_spawn_lane(max: usize, into: &mut Vec<LocalSpawnRequest>) -> usize {
    LOCAL_SPAWN_LANE.with(|lane| {
        let mut lane = lane.borrow_mut();
        let take = lane.len().min(max);
        for _ in 0..take {
            let Some(request) = lane.pop_front() else {
                break;
            };
            into.push(request);
        }
        take
    })
}

/// A spawn request travelling through the [`SpawnMailbox`].
///
/// Carries everything admission needs to create the task record under the
/// state lock: the provisional task id, owning region, budget, optional
/// debug name, the erased future, and the completion slot used if the
/// request is cancelled before it is ever admitted.
///
/// Note: `crate::remote::SpawnRequest` is an unrelated wire-protocol type
/// for cross-node spawns; this struct is runtime-local.
pub struct SpawnRequest {
    task_id: TaskId,
    region: RegionId,
    budget: Budget,
    name: Option<Arc<str>>,
    payload: SpawnPayload,
    on_unadmitted_cancel: Option<UnadmittedCancelFn>,
    on_admission_error: Option<AdmissionErrorFn>,
    pending_reservation: Option<PendingSpawnReservation>,
    admitted_slot: Option<Arc<OnceLock<AdmittedTask>>>,
}

/// Destructured [`SpawnRequest`] handed to the admission path.
pub struct SpawnRequestParts {
    /// Provisional task id (spawn-mailbox namespace).
    pub task_id: TaskId,
    /// Region that will own the task.
    pub region: RegionId,
    /// Budget the task starts with.
    pub budget: Budget,
    /// Optional debug name.
    pub name: Option<Arc<str>>,
    /// The work to admit (pre-erased future, or factory awaiting its Cx).
    pub payload: SpawnPayload,
    /// Completion slot for cancel-before-admission.
    pub on_unadmitted_cancel: Option<UnadmittedCancelFn>,
    /// Completion slot for non-cancellation admission failures
    /// (quota/capacity); falls back to the cancel slot when absent.
    pub on_admission_error: Option<AdmissionErrorFn>,
    /// Pending-spawn credit on the owning region. Admission must drop this
    /// only *after* the task is in the region's task list
    /// (decrement-after-successor-visibility; see [`PendingSpawnCounter`]).
    pub pending_reservation: Option<PendingSpawnReservation>,
    /// Producer-shared slot admission fills with the canonical identity.
    pub admitted_slot: Option<Arc<OnceLock<AdmittedTask>>>,
}

impl SpawnRequest {
    /// Creates a new spawn request.
    ///
    /// `task_id` must come from a [`SpawnIdAllocator`] so the id is unique
    /// and identifiable as provisional ([`is_spawn_mailbox_id`]).
    #[must_use]
    pub fn new(task_id: TaskId, region: RegionId, budget: Budget, task: StoredTask) -> Self {
        Self::with_payload(task_id, region, budget, SpawnPayload::Task(task))
    }

    /// Creates a factory spawn request (br-asupersync-4h8lye / A2.1): the
    /// factory receives the admission-built child `Cx` at the task's first
    /// poll, on a worker, outside the runtime lock.
    #[must_use]
    pub fn new_with_factory(
        task_id: TaskId,
        region: RegionId,
        budget: Budget,
        factory: SpawnFactoryFn,
    ) -> Self {
        Self::with_payload(task_id, region, budget, SpawnPayload::Factory(factory))
    }

    fn with_payload(
        task_id: TaskId,
        region: RegionId,
        budget: Budget,
        payload: SpawnPayload,
    ) -> Self {
        Self {
            task_id,
            region,
            budget,
            name: None,
            payload,
            on_unadmitted_cancel: None,
            on_admission_error: None,
            pending_reservation: None,
            admitted_slot: None,
        }
    }

    /// Attaches a producer-shared slot that admission fills with the
    /// canonical task identity (arena id + Cx weak handle).
    #[must_use]
    pub fn with_admitted_slot(mut self, slot: Arc<OnceLock<AdmittedTask>>) -> Self {
        self.admitted_slot = Some(slot);
        self
    }

    /// Attaches a debug name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<Arc<str>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Attaches the cancel-before-admission completion slot.
    #[must_use]
    pub fn with_unadmitted_cancel(mut self, slot: UnadmittedCancelFn) -> Self {
        self.on_unadmitted_cancel = Some(slot);
        self
    }

    /// Attaches the admission-error completion slot
    /// (br-asupersync-dx-core-api-v2-u1z5hn.1.3).
    ///
    /// Fired when admission rejects the request with a non-cancellation
    /// error (for example `SpawnError::RegionAtCapacity`). When absent, the
    /// cancel slot receives a cancellation describing the failure instead,
    /// so the caller-visible handle always resolves.
    #[must_use]
    pub fn with_admission_error_slot(mut self, slot: AdmissionErrorFn) -> Self {
        self.on_admission_error = Some(slot);
        self
    }

    /// Attaches the region's pending-spawn credit
    /// (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
    ///
    /// The reservation must have been taken (incrementing the region's
    /// counter) *before* this request is enqueued, per the
    /// increment-before-visibility contract. It is released exactly once:
    /// by admission after the task joins the region's task list, or by
    /// [`Self::resolve_cancelled`] after the future is destroyed, or by
    /// dropping the request whole.
    #[must_use]
    pub fn with_pending_reservation(mut self, reservation: PendingSpawnReservation) -> Self {
        self.pending_reservation = Some(reservation);
        self
    }

    /// Returns the provisional task id.
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the owning region.
    #[inline]
    #[must_use]
    pub fn region(&self) -> RegionId {
        self.region
    }

    /// Returns the spawn budget.
    #[inline]
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// Returns the debug name, if any.
    #[inline]
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Destructures the request for admission.
    #[must_use]
    pub fn into_parts(self) -> SpawnRequestParts {
        SpawnRequestParts {
            task_id: self.task_id,
            region: self.region,
            budget: self.budget,
            name: self.name,
            payload: self.payload,
            on_unadmitted_cancel: self.on_unadmitted_cancel,
            on_admission_error: self.on_admission_error,
            pending_reservation: self.pending_reservation,
            admitted_slot: self.admitted_slot,
        }
    }

    /// Resolves a request that will never be admitted.
    ///
    /// Drops the stored future without polling it, invokes the
    /// cancel-before-admission slot (if any) exactly once with `reason`,
    /// and releases the region's pending-spawn credit **last** — the region
    /// must not observe its pending count reach zero until the future is
    /// destroyed and the caller-visible handle resolved
    /// (decrement-after-successor-visibility). This is the drain path for
    /// region-close racing enqueue: the public semantics are identical to
    /// spawning into a closing region today, just observed later.
    pub fn resolve_cancelled(self, reason: CancelReason) {
        self.into_parts().resolve_cancelled(reason);
    }
}

impl SpawnRequestParts {
    /// Resolves a destructured request that will never be admitted.
    ///
    /// Same contract as [`SpawnRequest::resolve_cancelled`]: future dropped
    /// unpolled, cancel slot fired at most once, pending-spawn credit
    /// released last.
    pub fn resolve_cancelled(self, reason: CancelReason) {
        let Self {
            payload,
            on_unadmitted_cancel,
            pending_reservation,
            admitted_slot,
            ..
        } = self;
        drop(payload);
        let requested = admitted_slot
            .as_ref()
            .and_then(retire_pending_cancel_rendezvous);
        if let Some(slot) = on_unadmitted_cancel {
            slot(strengthen_with_requested_reason(reason, requested.as_ref()));
        }
        drop(pending_reservation);
    }

    /// Resolves a destructured request rejected by admission with `error`.
    ///
    /// Future dropped unpolled; the admission-error slot fires with the
    /// error, falling back to the cancel slot (with a descriptive reason)
    /// when no error slot was attached so the caller-visible handle always
    /// resolves; the pending-spawn credit is released last.
    pub fn resolve_failed(self, error: SpawnError) {
        let Self {
            payload,
            on_unadmitted_cancel,
            on_admission_error,
            pending_reservation,
            admitted_slot,
            ..
        } = self;
        drop(payload);
        let requested = admitted_slot
            .as_ref()
            .and_then(retire_pending_cancel_rendezvous);
        let requested_failure = requested_admission_failure_reason(&error, requested.as_ref());
        match (requested_failure, on_unadmitted_cancel, on_admission_error) {
            (Some(reason), Some(slot), _) => slot(reason),
            (_, _, Some(slot)) => slot(error),
            (None, Some(slot), None) => slot(CancelReason::user("spawn admission failed")),
            (_, None, None) => {}
        }
        drop(pending_reservation);
    }
}

impl fmt::Debug for SpawnRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnRequest")
            .field("task_id", &self.task_id)
            .field("region", &self.region)
            .field("name", &self.name)
            .field("has_cancel_slot", &self.on_unadmitted_cancel.is_some())
            .field("has_reservation", &self.pending_reservation.is_some())
            .finish_non_exhaustive()
    }
}

/// Lock-free multi-producer intake queue for spawn requests.
///
/// Producers enqueue from any thread without holding `RuntimeState`; the
/// scheduler's admission path consumes. The underlying queue is MPMC-safe,
/// but the FIFO guarantees documented on [`Self::dequeue`] and
/// [`Self::dequeue_batch_into`] are stated for a single logical consumer;
/// with concurrent consumers each pop still returns the oldest *remaining*
/// request, but the global drain order interleaves across consumers. See
/// module docs for capacity, backpressure, and trace-ordering contracts.
pub struct SpawnMailbox {
    queue: GlobalFifoQueue<SpawnRequest>,
    ids: SpawnIdAllocator,
    trace: Option<TraceBufferHandle>,
    total_enqueued: AtomicU64,
    total_dequeued: AtomicU64,
}

impl SpawnMailbox {
    /// Creates a new mailbox with no trace buffer attached.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: GlobalFifoQueue::default(),
            ids: SpawnIdAllocator::new(),
            trace: None,
            total_enqueued: AtomicU64::new(0),
            total_dequeued: AtomicU64::new(0),
        }
    }

    /// Creates a new mailbox that emits `TaskSpawnEnqueued` trace events to
    /// `trace`.
    #[must_use]
    pub fn with_trace(trace: TraceBufferHandle) -> Self {
        Self {
            trace: Some(trace),
            ..Self::new()
        }
    }

    /// Allocates a provisional task id for a request bound for this mailbox.
    #[inline]
    #[must_use]
    pub fn allocate_task_id(&self) -> TaskId {
        self.ids.allocate()
    }

    /// Enqueues a spawn request.
    ///
    /// Never blocks and never drops (the queue is unbounded; see the module
    /// docs for the backpressure contract). Emits
    /// [`TraceEventKind::TaskSpawnEnqueued`] *before* publishing the request
    /// so the enqueue event is sequenced ahead of any admission-side event.
    ///
    /// `now` is the caller's current time (explicit, per the runtime-wide
    /// explicit-time idiom; exact under lab virtual time).
    pub fn enqueue(&self, request: SpawnRequest, now: Time) {
        if let Some(trace) = &self.trace {
            let task = request.task_id();
            let region = request.region();
            trace.record_event(|seq| TraceEvent::task_spawn_enqueued(seq, now, task, region));
        }
        // Count before publishing: a consumer can pop (and bump
        // `total_dequeued`) the instant the push lands, and observers rely
        // on `total_enqueued >= total_dequeued`.
        self.total_enqueued.fetch_add(1, Ordering::Relaxed);
        self.queue.push(request);
    }

    /// Dequeues the oldest spawn request, if any.
    #[must_use]
    pub fn dequeue(&self) -> Option<SpawnRequest> {
        let request = self.queue.pop();
        if request.is_some() {
            self.total_dequeued.fetch_add(1, Ordering::Relaxed);
        }
        request
    }

    /// Dequeues up to `max` requests into `out`, preserving FIFO order.
    /// Returns the number drained.
    pub fn dequeue_batch_into(&self, max: usize, out: &mut Vec<SpawnRequest>) -> usize {
        let drained = self.queue.pop_batch_into(max, out);
        if drained > 0 {
            self.total_dequeued
                .fetch_add(drained as u64, Ordering::Relaxed);
        }
        drained
    }

    /// Best-effort snapshot of the number of queued requests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true if the mailbox appears empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Total requests ever enqueued.
    #[must_use]
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued.load(Ordering::Relaxed)
    }

    /// Total requests ever dequeued.
    #[must_use]
    pub fn total_dequeued(&self) -> u64 {
        self.total_dequeued.load(Ordering::Relaxed)
    }
}

impl Default for SpawnMailbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Producer-facing spawn gateway (br-asupersync-hwjqyo / A2.2).
///
/// Bundles everything a lock-free producer needs: the runtime's spawn
/// mailbox, a wake notifier (closing the parked-fleet lost-wakeup race),
/// and a clock for enqueue timestamps. Stored in `RuntimeState` and cloned
/// into every `Cx` at construction so `Cx::spawn` works without the state
/// lock.
pub struct SpawnGateway {
    mailbox: Arc<SpawnMailbox>,
    notify: Arc<dyn Fn() + Send + Sync>,
    clock: Option<crate::time::TimerDriverHandle>,
    runtime_liveness: std::sync::Weak<()>,
}

impl SpawnGateway {
    /// Creates a gateway. `notify` wakes the consumer side after enqueue
    /// (a worker coordinator in production; a no-op in the lab, whose step
    /// loop drains synchronously).
    #[must_use]
    pub fn new(
        mailbox: Arc<SpawnMailbox>,
        notify: Arc<dyn Fn() + Send + Sync>,
        clock: Option<crate::time::TimerDriverHandle>,
        runtime_liveness: std::sync::Weak<()>,
    ) -> Self {
        Self {
            mailbox,
            notify,
            clock,
            runtime_liveness,
        }
    }

    /// The underlying mailbox (for id allocation and tests).
    #[must_use]
    pub fn mailbox(&self) -> &Arc<SpawnMailbox> {
        &self.mailbox
    }

    /// Returns true while the runtime that owns this gateway is still alive.
    #[must_use]
    pub fn is_runtime_available(&self) -> bool {
        self.liveness_guard().is_some()
    }

    /// Holds the runtime liveness token across producer-side publication.
    ///
    /// A successful upgrade means runtime drop must either let a worker admit
    /// the request or wait for this guard to leave scope before doing the
    /// final mailbox drain.
    #[must_use]
    pub fn liveness_guard(&self) -> Option<Arc<()>> {
        self.runtime_liveness.upgrade()
    }

    /// Enqueues a request stamped with the gateway clock and wakes the
    /// consumer.
    pub fn enqueue_and_notify(&self, request: SpawnRequest) -> Result<(), SpawnError> {
        let Some(_liveness_guard) = self.liveness_guard() else {
            request
                .into_parts()
                .resolve_failed(SpawnError::RuntimeUnavailable);
            return Err(SpawnError::RuntimeUnavailable);
        };
        let now = self
            .clock
            .as_ref()
            .map_or(Time::ZERO, crate::time::TimerDriverHandle::now);
        self.mailbox.enqueue(request, now);
        (self.notify)();
        Ok(())
    }
}

impl fmt::Debug for SpawnGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnGateway")
            .field("mailbox", &self.mailbox)
            .field("has_clock", &self.clock.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for SpawnMailbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnMailbox")
            .field("len", &self.len())
            .field("total_enqueued", &self.total_enqueued())
            .field("total_dequeued", &self.total_dequeued())
            .field("has_trace", &self.trace.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Outcome;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::thread;

    fn test_region() -> RegionId {
        RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    fn noop_task(id: TaskId) -> StoredTask {
        StoredTask::new_with_id(async { Outcome::Ok(()) }, id)
    }

    fn request(mailbox: &SpawnMailbox) -> SpawnRequest {
        let id = mailbox.allocate_task_id();
        SpawnRequest::new(id, test_region(), Budget::new(), noop_task(id))
    }

    #[test]
    fn fifo_order_single_thread() {
        let mailbox = SpawnMailbox::new();
        let mut expected = Vec::new();
        for _ in 0..100 {
            let req = request(&mailbox);
            expected.push(req.task_id());
            mailbox.enqueue(req, Time::ZERO);
        }
        let mut actual = Vec::new();
        while let Some(req) = mailbox.dequeue() {
            actual.push(req.task_id());
        }
        assert_eq!(actual, expected, "dequeue order must match enqueue order");
        assert!(mailbox.is_empty());
    }

    #[test]
    fn id_allocator_uniqueness_under_8_thread_contention() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 10_000;
        let allocator = Arc::new(SpawnIdAllocator::new());
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let allocator = Arc::clone(&allocator);
            handles.push(thread::spawn(move || {
                (0..PER_THREAD)
                    .map(|_| allocator.allocate().as_u64())
                    .collect::<Vec<u64>>()
            }));
        }
        let mut all = HashSet::new();
        for handle in handles {
            for id in handle.join().expect("allocator thread panicked") {
                assert!(all.insert(id), "duplicate provisional task id {id:#x}");
            }
        }
        assert_eq!(all.len(), THREADS * PER_THREAD);
    }

    #[test]
    fn provisional_ids_carry_namespace_tag() {
        let allocator = SpawnIdAllocator::new();
        for shard in 0..SPAWN_ID_SHARDS {
            let id = allocator.allocate_on(shard);
            assert!(
                is_spawn_mailbox_id(id),
                "provisional id missing namespace tag: {id:?}"
            );
        }
        let arena_id = TaskId::from_arena(ArenaIndex::new(5, 3));
        assert!(!is_spawn_mailbox_id(arena_id));
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn allocate_on_rejects_out_of_range_shard() {
        let allocator = SpawnIdAllocator::new();
        let _ = allocator.allocate_on(SPAWN_ID_SHARDS);
    }

    #[test]
    fn multi_thread_enqueue_preserves_per_producer_fifo() {
        const THREADS: usize = 8;
        const PER_THREAD: usize = 500;
        let mailbox = Arc::new(SpawnMailbox::new());
        let owners: Arc<Mutex<HashMap<u64, usize>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut handles = Vec::new();
        for producer in 0..THREADS {
            let mailbox = Arc::clone(&mailbox);
            let owners = Arc::clone(&owners);
            handles.push(thread::spawn(move || {
                let mut order = Vec::with_capacity(PER_THREAD);
                for _ in 0..PER_THREAD {
                    let id = mailbox.allocate_task_id();
                    owners.lock().unwrap().insert(id.as_u64(), producer);
                    order.push(id.as_u64());
                    let req = SpawnRequest::new(id, test_region(), Budget::new(), noop_task(id));
                    mailbox.enqueue(req, Time::ZERO);
                }
                order
            }));
        }
        let mut per_producer_expected: Vec<Vec<u64>> = Vec::new();
        for handle in handles {
            per_producer_expected.push(handle.join().expect("producer thread panicked"));
        }

        let mut dequeued = Vec::new();
        while let Some(req) = mailbox.dequeue() {
            dequeued.push(req.task_id().as_u64());
        }
        assert_eq!(dequeued.len(), THREADS * PER_THREAD);

        let owners = owners.lock().unwrap();
        let mut per_producer_actual: Vec<Vec<u64>> = vec![Vec::new(); THREADS];
        for id in dequeued {
            let producer = owners[&id];
            per_producer_actual[producer].push(id);
        }
        for producer in 0..THREADS {
            assert_eq!(
                per_producer_actual[producer], per_producer_expected[producer],
                "per-producer FIFO violated for producer {producer}"
            );
        }
    }

    #[test]
    fn unbounded_mailbox_accepts_burst_without_drop() {
        // AC: full-mailbox behavior is explicit — the queue is unbounded,
        // so there is no full state and no silent drop; every enqueued
        // request is observable and drainable.
        const BURST: usize = 10_000;
        let mailbox = SpawnMailbox::new();
        for _ in 0..BURST {
            mailbox.enqueue(request(&mailbox), Time::ZERO);
        }
        assert_eq!(mailbox.len(), BURST);
        assert_eq!(mailbox.total_enqueued(), BURST as u64);
        let mut drained = 0usize;
        while mailbox.dequeue().is_some() {
            drained += 1;
        }
        assert_eq!(drained, BURST);
        assert_eq!(mailbox.total_dequeued(), BURST as u64);
        assert!(mailbox.is_empty());
    }

    #[test]
    fn task_spawn_enqueued_trace_event_emitted() {
        let trace = TraceBufferHandle::new(16);
        let mailbox = SpawnMailbox::with_trace(trace.clone());
        let req = request(&mailbox);
        let task_id = req.task_id();
        let region = req.region();
        let now = Time::from_secs(5);
        mailbox.enqueue(req, now);

        let events = trace.snapshot();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.kind, TraceEventKind::TaskSpawnEnqueued);
        assert_eq!(event.time, now);
        match &event.data {
            TraceData::Task { task, region: r } => {
                assert_eq!(*task, task_id);
                assert_eq!(*r, region);
            }
            other => panic!("expected TraceData::Task, got {other:?}"),
        }
    }

    #[test]
    fn resolve_cancelled_invokes_completion_slot_once() {
        let mailbox = SpawnMailbox::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_reason: Arc<Mutex<Option<CancelReason>>> = Arc::new(Mutex::new(None));
        let calls_in_slot = Arc::clone(&calls);
        let seen_in_slot = Arc::clone(&seen_reason);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, test_region(), Budget::new(), noop_task(id))
            .with_unadmitted_cancel(Box::new(move |reason| {
                calls_in_slot.fetch_add(1, Ordering::SeqCst);
                *seen_in_slot.lock().unwrap() = Some(reason);
            }));
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("request queued");
        req.resolve_cancelled(CancelReason::user("region closed before admission"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let seen = seen_reason.lock().unwrap();
        let reason = seen.as_ref().expect("slot received reason");
        assert_eq!(
            reason.message,
            Some("region closed before admission".into())
        );
    }

    #[test]
    fn resolve_cancelled_without_slot_is_noop() {
        let mailbox = SpawnMailbox::new();
        let req = request(&mailbox);
        req.resolve_cancelled(CancelReason::user("no slot attached"));
    }

    #[test]
    fn dequeue_batch_into_drains_in_order() {
        let mailbox = SpawnMailbox::new();
        let mut expected = Vec::new();
        for _ in 0..10 {
            let req = request(&mailbox);
            expected.push(req.task_id());
            mailbox.enqueue(req, Time::ZERO);
        }
        let mut batch = Vec::new();
        assert_eq!(mailbox.dequeue_batch_into(4, &mut batch), 4);
        let batch_ids: Vec<TaskId> = batch.iter().map(SpawnRequest::task_id).collect();
        assert_eq!(batch_ids, expected[..4]);
        assert_eq!(mailbox.len(), 6);
        assert_eq!(mailbox.total_dequeued(), 4);
    }

    #[test]
    fn request_preserves_region_budget_and_name() {
        let mailbox = SpawnMailbox::new();
        let id = mailbox.allocate_task_id();
        let budget = Budget::new().with_poll_quota(123).with_priority(7);
        let req = SpawnRequest::new(id, test_region(), budget, noop_task(id)).with_name("worker-a");
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("request queued");
        assert_eq!(req.task_id(), id);
        assert_eq!(req.region(), test_region());
        assert_eq!(req.name(), Some("worker-a"));
        let parts = req.into_parts();
        assert_eq!(parts.budget, budget);
        assert!(parts.on_unadmitted_cancel.is_none());
        assert!(parts.pending_reservation.is_none());
    }

    // === br-asupersync-dx-core-api-v2-u1z5hn.1.2: pending-spawn accounting ===

    use crate::runtime::state::RuntimeState;
    use crate::types::CancelKind;

    /// Reservation travels inside the request; resolve_cancelled releases it
    /// strictly AFTER the cancel slot fires (decrement-after-successor-
    /// visibility): the slot must still observe the credit outstanding.
    #[test]
    fn resolve_cancelled_releases_reservation_after_slot() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::new();
        let id = mailbox.allocate_task_id();
        let count_seen_in_slot = Arc::new(AtomicUsize::new(usize::MAX));
        let seen = Arc::clone(&count_seen_in_slot);
        let handle_for_slot = Arc::clone(&handle);
        let req = SpawnRequest::new(id, root, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_reason| {
                seen.store(handle_for_slot.count() as usize, Ordering::SeqCst);
            }));
        assert_eq!(handle.count(), 1, "credit taken before enqueue");
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("request queued");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(
            count_seen_in_slot.load(Ordering::SeqCst),
            1,
            "cancel slot must observe the credit still outstanding"
        );
        assert_eq!(handle.count(), 0, "credit released after resolve");
    }

    /// Parent AC 2(a): region close with N un-admitted spawn requests still
    /// reaches quiescence — the close path refuses to finalize while credits
    /// are outstanding, every request resolves Cancelled exactly once, and
    /// the state machine then closes the region with zero leaks.
    #[test]
    fn region_close_with_unadmitted_requests_reaches_quiescence() {
        const N: usize = 5;
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("child region exists")
            .pending_spawn_handle();

        // Producer side (no state lock needed): reserve then enqueue.
        let mailbox = SpawnMailbox::new();
        let cancelled = Arc::new(AtomicUsize::new(0));
        for _ in 0..N {
            let id = mailbox.allocate_task_id();
            let cancelled = Arc::clone(&cancelled);
            let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
                .with_pending_reservation(handle.reserve())
                .with_unadmitted_cancel(Box::new(move |reason| {
                    assert_eq!(reason.kind, CancelKind::ParentCancelled);
                    cancelled.fetch_add(1, Ordering::SeqCst);
                }));
            mailbox.enqueue(req, Time::ZERO);
        }
        assert_eq!(handle.count(), N as u32);

        // Begin closing the region. With credits outstanding the state
        // machine must not finalize, complete close, or report quiescence.
        state
            .region(region)
            .expect("child region exists")
            .begin_close(None);
        state.advance_region_state(region);
        assert!(
            !state.can_region_finalize(region),
            "pending spawns must block finalization"
        );
        assert!(!state.can_region_complete_close(region));
        assert!(
            !state.is_quiescent(),
            "pending spawns must block runtime quiescence"
        );
        let mid_close_state = state.region(region).expect("region exists").state();
        assert!(
            !mid_close_state.is_terminal(),
            "region must not close while requests are pending, got {mid_close_state:?}"
        );

        // Drain: the admission loop's region-closed path resolves each
        // request Cancelled (admit-then-cancel semantics land with A1.3;
        // resolve_cancelled is the never-admitted variant with identical
        // public semantics).
        let mut drained = Vec::new();
        mailbox.dequeue_batch_into(N, &mut drained);
        assert_eq!(drained.len(), N);
        for req in drained {
            req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        }
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            N,
            "all N resolved Cancelled"
        );
        assert_eq!(handle.count(), 0);

        // The state machine can now finalize and close to quiescence. A
        // fully closed region is removed from the region table, so "gone"
        // is the strongest success signal; a still-present record must be
        // terminal.
        state.advance_region_state(region);
        assert!(
            state
                .region(region)
                .is_none_or(|r| r.state() == crate::record::region::RegionState::Closed),
            "region closes once pending spawns drain"
        );
        assert!(state.is_quiescent(), "runtime quiescent after drain");
    }

    /// AC3 race matrix, interleaving 1: credit visible before the request —
    /// a close-side check between increment and publish sees the credit and
    /// refuses, so the request cannot be stranded.
    #[test]
    fn race_matrix_close_check_between_increment_and_publish() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();
        let mailbox = SpawnMailbox::new();

        // Producer step 1: reserve (increment) — request NOT yet published.
        let reservation = handle.reserve();

        // Closer runs its full check here: must refuse.
        state
            .region(region)
            .expect("region exists")
            .begin_close(None);
        state.advance_region_state(region);
        assert!(!state.can_region_finalize(region));
        assert!(
            !state
                .region(region)
                .expect("region exists")
                .state()
                .is_terminal()
        );

        // Producer step 2: publish.
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(reservation);
        mailbox.enqueue(req, Time::ZERO);

        // Drain resolves the request; close then completes (a fully closed
        // region is removed from the table).
        let req = mailbox.dequeue().expect("published request");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        state.advance_region_state(region);
        assert!(
            state
                .region(region)
                .is_none_or(|r| r.state() == crate::record::region::RegionState::Closed),
            "region closes once the pending request drains"
        );
    }

    /// AC3 race matrix, interleaving 2: close completes first (count was 0),
    /// then a late producer reserves + enqueues. The accounting stays
    /// consistent: the late request resolves Cancelled, the counter returns
    /// to zero, and global quiescence recovers. (The closed region itself is
    /// already terminal — the admission loop's closed-region path is what
    /// cancels the request, exactly the spawn-into-closing-region semantics.)
    #[test]
    fn race_matrix_late_enqueue_after_close_resolves_cancelled() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();
        let mailbox = SpawnMailbox::new();

        // Close fully first. The region record is removed from the table
        // once fully closed; the counter Arc survives detached.
        state
            .region(region)
            .expect("region exists")
            .begin_close(None);
        state.advance_region_state(region);
        assert!(
            state
                .region(region)
                .is_none_or(|r| r.state() == crate::record::region::RegionState::Closed),
            "clean close completes with no credits outstanding"
        );

        // Late producer: reserve + publish against the closed region.
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_in_slot = Arc::clone(&cancelled);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_| {
                cancelled_in_slot.fetch_add(1, Ordering::SeqCst);
            }));
        mailbox.enqueue(req, Time::ZERO);
        // Post-removal window: once the closed region is recycled out of
        // the region table, a late detached credit is no longer visible to
        // the region-table-based quiescence predicate. Liveness for this
        // window is owned by the admission loop's closed-region fallback
        // (resolve Cancelled on next drain pass) and by A1.3 folding
        // mailbox emptiness into the scheduler's idle/quiescence decision.
        // What this slice guarantees: the request still resolves Cancelled
        // exactly once and the accounting balances.

        // Admission loop finds the region closed (gone) and cancels the
        // request.
        let req = mailbox.dequeue().expect("late request");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(handle.count(), 0);
        assert!(mailbox.is_empty());
        assert!(state.is_quiescent());
    }

    /// AC3 stress: concurrent producers (reserve + enqueue) race a drain
    /// loop. Invariant: no request is ever lost — every enqueued request is
    /// either resolved by the drain loop, and the counter balances to zero.
    #[test]
    fn race_stress_concurrent_producers_vs_drain() {
        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 250;
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();

        let mailbox = Arc::new(SpawnMailbox::new());
        let resolved = Arc::new(AtomicUsize::new(0));

        let mut producers = Vec::new();
        for _ in 0..PRODUCERS {
            let mailbox = Arc::clone(&mailbox);
            let handle = Arc::clone(&handle);
            producers.push(thread::spawn(move || {
                for _ in 0..PER_PRODUCER {
                    let id = mailbox.allocate_task_id();
                    let req = SpawnRequest::new(
                        id,
                        RegionId::from_arena(ArenaIndex::new(0, 1)),
                        Budget::new(),
                        noop_task(id),
                    )
                    .with_pending_reservation(handle.reserve());
                    mailbox.enqueue(req, Time::ZERO);
                }
            }));
        }

        // Drain loop racing the producers: keep resolving until all
        // producers are done AND the counter says nothing is outstanding.
        let drain_mailbox = Arc::clone(&mailbox);
        let drain_handle = Arc::clone(&handle);
        let drain_resolved = Arc::clone(&resolved);
        let drainer = thread::spawn(move || {
            loop {
                while let Some(req) = drain_mailbox.dequeue() {
                    req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
                    drain_resolved.fetch_add(1, Ordering::SeqCst);
                }
                if drain_resolved.load(Ordering::SeqCst) == PRODUCERS * PER_PRODUCER {
                    break;
                }
                std::thread::yield_now();
                // Increment-before-visibility: a nonzero counter with an
                // empty queue means a publish is in flight — keep spinning.
                if drain_handle.count() == 0
                    && drain_mailbox.is_empty()
                    && drain_resolved.load(Ordering::SeqCst) == PRODUCERS * PER_PRODUCER
                {
                    break;
                }
            }
        });

        for p in producers {
            p.join().expect("producer panicked");
        }
        drainer.join().expect("drainer panicked");

        assert_eq!(resolved.load(Ordering::SeqCst), PRODUCERS * PER_PRODUCER);
        assert_eq!(handle.count(), 0, "all credits balanced");
        assert_eq!(handle.underflow_count(), 0);
        assert!(mailbox.is_empty());
        assert!(state.is_quiescent());
    }

    // === br-asupersync-dx-core-api-v2-u1z5hn.1.3: admission ===

    use crate::record::region::RegionLimits;
    use crate::runtime::state::{SpawnAdmission, SpawnError};
    use crate::trace::event::TraceEventKind as Kind;

    #[test]
    fn requested_cancel_reason_centrally_overrides_admission_failure_callback() {
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let admitted = Arc::new(AdmittedTaskSlot::new());
        let (_result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<(), crate::runtime::JoinError>>();
        let handle =
            crate::runtime::TaskHandle::new_pending(provisional, result_rx, Arc::clone(&admitted));
        handle.abort_with_reason(CancelReason::race_loser());
        drop(handle);
        let seen_reason = Arc::new(Mutex::new(None));
        let seen_reason_slot = Arc::clone(&seen_reason);
        let admission_error_called = Arc::new(AtomicBool::new(false));
        let admission_error_slot = Arc::clone(&admission_error_called);

        SpawnRequest::new(
            provisional,
            test_region(),
            Budget::new(),
            noop_task(provisional),
        )
        .with_admitted_slot(admitted)
        .with_unadmitted_cancel(Box::new(move |reason| {
            *seen_reason_slot.lock().expect("reason lock") = Some(reason);
        }))
        .with_admission_error_slot(Box::new(move |_| {
            admission_error_slot.store(true, Ordering::SeqCst);
        }))
        .into_parts()
        .resolve_failed(SpawnError::RuntimeUnavailable);

        assert!(
            !admission_error_called.load(Ordering::SeqCst),
            "requested cancellation must route denial through the cancellation slot"
        );
        let reason = seen_reason
            .lock()
            .expect("reason lock")
            .clone()
            .expect("cancellation slot receives reason");
        assert!(reason.is_kind(CancelKind::RaceLost));
    }

    #[test]
    fn pending_cancel_rendezvous_retires_and_replaces_stale_pointer_key() {
        let slot: Arc<OnceLock<AdmittedTask>> = Arc::new(OnceLock::new());
        let reason = register_pending_cancel_rendezvous(&slot);
        assert_eq!(
            Arc::strong_count(&reason),
            2,
            "registry owns the reason until admission or denial retires it"
        );
        let retrieved = register_pending_cancel_rendezvous(&slot);
        assert!(Arc::ptr_eq(&reason, &retrieved));
        let retired = retire_pending_cancel_rendezvous(&slot).expect("rendezvous retires");
        assert!(Arc::ptr_eq(&reason, &retired));
        assert!(retire_pending_cancel_rendezvous(&slot).is_none());

        // Deterministically model allocator address reuse by placing an
        // expired slot under the live replacement slot's pointer key.
        let stale_slot: Arc<OnceLock<AdmittedTask>> = Arc::new(OnceLock::new());
        let stale_slot = Arc::downgrade(&stale_slot);
        let stale_reason = Arc::new(RwLock::new(Some(CancelReason::timeout())));
        let replacement: Arc<OnceLock<AdmittedTask>> = Arc::new(OnceLock::new());
        let replacement_key = admitted_slot_key(&replacement);
        {
            let mut entries = pending_cancel_registry().lock();
            entries.insert(
                replacement_key,
                PendingCancelRendezvous {
                    slot: stale_slot,
                    reason: Arc::clone(&stale_reason),
                },
            );
        }

        let replacement_reason = register_pending_cancel_rendezvous(&replacement);
        assert!(!Arc::ptr_eq(&replacement_reason, &stale_reason));
        let retired = retire_pending_cancel_rendezvous(&replacement).expect("replacement retires");
        assert!(Arc::ptr_eq(&replacement_reason, &retired));
        assert!(
            !pending_cancel_registry()
                .lock()
                .contains_key(&replacement_key)
        );
    }

    #[test]
    fn pre_admission_abort_survives_handle_drop_until_successful_admission() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let admitted: Arc<OnceLock<AdmittedTask>> = Arc::new(OnceLock::new());
        let (_result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<(), crate::runtime::JoinError>>();
        let handle =
            crate::runtime::TaskHandle::new_pending(provisional, result_rx, Arc::clone(&admitted));
        handle.abort_with_reason(CancelReason::race_loser());
        drop(handle);

        let parts = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_admitted_slot(Arc::clone(&admitted))
            .into_parts();
        let SpawnAdmission::Admitted { .. } = state.admit_spawn_request(parts) else {
            panic!("expected admission to succeed");
        };

        let admitted_task = admitted.get().expect("admission publishes task identity");
        let inner = admitted_task
            .cx_inner
            .upgrade()
            .expect("admitted task context remains live");
        let guard = inner.read();
        assert!(
            guard.cancel_requested,
            "admission replays the pending abort"
        );
        assert!(
            guard
                .cancel_reason
                .as_ref()
                .is_some_and(|reason| reason.is_kind(CancelKind::RaceLost)),
            "replayed abort preserves RaceLost attribution"
        );
        drop(guard);
        assert!(
            retire_pending_cancel_rendezvous(&admitted).is_none(),
            "successful admission retires the rendezvous"
        );
    }

    /// Successful admission: provisional id replaced by a canonical arena
    /// id, task joins the region's task list, future stored, credit
    /// released, Spawn + TaskAdmitted trace events emitted in order after
    /// the enqueue event.
    #[test]
    fn admit_spawn_request_success_end_to_end() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let handle = state
            .region(root)
            .expect("root region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::with_trace(state.trace_handle());
        let provisional = mailbox.allocate_task_id();
        let req = SpawnRequest::new(provisional, root, Budget::new(), noop_task(provisional))
            .with_pending_reservation(handle.reserve());
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let admission = state.admit_spawn_request(parts);
        let SpawnAdmission::Admitted { task_id, priority } = admission else {
            panic!("expected admission to succeed");
        };
        assert!(
            !is_spawn_mailbox_id(task_id),
            "admitted id must be a canonical arena id, got {task_id:?}"
        );
        assert_eq!(priority, Budget::new().priority);
        assert_eq!(handle.count(), 0, "credit released after admission");
        assert_eq!(
            state.region(root).expect("root exists").task_count(),
            1,
            "task joined the region"
        );
        assert!(
            state.get_stored_future(task_id).is_some(),
            "future stored under the arena id"
        );

        let kinds: Vec<Kind> = state
            .trace_handle()
            .snapshot()
            .iter()
            .map(|e| e.kind)
            .filter(|k| {
                matches!(
                    k,
                    Kind::TaskSpawnEnqueued | Kind::Spawn | Kind::TaskAdmitted
                )
            })
            .collect();
        assert_eq!(
            kinds,
            vec![Kind::TaskSpawnEnqueued, Kind::Spawn, Kind::TaskAdmitted],
            "admission trace ordering"
        );
    }

    /// RegionClosed denial: admission returns the parts; resolving them
    /// cancelled fires the cancel slot and balances the credit.
    #[test]
    fn admit_spawn_request_region_closed_resolves_cancelled() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::new();
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_slot = Arc::clone(&cancelled);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_unadmitted_cancel(Box::new(move |_| {
                cancelled_slot.fetch_add(1, Ordering::SeqCst);
            }));
        mailbox.enqueue(req, Time::ZERO);

        // Close begins; the region can no longer accept work.
        state
            .region(region)
            .expect("region exists")
            .begin_close(None);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let SpawnAdmission::Denied { parts, error } = state.admit_spawn_request(parts) else {
            panic!("expected denial for closing region");
        };
        assert!(matches!(error, SpawnError::RegionClosed(r) if r == region));
        // Caller resolves after releasing the (conceptual) lock.
        parts.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert_eq!(handle.count(), 0);
        // The denied task never entered the region.
        assert_eq!(state.region(region).expect("region exists").task_count(), 0);
    }

    /// Quota denial: region at capacity routes through resolve_failed and
    /// the admission-error slot receives SpawnError::RegionAtCapacity.
    #[test]
    fn admit_spawn_request_quota_resolves_failed() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let region = state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        state
            .region(region)
            .expect("region exists")
            .set_limits(RegionLimits {
                max_tasks: Some(0),
                ..RegionLimits::UNLIMITED
            });
        let handle = state
            .region(region)
            .expect("region exists")
            .pending_spawn_handle();

        let mailbox = SpawnMailbox::new();
        let failed: Arc<Mutex<Option<SpawnError>>> = Arc::new(Mutex::new(None));
        let failed_slot = Arc::clone(&failed);
        let id = mailbox.allocate_task_id();
        let req = SpawnRequest::new(id, region, Budget::new(), noop_task(id))
            .with_pending_reservation(handle.reserve())
            .with_admission_error_slot(Box::new(move |err| {
                *failed_slot.lock().unwrap() = Some(err);
            }));
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let SpawnAdmission::Denied { parts, error } = state.admit_spawn_request(parts) else {
            panic!("expected quota denial");
        };
        assert!(matches!(error, SpawnError::RegionAtCapacity { .. }));
        parts.resolve_failed(error);
        let seen = failed.lock().unwrap();
        assert!(
            matches!(
                seen.as_ref(),
                Some(SpawnError::RegionAtCapacity { limit: 0, .. })
            ),
            "error slot received the capacity error, got {seen:?}"
        );
        assert_eq!(handle.count(), 0);
    }

    /// Parent AC 2(b): admission order is mailbox FIFO and replay-stable —
    /// two identical runs produce identical trace fingerprints (event kind
    /// sequence + task/region ids) and identical arena id assignment.
    #[test]
    fn admission_order_deterministic_across_identical_runs() {
        fn run_once() -> Vec<(Kind, u64, u64)> {
            const K: usize = 8;
            let mut state = RuntimeState::new();
            let root = state.create_root_region(Budget::INFINITE);
            let handle = state
                .region(root)
                .expect("root exists")
                .pending_spawn_handle();
            let mailbox = SpawnMailbox::with_trace(state.trace_handle());
            for _ in 0..K {
                let id = mailbox.allocate_task_id();
                let req = SpawnRequest::new(id, root, Budget::new(), noop_task(id))
                    .with_pending_reservation(handle.reserve());
                mailbox.enqueue(req, Time::ZERO);
            }
            // Drain in batches to exercise the batch path too.
            let mut batch = Vec::new();
            while mailbox.dequeue_batch_into(3, &mut batch) > 0 {}
            for req in batch {
                match state.admit_spawn_request(req.into_parts()) {
                    SpawnAdmission::Admitted { .. } => {}
                    SpawnAdmission::Denied { .. } => panic!("unexpected denial"),
                }
            }
            state
                .trace_handle()
                .snapshot()
                .iter()
                .filter(|e| {
                    matches!(
                        e.kind,
                        Kind::TaskSpawnEnqueued | Kind::Spawn | Kind::TaskAdmitted
                    )
                })
                .map(|e| {
                    let (task, region) = match &e.data {
                        crate::trace::event::TraceData::Task { task, region } => {
                            (task.as_u64(), region.as_u64())
                        }
                        other => panic!("unexpected trace data {other:?}"),
                    };
                    (e.kind, task, region)
                })
                .collect()
        }

        let first = run_once();
        let second = run_once();
        assert_eq!(
            first.len(),
            8 * 3,
            "K enqueue + K spawn + K admitted events"
        );
        assert_eq!(first, second, "replay fingerprint must be identical");
    }

    /// End-to-end: a real multi-worker runtime in mailbox admission mode
    /// spawns futures through the lock-free intake, workers admit them at
    /// dispatch time, and every join handle resolves with the task's value.
    /// Also exercises the parked-fleet wakeup (notify_spawn_enqueued) since
    /// workers may be idle when the producer enqueues.
    #[test]
    fn mailbox_mode_runtime_spawns_and_joins_end_to_end() {
        const TASKS: usize = 50;
        let runtime = crate::runtime::builder::RuntimeBuilder::new()
            .worker_threads(2)
            .spawn_admission(crate::runtime::config::SpawnAdmissionMode::Mailbox)
            .build()
            .expect("build mailbox-mode runtime");
        let handle = runtime.handle();

        let counter = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for i in 0..TASKS {
            let counter = Arc::clone(&counter);
            joins.push(handle.spawn(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                i
            }));
        }
        for (i, join) in joins.into_iter().enumerate() {
            let value = runtime.block_on(join);
            assert_eq!(value, i, "join handle resolves with the task value");
        }
        assert_eq!(counter.load(Ordering::SeqCst), TASKS);
    }

    // === br-asupersync-4h8lye (A2.1): factory spawns + lab drain ===

    use crate::lab::{LabConfig, LabRuntime};

    fn factory_request(
        mailbox: &SpawnMailbox,
        region: RegionId,
        ran: &Arc<AtomicUsize>,
        completed: &Arc<AtomicUsize>,
    ) -> SpawnRequest {
        let id = mailbox.allocate_task_id();
        let ran = Arc::clone(ran);
        let completed = Arc::clone(completed);
        SpawnRequest::new_with_factory(
            id,
            region,
            Budget::new(),
            Box::new(move |cx: crate::cx::Cx| {
                ran.fetch_add(1, Ordering::SeqCst);
                assert!(
                    !is_spawn_mailbox_id(cx.task_id()),
                    "factory must receive the admission-built Cx with the \
                     canonical arena id, got {:?}",
                    cx.task_id()
                );
                Box::pin(async move {
                    completed.fetch_add(1, Ordering::SeqCst);
                    Outcome::Ok(())
                })
            }),
        )
    }

    /// The factory runs at the task's FIRST POLL on the lab step loop —
    /// not during admission under the state lock.
    #[test]
    fn factory_runs_at_first_poll_not_at_admission() {
        let mut lab = LabRuntime::new(LabConfig::new(7));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let handle = lab
            .state
            .region(root)
            .expect("root exists")
            .pending_spawn_handle();
        let mailbox = lab.spawn_mailbox();

        let ran = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let req = factory_request(&mailbox, root, &ran, &completed)
            .with_pending_reservation(handle.reserve());
        mailbox.enqueue(req, Time::ZERO);

        // Admit WITHOUT polling: drain directly against state.
        let parts = mailbox.dequeue().expect("queued").into_parts();
        let admission = lab.state.admit_spawn_request(parts);
        let crate::runtime::state::SpawnAdmission::Admitted { task_id, priority } = admission
        else {
            panic!("expected admission");
        };
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "factory must NOT run during admission"
        );

        // Schedule + run: factory fires on first poll, future completes.
        lab.scheduler.lock().schedule(task_id, priority);
        lab.run_until_quiescent();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "factory ran exactly once");
        assert_eq!(completed.load(Ordering::SeqCst), 1, "task completed");
    }

    /// Admission fills the producer-shared admitted slot with the arena id
    /// and a live Cx weak handle.
    #[test]
    fn admitted_slot_filled_with_canonical_identity() {
        let mut state = RuntimeState::new();
        let root = state.create_root_region(Budget::INFINITE);
        let mailbox = SpawnMailbox::new();
        let slot: Arc<OnceLock<AdmittedTask>> = Arc::new(OnceLock::new());
        let ran = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let req =
            factory_request(&mailbox, root, &ran, &completed).with_admitted_slot(Arc::clone(&slot));
        let provisional = req.task_id();
        mailbox.enqueue(req, Time::ZERO);

        let parts = mailbox.dequeue().expect("queued").into_parts();
        let crate::runtime::state::SpawnAdmission::Admitted { task_id, .. } =
            state.admit_spawn_request(parts)
        else {
            panic!("expected admission");
        };
        let admitted = slot.get().expect("slot filled at admission");
        assert_eq!(admitted.task_id, task_id);
        assert_ne!(
            admitted.task_id, provisional,
            "arena id replaces provisional"
        );
        assert!(
            admitted.cx_inner.upgrade().is_some(),
            "cx weak handle is live while the task exists"
        );
    }

    /// Lab step loop drains the mailbox FIFO and runs factory tasks to
    /// completion; two identical runs produce identical admitted ids.
    #[test]
    fn lab_step_drains_factory_spawns_deterministically() {
        fn run_once() -> (usize, Vec<u64>) {
            const K: usize = 6;
            let mut lab = LabRuntime::new(LabConfig::new(11));
            let root = lab.state.create_root_region(Budget::INFINITE);
            let handle = lab
                .state
                .region(root)
                .expect("root exists")
                .pending_spawn_handle();
            let mailbox = lab.spawn_mailbox();
            let ran = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let mut slots = Vec::new();
            for _ in 0..K {
                let slot: Arc<OnceLock<AdmittedTask>> = Arc::new(OnceLock::new());
                let req = factory_request(&mailbox, root, &ran, &completed)
                    .with_pending_reservation(handle.reserve())
                    .with_admitted_slot(Arc::clone(&slot));
                mailbox.enqueue(req, Time::ZERO);
                slots.push(slot);
            }
            // The mailbox gates quiescence via pending credits, so a plain
            // run_until_quiescent drives admission + execution end to end.
            lab.run_until_quiescent();
            assert_eq!(completed.load(Ordering::SeqCst), K);
            assert_eq!(handle.count(), 0, "credits balanced after admission");
            let ids = slots
                .iter()
                .map(|s| s.get().expect("admitted").task_id.as_u64())
                .collect();
            (ran.load(Ordering::SeqCst), ids)
        }

        let (ran_a, ids_a) = run_once();
        let (ran_b, ids_b) = run_once();
        assert_eq!(ran_a, 6);
        assert_eq!(ran_b, 6);
        assert_eq!(ids_a, ids_b, "admitted arena ids replay-identical");
    }

    /// Cancel-before-admission with a factory payload: the factory is
    /// dropped uninvoked and the cancel slot fires.
    #[test]
    fn factory_request_cancelled_before_admission_never_runs() {
        let mailbox = SpawnMailbox::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_slot = Arc::clone(&cancelled);
        let req = factory_request(&mailbox, test_region(), &ran, &completed)
            .with_unadmitted_cancel(Box::new(move |_| {
                cancelled_slot.fetch_add(1, Ordering::SeqCst);
            }));
        mailbox.enqueue(req, Time::ZERO);

        let req = mailbox.dequeue().expect("queued");
        req.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "factory never invoked");
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    }

    // === br-asupersync-hwjqyo (A2.2): Cx::spawn public surface ===

    /// Builds a lab + a live parent task Cx (gateway/counter attached at
    /// Cx construction) and returns both plus the parent task id.
    fn lab_with_parent_cx() -> (LabRuntime, crate::cx::Cx, RegionId) {
        let mut lab = LabRuntime::new(LabConfig::new(21));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let system_cx = lab.state.create_system_cx();
        let (parent_tid, _handle, parent_cx, _result_tx) = lab
            .state
            .create_task_infrastructure::<()>(&system_cx, root, Budget::new(), false)
            .expect("parent task");
        lab.state.store_spawned_task(
            parent_tid,
            StoredTask::new_with_id(async { Outcome::Ok(()) }, parent_tid),
        );
        lab.scheduler.lock().schedule(parent_tid, 0);
        (lab, parent_cx, root)
    }

    /// Cx::spawn end to end under the lab: no RuntimeState at the call
    /// site, factory child runs, handle exposes the canonical arena id.
    #[test]
    fn cx_spawn_runs_child_without_runtime_state() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_in_child = Arc::clone(&counter);
        let handle = parent_cx
            .spawn(move |_child| async move {
                counter_in_child.fetch_add(1, Ordering::SeqCst);
                42usize
            })
            .expect("cx.spawn");
        assert!(
            is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        lab.run_until_quiescent();
        assert_eq!(counter.load(Ordering::SeqCst), 1, "child ran");
        assert!(
            !is_spawn_mailbox_id(handle.task_id()),
            "post-admission handle reports the arena id"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// The shared `Cx::spawn` / `Cx::spawn_in` gateway path must emit the
    /// same enqueue trace event as the direct mailbox and local-spawn paths.
    #[test]
    fn cx_spawn_gateway_paths_emit_task_spawn_enqueued_trace_events() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let trace = lab.state.trace_handle();

        let root_handle = parent_cx
            .spawn(|_child| async move { 11usize })
            .expect("cx.spawn");
        let root_provisional = root_handle.task_id();

        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let scoped_handle = parent_cx
            .spawn_in(&scope, |_child| async move { 22usize })
            .expect("cx.spawn_in");
        let scoped_provisional = scoped_handle.task_id();

        let events = trace.snapshot();
        for (expected_task, expected_region) in
            [(root_provisional, root), (scoped_provisional, child_region)]
        {
            let matches = events
                .iter()
                .filter(|event| {
                    event.kind == TraceEventKind::TaskSpawnEnqueued
                        && matches!(
                            &event.data,
                            TraceData::Task { task, region }
                                if *task == expected_task && *region == expected_region
                        )
                })
                .count();
            assert_eq!(
                matches, 1,
                "gateway enqueue for {expected_task:?} in {expected_region:?} must be traced exactly once"
            );
        }

        lab.run_until_quiescent();
    }

    /// Deep child: the factory-built child Cx carries the gateway and its
    /// region counter, so it can spawn a grandchild the same way.
    #[test]
    fn cx_spawn_from_factory_child_spawns_grandchild() {
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let grandchild_ran = Arc::new(AtomicUsize::new(0));
        let flag = Arc::clone(&grandchild_ran);
        let _child_handle = parent_cx
            .spawn(move |child| async move {
                let flag_inner = Arc::clone(&flag);
                child
                    .spawn(move |_grandchild| async move {
                        flag_inner.fetch_add(1, Ordering::SeqCst);
                    })
                    .expect("grandchild spawn from factory-built cx");
            })
            .expect("child spawn");
        lab.run_until_quiescent();
        assert_eq!(grandchild_ran.load(Ordering::SeqCst), 1);
    }

    /// A Cx built without runtime wiring (test-internals constructor) has
    /// no gateway: spawn errs with RuntimeUnavailable and never panics.
    #[test]
    fn cx_spawn_without_gateway_returns_runtime_unavailable() {
        let cx: crate::cx::Cx = crate::cx::Cx::new(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 1),
            Budget::new(),
        );
        let result = cx.spawn(|_child| async {});
        assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
    }

    /// A retained runtime-wired Cx must fail closed after its runtime drops:
    /// no panic, no orphaned mailbox enqueue, no pending-spawn credit.
    #[test]
    fn cx_spawn_after_runtime_drop_returns_runtime_unavailable() {
        let runtime = crate::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        let parent_cx = runtime.block_on(
            runtime
                .handle()
                .spawn(async { crate::cx::Cx::current().expect("runtime task Cx") }),
        );
        let gateway = parent_cx
            .spawn_gateway_handle()
            .expect("runtime task Cx carries spawn gateway");
        let total_enqueued = gateway.mailbox().total_enqueued();

        drop(runtime);

        assert!(
            !gateway.is_runtime_available(),
            "dropping the runtime must expire the gateway liveness token"
        );
        let result = parent_cx.spawn(|_child| async { 7usize });
        assert!(matches!(result, Err(SpawnError::RuntimeUnavailable)));
        assert_eq!(
            gateway.mailbox().total_enqueued(),
            total_enqueued,
            "post-drop Cx::spawn must not publish orphaned mailbox work"
        );
    }

    #[test]
    fn spawn_drop_race_liveness_guard_extends_publication_window() {
        use crate::runtime::task_handle::JoinError;

        let mailbox = Arc::new(SpawnMailbox::new());
        let liveness = Arc::new(());
        let gateway = SpawnGateway::new(
            Arc::clone(&mailbox),
            Arc::new(|| {}),
            None,
            Arc::downgrade(&liveness),
        );
        let guard = gateway
            .liveness_guard()
            .expect("runtime liveness should upgrade before drop starts");
        drop(liveness);

        assert!(
            gateway.is_runtime_available(),
            "a held producer guard keeps the runtime publication window visible"
        );

        let (tx, mut rx) = crate::channel::oneshot::channel::<Result<(), JoinError>>();
        let request = request(&mailbox).with_admission_error_slot(Box::new(move |error| {
            let mut reason = CancelReason::user("spawn admission failed");
            reason.message = Some(error.to_string());
            let _ = tx.send_blocking(Err(JoinError::Cancelled(reason)));
        }));
        gateway
            .enqueue_and_notify(request)
            .expect("held liveness guard should permit publication");
        drop(guard);

        assert!(
            !gateway.is_runtime_available(),
            "dropping the last producer guard expires the gateway"
        );
        let queued = mailbox.dequeue().expect("request was published");
        queued
            .into_parts()
            .resolve_failed(SpawnError::RuntimeUnavailable);
        assert!(
            matches!(rx.try_recv(), Ok(Err(JoinError::Cancelled(_)))),
            "final mailbox drain must resolve the caller-visible handle"
        );
    }

    #[test]
    fn spawn_drop_race_cx_spawn_resolves_returned_handles() {
        use crate::runtime::task_handle::JoinError;

        let runtime = crate::runtime::RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("runtime build");
        let parent_cx = runtime.block_on(
            runtime
                .handle()
                .spawn(async { crate::cx::Cx::current().expect("runtime task Cx") }),
        );
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let producer_stop = Arc::clone(&stop);
        let producer_cx = parent_cx.clone();

        let producer = thread::spawn(move || {
            let mut handles = Vec::new();
            let mut unavailable_count = 0usize;
            for _ in 0..64 {
                match producer_cx.spawn(|_child| async move { 1usize }) {
                    Ok(handle) => handles.push(handle),
                    Err(SpawnError::RuntimeUnavailable) => {
                        unavailable_count += 1;
                        break;
                    }
                    Err(error) => panic!("unexpected spawn error before runtime drop: {error:?}"),
                }
            }
            ready_tx
                .send(())
                .expect("test coordinator should receive producer ready");
            while !producer_stop.load(Ordering::Acquire) {
                match producer_cx.spawn(|_child| async move { 1usize }) {
                    Ok(handle) => handles.push(handle),
                    Err(SpawnError::RuntimeUnavailable) => {
                        unavailable_count += 1;
                        break;
                    }
                    Err(error) => panic!("unexpected spawn error during runtime drop: {error:?}"),
                }
                thread::yield_now();
            }
            (handles, unavailable_count)
        });

        ready_rx
            .recv()
            .expect("producer should enter the spawn loop");
        drop(runtime);
        stop.store(true, Ordering::Release);
        let (mut handles, unavailable_count) =
            producer.join().expect("producer thread should not panic");
        assert!(
            !handles.is_empty(),
            "test must exercise at least one returned Cx::spawn handle"
        );

        let mut pending = Vec::new();
        for handle in &mut handles {
            match handle.try_join() {
                Ok(Some(_)) | Err(JoinError::Cancelled(_)) => {}
                Ok(None) => pending.push(handle.task_id()),
                Err(other) => panic!("unexpected join result after runtime drop: {other:?}"),
            }
        }
        assert!(
            pending.is_empty(),
            "spawn handles returned around runtime drop must not hang pending: {pending:?}"
        );
        assert!(
            matches!(
                parent_cx.spawn(|_child| async move { 2usize }),
                Err(SpawnError::RuntimeUnavailable)
            ),
            "retained Cx fails closed after runtime drop"
        );
        assert!(
            unavailable_count <= 1,
            "producer stops at the first observed RuntimeUnavailable"
        );
    }

    /// Spawn into a closing region: admission denies, the cancel slot
    /// resolves the handle, and joining yields JoinError::Cancelled.
    #[test]
    fn cx_spawn_into_closing_region_join_resolves_cancelled() {
        use std::task::{Context, Poll, Waker};

        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        // Begin closing the root region BEFORE the spawn is admitted.
        lab.state.region(root).expect("root").begin_close(None);

        let mut handle = parent_cx
            .spawn(|_child| async move { 7usize })
            .expect("enqueue still succeeds; denial resolves via the handle");

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let mut join = handle.join(&parent_cx);
        let mut result = None;
        for _ in 0..200 {
            match Pin::new(&mut join).poll(&mut poll_cx) {
                Poll::Ready(r) => {
                    result = Some(r);
                    break;
                }
                Poll::Pending => lab.step_for_test(),
            }
        }
        drop(join);
        let result = result.expect("join resolved");
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Cancelled(_))
            ),
            "join must resolve Cancelled for a denied spawn, got {result:?}"
        );
    }

    // === br-asupersync-hwjqyo (A2.2): Cx::spawn_in scope-targeting surface ===

    /// `Cx::spawn_in` applies the SCOPE's planned capability budget to the
    /// admitted child — not the calling cx's — matching the legacy
    /// state-threaded scope contract (br-asupersync-4onmas).
    #[test]
    fn cx_spawn_in_applies_scope_capability_budget() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let planned = crate::types::CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_cpu_units(64)
            .with_artifact_bytes(128);
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new_with_capability_budget(root, Budget::INFINITE, planned)
                .with_pending_spawn_counter(
                    lab.state
                        .region(root)
                        .map(crate::record::RegionRecord::pending_spawn_handle),
                );
        let observed: Arc<std::sync::Mutex<Option<crate::types::CapabilityBudget>>> =
            Arc::new(std::sync::Mutex::new(None));
        let observed_in_child = Arc::clone(&observed);
        parent_cx
            .spawn_in(&scope, move |child| async move {
                *observed_in_child
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(child.capability_budget());
            })
            .expect("cx.spawn_in");
        lab.run_until_quiescent();
        let observed = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("child observed a capability budget");
        assert_eq!(
            observed, planned,
            "child must carry the scope's planned capability budget"
        );
    }

    /// `Cx::spawn_in` routes the pending reservation to the scope's region
    /// counter and the admitted child runs there, without `RuntimeState` at
    /// the call site.
    #[test]
    fn cx_spawn_in_targets_scope_region_counter() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_child = Arc::clone(&ran);
        let handle = parent_cx
            .spawn_in(&scope, move |_child| async move {
                ran_in_child.fetch_add(1, Ordering::SeqCst);
            })
            .expect("cx.spawn_in");
        assert!(
            is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            1,
            "reservation lands on the scope's region"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "caller's region carries no reservation for a scope-targeted spawn"
        );
        lab.run_until_quiescent();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "child ran");
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// A bare same-region scope (no wiring) falls back to the calling
    /// context's counter, because the counter is per-region.
    #[test]
    fn cx_spawn_in_same_region_bare_scope_falls_back() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let scope: crate::cx::Scope<'static> = crate::cx::Scope::new(root, Budget::INFINITE);
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_child = Arc::clone(&ran);
        parent_cx
            .spawn_in(&scope, move |_child| async move {
                ran_in_child.fetch_add(1, Ordering::SeqCst);
            })
            .expect("same-region fallback uses the cx counter");
        lab.run_until_quiescent();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "child ran");
    }

    /// A counter-less scope for a DIFFERENT region fails closed with
    /// `RuntimeUnavailable`: the calling context's counter must not be
    /// borrowed cross-region.
    #[test]
    fn cx_spawn_in_foreign_bare_scope_runtime_unavailable() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE);
        let result = parent_cx.spawn_in(&scope, |_child| async move {});
        assert!(
            matches!(
                result,
                Err(crate::runtime::state::SpawnError::RuntimeUnavailable)
            ),
            "cross-region spawn without scope wiring must fail closed"
        );
    }

    /// `Cx::scope()` carries the region's pending-spawn counter, so the
    /// returned scope works with `spawn_in` even when handed to another
    /// task whose Cx targets a different region.
    #[test]
    fn cx_scope_carries_pending_spawn_counter() {
        let (_lab, parent_cx, _root) = lab_with_parent_cx();
        assert!(
            parent_cx.scope().pending_spawn_counter_handle().is_some(),
            "wired Cx must propagate its region counter into Cx::scope()"
        );
    }

    /// `spawn_in` into a closing region: enqueue succeeds, the admission
    /// denial resolves through the handle as `JoinError::Cancelled`
    /// (mirrors the `Cx::spawn` closing-region contract).
    #[test]
    fn cx_spawn_in_closing_scope_region_resolves_cancelled() {
        use std::task::{Context, Poll, Waker};

        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        lab.state
            .region(child_region)
            .expect("child")
            .begin_close(None);

        let mut handle = parent_cx
            .spawn_in(&scope, |_child| async move { 7usize })
            .expect("enqueue still succeeds; denial resolves via the handle");

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let mut join = handle.join(&parent_cx);
        let mut result = None;
        for _ in 0..200 {
            match Pin::new(&mut join).poll(&mut poll_cx) {
                Poll::Ready(r) => {
                    result = Some(r);
                    break;
                }
                Poll::Pending => lab.step_for_test(),
            }
        }
        drop(join);
        let result = result.expect("join resolved");
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Cancelled(_))
            ),
            "join must resolve Cancelled for a denied scope-targeted spawn, got {result:?}"
        );
    }

    // === br-asupersync-wwyi9k (A2.2b): Cx::spawn_blocking v2 surface ===

    /// Drives `join` against the lab until it resolves (or the step budget
    /// runs out), returning the join result.
    fn poll_join_with_lab<T: Send + 'static>(
        lab: &mut LabRuntime,
        parent_cx: &crate::cx::Cx,
        handle: &mut crate::runtime::TaskHandle<T>,
    ) -> Result<T, crate::runtime::task_handle::JoinError> {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        let mut join = handle.join(parent_cx);
        for _ in 0..200 {
            match Pin::new(&mut join).poll(&mut poll_cx) {
                Poll::Ready(r) => return r,
                Poll::Pending => lab.step_for_test(),
            }
        }
        panic!("join did not resolve within the step budget");
    }

    // === br-asupersync-i9y5wb (A2.2a): Cx::spawn_local v2 surface ===

    fn clear_local_spawn_lane_for_test() {
        let mut dropped = Vec::new();
        while drain_local_spawn_lane(usize::MAX, &mut dropped) > 0 {
            dropped.clear();
        }
    }

    /// A runtime-wired Cx still fails closed when called off-worker: a
    /// `!Send` factory cannot be parked anywhere unless an owner worker is
    /// currently draining that thread-local lane.
    #[test]
    fn cx_spawn_local_off_worker_returns_local_scheduler_unavailable() {
        clear_local_spawn_lane_for_test();
        let (lab, parent_cx, root) = lab_with_parent_cx();
        let result = parent_cx.spawn_local(|_child| async {});
        assert!(matches!(
            result,
            Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable)
        ));
        assert!(
            local_spawn_lane_is_empty(),
            "off-worker call enqueues nothing"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "failed off-worker spawn takes no pending credit"
        );
    }

    /// Owner-worker local spawn: a `!Send` factory (captures `Rc<Cell<_>>`)
    /// is admitted under the same region/counter discipline, pinned to the
    /// owner worker, stored in TLS, queued only on `local_ready`, and joins
    /// with the produced value.
    #[test]
    fn cx_spawn_local_owner_worker_runs_non_send_future() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let local_ready = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::three_lane::LocalReadyQueueInner::new(
                std::collections::VecDeque::new(),
            ),
        ));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let _ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));

        let cell = std::rc::Rc::new(std::cell::Cell::new(0usize));
        let cell_in_child = std::rc::Rc::clone(&cell);
        let mut handle = parent_cx
            .spawn_local(move |_child| async move {
                cell_in_child.set(11);
                42usize
            })
            .expect("cx.spawn_local on owner worker");
        assert!(
            is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            1,
            "local spawn reserves a pending credit before admission"
        );

        let mut requests = Vec::new();
        assert_eq!(
            drain_local_spawn_lane(16, &mut requests),
            1,
            "one local request queued"
        );
        let request = requests.pop().expect("request present");
        let admission = lab.state.admit_local_spawn_request(request);
        let crate::runtime::state::LocalSpawnAdmission::Admitted {
            task_id, stored, ..
        } = admission
        else {
            panic!("expected local admission");
        };
        assert!(
            !is_spawn_mailbox_id(task_id),
            "admitted id must be canonical"
        );
        let record = lab.state.task(task_id).expect("task record");
        assert!(record.is_local(), "task record is marked local");
        assert_eq!(record.pinned_worker(), Some(0), "task pinned to owner");
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "credit released after local admission"
        );

        crate::runtime::local::store_local_task(task_id, stored);
        assert!(
            crate::runtime::scheduler::three_lane::schedule_local_task(task_id),
            "owner worker has local_ready TLS"
        );
        assert_eq!(
            local_ready.lock().pop_front(),
            Some(task_id),
            "task is queued on non-stealable local_ready"
        );

        let mut local_task = crate::runtime::local::remove_local_task(task_id)
            .expect("local task stored on owner thread");
        let waker = std::task::Waker::noop();
        let mut poll_cx = std::task::Context::from_waker(waker);
        assert!(matches!(
            local_task.poll(&mut poll_cx),
            std::task::Poll::Ready(Outcome::Ok(()))
        ));
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert_eq!(result.expect("joined value"), 42);
        assert_eq!(cell.get(), 11, "non-Send future ran on owner thread");
    }

    /// Closing-region denial resolves the returned handle as Cancelled and
    /// drops the `!Send` factory uninvoked.
    #[test]
    fn cx_spawn_local_into_closing_region_resolves_cancelled() {
        clear_local_spawn_lane_for_test();
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let local_ready = Arc::new(parking_lot::Mutex::new(
            crate::runtime::scheduler::three_lane::LocalReadyQueueInner::new(
                std::collections::VecDeque::new(),
            ),
        ));
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);
        let _ready_guard =
            crate::runtime::scheduler::three_lane::ScopedLocalReady::new(Arc::clone(&local_ready));
        lab.state.region(root).expect("root").begin_close(None);

        let ran = std::rc::Rc::new(std::cell::Cell::new(false));
        let ran_in_child = std::rc::Rc::clone(&ran);
        let mut handle = parent_cx
            .spawn_local(move |_child| async move {
                ran_in_child.set(true);
                7usize
            })
            .expect("enqueue still succeeds; denial resolves through handle");
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            1,
            "pending credit held while request is queued"
        );

        let mut requests = Vec::new();
        assert_eq!(drain_local_spawn_lane(16, &mut requests), 1);
        let request = requests.pop().expect("request present");
        let crate::runtime::state::LocalSpawnAdmission::Denied { request, error } =
            lab.state.admit_local_spawn_request(request)
        else {
            panic!("expected closing-region denial");
        };
        assert!(matches!(
            error,
            crate::runtime::state::SpawnError::RegionClosed(id) if id == root
        ));
        request.resolve_cancelled(crate::types::CancelReason::new(
            crate::types::CancelKind::ParentCancelled,
        ));
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "denial releases pending credit"
        );

        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert!(matches!(
            result,
            Err(crate::runtime::task_handle::JoinError::Cancelled(_))
        ));
        assert!(!ran.get(), "local factory was never invoked");
        assert!(local_ready.lock().is_empty(), "denied task never scheduled");
    }

    /// Without a pool handle (lab runtime), the closure runs inline inside
    /// the admitted region-owned task and the value flows through the
    /// handle — the deterministic fallback path.
    #[test]
    fn cx_spawn_blocking_inline_fallback_delivers_value() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_closure = Arc::clone(&ran);
        let mut handle = parent_cx
            .spawn_blocking(move |_child| {
                ran_in_closure.fetch_add(1, Ordering::SeqCst);
                42usize
            })
            .expect("cx.spawn_blocking");
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert_eq!(result.expect("blocking value"), 42);
        assert_eq!(ran.load(Ordering::SeqCst), 1, "closure ran exactly once");
        assert_eq!(
            lab.state.region(root).expect("root").pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// The blocking closure's child Cx inherits the caller's budget
    /// (A2.2 acceptance criterion: spawn_blocking budget inheritance).
    ///
    /// The deadline must carry over exactly; the poll quota is asserted
    /// within a small tolerance because the admitted wrapper task's own
    /// polls are charged against the child budget before the closure
    /// observes it.
    #[test]
    fn cx_spawn_blocking_child_inherits_caller_budget() {
        const QUOTA: u32 = 1_000;
        let deadline = Time::from_secs(77);
        let parent_budget = Budget::new().with_deadline(deadline).with_poll_quota(QUOTA);

        let mut lab = LabRuntime::new(LabConfig::new(21));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let system_cx = lab.state.create_system_cx();
        let (parent_tid, _handle, parent_cx, _result_tx) = lab
            .state
            .create_task_infrastructure::<()>(&system_cx, root, parent_budget, false)
            .expect("parent task");
        lab.state.store_spawned_task(
            parent_tid,
            StoredTask::new_with_id(async { Outcome::Ok(()) }, parent_tid),
        );
        lab.scheduler.lock().schedule(parent_tid, 0);

        let observed: Arc<std::sync::Mutex<Option<Budget>>> = Arc::new(std::sync::Mutex::new(None));
        let observed_in_closure = Arc::clone(&observed);
        parent_cx
            .spawn_blocking(move |child| {
                *observed_in_closure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(child.budget());
            })
            .expect("cx.spawn_blocking");
        lab.run_until_quiescent();
        let observed = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("closure observed a budget");
        assert_eq!(
            observed.deadline,
            Some(deadline),
            "child deadline must equal the caller's deadline at spawn time"
        );
        assert!(
            observed.poll_quota <= QUOTA && observed.poll_quota >= QUOTA - 10,
            "child poll quota must inherit the caller's quota modulo wrapper poll \
             accounting, got {} (expected within [{}, {QUOTA}])",
            observed.poll_quota,
            QUOTA - 10
        );
    }

    /// A panic inside the blocking closure resolves the handle as
    /// `JoinError::Panicked` (panic containment parity with the removed
    /// legacy `Scope::spawn_blocking`).
    #[test]
    fn cx_spawn_blocking_panic_resolves_join_panicked() {
        let (mut lab, parent_cx, _root) = lab_with_parent_cx();
        let mut handle = parent_cx
            .spawn_blocking(|_child| -> usize { panic!("blocking closure exploded") })
            .expect("cx.spawn_blocking");
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Panicked(_))
            ),
            "join must resolve Panicked, got {result:?}"
        );
    }

    /// `spawn_blocking_in` targets the scope's region: reservation and the
    /// admitted task land on the scope's counter/region.
    #[test]
    fn cx_spawn_blocking_in_targets_scope_region() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        let child_region = lab
            .state
            .create_child_region(root, Budget::INFINITE)
            .expect("child region");
        let scope: crate::cx::Scope<'static> =
            crate::cx::Scope::new(child_region, Budget::INFINITE).with_pending_spawn_counter(
                lab.state
                    .region(child_region)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        let mut handle = parent_cx
            .spawn_blocking_in(&scope, |_child| 7usize)
            .expect("cx.spawn_blocking_in");
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            1,
            "reservation lands on the scope's region"
        );
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert_eq!(result.expect("blocking value"), 7);
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child")
                .pending_spawn_count(),
            0,
            "credits balanced"
        );
    }

    /// `spawn_blocking` into a closing region resolves the handle as
    /// `JoinError::Cancelled` without running the closure.
    #[test]
    fn cx_spawn_blocking_into_closing_region_resolves_cancelled() {
        let (mut lab, parent_cx, root) = lab_with_parent_cx();
        lab.state.region(root).expect("root").begin_close(None);
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_closure = Arc::clone(&ran);
        let mut handle = parent_cx
            .spawn_blocking(move |_child| {
                ran_in_closure.fetch_add(1, Ordering::SeqCst);
                7usize
            })
            .expect("enqueue still succeeds; denial resolves via the handle");
        let result = poll_join_with_lab(&mut lab, &parent_cx, &mut handle);
        assert!(
            matches!(
                result,
                Err(crate::runtime::task_handle::JoinError::Cancelled(_))
            ),
            "join must resolve Cancelled for a denied blocking spawn, got {result:?}"
        );
        assert_eq!(ran.load(Ordering::SeqCst), 0, "closure never ran");
    }

    // === br-asupersync-i9y5wb (A2.2a): Cx::spawn_local v2 surface ===

    /// Off-worker producers fail closed at spawn time: the thread-local
    /// lane is only drained by runtime workers, so non-worker threads
    /// (including the lab and blocking-pool threads) get
    /// `LocalSchedulerUnavailable` immediately — a parked request can
    /// never rot on a thread with no drainer.
    #[test]
    fn cx_spawn_local_off_worker_fails_local_scheduler_unavailable() {
        let (_lab, parent_cx, _root) = lab_with_parent_cx();
        let result = parent_cx.spawn_local(|_child| async move { 5usize });
        assert!(
            matches!(
                result,
                Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable)
            ),
            "off-worker spawn_local must fail closed"
        );
    }

    /// Local admission success: the factory defers to first poll, the
    /// pending credit balances once the task joins the region task list,
    /// and the stored task completes when polled.
    #[test]
    fn local_admission_runs_factory_at_first_poll_and_balances_counter() {
        use std::task::{Context, Poll, Waker};

        let mut state = crate::runtime::state::RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        let pending = state.region(region).expect("region").pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_factory = Arc::clone(&ran);
        let factory: LocalSpawnFactoryFn = Box::new(move |_cx| {
            Box::pin(async move {
                ran_in_factory.fetch_add(1, Ordering::SeqCst);
                Outcome::Ok(())
            })
        });
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget: Budget::INFINITE,
            factory,
            on_unadmitted_cancel: None,
            on_admission_error: None,
            pending_reservation: Some(pending.reserve()),
            admitted_slot: None,
        };
        assert_eq!(
            state.region(region).expect("region").pending_spawn_count(),
            1,
            "reservation held while the request is parked"
        );

        let crate::runtime::state::LocalSpawnAdmission::Admitted {
            task_id,
            mut stored,
            ..
        } = state.admit_local_spawn_request(request)
        else {
            panic!("admission must succeed for an open region");
        };
        assert_eq!(
            state.region(region).expect("region").pending_spawn_count(),
            0,
            "credit released once the task is in the region task list"
        );
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "factory deferred to first poll"
        );

        let waker = Waker::noop();
        let mut poll_cx = Context::from_waker(waker);
        assert!(matches!(
            stored.poll(&mut poll_cx),
            Poll::Ready(Outcome::Ok(()))
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 1, "factory ran at first poll");
        assert_eq!(stored.task_id(), Some(task_id));
    }

    /// Local admission denial for a closing region: factory never runs,
    /// the cancel slot fires exactly once, and the pending credit is
    /// released last.
    #[test]
    fn local_admission_denied_for_closing_region_resolves_cancelled() {
        let mut state = crate::runtime::state::RuntimeState::new();
        let region = state.create_root_region(Budget::INFINITE);
        state.region(region).expect("region").begin_close(None);
        let pending = state.region(region).expect("region").pending_spawn_handle();
        let mailbox = SpawnMailbox::new();
        let provisional = mailbox.allocate_task_id();
        let _worker_guard = crate::runtime::scheduler::three_lane::ScopedWorkerId::new(0);

        let ran = Arc::new(AtomicUsize::new(0));
        let ran_in_factory = Arc::clone(&ran);
        let factory: LocalSpawnFactoryFn = Box::new(move |_cx| {
            Box::pin(async move {
                ran_in_factory.fetch_add(1, Ordering::SeqCst);
                Outcome::Ok(())
            })
        });
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancelled_slot = Arc::clone(&cancelled);
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget: Budget::INFINITE,
            factory,
            on_unadmitted_cancel: Some(Box::new(move |_| {
                cancelled_slot.fetch_add(1, Ordering::SeqCst);
            })),
            on_admission_error: None,
            pending_reservation: Some(pending.reserve()),
            admitted_slot: None,
        };

        let crate::runtime::state::LocalSpawnAdmission::Denied { request, error } =
            state.admit_local_spawn_request(request)
        else {
            panic!("admission must deny for a closing region");
        };
        assert!(matches!(
            error,
            crate::runtime::state::SpawnError::RegionClosed(_)
        ));
        request.resolve_cancelled(CancelReason::new(CancelKind::ParentCancelled));
        assert_eq!(ran.load(Ordering::SeqCst), 0, "factory never invoked");
        assert_eq!(
            cancelled.load(Ordering::SeqCst),
            1,
            "cancel slot fired once"
        );
        assert_eq!(
            state.region(region).expect("region").pending_spawn_count(),
            0,
            "credit released on denial"
        );
    }
}
