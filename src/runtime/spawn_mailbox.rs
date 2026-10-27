//! Spawn mailbox: lock-free spawn-request intake decoupled from `RuntimeState`.
//!
//! Today every spawn must hold the global `RuntimeState` lock while
//! `create_task` runs. The spawn mailbox is the first half of the fix
//! (br-asupersync-dx-core-api-v2-u1z5hn.1): callers pre-allocate a
//! *provisional* `TaskId` from a sharded allocator, package the erased
//! future plus its spawn parameters into a `SpawnRequest`, and enqueue it
//! onto the `SpawnMailbox` **without touching `RuntimeState`**. The
//! scheduler performs admission (region liveness check, task-record
//! insertion, obligation hookup) at dispatch time under the state lock it
//! already holds; that half lands separately
//! (br-asupersync-dx-core-api-v2-u1z5hn.1.3), as does region pending-spawn
//! quiescence accounting (br-asupersync-dx-core-api-v2-u1z5hn.1.2).
//!
//! # Provisional task-id namespace
//!
//! Arena-allocated `TaskId`s carry small generations: fresh slots start at
//! generation 0 and the generation increments once per slot reuse. Arena
//! slots retire permanently upon reaching `ARENA_MAX_GENERATION` (2^31 - 1
//! reuses, `br-asupersync-01oghn` L2), guaranteeing that an arena id never
//! sets bit 31. The mailbox mints ids in a strictly disjoint namespace by
//! setting the generation MSB (`SPAWN_ID_GENERATION_TAG = 0x8000_0000`).
//! Layout:
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
//! The mailbox is **unbounded** (`GlobalFifoQueue` wraps a lock-free
//! `SegQueue` on native targets, a mutexed `VecDeque` on wasm). `enqueue`
//! never blocks and never drops a request — silent drop is forbidden by the
//! spawn-mailbox contract. Backpressure is an *admission-side* concern:
//! region quotas reject spawn requests with an explicit `SpawnError` when
//! they are admitted, and region close resolves every pending request through
//! `SpawnRequest::resolve_cancelled` so the completion slot always learns
//! the outcome. The task-handle cancellation-command lane is also unbounded.
//! Producers coalesce identical or weaker reasons per handle and consumers
//! coalesce each drained batch, but neither lane has a hard in-memory backlog
//! bound; queue depth is an operational pressure signal, not a region-quota
//! guarantee.
//!
//! # Trace ordering
//!
//! `SpawnMailbox::enqueue` emits
//! [`TraceEventKind::TaskSpawnEnqueued`](crate::trace::event::TraceEventKind::TaskSpawnEnqueued)
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
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};

pub use crate::record::region::{PendingSpawnCounter, PendingSpawnReservation};

/// Generation tag (MSB) marking a provisional spawn-mailbox `TaskId`.
///
/// Arena generations start at 0 and increment once per slot reuse. Arena slots
/// retire permanently upon reaching `ARENA_MAX_GENERATION` (2^31 - 1 reuses,
/// `br-asupersync-01oghn` L2), guaranteeing that canonical arena IDs never set
/// this bit and preventing collision with provisional IDs.
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
/// `SpawnRequest::with_admitted_slot`.
#[derive(Debug)]
pub struct AdmittedTask {
    /// Canonical arena task id (replaces the provisional mailbox id).
    pub task_id: TaskId,
    /// Weak handle to the admission-built capability context, for
    /// handle-side abort plumbing (A2.2).
    pub cx_inner: std::sync::Weak<parking_lot::RwLock<crate::types::task_context::CxInner>>,
    /// True after admission transfers cancellation routing to the canonical
    /// task/gateway. On ordinary admission that coincides with first-lane
    /// publication; a managed pre-admission abort may transfer routing to its
    /// delegated command before that command publishes the physical cancel
    /// lane. This flag is therefore not a lane-visibility witness; Cx's
    /// `RunnablePublication` owns that proof.
    published: AtomicBool,
}

impl AdmittedTask {
    pub(crate) fn pending(
        task_id: TaskId,
        cx_inner: std::sync::Weak<parking_lot::RwLock<crate::types::task_context::CxInner>>,
    ) -> Self {
        Self {
            task_id,
            cx_inner,
            published: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    pub(crate) fn published(
        task_id: TaskId,
        cx_inner: std::sync::Weak<parking_lot::RwLock<crate::types::task_context::CxInner>>,
    ) -> Self {
        Self {
            task_id,
            cx_inner,
            published: AtomicBool::new(true),
        }
    }

    #[inline]
    pub(crate) fn is_published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    #[inline]
    fn mark_published(&self) {
        self.published.store(true, Ordering::Release);
    }
}

/// One-shot slot for publishing an admitted task's canonical identity.
///
/// Admission reserves the slot before mutating `RuntimeState`. Keeping the
/// underlying [`std::sync::OnceLock`] private prevents a second request from
/// racing an external `set` between that preflight and identity publication.
pub struct AdmittedTaskSlot {
    admitted: OnceLock<AdmittedTask>,
    reserved: AtomicBool,
    cancel_gateway: Option<Weak<SpawnGateway>>,
    // Immutable producer authority, installed on the canonical task context
    // before admission publishes it. Keeping it private preserves the public
    // request structs' existing construction surface.
    runtime_mask: crate::cx::cap::CapMask,
    /// Only the current-thread root's accounting task has its poll quota
    /// charged by the caller that polls the actual root future.
    caller_owned_poll_quota: bool,
    /// Retirement barrier shared with this task's join handle and, at
    /// admission, its `CxInner`, so the scheduler (which opens it after the
    /// record terminal commit) and the handle (which gates terminal-result
    /// visibility on it) observe the same signal (br-asupersync-yhueis).
    /// `None` until a record-backed spawn producer installs one; a handle
    /// reading `None` falls back to an open barrier and delivers immediately.
    retirement_barrier: Option<Arc<crate::runtime::task_handle::RetirementBarrier>>,
    /// Strongest cancellation requested while canonical identity publication
    /// is still pending. The cache is initialized per slot, so unrelated
    /// spawn producers never serialize through process-global state.
    pending_cancel_reason: OnceLock<PendingCancelReason>,
    /// Set by race-branch producers: admission mints a sealed child region of
    /// the requested region and admits the task into it, so the branch's own
    /// spawns stay inside a subtree the race can cancel and drain
    /// (br-asupersync-issue65-criticisms-kpmoy5.2.2).
    branch_region: Option<Arc<BranchRegionSlot>>,
    /// The spawner's fallback region, when the spawn names its context's own
    /// sealed region: admission uses it once that region has closed for good
    /// (br-asupersync-k27oxe).
    spawn_fallback: Option<RegionId>,
    /// Authoritative one-shot observer receipt for managed pre-admission
    /// aborts. Every repeat abort command carries this slot, so whichever
    /// consumer wins first-lane publication also wins this receipt.
    spawn_effects: Mutex<SpawnEffectHandoff>,
    /// The handles the task inherits from its spawner, taken once by
    /// admission so the record's context (`Cx::current()` in the task)
    /// carries them. Private for the same reason as `runtime_mask`
    /// (br-asupersync-93zkbz).
    inherited: Mutex<Option<crate::cx::cx::InheritedHandles>>,
}

struct SpawnEffectHandoff {
    lane_published: bool,
    effects: Option<crate::runtime::state::TaskSpawnEffects>,
}

impl SpawnEffectHandoff {
    const fn new() -> Self {
        Self {
            lane_published: false,
            effects: None,
        }
    }
}

impl AdmittedTaskSlot {
    /// Creates an empty, unreserved admission slot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            admitted: OnceLock::new(),
            reserved: AtomicBool::new(false),
            cancel_gateway: None,
            runtime_mask: crate::cx::cap::CapMask::all(),
            caller_owned_poll_quota: false,
            retirement_barrier: None,
            pending_cancel_reason: OnceLock::new(),
            branch_region: None,
            spawn_fallback: None,
            spawn_effects: Mutex::new(SpawnEffectHandoff::new()),
            inherited: Mutex::new(None),
        }
    }

    /// Creates an empty slot bound to its runtime's cancellation-command
    /// gateway. Only runtime spawn producers construct managed slots.
    pub(crate) fn new_with_cancel_gateway(cancel_gateway: Arc<SpawnGateway>) -> Self {
        Self {
            admitted: OnceLock::new(),
            reserved: AtomicBool::new(false),
            cancel_gateway: Some(Arc::downgrade(&cancel_gateway)),
            runtime_mask: crate::cx::cap::CapMask::all(),
            caller_owned_poll_quota: false,
            retirement_barrier: None,
            pending_cancel_reason: OnceLock::new(),
            branch_region: None,
            spawn_fallback: None,
            spawn_effects: Mutex::new(SpawnEffectHandoff::new()),
            inherited: Mutex::new(None),
        }
    }

    pub(crate) fn with_runtime_mask(mut self, mask: crate::cx::cap::CapMask) -> Self {
        self.runtime_mask = mask;
        self
    }

    /// Selects the quota owner before the first scheduler poll, including for
    /// a zero-quota root. This does not widen the admitted task's budget.
    pub(crate) fn with_caller_owned_poll_quota(mut self, caller_owned: bool) -> Self {
        self.caller_owned_poll_quota = caller_owned;
        self
    }

    pub(crate) fn caller_owned_poll_quota(&self) -> bool {
        self.caller_owned_poll_quota
    }

    /// Requests that admission run this task in a fresh sealed child region
    /// of the requested region, published through `slot`.
    pub(crate) fn with_branch_region(mut self, slot: Arc<BranchRegionSlot>) -> Self {
        self.branch_region = Some(slot);
        self
    }

    /// The branch-region request, when the producer made one.
    pub(crate) fn branch_region(&self) -> Option<&Arc<BranchRegionSlot>> {
        self.branch_region.as_ref()
    }

    /// Carries the spawner's fallback region (see
    /// `RegionRecord::spawn_fallback`).
    pub(crate) fn with_spawn_fallback(mut self, region: Option<RegionId>) -> Self {
        self.spawn_fallback = region;
        self
    }

    /// The region admission uses when the requested one has closed.
    pub(crate) fn spawn_fallback(&self) -> Option<RegionId> {
        self.spawn_fallback
    }

    /// Moves the spawner's inherited handles into the slot. Admission takes
    /// them when it builds the task's context (br-asupersync-93zkbz).
    pub(crate) fn with_inherited_handles(
        mut self,
        inherited: crate::cx::cx::InheritedHandles,
    ) -> Self {
        *self.inherited.get_mut() = Some(inherited);
        self
    }

    /// Takes the inherited handles; admission calls this once.
    pub(crate) fn take_inherited_handles(&self) -> Option<crate::cx::cx::InheritedHandles> {
        self.inherited.lock().take()
    }

    pub(crate) fn runtime_mask(&self) -> crate::cx::cap::CapMask {
        self.runtime_mask
    }

    /// Installs the retirement barrier for a record-backed spawn, shared with
    /// the join handle (which gates terminal-result visibility) and the task's
    /// `CxInner` (which the scheduler opens after the record terminal commit).
    pub(crate) fn with_retirement_barrier(
        mut self,
        barrier: Arc<crate::runtime::task_handle::RetirementBarrier>,
    ) -> Self {
        self.retirement_barrier = Some(barrier);
        self
    }

    /// Returns this task's retirement barrier if a record-backed spawn producer
    /// installed one; `None` for slots that carry no gated record.
    pub(crate) fn retirement_barrier(
        &self,
    ) -> Option<Arc<crate::runtime::task_handle::RetirementBarrier>> {
        self.retirement_barrier.clone()
    }

    /// Returns the canonical identity once admission has published it.
    #[inline]
    #[must_use]
    pub fn get(&self) -> Option<&AdmittedTask> {
        self.admitted.get()
    }

    pub(crate) fn cancel_gateway(&self) -> Option<Arc<SpawnGateway>> {
        self.cancel_gateway.as_ref().and_then(Weak::upgrade)
    }

    /// Returns this slot's shared strongest-reason cache.
    ///
    /// Initialization may synchronize callers racing on the same admission
    /// slot, but independent spawn producers touch disjoint `OnceLock`s.
    pub(crate) fn pending_cancel_reason(&self) -> PendingCancelReason {
        Arc::clone(
            self.pending_cancel_reason
                .get_or_init(|| Arc::new(RwLock::new(None))),
        )
    }

    /// Returns the cache for a newly constructed pending handle.
    ///
    /// Normal producer handles are built before enqueue and share the slot
    /// cache with admission. A handle constructed after runnable publication
    /// keeps independent caller-side attribution because no publisher remains
    /// to replay the slot cache.
    pub(crate) fn pending_handle_cancel_reason(&self) -> PendingCancelReason {
        if self.get().is_some_and(AdmittedTask::is_published) {
            Arc::new(RwLock::new(None))
        } else {
            self.pending_cancel_reason()
        }
    }

    fn install_spawn_effects(&self, spawn_effects: crate::runtime::state::TaskSpawnEffects) {
        let mut slot = self.spawn_effects.lock();
        debug_assert!(
            slot.effects.is_none(),
            "spawn observer receipt installed once"
        );
        debug_assert!(
            !slot.lane_published,
            "managed observer receipt precedes first-lane publication"
        );
        slot.effects = Some(spawn_effects);
    }

    pub(crate) fn publish_spawn_lane_and_take_effects(
        &self,
    ) -> Option<crate::runtime::state::TaskSpawnEffects> {
        let mut slot = self.spawn_effects.lock();
        slot.lane_published = true;
        slot.effects.take()
    }

    fn mark_spawn_lane_published(&self) {
        let mut slot = self.spawn_effects.lock();
        slot.lane_published = true;
        debug_assert!(
            slot.effects.is_none(),
            "ordinary admission must not install a delegated spawn observer receipt"
        );
    }

    pub(crate) fn take_spawn_effects_if_lane_published(
        &self,
    ) -> Option<crate::runtime::state::TaskSpawnEffects> {
        let mut slot = self.spawn_effects.lock();
        if slot.lane_published {
            slot.effects.take()
        } else {
            None
        }
    }

    /// Retires an observer receipt whose managed command can no longer be
    /// consumed because the runtime has shut down. No task lane became
    /// executable, so dispatch would assert a false spawn observation; the
    /// receipt's fail-closed `Drop` path contains arbitrary provider teardown.
    pub(crate) fn abandon_unpublished_spawn_effects(&self) {
        let effects = {
            let mut slot = self.spawn_effects.lock();
            if slot.lane_published {
                None
            } else {
                slot.effects.take()
            }
        };
        drop(effects);
    }

    /// Reserves this one-shot slot before admission mutates runtime state.
    #[inline]
    pub(crate) fn try_reserve(&self) -> bool {
        self.reserved
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Publishes the identity into a slot successfully reserved by admission.
    pub(crate) fn publish_reserved(&self, admitted: AdmittedTask) {
        self.admitted
            .set(admitted)
            .expect("a reserved admission slot is published exactly once");
    }

    #[cfg(test)]
    pub(crate) fn set(&self, admitted: AdmittedTask) -> Result<(), AdmittedTask> {
        if !self.try_reserve() {
            return Err(admitted);
        }
        self.admitted.set(admitted)
    }
}

impl fmt::Debug for AdmittedTaskSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmittedTaskSlot")
            .field("admitted", &self.admitted.get())
            .field("reserved", &self.reserved.load(Ordering::Relaxed))
            .field("has_cancel_gateway", &self.cancel_gateway.is_some())
            .field(
                "has_pending_cancel_reason",
                &self.pending_cancel_reason.get().is_some(),
            )
            .field("spawn_effect_handoff", &{
                let slot = self.spawn_effects.lock();
                (slot.lane_published, slot.effects.is_some())
            })
            .finish()
    }
}

impl Default for AdmittedTaskSlot {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) type PendingCancelReason = Arc<RwLock<Option<CancelReason>>>;

/// One-shot handoff from canonical identity admission to runnable-lane
/// publication. Cached handle aborts are replayed and the effective Cx
/// cancellation state is sampled before the admitted task becomes
/// scheduler-visible.
#[doc(hidden)]
#[must_use = "admitted tasks must cross the runnable publication boundary"]
pub struct AdmissionPublication {
    cx_inner: std::sync::Weak<parking_lot::RwLock<crate::types::task_context::CxInner>>,
    slot: Option<Arc<AdmittedTaskSlot>>,
    requested: Option<PendingCancelReason>,
}

impl AdmissionPublication {
    pub(crate) fn new(
        cx_inner: std::sync::Weak<parking_lot::RwLock<crate::types::task_context::CxInner>>,
        slot: Option<Arc<AdmittedTaskSlot>>,
    ) -> Self {
        let requested = slot.as_ref().map(|slot| slot.pending_cancel_reason());
        Self {
            cx_inner,
            slot,
            requested,
        }
    }

    /// Publishes the canonical task and snapshots any cancellation that raced
    /// admission. `publish_lane` receives the effective Cx cancellation
    /// priority, or `None` for ordinary ready-lane admission, and normally
    /// makes the task scheduler-visible without invoking user code. A managed
    /// pre-admission handle abort delegates the first lane publication to its
    /// runtime-owned cancellation command instead, so this closure is not
    /// invoked on that path. This crate-private closure is part of the
    /// scheduler boundary, not a user callback.
    /// Returned Wakers must be dispatched after scheduler locks are released.
    #[cfg(test)]
    pub(crate) fn publish(
        self,
        publish_lane: impl FnOnce(Option<u8>),
    ) -> crate::types::task_context::CancelWakeEffects {
        let (wakes, spawn_effects) = self.publish_inner(None, publish_lane);
        debug_assert!(spawn_effects.is_none());
        wakes
    }

    /// Publishes an admitted task together with its one-shot spawn observer.
    ///
    /// Ordinary admissions return the observer to the caller after the lane is
    /// physically visible. A managed pre-admission abort installs the observer
    /// in the authoritative admitted slot carried by every delegated cancel
    /// command. Whichever consumer physically publishes the first cancel lane
    /// atomically claims the observer before retained Wakers are dispatched.
    pub(crate) fn publish_with_spawn_effects(
        self,
        spawn_effects: crate::runtime::state::TaskSpawnEffects,
        publish_lane: impl FnOnce(Option<u8>),
    ) -> (
        crate::types::task_context::CancelWakeEffects,
        Option<crate::runtime::state::TaskSpawnEffects>,
    ) {
        self.publish_inner(Some(spawn_effects), publish_lane)
    }

    fn publish_inner(
        mut self,
        mut spawn_effects: Option<crate::runtime::state::TaskSpawnEffects>,
        publish_lane: impl FnOnce(Option<u8>),
    ) -> (
        crate::types::task_context::CancelWakeEffects,
        Option<crate::runtime::state::TaskSpawnEffects>,
    ) {
        let slot = self.slot.take();
        let admitted = slot.as_ref().and_then(|slot| slot.get());

        let cancel_wakes = if let Some(requested) = self.requested.take() {
            // This lock is the abort/publication linearization point. Handle
            // aborts either cache before this guard, or observe `published`
            // after it and apply their own reason directly.
            let cached = requested.write();
            let managed_command = cached.as_ref().and_then(|reason| {
                let admitted = admitted?;
                let slot = slot.as_ref()?;
                let gateway = slot.cancel_gateway()?;
                Some((admitted.task_id, gateway, reason.clone(), Arc::clone(slot)))
            });
            if let Some((task_id, gateway, reason, admitted_slot)) = managed_command {
                let effective_reason = self.cx_inner.upgrade().map_or(reason.clone(), |inner| {
                    crate::runtime::task_handle::prepare_admitted_handle_cancel_state(
                        &inner, &reason,
                    )
                });
                if let Some(effects) = spawn_effects.take() {
                    admitted_slot.install_spawn_effects(effects);
                }
                let observer_slot = Arc::clone(&admitted_slot);
                let enqueued = gateway.enqueue_handle_cancel_with_admitted_slot_without_notify(
                    task_id,
                    effective_reason,
                    admitted_slot,
                );
                // Keep the shared reason guard through identity publication
                // and mailbox insertion. A racing abort is therefore either
                // folded into `effective_reason` above or observes Published
                // after this command exists and enqueues a stronger follow-up.
                drop(cached);
                if enqueued {
                    gateway.notify_handle_cancel();
                } else {
                    observer_slot.abandon_unpublished_spawn_effects();
                }
                crate::types::task_context::CancelWakeEffects::empty()
            } else {
                let wakes = if let Some(inner) = self.cx_inner.upgrade() {
                    crate::runtime::task_handle::publish_admitted_cancel_state(
                        &inner,
                        cached.as_ref(),
                        publish_lane,
                    )
                } else {
                    // The runtime has already retired the Cx. Preserve the
                    // cached reason's fail-closed lane choice without running
                    // callbacks.
                    publish_lane(
                        cached
                            .as_ref()
                            .map(|reason| reason.cleanup_budget().priority),
                    );
                    crate::types::task_context::CancelWakeEffects::empty()
                };
                if let Some(admitted) = admitted {
                    admitted.mark_published();
                }
                if let Some(slot) = slot.as_ref() {
                    slot.mark_spawn_lane_published();
                }
                drop(cached);
                wakes
            }
        } else {
            let wakes = if let Some(inner) = self.cx_inner.upgrade() {
                crate::runtime::task_handle::publish_admitted_cancel_state(
                    &inner,
                    None,
                    publish_lane,
                )
            } else {
                publish_lane(None);
                crate::types::task_context::CancelWakeEffects::empty()
            };
            if let Some(admitted) = admitted {
                admitted.mark_published();
            }
            if let Some(slot) = slot.as_ref() {
                slot.mark_spawn_lane_published();
            }
            wakes
        };
        (cancel_wakes, spawn_effects)
    }
}

/// Returns the shared cache only when this request never published an
/// identity. A duplicate request can carry the winner's populated slot; its
/// denial must not inherit the winner's cancellation attribution.
fn unadmitted_cancel_reason(slot: &Arc<AdmittedTaskSlot>) -> Option<PendingCancelReason> {
    if slot.get().is_some() {
        None
    } else {
        Some(slot.pending_cancel_reason())
    }
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
            let factory_result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| factory(cx)));
            match factory_result {
                Ok(inner) => self.inner = Some(inner),
                Err(payload) => {
                    let message = crate::cx::scope::payload_to_string(&payload);
                    std::mem::forget(payload);
                    return Poll::Ready(Outcome::Panicked(crate::types::PanicPayload::new(
                        message,
                    )));
                }
            }
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
            let factory_result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| factory(cx)));
            match factory_result {
                Ok(inner) => self.inner = Some(inner),
                Err(payload) => {
                    let message = crate::cx::scope::payload_to_string(&payload);
                    std::mem::forget(payload);
                    return Poll::Ready(Outcome::Panicked(crate::types::PanicPayload::new(
                        message,
                    )));
                }
            }
        }
        self.inner
            .as_mut()
            .expect("inner future set above")
            .as_mut()
            .poll(task_cx)
    }
}

/// `!Send` mirror of [`UnadmittedCancelFn`]: fired on the owner worker when
/// a local spawn request is cancelled before admission.
pub type LocalUnadmittedCancelFn = Box<dyn FnOnce(CancelReason)>;

/// `!Send` mirror of [`AdmissionErrorFn`]: fired on the owner worker when
/// a local spawn request fails admission.
pub type LocalAdmissionErrorFn = Box<dyn FnOnce(SpawnError)>;

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
    pub on_unadmitted_cancel: Option<LocalUnadmittedCancelFn>,
    /// Completion slot for non-cancellation admission failures.
    pub on_admission_error: Option<LocalAdmissionErrorFn>,
    /// Pending-spawn credit on the owning region; released only after the
    /// task is visible in the region's task list (or on denial, last).
    pub pending_reservation: Option<crate::record::region::PendingSpawnReservation>,
    /// Producer-shared slot admission fills with the canonical identity.
    pub admitted_slot: Option<Arc<AdmittedTaskSlot>>,
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
        contain_denied_cleanup(move || drop(factory));
        let requested = admitted_slot.as_ref().and_then(unadmitted_cancel_reason);
        if let Some(slot) = on_unadmitted_cancel {
            let reason = strengthen_with_requested_reason(reason, requested.as_ref());
            contain_denied_cleanup(move || slot(reason));
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
        contain_denied_cleanup(move || drop(factory));
        let requested = admitted_slot.as_ref().and_then(unadmitted_cancel_reason);
        let requested_failure = requested_admission_failure_reason(&error, requested.as_ref());
        match (requested_failure, on_unadmitted_cancel, on_admission_error) {
            (Some(reason), Some(slot), _) => contain_denied_cleanup(move || slot(reason)),
            (_, _, Some(slot)) => contain_denied_cleanup(move || slot(error)),
            (None, Some(slot), None) => {
                let mut reason = CancelReason::user("spawn admission failed");
                reason.message = Some(error.to_string());
                contain_denied_cleanup(move || slot(reason));
            }
            (_, None, None) => {}
        }
        drop(pending_reservation);
    }
}

/// Private routing metadata keeps the public request shape unchanged. A weak
/// mailbox identity neither retains the runtime nor aliases a later mailbox.
pub(crate) struct LocalSpawnLaneEntry {
    owner: Option<Weak<SpawnMailbox>>,
    request: LocalSpawnRequest,
}

impl LocalSpawnLaneEntry {
    fn belongs_to(&self, owner: Option<&Arc<SpawnMailbox>>) -> bool {
        match (self.owner.as_ref(), owner) {
            (Some(queued), Some(current)) => std::ptr::eq(queued.as_ptr(), Arc::as_ptr(current)),
            (Some(_), None) => false,
            // Unowned entries support detached admission harnesses only.
            (None, _) => true,
        }
    }
}

thread_local! {
    /// Owner-thread lane of pending local spawn requests. Filled by
    /// `Cx::spawn_local[_in]` on workers, or by `Runtime::spawn_local` on
    /// workers and browser host threads. Each worker drains only its runtime's
    /// requests alongside the shared mailbox.
    static LOCAL_SPAWN_LANE: std::cell::RefCell<std::collections::VecDeque<LocalSpawnLaneEntry>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
    /// Runtime identity for the worker that owns [`LOCAL_SPAWN_LANE`].
    ///
    /// Ambient runtime handles can be replaced by nested `Runtime::block_on`,
    /// so the lane itself must carry the authoritative owner identity.
    static LOCAL_SPAWN_OWNER: std::cell::RefCell<Option<Arc<SpawnMailbox>>> =
        const { std::cell::RefCell::new(None) };
}

/// Scoped runtime owner for the current worker's local-spawn lane.
pub(crate) struct ScopedLocalSpawnLaneOwner {
    previous: Option<Arc<SpawnMailbox>>,
}

impl ScopedLocalSpawnLaneOwner {
    pub(crate) fn new(mailbox: Arc<SpawnMailbox>) -> Self {
        let previous = LOCAL_SPAWN_OWNER.with(|owner| owner.replace(Some(mailbox)));
        Self { previous }
    }
}

impl Drop for ScopedLocalSpawnLaneOwner {
    fn drop(&mut self) {
        let previous = self.previous.take();
        let _ = LOCAL_SPAWN_OWNER.try_with(|owner| {
            *owner.borrow_mut() = previous;
        });
    }
}

/// Returns true only when the current worker-local lane belongs to `gateway`.
pub(crate) fn local_spawn_lane_is_owned_by(gateway: &SpawnGateway) -> bool {
    local_spawn_lane_is_owned_by_mailbox(gateway.mailbox())
}

/// Returns true only when the current worker-local lane belongs to `mailbox`.
pub(crate) fn local_spawn_lane_is_owned_by_mailbox(mailbox: &Arc<SpawnMailbox>) -> bool {
    LOCAL_SPAWN_OWNER.with(|owner| {
        owner
            .borrow()
            .as_ref()
            .is_some_and(|owned| Arc::ptr_eq(owned, mailbox))
    })
}

/// Parks a local spawn request on the current thread's lane.
pub(crate) fn enqueue_local_spawn(request: LocalSpawnRequest) {
    let owner = LOCAL_SPAWN_OWNER.with(|owner| owner.borrow().as_ref().map(Arc::downgrade));
    LOCAL_SPAWN_LANE.with(|lane| {
        lane.borrow_mut()
            .push_back(LocalSpawnLaneEntry { owner, request });
    });
}

/// Queues a request for an explicit runtime, including browser callers outside
/// a pump turn where no worker-local owner is installed.
pub(crate) fn enqueue_local_spawn_for_mailbox(
    request: LocalSpawnRequest,
    mailbox: &Arc<SpawnMailbox>,
) {
    LOCAL_SPAWN_LANE.with(|lane| {
        lane.borrow_mut().push_back(LocalSpawnLaneEntry {
            owner: Some(Arc::downgrade(mailbox)),
            request,
        });
    });
}

/// Returns true when the current worker has no parked local spawns.
pub(crate) fn local_spawn_lane_is_empty() -> bool {
    LOCAL_SPAWN_LANE.with(|lane| {
        let lane = lane.borrow();
        // Keep the usual empty-lane scheduler check free of owner lookups and
        // reference-count traffic. The queued Weak keeps its identity unique.
        lane.is_empty()
            || LOCAL_SPAWN_OWNER.with(|owner| {
                let owner = owner.borrow();
                !lane.iter().any(|entry| entry.belongs_to(owner.as_ref()))
            })
    })
}

/// Moves up to `max` requests belonging to this worker into `into`, preserving
/// FIFO order and leaving other runtimes' requests on this thread untouched.
pub(crate) fn drain_local_spawn_lane(max: usize, into: &mut Vec<LocalSpawnRequest>) -> usize {
    LOCAL_SPAWN_OWNER.with(|owner| {
        let owner = owner.borrow();
        drain_local_spawn_lane_matching(max, into, |entry| entry.belongs_to(owner.as_ref()))
    })
}

fn drain_local_spawn_lane_matching(
    max: usize,
    into: &mut Vec<LocalSpawnRequest>,
    matches: impl Fn(&LocalSpawnLaneEntry) -> bool,
) -> usize {
    LOCAL_SPAWN_LANE.with(|lane| {
        let mut lane = lane.borrow_mut();
        let mut moved = 0;
        while moved < max {
            let Some(index) = lane.iter().position(&matches) else {
                break;
            };
            let entry = lane.remove(index).expect("matching lane entry exists");
            into.push(entry.request);
            moved += 1;
        }
        moved
    })
}

/// Sets aside legacy unowned requests during a native drive. Owned requests
/// stay reachable so dropping their runtime during a nested drive can cancel
/// them immediately; worker admission already filters by runtime identity.
pub(crate) fn take_unowned_local_spawn_lane() -> std::collections::VecDeque<LocalSpawnLaneEntry> {
    LOCAL_SPAWN_LANE.with(|lane| {
        let mut lane = lane.borrow_mut();
        let mut unowned = std::collections::VecDeque::new();
        let count = lane.len();
        for _ in 0..count {
            let entry = lane.pop_front().expect("original lane entry exists");
            if entry.owner.is_none() {
                unowned.push_back(entry);
            } else {
                lane.push_back(entry);
            }
        }
        unowned
    })
}

/// Restores requests set aside by a nested native drive, retaining their owners.
pub(crate) fn restore_local_spawn_lane(
    mut entries: std::collections::VecDeque<LocalSpawnLaneEntry>,
) {
    LOCAL_SPAWN_LANE.with(|lane| {
        let mut lane = lane.borrow_mut();
        // Requests queued during the nested drive follow the older outer
        // requests, including when they belong to the same browser runtime.
        entries.append(&mut lane);
        *lane = entries;
    });
}

/// Cancels only this runtime's queued requests on the calling thread. Resolve
/// callbacks and drop captured futures after releasing the thread-local borrow.
pub(crate) fn cancel_local_spawns_for_mailbox(mailbox: &Arc<SpawnMailbox>) {
    let owner = Arc::downgrade(mailbox);
    let mut requests = Vec::new();
    drain_local_spawn_lane_matching(usize::MAX, &mut requests, |entry| {
        entry
            .owner
            .as_ref()
            .is_some_and(|queued| Weak::ptr_eq(queued, &owner))
    });
    for request in requests {
        request.resolve_cancelled(CancelReason::shutdown());
    }
}

/// Cancels a runtime's local spawns still queued on this thread when dropped.
///
/// A native worker thread holds one while it runs. Its loop ends at shutdown
/// even when the thread's lane still holds that runtime's unadmitted
/// `spawn_local` requests, and thread exit would otherwise drop them during
/// thread-local teardown: their handles never resolve, and their captures are
/// destroyed where a panic aborts the process (br-asupersync-01oghn M1).
pub(crate) struct CancelLocalSpawnsOnExit(pub(crate) Arc<SpawnMailbox>);

impl Drop for CancelLocalSpawnsOnExit {
    fn drop(&mut self) {
        cancel_local_spawns_for_mailbox(&self.0);
    }
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
    admitted_slot: Option<Arc<AdmittedTaskSlot>>,
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
    pub admitted_slot: Option<Arc<AdmittedTaskSlot>>,
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
    pub(crate) fn with_admitted_slot(mut self, slot: Arc<AdmittedTaskSlot>) -> Self {
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
        contain_denied_cleanup(move || drop(payload));
        let requested = admitted_slot.as_ref().and_then(unadmitted_cancel_reason);
        if let Some(slot) = on_unadmitted_cancel {
            let reason = strengthen_with_requested_reason(reason, requested.as_ref());
            contain_denied_cleanup(move || slot(reason));
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
        contain_denied_cleanup(move || drop(payload));
        let requested = admitted_slot.as_ref().and_then(unadmitted_cancel_reason);
        let requested_failure = requested_admission_failure_reason(&error, requested.as_ref());
        match (requested_failure, on_unadmitted_cancel, on_admission_error) {
            (Some(reason), Some(slot), _) => contain_denied_cleanup(move || slot(reason)),
            (_, _, Some(slot)) => contain_denied_cleanup(move || slot(error)),
            (None, Some(slot), None) => contain_denied_cleanup(move || {
                slot(CancelReason::user("spawn admission failed"));
            }),
            (_, None, None) => {}
        }
        drop(pending_reservation);
    }
}

/// Runs one step of a denied request's resolution that can reach user code:
/// dropping the captured future (a capture's `Drop`, such as an unconsumed
/// `ObligationToken`, may panic) or invoking its completion slot (which wakes
/// joiners). A panic there used to skip the completion slot, so the handle's
/// join never resolved, and to unwind out of the worker's admission drain,
/// killing the worker. The panic payload is forgotten: it may itself panic on
/// destruction (br-asupersync-01oghn).
fn contain_denied_cleanup(cleanup: impl FnOnce()) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)) {
        std::mem::forget(payload);
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

/// Cancellation request issued through a `TaskHandle` before or after task admission.
pub(crate) struct HandleCancelRequest {
    pub(crate) task_id: TaskId,
    pub(crate) reason: CancelReason,
    pub(crate) admitted_slot: Option<Arc<AdmittedTaskSlot>>,
}

impl fmt::Debug for HandleCancelRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleCancelRequest")
            .field("task_id", &self.task_id)
            .field("reason", &self.reason)
            .field("has_admitted_slot", &self.admitted_slot.is_some())
            .finish()
    }
}

/// Coalesces a drained command batch by canonical task identity while
/// preserving the first-seen task order and strongest cancellation reason.
pub(crate) fn coalesce_handle_cancel_requests(
    requests: Vec<HandleCancelRequest>,
) -> Vec<HandleCancelRequest> {
    let mut coalesced: Vec<HandleCancelRequest> = Vec::with_capacity(requests.len());
    for mut request in requests {
        if let Some(existing) = coalesced
            .iter_mut()
            .find(|existing| existing.task_id == request.task_id)
        {
            existing.reason.strengthen(&request.reason);
            if existing.admitted_slot.is_none() {
                existing.admitted_slot = request.admitted_slot.take();
            }
        } else {
            coalesced.push(request);
        }
    }
    coalesced
}
/// Producer-side request to mint a child region record under a parent
/// (bd-asupersync-ambient-child-region-0fm8l). The producer holds only an
/// ambient [`crate::cx::Cx`]; the scheduler worker performs the actual
/// `RuntimeState` mint at the same dispatch point where mailbox spawns are
/// admitted, then publishes the outcome into the caller-shared
/// [`AdmittedRegionSlot`].
pub(crate) struct CreateRegionRequest {
    pub(crate) parent: RegionId,
    pub(crate) budget: Budget,
    pub(crate) capability_budget: crate::types::CapabilityBudget,
    pub(crate) requirements: crate::types::CapabilityBudgetRequirements,
    pub(crate) priority: crate::runtime::resource_monitor::RegionPriority,
    /// Provisional identity for the child region's principal capability
    /// context, allocated from the mailbox id space by the producer. No
    /// task record carries it; body work spawned through the child context
    /// mints its own canonical records at admission.
    pub(crate) principal_task_id: TaskId,
    pub(crate) slot: Arc<AdmittedRegionSlot>,
    /// Where the child is minted once `parent` has closed: the caller's
    /// spawn fallback (`Cx::spawn_fallback_for`), so a race winner's context
    /// kept past its sealed region opens children where it spawns
    /// (br-asupersync-inleqi M2, br-asupersync-k27oxe). `None` otherwise.
    pub(crate) parent_fallback: Option<RegionId>,
}

impl fmt::Debug for CreateRegionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateRegionRequest")
            .field("parent", &self.parent)
            .finish_non_exhaustive()
    }
}

/// A local future was destroyed on its owner thread before this was queued.
/// Native local admission installs the weak producer route; the lab never
/// creates these records. There is at most one command per abandoned future,
/// and no future, Cx, Waker, or user callback crosses the thread boundary.
#[derive(Debug)]
pub(crate) struct LocalTaskRetirement {
    pub(crate) task_id: TaskId,
    pub(crate) panic: Option<crate::types::PanicPayload>,
}

/// Commands that mutate region lifecycle state but carry no task payload.
#[derive(Debug)]
pub(crate) enum RegionCommand {
    /// Mint a child region and publish the owned handle parts.
    Create(CreateRegionRequest),
    /// Retain generation-owned state through real region finalization. The
    /// acknowledgment is published after the runtime state lock is released.
    RegisterFinalizer(RegisterRegionFinalizer),
    /// Request cancellation for an existing region (idempotent in effect:
    /// unknown regions are tolerated so late cancels after close never
    /// fail).
    Cancel {
        region_id: RegionId,
        reason: CancelReason,
    },
    /// Managed shutdown installs a monotone ceiling before propagating cancel.
    CancelWithBudget {
        region_id: RegionId,
        reason: CancelReason,
        shutdown_budget: Budget,
    },
    /// Begin the close protocol for a region. Emitted both by
    /// [`crate::cx::ChildRegion::close`] after body work finishes and by the
    /// `Drop` backstop for abandoned handles (whose body may still be
    /// running; the close protocol cancels whatever remains).
    Close { region_id: RegionId },
    /// Establish or remove a runtime monitor or link
    /// (br-asupersync-issue65-criticisms-kpmoy5.6.1).
    Watch(crate::monitor::WatchCommand),
    /// Report the live tasks of a region and its descendant regions
    /// (br-asupersync-issue65-criticisms-kpmoy5.2.4).
    LiveTasks(RegionLiveTasksQuery),
}

/// Crate-private query behind [`crate::cx::ChildRegion::close_within`]: the
/// tasks of a region subtree that have not completed. It is collected under
/// the runtime state lock and published after the lock is released, like a
/// finalizer acknowledgment. It lists the unfinished tasks; with an external
/// task table, a task that has just turned terminal can still appear once.
pub(crate) struct RegionLiveTasksQuery {
    region_id: RegionId,
    reply: crate::channel::oneshot::Sender<Vec<TaskId>>,
    tasks: Vec<TaskId>,
}

impl fmt::Debug for RegionLiveTasksQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegionLiveTasksQuery")
            .field("region_id", &self.region_id)
            .field("tasks", &self.tasks)
            .finish_non_exhaustive()
    }
}

impl RegionLiveTasksQuery {
    pub(crate) fn new(
        region_id: RegionId,
        reply: crate::channel::oneshot::Sender<Vec<TaskId>>,
    ) -> Self {
        Self {
            region_id,
            reply,
            tasks: Vec::new(),
        }
    }

    /// Collects the live tasks of the region subtree, in depth-first order.
    /// An unknown or reclaimed region contributes nothing.
    pub(crate) fn apply(mut self, state: &crate::runtime::state::RuntimeState) -> Self {
        let mut regions = vec![self.region_id];
        while let Some(region) = regions.pop() {
            if let Some(record) = state.region(region) {
                record.copy_task_ids_into(&mut self.tasks);
                record.copy_child_ids_into(&mut regions);
            }
        }
        self
    }

    pub(crate) fn publish(self) {
        let _ = self.reply.send_blocking(self.tasks);
    }
}

/// Crate-private finalizer admission with an owned acknowledgment. A rejected
/// callback remains in this request and is dropped only after publication,
/// outside the native runtime state lock.
pub(crate) struct RegisterRegionFinalizer {
    region_id: RegionId,
    finalizer: Option<Box<dyn FnOnce() + Send + 'static>>,
    completion: Option<
        crate::channel::oneshot::Sender<
            Result<(), crate::runtime::region_table::RegionCreateError>,
        >,
    >,
    outcome: Option<Result<(), crate::runtime::region_table::RegionCreateError>>,
}

impl fmt::Debug for RegisterRegionFinalizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterRegionFinalizer")
            .field("region_id", &self.region_id)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl RegisterRegionFinalizer {
    pub(crate) fn new(
        region_id: RegionId,
        finalizer: impl FnOnce() + Send + 'static,
        completion: crate::channel::oneshot::Sender<
            Result<(), crate::runtime::region_table::RegionCreateError>,
        >,
    ) -> Self {
        Self {
            region_id,
            finalizer: Some(Box::new(finalizer)),
            completion: Some(completion),
            outcome: None,
        }
    }

    pub(crate) fn apply(mut self, state: &mut crate::runtime::state::RuntimeState) -> Self {
        use crate::runtime::region_table::RegionCreateError;
        let refusal = match state.region(self.region_id) {
            None => Some(RegionCreateError::ParentNotFound(self.region_id)),
            Some(region) if region.state().is_closing() || region.state().is_terminal() => {
                Some(RegionCreateError::ParentClosed {
                    region: self.region_id,
                    state: region.state(),
                })
            }
            Some(_) => None,
        };
        self.outcome = Some(if let Some(error) = refusal {
            Err(error)
        } else {
            let finalizer = self.finalizer.take().expect("unapplied region finalizer");
            assert!(
                state.register_sync_finalizer(self.region_id, finalizer),
                "finalizer admission changed under the runtime state lock"
            );
            Ok(())
        });
        self
    }

    pub(crate) fn publish(mut self) {
        let completion = self
            .completion
            .take()
            .expect("unpublished finalizer admission");
        let outcome = self.outcome.take().expect("applied finalizer admission");
        let _ = completion.send_blocking(outcome);
    }
}

/// Worker-published outcome parts of one successfully minted child region.
///
/// Everything a caller needs to own the child region without ever holding
/// `RuntimeState`: the child identity, an admission-built child capability
/// context, and the shared close-state handle quiescence awaits poll.
pub struct AdmittedRegion {
    pub(crate) region_id: RegionId,
    /// Authoritative parent, including a sealed-region fallback chosen at mint.
    pub(crate) parent: RegionId,
    pub(crate) cx: crate::cx::Cx,
    pub(crate) close_notify: Arc<Mutex<crate::record::region::RegionCloseState>>,
    pub(crate) close_receipt: Arc<Mutex<Option<crate::record::region::RegionCloseOutcome>>>,
}

/// The sealed child region admission minted for one race branch
/// (br-asupersync-issue65-criticisms-kpmoy5.2.2).
pub(crate) struct MintedBranchRegion {
    pub(crate) region_id: RegionId,
    close_notify: Arc<Mutex<crate::record::region::RegionCloseState>>,
}

impl MintedBranchRegion {
    /// True once the region reached `Closed`.
    pub(crate) fn is_closed(&self) -> bool {
        self.close_notify.lock().closed
    }

    pub(crate) fn close_notify(&self) -> &Arc<Mutex<crate::record::region::RegionCloseState>> {
        &self.close_notify
    }
}

impl fmt::Debug for MintedBranchRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedBranchRegion")
            .field("region_id", &self.region_id)
            .finish_non_exhaustive()
    }
}

/// One-shot slot through which spawn admission publishes the sealed region it
/// minted for a race branch. It stays empty when admission denied the spawn
/// or could not mint a region (the task then runs in the requested region, as
/// before branch regions existed).
#[derive(Debug, Default)]
pub(crate) struct BranchRegionSlot {
    minted: OnceLock<MintedBranchRegion>,
}

impl BranchRegionSlot {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self) -> Option<&MintedBranchRegion> {
        self.minted.get()
    }

    /// Publishes the minted region. Called once, by admission, under the
    /// runtime state lock; it wakes nobody.
    pub(crate) fn publish(
        &self,
        region_id: RegionId,
        close_notify: Arc<Mutex<crate::record::region::RegionCloseState>>,
    ) {
        let _ = self.minted.set(MintedBranchRegion {
            region_id,
            close_notify,
        });
    }
}

/// One-shot slot the worker fills when a `RegionCommand::Create` resolves.
///
/// Mirrors the publish-after-admission discipline of [`AdmittedTaskSlot`]:
/// producers enqueue with the slot attached, workers publish exactly once,
/// and waiting futures register their wakers here so publication wakes them
/// directly.
///
/// # Single-consumer contract
///
/// Exactly one [`crate::cx::ChildRegionOpening`] polls a given slot — the
/// opening returned by the same `open_child_region` call that minted it.
/// `take` removes the outcome, so a second consumer would either hang (value
/// already taken) or spin (registered after publication); neither can occur
/// under this contract, and neither is handled.
#[derive(Default)]
pub struct AdmittedRegionSlot {
    inner: Mutex<Option<Result<AdmittedRegion, crate::runtime::region_table::RegionCreateError>>>,
    waiters: Mutex<Vec<std::task::Waker>>,
    // Both flags change only while `inner` is locked, so publication and
    // abandonment are ordered against each other.
    published: AtomicBool,
    // The opening was dropped before taking the outcome; publication closes
    // the minted region itself instead of storing it for nobody.
    abandoned: AtomicBool,
}

impl fmt::Debug for AdmittedRegionSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pending = self.inner.lock().is_none();
        f.debug_struct("AdmittedRegionSlot")
            .field("pending", &pending)
            .finish()
    }
}

impl AdmittedRegionSlot {
    /// Creates an empty, unresolved slot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes the mint outcome exactly once. Later publications are
    /// ignored (first writer wins) and all registered wakers are woken.
    pub(crate) fn publish(
        &self,
        result: Result<AdmittedRegion, crate::runtime::region_table::RegionCreateError>,
    ) {
        let (waiters, orphan) = {
            let mut inner = self.inner.lock();
            if self.published.load(Ordering::Acquire) {
                return;
            }
            self.published.store(true, Ordering::Release);
            let orphan = if self.abandoned.load(Ordering::Acquire) {
                Some(result)
            } else {
                *inner = Some(result);
                None
            };
            (std::mem::take(&mut *self.waiters.lock()), orphan)
        };
        // Nobody will take a region minted for a dropped opening. Its handle's
        // drop backstop queues the close, so the region cannot stay open
        // without an owner (and park its parent's close).
        if let Some(Ok(admitted)) = orphan {
            drop(crate::cx::ChildRegion::<crate::cx::cap::All>::from_admitted(admitted));
        }
        for waker in waiters {
            waker.wake();
        }
    }

    /// Returns the published outcome, taking it out of the slot.
    pub fn take(
        &self,
    ) -> Option<Result<AdmittedRegion, crate::runtime::region_table::RegionCreateError>> {
        self.inner.lock().take()
    }

    /// Returns true while the mint outcome is still pending.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        let _inner = self.inner.lock();
        !self.published.load(Ordering::Acquire)
    }

    pub(crate) fn register(&self, waker: std::task::Waker) {
        // Hold `inner` through the push: publication takes the waiters while
        // holding it, so it either sees this waker or has already published,
        // which this check observes.
        let inner = self.inner.lock();
        if self.published.load(Ordering::Acquire) {
            drop(inner);
            waker.wake_by_ref();
            return;
        }
        let mut waiters = self.waiters.lock();
        if !waiters
            .iter()
            .any(|registered| registered.will_wake(&waker))
        {
            waiters.push(waker);
        }
    }

    /// Wakes every registered opening without publishing. Runtime teardown
    /// calls this for a Create command it retires unapplied: the runtime's
    /// liveness token is already gone, so each re-poll finds an empty slot and
    /// a dead runtime and resolves as `ChildRegionError::RuntimeUnavailable`
    /// (br-asupersync-fbifws).
    pub(crate) fn wake_waiters(&self) {
        let waiters = {
            let _inner = self.inner.lock();
            std::mem::take(&mut *self.waiters.lock())
        };
        for waker in waiters {
            waker.wake();
        }
    }

    /// Marks the slot as abandoned by its only consumer and returns an
    /// outcome that was published but not taken, for the caller to close.
    /// A later publication closes the region it mints instead.
    pub(crate) fn abandon(
        &self,
    ) -> Option<Result<AdmittedRegion, crate::runtime::region_table::RegionCreateError>> {
        let mut inner = self.inner.lock();
        self.abandoned.store(true, Ordering::Release);
        inner.take()
    }
}

/// A runtime watch (monitor or link) that a task outside the runtime may be
/// awaiting: runtime teardown wakes it so its re-poll observes the dead
/// runtime (br-asupersync-werypv).
pub(crate) trait TeardownWake: Send + Sync {
    fn wake_for_teardown(&self);
}

/// Lock-free multi-producer intake mailbox for spawn requests, handle cancellations,
/// and region lifecycle commands.
///
/// Producers enqueue from any thread without holding `RuntimeState`; scheduler
/// worker threads consume requests under admission turns.
///
/// # Concurrency & Multi-Worker Ordering (br-asupersync-01oghn L4)
///
/// The mailbox maintains three independent lock-free lanes:
/// - `queue`: incoming spawn requests
/// - `handle_cancels`: handle cancellation requests
/// - `region_commands`: region lifecycle commands (create, cancel, close)
///
/// Each lane is backed by a lock-free `GlobalFifoQueue`. The FIFO guarantees
/// documented on dequeue operations hold for a single logical consumer. On
/// multi-worker runtimes, multiple workers dequeue and execute requests
/// concurrently:
/// 1. **Cross-lane ordering:** The lanes are drained concurrently; there is no
///    global total order across different request types without state-lock
///    synchronization. For instance, a cancel queued on `handle_cancels` and a
///    close command queued on `region_commands` may be dequeued in parallel.
/// 2. **Per-region ordering:** While requests in the same queue are popped in
///    FIFO order, concurrent worker threads processing distinct requests for
///    the same region interleave their execution. State transitions synchronize
///    under the `RuntimeState` lock upon admission.
pub struct SpawnMailbox {
    queue: GlobalFifoQueue<SpawnRequest>,
    handle_cancels: GlobalFifoQueue<HandleCancelRequest>,
    region_commands: GlobalFifoQueue<RegionCommand>,
    local_task_retirements: GlobalFifoQueue<LocalTaskRetirement>,
    ids: SpawnIdAllocator,
    trace: Option<TraceBufferHandle>,
    total_enqueued: AtomicU64,
    total_dequeued: AtomicU64,
    /// Runtime watches opened through this mailbox's gateway, woken at
    /// teardown. Weak: a dropped watch needs nothing.
    teardown_watches: Mutex<Vec<Weak<dyn TeardownWake>>>,
}

impl SpawnMailbox {
    /// Creates a new mailbox with no trace buffer attached.
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: GlobalFifoQueue::default(),
            handle_cancels: GlobalFifoQueue::default(),
            region_commands: GlobalFifoQueue::default(),
            local_task_retirements: GlobalFifoQueue::default(),
            ids: SpawnIdAllocator::new(),
            trace: None,
            total_enqueued: AtomicU64::new(0),
            total_dequeued: AtomicU64::new(0),
            teardown_watches: Mutex::new(Vec::new()),
        }
    }

    /// Registers a runtime watch to be woken at teardown. Watches that were
    /// dropped are pruned here, so the list stays as long as the live ones.
    pub(crate) fn register_teardown_wake(&self, watch: Weak<dyn TeardownWake>) {
        let mut watches = self.teardown_watches.lock();
        watches.retain(|registered| registered.strong_count() > 0);
        watches.push(watch);
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
    /// [`TraceEventKind::TaskSpawnEnqueued`](crate::trace::event::TraceEventKind::TaskSpawnEnqueued)
    /// *before* publishing the request
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

    pub(crate) fn enqueue_handle_cancel(&self, task_id: TaskId, reason: CancelReason) {
        self.handle_cancels.push(HandleCancelRequest {
            task_id,
            reason,
            admitted_slot: None,
        });
    }

    pub(crate) fn enqueue_handle_cancel_with_admitted_slot(
        &self,
        task_id: TaskId,
        reason: CancelReason,
        admitted_slot: Arc<AdmittedTaskSlot>,
    ) {
        self.handle_cancels.push(HandleCancelRequest {
            task_id,
            reason,
            admitted_slot: Some(admitted_slot),
        });
    }

    pub(crate) fn dequeue_handle_cancels_into(
        &self,
        max: usize,
        out: &mut Vec<HandleCancelRequest>,
    ) -> usize {
        self.handle_cancels.pop_batch_into(max, out)
    }

    #[must_use]
    pub(crate) fn handle_cancels_are_empty(&self) -> bool {
        self.handle_cancels.is_empty()
    }

    /// Pop one at a time: completion can unwind under the configured leak
    /// policy, and later retirements must remain queued for another turn.
    pub(crate) fn dequeue_local_task_retirement(&self) -> Option<LocalTaskRetirement> {
        self.local_task_retirements.pop()
    }

    #[must_use]
    pub(crate) fn local_task_retirements_are_empty(&self) -> bool {
        self.local_task_retirements.is_empty()
    }

    /// Returns true when the spawn-request lane itself is empty. Runtime
    /// admission uses this narrower predicate; scheduler parking and Lab
    /// quiescence use [`Self::is_empty`] across both work lanes.
    #[must_use]
    pub(crate) fn spawn_requests_are_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Enqueues a region lifecycle command. Never blocks and never drops.
    pub(crate) fn enqueue_region_command(&self, command: RegionCommand) {
        self.region_commands.push(command);
    }

    /// Dequeues up to `max` region commands into `out`, preserving FIFO
    /// order. Returns the number drained.
    pub(crate) fn dequeue_region_commands_into(
        &self,
        max: usize,
        out: &mut Vec<RegionCommand>,
    ) -> usize {
        self.region_commands.pop_batch_into(max, out)
    }

    /// Retire unapplied lifecycle commands after publishers and consumers
    /// have stopped. Retained contexts can keep this mailbox alive beyond
    /// runtime teardown, so waiting for its destructor would strand finalizer
    /// acknowledgments. Run only outside runtime and shard locks.
    ///
    /// An opening waiting on a retired Create or watch command is woken, and
    /// so is every registered runtime watch: they check liveness only when
    /// polled, and the runtime is gone by now (br-asupersync-fbifws,
    /// br-asupersync-werypv).
    pub(crate) fn retire_region_commands(&self) {
        // Task-table teardown owns any remaining local records at this point.
        // Retained Cx values can keep the mailbox itself alive.
        while self.dequeue_local_task_retirement().is_some() {}
        let watches = std::mem::take(&mut *self.teardown_watches.lock());
        for watch in watches.iter().filter_map(Weak::upgrade) {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| watch.wake_for_teardown()))
            {
                std::mem::forget(payload);
            }
        }
        let mut commands = Vec::new();
        while self.dequeue_region_commands_into(64, &mut commands) > 0 {
            for command in commands.drain(..) {
                let retire = || {
                    match &command {
                        RegionCommand::Create(request) => request.slot.wake_waiters(),
                        RegionCommand::Watch(watch) => watch.wake_unapplied(),
                        _ => {}
                    }
                    drop(command);
                };
                if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(retire))
                {
                    // Retention values and panic payloads can have arbitrary
                    // destructors. One failure cannot strand later senders.
                    std::mem::forget(payload);
                }
            }
        }
    }

    #[must_use]
    pub(crate) fn region_commands_are_empty(&self) -> bool {
        self.region_commands.is_empty()
    }

    /// Best-effort snapshot of queued spawn requests, handle cancellations,
    /// local task retirements, and region lifecycle commands. Lifetime
    /// enqueue/dequeue counters below remain spawn-only.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue
            .len()
            .saturating_add(self.handle_cancels.len())
            .saturating_add(self.region_commands.len())
            .saturating_add(self.local_task_retirements.len())
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
            && self.handle_cancels.is_empty()
            && self.region_commands.is_empty()
            && self.local_task_retirements.is_empty()
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
    scoped_cpu_admission: Arc<crate::cx::scoped_cpu::ScopedCpuAdmission>,
    /// Managed supervisors record their restart history here for the lab's
    /// supervision oracle (br-asupersync-52hxjz). Only the lab sets it.
    supervision_history: Option<crate::runtime::state::SupervisionHistoryHandle>,
    /// GenServer replies record their resolution here for the lab's
    /// reply-linearity oracle (br-asupersync-52hxjz). Only the lab sets it.
    reply_history: Option<crate::runtime::state::ReplyHistoryHandle>,
}

impl SpawnGateway {
    /// Creates a gateway. `notify` wakes the consumer side after enqueue
    /// (a worker coordinator in production; a no-op in the lab, whose step
    /// loop drains synchronously).
    #[must_use]
    pub(crate) fn new(
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
            scoped_cpu_admission: Arc::new(crate::cx::scoped_cpu::ScopedCpuAdmission::new(
                usize::MAX,
            )),
            supervision_history: None,
            reply_history: None,
        }
    }

    /// Hands managed supervisors a history for the lab's supervision oracle
    /// (br-asupersync-52hxjz).
    #[must_use]
    pub(crate) fn with_supervision_history(
        mut self,
        history: crate::runtime::state::SupervisionHistoryHandle,
    ) -> Self {
        self.supervision_history = Some(history);
        self
    }

    /// The supervision history, on runtimes that record one (the lab).
    #[must_use]
    pub(crate) fn supervision_history(
        &self,
    ) -> Option<&crate::runtime::state::SupervisionHistoryHandle> {
        self.supervision_history.as_ref()
    }

    /// Hands GenServer replies a history for the lab's reply-linearity
    /// oracle (br-asupersync-52hxjz).
    #[must_use]
    pub(crate) fn with_reply_history(
        mut self,
        history: crate::runtime::state::ReplyHistoryHandle,
    ) -> Self {
        self.reply_history = Some(history);
        self
    }

    /// The reply history, on runtimes that record one (the lab).
    #[must_use]
    pub(crate) fn reply_history(&self) -> Option<&crate::runtime::state::ReplyHistoryHandle> {
        self.reply_history.as_ref()
    }

    /// Configures the runtime-wide ceiling for borrowed scoped CPU workers.
    pub(crate) fn set_scoped_cpu_worker_limit(&self, limit: usize) {
        self.scoped_cpu_admission.set_limit(limit);
    }

    /// Returns the runtime-owned scoped CPU admission pool.
    #[must_use]
    pub(crate) fn scoped_cpu_admission(&self) -> Arc<crate::cx::scoped_cpu::ScopedCpuAdmission> {
        Arc::clone(&self.scoped_cpu_admission)
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

    /// Publishes prepared batch members in input order with one notification.
    ///
    /// This remains one queue insertion and one enqueue trace event per member;
    /// consumers can admit a prefix while the producer publishes the remainder.
    /// The shared timestamp is sampled once and runtime liveness covers the
    /// entire publication. An empty batch neither needs liveness nor wakes a
    /// worker. On runtime loss every request is resolved before returning.
    pub(crate) fn enqueue_batch_and_notify(
        &self,
        requests: Vec<SpawnRequest>,
    ) -> Result<(), SpawnError> {
        if requests.is_empty() {
            return Ok(());
        }
        let Some(_liveness_guard) = self.liveness_guard() else {
            for request in requests {
                request
                    .into_parts()
                    .resolve_failed(SpawnError::RuntimeUnavailable);
            }
            return Err(SpawnError::RuntimeUnavailable);
        };
        let now = self
            .clock
            .as_ref()
            .map_or(Time::ZERO, crate::time::TimerDriverHandle::now);
        for request in requests {
            self.mailbox.enqueue(request, now);
        }
        (self.notify)();
        Ok(())
    }

    /// Enqueues a task-handle cancellation command and wakes a worker. The
    /// command contains no Wakers or user callbacks, so this is safe from a
    /// caller's `Drop` stack and while the caller holds unrelated locks.
    pub(crate) fn enqueue_handle_cancel(&self, task_id: TaskId, reason: CancelReason) -> bool {
        let Some(_liveness_guard) = self.liveness_guard() else {
            return false;
        };
        self.mailbox.enqueue_handle_cancel(task_id, reason);
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (self.notify)();
        })) {
            // TaskHandle abort and JoinFuture::drop are fail-closed boundaries:
            // a broken runtime notifier must not unwind through caller code.
            std::mem::forget(payload);
        }
        true
    }

    /// Called after a local future's destructor, including from TLS teardown.
    /// The liveness guard excludes publication after the final shutdown drain;
    /// a notifier panic must never escape the owner's destructor stack.
    pub(crate) fn enqueue_local_task_retirement(&self, retirement: LocalTaskRetirement) {
        let Some(_liveness_guard) = self.liveness_guard() else {
            return;
        };
        self.mailbox.local_task_retirements.push(retirement);
        self.notify_handle_cancel();
    }

    pub(crate) fn enqueue_handle_cancel_with_admitted_slot(
        &self,
        task_id: TaskId,
        reason: CancelReason,
        admitted_slot: Arc<AdmittedTaskSlot>,
    ) -> bool {
        if !self.enqueue_handle_cancel_with_admitted_slot_without_notify(
            task_id,
            reason,
            admitted_slot,
        ) {
            return false;
        }
        self.notify_handle_cancel();
        true
    }

    fn enqueue_handle_cancel_with_admitted_slot_without_notify(
        &self,
        task_id: TaskId,
        reason: CancelReason,
        admitted_slot: Arc<AdmittedTaskSlot>,
    ) -> bool {
        let Some(_liveness_guard) = self.liveness_guard() else {
            return false;
        };
        if let Some(admitted) = admitted_slot.get() {
            // This store linearizes producer visibility with a command that is
            // guaranteed to enter the mailbox while the liveness guard is held.
            // If liveness has expired, the slot remains Pending and no task
            // lane or observer is falsely published.
            admitted.mark_published();
        }
        self.mailbox
            .enqueue_handle_cancel_with_admitted_slot(task_id, reason, admitted_slot);
        true
    }

    /// Enqueues a region lifecycle command and wakes the consumer side.
    ///
    /// Fails closed with [`SpawnError::RuntimeUnavailable`] when the owning
    /// runtime is already gone; the failure is observed by the caller before
    /// any slot is awaited, so a dropped runtime can never hang an opening.
    pub(crate) fn enqueue_region_command(&self, command: RegionCommand) -> Result<(), SpawnError> {
        let Some(_liveness_guard) = self.liveness_guard() else {
            return Err(SpawnError::RuntimeUnavailable);
        };
        self.mailbox.enqueue_region_command(command);
        // Region commands resolve caller-shared slots, so a broken notifier
        // must not unwind through caller code (same fail-closed boundary as
        // handle cancels).
        self.notify_handle_cancel();
        Ok(())
    }

    fn notify_handle_cancel(&self) {
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            (self.notify)();
        })) {
            std::mem::forget(payload);
        }
    }

    /// Clones the gateway's runtime liveness token for producer-side
    /// fail-closed checks while a mint publication is still pending.
    #[must_use]
    pub(crate) fn runtime_liveness_weak(&self) -> std::sync::Weak<()> {
        std::sync::Weak::clone(&self.runtime_liveness)
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
#[path = "spawn_mailbox_inline_tests.rs"]
mod tests;
