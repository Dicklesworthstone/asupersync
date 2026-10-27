//! The capability context type.
//!
//! `Cx` is the token that grants access to runtime capabilities:
//! - Querying identity (region ID, task ID)
//! - Checking cancellation status
//! - Yielding and sleeping
//! - Tracing
//!
//! # Capability Model
//!
//! Runtime-managed effectful operations in Asupersync flow through explicit
//! `Cx` or narrower capability tokens. Host-boundary adapters and test support
//! may use ambient OS services only when the boundary is documented and kept
//! outside deterministic runtime guarantees unless reached through a
//! capability-mediated path. This design narrows ambient authority and enables:
//!
//! - **Effect interception**: Production vs lab runtime can interpret effects differently
//! - **Cancellation propagation**: Cx carries cancellation signals through the task tree
//! - **Budget enforcement**: Deadlines and poll quotas flow through Cx
//! - **Observability**: Tracing and spans are tied to task identity
//!
//! # Thread Safety
//!
//! `Cx` is `Send + Sync` due to its internal `Arc<RwLock>`. However, the semantic
//! contract is that a `Cx` is associated with a specific task and should not be
//! shared across task boundaries. The runtime manages Cx lifetime and ensures
//! each task receives its own context.
//!
//! # Wrapping Cx for Frameworks
//!
//! Framework authors (e.g., fastapi_rust) should wrap `Cx` rather than store it directly:
//!
//! ```ignore
//! // CORRECT: Wrap Cx reference, delegate capabilities
//! pub struct RequestContext<'a> {
//!     cx: &'a Cx,
//!     request: &'a Request,
//!     // framework-specific fields
//! }
//!
//! impl<'a> RequestContext<'a> {
//!     pub fn check_cancelled(&self) -> bool {
//!         self.cx.is_cancel_requested()
//!     }
//!
//!     pub fn budget(&self) -> Budget {
//!         self.cx.budget()
//!     }
//! }
//! ```
//!
//! This pattern ensures:
//! - Cx lifetime is tied to the request scope
//! - Framework can add domain-specific context
//! - All capabilities flow through the wrapped Cx

use super::cap;
use super::macaroon::{MacaroonToken, VerificationContext, VerificationError};
use super::registry::RegistryHandle;
use crate::combinator::select::SelectAll;
use crate::evidence_sink::EvidenceSink;
#[cfg(feature = "messaging-fabric")]
use crate::messaging::capability::{
    FabricCapability, FabricCapabilityGrant, FabricCapabilityGrantError, FabricCapabilityId,
    FabricCapabilityRegistry, FabricCapabilityScope, GrantedFabricToken, PublishPermit,
    SubjectFamilyTag, SubscribeToken,
};
#[cfg(feature = "messaging-fabric")]
use crate::messaging::class::DeliveryClass;
#[cfg(feature = "messaging-fabric")]
use crate::messaging::ir::CapabilityTokenSchema;
#[cfg(feature = "messaging-fabric")]
use crate::messaging::subject::SubjectPattern;
use crate::observability::{
    DiagnosticContext, LogCollector, LogEntry, ObservabilityConfig, SpanId,
};
use crate::remote::RemoteCap;
use crate::runtime::blocking_pool::BlockingPoolHandle;
use crate::runtime::io_driver::IoDriverHandle;
#[cfg(unix)]
use crate::runtime::io_driver::IoRegistration;
#[cfg(unix)]
use crate::runtime::reactor::{Interest, Source};
use crate::runtime::state::LoserDrainHistoryHandle;
use crate::runtime::task_handle::JoinError;
use crate::time::{TimerDriverHandle, timeout};
use crate::trace::distributed::{LogicalClockHandle, LogicalTime};
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::{debug, error, info, trace, warn};
use crate::types::task_context::{CancelWaker, CancelWakerRegistration, CxCancellationState};
use crate::types::{
    Budget, CancelKind, CancelReason, CapabilityBudget, CapabilityBudgetRefusal,
    CapabilityBudgetRequirements, CxInner, RegionId, SystemPressure, TaskId, Time,
};
use crate::util::{ArenaIndex, EntropySource, OsEntropy};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Waker;
use std::time::Duration;

type NamedFuture<T> = (&'static str, Pin<Box<dyn Future<Output = T> + Send>>);
type NamedFutures<T> = Vec<NamedFuture<T>>;

/// Get the current wall clock time.
fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

/// Maximum allowed length of a `task_type` label value. Sized to fit the
/// dot-separated identifier conventions used by gRPC service names
/// (`package.Service.Method`) without admitting unbounded user input.
/// (br-asupersync-9vpwpc)
const MAX_TASK_TYPE_LEN: usize = 64;

/// Returns true if `s` is a syntactically safe `task_type` label.
///
/// A safe value is non-empty, ≤ [`MAX_TASK_TYPE_LEN`] bytes, starts with
/// an ASCII letter, and contains only ASCII alphanumerics plus the
/// punctuation `_`, `.`, `-`, `:`. This rejects the high-entropy shapes
/// typical of PII (UUIDs, base64 tokens, email addresses contain `@`,
/// user-id-templated formats contain `{}`, etc.) and the whitespace /
/// control characters that would corrupt OpenTelemetry label exports.
/// (br-asupersync-9vpwpc)
pub(crate) fn is_valid_task_type(s: &str) -> bool {
    if s.is_empty() || s.len() > MAX_TASK_TYPE_LEN {
        return false;
    }
    let mut bytes = s.bytes();
    let first = bytes.next().expect("checked non-empty above");
    if !first.is_ascii_alphabetic() {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'))
}

#[cfg(unix)]
fn noop_waker() -> Waker {
    Waker::noop().clone()
}

/// Grouped handle fields shared behind a single `Arc` to reduce per-clone
/// refcount operations from ~13 to 1 for this bundle.
#[derive(Clone)]
struct DefaultHttpClientSlot {
    inner: Arc<std::sync::OnceLock<crate::http::h1::HttpClient>>,
}

impl Default for DefaultHttpClientSlot {
    fn default() -> Self {
        Self {
            inner: Arc::new(std::sync::OnceLock::new()),
        }
    }
}

impl std::fmt::Debug for DefaultHttpClientSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefaultHttpClientSlot")
            .field("initialized", &self.inner.get().is_some())
            .finish_non_exhaustive()
    }
}

impl DefaultHttpClientSlot {
    fn get_or_init(&self) -> crate::http::h1::HttpClient {
        self.inner
            .get_or_init(crate::http::h1::HttpClient::new)
            .clone()
    }
}

#[derive(Debug, Clone)]
struct CxHandles {
    io_driver: Option<IoDriverHandle>,
    io_cap: Option<Arc<dyn crate::io::IoCap>>,
    timer_driver: Option<TimerDriverHandle>,
    blocking_pool: Option<BlockingPoolHandle>,
    entropy: Arc<dyn EntropySource>,
    logical_clock: LogicalClockHandle,
    /// Runtime identity for the opt-in lab task-causality producer. Kept out
    /// of clock component names so identical lab workloads remain replayable.
    task_causality_runtime: Option<u64>,
    remote_cap: Option<Arc<RemoteCap>>,
    registry: Option<RegistryHandle>,
    pressure: Option<Arc<SystemPressure>>,
    evidence_sink: Option<Arc<dyn EvidenceSink>>,
    macaroon: Option<Arc<MacaroonToken>>,
    /// Producer-side spawn gateway (br-asupersync-hwjqyo / A2.2): lets
    /// `Cx::spawn` enqueue without the RuntimeState lock.
    spawn_gateway: Option<Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    /// Pending-spawn counter for THIS Cx's region (cloned under the state
    /// lock at Cx build time; credits gate region close per A1.2).
    pending_spawns: Option<Arc<crate::record::region::PendingSpawnCounter>>,
    /// Obligation mailbox gateway (br-asupersync-bi2462.13).
    ///
    /// Lets `Cx::try_register_obligation` mint a runtime-tracked obligation
    /// without the RuntimeState lock. `None` for a Cx built without a runtime.
    obligation_gateway: Option<Arc<crate::runtime::obligation_mailbox::ObligationGateway>>,
    obligation_admission: Option<Arc<crate::record::region::ObligationAdmissionHandle>>,
    /// Explicit provenance survives intentionally stripped gateway handles.
    runtime_obligation_context: bool,
    /// Pending obligation-post counter for THIS Cx's region.
    ///
    /// Same shape and role as `pending_spawns`: a live token holds one
    /// credit so region close and drain gating see the reservation before it
    /// is applied.
    pending_obligation_posts: Option<Arc<crate::record::region::PendingSpawnCounter>>,
    /// Runtime-scoped default HTTP client slot. It is lazy so Cx creation does
    /// not allocate a pool unless the high-level HTTP facade is used.
    default_http_client: DefaultHttpClientSlot,
    #[cfg(feature = "messaging-fabric")]
    fabric_capabilities: Arc<FabricCapabilityRegistry>,
}

/// The handles a spawned task inherits from the context that spawned it.
///
/// The spawner takes this snapshot and moves it into the task's admission
/// slot. Admission builds the task's record context with it, and that record
/// context is what `Cx::current()` returns inside the task. The context the
/// spawn closure receives shares it, so both carry the same handles
/// (br-asupersync-93zkbz).
pub(crate) struct InheritedHandles {
    /// Taken by admission, which forks it for the task in spawn order.
    entropy: Option<Arc<dyn EntropySource>>,
    io_cap: Option<Arc<dyn crate::io::IoCap>>,
    registry: Option<RegistryHandle>,
    remote_cap: Option<Arc<RemoteCap>>,
    blocking_pool: Option<BlockingPoolHandle>,
    evidence_sink: Option<Arc<dyn EvidenceSink>>,
    macaroon: Option<Arc<MacaroonToken>>,
    default_http_client: DefaultHttpClientSlot,
    pressure: Option<Arc<SystemPressure>>,
    /// Captured when the spawn is requested, not when its mailbox is drained.
    task_causality: Option<(u64, LogicalTime)>,
}

impl InheritedHandles {
    pub(crate) fn task_causality(&self) -> Option<&(u64, LogicalTime)> {
        self.task_causality.as_ref()
    }

    /// The child's entropy source: the spawner's, forked for `task` now, in
    /// admission (spawn) order, under the runtime lock; only a user fork that
    /// panics is deferred to the task's first poll (`fork_contained`).
    pub(crate) fn deferred_entropy(&mut self, task: TaskId) -> Arc<dyn EntropySource> {
        let parent = self
            .entropy
            .take()
            .expect("admission takes a task's inherited entropy once");
        fork_contained(&parent, task)
    }
}

use crate::util::entropy::fork_contained;

/// Opaque ownership token for one auxiliary cancellation-Waker registration.
///
/// Live IDs are checked-monotonic and never reused, so an old token cannot
/// clear a later ABA-identical registration after its original owner has gone
/// away. ID zero is the reusable closed-registry sentinel and never owns an
/// entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the token is required to refresh or clear this cancellation-Waker registration"]
pub(crate) struct CancelWakerToken {
    id: u64,
}

/// Timer waker armed by [`Cx::arm_budget_deadline`] (br-asupersync-pev2xi).
///
/// It holds the context weakly: the wheel never keeps a finished task's
/// context alive, and the context's [`BudgetDeadlineTimer`] guard removes the
/// timer when the context drops.
///
/// [`BudgetDeadlineTimer`]: crate::types::task_context::BudgetDeadlineTimer
struct BudgetDeadlineWake {
    inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
    deadline: Time,
    /// A timer can fire between registration and publication of its handle.
    /// Each registration owns its publication state: a losing concurrent arm
    /// must not borrow the winner's timer slot. All state transitions hold the
    /// same context lock, making the out-of-lock wake replay lossless.
    publication: std::sync::atomic::AtomicU8,
}

impl BudgetDeadlineWake {
    const UNPUBLISHED: u8 = 0;
    const WAKE_OWED: u8 = 1;
    const PUBLISHED: u8 = 2;

    /// Called only while holding the context write lock, after its timer slot
    /// has been installed or replaced.
    fn publish(&self) -> bool {
        self.publication
            .swap(Self::PUBLISHED, std::sync::atomic::Ordering::AcqRel)
            == Self::WAKE_OWED
    }
}

impl std::task::Wake for BudgetDeadlineWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        loop {
            let mut guard = inner.write();
            if guard.cancel_waker_registry_closed || guard.is_cancel_requested() {
                return;
            }
            if self.publication.load(std::sync::atomic::Ordering::Acquire) != Self::PUBLISHED {
                self.publication
                    .store(Self::WAKE_OWED, std::sync::atomic::Ordering::Release);
                return;
            }
            let Some(timer) = guard
                .budget_deadline_timer
                .as_ref()
                .map(|armed| armed.timer.clone())
            else {
                return;
            };
            if timer.now() < self.deadline {
                // A deadline past the wheel's horizon fires early at the
                // horizon: re-arm for the real deadline, as Sleep does.
                self.publication
                    .store(Self::UNPUBLISHED, std::sync::atomic::Ordering::Release);
                drop(guard);
                let handle = timer.register(self.deadline, Waker::from(Arc::clone(self)));
                let replacement = crate::types::task_context::BudgetDeadlineTimer { timer, handle };
                let mut guard = inner.write();
                if guard.cancel_waker_registry_closed
                    || guard.is_cancel_requested()
                    || guard.budget_deadline_timer.is_none()
                {
                    drop(guard);
                    drop(replacement);
                    return;
                }
                let retired = guard.budget_deadline_timer.replace(replacement);
                let replay = self.publish();
                drop(guard);
                drop(retired);
                if replay {
                    // A replacement can also fire before publication. Keep
                    // repeated horizon handoffs at constant stack depth.
                    continue;
                }
                return;
            }
            // The budget may have been replaced since the timer was armed;
            // only a deadline at or before this one has passed.
            if guard
                .budget
                .deadline
                .is_none_or(|deadline| deadline > self.deadline)
            {
                return;
            }
            let reason = CancelReason::with_origin(CancelKind::Deadline, guard.region, self.deadline)
                .with_task(guard.task);
            guard.set_cancel_requested(true);
            if let Some(existing) = guard.cancel_reason.as_mut() {
                existing.strengthen(&reason);
            } else {
                guard.cancel_reason = Some(reason);
            }
            let wakers = guard.cancel_waker_snapshot();
            guard.cancel_wakers_pending = false;
            drop(guard);
            crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
            return;
        }
    }
}

/// The capability context for a task.
///
/// `Cx` provides access to runtime capabilities within Asupersync.
/// Runtime-managed effectful operations flow through `Cx` or narrower
/// capability tokens, ensuring explicit capability security for the runtime
/// boundary while keeping any host-boundary exceptions documented and scoped.
///
/// # Overview
///
/// A `Cx` instance is provided to each task by the runtime. It grants access to:
///
/// - **Identity**: Query the current region and task IDs
/// - **Budget**: Check remaining time/poll quotas
/// - **Cancellation**: Observe and respond to cancellation requests
/// - **Tracing**: Emit trace events for observability
///
/// # Cloning
///
/// `Cx` is cheaply clonable (it wraps an `Arc`). Clones share the same
/// underlying state, so cancellation signals and budget updates are visible
/// to all clones.
#[derive(Debug)]
pub struct Cx<Caps = cap::All> {
    pub(crate) inner: Arc<parking_lot::RwLock<CxInner>>,
    /// Shared cancellation publication envelope from [`CxInner`].
    ///
    /// This `Arc` is cloned from the inner's private, stable envelope at
    /// construction. Public compatibility fields cannot replace the runtime's
    /// envelope, and scheduler-owned publishers use its Release-ordered method.
    /// Public queries additionally inspect the 0.4.3 lock-backed flag so
    /// direct legacy field mutation remains observable with its original
    /// semantics.
    cancellation: Arc<CxCancellationState>,
    observability: Arc<parking_lot::RwLock<ObservabilityState>>,
    handles: Arc<CxHandles>,
    /// br-asupersync-5ckssb: runtime capability mask. Mirrors the
    /// type-level `Caps` parameter for cx instances obtained the
    /// normal way (through the runtime / restrict / for_testing).
    /// For cx instances obtained via [`Cx::current`], this mask
    /// reflects the **innermost** restriction pushed onto the
    /// thread-local restriction stack — so an ambient lookup
    /// cannot escape a narrowing applied by an outer
    /// `set_current_restricted` or `push_restriction`.
    ///
    /// Cap-gated *Option*-returning methods (`io`, `remote`,
    /// `timer_driver`, `fetch_cap`) consult this mask in addition
    /// to the type-level `Caps` bound and return `None` when the
    /// runtime mask blocks the capability — this is the actual
    /// teeth of the ambient-authority defense.
    pub(crate) runtime_mask: cap::CapMask,
    // Use fn() -> Caps instead of just Caps to ensure Send+Sync regardless of Caps
    _caps: PhantomData<fn() -> Caps>,
}

// Manual Clone impl to avoid requiring `Caps: Clone` (Caps is just a phantom marker type).
// Four Arc increments: inner, stable cancellation envelope, observability, and handles
// (rather than ~15 before handle aggregation).
impl<Caps> Clone for Cx<Caps> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            cancellation: Arc::clone(&self.cancellation),
            observability: Arc::clone(&self.observability),
            handles: Arc::clone(&self.handles),
            runtime_mask: self.runtime_mask,
            _caps: PhantomData,
        }
    }
}

/// Boolean view of one capability layer.
///
/// The five effect bits come from [`cap::CapMask`]. `trace` is intentionally
/// always `true` today because tracing/logging is a diagnostic Cx operation,
/// not a type-level or runtime-mask-gated effect.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLayerSnapshot {
    /// Task/region spawning.
    pub spawn: bool,
    /// Timers, timeouts, and runtime time.
    pub time: bool,
    /// Entropy/randomness.
    pub entropy: bool,
    /// Async I/O.
    pub io: bool,
    /// Remote task/effect authority.
    pub remote: bool,
    /// Diagnostic tracing/logging. This is not currently CapMask-gated.
    pub trace: bool,
}

impl CapabilityLayerSnapshot {
    #[inline]
    #[must_use]
    fn from_mask(mask: cap::CapMask) -> Self {
        Self {
            spawn: mask.has(cap::CapMask::SPAWN),
            time: mask.has(cap::CapMask::TIME),
            entropy: mask.has(cap::CapMask::RANDOM),
            io: mask.has(cap::CapMask::IO),
            remote: mask.has(cap::CapMask::REMOTE),
            trace: true,
        }
    }
}

/// Point-in-time view of the capabilities visible through a [`Cx`].
///
/// The top-level booleans are the effective authority that cap-gated methods on
/// this receiver can observe: the type-level [`cap::CapSet`] row intersected
/// with the receiver's runtime mask. `type_level`, `runtime`, and `effective`
/// expose the same calculation in verbose form for diagnostics.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySnapshot {
    /// Effective task/region spawning authority.
    pub spawn: bool,
    /// Effective timer/time authority.
    pub time: bool,
    /// Effective entropy/randomness authority.
    pub entropy: bool,
    /// Effective async I/O authority.
    pub io: bool,
    /// Effective remote authority.
    pub remote: bool,
    /// Effective diagnostic tracing/logging authority.
    pub trace: bool,
    /// Capability row encoded by the `Cx<Caps>` type parameter.
    pub type_level: CapabilityLayerSnapshot,
    /// Runtime mask carried by this `Cx`.
    pub runtime: CapabilityLayerSnapshot,
    /// Intersection of `type_level` and `runtime`.
    pub effective: CapabilityLayerSnapshot,
}

impl CapabilitySnapshot {
    #[inline]
    #[must_use]
    fn new(type_mask: cap::CapMask, runtime_mask: cap::CapMask) -> Self {
        let type_level = CapabilityLayerSnapshot::from_mask(type_mask);
        let runtime = CapabilityLayerSnapshot::from_mask(runtime_mask);
        let effective = CapabilityLayerSnapshot::from_mask(type_mask.intersect(runtime_mask));
        Self {
            spawn: effective.spawn,
            time: effective.time,
            entropy: effective.entropy,
            io: effective.io,
            remote: effective.remote,
            trace: effective.trace,
            type_level,
            runtime,
            effective,
        }
    }
}

/// Deadline component of [`BudgetStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineBudgetStats {
    /// Absolute logical deadline, if configured.
    pub at: Option<Time>,
    /// Duration remaining at snapshot time. `None` means no deadline or an
    /// already elapsed deadline.
    pub remaining: Option<Duration>,
}

/// Poll-quota component of [`BudgetStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollBudgetStats {
    /// Original finite poll quota. `None` means effectively unlimited.
    pub quota: Option<u32>,
    /// Polls consumed since the context's baseline. `None` means unlimited.
    pub used: Option<u32>,
    /// Polls remaining. `None` means effectively unlimited.
    pub remaining: Option<u32>,
}

/// Cost-quota component of [`BudgetStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostBudgetStats {
    /// Original finite cost quota. `None` means no cost quota was configured.
    pub quota: Option<u64>,
    /// Cost units consumed since the context's baseline.
    pub used: Option<u64>,
    /// Cost units remaining.
    pub remaining: Option<u64>,
}

/// Point-in-time budget accounting snapshot for a [`Cx`].
///
/// The values are a diagnostic read: they are consistent at the moment of the
/// call, and may be stale by the next poll. Calling [`Cx::budget_stats`] drains
/// pending fast-path checkpoint counters into the authoritative checkpoint
/// state before taking the budget snapshot, preserving the existing
/// checkpoint-accounting invariant.
///
/// ```
/// use asupersync::cx::{
///     BudgetStats, CostBudgetStats, DeadlineBudgetStats, PollBudgetStats,
/// };
/// use std::time::Duration;
///
/// let stats = BudgetStats {
///     deadline: DeadlineBudgetStats {
///         at: None,
///         remaining: Some(Duration::from_millis(75)),
///     },
///     polls: PollBudgetStats {
///         quota: Some(8),
///         used: Some(2),
///         remaining: Some(6),
///     },
///     cost: CostBudgetStats {
///         quota: None,
///         used: None,
///         remaining: None,
///     },
///     priority: 128,
/// };
///
/// let has_time = stats
///     .deadline
///     .remaining
///     .is_none_or(|left| left > std::time::Duration::from_millis(25));
/// let has_polls = stats.polls.remaining.is_none_or(|left| left > 2);
/// assert!(has_time && has_polls);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetStats {
    /// Deadline headroom.
    pub deadline: DeadlineBudgetStats,
    /// Poll quota headroom.
    pub polls: PollBudgetStats,
    /// Cost quota headroom.
    pub cost: CostBudgetStats,
    /// Current scheduling priority.
    pub priority: u8,
}

impl BudgetStats {
    #[inline]
    #[must_use]
    fn from_budget_pair(budget: Budget, baseline: Budget, now: Time) -> Self {
        Self {
            deadline: DeadlineBudgetStats {
                at: budget.deadline,
                remaining: budget.remaining_time(now),
            },
            polls: PollBudgetStats {
                quota: finite_poll_quota(baseline.poll_quota),
                used: finite_poll_quota(baseline.poll_quota)
                    .map(|quota| quota.saturating_sub(budget.poll_quota)),
                remaining: finite_poll_quota(budget.poll_quota),
            },
            cost: CostBudgetStats {
                quota: baseline.cost_quota,
                used: match (baseline.cost_quota, budget.cost_quota) {
                    (Some(quota), Some(remaining)) => Some(quota.saturating_sub(remaining)),
                    _ => None,
                },
                remaining: budget.cost_quota,
            },
            priority: budget.priority,
        }
    }
}

#[inline]
#[must_use]
fn finite_poll_quota(quota: u32) -> Option<u32> {
    if quota == u32::MAX { None } else { Some(quota) }
}

/// Internal observability state shared by `Cx` clones.
#[derive(Debug, Clone)]
pub struct ObservabilityState {
    collector: Option<LogCollector>,
    context: DiagnosticContext,
    trace: Option<TraceBufferHandle>,
    loser_drain_history: Option<LoserDrainHistoryHandle>,
    include_timestamps: bool,
}

impl ObservabilityState {
    fn new(region: RegionId, task: TaskId) -> Self {
        let context = DiagnosticContext::new()
            .with_task_id(task)
            .with_region_id(region)
            .with_span_id(SpanId::new());
        Self {
            collector: None,
            context,
            trace: None,
            loser_drain_history: None,
            include_timestamps: true,
        }
    }

    pub(crate) fn new_with_config(
        region: RegionId,
        task: TaskId,
        config: &ObservabilityConfig,
        collector: Option<LogCollector>,
    ) -> Self {
        let context = config
            .create_diagnostic_context()
            .with_task_id(task)
            .with_region_id(region)
            .with_span_id(SpanId::new());
        Self {
            collector,
            context,
            trace: None,
            loser_drain_history: None,
            include_timestamps: config.include_timestamps(),
        }
    }

    fn derive_child(&self, region: RegionId, task: TaskId) -> Self {
        let mut context = self.context.clone().fork();
        context = context.with_task_id(task).with_region_id(region);
        Self {
            collector: self.collector.clone(),
            context,
            trace: self.trace.clone(),
            loser_drain_history: self.loser_drain_history.clone(),
            include_timestamps: self.include_timestamps,
        }
    }
}

/// Guard that restores the cancellation mask on drop.
struct MaskGuard<'a> {
    inner: &'a Arc<parking_lot::RwLock<CxInner>>,
}

impl Drop for MaskGuard<'_> {
    /// Implements `inv.cancel.mask_monotone` (#12): mask_depth only decreases
    /// during cancel processing. `saturating_sub` ensures no underflow.
    fn drop(&mut self) {
        let mut inner = self.inner.write();
        inner.mask_depth = inner.mask_depth.saturating_sub(1);
        drop(inner);
        super::cancel_observation::record(
            self.inner,
            super::cancel_observation::CancelObservation::MaskExit,
        );
    }
}

type FullCx = Cx<cap::All>;

/// A context that is built the first time an ambient lookup needs it: a
/// fiber's own context, derived from its task's only if the fiber reads it
/// (br-asupersync-98569u). `materialize` returns the same context on every
/// call once built. It runs under the thread-local stack's borrow, so it
/// must not install or read the ambient context itself.
pub(crate) trait LazyCurrentCx: Send + Sync + std::fmt::Debug {
    fn materialize(&self) -> &FullCx;
}

/// What a frame installs: a context, or one built on first use.
#[derive(Debug, Clone)]
enum FrameCx {
    Ready(FullCx),
    Lazy(Arc<dyn LazyCurrentCx>),
}

impl FrameCx {
    /// The installed context, built first if it is a lazy one.
    fn installed(&self) -> &FullCx {
        match self {
            Self::Ready(cx) => cx,
            Self::Lazy(lazy) => lazy.materialize(),
        }
    }
}

/// br-asupersync-5ckssb: a single frame on the thread-local
/// `CURRENT_CX_STACK`. Each `set_current` push records BOTH the cx
/// itself AND the runtime [`cap::CapMask`] under which it was
/// installed. `Cx::current()` walks the stack to find the innermost
/// frame and returns its cx with the frame's mask applied — so a
/// nested `set_current_restricted::<Cx<NoCaps>>(...)` makes any
/// subsequent ambient `Cx::current()` lookup observe `CapMask::none()`
/// even though the underlying inner state is shared.
#[derive(Debug, Clone)]
struct CurrentCxFrame {
    id: u64,
    cx: FrameCx,
    mask: cap::CapMask,
}

thread_local! {
    /// Stack of `(cx, mask)` frames. The top of the stack is the
    /// innermost installed context; `current()` returns from there.
    /// The historical `Option<FullCx>` semantic is preserved by the
    /// invariant that an empty stack means "no current cx" — i.e.
    /// `current()` returns `None`.
    static CURRENT_CX_STACK: RefCell<Vec<CurrentCxFrame>> = const { RefCell::new(Vec::new()) };
    /// Per-thread identity source for stack frames. Guard drops use this
    /// identity so an outer guard dropped before an inner guard cannot remove
    /// the inner capability restriction.
    static NEXT_CURRENT_CX_FRAME_ID: Cell<u64> = const { Cell::new(1) };
}

#[inline]
fn next_current_cx_frame_id() -> u64 {
    NEXT_CURRENT_CX_FRAME_ID.with(|next| {
        let id = next.get();
        next.set(
            id.checked_add(1)
                .expect("current Cx frame identity space exhausted"),
        );
        id
    })
}

/// Guard that pops the corresponding frame from the
/// `CURRENT_CX_STACK` on drop. (br-asupersync-5ckssb)
#[cfg_attr(feature = "test-internals", visibility::make(pub))]
/// Guard returned by ambient current-context installation helpers.
pub struct CurrentCxGuard {
    /// Identity of the exact frame installed by this guard. `None` means the
    /// caller installed no context.
    frame_id: Option<u64>,
    _not_send: std::marker::PhantomData<*mut ()>,
}

impl Drop for CurrentCxGuard {
    fn drop(&mut self) {
        let Some(frame_id) = self.frame_id.take() else {
            return;
        };
        let _ = CURRENT_CX_STACK.try_with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.last().is_some_and(|frame| frame.id == frame_id) {
                stack.pop();
            } else if let Some(index) = stack.iter().rposition(|frame| frame.id == frame_id) {
                stack.remove(index);
            } else {
                debug_assert!(false, "current Cx guard frame was already removed");
            }
        });
    }
}

impl FullCx {
    /// Returns the current task context, if one is set.
    ///
    /// This is set by the runtime while polling a task.
    ///
    /// br-asupersync-5ckssb: walks the thread-local restriction stack
    /// to find the **innermost** installed context. If an outer scope
    /// pushed a restricted cx (via [`Cx::set_current_restricted`] or
    /// [`Cx::push_restriction`]), the returned cx carries the
    /// narrowed runtime mask, so cap-gated *Option*-returning
    /// methods (`io`, `remote`, `timer_driver`, `fetch_cap`) return
    /// `None` for any capability blocked by the restriction. This
    /// closes the ambient-authority leak that previously let
    /// untrusted call sites obtain a full-cap cx via the ambient
    /// lookup regardless of the type-level `Caps` parameter on the
    /// cx they were given as a function argument.
    ///
    /// Returns `None` when no task context is installed and also during
    /// thread-local teardown, where the ambient context is no longer
    /// accessible.
    #[inline]
    #[must_use]
    pub fn current() -> Option<Self> {
        CURRENT_CX_STACK
            .try_with(|slot| {
                slot.borrow().last().map(|frame| {
                    let mut cx = frame.cx.installed().clone();
                    cx.runtime_mask = frame.mask;
                    cx
                })
            })
            .unwrap_or(None)
    }

    /// Returns `true` iff a task context is installed on the current
    /// thread, without cloning any of the cx's internal `Arc`s.
    ///
    /// br-asupersync-xqt7dj: zero-Arc-clone existence check. Equivalent
    /// to `Cx::current().is_some()` but avoids the 3 atomic ops on the
    /// strong-count fields (inner, observability, handles) that
    /// `Cx::current` performs to materialize a returnable owned value.
    /// Use this for tight async polls that only need to detect whether
    /// they are running under a task context (e.g., diagnostic hooks).
    #[inline]
    #[must_use]
    pub fn is_active() -> bool {
        CURRENT_CX_STACK
            .try_with(|slot| !slot.borrow().is_empty())
            .unwrap_or(false)
    }

    /// Returns the current thread-local Cx restriction-stack depth.
    ///
    /// `0` means no ambient context is installed. A plain runtime
    /// [`set_current`](Self::set_current) contributes one frame preserving the held mask;
    /// nested [`Cx::set_current_restricted`] or [`push_restriction`](Self::push_restriction)
    /// calls add frames that may narrow the ambient view observed by
    /// [`current`](Self::current).
    #[inline]
    #[must_use]
    pub fn restriction_depth() -> usize {
        CURRENT_CX_STACK
            .try_with(|slot| slot.borrow().len())
            .unwrap_or(0)
    }

    /// Returns true when the ambient current Cx is currently mask-restricted.
    ///
    /// This reports the thread-local ambient stack state, not the type-level
    /// `Caps` parameter of an arbitrary `Cx` value. To inspect a receiver's
    /// effective type/runtime authority, use [`Cx::capabilities`].
    #[inline]
    #[must_use]
    pub fn is_restricted() -> bool {
        CURRENT_CX_STACK
            .try_with(|slot| {
                slot.borrow()
                    .last()
                    .is_some_and(|frame| frame.mask != cap::CapMask::all())
            })
            .unwrap_or(false)
    }

    /// Borrows the current task context for the duration of the closure.
    ///
    /// br-asupersync-xqt7dj — zero-Arc-clone hot path for callers that
    /// only need to *read* from the active context (`checkpoint()`,
    /// `trace()`, `now()`, `has_io()`, etc.). The legacy
    /// [`Cx::current`] clones the three internal `Arc`s (3 atomic ops
    /// per call) so the returned cx can be retained across await
    /// points; for hot async loops that consult the ambient context
    /// many times per poll, that clone cost compounds.
    ///
    /// `with_current` saves all 3 atomic ops in the common case (no
    /// active `set_current_restricted` / `push_restriction` narrowing
    /// — i.e. the frame's mask equals its installed context's
    /// `runtime_mask`), borrowing the frame's `Cx` directly (a fiber's
    /// own context is built on first use and then borrowed the same
    /// way) and handing `&Cx` to the closure. When a
    /// restriction stack IS active and the frame's mask differs from
    /// the cx's runtime mask, we must apply the narrowed mask to a
    /// stack-local copy of the cx (1 cheap clone) so cap-gated
    /// `Option`-returning methods (`io`, `remote`, `timer_driver`,
    /// `fetch_cap`) observe the restriction; that case degrades to the
    /// same cost as legacy `current()`, never worse.
    ///
    /// **Lifetime semantics:** the borrow on `CURRENT_CX_STACK` is
    /// held for the entire closure body, so the closure cannot install
    /// a new ambient cx via `set_current*` (the inner mutable borrow
    /// would panic). Use [`Cx::current`] (which clones) when the
    /// ambient cx must outlive a single read or be moved into an
    /// async block.
    ///
    /// **Restriction-mask correctness:** the borrowed/cloned cx
    /// observes the active frame's mask, so callers running under a
    /// `set_current_restricted` scope see the narrowed cap view via
    /// `with_current` exactly as they would via `current().clone()`.
    ///
    /// Returns `None` when no ambient context is installed (or during
    /// thread-local teardown); the closure is then NOT invoked.
    #[inline]
    pub fn with_current<F, R>(f: F) -> Option<R>
    where
        F: FnOnce(&Self) -> R,
    {
        CURRENT_CX_STACK
            .try_with(|slot| {
                let stack = slot.borrow();
                let frame = stack.last()?;
                let installed = frame.cx.installed();
                if frame.mask == installed.runtime_mask {
                    // Common case: no restriction-stack narrowing. The
                    // borrowed frame.cx already carries the correct
                    // runtime mask, so we hand it to the closure
                    // without any Arc::clone — saves 3 atomic ops
                    // versus `Cx::current()`.
                    Some(f(installed))
                } else {
                    // Restricted: apply the frame's narrowed mask to a
                    // stack-local copy. Equivalent in cost to legacy
                    // `current()` (3 Arc::clone), so the worst case is
                    // a tie, never a regression.
                    let mut cx = installed.clone();
                    cx.runtime_mask = frame.mask;
                    Some(f(&cx))
                }
            })
            .ok()
            .flatten()
    }

    /// Installs `cx` as the current ambient task context for the
    /// duration of the returned guard.
    ///
    /// Pushes a new frame onto the thread-local stack preserving the held
    /// context's runtime capability mask. For installations that should
    /// further narrow the ambient view (e.g. when handing control to
    /// untrusted code that should not see full caps), use
    /// [`Cx::set_current_restricted`] instead.
    ///
    /// Reinstalling an already-restricted context no longer restores the full
    /// ambient mask described by older versions. To deliberately install
    /// broader authority, retain and supply the original privileged context.
    ///
    /// This is the public ambient-install primitive: the scheduler
    /// calls it once per poll to mirror a task's owned `Cx` into the
    /// thread-local, and first-party bridges such as
    /// `asupersync-tokio-compat` call it from *outside* this crate to
    /// make a held `Cx` visible to tokio-shaped code that reaches for
    /// [`Cx::current`]. It is capability-safe — the caller can only
    /// install a `Cx` it already holds, so no authority is minted out
    /// of band (unlike the `test-internals`-gated standalone
    /// constructors); narrow the ambient view with
    /// [`Cx::set_current_restricted`]. Because the compat bridge ships
    /// as a separate crate, this must be `pub` at the crate boundary
    /// rather than `pub(crate)` (asupersync#49).
    #[inline]
    #[must_use]
    pub fn set_current(cx: Option<Self>) -> CurrentCxGuard {
        let frame_id = CURRENT_CX_STACK.with(|stack| match cx {
            Some(cx) => {
                let id = next_current_cx_frame_id();
                let mask = cx.runtime_mask;
                let cx = FrameCx::Ready(cx);
                stack.borrow_mut().push(CurrentCxFrame { id, cx, mask });
                Some(id)
            }
            None => None,
        });
        CurrentCxGuard {
            frame_id,
            _not_send: std::marker::PhantomData,
        }
    }

    /// Installs a context that is built the first time an ambient lookup
    /// needs it, under `mask`: a fiber's own context, which most fibers
    /// never read (br-asupersync-98569u).
    #[inline]
    #[must_use]
    pub(crate) fn set_current_lazy(
        lazy: Arc<dyn LazyCurrentCx>,
        mask: cap::CapMask,
    ) -> CurrentCxGuard {
        let frame_id = CURRENT_CX_STACK.with(|stack| {
            let id = next_current_cx_frame_id();
            let cx = FrameCx::Lazy(lazy);
            stack.borrow_mut().push(CurrentCxFrame { id, cx, mask });
            id
        });
        CurrentCxGuard {
            frame_id: Some(frame_id),
            _not_send: std::marker::PhantomData,
        }
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::CapSetRuntimeMask,
{
    /// Push this cx onto the thread-local restriction stack with
    /// its own runtime mask intersected with the type-level `Caps`
    /// parameter. While the returned guard is alive, any ambient
    /// `Cx::current()` lookup observes the narrowed mask — even if
    /// the underlying `FullCx` it wraps has every capability bit
    /// set internally.
    ///
    /// br-asupersync-5ckssb: this is the tooling that gives the
    /// `Cx::current()` ambient defense its teeth. A function that
    /// is about to delegate to less-trusted code can do
    ///
    /// ```ignore
    /// let _guard = restricted_cx.set_current_restricted();
    /// untrusted::do_work(); // ambient Cx::current() observes the
    ///                       // restricted cap mask
    /// ```
    ///
    /// and be confident that the callee cannot escape its capability
    /// budget via a thread-local lookup.
    #[inline]
    #[must_use]
    pub fn set_current_restricted(self) -> CurrentCxGuard {
        let mask = <Caps as cap::CapSetRuntimeMask>::MASK.intersect(self.runtime_mask);
        let cx = self.retype::<cap::All>();
        let frame_id = CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            assert!(
                s.len() < crate::types::task_context::MAX_CONTEXT_STACK_DEPTH,
                "context stack depth exceeded MAX_CONTEXT_STACK_DEPTH ({}): this prevents \
                 stack overflow in pathological nesting scenarios. Consider reducing \
                 nesting depth or restructuring the code to avoid excessive context \
                 restriction nesting.",
                crate::types::task_context::MAX_CONTEXT_STACK_DEPTH
            );
            let id = next_current_cx_frame_id();
            let cx = FrameCx::Ready(cx);
            s.push(CurrentCxFrame { id, cx, mask });
            id
        });
        CurrentCxGuard {
            frame_id: Some(frame_id),
            _not_send: std::marker::PhantomData,
        }
    }

    /// Returns the capabilities visible through this context.
    ///
    /// The top-level booleans in the returned [`CapabilitySnapshot`] are the
    /// effective authority of this receiver: the type-level capability row
    /// intersected with the runtime mask carried by this `Cx`. When a context
    /// is obtained via [`Cx::current`] under `set_current_restricted` or
    /// [`Cx::push_restriction`], the runtime mask already includes that
    /// ambient restriction.
    #[inline]
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySnapshot {
        CapabilitySnapshot::new(<Caps as cap::CapSetRuntimeMask>::MASK, self.runtime_mask)
    }
}

impl FullCx {
    /// Push an explicit [`cap::CapMask`] restriction onto the
    /// thread-local stack without changing the underlying cx.
    ///
    /// The mask is intersected with the currently-active mask
    /// (whatever `Cx::current()` would otherwise return). While the
    /// guard is alive, ambient lookups observe the narrowed view.
    /// Useful for short scoped restrictions ("disable IO across
    /// this callback") without requiring a separate restricted-cap
    /// cx instance.
    ///
    /// (br-asupersync-5ckssb)
    #[must_use]
    pub fn push_restriction(mask: cap::CapMask) -> CurrentCxGuard {
        let frame_id = CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            // Check depth limit before attempting to push
            assert!(
                s.len() < crate::types::task_context::MAX_CONTEXT_STACK_DEPTH,
                "context stack depth exceeded MAX_CONTEXT_STACK_DEPTH ({}): this prevents \
                 stack overflow in pathological nesting scenarios. Consider reducing \
                 nesting depth or restructuring the code to avoid excessive context \
                 restriction nesting.",
                crate::types::task_context::MAX_CONTEXT_STACK_DEPTH
            );
            // Intersect with the current top so a push can only
            // ever narrow, never widen.
            let (cx, intersected_mask) = match s.last() {
                Some(top) => (top.cx.clone(), top.mask.intersect(mask)),
                // No installed cx: push a no-op marker that current()
                // will see as None (no cx to clone). Skip push since
                // there's nothing to restrict.
                None => return None,
            };
            let id = next_current_cx_frame_id();
            s.push(CurrentCxFrame {
                id,
                cx,
                mask: intersected_mask,
            });
            Some(id)
        });
        CurrentCxGuard {
            frame_id,
            _not_send: std::marker::PhantomData,
        }
    }
}

impl<Caps> Cx<Caps> {
    /// Returns the runtime-owned cancellation publication bit without taking
    /// the compatibility-state lock.
    ///
    /// This is intentionally crate-private: compatibility-sensitive
    /// cancellation paths must also honor direct replacement of the v0.4.3
    /// `fast_cancel` handle. Spawn completion observation uses this stable bit
    /// only as a cheap preflight; it still takes the full lock on terminal
    /// polls and whenever the bit is set, so compatibility mutations and exact
    /// attribution are preserved.
    #[inline]
    pub(crate) fn has_published_cancellation(&self) -> bool {
        self.cancellation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Creates a new capability context (internal use).
    #[must_use]
    #[allow(dead_code)]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn new(region: RegionId, task: TaskId, budget: Budget) -> Self {
        Self::new_with_observability(region, task, budget, None, None, None)
    }

    /// Creates a new capability context from shared state (internal use).
    #[allow(dead_code)] // Internal construction path for runtime integration
    pub(crate) fn from_inner(inner: Arc<parking_lot::RwLock<CxInner>>) -> Self {
        let (region, task, cancellation) = {
            let guard = inner.read();
            (guard.region, guard.task, guard.cancellation_state())
        };
        Self {
            inner,
            cancellation,
            observability: Arc::new(parking_lot::RwLock::new(ObservabilityState::new(
                region, task,
            ))),
            handles: Arc::new(CxHandles {
                io_driver: None,
                io_cap: None,
                timer_driver: None,
                blocking_pool: None,
                entropy: Arc::new(OsEntropy),
                logical_clock: LogicalClockHandle::default(),
                task_causality_runtime: None,
                remote_cap: None,
                registry: None,
                pressure: None,
                evidence_sink: None,
                macaroon: None,
                spawn_gateway: None,
                pending_spawns: None,
                obligation_gateway: None,
                obligation_admission: None,
                runtime_obligation_context: false,
                pending_obligation_posts: None,
                default_http_client: DefaultHttpClientSlot::default(),
                #[cfg(feature = "messaging-fabric")]
                fabric_capabilities: Arc::new(FabricCapabilityRegistry::default()),
            }),
            runtime_mask: cap::CapMask::all(),
            _caps: PhantomData,
        }
    }

    /// Creates a new capability context with optional observability state (internal use).
    #[must_use]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn new_with_observability(
        region: RegionId,
        task: TaskId,
        budget: Budget,
        observability: Option<ObservabilityState>,
        io_driver: Option<IoDriverHandle>,
        entropy: Option<Arc<dyn EntropySource>>,
    ) -> Self {
        Self::new_with_io(
            region,
            task,
            budget,
            observability,
            io_driver,
            None,
            entropy,
        )
    }

    /// Creates a new capability context with optional I/O capability (internal use).
    #[must_use]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn new_with_io(
        region: RegionId,
        task: TaskId,
        budget: Budget,
        observability: Option<ObservabilityState>,
        io_driver: Option<IoDriverHandle>,
        io_cap: Option<Arc<dyn crate::io::IoCap>>,
        entropy: Option<Arc<dyn EntropySource>>,
    ) -> Self {
        Self::new_with_drivers(
            region,
            task,
            budget,
            observability,
            io_driver,
            io_cap,
            None,
            entropy,
        )
    }

    /// Creates a new capability context with optional I/O and timer drivers (internal use).
    #[must_use]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_drivers(
        region: RegionId,
        task: TaskId,
        budget: Budget,
        observability: Option<ObservabilityState>,
        io_driver: Option<IoDriverHandle>,
        io_cap: Option<Arc<dyn crate::io::IoCap>>,
        timer_driver: Option<TimerDriverHandle>,
        entropy: Option<Arc<dyn EntropySource>>,
    ) -> Self {
        Self::new_with_drivers_and_clock(
            region,
            task,
            budget,
            observability,
            io_driver,
            io_cap,
            timer_driver,
            entropy,
            LogicalClockHandle::default(),
        )
    }

    /// [`Self::new_with_drivers`] with its final logical clock, so the runtime
    /// does not build a default clock for every task only to replace it.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_drivers_and_clock(
        region: RegionId,
        task: TaskId,
        budget: Budget,
        observability: Option<ObservabilityState>,
        io_driver: Option<IoDriverHandle>,
        io_cap: Option<Arc<dyn crate::io::IoCap>>,
        timer_driver: Option<TimerDriverHandle>,
        entropy: Option<Arc<dyn EntropySource>>,
        logical_clock: LogicalClockHandle,
    ) -> Self {
        let inner = Arc::new(parking_lot::RwLock::new(CxInner::new(region, task, budget)));
        let cancellation = inner.read().cancellation_state();
        let observability_state =
            observability.unwrap_or_else(|| ObservabilityState::new(region, task));
        let observability = Arc::new(parking_lot::RwLock::new(observability_state));
        let entropy = entropy.unwrap_or_else(|| Arc::new(OsEntropy));

        debug!(
            task_id = ?task,
            region_id = ?region,
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            budget_cost_quota = ?budget.cost_quota,
            budget_priority = budget.priority,
            budget_source = "cx_new",
            "budget initialized for context"
        );

        Self {
            inner,
            cancellation,
            observability,
            handles: Arc::new(CxHandles {
                io_driver,
                io_cap,
                timer_driver,
                blocking_pool: None,
                entropy,
                logical_clock,
                task_causality_runtime: None,
                remote_cap: None,
                registry: None,
                pressure: None,
                evidence_sink: None,
                macaroon: None,
                spawn_gateway: None,
                pending_spawns: None,
                obligation_gateway: None,
                obligation_admission: None,
                runtime_obligation_context: false,
                pending_obligation_posts: None,
                default_http_client: DefaultHttpClientSlot::default(),
                #[cfg(feature = "messaging-fabric")]
                fabric_capabilities: Arc::new(FabricCapabilityRegistry::default()),
            }),
            runtime_mask: cap::CapMask::all(),
            _caps: PhantomData,
        }
    }

    /// Returns a cloned handle to the I/O driver, if present.
    #[inline]
    #[must_use]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn io_driver_handle(&self) -> Option<IoDriverHandle> {
        self.handles.io_driver.clone()
    }

    /// Borrow the dispatcher for socket-affinity checks without cloning this
    /// context or its driver's ownership handles on every blocked I/O poll.
    #[inline]
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn io_driver_ref(&self) -> Option<&IoDriverHandle> {
        self.handles.io_driver.as_ref()
    }

    /// Returns a clone of this context's inherited blocking-pool handle, if present.
    ///
    /// Runtime-created contexts and child scopes inherit their owner's pool.
    /// This accessor only clones an attached handle; it never creates a pool.
    /// Contexts without a pool, including those explicitly detached with
    /// [`Cx::with_blocking_pool_handle`], return `None`.
    /// A runtime restriction that removes spawn authority also returns `None`.
    ///
    /// The handle can outlive this context borrow, but the originating runtime
    /// or caller-owned [`BlockingPool`](crate::runtime::BlockingPool) controls
    /// the pool's lifetime. Retaining a handle does not prevent owner shutdown;
    /// the owner must remain alive and accepting work while the handle is used.
    ///
    /// A context without spawn capability cannot retrieve a submission handle:
    ///
    /// ```compile_fail
    /// use asupersync::{Cx, cx::cap};
    ///
    /// fn retrieve_without_spawn(cx: &Cx<cap::None>) {
    ///     let _ = cx.blocking_pool_handle();
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn blocking_pool_handle(&self) -> Option<BlockingPoolHandle>
    where
        Caps: cap::HasSpawn,
    {
        if !self.runtime_mask.has(cap::CapMask::SPAWN) {
            return None;
        }
        self.blocking_pool_handle_for_inheritance()
    }

    /// Copies the stored pool during internal context inheritance.
    ///
    /// Generic child construction preserves handles independently of its typed
    /// capabilities; public retrieval still enforces both spawn restrictions.
    #[inline]
    #[must_use]
    pub(crate) fn blocking_pool_handle_for_inheritance(&self) -> Option<BlockingPoolHandle> {
        self.handles.blocking_pool.clone()
    }

    /// Attaches a caller-owned blocking pool handle to this context.
    ///
    /// This is the embedder-facing counterpart to [`Cx::set_current`]. An
    /// embedder that drives Asupersync futures without a full [`Runtime`] can
    /// install the returned context so [`spawn_blocking`] dispatches through
    /// the supplied pool instead of using the thread-per-call fallback.
    ///
    /// The method does not mint blocking authority: the caller must already
    /// possess a [`BlockingPoolHandle`]. Passing `None` explicitly detaches a
    /// previously attached pool.
    ///
    /// [`Runtime`]: crate::runtime::Runtime
    /// [`spawn_blocking`]: crate::runtime::spawn_blocking()
    #[must_use]
    pub fn with_blocking_pool_handle(mut self, handle: Option<BlockingPoolHandle>) -> Self {
        Arc::make_mut(&mut self.handles).blocking_pool = handle;
        self
    }

    /// Attaches a logical clock handle to this context.
    #[must_use]
    pub(crate) fn with_logical_clock(mut self, clock: LogicalClockHandle) -> Self {
        Arc::make_mut(&mut self.handles).logical_clock = clock;
        self
    }

    /// Marks clocks whose components identify tasks in one lab runtime.
    #[must_use]
    pub(crate) fn with_task_causality_runtime(mut self, runtime: Option<u64>) -> Self {
        Arc::make_mut(&mut self.handles).task_causality_runtime = runtime;
        self
    }

    pub(crate) fn task_causality_runtime(&self) -> Option<u64> {
        self.handles.task_causality_runtime
    }

    /// A spawn/wake source must be sampled at the operation, before later
    /// events in the sending task can advance its clock.
    pub(crate) fn task_causality_snapshot(&self) -> Option<(u64, LogicalTime)> {
        self.task_causality_runtime()
            .map(|runtime| (runtime, self.logical_tick()))
    }

    /// Re-type this context to a narrower capability set.
    ///
    /// This is a zero-cost type-level restriction. It does not change runtime behavior,
    /// but removes access to gated APIs at compile time.
    #[must_use]
    pub fn restrict<NewCaps>(&self) -> Cx<NewCaps>
    where
        NewCaps: cap::SubsetOf<Caps>,
    {
        self.retype()
    }

    /// Internal re-typing helper (no subset enforcement).
    #[inline]
    #[must_use]
    pub(crate) fn retype<NewCaps>(&self) -> Cx<NewCaps> {
        Cx {
            inner: self.inner.clone(),
            cancellation: self.cancellation.clone(),
            observability: self.observability.clone(),
            handles: self.handles.clone(),
            // br-asupersync-5ckssb: preserve the runtime mask across
            // retype. Narrowing the type-level Caps does NOT widen
            // the runtime mask; widening is impossible at this layer
            // because the typed `restrict` requires SubsetOf.
            runtime_mask: self.runtime_mask,
            _caps: PhantomData,
        }
    }

    /// Attaches a registry handle to this context.
    ///
    /// This is how Spork-style naming is made capability-scoped (no globals):
    /// tasks only see a registry if their `Cx` carries one.
    #[must_use]
    pub(crate) fn with_registry_handle(mut self, registry: Option<RegistryHandle>) -> Self {
        Arc::make_mut(&mut self.handles).registry = registry;
        self
    }

    /// Attaches a remote capability to this context.
    ///
    /// This allows the context to perform remote operations like `spawn_remote`.
    #[must_use]
    pub fn with_remote_cap(mut self, cap: RemoteCap) -> Self {
        Arc::make_mut(&mut self.handles).remote_cap = Some(Arc::new(cap));
        self
    }

    /// Attach a system pressure handle for compute budget propagation.
    ///
    /// The handle is shared via `Arc` so all clones observe the same pressure
    /// state. A monitor thread can call [`SystemPressure::set_headroom`] to
    /// update the value, and any code with `&Cx` can read it lock-free.
    #[must_use]
    pub fn with_pressure(mut self, pressure: Arc<SystemPressure>) -> Self {
        Arc::make_mut(&mut self.handles).pressure = Some(pressure);
        self
    }

    /// Read the current system pressure, if attached.
    ///
    /// Returns `None` if no pressure handle was attached to this context.
    #[must_use]
    #[inline]
    pub fn pressure(&self) -> Option<&SystemPressure> {
        self.handles.pressure.as_deref()
    }

    /// Returns a cloned handle to the configured system pressure source, if any.
    ///
    /// This is `pub(crate)` so spawned child tasks can inherit the same shared
    /// pressure state as their parent. Some build slices currently exercise
    /// the inheritance path only behind optional runtime wiring/tests.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn pressure_handle(&self) -> Option<Arc<SystemPressure>> {
        self.handles.pressure.clone()
    }

    /// Returns a cloned handle to the configured remote capability, if any.
    ///
    /// This is `pub(crate)` so internal wiring (e.g. spawning child tasks) can
    /// inherit remote capability without requiring `Caps: HasRemote` bounds.
    #[inline]
    #[must_use]
    pub(crate) fn remote_cap_handle(&self) -> Option<Arc<RemoteCap>> {
        self.handles.remote_cap.clone()
    }

    /// Attaches an already-shared remote capability handle to this context.
    ///
    /// This is the internal counterpart to [`Cx::with_remote_cap`] used for
    /// capability propagation to child contexts.
    #[must_use]
    pub(crate) fn with_remote_cap_handle(mut self, cap: Option<Arc<RemoteCap>>) -> Self {
        Arc::make_mut(&mut self.handles).remote_cap = cap;
        self
    }

    /// Returns the registry capability handle, if attached.
    #[inline]
    #[must_use]
    pub fn registry_handle(&self) -> Option<RegistryHandle> {
        self.handles.registry.clone()
    }

    /// Returns true if a registry handle is attached.
    #[inline]
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.handles.registry.is_some()
    }

    /// Grant a shared FABRIC capability for runtime and distributed-path checks.
    #[cfg(feature = "messaging-fabric")]
    pub fn grant_fabric_capability(
        &self,
        capability: FabricCapability,
    ) -> Result<FabricCapabilityGrant, FabricCapabilityGrantError> {
        self.handles.fabric_capabilities.grant(capability)
    }

    /// Return the current FABRIC capability grants attached to this context.
    #[cfg(feature = "messaging-fabric")]
    #[must_use]
    pub fn fabric_capabilities(&self) -> Vec<FabricCapabilityGrant> {
        self.handles.fabric_capabilities.snapshot()
    }

    /// Grant a publish capability and mint the corresponding linear token.
    #[cfg(feature = "messaging-fabric")]
    pub fn grant_publish_capability<S: SubjectFamilyTag>(
        &self,
        subject: SubjectPattern,
        schema: &CapabilityTokenSchema,
        delivery_class: DeliveryClass,
    ) -> Result<GrantedFabricToken<PublishPermit<S>>, FabricCapabilityGrantError> {
        let token = PublishPermit::<S>::authorize(schema, delivery_class)?;
        let grant = self.grant_fabric_capability(FabricCapability::Publish { subject })?;
        Ok(GrantedFabricToken::new(grant, token))
    }

    /// Grant a subscription capability and mint the corresponding linear token.
    #[cfg(feature = "messaging-fabric")]
    pub fn grant_subscribe_capability<S: SubjectFamilyTag>(
        &self,
        subject: SubjectPattern,
        schema: &CapabilityTokenSchema,
        delivery_class: DeliveryClass,
    ) -> Result<GrantedFabricToken<SubscribeToken<S>>, FabricCapabilityGrantError> {
        let token = SubscribeToken::<S>::authorize(schema, delivery_class)?;
        let grant = self.grant_fabric_capability(FabricCapability::Subscribe { subject })?;
        Ok(GrantedFabricToken::new(grant, token))
    }

    /// Return true when the requested FABRIC capability is currently attached.
    #[cfg(feature = "messaging-fabric")]
    #[must_use]
    pub fn check_fabric_capability(&self, capability: &FabricCapability) -> bool {
        self.handles.fabric_capabilities.check(capability)
    }

    /// Revoke one FABRIC capability by its stable grant identifier.
    #[cfg(feature = "messaging-fabric")]
    #[must_use]
    pub fn revoke_fabric_capability(&self, id: FabricCapabilityId) -> Option<FabricCapability> {
        self.handles.fabric_capabilities.revoke_by_id(id)
    }

    /// Revoke every FABRIC capability whose subject space overlaps `subject`.
    #[cfg(feature = "messaging-fabric")]
    #[must_use]
    pub fn revoke_fabric_capability_by_subject(&self, subject: &SubjectPattern) -> usize {
        self.handles.fabric_capabilities.revoke_by_subject(subject)
    }

    /// Revoke every FABRIC capability in the provided coarse scope.
    #[cfg(feature = "messaging-fabric")]
    #[must_use]
    pub fn revoke_fabric_capability_scope(&self, scope: FabricCapabilityScope) -> usize {
        self.handles.fabric_capabilities.revoke_scope(scope)
    }

    /// Attaches an evidence sink for runtime decision tracing.
    #[must_use]
    pub fn with_evidence_sink(mut self, sink: Option<Arc<dyn EvidenceSink>>) -> Self {
        Arc::make_mut(&mut self.handles).evidence_sink = sink;
        self
    }

    /// Returns a cloned handle to the evidence sink, if attached.
    #[inline]
    #[must_use]
    pub(crate) fn evidence_sink_handle(&self) -> Option<Arc<dyn EvidenceSink>> {
        self.handles.evidence_sink.clone()
    }

    /// Emit an evidence entry to the attached sink, if any.
    ///
    /// This is a no-op if no evidence sink is configured. Errors during
    /// emission are handled internally by the sink (logged and dropped).
    pub fn emit_evidence(&self, entry: &franken_evidence::EvidenceLedger) {
        if let Some(ref sink) = self.handles.evidence_sink {
            sink.emit(entry);
        }
    }

    // -----------------------------------------------------------------
    // Macaroon-based capability attenuation (bd-2lqyk.2)
    // -----------------------------------------------------------------

    /// Attaches a Macaroon capability token to this context.
    ///
    /// The token is stored in an `Arc` for cheap cloning. Child contexts
    /// created via [`restrict`](Self::restrict) or `retype`
    /// inherit the macaroon.
    #[must_use]
    pub fn with_macaroon(mut self, token: MacaroonToken) -> Self {
        Arc::make_mut(&mut self.handles).macaroon = Some(Arc::new(token));
        self
    }

    /// Attaches a pre-shared Macaroon handle to this context (internal use).
    #[must_use]
    #[allow(dead_code)] // Macaroon integration API
    pub(crate) fn with_macaroon_handle(mut self, handle: Option<Arc<MacaroonToken>>) -> Self {
        Arc::make_mut(&mut self.handles).macaroon = handle;
        self
    }

    pub(crate) fn spawn_authority_snapshot(&self) -> crate::runtime::spawn_mailbox::SpawnAuthority {
        crate::runtime::spawn_mailbox::SpawnAuthority::new(
            self.task_id(),
            self.handles.macaroon.clone(),
        )
    }

    /// Attaches the producer-side spawn gateway
    /// (br-asupersync-hwjqyo / A2.2).
    #[must_use]
    pub(crate) fn with_spawn_gateway(
        mut self,
        gateway: Option<Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    ) -> Self {
        self.inner.write().cancel_gateway.clone_from(&gateway);
        let handles = Arc::make_mut(&mut self.handles);
        handles.spawn_gateway = gateway;
        handles.runtime_obligation_context = true;
        self
    }

    /// Attaches this Cx's region pending-spawn counter
    /// (br-asupersync-hwjqyo / A2.2).
    #[must_use]
    pub(crate) fn with_pending_spawn_counter(
        mut self,
        counter: Option<Arc<crate::record::region::PendingSpawnCounter>>,
    ) -> Self {
        Arc::make_mut(&mut self.handles).pending_spawns = counter;
        self
    }

    /// Attach the runtime's obligation mailbox gateway and the owning
    /// region's pending-post counter (br-asupersync-bi2462.13).
    ///
    /// Set by the runtime at task-context build time, next to the spawn
    /// gateway.
    #[must_use]
    pub(crate) fn with_obligation_gateway(
        mut self,
        gateway: Option<Arc<crate::runtime::obligation_mailbox::ObligationGateway>>,
        pending_posts: Option<Arc<crate::record::region::PendingSpawnCounter>>,
    ) -> Self {
        let handles = Arc::make_mut(&mut self.handles);
        handles.obligation_gateway = gateway;
        handles.pending_obligation_posts = pending_posts;
        handles.runtime_obligation_context = true;
        self
    }

    #[must_use]
    pub(crate) fn with_runtime_obligation_context(mut self) -> Self {
        Arc::make_mut(&mut self.handles).runtime_obligation_context = true;
        self
    }

    #[must_use]
    pub(crate) fn with_obligation_admission(
        mut self,
        admission: Option<Arc<crate::record::region::ObligationAdmissionHandle>>,
    ) -> Self {
        Arc::make_mut(&mut self.handles).obligation_admission = admission;
        self
    }

    pub(crate) fn revoke_obligation_admission(&self) {
        if let Some(admission) = &self.handles.obligation_admission {
            admission.revoke();
        }
    }

    pub(crate) fn obligation_admission_is_live(&self) -> bool {
        self.handles
            .obligation_admission
            .as_ref()
            .is_none_or(|handle| handle.is_live())
    }

    pub(crate) fn reserve_direct_obligation(
        &self,
        holder: TaskId,
        region: RegionId,
    ) -> Option<Result<(), crate::runtime::obligation_mailbox::ObligationAdmissionError>> {
        self.handles
            .obligation_admission
            .as_ref()
            .map(|handle| handle.reserve_direct(holder, region))
    }

    /// Synchronously admit an obligation before returning its owned token.
    ///
    /// The credit shares the region's authoritative quota; arena tracing is
    /// applied later by the runtime. `Ok(None)` is reserved for contexts built
    /// without a runtime. Legacy primitive APIs retain their existing behavior.
    ///
    /// # Errors
    /// Returns a distinct error for a retired runtime/holder, closed region,
    /// exhausted quota, or a holder different from this context's task.
    pub fn try_register_obligation_checked(
        &self,
        kind: crate::record::ObligationKind,
        holder: TaskId,
    ) -> Result<
        Option<crate::runtime::obligation_mailbox::ObligationToken>,
        crate::runtime::obligation_mailbox::ObligationAdmissionError,
    > {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError;
        let Some(gateway) = self.handles.obligation_gateway.as_ref() else {
            return if self.handles.obligation_admission.is_some() {
                Err(ObligationAdmissionError::RuntimeUnavailable)
            } else if self.handles.runtime_obligation_context {
                Err(ObligationAdmissionError::HolderNotLive)
            } else {
                Ok(None)
            };
        };
        let admission = self
            .handles
            .obligation_admission
            .as_ref()
            .ok_or(ObligationAdmissionError::HolderNotLive)?;
        gateway
            .register_checked(kind, holder, self.region_id(), admission)
            .map(Some)
    }

    pub(crate) fn obligation_transfer_destination(
        &self,
    ) -> Result<
        (
            &Arc<crate::runtime::obligation_mailbox::ObligationGateway>,
            &Arc<crate::record::region::ObligationAdmissionHandle>,
        ),
        crate::runtime::obligation_mailbox::ObligationAdmissionError,
    > {
        use crate::runtime::obligation_mailbox::ObligationAdmissionError as Error;
        let gateway = self
            .handles
            .obligation_gateway
            .as_ref()
            .ok_or(Error::RuntimeUnavailable)?;
        let admission = self
            .handles
            .obligation_admission
            .as_ref()
            .ok_or(Error::HolderNotLive)?;
        Ok((gateway, admission))
    }

    /// Mint a runtime-tracked obligation of `kind` held by `holder` in this
    /// context's region (br-asupersync-bi2462.13).
    ///
    /// Returns `None` when this context carries no runtime (a hand-built
    /// `Cx`), preserving the untracked behaviour such contexts always had.
    /// Otherwise the reservation is posted to the runtime's obligation
    /// mailbox and applied through `RuntimeState::create_obligation` at the
    /// next drain; the returned [`ObligationToken`] must be committed or
    /// aborted, and dropping it unresolved is reported as a leak.
    ///
    /// [`ObligationToken`]: crate::runtime::obligation_mailbox::ObligationToken
    pub(crate) fn try_register_obligation(
        &self,
        kind: crate::record::ObligationKind,
        holder: TaskId,
    ) -> Option<crate::runtime::obligation_mailbox::ObligationToken> {
        let gateway = self.handles.obligation_gateway.as_ref()?;
        let region = self.region_id();
        gateway.register(
            kind,
            holder,
            region,
            self.handles.pending_obligation_posts.as_ref(),
        )
    }

    /// Share the parent's lazy runtime-default HTTP client slot with this Cx.
    ///
    /// Child contexts inherit the slot rather than allocating their own, so
    /// `Client::default_for_runtime(cx)` remains runtime-scoped while still
    /// constructing the actual pooled client only on first use.
    #[must_use]
    pub(crate) fn with_default_http_client_slot_from<ParentCaps>(
        mut self,
        parent: &Cx<ParentCaps>,
    ) -> Self {
        Arc::make_mut(&mut self.handles).default_http_client =
            parent.handles.default_http_client.clone();
        self
    }

    /// Return the runtime's lazily initialized default HTTP client.
    #[inline]
    #[must_use]
    pub(crate) fn default_http_client(&self) -> crate::http::h1::HttpClient
    where
        Caps: cap::HasIo,
    {
        self.handles.default_http_client.get_or_init()
    }

    #[inline]
    pub(crate) fn spawn_gateway_handle(
        &self,
    ) -> Option<Arc<crate::runtime::spawn_mailbox::SpawnGateway>> {
        self.handles.spawn_gateway.clone()
    }

    #[inline]
    pub(crate) fn pending_spawn_counter_handle(
        &self,
    ) -> Option<Arc<crate::record::region::PendingSpawnCounter>> {
        self.handles.pending_spawns.clone()
    }

    /// Returns a reference to the attached Macaroon token, if any.
    #[inline]
    #[must_use]
    pub fn macaroon(&self) -> Option<&MacaroonToken> {
        self.handles.macaroon.as_deref()
    }

    /// Returns a cloned `Arc` handle to the macaroon, if any.
    #[inline]
    #[must_use]
    #[allow(dead_code)] // Macaroon integration API
    pub(crate) fn macaroon_handle(&self) -> Option<Arc<MacaroonToken>> {
        self.handles.macaroon.clone()
    }

    /// Attenuate the capability token by adding a caveat.
    ///
    /// Returns a new `Cx` with an attenuated macaroon. The original
    /// context is unchanged. This does **not** require the root key —
    /// any holder can add caveats (but nobody can remove them).
    ///
    /// Returns `None` if no macaroon is attached or the caveat cannot be
    /// encoded in the macaroon wire format.
    #[must_use]
    pub fn attenuate(&self, predicate: super::macaroon::CaveatPredicate) -> Option<Self> {
        let token = self.handles.macaroon.as_ref()?;
        if let Err(_error) = predicate.validate() {
            error!(
                token_id = %token.identifier(),
                error = %_error,
                "macaroon attenuation rejected unencodable caveat"
            );
            return None;
        }

        let attenuated = MacaroonToken::clone(token).add_caveat(predicate.clone());
        if !attenuated.is_direct_attenuation_of(token, &predicate) {
            error!(
                token_id = %token.identifier(),
                "macaroon attenuation failed runtime subset validation"
            );
            return None;
        }

        info!(
            token_id = %attenuated.identifier(),
            caveat_count = attenuated.caveat_count(),
            "capability attenuated"
        );

        let mut cx = self.clone();
        Arc::make_mut(&mut cx.handles).macaroon = Some(Arc::new(attenuated));
        Some(cx)
    }

    /// Attenuate with a time limit: the token expires at `deadline_ms`.
    ///
    /// Convenience wrapper around [`attenuate`](Self::attenuate) with
    /// [`CaveatPredicate::TimeBefore`](crate::cx::CaveatPredicate::TimeBefore).
    ///
    /// Returns `None` if no macaroon is attached.
    #[must_use]
    pub fn attenuate_time_limit(&self, deadline_ms: u64) -> Option<Self> {
        self.attenuate(super::macaroon::CaveatPredicate::TimeBefore(deadline_ms))
    }

    /// Attenuate with a resource scope restriction.
    ///
    /// The `pattern` uses simple glob syntax: `*` matches any single segment,
    /// `**` matches any number of segments.
    ///
    /// Returns `None` if no macaroon is attached or `pattern` exceeds the
    /// macaroon wire-format length cap.
    #[must_use]
    pub fn attenuate_scope(&self, pattern: impl Into<String>) -> Option<Self> {
        self.attenuate(super::macaroon::CaveatPredicate::ResourceScope(
            pattern.into(),
        ))
    }

    /// Attenuate with a windowed rate limit.
    ///
    /// Restricts the token to at most `max_count` uses per `window_secs`.
    /// The caller is responsible for tracking the sliding window and
    /// providing both the observed window duration and use count in
    /// [`VerificationContext`].
    ///
    /// Returns `None` if no macaroon is attached.
    #[must_use]
    pub fn attenuate_rate_limit(&self, max_count: u32, window_secs: u32) -> Option<Self> {
        self.attenuate(super::macaroon::CaveatPredicate::RateLimit {
            max_count,
            window_secs,
        })
    }

    /// Attenuate with the Cx's current budget deadline.
    ///
    /// If the Cx has a finite deadline, adds a `TimeBefore` caveat using it.
    /// If no deadline is set, the macaroon is returned unchanged.
    ///
    /// Returns `None` if no macaroon is attached.
    #[must_use]
    pub fn attenuate_from_budget(&self) -> Option<Self> {
        let _ = self.handles.macaroon.as_ref()?;
        let budget = self.budget();
        budget.deadline.map_or_else(
            || Some(self.clone()),
            |d| self.attenuate_time_limit(d.as_millis()),
        )
    }

    /// Verify the attached capability token against a root key, expected
    /// capability identifier, and runtime context.
    ///
    /// Checks the HMAC chain integrity and evaluates all caveat predicates.
    /// Emits evidence to the attached sink on both success and failure.
    ///
    /// Returns `Ok(())` if the token is valid and all caveats pass.
    ///
    /// # Errors
    ///
    /// Returns `VerificationError` if verification fails (bad signature or
    /// failed caveat). Returns `Err(VerificationError::InvalidSignature)` if
    /// no macaroon is attached.
    pub fn verify_capability(
        &self,
        root_key: &crate::security::key::AuthKey,
        expected_identifier: &str,
        context: &VerificationContext,
    ) -> Result<(), VerificationError> {
        let Some(token) = self.handles.macaroon.as_ref() else {
            // Emit evidence for the no-macaroon rejection before returning.
            warn!(
                task_id = ?self.task_id(),
                region_id = ?self.region_id(),
                "capability verification failed: no macaroon attached"
            );
            return Err(VerificationError::InvalidSignature);
        };

        let result = token.verify_for_identifier(root_key, expected_identifier, context);

        // Emit evidence for the verification decision.
        self.emit_macaroon_evidence(token, &result);

        match &result {
            Ok(()) => {
                info!(
                    token_id = %token.identifier(),
                    caveats_checked = token.caveat_count(),
                    "macaroon verified successfully"
                );
            }
            Err(VerificationError::InvalidSignature) => {
                error!(
                    token_id = %token.identifier(),
                    "HMAC chain integrity violation — possible tampering"
                );
            }
            #[allow(unused_variables)]
            Err(VerificationError::UnexpectedIdentifier { expected, actual }) => {
                error!(
                    token_id = %token.identifier(),
                    expected = %expected,
                    actual = %actual,
                    "macaroon identifier mismatch"
                );
            }
            #[allow(unused_variables)]
            Err(VerificationError::CaveatFailed {
                index,
                predicate,
                reason,
            }) => {
                info!(
                    token_id = %token.identifier(),
                    failed_at_caveat = index,
                    predicate = %predicate,
                    reason = %reason,
                    "macaroon verification failed"
                );
            }
            #[allow(unused_variables)]
            Err(VerificationError::MissingDischarge { index, identifier }) => {
                info!(
                    token_id = %token.identifier(),
                    failed_at_caveat = index,
                    discharge_id = %identifier,
                    "missing discharge macaroon"
                );
            }
            #[allow(unused_variables)]
            Err(VerificationError::DischargeInvalid { index, identifier }) => {
                info!(
                    token_id = %token.identifier(),
                    failed_at_caveat = index,
                    discharge_id = %identifier,
                    "discharge macaroon verification failed"
                );
            }
            #[allow(unused_variables)]
            Err(VerificationError::DischargeChainTooDeep { depth }) => {
                info!(
                    token_id = %token.identifier(),
                    depth = %depth,
                    "discharge macaroon chain too deep"
                );
            }
            Err(VerificationError::WeakCaveatKey) => {
                error!(
                    token_id = %token.identifier(),
                    "caveat key failed entropy validation — possible weak key attack"
                );
            }
        }

        result
    }

    /// Emit evidence for a macaroon verification decision.
    fn emit_macaroon_evidence(
        &self,
        token: &MacaroonToken,
        result: &Result<(), VerificationError>,
    ) {
        let Some(ref sink) = self.handles.evidence_sink else {
            return;
        };

        let now_ms = wall_clock_now().as_millis();

        let (action, loss) = match result {
            Ok(()) => ("verify_success".to_string(), 0.0),
            Err(VerificationError::InvalidSignature) => ("verify_fail_signature".to_string(), 1.0),
            Err(VerificationError::UnexpectedIdentifier { .. }) => {
                ("verify_fail_identifier".to_string(), 1.0)
            }
            Err(VerificationError::CaveatFailed { index, .. }) => {
                (format!("verify_fail_caveat_{index}"), 0.5)
            }
            Err(VerificationError::MissingDischarge { index, .. }) => {
                (format!("verify_fail_missing_discharge_{index}"), 0.8)
            }
            Err(VerificationError::DischargeInvalid { index, .. }) => {
                (format!("verify_fail_discharge_invalid_{index}"), 0.9)
            }
            Err(VerificationError::DischargeChainTooDeep { depth }) => {
                (format!("verify_fail_discharge_chain_too_deep_{depth}"), 1.0)
            }
            Err(VerificationError::WeakCaveatKey) => {
                ("verify_fail_weak_caveat_key".to_string(), 1.0)
            }
        };

        let entry = franken_evidence::EvidenceLedger {
            ts_unix_ms: now_ms,
            component: "cx_macaroon".to_string(),
            action: action.clone(),
            posterior: vec![1.0],
            expected_loss_by_action: std::collections::BTreeMap::from([(action, loss)]),
            chosen_expected_loss: loss,
            calibration_score: 1.0,
            fallback_active: false,
            #[allow(clippy::cast_precision_loss)]
            top_features: vec![("caveat_count".to_string(), token.caveat_count() as f64)],
        };
        sink.emit(&entry);
    }

    /// Returns the current logical time without ticking.
    #[inline]
    #[must_use]
    pub fn logical_now(&self) -> LogicalTime {
        self.handles.logical_clock.now()
    }

    /// Returns a clone of the task's logical clock handle.
    #[inline]
    #[must_use]
    pub(crate) fn logical_clock_handle(&self) -> LogicalClockHandle {
        self.handles.logical_clock.clone()
    }

    /// Records a local logical event and returns the updated time.
    #[inline]
    #[must_use]
    pub fn logical_tick(&self) -> LogicalTime {
        self.handles.logical_clock.tick()
    }

    /// Merges a received logical time and returns the updated time.
    #[inline]
    #[must_use]
    pub fn logical_receive(&self, sender_time: &LogicalTime) -> LogicalTime {
        self.handles.logical_clock.receive(sender_time)
    }

    /// Returns a cloned handle to the timer driver, if present.
    ///
    /// The timer driver provides access to timer registration for async time
    /// operations like `sleep`, `timeout`, and `interval`. When present, these
    /// operations use the runtime's timer wheel instead of spawning threads.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if let Some(timer) = Cx::current().and_then(|cx| cx.timer_driver()) {
    ///     let deadline = timer.now() + Duration::from_secs(1);
    ///     let handle = timer.register(deadline, waker);
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn timer_driver(&self) -> Option<TimerDriverHandle>
    where
        Caps: cap::HasTime,
    {
        // br-asupersync-5ckssb: respect the runtime mask. A cx
        // obtained via Cx::current() under an outer
        // set_current_restricted/push_restriction that excludes TIME
        // returns None even though Caps: HasTime would otherwise
        // permit access.
        if !self.runtime_mask.has(cap::CapMask::TIME) {
            return None;
        }
        self.handles.timer_driver.clone()
    }

    /// Returns true if a timer driver is available.
    ///
    /// When true, time operations can use the runtime's timer wheel.
    /// When false, time operations fall back to OS-level timing.
    #[inline]
    #[must_use]
    pub fn has_timer(&self) -> bool
    where
        Caps: cap::HasTime,
    {
        self.handles.timer_driver.is_some()
    }

    /// Returns the I/O capability, if one is configured.
    ///
    /// The I/O capability provides access to async I/O operations. If no capability
    /// is configured, this returns `None` and I/O operations are not available.
    ///
    /// # Capability Model
    ///
    /// Asupersync uses explicit capability-based I/O:
    /// - Production runtime configures real I/O capability (via reactor)
    /// - Lab runtime can configure virtual I/O for deterministic testing
    /// - Code that needs I/O must explicitly check for and use this capability
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn read_data(cx: &Cx) -> io::Result<Vec<u8>> {
    ///     let io = cx.io().ok_or_else(|| {
    ///         io::Error::new(io::ErrorKind::Unsupported, "I/O not available")
    ///     })?;
    ///
    ///     // Use io capability...
    ///     Ok(vec![])
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn io(&self) -> Option<&dyn crate::io::IoCap>
    where
        Caps: cap::HasIo,
    {
        // br-asupersync-5ckssb: respect the runtime mask — see the
        // doc-comment on `runtime_mask`. A cx obtained via
        // Cx::current() under an outer restriction returns None for
        // I/O even though Caps: HasIo would otherwise permit it.
        if !self.runtime_mask.has(cap::CapMask::IO) {
            return None;
        }
        self.handles.io_cap.as_ref().map(AsRef::as_ref)
    }

    /// Returns a cloned handle to the configured I/O capability, if any.
    ///
    /// This is `pub(crate)` so internal wiring can preserve I/O authority when
    /// deriving child task contexts without requiring `Caps: HasIo` bounds.
    /// Some build slices currently exercise the inheritance path only behind
    /// optional runtime wiring/tests.
    #[inline]
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn io_cap_handle(&self) -> Option<Arc<dyn crate::io::IoCap>> {
        self.handles.io_cap.clone()
    }

    /// Returns true if I/O capability is available.
    ///
    /// Convenience method to check if I/O operations can be performed.
    #[inline]
    #[must_use]
    pub fn has_io(&self) -> bool
    where
        Caps: cap::HasIo,
    {
        self.handles.io_cap.is_some()
    }

    /// Returns the fetch adapter capability, if one is configured.
    ///
    /// This is the browser-facing network authority surface. When present,
    /// requests must pass explicit origin/method/credential policy checks
    /// before any host fetch operation is attempted.
    #[inline]
    #[must_use]
    pub fn fetch_cap(&self) -> Option<&dyn crate::io::FetchIoCap>
    where
        Caps: cap::HasIo,
    {
        // br-asupersync-5ckssb: fetch_cap is on the IO surface; gate
        // it on the runtime IO bit too.
        if !self.runtime_mask.has(cap::CapMask::IO) {
            return None;
        }
        self.handles.io_cap.as_ref().and_then(|cap| cap.fetch_cap())
    }

    /// Returns true if a fetch adapter capability is available.
    #[inline]
    #[must_use]
    pub fn has_fetch_cap(&self) -> bool
    where
        Caps: cap::HasIo,
    {
        self.fetch_cap().is_some()
    }

    /// Returns the remote capability, if one is configured.
    ///
    /// The remote capability authorizes spawning tasks on remote nodes.
    /// Without this capability, [`spawn_remote`](crate::remote::spawn_remote)
    /// returns [`RemoteError::NoCapability`](crate::remote::RemoteError::NoCapability).
    ///
    /// # Capability Model
    ///
    /// Remote execution is an explicit capability:
    /// - Production runtime configures remote capability with transport config
    /// - Lab runtime can configure it for deterministic distributed testing
    /// - Code that needs remote spawning must check for this capability
    #[inline]
    #[must_use]
    pub fn remote(&self) -> Option<&RemoteCap>
    where
        Caps: cap::HasRemote,
    {
        // br-asupersync-5ckssb: respect the runtime mask. A cx
        // obtained via Cx::current() under an outer restriction
        // returns None for remote even though Caps: HasRemote would
        // otherwise permit access — closes the ambient-lookup
        // escape for the most-sensitive capability surface.
        if !self.runtime_mask.has(cap::CapMask::REMOTE) {
            return None;
        }
        self.handles.remote_cap.as_ref().map(AsRef::as_ref)
    }

    /// Returns true if the remote capability is available.
    ///
    /// Convenience method to check if remote task operations can be performed.
    #[inline]
    #[must_use]
    pub fn has_remote(&self) -> bool
    where
        Caps: cap::HasRemote,
    {
        self.runtime_mask.has(cap::CapMask::REMOTE) && self.handles.remote_cap.is_some()
    }

    /// Registers an I/O source with the reactor for the given interest.
    ///
    /// This method registers a source (such as a socket or file descriptor) with
    /// the reactor so that the task can be woken when I/O operations are ready.
    ///
    /// # Arguments
    ///
    /// * `source` - The I/O source to register (must implement [`Source`])
    /// * `interest` - The I/O operations to monitor for (read, write, or both)
    ///
    /// # Returns
    ///
    /// Returns a [`IoRegistration`] handle that represents the active registration.
    /// When dropped, the registration is automatically deregistered from the reactor.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No reactor is available (reactor not initialized or not present)
    /// - The reactor fails to register the source
    ///
    #[cfg(unix)]
    pub fn register_io<S: Source>(
        &self,
        source: &S,
        interest: Interest,
    ) -> std::io::Result<IoRegistration>
    where
        Caps: cap::HasIo,
    {
        let Some(driver) = self.io_driver_handle() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "I/O driver not available",
            ));
        };
        driver.register(source, interest, noop_waker())
    }

    /// Returns the current region ID.
    ///
    /// The region ID identifies the structured concurrency scope that owns this task.
    /// Useful for debugging and for associating task-specific data with region boundaries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn log_context(cx: &Cx) {
    ///     println!("Running in region: {:?}", cx.region_id());
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.inner.read().region
    }

    /// Returns the current task ID.
    ///
    /// The task ID uniquely identifies this task within the runtime. Useful for
    /// debugging, tracing, and correlating log entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn log_task(cx: &Cx) {
    ///     println!("Task {:?} starting work", cx.task_id());
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.inner.read().task
    }

    /// Returns the task type label, if one has been set.
    ///
    /// Task types are optional metadata used by adaptive deadline monitoring
    /// and metrics to group similar work.
    #[inline]
    #[must_use]
    pub fn task_type(&self) -> Option<String> {
        self.inner.read().task_type.clone()
    }

    /// Sets a task type label for adaptive monitoring and metrics.
    ///
    /// This is intended to be called early in task execution to associate
    /// a stable label with the task's behavior profile.
    ///
    /// # Policy (br-asupersync-9vpwpc)
    ///
    /// `task_type` is exported VERBATIM as an OpenTelemetry label by the
    /// observability layer (see `src/observability/otel.rs`). To prevent
    /// cardinality explosion against the metrics backend AND PII leakage
    /// into telemetry pipelines, the value MUST be a fixed, low-cardinality
    /// identifier:
    ///
    ///   * Length ≤ 64 bytes
    ///   * Charset: ASCII alphanumeric, `_`, `.`, `-`, `:` only (no
    ///     whitespace, no high-entropy characters typical of PII like
    ///     email addresses, UUIDs, or user IDs).
    ///   * First character: ASCII letter (matches OpenTelemetry naming
    ///     conventions and rejects formats like `"-leading-dash"`).
    ///
    /// Values that violate the policy are SILENTLY DROPPED with a
    /// `tracing::warn!` log instead of being stored — `set_task_type`'s
    /// public signature returns `()` so we cannot surface the rejection
    /// as `Err`. The warn includes a length-truncated preview so the
    /// developer can find their offending call site without the full
    /// PII content showing up in production logs again.
    pub fn set_task_type(&self, task_type: impl Into<String>) {
        let task_type = task_type.into();
        if !is_valid_task_type(&task_type) {
            // Truncate the offending value to 16 chars before logging so
            // we don't replay PII into the same log pipeline we're
            // trying to protect. This is enough for the developer to
            // recognise the misuse without echoing user_ids verbatim.
            let _preview: String = task_type.chars().take(16).collect();
            warn!(
                rejected_len = task_type.len(),
                rejected_preview = %_preview,
                "set_task_type: rejected high-cardinality / PII-shaped value \
                 (br-9vpwpc; must match [A-Za-z][A-Za-z0-9_.:-]{{0,63}})"
            );
            return;
        }
        let mut inner = self.inner.write();
        inner.task_type = Some(task_type);
    }

    /// Returns the current budget.
    ///
    /// The budget defines resource limits for this task:
    /// - `deadline`: Absolute time limit
    /// - `poll_quota`: Maximum number of polls
    /// - `cost_quota`: Abstract cost units
    /// - `priority`: Scheduling priority
    ///
    /// Frameworks can use the budget to implement request timeouts:
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn check_timeout(cx: &Cx) -> Result<(), TimeoutError> {
    ///     let budget = cx.budget();
    ///     if budget.is_expired() {
    ///         return Err(TimeoutError::DeadlineExceeded);
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().budget
    }

    /// The budget new work started by this task inherits: tasks it spawns and
    /// scopes and regions it opens. That is its live budget, except while the
    /// task runs its cancellation cleanup. The cleanup budget's poll quota then
    /// bounds only this task's own drain, so the new work carries no poll
    /// quota from it. A flush or drain helper spawned during cleanup would
    /// otherwise be cancelled with `PollQuota` after 50 to 1000 polls
    /// (br-asupersync-0fvvq9).
    fn inherited_budget(&self) -> Budget {
        let inner = self.inner.read();
        if inner.cleanup_phase {
            inner.budget.with_poll_quota(u32::MAX)
        } else {
            inner.budget
        }
    }

    /// Returns the explicit capability/resource budget carried by this context.
    #[inline]
    #[must_use]
    pub fn capability_budget(&self) -> CapabilityBudget {
        self.inner.read().capability_budget
    }

    /// Returns the ambient budget tightened by a relative timeout.
    ///
    /// `now` comes from this context's clock (the timer driver in production,
    /// virtual time in the lab), so the result is correct and deterministic
    /// under both. Composition uses [`Budget::tightened_by_timeout`]: the
    /// resulting deadline is `min(ambient_deadline, now + timeout)` — a
    /// per-call timeout can never loosen an outer deadline. All other budget
    /// dimensions are inherited unchanged.
    ///
    /// This is the canonical way to derive per-operation (request, statement,
    /// RPC) budgets for deadline propagation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn query(cx: &Cx, sql: &str) -> Result<Rows, DbError> {
    ///     // 30s statement timeout, but never beyond the request deadline.
    ///     let budget = cx.budget_for_timeout(Duration::from_secs(30));
    ///     run_with_budget(cx, budget, sql).await
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn budget_for_timeout(&self, timeout: Duration) -> Budget
    where
        Caps: cap::HasTime,
    {
        self.budget().tightened_by_timeout(self.now(), timeout)
    }

    /// Returns a point-in-time snapshot of this context's remaining budget.
    ///
    /// Thin wrapper over [`Budget::remaining`] using this context's clock via
    /// [`now_for_observability`](Self::now_for_observability), so no
    /// `HasTime` capability is required — this is a diagnostic read. The live
    /// budget's quotas drain as the task runs; the snapshot is valid only at
    /// the moment of the call.
    ///
    /// Canonical use is adaptive control flow: "do I have time and polls left
    /// for another retry?"
    #[inline]
    #[must_use]
    pub fn remaining_budget(&self) -> crate::types::RemainingBudget {
        self.budget().remaining(self.now_for_observability())
    }

    /// Returns point-in-time budget accounting for this context.
    ///
    /// The snapshot is consistent at call time only. Quotas and deadlines may
    /// be consumed immediately after this method returns. Before copying the
    /// budget fields, this drains pending fast-path checkpoint counters into
    /// the authoritative checkpoint state so diagnostic budget reads do not
    /// leave checkpoint accounting lagging behind fast-path progress.
    #[inline]
    #[must_use]
    pub fn budget_stats(&self) -> BudgetStats {
        let now = self.now_for_observability();
        let mut inner = self.inner.write();
        inner.drain_fast_path_checkpoint();
        BudgetStats::from_budget_pair(inner.budget, inner.budget_baseline, now)
    }

    /// Computes the effective child capability budget without mutating this
    /// context.
    ///
    /// Required dimensions fail closed if no parent or child budget supplies
    /// them, or if the effective envelope is already exhausted.
    #[inline]
    pub fn plan_child_capability_budget(
        &self,
        child: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
    ) -> Result<CapabilityBudget, CapabilityBudgetRefusal> {
        self.inner
            .read()
            .capability_budget
            .plan_child(child, requirements)
    }

    /// Applies a child capability budget to this context after fail-closed
    /// validation.
    ///
    /// This mutates the shared `CxInner`, so all clones observe the same
    /// effective envelope. Use [`Self::plan_child_capability_budget`] when a
    /// caller only needs an admission decision.
    #[inline]
    pub fn apply_child_capability_budget(
        &self,
        child: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
    ) -> Result<CapabilityBudget, CapabilityBudgetRefusal> {
        let mut inner = self.inner.write();
        let effective = inner.capability_budget.plan_child(child, requirements)?;
        inner.capability_budget = effective;
        Ok(effective)
    }

    /// Returns true if cancellation has been requested.
    ///
    /// This is a non-blocking, read-only check that queries whether a
    /// cancellation signal has been sent to this task. Unlike
    /// [`checkpoint`](Self::checkpoint), this method does not return an error;
    /// it only reports the current state. It is suitable for choosing when to
    /// enter an application-defined shutdown path. Use `checkpoint()` when the
    /// caller wants the standard cancellation error and protocol
    /// acknowledgement behavior.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_items(cx: &Cx, items: Vec<Item>) -> Result<(), Error> {
    ///     for item in items {
    ///         // A checkpoint both observes and acknowledges cancellation.
    ///         cx.checkpoint().map_err(|_| Error::Cancelled)?;
    ///         process(item).await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.inner.read().cancel_requested
    }

    /// Observes the published cancellation bit without taking any lock.
    ///
    /// This reads the stable Release-published cancellation envelope shared
    /// with every [`Cx`] clone and runtime-owned cancellation producer, so it
    /// is safe to call on every hot-loop iteration (for example, per-posting
    /// cancellation polls inside scoring leaves) without the `RwLock` read
    /// that [`Self::is_cancel_requested`] performs.
    ///
    /// For every cancellation that flows through the runtime mutation paths
    /// ([`Self::set_cancel_requested`], [`Self::cancel_with_reason`], [`Self::cancel_with`],
    /// [`Self::cancel_fast`], task-handle and budget producers), this returns
    /// the same value as [`Self::is_cancel_requested`], observed with Acquire
    /// ordering. The only divergence window is the legacy v0.4.3 compatibility
    /// path that writes `cancel_requested` directly under the inner lock
    /// without publishing: [`Self::checkpoint`] still honors and delivers such
    /// a mutation, but does not republish it, so the published bit may lag the
    /// locked field until the next runtime mutation re-syncs the envelope.
    /// It can only lag (report false while cancellation is pending), never
    /// spuriously report true.
    ///
    /// Like [`Self::is_cancel_requested`], this is mask-agnostic: masks only
    /// gate [`Self::checkpoint`] observability.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// assert!(!cx.published_cancel_requested());
    /// cx.cancel_fast(CancelKind::RaceLost);
    /// assert!(cx.published_cancel_requested());
    /// ```
    #[inline]
    #[must_use]
    pub fn published_cancel_requested(&self) -> bool {
        self.cancellation.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Alias for [`Self::published_cancel_requested`] with a conventional name.
    ///
    /// Hot cancellation polls inside tight loops should prefer this method over
    /// [`Self::is_cancel_requested`], which acquires the inner `RwLock` on every
    /// call to preserve the legacy v0.4.3 direct-field-mutation path. This alias
    /// reads only the Release/Acquire-published `AtomicBool` envelope shared by
    /// the runtime and every clone of this context.
    ///
    /// # Examples
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// assert!(!cx.is_cancelled());
    /// cx.cancel_fast(CancelKind::RaceLost);
    /// assert!(cx.is_cancelled());
    /// ```
    #[inline]
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.published_cancel_requested()
    }

    /// Checks for cancellation and returns an error if cancelled.
    ///
    /// This is a checkpoint where cancellation can be observed. It combines
    /// checking the cancellation flag with returning an error, making it
    /// convenient for use with the `?` operator.
    ///
    /// In addition to cancellation checking, this method records progress by
    /// updating the checkpoint state. This is useful for:
    /// - Detecting stuck/stalled tasks via `checkpoint_state()`
    /// - Work-stealing scheduler decisions
    /// - Observability and debugging
    ///
    /// If the context is currently masked (via `masked()`), this method
    /// returns `Ok(())` even when cancellation is pending, deferring the
    /// cancellation until the mask is released.
    ///
    /// # Errors
    ///
    /// Returns an `Err` with kind `ErrorKind::Cancelled` if cancellation is
    /// pending and the context is not masked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn do_work(cx: &Cx) -> Result<(), Error> {
    ///     // Use checkpoint with ? for concise cancellation handling
    ///     cx.checkpoint()?;
    ///
    ///     expensive_operation().await?;
    ///
    ///     cx.checkpoint()?;
    ///
    ///     another_operation().await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    /// Implements `rule.cancel.checkpoint_masked` (#10):
    /// if cancel_requested and mask_depth == 0, acknowledge cancellation.
    /// If mask_depth > 0, cancel remains deferred until mask is unwound.
    #[allow(clippy::result_large_err)]
    pub fn checkpoint(&self) -> Result<(), crate::error::Error> {
        let checkpoint_time = self.current_checkpoint_time();

        // ── Fast path (br-asupersync-is2xg0) ──────────────────────────────
        // The vast majority of checkpoint() calls fire on healthy tasks
        // with no cancellation pending and no budget exhaustion. Take a
        // read lock, query the compatibility-aware cancellation state, snapshot the
        // (Copy) budget to detect deadline / poll / cost exhaustion inline, and
        // record progress via two atomic ops — without acquiring the
        // write lock or cloning `cancel_reason`.
        //
        // Correctness: every runtime cancellation source calls
        // `CxInner::set_cancel_requested` under the write lock, updating the
        // lock-backed flag, public handle, and stable scheduler clone with
        // `Release`. This locked query also observes direct downstream public
        // handle mutation or replacement with `Acquire` ordering.
        // Budget exhaustion is checked inline so unit-test invariants
        // ("checkpoint detects deadline / poll-quota / cost-budget
        // exhaustion") are preserved without going through deadline_monitor.
        {
            let guard = self.inner.read();
            let cancelled = guard.is_cancel_requested();
            let exhausted = !cancelled
                && Self::checkpoint_budget_exhaustion(
                    guard.region,
                    guard.task,
                    guard.budget,
                    checkpoint_time,
                )
                .is_some();
            // Fast path must also check if there's a message to clear
            let has_message = guard.checkpoint_state.last_message.is_some();
            // First checkpoint must go through slow path for proper initialization
            let is_first_checkpoint = guard.checkpoint_state.checkpoint_count == 0
                && guard
                    .fast_path_count
                    .load(std::sync::atomic::Ordering::Relaxed)
                    == 0;
            if !cancelled && !exhausted && !has_message && !is_first_checkpoint {
                guard.fast_path_last_checkpoint_ns.store(
                    checkpoint_time.as_nanos(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                guard
                    .fast_path_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(());
            }
        }
        // ── Slow path ─────────────────────────────────────────────────────
        // Cancellation is pending. Acquire the write lock, drain any
        // fast-path checkpoint accounting into the authoritative
        // CheckpointState, then run the existing logic unchanged.
        let (
            cancel_requested,
            mask_depth,
            task,
            region,
            budget,
            budget_baseline,
            cancel_reason,
            budget_exhaustion,
        ) = {
            let mut inner = self.inner.write();
            inner.drain_fast_path_checkpoint();
            inner.checkpoint_state.record_at(checkpoint_time);
            // A 0.4.3 consumer can directly replace and publish through the
            // public `fast_cancel` handle. The read-side fast path observes
            // that handle, so materialize the same observation into the
            // authoritative locked state before making the slow-path
            // delivery decision. Without this step the fast path could route
            // here for cancellation only for this block to return `Ok(())`.
            if inner.is_cancel_requested() && !inner.cancel_requested {
                inner.set_cancel_requested(true);
            }
            let budget_exhaustion = Self::checkpoint_budget_exhaustion(
                inner.region,
                inner.task,
                inner.budget,
                checkpoint_time,
            );
            if let Some((reason, _, _)) = &budget_exhaustion {
                inner.set_cancel_requested(true);
                let changed = if let Some(existing) = &mut inner.cancel_reason {
                    existing.strengthen(reason)
                } else {
                    inner.cancel_reason = Some(reason.clone());
                    true
                };
                if changed {
                    inner.cancel_wakers_pending = true;
                }
            }
            if inner.cancel_requested && inner.mask_depth == 0 {
                inner.cancel_acknowledged = true;
                super::cancel_observation::record(
                    &self.inner,
                    super::cancel_observation::CancelObservation::CheckpointAck,
                );
            }
            (
                inner.cancel_requested,
                inner.mask_depth,
                inner.task,
                inner.region,
                inner.budget,
                inner.budget_baseline,
                inner.cancel_reason.clone(),
                budget_exhaustion.map(|(_, exhaustion_kind, deadline_remaining_ms)| {
                    (exhaustion_kind, deadline_remaining_ms)
                }),
            )
        };

        if let Some((exhaustion_kind, deadline_remaining_ms)) = budget_exhaustion {
            if let Some(ref sink) = self.handles.evidence_sink {
                crate::evidence_sink::emit_budget_evidence(
                    sink.as_ref(),
                    exhaustion_kind,
                    budget.poll_quota,
                    deadline_remaining_ms,
                );
            }
        }

        // Emit evidence for cancellation decisions observed at checkpoint.
        if cancel_requested && mask_depth == 0 {
            if let Some(ref sink) = self.handles.evidence_sink {
                let kind_str = cancel_reason
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |r| format!("{}", r.kind));
                crate::evidence_sink::emit_cancel_evidence(
                    sink.as_ref(),
                    &kind_str,
                    budget.poll_quota,
                    budget.priority,
                );
            }
        }

        Self::check_cancel_from_values(
            cancel_requested,
            mask_depth,
            task,
            region,
            budget,
            budget_baseline,
            checkpoint_time,
            cancel_reason.as_ref(),
        )
    }

    /// Checks for cancellation with a progress message.
    ///
    /// This is like [`checkpoint()`](Self::checkpoint) but also records a
    /// human-readable message describing the current progress. The message
    /// is stored in the checkpoint state and can be retrieved via
    /// [`checkpoint_state()`](Self::checkpoint_state).
    ///
    /// # Errors
    ///
    /// Returns an `Err` with kind `ErrorKind::Cancelled` if cancellation is
    /// pending and the context is not masked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_batch(cx: &Cx, items: &[Item]) -> Result<(), Error> {
    ///     for (i, item) in items.iter().enumerate() {
    ///         cx.checkpoint_with(format!("Processing item {}/{}", i + 1, items.len()))?;
    ///         process(item).await?;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    #[allow(clippy::result_large_err)]
    pub fn checkpoint_with(&self, msg: impl Into<String>) -> Result<(), crate::error::Error> {
        // `Into<String>` is user code. Materialize it before acquiring CxInner
        // so a custom conversion can inspect or reenter this context without
        // self-deadlocking on the write lock.
        let msg = msg.into();
        let checkpoint_time = self.current_checkpoint_time();
        // checkpoint_with always takes the write lock because the message
        // must be stored in CheckpointState under the lock, but we still
        // drain any pending fast-path accounting first so checkpoint_count
        // and last_checkpoint stay monotonic relative to fast checkpoints.
        // (br-asupersync-is2xg0)
        let (
            cancel_requested,
            mask_depth,
            task,
            region,
            budget,
            budget_baseline,
            cancel_reason,
            budget_exhaustion,
        ) = {
            let mut inner = self.inner.write();
            inner.drain_fast_path_checkpoint();
            inner
                .checkpoint_state
                .record_with_message_at(msg, checkpoint_time);
            // Keep the always-locked checkpoint variant consistent with
            // `checkpoint`: direct publication through the restored public
            // `fast_cancel` handle must be delivered, not merely observed by
            // the lock-free preflight in the other variant.
            if inner.is_cancel_requested() && !inner.cancel_requested {
                inner.set_cancel_requested(true);
            }
            let budget_exhaustion = Self::checkpoint_budget_exhaustion(
                inner.region,
                inner.task,
                inner.budget,
                checkpoint_time,
            );
            if let Some((reason, _, _)) = &budget_exhaustion {
                inner.set_cancel_requested(true);
                let changed = if let Some(existing) = &mut inner.cancel_reason {
                    existing.strengthen(reason)
                } else {
                    inner.cancel_reason = Some(reason.clone());
                    true
                };
                if changed {
                    inner.cancel_wakers_pending = true;
                }
            }
            if inner.cancel_requested && inner.mask_depth == 0 {
                inner.cancel_acknowledged = true;
                super::cancel_observation::record(
                    &self.inner,
                    super::cancel_observation::CancelObservation::CheckpointAck,
                );
            }
            (
                inner.cancel_requested,
                inner.mask_depth,
                inner.task,
                inner.region,
                inner.budget,
                inner.budget_baseline,
                inner.cancel_reason.clone(),
                budget_exhaustion.map(|(_, exhaustion_kind, deadline_remaining_ms)| {
                    (exhaustion_kind, deadline_remaining_ms)
                }),
            )
        };

        if let Some((exhaustion_kind, deadline_remaining_ms)) = budget_exhaustion {
            if let Some(ref sink) = self.handles.evidence_sink {
                crate::evidence_sink::emit_budget_evidence(
                    sink.as_ref(),
                    exhaustion_kind,
                    budget.poll_quota,
                    deadline_remaining_ms,
                );
            }
        }

        // Emit evidence for cancellation decisions observed at checkpoint.
        if cancel_requested && mask_depth == 0 {
            if let Some(ref sink) = self.handles.evidence_sink {
                let kind_str = cancel_reason
                    .as_ref()
                    .map_or_else(|| "unknown".to_string(), |r| format!("{}", r.kind));
                crate::evidence_sink::emit_cancel_evidence(
                    sink.as_ref(),
                    &kind_str,
                    budget.poll_quota,
                    budget.priority,
                );
            }
        }

        Self::check_cancel_from_values(
            cancel_requested,
            mask_depth,
            task,
            region,
            budget,
            budget_baseline,
            checkpoint_time,
            cancel_reason.as_ref(),
        )
    }

    /// Returns a snapshot of the current checkpoint state.
    ///
    /// The checkpoint state tracks progress reporting checkpoints:
    /// - `last_checkpoint`: The runtime time when the last checkpoint was recorded
    /// - `last_message`: The message from the last `checkpoint_with()` call
    /// - `checkpoint_count`: Total number of checkpoints
    ///
    /// This is useful for monitoring task progress and detecting stalled tasks.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn check_task_health(cx: &Cx) -> bool {
    ///     let state = cx.checkpoint_state();
    ///     state.last_checkpoint.is_some()
    /// }
    /// ```
    #[must_use]
    pub fn checkpoint_state(&self) -> crate::types::CheckpointState {
        // Materialise: clone the authoritative state PLUS merge any pending
        // fast-path checkpoint accounting that hasn't been drained yet
        // (br-asupersync-is2xg0).
        self.inner.read().materialised_checkpoint_state()
    }

    /// Returns the oldest-to-newest history of message checkpoints.
    ///
    /// Messageless [`checkpoint`](Self::checkpoint) calls update checkpoint
    /// count and time only; they do not allocate or append history entries.
    ///
    /// # Example
    ///
    /// ```ignore
    /// cx.checkpoint_with("connected")?;
    /// cx.checkpoint_with("querying")?;
    /// let trail = cx.checkpoint_history();
    /// assert_eq!(trail.last().map(|(_, msg)| msg.as_str()), Some("querying"));
    /// ```
    #[must_use]
    pub fn checkpoint_history(&self) -> Vec<(Time, String)> {
        self.inner
            .read()
            .materialised_checkpoint_state()
            .history()
            .into_iter()
            .map(|entry| (entry.at, entry.message))
            .collect()
    }

    /// Returns the current physical time according to the configured timer driver,
    /// or the wall clock if no timer driver is available.
    #[must_use]
    pub fn now(&self) -> Time
    where
        Caps: cap::HasTime,
    {
        self.handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now)
    }

    /// Internal: returns current time for checkpointing.
    #[inline]
    fn current_checkpoint_time(&self) -> Time {
        self.handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now)
    }

    /// Returns the current time from the configured timer driver, falling back
    /// to wall-clock when no driver is installed.
    ///
    /// Unlike `now`, this method does not require the `HasTime` capability.
    /// It is intended for observability/diagnostic code that wants replayable
    /// timestamps in lab mode without threading a `HasTime`-capable `Cx`
    /// through. Production behavior is identical to `now`.
    #[must_use]
    #[inline]
    pub fn now_for_observability(&self) -> Time {
        self.current_checkpoint_time()
    }

    #[inline]
    fn checkpoint_budget_exhaustion(
        region: RegionId,
        task: TaskId,
        budget: Budget,
        now: Time,
    ) -> Option<(CancelReason, &'static str, Option<u64>)> {
        let deadline_remaining_ms = budget
            .remaining_time(now)
            .map(Self::duration_millis_saturating);

        let mut exhaustion = if budget.is_past_deadline(now) {
            Some((
                CancelReason::with_origin(CancelKind::Deadline, region, now).with_task(task),
                "time",
                deadline_remaining_ms,
            ))
        } else {
            None
        };

        if budget.poll_quota == 0 {
            let candidate =
                CancelReason::with_origin(CancelKind::PollQuota, region, now).with_task(task);
            match &mut exhaustion {
                Some((existing, kind, _)) => {
                    if existing.strengthen(&candidate) {
                        *kind = "poll";
                    }
                }
                None => exhaustion = Some((candidate, "poll", deadline_remaining_ms)),
            }
        }

        if matches!(budget.cost_quota, Some(0)) {
            let candidate =
                CancelReason::with_origin(CancelKind::CostBudget, region, now).with_task(task);
            match &mut exhaustion {
                Some((existing, kind, _)) => {
                    if existing.strengthen(&candidate) {
                        *kind = "cost";
                    }
                }
                None => exhaustion = Some((candidate, "cost", deadline_remaining_ms)),
            }
        }

        exhaustion
    }

    #[inline]
    fn checkpoint_budget_usage(
        budget: Budget,
        budget_baseline: Budget,
        now: Time,
    ) -> (Option<u32>, Option<u64>, Option<u64>) {
        let polls_used = if budget_baseline.poll_quota == u32::MAX {
            None
        } else {
            Some(budget_baseline.poll_quota.saturating_sub(budget.poll_quota))
        };
        let cost_used = match (budget_baseline.cost_quota, budget.cost_quota) {
            (Some(baseline), Some(remaining)) => Some(baseline.saturating_sub(remaining)),
            _ => None,
        };
        let time_remaining_ms = budget
            .remaining_time(now)
            .map(Self::duration_millis_saturating);
        (polls_used, cost_used, time_remaining_ms)
    }

    #[inline]
    fn duration_millis_saturating(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    }

    /// Internal: checks cancellation from extracted values.
    #[allow(clippy::result_large_err)]
    #[allow(clippy::too_many_arguments)]
    fn check_cancel_from_values(
        cancel_requested: bool,
        mask_depth: u32,
        task: TaskId,
        region: RegionId,
        budget: Budget,
        budget_baseline: Budget,
        checkpoint_time: Time,
        cancel_reason: Option<&CancelReason>,
    ) -> Result<(), crate::error::Error> {
        let (polls_used, cost_used, time_remaining_ms) =
            Self::checkpoint_budget_usage(budget, budget_baseline, checkpoint_time);

        let _ = (
            &task,
            &region,
            &budget,
            &budget_baseline,
            &polls_used,
            &cost_used,
            &time_remaining_ms,
        );

        trace!(
            task_id = ?task,
            region_id = ?region,
            polls_used = ?polls_used,
            polls_remaining = budget.poll_quota,
            time_remaining_ms = ?time_remaining_ms,
            cost_used = ?cost_used,
            cost_remaining = ?budget.cost_quota,
            deadline = ?budget.deadline,
            cancel_reason = ?cancel_reason,
            cancel_requested,
            mask_depth,
            "checkpoint"
        );

        if cancel_requested {
            if mask_depth == 0 {
                let cancel_reason_ref = cancel_reason.as_ref();
                let exhausted_resource = cancel_reason_ref
                    .map_or_else(|| "unknown".to_string(), |r| format!("{:?}", r.kind));
                let _ = &exhausted_resource;

                info!(
                    task_id = ?task,
                    region_id = ?region,
                    exhausted_resource = %exhausted_resource,
                    cancel_reason = ?cancel_reason,
                    budget_deadline = ?budget.deadline,
                    budget_poll_quota = budget.poll_quota,
                    budget_cost_quota = ?budget.cost_quota,
                    "cancel observed at checkpoint - task cancelled"
                );

                trace!(
                    task_id = ?task,
                    region_id = ?region,
                    cancel_reason = ?cancel_reason,
                    cancel_kind = ?cancel_reason.as_ref().map(|r| r.kind),
                    mask_depth,
                    budget_deadline = ?budget.deadline,
                    budget_poll_quota = budget.poll_quota,
                    budget_cost_quota = ?budget.cost_quota,
                    budget_priority = budget.priority,
                    "cancel observed at checkpoint"
                );
                // The reason rides on the error, because the joiner may only
                // ever see the error (br-asupersync-issue65-criticisms-kpmoy5.3.6).
                // The `Err(...)` expression stays whole: source audits pin it.
                Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))
                    .map_err(|error| error.with_cancel_reason_from(cancel_reason))
            } else {
                trace!(
                    task_id = ?task,
                    region_id = ?region,
                    cancel_reason = ?cancel_reason,
                    cancel_kind = ?cancel_reason.as_ref().map(|r| r.kind),
                    mask_depth,
                    "cancel observed but masked"
                );
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    /// Executes a closure with cancellation masked.
    ///
    /// While masked, `checkpoint()` will return `Ok(())` even if cancellation
    /// has been requested. This is used for critical sections that must not
    /// be interrupted, such as:
    ///
    /// - Completing a two-phase commit
    /// - Flushing buffered data
    /// - Releasing resources in a specific order
    ///
    /// Masking can be nested - each call to `masked()` increments a depth
    /// counter, and cancellation is only observable when depth returns to 0.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn commit_transaction(cx: &Cx, tx: Transaction) -> Result<(), Error> {
    ///     // Critical section: must complete even if cancelled
    ///     cx.masked(|| {
    ///         tx.prepare()?;
    ///         tx.commit()?;  // Cannot be interrupted here
    ///         Ok(())
    ///     })
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// Use masking sparingly. Long-masked sections defeat the purpose of
    /// responsive cancellation. Prefer short critical sections followed
    /// by a checkpoint.
    ///
    /// Invariant `inv.cancel.mask_monotone` (#12): mask_depth is monotonically
    /// non-increasing during cancel processing. The increment here occurs before
    /// cancel acknowledgement; `MaskGuard::drop` decrements via `saturating_sub(1)`.
    /// Invariant `inv.cancel.mask_bounded` (#11): mask_depth <= MAX_MASK_DEPTH.
    pub fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        {
            let mut inner = self.inner.write();
            // Enforce mask depth cap to prevent overflow and infinite recursion
            // This maintains INV-MASK-BOUNDED invariant in both debug and release builds
            assert!(
                inner.mask_depth < crate::types::task_context::MAX_MASK_DEPTH,
                "mask depth exceeded MAX_MASK_DEPTH ({}): this violates INV-MASK-BOUNDED \
                 and prevents cancellation from ever being observed. \
                 Reduce nesting of Cx::masked() sections.",
                crate::types::task_context::MAX_MASK_DEPTH,
            );
            inner.mask_depth += 1;
        }

        let _guard = MaskGuard { inner: &self.inner };
        super::cancel_observation::record(
            &self.inner,
            super::cancel_observation::CancelObservation::MaskEnter,
        );
        f()
    }

    /// Traces an event for observability.
    ///
    /// Trace events are associated with the current task and region, enabling
    /// structured observability. In the lab runtime, traces are captured
    /// deterministically for replay and debugging.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_request(cx: &Cx, request: &Request) -> Response {
    ///     cx.trace("Request received");
    ///
    ///     let result = handle(request).await;
    ///
    ///     cx.trace("Request processed");
    ///
    ///     result
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// When a trace buffer is attached to this `Cx`, this writes a structured
    /// user trace event into that buffer and also emits to the log collector.
    /// Without a trace buffer, it still records the log entry.
    pub fn trace(&self, message: &str) {
        self.log_if_collector(|| LogEntry::trace(message));
        let Some(trace) = self.trace_buffer() else {
            return;
        };
        let now = self
            .handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now);
        let logical_time = self.logical_tick();
        trace.record_event(move |seq| {
            TraceEvent::user_trace(seq, now, message).with_logical_time(logical_time)
        });
    }

    /// Logs a trace-level message with structured key-value fields.
    ///
    /// Each field is attached to the resulting `LogEntry`, making it
    /// queryable in the log collector.
    ///
    /// # Example
    ///
    /// ```ignore
    /// cx.trace_with_fields("request handled", &[
    ///     ("method", "GET"),
    ///     ("path", "/api/users"),
    ///     ("status", "200"),
    /// ]);
    /// ```
    pub fn trace_with_fields(&self, message: &str, fields: &[(&str, &str)]) {
        // Correlation-safe field budget (br-asupersync-an0t8o): LogEntry caps
        // at MAX_FIELDS (16) and the collector inserts up to four prioritized
        // correlation ids (task/region/span/parent) that rotate-evict the
        // OLDEST fields of a full entry, while fields past the cap are
        // silently ignored. Emissions must stay at <=12 explicit fields —
        // split into companion entries instead of growing past the budget.
        debug_assert!(
            fields.len() <= 12,
            "trace_with_fields(\"{message}\") passed {} fields; the correlation-safe budget is 12 \
             (LogEntry MAX_FIELDS=16 minus four prioritized correlation ids) — split the emission",
            fields.len()
        );
        self.log_if_collector(|| {
            let mut entry = LogEntry::trace(message);
            for &(k, v) in fields {
                entry = entry.with_field(k, v);
            }
            entry
        });
        let Some(trace) = self.trace_buffer() else {
            return;
        };
        let now = self
            .handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now);
        let logical_time = self.logical_tick();
        trace.record_event(move |seq| {
            TraceEvent::user_trace(seq, now, message).with_logical_time(logical_time)
        });
    }

    /// Enters a named span, returning a guard that ends the span on drop.
    ///
    /// The span forks the current `DiagnosticContext`, assigning a new
    /// `SpanId` with the previous span as parent. When the guard is
    /// dropped the original context is restored.
    ///
    /// # Example
    ///
    /// ```ignore
    /// {
    ///     let _guard = cx.enter_span("parse_request");
    ///     // ... work inside the span ...
    /// } // span ends here
    /// ```
    #[must_use]
    pub fn enter_span(&self, name: &str) -> SpanGuard<Caps> {
        let prev = self.diagnostic_context();
        let child = prev.fork().with_custom("span.name", name);
        self.set_diagnostic_context(child);
        self.log(LogEntry::debug(format!("span enter: {name}")).with_target("tracing"));
        SpanGuard {
            cx: self.clone(),
            prev,
        }
    }

    /// Sets a request correlation ID on the diagnostic context.
    ///
    /// The ID propagates to all log entries and child spans created
    /// from this context, enabling end-to-end request tracing.
    pub fn set_request_id(&self, id: impl Into<String>) {
        let mut obs = self.observability.write();
        obs.context = obs.context.clone().with_custom("request_id", id);
    }

    /// Returns the current request correlation ID, if set.
    #[inline]
    #[must_use]
    pub fn request_id(&self) -> Option<String> {
        self.diagnostic_context()
            .custom("request_id")
            .map(String::from)
    }

    /// Logs a structured entry to the attached collector, if present.
    pub fn log(&self, entry: LogEntry) {
        self.log_if_collector(|| entry);
    }

    fn log_if_collector(&self, build_entry: impl FnOnce() -> LogEntry) {
        let obs = self.observability.read();
        let Some(collector) = obs.collector.clone() else {
            return;
        };
        let include_timestamps = obs.include_timestamps;
        let context = obs.context.clone();
        drop(obs);
        let mut entry = build_entry().with_context(&context);
        // `LogEntry::new`/`info` initialize `timestamp` to `Time::ZERO`, which is
        // the "unset" sentinel: when the caller did not supply an explicit
        // timestamp we fill it in from the context's timer driver. The previous
        // sentinel (`Time::from_nanos(1_000_000_000)`) never matched the actual
        // default, so auto-timestamping silently never fired and entries kept
        // `Time::ZERO`.
        if include_timestamps && entry.timestamp() == Time::ZERO {
            let now = self
                .handles
                .timer_driver
                .as_ref()
                .map_or_else(wall_clock_now, TimerDriverHandle::now);
            entry = entry.with_timestamp(now);
        }
        collector.log(entry);
    }

    /// Returns a snapshot of the current diagnostic context.
    #[must_use]
    pub fn diagnostic_context(&self) -> DiagnosticContext {
        self.observability.read().context.clone()
    }

    /// Replaces the current diagnostic context.
    pub fn set_diagnostic_context(&self, ctx: DiagnosticContext) {
        let mut obs = self.observability.write();
        obs.context = ctx;
    }

    /// Attaches a log collector to this context.
    pub fn set_log_collector(&self, collector: LogCollector) {
        let mut obs = self.observability.write();
        obs.collector = Some(collector);
    }

    /// Returns the current log collector, if attached.
    #[inline]
    #[must_use]
    pub fn log_collector(&self) -> Option<LogCollector> {
        self.observability.read().collector.clone()
    }

    /// Attaches a trace buffer to this context.
    pub fn set_trace_buffer(&self, trace: TraceBufferHandle) {
        let mut obs = self.observability.write();
        obs.trace = Some(trace);
    }

    /// Attaches the shared loser-drain history recorder to this context.
    pub(crate) fn set_loser_drain_history_handle(&self, history: LoserDrainHistoryHandle) {
        let mut obs = self.observability.write();
        obs.loser_drain_history = Some(history);
    }

    /// Returns the current trace buffer handle, if attached.
    #[inline]
    #[must_use]
    pub fn trace_buffer(&self) -> Option<TraceBufferHandle> {
        self.observability.read().trace.clone()
    }

    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn loser_drain_history_handle(&self) -> Option<LoserDrainHistoryHandle> {
        self.observability.read().loser_drain_history.clone()
    }

    /// Derives an observability state for a child task.
    pub(crate) fn child_observability(&self, region: RegionId, task: TaskId) -> ObservabilityState {
        let obs = self.observability.read();
        obs.derive_child(region, task)
    }

    /// Returns the entropy source for this context.
    #[inline]
    #[must_use]
    pub fn entropy(&self) -> &dyn EntropySource
    where
        Caps: cap::HasRandom,
    {
        self.handles.entropy.as_ref()
    }

    /// Derives an entropy source for a child task: forked now, in spawn order, with
    /// a panicking user fork contained and retried lazily (`fork_contained`).
    pub(crate) fn child_entropy(&self, task: TaskId) -> Arc<dyn EntropySource> {
        crate::util::entropy::fork_contained(&self.handles.entropy, task)
    }

    /// Returns a cloned entropy handle for capability-aware subsystems.
    #[inline]
    #[must_use]
    pub(crate) fn entropy_handle(&self) -> Arc<dyn EntropySource>
    where
        Caps: cap::HasRandom,
    {
        self.handles.entropy.clone()
    }

    /// Generates a random `u64` using the context entropy source.
    #[must_use]
    pub fn random_u64(&self) -> u64
    where
        Caps: cap::HasRandom,
    {
        let value = self.handles.entropy.next_u64();
        // br-asupersync-lw9q66: do NOT log the random value. If
        // random_u64 is used to generate cryptographic material
        // (keys, nonces, IVs, seeds, salts), including the value in
        // a trace event leaks the secret to anything reading the
        // trace stream — log files, distributed trace exports,
        // ring-buffer dumps, etc. Trace fields stay limited to
        // diagnostic non-sensitive data (source + task_id), matching
        // the random_bytes log shape (which only records `len`).
        trace!(
            source = self.handles.entropy.source_id(),
            task_id = ?self.task_id(),
            "entropy_u64"
        );
        value
    }

    /// Fills a buffer with random bytes using the context entropy source.
    pub fn random_bytes(&self, dest: &mut [u8])
    where
        Caps: cap::HasRandom,
    {
        self.handles.entropy.fill_bytes(dest);
        trace!(
            source = self.handles.entropy.source_id(),
            task_id = ?self.task_id(),
            len = dest.len(),
            "entropy_bytes"
        );
    }

    /// Generates a random `usize` in `[0, bound)` with rejection sampling.
    #[must_use]
    pub fn random_usize(&self, bound: usize) -> usize
    where
        Caps: cap::HasRandom,
    {
        assert!(bound > 0, "bound must be non-zero");
        let bound_u64 = bound as u64;
        let threshold = u64::MAX - (u64::MAX % bound_u64);
        loop {
            let value = self.random_u64();
            if value < threshold {
                return (value % bound_u64) as usize;
            }
        }
    }

    /// Generates a random boolean.
    #[must_use]
    pub fn random_bool(&self) -> bool
    where
        Caps: cap::HasRandom,
    {
        self.random_u64() & 1 == 1
    }

    /// Generates a random `f64` in `[0, 1)`.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn random_f64(&self) -> f64
    where
        Caps: cap::HasRandom,
    {
        (self.random_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Shuffles a slice in place using Fisher-Yates.
    pub fn shuffle<T>(&self, slice: &mut [T])
    where
        Caps: cap::HasRandom,
    {
        for i in (1..slice.len()).rev() {
            let j = self.random_usize(i + 1);
            slice.swap(i, j);
        }
    }

    /// Sets the cancellation flag (internal use).
    #[allow(dead_code)]
    pub(crate) fn set_cancel_internal(&self, value: bool) {
        let mut inner = self.inner.write();
        inner.set_cancel_requested(value);
        if !value {
            inner.cancel_reason = None;
            inner.cancel_wakers_pending = false;
        } else {
            inner.cancel_wakers_pending = true;
        }
    }

    /// Sets the cancellation flag for testing purposes.
    ///
    /// This method allows tests to simulate cancellation signals. It sets the
    /// `cancel_requested` flag, which will cause subsequent `checkpoint()` calls
    /// to return an error (unless masked).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::Cx;
    ///
    /// let cx = Cx::for_testing();
    /// assert!(cx.checkpoint().is_ok());
    ///
    /// cx.set_cancel_requested(true);
    /// assert!(cx.checkpoint().is_err());
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. In production, cancellation signals
    /// are propagated by the runtime through the task tree.
    pub fn set_cancel_requested(&self, value: bool) {
        let wakers = {
            let mut inner = self.inner.write();
            inner.set_cancel_requested(value);
            if !value {
                inner.cancel_reason = None;
                inner.cancel_wakers_pending = false;
                smallvec::SmallVec::new()
            } else {
                let wakers = inner.cancel_waker_snapshot();
                inner.cancel_wakers_pending = false;
                wakers
            }
        };
        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
    }

    /// Establishes or refreshes exactly one owned cancellation-Waker registration.
    ///
    /// Passing the token returned by the prior poll makes an unchanged, still
    /// current registration a no-op. Each future gets its own registry entry,
    /// so it cannot evict the runtime's cancellation-lane Waker or clear another
    /// future's ABA-identical registration. Arbitrary Waker clone and retirement
    /// callbacks run outside the Cx lock.
    pub(crate) fn refresh_cancel_waker(
        &self,
        previous: Option<CancelWakerToken>,
        waker: &Waker,
    ) -> CancelWakerToken {
        // The common repoll path requires neither allocation nor Waker clone.
        {
            let inner = self.inner.read();
            if inner.cancel_waker_registry_closed {
                return CancelWakerToken { id: 0 };
            }
            if let Some(token) = previous
                && inner.cancel_waker_registrations.iter().any(|registration| {
                    registration.token == token.id && registration.target.will_wake(waker)
                })
            {
                return token;
            }
        }

        // Clone without a live Cx guard: a custom RawWaker clone callback may
        // reenter this same context.
        let mut incoming = Some(self.recycled_cancel_waker(waker));
        let (token, retired_waker) = {
            let mut inner = self.inner.write();

            // Recheck after cloning because an owner may have refreshed its
            // entry while no lock was held.
            if inner.cancel_waker_registry_closed {
                (CancelWakerToken { id: 0 }, None)
            } else if let Some(token) = previous
                && let Some(registration) = inner
                    .cancel_waker_registrations
                    .iter_mut()
                    .find(|registration| registration.token == token.id)
            {
                if registration.target.will_wake(waker) {
                    (token, None)
                } else {
                    let retired = std::mem::replace(
                        &mut registration.target,
                        incoming
                            .take()
                            .expect("prepared cancellation Waker must be available"),
                    );
                    (token, Some(retired))
                }
            } else {
                let id = inner
                    .next_cancel_waker_token
                    .checked_add(1)
                    .expect("cancellation-Waker token space exhausted");
                inner.next_cancel_waker_token = id;
                // Establish capacity before moving the prepared final owner
                // under the lock. An allocation unwind can then retire only
                // the still-outside `incoming` value after the guard drops.
                inner.cancel_waker_registrations.reserve(1);
                inner
                    .cancel_waker_registrations
                    .push(CancelWakerRegistration {
                        token: id,
                        target: incoming
                            .take()
                            .expect("prepared cancellation Waker must be available"),
                    });
                (CancelWakerToken { id }, None)
            }
        };

        // Both an unused prepared clone and the previous slot owner can invoke
        // arbitrary destruction callbacks: recycling retires them after unlock.
        self.recycle_cancel_waker(retired_waker);
        self.recycle_cancel_waker(incoming);
        token
    }

    /// Idempotently registers one untracked current-task cancellation Waker.
    ///
    /// This compatibility slot never increments a refcount on repoll. Callers
    /// that own a future across polls should use [`Self::refresh_cancel_waker`]
    /// and retain its token instead.
    #[cfg(test)]
    pub(crate) fn register_cancel_waker(&self, waker: &Waker) {
        {
            let inner = self.inner.read();
            if inner.cancel_waker_registry_closed
                || inner
                    .untracked_cancel_waker
                    .as_ref()
                    .is_some_and(|registered| registered.will_wake(waker))
            {
                return;
            }
        }

        let mut incoming = Some(Arc::new(CancelWaker::new(waker.clone())));
        let retired = {
            let mut inner = self.inner.write();
            if inner.cancel_waker_registry_closed
                || inner
                    .untracked_cancel_waker
                    .as_ref()
                    .is_some_and(|registered| registered.will_wake(waker))
            {
                None
            } else {
                std::mem::replace(&mut inner.untracked_cancel_waker, incoming.take())
            }
        };
        drop(retired);
        drop(incoming);
    }

    /// Clears exactly the cancellation-Waker registration identified by `token`.
    pub(crate) fn clear_cancel_waker(&self, token: CancelWakerToken) {
        let retired_waker = {
            let mut inner = self.inner.write();
            inner
                .cancel_waker_registrations
                .iter()
                .position(|registration| registration.token == token.id)
                .map(|index| inner.cancel_waker_registrations.swap_remove(index).target)
        };
        // A safe Wake payload can run arbitrary destructor code; retire the
        // exact owner only after the Cx guard has been released.
        self.recycle_cancel_waker(retired_waker);
    }

    /// Arms a timer at this context's budget deadline that cancels it with
    /// [`CancelKind::Deadline`] and wakes its cancellation targets, so a task
    /// parked in a cancel-aware wait (channel receive, lock, semaphore) ends at
    /// its deadline instead of at its next checkpoint, which a parked task never
    /// reaches (br-asupersync-pev2xi). The runtime arms it once per task
    /// context; contexts without a deadline or a timer driver arm nothing.
    /// Cancellation and terminal cleanup retain their existing deadline
    /// handling, including the async-finalizer infrastructure exemption.
    pub(crate) fn arm_budget_deadline(&self) {
        let Some(timer) = self.handles.timer_driver.as_ref() else {
            return;
        };
        let deadline = {
            let inner = self.inner.read();
            match inner.budget.deadline {
                Some(deadline)
                    if deadline < Time::MAX
                        && inner.budget_deadline_timer.is_none()
                        && !inner.cancel_waker_registry_closed
                        && !inner.budget_deadline_exempt
                        && !inner.cleanup_phase
                        && !inner.is_cancel_requested() =>
                {
                    deadline
                }
                _ => return,
            }
        };
        let wake = Arc::new(BudgetDeadlineWake {
            inner: Arc::downgrade(&self.inner),
            deadline,
            publication: std::sync::atomic::AtomicU8::new(BudgetDeadlineWake::UNPUBLISHED),
        });
        let handle = timer.register(deadline, Waker::from(Arc::clone(&wake)));
        let armed = crate::types::task_context::BudgetDeadlineTimer {
            timer: timer.clone(),
            handle,
        };
        let replay = {
            let mut inner = self.inner.write();
            if inner.budget_deadline_timer.is_some()
                || inner.cancel_waker_registry_closed
                || inner.budget_deadline_exempt
                || inner.cleanup_phase
                || inner.is_cancel_requested()
            {
                // Registration may reenter the context or race retirement.
                // Retire a refused timer only after releasing its owner lock.
                drop(inner);
                drop(armed);
                return;
            }
            inner.budget_deadline_timer = Some(armed);
            wake.publish()
        };
        if replay {
            // This also re-arms a horizon-clamped early wake, for which merely
            // testing whether the real deadline has passed would lose it.
            std::task::Wake::wake_by_ref(&wake);
        }
    }

    // ========================================================================
    // Cancel Attribution API
    // ========================================================================

    /// Cancels this context with a detailed reason.
    ///
    /// This is the preferred method for initiating cancellation, as it provides
    /// complete attribution information. The reason includes:
    /// - The kind of cancellation (e.g., User, Timeout, Deadline)
    /// - An optional message explaining the cancellation
    /// - Origin region and task information (automatically set)
    ///
    /// # Arguments
    ///
    /// * `kind` - The type of cancellation being initiated
    /// * `message` - An optional human-readable message explaining why
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// cx.cancel_with(CancelKind::User, Some("User pressed Ctrl+C"));
    /// assert!(cx.is_cancel_requested());
    ///
    /// if let Some(reason) = cx.cancel_reason() {
    ///     assert_eq!(reason.kind, CancelKind::User);
    /// }
    /// ```
    ///
    /// # Note
    ///
    /// This method only sets the local cancellation flag. In a real runtime,
    /// cancellation propagates through the region tree via `cancel_request()`.
    pub fn cancel_with(&self, kind: CancelKind, message: Option<&'static str>) {
        // Stamp the reason with the real time: an equal-severity reason
        // already recorded keeps priority only if it is older
        // (br-asupersync-27bbrg; CancelReason::new is fixed at 1 s).
        let now = self.current_checkpoint_time();
        let (region, task, wakers) = {
            let mut inner = self.inner.write();
            let region = inner.region;
            let task = inner.task;

            let mut reason = CancelReason::with_origin(kind, region, now).with_task(task);
            if let Some(msg) = message {
                reason = reason.with_message(msg);
            }

            inner.set_cancel_requested(true);
            if let Some(existing) = inner.cancel_reason.as_mut() {
                existing.strengthen(&reason);
            } else {
                inner.cancel_reason = Some(reason);
            }
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            drop(inner);
            (region, task, wakers)
        };

        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();

        debug!(
            task_id = ?task,
            region_id = ?region,
            cancel_kind = ?kind,
            cancel_message = message,
            "cancel initiated via cancel_with"
        );
        let _ = (region, task);
    }

    /// Requests local cancellation while preserving an explicit cause chain.
    ///
    /// The supplied attribution is published atomically with the cancellation
    /// flag and strengthens any existing reason using [`CancelReason::strengthen`].
    /// A weaker request cannot overwrite a concurrent shutdown or another
    /// stronger cancellation. Registered waiters are woken after the context
    /// lock is released.
    ///
    /// Unlike [`Self::cancel_with`], this preserves the supplied origin and
    /// timestamp. Like that method, it cancels this context locally; region-tree
    /// propagation remains the responsibility of the runtime or region owner.
    pub fn cancel_with_reason(&self, reason: CancelReason) {
        let wakers = {
            let mut inner = self.inner.write();
            inner.set_cancel_requested(true);
            if let Some(existing) = inner.cancel_reason.as_mut() {
                existing.strengthen(&reason);
            } else {
                inner.cancel_reason = Some(reason);
            }
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            wakers
        };
        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
    }

    /// Charges one actual caller-polled root turn, using the native worker's
    /// cooperative quota semantics. Cancellation and terminal cleanup remain
    /// advisory: a pending user/deadline cancellation must keep its reason.
    /// Publish exhaustion under the same lock as the charge, then wake outside
    /// it so a callback may safely inspect or cancel this context.
    pub(crate) fn consume_root_poll(&self) {
        let wakers = {
            let mut inner = self.inner.write();
            if inner.is_cancel_requested()
                || inner.cleanup_phase
                || inner.budget.poll_quota == u32::MAX
                || inner.budget.consume_poll().is_some()
            {
                return;
            }
            inner.set_cancel_requested(true);
            let reason = CancelReason::poll_quota();
            if let Some(existing) = inner.cancel_reason.as_mut() {
                existing.strengthen(&reason);
            } else {
                inner.cancel_reason = Some(reason);
            }
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            wakers
        };
        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
    }

    /// Publishes cancellation requested by a checkpoint during a root poll.
    /// Workers do this while reconciling the task record; a caller-polled root
    /// must discharge the same wake debt before parking or returning: an
    /// unregistered adapter context has no task retirement to do it later.
    pub(crate) fn flush_root_cancel_wakes(&self) {
        if !self.has_published_cancellation() {
            return;
        }
        let wakers = {
            let mut inner = self.inner.write();
            if !inner.cancel_wakers_pending {
                return;
            }
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            wakers
        };
        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
    }

    /// Derives a cancellation scope inside this task: the context of one
    /// fiber (br-asupersync-issue65-criticisms-kpmoy5.3.1).
    ///
    /// | Shared with this context | Owned by the derived context |
    /// | --- | --- |
    /// | task and region identity: obligations, spawns and traces stay this task's | cancellation flag, reason and acknowledgement |
    /// | drivers, gateways, observability and the capability mask | cancel-waker registrations |
    /// | the budget, as a snapshot (the runtime charges the task's own) | mask depth and checkpoint progress |
    ///
    /// Cancelling the derived context never cancels this one. This one's
    /// cancellation reaches it through [`Self::observable_cancel_reason`] and
    /// [`Self::inherit_cancel`], which its owner calls each time it runs.
    #[must_use]
    pub(crate) fn derive_cancel_scope(&self) -> Self {
        let child = {
            let parent = self.inner.read();
            let mut child = CxInner::new(parent.region, parent.task, parent.budget);
            child.task_type.clone_from(&parent.task_type);
            child.budget_baseline = parent.budget_baseline;
            child.budget_deadline_exempt = parent.budget_deadline_exempt;
            child.capability_budget = parent.capability_budget;
            child.cleanup_phase = parent.cleanup_phase;
            child
        };
        let inner = Arc::new(parking_lot::RwLock::new(child));
        let cancellation = inner.read().cancellation_state();
        Self {
            inner,
            cancellation,
            observability: Arc::clone(&self.observability),
            handles: Arc::clone(&self.handles),
            runtime_mask: self.runtime_mask,
            _caps: PhantomData,
        }
    }

    /// The reason to pass on to derived scopes, if this context's
    /// cancellation is observable: requested, and not masked. A masked
    /// context is finishing cleanup its derived scopes may be part of, so
    /// they keep running until the mask is released.
    #[must_use]
    pub(crate) fn observable_cancel_reason(&self) -> Option<CancelReason> {
        let inner = self.inner.read();
        if !inner.is_cancel_requested() || inner.mask_depth > 0 {
            return None;
        }
        Some(inner.cancel_reason.clone().unwrap_or_else(|| {
            CancelReason::new(CancelKind::ParentCancelled)
                .with_region(inner.region)
                .with_task(inner.task)
        }))
    }

    /// Cancels this derived scope with its parent's `reason`, unless it is
    /// already cancelled. Returns whether it cancelled.
    pub(crate) fn inherit_cancel(&self, reason: &CancelReason) -> bool {
        if self.inner.read().is_cancel_requested() {
            return false;
        }
        self.cancel_with_reason(reason.clone());
        true
    }

    /// Cancels without building a full attribution chain (performance-critical path).
    ///
    /// Use this when attribution isn't needed and minimizing allocations is important.
    /// The cancellation reason will have minimal attribution (kind + region only).
    ///
    /// # Performance
    ///
    /// This method avoids:
    /// - Message string allocation
    /// - Cause chain allocation
    /// - Timestamp lookup
    ///
    /// Use `cancel_with` when you need full attribution for debugging.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Fast cancellation - no allocation
    /// cx.cancel_fast(CancelKind::RaceLost);
    /// assert!(cx.is_cancel_requested());
    /// ```
    pub fn cancel_fast(&self, kind: CancelKind) {
        let (region, wakers) = {
            let mut inner = self.inner.write();
            let region = inner.region;

            // Minimal attribution: just kind and region
            let reason = CancelReason::new(kind).with_region(region);

            inner.set_cancel_requested(true);
            if let Some(existing) = inner.cancel_reason.as_mut() {
                existing.strengthen(&reason);
            } else {
                inner.cancel_reason = Some(reason);
            }
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            drop(inner);
            (region, wakers)
        };

        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();

        trace!(
            region_id = ?region,
            cancel_kind = ?kind,
            "cancel_fast initiated"
        );
        let _ = region;
    }

    /// Gets the cancellation reason if this context is cancelled.
    ///
    /// Returns `None` if the context is not cancelled, or `Some(reason)` if
    /// cancellation has been requested. The returned reason includes full
    /// attribution (kind, origin region, origin task, timestamp, cause chain).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// assert!(cx.cancel_reason().is_none());
    ///
    /// cx.cancel_with(CancelKind::Timeout, Some("request timeout"));
    /// if let Some(reason) = cx.cancel_reason() {
    ///     assert_eq!(reason.kind, CancelKind::Timeout);
    ///     println!("Cancelled: {:?}", reason.kind);
    /// }
    /// ```
    #[inline]
    #[must_use]
    pub fn cancel_reason(&self) -> Option<CancelReason> {
        let inner = self.inner.read();
        inner.cancel_reason.clone()
    }

    /// Iterates through the full cancellation cause chain.
    ///
    /// The first element is the immediate reason, followed by parent causes
    /// in order (immediate -> root). This is useful for understanding the
    /// full propagation path of a cancellation.
    ///
    /// Returns an empty iterator if the context is not cancelled.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Create a chained reason: ParentCancelled -> Deadline
    /// let root_cause = CancelReason::deadline();
    /// let chained = CancelReason::parent_cancelled().with_cause(root_cause);
    ///
    /// // Set it via internal method for testing
    /// cx.set_cancel_reason(chained);
    ///
    /// let chain: Vec<_> = cx.cancel_chain().collect();
    /// assert_eq!(chain.len(), 2);
    /// assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
    /// assert_eq!(chain[1].kind, CancelKind::Deadline);
    /// ```
    pub fn cancel_chain(&self) -> impl Iterator<Item = CancelReason> {
        let cancel_reason = self.inner.read().cancel_reason.clone();
        std::iter::successors(cancel_reason, |r| r.cause.as_deref().cloned())
    }

    /// Gets the root cause of cancellation.
    ///
    /// This is the original trigger that initiated the cancellation, regardless
    /// of how many parent regions the cancellation propagated through. For example,
    /// if a grandchild task was cancelled due to a parent timeout, `root_cancel_cause()`
    /// returns the original Timeout reason, not the intermediate ParentCancelled reasons.
    ///
    /// Returns `None` if the context is not cancelled.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Simulate a deep cancellation chain
    /// let deadline = CancelReason::deadline();
    /// let parent1 = CancelReason::parent_cancelled().with_cause(deadline);
    /// let parent2 = CancelReason::parent_cancelled().with_cause(parent1);
    ///
    /// cx.set_cancel_reason(parent2);
    ///
    /// // Root cause is the original Deadline, not ParentCancelled
    /// if let Some(root) = cx.root_cancel_cause() {
    ///     assert_eq!(root.kind, CancelKind::Deadline);
    /// }
    /// ```
    #[must_use]
    pub fn root_cancel_cause(&self) -> Option<CancelReason> {
        let inner = self.inner.read();
        inner.cancel_reason.as_ref().map(|r| r.root_cause().clone())
    }

    /// Checks if cancellation was due to a specific kind.
    ///
    /// This checks the immediate reason only, not the cause chain. For example,
    /// if a task was cancelled with `ParentCancelled` due to an upstream timeout,
    /// `cancelled_by(CancelKind::ParentCancelled)` returns `true` but
    /// `cancelled_by(CancelKind::Timeout)` returns `false`.
    ///
    /// Use `any_cause_is()` to check the full cause chain.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::CancelKind};
    ///
    /// let cx = Cx::for_testing();
    /// cx.cancel_with(CancelKind::User, Some("manual cancel"));
    ///
    /// assert!(cx.cancelled_by(CancelKind::User));
    /// assert!(!cx.cancelled_by(CancelKind::Timeout));
    /// ```
    #[must_use]
    pub fn cancelled_by(&self, kind: CancelKind) -> bool {
        let inner = self.inner.read();
        inner.cancel_reason.as_ref().is_some_and(|r| r.kind == kind)
    }

    /// Checks if any cause in the chain is a specific kind.
    ///
    /// This searches the entire cause chain, from the immediate reason to the
    /// root cause. This is useful for checking if a specific condition (like
    /// a timeout) anywhere in the hierarchy caused this cancellation.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Grandchild cancelled due to parent timeout
    /// let timeout = CancelReason::timeout();
    /// let parent_cancelled = CancelReason::parent_cancelled().with_cause(timeout);
    ///
    /// cx.set_cancel_reason(parent_cancelled);
    ///
    /// // Immediate reason is ParentCancelled, but timeout is in the chain
    /// assert!(cx.cancelled_by(CancelKind::ParentCancelled));
    /// assert!(!cx.cancelled_by(CancelKind::Timeout));  // immediate only
    /// assert!(cx.any_cause_is(CancelKind::Timeout));   // searches chain
    /// assert!(cx.any_cause_is(CancelKind::ParentCancelled));  // also in chain
    /// ```
    #[must_use]
    pub fn any_cause_is(&self, kind: CancelKind) -> bool {
        let inner = self.inner.read();
        inner
            .cancel_reason
            .as_ref()
            .is_some_and(|r| r.any_cause_is(kind))
    }

    /// Sets the cancellation reason (for testing purposes).
    ///
    /// This method allows tests to set a specific cancellation reason, including
    /// complex cause chains. It sets both the `cancel_requested` flag and the
    /// `cancel_reason`.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, types::{CancelKind, CancelReason}};
    ///
    /// let cx = Cx::for_testing();
    ///
    /// // Create a chained reason for testing
    /// let root = CancelReason::deadline();
    /// let chained = CancelReason::parent_cancelled().with_cause(root);
    ///
    /// cx.set_cancel_reason(chained);
    ///
    /// assert!(cx.is_cancel_requested());
    /// assert_eq!(cx.cancel_reason().unwrap().kind, CancelKind::ParentCancelled);
    /// ```
    pub fn set_cancel_reason(&self, reason: CancelReason) {
        let wakers = {
            let mut inner = self.inner.write();
            inner.set_cancel_requested(true);
            inner.cancel_reason = Some(reason);
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            wakers
        };
        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
    }

    /// Races multiple futures, waiting for the first to complete.
    ///
    /// It runs the provided futures concurrently (inline, not spawned) and
    /// returns the result of the first one to complete. Losers are dropped
    /// (cancelled). The `race!` macro does not use it: see [`Cx::race_drained`].
    ///
    /// # Cancellation vs Draining
    ///
    /// This method **drops** the losing futures, which cancels them. However,
    /// unlike [`Scope::race`](crate::cx::Scope::race), it does not await the
    /// losers to ensure they have fully cleaned up ("drained").
    ///
    /// If you are racing [`TaskHandle`](crate::runtime::TaskHandle)s and require
    /// the "Losers are drained" invariant (parent waits for losers to terminate),
    /// use [`Scope::race`](crate::cx::Scope::race) or
    /// [`Scope::race_all`](crate::cx::Scope::race_all) instead.
    pub async fn race<T>(
        &self,
        futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>,
    ) -> Result<T, JoinError> {
        if futures.is_empty() {
            return std::future::poll_fn(|_poll_cx| {
                if self.checkpoint().is_err() {
                    let reason = self
                        .cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("race cancelled"));
                    std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
        }
        let (res, _) = SelectAll::new(futures)
            .await
            .map_err(|_| JoinError::PolledAfterCompletion)?;
        Ok(res)
    }

    /// Races multiple named futures.
    ///
    /// Similar to `race`, but accepts names for tracing purposes.
    ///
    /// # Cancellation vs Draining
    ///
    /// This method **drops** the losing futures, which cancels them. However,
    /// unlike [`Scope::race`](crate::cx::Scope::race), it does not await the
    /// losers to ensure they have fully cleaned up ("drained").
    pub async fn race_named<T>(&self, futures: NamedFutures<T>) -> Result<T, JoinError> {
        let futures: Vec<_> = futures.into_iter().map(|(_, f)| f).collect();
        self.race(futures).await
    }

    /// Races multiple futures with a timeout.
    ///
    /// If the timeout expires before any future completes, returns a cancellation error.
    ///
    /// # Cancellation vs Draining
    ///
    /// This method **drops** the losing futures (or all futures on timeout),
    /// which cancels them. However, it does not await the losers to ensure
    /// they have fully cleaned up ("drained").
    pub async fn race_timeout<T>(
        &self,
        duration: Duration,
        futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>,
    ) -> Result<T, JoinError>
    where
        Caps: cap::HasTime,
    {
        let race_fut = std::pin::pin!(self.race(futures));
        let now = self
            .handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now);
        timeout(now, duration, race_fut)
            .await
            .unwrap_or_else(|_| Err(JoinError::Cancelled(CancelReason::timeout())))
    }

    /// Races multiple named futures with a timeout.
    ///
    /// # Cancellation vs Draining
    ///
    /// This method **drops** the losing futures (or all futures on timeout),
    /// which cancels them. However, it does not await the losers to ensure
    /// they have fully cleaned up ("drained").
    pub async fn race_timeout_named<T>(
        &self,
        duration: Duration,
        futures: NamedFutures<T>,
    ) -> Result<T, JoinError>
    where
        Caps: cap::HasTime,
    {
        let futures: Vec<_> = futures.into_iter().map(|(_, f)| f).collect();
        self.race_timeout(duration, futures).await
    }

    /// Creates a [`Scope`](super::Scope) bound to this context's region.
    ///
    /// The returned `Scope` can be used to spawn tasks, create child regions,
    /// and register finalizers. All spawned tasks will be owned by this
    /// context's region.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Using the scope! macro (recommended):
    /// scope!(cx, {
    ///     let handle = cx.spawn_in(&scope, |cx| async { 42 });
    ///     handle.await
    /// });
    ///
    /// // Manual scope creation:
    /// let scope = cx.scope();
    /// // Use scope for spawning...
    /// ```
    ///
    /// # Note
    ///
    /// In Phase 0, this creates a scope bound to the current region. In later
    /// phases, the `scope!` macro will create child regions with proper
    /// quiescence guarantees.
    #[must_use]
    pub fn scope(&self) -> crate::cx::Scope<'static> {
        let budget = self.inherited_budget();
        debug!(
            task_id = ?self.task_id(),
            region_id = ?self.region_id(),
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            budget_cost_quota = ?budget.cost_quota,
            budget_priority = budget.priority,
            budget_source = "inherited",
            "scope budget inherited"
        );
        crate::cx::Scope::new_with_capability_budget(
            self.region_id(),
            budget,
            self.capability_budget(),
        )
        .with_pending_spawn_counter(self.pending_spawn_counter_handle())
    }

    /// Derives an owned child region from this ambient context
    /// (bd-asupersync-ambient-child-region-0fm8l).
    ///
    /// The mint is command-driven: the request rides this context's spawn
    /// gateway through its liveness guard, the scheduler performs the
    /// authoritative record transitions at its dispatch point, and the
    /// returned future resolves once publication lands — with the child's
    /// principal [`Cx`] carrying the met budget and pending-spawn credits.
    /// Parent linkage uses this context's region, so parent cancellation
    /// propagates through the standard region-tree protocol while the child
    /// stays independently cancellable via [`ChildRegion::cancel`](crate::cx::ChildRegion::cancel).
    ///
    /// # Errors
    ///
    /// Fails closed with [`ChildRegionError::NoRuntimeGateway`](crate::cx::ChildRegionError::NoRuntimeGateway) when this
    /// context was built without runtime wiring; detached contexts never
    /// invent ambient authority. A runtime mask without spawning authority
    /// returns [`ChildRegionError::RuntimeUnavailable`](crate::cx::ChildRegionError::RuntimeUnavailable) before enqueueing.
    /// The derived context preserves this context's runtime capability mask.
    /// Scheduler and capability budgets meet both this context's limits and
    /// the owning region's limits, even when the request supplies an override.
    ///
    /// The child's principal context also keeps this context's compile-time
    /// capability set, so a restricted context cannot regain gated APIs
    /// through a child region (asupersync-cwxavr):
    ///
    /// ```compile_fail
    /// use asupersync::{Cx, cx::{cap, ChildRegionSpec}};
    ///
    /// async fn escalate(cx: &Cx<cap::None>) {
    ///     let child = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    ///     let _ = child.cx().blocking_pool_handle();
    /// }
    /// ```
    ///
    /// The same code compiles for a context that holds the capability:
    ///
    /// ```no_run
    /// use asupersync::{Cx, cx::{cap, ChildRegionSpec}};
    ///
    /// async fn inherit(cx: &Cx<cap::All>) {
    ///     let child = cx.open_child_region(ChildRegionSpec::inherit()).await.unwrap();
    ///     let _ = child.cx().blocking_pool_handle();
    /// }
    /// ```
    pub fn open_child_region(
        &self,
        spec: crate::cx::child_region::ChildRegionSpec,
    ) -> crate::cx::child_region::ChildRegionOpening<Caps> {
        use crate::cx::child_region::{ChildRegionError, ChildRegionOpening};
        let Some(gateway) = self.handles.spawn_gateway.clone() else {
            return ChildRegionOpening::failed(ChildRegionError::NoRuntimeGateway);
        };
        if !self.runtime_mask.has(cap::CapMask::SPAWN) {
            return ChildRegionOpening::failed(ChildRegionError::RuntimeUnavailable);
        }
        let principal_task_id = gateway.mailbox().allocate_task_id();
        let slot = std::sync::Arc::new(crate::runtime::spawn_mailbox::AdmittedRegionSlot::new());
        let request = crate::runtime::spawn_mailbox::CreateRegionRequest {
            parent: self.region_id(),
            // The caller can be narrower than its owning region (for example
            // a scoped task or an AppSpec worker). The authoritative mint
            // meets these values with the region record, but cannot recover
            // constraints held only by this Cx. Carry them in the request so
            // opening a child cannot restore authority the caller gave up.
            budget: self
                .inherited_budget()
                .meet(spec.budget.unwrap_or(Budget::INFINITE)),
            capability_budget: self
                .capability_budget()
                .meet(spec.capability_budget.unwrap_or(CapabilityBudget::UNSPECIFIED)),
            requirements: spec.requirements,
            priority: spec.priority,
            principal_task_id,
            slot: std::sync::Arc::clone(&slot),
            parent_fallback: self.inner.read().spawn_fallback_region,
        };
        if gateway
            .enqueue_region_command(crate::runtime::spawn_mailbox::RegionCommand::Create(
                request,
            ))
            .is_err()
        {
            return ChildRegionOpening::failed(ChildRegionError::RuntimeUnavailable);
        }
        ChildRegionOpening::new(
            slot,
            gateway.runtime_liveness_weak(),
            self.runtime_mask,
            self.remote_cap_handle(),
        )
    }

    /// Creates a [`Scope`](super::Scope) bound to this context's region with a custom budget.
    ///
    /// This is used by the `scope!` macro when a budget is specified:
    /// ```ignore
    /// scope!(cx, budget: Budget::with_deadline_at_secs(5), {
    ///     // body
    /// })
    /// ```
    #[must_use]
    pub fn scope_with_budget(&self, budget: Budget) -> crate::cx::Scope<'static> {
        let parent_budget = self.inherited_budget();
        let deadline_tightened = match (parent_budget.deadline, budget.deadline) {
            (Some(parent), Some(child)) => child < parent,
            (None, Some(_)) => true,
            _ => false,
        };
        let poll_tightened = budget.poll_quota < parent_budget.poll_quota;
        let cost_tightened = match (parent_budget.cost_quota, budget.cost_quota) {
            (Some(parent), Some(child)) => child < parent,
            (None, Some(_)) => true,
            _ => false,
        };
        let priority_boosted = budget.priority > parent_budget.priority;
        let _ = (
            &deadline_tightened,
            &poll_tightened,
            &cost_tightened,
            &priority_boosted,
        );

        // Clamp child budget to parent constraints (structured concurrency
        // invariant: child regions cannot exceed parent resource limits).
        // Priority is intentionally unclamped — boosting is allowed.
        let clamped_deadline = match (parent_budget.deadline, budget.deadline) {
            (Some(parent), Some(child)) => Some(if child < parent { child } else { parent }),
            (Some(parent), None) => Some(parent),
            (None, child) => child,
        };
        let clamped_poll_quota = budget.poll_quota.min(parent_budget.poll_quota);
        let clamped_cost_quota = match (parent_budget.cost_quota, budget.cost_quota) {
            (Some(parent), Some(child)) => Some(child.min(parent)),
            (Some(parent), None) => Some(parent),
            (None, child) => child,
        };
        let clamped = Budget {
            deadline: clamped_deadline,
            poll_quota: clamped_poll_quota,
            cost_quota: clamped_cost_quota,
            priority: budget.priority,
        };

        debug!(
            task_id = ?self.task_id(),
            region_id = ?self.region_id(),
            parent_deadline = ?parent_budget.deadline,
            parent_poll_quota = parent_budget.poll_quota,
            parent_cost_quota = ?parent_budget.cost_quota,
            parent_priority = parent_budget.priority,
            budget_deadline = ?clamped.deadline,
            budget_poll_quota = clamped.poll_quota,
            budget_cost_quota = ?clamped.cost_quota,
            budget_priority = clamped.priority,
            deadline_tightened,
            poll_tightened,
            cost_tightened,
            priority_boosted,
            budget_source = "explicit",
            "scope budget set"
        );
        crate::cx::Scope::new_with_capability_budget(
            self.region_id(),
            clamped,
            self.capability_budget(),
        )
        .with_pending_spawn_counter(self.pending_spawn_counter_handle())
    }

    /// Creates a [`Scope`](super::Scope) with explicit scheduler and
    /// capability budgets.
    ///
    /// The scheduler budget is clamped with [`Budget::meet`] semantics by
    /// [`Self::scope_with_budget`]. The capability budget is planned against
    /// the context's current capability envelope and fails closed when a
    /// required dimension is absent or exhausted.
    pub fn scope_with_budget_and_capability_budget(
        &self,
        budget: Budget,
        capability_budget: CapabilityBudget,
        requirements: CapabilityBudgetRequirements,
    ) -> Result<crate::cx::Scope<'static>, CapabilityBudgetRefusal> {
        let scope = self.scope_with_budget(budget);
        let effective = self.plan_child_capability_budget(capability_budget, requirements)?;
        Ok(crate::cx::Scope::new_with_capability_budget(
            scope.region_id(),
            scope.budget(),
            effective,
        )
        .with_pending_spawn_counter(self.pending_spawn_counter_handle()))
    }
}

impl Cx<cap::All> {
    /// Borrows the runtime's spawn gateway, for hot paths that only read it:
    /// cloning the shared `Arc` would touch its refcount on every call.
    #[inline]
    pub(crate) fn spawn_gateway_ref(
        &self,
    ) -> Option<&Arc<crate::runtime::spawn_mailbox::SpawnGateway>> {
        self.handles.spawn_gateway.as_ref()
    }

    /// Races multiple inline futures with **loser-drain** semantics — the
    /// drain-correct engine behind the `race!` macro.
    ///
    /// Unlike [`Cx::race`], which merely *drops* (cancels) the losing futures,
    /// this entry point spawns every branch as a task in this context's region
    /// and resolves them through [`Scope::race_all`](crate::cx::Scope::race_all).
    /// The first branch to complete wins; every loser is then
    /// protocol-cancelled **and drained** — awaited to termination — before
    /// this future returns. This is the project's "losers are drained"
    /// invariant headline: resources held by a losing branch (obligations,
    /// finalizers, file handles) are resolved, not abandoned.
    ///
    /// Each branch runs in its own child region of this context's region, so
    /// the drain covers everything a losing branch spawned through its own
    /// context (for example via [`Cx::current`]), not only the branch task:
    /// those descendants are cancelled and awaited before this returns. The
    /// winner's region closes by itself once the winner's descendants finish,
    /// so work the winner started keeps running after the race, still owned
    /// by this context's region (br-asupersync-issue65-criticisms-kpmoy5.2.2).
    /// If the runtime refuses the child region (region limits or resource
    /// pressure), the branch runs directly in this context's region as before.
    ///
    /// Because branches run as spawned tasks, each must be `Send + 'static` and
    /// the output `T` must be `Send + 'static`, and this context must be
    /// runtime-wired (carry a spawn gateway). A branch that fails admission
    /// fails the race closed with [`JoinError::Cancelled`]. A region limit or
    /// closing region refuses through the branch's handle, and every admitted
    /// sibling is cancelled and drained first. When the runtime itself refuses
    /// the spawn (its spawn gateway is gone), the already-spawned siblings are
    /// asked to cancel but are not awaited.
    ///
    /// **A branch must use its own context to observe loser cancellation.**
    /// Cancellation targets the branch's spawned task. A prebuilt future that
    /// awaits a cancel-aware operation on this caller context (for example
    /// `rx.recv(&cx)`) never sees it, so the drain waits until that branch
    /// finishes on its own. Prefer [`Cx::race_drained_with`], whose factories
    /// receive their child context, or call [`Cx::current`] inside the branch.
    /// The same holds for a branch that waits for a task it spawned.
    /// [`TaskHandle::join`](crate::runtime::TaskHandle::join) does not observe
    /// the branch's cancellation, and the branch's region is cancelled only
    /// after the branch finishes. Join such a task through
    /// [`Scope::join_all_owned`](crate::cx::Scope::join_all_owned), which passes
    /// the branch's cancellation on (br-asupersync-inleqi).
    ///
    /// On an empty branch list this is pending until the context is cancelled,
    /// mirroring [`Cx::race`].
    pub async fn race_drained<T>(
        &self,
        futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        if futures.is_empty() {
            return std::future::poll_fn(|_poll_cx| {
                if self.checkpoint().is_err() {
                    let reason = self
                        .cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("race cancelled"));
                    std::task::Poll::Ready(Err(JoinError::Cancelled(reason)))
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
        }

        let scope = self.scope();
        let mut handles = Vec::with_capacity(futures.len());
        let mut regions =
            crate::cx::race_factory::BranchRegions::new(self.spawn_gateway_handle(), futures.len());
        for future in futures {
            match self.spawn_race_branch_in(&scope, move |_child| future) {
                Ok((handle, region)) => {
                    handles.push(handle);
                    regions.push(region);
                }
                Err(_spawn_err) => {
                    // Fail closed, and ask the branches that did spawn to
                    // cancel: dropping a TaskHandle does not cancel its task.
                    // A synchronous refusal means the runtime's spawn gateway
                    // is gone (or this context cannot spawn), so they are not
                    // awaited: nothing guarantees that they can still
                    // finish. Region limits and closing regions refuse through
                    // the branch's handle instead, which race_all handles by
                    // draining (br-asupersync-issue65-criticisms-kpmoy5.2.1).
                    let reason = CancelReason::user("race! branch spawn failed");
                    for handle in &handles {
                        handle.abort_with_reason(reason.clone());
                    }
                    regions.settle(None, reason.clone(), false).await;
                    return Err(JoinError::Cancelled(reason));
                }
            }
        }

        let result = scope.race_all(self, handles).await;
        crate::cx::race_factory::settle_branch_regions(regions, &result).await;
        result.map(|(value, _index)| value)
    }

    /// Races multiple **named** inline futures with loser-drain semantics.
    ///
    /// Names are accepted for source-level symmetry with [`Cx::race_named`];
    /// the drain machinery itself is name-agnostic. See [`Cx::race_drained`]
    /// for the full guarantee and the caller-context hazard; the child-context
    /// counterpart is [`Cx::race_drained_with_named`].
    pub async fn race_drained_named<T>(&self, futures: NamedFutures<T>) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        let futures: Vec<_> = futures.into_iter().map(|(_, f)| f).collect();
        self.race_drained(futures).await
    }

    /// Races multiple inline futures with loser-drain semantics and a timeout.
    ///
    /// If `duration` elapses before any branch completes, the whole race future
    /// is abandoned: every branch is cancelled by drop. The loser-*drain*
    /// guarantee applies to the ordinary win path; the timeout path mirrors
    /// [`Cx::race_timeout`] (cancel-on-drop, no post-timeout drain).
    /// [`Cx::race_drained_with_timeout`] instead cancels and drains every
    /// branch at the deadline, and its factories receive their child context
    /// (see [`Cx::race_drained`] for the caller-context hazard).
    pub async fn race_drained_timeout<T>(
        &self,
        duration: Duration,
        futures: Vec<Pin<Box<dyn Future<Output = T> + Send>>>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        let race_fut = std::pin::pin!(self.race_drained(futures));
        let now = self
            .handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now);
        timeout(now, duration, race_fut)
            .await
            .unwrap_or_else(|_| Err(JoinError::Cancelled(CancelReason::timeout())))
    }

    /// Races multiple **named** inline futures with loser-drain semantics and a
    /// timeout. See [`Cx::race_drained_timeout`].
    pub async fn race_drained_timeout_named<T>(
        &self,
        duration: Duration,
        futures: NamedFutures<T>,
    ) -> Result<T, JoinError>
    where
        T: Send + 'static,
    {
        let futures: Vec<_> = futures.into_iter().map(|(_, f)| f).collect();
        self.race_drained_timeout(duration, futures).await
    }
}

impl Cx<cap::None> {
    /// Creates a detached context that carries cancellation and budget state
    /// but no runtime effect capabilities.
    ///
    /// This is for adapters and CLI diagnostics that need to exercise
    /// cancellation-aware primitives outside a running task. It deliberately
    /// returns `Cx<cap::None>` and installs an empty runtime capability mask, so
    /// it cannot provide spawn, timer, random, I/O, or remote authority. The
    /// synthetic IDs are non-root so an accidental immediate-completion path
    /// cannot create a root-scoped obligation.
    #[must_use]
    pub fn detached_cancel_context() -> Self {
        let mut cx = Self::new(
            RegionId::from_arena(ArenaIndex::new(1, 1)),
            TaskId::from_arena(ArenaIndex::new(1, 1)),
            Budget::INFINITE,
        );
        cx.runtime_mask = cap::CapMask::none();
        cx
    }
}

/// Claims the one-shot result sender without retaining the slot lock while
/// terminal publication wakes the joiner.
fn take_spawn_result_sender<T>(
    slot: &Arc<std::sync::Mutex<Option<crate::runtime::task_handle::TaskResultSender<T>>>>,
) -> Option<crate::runtime::task_handle::TaskResultSender<T>> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// Maximum number of factories accepted by one structured spawn batch.
///
/// This bounds producer-side work and temporary storage. Region admission
/// limits still apply independently to each member when the scheduler admits it.
pub const MAX_SPAWN_BATCH_SIZE: usize = 1024;

/// A structured spawn batch was refused before publishing any of its members.
///
/// Region closure and admission quotas are asynchronous, per-member outcomes;
/// they are reported through the returned task handles, not through this error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpawnBatchError {
    /// The input contained more factories than a single batch accepts.
    TooManyTasks {
        /// Maximum accepted number of factories.
        limit: usize,
    },
    /// The context or target lacks a live, authorized spawn path.
    Spawn(crate::runtime::state::SpawnError),
}

impl SpawnBatchError {
    /// Stable diagnostic code; setup errors retain the underlying spawn code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooManyTasks { .. } => "ASUP-E010",
            Self::Spawn(error) => error.code(),
        }
    }
}

impl std::fmt::Display for SpawnBatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyTasks { limit } => {
                write!(
                    f,
                    "[ASUP-E010] spawn batch exceeds the {limit}-task limit; \
                     submit bounded batches and collect their results before admitting more work"
                )
            }
            Self::Spawn(error) => std::fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for SpawnBatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::TooManyTasks { .. } => None,
        }
    }
}

impl From<crate::runtime::state::SpawnError> for SpawnBatchError {
    fn from(error: crate::runtime::state::SpawnError) -> Self {
        Self::Spawn(error)
    }
}

/// Read only a bounded prefix, even when an iterator reports an incorrect size
/// hint or produces an infinite sequence. No task identities or credits exist yet.
fn collect_spawn_batch<I>(factories: I) -> Result<Vec<I::Item>, SpawnBatchError>
where
    I: IntoIterator,
{
    let factories: Vec<_> = factories.into_iter().take(MAX_SPAWN_BATCH_SIZE + 1).collect();
    if factories.len() > MAX_SPAWN_BATCH_SIZE {
        return Err(SpawnBatchError::TooManyTasks {
            limit: MAX_SPAWN_BATCH_SIZE,
        });
    }
    Ok(factories)
}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Spawns a task into **this Cx's own region** without touching the
    /// `RuntimeState` lock (br-asupersync-hwjqyo / A2.2).
    ///
    /// The factory receives its own child [`Cx`] — built by mailbox
    /// admission with the canonical task identity, then overlaid with this
    /// parent's inherited capabilities (observability fork, entropy fork,
    /// io-cap/registry/remote/blocking/evidence/macaroon/pressure handles,
    /// capability budget, runtime mask) — the same inheritance set as
    /// `Scope::build_child_task_cx`.
    ///
    /// # Targeting: `Cx::spawn` vs `Cx::spawn_in` vs state-threaded boot
    ///
    /// `Cx::spawn` is *ambient-within-my-region*: the child joins the
    /// calling task's region and is drained/cancelled with it. To target a
    /// specific scope's region through the same lock-free path, use
    /// [`Cx::spawn_in`]. When you need an explicit structural boundary (a
    /// child region that closes to quiescence before you proceed), create
    /// the region via a `Scope`. If you are unsure which you want, you want
    /// the `Scope`.
    ///
    /// # Cancellation result
    ///
    /// If cancellation is requested before the child future's first poll, the
    /// handle resolves with task-level [`JoinError::Cancelled`].
    /// Once user code has started polling, a value it returns after explicitly
    /// acknowledging an attributed cancellation is preserved as the successful
    /// outer join result. This lets cancellation-aware operations report their
    /// typed cancellation result and finish protocol cleanup without changing
    /// the v0.4.3 behavior of cancellation-blind or reasonless work. A late
    /// value from work that never acknowledged cancellation, or from a legacy
    /// reasonless `fast_cancel` request, remains task-level cancellation. APIs
    /// that intentionally require cancellation-dominant attribution use a
    /// separate internal policy.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when this Cx carries no
    /// spawn gateway or region counter (e.g. built by a harness without
    /// runtime wiring), or its runtime capability mask forbids spawning.
    /// Admission-time denials (region closing, quota)
    /// resolve through the returned handle as `JoinError::Cancelled`.
    /// Never panics.
    pub fn spawn<F, Fut>(
        &self,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let Some(pending) = self.pending_spawn_counter_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_via_gateway(
            self.region_id(),
            self.inherited_budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            f,
        )
    }

    /// Spawns a bounded batch of tasks into this context's own region.
    ///
    /// Requests and returned handles retain input order; task execution order
    /// remains the scheduler's decision. Each member has its own identity,
    /// inherited child context, pending-spawn reservation, enqueue trace event,
    /// and admission result, exactly as with [`Cx::spawn`]. Factories run only
    /// after the scheduler admits their individual requests. An empty batch
    /// succeeds without requiring a runtime or issuing a notification.
    ///
    /// The producer prepares the entire batch before publishing its requests,
    /// then performs one queue insertion per member and one scheduler notification.
    /// Concurrent consumers may admit a prefix before publication finishes;
    /// this is not atomic all-or-nothing admission and does not change scheduler
    /// fairness or dispatch policy. A region's quota can admit some members and
    /// deny others. Denials resolve through the corresponding handle as
    /// [`JoinError::Cancelled`], preserving the result of every other member.
    ///
    /// Dropping a handle does not detach its work from the owning region. As
    /// with [`Cx::spawn`], explicit abort or dropping a pending join future
    /// requests cancellation. Cancellation-result classification also matches
    /// `spawn`, including typed results after cancellation acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnBatchError::TooManyTasks`] for more than
    /// [`MAX_SPAWN_BATCH_SIZE`] factories, or [`SpawnBatchError::Spawn`] when the
    /// context has no live, authorized spawn gateway or region counter. Neither
    /// error publishes any member or invokes a factory. At most
    /// `MAX_SPAWN_BATCH_SIZE + 1` iterator elements are consumed; remaining
    /// elements are dropped with the iterator. User iterator panics propagate
    /// before any task is published.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, main};
    ///
    /// #[main]
    /// async fn main(cx: &Cx) {
    ///     let members = cx.spawn_batch((0..3).map(|value| {
    ///         move |child: Cx| async move {
    ///             child.checkpoint().expect("child remains active");
    ///             value * 2
    ///         }
    ///     })).expect("batch setup");
    ///     for (index, mut member) in members.into_iter().enumerate() {
    ///         assert_eq!(member.join(cx).await.expect("child completes"), index * 2);
    ///     }
    /// }
    /// ```
    pub fn spawn_batch<I, F, Fut>(
        &self,
        factories: I,
    ) -> Result<Vec<crate::runtime::TaskHandle<Fut::Output>>, SpawnBatchError>
    where
        I: IntoIterator<Item = F>,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let factories = collect_spawn_batch(factories)?;
        if factories.is_empty() {
            return Ok(Vec::new());
        }
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(crate::runtime::state::SpawnError::RuntimeUnavailable)?;
        let pending = self
            .pending_spawn_counter_handle()
            .ok_or(crate::runtime::state::SpawnError::RuntimeUnavailable)?;
        self.spawn_batch_via_gateway(
            self.region_id(),
            self.inherited_budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            factories,
        )
    }

    /// Spawn one typed structured member with terminal observation after the
    /// ordinary cancellation decision, using the same admission and retirement
    /// path as `spawn`. Only the admitted factory invokes the observer.
    pub(crate) fn spawn_with_terminal_observer<F, Fut, Observer>(
        &self,
        f: F,
        observer: Observer,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
        Observer: crate::runtime::task_handle::SpawnTerminalObserver<Fut::Output>,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let Some(pending) = self.pending_spawn_counter_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_via_gateway_in_branch_observed(
            self.region_id(),
            self.inherited_budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            None,
            f,
            observer,
        )
    }

    /// Internal own-region variant for wrappers whose documented contract
    /// discards a value produced after cancellation (for example,
    /// [`Self::spawn_blocking`]).
    fn spawn_cancellation_dominant<F, Fut>(
        &self,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let Some(pending) = self.pending_spawn_counter_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_via_gateway(
            self.region_id(),
            self.inherited_budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::CancellationDominant,
            f,
        )
    }

    /// Spawns a task into **`scope`'s region** without touching the
    /// `RuntimeState` lock (br-asupersync-hwjqyo / A2.2).
    ///
    /// This is the scope-targeting sibling of [`Cx::spawn`]: the child task
    /// is owned by `scope`'s region (joining its drain/cancel lifecycle and
    /// its close-to-quiescence accounting) and runs under `scope`'s budget
    /// (`budget_source = "scope"`, matching the state-threaded boot path),
    /// while capability inheritance and the factory-receives-its-own-`Cx`
    /// discipline come from this context exactly as in [`Cx::spawn`].
    ///
    /// # Targeting: `Cx::spawn` vs `Cx::spawn_in` vs state-threaded boot
    ///
    /// Use `Cx::spawn` to stay in *your own* region, `Cx::spawn_in` to
    /// target a scope's region through the same lock-free mailbox path. Use
    /// `Scope::spawn_registered(&mut RuntimeState, ..)` only for synchronous
    /// boot paths that still need inline task-record inspection.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Inside a running task: `cx` is this task's context and `scope`
    /// // was produced by runtime-wired scope creation (e.g. `cx.scope()`
    /// // or a child-region scope), so it carries its region's counter.
    /// let handle = cx.spawn_in(&scope, |child| async move {
    ///     child.checkpoint()?;
    ///     Outcome::ok(42)
    /// })?;
    /// let joined = handle.join(&cx).await;
    /// ```
    ///
    /// Cancellation-result classification is identical to [`Cx::spawn`].
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when this Cx carries no
    /// spawn gateway, or when `scope` carries no pending-spawn counter for
    /// its region (e.g. a scope built without runtime wiring whose region
    /// differs from this context's). Admission-time denials (region
    /// closing, quota) resolve through the returned handle as
    /// `JoinError::Cancelled`. Never panics.
    pub fn spawn_in<F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        // The counter is per-region: prefer the scope's own wiring, and
        // fall back to this context's counter only when the scope targets
        // this context's region.
        let pending = scope.pending_spawn_counter_handle().or_else(|| {
            (scope.region_id() == self.region_id())
                .then(|| self.pending_spawn_counter_handle())
                .flatten()
        });
        let Some(pending) = pending else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_via_gateway(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            f,
        )
    }

    /// Spawns a bounded batch into `scope`'s region.
    ///
    /// This combines [`Cx::spawn_batch`]'s bounded, ordered publication with
    /// [`Cx::spawn_in`]'s explicit ownership and scope-budget inheritance. The
    /// scope's pending-spawn counter keeps region close from overlooking the
    /// requests while they await admission. Every returned handle represents
    /// exactly one member, including members denied by a closing region or quota.
    ///
    /// # Errors
    ///
    /// Returns the batch-size and setup errors described by [`Cx::spawn_batch`].
    /// A scope without its own pending-spawn counter may use this context's
    /// counter only when both name the same region. Empty input succeeds without
    /// inspecting either runtime or scope wiring.
    pub fn spawn_batch_in<I, F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        factories: I,
    ) -> Result<Vec<crate::runtime::TaskHandle<Fut::Output>>, SpawnBatchError>
    where
        P: crate::types::Policy,
        I: IntoIterator<Item = F>,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.spawn_batch_in_with_policy(
            scope,
            factories,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
        )
    }

    /// Structured collection keeps cancellation as the member's outer outcome,
    /// just as repeated `spawn_in_cancellation_dominant` calls do.
    pub(crate) fn spawn_batch_in_cancellation_dominant<I, F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        factories: I,
    ) -> Result<Vec<crate::runtime::TaskHandle<Fut::Output>>, SpawnBatchError>
    where
        P: crate::types::Policy,
        I: IntoIterator<Item = F>,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.spawn_batch_in_with_policy(
            scope,
            factories,
            crate::runtime::task_handle::SpawnCompletionPolicy::CancellationDominant,
        )
    }

    fn spawn_batch_in_with_policy<I, F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        factories: I,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
    ) -> Result<Vec<crate::runtime::TaskHandle<Fut::Output>>, SpawnBatchError>
    where
        P: crate::types::Policy,
        I: IntoIterator<Item = F>,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let factories = collect_spawn_batch(factories)?;
        if factories.is_empty() {
            return Ok(Vec::new());
        }
        let gateway = self
            .spawn_gateway_handle()
            .ok_or(crate::runtime::state::SpawnError::RuntimeUnavailable)?;
        let pending = scope
            .pending_spawn_counter_handle()
            .or_else(|| {
                (scope.region_id() == self.region_id())
                    .then(|| self.pending_spawn_counter_handle())
                    .flatten()
            })
            .ok_or(crate::runtime::state::SpawnError::RuntimeUnavailable)?;
        self.spawn_batch_via_gateway(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
            &gateway,
            &pending,
            completion_policy,
            factories,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_batch_via_gateway<F, Fut>(
        &self,
        region: RegionId,
        budget: Budget,
        capability_budget: crate::types::CapabilityBudget,
        gateway: &Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
        pending: &Arc<crate::record::region::PendingSpawnCounter>,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
        factories: Vec<F>,
    ) -> Result<Vec<crate::runtime::TaskHandle<Fut::Output>>, SpawnBatchError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        if !self.runtime_mask.has(cap::CapMask::SPAWN) {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable.into());
        }
        // Pin the publication window once for the entire batch, including the
        // period when a consumer could already be admitting its first member.
        let _liveness_guard = gateway
            .liveness_guard()
            .ok_or(crate::runtime::state::SpawnError::RuntimeUnavailable)?;
        gateway.verify_spawn_cx(self, region, budget)?;
        let mut requests = Vec::with_capacity(factories.len());
        let mut handles = Vec::with_capacity(factories.len());
        for factory in factories {
            let (request, handle) = self.prepare_spawn_request(
                region,
                budget,
                capability_budget,
                gateway,
                pending,
                completion_policy,
                None,
                factory,
                crate::runtime::task_handle::NoopSpawnTerminalObserver,
            );
            requests.push(request);
            handles.push(handle);
        }
        gateway.enqueue_batch_and_notify(requests)?;
        Ok(handles)
    }

    /// Internal structured-member variant of [`Self::spawn_in`].
    ///
    /// A member that observes cancellation may still return a value so it can
    /// finish cleanup, but the owning structured combinator must retain the
    /// cancellation reason as its outer outcome. Keeping this policy private
    /// prevents an accidental public API fork while making that distinction
    /// explicit at the producer boundary.
    pub(crate) fn spawn_in_cancellation_dominant<F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let pending = scope.pending_spawn_counter_handle().or_else(|| {
            (scope.region_id() == self.region_id())
                .then(|| self.pending_spawn_counter_handle())
                .flatten()
        });
        let Some(pending) = pending else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_via_gateway(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::CancellationDominant,
            f,
        )
    }

    /// Spawns a task into **`scope`'s region** and registers it through
    /// gateway admission.
    ///
    /// This is the v2, Cx-side replacement for call sites that used
    /// `Scope::spawn_registered(&mut RuntimeState, ..)` only to avoid
    /// hand-calling `RuntimeState::store_spawned_task`. The returned
    /// handle is pending until mailbox admission runs: before admission,
    /// [`TaskHandle::task_id`](crate::runtime::TaskHandle::task_id)
    /// reports a provisional mailbox id; after admission, it reports the
    /// canonical runtime task id. Registration/storage happens in the
    /// admission path, not synchronously at the call site.
    ///
    /// Use this when a runtime-wired [`Cx`] is available and the caller
    /// does not need synchronous supervisor-boot failure observation.
    /// Synchronous boot paths that must observe child start failure inline
    /// still need the state-threaded path until that protocol is redesigned.
    /// Cancellation-result classification is identical to [`Cx::spawn`].
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when this Cx carries no
    /// spawn gateway, or when `scope` carries no pending-spawn counter for
    /// its region (see [`Cx::spawn_in`]). Admission-time denials resolve
    /// through the returned handle as
    /// [`JoinError::Cancelled`].
    pub fn spawn_registered_in<F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.spawn_in(scope, f)
    }

    /// Spawns a blocking closure into **this Cx's own region** without
    /// touching the `RuntimeState` lock (br-asupersync-wwyi9k / A2.2b).
    ///
    /// Admission runs through the same producer-side gateway as
    /// [`Cx::spawn`], so the blocking work is owned by a real region task
    /// (region close waits for it; pending-spawn accounting applies) and
    /// the closure receives its own child [`Cx`] carrying this parent's
    /// inherited capabilities and budget. Execution dispatches to the
    /// runtime blocking pool when this context carries a pool handle;
    /// without one (e.g. under the lab runtime) the closure runs inline
    /// inside the admitted task — the same deterministic fallback as the
    /// free [`spawn_blocking`](crate::runtime::spawn_blocking::spawn_blocking)
    /// and the removed legacy `Scope::spawn_blocking`.
    ///
    /// # Cancel safety
    ///
    /// Cancelling the owning region cancels the *wrapper task*; a closure
    /// already running on the pool is not preempted (its result is
    /// discarded), matching the documented `spawn_blocking` semantics.
    /// A panic inside the closure resolves the handle as
    /// `JoinError::Panicked` and the task outcome as `Panicked`.
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when this Cx carries no
    /// spawn gateway or region counter. Admission-time denials (region
    /// closing, quota) resolve through the returned handle as
    /// `JoinError::Cancelled`. Never panics.
    pub fn spawn_blocking<F, R>(
        &self,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<R>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.blocking_pool_handle();
        self.spawn_cancellation_dominant(move |child| async move {
            match pool {
                Some(pool) => {
                    crate::runtime::spawn_blocking::spawn_blocking_on_pool(pool, move || f(child))
                        .await
                }
                None => f(child),
            }
        })
    }

    /// Spawns a blocking closure into **`scope`'s region** without touching
    /// the `RuntimeState` lock (br-asupersync-wwyi9k / A2.2b).
    ///
    /// The scope-targeting sibling of [`Cx::spawn_blocking`]: region
    /// ownership, budget, and pending-spawn accounting come from `scope`
    /// exactly as in [`Cx::spawn_in`]; pool dispatch and the deterministic
    /// inline fallback match [`Cx::spawn_blocking`].
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when this Cx carries no
    /// spawn gateway, or when `scope` carries no pending-spawn counter for
    /// its region (see [`Cx::spawn_in`]). Admission-time denials resolve
    /// through the returned handle as `JoinError::Cancelled`. Never panics.
    pub fn spawn_blocking_in<F, R, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<R>, crate::runtime::state::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.blocking_pool_handle();
        self.spawn_in_cancellation_dominant(scope, move |child| async move {
            match pool {
                Some(pool) => {
                    crate::runtime::spawn_blocking::spawn_blocking_on_pool(pool, move || f(child))
                        .await
                }
                None => f(child),
            }
        })
    }

    /// Spawn a blocking closure with a region-owned retirement wait.
    ///
    /// The admitted runtime task stays alive until the blocking pool has
    /// completed the closure and destroyed its captures. Cancellation before
    /// the pool claims the closure prevents invocation; cancellation after
    /// claim is cooperative through the closure's own inherited `Cx`. A
    /// running closure's returned value is preserved, including a typed
    /// cancellation result. The returned handle's `join` waits for actual
    /// retirement even when its caller is cancelled.
    ///
    /// Dropping the handle requests cancellation without detaching ownership.
    /// If it is dropped before result publication, destruction of an unclaimed
    /// return value also runs on the pool and precedes retirement. Once a result
    /// is published to a live handle, it belongs to that handle's caller.
    ///
    /// This requires a blocking pool; `RuntimeBuilder` adds one on native
    /// targets unless `blocking_threads(0, 0)` opts out. A queued cancelled
    /// closure stays owned until a worker destroys its captures; if every pool
    /// worker is blocked, region shutdown can time out while retaining the
    /// unfinished task. Hard runtime teardown retains its existing semantics.
    /// The existing [`Self::spawn_blocking`] soft-cancellation API is unchanged.
    ///
    /// # Errors
    ///
    /// Returns `SpawnError::RuntimeUnavailable` without a blocking pool or
    /// runtime spawn authority. Later admission refusal is observed by joining
    /// the returned handle. No closure is executed inline as a fallback.
    pub fn spawn_blocking_drained<F, R>(
        &self,
        f: F,
    ) -> Result<crate::runtime::spawn_blocking::DrainedBlockingHandle<R>, crate::runtime::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.blocking_pool_handle()
            .ok_or(crate::runtime::SpawnError::RuntimeUnavailable)?;
        let state = crate::runtime::spawn_blocking::DrainedBlockingState::new();
        let publication = Arc::clone(&state);
        let task = self.spawn(move |child| {
            crate::runtime::spawn_blocking::drive_drained_blocking(child, pool, f, publication)
        })?;
        Ok(crate::runtime::spawn_blocking::DrainedBlockingHandle::new(task, state))
    }

    /// Scope-targeting counterpart of [`Self::spawn_blocking_drained`].
    ///
    /// Region ownership and budgets come from `scope`; capability inheritance,
    /// pool selection, cancellation and retirement have the same semantics as
    /// the own-region method. Closing this scope waits for the actual blocking
    /// closure and any unclaimed-result destruction.
    pub fn spawn_blocking_drained_in<F, R, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::spawn_blocking::DrainedBlockingHandle<R>, crate::runtime::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = self.blocking_pool_handle()
            .ok_or(crate::runtime::SpawnError::RuntimeUnavailable)?;
        let state = crate::runtime::spawn_blocking::DrainedBlockingState::new();
        let publication = Arc::clone(&state);
        let task = self.spawn_in(scope, move |child| {
            crate::runtime::spawn_blocking::drive_drained_blocking(child, pool, f, publication)
        })?;
        Ok(crate::runtime::spawn_blocking::DrainedBlockingHandle::new(task, state))
    }

    /// Spawns a `!Send` task into **this Cx's own region**, pinned to the
    /// current worker thread (br-asupersync-i9y5wb / A2.2a).
    ///
    /// The v2 sibling of the removed legacy `Scope::spawn_local`: no
    /// `&mut RuntimeState` at the call site. The factory is parked on the
    /// calling worker's thread-local spawn lane and admitted by that same
    /// worker at its next dispatch point — the factory and its future
    /// never cross threads. The admitted task is pinned to this worker,
    /// stored thread-locally, and scheduled on the non-stealable local
    /// queue, so steal paths reject migration structurally.
    ///
    /// # Targeting
    ///
    /// Like [`Cx::spawn`], the child joins this context's region. Use
    /// [`Cx::spawn_local_in`] to target a specific scope's region.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`SpawnError::LocalSchedulerUnavailable`](crate::runtime::SpawnError::LocalSchedulerUnavailable)
    /// when the calling
    /// thread is not a runtime worker (local spawns require an owner
    /// worker; this includes the lab runtime and blocking-pool threads —
    /// unlike the legacy path this never panics). Returns
    /// [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when this Cx carries no spawn
    /// gateway or region counter. Admission-time denials (region closing,
    /// quota) resolve through the returned handle as
    /// `JoinError::Cancelled`.
    /// Cancellation-result classification is identical to [`Cx::spawn`].
    pub fn spawn_local<F, Fut>(
        &self,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + 'static,
        Fut: Future + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let Some(pending) = self.pending_spawn_counter_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_local_via_lane(
            self.region_id(),
            self.inherited_budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            false,
            f,
        )
    }

    /// Registers the current-thread driver's bookkeeping task with its exact
    /// inherited budget. Admission marks the caller as the poll-quota owner
    /// before any scheduler poll, so even a zero-quota root receives its task
    /// identity before the actual root future is charged.
    pub(crate) fn spawn_root_accounting<F, Fut>(
        &self,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + 'static,
        Fut: Future + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let Some(pending) = self.pending_spawn_counter_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_local_via_lane(
            self.region_id(),
            self.inherited_budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            true,
            f,
        )
    }

    /// Spawns a `!Send` task into **`scope`'s region**, pinned to the
    /// current worker thread (br-asupersync-i9y5wb / A2.2a).
    ///
    /// The scope-targeting sibling of [`Cx::spawn_local`]: region
    /// ownership, budget, and pending-spawn accounting come from `scope`
    /// exactly as in [`Cx::spawn_in`].
    /// Cancellation-result classification is identical to [`Cx::spawn`].
    ///
    /// # Errors
    ///
    /// As [`Cx::spawn_local`], plus
    /// [`SpawnError::RuntimeUnavailable`](crate::runtime::SpawnError::RuntimeUnavailable)
    /// when `scope` carries no
    /// pending-spawn counter for its region (see [`Cx::spawn_in`]).
    pub fn spawn_local_in<F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> Fut + 'static,
        Fut: Future + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let pending = scope.pending_spawn_counter_handle().or_else(|| {
            (scope.region_id() == self.region_id())
                .then(|| self.pending_spawn_counter_handle())
                .flatten()
        });
        let Some(pending) = pending else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_local_via_lane(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            false,
            f,
        )
    }

    /// Owner-pinned counterpart of
    /// [`Self::spawn_in_cancellation_dominant`].
    pub(crate) fn spawn_local_in_cancellation_dominant<F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> Fut + 'static,
        Fut: Future + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let pending = scope.pending_spawn_counter_handle().or_else(|| {
            (scope.region_id() == self.region_id())
                .then(|| self.pending_spawn_counter_handle())
                .flatten()
        });
        let Some(pending) = pending else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        self.spawn_local_via_lane(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::CancellationDominant,
            false,
            f,
        )
    }

    /// Producer-side machinery for the owner-pinned local spawn lane:
    /// `!Send` mirror of [`Self::spawn_via_gateway`]. Fails closed with
    /// `LocalSchedulerUnavailable` off-worker (the thread-local lane is
    /// only drained by runtime workers), then parks a
    /// [`LocalSpawnRequest`](crate::runtime::spawn_mailbox::LocalSpawnRequest)
    /// on the calling worker's lane and returns a pending handle.
    fn spawn_local_via_lane<F, Fut>(
        &self,
        region: RegionId,
        budget: Budget,
        capability_budget: crate::types::CapabilityBudget,
        gateway: &Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
        pending: &Arc<crate::record::region::PendingSpawnCounter>,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
        caller_owned_poll_quota: bool,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + 'static,
        Fut: Future + 'static,
        Fut::Output: Send + 'static,
    {
        use crate::runtime::spawn_mailbox::{
            AdmittedTaskSlot, LocalSpawnFactoryFn, LocalSpawnRequest,
        };
        use crate::runtime::task_handle::JoinError;

        let Some(_liveness_guard) = gateway.liveness_guard() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        if !self.runtime_mask.has(cap::CapMask::SPAWN) {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        }
        if crate::runtime::scheduler::three_lane::current_worker_id().is_none() {
            return Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable);
        }
        if !crate::runtime::spawn_mailbox::local_spawn_lane_is_owned_by(gateway) {
            return Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable);
        }
        if !caller_owned_poll_quota {
            gateway.verify_spawn_cx(self, region, budget)?;
        }

        let provisional = gateway.mailbox().allocate_task_id();
        // Retirement barrier shared by this task's join handle (via the slot),
        // its `CxInner` (installed on first poll below), and the scheduler
        // (which opens it after the record commits terminal). Keeps a joined
        // owner from observing completion — and closing its region — before the
        // record is committed (br-asupersync-yhueis).
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        let admitted_slot = Arc::new(
            AdmittedTaskSlot::new_with_cancel_gateway(Arc::clone(gateway))
                .with_runtime_mask(self.runtime_mask)
                .with_caller_owned_poll_quota(caller_owned_poll_quota)
                .with_spawn_authority(gateway.capture_spawn_authority(self))
                .with_retirement_barrier(Arc::clone(&barrier))
                // Admission builds the task's one context with these, so
                // `Cx::current()` in the task carries them (br-asupersync-93zkbz).
                .with_inherited_handles(self.inherited_handles())
                .with_spawn_fallback(self.spawn_fallback_for(region)),
        );
        let (result_tx, handle) = crate::runtime::task_handle::pending_task_handle_channel::<
            Fut::Output,
        >(provisional, Arc::clone(&admitted_slot));
        // Take-once semantics across the mutually exclusive completion and
        // denial paths, as in `spawn_via_gateway`.
        let shared_tx = Arc::new(std::sync::Mutex::new(Some(result_tx)));

        let parent = self.clone();
        let factory_tx = Arc::clone(&shared_tx);
        let factory_barrier = Arc::clone(&barrier);
        let factory: LocalSpawnFactoryFn = Box::new(move |admission_cx: Cx| {
            Box::pin(async move {
                match (crate::cx::scope::CatchUnwind {
                    inner: async move {
                        let task_id = admission_cx.task_id();
                        let child: Cx<Caps> = admission_cx.overlay_parent_inheritance::<_, Caps>(
                            &parent,
                            task_id,
                            capability_budget,
                        );
                        // Install the shared retirement barrier into this task's
                        // CxInner so the scheduler can open it after the record
                        // commits terminal (br-asupersync-yhueis).
                        child.install_retirement_barrier(std::sync::Arc::clone(&factory_barrier));
                        let completion_cx = child.retype::<cap::All>();
                        crate::runtime::task_handle::observe_spawn_completion(
                            f(child),
                            completion_cx,
                            completion_policy,
                        )
                        .await
                    },
                })
                .await
                {
                    Ok(observed) => {
                        if let Some(tx) = take_spawn_result_sender(&factory_tx) {
                            // Terminal result publication is bookkeeping, not
                            // cancellable task work. The user future may have
                            // returned its operation-level cancellation after
                            // observing this task's cancelled Cx; using that Cx
                            // again here would discard the value and collapse
                            // join into a misleading task-level cancellation.
                            let result = observed.classify();
                            crate::runtime::task_handle::publish_terminal_result(tx, result);
                        }
                        crate::types::Outcome::Ok(())
                    }
                    Err(payload) => {
                        let message = crate::cx::scope::payload_to_string(&payload);
                        drop(payload);
                        let panic_payload = crate::types::outcome::PanicPayload::new(message);
                        if let Some(tx) = take_spawn_result_sender(&factory_tx) {
                            crate::runtime::task_handle::publish_terminal_result(
                                tx,
                                Err(JoinError::Panicked(panic_payload.clone())),
                            );
                        }
                        crate::types::Outcome::Panicked(panic_payload)
                    }
                }
            })
        });

        let cancel_tx = Arc::clone(&shared_tx);
        let error_tx = Arc::clone(&shared_tx);
        // A denied task is never minted into a record, so the scheduler never
        // opens its retirement barrier. Open it when the denial publishes its
        // terminal Err, or a handle gating on that value would wait forever
        // (br-asupersync-yhueis, admission-denial hazard).
        let cancel_barrier = Arc::clone(&barrier);
        let error_barrier = Arc::clone(&barrier);
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget,
            factory,
            on_unadmitted_cancel: Some(Box::new(move |reason| {
                if let Some(tx) = take_spawn_result_sender(&cancel_tx) {
                    crate::runtime::task_handle::publish_terminal_result(
                        tx,
                        Err(JoinError::Cancelled(reason)),
                    );
                    cancel_barrier.open_and_wake();
                }
            })),
            on_admission_error: Some(Box::new(move |error| {
                if let Some(tx) = take_spawn_result_sender(&error_tx) {
                    let mut reason = crate::types::CancelReason::user("spawn admission failed");
                    reason.message = Some(error.to_string());
                    crate::runtime::task_handle::publish_terminal_result(
                        tx,
                        Err(JoinError::Cancelled(reason)),
                    );
                    error_barrier.open_and_wake();
                }
            })),
            pending_reservation: Some(pending.reserve()),
            admitted_slot: Some(Arc::clone(&admitted_slot)),
        };

        if let Some(trace) = self.trace_buffer() {
            let now = self.current_checkpoint_time();
            trace
                .record_event(|seq| TraceEvent::task_spawn_enqueued(seq, now, provisional, region));
        }
        crate::runtime::spawn_mailbox::enqueue_local_spawn(request);
        Ok(handle)
    }

    /// Shared producer-side machinery for the lock-free spawn paths
    /// ([`Cx::spawn`], [`Cx::spawn_in`]): enqueues a factory-carrying
    /// [`SpawnRequest`](crate::runtime::spawn_mailbox::SpawnRequest) on the
    /// gateway with a pending reservation against `pending`, a take-once
    /// result channel, and cancel/admission-error slots, returning a
    /// pending [`TaskHandle`](crate::runtime::TaskHandle).
    fn spawn_via_gateway<F, Fut>(
        &self,
        region: RegionId,
        budget: Budget,
        capability_budget: crate::types::CapabilityBudget,
        gateway: &Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
        pending: &Arc<crate::record::region::PendingSpawnCounter>,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.spawn_via_gateway_in_branch(
            region,
            budget,
            capability_budget,
            gateway,
            pending,
            completion_policy,
            None,
            f,
        )
    }

    /// Spawns one race branch into `scope`'s region, asking admission to run
    /// it in a fresh sealed child region of that region
    /// (br-asupersync-issue65-criticisms-kpmoy5.2.2).
    ///
    /// Everything the branch spawns through its own context lands in that
    /// child region, so the race can cancel and drain a losing branch's whole
    /// subtree. The region closes by itself once the branch and its
    /// descendants finish, so a winner's descendants keep running after the
    /// race returns. The returned slot names the region once admission has
    /// minted it; it stays empty if the mint was refused, in which case the
    /// branch runs in `scope`'s region as before.
    pub(crate) fn spawn_race_branch_in<F, Fut, P>(
        &self,
        scope: &crate::cx::Scope<'_, P>,
        f: F,
    ) -> Result<
        (
            crate::runtime::TaskHandle<Fut::Output>,
            Arc<crate::runtime::spawn_mailbox::BranchRegionSlot>,
        ),
        crate::runtime::state::SpawnError,
    >
    where
        P: crate::types::Policy,
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let Some(gateway) = self.spawn_gateway_handle() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let pending = scope.pending_spawn_counter_handle().or_else(|| {
            (scope.region_id() == self.region_id())
                .then(|| self.pending_spawn_counter_handle())
                .flatten()
        });
        let Some(pending) = pending else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };
        let branch = Arc::new(crate::runtime::spawn_mailbox::BranchRegionSlot::new());
        let handle = self.spawn_via_gateway_in_branch(
            scope.region_id(),
            scope.budget(),
            scope.capability_budget(),
            &gateway,
            &pending,
            crate::runtime::task_handle::SpawnCompletionPolicy::PreserveAcknowledgedCancellationResult,
            Some(Arc::clone(&branch)),
            f,
        )?;
        Ok((handle, branch))
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_via_gateway_in_branch<F, Fut>(
        &self,
        region: RegionId,
        budget: Budget,
        capability_budget: crate::types::CapabilityBudget,
        gateway: &Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
        pending: &Arc<crate::record::region::PendingSpawnCounter>,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
        branch_region: Option<Arc<crate::runtime::spawn_mailbox::BranchRegionSlot>>,
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        self.spawn_via_gateway_in_branch_observed(
            region,
            budget,
            capability_budget,
            gateway,
            pending,
            completion_policy,
            branch_region,
            f,
            crate::runtime::task_handle::NoopSpawnTerminalObserver,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_via_gateway_in_branch_observed<F, Fut, Observer>(
        &self,
        region: RegionId,
        budget: Budget,
        capability_budget: crate::types::CapabilityBudget,
        gateway: &Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
        pending: &Arc<crate::record::region::PendingSpawnCounter>,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
        branch_region: Option<Arc<crate::runtime::spawn_mailbox::BranchRegionSlot>>,
        f: F,
        observer: Observer,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
        Observer: crate::runtime::task_handle::SpawnTerminalObserver<Fut::Output>,
    {
        // Ambient lookup returns a FullCx carrying the narrowed runtime mask.
        // The HasSpawn type bound alone cannot enforce that restriction. Check
        // before allocating a task identity or reserving region admission.
        if !self.runtime_mask.has(cap::CapMask::SPAWN) {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        }

        let Some(_liveness_guard) = gateway.liveness_guard() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };

        gateway.verify_spawn_cx(self, region, budget)?;
        let (request, handle) = self.prepare_spawn_request(
            region,
            budget,
            capability_budget,
            gateway,
            pending,
            completion_policy,
            branch_region,
            f,
            observer,
        );
        gateway.enqueue_and_notify(request)?;
        Ok(handle)
    }

    /// Prepares a single member without publishing it or invoking its factory.
    /// The caller validates capability and runtime liveness, and retains its
    /// liveness guard until all prepared requests have been published.
    #[allow(clippy::too_many_arguments)]
    fn prepare_spawn_request<F, Fut, Observer>(
        &self,
        region: RegionId,
        budget: Budget,
        capability_budget: crate::types::CapabilityBudget,
        gateway: &Arc<crate::runtime::spawn_mailbox::SpawnGateway>,
        pending: &Arc<crate::record::region::PendingSpawnCounter>,
        completion_policy: crate::runtime::task_handle::SpawnCompletionPolicy,
        branch_region: Option<Arc<crate::runtime::spawn_mailbox::BranchRegionSlot>>,
        f: F,
        observer: Observer,
    ) -> (
        crate::runtime::spawn_mailbox::SpawnRequest,
        crate::runtime::TaskHandle<Fut::Output>,
    )
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
        Observer: crate::runtime::task_handle::SpawnTerminalObserver<Fut::Output>,
    {
        use crate::runtime::spawn_mailbox::{AdmittedTaskSlot, SpawnFactoryFn, SpawnRequest};
        use crate::runtime::task_handle::JoinError;

        let provisional = gateway.mailbox().allocate_task_id();
        // Retirement barrier shared by this task's join handle (via the slot),
        // its `CxInner` (installed on first poll below), and the scheduler
        // (which opens it after the record commits terminal). Keeps a joined
        // owner from observing completion — and closing its region — before the
        // record is committed (br-asupersync-yhueis).
        let barrier = crate::runtime::task_handle::RetirementBarrier::pending();
        let mut admitted_slot = AdmittedTaskSlot::new_with_cancel_gateway(Arc::clone(gateway))
            .with_runtime_mask(self.runtime_mask)
            .with_spawn_authority(gateway.capture_spawn_authority(self))
            .with_retirement_barrier(Arc::clone(&barrier))
            // Admission builds the task's one context with these, so
            // `Cx::current()` in the task carries them (br-asupersync-93zkbz).
            .with_inherited_handles(self.inherited_handles())
            .with_spawn_fallback(self.spawn_fallback_for(region));
        if let Some(branch_region) = branch_region {
            admitted_slot = admitted_slot.with_branch_region(branch_region);
        }
        let admitted_slot = Arc::new(admitted_slot);
        let (result_tx, handle) = crate::runtime::task_handle::pending_task_handle_channel::<
            Fut::Output,
        >(provisional, Arc::clone(&admitted_slot));
        // The sender is claimed by exactly one of: task completion (inside
        // the factory-built future) or a denial slot. `Mutex<Option<..>>`
        // gives take-once semantics across those mutually exclusive paths.
        let shared_tx = Arc::new(std::sync::Mutex::new(Some(result_tx)));

        // Parent snapshot for capability inheritance (cheap Arc clones).
        let parent = self.clone();
        let factory_tx = Arc::clone(&shared_tx);
        let factory_barrier = Arc::clone(&barrier);
        let factory: SpawnFactoryFn = Box::new(move |admission_cx: Cx| {
            Box::pin(async move {
                // Retain the admitted identity even if inheritance or factory
                // construction panics before the user future starts.
                let task_id = admission_cx.task_id();
                let polled = (crate::cx::scope::CatchUnwind {
                    inner: async move {
                        let child: Cx<Caps> = admission_cx.overlay_parent_inheritance::<_, Caps>(
                            &parent,
                            task_id,
                            capability_budget,
                        );
                        // Install the shared retirement barrier into this task's
                        // CxInner so the scheduler can open it after the record
                        // commits terminal (br-asupersync-yhueis).
                        child.install_retirement_barrier(std::sync::Arc::clone(&factory_barrier));
                        let completion_cx = child.retype::<cap::All>();
                        crate::runtime::task_handle::observe_spawn_completion(
                            f(child),
                            completion_cx,
                            completion_policy,
                        )
                        .await
                    },
                })
                .await;
                // Ordinary spawns use the original direct classification.
                // An opted-in typed owner can also contain a destructor panic
                // from a value suppressed by cancellation, before observing it.
                let classified = match polled {
                    Ok(observed) => observer.classify(observed),
                    Err(payload) => Err(payload),
                };
                match classified {
                    Ok(result) => {
                        // User policy runs only after the result is immutable,
                        // outside both runtime and result-sender locks. A policy
                        // cancel request therefore cannot rewrite this value.
                        observer.on_terminal(task_id, &result);
                        if let Some(tx) = take_spawn_result_sender(&factory_tx) {
                            crate::runtime::task_handle::publish_terminal_result(tx, result);
                        }
                        crate::types::Outcome::Ok(())
                    }
                    Err(payload) => {
                        let panic_payload = observer.panic_payload(payload);
                        let result = Err(JoinError::Panicked(panic_payload.clone()));
                        observer.on_terminal(task_id, &result);
                        if let Some(tx) = take_spawn_result_sender(&factory_tx) {
                            crate::runtime::task_handle::publish_terminal_result(tx, result);
                        }
                        crate::types::Outcome::Panicked(panic_payload)
                    }
                }
            })
        });

        let cancel_tx = Arc::clone(&shared_tx);
        let error_tx = Arc::clone(&shared_tx);
        // A denied task is never minted into a record, so the scheduler never
        // opens its retirement barrier. Open it when the denial publishes its
        // terminal Err, or a handle gating on that value would wait forever
        // (br-asupersync-yhueis, admission-denial hazard).
        let cancel_barrier = Arc::clone(&barrier);
        let error_barrier = Arc::clone(&barrier);
        let request = SpawnRequest::new_with_factory(provisional, region, budget, factory)
            .with_admitted_slot(Arc::clone(&admitted_slot))
            .with_pending_reservation(pending.reserve())
            .with_unadmitted_cancel(Box::new(move |reason| {
                if let Some(tx) = take_spawn_result_sender(&cancel_tx) {
                    crate::runtime::task_handle::publish_terminal_result(
                        tx,
                        Err(JoinError::Cancelled(reason)),
                    );
                    cancel_barrier.open_and_wake();
                }
            }))
            .with_admission_error_slot(Box::new(move |error| {
                if let Some(tx) = take_spawn_result_sender(&error_tx) {
                    let mut reason = crate::types::CancelReason::user("spawn admission failed");
                    reason.message = Some(error.to_string());
                    crate::runtime::task_handle::publish_terminal_result(
                        tx,
                        Err(JoinError::Cancelled(reason)),
                    );
                    error_barrier.open_and_wake();
                }
            }));

        (request, handle)
    }

}

impl<Caps> Cx<Caps> {
    /// The region that admits a spawn into this context's own region once
    /// that sealed (race-branch) region has closed (br-asupersync-k27oxe).
    /// `None` for a spawn that names any other region: a closed scope or
    /// child region still denies it.
    pub(crate) fn spawn_fallback_for(&self, region: RegionId) -> Option<RegionId> {
        let inner = self.inner.read();
        if inner.region == region {
            inner.spawn_fallback_region
        } else {
            None
        }
    }

}

impl<Caps> Cx<Caps>
where
    Caps: cap::HasSpawn + Send + Sync + 'static,
{
    /// Records the fallback [`Self::spawn_fallback_for`] returns; admission
    /// sets it when it admits a task into a sealed region.
    pub(crate) fn set_spawn_fallback_region(&self, region: Option<RegionId>) {
        self.inner.write().spawn_fallback_region = region;
    }

    /// Snapshots the handles a task spawned from this context inherits:
    /// the entropy source (forked for the task at admission) and the io-cap,
    /// registry, remote, blocking-pool, evidence, macaroon, HTTP-client and
    /// pressure handles. The spawner takes it outside the runtime lock and
    /// moves it into the task's admission slot (br-asupersync-93zkbz).
    pub(crate) fn inherited_handles(&self) -> InheritedHandles {
        InheritedHandles {
            entropy: Some(self.handles.entropy.clone()),
            io_cap: self.io_cap_handle(),
            registry: self.registry_handle(),
            remote_cap: self.remote_cap_handle(),
            blocking_pool: self.blocking_pool_handle_for_inheritance(),
            evidence_sink: self.evidence_sink_handle(),
            macaroon: self.macaroon_handle(),
            default_http_client: self.handles.default_http_client.clone(),
            pressure: self.pressure_handle(),
            task_causality: self.task_causality_snapshot(),
        }
    }

    /// Moves a spawner's inherited handles into an admission-built context,
    /// mirroring `Scope::build_child_task_cx`: the handles replace what
    /// admission built, and a spawner without a pressure handle keeps the
    /// runtime's. Admission has already forked the spawner's entropy for the
    /// task. This only moves fields: the context is still private
    /// to admission, so `Arc::make_mut` does not clone (br-asupersync-93zkbz).
    pub(crate) fn adopt_inherited_handles(&mut self, inherited: InheritedHandles) {
        let InheritedHandles {
            entropy: _,
            io_cap,
            registry,
            remote_cap,
            blocking_pool,
            evidence_sink,
            macaroon,
            default_http_client,
            pressure,
            task_causality: _,
        } = inherited;
        let handles = Arc::make_mut(&mut self.handles);
        handles.io_cap = io_cap;
        handles.registry = registry;
        handles.remote_cap = remote_cap;
        handles.blocking_pool = blocking_pool;
        handles.evidence_sink = evidence_sink;
        handles.macaroon = macaroon;
        handles.default_http_client = default_http_client;
        if pressure.is_some() {
            handles.pressure = pressure;
        }
    }

    /// Finishes an admission-built child context for the spawn closure,
    /// mirroring `Scope::build_child_task_cx`: observability forks from the
    /// parent; `capability_budget` (the spawn target's planned envelope —
    /// the parent cx's for `Cx::spawn`, the SCOPE's for `Cx::spawn_in`,
    /// matching the state-threaded scope path, which applied the scope's;
    /// br-asupersync-4onmas) and the parent runtime mask apply.
    /// The inherited handles are already in place: admission moved them in
    /// from the slot, so the closure's context and the record's context
    /// (`Cx::current()` inside the task) share them (br-asupersync-93zkbz).
    /// State-side wiring (drivers, logical clock, trace buffer, loser-drain
    /// history, spawn gateway, region counter) stays as admission built it.
    /// The shared `CxInner` is untouched, so cancellation and budget flow
    /// through the record linkage admission already established.
    pub(crate) fn overlay_parent_inheritance<PCaps, Out>(
        self,
        parent: &Cx<PCaps>,
        task_id: TaskId,
        capability_budget: crate::types::CapabilityBudget,
    ) -> Cx<Out> {
        let region = self.region_id();
        *self.observability.write() = parent.child_observability(region, task_id);
        // A user fork that panicked at admission was deferred (DeferredFork):
        // retry it now, on the task and before its code runs, where the panic
        // reaches the join handle. source_id draws no randomness.
        let _ = self.handles.entropy.source_id();
        let _ = self.apply_child_capability_budget(
            capability_budget,
            crate::types::CapabilityBudgetRequirements::NONE,
        );
        let mut typed = self.retype::<Out>();
        typed.runtime_mask = parent.runtime_mask;
        typed
    }

    /// Installs this task's retirement barrier into its `CxInner`, so the
    /// scheduler can open it after the record commits terminal, releasing any
    /// consumer that received the terminal result early (br-asupersync-yhueis).
    /// Shares the barrier the spawn producer also handed the join handle; the
    /// two therefore gate on one signal.
    pub(crate) fn install_retirement_barrier(
        &self,
        barrier: std::sync::Arc<crate::runtime::task_handle::RetirementBarrier>,
    ) {
        barrier.attach_task_causality(self);
        self.inner.write().retirement_barrier = Some(barrier);
    }
}

impl Cx<cap::All> {
    /// Creates a capability context for testing purposes.
    ///
    /// This constructor creates a Cx with default IDs and an infinite budget,
    /// suitable for unit and integration tests. The resulting context is fully
    /// functional but not connected to a real runtime. The synthetic region is
    /// non-root so tests can create cancel-safe obligations without tripping the
    /// root-region leak guard.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::Cx;
    ///
    /// let cx = Cx::for_testing();
    /// assert!(!cx.is_cancel_requested());
    /// assert!(cx.checkpoint().is_ok());
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. Production code should receive
    /// Cx instances from the runtime, not construct them directly.
    ///
    /// # Visibility (br-asupersync-2x6hbi)
    ///
    /// Gated behind `#[cfg(any(test, feature = "test-internals"))]` so that
    /// production consumers of the asupersync crate cannot construct a
    /// `Cx<cap::All>` out of band, bypassing runtime cap-mask enforcement.
    /// Tests still see the constructor through `cfg(test)`, and explicit
    /// dev-time consumers can opt in with `--features test-internals`.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_testing() -> Self {
        Self::new(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
        )
    }

    /// Creates a test-only capability context with a specified budget.
    ///
    /// Similar to [`Self::for_testing()`] but allows specifying a custom budget
    /// for testing timeout behavior.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::{Cx, Budget, Time};
    ///
    /// // Create a context with a 30-second deadline
    /// let cx = Cx::for_testing_with_budget(
    ///     Budget::new().with_deadline(Time::from_secs(30))
    /// );
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. Production code should receive
    /// Cx instances from the runtime, not construct them directly.
    /// Gated behind `cfg(any(test, feature = "test-internals"))`
    /// (br-asupersync-2x6hbi).
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_testing_with_budget(budget: Budget) -> Self {
        Self::new(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            budget,
        )
    }

    /// Creates a test-only capability context with lab I/O capability.
    ///
    /// This constructor creates a Cx with a `LabIoCap` for testing I/O code paths
    /// without performing real I/O.
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::Cx;
    ///
    /// let cx = Cx::for_testing_with_io();
    /// assert!(cx.has_io());
    /// assert!(!cx.io().unwrap().is_real_io());
    /// ```
    ///
    /// # Note
    ///
    /// This API is intended for testing only. Gated behind
    /// `cfg(any(test, feature = "test-internals"))` (br-asupersync-2x6hbi).
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_testing_with_io() -> Self {
        Self::new_with_io(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::new(crate::io::LabIoCap::new_for_tests())),
            None,
        )
    }

    /// Creates a request-scoped capability context with a specified budget.
    ///
    /// br-asupersync-ovztin: this constructor is now gated behind
    /// `cfg(any(test, feature = "test-internals"))`. The pre-fix shape
    /// was fully `pub` and produced a Cx with `CapMask::all()` and
    /// freshly-minted ephemeral region/task IDs — i.e. **a fully
    /// ambient capability source available to any caller in any
    /// crate**. The doc comment claimed the resulting Cx "still
    /// carries the runtime cap-mask, so it cannot escalate beyond
    /// what the request handler was granted at the boundary"; that
    /// claim was false because [`Cx::new`] -> [`Cx::new_with_drivers`]
    /// constructed the runtime_mask as `CapMask::all()` without
    /// looking at any parent Cx.
    ///
    /// Concrete escape paths the previous shape allowed:
    ///
    ///   * **External-crate capability injection.** Any crate linking
    ///     asupersync could call `Cx::for_request_with_budget(Budget::
    ///     INFINITE)` from a Drop impl, panic handler, or sync helper
    ///     and get full Time / IO / blocking-pool / entropy /
    ///     remote_cap access.
    ///   * **Sandbox escape from restricted Cx.** A handler holding a
    ///     mask-narrowed Cx could call this to mint a fresh
    ///     all-capabilities Cx and bypass the restriction entirely.
    ///   * **Compounds with br-asupersync-3lk5n2 (now closed): the
    ///     ephemeral task is also not in `state.tasks`, so oracles /
    ///     deadline monitor / futurelock detector all silently miss
    ///     the request.
    ///
    /// Production callers that need a request-scoped Cx must go
    /// through [`crate::runtime::Runtime::request_cx_with_budget`],
    /// which inherits the runtime's drivers and cap-mask via
    /// `build_request_cx_from_inner` and is therefore non-escalating.
    ///
    /// Default builds exclude `test-internals`, so production
    /// consumers lose access to this constructor entirely unless they
    /// opt in explicitly. The only ambient-free way to mint a Cx in
    /// production is through the runtime boundary, which is
    /// capability-controlled.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_request_with_budget(budget: Budget) -> Self {
        Self::new(RegionId::new_ephemeral(), TaskId::new_ephemeral(), budget)
    }

    /// Creates a request-scoped capability context with an infinite budget.
    ///
    /// br-asupersync-ovztin: see [`Self::for_request_with_budget`] for
    /// the cfg-gating rationale; this is the infinite-budget convenience
    /// wrapper and is gated identically.
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_request() -> Self {
        Self::for_request_with_budget(Budget::INFINITE)
    }

    /// Creates a test-only capability context with a remote capability.
    ///
    /// This constructor creates a Cx with a [`RemoteCap`] for testing remote
    /// task spawning without a real network transport.
    ///
    /// # Note
    ///
    /// This API is intended for testing only. Gated behind
    /// `cfg(any(test, feature = "test-internals"))` (br-asupersync-2x6hbi).
    #[cfg(any(test, feature = "test-internals"))]
    #[must_use]
    pub fn for_testing_with_remote(cap: RemoteCap) -> Self {
        let mut cx = Self::for_testing();
        Arc::make_mut(&mut cx.handles).remote_cap = Some(Arc::new(cap));
        cx
    }
}

/// RAII guard returned by [`Cx::enter_span`].
///
/// On drop, restores the previous `DiagnosticContext` and emits a
/// span-exit log entry.
pub struct SpanGuard<Caps = cap::All> {
    cx: Cx<Caps>,
    prev: DiagnosticContext,
}

impl<Caps> Drop for SpanGuard<Caps> {
    fn drop(&mut self) {
        let name = self
            .cx
            .diagnostic_context()
            .custom("span.name")
            .unwrap_or("unknown")
            .to_owned();
        self.cx
            .log(LogEntry::debug(format!("span exit: {name}")).with_target("tracing"));
        self.cx.set_diagnostic_context(self.prev.clone());
    }
}

// Cancellation wake targets recycled per context, so a repeated cancel-aware
// wait (a contended Mutex lock, a Cancelled observer) allocates nothing once
// one target exists. These run without a Cx guard: Waker clone and drop are
// user callbacks.
impl<Caps> Cx<Caps> {
    /// A wake target for `waker`: a retired one from this context's pool when
    /// it holds one, otherwise a new allocation.
    fn recycled_cancel_waker(&self, waker: &Waker) -> Arc<CancelWaker> {
        let pooled = self.inner.write().cancel_waker_pool.pop();
        let incoming = waker.clone();
        match pooled {
            Some(mut target) => {
                if let Some(slot) = Arc::get_mut(&mut target) {
                    // The pooled target holds a no-op Waker.
                    drop(slot.replace_waker(incoming));
                    target
                } else {
                    Arc::new(CancelWaker::new(incoming))
                }
            }
            None => Arc::new(CancelWaker::new(incoming)),
        }
    }

    /// Retires a cleared wake target after the Cx guard is released. If no
    /// in-flight wake still holds it, its Waker is dropped here and the
    /// allocation goes back to the pool while the registry is open.
    fn recycle_cancel_waker(&self, retired: Option<Arc<CancelWaker>>) {
        let Some(mut target) = retired else {
            return;
        };
        let Some(slot) = Arc::get_mut(&mut target) else {
            return;
        };
        drop(slot.replace_waker(Waker::noop().clone()));
        let mut inner = self.inner.write();
        if !inner.cancel_waker_registry_closed
            && inner.cancel_waker_pool.len() < crate::types::task_context::CANCEL_WAKER_POOL_CAP
        {
            inner.cancel_waker_pool.push(target);
        }
        // Otherwise the target, now holding a no-op Waker, drops here and
        // runs no user code under the guard.
    }
}

#[cfg(test)]
#[path = "cx_inline_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "deadline_publication_tests.rs"]
mod deadline_publication_tests;
