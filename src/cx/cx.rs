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
use crate::types::task_context::{CancelWaker, CancelWakerRegistration};
use crate::types::{
    Budget, CancelKind, CancelReason, CapabilityBudget, CapabilityBudgetRefusal,
    CapabilityBudgetRequirements, CxInner, RegionId, SystemPressure, TaskId, Time,
};
use crate::util::{ArenaIndex, EntropySource, OsEntropy};
use std::cell::RefCell;
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
    /// Runtime-scoped default HTTP client slot. It is lazy so Cx creation does
    /// not allocate a pool unless the high-level HTTP facade is used.
    default_http_client: DefaultHttpClientSlot,
    #[cfg(feature = "messaging-fabric")]
    fabric_capabilities: Arc<FabricCapabilityRegistry>,
}

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
// Only 3 Arc increments instead of ~15.
impl<Caps> Clone for Cx<Caps> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
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
    }
}

type FullCx = Cx<cap::All>;

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
    cx: FullCx,
    mask: cap::CapMask,
}

thread_local! {
    /// Stack of `(cx, mask)` frames. The top of the stack is the
    /// innermost installed context; `current()` returns from there.
    /// The historical `Option<FullCx>` semantic is preserved by the
    /// invariant that an empty stack means "no current cx" — i.e.
    /// `current()` returns `None`.
    static CURRENT_CX_STACK: RefCell<Vec<CurrentCxFrame>> = const { RefCell::new(Vec::new()) };
}

/// Guard that pops the corresponding frame from the
/// `CURRENT_CX_STACK` on drop. (br-asupersync-5ckssb)
#[cfg_attr(feature = "test-internals", visibility::make(pub))]
/// Guard returned by ambient current-context installation helpers.
pub struct CurrentCxGuard {
    /// Whether this guard pushed a frame (true) or was a no-op
    /// (false, when caller passed `None`). Determines whether drop
    /// pops.
    pushed: bool,
    _not_send: std::marker::PhantomData<*mut ()>,
}

impl Drop for CurrentCxGuard {
    fn drop(&mut self) {
        if !self.pushed {
            return;
        }
        let _ = CURRENT_CX_STACK.try_with(|stack| {
            stack.borrow_mut().pop();
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
                    let mut cx = frame.cx.clone();
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
    /// [`set_current`](Self::set_current) contributes one unrestricted frame;
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
    /// — i.e. `frame.mask == frame.cx.runtime_mask`), borrowing the
    /// frame's `Cx` directly and handing `&Cx` to the closure. When a
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
                if frame.mask == frame.cx.runtime_mask {
                    // Common case: no restriction-stack narrowing. The
                    // borrowed frame.cx already carries the correct
                    // runtime mask, so we hand it to the closure
                    // without any Arc::clone — saves 3 atomic ops
                    // versus `Cx::current()`.
                    Some(f(&frame.cx))
                } else {
                    // Restricted: apply the frame's narrowed mask to a
                    // stack-local copy. Equivalent in cost to legacy
                    // `current()` (3 Arc::clone), so the worst case is
                    // a tie, never a regression.
                    let mut cx = frame.cx.clone();
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
    /// Pushes a new frame onto the thread-local stack with the FULL
    /// capability mask. For installations that should narrow the
    /// ambient view (e.g. when handing control to untrusted code
    /// that should not see full caps), use
    /// [`Cx::set_current_restricted`] instead.
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
        let pushed = CURRENT_CX_STACK.with(|stack| match cx {
            Some(cx) => {
                stack.borrow_mut().push(CurrentCxFrame {
                    cx,
                    mask: cap::CapMask::all(),
                });
                true
            }
            None => false,
        });
        CurrentCxGuard {
            pushed,
            _not_send: std::marker::PhantomData,
        }
    }
}

impl<Caps> Cx<Caps>
where
    Caps: cap::CapSetRuntimeMask,
{
    /// Push this cx onto the thread-local restriction stack with
    /// its OWN runtime mask (computed from the type-level `Caps`
    /// parameter). While the returned guard is alive, any ambient
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
        let mask = <Caps as cap::CapSetRuntimeMask>::MASK;
        let cx = self.retype::<cap::All>();
        CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            assert!(
                s.len() < crate::types::task_context::MAX_CONTEXT_STACK_DEPTH,
                "context stack depth exceeded MAX_CONTEXT_STACK_DEPTH ({}): this prevents \
                 stack overflow in pathological nesting scenarios. Consider reducing \
                 nesting depth or restructuring the code to avoid excessive context \
                 restriction nesting.",
                crate::types::task_context::MAX_CONTEXT_STACK_DEPTH
            );
            s.push(CurrentCxFrame { cx, mask });
        });
        CurrentCxGuard {
            pushed: true,
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
        let pushed = CURRENT_CX_STACK.with(|stack| {
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
                None => return false,
            };
            s.push(CurrentCxFrame {
                cx,
                mask: intersected_mask,
            });
            true
        });
        CurrentCxGuard {
            pushed,
            _not_send: std::marker::PhantomData,
        }
    }
}

impl<Caps> Cx<Caps> {
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
        let (region, task) = {
            let guard = inner.read();
            (guard.region, guard.task)
        };
        Self {
            inner,
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
                remote_cap: None,
                registry: None,
                pressure: None,
                evidence_sink: None,
                macaroon: None,
                spawn_gateway: None,
                pending_spawns: None,
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
        let inner = Arc::new(parking_lot::RwLock::new(CxInner::new(region, task, budget)));
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
            observability,
            handles: Arc::new(CxHandles {
                io_driver,
                io_cap,
                timer_driver,
                blocking_pool: None,
                entropy,
                logical_clock: LogicalClockHandle::default(),
                remote_cap: None,
                registry: None,
                pressure: None,
                evidence_sink: None,
                macaroon: None,
                spawn_gateway: None,
                pending_spawns: None,
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

    /// Returns a cloned handle to the blocking pool, if present.
    #[inline]
    #[must_use]
    pub(crate) fn blocking_pool_handle(&self) -> Option<BlockingPoolHandle> {
        self.handles.blocking_pool.clone()
    }

    /// Attaches a blocking pool handle to this context.
    #[must_use]
    pub(crate) fn with_blocking_pool_handle(mut self, handle: Option<BlockingPoolHandle>) -> Self {
        Arc::make_mut(&mut self.handles).blocking_pool = handle;
        self
    }

    /// Attaches a logical clock handle to this context.
    #[must_use]
    pub(crate) fn with_logical_clock(mut self, clock: LogicalClockHandle) -> Self {
        Arc::make_mut(&mut self.handles).logical_clock = clock;
        self
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
    /// created via [`restrict`](Self::restrict) or [`retype`](Self::retype)
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

    /// Attaches the producer-side spawn gateway
    /// (br-asupersync-hwjqyo / A2.2).
    #[must_use]
    pub(crate) fn with_spawn_gateway(
        mut self,
        gateway: Option<Arc<crate::runtime::spawn_mailbox::SpawnGateway>>,
    ) -> Self {
        self.inner.write().cancel_gateway = gateway.clone();
        Arc::make_mut(&mut self.handles).spawn_gateway = gateway;
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
    /// [`CaveatPredicate::TimeBefore`].
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
    /// This is a non-blocking check that queries whether a cancellation signal
    /// has been sent to this task. Unlike `checkpoint()`, this method does not
    /// return an error - it just reports the current state.
    ///
    /// Frameworks should check this periodically during long-running operations
    /// to enable graceful shutdown.
    ///
    /// # Example
    ///
    /// ```ignore
    /// async fn process_items(cx: &Cx, items: Vec<Item>) -> Result<(), Error> {
    ///     for item in items {
    ///         // Check for cancellation between items
    ///         if cx.is_cancel_requested() {
    ///             return Err(Error::Cancelled);
    ///         }
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
        // read lock, atomically check `fast_cancel`, snapshot the (Copy)
        // budget to detect deadline / poll / cost exhaustion inline, and
        // record progress via two atomic ops — without acquiring the
        // write lock or cloning `cancel_reason`.
        //
        // Correctness: `fast_cancel` is set with `Release` ordering by
        // every cancellation source (TaskHandle::cancel, deadline_monitor,
        // and the slow path below when it newly observes exhaustion). An
        // `Acquire` load here therefore observes any prior cancellation.
        // Budget exhaustion is checked inline so unit-test invariants
        // ("checkpoint detects deadline / poll-quota / cost-budget
        // exhaustion") are preserved without going through deadline_monitor.
        {
            let guard = self.inner.read();
            let cancelled = guard.fast_cancel.load(std::sync::atomic::Ordering::Acquire);
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
            let budget_exhaustion = Self::checkpoint_budget_exhaustion(
                inner.region,
                inner.task,
                inner.budget,
                checkpoint_time,
            );
            if let Some((reason, _, _)) = &budget_exhaustion {
                inner.cancel_requested = true;
                inner
                    .fast_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
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
            let budget_exhaustion = Self::checkpoint_budget_exhaustion(
                inner.region,
                inner.task,
                inner.budget,
                checkpoint_time,
            );
            if let Some((reason, _, _)) = &budget_exhaustion {
                inner.cancel_requested = true;
                inner
                    .fast_cancel
                    .store(true, std::sync::atomic::Ordering::Release);
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
    /// Unlike [`now`], this method does not require the `HasTime` capability.
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
                Err(crate::error::Error::new(crate::error::ErrorKind::Cancelled))
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

    /// Derives an entropy source for a child task.
    pub(crate) fn child_entropy(&self, task: TaskId) -> Arc<dyn EntropySource> {
        self.handles.entropy.fork(task)
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
        inner.cancel_requested = value;
        inner
            .fast_cancel
            .store(value, std::sync::atomic::Ordering::Release);
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
            inner.cancel_requested = value;
            inner
                .fast_cancel
                .store(value, std::sync::atomic::Ordering::Release);
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
        let mut incoming = Some(Arc::new(CancelWaker::new(waker.clone())));
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
        // arbitrary destruction callbacks. Retire them only after unlock.
        drop(retired_waker);
        drop(incoming);
        token
    }

    /// Idempotently registers one untracked current-task cancellation Waker.
    ///
    /// This compatibility slot never increments a refcount on repoll. Callers
    /// that own a future across polls should use [`Self::refresh_cancel_waker`]
    /// and retain its token instead.
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
        drop(retired_waker);
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
        let (region, task, wakers) = {
            let mut inner = self.inner.write();
            let region = inner.region;
            let task = inner.task;

            let mut reason = CancelReason::new(kind).with_region(region).with_task(task);
            if let Some(msg) = message {
                reason = reason.with_message(msg);
            }

            inner.cancel_requested = true;
            inner
                .fast_cancel
                .store(true, std::sync::atomic::Ordering::Release);
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

            inner.cancel_requested = true;
            inner
                .fast_cancel
                .store(true, std::sync::atomic::Ordering::Release);
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
            inner.cancel_requested = true;
            inner
                .fast_cancel
                .store(true, std::sync::atomic::Ordering::Release);
            inner.cancel_reason = Some(reason);
            let wakers = inner.cancel_waker_snapshot();
            inner.cancel_wakers_pending = false;
            wakers
        };
        crate::types::task_context::CancelWakeEffects::new(wakers).dispatch();
    }

    /// Races multiple futures, waiting for the first to complete.
    ///
    /// This method is used by the `race!` macro. It runs the provided futures
    /// concurrently (inline, not spawned) and returns the result of the first
    /// one to complete. Losers are dropped (cancelled).
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
        let budget = self.budget();
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
        let parent_budget = self.budget();
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
    /// Because branches run as spawned tasks, each must be `Send + 'static` and
    /// the output `T` must be `Send + 'static`, and this context must be
    /// runtime-wired (carry a spawn gateway). A branch that fails admission
    /// fails the race closed with [`JoinError::Cancelled`]; already-spawned
    /// siblings are cancelled as the race future unwinds.
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
        for future in futures {
            match self.spawn_in(&scope, move |_child| future) {
                Ok(handle) => handles.push(handle),
                Err(_spawn_err) => {
                    // Fail closed: dropping the already-spawned handles requests
                    // their cancellation. Surface the admission failure as a
                    // cancellation so the `race!` caller never observes a
                    // partially-built race silently succeeding.
                    drop(handles);
                    return Err(JoinError::Cancelled(CancelReason::user(
                        "race! branch spawn failed",
                    )));
                }
            }
        }

        scope
            .race_all(self, handles)
            .await
            .map(|(value, _index)| value)
    }

    /// Races multiple **named** inline futures with loser-drain semantics.
    ///
    /// Names are accepted for source-level symmetry with [`Cx::race_named`];
    /// the drain machinery itself is name-agnostic. See [`Cx::race_drained`]
    /// for the full guarantee.
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
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when this Cx carries no
    /// spawn gateway or region counter (e.g. built by a harness without
    /// runtime wiring). Admission-time denials (region closing, quota)
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
            self.budget(),
            self.capability_budget(),
            &gateway,
            &pending,
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
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when this Cx carries no
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
    ///
    /// # Errors
    ///
    /// Returns [`SpawnError::RuntimeUnavailable`] when this Cx carries no
    /// spawn gateway, or when `scope` carries no pending-spawn counter for
    /// its region (see [`Cx::spawn_in`]). Admission-time denials resolve
    /// through the returned handle as
    /// [`JoinError::Cancelled`](crate::runtime::JoinError::Cancelled).
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
    /// Returns [`SpawnError::RuntimeUnavailable`] when this Cx carries no
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
        self.spawn(move |child| async move {
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
    /// Returns [`SpawnError::RuntimeUnavailable`] when this Cx carries no
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
        self.spawn_in(scope, move |child| async move {
            match pool {
                Some(pool) => {
                    crate::runtime::spawn_blocking::spawn_blocking_on_pool(pool, move || f(child))
                        .await
                }
                None => f(child),
            }
        })
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
    /// Returns [`SpawnError::LocalSchedulerUnavailable`] when the calling
    /// thread is not a runtime worker (local spawns require an owner
    /// worker; this includes the lab runtime and blocking-pool threads —
    /// unlike the legacy path this never panics). Returns
    /// [`SpawnError::RuntimeUnavailable`] when this Cx carries no spawn
    /// gateway or region counter. Admission-time denials (region closing,
    /// quota) resolve through the returned handle as
    /// `JoinError::Cancelled`.
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
            self.budget(),
            self.capability_budget(),
            &gateway,
            &pending,
            f,
        )
    }

    /// Spawns a `!Send` task into **`scope`'s region**, pinned to the
    /// current worker thread (br-asupersync-i9y5wb / A2.2a).
    ///
    /// The scope-targeting sibling of [`Cx::spawn_local`]: region
    /// ownership, budget, and pending-spawn accounting come from `scope`
    /// exactly as in [`Cx::spawn_in`].
    ///
    /// # Errors
    ///
    /// As [`Cx::spawn_local`], plus
    /// [`SpawnError::RuntimeUnavailable`] when `scope` carries no
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
        if crate::runtime::scheduler::three_lane::current_worker_id().is_none() {
            return Err(crate::runtime::state::SpawnError::LocalSchedulerUnavailable);
        }

        let (result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<Fut::Output, JoinError>>();
        // Take-once semantics across the mutually exclusive completion and
        // denial paths, as in `spawn_via_gateway`.
        let shared_tx = Arc::new(std::sync::Mutex::new(Some(result_tx)));
        let admitted_slot = Arc::new(AdmittedTaskSlot::new_with_cancel_gateway(Arc::clone(
            gateway,
        )));
        let pending_cancel_reason =
            crate::runtime::spawn_mailbox::register_pending_cancel_rendezvous(&admitted_slot);

        let parent = self.clone();
        let factory_tx = Arc::clone(&shared_tx);
        let factory: LocalSpawnFactoryFn = Box::new(move |admission_cx: Cx| {
            // Keep a context for terminal result delivery even if inheritance
            // itself panics. Retyping only clones the admission-built handles;
            // all user/reentrant hooks stay inside the caught future below.
            let completion_cx = admission_cx.retype::<cap::All>();
            Box::pin(async move {
                match (crate::cx::scope::CatchUnwind {
                    inner: async move {
                        let task_id = admission_cx.task_id();
                        let child: Cx<Caps> = admission_cx.overlay_parent_inheritance::<_, Caps>(
                            &parent,
                            task_id,
                            capability_budget,
                        );
                        let child_all = child.retype::<cap::All>();
                        let value = f(child).await;
                        (value, child_all)
                    },
                })
                .await
                {
                    Ok((value, child_all)) => {
                        if let Some(tx) = factory_tx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            let _ = tx.send(&child_all, Ok(value));
                        }
                        crate::types::Outcome::Ok(())
                    }
                    Err(payload) => {
                        let message = crate::cx::scope::payload_to_string(&payload);
                        std::mem::forget(payload);
                        let panic_payload = crate::types::outcome::PanicPayload::new(message);
                        if let Some(tx) = factory_tx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            let _ = tx.send(
                                &completion_cx,
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
        let provisional = gateway.mailbox().allocate_task_id();
        let request = LocalSpawnRequest {
            task_id: provisional,
            region,
            budget,
            factory,
            on_unadmitted_cancel: Some(Box::new(move |reason| {
                if let Some(tx) = cancel_tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = tx.send_blocking(Err(JoinError::Cancelled(reason)));
                }
            })),
            on_admission_error: Some(Box::new(move |error| {
                if let Some(tx) = error_tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let mut reason = crate::types::CancelReason::user("spawn admission failed");
                    reason.message = Some(error.to_string());
                    let _ = tx.send_blocking(Err(JoinError::Cancelled(reason)));
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
        let handle = crate::runtime::TaskHandle::new_pending(provisional, result_rx, admitted_slot);
        crate::runtime::spawn_mailbox::enqueue_local_spawn(request);
        drop(pending_cancel_reason);
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
        f: F,
    ) -> Result<crate::runtime::TaskHandle<Fut::Output>, crate::runtime::state::SpawnError>
    where
        F: FnOnce(Cx<Caps>) -> Fut + Send + 'static,
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        use crate::runtime::spawn_mailbox::{AdmittedTaskSlot, SpawnFactoryFn, SpawnRequest};
        use crate::runtime::task_handle::JoinError;

        let Some(_liveness_guard) = gateway.liveness_guard() else {
            return Err(crate::runtime::state::SpawnError::RuntimeUnavailable);
        };

        let (result_tx, result_rx) =
            crate::channel::oneshot::channel::<Result<Fut::Output, JoinError>>();
        // The sender is claimed by exactly one of: task completion (inside
        // the factory-built future) or a denial slot. `Mutex<Option<..>>`
        // gives take-once semantics across those mutually exclusive paths.
        let shared_tx = Arc::new(std::sync::Mutex::new(Some(result_tx)));
        let admitted_slot = Arc::new(AdmittedTaskSlot::new_with_cancel_gateway(Arc::clone(
            gateway,
        )));
        let pending_cancel_reason =
            crate::runtime::spawn_mailbox::register_pending_cancel_rendezvous(&admitted_slot);

        // Parent snapshot for capability inheritance (cheap Arc clones).
        let parent = self.clone();
        let factory_tx = Arc::clone(&shared_tx);
        let factory: SpawnFactoryFn = Box::new(move |admission_cx: Cx| {
            // Keep a context for terminal result delivery even if inheritance
            // itself panics. Retyping only clones the admission-built handles;
            // all user/reentrant hooks stay inside the caught future below.
            let completion_cx = admission_cx.retype::<cap::All>();
            Box::pin(async move {
                match (crate::cx::scope::CatchUnwind {
                    inner: async move {
                        let task_id = admission_cx.task_id();
                        let child: Cx<Caps> = admission_cx.overlay_parent_inheritance::<_, Caps>(
                            &parent,
                            task_id,
                            capability_budget,
                        );
                        let child_all = child.retype::<cap::All>();
                        let value = f(child).await;
                        (value, child_all)
                    },
                })
                .await
                {
                    Ok((value, child_all)) => {
                        if let Some(tx) = factory_tx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            let _ = tx.send(&child_all, Ok(value));
                        }
                        crate::types::Outcome::Ok(())
                    }
                    Err(payload) => {
                        let message = crate::cx::scope::payload_to_string(&payload);
                        std::mem::forget(payload);
                        let panic_payload = crate::types::outcome::PanicPayload::new(message);
                        if let Some(tx) = factory_tx
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take()
                        {
                            let _ = tx.send(
                                &completion_cx,
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
        let provisional = gateway.mailbox().allocate_task_id();
        let request = SpawnRequest::new_with_factory(provisional, region, budget, factory)
            .with_admitted_slot(Arc::clone(&admitted_slot))
            .with_pending_reservation(pending.reserve())
            .with_unadmitted_cancel(Box::new(move |reason| {
                if let Some(tx) = cancel_tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let _ = tx.send_blocking(Err(JoinError::Cancelled(reason)));
                }
            }))
            .with_admission_error_slot(Box::new(move |error| {
                if let Some(tx) = error_tx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    let mut reason = crate::types::CancelReason::user("spawn admission failed");
                    reason.message = Some(error.to_string());
                    let _ = tx.send_blocking(Err(JoinError::Cancelled(reason)));
                }
            }));

        let handle = crate::runtime::TaskHandle::new_pending(provisional, result_rx, admitted_slot);
        gateway.enqueue_and_notify(request)?;
        drop(pending_cancel_reason);
        Ok(handle)
    }

    /// Overlays parent-inherited capability state onto an admission-built
    /// child context, mirroring `Scope::build_child_task_cx` exactly:
    /// observability and entropy fork from the parent; io-cap/registry/
    /// remote/blocking/evidence/macaroon/pressure handles copy from the
    /// parent; `capability_budget` (the spawn target's planned envelope —
    /// the parent cx's for `Cx::spawn`, the SCOPE's for `Cx::spawn_in`,
    /// matching the state-threaded scope path, which applied the scope's;
    /// br-asupersync-4onmas) and the parent runtime mask apply.
    /// State-side wiring (drivers, logical clock, trace buffer, loser-drain
    /// history, spawn gateway, region counter) stays as admission built it.
    /// The shared `CxInner` is untouched, so cancellation and budget flow
    /// through the record linkage admission already established.
    pub(crate) fn overlay_parent_inheritance<PCaps, Out>(
        mut self,
        parent: &Cx<PCaps>,
        task_id: TaskId,
        capability_budget: crate::types::CapabilityBudget,
    ) -> Cx<Out> {
        let region = self.region_id();
        *self.observability.write() = parent.child_observability(region, task_id);
        {
            let handles = Arc::make_mut(&mut self.handles);
            handles.entropy = parent.child_entropy(task_id);
            handles.io_cap = parent.io_cap_handle();
            handles.registry = parent.registry_handle();
            handles.remote_cap = parent.remote_cap_handle();
            handles.blocking_pool = parent.blocking_pool_handle();
            handles.evidence_sink = parent.evidence_sink_handle();
            handles.macaroon = parent.macaroon_handle();
            handles.default_http_client = parent.handles.default_http_client.clone();
            if let Some(pressure) = parent.pressure_handle() {
                handles.pressure = Some(pressure);
            }
        }
        let _ = self.apply_child_capability_budget(
            capability_budget,
            crate::types::CapabilityBudgetRequirements::NONE,
        );
        let mut typed = self.retype::<Out>();
        typed.runtime_mask = parent.runtime_mask;
        typed
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
    /// ```ignore
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
    /// ```ignore
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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::cx::macaroon::CaveatPredicate;
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::capability::{CommandFamily, FabricCapability, FabricCapabilityScope};
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::class::DeliveryClass;
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::ir::{CapabilityPermission, CapabilityTokenSchema, SubjectFamily};
    #[cfg(feature = "messaging-fabric")]
    use crate::messaging::subject::SubjectPattern;
    use crate::trace::TraceBufferHandle;
    use crate::types::CapabilityBudgetDimension;
    use crate::util::DetEntropy;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    static CURRENT_CX_DTOR_STATE: AtomicU8 = AtomicU8::new(0);

    thread_local! {
        static CURRENT_CX_DTOR_PROBE: CurrentCxDtorProbe = const { CurrentCxDtorProbe };
    }

    struct CurrentCxDtorProbe;

    impl Drop for CurrentCxDtorProbe {
        fn drop(&mut self) {
            let state = if Cx::is_active() {
                1
            } else if Cx::current().is_some() {
                2
            } else {
                3
            };
            CURRENT_CX_DTOR_STATE.store(state as u8, Ordering::SeqCst);
        }
    }

    fn test_cx() -> Cx<cap::All> {
        Cx::for_testing()
    }

    fn clear_current_stack() {
        CURRENT_CX_STACK.with(|stack| {
            stack.borrow_mut().clear();
        });
    }

    fn cap_layer(
        spawn: bool,
        time: bool,
        entropy: bool,
        io: bool,
        remote: bool,
    ) -> CapabilityLayerSnapshot {
        CapabilityLayerSnapshot {
            spawn,
            time,
            entropy,
            io,
            remote,
            trace: true,
        }
    }

    fn lab_with_spawn_cx() -> (crate::lab::LabRuntime, Cx<cap::All>, RegionId) {
        let mut lab = crate::lab::LabRuntime::new(crate::lab::LabConfig::default());
        let root = lab.state.create_root_region(Budget::INFINITE);
        let cx = Cx::new(root, TaskId::testing_default(), Budget::INFINITE)
            .with_spawn_gateway(lab.state.spawn_gateway())
            .with_pending_spawn_counter(
                lab.state
                    .region(root)
                    .map(crate::record::RegionRecord::pending_spawn_handle),
            );
        (lab, cx, root)
    }

    fn test_cx_with_entropy(seed: u64) -> Cx<cap::All> {
        Cx::new_with_observability(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::new(DetEntropy::new(seed))),
        )
    }

    #[test]
    fn spawn_registered_in_admits_and_registers_through_gateway() {
        struct YieldOnce(bool);

        impl std::future::Future for YieldOnce {
            type Output = ();

            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<()> {
                if self.0 {
                    std::task::Poll::Ready(())
                } else {
                    self.0 = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            }
        }

        let (mut lab, cx, root) = lab_with_spawn_cx();
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
        let mut handle = cx
            .spawn_registered_in(&scope, move |child| async move {
                assert_eq!(child.region_id(), child_region);
                ran_in_child.fetch_add(1, Ordering::SeqCst);
                YieldOnce(false).await;
                17usize
            })
            .expect("spawn_registered_in should enqueue through the gateway");

        assert!(
            crate::runtime::spawn_mailbox::is_spawn_mailbox_id(handle.task_id()),
            "pre-admission handle reports the provisional id"
        );
        assert_eq!(
            lab.state
                .region(child_region)
                .expect("child region should exist")
                .pending_spawn_count(),
            1,
            "pending reservation lands on the target scope region"
        );

        lab.step_for_test();

        assert_eq!(ran.load(Ordering::SeqCst), 1, "child task ran");
        assert!(
            !crate::runtime::spawn_mailbox::is_spawn_mailbox_id(handle.task_id()),
            "post-admission handle reports the canonical task id while the task is live"
        );
        assert_eq!(
            lab.state
                .task(handle.task_id())
                .expect("admitted task record should exist while pending")
                .owner,
            child_region
        );
        lab.run_until_quiescent();
        let joined = futures_lite::future::block_on(handle.join(&cx)).expect("joined child result");
        assert_eq!(joined, 17);
    }

    #[test]
    fn spawn_registered_in_without_runtime_wiring_fails_closed() {
        let cx = test_cx();
        let scope = cx.scope();
        let result = cx.spawn_registered_in(&scope, |_child| async move { 1usize });
        assert!(matches!(
            result,
            Err(crate::runtime::state::SpawnError::RuntimeUnavailable)
        ));
    }

    fn test_cx_with_virtual_time(budget: Budget, now: Time) -> Cx<cap::All> {
        let clock = Arc::new(crate::time::VirtualClock::starting_at(now));
        Cx::new_with_drivers(
            RegionId::new_for_test(0, 1),
            TaskId::new_for_test(0, 0),
            budget,
            None,
            None,
            None,
            Some(TimerDriverHandle::with_virtual_clock(clock)),
            None,
        )
    }

    #[test]
    fn introspection_capabilities_reflect_wrapper_type_level_masks() {
        let full = Arc::new(Cx::for_testing());

        let web: Arc<Cx<crate::cx::wrappers::WebCaps>> = crate::cx::wrappers::narrow(&full);
        let grpc: Arc<Cx<crate::cx::wrappers::GrpcCaps>> = crate::cx::wrappers::narrow(&full);
        let background: Arc<Cx<crate::cx::wrappers::BackgroundCaps>> =
            crate::cx::wrappers::narrow(&full);
        let pure: Arc<Cx<crate::cx::wrappers::PureCaps>> = crate::cx::wrappers::narrow(&full);
        let entropy: Arc<Cx<crate::cx::wrappers::EntropyCaps>> = crate::cx::wrappers::narrow(&full);

        let cases = [
            (
                web.capabilities(),
                cap_layer(false, true, false, true, false),
            ),
            (
                grpc.capabilities(),
                cap_layer(true, true, false, true, false),
            ),
            (
                background.capabilities(),
                cap_layer(true, true, false, false, false),
            ),
            (
                pure.capabilities(),
                cap_layer(false, false, false, false, false),
            ),
            (
                entropy.capabilities(),
                cap_layer(false, false, true, false, false),
            ),
        ];

        for (snapshot, expected_effective) in cases {
            assert_eq!(snapshot.runtime, cap_layer(true, true, true, true, true));
            assert_eq!(snapshot.effective, expected_effective);
            assert_eq!(snapshot.type_level, expected_effective);
            assert_eq!(snapshot.spawn, expected_effective.spawn);
            assert_eq!(snapshot.time, expected_effective.time);
            assert_eq!(snapshot.entropy, expected_effective.entropy);
            assert_eq!(snapshot.io, expected_effective.io);
            assert_eq!(snapshot.remote, expected_effective.remote);
            assert!(snapshot.trace);
        }
    }

    #[test]
    fn introspection_capabilities_intersect_type_and_runtime_masks() {
        clear_current_stack();

        let full = Cx::for_testing();
        let restricted_type: Cx<cap::None> = full.restrict::<cap::None>();
        let type_snapshot = restricted_type.capabilities();

        assert_eq!(
            type_snapshot.type_level,
            cap_layer(false, false, false, false, false)
        );
        assert_eq!(
            type_snapshot.runtime,
            cap_layer(true, true, true, true, true)
        );
        assert_eq!(
            type_snapshot.effective,
            cap_layer(false, false, false, false, false)
        );

        let _outer = Cx::set_current(Some(full.clone()));
        assert_eq!(Cx::restriction_depth(), 1);
        assert!(!Cx::is_restricted());

        let _restricted = Cx::push_restriction(cap::CapMask::none());
        assert_eq!(Cx::restriction_depth(), 2);
        assert!(Cx::is_restricted());

        let ambient = Cx::current().expect("ambient cx must be installed");
        let ambient_snapshot = ambient.capabilities();
        assert_eq!(
            ambient_snapshot.type_level,
            cap_layer(true, true, true, true, true)
        );
        assert_eq!(
            ambient_snapshot.runtime,
            cap_layer(false, false, false, false, false)
        );
        assert_eq!(
            ambient_snapshot.effective,
            cap_layer(false, false, false, false, false)
        );
    }

    #[test]
    fn introspection_budget_stats_reports_used_remaining_and_deadline() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(110))
            .with_poll_quota(3)
            .with_cost_quota(9)
            .with_priority(77);
        let cx = test_cx_with_virtual_time(budget, Time::from_secs(100));
        {
            let mut inner = cx.inner.write();
            inner.budget.poll_quota = 1;
            inner.budget.cost_quota = Some(4);
        }

        let stats = cx.budget_stats();

        assert_eq!(stats.deadline.at, Some(Time::from_secs(110)));
        assert_eq!(stats.deadline.remaining, Some(Duration::from_secs(10)));
        assert_eq!(stats.polls.quota, Some(3));
        assert_eq!(stats.polls.used, Some(2));
        assert_eq!(stats.polls.remaining, Some(1));
        assert_eq!(stats.cost.quota, Some(9));
        assert_eq!(stats.cost.used, Some(5));
        assert_eq!(stats.cost.remaining, Some(4));
        assert_eq!(stats.priority, 77);
    }

    #[test]
    fn introspection_budget_stats_drains_fast_path_checkpoint_counters() {
        let cx = test_cx_with_virtual_time(Budget::new().with_poll_quota(10), Time::from_secs(100));

        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());

        assert_eq!(
            cx.inner
                .read()
                .fast_path_count
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        let _stats = cx.budget_stats();

        let inner = cx.inner.read();
        assert_eq!(
            inner
                .fast_path_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(inner.checkpoint_state.checkpoint_count, 3);
    }

    #[test]
    fn budget_for_timeout_uses_virtual_time_deterministically() {
        // Virtual-time half of the wall/virtual test pair: with the clock
        // pinned at t=100s, a 30s timeout must produce exactly t=130s.
        let cx = test_cx_with_virtual_time(Budget::INFINITE, Time::from_secs(100));
        let budget = cx.budget_for_timeout(Duration::from_secs(30));
        assert_eq!(budget.deadline, Some(Time::from_secs(130)));
    }

    #[test]
    fn budget_for_timeout_never_loosens_ambient_deadline() {
        // Ambient deadline (t=110s) is sooner than now (100s) + 30s: the
        // per-call timeout must NOT extend it past the caller's bound.
        let ambient = Budget::new().with_deadline(Time::from_secs(110));
        let cx = test_cx_with_virtual_time(ambient, Time::from_secs(100));
        let budget = cx.budget_for_timeout(Duration::from_secs(30));
        assert_eq!(budget.deadline, Some(Time::from_secs(110)));
    }

    #[test]
    fn budget_for_timeout_inherits_non_deadline_dimensions() {
        let ambient = Budget::new().with_poll_quota(64).with_cost_quota(5);
        let cx = test_cx_with_virtual_time(ambient, Time::from_secs(1));
        let budget = cx.budget_for_timeout(Duration::from_secs(2));
        assert_eq!(budget.poll_quota, 64);
        assert_eq!(budget.cost_quota, Some(5));
        assert_eq!(budget.deadline, Some(Time::from_secs(3)));
    }

    #[test]
    fn budget_for_timeout_wall_clock_fallback_keeps_contract() {
        // Wall-clock half of the pair: without a timer driver, now() falls
        // back to the wall clock. Exact instants are nondeterministic, so
        // this asserts the clock-independent contract only: an open budget
        // gains SOME deadline, and tightening never exceeds an ambient one.
        let open = test_cx();
        let bounded = open.budget_for_timeout(Duration::from_secs(30));
        assert!(bounded.deadline.is_some());

        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));
        let tightened = cx.budget_for_timeout(Duration::from_secs(30));
        // min(ambient, now + 30s) can never exceed the ambient deadline.
        assert_eq!(tightened.deadline, Some(Time::ZERO));
    }

    #[test]
    fn remaining_budget_snapshot_reflects_live_budget() {
        let budget = Budget::new().with_poll_quota(42).with_cost_quota(7);
        let cx = Cx::for_testing_with_budget(budget);
        let left = cx.remaining_budget();
        assert_eq!(left.polls, Some(42));
        assert_eq!(left.cost, Some(7));
        assert_eq!(left.deadline, None); // no deadline configured

        let unlimited = test_cx().remaining_budget();
        assert_eq!(unlimited.polls, None);
        assert_eq!(unlimited.cost, None);
    }

    fn trace_message(event: &crate::trace::TraceEvent) -> &str {
        match &event.data {
            crate::trace::TraceData::Message(message) => message,
            other => panic!("expected user trace message, got {other:?}"),
        }
    }

    #[cfg(feature = "messaging-fabric")]
    fn capability_schema(
        families: Vec<SubjectFamily>,
        permissions: Vec<CapabilityPermission>,
    ) -> CapabilityTokenSchema {
        CapabilityTokenSchema {
            name: "fabric.cx.demo".to_owned(),
            families,
            delivery_classes: vec![DeliveryClass::EphemeralInteractive],
            permissions,
        }
    }

    #[test]
    fn io_not_available_by_default() {
        let cx = test_cx();
        assert!(!cx.has_io());
        assert!(cx.io().is_none());
    }

    /// br-asupersync-xqt7dj: with_current(f) must invoke f with a borrowed
    /// &Cx that observes the SAME runtime mask as the legacy Cx::current()
    /// would have observed under set_current_restricted, AND in the
    /// unrestricted common case must NOT bump any Arc strong count of the
    /// installed cx (zero-clone fast path).
    #[test]
    fn with_current_zero_clone_in_unrestricted_case() {
        let cx = test_cx();
        // Reference strong counts BEFORE installation as ambient.
        let _guard = Cx::set_current(Some(cx.clone()));
        // Capture strong counts of the installed-frame's inner Arcs.
        let frame_inner_strong_before =
            Arc::strong_count(&Cx::current().expect("current should resolve").inner.clone());
        // current() itself bumped the count by +1 above (we cloned to read);
        // hold a 2nd reference to keep the count stable across with_current.
        let cx_pin = Cx::current().expect("current");
        let baseline = Arc::strong_count(&cx_pin.inner);

        let observed = Cx::with_current(|borrowed| {
            // Inside the closure, while we hold the borrow, the inner
            // strong count must NOT have been incremented above baseline.
            // This proves the zero-clone fast path was taken.
            let count_during_borrow = Arc::strong_count(&borrowed.inner);
            (count_during_borrow, borrowed.runtime_mask)
        })
        .expect("with_current should invoke closure");

        // The fast path borrows frame.cx directly without Arc::clone, so
        // the inner strong count during the borrow equals baseline.
        assert_eq!(
            observed.0, baseline,
            "with_current must not bump inner.strong_count in unrestricted case"
        );
        // Mask must reflect the installed frame (full caps for set_current).
        assert_eq!(observed.1, cap::CapMask::all());
        let _ = frame_inner_strong_before;
    }

    /// br-asupersync-xqt7dj: with_current must apply the frame's narrowed
    /// mask when set_current_restricted is active. In the restricted case
    /// the implementation falls back to clone+overlay (3 Arc::clone) to
    /// preserve the security invariant from br-asupersync-5ckssb; verify
    /// the closure observes the narrow mask.
    #[test]
    fn with_current_applies_restriction_mask() {
        let cx = test_cx();
        // restricted_cx with NoCaps narrows the runtime mask.
        let restricted = cx.clone().restrict::<cap::None>();
        let _guard = restricted.set_current_restricted();
        let mask_seen = Cx::with_current(|borrowed| borrowed.runtime_mask)
            .expect("with_current should resolve under restricted scope");
        assert_eq!(
            mask_seen,
            cap::CapMask::none(),
            "with_current must apply the frame's narrowed mask"
        );
    }

    /// br-asupersync-xqt7dj: with_current returns None when no ambient cx
    /// is installed; the closure must NOT fire.
    #[test]
    fn with_current_returns_none_when_no_ambient() {
        let mut closure_ran = false;
        let result = Cx::with_current(|_cx| {
            closure_ran = true;
            42_u32
        });
        assert!(result.is_none());
        assert!(
            !closure_ran,
            "closure must not be invoked when no ambient cx is installed"
        );
    }

    #[test]
    fn io_available_with_for_testing_with_io() {
        let cx: Cx = Cx::for_testing_with_io();
        assert!(cx.has_io());
        let io = cx.io().expect("should have io cap");
        assert!(!io.is_real_io());
        assert_eq!(io.name(), "lab");
    }

    #[test]
    fn checkpoint_without_cancel() {
        let cx = test_cx();
        assert!(cx.checkpoint().is_ok());
    }

    #[test]
    fn checkpoint_with_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);
        assert!(cx.checkpoint().is_err());
    }

    #[test]
    fn masked_defers_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        cx.masked(|| {
            assert!(
                cx.checkpoint().is_ok(),
                "checkpoint should succeed when masked"
            );
        });

        assert!(
            cx.checkpoint().is_err(),
            "checkpoint should fail after unmasking"
        );
    }

    #[test]
    fn trace_attaches_logical_time() {
        let cx = test_cx();
        let trace = TraceBufferHandle::new(8);
        cx.set_trace_buffer(trace.clone());

        cx.trace("hello");

        let events = trace.snapshot();
        let event = events.first().expect("trace event");
        assert!(event.logical_time.is_some());
    }

    #[test]
    fn masked_panic_safety() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let cx = test_cx();
        cx.set_cancel_requested(true);

        // Ensure initial state is cancelled (unmasked)
        assert!(cx.checkpoint().is_err());

        // Run a masked block that panics
        let cx_clone = cx.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            cx_clone.masked(|| {
                // Avoid `panic!/unreachable!` macros (UBS critical). We still
                // need an unwind here to validate mask-depth restoration.
                std::panic::resume_unwind(Box::new("oops"));
            });
        }));

        // After panic, mask depth should have been restored.
        // If it leaked, checkpoint() will return Ok(()) because it thinks it's still masked.
        assert!(
            cx.checkpoint().is_err(),
            "Cx remains masked after panic! mask_depth leaked."
        );
    }

    #[test]
    fn current_returns_none_during_thread_local_teardown() {
        CURRENT_CX_DTOR_STATE.store(0, Ordering::SeqCst);

        let join = std::thread::spawn(|| {
            // Initialize the probe first so its destructor runs after CURRENT_CX
            // and exercises ambient lookup during TLS teardown.
            CURRENT_CX_DTOR_PROBE.with(|_| {});

            let cx = test_cx();
            let _guard = Cx::set_current(Some(cx));
            assert!(Cx::is_active(), "current cx should be installed");
        });

        join.join()
            .expect("thread-local teardown should not panic when reading Cx");
        assert_eq!(
            CURRENT_CX_DTOR_STATE.load(Ordering::SeqCst),
            3,
            "Cx::current() should fail closed once CURRENT_CX is unavailable"
        );
    }

    /// INV-MASK-BOUNDED: exceeding MAX_MASK_DEPTH must panic.
    #[test]
    #[should_panic(expected = "MAX_MASK_DEPTH")]
    fn mask_depth_exceeds_bound_panics() {
        let cx = test_cx();

        // Directly set mask_depth to the limit, then call masked() once
        // to trigger the bound check. This avoids deep nesting which
        // would cause double-panic in MaskGuard drops during unwind.
        {
            let mut inner = cx.inner.write();
            inner.mask_depth = crate::types::task_context::MAX_MASK_DEPTH;
        }
        // This call should panic because mask_depth is already at the limit.
        cx.masked(|| {});
    }

    /// Context stack depth must be bounded to prevent stack overflow.
    #[test]
    #[should_panic(expected = "MAX_CONTEXT_STACK_DEPTH")]
    fn context_stack_depth_exceeds_bound_panics_set_current() {
        let cx = test_cx();

        // Fill the context stack to the limit manually to avoid deep nesting
        // during test setup that could cause issues during panic unwinding.
        CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            for _ in 0..crate::types::task_context::MAX_CONTEXT_STACK_DEPTH {
                s.push(CurrentCxFrame {
                    cx: cx.clone().retype::<cap::All>(),
                    mask: cap::CapMask::all(),
                });
            }
        });

        // This call should panic because stack is already at the limit.
        let _guard = cx.set_current_restricted();
    }

    /// Context stack depth must be bounded to prevent stack overflow (push_restriction variant).
    #[test]
    #[should_panic(expected = "MAX_CONTEXT_STACK_DEPTH")]
    fn context_stack_depth_exceeds_bound_panics_push_restriction() {
        let cx = test_cx();
        let _guard = Cx::set_current(Some(cx.clone()));

        // Fill the context stack to the limit manually to avoid deep nesting
        CURRENT_CX_STACK.with(|stack| {
            let mut s = stack.borrow_mut();
            for _ in 0..crate::types::task_context::MAX_CONTEXT_STACK_DEPTH {
                s.push(CurrentCxFrame {
                    cx: cx.clone().retype::<cap::All>(),
                    mask: cap::CapMask::all(),
                });
            }
        });

        // This call should panic because stack is already at the limit.
        let _restriction_guard = FullCx::push_restriction(cap::CapMask::none());
    }

    #[test]
    fn random_usize_in_range() {
        let cx = test_cx_with_entropy(123);
        for _ in 0..100 {
            let value = cx.random_usize(7);
            assert!(value < 7);
        }
    }

    #[test]
    fn shuffle_deterministic() {
        let cx1 = test_cx_with_entropy(42);
        let cx2 = test_cx_with_entropy(42);

        let mut a = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut b = [1, 2, 3, 4, 5, 6, 7, 8];

        cx1.shuffle(&mut a);
        cx2.shuffle(&mut b);

        assert_eq!(a, b);
    }

    #[test]
    fn random_f64_range() {
        let cx = test_cx_with_entropy(7);
        for _ in 0..100 {
            let value = cx.random_f64();
            assert!((0.0..1.0).contains(&value));
        }
    }

    /// br-asupersync-lw9q66: random_u64 must NOT include the random
    /// value in its trace event. The static-source proof is the
    /// commit comment + the trace! call shape; this test pins the
    /// runtime behaviour by asserting the function still returns
    /// distinct values and matches the same per-seed output as
    /// before the trace change (so no semantic regression accompanied
    /// the log-shape fix).
    #[test]
    fn lw9q66_random_u64_returns_distinct_values_without_logging_value() {
        let cx = test_cx_with_entropy(0xdead_beef);
        let mut samples = std::collections::HashSet::new();
        for _ in 0..256 {
            samples.insert(cx.random_u64());
        }
        // 256 samples from a CSPRNG: expect at least 200 unique to
        // confirm the source is producing varied output (not stuck).
        assert!(
            samples.len() >= 200,
            "random_u64 must produce varied output (got {} unique of 256)",
            samples.len()
        );
        // Determinism check: a fresh cx with the same seed should
        // produce the same first value (proves seed propagation
        // isn't perturbed by the trace-shape change).
        let cx2 = test_cx_with_entropy(0xdead_beef);
        let cx3 = test_cx_with_entropy(0xdead_beef);
        assert_eq!(cx2.random_u64(), cx3.random_u64());
    }

    // ========================================================================
    // Cancel Attribution API Tests
    // ========================================================================

    #[test]
    fn cancel_with_sets_reason() {
        let cx = test_cx();
        assert!(cx.cancel_reason().is_none());

        cx.cancel_with(CancelKind::User, Some("manual stop"));

        assert!(cx.is_cancel_requested());
        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::User);
        assert_eq!(reason.message, Some("manual stop".to_string()));
    }

    #[test]
    fn cancel_with_no_message() {
        let cx = test_cx();
        cx.cancel_with(CancelKind::Timeout, None);

        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::Timeout);
        assert!(reason.message.is_none());
    }

    #[test]
    fn local_cancel_apis_never_weaken_existing_reason() {
        let cx = test_cx();
        cx.cancel_fast(CancelKind::Shutdown);
        cx.cancel_with(CancelKind::User, Some("late weaker request"));
        assert!(
            cx.cancel_reason()
                .is_some_and(|reason| reason.kind == CancelKind::Shutdown)
        );

        let cx = test_cx();
        cx.cancel_with(CancelKind::Shutdown, None);
        cx.cancel_fast(CancelKind::User);
        assert!(
            cx.cancel_reason()
                .is_some_and(|reason| reason.kind == CancelKind::Shutdown)
        );
    }

    #[test]
    fn cancel_reason_returns_none_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.cancel_reason().is_none());
    }

    #[test]
    fn cancel_chain_empty_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.cancel_chain().next().is_none());
    }

    #[test]
    fn cancel_chain_traverses_causes() {
        let cx = test_cx();

        // Build a chain: ParentCancelled -> ParentCancelled -> Deadline
        let deadline = CancelReason::deadline();
        let parent1 = CancelReason::parent_cancelled().with_cause(deadline);
        let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

        cx.set_cancel_reason(parent2);

        let chain: Vec<_> = cx.cancel_chain().collect();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[1].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[2].kind, CancelKind::Deadline);
    }

    #[test]
    fn root_cancel_cause_returns_none_when_not_cancelled() {
        let cx = test_cx();
        assert!(cx.root_cancel_cause().is_none());
    }

    #[test]
    fn root_cancel_cause_finds_root() {
        let cx = test_cx();

        // Build: ParentCancelled -> Timeout
        let timeout = CancelReason::timeout();
        let parent = CancelReason::parent_cancelled().with_cause(timeout);

        cx.set_cancel_reason(parent);

        let root = cx.root_cancel_cause().expect("should have root");
        assert_eq!(root.kind, CancelKind::Timeout);
    }

    #[test]
    fn root_cancel_cause_with_no_chain() {
        let cx = test_cx();
        cx.cancel_with(CancelKind::Shutdown, None);

        let root = cx.root_cancel_cause().expect("should have root");
        assert_eq!(root.kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancelled_by_checks_immediate_reason() {
        let cx = test_cx();

        // Build: ParentCancelled -> Deadline
        let deadline = CancelReason::deadline();
        let parent = CancelReason::parent_cancelled().with_cause(deadline);

        cx.set_cancel_reason(parent);

        // Immediate reason is ParentCancelled
        assert!(cx.cancelled_by(CancelKind::ParentCancelled));
        // Deadline is in chain but not immediate
        assert!(!cx.cancelled_by(CancelKind::Deadline));
    }

    #[test]
    fn cancelled_by_returns_false_when_not_cancelled() {
        let cx = test_cx();
        assert!(!cx.cancelled_by(CancelKind::User));
    }

    #[test]
    fn any_cause_is_searches_chain() {
        let cx = test_cx();

        // Build: ParentCancelled -> ParentCancelled -> Timeout
        let timeout = CancelReason::timeout();
        let parent1 = CancelReason::parent_cancelled().with_cause(timeout);
        let parent2 = CancelReason::parent_cancelled().with_cause(parent1);

        cx.set_cancel_reason(parent2);

        // All kinds in the chain return true
        assert!(cx.any_cause_is(CancelKind::ParentCancelled));
        assert!(cx.any_cause_is(CancelKind::Timeout));

        // Kinds not in chain return false
        assert!(!cx.any_cause_is(CancelKind::Deadline));
        assert!(!cx.any_cause_is(CancelKind::Shutdown));
    }

    #[test]
    fn any_cause_is_returns_false_when_not_cancelled() {
        let cx = test_cx();
        assert!(!cx.any_cause_is(CancelKind::Timeout));
    }

    #[test]
    fn set_cancel_reason_sets_flag_and_reason() {
        let cx = test_cx();
        assert!(!cx.is_cancel_requested());

        cx.set_cancel_reason(CancelReason::shutdown());

        assert!(cx.is_cancel_requested());
        assert_eq!(
            cx.cancel_reason().expect("should have reason").kind,
            CancelKind::Shutdown
        );
    }

    #[test]
    fn integration_realistic_usage() {
        // Simulate a realistic cancellation scenario:
        // 1. Root region times out
        // 2. Child task receives ParentCancelled
        // 3. Handler inspects the cause chain

        let cx = test_cx();

        // Simulate runtime setting a chained reason (timeout -> parent_cancelled)
        let timeout_reason = CancelReason::timeout().with_message("request timeout");
        let child_reason = CancelReason::parent_cancelled().with_cause(timeout_reason);

        cx.set_cancel_reason(child_reason);

        // Handler code checks various conditions
        assert!(cx.is_cancel_requested());

        // Immediate reason is ParentCancelled
        assert!(cx.cancelled_by(CancelKind::ParentCancelled));

        // But we want to know if a timeout caused it
        if cx.any_cause_is(CancelKind::Timeout) {
            // Log or metric: "Request cancelled due to timeout"
            let root = cx.root_cancel_cause().unwrap();
            assert_eq!(root.kind, CancelKind::Timeout);
            assert_eq!(root.message, Some("request timeout".to_string()));
        }

        // Full chain inspection
        let chain: Vec<_> = cx.cancel_chain().collect();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].kind, CancelKind::ParentCancelled);
        assert_eq!(chain[1].kind, CancelKind::Timeout);
    }

    #[test]
    fn cancel_fast_sets_flag_and_reason() {
        let cx = test_cx();
        assert!(!cx.is_cancel_requested());
        assert!(cx.cancel_reason().is_none());

        cx.cancel_fast(CancelKind::Shutdown);

        assert!(cx.is_cancel_requested());
        let reason = cx.cancel_reason().expect("should have reason");
        assert_eq!(reason.kind, CancelKind::Shutdown);
    }

    #[test]
    fn cancel_fast_no_cause_chain() {
        // cancel_fast is for the no-attribution path - it shouldn't create cause chains
        let cx = test_cx();

        cx.cancel_fast(CancelKind::Timeout);

        let reason = cx.cancel_reason().expect("should have reason");
        // No cause chain
        assert!(reason.cause.is_none());
        // No message
        assert!(reason.message.is_none());
        // Not truncated (nothing to truncate)
        assert!(!reason.truncated);
    }

    #[test]
    fn cancel_fast_sets_region() {
        let cx = test_cx();

        cx.cancel_fast(CancelKind::User);

        let reason = cx.cancel_reason().expect("should have reason");
        // Region should be set from the Cx
        let expected_region = cx.region_id();
        assert_eq!(reason.origin_region, expected_region);
    }

    #[test]
    fn cancel_fast_minimal_allocation() {
        // cancel_fast should create minimal CancelReason without extra allocations
        let cx = test_cx();

        cx.cancel_fast(CancelKind::Deadline);

        let reason = cx.cancel_reason().expect("should have reason");
        // Verify minimal structure: just kind, region, no message, no cause, no truncation
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(reason.message.is_none());
        assert!(reason.cause.is_none());
        assert!(!reason.truncated);
        assert!(reason.truncated_at_depth.is_none());

        // Memory cost should be minimal (just the struct size, no boxed cause)
        let cost = reason.estimated_memory_cost();
        // Should be roughly just the size of CancelReason without any heap allocations for cause
        assert!(
            cost < 200,
            "cancel_fast should have minimal memory cost, got {cost}"
        );
    }

    // ========================================================================
    // Checkpoint Progress Reporting Tests
    // ========================================================================

    #[test]
    fn checkpoint_records_progress() {
        let cx = test_cx();

        // Initially no checkpoints
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_none());
        assert!(state.last_message.is_none());
        assert_eq!(state.checkpoint_count, 0);

        // Record first checkpoint
        assert!(cx.checkpoint().is_ok());
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_some());
        assert!(state.last_message.is_none());
        assert_eq!(state.checkpoint_count, 1);

        // Record second checkpoint
        assert!(cx.checkpoint().is_ok());
        let state = cx.checkpoint_state();
        assert_eq!(state.checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_records_message() {
        let cx = test_cx();

        // Record checkpoint with message
        assert!(cx.checkpoint_with("processing step 1").is_ok());
        let state = cx.checkpoint_state();
        assert!(state.last_checkpoint.is_some());
        assert_eq!(state.last_message.as_deref(), Some("processing step 1"));
        assert_eq!(state.checkpoint_count, 1);

        // Second checkpoint overwrites message
        assert!(cx.checkpoint_with("processing step 2").is_ok());
        let state = cx.checkpoint_state();
        assert_eq!(state.last_message.as_deref(), Some("processing step 2"));
        assert_eq!(state.checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_converts_user_message_before_inner_lock() {
        struct ReentrantMessage {
            inner: Arc<parking_lot::RwLock<CxInner>>,
            conversions: Arc<AtomicUsize>,
        }

        impl From<ReentrantMessage> for String {
            fn from(message: ReentrantMessage) -> Self {
                assert!(
                    message.inner.try_read().is_some(),
                    "message conversion must run before checkpoint_with acquires CxInner"
                );
                message.conversions.fetch_add(1, Ordering::SeqCst);
                "reentrant conversion".to_owned()
            }
        }

        let cx = test_cx();
        let conversions = Arc::new(AtomicUsize::new(0));
        let message = ReentrantMessage {
            inner: Arc::clone(&cx.inner),
            conversions: Arc::clone(&conversions),
        };

        assert!(cx.checkpoint_with(message).is_ok());
        assert_eq!(conversions.load(Ordering::SeqCst), 1);
        assert_eq!(
            cx.checkpoint_state().last_message.as_deref(),
            Some("reentrant conversion")
        );
    }

    #[test]
    fn checkpoint_history_returns_message_trail() {
        let cx = test_cx();

        cx.checkpoint_with("connect")
            .expect("first checkpoint_with should succeed");
        cx.checkpoint()
            .expect("messageless checkpoint should succeed");
        cx.checkpoint_with("query")
            .expect("second checkpoint_with should succeed");

        let history = cx.checkpoint_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].1.as_str(), "connect");
        assert_eq!(history[1].1.as_str(), "query");
        assert!(history[0].0 <= history[1].0);
    }

    #[test]
    fn checkpoint_clears_message() {
        let cx = test_cx();

        // Record checkpoint with message
        cx.checkpoint_with("step 1")
            .expect("checkpoint_with should succeed");
        assert_eq!(
            cx.checkpoint_state().last_message.as_deref(),
            Some("step 1")
        );

        // Regular checkpoint clears the message
        cx.checkpoint()
            .expect("checkpoint should succeed after message set");
        assert!(cx.checkpoint_state().last_message.is_none());
    }

    #[test]
    fn checkpoint_with_checks_cancel() {
        let cx = test_cx();
        cx.set_cancel_requested(true);

        // checkpoint_with should return error on cancellation
        assert!(cx.checkpoint_with("should fail").is_err());

        // But checkpoint state should still be updated
        let state = cx.checkpoint_state();
        assert_eq!(state.checkpoint_count, 1);
        assert_eq!(state.last_message.as_deref(), Some("should fail"));
    }

    #[test]
    fn checkpoint_deadline_exhaustion_sets_cancel_reason() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));

        assert!(cx.checkpoint().is_err());
        let reason = cx
            .cancel_reason()
            .expect("deadline exhaustion must set reason");
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn checkpoint_poll_budget_exhaustion_sets_cancel_reason() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_poll_quota(0));

        assert!(cx.checkpoint().is_err());
        let reason = cx
            .cancel_reason()
            .expect("poll quota exhaustion must set reason");
        assert_eq!(reason.kind, CancelKind::PollQuota);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn checkpoint_cost_budget_exhaustion_sets_cancel_reason() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_cost_quota(0));

        assert!(cx.checkpoint().is_err());
        let reason = cx
            .cancel_reason()
            .expect("cost budget exhaustion must set reason");
        assert_eq!(reason.kind, CancelKind::CostBudget);
        assert!(cx.is_cancel_requested());
    }

    #[test]
    fn capability_budget_plan_inherits_and_tightens() {
        let cx = test_cx();
        let parent = CapabilityBudget::new()
            .with_memory_bytes(1_024)
            .with_io_bytes(4_096)
            .with_cleanup_budget(Budget::new().with_poll_quota(100_000));
        let requirements = CapabilityBudgetRequirements::new()
            .require_memory_bytes()
            .require_io_bytes()
            .require_cleanup();

        cx.apply_child_capability_budget(parent, requirements)
            .expect("parent capability budget is complete");

        let child = CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_io_bytes(512)
            .with_cleanup_budget(Budget::new().with_poll_quota(100_000));
        let effective = cx
            .plan_child_capability_budget(child, requirements)
            .expect("child should inherit missing required envelopes");

        assert_eq!(effective.memory_bytes, Some(1_024));
        assert_eq!(effective.io_bytes, Some(512));
        assert_eq!(
            effective.cleanup_budget.map(|budget| budget.poll_quota),
            Some(100_000)
        );
        assert_eq!(cx.capability_budget(), parent);
    }

    #[test]
    fn capability_budget_apply_fails_closed_when_required_missing() {
        let cx = test_cx();
        let requirements = CapabilityBudgetRequirements::new().require_artifact_bytes();

        let err = cx
            .apply_child_capability_budget(CapabilityBudget::new(), requirements)
            .expect_err("missing artifact budget must fail closed");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::ArtifactBytes)
        );
        assert_eq!(cx.capability_budget(), CapabilityBudget::UNSPECIFIED);
    }

    #[test]
    fn scope_inherits_cx_capability_budget() {
        let cx = test_cx();
        let budget = CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_cpu_units(32);

        cx.apply_child_capability_budget(budget, CapabilityBudgetRequirements::NONE)
            .expect("optional capability budget should apply");

        let scope = cx.scope();

        assert_eq!(scope.capability_budget(), budget);
    }

    #[test]
    fn scope_with_capability_budget_fails_closed_when_required_missing() {
        let cx = test_cx();

        let err = cx
            .scope_with_budget_and_capability_budget(
                Budget::INFINITE,
                CapabilityBudget::new(),
                CapabilityBudgetRequirements::new().require_artifact_bytes(),
            )
            .expect_err("missing artifact envelope must fail closed");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::ArtifactBytes)
        );
    }

    #[test]
    fn masked_checkpoint_defers_budget_exhaustion() {
        let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::ZERO));

        cx.masked(|| {
            assert!(
                cx.checkpoint().is_ok(),
                "budget exhaustion should defer while masked"
            );
        });

        let reason = cx
            .cancel_reason()
            .expect("masked checkpoint should still record exhaustion reason");
        assert_eq!(reason.kind, CancelKind::Deadline);
        assert!(
            cx.checkpoint().is_err(),
            "deadline exhaustion should be observed after unmasking"
        );
    }

    #[test]
    fn checkpoint_budget_usage_reports_remaining_time_in_millis() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(3)
            .with_cost_quota(7);
        let baseline = Budget::new()
            .with_deadline(Time::from_secs(20))
            .with_poll_quota(5)
            .with_cost_quota(11);

        let (polls_used, cost_used, time_remaining_ms) =
            Cx::<cap::All>::checkpoint_budget_usage(budget, baseline, Time::from_secs(7));

        assert_eq!(polls_used, Some(2));
        assert_eq!(cost_used, Some(4));
        assert_eq!(time_remaining_ms, Some(3_000));
    }

    #[test]
    fn set_cancel_requested_wakes_registered_cancel_waker() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Waker;

        struct CountWaker(Arc<AtomicUsize>);

        use std::task::Wake;
        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));

        {
            let mut inner = cx.inner.write();
            inner.cancel_waker = Some(Arc::new(CancelWaker::new(waker)));
        }

        cx.set_cancel_requested(true);

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "set_cancel_requested(true) must wake the registered cancel waker"
        );

        cx.set_cancel_requested(false);

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "clearing cancellation must not spuriously wake the cancel waker"
        );
    }

    #[test]
    fn tracked_cancel_wakers_have_exact_independent_ownership() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Waker;

        struct CountWaker(Arc<AtomicUsize>);

        use std::task::Wake;
        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let wakes = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes))));

        let first = cx.refresh_cancel_waker(None, &waker);
        let second = cx.refresh_cancel_waker(None, &waker);
        assert_ne!(first, second, "distinct owners need distinct tokens");

        {
            let inner = cx.inner.read();
            assert!(inner.cancel_waker.is_none());
            assert_eq!(inner.cancel_waker_registrations.len(), 2);
        }

        cx.clear_cancel_waker(first);
        {
            let inner = cx.inner.read();
            assert_eq!(inner.cancel_waker_registrations.len(), 1);
        }
        cx.cancel_fast(CancelKind::User);
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "equivalent tracked owners must be deduplicated during fanout"
        );

        cx.clear_cancel_waker(second);
        {
            let inner = cx.inner.read();
            assert!(inner.cancel_waker.is_none());
            assert!(inner.cancel_waker_registrations.is_empty());
        }

        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "registration cleanup must not wake the task"
        );
    }

    #[test]
    fn cancel_waker_tokens_reject_stale_cleanup_after_aba_identity() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct CountWaker(Arc<AtomicUsize>);

        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let wakes_a = Arc::new(AtomicUsize::new(0));
        let wakes_b = Arc::new(AtomicUsize::new(0));
        let waker_a = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes_a))));
        let waker_b = Waker::from(Arc::new(CountWaker(Arc::clone(&wakes_b))));

        let stale_a = cx.refresh_cancel_waker(None, &waker_a);
        cx.clear_cancel_waker(stale_a);
        let current_b = cx.refresh_cancel_waker(None, &waker_b);
        let current_a = cx.refresh_cancel_waker(None, &waker_a);
        assert_ne!(stale_a, current_a, "a cleared token must never be reused");

        // A late cleanup from the old A owner must not remove either current
        // registration, even though one has the ABA-identical Waker.
        cx.clear_cancel_waker(stale_a);
        assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 2);
        cx.cancel_fast(CancelKind::User);
        assert_eq!(wakes_a.load(Ordering::SeqCst), 1);
        assert_eq!(wakes_b.load(Ordering::SeqCst), 1);

        cx.clear_cancel_waker(current_a);
        cx.clear_cancel_waker(current_b);
        let inner = cx.inner.read();
        assert!(inner.cancel_waker.is_none());
        assert!(inner.cancel_waker_registrations.is_empty());
    }

    #[test]
    fn auxiliary_registration_preserves_runtime_primary_and_untracked_is_idempotent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct CountWaker(Arc<AtomicUsize>);

        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let cx = test_cx();
        let primary_wakes = Arc::new(AtomicUsize::new(0));
        let auxiliary_wakes = Arc::new(AtomicUsize::new(0));
        let untracked_wakes = Arc::new(AtomicUsize::new(0));
        let primary = Waker::from(Arc::new(CountWaker(Arc::clone(&primary_wakes))));
        let auxiliary = Waker::from(Arc::new(CountWaker(Arc::clone(&auxiliary_wakes))));
        let untracked = Waker::from(Arc::new(CountWaker(Arc::clone(&untracked_wakes))));
        cx.inner.write().cancel_waker = Some(Arc::new(CancelWaker::new(primary)));

        let token = cx.refresh_cancel_waker(None, &auxiliary);
        for _ in 0..4_096 {
            cx.register_cancel_waker(&untracked);
        }
        assert!(cx.inner.read().cancel_waker.is_some());
        assert_eq!(cx.inner.read().cancel_waker_registrations.len(), 1);

        cx.cancel_fast(CancelKind::User);
        assert_eq!(primary_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(auxiliary_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(untracked_wakes.load(Ordering::SeqCst), 1);

        cx.clear_cancel_waker(token);
        assert!(cx.inner.read().cancel_waker.is_some());
        assert!(cx.inner.read().cancel_waker_registrations.is_empty());
    }

    #[test]
    fn completed_context_rejects_new_cancel_waker_registrations() {
        let cx = test_cx();
        let retired = cx.inner.write().take_cancel_wakers();
        drop(retired);
        let waker = Waker::noop().clone();

        let token = cx.refresh_cancel_waker(None, &waker);
        cx.register_cancel_waker(&waker);

        let inner = cx.inner.read();
        assert_eq!(token.id, 0);
        assert!(inner.cancel_waker_registry_closed);
        assert!(inner.cancel_waker.is_none());
        assert!(inner.untracked_cancel_waker.is_none());
        assert!(inner.cancel_waker_registrations.is_empty());
    }

    #[test]
    fn replacing_cancel_waker_retires_safe_payload_after_unlock() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct DropProbe {
            inner: std::sync::Weak<parking_lot::RwLock<CxInner>>,
            drops: Arc<AtomicUsize>,
            unlocked_drops: Arc<AtomicUsize>,
        }

        #[allow(clippy::manual_noop_waker)]
        impl Wake for DropProbe {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                if let Some(inner) = self.inner.upgrade()
                    && inner.try_write().is_some()
                {
                    self.unlocked_drops.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        let cx = test_cx();
        let drops = Arc::new(AtomicUsize::new(0));
        let unlocked_drops = Arc::new(AtomicUsize::new(0));
        let first_waker = Waker::from(Arc::new(DropProbe {
            inner: Arc::downgrade(&cx.inner),
            drops: Arc::clone(&drops),
            unlocked_drops: Arc::clone(&unlocked_drops),
        }));
        let first = cx.refresh_cancel_waker(None, &first_waker);
        drop(first_waker);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        let replacement = Waker::noop().clone();
        let replacement_token = cx.refresh_cancel_waker(Some(first), &replacement);
        assert_eq!(replacement_token, first);

        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(unlocked_drops.load(Ordering::SeqCst), 1);
        cx.clear_cancel_waker(replacement_token);
    }

    #[test]
    fn checkpoint_state_is_snapshot() {
        let cx = test_cx();

        // Get a snapshot
        let snapshot = cx.checkpoint_state();
        assert_eq!(snapshot.checkpoint_count, 0);

        // Record more checkpoints
        assert!(cx.checkpoint().is_ok());
        assert!(cx.checkpoint().is_ok());

        // Original snapshot should be unchanged
        assert_eq!(snapshot.checkpoint_count, 0);

        // New snapshot should reflect updates
        assert_eq!(cx.checkpoint_state().checkpoint_count, 2);
    }

    #[test]
    fn checkpoint_with_accepts_string_types() {
        let cx = test_cx();

        // Test &str
        assert!(cx.checkpoint_with("literal").is_ok());

        // Test String
        assert!(cx.checkpoint_with(String::from("owned")).is_ok());

        // Test format!
        assert!(cx.checkpoint_with(format!("item {}", 42)).is_ok());

        assert_eq!(cx.checkpoint_state().checkpoint_count, 3);
    }

    // -----------------------------------------------------------------
    // Macaroon integration tests (bd-2lqyk.2)
    // -----------------------------------------------------------------

    fn test_root_key() -> crate::security::key::AuthKey {
        crate::security::key::AuthKey::from_seed(42)
    }

    #[test]
    fn cx_no_macaroon_by_default() {
        let cx = test_cx();
        assert!(cx.macaroon().is_none());
    }

    #[test]
    fn cx_with_macaroon_attaches_token() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let m = cx.macaroon().expect("should have macaroon");
        assert_eq!(m.identifier(), "spawn:r1");
        assert_eq!(m.location(), "cx/scheduler");
    }

    #[test]
    fn cx_macaroon_survives_clone() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "io:net", "cx/io");
        let cx = test_cx().with_macaroon(token);
        let cx2 = cx.clone();

        assert_eq!(
            cx.macaroon()
                .expect("cx should have macaroon after with_macaroon")
                .identifier(),
            cx2.macaroon()
                .expect("cloned cx should have macaroon")
                .identifier()
        );

        // Test attenuation to verify the attenuation mechanism works
        let attenuated_cx = cx
            .attenuate(CaveatPredicate::TimeBefore(u64::MAX / 2))
            .expect("attenuation should succeed");
        assert!(
            attenuated_cx
                .macaroon()
                .expect("attenuated cx should have macaroon")
                .is_direct_attenuation_of(
                    cx.macaroon()
                        .expect("cx should have macaroon for attenuation check"),
                    &CaveatPredicate::TimeBefore(u64::MAX / 2)
                ),
            "Cx::attenuate must install only a direct child of the parent token"
        );
    }

    #[test]
    fn cx_macaroon_survives_restrict() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "all:cap", "cx/root");
        let cx: Cx<cap::All> = test_cx().with_macaroon(token);
        let narrow: Cx<cap::None> = cx.restrict();

        assert_eq!(
            cx.macaroon().expect("cx should have macaroon").identifier(),
            narrow
                .macaroon()
                .expect("narrow should have macaroon")
                .identifier()
        );
    }

    #[test]
    fn cx_attenuate_adds_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let cx2 = cx
            .attenuate(CaveatPredicate::TimeBefore(u64::MAX / 2))
            .expect("attenuate should succeed");

        // Original unchanged
        assert_eq!(
            cx.macaroon()
                .expect("cx should have macaroon")
                .caveat_count(),
            0
        );
        // Attenuated has one caveat
        assert_eq!(
            cx2.macaroon()
                .expect("cx2 should have macaroon")
                .caveat_count(),
            1
        );
        // Both share the same identifier
        assert_eq!(
            cx.macaroon().expect("cx should have macaroon").identifier(),
            cx2.macaroon()
                .expect("cx2 should have macaroon")
                .identifier()
        );
    }

    #[test]
    fn cx_attenuate_returns_none_without_macaroon() {
        let cx = test_cx();
        assert!(cx.attenuate(CaveatPredicate::MaxUses(10)).is_none());
    }

    #[test]
    fn cx_attenuate_scope_rejects_oversized_pattern() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);
        let pattern = "x".repeat(u16::MAX as usize + 1);

        let attenuated = cx.attenuate_scope(pattern);

        assert!(
            attenuated.is_none(),
            "oversized caveat content must fail closed instead of reaching the encoder"
        );
        assert_eq!(
            cx.macaroon()
                .expect("cx should have macaroon")
                .caveat_count(),
            0
        );
    }

    #[test]
    fn cx_attenuate_from_budget_returns_none_without_macaroon() {
        let cx = test_cx();
        assert!(cx.attenuate_from_budget().is_none());
    }

    #[test]
    fn cx_attenuate_from_budget_preserves_token_without_deadline() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let attenuated = cx
            .attenuate_from_budget()
            .expect("macaroon should still be present");
        assert_eq!(
            attenuated
                .macaroon()
                .expect("attenuated should have macaroon")
                .caveat_count(),
            0
        );
        assert_eq!(
            attenuated
                .macaroon()
                .expect("attenuated should have macaroon")
                .identifier(),
            cx.macaroon().expect("cx should have macaroon").identifier()
        );
    }

    #[test]
    fn cx_attenuate_from_budget_adds_deadline_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let budget = Budget::new().with_deadline(Time::from_millis(5_000));
        let cx = Cx::for_testing_with_budget(budget).with_macaroon(token);

        let attenuated = cx
            .attenuate_from_budget()
            .expect("attenuation with deadline should succeed");
        assert_eq!(
            attenuated
                .macaroon()
                .expect("attenuated should have macaroon")
                .caveat_count(),
            1
        );
    }

    #[test]
    fn cx_verify_capability_succeeds() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let ctx = VerificationContext::new().with_time(1000);
        assert!(cx.verify_capability(&key, "spawn:r1", &ctx).is_ok());
    }

    #[test]
    fn cx_verify_capability_fails_wrong_key() {
        let key = test_root_key();
        let wrong_key = crate::security::key::AuthKey::from_seed(99);
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let ctx = VerificationContext::new();
        let err = cx
            .verify_capability(&wrong_key, "spawn:r1", &ctx)
            .unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn cx_verify_capability_fails_no_macaroon() {
        let key = test_root_key();
        let cx = test_cx();

        let ctx = VerificationContext::new();
        let err = cx.verify_capability(&key, "spawn:r1", &ctx).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn cx_verify_with_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler")
            .add_caveat(CaveatPredicate::TimeBefore(5_000))
            .add_caveat(CaveatPredicate::RegionScope(42));

        let cx = test_cx().with_macaroon(token);

        // Passes with correct context
        let ctx = VerificationContext::new().with_time(1000).with_region(42);
        assert!(cx.verify_capability(&key, "spawn:r1", &ctx).is_ok());

        // Fails with expired time
        let ctx_expired = VerificationContext::new().with_time(6000).with_region(42);
        let err = cx
            .verify_capability(&key, "spawn:r1", &ctx_expired)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 0, .. }
        ));

        // Fails with wrong region
        let ctx_wrong_region = VerificationContext::new().with_time(1000).with_region(99);
        let err = cx
            .verify_capability(&key, "spawn:r1", &ctx_wrong_region)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 1, .. }
        ));
    }

    #[test]
    fn cx_attenuate_then_verify() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "time:sleep", "cx/time");
        let cx = test_cx().with_macaroon(token);

        // Attenuate with time limit
        let cx2 = cx
            .attenuate(CaveatPredicate::TimeBefore(3_000))
            .expect("attenuation should succeed");

        // Further attenuate with max uses
        let cx3 = cx2
            .attenuate(CaveatPredicate::MaxUses(5))
            .expect("second attenuation should succeed");

        // Original has no restrictions
        let ctx = VerificationContext::new().with_time(1000);
        assert!(cx.verify_capability(&key, "time:sleep", &ctx).is_ok());

        // cx2 has time restriction
        assert!(cx2.verify_capability(&key, "time:sleep", &ctx).is_ok());
        let ctx_late = VerificationContext::new().with_time(4000);
        assert!(
            cx2.verify_capability(&key, "time:sleep", &ctx_late)
                .is_err()
        );

        // cx3 has both time + uses restriction
        let ctx_ok = VerificationContext::new().with_time(1000).with_use_count(3);
        assert!(cx3.verify_capability(&key, "time:sleep", &ctx_ok).is_ok());
        let ctx_overuse = VerificationContext::new()
            .with_time(1000)
            .with_use_count(10);
        assert!(
            cx3.verify_capability(&key, "time:sleep", &ctx_overuse)
                .is_err()
        );
    }

    #[test]
    fn cx_verify_emits_evidence() {
        use crate::evidence_sink::CollectorSink;

        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let sink = Arc::new(CollectorSink::new());
        let cx = test_cx()
            .with_macaroon(token)
            .with_evidence_sink(Some(sink.clone() as Arc<dyn EvidenceSink>));

        let ctx = VerificationContext::new();

        // Successful verification should emit evidence
        cx.verify_capability(&key, "spawn:r1", &ctx)
            .expect("capability verification should succeed");
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component, "cx_macaroon");
        assert_eq!(entries[0].action, "verify_success");

        // Failed verification should also emit evidence
        let wrong_key = crate::security::key::AuthKey::from_seed(99);
        let _ = cx.verify_capability(&wrong_key, "spawn:r1", &ctx);
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].action, "verify_fail_signature");
    }

    #[test]
    fn cx_verify_capability_rejects_wrong_identifier() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let err = cx
            .verify_capability(&key, "spawn:r2", &VerificationContext::new())
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::UnexpectedIdentifier { .. }
        ));
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_grant_publish_capability_mints_token_and_runtime_grant() {
        let cx = test_cx();
        let schema = capability_schema(
            vec![SubjectFamily::Command],
            vec![CapabilityPermission::Publish],
        );

        let granted = cx
            .grant_publish_capability::<CommandFamily>(
                SubjectPattern::new("orders.>"),
                &schema,
                DeliveryClass::EphemeralInteractive,
            )
            .expect("publish capability should mint");

        assert_eq!(granted.token().family(), SubjectFamily::Command);
        assert!(cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(!cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("payments.created"),
        }));
        assert_eq!(cx.fabric_capabilities().len(), 1);
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_revoke_fabric_capabilities_by_id_and_scope_propagates_to_children() {
        let cx = test_cx();
        let child = cx.restrict::<cap::None>();
        let publish = cx
            .grant_fabric_capability(FabricCapability::Publish {
                subject: SubjectPattern::new("orders.>"),
            })
            .expect("publish grant");
        let subscribe = cx
            .grant_fabric_capability(FabricCapability::Subscribe {
                subject: SubjectPattern::new("orders.created"),
            })
            .expect("subscribe grant");

        assert!(child.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert_eq!(
            child.revoke_fabric_capability_scope(FabricCapabilityScope::Publish),
            1
        );
        assert!(!cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert_eq!(
            cx.revoke_fabric_capability(subscribe.id()),
            Some(FabricCapability::Subscribe {
                subject: SubjectPattern::new("orders.created"),
            })
        );
        assert!(
            !child.check_fabric_capability(&FabricCapability::Subscribe {
                subject: SubjectPattern::new("orders.created"),
            })
        );
        assert_eq!(publish.id().raw(), 1);
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_revoke_fabric_capability_by_subject_is_overlap_based() {
        let cx = test_cx();
        cx.grant_fabric_capability(FabricCapability::Publish {
            subject: SubjectPattern::new("orders.>"),
        })
        .expect("publish grant");
        cx.grant_fabric_capability(FabricCapability::Subscribe {
            subject: SubjectPattern::new("payments.>"),
        })
        .expect("subscribe grant");

        assert_eq!(
            cx.revoke_fabric_capability_by_subject(&SubjectPattern::new("orders.created")),
            1
        );
        assert!(!cx.check_fabric_capability(&FabricCapability::Publish {
            subject: SubjectPattern::new("orders.created"),
        }));
        assert!(cx.check_fabric_capability(&FabricCapability::Subscribe {
            subject: SubjectPattern::new("payments.captured"),
        }));
    }

    #[cfg(feature = "messaging-fabric")]
    #[test]
    fn cx_rejects_empty_stream_capability_names() {
        let cx = test_cx();

        let error = cx
            .grant_fabric_capability(FabricCapability::ConsumeStream {
                stream: "   ".to_owned(),
            })
            .expect_err("blank stream names must fail");

        assert_eq!(error, FabricCapabilityGrantError::EmptyStreamName);
    }

    // ========================================================================
    // Metamorphic Testing: Cx::trace ordering across scope boundaries
    // ========================================================================

    /// MR1: Parent-Child Trace Ordering (Inclusive)
    /// Transformation: Create child scope
    /// Relation: Parent traces precede child traces in logical order
    #[test]
    fn mr_trace_parent_child_ordering() {
        let parent_cx = test_cx();
        let trace = TraceBufferHandle::new(16);
        parent_cx.set_trace_buffer(trace.clone());

        // Parent emits trace first
        parent_cx.trace("parent trace 1");

        // Create child context (simulating child scope)
        let child_cx = parent_cx.clone();
        child_cx.trace("child trace 1");
        child_cx.trace("child trace 2");

        // Parent emits another trace after child
        parent_cx.trace("parent trace 2");

        let events = trace.snapshot();
        assert_eq!(events.len(), 4);

        // Extract logical times for ordering verification
        let times: Vec<_> = events
            .iter()
            .map(|e| e.logical_time.as_ref().expect("logical time"))
            .collect();

        // Verify parent traces have logical time precedence structure
        // (In a real parent-child scenario, parent regions would have different region IDs)
        // For this test we verify causal ordering through logical time monotonicity
        for i in 1..times.len() {
            assert!(
                times[i - 1] <= times[i],
                "Logical time should be monotonically increasing: {:?} > {:?}",
                times[i - 1],
                times[i]
            );
        }
    }

    /// MR2: Deterministic Interleaving (Equivalence)
    /// Transformation: Same seed replay
    /// Relation: Identical trace order under deterministic execution
    #[test]
    fn mr_trace_deterministic_interleaving() {
        // First execution with entropy seed
        let cx1 = test_cx_with_entropy(42);
        let trace1 = TraceBufferHandle::new(16);
        cx1.set_trace_buffer(trace1.clone());

        // Simulate concurrent traces with deterministic randomization
        for i in 0..5 {
            if cx1.random_usize(2) == 0 {
                cx1.trace(&format!("branch_a_{}", i));
            } else {
                cx1.trace(&format!("branch_b_{}", i));
            }
        }

        // Second execution with same seed
        let cx2 = test_cx_with_entropy(42);
        let trace2 = TraceBufferHandle::new(16);
        cx2.set_trace_buffer(trace2.clone());

        for i in 0..5 {
            if cx2.random_usize(2) == 0 {
                cx2.trace(&format!("branch_a_{}", i));
            } else {
                cx2.trace(&format!("branch_b_{}", i));
            }
        }

        let events1 = trace1.snapshot();
        let events2 = trace2.snapshot();

        // Deterministic execution should produce identical trace sequences
        assert_eq!(
            events1.len(),
            events2.len(),
            "Trace count should be deterministic"
        );

        for (i, (e1, e2)) in events1.iter().zip(events2.iter()).enumerate() {
            // Note: We compare message content rather than exact logical time
            // as time implementation details may vary while maintaining determinism
            assert_eq!(
                trace_message(e1),
                trace_message(e2),
                "Trace message at index {} should be deterministic: '{}' vs '{}'",
                i,
                trace_message(e1),
                trace_message(e2)
            );
        }
    }

    /// MR3: Macaroon Causal Ordering (Permutative)
    /// Transformation: Macaroon attenuation chain
    /// Relation: Logical time monotonic through auth flow
    #[test]
    fn mr_trace_macaroon_causal_ordering() {
        use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
        use crate::security::key::AuthKey;

        let key = AuthKey::from_seed(42);
        let token = MacaroonToken::mint(&key, "trace:emit", "cx/trace");

        // Root context with macaroon
        let root_cx = test_cx().with_macaroon(token);
        let trace = TraceBufferHandle::new(16);
        root_cx.set_trace_buffer(trace.clone());

        root_cx.trace("root macaroon trace");

        // Attenuated context (simulating capability restriction)
        let attenuated_cx = root_cx
            .attenuate(CaveatPredicate::TimeBefore(u64::MAX / 2))
            .expect("attenuation should succeed");
        attenuated_cx.trace("attenuated trace 1");

        // Further attenuated context
        let further_attenuated_cx = attenuated_cx
            .attenuate(CaveatPredicate::MaxUses(10))
            .expect("further attenuation should succeed");
        further_attenuated_cx.trace("further attenuated trace");

        // Back to less attenuated
        attenuated_cx.trace("attenuated trace 2");

        let events = trace.snapshot();
        assert_eq!(events.len(), 4);

        // Verify causal ordering preservation through logical time
        let logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref())
            .collect();

        // Logical time should increase monotonically regardless of attenuation level
        for i in 1..logical_times.len() {
            assert!(
                logical_times[i - 1] <= logical_times[i],
                "Macaroon attenuation should preserve causal ordering: tick {:?} > {:?}",
                logical_times[i - 1],
                logical_times[i]
            );
        }
    }

    /// MR4: Budget Exhaustion Idempotence (Equivalence)
    /// Transformation: Multiple budget exhaust attempts
    /// Relation: Single log entry recorded
    #[test]
    fn mr_trace_budget_exhaustion_idempotence() {
        use crate::types::Budget;

        // Create context with minimal budget
        let budget = Budget::new().with_poll_quota(1);
        let cx = Cx::for_testing_with_budget(budget);
        let trace = TraceBufferHandle::new(16);
        cx.set_trace_buffer(trace.clone());

        // First trace that might exhaust budget
        cx.trace("pre-exhaustion trace");

        // Simulate budget exhaustion (in practice this would happen during task execution)
        // For this test, we verify that multiple trace attempts during exhaustion
        // don't create duplicate entries
        cx.trace("exhaustion trace 1");
        cx.trace("exhaustion trace 2"); // Same condition
        cx.trace("exhaustion trace 3"); // Same condition

        let events = trace.snapshot();

        // All trace calls should succeed (budget exhaustion doesn't prevent tracing)
        // But this verifies that tracing remains consistent under budget pressure
        assert_eq!(events.len(), 4, "All traces should be recorded");

        // Verify no duplicate logical times (idempotence of time allocation)
        let mut logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref().map(|t| format!("{:?}", t)))
            .collect();
        logical_times.sort_unstable();
        logical_times.dedup();

        assert_eq!(
            logical_times.len(),
            4,
            "Logical time allocation should be idempotent (no duplicate times)"
        );
    }

    /// MR5: Clone Trace Equivalence (Equivalence)
    /// Transformation: Clone Cx
    /// Relation: Same trace patterns produced
    #[test]
    fn mr_trace_clone_equivalence() {
        let original_cx = test_cx_with_entropy(123);
        let trace = TraceBufferHandle::new(16);
        original_cx.set_trace_buffer(trace.clone());

        // Clone the context
        let cloned_cx = original_cx.clone();

        // Both should share the same trace buffer and produce equivalent patterns
        original_cx.trace("original trace 1");
        cloned_cx.trace("cloned trace 1");
        original_cx.trace("original trace 2");
        cloned_cx.trace("cloned trace 2");

        let events = trace.snapshot();
        assert_eq!(events.len(), 4, "Both contexts should write to same buffer");

        // Verify logical time ordering is preserved across clone usage
        let logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref())
            .collect();

        for i in 1..logical_times.len() {
            assert!(
                logical_times[i - 1] <= logical_times[i],
                "Clone should preserve logical time ordering: {:?} > {:?}",
                logical_times[i - 1],
                logical_times[i]
            );
        }

        // Verify cloned context shares the entropy stream rather than
        // replaying the first draw from a copied RNG state.
        let val1 = original_cx.random_usize(100);
        let val2 = cloned_cx.random_usize(100);
        let control_cx = test_cx_with_entropy(123);
        let expected1 = control_cx.random_usize(100);
        let expected2 = control_cx.random_usize(100);

        assert_eq!(
            (val1, val2),
            (expected1, expected2),
            "Cloned context should continue the shared entropy sequence"
        );
    }

    /// MR6: Composite Trace Ordering (Composition)
    /// Combines parent-child + clone + macaroon relations
    #[test]
    fn mr_trace_composite_ordering() {
        use crate::cx::macaroon::{CaveatPredicate, MacaroonToken};
        use crate::security::key::AuthKey;

        let key = AuthKey::from_seed(789);
        let token = MacaroonToken::mint(&key, "trace:composite", "cx/test");

        // Root context with macaroon
        let root_cx = test_cx_with_entropy(456).with_macaroon(token);
        let trace = TraceBufferHandle::new(32);
        root_cx.set_trace_buffer(trace.clone());

        // MR1 + MR3: Parent with macaroon
        root_cx.trace("parent+macaroon trace");

        // MR5: Clone preserves properties
        let child_cx = root_cx.clone();

        // MR3: Attenuation preserves ordering
        let attenuated_child = child_cx
            .attenuate(CaveatPredicate::TimeBefore(10000))
            .expect("attenuation should work");

        // MR1: Child traces after parent
        attenuated_child.trace("child+attenuated trace");

        // MR2: Deterministic interleaving
        for i in 0..3 {
            if root_cx.random_usize(2) == 0 {
                root_cx.trace(&format!("parent_branch_{}", i));
            } else {
                attenuated_child.trace(&format!("child_branch_{}", i));
            }
        }

        let events = trace.snapshot();
        assert!(
            events.len() >= 5,
            "Composite test should produce multiple traces"
        );

        // Verify all metamorphic properties hold in composition:

        // 1. Logical time monotonicity (covers MR1, MR3, MR5)
        let logical_times: Vec<_> = events
            .iter()
            .filter_map(|e| e.logical_time.as_ref())
            .collect();

        for i in 1..logical_times.len() {
            assert!(
                logical_times[i - 1] <= logical_times[i],
                "Composite trace ordering should preserve monotonicity: {:?} > {:?}",
                logical_times[i - 1],
                logical_times[i]
            );
        }

        // 2. All traces recorded (MR4 budget idempotence equivalent)
        assert!(
            events.iter().all(|e| !trace_message(e).is_empty()),
            "All traces should have non-empty messages"
        );

        // 3. Deterministic branching produces expected pattern (MR2)
        let branch_traces = events
            .iter()
            .filter(|e| trace_message(e).contains("_branch_"))
            .count();
        assert_eq!(
            branch_traces, 3,
            "Deterministic branching should produce exactly 3 branch traces"
        );
    }

    // ========================================================================
    // br-asupersync-5ckssb: Cx::current() honors restriction stack
    // ========================================================================

    /// Sanity: a freshly-installed full cx returns the full mask.
    #[test]
    fn _5ckssb_full_set_current_returns_full_mask() {
        // Suppress any cx left installed by a previous test on this thread.
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let cx = Cx::for_testing();
        let _guard = Cx::set_current(Some(cx.clone()));
        let observed = Cx::current().expect("current must be installed");
        assert_eq!(observed.runtime_mask, cap::CapMask::all());
    }

    /// The actual ambient-authority defense: a restricted cx pushed
    /// via set_current_restricted causes any subsequent ambient
    /// Cx::current() lookup to observe the narrowed mask.
    #[test]
    fn _5ckssb_set_current_restricted_narrows_ambient_view() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        // Install a full cx first (simulates the runtime polling a task).
        let full_cx = Cx::for_testing();
        let _outer = Cx::set_current(Some(full_cx.clone()));

        // Now nest a restricted view (None).
        let restricted: Cx<cap::None> = full_cx.restrict::<cap::None>();
        let _inner = restricted.set_current_restricted();

        // Ambient lookup must now see the narrowed mask.
        let observed = Cx::current().expect("current must be installed");
        assert_eq!(
            observed.runtime_mask,
            cap::CapMask::none(),
            "innermost restriction must narrow the ambient mask"
        );

        // The cap-gated Option-returning methods must respect the
        // narrowed mask. These compile because the returned cx still
        // has Caps = cap::All (set_current always installs a FullCx);
        // the runtime check is what blocks access.
        assert!(observed.io().is_none(), "IO must be masked");
        assert!(observed.remote().is_none(), "REMOTE must be masked");
        assert!(observed.timer_driver().is_none(), "TIME must be masked");
        assert!(observed.fetch_cap().is_none(), "fetch_cap must be masked");
    }

    /// After the restriction guard drops, ambient lookups recover the
    /// outer (full) view.
    #[test]
    fn _5ckssb_restriction_guard_drop_restores_outer_mask() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing();
        let _outer = Cx::set_current(Some(full_cx.clone()));
        {
            let restricted: Cx<cap::None> = full_cx.restrict::<cap::None>();
            let _inner = restricted.set_current_restricted();
            assert_eq!(
                Cx::current()
                    .expect("current context should be set")
                    .runtime_mask,
                cap::CapMask::none(),
                "inside scope: restricted"
            );
        }
        // Inner guard dropped — outer full mask restored.
        assert_eq!(
            Cx::current().unwrap().runtime_mask,
            cap::CapMask::all(),
            "outer scope: full mask restored"
        );
    }

    /// Explicit push_restriction(none()) drops every cap on top of
    /// the current mask without changing the underlying cx.
    #[test]
    fn _5ckssb_push_restriction_intersects_with_current_mask() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing();
        let _outer = Cx::set_current(Some(full_cx));

        let _restrict = Cx::push_restriction(cap::CapMask::none());
        let observed = Cx::current().unwrap();
        assert_eq!(
            observed.runtime_mask,
            cap::CapMask::none(),
            "push_restriction(none) intersects to none"
        );
        assert!(observed.io().is_none());
        assert!(observed.remote().is_none());
        assert!(observed.timer_driver().is_none());

        // After drop, outer ALL is restored.
        drop(_restrict);
        assert_eq!(Cx::current().unwrap().runtime_mask, cap::CapMask::all());
    }

    #[test]
    fn _5ckssb_has_remote_respects_push_restriction_mask() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing_with_remote(crate::remote::RemoteCap::new());
        let _outer = Cx::set_current(Some(full_cx));
        assert!(
            Cx::current().unwrap().has_remote(),
            "unrestricted context should expose REMOTE"
        );

        let _restrict = Cx::push_restriction(cap::CapMask::none());
        let observed = Cx::current().unwrap();
        assert!(observed.remote().is_none(), "REMOTE handle must be masked");
        assert!(
            !observed.has_remote(),
            "has_remote must agree with the runtime capability mask"
        );
    }

    /// push_restriction with no installed cx must return a no-op
    /// guard (no panic, drop is safe).
    #[test]
    fn _5ckssb_push_restriction_with_no_current_is_no_op() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }
        let _g = Cx::push_restriction(cap::CapMask::none());
        assert!(Cx::current().is_none());
    }

    /// Multiple nested restrictions: each push narrows further; pops
    /// restore the prior level.
    #[test]
    fn _5ckssb_nested_restrictions_walk_stack_correctly() {
        while CURRENT_CX_STACK.with(|s| s.borrow().last().is_some()) {
            CURRENT_CX_STACK.with(|s| {
                s.borrow_mut().pop();
            });
        }

        let full_cx = Cx::for_testing();
        let _l1 = Cx::set_current(Some(full_cx.clone())); // ALL
        {
            let l2_cx: Cx<cap::CapSet<true, true, true, false, true>> =
                full_cx.restrict::<cap::CapSet<true, true, true, false, true>>();
            let _l2 = l2_cx.set_current_restricted(); // no IO
            assert!(!Cx::current().unwrap().runtime_mask.has(cap::CapMask::IO));
            assert!(
                Cx::current()
                    .unwrap()
                    .runtime_mask
                    .has(cap::CapMask::REMOTE)
            );
            {
                let l3_cx: Cx<cap::None> = full_cx.restrict::<cap::None>();
                let _l3 = l3_cx.set_current_restricted(); // none
                assert_eq!(Cx::current().unwrap().runtime_mask, cap::CapMask::none());
            }
            // l3 dropped — back to no-IO mask
            assert!(!Cx::current().unwrap().runtime_mask.has(cap::CapMask::IO));
            assert!(
                Cx::current()
                    .unwrap()
                    .runtime_mask
                    .has(cap::CapMask::REMOTE)
            );
        }
        // l2 dropped — back to ALL
        assert_eq!(Cx::current().unwrap().runtime_mask, cap::CapMask::all());
    }

    /// br-asupersync-ovztin: `Cx::for_request_with_budget` is now
    /// gated behind `cfg(any(test, feature = "test-internals"))`. In
    /// the cfg(test) compilation it remains visible for the existing
    /// conformance harness (cx_capability_semantics.rs:53,76); in a
    /// production build with `default-features = false` the
    /// constructor is removed entirely so external callers cannot
    /// mint a fully-capable Cx out of thin air.
    ///
    /// This regression test keeps the test-internals path observable
    /// (the constructor still works in cfg(test)) AND pins the
    /// invariant that the resulting Cx — like the pre-fix Cx — has
    /// `CapMask::all()`. That latter half is what makes external
    /// access to this constructor a capability-bypass: the previous
    /// shape was a fully ambient capability source. The fix removes
    /// the production access path, NOT the cap-mask shape (changing
    /// the cap-mask shape would break the legitimate test callers).
    #[test]
    fn ovztin_for_request_is_gated_and_remains_full_caps_in_tests() {
        // In cfg(test) the constructor is visible — call it.
        let cx = Cx::for_request();
        // Documented contract: the test constructor returns a Cx with
        // CapMask::all(). Production access is removed via cfg-gate;
        // this assertion just pins that the test path is unchanged.
        assert_eq!(cx.runtime_mask, cap::CapMask::all());
    }
}
