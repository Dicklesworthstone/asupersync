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
//! All effectful operations in Asupersync flow through explicit `Cx` tokens.
//! This design prevents ambient authority and enables:
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
use crate::observability::{
    DiagnosticContext, LogCollector, LogEntry, ObservabilityConfig, SpanId,
};
use crate::remote::RemoteCap;
use crate::runtime::blocking_pool::BlockingPoolHandle;
use crate::runtime::io_driver::{IoDriverHandle, IoRegistration};
use crate::runtime::reactor::{Interest, Source};
use crate::runtime::task_handle::JoinError;
use crate::time::{timeout, TimeSource, TimerDriverHandle, WallClock};
use crate::trace::distributed::{LogicalClockHandle, LogicalTime};
use crate::trace::{TraceBufferHandle, TraceEvent};
use crate::tracing_compat::{debug, error, info, trace};
use crate::types::{
    Budget, CancelKind, CancelReason, CxInner, RegionId, SystemPressure, TaskId, Time,
};
use crate::util::{EntropySource, OsEntropy};
use std::cell::RefCell;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Wake, Waker};
use std::time::Duration;

type NamedFuture<T> = (&'static str, Pin<Box<dyn Future<Output = T> + Send>>);
type NamedFutures<T> = Vec<NamedFuture<T>>;

/// Get the current wall clock time.
fn wall_clock_now() -> Time {
    static CLOCK: OnceLock<WallClock> = OnceLock::new();
    CLOCK.get_or_init(WallClock::new).now()
}

fn noop_waker() -> Waker {
    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
        fn wake_by_ref(self: &Arc<Self>) {}
    }

    Waker::from(Arc::new(NoopWaker))
}

/// The capability context for a task.
///
/// `Cx` provides access to runtime capabilities within Asupersync. All effectful
/// operations flow through `Cx`, ensuring explicit capability security with no
/// ambient authority.
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
/// # Usage for External Crates
///
/// External crates like fastapi_rust can depend on Asupersync and use `Cx`:
///
/// ```ignore
/// use asupersync::Cx;
///
/// async fn handle_request(cx: &Cx) -> Result<Response, Error> {
///     // Check if the request should be cancelled
///     if cx.is_cancel_requested() {
///         return Err(Error::Cancelled);
///     }
///
///     // Check remaining budget (timeout)
///     let budget = cx.budget();
///     if budget.is_expired() {
///         return Err(Error::Timeout);
///     }
///
///     // Trace request handling
///     cx.trace("Processing request");
///
///     // Do work...
///     Ok(Response::new())
/// }
/// ```
///
/// # Cloning
///
/// `Cx` is cheaply clonable (it wraps an `Arc`). Clones share the same
/// underlying state, so cancellation signals and budget updates are visible
/// to all clones.
///
/// # Lifetime Considerations
///
/// While `Cx` can be cloned and moved, it semantically belongs to a specific
/// task within a specific region. The runtime ensures proper cleanup when
/// tasks complete.
/// Grouped handle fields shared behind a single `Arc` to reduce per-clone
/// refcount operations from ~13 to 1 for this bundle.
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
}

#[derive(Debug)]
pub struct Cx<Caps = cap::All> {
    pub(crate) inner: Arc<std::sync::RwLock<CxInner>>,
    observability: Arc<std::sync::RwLock<ObservabilityState>>,
    handles: Arc<CxHandles>,
    // Use fn() -> Caps instead of just Caps to ensure Send+Sync regardless of Caps
    _caps: PhantomData<fn() -> Caps>,
}

// Manual Clone impl to avoid requiring `Caps: Clone` (Caps is just a phantom marker type).
// Only 3 Arc increments instead of ~15.
impl<Caps> Clone for Cx<Caps> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            observability: Arc::clone(&self.observability),
            handles: Arc::clone(&self.handles),
            _caps: PhantomData,
        }
    }
}

/// Internal observability state shared by `Cx` clones.
#[derive(Debug, Clone)]
pub struct ObservabilityState {
    collector: Option<LogCollector>,
    context: DiagnosticContext,
    trace: Option<TraceBufferHandle>,
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
            include_timestamps: self.include_timestamps,
        }
    }
}

/// Guard that restores the cancellation mask on drop.
struct MaskGuard<'a> {
    inner: &'a Arc<std::sync::RwLock<CxInner>>,
}

impl Drop for MaskGuard<'_> {
    fn drop(&mut self) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.mask_depth = inner.mask_depth.saturating_sub(1);
    }
}

type FullCx = Cx<cap::All>;

thread_local! {
    static CURRENT_CX: RefCell<Option<FullCx>> = const { RefCell::new(None) };
}

/// Guard that restores the previous Cx on drop.
#[cfg_attr(feature = "test-internals", visibility::make(pub))]
pub(crate) struct CurrentCxGuard {
    prev: Option<FullCx>,
}

impl Drop for CurrentCxGuard {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CURRENT_CX.with(|slot| {
            *slot.borrow_mut() = prev;
        });
    }
}

impl FullCx {
    /// Returns the current task context, if one is set.
    ///
    /// This is set by the runtime while polling a task.
    #[must_use]
    pub fn current() -> Option<Self> {
        CURRENT_CX.with(|slot| slot.borrow().clone())
    }

    /// Sets the current task context for the duration of the guard.
    #[must_use]
    #[cfg_attr(feature = "test-internals", visibility::make(pub))]
    pub(crate) fn set_current(cx: Option<Self>) -> CurrentCxGuard {
        let prev = CURRENT_CX.with(|slot| {
            let mut guard = slot.borrow_mut();
            let prev = guard.take();
            *guard = cx;
            prev
        });
        CurrentCxGuard { prev }
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
    pub(crate) fn from_inner(inner: Arc<std::sync::RwLock<CxInner>>) -> Self {
        let (region, task) = {
            let guard = inner.read().expect("lock poisoned");
            (guard.region, guard.task)
        };
        Self {
            inner,
            observability: Arc::new(std::sync::RwLock::new(ObservabilityState::new(
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
            }),
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
        let inner = Arc::new(std::sync::RwLock::new(CxInner::new(region, task, budget)));
        let observability_state =
            observability.unwrap_or_else(|| ObservabilityState::new(region, task));
        let observability = Arc::new(std::sync::RwLock::new(observability_state));
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
            }),
            _caps: PhantomData,
        }
    }

    /// Returns a cloned handle to the I/O driver, if present.
    #[must_use]
    pub(crate) fn io_driver_handle(&self) -> Option<IoDriverHandle> {
        self.handles.io_driver.clone()
    }

    /// Returns a cloned handle to the blocking pool, if present.
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
    #[must_use]
    pub(crate) fn retype<NewCaps>(&self) -> Cx<NewCaps> {
        Cx {
            inner: self.inner.clone(),
            observability: self.observability.clone(),
            handles: self.handles.clone(),
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
    pub fn pressure(&self) -> Option<&SystemPressure> {
        self.handles.pressure.as_deref()
    }

    /// Returns a cloned handle to the configured remote capability, if any.
    ///
    /// This is `pub(crate)` so internal wiring (e.g. spawning child tasks) can
    /// inherit remote capability without requiring `Caps: HasRemote` bounds.
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
    #[must_use]
    pub fn registry_handle(&self) -> Option<RegistryHandle> {
        self.handles.registry.clone()
    }

    /// Returns true if a registry handle is attached.
    #[must_use]
    pub fn has_registry(&self) -> bool {
        self.handles.registry.is_some()
    }

    /// Attaches an evidence sink for runtime decision tracing.
    #[must_use]
    pub fn with_evidence_sink(mut self, sink: Option<Arc<dyn EvidenceSink>>) -> Self {
        Arc::make_mut(&mut self.handles).evidence_sink = sink;
        self
    }

    /// Returns a cloned handle to the evidence sink, if attached.
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
    pub(crate) fn with_macaroon_handle(mut self, handle: Option<Arc<MacaroonToken>>) -> Self {
        Arc::make_mut(&mut self.handles).macaroon = handle;
        self
    }

    /// Returns a reference to the attached Macaroon token, if any.
    #[must_use]
    pub fn macaroon(&self) -> Option<&MacaroonToken> {
        self.handles.macaroon.as_deref()
    }

    /// Returns a cloned `Arc` handle to the macaroon, if any.
    #[must_use]
    pub(crate) fn macaroon_handle(&self) -> Option<Arc<MacaroonToken>> {
        self.handles.macaroon.clone()
    }

    /// Attenuate the capability token by adding a caveat.
    ///
    /// Returns a new `Cx` with an attenuated macaroon. The original
    /// context is unchanged. This does **not** require the root key —
    /// any holder can add caveats (but nobody can remove them).
    ///
    /// Returns `None` if no macaroon is attached.
    #[must_use]
    pub fn attenuate(&self, predicate: super::macaroon::CaveatPredicate) -> Option<Self> {
        let token = self.handles.macaroon.as_ref()?;
        let attenuated = MacaroonToken::clone(token).add_caveat(predicate);

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
    /// Returns `None` if no macaroon is attached.
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
    /// providing `window_use_count` in [`VerificationContext`].
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
        let budget = self.budget();
        budget.deadline.map_or_else(
            || Some(self.clone()),
            |d| self.attenuate_time_limit(d.as_millis()),
        )
    }

    /// Verify the attached capability token against a root key and context.
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
        context: &VerificationContext,
    ) -> Result<(), VerificationError> {
        let Some(token) = self.handles.macaroon.as_ref() else {
            return Err(VerificationError::InvalidSignature);
        };

        let result = token.verify(root_key, context);

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
            Err(VerificationError::CaveatFailed { index, .. }) => {
                (format!("verify_fail_caveat_{index}"), 0.5)
            }
            Err(VerificationError::MissingDischarge { index, .. }) => {
                (format!("verify_fail_missing_discharge_{index}"), 0.8)
            }
            Err(VerificationError::DischargeInvalid { index, .. }) => {
                (format!("verify_fail_discharge_invalid_{index}"), 0.9)
            }
        };

        let entry = franken_evidence::EvidenceLedger {
            ts_unix_ms: now_ms,
            component: "cx_macaroon".to_string(),
            action: action.clone(),
            posterior: vec![1.0],
            expected_loss_by_action: std::collections::HashMap::from([(action, loss)]),
            chosen_expected_loss: loss,
            calibration_score: 1.0,
            fallback_active: false,
            #[allow(clippy::cast_precision_loss)]
            top_features: vec![("caveat_count".to_string(), token.caveat_count() as f64)],
        };
        sink.emit(&entry);
    }

    /// Returns the current logical time without ticking.
    #[must_use]
    pub fn logical_now(&self) -> LogicalTime {
        self.handles.logical_clock.now()
    }

    /// Records a local logical event and returns the updated time.
    #[must_use]
    pub fn logical_tick(&self) -> LogicalTime {
        self.handles.logical_clock.tick()
    }

    /// Merges a received logical time and returns the updated time.
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
    #[must_use]
    pub fn timer_driver(&self) -> Option<TimerDriverHandle>
    where
        Caps: cap::HasTime,
    {
        self.handles.timer_driver.clone()
    }

    /// Returns true if a timer driver is available.
    ///
    /// When true, time operations can use the runtime's timer wheel.
    /// When false, time operations fall back to OS-level timing.
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
    #[must_use]
    pub fn io(&self) -> Option<&dyn crate::io::IoCap>
    where
        Caps: cap::HasIo,
    {
        self.handles.io_cap.as_ref().map(AsRef::as_ref)
    }

    /// Returns true if I/O capability is available.
    ///
    /// Convenience method to check if I/O operations can be performed.
    #[must_use]
    pub fn has_io(&self) -> bool
    where
        Caps: cap::HasIo,
    {
        self.handles.io_cap.is_some()
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
    #[must_use]
    pub fn remote(&self) -> Option<&RemoteCap>
    where
        Caps: cap::HasRemote,
    {
        self.handles.remote_cap.as_ref().map(AsRef::as_ref)
    }

    /// Returns true if the remote capability is available.
    ///
    /// Convenience method to check if remote task operations can be performed.
    #[must_use]
    pub fn has_remote(&self) -> bool
    where
        Caps: cap::HasRemote,
    {
        self.handles.remote_cap.is_some()
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
    #[must_use]
    pub fn region_id(&self) -> RegionId {
        self.inner.read().expect("lock poisoned").region
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
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.inner.read().expect("lock poisoned").task
    }

    /// Returns the task type label, if one has been set.
    ///
    /// Task types are optional metadata used by adaptive deadline monitoring
    /// and metrics to group similar work.
    #[must_use]
    pub fn task_type(&self) -> Option<String> {
        self.inner.read().expect("lock poisoned").task_type.clone()
    }

    /// Sets a task type label for adaptive monitoring and metrics.
    ///
    /// This is intended to be called early in task execution to associate
    /// a stable label with the task's behavior profile.
    pub fn set_task_type(&self, task_type: impl Into<String>) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.task_type = Some(task_type.into());
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
    #[must_use]
    pub fn budget(&self) -> Budget {
        self.inner.read().expect("lock poisoned").budget
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
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.inner.read().expect("lock poisoned").cancel_requested
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
    #[allow(clippy::result_large_err)]
    pub fn checkpoint(&self) -> Result<(), crate::error::Error> {
        // Record progress checkpoint and check cancellation under a single lock
        let (cancel_requested, mask_depth, task, region, budget, budget_baseline, cancel_reason) = {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.checkpoint_state.record();
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
            )
        };

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
        // Record progress checkpoint and check cancellation under a single lock
        let (cancel_requested, mask_depth, task, region, budget, budget_baseline, cancel_reason) = {
            let mut inner = self.inner.write().expect("lock poisoned");
            inner.checkpoint_state.record_with_message(msg.into());
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
            )
        };

        Self::check_cancel_from_values(
            cancel_requested,
            mask_depth,
            task,
            region,
            budget,
            budget_baseline,
            cancel_reason.as_ref(),
        )
    }

    /// Returns a snapshot of the current checkpoint state.
    ///
    /// The checkpoint state tracks progress reporting checkpoints:
    /// - `last_checkpoint`: When the last checkpoint was recorded
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
    ///     if let Some(last) = state.last_checkpoint {
    ///         // Stalled if no checkpoint in 30 seconds
    ///         last.elapsed() < Duration::from_secs(30)
    ///     } else {
    ///         // Never checkpointed, could be stuck
    ///         false
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn checkpoint_state(&self) -> crate::types::CheckpointState {
        self.inner
            .read()
            .expect("lock poisoned")
            .checkpoint_state
            .clone()
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
        cancel_reason: Option<&CancelReason>,
    ) -> Result<(), crate::error::Error> {
        let polls_used = if budget_baseline.poll_quota == u32::MAX {
            None
        } else {
            Some(budget_baseline.poll_quota.saturating_sub(budget.poll_quota))
        };
        let cost_used = match (budget_baseline.cost_quota, budget.cost_quota) {
            (Some(baseline), Some(remaining)) => Some(baseline.saturating_sub(remaining)),
            _ => None,
        };
        let time_remaining = budget.deadline;

        let _ = (
            &task,
            &region,
            &budget,
            &budget_baseline,
            &polls_used,
            &cost_used,
            &time_remaining,
        );

        trace!(
            task_id = ?task,
            region_id = ?region,
            polls_used = ?polls_used,
            polls_remaining = budget.poll_quota,
            time_remaining = ?time_remaining,
            time_remaining_source = "deadline",
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

    /// Internal: checks cancellation without recording a checkpoint.
    #[allow(clippy::result_large_err)]
    fn check_cancel(&self) -> Result<(), crate::error::Error> {
        let (cancel_requested, mask_depth, task, region, budget, budget_baseline, cancel_reason) = {
            let inner = self.inner.read().expect("lock poisoned");
            (
                inner.cancel_requested,
                inner.mask_depth,
                inner.task,
                inner.region,
                inner.budget,
                inner.budget_baseline,
                inner.cancel_reason.clone(),
            )
        };

        Self::check_cancel_from_values(
            cancel_requested,
            mask_depth,
            task,
            region,
            budget,
            budget_baseline,
            cancel_reason.as_ref(),
        )
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
    pub fn masked<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        {
            let mut inner = self.inner.write().expect("lock poisoned");
            debug_assert!(
                inner.mask_depth < crate::types::task_context::MAX_MASK_DEPTH,
                "mask depth exceeded MAX_MASK_DEPTH ({}): this violates INV-MASK-BOUNDED \
                 and prevents cancellation from ever being observed. \
                 Reduce nesting of Cx::masked() sections.",
                crate::types::task_context::MAX_MASK_DEPTH,
            );
            if inner.mask_depth >= crate::types::task_context::MAX_MASK_DEPTH {
                error!(
                    depth = inner.mask_depth,
                    max = crate::types::task_context::MAX_MASK_DEPTH,
                    "INV-MASK-BOUNDED violated: mask depth saturated, cancellation may be unobservable"
                );
            }
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
    /// This is currently a placeholder. The full implementation will write
    /// to the trace buffer maintained by the runtime.
    pub fn trace(&self, message: &str) {
        self.log(LogEntry::trace(message));
        let Some(trace) = self.trace_buffer() else {
            return;
        };
        let now = self
            .handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now);
        let seq = trace.next_seq();
        let logical_time = self.logical_tick();
        trace.push_event(TraceEvent::user_trace(seq, now, message).with_logical_time(logical_time));
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
        let mut entry = LogEntry::trace(message);
        for &(k, v) in fields {
            entry = entry.with_field(k, v);
        }
        self.log(entry);
        let Some(trace) = self.trace_buffer() else {
            return;
        };
        let now = self
            .handles
            .timer_driver
            .as_ref()
            .map_or_else(wall_clock_now, TimerDriverHandle::now);
        let seq = trace.next_seq();
        let logical_time = self.logical_tick();
        trace.push_event(TraceEvent::user_trace(seq, now, message).with_logical_time(logical_time));
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
        let mut obs = self.observability.write().expect("lock poisoned");
        obs.context = obs.context.clone().with_custom("request_id", id);
    }

    /// Returns the current request correlation ID, if set.
    #[must_use]
    pub fn request_id(&self) -> Option<String> {
        self.diagnostic_context()
            .custom("request_id")
            .map(String::from)
    }

    /// Logs a structured entry to the attached collector, if present.
    pub fn log(&self, entry: LogEntry) {
        let obs = self.observability.read().expect("lock poisoned");
        let Some(collector) = obs.collector.clone() else {
            return;
        };
        let include_timestamps = obs.include_timestamps;
        let context = obs.context.clone();
        drop(obs);
        let mut entry = entry.with_context(&context);
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
        self.observability
            .read()
            .expect("lock poisoned")
            .context
            .clone()
    }

    /// Replaces the current diagnostic context.
    pub fn set_diagnostic_context(&self, ctx: DiagnosticContext) {
        let mut obs = self.observability.write().expect("lock poisoned");
        obs.context = ctx;
    }

    /// Attaches a log collector to this context.
    pub fn set_log_collector(&self, collector: LogCollector) {
        let mut obs = self.observability.write().expect("lock poisoned");
        obs.collector = Some(collector);
    }

    /// Returns the current log collector, if attached.
    #[must_use]
    pub fn log_collector(&self) -> Option<LogCollector> {
        self.observability
            .read()
            .expect("lock poisoned")
            .collector
            .clone()
    }

    /// Attaches a trace buffer to this context.
    pub fn set_trace_buffer(&self, trace: TraceBufferHandle) {
        let mut obs = self.observability.write().expect("lock poisoned");
        obs.trace = Some(trace);
    }

    /// Returns the current trace buffer handle, if attached.
    #[must_use]
    pub fn trace_buffer(&self) -> Option<TraceBufferHandle> {
        self.observability
            .read()
            .expect("lock poisoned")
            .trace
            .clone()
    }

    /// Derives an observability state for a child task.
    pub(crate) fn child_observability(&self, region: RegionId, task: TaskId) -> ObservabilityState {
        let obs = self.observability.read().expect("lock poisoned");
        obs.derive_child(region, task)
    }

    /// Returns the entropy source for this context.
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

    /// Generates a random `u64` using the context entropy source.
    #[must_use]
    pub fn random_u64(&self) -> u64
    where
        Caps: cap::HasRandom,
    {
        let value = self.handles.entropy.next_u64();
        trace!(
            source = self.handles.entropy.source_id(),
            task_id = ?self.task_id(),
            value,
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
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = value;
        if !value {
            inner.cancel_reason = None;
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
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = value;
        if !value {
            inner.cancel_reason = None;
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
        let (region, task) = {
            let mut inner = self.inner.write().expect("lock poisoned");
            let region = inner.region;
            let task = inner.task;

            let mut reason = CancelReason::new(kind).with_region(region).with_task(task);
            if let Some(msg) = message {
                reason = reason.with_message(msg);
            }

            inner.cancel_requested = true;
            inner.cancel_reason = Some(reason);
            drop(inner);
            (region, task)
        };

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
        let region = {
            let mut inner = self.inner.write().expect("lock poisoned");
            let region = inner.region;

            // Minimal attribution: just kind and region
            let reason = CancelReason::new(kind).with_region(region);

            inner.cancel_requested = true;
            inner.cancel_reason = Some(reason);
            region
        };

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
    #[must_use]
    pub fn cancel_reason(&self) -> Option<CancelReason> {
        let inner = self.inner.read().expect("lock poisoned");
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
        let cancel_reason = self
            .inner
            .read()
            .expect("lock poisoned")
            .cancel_reason
            .clone();
        let chain: Vec<CancelReason> = cancel_reason
            .as_ref()
            .map(|r| r.chain().cloned().collect())
            .unwrap_or_default();
        chain.into_iter()
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
        let inner = self.inner.read().expect("lock poisoned");
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
        let inner = self.inner.read().expect("lock poisoned");
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
        let inner = self.inner.read().expect("lock poisoned");
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
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.cancel_requested = true;
        inner.cancel_reason = Some(reason);
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
        let (res, _) = SelectAll::new(futures).await;
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
        let race_fut = Box::pin(self.race(futures));
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
    ///     let handle = scope.spawn(|cx| async { 42 });
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
        crate::cx::Scope::new(self.region_id(), budget)
    }

    /// Creates a [`Scope`](super::Scope) bound to this context's region with a custom budget.
    ///
    /// This is used by the `scope!` macro when a budget is specified:
    /// ```ignore
    /// scope!(cx, budget: Budget::deadline(Duration::from_secs(5)), {
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

        debug!(
            task_id = ?self.task_id(),
            region_id = ?self.region_id(),
            parent_deadline = ?parent_budget.deadline,
            parent_poll_quota = parent_budget.poll_quota,
            parent_cost_quota = ?parent_budget.cost_quota,
            parent_priority = parent_budget.priority,
            budget_deadline = ?budget.deadline,
            budget_poll_quota = budget.poll_quota,
            budget_cost_quota = ?budget.cost_quota,
            budget_priority = budget.priority,
            deadline_tightened,
            poll_tightened,
            cost_tightened,
            priority_boosted,
            budget_source = "explicit",
            "scope budget set"
        );
        crate::cx::Scope::new(self.region_id(), budget)
    }
}

impl Cx<cap::All> {
    /// Creates a capability context for testing purposes.
    ///
    /// This constructor creates a Cx with default IDs and an infinite budget,
    /// suitable for unit and integration tests. The resulting context is fully
    /// functional but not connected to a real runtime.
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
    #[must_use]
    pub fn for_testing() -> Self {
        Self::new(
            RegionId::new_for_test(0, 0),
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
    #[must_use]
    pub fn for_testing_with_budget(budget: Budget) -> Self {
        Self::new(
            RegionId::new_for_test(0, 0),
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
    /// This API is intended for testing only.
    #[must_use]
    pub fn for_testing_with_io() -> Self {
        Self::new_with_io(
            RegionId::new_for_test(0, 0),
            TaskId::new_for_test(0, 0),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::new(crate::io::LabIoCap::new())),
            None,
        )
    }

    /// Creates a request-scoped capability context with a specified budget.
    ///
    /// This is intended for production request handling that needs unique
    /// task/region identifiers outside the scheduler.
    #[must_use]
    pub fn for_request_with_budget(budget: Budget) -> Self {
        Self::new(RegionId::new_ephemeral(), TaskId::new_ephemeral(), budget)
    }

    /// Creates a request-scoped capability context with an infinite budget.
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
    /// This API is intended for testing only.
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
    use super::*;
    use crate::cx::macaroon::CaveatPredicate;
    use crate::trace::TraceBufferHandle;
    use crate::util::{ArenaIndex, DetEntropy};

    fn test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    fn test_cx_with_entropy(seed: u64) -> Cx {
        Cx::new_with_observability(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
            None,
            None,
            Some(Arc::new(DetEntropy::new(seed))),
        )
    }

    #[test]
    fn io_not_available_by_default() {
        let cx = test_cx();
        assert!(!cx.has_io());
        assert!(cx.io().is_none());
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
        use std::panic::{catch_unwind, AssertUnwindSafe};

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

    /// INV-MASK-BOUNDED: exceeding MAX_MASK_DEPTH must panic.
    #[test]
    #[should_panic(expected = "MAX_MASK_DEPTH")]
    fn mask_depth_exceeds_bound_panics() {
        let cx = test_cx();

        // Directly set mask_depth to the limit, then call masked() once
        // to trigger the bound check. This avoids deep nesting which
        // would cause double-panic in MaskGuard drops during unwind.
        {
            let mut inner = cx.inner.write().expect("lock");
            inner.mask_depth = crate::types::task_context::MAX_MASK_DEPTH;
        }
        // This call should panic because mask_depth is already at the limit.
        cx.masked(|| {});
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
        assert_eq!(reason.message, Some("manual stop"));
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
            assert_eq!(root.message, Some("request timeout"));
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
        let expected_region = RegionId::from_arena(ArenaIndex::new(0, 0));
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
    fn checkpoint_clears_message() {
        let cx = test_cx();

        // Record checkpoint with message
        assert!(cx.checkpoint_with("step 1").is_ok());
        assert_eq!(
            cx.checkpoint_state().last_message.as_deref(),
            Some("step 1")
        );

        // Regular checkpoint clears the message
        assert!(cx.checkpoint().is_ok());
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
            cx.macaroon().unwrap().identifier(),
            cx2.macaroon().unwrap().identifier()
        );
    }

    #[test]
    fn cx_macaroon_survives_restrict() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "all:cap", "cx/root");
        let cx: Cx<cap::All> = test_cx().with_macaroon(token);
        let narrow: Cx<cap::None> = cx.restrict();

        assert_eq!(
            cx.macaroon().unwrap().identifier(),
            narrow.macaroon().unwrap().identifier()
        );
    }

    #[test]
    fn cx_attenuate_adds_caveat() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let cx2 = cx
            .attenuate(CaveatPredicate::TimeBefore(5000))
            .expect("attenuate should succeed");

        // Original unchanged
        assert_eq!(cx.macaroon().unwrap().caveat_count(), 0);
        // Attenuated has one caveat
        assert_eq!(cx2.macaroon().unwrap().caveat_count(), 1);
        // Both share the same identifier
        assert_eq!(
            cx.macaroon().unwrap().identifier(),
            cx2.macaroon().unwrap().identifier()
        );
    }

    #[test]
    fn cx_attenuate_returns_none_without_macaroon() {
        let cx = test_cx();
        assert!(cx.attenuate(CaveatPredicate::MaxUses(10)).is_none());
    }

    #[test]
    fn cx_verify_capability_succeeds() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let ctx = VerificationContext::new().with_time(1000);
        assert!(cx.verify_capability(&key, &ctx).is_ok());
    }

    #[test]
    fn cx_verify_capability_fails_wrong_key() {
        let key = test_root_key();
        let wrong_key = crate::security::key::AuthKey::from_seed(99);
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler");
        let cx = test_cx().with_macaroon(token);

        let ctx = VerificationContext::new();
        let err = cx.verify_capability(&wrong_key, &ctx).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn cx_verify_capability_fails_no_macaroon() {
        let key = test_root_key();
        let cx = test_cx();

        let ctx = VerificationContext::new();
        let err = cx.verify_capability(&key, &ctx).unwrap_err();
        assert!(matches!(err, VerificationError::InvalidSignature));
    }

    #[test]
    fn cx_verify_with_caveats() {
        let key = test_root_key();
        let token = MacaroonToken::mint(&key, "spawn:r1", "cx/scheduler")
            .add_caveat(CaveatPredicate::TimeBefore(5000))
            .add_caveat(CaveatPredicate::RegionScope(42));

        let cx = test_cx().with_macaroon(token);

        // Passes with correct context
        let ctx = VerificationContext::new().with_time(1000).with_region(42);
        assert!(cx.verify_capability(&key, &ctx).is_ok());

        // Fails with expired time
        let ctx_expired = VerificationContext::new().with_time(6000).with_region(42);
        let err = cx.verify_capability(&key, &ctx_expired).unwrap_err();
        assert!(matches!(
            err,
            VerificationError::CaveatFailed { index: 0, .. }
        ));

        // Fails with wrong region
        let ctx_wrong_region = VerificationContext::new().with_time(1000).with_region(99);
        let err = cx.verify_capability(&key, &ctx_wrong_region).unwrap_err();
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
        let cx2 = cx.attenuate(CaveatPredicate::TimeBefore(3000)).unwrap();

        // Further attenuate with max uses
        let cx3 = cx2.attenuate(CaveatPredicate::MaxUses(5)).unwrap();

        // Original has no restrictions
        let ctx = VerificationContext::new().with_time(1000);
        assert!(cx.verify_capability(&key, &ctx).is_ok());

        // cx2 has time restriction
        assert!(cx2.verify_capability(&key, &ctx).is_ok());
        let ctx_late = VerificationContext::new().with_time(4000);
        assert!(cx2.verify_capability(&key, &ctx_late).is_err());

        // cx3 has both time + uses restriction
        let ctx_ok = VerificationContext::new().with_time(1000).with_use_count(3);
        assert!(cx3.verify_capability(&key, &ctx_ok).is_ok());
        let ctx_overuse = VerificationContext::new()
            .with_time(1000)
            .with_use_count(10);
        assert!(cx3.verify_capability(&key, &ctx_overuse).is_err());
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
        cx.verify_capability(&key, &ctx).unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].component, "cx_macaroon");
        assert_eq!(entries[0].action, "verify_success");

        // Failed verification should also emit evidence
        let wrong_key = crate::security::key::AuthKey::from_seed(99);
        let _ = cx.verify_capability(&wrong_key, &ctx);
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].action, "verify_fail_signature");
    }
}
