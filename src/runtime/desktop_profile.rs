//! Bounded runtime configuration for native desktop hosts.
//!
//! This profile is deliberately additive: enabling `desktop-runtime-profile`
//! does not enable the networking, security, database, telemetry, or CLI
//! feature surfaces. It gives an owner or embedding host a single, reviewed
//! configuration boundary instead of inheriting the runtime's unbounded queue
//! default or an accidentally unlimited root region.

use crate::record::RegionLimits;
use crate::runtime::reactor::{
    BrowserReactor, Events, Interest, IoReactorCapabilitySnapshot, Reactor, Source, Token,
};
use crate::runtime::{Runtime, RuntimeConfig, RuntimeHandle};
use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Stable name for the first bounded desktop profile.
pub const DESKTOP_RUNTIME_PROFILE_NAME: &str = "desktop-bounded-v1";

/// A validated set of admission and scheduling limits for a desktop runtime.
///
/// The values are intentionally explicit and small enough to leave headroom
/// for the host's event and render paths. This type only describes runtime
/// admission; it is not an application resource-byte ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopRuntimeProfile {
    worker_threads: usize,
    global_queue_limit: usize,
    steal_batch_size: usize,
    poll_budget: u32,
    blocking_min_threads: usize,
    blocking_max_threads: usize,
    root_max_children: usize,
    root_max_tasks: usize,
    root_max_obligations: usize,
    root_max_heap_bytes: usize,
}

impl DesktopRuntimeProfile {
    /// Construct the reviewed bounded profile.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            worker_threads: 2,
            global_queue_limit: 256,
            steal_batch_size: 8,
            poll_budget: 64,
            blocking_min_threads: 1,
            blocking_max_threads: 2,
            root_max_children: 64,
            root_max_tasks: 1_024,
            root_max_obligations: 1_024,
            root_max_heap_bytes: 64 * 1024 * 1024,
        }
    }

    /// Construct a profile with explicit limits for boundary testing and
    /// hosts that have a measured, documented envelope.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn with_limits(
        worker_threads: usize,
        global_queue_limit: usize,
        steal_batch_size: usize,
        poll_budget: u32,
        blocking_min_threads: usize,
        blocking_max_threads: usize,
        root_max_children: usize,
        root_max_tasks: usize,
        root_max_obligations: usize,
        root_max_heap_bytes: usize,
    ) -> Self {
        Self {
            worker_threads,
            global_queue_limit,
            steal_batch_size,
            poll_budget,
            blocking_min_threads,
            blocking_max_threads,
            root_max_children,
            root_max_tasks,
            root_max_obligations,
            root_max_heap_bytes,
        }
    }

    /// Validate the profile without creating threads or touching the host.
    pub fn validate(&self) -> Result<(), DesktopRuntimeProfileError> {
        if self.worker_threads == 0 {
            return Err(DesktopRuntimeProfileError::ZeroWorkers);
        }
        if self.global_queue_limit == 0 {
            return Err(DesktopRuntimeProfileError::UnboundedGlobalQueue);
        }
        if self.steal_batch_size == 0 {
            return Err(DesktopRuntimeProfileError::ZeroStealBatch);
        }
        if self.poll_budget == 0 {
            return Err(DesktopRuntimeProfileError::ZeroPollBudget);
        }
        if self.blocking_min_threads > self.blocking_max_threads {
            return Err(DesktopRuntimeProfileError::BlockingRangeInverted {
                min: self.blocking_min_threads,
                max: self.blocking_max_threads,
            });
        }
        for (kind, value) in [
            (DesktopRootLimit::Children, self.root_max_children),
            (DesktopRootLimit::Tasks, self.root_max_tasks),
            (DesktopRootLimit::Obligations, self.root_max_obligations),
            (DesktopRootLimit::HeapBytes, self.root_max_heap_bytes),
        ] {
            if value == 0 {
                return Err(DesktopRuntimeProfileError::ZeroRootLimit { kind });
            }
        }
        Ok(())
    }

    /// Materialize the profile as an inert runtime configuration.
    ///
    /// This method performs no runtime construction, thread creation, I/O, or
    /// environment reads. The host decides when and where to build the runtime.
    pub fn runtime_config(&self) -> Result<RuntimeConfig, DesktopRuntimeProfileError> {
        self.validate()?;
        let mut config = RuntimeConfig::default();
        config.worker_threads = self.worker_threads;
        config.global_queue_limit = self.global_queue_limit;
        config.steal_batch_size = self.steal_batch_size;
        config.poll_budget = self.poll_budget;
        config.blocking.min_threads = self.blocking_min_threads;
        config.blocking.max_threads = self.blocking_max_threads;
        config.thread_name_prefix = "asupersync-desktop".to_string();
        config.root_region_limits = Some(RegionLimits {
            max_children: Some(self.root_max_children),
            max_tasks: Some(self.root_max_tasks),
            max_obligations: Some(self.root_max_obligations),
            max_heap_bytes: Some(self.root_max_heap_bytes),
            curve_budget: None,
        });
        Ok(config)
    }

    /// Start a runtime owned by the desktop host.
    ///
    /// Validation and construction are intentionally separate from
    /// [`Self::standard`]: selecting a profile is inert, while this explicit
    /// operation starts the runtime's workers and blocking pool. The returned
    /// owner contains only Asupersync resources; the host's event loop,
    /// windows, and devices remain caller-owned.
    #[allow(clippy::result_large_err)]
    pub fn start(&self) -> Result<DesktopRuntime, DesktopRuntimeStartError> {
        let config = self
            .runtime_config()
            .map_err(DesktopRuntimeStartError::InvalidProfile)?;
        // The desktop profile is the dependency-clean structured-runtime
        // slice: it deliberately has no host-I/O authority. Native socket and
        // polling adapters stay behind `native-runtime`; a later host adapter
        // may inject one explicitly when the product actually needs it.
        Runtime::with_config_and_reactor(config, Some(Arc::new(DesktopReactor::default())))
            .map(|runtime| DesktopRuntime { runtime })
            .map_err(DesktopRuntimeStartError::Runtime)
    }
}

/// The desktop profile's reactor: the non-blocking first-party event reactor
/// with native host-I/O registration refused.
///
/// `BrowserReactor` accepts any source for token bookkeeping but only reports
/// readiness published by browser host bindings, so a native socket registered
/// with it parked forever (asupersync-bi2462.121). Refusing with `Unsupported`
/// is the socket layer's "no reactor can take this fd" signal: the socket
/// re-polls on its own instead of waiting for a wake that never comes.
#[derive(Default)]
struct DesktopReactor(BrowserReactor);

impl Reactor for DesktopReactor {
    fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        self.0.capability_snapshot()
    }

    fn register(&self, _source: &dyn Source, _token: Token, _interest: Interest) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the desktop runtime profile has no host I/O reactor",
        ))
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.0.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        self.0.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        self.0.poll(events, timeout)
    }

    fn wake(&self) -> io::Result<()> {
        self.0.wake()
    }

    fn registration_count(&self) -> usize {
        self.0.registration_count()
    }
}

impl Default for DesktopRuntimeProfile {
    fn default() -> Self {
        Self::standard()
    }
}

/// Root admission dimensions checked by the desktop profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopRootLimit {
    /// Maximum child regions.
    Children,
    /// Maximum live tasks.
    Tasks,
    /// Maximum pending obligations.
    Obligations,
    /// Maximum region-owned heap bytes.
    HeapBytes,
}

/// Validation failures for a desktop runtime profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopRuntimeProfileError {
    /// At least one worker is required for this native profile.
    ZeroWorkers,
    /// A zero global queue means unbounded admission and is forbidden here.
    UnboundedGlobalQueue,
    /// A zero steal batch does not make a useful bounded profile.
    ZeroStealBatch,
    /// A zero poll budget would be normalized implicitly by the runtime.
    ZeroPollBudget,
    /// Blocking-pool limits must describe an ordered range.
    BlockingRangeInverted { min: usize, max: usize },
    /// Every root admission dimension must be explicitly positive.
    ZeroRootLimit { kind: DesktopRootLimit },
}

impl fmt::Display for DesktopRuntimeProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroWorkers => f.write_str("desktop profile requires at least one worker"),
            Self::UnboundedGlobalQueue => {
                f.write_str("desktop profile requires a bounded global queue")
            }
            Self::ZeroStealBatch => f.write_str("desktop profile requires a positive steal batch"),
            Self::ZeroPollBudget => f.write_str("desktop profile requires a positive poll budget"),
            Self::BlockingRangeInverted { min, max } => {
                write!(
                    f,
                    "desktop blocking range is inverted: min={min}, max={max}"
                )
            }
            Self::ZeroRootLimit { kind } => write!(f, "desktop root limit is zero: {kind:?}"),
        }
    }
}

impl std::error::Error for DesktopRuntimeProfileError {}

/// A runtime explicitly owned by one desktop host instance.
///
/// This wrapper makes the lifecycle boundary visible to an embedding host:
/// [`Self::close`] shuts down only this runtime. It does not own or stop the
/// host event loop, window system, or rendering device.
pub struct DesktopRuntime {
    runtime: Runtime,
}

impl DesktopRuntime {
    /// Run a future using this runtime's caller-driven entry point.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// Return a strong handle for host-owned task admission.
    ///
    /// The host must release this handle before expecting [`Self::close`] to
    /// report completed teardown, because a strong handle keeps the runtime
    /// alive by design.
    #[must_use]
    pub fn handle(&self) -> RuntimeHandle {
        self.runtime.handle()
    }

    /// Return the immutable reactor receipt selected for this profile.
    ///
    /// The bounded profile must remain usable for structured concurrency and
    /// channels without acquiring a native socket/poller. Hosts that need
    /// I/O use the separately qualified runtime builder injection seam.
    #[must_use]
    pub fn io_reactor_capability_snapshot(
        &self,
    ) -> crate::runtime::reactor::IoReactorCapabilitySnapshot {
        self.runtime.io_reactor_capability_snapshot()
    }

    /// Close this runtime within the host's teardown bound.
    ///
    /// A `true` result means the runtime's workers and drivers completed
    /// teardown within `timeout`; `false` means teardown continues on the
    /// runtime's bounded reaper path. No host-owned resource is touched.
    #[must_use]
    pub fn close(self, timeout: Duration) -> bool {
        self.runtime.shutdown_timeout(timeout)
    }
}

/// Failure while starting a validated desktop runtime profile.
#[derive(Debug)]
pub enum DesktopRuntimeStartError {
    /// The profile contains an invalid or unbounded limit.
    InvalidProfile(DesktopRuntimeProfileError),
    /// The runtime could not start its configured host-side workers/drivers.
    Runtime(crate::error::Error),
}

impl fmt::Display for DesktopRuntimeStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(error) => write!(f, "invalid desktop runtime profile: {error}"),
            Self::Runtime(error) => write!(f, "desktop runtime start failed: {error}"),
        }
    }
}

impl std::error::Error for DesktopRuntimeStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProfile(error) => Some(error),
            Self::Runtime(error) => Some(error),
        }
    }
}

/// Completion receipt for an operation delegated to a foreign blocking call.
///
/// Cancellation may discard the wrapper's returned value, but it must not
/// pretend that the foreign call stopped. The operation owns this receipt and
/// marks it at the actual terminal point, including panic unwinding.
#[derive(Clone, Debug, Default)]
pub struct ForeignCallCompletion {
    completed: Arc<AtomicBool>,
}

impl ForeignCallCompletion {
    /// Create a receipt in the not-yet-complete state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return whether the foreign operation reached its terminal point.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }

    fn mark_complete(&self) {
        self.completed.store(true, Ordering::Release);
    }
}

/// Run a foreign blocking operation while conserving its terminal receipt.
///
/// The returned future follows Asupersync's soft-cancellation policy: dropping
/// the wrapper cancels result delivery, while the already-running foreign call
/// continues to its terminal point. `completion` becomes observable only when
/// that point is reached.
pub async fn run_foreign_call<F, T>(completion: ForeignCallCompletion, operation: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    crate::runtime::spawn_blocking::spawn_blocking(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
        completion.mark_complete();
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_profile_materializes_explicit_bounded_admission() {
        let profile = DesktopRuntimeProfile::standard();
        let config = profile.runtime_config().expect("standard profile is valid");

        assert_eq!(DESKTOP_RUNTIME_PROFILE_NAME, "desktop-bounded-v1");
        assert_eq!(config.worker_threads, 2);
        assert_eq!(config.global_queue_limit, 256);
        assert_eq!(config.blocking.min_threads, 1);
        assert_eq!(config.blocking.max_threads, 2);
        assert_eq!(
            config.root_region_limits.as_ref().unwrap().max_tasks,
            Some(1_024)
        );
        assert_eq!(config.thread_name_prefix, "asupersync-desktop");
    }

    #[test]
    fn zero_queue_is_rejected_instead_of_normalized_to_unbounded() {
        let profile = DesktopRuntimeProfile::with_limits(1, 0, 1, 1, 0, 0, 1, 1, 1, 1);
        assert_eq!(
            profile.validate(),
            Err(DesktopRuntimeProfileError::UnboundedGlobalQueue)
        );
    }

    #[test]
    fn inverted_blocking_range_is_rejected() {
        let profile = DesktopRuntimeProfile::with_limits(1, 1, 1, 1, 2, 1, 1, 1, 1, 1);
        assert_eq!(
            profile.validate(),
            Err(DesktopRuntimeProfileError::BlockingRangeInverted { min: 2, max: 1 })
        );
    }

    #[test]
    fn unit_limits_are_the_valid_boundary() {
        let profile = DesktopRuntimeProfile::with_limits(1, 1, 1, 1, 0, 0, 1, 1, 1, 1);
        let config = profile.runtime_config().expect("unit limits are valid");

        assert_eq!(config.global_queue_limit, 1);
        assert_eq!(config.steal_batch_size, 1);
        assert_eq!(config.poll_budget, 1);
        assert_eq!(
            config.root_region_limits.as_ref().unwrap().max_heap_bytes,
            Some(1)
        );
    }
}
