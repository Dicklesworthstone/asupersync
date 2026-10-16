//! Service discovery trait and implementations.
//!
//! Provides abstractions for discovering service endpoints dynamically.
//! The [`Discover`] trait models a stream of endpoint changes, enabling
//! load balancers and connection pools to react to topology changes.
//!
//! # Implementations
//!
//! - [`StaticList`]: Fixed set of endpoints (no changes).
//! - [`DnsServiceDiscovery`]: Resolves a hostname via DNS, polling periodically.
//! - [`ActiveHealthDiscovery`]: Wraps another discovery source with deterministic
//!   endpoint probes and backoff.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::service::discover::{Discover, StaticList, Change};
//!
//! let endpoints = StaticList::new(vec![
//!     "10.0.0.1:8080".parse().unwrap(),
//!     "10.0.0.2:8080".parse().unwrap(),
//! ]);
//!
//! let changes = endpoints.poll_discover();
//! ```

use crate::types::Time;
use parking_lot::{Condvar, Mutex};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn wall_clock_now() -> Time {
    crate::time::wall_now()
}

fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

type ResolveFn =
    Arc<dyn Fn(&str, u16) -> Result<HashSet<SocketAddr>, std::io::Error> + Send + Sync + 'static>;

fn default_resolve(hostname: &str, port: u16) -> Result<HashSet<SocketAddr>, std::io::Error> {
    let host_port = format!("{hostname}:{port}");
    let addrs: HashSet<SocketAddr> = host_port.to_socket_addrs()?.collect();
    Ok(addrs)
}

// ─── Change type ────────────────────────────────────────────────────────────

/// A change in the set of discovered endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change<K> {
    /// A new endpoint was discovered.
    Insert(K),
    /// An endpoint was removed.
    Remove(K),
}

impl<K: fmt::Display> fmt::Display for Change<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insert(k) => write!(f, "+{k}"),
            Self::Remove(k) => write!(f, "-{k}"),
        }
    }
}

// ─── Discover trait ─────────────────────────────────────────────────────────

/// Service discovery: produces changes in the set of endpoints.
///
/// Implementations produce a sequence of [`Change`] events indicating
/// when endpoints are added or removed. Callers poll for updates and
/// apply changes to their routing tables.
pub trait Discover {
    /// The key type identifying an endpoint (typically `SocketAddr`).
    type Key: Clone + Eq + std::hash::Hash + fmt::Debug;

    /// Error type for discovery operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Poll for the next batch of changes.
    ///
    /// Returns a list of changes since the last poll. An empty vec
    /// means no changes are available.
    fn poll_discover(&self) -> Result<Vec<Change<Self::Key>>, Self::Error>;

    /// Get all currently known endpoints.
    fn endpoints(&self) -> Vec<Self::Key>;
}

// ─── StaticList ─────────────────────────────────────────────────────────────

/// A static, immutable list of endpoints.
///
/// Returns all endpoints as `Insert` on the first poll, then returns
/// an empty list on subsequent polls.
pub struct StaticList<K> {
    endpoints: Vec<K>,
    delivered: Mutex<bool>,
}

fn dedup_preserve_order<K>(items: &[K]) -> Vec<K>
where
    K: Clone + Eq + std::hash::Hash,
{
    let mut seen = HashSet::with_capacity(items.len());
    let mut deduped = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item) {
            deduped.push(item.clone());
        }
    }
    deduped
}

impl<K: Clone> StaticList<K> {
    /// Create a new static list with the given endpoints.
    #[must_use]
    pub fn new(endpoints: Vec<K>) -> Self {
        Self {
            endpoints,
            delivered: Mutex::new(false),
        }
    }
}

impl<K: Clone + Eq + std::hash::Hash + fmt::Debug + Send + Sync + 'static> Discover
    for StaticList<K>
{
    type Key = K;
    type Error = std::convert::Infallible;

    fn poll_discover(&self) -> Result<Vec<Change<K>>, Self::Error> {
        let mut delivered = self.delivered.lock();
        if *delivered {
            return Ok(Vec::new());
        }
        *delivered = true;
        drop(delivered);
        Ok(dedup_preserve_order(&self.endpoints)
            .into_iter()
            .map(Change::Insert)
            .collect())
    }

    fn endpoints(&self) -> Vec<K> {
        dedup_preserve_order(&self.endpoints)
    }
}

impl<K: fmt::Debug> fmt::Debug for StaticList<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticList")
            .field("endpoints", &self.endpoints)
            .field("delivered", &*self.delivered.lock())
            .finish()
    }
}

// ─── Active health discovery ───────────────────────────────────────────────

/// Health probe transport shape.
///
/// The probe kind is metadata for callers that want one reusable probe closure
/// across HTTP, gRPC, and TCP checks. The discovery wrapper itself stays
/// runtime-agnostic and deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthProbeKind {
    /// HTTP health check, conventionally a GET against `path`.
    Http {
        /// Request path used by the probe.
        path: String,
    },
    /// gRPC health-check protocol.
    Grpc,
    /// TCP connect-style liveness check.
    Tcp,
}

impl HealthProbeKind {
    /// Build an HTTP probe kind.
    #[must_use]
    pub fn http(path: impl Into<String>) -> Self {
        Self::Http { path: path.into() }
    }
}

/// Result of probing one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Endpoint is available for load-balanced traffic.
    Healthy,
    /// Endpoint should be withheld from load-balanced traffic.
    Unhealthy,
}

/// Published endpoint health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHealthStatus {
    /// Endpoint is known in topology but has not produced a probe result yet.
    Unknown,
    /// Endpoint is currently available.
    Healthy,
    /// Endpoint is currently unavailable.
    Unhealthy,
}

impl EndpointHealthStatus {
    /// Returns whether this status should be exposed through [`Discover::endpoints`].
    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// Exponential backoff settings for failed active probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeBackoff {
    base: Duration,
    max: Duration,
}

impl ProbeBackoff {
    /// Create a probe backoff schedule.
    #[must_use]
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self { base, max }
    }

    /// Base delay applied after the first failed probe.
    #[must_use]
    pub const fn base(self) -> Duration {
        self.base
    }

    /// Maximum delay applied after repeated failed probes.
    #[must_use]
    pub const fn max(self) -> Duration {
        self.max
    }

    #[must_use]
    fn delay_for(self, consecutive_failures: u32) -> Duration {
        let mut nanos = duration_to_nanos(self.base);
        let shifts = consecutive_failures.saturating_sub(1).min(31);
        for _ in 0..shifts {
            nanos = nanos.saturating_mul(2);
        }
        Duration::from_nanos(nanos.min(duration_to_nanos(self.max)))
    }
}

impl Default for ProbeBackoff {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(30))
    }
}

/// Configuration for active health discovery.
#[derive(Clone)]
pub struct ActiveHealthConfig {
    probe_kind: HealthProbeKind,
    probe_interval: Duration,
    failure_backoff: ProbeBackoff,
    time_getter: fn() -> Time,
}

impl ActiveHealthConfig {
    /// Create active health configuration for a probe kind.
    #[must_use]
    pub fn new(probe_kind: HealthProbeKind) -> Self {
        Self {
            probe_kind,
            probe_interval: Duration::from_secs(30),
            failure_backoff: ProbeBackoff::default(),
            time_getter: wall_clock_now,
        }
    }

    /// Set the interval between successful probes.
    #[must_use]
    pub fn probe_interval(mut self, interval: Duration) -> Self {
        self.probe_interval = interval;
        self
    }

    /// Set the failed-probe backoff schedule.
    #[must_use]
    pub fn failure_backoff(mut self, backoff: ProbeBackoff) -> Self {
        self.failure_backoff = backoff;
        self
    }

    /// Set a deterministic time source.
    #[must_use]
    pub fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }

    /// Returns the configured probe kind.
    #[must_use]
    pub const fn probe_kind(&self) -> &HealthProbeKind {
        &self.probe_kind
    }
}

impl fmt::Debug for ActiveHealthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveHealthConfig")
            .field("probe_kind", &self.probe_kind)
            .field("probe_interval", &self.probe_interval)
            .field("failure_backoff", &self.failure_backoff)
            .field("time_getter", &"<fn>")
            .finish()
    }
}

#[derive(Debug, Clone)]
struct ProbeEntry {
    status: EndpointHealthStatus,
    consecutive_failures: u32,
    probe_count: u64,
    transition_count: u64,
    next_probe_at: Option<Time>,
}

impl Default for ProbeEntry {
    fn default() -> Self {
        Self {
            status: EndpointHealthStatus::Unknown,
            consecutive_failures: 0,
            probe_count: 0,
            transition_count: 0,
            next_probe_at: None,
        }
    }
}

impl ProbeEntry {
    fn should_probe(&self, now: Time) -> bool {
        self.next_probe_at.is_none_or(|deadline| now >= deadline)
    }

    fn record_probe(&mut self, outcome: ProbeOutcome, now: Time, config: &ActiveHealthConfig) {
        self.probe_count = self.probe_count.saturating_add(1);
        let next_status = match outcome {
            ProbeOutcome::Healthy => EndpointHealthStatus::Healthy,
            ProbeOutcome::Unhealthy => EndpointHealthStatus::Unhealthy,
        };
        if self.status != next_status {
            self.transition_count = self.transition_count.saturating_add(1);
        }
        self.status = next_status;

        match outcome {
            ProbeOutcome::Healthy => {
                self.consecutive_failures = 0;
                self.next_probe_at = Some(now + config.probe_interval);
            }
            ProbeOutcome::Unhealthy => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                self.next_probe_at =
                    Some(now + config.failure_backoff.delay_for(self.consecutive_failures));
            }
        }
    }
}

#[derive(Debug)]
struct ActiveHealthState<K> {
    entries: HashMap<K, ProbeEntry>,
    published: Vec<K>,
}

impl<K> Default for ActiveHealthState<K> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            published: Vec::new(),
        }
    }
}

/// Health snapshot for one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealth<K> {
    /// Endpoint key.
    pub endpoint: K,
    /// Current health status.
    pub status: EndpointHealthStatus,
    /// Consecutive failed probes.
    pub consecutive_failures: u32,
    /// Total probes run for this endpoint.
    pub probe_count: u64,
    /// Number of status transitions observed.
    pub transition_count: u64,
    /// Next scheduled probe time.
    pub next_probe_at: Option<Time>,
}

/// Discovery error from active health wrapping.
#[derive(Debug)]
pub enum ActiveHealthDiscoveryError<E> {
    /// The wrapped discovery source failed.
    Discover(E),
}

impl<E: fmt::Display> fmt::Display for ActiveHealthDiscoveryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discover(e) => write!(f, "active health discovery source error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for ActiveHealthDiscoveryError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Discover(e) => Some(e),
        }
    }
}

/// Discovery wrapper that withholds endpoints failing active health probes.
///
/// The wrapped discovery source remains the topology authority. Active health
/// only decides which known endpoints are published to load balancers through
/// the normal [`Discover`] contract.
pub struct ActiveHealthDiscovery<D: Discover, P> {
    inner: D,
    config: ActiveHealthConfig,
    probe: P,
    state: Mutex<ActiveHealthState<D::Key>>,
}

impl<D: Discover, P> ActiveHealthDiscovery<D, P> {
    /// Create an active-health wrapper around a discovery source.
    #[must_use]
    pub fn new(inner: D, config: ActiveHealthConfig, probe: P) -> Self {
        Self {
            inner,
            config,
            probe,
            state: Mutex::new(ActiveHealthState::default()),
        }
    }

    /// Returns the wrapped discovery source.
    #[must_use]
    pub const fn inner(&self) -> &D {
        &self.inner
    }

    /// Returns the active-health configuration.
    #[must_use]
    pub const fn config(&self) -> &ActiveHealthConfig {
        &self.config
    }

    /// Returns the latest health snapshot for an endpoint.
    #[must_use]
    pub fn endpoint_health(&self, endpoint: &D::Key) -> Option<EndpointHealth<D::Key>>
    where
        D::Key: Clone,
    {
        self.state
            .lock()
            .entries
            .get(endpoint)
            .map(|entry| EndpointHealth {
                endpoint: endpoint.clone(),
                status: entry.status,
                consecutive_failures: entry.consecutive_failures,
                probe_count: entry.probe_count,
                transition_count: entry.transition_count,
                next_probe_at: entry.next_probe_at,
            })
    }
}

impl<D, P> Discover for ActiveHealthDiscovery<D, P>
where
    D: Discover,
    D::Key: Clone + Eq + std::hash::Hash + fmt::Debug + Send + Sync + 'static,
    P: Fn(&D::Key, &HealthProbeKind) -> ProbeOutcome + Send + Sync,
{
    type Key = D::Key;
    type Error = ActiveHealthDiscoveryError<D::Error>;

    fn poll_discover(&self) -> Result<Vec<Change<Self::Key>>, Self::Error> {
        self.inner
            .poll_discover()
            .map_err(ActiveHealthDiscoveryError::Discover)?;

        let raw_endpoints = self.inner.endpoints();
        let raw_set: HashSet<_> = raw_endpoints.iter().cloned().collect();
        let now = (self.config.time_getter)();
        let due = {
            let mut state = self.state.lock();
            state
                .entries
                .retain(|endpoint, _| raw_set.contains(endpoint));
            raw_endpoints
                .iter()
                .filter_map(|endpoint| {
                    let entry = state.entries.entry(endpoint.clone()).or_default();
                    entry.should_probe(now).then(|| endpoint.clone())
                })
                .collect::<Vec<_>>()
        };

        let probe_results = due
            .into_iter()
            .map(|endpoint| {
                let outcome = (self.probe)(&endpoint, &self.config.probe_kind);
                (endpoint, outcome)
            })
            .collect::<Vec<_>>();

        let mut state = self.state.lock();
        state
            .entries
            .retain(|endpoint, _| raw_set.contains(endpoint));
        for endpoint in &raw_endpoints {
            state.entries.entry(endpoint.clone()).or_default();
        }
        for (endpoint, outcome) in probe_results {
            if raw_set.contains(&endpoint) {
                state
                    .entries
                    .entry(endpoint)
                    .or_default()
                    .record_probe(outcome, now, &self.config);
            }
        }

        let new_published = raw_endpoints
            .into_iter()
            .filter(|endpoint| {
                state
                    .entries
                    .get(endpoint)
                    .is_some_and(|entry| entry.status.is_healthy())
            })
            .collect::<Vec<_>>();
        let old_published = state.published.clone();
        let old_set: HashSet<_> = old_published.iter().cloned().collect();
        let new_set: HashSet<_> = new_published.iter().cloned().collect();
        let mut changes = Vec::new();

        changes.extend(
            new_published
                .iter()
                .filter(|endpoint| !old_set.contains(*endpoint))
                .cloned()
                .map(Change::Insert),
        );
        changes.extend(
            old_published
                .into_iter()
                .filter(|endpoint| !new_set.contains(endpoint))
                .map(Change::Remove),
        );
        state.published = new_published;

        Ok(changes)
    }

    fn endpoints(&self) -> Vec<Self::Key> {
        self.state.lock().published.clone()
    }
}

impl<D, P> fmt::Debug for ActiveHealthDiscovery<D, P>
where
    D: Discover + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("ActiveHealthDiscovery")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .field("endpoints", &state.published.len())
            .finish()
    }
}

// ─── DnsServiceDiscovery ────────────────────────────────────────────────────

/// DNS-based service discovery error.
#[derive(Debug)]
pub enum DnsDiscoveryError {
    /// DNS resolution failed.
    Resolve(std::io::Error),
}

impl fmt::Display for DnsDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(e) => write!(f, "DNS resolution failed: {e}"),
        }
    }
}

impl std::error::Error for DnsDiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve(e) => Some(e),
        }
    }
}

/// DNS-based service discovery configuration.
#[derive(Clone)]
pub struct DnsDiscoveryConfig {
    /// Hostname to resolve (e.g., "api.example.com").
    pub hostname: String,
    /// Port to use for discovered endpoints.
    pub port: u16,
    /// How often to re-resolve the hostname.
    pub poll_interval: Duration,
    time_getter: fn() -> Time,
    resolver: ResolveFn,
    resolver_label: &'static str,
}

impl DnsDiscoveryConfig {
    /// Create a new DNS discovery configuration.
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            poll_interval: Duration::from_secs(30),
            time_getter: wall_clock_now,
            resolver: Arc::new(
                default_resolve as fn(&str, u16) -> Result<HashSet<SocketAddr>, std::io::Error>,
            ),
            resolver_label: "system",
        }
    }

    /// Set the poll interval.
    #[must_use]
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Set a custom time source for deterministic retry cooldowns.
    #[must_use]
    pub fn with_time_getter(mut self, time_getter: fn() -> Time) -> Self {
        self.time_getter = time_getter;
        self
    }

    /// Set a custom resolver for deterministic tests or non-standard lookup sources.
    #[must_use]
    pub fn with_resolver<R>(mut self, resolver: R) -> Self
    where
        R: Fn(&str, u16) -> Result<HashSet<SocketAddr>, std::io::Error> + Send + Sync + 'static,
    {
        self.resolver = Arc::new(resolver);
        self.resolver_label = "custom";
        self
    }

    /// Returns the time source used by this config.
    #[must_use]
    pub fn time_getter(&self) -> fn() -> Time {
        self.time_getter
    }
}

impl fmt::Debug for DnsDiscoveryConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsDiscoveryConfig")
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("poll_interval", &self.poll_interval)
            .field("time_getter", &"<fn>")
            .field("resolver", &self.resolver_label)
            .finish()
    }
}

/// DNS-based service discovery.
///
/// Periodically resolves a hostname to produce endpoint changes.
/// On each poll, the hostname is re-resolved and the difference
/// between the current and previous endpoint sets is computed.
pub struct DnsServiceDiscovery {
    config: DnsDiscoveryConfig,
    state: Mutex<DnsDiscoveryState>,
    resolve_done: Condvar,
    /// Number of pollers currently blocked inside `resolve_done.wait`,
    /// waiting for the active leader to publish an inflight generation.
    ///
    /// Exposed via [`Self::waiter_count`] so tests can deterministically
    /// synchronise the release of a captive leader with the arrival of
    /// followers on the condvar; racing the release against an async
    /// scheduler otherwise makes the coalesce paths flaky.
    waiters: AtomicUsize,
}

struct DnsDiscoveryState {
    /// Currently known endpoints.
    current: HashSet<SocketAddr>,
    /// When the last resolution attempt was performed.
    last_resolve: Option<Time>,
    /// Monotonic generation for started resolution attempts.
    resolve_generation: u64,
    /// Generation currently being resolved, if any.
    in_flight_generation: Option<u64>,
    /// Generation of the last successful resolution applied to `current`.
    applied_generation: u64,
    /// Number of successful resolutions applied to `current`.
    resolve_count: u64,
    /// Number of failed resolutions.
    error_count: u64,
    /// Last resolver failure produced by an in-flight generation.
    last_resolution_error: Option<StoredDnsError>,
}

#[derive(Clone)]
struct StoredDnsError {
    generation: u64,
    kind: std::io::ErrorKind,
    message: String,
}

impl StoredDnsError {
    fn from_error(generation: u64, error: &std::io::Error) -> Self {
        Self {
            generation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn into_error(self) -> DnsDiscoveryError {
        DnsDiscoveryError::Resolve(std::io::Error::new(self.kind, self.message))
    }
}

fn sorted_socket_addrs(addrs: &HashSet<SocketAddr>) -> Vec<SocketAddr> {
    let mut sorted: Vec<SocketAddr> = addrs.iter().copied().collect();
    sorted.sort_unstable();
    sorted
}

fn dns_changes(
    current: &HashSet<SocketAddr>,
    new_addrs: &HashSet<SocketAddr>,
) -> Vec<Change<SocketAddr>> {
    let mut changes = Vec::new();

    for addr in sorted_socket_addrs(new_addrs) {
        if !current.contains(&addr) {
            changes.push(Change::Insert(addr));
        }
    }

    for addr in sorted_socket_addrs(current) {
        if !new_addrs.contains(&addr) {
            changes.push(Change::Remove(addr));
        }
    }

    changes
}

impl DnsServiceDiscovery {
    /// Create a new DNS-based service discovery.
    #[must_use]
    pub fn new(config: DnsDiscoveryConfig) -> Self {
        Self {
            config,
            state: Mutex::new(DnsDiscoveryState {
                current: HashSet::new(),
                last_resolve: None,
                resolve_generation: 0,
                in_flight_generation: None,
                applied_generation: 0,
                resolve_count: 0,
                error_count: 0,
                last_resolution_error: None,
            }),
            resolve_done: Condvar::new(),
            waiters: AtomicUsize::new(0),
        }
    }

    /// Number of pollers currently waiting on a coalesced in-flight resolution.
    ///
    /// Primarily intended for tests that need to observe that at least one
    /// follower has parked on the condvar before releasing the leader. Callers
    /// should treat this as a best-effort snapshot.
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// Create with hostname and port.
    pub fn from_host(hostname: impl Into<String>, port: u16) -> Self {
        Self::new(DnsDiscoveryConfig::new(hostname, port))
    }

    /// Get the hostname being resolved.
    #[must_use]
    pub fn hostname(&self) -> &str {
        &self.config.hostname
    }

    /// Get the port being used.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.config.port
    }

    /// Get the number of successful resolutions applied to the current state.
    #[must_use]
    pub fn resolve_count(&self) -> u64 {
        self.state.lock().resolve_count
    }

    /// Get the number of failed resolutions.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.state.lock().error_count
    }

    /// Force a re-resolution on the next poll.
    pub fn invalidate(&self) {
        self.state.lock().last_resolve = None;
    }

    /// Perform DNS resolution synchronously.
    fn resolve(&self) -> Result<HashSet<SocketAddr>, std::io::Error> {
        (self.config.resolver)(&self.config.hostname, self.config.port)
    }

    /// Check if a re-resolution is needed based on the poll interval.
    fn needs_resolve(&self, now: Time, state: &DnsDiscoveryState) -> bool {
        let poll_interval_nanos = duration_to_nanos(self.config.poll_interval);
        state
            .last_resolve
            .is_none_or(|last| now.duration_since(last) >= poll_interval_nanos)
    }
}

/// Armed around the resolver call and forgotten when it returns; dropped
/// only while a resolver panic unwinds.
struct ReleaseInFlightOnUnwind<'a> {
    discovery: &'a DnsServiceDiscovery,
    generation: u64,
}

impl Drop for ReleaseInFlightOnUnwind<'_> {
    fn drop(&mut self) {
        let mut state = self.discovery.state.lock();
        if state.in_flight_generation == Some(self.generation) {
            state.in_flight_generation = None;
        }
        state.error_count += 1;
        state.last_resolution_error = Some(StoredDnsError::from_error(
            self.generation,
            &std::io::Error::other("dns discovery resolver panicked"),
        ));
        drop(state);
        self.discovery.resolve_done.notify_all();
    }
}

impl Discover for DnsServiceDiscovery {
    type Key = SocketAddr;
    type Error = DnsDiscoveryError;

    fn poll_discover(&self) -> Result<Vec<Change<SocketAddr>>, DnsDiscoveryError> {
        let now = (self.config.time_getter)();
        let resolve_generation = {
            let mut state = self.state.lock();
            if let Some(in_flight_generation) = state.in_flight_generation {
                // Publish that a follower is about to park before releasing
                // the state mutex inside `wait`. Tests spin on `waiter_count`
                // to confirm the follower has arrived before they release the
                // leader, which eliminates the racy schedule where the leader
                // completes before the follower observes the in-flight slot.
                self.waiters.fetch_add(1, Ordering::AcqRel);
                self.resolve_done.wait(&mut state);
                self.waiters.fetch_sub(1, Ordering::AcqRel);
                if let Some(err) = state
                    .last_resolution_error
                    .clone()
                    .filter(|err| err.generation == in_flight_generation)
                {
                    return Err(err.into_error());
                }
                return Ok(Vec::new());
            }

            if !self.needs_resolve(now, &state) {
                return Ok(Vec::new());
            }

            // Anchor the cooldown to the decision point before invoking the
            // resolver so concurrent readers do not block behind DNS latency.
            state.last_resolve = Some(now);
            state.resolve_generation = state
                .resolve_generation
                .checked_add(1)
                .expect("dns discovery resolve generation overflow");
            state.in_flight_generation = Some(state.resolve_generation);
            state.resolve_generation
        };

        // If the resolver panics, the in-flight slot must still be released:
        // otherwise every waiting follower, and every later poll, would wait
        // on `resolve_done` for a resolution that never finishes.
        let unwind = ReleaseInFlightOnUnwind {
            discovery: self,
            generation: resolve_generation,
        };
        let resolution = self.resolve();
        std::mem::forget(unwind);
        let mut state = self.state.lock();
        state.in_flight_generation = None;
        let result = match resolution {
            Ok(new_addrs) => {
                state.last_resolution_error = None;
                if resolve_generation <= state.applied_generation {
                    // A newer successful poll already committed fresher state
                    // after this resolve began, so this older success must not
                    // clobber it.
                    Ok(Vec::new())
                } else {
                    state.resolve_count += 1;
                    let changes = dns_changes(&state.current, &new_addrs);
                    state.current = new_addrs;
                    state.applied_generation = resolve_generation;
                    Ok(changes)
                }
            }
            Err(e) => {
                // Failed attempts still count as resolver errors even if a newer
                // generation has already started; flattening them to Ok([])
                // hides a real failure from the caller.
                // Failures participate in the same cooldown as successful
                // resolutions so callers that poll frequently do not hot-loop
                // on an unhealthy hostname.
                state.error_count += 1;
                state.last_resolution_error =
                    Some(StoredDnsError::from_error(resolve_generation, &e));
                Err(DnsDiscoveryError::Resolve(e))
            }
        };
        drop(state);
        self.resolve_done.notify_all();
        result
    }

    fn endpoints(&self) -> Vec<SocketAddr> {
        sorted_socket_addrs(&self.state.lock().current)
    }
}

impl fmt::Debug for DnsServiceDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("DnsServiceDiscovery")
            .field("hostname", &self.config.hostname)
            .field("port", &self.config.port)
            .field("endpoints", &state.current.len())
            .field("resolve_count", &state.resolve_count)
            .finish()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "discover_inline_tests.rs"]
mod tests;
