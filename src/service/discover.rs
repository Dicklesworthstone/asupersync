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
use parking_lot::Mutex;
use std::collections::HashSet;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
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
}

struct DnsDiscoveryState {
    /// Currently known endpoints.
    current: HashSet<SocketAddr>,
    /// When the last resolution attempt was performed.
    last_resolve: Option<Time>,
    /// Monotonic generation for started resolution attempts.
    resolve_generation: u64,
    /// Generation of the last successful resolution applied to `current`.
    applied_generation: u64,
    /// Number of successful resolutions applied to `current`.
    resolve_count: u64,
    /// Number of failed resolutions.
    error_count: u64,
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
                applied_generation: 0,
                resolve_count: 0,
                error_count: 0,
            }),
        }
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

impl Discover for DnsServiceDiscovery {
    type Key = SocketAddr;
    type Error = DnsDiscoveryError;

    fn poll_discover(&self) -> Result<Vec<Change<SocketAddr>>, DnsDiscoveryError> {
        let now = (self.config.time_getter)();
        let resolve_generation = {
            let mut state = self.state.lock();
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
            state.resolve_generation
        };

        let resolution = self.resolve();
        let mut state = self.state.lock();
        let result = match resolution {
            Ok(new_addrs) => {
                if resolve_generation <= state.applied_generation {
                    // A newer successful poll already committed fresher state
                    // after this resolve began, so this older success must not
                    // clobber it.
                    return Ok(Vec::new());
                }
                state.resolve_count += 1;
                let changes = dns_changes(&state.current, &new_addrs);
                state.current = new_addrs;
                state.applied_generation = resolve_generation;
                Ok(changes)
            }
            Err(e) => {
                // Failed attempts still count as resolver errors even if a newer
                // generation has already started; flattening them to Ok([])
                // hides a real failure from the caller.
                // Failures participate in the same cooldown as successful
                // resolutions so callers that poll frequently do not hot-loop
                // on an unhealthy hostname.
                state.error_count += 1;
                Err(DnsDiscoveryError::Resolve(e))
            }
        };
        drop(state);
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
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex as StdMutex, mpsc};
    use std::thread;

    thread_local! {
        static TEST_NOW: Cell<u64> = const { Cell::new(0) };
    }

    type ResolverResult = Result<HashSet<SocketAddr>, std::io::Error>;

    fn set_test_time(nanos: u64) {
        TEST_NOW.with(|now| now.set(nanos));
    }

    fn test_time() -> Time {
        Time::from_nanos(TEST_NOW.with(std::cell::Cell::get))
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn socket_set(addrs: &[&str]) -> HashSet<SocketAddr> {
        addrs.iter().map(|addr| addr.parse().unwrap()).collect()
    }

    fn scripted_resolver(
        script: Vec<ResolverResult>,
    ) -> impl Fn(&str, u16) -> ResolverResult + Send + Sync + 'static {
        let script = Arc::new(StdMutex::new(VecDeque::from(script)));
        move |_, _| {
            script
                .lock()
                .expect("resolver script lock poisoned")
                .pop_front()
                .expect("resolver script exhausted")
        }
    }

    // ================================================================
    // Change
    // ================================================================

    #[test]
    fn change_insert_display() {
        let change = Change::Insert("10.0.0.1:80".to_string());
        assert_eq!(format!("{change}"), "+10.0.0.1:80");
    }

    #[test]
    fn change_remove_display() {
        let change = Change::Remove("10.0.0.1:80".to_string());
        assert_eq!(format!("{change}"), "-10.0.0.1:80");
    }

    #[test]
    fn change_eq() {
        let a = Change::Insert(42);
        let b = Change::Insert(42);
        let c = Change::Remove(42);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn change_debug_clone() {
        let change = Change::Insert(1);
        let dbg = format!("{change:?}");
        assert!(dbg.contains("Insert"));
        let cloned = change.clone();
        assert_eq!(cloned, change);
    }

    // ================================================================
    // StaticList
    // ================================================================

    #[test]
    fn static_list_first_poll_returns_inserts() {
        init_test("static_list_first_poll_returns_inserts");
        let list = StaticList::new(vec![1, 2, 3]);
        let changes = list.poll_discover().unwrap();
        assert_eq!(changes.len(), 3);
        assert!(changes.contains(&Change::Insert(1)));
        assert!(changes.contains(&Change::Insert(2)));
        assert!(changes.contains(&Change::Insert(3)));
        crate::test_complete!("static_list_first_poll_returns_inserts");
    }

    #[test]
    fn static_list_subsequent_polls_empty() {
        init_test("static_list_subsequent_polls_empty");
        let list = StaticList::new(vec![1, 2]);
        let _ = list.poll_discover().unwrap();
        let changes = list.poll_discover().unwrap();
        assert!(changes.is_empty());
        crate::test_complete!("static_list_subsequent_polls_empty");
    }

    #[test]
    fn static_list_endpoints() {
        let list = StaticList::new(vec![10, 20]);
        assert_eq!(list.endpoints(), vec![10, 20]);
    }

    #[test]
    fn static_list_first_poll_deduplicates_duplicate_endpoints() {
        init_test("static_list_first_poll_deduplicates_duplicate_endpoints");
        let list = StaticList::new(vec![1, 2, 1, 3, 2]);
        let changes = list.poll_discover().unwrap();
        assert_eq!(
            changes,
            vec![Change::Insert(1), Change::Insert(2), Change::Insert(3)]
        );
        crate::test_complete!("static_list_first_poll_deduplicates_duplicate_endpoints");
    }

    #[test]
    fn static_list_endpoints_deduplicate_preserving_first_seen_order() {
        init_test("static_list_endpoints_deduplicate_preserving_first_seen_order");
        let list = StaticList::new(vec![3, 1, 3, 2, 1, 4]);
        assert_eq!(list.endpoints(), vec![3, 1, 2, 4]);
        crate::test_complete!("static_list_endpoints_deduplicate_preserving_first_seen_order");
    }

    #[test]
    fn static_list_empty() {
        let list = StaticList::<i32>::new(vec![]);
        let changes = list.poll_discover().unwrap();
        assert!(changes.is_empty());
        assert!(list.endpoints().is_empty());
    }

    #[test]
    fn static_list_debug() {
        let list = StaticList::new(vec![1, 2]);
        let dbg = format!("{list:?}");
        assert!(dbg.contains("StaticList"));
    }

    // ================================================================
    // DnsDiscoveryConfig
    // ================================================================

    #[test]
    fn dns_config_new() {
        init_test("dns_config_new");
        let config = DnsDiscoveryConfig::new("example.com", 80);
        assert_eq!(config.hostname, "example.com");
        assert_eq!(config.port, 80);
        assert_eq!(config.poll_interval, Duration::from_secs(30));
        crate::test_complete!("dns_config_new");
    }

    #[test]
    fn dns_config_poll_interval() {
        let config =
            DnsDiscoveryConfig::new("example.com", 80).poll_interval(Duration::from_mins(1));
        assert_eq!(config.poll_interval, Duration::from_mins(1));
    }

    #[test]
    fn dns_config_with_time_getter() {
        let config = DnsDiscoveryConfig::new("example.com", 80).with_time_getter(test_time);
        assert_eq!((config.time_getter())().as_nanos(), 0);
    }

    #[test]
    fn dns_config_debug_clone() {
        let config = DnsDiscoveryConfig::new("host", 443);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DnsDiscoveryConfig"));
        assert_eq!(config.hostname, "host");
    }

    // ================================================================
    // DnsServiceDiscovery
    // ================================================================

    #[test]
    fn dns_discovery_new() {
        init_test("dns_discovery_new");
        let discovery = DnsServiceDiscovery::from_host("localhost", 80);
        assert_eq!(discovery.hostname(), "localhost");
        assert_eq!(discovery.port(), 80);
        assert_eq!(discovery.resolve_count(), 0);
        assert_eq!(discovery.error_count(), 0);
        crate::test_complete!("dns_discovery_new");
    }

    #[test]
    fn dns_discovery_default_resolver_accepts_ip_literal() {
        init_test("dns_discovery_default_resolver_accepts_ip_literal");
        let discovery = DnsServiceDiscovery::from_host("127.0.0.1", 8080);

        let changes = discovery.poll_discover().unwrap();
        assert_eq!(
            changes,
            vec![Change::Insert("127.0.0.1:8080".parse().unwrap())]
        );
        assert_eq!(discovery.resolve_count(), 1);

        crate::test_complete!("dns_discovery_default_resolver_accepts_ip_literal");
    }

    #[test]
    fn dns_discovery_no_change_within_interval() {
        init_test("dns_discovery_no_change_within_interval");
        let addrs = socket_set(&["127.0.0.1:80"]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_mins(5))
                .with_resolver(move |hostname, port| {
                    assert_eq!(hostname, "service.test");
                    assert_eq!(port, 80);
                    Ok(addrs.clone())
                }),
        );

        let _ = discovery.poll_discover().unwrap();
        // Second poll should return empty (within poll interval).
        let changes = discovery.poll_discover().unwrap();
        assert!(changes.is_empty());
        assert_eq!(discovery.resolve_count(), 1);
        crate::test_complete!("dns_discovery_no_change_within_interval");
    }

    #[test]
    fn dns_discovery_invalidate_forces_resolve() {
        init_test("dns_discovery_invalidate_forces_resolve");
        let resolver = scripted_resolver(vec![
            Ok(socket_set(&["127.0.0.1:80"])),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_mins(5))
                .with_resolver(resolver),
        );

        let _ = discovery.poll_discover().unwrap();
        assert_eq!(discovery.resolve_count(), 1);

        discovery.invalidate();
        let _ = discovery.poll_discover().unwrap();
        assert_eq!(discovery.resolve_count(), 2);
        crate::test_complete!("dns_discovery_invalidate_forces_resolve");
    }

    #[test]
    fn dns_discovery_endpoints_follow_custom_resolver() {
        init_test("dns_discovery_endpoints_follow_custom_resolver");
        let addrs = socket_set(&["127.0.0.1:80", "127.0.0.2:80"]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .with_resolver(move |_, _| Ok(addrs.clone())),
        );
        assert!(discovery.endpoints().is_empty());
        let _ = discovery.poll_discover().unwrap();
        assert_eq!(
            discovery.endpoints(),
            vec![
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.2:80".parse().unwrap(),
            ]
        );
        crate::test_complete!("dns_discovery_endpoints_follow_custom_resolver");
    }

    #[test]
    fn dns_discovery_custom_resolver_can_reenter_without_deadlock() {
        init_test("dns_discovery_custom_resolver_can_reenter_without_deadlock");
        let discovery_handle = Arc::new(StdMutex::new(None::<Arc<DnsServiceDiscovery>>));
        let discovery_handle_for_resolver = Arc::clone(&discovery_handle);
        let observed = Arc::new(StdMutex::new(None::<(u64, Vec<SocketAddr>)>));
        let observed_for_resolver = Arc::clone(&observed);
        let addrs = socket_set(&["127.0.0.1:80"]);

        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80).with_resolver(move |_, _| {
                let discovery = discovery_handle_for_resolver
                    .lock()
                    .expect("discovery handle lock poisoned")
                    .as_ref()
                    .cloned()
                    .expect("discovery handle installed before poll");
                let snapshot = (discovery.resolve_count(), discovery.endpoints());
                *observed_for_resolver
                    .lock()
                    .expect("observed snapshot lock poisoned") = Some(snapshot);
                Ok(addrs.clone())
            }),
        ));
        *discovery_handle
            .lock()
            .expect("discovery handle lock poisoned") = Some(Arc::clone(&discovery));

        let (tx, rx) = mpsc::channel();
        let discovery_for_thread = Arc::clone(&discovery);
        let worker = thread::spawn(move || {
            let result = discovery_for_thread.poll_discover();
            tx.send(result)
                .expect("reentrant resolver test channel should be open");
        });

        let result = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("poll_discover should not deadlock when the resolver re-enters discovery");
        worker
            .join()
            .expect("reentrant resolver worker should not panic");

        assert_eq!(
            result.unwrap(),
            vec![Change::Insert("127.0.0.1:80".parse().unwrap())]
        );
        assert_eq!(
            *observed.lock().expect("observed snapshot lock poisoned"),
            Some((0, Vec::new()))
        );
        assert_eq!(discovery.resolve_count(), 1);
        crate::test_complete!("dns_discovery_custom_resolver_can_reenter_without_deadlock");
    }

    #[test]
    fn dns_discovery_stale_concurrent_resolution_cannot_clobber_newer_state() {
        init_test("dns_discovery_stale_concurrent_resolution_cannot_clobber_newer_state");
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let release_first = Arc::new((StdMutex::new(false), Condvar::new()));
        let release_first_for_resolver = Arc::clone(&release_first);
        let call_index = Arc::new(AtomicUsize::new(0));
        let call_index_for_resolver = Arc::clone(&call_index);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    match call_index_for_resolver.fetch_add(1, Ordering::SeqCst) {
                        0 => {
                            first_started_tx
                                .send(())
                                .expect("first-started channel should be open");
                            let (lock, ready) = &*release_first_for_resolver;
                            let mut released = lock.lock().expect("release lock poisoned");
                            while !*released {
                                released = ready.wait(released).expect("release wait poisoned");
                            }
                            drop(released);
                            Ok(socket_set(&["127.0.0.1:80"]))
                        }
                        1 => Ok(socket_set(&["127.0.0.2:80"])),
                        other => panic!("unexpected resolver invocation {other}"),
                    }
                }),
        ));

        let first_discovery = Arc::clone(&discovery);
        let first_worker = thread::spawn(move || first_discovery.poll_discover());
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first resolver call should start");

        let second_discovery = Arc::clone(&discovery);
        let second_result = thread::spawn(move || second_discovery.poll_discover())
            .join()
            .expect("second worker should not panic")
            .expect("second poll should succeed");
        assert_eq!(
            second_result,
            vec![Change::Insert("127.0.0.2:80".parse().unwrap())]
        );

        let (lock, ready) = &*release_first;
        *lock.lock().expect("release lock poisoned") = true;
        ready.notify_all();

        let first_result = first_worker
            .join()
            .expect("first worker should not panic")
            .expect("first poll should not fail");
        assert!(
            first_result.is_empty(),
            "stale completion should not publish changes"
        );
        assert_eq!(discovery.endpoints(), vec!["127.0.0.2:80".parse().unwrap()]);
        assert_eq!(discovery.resolve_count(), 1);
        crate::test_complete!(
            "dns_discovery_stale_concurrent_resolution_cannot_clobber_newer_state"
        );
    }

    #[test]
    fn dns_discovery_stale_concurrent_resolution_still_reports_error_to_caller() {
        init_test("dns_discovery_stale_concurrent_resolution_still_reports_error_to_caller");
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let release_first = Arc::new((StdMutex::new(false), Condvar::new()));
        let release_first_for_resolver = Arc::clone(&release_first);
        let call_index = Arc::new(AtomicUsize::new(0));
        let call_index_for_resolver = Arc::clone(&call_index);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    match call_index_for_resolver.fetch_add(1, Ordering::SeqCst) {
                        0 => {
                            first_started_tx
                                .send(())
                                .expect("first-started channel should be open");
                            let (lock, ready) = &*release_first_for_resolver;
                            let mut released = lock.lock().expect("release lock poisoned");
                            while !*released {
                                released = ready.wait(released).expect("release wait poisoned");
                            }
                            drop(released);
                            Err(std::io::Error::other("stale failure"))
                        }
                        1 => Ok(socket_set(&["127.0.0.2:80"])),
                        other => panic!("unexpected resolver invocation {other}"),
                    }
                }),
        ));

        let first_discovery = Arc::clone(&discovery);
        let first_worker = thread::spawn(move || first_discovery.poll_discover());
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first resolver call should start");

        let second_discovery = Arc::clone(&discovery);
        let second_result = thread::spawn(move || second_discovery.poll_discover())
            .join()
            .expect("second worker should not panic")
            .expect("second poll should succeed");
        assert_eq!(
            second_result,
            vec![Change::Insert("127.0.0.2:80".parse().unwrap())]
        );

        let (lock, ready) = &*release_first;
        *lock.lock().expect("release lock poisoned") = true;
        ready.notify_all();

        let first_result = first_worker.join().expect("first worker should not panic");
        let err = first_result.expect_err("stale failed resolution should still report error");
        assert_eq!(err.to_string(), "DNS resolution failed: stale failure");
        assert_eq!(discovery.endpoints(), vec!["127.0.0.2:80".parse().unwrap()]);
        assert_eq!(discovery.resolve_count(), 1);
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!(
            "dns_discovery_stale_concurrent_resolution_still_reports_error_to_caller"
        );
    }

    #[test]
    fn dns_discovery_older_success_still_applies_after_newer_failure() {
        init_test("dns_discovery_older_success_still_applies_after_newer_failure");
        let (first_started_tx, first_started_rx) = mpsc::channel();
        let release_first = Arc::new((StdMutex::new(false), Condvar::new()));
        let release_first_for_resolver = Arc::clone(&release_first);
        let call_index = Arc::new(AtomicUsize::new(0));
        let call_index_for_resolver = Arc::clone(&call_index);
        let discovery = Arc::new(DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::ZERO)
                .with_resolver(move |_, _| {
                    match call_index_for_resolver.fetch_add(1, Ordering::SeqCst) {
                        0 => {
                            first_started_tx
                                .send(())
                                .expect("first-started channel should be open");
                            let (lock, ready) = &*release_first_for_resolver;
                            let mut released = lock.lock().expect("release lock poisoned");
                            while !*released {
                                released = ready.wait(released).expect("release wait poisoned");
                            }
                            drop(released);
                            Ok(socket_set(&["127.0.0.1:80"]))
                        }
                        1 => Err(std::io::Error::other("newer failure")),
                        other => panic!("unexpected resolver invocation {other}"),
                    }
                }),
        ));

        let first_discovery = Arc::clone(&discovery);
        let first_worker = thread::spawn(move || first_discovery.poll_discover());
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first resolver call should start");

        let second_discovery = Arc::clone(&discovery);
        let second_result = thread::spawn(move || second_discovery.poll_discover())
            .join()
            .expect("second worker should not panic");
        let second_err =
            second_result.expect_err("newer failed resolution should still report error");
        assert_eq!(
            second_err.to_string(),
            "DNS resolution failed: newer failure"
        );

        let (lock, ready) = &*release_first;
        *lock.lock().expect("release lock poisoned") = true;
        ready.notify_all();

        let first_result = first_worker
            .join()
            .expect("first worker should not panic")
            .expect("older success should still apply when newer attempt failed");
        assert_eq!(
            first_result,
            vec![Change::Insert("127.0.0.1:80".parse().unwrap())]
        );
        assert_eq!(discovery.endpoints(), vec!["127.0.0.1:80".parse().unwrap()]);
        assert_eq!(discovery.resolve_count(), 1);
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_older_success_still_applies_after_newer_failure");
    }

    #[test]
    fn dns_changes_are_sorted_and_grouped() {
        let current: HashSet<SocketAddr> = [
            "127.0.0.3:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        ]
        .into_iter()
        .collect();
        let new_addrs: HashSet<SocketAddr> = [
            "127.0.0.2:80".parse().unwrap(),
            "127.0.0.3:80".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        let changes = dns_changes(&current, &new_addrs);

        assert_eq!(
            changes,
            vec![
                Change::Insert("127.0.0.2:80".parse().unwrap()),
                Change::Remove("127.0.0.1:80".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn dns_discovery_endpoints_are_sorted() {
        let discovery = DnsServiceDiscovery::from_host("127.0.0.1", 80);
        discovery.state.lock().current = [
            "127.0.0.3:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
            "127.0.0.2:80".parse().unwrap(),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            discovery.endpoints(),
            vec![
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.2:80".parse().unwrap(),
                "127.0.0.3:80".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn dns_discovery_debug() {
        let discovery = DnsServiceDiscovery::from_host("127.0.0.1", 80);
        let dbg = format!("{discovery:?}");
        assert!(dbg.contains("DnsServiceDiscovery"));
        assert!(dbg.contains("127.0.0.1"));
    }

    #[test]
    fn dns_discovery_resolver_error_propagates() {
        init_test("dns_discovery_resolver_error_propagates");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );
        let result = discovery.poll_discover();
        assert!(result.is_err());
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_resolver_error_propagates");
    }

    #[test]
    fn dns_discovery_failed_resolution_respects_poll_interval() {
        init_test("dns_discovery_failed_resolution_respects_poll_interval");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_mins(5))
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );

        let result = discovery.poll_discover();
        assert!(result.is_err());
        assert_eq!(discovery.error_count(), 1);
        assert!(discovery.state.lock().last_resolve.is_some());

        let second = discovery.poll_discover().unwrap();
        assert!(
            second.is_empty(),
            "retry should be rate-limited by poll_interval"
        );
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_failed_resolution_respects_poll_interval");
    }

    #[test]
    fn dns_discovery_time_getter_respects_poll_interval_without_sleep() {
        init_test("dns_discovery_time_getter_respects_poll_interval_without_sleep");
        set_test_time(0);
        let resolver = scripted_resolver(vec![
            Ok(socket_set(&["127.0.0.1:80"])),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(30))
                .with_time_getter(test_time)
                .with_resolver(resolver),
        );

        let first = discovery.poll_discover().unwrap();
        assert!(!first.is_empty());
        assert_eq!(discovery.resolve_count(), 1);

        set_test_time(Duration::from_secs(10).as_nanos().min(u128::from(u64::MAX)) as u64);
        let second = discovery.poll_discover().unwrap();
        assert!(second.is_empty());
        assert_eq!(discovery.resolve_count(), 1);

        set_test_time(Duration::from_secs(30).as_nanos().min(u128::from(u64::MAX)) as u64);
        let third = discovery.poll_discover().unwrap();
        assert!(third.is_empty());
        assert_eq!(discovery.resolve_count(), 2);
        crate::test_complete!("dns_discovery_time_getter_respects_poll_interval_without_sleep");
    }

    #[test]
    fn dns_discovery_time_getter_controls_failed_resolution_cooldown() {
        init_test("dns_discovery_time_getter_controls_failed_resolution_cooldown");
        set_test_time(0);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(30))
                .with_time_getter(test_time)
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );

        assert!(discovery.poll_discover().is_err());
        assert_eq!(discovery.error_count(), 1);

        set_test_time(Duration::from_secs(10).as_nanos().min(u128::from(u64::MAX)) as u64);
        let second = discovery.poll_discover().unwrap();
        assert!(second.is_empty());
        assert_eq!(discovery.error_count(), 1);

        set_test_time(Duration::from_secs(30).as_nanos().min(u128::from(u64::MAX)) as u64);
        assert!(discovery.poll_discover().is_err());
        assert_eq!(discovery.error_count(), 2);
        crate::test_complete!("dns_discovery_time_getter_controls_failed_resolution_cooldown");
    }

    #[test]
    fn dns_discovery_invalidate_forces_retry_after_failed_resolution() {
        init_test("dns_discovery_invalidate_forces_retry_after_failed_resolution");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_mins(5))
                .with_resolver(|_, _| Err(std::io::Error::other("resolver failed"))),
        );

        let first = discovery.poll_discover();
        assert!(first.is_err());
        assert_eq!(discovery.error_count(), 1);

        discovery.invalidate();

        let second = discovery.poll_discover();
        assert!(second.is_err());
        assert_eq!(discovery.error_count(), 2);
        crate::test_complete!("dns_discovery_invalidate_forces_retry_after_failed_resolution");
    }

    // ================================================================
    // Regression: last_resolve uses decision-time `now`
    // ================================================================

    #[test]
    fn dns_discovery_last_resolve_uses_decision_time_not_post_resolve_time() {
        init_test("dns_discovery_last_resolve_uses_decision_time_not_post_resolve_time");
        // Before the fix, poll_discover() called time_getter() a second time
        // after resolve() returned to set last_resolve. With virtual time that
        // advances between calls, this pushed the cooldown window forward,
        // making the next re-resolution happen later than expected.
        //
        // After the fix, last_resolve is set to the `now` captured at the
        // start of poll_discover(), so the cooldown is anchored to the
        // decision point.
        set_test_time(1_000_000_000); // 1s
        let resolver = scripted_resolver(vec![
            Ok(socket_set(&["127.0.0.1:80"])),
            Ok(socket_set(&["127.0.0.1:80"])),
        ]);
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("service.test", 80)
                .poll_interval(Duration::from_secs(10))
                .with_time_getter(test_time)
                .with_resolver(resolver),
        );

        let first = discovery.poll_discover().unwrap();
        assert!(!first.is_empty());

        // Verify that last_resolve was set to the decision time (1s),
        // not a later time. Advance virtual clock to exactly 1s + 10s = 11s.
        // If last_resolve used the decision time, this should trigger a
        // new resolution (11s - 1s = 10s >= poll_interval).
        set_test_time(11_000_000_000); // 11s
        let second = discovery.poll_discover().unwrap();
        // Should resolve again because 11s - 1s = 10s >= 10s poll_interval
        assert_eq!(
            discovery.resolve_count(),
            2,
            "last_resolve should anchor to decision time, allowing re-resolve at exactly poll_interval"
        );
        // second may be empty (same addresses) but resolution happened
        let _ = second;
        crate::test_complete!(
            "dns_discovery_last_resolve_uses_decision_time_not_post_resolve_time"
        );
    }

    // ================================================================
    // DnsDiscoveryError
    // ================================================================

    #[test]
    fn dns_error_display() {
        let io_err = std::io::Error::other("test");
        let err = DnsDiscoveryError::Resolve(io_err);
        let display = format!("{err}");
        assert!(display.contains("DNS resolution failed"));
    }

    #[test]
    fn dns_error_debug() {
        let io_err = std::io::Error::other("test");
        let err = DnsDiscoveryError::Resolve(io_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Resolve"));
    }

    #[test]
    fn dns_error_source() {
        use std::error::Error;
        let io_err = std::io::Error::other("test");
        let err = DnsDiscoveryError::Resolve(io_err);
        assert!(err.source().is_some());
    }

    // ================================================================
    // StaticList with SocketAddr
    // ================================================================

    #[test]
    fn static_list_socket_addrs() {
        init_test("static_list_socket_addrs");
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
        ];
        let list = StaticList::new(addrs.clone());

        let changes = list.poll_discover().unwrap();
        assert_eq!(changes.len(), 2);

        let endpoints = list.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.contains(&addrs[0]));
        assert!(endpoints.contains(&addrs[1]));
        crate::test_complete!("static_list_socket_addrs");
    }
}
