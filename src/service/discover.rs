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

use std::collections::HashSet;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
        let mut delivered = self.delivered.lock().unwrap();
        if *delivered {
            return Ok(Vec::new());
        }
        *delivered = true;
        drop(delivered);
        Ok(self
            .endpoints
            .iter()
            .map(|e| Change::Insert(e.clone()))
            .collect())
    }

    fn endpoints(&self) -> Vec<K> {
        self.endpoints.clone()
    }
}

impl<K: fmt::Debug> fmt::Debug for StaticList<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticList")
            .field("endpoints", &self.endpoints)
            .field("delivered", &*self.delivered.lock().unwrap())
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
#[derive(Debug, Clone)]
pub struct DnsDiscoveryConfig {
    /// Hostname to resolve (e.g., "api.example.com").
    pub hostname: String,
    /// Port to use for discovered endpoints.
    pub port: u16,
    /// How often to re-resolve the hostname.
    pub poll_interval: Duration,
}

impl DnsDiscoveryConfig {
    /// Create a new DNS discovery configuration.
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Self {
            hostname: hostname.into(),
            port,
            poll_interval: Duration::from_secs(30),
        }
    }

    /// Set the poll interval.
    #[must_use]
    pub fn poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
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
    /// When the last resolution was performed.
    last_resolve: Option<Instant>,
    /// Number of successful resolutions.
    resolve_count: u64,
    /// Number of failed resolutions.
    error_count: u64,
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

    /// Get the number of successful resolutions.
    #[must_use]
    pub fn resolve_count(&self) -> u64 {
        self.state.lock().unwrap().resolve_count
    }

    /// Get the number of failed resolutions.
    #[must_use]
    pub fn error_count(&self) -> u64 {
        self.state.lock().unwrap().error_count
    }

    /// Force a re-resolution on the next poll.
    pub fn invalidate(&self) {
        self.state.lock().unwrap().last_resolve = None;
    }

    /// Perform DNS resolution synchronously.
    fn resolve(&self) -> Result<HashSet<SocketAddr>, std::io::Error> {
        let host_port = format!("{}:{}", self.config.hostname, self.config.port);
        let addrs: HashSet<SocketAddr> = host_port.to_socket_addrs()?.collect();
        Ok(addrs)
    }

    /// Check if a re-resolution is needed based on the poll interval.
    fn needs_resolve(&self, state: &DnsDiscoveryState) -> bool {
        state
            .last_resolve
            .is_none_or(|last| last.elapsed() >= self.config.poll_interval)
    }
}

impl Discover for DnsServiceDiscovery {
    type Key = SocketAddr;
    type Error = DnsDiscoveryError;

    fn poll_discover(&self) -> Result<Vec<Change<SocketAddr>>, DnsDiscoveryError> {
        let mut state = self.state.lock().unwrap();

        if !self.needs_resolve(&state) {
            return Ok(Vec::new());
        }

        // Perform resolution.
        let new_addrs = match self.resolve() {
            Ok(addrs) => {
                state.resolve_count += 1;
                state.last_resolve = Some(Instant::now());
                addrs
            }
            Err(e) => {
                state.error_count += 1;
                return Err(DnsDiscoveryError::Resolve(e));
            }
        };

        // Compute diff.
        let mut changes = Vec::new();

        // New endpoints.
        for addr in &new_addrs {
            if !state.current.contains(addr) {
                changes.push(Change::Insert(*addr));
            }
        }

        // Removed endpoints.
        for addr in &state.current {
            if !new_addrs.contains(addr) {
                changes.push(Change::Remove(*addr));
            }
        }

        state.current = new_addrs;
        drop(state);
        Ok(changes)
    }

    fn endpoints(&self) -> Vec<SocketAddr> {
        self.state.lock().unwrap().current.iter().copied().collect()
    }
}

impl fmt::Debug for DnsServiceDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap();
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

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
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
            DnsDiscoveryConfig::new("example.com", 80).poll_interval(Duration::from_secs(60));
        assert_eq!(config.poll_interval, Duration::from_secs(60));
    }

    #[test]
    fn dns_config_debug_clone() {
        let config = DnsDiscoveryConfig::new("host", 443);
        let dbg = format!("{config:?}");
        assert!(dbg.contains("DnsDiscoveryConfig"));
        let cloned = config.clone();
        assert_eq!(cloned.hostname, "host");
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
    fn dns_discovery_resolves_localhost() {
        init_test("dns_discovery_resolves_localhost");
        let discovery = DnsServiceDiscovery::from_host("localhost", 8080);

        let changes = discovery.poll_discover().unwrap();
        // localhost should resolve to at least one address.
        assert!(!changes.is_empty());
        assert!(changes.iter().all(|c| matches!(c, Change::Insert(_))));
        assert_eq!(discovery.resolve_count(), 1);

        // All endpoints should have port 8080.
        for change in &changes {
            if let Change::Insert(addr) = change {
                assert_eq!(addr.port(), 8080);
            }
        }
        crate::test_complete!("dns_discovery_resolves_localhost");
    }

    #[test]
    fn dns_discovery_no_change_within_interval() {
        init_test("dns_discovery_no_change_within_interval");
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("localhost", 80).poll_interval(Duration::from_secs(300)),
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
        let discovery = DnsServiceDiscovery::new(
            DnsDiscoveryConfig::new("localhost", 80).poll_interval(Duration::from_secs(300)),
        );

        let _ = discovery.poll_discover().unwrap();
        assert_eq!(discovery.resolve_count(), 1);

        discovery.invalidate();
        let _ = discovery.poll_discover().unwrap();
        assert_eq!(discovery.resolve_count(), 2);
        crate::test_complete!("dns_discovery_invalidate_forces_resolve");
    }

    #[test]
    fn dns_discovery_endpoints() {
        init_test("dns_discovery_endpoints");
        let discovery = DnsServiceDiscovery::from_host("localhost", 80);
        assert!(discovery.endpoints().is_empty());
        let _ = discovery.poll_discover().unwrap();
        assert!(!discovery.endpoints().is_empty());
        crate::test_complete!("dns_discovery_endpoints");
    }

    #[test]
    fn dns_discovery_debug() {
        let discovery = DnsServiceDiscovery::from_host("localhost", 80);
        let dbg = format!("{discovery:?}");
        assert!(dbg.contains("DnsServiceDiscovery"));
        assert!(dbg.contains("localhost"));
    }

    #[test]
    fn dns_discovery_invalid_hostname() {
        init_test("dns_discovery_invalid_hostname");
        let discovery =
            DnsServiceDiscovery::from_host("this.hostname.definitely.does.not.exist.invalid", 80);
        let result = discovery.poll_discover();
        assert!(result.is_err());
        assert_eq!(discovery.error_count(), 1);
        crate::test_complete!("dns_discovery_invalid_hostname");
    }

    // ================================================================
    // DnsDiscoveryError
    // ================================================================

    #[test]
    fn dns_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err = DnsDiscoveryError::Resolve(io_err);
        let display = format!("{err}");
        assert!(display.contains("DNS resolution failed"));
    }

    #[test]
    fn dns_error_debug() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let err = DnsDiscoveryError::Resolve(io_err);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Resolve"));
    }

    #[test]
    fn dns_error_source() {
        use std::error::Error;
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
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
