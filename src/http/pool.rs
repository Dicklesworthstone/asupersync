//! HTTP connection pooling.
//!
//! Provides connection pool management for HTTP clients, enabling connection
//! reuse and efficient handling of concurrent requests to the same hosts.
//!
//! # Connection Reuse
//!
//! The pool maintains idle connections that can be reused for subsequent
//! requests to the same host, reducing connection establishment overhead.
//!
//! # Pool Configuration
//!
//! The pool can be configured with:
//! - Maximum connections per host
//! - Maximum total connections
//! - Idle connection timeout
//! - Connection health checks

use smallvec::SmallVec;
use std::collections::HashMap;
use std::time::Duration;

use crate::types::Time;

/// Connection pool key identifying a specific host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PoolKey {
    /// Host name or IP address.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// Whether this is an HTTPS connection.
    pub is_https: bool,
}

impl PoolKey {
    /// Creates a new pool key.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, is_https: bool) -> Self {
        Self {
            host: host.into(),
            port,
            is_https,
        }
    }

    /// Creates a pool key for HTTP (port 80 default).
    #[must_use]
    pub fn http(host: impl Into<String>, port: Option<u16>) -> Self {
        Self::new(host, port.unwrap_or(80), false)
    }

    /// Creates a pool key for HTTPS (port 443 default).
    #[must_use]
    pub fn https(host: impl Into<String>, port: Option<u16>) -> Self {
        Self::new(host, port.unwrap_or(443), true)
    }
}

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum connections per host.
    pub max_connections_per_host: usize,
    /// Maximum total connections across all hosts.
    pub max_total_connections: usize,
    /// How long an idle connection is kept before eviction.
    pub idle_timeout: Duration,
    /// How often to run the idle connection cleanup.
    pub cleanup_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 6,
            max_total_connections: 100,
            idle_timeout: Duration::from_secs(90),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

impl PoolConfig {
    /// Creates a new pool configuration builder.
    #[must_use]
    pub fn builder() -> PoolConfigBuilder {
        PoolConfigBuilder::default()
    }
}

/// Builder for [`PoolConfig`].
#[derive(Debug, Default)]
pub struct PoolConfigBuilder {
    max_connections_per_host: Option<usize>,
    max_total_connections: Option<usize>,
    idle_timeout: Option<Duration>,
    cleanup_interval: Option<Duration>,
}

impl PoolConfigBuilder {
    /// Sets the maximum connections per host.
    #[must_use]
    pub fn max_connections_per_host(mut self, max: usize) -> Self {
        self.max_connections_per_host = Some(max);
        self
    }

    /// Sets the maximum total connections.
    #[must_use]
    pub fn max_total_connections(mut self, max: usize) -> Self {
        self.max_total_connections = Some(max);
        self
    }

    /// Sets the idle connection timeout.
    #[must_use]
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = Some(timeout);
        self
    }

    /// Sets the cleanup interval.
    #[must_use]
    pub fn cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = Some(interval);
        self
    }

    /// Builds the configuration.
    #[must_use]
    pub fn build(self) -> PoolConfig {
        let defaults = PoolConfig::default();
        PoolConfig {
            max_connections_per_host: self
                .max_connections_per_host
                .unwrap_or(defaults.max_connections_per_host),
            max_total_connections: self
                .max_total_connections
                .unwrap_or(defaults.max_total_connections),
            idle_timeout: self.idle_timeout.unwrap_or(defaults.idle_timeout),
            cleanup_interval: self.cleanup_interval.unwrap_or(defaults.cleanup_interval),
        }
    }
}

/// Connection state in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PooledConnectionState {
    /// Connection is idle and available for reuse.
    Idle,
    /// Connection is currently in use.
    InUse,
    /// Connection is being established.
    Connecting,
    /// Connection has been marked as unhealthy.
    Unhealthy,
}

/// Metadata for a pooled connection.
#[derive(Debug)]
pub struct PooledConnectionMeta {
    /// Unique identifier for this connection.
    pub id: u64,
    /// Connection state.
    pub state: PooledConnectionState,
    /// When the connection was created.
    pub created_at: Time,
    /// When the connection was last used.
    pub last_used: Time,
    /// Number of requests served by this connection.
    pub requests_served: u64,
    /// HTTP version (1 for HTTP/1.x, 2 for HTTP/2).
    pub http_version: u8,
}

impl PooledConnectionMeta {
    /// Creates new connection metadata.
    #[must_use]
    pub fn new(id: u64, now: Time, http_version: u8) -> Self {
        Self {
            id,
            state: PooledConnectionState::Connecting,
            created_at: now,
            last_used: now,
            requests_served: 0,
            http_version,
        }
    }

    /// Marks the connection as idle.
    pub fn mark_idle(&mut self, now: Time) {
        self.state = PooledConnectionState::Idle;
        self.last_used = now;
    }

    /// Marks the connection as in use.
    pub fn mark_in_use(&mut self) {
        self.state = PooledConnectionState::InUse;
        self.requests_served += 1;
    }

    /// Marks the connection as unhealthy.
    pub fn mark_unhealthy(&mut self) {
        self.state = PooledConnectionState::Unhealthy;
    }

    /// Returns true if this connection has been idle longer than the timeout.
    #[must_use]
    pub fn is_expired(&self, now: Time, idle_timeout: Duration) -> bool {
        if self.state != PooledConnectionState::Idle {
            return false;
        }
        let elapsed_nanos = now.duration_since(self.last_used);
        elapsed_nanos >= u64::try_from(idle_timeout.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Statistics for a connection pool.
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    /// Total number of connections currently in the pool.
    pub total_connections: usize,
    /// Number of idle connections.
    pub idle_connections: usize,
    /// Number of connections in use.
    pub in_use_connections: usize,
    /// Number of connections being established.
    pub connecting: usize,
    /// Number of hosts with connections.
    pub hosts_count: usize,
    /// Total connections created over the pool's lifetime.
    pub connections_created: u64,
    /// Total connections closed over the pool's lifetime.
    pub connections_closed: u64,
    /// Total connections that timed out.
    pub connections_timed_out: u64,
}

/// Tracks connections for a single host.
#[derive(Debug)]
struct HostPool {
    /// Connections for this host (by connection ID).
    connections: HashMap<u64, PooledConnectionMeta>,
}

impl HostPool {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    fn connection_count(&self) -> usize {
        self.connections.len()
    }

    fn idle_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == PooledConnectionState::Idle)
            .count()
    }

    fn in_use_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == PooledConnectionState::InUse)
            .count()
    }

    fn connecting_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == PooledConnectionState::Connecting)
            .count()
    }
}

/// HTTP connection pool.
///
/// Manages a pool of connections to different hosts, enabling connection
/// reuse for improved performance.
#[derive(Debug)]
pub struct Pool {
    /// Pool configuration.
    config: PoolConfig,
    /// Connections organized by host.
    hosts: HashMap<PoolKey, HostPool>,
    /// Next connection ID.
    next_id: u64,
    /// Lifetime statistics.
    stats: PoolStats,
    /// Last time cleanup was run.
    last_cleanup: Time,
}

impl Pool {
    /// Creates a new connection pool with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PoolConfig::default())
    }

    /// Creates a new connection pool with the given configuration.
    #[must_use]
    pub fn with_config(config: PoolConfig) -> Self {
        Self {
            config,
            hosts: HashMap::new(),
            next_id: 1,
            stats: PoolStats::default(),
            last_cleanup: Time::ZERO,
        }
    }

    /// Returns the pool configuration.
    #[must_use]
    pub fn config(&self) -> &PoolConfig {
        &self.config
    }

    /// Returns current pool statistics.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        let mut stats = self.stats.clone();
        stats.hosts_count = self.hosts.len();
        stats.total_connections = 0;
        stats.idle_connections = 0;
        stats.in_use_connections = 0;
        stats.connecting = 0;

        for host_pool in self.hosts.values() {
            stats.total_connections += host_pool.connection_count();
            stats.idle_connections += host_pool.idle_count();
            stats.in_use_connections += host_pool.in_use_count();
            stats.connecting += host_pool.connecting_count();
        }

        stats
    }

    /// Attempts to acquire an idle connection for the given key.
    ///
    /// Returns the connection ID if an idle connection is available.
    pub fn try_acquire(&mut self, key: &PoolKey, now: Time) -> Option<u64> {
        self.maybe_cleanup(now);
        let host_pool = self.hosts.get_mut(key)?;

        // Find an idle connection that's not expired
        let idle_id = host_pool
            .connections
            .iter()
            .find(|(_, conn)| {
                conn.state == PooledConnectionState::Idle
                    && !conn.is_expired(now, self.config.idle_timeout)
            })
            .map(|(id, _)| *id);

        if let Some(id) = idle_id {
            if let Some(conn) = host_pool.connections.get_mut(&id) {
                conn.mark_in_use();
                return Some(id);
            }
        }

        None
    }

    /// Checks if a new connection can be created for the given key.
    ///
    /// This also evicts expired idle connections using the provided timestamp
    /// so stale entries do not block new connections.
    #[must_use]
    pub fn can_create_connection(&mut self, key: &PoolKey, now: Time) -> bool {
        // Capacity checks must ignore expired idle sockets immediately, not only
        // on periodic cleanup ticks.
        self.cleanup_expired(now);
        self.last_cleanup = now;
        // Check total connection limit
        let total = self
            .hosts
            .values()
            .map(HostPool::connection_count)
            .sum::<usize>();
        if total >= self.config.max_total_connections {
            return false;
        }

        // Check per-host limit
        if let Some(host_pool) = self.hosts.get(key) {
            if host_pool.connection_count() >= self.config.max_connections_per_host {
                return false;
            }
        }

        true
    }

    fn maybe_cleanup(&mut self, now: Time) {
        let elapsed = now.as_nanos().saturating_sub(self.last_cleanup.as_nanos());
        if elapsed >= self.config.cleanup_interval.as_nanos() as u64 {
            self.cleanup_expired(now);
            self.last_cleanup = now;
        }
    }

    /// Registers a new connection being established.
    ///
    /// Returns the connection ID for tracking.
    pub fn register_connecting(&mut self, key: PoolKey, now: Time, http_version: u8) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let meta = PooledConnectionMeta::new(id, now, http_version);

        let host_pool = self.hosts.entry(key).or_insert_with(HostPool::new);
        host_pool.connections.insert(id, meta);

        self.stats.connections_created += 1;

        id
    }

    /// Marks a connection as successfully established and idle.
    pub fn mark_connected(&mut self, key: &PoolKey, id: u64, now: Time) {
        if let Some(host_pool) = self.hosts.get_mut(key) {
            if let Some(conn) = host_pool.connections.get_mut(&id) {
                conn.mark_idle(now);
            }
        }
    }

    /// Returns a connection to the pool (makes it idle).
    pub fn release(&mut self, key: &PoolKey, id: u64, now: Time) {
        if let Some(host_pool) = self.hosts.get_mut(key) {
            if let Some(conn) = host_pool.connections.get_mut(&id) {
                conn.mark_idle(now);
            }
        }
    }

    /// Removes a connection from the pool.
    pub fn remove(&mut self, key: &PoolKey, id: u64) {
        if let Some(host_pool) = self.hosts.get_mut(key) {
            if host_pool.connections.remove(&id).is_some() {
                self.stats.connections_closed += 1;
            }

            // Clean up empty host pools
            if host_pool.connections.is_empty() {
                self.hosts.remove(key);
            }
        }
    }

    /// Cleans up expired idle connections.
    ///
    /// Returns the number of connections removed.
    pub fn cleanup_expired(&mut self, now: Time) -> usize {
        let idle_timeout = self.config.idle_timeout;
        let mut removed = 0;
        let mut empty_keys: SmallVec<[PoolKey; 4]> = SmallVec::new();

        for (key, host_pool) in &mut self.hosts {
            let expired_ids: SmallVec<[u64; 8]> = host_pool
                .connections
                .iter()
                .filter(|(_, conn)| conn.is_expired(now, idle_timeout))
                .map(|(id, _)| *id)
                .collect();

            for id in expired_ids {
                host_pool.connections.remove(&id);
                self.stats.connections_closed += 1;
                self.stats.connections_timed_out += 1;
                removed += 1;
            }

            if host_pool.connections.is_empty() {
                empty_keys.push(key.clone());
            }
        }

        for key in empty_keys {
            self.hosts.remove(&key);
        }

        removed
    }

    /// Gets metadata for a specific connection.
    #[must_use]
    pub fn get_connection_meta(&self, key: &PoolKey, id: u64) -> Option<&PooledConnectionMeta> {
        self.hosts.get(key)?.connections.get(&id)
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_time(ms: u64) -> Time {
        Time::from_millis(ms)
    }

    #[test]
    fn pool_key_creation() {
        let key = PoolKey::new("example.com", 8080, true);
        assert_eq!(key.host, "example.com");
        assert_eq!(key.port, 8080);
        assert!(key.is_https);

        let plain_key = PoolKey::http("example.com", None);
        assert_eq!(plain_key.port, 80);
        assert!(!plain_key.is_https);

        let tls_key = PoolKey::https("example.com", None);
        assert_eq!(tls_key.port, 443);
        assert!(tls_key.is_https);
    }

    #[test]
    fn pool_config_builder() {
        let config = PoolConfig::builder()
            .max_connections_per_host(10)
            .max_total_connections(200)
            .idle_timeout(Duration::from_mins(1))
            .build();

        assert_eq!(config.max_connections_per_host, 10);
        assert_eq!(config.max_total_connections, 200);
        assert_eq!(config.idle_timeout, Duration::from_mins(1));
    }

    #[test]
    fn pool_register_and_acquire() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let now = make_time(1000);

        // Register a connecting connection
        let id = pool.register_connecting(key.clone(), now, 2);
        assert_eq!(id, 1);

        // Can't acquire while connecting
        assert!(pool.try_acquire(&key, now).is_none());

        // Mark as connected
        pool.mark_connected(&key, id, now);

        // Now we can acquire it
        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id));

        // Can't acquire again (it's in use)
        assert!(pool.try_acquire(&key, now).is_none());

        // Release it
        pool.release(&key, id, now);

        // Can acquire again
        let acquired = pool.try_acquire(&key, now);
        assert_eq!(acquired, Some(id));
    }

    #[test]
    fn pool_connection_limits() {
        let config = PoolConfig::builder()
            .max_connections_per_host(2)
            .max_total_connections(5)
            .build();
        let mut pool = Pool::with_config(config);
        let now = make_time(1000);

        let key1 = PoolKey::https("host1.com", None);
        let key2 = PoolKey::https("host2.com", None);

        // Can create connections up to per-host limit
        assert!(pool.can_create_connection(&key1, now));
        pool.register_connecting(key1.clone(), now, 2);
        assert!(pool.can_create_connection(&key1, now));
        pool.register_connecting(key1.clone(), now, 2);
        assert!(!pool.can_create_connection(&key1, now)); // At limit for host1

        // Can still create for different host
        assert!(pool.can_create_connection(&key2, now));
        pool.register_connecting(key2.clone(), now, 2);
        pool.register_connecting(key2.clone(), now, 2);

        // One more overall
        pool.register_connecting(key2, now, 2);

        // Now at total limit
        let key3 = PoolKey::https("host3.com", None);
        assert!(!pool.can_create_connection(&key3, now));
    }

    #[test]
    fn pool_cleanup_expired() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        // Create a connection at time 0
        let id = pool.register_connecting(key.clone(), make_time(0), 2);
        pool.mark_connected(&key, id, make_time(0));

        // Not expired at time 50
        let removed = pool.cleanup_expired(make_time(50));
        assert_eq!(removed, 0);
        assert!(pool.get_connection_meta(&key, id).is_some());

        // Expired at time 150
        let removed = pool.cleanup_expired(make_time(150));
        assert_eq!(removed, 1);
        assert!(pool.get_connection_meta(&key, id).is_none());
    }

    #[test]
    fn pool_can_create_connection_ignores_expired_idle() {
        let config = PoolConfig::builder()
            .max_connections_per_host(1)
            .max_total_connections(1)
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        let id = pool.register_connecting(key.clone(), make_time(0), 2);
        pool.mark_connected(&key, id, make_time(0));

        assert!(
            pool.can_create_connection(&key, make_time(150)),
            "expired idle connection should not block creation"
        );
    }

    #[test]
    fn pool_stats() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        let now = make_time(1000);

        let id1 = pool.register_connecting(key.clone(), now, 2);
        let id2 = pool.register_connecting(key.clone(), now, 2);

        let stats = pool.stats();
        assert_eq!(stats.total_connections, 2);
        assert_eq!(stats.connecting, 2);
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.connections_created, 2);

        pool.mark_connected(&key, id1, now);
        pool.mark_connected(&key, id2, now);

        let stats = pool.stats();
        assert_eq!(stats.idle_connections, 2);
        assert_eq!(stats.connecting, 0);

        pool.try_acquire(&key, now);

        let stats = pool.stats();
        assert_eq!(stats.idle_connections, 1);
        assert_eq!(stats.in_use_connections, 1);
    }

    #[test]
    fn connection_meta_expiry() {
        let mut meta = PooledConnectionMeta::new(1, make_time(0), 2);
        let timeout = Duration::from_millis(100);

        // Not expired while connecting
        assert!(!meta.is_expired(make_time(200), timeout));

        // Mark idle
        meta.mark_idle(make_time(100));

        // Not expired yet
        assert!(!meta.is_expired(make_time(150), timeout));

        // Expired after timeout
        assert!(meta.is_expired(make_time(250), timeout));
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        // Removing from empty pool should not panic
        pool.remove(&key, 999);
        assert_eq!(pool.stats().connections_closed, 0);
    }

    #[test]
    fn release_nonexistent_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        // Releasing a nonexistent connection should not panic
        pool.release(&key, 999, make_time(0));
    }

    #[test]
    fn mark_connected_nonexistent_is_noop() {
        let mut pool = Pool::new();
        let key = PoolKey::https("example.com", None);
        pool.mark_connected(&key, 999, make_time(0));
    }

    #[test]
    fn pool_default_config() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 6);
        assert_eq!(config.max_total_connections, 100);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn acquire_prefers_idle_over_expired() {
        let config = PoolConfig::builder()
            .idle_timeout(Duration::from_millis(100))
            .build();
        let mut pool = Pool::with_config(config);
        let key = PoolKey::https("example.com", None);

        // Create two connections at time 0
        let id1 = pool.register_connecting(key.clone(), make_time(0), 2);
        pool.mark_connected(&key, id1, make_time(0));
        let id2 = pool.register_connecting(key.clone(), make_time(50), 2);
        pool.mark_connected(&key, id2, make_time(50));

        // At time 120: id1 is expired (idle 120ms), id2 is not (idle 70ms)
        let acquired = pool.try_acquire(&key, make_time(120));
        assert_eq!(acquired, Some(id2));
    }
}
