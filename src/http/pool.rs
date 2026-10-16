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

    /// Marks the connection as connected only if it is still connecting.
    ///
    /// Returns true when the transition was applied.
    #[must_use]
    pub fn mark_connected(&mut self, now: Time) -> bool {
        if self.state == PooledConnectionState::Connecting {
            self.mark_idle(now);
            true
        } else {
            false
        }
    }

    /// Marks the connection as in use.
    pub fn mark_in_use(&mut self) {
        self.state = PooledConnectionState::InUse;
        self.requests_served += 1;
    }

    /// Returns the connection to idle only if it is currently checked out.
    ///
    /// Returns true when the transition was applied.
    #[must_use]
    pub fn release(&mut self, now: Time) -> bool {
        if self.state == PooledConnectionState::InUse {
            self.mark_idle(now);
            true
        } else {
            false
        }
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
#[derive(Debug, Default)]
struct HostPool {
    /// Connections for this host (by connection ID).
    connections: HashMap<u64, PooledConnectionMeta>,
}

impl HostPool {
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

        // HashMap iteration order is randomized, so explicitly choose the
        // lowest viable connection ID to keep reuse deterministic.
        let idle_id = host_pool
            .connections
            .iter()
            .filter(|(_, conn)| {
                conn.state == PooledConnectionState::Idle
                    && !conn.is_expired(now, self.config.idle_timeout)
            })
            .map(|(id, _)| *id)
            .min();

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
    pub fn can_create_connection(&self, key: &PoolKey, now: Time) -> bool {
        let idle_timeout = self.config.idle_timeout;

        // Check total connection limit, ignoring expired idle connections
        let total = self
            .hosts
            .values()
            .map(|host_pool| {
                host_pool
                    .connections
                    .values()
                    .filter(|conn| !conn.is_expired(now, idle_timeout))
                    .count()
            })
            .sum::<usize>();

        if total >= self.config.max_total_connections {
            return false;
        }

        // Check per-host limit, ignoring expired idle connections
        if let Some(host_pool) = self.hosts.get(key) {
            let host_total = host_pool
                .connections
                .values()
                .filter(|conn| !conn.is_expired(now, idle_timeout))
                .count();

            if host_total >= self.config.max_connections_per_host {
                return false;
            }
        }

        true
    }

    /// Removes every idle connection to `key` and returns their ids, so the
    /// caller can close their sockets.
    pub(crate) fn remove_idle(&mut self, key: &PoolKey) -> Vec<u64> {
        let Some(host_pool) = self.hosts.get(key) else {
            return Vec::new();
        };
        let ids: Vec<u64> = host_pool
            .connections
            .values()
            .filter(|conn| conn.state == PooledConnectionState::Idle)
            .map(|conn| conn.id)
            .collect();
        for &id in &ids {
            self.remove(key, id);
        }
        ids
    }

    /// Makes room for a new connection to `key` when connections to other
    /// hosts fill `max_total_connections`.
    ///
    /// Removes the least recently used idle connection of another host and
    /// returns it so the caller can close its socket. Returns `None` when no
    /// eviction is needed or none would help: the total limit is not reached,
    /// `key` is at its own per-host limit, or no other host has an idle
    /// connection. Without this, idle connections to hosts contacted once
    /// refused every new host until they expired.
    pub(crate) fn evict_idle_for(&mut self, key: &PoolKey, now: Time) -> Option<(PoolKey, u64)> {
        let idle_timeout = self.config.idle_timeout;
        let live = |conn: &PooledConnectionMeta| !conn.is_expired(now, idle_timeout);
        let total = self
            .hosts
            .values()
            .map(|host_pool| host_pool.connections.values().filter(|c| live(c)).count())
            .sum::<usize>();
        if total < self.config.max_total_connections {
            return None;
        }
        if self.hosts.get(key).is_some_and(|host_pool| {
            host_pool.connections.values().filter(|c| live(c)).count()
                >= self.config.max_connections_per_host
        }) {
            return None;
        }
        let (victim_key, victim_id) = self
            .hosts
            .iter()
            .filter(|(host_key, _)| *host_key != key)
            .flat_map(|(host_key, host_pool)| {
                host_pool
                    .connections
                    .values()
                    .filter(|conn| conn.state == PooledConnectionState::Idle && live(conn))
                    .map(move |conn| (conn.last_used, conn.id, host_key))
            })
            .min_by_key(|(last_used, id, _)| (*last_used, *id))
            .map(|(_, id, host_key)| (host_key.clone(), id))?;
        self.remove(&victim_key, victim_id);
        Some((victim_key, victim_id))
    }

    fn maybe_cleanup(&mut self, now: Time) {
        let elapsed = now.as_nanos().saturating_sub(self.last_cleanup.as_nanos());
        let interval_nanos =
            u64::try_from(self.config.cleanup_interval.as_nanos()).unwrap_or(u64::MAX);
        if elapsed >= interval_nanos {
            self.cleanup_expired(now);
            self.last_cleanup = now;
        }
    }

    /// Registers a new connection being established.
    ///
    /// Returns the connection ID for tracking.
    pub fn register_connecting(&mut self, key: PoolKey, now: Time, http_version: u8) -> u64 {
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("http connection pool id counter exhausted");

        let meta = PooledConnectionMeta::new(id, now, http_version);

        let host_pool = self.hosts.entry(key).or_default();
        host_pool.connections.insert(id, meta);

        self.stats.connections_created += 1;

        id
    }

    /// Marks a connection as successfully established and idle.
    ///
    /// Returns true when the transition was applied.
    pub fn mark_connected(&mut self, key: &PoolKey, id: u64, now: Time) -> bool {
        if let Some(host_pool) = self.hosts.get_mut(key) {
            if let Some(conn) = host_pool.connections.get_mut(&id) {
                return conn.mark_connected(now);
            }
        }
        false
    }

    /// Returns a connection to the pool (makes it idle).
    ///
    /// Returns true when the transition was applied.
    pub fn release(&mut self, key: &PoolKey, id: u64, now: Time) -> bool {
        if let Some(host_pool) = self.hosts.get_mut(key) {
            if let Some(conn) = host_pool.connections.get_mut(&id) {
                return conn.release(now);
            }
        }
        false
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

    /// Removes expired idle connections and returns the retired `(key, id)` pairs.
    pub fn cleanup_expired_entries(&mut self, now: Time) -> Vec<(PoolKey, u64)> {
        let idle_timeout = self.config.idle_timeout;
        let mut removed = Vec::new();
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
                removed.push((key.clone(), id));
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

    /// Cleans up expired idle connections.
    ///
    /// Returns the number of connections removed.
    pub fn cleanup_expired(&mut self, now: Time) -> usize {
        self.cleanup_expired_entries(now).len()
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
#[path = "pool_inline_tests.rs"]
mod tests;
