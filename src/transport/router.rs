//! Symbol routing and dispatch infrastructure.
//!
//! This module provides the routing layer for symbol transmission:
//! - `RoutingTable`: Maps ObjectId/RegionId to endpoints
//! - `SymbolRouter`: Resolves destinations for symbols
//! - `SymbolDispatcher`: Sends symbols to resolved destinations
//! - Load balancing strategies: round-robin, weighted, least-connections

use crate::cx::Cx;
use crate::error::{Error, ErrorKind};
use crate::security::authenticated::AuthenticatedSymbol;
use crate::sync::Mutex;
use crate::sync::OwnedMutexGuard;
use crate::transport::sink::{SymbolSink, SymbolSinkExt};
use crate::types::symbol::{ObjectId, Symbol};
use crate::types::{RegionId, Time};
use parking_lot::RwLock;
use smallvec::{smallvec, SmallVec};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

type EndpointSinkMap = HashMap<EndpointId, Arc<Mutex<Box<dyn SymbolSink>>>>;

// ============================================================================
// Endpoint Types
// ============================================================================

/// Unique identifier for an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EndpointId(pub u64);

impl EndpointId {
    /// Creates a new endpoint ID.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for EndpointId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Endpoint({})", self.0)
    }
}

/// State of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EndpointState {
    /// Endpoint is healthy and available.
    Healthy,

    /// Endpoint is degraded (experiencing issues but still usable).
    Degraded,

    /// Endpoint is unhealthy (should not receive traffic).
    Unhealthy,

    /// Endpoint is draining (finishing existing work, no new traffic).
    Draining,

    /// Endpoint has been removed.
    Removed,
}

impl EndpointState {
    const fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(value: u8) -> Self {
        match value {
            x if x == Self::Healthy as u8 => Self::Healthy,
            x if x == Self::Degraded as u8 => Self::Degraded,
            x if x == Self::Unhealthy as u8 => Self::Unhealthy,
            x if x == Self::Draining as u8 => Self::Draining,
            _ => Self::Removed,
        }
    }

    /// Returns true if the endpoint can receive new traffic.
    #[must_use]
    pub const fn can_receive(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    /// Returns true if the endpoint is available at all.
    #[must_use]
    pub const fn is_available(&self) -> bool {
        !matches!(self, Self::Removed)
    }
}

/// An endpoint that can receive symbols.
#[derive(Debug)]
pub struct Endpoint {
    /// Unique identifier.
    pub id: EndpointId,

    /// Address (e.g., "192.168.1.1:8080" or "node-1").
    pub address: String,

    /// Current state.
    state: AtomicU8,

    /// Weight for weighted load balancing (higher = more traffic).
    pub weight: u32,

    /// Region this endpoint belongs to.
    pub region: Option<RegionId>,

    /// Number of active connections/operations.
    pub active_connections: AtomicU32,

    /// Total symbols sent to this endpoint.
    pub symbols_sent: AtomicU64,

    /// Total failures for this endpoint.
    pub failures: AtomicU64,

    /// Last successful operation time (nanoseconds; 0 = None).
    pub last_success: AtomicU64,

    /// Last failure time (nanoseconds; 0 = None).
    pub last_failure: AtomicU64,

    /// Custom metadata.
    pub metadata: HashMap<String, String>,
}

impl Endpoint {
    /// Creates a new endpoint.
    pub fn new(id: EndpointId, address: impl Into<String>) -> Self {
        Self {
            id,
            address: address.into(),
            state: AtomicU8::new(EndpointState::Healthy.as_u8()),
            weight: 100,
            region: None,
            active_connections: AtomicU32::new(0),
            symbols_sent: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            last_success: AtomicU64::new(0),
            last_failure: AtomicU64::new(0),
            metadata: HashMap::new(),
        }
    }

    /// Sets the endpoint weight.
    #[must_use]
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Sets the endpoint region.
    #[must_use]
    pub fn with_region(mut self, region: RegionId) -> Self {
        self.region = Some(region);
        self
    }

    /// Sets the endpoint state.
    #[must_use]
    pub fn with_state(self, state: EndpointState) -> Self {
        self.state.store(state.as_u8(), Ordering::Relaxed);
        self
    }

    /// Returns the current endpoint state.
    #[must_use]
    pub fn state(&self) -> EndpointState {
        EndpointState::from_u8(self.state.load(Ordering::Relaxed))
    }

    /// Updates the endpoint state.
    pub fn set_state(&self, state: EndpointState) {
        self.state.store(state.as_u8(), Ordering::Relaxed);
    }

    /// Records a successful operation.
    pub fn record_success(&self, now: Time) {
        self.symbols_sent.fetch_add(1, Ordering::Relaxed);
        self.last_success.store(now.as_nanos(), Ordering::Relaxed);
    }

    /// Records a failure.
    pub fn record_failure(&self, now: Time) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(now.as_nanos(), Ordering::Relaxed);
    }

    /// Acquires a connection slot.
    pub fn acquire_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Releases a connection slot.
    pub fn release_connection(&self) {
        let _ =
            self.active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(1))
                });
    }

    /// Returns the current connection count.
    #[must_use]
    pub fn connection_count(&self) -> u32 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Returns the failure rate (failures / total operations).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn failure_rate(&self) -> f64 {
        let sent = self.symbols_sent.load(Ordering::Relaxed);
        let failures = self.failures.load(Ordering::Relaxed);
        let total = sent + failures;
        if total == 0 {
            0.0
        } else {
            failures as f64 / total as f64
        }
    }

    /// Acquires a connection slot and returns a RAII guard.
    ///
    /// The connection slot is automatically released when the guard is dropped.
    pub fn acquire_connection_guard(&self) -> ConnectionGuard<'_> {
        self.acquire_connection();
        ConnectionGuard { endpoint: self }
    }
}

/// RAII guard for an active connection slot.
pub struct ConnectionGuard<'a> {
    endpoint: &'a Endpoint,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.endpoint.release_connection();
    }
}

// ============================================================================
// Load Balancing
// ============================================================================

/// Load balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalanceStrategy {
    /// Simple round-robin across all healthy endpoints.
    #[default]
    RoundRobin,

    /// Weighted round-robin based on endpoint weights.
    WeightedRoundRobin,

    /// Send to endpoint with fewest active connections.
    LeastConnections,

    /// Weighted least connections.
    WeightedLeastConnections,

    /// Random selection.
    Random,

    /// Hash-based selection (sticky routing based on ObjectId).
    HashBased,

    /// Always use first available endpoint.
    FirstAvailable,
}

/// State for load balancer.
#[derive(Debug)]
pub struct LoadBalancer {
    /// Strategy to use.
    strategy: LoadBalanceStrategy,

    /// Round-robin counter.
    rr_counter: AtomicU64,

    /// Random seed.
    random_seed: AtomicU64,
}

impl LoadBalancer {
    /// Creates a new load balancer.
    #[must_use]
    pub fn new(strategy: LoadBalanceStrategy) -> Self {
        Self {
            strategy,
            rr_counter: AtomicU64::new(0),
            random_seed: AtomicU64::new(0),
        }
    }

    /// Selects an endpoint from the available set.
    pub fn select<'a>(
        &self,
        endpoints: &'a [Arc<Endpoint>],
        object_id: Option<ObjectId>,
    ) -> Option<&'a Arc<Endpoint>> {
        let available: SmallVec<[&Arc<Endpoint>; 8]> = endpoints
            .iter()
            .filter(|e| e.state().can_receive())
            .collect();

        if available.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let idx = (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % available.len();
                Some(available[idx])
            }

            LoadBalanceStrategy::WeightedRoundRobin => {
                let total_weight: u64 = available.iter().map(|e| u64::from(e.weight)).sum();
                if total_weight == 0 {
                    return Some(available[0]);
                }

                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let target = counter % total_weight;

                let mut cumulative = 0u64;
                for endpoint in &available {
                    cumulative += u64::from(endpoint.weight);
                    if target < cumulative {
                        return Some(endpoint);
                    }
                }
                Some(*available.last().unwrap())
            }

            LoadBalanceStrategy::LeastConnections => available
                .into_iter()
                .min_by_key(|e| e.connection_count()),

            LoadBalanceStrategy::WeightedLeastConnections => available
                .into_iter()
                .min_by(|a, b| {
                    let a_score = f64::from(a.connection_count()) / f64::from(a.weight.max(1));
                    let b_score = f64::from(b.connection_count()) / f64::from(b.weight.max(1));
                    a_score
                        .partial_cmp(&b_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),

            LoadBalanceStrategy::Random => {
                // Simple LCG random
                let seed = self.random_seed.fetch_add(1, Ordering::Relaxed);
                let random = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let idx = (random as usize) % available.len();
                Some(available[idx])
            }

            LoadBalanceStrategy::HashBased => object_id.map_or_else(
                || {
                    // Fall back to round-robin
                    let idx = (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % available.len();
                    Some(available[idx])
                },
                |oid| {
                    let hash = oid.as_u128() as usize;
                    Some(available[hash % available.len()])
                },
            ),
            LoadBalanceStrategy::FirstAvailable => Some(available[0]),
        }
    }

    /// Selects multiple endpoints from the available set.
    pub fn select_n<'a>(
        &self,
        endpoints: &'a [Arc<Endpoint>],
        n: usize,
        _object_id: Option<ObjectId>,
    ) -> Vec<&'a Arc<Endpoint>> {
        if n == 0 {
            return Vec::new();
        }

        // Filter healthy endpoints first
        // Note: For high-throughput this allocation might be costly.
        // But we need a contiguous slice/vec for indexing.
        let mut available: Vec<&Arc<Endpoint>> = endpoints
            .iter()
            .filter(|e| e.state().can_receive())
            .collect();

        if available.is_empty() {
            return Vec::new();
        }

        if n >= available.len() {
            return available;
        }

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let start = self.rr_counter.fetch_add(n as u64, Ordering::Relaxed) as usize;
                let len = available.len();
                (0..n).map(|i| available[(start + i) % len]).collect()
            }

            LoadBalanceStrategy::Random => {
                // Fisher-Yates shuffle in-place on the available vector.
                // This avoids allocating a separate indices vector.
                let mut seed = self.random_seed.fetch_add(n as u64, Ordering::Relaxed);
                let len = available.len();
                let count = n.min(len);

                for i in 0..count {
                    // Simple LCG step
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    // Range is [i, len)
                    let range = len - i;
                    let offset = (seed as usize) % range;
                    let swap_idx = i + offset;
                    available.swap(i, swap_idx);
                }
                available.truncate(count);
                available
            }
            LoadBalanceStrategy::LeastConnections
            | LoadBalanceStrategy::WeightedLeastConnections => {
                let mut candidates = available;
                // Sort by connection count (approximated by full sort for simplicity)
                // In production, select_nth_unstable is better.
                candidates.sort_by_key(|e| e.connection_count());
                candidates.truncate(n);
                candidates
            }

            // For others, fallback to first-available logic or simple selection
            _ => available.into_iter().take(n).collect(),
        }
    }
}

// ============================================================================
// Routing Table
// ============================================================================

/// Entry in the routing table.
#[derive(Debug, Clone)]
pub struct RoutingEntry {
    /// Endpoints for this route.
    pub endpoints: Vec<Arc<Endpoint>>,

    /// Load balancer for this route.
    pub load_balancer: Arc<LoadBalancer>,

    /// Priority (lower = higher priority).
    pub priority: u32,

    /// TTL for this entry (None = permanent).
    pub ttl: Option<Time>,

    /// When this entry was created.
    pub created_at: Time,
}

impl RoutingEntry {
    /// Creates a new routing entry.
    #[must_use]
    pub fn new(endpoints: Vec<Arc<Endpoint>>, created_at: Time) -> Self {
        Self {
            endpoints,
            load_balancer: Arc::new(LoadBalancer::new(LoadBalanceStrategy::RoundRobin)),
            priority: 100,
            ttl: None,
            created_at,
        }
    }

    /// Sets the load balancing strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: LoadBalanceStrategy) -> Self {
        self.load_balancer = Arc::new(LoadBalancer::new(strategy));
        self
    }

    /// Sets the priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets the TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Time) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Returns true if this entry has expired.
    #[must_use]
    pub fn is_expired(&self, now: Time) -> bool {
        self.ttl.is_some_and(|ttl| {
            let expiry = self.created_at.saturating_add_nanos(ttl.as_nanos());
            now > expiry
        })
    }

    /// Selects an endpoint for routing.
    #[must_use]
    pub fn select_endpoint(&self, object_id: Option<ObjectId>) -> Option<Arc<Endpoint>> {
        self.load_balancer
            .select(&self.endpoints, object_id)
            .cloned()
    }

    /// Selects multiple endpoints for routing.
    #[must_use]
    pub fn select_endpoints(&self, n: usize, object_id: Option<ObjectId>) -> Vec<Arc<Endpoint>> {
        self.load_balancer
            .select_n(&self.endpoints, n, object_id)
            .into_iter()
            .cloned()
            .collect()
    }
}

/// Key for routing table lookups.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RouteKey {
    /// Route by ObjectId.
    Object(ObjectId),

    /// Route by RegionId.
    Region(RegionId),

    /// Route by ObjectId and RegionId.
    ObjectAndRegion(ObjectId, RegionId),

    /// Default route (fallback).
    Default,
}

impl RouteKey {
    /// Creates a key from an ObjectId.
    #[must_use]
    pub fn object(oid: ObjectId) -> Self {
        Self::Object(oid)
    }

    /// Creates a key from a RegionId.
    #[must_use]
    pub fn region(rid: RegionId) -> Self {
        Self::Region(rid)
    }
}

/// The routing table for symbol dispatch.
#[derive(Debug)]
pub struct RoutingTable {
    /// Routes by key.
    routes: RwLock<HashMap<RouteKey, RoutingEntry>>,

    /// Default route (if no specific route matches).
    default_route: RwLock<Option<RoutingEntry>>,

    /// All known endpoints.
    endpoints: RwLock<HashMap<EndpointId, Arc<Endpoint>>>,
}

impl RoutingTable {
    /// Creates a new routing table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
            default_route: RwLock::new(None),
            endpoints: RwLock::new(HashMap::new()),
        }
    }

    /// Registers an endpoint.
    pub fn register_endpoint(&self, endpoint: Endpoint) -> Arc<Endpoint> {
        let id = endpoint.id;
        let arc = Arc::new(endpoint);
        self.endpoints.write().insert(id, arc.clone());
        arc
    }

    /// Gets an endpoint by ID.
    #[must_use]
    pub fn get_endpoint(&self, id: EndpointId) -> Option<Arc<Endpoint>> {
        self.endpoints.read().get(&id).cloned()
    }

    /// Updates endpoint state.
    pub fn update_endpoint_state(&self, id: EndpointId, state: EndpointState) -> bool {
        self.endpoints.read().get(&id).is_some_and(|endpoint| {
            endpoint.set_state(state);
            true
        })
    }

    /// Adds a route.
    pub fn add_route(&self, key: RouteKey, entry: RoutingEntry) {
        if key == RouteKey::Default {
            *self.default_route.write() = Some(entry);
        } else {
            self.routes.write().insert(key, entry);
        }
    }

    /// Removes a route.
    pub fn remove_route(&self, key: &RouteKey) -> bool {
        if *key == RouteKey::Default {
            let mut default = self.default_route.write();
            let had_route = default.is_some();
            *default = None;
            had_route
        } else {
            self.routes.write().remove(key).is_some()
        }
    }

    /// Looks up a route.
    #[must_use]
    pub fn lookup(&self, key: &RouteKey) -> Option<RoutingEntry> {
        // Try exact match first
        if let Some(entry) = self.routes.read().get(key) {
            return Some(entry.clone());
        }

        // Try fallback strategies
        if let RouteKey::ObjectAndRegion(oid, rid) = key {
            // Try object-only
            if let Some(entry) = self.routes.read().get(&RouteKey::Object(*oid)) {
                return Some(entry.clone());
            }
            // Try region-only
            if let Some(entry) = self.routes.read().get(&RouteKey::Region(*rid)) {
                return Some(entry.clone());
            }
        }

        // Fall back to default
        self.default_route.read().clone()
    }

    /// Looks up a route without falling back to the default route.
    ///
    /// This preserves object/region fallback behavior for compound keys but
    /// never consults `default_route`.
    #[must_use]
    pub fn lookup_without_default(&self, key: &RouteKey) -> Option<RoutingEntry> {
        if let Some(entry) = self.routes.read().get(key) {
            return Some(entry.clone());
        }

        if let RouteKey::ObjectAndRegion(oid, rid) = key {
            if let Some(entry) = self.routes.read().get(&RouteKey::Object(*oid)) {
                return Some(entry.clone());
            }
            if let Some(entry) = self.routes.read().get(&RouteKey::Region(*rid)) {
                return Some(entry.clone());
            }
        }

        None
    }

    /// Prunes expired routes.
    pub fn prune_expired(&self, now: Time) -> usize {
        let mut routes = self.routes.write();
        let before = routes.len();
        routes.retain(|_, entry| !entry.is_expired(now));
        before - routes.len()
    }

    /// Returns all healthy endpoints.
    #[must_use]
    pub fn healthy_endpoints(&self) -> Vec<Arc<Endpoint>> {
        self.endpoints
            .read()
            .values()
            .filter(|e| e.state() == EndpointState::Healthy)
            .cloned()
            .collect()
    }

    /// Returns route count.
    #[must_use]
    pub fn route_count(&self) -> usize {
        let routes = self.routes.read().len();
        let default = usize::from(self.default_route.read().is_some());
        routes + default
    }
}

impl Default for RoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Symbol Router
// ============================================================================

/// Result of routing a symbol.
#[derive(Debug, Clone)]
pub struct RouteResult {
    /// Selected endpoint.
    pub endpoint: Arc<Endpoint>,

    /// Route key that matched.
    pub matched_key: RouteKey,

    /// Whether this was a fallback match.
    pub is_fallback: bool,
}

/// The symbol router resolves destinations for symbols.
#[derive(Debug)]
pub struct SymbolRouter {
    /// The routing table.
    table: Arc<RoutingTable>,

    /// Whether to allow fallback to default route.
    allow_fallback: bool,

    /// Whether to prefer local endpoints.
    prefer_local: bool,

    /// Local region ID (if any).
    local_region: Option<RegionId>,
}

impl SymbolRouter {
    /// Creates a new router with the given routing table.
    pub fn new(table: Arc<RoutingTable>) -> Self {
        Self {
            table,
            allow_fallback: true,
            prefer_local: false,
            local_region: None,
        }
    }

    /// Disables fallback to default route.
    #[must_use]
    pub fn without_fallback(mut self) -> Self {
        self.allow_fallback = false;
        self
    }

    /// Enables local preference.
    #[must_use]
    pub fn with_local_preference(mut self, region: RegionId) -> Self {
        self.prefer_local = true;
        self.local_region = Some(region);
        self
    }

    /// Routes a symbol to an endpoint.
    pub fn route(&self, symbol: &Symbol) -> Result<RouteResult, RoutingError> {
        let object_id = symbol.object_id();
        let primary_key = RouteKey::Object(object_id);

        if let Some(entry) = self.table.lookup_without_default(&primary_key) {
            if let Some(endpoint) = entry.select_endpoint(Some(object_id)) {
                // Check local preference
                if self.prefer_local {
                    if let Some(local) = self.local_region {
                        if endpoint.region == Some(local) {
                            // Prefer this endpoint
                        }
                    }
                }

                return Ok(RouteResult {
                    endpoint,
                    matched_key: primary_key,
                    is_fallback: false,
                });
            }
        }

        if self.allow_fallback {
            let fallback_key = RouteKey::Default;
            if let Some(entry) = self.table.lookup(&fallback_key) {
                if let Some(endpoint) = entry.select_endpoint(Some(object_id)) {
                    return Ok(RouteResult {
                        endpoint,
                        matched_key: fallback_key,
                        is_fallback: true,
                    });
                }
            }
        }

        Err(RoutingError::NoRoute {
            object_id,
            reason: "No matching route and no default route configured".into(),
        })
    }

    /// Routes to multiple endpoints for multicast.
    pub fn route_multicast(
        &self,
        symbol: &Symbol,
        count: usize,
    ) -> Result<Vec<RouteResult>, RoutingError> {
        let object_id = symbol.object_id();

        let key = RouteKey::Object(object_id);
        let (entry, matched_key, is_fallback) =
            if let Some(entry) = self.table.lookup_without_default(&key) {
                (entry, key, false)
            } else if self.allow_fallback {
                let fallback_key = RouteKey::Default;
                let fallback =
                    self.table
                        .lookup(&fallback_key)
                        .ok_or_else(|| RoutingError::NoRoute {
                            object_id,
                            reason: "No route for multicast".into(),
                        })?;
                (fallback, fallback_key, true)
            } else {
                return Err(RoutingError::NoRoute {
                    object_id,
                    reason: "No route for multicast".into(),
                });
            };

        // Select multiple endpoints
        let endpoints = entry.select_endpoints(count, Some(object_id));

        if endpoints.is_empty() {
            return Err(RoutingError::NoHealthyEndpoints { object_id });
        }

        let results: Vec<_> = endpoints
            .into_iter()
            .map(|endpoint| RouteResult {
                endpoint,
                matched_key: matched_key.clone(),
                is_fallback,
            })
            .collect();

        Ok(results)
    }

    /// Returns the routing table.
    #[must_use]
    pub fn table(&self) -> &Arc<RoutingTable> {
        &self.table
    }
}

// ============================================================================
// Dispatch Strategy
// ============================================================================

/// Strategy for dispatching symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DispatchStrategy {
    /// Send to single endpoint.
    #[default]
    Unicast,

    /// Send to multiple endpoints.
    Multicast {
        /// Number of endpoints to send to.
        count: usize,
    },

    /// Send to all available endpoints.
    Broadcast,

    /// Send to endpoints until threshold confirmed.
    QuorumCast {
        /// Number of successful sends required.
        required: usize,
    },
}

/// Result of a dispatch operation.
#[derive(Debug)]
pub struct DispatchResult {
    /// Number of successful dispatches.
    pub successes: usize,

    /// Number of failed dispatches.
    pub failures: usize,

    /// Endpoints that received the symbol.
    pub sent_to: SmallVec<[EndpointId; 4]>,

    /// Endpoints that failed.
    pub failed_endpoints: SmallVec<[(EndpointId, DispatchError); 4]>,

    /// Total time for dispatch.
    pub duration: Time,
}

impl DispatchResult {
    /// Returns true if all dispatches succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failures == 0 && self.successes > 0
    }

    /// Returns true if at least one dispatch succeeded.
    #[must_use]
    pub fn any_succeeded(&self) -> bool {
        self.successes > 0
    }

    /// Returns true if quorum was reached.
    #[must_use]
    pub fn quorum_reached(&self, required: usize) -> bool {
        self.successes >= required
    }
}

// ============================================================================
// Symbol Dispatcher
// ============================================================================

/// Configuration for the dispatcher.
#[derive(Debug, Clone)]
pub struct DispatchConfig {
    /// Default dispatch strategy.
    pub default_strategy: DispatchStrategy,

    /// Timeout for each dispatch attempt.
    pub timeout: Time,

    /// Maximum retries per endpoint.
    pub max_retries: u32,

    /// Delay between retries.
    pub retry_delay: Time,

    /// Whether to fail fast on first error.
    pub fail_fast: bool,

    /// Maximum concurrent dispatches.
    pub max_concurrent: u32,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            default_strategy: DispatchStrategy::Unicast,
            timeout: Time::from_secs(5),
            max_retries: 3,
            retry_delay: Time::from_millis(100),
            fail_fast: false,
            max_concurrent: 100,
        }
    }
}

/// The symbol dispatcher sends symbols to resolved endpoints.
pub struct SymbolDispatcher {
    /// The router.
    router: Arc<SymbolRouter>,

    /// Configuration.
    config: DispatchConfig,

    /// Active dispatch count.
    active_dispatches: AtomicU32,

    /// Total symbols dispatched.
    total_dispatched: AtomicU64,

    /// Total failures.
    total_failures: AtomicU64,

    /// Registered sinks for endpoints.
    sinks: RwLock<EndpointSinkMap>,
}

impl std::fmt::Debug for SymbolDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolDispatcher")
            .field("router", &self.router)
            .field("config", &self.config)
            .field("active_dispatches", &self.active_dispatches)
            .field("total_dispatched", &self.total_dispatched)
            .field("total_failures", &self.total_failures)
            .field(
                "sinks",
                &format_args!("<{} sinks>", self.sinks.read().len()),
            )
            .finish()
    }
}

/// RAII guard for an active dispatch.
struct DispatchGuard<'a> {
    dispatcher: &'a SymbolDispatcher,
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        self.dispatcher
            .active_dispatches
            .fetch_sub(1, Ordering::Release);
    }
}

impl SymbolDispatcher {
    /// Creates a new dispatcher.
    #[must_use]
    pub fn new(router: Arc<SymbolRouter>, config: DispatchConfig) -> Self {
        Self {
            router,
            config,
            active_dispatches: AtomicU32::new(0),
            total_dispatched: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            sinks: RwLock::new(HashMap::new()),
        }
    }

    /// Register a sink for an endpoint.
    pub fn add_sink(&self, endpoint: EndpointId, sink: Box<dyn SymbolSink>) {
        self.sinks
            .write()
            .insert(endpoint, Arc::new(Mutex::new(sink)));
    }

    /// Dispatches a symbol using the default strategy.
    pub async fn dispatch(
        &self,
        cx: &Cx,
        symbol: AuthenticatedSymbol,
    ) -> Result<DispatchResult, DispatchError> {
        self.dispatch_with_strategy(cx, symbol, self.config.default_strategy)
            .await
    }

    /// Dispatches a symbol with a specific strategy.
    pub async fn dispatch_with_strategy(
        &self,
        cx: &Cx,
        symbol: AuthenticatedSymbol,
        strategy: DispatchStrategy,
    ) -> Result<DispatchResult, DispatchError> {
        // Check concurrent dispatch limit
        let active = self.active_dispatches.fetch_add(1, Ordering::AcqRel);
        if active >= self.config.max_concurrent {
            self.active_dispatches.fetch_sub(1, Ordering::Release);
            return Err(DispatchError::Overloaded);
        }

        // RAII guard to ensure active_dispatches is decremented even on cancellation/panic
        let _guard = DispatchGuard { dispatcher: self };

        let result = match strategy {
            DispatchStrategy::Unicast => self.dispatch_unicast(cx, symbol).await,
            DispatchStrategy::Multicast { count } => {
                self.dispatch_multicast(cx, &symbol, count).await
            }
            DispatchStrategy::Broadcast => self.dispatch_broadcast(cx, &symbol).await,
            DispatchStrategy::QuorumCast { required } => {
                self.dispatch_quorum(cx, &symbol, required).await
            }
        };

        // Explicitly drop guard is handled by RAII, but we need to update stats before returning.
        // We can do stats update here. The guard handles the decrement.

        match &result {
            Ok(r) => {
                self.total_dispatched
                    .fetch_add(r.successes as u64, Ordering::Relaxed);
                self.total_failures
                    .fetch_add(r.failures as u64, Ordering::Relaxed);
            }
            Err(_) => {
                self.total_failures.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

    /// Dispatches to a single endpoint.
    #[allow(clippy::unused_async)]
    async fn dispatch_unicast(
        &self,
        cx: &Cx,
        symbol: AuthenticatedSymbol,
    ) -> Result<DispatchResult, DispatchError> {
        let route = self.router.route(symbol.symbol())?;

        // Get sink
        let sink = {
            let sinks = self.sinks.read();
            sinks.get(&route.endpoint.id).cloned()
        };

        let _guard = route.endpoint.acquire_connection_guard();

        let result = if let Some(sink) = sink {
            let send_result = match OwnedMutexGuard::lock(sink, cx).await {
                Ok(mut guard) => guard
                    .send(symbol)
                    .await
                    .map_err(|_| DispatchError::SendFailed {
                        endpoint: route.endpoint.id,
                        reason: "Send failed".into(),
                    }),
                Err(_) => Err(DispatchError::Timeout),
            };

            match send_result {
                Ok(()) => {
                    route.endpoint.record_success(Time::ZERO);
                    Ok(DispatchResult {
                        successes: 1,
                        failures: 0,
                        sent_to: smallvec![route.endpoint.id],
                        failed_endpoints: SmallVec::new(),
                        duration: Time::ZERO,
                    })
                }
                Err(err) => {
                    route.endpoint.record_failure(Time::ZERO);
                    Err(err)
                }
            }
        } else {
            // Fallback to simulation if no sink registered (for existing logic)
            route.endpoint.record_success(Time::ZERO);
            Ok(DispatchResult {
                successes: 1,
                failures: 0,
                sent_to: smallvec![route.endpoint.id],
                failed_endpoints: SmallVec::new(),
                duration: Time::ZERO,
            })
        };

        // Guard drop releases connection
        result
    }

    /// Dispatches to multiple endpoints.
    #[allow(clippy::unused_async)]
    async fn dispatch_multicast(
        &self,
        cx: &Cx,
        symbol: &AuthenticatedSymbol,
        count: usize,
    ) -> Result<DispatchResult, DispatchError> {
        if count == 0 {
            return Ok(DispatchResult {
                successes: 0,
                failures: 0,
                sent_to: SmallVec::new(),
                failed_endpoints: SmallVec::new(),
                duration: Time::ZERO,
            });
        }

        // Use router to resolve endpoints with load balancing strategy
        let routes = match self.router.route_multicast(symbol.symbol(), count) {
            Ok(routes) => routes,
            Err(RoutingError::NoHealthyEndpoints { object_id }) => {
                return Err(DispatchError::RoutingFailed(
                    RoutingError::NoHealthyEndpoints { object_id },
                ));
            }
            Err(e) => return Err(DispatchError::RoutingFailed(e)),
        };

        // Actually dispatch to selected endpoints
        let mut successes = 0;
        let mut failures = 0;
        let mut sent_to = SmallVec::<[EndpointId; 4]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 4]>::new();

        for route in routes {
            let endpoint = route.endpoint;
            let _guard = endpoint.acquire_connection_guard();

            // Attempt send
            let success = if let Some(sink) = {
                let sinks = self.sinks.read();
                sinks.get(&endpoint.id).cloned()
            } {
                match OwnedMutexGuard::lock(sink, cx).await {
                    Ok(mut guard) => {
                        let guard: &mut Box<dyn SymbolSink> = &mut guard;
                        guard.send(symbol.clone()).await.is_ok()
                    }
                    Err(_) => false,
                }
            } else {
                // Simulation mode
                true
            };

            // Release is implicit on loop continue/exit

            if success {
                endpoint.record_success(Time::ZERO);
                successes += 1;
                sent_to.push(endpoint.id);
            } else {
                endpoint.record_failure(Time::ZERO);
                failures += 1;
                failed.push((
                    endpoint.id,
                    DispatchError::SendFailed {
                        endpoint: endpoint.id,
                        reason: "Send failed".into(),
                    },
                ));
            }
        }

        Ok(DispatchResult {
            successes,
            failures,
            sent_to,
            failed_endpoints: failed,
            duration: Time::ZERO,
        })
    }

    /// Dispatches to all endpoints.
    #[allow(clippy::unused_async)]
    async fn dispatch_broadcast(
        &self,
        cx: &Cx,
        symbol: &AuthenticatedSymbol,
    ) -> Result<DispatchResult, DispatchError> {
        let endpoints = self.router.table().healthy_endpoints();

        if endpoints.is_empty() {
            return Err(DispatchError::NoEndpoints);
        }

        let mut successes = 0;
        let mut failures = 0;
        let mut sent_to = SmallVec::<[EndpointId; 4]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 4]>::new();

        for route in endpoints {
            let _guard = route.acquire_connection_guard();

            // Attempt send
            let success = if let Some(sink) = {
                let sinks = self.sinks.read();
                sinks.get(&route.id).cloned()
            } {
                match OwnedMutexGuard::lock(sink, cx).await {
                    Ok(mut guard) => {
                        let guard: &mut Box<dyn SymbolSink> = &mut guard;
                        guard.send(symbol.clone()).await.is_ok()
                    }
                    Err(_) => false,
                }
            } else {
                // Simulation
                true
            };

            if success {
                route.record_success(Time::ZERO);
                successes += 1;
                sent_to.push(route.id);
            } else {
                route.record_failure(Time::ZERO);
                failures += 1;
                failed.push((
                    route.id,
                    DispatchError::SendFailed {
                        endpoint: route.id,
                        reason: "Send failed".into(),
                    },
                ));
            }
        }

        Ok(DispatchResult {
            successes,
            failures,
            sent_to,
            failed_endpoints: failed,
            duration: Time::ZERO,
        })
    }

    /// Dispatches until quorum is reached.
    #[allow(clippy::unused_async)]
    async fn dispatch_quorum(
        &self,
        cx: &Cx,
        symbol: &AuthenticatedSymbol,
        required: usize,
    ) -> Result<DispatchResult, DispatchError> {
        let endpoints = self.router.table().healthy_endpoints();

        if endpoints.len() < required {
            return Err(DispatchError::InsufficientEndpoints {
                available: endpoints.len(),
                required,
            });
        }

        let mut successes = 0;
        let mut failures = 0;
        let mut sent_to = SmallVec::<[EndpointId; 4]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 4]>::new();

        for route in endpoints {
            if successes >= required {
                break;
            }

            let _guard = route.acquire_connection_guard();

            let success = if let Some(sink) = {
                let sinks = self.sinks.read();
                sinks.get(&route.id).cloned()
            } {
                match OwnedMutexGuard::lock(sink, cx).await {
                    Ok(mut guard) => {
                        let guard: &mut Box<dyn SymbolSink> = &mut guard;
                        guard.send(symbol.clone()).await.is_ok()
                    }
                    Err(_) => false,
                }
            } else {
                true
            };

            if success {
                route.record_success(Time::ZERO);
                successes += 1;
                sent_to.push(route.id);
            } else {
                route.record_failure(Time::ZERO);
                failures += 1;
                failed.push((
                    route.id,
                    DispatchError::SendFailed {
                        endpoint: route.id,
                        reason: "Send failed".into(),
                    },
                ));
            }
        }

        if successes < required {
            return Err(DispatchError::QuorumNotReached {
                achieved: successes,
                required,
            });
        }

        Ok(DispatchResult {
            successes,
            failures,
            sent_to,
            failed_endpoints: failed,
            duration: Time::ZERO,
        })
    }

    /// Returns dispatcher statistics.
    #[must_use]
    pub fn stats(&self) -> DispatcherStats {
        DispatcherStats {
            active_dispatches: self.active_dispatches.load(Ordering::Relaxed),
            total_dispatched: self.total_dispatched.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
        }
    }
}

/// Dispatcher statistics.
#[derive(Debug, Clone)]
pub struct DispatcherStats {
    /// Currently active dispatches.
    pub active_dispatches: u32,

    /// Total symbols dispatched.
    pub total_dispatched: u64,

    /// Total failures.
    pub total_failures: u64,
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors from routing.
#[derive(Debug, Clone)]
pub enum RoutingError {
    /// No route found for the symbol.
    NoRoute {
        /// The object ID that failed routing.
        object_id: ObjectId,
        /// Reason for failure.
        reason: String,
    },

    /// No healthy endpoints available.
    NoHealthyEndpoints {
        /// The object ID.
        object_id: ObjectId,
    },

    /// Route table is empty.
    EmptyTable,
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoute { object_id, reason } => {
                write!(f, "no route for object {object_id:?}: {reason}")
            }
            Self::NoHealthyEndpoints { object_id } => {
                write!(f, "no healthy endpoints for object {object_id:?}")
            }
            Self::EmptyTable => write!(f, "routing table is empty"),
        }
    }
}

impl std::error::Error for RoutingError {}

impl From<RoutingError> for Error {
    fn from(e: RoutingError) -> Self {
        Self::new(ErrorKind::RoutingFailed).with_message(e.to_string())
    }
}
/// Errors from dispatch.
#[derive(Debug, Clone)]
pub enum DispatchError {
    /// Routing failed.
    RoutingFailed(RoutingError),

    /// Send failed.
    SendFailed {
        /// The endpoint that failed.
        endpoint: EndpointId,
        /// Reason for failure.
        reason: String,
    },

    /// Dispatcher is overloaded.
    Overloaded,

    /// No endpoints available.
    NoEndpoints,

    /// Insufficient endpoints for quorum.
    InsufficientEndpoints {
        /// Available endpoints.
        available: usize,
        /// Required endpoints.
        required: usize,
    },

    /// Quorum not reached.
    QuorumNotReached {
        /// Achieved successes.
        achieved: usize,
        /// Required successes.
        required: usize,
    },

    /// Timeout.
    Timeout,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoutingFailed(e) => write!(f, "routing failed: {e}"),
            Self::SendFailed { endpoint, reason } => {
                write!(f, "send to {endpoint} failed: {reason}")
            }
            Self::Overloaded => write!(f, "dispatcher overloaded"),
            Self::NoEndpoints => write!(f, "no endpoints available"),
            Self::InsufficientEndpoints {
                available,
                required,
            } => {
                write!(
                    f,
                    "insufficient endpoints: {available} available, {required} required"
                )
            }
            Self::QuorumNotReached { achieved, required } => {
                write!(f, "quorum not reached: {achieved} of {required} required")
            }
            Self::Timeout => write!(f, "dispatch timeout"),
        }
    }
}

impl std::error::Error for DispatchError {}

impl From<RoutingError> for DispatchError {
    fn from(e: RoutingError) -> Self {
        Self::RoutingFailed(e)
    }
}

impl From<DispatchError> for Error {
    fn from(e: DispatchError) -> Self {
        match e {
            DispatchError::RoutingFailed(_) => {
                Self::new(ErrorKind::RoutingFailed).with_message(e.to_string())
            }
            DispatchError::QuorumNotReached { .. } => {
                Self::new(ErrorKind::QuorumNotReached).with_message(e.to_string())
            }
            _ => Self::new(ErrorKind::DispatchFailed).with_message(e.to_string()),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn test_endpoint(id: u64) -> Endpoint {
        Endpoint::new(EndpointId(id), format!("node-{id}:8080"))
    }

    // Test 1: Endpoint state predicates
    #[test]
    fn test_endpoint_state() {
        assert!(EndpointState::Healthy.can_receive());
        assert!(EndpointState::Degraded.can_receive());
        assert!(!EndpointState::Unhealthy.can_receive());
        assert!(!EndpointState::Draining.can_receive());
        assert!(!EndpointState::Removed.can_receive());

        assert!(EndpointState::Healthy.is_available());
        assert!(!EndpointState::Removed.is_available());
    }

    // Test 2: Endpoint statistics
    #[test]
    fn test_endpoint_statistics() {
        let endpoint = test_endpoint(1);

        endpoint.record_success(Time::from_secs(1));
        endpoint.record_success(Time::from_secs(2));
        endpoint.record_failure(Time::from_secs(3));

        assert_eq!(endpoint.symbols_sent.load(Ordering::Relaxed), 2);
        assert_eq!(endpoint.failures.load(Ordering::Relaxed), 1);

        // Failure rate: 1 / (2 + 1) = 0.333...
        let rate = endpoint.failure_rate();
        assert!(rate > 0.3 && rate < 0.34);
    }

    // Test 3: Load balancer round robin
    #[test]
    fn test_load_balancer_round_robin() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::RoundRobin);

        let endpoints: Vec<Arc<Endpoint>> = (1..=3).map(|i| Arc::new(test_endpoint(i))).collect();

        let e1 = lb.select(&endpoints, None);
        let e2 = lb.select(&endpoints, None);
        let e3 = lb.select(&endpoints, None);
        let e4 = lb.select(&endpoints, None); // Should wrap around

        assert_eq!(e1.unwrap().id, EndpointId(1));
        assert_eq!(e2.unwrap().id, EndpointId(2));
        assert_eq!(e3.unwrap().id, EndpointId(3));
        assert_eq!(e4.unwrap().id, EndpointId(1));
    }

    // Test 4: Load balancer least connections
    #[test]
    fn test_load_balancer_least_connections() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::LeastConnections);

        let e1 = Arc::new(test_endpoint(1));
        let e2 = Arc::new(test_endpoint(2));
        let e3 = Arc::new(test_endpoint(3));

        e1.active_connections.store(5, Ordering::Relaxed);
        e2.active_connections.store(2, Ordering::Relaxed);
        e3.active_connections.store(10, Ordering::Relaxed);

        let endpoints = vec![e1, e2.clone(), e3];

        let selected = lb.select(&endpoints, None).unwrap();
        assert_eq!(selected.id, e2.id); // Least connections
    }

    // Test 5: Load balancer hash-based
    #[test]
    fn test_load_balancer_hash_based() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::HashBased);

        let endpoints: Vec<Arc<Endpoint>> = (1..=3).map(|i| Arc::new(test_endpoint(i))).collect();

        let oid = ObjectId::new_for_test(42);

        // Same ObjectId should always select same endpoint
        let s1 = lb.select(&endpoints, Some(oid));
        let s2 = lb.select(&endpoints, Some(oid));
        assert_eq!(s1.unwrap().id, s2.unwrap().id);
    }

    // Test 6: Routing table basic operations
    #[test]
    fn test_routing_table_basic() {
        let table = RoutingTable::new();

        let _e1 = table.register_endpoint(test_endpoint(1));
        let e2 = table.register_endpoint(test_endpoint(2));

        assert!(table.get_endpoint(EndpointId(1)).is_some());
        assert!(table.get_endpoint(EndpointId(999)).is_none());

        let entry = RoutingEntry::new(vec![e2], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        assert_eq!(table.route_count(), 1);
    }

    // Test 7: Routing table lookup with fallback
    #[test]
    fn test_routing_table_lookup() {
        let table = RoutingTable::new();

        let e1 = table.register_endpoint(test_endpoint(1));
        let e2 = table.register_endpoint(test_endpoint(2));

        // Add default route
        let default = RoutingEntry::new(vec![e1], Time::ZERO);
        table.add_route(RouteKey::Default, default);

        // Add specific object route
        let oid = ObjectId::new_for_test(42);
        let specific = RoutingEntry::new(vec![e2], Time::ZERO);
        table.add_route(RouteKey::Object(oid), specific);

        // Lookup specific route
        let found = table.lookup(&RouteKey::Object(oid));
        assert!(found.is_some());

        // Lookup unknown object falls back to default
        let other_oid = ObjectId::new_for_test(999);
        let found = table.lookup(&RouteKey::Object(other_oid));
        assert!(found.is_some()); // Default route
    }

    // Test 8: Routing entry TTL
    #[test]
    fn test_routing_entry_ttl() {
        let entry = RoutingEntry::new(vec![], Time::from_secs(100)).with_ttl(Time::from_secs(60));

        assert!(!entry.is_expired(Time::from_secs(150)));
        assert!(entry.is_expired(Time::from_secs(170)));
    }

    // Test 9: Routing table prune expired
    #[test]
    fn test_routing_table_prune() {
        let table = RoutingTable::new();

        let e1 = table.register_endpoint(test_endpoint(1));

        // Add routes with different TTLs
        let entry1 =
            RoutingEntry::new(vec![e1.clone()], Time::from_secs(0)).with_ttl(Time::from_secs(10));
        let entry2 = RoutingEntry::new(vec![e1], Time::from_secs(0)).with_ttl(Time::from_secs(100));

        table.add_route(RouteKey::Object(ObjectId::new_for_test(1)), entry1);
        table.add_route(RouteKey::Object(ObjectId::new_for_test(2)), entry2);

        assert_eq!(table.route_count(), 2);

        // Prune at time 50 - should remove first entry
        let pruned = table.prune_expired(Time::from_secs(50));
        assert_eq!(pruned, 1);
        assert_eq!(table.route_count(), 1);
    }

    // Test 10: SymbolRouter basic routing
    #[test]
    fn test_symbol_router() {
        let table = Arc::new(RoutingTable::new());
        let e1 = table.register_endpoint(test_endpoint(1));

        let entry = RoutingEntry::new(vec![e1], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let result = router.route(&symbol);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().endpoint.id, EndpointId(1));
    }

    // Test 10.0: SymbolRouter respects `without_fallback`.
    #[test]
    fn test_symbol_router_without_fallback() {
        let table = Arc::new(RoutingTable::new());
        let e1 = table.register_endpoint(test_endpoint(1));

        // Default route exists, but there is no object-specific route.
        let entry = RoutingEntry::new(vec![e1], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table).without_fallback();

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let result = router.route(&symbol);

        assert!(
            result.is_err(),
            "without_fallback should reject default-only route"
        );
    }

    // Test 10.1: SymbolRouter failover to healthy endpoint
    #[test]
    fn test_symbol_router_failover() {
        let table = Arc::new(RoutingTable::new());

        let primary =
            table.register_endpoint(test_endpoint(1).with_state(EndpointState::Unhealthy));
        let backup = table.register_endpoint(test_endpoint(2).with_state(EndpointState::Healthy));

        let entry = RoutingEntry::new(vec![primary, backup.clone()], Time::ZERO)
            .with_strategy(LoadBalanceStrategy::FirstAvailable);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);
        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let result = router.route(&symbol).expect("route");

        assert_eq!(result.endpoint.id, backup.id);
    }

    // Test 11: SymbolRouter multicast
    #[test]
    fn test_symbol_router_multicast() {
        let table = Arc::new(RoutingTable::new());
        let e1 = table.register_endpoint(test_endpoint(1));
        let e2 = table.register_endpoint(test_endpoint(2));
        let e3 = table.register_endpoint(test_endpoint(3));

        let entry = RoutingEntry::new(vec![e1, e2, e3], Time::ZERO);
        table.add_route(RouteKey::Default, entry);

        let router = SymbolRouter::new(table);

        let symbol = Symbol::new_for_test(1, 0, 0, &[1, 2, 3]);
        let results = router.route_multicast(&symbol, 2);

        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 2);
    }

    // Test 12: DispatchResult quorum check
    #[test]
    fn test_dispatch_result_quorum() {
        let result = DispatchResult {
            successes: 3,
            failures: 1,
            sent_to: smallvec![EndpointId(1), EndpointId(2), EndpointId(3)],
            failed_endpoints: SmallVec::new(),
            duration: Time::ZERO,
        };

        assert!(result.quorum_reached(2));
        assert!(result.quorum_reached(3));
        assert!(!result.quorum_reached(4));
        assert!(result.any_succeeded());
        assert!(!result.all_succeeded()); // Has failures
    }

    #[test]
    fn dispatch_result_unicast_stays_inline() {
        let result = DispatchResult {
            successes: 1,
            failures: 0,
            sent_to: smallvec![EndpointId(7)],
            failed_endpoints: SmallVec::new(),
            duration: Time::ZERO,
        };

        assert!(!result.sent_to.spilled());
        assert!(!result.failed_endpoints.spilled());
    }

    // Test 13: Endpoint connection tracking
    #[test]
    fn test_endpoint_connections() {
        let endpoint = test_endpoint(1);

        assert_eq!(endpoint.connection_count(), 0);

        endpoint.acquire_connection();
        endpoint.acquire_connection();
        assert_eq!(endpoint.connection_count(), 2);

        endpoint.release_connection();
        assert_eq!(endpoint.connection_count(), 1);
    }

    #[test]
    fn test_endpoint_release_connection_saturates() {
        let endpoint = test_endpoint(1);
        endpoint.release_connection();
        assert_eq!(endpoint.connection_count(), 0);
    }

    #[test]
    fn test_routing_table_updates_endpoint_state() {
        let table = RoutingTable::new();
        let endpoint = table.register_endpoint(test_endpoint(9));
        assert_eq!(endpoint.state(), EndpointState::Healthy);
        assert!(table.update_endpoint_state(EndpointId(9), EndpointState::Draining));
        assert_eq!(endpoint.state(), EndpointState::Draining);
        assert!(!table.update_endpoint_state(EndpointId(999), EndpointState::Healthy));
    }

    // Test 14: RoutingError display
    #[test]
    fn test_routing_error_display() {
        let oid = ObjectId::new_for_test(42);

        let no_route = RoutingError::NoRoute {
            object_id: oid,
            reason: "test".into(),
        };
        assert!(no_route.to_string().contains("no route"));

        let no_healthy = RoutingError::NoHealthyEndpoints { object_id: oid };
        assert!(no_healthy.to_string().contains("healthy"));
    }

    // Test 15: DispatchError display
    #[test]
    fn test_dispatch_error_display() {
        let overloaded = DispatchError::Overloaded;
        assert!(overloaded.to_string().contains("overloaded"));

        let quorum = DispatchError::QuorumNotReached {
            achieved: 2,
            required: 3,
        };
        assert!(quorum.to_string().contains("quorum"));
        assert!(quorum.to_string().contains('2'));
        assert!(quorum.to_string().contains('3'));
    }

    // Pure data-type tests (wave 17 – CyanBarn)

    #[test]
    fn endpoint_id_debug_display() {
        let id = EndpointId::new(42);
        assert!(format!("{id:?}").contains("42"));
        assert_eq!(id.to_string(), "Endpoint(42)");
    }

    #[test]
    fn endpoint_id_clone_copy_eq() {
        let id = EndpointId::new(7);
        let id2 = id;
        assert_eq!(id, id2);
    }

    #[test]
    fn endpoint_id_ord_hash() {
        let a = EndpointId::new(1);
        let b = EndpointId::new(2);
        assert!(a < b);

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn endpoint_state_debug_clone_copy_eq() {
        let s = EndpointState::Healthy;
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("Healthy"));
    }

    #[test]
    fn endpoint_state_as_u8_roundtrip() {
        let states = [
            EndpointState::Healthy,
            EndpointState::Degraded,
            EndpointState::Unhealthy,
            EndpointState::Draining,
            EndpointState::Removed,
        ];
        for &s in &states {
            assert_eq!(EndpointState::from_u8(s.as_u8()), s);
        }
    }

    #[test]
    fn endpoint_state_from_u8_invalid() {
        let s = EndpointState::from_u8(255);
        assert_eq!(s, EndpointState::Removed);
    }

    #[test]
    fn endpoint_debug() {
        let ep = Endpoint::new(EndpointId::new(1), "addr:80");
        let dbg = format!("{ep:?}");
        assert!(dbg.contains("Endpoint"));
    }

    #[test]
    fn endpoint_with_weight_region() {
        let region = RegionId::new_for_test(1, 0);
        let ep = Endpoint::new(EndpointId::new(5), "host:80")
            .with_weight(200)
            .with_region(region);
        assert_eq!(ep.weight, 200);
        assert_eq!(ep.region, Some(region));
    }

    #[test]
    fn endpoint_with_state_setter() {
        let ep = Endpoint::new(EndpointId::new(1), "h:80").with_state(EndpointState::Draining);
        assert_eq!(ep.state(), EndpointState::Draining);
        ep.set_state(EndpointState::Healthy);
        assert_eq!(ep.state(), EndpointState::Healthy);
    }

    #[test]
    fn endpoint_failure_rate_zero() {
        let ep = Endpoint::new(EndpointId::new(1), "h:80");
        assert!((ep.failure_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn endpoint_connection_guard_drops() {
        let ep = Endpoint::new(EndpointId::new(1), "h:80");
        {
            let _guard = ep.acquire_connection_guard();
            assert_eq!(ep.connection_count(), 1);
        }
        assert_eq!(ep.connection_count(), 0);
    }

    #[test]
    fn load_balance_strategy_debug_clone_copy_eq_default() {
        let s = LoadBalanceStrategy::default();
        assert_eq!(s, LoadBalanceStrategy::RoundRobin);
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("RoundRobin"));
    }

    #[test]
    fn route_key_debug_clone_eq_ord_hash() {
        let oid = ObjectId::new_for_test(1);
        let k1 = RouteKey::Object(oid);
        let k2 = k1.clone();
        assert_eq!(k1, k2);
        assert!(format!("{k1:?}").contains("Object"));
        assert!(k1 <= k2);

        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(k1);
        set.insert(RouteKey::Default);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn route_key_constructors() {
        let oid = ObjectId::new_for_test(1);
        let rid = RegionId::new_for_test(2, 0);
        assert_eq!(RouteKey::object(oid), RouteKey::Object(oid));
        assert_eq!(RouteKey::region(rid), RouteKey::Region(rid));
    }

    #[test]
    fn dispatch_strategy_debug_clone_copy_eq_default() {
        let s = DispatchStrategy::default();
        assert_eq!(s, DispatchStrategy::Unicast);
        let s2 = s;
        assert_eq!(s, s2);
        assert!(format!("{s:?}").contains("Unicast"));
    }

    #[test]
    fn dispatch_config_debug_clone_default() {
        let cfg = DispatchConfig::default();
        let cfg2 = cfg;
        assert_eq!(cfg2.max_retries, 3);
        assert!(format!("{cfg2:?}").contains("DispatchConfig"));
    }

    #[test]
    fn dispatcher_stats_debug() {
        let stats = DispatcherStats {
            active_dispatches: 0,
            total_dispatched: 100,
            total_failures: 5,
        };
        let dbg = format!("{stats:?}");
        assert!(dbg.contains("100"));
    }

    #[test]
    fn routing_error_debug_clone() {
        let err = RoutingError::EmptyTable;
        let err2 = err;
        assert!(format!("{err2:?}").contains("EmptyTable"));
    }

    #[test]
    fn routing_error_display_all_variants() {
        let oid = ObjectId::new_for_test(1);
        let e1 = RoutingError::NoRoute {
            object_id: oid,
            reason: "gone".into(),
        };
        assert!(e1.to_string().contains("no route"));
        assert!(e1.to_string().contains("gone"));

        let e2 = RoutingError::NoHealthyEndpoints { object_id: oid };
        assert!(e2.to_string().contains("healthy"));

        let e3 = RoutingError::EmptyTable;
        assert!(e3.to_string().contains("empty"));
    }

    #[test]
    fn routing_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(RoutingError::EmptyTable);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn dispatch_error_debug_clone() {
        let err = DispatchError::Timeout;
        let err2 = err;
        assert!(format!("{err2:?}").contains("Timeout"));
    }

    #[test]
    fn dispatch_error_display_all_variants() {
        let e1 = DispatchError::RoutingFailed(RoutingError::EmptyTable);
        assert!(e1.to_string().contains("routing failed"));

        let e2 = DispatchError::SendFailed {
            endpoint: EndpointId::new(3),
            reason: "down".into(),
        };
        assert!(e2.to_string().contains("send"));

        let e3 = DispatchError::NoEndpoints;
        assert!(e3.to_string().contains("no endpoints"));

        let e4 = DispatchError::InsufficientEndpoints {
            available: 1,
            required: 3,
        };
        assert!(e4.to_string().contains("insufficient"));

        let e5 = DispatchError::Timeout;
        assert!(e5.to_string().contains("timeout"));
    }

    #[test]
    fn dispatch_error_from_routing_error() {
        let re = RoutingError::EmptyTable;
        let de = DispatchError::from(re);
        assert!(matches!(de, DispatchError::RoutingFailed(_)));
    }

    #[test]
    fn dispatch_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(DispatchError::Timeout);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn routing_entry_with_priority() {
        let entry = RoutingEntry::new(vec![], Time::ZERO).with_priority(10);
        assert_eq!(entry.priority, 10);
    }

    #[test]
    fn routing_entry_select_endpoint_empty() {
        let entry = RoutingEntry::new(vec![], Time::ZERO);
        assert!(entry.select_endpoint(None).is_none());
    }

    #[test]
    fn load_balancer_debug() {
        let lb = LoadBalancer::new(LoadBalanceStrategy::Random);
        assert!(format!("{lb:?}").contains("Random"));
    }

    #[test]
    fn routing_table_debug() {
        let table = RoutingTable::new();
        assert!(format!("{table:?}").contains("RoutingTable"));
    }
}
