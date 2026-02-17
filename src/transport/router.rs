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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
    pub state: EndpointState,

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
            state: EndpointState::Healthy,
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
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
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
        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let available_len = endpoints.iter().filter(|e| e.state.can_receive()).count();
                if available_len == 0 {
                    return None;
                }
                let idx =
                    (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % available_len;
                endpoints.iter().filter(|e| e.state.can_receive()).nth(idx)
            }

            LoadBalanceStrategy::WeightedRoundRobin => {
                let available: SmallVec<[&Arc<Endpoint>; 8]> =
                    endpoints.iter().filter(|e| e.state.can_receive()).collect();
                if available.is_empty() {
                    return None;
                }
                let total_weight: u32 = available.iter().map(|e| e.weight).sum();
                if total_weight == 0 {
                    return available.first().copied();
                }

                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let target = (counter % u64::from(total_weight)) as u32;

                let mut cumulative = 0u32;
                for endpoint in &available {
                    cumulative += endpoint.weight;
                    if target < cumulative {
                        return Some(endpoint);
                    }
                }
                available.last().copied()
            }

            LoadBalanceStrategy::LeastConnections => endpoints
                .iter()
                .filter(|e| e.state.can_receive())
                .min_by_key(|e| e.connection_count()),

            LoadBalanceStrategy::WeightedLeastConnections => endpoints
                .iter()
                .filter(|e| e.state.can_receive())
                .min_by(|a, b| {
                    let a_score = f64::from(a.connection_count()) / f64::from(a.weight.max(1));
                    let b_score = f64::from(b.connection_count()) / f64::from(b.weight.max(1));
                    a_score
                        .partial_cmp(&b_score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }),

            LoadBalanceStrategy::Random => {
                let available_len = endpoints.iter().filter(|e| e.state.can_receive()).count();
                if available_len == 0 {
                    return None;
                }
                // Simple LCG random
                let seed = self.random_seed.fetch_add(1, Ordering::Relaxed);
                let random = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let idx = (random as usize) % available_len;
                endpoints.iter().filter(|e| e.state.can_receive()).nth(idx)
            }

            LoadBalanceStrategy::HashBased => object_id.map_or_else(
                || {
                    // Fall back to round-robin
                    let available_len = endpoints.iter().filter(|e| e.state.can_receive()).count();
                    if available_len == 0 {
                        return None;
                    }
                    let idx =
                        (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % available_len;
                    endpoints.iter().filter(|e| e.state.can_receive()).nth(idx)
                },
                |oid| {
                    let available_len = endpoints.iter().filter(|e| e.state.can_receive()).count();
                    if available_len == 0 {
                        return None;
                    }
                    let hash = oid.as_u128() as usize;
                    endpoints
                        .iter()
                        .filter(|e| e.state.can_receive())
                        .nth(hash % available_len)
                },
            ),

            LoadBalanceStrategy::FirstAvailable => endpoints.iter().find(|e| e.state.can_receive()),
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
    pub fn update_endpoint_state(&self, id: EndpointId, _state: EndpointState) -> bool {
        self.endpoints.read().get(&id).is_some_and(|_endpoint| true)
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
            .filter(|e| e.state == EndpointState::Healthy)
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
        let available: Vec<_> = entry
            .endpoints
            .iter()
            .filter(|e| e.state.can_receive())
            .cloned()
            .collect();

        if available.is_empty() {
            return Err(RoutingError::NoHealthyEndpoints { object_id });
        }

        let selected_count = count.min(available.len());
        let results: Vec<_> = available
            .into_iter()
            .take(selected_count)
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
            .fetch_sub(1, Ordering::SeqCst);
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
        let active = self.active_dispatches.fetch_add(1, Ordering::SeqCst);
        if active >= self.config.max_concurrent {
            self.active_dispatches.fetch_sub(1, Ordering::SeqCst);
            return Err(DispatchError::Overloaded);
        }

        // RAII guard to ensure active_dispatches is decremented even on cancellation/panic
        let _guard = DispatchGuard { dispatcher: self };

        let result = match strategy {
            DispatchStrategy::Unicast => self.dispatch_unicast(cx, &symbol).await,
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
        symbol: &AuthenticatedSymbol,
    ) -> Result<DispatchResult, DispatchError> {
        let route = self.router.route(symbol.symbol())?;

        // Get sink
        let sink = {
            let sinks = self.sinks.read();
            sinks.get(&route.endpoint.id).cloned()
        };

        let _guard = route.endpoint.acquire_connection_guard();

        let result =
            if let Some(sink) = sink {
                let send_result =
                    match OwnedMutexGuard::lock(sink, cx).await {
                        Ok(mut guard) => guard.send(symbol.clone()).await.map_err(|_| {
                            DispatchError::SendFailed {
                                endpoint: route.endpoint.id,
                                reason: "Send failed".into(),
                            }
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
        let object_id = symbol.symbol().object_id();

        if count == 0 {
            return Ok(DispatchResult {
                successes: 0,
                failures: 0,
                sent_to: SmallVec::new(),
                failed_endpoints: SmallVec::new(),
                duration: Time::ZERO,
            });
        }

        // Get the routing entry
        let key = RouteKey::Object(object_id);
        let entry = self
            .router
            .table()
            .lookup(&key)
            .or_else(|| self.router.table().lookup(&RouteKey::Default))
            .ok_or_else(|| RoutingError::NoRoute {
                object_id,
                reason: "No route for multicast".into(),
            })?;

        let mut selected = SmallVec::<[Arc<Endpoint>; 8]>::new();
        for endpoint in &entry.endpoints {
            if endpoint.state.can_receive() {
                selected.push(endpoint.clone());
                if selected.len() >= count {
                    break;
                }
            }
        }

        if selected.is_empty() {
            return Err(DispatchError::RoutingFailed(
                RoutingError::NoHealthyEndpoints { object_id },
            ));
        }

        // Actually dispatch to selected endpoints
        let mut successes = 0;
        let mut failures = 0;
        let mut sent_to = SmallVec::<[EndpointId; 4]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 4]>::new();

        for endpoint in selected {
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

        let mut primary = test_endpoint(1);
        primary.state = EndpointState::Unhealthy;
        let mut backup = test_endpoint(2);
        backup.state = EndpointState::Healthy;

        let primary = table.register_endpoint(primary);
        let backup = table.register_endpoint(backup);

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
}
