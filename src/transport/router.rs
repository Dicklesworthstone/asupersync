//! Symbol routing and dispatch infrastructure.
//!
//! This module provides the routing layer for symbol transmission:
//! - `RoutingTable`: Maps ObjectId/RegionId to endpoints
//! - `SymbolRouter`: Resolves destinations for symbols
//! - `SymbolDispatcher`: Sends symbols to resolved destinations
//! - Load balancing strategies: round-robin, weighted, least-connections

use crate::cx::Cx;
use crate::distributed::encoding::PathQualitySnapshot;
use crate::error::{Error, ErrorKind};
#[cfg(feature = "messaging-fabric")]
use crate::messaging::capability::FabricCapability;
use crate::security::authenticated::AuthenticatedSymbol;
use crate::sync::Mutex;
use crate::sync::OwnedMutexGuard;
use crate::transport::sink::{SymbolSink, SymbolSinkExt};
use crate::types::symbol::{ObjectId, Symbol};
use crate::types::{RegionId, TaskId, Time};
use parking_lot::{Mutex as ParkingMutex, RwLock};
use smallvec::{SmallVec, smallvec};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

type EndpointSinkMap = HashMap<EndpointId, Arc<EndpointSinkSlot>>;

struct EndpointSinkSlot {
    sink: Arc<Mutex<Box<dyn SymbolSink>>>,
    active_sender: ParkingMutex<Option<TaskId>>,
}

impl EndpointSinkSlot {
    fn new(sink: Box<dyn SymbolSink>) -> Self {
        Self {
            sink: Arc::new(Mutex::new(sink)),
            active_sender: ParkingMutex::new(None),
        }
    }

    fn is_active_for(&self, task: TaskId) -> bool {
        self.active_sender
            .lock()
            .is_some_and(|active| active == task)
    }

    fn mark_active(&self, task: TaskId) -> EndpointSinkActiveGuard<'_> {
        let previous = self.active_sender.lock().replace(task);
        debug_assert!(
            previous.is_none(),
            "endpoint sink owner should be empty once the sink mutex is acquired"
        );
        EndpointSinkActiveGuard { slot: self, task }
    }
}

struct EndpointSinkActiveGuard<'a> {
    slot: &'a EndpointSinkSlot,
    task: TaskId,
}

impl Drop for EndpointSinkActiveGuard<'_> {
    fn drop(&mut self) {
        let mut active = self.slot.active_sender.lock();
        if active.is_some_and(|task| task == self.task) {
            *active = None;
        }
    }
}

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
        // br-asupersync-4p3xds: Use Release ordering to prevent race conditions
        self.state.store(state.as_u8(), Ordering::Release);
        self
    }

    /// Returns the current endpoint state.
    #[must_use]
    pub fn state(&self) -> EndpointState {
        // br-asupersync-4p3xds: Use Acquire ordering to synchronize with Release stores
        EndpointState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Updates the endpoint state.
    ///
    /// **Security**: This method should only be called by authorized components
    /// to prevent endpoint state manipulation attacks (br-asupersync-4p3xds).
    pub fn set_state(&self, state: EndpointState) {
        // br-asupersync-4p3xds: Use Release ordering to prevent race conditions
        // during routing decisions. Ensures visibility of state changes.
        self.state.store(state.as_u8(), Ordering::Release);
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
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
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

    /// Exports endpoint failure telemetry for adaptive RaptorQ block layout.
    ///
    /// Routers do not own RTT or reorder estimators, so callers pass the
    /// replayable RTT/reorder observations from their probe or transport layer;
    /// this method contributes the endpoint failure-rate EWMA as the loss input.
    #[must_use]
    pub fn encoding_path_quality(
        &self,
        rtt_ewma_ms: u32,
        reorder_depth: u16,
    ) -> PathQualitySnapshot {
        PathQualitySnapshot::from_loss_rate(rtt_ewma_ms, self.failure_rate(), reorder_depth)
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

    /// Hash-based selection that skips over-capacity primaries when possible.
    BoundedLoadHash,

    /// Always use first available endpoint.
    FirstAvailable,
}

/// Capacity policy for [`LoadBalanceStrategy::BoundedLoadHash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLoadConfig {
    /// Extra headroom above the endpoint's weighted capacity, in permille.
    pub epsilon_milli: u32,

    /// Minimum capacity for every dispatchable endpoint.
    pub min_capacity: u32,

    /// Active-operation slots represented by each endpoint weight unit.
    pub capacity_per_weight: u32,
}

impl Default for BoundedLoadConfig {
    fn default() -> Self {
        Self {
            epsilon_milli: 250,
            min_capacity: 1,
            capacity_per_weight: 1,
        }
    }
}

impl BoundedLoadConfig {
    /// Creates a bounded-load capacity policy.
    ///
    /// **Security**: Validates configuration parameters to prevent overflow attacks
    /// (br-asupersync-qfgsh1). Clamps values to safe ranges.
    #[must_use]
    pub const fn new(epsilon_milli: u32, min_capacity: u32, capacity_per_weight: u32) -> Self {
        // br-asupersync-qfgsh1: Clamp parameters to safe ranges to prevent overflow attacks
        const MAX_EPSILON_MILLI: u32 = 5_000; // Max 500% overhead
        const MAX_MIN_CAPACITY: u32 = 10_000; // Reasonable minimum capacity limit
        const MAX_CAPACITY_PER_WEIGHT: u32 = 1_000; // Reasonable scaling factor

        Self {
            epsilon_milli: if epsilon_milli > MAX_EPSILON_MILLI {
                MAX_EPSILON_MILLI
            } else {
                epsilon_milli
            },
            min_capacity: if min_capacity > MAX_MIN_CAPACITY {
                MAX_MIN_CAPACITY
            } else {
                min_capacity
            },
            capacity_per_weight: if capacity_per_weight > MAX_CAPACITY_PER_WEIGHT {
                MAX_CAPACITY_PER_WEIGHT
            } else {
                capacity_per_weight
            },
        }
    }

    /// Computes the current capacity for an endpoint.
    ///
    /// **Security**: Validates inputs and fails safely on overflow to prevent
    /// routing bypass attacks (br-asupersync-qfgsh1). Returns reasonable capacity
    /// limits instead of silently allowing unlimited connections.
    #[must_use]
    pub fn capacity_for(&self, endpoint: &Endpoint) -> u32 {
        // br-asupersync-qfgsh1: Validate endpoint weight to prevent overflow attacks
        const MAX_SAFE_WEIGHT: u32 = 10_000; // Reasonable upper bound
        const MAX_SAFE_EPSILON_MILLI: u32 = 5_000; // Max 500% overhead
        const MAX_SAFE_CAPACITY_PER_WEIGHT: u32 = 1_000; // Reasonable scaling

        let safe_weight = endpoint.weight.clamp(1, MAX_SAFE_WEIGHT);
        let safe_epsilon = self.epsilon_milli.min(MAX_SAFE_EPSILON_MILLI);
        let safe_capacity_per_weight = self
            .capacity_per_weight
            .clamp(1, MAX_SAFE_CAPACITY_PER_WEIGHT);

        // br-asupersync-qfgsh1: Use checked arithmetic to detect overflow attempts
        let base = match safe_weight.checked_mul(safe_capacity_per_weight) {
            Some(result) => result,
            None => {
                // Overflow detected - return bounded capacity instead of unlimited
                return self.min_capacity.clamp(1, 1_000); // Bounded fallback
            }
        };

        let scale = 1_000_u64.saturating_add(u64::from(safe_epsilon));

        // br-asupersync-qfgsh1: Use checked arithmetic for scaling calculation
        let scaled_u64 = match u64::from(base).checked_mul(scale) {
            Some(product) => product.div_ceil(1_000),
            None => {
                // Overflow detected in scaling - return bounded capacity
                return self.min_capacity.clamp(1, 1_000); // Bounded fallback
            }
        };

        // br-asupersync-qfgsh1: Safely convert back to u32 with reasonable upper bound
        let final_capacity = match u32::try_from(scaled_u64) {
            Ok(capacity) if capacity <= 100_000 => capacity, // Reasonable upper limit
            _ => {
                // Value too large or conversion failed - use bounded capacity
                self.min_capacity.clamp(1, 1_000) // Bounded fallback
            }
        };

        final_capacity.max(self.min_capacity.max(1))
    }

    #[inline]
    fn accepts(&self, endpoint: &Endpoint) -> bool {
        endpoint.connection_count() < self.capacity_for(endpoint)
    }
}

/// Why a bounded-load hash decision selected its endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedLoadRebalanceReason {
    /// No endpoint could receive traffic.
    NoHealthyEndpoints,

    /// No object ID was available, so hash placement was not possible.
    NoObjectIdFallback,

    /// The HRW primary was below its bounded-load capacity.
    PrimaryWithinCapacity,

    /// The HRW primary was over capacity and traffic moved to the next eligible endpoint.
    PrimaryOverCapacityRebalanced,

    /// Every endpoint was over capacity, so the HRW primary was retained as a safe fallback.
    AllEndpointsOverCapacityFallback,
}

impl BoundedLoadRebalanceReason {
    /// Stable identifier for structured routing decision logs.
    #[must_use]
    pub const fn reason_id(self) -> &'static str {
        match self {
            Self::NoHealthyEndpoints => "no-healthy-endpoints",
            Self::NoObjectIdFallback => "no-object-id-fallback",
            Self::PrimaryWithinCapacity => "primary-within-capacity",
            Self::PrimaryOverCapacityRebalanced => "primary-over-capacity-rebalanced",
            Self::AllEndpointsOverCapacityFallback => "all-endpoints-over-capacity-fallback",
        }
    }
}

/// Per-endpoint bounded-load telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedLoadEndpointTelemetry {
    /// Endpoint being evaluated.
    pub endpoint_id: EndpointId,

    /// Current active-operation load.
    pub actual_load: u32,

    /// Capacity after applying weight, epsilon, and minimum-capacity policy.
    pub capacity: u32,

    /// Whether this endpoint was below capacity at decision time.
    pub within_capacity: bool,

    /// Whether this endpoint was the original HRW primary.
    pub is_primary: bool,

    /// Whether this endpoint was selected.
    pub is_selected: bool,
}

/// Bounded-load hash routing decision for deterministic operator evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedLoadDecision {
    /// Endpoint selected by bounded-load routing, if any.
    pub selected: Option<EndpointId>,

    /// Endpoint selected by plain HRW before applying the capacity gate.
    pub primary: Option<EndpointId>,

    /// Reason for the selected endpoint.
    pub reason: BoundedLoadRebalanceReason,

    /// Per-node load/capacity facts sorted by endpoint id.
    pub endpoints: Vec<BoundedLoadEndpointTelemetry>,
}

impl BoundedLoadDecision {
    /// Stable identifier for the decision surface.
    pub const DECISION_ID: &'static str = "transport.bounded-load-hash.v1";

    /// Stable identifier for the bounded-load fairness policy.
    pub const FAIRNESS_POLICY_ID: &'static str = "hrw-bounded-load";

    /// Stable identifier for the rebalance reason.
    #[must_use]
    pub const fn reason_id(&self) -> &'static str {
        self.reason.reason_id()
    }

    /// Endpoint alternatives that were considered but not selected.
    #[must_use]
    pub fn rejected_endpoint_ids(&self) -> SmallVec<[EndpointId; 16]> {
        self.endpoints
            .iter()
            .filter(|endpoint| !endpoint.is_selected)
            .map(|endpoint| endpoint.endpoint_id)
            .collect()
    }

    #[allow(dead_code)]
    fn format_optional_endpoint_id(endpoint_id: Option<EndpointId>) -> String {
        endpoint_id.map_or_else(String::new, |endpoint_id| endpoint_id.to_string())
    }

    /// br-asupersync-36grbm: Buckets counts to prevent exact enumeration timing attacks.
    /// Returns approximate ranges instead of exact values to limit reconnaissance.
    fn bucket_count(count: usize) -> &'static str {
        // Use logarithmic buckets to provide operational visibility while preventing
        // exact fingerprinting. Constant-time operation prevents timing side channels.
        match count {
            0 => "0",
            1..=2 => "1-2",
            3..=5 => "3-5",
            6..=10 => "6-10",
            11..=20 => "11-20",
            21..=50 => "21-50",
            51..=100 => "51-100",
            101..=200 => "101-200",
            201..=500 => "201-500",
            _ => "500+",
        }
    }

    // br-asupersync-36grbm: Removed format_endpoint_ids() to prevent endpoint ID exposure
    // in logs, which enabled reconnaissance attacks.

    fn format_endpoint_pressure(endpoints: &[BoundedLoadEndpointTelemetry]) -> String {
        // br-asupersync-36grbm: Use aggregated pressure metrics to prevent timing attacks
        // and reconnaissance. Avoid exposing exact endpoint IDs, loads, or capacities.
        let total = endpoints.len();
        let within_capacity = endpoints.iter().filter(|e| e.within_capacity).count();
        let over_capacity = total - within_capacity;

        // Use bucketed aggregates instead of exact values to prevent fingerprinting
        format!(
            "total_bucket={};within_capacity_bucket={};over_capacity_bucket={}",
            Self::bucket_count(total),
            Self::bucket_count(within_capacity),
            Self::bucket_count(over_capacity)
        )
    }

    #[allow(dead_code)]
    fn format_fairness_state(
        &self,
        rejected_endpoint_count: usize,
        overloaded_endpoint_count: usize,
        within_capacity_endpoint_count: usize,
    ) -> String {
        let primary_endpoint_id = Self::format_optional_endpoint_id(self.primary);
        let selected_endpoint_id = Self::format_optional_endpoint_id(self.selected);
        let available_endpoint_count = self.endpoints.len();
        format!(
            "policy={};primary={primary_endpoint_id};selected={selected_endpoint_id};available={available_endpoint_count};rejected={rejected_endpoint_count};overloaded={overloaded_endpoint_count};within_capacity={within_capacity_endpoint_count}",
            Self::FAIRNESS_POLICY_ID
        )
    }

    /// br-asupersync-36grbm: Bucketed version of fairness state formatting to prevent timing attacks.
    fn format_fairness_state_bucketed(
        &self,
        rejected_endpoint_count: usize,
        overloaded_endpoint_count: usize,
        within_capacity_endpoint_count: usize,
    ) -> String {
        // br-asupersync-36grbm: Use boolean indicators instead of endpoint IDs to prevent reconnaissance
        let primary_selected = self.primary.is_some();
        let selection_occurred = self.selected.is_some();
        let available_bucket = Self::bucket_count(self.endpoints.len());
        let rejected_bucket = Self::bucket_count(rejected_endpoint_count);
        let overloaded_bucket = Self::bucket_count(overloaded_endpoint_count);
        let within_capacity_bucket = Self::bucket_count(within_capacity_endpoint_count);

        format!(
            "policy={};primary_selected={primary_selected};selection_occurred={selection_occurred};available_bucket={available_bucket};rejected_bucket={rejected_bucket};overloaded_bucket={overloaded_bucket};within_capacity_bucket={within_capacity_bucket}",
            Self::FAIRNESS_POLICY_ID
        )
    }

    /// Serializes the decision into stable key/value fields for logs or artifacts.
    ///
    /// **Security**: Uses bucketed aggregates to prevent timing attacks and reconnaissance
    /// (br-asupersync-36grbm). Sensitive endpoint IDs and exact counts are omitted.
    #[must_use]
    pub fn log_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();

        // br-asupersync-36grbm: Calculate counts in constant time to prevent timing side channels
        let rejected_count = self.endpoints.iter().filter(|e| !e.is_selected).count();
        let overloaded_count = self.endpoints.iter().filter(|e| !e.within_capacity).count();
        let within_capacity_count = self.endpoints.len() - overloaded_count;

        fields.insert("decision_id".to_owned(), Self::DECISION_ID.to_owned());
        fields.insert(
            "fairness_policy_id".to_owned(),
            Self::FAIRNESS_POLICY_ID.to_owned(),
        );

        // br-asupersync-36grbm: Use bucketed counts to prevent exact enumeration attacks
        fields.insert(
            "fairness_state".to_owned(),
            self.format_fairness_state_bucketed(
                rejected_count,
                overloaded_count,
                within_capacity_count,
            ),
        );
        fields.insert("strategy_id".to_owned(), "bounded-load-hash".to_owned());

        // br-asupersync-36grbm: Omit specific endpoint IDs to prevent reconnaissance
        // Only log whether selection occurred (boolean) not which endpoint
        fields.insert(
            "selection_occurred".to_owned(),
            self.selected.is_some().to_string(),
        );
        fields.insert(
            "primary_selection_occurred".to_owned(),
            self.primary.is_some().to_string(),
        );
        fields.insert("rebalance_reason".to_owned(), self.reason_id().to_owned());

        // br-asupersync-36grbm: Replace exact counts with bucketed ranges
        fields.insert(
            "available_endpoint_bucket".to_owned(),
            Self::bucket_count(self.endpoints.len()).to_owned(),
        );
        fields.insert(
            "rejected_endpoint_bucket".to_owned(),
            Self::bucket_count(rejected_count).to_owned(),
        );
        fields.insert(
            "overloaded_endpoint_bucket".to_owned(),
            Self::bucket_count(overloaded_count).to_owned(),
        );
        fields.insert(
            "within_capacity_endpoint_bucket".to_owned(),
            Self::bucket_count(within_capacity_count).to_owned(),
        );

        // br-asupersync-36grbm: Use aggregated pressure metrics instead of detailed snapshots
        fields.insert(
            "endpoint_pressure_aggregate".to_owned(),
            Self::format_endpoint_pressure(self.endpoints.as_slice()),
        );
        fields
    }
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

    /// br-asupersync-is96u6: 256-bit cryptographic salt for hash ring security.
    /// Upgraded from weak 64-bit salt to defeat collision attacks. Uses
    /// cryptographically secure entropy with domain separation to prevent
    /// cross-deployment attacks and birthday paradox exploits.
    ///
    /// Previous vulnerability: 64-bit salt enabled collision attacks with
    /// 2^32 complexity (birthday paradox). Attackers could craft ObjectIds
    /// that all route to the same endpoint, causing DoS.
    ///
    /// Current security: 256-bit entropy raises collision resistance to
    /// 2^128 complexity, making practical attacks infeasible.
    hash_ring_salt: crate::util::entropy::CryptoSalt,

    /// Capacity policy used by [`LoadBalanceStrategy::BoundedLoadHash`].
    bounded_load_config: BoundedLoadConfig,
}

impl LoadBalancer {
    const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;
    const LCG_INCREMENT: u64 = 1;
    const RANDOM_FLOYD_SMALL_N_MAX: usize = 8;

    #[inline]
    fn next_lcg(seed: u64) -> u64 {
        seed.wrapping_mul(Self::LCG_MULTIPLIER)
            .wrapping_add(Self::LCG_INCREMENT)
    }

    #[inline]
    fn compare_weighted_load(a: &Endpoint, b: &Endpoint) -> std::cmp::Ordering {
        let a_conn = u64::from(a.connection_count());
        let b_conn = u64::from(b.connection_count());
        let a_weight = u64::from(a.weight.max(1));
        let b_weight = u64::from(b.weight.max(1));
        (a_conn * b_weight).cmp(&(b_conn * a_weight))
    }

    #[inline]
    fn select_ranked_prefix<'a, F>(
        available: Vec<&'a Arc<Endpoint>>,
        n: usize,
        mut cmp: F,
    ) -> Vec<&'a Arc<Endpoint>>
    where
        F: FnMut(&(usize, &'a Arc<Endpoint>), &(usize, &'a Arc<Endpoint>)) -> std::cmp::Ordering,
    {
        if n == 0 || available.is_empty() {
            return Vec::new();
        }
        if n == 1 {
            let mut best_idx = 0;
            let mut best_ep = available[0];
            for (i, ep) in available.into_iter().enumerate().skip(1) {
                if cmp(&(i, ep), &(best_idx, best_ep)) == std::cmp::Ordering::Less {
                    best_idx = i;
                    best_ep = ep;
                }
            }
            return vec![best_ep];
        }

        let mut ranked: Vec<(usize, &Arc<Endpoint>)> = available.into_iter().enumerate().collect();

        if n < ranked.len() {
            ranked.select_nth_unstable_by(n, |a, b| cmp(a, b));
            ranked.truncate(n);
        }

        ranked.sort_by(|a, b| cmp(a, b));
        ranked.into_iter().map(|(_, endpoint)| endpoint).collect()
    }

    #[inline]
    fn weighted_endpoint_span_for_slot(available: &[&Arc<Endpoint>], slot: u64) -> (usize, u64) {
        let mut cumulative = 0u64;
        for (idx, endpoint) in available.iter().enumerate() {
            cumulative += u64::from(endpoint.weight);
            if slot < cumulative {
                return (idx, cumulative);
            }
        }

        let last_index = available.len().saturating_sub(1);
        (last_index, cumulative)
    }

    /// Unique weighted round-robin selection for multicast/quorum routing.
    ///
    /// `select_n` must return distinct healthy endpoints, but it still needs to
    /// honor the weighted wheel so that repeated multicast/quorum selections keep
    /// preferring higher-weight endpoints instead of silently degrading to plain
    /// round-robin. We walk the weighted ring until we have `n` unique picks,
    /// then fall back to the remaining healthy endpoints only if zero-weight
    /// entries prevented the weighted wheel from producing enough distinct picks.
    fn select_n_weighted_round_robin<'a>(
        &self,
        available: &[&'a Arc<Endpoint>],
        n: usize,
    ) -> Vec<&'a Arc<Endpoint>> {
        let len = available.len();
        let total_weight: u64 = available
            .iter()
            .map(|endpoint| u64::from(endpoint.weight))
            .sum();

        if total_weight == 0 {
            let counter = self.rr_counter.fetch_add(n as u64, Ordering::Relaxed);
            let start = counter as usize;
            return (0..n).map(|i| available[(start + i) % len]).collect();
        }

        loop {
            let counter = self.rr_counter.load(Ordering::Relaxed);
            let mut selected = Vec::with_capacity(n);
            let mut selected_indices = SmallVec::<[usize; 16]>::new();
            let mut slot = counter % total_weight;
            let mut consumed_slots = 0u64;

            while consumed_slots < total_weight {
                let (idx, block_end) = Self::weighted_endpoint_span_for_slot(available, slot);
                let span = block_end - slot;
                if !selected_indices.contains(&idx) {
                    selected_indices.push(idx);
                    selected.push(available[idx]);
                    if selected.len() == n {
                        consumed_slots += 1;
                        break;
                    }
                }

                consumed_slots += span;
                slot = if block_end == total_weight {
                    0
                } else {
                    block_end
                };
            }

            // Fallback: if the weighted walk didn't fill n slots (more
            // endpoints requested than distinct weights), top up from
            // unselected endpoints in round-robin order.
            if selected.len() < n {
                let fallback_start = counter as usize % len;
                for offset in 0..len {
                    let idx = (fallback_start + offset) % len;
                    if selected_indices.contains(&idx) {
                        continue;
                    }
                    selected.push(available[idx]);
                    if selected.len() >= n {
                        break;
                    }
                }
            }

            let next_counter = counter.saturating_add(consumed_slots.max(1));
            if self
                .rr_counter
                .compare_exchange_weak(counter, next_counter, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return selected;
            }
        }
    }

    /// Creates a new load balancer with a cryptographically secure HashRing
    /// salt (br-asupersync-is96u6). Uses 256-bit entropy with domain separation
    /// to prevent collision attacks. Use [`Self::with_test_salt`] in tests/lab
    /// runs where deterministic routing is required.
    #[must_use]
    pub fn new(strategy: LoadBalanceStrategy) -> Self {
        Self::with_crypto_salt(
            strategy,
            crate::util::entropy::CryptoSalt::generate("transport-router"),
        )
    }

    /// Creates a new load balancer with an explicit CryptoSalt.
    /// For production use, prefer [`Self::new`] which generates secure entropy.
    /// (br-asupersync-is96u6)
    #[must_use]
    pub fn with_crypto_salt(
        strategy: LoadBalanceStrategy,
        hash_ring_salt: crate::util::entropy::CryptoSalt,
    ) -> Self {
        Self {
            strategy,
            rr_counter: AtomicU64::new(0),
            random_seed: AtomicU64::new(0),
            hash_ring_salt,
            bounded_load_config: BoundedLoadConfig::default(),
        }
    }

    /// Creates a new load balancer with a deterministic test salt.
    /// Only for use in tests and lab runtime where deterministic routing
    /// is required. Production code MUST use [`Self::new`].
    /// (br-asupersync-is96u6)
    #[must_use]
    pub fn with_test_salt(strategy: LoadBalanceStrategy, test_seed: u64) -> Self {
        Self::with_crypto_salt(
            strategy,
            crate::util::entropy::CryptoSalt::for_test(test_seed, "transport-router-test"),
        )
    }

    /// DEPRECATED: Creates a load balancer with legacy 64-bit salt.
    /// Only for compatibility during migration. New code MUST use
    /// [`Self::new`] or [`Self::with_test_salt`]. (br-asupersync-is96u6)
    #[deprecated(
        since = "0.1.0",
        note = "Use with_test_salt() for tests or new() for production"
    )]
    #[must_use]
    pub fn with_seed(strategy: LoadBalanceStrategy, hash_ring_salt: u64) -> Self {
        Self::with_test_salt(strategy, hash_ring_salt)
    }

    /// Sets the bounded-load capacity policy.
    #[must_use]
    pub fn with_bounded_load_config(mut self, config: BoundedLoadConfig) -> Self {
        self.bounded_load_config = config;
        self
    }

    /// Returns the per-router HashRing salt as 64-bit for compatibility.
    /// Exposed for diagnostics and replay-stability assertions.
    /// For full entropy, use `crypto_salt()`. (br-asupersync-is96u6)
    #[must_use]
    pub fn hash_ring_salt(&self) -> u64 {
        self.hash_ring_salt.as_u64()
    }

    /// Returns the full 256-bit cryptographic salt.
    /// Prefer this over `hash_ring_salt()` for new code. (br-asupersync-is96u6)
    #[must_use]
    pub fn crypto_salt(&self) -> &crate::util::entropy::CryptoSalt {
        &self.hash_ring_salt
    }

    /// Returns the current bounded-load capacity policy.
    #[must_use]
    pub fn bounded_load_config(&self) -> BoundedLoadConfig {
        self.bounded_load_config
    }

    /// Returns deterministic bounded-load routing evidence without mutating counters.
    #[must_use]
    pub fn bounded_load_decision(
        &self,
        endpoints: &[Arc<Endpoint>],
        object_id: Option<ObjectId>,
    ) -> BoundedLoadDecision {
        let mut available = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if endpoint.state().can_receive() {
                available.push(endpoint);
            }
        }
        if available.is_empty() {
            return BoundedLoadDecision {
                selected: None,
                primary: None,
                reason: BoundedLoadRebalanceReason::NoHealthyEndpoints,
                endpoints: Vec::new(),
            };
        }

        let Some(object_id) = object_id else {
            let mut endpoints = self.bounded_load_telemetry(&available, None, None);
            endpoints.sort_unstable_by_key(|telemetry| telemetry.endpoint_id);
            return BoundedLoadDecision {
                selected: None,
                primary: None,
                reason: BoundedLoadRebalanceReason::NoObjectIdFallback,
                endpoints,
            };
        };

        let primary = crate::distributed::consistent_hash::select_hrw(
            available.iter().copied(),
            &object_id.as_u128(),
            self.hash_ring_salt.as_u64(),
            |endpoint| &endpoint.id,
            |endpoint| endpoint.weight.max(1),
        )
        .map(|endpoint| endpoint.id);

        let selected = self
            .select_bounded_load_hash(&available, object_id)
            .map(|endpoint| endpoint.id);

        let reason = match (primary, selected) {
            (None, _) => BoundedLoadRebalanceReason::NoHealthyEndpoints,
            (Some(primary), Some(selected)) if primary == selected => {
                if available
                    .iter()
                    .find(|endpoint| endpoint.id == primary)
                    .is_some_and(|endpoint| self.bounded_load_config.accepts(endpoint))
                {
                    BoundedLoadRebalanceReason::PrimaryWithinCapacity
                } else {
                    BoundedLoadRebalanceReason::AllEndpointsOverCapacityFallback
                }
            }
            (Some(_), Some(_)) => BoundedLoadRebalanceReason::PrimaryOverCapacityRebalanced,
            (Some(_), None) => BoundedLoadRebalanceReason::NoHealthyEndpoints,
        };

        let mut endpoints = self.bounded_load_telemetry(&available, primary, selected);
        endpoints.sort_unstable_by_key(|telemetry| telemetry.endpoint_id);
        BoundedLoadDecision {
            selected,
            primary,
            reason,
            endpoints,
        }
    }

    fn bounded_load_telemetry(
        &self,
        endpoints: &[&Arc<Endpoint>],
        primary: Option<EndpointId>,
        selected: Option<EndpointId>,
    ) -> Vec<BoundedLoadEndpointTelemetry> {
        endpoints
            .iter()
            .map(|endpoint| {
                let actual_load = endpoint.connection_count();
                let capacity = self.bounded_load_config.capacity_for(endpoint);
                BoundedLoadEndpointTelemetry {
                    endpoint_id: endpoint.id,
                    actual_load,
                    capacity,
                    within_capacity: actual_load < capacity,
                    is_primary: primary == Some(endpoint.id),
                    is_selected: selected == Some(endpoint.id),
                }
            })
            .collect()
    }

    fn select_bounded_load_hash<'a>(
        &self,
        available: &[&'a Arc<Endpoint>],
        object_id: ObjectId,
    ) -> Option<&'a Arc<Endpoint>> {
        let key = object_id.as_u128();
        let primary = crate::distributed::consistent_hash::select_hrw(
            available.iter().copied(),
            &key,
            self.hash_ring_salt.as_u64(),
            |endpoint| &endpoint.id,
            |endpoint| endpoint.weight.max(1),
        );
        let eligible = crate::distributed::consistent_hash::select_hrw(
            available
                .iter()
                .copied()
                .filter(|endpoint| self.bounded_load_config.accepts(endpoint)),
            &key,
            self.hash_ring_salt.as_u64(),
            |endpoint| &endpoint.id,
            |endpoint| endpoint.weight.max(1),
        );
        eligible.or(primary)
    }

    fn select_n_bounded_load_hash<'a>(
        &self,
        available: &[&'a Arc<Endpoint>],
        count: usize,
        object_id: ObjectId,
    ) -> Vec<&'a Arc<Endpoint>> {
        if count == 0 {
            return Vec::new();
        }

        let key = object_id.as_u128();
        let eligible = available
            .iter()
            .copied()
            .filter(|endpoint| self.bounded_load_config.accepts(endpoint));
        let mut selected = crate::distributed::consistent_hash::select_top_k_hrw(
            eligible,
            count,
            &key,
            self.hash_ring_salt.as_u64(),
            |endpoint| &endpoint.id,
            |endpoint| endpoint.weight.max(1),
        );

        if selected.len() >= count {
            return selected;
        }

        let mut selected_ids = SmallVec::<[EndpointId; 16]>::new();
        selected_ids.extend(selected.iter().map(|endpoint| endpoint.id));
        let remaining = count - selected.len();
        let mut fallback = crate::distributed::consistent_hash::select_top_k_hrw(
            available
                .iter()
                .copied()
                .filter(|endpoint| !selected_ids.contains(&endpoint.id)),
            remaining,
            &key,
            self.hash_ring_salt.as_u64(),
            |endpoint| &endpoint.id,
            |endpoint| endpoint.weight.max(1),
        );
        selected.append(&mut fallback);
        selected
    }

    /// Selects an endpoint based on the routing strategy.
    #[allow(clippy::too_many_lines)]
    pub fn select<'a>(
        &self,
        endpoints: &'a [Arc<Endpoint>],
        object_id: Option<ObjectId>,
    ) -> Option<&'a Arc<Endpoint>> {
        if endpoints.is_empty() {
            return None;
        }

        match self.strategy {
            LoadBalanceStrategy::Random => {
                self.select_random_single_without_materializing(endpoints)
            }
            LoadBalanceStrategy::LeastConnections => {
                let mut best = None;
                let mut best_count = u32::MAX;
                for ep in endpoints {
                    if ep.state().can_receive() {
                        let count = ep.connection_count();
                        if best.is_none() || count < best_count {
                            best_count = count;
                            best = Some(ep);
                            if count == 0 {
                                break;
                            }
                        }
                    }
                }
                best
            }
            LoadBalanceStrategy::WeightedLeastConnections => {
                let mut best = None;
                let mut best_score = None;
                for ep in endpoints {
                    if ep.state().can_receive() {
                        let count = u64::from(ep.connection_count());
                        let weight = u64::from(ep.weight.max(1));

                        let is_better = match best_score {
                            None => true,
                            Some((best_count_u64, best_weight_u64)) => {
                                (count * best_weight_u64) < (best_count_u64 * weight)
                            }
                        };
                        if is_better {
                            best_score = Some((count, weight));
                            best = Some(ep);
                            if count == 0 {
                                break;
                            }
                        }
                    }
                }
                best
            }
            LoadBalanceStrategy::RoundRobin => {
                let count = endpoints.iter().filter(|e| e.state().can_receive()).count();
                if count == 0 {
                    return None;
                }
                let target = (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % count;
                endpoints
                    .iter()
                    .filter(|e| e.state().can_receive())
                    .nth(target)
                    .or_else(|| endpoints.iter().find(|e| e.state().can_receive()))
            }
            LoadBalanceStrategy::WeightedRoundRobin => {
                let total_weight: u64 = endpoints
                    .iter()
                    .filter(|e| e.state().can_receive())
                    .map(|e| u64::from(e.weight))
                    .sum();
                if total_weight == 0 {
                    return endpoints.iter().find(|e| e.state().can_receive());
                }

                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let target = counter % total_weight;

                let mut cumulative = 0u64;
                for endpoint in endpoints {
                    if endpoint.state().can_receive() {
                        cumulative += u64::from(endpoint.weight);
                        if target < cumulative {
                            return Some(endpoint);
                        }
                    }
                }
                endpoints.iter().rfind(|e| e.state().can_receive())
            }
            LoadBalanceStrategy::HashBased => {
                // br-asupersync-v535in: preserve sticky routing under
                // membership churn by scoring healthy endpoints
                // directly with salted rendezvous hashing instead of
                // modulo arithmetic over a counted slice.
                let healthy: Vec<&Arc<Endpoint>> = endpoints
                    .iter()
                    .filter(|e| e.state().can_receive())
                    .collect();
                if healthy.is_empty() {
                    return None;
                }
                object_id.map_or_else(
                    || {
                        // No object_id supplied — fall back to RR
                        // (modulo here is fine; there's no
                        // stickiness contract to preserve).
                        let idx = (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize)
                            % healthy.len();
                        Some(healthy[idx])
                    },
                    |oid| {
                        crate::distributed::consistent_hash::select_hrw(
                            healthy.iter().copied(),
                            &oid.as_u128(),
                            self.hash_ring_salt.as_u64(),
                            |endpoint| &endpoint.id,
                            |endpoint| endpoint.weight.max(1),
                        )
                    },
                )
            }
            LoadBalanceStrategy::BoundedLoadHash => {
                let healthy: Vec<&Arc<Endpoint>> = endpoints
                    .iter()
                    .filter(|e| e.state().can_receive())
                    .collect();
                if healthy.is_empty() {
                    return None;
                }
                object_id.map_or_else(
                    || {
                        let idx = (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize)
                            % healthy.len();
                        Some(healthy[idx])
                    },
                    |oid| self.select_bounded_load_hash(&healthy, oid),
                )
            }
            LoadBalanceStrategy::FirstAvailable => {
                endpoints.iter().find(|e| e.state().can_receive())
            }
        }
    }

    /// Selects multiple endpoints.
    #[allow(clippy::too_many_lines)]
    pub fn select_n<'a>(
        &self,
        endpoints: &'a [Arc<Endpoint>],
        n: usize,
        object_id: Option<ObjectId>,
    ) -> Vec<&'a Arc<Endpoint>> {
        if n == 0 {
            return Vec::new();
        }

        if n == 1 {
            match self.strategy {
                LoadBalanceStrategy::Random => {
                    return self
                        .select_random_single_without_materializing(endpoints)
                        .into_iter()
                        .collect();
                }
                LoadBalanceStrategy::LeastConnections => {
                    let mut best = None;
                    let mut best_count = u32::MAX;
                    for ep in endpoints {
                        if ep.state().can_receive() {
                            let count = ep.connection_count();
                            if best.is_none() || count < best_count {
                                best_count = count;
                                best = Some(ep);
                                if count == 0 {
                                    break;
                                }
                            }
                        }
                    }
                    return best.into_iter().collect();
                }
                LoadBalanceStrategy::WeightedLeastConnections => {
                    let mut best = None;
                    let mut best_score = None;
                    for ep in endpoints {
                        if ep.state().can_receive() {
                            let count = u64::from(ep.connection_count());
                            let weight = u64::from(ep.weight.max(1));

                            let is_better = match best_score {
                                None => true,
                                Some((best_count_u64, best_weight_u64)) => {
                                    (count * best_weight_u64) < (best_count_u64 * weight)
                                }
                            };
                            if is_better {
                                best_score = Some((count, weight));
                                best = Some(ep);
                                if count == 0 {
                                    break;
                                }
                            }
                        }
                    }
                    return best.into_iter().collect();
                }
                _ => {}
            }
        }

        if matches!(self.strategy, LoadBalanceStrategy::Random)
            && n <= Self::RANDOM_FLOYD_SMALL_N_MAX
        {
            if let Some(selected) = self.select_n_random_small_without_materializing(endpoints, n) {
                return selected;
            }
        }

        if n <= 16 {
            match self.strategy {
                LoadBalanceStrategy::LeastConnections => {
                    let mut top_n =
                        smallvec::SmallVec::<[(usize, u32, &'a Arc<Endpoint>); 16]>::new();
                    for (idx, ep) in endpoints.iter().enumerate() {
                        if ep.state().can_receive() {
                            let count = ep.connection_count();
                            if top_n.len() == n {
                                let last = &top_n[n - 1];
                                if last.1 == 0 {
                                    break;
                                }
                                if count > last.1 || (count == last.1 && idx > last.0) {
                                    continue;
                                }
                            }
                            // Insertion sort
                            let mut insert_pos = top_n.len();
                            for i in 0..top_n.len() {
                                if count < top_n[i].1 || (count == top_n[i].1 && idx < top_n[i].0) {
                                    insert_pos = i;
                                    break;
                                }
                            }
                            if insert_pos < n {
                                top_n.insert(insert_pos, (idx, count, ep));
                                if top_n.len() > n {
                                    top_n.pop();
                                }
                            }
                        }
                    }
                    return top_n.into_iter().map(|(_, _, ep)| ep).collect();
                }
                LoadBalanceStrategy::WeightedLeastConnections => {
                    let mut top_n =
                        smallvec::SmallVec::<[(usize, u64, u64, &'a Arc<Endpoint>); 16]>::new();
                    for (idx, ep) in endpoints.iter().enumerate() {
                        if ep.state().can_receive() {
                            let count = u64::from(ep.connection_count());
                            let weight = u64::from(ep.weight.max(1));

                            if top_n.len() == n {
                                let last = &top_n[n - 1];
                                if last.1 == 0 {
                                    break;
                                }
                                let (other_idx, other_count, other_weight, _) = *last;
                                let is_better = (count * other_weight) < (other_count * weight)
                                    || ((count * other_weight) == (other_count * weight)
                                        && idx < other_idx);
                                if !is_better {
                                    continue;
                                }
                            }

                            // Insertion sort
                            let mut insert_pos = top_n.len();
                            for i in 0..top_n.len() {
                                let (other_idx, other_count, other_weight, _) = top_n[i];
                                let is_better = (count * other_weight) < (other_count * weight)
                                    || ((count * other_weight) == (other_count * weight)
                                        && idx < other_idx);
                                if is_better {
                                    insert_pos = i;
                                    break;
                                }
                            }
                            if insert_pos < n {
                                top_n.insert(insert_pos, (idx, count, weight, ep));
                                if top_n.len() > n {
                                    top_n.pop();
                                }
                            }
                        }
                    }
                    return top_n.into_iter().map(|(_, _, _, ep)| ep).collect();
                }
                _ => {}
            }
        }

        // Filter healthy endpoints first.
        // Pre-size from the full endpoint set to avoid repeated growth in mixed-health pools.
        let mut available: Vec<&Arc<Endpoint>> = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            if endpoint.state().can_receive() {
                available.push(endpoint);
            }
        }

        if available.is_empty() {
            return Vec::new();
        }

        let count = n.min(available.len());

        match self.strategy {
            LoadBalanceStrategy::RoundRobin => {
                let start = self.rr_counter.fetch_add(count as u64, Ordering::Relaxed) as usize;
                let len = available.len();
                (0..count).map(|i| available[(start + i) % len]).collect()
            }

            LoadBalanceStrategy::Random => {
                // Fisher-Yates shuffle in-place on the available vector.
                // This avoids allocating a separate indices vector.
                let mut seed = self.random_seed.fetch_add(count as u64, Ordering::Relaxed);
                let len = available.len();

                for i in 0..count {
                    // Simple LCG step
                    seed = Self::next_lcg(seed);
                    // Range is [i, len)
                    let range = len - i;
                    let offset = (seed as usize) % range;
                    let swap_idx = i + offset;
                    available.swap(i, swap_idx);
                }
                available.truncate(count);
                available
            }
            LoadBalanceStrategy::LeastConnections => {
                Self::select_ranked_prefix(available, count, |a, b| {
                    a.1.connection_count()
                        .cmp(&b.1.connection_count())
                        .then(a.0.cmp(&b.0))
                })
            }
            LoadBalanceStrategy::WeightedLeastConnections => {
                Self::select_ranked_prefix(available, count, |a, b| {
                    Self::compare_weighted_load(a.1, b.1).then(a.0.cmp(&b.0))
                })
            }
            LoadBalanceStrategy::HashBased => object_id.map_or_else(
                || {
                    let start_idx =
                        self.rr_counter.fetch_add(count as u64, Ordering::Relaxed) as usize;
                    let len = available.len();
                    (0..count)
                        .map(|i| available[(start_idx + i) % len])
                        .collect()
                },
                |oid| {
                    crate::distributed::consistent_hash::select_top_k_hrw(
                        available.iter().copied(),
                        count,
                        &oid.as_u128(),
                        self.hash_ring_salt.as_u64(),
                        |endpoint| &endpoint.id,
                        |endpoint| endpoint.weight.max(1),
                    )
                },
            ),
            LoadBalanceStrategy::BoundedLoadHash => object_id.map_or_else(
                || {
                    let start_idx =
                        self.rr_counter.fetch_add(count as u64, Ordering::Relaxed) as usize;
                    let len = available.len();
                    (0..count)
                        .map(|i| available[(start_idx + i) % len])
                        .collect()
                },
                |oid| self.select_n_bounded_load_hash(&available, count, oid),
            ),
            LoadBalanceStrategy::WeightedRoundRobin => {
                self.select_n_weighted_round_robin(&available, count)
            }
            LoadBalanceStrategy::FirstAvailable => available.into_iter().take(count).collect(),
        }
    }

    /// Allocation-free random single-endpoint selection.
    ///
    /// Uses one-pass reservoir sampling over healthy endpoints, avoiding the
    /// old two-pass "count then index-select" scan while keeping uniform
    /// selection among observed healthy endpoints.
    fn select_random_single_without_materializing<'a>(
        &self,
        endpoints: &'a [Arc<Endpoint>],
    ) -> Option<&'a Arc<Endpoint>> {
        if endpoints.is_empty() {
            return None;
        }
        let mut seed = self.random_seed.fetch_add(1, Ordering::Relaxed);
        let total = endpoints.len();

        // Rejection sampling: pick random index, check health.
        // For all-healthy pools this succeeds on first attempt.
        let max_attempts = total.min(64);
        for _ in 0..max_attempts {
            seed = Self::next_lcg(seed);
            let idx = (seed as usize) % total;
            if endpoints[idx].state().can_receive() {
                return Some(&endpoints[idx]);
            }
        }

        // Fallback: linear scan for pools with very few healthy endpoints.
        endpoints.iter().find(|ep| ep.state().can_receive())
    }

    /// Small-n random selection using rejection sampling.
    ///
    /// For small n relative to a large endpoint pool, this generates n
    /// random indices and checks health + uniqueness, avoiding both the
    /// O(N)-push materialization and the O(N)-RNG reservoir scan.
    /// Expected attempts for n=3 from 512 all-healthy endpoints: ~3.006.
    /// Falls through to `None` if too many attempts needed (unhealthy-heavy pools).
    fn select_n_random_small_without_materializing<'a>(
        &self,
        endpoints: &'a [Arc<Endpoint>],
        n: usize,
    ) -> Option<Vec<&'a Arc<Endpoint>>> {
        if n == 0 {
            return Some(Vec::new());
        }
        let total = endpoints.len();
        if total == 0 {
            return None;
        }

        let mut seed = self.random_seed.fetch_add(n as u64, Ordering::Relaxed);
        let mut selected = SmallVec::<[usize; Self::RANDOM_FLOYD_SMALL_N_MAX]>::new();
        let max_attempts = n * 4 + 16;
        let mut attempts = 0;

        while selected.len() < n {
            if attempts >= max_attempts {
                return None; // Fall through to general Fisher-Yates path.
            }
            attempts += 1;
            seed = Self::next_lcg(seed);
            let idx = (seed as usize) % total;

            if !endpoints[idx].state().can_receive() {
                continue;
            }
            if selected.contains(&idx) {
                continue;
            }
            selected.push(idx);
        }

        Some(selected.into_iter().map(|i| &endpoints[i]).collect())
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

    /// Sets the bounded-load capacity policy for this route.
    #[must_use]
    pub fn with_bounded_load_config(mut self, config: BoundedLoadConfig) -> Self {
        let load_balancer = LoadBalancer::with_crypto_salt(
            self.load_balancer.strategy,
            *self.load_balancer.crypto_salt(),
        )
        .with_bounded_load_config(config);
        self.load_balancer = Arc::new(load_balancer);
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
            now >= expiry
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
#[derive(Debug, Default)]
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
        Self::default()
    }

    /// Checks that the context has admin-level capabilities for endpoint management.
    ///
    /// br-asupersync-49wynd: Prevents unauthorized endpoint removal DoS attacks.
    /// Admin capabilities are required for destructive routing operations.
    fn require_admin_capability(&self, cx: &Cx) -> Result<(), Error> {
        #[cfg(feature = "messaging-fabric")]
        {
            if cx.check_fabric_capability(&FabricCapability::AdminControl) {
                return Ok(());
            }
        }
        #[cfg(not(feature = "messaging-fabric"))]
        {
            let _ = cx;
        }

        Err(Error::new(ErrorKind::AdmissionDenied)
            .with_message("routing table endpoint administration requires AdminControl capability"))
    }

    /// Registers an endpoint.
    pub fn register_endpoint(&self, endpoint: Endpoint) -> Arc<Endpoint> {
        let id = endpoint.id;
        let arc = Arc::new(endpoint);
        self.endpoints.write().insert(id, arc.clone());
        arc
    }

    /// br-asupersync-mboi13: removes the endpoint with `id` from the
    /// routing table, returning the dropped `Arc<Endpoint>` if it was
    /// present.
    ///
    /// The pre-fix shape registered endpoints via `register_endpoint`
    /// but had no inverse — the `endpoints` HashMap accumulated
    /// `Arc<Endpoint>` entries forever. In long-running services with
    /// dynamic membership (k8s pod churn, blue/green deploys, cloud
    /// autoscaling) every dead endpoint kept its metric counters,
    /// dispatch history, last-success/failure timestamps, and label
    /// maps live — at conservatively 1-2 KiB per entry, ~13 MiB
    /// leaked per ~9000-pod-day workload. This violated the
    /// asupersync 'no obligation leaks' invariant: the routing table
    /// holds Endpoint Arcs that are obligations to dispatch, and
    /// without a removal path those obligations leak.
    ///
    /// Callers invoke this when an endpoint goes permanently offline
    /// (deregistration event from the membership layer, k8s
    /// pod-deleted webhook, etc.). Removal is authoritative: the
    /// endpoint is scrubbed from the side index, every keyed route,
    /// and the default route. Empty routes are pruned so object-route
    /// lookups can fall back to the default route again instead of
    /// getting stuck on an empty stale entry.
    ///
    /// **Security**: Requires admin-level capabilities to prevent unauthorized
    /// endpoint removal DoS attacks (br-asupersync-49wynd).
    pub fn remove_endpoint(&self, cx: &Cx, id: EndpointId) -> Result<Option<Arc<Endpoint>>, Error> {
        // br-asupersync-49wynd: Add admin capability check to prevent DoS attacks
        self.require_admin_capability(cx)?;

        let removed = self.endpoints.write().remove(&id);

        {
            let mut routes = self.routes.write();
            routes.retain(|_, entry| {
                entry.endpoints.retain(|endpoint| endpoint.id != id);
                !entry.endpoints.is_empty()
            });
        }

        {
            let mut default = self.default_route.write();
            if let Some(entry) = default.as_mut() {
                entry.endpoints.retain(|endpoint| endpoint.id != id);
                if entry.endpoints.is_empty() {
                    *default = None;
                }
            }
        }

        Ok(removed)
    }

    /// Gets an endpoint by ID.
    #[must_use]
    pub fn get_endpoint(&self, id: EndpointId) -> Option<Arc<Endpoint>> {
        self.endpoints.read().get(&id).cloned()
    }

    /// Updates endpoint state.
    ///
    /// **Security**: Requires admin-level capabilities to prevent endpoint state
    /// manipulation attacks (br-asupersync-4p3xds).
    pub fn update_endpoint_state(
        &self,
        cx: &Cx,
        id: EndpointId,
        state: EndpointState,
    ) -> Result<bool, Error> {
        // br-asupersync-4p3xds: Add admin capability check to prevent state manipulation DoS
        self.require_admin_capability(cx)?;

        let updated = self.endpoints.read().get(&id).is_some_and(|endpoint| {
            endpoint.set_state(state);
            true
        });
        Ok(updated)
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
    pub fn lookup(&self, key: &RouteKey, now: Time) -> Option<RoutingEntry> {
        // Try exact match first
        if let Some(entry) = self.routes.read().get(key) {
            if !entry.is_expired(now) {
                return Some(entry.clone());
            }
        }

        // Try fallback strategies
        if let RouteKey::ObjectAndRegion(oid, rid) = key {
            // Try object-only
            if let Some(entry) = self.routes.read().get(&RouteKey::Object(*oid)) {
                if !entry.is_expired(now) {
                    return Some(entry.clone());
                }
            }
            // Try region-only
            if let Some(entry) = self.routes.read().get(&RouteKey::Region(*rid)) {
                if !entry.is_expired(now) {
                    return Some(entry.clone());
                }
            }
        }

        // Fall back to default
        self.default_route.read().as_ref().and_then(|entry| {
            if !entry.is_expired(now) {
                Some(entry.clone())
            } else {
                None
            }
        })
    }

    /// Looks up a route without falling back to the default route.
    ///
    /// This preserves object/region fallback behavior for compound keys but
    /// never consults `default_route`.
    #[must_use]
    pub fn lookup_without_default(&self, key: &RouteKey, now: Time) -> Option<RoutingEntry> {
        if let Some(entry) = self.routes.read().get(key) {
            if !entry.is_expired(now) {
                return Some(entry.clone());
            }
        }

        if let RouteKey::ObjectAndRegion(oid, rid) = key {
            if let Some(entry) = self.routes.read().get(&RouteKey::Object(*oid)) {
                if !entry.is_expired(now) {
                    return Some(entry.clone());
                }
            }
            if let Some(entry) = self.routes.read().get(&RouteKey::Region(*rid)) {
                if !entry.is_expired(now) {
                    return Some(entry.clone());
                }
            }
        }

        None
    }

    /// Prunes expired routes, including the default route.
    pub fn prune_expired(&self, now: Time) -> usize {
        let mut routes = self.routes.write();
        let before = routes.len();
        routes.retain(|_, entry| !entry.is_expired(now));
        let mut pruned = before - routes.len();
        drop(routes);

        let mut default = self.default_route.write();
        if default.as_ref().is_some_and(|entry| entry.is_expired(now)) {
            *default = None;
            pruned += 1;
        }
        drop(default);

        pruned
    }

    /// Returns all endpoints that can currently receive traffic in stable ID order.
    #[must_use]
    pub fn dispatchable_endpoints(&self) -> Vec<Arc<Endpoint>> {
        let mut endpoints = self
            .endpoints
            .read()
            .values()
            .filter(|endpoint| endpoint.state().can_receive())
            .cloned()
            .collect::<Vec<_>>();
        endpoints.sort_unstable_by_key(|endpoint| endpoint.id);
        endpoints
    }

    /// Returns route count.
    #[must_use]
    pub fn route_count(&self) -> usize {
        let routes = self.routes.read().len();
        let default = usize::from(self.default_route.read().is_some());
        routes + default
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

    fn local_candidates(&self, entry: &RoutingEntry) -> Vec<Arc<Endpoint>> {
        if !self.prefer_local {
            return Vec::new();
        }
        let Some(local) = self.local_region else {
            return Vec::new();
        };
        entry
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.region == Some(local) && endpoint.state().can_receive())
            .cloned()
            .collect()
    }

    fn select_preferred_endpoint(
        &self,
        entry: &RoutingEntry,
        object_id: ObjectId,
    ) -> Option<Arc<Endpoint>> {
        let local = self.local_candidates(entry);
        if !local.is_empty() {
            return entry.load_balancer.select(&local, Some(object_id)).cloned();
        }
        entry.select_endpoint(Some(object_id))
    }

    fn select_preferred_endpoints(
        &self,
        entry: &RoutingEntry,
        object_id: ObjectId,
        count: usize,
    ) -> Vec<Arc<Endpoint>> {
        let local = self.local_candidates(entry);
        if local.is_empty() {
            return entry.select_endpoints(count, Some(object_id));
        }

        let local_take = local.len().min(count);
        let mut selected = entry
            .load_balancer
            .select_n(&local, local_take, Some(object_id))
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        if selected.len() >= count {
            return selected;
        }

        let Some(local_region) = self.local_region else {
            return entry.select_endpoints(count, Some(object_id));
        };
        let non_local = entry
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.region != Some(local_region) && endpoint.state().can_receive()
            })
            .cloned()
            .collect::<Vec<_>>();

        let remaining = count - selected.len();
        let mut tail = entry
            .load_balancer
            .select_n(&non_local, remaining, Some(object_id))
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        selected.append(&mut tail);
        selected
    }

    /// Routes a symbol to an endpoint.
    pub fn route(&self, symbol: &Symbol, now: Time) -> Result<RouteResult, RoutingError> {
        let object_id = symbol.object_id();
        let primary_key = RouteKey::Object(object_id);

        let primary_entry = self.table.lookup_without_default(&primary_key, now);

        if let Some(entry) = primary_entry.as_ref() {
            if let Some(endpoint) = self.select_preferred_endpoint(entry, object_id) {
                return Ok(RouteResult {
                    endpoint,
                    matched_key: primary_key,
                    is_fallback: false,
                });
            }
        }

        if self.allow_fallback {
            let fallback_key = RouteKey::Default;
            if let Some(entry) = self.table.lookup(&fallback_key, now) {
                if let Some(endpoint) = entry.select_endpoint(Some(object_id)) {
                    return Ok(RouteResult {
                        endpoint,
                        matched_key: fallback_key,
                        is_fallback: true,
                    });
                }
                return Err(RoutingError::NoHealthyEndpoints { object_id });
            }
        }

        if primary_entry.is_some() {
            return Err(RoutingError::NoHealthyEndpoints { object_id });
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
        now: Time,
    ) -> Result<Vec<RouteResult>, RoutingError> {
        let object_id = symbol.object_id();

        let key = RouteKey::Object(object_id);
        let (entry, matched_key, is_fallback) =
            if let Some(entry) = self.table.lookup_without_default(&key, now) {
                (entry, key, false)
            } else if self.allow_fallback {
                let fallback_key = RouteKey::Default;
                let fallback =
                    self.table
                        .lookup(&fallback_key, now)
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
        let endpoints = self.select_preferred_endpoints(&entry, object_id, count);

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
    ///
    /// br-asupersync-dv32fs: inline capacity bumped from 4 → 16. The
    /// pre-fix `[EndpointId; 4]` shape spilled to the heap on every
    /// broadcast/multicast/quorum to 5+ endpoints — typical k8s
    /// service fan-out (10-50 pods) ALWAYS spilled, defeating
    /// SmallVec's purpose entirely. 16 covers the typical
    /// in-process / single-AZ fan-out without spill while keeping
    /// the per-DispatchResult stack footprint bounded
    /// (16 × 8 bytes = 128 bytes inline, comfortably below typical
    /// 8 KiB stack frame budget). Larger fan-outs still spill but
    /// that's the documented tradeoff at this capacity.
    pub sent_to: SmallVec<[EndpointId; 16]>,

    /// Endpoints that failed.
    ///
    /// br-asupersync-dv32fs: inline capacity bumped from 4 → 16
    /// (same rationale as `sent_to`). The failure tuple
    /// `(EndpointId, DispatchError)` is wider than EndpointId alone,
    /// so 16 inline entries cost ~256 bytes inline — still below
    /// any reasonable stack budget.
    pub failed_endpoints: SmallVec<[(EndpointId, DispatchError); 16]>,

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
            .insert(endpoint, Arc::new(EndpointSinkSlot::new(sink)));
    }

    fn send_failed(endpoint: EndpointId) -> DispatchError {
        DispatchError::SendFailed {
            endpoint,
            reason: "Send failed".into(),
        }
    }

    fn reentrant_send_failed(endpoint: EndpointId) -> DispatchError {
        DispatchError::SendFailed {
            endpoint,
            reason: "reentrant dispatch to endpoint from the same task would deadlock".into(),
        }
    }

    async fn send_to_endpoint(
        &self,
        cx: &Cx,
        endpoint: EndpointId,
        symbol: AuthenticatedSymbol,
    ) -> Result<(), DispatchError> {
        let slot = {
            let sinks = self.sinks.read();
            sinks.get(&endpoint).cloned()
        };

        let Some(slot) = slot else {
            // Simulation mode when no concrete sink is registered.
            return Ok(());
        };

        if cx.checkpoint().is_err() {
            return Err(DispatchError::Cancelled);
        }

        let task = cx.task_id();
        if slot.is_active_for(task) {
            return Err(Self::reentrant_send_failed(endpoint));
        }

        match OwnedMutexGuard::lock(Arc::clone(&slot.sink), cx).await {
            Ok(mut guard) => {
                let _active = slot.mark_active(task);
                let guard: &mut Box<dyn SymbolSink> = &mut guard;
                match guard.send(symbol).await {
                    Ok(()) => Ok(()),
                    Err(crate::transport::error::SinkError::Cancelled) => {
                        Err(DispatchError::Cancelled)
                    }
                    Err(crate::transport::error::SinkError::Io { source })
                        if source.kind() == std::io::ErrorKind::Interrupted
                            && cx.checkpoint().is_err() =>
                    {
                        Err(DispatchError::Cancelled)
                    }
                    Err(_) => Err(Self::send_failed(endpoint)),
                }
            }
            Err(crate::sync::LockError::Cancelled) => Err(DispatchError::Cancelled),
            Err(_) => Err(DispatchError::Timeout),
        }
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
        // br-asupersync-kfk19o: see dispatch_multicast for rationale.
        let now_fn = || {
            cx.timer_driver()
                .map_or_else(crate::time::wall_now, |d| d.now())
        };
        let route = self.router.route(symbol.symbol(), now_fn())?;

        let _guard = route.endpoint.acquire_connection_guard();

        match self.send_to_endpoint(cx, route.endpoint.id, symbol).await {
            Ok(()) => {
                route.endpoint.record_success(now_fn());
                Ok(DispatchResult {
                    successes: 1,
                    failures: 0,
                    sent_to: smallvec![route.endpoint.id],
                    failed_endpoints: SmallVec::new(),
                    duration: Time::ZERO,
                })
            }
            Err(DispatchError::Cancelled) => Err(DispatchError::Cancelled),
            Err(err) => {
                route.endpoint.record_failure(now_fn());
                Err(err)
            }
        }
        // _guard dropped here, releasing connection
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

        // br-asupersync-kfk19o: route timestamps through the caller's
        // Cx so endpoint health metrics observe meaningful time. The
        // pre-fix shape passed Time::ZERO into every record_success /
        // record_failure call, leaving last_success and last_failure
        // permanently at Unix epoch zero — circuit breakers tripping
        // on 'no success in last 30s' fired on every fresh endpoint
        // (epoch-zero is older than any threshold under wall_now), and
        // recovery cooldowns either skipped or never advanced. Mirror
        // the asupersync-my0rls / asupersync-307rnt pattern:
        // cx.timer_driver() for replay-determinism in the lab harness,
        // wall_now() fallback for production builds without a driver.
        let now_fn = || {
            cx.timer_driver()
                .map_or_else(crate::time::wall_now, |d| d.now())
        };

        // Use router to resolve endpoints with load balancing strategy
        let routes = match self
            .router
            .route_multicast(symbol.symbol(), count, now_fn())
        {
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
        let mut sent_to = SmallVec::<[EndpointId; 16]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 16]>::new();

        for route in routes {
            if cx.checkpoint().is_err() {
                return Err(DispatchError::Cancelled);
            }

            let endpoint = route.endpoint;
            let _guard = endpoint.acquire_connection_guard();

            match self.send_to_endpoint(cx, endpoint.id, symbol.clone()).await {
                Ok(()) => {
                    endpoint.record_success(now_fn());
                    successes += 1;
                    sent_to.push(endpoint.id);
                }
                Err(DispatchError::Cancelled) => return Err(DispatchError::Cancelled),
                Err(err) => {
                    endpoint.record_failure(now_fn());
                    failures += 1;
                    failed.push((endpoint.id, err));
                }
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
        let endpoints = self.router.table().dispatchable_endpoints();

        if endpoints.is_empty() {
            return Err(DispatchError::NoEndpoints);
        }

        // br-asupersync-kfk19o: see dispatch_multicast for rationale.
        let now_fn = || {
            cx.timer_driver()
                .map_or_else(crate::time::wall_now, |d| d.now())
        };

        let mut successes = 0;
        let mut failures = 0;
        let mut sent_to = SmallVec::<[EndpointId; 16]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 16]>::new();

        for route in endpoints {
            if cx.checkpoint().is_err() {
                return Err(DispatchError::Cancelled);
            }

            let _guard = route.acquire_connection_guard();

            match self.send_to_endpoint(cx, route.id, symbol.clone()).await {
                Ok(()) => {
                    route.record_success(now_fn());
                    successes += 1;
                    sent_to.push(route.id);
                }
                Err(DispatchError::Cancelled) => return Err(DispatchError::Cancelled),
                Err(err) => {
                    route.record_failure(now_fn());
                    failures += 1;
                    failed.push((route.id, err));
                }
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
        let endpoints = self.router.table().dispatchable_endpoints();

        if endpoints.len() < required {
            return Err(DispatchError::InsufficientEndpoints {
                available: endpoints.len(),
                required,
            });
        }

        // br-asupersync-kfk19o: see dispatch_multicast for rationale.
        let now_fn = || {
            cx.timer_driver()
                .map_or_else(crate::time::wall_now, |d| d.now())
        };

        let mut successes = 0;
        let mut failures = 0;
        let mut sent_to = SmallVec::<[EndpointId; 16]>::new();
        let mut failed = SmallVec::<[(EndpointId, DispatchError); 16]>::new();

        for route in endpoints {
            if cx.checkpoint().is_err() {
                return Err(DispatchError::Cancelled);
            }

            if successes >= required {
                break;
            }

            let _guard = route.acquire_connection_guard();

            match self.send_to_endpoint(cx, route.id, symbol.clone()).await {
                Ok(()) => {
                    route.record_success(now_fn());
                    successes += 1;
                    sent_to.push(route.id);
                }
                Err(DispatchError::Cancelled) => return Err(DispatchError::Cancelled),
                Err(err) => {
                    route.record_failure(now_fn());
                    failures += 1;
                    failed.push((route.id, err));
                }
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

    /// Cancelled by context.
    Cancelled,
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
            Self::Cancelled => write!(f, "dispatch cancelled"),
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
#[path = "router_inline_tests.rs"]
mod tests;
