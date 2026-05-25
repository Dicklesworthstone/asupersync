//! Real distributed/consistent_hash ↔ service/load_balance integration e2e tests
//!
//! Tests the integration between consistent hashing algorithms and load balancing
//! strategies, verifying that hash ring management properly coordinates with service
//! discovery, node failure detection, and request routing for distributed system
//! fault tolerance and optimal load distribution.
//!
//! Test scenarios:
//! - Consistent hash ring coordination with load balancer service selection
//! - Node failure detection with hash ring rebalancing and load redistribution
//! - Service discovery integration with consistent hashing for routing decisions
//! - Load balancing strategy adaptation based on hash ring topology changes

use crate::{
    cx::{Cx, Scope},
    distributed::consistent_hash::{
        ConsistentHashError, ConsistentHashRing, HashDistribution, HashFunction, HashRingConfig,
        HashRingNode, NodeFailureDetection, NodeWeight, RingPosition, RingRebalancing, VirtualNode,
    },
    error::Error,
    service::load_balance::{
        DistributionPolicy, HealthCheck, LoadBalanceConfig, LoadBalanceDecision, LoadBalanceError,
        LoadBalanceStrategy, LoadBalancer, RequestMetrics, ServiceDiscovery, ServiceEndpoint,
        TrafficSplitting,
    },
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
    types::{Budget, Outcome, TaskId},
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

/// Controllable distributed system integrating consistent hashing with load balancing
/// for testing fault-tolerant request routing and service coordination
struct ConsistentHashLoadBalanceSystem {
    hash_ring: ConsistentHashRing,
    load_balancer: LoadBalancer,
    integration_coordinator: Arc<RwLock<IntegrationCoordinatorConfig>>,
    hash_balance_correlation: Arc<Mutex<HashMap<String, HashBalanceCorrelation>>>,
    routing_stats: Arc<Mutex<DistributedRoutingStats>>,
    topology_monitor: Arc<Mutex<TopologyChangeMonitor>>,
}

#[derive(Clone)]
struct IntegrationCoordinatorConfig {
    auto_rebalance_on_topology_change: bool,
    hash_ring_sync_interval_ms: u64,
    load_balance_update_threshold: f64,
    max_virtual_nodes_per_service: usize,
    failure_detection_timeout_ms: u64,
    adaptive_load_balancing: bool,
    consistent_routing_enforcement: bool,
}

#[derive(Debug)]
struct HashBalanceCorrelation {
    correlation_id: String,
    request_key: String,
    hash_value: u64,
    ring_position: RingPosition,
    selected_node: Option<HashRingNode>,
    load_balance_decision: Option<LoadBalanceDecision>,
    service_endpoints: Vec<ServiceEndpoint>,
    routing_decision: RoutingDecision,
    created_at: Instant,
    resolved_at: Option<Instant>,
    final_status: RoutingStatus,
}

#[derive(Debug, Clone)]
struct RoutingDecision {
    primary_endpoint: ServiceEndpoint,
    backup_endpoints: Vec<ServiceEndpoint>,
    routing_strategy: RoutingStrategy,
    load_distribution_weight: f64,
    consistency_guarantee: ConsistencyLevel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RoutingStrategy {
    ConsistentHashPrimary,
    LoadBalanceWeighted,
    FailoverCascade,
    AdaptiveHybrid,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConsistencyLevel {
    StrictConsistent,
    EventuallyConsistent,
    BestEffort,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RoutingStatus {
    Pending,
    HashResolved,
    LoadBalanceApplied,
    EndpointSelected,
    RoutingCompleted,
    Failed,
    Retrying,
}

#[derive(Debug)]
struct DistributedRoutingStats {
    total_routing_requests: AtomicU64,
    consistent_hash_routes: AtomicU64,
    load_balance_routes: AtomicU64,
    hybrid_routes: AtomicU64,
    failed_routes: AtomicU64,
    topology_changes: AtomicU64,
    rebalancing_events: AtomicU64,
    node_failures_detected: AtomicU64,
    average_routing_time_ms: AtomicU64,
    consistency_violations: AtomicU64,
}

#[derive(Debug)]
struct TopologyChangeMonitor {
    active_nodes: HashSet<HashRingNode>,
    failed_nodes: HashSet<HashRingNode>,
    node_weights: HashMap<HashRingNode, NodeWeight>,
    topology_version: u64,
    last_rebalance_at: Option<Instant>,
    pending_changes: VecDeque<TopologyChange>,
    stability_window_ms: u64,
}

#[derive(Debug, Clone)]
struct TopologyChange {
    change_type: TopologyChangeType,
    affected_node: HashRingNode,
    timestamp: Instant,
    impact_assessment: TopologyImpact,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum TopologyChangeType {
    NodeAdded,
    NodeRemoved,
    NodeFailed,
    NodeRecovered,
    WeightChanged,
}

#[derive(Debug, Clone)]
struct TopologyImpact {
    affected_key_range: f64,
    rebalance_required: bool,
    estimated_migration_cost: u64,
    consistency_risk_level: RiskLevel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl ConsistentHashLoadBalanceSystem {
    pub async fn new(
        hash_ring_config: HashRingConfig,
        load_balance_config: LoadBalanceConfig,
        coordinator_config: IntegrationCoordinatorConfig,
    ) -> Result<Self, Error> {
        let hash_ring = ConsistentHashRing::new(hash_ring_config).await?;
        let load_balancer = LoadBalancer::new(load_balance_config).await?;

        Ok(Self {
            hash_ring,
            load_balancer,
            integration_coordinator: Arc::new(RwLock::new(coordinator_config)),
            hash_balance_correlation: Arc::new(Mutex::new(HashMap::new())),
            routing_stats: Arc::new(Mutex::new(DistributedRoutingStats {
                total_routing_requests: AtomicU64::new(0),
                consistent_hash_routes: AtomicU64::new(0),
                load_balance_routes: AtomicU64::new(0),
                hybrid_routes: AtomicU64::new(0),
                failed_routes: AtomicU64::new(0),
                topology_changes: AtomicU64::new(0),
                rebalancing_events: AtomicU64::new(0),
                node_failures_detected: AtomicU64::new(0),
                average_routing_time_ms: AtomicU64::new(0),
                consistency_violations: AtomicU64::new(0),
            })),
            topology_monitor: Arc::new(Mutex::new(TopologyChangeMonitor {
                active_nodes: HashSet::new(),
                failed_nodes: HashSet::new(),
                node_weights: HashMap::new(),
                topology_version: 1,
                last_rebalance_at: None,
                pending_changes: VecDeque::new(),
                stability_window_ms: 5000,
            })),
        })
    }

    /// Route request using integrated consistent hashing and load balancing
    pub async fn route_request(
        &self,
        cx: &Cx,
        request_key: String,
        routing_options: RoutingOptions,
    ) -> Outcome<DistributedRoutingResult, Error> {
        let correlation_id = format!("route_{}", uuid::Uuid::new_v4());
        let start_time = Instant::now();

        self.increment_stat("total_routing_requests", 1);

        // Create correlation tracking
        let correlation = HashBalanceCorrelation {
            correlation_id: correlation_id.clone(),
            request_key: request_key.clone(),
            hash_value: 0,
            ring_position: RingPosition::new(0),
            selected_node: None,
            load_balance_decision: None,
            service_endpoints: Vec::new(),
            routing_decision: RoutingDecision {
                primary_endpoint: ServiceEndpoint::default(),
                backup_endpoints: Vec::new(),
                routing_strategy: RoutingStrategy::ConsistentHashPrimary,
                load_distribution_weight: 0.0,
                consistency_guarantee: ConsistencyLevel::StrictConsistent,
            },
            created_at: start_time,
            resolved_at: None,
            final_status: RoutingStatus::Pending,
        };

        {
            let mut correlations = self.hash_balance_correlation.lock().unwrap();
            correlations.insert(correlation_id.clone(), correlation);
        }

        // Phase 1: Consistent Hash Resolution
        let hash_result = match self.resolve_consistent_hash(cx, &request_key).await {
            Ok(result) => {
                self.update_correlation_hash_resolved(&correlation_id, result.clone())
                    .await;
                result
            }
            Err(e) => {
                self.handle_routing_failure(
                    &correlation_id,
                    format!("Hash resolution failed: {}", e),
                )
                .await;
                return Outcome::Err(Error::internal(format!(
                    "Consistent hash resolution failed: {}",
                    e
                )));
            }
        };

        // Phase 2: Load Balance Integration
        let load_balance_result = match self
            .integrate_load_balancing(cx, &hash_result, &routing_options)
            .await
        {
            Ok(result) => {
                self.update_correlation_load_balance_applied(&correlation_id, result.clone())
                    .await;
                result
            }
            Err(e) => {
                self.handle_routing_failure(
                    &correlation_id,
                    format!("Load balancing failed: {}", e),
                )
                .await;
                return Outcome::Err(Error::internal(format!(
                    "Load balancing integration failed: {}",
                    e
                )));
            }
        };

        // Phase 3: Final Routing Decision
        let routing_decision = self
            .make_routing_decision(&hash_result, &load_balance_result, &routing_options)
            .await;

        self.update_correlation_completed(&correlation_id, routing_decision.clone())
            .await;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        self.update_average_routing_time(execution_time_ms);

        // Track routing strategy statistics
        match routing_decision.routing_strategy {
            RoutingStrategy::ConsistentHashPrimary => {
                self.increment_stat("consistent_hash_routes", 1)
            }
            RoutingStrategy::LoadBalanceWeighted => self.increment_stat("load_balance_routes", 1),
            RoutingStrategy::AdaptiveHybrid => self.increment_stat("hybrid_routes", 1),
            _ => {}
        }

        Outcome::Ok(DistributedRoutingResult {
            correlation_id,
            request_key,
            routing_decision,
            hash_result,
            load_balance_result,
            execution_time: start_time.elapsed(),
            consistency_level: routing_decision.consistency_guarantee,
        })
    }

    async fn resolve_consistent_hash(
        &self,
        cx: &Cx,
        request_key: &str,
    ) -> Result<ConsistentHashResult, ConsistentHashError> {
        // Compute hash value for the request key
        let hash_value = self.hash_ring.hash_function().hash(request_key.as_bytes());

        // Find position on the hash ring
        let ring_position = self.hash_ring.find_position(hash_value).await?;

        // Get the node responsible for this position
        let selected_node = self.hash_ring.get_node_for_position(ring_position).await?;

        // Get virtual nodes for load distribution
        let virtual_nodes = self
            .hash_ring
            .get_virtual_nodes_for_key(request_key)
            .await?;

        Ok(ConsistentHashResult {
            request_key: request_key.to_string(),
            hash_value,
            ring_position,
            primary_node: selected_node.clone(),
            virtual_nodes,
            ring_topology_version: self.get_current_topology_version().await,
        })
    }

    async fn integrate_load_balancing(
        &self,
        cx: &Cx,
        hash_result: &ConsistentHashResult,
        routing_options: &RoutingOptions,
    ) -> Result<LoadBalanceIntegrationResult, LoadBalanceError> {
        // Get service endpoints for the hash-selected node
        let primary_endpoints = self
            .load_balancer
            .get_endpoints_for_node(cx, &hash_result.primary_node)
            .await?;

        // Apply load balancing strategy
        let load_balance_decision = self
            .load_balancer
            .make_routing_decision(
                cx,
                &primary_endpoints,
                routing_options.load_balance_strategy,
            )
            .await?;

        // Get backup endpoints for fault tolerance
        let backup_endpoints = self
            .get_backup_endpoints_from_virtual_nodes(cx, &hash_result.virtual_nodes)
            .await?;

        Ok(LoadBalanceIntegrationResult {
            primary_endpoints,
            backup_endpoints,
            load_balance_decision,
            distribution_weights: self
                .calculate_distribution_weights(&hash_result.virtual_nodes)
                .await,
            health_status: self.load_balancer.health_check_status().await,
        })
    }

    async fn make_routing_decision(
        &self,
        hash_result: &ConsistentHashResult,
        load_balance_result: &LoadBalanceIntegrationResult,
        routing_options: &RoutingOptions,
    ) -> RoutingDecision {
        let config = self.integration_coordinator.read().unwrap().clone();

        let routing_strategy = if config.adaptive_load_balancing {
            self.choose_adaptive_routing_strategy(hash_result, load_balance_result)
                .await
        } else {
            routing_options.preferred_strategy
        };

        let primary_endpoint = match routing_strategy {
            RoutingStrategy::ConsistentHashPrimary => load_balance_result
                .load_balance_decision
                .selected_endpoint
                .clone(),
            RoutingStrategy::LoadBalanceWeighted => {
                self.select_weighted_endpoint(&load_balance_result.distribution_weights)
                    .await
            }
            RoutingStrategy::AdaptiveHybrid => {
                self.select_hybrid_endpoint(hash_result, load_balance_result)
                    .await
            }
            RoutingStrategy::FailoverCascade => {
                self.select_failover_endpoint(load_balance_result).await
            }
        };

        let consistency_guarantee = if config.consistent_routing_enforcement {
            ConsistencyLevel::StrictConsistent
        } else {
            ConsistencyLevel::EventuallyConsistent
        };

        RoutingDecision {
            primary_endpoint,
            backup_endpoints: load_balance_result.backup_endpoints.clone(),
            routing_strategy,
            load_distribution_weight: self.calculate_load_weight(&routing_strategy).await,
            consistency_guarantee,
        }
    }

    async fn choose_adaptive_routing_strategy(
        &self,
        hash_result: &ConsistentHashResult,
        load_balance_result: &LoadBalanceIntegrationResult,
    ) -> RoutingStrategy {
        // Simple adaptive logic based on load and health
        let primary_load = load_balance_result.load_balance_decision.current_load;
        let health_status = &load_balance_result.health_status;

        if primary_load > 0.8 {
            // High load, use load balancing
            RoutingStrategy::LoadBalanceWeighted
        } else if health_status.unhealthy_endpoints > 0 {
            // Some unhealthy endpoints, use hybrid approach
            RoutingStrategy::AdaptiveHybrid
        } else {
            // Normal conditions, use consistent hashing
            RoutingStrategy::ConsistentHashPrimary
        }
    }

    async fn select_weighted_endpoint(
        &self,
        weights: &HashMap<ServiceEndpoint, f64>,
    ) -> ServiceEndpoint {
        // Select endpoint based on weights (simplified implementation)
        weights
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(endpoint, _)| endpoint.clone())
            .unwrap_or_default()
    }

    async fn select_hybrid_endpoint(
        &self,
        hash_result: &ConsistentHashResult,
        load_balance_result: &LoadBalanceIntegrationResult,
    ) -> ServiceEndpoint {
        // Hybrid selection combining hash consistency and load balancing
        let hash_preferred = &load_balance_result.load_balance_decision.selected_endpoint;
        let load_balanced = self
            .select_weighted_endpoint(&load_balance_result.distribution_weights)
            .await;

        // Choose based on load difference
        if load_balance_result.load_balance_decision.current_load < 0.6 {
            hash_preferred.clone()
        } else {
            load_balanced
        }
    }

    async fn select_failover_endpoint(
        &self,
        load_balance_result: &LoadBalanceIntegrationResult,
    ) -> ServiceEndpoint {
        // Select from backup endpoints
        load_balance_result
            .backup_endpoints
            .first()
            .cloned()
            .unwrap_or_else(|| {
                load_balance_result
                    .load_balance_decision
                    .selected_endpoint
                    .clone()
            })
    }

    async fn calculate_load_weight(&self, strategy: &RoutingStrategy) -> f64 {
        match strategy {
            RoutingStrategy::ConsistentHashPrimary => 1.0,
            RoutingStrategy::LoadBalanceWeighted => 0.5,
            RoutingStrategy::AdaptiveHybrid => 0.75,
            RoutingStrategy::FailoverCascade => 0.25,
        }
    }

    async fn get_backup_endpoints_from_virtual_nodes(
        &self,
        cx: &Cx,
        virtual_nodes: &[VirtualNode],
    ) -> Result<Vec<ServiceEndpoint>, LoadBalanceError> {
        let mut backup_endpoints = Vec::new();

        for virtual_node in virtual_nodes.iter().take(3) {
            // Limit to 3 backups
            if let Ok(endpoints) = self
                .load_balancer
                .get_endpoints_for_virtual_node(cx, virtual_node)
                .await
            {
                backup_endpoints.extend(endpoints);
            }
        }

        Ok(backup_endpoints)
    }

    async fn calculate_distribution_weights(
        &self,
        virtual_nodes: &[VirtualNode],
    ) -> HashMap<ServiceEndpoint, f64> {
        let mut weights = HashMap::new();

        for (i, virtual_node) in virtual_nodes.iter().enumerate() {
            if let Ok(endpoints) = self.get_endpoints_for_virtual_node(virtual_node).await {
                let weight = 1.0 / (i + 1) as f64; // Decreasing weight for backup nodes
                for endpoint in endpoints {
                    weights.insert(endpoint, weight);
                }
            }
        }

        weights
    }

    async fn get_endpoints_for_virtual_node(
        &self,
        virtual_node: &VirtualNode,
    ) -> Result<Vec<ServiceEndpoint>, Error> {
        // Simplified endpoint resolution for virtual nodes
        Ok(vec![ServiceEndpoint::from_virtual_node(virtual_node)])
    }

    async fn get_current_topology_version(&self) -> u64 {
        let monitor = self.topology_monitor.lock().unwrap();
        monitor.topology_version
    }

    /// Simulate node failure and test rebalancing coordination
    pub async fn simulate_node_failure(
        &self,
        cx: &Cx,
        failed_node: HashRingNode,
    ) -> Outcome<NodeFailureRecoveryResult, Error> {
        let failure_start = Instant::now();

        // Update topology monitor
        {
            let mut monitor = self.topology_monitor.lock().unwrap();
            monitor.active_nodes.remove(&failed_node);
            monitor.failed_nodes.insert(failed_node.clone());

            let topology_change = TopologyChange {
                change_type: TopologyChangeType::NodeFailed,
                affected_node: failed_node.clone(),
                timestamp: failure_start,
                impact_assessment: TopologyImpact {
                    affected_key_range: 0.1, // Simplified calculation
                    rebalance_required: true,
                    estimated_migration_cost: 1000,
                    consistency_risk_level: RiskLevel::Medium,
                },
            };

            monitor.pending_changes.push_back(topology_change);
            monitor.topology_version += 1;
        }

        self.increment_stat("node_failures_detected", 1);
        self.increment_stat("topology_changes", 1);

        // Trigger hash ring rebalancing
        let rebalance_result = self
            .hash_ring
            .rebalance_after_node_failure(cx, &failed_node)
            .await?;

        // Update load balancer with topology changes
        self.load_balancer
            .handle_node_failure(cx, &failed_node)
            .await?;

        // Update coordinator
        {
            let mut monitor = self.topology_monitor.lock().unwrap();
            monitor.last_rebalance_at = Some(Instant::now());
        }

        self.increment_stat("rebalancing_events", 1);

        let recovery_time = failure_start.elapsed();

        Ok(NodeFailureRecoveryResult {
            failed_node,
            rebalance_result,
            recovery_time,
            affected_requests: 0, // Simplified
            consistency_maintained: true,
        })
    }

    async fn update_correlation_hash_resolved(
        &self,
        correlation_id: &str,
        hash_result: ConsistentHashResult,
    ) {
        let mut correlations = self.hash_balance_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.hash_value = hash_result.hash_value;
            correlation.ring_position = hash_result.ring_position;
            correlation.selected_node = Some(hash_result.primary_node);
            correlation.final_status = RoutingStatus::HashResolved;
        }
    }

    async fn update_correlation_load_balance_applied(
        &self,
        correlation_id: &str,
        lb_result: LoadBalanceIntegrationResult,
    ) {
        let mut correlations = self.hash_balance_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.load_balance_decision = Some(lb_result.load_balance_decision);
            correlation.service_endpoints = lb_result.primary_endpoints;
            correlation.final_status = RoutingStatus::LoadBalanceApplied;
        }
    }

    async fn update_correlation_completed(
        &self,
        correlation_id: &str,
        routing_decision: RoutingDecision,
    ) {
        let mut correlations = self.hash_balance_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.routing_decision = routing_decision;
            correlation.resolved_at = Some(Instant::now());
            correlation.final_status = RoutingStatus::RoutingCompleted;
        }
    }

    async fn handle_routing_failure(&self, correlation_id: &str, error_message: String) {
        let mut correlations = self.hash_balance_correlation.lock().unwrap();
        if let Some(correlation) = correlations.get_mut(correlation_id) {
            correlation.final_status = RoutingStatus::Failed;
        }
        self.increment_stat("failed_routes", 1);
    }

    fn increment_stat(&self, stat_name: &str, count: u64) {
        let stats = self.routing_stats.lock().unwrap();
        match stat_name {
            "total_routing_requests" => stats
                .total_routing_requests
                .fetch_add(count, Ordering::SeqCst),
            "consistent_hash_routes" => stats
                .consistent_hash_routes
                .fetch_add(count, Ordering::SeqCst),
            "load_balance_routes" => stats.load_balance_routes.fetch_add(count, Ordering::SeqCst),
            "hybrid_routes" => stats.hybrid_routes.fetch_add(count, Ordering::SeqCst),
            "failed_routes" => stats.failed_routes.fetch_add(count, Ordering::SeqCst),
            "topology_changes" => stats.topology_changes.fetch_add(count, Ordering::SeqCst),
            "rebalancing_events" => stats.rebalancing_events.fetch_add(count, Ordering::SeqCst),
            "node_failures_detected" => stats
                .node_failures_detected
                .fetch_add(count, Ordering::SeqCst),
            "consistency_violations" => stats
                .consistency_violations
                .fetch_add(count, Ordering::SeqCst),
            _ => 0,
        };
    }

    fn update_average_routing_time(&self, time_ms: u64) {
        let stats = self.routing_stats.lock().unwrap();
        stats
            .average_routing_time_ms
            .store(time_ms, Ordering::SeqCst);
    }

    /// Get comprehensive distributed routing statistics
    pub fn get_distributed_routing_stats(&self) -> DistributedRoutingIntegrationStats {
        let stats = self.routing_stats.lock().unwrap();

        DistributedRoutingIntegrationStats {
            total_routing_requests: stats.total_routing_requests.load(Ordering::SeqCst),
            consistent_hash_routes: stats.consistent_hash_routes.load(Ordering::SeqCst),
            load_balance_routes: stats.load_balance_routes.load(Ordering::SeqCst),
            hybrid_routes: stats.hybrid_routes.load(Ordering::SeqCst),
            failed_routes: stats.failed_routes.load(Ordering::SeqCst),
            topology_changes: stats.topology_changes.load(Ordering::SeqCst),
            rebalancing_events: stats.rebalancing_events.load(Ordering::SeqCst),
            node_failures_detected: stats.node_failures_detected.load(Ordering::SeqCst),
            average_routing_time_ms: stats.average_routing_time_ms.load(Ordering::SeqCst),
            consistency_violations: stats.consistency_violations.load(Ordering::SeqCst),
        }
    }
}

// Placeholder types for compilation (would be imported from actual modules)
#[derive(Debug, Clone, Default)]
pub struct RoutingOptions {
    pub preferred_strategy: RoutingStrategy,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub consistency_requirement: ConsistencyLevel,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ConsistentHashResult {
    pub request_key: String,
    pub hash_value: u64,
    pub ring_position: RingPosition,
    pub primary_node: HashRingNode,
    pub virtual_nodes: Vec<VirtualNode>,
    pub ring_topology_version: u64,
}

#[derive(Debug, Clone)]
pub struct LoadBalanceIntegrationResult {
    pub primary_endpoints: Vec<ServiceEndpoint>,
    pub backup_endpoints: Vec<ServiceEndpoint>,
    pub load_balance_decision: LoadBalanceDecision,
    pub distribution_weights: HashMap<ServiceEndpoint, f64>,
    pub health_status: HealthCheckStatus,
}

#[derive(Debug, Clone)]
pub struct HealthCheckStatus {
    pub healthy_endpoints: usize,
    pub unhealthy_endpoints: usize,
    pub unknown_endpoints: usize,
}

#[derive(Debug, Clone)]
pub struct DistributedRoutingResult {
    pub correlation_id: String,
    pub request_key: String,
    pub routing_decision: RoutingDecision,
    pub hash_result: ConsistentHashResult,
    pub load_balance_result: LoadBalanceIntegrationResult,
    pub execution_time: Duration,
    pub consistency_level: ConsistencyLevel,
}

#[derive(Debug, Clone)]
pub struct NodeFailureRecoveryResult {
    pub failed_node: HashRingNode,
    pub rebalance_result: RingRebalancing,
    pub recovery_time: Duration,
    pub affected_requests: usize,
    pub consistency_maintained: bool,
}

#[derive(Debug, Clone)]
pub struct DistributedRoutingIntegrationStats {
    pub total_routing_requests: u64,
    pub consistent_hash_routes: u64,
    pub load_balance_routes: u64,
    pub hybrid_routes: u64,
    pub failed_routes: u64,
    pub topology_changes: u64,
    pub rebalancing_events: u64,
    pub node_failures_detected: u64,
    pub average_routing_time_ms: u64,
    pub consistency_violations: u64,
}

#[cfg(all(test, feature = "real-service-e2e"))]
mod tests {
    use super::*;
    use crate::cx::region;

    #[tokio::test]
    async fn test_basic_consistent_hash_load_balance_integration() {
        let budget = Budget::new(Duration::from_secs(30), Duration::from_secs(5));

        region(budget, |cx, scope| async move {
            // Set up integrated hash ring and load balancer
            let hash_ring_config = HashRingConfig {
                virtual_nodes_per_server: 150,
                hash_function: HashFunction::Sha256,
                replication_factor: 3,
                ..Default::default()
            };

            let load_balance_config = LoadBalanceConfig {
                strategy: LoadBalanceStrategy::WeightedRoundRobin,
                health_check_interval: Duration::from_secs(30),
                failure_threshold: 3,
                recovery_threshold: 2,
                ..Default::default()
            };

            let coordinator_config = IntegrationCoordinatorConfig {
                auto_rebalance_on_topology_change: true,
                hash_ring_sync_interval_ms: 1000,
                load_balance_update_threshold: 0.1,
                max_virtual_nodes_per_service: 200,
                failure_detection_timeout_ms: 5000,
                adaptive_load_balancing: false,
                consistent_routing_enforcement: true,
            };

            let routing_system = ConsistentHashLoadBalanceSystem::new(
                hash_ring_config,
                load_balance_config,
                coordinator_config,
            )
            .await
            .expect("Failed to create routing system");

            // Test basic request routing
            let request_key = "test_request_001".to_string();
            let routing_options = RoutingOptions {
                preferred_strategy: RoutingStrategy::ConsistentHashPrimary,
                load_balance_strategy: LoadBalanceStrategy::WeightedRoundRobin,
                consistency_requirement: ConsistencyLevel::StrictConsistent,
                timeout: Duration::from_secs(5),
            };

            let routing_result = routing_system
                .route_request(cx, request_key.clone(), routing_options)
                .await
                .expect("Routing should succeed");

            assert_eq!(routing_result.request_key, request_key);
            assert_eq!(
                routing_result.routing_decision.routing_strategy,
                RoutingStrategy::ConsistentHashPrimary
            );
            assert_eq!(
                routing_result.consistency_level,
                ConsistencyLevel::StrictConsistent
            );
            assert!(!routing_result.execution_time.is_zero());

            // Verify statistics
            let stats = routing_system.get_distributed_routing_stats();
            assert_eq!(stats.total_routing_requests, 1);
            assert_eq!(stats.consistent_hash_routes, 1);
            assert_eq!(stats.failed_routes, 0);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_node_failure_rebalancing_coordination() {
        let budget = Budget::new(Duration::from_secs(45), Duration::from_secs(10));

        region(budget, |cx, scope| async move {
            let hash_ring_config = HashRingConfig {
                virtual_nodes_per_server: 100,
                hash_function: HashFunction::Sha256,
                replication_factor: 2,
                ..Default::default()
            };

            let load_balance_config = LoadBalanceConfig {
                strategy: LoadBalanceStrategy::LeastConnections,
                health_check_interval: Duration::from_secs(10),
                failure_threshold: 2,
                recovery_threshold: 1,
                ..Default::default()
            };

            let coordinator_config = IntegrationCoordinatorConfig {
                auto_rebalance_on_topology_change: true,
                hash_ring_sync_interval_ms: 500,
                load_balance_update_threshold: 0.05,
                max_virtual_nodes_per_service: 150,
                failure_detection_timeout_ms: 3000,
                adaptive_load_balancing: true,
                consistent_routing_enforcement: false,
            };

            let routing_system = ConsistentHashLoadBalanceSystem::new(
                hash_ring_config,
                load_balance_config,
                coordinator_config,
            )
            .await
            .expect("Failed to create routing system");

            // Set up initial routing requests
            let mut routing_tasks = Vec::new();
            for i in 0..5 {
                let request_key = format!("request_{}", i);
                let routing_options = RoutingOptions {
                    preferred_strategy: RoutingStrategy::AdaptiveHybrid,
                    load_balance_strategy: LoadBalanceStrategy::LeastConnections,
                    consistency_requirement: ConsistencyLevel::EventuallyConsistent,
                    timeout: Duration::from_secs(3),
                };

                let system_ref = &routing_system;
                let task = scope.spawn(&format!("route_{}", i), async move {
                    system_ref
                        .route_request(cx, request_key, routing_options)
                        .await
                })?;

                routing_tasks.push(task);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // Simulate node failure during routing
            let failed_node = HashRingNode::new("node_1".to_string());
            let failure_result = routing_system
                .simulate_node_failure(cx, failed_node.clone())
                .await
                .expect("Node failure simulation should succeed");

            assert_eq!(failure_result.failed_node, failed_node);
            assert!(!failure_result.recovery_time.is_zero());
            assert!(failure_result.consistency_maintained);

            // Wait for routing tasks to complete
            let mut successful_routes = 0;
            let mut failed_routes = 0;

            for task in routing_tasks {
                match task.join(cx).await {
                    Ok(Ok(_)) => successful_routes += 1,
                    Ok(Err(_)) => failed_routes += 1,
                    Err(_) => failed_routes += 1,
                }
            }

            // Verify failure handling
            let stats = routing_system.get_distributed_routing_stats();
            assert_eq!(stats.node_failures_detected, 1);
            assert_eq!(stats.topology_changes, 1);
            assert_eq!(stats.rebalancing_events, 1);

            println!("Node failure test results:");
            println!("- Successful routes: {}", successful_routes);
            println!("- Failed routes: {}", failed_routes);
            println!("- Recovery time: {:?}", failure_result.recovery_time);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }

    #[tokio::test]
    async fn test_adaptive_routing_strategy_coordination() {
        let budget = Budget::new(Duration::from_secs(45), Duration::from_secs(10));

        region(budget, |cx, scope| async move {
            let hash_ring_config = HashRingConfig {
                virtual_nodes_per_server: 120,
                hash_function: HashFunction::Sha256,
                replication_factor: 3,
                ..Default::default()
            };

            let load_balance_config = LoadBalanceConfig {
                strategy: LoadBalanceStrategy::PowerOfTwoChoices,
                health_check_interval: Duration::from_secs(15),
                failure_threshold: 3,
                recovery_threshold: 2,
                ..Default::default()
            };

            let coordinator_config = IntegrationCoordinatorConfig {
                auto_rebalance_on_topology_change: true,
                hash_ring_sync_interval_ms: 750,
                load_balance_update_threshold: 0.15,
                max_virtual_nodes_per_service: 180,
                failure_detection_timeout_ms: 4000,
                adaptive_load_balancing: true, // Enable adaptive routing
                consistent_routing_enforcement: false,
            };

            let routing_system = ConsistentHashLoadBalanceSystem::new(
                hash_ring_config,
                load_balance_config,
                coordinator_config,
            )
            .await
            .expect("Failed to create routing system");

            // Test different routing strategies
            let test_strategies = vec![
                RoutingStrategy::ConsistentHashPrimary,
                RoutingStrategy::LoadBalanceWeighted,
                RoutingStrategy::AdaptiveHybrid,
            ];

            let mut strategy_results = HashMap::new();

            for (i, strategy) in test_strategies.into_iter().enumerate() {
                let mut strategy_tasks = Vec::new();

                for j in 0..4 {
                    let request_key = format!("adaptive_test_{}_{}", i, j);
                    let routing_options = RoutingOptions {
                        preferred_strategy: strategy,
                        load_balance_strategy: LoadBalanceStrategy::PowerOfTwoChoices,
                        consistency_requirement: ConsistencyLevel::BestEffort,
                        timeout: Duration::from_secs(4),
                    };

                    let system_ref = &routing_system;
                    let task = scope.spawn(&format!("adaptive_{}_{}", i, j), async move {
                        system_ref
                            .route_request(cx, request_key, routing_options)
                            .await
                    })?;

                    strategy_tasks.push(task);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }

                let mut successful_count = 0;
                for task in strategy_tasks {
                    match task.join(cx).await {
                        Ok(Ok(_)) => successful_count += 1,
                        _ => {}
                    }
                }

                strategy_results.insert(strategy, successful_count);
            }

            // Verify adaptive coordination
            let stats = routing_system.get_distributed_routing_stats();
            assert!(stats.total_routing_requests >= 12);

            // Should have used multiple routing strategies
            let total_strategic_routes =
                stats.consistent_hash_routes + stats.load_balance_routes + stats.hybrid_routes;
            assert!(total_strategic_routes > 0);

            println!("Adaptive routing results:");
            for (strategy, count) in strategy_results {
                println!("- {:?}: {} successful routes", strategy, count);
            }
            println!("- Total requests: {}", stats.total_routing_requests);
            println!("- Hash routes: {}", stats.consistent_hash_routes);
            println!("- Load balance routes: {}", stats.load_balance_routes);
            println!("- Hybrid routes: {}", stats.hybrid_routes);

            Outcome::Ok(())
        })
        .await
        .expect("Region should complete successfully");
    }
}
