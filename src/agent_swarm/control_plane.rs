//! Agent Swarm Control Plane coordinator.
//!
//! This module provides the main coordination layer for multi-agent workflows,
//! managing resource admission, validation lanes, crash recovery, and operator
//! visibility across concurrent AI agent operations on high-core machines.

use crate::cx::Cx;
use crate::error::Result;
use crate::sync::Mutex;
use crate::types::RegionId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::handoff_verifier::{HandoffVerifier, SessionMetadata};
use super::release_proof_aggregator::ReleaseProofAggregator;

/// Core Agent Swarm Control Plane for coordinating multi-agent workflows.
#[derive(Debug)]
pub struct AgentSwarmControlPlane {
    /// Agent admission and resource control
    admission_controller: Arc<AdmissionController>,
    /// Validation and proof lane coordination
    validation_coordinator: Arc<ValidationCoordinator>,
    /// Session handoff and crash recovery
    handoff_verifier: Arc<Mutex<HandoffVerifier>>,
    /// Release proof aggregation
    proof_aggregator: Arc<Mutex<ReleaseProofAggregator>>,
    /// Active agent registry
    agent_registry: Arc<Mutex<AgentRegistry>>,
    /// Resource pressure monitoring
    pressure_monitor: Arc<PressureMonitor>,
    /// Control plane metrics
    metrics: Arc<Mutex<ControlPlaneMetrics>>,
}

/// Agent admission controller for resource-aware scheduling.
#[derive(Debug)]
pub struct AdmissionController {
    /// Maximum concurrent agents allowed
    max_concurrent_agents: usize,
    /// Resource allocation policies
    resource_policies: ResourcePolicies,
    /// Current resource usage
    current_usage: Arc<Mutex<ResourceUsage>>,
    /// Admission queue for waiting agents
    admission_queue: Arc<Mutex<VecDeque<AgentAdmissionRequest>>>,
}

/// Validation lane coordinator for proof and testing workflows.
#[derive(Debug)]
pub struct ValidationCoordinator {
    /// Available validation lanes
    validation_lanes: Arc<Mutex<BTreeMap<LaneId, ValidationLane>>>,
    /// Lane assignment policies
    lane_policies: LanePolicies,
    /// Proof routing configuration
    proof_routing: ProofRoutingConfig,
}

/// Active agent registry with session tracking.
#[derive(Debug)]
pub struct AgentRegistry {
    /// Active agent sessions
    active_agents: HashMap<AgentId, AgentSession>,
    /// Agent capabilities and permissions
    agent_capabilities: HashMap<AgentId, AgentCapabilities>,
    /// Session metadata tracking
    session_metadata: HashMap<SessionId, SessionMetadata>,
}

/// System pressure monitoring and feedback.
#[derive(Debug)]
pub struct PressureMonitor {
    /// CPU pressure thresholds
    cpu_thresholds: PressureThresholds,
    /// Memory pressure thresholds
    memory_thresholds: PressureThresholds,
    /// Disk pressure thresholds
    disk_thresholds: PressureThresholds,
    /// Network pressure thresholds
    network_thresholds: PressureThresholds,
    /// Current pressure readings
    current_pressure: Arc<Mutex<SystemPressure>>,
}

/// Control plane operational metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneMetrics {
    /// Total agents admitted
    pub total_agents_admitted: u64,
    /// Total agents rejected
    pub total_agents_rejected: u64,
    /// Current active agent count
    pub active_agent_count: usize,
    /// Average agent session duration
    pub avg_session_duration: Duration,
    /// Resource utilization statistics
    pub resource_utilization: ResourceUtilization,
    /// Validation lane usage statistics
    pub validation_lane_usage: ValidationLaneUsage,
    /// Proof aggregation metrics
    pub proof_aggregation_metrics: ProofAggregationMetrics,
    /// Last metrics update timestamp
    pub last_updated: SystemTime,
}

/// Resource allocation policies and limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicies {
    /// CPU allocation policy
    pub cpu_policy: CpuAllocationPolicy,
    /// Memory allocation policy
    pub memory_policy: MemoryAllocationPolicy,
    /// Disk allocation policy
    pub disk_policy: DiskAllocationPolicy,
    /// Network allocation policy
    pub network_policy: NetworkAllocationPolicy,
}

/// Current system resource usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU cores allocated
    pub cpu_cores_allocated: f64,
    /// Memory allocated in bytes
    pub memory_allocated: u64,
    /// Disk space allocated in bytes
    pub disk_allocated: u64,
    /// Network bandwidth allocated in bytes/sec
    pub network_bandwidth_allocated: u64,
    /// Active obligation count
    pub active_obligations: usize,
    /// Active region count
    pub active_regions: usize,
}

/// Agent admission request with resource requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAdmissionRequest {
    /// Agent identifier
    pub agent_id: AgentId,
    /// Requested resource allocation
    pub resource_requirements: ResourceRequirements,
    /// Required capabilities
    pub required_capabilities: Vec<RequiredCapability>,
    /// Priority level
    pub priority: AdmissionPriority,
    /// Request timestamp
    pub requested_at: SystemTime,
    /// Optional timeout for admission
    pub admission_timeout: Option<Duration>,
}

/// Resource requirements for agent admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// CPU cores needed
    pub cpu_cores: f64,
    /// Memory needed in bytes
    pub memory_bytes: u64,
    /// Disk space needed in bytes
    pub disk_bytes: u64,
    /// Network bandwidth needed in bytes/sec
    pub network_bandwidth: u64,
    /// Estimated session duration
    pub estimated_duration: Option<Duration>,
}

/// Active agent session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    /// Agent identifier
    pub agent_id: AgentId,
    /// Session identifier
    pub session_id: SessionId,
    /// Region owning this agent's tasks
    pub agent_region: RegionId,
    /// Allocated resources
    pub allocated_resources: ResourceRequirements,
    /// Session start time
    pub started_at: SystemTime,
    /// Last activity timestamp
    pub last_activity: SystemTime,
    /// Current agent status
    pub status: AgentStatus,
    /// Active obligations count
    pub active_obligations_count: usize,
}

/// Validation lane for proof and testing workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationLane {
    /// Lane identifier
    pub lane_id: LaneId,
    /// Lane type and purpose
    pub lane_type: ValidationType,
    /// Current lane status
    pub status: LaneStatus,
    /// Assigned agent (if any)
    pub assigned_agent: Option<AgentId>,
    /// Lane resource allocation
    pub resource_allocation: ResourceRequirements,
    /// Validation configuration
    pub validation_config: ValidationConfig,
}

/// System pressure readings across different resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPressure {
    /// CPU pressure (0.0 to 1.0)
    pub cpu_pressure: f64,
    /// Memory pressure (0.0 to 1.0)
    pub memory_pressure: f64,
    /// Disk pressure (0.0 to 1.0)
    pub disk_pressure: f64,
    /// Network pressure (0.0 to 1.0)
    pub network_pressure: f64,
    /// Validation lane pressure (0.0 to 1.0)
    pub validation_pressure: f64,
    /// Overall system pressure (0.0 to 1.0)
    pub overall_pressure: f64,
    /// Pressure measurement timestamp
    pub measured_at: SystemTime,
}

// Type aliases for clarity
pub type AgentId = String;
pub type SessionId = String;
pub type LaneId = String;

// Enums for various states and types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Agent is initializing
    Initializing,
    /// Agent is active and working
    Active,
    /// Agent is idle but ready
    Idle,
    /// Agent is shutting down
    Shutting,
    /// Agent has crashed or failed
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdmissionPriority {
    /// Critical priority (system maintenance)
    Critical,
    /// High priority (urgent work)
    High,
    /// Normal priority (regular work)
    Normal,
    /// Low priority (background tasks)
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationType {
    /// Compilation validation
    Compilation,
    /// Unit testing validation
    UnitTest,
    /// Integration testing validation
    IntegrationTest,
    /// Proof generation validation
    ProofGeneration,
    /// Documentation validation
    Documentation,
    /// Lint/format validation
    Lint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LaneStatus {
    /// Lane is available for assignment
    Available,
    /// Lane is assigned and active
    Active,
    /// Lane is shutting down
    Shutting,
    /// Lane is unavailable (maintenance, etc.)
    Unavailable,
}

// Placeholder structs for complex types that would be defined elsewhere
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    pub supported_languages: Vec<String>,
    pub max_file_size: u64,
    pub required_features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredCapability {
    pub capability_name: String,
    pub minimum_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuAllocationPolicy {
    pub max_cores_per_agent: f64,
    pub reservation_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAllocationPolicy {
    pub max_memory_per_agent: u64,
    pub oom_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskAllocationPolicy {
    pub max_disk_per_agent: u64,
    pub cleanup_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAllocationPolicy {
    pub max_bandwidth_per_agent: u64,
    pub qos_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanePolicies {
    pub lane_assignment_strategy: String,
    pub max_lanes_per_agent: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRoutingConfig {
    pub routing_strategy: String,
    pub proof_retention_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureThresholds {
    pub warning_threshold: f64,
    pub critical_threshold: f64,
    pub emergency_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    pub timeout: Duration,
    pub retry_policy: String,
    pub resource_limits: ResourceRequirements,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    pub cpu_utilization: f64,
    pub memory_utilization: f64,
    pub disk_utilization: f64,
    pub network_utilization: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationLaneUsage {
    pub total_validations: u64,
    pub successful_validations: u64,
    pub failed_validations: u64,
    pub average_validation_time: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAggregationMetrics {
    pub total_proofs_generated: u64,
    pub proofs_per_hour: f64,
    pub average_proof_size: u64,
}

impl AgentSwarmControlPlane {
    /// Create a new Agent Swarm Control Plane instance.
    pub fn new(config: ControlPlaneConfig) -> Result<Self> {
        let admission_controller = Arc::new(AdmissionController::new(config.admission_config)?);
        let validation_coordinator =
            Arc::new(ValidationCoordinator::new(config.validation_config)?);
        let handoff_verifier = Arc::new(Mutex::new(HandoffVerifier::new()));
        // Create a basic aggregator config for now
        let aggregator_config = super::release_proof_aggregator::AggregatorConfig {
            max_evidence_age: Duration::from_secs(3600),
            max_commit_age: Duration::from_secs(3600 * 24),
            require_remote_rch: true,
            redact_sensitive: false,
            output_retention_days: 7,
        };
        let proof_aggregator = Arc::new(Mutex::new(ReleaseProofAggregator::new(aggregator_config)));
        let agent_registry = Arc::new(Mutex::new(AgentRegistry::new()));
        let pressure_monitor = Arc::new(PressureMonitor::new(config.pressure_config)?);
        let metrics = Arc::new(Mutex::new(ControlPlaneMetrics::new()));

        Ok(Self {
            admission_controller,
            validation_coordinator,
            handoff_verifier,
            proof_aggregator,
            agent_registry,
            pressure_monitor,
            metrics,
        })
    }

    /// Admit a new agent to the swarm with resource allocation.
    pub async fn admit_agent(
        &self,
        cx: &Cx,
        request: AgentAdmissionRequest,
    ) -> Result<AgentAdmissionResult> {
        // Check current system pressure
        let pressure = self.pressure_monitor.current_pressure(cx).await?;
        if pressure.overall_pressure > 0.8 {
            return Ok(AgentAdmissionResult::Rejected {
                reason: AdmissionRejectionReason::SystemPressure,
                retry_after: Some(Duration::from_secs(30)),
            });
        }

        // Check resource availability
        let can_admit = self
            .admission_controller
            .can_admit_agent(cx, &request)
            .await?;

        if !can_admit {
            return Ok(AgentAdmissionResult::Rejected {
                reason: AdmissionRejectionReason::ResourceUnavailable,
                retry_after: Some(Duration::from_secs(60)),
            });
        }

        // Create agent session with placeholder region
        let agent_region = RegionId::new_ephemeral();
        let session = AgentSession {
            agent_id: request.agent_id.clone(),
            session_id: format!(
                "session-{}-{}",
                request.agent_id,
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ),
            agent_region,
            allocated_resources: request.resource_requirements.clone(),
            started_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            status: AgentStatus::Initializing,
            active_obligations_count: 0,
        };

        // Register agent session
        {
            let mut registry = self.agent_registry.lock(cx).await?;
            registry.register_session(session.clone())?;
        }

        // Update metrics
        {
            let mut metrics = self.metrics.lock(cx).await?;
            metrics.total_agents_admitted += 1;
            metrics.active_agent_count += 1;
            metrics.last_updated = SystemTime::now();
        }

        Ok(AgentAdmissionResult::Admitted {
            session_id: session.session_id,
            allocated_resources: session.allocated_resources,
            agent_region,
        })
    }

    /// Get current control plane metrics.
    pub async fn metrics(&self, cx: &Cx) -> Result<ControlPlaneMetrics> {
        Ok(self.metrics.lock(cx).await?.clone())
    }

    /// Update system pressure readings.
    pub async fn update_pressure(&self, cx: &Cx, pressure: SystemPressure) -> Result<()> {
        self.pressure_monitor.update_pressure(cx, pressure).await
    }

    /// Shutdown the control plane gracefully.
    pub async fn shutdown(&self, cx: &Cx) -> Result<()> {
        // Gracefully shutdown all active agents
        let active_sessions = {
            let registry = self.agent_registry.lock(cx).await?;
            registry.active_agents.keys().cloned().collect::<Vec<_>>()
        };

        for _agent_id in active_sessions {
            // Signal agent shutdown and wait for graceful termination
            // Implementation would depend on agent communication protocol
        }

        Ok(())
    }
}

/// Configuration for the Agent Swarm Control Plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    pub admission_config: AdmissionConfig,
    pub validation_config: ValidationCoordinatorConfig,
    pub handoff_config: HandoffVerifierConfig,
    pub proof_config: ProofAggregatorConfig,
    pub pressure_config: PressureMonitorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionConfig {
    pub max_concurrent_agents: usize,
    pub resource_policies: ResourcePolicies,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCoordinatorConfig {
    pub max_validation_lanes: usize,
    pub lane_policies: LanePolicies,
    pub proof_routing: ProofRoutingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffVerifierConfig {
    pub session_timeout: Duration,
    pub verification_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureMonitorConfig {
    pub monitoring_interval: Duration,
    pub pressure_thresholds: HashMap<String, PressureThresholds>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofAggregatorConfig {
    pub max_beads_per_aggregation: usize,
    pub aggregation_timeout: Duration,
    pub enable_validation: bool,
}

/// Result of agent admission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentAdmissionResult {
    /// Agent was successfully admitted
    Admitted {
        session_id: SessionId,
        allocated_resources: ResourceRequirements,
        agent_region: RegionId,
    },
    /// Agent admission was rejected
    Rejected {
        reason: AdmissionRejectionReason,
        retry_after: Option<Duration>,
    },
}

/// Reasons for agent admission rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdmissionRejectionReason {
    /// System under pressure
    SystemPressure,
    /// Required resources not available
    ResourceUnavailable,
    /// Agent lacks required capabilities
    InsufficientCapabilities,
    /// Maximum agent limit reached
    AgentLimitReached,
    /// Configuration error
    ConfigurationError,
}

// Implementation stubs for associated types
impl AdmissionController {
    pub fn new(config: AdmissionConfig) -> Result<Self> {
        Ok(Self {
            max_concurrent_agents: config.max_concurrent_agents,
            resource_policies: config.resource_policies,
            current_usage: Arc::new(Mutex::new(ResourceUsage::default())),
            admission_queue: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    pub async fn can_admit_agent(&self, cx: &Cx, request: &AgentAdmissionRequest) -> Result<bool> {
        let current_usage = self.current_usage.lock(cx).await?;
        // Implementation would check resource constraints
        Ok(current_usage.cpu_cores_allocated + request.resource_requirements.cpu_cores <= 64.0)
    }
}

impl ValidationCoordinator {
    pub fn new(config: ValidationCoordinatorConfig) -> Result<Self> {
        Ok(Self {
            validation_lanes: Arc::new(Mutex::new(BTreeMap::new())),
            lane_policies: config.lane_policies,
            proof_routing: config.proof_routing,
        })
    }
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            active_agents: HashMap::new(),
            agent_capabilities: HashMap::new(),
            session_metadata: HashMap::new(),
        }
    }

    pub fn register_session(&mut self, session: AgentSession) -> Result<()> {
        self.active_agents.insert(session.agent_id.clone(), session);
        Ok(())
    }
}

impl PressureMonitor {
    pub fn new(_config: PressureMonitorConfig) -> Result<Self> {
        Ok(Self {
            cpu_thresholds: PressureThresholds {
                warning_threshold: 0.7,
                critical_threshold: 0.85,
                emergency_threshold: 0.95,
            },
            memory_thresholds: PressureThresholds {
                warning_threshold: 0.75,
                critical_threshold: 0.90,
                emergency_threshold: 0.98,
            },
            disk_thresholds: PressureThresholds {
                warning_threshold: 0.80,
                critical_threshold: 0.90,
                emergency_threshold: 0.95,
            },
            network_thresholds: PressureThresholds {
                warning_threshold: 0.70,
                critical_threshold: 0.85,
                emergency_threshold: 0.95,
            },
            current_pressure: Arc::new(Mutex::new(SystemPressure::default())),
        })
    }

    pub async fn current_pressure(&self, cx: &Cx) -> Result<SystemPressure> {
        Ok(self.current_pressure.lock(cx).await?.clone())
    }

    pub async fn update_pressure(&self, cx: &Cx, pressure: SystemPressure) -> Result<()> {
        *self.current_pressure.lock(cx).await? = pressure;
        Ok(())
    }
}

impl ControlPlaneMetrics {
    pub fn new() -> Self {
        Self {
            total_agents_admitted: 0,
            total_agents_rejected: 0,
            active_agent_count: 0,
            avg_session_duration: Duration::from_secs(0),
            resource_utilization: ResourceUtilization::default(),
            validation_lane_usage: ValidationLaneUsage::default(),
            proof_aggregation_metrics: ProofAggregationMetrics::default(),
            last_updated: SystemTime::now(),
        }
    }
}

// Default implementations
impl Default for ResourceUsage {
    fn default() -> Self {
        Self {
            cpu_cores_allocated: 0.0,
            memory_allocated: 0,
            disk_allocated: 0,
            network_bandwidth_allocated: 0,
            active_obligations: 0,
            active_regions: 0,
        }
    }
}

impl Default for SystemPressure {
    fn default() -> Self {
        Self {
            cpu_pressure: 0.0,
            memory_pressure: 0.0,
            disk_pressure: 0.0,
            network_pressure: 0.0,
            validation_pressure: 0.0,
            overall_pressure: 0.0,
            measured_at: SystemTime::now(),
        }
    }
}

impl Default for ResourceUtilization {
    fn default() -> Self {
        Self {
            cpu_utilization: 0.0,
            memory_utilization: 0.0,
            disk_utilization: 0.0,
            network_utilization: 0.0,
        }
    }
}

impl Default for ValidationLaneUsage {
    fn default() -> Self {
        Self {
            total_validations: 0,
            successful_validations: 0,
            failed_validations: 0,
            average_validation_time: Duration::from_secs(0),
        }
    }
}

impl Default for ProofAggregationMetrics {
    fn default() -> Self {
        Self {
            total_proofs_generated: 0,
            proofs_per_hour: 0.0,
            average_proof_size: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Budget, Outcome};

    #[test]
    fn test_control_plane_metrics_creation() {
        let metrics = ControlPlaneMetrics::new();
        assert_eq!(metrics.total_agents_admitted, 0);
        assert_eq!(metrics.total_agents_rejected, 0);
        assert_eq!(metrics.active_agent_count, 0);
    }

    #[test]
    fn test_resource_usage_default() {
        let usage = ResourceUsage::default();
        assert_eq!(usage.cpu_cores_allocated, 0.0);
        assert_eq!(usage.memory_allocated, 0);
        assert_eq!(usage.active_obligations, 0);
    }

    #[test]
    fn test_system_pressure_default() {
        let pressure = SystemPressure::default();
        assert_eq!(pressure.cpu_pressure, 0.0);
        assert_eq!(pressure.overall_pressure, 0.0);
    }

    #[test]
    fn test_admission_request_serialization() {
        let request = AgentAdmissionRequest {
            agent_id: "test-agent".to_string(),
            resource_requirements: ResourceRequirements {
                cpu_cores: 2.0,
                memory_bytes: 1024 * 1024 * 1024,    // 1GB
                disk_bytes: 10 * 1024 * 1024 * 1024, // 10GB
                network_bandwidth: 1000000,          // 1MB/s
                estimated_duration: Some(Duration::from_secs(3600)),
            },
            required_capabilities: vec![],
            priority: AdmissionPriority::Normal,
            requested_at: SystemTime::now(),
            admission_timeout: Some(Duration::from_secs(300)),
        };

        let serialized = serde_json::to_string(&request).expect("Failed to serialize");
        let deserialized: AgentAdmissionRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(request.agent_id, deserialized.agent_id);
        assert_eq!(request.priority, deserialized.priority);
    }
}
