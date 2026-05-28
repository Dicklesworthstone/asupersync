//! Agent Swarm Control Plane coordinator.
//!
//! This module provides the main coordination layer for multi-agent workflows,
//! managing resource admission, validation lanes, crash recovery, and operator
//! visibility across concurrent AI agent operations on high-core machines.

#![allow(dead_code)]

use crate::cx::Cx;
use crate::error::{Error, ErrorKind, Result};
use crate::sync::Mutex;
use crate::types::{RegionId, id::next_bootstrap_region_id};
use hmac::{Hmac, KeyInit, Mac};
use nkeys::KeyPair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

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
    /// Authentication and credential verification policy
    auth_policy: AgentAuthPolicy,
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

/// Authentication credentials for agent admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredentials {
    /// Certificate or signature proving agent identity
    pub certificate: String,
    /// Public key for verification
    pub public_key: String,
    /// Signature over agent_id + requested_at timestamp
    pub signature: String,
    /// Optional trust anchor or issuer information
    pub issuer: Option<String>,
}

/// Authentication policy for agent admission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuthPolicy {
    /// HMAC key used to issue and verify scoped admission bearer tokens.
    pub token_hmac_key: String,
    /// Maximum accepted lifetime for bearer tokens.
    pub token_lifetime: Duration,
    /// Maximum accepted age for signed credential admission requests.
    pub credential_lifetime: Duration,
    /// Accepted wall-clock skew for issued-at timestamps.
    pub max_clock_skew: Duration,
    /// Optional allow-list of credential issuers. Empty means issuer allow-listing is disabled.
    pub trusted_issuers: Vec<String>,
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
    /// Authentication token for agent authorization
    pub auth_token: Option<String>,
    /// Agent certificate or credential proof
    pub agent_credentials: Option<AgentCredentials>,
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

type HmacSha256 = Hmac<Sha256>;

const AGENT_AUTH_TOKEN_SCHEME: &str = "agent_token_v1";
const AGENT_CREDENTIAL_SIGNATURE_SCHEME: &str = "nkey_ed25519";
const AGENT_AUTH_TOKEN_DOMAIN: &[u8] = b"asupersync-agent-swarm-auth-token-v1";
const AGENT_CREDENTIAL_SIGNATURE_DOMAIN: &str = "asupersync-agent-swarm-credential-v1";
const MIN_AUTH_HMAC_KEY_BYTES: usize = 32;

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

// Configuration model types used by the in-memory swarm coordinator.
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

impl AgentAuthPolicy {
    /// Issue a scoped bearer token for one agent identity.
    #[must_use]
    pub fn issue_auth_token(
        &self,
        agent_id: &AgentId,
        issued_at: SystemTime,
        lifetime: Duration,
    ) -> Option<String> {
        if !is_valid_agent_auth_identifier(agent_id)
            || self.token_hmac_key.len() < MIN_AUTH_HMAC_KEY_BYTES
            || lifetime.is_zero()
            || lifetime > self.token_lifetime
        {
            return None;
        }

        let issued_at_unix = system_time_unix_seconds(issued_at)?;
        let expires_at_unix = issued_at_unix.checked_add(lifetime.as_secs())?;
        let signature = sign_agent_auth_token(
            agent_id,
            issued_at_unix,
            expires_at_unix,
            self.token_hmac_key.as_bytes(),
        )?;

        Some(format!(
            "{AGENT_AUTH_TOKEN_SCHEME}.{agent_id}.{issued_at_unix}.{expires_at_unix}.{signature}"
        ))
    }
}

fn validate_agent_auth_policy(policy: &AgentAuthPolicy) -> Result<()> {
    if policy.token_hmac_key.len() < MIN_AUTH_HMAC_KEY_BYTES {
        return Err(Error::new(ErrorKind::ConfigError).with_message(format!(
            "agent auth token_hmac_key must be at least {MIN_AUTH_HMAC_KEY_BYTES} bytes"
        )));
    }
    if policy.token_lifetime.is_zero() {
        return Err(Error::new(ErrorKind::ConfigError)
            .with_message("agent auth token_lifetime must be greater than zero"));
    }
    if policy.credential_lifetime.is_zero() {
        return Err(Error::new(ErrorKind::ConfigError)
            .with_message("agent auth credential_lifetime must be greater than zero"));
    }
    if policy.max_clock_skew > policy.token_lifetime {
        return Err(Error::new(ErrorKind::ConfigError)
            .with_message("agent auth max_clock_skew must not exceed token_lifetime"));
    }
    Ok(())
}

fn system_time_unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|age| age.as_secs())
}

fn is_valid_agent_auth_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= 128
        && identifier.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'@' | b'/')
        })
}

fn sign_agent_auth_token(
    agent_id: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
    key: &[u8],
) -> Option<String> {
    if key.len() < MIN_AUTH_HMAC_KEY_BYTES {
        return None;
    }

    let issued = issued_at_unix.to_string();
    let expires = expires_at_unix.to_string();
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(AGENT_AUTH_TOKEN_DOMAIN);
    mac.update(&[0]);
    mac.update(agent_id.as_bytes());
    mac.update(&[0]);
    mac.update(issued.as_bytes());
    mac.update(&[0]);
    mac.update(expires.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

fn credential_signature_payload(
    credentials: &AgentCredentials,
    agent_id: &AgentId,
    requested_at_unix: u64,
) -> String {
    let certificate_digest = Sha256::digest(credentials.certificate.as_bytes());
    format!(
        "{AGENT_CREDENTIAL_SIGNATURE_DOMAIN}\nagent_id:{agent_id}\nrequested_at:{requested_at_unix}\ncertificate_sha256:{}\nissuer:{}\n",
        hex::encode(certificate_digest),
        credentials.issuer.as_deref().unwrap_or("")
    )
}

fn constant_time_hex_eq(left_hex: &str, right_hex: &str) -> bool {
    let Ok(left) = hex::decode(left_hex) else {
        return false;
    };
    let Ok(right) = hex::decode(right_hex) else {
        return false;
    };
    bool::from(left.as_slice().ct_eq(right.as_slice()))
}

impl AgentSwarmControlPlane {
    /// Create a new Agent Swarm Control Plane instance.
    pub fn new(config: ControlPlaneConfig) -> Result<Self> {
        let admission_controller = Arc::new(AdmissionController::new(config.admission_config)?);
        let validation_coordinator =
            Arc::new(ValidationCoordinator::new(config.validation_config)?);
        let handoff_verifier = Arc::new(Mutex::new(HandoffVerifier::new()));
        let proof_aggregator = Arc::new(Mutex::new(ReleaseProofAggregator::new(
            config.proof_config.to_release_aggregator_config(),
        )));
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
        // SECURITY: Validate agent authentication/authorization before admission
        if !self.validate_agent_authorization(cx, &request).await? {
            return self
                .reject_admission(
                    cx,
                    AdmissionRejectionReason::Unauthorized,
                    Some(Duration::from_secs(60)),
                )
                .await;
        }

        // Check current system pressure
        let pressure = self.pressure_monitor.current_pressure(cx).await?;
        if pressure.overall_pressure > 0.8 {
            return self
                .reject_admission(
                    cx,
                    AdmissionRejectionReason::SystemPressure,
                    Some(Duration::from_secs(30)),
                )
                .await;
        }

        let already_active = {
            let registry = self.agent_registry.lock(cx).await?;
            registry.active_agents.contains_key(&request.agent_id)
        };

        if already_active {
            return self
                .reject_admission(
                    cx,
                    AdmissionRejectionReason::AgentLimitReached,
                    Some(Duration::from_secs(60)),
                )
                .await;
        }

        let allocated = self
            .admission_controller
            .try_allocate_agent_resources(cx, &request)
            .await?;

        if !allocated {
            return self
                .reject_admission(
                    cx,
                    AdmissionRejectionReason::ResourceUnavailable,
                    Some(Duration::from_secs(60)),
                )
                .await;
        }

        // Create a control-plane-local owning region for this admission.
        let agent_region = next_bootstrap_region_id();
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

        if let Err(err) = {
            let mut registry = self.agent_registry.lock(cx).await?;
            registry.register_session(session.clone())
        } {
            self.admission_controller
                .release_agent_resources(cx, &request.resource_requirements)
                .await?;
            return Err(err);
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

    async fn reject_admission(
        &self,
        cx: &Cx,
        reason: AdmissionRejectionReason,
        retry_after: Option<Duration>,
    ) -> Result<AgentAdmissionResult> {
        {
            let mut metrics = self.metrics.lock(cx).await?;
            metrics.total_agents_rejected += 1;
            metrics.last_updated = SystemTime::now();
        }

        Ok(AgentAdmissionResult::Rejected {
            reason,
            retry_after,
        })
    }

    /// Validate agent authorization and authentication.
    async fn validate_agent_authorization(
        &self,
        _cx: &Cx,
        request: &AgentAdmissionRequest,
    ) -> Result<bool> {
        // If no authentication provided, reject
        if request.auth_token.is_none() && request.agent_credentials.is_none() {
            return Ok(false);
        }

        // Validate auth token if provided
        if let Some(ref token) = request.auth_token {
            if !self.validate_auth_token(token, &request.agent_id).await? {
                return Ok(false);
            }
        }

        // Validate agent credentials if provided
        if let Some(ref credentials) = request.agent_credentials {
            if !self
                .validate_agent_credentials(credentials, &request.agent_id, request.requested_at)
                .await?
            {
                return Ok(false);
            }
        }

        // Additional authorization checks (role-based access, resource limits, etc.)
        self.check_agent_permissions(&request.agent_id, &request.priority)
            .await
    }

    /// Validate authentication token.
    async fn validate_auth_token(&self, token: &str, agent_id: &AgentId) -> Result<bool> {
        let policy = &self.admission_controller.auth_policy;
        let mut parts = token.split('.');
        let Some(scheme) = parts.next() else {
            return Ok(false);
        };
        let Some(token_agent_id) = parts.next() else {
            return Ok(false);
        };
        let Some(issued_at_raw) = parts.next() else {
            return Ok(false);
        };
        let Some(expires_at_raw) = parts.next() else {
            return Ok(false);
        };
        let Some(signature_hex) = parts.next() else {
            return Ok(false);
        };
        if parts.next().is_some()
            || scheme != AGENT_AUTH_TOKEN_SCHEME
            || !is_valid_agent_auth_identifier(token_agent_id)
            || !bool::from(token_agent_id.as_bytes().ct_eq(agent_id.as_bytes()))
        {
            return Ok(false);
        }

        let Ok(issued_at_unix) = issued_at_raw.parse::<u64>() else {
            return Ok(false);
        };
        let Ok(expires_at_unix) = expires_at_raw.parse::<u64>() else {
            return Ok(false);
        };
        if expires_at_unix <= issued_at_unix {
            return Ok(false);
        }

        let lifetime = Duration::from_secs(expires_at_unix - issued_at_unix);
        if lifetime > policy.token_lifetime {
            return Ok(false);
        }

        let Some(now_unix) = system_time_unix_seconds(SystemTime::now()) else {
            return Ok(false);
        };
        let skew = policy.max_clock_skew.as_secs();
        if issued_at_unix > now_unix.saturating_add(skew)
            || now_unix > expires_at_unix.saturating_add(skew)
        {
            return Ok(false);
        }

        let Some(expected_signature) = sign_agent_auth_token(
            token_agent_id,
            issued_at_unix,
            expires_at_unix,
            policy.token_hmac_key.as_bytes(),
        ) else {
            return Ok(false);
        };

        Ok(constant_time_hex_eq(signature_hex, &expected_signature))
    }

    /// Validate agent credentials and signature.
    async fn validate_agent_credentials(
        &self,
        credentials: &AgentCredentials,
        agent_id: &AgentId,
        requested_at: SystemTime,
    ) -> Result<bool> {
        if credentials.certificate.is_empty()
            || credentials.public_key.is_empty()
            || credentials.signature.is_empty()
            || !is_valid_agent_auth_identifier(agent_id)
        {
            return Ok(false);
        }

        let policy = &self.admission_controller.auth_policy;
        if !policy.trusted_issuers.is_empty() {
            let Some(issuer) = credentials.issuer.as_deref() else {
                return Ok(false);
            };
            if !policy
                .trusted_issuers
                .iter()
                .any(|trusted| trusted == issuer)
            {
                return Ok(false);
            }
        }

        let Some(requested_at_unix) = system_time_unix_seconds(requested_at) else {
            return Ok(false);
        };
        let Some(now_unix) = system_time_unix_seconds(SystemTime::now()) else {
            return Ok(false);
        };
        let skew = policy.max_clock_skew.as_secs();
        if requested_at_unix > now_unix.saturating_add(skew) {
            return Ok(false);
        }
        let max_age = policy
            .credential_lifetime
            .as_secs()
            .saturating_add(policy.max_clock_skew.as_secs());
        if now_unix.saturating_sub(requested_at_unix) > max_age {
            return Ok(false);
        }

        let Some(signature_hex) = credentials
            .signature
            .strip_prefix(AGENT_CREDENTIAL_SIGNATURE_SCHEME)
            .and_then(|rest| rest.strip_prefix('.'))
        else {
            return Ok(false);
        };
        let Ok(signature) = hex::decode(signature_hex) else {
            return Ok(false);
        };
        let Ok(key_pair) = KeyPair::from_public_key(&credentials.public_key) else {
            return Ok(false);
        };
        let payload = credential_signature_payload(credentials, agent_id, requested_at_unix);

        Ok(key_pair.verify(payload.as_bytes(), &signature).is_ok())
    }

    /// Check agent permissions and authorization levels.
    async fn check_agent_permissions(
        &self,
        agent_id: &AgentId,
        priority: &AdmissionPriority,
    ) -> Result<bool> {
        // Check if agent is in allowed list
        // Check role-based access for the requested priority level
        // Verify agent has not been revoked or banned

        // For critical/high priority, require additional authorization
        match priority {
            AdmissionPriority::Critical => {
                // Only pre-approved critical agents allowed
                Ok(agent_id.starts_with("critical_agent_"))
            }
            AdmissionPriority::High => {
                // High priority agents need elevated permissions
                Ok(agent_id.starts_with("high_agent_") || agent_id.starts_with("critical_agent_"))
            }
            AdmissionPriority::Normal | AdmissionPriority::Low => {
                // Normal agents just need valid authentication
                Ok(!agent_id.starts_with("banned_") && !agent_id.is_empty())
            }
        }
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
        let active_sessions = {
            let mut registry = self.agent_registry.lock(cx).await?;
            let sessions = registry
                .active_agents
                .values_mut()
                .map(|session| {
                    session.status = AgentStatus::Shutting;
                    session.clone()
                })
                .collect::<Vec<_>>();
            registry.active_agents.clear();
            sessions
        };

        let mut total_duration = Duration::ZERO;
        let now = SystemTime::now();
        for session in &active_sessions {
            self.admission_controller
                .release_agent_resources(cx, &session.allocated_resources)
                .await?;
            total_duration += now
                .duration_since(session.started_at)
                .unwrap_or(Duration::ZERO);
        }

        {
            let mut metrics = self.metrics.lock(cx).await?;
            metrics.active_agent_count = 0;
            if !active_sessions.is_empty() {
                metrics.avg_session_duration =
                    total_duration / u32::try_from(active_sessions.len()).unwrap_or(u32::MAX);
            }
            metrics.last_updated = now;
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
    pub auth_policy: AgentAuthPolicy,
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
    pub max_evidence_age: Duration,
    pub max_commit_age: Duration,
    pub require_remote_rch: bool,
    pub redact_sensitive: bool,
    pub output_retention_days: u64,
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
    /// Agent lacks valid authentication or authorization
    Unauthorized,
}

impl ProofAggregatorConfig {
    fn to_release_aggregator_config(&self) -> super::release_proof_aggregator::AggregatorConfig {
        super::release_proof_aggregator::AggregatorConfig {
            max_evidence_age: self.max_evidence_age,
            max_commit_age: self.max_commit_age,
            require_remote_rch: self.require_remote_rch && self.enable_validation,
            redact_sensitive: self.redact_sensitive,
            output_retention_days: self.output_retention_days,
        }
    }
}

impl AdmissionController {
    pub fn new(config: AdmissionConfig) -> Result<Self> {
        validate_agent_auth_policy(&config.auth_policy)?;
        Ok(Self {
            max_concurrent_agents: config.max_concurrent_agents,
            resource_policies: config.resource_policies,
            auth_policy: config.auth_policy,
            current_usage: Arc::new(Mutex::new(ResourceUsage::default())),
            admission_queue: Arc::new(Mutex::new(VecDeque::new())),
        })
    }

    pub async fn can_admit_agent(&self, cx: &Cx, request: &AgentAdmissionRequest) -> Result<bool> {
        let current_usage = self.current_usage.lock(cx).await?;
        Ok(self.can_fit_locked(&current_usage, &request.resource_requirements))
    }

    pub async fn try_allocate_agent_resources(
        &self,
        cx: &Cx,
        request: &AgentAdmissionRequest,
    ) -> Result<bool> {
        let mut current_usage = self.current_usage.lock(cx).await?;
        if !self.can_fit_locked(&current_usage, &request.resource_requirements) {
            return Ok(false);
        }

        current_usage.cpu_cores_allocated += request.resource_requirements.cpu_cores;
        current_usage.memory_allocated = current_usage
            .memory_allocated
            .saturating_add(request.resource_requirements.memory_bytes);
        current_usage.disk_allocated = current_usage
            .disk_allocated
            .saturating_add(request.resource_requirements.disk_bytes);
        current_usage.network_bandwidth_allocated = current_usage
            .network_bandwidth_allocated
            .saturating_add(request.resource_requirements.network_bandwidth);
        current_usage.active_regions = current_usage.active_regions.saturating_add(1);
        Ok(true)
    }

    pub async fn release_agent_resources(
        &self,
        cx: &Cx,
        resources: &ResourceRequirements,
    ) -> Result<()> {
        let mut current_usage = self.current_usage.lock(cx).await?;
        current_usage.cpu_cores_allocated =
            (current_usage.cpu_cores_allocated - resources.cpu_cores).max(0.0);
        current_usage.memory_allocated = current_usage
            .memory_allocated
            .saturating_sub(resources.memory_bytes);
        current_usage.disk_allocated = current_usage
            .disk_allocated
            .saturating_sub(resources.disk_bytes);
        current_usage.network_bandwidth_allocated = current_usage
            .network_bandwidth_allocated
            .saturating_sub(resources.network_bandwidth);
        current_usage.active_regions = current_usage.active_regions.saturating_sub(1);
        Ok(())
    }

    fn can_fit_locked(
        &self,
        current_usage: &ResourceUsage,
        requested: &ResourceRequirements,
    ) -> bool {
        if self.max_concurrent_agents == 0
            || current_usage.active_regions >= self.max_concurrent_agents
            || requested.cpu_cores <= 0.0
            || !requested.cpu_cores.is_finite()
            || requested.memory_bytes == 0
        {
            return false;
        }

        if requested.cpu_cores > self.resource_policies.cpu_policy.max_cores_per_agent
            || requested.memory_bytes > self.resource_policies.memory_policy.max_memory_per_agent
            || requested.disk_bytes > self.resource_policies.disk_policy.max_disk_per_agent
            || requested.network_bandwidth
                > self
                    .resource_policies
                    .network_policy
                    .max_bandwidth_per_agent
        {
            return false;
        }

        let max_agents = self.max_concurrent_agents as f64;
        let total_cpu_capacity = self.resource_policies.cpu_policy.max_cores_per_agent * max_agents;
        let total_memory_capacity = self
            .resource_policies
            .memory_policy
            .max_memory_per_agent
            .saturating_mul(self.max_concurrent_agents as u64);
        let total_disk_capacity = self
            .resource_policies
            .disk_policy
            .max_disk_per_agent
            .saturating_mul(self.max_concurrent_agents as u64);
        let total_network_capacity = self
            .resource_policies
            .network_policy
            .max_bandwidth_per_agent
            .saturating_mul(self.max_concurrent_agents as u64);

        current_usage.cpu_cores_allocated + requested.cpu_cores <= total_cpu_capacity
            && current_usage
                .memory_allocated
                .saturating_add(requested.memory_bytes)
                <= total_memory_capacity
            && current_usage
                .disk_allocated
                .saturating_add(requested.disk_bytes)
                <= total_disk_capacity
            && current_usage
                .network_bandwidth_allocated
                .saturating_add(requested.network_bandwidth)
                <= total_network_capacity
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

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
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
            auth_token: None,
            agent_credentials: None,
        };

        let serialized = serde_json::to_string(&request).expect("Failed to serialize");
        let deserialized: AgentAdmissionRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(request.agent_id, deserialized.agent_id);
        assert_eq!(request.priority, deserialized.priority);
    }
}
