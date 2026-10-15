//! ATP Multi-Peer Test Infrastructure
//!
//! Test framework for ATP-NR12 mailbox, swarm, cache, and multi-peer scenarios.
//! This module provides the foundational test infrastructure for validating
//! complex ATP data movement scenarios involving multiple peers, offline modes,
//! caching, and swarm transfers.

pub mod cache;
pub mod contracts;
pub mod harness;
pub mod mailbox;
pub mod scenarios;
pub mod swarm;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Schema version for multi-peer test reports
pub const MULTI_PEER_REPORT_SCHEMA: &str = "asupersync.atp.multipeer.report.v1";

/// Schema version for multi-peer test events
pub const MULTI_PEER_EVENT_SCHEMA: &str = "asupersync.atp.multipeer.event.v1";

/// Multi-peer test scenario configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiPeerScenario {
    /// Scenario identifier
    pub scenario_id: String,
    /// Human-readable description
    pub description: String,
    /// Scenario type (mailbox, swarm, cache, adversarial)
    pub scenario_type: ScenarioType,
    /// Participating peers
    pub peers: Vec<PeerConfig>,
    /// Network topology configuration
    pub network: NetworkConfig,
    /// Transfer configuration
    pub transfer: TransferConfig,
    /// Expected outcomes
    pub expectations: ScenarioExpectations,
    /// Test timeout
    pub timeout: Duration,
}

/// Type of multi-peer scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScenarioType {
    /// Offline mailbox upload/download
    Mailbox,
    /// Multi-source swarm transfer
    Swarm,
    /// Cache hit/miss/eviction scenarios
    Cache,
    /// Peer churn and network dynamics
    PeerChurn,
    /// Malicious peer behavior
    Adversarial,
    /// Combined scenario
    Hybrid(Vec<ScenarioType>),
}

/// Configuration for a participating peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer identifier
    pub peer_id: String,
    /// Peer role (sender, receiver, relay, seed, malicious)
    pub role: PeerRole,
    /// Online/offline schedule
    pub availability: AvailabilitySchedule,
    /// Capability configuration
    pub capabilities: PeerCapabilities,
    /// Working directory
    pub work_dir: Option<PathBuf>,
}

/// Role of a peer in the scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerRole {
    /// Original source of data
    Sender,
    /// Final destination of data
    Receiver,
    /// Relay/forwarding node
    Relay,
    /// Seeding node with cached data
    Seed,
    /// Mailbox storage provider
    Mailbox,
    /// Malicious/adversarial node
    Malicious,
}

/// Peer online/offline schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilitySchedule {
    /// Initial online state
    pub initially_online: bool,
    /// Scheduled state changes (time, online)
    pub schedule: Vec<(Duration, bool)>,
}

/// Capabilities of a peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    /// Maximum storage quota
    pub storage_quota: Option<u64>,
    /// Maximum bandwidth (bytes/sec)
    pub bandwidth_limit: Option<u64>,
    /// Cache policies enabled
    pub cache_enabled: bool,
    /// Seeding enabled
    pub seeding_enabled: bool,
    /// Relay enabled
    pub relay_enabled: bool,
}

/// Network configuration for the scenario
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Network latency between peers (ms)
    pub latency_ms: HashMap<(String, String), u64>,
    /// Packet loss rates between peers (0.0-1.0)
    pub packet_loss: HashMap<(String, String), f64>,
    /// Bandwidth limits between peers (bytes/sec)
    pub bandwidth: HashMap<(String, String), u64>,
    /// Network partitions (list of peer groups)
    pub partitions: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkPairMetric<T> {
    from: String,
    to: String,
    value: T,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkConfigWire {
    latency_ms: Vec<NetworkPairMetric<u64>>,
    packet_loss: Vec<NetworkPairMetric<f64>>,
    bandwidth: Vec<NetworkPairMetric<u64>>,
    partitions: Vec<Vec<String>>,
}

impl Serialize for NetworkConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        NetworkConfigWire {
            latency_ms: sorted_pair_metrics(&self.latency_ms),
            packet_loss: sorted_pair_metrics(&self.packet_loss),
            bandwidth: sorted_pair_metrics(&self.bandwidth),
            partitions: self.partitions.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetworkConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = NetworkConfigWire::deserialize(deserializer)?;
        Ok(Self {
            latency_ms: pair_metrics_to_map(wire.latency_ms),
            packet_loss: pair_metrics_to_map(wire.packet_loss),
            bandwidth: pair_metrics_to_map(wire.bandwidth),
            partitions: wire.partitions,
        })
    }
}

fn sorted_pair_metrics<T: Clone>(map: &HashMap<(String, String), T>) -> Vec<NetworkPairMetric<T>> {
    let mut metrics: Vec<_> = map
        .iter()
        .map(|((from, to), value)| NetworkPairMetric {
            from: from.clone(),
            to: to.clone(),
            value: value.clone(),
        })
        .collect();
    metrics.sort_by(|left, right| {
        left.from
            .cmp(&right.from)
            .then_with(|| left.to.cmp(&right.to))
    });
    metrics
}

fn pair_metrics_to_map<T>(metrics: Vec<NetworkPairMetric<T>>) -> HashMap<(String, String), T> {
    metrics
        .into_iter()
        .map(|metric| ((metric.from, metric.to), metric.value))
        .collect()
}

/// Transfer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferConfig {
    /// Source file size or content specification
    pub source: SourceSpec,
    /// Required encryption
    pub encrypted: bool,
    /// Repair coding configuration
    pub repair_config: Option<RepairConfig>,
    /// Chunk size
    pub chunk_size: u64,
    /// Verification requirements
    pub verification: VerificationConfig,
}

/// Source content specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceSpec {
    /// Random data of specified size
    RandomBytes(u64),
    /// Specific file path
    FilePath(PathBuf),
    /// Sparse file with holes
    SparseFile { size: u64, hole_ratio: f64 },
    /// Directory tree
    Directory { path: PathBuf, recursive: bool },
}

/// Repair coding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairConfig {
    /// Number of data blocks
    pub k: u32,
    /// Number of repair blocks
    pub n: u32,
    /// Repair threshold
    pub threshold: f64,
}

/// Verification requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Require cryptographic verification
    pub crypto_verification: bool,
    /// Require manifest verification
    pub manifest_verification: bool,
    /// Require proof bundle
    pub proof_bundle: bool,
    /// Allowed verification failures
    pub allowed_failures: u32,
}

/// Expected outcomes for the scenario
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioExpectations {
    /// Expected success state
    pub success: bool,
    /// Expected transfer completion time
    pub completion_time: Option<Duration>,
    /// Expected bytes transferred
    pub bytes_transferred: Option<u64>,
    /// Expected peer rejections
    pub peer_rejections: Option<u32>,
    /// Expected cache hits/misses
    pub cache_metrics: Option<CacheMetrics>,
    /// Expected log events
    pub log_events: Vec<LogEventExpectation>,
}

/// Expected cache metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    /// Expected cache hits
    pub hits: Option<u32>,
    /// Expected cache misses
    pub misses: Option<u32>,
    /// Expected evictions
    pub evictions: Option<u32>,
}

/// Expected log event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEventExpectation {
    /// Event type pattern
    pub event_type: String,
    /// Required fields
    pub required_fields: Vec<String>,
    /// Expected occurrence count
    pub count: Option<u32>,
}

/// Result of a multi-peer scenario execution
#[derive(Debug, Serialize, Deserialize)]
pub struct MultiPeerResult {
    /// Schema version
    pub schema_version: String,
    /// Scenario that was executed
    pub scenario: MultiPeerScenario,
    /// Execution timestamp
    pub executed_at: SystemTime,
    /// Overall success state
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Duration of execution
    pub duration: Duration,
    /// Per-peer results
    pub peer_results: HashMap<String, PeerResult>,
    /// Network events observed
    pub network_events: Vec<NetworkEvent>,
    /// Transfer metrics
    pub transfer_metrics: TransferMetrics,
    /// Cache metrics
    pub cache_metrics: HashMap<String, CacheMetrics>,
    /// Verification results
    pub verification_results: VerificationResults,
    /// Artifact paths
    pub artifacts: ArtifactPaths,
}

/// Result for an individual peer
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerResult {
    /// Peer configuration
    pub config: PeerConfig,
    /// Success state
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Process exit code
    pub exit_code: Option<i32>,
    /// Bytes sent/received
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Connection events
    pub connections: Vec<ConnectionEvent>,
    /// Log file path
    pub log_path: PathBuf,
}

/// Network event observed during execution
#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: String,
    /// Participating peers
    pub peers: Vec<String>,
    /// Additional data
    pub data: HashMap<String, String>,
}

/// Connection event between peers
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Remote peer ID
    pub remote_peer: String,
    /// Event type (connect, disconnect, error)
    pub event_type: String,
    /// Additional details
    pub details: Option<String>,
}

/// Transfer metrics for the scenario
#[derive(Debug, Serialize, Deserialize)]
pub struct TransferMetrics {
    /// Total bytes transferred
    pub total_bytes: u64,
    /// Bytes verified successfully
    pub verified_bytes: u64,
    /// Number of chunks transferred
    pub chunks_transferred: u32,
    /// Number of repair blocks used
    pub repair_blocks_used: u32,
    /// Peer rejection count
    pub peer_rejections: u32,
    /// Source selection decisions
    pub source_selections: Vec<SourceSelection>,
}

/// Record of source selection decision
#[derive(Debug, Serialize, Deserialize)]
pub struct SourceSelection {
    /// Chunk identifier
    pub chunk_id: String,
    /// Selected peer
    pub selected_peer: String,
    /// Selection reason
    pub reason: String,
    /// Rejected peers and reasons
    pub rejected_peers: HashMap<String, String>,
}

/// Verification results
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationResults {
    /// Cryptographic verification passed
    pub crypto_verified: bool,
    /// Manifest verification passed
    pub manifest_verified: bool,
    /// Proof bundle verified
    pub proof_verified: bool,
    /// Verification failures
    pub failures: Vec<VerificationFailure>,
}

/// Verification failure details
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationFailure {
    /// Verification type that failed
    pub verification_type: String,
    /// Failure reason
    pub reason: String,
    /// Associated chunk/peer
    pub context: HashMap<String, String>,
}

/// Artifact paths generated during test
#[derive(Debug, Serialize, Deserialize)]
pub struct ArtifactPaths {
    /// Test report JSON
    pub report: PathBuf,
    /// Log directory
    pub logs: PathBuf,
    /// Trace files
    pub traces: Vec<PathBuf>,
    /// Source files
    pub sources: Vec<PathBuf>,
    /// Destination files
    pub destinations: Vec<PathBuf>,
}

impl MultiPeerScenario {
    /// Validate scenario configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.peers.is_empty() {
            return Err("Scenario must have at least one peer".to_string());
        }

        // Validate peer roles make sense for scenario type
        match self.scenario_type {
            ScenarioType::Mailbox => {
                let has_sender = self
                    .peers
                    .iter()
                    .any(|p| matches!(p.role, PeerRole::Sender));
                let has_receiver = self
                    .peers
                    .iter()
                    .any(|p| matches!(p.role, PeerRole::Receiver));
                let has_mailbox = self
                    .peers
                    .iter()
                    .any(|p| matches!(p.role, PeerRole::Mailbox));

                if !has_sender || !has_receiver || !has_mailbox {
                    return Err(
                        "Mailbox scenario requires sender, receiver, and mailbox peers".to_string(),
                    );
                }
            }
            ScenarioType::Swarm => {
                let has_receiver = self
                    .peers
                    .iter()
                    .any(|p| matches!(p.role, PeerRole::Receiver));
                let seed_count = self
                    .peers
                    .iter()
                    .filter(|p| matches!(p.role, PeerRole::Seed))
                    .count();

                if !has_receiver || seed_count < 2 {
                    return Err(
                        "Swarm scenario requires receiver and multiple seed peers".to_string()
                    );
                }
            }
            _ => {} // Other scenarios have more flexible requirements
        }

        Ok(())
    }

    /// Get all peer IDs
    pub fn peer_ids(&self) -> Vec<String> {
        self.peers.iter().map(|p| p.peer_id.clone()).collect()
    }

    /// Get peers by role
    pub fn peers_by_role(&self, role: &PeerRole) -> Vec<&PeerConfig> {
        self.peers
            .iter()
            .filter(|p| std::mem::discriminant(&p.role) == std::mem::discriminant(role))
            .collect()
    }
}

impl Default for MultiPeerScenario {
    fn default() -> Self {
        Self {
            scenario_id: "default".to_string(),
            description: "Default multi-peer scenario".to_string(),
            scenario_type: ScenarioType::Swarm,
            peers: Vec::new(),
            network: NetworkConfig {
                latency_ms: HashMap::new(),
                packet_loss: HashMap::new(),
                bandwidth: HashMap::new(),
                partitions: Vec::new(),
            },
            transfer: TransferConfig {
                source: SourceSpec::RandomBytes(1024 * 1024), // 1MB
                encrypted: true,
                repair_config: None,
                chunk_size: 64 * 1024, // 64KB
                verification: VerificationConfig {
                    crypto_verification: true,
                    manifest_verification: true,
                    proof_bundle: true,
                    allowed_failures: 0,
                },
            },
            expectations: ScenarioExpectations {
                success: true,
                completion_time: None,
                bytes_transferred: None,
                peer_rejections: None,
                cache_metrics: None,
                log_events: Vec::new(),
            },
            timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}
