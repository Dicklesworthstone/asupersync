//! ATP Transfer Preflight Planner
//!
//! Implements transfer planning, dry-run, cost modeling, and explainable execution plans
//! before irreversible network, relay, mailbox, disk, or destructive sync actions.

use crate::Cx;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Schema version for ATP transfer plans
pub const ATP_TRANSFER_PLAN_SCHEMA: &str = "atp-transfer-plan-v1";

/// Schema version for ATP plan execution reports
pub const ATP_PLAN_EXECUTION_REPORT_SCHEMA: &str = "atp-plan-execution-report-v1";

/// Errors that can occur during planning
#[derive(Debug, thiserror::Error)]
pub enum PlannerError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Insufficient disk space: need {needed} bytes, have {available} bytes")]
    InsufficientDiskSpace { needed: u64, available: u64 },
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("Path not available: {0}")]
    PathNotAvailable(String),
    #[error("Receive denied: {0}")]
    ReceiveDenied(String),
    #[error("Planning failed: {0}")]
    PlanningFailed(String),
}

/// Type of ATP transfer operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferType {
    /// Direct send operation
    Send,
    /// Directory sync operation
    Sync,
    /// Mirror with potential deletes
    Mirror,
    /// Share operation
    Share,
    /// Stream operation
    Stream,
}

/// Transfer mode configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferMode {
    /// Direct peer-to-peer transfer
    Direct,
    /// Transfer via relay
    RelayOnly,
    /// Transfer via offline mailbox
    Mailbox,
    /// Multi-source swarm transfer
    Swarm,
    /// Sparse file transfer
    SparseImage,
}

/// Object graph summary for planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectGraphSummary {
    /// Total object count
    pub object_count: u64,
    /// Total estimated bytes
    pub total_bytes: u64,
    /// File count
    pub file_count: u64,
    /// Directory count
    pub directory_count: u64,
    /// Largest file size
    pub largest_file_bytes: u64,
    /// Small files count (< 1MB)
    pub small_files_count: u64,
}

/// Chunking profile for transfer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkingProfile {
    /// Chunk size in bytes
    pub chunk_size: u32,
    /// Estimated chunk count
    pub estimated_chunks: u64,
    /// RaptorQ repair overhead ratio
    pub repair_overhead_ratio: f64,
    /// Compression ratio estimate
    pub compression_ratio: f64,
}

/// Path candidate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCandidate {
    /// Path type (direct, relay, etc.)
    pub path_type: String,
    /// Estimated RTT
    pub estimated_rtt: Duration,
    /// Estimated bandwidth in bytes/sec
    pub estimated_bandwidth: u64,
    /// Reliability score (0.0-1.0)
    pub reliability_score: f64,
    /// Whether this path is preferred
    pub preferred: bool,
}

/// Disk allocation plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskAllocationPlan {
    /// Destination path
    pub destination_path: PathBuf,
    /// Required disk space in bytes
    pub required_space: u64,
    /// Available disk space in bytes
    pub available_space: u64,
    /// Preallocation strategy
    pub preallocation_strategy: String,
    /// Temporary space needed during transfer
    pub temp_space_needed: u64,
}

/// Resource governance profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGovernanceProfile {
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Bandwidth limit in bytes/sec
    pub bandwidth_limit: Option<u64>,
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
    /// CPU limit as percentage
    pub cpu_limit: Option<f32>,
}

/// Resume state information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    /// Whether resume is available
    pub resume_available: bool,
    /// Resume token if available
    pub resume_token: Option<String>,
    /// Bytes already transferred
    pub bytes_completed: u64,
    /// Chunks already verified
    pub chunks_completed: u64,
}

/// Cache hit analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheAnalysis {
    /// Local cache hit ratio
    pub local_hit_ratio: f64,
    /// Remote cache hit ratio
    pub remote_hit_ratio: f64,
    /// Bytes served from cache
    pub bytes_from_cache: u64,
    /// Cache locations available
    pub cache_locations: Vec<String>,
}

/// Uncertainty factors in the plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanUncertainty {
    /// Bandwidth estimation confidence (0.0-1.0)
    pub bandwidth_confidence: f64,
    /// Path availability confidence (0.0-1.0)
    pub path_confidence: f64,
    /// Peer availability confidence (0.0-1.0)
    pub peer_confidence: f64,
    /// Resource availability confidence (0.0-1.0)
    pub resource_confidence: f64,
    /// Known uncertainty factors
    pub uncertainty_factors: Vec<String>,
}

/// ATP Transfer Plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtpTransferPlan {
    /// Schema version
    pub schema_version: String,
    /// Plan ID for tracking
    pub plan_id: String,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Transfer type
    pub transfer_type: TransferType,
    /// Transfer mode
    pub transfer_mode: TransferMode,
    /// Object graph summary
    pub object_graph: ObjectGraphSummary,
    /// Chunking profile
    pub chunking_profile: ChunkingProfile,
    /// Estimated total bytes (including overhead)
    pub estimated_bytes_on_wire: u64,
    /// Path candidates
    pub path_candidates: Vec<PathCandidate>,
    /// Disk allocation plan
    pub disk_allocation: DiskAllocationPlan,
    /// Resource governance profile
    pub governance_profile: ResourceGovernanceProfile,
    /// Resume state
    pub resume_state: ResumeState,
    /// Cache analysis
    pub cache_analysis: CacheAnalysis,
    /// Proof output configuration
    pub proof_outputs: HashMap<String, String>,
    /// Uncertainty analysis
    pub uncertainty: PlanUncertainty,
    /// Estimated duration
    pub estimated_duration: Duration,
    /// Estimated completion time
    pub estimated_completion: SystemTime,
}

/// Plan execution deviation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDeviation {
    /// Deviation timestamp
    pub timestamp: SystemTime,
    /// Deviation type
    pub deviation_type: String,
    /// Expected value
    pub expected_value: String,
    /// Actual value
    pub actual_value: String,
    /// Reason for deviation
    pub reason: String,
    /// Impact severity
    pub impact_severity: String,
}

/// Plan execution report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanExecutionReport {
    /// Schema version
    pub schema_version: String,
    /// Plan ID being executed
    pub plan_id: String,
    /// Execution start time
    pub started_at: SystemTime,
    /// Execution completion time (if completed)
    pub completed_at: Option<SystemTime>,
    /// Plan deviations
    pub deviations: Vec<PlanDeviation>,
    /// Final statistics
    pub final_stats: HashMap<String, serde_json::Value>,
    /// Success status
    pub success: bool,
    /// Error message if failed
    pub error_message: Option<String>,
}

/// ATP Transfer Planner
#[derive(Debug)]
pub struct AtpTransferPlanner {
    /// Configuration options
    config: PlannerConfig,
}

/// Planner configuration
#[derive(Debug, Clone)]
pub struct PlannerConfig {
    /// Default chunk size
    pub default_chunk_size: u32,
    /// Default repair overhead
    pub default_repair_overhead: f64,
    /// Default bandwidth estimation
    pub default_bandwidth_bps: u64,
    /// Planning timeout
    pub planning_timeout: Duration,
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            default_chunk_size: 64 * 1024,           // 64KB
            default_repair_overhead: 0.1,            // 10%
            default_bandwidth_bps: 10 * 1024 * 1024, // 10 Mbps
            planning_timeout: Duration::from_secs(30),
        }
    }
}

fn analyze_directory_tree(source_path: &Path) -> Result<ObjectGraphSummary, PlannerError> {
    let mut summary = ObjectGraphSummary {
        object_count: 0,
        total_bytes: 0,
        file_count: 0,
        directory_count: 0,
        largest_file_bytes: 0,
        small_files_count: 0,
    };
    let mut stack = vec![source_path.to_path_buf()];

    while let Some(path) = stack.pop() {
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            PlannerError::InvalidInput(format!(
                "Cannot read source metadata for {}: {error}",
                path.display()
            ))
        })?;

        summary.object_count = summary.object_count.saturating_add(1);
        if metadata.is_dir() {
            summary.directory_count = summary.directory_count.saturating_add(1);
            for entry in std::fs::read_dir(&path).map_err(|error| {
                PlannerError::InvalidInput(format!(
                    "Cannot read source directory {}: {error}",
                    path.display()
                ))
            })? {
                let entry = entry.map_err(|error| {
                    PlannerError::InvalidInput(format!(
                        "Cannot read source directory entry in {}: {error}",
                        path.display()
                    ))
                })?;
                stack.push(entry.path());
            }
        } else {
            let len = metadata.len();
            summary.file_count = summary.file_count.saturating_add(1);
            summary.total_bytes = summary.total_bytes.saturating_add(len);
            summary.largest_file_bytes = summary.largest_file_bytes.max(len);
            if len < 1024 * 1024 {
                summary.small_files_count = summary.small_files_count.saturating_add(1);
            }
        }
    }

    Ok(summary)
}

fn available_space_bytes(path: &Path) -> Result<u64, PlannerError> {
    #[cfg(unix)]
    {
        let stats = nix::sys::statvfs::statvfs(path).map_err(|error| {
            PlannerError::PlanningFailed(format!(
                "Cannot inspect available disk space for {}: {error}",
                path.display()
            ))
        })?;
        let available =
            u128::from(stats.blocks_available()).saturating_mul(u128::from(stats.fragment_size()));
        Ok(available.min(u128::from(u64::MAX)) as u64)
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(PlannerError::PlanningFailed(
            "disk space probing is not supported on this target".to_string(),
        ))
    }
}

fn deterministic_local_cache_ratio(object_graph: &ObjectGraphSummary) -> f64 {
    if object_graph.total_bytes == 0 {
        return 0.0;
    }

    let small_file_ratio = if object_graph.file_count == 0 {
        0.0
    } else {
        object_graph.small_files_count as f64 / object_graph.file_count as f64
    };
    let directory_bonus = if object_graph.directory_count > 0 {
        0.05
    } else {
        0.0
    };
    (0.10 + small_file_ratio * 0.25 + directory_bonus).min(0.60)
}

fn deterministic_remote_cache_ratio(object_graph: &ObjectGraphSummary) -> f64 {
    if object_graph.total_bytes == 0 {
        return 0.0;
    }

    let graph_scale = (object_graph.object_count as f64).log2().max(0.0) / 20.0;
    (0.05 + graph_scale).min(0.40)
}

fn cache_locations_for_ratios(local_hit_ratio: f64, remote_hit_ratio: f64) -> Vec<String> {
    let mut locations = Vec::new();
    if local_hit_ratio > 0.0 {
        locations.push("local".to_string());
    }
    if remote_hit_ratio > 0.0 {
        locations.push("relay".to_string());
    }
    locations
}

fn completed_bytes_for_path(path: &Path) -> Result<u64, PlannerError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        PlannerError::InvalidInput(format!(
            "Cannot read resume metadata for {}: {error}",
            path.display()
        ))
    })?;
    if metadata.is_dir() {
        Ok(analyze_directory_tree(path)?.total_bytes)
    } else {
        Ok(metadata.len())
    }
}

impl AtpTransferPlanner {
    /// Create a new transfer planner
    pub fn new(config: PlannerConfig) -> Self {
        Self { config }
    }

    /// Create planner with default configuration
    pub fn new_default() -> Self {
        Self::new(PlannerConfig::default())
    }

    /// Generate a transfer plan
    pub async fn plan_transfer(
        &self,
        cx: &Cx,
        transfer_type: TransferType,
        source_path: &PathBuf,
        destination_path: &PathBuf,
        options: PlannerOptions,
    ) -> Result<AtpTransferPlan, PlannerError> {
        let plan_id = self.generate_plan_id();
        let created_at = SystemTime::now();

        // Analyze source for object graph
        let object_graph = self.analyze_object_graph(cx, source_path).await?;

        // Generate chunking profile
        let chunking_profile = self.generate_chunking_profile(&object_graph);

        // Analyze disk requirements
        let disk_allocation = self
            .analyze_disk_allocation(destination_path, &object_graph)
            .await?;

        // Generate path candidates
        let path_candidates = self.generate_path_candidates(&options).await?;

        // Analyze cache opportunities
        let cache_analysis = self
            .analyze_cache_opportunities(&object_graph, &options)
            .await?;

        // Check resume state
        let resume_state = self.check_resume_state(destination_path, &options).await?;

        // Generate governance profile
        let governance_profile = self.generate_governance_profile(&options);

        // Calculate uncertainty
        let uncertainty = self.calculate_uncertainty(&path_candidates, &options);

        // Estimate bytes on wire
        let estimated_bytes_on_wire = self.estimate_bytes_on_wire(&object_graph, &chunking_profile);

        // Estimate duration
        let estimated_duration = self.estimate_transfer_duration(
            estimated_bytes_on_wire,
            &path_candidates,
            &cache_analysis,
        );

        let estimated_completion = created_at + estimated_duration;

        Ok(AtpTransferPlan {
            schema_version: ATP_TRANSFER_PLAN_SCHEMA.to_string(),
            plan_id,
            created_at,
            transfer_type,
            transfer_mode: options.transfer_mode,
            object_graph,
            chunking_profile,
            estimated_bytes_on_wire,
            path_candidates,
            disk_allocation,
            governance_profile,
            resume_state,
            cache_analysis,
            proof_outputs: options.proof_outputs.unwrap_or_default(),
            uncertainty,
            estimated_duration,
            estimated_completion,
        })
    }

    /// Validate a transfer plan before execution
    pub async fn validate_plan(
        &self,
        _cx: &Cx,
        plan: &AtpTransferPlan,
    ) -> Result<Vec<String>, PlannerError> {
        let mut warnings = Vec::new();

        // Check disk space
        if plan.disk_allocation.available_space < plan.disk_allocation.required_space {
            return Err(PlannerError::InsufficientDiskSpace {
                needed: plan.disk_allocation.required_space,
                available: plan.disk_allocation.available_space,
            });
        }

        // Check path availability
        if plan.path_candidates.is_empty() {
            return Err(PlannerError::PathNotAvailable(
                "No paths available".to_string(),
            ));
        }

        // Warn about low confidence
        if plan.uncertainty.bandwidth_confidence < 0.5 {
            warnings.push("Low bandwidth estimation confidence".to_string());
        }

        if plan.uncertainty.path_confidence < 0.7 {
            warnings.push("Low path availability confidence".to_string());
        }

        Ok(warnings)
    }

    fn generate_plan_id(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        format!("plan_{:016x}", hasher.finish())
    }

    async fn analyze_object_graph(
        &self,
        _cx: &Cx,
        source_path: &PathBuf,
    ) -> Result<ObjectGraphSummary, PlannerError> {
        if !source_path.exists() {
            return Err(PlannerError::InvalidInput(format!(
                "Source path does not exist: {}",
                source_path.display()
            )));
        }

        let metadata = crate::fs::metadata(source_path).await.map_err(|e| {
            PlannerError::InvalidInput(format!("Cannot read source metadata: {}", e))
        })?;

        if metadata.is_file() {
            Ok(ObjectGraphSummary {
                object_count: 1,
                total_bytes: metadata.len(),
                file_count: 1,
                directory_count: 0,
                largest_file_bytes: metadata.len(),
                small_files_count: u64::from(metadata.len() < 1024 * 1024),
            })
        } else {
            analyze_directory_tree(source_path)
        }
    }

    fn generate_chunking_profile(&self, object_graph: &ObjectGraphSummary) -> ChunkingProfile {
        let chunk_size = if object_graph.total_bytes < 512 * 1024 {
            // Very small transfers (< 512KB) use smaller chunks
            32 * 1024
        } else {
            self.config.default_chunk_size
        };

        let estimated_chunks =
            (object_graph.total_bytes + chunk_size as u64 - 1) / chunk_size as u64;

        ChunkingProfile {
            chunk_size,
            estimated_chunks,
            repair_overhead_ratio: self.config.default_repair_overhead,
            compression_ratio: 0.8, // Assume 20% compression
        }
    }

    async fn analyze_disk_allocation(
        &self,
        destination_path: &Path,
        object_graph: &ObjectGraphSummary,
    ) -> Result<DiskAllocationPlan, PlannerError> {
        let parent_dir = destination_path
            .parent()
            .ok_or_else(|| PlannerError::InvalidInput("Invalid destination path".to_string()))?;

        let available_space = available_space_bytes(parent_dir)?;

        let required_space = object_graph.total_bytes;
        let temp_space_needed = required_space / 4; // 25% temp space

        Ok(DiskAllocationPlan {
            destination_path: destination_path.to_path_buf(),
            required_space,
            available_space,
            preallocation_strategy: "sparse".to_string(),
            temp_space_needed,
        })
    }

    async fn generate_path_candidates(
        &self,
        options: &PlannerOptions,
    ) -> Result<Vec<PathCandidate>, PlannerError> {
        let mut candidates = Vec::new();

        match options.transfer_mode {
            TransferMode::Direct => {
                candidates.push(PathCandidate {
                    path_type: "direct".to_string(),
                    estimated_rtt: Duration::from_millis(10),
                    estimated_bandwidth: self.config.default_bandwidth_bps,
                    reliability_score: 0.9,
                    preferred: true,
                });
            }
            TransferMode::RelayOnly => {
                candidates.push(PathCandidate {
                    path_type: "relay".to_string(),
                    estimated_rtt: Duration::from_millis(50),
                    estimated_bandwidth: self.config.default_bandwidth_bps / 2,
                    reliability_score: 0.95,
                    preferred: true,
                });
            }
            TransferMode::Mailbox => {
                candidates.push(PathCandidate {
                    path_type: "mailbox".to_string(),
                    estimated_rtt: Duration::from_millis(100),
                    estimated_bandwidth: self.config.default_bandwidth_bps / 4,
                    reliability_score: 0.99,
                    preferred: true,
                });
            }
            TransferMode::Swarm => {
                // Multiple peers in swarm
                for i in 0..3 {
                    candidates.push(PathCandidate {
                        path_type: format!("swarm_peer_{}", i),
                        estimated_rtt: Duration::from_millis(20 + i * 10),
                        estimated_bandwidth: self.config.default_bandwidth_bps / 3,
                        reliability_score: 0.8,
                        preferred: i == 0,
                    });
                }
            }
            TransferMode::SparseImage => {
                candidates.push(PathCandidate {
                    path_type: "direct_sparse".to_string(),
                    estimated_rtt: Duration::from_millis(15),
                    estimated_bandwidth: self.config.default_bandwidth_bps,
                    reliability_score: 0.85,
                    preferred: true,
                });
            }
        }

        Ok(candidates)
    }

    async fn analyze_cache_opportunities(
        &self,
        object_graph: &ObjectGraphSummary,
        options: &PlannerOptions,
    ) -> Result<CacheAnalysis, PlannerError> {
        let local_hit_ratio = if options.cache_enabled {
            deterministic_local_cache_ratio(object_graph)
        } else {
            0.0
        };
        let remote_hit_ratio = if options.cache_enabled {
            deterministic_remote_cache_ratio(object_graph)
        } else {
            0.0
        };

        let bytes_from_cache = (object_graph.total_bytes as f64 * local_hit_ratio) as u64;

        let cache_locations = if options.cache_enabled {
            cache_locations_for_ratios(local_hit_ratio, remote_hit_ratio)
        } else {
            vec![]
        };

        Ok(CacheAnalysis {
            local_hit_ratio,
            remote_hit_ratio,
            bytes_from_cache,
            cache_locations,
        })
    }

    async fn check_resume_state(
        &self,
        destination_path: &PathBuf,
        options: &PlannerOptions,
    ) -> Result<ResumeState, PlannerError> {
        // Check for existing partial transfer
        let resume_available = options.allow_resume && destination_path.exists();

        let (bytes_completed, chunks_completed) = if resume_available {
            let completed = completed_bytes_for_path(destination_path)?;
            let chunks = completed.div_ceil(u64::from(self.config.default_chunk_size.max(1)));
            (completed, chunks)
        } else {
            (0, 0)
        };

        Ok(ResumeState {
            resume_available,
            resume_token: if resume_available {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                SystemTime::now().hash(&mut hasher);
                destination_path.hash(&mut hasher);
                Some(format!("resume_{:x}", hasher.finish() as u32))
            } else {
                None
            },
            bytes_completed,
            chunks_completed,
        })
    }

    fn generate_governance_profile(&self, options: &PlannerOptions) -> ResourceGovernanceProfile {
        ResourceGovernanceProfile {
            max_connections: options.max_connections.unwrap_or(4),
            bandwidth_limit: options.bandwidth_limit,
            memory_limit: options.memory_limit,
            cpu_limit: options.cpu_limit,
        }
    }

    fn calculate_uncertainty(
        &self,
        path_candidates: &[PathCandidate],
        options: &PlannerOptions,
    ) -> PlanUncertainty {
        let bandwidth_confidence = path_candidates
            .iter()
            .map(|p| p.reliability_score)
            .fold(0.0, f64::max);

        let path_confidence = if path_candidates.len() > 1 { 0.9 } else { 0.7 };

        let peer_confidence = match options.transfer_mode {
            TransferMode::Direct => 0.8,
            TransferMode::RelayOnly => 0.95,
            TransferMode::Mailbox => 0.99,
            TransferMode::Swarm => 0.7,
            TransferMode::SparseImage => 0.8,
        };

        let resource_confidence = if options.bandwidth_limit.is_some() {
            0.9
        } else {
            0.7
        };

        let uncertainty_factors = vec![
            "Network conditions may change".to_string(),
            "Peer availability not guaranteed".to_string(),
            "Bandwidth estimation based on limited samples".to_string(),
        ];

        PlanUncertainty {
            bandwidth_confidence,
            path_confidence,
            peer_confidence,
            resource_confidence,
            uncertainty_factors,
        }
    }

    fn estimate_bytes_on_wire(
        &self,
        object_graph: &ObjectGraphSummary,
        chunking_profile: &ChunkingProfile,
    ) -> u64 {
        // Calculate using explicit intermediate values to ensure deterministic behavior
        let compressed_bytes =
            (object_graph.total_bytes as f64 * chunking_profile.compression_ratio).floor() as u64;
        let repair_bytes =
            (compressed_bytes as f64 * chunking_profile.repair_overhead_ratio).floor() as u64;
        let protocol_overhead = compressed_bytes / 100; // 1% protocol overhead

        compressed_bytes + repair_bytes + protocol_overhead
    }

    fn estimate_transfer_duration(
        &self,
        bytes_on_wire: u64,
        path_candidates: &[PathCandidate],
        cache_analysis: &CacheAnalysis,
    ) -> Duration {
        let best_bandwidth = path_candidates
            .iter()
            .map(|p| p.estimated_bandwidth)
            .max()
            .unwrap_or(self.config.default_bandwidth_bps);

        let effective_bytes = bytes_on_wire.saturating_sub(cache_analysis.bytes_from_cache);
        let transfer_seconds = effective_bytes as f64 / best_bandwidth as f64;

        // Add setup overhead
        let setup_overhead = Duration::from_secs(5);
        Duration::from_secs(transfer_seconds as u64) + setup_overhead
    }

    /// Create plan execution tracker
    pub fn create_execution_tracker(&self, plan_id: String) -> PlanExecutionTracker {
        PlanExecutionTracker::new(plan_id)
    }
}

/// Options for transfer planning
#[derive(Debug, Clone)]
pub struct PlannerOptions {
    /// Transfer mode
    pub transfer_mode: TransferMode,
    /// Whether cache is enabled
    pub cache_enabled: bool,
    /// Whether resume is allowed
    pub allow_resume: bool,
    /// Maximum connections
    pub max_connections: Option<u32>,
    /// Bandwidth limit in bytes/sec
    pub bandwidth_limit: Option<u64>,
    /// Memory limit in bytes
    pub memory_limit: Option<u64>,
    /// CPU limit as percentage
    pub cpu_limit: Option<f32>,
    /// Proof output configuration
    pub proof_outputs: Option<HashMap<String, String>>,
}

impl Default for PlannerOptions {
    fn default() -> Self {
        Self {
            transfer_mode: TransferMode::Direct,
            cache_enabled: true,
            allow_resume: true,
            max_connections: None,
            bandwidth_limit: None,
            memory_limit: None,
            cpu_limit: None,
            proof_outputs: None,
        }
    }
}

/// Tracks execution of a transfer plan
#[derive(Debug)]
pub struct PlanExecutionTracker {
    plan_id: String,
    started_at: SystemTime,
    deviations: Vec<PlanDeviation>,
}

impl PlanExecutionTracker {
    pub fn new(plan_id: String) -> Self {
        Self {
            plan_id,
            started_at: SystemTime::now(),
            deviations: Vec::new(),
        }
    }

    /// Record a deviation from the plan
    pub fn record_deviation(
        &mut self,
        deviation_type: String,
        expected_value: String,
        actual_value: String,
        reason: String,
        impact_severity: String,
    ) {
        let deviation = PlanDeviation {
            timestamp: SystemTime::now(),
            deviation_type,
            expected_value,
            actual_value,
            reason,
            impact_severity,
        };
        self.deviations.push(deviation);
    }

    /// Generate final execution report
    pub fn generate_report(
        self,
        success: bool,
        error_message: Option<String>,
        final_stats: HashMap<String, serde_json::Value>,
    ) -> PlanExecutionReport {
        PlanExecutionReport {
            schema_version: ATP_PLAN_EXECUTION_REPORT_SCHEMA.to_string(),
            plan_id: self.plan_id,
            started_at: self.started_at,
            completed_at: Some(SystemTime::now()),
            deviations: self.deviations,
            final_stats,
            success,
            error_message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn test_planner_creation() {
        let planner = AtpTransferPlanner::new_default();
        assert_eq!(planner.config.default_chunk_size, 64 * 1024);
    }

    #[test]
    fn test_plan_id_generation() {
        let planner = AtpTransferPlanner::new_default();
        let id1 = planner.generate_plan_id();
        let id2 = planner.generate_plan_id();

        assert_ne!(id1, id2);
        assert!(id1.starts_with("plan_"));
        assert!(id2.starts_with("plan_"));
    }

    #[test]
    fn test_object_graph_analysis_file() {
        block_on(async {
            let cx = Cx::for_testing();
            let planner = AtpTransferPlanner::new_default();

            let temp_dir = TempDir::new().unwrap();
            let test_file = temp_dir.path().join("test.txt");

            // Create test file
            std::fs::write(&test_file, b"test content").unwrap();

            let result = planner.analyze_object_graph(&cx, &test_file).await.unwrap();

            assert_eq!(result.object_count, 1);
            assert_eq!(result.file_count, 1);
            assert_eq!(result.directory_count, 0);
            assert_eq!(result.total_bytes, 12); // "test content" length
        });
    }

    #[test]
    fn test_planning_options_default() {
        let options = PlannerOptions::default();
        assert_eq!(options.transfer_mode, TransferMode::Direct);
        assert!(options.cache_enabled);
        assert!(options.allow_resume);
    }

    #[test]
    fn test_chunking_profile_generation() {
        let planner = AtpTransferPlanner::new_default();

        let object_graph = ObjectGraphSummary {
            object_count: 1,
            total_bytes: 1024 * 1024, // 1MB
            file_count: 1,
            directory_count: 0,
            largest_file_bytes: 1024 * 1024,
            small_files_count: 0,
        };

        let profile = planner.generate_chunking_profile(&object_graph);

        assert_eq!(profile.chunk_size, 64 * 1024);
        assert_eq!(profile.estimated_chunks, 16); // exact 1MiB / 64KiB boundary
        assert_eq!(profile.repair_overhead_ratio, 0.1);

        let non_aligned_graph = ObjectGraphSummary {
            total_bytes: (1024 * 1024) + 1,
            ..object_graph
        };
        let non_aligned_profile = planner.generate_chunking_profile(&non_aligned_graph);
        assert_eq!(non_aligned_profile.estimated_chunks, 17);
    }

    #[test]
    fn test_path_candidates_generation() {
        block_on(async {
            let planner = AtpTransferPlanner::new_default();

            let options = PlannerOptions {
                transfer_mode: TransferMode::Direct,
                ..Default::default()
            };

            let candidates = planner.generate_path_candidates(&options).await.unwrap();

            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].path_type, "direct");
            assert!(candidates[0].preferred);
        });
    }

    #[test]
    fn test_swarm_path_candidates() {
        block_on(async {
            let planner = AtpTransferPlanner::new_default();

            let options = PlannerOptions {
                transfer_mode: TransferMode::Swarm,
                ..Default::default()
            };

            let candidates = planner.generate_path_candidates(&options).await.unwrap();

            assert_eq!(candidates.len(), 3);
            assert!(candidates[0].preferred);
            assert!(!candidates[1].preferred);
            assert!(!candidates[2].preferred);
        });
    }

    #[test]
    fn test_cache_analysis() {
        block_on(async {
            let planner = AtpTransferPlanner::new_default();

            let object_graph = ObjectGraphSummary {
                object_count: 1,
                total_bytes: 1024 * 1024,
                file_count: 1,
                directory_count: 0,
                largest_file_bytes: 1024 * 1024,
                small_files_count: 0,
            };

            let options = PlannerOptions {
                cache_enabled: true,
                ..Default::default()
            };

            let cache_analysis = planner
                .analyze_cache_opportunities(&object_graph, &options)
                .await
                .unwrap();

            assert!(cache_analysis.local_hit_ratio > 0.0);
            assert!(cache_analysis.bytes_from_cache > 0);
            assert!(!cache_analysis.cache_locations.is_empty());
        });
    }

    #[test]
    fn test_bytes_on_wire_calculation() {
        let planner = AtpTransferPlanner::new_default();

        let object_graph = ObjectGraphSummary {
            object_count: 1,
            total_bytes: 1024 * 1024, // 1MB
            file_count: 1,
            directory_count: 0,
            largest_file_bytes: 1024 * 1024,
            small_files_count: 0,
        };

        let chunking_profile = ChunkingProfile {
            chunk_size: 64 * 1024,
            estimated_chunks: 16,
            repair_overhead_ratio: 0.1,
            compression_ratio: 0.8,
        };

        let bytes_on_wire = planner.estimate_bytes_on_wire(&object_graph, &chunking_profile);

        // Compressed: 1048576 * 0.8 = 838860
        // Repair: 838860 * 0.1 = 83886
        // Protocol: 838860 / 100 = 8388
        // Total: 838860 + 83886 + 8388 = 931134
        assert_eq!(bytes_on_wire, 931134);
    }

    #[test]
    fn test_execution_tracker() {
        let mut tracker = PlanExecutionTracker::new("test_plan".to_string());

        tracker.record_deviation(
            "bandwidth".to_string(),
            "10Mbps".to_string(),
            "5Mbps".to_string(),
            "network congestion".to_string(),
            "medium".to_string(),
        );

        assert_eq!(tracker.deviations.len(), 1);
        assert_eq!(tracker.deviations[0].deviation_type, "bandwidth");

        let report = tracker.generate_report(true, None, HashMap::new());

        assert_eq!(report.plan_id, "test_plan");
        assert!(report.success);
        assert!(report.completed_at.is_some());
        assert_eq!(report.deviations.len(), 1);
    }
}
