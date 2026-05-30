//! Data-aware transfer brain for ATP optimal scheduling.
//!
//! The Transfer Brain optimizes for verified completion, early usability, repair ROI,
//! relay cost, disk pressure, CPU pressure, and path stability rather than raw throughput.
//! It uses Asupersync budgets, backpressure, and cancellation semantics directly.

use crate::atp::object::ObjectId;
use crate::error::{Error, ErrorKind, Result};
use crate::types::{Budget, TraceId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, SystemTime};
#[cfg(feature = "tracing-integration")]
use tracing::{debug, info, warn};

// Provide no-op tracing macros when tracing is disabled
#[cfg(not(feature = "tracing-integration"))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! warn {
    ($($arg:tt)*) => {};
}

/// Configuration for the transfer brain scheduler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferBrainConfig {
    /// Maximum concurrent transfers
    pub max_concurrent_transfers: usize,
    /// Default chunk size for scheduling decisions
    pub default_chunk_size_bytes: usize,
    /// Maximum in-flight chunks per transfer
    pub max_in_flight_chunks: usize,
    /// CPU pressure threshold for adaptive scheduling
    pub cpu_pressure_threshold: f64,
    /// Disk pressure threshold for adaptive scheduling
    pub disk_pressure_threshold: f64,
    /// Enable early usability optimizations
    pub enable_early_usability: bool,
    /// Enable repair cost optimization
    pub enable_repair_optimization: bool,
    /// Transfer decision logging level
    pub decision_logging_level: DecisionLoggingLevel,
}

impl Default for TransferBrainConfig {
    fn default() -> Self {
        Self {
            max_concurrent_transfers: 16,
            default_chunk_size_bytes: 64 * 1024, // 64KB
            max_in_flight_chunks: 32,
            cpu_pressure_threshold: 0.8,
            disk_pressure_threshold: 0.7,
            enable_early_usability: true,
            enable_repair_optimization: true,
            decision_logging_level: DecisionLoggingLevel::Normal,
        }
    }
}

/// Level of decision logging for transfer brain diagnostics
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DecisionLoggingLevel {
    /// Minimal logging (errors only)
    Minimal,
    /// Normal logging (major decisions)
    Normal,
    /// Verbose logging (all scheduling decisions)
    Verbose,
    /// Debug logging (internal state changes)
    Debug,
}

/// Priority classes for transfer operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransferPriority {
    /// Control frames and metadata (highest priority)
    Control = 0,
    /// Early usability chunks (manifest, small files, prefix data)
    EarlyUsability = 1,
    /// Useful chunks for current decode operations
    DecodeUseful = 2,
    /// Standard data chunks
    Standard = 3,
    /// Repair symbols and redundant data
    Repair = 4,
    /// Speculative prefetch and caching
    Speculative = 5,
}

impl TransferPriority {
    /// Check if this priority should preempt another
    pub fn preempts(&self, other: &TransferPriority) -> bool {
        (*self as u8) < (*other as u8)
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            TransferPriority::Control => "control frames and metadata",
            TransferPriority::EarlyUsability => "early usability chunks",
            TransferPriority::DecodeUseful => "decode-useful chunks",
            TransferPriority::Standard => "standard data chunks",
            TransferPriority::Repair => "repair symbols",
            TransferPriority::Speculative => "speculative prefetch",
        }
    }
}

/// Metrics tracked by the transfer brain for optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferMetrics {
    /// Time to first verified file completion
    pub time_to_first_verified_file: Option<Duration>,
    /// Time to first usable prefix availability
    pub time_to_first_usable_prefix: Option<Duration>,
    /// Time to whole object commit completion
    pub time_to_whole_object_commit: Option<Duration>,
    /// Bytes wasted on cancelled or duplicate chunks
    pub bytes_wasted: u64,
    /// CPU usage per GiB transferred
    pub cpu_per_gib: f64,
    /// Peak disk pressure during transfer
    pub peak_disk_pressure: f64,
    /// Total repair ROI (return on investment)
    pub repair_roi: f64,
    /// Total relay cost incurred
    pub relay_cost: f64,
    /// Path stability score (0.0 to 1.0)
    pub path_stability: f64,
    /// Resume value (bytes saved from previous attempts)
    pub resume_value: u64,
    /// User-visible responsiveness score (0.0 to 1.0)
    pub responsiveness: f64,
}

impl Default for TransferMetrics {
    fn default() -> Self {
        Self {
            time_to_first_verified_file: None,
            time_to_first_usable_prefix: None,
            time_to_whole_object_commit: None,
            bytes_wasted: 0,
            cpu_per_gib: 0.0,
            peak_disk_pressure: 0.0,
            repair_roi: 0.0,
            relay_cost: 0.0,
            path_stability: 1.0,
            resume_value: 0,
            responsiveness: 1.0,
        }
    }
}

/// Pressure feedback from system resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemPressure {
    /// CPU utilization (0.0 to 1.0)
    pub cpu_utilization: f64,
    /// Disk I/O pressure (0.0 to 1.0)
    pub disk_pressure: f64,
    /// Network pressure (0.0 to 1.0)
    pub network_pressure: f64,
    /// Memory pressure (0.0 to 1.0)
    pub memory_pressure: f64,
    /// Timestamp when pressure was measured
    pub measured_at: SystemTime,
}

impl Default for SystemPressure {
    fn default() -> Self {
        Self {
            cpu_utilization: 0.0,
            disk_pressure: 0.0,
            network_pressure: 0.0,
            memory_pressure: 0.0,
            measured_at: SystemTime::now(),
        }
    }
}

/// A scheduled chunk operation with priority and resource requirements
#[derive(Debug, Clone)]
pub struct ScheduledChunk {
    /// Unique identifier for this chunk
    pub chunk_id: ChunkId,
    /// Object this chunk belongs to
    pub object_id: ObjectId,
    /// Priority class for scheduling
    pub priority: TransferPriority,
    /// Chunk size in bytes
    pub size_bytes: usize,
    /// Expected CPU cost for this chunk
    pub cpu_cost: f64,
    /// Expected disk I/O cost
    pub disk_cost: f64,
    /// Expected network cost
    pub network_cost: f64,
    /// Deadline for completion (if any)
    pub deadline: Option<SystemTime>,
    /// Early usability benefits if completed
    pub early_usability_value: f64,
    /// Decode usefulness score
    pub decode_usefulness: f64,
    /// Resume value (benefit if chunk already exists)
    pub resume_value: u64,
    /// Trace ID for diagnostics
    pub trace_id: TraceId,
}

/// Unique identifier for a chunk in the scheduler
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChunkId {
    /// Object identifier
    pub object_id: ObjectId,
    /// Chunk offset within object
    pub offset: u64,
    /// Chunk size
    pub size: usize,
}

impl ChunkId {
    /// Create a new chunk ID
    pub fn new(object_id: ObjectId, offset: u64, size: usize) -> Self {
        Self {
            object_id,
            offset,
            size,
        }
    }

    /// Get string representation for logging
    pub fn as_string(&self) -> String {
        format!("{}@{}+{}", self.object_id, self.offset, self.size)
    }
}

/// Scheduling decision made by the transfer brain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingDecision {
    /// Chosen chunk to process next
    pub chunk_id: ChunkId,
    /// Priority assigned
    pub priority: TransferPriority,
    /// Reasoning for this decision
    pub reasoning: String,
    /// Factors considered in decision
    pub factors: DecisionFactors,
    /// Expected resource usage
    pub expected_resources: ResourceUsage,
    /// Decision timestamp
    pub decided_at: SystemTime,
    /// Decision trace ID
    pub trace_id: TraceId,
}

/// Factors considered in a scheduling decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFactors {
    /// Early usability impact
    pub early_usability_impact: f64,
    /// Decode usefulness score
    pub decode_usefulness: f64,
    /// Current system pressure
    pub system_pressure: SystemPressure,
    /// Path quality score
    pub path_quality: f64,
    /// Repair ROI consideration
    pub repair_roi: f64,
    /// Resume value consideration
    pub resume_value: f64,
    /// Fairness adjustment
    pub fairness_adjustment: f64,
}

/// Expected resource usage for a scheduled operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Expected CPU usage
    pub cpu: f64,
    /// Expected disk I/O
    pub disk_io: f64,
    /// Expected network usage
    pub network: f64,
    /// Expected memory usage
    pub memory: f64,
    /// Expected duration
    pub duration: Duration,
}

/// Core transfer brain scheduler
#[derive(Debug)]
pub struct TransferBrain {
    /// Configuration
    config: TransferBrainConfig,
    /// Pending chunks to schedule
    pending_chunks: BTreeMap<TransferPriority, Vec<ScheduledChunk>>,
    /// Currently in-flight chunks
    in_flight_chunks: HashMap<ChunkId, ScheduledChunk>,
    /// Completed chunks
    completed_chunks: HashSet<ChunkId>,
    /// Current system pressure
    current_pressure: SystemPressure,
    /// Transfer metrics
    metrics: TransferMetrics,
    /// Decision history for diagnostics
    decision_history: Vec<SchedulingDecision>,
    /// Start time for metrics calculation
    start_time: SystemTime,
}

impl TransferBrain {
    /// Create a new transfer brain with given configuration
    pub fn new(config: TransferBrainConfig) -> Self {
        Self {
            config,
            pending_chunks: BTreeMap::new(),
            in_flight_chunks: HashMap::new(),
            completed_chunks: HashSet::new(),
            current_pressure: SystemPressure::default(),
            metrics: TransferMetrics::default(),
            decision_history: Vec::new(),
            start_time: SystemTime::now(),
        }
    }

    /// Add a chunk to the scheduling queue
    pub fn schedule_chunk(&mut self, chunk: ScheduledChunk) -> Result<()> {
        if self.completed_chunks.contains(&chunk.chunk_id) {
            debug!(
                "Chunk {} already completed, skipping",
                chunk.chunk_id.as_string()
            );
            return Ok(());
        }

        if self.in_flight_chunks.contains_key(&chunk.chunk_id) {
            debug!(
                "Chunk {} already in flight, skipping",
                chunk.chunk_id.as_string()
            );
            return Ok(());
        }

        let priority = chunk.priority;
        info!(
            "Scheduling chunk {} with priority {:?}: {}",
            chunk.chunk_id.as_string(),
            priority,
            priority.description()
        );

        self.pending_chunks.entry(priority).or_default().push(chunk);

        Ok(())
    }

    /// Get the next chunk to process based on current system state
    pub fn next_chunk(
        &mut self,
        budget: &Budget,
        trace_id: TraceId,
    ) -> Result<Option<ScheduledChunk>> {
        // Check if we can start new work based on current pressure and limits
        if self.in_flight_chunks.len() >= self.config.max_in_flight_chunks {
            debug!(
                "Max in-flight chunks reached ({})",
                self.config.max_in_flight_chunks
            );
            return Ok(None);
        }

        if self.should_throttle_due_to_pressure() {
            debug!("Throttling due to system pressure");
            return Ok(None);
        }

        // Find highest priority chunk that fits within budget - collect candidates first to avoid borrow conflicts
        let mut candidates = Vec::new();

        for (priority, chunks) in &self.pending_chunks {
            if chunks.is_empty() {
                continue;
            }

            // Collect utility scores and budget checks without borrowing conflicts
            for (idx, chunk) in chunks.iter().enumerate() {
                let score = self.calculate_chunk_utility_score(chunk);
                let fits_budget = self.chunk_fits_budget(chunk, budget);
                if fits_budget {
                    candidates.push((*priority, idx, score, chunk.clone()));
                }
            }
        }

        // Sort candidates by score (highest first)
        candidates.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        // Select the best candidate and remove it from pending chunks
        if let Some((priority, chunk_index, _score, chosen_chunk)) = candidates.into_iter().next() {
            // Remove the chosen chunk from pending_chunks
            if let Some(chunks) = self.pending_chunks.get_mut(&priority) {
                if chunk_index < chunks.len() {
                    chunks.remove(chunk_index);
                    let decision = self.make_scheduling_decision(&chosen_chunk, trace_id);

                    info!(
                        "Selected chunk {} (priority {:?}): {}",
                        chosen_chunk.chunk_id.as_string(),
                        chosen_chunk.priority,
                        decision.reasoning
                    );

                    self.record_decision(decision);
                    self.in_flight_chunks
                        .insert(chosen_chunk.chunk_id.clone(), chosen_chunk.clone());

                    return Ok(Some(chosen_chunk));
                }
            }
        }

        debug!("No suitable chunk found for current budget and system state");
        Ok(None)
    }

    /// Mark a chunk as completed
    pub fn complete_chunk(
        &mut self,
        chunk_id: &ChunkId,
        success: bool,
        actual_resources: ResourceUsage,
    ) -> Result<()> {
        let chunk = self
            .in_flight_chunks
            .remove(chunk_id)
            .ok_or_else(|| Error::new(ErrorKind::Internal))?;

        if success {
            self.completed_chunks.insert(chunk_id.clone());
            info!("Completed chunk {} successfully", chunk_id.as_string());

            // Update metrics based on completion
            self.update_metrics_on_completion(&chunk, &actual_resources);
        } else {
            warn!("Chunk {} failed, rescheduling", chunk_id.as_string());
            // Store size before moving chunk
            let chunk_size = chunk.size_bytes;
            // Reschedule failed chunk (potentially with lower priority)
            self.schedule_chunk(chunk)?;
            self.metrics.bytes_wasted += chunk_size as u64;
        }

        Ok(())
    }

    /// Update system pressure feedback
    pub fn update_pressure(&mut self, pressure: SystemPressure) {
        // Update peak pressure metrics before moving pressure
        self.metrics.peak_disk_pressure =
            self.metrics.peak_disk_pressure.max(pressure.disk_pressure);

        // Log before moving the value
        debug!(
            "Updated system pressure - CPU: {:.2}, Disk: {:.2}, Network: {:.2}",
            pressure.cpu_utilization, pressure.disk_pressure, pressure.network_pressure
        );

        self.current_pressure = pressure;
    }

    /// Get current transfer metrics
    pub fn metrics(&self) -> &TransferMetrics {
        &self.metrics
    }

    /// Get decision history for diagnostics
    pub fn decision_history(&self) -> &[SchedulingDecision] {
        &self.decision_history
    }

    /// Get current scheduling state summary
    pub fn scheduling_state(&self) -> SchedulingState {
        SchedulingState {
            pending_chunks_by_priority: self
                .pending_chunks
                .iter()
                .map(|(priority, chunks)| (*priority, chunks.len()))
                .collect(),
            in_flight_count: self.in_flight_chunks.len(),
            completed_count: self.completed_chunks.len(),
            current_pressure: self.current_pressure.clone(),
            uptime: self.start_time.elapsed().unwrap_or(Duration::ZERO),
        }
    }

    // Private helper methods

    fn should_throttle_due_to_pressure(&self) -> bool {
        self.current_pressure.cpu_utilization > self.config.cpu_pressure_threshold
            || self.current_pressure.disk_pressure > self.config.disk_pressure_threshold
    }

    fn calculate_chunk_utility_score(&self, chunk: &ScheduledChunk) -> f64 {
        let mut score = 0.0;

        // Early usability bonus
        if self.config.enable_early_usability {
            score += chunk.early_usability_value * 2.0;
        }

        // Decode usefulness
        score += chunk.decode_usefulness * 1.5;

        // Resume value bonus
        if chunk.resume_value > 0 {
            score += 1.0;
        }

        // Deadline urgency
        if let Some(deadline) = chunk.deadline {
            let time_to_deadline = deadline
                .duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO);
            if time_to_deadline < Duration::from_secs(60) {
                score += 3.0; // Urgent deadline
            } else if time_to_deadline < Duration::from_secs(300) {
                score += 1.0; // Moderate urgency
            }
        }

        // System pressure penalty
        if self.current_pressure.cpu_utilization > 0.8 {
            score -= chunk.cpu_cost * 2.0;
        }
        if self.current_pressure.disk_pressure > 0.7 {
            score -= chunk.disk_cost * 2.0;
        }

        score
    }

    fn chunk_fits_budget(&self, chunk: &ScheduledChunk, budget: &Budget) -> bool {
        let required_polls = self.estimated_poll_cost(chunk);
        if budget.remaining_polls() < required_polls {
            return false;
        }

        if let Some(remaining_cost) = budget.remaining_cost() {
            self.estimated_budget_cost(chunk) <= remaining_cost
        } else {
            true
        }
    }

    fn make_scheduling_decision(
        &self,
        chunk: &ScheduledChunk,
        trace_id: TraceId,
    ) -> SchedulingDecision {
        let path_quality = self.calculate_path_quality(chunk);
        let repair_roi = self.calculate_repair_roi(chunk);
        let fairness_adjustment = self.calculate_fairness_adjustment(chunk);

        let factors = DecisionFactors {
            early_usability_impact: chunk.early_usability_value,
            decode_usefulness: chunk.decode_usefulness,
            system_pressure: self.current_pressure.clone(),
            path_quality,
            repair_roi,
            resume_value: chunk.resume_value as f64,
            fairness_adjustment,
        };

        let reasoning = format!(
            "Selected for {} (usability: {:.2}, decode: {:.2}, path: {:.2}, repair_roi: {:.2}, fairness: {:+.2}, resume: {}B)",
            chunk.priority.description(),
            chunk.early_usability_value,
            chunk.decode_usefulness,
            path_quality,
            repair_roi,
            fairness_adjustment,
            chunk.resume_value
        );

        let expected_resources = ResourceUsage {
            cpu: chunk.cpu_cost,
            disk_io: chunk.disk_cost,
            network: chunk.network_cost,
            memory: (chunk.size_bytes as f64) * 1.1, // 10% overhead
            duration: self.estimate_chunk_duration(chunk, path_quality),
        };

        SchedulingDecision {
            chunk_id: chunk.chunk_id.clone(),
            priority: chunk.priority,
            reasoning,
            factors,
            expected_resources,
            decided_at: SystemTime::now(),
            trace_id,
        }
    }

    fn estimated_poll_cost(&self, chunk: &ScheduledChunk) -> u32 {
        let chunk_granularity = self.config.default_chunk_size_bytes.max(1);
        let chunk_units = chunk.size_bytes.div_ceil(chunk_granularity).max(1);
        let resource_units = finite_nonnegative(chunk.cpu_cost)
            + finite_nonnegative(chunk.disk_cost)
            + finite_nonnegative(chunk.network_cost);
        let pressure_multiplier = 1.0
            + self.current_pressure.cpu_utilization.clamp(0.0, 1.0)
            + self.current_pressure.disk_pressure.clamp(0.0, 1.0)
            + self.current_pressure.network_pressure.clamp(0.0, 1.0);
        let weighted = (chunk_units as f64) * pressure_multiplier + resource_units.ceil();

        weighted.ceil().clamp(1.0, u32::MAX as f64) as u32
    }

    fn estimated_budget_cost(&self, chunk: &ScheduledChunk) -> u64 {
        let byte_cost = (chunk.size_bytes as u64).div_ceil(1024).max(1);
        let resource_cost = ((finite_nonnegative(chunk.cpu_cost)
            + finite_nonnegative(chunk.disk_cost)
            + finite_nonnegative(chunk.network_cost))
            * 1024.0)
            .ceil()
            .clamp(0.0, u64::MAX as f64) as u64;
        let resume_discount = (chunk.resume_value / 1024).min(byte_cost / 2);
        byte_cost
            .saturating_add(resource_cost)
            .saturating_sub(resume_discount)
    }

    fn calculate_path_quality(&self, chunk: &ScheduledChunk) -> f64 {
        let resource_total = finite_nonnegative(chunk.cpu_cost)
            + finite_nonnegative(chunk.disk_cost)
            + finite_nonnegative(chunk.network_cost);
        let weighted_pressure = if resource_total > f64::EPSILON {
            (finite_nonnegative(chunk.cpu_cost) * self.current_pressure.cpu_utilization
                + finite_nonnegative(chunk.disk_cost) * self.current_pressure.disk_pressure
                + finite_nonnegative(chunk.network_cost) * self.current_pressure.network_pressure)
                / resource_total
        } else {
            (self.current_pressure.cpu_utilization
                + self.current_pressure.disk_pressure
                + self.current_pressure.network_pressure)
                / 3.0
        };
        let memory_headroom = 1.0 - self.current_pressure.memory_pressure.clamp(0.0, 1.0);
        let pressure_fit = 1.0 - weighted_pressure.clamp(0.0, 1.0);

        finite_unit(
            self.metrics.path_stability.clamp(0.0, 1.0) * 0.45
                + self.metrics.responsiveness.clamp(0.0, 1.0) * 0.20
                + pressure_fit * 0.25
                + memory_headroom * 0.10,
        )
    }

    fn calculate_repair_roi(&self, chunk: &ScheduledChunk) -> f64 {
        if !self.config.enable_repair_optimization {
            return finite_nonnegative(self.metrics.repair_roi);
        }

        let utility_gain = chunk.decode_usefulness.max(chunk.early_usability_value)
            + (chunk.resume_value as f64 / chunk.size_bytes.max(1) as f64).min(1.0);
        let resource_cost = 1.0
            + finite_nonnegative(chunk.cpu_cost)
            + finite_nonnegative(chunk.disk_cost)
            + finite_nonnegative(chunk.network_cost)
            + (self.metrics.bytes_wasted as f64 / chunk.size_bytes.max(1) as f64).min(4.0);
        let priority_multiplier = match chunk.priority {
            TransferPriority::Control | TransferPriority::EarlyUsability => 1.25,
            TransferPriority::DecodeUseful => 1.1,
            TransferPriority::Standard => 1.0,
            TransferPriority::Repair => 1.5,
            TransferPriority::Speculative => 0.5,
        };
        let marginal_roi = (utility_gain * priority_multiplier) / resource_cost;

        finite_nonnegative((self.metrics.repair_roi * 0.7) + (marginal_roi * 0.3))
    }

    fn calculate_fairness_adjustment(&self, chunk: &ScheduledChunk) -> f64 {
        let capacity = self.config.max_in_flight_chunks.max(1) as f64;
        let total_occupancy = self.in_flight_chunks.len() as f64 / capacity;
        let same_object_occupancy = self
            .in_flight_chunks
            .values()
            .filter(|in_flight| in_flight.object_id == chunk.object_id)
            .count() as f64
            / capacity;
        let priority_bonus = match chunk.priority {
            TransferPriority::Control => 0.40,
            TransferPriority::EarlyUsability => 0.30,
            TransferPriority::DecodeUseful => 0.20,
            TransferPriority::Standard => 0.0,
            TransferPriority::Repair => -0.10,
            TransferPriority::Speculative => -0.30,
        };

        (priority_bonus - (same_object_occupancy * 0.75) - (total_occupancy * 0.25))
            .clamp(-1.0, 1.0)
    }

    fn estimate_chunk_duration(&self, chunk: &ScheduledChunk, path_quality: f64) -> Duration {
        let granularity = self.config.default_chunk_size_bytes.max(1) as f64;
        let chunk_units = (chunk.size_bytes as f64 / granularity).max(1.0);
        let resource_units = finite_nonnegative(chunk.cpu_cost)
            + finite_nonnegative(chunk.disk_cost)
            + finite_nonnegative(chunk.network_cost);
        let pressure_multiplier = 1.0
            + self.current_pressure.cpu_utilization.clamp(0.0, 1.0)
            + self.current_pressure.disk_pressure.clamp(0.0, 1.0)
            + self.current_pressure.network_pressure.clamp(0.0, 1.0);
        let path_multiplier = 1.0 + (1.0 - path_quality.clamp(0.0, 1.0));
        let millis =
            ((chunk_units * 8.0) + (resource_units * 64.0)) * pressure_multiplier * path_multiplier;

        Duration::from_millis(millis.ceil().clamp(1.0, u64::MAX as f64) as u64)
    }

    fn record_decision(&mut self, decision: SchedulingDecision) {
        // Log decision based on configured level
        match self.config.decision_logging_level {
            DecisionLoggingLevel::Debug => {
                debug!("Scheduling decision: {:?}", decision);
            }
            DecisionLoggingLevel::Verbose => {
                info!(
                    "Scheduled {}: {}",
                    decision.chunk_id.as_string(),
                    decision.reasoning
                );
            }
            DecisionLoggingLevel::Normal => {
                if decision.priority <= TransferPriority::EarlyUsability {
                    info!(
                        "Scheduled {}: {}",
                        decision.chunk_id.as_string(),
                        decision.reasoning
                    );
                }
            }
            DecisionLoggingLevel::Minimal => {
                // No logging for regular decisions
            }
        }

        self.decision_history.push(decision);

        // Keep decision history bounded
        if self.decision_history.len() > 10000 {
            self.decision_history.drain(0..1000);
        }
    }

    fn update_metrics_on_completion(
        &mut self,
        chunk: &ScheduledChunk,
        actual_resources: &ResourceUsage,
    ) {
        // Update CPU per GiB metric
        let gib = (chunk.size_bytes as f64) / (1024.0 * 1024.0 * 1024.0);
        if gib > 0.0 {
            let current_cpu_gib = self.metrics.cpu_per_gib * (self.completed_chunks.len() as f64);
            self.metrics.cpu_per_gib = (current_cpu_gib + actual_resources.cpu)
                / ((self.completed_chunks.len() + 1) as f64);
        }

        // Update early usability metrics
        if chunk.early_usability_value > 0.0 {
            let elapsed = self.start_time.elapsed().unwrap_or(Duration::ZERO);

            if self.metrics.time_to_first_usable_prefix.is_none() {
                self.metrics.time_to_first_usable_prefix = Some(elapsed);
            }

            if chunk.priority == TransferPriority::EarlyUsability
                && self.metrics.time_to_first_verified_file.is_none()
            {
                self.metrics.time_to_first_verified_file = Some(elapsed);
            }
        }

        // Update resume value
        self.metrics.resume_value += chunk.resume_value;
    }
}

fn finite_nonnegative(value: f64) -> f64 {
    if value.is_finite() {
        value.max(0.0)
    } else {
        0.0
    }
}

fn finite_unit(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// Current state of the scheduler for diagnostics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingState {
    /// Number of pending chunks by priority
    pub pending_chunks_by_priority: BTreeMap<TransferPriority, usize>,
    /// Number of in-flight chunks
    pub in_flight_count: usize,
    /// Number of completed chunks
    pub completed_count: usize,
    /// Current system pressure
    pub current_pressure: SystemPressure,
    /// Scheduler uptime
    pub uptime: Duration,
}

#[cfg(all(test, feature = "legacy-internal-test-harnesses"))]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;
    use crate::types::{Budget, TraceId};

    fn test_object_id(object_id: &str) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(object_id.as_bytes()))
    }

    const fn test_trace_id(value: u128) -> TraceId {
        TraceId::from_raw(value)
    }

    fn create_test_chunk(
        object_id: &str,
        offset: u64,
        priority: TransferPriority,
    ) -> ScheduledChunk {
        let object_id = test_object_id(object_id);
        ScheduledChunk {
            chunk_id: ChunkId::new(object_id.clone(), offset, 1024),
            object_id,
            priority,
            size_bytes: 1024,
            cpu_cost: 0.1,
            disk_cost: 0.1,
            network_cost: 0.1,
            deadline: None,
            early_usability_value: if priority == TransferPriority::EarlyUsability {
                1.0
            } else {
                0.0
            },
            decode_usefulness: 0.5,
            resume_value: 0,
            trace_id: test_trace_id(1),
        }
    }

    #[test]
    fn test_transfer_brain_creation() {
        let config = TransferBrainConfig::default();
        let brain = TransferBrain::new(config);

        let state = brain.scheduling_state();
        assert_eq!(state.in_flight_count, 0);
        assert_eq!(state.completed_count, 0);
        assert!(state.pending_chunks_by_priority.is_empty());
    }

    #[test]
    fn test_priority_ordering() {
        assert!(TransferPriority::Control.preempts(&TransferPriority::Standard));
        assert!(TransferPriority::EarlyUsability.preempts(&TransferPriority::Repair));
        assert!(!TransferPriority::Repair.preempts(&TransferPriority::Control));
    }

    #[test]
    fn test_chunk_scheduling() -> Result<()> {
        let config = TransferBrainConfig::default();
        let mut brain = TransferBrain::new(config);

        // Schedule chunks with different priorities
        let chunk1 = create_test_chunk("obj1", 0, TransferPriority::Control);
        let chunk2 = create_test_chunk("obj1", 1024, TransferPriority::Standard);
        let chunk3 = create_test_chunk("obj1", 2048, TransferPriority::EarlyUsability);

        brain.schedule_chunk(chunk1)?;
        brain.schedule_chunk(chunk2)?;
        brain.schedule_chunk(chunk3)?;

        let state = brain.scheduling_state();
        assert_eq!(state.pending_chunks_by_priority.len(), 3);
        assert_eq!(
            state.pending_chunks_by_priority[&TransferPriority::Control],
            1
        );
        assert_eq!(
            state.pending_chunks_by_priority[&TransferPriority::Standard],
            1
        );
        assert_eq!(
            state.pending_chunks_by_priority[&TransferPriority::EarlyUsability],
            1
        );

        Ok(())
    }

    #[test]
    fn test_priority_based_selection() -> Result<()> {
        let config = TransferBrainConfig::default();
        let mut brain = TransferBrain::new(config);
        let budget = Budget::unlimited();

        // Schedule chunks with different priorities
        brain.schedule_chunk(create_test_chunk("obj1", 1024, TransferPriority::Standard))?;
        brain.schedule_chunk(create_test_chunk("obj1", 0, TransferPriority::Control))?;
        brain.schedule_chunk(create_test_chunk("obj1", 2048, TransferPriority::Repair))?;

        // Should select control chunk first
        let next = brain.next_chunk(&budget, test_trace_id(2))?.unwrap();
        assert_eq!(next.priority, TransferPriority::Control);
        assert_eq!(next.chunk_id.offset, 0);

        // Should select standard chunk next
        let next = brain.next_chunk(&budget, test_trace_id(3))?.unwrap();
        assert_eq!(next.priority, TransferPriority::Standard);
        assert_eq!(next.chunk_id.offset, 1024);

        // Should select repair chunk last
        let next = brain.next_chunk(&budget, test_trace_id(4))?.unwrap();
        assert_eq!(next.priority, TransferPriority::Repair);
        assert_eq!(next.chunk_id.offset, 2048);

        Ok(())
    }

    #[test]
    fn test_chunk_completion() -> Result<()> {
        let config = TransferBrainConfig::default();
        let mut brain = TransferBrain::new(config);
        let budget = Budget::unlimited();

        let chunk = create_test_chunk("obj1", 0, TransferPriority::Standard);
        let chunk_id = chunk.chunk_id.clone();

        brain.schedule_chunk(chunk)?;
        let _selected = brain.next_chunk(&budget, test_trace_id(5))?.unwrap();

        assert_eq!(brain.scheduling_state().in_flight_count, 1);

        let resources = ResourceUsage {
            cpu: 0.1,
            disk_io: 0.05,
            network: 0.1,
            memory: 1024.0,
            duration: Duration::from_millis(100),
        };

        brain.complete_chunk(&chunk_id, true, resources)?;

        let state = brain.scheduling_state();
        assert_eq!(state.in_flight_count, 0);
        assert_eq!(state.completed_count, 1);

        Ok(())
    }

    #[test]
    fn test_early_usability_metrics() -> Result<()> {
        let config = TransferBrainConfig::default();
        let mut brain = TransferBrain::new(config);
        let budget = Budget::unlimited();

        let chunk = create_test_chunk("obj1", 0, TransferPriority::EarlyUsability);
        let chunk_id = chunk.chunk_id.clone();

        brain.schedule_chunk(chunk)?;
        let _selected = brain.next_chunk(&budget, test_trace_id(6))?.unwrap();

        std::thread::sleep(Duration::from_millis(10)); // Small delay for metrics

        let resources = ResourceUsage {
            cpu: 0.1,
            disk_io: 0.05,
            network: 0.1,
            memory: 1024.0,
            duration: Duration::from_millis(10),
        };

        brain.complete_chunk(&chunk_id, true, resources)?;

        let metrics = brain.metrics();
        assert!(metrics.time_to_first_usable_prefix.is_some());
        assert!(metrics.time_to_first_verified_file.is_some());

        Ok(())
    }

    #[test]
    fn test_pressure_throttling() {
        let config = TransferBrainConfig::default();
        let mut brain = TransferBrain::new(config);
        let budget = Budget::unlimited();

        // Set high pressure
        let high_pressure = SystemPressure {
            cpu_utilization: 0.95,
            disk_pressure: 0.85,
            network_pressure: 0.5,
            memory_pressure: 0.6,
            measured_at: SystemTime::now(),
        };

        brain.update_pressure(high_pressure);
        brain
            .schedule_chunk(create_test_chunk("obj1", 0, TransferPriority::Standard))
            .unwrap();

        // Should throttle due to high pressure
        let next = brain.next_chunk(&budget, test_trace_id(7)).unwrap();
        assert!(next.is_none());
    }

    #[test]
    fn test_decision_logging() -> Result<()> {
        let config = TransferBrainConfig {
            decision_logging_level: DecisionLoggingLevel::Verbose,
            ..TransferBrainConfig::default()
        };
        let mut brain = TransferBrain::new(config);
        let budget = Budget::unlimited();

        brain.schedule_chunk(create_test_chunk("obj1", 0, TransferPriority::Control))?;
        let _chunk = brain.next_chunk(&budget, test_trace_id(8))?.unwrap();

        let history = brain.decision_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].priority, TransferPriority::Control);
        assert!(!history[0].reasoning.is_empty());

        Ok(())
    }
}
