//! Repair Coordinator for economically adaptive RaptorQ repair across ATP modes.
//!
//! The RepairCoordinator makes policy-driven repair decisions based on measurable ROI,
//! considering expected time saved, CPU costs, bandwidth overhead, path instability,
//! and repair mode economics across tail, lossy, resume, relay, and swarm scenarios.

use crate::atp::object::ObjectId;
use crate::atp::repair_scheduler::MultiSourceRepairScheduler;
use crate::error::Result;
use crate::types::TraceId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
#[cfg(feature = "tracing-integration")]
use tracing::{debug, info};

// Provide no-op tracing macros when tracing is disabled
#[cfg(not(feature = "tracing-integration"))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}
#[cfg(not(feature = "tracing-integration"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}

/// Configuration for the repair coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairCoordinatorConfig {
    /// Minimum ROI threshold to enable repair
    pub min_roi_threshold: f64,
    /// Default repair mode when policy is ambiguous
    pub default_repair_mode: RepairMode,
    /// Maximum CPU budget for encoding per object
    pub max_encode_cpu_budget: Duration,
    /// Maximum memory overhead for repair (as fraction of object size)
    pub max_memory_overhead_ratio: f64,
    /// Enable repair telemetry collection
    pub enable_telemetry: bool,
    /// Repair decision logging level
    pub decision_logging_level: RepairLoggingLevel,
    /// Maximum decisions per minute from any source
    pub max_decisions_per_minute: u32,
    /// Maximum telemetry entries per minute from any source
    pub max_telemetry_per_minute: u32,
    /// Maximum decision history size
    pub max_decision_history: usize,
    /// Maximum telemetry history size
    pub max_telemetry_history: usize,
}

impl Default for RepairCoordinatorConfig {
    fn default() -> Self {
        Self {
            min_roi_threshold: 1.2, // 20% improvement required
            default_repair_mode: RepairMode::Off,
            max_encode_cpu_budget: Duration::from_millis(500),
            max_memory_overhead_ratio: 0.1, // 10% memory overhead max
            enable_telemetry: true,
            decision_logging_level: RepairLoggingLevel::Normal,
            max_decisions_per_minute: 60, // Limit to 1 decision per second
            max_telemetry_per_minute: 120, // Limit to 2 telemetry entries per second
            max_decision_history: 100,    // Reduced from 1000 to prevent memory exhaustion
            max_telemetry_history: 500,   // Reduced from 10000 to prevent memory exhaustion
        }
    }
}

/// Level of repair decision logging
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum RepairLoggingLevel {
    /// No logging
    Off,
    /// Normal logging (major decisions)
    Normal,
    /// Verbose logging (all decisions)
    Verbose,
    /// Debug logging (ROI calculations)
    Debug,
}

/// Repair modes available for different network scenarios
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RepairMode {
    /// No repair - rely on exact retransmission
    Off,
    /// Tail repair - cover last missing chunks efficiently
    Tail,
    /// Lossy path repair - preemptive repair for packet loss
    Lossy,
    /// Resume repair - repair gaps from previous interrupted transfers
    ResumeRepair,
    /// Broadcast repair - efficient multicast/broadcast scenarios
    Broadcast,
    /// Swarm repair - multi-peer repair coordination
    Swarm,
    /// Relay-expensive repair - minimize relay bandwidth usage
    RelayExpensive,
    /// Mobile-unstable repair - handle unstable mobile connections
    MobileUnstable,
    /// Satellite/high-BDP repair - handle high bandwidth-delay product links
    HighBDP,
}

impl RepairMode {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            RepairMode::Off => "no repair - exact retransmission only",
            RepairMode::Tail => "tail repair for last missing chunks",
            RepairMode::Lossy => "preemptive repair for lossy paths",
            RepairMode::ResumeRepair => "repair gaps from interrupted transfers",
            RepairMode::Broadcast => "efficient multicast/broadcast repair",
            RepairMode::Swarm => "multi-peer swarm coordination",
            RepairMode::RelayExpensive => "minimize relay bandwidth usage",
            RepairMode::MobileUnstable => "handle unstable mobile connections",
            RepairMode::HighBDP => "handle high bandwidth-delay product",
        }
    }

    /// Check if this repair mode requires multi-source capability
    pub fn requires_multi_source(&self) -> bool {
        matches!(self, RepairMode::Swarm | RepairMode::Broadcast)
    }

    /// Get typical overhead multiplier for this mode
    pub fn typical_overhead_multiplier(&self) -> f64 {
        match self {
            RepairMode::Off => 0.0,
            RepairMode::Tail => 0.05,        // 5% overhead for tail repair
            RepairMode::Lossy => 0.15,       // 15% preemptive overhead
            RepairMode::ResumeRepair => 0.1, // 10% resume gaps
            RepairMode::Broadcast => 0.2,    // 20% for broadcast efficiency
            RepairMode::Swarm => 0.25,       // 25% for swarm coordination
            RepairMode::RelayExpensive => 0.3, // 30% to avoid relay retransmits
            RepairMode::MobileUnstable => 0.35, // 35% for unstable connections
            RepairMode::HighBDP => 0.4,      // 40% for high BDP links
        }
    }
}

/// Network path characteristics that influence repair decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathCharacteristics {
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
    /// Available bandwidth in bytes per second
    pub bandwidth_bps: u64,
    /// Packet loss rate (0.0 to 1.0)
    pub loss_rate: f64,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
    /// Bandwidth-delay product in bytes
    pub bdp_bytes: u64,
    /// Path stability score (0.0 to 1.0)
    pub stability_score: f64,
    /// Whether path goes through relay
    pub uses_relay: bool,
    /// Relay cost per byte (if applicable)
    pub relay_cost_per_byte: f64,
    /// Mobile connection characteristics
    pub is_mobile: bool,
    /// Satellite or high-latency link
    pub is_high_latency: bool,
}

impl Default for PathCharacteristics {
    fn default() -> Self {
        Self {
            rtt_ms: 50.0,
            bandwidth_bps: 10_000_000, // 10 Mbps
            loss_rate: 0.001,          // 0.1%
            jitter_ms: 5.0,
            bdp_bytes: 62_500, // 50ms * 10Mbps
            stability_score: 0.9,
            uses_relay: false,
            relay_cost_per_byte: 0.0,
            is_mobile: false,
            is_high_latency: false,
        }
    }
}

/// Transfer state information for repair decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferState {
    /// Total object size in bytes
    pub object_size_bytes: u64,
    /// Bytes already successfully transferred
    pub bytes_transferred: u64,
    /// Number of missing chunks
    pub missing_chunks: usize,
    /// Size of missing data in bytes
    pub missing_bytes: u64,
    /// Whether this is a resumed transfer
    pub is_resume: bool,
    /// Time spent on transfer so far
    pub elapsed_time: Duration,
    /// Number of retransmission attempts so far
    pub retransmit_attempts: u32,
    /// Available peers for multi-source repair
    pub available_peers: usize,
    /// Memory pressure (0.0 to 1.0)
    pub memory_pressure: f64,
    /// CPU pressure (0.0 to 1.0)
    pub cpu_pressure: f64,
}

/// ROI calculation inputs and results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairRoi {
    /// Expected time saved by using repair vs retransmit
    pub expected_time_saved: Duration,
    /// CPU cost for encoding repair symbols
    pub encode_cpu_cost: Duration,
    /// CPU cost for decoding repair symbols
    pub decode_cpu_cost: Duration,
    /// Additional bandwidth overhead for repair symbols
    pub bandwidth_overhead: u64,
    /// Memory overhead for repair state
    pub memory_overhead: u64,
    /// Expected coordination cost for multi-source
    pub coordination_cost: Duration,
    /// Total economic benefit score
    pub benefit_score: f64,
    /// Total economic cost score
    pub cost_score: f64,
    /// Return on investment ratio (benefit / cost)
    pub roi_ratio: f64,
    /// Confidence in ROI calculation (0.0 to 1.0)
    pub confidence: f64,
}

impl RepairRoi {
    /// Check if ROI justifies using repair
    pub fn justifies_repair(&self, threshold: f64) -> bool {
        self.roi_ratio >= threshold && self.confidence >= 0.6
    }

    /// Get human-readable ROI summary
    pub fn summary(&self) -> String {
        format!(
            "ROI {:.2} (benefit: {:.2}, cost: {:.2}, confidence: {:.1}%)",
            self.roi_ratio,
            self.benefit_score,
            self.cost_score,
            self.confidence * 100.0
        )
    }
}

/// Repair decision made by the coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairDecision {
    /// Chosen repair mode
    pub mode: RepairMode,
    /// ROI calculation that informed the decision
    pub roi: RepairRoi,
    /// Reasoning for the decision
    pub reasoning: String,
    /// Factors considered in the decision
    pub factors: RepairDecisionFactors,
    /// Decision timestamp
    pub decided_at: SystemTime,
    /// Decision trace ID
    pub trace_id: TraceId,
}

/// Factors that influenced a repair decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairDecisionFactors {
    /// Path quality assessment
    pub path_quality: f64,
    /// Loss rate significance
    pub loss_impact: f64,
    /// Bandwidth-delay product impact
    pub bdp_impact: f64,
    /// Relay cost consideration
    pub relay_cost_impact: f64,
    /// Resume benefit (for interrupted transfers)
    pub resume_benefit: f64,
    /// Multi-source availability
    pub multi_source_benefit: f64,
    /// Resource pressure constraints
    pub resource_pressure: f64,
}

/// Repair telemetry for measuring actual ROI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairTelemetry {
    /// Object being repaired
    pub object_id: ObjectId,
    /// Repair mode used
    pub mode: RepairMode,
    /// Predicted ROI at decision time
    pub predicted_roi: RepairRoi,
    /// Actual time taken for repair
    pub actual_repair_time: Duration,
    /// Actual CPU time used for encoding
    pub actual_encode_cpu: Duration,
    /// Actual CPU time used for decoding
    pub actual_decode_cpu: Duration,
    /// Actual bandwidth used for repair
    pub actual_bandwidth_used: u64,
    /// Number of repair symbols sent
    pub repair_symbols_sent: u32,
    /// Number of repair symbols successfully decoded
    pub repair_symbols_decoded: u32,
    /// Whether repair was successful
    pub success: bool,
    /// Actual benefit achieved
    pub actual_benefit_score: f64,
    /// Actual ROI ratio
    pub actual_roi_ratio: f64,
    /// Measurement timestamp
    pub measured_at: SystemTime,
}

/// Core repair coordinator for economically adaptive RaptorQ repair
pub struct RepairCoordinator {
    /// Configuration
    config: RepairCoordinatorConfig,
    /// Multi-source scheduler for swarm repair
    multi_source_scheduler: Option<MultiSourceRepairScheduler>,
    /// Decision history for learning
    decision_history: Vec<RepairDecision>,
    /// Telemetry for measuring actual ROI
    telemetry: Vec<RepairTelemetry>,
    /// Per-mode statistics for adaptive thresholds
    mode_statistics: HashMap<RepairMode, ModeStatistics>,
    /// Rate limiter for decision requests
    decision_rate_limiter: RateLimiter,
    /// Rate limiter for telemetry submissions
    telemetry_rate_limiter: RateLimiter,
}

/// Statistics for a particular repair mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeStatistics {
    /// Number of times this mode was used
    usage_count: u32,
    /// Average predicted ROI
    avg_predicted_roi: f64,
    /// Average actual ROI
    avg_actual_roi: f64,
    /// Success rate (0.0 to 1.0)
    success_rate: f64,
    /// Last updated timestamp
    last_updated: SystemTime,
}

/// Rate limiter for preventing economic attacks
#[derive(Debug)]
struct RateLimiter {
    /// Window start time
    window_start: SystemTime,
    /// Count of requests in current window
    request_count: u32,
    /// Requests per window limit
    limit: u32,
    /// Window duration (1 minute)
    window_duration: Duration,
}

impl RateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            window_start: SystemTime::now(),
            request_count: 0,
            limit,
            window_duration: Duration::from_secs(60), // 1 minute window
        }
    }

    fn check_rate_limit(&mut self) -> bool {
        let now = SystemTime::now();

        // Reset window if expired
        if now.duration_since(self.window_start).unwrap_or_default() >= self.window_duration {
            self.window_start = now;
            self.request_count = 0;
        }

        // Check if within limit
        if self.request_count >= self.limit {
            false
        } else {
            self.request_count += 1;
            true
        }
    }
}

impl Default for ModeStatistics {
    fn default() -> Self {
        Self {
            usage_count: 0,
            avg_predicted_roi: 1.0,
            avg_actual_roi: 1.0,
            success_rate: 1.0,
            last_updated: SystemTime::now(),
        }
    }
}

impl RepairCoordinator {
    /// Create a new repair coordinator
    pub fn new(config: RepairCoordinatorConfig) -> Self {
        Self {
            decision_rate_limiter: RateLimiter::new(config.max_decisions_per_minute),
            telemetry_rate_limiter: RateLimiter::new(config.max_telemetry_per_minute),
            config,
            multi_source_scheduler: None,
            decision_history: Vec::new(),
            telemetry: Vec::new(),
            mode_statistics: HashMap::new(),
        }
    }

    /// Create coordinator with multi-source capability
    pub fn with_multi_source(mut self, scheduler: MultiSourceRepairScheduler) -> Self {
        self.multi_source_scheduler = Some(scheduler);
        self
    }

    /// Make a repair decision based on current conditions
    pub fn decide_repair_mode(
        &mut self,
        _object_id: ObjectId,
        path: &PathCharacteristics,
        transfer: &TransferState,
        trace_id: TraceId,
    ) -> Result<RepairDecision> {
        // Rate limiting check to prevent economic attacks
        if !self.decision_rate_limiter.check_rate_limit() {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::RateLimited,
            ));
        }
        // Calculate ROI for each applicable repair mode
        let mode_candidates = self.get_applicable_modes(path, transfer);
        let mut best_decision: Option<RepairDecision> = None;
        let mut best_roi = 0.0;

        for mode in mode_candidates {
            let roi = self.calculate_roi(mode, path, transfer)?;

            if roi.justifies_repair(self.config.min_roi_threshold) && roi.roi_ratio > best_roi {
                let decision = RepairDecision {
                    mode,
                    roi: roi.clone(),
                    reasoning: self.generate_reasoning(mode, &roi, path, transfer),
                    factors: self.analyze_decision_factors(mode, path, transfer),
                    decided_at: SystemTime::now(),
                    trace_id,
                };

                best_roi = roi.roi_ratio;
                best_decision = Some(decision);
            }
        }

        // Fall back to no repair if no mode meets ROI threshold
        let decision = best_decision.unwrap_or_else(|| RepairDecision {
            mode: RepairMode::Off,
            roi: RepairRoi {
                expected_time_saved: Duration::ZERO,
                encode_cpu_cost: Duration::ZERO,
                decode_cpu_cost: Duration::ZERO,
                bandwidth_overhead: 0,
                memory_overhead: 0,
                coordination_cost: Duration::ZERO,
                benefit_score: 0.0,
                cost_score: 1.0,
                roi_ratio: 0.0,
                confidence: 1.0,
            },
            reasoning: format!(
                "No repair mode meets ROI threshold {:.2}",
                self.config.min_roi_threshold
            ),
            factors: RepairDecisionFactors {
                path_quality: self.assess_path_quality(path),
                loss_impact: path.loss_rate,
                bdp_impact: (path.bdp_bytes as f64) / (64.0 * 1024.0), // Normalize to 64KB chunks
                relay_cost_impact: if path.uses_relay {
                    path.relay_cost_per_byte
                } else {
                    0.0
                },
                resume_benefit: if transfer.is_resume { 1.0 } else { 0.0 },
                multi_source_benefit: if transfer.available_peers > 1 {
                    (transfer.available_peers as f64).log2() / 4.0
                } else {
                    0.0
                },
                resource_pressure: f64::midpoint(transfer.cpu_pressure, transfer.memory_pressure),
            },
            decided_at: SystemTime::now(),
            trace_id,
        });

        // Log decision based on configured level
        self.log_decision(&decision);

        // Store decision for future learning
        self.decision_history.push(decision.clone());

        // Keep history bounded to prevent memory exhaustion attacks
        if self.decision_history.len() > self.config.max_decision_history {
            let drain_count = self.config.max_decision_history / 10; // Remove 10% when over limit
            self.decision_history.drain(0..drain_count);
        }

        Ok(decision)
    }

    /// Record actual telemetry for a completed repair operation
    pub fn record_telemetry(&mut self, telemetry: RepairTelemetry) -> Result<()> {
        // Rate limiting check to prevent economic attacks
        if !self.telemetry_rate_limiter.check_rate_limit() {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::RateLimited,
            ));
        }

        // Validate telemetry data authenticity to prevent forged data injection.
        self.validate_telemetry(&telemetry)?;
        // Update mode statistics
        let stats = self.mode_statistics.entry(telemetry.mode).or_default();

        stats.usage_count += 1;
        stats.avg_predicted_roi = (stats.avg_predicted_roi * (stats.usage_count - 1) as f64
            + telemetry.predicted_roi.roi_ratio)
            / stats.usage_count as f64;
        stats.avg_actual_roi = (stats.avg_actual_roi * (stats.usage_count - 1) as f64
            + telemetry.actual_roi_ratio)
            / stats.usage_count as f64;
        stats.success_rate = (stats.success_rate * (stats.usage_count - 1) as f64
            + if telemetry.success { 1.0 } else { 0.0 })
            / stats.usage_count as f64;
        stats.last_updated = SystemTime::now();

        self.telemetry.push(telemetry);

        // Keep telemetry bounded to prevent memory exhaustion attacks
        if self.telemetry.len() > self.config.max_telemetry_history {
            let drain_count = self.config.max_telemetry_history / 10; // Remove 10% when over limit
            self.telemetry.drain(0..drain_count);
        }

        Ok(())
    }

    /// Get repair mode statistics for analysis
    pub fn get_mode_statistics(&self) -> &HashMap<RepairMode, ModeStatistics> {
        &self.mode_statistics
    }

    /// Get recent decision history
    pub fn get_decision_history(&self, limit: usize) -> &[RepairDecision] {
        let start = self.decision_history.len().saturating_sub(limit);
        &self.decision_history[start..]
    }

    // Private helper methods

    fn get_applicable_modes(
        &self,
        path: &PathCharacteristics,
        transfer: &TransferState,
    ) -> Vec<RepairMode> {
        let mut modes = vec![RepairMode::Off]; // Always consider no repair

        // Tail repair for nearly complete transfers
        if transfer.bytes_transferred as f64 / transfer.object_size_bytes as f64 >= 0.8 {
            modes.push(RepairMode::Tail);
        }

        // Lossy repair for high loss rates
        if path.loss_rate > 0.01 {
            // > 1% loss
            modes.push(RepairMode::Lossy);
        }

        // Resume repair for interrupted transfers
        if transfer.is_resume {
            modes.push(RepairMode::ResumeRepair);
        }

        // Relay expensive for relay paths
        if path.uses_relay && path.relay_cost_per_byte > 0.0 {
            modes.push(RepairMode::RelayExpensive);
        }

        // Mobile unstable for mobile connections
        if path.is_mobile || path.stability_score < 0.7 {
            modes.push(RepairMode::MobileUnstable);
        }

        // High BDP for satellite/high-latency links
        if path.is_high_latency || path.bdp_bytes > 1_000_000 {
            // > 1MB BDP
            modes.push(RepairMode::HighBDP);
        }

        // Swarm repair if multiple peers available
        if transfer.available_peers > 1 && self.multi_source_scheduler.is_some() {
            modes.push(RepairMode::Swarm);
        }

        modes
    }

    fn calculate_roi(
        &self,
        mode: RepairMode,
        path: &PathCharacteristics,
        transfer: &TransferState,
    ) -> Result<RepairRoi> {
        if mode == RepairMode::Off {
            return Ok(RepairRoi {
                expected_time_saved: Duration::ZERO,
                encode_cpu_cost: Duration::ZERO,
                decode_cpu_cost: Duration::ZERO,
                bandwidth_overhead: 0,
                memory_overhead: 0,
                coordination_cost: Duration::ZERO,
                benefit_score: 0.0,
                cost_score: 1.0,
                roi_ratio: 0.0,
                confidence: 1.0,
            });
        }

        // Calculate expected time saved vs pure retransmission
        let retransmit_time = self.estimate_retransmit_time(path, transfer);
        let repair_time = self.estimate_repair_time(mode, path, transfer);
        let expected_time_saved = retransmit_time.saturating_sub(repair_time);

        // Calculate costs
        let overhead_multiplier = mode.typical_overhead_multiplier();
        let encode_cpu_cost = Duration::from_millis(transfer.missing_bytes / 1024 / 10); // ~0.1ms per KB
        let decode_cpu_cost = Duration::from_millis(transfer.missing_bytes / 1024 / 20); // ~0.05ms per KB
        let bandwidth_overhead = (transfer.missing_bytes as f64 * overhead_multiplier) as u64;
        let memory_overhead = (transfer.missing_bytes as f64 * 0.1) as u64; // 10% memory overhead

        let coordination_cost = if mode.requires_multi_source() {
            Duration::from_millis(transfer.available_peers as u64 * 10) // 10ms per peer coordination
        } else {
            Duration::ZERO
        };

        // Calculate benefit and cost scores
        let time_benefit = expected_time_saved.as_secs_f64();
        let bandwidth_benefit = if path.uses_relay {
            (transfer.missing_bytes as f64 * path.relay_cost_per_byte * (1.0 - overhead_multiplier))
                .max(0.0)
        } else {
            0.0
        };

        let benefit_score = time_benefit + bandwidth_benefit;

        let cpu_cost = (encode_cpu_cost + decode_cpu_cost).as_secs_f64();
        let bandwidth_cost = bandwidth_overhead as f64 / path.bandwidth_bps as f64;
        let coordination_cost_score = coordination_cost.as_secs_f64();

        let cost_score = cpu_cost + bandwidth_cost + coordination_cost_score + 1.0; // Base cost

        let roi_ratio = if cost_score > 0.0 {
            benefit_score / cost_score
        } else {
            0.0
        };

        // Calculate confidence based on available data and path stability
        let confidence = (path.stability_score * 0.5
            + (transfer.retransmit_attempts.min(10) as f64 / 10.0) * 0.3
            + 0.2)
            .min(1.0);

        Ok(RepairRoi {
            expected_time_saved,
            encode_cpu_cost,
            decode_cpu_cost,
            bandwidth_overhead,
            memory_overhead,
            coordination_cost,
            benefit_score,
            cost_score,
            roi_ratio,
            confidence,
        })
    }

    fn estimate_retransmit_time(
        &self,
        path: &PathCharacteristics,
        transfer: &TransferState,
    ) -> Duration {
        // Simple estimate: RTT * number of missing chunks * loss probability
        let base_time = Duration::from_millis(path.rtt_ms as u64 * transfer.missing_chunks as u64);
        let loss_multiplier = 1.0 + path.loss_rate * 2.0; // Account for retransmissions due to loss
        Duration::from_millis((base_time.as_millis() as f64 * loss_multiplier) as u64)
    }

    fn estimate_repair_time(
        &self,
        mode: RepairMode,
        path: &PathCharacteristics,
        _transfer: &TransferState,
    ) -> Duration {
        // Estimate based on repair mode overhead and coordination
        let base_time = Duration::from_millis(path.rtt_ms as u64 / 2); // Half RTT for parallel repair
        let mode_multiplier = mode.typical_overhead_multiplier() + 1.0;
        Duration::from_millis((base_time.as_millis() as f64 * mode_multiplier) as u64)
    }

    fn assess_path_quality(&self, path: &PathCharacteristics) -> f64 {
        let latency_score = (100.0 - path.rtt_ms.min(100.0)) / 100.0;
        let loss_score = 1.0 - path.loss_rate.min(1.0);
        let stability_score = path.stability_score;
        (latency_score + loss_score + stability_score) / 3.0
    }

    fn generate_reasoning(
        &self,
        mode: RepairMode,
        roi: &RepairRoi,
        path: &PathCharacteristics,
        transfer: &TransferState,
    ) -> String {
        let mut reasons = Vec::new();

        if roi.expected_time_saved > Duration::from_millis(100) {
            reasons.push(format!(
                "saves {:.1}s vs retransmit",
                roi.expected_time_saved.as_secs_f64()
            ));
        }

        if path.loss_rate > 0.01 {
            reasons.push(format!("high loss rate {:.1}%", path.loss_rate * 100.0));
        }

        if path.uses_relay {
            reasons.push("expensive relay path".to_string());
        }

        if transfer.is_resume {
            reasons.push("resume repair benefit".to_string());
        }

        if transfer.available_peers > 1 && mode.requires_multi_source() {
            reasons.push(format!("{} peers available", transfer.available_peers));
        }

        if reasons.is_empty() {
            format!("{} - {}", mode.description(), roi.summary())
        } else {
            format!(
                "{} - {} ({})",
                mode.description(),
                roi.summary(),
                reasons.join(", ")
            )
        }
    }

    fn analyze_decision_factors(
        &self,
        _mode: RepairMode,
        path: &PathCharacteristics,
        transfer: &TransferState,
    ) -> RepairDecisionFactors {
        RepairDecisionFactors {
            path_quality: self.assess_path_quality(path),
            loss_impact: path.loss_rate,
            bdp_impact: (path.bdp_bytes as f64) / (64.0 * 1024.0),
            relay_cost_impact: if path.uses_relay {
                path.relay_cost_per_byte
            } else {
                0.0
            },
            resume_benefit: if transfer.is_resume { 1.0 } else { 0.0 },
            multi_source_benefit: if transfer.available_peers > 1 {
                (transfer.available_peers as f64).log2() / 4.0
            } else {
                0.0
            },
            resource_pressure: f64::midpoint(transfer.cpu_pressure, transfer.memory_pressure),
        }
    }

    fn validate_telemetry(&self, telemetry: &RepairTelemetry) -> Result<()> {
        // Validate that telemetry data is plausible to prevent forged telemetry attacks.

        // Check for impossible values
        if telemetry.actual_roi_ratio < 0.0 || telemetry.actual_roi_ratio > 1000.0 {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::InvalidInput,
            ));
        }

        if telemetry.predicted_roi.roi_ratio < 0.0 || telemetry.predicted_roi.roi_ratio > 1000.0 {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::InvalidInput,
            ));
        }

        // Validate repair symbols counts are reasonable
        if telemetry.repair_symbols_sent == 0 && telemetry.success {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::InvalidInput,
            ));
        }

        if telemetry.repair_symbols_decoded > telemetry.repair_symbols_sent {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::InvalidInput,
            ));
        }

        // Check for time-based anomalies
        let now = SystemTime::now();
        if telemetry.measured_at > now {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::InvalidInput,
            ));
        }

        // Check for excessively old telemetry (could be replay attack)
        if let Ok(age) = now.duration_since(telemetry.measured_at) {
            if age > Duration::from_secs(3600) {
                // 1 hour max age
                return Err(crate::error::Error::new(
                    crate::error::ErrorKind::InvalidInput,
                ));
            }
        }

        Ok(())
    }

    fn log_decision(&self, decision: &RepairDecision) {
        match self.config.decision_logging_level {
            RepairLoggingLevel::Off => {}
            RepairLoggingLevel::Normal => {
                if decision.mode != RepairMode::Off {
                    info!(
                        "Repair decision: {:?} - {}",
                        decision.mode, decision.reasoning
                    );
                }
            }
            RepairLoggingLevel::Verbose => {
                info!(
                    "Repair decision: {:?} - {}",
                    decision.mode, decision.reasoning
                );
            }
            RepairLoggingLevel::Debug => {
                debug!(
                    "Repair decision: {:?} - {} (ROI: {:.2})",
                    decision.mode, decision.reasoning, decision.roi.roi_ratio
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::object::ContentId;

    fn test_object_id() -> ObjectId {
        ObjectId::content(ContentId::from_bytes(b"test-object"))
    }

    fn create_test_path() -> PathCharacteristics {
        PathCharacteristics {
            rtt_ms: 50.0,
            bandwidth_bps: 10_000_000,
            loss_rate: 0.02, // 2% loss
            jitter_ms: 5.0,
            bdp_bytes: 62_500,
            stability_score: 0.8,
            uses_relay: false,
            relay_cost_per_byte: 0.0,
            is_mobile: false,
            is_high_latency: false,
        }
    }

    fn create_test_transfer() -> TransferState {
        TransferState {
            object_size_bytes: 1_000_000, // 1MB
            bytes_transferred: 800_000,   // 80% complete
            missing_chunks: 10,
            missing_bytes: 200_000,
            is_resume: false,
            elapsed_time: Duration::from_secs(5),
            retransmit_attempts: 3,
            available_peers: 1,
            memory_pressure: 0.3,
            cpu_pressure: 0.4,
        }
    }

    #[test]
    fn test_repair_coordinator_creation() {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);

        assert_eq!(coordinator.decision_history.len(), 0);
        assert_eq!(coordinator.telemetry.len(), 0);
    }

    #[test]
    fn test_repair_mode_descriptions() {
        assert_eq!(
            RepairMode::Off.description(),
            "no repair - exact retransmission only"
        );
        assert_eq!(
            RepairMode::Tail.description(),
            "tail repair for last missing chunks"
        );
        assert!(RepairMode::Swarm.requires_multi_source());
        assert!(!RepairMode::Tail.requires_multi_source());
    }

    #[test]
    fn test_path_quality_assessment() {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();

        let quality = coordinator.assess_path_quality(&path);
        assert!(quality > 0.0 && quality <= 1.0);
    }

    #[test]
    fn test_applicable_modes() {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        let modes = coordinator.get_applicable_modes(&path, &transfer);

        // Should include Off, Tail (80% complete), and Lossy (2% loss)
        assert!(modes.contains(&RepairMode::Off));
        assert!(modes.contains(&RepairMode::Tail));
        assert!(modes.contains(&RepairMode::Lossy));
    }

    #[test]
    fn test_roi_calculation_off_mode() -> Result<()> {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        let roi = coordinator.calculate_roi(RepairMode::Off, &path, &transfer)?;

        assert_eq!(roi.roi_ratio, 0.0);
        assert_eq!(roi.expected_time_saved, Duration::ZERO);
        assert!(!roi.justifies_repair(1.0));

        Ok(())
    }

    #[test]
    fn test_roi_calculation_tail_mode() -> Result<()> {
        let config = RepairCoordinatorConfig::default();
        let coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();

        let roi = coordinator.calculate_roi(RepairMode::Tail, &path, &transfer)?;

        assert!(roi.roi_ratio > 0.0);
        assert!(roi.confidence > 0.0);

        Ok(())
    }

    #[test]
    fn test_repair_decision() -> Result<()> {
        let config = RepairCoordinatorConfig {
            min_roi_threshold: 0.5, // Lower threshold for test
            ..RepairCoordinatorConfig::default()
        };
        let mut coordinator = RepairCoordinator::new(config);
        let path = create_test_path();
        let transfer = create_test_transfer();
        let object_id = test_object_id();

        let decision = coordinator.decide_repair_mode(
            object_id,
            &path,
            &transfer,
            TraceId::from_parts(1, 1),
        )?;

        // Should make a decision
        assert!(!decision.reasoning.is_empty());
        assert!(decision.roi.confidence > 0.0);

        Ok(())
    }

    #[test]
    fn test_telemetry_recording() {
        let config = RepairCoordinatorConfig::default();
        let mut coordinator = RepairCoordinator::new(config);

        let telemetry = RepairTelemetry {
            object_id: test_object_id(),
            mode: RepairMode::Tail,
            predicted_roi: RepairRoi {
                roi_ratio: 1.5,
                ..RepairRoi {
                    expected_time_saved: Duration::from_millis(100),
                    encode_cpu_cost: Duration::from_millis(10),
                    decode_cpu_cost: Duration::from_millis(5),
                    bandwidth_overhead: 1000,
                    memory_overhead: 500,
                    coordination_cost: Duration::ZERO,
                    benefit_score: 2.0,
                    cost_score: 1.0,
                    roi_ratio: 1.5,
                    confidence: 0.8,
                }
            },
            actual_repair_time: Duration::from_millis(90),
            actual_encode_cpu: Duration::from_millis(12),
            actual_decode_cpu: Duration::from_millis(6),
            actual_bandwidth_used: 1200,
            repair_symbols_sent: 5,
            repair_symbols_decoded: 5,
            success: true,
            actual_benefit_score: 2.1,
            actual_roi_ratio: 1.6,
            measured_at: SystemTime::now(),
        };

        coordinator
            .record_telemetry(telemetry)
            .expect("Telemetry recording failed");

        assert_eq!(coordinator.telemetry.len(), 1);
        assert!(coordinator.mode_statistics.contains_key(&RepairMode::Tail));

        let stats = &coordinator.mode_statistics[&RepairMode::Tail];
        assert_eq!(stats.usage_count, 1);
        assert_eq!(stats.success_rate, 1.0);
    }
}
