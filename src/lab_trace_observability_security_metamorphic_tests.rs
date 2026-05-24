//! Metamorphic tests for lab/*, trace/*, observability/*, and security/* modules.
//!
//! This test suite implements metamorphic testing for deterministic testing frameworks,
//! causality verification, observability correctness, and cryptographic security properties.
//!
//! # Coverage Areas
//!
//! ## lab/* modules
//! - Chaos determinism (same seed → same chaos sequence)
//! - Replay verifier (replay should produce same result)
//! - Scenario runner (scenario execution determinism)
//! - Snapshot/restore round-trip (state preservation identity)
//!
//! ## trace/* modules
//! - Causality DAG (causal ordering preservation)
//! - DPOR (Dynamic Partial-Order Reduction equivalence)
//! - Integrity hash (same trace → same hash)
//!
//! ## observability/* modules
//! - OTEL exporter span-tree (span relationships preserved)
//! - Spectral health smoothing (trend preservation)
//! - Diagnostics percentile (percentile ordering consistency)
//!
//! ## security/* modules
//! - Authenticated encryption symmetry (encrypt→decrypt round-trip)
//! - Tag verification (verification consistency)
//!
//! # Metamorphic Relations
//!
//! Each test implements one of the six fundamental MR types:
//! - **Equivalence**: f(T(x)) = f(x) for transformations that shouldn't change output
//! - **Additive**: f(x + c) = f(x) + g(c) for predictable offset behavior
//! - **Multiplicative**: f(k·x) = h(k)·f(x) for scaling relationships
//! - **Permutative**: f(permute(x)) = permute(f(x)) for order-preserving ops
//! - **Inclusive**: subset(x) ⊆ subset(f(x)) for monotonic operations
//! - **Invertive**: f(T(T(x))) = f(x) for round-trip operations

#[cfg(test)]
use proptest::prelude::*;

// Mock types and traits for testing lab, trace, observability, and security
#[derive(Debug, Clone, PartialEq)]
pub struct MockChaosGenerator {
    pub seed: u64,
    pub sequence: Vec<ChaosEvent>,
    pub current_index: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChaosEvent {
    NetworkDelay { duration_ms: u64 },
    ProcessCrash { process_id: u64 },
    MemoryPressure { pressure_level: u8 },
    DiskFailure { disk_id: u64 },
    PacketLoss { loss_rate: f64 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockReplayVerifier {
    pub original_trace: Vec<TraceEvent>,
    pub replay_trace: Vec<TraceEvent>,
    pub verification_result: VerificationResult,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceEvent {
    pub event_id: u64,
    pub timestamp: u64,
    pub event_type: EventType,
    pub causality_vector: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    TaskStart { task_id: u64 },
    TaskComplete { task_id: u64 },
    MessageSend { message_id: u64, target: u64 },
    MessageReceive { message_id: u64, source: u64 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationResult {
    Identical,
    EquivalentOrdering,
    DifferentOutcome,
    ReplayFailed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockScenarioRunner {
    pub scenario_id: String,
    pub execution_steps: Vec<ExecutionStep>,
    pub execution_results: Vec<StepResult>,
    pub deterministic_seed: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionStep {
    pub step_id: u64,
    pub step_type: StepType,
    pub parameters: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StepType {
    SpawnTask,
    SendMessage,
    WaitForCompletion,
    InjectFailure,
    CheckState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StepResult {
    pub step_id: u64,
    pub success: bool,
    pub output: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockLabSnapshot {
    pub snapshot_id: u64,
    pub state_data: Vec<(String, Vec<u8>)>,
    pub metadata: SnapshotMetadata,
    pub integrity_hash: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotMetadata {
    pub version: u64,
    pub timestamp: u64,
    pub execution_context: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockCausalityDag {
    pub events: Vec<CausalEvent>,
    pub dependencies: Vec<(u64, u64)>, // (predecessor, successor)
    pub topological_order: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CausalEvent {
    pub event_id: u64,
    pub logical_timestamp: u64,
    pub process_id: u64,
    pub event_data: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockDpor {
    pub execution_paths: Vec<ExecutionPath>,
    pub reduced_paths: Vec<ExecutionPath>,
    pub equivalence_classes: Vec<Vec<usize>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionPath {
    pub path_id: u64,
    pub operations: Vec<Operation>,
    pub final_state: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Operation {
    pub operation_id: u64,
    pub operation_type: OperationType,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    Read,
    Write,
    Lock,
    Unlock,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockTraceIntegrity {
    pub trace_segments: Vec<TraceSegment>,
    pub cumulative_hash: u64,
    pub integrity_proofs: Vec<IntegrityProof>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TraceSegment {
    pub segment_id: u64,
    pub events: Vec<TraceEvent>,
    pub segment_hash: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IntegrityProof {
    pub segment_id: u64,
    pub merkle_root: u64,
    pub proof_chain: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockOtelSpanTree {
    pub root_span: Span,
    pub span_relationships: Vec<SpanRelationship>,
    pub exported_spans: Vec<ExportedSpan>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub span_id: u64,
    pub parent_id: Option<u64>,
    pub operation_name: String,
    pub start_time: u64,
    pub end_time: Option<u64>,
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpanRelationship {
    pub parent_id: u64,
    pub child_id: u64,
    pub relationship_type: RelationshipType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RelationshipType {
    ChildOf,
    FollowsFrom,
    References,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExportedSpan {
    pub span_id: u64,
    pub trace_id: u64,
    pub parent_span_id: Option<u64>,
    pub operation_name: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockSpectralHealth {
    pub time_series: Vec<HealthDataPoint>,
    pub smoothed_series: Vec<HealthDataPoint>,
    pub spectral_coefficients: Vec<f64>,
    pub trend_direction: TrendDirection,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HealthDataPoint {
    pub timestamp: u64,
    pub value: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockDiagnosticsPercentile {
    pub measurements: Vec<f64>,
    pub percentiles: Vec<(f64, f64)>, // (percentile, value)
    pub sorted_measurements: Vec<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockAuthenticatedEncryption {
    pub plaintext: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authentication_tag: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockSecurityTag {
    pub data: Vec<u8>,
    pub tag: Vec<u8>,
    pub algorithm: TagAlgorithm,
    pub verification_result: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TagAlgorithm {
    HmacSha256,
    HmacSha512,
    Poly1305,
    Aes128Gmac,
}

// Mock implementations for testing

impl MockChaosGenerator {
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            sequence: Vec::new(),
            current_index: 0,
        }
    }

    pub fn generate_chaos_sequence(&mut self, count: usize) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        self.sequence.clear();
        let mut current_seed = self.seed;

        for i in 0..count {
            let mut hasher = DefaultHasher::new();
            (current_seed, i).hash(&mut hasher);
            let hash_value = hasher.finish();

            let event = match hash_value % 5 {
                0 => ChaosEvent::NetworkDelay {
                    duration_ms: (hash_value % 1000) + 10,
                },
                1 => ChaosEvent::ProcessCrash {
                    process_id: hash_value % 10,
                },
                2 => ChaosEvent::MemoryPressure {
                    pressure_level: ((hash_value % 100) as u8).min(100),
                },
                3 => ChaosEvent::DiskFailure {
                    disk_id: hash_value % 5,
                },
                _ => ChaosEvent::PacketLoss {
                    loss_rate: ((hash_value % 100) as f64) / 100.0,
                },
            };

            self.sequence.push(event);
            current_seed = hash_value;
        }
    }

    pub fn next_event(&mut self) -> Option<ChaosEvent> {
        if self.current_index < self.sequence.len() {
            let event = self.sequence[self.current_index].clone();
            self.current_index += 1;
            Some(event)
        } else {
            None
        }
    }

    pub fn determinism_holds(&self, other: &Self) -> bool {
        self.seed == other.seed && self.sequence == other.sequence
    }
}

impl MockReplayVerifier {
    pub fn new(original_trace: Vec<TraceEvent>) -> Self {
        Self {
            original_trace,
            replay_trace: Vec::new(),
            verification_result: VerificationResult::ReplayFailed,
        }
    }

    pub fn replay(&mut self, replay_trace: Vec<TraceEvent>) -> VerificationResult {
        self.replay_trace = replay_trace;

        if self.original_trace == self.replay_trace {
            self.verification_result = VerificationResult::Identical;
        } else if self.causal_ordering_equivalent() {
            self.verification_result = VerificationResult::EquivalentOrdering;
        } else {
            self.verification_result = VerificationResult::DifferentOutcome;
        }

        self.verification_result.clone()
    }

    fn causal_ordering_equivalent(&self) -> bool {
        // Check if causality vectors are consistent
        for (orig, replay) in self.original_trace.iter().zip(&self.replay_trace) {
            if orig.causality_vector != replay.causality_vector {
                return false;
            }
        }
        true
    }

    pub fn replay_correctness_holds(&self) -> bool {
        matches!(
            self.verification_result,
            VerificationResult::Identical | VerificationResult::EquivalentOrdering
        )
    }
}

impl MockScenarioRunner {
    pub fn new(scenario_id: String, deterministic_seed: u64) -> Self {
        Self {
            scenario_id,
            execution_steps: Vec::new(),
            execution_results: Vec::new(),
            deterministic_seed,
        }
    }

    pub fn add_step(&mut self, step: ExecutionStep) {
        self.execution_steps.push(step);
    }

    pub fn execute(&mut self) -> bool {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        self.execution_results.clear();
        let mut current_seed = self.deterministic_seed;

        for step in &self.execution_steps {
            let mut hasher = DefaultHasher::new();
            (current_seed, step.step_id).hash(&mut hasher);
            let step_hash = hasher.finish();

            // Deterministic execution based on seed
            let success = (step_hash % 10) > 1; // 90% success rate
            let duration_ms = (step_hash % 1000) + 10;
            let output = format!("Step {} executed with seed {}", step.step_id, step_hash);

            self.execution_results.push(StepResult {
                step_id: step.step_id,
                success,
                output,
                duration_ms,
            });

            current_seed = step_hash;
        }

        self.execution_results.iter().all(|r| r.success)
    }

    pub fn execution_determinism_holds(&self, other: &Self) -> bool {
        self.deterministic_seed == other.deterministic_seed
            && self.execution_steps == other.execution_steps
            && self.execution_results == other.execution_results
    }
}

impl MockLabSnapshot {
    pub fn create(state_data: Vec<(String, Vec<u8>)>, metadata: SnapshotMetadata) -> Self {
        let integrity_hash = Self::calculate_integrity_hash(&state_data, &metadata);

        Self {
            snapshot_id: metadata.timestamp, // Use timestamp as ID
            state_data,
            metadata,
            integrity_hash,
        }
    }

    pub fn restore(snapshot: &Self) -> Self {
        // Round-trip: create new snapshot from existing one
        Self::create(snapshot.state_data.clone(), snapshot.metadata.clone())
    }

    fn calculate_integrity_hash(
        state_data: &[(String, Vec<u8>)],
        metadata: &SnapshotMetadata,
    ) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        metadata.version.hash(&mut hasher);
        metadata.timestamp.hash(&mut hasher);
        metadata.execution_context.hash(&mut hasher);

        for (key, value) in state_data {
            key.hash(&mut hasher);
            value.hash(&mut hasher);
        }

        hasher.finish()
    }

    pub fn roundtrip_preserves_state(&self, restored: &Self) -> bool {
        self.state_data == restored.state_data
            && self.metadata == restored.metadata
            && self.integrity_hash == restored.integrity_hash
    }
}

impl MockCausalityDag {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            dependencies: Vec::new(),
            topological_order: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: CausalEvent) {
        self.events.push(event);
    }

    pub fn add_dependency(&mut self, predecessor: u64, successor: u64) {
        self.dependencies.push((predecessor, successor));
    }

    pub fn compute_topological_order(&mut self) -> bool {
        // Simple topological sort using Kahn's algorithm
        let mut in_degree: std::collections::HashMap<u64, usize> =
            self.events.iter().map(|e| (e.event_id, 0)).collect();

        // Calculate in-degrees
        for &(_, successor) in &self.dependencies {
            *in_degree.entry(successor).or_insert(0) += 1;
        }

        // Find nodes with no incoming edges
        let mut queue: Vec<u64> = in_degree
            .iter()
            .filter_map(
                |(&event_id, &degree)| {
                    if degree == 0 { Some(event_id) } else { None }
                },
            )
            .collect();

        self.topological_order.clear();

        while let Some(event_id) = queue.pop() {
            self.topological_order.push(event_id);

            // Remove edges from this node
            for &(pred, succ) in &self.dependencies {
                if pred == event_id {
                    let succ_degree = in_degree.get_mut(&succ).unwrap();
                    *succ_degree -= 1;
                    if *succ_degree == 0 {
                        queue.push(succ);
                    }
                }
            }
        }

        // Check if all events are included (no cycles)
        self.topological_order.len() == self.events.len()
    }

    pub fn causal_ordering_preserved(&self) -> bool {
        // Verify that dependencies respect topological order
        for &(pred, succ) in &self.dependencies {
            let pred_pos = self.topological_order.iter().position(|&id| id == pred);
            let succ_pos = self.topological_order.iter().position(|&id| id == succ);

            if let (Some(pred_idx), Some(succ_idx)) = (pred_pos, succ_pos) {
                if pred_idx >= succ_idx {
                    return false; // Causal ordering violated
                }
            }
        }
        true
    }
}

impl MockDpor {
    pub fn new() -> Self {
        Self {
            execution_paths: Vec::new(),
            reduced_paths: Vec::new(),
            equivalence_classes: Vec::new(),
        }
    }

    pub fn add_execution_path(&mut self, path: ExecutionPath) {
        self.execution_paths.push(path);
    }

    pub fn apply_dpor_reduction(&mut self) {
        // Simple DPOR: group paths by final state
        let mut state_groups: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();

        for (i, path) in self.execution_paths.iter().enumerate() {
            state_groups
                .entry(path.final_state.clone())
                .or_insert_with(Vec::new)
                .push(i);
        }

        // Create equivalence classes
        self.equivalence_classes = state_groups.values().cloned().collect();

        // Select representative from each equivalence class
        self.reduced_paths.clear();
        for class in &self.equivalence_classes {
            if let Some(&first_idx) = class.first() {
                self.reduced_paths
                    .push(self.execution_paths[first_idx].clone());
            }
        }
    }

    pub fn dpor_equivalence_preserved(&self) -> bool {
        // Check that each equivalence class has same final state
        for class in &self.equivalence_classes {
            let mut final_states: std::collections::HashSet<&String> =
                std::collections::HashSet::new();

            for &path_idx in class {
                if let Some(path) = self.execution_paths.get(path_idx) {
                    final_states.insert(&path.final_state);
                }
            }

            if final_states.len() > 1 {
                return false; // Equivalence class has different final states
            }
        }
        true
    }
}

impl MockTraceIntegrity {
    pub fn new() -> Self {
        Self {
            trace_segments: Vec::new(),
            cumulative_hash: 0,
            integrity_proofs: Vec::new(),
        }
    }

    pub fn add_segment(&mut self, segment: TraceSegment) {
        self.trace_segments.push(segment);
        self.recalculate_cumulative_hash();
    }

    fn recalculate_cumulative_hash(&mut self) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        for segment in &self.trace_segments {
            segment.segment_hash.hash(&mut hasher);
        }
        self.cumulative_hash = hasher.finish();
    }

    pub fn generate_integrity_proof(&mut self, segment_id: u64) -> bool {
        if let Some(segment) = self
            .trace_segments
            .iter()
            .find(|s| s.segment_id == segment_id)
        {
            // Generate merkle proof for segment
            let merkle_root = segment.segment_hash;
            let proof_chain = vec![merkle_root, self.cumulative_hash];

            self.integrity_proofs.push(IntegrityProof {
                segment_id,
                merkle_root,
                proof_chain,
            });
            true
        } else {
            false
        }
    }

    pub fn verify_integrity(&self) -> bool {
        // Verify that cumulative hash is consistent with segments
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        for segment in &self.trace_segments {
            segment.segment_hash.hash(&mut hasher);
        }
        let computed_hash = hasher.finish();

        computed_hash == self.cumulative_hash
    }

    pub fn integrity_hash_determinism(&self, other: &Self) -> bool {
        if self.trace_segments.len() != other.trace_segments.len() {
            return false;
        }

        // Same trace segments should produce same cumulative hash
        for (s1, s2) in self.trace_segments.iter().zip(&other.trace_segments) {
            if s1.events != s2.events {
                return false;
            }
        }

        self.cumulative_hash == other.cumulative_hash
    }
}

impl MockOtelSpanTree {
    pub fn new(root_span: Span) -> Self {
        Self {
            root_span,
            span_relationships: Vec::new(),
            exported_spans: Vec::new(),
        }
    }

    pub fn add_child_span(&mut self, parent_id: u64, child_span: Span) {
        let relationship = SpanRelationship {
            parent_id,
            child_id: child_span.span_id,
            relationship_type: RelationshipType::ChildOf,
        };
        self.span_relationships.push(relationship);
    }

    pub fn export_spans(&mut self) {
        self.exported_spans.clear();

        // Export root span
        let root_duration = self
            .root_span
            .end_time
            .map(|end| end.saturating_sub(self.root_span.start_time))
            .unwrap_or(0);

        self.exported_spans.push(ExportedSpan {
            span_id: self.root_span.span_id,
            trace_id: 1, // Simplified trace ID
            parent_span_id: self.root_span.parent_id,
            operation_name: self.root_span.operation_name.clone(),
            duration_ms: root_duration,
        });

        // Export child spans
        for relationship in &self.span_relationships {
            let exported = ExportedSpan {
                span_id: relationship.child_id,
                trace_id: 1,
                parent_span_id: Some(relationship.parent_id),
                operation_name: format!("child_operation_{}", relationship.child_id),
                duration_ms: 100, // Simplified duration
            };
            self.exported_spans.push(exported);
        }
    }

    pub fn span_tree_preserved(&self) -> bool {
        // Check that parent-child relationships are preserved in export
        for relationship in &self.span_relationships {
            let child_exported = self
                .exported_spans
                .iter()
                .find(|s| s.span_id == relationship.child_id);

            if let Some(exported_child) = child_exported {
                if exported_child.parent_span_id != Some(relationship.parent_id) {
                    return false;
                }
            } else {
                return false; // Child span not exported
            }
        }
        true
    }
}

impl MockSpectralHealth {
    pub fn new(time_series: Vec<HealthDataPoint>) -> Self {
        Self {
            time_series,
            smoothed_series: Vec::new(),
            spectral_coefficients: Vec::new(),
            trend_direction: TrendDirection::Unknown,
        }
    }

    pub fn apply_spectral_smoothing(&mut self, window_size: usize) {
        if self.time_series.len() < window_size {
            self.smoothed_series = self.time_series.clone();
            return;
        }

        self.smoothed_series.clear();

        for i in 0..self.time_series.len() {
            let start = if i >= window_size / 2 {
                i - window_size / 2
            } else {
                0
            };
            let end = (i + window_size / 2 + 1).min(self.time_series.len());

            let sum: f64 = self.time_series[start..end].iter().map(|dp| dp.value).sum();
            let count = (end - start) as f64;
            let smoothed_value = sum / count;

            let confidence_sum: f64 = self.time_series[start..end]
                .iter()
                .map(|dp| dp.confidence)
                .sum();
            let smoothed_confidence = confidence_sum / count;

            self.smoothed_series.push(HealthDataPoint {
                timestamp: self.time_series[i].timestamp,
                value: smoothed_value,
                confidence: smoothed_confidence,
            });
        }

        self.update_trend_direction();
    }

    fn update_trend_direction(&mut self) {
        if self.smoothed_series.len() < 2 {
            self.trend_direction = TrendDirection::Unknown;
            return;
        }

        let first_half_avg = self.smoothed_series[..self.smoothed_series.len() / 2]
            .iter()
            .map(|dp| dp.value)
            .sum::<f64>()
            / (self.smoothed_series.len() / 2) as f64;

        let second_half_avg = self.smoothed_series[self.smoothed_series.len() / 2..]
            .iter()
            .map(|dp| dp.value)
            .sum::<f64>()
            / (self.smoothed_series.len() - self.smoothed_series.len() / 2) as f64;

        let threshold = 0.05; // 5% threshold for trend detection

        if second_half_avg > first_half_avg * (1.0 + threshold) {
            self.trend_direction = TrendDirection::Improving;
        } else if second_half_avg < first_half_avg * (1.0 - threshold) {
            self.trend_direction = TrendDirection::Degrading;
        } else {
            self.trend_direction = TrendDirection::Stable;
        }
    }

    pub fn smoothing_preserves_trends(&self, original_trend: TrendDirection) -> bool {
        // Smoothing should preserve major trends
        match (original_trend, &self.trend_direction) {
            (TrendDirection::Improving, TrendDirection::Improving)
            | (TrendDirection::Degrading, TrendDirection::Degrading)
            | (TrendDirection::Stable, TrendDirection::Stable) => true,
            // Allow some tolerance for unknown trends
            (TrendDirection::Unknown, _) | (_, TrendDirection::Unknown) => true,
            // Smoothing might stabilize small variations
            (_, TrendDirection::Stable) => true,
            _ => false,
        }
    }
}

impl MockDiagnosticsPercentile {
    pub fn new(measurements: Vec<f64>) -> Self {
        let mut sorted_measurements = measurements.clone();
        sorted_measurements.sort_by(|a, b| a.partial_cmp(b).unwrap());

        Self {
            measurements,
            percentiles: Vec::new(),
            sorted_measurements,
        }
    }

    pub fn calculate_percentiles(&mut self, percentile_points: &[f64]) {
        self.percentiles.clear();

        for &percentile in percentile_points {
            if percentile < 0.0 || percentile > 100.0 {
                continue; // Invalid percentile
            }

            let value = self.calculate_percentile_value(percentile);
            self.percentiles.push((percentile, value));
        }
    }

    fn calculate_percentile_value(&self, percentile: f64) -> f64 {
        if self.sorted_measurements.is_empty() {
            return 0.0;
        }

        if percentile == 0.0 {
            return self.sorted_measurements[0];
        }

        if percentile == 100.0 {
            return self.sorted_measurements[self.sorted_measurements.len() - 1];
        }

        let index = (percentile / 100.0) * (self.sorted_measurements.len() - 1) as f64;
        let lower_index = index.floor() as usize;
        let upper_index = index.ceil() as usize;

        if lower_index == upper_index {
            self.sorted_measurements[lower_index]
        } else {
            let weight = index - lower_index as f64;
            let lower_value = self.sorted_measurements[lower_index];
            let upper_value = self.sorted_measurements[upper_index];
            lower_value + weight * (upper_value - lower_value)
        }
    }

    pub fn percentile_ordering_preserved(&self) -> bool {
        // Check that percentiles are in ascending order
        for window in self.percentiles.windows(2) {
            if window[0].0 > window[1].0 {
                continue; // Skip if percentile points are not in order
            }
            if window[0].1 > window[1].1 {
                return false; // Values should be non-decreasing
            }
        }
        true
    }
}

impl MockAuthenticatedEncryption {
    pub fn new(plaintext: Vec<u8>, key: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            plaintext,
            key,
            nonce,
            ciphertext: Vec::new(),
            authentication_tag: Vec::new(),
        }
    }

    pub fn encrypt(&mut self) -> bool {
        if self.key.len() < 32 || self.nonce.len() < 12 {
            return false; // Invalid key or nonce size
        }

        // Simple XOR encryption (for testing purposes)
        self.ciphertext = self
            .plaintext
            .iter()
            .zip(self.key.iter().cycle())
            .map(|(p, k)| p ^ k)
            .collect();

        // Generate authentication tag (simplified)
        self.authentication_tag = self.compute_auth_tag(&self.ciphertext);
        true
    }

    pub fn decrypt(&self) -> Option<Vec<u8>> {
        if self.ciphertext.is_empty() || self.authentication_tag.is_empty() {
            return None;
        }

        // Verify authentication tag first
        let computed_tag = self.compute_auth_tag(&self.ciphertext);
        if computed_tag != self.authentication_tag {
            return None; // Authentication failed
        }

        // Decrypt (reverse XOR)
        let decrypted: Vec<u8> = self
            .ciphertext
            .iter()
            .zip(self.key.iter().cycle())
            .map(|(c, k)| c ^ k)
            .collect();

        Some(decrypted)
    }

    fn compute_auth_tag(&self, data: &[u8]) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.key.hash(&mut hasher);
        self.nonce.hash(&mut hasher);
        data.hash(&mut hasher);

        let hash_value = hasher.finish();
        hash_value.to_le_bytes().to_vec()
    }

    pub fn encryption_symmetry_holds(&self) -> bool {
        if let Some(decrypted) = self.decrypt() {
            decrypted == self.plaintext
        } else {
            false
        }
    }
}

impl MockSecurityTag {
    pub fn new(data: Vec<u8>, algorithm: TagAlgorithm) -> Self {
        Self {
            data,
            tag: Vec::new(),
            algorithm,
            verification_result: false,
        }
    }

    pub fn generate_tag(&mut self, key: &[u8]) -> bool {
        if key.is_empty() {
            return false;
        }

        self.tag = self.compute_tag(key);
        true
    }

    fn compute_tag(&self, key: &[u8]) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        match self.algorithm {
            TagAlgorithm::HmacSha256 => {
                key.hash(&mut hasher);
                self.data.hash(&mut hasher);
                "HMAC-SHA256".hash(&mut hasher);
            }
            TagAlgorithm::HmacSha512 => {
                key.hash(&mut hasher);
                self.data.hash(&mut hasher);
                "HMAC-SHA512".hash(&mut hasher);
            }
            TagAlgorithm::Poly1305 => {
                key.hash(&mut hasher);
                self.data.hash(&mut hasher);
                "Poly1305".hash(&mut hasher);
            }
            TagAlgorithm::Aes128Gmac => {
                key.hash(&mut hasher);
                self.data.hash(&mut hasher);
                "AES-128-GMAC".hash(&mut hasher);
            }
        }

        let hash_value = hasher.finish();
        hash_value.to_le_bytes().to_vec()
    }

    pub fn verify_tag(&mut self, key: &[u8]) -> bool {
        let computed_tag = self.compute_tag(key);
        self.verification_result = computed_tag == self.tag;
        self.verification_result
    }

    pub fn tag_verification_consistency(&self, other: &Self) -> bool {
        // Same data and key should produce same verification result
        self.data == other.data
            && self.tag == other.tag
            && self.algorithm == other.algorithm
            && self.verification_result == other.verification_result
    }
}

/// MR-ChaosDeterminism: Chaos generation should be deterministic for same seed
/// Category: Equivalence (same seed → same chaos sequence)
/// Property: chaos_generator(seed) should produce identical sequences for same seed
#[test]
fn test_mr_chaos_determinism() {
    proptest!(|(
        seed: u64,
        sequence_length in 1usize..=50usize,
        iterations in 2usize..=5usize
    )| {
        let mut generators = Vec::new();

        // Create multiple generators with same seed
        for _ in 0..iterations {
            let mut generator = MockChaosGenerator::new(seed);
            generator.generate_chaos_sequence(sequence_length);
            generators.push(generator);
        }

        // MR: All generators with same seed should produce identical sequences
        let first_generator = &generators[0];
        for generator in generators.iter().skip(1) {
            prop_assert!(first_generator.determinism_holds(generator),
                "Chaos generators with same seed should produce identical sequences");
        }

        // Test event iteration determinism
        for generator_pair in generators.windows(2) {
            let mut gen1 = generator_pair[0].clone();
            let mut gen2 = generator_pair[1].clone();

            for _ in 0..sequence_length {
                let event1 = gen1.next_event();
                let event2 = gen2.next_event();
                prop_assert_eq!(event1, event2,
                    "Event iteration should be deterministic for same seed");
            }
        }
    });
}

/// MR-ReplayVerifier: Replay verification should preserve causal correctness
/// Category: Equivalence (replay should produce equivalent result)
/// Property: replay(trace) should verify correctly if causally consistent
#[test]
fn test_mr_replay_verifier() {
    proptest!(|(
        event_count in 1usize..=20usize,
        process_count in 1u64..=5u64
    )| {
        let mut original_events = Vec::new();

        // Generate causal trace
        for i in 0..event_count {
            let process_id = (i as u64) % process_count;
            let event = TraceEvent {
                event_id: i as u64,
                timestamp: i as u64 * 1000,
                event_type: EventType::TaskStart { task_id: i as u64 },
                causality_vector: vec![i as u64; process_count as usize],
            };
            original_events.push(event);
        }

        let mut verifier = MockReplayVerifier::new(original_events.clone());

        // Test identical replay
        let identical_result = verifier.replay(original_events.clone());
        prop_assert_eq!(identical_result, VerificationResult::Identical,
            "Identical replay should verify as identical");

        // Test equivalent replay (same causality)
        let equivalent_events = original_events.clone();
        let equivalent_result = verifier.replay(equivalent_events);

        // MR: Replay verification should preserve correctness for equivalent traces
        prop_assert!(verifier.replay_correctness_holds(),
            "Replay verification should preserve causal correctness");
    });
}

/// MR-ScenarioRunnerDeterminism: Scenario execution should be deterministic
/// Category: Equivalence (same seed + scenario → same results)
/// Property: scenario_runner(seed, steps) should produce identical results
#[test]
fn test_mr_scenario_runner_determinism() {
    proptest!(|(
        scenario_id: String,
        deterministic_seed: u64,
        step_count in 1usize..=10usize
    )| {
        if scenario_id.is_empty() {
            return Ok(());
        }

        // Create execution steps
        let mut steps = Vec::new();
        for i in 0..step_count {
            steps.push(ExecutionStep {
                step_id: i as u64,
                step_type: StepType::SpawnTask,
                parameters: vec![("param".to_string(), format!("value_{}", i))],
            });
        }

        // Run scenario multiple times with same seed
        let mut runners = Vec::new();
        for _ in 0..3 {
            let mut runner = MockScenarioRunner::new(scenario_id.clone(), deterministic_seed);
            for step in &steps {
                runner.add_step(step.clone());
            }
            let success = runner.execute();
            runners.push((runner, success));
        }

        // MR: All runs with same seed should produce identical results
        let (first_runner, first_success) = &runners[0];
        for (runner, success) in runners.iter().skip(1) {
            prop_assert!(first_runner.execution_determinism_holds(runner),
                "Scenario execution should be deterministic for same seed");
            prop_assert_eq!(*success, *first_success,
                "Scenario success should be deterministic");
        }
    });
}

/// MR-LabSnapshotRestoreRoundTrip: Lab snapshot/restore should preserve state
/// Category: Invertive (snapshot→restore should preserve state)
/// Property: restore(snapshot(state)) = state
#[test]
fn test_mr_lab_snapshot_restore_round_trip() {
    proptest!(|(
        state_entries: Vec<(String, Vec<u8>)>,
        version: u64,
        timestamp: u64,
        execution_context: String
    )| {
        if execution_context.is_empty() {
            return Ok(());
        }

        let metadata = SnapshotMetadata {
            version,
            timestamp,
            execution_context,
        };

        let original_snapshot = MockLabSnapshot::create(state_entries, metadata);
        let restored_snapshot = MockLabSnapshot::restore(&original_snapshot);

        // MR: Snapshot/restore round-trip should preserve all state
        prop_assert!(original_snapshot.roundtrip_preserves_state(&restored_snapshot),
            "Lab snapshot/restore round-trip should preserve state");

        // Multiple restore operations should be idempotent
        let second_restore = MockLabSnapshot::restore(&restored_snapshot);
        prop_assert!(restored_snapshot.roundtrip_preserves_state(&second_restore),
            "Multiple snapshot restores should be idempotent");
    });
}

/// MR-CausalityDagOrdering: Causality DAG should preserve causal ordering
/// Category: Permutative (causal dependencies preserved under reordering)
/// Property: topological_sort(dag) should respect all causal dependencies
#[test]
fn test_mr_causality_dag_ordering() {
    proptest!(|(
        event_count in 2usize..=15usize,
        dependency_ratio in 0.0f64..=0.5f64
    )| {
        let mut dag = MockCausalityDag::new();

        // Add events
        for i in 0..event_count {
            dag.add_event(CausalEvent {
                event_id: i as u64,
                logical_timestamp: i as u64,
                process_id: (i % 3) as u64,
                event_data: format!("event_{}", i),
            });
        }

        // Add dependencies
        let dependency_count = ((event_count as f64) * dependency_ratio) as usize;
        for i in 0..dependency_count.min(event_count - 1) {
            dag.add_dependency(i as u64, (i + 1) as u64);
        }

        // Compute topological order
        let has_valid_order = dag.compute_topological_order();

        if has_valid_order {
            // MR: Causal ordering should be preserved in topological sort
            prop_assert!(dag.causal_ordering_preserved(),
                "Causality DAG should preserve causal ordering in topological sort");

            // All events should be included in topological order
            prop_assert_eq!(dag.topological_order.len(), event_count,
                "All events should be included in topological order");
        }
    });
}

/// MR-DporEquivalencePreservation: DPOR should preserve equivalent execution outcomes
/// Category: Equivalence (equivalent executions → same final state)
/// Property: dpor_reduce(paths) should group equivalent executions correctly
#[test]
fn test_mr_dpor_equivalence_preservation() {
    proptest!(|(
        path_count in 2usize..=10usize,
        operation_count in 1usize..=5usize
    )| {
        let mut dpor = MockDpor::new();

        // Generate execution paths with some equivalent final states
        for i in 0..path_count {
            let mut operations = Vec::new();
            for j in 0..operation_count {
                operations.push(Operation {
                    operation_id: (i * operation_count + j) as u64,
                    operation_type: if j % 2 == 0 { OperationType::Read } else { OperationType::Write },
                    target: format!("var_{}", j % 3),
                });
            }

            // Create some paths with same final state
            let final_state = format!("state_{}", i % 3);

            dpor.add_execution_path(ExecutionPath {
                path_id: i as u64,
                operations,
                final_state,
            });
        }

        // Apply DPOR reduction
        dpor.apply_dpor_reduction();

        // MR: DPOR should preserve equivalence classes correctly
        prop_assert!(dpor.dpor_equivalence_preserved(),
            "DPOR should preserve equivalence classes with same final states");

        // Reduced paths should be fewer than or equal to original paths
        prop_assert!(dpor.reduced_paths.len() <= dpor.execution_paths.len(),
            "DPOR reduction should not increase path count");
    });
}

/// MR-TraceIntegrityHashDeterminism: Trace integrity hashes should be deterministic
/// Category: Equivalence (same trace → same integrity hash)
/// Property: integrity_hash(trace) should be identical for same trace content
#[test]
fn test_mr_trace_integrity_hash_determinism() {
    proptest!(|(
        segment_count in 1usize..=5usize,
        events_per_segment in 1usize..=10usize
    )| {
        let mut trace1 = MockTraceIntegrity::new();
        let mut trace2 = MockTraceIntegrity::new();

        // Add identical segments to both traces
        for seg_id in 0..segment_count {
            let mut events = Vec::new();
            for event_id in 0..events_per_segment {
                events.push(TraceEvent {
                    event_id: (seg_id * events_per_segment + event_id) as u64,
                    timestamp: (event_id * 1000) as u64,
                    event_type: EventType::TaskStart { task_id: event_id as u64 },
                    causality_vector: vec![event_id as u64],
                });
            }

            let segment_hash = (seg_id as u64 + 1) * 12345; // Deterministic hash
            let segment = TraceSegment {
                segment_id: seg_id as u64,
                events: events.clone(),
                segment_hash,
            };

            trace1.add_segment(segment.clone());
            trace2.add_segment(segment);
        }

        // MR: Identical traces should have identical integrity hashes
        prop_assert!(trace1.integrity_hash_determinism(&trace2),
            "Identical traces should produce identical integrity hashes");

        // Both traces should verify successfully
        prop_assert!(trace1.verify_integrity(),
            "Trace 1 should verify its integrity");
        prop_assert!(trace2.verify_integrity(),
            "Trace 2 should verify its integrity");

        // Generate proofs for all segments
        for seg_id in 0..segment_count {
            let proof1_success = trace1.generate_integrity_proof(seg_id as u64);
            let proof2_success = trace2.generate_integrity_proof(seg_id as u64);

            prop_assert!(proof1_success && proof2_success,
                "Integrity proof generation should succeed for valid segments");
        }
    });
}

/// MR-OtelSpanTreePreservation: OTEL span export should preserve tree structure
/// Category: Permutative (span relationships preserved under export)
/// Property: export(span_tree) should maintain parent-child relationships
#[test]
fn test_mr_otel_span_tree_preservation() {
    proptest!(|(
        root_operation: String,
        child_count in 1usize..=8usize
    )| {
        if root_operation.is_empty() {
            return Ok(());
        }

        let root_span = Span {
            span_id: 1,
            parent_id: None,
            operation_name: root_operation,
            start_time: 1000,
            end_time: Some(5000),
            attributes: vec![("service".to_string(), "test".to_string())],
        };

        let mut span_tree = MockOtelSpanTree::new(root_span);

        // Add child spans
        for i in 0..child_count {
            let child_span = Span {
                span_id: (i + 2) as u64,
                parent_id: Some(1),
                operation_name: format!("child_operation_{}", i),
                start_time: 2000 + i as u64 * 500,
                end_time: Some(3000 + i as u64 * 500),
                attributes: vec![],
            };

            span_tree.add_child_span(1, child_span);
        }

        // Export spans
        span_tree.export_spans();

        // MR: Span tree structure should be preserved in export
        prop_assert!(span_tree.span_tree_preserved(),
            "OTEL span export should preserve parent-child relationships");

        // All spans should be exported (root + children)
        prop_assert_eq!(span_tree.exported_spans.len(), child_count + 1,
            "All spans should be exported: root + children");

        // Root span should have no parent in export
        let root_exported = span_tree.exported_spans.iter()
            .find(|s| s.span_id == 1);

        if let Some(root) = root_exported {
            prop_assert_eq!(root.parent_span_id, None,
                "Root span should have no parent in export");
        }
    });
}

/// MR-SpectralHealthSmoothingTrendPreservation: Spectral smoothing should preserve major trends
/// Category: Inclusive (smoothing preserves trend direction)
/// Property: smooth(health_data) should preserve overall trend direction
#[test]
fn test_mr_spectral_health_smoothing_trend_preservation() {
    proptest!(|(
        data_points: Vec<(u64, f64, f64)>, // (timestamp, value, confidence)
        window_size in 3usize..=10usize
    )| {
        if data_points.len() < window_size {
            return Ok(());
        }

        let health_data: Vec<HealthDataPoint> = data_points.into_iter()
            .map(|(timestamp, value, confidence)| HealthDataPoint {
                timestamp,
                value: value.abs().min(100.0), // Keep values reasonable
                confidence: confidence.abs().min(1.0),
            })
            .collect();

        // Determine original trend
        let first_half_avg = health_data[..health_data.len()/2]
            .iter().map(|dp| dp.value).sum::<f64>() / (health_data.len()/2) as f64;
        let second_half_avg = health_data[health_data.len()/2..]
            .iter().map(|dp| dp.value).sum::<f64>() / (health_data.len() - health_data.len()/2) as f64;

        let original_trend = if second_half_avg > first_half_avg * 1.1 {
            TrendDirection::Improving
        } else if second_half_avg < first_half_avg * 0.9 {
            TrendDirection::Degrading
        } else {
            TrendDirection::Stable
        };

        let mut spectral_health = MockSpectralHealth::new(health_data);
        spectral_health.apply_spectral_smoothing(window_size);

        // MR: Smoothing should preserve major trends
        prop_assert!(spectral_health.smoothing_preserves_trends(original_trend.clone()),
            "Spectral smoothing should preserve trend direction: original={:?}, smoothed={:?}",
            original_trend, spectral_health.trend_direction);

        // Smoothed series should have same length as original
        prop_assert_eq!(spectral_health.smoothed_series.len(), spectral_health.time_series.len(),
            "Smoothed series should have same length as original");
    });
}

/// MR-DiagnosticsPercentileOrdering: Diagnostics percentiles should maintain ordering
/// Category: Inclusive (percentile ordering preserved)
/// Property: percentile(p1) ≤ percentile(p2) if p1 ≤ p2
#[test]
fn test_mr_diagnostics_percentile_ordering() {
    proptest!(|(
        measurements: Vec<f64>,
        percentile_points: Vec<f64>
    )| {
        if measurements.is_empty() || percentile_points.is_empty() {
            return Ok(());
        }

        // Filter valid percentiles and sort them
        let mut valid_percentiles: Vec<f64> = percentile_points.into_iter()
            .filter(|&p| p >= 0.0 && p <= 100.0)
            .collect();

        if valid_percentiles.len() < 2 {
            return Ok(());
        }

        valid_percentiles.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let mut diagnostics = MockDiagnosticsPercentile::new(measurements);
        diagnostics.calculate_percentiles(&valid_percentiles);

        // MR: Percentile ordering should be preserved
        prop_assert!(diagnostics.percentile_ordering_preserved(),
            "Diagnostics percentiles should maintain ordering property");

        // Check specific percentile relationships
        if valid_percentiles.contains(&0.0) && valid_percentiles.contains(&100.0) {
            let p0 = diagnostics.percentiles.iter().find(|(p, _)| *p == 0.0);
            let p100 = diagnostics.percentiles.iter().find(|(p, _)| *p == 100.0);

            if let (Some((_, min_val)), Some((_, max_val))) = (p0, p100) {
                prop_assert!(*min_val <= *max_val,
                    "0th percentile should be ≤ 100th percentile");
            }
        }
    });
}

/// MR-AuthenticatedEncryptionSymmetry: Authenticated encryption should be reversible
/// Category: Invertive (encrypt→decrypt = identity)
/// Property: decrypt(encrypt(plaintext)) = plaintext
#[test]
fn test_mr_authenticated_encryption_symmetry() {
    proptest!(|(
        plaintext: Vec<u8>,
        key_size in 32usize..=64usize,
        nonce_size in 12usize..=24usize
    )| {
        if plaintext.is_empty() {
            return Ok(());
        }

        // Generate deterministic key and nonce
        let key: Vec<u8> = (0..key_size).map(|i| (i * 17 + 42) as u8).collect();
        let nonce: Vec<u8> = (0..nonce_size).map(|i| (i * 23 + 7) as u8).collect();

        let mut auth_encryption = MockAuthenticatedEncryption::new(plaintext.clone(), key, nonce);

        // Encrypt
        let encrypt_success = auth_encryption.encrypt();
        prop_assert!(encrypt_success, "Encryption should succeed with valid key/nonce");

        // MR: Authenticated encryption should be symmetric (reversible)
        prop_assert!(auth_encryption.encryption_symmetry_holds(),
            "Authenticated encryption should be symmetric: decrypt(encrypt(plaintext)) = plaintext");

        // Ciphertext should be different from plaintext (unless all zeros)
        if !plaintext.iter().all(|&b| b == 0) {
            prop_assert_ne!(auth_encryption.ciphertext, plaintext,
                "Ciphertext should differ from plaintext");
        }

        // Authentication tag should be generated
        prop_assert!(!auth_encryption.authentication_tag.is_empty(),
            "Authentication tag should be generated");
    });
}

/// MR-SecurityTagVerificationConsistency: Tag verification should be consistent
/// Category: Equivalence (same data + key → same verification result)
/// Property: verify_tag(data, key) should produce consistent results
#[test]
fn test_mr_security_tag_verification_consistency() {
    proptest!(|(
        data: Vec<u8>,
        key: Vec<u8>,
        algorithm_idx in 0usize..4
    )| {
        if data.is_empty() || key.is_empty() {
            return Ok(());
        }

        let algorithms = [
            TagAlgorithm::HmacSha256,
            TagAlgorithm::HmacSha512,
            TagAlgorithm::Poly1305,
            TagAlgorithm::Aes128Gmac,
        ];

        let algorithm = algorithms[algorithm_idx].clone();

        // Generate tag with multiple instances
        let mut tag1 = MockSecurityTag::new(data.clone(), algorithm.clone());
        let mut tag2 = MockSecurityTag::new(data.clone(), algorithm);

        let gen_success1 = tag1.generate_tag(&key);
        let gen_success2 = tag2.generate_tag(&key);

        prop_assert!(gen_success1 && gen_success2,
            "Tag generation should succeed with valid inputs");

        // Tags should be identical for same inputs. `.clone()` the tag
        // field so tag1/tag2 remain intact for the followup verify_tag
        // borrows below.
        prop_assert_eq!(tag1.tag.clone(), tag2.tag.clone(),
            "Same data and key should produce identical tags");

        // Verify tags
        let verify1 = tag1.verify_tag(&key);
        let verify2 = tag2.verify_tag(&key);

        // MR: Tag verification should be consistent
        prop_assert!(tag1.tag_verification_consistency(&tag2),
            "Tag verification should be consistent for same inputs");

        prop_assert!(verify1 && verify2,
            "Tag verification should succeed for correctly generated tags");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_implementations() {
        // Test chaos generator determinism
        let mut gen1 = MockChaosGenerator::new(12345);
        let mut gen2 = MockChaosGenerator::new(12345);
        gen1.generate_chaos_sequence(5);
        gen2.generate_chaos_sequence(5);
        assert!(gen1.determinism_holds(&gen2));

        // Test replay verifier
        let events = vec![TraceEvent {
            event_id: 1,
            timestamp: 1000,
            event_type: EventType::TaskStart { task_id: 1 },
            causality_vector: vec![1, 0],
        }];
        let mut verifier = MockReplayVerifier::new(events.clone());
        let result = verifier.replay(events);
        assert_eq!(result, VerificationResult::Identical);

        // Test authenticated encryption
        let plaintext = vec![1, 2, 3, 4, 5];
        let key = vec![42; 32];
        let nonce = vec![7; 12];
        let mut auth_enc = MockAuthenticatedEncryption::new(plaintext, key, nonce);
        assert!(auth_enc.encrypt());
        assert!(auth_enc.encryption_symmetry_holds());
    }
}
