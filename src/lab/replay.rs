//! Replay and diff utilities for trace analysis.
//!
//! This module provides utilities for:
//! - Replaying a trace to reproduce an execution
//! - Comparing two traces to find divergences
//! - Replay validation with certificate checking
//! - **Trace normalization** for canonical replay ordering
//!
//! # Trace Normalization
//!
//! Use [`normalize_for_replay`] to reorder trace events into a canonical form
//! that minimizes context switches while preserving all happens-before
//! relationships. This is useful for:
//!
//! - Deterministic comparison of equivalent traces
//! - Debugging with reduced interleaving noise
//! - Trace minimization and simplification
//!
//! ```ignore
//! use asupersync::lab::replay::{normalize_for_replay, traces_equivalent};
//!
//! // Normalize a trace
//! let result = normalize_for_replay(&events);
//! println!("{}", result); // Shows switch count reduction
//!
//! // Compare two traces for equivalence
//! if traces_equivalent(&trace_a, &trace_b) {
//!     println!("Traces are equivalent under normalization");
//! }
//! ```

use crate::lab::config::LabConfig;
use crate::lab::runtime::{CrashpackLink, LabRuntime, SporkHarnessReport};
use crate::lab::spork_harness::{ScenarioRunnerError, SporkScenarioConfig, SporkScenarioRunner};
use crate::trace::{TraceBuffer, TraceBufferHandle, TraceEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Compares two traces and returns the first divergence point.
///
/// Returns `None` if the traces are equivalent.
#[must_use]
pub fn find_divergence(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let a_events = a;
    let b_events = b;

    for (i, (a_event, b_event)) in a_events.iter().zip(b_events.iter()).enumerate() {
        if !events_match(a_event, b_event) {
            return Some(TraceDivergence {
                position: i,
                event_a: (*a_event).clone(),
                event_b: (*b_event).clone(),
            });
        }
    }

    // Check for length mismatch
    if a_events.len() != b_events.len() {
        let position = a_events.len().min(b_events.len());
        #[allow(clippy::map_unwrap_or)]
        return Some(TraceDivergence {
            position,
            event_a: a_events
                .get(position)
                .map(|e| (*e).clone())
                .unwrap_or_else(|| {
                    TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace A>")
                }),
            event_b: b_events
                .get(position)
                .map(|e| (*e).clone())
                .unwrap_or_else(|| {
                    TraceEvent::user_trace(0, crate::types::Time::ZERO, "<end of trace B>")
                }),
        });
    }

    None
}

/// Checks if two events match (ignoring sequence numbers).
fn events_match(a: &TraceEvent, b: &TraceEvent) -> bool {
    a.kind == b.kind && a.time == b.time && a.logical_time == b.logical_time && a.data == b.data
}

/// A divergence between two traces.
#[derive(Debug, Clone)]
pub struct TraceDivergence {
    /// Position in the trace where divergence occurred.
    pub position: usize,
    /// Event from trace A at the divergence point.
    pub event_a: TraceEvent,
    /// Event from trace B at the divergence point.
    pub event_b: TraceEvent,
}

impl std::fmt::Display for TraceDivergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Divergence at position {}:\n  A: {}\n  B: {}",
            self.position, self.event_a, self.event_b
        )
    }
}

/// Summary of a trace for quick comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceSummary {
    /// Number of events.
    pub event_count: usize,
    /// Number of spawn events.
    pub spawn_count: usize,
    /// Number of complete events.
    pub complete_count: usize,
    /// Number of cancel events.
    pub cancel_count: usize,
}

impl TraceSummary {
    /// Creates a summary from a trace buffer.
    #[must_use]
    pub fn from_buffer(buffer: &TraceBuffer) -> Self {
        use crate::trace::event::TraceEventKind;

        let mut summary = Self {
            event_count: 0,
            spawn_count: 0,
            complete_count: 0,
            cancel_count: 0,
        };

        for event in buffer.iter() {
            summary.event_count += 1;
            match event.kind {
                TraceEventKind::Spawn => summary.spawn_count += 1,
                TraceEventKind::Complete => summary.complete_count += 1,
                TraceEventKind::CancelRequest | TraceEventKind::CancelAck => {
                    summary.cancel_count += 1;
                }
                _ => {}
            }
        }

        summary
    }
}

/// Result of a replay validation.
#[derive(Debug)]
pub struct ReplayValidation {
    /// Whether the replay matched the original.
    pub matched: bool,
    /// Certificate from the original run.
    pub original_certificate: u64,
    /// Certificate from the replay.
    pub replay_certificate: u64,
    /// First trace divergence (if any).
    pub divergence: Option<TraceDivergence>,
    /// Steps in original.
    pub original_steps: u64,
    /// Steps in replay.
    pub replay_steps: u64,
}

impl ReplayValidation {
    /// True if both certificate and trace matched.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.matched && self.divergence.is_none()
    }
}

impl std::fmt::Display for ReplayValidation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_valid() {
            write!(
                f,
                "Replay OK: {} steps, certificate {:#018x}",
                self.replay_steps, self.replay_certificate
            )
        } else {
            write!(f, "Replay DIVERGED:")?;
            if self.original_certificate != self.replay_certificate {
                write!(
                    f,
                    "\n  Certificate mismatch: original={:#018x} replay={:#018x}",
                    self.original_certificate, self.replay_certificate
                )?;
            }
            if let Some(ref div) = self.divergence {
                write!(f, "\n  {div}")?;
            }
            if self.original_steps != self.replay_steps {
                write!(
                    f,
                    "\n  Step count mismatch: original={} replay={}",
                    self.original_steps, self.replay_steps
                )?;
            }
            Ok(())
        }
    }
}

/// Replay a test with the same seed and validate determinism.
///
/// Runs the test twice with the same seed and checks:
/// 1. Schedule certificates match
/// 2. Traces match (no divergence)
/// 3. Step counts match
pub fn validate_replay<F>(seed: u64, worker_count: usize, test: F) -> ReplayValidation
where
    F: Fn(&mut LabRuntime),
{
    let run = |s: u64| -> (u64, u64, TraceBufferHandle) {
        let mut config = LabConfig::new(s);
        config = config.worker_count(worker_count);
        let mut runtime = LabRuntime::new(config);
        test(&mut runtime);
        let steps = runtime.steps();
        let cert = runtime.certificate().hash();
        let trace = runtime.trace().clone();
        (steps, cert, trace)
    };

    let (steps_a, cert_a, trace_a) = run(seed);
    let (steps_b, cert_b, trace_b) = run(seed);

    let events_a = trace_a.snapshot();
    let events_b = trace_b.snapshot();
    let divergence = find_divergence(&events_a, &events_b);
    let matched = cert_a == cert_b && steps_a == steps_b;

    ReplayValidation {
        matched,
        original_certificate: cert_a,
        replay_certificate: cert_b,
        divergence,
        original_steps: steps_a,
        replay_steps: steps_b,
    }
}

/// Validate replay across multiple seeds and report any failures.
pub fn validate_replay_multi<F>(
    seeds: &[u64],
    worker_count: usize,
    test: F,
) -> Vec<ReplayValidation>
where
    F: Fn(&mut LabRuntime),
{
    seeds
        .iter()
        .map(|&seed| validate_replay(seed, worker_count, &test))
        .collect()
}

/// Single seed-run summary for schedule exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationRunSummary {
    /// Seed used for this run.
    pub seed: u64,
    /// Scheduler certificate hash for this run.
    pub schedule_hash: u64,
    /// Canonical normalized-trace fingerprint for this run.
    pub trace_fingerprint: u64,
}

/// Deterministic fingerprint class produced by exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationFingerprintClass {
    /// Canonical normalized-trace fingerprint.
    pub trace_fingerprint: u64,
    /// Number of runs in this class.
    pub run_count: usize,
    /// Seeds observed in this class (sorted, deduplicated).
    pub seeds: Vec<u64>,
    /// Schedule hashes observed in this class (sorted, deduplicated).
    pub schedule_hashes: Vec<u64>,
}

/// Deterministic schedule-exploration report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorationReport {
    /// Per-seed runs in stable order.
    pub runs: Vec<ExplorationRunSummary>,
    /// Unique canonical fingerprint classes in stable order.
    pub fingerprint_classes: Vec<ExplorationFingerprintClass>,
}

impl ExplorationReport {
    /// Number of unique canonical fingerprint classes observed.
    #[must_use]
    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprint_classes.len()
    }
}

/// Per-run deterministic summary for Spork app exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkExplorationRunSummary {
    /// Seed used for this run.
    pub seed: u64,
    /// Scheduler certificate hash for this run.
    pub schedule_hash: u64,
    /// Canonical trace fingerprint for this run.
    pub trace_fingerprint: u64,
    /// Whether all run invariants/oracles passed.
    pub passed: bool,
    /// Crashpack link metadata for failing runs when available.
    pub crashpack_link: Option<CrashpackLink>,
}

/// Deterministic DPOR-style report for Spork app seed exploration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkExplorationReport {
    /// Per-seed run summaries in stable order.
    pub runs: Vec<SporkExplorationRunSummary>,
    /// Unique canonical fingerprint classes in stable order.
    pub fingerprint_classes: Vec<ExplorationFingerprintClass>,
}

impl SporkExplorationReport {
    /// Number of unique canonical fingerprint classes observed.
    #[must_use]
    pub fn unique_fingerprint_count(&self) -> usize {
        self.fingerprint_classes.len()
    }

    /// Number of failed runs.
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.runs.iter().filter(|run| !run.passed).count()
    }

    /// True when every failed run includes crashpack linkage metadata.
    #[must_use]
    pub fn all_failures_linked_to_crashpacks(&self) -> bool {
        self.runs
            .iter()
            .filter(|run| !run.passed)
            .all(|run| run.crashpack_link.is_some())
    }
}

/// Classify run summaries by canonical fingerprint into deterministic classes.
#[must_use]
pub fn classify_fingerprint_classes(
    runs: &[ExplorationRunSummary],
) -> Vec<ExplorationFingerprintClass> {
    let mut grouped: BTreeMap<u64, (usize, Vec<u64>, Vec<u64>)> = BTreeMap::new();

    for run in runs {
        let entry = grouped
            .entry(run.trace_fingerprint)
            .or_insert_with(|| (0, Vec::new(), Vec::new()));
        entry.0 += 1;
        entry.1.push(run.seed);
        entry.2.push(run.schedule_hash);
    }

    grouped
        .into_iter()
        .map(
            |(trace_fingerprint, (run_count, mut seeds, mut schedule_hashes))| {
                seeds.sort_unstable();
                seeds.dedup();
                schedule_hashes.sort_unstable();
                schedule_hashes.dedup();
                ExplorationFingerprintClass {
                    trace_fingerprint,
                    run_count,
                    seeds,
                    schedule_hashes,
                }
            },
        )
        .collect()
}

/// Explore a seed-space and report deterministic canonical fingerprint classes.
///
/// This is a DPOR-style seed exploration helper: each seed produces one schedule
/// and one normalized-trace fingerprint; the report groups equivalent runs.
pub fn explore_seed_space<F>(seeds: &[u64], worker_count: usize, test: F) -> ExplorationReport
where
    F: Fn(&mut LabRuntime),
{
    let mut runs: Vec<ExplorationRunSummary> = seeds
        .iter()
        .map(|&seed| {
            let mut config = LabConfig::new(seed);
            config = config.worker_count(worker_count);
            let mut runtime = LabRuntime::new(config);
            test(&mut runtime);

            let trace_events = runtime.trace().snapshot();
            let normalized = normalize_for_replay(&trace_events);
            let trace_fingerprint =
                crate::trace::canonicalize::trace_fingerprint(&normalized.normalized);

            ExplorationRunSummary {
                seed,
                schedule_hash: runtime.certificate().hash(),
                trace_fingerprint,
            }
        })
        .collect();

    runs.sort_by_key(|run| run.seed);
    let fingerprint_classes = classify_fingerprint_classes(&runs);
    ExplorationReport {
        runs,
        fingerprint_classes,
    }
}

/// Build a deterministic Spork exploration report from completed harness reports.
#[must_use]
pub fn summarize_spork_reports(reports: &[SporkHarnessReport]) -> SporkExplorationReport {
    let mut runs: Vec<SporkExplorationRunSummary> = reports
        .iter()
        .map(|report| {
            let passed = report.passed();
            SporkExplorationRunSummary {
                seed: report.seed(),
                schedule_hash: report.run.trace_certificate.schedule_hash,
                trace_fingerprint: report.trace_fingerprint(),
                passed,
                crashpack_link: if passed {
                    None
                } else {
                    report.crashpack_link()
                },
            }
        })
        .collect();

    runs.sort_by_key(|run| (run.seed, run.schedule_hash, run.trace_fingerprint));

    let class_input: Vec<ExplorationRunSummary> = runs
        .iter()
        .map(|run| ExplorationRunSummary {
            seed: run.seed,
            schedule_hash: run.schedule_hash,
            trace_fingerprint: run.trace_fingerprint,
        })
        .collect();

    SporkExplorationReport {
        runs,
        fingerprint_classes: classify_fingerprint_classes(&class_input),
    }
}

/// Explore a Spork app seed-space and produce a deterministic DPOR-style report.
///
/// The caller provides one harness report per seed (typically by running
/// `SporkAppHarness`/`SporkScenarioRunner` with that seed). The result is
/// grouped by canonical fingerprint class and keeps failure-to-crashpack links.
pub fn explore_spork_seed_space<F>(seeds: &[u64], mut run_for_seed: F) -> SporkExplorationReport
where
    F: FnMut(u64) -> SporkHarnessReport,
{
    let reports: Vec<SporkHarnessReport> = seeds.iter().map(|&seed| run_for_seed(seed)).collect();
    summarize_spork_reports(&reports)
}

/// Run a registered Spork scenario across seeds and return deterministic
/// exploration classes with failure-to-crashpack linkage.
///
/// This is the glue between `SporkScenarioRunner` and DPOR-style exploration:
/// callers provide a scenario id and base config, and this helper handles
/// seed fan-out + deterministic report grouping.
pub fn explore_scenario_runner_seed_space(
    runner: &SporkScenarioRunner,
    scenario_id: &str,
    base_config: &SporkScenarioConfig,
    seeds: &[u64],
) -> Result<SporkExplorationReport, ScenarioRunnerError> {
    let mut reports = Vec::with_capacity(seeds.len());
    for &seed in seeds {
        let mut config = base_config.clone();
        config.seed = seed;
        let result = runner.run_with_config(scenario_id, Some(config))?;
        reports.push(result.report);
    }
    Ok(summarize_spork_reports(&reports))
}

/// Schema version for the divergence corpus registry.
pub const DIVERGENCE_CORPUS_SCHEMA_VERSION: &str = "lab-live-divergence-corpus-v1";

/// Retention class for a divergence artifact bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceBundleLevel {
    /// Preserve the complete debugging bundle.
    Full,
    /// Preserve only the reduced summary bundle.
    Reduced,
}

/// Final differential policy class from the divergence taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialPolicyClass {
    /// Stable semantic mismatch on a supported surface.
    RuntimeSemanticBug,
    /// Lab model, mapping, or comparator bug.
    LabModelOrMappingBug,
    /// Required artifact schema or evidence is missing/malformed.
    ArtifactSchemaViolation,
    /// The surface lacks the observability needed for a strong claim.
    InsufficientObservability,
    /// The surface is outside the admitted differential scope.
    UnsupportedSurface,
    /// The mismatch looks like scheduling noise rather than semantics.
    SchedulerNoiseSuspected,
    /// The mismatch could not be stabilized by rerun policy.
    IrreproducibleDivergence,
}

impl DifferentialPolicyClass {
    /// Stable string form shared by docs, logs, and registry entries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeSemanticBug => "runtime_semantic_bug",
            Self::LabModelOrMappingBug => "lab_model_or_mapping_bug",
            Self::ArtifactSchemaViolation => "artifact_schema_violation",
            Self::InsufficientObservability => "insufficient_observability",
            Self::UnsupportedSurface => "unsupported_surface",
            Self::SchedulerNoiseSuspected => "scheduler_noise_suspected",
            Self::IrreproducibleDivergence => "irreproducible_divergence",
        }
    }

    /// Required bundle strength from the divergence taxonomy.
    #[must_use]
    pub fn bundle_level(self) -> DivergenceBundleLevel {
        match self {
            Self::RuntimeSemanticBug
            | Self::LabModelOrMappingBug
            | Self::ArtifactSchemaViolation
            | Self::IrreproducibleDivergence => DivergenceBundleLevel::Full,
            Self::InsufficientObservability
            | Self::UnsupportedSurface
            | Self::SchedulerNoiseSuspected => DivergenceBundleLevel::Reduced,
        }
    }
}

impl std::fmt::Display for DifferentialPolicyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state for a divergence corpus entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionPromotionState {
    /// Newly discovered divergence under investigation.
    Investigating,
    /// A minimized reproducer exists and preserves the same semantics.
    Minimized,
    /// Promoted into a durable regression artifact.
    PromotedRegression,
    /// Retained as a known-open investigation instead of a regression.
    KnownOpen,
    /// Explicitly rejected for promotion.
    Rejected,
}

/// Minimization/shrinker status for a divergence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceShrinkStatus {
    /// No shrinker has been requested yet.
    NotRequested,
    /// Shrinking is still in progress.
    Pending,
    /// A minimized reproducer exists and preserves the semantic class.
    PreservedSemanticClass,
    /// Shrinking failed to preserve the semantic class and must not replace the original.
    Rejected,
}

/// Stable artifact layout for a retained differential bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceArtifactBundle {
    /// Root directory for the retained bundle.
    pub bundle_root: String,
    /// Stable summary record path.
    pub differential_summary_path: String,
    /// Stable event-log path.
    pub differential_event_log_path: String,
    /// Stable failures path.
    pub differential_failures_path: String,
    /// Stable deviations path.
    pub differential_deviations_path: String,
    /// Stable repro manifest path.
    pub differential_repro_manifest_path: String,
    /// Stable lab normalized-record path.
    pub lab_normalized_path: String,
    /// Stable live normalized-record path.
    pub live_normalized_path: String,
}

impl DivergenceArtifactBundle {
    /// Build the canonical bundle layout under a root directory.
    #[must_use]
    pub fn under(root: impl Into<String>) -> Self {
        let bundle_root = root.into().trim_end_matches('/').to_string();
        let join = |name: &str| format!("{bundle_root}/{name}");
        Self {
            bundle_root: bundle_root.clone(),
            differential_summary_path: join("differential_summary.json"),
            differential_event_log_path: join("differential_event_log.jsonl"),
            differential_failures_path: join("differential_failures.json"),
            differential_deviations_path: join("differential_deviations.json"),
            differential_repro_manifest_path: join("differential_repro_manifest.json"),
            lab_normalized_path: join("lab_normalized.json"),
            live_normalized_path: join("live_normalized.json"),
        }
    }
}

/// Stable retention metadata for a divergence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceRetentionMetadata {
    /// Required bundle strength.
    pub bundle_level: DivergenceBundleLevel,
    /// Default local retention window in days.
    pub local_retention_days: u16,
    /// Default CI retention window in days.
    pub ci_retention_days: u16,
    /// Default redaction policy for retained artifacts.
    pub redaction_mode: String,
}

impl DivergenceRetentionMetadata {
    /// Retention defaults derived from the divergence taxonomy.
    #[must_use]
    pub fn for_policy_class(policy_class: DifferentialPolicyClass) -> Self {
        Self {
            bundle_level: policy_class.bundle_level(),
            local_retention_days: 14,
            ci_retention_days: 30,
            redaction_mode: "metadata_only".to_string(),
        }
    }
}

/// First-seen execution context for a divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceFirstSeenContext {
    /// Named runner profile such as `smoke`, `pilot_surface`, or `nightly`.
    pub runner_profile: String,
    /// Attempt index within the local run.
    pub attempt_index: u32,
    /// Number of reruns already attempted when this entry was recorded.
    pub rerun_count: u32,
}

/// Minimization lineage for a divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceMinimizationLineage {
    /// Original canonical seed from the first-seen run.
    pub original_seed: u64,
    /// Minimized seed when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimized_seed: Option<u64>,
    /// Named shrinker or minimization pass when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shrinker: Option<String>,
    /// Current shrink status.
    pub shrink_status: DivergenceShrinkStatus,
    /// Whether the minimized form preserved the same divergence class.
    pub preserved_divergence_class: bool,
    /// Whether the minimized form preserved the same policy class.
    pub preserved_policy_class: bool,
}

impl DivergenceMinimizationLineage {
    /// Start minimization lineage from a seed lineage record.
    #[must_use]
    pub fn from_seed_lineage(lineage: &crate::lab::dual_run::SeedLineageRecord) -> Self {
        Self {
            original_seed: lineage.canonical_seed,
            minimized_seed: None,
            shrinker: None,
            shrink_status: DivergenceShrinkStatus::NotRequested,
            preserved_divergence_class: true,
            preserved_policy_class: true,
        }
    }

    /// Record a minimized reproducer that preserves the same semantic meaning.
    #[must_use]
    pub fn with_minimized_seed(
        mut self,
        seed: u64,
        shrinker: impl Into<String>,
        preserved_divergence_class: bool,
        preserved_policy_class: bool,
    ) -> Self {
        self.minimized_seed = Some(seed);
        self.shrinker = Some(shrinker.into());
        self.shrink_status = if preserved_divergence_class && preserved_policy_class {
            DivergenceShrinkStatus::PreservedSemanticClass
        } else {
            DivergenceShrinkStatus::Rejected
        };
        self.preserved_divergence_class = preserved_divergence_class;
        self.preserved_policy_class = preserved_policy_class;
        self
    }
}

/// One retained divergence entry in the differential corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceCorpusEntry {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable entry identifier used for registry upsert.
    pub entry_id: String,
    /// Scenario id from the differential run.
    pub scenario_id: String,
    /// Surface id from the differential run.
    pub surface_id: String,
    /// Surface contract version from the differential run.
    pub surface_contract_version: String,
    /// Diagnostic divergence class for this entry.
    pub divergence_class: String,
    /// Final differential policy class for this entry.
    pub policy_class: DifferentialPolicyClass,
    /// First-seen execution context.
    pub first_seen: DivergenceFirstSeenContext,
    /// Full seed lineage from the originating run.
    pub seed_lineage: crate::lab::dual_run::SeedLineageRecord,
    /// Stable mismatch field names for semantic preservation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatch_fields: Vec<String>,
    /// Stable retained bundle layout.
    pub artifact_bundle: DivergenceArtifactBundle,
    /// Shrinker/minimization lineage.
    pub minimization_lineage: DivergenceMinimizationLineage,
    /// Current promotion state for this entry.
    pub regression_promotion_state: RegressionPromotionState,
    /// Stable retention metadata.
    pub retention: DivergenceRetentionMetadata,
    /// Additional machine-readable annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl DivergenceCorpusEntry {
    /// Create a registry entry from a differential result and retained bundle root.
    #[must_use]
    pub fn from_dual_run_result(
        result: &crate::lab::dual_run::DualRunResult,
        runner_profile: impl Into<String>,
        divergence_class: impl Into<String>,
        policy_class: DifferentialPolicyClass,
        bundle_root: impl Into<String>,
    ) -> Self {
        let seed_lineage = result.seed_lineage.clone();
        let entry_id = Self::entry_id_for(
            &result.verdict.scenario_id,
            &seed_lineage.seed_lineage_id,
            policy_class,
        );
        let mut mismatch_fields: Vec<String> = result
            .verdict
            .mismatches
            .iter()
            .map(|mismatch| mismatch.field.clone())
            .collect();
        mismatch_fields.sort_unstable();
        mismatch_fields.dedup();

        let mut metadata = BTreeMap::new();
        if let Some(path) = result.lab.provenance.artifact_path.as_deref() {
            metadata.insert("lab_artifact_path".to_string(), path.to_string());
        }
        if let Some(path) = result.live.provenance.artifact_path.as_deref() {
            metadata.insert("live_artifact_path".to_string(), path.to_string());
        }
        if let Some(cmd) = result.lab.provenance.repro_command.as_deref() {
            metadata.insert("lab_repro_command".to_string(), cmd.to_string());
        }
        if let Some(cmd) = result.live.provenance.repro_command.as_deref() {
            metadata.insert("live_repro_command".to_string(), cmd.to_string());
        }
        if !result.lab_invariant_violations.is_empty() {
            metadata.insert(
                "lab_invariant_violations".to_string(),
                result.lab_invariant_violations.join(","),
            );
        }
        if !result.live_invariant_violations.is_empty() {
            metadata.insert(
                "live_invariant_violations".to_string(),
                result.live_invariant_violations.join(","),
            );
        }

        Self {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entry_id,
            scenario_id: result.verdict.scenario_id.clone(),
            surface_id: result.verdict.surface_id.clone(),
            surface_contract_version: result.lab.surface_contract_version.clone(),
            divergence_class: divergence_class.into(),
            policy_class,
            first_seen: DivergenceFirstSeenContext {
                runner_profile: runner_profile.into(),
                attempt_index: 0,
                rerun_count: 0,
            },
            seed_lineage: seed_lineage.clone(),
            mismatch_fields,
            artifact_bundle: DivergenceArtifactBundle::under(bundle_root),
            minimization_lineage: DivergenceMinimizationLineage::from_seed_lineage(&seed_lineage),
            regression_promotion_state: RegressionPromotionState::Investigating,
            retention: DivergenceRetentionMetadata::for_policy_class(policy_class),
            metadata,
        }
    }

    /// Stable entry id from the scenario, seed lineage, and final policy class.
    #[must_use]
    pub fn entry_id_for(
        scenario_id: &str,
        seed_lineage_id: &str,
        policy_class: DifferentialPolicyClass,
    ) -> String {
        format!(
            "{}.{}.{}",
            sanitize_registry_component(scenario_id),
            sanitize_registry_component(seed_lineage_id),
            policy_class.as_str()
        )
    }

    /// Default bundle root for this entry under `artifacts/differential/`.
    #[must_use]
    pub fn default_bundle_root(&self) -> String {
        format!(
            "artifacts/differential/{}/{}/{}",
            sanitize_registry_component(&self.surface_id),
            sanitize_registry_component(&self.scenario_id),
            sanitize_registry_component(&self.seed_lineage.seed_lineage_id)
        )
    }

    /// Update first-seen attempt/rerun counters.
    #[must_use]
    pub fn with_first_seen_attempt(mut self, attempt_index: u32, rerun_count: u32) -> Self {
        self.first_seen.attempt_index = attempt_index;
        self.first_seen.rerun_count = rerun_count;
        self
    }

    /// Update the minimization lineage.
    #[must_use]
    pub fn with_minimization_lineage(mut self, lineage: DivergenceMinimizationLineage) -> Self {
        self.minimization_lineage = lineage;
        self.regression_promotion_state = if self.minimization_lineage.minimized_seed.is_some() {
            RegressionPromotionState::Minimized
        } else {
            self.regression_promotion_state
        };
        self
    }

    /// Promote the entry into a durable regression artifact.
    #[must_use]
    pub fn promote_to_regression(mut self, promoted_scenario_id: impl Into<String>) -> Self {
        self.regression_promotion_state = RegressionPromotionState::PromotedRegression;
        self.metadata.insert(
            "promoted_scenario_id".to_string(),
            promoted_scenario_id.into(),
        );
        self
    }
}

/// Deterministic registry of retained divergences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceCorpusRegistry {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Entries sorted by stable entry id.
    pub entries: Vec<DivergenceCorpusEntry>,
}

impl DivergenceCorpusRegistry {
    /// Create an empty divergence corpus registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: DIVERGENCE_CORPUS_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        }
    }

    /// Insert or replace an entry by stable id, preserving deterministic order.
    pub fn upsert(&mut self, entry: DivergenceCorpusEntry) {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|existing| existing.entry_id == entry.entry_id)
        {
            *existing = entry;
        } else {
            self.entries.push(entry);
            self.entries
                .sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
        }
    }
}

impl Default for DivergenceCorpusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Schema version for the retained divergence summary payload.
pub const DIFFERENTIAL_SUMMARY_SCHEMA_VERSION: &str = "lab-live-differential-summary-v1";
/// Schema version for runtime/failure artifact linkage.
pub const DIFFERENTIAL_FAILURES_SCHEMA_VERSION: &str = "lab-live-differential-failures-v1";
/// Schema version for mismatch/deviation details.
pub const DIFFERENTIAL_DEVIATIONS_SCHEMA_VERSION: &str = "lab-live-differential-deviations-v1";
/// Schema version for the replay/minimization repro manifest.
pub const DIFFERENTIAL_REPRO_MANIFEST_SCHEMA_VERSION: &str =
    "lab-live-differential-repro-manifest-v1";

/// Serializable crashpack linkage metadata for retained divergence bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialCrashpackReference {
    /// Crashpack artifact path.
    pub path: String,
    /// Stable crashpack identifier.
    pub id: String,
    /// Canonical trace fingerprint associated with the crashpack.
    pub fingerprint: u64,
    /// One-line replay command for the crashpack.
    pub replay_command: String,
}

impl DifferentialCrashpackReference {
    /// Convert an existing runtime crashpack link into the retained schema.
    #[must_use]
    pub fn from_runtime_link(link: &CrashpackLink) -> Self {
        Self {
            path: link.path.clone(),
            id: link.id.clone(),
            fingerprint: link.fingerprint,
            replay_command: link.replay.command_line.clone(),
        }
    }

    /// Infer crashpack linkage from normalized provenance when the artifact path
    /// already points at a crashpack-like artifact.
    #[must_use]
    pub fn from_provenance(provenance: &crate::lab::dual_run::ReplayMetadata) -> Option<Self> {
        let path = provenance.artifact_path.as_ref()?;
        let file_name = path.rsplit('/').next().unwrap_or(path);
        if !file_name.contains("crashpack") {
            return None;
        }
        let fingerprint = provenance.trace_fingerprint?;
        Some(Self {
            path: path.clone(),
            id: format!(
                "crashpack-{:016x}-{:016x}",
                provenance.effective_seed, fingerprint
            ),
            fingerprint,
            replay_command: provenance
                .repro_command
                .clone()
                .unwrap_or_else(|| provenance.default_repro_command()),
        })
    }
}

/// One runtime-side artifact record inside `differential_failures.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialFailureArtifact {
    /// Runtime side that produced the artifact.
    pub runtime_kind: String,
    /// Canonical normalized-record path inside the retained bundle.
    pub normalized_record_path: String,
    /// Optional source artifact path from the original execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    /// Replay command for rerunning this side.
    pub repro_command: String,
    /// Crashpack metadata when the source artifact is a crashpack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crashpack_link: Option<DifferentialCrashpackReference>,
    /// Side-specific invariant violations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant_violations: Vec<String>,
}

impl DifferentialFailureArtifact {
    #[must_use]
    fn from_observable(
        observable: &crate::lab::dual_run::NormalizedObservable,
        normalized_record_path: impl Into<String>,
        invariant_violations: &[String],
    ) -> Self {
        let repro_command = observable
            .provenance
            .repro_command
            .clone()
            .unwrap_or_else(|| observable.provenance.default_repro_command());

        Self {
            runtime_kind: observable.runtime_kind.to_string(),
            normalized_record_path: normalized_record_path.into(),
            artifact_path: observable.provenance.artifact_path.clone(),
            repro_command,
            crashpack_link: DifferentialCrashpackReference::from_provenance(&observable.provenance),
            invariant_violations: invariant_violations.to_vec(),
        }
    }
}

/// Stable contents for `differential_summary.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialSummaryDocument {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Surface contract version.
    pub surface_contract_version: String,
    /// Human-readable verdict summary.
    pub verdict_summary: String,
    /// Policy-layer summary.
    pub policy_summary: String,
    /// Divergence class retained for the bundle.
    pub divergence_class: String,
    /// Final policy class retained for the bundle.
    pub policy_class: DifferentialPolicyClass,
    /// Current promotion state.
    pub regression_promotion_state: RegressionPromotionState,
    /// Stable mismatch field names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatch_fields: Vec<String>,
    /// Number of mismatch fields retained in the summary.
    pub mismatch_count: usize,
    /// Whether the underlying run semantically passed.
    pub passed: bool,
    /// Number of lab-side invariant violations.
    pub lab_invariant_violation_count: usize,
    /// Number of live-side invariant violations.
    pub live_invariant_violation_count: usize,
    /// Retained bundle strength.
    pub bundle_level: DivergenceBundleLevel,
    /// Stable retained bundle root.
    pub bundle_root: String,
}

/// Stable contents for `differential_failures.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialFailuresDocument {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Runtime-side artifact linkage records.
    pub failure_artifacts: Vec<DifferentialFailureArtifact>,
}

/// Stable contents for `differential_deviations.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialDeviationsDocument {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Policy-layer summary for the mismatch.
    pub policy_summary: String,
    /// Provisional divergence class.
    pub provisional_class: String,
    /// Suggested final divergence class when already known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_final_class: Option<String>,
    /// Human-readable explanation for downstream reports.
    pub explanation: String,
    /// Stable semantic mismatches in field order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatches: Vec<crate::lab::dual_run::SemanticMismatch>,
    /// Lab-side invariant violations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lab_invariant_violations: Vec<String>,
    /// Live-side invariant violations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub live_invariant_violations: Vec<String>,
}

/// Stable contents for `differential_repro_manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialReproManifest {
    /// Stable schema discriminator.
    pub schema_version: String,
    /// Stable divergence entry identifier.
    pub entry_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Surface identifier.
    pub surface_id: String,
    /// Surface contract version.
    pub surface_contract_version: String,
    /// Divergence class retained for the bundle.
    pub divergence_class: String,
    /// Final policy class retained for the bundle.
    pub policy_class: DifferentialPolicyClass,
    /// Current promotion state.
    pub regression_promotion_state: RegressionPromotionState,
    /// Automatic rerun decision from the policy layer.
    pub rerun_decision: crate::lab::dual_run::RerunDecision,
    /// Original first-seen run context.
    pub first_seen: DivergenceFirstSeenContext,
    /// Seed lineage for replay/reproduction.
    pub seed_lineage: crate::lab::dual_run::SeedLineageRecord,
    /// Shrinker/minimization lineage.
    pub minimization_lineage: DivergenceMinimizationLineage,
    /// Stable retained bundle root.
    pub bundle_root: String,
    /// Stable retained summary path.
    pub summary_path: String,
    /// Stable retained deviations path.
    pub deviations_path: String,
    /// Stable retained failures path.
    pub failure_artifacts_path: String,
    /// Stable retained lab normalized observable path.
    pub lab_normalized_path: String,
    /// Stable retained live normalized observable path.
    pub live_normalized_path: String,
    /// Stable reproduction commands across both sides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repro_commands: Vec<String>,
    /// Promoted regression scenario identifier when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_scenario_id: Option<String>,
}

/// Complete in-memory payload set for a retained divergence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialBundleArtifacts {
    /// Summary payload for `differential_summary.json`.
    pub summary: DifferentialSummaryDocument,
    /// Artifact linkage payload for `differential_failures.json`.
    pub failures: DifferentialFailuresDocument,
    /// Mismatch/deviation payload for `differential_deviations.json`.
    pub deviations: DifferentialDeviationsDocument,
    /// Replay/minimization manifest for `differential_repro_manifest.json`.
    pub repro_manifest: DifferentialReproManifest,
    /// Canonical lab-side normalized observable for `lab_normalized.json`.
    pub lab_normalized: crate::lab::dual_run::NormalizedObservable,
    /// Canonical live-side normalized observable for `live_normalized.json`.
    pub live_normalized: crate::lab::dual_run::NormalizedObservable,
}

impl DifferentialBundleArtifacts {
    /// Build the full retained bundle payload set from a divergence entry and
    /// the originating differential result.
    #[must_use]
    pub fn from_dual_run_result(
        entry: &DivergenceCorpusEntry,
        result: &crate::lab::dual_run::DualRunResult,
    ) -> Self {
        let failure_artifacts = vec![
            DifferentialFailureArtifact::from_observable(
                &result.lab,
                entry.artifact_bundle.lab_normalized_path.clone(),
                &result.lab_invariant_violations,
            ),
            DifferentialFailureArtifact::from_observable(
                &result.live,
                entry.artifact_bundle.live_normalized_path.clone(),
                &result.live_invariant_violations,
            ),
        ];
        let mut repro_commands: Vec<String> = failure_artifacts
            .iter()
            .map(|artifact| artifact.repro_command.clone())
            .collect();
        repro_commands.sort_unstable();
        repro_commands.dedup();

        let summary = DifferentialSummaryDocument {
            schema_version: DIFFERENTIAL_SUMMARY_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            surface_contract_version: entry.surface_contract_version.clone(),
            verdict_summary: result.verdict.summary(),
            policy_summary: result.policy.summary(),
            divergence_class: entry.divergence_class.clone(),
            policy_class: entry.policy_class,
            regression_promotion_state: entry.regression_promotion_state,
            mismatch_fields: entry.mismatch_fields.clone(),
            mismatch_count: entry.mismatch_fields.len(),
            passed: result.passed(),
            lab_invariant_violation_count: result.lab_invariant_violations.len(),
            live_invariant_violation_count: result.live_invariant_violations.len(),
            bundle_level: entry.retention.bundle_level,
            bundle_root: entry.artifact_bundle.bundle_root.clone(),
        };

        let failures = DifferentialFailuresDocument {
            schema_version: DIFFERENTIAL_FAILURES_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            failure_artifacts,
        };

        let deviations = DifferentialDeviationsDocument {
            schema_version: DIFFERENTIAL_DEVIATIONS_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            policy_summary: result.policy.summary(),
            provisional_class: result.policy.provisional_class.to_string(),
            suggested_final_class: result
                .policy
                .suggested_final_class
                .map(|class| class.to_string()),
            explanation: result.policy.explanation.clone(),
            mismatches: result.verdict.mismatches.clone(),
            lab_invariant_violations: result.lab_invariant_violations.clone(),
            live_invariant_violations: result.live_invariant_violations.clone(),
        };

        let repro_manifest = DifferentialReproManifest {
            schema_version: DIFFERENTIAL_REPRO_MANIFEST_SCHEMA_VERSION.to_string(),
            entry_id: entry.entry_id.clone(),
            scenario_id: entry.scenario_id.clone(),
            surface_id: entry.surface_id.clone(),
            surface_contract_version: entry.surface_contract_version.clone(),
            divergence_class: entry.divergence_class.clone(),
            policy_class: entry.policy_class,
            regression_promotion_state: entry.regression_promotion_state,
            rerun_decision: result.policy.rerun_decision,
            first_seen: entry.first_seen.clone(),
            seed_lineage: entry.seed_lineage.clone(),
            minimization_lineage: entry.minimization_lineage.clone(),
            bundle_root: entry.artifact_bundle.bundle_root.clone(),
            summary_path: entry.artifact_bundle.differential_summary_path.clone(),
            deviations_path: entry.artifact_bundle.differential_deviations_path.clone(),
            failure_artifacts_path: entry.artifact_bundle.differential_failures_path.clone(),
            lab_normalized_path: entry.artifact_bundle.lab_normalized_path.clone(),
            live_normalized_path: entry.artifact_bundle.live_normalized_path.clone(),
            repro_commands,
            promoted_scenario_id: entry.metadata.get("promoted_scenario_id").cloned(),
        };

        Self {
            summary,
            failures,
            deviations,
            repro_manifest,
            lab_normalized: result.lab.clone(),
            live_normalized: result.live.clone(),
        }
    }
}

fn sanitize_registry_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

// ============================================================================
// Trace Normalization for Canonical Replay
// ============================================================================

/// Result of trace normalization.
#[derive(Debug, Clone)]
pub struct NormalizationResult {
    /// The normalized (reordered) trace events.
    pub normalized: Vec<TraceEvent>,
    /// Number of owner switches in the original trace.
    pub original_switches: usize,
    /// Number of owner switches after normalization.
    pub normalized_switches: usize,
    /// The algorithm used for normalization.
    pub algorithm: String,
}

impl NormalizationResult {
    /// Returns the reduction in switch count.
    #[must_use]
    pub fn switch_reduction(&self) -> usize {
        self.original_switches
            .saturating_sub(self.normalized_switches)
    }

    /// Returns the switch reduction as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn switch_reduction_pct(&self) -> f64 {
        if self.original_switches == 0 {
            0.0
        } else {
            (self.switch_reduction() as f64 / self.original_switches as f64) * 100.0
        }
    }
}

impl std::fmt::Display for NormalizationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Normalized {} events: {} → {} switches ({:.1}% reduction, {})",
            self.normalized.len(),
            self.original_switches,
            self.normalized_switches,
            self.switch_reduction_pct(),
            self.algorithm
        )
    }
}

/// Normalize a trace for canonical replay ordering.
///
/// This reorders trace events to minimize context switches while preserving
/// all happens-before relationships. The result is a canonical form suitable
/// for:
/// - Deterministic replay comparison
/// - Debugging (reduced noise from interleaving)
/// - Trace minimization
///
/// # Example
///
/// ```ignore
/// use asupersync::lab::replay::normalize_for_replay;
///
/// let events: Vec<TraceEvent> = /* captured trace */;
/// let result = normalize_for_replay(&events);
/// println!("{}", result); // Shows switch reduction
/// ```
#[must_use]
pub fn normalize_for_replay(events: &[TraceEvent]) -> NormalizationResult {
    normalize_for_replay_with_config(events, &crate::trace::GeodesicConfig::default())
}

/// Normalize a trace with custom configuration.
///
/// See [`GeodesicConfig`] for available options:
/// - `beam_threshold`: Trace size above which beam search is used
/// - `beam_width`: Width of beam search
/// - `step_budget`: Maximum search steps
#[must_use]
pub fn normalize_for_replay_with_config(
    events: &[TraceEvent],
    config: &crate::trace::GeodesicConfig,
) -> NormalizationResult {
    let original_switches = crate::trace::trace_switch_cost(events);
    let (normalized, geodesic_result) = crate::trace::normalize_trace(events, config);

    NormalizationResult {
        normalized,
        original_switches,
        normalized_switches: geodesic_result.switch_count,
        algorithm: format!("{:?}", geodesic_result.algorithm),
    }
}

/// Compare two traces for equivalence after normalization.
///
/// Two traces are considered equivalent if their normalized forms produce
/// the same sequence of events (respecting happens-before ordering).
///
/// Returns `None` if the traces are equivalent, or `Some(divergence)` if
/// they differ.
#[must_use]
pub fn compare_normalized(a: &[TraceEvent], b: &[TraceEvent]) -> Option<TraceDivergence> {
    let norm_a = normalize_for_replay(a);
    let norm_b = normalize_for_replay(b);
    find_divergence(&norm_a.normalized, &norm_b.normalized)
}

/// Check if two traces are equivalent under normalization.
///
/// This is a convenience wrapper around [`compare_normalized`].
#[must_use]
pub fn traces_equivalent(a: &[TraceEvent], b: &[TraceEvent]) -> bool {
    compare_normalized(a, b).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppSpec;
    use crate::lab::SporkScenarioSpec;
    use crate::trace::event::{TraceData, TraceEventKind};
    use crate::types::Budget;
    use crate::types::Time;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn identical_traces_no_divergence() {
        init_test("identical_traces_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "no divergence", true, ok);
        crate::test_complete!("identical_traces_no_divergence");
    }

    #[test]
    fn trace_seq_only_difference_no_divergence() {
        init_test("trace_seq_only_difference_no_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];
        let b = vec![TraceEvent::new(
            99,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("same".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let ok = div.is_none();
        crate::assert_with_log!(ok, "seq-only differences ignored", true, ok);
        crate::test_complete!("trace_seq_only_difference_no_divergence");
    }

    #[test]
    fn different_traces_find_divergence() {
        init_test("different_traces_find_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence");
    }

    #[test]
    fn different_traces_find_divergence_data() {
        init_test("different_traces_find_divergence_data");
        let a = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("a".to_string()),
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::ZERO,
            TraceEventKind::UserTrace,
            TraceData::Message("b".to_string()),
        )];

        let div = find_divergence(&a, &b);
        let some = div.is_some();
        crate::assert_with_log!(some, "divergence", true, some);
        let pos = div.expect("divergence").position;
        crate::assert_with_log!(pos == 0, "position", 0, pos);
        crate::test_complete!("different_traces_find_divergence_data");
    }

    // ── Replay validation tests ─────────────────────────────────────────

    #[test]
    fn replay_single_task_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(42, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
        assert_eq!(
            validation.original_certificate,
            validation.replay_certificate
        );
        assert_eq!(validation.original_steps, validation.replay_steps);
    }

    #[test]
    fn replay_two_tasks_deterministic() {
        use crate::types::Budget;
        let validation = validate_replay(0, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(validation.is_valid(), "Replay failed: {validation}");
    }

    #[test]
    fn replay_multi_seeds_all_deterministic() {
        use crate::types::Budget;
        let seeds: Vec<u64> = (0..10).collect();
        let results = validate_replay_multi(&seeds, 1, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for (i, v) in results.iter().enumerate() {
            assert!(v.is_valid(), "Seed {} replay failed: {v}", seeds[i]);
        }
    }

    #[test]
    fn replay_validation_display_ok() {
        let v = ReplayValidation {
            matched: true,
            original_certificate: 0x1234,
            replay_certificate: 0x1234,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("Replay OK"));
    }

    #[test]
    fn replay_validation_display_diverged() {
        let v = ReplayValidation {
            matched: false,
            original_certificate: 0x1234,
            replay_certificate: 0x5678,
            divergence: None,
            original_steps: 5,
            replay_steps: 5,
        };
        let s = format!("{v}");
        assert!(s.contains("DIVERGED"));
        assert!(s.contains("Certificate mismatch"));
    }

    // ── Normalization tests ─────────────────────────────────────────────

    #[test]
    fn normalization_single_owner_no_switches() {
        init_test("normalization_single_owner_no_switches");
        // All events from owner 1 - should have 0 switches
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(2),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];
        // All have seq numbers, but owner extraction uses seq % some_value or similar
        // The trace module should handle this; we're testing the wrapper

        let result = normalize_for_replay(&events);
        // Single-owner trace has no switches before or after
        assert_eq!(result.switch_reduction(), 0);
        crate::test_complete!("normalization_single_owner_no_switches");
    }

    #[test]
    fn normalization_result_display() {
        init_test("normalization_result_display");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 10,
            normalized_switches: 3,
            algorithm: "Greedy".to_string(),
        };

        let display = format!("{result}");
        assert!(display.contains("10 → 3 switches"));
        assert!(display.contains("70.0% reduction"));
        assert!(display.contains("Greedy"));
        crate::test_complete!("normalization_result_display");
    }

    #[test]
    fn normalization_result_zero_switches() {
        init_test("normalization_result_zero_switches");
        let result = NormalizationResult {
            normalized: vec![],
            original_switches: 0,
            normalized_switches: 0,
            algorithm: "Trivial".to_string(),
        };

        // Avoid division by zero
        let pct = result.switch_reduction_pct();
        assert!((pct - 0.0).abs() < f64::EPSILON);
        crate::test_complete!("normalization_result_zero_switches");
    }

    #[test]
    fn traces_equivalent_identical() {
        init_test("traces_equivalent_identical");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Complete,
                TraceData::None,
            ),
        ];

        let equivalent = traces_equivalent(&events, &events);
        crate::assert_with_log!(equivalent, "identical traces equivalent", true, equivalent);
        crate::test_complete!("traces_equivalent_identical");
    }

    #[test]
    fn traces_equivalent_ignores_sequence_numbers() {
        init_test("traces_equivalent_ignores_sequence_numbers");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            42,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            equivalent,
            "seq-only differences still equivalent",
            true,
            equivalent
        );
        crate::test_complete!("traces_equivalent_ignores_sequence_numbers");
    }

    #[test]
    fn traces_equivalent_different_kinds() {
        init_test("traces_equivalent_different_kinds");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let equivalent = traces_equivalent(&a, &b);
        crate::assert_with_log!(
            !equivalent,
            "different kinds not equivalent",
            false,
            equivalent
        );
        crate::test_complete!("traces_equivalent_different_kinds");
    }

    #[test]
    fn compare_normalized_returns_divergence() {
        init_test("compare_normalized_returns_divergence");
        let a = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Spawn,
            TraceData::None,
        )];
        let b = vec![TraceEvent::new(
            1,
            Time::from_nanos(0),
            TraceEventKind::Complete,
            TraceData::None,
        )];

        let divergence = compare_normalized(&a, &b);
        let has_div = divergence.is_some();
        crate::assert_with_log!(has_div, "divergence found", true, has_div);
        crate::test_complete!("compare_normalized_returns_divergence");
    }

    #[test]
    fn normalize_with_config_custom_beam() {
        use crate::trace::GeodesicConfig;

        init_test("normalize_with_config_custom_beam");
        let events = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(0),
                TraceEventKind::Spawn,
                TraceData::None,
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(1),
                TraceEventKind::Poll,
                TraceData::None,
            ),
        ];

        let config = GeodesicConfig {
            exact_threshold: 0,
            beam_threshold: 1,
            beam_width: 4,
            step_budget: 100,
        };

        let result = normalize_for_replay_with_config(&events, &config);
        // Just verify it runs without panic; algorithm choice depends on trace size
        assert!(!result.algorithm.is_empty());
        crate::test_complete!("normalize_with_config_custom_beam");
    }

    #[test]
    fn classify_fingerprint_classes_is_deterministic() {
        init_test("classify_fingerprint_classes_is_deterministic");

        let runs = vec![
            ExplorationRunSummary {
                seed: 9,
                schedule_hash: 0xB,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 3,
                schedule_hash: 0xA,
                trace_fingerprint: 0xBB,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
            ExplorationRunSummary {
                seed: 7,
                schedule_hash: 0xC,
                trace_fingerprint: 0xAA,
            },
        ];

        let classes = classify_fingerprint_classes(&runs);
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].trace_fingerprint, 0xAA);
        assert_eq!(classes[0].run_count, 3);
        assert_eq!(classes[0].seeds, vec![7, 9]);
        assert_eq!(classes[0].schedule_hashes, vec![0xB, 0xC]);
        assert_eq!(classes[1].trace_fingerprint, 0xBB);
        assert_eq!(classes[1].run_count, 1);
        assert_eq!(classes[1].seeds, vec![3]);
        assert_eq!(classes[1].schedule_hashes, vec![0xA]);

        crate::test_complete!("classify_fingerprint_classes_is_deterministic");
    }

    #[test]
    fn explore_seed_space_is_deterministic_for_same_inputs() {
        init_test("explore_seed_space_is_deterministic_for_same_inputs");

        let seeds = [11_u64, 13_u64, 11_u64];
        let scenario = |runtime: &mut LabRuntime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        };

        let a = explore_seed_space(&seeds, 1, scenario);
        let b = explore_seed_space(&seeds, 1, scenario);

        assert_eq!(a, b, "same seeds and scenario must produce same report");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        crate::test_complete!("explore_seed_space_is_deterministic_for_same_inputs");
    }

    fn make_spork_report(seed: u64, failing: bool) -> SporkHarnessReport {
        use crate::record::ObligationKind;

        let mut runtime = LabRuntime::with_seed(seed);
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
        runtime.run_until_quiescent();

        if failing {
            runtime
                .state
                .create_obligation(
                    ObligationKind::SendPermit,
                    task,
                    region,
                    Some("intentional failure for exploration".to_string()),
                )
                .expect("create failing obligation");
        }

        runtime.spork_report("spork_exploration", Vec::new())
    }

    #[test]
    fn summarize_spork_reports_links_failures_to_crashpacks() {
        init_test("summarize_spork_reports_links_failures_to_crashpacks");

        let passing = make_spork_report(31, false);
        let failing = make_spork_report(32, true);

        let summary = summarize_spork_reports(&[failing, passing]);
        assert_eq!(summary.runs.len(), 2);
        assert_eq!(summary.failure_count(), 1);
        assert!(summary.unique_fingerprint_count() >= 1);
        assert!(
            summary.all_failures_linked_to_crashpacks(),
            "failed runs must include crashpack linkage metadata"
        );

        let failed_run = summary
            .runs
            .iter()
            .find(|run| !run.passed)
            .expect("one failing run expected");
        let crashpack = failed_run
            .crashpack_link
            .as_ref()
            .expect("failing run should have crashpack link");
        assert!(
            crashpack.path.starts_with("crashpack-"),
            "unexpected crashpack path: {}",
            crashpack.path
        );

        crate::test_complete!("summarize_spork_reports_links_failures_to_crashpacks");
    }

    #[test]
    fn explore_spork_seed_space_is_deterministic() {
        init_test("explore_spork_seed_space_is_deterministic");

        let seeds = [42_u64, 41_u64, 42_u64];

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let a = explore_spork_seed_space(&seeds, run_for_seed);

        let run_for_seed = |seed: u64| make_spork_report(seed, seed.is_multiple_of(2));
        let b = explore_spork_seed_space(&seeds, run_for_seed);

        assert_eq!(a, b, "same seeds must produce deterministic report");
        assert_eq!(a.runs.len(), seeds.len());
        assert_eq!(a.failure_count(), 2);
        assert!(a.unique_fingerprint_count() >= 1);
        assert!(a.all_failures_linked_to_crashpacks());

        crate::test_complete!("explore_spork_seed_space_is_deterministic");
    }

    #[test]
    fn scenario_runner_exploration_has_deterministic_fingerprints() {
        init_test("scenario_runner_exploration_has_deterministic_fingerprints");

        let mut runner = SporkScenarioRunner::new();
        runner
            .register(
                SporkScenarioSpec::new("replay.scenario", |_| AppSpec::new("replay_app"))
                    .with_default_config(SporkScenarioConfig::default()),
            )
            .expect("register scenario");

        let base_config = SporkScenarioConfig::default();
        let seeds = [12_u64, 13_u64, 12_u64];

        let a =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration A");
        let b =
            explore_scenario_runner_seed_space(&runner, "replay.scenario", &base_config, &seeds)
                .expect("exploration B");

        assert_eq!(a, b, "scenario exploration must be deterministic");
        assert_eq!(a.runs.len(), seeds.len());
        assert!(a.unique_fingerprint_count() >= 1);

        // Same seed should map to the same fingerprint.
        let seed_12: Vec<_> = a.runs.iter().filter(|run| run.seed == 12).collect();
        assert_eq!(seed_12.len(), 2);
        assert_eq!(seed_12[0].trace_fingerprint, seed_12[1].trace_fingerprint);

        crate::test_complete!("scenario_runner_exploration_has_deterministic_fingerprints");
    }

    fn make_dual_run_divergence_result() -> crate::lab::dual_run::DualRunResult {
        use crate::lab::dual_run::{
            CancellationRecord, DualRunHarness, LoserDrainRecord, ObligationBalanceRecord,
            RegionCloseRecord, ResourceSurfaceRecord, TerminalOutcome,
        };

        fn base_semantics() -> crate::lab::dual_run::NormalizedSemantics {
            crate::lab::dual_run::NormalizedSemantics {
                terminal_outcome: TerminalOutcome::ok(),
                cancellation: CancellationRecord::none(),
                loser_drain: LoserDrainRecord::not_applicable(),
                region_close: RegionCloseRecord::quiescent(),
                obligation_balance: ObligationBalanceRecord::zero(),
                resource_surface: ResourceSurfaceRecord::empty("test.surface"),
            }
        }

        let mut result = DualRunHarness::phase1(
            "divergence.registry.case",
            "test.surface",
            "v1",
            "Divergence corpus registry coverage",
            0xD1,
        )
        .lab(|_config| base_semantics())
        .live(|_seed, _entropy| {
            let mut sem = base_semantics();
            sem.obligation_balance = ObligationBalanceRecord {
                reserved: 1,
                committed: 0,
                aborted: 0,
                leaked: 1,
                unresolved: 0,
                balanced: false,
            };
            sem
        })
        .run();

        let mut lab_provenance = result
            .lab
            .provenance
            .clone()
            .with_artifact_path("crashpack-divergence.registry.case.json")
            .with_repro_command("cargo test divergence.registry.case -- --nocapture");
        if lab_provenance.trace_fingerprint.is_none() {
            lab_provenance.trace_fingerprint = Some(0xC0DE_CAFE);
        }
        result.lab.provenance = lab_provenance;

        let mut live_provenance = result
            .live
            .provenance
            .clone()
            .with_artifact_path("artifacts/live/divergence.registry.case.json")
            .with_repro_command("cargo test divergence.registry.case -- --nocapture --live");
        if live_provenance.trace_fingerprint.is_none() {
            live_provenance.trace_fingerprint = Some(0xBEEF_BAAD);
        }
        result.live.provenance = live_provenance;
        result
    }

    #[test]
    fn divergence_artifact_bundle_uses_stable_bundle_layout() {
        init_test("divergence_artifact_bundle_uses_stable_bundle_layout");

        let bundle = DivergenceArtifactBundle::under("artifacts/differential/run-001");
        assert_eq!(
            bundle.differential_summary_path,
            "artifacts/differential/run-001/differential_summary.json"
        );
        assert_eq!(
            bundle.live_normalized_path,
            "artifacts/differential/run-001/live_normalized.json"
        );

        crate::test_complete!("divergence_artifact_bundle_uses_stable_bundle_layout");
    }

    #[test]
    fn divergence_retention_defaults_follow_policy_class() {
        init_test("divergence_retention_defaults_follow_policy_class");

        let full = DivergenceRetentionMetadata::for_policy_class(
            DifferentialPolicyClass::RuntimeSemanticBug,
        );
        assert_eq!(full.bundle_level, DivergenceBundleLevel::Full);
        assert_eq!(full.local_retention_days, 14);
        assert_eq!(full.ci_retention_days, 30);
        assert_eq!(full.redaction_mode, "metadata_only");

        let reduced = DivergenceRetentionMetadata::for_policy_class(
            DifferentialPolicyClass::UnsupportedSurface,
        );
        assert_eq!(reduced.bundle_level, DivergenceBundleLevel::Reduced);

        crate::test_complete!("divergence_retention_defaults_follow_policy_class");
    }

    #[test]
    fn divergence_corpus_entry_tracks_lineage_and_promotion_state() {
        init_test("divergence_corpus_entry_tracks_lineage_and_promotion_state");

        let result = make_dual_run_divergence_result();
        assert!(!result.passed(), "test fixture must produce a divergence");

        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "pilot_surface",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/test-run",
        )
        .with_first_seen_attempt(2, 1)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "prefix_shrinker", true, true),
        )
        .promote_to_regression("regression.test.surface.obligation_leak.seed_2a");

        assert_eq!(
            entry.policy_class,
            DifferentialPolicyClass::RuntimeSemanticBug
        );
        assert_eq!(entry.first_seen.runner_profile, "pilot_surface");
        assert_eq!(entry.first_seen.attempt_index, 2);
        assert_eq!(entry.first_seen.rerun_count, 1);
        assert_eq!(
            entry.minimization_lineage.shrink_status,
            DivergenceShrinkStatus::PreservedSemanticClass
        );
        assert_eq!(
            entry.regression_promotion_state,
            RegressionPromotionState::PromotedRegression
        );
        assert_eq!(
            entry.metadata.get("promoted_scenario_id"),
            Some(&"regression.test.surface.obligation_leak.seed_2a".to_string())
        );
        assert!(
            entry
                .mismatch_fields
                .contains(&"semantics.obligation_balance.balanced".to_string()),
            "mismatch fields should retain the semantic mismatch path"
        );
        assert!(
            entry
                .artifact_bundle
                .differential_repro_manifest_path
                .ends_with("differential_repro_manifest.json")
        );
        assert_eq!(
            entry.artifact_bundle.bundle_root,
            "artifacts/differential/test-run"
        );

        crate::test_complete!("divergence_corpus_entry_tracks_lineage_and_promotion_state");
    }

    #[test]
    fn divergence_registry_upsert_is_deterministic() {
        init_test("divergence_registry_upsert_is_deterministic");

        let result = make_dual_run_divergence_result();
        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "nightly",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/nightly-case",
        );

        let mut registry = DivergenceCorpusRegistry::new();
        registry.upsert(entry.clone());
        registry.upsert(entry.promote_to_regression("regression.promoted"));

        assert_eq!(registry.schema_version, DIVERGENCE_CORPUS_SCHEMA_VERSION);
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(
            registry.entries[0].regression_promotion_state,
            RegressionPromotionState::PromotedRegression
        );

        crate::test_complete!("divergence_registry_upsert_is_deterministic");
    }

    #[test]
    fn differential_bundle_artifacts_capture_repro_and_minimization_lineage() {
        init_test("differential_bundle_artifacts_capture_repro_and_minimization_lineage");

        let result = make_dual_run_divergence_result();
        let entry = DivergenceCorpusEntry::from_dual_run_result(
            &result,
            "nightly",
            "obligation_balance_mismatch",
            DifferentialPolicyClass::RuntimeSemanticBug,
            "artifacts/differential/nightly/divergence.registry.case",
        )
        .with_first_seen_attempt(3, 2)
        .with_minimization_lineage(
            DivergenceMinimizationLineage::from_seed_lineage(&result.seed_lineage)
                .with_minimized_seed(0x2A, "prefix_shrinker", true, true),
        )
        .promote_to_regression("regression.test.surface.obligation_leak.seed_2a");

        let bundle = DifferentialBundleArtifacts::from_dual_run_result(&entry, &result);
        assert_eq!(
            bundle.summary.schema_version,
            DIFFERENTIAL_SUMMARY_SCHEMA_VERSION
        );
        assert_eq!(
            bundle.summary.bundle_root,
            "artifacts/differential/nightly/divergence.registry.case"
        );
        assert_eq!(bundle.failures.failure_artifacts.len(), 2);
        assert_eq!(
            bundle.failures.failure_artifacts[0].runtime_kind,
            "lab".to_string()
        );
        assert_eq!(
            bundle.failures.failure_artifacts[0]
                .crashpack_link
                .as_ref()
                .map(|link| link.path.as_str()),
            Some("crashpack-divergence.registry.case.json")
        );
        assert_eq!(
            bundle.repro_manifest.promoted_scenario_id.as_deref(),
            Some("regression.test.surface.obligation_leak.seed_2a")
        );
        assert_eq!(
            bundle.repro_manifest.minimization_lineage.shrink_status,
            DivergenceShrinkStatus::PreservedSemanticClass
        );
        assert_eq!(
            bundle.repro_manifest.failure_artifacts_path,
            "artifacts/differential/nightly/divergence.registry.case/differential_failures.json"
        );
        assert!(
            bundle
                .repro_manifest
                .repro_commands
                .contains(&"cargo test divergence.registry.case -- --nocapture".to_string())
        );
        assert!(
            bundle
                .deviations
                .mismatches
                .iter()
                .any(|mismatch| mismatch.field == "semantics.obligation_balance.balanced")
        );

        crate::test_complete!(
            "differential_bundle_artifacts_capture_repro_and_minimization_lineage"
        );
    }

    #[test]
    fn inferred_crashpack_reference_requires_crashpack_like_path() {
        init_test("inferred_crashpack_reference_requires_crashpack_like_path");

        let result = make_dual_run_divergence_result();
        let lab_link = DifferentialCrashpackReference::from_provenance(&result.lab.provenance);
        let live_link = DifferentialCrashpackReference::from_provenance(&result.live.provenance);

        assert!(
            lab_link.is_some(),
            "crashpack-like lab artifact should infer linkage"
        );
        assert!(
            live_link.is_none(),
            "non-crashpack live artifact should not infer crashpack linkage"
        );

        crate::test_complete!("inferred_crashpack_reference_requires_crashpack_like_path");
    }
}
