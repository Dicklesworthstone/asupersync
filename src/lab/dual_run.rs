#![allow(missing_docs)]
//! Dual-run scenario types for lab-vs-live differential testing.
//!
//! This module implements the shared seed plumbing and replay metadata
//! types defined by the `DualRunScenarioSpec` contract
//! (`docs/lab_live_scenario_adapter_contract.md`).
//!
//! # Seed Flow
//!
//! ```text
//! DualRunScenarioSpec.seed_plan
//!     ├─→ Lab adapter: SeedPlan → LabConfig (inherit or override)
//!     └─→ Live adapter: SeedPlan → live runner seed (inherit or override)
//!
//! SeedPlan.canonical_seed + scenario_id → deterministic execution
//! SeedPlan.seed_lineage_id → artifact traceability
//! ```
//!
//! # Scenario Identity
//!
//! The system distinguishes two layers of identity:
//!
//! - **Scenario family**: the stable adversarial case (e.g., "cancel during
//!   two-phase send") — survives shrinking, promotion, and reruns.
//! - **Execution instance**: one concrete run of a family (seed + config
//!   snapshot) — unique per execution.
//!
//! This separation lets reruns, shrink steps, and regression promotion
//! carry the family identity cleanly while tracking which specific
//! execution produced evidence.
//!
//! # Replay Metadata
//!
//! [`ReplayMetadata`] captures both identity layers plus enough provenance
//! to rerun or explain a mismatch. It is emitted into normalized
//! observables and mismatch bundles.

use crate::lab::config::LabConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// Keep deterministic seed derivation available in normal library builds;
// `test_logging` is gated behind `test-internals` and is unavailable in wasm.
fn derive_component_seed(root: u64, component: &str) -> u64 {
    fnv1a_mix(root, component.as_bytes())
}

fn derive_scenario_seed(root: u64, scenario: &str) -> u64 {
    let tag = format!("scenario:{scenario}");
    fnv1a_mix(root, tag.as_bytes())
}

fn fnv1a_mix(root: u64, tag: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for byte in root.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    for &byte in tag {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ============================================================================
// Seed Mode and Replay Policy
// ============================================================================

/// How an adapter derives its effective seed from the canonical seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedMode {
    /// Use `canonical_seed` directly (or derived via `derive_scenario_seed`).
    Inherit,
    /// The adapter provides its own seed, overriding the canonical one.
    /// The override value is stored in `SeedPlan::lab_seed_override` or
    /// `SeedPlan::live_seed_override`.
    Override,
}

/// Replay strategy for seed-based reproducibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayPolicy {
    /// Run with exactly one seed. Simplest and most common.
    SingleSeed,
    /// Sweep a range of seeds derived from the canonical seed.
    /// Used for schedule exploration.
    SeedSweep,
    /// Replay from a previously captured trace bundle.
    /// Seed is informational; the trace dictates scheduling.
    ReplayBundle,
}

// ============================================================================
// Seed Plan
// ============================================================================

/// Deterministic seed plan for dual-run scenario execution.
///
/// This is the single source of truth for how both lab and live adapters
/// obtain their seeds. It enforces the contract rule: "The live adapter
/// may not silently pick a different seed than the lab adapter."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedPlan {
    /// Stable seed chosen by the scenario author.
    pub canonical_seed: u64,

    /// Stable token emitted into mismatch artifacts and repro commands.
    /// Typically the scenario_id or a human-readable lineage tag.
    pub seed_lineage_id: String,

    /// How the lab adapter derives its effective seed.
    pub lab_seed_mode: SeedMode,

    /// How the live adapter derives its effective seed.
    pub live_seed_mode: SeedMode,

    /// Replay strategy.
    pub replay_policy: ReplayPolicy,

    /// Explicit lab seed override (only used when `lab_seed_mode == Override`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lab_seed_override: Option<u64>,

    /// Explicit live seed override (only used when `live_seed_mode == Override`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_seed_override: Option<u64>,

    /// Optional entropy seed override. When `None`, entropy derives from
    /// the effective seed via `derive_component_seed(seed, "entropy")`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_seed_override: Option<u64>,
}

impl SeedPlan {
    /// Create a simple seed plan that inherits the canonical seed on both sides.
    #[must_use]
    pub fn inherit(canonical_seed: u64, lineage_id: impl Into<String>) -> Self {
        Self {
            canonical_seed,
            seed_lineage_id: lineage_id.into(),
            lab_seed_mode: SeedMode::Inherit,
            live_seed_mode: SeedMode::Inherit,
            replay_policy: ReplayPolicy::SingleSeed,
            lab_seed_override: None,
            live_seed_override: None,
            entropy_seed_override: None,
        }
    }

    /// Compute the effective seed for the lab adapter.
    #[must_use]
    pub fn effective_lab_seed(&self) -> u64 {
        match self.lab_seed_mode {
            SeedMode::Inherit => self.canonical_seed,
            SeedMode::Override => self.lab_seed_override.unwrap_or(self.canonical_seed),
        }
    }

    /// Compute the effective seed for the live adapter.
    #[must_use]
    pub fn effective_live_seed(&self) -> u64 {
        match self.live_seed_mode {
            SeedMode::Inherit => self.canonical_seed,
            SeedMode::Override => self.live_seed_override.unwrap_or(self.canonical_seed),
        }
    }

    /// Compute the effective entropy seed for an adapter.
    /// Uses the explicit override if set, otherwise derives from the
    /// given effective seed.
    #[must_use]
    pub fn effective_entropy_seed(&self, effective_seed: u64) -> u64 {
        self.entropy_seed_override
            .unwrap_or_else(|| derive_component_seed(effective_seed, "entropy"))
    }

    /// Build a [`LabConfig`] from this seed plan.
    ///
    /// Sets `seed` and `entropy_seed` according to the plan's lab mode.
    #[must_use]
    pub fn to_lab_config(&self) -> LabConfig {
        let seed = self.effective_lab_seed();
        let entropy = self.effective_entropy_seed(seed);
        LabConfig::new(seed).entropy_seed(entropy)
    }

    /// Generate seeds for a sweep of `count` derived seeds.
    ///
    /// Each seed is deterministically derived from the canonical seed
    /// using `derive_scenario_seed` with a sweep index tag.
    /// Only meaningful when `replay_policy == SeedSweep`.
    #[must_use]
    pub fn sweep_seeds(&self, count: usize) -> Vec<u64> {
        (0..count)
            .map(|i| {
                let tag = format!("sweep:{i}");
                derive_scenario_seed(self.canonical_seed, &tag)
            })
            .collect()
    }

    /// Set lab seed mode to override with the given seed.
    #[must_use]
    pub fn with_lab_override(mut self, seed: u64) -> Self {
        self.lab_seed_mode = SeedMode::Override;
        self.lab_seed_override = Some(seed);
        self
    }

    /// Set live seed mode to override with the given seed.
    #[must_use]
    pub fn with_live_override(mut self, seed: u64) -> Self {
        self.live_seed_mode = SeedMode::Override;
        self.live_seed_override = Some(seed);
        self
    }

    /// Set the replay policy.
    #[must_use]
    pub fn with_replay_policy(mut self, policy: ReplayPolicy) -> Self {
        self.replay_policy = policy;
        self
    }

    /// Set an explicit entropy seed override for both adapters.
    #[must_use]
    pub fn with_entropy_seed(mut self, seed: u64) -> Self {
        self.entropy_seed_override = Some(seed);
        self
    }
}

impl fmt::Display for SeedPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SeedPlan(canonical=0x{:X}, lineage={}, lab={:?}, live={:?}, policy={:?})",
            self.canonical_seed,
            self.seed_lineage_id,
            self.lab_seed_mode,
            self.live_seed_mode,
            self.replay_policy,
        )
    }
}

// ============================================================================
// Scenario Identity
// ============================================================================

/// Stable identifier for a scenario family.
///
/// A family represents the abstract adversarial case independent of any
/// particular execution. The same family survives shrinking, promotion
/// into regression suites, and reruns with different seeds.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScenarioFamilyId {
    /// Primary stable identifier (e.g., `"phase1.cancel.race.one_loser"`).
    pub id: String,
    /// Semantic surface being exercised (e.g., `"cancellation.race"`).
    pub surface_id: String,
    /// Versioned comparator contract for this surface.
    pub surface_contract_version: String,
}

impl ScenarioFamilyId {
    /// Create a new scenario family identifier.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        surface_id: impl Into<String>,
        contract_version: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            surface_id: surface_id.into(),
            surface_contract_version: contract_version.into(),
        }
    }
}

impl fmt::Display for ScenarioFamilyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}({})",
            self.id, self.surface_id, self.surface_contract_version
        )
    }
}

/// Unique identifier for a specific execution of a scenario family.
///
/// Combines the family identity with the concrete seed and a monotonic
/// run counter. Two executions of the same family with different seeds
/// produce different instance IDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExecutionInstanceId {
    /// Which scenario family this execution belongs to.
    pub family_id: String,
    /// Effective seed used for this execution.
    pub effective_seed: u64,
    /// Runtime kind that produced this instance.
    pub runtime_kind: RuntimeKind,
    /// Monotonic run index within a sweep (0 for single-seed runs).
    pub run_index: u32,
}

impl ExecutionInstanceId {
    /// Create a new execution instance ID for a single-seed lab run.
    #[must_use]
    pub fn lab(family_id: impl Into<String>, seed: u64) -> Self {
        Self {
            family_id: family_id.into(),
            effective_seed: seed,
            runtime_kind: RuntimeKind::Lab,
            run_index: 0,
        }
    }

    /// Create a new execution instance ID for a single-seed live run.
    #[must_use]
    pub fn live(family_id: impl Into<String>, seed: u64) -> Self {
        Self {
            family_id: family_id.into(),
            effective_seed: seed,
            runtime_kind: RuntimeKind::Live,
            run_index: 0,
        }
    }

    /// Set the run index (for sweep runs).
    #[must_use]
    pub fn with_run_index(mut self, index: u32) -> Self {
        self.run_index = index;
        self
    }

    /// Produce a stable string key for this instance.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}:{}:0x{:X}:{}",
            self.family_id, self.runtime_kind, self.effective_seed, self.run_index
        )
    }
}

impl fmt::Display for ExecutionInstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}@0x{:X}#{}]",
            self.family_id, self.runtime_kind, self.effective_seed, self.run_index
        )
    }
}

/// Which runtime produced an execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeKind {
    /// Deterministic lab runtime (`LabRuntime`).
    Lab,
    /// Live runtime (`RuntimeBuilder::current_thread()` for Phase 1).
    Live,
}

impl fmt::Display for RuntimeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lab => write!(f, "lab"),
            Self::Live => write!(f, "live"),
        }
    }
}

// ============================================================================
// Replay Metadata
// ============================================================================

/// Replay and provenance metadata for a single execution.
///
/// Captures everything needed to rerun or explain a mismatch:
/// family identity (what scenario?), instance identity (which run?),
/// effective seeds, trace evidence, and repro commands.
///
/// This maps to the `provenance` section of the normalized observable
/// schema (`lab-live-normalized-observable-v1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMetadata {
    /// Scenario family identity.
    pub family: ScenarioFamilyId,

    /// Execution instance identity.
    pub instance: ExecutionInstanceId,

    /// Seed plan that produced this execution.
    pub seed_plan: SeedPlan,

    /// Effective seed actually used by the adapter.
    pub effective_seed: u64,

    /// Effective entropy seed actually used.
    pub effective_entropy_seed: u64,

    /// Trace fingerprint from lab execution (Foata/Mazurkiewicz class).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_fingerprint: Option<u64>,

    /// Schedule hash from lab execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_hash: Option<u64>,

    /// Event hash from lab execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<u64>,

    /// Total events observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<u64>,

    /// Total scheduler steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub steps_total: Option<u64>,

    /// Path to artifact bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,

    /// Direct deterministic rerun command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repro_command: Option<String>,

    /// Hash of the config used for this execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,

    /// Live-side nondeterminism notes retained for later classification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nondeterminism_notes: Vec<String>,
}

impl ReplayMetadata {
    /// Create replay metadata for a lab execution from a seed plan.
    #[must_use]
    pub fn for_lab(family: ScenarioFamilyId, seed_plan: &SeedPlan) -> Self {
        let effective_seed = seed_plan.effective_lab_seed();
        let effective_entropy_seed = seed_plan.effective_entropy_seed(effective_seed);
        let instance = ExecutionInstanceId::lab(&family.id, effective_seed);

        Self {
            family,
            instance,
            seed_plan: seed_plan.clone(),
            effective_seed,
            effective_entropy_seed,
            trace_fingerprint: None,
            schedule_hash: None,
            event_hash: None,
            event_count: None,
            steps_total: None,
            artifact_path: None,
            repro_command: None,
            config_hash: None,
            nondeterminism_notes: Vec::new(),
        }
    }

    /// Create replay metadata for a live execution from a seed plan.
    #[must_use]
    pub fn for_live(family: ScenarioFamilyId, seed_plan: &SeedPlan) -> Self {
        let effective_seed = seed_plan.effective_live_seed();
        let effective_entropy_seed = seed_plan.effective_entropy_seed(effective_seed);
        let instance = ExecutionInstanceId::live(&family.id, effective_seed);

        Self {
            family,
            instance,
            seed_plan: seed_plan.clone(),
            effective_seed,
            effective_entropy_seed,
            trace_fingerprint: None,
            schedule_hash: None,
            event_hash: None,
            event_count: None,
            steps_total: None,
            artifact_path: None,
            repro_command: None,
            config_hash: None,
            nondeterminism_notes: Vec::new(),
        }
    }

    /// Update from a `LabRunReport`'s trace certificate.
    #[must_use]
    pub fn with_lab_report(
        mut self,
        trace_fingerprint: u64,
        event_hash: u64,
        event_count: u64,
        schedule_hash: u64,
        steps_total: u64,
    ) -> Self {
        self.trace_fingerprint = Some(trace_fingerprint);
        self.event_hash = Some(event_hash);
        self.event_count = Some(event_count);
        self.schedule_hash = Some(schedule_hash);
        self.steps_total = Some(steps_total);
        self
    }

    /// Set the repro command.
    #[must_use]
    pub fn with_repro_command(mut self, cmd: impl Into<String>) -> Self {
        self.repro_command = Some(cmd.into());
        self
    }

    /// Set the artifact path.
    #[must_use]
    pub fn with_artifact_path(mut self, path: impl Into<String>) -> Self {
        self.artifact_path = Some(path.into());
        self
    }

    /// Attach nondeterminism notes gathered during the execution.
    #[must_use]
    pub fn with_nondeterminism_notes(mut self, notes: Vec<String>) -> Self {
        self.nondeterminism_notes = notes;
        self
    }

    /// Generate a default repro command for this execution.
    #[must_use]
    pub fn default_repro_command(&self) -> String {
        format!(
            "ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
            self.effective_seed, self.family.id
        )
    }
}

// ============================================================================
// Seed Lineage Record
// ============================================================================

/// Complete record of seeds used across a dual-run pair.
///
/// Emitted into mismatch bundles and summary records so that every
/// seed decision is auditable. Satisfies the contract requirement:
/// "Seed rewrites must be explicit in `seed_plan`, never hidden."
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeedLineageRecord {
    /// Seed lineage identifier from the plan.
    pub seed_lineage_id: String,

    /// Canonical seed from the plan.
    pub canonical_seed: u64,

    /// Effective lab seed actually used.
    pub lab_effective_seed: u64,

    /// Effective live seed actually used.
    pub live_effective_seed: u64,

    /// Lab seed mode.
    pub lab_seed_mode: SeedMode,

    /// Live seed mode.
    pub live_seed_mode: SeedMode,

    /// Effective lab entropy seed.
    pub lab_entropy_seed: u64,

    /// Effective live entropy seed.
    pub live_entropy_seed: u64,

    /// Replay policy used.
    pub replay_policy: ReplayPolicy,

    /// Whether lab and live used the same effective seed.
    pub seeds_match: bool,

    /// Additional audit annotations.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl SeedLineageRecord {
    /// Build a lineage record from a seed plan.
    #[must_use]
    pub fn from_plan(plan: &SeedPlan) -> Self {
        let lab_seed = plan.effective_lab_seed();
        let live_seed = plan.effective_live_seed();
        let lab_entropy = plan.effective_entropy_seed(lab_seed);
        let live_entropy = plan.effective_entropy_seed(live_seed);

        Self {
            seed_lineage_id: plan.seed_lineage_id.clone(),
            canonical_seed: plan.canonical_seed,
            lab_effective_seed: lab_seed,
            live_effective_seed: live_seed,
            lab_seed_mode: plan.lab_seed_mode,
            live_seed_mode: plan.live_seed_mode,
            lab_entropy_seed: lab_entropy,
            live_entropy_seed: live_entropy,
            replay_policy: plan.replay_policy,
            seeds_match: lab_seed == live_seed,
            annotations: BTreeMap::new(),
        }
    }

    /// Add an audit annotation.
    #[must_use]
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }
}

// ============================================================================
// Dual-Run Scenario Spec (partial — shared seed/replay fields only)
// ============================================================================

/// Schema version for the dual-run scenario spec.
pub const DUAL_RUN_SCHEMA_VERSION: &str = "lab-live-scenario-spec-v1";

/// Rollout phase for a dual-run scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Phase 1: cancellation, combinators, channels, obligations, region
    /// close, sync primitives. Current-thread live runner only.
    #[serde(rename = "Phase 1")]
    Phase1,
    /// Phase 2: timers, virtualized transport.
    #[serde(rename = "Phase 2")]
    Phase2,
    /// Phase 3: actor/supervision, HTTP/gRPC on captured boundaries.
    #[serde(rename = "Phase 3")]
    Phase3,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Phase1 => write!(f, "Phase 1"),
            Self::Phase2 => write!(f, "Phase 2"),
            Self::Phase3 => write!(f, "Phase 3"),
        }
    }
}

/// Core identity and seed fields of a `DualRunScenarioSpec`.
///
/// This struct captures the seed-plan-aware subset of the full
/// `DualRunScenarioSpec` contract. The full contract includes
/// participants, operations, perturbations, expectations, and bindings
/// which are built by downstream beads (`asupersync-2a6k9.2.4`+).
///
/// This bead (`asupersync-2a6k9.2.3`) makes seeds, parameters, and
/// replay metadata first-class across both execution paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualRunScenarioIdentity {
    /// Stable contract discriminator.
    pub schema_version: String,

    /// Stable case identifier reused across lab and live.
    pub scenario_id: String,

    /// Semantic surface being exercised.
    pub surface_id: String,

    /// Versioned comparator contract.
    pub surface_contract_version: String,

    /// Human-readable scenario meaning.
    pub description: String,

    /// Rollout phase from the scope matrix.
    pub phase: Phase,

    /// Deterministic seed and rerun lineage.
    pub seed_plan: SeedPlan,

    /// Ownership, tags, bead lineage.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl DualRunScenarioIdentity {
    /// Create a Phase 1 scenario identity with inherited seeds.
    #[must_use]
    pub fn phase1(
        scenario_id: impl Into<String>,
        surface_id: impl Into<String>,
        contract_version: impl Into<String>,
        description: impl Into<String>,
        canonical_seed: u64,
    ) -> Self {
        let sid = scenario_id.into();
        Self {
            schema_version: DUAL_RUN_SCHEMA_VERSION.to_string(),
            scenario_id: sid.clone(),
            surface_id: surface_id.into(),
            surface_contract_version: contract_version.into(),
            description: description.into(),
            phase: Phase::Phase1,
            seed_plan: SeedPlan::inherit(canonical_seed, sid),
            metadata: BTreeMap::new(),
        }
    }

    /// Extract the scenario family identity.
    #[must_use]
    pub fn family_id(&self) -> ScenarioFamilyId {
        ScenarioFamilyId::new(
            &self.scenario_id,
            &self.surface_id,
            &self.surface_contract_version,
        )
    }

    /// Build lab replay metadata from this identity.
    #[must_use]
    pub fn lab_replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata::for_lab(self.family_id(), &self.seed_plan)
    }

    /// Build live replay metadata from this identity.
    #[must_use]
    pub fn live_replay_metadata(&self) -> ReplayMetadata {
        ReplayMetadata::for_live(self.family_id(), &self.seed_plan)
    }

    /// Build a seed lineage record for audit.
    #[must_use]
    pub fn seed_lineage(&self) -> SeedLineageRecord {
        SeedLineageRecord::from_plan(&self.seed_plan)
    }

    /// Build a `LabConfig` from this identity's seed plan.
    #[must_use]
    pub fn to_lab_config(&self) -> LabConfig {
        self.seed_plan.to_lab_config()
    }

    /// Set a metadata annotation.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Override the seed plan.
    #[must_use]
    pub fn with_seed_plan(mut self, plan: SeedPlan) -> Self {
        self.seed_plan = plan;
        self
    }
}

// ============================================================================
// Normalized Observable Schema (lab-live-normalized-observable-v1)
// ============================================================================

/// Schema version for normalized observables.
pub const NORMALIZED_OBSERVABLE_SCHEMA_VERSION: &str = "lab-live-normalized-observable-v1";

/// Outcome class for the terminal result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeClass {
    /// Successful completion.
    Ok,
    /// Failed with an error.
    Err,
    /// Cancelled via the cancellation protocol.
    Cancelled,
    /// Panicked during execution.
    Panicked,
}

impl fmt::Display for OutcomeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::Err => write!(f, "err"),
            Self::Cancelled => write!(f, "cancelled"),
            Self::Panicked => write!(f, "panicked"),
        }
    }
}

/// Terminal phase of the cancellation protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum CancelTerminalPhase {
    NotCancelled,
    CancelRequested,
    Cancelling,
    Finalizing,
    Completed,
}

/// Loser drain status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainStatus {
    /// No drain was needed for this participant.
    NotApplicable,
    /// All losers were fully drained.
    Complete,
    /// Some losers were not fully drained.
    Incomplete,
}

/// Region close state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionState {
    /// Region is accepting new work.
    Open,
    /// Region close has been initiated.
    Closing,
    /// Region is draining children.
    Draining,
    /// Region finalizers are running.
    Finalizing,
    /// Region has reached quiescence.
    Closed,
}

/// Comparison tolerance for resource counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterTolerance {
    /// Counts must match exactly.
    Exact,
    /// Observed count must be at least the expected value.
    AtLeast,
    /// Observed count must be at most the expected value.
    AtMost,
    /// Counter comparison is not supported for this surface.
    Unsupported,
}

/// Terminal outcome subrecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct TerminalOutcome {
    pub class: OutcomeClass,
    pub severity: OutcomeClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancel_reason_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub panic_class: Option<String>,
}

impl TerminalOutcome {
    /// Create an Ok terminal outcome.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            class: OutcomeClass::Ok,
            severity: OutcomeClass::Ok,
            surface_result: None,
            error_class: None,
            cancel_reason_class: None,
            panic_class: None,
        }
    }

    /// Create a Cancelled terminal outcome.
    #[must_use]
    pub fn cancelled(reason_class: impl Into<String>) -> Self {
        Self {
            class: OutcomeClass::Cancelled,
            severity: OutcomeClass::Cancelled,
            surface_result: None,
            error_class: None,
            cancel_reason_class: Some(reason_class.into()),
            panic_class: None,
        }
    }

    /// Create an Err terminal outcome.
    #[must_use]
    pub fn err(error_class: impl Into<String>) -> Self {
        Self {
            class: OutcomeClass::Err,
            severity: OutcomeClass::Err,
            surface_result: None,
            error_class: Some(error_class.into()),
            cancel_reason_class: None,
            panic_class: None,
        }
    }
}

/// Cancellation subrecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[allow(missing_docs)]
pub struct CancellationRecord {
    pub requested: bool,
    pub acknowledged: bool,
    pub cleanup_completed: bool,
    pub finalization_completed: bool,
    pub terminal_phase: CancelTerminalPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_observed: Option<bool>,
}

impl CancellationRecord {
    /// No cancellation occurred.
    #[must_use]
    pub fn none() -> Self {
        Self {
            requested: false,
            acknowledged: false,
            cleanup_completed: false,
            finalization_completed: false,
            terminal_phase: CancelTerminalPhase::NotCancelled,
            checkpoint_observed: None,
        }
    }

    /// Full cancellation protocol completed.
    #[must_use]
    pub fn completed() -> Self {
        Self {
            requested: true,
            acknowledged: true,
            cleanup_completed: true,
            finalization_completed: true,
            terminal_phase: CancelTerminalPhase::Completed,
            checkpoint_observed: Some(true),
        }
    }
}

/// Loser drain subrecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct LoserDrainRecord {
    pub applicable: bool,
    pub expected_losers: u32,
    pub drained_losers: u32,
    pub status: DrainStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl LoserDrainRecord {
    /// No loser drain applicable.
    #[must_use]
    pub fn not_applicable() -> Self {
        Self {
            applicable: false,
            expected_losers: 0,
            drained_losers: 0,
            status: DrainStatus::NotApplicable,
            evidence: None,
        }
    }

    /// All losers drained.
    #[must_use]
    pub fn complete(expected: u32) -> Self {
        Self {
            applicable: true,
            expected_losers: expected,
            drained_losers: expected,
            status: DrainStatus::Complete,
            evidence: None,
        }
    }
}

/// Region close subrecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct RegionCloseRecord {
    pub root_state: RegionState,
    pub quiescent: bool,
    pub live_children: u32,
    pub finalizers_pending: u32,
    pub close_completed: bool,
}

impl RegionCloseRecord {
    /// Region closed to quiescence.
    #[must_use]
    pub fn quiescent() -> Self {
        Self {
            root_state: RegionState::Closed,
            quiescent: true,
            live_children: 0,
            finalizers_pending: 0,
            close_completed: true,
        }
    }
}

/// Obligation balance subrecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ObligationBalanceRecord {
    pub reserved: u32,
    pub committed: u32,
    pub aborted: u32,
    pub leaked: u32,
    pub unresolved: u32,
    pub balanced: bool,
}

impl ObligationBalanceRecord {
    /// Fully balanced (no leaks, no unresolved).
    #[must_use]
    pub fn balanced(reserved: u32, committed: u32, aborted: u32) -> Self {
        Self {
            reserved,
            committed,
            aborted,
            leaked: 0,
            unresolved: 0,
            balanced: true,
        }
    }

    /// Zero obligations.
    #[must_use]
    pub fn zero() -> Self {
        Self::balanced(0, 0, 0)
    }

    /// Recompute `balanced` and `unresolved` from the other fields.
    #[must_use]
    pub fn recompute(mut self) -> Self {
        let terminal = self
            .committed
            .saturating_add(self.aborted)
            .saturating_add(self.leaked);
        self.unresolved = self.reserved.saturating_sub(terminal);
        self.balanced = self.leaked == 0 && self.unresolved == 0;
        self
    }
}

/// Resource surface subrecord.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct ResourceSurfaceRecord {
    pub contract_scope: String,
    #[serde(default)]
    pub counters: BTreeMap<String, i64>,
    #[serde(default)]
    pub tolerances: BTreeMap<String, CounterTolerance>,
}

impl ResourceSurfaceRecord {
    /// Create a resource surface with no counters.
    #[must_use]
    pub fn empty(scope: impl Into<String>) -> Self {
        Self {
            contract_scope: scope.into(),
            counters: BTreeMap::new(),
            tolerances: BTreeMap::new(),
        }
    }

    /// Add an exact counter.
    #[must_use]
    pub fn with_counter(mut self, name: impl Into<String>, value: i64) -> Self {
        let n = name.into();
        self.counters.insert(n.clone(), value);
        self.tolerances.insert(n, CounterTolerance::Exact);
        self
    }

    /// Add a counter with a specific tolerance.
    #[must_use]
    pub fn with_counter_tolerance(
        mut self,
        name: impl Into<String>,
        value: i64,
        tolerance: CounterTolerance,
    ) -> Self {
        let n = name.into();
        self.counters.insert(n.clone(), value);
        self.tolerances.insert(n, tolerance);
        self
    }
}

/// Semantic section of a normalized observable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct NormalizedSemantics {
    pub terminal_outcome: TerminalOutcome,
    pub cancellation: CancellationRecord,
    pub loser_drain: LoserDrainRecord,
    pub region_close: RegionCloseRecord,
    pub obligation_balance: ObligationBalanceRecord,
    pub resource_surface: ResourceSurfaceRecord,
}

/// Complete normalized observable record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct NormalizedObservable {
    pub schema_version: String,
    pub scenario_id: String,
    pub surface_id: String,
    pub surface_contract_version: String,
    pub runtime_kind: RuntimeKind,
    pub semantics: NormalizedSemantics,
    pub provenance: ReplayMetadata,
}

impl NormalizedObservable {
    /// Create a normalized observable from identity and semantics.
    #[must_use]
    pub fn new(
        identity: &DualRunScenarioIdentity,
        runtime_kind: RuntimeKind,
        semantics: NormalizedSemantics,
        provenance: ReplayMetadata,
    ) -> Self {
        Self {
            schema_version: NORMALIZED_OBSERVABLE_SCHEMA_VERSION.to_string(),
            scenario_id: identity.scenario_id.clone(),
            surface_id: identity.surface_id.clone(),
            surface_contract_version: identity.surface_contract_version.clone(),
            runtime_kind,
            semantics,
            provenance,
        }
    }
}

// ============================================================================
// Witness / Assertion Helpers
// ============================================================================

/// A single mismatch between lab and live observables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticMismatch {
    /// Dot-separated path to the mismatched field.
    pub field: String,
    /// Description of the mismatch.
    pub description: String,
    /// Lab-side value (display representation).
    pub lab_value: String,
    /// Live-side value (display representation).
    pub live_value: String,
}

impl fmt::Display for SemanticMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (lab={}, live={})",
            self.field, self.description, self.lab_value, self.live_value
        )
    }
}

/// Result of comparing two normalized observables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonVerdict {
    /// Scenario identity.
    pub scenario_id: String,
    /// Surface identity.
    pub surface_id: String,
    /// Whether the comparison passed (no semantic mismatches).
    pub passed: bool,
    /// Semantic mismatches found.
    pub mismatches: Vec<SemanticMismatch>,
    /// Seed lineage record for audit.
    pub seed_lineage: SeedLineageRecord,
}

impl ComparisonVerdict {
    /// Whether the verdict indicates semantic equivalence.
    #[must_use]
    pub fn is_equivalent(&self) -> bool {
        self.passed
    }

    /// Format a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        if self.passed {
            format!(
                "PASS: {} on {} (seed lineage: {})",
                self.scenario_id, self.surface_id, self.seed_lineage.seed_lineage_id
            )
        } else {
            let mismatch_list: Vec<String> =
                self.mismatches.iter().map(ToString::to_string).collect();
            format!(
                "FAIL: {} on {} — {} mismatch(es):\n  {}",
                self.scenario_id,
                self.surface_id,
                self.mismatches.len(),
                mismatch_list.join("\n  ")
            )
        }
    }

    /// Format a human-readable summary augmented with capture provenance.
    #[must_use]
    pub fn summary_with_manifests(
        &self,
        lab_manifest: Option<&CaptureManifest>,
        live_manifest: Option<&CaptureManifest>,
    ) -> String {
        if self.passed {
            return self.summary();
        }

        let mismatch_list: Vec<String> = self
            .mismatches
            .iter()
            .map(|mismatch| {
                let mut line = mismatch.to_string();
                let mut capture_notes = Vec::new();
                if let Some(lab_capture) = lab_manifest
                    .and_then(|manifest| manifest.describe_field_capture(&mismatch.field))
                {
                    capture_notes.push(format!("lab_capture={lab_capture}"));
                }
                if let Some(live_capture) = live_manifest
                    .and_then(|manifest| manifest.describe_field_capture(&mismatch.field))
                {
                    capture_notes.push(format!("live_capture={live_capture}"));
                }
                if !capture_notes.is_empty() {
                    line.push_str(" [");
                    line.push_str(&capture_notes.join("; "));
                    line.push(']');
                }
                line
            })
            .collect();

        format!(
            "FAIL: {} on {} — {} mismatch(es):\n  {}",
            self.scenario_id,
            self.surface_id,
            self.mismatches.len(),
            mismatch_list.join("\n  ")
        )
    }
}

impl fmt::Display for ComparisonVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Provisional mismatch class prior to any automatic reruns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionalDivergenceClass {
    /// No semantic mismatch or invariant failure was observed.
    Pass,
    /// Surface is outside the current supported comparison envelope.
    UnsupportedSurface,
    /// The compared artifacts are not on the same schema contract.
    ArtifactSchemaViolation,
    /// The surface is conceptually valid, but current evidence is insufficient.
    InsufficientObservability,
    /// Only scheduler/provenance noise remains after semantic comparison.
    SchedulerNoiseSuspected,
    /// A semantic mismatch on an admitted surface still needs reruns.
    SemanticMismatchAdmittedSurface,
    /// The live side already shows a hard contract break.
    HardContractBreak,
}

impl fmt::Display for ProvisionalDivergenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::UnsupportedSurface => write!(f, "unsupported_surface"),
            Self::ArtifactSchemaViolation => write!(f, "artifact_schema_violation"),
            Self::InsufficientObservability => write!(f, "insufficient_observability"),
            Self::SchedulerNoiseSuspected => write!(f, "scheduler_noise_suspected"),
            Self::SemanticMismatchAdmittedSurface => {
                write!(f, "semantic_mismatch_admitted_surface")
            }
            Self::HardContractBreak => write!(f, "hard_contract_break"),
        }
    }
}

/// Final divergence class from the published taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalDivergenceClass {
    RuntimeSemanticBug,
    LabModelOrMappingBug,
    IrreproducibleDivergence,
    UnsupportedSurface,
    ArtifactSchemaViolation,
    InsufficientObservability,
    SchedulerNoiseSuspected,
}

impl fmt::Display for FinalDivergenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeSemanticBug => write!(f, "runtime_semantic_bug"),
            Self::LabModelOrMappingBug => write!(f, "lab_model_or_mapping_bug"),
            Self::IrreproducibleDivergence => write!(f, "irreproducible_divergence"),
            Self::UnsupportedSurface => write!(f, "unsupported_surface"),
            Self::ArtifactSchemaViolation => write!(f, "artifact_schema_violation"),
            Self::InsufficientObservability => write!(f, "insufficient_observability"),
            Self::SchedulerNoiseSuspected => write!(f, "scheduler_noise_suspected"),
        }
    }
}

/// Time/noise class emitted by the mismatch policy layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimePolicyClass {
    NotApplicable,
    ProvenanceOnlyTime,
    SchedulerNoiseSignal,
    QualifiedTime,
    UnsupportedTimeSurface,
    SemanticTime,
    PolicyViolation,
}

impl fmt::Display for TimePolicyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotApplicable => write!(f, "not_applicable"),
            Self::ProvenanceOnlyTime => write!(f, "provenance_only_time"),
            Self::SchedulerNoiseSignal => write!(f, "scheduler_noise_signal"),
            Self::QualifiedTime => write!(f, "qualified_time"),
            Self::UnsupportedTimeSurface => write!(f, "unsupported_time_surface"),
            Self::SemanticTime => write!(f, "semantic_time"),
            Self::PolicyViolation => write!(f, "policy_violation"),
        }
    }
}

/// Which scheduler/provenance drift triggered a noise classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerNoiseClass {
    None,
    NondeterminismNotesOnly,
    ScheduleHashDrift,
    EventHashDrift,
    EventCountDrift,
    ProvenanceDrift,
}

impl fmt::Display for SchedulerNoiseClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::NondeterminismNotesOnly => write!(f, "nondeterminism_notes_only"),
            Self::ScheduleHashDrift => write!(f, "schedule_hash_drift"),
            Self::EventHashDrift => write!(f, "event_hash_drift"),
            Self::EventCountDrift => write!(f, "event_count_drift"),
            Self::ProvenanceDrift => write!(f, "provenance_drift"),
        }
    }
}

/// Automatic rerun plan for a provisional differential classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RerunDecision {
    None,
    LiveConfirmations { additional_runs: u8 },
    DeterministicLabReplayAndLiveConfirmations { additional_live_runs: u8 },
    ConfirmationIfRicherInstrumentationEnabled { additional_runs: u8 },
}

impl fmt::Display for RerunDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::LiveConfirmations { additional_runs } => {
                write!(f, "live_confirmations(+{additional_runs})")
            }
            Self::DeterministicLabReplayAndLiveConfirmations {
                additional_live_runs,
            } => write!(
                f,
                "deterministic_lab_replay_and_live_confirmations(+{additional_live_runs} live)"
            ),
            Self::ConfirmationIfRicherInstrumentationEnabled { additional_runs } => write!(
                f,
                "confirmation_if_richer_instrumentation_enabled(+{additional_runs})"
            ),
        }
    }
}

/// Policy output layered on top of the raw semantic comparison result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialPolicyOutcome {
    /// Provisional class before any automatic reruns are executed.
    pub provisional_class: ProvisionalDivergenceClass,
    /// Whether the harness should schedule reruns for classification.
    pub rerun_decision: RerunDecision,
    /// Final class suggestion when policy can decide immediately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_final_class: Option<FinalDivergenceClass>,
    /// Time/noise interpretation from the normalization policy.
    pub time_policy_class: TimePolicyClass,
    /// Which scheduler/provenance signal was recognized.
    pub scheduler_noise_class: SchedulerNoiseClass,
    /// Optional reason for suppression or immediate rejection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_reason: Option<String>,
    /// Human-readable explanation for logs and summaries.
    pub explanation: String,
}

impl DifferentialPolicyOutcome {
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = vec![
            format!("provisional_class={}", self.provisional_class),
            format!("rerun_decision={}", self.rerun_decision),
            format!("time_policy_class={}", self.time_policy_class),
            format!("scheduler_noise_class={}", self.scheduler_noise_class),
        ];
        if let Some(final_class) = self.suggested_final_class {
            parts.push(format!("suggested_final_class={final_class}"));
        }
        if let Some(reason) = &self.suppression_reason {
            parts.push(format!("suppression_reason={reason}"));
        }
        parts.push(self.explanation.clone());
        parts.join("; ")
    }
}

impl fmt::Display for DifferentialPolicyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Compare two normalized observables and produce a verdict.
///
/// Compares all semantic fields. Provenance is recorded but not compared
/// (audit-only by default).
#[must_use]
pub fn compare_observables(
    lab: &NormalizedObservable,
    live: &NormalizedObservable,
    seed_lineage: SeedLineageRecord,
) -> ComparisonVerdict {
    let mut mismatches = Vec::new();

    // Schema version
    if lab.schema_version != live.schema_version {
        mismatches.push(SemanticMismatch {
            field: "schema_version".to_string(),
            description: "Schema version mismatch".to_string(),
            lab_value: lab.schema_version.clone(),
            live_value: live.schema_version.clone(),
        });
    }

    // Scenario identity
    if lab.scenario_id != live.scenario_id {
        mismatches.push(SemanticMismatch {
            field: "scenario_id".to_string(),
            description: "Scenario ID mismatch".to_string(),
            lab_value: lab.scenario_id.clone(),
            live_value: live.scenario_id.clone(),
        });
    }
    if lab.surface_id != live.surface_id {
        mismatches.push(SemanticMismatch {
            field: "surface_id".to_string(),
            description: "Surface ID mismatch".to_string(),
            lab_value: lab.surface_id.clone(),
            live_value: live.surface_id.clone(),
        });
    }
    if lab.surface_contract_version != live.surface_contract_version {
        mismatches.push(SemanticMismatch {
            field: "surface_contract_version".to_string(),
            description: "Surface contract version mismatch".to_string(),
            lab_value: lab.surface_contract_version.clone(),
            live_value: live.surface_contract_version.clone(),
        });
    }

    // Terminal outcome
    compare_terminal_outcome(
        &lab.semantics.terminal_outcome,
        &live.semantics.terminal_outcome,
        &mut mismatches,
    );

    // Cancellation
    compare_cancellation(
        &lab.semantics.cancellation,
        &live.semantics.cancellation,
        &mut mismatches,
    );

    // Loser drain
    compare_loser_drain(
        &lab.semantics.loser_drain,
        &live.semantics.loser_drain,
        &mut mismatches,
    );

    // Region close
    compare_region_close(
        &lab.semantics.region_close,
        &live.semantics.region_close,
        &mut mismatches,
    );

    // Obligation balance
    compare_obligation_balance(
        &lab.semantics.obligation_balance,
        &live.semantics.obligation_balance,
        &mut mismatches,
    );

    // Resource surface
    compare_resource_surface(
        &lab.semantics.resource_surface,
        &live.semantics.resource_surface,
        &mut mismatches,
    );

    ComparisonVerdict {
        scenario_id: lab.scenario_id.clone(),
        surface_id: lab.surface_id.clone(),
        passed: mismatches.is_empty(),
        mismatches,
        seed_lineage,
    }
}

fn compare_terminal_outcome(
    lab: &TerminalOutcome,
    live: &TerminalOutcome,
    mismatches: &mut Vec<SemanticMismatch>,
) {
    if lab.class != live.class {
        mismatches.push(SemanticMismatch {
            field: "semantics.terminal_outcome.class".to_string(),
            description: "Terminal outcome class mismatch".to_string(),
            lab_value: format!("{}", lab.class),
            live_value: format!("{}", live.class),
        });
    }
    if lab.severity != live.severity {
        mismatches.push(SemanticMismatch {
            field: "semantics.terminal_outcome.severity".to_string(),
            description: "Terminal outcome severity mismatch".to_string(),
            lab_value: format!("{}", lab.severity),
            live_value: format!("{}", live.severity),
        });
    }
    if lab.surface_result != live.surface_result {
        mismatches.push(SemanticMismatch {
            field: "semantics.terminal_outcome.surface_result".to_string(),
            description: "Surface result mismatch".to_string(),
            lab_value: format!("{:?}", lab.surface_result),
            live_value: format!("{:?}", live.surface_result),
        });
    }
    if lab.error_class != live.error_class {
        mismatches.push(SemanticMismatch {
            field: "semantics.terminal_outcome.error_class".to_string(),
            description: "Error class mismatch".to_string(),
            lab_value: format!("{:?}", lab.error_class),
            live_value: format!("{:?}", live.error_class),
        });
    }
    if lab.cancel_reason_class != live.cancel_reason_class {
        mismatches.push(SemanticMismatch {
            field: "semantics.terminal_outcome.cancel_reason_class".to_string(),
            description: "Cancel reason class mismatch".to_string(),
            lab_value: format!("{:?}", lab.cancel_reason_class),
            live_value: format!("{:?}", live.cancel_reason_class),
        });
    }
    if lab.panic_class != live.panic_class {
        mismatches.push(SemanticMismatch {
            field: "semantics.terminal_outcome.panic_class".to_string(),
            description: "Panic class mismatch".to_string(),
            lab_value: format!("{:?}", lab.panic_class),
            live_value: format!("{:?}", live.panic_class),
        });
    }
}

fn compare_cancellation(
    lab: &CancellationRecord,
    live: &CancellationRecord,
    mismatches: &mut Vec<SemanticMismatch>,
) {
    let fields = [
        ("requested", lab.requested, live.requested),
        ("acknowledged", lab.acknowledged, live.acknowledged),
        (
            "cleanup_completed",
            lab.cleanup_completed,
            live.cleanup_completed,
        ),
        (
            "finalization_completed",
            lab.finalization_completed,
            live.finalization_completed,
        ),
    ];
    for (name, lab_val, live_val) in fields {
        if lab_val != live_val {
            mismatches.push(SemanticMismatch {
                field: format!("semantics.cancellation.{name}"),
                description: format!("Cancellation {name} mismatch"),
                lab_value: format!("{lab_val}"),
                live_value: format!("{live_val}"),
            });
        }
    }
    if lab.terminal_phase != live.terminal_phase {
        mismatches.push(SemanticMismatch {
            field: "semantics.cancellation.terminal_phase".to_string(),
            description: "Cancellation terminal phase mismatch".to_string(),
            lab_value: format!("{:?}", lab.terminal_phase),
            live_value: format!("{:?}", live.terminal_phase),
        });
    }
    // checkpoint_observed: only compare if both sides report it
    if let (Some(lab_cp), Some(live_cp)) = (lab.checkpoint_observed, live.checkpoint_observed) {
        if lab_cp != live_cp {
            mismatches.push(SemanticMismatch {
                field: "semantics.cancellation.checkpoint_observed".to_string(),
                description: "Checkpoint observed mismatch".to_string(),
                lab_value: format!("{lab_cp}"),
                live_value: format!("{live_cp}"),
            });
        }
    }
}

fn compare_loser_drain(
    lab: &LoserDrainRecord,
    live: &LoserDrainRecord,
    mismatches: &mut Vec<SemanticMismatch>,
) {
    if lab.status != live.status {
        mismatches.push(SemanticMismatch {
            field: "semantics.loser_drain.status".to_string(),
            description: "Loser drain status mismatch".to_string(),
            lab_value: format!("{:?}", lab.status),
            live_value: format!("{:?}", live.status),
        });
    }
    if lab.applicable != live.applicable {
        mismatches.push(SemanticMismatch {
            field: "semantics.loser_drain.applicable".to_string(),
            description: "Loser drain applicability mismatch".to_string(),
            lab_value: format!("{}", lab.applicable),
            live_value: format!("{}", live.applicable),
        });
    }
    if lab.expected_losers != live.expected_losers {
        mismatches.push(SemanticMismatch {
            field: "semantics.loser_drain.expected_losers".to_string(),
            description: "Expected losers count mismatch".to_string(),
            lab_value: format!("{}", lab.expected_losers),
            live_value: format!("{}", live.expected_losers),
        });
    }
    if lab.drained_losers != live.drained_losers {
        mismatches.push(SemanticMismatch {
            field: "semantics.loser_drain.drained_losers".to_string(),
            description: "Drained losers count mismatch".to_string(),
            lab_value: format!("{}", lab.drained_losers),
            live_value: format!("{}", live.drained_losers),
        });
    }
}

fn compare_region_close(
    lab: &RegionCloseRecord,
    live: &RegionCloseRecord,
    mismatches: &mut Vec<SemanticMismatch>,
) {
    if lab.root_state != live.root_state {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.root_state".to_string(),
            description: "Region root state mismatch".to_string(),
            lab_value: format!("{:?}", lab.root_state),
            live_value: format!("{:?}", live.root_state),
        });
    }
    if lab.quiescent != live.quiescent {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.quiescent".to_string(),
            description: "Region quiescence mismatch".to_string(),
            lab_value: format!("{}", lab.quiescent),
            live_value: format!("{}", live.quiescent),
        });
    }
    if lab.close_completed != live.close_completed {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.close_completed".to_string(),
            description: "Region close completed mismatch".to_string(),
            lab_value: format!("{}", lab.close_completed),
            live_value: format!("{}", live.close_completed),
        });
    }
    if lab.live_children != live.live_children {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.live_children".to_string(),
            description: "Region live child count mismatch".to_string(),
            lab_value: format!("{}", lab.live_children),
            live_value: format!("{}", live.live_children),
        });
    }
    if lab.finalizers_pending != live.finalizers_pending {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.finalizers_pending".to_string(),
            description: "Region finalizers pending mismatch".to_string(),
            lab_value: format!("{}", lab.finalizers_pending),
            live_value: format!("{}", live.finalizers_pending),
        });
    }
}

fn compare_obligation_balance(
    lab: &ObligationBalanceRecord,
    live: &ObligationBalanceRecord,
    mismatches: &mut Vec<SemanticMismatch>,
) {
    if lab.balanced != live.balanced {
        mismatches.push(SemanticMismatch {
            field: "semantics.obligation_balance.balanced".to_string(),
            description: "Obligation balance mismatch".to_string(),
            lab_value: format!("{}", lab.balanced),
            live_value: format!("{}", live.balanced),
        });
    }
    if lab.leaked != live.leaked {
        mismatches.push(SemanticMismatch {
            field: "semantics.obligation_balance.leaked".to_string(),
            description: "Leaked obligation count mismatch".to_string(),
            lab_value: format!("{}", lab.leaked),
            live_value: format!("{}", live.leaked),
        });
    }
    if lab.unresolved != live.unresolved {
        mismatches.push(SemanticMismatch {
            field: "semantics.obligation_balance.unresolved".to_string(),
            description: "Unresolved obligation count mismatch".to_string(),
            lab_value: format!("{}", lab.unresolved),
            live_value: format!("{}", live.unresolved),
        });
    }
    if lab.reserved != live.reserved {
        mismatches.push(SemanticMismatch {
            field: "semantics.obligation_balance.reserved".to_string(),
            description: "Reserved obligation count mismatch".to_string(),
            lab_value: format!("{}", lab.reserved),
            live_value: format!("{}", live.reserved),
        });
    }
    if lab.committed != live.committed {
        mismatches.push(SemanticMismatch {
            field: "semantics.obligation_balance.committed".to_string(),
            description: "Committed obligation count mismatch".to_string(),
            lab_value: format!("{}", lab.committed),
            live_value: format!("{}", live.committed),
        });
    }
    if lab.aborted != live.aborted {
        mismatches.push(SemanticMismatch {
            field: "semantics.obligation_balance.aborted".to_string(),
            description: "Aborted obligation count mismatch".to_string(),
            lab_value: format!("{}", lab.aborted),
            live_value: format!("{}", live.aborted),
        });
    }
}

fn compare_resource_surface(
    lab: &ResourceSurfaceRecord,
    live: &ResourceSurfaceRecord,
    mismatches: &mut Vec<SemanticMismatch>,
) {
    if lab.contract_scope != live.contract_scope {
        mismatches.push(SemanticMismatch {
            field: "semantics.resource_surface.contract_scope".to_string(),
            description: "Resource surface contract scope mismatch".to_string(),
            lab_value: lab.contract_scope.clone(),
            live_value: live.contract_scope.clone(),
        });
        return; // No point comparing counters if scopes differ.
    }

    // Compare counters using declared tolerances.
    for (name, &lab_val) in &lab.counters {
        let Some(&live_val) = live.counters.get(name) else {
            mismatches.push(SemanticMismatch {
                field: format!("semantics.resource_surface.counters.{name}"),
                description: format!("Counter '{name}' missing in live observable"),
                lab_value: format!("{lab_val}"),
                live_value: "absent".to_string(),
            });
            continue;
        };

        let lab_tolerance = lab
            .tolerances
            .get(name)
            .copied()
            .unwrap_or(CounterTolerance::Exact);
        let live_tolerance = live
            .tolerances
            .get(name)
            .copied()
            .unwrap_or(CounterTolerance::Exact);

        if lab_tolerance != live_tolerance {
            mismatches.push(SemanticMismatch {
                field: format!("semantics.resource_surface.tolerances.{name}"),
                description: format!("Counter '{name}' tolerance mismatch"),
                lab_value: format!("{lab_tolerance:?}"),
                live_value: format!("{live_tolerance:?}"),
            });
        }

        let mismatch = match lab_tolerance {
            CounterTolerance::Exact => lab_val != live_val,
            CounterTolerance::AtLeast => live_val < lab_val,
            CounterTolerance::AtMost => live_val > lab_val,
            CounterTolerance::Unsupported => false,
        };

        if mismatch {
            mismatches.push(SemanticMismatch {
                field: format!("semantics.resource_surface.counters.{name}"),
                description: format!("Counter '{name}' mismatch (tolerance: {lab_tolerance:?})"),
                lab_value: format!("{lab_val}"),
                live_value: format!("{live_val}"),
            });
        }
    }

    // Check for counters in live but not in lab.
    for name in live.counters.keys() {
        if !lab.counters.contains_key(name) {
            let live_val = live.counters[name];
            mismatches.push(SemanticMismatch {
                field: format!("semantics.resource_surface.counters.{name}"),
                description: format!("Counter '{name}' present in live but not in lab"),
                lab_value: "absent".to_string(),
                live_value: format!("{live_val}"),
            });
        }
    }
}

fn classify_scheduler_noise(
    lab: &NormalizedObservable,
    live: &NormalizedObservable,
) -> SchedulerNoiseClass {
    if !live.provenance.nondeterminism_notes.is_empty() {
        return SchedulerNoiseClass::NondeterminismNotesOnly;
    }
    if let (Some(lab_hash), Some(live_hash)) =
        (lab.provenance.schedule_hash, live.provenance.schedule_hash)
    {
        if lab_hash != live_hash {
            return SchedulerNoiseClass::ScheduleHashDrift;
        }
    }
    if let (Some(lab_hash), Some(live_hash)) =
        (lab.provenance.event_hash, live.provenance.event_hash)
    {
        if lab_hash != live_hash {
            return SchedulerNoiseClass::EventHashDrift;
        }
    }
    if let (Some(lab_count), Some(live_count)) =
        (lab.provenance.event_count, live.provenance.event_count)
    {
        if lab_count != live_count {
            return SchedulerNoiseClass::EventCountDrift;
        }
    }
    if lab.provenance.artifact_path != live.provenance.artifact_path
        || lab.provenance.config_hash != live.provenance.config_hash
    {
        return SchedulerNoiseClass::ProvenanceDrift;
    }
    SchedulerNoiseClass::None
}

fn classify_time_policy(
    identity: &DualRunScenarioIdentity,
    verdict: &ComparisonVerdict,
    noise_class: SchedulerNoiseClass,
) -> TimePolicyClass {
    let has_timer_contract = [
        "scenario_clock_id",
        "logical_deadline_id",
        "normalization_window",
    ]
    .iter()
    .all(|key| identity.metadata.contains_key(*key));
    let has_time_mismatch = verdict.mismatches.iter().any(|mismatch| {
        mismatch.field.contains("timeout")
            || mismatch.field.contains("deadline")
            || mismatch.field.contains("clock")
    });

    if has_time_mismatch && has_timer_contract {
        return TimePolicyClass::SemanticTime;
    }
    if has_time_mismatch {
        return TimePolicyClass::UnsupportedTimeSurface;
    }
    if noise_class != SchedulerNoiseClass::None && verdict.mismatches.is_empty() {
        return TimePolicyClass::SchedulerNoiseSignal;
    }
    TimePolicyClass::NotApplicable
}

fn eligibility_verdict(identity: &DualRunScenarioIdentity) -> Option<&str> {
    identity
        .metadata
        .get("eligibility_verdict")
        .map(String::as_str)
}

fn is_bridge_only_downgrade(identity: &DualRunScenarioIdentity) -> bool {
    let has_bridge_only_support_class = matches!(
        identity.metadata.get("support_class").map(String::as_str),
        Some("bridge_only")
    );

    let has_supported_downgrade_reason = matches!(
        identity.metadata.get("reason_code").map(String::as_str),
        Some(
            "downgrade_to_server_bridge"
                | "downgrade_to_edge_bridge"
                | "downgrade_to_websocket_or_fetch"
                | "downgrade_to_export_bytes_for_download"
                | "downgrade_to_bridge_only"
        )
    );

    has_bridge_only_support_class && has_supported_downgrade_reason
}

fn unsupported_surface_reason(identity: &DualRunScenarioIdentity) -> Option<String> {
    if let Some(
        verdict @ ("blocked_missing_virtualization"
        | "blocked_missing_verification"
        | "blocked_scope_red_line"
        | "unsupported"
        | "rejected"
        | "unsupported_surface"),
    ) = eligibility_verdict(identity)
    {
        return Some(format!("eligibility_verdict={verdict}"));
    }

    if let Some(class) = identity.metadata.get("support_class") {
        if matches!(class.as_str(), "unsupported" | "unsupported_surface") {
            return Some(format!("support_class={class}"));
        }
    }

    if is_bridge_only_downgrade(identity) {
        return None;
    }

    if let Some(reason) = identity.metadata.get("unsupported_reason") {
        return Some(reason.clone());
    }

    None
}

fn insufficient_observability_reason(
    identity: &DualRunScenarioIdentity,
    verdict: &ComparisonVerdict,
    live: &NormalizedObservable,
) -> Option<String> {
    if matches!(
        eligibility_verdict(identity),
        Some("blocked_missing_observability")
    ) {
        return Some("eligibility_verdict=blocked_missing_observability".to_string());
    }

    if let Some(status) = identity.metadata.get("observability_status") {
        let lowered = status.to_ascii_lowercase();
        if ["blocked", "missing", "limited", "insufficient"]
            .iter()
            .any(|needle| lowered.contains(needle))
        {
            return Some(status.clone());
        }
    }

    if verdict
        .mismatches
        .iter()
        .any(|mismatch| mismatch.description.contains("missing in live observable"))
        && live
            .semantics
            .resource_surface
            .tolerances
            .values()
            .any(|tolerance| *tolerance == CounterTolerance::Unsupported)
    {
        return Some(
            "live observable omitted a required counter while declaring unsupported tolerance"
                .to_string(),
        );
    }

    None
}

fn hard_contract_break_reason(
    live: &NormalizedObservable,
    live_invariant_violations: &[String],
) -> Option<String> {
    if !live_invariant_violations.is_empty() {
        return Some(format!(
            "live invariant violations: {}",
            live_invariant_violations.join("; ")
        ));
    }
    if live.semantics.obligation_balance.leaked > 0 {
        return Some("live run leaked obligations".to_string());
    }
    if live.semantics.obligation_balance.unresolved > 0 {
        return Some("live run left obligations unresolved".to_string());
    }
    if live.semantics.loser_drain.applicable
        && live.semantics.loser_drain.status != DrainStatus::Complete
    {
        return Some("live run did not complete loser drain".to_string());
    }
    if !live.semantics.region_close.quiescent {
        return Some("live root region did not close to quiescence".to_string());
    }
    if live.semantics.terminal_outcome.class == OutcomeClass::Panicked {
        return Some("live run panicked on an admitted surface".to_string());
    }
    if live.semantics.cancellation.acknowledged
        && (!live.semantics.cancellation.cleanup_completed
            || !live.semantics.cancellation.finalization_completed)
    {
        return Some("live cancellation acknowledged without cleanup/finalization".to_string());
    }
    None
}

fn terminal_policy_outcome(
    provisional_class: ProvisionalDivergenceClass,
    rerun_decision: RerunDecision,
    suggested_final_class: Option<FinalDivergenceClass>,
    time_policy_class: TimePolicyClass,
    scheduler_noise_class: SchedulerNoiseClass,
    suppression_reason: Option<String>,
    explanation: impl Into<String>,
) -> DifferentialPolicyOutcome {
    DifferentialPolicyOutcome {
        provisional_class,
        rerun_decision,
        suggested_final_class,
        time_policy_class,
        scheduler_noise_class,
        suppression_reason,
        explanation: explanation.into(),
    }
}

fn classify_differential_policy(
    identity: &DualRunScenarioIdentity,
    lab: &NormalizedObservable,
    live: &NormalizedObservable,
    verdict: &ComparisonVerdict,
    lab_invariant_violations: &[String],
    live_invariant_violations: &[String],
) -> DifferentialPolicyOutcome {
    let noise_class = classify_scheduler_noise(lab, live);
    let time_policy_class = classify_time_policy(identity, verdict, noise_class);

    if lab.schema_version != live.schema_version {
        return terminal_policy_outcome(
            ProvisionalDivergenceClass::ArtifactSchemaViolation,
            RerunDecision::None,
            Some(FinalDivergenceClass::ArtifactSchemaViolation),
            time_policy_class,
            noise_class,
            Some("schema version mismatch".to_string()),
            "comparison artifacts do not share a schema contract, so reruns would not be honest",
        );
    }

    if let Some(reason) = unsupported_surface_reason(identity) {
        return terminal_policy_outcome(
            ProvisionalDivergenceClass::UnsupportedSurface,
            RerunDecision::None,
            Some(FinalDivergenceClass::UnsupportedSurface),
            time_policy_class,
            noise_class,
            Some(reason),
            "scenario metadata marks this surface unsupported, so the mismatch is rejected immediately",
        );
    }

    if let Some(reason) = insufficient_observability_reason(identity, verdict, live) {
        return terminal_policy_outcome(
            ProvisionalDivergenceClass::InsufficientObservability,
            RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs: 1 },
            Some(FinalDivergenceClass::InsufficientObservability),
            time_policy_class,
            noise_class,
            Some(reason),
            "required evidence is missing or explicitly blocked, so this surface cannot be promoted honestly",
        );
    }

    if let Some(reason) = hard_contract_break_reason(live, live_invariant_violations) {
        return terminal_policy_outcome(
            ProvisionalDivergenceClass::HardContractBreak,
            RerunDecision::None,
            Some(FinalDivergenceClass::RuntimeSemanticBug),
            time_policy_class,
            noise_class,
            Some(reason),
            "the live side already violates a hard semantic contract, so the framework should escalate immediately",
        );
    }

    if verdict.passed
        && lab_invariant_violations.is_empty()
        && live_invariant_violations.is_empty()
        && noise_class != SchedulerNoiseClass::None
    {
        return terminal_policy_outcome(
            ProvisionalDivergenceClass::SchedulerNoiseSuspected,
            RerunDecision::LiveConfirmations { additional_runs: 2 },
            Some(FinalDivergenceClass::SchedulerNoiseSuspected),
            time_policy_class,
            noise_class,
            Some(
                "semantic observables stayed equal while only scheduler/provenance signals drifted"
                    .to_string(),
            ),
            "the semantic verdict remains a pass, but the report should retain scheduler-noise triage metadata",
        );
    }

    if verdict.passed && lab_invariant_violations.is_empty() && live_invariant_violations.is_empty()
    {
        return terminal_policy_outcome(
            ProvisionalDivergenceClass::Pass,
            RerunDecision::None,
            None,
            time_policy_class,
            noise_class,
            None,
            "semantic observables match and no invariant failures were observed",
        );
    }

    terminal_policy_outcome(
        ProvisionalDivergenceClass::SemanticMismatchAdmittedSurface,
        RerunDecision::DeterministicLabReplayAndLiveConfirmations {
            additional_live_runs: 2,
        },
        None,
        time_policy_class,
        noise_class,
        None,
        "semantic mismatches survived the initial comparison on an admitted surface; schedule the canonical lab replay plus two live confirmation reruns",
    )
}

// ============================================================================
// Assertion Helpers
// ============================================================================

/// Assert that a normalized observable satisfies the core Asupersync
/// invariants: no obligation leaks, region closed to quiescence, and
/// losers drained (if applicable).
///
/// Returns a list of invariant violations (empty if all pass).
#[must_use]
pub fn check_core_invariants(obs: &NormalizedObservable) -> Vec<String> {
    let mut violations = Vec::new();

    // Obligation balance
    if !obs.semantics.obligation_balance.balanced {
        violations.push(format!(
            "Obligation balance: leaked={}, unresolved={}",
            obs.semantics.obligation_balance.leaked, obs.semantics.obligation_balance.unresolved
        ));
    }

    // Region quiescence
    if !obs.semantics.region_close.quiescent {
        violations.push(format!(
            "Region not quiescent: state={:?}, live_children={}, finalizers_pending={}",
            obs.semantics.region_close.root_state,
            obs.semantics.region_close.live_children,
            obs.semantics.region_close.finalizers_pending
        ));
    }

    // Loser drain
    if obs.semantics.loser_drain.applicable
        && obs.semantics.loser_drain.status == DrainStatus::Incomplete
    {
        violations.push(format!(
            "Incomplete loser drain: expected={}, drained={}",
            obs.semantics.loser_drain.expected_losers, obs.semantics.loser_drain.drained_losers
        ));
    }

    // Cancellation protocol completion
    if obs.semantics.cancellation.requested && !obs.semantics.cancellation.cleanup_completed {
        violations.push(format!(
            "Cancellation cleanup incomplete: phase={:?}",
            obs.semantics.cancellation.terminal_phase
        ));
    }

    violations
}

/// Assert a normalized observable against expected semantics.
///
/// Returns mismatches between actual and expected values.
#[must_use]
pub fn assert_semantics(
    actual: &NormalizedSemantics,
    expected: &NormalizedSemantics,
) -> Vec<SemanticMismatch> {
    // Build temporary observables just for comparison.
    let lab = NormalizedObservable {
        schema_version: NORMALIZED_OBSERVABLE_SCHEMA_VERSION.to_string(),
        scenario_id: String::new(),
        surface_id: String::new(),
        surface_contract_version: String::new(),
        runtime_kind: RuntimeKind::Lab,
        semantics: expected.clone(),
        provenance: ReplayMetadata::for_lab(
            ScenarioFamilyId::new("", "", ""),
            &SeedPlan::inherit(0, ""),
        ),
    };
    let live = NormalizedObservable {
        schema_version: NORMALIZED_OBSERVABLE_SCHEMA_VERSION.to_string(),
        scenario_id: String::new(),
        surface_id: String::new(),
        surface_contract_version: String::new(),
        runtime_kind: RuntimeKind::Live,
        semantics: actual.clone(),
        provenance: ReplayMetadata::for_live(
            ScenarioFamilyId::new("", "", ""),
            &SeedPlan::inherit(0, ""),
        ),
    };

    let verdict = compare_observables(
        &lab,
        &live,
        SeedLineageRecord::from_plan(&SeedPlan::inherit(0, "")),
    );
    verdict.mismatches
}

// ============================================================================
// Live Runner Adapter
// ============================================================================

/// Execution profile for the live runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveExecutionProfile {
    /// Phase 1: `RuntimeBuilder::current_thread()` — single-threaded,
    /// no ambient globals, explicit `Cx`.
    CurrentThread,
}

impl fmt::Display for LiveExecutionProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentThread => write!(f, "phase1.current_thread"),
        }
    }
}

/// Configuration for a live runner execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRunnerConfig {
    /// Effective seed for this live execution.
    pub seed: u64,
    /// Effective entropy seed.
    pub entropy_seed: u64,
    /// Execution profile.
    pub profile: LiveExecutionProfile,
    /// Scenario identity.
    pub scenario_id: String,
    /// Surface identity.
    pub surface_id: String,
    /// Seed lineage ID for audit.
    pub seed_lineage_id: String,
}

impl LiveRunnerConfig {
    /// Create a live runner config from a `DualRunScenarioIdentity`.
    #[must_use]
    pub fn from_identity(identity: &DualRunScenarioIdentity) -> Self {
        let live_seed = identity.seed_plan.effective_live_seed();
        let entropy = identity.seed_plan.effective_entropy_seed(live_seed);
        Self {
            seed: live_seed,
            entropy_seed: entropy,
            profile: LiveExecutionProfile::CurrentThread,
            scenario_id: identity.scenario_id.clone(),
            surface_id: identity.surface_id.clone(),
            seed_lineage_id: identity.seed_plan.seed_lineage_id.clone(),
        }
    }

    /// Create a live runner config from a `SeedPlan` with a scenario ID.
    #[must_use]
    pub fn from_plan(
        plan: &SeedPlan,
        scenario_id: impl Into<String>,
        surface_id: impl Into<String>,
    ) -> Self {
        let live_seed = plan.effective_live_seed();
        let entropy = plan.effective_entropy_seed(live_seed);
        Self {
            seed: live_seed,
            entropy_seed: entropy,
            profile: LiveExecutionProfile::CurrentThread,
            scenario_id: scenario_id.into(),
            surface_id: surface_id.into(),
            seed_lineage_id: plan.seed_lineage_id.clone(),
        }
    }
}

impl fmt::Display for LiveRunnerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LiveRunner(scenario={}, surface={}, seed=0x{:X}, profile={})",
            self.scenario_id, self.surface_id, self.seed, self.profile
        )
    }
}

/// Witness collector for live-side semantic evidence.
///
/// The live adapter cannot rely on lab-only introspection (oracle reports,
/// trace certificates). Instead, it collects evidence from explicit
/// witnesses: joined handles, counters, lifecycle hooks, and stream
/// termination signals.
///
/// A `LiveWitnessCollector` is passed into the live execution closure.
/// The closure records evidence, and the collector normalizes it into
/// `NormalizedSemantics` at the end.
#[derive(Debug, Clone)]
pub struct LiveWitnessCollector {
    terminal_outcome: TerminalOutcome,
    cancellation: CancellationRecord,
    loser_drain: LoserDrainRecord,
    region_close: RegionCloseRecord,
    obligation_balance: ObligationBalanceRecord,
    resource_surface: ResourceSurfaceRecord,
    manifest: CaptureManifest,
    /// Nondeterminism qualifiers observed during execution.
    nondeterminism_notes: Vec<String>,
}

impl LiveWitnessCollector {
    /// Create a new collector with default (happy-path) assumptions.
    ///
    /// All fields start at "clean" values. The live execution closure
    /// overrides them as evidence is observed.
    #[must_use]
    pub fn new(surface_scope: impl Into<String>) -> Self {
        let surface_scope = surface_scope.into();
        let mut manifest = CaptureManifest::new();
        manifest.inferred("terminal_outcome", "run_live_adapter.default_ok");
        manifest.inferred("cancellation", "run_live_adapter.default_no_cancellation");
        manifest.unsupported("cancellation.checkpoint_observed");
        manifest.inferred("loser_drain", "run_live_adapter.default_not_applicable");
        manifest.inferred("region_close", "run_live_adapter.default_quiescent");
        manifest.inferred(
            "obligation_balance",
            "run_live_adapter.default_balanced_obligations",
        );
        manifest.observed(
            "resource_surface.contract_scope",
            "scenario_identity.surface_id",
        );

        Self {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: RegionCloseRecord::quiescent(),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty(surface_scope),
            manifest,
            nondeterminism_notes: Vec::new(),
        }
    }

    /// Record the terminal outcome.
    pub fn set_outcome(&mut self, outcome: TerminalOutcome) {
        self.terminal_outcome = outcome;
        self.manifest
            .observed("terminal_outcome", "witness.set_outcome");
    }

    /// Record cancellation evidence.
    pub fn set_cancellation(&mut self, record: CancellationRecord) {
        if record.checkpoint_observed.is_some() {
            self.manifest.observed(
                "cancellation.checkpoint_observed",
                "witness.set_cancellation",
            );
        } else {
            self.manifest
                .unsupported("cancellation.checkpoint_observed");
        }
        self.cancellation = record;
        self.manifest
            .observed("cancellation", "witness.set_cancellation");
    }

    /// Record loser drain evidence.
    pub fn set_loser_drain(&mut self, record: LoserDrainRecord) {
        self.loser_drain = record;
        self.manifest
            .observed("loser_drain", "witness.set_loser_drain");
    }

    /// Record region close evidence.
    pub fn set_region_close(&mut self, record: RegionCloseRecord) {
        self.region_close = record;
        self.manifest
            .observed("region_close", "witness.set_region_close");
    }

    /// Record obligation balance evidence.
    pub fn set_obligation_balance(&mut self, record: ObligationBalanceRecord) {
        self.obligation_balance = record;
        self.manifest
            .observed("obligation_balance", "witness.set_obligation_balance");
    }

    /// Set a resource counter.
    pub fn record_counter(&mut self, name: impl Into<String>, value: i64) {
        let n = name.into();
        let counter_manifest_key = format!("resource_surface.counters.{n}");
        let tolerance_manifest_key = format!("resource_surface.tolerances.{n}");
        self.resource_surface.counters.insert(n.clone(), value);
        self.resource_surface
            .tolerances
            .insert(n, CounterTolerance::Exact);
        self.manifest
            .observed(counter_manifest_key, "witness.record_counter");
        self.manifest
            .observed(tolerance_manifest_key, "witness.record_counter");
    }

    /// Set a resource counter with tolerance.
    pub fn record_counter_with_tolerance(
        &mut self,
        name: impl Into<String>,
        value: i64,
        tolerance: CounterTolerance,
    ) {
        let n = name.into();
        self.resource_surface.counters.insert(n.clone(), value);
        self.resource_surface
            .tolerances
            .insert(n.clone(), tolerance);
        self.manifest.observed(
            format!("resource_surface.counters.{n}"),
            "witness.record_counter_with_tolerance",
        );
        self.manifest.observed(
            format!("resource_surface.tolerances.{n}"),
            "witness.record_counter_with_tolerance",
        );
    }

    /// Note a nondeterminism qualifier (e.g., "scheduler ordering may vary").
    pub fn note_nondeterminism(&mut self, note: impl Into<String>) {
        self.nondeterminism_notes.push(note.into());
    }

    /// Finalize into normalized semantics.
    #[must_use]
    pub fn finalize(self) -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: self.terminal_outcome,
            cancellation: self.cancellation,
            loser_drain: self.loser_drain,
            region_close: self.region_close,
            obligation_balance: self.obligation_balance,
            resource_surface: self.resource_surface,
        }
    }

    /// Access the capture manifest built for the live run.
    #[must_use]
    pub fn capture_manifest(&self) -> &CaptureManifest {
        &self.manifest
    }

    /// Access nondeterminism notes.
    #[must_use]
    pub fn nondeterminism_notes(&self) -> &[String] {
        &self.nondeterminism_notes
    }
}

/// Structured metadata emitted by a live run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRunMetadata {
    /// Configuration used.
    pub config: LiveRunnerConfig,
    /// Nondeterminism qualifiers observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nondeterminism_notes: Vec<String>,
    /// Capture provenance for the normalized live semantics.
    pub capture_manifest: CaptureManifest,
    /// Replay metadata for this execution.
    pub replay: ReplayMetadata,
}

/// Result of a live runner execution.
#[derive(Debug, Clone)]
pub struct LiveRunResult {
    /// Normalized semantics from the live run.
    pub semantics: NormalizedSemantics,
    /// Structured run metadata.
    pub metadata: LiveRunMetadata,
}

/// Execute a differential scenario through the live runner adapter.
///
/// This is the live-side counterpart to lab execution. It:
/// 1. Builds a `LiveRunnerConfig` from the identity
/// 2. Logs structured start metadata
/// 3. Invokes the user's execution closure with a `LiveWitnessCollector`
/// 4. Logs structured completion metadata
/// 5. Returns `LiveRunResult` with normalized semantics
///
/// # Example
///
/// ```ignore
/// let identity = DualRunScenarioIdentity::phase1(
///     "cancel.race", "cancellation.race", "v1", "desc", 42,
/// );
/// let result = run_live_adapter(&identity, |config, witness| {
///     // Run on current-thread runtime
///     let rt = RuntimeBuilder::current_thread().build().unwrap();
///     let cx = Cx::for_testing();
///     rt.block_on(async {
///         // ... execute scenario, record witnesses ...
///         witness.set_outcome(TerminalOutcome::ok());
///     });
/// });
/// ```
#[must_use]
pub fn run_live_adapter(
    identity: &DualRunScenarioIdentity,
    f: impl FnOnce(&LiveRunnerConfig, &mut LiveWitnessCollector),
) -> LiveRunResult {
    let config = LiveRunnerConfig::from_identity(identity);
    let mut witness = LiveWitnessCollector::new(&identity.surface_id);

    #[cfg(feature = "tracing-integration")]
    tracing::info!(
        scenario_id = %identity.scenario_id,
        surface_id = %identity.surface_id,
        seed = %format_args!("0x{:X}", config.seed),
        entropy_seed = %format_args!("0x{:X}", config.entropy_seed),
        profile = %config.profile,
        seed_lineage = %config.seed_lineage_id,
        "LIVE_RUN_START"
    );

    f(&config, &mut witness);

    let nondeterminism_notes = witness.nondeterminism_notes().to_vec();
    let capture_manifest = witness.capture_manifest().clone();
    let semantics = witness.finalize();
    let replay = ReplayMetadata::for_live(identity.family_id(), &identity.seed_plan);

    #[cfg(feature = "tracing-integration")]
    tracing::info!(
        scenario_id = %identity.scenario_id,
        outcome = %semantics.terminal_outcome.class,
        quiescent = semantics.region_close.quiescent,
        obligation_balanced = semantics.obligation_balance.balanced,
        nondeterminism_count = nondeterminism_notes.len(),
        "LIVE_RUN_COMPLETE"
    );

    LiveRunResult {
        semantics,
        metadata: LiveRunMetadata {
            config,
            nondeterminism_notes,
            capture_manifest,
            replay,
        },
    }
}

// ============================================================================
// Semantic Capture Hooks
// ============================================================================

/// Observability status for a captured field.
///
/// When a live adapter cannot observe a semantic field, it must declare
/// the limitation explicitly rather than fabricating a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldObservability {
    /// Field was observed from a stable semantic hook.
    Observed,
    /// Field was inferred from indirect evidence.
    Inferred,
    /// Field is not observable on this adapter and was set to a default.
    Unsupported,
}

impl fmt::Display for FieldObservability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observed => write!(f, "observed"),
            Self::Inferred => write!(f, "inferred"),
            Self::Unsupported => write!(f, "unsupported"),
        }
    }
}

/// Evidence annotation for a single captured field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureAnnotation {
    /// Dot-path of the field (e.g., `"cancellation.checkpoint_observed"`).
    pub field: String,
    /// How the field was captured.
    pub observability: FieldObservability,
    /// Source of the evidence (e.g., `"task_handle.join"`, `"oracle.loser_drain"`).
    pub source: String,
}

/// Semantic capture manifest for a live run.
///
/// Records how each normalized field was captured, enabling downstream
/// tools to distinguish strongly-observed from weakly-inferred evidence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureManifest {
    /// Per-field capture annotations.
    pub annotations: Vec<CaptureAnnotation>,
    /// Fields that are unsupported on this adapter.
    pub unsupported_fields: Vec<String>,
}

impl CaptureManifest {
    fn upsert(&mut self, field: String, observability: FieldObservability, source: String) {
        self.unsupported_fields
            .retain(|existing| existing != &field);
        if observability == FieldObservability::Unsupported {
            self.unsupported_fields.push(field.clone());
            self.unsupported_fields.sort_unstable();
            self.unsupported_fields.dedup();
        }

        if let Some(annotation) = self.annotations.iter_mut().find(|a| a.field == field) {
            annotation.observability = observability;
            annotation.source = source;
        } else {
            self.annotations.push(CaptureAnnotation {
                field,
                observability,
                source,
            });
        }
        self.annotations.sort_by(|left, right| {
            left.field
                .cmp(&right.field)
                .then(left.source.cmp(&right.source))
        });
    }

    fn annotation_for_candidate(&self, field: &str) -> Option<&CaptureAnnotation> {
        self.annotations
            .iter()
            .find(|annotation| annotation.field == field)
    }

    /// Create an empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a field was directly observed.
    pub fn observed(&mut self, field: impl Into<String>, source: impl Into<String>) {
        self.upsert(field.into(), FieldObservability::Observed, source.into());
    }

    /// Record that a field was inferred from indirect evidence.
    pub fn inferred(&mut self, field: impl Into<String>, source: impl Into<String>) {
        self.upsert(field.into(), FieldObservability::Inferred, source.into());
    }

    /// Record that a field is unsupported and was defaulted.
    pub fn unsupported(&mut self, field: impl Into<String>) {
        self.upsert(
            field.into(),
            FieldObservability::Unsupported,
            "default".to_string(),
        );
    }

    /// How many fields were captured total.
    #[must_use]
    pub fn total_fields(&self) -> usize {
        self.annotations.len()
    }

    /// How many fields are unsupported.
    #[must_use]
    pub fn unsupported_count(&self) -> usize {
        self.unsupported_fields.len()
    }

    /// Whether all fields were directly observed (no inferred or unsupported).
    #[must_use]
    pub fn fully_observed(&self) -> bool {
        !self.annotations.is_empty()
            && self
                .annotations
                .iter()
                .all(|a| a.observability == FieldObservability::Observed)
    }

    /// Resolve the capture annotation for a semantic field or one of its
    /// parents.
    #[must_use]
    pub fn annotation_for_field(&self, field: &str) -> Option<&CaptureAnnotation> {
        if let Some(annotation) = self.annotation_for_candidate(field) {
            return Some(annotation);
        }

        let normalized = field.strip_prefix("semantics.").unwrap_or(field);
        if let Some(annotation) = self.annotation_for_candidate(normalized) {
            return Some(annotation);
        }

        let mut candidate = normalized;
        while let Some((parent, _)) = candidate.rsplit_once('.') {
            if let Some(annotation) = self.annotation_for_candidate(parent) {
                return Some(annotation);
            }
            candidate = parent;
        }

        None
    }

    /// Render capture provenance for a semantic field.
    #[must_use]
    pub fn describe_field_capture(&self, field: &str) -> Option<String> {
        self.annotation_for_field(field)
            .map(|annotation| format!("{} via {}", annotation.observability, annotation.source))
    }
}

/// Capture a `TerminalOutcome` from an `Outcome<T, E>`.
///
/// Maps the four-valued `Outcome` enum to the normalized
/// `TerminalOutcome` record. Error and cancel reason classes are
/// derived from `Display` on the error/reason values.
#[must_use]
pub fn capture_terminal_outcome<T, E: fmt::Display>(
    outcome: &crate::types::outcome::Outcome<T, E>,
) -> TerminalOutcome {
    match outcome {
        crate::types::outcome::Outcome::Ok(_) => TerminalOutcome::ok(),
        crate::types::outcome::Outcome::Err(e) => TerminalOutcome::err(format!("{e}")),
        crate::types::outcome::Outcome::Cancelled(reason) => {
            TerminalOutcome::cancelled(format!("{reason}"))
        }
        crate::types::outcome::Outcome::Panicked(_) => TerminalOutcome {
            class: OutcomeClass::Panicked,
            severity: OutcomeClass::Panicked,
            surface_result: None,
            error_class: None,
            cancel_reason_class: None,
            panic_class: Some("caught_panic".to_string()),
        },
    }
}

/// Capture a `TerminalOutcome` from a `Result<T, E>`.
///
/// Maps `Ok` to `OutcomeClass::Ok` and `Err` to `OutcomeClass::Err`.
#[must_use]
pub fn capture_terminal_from_result<T, E: fmt::Display>(result: &Result<T, E>) -> TerminalOutcome {
    match result {
        Ok(_) => TerminalOutcome::ok(),
        Err(e) => TerminalOutcome::err(format!("{e}")),
    }
}

/// Capture obligation balance from explicit counters.
///
/// This is a convenience for live adapters that track obligations
/// via explicit counters rather than a full ledger.
#[must_use]
pub fn capture_obligation_balance(
    reserved: u32,
    committed: u32,
    aborted: u32,
) -> ObligationBalanceRecord {
    let leaked = reserved.saturating_sub(committed.saturating_add(aborted));
    ObligationBalanceRecord {
        reserved,
        committed,
        aborted,
        leaked,
        unresolved: 0,
        balanced: leaked == 0,
    }
    .recompute()
}

/// Capture region close evidence from explicit flags.
///
/// For live adapters that check quiescence by joining all child tasks.
#[must_use]
pub fn capture_region_close(
    all_children_joined: bool,
    all_finalizers_done: bool,
) -> RegionCloseRecord {
    let quiescent = all_children_joined && all_finalizers_done;
    RegionCloseRecord {
        root_state: if quiescent {
            RegionState::Closed
        } else {
            RegionState::Open
        },
        quiescent,
        live_children: u32::from(!all_children_joined),
        finalizers_pending: u32::from(!all_finalizers_done),
        close_completed: quiescent,
    }
}

/// Capture loser drain evidence from join results.
///
/// `loser_joined` is a list of booleans indicating whether each loser
/// task was successfully joined (true = drained).
#[must_use]
pub fn capture_loser_drain(loser_joined: &[bool]) -> LoserDrainRecord {
    if loser_joined.is_empty() {
        return LoserDrainRecord::not_applicable();
    }
    let expected = loser_joined.len() as u32;
    let drained = loser_joined.iter().filter(|&&x| x).count() as u32;
    LoserDrainRecord {
        applicable: true,
        expected_losers: expected,
        drained_losers: drained,
        status: if drained == expected {
            DrainStatus::Complete
        } else {
            DrainStatus::Incomplete
        },
        evidence: Some("task_handle.join".to_string()),
    }
}

/// Capture cancellation evidence from explicit lifecycle flags.
#[must_use]
#[allow(clippy::fn_params_excessive_bools)]
pub fn capture_cancellation(
    requested: bool,
    acknowledged: bool,
    cleanup_completed: bool,
    finalization_completed: bool,
    checkpoint_observed: Option<bool>,
) -> CancellationRecord {
    let terminal_phase = if !requested {
        CancelTerminalPhase::NotCancelled
    } else if finalization_completed {
        CancelTerminalPhase::Completed
    } else if cleanup_completed {
        CancelTerminalPhase::Finalizing
    } else if acknowledged {
        CancelTerminalPhase::Cancelling
    } else {
        CancelTerminalPhase::CancelRequested
    };

    CancellationRecord {
        requested,
        acknowledged,
        cleanup_completed,
        finalization_completed,
        terminal_phase,
        checkpoint_observed,
    }
}

// ============================================================================
// Lab Evidence Normalizer
// ============================================================================

/// Normalize a `LabRunReport` into `NormalizedSemantics`.
///
/// Extracts semantic facts from the lab report and oracle results:
/// - Terminal outcome from oracle pass/fail status
/// - Region quiescence from `report.quiescent`
/// - Obligation leaks from invariant violations
/// - Cancellation and loser drain from oracle entries
///
/// Returns `(NormalizedSemantics, CaptureManifest)` so callers know
/// exactly how each field was derived.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn normalize_lab_report(
    report: &crate::lab::runtime::LabRunReport,
    surface_scope: &str,
) -> (NormalizedSemantics, CaptureManifest) {
    let mut manifest = CaptureManifest::new();

    // Terminal outcome: if oracle failed or invariant violations, it's an error.
    let terminal_outcome = if !report.invariant_violations.is_empty() {
        manifest.observed("terminal_outcome", "invariant_violations");
        TerminalOutcome::err("invariant_violation")
    } else if !report.oracle_report.all_passed() {
        manifest.observed("terminal_outcome", "oracle_report.failures");
        TerminalOutcome::err("oracle_failure")
    } else {
        manifest.observed("terminal_outcome", "oracle_report.all_passed");
        TerminalOutcome::ok()
    };

    // Region close: directly from quiescence flag.
    manifest.observed("region_close.quiescent", "LabRunReport.quiescent");
    let region_close = RegionCloseRecord {
        root_state: if report.quiescent {
            RegionState::Closed
        } else {
            RegionState::Open
        },
        quiescent: report.quiescent,
        live_children: 0,
        finalizers_pending: 0,
        close_completed: report.quiescent,
    };

    // Obligation balance: check for leak oracle or invariant violations.
    let has_leak = report
        .invariant_violations
        .iter()
        .any(|v| v.contains("obligation") || v.contains("leak"));
    let obligation_oracle_failed = report
        .oracle_report
        .entry("obligation_leak")
        .is_some_and(|e| !e.passed);
    manifest.observed("obligation_balance", "oracle.obligation_leak + invariants");
    let obligation_balance = if has_leak || obligation_oracle_failed {
        ObligationBalanceRecord {
            reserved: 0,
            committed: 0,
            aborted: 0,
            leaked: 1,
            unresolved: 0,
            balanced: false,
        }
    } else {
        ObligationBalanceRecord::zero()
    };

    // Loser drain: check for loser_drain oracle.
    let loser_drain_entry = report.oracle_report.entry("loser_drain");
    let loser_drain = if let Some(entry) = loser_drain_entry {
        manifest.observed("loser_drain", "oracle.loser_drain");
        if entry.passed {
            // Oracle passed but we don't know exact counts.
            LoserDrainRecord {
                applicable: true,
                expected_losers: 0,
                drained_losers: 0,
                status: DrainStatus::Complete,
                evidence: Some("oracle.loser_drain.passed".to_string()),
            }
        } else {
            LoserDrainRecord {
                applicable: true,
                expected_losers: 0,
                drained_losers: 0,
                status: DrainStatus::Incomplete,
                evidence: Some("oracle.loser_drain.failed".to_string()),
            }
        }
    } else {
        manifest.inferred("loser_drain", "no_oracle_entry");
        LoserDrainRecord::not_applicable()
    };

    // Cancellation: check for cancellation_protocol oracle.
    let cancel_entry = report.oracle_report.entry("cancellation_protocol");
    let cancellation = if let Some(entry) = cancel_entry {
        manifest.observed("cancellation", "oracle.cancellation_protocol");
        if entry.passed {
            CancellationRecord::completed()
        } else {
            CancellationRecord {
                requested: true,
                acknowledged: false,
                cleanup_completed: false,
                finalization_completed: false,
                terminal_phase: CancelTerminalPhase::CancelRequested,
                checkpoint_observed: None,
            }
        }
    } else {
        manifest.inferred("cancellation", "no_oracle_entry");
        CancellationRecord::none()
    };

    let semantics = NormalizedSemantics {
        terminal_outcome,
        cancellation,
        loser_drain,
        region_close,
        obligation_balance,
        resource_surface: ResourceSurfaceRecord::empty(surface_scope),
    };

    (semantics, manifest)
}

/// Build a complete `NormalizedObservable` from a lab run.
///
/// Combines `normalize_lab_report` with identity and provenance.
#[must_use]
pub fn normalize_lab_observable(
    identity: &DualRunScenarioIdentity,
    report: &crate::lab::runtime::LabRunReport,
) -> NormalizedObservable {
    let (semantics, _manifest) = normalize_lab_report(report, &identity.surface_id);
    let mut prov = ReplayMetadata::for_lab(identity.family_id(), &identity.seed_plan);
    prov = prov.with_lab_report(
        report.trace_fingerprint,
        report.trace_certificate.event_hash,
        report.trace_certificate.event_count,
        report.trace_certificate.schedule_hash,
        report.steps_total,
    );
    NormalizedObservable::new(identity, RuntimeKind::Lab, semantics, prov)
}

/// Build a complete `NormalizedObservable` from a live run result.
#[must_use]
pub fn normalize_live_observable(
    identity: &DualRunScenarioIdentity,
    live_result: &LiveRunResult,
) -> NormalizedObservable {
    NormalizedObservable::new(
        identity,
        RuntimeKind::Live,
        live_result.semantics.clone(),
        live_result.metadata.replay.clone(),
    )
}

// ============================================================================
// Fuzz-to-Scenario Promotion
// ============================================================================

/// A promoted fuzz finding as a replayable dual-run scenario descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotedFuzzScenario {
    /// Dual-run scenario identity with seed plan derived from the finding.
    pub identity: DualRunScenarioIdentity,
    /// Original fuzz seed that discovered the issue.
    pub original_seed: u64,
    /// Minimized seed (if available), used as the canonical replay seed.
    pub replay_seed: u64,
    /// Violation categories observed.
    pub violation_categories: Vec<String>,
    /// Trace fingerprint from the failing lab run.
    pub trace_fingerprint: u64,
    /// Certificate hash from the failing lab run.
    pub certificate_hash: u64,
    /// Human-readable description of what was found.
    pub description: String,
    /// Provenance: which fuzz campaign produced this.
    pub campaign_base_seed: Option<u64>,
    /// Provenance: iteration index in the campaign.
    pub campaign_iteration: Option<usize>,
    /// Optional artifact path for the source fuzz or regression bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_artifact_path: Option<String>,
}

impl PromotedFuzzScenario {
    /// Default repro command for this scenario.
    #[must_use]
    pub fn repro_command(&self) -> String {
        format!(
            "ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
            self.replay_seed, self.identity.scenario_id
        )
    }

    /// Annotate the promoted scenario with the source artifact bundle path.
    #[must_use]
    pub fn with_source_artifact_path(mut self, path: impl Into<String>) -> Self {
        self.source_artifact_path = Some(path.into());
        self
    }

    /// Build lab replay metadata for this promoted fuzz scenario.
    #[must_use]
    pub fn lab_replay_metadata(&self) -> ReplayMetadata {
        let mut metadata = self
            .identity
            .lab_replay_metadata()
            .with_repro_command(self.repro_command());
        metadata.trace_fingerprint = Some(self.trace_fingerprint);
        if let Some(path) = &self.source_artifact_path {
            metadata = metadata.with_artifact_path(path.clone());
        }
        metadata
    }
}

impl fmt::Display for PromotedFuzzScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PromotedFuzz({}, seed=0x{:X}, violations=[{}])",
            self.identity.scenario_id,
            self.replay_seed,
            self.violation_categories.join(", ")
        )
    }
}

fn promoted_violation_categories(
    violations: &[crate::lab::runtime::InvariantViolation],
) -> Vec<String> {
    use crate::lab::runtime::InvariantViolation;

    let mut categories: Vec<String> = violations
        .iter()
        .map(|violation| match violation {
            InvariantViolation::ObligationLeak { .. } => "obligation_leak".to_string(),
            InvariantViolation::TaskLeak { .. } => "task_leak".to_string(),
            InvariantViolation::ActorLeak { .. } => "actor_leak".to_string(),
            InvariantViolation::QuiescenceViolation => "quiescence_violation".to_string(),
            InvariantViolation::Futurelock { .. } => "futurelock".to_string(),
        })
        .collect();
    categories.sort_unstable();
    categories.dedup();
    categories
}

/// Replayable differential scenario promoted from schedule exploration output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotedExplorationScenario {
    /// Replayable dual-run identity selected for the representative schedule.
    pub identity: DualRunScenarioIdentity,
    /// Representative seed chosen for replay/minimized regression coverage.
    pub replay_seed: u64,
    /// Canonical trace fingerprint for the promoted schedule class.
    pub trace_fingerprint: u64,
    /// Schedule hash for the representative run.
    pub representative_schedule_hash: u64,
    /// All seeds observed in the original exploration class.
    pub original_seeds: Vec<u64>,
    /// Seeds in the class that produced invariant violations.
    pub violation_seeds: Vec<u64>,
    /// Stable stringified violation summaries for this class.
    pub violation_summaries: Vec<String>,
    /// All schedule hashes observed in the class.
    pub supporting_schedule_hashes: Vec<u64>,
    /// Number of runs collapsed into this promoted class.
    pub class_run_count: usize,
    /// Total runs in the source exploration report.
    pub source_total_runs: usize,
    /// Total unique classes in the source exploration report.
    pub source_unique_classes: usize,
    /// Optional artifact path for the source exploration report bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_artifact_path: Option<String>,
    /// Human-readable scenario meaning.
    pub description: String,
}

impl PromotedExplorationScenario {
    /// Default repro command for this promoted schedule scenario.
    #[must_use]
    pub fn repro_command(&self) -> String {
        format!(
            "ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
            self.replay_seed, self.identity.scenario_id
        )
    }

    /// Annotate the promoted scenario with the source artifact bundle path.
    #[must_use]
    pub fn with_source_artifact_path(mut self, path: impl Into<String>) -> Self {
        self.source_artifact_path = Some(path.into());
        self
    }

    /// Build lab replay metadata for the representative schedule.
    #[must_use]
    pub fn lab_replay_metadata(&self) -> ReplayMetadata {
        let mut metadata = self
            .identity
            .lab_replay_metadata()
            .with_repro_command(self.repro_command());
        metadata.trace_fingerprint = Some(self.trace_fingerprint);
        metadata.schedule_hash = Some(self.representative_schedule_hash);
        if let Some(path) = &self.source_artifact_path {
            metadata = metadata.with_artifact_path(path.clone());
        }
        metadata
    }
}

impl fmt::Display for PromotedExplorationScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PromotedExploration({}, fingerprint=0x{:X}, seed=0x{:X}, runs={})",
            self.identity.scenario_id,
            self.trace_fingerprint,
            self.replay_seed,
            self.class_run_count
        )
    }
}

/// Promote a `FuzzFinding` into a replayable `DualRunScenarioIdentity`.
#[must_use]
pub fn promote_fuzz_finding(
    finding: &crate::lab::fuzz::FuzzFinding,
    surface_id: &str,
    contract_version: &str,
) -> PromotedFuzzScenario {
    let replay_seed = finding.minimized_seed.unwrap_or(finding.seed);
    let violation_cats = promoted_violation_categories(&finding.violations);
    let primary_violation = violation_cats.first().map_or("unknown", String::as_str);

    let scenario_id = format!(
        "fuzz.{surface_id}.{primary_violation}.seed_{:x}",
        replay_seed & 0xFFFF_FFFF
    );
    let description = format!(
        "Fuzz-discovered {primary_violation} adversarial case: {} violation(s) at seed 0x{:X}",
        finding.violations.len(),
        finding.seed
    );

    let identity = DualRunScenarioIdentity::phase1(
        &scenario_id,
        surface_id,
        contract_version,
        &description,
        replay_seed,
    )
    .with_metadata("promoted_from", "fuzz_finding")
    .with_metadata("original_seed", format!("0x{:X}", finding.seed))
    .with_metadata(
        "trace_fingerprint",
        format!("0x{:X}", finding.trace_fingerprint),
    )
    .with_metadata(
        "certificate_hash",
        format!("0x{:X}", finding.certificate_hash),
    )
    .with_metadata("violation_categories", violation_cats.join(","));

    PromotedFuzzScenario {
        identity,
        original_seed: finding.seed,
        replay_seed,
        violation_categories: violation_cats,
        trace_fingerprint: finding.trace_fingerprint,
        certificate_hash: finding.certificate_hash,
        description,
        campaign_base_seed: None,
        campaign_iteration: None,
        source_artifact_path: None,
    }
}

/// Promote a `FuzzRegressionCase` into a replayable scenario descriptor.
#[must_use]
pub fn promote_regression_case(
    case: &crate::lab::fuzz::FuzzRegressionCase,
    surface_id: &str,
    contract_version: &str,
) -> PromotedFuzzScenario {
    let primary_violation = case
        .violation_categories
        .first()
        .map_or("unknown", String::as_str);
    let scenario_id = format!(
        "regression.{surface_id}.{primary_violation}.seed_{:x}",
        case.replay_seed & 0xFFFF_FFFF
    );
    let description = format!(
        "Regression case ({primary_violation}): {} violation(s), replay seed 0x{:X}",
        case.violation_categories.len(),
        case.replay_seed
    );

    let identity = DualRunScenarioIdentity::phase1(
        &scenario_id,
        surface_id,
        contract_version,
        &description,
        case.replay_seed,
    )
    .with_metadata("promoted_from", "regression_case")
    .with_metadata("original_seed", format!("0x{:X}", case.seed))
    .with_metadata(
        "trace_fingerprint",
        format!("0x{:X}", case.trace_fingerprint),
    )
    .with_metadata("certificate_hash", format!("0x{:X}", case.certificate_hash))
    .with_metadata("violation_categories", case.violation_categories.join(","));

    PromotedFuzzScenario {
        identity,
        original_seed: case.seed,
        replay_seed: case.replay_seed,
        violation_categories: case.violation_categories.clone(),
        trace_fingerprint: case.trace_fingerprint,
        certificate_hash: case.certificate_hash,
        description,
        campaign_base_seed: None,
        campaign_iteration: None,
        source_artifact_path: None,
    }
}

/// Promote an entire `FuzzRegressionCorpus` into replayable scenarios.
#[must_use]
pub fn promote_regression_corpus(
    corpus: &crate::lab::fuzz::FuzzRegressionCorpus,
    surface_id: &str,
    contract_version: &str,
) -> Vec<PromotedFuzzScenario> {
    corpus
        .cases
        .iter()
        .enumerate()
        .map(|(i, case)| {
            let mut promoted = promote_regression_case(case, surface_id, contract_version);
            promoted.campaign_base_seed = Some(corpus.base_seed);
            promoted.campaign_iteration = Some(i);
            promoted.identity.metadata.insert(
                "campaign_base_seed".to_string(),
                format!("0x{:X}", corpus.base_seed),
            );
            promoted
                .identity
                .metadata
                .insert("campaign_iteration".to_string(), i.to_string());
            promoted
        })
        .collect()
}

/// Promote schedule-exploration classes into replayable differential scenarios.
///
/// The promotion rule keeps one representative run per canonical fingerprint
/// class. When a class contains violations, the smallest violating seed is
/// chosen so regression promotion remains focused on the failing lineage.
#[must_use]
pub fn promote_exploration_report(
    report: &crate::lab::explorer::ExplorationReport,
    surface_id: &str,
    contract_version: &str,
) -> Vec<PromotedExplorationScenario> {
    #[derive(Default)]
    struct ClassAggregate {
        seeds: Vec<u64>,
        schedule_hashes: Vec<u64>,
        run_count: usize,
        representative_schedule_hash: Option<u64>,
        violation_seeds: Vec<u64>,
        violation_summaries: Vec<String>,
    }

    let mut by_fingerprint: BTreeMap<u64, ClassAggregate> = BTreeMap::new();

    for run in &report.runs {
        let entry = by_fingerprint.entry(run.fingerprint).or_default();
        entry.seeds.push(run.seed);
        entry.schedule_hashes.push(run.certificate_hash);
        entry.run_count += 1;
        if entry.representative_schedule_hash.is_none() {
            entry.representative_schedule_hash = Some(run.certificate_hash);
        }
    }

    for violation in &report.violations {
        let entry = by_fingerprint.entry(violation.fingerprint).or_default();
        entry.violation_seeds.push(violation.seed);
        entry
            .violation_summaries
            .extend(violation.violations.iter().map(ToString::to_string));
    }

    by_fingerprint
        .into_iter()
        .map(|(trace_fingerprint, mut aggregate)| {
            aggregate.seeds.sort_unstable();
            aggregate.seeds.dedup();
            aggregate.schedule_hashes.sort_unstable();
            aggregate.schedule_hashes.dedup();
            aggregate.violation_seeds.sort_unstable();
            aggregate.violation_seeds.dedup();
            aggregate.violation_summaries.sort();
            aggregate.violation_summaries.dedup();

            let (replay_seed, representative_reason) =
                if let Some(seed) = aggregate.violation_seeds.first().copied() {
                    (seed, "lowest_violation_seed")
                } else {
                    (
                        *aggregate
                            .seeds
                            .first()
                            .expect("exploration class must contain at least one run"),
                        "lowest_seed",
                    )
                };

            let representative_schedule_hash = report
                .runs
                .iter()
                .find(|run| run.fingerprint == trace_fingerprint && run.seed == replay_seed)
                .map(|run| run.certificate_hash)
                .or(aggregate.representative_schedule_hash)
                .expect("exploration class must have a representative schedule hash");

            let scenario_id = format!(
                "schedule.{surface_id}.fp_{trace_fingerprint:016x}.seed_{:08x}",
                replay_seed & 0xFFFF_FFFF
            );
            let description = format!(
                "Promoted schedule exploration class 0x{trace_fingerprint:X}: {} run(s), representative seed 0x{replay_seed:X}",
                aggregate.run_count
            );

            let identity = DualRunScenarioIdentity::phase1(
                &scenario_id,
                surface_id,
                contract_version,
                &description,
                replay_seed,
            )
            .with_metadata("promoted_from", "exploration_report")
            .with_metadata("trace_fingerprint", format!("0x{trace_fingerprint:X}"))
            .with_metadata("class_run_count", aggregate.run_count.to_string())
            .with_metadata("source_total_runs", report.total_runs.to_string())
            .with_metadata("source_unique_classes", report.unique_classes.to_string())
            .with_metadata("representative_reason", representative_reason);

            PromotedExplorationScenario {
                identity,
                replay_seed,
                trace_fingerprint,
                representative_schedule_hash,
                original_seeds: aggregate.seeds,
                violation_seeds: aggregate.violation_seeds,
                violation_summaries: aggregate.violation_summaries,
                supporting_schedule_hashes: aggregate.schedule_hashes,
                class_run_count: aggregate.run_count,
                source_total_runs: report.total_runs,
                source_unique_classes: report.unique_classes,
                source_artifact_path: None,
                description,
            }
        })
        .collect()
}

// ============================================================================
// Dual-Run Harness Entrypoint
// ============================================================================

/// Result of a dual-run harness execution.
#[derive(Debug, Clone)]
pub struct DualRunResult {
    /// Lab-side normalized observable.
    pub lab: NormalizedObservable,
    /// Live-side normalized observable.
    pub live: NormalizedObservable,
    /// Comparison verdict.
    pub verdict: ComparisonVerdict,
    /// Core invariant violations for the lab run.
    pub lab_invariant_violations: Vec<String>,
    /// Core invariant violations for the live run.
    pub live_invariant_violations: Vec<String>,
    /// Seed lineage record.
    pub seed_lineage: SeedLineageRecord,
    /// Policy-layer classification and rerun plan.
    pub policy: DifferentialPolicyOutcome,
}

impl DualRunResult {
    /// Whether the dual-run passed: no semantic mismatches and no invariant
    /// violations on either side.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.verdict.passed
            && self.lab_invariant_violations.is_empty()
            && self.live_invariant_violations.is_empty()
    }

    /// Formatted summary of the result.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = vec![self.verdict.summary()];
        if !self.lab_invariant_violations.is_empty() {
            parts.push(format!(
                "Lab invariant violations: {}",
                self.lab_invariant_violations.join("; ")
            ));
        }
        if !self.live_invariant_violations.is_empty() {
            parts.push(format!(
                "Live invariant violations: {}",
                self.live_invariant_violations.join("; ")
            ));
        }
        parts.push(format!("Policy: {}", self.policy.summary()));
        parts.join("\n")
    }
}

impl fmt::Display for DualRunResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

/// Builder for dual-run differential test harnesses.
///
/// # Usage
///
/// ```ignore
/// let result = DualRunHarness::phase1(
///     "cancel.race.one_loser",
///     "cancellation.race",
///     "v1",
///     "Race two tasks, cancel loser, verify drain",
///     42,
/// )
/// .lab(|config| {
///     let mut lab = LabRuntime::new(config);
///     // ... run scenario ...
///     make_happy_semantics()
/// })
/// .live(|seed, entropy_seed| {
///     // ... run scenario on current-thread runtime ...
///     make_happy_semantics()
/// })
/// .run();
///
/// assert!(result.passed());
/// ```
pub struct DualRunHarness {
    identity: DualRunScenarioIdentity,
    lab_fn: Option<Box<dyn FnOnce(LabConfig) -> NormalizedSemantics>>,
    live_fn: Option<Box<dyn FnOnce(u64, u64) -> LiveExecutionCapture>>,
}

#[derive(Debug, Clone)]
struct LiveExecutionCapture {
    semantics: NormalizedSemantics,
    replay: Option<ReplayMetadata>,
}

impl From<NormalizedSemantics> for LiveExecutionCapture {
    fn from(semantics: NormalizedSemantics) -> Self {
        Self {
            semantics,
            replay: None,
        }
    }
}

impl From<LiveRunResult> for LiveExecutionCapture {
    fn from(result: LiveRunResult) -> Self {
        Self {
            semantics: result.semantics,
            replay: Some(
                result
                    .metadata
                    .replay
                    .with_nondeterminism_notes(result.metadata.nondeterminism_notes),
            ),
        }
    }
}

impl DualRunHarness {
    /// Create a Phase 1 harness builder.
    #[must_use]
    pub fn phase1(
        scenario_id: impl Into<String>,
        surface_id: impl Into<String>,
        contract_version: impl Into<String>,
        description: impl Into<String>,
        canonical_seed: u64,
    ) -> Self {
        Self {
            identity: DualRunScenarioIdentity::phase1(
                scenario_id,
                surface_id,
                contract_version,
                description,
                canonical_seed,
            ),
            lab_fn: None,
            live_fn: None,
        }
    }

    /// Create a harness from an existing identity.
    #[must_use]
    pub fn from_identity(identity: DualRunScenarioIdentity) -> Self {
        Self {
            identity,
            lab_fn: None,
            live_fn: None,
        }
    }

    /// Set the lab execution function.
    ///
    /// Receives a `LabConfig` derived from the seed plan. Must return
    /// normalized semantics from the lab execution.
    #[must_use]
    pub fn lab(mut self, f: impl FnOnce(LabConfig) -> NormalizedSemantics + 'static) -> Self {
        self.lab_fn = Some(Box::new(f));
        self
    }

    /// Set the live execution function.
    ///
    /// Receives `(effective_seed, entropy_seed)` derived from the seed plan.
    /// Must return normalized semantics from the live execution.
    #[must_use]
    pub fn live(mut self, f: impl FnOnce(u64, u64) -> NormalizedSemantics + 'static) -> Self {
        self.live_fn = Some(Box::new(move |seed, entropy| f(seed, entropy).into()));
        self
    }

    /// Set the live execution function using the richer `LiveRunResult`.
    ///
    /// This preserves nondeterminism notes and replay metadata so the
    /// mismatch classifier can distinguish scheduler noise from semantic drift.
    #[must_use]
    pub fn live_result(mut self, f: impl FnOnce(u64, u64) -> LiveRunResult + 'static) -> Self {
        self.live_fn = Some(Box::new(move |seed, entropy| f(seed, entropy).into()));
        self
    }

    /// Override the seed plan.
    #[must_use]
    pub fn with_seed_plan(mut self, plan: SeedPlan) -> Self {
        self.identity.seed_plan = plan;
        self
    }

    /// Execute both sides and produce a comparison result.
    ///
    /// # Panics
    ///
    /// Panics if either `lab` or `live` was not set.
    #[must_use]
    pub fn run(self) -> DualRunResult {
        let lab_fn = self.lab_fn.expect("DualRunHarness: lab function not set");
        let live_fn = self.live_fn.expect("DualRunHarness: live function not set");

        let plan = &self.identity.seed_plan;
        let family = self.identity.family_id();

        // Run lab side.
        let lab_config = plan.to_lab_config();
        let lab_semantics = lab_fn(lab_config);
        let lab_prov = ReplayMetadata::for_lab(family.clone(), plan);
        let lab_obs =
            NormalizedObservable::new(&self.identity, RuntimeKind::Lab, lab_semantics, lab_prov);

        // Run live side.
        let live_seed = plan.effective_live_seed();
        let live_entropy = plan.effective_entropy_seed(live_seed);
        let live_capture = live_fn(live_seed, live_entropy);
        let live_semantics = live_capture.semantics;
        let live_prov = live_capture
            .replay
            .unwrap_or_else(|| ReplayMetadata::for_live(family, plan));
        let live_obs =
            NormalizedObservable::new(&self.identity, RuntimeKind::Live, live_semantics, live_prov);

        // Check invariants.
        let lab_violations = check_core_invariants(&lab_obs);
        let live_violations = check_core_invariants(&live_obs);

        // Compare.
        let lineage = SeedLineageRecord::from_plan(plan);
        let verdict = compare_observables(&lab_obs, &live_obs, lineage.clone());
        let policy = classify_differential_policy(
            &self.identity,
            &lab_obs,
            &live_obs,
            &verdict,
            &lab_violations,
            &live_violations,
        );

        // Log result.
        #[cfg(feature = "tracing-integration")]
        tracing::info!(
            scenario_id = %self.identity.scenario_id,
            surface_id = %self.identity.surface_id,
            seed = %format_args!("0x{:X}", plan.canonical_seed),
            passed = verdict.passed,
            lab_violations = lab_violations.len(),
            live_violations = live_violations.len(),
            mismatches = verdict.mismatches.len(),
            provisional_class = %policy.provisional_class,
            rerun_decision = %policy.rerun_decision,
            time_policy_class = %policy.time_policy_class,
            scheduler_noise_class = %policy.scheduler_noise_class,
            suppression_reason = ?policy.suppression_reason,
            "DUAL_RUN_RESULT"
        );

        DualRunResult {
            lab: lab_obs,
            live: live_obs,
            verdict,
            lab_invariant_violations: lab_violations,
            live_invariant_violations: live_violations,
            seed_lineage: lineage,
            policy,
        }
    }
}

/// Convenience: run a dual-run test and assert it passes.
///
/// Panics with a detailed message if the test fails.
pub fn assert_dual_run_passes(result: &DualRunResult) {
    assert!(
        result.passed(),
        "Dual-run test failed for scenario '{}' on surface '{}':\n{}",
        result.verdict.scenario_id,
        result.verdict.surface_id,
        result.summary()
    );
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    // --- SeedMode ---

    #[test]
    fn seed_mode_serde_roundtrip() {
        init_test("seed_mode_serde_roundtrip");
        let json = serde_json::to_string(&SeedMode::Inherit).unwrap();
        assert_eq!(json, "\"inherit\"");
        let parsed: SeedMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SeedMode::Inherit);

        let json = serde_json::to_string(&SeedMode::Override).unwrap();
        assert_eq!(json, "\"override\"");
        let parsed: SeedMode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SeedMode::Override);
        crate::test_complete!("seed_mode_serde_roundtrip");
    }

    // --- ReplayPolicy ---

    #[test]
    fn replay_policy_serde_roundtrip() {
        init_test("replay_policy_serde_roundtrip");
        for policy in [
            ReplayPolicy::SingleSeed,
            ReplayPolicy::SeedSweep,
            ReplayPolicy::ReplayBundle,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let parsed: ReplayPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, policy);
        }
        crate::test_complete!("replay_policy_serde_roundtrip");
    }

    // --- SeedPlan ---

    #[test]
    fn seed_plan_inherit_uses_canonical() {
        init_test("seed_plan_inherit_uses_canonical");
        let plan = SeedPlan::inherit(0xBEEF, "test-scenario");
        assert_eq!(plan.effective_lab_seed(), 0xBEEF);
        assert_eq!(plan.effective_live_seed(), 0xBEEF);
        assert_eq!(plan.lab_seed_mode, SeedMode::Inherit);
        assert_eq!(plan.live_seed_mode, SeedMode::Inherit);
        crate::test_complete!("seed_plan_inherit_uses_canonical");
    }

    #[test]
    fn seed_plan_override_uses_explicit_seed() {
        init_test("seed_plan_override_uses_explicit_seed");
        let plan = SeedPlan::inherit(0xBEEF, "test")
            .with_lab_override(0xCAFE)
            .with_live_override(0xFACE);
        assert_eq!(plan.effective_lab_seed(), 0xCAFE);
        assert_eq!(plan.effective_live_seed(), 0xFACE);
        assert_eq!(plan.lab_seed_mode, SeedMode::Override);
        assert_eq!(plan.live_seed_mode, SeedMode::Override);
        crate::test_complete!("seed_plan_override_uses_explicit_seed");
    }

    #[test]
    fn seed_plan_override_without_value_falls_back_to_canonical() {
        init_test("seed_plan_override_without_value_falls_back");
        let mut plan = SeedPlan::inherit(0xBEEF, "test");
        plan.lab_seed_mode = SeedMode::Override;
        // No lab_seed_override set — should fall back to canonical.
        assert_eq!(plan.effective_lab_seed(), 0xBEEF);
        crate::test_complete!("seed_plan_override_without_value_falls_back");
    }

    #[test]
    fn seed_plan_entropy_derives_from_effective() {
        init_test("seed_plan_entropy_derives_from_effective");
        let plan = SeedPlan::inherit(42, "test");
        let entropy = plan.effective_entropy_seed(42);
        // Must be deterministic.
        assert_eq!(entropy, plan.effective_entropy_seed(42));
        // Must differ from the seed itself (extremely unlikely to collide).
        assert_ne!(entropy, 42);
        crate::test_complete!("seed_plan_entropy_derives_from_effective");
    }

    #[test]
    fn seed_plan_entropy_override() {
        init_test("seed_plan_entropy_override");
        let plan = SeedPlan::inherit(42, "test").with_entropy_seed(999);
        assert_eq!(plan.effective_entropy_seed(42), 999);
        assert_eq!(plan.effective_entropy_seed(100), 999);
        crate::test_complete!("seed_plan_entropy_override");
    }

    #[test]
    fn seed_plan_to_lab_config() {
        init_test("seed_plan_to_lab_config");
        let plan = SeedPlan::inherit(0xDEAD, "test");
        let config = plan.to_lab_config();
        assert_eq!(config.seed, 0xDEAD);
        let expected_entropy = plan.effective_entropy_seed(0xDEAD);
        assert_eq!(config.entropy_seed, expected_entropy);
        crate::test_complete!("seed_plan_to_lab_config");
    }

    #[test]
    fn seed_plan_to_lab_config_with_override() {
        init_test("seed_plan_to_lab_config_with_override");
        let plan = SeedPlan::inherit(0xDEAD, "test").with_lab_override(0xCAFE);
        let config = plan.to_lab_config();
        assert_eq!(config.seed, 0xCAFE);
        crate::test_complete!("seed_plan_to_lab_config_with_override");
    }

    #[test]
    fn seed_plan_sweep_deterministic() {
        init_test("seed_plan_sweep_deterministic");
        let plan = SeedPlan::inherit(42, "test").with_replay_policy(ReplayPolicy::SeedSweep);
        let seeds1 = plan.sweep_seeds(5);
        let seeds2 = plan.sweep_seeds(5);
        assert_eq!(seeds1, seeds2);
        assert_eq!(seeds1.len(), 5);
        // All seeds should be distinct.
        let mut unique = seeds1;
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 5);
        crate::test_complete!("seed_plan_sweep_deterministic");
    }

    #[test]
    fn seed_plan_serde_roundtrip() {
        init_test("seed_plan_serde_roundtrip");
        let plan = SeedPlan::inherit(0xABCD, "lineage-1")
            .with_lab_override(0x1234)
            .with_entropy_seed(0x5678)
            .with_replay_policy(ReplayPolicy::SeedSweep);
        let json = serde_json::to_string_pretty(&plan).unwrap();
        let parsed: SeedPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, plan);
        crate::test_complete!("seed_plan_serde_roundtrip");
    }

    #[test]
    fn seed_plan_display() {
        init_test("seed_plan_display");
        let plan = SeedPlan::inherit(42, "test-scenario");
        let display = format!("{plan}");
        assert!(display.contains("0x2A"));
        assert!(display.contains("test-scenario"));
        crate::test_complete!("seed_plan_display");
    }

    // --- ScenarioFamilyId ---

    #[test]
    fn scenario_family_id_display() {
        init_test("scenario_family_id_display");
        let fam = ScenarioFamilyId::new("cancel.race", "cancellation.race", "v1");
        let s = format!("{fam}");
        assert!(s.contains("cancel.race"));
        assert!(s.contains("cancellation.race"));
        assert!(s.contains("v1"));
        crate::test_complete!("scenario_family_id_display");
    }

    #[test]
    fn scenario_family_id_serde_roundtrip() {
        init_test("scenario_family_id_serde_roundtrip");
        let fam = ScenarioFamilyId::new("cancel.race", "cancellation.race", "v1");
        let json = serde_json::to_string(&fam).unwrap();
        let parsed: ScenarioFamilyId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, fam);
        crate::test_complete!("scenario_family_id_serde_roundtrip");
    }

    // --- ExecutionInstanceId ---

    #[test]
    fn execution_instance_lab_vs_live() {
        init_test("execution_instance_lab_vs_live");
        let lab = ExecutionInstanceId::lab("test-family", 42);
        let live = ExecutionInstanceId::live("test-family", 42);
        assert_eq!(lab.runtime_kind, RuntimeKind::Lab);
        assert_eq!(live.runtime_kind, RuntimeKind::Live);
        assert_ne!(lab.key(), live.key());
        crate::test_complete!("execution_instance_lab_vs_live");
    }

    #[test]
    fn execution_instance_key_stable() {
        init_test("execution_instance_key_stable");
        let inst = ExecutionInstanceId::lab("fam", 0xBEEF).with_run_index(3);
        let key1 = inst.key();
        let key2 = inst.key();
        assert_eq!(key1, key2);
        assert!(key1.contains("fam"));
        assert!(key1.contains("0xBEEF"));
        assert!(key1.contains('3'));
        crate::test_complete!("execution_instance_key_stable");
    }

    // --- RuntimeKind ---

    #[test]
    fn runtime_kind_display() {
        init_test("runtime_kind_display");
        assert_eq!(format!("{}", RuntimeKind::Lab), "lab");
        assert_eq!(format!("{}", RuntimeKind::Live), "live");
        crate::test_complete!("runtime_kind_display");
    }

    // --- ReplayMetadata ---

    #[test]
    fn replay_metadata_lab_seeds_match_plan() {
        init_test("replay_metadata_lab_seeds_match_plan");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(0xDEAD, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan);
        assert_eq!(meta.effective_seed, 0xDEAD);
        assert_eq!(meta.instance.runtime_kind, RuntimeKind::Lab);
        assert_eq!(
            meta.effective_entropy_seed,
            plan.effective_entropy_seed(0xDEAD)
        );
        crate::test_complete!("replay_metadata_lab_seeds_match_plan");
    }

    #[test]
    fn replay_metadata_live_seeds_match_plan() {
        init_test("replay_metadata_live_seeds_match_plan");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(0xCAFE, "lineage");
        let meta = ReplayMetadata::for_live(family, &plan);
        assert_eq!(meta.effective_seed, 0xCAFE);
        assert_eq!(meta.instance.runtime_kind, RuntimeKind::Live);
        crate::test_complete!("replay_metadata_live_seeds_match_plan");
    }

    #[test]
    fn replay_metadata_with_overrides() {
        init_test("replay_metadata_with_overrides");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(42, "lineage").with_lab_override(999);
        let meta = ReplayMetadata::for_lab(family, &plan);
        assert_eq!(meta.effective_seed, 999);
        crate::test_complete!("replay_metadata_with_overrides");
    }

    #[test]
    fn replay_metadata_with_lab_report() {
        init_test("replay_metadata_with_lab_report");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(42, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan)
            .with_lab_report(0xF1, 0xE1, 100, 0x51, 500)
            .with_repro_command("cargo test test -- --nocapture")
            .with_artifact_path("/tmp/artifacts/test");
        assert_eq!(meta.trace_fingerprint, Some(0xF1));
        assert_eq!(meta.event_count, Some(100));
        assert_eq!(meta.steps_total, Some(500));
        assert!(meta.repro_command.is_some());
        assert!(meta.artifact_path.is_some());
        crate::test_complete!("replay_metadata_with_lab_report");
    }

    #[test]
    fn replay_metadata_default_repro_command() {
        init_test("replay_metadata_default_repro_command");
        let family = ScenarioFamilyId::new("cancel.race", "surface", "v1");
        let plan = SeedPlan::inherit(0xDEAD, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan);
        let cmd = meta.default_repro_command();
        assert!(cmd.contains("0xDEAD"));
        assert!(cmd.contains("cancel.race"));
        crate::test_complete!("replay_metadata_default_repro_command");
    }

    #[test]
    fn replay_metadata_serde_roundtrip() {
        init_test("replay_metadata_serde_roundtrip");
        let family = ScenarioFamilyId::new("test", "surface", "v1");
        let plan = SeedPlan::inherit(42, "lineage");
        let meta = ReplayMetadata::for_lab(family, &plan).with_repro_command("cargo test");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        let parsed: ReplayMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.effective_seed, meta.effective_seed);
        assert_eq!(parsed.family.id, "test");
        crate::test_complete!("replay_metadata_serde_roundtrip");
    }

    // --- SeedLineageRecord ---

    #[test]
    fn seed_lineage_record_inherit_seeds_match() {
        init_test("seed_lineage_record_inherit_seeds_match");
        let plan = SeedPlan::inherit(0xBEEF, "lineage-1");
        let record = SeedLineageRecord::from_plan(&plan);
        assert!(record.seeds_match);
        assert_eq!(record.lab_effective_seed, 0xBEEF);
        assert_eq!(record.live_effective_seed, 0xBEEF);
        assert_eq!(record.lab_entropy_seed, record.live_entropy_seed);
        crate::test_complete!("seed_lineage_record_inherit_seeds_match");
    }

    #[test]
    fn seed_lineage_record_override_seeds_differ() {
        init_test("seed_lineage_record_override_seeds_differ");
        let plan = SeedPlan::inherit(42, "lineage-1")
            .with_lab_override(100)
            .with_live_override(200);
        let record = SeedLineageRecord::from_plan(&plan);
        assert!(!record.seeds_match);
        assert_eq!(record.lab_effective_seed, 100);
        assert_eq!(record.live_effective_seed, 200);
        crate::test_complete!("seed_lineage_record_override_seeds_differ");
    }

    #[test]
    fn seed_lineage_record_serde_roundtrip() {
        init_test("seed_lineage_record_serde_roundtrip");
        let plan = SeedPlan::inherit(42, "lin");
        let record = SeedLineageRecord::from_plan(&plan).with_annotation("source", "test");
        let json = serde_json::to_string(&record).unwrap();
        let parsed: SeedLineageRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.canonical_seed, 42);
        assert_eq!(parsed.annotations.get("source").unwrap(), "test");
        crate::test_complete!("seed_lineage_record_serde_roundtrip");
    }

    // --- DualRunScenarioIdentity ---

    #[test]
    fn dual_run_scenario_identity_phase1() {
        init_test("dual_run_scenario_identity_phase1");
        let ident = DualRunScenarioIdentity::phase1(
            "phase1.cancel.race.one_loser",
            "cancellation.race",
            "v1",
            "Race two tasks, cancel loser, verify drain",
            42,
        );
        assert_eq!(ident.schema_version, DUAL_RUN_SCHEMA_VERSION);
        assert_eq!(ident.phase, Phase::Phase1);
        assert_eq!(ident.seed_plan.canonical_seed, 42);
        assert_eq!(
            ident.seed_plan.seed_lineage_id,
            "phase1.cancel.race.one_loser"
        );
        crate::test_complete!("dual_run_scenario_identity_phase1");
    }

    #[test]
    fn dual_run_identity_lab_config() {
        init_test("dual_run_identity_lab_config");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 0xBEEF);
        let config = ident.to_lab_config();
        assert_eq!(config.seed, 0xBEEF);
        crate::test_complete!("dual_run_identity_lab_config");
    }

    #[test]
    fn dual_run_identity_replay_metadata_lab_live_differ() {
        init_test("dual_run_identity_replay_metadata_lab_live_differ");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let lab_meta = ident.lab_replay_metadata();
        let live_meta = ident.live_replay_metadata();
        assert_eq!(lab_meta.instance.runtime_kind, RuntimeKind::Lab);
        assert_eq!(live_meta.instance.runtime_kind, RuntimeKind::Live);
        // With inherit mode, effective seeds match.
        assert_eq!(lab_meta.effective_seed, live_meta.effective_seed);
        crate::test_complete!("dual_run_identity_replay_metadata_lab_live_differ");
    }

    #[test]
    fn dual_run_identity_family_id() {
        init_test("dual_run_identity_family_id");
        let ident = DualRunScenarioIdentity::phase1("test", "surface", "v1", "desc", 42);
        let fam = ident.family_id();
        assert_eq!(fam.id, "test");
        assert_eq!(fam.surface_id, "surface");
        assert_eq!(fam.surface_contract_version, "v1");
        crate::test_complete!("dual_run_identity_family_id");
    }

    #[test]
    fn dual_run_identity_seed_lineage() {
        init_test("dual_run_identity_seed_lineage");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let lineage = ident.seed_lineage();
        assert!(lineage.seeds_match);
        assert_eq!(lineage.canonical_seed, 42);
        crate::test_complete!("dual_run_identity_seed_lineage");
    }

    #[test]
    fn dual_run_identity_with_seed_plan_override() {
        init_test("dual_run_identity_with_seed_plan_override");
        let plan = SeedPlan::inherit(99, "custom-lineage").with_lab_override(0xFF);
        let ident =
            DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42).with_seed_plan(plan);
        assert_eq!(ident.seed_plan.canonical_seed, 99);
        assert_eq!(ident.to_lab_config().seed, 0xFF);
        crate::test_complete!("dual_run_identity_with_seed_plan_override");
    }

    #[test]
    fn dual_run_identity_metadata() {
        init_test("dual_run_identity_metadata");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42)
            .with_metadata("bead", "2a6k9.2.3")
            .with_metadata("author", "SapphireHill");
        assert_eq!(ident.metadata.get("bead").unwrap(), "2a6k9.2.3");
        assert_eq!(ident.metadata.get("author").unwrap(), "SapphireHill");
        crate::test_complete!("dual_run_identity_metadata");
    }

    #[test]
    fn dual_run_identity_serde_roundtrip() {
        init_test("dual_run_identity_serde_roundtrip");
        let ident = DualRunScenarioIdentity::phase1(
            "phase1.cancel.race.one_loser",
            "cancellation.race",
            "v1",
            "Race two tasks, cancel loser, verify drain",
            42,
        )
        .with_metadata("bead", "2a6k9.2.3");
        let json = serde_json::to_string_pretty(&ident).unwrap();
        let parsed: DualRunScenarioIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scenario_id, ident.scenario_id);
        assert_eq!(parsed.seed_plan, ident.seed_plan);
        assert_eq!(parsed.phase, Phase::Phase1);
        crate::test_complete!("dual_run_identity_serde_roundtrip");
    }

    // --- Cross-cutting: seed determinism across lab and live ---

    #[test]
    fn same_plan_produces_same_lab_config() {
        init_test("same_plan_produces_same_lab_config");
        let plan = SeedPlan::inherit(0xCAFE_BABE, "determinism-check");
        let c1 = plan.to_lab_config();
        let c2 = plan.to_lab_config();
        assert_eq!(c1.seed, c2.seed);
        assert_eq!(c1.entropy_seed, c2.entropy_seed);
        crate::test_complete!("same_plan_produces_same_lab_config");
    }

    #[test]
    fn inherit_mode_lab_live_seeds_identical() {
        init_test("inherit_mode_lab_live_seeds_identical");
        let plan = SeedPlan::inherit(0xDEAD_BEEF, "identical-check");
        assert_eq!(plan.effective_lab_seed(), plan.effective_live_seed());
        let lab_ent = plan.effective_entropy_seed(plan.effective_lab_seed());
        let live_ent = plan.effective_entropy_seed(plan.effective_live_seed());
        assert_eq!(lab_ent, live_ent);
        crate::test_complete!("inherit_mode_lab_live_seeds_identical");
    }

    #[test]
    fn different_canonical_seeds_produce_different_entropies() {
        init_test("different_canonical_seeds_different_entropies");
        let p1 = SeedPlan::inherit(1, "a");
        let p2 = SeedPlan::inherit(2, "b");
        assert_ne!(
            p1.effective_entropy_seed(p1.effective_lab_seed()),
            p2.effective_entropy_seed(p2.effective_lab_seed())
        );
        crate::test_complete!("different_canonical_seeds_different_entropies");
    }

    // --- Normalized Observable types ---

    fn make_happy_semantics() -> NormalizedSemantics {
        NormalizedSemantics {
            terminal_outcome: TerminalOutcome::ok(),
            cancellation: CancellationRecord::none(),
            loser_drain: LoserDrainRecord::not_applicable(),
            region_close: RegionCloseRecord::quiescent(),
            obligation_balance: ObligationBalanceRecord::zero(),
            resource_surface: ResourceSurfaceRecord::empty("test"),
        }
    }

    fn make_observable(kind: RuntimeKind, semantics: NormalizedSemantics) -> NormalizedObservable {
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let prov = match kind {
            RuntimeKind::Lab => ident.lab_replay_metadata(),
            RuntimeKind::Live => ident.live_replay_metadata(),
        };
        NormalizedObservable::new(&ident, kind, semantics, prov)
    }

    #[test]
    fn terminal_outcome_ok_serde() {
        init_test("terminal_outcome_ok_serde");
        let t = TerminalOutcome::ok();
        let json = serde_json::to_string(&t).unwrap();
        let parsed: TerminalOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.class, OutcomeClass::Ok);
        crate::test_complete!("terminal_outcome_ok_serde");
    }

    #[test]
    fn terminal_outcome_cancelled() {
        init_test("terminal_outcome_cancelled");
        let t = TerminalOutcome::cancelled("user_request");
        assert_eq!(t.class, OutcomeClass::Cancelled);
        assert_eq!(t.cancel_reason_class.as_deref(), Some("user_request"));
        crate::test_complete!("terminal_outcome_cancelled");
    }

    #[test]
    fn cancellation_record_none_vs_completed() {
        init_test("cancellation_record_none_vs_completed");
        let none = CancellationRecord::none();
        let completed = CancellationRecord::completed();
        assert!(!none.requested);
        assert!(completed.requested);
        assert!(completed.acknowledged);
        assert!(completed.cleanup_completed);
        assert!(completed.finalization_completed);
        assert_eq!(completed.terminal_phase, CancelTerminalPhase::Completed);
        crate::test_complete!("cancellation_record_none_vs_completed");
    }

    #[test]
    fn loser_drain_complete() {
        init_test("loser_drain_complete");
        let drain = LoserDrainRecord::complete(3);
        assert!(drain.applicable);
        assert_eq!(drain.expected_losers, 3);
        assert_eq!(drain.drained_losers, 3);
        assert_eq!(drain.status, DrainStatus::Complete);
        crate::test_complete!("loser_drain_complete");
    }

    #[test]
    fn obligation_balance_recompute() {
        init_test("obligation_balance_recompute");
        let b = ObligationBalanceRecord {
            reserved: 10,
            committed: 7,
            aborted: 2,
            leaked: 1,
            unresolved: 99, // wrong, should recompute
            balanced: true, // wrong
        }
        .recompute();
        assert_eq!(b.unresolved, 0); // 10 - (7+2+1) = 0
        assert!(!b.balanced); // leaked > 0
        crate::test_complete!("obligation_balance_recompute");
    }

    #[test]
    fn resource_surface_counter_tolerance() {
        init_test("resource_surface_counter_tolerance");
        let rs = ResourceSurfaceRecord::empty("test-surface")
            .with_counter("msgs", 5)
            .with_counter_tolerance("bytes", 100, CounterTolerance::AtLeast);
        assert_eq!(rs.counters["msgs"], 5);
        assert_eq!(rs.tolerances["msgs"], CounterTolerance::Exact);
        assert_eq!(rs.tolerances["bytes"], CounterTolerance::AtLeast);
        crate::test_complete!("resource_surface_counter_tolerance");
    }

    #[test]
    fn normalized_observable_serde_roundtrip() {
        init_test("normalized_observable_serde_roundtrip");
        let obs = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let json = serde_json::to_string_pretty(&obs).unwrap();
        let parsed: NormalizedObservable = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, NORMALIZED_OBSERVABLE_SCHEMA_VERSION);
        assert_eq!(parsed.runtime_kind, RuntimeKind::Lab);
        assert_eq!(parsed.semantics.terminal_outcome.class, OutcomeClass::Ok);
        crate::test_complete!("normalized_observable_serde_roundtrip");
    }

    // --- Compare / Verdict ---

    #[test]
    fn compare_identical_observables_passes() {
        init_test("compare_identical_observables_passes");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let live = make_observable(RuntimeKind::Live, make_happy_semantics());
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(verdict.passed);
        assert!(verdict.mismatches.is_empty());
        crate::test_complete!("compare_identical_observables_passes");
    }

    #[test]
    fn compare_outcome_mismatch_fails() {
        init_test("compare_outcome_mismatch_fails");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.terminal_outcome = TerminalOutcome::cancelled("timeout");
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("terminal_outcome.class"))
        );
        crate::test_complete!("compare_outcome_mismatch_fails");
    }

    #[test]
    fn compare_surface_identity_mismatch_fails() {
        init_test("compare_surface_identity_mismatch_fails");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let mut live = make_observable(RuntimeKind::Live, make_happy_semantics());
        live.surface_id = "different.surface".to_string();
        live.surface_contract_version = "v2".to_string();
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(verdict.mismatches.iter().any(|m| m.field == "surface_id"));
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "surface_contract_version")
        );
        crate::test_complete!("compare_surface_identity_mismatch_fails");
    }

    #[test]
    fn compare_terminal_reason_and_panic_class_mismatch_fails() {
        init_test("compare_terminal_reason_and_panic_class_mismatch_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.terminal_outcome = TerminalOutcome::cancelled("timeout");

        let mut live_sem = make_happy_semantics();
        live_sem.terminal_outcome = TerminalOutcome::cancelled("shutdown");

        let lab = make_observable(RuntimeKind::Lab, lab_sem.clone());
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| { m.field == "semantics.terminal_outcome.cancel_reason_class" })
        );

        let mut panic_sem = lab_sem;
        panic_sem.terminal_outcome = TerminalOutcome {
            class: OutcomeClass::Panicked,
            severity: OutcomeClass::Panicked,
            surface_result: None,
            error_class: None,
            cancel_reason_class: None,
            panic_class: Some("panic_a".to_string()),
        };
        let mut other_panic_sem = make_happy_semantics();
        other_panic_sem.terminal_outcome = TerminalOutcome {
            class: OutcomeClass::Panicked,
            severity: OutcomeClass::Panicked,
            surface_result: None,
            error_class: None,
            cancel_reason_class: None,
            panic_class: Some("panic_b".to_string()),
        };
        let panic_lab = make_observable(RuntimeKind::Lab, panic_sem);
        let panic_live = make_observable(RuntimeKind::Live, other_panic_sem);
        let panic_verdict =
            compare_observables(&panic_lab, &panic_live, SeedLineageRecord::from_plan(&plan));
        assert!(!panic_verdict.passed);
        assert!(
            panic_verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.terminal_outcome.panic_class")
        );
        crate::test_complete!("compare_terminal_reason_and_panic_class_mismatch_fails");
    }

    #[test]
    fn compare_obligation_leak_mismatch() {
        init_test("compare_obligation_leak_mismatch");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.obligation_balance = ObligationBalanceRecord {
            reserved: 5,
            committed: 3,
            aborted: 0,
            leaked: 2,
            unresolved: 0,
            balanced: false,
        };
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("leaked"))
        );
        crate::test_complete!("compare_obligation_leak_mismatch");
    }

    #[test]
    fn compare_obligation_component_mismatch_fails_even_when_balanced() {
        init_test("compare_obligation_component_mismatch_fails_even_when_balanced");
        let mut lab_sem = make_happy_semantics();
        lab_sem.obligation_balance = ObligationBalanceRecord::balanced(3, 3, 0);
        let mut live_sem = make_happy_semantics();
        live_sem.obligation_balance = ObligationBalanceRecord::balanced(3, 2, 1);
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.obligation_balance.committed")
        );
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.obligation_balance.aborted")
        );
        crate::test_complete!("compare_obligation_component_mismatch_fails_even_when_balanced");
    }

    #[test]
    fn compare_resource_counter_exact_mismatch() {
        init_test("compare_resource_counter_exact_mismatch");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 5);
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 3);
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("counters.msgs"))
        );
        crate::test_complete!("compare_resource_counter_exact_mismatch");
    }

    #[test]
    fn compare_resource_counter_missing_in_live_fails() {
        init_test("compare_resource_counter_missing_in_live_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 0);
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test");
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.description.contains("missing in live observable"))
        );
        crate::test_complete!("compare_resource_counter_missing_in_live_fails");
    }

    #[test]
    fn compare_resource_counter_missing_in_lab_fails() {
        init_test("compare_resource_counter_missing_in_lab_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test");
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter("msgs", 0);
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.description.contains("present in live but not in lab"))
        );
        crate::test_complete!("compare_resource_counter_missing_in_lab_fails");
    }

    #[test]
    fn compare_resource_tolerance_mismatch_fails() {
        init_test("compare_resource_tolerance_mismatch_fails");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            5,
            CounterTolerance::Exact,
        );
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            5,
            CounterTolerance::Unsupported,
        );
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.resource_surface.tolerances.msgs")
        );
        crate::test_complete!("compare_resource_tolerance_mismatch_fails");
    }

    #[test]
    fn compare_resource_counter_at_least_passes() {
        init_test("compare_resource_counter_at_least_passes");
        let mut lab_sem = make_happy_semantics();
        lab_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            5,
            CounterTolerance::AtLeast,
        );
        let mut live_sem = make_happy_semantics();
        live_sem.resource_surface = ResourceSurfaceRecord::empty("test").with_counter_tolerance(
            "msgs",
            7,
            CounterTolerance::AtLeast,
        );
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(verdict.passed);
        crate::test_complete!("compare_resource_counter_at_least_passes");
    }

    #[test]
    fn compare_region_close_counts_mismatch_fails() {
        init_test("compare_region_close_counts_mismatch_fails");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.region_close.live_children = 1;
        live_sem.region_close.finalizers_pending = 2;
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.region_close.live_children")
        );
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field == "semantics.region_close.finalizers_pending")
        );
        crate::test_complete!("compare_region_close_counts_mismatch_fails");
    }

    #[test]
    fn compare_cancellation_mismatch() {
        init_test("compare_cancellation_mismatch");
        let mut lab_sem = make_happy_semantics();
        lab_sem.cancellation = CancellationRecord::completed();
        let live_sem = make_happy_semantics(); // no cancellation
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        assert!(!verdict.passed);
        assert!(
            verdict
                .mismatches
                .iter()
                .any(|m| m.field.contains("cancellation"))
        );
        crate::test_complete!("compare_cancellation_mismatch");
    }

    #[test]
    fn verdict_display_pass() {
        init_test("verdict_display_pass");
        let lab = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let live = make_observable(RuntimeKind::Live, make_happy_semantics());
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        let summary = verdict.summary();
        assert!(summary.contains("PASS"));
        crate::test_complete!("verdict_display_pass");
    }

    #[test]
    fn verdict_display_fail() {
        init_test("verdict_display_fail");
        let lab_sem = make_happy_semantics();
        let mut live_sem = make_happy_semantics();
        live_sem.region_close.quiescent = false;
        let lab = make_observable(RuntimeKind::Lab, lab_sem);
        let live = make_observable(RuntimeKind::Live, live_sem);
        let plan = SeedPlan::inherit(42, "test");
        let verdict = compare_observables(&lab, &live, SeedLineageRecord::from_plan(&plan));
        let summary = verdict.summary();
        assert!(summary.contains("FAIL"));
        assert!(summary.contains("mismatch"));
        crate::test_complete!("verdict_display_fail");
    }

    // --- Core Invariant Checks ---

    #[test]
    fn check_core_invariants_all_pass() {
        init_test("check_core_invariants_all_pass");
        let obs = make_observable(RuntimeKind::Lab, make_happy_semantics());
        let violations = check_core_invariants(&obs);
        assert!(violations.is_empty());
        crate::test_complete!("check_core_invariants_all_pass");
    }

    #[test]
    fn check_core_invariants_obligation_leak() {
        init_test("check_core_invariants_obligation_leak");
        let mut sem = make_happy_semantics();
        sem.obligation_balance.leaked = 1;
        sem.obligation_balance.balanced = false;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(!violations.is_empty());
        assert!(violations[0].contains("leaked"));
        crate::test_complete!("check_core_invariants_obligation_leak");
    }

    #[test]
    fn check_core_invariants_not_quiescent() {
        init_test("check_core_invariants_not_quiescent");
        let mut sem = make_happy_semantics();
        sem.region_close.quiescent = false;
        sem.region_close.live_children = 2;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(violations.iter().any(|v| v.contains("quiescent")));
        crate::test_complete!("check_core_invariants_not_quiescent");
    }

    #[test]
    fn check_core_invariants_incomplete_drain() {
        init_test("check_core_invariants_incomplete_drain");
        let mut sem = make_happy_semantics();
        sem.loser_drain = LoserDrainRecord {
            applicable: true,
            expected_losers: 3,
            drained_losers: 1,
            status: DrainStatus::Incomplete,
            evidence: None,
        };
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(violations.iter().any(|v| v.contains("drain")));
        crate::test_complete!("check_core_invariants_incomplete_drain");
    }

    #[test]
    fn check_core_invariants_cancel_incomplete() {
        init_test("check_core_invariants_cancel_incomplete");
        let mut sem = make_happy_semantics();
        sem.cancellation.requested = true;
        sem.cancellation.cleanup_completed = false;
        sem.cancellation.terminal_phase = CancelTerminalPhase::Cancelling;
        let obs = make_observable(RuntimeKind::Lab, sem);
        let violations = check_core_invariants(&obs);
        assert!(violations.iter().any(|v| v.contains("Cancellation")));
        crate::test_complete!("check_core_invariants_cancel_incomplete");
    }

    // --- assert_semantics ---

    #[test]
    fn assert_semantics_identical_passes() {
        init_test("assert_semantics_identical_passes");
        let sem = make_happy_semantics();
        let mismatches = assert_semantics(&sem, &sem);
        assert!(mismatches.is_empty());
        crate::test_complete!("assert_semantics_identical_passes");
    }

    #[test]
    fn assert_semantics_detects_diff() {
        init_test("assert_semantics_detects_diff");
        let expected = make_happy_semantics();
        let mut actual = make_happy_semantics();
        actual.terminal_outcome = TerminalOutcome::err("network_error");
        let mismatches = assert_semantics(&actual, &expected);
        assert!(!mismatches.is_empty());
        crate::test_complete!("assert_semantics_detects_diff");
    }

    // --- DualRunHarness ---

    #[test]
    fn harness_identical_runs_pass() {
        init_test("harness_identical_runs_pass");
        let result = DualRunHarness::phase1(
            "test.happy_path",
            "test.surface",
            "v1",
            "Both sides produce identical semantics",
            42,
        )
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| make_happy_semantics())
        .run();

        assert!(result.passed());
        assert!(result.verdict.is_equivalent());
        assert!(result.lab_invariant_violations.is_empty());
        assert!(result.live_invariant_violations.is_empty());
        crate::test_complete!("harness_identical_runs_pass");
    }

    #[test]
    fn harness_outcome_mismatch_fails() {
        init_test("harness_outcome_mismatch_fails");
        let result = DualRunHarness::phase1(
            "test.mismatch",
            "test.surface",
            "v1",
            "Lab succeeds, live cancels",
            42,
        )
        .lab(|_config| make_happy_semantics())
        .live(|_seed, _entropy| {
            let mut sem = make_happy_semantics();
            sem.terminal_outcome = TerminalOutcome::cancelled("timeout");
            sem
        })
        .run();

        assert!(!result.passed());
        assert!(!result.verdict.is_equivalent());
        crate::test_complete!("harness_outcome_mismatch_fails");
    }

    #[test]
    fn harness_lab_invariant_violation_fails() {
        init_test("harness_lab_invariant_violation_fails");
        let result = DualRunHarness::phase1(
            "test.leak",
            "test.surface",
            "v1",
            "Lab leaks obligations",
            42,
        )
        .lab(|_config| {
            let mut sem = make_happy_semantics();
            sem.obligation_balance.leaked = 1;
            sem.obligation_balance.balanced = false;
            sem
        })
        .live(|_seed, _entropy| {
            let mut sem = make_happy_semantics();
            sem.obligation_balance.leaked = 1;
            sem.obligation_balance.balanced = false;
            sem
        })
        .run();

        // Semantics match (both leak), but invariant check catches it.
        assert!(result.verdict.is_equivalent());
        assert!(!result.lab_invariant_violations.is_empty());
        assert!(!result.passed()); // Failed due to invariant violations.
        crate::test_complete!("harness_lab_invariant_violation_fails");
    }

    #[test]
    fn harness_receives_correct_seeds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        init_test("harness_receives_correct_seeds");

        let captured_lab_seed = Arc::new(AtomicU64::new(0));
        let captured_live_seed = Arc::new(AtomicU64::new(0));
        let lab_clone = Arc::clone(&captured_lab_seed);
        let live_clone = Arc::clone(&captured_live_seed);

        let result = DualRunHarness::phase1("test.seeds", "s", "v1", "d", 0xBEEF)
            .lab(move |config| {
                lab_clone.store(config.seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .live(move |seed, _entropy| {
                live_clone.store(seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .run();

        assert!(result.passed());
        assert_eq!(captured_lab_seed.load(Ordering::Relaxed), 0xBEEF);
        assert_eq!(captured_live_seed.load(Ordering::Relaxed), 0xBEEF);
        crate::test_complete!("harness_receives_correct_seeds");
    }

    #[test]
    fn harness_with_custom_seed_plan() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};
        init_test("harness_with_custom_seed_plan");

        let captured_lab = Arc::new(AtomicU64::new(0));
        let captured_live = Arc::new(AtomicU64::new(0));
        let lab_c = Arc::clone(&captured_lab);
        let live_c = Arc::clone(&captured_live);

        let plan = SeedPlan::inherit(42, "custom")
            .with_lab_override(0xCAFE)
            .with_live_override(0xFACE);

        let result = DualRunHarness::phase1("test", "s", "v1", "d", 42)
            .with_seed_plan(plan)
            .lab(move |config| {
                lab_c.store(config.seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .live(move |seed, _entropy| {
                live_c.store(seed, Ordering::Relaxed);
                make_happy_semantics()
            })
            .run();

        assert_eq!(captured_lab.load(Ordering::Relaxed), 0xCAFE);
        assert_eq!(captured_live.load(Ordering::Relaxed), 0xFACE);
        // Semantics match despite different seeds.
        assert!(result.verdict.is_equivalent());
        // But seeds don't match.
        assert!(!result.seed_lineage.seeds_match);
        crate::test_complete!("harness_with_custom_seed_plan");
    }

    #[test]
    fn harness_from_identity() {
        init_test("harness_from_identity");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 99);
        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();
        assert!(result.passed());
        assert_eq!(result.verdict.scenario_id, "test");
        crate::test_complete!("harness_from_identity");
    }

    #[test]
    fn dual_run_result_display() {
        init_test("dual_run_result_display");
        let result = DualRunHarness::phase1("test", "s", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();
        let summary = format!("{result}");
        assert!(summary.contains("PASS"));
        crate::test_complete!("dual_run_result_display");
    }

    #[test]
    fn harness_noise_notes_classify_scheduler_noise() {
        init_test("harness_noise_notes_classify_scheduler_noise");
        let ident = DualRunScenarioIdentity::phase1("test.noise", "test.surface", "v1", "d", 42);
        let live_ident = ident.clone();

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live_result(move |_, _| {
                let mut result = run_live_adapter(&live_ident, |_config, witness| {
                    witness.set_outcome(TerminalOutcome::ok());
                    witness.note_nondeterminism("thread scheduling");
                });
                result.semantics.resource_surface = ResourceSurfaceRecord::empty("test");
                result
            })
            .run();

        assert!(result.passed());
        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::SchedulerNoiseSuspected
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::LiveConfirmations { additional_runs: 2 }
        );
        assert_eq!(
            result.policy.scheduler_noise_class,
            SchedulerNoiseClass::NondeterminismNotesOnly
        );
        crate::test_complete!("harness_noise_notes_classify_scheduler_noise");
    }

    #[test]
    fn harness_semantic_mismatch_policy_requests_reruns() {
        init_test("harness_semantic_mismatch_policy_requests_reruns");
        let result = DualRunHarness::phase1("test.mismatch.policy", "test.surface", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.terminal_outcome = TerminalOutcome::err("network_error");
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::SemanticMismatchAdmittedSurface
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::DeterministicLabReplayAndLiveConfirmations {
                additional_live_runs: 2,
            }
        );
        assert_eq!(result.policy.suggested_final_class, None);
        crate::test_complete!("harness_semantic_mismatch_policy_requests_reruns");
    }

    #[test]
    fn harness_unsupported_surface_policy_short_circuits() {
        init_test("harness_unsupported_surface_policy_short_circuits");
        let ident =
            DualRunScenarioIdentity::phase1("test.unsupported", "browser.surface", "v1", "d", 42)
                .with_metadata("eligibility_verdict", "unsupported")
                .with_metadata("unsupported_reason", "browser timing surface not admitted");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.terminal_outcome = TerminalOutcome::err("unsupported_surface");
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_unsupported_surface_policy_short_circuits");
    }

    #[test]
    fn harness_insufficient_observability_policy_marks_gap() {
        init_test("harness_insufficient_observability_policy_marks_gap");
        let ident =
            DualRunScenarioIdentity::phase1("test.observability", "timer.surface", "v1", "d", 42)
                .with_metadata("observability_status", "blocked_missing_live_timer_surface");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| {
                let mut sem = make_happy_semantics();
                sem.resource_surface =
                    ResourceSurfaceRecord::empty("timer.surface").with_counter("timeouts", 1);
                sem
            })
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.resource_surface = ResourceSurfaceRecord::empty("timer.surface");
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::InsufficientObservability
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs: 1 }
        );
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::InsufficientObservability)
        );
        crate::test_complete!("harness_insufficient_observability_policy_marks_gap");
    }

    #[test]
    fn harness_blocked_missing_observability_gate_is_not_a_pass() {
        init_test("harness_blocked_missing_observability_gate_is_not_a_pass");
        let ident = DualRunScenarioIdentity::phase1(
            "test.observability.gate",
            "timer.surface",
            "v1",
            "d",
            42,
        )
        .with_metadata("eligibility_verdict", "blocked_missing_observability");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::InsufficientObservability
        );
        assert_eq!(
            result.policy.rerun_decision,
            RerunDecision::ConfirmationIfRicherInstrumentationEnabled { additional_runs: 1 }
        );
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::InsufficientObservability)
        );
        crate::test_complete!("harness_blocked_missing_observability_gate_is_not_a_pass");
    }

    #[test]
    fn harness_bridge_only_downgrade_can_still_be_an_admitted_surface() {
        init_test("harness_bridge_only_downgrade_can_still_be_an_admitted_surface");
        let ident = DualRunScenarioIdentity::phase1(
            "test.bridge_only_admitted",
            "browser.surface",
            "v1",
            "bridge-only downgrade remains comparable when admitted",
            42,
        )
        .with_metadata("eligibility_verdict", "eligible_for_pilot")
        .with_metadata("support_class", "bridge_only")
        .with_metadata("reason_code", "downgrade_to_server_bridge");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert!(result.passed(), "{}", result.summary());
        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::Pass
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(result.policy.suggested_final_class, None);
        crate::test_complete!("harness_bridge_only_downgrade_can_still_be_an_admitted_surface");
    }

    #[test]
    fn harness_bridge_only_without_downgrade_reason_stays_unsupported() {
        init_test("harness_bridge_only_without_downgrade_reason_stays_unsupported");
        let ident = DualRunScenarioIdentity::phase1(
            "test.bridge_only_invalid_reason",
            "browser.surface",
            "v1",
            "bridge-only without a supported downgrade reason must fail closed",
            42,
        )
        .with_metadata("support_class", "bridge_only")
        .with_metadata("reason_code", "unsupported_runtime_context")
        .with_metadata(
            "unsupported_reason",
            "non-browser runtime context has no admitted downgrade lane",
        );

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_bridge_only_without_downgrade_reason_stays_unsupported");
    }

    #[test]
    fn harness_eligible_gate_does_not_override_unsupported_support_class() {
        init_test("harness_eligible_gate_does_not_override_unsupported_support_class");
        let ident = DualRunScenarioIdentity::phase1(
            "test.eligible_gate_conflict",
            "browser.surface",
            "v1",
            "contradictory unsupported support class must fail closed",
            42,
        )
        .with_metadata("eligibility_verdict", "eligible_for_pilot")
        .with_metadata("support_class", "unsupported")
        .with_metadata(
            "unsupported_reason",
            "shared worker direct runtime not shipped",
        );

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_eligible_gate_does_not_override_unsupported_support_class");
    }

    #[test]
    fn harness_blocked_missing_verification_gate_stays_unsupported() {
        init_test("harness_blocked_missing_verification_gate_stays_unsupported");
        let ident = DualRunScenarioIdentity::phase1(
            "test.verification.gate",
            "browser.surface",
            "v1",
            "d",
            42,
        )
        .with_metadata("eligibility_verdict", "blocked_missing_verification")
        .with_metadata("support_class", "bridge_only")
        .with_metadata("reason_code", "downgrade_to_server_bridge");

        let result = DualRunHarness::from_identity(ident)
            .lab(|_| make_happy_semantics())
            .live(|_, _| make_happy_semantics())
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::UnsupportedSurface
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::UnsupportedSurface)
        );
        crate::test_complete!("harness_blocked_missing_verification_gate_stays_unsupported");
    }

    #[test]
    fn harness_hard_contract_break_policy_short_circuits() {
        init_test("harness_hard_contract_break_policy_short_circuits");
        let result = DualRunHarness::phase1("test.hard_break", "test.surface", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.obligation_balance.leaked = 1;
                sem.obligation_balance.balanced = false;
                sem
            })
            .run();

        assert_eq!(
            result.policy.provisional_class,
            ProvisionalDivergenceClass::HardContractBreak
        );
        assert_eq!(result.policy.rerun_decision, RerunDecision::None);
        assert_eq!(
            result.policy.suggested_final_class,
            Some(FinalDivergenceClass::RuntimeSemanticBug)
        );
        crate::test_complete!("harness_hard_contract_break_policy_short_circuits");
    }

    #[test]
    #[should_panic(expected = "Dual-run test failed")]
    fn assert_dual_run_passes_panics_on_failure() {
        init_test("assert_dual_run_passes_panics_on_failure");
        let result = DualRunHarness::phase1("test", "s", "v1", "d", 42)
            .lab(|_| make_happy_semantics())
            .live(|_, _| {
                let mut sem = make_happy_semantics();
                sem.terminal_outcome = TerminalOutcome::err("oops");
                sem
            })
            .run();
        assert_dual_run_passes(&result);
    }

    // --- LiveRunnerAdapter ---

    #[test]
    fn live_runner_config_from_identity() {
        init_test("live_runner_config_from_identity");
        let ident = DualRunScenarioIdentity::phase1("test", "surface", "v1", "d", 0xBEEF);
        let config = LiveRunnerConfig::from_identity(&ident);
        assert_eq!(config.seed, 0xBEEF);
        assert_eq!(config.profile, LiveExecutionProfile::CurrentThread);
        assert_eq!(config.scenario_id, "test");
        assert_eq!(config.surface_id, "surface");
        crate::test_complete!("live_runner_config_from_identity");
    }

    #[test]
    fn live_runner_config_from_plan() {
        init_test("live_runner_config_from_plan");
        let plan = SeedPlan::inherit(42, "lineage").with_live_override(0xCAFE);
        let config = LiveRunnerConfig::from_plan(&plan, "scenario", "surface");
        assert_eq!(config.seed, 0xCAFE);
        assert_eq!(config.seed_lineage_id, "lineage");
        crate::test_complete!("live_runner_config_from_plan");
    }

    #[test]
    fn live_runner_config_display() {
        init_test("live_runner_config_display");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let config = LiveRunnerConfig::from_identity(&ident);
        let s = format!("{config}");
        assert!(s.contains("test"));
        assert!(s.contains("current_thread"));
        crate::test_complete!("live_runner_config_display");
    }

    #[test]
    fn live_witness_collector_defaults() {
        init_test("live_witness_collector_defaults");
        let witness = LiveWitnessCollector::new("test.surface");
        let sem = witness.finalize();
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Ok);
        assert!(sem.region_close.quiescent);
        assert!(sem.obligation_balance.balanced);
        assert_eq!(sem.loser_drain.status, DrainStatus::NotApplicable);
        assert_eq!(sem.resource_surface.contract_scope, "test.surface");
        crate::test_complete!("live_witness_collector_defaults");
    }

    #[test]
    fn live_witness_collector_records_evidence() {
        init_test("live_witness_collector_records_evidence");
        let mut witness = LiveWitnessCollector::new("test");
        witness.set_outcome(TerminalOutcome::cancelled("timeout"));
        witness.set_cancellation(CancellationRecord::completed());
        witness.set_loser_drain(LoserDrainRecord::complete(2));
        witness.set_obligation_balance(ObligationBalanceRecord::balanced(5, 4, 1));
        witness.record_counter("msgs_sent", 10);
        witness.record_counter_with_tolerance("bytes", 1024, CounterTolerance::AtLeast);
        witness.note_nondeterminism("scheduler ordering may vary");

        assert_eq!(witness.nondeterminism_notes().len(), 1);

        let sem = witness.finalize();
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Cancelled);
        assert!(sem.cancellation.requested);
        assert_eq!(sem.loser_drain.drained_losers, 2);
        assert_eq!(sem.obligation_balance.committed, 4);
        assert_eq!(sem.resource_surface.counters["msgs_sent"], 10);
        assert_eq!(
            sem.resource_surface.tolerances["bytes"],
            CounterTolerance::AtLeast
        );
        crate::test_complete!("live_witness_collector_records_evidence");
    }

    #[test]
    fn run_live_adapter_happy_path() {
        init_test("run_live_adapter_happy_path");
        let ident = DualRunScenarioIdentity::phase1(
            "test.happy",
            "test.surface",
            "v1",
            "Happy path live adapter test",
            42,
        );
        let result = run_live_adapter(&ident, |config, witness| {
            assert_eq!(config.seed, 42);
            assert_eq!(config.profile, LiveExecutionProfile::CurrentThread);
            witness.set_outcome(TerminalOutcome::ok());
            witness.record_counter("items_processed", 5);
        });
        assert_eq!(result.semantics.terminal_outcome.class, OutcomeClass::Ok);
        assert_eq!(
            result.semantics.resource_surface.counters["items_processed"],
            5
        );
        assert_eq!(result.metadata.config.scenario_id, "test.happy");
        assert!(result.metadata.nondeterminism_notes.is_empty());
        assert_eq!(
            result
                .metadata
                .capture_manifest
                .describe_field_capture("semantics.terminal_outcome.class")
                .as_deref(),
            Some("observed via witness.set_outcome")
        );
        assert_eq!(
            result
                .metadata
                .capture_manifest
                .describe_field_capture("semantics.resource_surface.counters.items_processed")
                .as_deref(),
            Some("observed via witness.record_counter")
        );
        crate::test_complete!("run_live_adapter_happy_path");
    }

    #[test]
    fn run_live_adapter_with_nondeterminism() {
        init_test("run_live_adapter_with_nondeterminism");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let result = run_live_adapter(&ident, |_config, witness| {
            witness.note_nondeterminism("timer resolution varies");
            witness.note_nondeterminism("thread scheduling");
        });
        assert_eq!(result.metadata.nondeterminism_notes.len(), 2);
        crate::test_complete!("run_live_adapter_with_nondeterminism");
    }

    #[test]
    fn run_live_adapter_cancellation_scenario() {
        init_test("run_live_adapter_cancellation_scenario");
        let ident = DualRunScenarioIdentity::phase1(
            "cancel.race",
            "cancellation.race",
            "v1",
            "Cancel and drain",
            0xDEAD,
        );
        let result = run_live_adapter(&ident, |config, witness| {
            assert_eq!(config.seed, 0xDEAD);
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_cancellation(CancellationRecord::completed());
            witness.set_loser_drain(LoserDrainRecord::complete(1));
        });
        assert!(result.semantics.cancellation.requested);
        assert!(result.semantics.cancellation.cleanup_completed);
        assert_eq!(result.semantics.loser_drain.status, DrainStatus::Complete);
        assert_eq!(
            result.metadata.replay.instance.runtime_kind,
            RuntimeKind::Live
        );
        assert_eq!(
            result
                .metadata
                .capture_manifest
                .describe_field_capture("semantics.cancellation.checkpoint_observed")
                .as_deref(),
            Some("observed via witness.set_cancellation")
        );
        crate::test_complete!("run_live_adapter_cancellation_scenario");
    }

    #[test]
    fn run_live_adapter_metadata_serde() {
        init_test("run_live_adapter_metadata_serde");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let result = run_live_adapter(&ident, |_, _| {});
        let json = serde_json::to_string_pretty(&result.metadata).unwrap();
        let parsed: LiveRunMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.config.seed, 42);
        assert_eq!(parsed.config.profile, LiveExecutionProfile::CurrentThread);
        assert_eq!(
            parsed
                .capture_manifest
                .describe_field_capture("semantics.region_close.quiescent")
                .as_deref(),
            Some("inferred via run_live_adapter.default_quiescent")
        );
        crate::test_complete!("run_live_adapter_metadata_serde");
    }

    #[test]
    fn live_adapter_integrates_with_harness() {
        init_test("live_adapter_integrates_with_harness");
        // Demonstrates the full pattern: use run_live_adapter inside
        // DualRunHarness.live() closure for structured live evidence.
        let result = DualRunHarness::phase1(
            "integration.test",
            "test.surface",
            "v1",
            "Full integration of live adapter with harness",
            0xBEEF,
        )
        .lab(|_config| make_happy_semantics())
        .live(|seed, _entropy| {
            let ident = DualRunScenarioIdentity::phase1(
                "integration.test",
                "test.surface",
                "v1",
                "d",
                seed,
            );
            let live_result = run_live_adapter(&ident, |_config, witness| {
                witness.set_outcome(TerminalOutcome::ok());
                witness.record_counter("items", 3);
            });
            live_result.semantics
        })
        .run();

        // Resource counter won't match lab (which has no counters),
        // but that's expected — live has extra counters.
        // The harness detects this properly.
        assert!(!result.verdict.passed); // Different resource surfaces
        crate::test_complete!("live_adapter_integrates_with_harness");
    }

    // --- Semantic Capture Hooks ---

    #[test]
    fn capture_manifest_tracking() {
        init_test("capture_manifest_tracking");
        let mut manifest = CaptureManifest::new();
        manifest.observed("terminal_outcome", "outcome_match");
        manifest.inferred("cancellation.acknowledged", "task_handle.join");
        manifest.unsupported("cancellation.checkpoint_observed");

        assert_eq!(manifest.total_fields(), 3);
        assert_eq!(manifest.unsupported_count(), 1);
        assert!(!manifest.fully_observed());
        assert_eq!(
            manifest.unsupported_fields,
            vec!["cancellation.checkpoint_observed"]
        );
        crate::test_complete!("capture_manifest_tracking");
    }

    #[test]
    fn capture_manifest_fully_observed() {
        init_test("capture_manifest_fully_observed");
        let mut manifest = CaptureManifest::new();
        manifest.observed("outcome", "match");
        manifest.observed("cancel", "hook");
        assert!(manifest.fully_observed());
        crate::test_complete!("capture_manifest_fully_observed");
    }

    #[test]
    fn capture_manifest_empty_is_not_fully_observed() {
        init_test("capture_manifest_empty_is_not_fully_observed");
        let manifest = CaptureManifest::new();
        assert!(!manifest.fully_observed());
        crate::test_complete!("capture_manifest_empty_is_not_fully_observed");
    }

    #[test]
    fn capture_manifest_serde() {
        init_test("capture_manifest_serde");
        let mut manifest = CaptureManifest::new();
        manifest.observed("outcome", "match");
        manifest.unsupported("checkpoint");
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: CaptureManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_fields(), 2);
        crate::test_complete!("capture_manifest_serde");
    }

    #[test]
    fn capture_manifest_canonicalizes_and_resolves_parent_fields() {
        init_test("capture_manifest_canonicalizes_and_resolves_parent_fields");
        let mut manifest = CaptureManifest::new();
        manifest.unsupported("terminal_outcome");
        manifest.observed("resource_surface.counters.items", "counter");
        manifest.observed("terminal_outcome", "hook");
        manifest.inferred("cancellation", "fallback");

        let fields: Vec<&str> = manifest
            .annotations
            .iter()
            .map(|annotation| annotation.field.as_str())
            .collect();
        assert_eq!(
            fields,
            vec![
                "cancellation",
                "resource_surface.counters.items",
                "terminal_outcome"
            ]
        );
        assert!(manifest.unsupported_fields.is_empty());
        assert_eq!(
            manifest
                .annotation_for_field("semantics.resource_surface.counters.items")
                .unwrap()
                .source,
            "counter"
        );
        assert_eq!(
            manifest
                .describe_field_capture("semantics.terminal_outcome.class")
                .as_deref(),
            Some("observed via hook")
        );
        crate::test_complete!("capture_manifest_canonicalizes_and_resolves_parent_fields");
    }

    #[test]
    fn capture_terminal_from_outcome_ok() {
        init_test("capture_terminal_from_outcome_ok");
        let outcome: crate::types::outcome::Outcome<i32, String> =
            crate::types::outcome::Outcome::Ok(42);
        let t = capture_terminal_outcome(&outcome);
        assert_eq!(t.class, OutcomeClass::Ok);
        assert_eq!(t.severity, OutcomeClass::Ok);
        crate::test_complete!("capture_terminal_from_outcome_ok");
    }

    #[test]
    fn capture_terminal_from_outcome_err() {
        init_test("capture_terminal_from_outcome_err");
        let outcome: crate::types::outcome::Outcome<i32, String> =
            crate::types::outcome::Outcome::Err("network_error".to_string());
        let t = capture_terminal_outcome(&outcome);
        assert_eq!(t.class, OutcomeClass::Err);
        assert_eq!(t.error_class.as_deref(), Some("network_error"));
        crate::test_complete!("capture_terminal_from_outcome_err");
    }

    #[test]
    fn capture_terminal_from_outcome_cancelled() {
        init_test("capture_terminal_from_outcome_cancelled");
        let outcome: crate::types::outcome::Outcome<i32, String> =
            crate::types::outcome::Outcome::Cancelled(crate::types::CancelReason::new(
                crate::types::CancelKind::User,
            ));
        let t = capture_terminal_outcome(&outcome);
        assert_eq!(t.class, OutcomeClass::Cancelled);
        assert!(t.cancel_reason_class.is_some());
        crate::test_complete!("capture_terminal_from_outcome_cancelled");
    }

    #[test]
    fn capture_terminal_from_result_ok_and_err() {
        init_test("capture_terminal_from_result_ok_and_err");
        let ok: Result<i32, String> = Ok(42);
        let err: Result<i32, String> = Err("fail".to_string());
        assert_eq!(
            super::capture_terminal_from_result(&ok).class,
            OutcomeClass::Ok
        );
        assert_eq!(
            super::capture_terminal_from_result(&err).class,
            OutcomeClass::Err
        );
        crate::test_complete!("capture_terminal_from_result_ok_and_err");
    }

    #[test]
    fn capture_obligation_balanced() {
        init_test("capture_obligation_balanced");
        let b = capture_obligation_balance(10, 8, 2);
        assert!(b.balanced);
        assert_eq!(b.leaked, 0);
        assert_eq!(b.unresolved, 0);
        crate::test_complete!("capture_obligation_balanced");
    }

    #[test]
    fn capture_obligation_leaked() {
        init_test("capture_obligation_leaked");
        let b = capture_obligation_balance(10, 5, 2);
        assert!(!b.balanced);
        assert_eq!(b.leaked, 3);
        crate::test_complete!("capture_obligation_leaked");
    }

    #[test]
    fn capture_region_close_quiescent() {
        init_test("capture_region_close_quiescent");
        let r = capture_region_close(true, true);
        assert!(r.quiescent);
        assert!(r.close_completed);
        assert_eq!(r.root_state, RegionState::Closed);
        assert_eq!(r.live_children, 0);
        crate::test_complete!("capture_region_close_quiescent");
    }

    #[test]
    fn capture_region_close_not_quiescent() {
        init_test("capture_region_close_not_quiescent");
        let r = capture_region_close(false, true);
        assert!(!r.quiescent);
        assert!(!r.close_completed);
        assert_eq!(r.live_children, 1);
        crate::test_complete!("capture_region_close_not_quiescent");
    }

    #[test]
    fn capture_loser_drain_not_applicable() {
        init_test("capture_loser_drain_not_applicable");
        let d = capture_loser_drain(&[]);
        assert!(!d.applicable);
        assert_eq!(d.status, DrainStatus::NotApplicable);
        crate::test_complete!("capture_loser_drain_not_applicable");
    }

    #[test]
    fn capture_loser_drain_all_drained() {
        init_test("capture_loser_drain_all_drained");
        let d = capture_loser_drain(&[true, true, true]);
        assert!(d.applicable);
        assert_eq!(d.status, DrainStatus::Complete);
        assert_eq!(d.expected_losers, 3);
        assert_eq!(d.drained_losers, 3);
        crate::test_complete!("capture_loser_drain_all_drained");
    }

    #[test]
    fn capture_loser_drain_partial() {
        init_test("capture_loser_drain_partial");
        let d = capture_loser_drain(&[true, false, true]);
        assert_eq!(d.status, DrainStatus::Incomplete);
        assert_eq!(d.drained_losers, 2);
        crate::test_complete!("capture_loser_drain_partial");
    }

    #[test]
    fn capture_cancellation_not_cancelled() {
        init_test("capture_cancellation_not_cancelled");
        let c = capture_cancellation(false, false, false, false, None);
        assert_eq!(c.terminal_phase, CancelTerminalPhase::NotCancelled);
        assert!(!c.requested);
        crate::test_complete!("capture_cancellation_not_cancelled");
    }

    #[test]
    fn capture_cancellation_completed() {
        init_test("capture_cancellation_completed");
        let c = capture_cancellation(true, true, true, true, Some(true));
        assert_eq!(c.terminal_phase, CancelTerminalPhase::Completed);
        assert!(c.requested);
        assert!(c.acknowledged);
        assert!(c.cleanup_completed);
        assert!(c.finalization_completed);
        assert_eq!(c.checkpoint_observed, Some(true));
        crate::test_complete!("capture_cancellation_completed");
    }

    #[test]
    fn capture_cancellation_in_progress() {
        init_test("capture_cancellation_in_progress");
        let c = capture_cancellation(true, true, false, false, None);
        assert_eq!(c.terminal_phase, CancelTerminalPhase::Cancelling);
        crate::test_complete!("capture_cancellation_in_progress");
    }

    #[test]
    fn capture_cancellation_finalizing() {
        init_test("capture_cancellation_finalizing");
        let c = capture_cancellation(true, true, true, false, None);
        assert_eq!(c.terminal_phase, CancelTerminalPhase::Finalizing);
        crate::test_complete!("capture_cancellation_finalizing");
    }

    // --- Lab Normalizer ---

    fn make_passing_oracle_report() -> crate::lab::oracle::OracleReport {
        crate::lab::oracle::OracleReport {
            entries: vec![],
            total: 0,
            passed: 0,
            failed: 0,
            check_time_nanos: 0,
        }
    }

    fn make_passing_lab_report(seed: u64) -> crate::lab::runtime::LabRunReport {
        crate::lab::runtime::LabRunReport {
            seed,
            steps_delta: 100,
            steps_total: 100,
            quiescent: true,
            now_nanos: 0,
            trace_len: 10,
            trace_fingerprint: 0xABCD,
            trace_certificate: crate::lab::runtime::LabTraceCertificateSummary {
                event_hash: 0x1234,
                event_count: 10,
                schedule_hash: 0x5678,
            },
            oracle_report: make_passing_oracle_report(),
            invariant_violations: vec![],
            temporal_invariant_failures: vec![],
            temporal_counterexample_prefix_len: None,
            refinement_firewall_rule_id: None,
            refinement_firewall_event_index: None,
            refinement_firewall_event_seq: None,
            refinement_counterexample_prefix_len: None,
            refinement_firewall_skipped_due_to_trace_truncation: false,
        }
    }

    fn make_golden_live_result(identity: &DualRunScenarioIdentity) -> LiveRunResult {
        run_live_adapter(identity, |_, witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.set_loser_drain(LoserDrainRecord::complete(2));
            witness.record_counter("items", 5);
            witness.record_counter_with_tolerance("bytes", 128, CounterTolerance::AtLeast);
            witness.note_nondeterminism("scheduler jitter");
        })
    }

    #[test]
    fn normalize_lab_report_happy_path() {
        init_test("normalize_lab_report_happy_path");
        let report = make_passing_lab_report(42);
        let (sem, manifest) = normalize_lab_report(&report, "test.surface");
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Ok);
        assert!(sem.region_close.quiescent);
        assert!(sem.obligation_balance.balanced);
        assert!(manifest.total_fields() > 0);
        crate::test_complete!("normalize_lab_report_happy_path");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn normalize_lab_report_matches_golden_record() {
        init_test("normalize_lab_report_matches_golden_record");
        let identity = DualRunScenarioIdentity::phase1(
            "golden.lab",
            "test.surface",
            "v1",
            "Golden lab normalization",
            42,
        );
        let report = make_passing_lab_report(42);
        let (semantics, manifest) = normalize_lab_report(&report, "test.surface");
        let observable = normalize_lab_observable(&identity, &report);

        assert_eq!(observable.semantics, semantics);
        assert_eq!(
            serde_json::to_value(&manifest).unwrap(),
            serde_json::json!({
                "annotations": [
                    {
                        "field": "cancellation",
                        "observability": "inferred",
                        "source": "no_oracle_entry",
                    },
                    {
                        "field": "loser_drain",
                        "observability": "inferred",
                        "source": "no_oracle_entry",
                    },
                    {
                        "field": "obligation_balance",
                        "observability": "observed",
                        "source": "oracle.obligation_leak + invariants",
                    },
                    {
                        "field": "region_close.quiescent",
                        "observability": "observed",
                        "source": "LabRunReport.quiescent",
                    },
                    {
                        "field": "terminal_outcome",
                        "observability": "observed",
                        "source": "oracle_report.all_passed",
                    }
                ],
                "unsupported_fields": [],
            })
        );
        assert_eq!(
            serde_json::to_value(&observable).unwrap(),
            serde_json::json!({
                "schema_version": NORMALIZED_OBSERVABLE_SCHEMA_VERSION,
                "scenario_id": "golden.lab",
                "surface_id": "test.surface",
                "surface_contract_version": "v1",
                "runtime_kind": "lab",
                "semantics": {
                    "terminal_outcome": {
                        "class": "ok",
                        "severity": "ok",
                    },
                    "cancellation": {
                        "requested": false,
                        "acknowledged": false,
                        "cleanup_completed": false,
                        "finalization_completed": false,
                        "terminal_phase": "not_cancelled",
                    },
                    "loser_drain": {
                        "applicable": false,
                        "expected_losers": 0,
                        "drained_losers": 0,
                        "status": "not_applicable",
                    },
                    "region_close": {
                        "root_state": "closed",
                        "quiescent": true,
                        "live_children": 0,
                        "finalizers_pending": 0,
                        "close_completed": true,
                    },
                    "obligation_balance": {
                        "reserved": 0,
                        "committed": 0,
                        "aborted": 0,
                        "leaked": 0,
                        "unresolved": 0,
                        "balanced": true,
                    },
                    "resource_surface": {
                        "contract_scope": "test.surface",
                        "counters": {},
                        "tolerances": {},
                    },
                },
                "provenance": {
                    "family": {
                        "id": "golden.lab",
                        "surface_id": "test.surface",
                        "surface_contract_version": "v1",
                    },
                    "instance": {
                        "family_id": "golden.lab",
                        "effective_seed": 42,
                        "runtime_kind": "lab",
                        "run_index": 0,
                    },
                    "seed_plan": {
                        "canonical_seed": 42,
                        "seed_lineage_id": "golden.lab",
                        "lab_seed_mode": "inherit",
                        "live_seed_mode": "inherit",
                        "replay_policy": "single_seed",
                    },
                    "effective_seed": 42,
                    "effective_entropy_seed": derive_component_seed(42, "entropy"),
                    "trace_fingerprint": 43981,
                    "schedule_hash": 22136,
                    "event_hash": 4660,
                    "event_count": 10,
                    "steps_total": 100,
                },
            })
        );
        crate::test_complete!("normalize_lab_report_matches_golden_record");
    }

    #[test]
    fn normalize_lab_report_invariant_violation() {
        init_test("normalize_lab_report_invariant_violation");
        let mut report = make_passing_lab_report(42);
        report.invariant_violations = vec!["obligation leak detected".to_string()];
        let (sem, _) = normalize_lab_report(&report, "test");
        assert_eq!(sem.terminal_outcome.class, OutcomeClass::Err);
        assert!(!sem.obligation_balance.balanced);
        crate::test_complete!("normalize_lab_report_invariant_violation");
    }

    #[test]
    fn normalize_lab_report_not_quiescent() {
        init_test("normalize_lab_report_not_quiescent");
        let mut report = make_passing_lab_report(42);
        report.quiescent = false;
        let (sem, _) = normalize_lab_report(&report, "test");
        assert!(!sem.region_close.quiescent);
        assert!(!sem.region_close.close_completed);
        crate::test_complete!("normalize_lab_report_not_quiescent");
    }

    #[test]
    fn normalize_lab_observable_preserves_provenance() {
        init_test("normalize_lab_observable_preserves_provenance");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let report = make_passing_lab_report(42);
        let obs = normalize_lab_observable(&ident, &report);
        assert_eq!(obs.runtime_kind, RuntimeKind::Lab);
        assert_eq!(obs.provenance.trace_fingerprint, Some(0xABCD));
        assert_eq!(obs.provenance.event_hash, Some(0x1234));
        assert_eq!(obs.provenance.steps_total, Some(100));
        crate::test_complete!("normalize_lab_observable_preserves_provenance");
    }

    #[test]
    fn normalize_live_observable_from_result() {
        init_test("normalize_live_observable_from_result");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);
        let live_result = run_live_adapter(&ident, |_, witness| {
            witness.set_outcome(TerminalOutcome::ok());
            witness.record_counter("items", 5);
        });
        let obs = normalize_live_observable(&ident, &live_result);
        assert_eq!(obs.runtime_kind, RuntimeKind::Live);
        assert_eq!(obs.semantics.terminal_outcome.class, OutcomeClass::Ok);
        assert_eq!(obs.semantics.resource_surface.counters["items"], 5);
        crate::test_complete!("normalize_live_observable_from_result");
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn normalize_live_observable_matches_golden_record_and_manifest() {
        init_test("normalize_live_observable_matches_golden_record_and_manifest");
        let identity = DualRunScenarioIdentity::phase1(
            "golden.live",
            "test.surface",
            "v1",
            "Golden live normalization",
            42,
        );
        let live_result = make_golden_live_result(&identity);
        let observable = normalize_live_observable(&identity, &live_result);

        assert_eq!(
            serde_json::to_value(&live_result.metadata.capture_manifest).unwrap(),
            serde_json::json!({
                "annotations": [
                    {
                        "field": "cancellation",
                        "observability": "inferred",
                        "source": "run_live_adapter.default_no_cancellation",
                    },
                    {
                        "field": "cancellation.checkpoint_observed",
                        "observability": "unsupported",
                        "source": "default",
                    },
                    {
                        "field": "loser_drain",
                        "observability": "observed",
                        "source": "witness.set_loser_drain",
                    },
                    {
                        "field": "obligation_balance",
                        "observability": "inferred",
                        "source": "run_live_adapter.default_balanced_obligations",
                    },
                    {
                        "field": "region_close",
                        "observability": "inferred",
                        "source": "run_live_adapter.default_quiescent",
                    },
                    {
                        "field": "resource_surface.contract_scope",
                        "observability": "observed",
                        "source": "scenario_identity.surface_id",
                    },
                    {
                        "field": "resource_surface.counters.bytes",
                        "observability": "observed",
                        "source": "witness.record_counter_with_tolerance",
                    },
                    {
                        "field": "resource_surface.counters.items",
                        "observability": "observed",
                        "source": "witness.record_counter",
                    },
                    {
                        "field": "resource_surface.tolerances.bytes",
                        "observability": "observed",
                        "source": "witness.record_counter_with_tolerance",
                    },
                    {
                        "field": "resource_surface.tolerances.items",
                        "observability": "observed",
                        "source": "witness.record_counter",
                    },
                    {
                        "field": "terminal_outcome",
                        "observability": "observed",
                        "source": "witness.set_outcome",
                    }
                ],
                "unsupported_fields": ["cancellation.checkpoint_observed"],
            })
        );
        assert_eq!(
            serde_json::to_value(&observable).unwrap(),
            serde_json::json!({
                "schema_version": NORMALIZED_OBSERVABLE_SCHEMA_VERSION,
                "scenario_id": "golden.live",
                "surface_id": "test.surface",
                "surface_contract_version": "v1",
                "runtime_kind": "live",
                "semantics": {
                    "terminal_outcome": {
                        "class": "ok",
                        "severity": "ok",
                    },
                    "cancellation": {
                        "requested": false,
                        "acknowledged": false,
                        "cleanup_completed": false,
                        "finalization_completed": false,
                        "terminal_phase": "not_cancelled",
                    },
                    "loser_drain": {
                        "applicable": true,
                        "expected_losers": 2,
                        "drained_losers": 2,
                        "status": "complete",
                    },
                    "region_close": {
                        "root_state": "closed",
                        "quiescent": true,
                        "live_children": 0,
                        "finalizers_pending": 0,
                        "close_completed": true,
                    },
                    "obligation_balance": {
                        "reserved": 0,
                        "committed": 0,
                        "aborted": 0,
                        "leaked": 0,
                        "unresolved": 0,
                        "balanced": true,
                    },
                    "resource_surface": {
                        "contract_scope": "test.surface",
                        "counters": {
                            "bytes": 128,
                            "items": 5,
                        },
                        "tolerances": {
                            "bytes": "at_least",
                            "items": "exact",
                        },
                    },
                },
                "provenance": {
                    "family": {
                        "id": "golden.live",
                        "surface_id": "test.surface",
                        "surface_contract_version": "v1",
                    },
                    "instance": {
                        "family_id": "golden.live",
                        "effective_seed": 42,
                        "runtime_kind": "live",
                        "run_index": 0,
                    },
                    "seed_plan": {
                        "canonical_seed": 42,
                        "seed_lineage_id": "golden.live",
                        "lab_seed_mode": "inherit",
                        "live_seed_mode": "inherit",
                        "replay_policy": "single_seed",
                    },
                    "effective_seed": 42,
                    "effective_entropy_seed": derive_component_seed(42, "entropy"),
                },
            })
        );
        crate::test_complete!("normalize_live_observable_matches_golden_record_and_manifest");
    }

    #[test]
    fn normalize_and_compare_lab_vs_live() {
        init_test("normalize_and_compare_lab_vs_live");
        let ident = DualRunScenarioIdentity::phase1("test", "s", "v1", "d", 42);

        // Lab side
        let report = make_passing_lab_report(42);
        let lab_obs = normalize_lab_observable(&ident, &report);

        // Live side
        let live_result = run_live_adapter(&ident, |_, _| {});
        let live_obs = normalize_live_observable(&ident, &live_result);

        // Compare
        let lineage = ident.seed_lineage();
        let verdict = compare_observables(&lab_obs, &live_obs, lineage);
        // Both should have ok outcomes and quiescent regions
        assert!(verdict.passed, "Verdict: {}", verdict.summary());
        crate::test_complete!("normalize_and_compare_lab_vs_live");
    }

    #[test]
    fn mismatch_summary_with_manifests_includes_capture_sources() {
        init_test("mismatch_summary_with_manifests_includes_capture_sources");
        let identity = DualRunScenarioIdentity::phase1(
            "capture.summary",
            "test.surface",
            "v1",
            "Mismatch summaries should include capture provenance",
            42,
        );

        let mut report = make_passing_lab_report(42);
        report.invariant_violations = vec!["obligation leak detected".to_string()];
        let (lab_semantics, lab_manifest) = normalize_lab_report(&report, "test.surface");
        let lab = NormalizedObservable::new(
            &identity,
            RuntimeKind::Lab,
            lab_semantics,
            identity.lab_replay_metadata(),
        );

        let live_result = run_live_adapter(&identity, |_, witness| {
            witness.set_outcome(TerminalOutcome::ok());
        });
        let live = normalize_live_observable(&identity, &live_result);

        let verdict = compare_observables(&lab, &live, identity.seed_lineage());
        assert!(!verdict.passed);

        let summary = verdict.summary_with_manifests(
            Some(&lab_manifest),
            Some(&live_result.metadata.capture_manifest),
        );
        assert!(summary.contains("semantics.terminal_outcome.class"));
        assert!(summary.contains("lab_capture=observed via invariant_violations"));
        assert!(summary.contains("live_capture=observed via witness.set_outcome"));
        crate::test_complete!("mismatch_summary_with_manifests_includes_capture_sources");
    }

    // --- Fuzz-to-Scenario Promotion ---

    fn make_test_fuzz_finding(seed: u64) -> crate::lab::fuzz::FuzzFinding {
        crate::lab::fuzz::FuzzFinding {
            seed,
            steps: 500,
            violations: vec![],
            certificate_hash: 0xABCD,
            trace_fingerprint: 0x1234,
            minimized_seed: Some(seed.wrapping_add(1)),
        }
    }

    #[test]
    fn promote_fuzz_finding_basic() {
        init_test("promote_fuzz_finding_basic");
        let finding = make_test_fuzz_finding(0xDEAD);
        let promoted = promote_fuzz_finding(&finding, "cancellation", "v1");
        assert!(promoted.identity.scenario_id.contains("fuzz"));
        assert!(promoted.identity.scenario_id.contains("cancellation"));
        assert_eq!(promoted.replay_seed, 0xDEAD + 1); // minimized
        assert_eq!(promoted.original_seed, 0xDEAD);
        assert_eq!(promoted.identity.seed_plan.canonical_seed, 0xDEAD + 1);
        assert_eq!(promoted.identity.phase, Phase::Phase1);
        assert!(promoted.identity.metadata.contains_key("promoted_from"));
        crate::test_complete!("promote_fuzz_finding_basic");
    }

    #[test]
    fn promote_fuzz_finding_no_minimized_seed() {
        init_test("promote_fuzz_finding_no_minimized_seed");
        let mut finding = make_test_fuzz_finding(0xBEEF);
        finding.minimized_seed = None;
        let promoted = promote_fuzz_finding(&finding, "obligation", "v1");
        assert_eq!(promoted.replay_seed, 0xBEEF); // falls back to original
        crate::test_complete!("promote_fuzz_finding_no_minimized_seed");
    }

    #[test]
    fn promote_fuzz_finding_stabilizes_violation_categories_and_metadata() {
        init_test("promote_fuzz_finding_stabilizes_violation_categories_and_metadata");
        let mut finding = make_test_fuzz_finding(0xD00D);
        finding.violations = vec![
            crate::lab::runtime::InvariantViolation::QuiescenceViolation,
            crate::lab::runtime::InvariantViolation::Futurelock {
                task: crate::types::TaskId::new_for_test(1, 0),
                region: crate::types::RegionId::new_for_test(1, 0),
                idle_steps: 1,
                held: Vec::new(),
            },
            crate::lab::runtime::InvariantViolation::QuiescenceViolation,
        ];

        let promoted = promote_fuzz_finding(&finding, "cancellation", "v1");
        assert_eq!(
            promoted.violation_categories,
            vec!["futurelock", "quiescence_violation"]
        );
        assert!(promoted.identity.scenario_id.contains("futurelock"));
        assert_eq!(
            promoted.identity.metadata.get("violation_categories"),
            Some(&"futurelock,quiescence_violation".to_string())
        );
        assert_eq!(
            promoted.identity.metadata.get("certificate_hash"),
            Some(&"0xABCD".to_string())
        );
        crate::test_complete!("promote_fuzz_finding_stabilizes_violation_categories_and_metadata");
    }

    #[test]
    fn promote_fuzz_finding_repro_command() {
        init_test("promote_fuzz_finding_repro_command");
        let finding = make_test_fuzz_finding(42);
        let promoted = promote_fuzz_finding(&finding, "drain", "v1");
        let cmd = promoted.repro_command();
        assert!(cmd.contains("ASUPERSYNC_SEED"));
        assert!(cmd.contains("cargo test"));
        crate::test_complete!("promote_fuzz_finding_repro_command");
    }

    #[test]
    fn promote_fuzz_finding_display() {
        init_test("promote_fuzz_finding_display");
        let finding = make_test_fuzz_finding(42);
        let promoted = promote_fuzz_finding(&finding, "test", "v1");
        let s = format!("{promoted}");
        assert!(s.contains("PromotedFuzz"));
        crate::test_complete!("promote_fuzz_finding_display");
    }

    #[test]
    fn promote_fuzz_finding_serde_roundtrip() {
        init_test("promote_fuzz_finding_serde_roundtrip");
        let finding = make_test_fuzz_finding(0xCAFE);
        let promoted = promote_fuzz_finding(&finding, "test", "v1")
            .with_source_artifact_path("/tmp/fuzz/report.json");
        let json = serde_json::to_string_pretty(&promoted).unwrap();
        let parsed: PromotedFuzzScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.replay_seed, promoted.replay_seed);
        assert_eq!(parsed.original_seed, 0xCAFE);
        assert_eq!(
            parsed.source_artifact_path.as_deref(),
            Some("/tmp/fuzz/report.json")
        );
        crate::test_complete!("promote_fuzz_finding_serde_roundtrip");
    }

    #[test]
    fn promoted_fuzz_scenario_replay_metadata_includes_artifact_and_repro() {
        init_test("promoted_fuzz_scenario_replay_metadata_includes_artifact_and_repro");
        let finding = make_test_fuzz_finding(0xCAFE);
        let promoted = promote_fuzz_finding(&finding, "test.surface", "v1")
            .with_source_artifact_path("/tmp/fuzz/report.json");

        let metadata = promoted.lab_replay_metadata();
        assert_eq!(metadata.trace_fingerprint, Some(promoted.trace_fingerprint));
        assert_eq!(
            metadata.artifact_path.as_deref(),
            Some("/tmp/fuzz/report.json")
        );
        assert_eq!(
            metadata.repro_command.as_deref(),
            Some(promoted.repro_command().as_str())
        );
        crate::test_complete!("promoted_fuzz_scenario_replay_metadata_includes_artifact_and_repro");
    }

    #[test]
    fn promote_regression_case_basic() {
        init_test("promote_regression_case_basic");
        let case = crate::lab::fuzz::FuzzRegressionCase {
            seed: 0xDEAD,
            replay_seed: 0xBEEF,
            certificate_hash: 0x1111,
            trace_fingerprint: 0x2222,
            violation_categories: vec!["obligation_leak".to_string()],
        };
        let promoted = promote_regression_case(&case, "obligation", "v1");
        assert!(promoted.identity.scenario_id.contains("regression"));
        assert_eq!(promoted.replay_seed, 0xBEEF);
        assert_eq!(promoted.violation_categories, vec!["obligation_leak"]);
        crate::test_complete!("promote_regression_case_basic");
    }

    #[test]
    fn promote_regression_corpus_preserves_order() {
        init_test("promote_regression_corpus_preserves_order");
        let corpus = crate::lab::fuzz::FuzzRegressionCorpus {
            schema_version: 1,
            base_seed: 42,
            iterations: 1000,
            cases: vec![
                crate::lab::fuzz::FuzzRegressionCase {
                    seed: 1,
                    replay_seed: 10,
                    certificate_hash: 0,
                    trace_fingerprint: 0,
                    violation_categories: vec!["a".to_string()],
                },
                crate::lab::fuzz::FuzzRegressionCase {
                    seed: 2,
                    replay_seed: 20,
                    certificate_hash: 0,
                    trace_fingerprint: 0,
                    violation_categories: vec!["b".to_string()],
                },
            ],
        };
        let promoted = promote_regression_corpus(&corpus, "test", "v1");
        assert_eq!(promoted.len(), 2);
        assert_eq!(promoted[0].replay_seed, 10);
        assert_eq!(promoted[1].replay_seed, 20);
        assert_eq!(promoted[0].campaign_base_seed, Some(42));
        assert_eq!(promoted[0].campaign_iteration, Some(0));
        assert_eq!(promoted[1].campaign_iteration, Some(1));
        crate::test_complete!("promote_regression_corpus_preserves_order");
    }

    #[test]
    fn promoted_fuzz_scenario_runs_through_harness() {
        init_test("promoted_fuzz_scenario_runs_through_harness");
        let finding = make_test_fuzz_finding(42);
        let promoted = promote_fuzz_finding(&finding, "test.surface", "v1");

        // Use the promoted identity in a DualRunHarness
        let result = DualRunHarness::from_identity(promoted.identity)
            .lab(|_config| make_happy_semantics())
            .live(|_seed, _entropy| make_happy_semantics())
            .run();

        assert!(result.passed());
        crate::test_complete!("promoted_fuzz_scenario_runs_through_harness");
    }

    #[test]
    fn promoted_regression_corpus_case_runs_through_harness_with_campaign_metadata() {
        init_test("promoted_regression_corpus_case_runs_through_harness_with_campaign_metadata");
        let corpus = crate::lab::fuzz::FuzzRegressionCorpus {
            schema_version: 1,
            base_seed: 0x2A,
            iterations: 3,
            cases: vec![crate::lab::fuzz::FuzzRegressionCase {
                seed: 0x10,
                replay_seed: 0x11,
                certificate_hash: 0x2222,
                trace_fingerprint: 0x3333,
                violation_categories: vec!["obligation_leak".to_string()],
            }],
        };
        let promoted = promote_regression_corpus(&corpus, "test.surface", "v1");
        let promoted = promoted[0]
            .clone()
            .with_source_artifact_path("/tmp/fuzz/corpus.json");

        assert_eq!(promoted.campaign_base_seed, Some(0x2A));
        assert_eq!(promoted.campaign_iteration, Some(0));
        assert_eq!(
            promoted.identity.metadata.get("campaign_base_seed"),
            Some(&"0x2A".to_string())
        );
        assert_eq!(
            promoted.identity.metadata.get("campaign_iteration"),
            Some(&"0".to_string())
        );

        let metadata = promoted.lab_replay_metadata();
        assert_eq!(metadata.trace_fingerprint, Some(0x3333));
        assert_eq!(
            metadata.artifact_path.as_deref(),
            Some("/tmp/fuzz/corpus.json")
        );

        let result = DualRunHarness::from_identity(promoted.identity)
            .lab(|_config| make_happy_semantics())
            .live(|_seed, _entropy| make_happy_semantics())
            .run();
        assert!(result.passed());
        crate::test_complete!(
            "promoted_regression_corpus_case_runs_through_harness_with_campaign_metadata"
        );
    }

    fn make_test_exploration_report() -> crate::lab::explorer::ExplorationReport {
        use crate::lab::explorer::{
            CoverageMetrics, RunResult, SaturationMetrics, ViolationReport,
        };
        use crate::lab::runtime::InvariantViolation;

        crate::lab::explorer::ExplorationReport {
            total_runs: 3,
            unique_classes: 2,
            violations: vec![ViolationReport {
                seed: 0x20,
                steps: 42,
                violations: vec![InvariantViolation::QuiescenceViolation],
                fingerprint: 0xAAAA,
            }],
            coverage: CoverageMetrics {
                equivalence_classes: 2,
                total_runs: 3,
                new_class_discoveries: 2,
                class_run_counts: BTreeMap::from([(0xAAAA, 2), (0xBBBB, 1)]),
                novelty_histogram: BTreeMap::from([(0, 1), (1, 2)]),
                saturation: SaturationMetrics {
                    window: 10,
                    saturated: false,
                    existing_class_hits: 1,
                    runs_since_last_new_class: Some(1),
                },
            },
            top_unexplored: Vec::new(),
            runs: vec![
                RunResult {
                    seed: 0x10,
                    steps: 10,
                    fingerprint: 0xAAAA,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 0x100,
                },
                RunResult {
                    seed: 0x20,
                    steps: 42,
                    fingerprint: 0xAAAA,
                    is_new_class: false,
                    violations: vec![InvariantViolation::QuiescenceViolation],
                    certificate_hash: 0x200,
                },
                RunResult {
                    seed: 0x30,
                    steps: 11,
                    fingerprint: 0xBBBB,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 0x300,
                },
            ],
        }
    }

    #[test]
    fn promote_exploration_report_prefers_lowest_violation_seed_and_preserves_lineage() {
        init_test("promote_exploration_report_prefers_lowest_violation_seed_and_preserves_lineage");
        let report = make_test_exploration_report();
        let promoted = promote_exploration_report(&report, "schedule.surface", "v1");
        assert_eq!(promoted.len(), 2);

        let promoted_class = promoted
            .iter()
            .find(|scenario| scenario.trace_fingerprint == 0xAAAA)
            .expect("class 0xAAAA should be promoted");
        assert_eq!(promoted_class.replay_seed, 0x20);
        assert_eq!(promoted_class.original_seeds, vec![0x10, 0x20]);
        assert_eq!(promoted_class.violation_seeds, vec![0x20]);
        assert_eq!(
            promoted_class.supporting_schedule_hashes,
            vec![0x100, 0x200]
        );
        assert!(
            promoted_class
                .violation_summaries
                .iter()
                .any(|summary| summary.contains("region closed without quiescence"))
        );
        assert_eq!(
            promoted_class.identity.metadata.get("promoted_from"),
            Some(&"exploration_report".to_owned())
        );
        assert_eq!(
            promoted_class
                .identity
                .metadata
                .get("representative_reason"),
            Some(&"lowest_violation_seed".to_owned())
        );
        crate::test_complete!(
            "promote_exploration_report_prefers_lowest_violation_seed_and_preserves_lineage"
        );
    }

    #[test]
    fn promoted_exploration_scenario_replay_metadata_includes_artifact_and_repro() {
        init_test("promoted_exploration_scenario_replay_metadata_includes_artifact_and_repro");
        let report = make_test_exploration_report();
        let promoted = promote_exploration_report(&report, "schedule.surface", "v1");
        let promoted = promoted[0]
            .clone()
            .with_source_artifact_path("/tmp/dpor/report.json");

        let metadata = promoted.lab_replay_metadata();
        assert_eq!(metadata.trace_fingerprint, Some(promoted.trace_fingerprint));
        assert_eq!(
            metadata.schedule_hash,
            Some(promoted.representative_schedule_hash)
        );
        assert_eq!(
            metadata.artifact_path.as_deref(),
            Some("/tmp/dpor/report.json")
        );
        assert_eq!(
            metadata.repro_command.as_deref(),
            Some(promoted.repro_command().as_str())
        );
        crate::test_complete!(
            "promoted_exploration_scenario_replay_metadata_includes_artifact_and_repro"
        );
    }

    #[test]
    fn promote_exploration_report_serde_roundtrip() {
        init_test("promote_exploration_report_serde_roundtrip");
        let report = make_test_exploration_report();
        let promoted = promote_exploration_report(&report, "schedule.surface", "v1");
        let json = serde_json::to_string_pretty(&promoted).unwrap();
        let parsed: Vec<PromotedExplorationScenario> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), promoted.len());
        assert_eq!(parsed[0].trace_fingerprint, promoted[0].trace_fingerprint);
        crate::test_complete!("promote_exploration_report_serde_roundtrip");
    }
}
