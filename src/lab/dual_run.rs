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

pub fn derive_scenario_seed(root: u64, scenario: &str) -> u64 {
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
            "rch exec -- env ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
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
    let counts_unknown = loser_drain_counts_unknown(lab) || loser_drain_counts_unknown(live);
    if !counts_unknown && lab.expected_losers != live.expected_losers {
        mismatches.push(SemanticMismatch {
            field: "semantics.loser_drain.expected_losers".to_string(),
            description: "Expected losers count mismatch".to_string(),
            lab_value: format!("{}", lab.expected_losers),
            live_value: format!("{}", live.expected_losers),
        });
    }
    if !counts_unknown && lab.drained_losers != live.drained_losers {
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
    // The published dual-run contract requires quiescence, child/finalizer
    // counts, and close completion for region-close comparison. Non-quiescent
    // root_state is only a best-effort phase hint, and adapters do not always
    // have equally precise visibility there.
    if lab.quiescent && live.quiescent && lab.root_state != live.root_state {
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
    let counts_unknown = region_close_counts_unknown(lab) || region_close_counts_unknown(live);
    if !counts_unknown && lab.live_children != live.live_children {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.live_children".to_string(),
            description: "Region live child count mismatch".to_string(),
            lab_value: format!("{}", lab.live_children),
            live_value: format!("{}", live.live_children),
        });
    }
    if !counts_unknown && lab.finalizers_pending != live.finalizers_pending {
        mismatches.push(SemanticMismatch {
            field: "semantics.region_close.finalizers_pending".to_string(),
            description: "Region finalizers pending mismatch".to_string(),
            lab_value: format!("{}", lab.finalizers_pending),
            live_value: format!("{}", live.finalizers_pending),
        });
    }
}

fn loser_drain_counts_unknown(record: &LoserDrainRecord) -> bool {
    record.applicable
        && record.expected_losers == 0
        && record.drained_losers == 0
        && record
            .evidence
            .as_deref()
            .is_some_and(|source| source.starts_with("oracle.loser_drain."))
}

fn region_close_counts_unknown(record: &RegionCloseRecord) -> bool {
    !record.quiescent
        && !record.close_completed
        && record.root_state == RegionState::Closing
        && record.live_children == 0
        && record.finalizers_pending == 0
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
    if !live.provenance.nondeterminism_notes.is_empty() {
        return SchedulerNoiseClass::NondeterminismNotesOnly;
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
    if obs.semantics.cancellation.requested
        && obs.semantics.cancellation.cleanup_completed
        && !obs.semantics.cancellation.finalization_completed
    {
        violations.push(format!(
            "Cancellation finalization incomplete: phase={:?}",
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
    let replay = ReplayMetadata::for_live(identity.family_id(), &identity.seed_plan)
        .with_nondeterminism_notes(nondeterminism_notes.clone());

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
        // This helper is used once a close path is already under evaluation,
        // so non-quiescent states should reflect drain/finalize progress rather
        // than pretending the region is still open for new work.
        root_state: if quiescent {
            RegionState::Closed
        } else if all_children_joined {
            RegionState::Finalizing
        } else {
            RegionState::Draining
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
            RegionState::Closing
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
    let provenance = live_result
        .metadata
        .replay
        .clone()
        .with_nondeterminism_notes(live_result.metadata.nondeterminism_notes.clone());
    NormalizedObservable::new(
        identity,
        RuntimeKind::Live,
        live_result.semantics.clone(),
        provenance,
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
            "rch exec -- env ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
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
            InvariantViolation::CancellationProtocol { .. } => "cancellation_protocol".to_string(),
            InvariantViolation::TestPanic { .. } => "test_panic".to_string(),
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
            "rch exec -- env ASUPERSYNC_SEED=0x{:X} cargo test {} -- --nocapture",
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
    .with_seed_plan(
        SeedPlan::inherit(replay_seed, scenario_id.clone()).with_entropy_seed(finding.entropy_seed),
    )
    .with_metadata("promoted_from", "fuzz_finding")
    .with_metadata("original_seed", format!("0x{:X}", finding.seed))
    .with_metadata("entropy_seed", format!("0x{:X}", finding.entropy_seed))
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
    .with_seed_plan(
        SeedPlan::inherit(case.replay_seed, scenario_id.clone())
            .with_entropy_seed(case.entropy_seed),
    )
    .with_metadata("promoted_from", "regression_case")
    .with_metadata("original_seed", format!("0x{:X}", case.seed))
    .with_metadata("entropy_seed", format!("0x{:X}", case.entropy_seed))
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
            promoted.identity.metadata.insert(
                "campaign_entropy_seed".to_string(),
                format!("0x{:X}", corpus.entropy_seed),
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
#[path = "dual_run_inline_tests.rs"]
mod tests;
