//! Doctor-oriented CLI primitives.
//!
//! This module provides deterministic workspace scanning utilities used by
//! `doctor_asupersync` surfaces.

use super::Outputtable;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Deterministic workspace scan report.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkspaceScanReport {
    /// Root path used for the scan.
    pub root: String,
    /// Manifest path used as the scan entrypoint.
    pub workspace_manifest: String,
    /// Scanner schema version for downstream consumers.
    pub scanner_version: String,
    /// Capability taxonomy version used for this scan.
    pub taxonomy_version: String,
    /// Workspace members discovered in deterministic order.
    pub members: Vec<WorkspaceMember>,
    /// Capability-flow edges from member crate to runtime surface.
    pub capability_edges: Vec<CapabilityEdge>,
    /// Non-fatal scan warnings.
    pub warnings: Vec<String>,
    /// Deterministic structured scan events.
    pub events: Vec<ScanEvent>,
}

/// Deterministic operator/persona model contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorModelContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Operator personas in deterministic order.
    pub personas: Vec<OperatorPersona>,
    /// Named decision loops used by doctor workflows.
    pub decision_loops: Vec<DecisionLoop>,
    /// Global evidence requirements attached to all workflows.
    pub global_evidence_requirements: Vec<String>,
    /// Deterministic information architecture and navigation topology.
    pub navigation_topology: NavigationTopology,
}

/// Deterministic IA/navigation topology for operator workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavigationTopology {
    /// Topology version for compatibility checks.
    pub version: String,
    /// Entry-point screens in lexical order.
    pub entry_points: Vec<String>,
    /// Screen definitions in lexical `id` order.
    pub screens: Vec<NavigationScreen>,
    /// Deterministic route graph edges in lexical `id` order.
    pub routes: Vec<NavigationRoute>,
    /// Deterministic keyboard binding catalog.
    pub keyboard_bindings: Vec<NavigationKeyboardBinding>,
    /// Structured route-event schema for observability.
    pub route_events: Vec<NavigationRouteEvent>,
}

/// One screen node in the navigation topology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavigationScreen {
    /// Stable screen identifier.
    pub id: String,
    /// Human-readable screen label.
    pub label: String,
    /// Canonical route path for this screen.
    pub route: String,
    /// Personas that primarily own this surface.
    pub personas: Vec<String>,
    /// Canonical panel set for this surface.
    pub primary_panels: Vec<String>,
    /// Deterministic focus order for panel traversal.
    pub focus_order: Vec<String>,
    /// Recovery route identifiers reachable from this screen.
    pub recovery_routes: Vec<String>,
}

/// One directed navigation route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavigationRoute {
    /// Stable route identifier.
    pub id: String,
    /// Source screen identifier.
    pub from_screen: String,
    /// Destination screen identifier.
    pub to_screen: String,
    /// Trigger for this route.
    pub trigger: String,
    /// Guard expression for this route.
    pub guard: String,
    /// Outcome class (`success`, `cancelled`, `failed`).
    pub outcome: String,
}

/// Scope of a keyboard binding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NavigationBindingScope {
    /// Binding is global and available from any screen.
    Global,
    /// Binding applies within a screen context.
    Screen,
}

/// One deterministic keyboard binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavigationKeyboardBinding {
    /// Key chord.
    pub key: String,
    /// Action executed by this binding.
    pub action: String,
    /// Binding scope.
    pub scope: NavigationBindingScope,
    /// Optional destination screen.
    pub target_screen: Option<String>,
    /// Optional destination panel.
    pub target_panel: Option<String>,
}

/// One route-event schema entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NavigationRouteEvent {
    /// Event key.
    pub event: String,
    /// Required fields for this event in lexical order.
    pub required_fields: Vec<String>,
}

/// One operator persona in the doctor product model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorPersona {
    /// Stable identifier.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Primary mission statement.
    pub mission: String,
    /// Deterministic mission-success signals used for acceptance checks.
    pub mission_success_signals: Vec<String>,
    /// Primary UI surfaces used by this persona.
    pub primary_views: Vec<String>,
    /// Default decision loop identifier.
    pub default_decision_loop: String,
    /// High-stakes decisions this persona is expected to make.
    pub high_stakes_decisions: Vec<PersonaDecision>,
}

/// One high-stakes operator decision mapped to the canonical decision loops.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersonaDecision {
    /// Stable decision identifier within the persona.
    pub id: String,
    /// Human-readable decision prompt.
    pub prompt: String,
    /// Decision loop this decision belongs to.
    pub decision_loop: String,
    /// Step identifier inside `decision_loop` this decision binds to.
    pub decision_step: String,
    /// Evidence keys required for making the decision.
    pub required_evidence: Vec<String>,
}

/// Deterministic decision loop definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionLoop {
    /// Stable identifier.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Ordered steps for the loop.
    pub steps: Vec<DecisionStep>,
}

/// One step inside a decision loop.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionStep {
    /// Stable step identifier within the loop.
    pub id: String,
    /// Action performed at this step.
    pub action: String,
    /// Required evidence keys for this step.
    pub required_evidence: Vec<String>,
}

/// Final UX acceptance signoff matrix contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxSignoffMatrixContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Baseline matrix version this signoff matrix extends.
    pub baseline_matrix_version: String,
    /// Required structured logging fields for every signoff assertion.
    pub logging_requirements: Vec<String>,
    /// Journey-level acceptance signoff definitions.
    pub journeys: Vec<UxJourneySignoff>,
    /// Rollout pass/fail gate policy.
    pub rollout_gate: UxRolloutGatePolicy,
}

/// One operator journey in the signoff matrix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxJourneySignoff {
    /// Stable journey identifier.
    pub journey_id: String,
    /// Persona id this journey validates.
    pub persona_id: String,
    /// Decision loop id this journey validates.
    pub decision_loop_id: String,
    /// Canonical screen path for the journey.
    pub canonical_path: Vec<String>,
    /// Transition assertions for the happy path.
    pub transitions: Vec<UxTransitionAssertion>,
    /// Interruption/cancellation assertions for this journey.
    pub interruption_assertions: Vec<UxInterruptionAssertion>,
    /// Recovery assertions for this journey.
    pub recovery_assertions: Vec<UxRecoveryAssertion>,
    /// Evidence visibility assertions for this journey.
    pub evidence_assertions: Vec<UxEvidenceAssertion>,
}

/// One happy-path transition assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxTransitionAssertion {
    /// Stable assertion id.
    pub id: String,
    /// Source screen id.
    pub from_screen: String,
    /// Destination screen id.
    pub to_screen: String,
    /// Referenced topology route id.
    pub route_ref: String,
    /// Expected focused panel after transition.
    pub expected_focus_panel: String,
}

/// One interruption-path assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxInterruptionAssertion {
    /// Stable assertion id.
    pub id: String,
    /// Screen where interruption is injected.
    pub screen_id: String,
    /// Trigger producing interruption.
    pub trigger: String,
    /// Expected state class after interruption.
    pub expected_state: String,
}

/// One recovery-path assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxRecoveryAssertion {
    /// Stable assertion id.
    pub id: String,
    /// Source screen id.
    pub from_screen: String,
    /// Destination screen id.
    pub to_screen: String,
    /// Referenced recovery route id.
    pub route_ref: String,
    /// Whether rerun context must be preserved through recovery.
    pub requires_rerun_context: bool,
}

/// One evidence visibility assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxEvidenceAssertion {
    /// Stable assertion id.
    pub id: String,
    /// Screen id where evidence must be visible.
    pub screen_id: String,
    /// Required evidence keys that must be present.
    pub required_evidence_keys: Vec<String>,
}

/// Rollout gate policy for signoff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UxRolloutGatePolicy {
    /// Minimum aggregate pass rate required for signoff.
    pub min_pass_rate_percent: u8,
    /// No critical-severity failures may remain for signoff.
    pub require_zero_critical_failures: bool,
    /// Journeys that must pass before rollout.
    pub required_journeys: Vec<String>,
    /// Remediation actions required when signoff criteria fail.
    pub mandatory_remediations: Vec<String>,
}

/// Deterministic screen-to-engine data contract for doctor TUI surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenEngineContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Operator-model contract version this screen contract depends on.
    pub operator_model_version: String,
    /// Globally required request envelope fields.
    pub global_request_fields: Vec<String>,
    /// Globally required response envelope fields.
    pub global_response_fields: Vec<String>,
    /// Compatibility window and migration guidance.
    pub compatibility: ContractCompatibility,
    /// Per-screen request/response/state contracts.
    pub screens: Vec<ScreenContract>,
    /// Standardized error envelope for rejected or invalid payloads.
    pub error_envelope: ContractErrorEnvelope,
}

/// Compatibility metadata for contract readers/writers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractCompatibility {
    /// Oldest supported reader contract version.
    pub minimum_reader_version: String,
    /// Supported reader versions in lexical order.
    pub supported_reader_versions: Vec<String>,
    /// Additive/breaking migration steps in deterministic order.
    pub migration_guidance: Vec<MigrationGuidance>,
}

/// One migration step between contract versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationGuidance {
    /// Source contract version.
    pub from_version: String,
    /// Target contract version.
    pub to_version: String,
    /// Whether this migration introduces breaking behavior.
    pub breaking: bool,
    /// Required downstream actions.
    pub required_actions: Vec<String>,
}

/// One screen surface contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenContract {
    /// Stable screen identifier.
    pub id: String,
    /// Human-readable surface label.
    pub label: String,
    /// Primary operator personas expected to use this screen.
    pub personas: Vec<String>,
    /// Request payload schema.
    pub request_schema: PayloadSchema,
    /// Response payload schema.
    pub response_schema: PayloadSchema,
    /// Allowed screen states in lexical order.
    pub states: Vec<String>,
    /// Allowed deterministic state transitions.
    pub transitions: Vec<StateTransition>,
}

/// Schema for one payload channel (request or response).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadSchema {
    /// Schema identifier for compatibility checks.
    pub schema_id: String,
    /// Required payload fields in lexical order.
    pub required_fields: Vec<PayloadField>,
    /// Optional payload fields in lexical order.
    pub optional_fields: Vec<PayloadField>,
}

/// One typed payload field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PayloadField {
    /// Stable field key.
    pub key: String,
    /// Data type descriptor (e.g. `string`, `u64`, `enum`).
    pub field_type: String,
    /// Field-level contract note.
    pub description: String,
}

/// One legal state transition for a screen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateTransition {
    /// Source state.
    pub from_state: String,
    /// Target state.
    pub to_state: String,
    /// Trigger/action that causes the transition.
    pub trigger: String,
    /// Transition outcome class (`success`, `cancelled`, `failed`).
    pub outcome: String,
}

/// Shared error envelope contract for rejected payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractErrorEnvelope {
    /// Required fields present in every error envelope.
    pub required_fields: Vec<String>,
    /// Known retryable error codes.
    pub retryable_codes: Vec<String>,
}

/// Synthetic exchange outcome for contract simulations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExchangeOutcome {
    /// Request/response completed successfully.
    Success,
    /// Request was cancelled and should preserve replay context.
    Cancelled,
    /// Request failed with an engine error.
    Failed,
}

/// Screen request payload used by exchange simulations and tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenExchangeRequest {
    /// Screen identifier.
    pub screen_id: String,
    /// Correlation identifier for the exchange.
    pub correlation_id: String,
    /// Rerun context pointer (command/seed/replay pointer).
    pub rerun_context: String,
    /// Request payload values by field key.
    pub payload: BTreeMap<String, String>,
    /// Requested outcome mode.
    pub outcome: ExchangeOutcome,
}

/// Screen response envelope emitted by exchange simulations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenExchangeEnvelope {
    /// Screen contract version.
    pub contract_version: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Screen identifier.
    pub screen_id: String,
    /// Outcome class (`success`, `cancelled`, `failed`).
    pub outcome_class: String,
    /// Deterministic response payload.
    pub response_payload: BTreeMap<String, String>,
}

/// Structured rejection log used for invalid payload envelopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedPayloadLog {
    /// Contract version under which validation failed.
    pub contract_version: String,
    /// Correlation identifier for the rejected payload.
    pub correlation_id: String,
    /// Validation failures in deterministic lexical order.
    pub validation_failures: Vec<String>,
    /// Rerun context supplied by the caller.
    pub rerun_context: String,
}

/// Terminal color capability class used for deterministic theme selection.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TerminalCapabilityClass {
    /// 24-bit color terminals.
    TrueColor,
    /// 256-color terminals.
    Ansi256,
    /// 16-color terminals.
    Ansi16,
}

/// Deterministic visual-language contract for doctor TUI surfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualLanguageContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Source visual baseline.
    pub source_showcase: String,
    /// Default profile used when no explicit screen mapping exists.
    pub default_profile_id: String,
    /// Available style profiles in lexical profile-id order.
    pub profiles: Vec<VisualStyleProfile>,
    /// Screen-specific style bindings in lexical screen-id order.
    pub screen_styles: Vec<ScreenVisualStyle>,
    /// Accessibility/readability guardrails.
    pub accessibility_constraints: Vec<String>,
    /// Explicit non-goals to avoid visual drift.
    pub non_goals: Vec<String>,
}

/// One visual profile (palette + typography + motion + layout motifs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualStyleProfile {
    /// Stable profile identifier.
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Minimum terminal capability required for this profile.
    pub minimum_capability: TerminalCapabilityClass,
    /// Typography token stack in lexical order.
    pub typography_tokens: Vec<String>,
    /// Spacing token stack in lexical order.
    pub spacing_tokens: Vec<String>,
    /// Palette tokens in lexical role order.
    pub palette_tokens: Vec<ColorToken>,
    /// Panel motif tokens in lexical order.
    pub panel_motifs: Vec<String>,
    /// Motion cues in lexical cue-id order.
    pub motion_cues: Vec<MotionCue>,
    /// Optional fallback profile for weaker terminal capabilities.
    pub fallback_profile_id: Option<String>,
    /// Readability notes for operators.
    pub readability_notes: Vec<String>,
}

/// One color token keyed by semantic role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColorToken {
    /// Semantic role key.
    pub role: String,
    /// Foreground token value.
    pub fg: String,
    /// Background token value.
    pub bg: String,
    /// Accent token value.
    pub accent: String,
}

/// One motion cue for deterministic transitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MotionCue {
    /// Stable cue identifier.
    pub id: String,
    /// Trigger event.
    pub trigger: String,
    /// Animation pattern.
    pub pattern: String,
    /// Duration in milliseconds.
    pub duration_ms: u16,
}

/// Screen-level mapping from semantic surface to style profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenVisualStyle {
    /// Stable screen identifier.
    pub screen_id: String,
    /// Preferred profile identifier for this screen.
    pub preferred_profile_id: String,
    /// Required semantic color roles for this screen.
    pub required_color_roles: Vec<String>,
    /// Canonical layout motif when preferred profile is applied.
    pub canonical_layout_motif: String,
    /// Degraded layout motif when fallback is applied.
    pub degraded_layout_motif: String,
}

/// Structured visual-theme event emitted during token resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualThemeEvent {
    /// Event kind (`theme_selected`, `theme_fallback`, `token_resolution_failure`, etc).
    pub event_kind: String,
    /// Correlation identifier for this render path.
    pub correlation_id: String,
    /// Screen identifier for this event.
    pub screen_id: String,
    /// Selected profile identifier.
    pub profile_id: String,
    /// Terminal capability class used for this resolution.
    pub capability_class: TerminalCapabilityClass,
    /// Human-readable event message.
    pub message: String,
    /// Actionable remediation hint for operators.
    pub remediation_hint: String,
}

/// Deterministic transcript of one screen token-application flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VisualApplicationTranscript {
    /// Visual contract version used for this application.
    pub contract_version: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Screen identifier.
    pub screen_id: String,
    /// Selected profile identifier.
    pub selected_profile_id: String,
    /// Whether a fallback profile was applied.
    pub fallback_applied: bool,
    /// Applied layout motif.
    pub applied_layout_motif: String,
    /// Required roles that were missing from the selected profile.
    pub missing_roles: Vec<String>,
    /// Structured visual events emitted during resolution.
    pub events: Vec<VisualThemeEvent>,
}

/// One raw runtime artifact prior to deterministic normalization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeArtifact {
    /// Stable artifact identifier supplied by the caller.
    pub artifact_id: String,
    /// Artifact type (`trace`, `structured_log`, `ubs_findings`, `benchmark`, ...).
    pub artifact_type: String,
    /// Source file path or logical source pointer.
    pub source_path: String,
    /// Replay pointer/command used to regenerate this artifact.
    pub replay_pointer: String,
    /// Raw artifact body.
    pub content: String,
}

/// Normalized evidence record emitted from one artifact input.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRecord {
    /// Stable evidence identifier.
    pub evidence_id: String,
    /// Artifact identifier that produced this record.
    pub artifact_id: String,
    /// Canonical artifact type.
    pub artifact_type: String,
    /// Source path pointer.
    pub source_path: String,
    /// Correlation identifier for cross-system joins.
    pub correlation_id: String,
    /// Scenario identifier used for deterministic replay.
    pub scenario_id: String,
    /// Seed or seed pointer (string to support numeric/hash forms).
    pub seed: String,
    /// Outcome class (`success`, `cancelled`, `failed`).
    pub outcome_class: String,
    /// Human-readable summary.
    pub summary: String,
    /// Replay pointer propagated from source artifact.
    pub replay_pointer: String,
    /// Source provenance metadata.
    pub provenance: EvidenceProvenance,
}

/// Deterministic provenance metadata for a normalized evidence record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceProvenance {
    /// Deterministic normalization rule identifier.
    pub normalization_rule: String,
    /// Stable source digest generated from raw artifact content.
    pub source_digest: String,
}

/// One rejected artifact entry with deterministic reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectedArtifact {
    /// Artifact identifier.
    pub artifact_id: String,
    /// Artifact type.
    pub artifact_type: String,
    /// Source path pointer.
    pub source_path: String,
    /// Replay pointer/command.
    pub replay_pointer: String,
    /// Deterministic rejection reason.
    pub reason: String,
}

/// Structured ingestion event for deterministic diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestionEvent {
    /// Stage name (`ingest_start`, `parse_artifact`, `normalize`, ...).
    pub stage: String,
    /// Level (`info` | `warn`).
    pub level: String,
    /// Event message.
    pub message: String,
    /// Synthetic deterministic elapsed milliseconds.
    pub elapsed_ms: u64,
    /// Artifact identifier when stage is artifact-scoped.
    pub artifact_id: Option<String>,
    /// Replay pointer when available.
    pub replay_pointer: Option<String>,
}

/// End-to-end deterministic report for runtime evidence ingestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceIngestionReport {
    /// Evidence schema version.
    pub schema_version: String,
    /// Ingestion run identifier.
    pub run_id: String,
    /// Normalized records in deterministic order.
    pub records: Vec<EvidenceRecord>,
    /// Rejected artifacts in deterministic order.
    pub rejected: Vec<RejectedArtifact>,
    /// Structured ingestion events for replay/debugging.
    pub events: Vec<IngestionEvent>,
}

/// Typed definition for one required field in the logging envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoggingFieldSpec {
    /// Stable field key.
    pub key: String,
    /// Data type descriptor (e.g. `string`, `enum`).
    pub field_type: String,
    /// Deterministic formatting rule.
    pub format_rule: String,
    /// Field-level contract note.
    pub description: String,
}

/// Correlation primitive used for cross-flow joins.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrelationPrimitiveSpec {
    /// Stable primitive key.
    pub key: String,
    /// Deterministic formatting rule.
    pub format_rule: String,
    /// Human-readable purpose for operators.
    pub purpose: String,
}

/// Core-flow logging requirements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoggingFlowSpec {
    /// Stable flow identifier (`execution`, `replay`, `remediation`, `integration`).
    pub flow_id: String,
    /// Human-readable flow description.
    pub description: String,
    /// Required fields for this flow in lexical order.
    pub required_fields: Vec<String>,
    /// Optional fields for this flow in lexical order.
    pub optional_fields: Vec<String>,
    /// Allowed event kinds for this flow in lexical order.
    pub event_kinds: Vec<String>,
}

/// Baseline structured-logging contract for doctor flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredLoggingContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Required envelope fields and formatting rules.
    pub envelope_required_fields: Vec<LoggingFieldSpec>,
    /// Correlation primitives required across all core flows.
    pub correlation_primitives: Vec<CorrelationPrimitiveSpec>,
    /// Allowed normalized outcome classes in lexical order.
    pub outcome_classes: Vec<String>,
    /// Core flow requirements in lexical order by `flow_id`.
    pub core_flows: Vec<LoggingFlowSpec>,
    /// Event taxonomy in lexical order.
    pub event_taxonomy: Vec<String>,
    /// Compatibility/versioning guidance for consumers.
    pub compatibility: ContractCompatibility,
}

/// One normalized structured-log event emitted under the baseline contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredLogEvent {
    /// Contract version used for this event.
    pub contract_version: String,
    /// Flow identifier (`execution`, `replay`, `remediation`, `integration`).
    pub flow_id: String,
    /// Event kind from taxonomy.
    pub event_kind: String,
    /// Field payload (deterministically keyed).
    pub fields: BTreeMap<String, String>,
}

/// Machine-readable remediation recipe DSL contract for doctor workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationRecipeContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Required upstream logging contract dependency.
    pub logging_contract_version: String,
    /// Required top-level recipe fields in lexical order.
    pub required_recipe_fields: Vec<String>,
    /// Required precondition fields in lexical order.
    pub required_precondition_fields: Vec<String>,
    /// Required rollback-plan fields in lexical order.
    pub required_rollback_fields: Vec<String>,
    /// Required confidence-input fields in lexical order.
    pub required_confidence_input_fields: Vec<String>,
    /// Allowed fix-intent identifiers in lexical order.
    pub allowed_fix_intents: Vec<String>,
    /// Allowed precondition predicates in lexical order.
    pub allowed_precondition_predicates: Vec<String>,
    /// Allowed rollback strategies in lexical order.
    pub allowed_rollback_strategies: Vec<String>,
    /// Confidence-input weights in lexical key order.
    pub confidence_weights: Vec<RemediationConfidenceWeight>,
    /// Risk-band policy in lexical band-id order.
    pub risk_bands: Vec<RemediationRiskBand>,
    /// Compatibility/versioning guidance for readers and writers.
    pub compatibility: ContractCompatibility,
}

/// One weighted confidence input used by the remediation scoring model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationConfidenceWeight {
    /// Stable confidence input key.
    pub key: String,
    /// Weight in basis points (0..=10_000).
    pub weight_bps: u16,
    /// Human-readable rationale for this signal.
    pub rationale: String,
}

/// One risk band used to classify confidence scores.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationRiskBand {
    /// Stable risk-band identifier.
    pub band_id: String,
    /// Inclusive lower score bound.
    pub min_score_inclusive: u8,
    /// Inclusive upper score bound.
    pub max_score_inclusive: u8,
    /// Whether human approval is mandatory for this band.
    pub requires_human_approval: bool,
    /// Whether auto-apply is allowed for this band.
    pub allow_auto_apply: bool,
}

/// One remediation recipe expressed against the DSL contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationRecipe {
    /// Stable recipe identifier.
    pub recipe_id: String,
    /// Target finding identifier.
    pub finding_id: String,
    /// Fix-intent identifier from contract allowlist.
    pub fix_intent: String,
    /// Preconditions in lexical key order.
    pub preconditions: Vec<RemediationPrecondition>,
    /// Rollback strategy for this recipe.
    pub rollback: RemediationRollbackPlan,
    /// Confidence inputs in lexical key order.
    pub confidence_inputs: Vec<RemediationConfidenceInput>,
    /// Optional override rationale for forced apply.
    pub override_justification: Option<String>,
}

/// One recipe precondition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationPrecondition {
    /// Stable precondition key.
    pub key: String,
    /// Predicate identifier from contract allowlist.
    pub predicate: String,
    /// Expected value encoded as a stable scalar string.
    pub expected_value: String,
    /// Evidence reference supporting this precondition.
    pub evidence_ref: String,
    /// Whether this precondition is mandatory.
    pub required: bool,
}

/// Rollback-plan surface for one recipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationRollbackPlan {
    /// Rollback strategy identifier from contract allowlist.
    pub strategy: String,
    /// Rollback command to revert an applied change.
    pub rollback_command: String,
    /// Verification command proving rollback success.
    pub verify_command: String,
    /// Timeout budget in seconds.
    pub timeout_secs: u32,
}

/// One confidence input value captured for a recipe instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationConfidenceInput {
    /// Confidence input key from contract weights.
    pub key: String,
    /// Input score (`0..=100`).
    pub score: u8,
    /// Input rationale.
    pub rationale: String,
    /// Evidence reference backing this score.
    pub evidence_ref: String,
}

/// Deterministic confidence-score output for one remediation recipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationConfidenceScore {
    /// Recipe identifier.
    pub recipe_id: String,
    /// Computed confidence score (`0..=100`).
    pub confidence_score: u8,
    /// Classified risk band.
    pub risk_band: String,
    /// Whether human approval is required.
    pub requires_human_approval: bool,
    /// Whether auto-apply is allowed.
    pub allow_auto_apply: bool,
    /// Deterministic weighted contribution trace.
    pub weighted_contributions: Vec<String>,
}

/// Deterministic fixture for remediation DSL validation/scoring.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationRecipeFixture {
    /// Stable fixture identifier.
    pub fixture_id: String,
    /// Human-readable fixture description.
    pub description: String,
    /// Canonical recipe payload.
    pub recipe: RemediationRecipe,
    /// Expected confidence score.
    pub expected_confidence_score: u8,
    /// Expected risk band id.
    pub expected_risk_band: String,
    /// Expected deterministic decision class.
    pub expected_decision: String,
}

/// Serializable bundle containing the remediation contract and fixtures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationRecipeBundle {
    /// Remediation recipe DSL contract.
    pub contract: RemediationRecipeContract,
    /// Deterministic fixture set.
    pub fixtures: Vec<RemediationRecipeFixture>,
}

/// Deterministic rch-backed execution-adapter contract for doctor orchestration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionAdapterContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Required upstream logging contract dependency.
    pub logging_contract_version: String,
    /// Required request envelope fields in lexical order.
    pub required_request_fields: Vec<String>,
    /// Required result envelope fields in lexical order.
    pub required_result_fields: Vec<String>,
    /// Command-class catalog in lexical class-id order.
    pub command_classes: Vec<ExecutionCommandClass>,
    /// Route/fallback policy catalog in lexical policy-id order.
    pub route_policies: Vec<ExecutionRoutePolicy>,
    /// Timeout profiles in lexical class-id order.
    pub timeout_profiles: Vec<ExecutionTimeoutProfile>,
    /// Allowed deterministic execution-state transitions.
    pub state_transitions: Vec<ExecutionStateTransition>,
    /// Failure taxonomy in lexical code order.
    pub failure_taxonomy: Vec<ExecutionFailureClass>,
    /// Required artifact-manifest fields in lexical order.
    pub artifact_manifest_fields: Vec<String>,
}

/// One command class supported by the execution adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionCommandClass {
    /// Stable class identifier.
    pub class_id: String,
    /// Human-readable class label.
    pub label: String,
    /// Allowed command prefixes for this class in lexical order.
    pub allowed_prefixes: Vec<String>,
    /// Whether this class must be routed through `rch`.
    pub force_rch: bool,
    /// Default timeout (seconds) for this class.
    pub default_timeout_secs: u32,
}

/// One deterministic route policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionRoutePolicy {
    /// Stable policy identifier.
    pub policy_id: String,
    /// Condition expression describing when this policy applies.
    pub condition: String,
    /// Route selected by this policy (`remote_rch`, `local_direct`, `fail_closed`).
    pub route: String,
    /// Retry strategy identifier.
    pub retry_strategy: String,
    /// Maximum retries allowed by this policy.
    pub max_retries: u8,
}

/// Timeout profile for one command class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionTimeoutProfile {
    /// Command class id this timeout profile applies to.
    pub class_id: String,
    /// Soft timeout threshold in seconds.
    pub soft_timeout_secs: u32,
    /// Hard timeout threshold in seconds.
    pub hard_timeout_secs: u32,
    /// Cancellation grace period in seconds.
    pub cancel_grace_secs: u32,
}

/// One legal execution-state transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionStateTransition {
    /// Source state.
    pub from_state: String,
    /// Trigger that causes the transition.
    pub trigger: String,
    /// Target state.
    pub to_state: String,
}

/// One deterministic failure-taxonomy entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionFailureClass {
    /// Stable failure code.
    pub code: String,
    /// Severity (`critical`, `high`, `medium`, `low`).
    pub severity: String,
    /// Whether this failure is retryable.
    pub retryable: bool,
    /// Required operator action for this failure.
    pub operator_action: String,
}

/// Request envelope for deterministic command planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionAdapterRequest {
    /// Stable command identifier.
    pub command_id: String,
    /// Command class id.
    pub command_class: String,
    /// Correlation id for replay/audit joins.
    pub correlation_id: String,
    /// Raw command text submitted by caller.
    pub raw_command: String,
    /// Whether remote execution is preferred when available.
    pub prefer_remote: bool,
}

/// Deterministic execution plan emitted by the adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionAdapterPlan {
    /// Stable command identifier.
    pub command_id: String,
    /// Command class id.
    pub command_class: String,
    /// Correlation id for replay/audit joins.
    pub correlation_id: String,
    /// Normalized command string.
    pub normalized_command: String,
    /// Routed command actually executed.
    pub routed_command: String,
    /// Selected route (`remote_rch`, `local_direct`, `fail_closed`).
    pub route: String,
    /// Effective timeout in seconds.
    pub timeout_secs: u32,
    /// Initial state for state-machine progression.
    pub initial_state: String,
    /// Required artifact-manifest field set.
    pub artifact_manifest_fields: Vec<String>,
}

/// Deterministic scenario-composer and run-queue manager contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioComposerContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Required execution-adapter dependency.
    pub execution_adapter_version: String,
    /// Required logging contract dependency.
    pub logging_contract_version: String,
    /// Required request fields in lexical order.
    pub required_request_fields: Vec<String>,
    /// Required queued-run fields in lexical order.
    pub required_run_fields: Vec<String>,
    /// Deterministic scenario template catalog in lexical template-id order.
    pub scenario_templates: Vec<ScenarioTemplate>,
    /// Deterministic run-queue policy.
    pub queue_policy: ScenarioRunQueuePolicy,
    /// Deterministic failure taxonomy for compose/queue operations.
    pub failure_taxonomy: Vec<ScenarioQueueFailureClass>,
}

/// One scenario template used for compose + queue planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioTemplate {
    /// Stable template identifier.
    pub template_id: String,
    /// Human-readable template description.
    pub description: String,
    /// Command classes required by this template in lexical order.
    pub required_command_classes: Vec<String>,
    /// Artifact classes expected from execution in lexical order.
    pub required_artifacts: Vec<String>,
    /// Default queue priority (0..=255, larger means higher priority).
    pub default_priority: u8,
    /// Retry budget for this template.
    pub max_retries: u8,
    /// Whether this template requires an explicit deterministic seed.
    pub requires_replay_seed: bool,
}

/// Deterministic run-queue policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioRunQueuePolicy {
    /// Maximum concurrent runs in `running` state.
    pub max_concurrent_runs: u16,
    /// Maximum queue depth accepted by the manager.
    pub max_queue_depth: u16,
    /// Dispatch policy identifier.
    pub dispatch_order: String,
    /// Priority-band labels in lexical order.
    pub priority_bands: Vec<String>,
    /// Queue-level cancellation policy.
    pub cancellation_policy: String,
}

/// One request passed to the scenario composer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioRunRequest {
    /// Stable run identifier.
    pub run_id: String,
    /// Template identifier to compose.
    pub template_id: String,
    /// Correlation identifier for replay/audit joins.
    pub correlation_id: String,
    /// Deterministic seed for replay.
    pub seed: String,
    /// Optional explicit priority override.
    pub priority_override: Option<u8>,
    /// Requester identity.
    pub requested_by: String,
}

/// One composed queue entry ready for execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioRunQueueEntry {
    /// Stable queue entry identifier.
    pub queue_id: String,
    /// Stable run identifier.
    pub run_id: String,
    /// Template identifier.
    pub template_id: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Deterministic seed.
    pub seed: String,
    /// Effective priority used by queue ordering.
    pub priority: u8,
    /// Queue state (`queued` | `running`).
    pub state: String,
    /// Required command classes for this run.
    pub command_classes: Vec<String>,
    /// Required artifact classes for this run.
    pub required_artifacts: Vec<String>,
    /// Remaining retries for this run.
    pub retries_remaining: u8,
}

/// One deterministic failure-taxonomy entry for scenario compose/queue flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioQueueFailureClass {
    /// Stable failure code.
    pub code: String,
    /// Severity (`critical`, `high`, `medium`, `low`).
    pub severity: String,
    /// Whether the failure is retryable.
    pub retryable: bool,
    /// Required operator action for this failure.
    pub operator_action: String,
}

/// Deterministic e2e harness core contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eHarnessCoreContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Required execution-adapter dependency.
    pub execution_adapter_version: String,
    /// Required logging-contract dependency.
    pub logging_contract_version: String,
    /// Required config fields in lexical order.
    pub required_config_fields: Vec<String>,
    /// Required transcript fields in lexical order.
    pub required_transcript_fields: Vec<String>,
    /// Required artifact-index fields in lexical order.
    pub required_artifact_index_fields: Vec<String>,
    /// Deterministic lifecycle states in lexical order.
    pub lifecycle_states: Vec<String>,
    /// Deterministic failure taxonomy.
    pub failure_taxonomy: Vec<E2eHarnessFailureClass>,
}

/// One deterministic failure-taxonomy entry for harness execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eHarnessFailureClass {
    /// Stable failure code.
    pub code: String,
    /// Severity (`critical`, `high`, `medium`, `low`).
    pub severity: String,
    /// Whether this failure is retryable.
    pub retryable: bool,
    /// Required operator action for this failure.
    pub operator_action: String,
}

/// Parsed deterministic e2e harness configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eHarnessConfig {
    /// Deterministic run identifier.
    pub run_id: String,
    /// Deterministic scenario identifier.
    pub scenario_id: String,
    /// Correlation identifier for joins across evidence surfaces.
    pub correlation_id: String,
    /// Deterministic replay seed.
    pub seed: String,
    /// Harness script identifier.
    pub script_id: String,
    /// Requester identity.
    pub requested_by: String,
    /// Scenario timeout in seconds.
    pub timeout_secs: u32,
    /// Expected top-level outcome (`success`, `failed`, `cancelled`).
    pub expected_outcome: String,
}

/// One deterministic transcript event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eHarnessTranscriptEvent {
    /// Event sequence number (1-based).
    pub sequence: u32,
    /// Logical stage identifier.
    pub stage: String,
    /// Lifecycle state after this event.
    pub state: String,
    /// Event outcome class.
    pub outcome_class: String,
    /// Human-readable event summary.
    pub message: String,
    /// Stage-local propagated seed.
    pub propagated_seed: String,
}

/// Deterministic transcript bundle for one harness run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eHarnessTranscript {
    /// Deterministic run identifier.
    pub run_id: String,
    /// Deterministic scenario identifier.
    pub scenario_id: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Root deterministic replay seed.
    pub seed: String,
    /// Ordered transcript events.
    pub events: Vec<E2eHarnessTranscriptEvent>,
}

/// One deterministic artifact-index record for harness outputs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eHarnessArtifactIndexEntry {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Artifact class (`transcript`, `structured_log`, `summary`).
    pub artifact_class: String,
    /// Canonical artifact path.
    pub artifact_path: String,
    /// Deterministic checksum hint for replay joins.
    pub checksum_hint: String,
}

/// Deterministic scenario-coverage contract for doctor e2e workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorScenarioCoveragePacksContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Required e2e harness contract dependency.
    pub e2e_harness_contract_version: String,
    /// Required structured logging contract dependency.
    pub logging_contract_version: String,
    /// Supported deterministic selection modes in lexical order.
    pub selection_modes: Vec<String>,
    /// Required pack-spec fields in lexical order.
    pub required_pack_fields: Vec<String>,
    /// Required run-report fields in lexical order.
    pub required_run_fields: Vec<String>,
    /// Required structured-log summary fields in lexical order.
    pub required_log_fields: Vec<String>,
    /// Minimum required pack ids in lexical order.
    pub minimum_required_pack_ids: Vec<String>,
    /// Policy guardrails for adding new coverage packs.
    pub add_pack_policy: Vec<String>,
    /// Canonical pack specifications in lexical `pack_id` order.
    pub coverage_packs: Vec<DoctorScenarioCoveragePackSpec>,
}

/// One deterministic scenario coverage-pack specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorScenarioCoveragePackSpec {
    /// Stable pack identifier.
    pub pack_id: String,
    /// Stable scenario identifier.
    pub scenario_id: String,
    /// Workflow variant (`cancellation`, `retry`, `degraded_dependency`, `recovery`).
    pub workflow_variant: String,
    /// Expected top-level outcome (`success`, `failed`, `cancelled`).
    pub expected_outcome: String,
    /// Deterministic stages used to build the transcript.
    pub stages: Vec<String>,
    /// Required artifact classes in lexical order.
    pub required_artifact_classes: Vec<String>,
    /// Failure-clustering key used by structured logs.
    pub failure_cluster: String,
    /// Operator-facing description for this pack.
    pub description: String,
}

/// Structured log summary emitted for one scenario-pack run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorScenarioCoverageStructuredLogSummary {
    /// Pack identifier.
    pub pack_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Root deterministic seed.
    pub seed: String,
    /// Normalized stage outcomes in sequence order.
    pub stage_outcomes: Vec<String>,
    /// Final outcome class.
    pub outcome_class: String,
    /// Failure cluster classification.
    pub failure_cluster: String,
    /// Canonical transcript artifact path.
    pub transcript_path: String,
    /// Canonical visual snapshot artifact path.
    pub snapshot_path: String,
    /// Canonical metrics artifact path.
    pub metrics_path: String,
    /// Canonical replay-metadata artifact path.
    pub replay_metadata_path: String,
    /// Canonical artifact-manifest path.
    pub artifact_manifest_path: String,
}

/// Deterministic visual snapshot emitted by the baseline harness runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorVisualHarnessSnapshot {
    /// Stable snapshot identifier.
    pub snapshot_id: String,
    /// Viewport width used for deterministic capture.
    pub viewport_width: u16,
    /// Viewport height used for deterministic capture.
    pub viewport_height: u16,
    /// Focused panel at capture time.
    pub focused_panel: String,
    /// Selected node identifier at capture time.
    pub selected_node_id: String,
    /// Deterministic digest of stage/outcome progression.
    pub stage_digest: String,
    /// Deterministic visual profile token.
    pub visual_profile: String,
    /// Capture index within this smoke run.
    pub capture_index: u32,
}

/// One artifact entry in the baseline visual harness manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorVisualHarnessArtifactRecord {
    /// Stable artifact identifier.
    pub artifact_id: String,
    /// Artifact class (`transcript`, `snapshot`, `metrics`, etc.).
    pub artifact_class: String,
    /// Canonical path for this artifact.
    pub artifact_path: String,
    /// Deterministic checksum hint for triage joins.
    pub checksum_hint: String,
    /// Retention class (`hot`, `warm`) for lifecycle policy.
    pub retention_class: String,
    /// Related artifact identifiers in lexical order.
    pub linked_artifacts: Vec<String>,
}

/// Deterministic artifact manifest for the baseline visual harness runtime.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorVisualHarnessArtifactManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// Deterministic run identifier.
    pub run_id: String,
    /// Deterministic scenario identifier.
    pub scenario_id: String,
    /// Root artifact directory for this run.
    pub artifact_root: String,
    /// Manifest records in lexical artifact-id order.
    pub records: Vec<DoctorVisualHarnessArtifactRecord>,
}

/// One deterministic scenario-pack execution report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorScenarioCoveragePackRun {
    /// Pack identifier.
    pub pack_id: String,
    /// Scenario identifier.
    pub scenario_id: String,
    /// Workflow variant for this run.
    pub workflow_variant: String,
    /// Selection mode that included this pack.
    pub selected_mode: String,
    /// Expected top-level outcome (`success`, `failed`, `cancelled`).
    pub expected_outcome: String,
    /// Observed terminal state (`completed`, `failed`, `cancelled`).
    pub terminal_state: String,
    /// Run status (`passed` when expected and observed outcomes align).
    pub status: String,
    /// Failure cluster classification.
    pub failure_cluster: String,
    /// Deterministic rerun command.
    pub repro_command: String,
    /// Deterministic transcript bundle.
    pub transcript: E2eHarnessTranscript,
    /// Deterministic artifact index.
    pub artifact_index: Vec<E2eHarnessArtifactIndexEntry>,
    /// Deterministic visual snapshot payload.
    pub visual_snapshot: DoctorVisualHarnessSnapshot,
    /// Deterministic artifact manifest with retention/cross-link metadata.
    pub artifact_manifest: DoctorVisualHarnessArtifactManifest,
    /// Structured log summary.
    pub structured_log_summary: DoctorScenarioCoverageStructuredLogSummary,
}

/// Deterministic smoke report spanning selected scenario packs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorScenarioCoveragePackSmokeReport {
    /// Report schema version.
    pub schema_version: String,
    /// Selection mode used for this report.
    pub selection_mode: String,
    /// Requester identity.
    pub requested_by: String,
    /// Root deterministic seed.
    pub seed: String,
    /// Distinct failure clusters in lexical order.
    pub failure_clusters: Vec<String>,
    /// Ordered pack-run reports.
    pub runs: Vec<DoctorScenarioCoveragePackRun>,
}

/// Deterministic beads/bv command-center contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeadsCommandCenterContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Canonical `br` command used to fetch ready work.
    pub br_ready_command: String,
    /// Canonical `br` command used to fetch blocked work.
    pub br_blocked_command: String,
    /// Canonical `bv` command used to fetch triage insights.
    pub bv_triage_command: String,
    /// Required fields for `br ready --json` entries in lexical order.
    pub required_ready_fields: Vec<String>,
    /// Required fields for `br blocked --json` entries in lexical order.
    pub required_blocker_fields: Vec<String>,
    /// Required fields for triage top-pick entries in lexical order.
    pub required_triage_fields: Vec<String>,
    /// Supported filter modes in lexical order.
    pub filter_modes: Vec<String>,
    /// Structured event taxonomy in lexical order.
    pub event_taxonomy: Vec<String>,
    /// Maximum age (seconds) before data is considered stale.
    pub stale_after_secs: u64,
}

/// One normalized ready-work record from beads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeadsReadyWorkItem {
    /// Bead identifier.
    pub id: String,
    /// Human-readable bead title.
    pub title: String,
    /// Bead status (`open`, `in_progress`, `closed`).
    pub status: String,
    /// Numeric priority (`0` highest).
    pub priority: u8,
    /// Optional assignee.
    pub assignee: Option<String>,
}

/// One normalized blocked-work record from beads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeadsBlockedItem {
    /// Bead identifier.
    pub id: String,
    /// Human-readable bead title.
    pub title: String,
    /// Bead status (`open`, `in_progress`, `closed`).
    pub status: String,
    /// Numeric priority (`0` highest).
    pub priority: u8,
    /// Upstream blocker identifiers in lexical order.
    pub blocked_by: Vec<String>,
}

/// One normalized triage recommendation row from `bv --robot-triage`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BvTriageRecommendation {
    /// Bead identifier.
    pub id: String,
    /// Human-readable bead title.
    pub title: String,
    /// Triage score from `bv`.
    pub score: f64,
    /// Count of downstream items this recommendation unblocks.
    pub unblocks: u32,
    /// Human-readable recommendation reasons in lexical order.
    pub reasons: Vec<String>,
}

/// One structured command-center event for diagnostics and replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BeadsCommandCenterEvent {
    /// Event kind (`command_invoked`, `parse_failure`, `snapshot_built`, etc).
    pub event_kind: String,
    /// Source stream (`ready`, `blocked`, `triage`, `snapshot`).
    pub source: String,
    /// Deterministic event message.
    pub message: String,
}

/// Deterministic command-center snapshot for the beads/bv pane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BeadsCommandCenterSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Active filter mode.
    pub filter_mode: String,
    /// Whether source data is stale.
    pub stale: bool,
    /// Deterministic fingerprint for refresh/change detection.
    pub refresh_fingerprint: String,
    /// Normalized ready-work entries.
    pub ready_work: Vec<BeadsReadyWorkItem>,
    /// Normalized blocked-work entries.
    pub blocked_work: Vec<BeadsBlockedItem>,
    /// Normalized triage recommendations.
    pub triage: Vec<BvTriageRecommendation>,
    /// Parse errors captured while building the snapshot.
    pub parse_errors: Vec<String>,
    /// Structured command-center events.
    pub events: Vec<BeadsCommandCenterEvent>,
}

/// Deterministic Agent Mail pane contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailPaneContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Canonical inbox command surface.
    pub fetch_inbox_command: String,
    /// Canonical outbox query command surface.
    pub fetch_outbox_command: String,
    /// Canonical contact-list command surface.
    pub list_contacts_command: String,
    /// Canonical message acknowledgement command surface.
    pub acknowledge_command: String,
    /// Canonical in-thread reply command surface.
    pub reply_command: String,
    /// Required message fields in lexical order.
    pub required_message_fields: Vec<String>,
    /// Required contact fields in lexical order.
    pub required_contact_fields: Vec<String>,
    /// Supported thread filter modes in lexical order.
    pub thread_filter_modes: Vec<String>,
    /// Structured event taxonomy in lexical order.
    pub event_taxonomy: Vec<String>,
}

/// One normalized Agent Mail message row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailMessageItem {
    /// Message identifier.
    pub id: u64,
    /// Message subject.
    pub subject: String,
    /// Message sender.
    pub from: String,
    /// Message creation timestamp.
    pub created_ts: String,
    /// Importance class.
    pub importance: String,
    /// Whether acknowledgement is required.
    pub ack_required: bool,
    /// Whether message is currently acknowledged.
    pub acknowledged: bool,
    /// Optional thread identifier.
    pub thread_id: Option<String>,
    /// Delivery status (`received`, `sent`, `failed`).
    pub delivery_status: String,
    /// Direction (`inbox` or `outbox`).
    pub direction: String,
}

/// One normalized Agent Mail contact status row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailContactItem {
    /// Contact peer agent name.
    pub peer: String,
    /// Contact status (`approved`, `pending`, `denied`).
    pub status: String,
    /// Contact rationale.
    pub reason: String,
    /// Last status update timestamp.
    pub updated_ts: String,
    /// Optional expiry timestamp.
    pub expires_ts: Option<String>,
}

/// One structured Agent Mail pane event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailPaneEvent {
    /// Event kind (`command_invoked`, `ack_transition`, etc).
    pub event_kind: String,
    /// Source stream (`inbox`, `outbox`, `contacts`, `thread`, `snapshot`).
    pub source: String,
    /// Optional message identifier.
    pub message_id: Option<u64>,
    /// Optional thread identifier.
    pub thread_id: Option<String>,
    /// Deterministic event message.
    pub message: String,
}

/// Deterministic Agent Mail pane snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailPaneSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Active thread filter mode.
    pub thread_filter_mode: String,
    /// Active thread identifier.
    pub active_thread: Option<String>,
    /// Deterministic fingerprint for snapshot refresh/change detection.
    pub refresh_fingerprint: String,
    /// Normalized inbox rows.
    pub inbox: Vec<AgentMailMessageItem>,
    /// Normalized outbox rows.
    pub outbox: Vec<AgentMailMessageItem>,
    /// Active-thread merged rows.
    pub thread_messages: Vec<AgentMailMessageItem>,
    /// Contact-awareness rows.
    pub contacts: Vec<AgentMailContactItem>,
    /// Count of ack-required inbox rows still pending acknowledgement.
    pub pending_ack_count: u32,
    /// Replay-ready command trace snippets.
    pub replay_commands: Vec<String>,
    /// Parse errors captured during snapshot assembly.
    pub parse_errors: Vec<String>,
    /// Structured pane events.
    pub events: Vec<AgentMailPaneEvent>,
}

/// One deterministic smoke-workflow step for Agent Mail.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailPaneWorkflowStep {
    /// Step identifier.
    pub step_id: String,
    /// Human-readable action summary.
    pub action: String,
    /// Snapshot captured at this workflow step.
    pub snapshot: AgentMailPaneSnapshot,
}

/// Deterministic Agent Mail smoke-workflow transcript.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentMailPaneWorkflowTranscript {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Ordered workflow steps.
    pub steps: Vec<AgentMailPaneWorkflowStep>,
}

/// Deterministic timeline explorer contract for findings/evidence drill-down.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineContract {
    /// Contract version for compatibility checks.
    pub contract_version: String,
    /// Core diagnostics report contract this timeline contract depends on.
    pub core_report_contract_version: String,
    /// Canonical command surface for fetching timeline material.
    pub timeline_source_command: String,
    /// Required timeline node fields in lexical order.
    pub required_node_fields: Vec<String>,
    /// Required timeline group fields in lexical order.
    pub required_group_fields: Vec<String>,
    /// Supported deterministic sort modes in lexical order.
    pub sort_modes: Vec<String>,
    /// Supported deterministic filter modes in lexical order.
    pub filter_modes: Vec<String>,
    /// Supported deterministic group modes in lexical order.
    pub group_modes: Vec<String>,
    /// Canonical keyboard bindings for timeline interactions.
    pub keyboard_bindings: Vec<EvidenceTimelineKeyboardBinding>,
    /// Structured event taxonomy in lexical order.
    pub event_taxonomy: Vec<String>,
    /// Compatibility/versioning guidance for consumers.
    pub compatibility: ContractCompatibility,
    /// Downstream report/export consumers in lexical order.
    pub downstream_consumers: Vec<String>,
}

/// One deterministic keyboard binding for the evidence timeline explorer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineKeyboardBinding {
    /// Key chord.
    pub key: String,
    /// Action executed by this binding.
    pub action: String,
    /// Source panel for this action.
    pub from_panel: String,
    /// Destination panel for this action.
    pub to_panel: String,
}

/// One normalized timeline node for findings/evidence drill-down.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineNode {
    /// Stable timeline node identifier.
    pub node_id: String,
    /// Deterministic timestamp string (RFC3339 expected).
    pub occurred_at: String,
    /// Linked finding identifier.
    pub finding_id: String,
    /// Human-readable finding title.
    pub title: String,
    /// Finding severity (`critical`, `high`, `medium`, `low`).
    pub severity: String,
    /// Finding status (`open`, `in_progress`, `resolved`).
    pub status: String,
    /// Normalized outcome class.
    pub outcome_class: String,
    /// Linked evidence identifiers in lexical order.
    pub evidence_refs: Vec<String>,
    /// Linked command identifiers in lexical order.
    pub command_refs: Vec<String>,
    /// Causal parent node identifiers in lexical order.
    pub causal_parents: Vec<String>,
    /// Causal child node identifiers in lexical order.
    pub causal_children: Vec<String>,
    /// Missing causal references for diagnostics in lexical order.
    pub missing_causal_refs: Vec<String>,
    /// Whether this node has missing required links.
    pub has_missing_links: bool,
}

/// One deterministic timeline group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineGroup {
    /// Group key (e.g. `critical`, `open`, `failed`).
    pub group_key: String,
    /// Node identifiers in deterministic order.
    pub node_ids: Vec<String>,
}

/// One structured timeline event for diagnostics and replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineEvent {
    /// Event kind (`timeline_interaction`, `causal_expansion_decision`, ...).
    pub event_kind: String,
    /// Source stream (`timeline`, `grouping`, `interaction`, `snapshot`).
    pub source: String,
    /// Optional timeline node identifier.
    pub node_id: Option<String>,
    /// Deterministic event message.
    pub message: String,
}

/// Deterministic snapshot for the evidence timeline explorer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Active sort mode.
    pub sort_mode: String,
    /// Active filter mode.
    pub filter_mode: String,
    /// Active grouping mode.
    pub group_mode: String,
    /// Focused panel id (`context_panel`, `primary_panel`, `action_panel`, `evidence_panel`).
    pub focused_panel: String,
    /// Selected timeline node identifier.
    pub selected_node: Option<String>,
    /// Evidence-panel node identifier when drill-down is open.
    pub evidence_panel_node: Option<String>,
    /// Timeline nodes after sorting/filtering.
    pub nodes: Vec<EvidenceTimelineNode>,
    /// Timeline groups after grouping.
    pub groups: Vec<EvidenceTimelineGroup>,
    /// Parse/validation errors captured during snapshot assembly.
    pub parse_errors: Vec<String>,
    /// Deterministic refresh fingerprint.
    pub refresh_fingerprint: String,
    /// Structured timeline events.
    pub events: Vec<EvidenceTimelineEvent>,
}

/// One deterministic keyboard-interaction step for timeline workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineInteractionStep {
    /// Step identifier.
    pub step_id: String,
    /// Key chord exercised by this step.
    pub key_chord: String,
    /// Focused panel after applying this key.
    pub focused_panel: String,
    /// Selected node after applying this key.
    pub selected_node: Option<String>,
    /// Evidence-panel node after applying this key.
    pub evidence_panel_node: Option<String>,
    /// Snapshot captured at this step.
    pub snapshot: EvidenceTimelineSnapshot,
}

/// Deterministic keyboard-flow transcript for the evidence timeline explorer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceTimelineWorkflowTranscript {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Ordered interaction steps.
    pub steps: Vec<EvidenceTimelineInteractionStep>,
}

/// Core diagnostics report contract for doctor report consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsReportContract {
    /// Contract/schema version for report payloads.
    pub contract_version: String,
    /// Required top-level report sections in lexical order.
    pub required_sections: Vec<String>,
    /// Required summary fields in lexical order.
    pub summary_required_fields: Vec<String>,
    /// Required finding fields in lexical order.
    pub finding_required_fields: Vec<String>,
    /// Required evidence fields in lexical order.
    pub evidence_required_fields: Vec<String>,
    /// Required command fields in lexical order.
    pub command_required_fields: Vec<String>,
    /// Required provenance fields in lexical order.
    pub provenance_required_fields: Vec<String>,
    /// Allowed normalized outcome classes in lexical order.
    pub outcome_classes: Vec<String>,
    /// Upstream logging contract dependency.
    pub logging_contract_version: String,
    /// Upstream evidence-ingestion schema dependency.
    pub evidence_schema_version: String,
    /// Compatibility/versioning guidance for readers and writers.
    pub compatibility: ContractCompatibility,
    /// Follow-up bead for advanced report-extension semantics.
    pub advanced_extension_bead: String,
    /// Cross-system interoperability checks required before full closure.
    pub integration_gate_beads: Vec<String>,
}

/// Core diagnostics report payload consumed by baseline TUI/report backends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsReport {
    /// Report schema version.
    pub schema_version: String,
    /// Stable report identifier.
    pub report_id: String,
    /// High-level deterministic summary.
    pub summary: CoreDiagnosticsSummary,
    /// Findings ordered lexically by `finding_id`.
    pub findings: Vec<CoreDiagnosticsFinding>,
    /// Evidence records ordered lexically by `evidence_id`.
    pub evidence: Vec<CoreDiagnosticsEvidence>,
    /// Command provenance records ordered lexically by `command_id`.
    pub commands: Vec<CoreDiagnosticsCommand>,
    /// Provenance envelope for replay and audit.
    pub provenance: CoreDiagnosticsProvenance,
}

/// Deterministic report summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsSummary {
    /// Summary status (`healthy`, `degraded`, `failed`).
    pub status: String,
    /// Normalized top-level outcome class.
    pub overall_outcome: String,
    /// Total findings represented in the report.
    pub total_findings: u32,
    /// Count of findings with `critical` severity.
    pub critical_findings: u32,
}

/// One deterministic finding entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsFinding {
    /// Stable finding identifier.
    pub finding_id: String,
    /// Human-readable finding title.
    pub title: String,
    /// Severity (`critical`, `high`, `medium`, `low`).
    pub severity: String,
    /// Finding status (`open`, `in_progress`, `resolved`).
    pub status: String,
    /// Evidence identifiers supporting this finding.
    pub evidence_refs: Vec<String>,
    /// Command identifiers used to reproduce/verify this finding.
    pub command_refs: Vec<String>,
}

/// One deterministic evidence entry for report rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsEvidence {
    /// Stable evidence identifier.
    pub evidence_id: String,
    /// Evidence source label.
    pub source: String,
    /// Artifact pointer for deterministic retrieval.
    pub artifact_pointer: String,
    /// Replay command/pointer for this evidence item.
    pub replay_pointer: String,
    /// Normalized outcome class for this evidence item.
    pub outcome_class: String,
    /// FrankenSuite-aligned trace reference.
    pub franken_trace_id: String,
}

/// One deterministic command/provenance record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsCommand {
    /// Stable command identifier.
    pub command_id: String,
    /// Shell command issued.
    pub command: String,
    /// Tool family (`rch`, `br`, `bv`, `asupersync`, etc).
    pub tool: String,
    /// Exit code produced by command execution.
    pub exit_code: i32,
    /// Normalized outcome class derived from execution result.
    pub outcome_class: String,
}

/// Provenance envelope attached to every diagnostics report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsProvenance {
    /// Deterministic run identifier.
    pub run_id: String,
    /// Deterministic scenario identifier.
    pub scenario_id: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Seed used for deterministic replay.
    pub seed: String,
    /// Generator identity for this report.
    pub generated_by: String,
    /// Stable timestamp string (typically RFC3339) emitted by generator.
    pub generated_at: String,
}

/// Deterministic fixture entry for core diagnostics report validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsFixture {
    /// Stable fixture identifier.
    pub fixture_id: String,
    /// Human-readable fixture description.
    pub description: String,
    /// Canonical report payload for this fixture.
    pub report: CoreDiagnosticsReport,
}

/// Serializable bundle containing the contract plus deterministic fixtures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreDiagnosticsReportBundle {
    /// Core report contract.
    pub contract: CoreDiagnosticsReportContract,
    /// Deterministic fixture set.
    pub fixtures: Vec<CoreDiagnosticsFixture>,
}

/// Taxonomy mapping allow-list used by advanced report extensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedDiagnosticsTaxonomyMapping {
    /// Allowed taxonomy class identifiers.
    pub class_allowlist: Vec<String>,
    /// Allowed taxonomy dimension identifiers.
    pub dimension_allowlist: Vec<String>,
    /// Allowed taxonomy severity identifiers.
    pub severity_allowlist: Vec<String>,
}

/// Advanced diagnostics report extension contract layered on top of core report schema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedDiagnosticsReportExtensionContract {
    /// Extension contract/schema version.
    pub contract_version: String,
    /// Required base core-report contract version.
    pub base_contract_version: String,
    /// Required advanced observability taxonomy contract version.
    pub taxonomy_contract_version: String,
    /// Required extension sections in lexical order.
    pub required_extension_sections: Vec<String>,
    /// Required remediation-delta fields in lexical order.
    pub remediation_delta_required_fields: Vec<String>,
    /// Required trust-transition fields in lexical order.
    pub trust_transition_required_fields: Vec<String>,
    /// Required collaboration-trail fields in lexical order.
    pub collaboration_required_fields: Vec<String>,
    /// Required troubleshooting-playbook fields in lexical order.
    pub playbook_required_fields: Vec<String>,
    /// Allowed normalized outcome classes in lexical order.
    pub outcome_classes: Vec<String>,
    /// Mapping constraints to advanced taxonomy outputs.
    pub taxonomy_mapping: AdvancedDiagnosticsTaxonomyMapping,
    /// Compatibility/versioning guidance.
    pub compatibility: ContractCompatibility,
    /// Integration handoff bead for full cross-system validation.
    pub integration_handoff_bead: String,
}

/// Advanced extension payload linked to one base core diagnostics report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedDiagnosticsReportExtension {
    /// Extension schema version.
    pub schema_version: String,
    /// Base report identifier this extension augments.
    pub base_report_id: String,
    /// Base report schema version.
    pub base_report_schema_version: String,
    /// Remediation deltas ordered lexically by `delta_id`.
    pub remediation_deltas: Vec<AdvancedRemediationDelta>,
    /// Trust transitions ordered lexically by `transition_id`.
    pub trust_transitions: Vec<AdvancedTrustTransition>,
    /// Collaboration/audit trail ordered lexically by `entry_id`.
    pub collaboration_trail: Vec<AdvancedCollaborationEntry>,
    /// Troubleshooting playbooks ordered lexically by `playbook_id`.
    pub troubleshooting_playbooks: Vec<AdvancedTroubleshootingPlaybook>,
}

/// One remediation delta tied to a core finding and taxonomy semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedRemediationDelta {
    /// Stable remediation-delta identifier.
    pub delta_id: String,
    /// Target finding in base report.
    pub finding_id: String,
    /// Previous finding status.
    pub previous_status: String,
    /// New finding status.
    pub next_status: String,
    /// Normalized outcome class for this delta.
    pub delta_outcome: String,
    /// Linked advanced taxonomy class id.
    pub mapped_taxonomy_class: String,
    /// Linked advanced taxonomy dimension id.
    pub mapped_taxonomy_dimension: String,
    /// Supporting evidence references from base report.
    pub verification_evidence_refs: Vec<String>,
}

/// One trust-score transition entry for report trust evolution semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedTrustTransition {
    /// Stable transition identifier.
    pub transition_id: String,
    /// Transition stage label.
    pub stage: String,
    /// Previous trust score (`0..=100`).
    pub previous_score: u8,
    /// Next trust score (`0..=100`).
    pub next_score: u8,
    /// Normalized outcome class.
    pub outcome_class: String,
    /// Linked advanced taxonomy severity.
    pub mapped_taxonomy_severity: String,
    /// Human-readable transition rationale.
    pub rationale: String,
}

/// One collaboration/audit-trail entry for cross-agent provenance context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedCollaborationEntry {
    /// Stable collaboration entry identifier.
    pub entry_id: String,
    /// Channel (`agent_mail`, `beads`, `doctor_cli`, ...).
    pub channel: String,
    /// Actor identifier.
    pub actor: String,
    /// Action summary.
    pub action: String,
    /// Linked thread identifier.
    pub thread_id: String,
    /// Linked message reference id.
    pub message_ref: String,
    /// Linked bead identifier.
    pub bead_ref: String,
    /// Linked taxonomy narrative snippet.
    pub mapped_taxonomy_narrative: String,
}

/// Troubleshooting playbook guidance entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedTroubleshootingPlaybook {
    /// Stable playbook identifier.
    pub playbook_id: String,
    /// Human-readable playbook title.
    pub title: String,
    /// Triggering taxonomy class id.
    pub trigger_taxonomy_class: String,
    /// Triggering taxonomy severity id.
    pub trigger_taxonomy_severity: String,
    /// Ordered deterministic playbook steps.
    pub ordered_steps: Vec<String>,
    /// Referenced base-report command ids.
    pub command_refs: Vec<String>,
    /// Referenced base-report evidence ids.
    pub evidence_refs: Vec<String>,
}

/// Deterministic fixture entry pairing base core report with advanced extension payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedDiagnosticsFixture {
    /// Stable fixture identifier.
    pub fixture_id: String,
    /// Human-readable fixture description.
    pub description: String,
    /// Base core-report payload.
    pub core_report: CoreDiagnosticsReport,
    /// Advanced extension payload.
    pub extension: AdvancedDiagnosticsReportExtension,
}

/// Serializable advanced-report bundle for validation/smoke/e2e flows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvancedDiagnosticsReportBundle {
    /// Core report contract dependency.
    pub core_contract: CoreDiagnosticsReportContract,
    /// Advanced extension contract.
    pub extension_contract: AdvancedDiagnosticsReportExtensionContract,
    /// Deterministic fixture set.
    pub fixtures: Vec<AdvancedDiagnosticsFixture>,
}

impl Outputtable for WorkspaceScanReport {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Root: {}", self.root));
        lines.push(format!("Manifest: {}", self.workspace_manifest));
        lines.push(format!("Members: {}", self.members.len()));
        lines.push(format!("Capability edges: {}", self.capability_edges.len()));
        lines.push(format!("Scanner version: {}", self.scanner_version));
        lines.push(format!("Taxonomy version: {}", self.taxonomy_version));
        lines.push(format!("Events: {}", self.events.len()));
        if !self.warnings.is_empty() {
            lines.push(format!("Warnings: {}", self.warnings.len()));
        }
        for member in &self.members {
            lines.push(format!(
                "- {} ({}) [{}]",
                member.name,
                member.relative_path,
                member.capability_surfaces.join(", "),
            ));
        }
        for warning in &self.warnings {
            lines.push(format!("warning: {warning}"));
        }
        lines.join("\n")
    }
}

impl Outputtable for InvariantAnalyzerReport {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Analyzer version: {}", self.analyzer_version));
        lines.push(format!("Scanner version: {}", self.scanner_version));
        lines.push(format!("Taxonomy version: {}", self.taxonomy_version));
        lines.push(format!("Correlation id: {}", self.correlation_id));
        lines.push(format!("Members evaluated: {}", self.member_count));
        lines.push(format!("Findings: {}", self.finding_count));
        lines.push(format!("Rule traces: {}", self.rule_traces.len()));
        for finding in &self.findings {
            lines.push(format!(
                "- [{}] {} (rule={}, confidence={})",
                finding.severity, finding.summary, finding.rule_id, finding.confidence
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for LockContentionAnalyzerReport {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Analyzer version: {}", self.analyzer_version));
        lines.push(format!("Scanner version: {}", self.scanner_version));
        lines.push(format!("Correlation id: {}", self.correlation_id));
        lines.push(format!("Members evaluated: {}", self.member_count));
        lines.push(format!("Hotspots: {}", self.hotspot_count));
        lines.push(format!("Violations: {}", self.violation_count));
        lines.push(format!(
            "Deadlock risk patterns: {}",
            self.deadlock_risk_patterns.len()
        ));
        lines.push(format!("Rule traces: {}", self.rule_traces.len()));
        for hotspot in &self.hotspots {
            lines.push(format!(
                "- [{}] {} (score={}, confidence={}, locks={}, contention={}, violations={})",
                hotspot.risk_level,
                hotspot.path,
                hotspot.risk_score,
                hotspot.confidence,
                hotspot.lock_acquisitions,
                hotspot.contention_markers,
                hotspot.violation_count
            ));
        }
        for violation in &self.violations {
            lines.push(format!(
                "- [violation] {} :: {} ({})",
                violation.path, violation.observed_transition, violation.function_name
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for OperatorModelContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!("Personas: {}", self.personas.len()));
        lines.push(format!("Decision loops: {}", self.decision_loops.len()));
        lines.push(format!(
            "Navigation topology: {} (screens={}, routes={}, bindings={})",
            self.navigation_topology.version,
            self.navigation_topology.screens.len(),
            self.navigation_topology.routes.len(),
            self.navigation_topology.keyboard_bindings.len()
        ));
        lines.push(format!(
            "Global evidence requirements: {}",
            self.global_evidence_requirements.join(", ")
        ));
        for persona in &self.personas {
            lines.push(format!(
                "- {} ({}) => {} [loop={}, decisions={}]",
                persona.label,
                persona.id,
                persona.mission,
                persona.default_decision_loop,
                persona.high_stakes_decisions.len()
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for UxSignoffMatrixContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!("Baseline matrix: {}", self.baseline_matrix_version));
        lines.push(format!("Journeys: {}", self.journeys.len()));
        lines.push(format!(
            "Rollout gate: pass_rate>={}%, zero_critical_failures={}",
            self.rollout_gate.min_pass_rate_percent,
            self.rollout_gate.require_zero_critical_failures
        ));
        lines.push(format!(
            "Logging requirements: {}",
            self.logging_requirements.join(", ")
        ));
        for journey in &self.journeys {
            lines.push(format!(
                "- {} [{}] transitions={}, interruptions={}, recoveries={}, evidence={}",
                journey.journey_id,
                journey.persona_id,
                journey.transitions.len(),
                journey.interruption_assertions.len(),
                journey.recovery_assertions.len(),
                journey.evidence_assertions.len()
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for ScreenEngineContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Operator model version: {}",
            self.operator_model_version
        ));
        lines.push(format!("Screens: {}", self.screens.len()));
        lines.push(format!(
            "Global request fields: {}",
            self.global_request_fields.join(", ")
        ));
        lines.push(format!(
            "Global response fields: {}",
            self.global_response_fields.join(", ")
        ));
        for screen in &self.screens {
            lines.push(format!(
                "- {} ({}) [states={}, transitions={}]",
                screen.label,
                screen.id,
                screen.states.len(),
                screen.transitions.len()
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for EvidenceIngestionReport {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Schema version: {}", self.schema_version));
        lines.push(format!("Run id: {}", self.run_id));
        lines.push(format!("Records: {}", self.records.len()));
        lines.push(format!("Rejected artifacts: {}", self.rejected.len()));
        lines.push(format!("Events: {}", self.events.len()));
        for record in &self.records {
            lines.push(format!(
                "- {} [{}] {} ({})",
                record.evidence_id, record.artifact_type, record.summary, record.outcome_class
            ));
        }
        for rejected in &self.rejected {
            lines.push(format!(
                "rejected: {} [{}] {}",
                rejected.artifact_id, rejected.artifact_type, rejected.reason
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for StructuredLoggingContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Envelope required fields: {}",
            self.envelope_required_fields.len()
        ));
        lines.push(format!(
            "Correlation primitives: {}",
            self.correlation_primitives.len()
        ));
        lines.push(format!("Core flows: {}", self.core_flows.len()));
        lines.push(format!(
            "Event taxonomy: {}",
            self.event_taxonomy.join(", ")
        ));
        for flow in &self.core_flows {
            lines.push(format!(
                "- {} [required={}, optional={}, events={}]",
                flow.flow_id,
                flow.required_fields.len(),
                flow.optional_fields.len(),
                flow.event_kinds.join(", ")
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for RemediationRecipeContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Logging contract dependency: {}",
            self.logging_contract_version
        ));
        lines.push(format!(
            "Required recipe fields: {}",
            self.required_recipe_fields.join(", ")
        ));
        lines.push(format!(
            "Allowed fix intents: {}",
            self.allowed_fix_intents.join(", ")
        ));
        lines.push(format!(
            "Allowed predicates: {}",
            self.allowed_precondition_predicates.join(", ")
        ));
        lines.push(format!(
            "Allowed rollback strategies: {}",
            self.allowed_rollback_strategies.join(", ")
        ));
        lines.push(format!(
            "Confidence weights: {}",
            self.confidence_weights.len()
        ));
        lines.push(format!("Risk bands: {}", self.risk_bands.len()));
        for band in &self.risk_bands {
            lines.push(format!(
                "- {} [{}-{}] approval={} auto_apply={}",
                band.band_id,
                band.min_score_inclusive,
                band.max_score_inclusive,
                band.requires_human_approval,
                band.allow_auto_apply
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for RemediationRecipeBundle {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(self.contract.human_format());
        lines.push(format!("Fixtures: {}", self.fixtures.len()));
        for fixture in &self.fixtures {
            lines.push(format!(
                "- {} [{}] score={} band={} decision={}",
                fixture.fixture_id,
                fixture.recipe.fix_intent,
                fixture.expected_confidence_score,
                fixture.expected_risk_band,
                fixture.expected_decision
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for ExecutionAdapterContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Logging contract dependency: {}",
            self.logging_contract_version
        ));
        lines.push(format!("Command classes: {}", self.command_classes.len()));
        lines.push(format!("Route policies: {}", self.route_policies.len()));
        lines.push(format!("Timeout profiles: {}", self.timeout_profiles.len()));
        lines.push(format!(
            "State transitions: {}",
            self.state_transitions.len()
        ));
        lines.push(format!("Failure taxonomy: {}", self.failure_taxonomy.len()));
        for class in &self.command_classes {
            lines.push(format!(
                "- {} [{}] force_rch={} timeout={}s",
                class.class_id, class.label, class.force_rch, class.default_timeout_secs
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for ScenarioComposerContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Execution adapter dependency: {}",
            self.execution_adapter_version
        ));
        lines.push(format!(
            "Logging contract dependency: {}",
            self.logging_contract_version
        ));
        lines.push(format!(
            "Scenario templates: {}",
            self.scenario_templates.len()
        ));
        lines.push(format!(
            "Queue policy: max_concurrent={}, max_depth={}, dispatch={}",
            self.queue_policy.max_concurrent_runs,
            self.queue_policy.max_queue_depth,
            self.queue_policy.dispatch_order
        ));
        lines.push(format!("Failure taxonomy: {}", self.failure_taxonomy.len()));
        for template in &self.scenario_templates {
            lines.push(format!(
                "- {} [priority={}, retries={}, seed_required={}]",
                template.template_id,
                template.default_priority,
                template.max_retries,
                template.requires_replay_seed
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for E2eHarnessCoreContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Execution adapter dependency: {}",
            self.execution_adapter_version
        ));
        lines.push(format!(
            "Logging contract dependency: {}",
            self.logging_contract_version
        ));
        lines.push(format!(
            "Required config fields: {}",
            self.required_config_fields.len()
        ));
        lines.push(format!(
            "Required transcript fields: {}",
            self.required_transcript_fields.len()
        ));
        lines.push(format!(
            "Required artifact index fields: {}",
            self.required_artifact_index_fields.len()
        ));
        lines.push(format!(
            "Lifecycle states: {}",
            self.lifecycle_states.join(", ")
        ));
        lines.push(format!("Failure taxonomy: {}", self.failure_taxonomy.len()));
        lines.join("\n")
    }
}

impl Outputtable for BeadsCommandCenterContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!("br ready command: {}", self.br_ready_command));
        lines.push(format!("br blocked command: {}", self.br_blocked_command));
        lines.push(format!("bv triage command: {}", self.bv_triage_command));
        lines.push(format!(
            "Required ready fields: {}",
            self.required_ready_fields.join(", ")
        ));
        lines.push(format!(
            "Required blocker fields: {}",
            self.required_blocker_fields.join(", ")
        ));
        lines.push(format!(
            "Required triage fields: {}",
            self.required_triage_fields.join(", ")
        ));
        lines.push(format!("Filter modes: {}", self.filter_modes.join(", ")));
        lines.push(format!(
            "Event taxonomy: {}",
            self.event_taxonomy.join(", ")
        ));
        lines.push(format!("Stale after: {}s", self.stale_after_secs));
        lines.join("\n")
    }
}

impl Outputtable for AgentMailPaneContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!("Fetch inbox command: {}", self.fetch_inbox_command));
        lines.push(format!(
            "Fetch outbox command: {}",
            self.fetch_outbox_command
        ));
        lines.push(format!(
            "List contacts command: {}",
            self.list_contacts_command
        ));
        lines.push(format!("Acknowledge command: {}", self.acknowledge_command));
        lines.push(format!("Reply command: {}", self.reply_command));
        lines.push(format!(
            "Required message fields: {}",
            self.required_message_fields.join(", ")
        ));
        lines.push(format!(
            "Required contact fields: {}",
            self.required_contact_fields.join(", ")
        ));
        lines.push(format!(
            "Thread filter modes: {}",
            self.thread_filter_modes.join(", ")
        ));
        lines.push(format!(
            "Event taxonomy: {}",
            self.event_taxonomy.join(", ")
        ));
        lines.join("\n")
    }
}

impl Outputtable for CoreDiagnosticsReportContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Required sections: {}",
            self.required_sections.join(", ")
        ));
        lines.push(format!(
            "Logging contract: {}",
            self.logging_contract_version
        ));
        lines.push(format!("Evidence schema: {}", self.evidence_schema_version));
        lines.push(format!(
            "Advanced extension bead: {}",
            self.advanced_extension_bead
        ));
        lines.push(format!(
            "Integration gates: {}",
            self.integration_gate_beads.join(", ")
        ));
        lines.join("\n")
    }
}

impl Outputtable for CoreDiagnosticsReportBundle {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(self.contract.human_format());
        lines.push(format!("Fixtures: {}", self.fixtures.len()));
        for fixture in &self.fixtures {
            lines.push(format!(
                "- {} [{}] findings={} evidence={} commands={}",
                fixture.fixture_id,
                fixture.report.summary.overall_outcome,
                fixture.report.findings.len(),
                fixture.report.evidence.len(),
                fixture.report.commands.len()
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for AdvancedDiagnosticsReportExtensionContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!(
            "Base contract version: {}",
            self.base_contract_version
        ));
        lines.push(format!(
            "Taxonomy contract version: {}",
            self.taxonomy_contract_version
        ));
        lines.push(format!(
            "Required extension sections: {}",
            self.required_extension_sections.join(", ")
        ));
        lines.push(format!(
            "Taxonomy classes: {}",
            self.taxonomy_mapping.class_allowlist.join(", ")
        ));
        lines.push(format!(
            "Taxonomy dimensions: {}",
            self.taxonomy_mapping.dimension_allowlist.join(", ")
        ));
        lines.push(format!(
            "Taxonomy severities: {}",
            self.taxonomy_mapping.severity_allowlist.join(", ")
        ));
        lines.push(format!(
            "Integration handoff bead: {}",
            self.integration_handoff_bead
        ));
        lines.join("\n")
    }
}

impl Outputtable for AdvancedDiagnosticsReportBundle {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(self.extension_contract.human_format());
        lines.push(format!("Fixtures: {}", self.fixtures.len()));
        for fixture in &self.fixtures {
            lines.push(format!(
                "- {} [{}] deltas={} trust={} collab={} playbooks={}",
                fixture.fixture_id,
                fixture.core_report.summary.overall_outcome,
                fixture.extension.remediation_deltas.len(),
                fixture.extension.trust_transitions.len(),
                fixture.extension.collaboration_trail.len(),
                fixture.extension.troubleshooting_playbooks.len()
            ));
        }
        lines.join("\n")
    }
}

impl Outputtable for VisualLanguageContract {
    fn human_format(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Contract version: {}", self.contract_version));
        lines.push(format!("Source showcase: {}", self.source_showcase));
        lines.push(format!("Default profile: {}", self.default_profile_id));
        lines.push(format!("Profiles: {}", self.profiles.len()));
        lines.push(format!("Screen styles: {}", self.screen_styles.len()));
        for profile in &self.profiles {
            lines.push(format!(
                "- {} ({}) [capability={:?}, palette_roles={}]",
                profile.label,
                profile.id,
                profile.minimum_capability,
                profile.palette_tokens.len()
            ));
        }
        lines.join("\n")
    }
}

/// Deterministic structured scan event.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScanEvent {
    /// Phase name for the scanner step.
    pub phase: String,
    /// Event level (`info` or `warn`).
    pub level: String,
    /// Human-readable message.
    pub message: String,
    /// Optional path associated with this event.
    pub path: Option<String>,
}

/// Deterministic summary of one workspace member.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WorkspaceMember {
    /// Cargo package name (or fallback name).
    pub name: String,
    /// Path relative to scan root.
    pub relative_path: String,
    /// Manifest path relative to scan root.
    pub manifest_path: String,
    /// Number of Rust files scanned under `src/`.
    pub rust_file_count: usize,
    /// Runtime/capability surfaces referenced by this member.
    pub capability_surfaces: Vec<String>,
}

/// Deterministic capability-flow edge.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityEdge {
    /// Workspace member package name.
    pub member: String,
    /// Runtime surface label.
    pub surface: String,
    /// Number of files that referenced this surface.
    pub evidence_count: usize,
    /// Sample relative source files containing references.
    pub sample_files: Vec<String>,
}

/// Deterministic invariant-analyzer report over a workspace scan.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InvariantAnalyzerReport {
    /// Analyzer schema version for downstream consumers.
    pub analyzer_version: String,
    /// Scanner version used to generate the source report.
    pub scanner_version: String,
    /// Taxonomy version used to classify surfaces.
    pub taxonomy_version: String,
    /// Stable correlation identifier for linking analyzer traces/findings.
    pub correlation_id: String,
    /// Number of members evaluated.
    pub member_count: usize,
    /// Number of emitted findings.
    pub finding_count: usize,
    /// Findings in deterministic order.
    pub findings: Vec<InvariantFinding>,
    /// Rule-level evaluation traces in deterministic order.
    pub rule_traces: Vec<InvariantRuleTrace>,
}

/// One invariant finding produced by [`analyze_workspace_invariants`].
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InvariantFinding {
    /// Stable finding identifier.
    pub finding_id: String,
    /// Rule identifier that emitted this finding.
    pub rule_id: String,
    /// Severity (`warn` or `error`).
    pub severity: String,
    /// Human-readable summary.
    pub summary: String,
    /// Confidence score in range `0..=100`.
    pub confidence: u8,
    /// Deterministic evidence lines supporting the finding.
    pub evidence: Vec<String>,
    /// Remediation guidance consumable by follow-up fix pipelines.
    pub remediation_guidance: String,
}

/// One rule-level trace entry emitted by the invariant analyzer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InvariantRuleTrace {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Correlation identifier inherited from the analyzer report.
    pub correlation_id: String,
    /// Evaluation outcome (`pass`, `fail`, or `suppressed`).
    pub outcome: String,
    /// Confidence score in range `0..=100`.
    pub confidence: u8,
    /// Deterministic evidence lines used by the rule.
    pub evidence: Vec<String>,
    /// Optional suppression rationale.
    pub suppressed_reason: Option<String>,
}

/// Deterministic lock-order/contention analyzer report over a workspace scan.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LockContentionAnalyzerReport {
    /// Analyzer schema version for downstream consumers.
    pub analyzer_version: String,
    /// Scanner version used to generate the source report.
    pub scanner_version: String,
    /// Stable correlation identifier for linking analyzer traces/findings.
    pub correlation_id: String,
    /// Number of members evaluated.
    pub member_count: usize,
    /// Number of emitted contention hotspots.
    pub hotspot_count: usize,
    /// Number of emitted lock-order violations.
    pub violation_count: usize,
    /// Unique deadlock-risk lock-order inversion patterns observed.
    pub deadlock_risk_patterns: Vec<String>,
    /// Ranked contention hotspots in deterministic order.
    pub hotspots: Vec<LockContentionHotspot>,
    /// Lock-order violations in deterministic order.
    pub violations: Vec<LockOrderViolation>,
    /// Rule-level evaluation traces in deterministic order.
    pub rule_traces: Vec<LockContentionRuleTrace>,
    /// Reproducible command pointers for this analyzer pass.
    pub reproduction_commands: Vec<String>,
}

/// One lock-order contention hotspot ranked by deterministic score.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LockContentionHotspot {
    /// Stable hotspot identifier.
    pub hotspot_id: String,
    /// Path where this hotspot was observed (relative to workspace root).
    pub path: String,
    /// Count of lock acquisition callsites in this file.
    pub lock_acquisitions: u32,
    /// Count of contention markers (`lock_wait_ns`, `ContendedMutex`, etc.).
    pub contention_markers: u32,
    /// Count of lock-order violations detected in this file.
    pub violation_count: u32,
    /// Composite deterministic risk score.
    pub risk_score: u32,
    /// Risk level (`low`, `medium`, `high`, `critical`).
    pub risk_level: String,
    /// Confidence score in range `0..=100`.
    pub confidence: u8,
    /// Deterministic evidence snippets for operator triage.
    pub evidence: Vec<String>,
    /// Deterministic remediation guidance tied to this hotspot.
    pub remediation_guidance: String,
}

/// One lock-order violation discovered by the analyzer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LockOrderViolation {
    /// Stable violation identifier.
    pub violation_id: String,
    /// Path where the violation was observed.
    pub path: String,
    /// Function context where the transition was observed.
    pub function_name: String,
    /// Canonical required order for multi-lock acquisition.
    pub expected_order: String,
    /// Observed lock transition that violated canonical ordering.
    pub observed_transition: String,
    /// Severity (`warn` or `error`).
    pub severity: String,
    /// Confidence score in range `0..=100`.
    pub confidence: u8,
    /// Deterministic evidence snippets supporting the violation.
    pub evidence: Vec<String>,
    /// Deterministic remediation guidance.
    pub remediation_guidance: String,
}

/// One rule-level trace entry emitted by the lock/contention analyzer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LockContentionRuleTrace {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Correlation identifier inherited from the analyzer report.
    pub correlation_id: String,
    /// Evaluation outcome (`pass`, `fail`, or `suppressed`).
    pub outcome: String,
    /// Confidence score in range `0..=100`.
    pub confidence: u8,
    /// Deterministic evidence lines used by the rule.
    pub evidence: Vec<String>,
    /// Optional suppression rationale.
    pub suppressed_reason: Option<String>,
}

#[derive(Debug, Clone)]
struct MemberScan {
    member: WorkspaceMember,
    evidence: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Default)]
struct ScanLog {
    warnings: Vec<String>,
    events: Vec<ScanEvent>,
}

impl ScanLog {
    fn info(&mut self, phase: &str, message: impl Into<String>, path: Option<String>) {
        self.events.push(ScanEvent {
            phase: phase.to_string(),
            level: "info".to_string(),
            message: message.into(),
            path,
        });
    }

    fn warn(&mut self, phase: &str, warning: impl Into<String>, path: Option<String>) {
        let warning = warning.into();
        self.warnings.push(warning.clone());
        self.events.push(ScanEvent {
            phase: phase.to_string(),
            level: "warn".to_string(),
            message: warning,
            path,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedStringArray {
    values: Vec<String>,
    malformed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LockShard {
    Config,
    Instrumentation,
    Regions,
    Tasks,
    Obligations,
}

impl LockShard {
    fn rank(self) -> u8 {
        match self {
            Self::Config => 0,
            Self::Instrumentation => 1,
            Self::Regions => 2,
            Self::Tasks => 3,
            Self::Obligations => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Config => "E(Config)",
            Self::Instrumentation => "D(Instrumentation)",
            Self::Regions => "B(Regions)",
            Self::Tasks => "A(Tasks)",
            Self::Obligations => "C(Obligations)",
        }
    }
}

#[derive(Debug, Clone, Default)]
struct LockHotspotAccumulator {
    lock_acquisitions: u32,
    contention_markers: u32,
    violation_count: u32,
    evidence: Vec<String>,
}

const SCANNER_VERSION: &str = "doctor-workspace-scan-v1";
const TAXONOMY_VERSION: &str = "capability-surfaces-v1";
const OPERATOR_MODEL_VERSION: &str = "doctor-operator-model-v1";
const NAVIGATION_TOPOLOGY_VERSION: &str = "doctor-navigation-topology-v1";
const UX_SIGNOFF_MATRIX_VERSION: &str = "doctor-ux-signoff-matrix-v1";
const UX_BASELINE_MATRIX_VERSION: &str = "doctor-ux-acceptance-matrix-v0";
const SCREEN_ENGINE_CONTRACT_VERSION: &str = "doctor-screen-engine-v1";
const EVIDENCE_SCHEMA_VERSION: &str = "doctor-evidence-v1";
const STRUCTURED_LOGGING_CONTRACT_VERSION: &str = "doctor-logging-v1";
const REMEDIATION_RECIPE_CONTRACT_VERSION: &str = "doctor-remediation-recipe-v1";
const EXECUTION_ADAPTER_CONTRACT_VERSION: &str = "doctor-exec-adapter-v1";
const SCENARIO_COMPOSER_CONTRACT_VERSION: &str = "doctor-scenario-composer-v1";
const E2E_HARNESS_CONTRACT_VERSION: &str = "doctor-e2e-harness-v1";
const BEADS_COMMAND_CENTER_CONTRACT_VERSION: &str = "doctor-beads-command-center-v1";
const AGENT_MAIL_PANE_CONTRACT_VERSION: &str = "doctor-agent-mail-pane-v1";
const EVIDENCE_TIMELINE_CONTRACT_VERSION: &str = "doctor-evidence-timeline-v1";
const DOCTOR_SCENARIO_COVERAGE_PACK_CONTRACT_VERSION: &str = "doctor-scenario-coverage-packs-v1";
const DOCTOR_SCENARIO_COVERAGE_PACK_REPORT_VERSION: &str =
    "doctor-scenario-coverage-pack-report-v1";
const DOCTOR_VISUAL_HARNESS_MANIFEST_VERSION: &str = "doctor-visual-harness-manifest-v1";
const CORE_DIAGNOSTICS_REPORT_VERSION: &str = "doctor-core-report-v1";
const ADVANCED_DIAGNOSTICS_REPORT_VERSION: &str = "doctor-advanced-report-v1";
const VISUAL_LANGUAGE_VERSION: &str = "doctor-visual-language-v1";
const INVARIANT_ANALYZER_VERSION: &str = "doctor-invariant-analyzer-v1";
const LOCK_CONTENTION_ANALYZER_VERSION: &str = "doctor-lock-contention-analyzer-v1";
const LOCK_ORDER_CANONICAL: &str =
    "E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations)";
const DEFAULT_VISUAL_VIEWPORT_WIDTH: u16 = 132;
const DEFAULT_VISUAL_VIEWPORT_HEIGHT: u16 = 44;
const MIN_VISUAL_VIEWPORT_WIDTH: u16 = 110;
const MIN_VISUAL_VIEWPORT_HEIGHT: u16 = 32;
const MAX_SAMPLE_FILES: usize = 3;
const SURFACE_MARKERS: [(&str, &[&str]); 12] = [
    (
        "cx",
        &["&Cx", "asupersync::Cx", "Cx::", "use asupersync::Cx"],
    ),
    ("scope", &["Scope", "scope!(", ".region("]),
    (
        "runtime",
        &["RuntimeBuilder", "runtime::", "asupersync::runtime"],
    ),
    (
        "channel",
        &["channel::", "asupersync::channel", "mpsc::", "oneshot::"],
    ),
    (
        "sync",
        &[
            "sync::Mutex",
            "sync::RwLock",
            "sync::Semaphore",
            "asupersync::sync",
        ],
    ),
    (
        "lab",
        &["LabRuntime", "LabConfig", "asupersync::lab", "lab::"],
    ),
    (
        "trace",
        &[
            "ReplayEvent",
            "TraceWriter",
            "TraceReader",
            "asupersync::trace",
        ],
    ),
    (
        "net",
        &["asupersync::net", "TcpStream", "TcpListener", "UdpSocket"],
    ),
    ("io", &["asupersync::io", "AsyncRead", "AsyncWrite"]),
    (
        "http",
        &[
            "asupersync::http",
            "http::",
            "Request::new(",
            "Response::new(",
        ],
    ),
    (
        "cancel",
        &["CancelReason", "CancelKind", "asupersync::cancel"],
    ),
    (
        "obligation",
        &[
            "Obligation",
            "asupersync::obligation",
            "reserve(",
            "commit(",
        ],
    ),
];

fn payload_field(key: &str, field_type: &str, description: &str) -> PayloadField {
    PayloadField {
        key: key.to_string(),
        field_type: field_type.to_string(),
        description: description.to_string(),
    }
}

fn payload_schema(
    schema_id: &str,
    required_fields: Vec<PayloadField>,
    optional_fields: Vec<PayloadField>,
) -> PayloadSchema {
    PayloadSchema {
        schema_id: schema_id.to_string(),
        required_fields,
        optional_fields,
    }
}

/// Returns the canonical operator/persona contract for doctor surfaces.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn operator_model_contract() -> OperatorModelContract {
    let global_evidence_requirements = vec![
        "artifact_pointer".to_string(),
        "command_provenance".to_string(),
        "outcome_class".to_string(),
        "run_id".to_string(),
        "scenario_id".to_string(),
        "trace_id".to_string(),
    ];

    let decision_loops = vec![
        DecisionLoop {
            id: "incident_containment".to_string(),
            title: "Incident containment and stabilization".to_string(),
            steps: vec![
                DecisionStep {
                    id: "detect_signal".to_string(),
                    action: "Detect high-severity runtime signal and classify blast radius."
                        .to_string(),
                    required_evidence: vec![
                        "finding_id".to_string(),
                        "severity".to_string(),
                        "trace_id".to_string(),
                    ],
                },
                DecisionStep {
                    id: "stabilize_runtime".to_string(),
                    action: "Apply containment decision and verify cancellation/quiescence state."
                        .to_string(),
                    required_evidence: vec![
                        "cancel_phase".to_string(),
                        "obligation_snapshot".to_string(),
                        "run_id".to_string(),
                    ],
                },
                DecisionStep {
                    id: "record_postmortem_input".to_string(),
                    action: "Capture replay pointer and remediation recommendation for follow-up."
                        .to_string(),
                    required_evidence: vec![
                        "artifact_pointer".to_string(),
                        "repro_command".to_string(),
                        "scenario_id".to_string(),
                    ],
                },
            ],
        },
        DecisionLoop {
            id: "release_gate_verification".to_string(),
            title: "Release gate verification".to_string(),
            steps: vec![
                DecisionStep {
                    id: "collect_gate_status".to_string(),
                    action: "Collect formatter/compiler/lint/test gate outcomes.".to_string(),
                    required_evidence: vec![
                        "command_provenance".to_string(),
                        "gate_name".to_string(),
                        "outcome_class".to_string(),
                    ],
                },
                DecisionStep {
                    id: "validate_determinism".to_string(),
                    action: "Validate deterministic replay and artifact completeness.".to_string(),
                    required_evidence: vec![
                        "artifact_pointer".to_string(),
                        "seed".to_string(),
                        "trace_id".to_string(),
                    ],
                },
                DecisionStep {
                    id: "signoff_or_block".to_string(),
                    action: "Emit release signoff or explicit blocking rationale.".to_string(),
                    required_evidence: vec![
                        "decision_reason".to_string(),
                        "outcome_class".to_string(),
                        "run_id".to_string(),
                    ],
                },
            ],
        },
        DecisionLoop {
            id: "triage_investigate_remediate".to_string(),
            title: "Triage -> investigate -> remediate".to_string(),
            steps: vec![
                DecisionStep {
                    id: "prioritize_finding".to_string(),
                    action: "Prioritize work item using severity + dependency impact.".to_string(),
                    required_evidence: vec![
                        "finding_id".to_string(),
                        "priority_score".to_string(),
                        "scenario_id".to_string(),
                    ],
                },
                DecisionStep {
                    id: "reproduce_deterministically".to_string(),
                    action: "Reproduce the issue with deterministic run + replay metadata."
                        .to_string(),
                    required_evidence: vec![
                        "repro_command".to_string(),
                        "run_id".to_string(),
                        "seed".to_string(),
                    ],
                },
                DecisionStep {
                    id: "apply_fix_and_verify".to_string(),
                    action: "Apply remediation and verify delta using the same evidence envelope."
                        .to_string(),
                    required_evidence: vec![
                        "artifact_pointer".to_string(),
                        "command_provenance".to_string(),
                        "outcome_class".to_string(),
                    ],
                },
            ],
        },
    ];

    let personas = vec![
        OperatorPersona {
            id: "conformance_engineer".to_string(),
            label: "Conformance Engineer".to_string(),
            mission: "Drive deterministic reproduction and close correctness gaps.".to_string(),
            mission_success_signals: vec![
                "deterministic_repro_pass_rate".to_string(),
                "regression_suite_green".to_string(),
            ],
            primary_views: vec![
                "bead_command_center".to_string(),
                "scenario_workbench".to_string(),
                "evidence_timeline".to_string(),
            ],
            default_decision_loop: "triage_investigate_remediate".to_string(),
            high_stakes_decisions: vec![
                PersonaDecision {
                    id: "promote_finding_to_active_work".to_string(),
                    prompt: "Promote finding to active remediation work item.".to_string(),
                    decision_loop: "triage_investigate_remediate".to_string(),
                    decision_step: "prioritize_finding".to_string(),
                    required_evidence: vec![
                        "finding_id".to_string(),
                        "priority_score".to_string(),
                        "scenario_id".to_string(),
                    ],
                },
                PersonaDecision {
                    id: "declare_remediation_verified".to_string(),
                    prompt: "Declare remediation verified for the candidate patch.".to_string(),
                    decision_loop: "triage_investigate_remediate".to_string(),
                    decision_step: "apply_fix_and_verify".to_string(),
                    required_evidence: vec![
                        "artifact_pointer".to_string(),
                        "command_provenance".to_string(),
                        "outcome_class".to_string(),
                    ],
                },
            ],
        },
        OperatorPersona {
            id: "release_guardian".to_string(),
            label: "Release Guardian".to_string(),
            mission: "Enforce release gates and block unsafe promotions.".to_string(),
            mission_success_signals: vec![
                "gate_closure_latency".to_string(),
                "release_block_precision".to_string(),
            ],
            primary_views: vec![
                "gate_status_board".to_string(),
                "artifact_audit".to_string(),
                "decision_ledger".to_string(),
            ],
            default_decision_loop: "release_gate_verification".to_string(),
            high_stakes_decisions: vec![
                PersonaDecision {
                    id: "approve_release_candidate".to_string(),
                    prompt: "Approve release candidate once all deterministic gates pass."
                        .to_string(),
                    decision_loop: "release_gate_verification".to_string(),
                    decision_step: "signoff_or_block".to_string(),
                    required_evidence: vec![
                        "decision_reason".to_string(),
                        "outcome_class".to_string(),
                        "run_id".to_string(),
                    ],
                },
                PersonaDecision {
                    id: "block_release_candidate".to_string(),
                    prompt: "Block release candidate when gate evidence is incomplete.".to_string(),
                    decision_loop: "release_gate_verification".to_string(),
                    decision_step: "collect_gate_status".to_string(),
                    required_evidence: vec![
                        "command_provenance".to_string(),
                        "gate_name".to_string(),
                        "outcome_class".to_string(),
                    ],
                },
            ],
        },
        OperatorPersona {
            id: "runtime_operator".to_string(),
            label: "Runtime Operator".to_string(),
            mission: "Contain live incidents while preserving deterministic evidence.".to_string(),
            mission_success_signals: vec![
                "incident_mttc".to_string(),
                "postmortem_evidence_completeness".to_string(),
            ],
            primary_views: vec![
                "incident_console".to_string(),
                "runtime_health".to_string(),
                "replay_inspector".to_string(),
            ],
            default_decision_loop: "incident_containment".to_string(),
            high_stakes_decisions: vec![
                PersonaDecision {
                    id: "declare_containment_state".to_string(),
                    prompt: "Declare whether containment actions are sufficient for stabilization."
                        .to_string(),
                    decision_loop: "incident_containment".to_string(),
                    decision_step: "stabilize_runtime".to_string(),
                    required_evidence: vec![
                        "cancel_phase".to_string(),
                        "obligation_snapshot".to_string(),
                        "run_id".to_string(),
                    ],
                },
                PersonaDecision {
                    id: "escalate_to_postmortem".to_string(),
                    prompt: "Escalate incident to postmortem workflow with replay pointers."
                        .to_string(),
                    decision_loop: "incident_containment".to_string(),
                    decision_step: "record_postmortem_input".to_string(),
                    required_evidence: vec![
                        "artifact_pointer".to_string(),
                        "repro_command".to_string(),
                        "scenario_id".to_string(),
                    ],
                },
            ],
        },
    ];

    let navigation_topology = NavigationTopology {
        version: NAVIGATION_TOPOLOGY_VERSION.to_string(),
        entry_points: vec![
            "bead_command_center".to_string(),
            "gate_status_board".to_string(),
            "incident_console".to_string(),
        ],
        screens: vec![
            NavigationScreen {
                id: "artifact_audit".to_string(),
                label: "Artifact Audit".to_string(),
                route: "/doctor/artifacts".to_string(),
                personas: vec!["release_guardian".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_artifact_audit_to_evidence_timeline_on_failure".to_string(),
                    "route_artifact_audit_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "bead_command_center".to_string(),
                label: "Bead Command Center".to_string(),
                route: "/doctor/beads".to_string(),
                personas: vec!["conformance_engineer".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_bead_command_center_to_evidence_timeline_on_failure".to_string(),
                    "route_bead_command_center_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "decision_ledger".to_string(),
                label: "Decision Ledger".to_string(),
                route: "/doctor/ledger".to_string(),
                personas: vec!["release_guardian".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_decision_ledger_to_evidence_timeline_on_failure".to_string(),
                    "route_decision_ledger_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "evidence_timeline".to_string(),
                label: "Evidence Timeline".to_string(),
                route: "/doctor/evidence".to_string(),
                personas: vec![
                    "conformance_engineer".to_string(),
                    "runtime_operator".to_string(),
                ],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec!["route_evidence_timeline_to_loading_on_retry".to_string()],
            },
            NavigationScreen {
                id: "gate_status_board".to_string(),
                label: "Gate Status Board".to_string(),
                route: "/doctor/gates".to_string(),
                personas: vec!["release_guardian".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_gate_status_board_to_artifact_audit_on_failure".to_string(),
                    "route_gate_status_board_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "incident_console".to_string(),
                label: "Incident Console".to_string(),
                route: "/doctor/incidents".to_string(),
                personas: vec!["runtime_operator".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_incident_console_to_runtime_health_on_failure".to_string(),
                    "route_incident_console_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "replay_inspector".to_string(),
                label: "Replay Inspector".to_string(),
                route: "/doctor/replay".to_string(),
                personas: vec!["runtime_operator".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_replay_inspector_to_evidence_timeline_on_failure".to_string(),
                    "route_replay_inspector_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "runtime_health".to_string(),
                label: "Runtime Health".to_string(),
                route: "/doctor/runtime".to_string(),
                personas: vec!["runtime_operator".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_runtime_health_to_evidence_timeline_on_failure".to_string(),
                    "route_runtime_health_to_loading_on_retry".to_string(),
                ],
            },
            NavigationScreen {
                id: "scenario_workbench".to_string(),
                label: "Scenario Workbench".to_string(),
                route: "/doctor/scenarios".to_string(),
                personas: vec!["conformance_engineer".to_string()],
                primary_panels: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                focus_order: vec![
                    "context_panel".to_string(),
                    "primary_panel".to_string(),
                    "action_panel".to_string(),
                ],
                recovery_routes: vec![
                    "route_scenario_workbench_to_evidence_timeline_on_failure".to_string(),
                    "route_scenario_workbench_to_loading_on_retry".to_string(),
                ],
            },
        ],
        routes: vec![
            NavigationRoute {
                id: "route_artifact_audit_to_decision_ledger".to_string(),
                from_screen: "artifact_audit".to_string(),
                to_screen: "decision_ledger".to_string(),
                trigger: "next_stage".to_string(),
                guard: "artifacts_complete".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_artifact_audit_to_evidence_timeline_on_failure".to_string(),
                from_screen: "artifact_audit".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "recover".to_string(),
                guard: "artifact_missing_or_invalid".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_artifact_audit_to_loading_on_retry".to_string(),
                from_screen: "artifact_audit".to_string(),
                to_screen: "artifact_audit".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_bead_command_center_to_evidence_timeline_on_failure".to_string(),
                from_screen: "bead_command_center".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "recover".to_string(),
                guard: "triage_data_invalid".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_bead_command_center_to_loading_on_retry".to_string(),
                from_screen: "bead_command_center".to_string(),
                to_screen: "bead_command_center".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_bead_command_center_to_scenario_workbench".to_string(),
                from_screen: "bead_command_center".to_string(),
                to_screen: "scenario_workbench".to_string(),
                trigger: "open_scenario_workbench".to_string(),
                guard: "selected_work_item_exists".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_decision_ledger_to_evidence_timeline_on_failure".to_string(),
                from_screen: "decision_ledger".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "recover".to_string(),
                guard: "decision_evidence_incomplete".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_decision_ledger_to_gate_status_board".to_string(),
                from_screen: "decision_ledger".to_string(),
                to_screen: "gate_status_board".to_string(),
                trigger: "back_to_gates".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_decision_ledger_to_loading_on_retry".to_string(),
                from_screen: "decision_ledger".to_string(),
                to_screen: "decision_ledger".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_evidence_timeline_to_bead_command_center".to_string(),
                from_screen: "evidence_timeline".to_string(),
                to_screen: "bead_command_center".to_string(),
                trigger: "return_to_triage".to_string(),
                guard: "persona_conformance_engineer".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_evidence_timeline_to_gate_status_board".to_string(),
                from_screen: "evidence_timeline".to_string(),
                to_screen: "gate_status_board".to_string(),
                trigger: "handoff_to_release_guardian".to_string(),
                guard: "gate_context_available".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_evidence_timeline_to_incident_console".to_string(),
                from_screen: "evidence_timeline".to_string(),
                to_screen: "incident_console".to_string(),
                trigger: "handoff_to_runtime_operator".to_string(),
                guard: "incident_context_available".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_evidence_timeline_to_loading_on_retry".to_string(),
                from_screen: "evidence_timeline".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_gate_status_board_to_artifact_audit".to_string(),
                from_screen: "gate_status_board".to_string(),
                to_screen: "artifact_audit".to_string(),
                trigger: "audit_artifacts".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_gate_status_board_to_artifact_audit_on_failure".to_string(),
                from_screen: "gate_status_board".to_string(),
                to_screen: "artifact_audit".to_string(),
                trigger: "recover".to_string(),
                guard: "gate_evidence_incomplete".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_gate_status_board_to_evidence_timeline".to_string(),
                from_screen: "gate_status_board".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "inspect_evidence".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_gate_status_board_to_loading_on_retry".to_string(),
                from_screen: "gate_status_board".to_string(),
                to_screen: "gate_status_board".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_incident_console_to_evidence_timeline".to_string(),
                from_screen: "incident_console".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "handoff_to_evidence".to_string(),
                guard: "containment_snapshot_available".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_incident_console_to_loading_on_retry".to_string(),
                from_screen: "incident_console".to_string(),
                to_screen: "incident_console".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_incident_console_to_runtime_health".to_string(),
                from_screen: "incident_console".to_string(),
                to_screen: "runtime_health".to_string(),
                trigger: "inspect_runtime_health".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_incident_console_to_runtime_health_on_failure".to_string(),
                from_screen: "incident_console".to_string(),
                to_screen: "runtime_health".to_string(),
                trigger: "recover".to_string(),
                guard: "incident_flow_failed".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_replay_inspector_to_evidence_timeline_on_failure".to_string(),
                from_screen: "replay_inspector".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "recover".to_string(),
                guard: "replay_artifact_missing".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_replay_inspector_to_incident_console".to_string(),
                from_screen: "replay_inspector".to_string(),
                to_screen: "incident_console".to_string(),
                trigger: "return_to_incident_console".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_replay_inspector_to_loading_on_retry".to_string(),
                from_screen: "replay_inspector".to_string(),
                to_screen: "replay_inspector".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_runtime_health_to_evidence_timeline_on_failure".to_string(),
                from_screen: "runtime_health".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "recover".to_string(),
                guard: "runtime_snapshot_unavailable".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_runtime_health_to_loading_on_retry".to_string(),
                from_screen: "runtime_health".to_string(),
                to_screen: "runtime_health".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_runtime_health_to_replay_inspector".to_string(),
                from_screen: "runtime_health".to_string(),
                to_screen: "replay_inspector".to_string(),
                trigger: "open_replay_inspector".to_string(),
                guard: "replay_context_available".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_scenario_workbench_to_evidence_timeline".to_string(),
                from_screen: "scenario_workbench".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "open_evidence_timeline".to_string(),
                guard: "scenario_execution_complete".to_string(),
                outcome: "success".to_string(),
            },
            NavigationRoute {
                id: "route_scenario_workbench_to_evidence_timeline_on_failure".to_string(),
                from_screen: "scenario_workbench".to_string(),
                to_screen: "evidence_timeline".to_string(),
                trigger: "recover".to_string(),
                guard: "scenario_execution_failed".to_string(),
                outcome: "failed".to_string(),
            },
            NavigationRoute {
                id: "route_scenario_workbench_to_loading_on_retry".to_string(),
                from_screen: "scenario_workbench".to_string(),
                to_screen: "scenario_workbench".to_string(),
                trigger: "retry".to_string(),
                guard: "always".to_string(),
                outcome: "success".to_string(),
            },
        ],
        keyboard_bindings: vec![
            NavigationKeyboardBinding {
                key: "?".to_string(),
                action: "open_help_overlay".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: None,
                target_panel: None,
            },
            NavigationKeyboardBinding {
                key: "g a".to_string(),
                action: "go_artifact_audit".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("artifact_audit".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g b".to_string(),
                action: "go_bead_command_center".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("bead_command_center".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g d".to_string(),
                action: "go_decision_ledger".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("decision_ledger".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g e".to_string(),
                action: "go_evidence_timeline".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("evidence_timeline".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g i".to_string(),
                action: "go_incident_console".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("incident_console".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g p".to_string(),
                action: "go_replay_inspector".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("replay_inspector".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g r".to_string(),
                action: "go_runtime_health".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("runtime_health".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g s".to_string(),
                action: "go_scenario_workbench".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("scenario_workbench".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "g t".to_string(),
                action: "go_gate_status_board".to_string(),
                scope: NavigationBindingScope::Global,
                target_screen: Some("gate_status_board".to_string()),
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "c".to_string(),
                action: "request_cancellation".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: Some("action_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "enter".to_string(),
                action: "execute_focused_action".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: Some("action_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "esc".to_string(),
                action: "cancel_modal_return_context".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "r".to_string(),
                action: "refresh_surface".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: Some("context_panel".to_string()),
            },
            NavigationKeyboardBinding {
                key: "shift+tab".to_string(),
                action: "focus_prev_panel".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: None,
            },
            NavigationKeyboardBinding {
                key: "tab".to_string(),
                action: "focus_next_panel".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: None,
            },
            NavigationKeyboardBinding {
                key: "x".to_string(),
                action: "open_replay_or_export".to_string(),
                scope: NavigationBindingScope::Screen,
                target_screen: None,
                target_panel: Some("action_panel".to_string()),
            },
        ],
        route_events: vec![
            NavigationRouteEvent {
                event: "focus_changed".to_string(),
                required_fields: vec![
                    "contract_version".to_string(),
                    "correlation_id".to_string(),
                    "event".to_string(),
                    "focus_target".to_string(),
                    "latency_ms".to_string(),
                    "navigation_topology_version".to_string(),
                    "run_id".to_string(),
                    "screen_id".to_string(),
                    "trace_id".to_string(),
                ],
            },
            NavigationRouteEvent {
                event: "focus_invalid".to_string(),
                required_fields: vec![
                    "contract_version".to_string(),
                    "correlation_id".to_string(),
                    "diagnostic_reason".to_string(),
                    "event".to_string(),
                    "focus_target".to_string(),
                    "latency_ms".to_string(),
                    "navigation_topology_version".to_string(),
                    "run_id".to_string(),
                    "screen_id".to_string(),
                    "trace_id".to_string(),
                ],
            },
            NavigationRouteEvent {
                event: "route_blocked".to_string(),
                required_fields: vec![
                    "contract_version".to_string(),
                    "correlation_id".to_string(),
                    "diagnostic_reason".to_string(),
                    "event".to_string(),
                    "focus_target".to_string(),
                    "from_state".to_string(),
                    "latency_ms".to_string(),
                    "navigation_topology_version".to_string(),
                    "outcome_class".to_string(),
                    "run_id".to_string(),
                    "screen_id".to_string(),
                    "to_state".to_string(),
                    "trace_id".to_string(),
                    "trigger".to_string(),
                ],
            },
            NavigationRouteEvent {
                event: "route_entered".to_string(),
                required_fields: vec![
                    "contract_version".to_string(),
                    "correlation_id".to_string(),
                    "event".to_string(),
                    "focus_target".to_string(),
                    "from_state".to_string(),
                    "latency_ms".to_string(),
                    "navigation_topology_version".to_string(),
                    "outcome_class".to_string(),
                    "run_id".to_string(),
                    "screen_id".to_string(),
                    "to_state".to_string(),
                    "trace_id".to_string(),
                    "trigger".to_string(),
                ],
            },
            NavigationRouteEvent {
                event: "route_recovery_completed".to_string(),
                required_fields: vec![
                    "contract_version".to_string(),
                    "correlation_id".to_string(),
                    "event".to_string(),
                    "focus_target".to_string(),
                    "from_state".to_string(),
                    "latency_ms".to_string(),
                    "navigation_topology_version".to_string(),
                    "outcome_class".to_string(),
                    "recovery_route_id".to_string(),
                    "rerun_context".to_string(),
                    "run_id".to_string(),
                    "screen_id".to_string(),
                    "to_state".to_string(),
                    "trace_id".to_string(),
                    "trigger".to_string(),
                ],
            },
            NavigationRouteEvent {
                event: "route_recovery_started".to_string(),
                required_fields: vec![
                    "contract_version".to_string(),
                    "correlation_id".to_string(),
                    "event".to_string(),
                    "focus_target".to_string(),
                    "from_state".to_string(),
                    "latency_ms".to_string(),
                    "navigation_topology_version".to_string(),
                    "outcome_class".to_string(),
                    "recovery_route_id".to_string(),
                    "rerun_context".to_string(),
                    "run_id".to_string(),
                    "screen_id".to_string(),
                    "to_state".to_string(),
                    "trace_id".to_string(),
                    "trigger".to_string(),
                ],
            },
        ],
    };

    OperatorModelContract {
        contract_version: OPERATOR_MODEL_VERSION.to_string(),
        personas,
        decision_loops,
        global_evidence_requirements,
        navigation_topology,
    }
}

/// Validates structural invariants of an [`OperatorModelContract`].
///
/// # Errors
///
/// Returns `Err` when required fields are missing, duplicated, or inconsistent.
#[allow(clippy::too_many_lines)]
pub fn validate_operator_model_contract(contract: &OperatorModelContract) -> Result<(), String> {
    if contract.contract_version.trim().is_empty() {
        return Err("contract_version must be non-empty".to_string());
    }

    if contract.personas.is_empty() {
        return Err("personas must be non-empty".to_string());
    }
    if contract.decision_loops.is_empty() {
        return Err("decision_loops must be non-empty".to_string());
    }
    if contract.global_evidence_requirements.is_empty() {
        return Err("global_evidence_requirements must be non-empty".to_string());
    }
    if contract.navigation_topology.version.trim().is_empty() {
        return Err("navigation_topology.version must be non-empty".to_string());
    }

    let mut deduped_global = contract.global_evidence_requirements.clone();
    deduped_global.sort();
    deduped_global.dedup();
    if deduped_global.len() != contract.global_evidence_requirements.len() {
        return Err("global_evidence_requirements must be unique".to_string());
    }
    if deduped_global != contract.global_evidence_requirements {
        return Err("global_evidence_requirements must be lexically sorted".to_string());
    }
    let global_evidence_set: BTreeSet<_> = contract.global_evidence_requirements.iter().collect();

    let mut seen_personas = BTreeSet::new();
    for persona in &contract.personas {
        if persona.id.trim().is_empty() || persona.label.trim().is_empty() {
            return Err("persona id and label must be non-empty".to_string());
        }
        if !seen_personas.insert(persona.id.clone()) {
            return Err(format!("duplicate persona id: {}", persona.id));
        }
        if persona.default_decision_loop.trim().is_empty() {
            return Err(format!(
                "persona {} has empty default_decision_loop",
                persona.id
            ));
        }
        if persona.primary_views.is_empty() {
            return Err(format!("persona {} must define primary_views", persona.id));
        }
        if persona.mission_success_signals.is_empty() {
            return Err(format!(
                "persona {} must define mission_success_signals",
                persona.id
            ));
        }
        let mut deduped_signals = persona.mission_success_signals.clone();
        deduped_signals.sort();
        deduped_signals.dedup();
        if deduped_signals.len() != persona.mission_success_signals.len() {
            return Err(format!(
                "persona {} mission_success_signals must be unique",
                persona.id
            ));
        }
        if deduped_signals != persona.mission_success_signals {
            return Err(format!(
                "persona {} mission_success_signals must be lexically sorted",
                persona.id
            ));
        }
        if persona.high_stakes_decisions.is_empty() {
            return Err(format!(
                "persona {} must define high_stakes_decisions",
                persona.id
            ));
        }
    }

    let mut loop_steps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut step_evidence_keys: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut seen_loops = BTreeSet::new();
    for loop_def in &contract.decision_loops {
        if loop_def.id.trim().is_empty() {
            return Err("decision loop id must be non-empty".to_string());
        }
        if !seen_loops.insert(loop_def.id.clone()) {
            return Err(format!("duplicate decision loop id: {}", loop_def.id));
        }
        if loop_def.steps.is_empty() {
            return Err(format!("decision loop {} has no steps", loop_def.id));
        }

        let mut seen_steps = BTreeSet::new();
        let mut loop_step_ids = BTreeSet::new();
        for step in &loop_def.steps {
            if step.id.trim().is_empty() || step.action.trim().is_empty() {
                return Err(format!(
                    "decision loop {} has step with empty id/action",
                    loop_def.id
                ));
            }
            if !seen_steps.insert(step.id.clone()) {
                return Err(format!(
                    "duplicate step id {} in loop {}",
                    step.id, loop_def.id
                ));
            }
            if step.required_evidence.is_empty() {
                return Err(format!(
                    "decision loop {} step {} must declare required evidence",
                    loop_def.id, step.id
                ));
            }
            let mut deduped_step_evidence = step.required_evidence.clone();
            deduped_step_evidence.sort();
            deduped_step_evidence.dedup();
            if deduped_step_evidence.len() != step.required_evidence.len() {
                return Err(format!(
                    "decision loop {} step {} required_evidence must be unique",
                    loop_def.id, step.id
                ));
            }
            if deduped_step_evidence != step.required_evidence {
                return Err(format!(
                    "decision loop {} step {} required_evidence must be lexically sorted",
                    loop_def.id, step.id
                ));
            }
            if step
                .required_evidence
                .iter()
                .any(|key| key.trim().is_empty())
            {
                return Err(format!(
                    "decision loop {} step {} has empty evidence key",
                    loop_def.id, step.id
                ));
            }
            loop_step_ids.insert(step.id.clone());
            step_evidence_keys.insert(
                (loop_def.id.clone(), step.id.clone()),
                step.required_evidence.iter().cloned().collect(),
            );
        }
        loop_steps.insert(loop_def.id.clone(), loop_step_ids);
    }

    for persona in &contract.personas {
        if !seen_loops.contains(&persona.default_decision_loop) {
            return Err(format!(
                "persona {} references unknown decision loop {}",
                persona.id, persona.default_decision_loop
            ));
        }
        let mut seen_decisions = BTreeSet::new();
        for decision in &persona.high_stakes_decisions {
            if decision.id.trim().is_empty() || decision.prompt.trim().is_empty() {
                return Err(format!(
                    "persona {} has high_stakes_decision with empty id/prompt",
                    persona.id
                ));
            }
            if !seen_decisions.insert(decision.id.clone()) {
                return Err(format!(
                    "persona {} has duplicate high_stakes_decision id {}",
                    persona.id, decision.id
                ));
            }
            if decision.decision_loop != persona.default_decision_loop {
                return Err(format!(
                    "persona {} decision {} must use default decision loop {}",
                    persona.id, decision.id, persona.default_decision_loop
                ));
            }
            let Some(step_ids) = loop_steps.get(&decision.decision_loop) else {
                return Err(format!(
                    "persona {} decision {} references unknown decision loop {}",
                    persona.id, decision.id, decision.decision_loop
                ));
            };
            if !step_ids.contains(&decision.decision_step) {
                return Err(format!(
                    "persona {} decision {} references unknown step {} in loop {}",
                    persona.id, decision.id, decision.decision_step, decision.decision_loop
                ));
            }
            if decision.required_evidence.is_empty() {
                return Err(format!(
                    "persona {} decision {} must declare required_evidence",
                    persona.id, decision.id
                ));
            }
            let mut deduped_decision_evidence = decision.required_evidence.clone();
            deduped_decision_evidence.sort();
            deduped_decision_evidence.dedup();
            if deduped_decision_evidence.len() != decision.required_evidence.len() {
                return Err(format!(
                    "persona {} decision {} required_evidence must be unique",
                    persona.id, decision.id
                ));
            }
            if deduped_decision_evidence != decision.required_evidence {
                return Err(format!(
                    "persona {} decision {} required_evidence must be lexically sorted",
                    persona.id, decision.id
                ));
            }
            let Some(step_keys) = step_evidence_keys.get(&(
                decision.decision_loop.clone(),
                decision.decision_step.clone(),
            )) else {
                return Err(format!(
                    "persona {} decision {} has missing step evidence binding",
                    persona.id, decision.id
                ));
            };
            for key in &decision.required_evidence {
                if key.trim().is_empty() {
                    return Err(format!(
                        "persona {} decision {} has empty evidence key",
                        persona.id, decision.id
                    ));
                }
                if !step_keys.contains(key) && !global_evidence_set.contains(key) {
                    return Err(format!(
                        "persona {} decision {} references unknown evidence key {}",
                        persona.id, decision.id, key
                    ));
                }
            }
        }
    }

    let topology = &contract.navigation_topology;
    if topology.entry_points.is_empty() {
        return Err("navigation_topology.entry_points must be non-empty".to_string());
    }
    let mut deduped_entry_points = topology.entry_points.clone();
    deduped_entry_points.sort();
    deduped_entry_points.dedup();
    if deduped_entry_points.len() != topology.entry_points.len() {
        return Err("navigation_topology.entry_points must be unique".to_string());
    }
    if deduped_entry_points != topology.entry_points {
        return Err("navigation_topology.entry_points must be lexically sorted".to_string());
    }

    if topology.screens.is_empty() {
        return Err("navigation_topology.screens must be non-empty".to_string());
    }
    let screen_ids: Vec<_> = topology
        .screens
        .iter()
        .map(|screen| screen.id.clone())
        .collect();
    if screen_ids.iter().any(|id| id.trim().is_empty()) {
        return Err("navigation_topology.screens contains empty id".to_string());
    }
    let mut deduped_screen_ids = screen_ids.clone();
    deduped_screen_ids.sort();
    deduped_screen_ids.dedup();
    if deduped_screen_ids.len() != screen_ids.len() {
        return Err("navigation_topology.screens must be unique by id".to_string());
    }
    if deduped_screen_ids != screen_ids {
        return Err("navigation_topology.screens must be lexically sorted by id".to_string());
    }
    let topology_screen_set: BTreeSet<_> = screen_ids.iter().cloned().collect();

    let screen_contract = screen_engine_contract();
    let screen_contract_ids: BTreeSet<_> = screen_contract
        .screens
        .into_iter()
        .map(|screen| screen.id)
        .collect();

    for screen in &topology.screens {
        if screen.label.trim().is_empty() {
            return Err(format!(
                "navigation_topology screen {} has empty label",
                screen.id
            ));
        }
        if !screen.route.starts_with("/doctor/") {
            return Err(format!(
                "navigation_topology screen {} has invalid route {}",
                screen.id, screen.route
            ));
        }
        if screen.personas.is_empty() {
            return Err(format!(
                "navigation_topology screen {} must declare personas",
                screen.id
            ));
        }
        let mut deduped_personas = screen.personas.clone();
        deduped_personas.sort();
        deduped_personas.dedup();
        if deduped_personas.len() != screen.personas.len() {
            return Err(format!(
                "navigation_topology screen {} personas must be unique",
                screen.id
            ));
        }
        if deduped_personas != screen.personas {
            return Err(format!(
                "navigation_topology screen {} personas must be lexically sorted",
                screen.id
            ));
        }
        for persona_id in &screen.personas {
            if !seen_personas.contains(persona_id) {
                return Err(format!(
                    "navigation_topology screen {} references unknown persona {}",
                    screen.id, persona_id
                ));
            }
        }
        if screen.primary_panels.is_empty() || screen.focus_order.is_empty() {
            return Err(format!(
                "navigation_topology screen {} must define primary_panels and focus_order",
                screen.id
            ));
        }
        if screen
            .primary_panels
            .iter()
            .any(|panel| panel.trim().is_empty())
            || screen
                .focus_order
                .iter()
                .any(|panel| panel.trim().is_empty())
        {
            return Err(format!(
                "navigation_topology screen {} has empty panel id",
                screen.id
            ));
        }
        let mut deduped_primary_panels = screen.primary_panels.clone();
        deduped_primary_panels.sort();
        deduped_primary_panels.dedup();
        if deduped_primary_panels.len() != screen.primary_panels.len() {
            return Err(format!(
                "navigation_topology screen {} primary_panels must be unique",
                screen.id
            ));
        }
        let mut deduped_focus_order = screen.focus_order.clone();
        deduped_focus_order.sort();
        deduped_focus_order.dedup();
        if deduped_focus_order.len() != screen.focus_order.len() {
            return Err(format!(
                "navigation_topology screen {} focus_order must be unique",
                screen.id
            ));
        }
        let primary_panel_set: BTreeSet<_> = screen.primary_panels.iter().collect();
        let focus_panel_set: BTreeSet<_> = screen.focus_order.iter().collect();
        if primary_panel_set != focus_panel_set {
            return Err(format!(
                "navigation_topology screen {} focus_order must match primary_panels set",
                screen.id
            ));
        }
        if screen.recovery_routes.is_empty() {
            return Err(format!(
                "navigation_topology screen {} must define recovery_routes",
                screen.id
            ));
        }
        let mut deduped_recovery_routes = screen.recovery_routes.clone();
        deduped_recovery_routes.sort();
        deduped_recovery_routes.dedup();
        if deduped_recovery_routes.len() != screen.recovery_routes.len() {
            return Err(format!(
                "navigation_topology screen {} recovery_routes must be unique",
                screen.id
            ));
        }
        if !screen_contract_ids.contains(&screen.id) {
            return Err(format!(
                "navigation_topology screen {} is missing from screen_engine_contract",
                screen.id
            ));
        }
    }

    if topology_screen_set != screen_contract_ids {
        return Err(
            "navigation_topology screens must match screen_engine_contract screens".to_string(),
        );
    }
    for entry in &topology.entry_points {
        if !topology_screen_set.contains(entry) {
            return Err(format!(
                "navigation_topology entry_point {entry} references unknown screen"
            ));
        }
    }

    if topology.routes.is_empty() {
        return Err("navigation_topology.routes must be non-empty".to_string());
    }
    let route_ids: Vec<_> = topology
        .routes
        .iter()
        .map(|route| route.id.clone())
        .collect();
    if route_ids.iter().any(|id| id.trim().is_empty()) {
        return Err("navigation_topology.routes contains empty id".to_string());
    }
    let mut deduped_route_ids = route_ids.clone();
    deduped_route_ids.sort();
    deduped_route_ids.dedup();
    if deduped_route_ids.len() != route_ids.len() {
        return Err("navigation_topology.routes must be unique by id".to_string());
    }
    if deduped_route_ids != route_ids {
        return Err("navigation_topology.routes must be lexically sorted by id".to_string());
    }
    let route_id_set: BTreeSet<_> = route_ids.iter().cloned().collect();
    for route in &topology.routes {
        if route.trigger.trim().is_empty() || route.guard.trim().is_empty() {
            return Err(format!(
                "navigation route {} must define non-empty trigger/guard",
                route.id
            ));
        }
        if !topology_screen_set.contains(&route.from_screen)
            || !topology_screen_set.contains(&route.to_screen)
        {
            return Err(format!(
                "navigation route {} references unknown screen(s): {} -> {}",
                route.id, route.from_screen, route.to_screen
            ));
        }
        if route.outcome != "success" && route.outcome != "cancelled" && route.outcome != "failed" {
            return Err(format!(
                "navigation route {} has invalid outcome {}",
                route.id, route.outcome
            ));
        }
    }
    for screen in &topology.screens {
        for route_id in &screen.recovery_routes {
            if !route_id_set.contains(route_id) {
                return Err(format!(
                    "navigation screen {} recovery route {} is undefined",
                    screen.id, route_id
                ));
            }
        }
    }

    if topology.keyboard_bindings.is_empty() {
        return Err("navigation_topology.keyboard_bindings must be non-empty".to_string());
    }
    let mut binding_uniqueness = BTreeSet::new();
    let mut binding_order = Vec::new();
    let valid_panels = BTreeSet::from([
        "action_panel".to_string(),
        "context_panel".to_string(),
        "primary_panel".to_string(),
    ]);
    for binding in &topology.keyboard_bindings {
        if binding.key.trim().is_empty() || binding.action.trim().is_empty() {
            return Err("navigation keyboard binding has empty key/action".to_string());
        }
        if !binding_uniqueness.insert((binding.scope, binding.key.clone())) {
            return Err(format!(
                "duplicate navigation keyboard binding for scope/key: {:?} {}",
                binding.scope, binding.key
            ));
        }
        if let Some(target_screen) = &binding.target_screen
            && !topology_screen_set.contains(target_screen)
        {
            return Err(format!(
                "navigation keyboard binding {} references unknown target_screen {}",
                binding.key, target_screen
            ));
        }
        if let Some(target_panel) = &binding.target_panel
            && !valid_panels.contains(target_panel)
        {
            return Err(format!(
                "navigation keyboard binding {} references unknown target_panel {}",
                binding.key, target_panel
            ));
        }
        if binding.scope == NavigationBindingScope::Screen && binding.target_screen.is_some() {
            return Err(format!(
                "screen-scoped binding {} must not set target_screen",
                binding.key
            ));
        }
        binding_order.push((
            binding.scope,
            binding.key.clone(),
            binding.target_screen.clone(),
            binding.target_panel.clone(),
            binding.action.clone(),
        ));
    }
    let mut sorted_binding_order = binding_order.clone();
    sorted_binding_order.sort();
    if sorted_binding_order != binding_order {
        return Err("navigation_topology.keyboard_bindings must be lexically sorted".to_string());
    }

    if topology.route_events.is_empty() {
        return Err("navigation_topology.route_events must be non-empty".to_string());
    }
    let route_event_names: Vec<_> = topology
        .route_events
        .iter()
        .map(|event| event.event.clone())
        .collect();
    if route_event_names
        .iter()
        .any(|event| event.trim().is_empty())
    {
        return Err("navigation_topology.route_events contains empty event".to_string());
    }
    let mut deduped_route_event_names = route_event_names.clone();
    deduped_route_event_names.sort();
    deduped_route_event_names.dedup();
    if deduped_route_event_names.len() != route_event_names.len() {
        return Err("navigation_topology.route_events must be unique by event".to_string());
    }
    if deduped_route_event_names != route_event_names {
        return Err(
            "navigation_topology.route_events must be lexically sorted by event".to_string(),
        );
    }
    for event in &topology.route_events {
        if event.required_fields.is_empty() {
            return Err(format!(
                "navigation route_event {} must define required_fields",
                event.event
            ));
        }
        if event
            .required_fields
            .iter()
            .any(|field| field.trim().is_empty())
        {
            return Err(format!(
                "navigation route_event {} has empty required field",
                event.event
            ));
        }
        let mut deduped_required_fields = event.required_fields.clone();
        deduped_required_fields.sort();
        deduped_required_fields.dedup();
        if deduped_required_fields.len() != event.required_fields.len() {
            return Err(format!(
                "navigation route_event {} required_fields must be unique",
                event.event
            ));
        }
        if deduped_required_fields != event.required_fields {
            return Err(format!(
                "navigation route_event {} required_fields must be lexically sorted",
                event.event
            ));
        }
        for required in ["correlation_id", "run_id", "screen_id", "trace_id"] {
            if !event.required_fields.iter().any(|field| field == required) {
                return Err(format!(
                    "navigation route_event {} missing required field {}",
                    event.event, required
                ));
            }
        }
    }

    Ok(())
}

/// Returns the final UX signoff matrix contract layered on the v0 baseline.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn ux_signoff_matrix_contract() -> UxSignoffMatrixContract {
    UxSignoffMatrixContract {
        contract_version: UX_SIGNOFF_MATRIX_VERSION.to_string(),
        baseline_matrix_version: UX_BASELINE_MATRIX_VERSION.to_string(),
        logging_requirements: vec![
            "assertion_id".to_string(),
            "correlation_id".to_string(),
            "journey_id".to_string(),
            "outcome".to_string(),
            "route_ref".to_string(),
            "run_id".to_string(),
            "screen_id".to_string(),
            "trace_id".to_string(),
        ],
        journeys: vec![
            UxJourneySignoff {
                journey_id: "journey_conformance_engineer_triage".to_string(),
                persona_id: "conformance_engineer".to_string(),
                decision_loop_id: "triage_investigate_remediate".to_string(),
                canonical_path: vec![
                    "bead_command_center".to_string(),
                    "scenario_workbench".to_string(),
                    "evidence_timeline".to_string(),
                    "bead_command_center".to_string(),
                ],
                transitions: vec![
                    UxTransitionAssertion {
                        id: "tx_journey_conformance_engineer_triage_01".to_string(),
                        from_screen: "bead_command_center".to_string(),
                        to_screen: "scenario_workbench".to_string(),
                        route_ref: "route_bead_command_center_to_scenario_workbench".to_string(),
                        expected_focus_panel: "context_panel".to_string(),
                    },
                    UxTransitionAssertion {
                        id: "tx_journey_conformance_engineer_triage_02".to_string(),
                        from_screen: "scenario_workbench".to_string(),
                        to_screen: "evidence_timeline".to_string(),
                        route_ref: "route_scenario_workbench_to_evidence_timeline".to_string(),
                        expected_focus_panel: "primary_panel".to_string(),
                    },
                    UxTransitionAssertion {
                        id: "tx_journey_conformance_engineer_triage_03".to_string(),
                        from_screen: "evidence_timeline".to_string(),
                        to_screen: "bead_command_center".to_string(),
                        route_ref: "route_evidence_timeline_to_bead_command_center".to_string(),
                        expected_focus_panel: "context_panel".to_string(),
                    },
                ],
                interruption_assertions: vec![
                    UxInterruptionAssertion {
                        id: "int_journey_conformance_engineer_triage_01".to_string(),
                        screen_id: "scenario_workbench".to_string(),
                        trigger: "cancellation_request".to_string(),
                        expected_state: "cancelled".to_string(),
                    },
                    UxInterruptionAssertion {
                        id: "int_journey_conformance_engineer_triage_02".to_string(),
                        screen_id: "evidence_timeline".to_string(),
                        trigger: "route_blocked".to_string(),
                        expected_state: "failed".to_string(),
                    },
                ],
                recovery_assertions: vec![
                    UxRecoveryAssertion {
                        id: "rec_journey_conformance_engineer_triage_01".to_string(),
                        from_screen: "scenario_workbench".to_string(),
                        to_screen: "scenario_workbench".to_string(),
                        route_ref: "route_scenario_workbench_to_loading_on_retry".to_string(),
                        requires_rerun_context: true,
                    },
                    UxRecoveryAssertion {
                        id: "rec_journey_conformance_engineer_triage_02".to_string(),
                        from_screen: "scenario_workbench".to_string(),
                        to_screen: "evidence_timeline".to_string(),
                        route_ref: "route_scenario_workbench_to_evidence_timeline_on_failure"
                            .to_string(),
                        requires_rerun_context: true,
                    },
                ],
                evidence_assertions: vec![
                    UxEvidenceAssertion {
                        id: "ev_journey_conformance_engineer_triage_01".to_string(),
                        screen_id: "bead_command_center".to_string(),
                        required_evidence_keys: vec![
                            "finding_id".to_string(),
                            "priority_score".to_string(),
                            "scenario_id".to_string(),
                        ],
                    },
                    UxEvidenceAssertion {
                        id: "ev_journey_conformance_engineer_triage_02".to_string(),
                        screen_id: "evidence_timeline".to_string(),
                        required_evidence_keys: vec![
                            "artifact_pointer".to_string(),
                            "outcome_class".to_string(),
                            "trace_id".to_string(),
                        ],
                    },
                ],
            },
            UxJourneySignoff {
                journey_id: "journey_release_guardian_gate".to_string(),
                persona_id: "release_guardian".to_string(),
                decision_loop_id: "release_gate_verification".to_string(),
                canonical_path: vec![
                    "gate_status_board".to_string(),
                    "artifact_audit".to_string(),
                    "decision_ledger".to_string(),
                    "gate_status_board".to_string(),
                ],
                transitions: vec![
                    UxTransitionAssertion {
                        id: "tx_journey_release_guardian_gate_01".to_string(),
                        from_screen: "gate_status_board".to_string(),
                        to_screen: "artifact_audit".to_string(),
                        route_ref: "route_gate_status_board_to_artifact_audit".to_string(),
                        expected_focus_panel: "context_panel".to_string(),
                    },
                    UxTransitionAssertion {
                        id: "tx_journey_release_guardian_gate_02".to_string(),
                        from_screen: "artifact_audit".to_string(),
                        to_screen: "decision_ledger".to_string(),
                        route_ref: "route_artifact_audit_to_decision_ledger".to_string(),
                        expected_focus_panel: "action_panel".to_string(),
                    },
                    UxTransitionAssertion {
                        id: "tx_journey_release_guardian_gate_03".to_string(),
                        from_screen: "decision_ledger".to_string(),
                        to_screen: "gate_status_board".to_string(),
                        route_ref: "route_decision_ledger_to_gate_status_board".to_string(),
                        expected_focus_panel: "context_panel".to_string(),
                    },
                ],
                interruption_assertions: vec![
                    UxInterruptionAssertion {
                        id: "int_journey_release_guardian_gate_01".to_string(),
                        screen_id: "artifact_audit".to_string(),
                        trigger: "cancellation_request".to_string(),
                        expected_state: "cancelled".to_string(),
                    },
                    UxInterruptionAssertion {
                        id: "int_journey_release_guardian_gate_02".to_string(),
                        screen_id: "gate_status_board".to_string(),
                        trigger: "route_blocked".to_string(),
                        expected_state: "failed".to_string(),
                    },
                ],
                recovery_assertions: vec![
                    UxRecoveryAssertion {
                        id: "rec_journey_release_guardian_gate_01".to_string(),
                        from_screen: "gate_status_board".to_string(),
                        to_screen: "artifact_audit".to_string(),
                        route_ref: "route_gate_status_board_to_artifact_audit_on_failure"
                            .to_string(),
                        requires_rerun_context: true,
                    },
                    UxRecoveryAssertion {
                        id: "rec_journey_release_guardian_gate_02".to_string(),
                        from_screen: "artifact_audit".to_string(),
                        to_screen: "artifact_audit".to_string(),
                        route_ref: "route_artifact_audit_to_loading_on_retry".to_string(),
                        requires_rerun_context: true,
                    },
                ],
                evidence_assertions: vec![
                    UxEvidenceAssertion {
                        id: "ev_journey_release_guardian_gate_01".to_string(),
                        screen_id: "artifact_audit".to_string(),
                        required_evidence_keys: vec![
                            "command_provenance".to_string(),
                            "gate_name".to_string(),
                            "outcome_class".to_string(),
                        ],
                    },
                    UxEvidenceAssertion {
                        id: "ev_journey_release_guardian_gate_02".to_string(),
                        screen_id: "decision_ledger".to_string(),
                        required_evidence_keys: vec![
                            "decision_reason".to_string(),
                            "outcome_class".to_string(),
                            "run_id".to_string(),
                        ],
                    },
                ],
            },
            UxJourneySignoff {
                journey_id: "journey_runtime_operator_incident".to_string(),
                persona_id: "runtime_operator".to_string(),
                decision_loop_id: "incident_containment".to_string(),
                canonical_path: vec![
                    "incident_console".to_string(),
                    "runtime_health".to_string(),
                    "replay_inspector".to_string(),
                    "incident_console".to_string(),
                ],
                transitions: vec![
                    UxTransitionAssertion {
                        id: "tx_journey_runtime_operator_incident_01".to_string(),
                        from_screen: "incident_console".to_string(),
                        to_screen: "runtime_health".to_string(),
                        route_ref: "route_incident_console_to_runtime_health".to_string(),
                        expected_focus_panel: "context_panel".to_string(),
                    },
                    UxTransitionAssertion {
                        id: "tx_journey_runtime_operator_incident_02".to_string(),
                        from_screen: "runtime_health".to_string(),
                        to_screen: "replay_inspector".to_string(),
                        route_ref: "route_runtime_health_to_replay_inspector".to_string(),
                        expected_focus_panel: "primary_panel".to_string(),
                    },
                    UxTransitionAssertion {
                        id: "tx_journey_runtime_operator_incident_03".to_string(),
                        from_screen: "replay_inspector".to_string(),
                        to_screen: "incident_console".to_string(),
                        route_ref: "route_replay_inspector_to_incident_console".to_string(),
                        expected_focus_panel: "context_panel".to_string(),
                    },
                ],
                interruption_assertions: vec![
                    UxInterruptionAssertion {
                        id: "int_journey_runtime_operator_incident_01".to_string(),
                        screen_id: "incident_console".to_string(),
                        trigger: "cancellation_request".to_string(),
                        expected_state: "cancelled".to_string(),
                    },
                    UxInterruptionAssertion {
                        id: "int_journey_runtime_operator_incident_02".to_string(),
                        screen_id: "runtime_health".to_string(),
                        trigger: "route_blocked".to_string(),
                        expected_state: "failed".to_string(),
                    },
                ],
                recovery_assertions: vec![
                    UxRecoveryAssertion {
                        id: "rec_journey_runtime_operator_incident_01".to_string(),
                        from_screen: "incident_console".to_string(),
                        to_screen: "incident_console".to_string(),
                        route_ref: "route_incident_console_to_loading_on_retry".to_string(),
                        requires_rerun_context: true,
                    },
                    UxRecoveryAssertion {
                        id: "rec_journey_runtime_operator_incident_02".to_string(),
                        from_screen: "incident_console".to_string(),
                        to_screen: "runtime_health".to_string(),
                        route_ref: "route_incident_console_to_runtime_health_on_failure"
                            .to_string(),
                        requires_rerun_context: true,
                    },
                ],
                evidence_assertions: vec![
                    UxEvidenceAssertion {
                        id: "ev_journey_runtime_operator_incident_01".to_string(),
                        screen_id: "runtime_health".to_string(),
                        required_evidence_keys: vec![
                            "cancel_phase".to_string(),
                            "obligation_snapshot".to_string(),
                            "run_id".to_string(),
                        ],
                    },
                    UxEvidenceAssertion {
                        id: "ev_journey_runtime_operator_incident_02".to_string(),
                        screen_id: "replay_inspector".to_string(),
                        required_evidence_keys: vec![
                            "artifact_pointer".to_string(),
                            "repro_command".to_string(),
                            "scenario_id".to_string(),
                        ],
                    },
                ],
            },
        ],
        rollout_gate: UxRolloutGatePolicy {
            min_pass_rate_percent: 98,
            require_zero_critical_failures: true,
            required_journeys: vec![
                "journey_conformance_engineer_triage".to_string(),
                "journey_release_guardian_gate".to_string(),
                "journey_runtime_operator_incident".to_string(),
            ],
            mandatory_remediations: vec![
                "block_rollout_until_green_signoff".to_string(),
                "capture_state_diff_and_rerun_hint".to_string(),
                "file_followup_bead_with_trace_link".to_string(),
            ],
        },
    }
}

/// Validates final UX signoff matrix integrity and rollout gates.
#[allow(clippy::too_many_lines)]
pub fn validate_ux_signoff_matrix_contract(
    contract: &UxSignoffMatrixContract,
) -> Result<(), String> {
    if contract.contract_version != UX_SIGNOFF_MATRIX_VERSION {
        return Err(format!(
            "ux_signoff contract_version must equal {UX_SIGNOFF_MATRIX_VERSION}"
        ));
    }
    if contract.baseline_matrix_version != UX_BASELINE_MATRIX_VERSION {
        return Err(format!(
            "ux_signoff baseline_matrix_version must equal {UX_BASELINE_MATRIX_VERSION}"
        ));
    }
    if contract.logging_requirements.is_empty() {
        return Err("ux_signoff logging_requirements must be non-empty".to_string());
    }
    let mut sorted_logging_requirements = contract.logging_requirements.clone();
    sorted_logging_requirements.sort();
    sorted_logging_requirements.dedup();
    if sorted_logging_requirements.len() != contract.logging_requirements.len() {
        return Err("ux_signoff logging_requirements must be unique".to_string());
    }
    if sorted_logging_requirements != contract.logging_requirements {
        return Err("ux_signoff logging_requirements must be lexically sorted".to_string());
    }
    for required in [
        "assertion_id",
        "correlation_id",
        "journey_id",
        "outcome",
        "route_ref",
        "run_id",
        "screen_id",
        "trace_id",
    ] {
        if !contract
            .logging_requirements
            .iter()
            .any(|field| field == required)
        {
            return Err(format!(
                "ux_signoff logging_requirements missing required field {required}"
            ));
        }
    }

    let operator_contract = operator_model_contract();
    validate_operator_model_contract(&operator_contract)?;
    let screen_contract = screen_engine_contract();
    validate_screen_engine_contract(&screen_contract)?;

    let persona_ids: BTreeSet<_> = operator_contract
        .personas
        .iter()
        .map(|persona| persona.id.clone())
        .collect();
    let decision_loop_ids: BTreeSet<_> = operator_contract
        .decision_loops
        .iter()
        .map(|decision_loop| decision_loop.id.clone())
        .collect();
    let screen_ids: BTreeSet<_> = screen_contract
        .screens
        .iter()
        .map(|screen| screen.id.clone())
        .collect();
    let route_map: BTreeMap<_, _> = operator_contract
        .navigation_topology
        .routes
        .iter()
        .map(|route| {
            (
                route.id.clone(),
                (route.from_screen.clone(), route.to_screen.clone()),
            )
        })
        .collect();
    let route_pairs: BTreeSet<_> = route_map
        .values()
        .map(|(from_screen, to_screen)| (from_screen.clone(), to_screen.clone()))
        .collect();
    let mut known_evidence_keys: BTreeSet<String> = operator_contract
        .global_evidence_requirements
        .iter()
        .cloned()
        .collect();
    for decision_loop in &operator_contract.decision_loops {
        for step in &decision_loop.steps {
            known_evidence_keys.extend(step.required_evidence.iter().cloned());
        }
    }

    if contract.journeys.is_empty() {
        return Err("ux_signoff journeys must be non-empty".to_string());
    }
    let journey_ids: Vec<_> = contract
        .journeys
        .iter()
        .map(|journey| journey.journey_id.clone())
        .collect();
    let mut sorted_journey_ids = journey_ids.clone();
    sorted_journey_ids.sort();
    sorted_journey_ids.dedup();
    if sorted_journey_ids.len() != journey_ids.len() {
        return Err("ux_signoff journeys must be unique by journey_id".to_string());
    }
    if sorted_journey_ids != journey_ids {
        return Err("ux_signoff journeys must be lexically sorted by journey_id".to_string());
    }

    for journey in &contract.journeys {
        if !persona_ids.contains(&journey.persona_id) {
            return Err(format!(
                "ux_signoff journey {} references unknown persona {}",
                journey.journey_id, journey.persona_id
            ));
        }
        if !decision_loop_ids.contains(&journey.decision_loop_id) {
            return Err(format!(
                "ux_signoff journey {} references unknown decision_loop {}",
                journey.journey_id, journey.decision_loop_id
            ));
        }
        if journey.canonical_path.len() < 2 {
            return Err(format!(
                "ux_signoff journey {} canonical_path must have at least 2 screens",
                journey.journey_id
            ));
        }
        for screen_id in &journey.canonical_path {
            if !screen_ids.contains(screen_id) {
                return Err(format!(
                    "ux_signoff journey {} references unknown screen {} in canonical_path",
                    journey.journey_id, screen_id
                ));
            }
        }
        for path_pair in journey.canonical_path.windows(2) {
            let pair = (path_pair[0].clone(), path_pair[1].clone());
            if !route_pairs.contains(&pair) {
                return Err(format!(
                    "ux_signoff journey {} has canonical_path edge without route: {} -> {}",
                    journey.journey_id, pair.0, pair.1
                ));
            }
        }

        if journey.transitions.is_empty() {
            return Err(format!(
                "ux_signoff journey {} transitions must be non-empty",
                journey.journey_id
            ));
        }
        let transition_ids: Vec<_> = journey
            .transitions
            .iter()
            .map(|assertion| assertion.id.clone())
            .collect();
        let mut sorted_transition_ids = transition_ids.clone();
        sorted_transition_ids.sort();
        sorted_transition_ids.dedup();
        if sorted_transition_ids.len() != transition_ids.len() {
            return Err(format!(
                "ux_signoff journey {} transitions must be unique by id",
                journey.journey_id
            ));
        }
        if sorted_transition_ids != transition_ids {
            return Err(format!(
                "ux_signoff journey {} transitions must be lexically sorted by id",
                journey.journey_id
            ));
        }
        for transition in &journey.transitions {
            if !screen_ids.contains(&transition.from_screen)
                || !screen_ids.contains(&transition.to_screen)
            {
                return Err(format!(
                    "ux_signoff transition {} references unknown screen(s)",
                    transition.id
                ));
            }
            let Some((route_from, route_to)) = route_map.get(&transition.route_ref) else {
                return Err(format!(
                    "ux_signoff transition {} references unknown route {}",
                    transition.id, transition.route_ref
                ));
            };
            if route_from != &transition.from_screen || route_to != &transition.to_screen {
                return Err(format!(
                    "ux_signoff transition {} route {} mismatches {} -> {}",
                    transition.id,
                    transition.route_ref,
                    transition.from_screen,
                    transition.to_screen
                ));
            }
            if transition.expected_focus_panel != "action_panel"
                && transition.expected_focus_panel != "context_panel"
                && transition.expected_focus_panel != "primary_panel"
            {
                return Err(format!(
                    "ux_signoff transition {} has invalid expected_focus_panel {}",
                    transition.id, transition.expected_focus_panel
                ));
            }
        }

        if journey.interruption_assertions.is_empty() {
            return Err(format!(
                "ux_signoff journey {} interruption_assertions must be non-empty",
                journey.journey_id
            ));
        }
        let interruption_ids: Vec<_> = journey
            .interruption_assertions
            .iter()
            .map(|assertion| assertion.id.clone())
            .collect();
        let mut sorted_interruption_ids = interruption_ids.clone();
        sorted_interruption_ids.sort();
        sorted_interruption_ids.dedup();
        if sorted_interruption_ids.len() != interruption_ids.len() {
            return Err(format!(
                "ux_signoff journey {} interruption_assertions must be unique by id",
                journey.journey_id
            ));
        }
        if sorted_interruption_ids != interruption_ids {
            return Err(format!(
                "ux_signoff journey {} interruption_assertions must be lexically sorted by id",
                journey.journey_id
            ));
        }
        for interruption in &journey.interruption_assertions {
            if !screen_ids.contains(&interruption.screen_id) {
                return Err(format!(
                    "ux_signoff interruption {} references unknown screen {}",
                    interruption.id, interruption.screen_id
                ));
            }
            if interruption.trigger.trim().is_empty() {
                return Err(format!(
                    "ux_signoff interruption {} trigger must be non-empty",
                    interruption.id
                ));
            }
            if interruption.expected_state != "cancelled"
                && interruption.expected_state != "failed"
                && interruption.expected_state != "idle"
                && interruption.expected_state != "loading"
                && interruption.expected_state != "ready"
            {
                return Err(format!(
                    "ux_signoff interruption {} has invalid expected_state {}",
                    interruption.id, interruption.expected_state
                ));
            }
        }

        if journey.recovery_assertions.is_empty() {
            return Err(format!(
                "ux_signoff journey {} recovery_assertions must be non-empty",
                journey.journey_id
            ));
        }
        let recovery_ids: Vec<_> = journey
            .recovery_assertions
            .iter()
            .map(|assertion| assertion.id.clone())
            .collect();
        let mut sorted_recovery_ids = recovery_ids.clone();
        sorted_recovery_ids.sort();
        sorted_recovery_ids.dedup();
        if sorted_recovery_ids.len() != recovery_ids.len() {
            return Err(format!(
                "ux_signoff journey {} recovery_assertions must be unique by id",
                journey.journey_id
            ));
        }
        if sorted_recovery_ids != recovery_ids {
            return Err(format!(
                "ux_signoff journey {} recovery_assertions must be lexically sorted by id",
                journey.journey_id
            ));
        }
        for recovery in &journey.recovery_assertions {
            if !screen_ids.contains(&recovery.from_screen)
                || !screen_ids.contains(&recovery.to_screen)
            {
                return Err(format!(
                    "ux_signoff recovery {} references unknown screen(s)",
                    recovery.id
                ));
            }
            let Some((route_from, route_to)) = route_map.get(&recovery.route_ref) else {
                return Err(format!(
                    "ux_signoff recovery {} references unknown route {}",
                    recovery.id, recovery.route_ref
                ));
            };
            if route_from != &recovery.from_screen || route_to != &recovery.to_screen {
                return Err(format!(
                    "ux_signoff recovery {} route {} mismatches {} -> {}",
                    recovery.id, recovery.route_ref, recovery.from_screen, recovery.to_screen
                ));
            }
        }

        if journey.evidence_assertions.is_empty() {
            return Err(format!(
                "ux_signoff journey {} evidence_assertions must be non-empty",
                journey.journey_id
            ));
        }
        let evidence_ids: Vec<_> = journey
            .evidence_assertions
            .iter()
            .map(|assertion| assertion.id.clone())
            .collect();
        let mut sorted_evidence_ids = evidence_ids.clone();
        sorted_evidence_ids.sort();
        sorted_evidence_ids.dedup();
        if sorted_evidence_ids.len() != evidence_ids.len() {
            return Err(format!(
                "ux_signoff journey {} evidence_assertions must be unique by id",
                journey.journey_id
            ));
        }
        if sorted_evidence_ids != evidence_ids {
            return Err(format!(
                "ux_signoff journey {} evidence_assertions must be lexically sorted by id",
                journey.journey_id
            ));
        }
        for evidence in &journey.evidence_assertions {
            if !screen_ids.contains(&evidence.screen_id) {
                return Err(format!(
                    "ux_signoff evidence assertion {} references unknown screen {}",
                    evidence.id, evidence.screen_id
                ));
            }
            if evidence.required_evidence_keys.is_empty() {
                return Err(format!(
                    "ux_signoff evidence assertion {} required_evidence_keys must be non-empty",
                    evidence.id
                ));
            }
            let mut sorted_required_keys = evidence.required_evidence_keys.clone();
            sorted_required_keys.sort();
            sorted_required_keys.dedup();
            if sorted_required_keys.len() != evidence.required_evidence_keys.len() {
                return Err(format!(
                    "ux_signoff evidence assertion {} required_evidence_keys must be unique",
                    evidence.id
                ));
            }
            if sorted_required_keys != evidence.required_evidence_keys {
                return Err(format!(
                    "ux_signoff evidence assertion {} required_evidence_keys must be lexically sorted",
                    evidence.id
                ));
            }
            for evidence_key in &evidence.required_evidence_keys {
                if !known_evidence_keys.contains(evidence_key) {
                    return Err(format!(
                        "ux_signoff evidence assertion {} references unknown evidence key {}",
                        evidence.id, evidence_key
                    ));
                }
            }
        }
    }

    if contract.rollout_gate.min_pass_rate_percent < 95 {
        return Err("ux_signoff rollout_gate min_pass_rate_percent must be >= 95".to_string());
    }
    if !contract.rollout_gate.require_zero_critical_failures {
        return Err("ux_signoff rollout_gate must require zero critical failures".to_string());
    }
    if contract.rollout_gate.required_journeys.is_empty() {
        return Err("ux_signoff rollout_gate required_journeys must be non-empty".to_string());
    }
    let mut sorted_required_journeys = contract.rollout_gate.required_journeys.clone();
    sorted_required_journeys.sort();
    sorted_required_journeys.dedup();
    if sorted_required_journeys.len() != contract.rollout_gate.required_journeys.len() {
        return Err("ux_signoff rollout_gate required_journeys must be unique".to_string());
    }
    if sorted_required_journeys != contract.rollout_gate.required_journeys {
        return Err(
            "ux_signoff rollout_gate required_journeys must be lexically sorted".to_string(),
        );
    }
    if sorted_required_journeys != journey_ids {
        return Err(
            "ux_signoff rollout_gate required_journeys must match journey ids exactly".to_string(),
        );
    }
    if contract.rollout_gate.mandatory_remediations.is_empty() {
        return Err("ux_signoff rollout_gate mandatory_remediations must be non-empty".to_string());
    }
    let mut sorted_mandatory_remediations = contract.rollout_gate.mandatory_remediations.clone();
    sorted_mandatory_remediations.sort();
    sorted_mandatory_remediations.dedup();
    if sorted_mandatory_remediations.len() != contract.rollout_gate.mandatory_remediations.len() {
        return Err("ux_signoff rollout_gate mandatory_remediations must be unique".to_string());
    }
    if sorted_mandatory_remediations != contract.rollout_gate.mandatory_remediations {
        return Err(
            "ux_signoff rollout_gate mandatory_remediations must be lexically sorted".to_string(),
        );
    }

    Ok(())
}

/// Returns the canonical screen-to-engine contract for doctor TUI surfaces.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn screen_engine_contract() -> ScreenEngineContract {
    let base_request_required = vec![
        payload_field(
            "action",
            "enum",
            "Requested action for this screen surface.",
        ),
        payload_field(
            "focus_target",
            "string",
            "Selected entity or region identifier currently in focus.",
        ),
        payload_field("run_id", "string", "Deterministic run identifier."),
    ];
    let base_request_optional = vec![
        payload_field("filter_expr", "string", "Optional filter expression."),
        payload_field("page_cursor", "string", "Optional pagination cursor."),
        payload_field("scenario_id", "string", "Optional scenario identifier."),
    ];
    let base_response_required = vec![
        payload_field(
            "confidence_score",
            "f64",
            "Confidence score for emitted findings.",
        ),
        payload_field(
            "findings",
            "array<string>",
            "Deterministically ordered finding identifiers.",
        ),
        payload_field("outcome_class", "enum", "success|cancelled|failed"),
        payload_field("state", "enum", "Current surface state after processing."),
    ];
    let base_response_optional = vec![
        payload_field(
            "evidence_links",
            "array<string>",
            "Deterministic evidence pointers for the rendered result.",
        ),
        payload_field(
            "remediation_affordances",
            "array<string>",
            "Affordance identifiers available to the operator.",
        ),
        payload_field(
            "warnings",
            "array<string>",
            "Optional warnings attached to the payload exchange.",
        ),
    ];

    let transitions = vec![
        StateTransition {
            from_state: "cancelled".to_string(),
            to_state: "idle".to_string(),
            trigger: "retry".to_string(),
            outcome: "success".to_string(),
        },
        StateTransition {
            from_state: "failed".to_string(),
            to_state: "loading".to_string(),
            trigger: "retry".to_string(),
            outcome: "success".to_string(),
        },
        StateTransition {
            from_state: "idle".to_string(),
            to_state: "loading".to_string(),
            trigger: "request_submitted".to_string(),
            outcome: "cancelled".to_string(),
        },
        StateTransition {
            from_state: "idle".to_string(),
            to_state: "loading".to_string(),
            trigger: "request_submitted".to_string(),
            outcome: "failed".to_string(),
        },
        StateTransition {
            from_state: "idle".to_string(),
            to_state: "loading".to_string(),
            trigger: "request_submitted".to_string(),
            outcome: "success".to_string(),
        },
        StateTransition {
            from_state: "loading".to_string(),
            to_state: "cancelled".to_string(),
            trigger: "cancellation_ack".to_string(),
            outcome: "cancelled".to_string(),
        },
        StateTransition {
            from_state: "loading".to_string(),
            to_state: "failed".to_string(),
            trigger: "engine_error".to_string(),
            outcome: "failed".to_string(),
        },
        StateTransition {
            from_state: "loading".to_string(),
            to_state: "ready".to_string(),
            trigger: "engine_response".to_string(),
            outcome: "success".to_string(),
        },
        StateTransition {
            from_state: "ready".to_string(),
            to_state: "loading".to_string(),
            trigger: "refresh".to_string(),
            outcome: "success".to_string(),
        },
    ];

    let states = vec![
        "cancelled".to_string(),
        "failed".to_string(),
        "idle".to_string(),
        "loading".to_string(),
        "ready".to_string(),
    ];

    let screens = vec![
        ("artifact_audit", "Artifact Audit", vec!["release_guardian"]),
        (
            "bead_command_center",
            "Bead Command Center",
            vec!["conformance_engineer"],
        ),
        (
            "decision_ledger",
            "Decision Ledger",
            vec!["release_guardian"],
        ),
        (
            "evidence_timeline",
            "Evidence Timeline",
            vec!["conformance_engineer", "runtime_operator"],
        ),
        (
            "gate_status_board",
            "Gate Status Board",
            vec!["release_guardian"],
        ),
        (
            "incident_console",
            "Incident Console",
            vec!["runtime_operator"],
        ),
        (
            "replay_inspector",
            "Replay Inspector",
            vec!["runtime_operator"],
        ),
        ("runtime_health", "Runtime Health", vec!["runtime_operator"]),
        (
            "scenario_workbench",
            "Scenario Workbench",
            vec!["conformance_engineer"],
        ),
    ]
    .into_iter()
    .map(|(id, label, personas)| ScreenContract {
        id: id.to_string(),
        label: label.to_string(),
        personas: personas.into_iter().map(ToString::to_string).collect(),
        request_schema: payload_schema(
            &format!("{id}.request.v1"),
            base_request_required.clone(),
            base_request_optional.clone(),
        ),
        response_schema: payload_schema(
            &format!("{id}.response.v1"),
            base_response_required.clone(),
            base_response_optional.clone(),
        ),
        states: states.clone(),
        transitions: transitions.clone(),
    })
    .collect();

    ScreenEngineContract {
        contract_version: SCREEN_ENGINE_CONTRACT_VERSION.to_string(),
        operator_model_version: OPERATOR_MODEL_VERSION.to_string(),
        global_request_fields: vec![
            "contract_version".to_string(),
            "correlation_id".to_string(),
            "rerun_context".to_string(),
            "screen_id".to_string(),
        ],
        global_response_fields: vec![
            "contract_version".to_string(),
            "correlation_id".to_string(),
            "outcome_class".to_string(),
            "screen_id".to_string(),
            "state".to_string(),
        ],
        compatibility: ContractCompatibility {
            minimum_reader_version: SCREEN_ENGINE_CONTRACT_VERSION.to_string(),
            supported_reader_versions: vec![SCREEN_ENGINE_CONTRACT_VERSION.to_string()],
            migration_guidance: vec![MigrationGuidance {
                from_version: "doctor-screen-engine-v0".to_string(),
                to_version: SCREEN_ENGINE_CONTRACT_VERSION.to_string(),
                breaking: false,
                required_actions: vec![
                    "Accept explicit state transition envelopes per screen.".to_string(),
                    "Require correlation_id + rerun_context on every request.".to_string(),
                    "Validate response payload ordering by schema field key.".to_string(),
                ],
            }],
        },
        screens,
        error_envelope: ContractErrorEnvelope {
            required_fields: vec![
                "contract_version".to_string(),
                "correlation_id".to_string(),
                "error_code".to_string(),
                "error_message".to_string(),
                "rerun_context".to_string(),
                "validation_failures".to_string(),
            ],
            retryable_codes: vec![
                "cancelled_request".to_string(),
                "stale_contract_version".to_string(),
                "transient_engine_failure".to_string(),
            ],
        },
    }
}

/// Returns true if the provided reader version is supported by the contract.
#[must_use]
pub fn is_screen_contract_version_supported(
    contract: &ScreenEngineContract,
    reader_version: &str,
) -> bool {
    contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == reader_version)
        && reader_version >= contract.compatibility.minimum_reader_version.as_str()
}

fn validate_field_ordering(fields: &[PayloadField], context: &str) -> Result<(), String> {
    if fields.is_empty() {
        return Err(format!("{context} must declare at least one field"));
    }
    let keys: Vec<_> = fields.iter().map(|field| field.key.clone()).collect();
    if keys.iter().any(|key| key.trim().is_empty()) {
        return Err(format!("{context} has empty field key"));
    }
    let mut deduped = keys.clone();
    deduped.sort();
    deduped.dedup();
    if deduped.len() != keys.len() {
        return Err(format!("{context} field keys must be unique"));
    }
    if deduped != keys {
        return Err(format!("{context} field keys must be lexically sorted"));
    }
    if fields
        .iter()
        .any(|field| field.field_type.trim().is_empty() || field.description.trim().is_empty())
    {
        return Err(format!("{context} has field with empty type/description"));
    }
    Ok(())
}

fn validate_payload_schema(schema: &PayloadSchema, context: &str) -> Result<(), String> {
    if schema.schema_id.trim().is_empty() {
        return Err(format!("{context} schema_id must be non-empty"));
    }
    validate_field_ordering(
        &schema.required_fields,
        &format!("{context} required_fields"),
    )?;
    validate_field_ordering(
        &schema.optional_fields,
        &format!("{context} optional_fields"),
    )?;

    let mut all_keys = schema
        .required_fields
        .iter()
        .map(|field| field.key.clone())
        .collect::<Vec<_>>();
    all_keys.extend(schema.optional_fields.iter().map(|field| field.key.clone()));
    let mut deduped = all_keys.clone();
    deduped.sort();
    deduped.dedup();
    if deduped.len() != all_keys.len() {
        return Err(format!(
            "{context} required/optional field keys must not overlap"
        ));
    }
    Ok(())
}

/// Validates structural invariants for [`ScreenEngineContract`].
///
/// # Errors
///
/// Returns `Err` when schema, transition, or compatibility invariants fail.
#[allow(clippy::too_many_lines)]
pub fn validate_screen_engine_contract(contract: &ScreenEngineContract) -> Result<(), String> {
    if contract.contract_version.trim().is_empty() {
        return Err("contract_version must be non-empty".to_string());
    }
    if contract.operator_model_version.trim().is_empty() {
        return Err("operator_model_version must be non-empty".to_string());
    }
    if contract.screens.is_empty() {
        return Err("screens must be non-empty".to_string());
    }

    let mut request_fields = contract.global_request_fields.clone();
    request_fields.sort();
    request_fields.dedup();
    if request_fields.len() != contract.global_request_fields.len() {
        return Err("global_request_fields must be unique".to_string());
    }
    if request_fields != contract.global_request_fields {
        return Err("global_request_fields must be lexically sorted".to_string());
    }
    let mut response_fields = contract.global_response_fields.clone();
    response_fields.sort();
    response_fields.dedup();
    if response_fields.len() != contract.global_response_fields.len() {
        return Err("global_response_fields must be unique".to_string());
    }
    if response_fields != contract.global_response_fields {
        return Err("global_response_fields must be lexically sorted".to_string());
    }

    if contract
        .compatibility
        .minimum_reader_version
        .trim()
        .is_empty()
    {
        return Err("compatibility minimum_reader_version must be non-empty".to_string());
    }
    if contract.compatibility.supported_reader_versions.is_empty() {
        return Err("compatibility supported_reader_versions must be non-empty".to_string());
    }
    let mut versions = contract.compatibility.supported_reader_versions.clone();
    versions.sort();
    versions.dedup();
    if versions.len() != contract.compatibility.supported_reader_versions.len() {
        return Err("compatibility supported_reader_versions must be unique".to_string());
    }
    if versions != contract.compatibility.supported_reader_versions {
        return Err("compatibility supported_reader_versions must be lexically sorted".to_string());
    }
    if !contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &contract.compatibility.minimum_reader_version)
    {
        return Err(
            "minimum_reader_version must be present in supported_reader_versions".to_string(),
        );
    }
    if contract.compatibility.migration_guidance.is_empty() {
        return Err("compatibility migration_guidance must be non-empty".to_string());
    }
    for entry in &contract.compatibility.migration_guidance {
        if entry.from_version.trim().is_empty() || entry.to_version.trim().is_empty() {
            return Err(
                "migration_guidance entries must define from_version/to_version".to_string(),
            );
        }
        if entry.required_actions.is_empty() {
            return Err(format!(
                "migration guidance {} -> {} must define required_actions",
                entry.from_version, entry.to_version
            ));
        }
    }

    let mut error_required_fields = contract.error_envelope.required_fields.clone();
    error_required_fields.sort();
    error_required_fields.dedup();
    if error_required_fields.len() != contract.error_envelope.required_fields.len() {
        return Err("error_envelope required_fields must be unique".to_string());
    }
    if error_required_fields != contract.error_envelope.required_fields {
        return Err("error_envelope required_fields must be lexically sorted".to_string());
    }
    let mut retryable_codes = contract.error_envelope.retryable_codes.clone();
    retryable_codes.sort();
    retryable_codes.dedup();
    if retryable_codes.len() != contract.error_envelope.retryable_codes.len() {
        return Err("error_envelope retryable_codes must be unique".to_string());
    }
    if retryable_codes != contract.error_envelope.retryable_codes {
        return Err("error_envelope retryable_codes must be lexically sorted".to_string());
    }

    let mut screen_ids = contract
        .screens
        .iter()
        .map(|screen| screen.id.clone())
        .collect::<Vec<_>>();
    let mut sorted_screen_ids = screen_ids.clone();
    sorted_screen_ids.sort();
    sorted_screen_ids.dedup();
    if sorted_screen_ids.len() != screen_ids.len() {
        return Err("screen ids must be unique".to_string());
    }
    if sorted_screen_ids != screen_ids {
        return Err("screen contracts must be ordered lexically by id".to_string());
    }

    for screen in &contract.screens {
        if screen.label.trim().is_empty() {
            return Err(format!("screen {} must define non-empty label", screen.id));
        }
        if screen.personas.is_empty() {
            return Err(format!("screen {} must define personas", screen.id));
        }
        let mut personas = screen.personas.clone();
        personas.sort();
        personas.dedup();
        if personas.len() != screen.personas.len() {
            return Err(format!("screen {} personas must be unique", screen.id));
        }
        if personas != screen.personas {
            return Err(format!(
                "screen {} personas must be lexically sorted",
                screen.id
            ));
        }
        if screen.states.is_empty() {
            return Err(format!("screen {} must define states", screen.id));
        }
        let mut states = screen.states.clone();
        states.sort();
        states.dedup();
        if states.len() != screen.states.len() {
            return Err(format!("screen {} states must be unique", screen.id));
        }
        if states != screen.states {
            return Err(format!(
                "screen {} states must be lexically sorted",
                screen.id
            ));
        }
        if !states.iter().any(|state| state == "idle")
            || !states.iter().any(|state| state == "loading")
        {
            return Err(format!(
                "screen {} must include idle/loading states",
                screen.id
            ));
        }

        validate_payload_schema(
            &screen.request_schema,
            &format!("screen {} request_schema", screen.id),
        )?;
        validate_payload_schema(
            &screen.response_schema,
            &format!("screen {} response_schema", screen.id),
        )?;

        if screen.transitions.is_empty() {
            return Err(format!("screen {} must define transitions", screen.id));
        }
        for transition in &screen.transitions {
            if transition.trigger.trim().is_empty() || transition.outcome.trim().is_empty() {
                return Err(format!(
                    "screen {} transition must define trigger/outcome",
                    screen.id
                ));
            }
            if !states.iter().any(|state| state == &transition.from_state)
                || !states.iter().any(|state| state == &transition.to_state)
            {
                return Err(format!(
                    "screen {} transition {} -> {} references unknown states",
                    screen.id, transition.from_state, transition.to_state
                ));
            }
            if !matches!(
                transition.outcome.as_str(),
                "success" | "cancelled" | "failed"
            ) {
                return Err(format!(
                    "screen {} transition outcome {} is invalid",
                    screen.id, transition.outcome
                ));
            }
        }

        let has_success = screen.transitions.iter().any(|transition| {
            transition.from_state == "loading"
                && transition.to_state == "ready"
                && transition.outcome == "success"
        });
        let has_cancelled = screen.transitions.iter().any(|transition| {
            transition.from_state == "loading"
                && transition.to_state == "cancelled"
                && transition.outcome == "cancelled"
        });
        let has_failed = screen.transitions.iter().any(|transition| {
            transition.from_state == "loading"
                && transition.to_state == "failed"
                && transition.outcome == "failed"
        });
        if !has_success || !has_cancelled || !has_failed {
            return Err(format!(
                "screen {} must include loading transitions for success/cancelled/failed",
                screen.id
            ));
        }
    }
    screen_ids.clear();

    Ok(())
}

fn rejection_log(
    contract: &ScreenEngineContract,
    correlation_id: &str,
    rerun_context: &str,
    mut failures: Vec<String>,
) -> RejectedPayloadLog {
    failures.sort();
    failures.dedup();
    RejectedPayloadLog {
        contract_version: contract.contract_version.clone(),
        correlation_id: correlation_id.to_string(),
        validation_failures: failures,
        rerun_context: rerun_context.to_string(),
    }
}

/// Simulates screen payload exchange and enforces required-field contracts.
///
/// # Errors
///
/// Returns [`RejectedPayloadLog`] if the request does not satisfy the contract.
pub fn simulate_screen_exchange(
    contract: &ScreenEngineContract,
    request: &ScreenExchangeRequest,
) -> Result<ScreenExchangeEnvelope, RejectedPayloadLog> {
    let mut failures = Vec::new();
    if request.screen_id.trim().is_empty() {
        failures.push("screen_id must be non-empty".to_string());
    }
    if request.correlation_id.trim().is_empty() {
        failures.push("correlation_id must be non-empty".to_string());
    }
    if request.rerun_context.trim().is_empty() {
        failures.push("rerun_context must be non-empty".to_string());
    }
    if !is_screen_contract_version_supported(contract, &contract.contract_version) {
        failures.push("contract version is not self-compatible".to_string());
    }

    let Some(screen) = contract
        .screens
        .iter()
        .find(|screen| screen.id == request.screen_id)
    else {
        failures.push(format!("unknown screen id {}", request.screen_id));
        return Err(rejection_log(
            contract,
            &request.correlation_id,
            &request.rerun_context,
            failures,
        ));
    };

    for field in &screen.request_schema.required_fields {
        if !request.payload.contains_key(&field.key) {
            failures.push(format!("missing required request field {}", field.key));
        }
    }
    if !failures.is_empty() {
        return Err(rejection_log(
            contract,
            &request.correlation_id,
            &request.rerun_context,
            failures,
        ));
    }

    let (outcome_class, state) = match request.outcome {
        ExchangeOutcome::Success => ("success".to_string(), "ready".to_string()),
        ExchangeOutcome::Cancelled => ("cancelled".to_string(), "cancelled".to_string()),
        ExchangeOutcome::Failed => ("failed".to_string(), "failed".to_string()),
    };
    let mut response_payload = BTreeMap::new();
    response_payload.insert("confidence_score".to_string(), "1.0".to_string());
    response_payload.insert("findings".to_string(), "[]".to_string());
    response_payload.insert("outcome_class".to_string(), outcome_class.clone());
    response_payload.insert("state".to_string(), state);

    Ok(ScreenExchangeEnvelope {
        contract_version: contract.contract_version.clone(),
        correlation_id: request.correlation_id.clone(),
        screen_id: request.screen_id.clone(),
        outcome_class,
        response_payload,
    })
}

fn next_elapsed_tick(counter: &mut u64) -> u64 {
    let current = *counter;
    *counter = counter.saturating_add(1);
    current
}

fn content_digest(content: &str) -> String {
    let mut weighted_sum: u128 = 0;
    let mut rolling_xor: u8 = 0;
    for (idx, byte) in content.bytes().enumerate() {
        let weight = (idx as u128).saturating_add(1);
        weighted_sum = weighted_sum.saturating_add(weight.saturating_mul(u128::from(byte)));
        rolling_xor ^= byte;
    }
    format!(
        "len:{}:wsum:{}:xor:{rolling_xor:02x}",
        content.len(),
        weighted_sum
    )
}

fn canonical_outcome_class(raw: Option<&str>) -> String {
    match raw.map(str::trim) {
        Some("success") => "success".to_string(),
        Some("cancelled") => "cancelled".to_string(),
        _ => "failed".to_string(),
    }
}

fn json_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn parse_json_artifact(
    run_id: &str,
    artifact: &RuntimeArtifact,
    normalization_rule: &str,
) -> Result<Vec<EvidenceRecord>, String> {
    let parsed: serde_json::Value = serde_json::from_str(&artifact.content)
        .map_err(|err| format!("invalid JSON payload: {err}"))?;
    let Some(obj) = parsed.as_object() else {
        return Err("JSON artifact must be an object".to_string());
    };

    let correlation_id = obj
        .get("correlation_id")
        .and_then(json_value_to_string)
        .or_else(|| obj.get("trace_id").and_then(json_value_to_string))
        .unwrap_or_else(|| format!("{}-correlation", artifact.artifact_id));
    let scenario_id = obj
        .get("scenario_id")
        .and_then(json_value_to_string)
        .unwrap_or_else(|| "unknown_scenario".to_string());
    let seed = obj
        .get("seed")
        .and_then(json_value_to_string)
        .unwrap_or_else(|| "unknown_seed".to_string());
    let summary = obj
        .get("summary")
        .and_then(json_value_to_string)
        .or_else(|| obj.get("message").and_then(json_value_to_string))
        .unwrap_or_else(|| "normalized_json_artifact".to_string());
    let outcome_class = canonical_outcome_class(
        obj.get("outcome_class")
            .and_then(serde_json::Value::as_str)
            .or_else(|| obj.get("outcome").and_then(serde_json::Value::as_str)),
    );

    Ok(vec![EvidenceRecord {
        evidence_id: format!("{run_id}:{}:0000", artifact.artifact_id),
        artifact_id: artifact.artifact_id.clone(),
        artifact_type: artifact.artifact_type.clone(),
        source_path: artifact.source_path.clone(),
        correlation_id,
        scenario_id,
        seed,
        outcome_class,
        summary,
        replay_pointer: artifact.replay_pointer.clone(),
        provenance: EvidenceProvenance {
            normalization_rule: normalization_rule.to_string(),
            source_digest: content_digest(&artifact.content),
        },
    }])
}

fn parse_ubs_artifact(
    run_id: &str,
    artifact: &RuntimeArtifact,
) -> Result<Vec<EvidenceRecord>, String> {
    let findings = artifact
        .content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if findings.is_empty() {
        return Err("UBS artifact contains no findings".to_string());
    }

    Ok(findings
        .into_iter()
        .enumerate()
        .map(|(idx, line)| EvidenceRecord {
            evidence_id: format!("{run_id}:{}:{idx:04}", artifact.artifact_id),
            artifact_id: artifact.artifact_id.clone(),
            artifact_type: artifact.artifact_type.clone(),
            source_path: artifact.source_path.clone(),
            correlation_id: format!("{}-{idx}", artifact.artifact_id),
            scenario_id: "ubs_scan".to_string(),
            seed: "none".to_string(),
            outcome_class: "failed".to_string(),
            summary: line.to_string(),
            replay_pointer: artifact.replay_pointer.clone(),
            provenance: EvidenceProvenance {
                normalization_rule: "ubs_findings_line_normalization_v1".to_string(),
                source_digest: content_digest(&artifact.content),
            },
        })
        .collect())
}

fn parse_benchmark_artifact(
    run_id: &str,
    artifact: &RuntimeArtifact,
) -> Result<Vec<EvidenceRecord>, String> {
    let metrics = artifact
        .content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.split_once('=').map(|(k, v)| (k.trim(), v.trim())))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "benchmark artifact line must be key=value".to_string())?;
    if metrics.is_empty() {
        return Err("benchmark artifact contains no metrics".to_string());
    }

    Ok(metrics
        .into_iter()
        .enumerate()
        .map(|(idx, (metric, value))| EvidenceRecord {
            evidence_id: format!("{run_id}:{}:{idx:04}", artifact.artifact_id),
            artifact_id: artifact.artifact_id.clone(),
            artifact_type: artifact.artifact_type.clone(),
            source_path: artifact.source_path.clone(),
            correlation_id: format!("{}-bench-{idx}", artifact.artifact_id),
            scenario_id: "benchmark".to_string(),
            seed: "none".to_string(),
            outcome_class: "success".to_string(),
            summary: format!("benchmark {metric}={value}"),
            replay_pointer: artifact.replay_pointer.clone(),
            provenance: EvidenceProvenance {
                normalization_rule: "benchmark_kv_normalization_v1".to_string(),
                source_digest: content_digest(&artifact.content),
            },
        })
        .collect())
}

/// Ingests raw runtime artifacts and emits a deterministic evidence report.
///
/// # Errors
///
/// This function does not fail; malformed inputs are emitted in `rejected`.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn ingest_runtime_artifacts(
    run_id: &str,
    artifacts: &[RuntimeArtifact],
) -> EvidenceIngestionReport {
    let normalized_run_id = if run_id.trim().is_empty() {
        "unknown-run".to_string()
    } else {
        run_id.to_string()
    };

    let mut ordered = artifacts.to_vec();
    ordered.sort_by(|left, right| {
        (
            left.artifact_id.as_str(),
            left.artifact_type.as_str(),
            left.source_path.as_str(),
        )
            .cmp(&(
                right.artifact_id.as_str(),
                right.artifact_type.as_str(),
                right.source_path.as_str(),
            ))
    });

    let mut elapsed = 0_u64;
    let mut events = vec![IngestionEvent {
        stage: "ingest_start".to_string(),
        level: "info".to_string(),
        message: format!("starting artifact ingestion: {}", ordered.len()),
        elapsed_ms: next_elapsed_tick(&mut elapsed),
        artifact_id: None,
        replay_pointer: None,
    }];
    let mut records = Vec::new();
    let mut rejected = Vec::new();
    let mut seen_keys = BTreeSet::new();

    for artifact in ordered {
        events.push(IngestionEvent {
            stage: "parse_artifact".to_string(),
            level: "info".to_string(),
            message: format!(
                "parsing {} artifact {}",
                artifact.artifact_type, artifact.artifact_id
            ),
            elapsed_ms: next_elapsed_tick(&mut elapsed),
            artifact_id: Some(artifact.artifact_id.clone()),
            replay_pointer: Some(artifact.replay_pointer.clone()),
        });

        if artifact.artifact_id.trim().is_empty()
            || artifact.artifact_type.trim().is_empty()
            || artifact.source_path.trim().is_empty()
            || artifact.replay_pointer.trim().is_empty()
        {
            let reason = "artifact missing required metadata fields".to_string();
            rejected.push(RejectedArtifact {
                artifact_id: artifact.artifact_id.clone(),
                artifact_type: artifact.artifact_type.clone(),
                source_path: artifact.source_path.clone(),
                replay_pointer: artifact.replay_pointer.clone(),
                reason: reason.clone(),
            });
            events.push(IngestionEvent {
                stage: "reject_artifact".to_string(),
                level: "warn".to_string(),
                message: reason,
                elapsed_ms: next_elapsed_tick(&mut elapsed),
                artifact_id: Some(artifact.artifact_id),
                replay_pointer: Some(artifact.replay_pointer),
            });
            continue;
        }

        let parsed = match artifact.artifact_type.as_str() {
            "trace" => {
                parse_json_artifact(&normalized_run_id, &artifact, "trace_json_normalization_v1")
            }
            "structured_log" => parse_json_artifact(
                &normalized_run_id,
                &artifact,
                "structured_log_json_normalization_v1",
            ),
            "ubs_findings" => parse_ubs_artifact(&normalized_run_id, &artifact),
            "benchmark" => parse_benchmark_artifact(&normalized_run_id, &artifact),
            _ => Err(format!(
                "unsupported artifact type {}",
                artifact.artifact_type
            )),
        };

        match parsed {
            Ok(parsed_records) => {
                for record in parsed_records {
                    let dedupe_key = format!(
                        "{}|{}|{}|{}|{}|{}",
                        record.artifact_type,
                        record.correlation_id,
                        record.scenario_id,
                        record.seed,
                        record.outcome_class,
                        record.summary
                    );
                    if !seen_keys.insert(dedupe_key) {
                        events.push(IngestionEvent {
                            stage: "dedupe_record".to_string(),
                            level: "info".to_string(),
                            message: format!("deduplicated record {}", record.evidence_id),
                            elapsed_ms: next_elapsed_tick(&mut elapsed),
                            artifact_id: Some(record.artifact_id.clone()),
                            replay_pointer: Some(record.replay_pointer.clone()),
                        });
                        continue;
                    }

                    events.push(IngestionEvent {
                        stage: "normalize_record".to_string(),
                        level: "info".to_string(),
                        message: format!("normalized evidence {}", record.evidence_id),
                        elapsed_ms: next_elapsed_tick(&mut elapsed),
                        artifact_id: Some(record.artifact_id.clone()),
                        replay_pointer: Some(record.replay_pointer.clone()),
                    });
                    records.push(record);
                }
            }
            Err(reason) => {
                rejected.push(RejectedArtifact {
                    artifact_id: artifact.artifact_id.clone(),
                    artifact_type: artifact.artifact_type.clone(),
                    source_path: artifact.source_path.clone(),
                    replay_pointer: artifact.replay_pointer.clone(),
                    reason: reason.clone(),
                });
                events.push(IngestionEvent {
                    stage: "reject_artifact".to_string(),
                    level: "warn".to_string(),
                    message: reason,
                    elapsed_ms: next_elapsed_tick(&mut elapsed),
                    artifact_id: Some(artifact.artifact_id),
                    replay_pointer: Some(artifact.replay_pointer),
                });
            }
        }
    }

    records.sort_by(|left, right| {
        (
            left.evidence_id.as_str(),
            left.artifact_id.as_str(),
            left.summary.as_str(),
        )
            .cmp(&(
                right.evidence_id.as_str(),
                right.artifact_id.as_str(),
                right.summary.as_str(),
            ))
    });
    rejected.sort_by(|left, right| {
        (
            left.artifact_id.as_str(),
            left.artifact_type.as_str(),
            left.reason.as_str(),
        )
            .cmp(&(
                right.artifact_id.as_str(),
                right.artifact_type.as_str(),
                right.reason.as_str(),
            ))
    });

    events.push(IngestionEvent {
        stage: "ingest_complete".to_string(),
        level: "info".to_string(),
        message: format!(
            "ingestion complete: records={} rejected={}",
            records.len(),
            rejected.len()
        ),
        elapsed_ms: next_elapsed_tick(&mut elapsed),
        artifact_id: None,
        replay_pointer: None,
    });

    EvidenceIngestionReport {
        schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        run_id: normalized_run_id,
        records,
        rejected,
        events,
    }
}

/// Validates invariants for [`EvidenceIngestionReport`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or metadata invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_evidence_ingestion_report(report: &EvidenceIngestionReport) -> Result<(), String> {
    if report.schema_version != EVIDENCE_SCHEMA_VERSION {
        return Err(format!(
            "unexpected schema_version {}",
            report.schema_version
        ));
    }
    if report.run_id.trim().is_empty() {
        return Err("run_id must be non-empty".to_string());
    }
    if report.events.is_empty() {
        return Err("events must be non-empty".to_string());
    }

    let mut last_elapsed = 0_u64;
    for (index, event) in report.events.iter().enumerate() {
        if event.stage.trim().is_empty() || event.message.trim().is_empty() {
            return Err(format!("event {index} has empty stage/message"));
        }
        if !matches!(event.level.as_str(), "info" | "warn") {
            return Err(format!("event {index} has invalid level {}", event.level));
        }
        if index > 0 && event.elapsed_ms < last_elapsed {
            return Err("event elapsed_ms must be monotonic".to_string());
        }
        last_elapsed = event.elapsed_ms;
    }

    let mut sorted_evidence_ids = report
        .records
        .iter()
        .map(|record| record.evidence_id.clone())
        .collect::<Vec<_>>();
    let mut deduped = sorted_evidence_ids.clone();
    deduped.sort();
    deduped.dedup();
    if deduped.len() != sorted_evidence_ids.len() {
        return Err("record evidence_id values must be unique".to_string());
    }
    if deduped != sorted_evidence_ids {
        return Err("records must be lexically ordered by evidence_id".to_string());
    }

    for record in &report.records {
        if record.artifact_id.trim().is_empty()
            || record.artifact_type.trim().is_empty()
            || record.source_path.trim().is_empty()
            || record.correlation_id.trim().is_empty()
            || record.scenario_id.trim().is_empty()
            || record.seed.trim().is_empty()
            || record.summary.trim().is_empty()
            || record.replay_pointer.trim().is_empty()
        {
            return Err(format!(
                "record {} has empty required fields",
                record.evidence_id
            ));
        }
        if !matches!(
            record.outcome_class.as_str(),
            "success" | "cancelled" | "failed"
        ) {
            return Err(format!(
                "record {} has invalid outcome_class {}",
                record.evidence_id, record.outcome_class
            ));
        }
        if record.provenance.normalization_rule.trim().is_empty()
            || record.provenance.source_digest.trim().is_empty()
        {
            return Err(format!(
                "record {} has empty provenance fields",
                record.evidence_id
            ));
        }
    }

    let mut rejected_keys = report
        .rejected
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}|{}|{}",
                entry.artifact_id,
                entry.artifact_type,
                entry.source_path,
                entry.replay_pointer,
                entry.reason
            )
        })
        .collect::<Vec<_>>();
    let mut sorted_rejected = rejected_keys.clone();
    sorted_rejected.sort();
    if sorted_rejected != rejected_keys {
        return Err("rejected entries must be lexically ordered".to_string());
    }
    for entry in &report.rejected {
        if entry.artifact_id.trim().is_empty()
            || entry.artifact_type.trim().is_empty()
            || entry.source_path.trim().is_empty()
            || entry.replay_pointer.trim().is_empty()
            || entry.reason.trim().is_empty()
        {
            return Err("rejected entry has empty required fields".to_string());
        }
    }

    sorted_evidence_ids.clear();
    rejected_keys.clear();

    Ok(())
}

fn validate_lexical_string_set(values: &[String], context: &str) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{context} must be non-empty"));
    }
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{context} must not contain empty values"));
    }
    let mut deduped = values.to_vec();
    deduped.sort();
    deduped.dedup();
    if deduped.len() != values.len() {
        return Err(format!("{context} must be unique"));
    }
    if deduped != values {
        return Err(format!("{context} must be lexically sorted"));
    }
    Ok(())
}

fn is_slug_like(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '-' | '_' | '.' | ':' | '/')
        })
}

fn validate_field_format(
    field: &LoggingFieldSpec,
    value: &str,
    allowed_outcomes: &[String],
) -> Result<(), String> {
    match field.key.as_str() {
        "run_id" => {
            if !value.starts_with("run-") || !is_slug_like(value) {
                return Err("run_id must match run-* slug format".to_string());
            }
        }
        "scenario_id" => {
            if !is_slug_like(value) {
                return Err("scenario_id must be a slug-like identifier".to_string());
            }
        }
        "trace_id" => {
            if !value.starts_with("trace-") || !is_slug_like(value) {
                return Err("trace_id must match trace-* slug format".to_string());
            }
        }
        "command_provenance" => {
            if value.contains('\n') || value.contains('\r') {
                return Err("command_provenance must be a single-line command".to_string());
            }
        }
        "outcome_class" => {
            if !allowed_outcomes.iter().any(|candidate| candidate == value) {
                return Err(format!("outcome_class {value} is not supported"));
            }
        }
        _ => {}
    }
    Ok(())
}

/// Returns the canonical baseline structured-logging contract for doctor flows.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn structured_logging_contract() -> StructuredLoggingContract {
    let envelope_required_fields = vec![
        LoggingFieldSpec {
            key: "artifact_pointer".to_string(),
            field_type: "string".to_string(),
            format_rule: "non-empty pointer to deterministic artifact".to_string(),
            description: "Artifact path or pointer used for replay/audit.".to_string(),
        },
        LoggingFieldSpec {
            key: "command_provenance".to_string(),
            field_type: "string".to_string(),
            format_rule: "single-line shell command".to_string(),
            description: "Exact command provenance used to produce this event.".to_string(),
        },
        LoggingFieldSpec {
            key: "flow_id".to_string(),
            field_type: "enum".to_string(),
            format_rule: "execution|integration|remediation|replay".to_string(),
            description: "Core workflow lane emitting this event.".to_string(),
        },
        LoggingFieldSpec {
            key: "outcome_class".to_string(),
            field_type: "enum".to_string(),
            format_rule: "cancelled|failed|success".to_string(),
            description: "Normalized event outcome class.".to_string(),
        },
        LoggingFieldSpec {
            key: "run_id".to_string(),
            field_type: "string".to_string(),
            format_rule: "run-[a-z0-9._:/-]+".to_string(),
            description: "Deterministic run identifier.".to_string(),
        },
        LoggingFieldSpec {
            key: "scenario_id".to_string(),
            field_type: "string".to_string(),
            format_rule: "[a-z0-9._:/-]+".to_string(),
            description: "Scenario identifier for replay grouping.".to_string(),
        },
        LoggingFieldSpec {
            key: "trace_id".to_string(),
            field_type: "string".to_string(),
            format_rule: "trace-[a-z0-9._:/-]+".to_string(),
            description: "Trace identifier for deterministic replay joins.".to_string(),
        },
    ];

    let correlation_primitives = vec![
        CorrelationPrimitiveSpec {
            key: "command_provenance".to_string(),
            format_rule: "single-line shell command".to_string(),
            purpose: "Reconstruct exact command lineage for reproduction.".to_string(),
        },
        CorrelationPrimitiveSpec {
            key: "outcome_class".to_string(),
            format_rule: "cancelled|failed|success".to_string(),
            purpose: "Normalize cross-flow success/failure semantics.".to_string(),
        },
        CorrelationPrimitiveSpec {
            key: "run_id".to_string(),
            format_rule: "run-[a-z0-9._:/-]+".to_string(),
            purpose: "Join all events emitted by one deterministic run.".to_string(),
        },
        CorrelationPrimitiveSpec {
            key: "scenario_id".to_string(),
            format_rule: "[a-z0-9._:/-]+".to_string(),
            purpose: "Join events by scenario family and replay fixture.".to_string(),
        },
        CorrelationPrimitiveSpec {
            key: "trace_id".to_string(),
            format_rule: "trace-[a-z0-9._:/-]+".to_string(),
            purpose: "Join events with trace/replay artifacts.".to_string(),
        },
    ];

    let common_required = vec![
        "artifact_pointer".to_string(),
        "command_provenance".to_string(),
        "flow_id".to_string(),
        "outcome_class".to_string(),
        "run_id".to_string(),
        "scenario_id".to_string(),
        "trace_id".to_string(),
    ];

    let core_flows = vec![
        LoggingFlowSpec {
            flow_id: "execution".to_string(),
            description: "Build/test/lint execution telemetry.".to_string(),
            required_fields: common_required.clone(),
            optional_fields: vec!["gate_name".to_string(), "worker_route".to_string()],
            event_kinds: vec![
                "command_complete".to_string(),
                "command_start".to_string(),
                "verification_summary".to_string(),
            ],
        },
        LoggingFlowSpec {
            flow_id: "integration".to_string(),
            description: "Cross-system integration adapter telemetry.".to_string(),
            required_fields: common_required.clone(),
            optional_fields: vec!["integration_target".to_string(), "retry_count".to_string()],
            event_kinds: vec![
                "integration_error".to_string(),
                "integration_sync".to_string(),
                "verification_summary".to_string(),
            ],
        },
        LoggingFlowSpec {
            flow_id: "remediation".to_string(),
            description: "Guided remediation and verify-after-change telemetry.".to_string(),
            required_fields: common_required.clone(),
            optional_fields: vec!["finding_id".to_string(), "risk_score".to_string()],
            event_kinds: vec![
                "remediation_apply".to_string(),
                "remediation_verify".to_string(),
                "verification_summary".to_string(),
            ],
        },
        LoggingFlowSpec {
            flow_id: "replay".to_string(),
            description: "Replay and determinism verification telemetry.".to_string(),
            required_fields: common_required,
            optional_fields: vec!["replay_pointer".to_string(), "seed".to_string()],
            event_kinds: vec![
                "replay_complete".to_string(),
                "replay_start".to_string(),
                "verification_summary".to_string(),
            ],
        },
    ];

    StructuredLoggingContract {
        contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        envelope_required_fields,
        correlation_primitives,
        outcome_classes: vec![
            "cancelled".to_string(),
            "failed".to_string(),
            "success".to_string(),
        ],
        core_flows,
        event_taxonomy: vec![
            "command_complete".to_string(),
            "command_start".to_string(),
            "integration_error".to_string(),
            "integration_sync".to_string(),
            "remediation_apply".to_string(),
            "remediation_verify".to_string(),
            "replay_complete".to_string(),
            "replay_start".to_string(),
            "verification_summary".to_string(),
        ],
        compatibility: ContractCompatibility {
            minimum_reader_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
            supported_reader_versions: vec![STRUCTURED_LOGGING_CONTRACT_VERSION.to_string()],
            migration_guidance: vec![MigrationGuidance {
                from_version: "doctor-logging-v0".to_string(),
                to_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
                breaking: false,
                required_actions: vec![
                    "Attach command_provenance to every event envelope.".to_string(),
                    "Emit normalized outcome_class for every core-flow event.".to_string(),
                    "Fail validation when required correlation primitives are missing.".to_string(),
                ],
            }],
        },
    }
}

/// Validates invariants for [`StructuredLoggingContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or compatibility invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_structured_logging_contract(
    contract: &StructuredLoggingContract,
) -> Result<(), String> {
    if contract.contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.envelope_required_fields.is_empty() {
        return Err("envelope_required_fields must be non-empty".to_string());
    }

    let envelope_keys = contract
        .envelope_required_fields
        .iter()
        .map(|field| field.key.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&envelope_keys, "envelope_required_fields keys")?;
    for field in &contract.envelope_required_fields {
        if field.field_type.trim().is_empty()
            || field.format_rule.trim().is_empty()
            || field.description.trim().is_empty()
        {
            return Err(format!(
                "envelope field {} must define type/format_rule/description",
                field.key
            ));
        }
    }

    let primitive_keys = contract
        .correlation_primitives
        .iter()
        .map(|primitive| primitive.key.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&primitive_keys, "correlation_primitives keys")?;
    for primitive in &contract.correlation_primitives {
        if primitive.format_rule.trim().is_empty() || primitive.purpose.trim().is_empty() {
            return Err(format!(
                "correlation primitive {} must define format_rule/purpose",
                primitive.key
            ));
        }
        if !envelope_keys.contains(&primitive.key) {
            return Err(format!(
                "correlation primitive {} missing from envelope_required_fields",
                primitive.key
            ));
        }
    }

    validate_lexical_string_set(&contract.outcome_classes, "outcome_classes")?;
    for required in ["cancelled", "failed", "success"] {
        if !contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == required)
        {
            return Err(format!("outcome_classes missing required value {required}"));
        }
    }
    validate_lexical_string_set(&contract.event_taxonomy, "event_taxonomy")?;

    if contract.core_flows.is_empty() {
        return Err("core_flows must be non-empty".to_string());
    }
    let flow_ids = contract
        .core_flows
        .iter()
        .map(|flow| flow.flow_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&flow_ids, "core_flows flow_id")?;
    for required in ["execution", "integration", "remediation", "replay"] {
        if !flow_ids.iter().any(|flow_id| flow_id == required) {
            return Err(format!("core_flows missing required flow {required}"));
        }
    }

    for flow in &contract.core_flows {
        if flow.description.trim().is_empty() {
            return Err(format!("flow {} has empty description", flow.flow_id));
        }
        validate_lexical_string_set(
            &flow.required_fields,
            &format!("flow {} required_fields", flow.flow_id),
        )?;
        validate_lexical_string_set(
            &flow.optional_fields,
            &format!("flow {} optional_fields", flow.flow_id),
        )?;
        validate_lexical_string_set(
            &flow.event_kinds,
            &format!("flow {} event_kinds", flow.flow_id),
        )?;

        for key in &flow.required_fields {
            if !envelope_keys.contains(key) {
                return Err(format!(
                    "flow {} requires unknown envelope key {}",
                    flow.flow_id, key
                ));
            }
        }
        for key in &flow.optional_fields {
            if flow.required_fields.iter().any(|required| required == key) {
                return Err(format!(
                    "flow {} optional field {} must not overlap required fields",
                    flow.flow_id, key
                ));
            }
        }
        for kind in &flow.event_kinds {
            if !contract.event_taxonomy.iter().any(|event| event == kind) {
                return Err(format!(
                    "flow {} uses event kind {} outside event_taxonomy",
                    flow.flow_id, kind
                ));
            }
        }
        for primitive in &contract.correlation_primitives {
            if !flow
                .required_fields
                .iter()
                .any(|required| required == &primitive.key)
            {
                return Err(format!(
                    "flow {} must require primitive {}",
                    flow.flow_id, primitive.key
                ));
            }
        }
    }

    if contract
        .compatibility
        .minimum_reader_version
        .trim()
        .is_empty()
    {
        return Err("compatibility.minimum_reader_version must be non-empty".to_string());
    }
    validate_lexical_string_set(
        &contract.compatibility.supported_reader_versions,
        "compatibility.supported_reader_versions",
    )?;
    if !contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &contract.compatibility.minimum_reader_version)
    {
        return Err("minimum_reader_version missing from supported_reader_versions".to_string());
    }
    for (index, guidance) in contract.compatibility.migration_guidance.iter().enumerate() {
        if guidance.from_version.trim().is_empty() || guidance.to_version.trim().is_empty() {
            return Err(format!(
                "migration_guidance[{index}] has empty from/to version"
            ));
        }
        validate_lexical_string_set(
            &guidance.required_actions,
            &format!("migration_guidance[{index}].required_actions"),
        )?;
    }

    Ok(())
}

/// Emits one normalized event and enforces required field presence/format rules.
///
/// # Errors
///
/// Returns `Err` when field presence, formatting, or taxonomy checks fail.
pub fn emit_structured_log_event(
    contract: &StructuredLoggingContract,
    flow_id: &str,
    event_kind: &str,
    fields: &BTreeMap<String, String>,
) -> Result<StructuredLogEvent, String> {
    validate_structured_logging_contract(contract)?;

    let flow = contract
        .core_flows
        .iter()
        .find(|candidate| candidate.flow_id == flow_id)
        .ok_or_else(|| format!("unknown flow_id {flow_id}"))?;
    if !flow.event_kinds.iter().any(|kind| kind == event_kind) {
        return Err(format!(
            "event_kind {event_kind} is not allowed for flow {flow_id}"
        ));
    }

    if !contract
        .event_taxonomy
        .iter()
        .any(|kind| kind == event_kind)
    {
        return Err(format!(
            "event_kind {event_kind} missing from event_taxonomy"
        ));
    }

    let mut normalized_fields = BTreeMap::new();
    for (key, value) in fields {
        normalized_fields.insert(key.clone(), value.trim().to_string());
    }

    for required in &flow.required_fields {
        let value = normalized_fields
            .get(required)
            .ok_or_else(|| format!("missing required field {required}"))?;
        if value.is_empty() {
            return Err(format!("required field {required} must be non-empty"));
        }
    }

    for spec in &contract.envelope_required_fields {
        let value = normalized_fields
            .get(&spec.key)
            .ok_or_else(|| format!("missing required envelope field {}", spec.key))?;
        if value.is_empty() {
            return Err(format!(
                "required envelope field {} must be non-empty",
                spec.key
            ));
        }
        validate_field_format(spec, value, &contract.outcome_classes).map_err(|reason| {
            format!(
                "invalid field format for {}: {} (rule: {})",
                spec.key, reason, spec.format_rule
            )
        })?;
    }

    if normalized_fields
        .get("flow_id")
        .is_some_and(|value| value != flow_id)
    {
        return Err(format!(
            "flow_id field value must match flow argument ({flow_id})"
        ));
    }

    Ok(StructuredLogEvent {
        contract_version: contract.contract_version.clone(),
        flow_id: flow_id.to_string(),
        event_kind: event_kind.to_string(),
        fields: normalized_fields,
    })
}

/// Validates one previously emitted [`StructuredLogEvent`].
///
/// # Errors
///
/// Returns `Err` when the event does not satisfy contract invariants.
pub fn validate_structured_log_event(
    contract: &StructuredLoggingContract,
    event: &StructuredLogEvent,
) -> Result<(), String> {
    if event.contract_version != contract.contract_version {
        return Err(format!(
            "event contract_version {} does not match {}",
            event.contract_version, contract.contract_version
        ));
    }
    let normalized =
        emit_structured_log_event(contract, &event.flow_id, &event.event_kind, &event.fields)?;
    if normalized.fields != event.fields {
        return Err("event fields are not deterministically normalized".to_string());
    }
    Ok(())
}

/// Emits deterministic smoke events for execution/replay/remediation/integration flows.
///
/// # Errors
///
/// Returns `Err` when any event fails contract validation.
pub fn run_structured_logging_smoke(
    contract: &StructuredLoggingContract,
    run_id: &str,
) -> Result<Vec<StructuredLogEvent>, String> {
    let normalized_run_id = if run_id.trim().is_empty() {
        "run-smoke".to_string()
    } else {
        run_id.trim().to_string()
    };
    let trace_suffix = normalized_run_id
        .strip_prefix("run-")
        .unwrap_or(&normalized_run_id);

    let mut events = Vec::new();
    for flow in &contract.core_flows {
        for kind in &flow.event_kinds {
            let outcome = if kind.ends_with("_error") {
                "failed".to_string()
            } else if kind.contains("cancel") {
                "cancelled".to_string()
            } else {
                "success".to_string()
            };

            let mut fields = BTreeMap::new();
            fields.insert(
                "artifact_pointer".to_string(),
                format!("artifacts/{normalized_run_id}/{}/{kind}.json", flow.flow_id),
            );
            fields.insert(
                "command_provenance".to_string(),
                format!(
                    "rch exec -- cargo test -p asupersync -- doctor-{}-smoke",
                    flow.flow_id
                ),
            );
            fields.insert("flow_id".to_string(), flow.flow_id.clone());
            fields.insert("outcome_class".to_string(), outcome);
            fields.insert("run_id".to_string(), normalized_run_id.clone());
            fields.insert(
                "scenario_id".to_string(),
                format!("doctor-{}-smoke", flow.flow_id),
            );
            fields.insert(
                "trace_id".to_string(),
                format!("trace-{trace_suffix}-{}", flow.flow_id),
            );

            let event = emit_structured_log_event(contract, &flow.flow_id, kind, &fields)?;
            events.push(event);
        }
    }

    events.sort_by(|left, right| {
        (
            left.flow_id.as_str(),
            left.event_kind.as_str(),
            left.fields
                .get("trace_id")
                .map(String::as_str)
                .unwrap_or_default(),
        )
            .cmp(&(
                right.flow_id.as_str(),
                right.event_kind.as_str(),
                right
                    .fields
                    .get("trace_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ))
    });

    Ok(events)
}

/// Validates a stream of structured log events and ordering guarantees.
///
/// # Errors
///
/// Returns `Err` when stream ordering or field invariants are violated.
pub fn validate_structured_logging_event_stream(
    contract: &StructuredLoggingContract,
    events: &[StructuredLogEvent],
) -> Result<(), String> {
    if events.is_empty() {
        return Err("events must be non-empty".to_string());
    }

    let mut last_key: Option<(String, String, String)> = None;
    for event in events {
        validate_structured_log_event(contract, event)?;

        let ordering_key = (
            event.flow_id.clone(),
            event.event_kind.clone(),
            event.fields.get("trace_id").cloned().unwrap_or_default(),
        );
        if let Some(previous) = &last_key
            && ordering_key < *previous
        {
            return Err(
                "events must be lexically ordered by flow_id/event_kind/trace_id".to_string(),
            );
        }
        last_key = Some(ordering_key);
    }

    Ok(())
}

/// Returns the canonical remediation-recipe DSL contract.
#[must_use]
pub fn remediation_recipe_contract() -> RemediationRecipeContract {
    RemediationRecipeContract {
        contract_version: REMEDIATION_RECIPE_CONTRACT_VERSION.to_string(),
        logging_contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        required_recipe_fields: vec![
            "confidence_inputs".to_string(),
            "finding_id".to_string(),
            "fix_intent".to_string(),
            "preconditions".to_string(),
            "recipe_id".to_string(),
            "rollback".to_string(),
        ],
        required_precondition_fields: vec![
            "evidence_ref".to_string(),
            "expected_value".to_string(),
            "key".to_string(),
            "predicate".to_string(),
            "required".to_string(),
        ],
        required_rollback_fields: vec![
            "rollback_command".to_string(),
            "strategy".to_string(),
            "timeout_secs".to_string(),
            "verify_command".to_string(),
        ],
        required_confidence_input_fields: vec![
            "evidence_ref".to_string(),
            "key".to_string(),
            "rationale".to_string(),
            "score".to_string(),
        ],
        allowed_fix_intents: vec![
            "add_cancellation_checkpoint".to_string(),
            "adjust_timeout_budget".to_string(),
            "enforce_lock_order".to_string(),
            "harden_retry_backoff".to_string(),
            "reduce_lock_scope".to_string(),
        ],
        allowed_precondition_predicates: vec![
            "contains".to_string(),
            "eq".to_string(),
            "exists".to_string(),
            "gte".to_string(),
            "lte".to_string(),
        ],
        allowed_rollback_strategies: vec![
            "git_apply_reverse_patch".to_string(),
            "replay_last_green_artifact".to_string(),
            "restore_backup_snapshot".to_string(),
        ],
        confidence_weights: vec![
            RemediationConfidenceWeight {
                key: "analyzer_confidence".to_string(),
                weight_bps: 3_200,
                rationale: "Confidence reported by analyzer or invariant oracle.".to_string(),
            },
            RemediationConfidenceWeight {
                key: "blast_radius".to_string(),
                weight_bps: 2_400,
                rationale: "Estimated change-surface containment (higher is narrower)."
                    .to_string(),
            },
            RemediationConfidenceWeight {
                key: "replay_reproducibility".to_string(),
                weight_bps: 2_200,
                rationale: "Deterministic replay confidence for this finding.".to_string(),
            },
            RemediationConfidenceWeight {
                key: "test_coverage_delta".to_string(),
                weight_bps: 2_200,
                rationale: "Coverage confidence that the recipe is regression-safe.".to_string(),
            },
        ],
        risk_bands: vec![
            RemediationRiskBand {
                band_id: "critical_risk".to_string(),
                min_score_inclusive: 0,
                max_score_inclusive: 39,
                requires_human_approval: true,
                allow_auto_apply: false,
            },
            RemediationRiskBand {
                band_id: "elevated_risk".to_string(),
                min_score_inclusive: 40,
                max_score_inclusive: 69,
                requires_human_approval: true,
                allow_auto_apply: false,
            },
            RemediationRiskBand {
                band_id: "guarded_auto_apply".to_string(),
                min_score_inclusive: 70,
                max_score_inclusive: 84,
                requires_human_approval: false,
                allow_auto_apply: true,
            },
            RemediationRiskBand {
                band_id: "trusted_auto_apply".to_string(),
                min_score_inclusive: 85,
                max_score_inclusive: 100,
                requires_human_approval: false,
                allow_auto_apply: true,
            },
        ],
        compatibility: ContractCompatibility {
            minimum_reader_version: REMEDIATION_RECIPE_CONTRACT_VERSION.to_string(),
            supported_reader_versions: vec![REMEDIATION_RECIPE_CONTRACT_VERSION.to_string()],
            migration_guidance: vec![MigrationGuidance {
                from_version: "doctor-remediation-recipe-v0".to_string(),
                to_version: REMEDIATION_RECIPE_CONTRACT_VERSION.to_string(),
                breaking: false,
                required_actions: vec![
                    "Fail recipe parsing when fix_intent/predicate/rollback strategy are outside allowlists.".to_string(),
                    "Require confidence input weights to sum to exactly 10_000 bps.".to_string(),
                    "Validate lexical ordering for all deterministic array fields.".to_string(),
                ],
            }],
        },
    }
}

/// Validates invariants for [`RemediationRecipeContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or compatibility invariants are violated.
pub fn validate_remediation_recipe_contract(
    contract: &RemediationRecipeContract,
) -> Result<(), String> {
    if contract.contract_version != REMEDIATION_RECIPE_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.logging_contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected logging_contract_version {}",
            contract.logging_contract_version
        ));
    }
    validate_lexical_string_set(&contract.required_recipe_fields, "required_recipe_fields")?;
    validate_lexical_string_set(
        &contract.required_precondition_fields,
        "required_precondition_fields",
    )?;
    validate_lexical_string_set(
        &contract.required_rollback_fields,
        "required_rollback_fields",
    )?;
    validate_lexical_string_set(
        &contract.required_confidence_input_fields,
        "required_confidence_input_fields",
    )?;
    validate_lexical_string_set(&contract.allowed_fix_intents, "allowed_fix_intents")?;
    validate_lexical_string_set(
        &contract.allowed_precondition_predicates,
        "allowed_precondition_predicates",
    )?;
    validate_lexical_string_set(
        &contract.allowed_rollback_strategies,
        "allowed_rollback_strategies",
    )?;
    for required in [
        "confidence_inputs",
        "finding_id",
        "fix_intent",
        "preconditions",
        "recipe_id",
        "rollback",
    ] {
        if !contract
            .required_recipe_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_recipe_fields missing {required}"));
        }
    }

    if contract.confidence_weights.is_empty() {
        return Err("confidence_weights must be non-empty".to_string());
    }
    let weight_keys = contract
        .confidence_weights
        .iter()
        .map(|weight| weight.key.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&weight_keys, "confidence_weights.key")?;
    let mut total_weight_bps: u32 = 0;
    for weight in &contract.confidence_weights {
        if weight.rationale.trim().is_empty() {
            return Err(format!(
                "confidence weight {} must include rationale",
                weight.key
            ));
        }
        if weight.weight_bps == 0 {
            return Err(format!(
                "confidence weight {} must have non-zero weight_bps",
                weight.key
            ));
        }
        total_weight_bps = total_weight_bps.saturating_add(u32::from(weight.weight_bps));
    }
    if total_weight_bps != 10_000 {
        return Err(format!(
            "confidence_weights must sum to 10000 bps (got {total_weight_bps})"
        ));
    }

    if contract.risk_bands.is_empty() {
        return Err("risk_bands must be non-empty".to_string());
    }
    let band_ids = contract
        .risk_bands
        .iter()
        .map(|band| band.band_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&band_ids, "risk_bands.band_id")?;
    let mut ordered_ranges = contract
        .risk_bands
        .iter()
        .map(|band| (band.min_score_inclusive, band.max_score_inclusive))
        .collect::<Vec<_>>();
    ordered_ranges.sort();
    let mut cursor = 0u8;
    for (min_score, max_score) in ordered_ranges {
        if min_score > max_score {
            return Err("risk band has min_score_inclusive > max_score_inclusive".to_string());
        }
        if min_score != cursor {
            return Err("risk_bands must cover 0..=100 without gaps".to_string());
        }
        cursor = max_score.saturating_add(1);
    }
    if cursor != 101 {
        return Err("risk_bands must end at max score 100".to_string());
    }

    if contract
        .compatibility
        .minimum_reader_version
        .trim()
        .is_empty()
    {
        return Err("compatibility.minimum_reader_version must be non-empty".to_string());
    }
    validate_lexical_string_set(
        &contract.compatibility.supported_reader_versions,
        "compatibility.supported_reader_versions",
    )?;
    if !contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &contract.compatibility.minimum_reader_version)
    {
        return Err("minimum_reader_version missing from supported_reader_versions".to_string());
    }
    for (index, guidance) in contract.compatibility.migration_guidance.iter().enumerate() {
        if guidance.from_version.trim().is_empty() || guidance.to_version.trim().is_empty() {
            return Err(format!(
                "migration_guidance[{index}] has empty from/to version"
            ));
        }
        validate_lexical_string_set(
            &guidance.required_actions,
            &format!("migration_guidance[{index}].required_actions"),
        )?;
    }

    Ok(())
}

/// Validates one remediation recipe against the canonical DSL contract.
///
/// # Errors
///
/// Returns `Err` when recipe content violates deterministic DSL invariants.
pub fn validate_remediation_recipe(
    contract: &RemediationRecipeContract,
    recipe: &RemediationRecipe,
) -> Result<(), String> {
    validate_remediation_recipe_contract(contract)?;

    if !recipe.recipe_id.starts_with("recipe-") || !is_slug_like(&recipe.recipe_id) {
        return Err("recipe_id must match recipe-* slug format".to_string());
    }
    if recipe.finding_id.trim().is_empty() {
        return Err("finding_id must be non-empty".to_string());
    }
    if !contract
        .allowed_fix_intents
        .iter()
        .any(|candidate| candidate == &recipe.fix_intent)
    {
        return Err(format!("unsupported fix_intent {}", recipe.fix_intent));
    }
    if recipe.preconditions.is_empty() {
        return Err("preconditions must be non-empty".to_string());
    }
    let precondition_keys = recipe
        .preconditions
        .iter()
        .map(|precondition| precondition.key.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&precondition_keys, "recipe.preconditions.key")?;
    for precondition in &recipe.preconditions {
        if !contract
            .allowed_precondition_predicates
            .iter()
            .any(|predicate| predicate == &precondition.predicate)
        {
            return Err(format!(
                "unsupported precondition predicate {}",
                precondition.predicate
            ));
        }
        if precondition.expected_value.trim().is_empty() {
            return Err(format!(
                "precondition {} expected_value must be non-empty",
                precondition.key
            ));
        }
        if precondition.required && precondition.evidence_ref.trim().is_empty() {
            return Err(format!(
                "required precondition {} must include evidence_ref",
                precondition.key
            ));
        }
    }

    if !contract
        .allowed_rollback_strategies
        .iter()
        .any(|strategy| strategy == &recipe.rollback.strategy)
    {
        return Err(format!(
            "unsupported rollback strategy {}",
            recipe.rollback.strategy
        ));
    }
    if recipe.rollback.rollback_command.trim().is_empty()
        || recipe.rollback.verify_command.trim().is_empty()
    {
        return Err("rollback commands must be non-empty".to_string());
    }
    if recipe.rollback.rollback_command.contains('\n')
        || recipe.rollback.rollback_command.contains('\r')
        || recipe.rollback.verify_command.contains('\n')
        || recipe.rollback.verify_command.contains('\r')
    {
        return Err("rollback commands must be single-line command strings".to_string());
    }
    if recipe.rollback.timeout_secs == 0 {
        return Err("rollback timeout_secs must be > 0".to_string());
    }

    if recipe.confidence_inputs.is_empty() {
        return Err("confidence_inputs must be non-empty".to_string());
    }
    let input_keys = recipe
        .confidence_inputs
        .iter()
        .map(|input| input.key.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&input_keys, "recipe.confidence_inputs.key")?;
    let weight_keys = contract
        .confidence_weights
        .iter()
        .map(|weight| weight.key.clone())
        .collect::<BTreeSet<_>>();
    for input in &recipe.confidence_inputs {
        if !weight_keys.contains(&input.key) {
            return Err(format!(
                "confidence input {} missing from contract weights",
                input.key
            ));
        }
        if input.score > 100 {
            return Err(format!(
                "confidence input {} score {} must be <= 100",
                input.key, input.score
            ));
        }
        if input.rationale.trim().is_empty() {
            return Err(format!(
                "confidence input {} must include rationale",
                input.key
            ));
        }
        if input.evidence_ref.trim().is_empty() {
            return Err(format!(
                "confidence input {} must include evidence_ref",
                input.key
            ));
        }
    }
    for required_weight in &weight_keys {
        if !input_keys
            .iter()
            .any(|input_key| input_key == required_weight)
        {
            return Err(format!(
                "missing confidence input for required weight {required_weight}"
            ));
        }
    }
    if let Some(override_justification) = &recipe.override_justification
        && override_justification.trim().is_empty()
    {
        return Err("override_justification must be non-empty when provided".to_string());
    }

    Ok(())
}

/// Parses one remediation recipe JSON payload and validates it against contract invariants.
///
/// # Errors
///
/// Returns `Err` when deserialization or validation fails.
pub fn parse_remediation_recipe(
    contract: &RemediationRecipeContract,
    payload: &str,
) -> Result<RemediationRecipe, String> {
    let recipe: RemediationRecipe = serde_json::from_str(payload)
        .map_err(|err| format!("invalid remediation recipe JSON: {err}"))?;
    validate_remediation_recipe(contract, &recipe)?;
    Ok(recipe)
}

/// Computes deterministic confidence score for one remediation recipe.
///
/// # Errors
///
/// Returns `Err` when recipe validation fails or risk-band mapping is invalid.
pub fn compute_remediation_confidence_score(
    contract: &RemediationRecipeContract,
    recipe: &RemediationRecipe,
) -> Result<RemediationConfidenceScore, String> {
    validate_remediation_recipe(contract, recipe)?;

    let input_scores = recipe
        .confidence_inputs
        .iter()
        .map(|input| (input.key.clone(), input.score))
        .collect::<BTreeMap<_, _>>();
    let mut total: u32 = 0;
    let mut weighted_contributions = Vec::new();
    for weight in &contract.confidence_weights {
        let score = input_scores
            .get(&weight.key)
            .copied()
            .ok_or_else(|| format!("missing confidence input {}", weight.key))?;
        let contribution = u32::from(score) * u32::from(weight.weight_bps);
        total = total.saturating_add(contribution);
        weighted_contributions.push(format!(
            "{}={}*{}bps/10000",
            weight.key, score, weight.weight_bps
        ));
    }

    let confidence_score = u8::try_from(total / 10_000).map_err(|_| {
        "computed confidence score exceeded u8 bounds; check weight configuration".to_string()
    })?;

    let mut sorted_bands = contract.risk_bands.clone();
    sorted_bands.sort_by_key(|band| band.min_score_inclusive);
    let band = sorted_bands
        .iter()
        .find(|candidate| {
            confidence_score >= candidate.min_score_inclusive
                && confidence_score <= candidate.max_score_inclusive
        })
        .ok_or_else(|| format!("no risk band covers confidence score {}", confidence_score))?;

    Ok(RemediationConfidenceScore {
        recipe_id: recipe.recipe_id.clone(),
        confidence_score,
        risk_band: band.band_id.clone(),
        requires_human_approval: band.requires_human_approval,
        allow_auto_apply: band.allow_auto_apply && recipe.override_justification.is_none(),
        weighted_contributions,
    })
}

/// Returns deterministic fixtures for remediation recipe validation/scoring.
#[must_use]
pub fn remediation_recipe_fixtures() -> Vec<RemediationRecipeFixture> {
    vec![
        RemediationRecipeFixture {
            fixture_id: "fixture-guarded-auto-apply".to_string(),
            description: "High-confidence lock-order fix with deterministic rollback.".to_string(),
            recipe: RemediationRecipe {
                recipe_id: "recipe-lock-order-001".to_string(),
                finding_id: "doctor-lock-contention:src/runtime/state.rs:critical".to_string(),
                fix_intent: "enforce_lock_order".to_string(),
                preconditions: vec![
                    RemediationPrecondition {
                        key: "lock_order_violation_present".to_string(),
                        predicate: "eq".to_string(),
                        expected_value: "true".to_string(),
                        evidence_ref: "evidence-lock-001".to_string(),
                        required: true,
                    },
                    RemediationPrecondition {
                        key: "repro_seed_available".to_string(),
                        predicate: "exists".to_string(),
                        expected_value: "true".to_string(),
                        evidence_ref: "evidence-seed-001".to_string(),
                        required: true,
                    },
                ],
                rollback: RemediationRollbackPlan {
                    strategy: "git_apply_reverse_patch".to_string(),
                    rollback_command: "git apply -R artifacts/run-lock/patch.diff".to_string(),
                    verify_command:
                        "rch exec -- cargo test --lib cli::doctor::tests::lock_order_smoke"
                            .to_string(),
                    timeout_secs: 120,
                },
                confidence_inputs: vec![
                    RemediationConfidenceInput {
                        key: "analyzer_confidence".to_string(),
                        score: 86,
                        rationale: "Invariant analyzer reported high confidence.".to_string(),
                        evidence_ref: "evidence-analyzer-001".to_string(),
                    },
                    RemediationConfidenceInput {
                        key: "blast_radius".to_string(),
                        score: 82,
                        rationale: "Change is constrained to one lock-order block.".to_string(),
                        evidence_ref: "evidence-diff-001".to_string(),
                    },
                    RemediationConfidenceInput {
                        key: "replay_reproducibility".to_string(),
                        score: 79,
                        rationale: "Replay reproduces failure with fixed seed.".to_string(),
                        evidence_ref: "evidence-replay-001".to_string(),
                    },
                    RemediationConfidenceInput {
                        key: "test_coverage_delta".to_string(),
                        score: 74,
                        rationale: "Targeted tests cover touched lock-order path.".to_string(),
                        evidence_ref: "evidence-tests-001".to_string(),
                    },
                ],
                override_justification: None,
            },
            expected_confidence_score: 80,
            expected_risk_band: "guarded_auto_apply".to_string(),
            expected_decision: "apply".to_string(),
        },
        RemediationRecipeFixture {
            fixture_id: "fixture-human-approval".to_string(),
            description: "Low-confidence timeout tuning requiring manual approval.".to_string(),
            recipe: RemediationRecipe {
                recipe_id: "recipe-timeout-budget-001".to_string(),
                finding_id: "doctor-invariant:src/time/driver.rs:warning".to_string(),
                fix_intent: "adjust_timeout_budget".to_string(),
                preconditions: vec![
                    RemediationPrecondition {
                        key: "rollback_artifact_exists".to_string(),
                        predicate: "exists".to_string(),
                        expected_value: "true".to_string(),
                        evidence_ref: "evidence-rollback-001".to_string(),
                        required: true,
                    },
                    RemediationPrecondition {
                        key: "timeout_regression_detected".to_string(),
                        predicate: "eq".to_string(),
                        expected_value: "true".to_string(),
                        evidence_ref: "evidence-timeout-001".to_string(),
                        required: true,
                    },
                ],
                rollback: RemediationRollbackPlan {
                    strategy: "restore_backup_snapshot".to_string(),
                    rollback_command: "cp artifacts/backups/time-driver.prev src/time/driver.rs"
                        .to_string(),
                    verify_command: "rch exec -- cargo test --lib time::driver::tests::timeout_budget_regression"
                        .to_string(),
                    timeout_secs: 120,
                },
                confidence_inputs: vec![
                    RemediationConfidenceInput {
                        key: "analyzer_confidence".to_string(),
                        score: 38,
                        rationale: "Analyzer confidence is low due to sparse evidence.".to_string(),
                        evidence_ref: "evidence-analyzer-002".to_string(),
                    },
                    RemediationConfidenceInput {
                        key: "blast_radius".to_string(),
                        score: 44,
                        rationale: "Potential impact spans scheduler and timer paths.".to_string(),
                        evidence_ref: "evidence-diff-002".to_string(),
                    },
                    RemediationConfidenceInput {
                        key: "replay_reproducibility".to_string(),
                        score: 41,
                        rationale: "Replay currently reproduces intermittently.".to_string(),
                        evidence_ref: "evidence-replay-002".to_string(),
                    },
                    RemediationConfidenceInput {
                        key: "test_coverage_delta".to_string(),
                        score: 36,
                        rationale: "Coverage increase still pending.".to_string(),
                        evidence_ref: "evidence-tests-002".to_string(),
                    },
                ],
                override_justification: Some(
                    "Force plan generation for operator review; do not auto-apply.".to_string(),
                ),
            },
            expected_confidence_score: 39,
            expected_risk_band: "critical_risk".to_string(),
            expected_decision: "review".to_string(),
        },
    ]
}

/// Returns bundle for remediation-recipe DSL contract consumers.
#[must_use]
pub fn remediation_recipe_bundle() -> RemediationRecipeBundle {
    RemediationRecipeBundle {
        contract: remediation_recipe_contract(),
        fixtures: remediation_recipe_fixtures(),
    }
}

/// Executes deterministic remediation recipe smoke flow and emits structured logs.
///
/// # Errors
///
/// Returns `Err` when fixture evaluation or log emission violates contracts.
pub fn run_remediation_recipe_smoke(
    recipe_contract: &RemediationRecipeContract,
    logging_contract: &StructuredLoggingContract,
) -> Result<Vec<StructuredLogEvent>, String> {
    validate_remediation_recipe_contract(recipe_contract)?;
    let mut events = Vec::new();
    let bundle = remediation_recipe_bundle();

    for fixture in &bundle.fixtures {
        let score = compute_remediation_confidence_score(recipe_contract, &fixture.recipe)?;
        if score.confidence_score != fixture.expected_confidence_score {
            return Err(format!(
                "fixture {} expected confidence {}, got {}",
                fixture.fixture_id, fixture.expected_confidence_score, score.confidence_score
            ));
        }
        if score.risk_band != fixture.expected_risk_band {
            return Err(format!(
                "fixture {} expected risk band {}, got {}",
                fixture.fixture_id, fixture.expected_risk_band, score.risk_band
            ));
        }

        let outcome_class = if fixture.expected_decision == "apply" {
            "success"
        } else {
            "failed"
        };
        let mut apply_fields = BTreeMap::new();
        apply_fields.insert(
            "artifact_pointer".to_string(),
            format!(
                "artifacts/run-remediation-smoke/{}/apply.json",
                fixture.fixture_id
            ),
        );
        apply_fields.insert(
            "command_provenance".to_string(),
            "rch exec -- cargo test --lib cli::doctor::tests::remediation_recipe_smoke".to_string(),
        );
        apply_fields.insert("flow_id".to_string(), "remediation".to_string());
        apply_fields.insert("outcome_class".to_string(), outcome_class.to_string());
        apply_fields.insert("run_id".to_string(), "run-remediation-smoke".to_string());
        apply_fields.insert("scenario_id".to_string(), fixture.fixture_id.clone());
        apply_fields.insert(
            "trace_id".to_string(),
            format!("trace-remediation-{}-apply", fixture.fixture_id),
        );
        apply_fields.insert("risk_score".to_string(), score.confidence_score.to_string());
        apply_fields.insert("recipe_id".to_string(), fixture.recipe.recipe_id.clone());
        apply_fields.insert("risk_band".to_string(), score.risk_band.clone());
        apply_fields.insert(
            "confidence_breakdown".to_string(),
            score.weighted_contributions.join(";"),
        );
        apply_fields.insert(
            "decision_rationale".to_string(),
            format!(
                "decision={} requires_human_approval={}",
                fixture.expected_decision, score.requires_human_approval
            ),
        );
        if fixture.expected_decision == "review" {
            apply_fields.insert(
                "rejection_rationale".to_string(),
                "confidence below auto-apply threshold; escalate to operator review".to_string(),
            );
            if let Some(override_justification) = &fixture.recipe.override_justification {
                apply_fields.insert(
                    "override_rationale".to_string(),
                    override_justification.clone(),
                );
            }
        }
        let apply_event = emit_structured_log_event(
            logging_contract,
            "remediation",
            "remediation_apply",
            &apply_fields,
        )?;
        events.push(apply_event);

        let mut verify_fields = BTreeMap::new();
        verify_fields.insert(
            "artifact_pointer".to_string(),
            format!(
                "artifacts/run-remediation-smoke/{}/verify.json",
                fixture.fixture_id
            ),
        );
        verify_fields.insert(
            "command_provenance".to_string(),
            fixture.recipe.rollback.verify_command.clone(),
        );
        verify_fields.insert("flow_id".to_string(), "remediation".to_string());
        verify_fields.insert("outcome_class".to_string(), "success".to_string());
        verify_fields.insert("run_id".to_string(), "run-remediation-smoke".to_string());
        verify_fields.insert("scenario_id".to_string(), fixture.fixture_id.clone());
        verify_fields.insert(
            "trace_id".to_string(),
            format!("trace-remediation-{}-verify", fixture.fixture_id),
        );
        verify_fields.insert("risk_score".to_string(), score.confidence_score.to_string());
        verify_fields.insert("recipe_id".to_string(), fixture.recipe.recipe_id.clone());
        verify_fields.insert(
            "verification_summary".to_string(),
            "rollback_readiness=verified".to_string(),
        );
        let verify_event = emit_structured_log_event(
            logging_contract,
            "remediation",
            "remediation_verify",
            &verify_fields,
        )?;
        events.push(verify_event);
    }

    let mut summary_fields = BTreeMap::new();
    summary_fields.insert(
        "artifact_pointer".to_string(),
        "artifacts/run-remediation-smoke/summary.json".to_string(),
    );
    summary_fields.insert(
        "command_provenance".to_string(),
        "asupersync doctor remediation-contract --json".to_string(),
    );
    summary_fields.insert("flow_id".to_string(), "remediation".to_string());
    summary_fields.insert("outcome_class".to_string(), "success".to_string());
    summary_fields.insert("run_id".to_string(), "run-remediation-smoke".to_string());
    summary_fields.insert(
        "scenario_id".to_string(),
        "doctor-remediation-smoke".to_string(),
    );
    summary_fields.insert(
        "trace_id".to_string(),
        "trace-remediation-summary".to_string(),
    );
    summary_fields.insert(
        "decision_rationale".to_string(),
        "all remediation recipe fixtures matched expected decisions and risk bands".to_string(),
    );
    let summary_event = emit_structured_log_event(
        logging_contract,
        "remediation",
        "verification_summary",
        &summary_fields,
    )?;
    events.push(summary_event);

    events.sort_by(|left, right| {
        (
            left.flow_id.as_str(),
            left.event_kind.as_str(),
            left.fields
                .get("trace_id")
                .map(String::as_str)
                .unwrap_or_default(),
        )
            .cmp(&(
                right.flow_id.as_str(),
                right.event_kind.as_str(),
                right
                    .fields
                    .get("trace_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ))
    });
    Ok(events)
}

/// Returns the canonical rch-backed execution-adapter contract.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn execution_adapter_contract() -> ExecutionAdapterContract {
    ExecutionAdapterContract {
        contract_version: EXECUTION_ADAPTER_CONTRACT_VERSION.to_string(),
        logging_contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        required_request_fields: vec![
            "command_class".to_string(),
            "command_id".to_string(),
            "correlation_id".to_string(),
            "prefer_remote".to_string(),
            "raw_command".to_string(),
        ],
        required_result_fields: vec![
            "artifact_manifest".to_string(),
            "command_id".to_string(),
            "exit_code".to_string(),
            "outcome_class".to_string(),
            "route".to_string(),
            "routed_command".to_string(),
            "state".to_string(),
        ],
        command_classes: vec![
            ExecutionCommandClass {
                class_id: "cargo_check".to_string(),
                label: "cargo check".to_string(),
                allowed_prefixes: vec!["cargo check".to_string()],
                force_rch: true,
                default_timeout_secs: 300,
            },
            ExecutionCommandClass {
                class_id: "cargo_clippy".to_string(),
                label: "cargo clippy".to_string(),
                allowed_prefixes: vec!["cargo clippy".to_string()],
                force_rch: true,
                default_timeout_secs: 300,
            },
            ExecutionCommandClass {
                class_id: "cargo_fmt_check".to_string(),
                label: "cargo fmt --check".to_string(),
                allowed_prefixes: vec!["cargo fmt --check".to_string()],
                force_rch: false,
                default_timeout_secs: 120,
            },
            ExecutionCommandClass {
                class_id: "cargo_test".to_string(),
                label: "cargo test".to_string(),
                allowed_prefixes: vec!["cargo test".to_string()],
                force_rch: true,
                default_timeout_secs: 1800,
            },
            ExecutionCommandClass {
                class_id: "doctor_custom".to_string(),
                label: "doctor custom command".to_string(),
                allowed_prefixes: vec![
                    "asupersync doctor".to_string(),
                    "br ".to_string(),
                    "bv --robot-".to_string(),
                ],
                force_rch: false,
                default_timeout_secs: 180,
            },
        ],
        route_policies: vec![
            ExecutionRoutePolicy {
                policy_id: "local_fallback_on_rch_unavailable".to_string(),
                condition: "rch_unavailable".to_string(),
                route: "local_direct".to_string(),
                retry_strategy: "none".to_string(),
                max_retries: 0,
            },
            ExecutionRoutePolicy {
                policy_id: "remote_rch_default".to_string(),
                condition: "prefer_remote_and_rch_available".to_string(),
                route: "remote_rch".to_string(),
                retry_strategy: "bounded_backoff".to_string(),
                max_retries: 2,
            },
        ],
        timeout_profiles: vec![
            ExecutionTimeoutProfile {
                class_id: "cargo_check".to_string(),
                soft_timeout_secs: 180,
                hard_timeout_secs: 300,
                cancel_grace_secs: 10,
            },
            ExecutionTimeoutProfile {
                class_id: "cargo_clippy".to_string(),
                soft_timeout_secs: 240,
                hard_timeout_secs: 300,
                cancel_grace_secs: 10,
            },
            ExecutionTimeoutProfile {
                class_id: "cargo_fmt_check".to_string(),
                soft_timeout_secs: 90,
                hard_timeout_secs: 120,
                cancel_grace_secs: 5,
            },
            ExecutionTimeoutProfile {
                class_id: "cargo_test".to_string(),
                soft_timeout_secs: 1500,
                hard_timeout_secs: 1800,
                cancel_grace_secs: 30,
            },
            ExecutionTimeoutProfile {
                class_id: "doctor_custom".to_string(),
                soft_timeout_secs: 120,
                hard_timeout_secs: 180,
                cancel_grace_secs: 10,
            },
        ],
        state_transitions: vec![
            ExecutionStateTransition {
                from_state: "cancel_requested".to_string(),
                trigger: "cancel_completed".to_string(),
                to_state: "cancelled".to_string(),
            },
            ExecutionStateTransition {
                from_state: "cancel_requested".to_string(),
                trigger: "cancel_timeout".to_string(),
                to_state: "failed".to_string(),
            },
            ExecutionStateTransition {
                from_state: "planned".to_string(),
                trigger: "enqueue".to_string(),
                to_state: "queued".to_string(),
            },
            ExecutionStateTransition {
                from_state: "queued".to_string(),
                trigger: "start".to_string(),
                to_state: "running".to_string(),
            },
            ExecutionStateTransition {
                from_state: "running".to_string(),
                trigger: "cancel".to_string(),
                to_state: "cancel_requested".to_string(),
            },
            ExecutionStateTransition {
                from_state: "running".to_string(),
                trigger: "process_exit_nonzero".to_string(),
                to_state: "failed".to_string(),
            },
            ExecutionStateTransition {
                from_state: "running".to_string(),
                trigger: "process_exit_zero".to_string(),
                to_state: "succeeded".to_string(),
            },
        ],
        failure_taxonomy: vec![
            ExecutionFailureClass {
                code: "command_failed".to_string(),
                severity: "high".to_string(),
                retryable: false,
                operator_action: "Inspect stderr and open remediation workflow.".to_string(),
            },
            ExecutionFailureClass {
                code: "command_timeout".to_string(),
                severity: "medium".to_string(),
                retryable: true,
                operator_action: "Retry with bounded backoff and attach transcript.".to_string(),
            },
            ExecutionFailureClass {
                code: "invalid_transition".to_string(),
                severity: "critical".to_string(),
                retryable: false,
                operator_action: "Abort run and emit deterministic state-machine diagnostics."
                    .to_string(),
            },
            ExecutionFailureClass {
                code: "rch_unavailable".to_string(),
                severity: "medium".to_string(),
                retryable: true,
                operator_action: "Apply local fallback policy and log route downgrade.".to_string(),
            },
        ],
        artifact_manifest_fields: vec![
            "command_provenance".to_string(),
            "outcome_class".to_string(),
            "run_id".to_string(),
            "scenario_id".to_string(),
            "trace_id".to_string(),
            "transcript_path".to_string(),
            "worker_route".to_string(),
        ],
    }
}

/// Validates invariants for [`ExecutionAdapterContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or policy invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_execution_adapter_contract(
    contract: &ExecutionAdapterContract,
) -> Result<(), String> {
    if contract.contract_version != EXECUTION_ADAPTER_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.logging_contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected logging_contract_version {}",
            contract.logging_contract_version
        ));
    }

    validate_lexical_string_set(&contract.required_request_fields, "required_request_fields")?;
    for required in [
        "command_class",
        "command_id",
        "correlation_id",
        "prefer_remote",
        "raw_command",
    ] {
        if !contract
            .required_request_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_request_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_result_fields, "required_result_fields")?;
    for required in [
        "artifact_manifest",
        "command_id",
        "exit_code",
        "outcome_class",
        "route",
        "routed_command",
        "state",
    ] {
        if !contract
            .required_result_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_result_fields missing {required}"));
        }
    }

    validate_lexical_string_set(
        &contract.artifact_manifest_fields,
        "artifact_manifest_fields",
    )?;
    for required in [
        "command_provenance",
        "outcome_class",
        "run_id",
        "scenario_id",
        "trace_id",
        "transcript_path",
        "worker_route",
    ] {
        if !contract
            .artifact_manifest_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("artifact_manifest_fields missing {required}"));
        }
    }

    if contract.command_classes.is_empty() {
        return Err("command_classes must be non-empty".to_string());
    }
    let class_ids = contract
        .command_classes
        .iter()
        .map(|class| class.class_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&class_ids, "command_classes.class_id")?;
    for class in &contract.command_classes {
        if class.label.trim().is_empty() {
            return Err(format!("command class {} has empty label", class.class_id));
        }
        validate_lexical_string_set(
            &class.allowed_prefixes,
            &format!("command class {} allowed_prefixes", class.class_id),
        )?;
        if class.default_timeout_secs == 0 {
            return Err(format!(
                "command class {} default_timeout_secs must be > 0",
                class.class_id
            ));
        }
        if class.force_rch
            && !class
                .allowed_prefixes
                .iter()
                .all(|prefix| prefix.starts_with("cargo "))
        {
            return Err(format!(
                "force_rch command class {} must use cargo-prefixed allowed_prefixes",
                class.class_id
            ));
        }
    }

    if contract.route_policies.is_empty() {
        return Err("route_policies must be non-empty".to_string());
    }
    let policy_ids = contract
        .route_policies
        .iter()
        .map(|policy| policy.policy_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&policy_ids, "route_policies.policy_id")?;
    for required in ["local_fallback_on_rch_unavailable", "remote_rch_default"] {
        if !policy_ids.iter().any(|policy_id| policy_id == required) {
            return Err(format!("route_policies missing required policy {required}"));
        }
    }
    for policy in &contract.route_policies {
        if policy.condition.trim().is_empty() || policy.retry_strategy.trim().is_empty() {
            return Err(format!(
                "route policy {} must define condition/retry_strategy",
                policy.policy_id
            ));
        }
        if !matches!(
            policy.route.as_str(),
            "fail_closed" | "local_direct" | "remote_rch"
        ) {
            return Err(format!(
                "route policy {} uses unsupported route {}",
                policy.policy_id, policy.route
            ));
        }
    }

    if contract.timeout_profiles.is_empty() {
        return Err("timeout_profiles must be non-empty".to_string());
    }
    let timeout_class_ids = contract
        .timeout_profiles
        .iter()
        .map(|profile| profile.class_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&timeout_class_ids, "timeout_profiles.class_id")?;
    if timeout_class_ids != class_ids {
        return Err("timeout_profiles.class_id must exactly match command class ids".to_string());
    }
    for profile in &contract.timeout_profiles {
        if profile.soft_timeout_secs == 0
            || profile.hard_timeout_secs == 0
            || profile.cancel_grace_secs == 0
        {
            return Err(format!(
                "timeout profile {} must have non-zero values",
                profile.class_id
            ));
        }
        if profile.soft_timeout_secs > profile.hard_timeout_secs {
            return Err(format!(
                "timeout profile {} soft_timeout_secs must be <= hard_timeout_secs",
                profile.class_id
            ));
        }
    }

    if contract.state_transitions.is_empty() {
        return Err("state_transitions must be non-empty".to_string());
    }
    let mut transition_keys = contract
        .state_transitions
        .iter()
        .map(|transition| {
            format!(
                "{}|{}|{}",
                transition.from_state, transition.trigger, transition.to_state
            )
        })
        .collect::<Vec<_>>();
    validate_lexical_string_set(&transition_keys, "state_transitions")?;
    let valid_states = [
        "cancel_requested",
        "cancelled",
        "failed",
        "planned",
        "queued",
        "running",
        "succeeded",
    ];
    for transition in &contract.state_transitions {
        if !valid_states
            .iter()
            .any(|state| state == &transition.from_state.as_str())
        {
            return Err(format!(
                "state transition uses unknown from_state {}",
                transition.from_state
            ));
        }
        if !valid_states
            .iter()
            .any(|state| state == &transition.to_state.as_str())
        {
            return Err(format!(
                "state transition uses unknown to_state {}",
                transition.to_state
            ));
        }
        if transition.trigger.trim().is_empty() {
            return Err("state transition trigger must be non-empty".to_string());
        }
    }
    for required in [
        "cancel_requested|cancel_completed|cancelled",
        "cancel_requested|cancel_timeout|failed",
        "planned|enqueue|queued",
        "queued|start|running",
        "running|cancel|cancel_requested",
        "running|process_exit_nonzero|failed",
        "running|process_exit_zero|succeeded",
    ] {
        if !transition_keys.iter().any(|key| key == required) {
            return Err(format!(
                "state_transitions missing required edge {required}"
            ));
        }
    }
    transition_keys.clear();

    if contract.failure_taxonomy.is_empty() {
        return Err("failure_taxonomy must be non-empty".to_string());
    }
    let failure_codes = contract
        .failure_taxonomy
        .iter()
        .map(|failure| failure.code.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&failure_codes, "failure_taxonomy.code")?;
    for required in [
        "command_failed",
        "command_timeout",
        "invalid_transition",
        "rch_unavailable",
    ] {
        if !failure_codes.iter().any(|code| code == required) {
            return Err(format!("failure_taxonomy missing required code {required}"));
        }
    }
    for failure in &contract.failure_taxonomy {
        if !matches!(
            failure.severity.as_str(),
            "critical" | "high" | "low" | "medium"
        ) {
            return Err(format!(
                "failure {} has unsupported severity {}",
                failure.code, failure.severity
            ));
        }
        if failure.operator_action.trim().is_empty() {
            return Err(format!(
                "failure {} must define operator_action",
                failure.code
            ));
        }
    }

    Ok(())
}

fn normalize_command_line(raw_command: &str) -> Result<String, String> {
    let normalized = raw_command
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();
    if normalized.is_empty() {
        return Err("raw_command must be non-empty".to_string());
    }
    Ok(normalized)
}

/// Builds a deterministic execution plan for one adapter request.
///
/// # Errors
///
/// Returns `Err` when request fields, command-class matching, or routing rules fail.
pub fn plan_execution_command(
    contract: &ExecutionAdapterContract,
    request: &ExecutionAdapterRequest,
    rch_available: bool,
) -> Result<ExecutionAdapterPlan, String> {
    validate_execution_adapter_contract(contract)?;

    if request.command_id.trim().is_empty() {
        return Err("command_id must be non-empty".to_string());
    }
    if !is_slug_like(&request.correlation_id) {
        return Err("correlation_id must be slug-like".to_string());
    }

    let class = contract
        .command_classes
        .iter()
        .find(|candidate| candidate.class_id == request.command_class)
        .ok_or_else(|| format!("unknown command_class {}", request.command_class))?;

    let normalized_command = normalize_command_line(&request.raw_command)?;
    if !class
        .allowed_prefixes
        .iter()
        .any(|prefix| normalized_command.starts_with(prefix))
    {
        return Err(format!(
            "raw_command for class {} must start with one of [{}]",
            class.class_id,
            class.allowed_prefixes.join(", ")
        ));
    }

    let route = if request.prefer_remote && (class.force_rch || rch_available) {
        if rch_available {
            "remote_rch".to_string()
        } else {
            contract
                .route_policies
                .iter()
                .find(|policy| policy.policy_id == "local_fallback_on_rch_unavailable")
                .map_or_else(|| "local_direct".to_string(), |policy| policy.route.clone())
        }
    } else {
        "local_direct".to_string()
    };

    let routed_command = if route == "remote_rch" {
        if normalized_command.starts_with("rch exec -- ") {
            normalized_command.clone()
        } else {
            format!("rch exec -- {normalized_command}")
        }
    } else {
        normalized_command.clone()
    };

    let timeout_profile = contract
        .timeout_profiles
        .iter()
        .find(|profile| profile.class_id == class.class_id)
        .ok_or_else(|| {
            format!(
                "missing timeout profile for command class {}",
                class.class_id
            )
        })?;

    Ok(ExecutionAdapterPlan {
        command_id: request.command_id.clone(),
        command_class: class.class_id.clone(),
        correlation_id: request.correlation_id.clone(),
        normalized_command,
        routed_command,
        route,
        timeout_secs: timeout_profile.hard_timeout_secs,
        initial_state: "planned".to_string(),
        artifact_manifest_fields: contract.artifact_manifest_fields.clone(),
    })
}

/// Advances the deterministic execution state machine by one trigger.
///
/// # Errors
///
/// Returns `Err` when no transition exists for `(current_state, trigger)`.
pub fn advance_execution_state(
    contract: &ExecutionAdapterContract,
    current_state: &str,
    trigger: &str,
) -> Result<String, String> {
    validate_execution_adapter_contract(contract)?;
    let transition = contract
        .state_transitions
        .iter()
        .find(|candidate| {
            candidate.from_state == current_state.trim() && candidate.trigger == trigger.trim()
        })
        .ok_or_else(|| {
            format!("invalid execution state transition from {current_state} using {trigger}")
        })?;
    Ok(transition.to_state.clone())
}

/// Returns the canonical scenario-composer + run-queue manager contract.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn scenario_composer_contract() -> ScenarioComposerContract {
    ScenarioComposerContract {
        contract_version: SCENARIO_COMPOSER_CONTRACT_VERSION.to_string(),
        execution_adapter_version: EXECUTION_ADAPTER_CONTRACT_VERSION.to_string(),
        logging_contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        required_request_fields: vec![
            "correlation_id".to_string(),
            "requested_by".to_string(),
            "run_id".to_string(),
            "seed".to_string(),
            "template_id".to_string(),
        ],
        required_run_fields: vec![
            "command_classes".to_string(),
            "correlation_id".to_string(),
            "priority".to_string(),
            "queue_id".to_string(),
            "required_artifacts".to_string(),
            "retries_remaining".to_string(),
            "run_id".to_string(),
            "seed".to_string(),
            "state".to_string(),
            "template_id".to_string(),
        ],
        scenario_templates: vec![
            ScenarioTemplate {
                template_id: "scenario_cancel_recovery".to_string(),
                description: "Cancellation-path replay with deterministic recovery verification."
                    .to_string(),
                required_command_classes: vec!["cargo_check".to_string(), "cargo_test".to_string()],
                required_artifacts: vec!["structured_log".to_string(), "trace_bundle".to_string()],
                default_priority: 220,
                max_retries: 2,
                requires_replay_seed: true,
            },
            ScenarioTemplate {
                template_id: "scenario_happy_path_smoke".to_string(),
                description:
                    "Fast deterministic smoke path for baseline command/orchestration health."
                        .to_string(),
                required_command_classes: vec![
                    "cargo_check".to_string(),
                    "cargo_fmt_check".to_string(),
                ],
                required_artifacts: vec![
                    "structured_log".to_string(),
                    "summary_report".to_string(),
                ],
                default_priority: 120,
                max_retries: 1,
                requires_replay_seed: false,
            },
            ScenarioTemplate {
                template_id: "scenario_regression_bundle".to_string(),
                description: "Full regression execution with replay-ready transcript capture."
                    .to_string(),
                required_command_classes: vec![
                    "cargo_check".to_string(),
                    "cargo_clippy".to_string(),
                    "cargo_test".to_string(),
                ],
                required_artifacts: vec![
                    "structured_log".to_string(),
                    "summary_report".to_string(),
                    "transcript".to_string(),
                ],
                default_priority: 180,
                max_retries: 2,
                requires_replay_seed: true,
            },
        ],
        queue_policy: ScenarioRunQueuePolicy {
            max_concurrent_runs: 2,
            max_queue_depth: 32,
            dispatch_order: "priority_then_run_id".to_string(),
            priority_bands: vec![
                "p0_critical".to_string(),
                "p1_high".to_string(),
                "p2_normal".to_string(),
                "p3_low".to_string(),
            ],
            cancellation_policy: "cancel_duplicate_run_id".to_string(),
        },
        failure_taxonomy: vec![
            ScenarioQueueFailureClass {
                code: "invalid_seed".to_string(),
                severity: "high".to_string(),
                retryable: false,
                operator_action: "Provide deterministic replay seed and retry compose.".to_string(),
            },
            ScenarioQueueFailureClass {
                code: "queue_full".to_string(),
                severity: "medium".to_string(),
                retryable: true,
                operator_action: "Drain queue or increase queue budget in policy.".to_string(),
            },
            ScenarioQueueFailureClass {
                code: "unknown_template".to_string(),
                severity: "critical".to_string(),
                retryable: false,
                operator_action: "Use a known template_id from scenario_templates.".to_string(),
            },
        ],
    }
}

/// Validates invariants for [`ScenarioComposerContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or queue-policy invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_scenario_composer_contract(
    contract: &ScenarioComposerContract,
) -> Result<(), String> {
    if contract.contract_version != SCENARIO_COMPOSER_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.execution_adapter_version != EXECUTION_ADAPTER_CONTRACT_VERSION {
        return Err(format!(
            "unexpected execution_adapter_version {}",
            contract.execution_adapter_version
        ));
    }
    if contract.logging_contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected logging_contract_version {}",
            contract.logging_contract_version
        ));
    }

    validate_lexical_string_set(&contract.required_request_fields, "required_request_fields")?;
    for required in [
        "correlation_id",
        "requested_by",
        "run_id",
        "seed",
        "template_id",
    ] {
        if !contract
            .required_request_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_request_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_run_fields, "required_run_fields")?;
    for required in [
        "command_classes",
        "correlation_id",
        "priority",
        "queue_id",
        "required_artifacts",
        "retries_remaining",
        "run_id",
        "seed",
        "state",
        "template_id",
    ] {
        if !contract
            .required_run_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_run_fields missing {required}"));
        }
    }

    if contract.scenario_templates.is_empty() {
        return Err("scenario_templates must be non-empty".to_string());
    }
    let template_ids = contract
        .scenario_templates
        .iter()
        .map(|template| template.template_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&template_ids, "scenario_templates.template_id")?;
    let execution_contract = execution_adapter_contract();
    let execution_class_ids = execution_contract
        .command_classes
        .iter()
        .map(|class| class.class_id.clone())
        .collect::<BTreeSet<_>>();

    for template in &contract.scenario_templates {
        if template.description.trim().is_empty() {
            return Err(format!(
                "template {} has empty description",
                template.template_id
            ));
        }
        validate_lexical_string_set(
            &template.required_command_classes,
            &format!("template {} required_command_classes", template.template_id),
        )?;
        validate_lexical_string_set(
            &template.required_artifacts,
            &format!("template {} required_artifacts", template.template_id),
        )?;
        if template.max_retries > 8 {
            return Err(format!(
                "template {} max_retries must be <= 8",
                template.template_id
            ));
        }
        for class_id in &template.required_command_classes {
            if !execution_class_ids.contains(class_id) {
                return Err(format!(
                    "template {} references unknown command class {}",
                    template.template_id, class_id
                ));
            }
        }
        if template.requires_replay_seed && template.default_priority < 100 {
            return Err(format!(
                "template {} requires_replay_seed must have default_priority >= 100",
                template.template_id
            ));
        }
    }

    if contract.queue_policy.max_concurrent_runs == 0 {
        return Err("queue_policy.max_concurrent_runs must be > 0".to_string());
    }
    if contract.queue_policy.max_queue_depth == 0 {
        return Err("queue_policy.max_queue_depth must be > 0".to_string());
    }
    if contract.queue_policy.max_concurrent_runs > contract.queue_policy.max_queue_depth {
        return Err(
            "queue_policy.max_concurrent_runs must be <= queue_policy.max_queue_depth".to_string(),
        );
    }
    if contract.queue_policy.dispatch_order != "priority_then_run_id" {
        return Err("queue_policy.dispatch_order must be priority_then_run_id".to_string());
    }
    validate_lexical_string_set(
        &contract.queue_policy.priority_bands,
        "queue_policy.priority_bands",
    )?;
    if contract.queue_policy.cancellation_policy != "cancel_duplicate_run_id" {
        return Err("queue_policy.cancellation_policy must be cancel_duplicate_run_id".to_string());
    }

    if contract.failure_taxonomy.is_empty() {
        return Err("failure_taxonomy must be non-empty".to_string());
    }
    let failure_codes = contract
        .failure_taxonomy
        .iter()
        .map(|failure| failure.code.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&failure_codes, "failure_taxonomy.code")?;
    for required in ["invalid_seed", "queue_full", "unknown_template"] {
        if !failure_codes.iter().any(|code| code == required) {
            return Err(format!("failure_taxonomy missing required code {required}"));
        }
    }
    for failure in &contract.failure_taxonomy {
        if !matches!(
            failure.severity.as_str(),
            "critical" | "high" | "low" | "medium"
        ) {
            return Err(format!(
                "failure {} has unsupported severity {}",
                failure.code, failure.severity
            ));
        }
        if failure.operator_action.trim().is_empty() {
            return Err(format!(
                "failure {} must define operator_action",
                failure.code
            ));
        }
    }

    Ok(())
}

/// Composes one deterministic queue entry from a scenario request.
///
/// # Errors
///
/// Returns `Err` when request fields or template constraints are violated.
pub fn compose_scenario_run(
    contract: &ScenarioComposerContract,
    request: &ScenarioRunRequest,
) -> Result<ScenarioRunQueueEntry, String> {
    validate_scenario_composer_contract(contract)?;

    if request.run_id.trim().is_empty() {
        return Err("run_id must be non-empty".to_string());
    }
    if !is_slug_like(&request.correlation_id) {
        return Err("correlation_id must be slug-like".to_string());
    }
    if request.requested_by.trim().is_empty() {
        return Err("requested_by must be non-empty".to_string());
    }

    let template = contract
        .scenario_templates
        .iter()
        .find(|candidate| candidate.template_id == request.template_id)
        .ok_or_else(|| format!("unknown template_id {}", request.template_id))?;
    if template.requires_replay_seed && request.seed.trim().is_empty() {
        return Err("seed must be non-empty for templates requiring replay seed".to_string());
    }
    if !request.seed.trim().is_empty() && !is_slug_like(request.seed.trim()) {
        return Err("seed must be slug-like when provided".to_string());
    }

    Ok(ScenarioRunQueueEntry {
        queue_id: format!("queue-{}", request.run_id.trim()),
        run_id: request.run_id.trim().to_string(),
        template_id: template.template_id.clone(),
        correlation_id: request.correlation_id.clone(),
        seed: request.seed.trim().to_string(),
        priority: request
            .priority_override
            .unwrap_or(template.default_priority),
        state: "queued".to_string(),
        command_classes: template.required_command_classes.clone(),
        required_artifacts: template.required_artifacts.clone(),
        retries_remaining: template.max_retries,
    })
}

/// Builds a deterministic run queue from scenario requests.
///
/// # Errors
///
/// Returns `Err` when composed entries violate queue-capacity policy.
pub fn build_scenario_run_queue(
    contract: &ScenarioComposerContract,
    requests: &[ScenarioRunRequest],
) -> Result<Vec<ScenarioRunQueueEntry>, String> {
    validate_scenario_composer_contract(contract)?;
    if requests.len() > usize::from(contract.queue_policy.max_queue_depth) {
        return Err(format!(
            "queue_full: {} requests exceed max_queue_depth {}",
            requests.len(),
            contract.queue_policy.max_queue_depth
        ));
    }

    let mut entries = requests
        .iter()
        .map(|request| compose_scenario_run(contract, request))
        .collect::<Result<Vec<_>, _>>()?;

    entries.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then(left.run_id.cmp(&right.run_id))
            .then(left.template_id.cmp(&right.template_id))
    });
    Ok(entries)
}

/// Applies dispatch policy to a deterministic queue and marks running entries.
///
/// # Errors
///
/// Returns `Err` when queue entries fail policy validation.
pub fn dispatch_scenario_run_queue(
    contract: &ScenarioComposerContract,
    entries: &[ScenarioRunQueueEntry],
) -> Result<Vec<ScenarioRunQueueEntry>, String> {
    validate_scenario_composer_contract(contract)?;
    if entries.len() > usize::from(contract.queue_policy.max_queue_depth) {
        return Err(format!(
            "queue_full: {} entries exceed max_queue_depth {}",
            entries.len(),
            contract.queue_policy.max_queue_depth
        ));
    }

    let mut normalized = entries.to_vec();
    normalized.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then(left.run_id.cmp(&right.run_id))
            .then(left.template_id.cmp(&right.template_id))
    });

    let running_limit = usize::from(contract.queue_policy.max_concurrent_runs);
    for (index, entry) in normalized.iter_mut().enumerate() {
        entry.state = if index < running_limit {
            "running".to_string()
        } else {
            "queued".to_string()
        };
    }
    Ok(normalized)
}

/// Returns the canonical deterministic e2e harness core contract.
#[must_use]
pub fn e2e_harness_core_contract() -> E2eHarnessCoreContract {
    E2eHarnessCoreContract {
        contract_version: E2E_HARNESS_CONTRACT_VERSION.to_string(),
        execution_adapter_version: EXECUTION_ADAPTER_CONTRACT_VERSION.to_string(),
        logging_contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        required_config_fields: vec![
            "correlation_id".to_string(),
            "expected_outcome".to_string(),
            "requested_by".to_string(),
            "run_id".to_string(),
            "scenario_id".to_string(),
            "script_id".to_string(),
            "seed".to_string(),
            "timeout_secs".to_string(),
        ],
        required_transcript_fields: vec![
            "correlation_id".to_string(),
            "events".to_string(),
            "run_id".to_string(),
            "scenario_id".to_string(),
            "seed".to_string(),
        ],
        required_artifact_index_fields: vec![
            "artifact_class".to_string(),
            "artifact_id".to_string(),
            "artifact_path".to_string(),
            "checksum_hint".to_string(),
        ],
        lifecycle_states: vec![
            "cancelled".to_string(),
            "completed".to_string(),
            "failed".to_string(),
            "running".to_string(),
            "started".to_string(),
        ],
        failure_taxonomy: vec![
            E2eHarnessFailureClass {
                code: "config_missing".to_string(),
                severity: "high".to_string(),
                retryable: false,
                operator_action: "Provide all required config fields and retry.".to_string(),
            },
            E2eHarnessFailureClass {
                code: "invalid_seed".to_string(),
                severity: "high".to_string(),
                retryable: false,
                operator_action: "Use a deterministic slug-like seed.".to_string(),
            },
            E2eHarnessFailureClass {
                code: "script_timeout".to_string(),
                severity: "medium".to_string(),
                retryable: true,
                operator_action: "Increase timeout budget or reduce scenario scope.".to_string(),
            },
        ],
    }
}

/// Validates invariants for [`E2eHarnessCoreContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or dependency invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_e2e_harness_core_contract(contract: &E2eHarnessCoreContract) -> Result<(), String> {
    if contract.contract_version != E2E_HARNESS_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.execution_adapter_version != EXECUTION_ADAPTER_CONTRACT_VERSION {
        return Err(format!(
            "unexpected execution_adapter_version {}",
            contract.execution_adapter_version
        ));
    }
    if contract.logging_contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected logging_contract_version {}",
            contract.logging_contract_version
        ));
    }

    validate_lexical_string_set(&contract.required_config_fields, "required_config_fields")?;
    for required in [
        "correlation_id",
        "expected_outcome",
        "requested_by",
        "run_id",
        "scenario_id",
        "script_id",
        "seed",
        "timeout_secs",
    ] {
        if !contract
            .required_config_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_config_fields missing {required}"));
        }
    }

    validate_lexical_string_set(
        &contract.required_transcript_fields,
        "required_transcript_fields",
    )?;
    for required in ["correlation_id", "events", "run_id", "scenario_id", "seed"] {
        if !contract
            .required_transcript_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_transcript_fields missing {required}"));
        }
    }

    validate_lexical_string_set(
        &contract.required_artifact_index_fields,
        "required_artifact_index_fields",
    )?;
    for required in [
        "artifact_class",
        "artifact_id",
        "artifact_path",
        "checksum_hint",
    ] {
        if !contract
            .required_artifact_index_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_artifact_index_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.lifecycle_states, "lifecycle_states")?;
    for required in ["cancelled", "completed", "failed", "running", "started"] {
        if !contract
            .lifecycle_states
            .iter()
            .any(|state| state == required)
        {
            return Err(format!("lifecycle_states missing {required}"));
        }
    }

    if contract.failure_taxonomy.is_empty() {
        return Err("failure_taxonomy must be non-empty".to_string());
    }
    let failure_codes = contract
        .failure_taxonomy
        .iter()
        .map(|failure| failure.code.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&failure_codes, "failure_taxonomy.code")?;
    for required in ["config_missing", "invalid_seed", "script_timeout"] {
        if !failure_codes.iter().any(|code| code == required) {
            return Err(format!("failure_taxonomy missing required code {required}"));
        }
    }
    for failure in &contract.failure_taxonomy {
        if !matches!(
            failure.severity.as_str(),
            "critical" | "high" | "medium" | "low"
        ) {
            return Err(format!(
                "failure {} has unsupported severity {}",
                failure.code, failure.severity
            ));
        }
        if failure.operator_action.trim().is_empty() {
            return Err(format!(
                "failure {} must define operator_action",
                failure.code
            ));
        }
    }

    Ok(())
}

/// Parses deterministic harness configuration from raw key-value inputs.
///
/// # Errors
///
/// Returns `Err` when required fields are missing or invalid.
pub fn parse_e2e_harness_config(
    contract: &E2eHarnessCoreContract,
    raw: &BTreeMap<String, String>,
) -> Result<E2eHarnessConfig, String> {
    validate_e2e_harness_core_contract(contract)?;

    for field in &contract.required_config_fields {
        if raw.get(field).is_none_or(|value| value.trim().is_empty()) {
            return Err(format!("missing required config field {field}"));
        }
    }

    let run_id = raw
        .get("run_id")
        .ok_or_else(|| "missing required config field run_id".to_string())?;
    let scenario_id = raw
        .get("scenario_id")
        .ok_or_else(|| "missing required config field scenario_id".to_string())?;
    let correlation_id = raw
        .get("correlation_id")
        .ok_or_else(|| "missing required config field correlation_id".to_string())?;
    let seed = raw
        .get("seed")
        .ok_or_else(|| "missing required config field seed".to_string())?;
    let script_id = raw
        .get("script_id")
        .ok_or_else(|| "missing required config field script_id".to_string())?;
    let requested_by = raw
        .get("requested_by")
        .ok_or_else(|| "missing required config field requested_by".to_string())?;
    let timeout_secs_raw = raw
        .get("timeout_secs")
        .ok_or_else(|| "missing required config field timeout_secs".to_string())?;
    let expected_outcome = raw
        .get("expected_outcome")
        .ok_or_else(|| "missing required config field expected_outcome".to_string())?;

    for (label, value) in [
        ("run_id", run_id),
        ("scenario_id", scenario_id),
        ("correlation_id", correlation_id),
        ("seed", seed),
        ("script_id", script_id),
    ] {
        if !is_slug_like(value) {
            return Err(format!("{label} must be slug-like"));
        }
    }
    if requested_by.trim().is_empty() {
        return Err("requested_by must be non-empty".to_string());
    }
    let timeout_secs = timeout_secs_raw
        .parse::<u32>()
        .map_err(|_| "timeout_secs must parse as u32".to_string())?;
    if timeout_secs == 0 {
        return Err("timeout_secs must be greater than 0".to_string());
    }
    if !matches!(
        expected_outcome.as_str(),
        "success" | "failed" | "cancelled"
    ) {
        return Err("expected_outcome must be one of success|failed|cancelled".to_string());
    }

    Ok(E2eHarnessConfig {
        run_id: run_id.clone(),
        scenario_id: scenario_id.clone(),
        correlation_id: correlation_id.clone(),
        seed: seed.clone(),
        script_id: script_id.clone(),
        requested_by: requested_by.clone(),
        timeout_secs,
        expected_outcome: expected_outcome.clone(),
    })
}

/// Derives a deterministic stage seed from a root scenario seed.
///
/// # Errors
///
/// Returns `Err` when inputs are empty or not slug-like.
pub fn propagate_harness_seed(seed: &str, stage: &str) -> Result<String, String> {
    let root = seed.trim();
    let stage_id = stage.trim();
    if !is_slug_like(root) {
        return Err("seed must be slug-like".to_string());
    }
    if !is_slug_like(stage_id) {
        return Err("stage must be slug-like".to_string());
    }
    Ok(format!("{root}-{stage_id}"))
}

/// Builds a deterministic transcript for one harness scenario execution.
///
/// # Errors
///
/// Returns `Err` when config or stage data violates contract constraints.
pub fn build_e2e_harness_transcript(
    contract: &E2eHarnessCoreContract,
    config: &E2eHarnessConfig,
    stages: &[String],
) -> Result<E2eHarnessTranscript, String> {
    validate_e2e_harness_core_contract(contract)?;
    if stages.is_empty() {
        return Err("stages must be non-empty".to_string());
    }

    let mut events = Vec::with_capacity(stages.len());
    let last_index = stages.len() - 1;
    for (index, stage) in stages.iter().enumerate() {
        let stage_id = stage.trim();
        if !is_slug_like(stage_id) {
            return Err(format!("stage {stage_id} must be slug-like"));
        }
        let state = if index == 0 {
            "started"
        } else if index == last_index {
            match config.expected_outcome.as_str() {
                "success" => "completed",
                "failed" => "failed",
                "cancelled" => "cancelled",
                _ => return Err("unsupported expected_outcome".to_string()),
            }
        } else {
            "running"
        };
        let outcome_class = if index == last_index {
            config.expected_outcome.as_str()
        } else {
            "success"
        };
        events.push(E2eHarnessTranscriptEvent {
            sequence: u32::try_from(index + 1).map_err(|_| "sequence overflow".to_string())?,
            stage: stage_id.to_string(),
            state: state.to_string(),
            outcome_class: outcome_class.to_string(),
            message: format!("{stage_id} transitioned to {state}"),
            propagated_seed: propagate_harness_seed(&config.seed, stage_id)?,
        });
    }

    Ok(E2eHarnessTranscript {
        run_id: config.run_id.clone(),
        scenario_id: config.scenario_id.clone(),
        correlation_id: config.correlation_id.clone(),
        seed: config.seed.clone(),
        events,
    })
}

/// Builds deterministic artifact-index entries for one harness transcript.
///
/// # Errors
///
/// Returns `Err` when transcript data is invalid.
pub fn build_e2e_harness_artifact_index(
    contract: &E2eHarnessCoreContract,
    transcript: &E2eHarnessTranscript,
) -> Result<Vec<E2eHarnessArtifactIndexEntry>, String> {
    validate_e2e_harness_core_contract(contract)?;
    if transcript.events.is_empty() {
        return Err("transcript.events must be non-empty".to_string());
    }

    let base = format!("artifacts/{}/doctor/e2e", transcript.run_id);
    let mut entries = vec![
        E2eHarnessArtifactIndexEntry {
            artifact_id: format!("{}-structured-log", transcript.scenario_id),
            artifact_class: "structured_log".to_string(),
            artifact_path: format!("{base}/{}-events.jsonl", transcript.scenario_id),
            checksum_hint: format!(
                "{}-structured-log-{}",
                transcript.run_id,
                transcript.events.len()
            ),
        },
        E2eHarnessArtifactIndexEntry {
            artifact_id: format!("{}-summary", transcript.scenario_id),
            artifact_class: "summary".to_string(),
            artifact_path: format!("{base}/{}-summary.json", transcript.scenario_id),
            checksum_hint: format!("{}-summary-{}", transcript.run_id, transcript.events.len()),
        },
        E2eHarnessArtifactIndexEntry {
            artifact_id: format!("{}-transcript", transcript.scenario_id),
            artifact_class: "transcript".to_string(),
            artifact_path: format!("{base}/{}-transcript.json", transcript.scenario_id),
            checksum_hint: format!(
                "{}-transcript-{}",
                transcript.run_id,
                transcript.events.len()
            ),
        },
    ];
    entries.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let classes = entries
        .iter()
        .map(|entry| entry.artifact_class.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&classes, "artifact_index.artifact_class")?;
    for entry in &entries {
        if !entry.artifact_path.starts_with("artifacts/") {
            return Err(format!(
                "artifact_path must be under artifacts/: {}",
                entry.artifact_id
            ));
        }
        if entry.checksum_hint.trim().is_empty() {
            return Err(format!(
                "checksum_hint must be non-empty: {}",
                entry.artifact_id
            ));
        }
    }
    Ok(entries)
}

fn build_doctor_visual_harness_snapshot(
    pack: &DoctorScenarioCoveragePackSpec,
    transcript: &E2eHarnessTranscript,
    stage_outcomes: &[String],
    capture_index: u32,
) -> Result<DoctorVisualHarnessSnapshot, String> {
    let last_event = transcript
        .events
        .last()
        .ok_or_else(|| "transcript must contain at least one event".to_string())?;
    let visual_profile = match last_event.outcome_class.as_str() {
        "success" => "frankentui-stable",
        "cancelled" => "frankentui-cancel",
        _ => "frankentui-alert",
    };
    let focused_panel = if last_event.outcome_class == "success" {
        "summary_panel"
    } else {
        "triage_panel"
    };

    Ok(DoctorVisualHarnessSnapshot {
        snapshot_id: format!("snapshot-{}", pack.pack_id),
        viewport_width: DEFAULT_VISUAL_VIEWPORT_WIDTH,
        viewport_height: DEFAULT_VISUAL_VIEWPORT_HEIGHT,
        focused_panel: focused_panel.to_string(),
        selected_node_id: format!("node-{:02}", last_event.sequence),
        stage_digest: content_digest(&stage_outcomes.join("|")),
        visual_profile: visual_profile.to_string(),
        capture_index,
    })
}

fn linked_artifacts(values: &[&str]) -> Vec<String> {
    let mut linked = values
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    linked.sort();
    linked.dedup();
    linked
}

fn build_doctor_visual_harness_artifact_manifest(
    transcript: &E2eHarnessTranscript,
    artifact_index: &[E2eHarnessArtifactIndexEntry],
    snapshot: &DoctorVisualHarnessSnapshot,
) -> Result<DoctorVisualHarnessArtifactManifest, String> {
    let base = format!("artifacts/{}/doctor/e2e", transcript.run_id);
    let scenario = transcript.scenario_id.as_str();

    let mut records = artifact_index
        .iter()
        .map(|entry| {
            let linked = match entry.artifact_class.as_str() {
                "structured_log" => linked_artifacts(&[
                    &format!("{scenario}-summary"),
                    &format!("{scenario}-transcript"),
                    &format!("{scenario}-replay-metadata"),
                ]),
                "summary" => linked_artifacts(&[
                    &format!("{scenario}-structured-log"),
                    &format!("{scenario}-metrics"),
                ]),
                "transcript" => linked_artifacts(&[
                    &format!("{scenario}-structured-log"),
                    &format!("{scenario}-snapshot"),
                ]),
                _ => Vec::new(),
            };

            DoctorVisualHarnessArtifactRecord {
                artifact_id: entry.artifact_id.clone(),
                artifact_class: entry.artifact_class.clone(),
                artifact_path: entry.artifact_path.clone(),
                checksum_hint: entry.checksum_hint.clone(),
                retention_class: if entry.artifact_class == "summary" {
                    "warm".to_string()
                } else {
                    "hot".to_string()
                },
                linked_artifacts: linked,
            }
        })
        .collect::<Vec<_>>();

    records.push(DoctorVisualHarnessArtifactRecord {
        artifact_id: format!("{scenario}-snapshot"),
        artifact_class: "snapshot".to_string(),
        artifact_path: format!("{base}/{scenario}-snapshot.json"),
        checksum_hint: format!(
            "{}-snapshot-{}",
            snapshot.snapshot_id, snapshot.capture_index
        ),
        retention_class: "hot".to_string(),
        linked_artifacts: linked_artifacts(&[
            &format!("{scenario}-transcript"),
            &format!("{scenario}-summary"),
        ]),
    });
    records.push(DoctorVisualHarnessArtifactRecord {
        artifact_id: format!("{scenario}-metrics"),
        artifact_class: "metrics".to_string(),
        artifact_path: format!("{base}/{scenario}-metrics.json"),
        checksum_hint: format!("{}-metrics", transcript.run_id),
        retention_class: "warm".to_string(),
        linked_artifacts: linked_artifacts(&[
            &format!("{scenario}-summary"),
            &format!("{scenario}-replay-metadata"),
        ]),
    });
    records.push(DoctorVisualHarnessArtifactRecord {
        artifact_id: format!("{scenario}-replay-metadata"),
        artifact_class: "replay_metadata".to_string(),
        artifact_path: format!("{base}/{scenario}-replay-metadata.json"),
        checksum_hint: format!("{}-replay", transcript.run_id),
        retention_class: "warm".to_string(),
        linked_artifacts: linked_artifacts(&[
            &format!("{scenario}-structured-log"),
            &format!("{scenario}-transcript"),
        ]),
    });

    records.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    for record in &records {
        if !record.artifact_path.starts_with("artifacts/") {
            return Err(format!(
                "artifact_path must be under artifacts/: {}",
                record.artifact_id
            ));
        }
        if !matches!(record.retention_class.as_str(), "hot" | "warm") {
            return Err(format!(
                "unsupported retention_class {} for {}",
                record.retention_class, record.artifact_id
            ));
        }
        if record.checksum_hint.trim().is_empty() {
            return Err(format!(
                "checksum_hint must be non-empty for {}",
                record.artifact_id
            ));
        }
    }

    Ok(DoctorVisualHarnessArtifactManifest {
        schema_version: DOCTOR_VISUAL_HARNESS_MANIFEST_VERSION.to_string(),
        run_id: transcript.run_id.clone(),
        scenario_id: transcript.scenario_id.clone(),
        artifact_root: base,
        records,
    })
}

fn expected_terminal_state_for_outcome(expected_outcome: &str) -> Result<&'static str, String> {
    match expected_outcome {
        "success" => Ok("completed"),
        "failed" => Ok("failed"),
        "cancelled" => Ok("cancelled"),
        _ => Err(format!("unsupported expected_outcome {expected_outcome}")),
    }
}

/// Returns the canonical scenario-coverage-pack contract for doctor e2e flows.
#[must_use]
pub fn doctor_scenario_coverage_packs_contract() -> DoctorScenarioCoveragePacksContract {
    DoctorScenarioCoveragePacksContract {
        contract_version: DOCTOR_SCENARIO_COVERAGE_PACK_CONTRACT_VERSION.to_string(),
        e2e_harness_contract_version: E2E_HARNESS_CONTRACT_VERSION.to_string(),
        logging_contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        selection_modes: vec![
            "all".to_string(),
            "cancellation".to_string(),
            "degraded_dependency".to_string(),
            "recovery".to_string(),
            "retry".to_string(),
        ],
        required_pack_fields: vec![
            "description".to_string(),
            "expected_outcome".to_string(),
            "failure_cluster".to_string(),
            "pack_id".to_string(),
            "required_artifact_classes".to_string(),
            "scenario_id".to_string(),
            "stages".to_string(),
            "workflow_variant".to_string(),
        ],
        required_run_fields: vec![
            "artifact_index".to_string(),
            "artifact_manifest".to_string(),
            "expected_outcome".to_string(),
            "failure_cluster".to_string(),
            "pack_id".to_string(),
            "repro_command".to_string(),
            "scenario_id".to_string(),
            "selected_mode".to_string(),
            "status".to_string(),
            "structured_log_summary".to_string(),
            "terminal_state".to_string(),
            "transcript".to_string(),
            "visual_snapshot".to_string(),
            "workflow_variant".to_string(),
        ],
        required_log_fields: vec![
            "artifact_manifest_path".to_string(),
            "correlation_id".to_string(),
            "failure_cluster".to_string(),
            "metrics_path".to_string(),
            "outcome_class".to_string(),
            "pack_id".to_string(),
            "replay_metadata_path".to_string(),
            "scenario_id".to_string(),
            "seed".to_string(),
            "snapshot_path".to_string(),
            "stage_outcomes".to_string(),
            "transcript_path".to_string(),
        ],
        minimum_required_pack_ids: vec![
            "pack-cancellation".to_string(),
            "pack-degraded-dependency".to_string(),
            "pack-recovery".to_string(),
            "pack-retry".to_string(),
        ],
        add_pack_policy: vec![
            "New packs must declare workflow_variant and expected_outcome using canonical enums."
                .to_string(),
            "New packs must define deterministic stage ids and remain replayable with fixed seed."
                .to_string(),
            "New packs must include failure_cluster and required_artifact_classes for triage joins."
                .to_string(),
            "Any added pack must include unit coverage and be exercised by the scenario-pack e2e script."
                .to_string(),
        ],
        coverage_packs: vec![
            DoctorScenarioCoveragePackSpec {
                pack_id: "pack-cancellation".to_string(),
                scenario_id: "doctor-pack-cancellation".to_string(),
                workflow_variant: "cancellation".to_string(),
                expected_outcome: "cancelled".to_string(),
                stages: vec![
                    "bootstrap".to_string(),
                    "compose".to_string(),
                    "queue".to_string(),
                    "cancel_request".to_string(),
                    "drain_finalize".to_string(),
                ],
                required_artifact_classes: vec![
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ],
                failure_cluster: "cluster-cancellation-path".to_string(),
                description:
                    "Cancellation path coverage pack validates request->drain->finalize semantics."
                        .to_string(),
            },
            DoctorScenarioCoveragePackSpec {
                pack_id: "pack-degraded-dependency".to_string(),
                scenario_id: "doctor-pack-degraded-dependency".to_string(),
                workflow_variant: "degraded_dependency".to_string(),
                expected_outcome: "failed".to_string(),
                stages: vec![
                    "bootstrap".to_string(),
                    "compose".to_string(),
                    "queue".to_string(),
                    "dependency_degraded".to_string(),
                    "run_failed".to_string(),
                    "triage".to_string(),
                ],
                required_artifact_classes: vec![
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ],
                failure_cluster: "cluster-degraded-dependency".to_string(),
                description: "Degraded-dependency pack exercises deterministic failure diagnostics."
                    .to_string(),
            },
            DoctorScenarioCoveragePackSpec {
                pack_id: "pack-recovery".to_string(),
                scenario_id: "doctor-pack-recovery".to_string(),
                workflow_variant: "recovery".to_string(),
                expected_outcome: "success".to_string(),
                stages: vec![
                    "bootstrap".to_string(),
                    "compose".to_string(),
                    "queue".to_string(),
                    "recovery_plan".to_string(),
                    "rerun".to_string(),
                    "recovery_verify".to_string(),
                ],
                required_artifact_classes: vec![
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ],
                failure_cluster: "cluster-recovery".to_string(),
                description:
                    "Recovery pack validates deterministic remediation loop and successful rerun."
                        .to_string(),
            },
            DoctorScenarioCoveragePackSpec {
                pack_id: "pack-retry".to_string(),
                scenario_id: "doctor-pack-retry".to_string(),
                workflow_variant: "retry".to_string(),
                expected_outcome: "success".to_string(),
                stages: vec![
                    "bootstrap".to_string(),
                    "compose".to_string(),
                    "queue".to_string(),
                    "run_attempt_1".to_string(),
                    "retry_dispatch".to_string(),
                    "run_attempt_2".to_string(),
                    "verify".to_string(),
                ],
                required_artifact_classes: vec![
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ],
                failure_cluster: "cluster-retry".to_string(),
                description:
                    "Retry pack validates deterministic retry scheduling and terminal success."
                        .to_string(),
            },
        ],
    }
}

/// Validates invariants for [`DoctorScenarioCoveragePacksContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, required-variant, or schema invariants fail.
pub fn validate_doctor_scenario_coverage_packs_contract(
    contract: &DoctorScenarioCoveragePacksContract,
) -> Result<(), String> {
    if contract.contract_version != DOCTOR_SCENARIO_COVERAGE_PACK_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.e2e_harness_contract_version != E2E_HARNESS_CONTRACT_VERSION {
        return Err(format!(
            "unexpected e2e_harness_contract_version {}",
            contract.e2e_harness_contract_version
        ));
    }
    if contract.logging_contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected logging_contract_version {}",
            contract.logging_contract_version
        ));
    }

    validate_lexical_string_set(&contract.selection_modes, "selection_modes")?;
    for required_mode in [
        "all",
        "cancellation",
        "degraded_dependency",
        "recovery",
        "retry",
    ] {
        if !contract
            .selection_modes
            .iter()
            .any(|mode| mode == required_mode)
        {
            return Err(format!("selection_modes missing {required_mode}"));
        }
    }

    validate_lexical_string_set(&contract.required_pack_fields, "required_pack_fields")?;
    for required in [
        "description",
        "expected_outcome",
        "failure_cluster",
        "pack_id",
        "required_artifact_classes",
        "scenario_id",
        "stages",
        "workflow_variant",
    ] {
        if !contract
            .required_pack_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_pack_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_run_fields, "required_run_fields")?;
    for required in [
        "artifact_manifest",
        "artifact_index",
        "expected_outcome",
        "failure_cluster",
        "pack_id",
        "repro_command",
        "scenario_id",
        "selected_mode",
        "status",
        "structured_log_summary",
        "terminal_state",
        "transcript",
        "visual_snapshot",
        "workflow_variant",
    ] {
        if !contract
            .required_run_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_run_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_log_fields, "required_log_fields")?;
    for required in [
        "artifact_manifest_path",
        "correlation_id",
        "failure_cluster",
        "metrics_path",
        "outcome_class",
        "pack_id",
        "replay_metadata_path",
        "scenario_id",
        "seed",
        "snapshot_path",
        "stage_outcomes",
        "transcript_path",
    ] {
        if !contract
            .required_log_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_log_fields missing {required}"));
        }
    }

    validate_lexical_string_set(
        &contract.minimum_required_pack_ids,
        "minimum_required_pack_ids",
    )?;
    if contract.add_pack_policy.is_empty() {
        return Err("add_pack_policy must be non-empty".to_string());
    }
    if contract
        .add_pack_policy
        .iter()
        .any(|line| line.trim().is_empty())
    {
        return Err("add_pack_policy must not contain empty entries".to_string());
    }
    if contract.coverage_packs.is_empty() {
        return Err("coverage_packs must be non-empty".to_string());
    }

    let pack_ids = contract
        .coverage_packs
        .iter()
        .map(|pack| pack.pack_id.clone())
        .collect::<Vec<_>>();
    validate_lexical_string_set(&pack_ids, "coverage_packs.pack_id")?;
    for required_pack_id in &contract.minimum_required_pack_ids {
        if !pack_ids
            .iter()
            .any(|candidate| candidate == required_pack_id)
        {
            return Err(format!(
                "minimum_required_pack_ids references unknown pack_id {required_pack_id}"
            ));
        }
    }

    let mut variants = BTreeSet::new();
    for pack in &contract.coverage_packs {
        if !is_slug_like(&pack.pack_id) {
            return Err(format!("pack_id must be slug-like: {}", pack.pack_id));
        }
        if !is_slug_like(&pack.scenario_id) {
            return Err(format!(
                "scenario_id must be slug-like: {}",
                pack.scenario_id
            ));
        }
        if !matches!(
            pack.workflow_variant.as_str(),
            "cancellation" | "retry" | "degraded_dependency" | "recovery"
        ) {
            return Err(format!(
                "workflow_variant must be canonical for pack {}",
                pack.pack_id
            ));
        }
        if !matches!(
            pack.expected_outcome.as_str(),
            "success" | "failed" | "cancelled"
        ) {
            return Err(format!(
                "unsupported expected_outcome for pack {}",
                pack.pack_id
            ));
        }
        if pack.description.trim().is_empty() {
            return Err(format!(
                "description must be non-empty for pack {}",
                pack.pack_id
            ));
        }
        if !is_slug_like(&pack.failure_cluster) {
            return Err(format!(
                "failure_cluster must be slug-like for pack {}",
                pack.pack_id
            ));
        }
        validate_lexical_string_set(
            &pack.required_artifact_classes,
            &format!("coverage_packs.{}.required_artifact_classes", pack.pack_id),
        )?;
        if pack.required_artifact_classes
            != vec![
                "structured_log".to_string(),
                "summary".to_string(),
                "transcript".to_string(),
            ]
        {
            return Err(format!(
                "required_artifact_classes must be [structured_log, summary, transcript] for pack {}",
                pack.pack_id
            ));
        }
        if pack.stages.is_empty() {
            return Err(format!(
                "stages must be non-empty for pack {}",
                pack.pack_id
            ));
        }
        let mut stage_set = BTreeSet::new();
        for stage in &pack.stages {
            if !is_slug_like(stage) {
                return Err(format!(
                    "stage {stage} must be slug-like for pack {}",
                    pack.pack_id
                ));
            }
            if !stage_set.insert(stage.clone()) {
                return Err(format!("duplicate stage {stage} for pack {}", pack.pack_id));
            }
        }
        variants.insert(pack.workflow_variant.clone());
    }

    for required_variant in ["cancellation", "retry", "degraded_dependency", "recovery"] {
        if !variants.contains(required_variant) {
            return Err(format!(
                "coverage_packs missing required workflow_variant {required_variant}"
            ));
        }
    }

    Ok(())
}

/// Selects deterministic scenario packs by mode.
///
/// # Errors
///
/// Returns `Err` when mode is unsupported or validation fails.
pub fn select_doctor_scenario_coverage_packs(
    contract: &DoctorScenarioCoveragePacksContract,
    selection_mode: &str,
) -> Result<Vec<DoctorScenarioCoveragePackSpec>, String> {
    validate_doctor_scenario_coverage_packs_contract(contract)?;
    let mode = selection_mode.trim();
    if !contract
        .selection_modes
        .iter()
        .any(|candidate| candidate == mode)
    {
        return Err(format!("unsupported selection_mode {mode}"));
    }

    let mut selected = contract
        .coverage_packs
        .iter()
        .filter(|pack| mode == "all" || pack.workflow_variant == mode)
        .cloned()
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));
    if selected.is_empty() {
        return Err(format!("selection_mode {mode} produced no packs"));
    }
    Ok(selected)
}

/// Builds deterministic scenario-pack smoke report with transcript assertions.
///
/// # Errors
///
/// Returns `Err` when validation, selection, or transcript generation fails.
pub fn build_doctor_scenario_coverage_pack_smoke_report(
    contract: &DoctorScenarioCoveragePacksContract,
    selection_mode: &str,
    seed: &str,
) -> Result<DoctorScenarioCoveragePackSmokeReport, String> {
    validate_doctor_scenario_coverage_packs_contract(contract)?;
    let normalized_seed = seed.trim();
    if !is_slug_like(normalized_seed) {
        return Err("seed must be slug-like".to_string());
    }
    let mode = selection_mode.trim();
    let selected = select_doctor_scenario_coverage_packs(contract, mode)?;
    let harness_contract = e2e_harness_core_contract();

    let mut runs = Vec::with_capacity(selected.len());
    for (index, pack) in selected.iter().enumerate() {
        let run_id = format!("run-doctor-pack-{:02}-{}", index + 1, pack.pack_id);
        let correlation_id = format!("corr-{}", pack.pack_id);
        let script_id = format!("script-{}", pack.pack_id);
        let mut raw = BTreeMap::new();
        raw.insert("run_id".to_string(), run_id.clone());
        raw.insert("scenario_id".to_string(), pack.scenario_id.clone());
        raw.insert("correlation_id".to_string(), correlation_id.clone());
        raw.insert("seed".to_string(), normalized_seed.to_string());
        raw.insert("script_id".to_string(), script_id);
        raw.insert(
            "requested_by".to_string(),
            "doctor_scenario_coverage_pack_smoke".to_string(),
        );
        raw.insert("timeout_secs".to_string(), "180".to_string());
        raw.insert(
            "expected_outcome".to_string(),
            pack.expected_outcome.clone(),
        );

        let config = parse_e2e_harness_config(&harness_contract, &raw)?;
        let transcript = build_e2e_harness_transcript(&harness_contract, &config, &pack.stages)?;
        let artifact_index = build_e2e_harness_artifact_index(&harness_contract, &transcript)?;

        let expected_terminal = expected_terminal_state_for_outcome(&pack.expected_outcome)?;
        let terminal_state = transcript
            .events
            .last()
            .ok_or_else(|| format!("transcript empty for pack {}", pack.pack_id))?
            .state
            .clone();
        if terminal_state != expected_terminal {
            return Err(format!(
                "terminal_state mismatch for {}: expected {} observed {}",
                pack.pack_id, expected_terminal, terminal_state
            ));
        }

        let stage_outcomes = transcript
            .events
            .iter()
            .map(|event| format!("{}:{}:{}", event.stage, event.state, event.outcome_class))
            .collect::<Vec<_>>();
        let capture_index =
            u32::try_from(index + 1).map_err(|_| "capture_index overflow".to_string())?;
        let visual_snapshot = build_doctor_visual_harness_snapshot(
            pack,
            &transcript,
            &stage_outcomes,
            capture_index,
        )?;
        let artifact_manifest = build_doctor_visual_harness_artifact_manifest(
            &transcript,
            &artifact_index,
            &visual_snapshot,
        )?;
        let transcript_path = artifact_manifest
            .records
            .iter()
            .find(|entry| entry.artifact_class == "transcript")
            .map(|entry| entry.artifact_path.clone())
            .ok_or_else(|| format!("missing transcript artifact for {}", pack.pack_id))?;
        let snapshot_path = artifact_manifest
            .records
            .iter()
            .find(|entry| entry.artifact_class == "snapshot")
            .map(|entry| entry.artifact_path.clone())
            .ok_or_else(|| format!("missing snapshot artifact for {}", pack.pack_id))?;
        let metrics_path = artifact_manifest
            .records
            .iter()
            .find(|entry| entry.artifact_class == "metrics")
            .map(|entry| entry.artifact_path.clone())
            .ok_or_else(|| format!("missing metrics artifact for {}", pack.pack_id))?;
        let replay_metadata_path = artifact_manifest
            .records
            .iter()
            .find(|entry| entry.artifact_class == "replay_metadata")
            .map(|entry| entry.artifact_path.clone())
            .ok_or_else(|| format!("missing replay_metadata artifact for {}", pack.pack_id))?;
        let artifact_manifest_path = format!(
            "artifacts/{}/doctor/e2e/{}-artifact-index.json",
            transcript.run_id, transcript.scenario_id
        );

        runs.push(DoctorScenarioCoveragePackRun {
            pack_id: pack.pack_id.clone(),
            scenario_id: pack.scenario_id.clone(),
            workflow_variant: pack.workflow_variant.clone(),
            selected_mode: mode.to_string(),
            expected_outcome: pack.expected_outcome.clone(),
            terminal_state,
            status: "passed".to_string(),
            failure_cluster: pack.failure_cluster.clone(),
            repro_command: format!(
                "asupersync doctor scenario-coverage-pack-smoke --selection-mode {} --seed {}",
                mode, normalized_seed
            ),
            transcript,
            artifact_index,
            visual_snapshot,
            artifact_manifest,
            structured_log_summary: DoctorScenarioCoverageStructuredLogSummary {
                pack_id: pack.pack_id.clone(),
                scenario_id: pack.scenario_id.clone(),
                correlation_id,
                seed: normalized_seed.to_string(),
                stage_outcomes,
                outcome_class: pack.expected_outcome.clone(),
                failure_cluster: pack.failure_cluster.clone(),
                transcript_path,
                snapshot_path,
                metrics_path,
                replay_metadata_path,
                artifact_manifest_path,
            },
        });
    }

    runs.sort_by(|left, right| left.pack_id.cmp(&right.pack_id));
    let mut failure_clusters = runs
        .iter()
        .map(|run| run.failure_cluster.clone())
        .collect::<Vec<_>>();
    failure_clusters.sort();
    failure_clusters.dedup();

    Ok(DoctorScenarioCoveragePackSmokeReport {
        schema_version: DOCTOR_SCENARIO_COVERAGE_PACK_REPORT_VERSION.to_string(),
        selection_mode: mode.to_string(),
        requested_by: "doctor_scenario_coverage_pack_smoke".to_string(),
        seed: normalized_seed.to_string(),
        failure_clusters,
        runs,
    })
}

/// Returns the canonical beads/bv command-center contract.
#[must_use]
pub fn beads_command_center_contract() -> BeadsCommandCenterContract {
    BeadsCommandCenterContract {
        contract_version: BEADS_COMMAND_CENTER_CONTRACT_VERSION.to_string(),
        br_ready_command: "br ready --json".to_string(),
        br_blocked_command: "br blocked --json".to_string(),
        bv_triage_command: "bv --robot-triage".to_string(),
        required_ready_fields: vec![
            "id".to_string(),
            "priority".to_string(),
            "status".to_string(),
            "title".to_string(),
        ],
        required_blocker_fields: vec![
            "blocked_by".to_string(),
            "id".to_string(),
            "priority".to_string(),
            "status".to_string(),
            "title".to_string(),
        ],
        required_triage_fields: vec![
            "id".to_string(),
            "reasons".to_string(),
            "score".to_string(),
            "title".to_string(),
            "unblocks".to_string(),
        ],
        filter_modes: vec![
            "all".to_string(),
            "in_progress".to_string(),
            "open".to_string(),
            "priority_le_2".to_string(),
            "unblocked_only".to_string(),
        ],
        event_taxonomy: vec![
            "command_invoked".to_string(),
            "parse_failure".to_string(),
            "snapshot_built".to_string(),
            "stale_data_detected".to_string(),
        ],
        stale_after_secs: 300,
    }
}

/// Validates invariants for [`BeadsCommandCenterContract`].
///
/// # Errors
///
/// Returns `Err` when command strings, field requirements, or deterministic
/// ordering invariants are violated.
pub fn validate_beads_command_center_contract(
    contract: &BeadsCommandCenterContract,
) -> Result<(), String> {
    if contract.contract_version != BEADS_COMMAND_CENTER_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.br_ready_command.trim() != "br ready --json" {
        return Err("br_ready_command must be exactly `br ready --json`".to_string());
    }
    if contract.br_blocked_command.trim() != "br blocked --json" {
        return Err("br_blocked_command must be exactly `br blocked --json`".to_string());
    }
    if contract.bv_triage_command.trim() != "bv --robot-triage" {
        return Err("bv_triage_command must be exactly `bv --robot-triage`".to_string());
    }

    validate_lexical_string_set(&contract.required_ready_fields, "required_ready_fields")?;
    for required in ["id", "priority", "status", "title"] {
        if !contract
            .required_ready_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_ready_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_blocker_fields, "required_blocker_fields")?;
    for required in ["blocked_by", "id", "priority", "status", "title"] {
        if !contract
            .required_blocker_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_blocker_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_triage_fields, "required_triage_fields")?;
    for required in ["id", "reasons", "score", "title", "unblocks"] {
        if !contract
            .required_triage_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_triage_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.filter_modes, "filter_modes")?;
    for required in [
        "all",
        "in_progress",
        "open",
        "priority_le_2",
        "unblocked_only",
    ] {
        if !contract.filter_modes.iter().any(|mode| mode == required) {
            return Err(format!("filter_modes missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.event_taxonomy, "event_taxonomy")?;
    for required in [
        "command_invoked",
        "parse_failure",
        "snapshot_built",
        "stale_data_detected",
    ] {
        if !contract.event_taxonomy.iter().any(|kind| kind == required) {
            return Err(format!("event_taxonomy missing {required}"));
        }
    }

    if contract.stale_after_secs == 0 {
        return Err("stale_after_secs must be > 0".to_string());
    }
    Ok(())
}

fn parse_required_string_field(
    entry: &serde_json::Value,
    field: &str,
    source: &str,
    index: usize,
) -> Result<String, String> {
    let value = entry
        .get(field)
        .ok_or_else(|| format!("parse_failure: {source}[{index}] missing field {field}"))?;
    let text = value.as_str().ok_or_else(|| {
        format!("parse_failure: {source}[{index}] field {field} must be a string")
    })?;
    if text.trim().is_empty() {
        return Err(format!(
            "parse_failure: {source}[{index}] field {field} must be non-empty"
        ));
    }
    Ok(text.to_string())
}

fn parse_optional_string_field(
    entry: &serde_json::Value,
    field: &str,
    source: &str,
    index: usize,
) -> Result<Option<String>, String> {
    let Some(value) = entry.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = value.as_str().ok_or_else(|| {
        format!("parse_failure: {source}[{index}] field {field} must be a string")
    })?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(text.to_string()))
}

fn parse_priority_field(
    entry: &serde_json::Value,
    source: &str,
    index: usize,
) -> Result<u8, String> {
    let value = entry
        .get("priority")
        .ok_or_else(|| format!("parse_failure: {source}[{index}] missing field priority"))?;
    let raw = value.as_u64().ok_or_else(|| {
        format!("parse_failure: {source}[{index}] field priority must be an unsigned integer")
    })?;
    u8::try_from(raw)
        .map_err(|_| format!("parse_failure: {source}[{index}] field priority out of range"))
}

fn parse_required_u64_field(
    entry: &serde_json::Value,
    field: &str,
    source: &str,
    index: usize,
) -> Result<u64, String> {
    let value = entry
        .get(field)
        .ok_or_else(|| format!("parse_failure: {source}[{index}] missing field {field}"))?;
    value.as_u64().ok_or_else(|| {
        format!("parse_failure: {source}[{index}] field {field} must be an unsigned integer")
    })
}

fn parse_bool_or_binary_u64_field(
    entry: &serde_json::Value,
    field: &str,
    source: &str,
    index: usize,
) -> Result<bool, String> {
    let value = entry
        .get(field)
        .ok_or_else(|| format!("parse_failure: {source}[{index}] missing field {field}"))?;
    if let Some(boolean) = value.as_bool() {
        return Ok(boolean);
    }
    if let Some(raw) = value.as_u64() {
        return match raw {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(format!(
                "parse_failure: {source}[{index}] field {field} must be 0 or 1 when numeric"
            )),
        };
    }
    Err(format!(
        "parse_failure: {source}[{index}] field {field} must be a bool or unsigned integer"
    ))
}

fn parse_result_array(
    payload: &serde_json::Value,
    source: &str,
) -> Result<Vec<serde_json::Value>, String> {
    if let Some(entries) = payload.as_array() {
        return Ok(entries.clone());
    }
    if let Some(entries) = payload.get("result").and_then(serde_json::Value::as_array) {
        return Ok(entries.clone());
    }
    Err(format!(
        "parse_failure: {source} JSON must be an array or object containing result array"
    ))
}

/// Parses `br ready --json` output into deterministic ready-work rows.
///
/// # Errors
///
/// Returns `Err` when required fields are missing or malformed.
pub fn parse_br_ready_items(
    contract: &BeadsCommandCenterContract,
    raw_json: &str,
) -> Result<Vec<BeadsReadyWorkItem>, String> {
    validate_beads_command_center_contract(contract)?;
    let payload: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| format!("parse_failure: ready JSON: {err}"))?;
    let entries = payload
        .as_array()
        .ok_or_else(|| "parse_failure: ready JSON must be an array".to_string())?;

    let mut rows = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let id = parse_required_string_field(entry, "id", "ready", index)?;
        let title = parse_required_string_field(entry, "title", "ready", index)?;
        let status = parse_required_string_field(entry, "status", "ready", index)?;
        let priority = parse_priority_field(entry, "ready", index)?;
        let assignee = parse_optional_string_field(entry, "assignee", "ready", index)?;
        rows.push(BeadsReadyWorkItem {
            id,
            title,
            status,
            priority,
            assignee,
        });
    }
    rows.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(rows)
}

/// Parses `br blocked --json` output into deterministic blocked-work rows.
///
/// # Errors
///
/// Returns `Err` when required fields are missing or malformed.
pub fn parse_br_blocked_items(
    contract: &BeadsCommandCenterContract,
    raw_json: &str,
) -> Result<Vec<BeadsBlockedItem>, String> {
    validate_beads_command_center_contract(contract)?;
    let payload: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| format!("parse_failure: blocked JSON: {err}"))?;
    let entries = payload
        .as_array()
        .ok_or_else(|| "parse_failure: blocked JSON must be an array".to_string())?;

    let mut rows = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let id = parse_required_string_field(entry, "id", "blocked", index)?;
        let title = parse_required_string_field(entry, "title", "blocked", index)?;
        let status = parse_required_string_field(entry, "status", "blocked", index)?;
        let priority = parse_priority_field(entry, "blocked", index)?;

        let blocked_by_value = entry
            .get("blocked_by")
            .ok_or_else(|| format!("parse_failure: blocked[{index}] missing field blocked_by"))?;
        let blocked_by_entries = blocked_by_value.as_array().ok_or_else(|| {
            format!("parse_failure: blocked[{index}] field blocked_by must be an array")
        })?;
        let mut blocked_by = Vec::new();
        for (blocker_index, blocker) in blocked_by_entries.iter().enumerate() {
            if let Some(blocker_id) = blocker.as_str() {
                if blocker_id.trim().is_empty() {
                    return Err(format!(
                        "parse_failure: blocked[{index}].blocked_by[{blocker_index}] must be non-empty"
                    ));
                }
                blocked_by.push(blocker_id.to_string());
                continue;
            }
            if let Some(blocker_id) = blocker.get("id").and_then(serde_json::Value::as_str) {
                if blocker_id.trim().is_empty() {
                    return Err(format!(
                        "parse_failure: blocked[{index}].blocked_by[{blocker_index}].id must be non-empty"
                    ));
                }
                blocked_by.push(blocker_id.to_string());
                continue;
            }
            return Err(format!(
                "parse_failure: blocked[{index}].blocked_by[{blocker_index}] must be a string or object with id"
            ));
        }
        blocked_by.sort();
        blocked_by.dedup();
        rows.push(BeadsBlockedItem {
            id,
            title,
            status,
            priority,
            blocked_by,
        });
    }
    rows.sort_by(|left, right| {
        right
            .blocked_by
            .len()
            .cmp(&left.blocked_by.len())
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(rows)
}

/// Parses `bv --robot-triage` output into deterministic recommendation rows.
///
/// # Errors
///
/// Returns `Err` when triage fields are missing or malformed.
pub fn parse_bv_triage_recommendations(
    contract: &BeadsCommandCenterContract,
    raw_json: &str,
) -> Result<Vec<BvTriageRecommendation>, String> {
    validate_beads_command_center_contract(contract)?;
    let payload: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| format!("parse_failure: triage JSON: {err}"))?;
    let picks = payload
        .get("triage")
        .and_then(|triage| triage.get("quick_ref"))
        .and_then(|quick_ref| quick_ref.get("top_picks"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            "parse_failure: triage.quick_ref.top_picks must be a JSON array".to_string()
        })?;

    let mut rows = Vec::new();
    for (index, entry) in picks.iter().enumerate() {
        let id = parse_required_string_field(entry, "id", "triage", index)?;
        let title = parse_required_string_field(entry, "title", "triage", index)?;
        let score = entry
            .get("score")
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                format!("parse_failure: triage[{index}] field score must be a number")
            })?;
        let unblocks_raw = entry
            .get("unblocks")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                format!("parse_failure: triage[{index}] field unblocks must be an unsigned integer")
            })?;
        let unblocks = u32::try_from(unblocks_raw)
            .map_err(|_| format!("parse_failure: triage[{index}] field unblocks out of range"))?;
        let reasons_value = entry
            .get("reasons")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                format!("parse_failure: triage[{index}] field reasons must be an array")
            })?;
        let mut reasons = Vec::new();
        for (reason_index, reason) in reasons_value.iter().enumerate() {
            let text = reason.as_str().ok_or_else(|| {
                format!("parse_failure: triage[{index}].reasons[{reason_index}] must be a string")
            })?;
            if text.trim().is_empty() {
                return Err(format!(
                    "parse_failure: triage[{index}].reasons[{reason_index}] must be non-empty"
                ));
            }
            reasons.push(text.to_string());
        }
        reasons.sort();
        reasons.dedup();
        rows.push(BvTriageRecommendation {
            id,
            title,
            score,
            unblocks,
            reasons,
        });
    }
    rows.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(rows)
}

/// Builds one deterministic beads/bv command-center snapshot.
///
/// # Errors
///
/// Returns `Err` when the contract or filter mode is invalid.
#[allow(clippy::too_many_lines)]
pub fn build_beads_command_center_snapshot(
    contract: &BeadsCommandCenterContract,
    ready_json: &str,
    blocked_json: &str,
    triage_json: &str,
    filter_mode: &str,
    snapshot_age_secs: u64,
) -> Result<BeadsCommandCenterSnapshot, String> {
    validate_beads_command_center_contract(contract)?;
    if !contract.filter_modes.iter().any(|mode| mode == filter_mode) {
        return Err(format!("unsupported filter_mode {filter_mode}"));
    }

    let mut events = vec![
        BeadsCommandCenterEvent {
            event_kind: "command_invoked".to_string(),
            source: "ready".to_string(),
            message: contract.br_ready_command.clone(),
        },
        BeadsCommandCenterEvent {
            event_kind: "command_invoked".to_string(),
            source: "blocked".to_string(),
            message: contract.br_blocked_command.clone(),
        },
        BeadsCommandCenterEvent {
            event_kind: "command_invoked".to_string(),
            source: "triage".to_string(),
            message: contract.bv_triage_command.clone(),
        },
    ];
    let mut parse_errors = Vec::new();

    let mut ready_work = match parse_br_ready_items(contract, ready_json) {
        Ok(rows) => rows,
        Err(err) => {
            events.push(BeadsCommandCenterEvent {
                event_kind: "parse_failure".to_string(),
                source: "ready".to_string(),
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };
    let mut blocked_work = match parse_br_blocked_items(contract, blocked_json) {
        Ok(rows) => rows,
        Err(err) => {
            events.push(BeadsCommandCenterEvent {
                event_kind: "parse_failure".to_string(),
                source: "blocked".to_string(),
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };
    let mut triage = match parse_bv_triage_recommendations(contract, triage_json) {
        Ok(rows) => rows,
        Err(err) => {
            events.push(BeadsCommandCenterEvent {
                event_kind: "parse_failure".to_string(),
                source: "triage".to_string(),
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };

    match filter_mode {
        "all" => {}
        "in_progress" => {
            ready_work.retain(|item| item.status == "in_progress");
            blocked_work.retain(|item| item.status == "in_progress");
        }
        "open" => {
            ready_work.retain(|item| item.status == "open");
            blocked_work.retain(|item| item.status == "open");
        }
        "priority_le_2" => {
            ready_work.retain(|item| item.priority <= 2);
            blocked_work.retain(|item| item.priority <= 2);
        }
        "unblocked_only" => {
            let blocked_ids = blocked_work
                .iter()
                .map(|item| item.id.clone())
                .collect::<BTreeSet<_>>();
            ready_work.retain(|item| !blocked_ids.contains(&item.id));
            blocked_work.clear();
        }
        _ => {
            return Err(format!("unsupported filter_mode {filter_mode}"));
        }
    }

    triage.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });

    let stale = snapshot_age_secs > contract.stale_after_secs;
    if stale {
        events.push(BeadsCommandCenterEvent {
            event_kind: "stale_data_detected".to_string(),
            source: "snapshot".to_string(),
            message: format!(
                "snapshot age {}s exceeds stale_after_secs {}s",
                snapshot_age_secs, contract.stale_after_secs
            ),
        });
    }
    events.push(BeadsCommandCenterEvent {
        event_kind: "snapshot_built".to_string(),
        source: "snapshot".to_string(),
        message: format!(
            "ready={} blocked={} triage={} errors={}",
            ready_work.len(),
            blocked_work.len(),
            triage.len(),
            parse_errors.len()
        ),
    });

    let ready_ids = ready_work
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>()
        .join(",");
    let blocked_ids = blocked_work
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>()
        .join(",");
    let triage_ids = triage
        .iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>()
        .join(",");
    let refresh_fingerprint =
        format!("filter={filter_mode};ready={ready_ids};blocked={blocked_ids};triage={triage_ids}");

    Ok(BeadsCommandCenterSnapshot {
        schema_version: contract.contract_version.clone(),
        filter_mode: filter_mode.to_string(),
        stale,
        refresh_fingerprint,
        ready_work,
        blocked_work,
        triage,
        parse_errors,
        events,
    })
}

/// Runs a deterministic command-center smoke workflow using canonical fixtures.
///
/// # Errors
///
/// Returns `Err` when contract validation or snapshot assembly fails.
pub fn run_beads_command_center_smoke(
    contract: &BeadsCommandCenterContract,
) -> Result<BeadsCommandCenterSnapshot, String> {
    let ready_json = r#"[
  {"id":"asupersync-2b4jj.5.1","title":"Build beads and bv command-center pane","status":"open","priority":2},
  {"id":"asupersync-2b4jj.2.1","title":"Build workspace scanner for Cargo graph and capability flow","status":"in_progress","priority":1,"assignee":"PearlBadger"},
  {"id":"asupersync-2b4jj.5.2","title":"Build Agent Mail inbox-outbox and ack workflow pane","status":"open","priority":2}
]"#;
    let blocked_json = r#"[
  {
    "id":"asupersync-2b4jj.5.2",
    "title":"Build Agent Mail inbox-outbox and ack workflow pane",
    "status":"open",
    "priority":2,
    "blocked_by":[{"id":"asupersync-2b4jj.2.1"}]
  }
]"#;
    let triage_json = r#"{
  "triage": {
    "quick_ref": {
      "top_picks": [
        {
          "id":"asupersync-2b4jj.5.1",
          "title":"Build beads and bv command-center pane",
          "score":0.31,
          "unblocks":3,
          "reasons":["available","high impact"]
        },
        {
          "id":"asupersync-2b4jj.5.2",
          "title":"Build Agent Mail inbox-outbox and ack workflow pane",
          "score":0.2,
          "unblocks":2,
          "reasons":["available"]
        }
      ]
    }
  }
}"#;
    build_beads_command_center_snapshot(contract, ready_json, blocked_json, triage_json, "all", 12)
}

/// Returns the canonical Agent Mail pane contract.
#[must_use]
pub fn agent_mail_pane_contract() -> AgentMailPaneContract {
    AgentMailPaneContract {
        contract_version: AGENT_MAIL_PANE_CONTRACT_VERSION.to_string(),
        fetch_inbox_command:
            "mcp_agent_mail.fetch_inbox(project_key, agent_name, include_bodies=true, limit=50)"
                .to_string(),
        fetch_outbox_command:
            "mcp_agent_mail.search_messages(project_key, query=\"from:<agent_name>\", limit=50)"
                .to_string(),
        list_contacts_command: "mcp_agent_mail.list_contacts(project_key, agent_name)".to_string(),
        acknowledge_command:
            "mcp_agent_mail.acknowledge_message(project_key, agent_name, message_id)".to_string(),
        reply_command:
            "mcp_agent_mail.reply_message(project_key, message_id, sender_name, body_md)"
                .to_string(),
        required_message_fields: vec![
            "ack_required".to_string(),
            "created_ts".to_string(),
            "from".to_string(),
            "id".to_string(),
            "importance".to_string(),
            "subject".to_string(),
        ],
        required_contact_fields: vec![
            "reason".to_string(),
            "status".to_string(),
            "to".to_string(),
            "updated_ts".to_string(),
        ],
        thread_filter_modes: vec![
            "ack_required".to_string(),
            "all".to_string(),
            "thread_only".to_string(),
            "unacked_only".to_string(),
        ],
        event_taxonomy: vec![
            "ack_transition".to_string(),
            "command_invoked".to_string(),
            "contact_attention_required".to_string(),
            "delivery_failure".to_string(),
            "parse_failure".to_string(),
            "snapshot_built".to_string(),
            "thread_continuity_gap".to_string(),
            "thread_view_updated".to_string(),
        ],
    }
}

/// Validates invariants for [`AgentMailPaneContract`].
///
/// # Errors
///
/// Returns `Err` when command surfaces, required fields, or deterministic
/// ordering invariants are violated.
pub fn validate_agent_mail_pane_contract(contract: &AgentMailPaneContract) -> Result<(), String> {
    if contract.contract_version != AGENT_MAIL_PANE_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }

    for (key, value) in [
        ("fetch_inbox_command", &contract.fetch_inbox_command),
        ("fetch_outbox_command", &contract.fetch_outbox_command),
        ("list_contacts_command", &contract.list_contacts_command),
        ("acknowledge_command", &contract.acknowledge_command),
        ("reply_command", &contract.reply_command),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{key} must be non-empty"));
        }
    }

    validate_lexical_string_set(&contract.required_message_fields, "required_message_fields")?;
    for required in [
        "ack_required",
        "created_ts",
        "from",
        "id",
        "importance",
        "subject",
    ] {
        if !contract
            .required_message_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_message_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_contact_fields, "required_contact_fields")?;
    for required in ["reason", "status", "to", "updated_ts"] {
        if !contract
            .required_contact_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_contact_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.thread_filter_modes, "thread_filter_modes")?;
    for required in ["ack_required", "all", "thread_only", "unacked_only"] {
        if !contract
            .thread_filter_modes
            .iter()
            .any(|mode| mode == required)
        {
            return Err(format!("thread_filter_modes missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.event_taxonomy, "event_taxonomy")?;
    for required in [
        "ack_transition",
        "command_invoked",
        "contact_attention_required",
        "delivery_failure",
        "parse_failure",
        "snapshot_built",
        "thread_continuity_gap",
        "thread_view_updated",
    ] {
        if !contract.event_taxonomy.iter().any(|kind| kind == required) {
            return Err(format!("event_taxonomy missing {required}"));
        }
    }

    Ok(())
}

/// Parses Agent Mail message rows for one source stream.
///
/// # Errors
///
/// Returns `Err` when required fields are missing or malformed.
pub fn parse_agent_mail_messages(
    contract: &AgentMailPaneContract,
    raw_json: &str,
    source: &str,
    direction: &str,
) -> Result<Vec<AgentMailMessageItem>, String> {
    validate_agent_mail_pane_contract(contract)?;
    if !matches!(direction, "inbox" | "outbox") {
        return Err("direction must be inbox or outbox".to_string());
    }

    let payload: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| format!("parse_failure: {source} JSON: {err}"))?;
    let entries = parse_result_array(&payload, source)?;

    let mut rows = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let id = parse_required_u64_field(entry, "id", source, index)?;
        let subject = parse_required_string_field(entry, "subject", source, index)?;
        let from = parse_required_string_field(entry, "from", source, index)?;
        let created_ts = parse_required_string_field(entry, "created_ts", source, index)?;
        let importance = parse_required_string_field(entry, "importance", source, index)?;
        let ack_required = parse_bool_or_binary_u64_field(entry, "ack_required", source, index)?;
        let thread_id = parse_optional_string_field(entry, "thread_id", source, index)?;
        let delivery_status = if direction == "outbox" {
            parse_optional_string_field(entry, "delivery_status", source, index)?
                .unwrap_or_else(|| "sent".to_string())
        } else {
            "received".to_string()
        };

        rows.push(AgentMailMessageItem {
            id,
            subject,
            from,
            created_ts,
            importance,
            ack_required,
            acknowledged: false,
            thread_id,
            delivery_status,
            direction: direction.to_string(),
        });
    }

    rows.sort_by(|left, right| {
        left.created_ts
            .cmp(&right.created_ts)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.direction.cmp(&right.direction))
    });
    Ok(rows)
}

/// Parses Agent Mail contact rows.
///
/// # Errors
///
/// Returns `Err` when required fields are missing or malformed.
pub fn parse_agent_mail_contacts(
    contract: &AgentMailPaneContract,
    raw_json: &str,
) -> Result<Vec<AgentMailContactItem>, String> {
    validate_agent_mail_pane_contract(contract)?;
    let payload: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| format!("parse_failure: contacts JSON: {err}"))?;
    let entries = parse_result_array(&payload, "contacts")?;

    let mut contacts = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let peer = parse_required_string_field(entry, "to", "contacts", index)?;
        let status = parse_required_string_field(entry, "status", "contacts", index)?;
        let reason = parse_required_string_field(entry, "reason", "contacts", index)?;
        let updated_ts = parse_required_string_field(entry, "updated_ts", "contacts", index)?;
        let expires_ts = parse_optional_string_field(entry, "expires_ts", "contacts", index)?;

        contacts.push(AgentMailContactItem {
            peer,
            status,
            reason,
            updated_ts,
            expires_ts,
        });
    }
    contacts.sort_by(|left, right| left.peer.cmp(&right.peer));
    Ok(contacts)
}

/// Builds one deterministic Agent Mail pane snapshot.
///
/// # Errors
///
/// Returns `Err` when the contract is invalid or when thread filtering is
/// requested without an active thread.
#[allow(clippy::too_many_lines)]
pub fn build_agent_mail_pane_snapshot(
    contract: &AgentMailPaneContract,
    inbox_json: &str,
    outbox_json: &str,
    contacts_json: &str,
    active_thread: Option<&str>,
    thread_filter_mode: &str,
    acknowledged_message_ids: &[u64],
) -> Result<AgentMailPaneSnapshot, String> {
    validate_agent_mail_pane_contract(contract)?;
    if !contract
        .thread_filter_modes
        .iter()
        .any(|mode| mode == thread_filter_mode)
    {
        return Err(format!(
            "unsupported thread_filter_mode {thread_filter_mode}"
        ));
    }
    if thread_filter_mode == "thread_only" && active_thread.is_none() {
        return Err("thread_only filter requires active_thread".to_string());
    }

    let mut events = vec![
        AgentMailPaneEvent {
            event_kind: "command_invoked".to_string(),
            source: "inbox".to_string(),
            message_id: None,
            thread_id: None,
            message: contract.fetch_inbox_command.clone(),
        },
        AgentMailPaneEvent {
            event_kind: "command_invoked".to_string(),
            source: "outbox".to_string(),
            message_id: None,
            thread_id: None,
            message: contract.fetch_outbox_command.clone(),
        },
        AgentMailPaneEvent {
            event_kind: "command_invoked".to_string(),
            source: "contacts".to_string(),
            message_id: None,
            thread_id: None,
            message: contract.list_contacts_command.clone(),
        },
    ];
    let mut parse_errors = Vec::new();

    let mut inbox = match parse_agent_mail_messages(contract, inbox_json, "inbox", "inbox") {
        Ok(rows) => rows,
        Err(err) => {
            events.push(AgentMailPaneEvent {
                event_kind: "parse_failure".to_string(),
                source: "inbox".to_string(),
                message_id: None,
                thread_id: None,
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };
    let mut outbox = match parse_agent_mail_messages(contract, outbox_json, "outbox", "outbox") {
        Ok(rows) => rows,
        Err(err) => {
            events.push(AgentMailPaneEvent {
                event_kind: "parse_failure".to_string(),
                source: "outbox".to_string(),
                message_id: None,
                thread_id: None,
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };
    let contacts = match parse_agent_mail_contacts(contract, contacts_json) {
        Ok(rows) => rows,
        Err(err) => {
            events.push(AgentMailPaneEvent {
                event_kind: "parse_failure".to_string(),
                source: "contacts".to_string(),
                message_id: None,
                thread_id: None,
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };

    let acknowledged_ids = acknowledged_message_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    for message in &mut inbox {
        if message.ack_required && acknowledged_ids.contains(&message.id) {
            message.acknowledged = true;
            events.push(AgentMailPaneEvent {
                event_kind: "ack_transition".to_string(),
                source: "inbox".to_string(),
                message_id: Some(message.id),
                thread_id: message.thread_id.clone(),
                message: format!("message {} acknowledged", message.id),
            });
        }
        if !message.ack_required {
            message.acknowledged = true;
        }
    }
    for message in &mut outbox {
        if !message.ack_required {
            message.acknowledged = true;
        }
        if message.delivery_status == "failed" {
            events.push(AgentMailPaneEvent {
                event_kind: "delivery_failure".to_string(),
                source: "outbox".to_string(),
                message_id: Some(message.id),
                thread_id: message.thread_id.clone(),
                message: format!("message {} delivery failed", message.id),
            });
        }
    }

    match thread_filter_mode {
        "all" => {}
        "ack_required" => {
            inbox.retain(|message| message.ack_required);
            outbox.retain(|message| message.ack_required);
        }
        "unacked_only" => {
            inbox.retain(|message| message.ack_required && !message.acknowledged);
            outbox.retain(|message| message.ack_required && !message.acknowledged);
        }
        "thread_only" => {
            let Some(thread) = active_thread else {
                return Err("thread_only filter requires active_thread".to_string());
            };
            inbox.retain(|message| message.thread_id.as_deref() == Some(thread));
            outbox.retain(|message| message.thread_id.as_deref() == Some(thread));
        }
        _ => {
            return Err(format!(
                "unsupported thread_filter_mode {thread_filter_mode}"
            ));
        }
    }

    let selected_thread = active_thread.map(str::to_string).or_else(|| {
        inbox
            .iter()
            .chain(outbox.iter())
            .filter_map(|message| message.thread_id.clone())
            .min()
    });

    let mut thread_messages = selected_thread.as_ref().map_or_else(Vec::new, |thread_id| {
        inbox
            .iter()
            .chain(outbox.iter())
            .filter(|message| message.thread_id.as_ref() == Some(thread_id))
            .cloned()
            .collect::<Vec<_>>()
    });
    thread_messages.sort_by(|left, right| {
        left.created_ts
            .cmp(&right.created_ts)
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.direction.cmp(&right.direction))
    });

    if active_thread.is_some() && thread_messages.is_empty() {
        events.push(AgentMailPaneEvent {
            event_kind: "thread_continuity_gap".to_string(),
            source: "thread".to_string(),
            message_id: None,
            thread_id: selected_thread.clone(),
            message: "active thread has no visible messages in current snapshot".to_string(),
        });
    } else if !thread_messages.is_empty() {
        events.push(AgentMailPaneEvent {
            event_kind: "thread_view_updated".to_string(),
            source: "thread".to_string(),
            message_id: None,
            thread_id: selected_thread.clone(),
            message: format!("thread view contains {} messages", thread_messages.len()),
        });
    }

    for contact in &contacts {
        if contact.status != "approved" {
            events.push(AgentMailPaneEvent {
                event_kind: "contact_attention_required".to_string(),
                source: "contacts".to_string(),
                message_id: None,
                thread_id: None,
                message: format!("contact {} is in {} state", contact.peer, contact.status),
            });
        }
    }

    let pending_ack_count = u32::try_from(
        inbox
            .iter()
            .filter(|message| message.ack_required && !message.acknowledged)
            .count(),
    )
    .map_err(|_| "pending ack count overflow".to_string())?;

    let mut replay_commands = vec![
        contract.fetch_inbox_command.clone(),
        contract.fetch_outbox_command.clone(),
        contract.list_contacts_command.clone(),
    ];
    if pending_ack_count > 0 {
        replay_commands.push(contract.acknowledge_command.clone());
    }
    if selected_thread.is_some() {
        replay_commands.push(contract.reply_command.clone());
    }

    events.push(AgentMailPaneEvent {
        event_kind: "snapshot_built".to_string(),
        source: "snapshot".to_string(),
        message_id: None,
        thread_id: selected_thread.clone(),
        message: format!(
            "inbox={} outbox={} thread={} contacts={} pending_ack={} errors={}",
            inbox.len(),
            outbox.len(),
            thread_messages.len(),
            contacts.len(),
            pending_ack_count,
            parse_errors.len()
        ),
    });

    let inbox_fingerprint = inbox
        .iter()
        .map(|message| format!("{}:{}", message.id, message.acknowledged))
        .collect::<Vec<_>>()
        .join(",");
    let outbox_fingerprint = outbox
        .iter()
        .map(|message| format!("{}:{}", message.id, message.delivery_status))
        .collect::<Vec<_>>()
        .join(",");
    let contact_fingerprint = contacts
        .iter()
        .map(|contact| format!("{}:{}", contact.peer, contact.status))
        .collect::<Vec<_>>()
        .join(",");
    let refresh_fingerprint = format!(
        "filter={thread_filter_mode};thread={};inbox={inbox_fingerprint};outbox={outbox_fingerprint};contacts={contact_fingerprint}",
        selected_thread.as_deref().unwrap_or("-")
    );

    Ok(AgentMailPaneSnapshot {
        schema_version: contract.contract_version.clone(),
        thread_filter_mode: thread_filter_mode.to_string(),
        active_thread: selected_thread,
        refresh_fingerprint,
        inbox,
        outbox,
        thread_messages,
        contacts,
        pending_ack_count,
        replay_commands,
        parse_errors,
        events,
    })
}

/// Runs a deterministic Agent Mail workflow smoke transcript.
///
/// # Errors
///
/// Returns `Err` when any workflow snapshot assembly step fails.
#[allow(clippy::too_many_lines)]
pub fn run_agent_mail_pane_smoke(
    contract: &AgentMailPaneContract,
) -> Result<AgentMailPaneWorkflowTranscript, String> {
    let inbox_json = r#"{
  "result": [
    {
      "id": 2449,
      "subject": "Re: [coord] BlackElk online: archaeology + next bead execution",
      "importance": "normal",
      "ack_required": true,
      "created_ts": "2026-02-27T19:14:05.885632+00:00",
      "thread_id": "coord-2026-02-27-blackelk",
      "from": "BlackElk"
    },
    {
      "id": 2466,
      "subject": "[asupersync-28c51.489] Completed: Batch 42 random audit",
      "importance": "normal",
      "ack_required": false,
      "created_ts": "2026-02-27T19:59:33.302248+00:00",
      "thread_id": "asupersync-28c51.489",
      "from": "SapphireHill"
    }
  ]
}"#;
    let outbox_before_reply = r#"[
  {
    "id": 2506,
    "subject": "[asupersync-2b4jj.5.2] Start: Agent Mail inbox/outbox/ack workflow pane",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T23:52:19.925466+00:00",
    "thread_id": "asupersync-2b4jj.5.2",
    "from": "VioletStone",
    "delivery_status": "sent"
  }
]"#;
    let outbox_after_reply = r#"[
  {
    "id": 2506,
    "subject": "[asupersync-2b4jj.5.2] Start: Agent Mail inbox/outbox/ack workflow pane",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T23:52:19.925466+00:00",
    "thread_id": "asupersync-2b4jj.5.2",
    "from": "VioletStone",
    "delivery_status": "sent"
  },
  {
    "id": 2507,
    "subject": "Re: [coord] BlackElk online: archaeology + next bead execution",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T23:52:39.925466+00:00",
    "thread_id": "coord-2026-02-27-blackelk",
    "from": "VioletStone",
    "delivery_status": "sent"
  }
]"#;
    let contacts_json = r#"{
  "result": [
    {
      "to": "BlackElk",
      "status": "approved",
      "reason": "Coordinate active bead claims and avoid overlap",
      "updated_ts": "2026-02-27T18:36:16.334889+00:00",
      "expires_ts": "2026-03-06T18:36:16.334889+00:00"
    },
    {
      "to": "RainyCat",
      "status": "pending",
      "reason": "Requested coordination for thread handoff",
      "updated_ts": "2026-02-27T18:40:28.202564+00:00",
      "expires_ts": "2026-03-06T18:40:28.202564+00:00"
    }
  ]
}"#;

    let fetch_step = build_agent_mail_pane_snapshot(
        contract,
        inbox_json,
        outbox_before_reply,
        contacts_json,
        Some("coord-2026-02-27-blackelk"),
        "all",
        &[],
    )?;
    let ack_step = build_agent_mail_pane_snapshot(
        contract,
        inbox_json,
        outbox_before_reply,
        contacts_json,
        Some("coord-2026-02-27-blackelk"),
        "all",
        &[2449],
    )?;
    let reply_step = build_agent_mail_pane_snapshot(
        contract,
        inbox_json,
        outbox_after_reply,
        contacts_json,
        Some("coord-2026-02-27-blackelk"),
        "thread_only",
        &[2449],
    )?;

    Ok(AgentMailPaneWorkflowTranscript {
        scenario_id: "doctor-agent-mail-smoke".to_string(),
        steps: vec![
            AgentMailPaneWorkflowStep {
                step_id: "fetch".to_string(),
                action: "fetch inbox/outbox/contact state".to_string(),
                snapshot: fetch_step,
            },
            AgentMailPaneWorkflowStep {
                step_id: "ack".to_string(),
                action: "acknowledge pending inbox item".to_string(),
                snapshot: ack_step,
            },
            AgentMailPaneWorkflowStep {
                step_id: "reply".to_string(),
                action: "reply in-thread and verify continuity".to_string(),
                snapshot: reply_step,
            },
        ],
    })
}

/// Returns the canonical evidence-timeline explorer contract.
#[must_use]
pub fn evidence_timeline_contract() -> EvidenceTimelineContract {
    EvidenceTimelineContract {
        contract_version: EVIDENCE_TIMELINE_CONTRACT_VERSION.to_string(),
        core_report_contract_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
        timeline_source_command:
            "asupersync doctor report-contract --json && asupersync doctor logging-contract --json"
                .to_string(),
        required_node_fields: vec![
            "causal_children".to_string(),
            "causal_parents".to_string(),
            "command_refs".to_string(),
            "evidence_refs".to_string(),
            "finding_id".to_string(),
            "has_missing_links".to_string(),
            "missing_causal_refs".to_string(),
            "node_id".to_string(),
            "occurred_at".to_string(),
            "outcome_class".to_string(),
            "severity".to_string(),
            "status".to_string(),
            "title".to_string(),
        ],
        required_group_fields: vec!["group_key".to_string(), "node_ids".to_string()],
        sort_modes: vec![
            "chronological_asc".to_string(),
            "chronological_desc".to_string(),
        ],
        filter_modes: vec![
            "all".to_string(),
            "critical_only".to_string(),
            "open_only".to_string(),
            "with_missing_links".to_string(),
        ],
        group_modes: vec![
            "outcome".to_string(),
            "severity".to_string(),
            "status".to_string(),
        ],
        keyboard_bindings: vec![
            EvidenceTimelineKeyboardBinding {
                key: "enter".to_string(),
                action: "open_evidence_panel".to_string(),
                from_panel: "primary_panel".to_string(),
                to_panel: "evidence_panel".to_string(),
            },
            EvidenceTimelineKeyboardBinding {
                key: "esc".to_string(),
                action: "close_evidence_panel".to_string(),
                from_panel: "evidence_panel".to_string(),
                to_panel: "primary_panel".to_string(),
            },
            EvidenceTimelineKeyboardBinding {
                key: "j".to_string(),
                action: "cursor_next".to_string(),
                from_panel: "primary_panel".to_string(),
                to_panel: "primary_panel".to_string(),
            },
            EvidenceTimelineKeyboardBinding {
                key: "k".to_string(),
                action: "cursor_prev".to_string(),
                from_panel: "primary_panel".to_string(),
                to_panel: "primary_panel".to_string(),
            },
            EvidenceTimelineKeyboardBinding {
                key: "tab".to_string(),
                action: "focus_cycle".to_string(),
                from_panel: "context_panel".to_string(),
                to_panel: "primary_panel".to_string(),
            },
        ],
        event_taxonomy: vec![
            "causal_expansion_decision".to_string(),
            "command_invoked".to_string(),
            "missing_link_diagnostic".to_string(),
            "parse_failure".to_string(),
            "snapshot_built".to_string(),
            "timeline_interaction".to_string(),
        ],
        compatibility: ContractCompatibility {
            minimum_reader_version: EVIDENCE_TIMELINE_CONTRACT_VERSION.to_string(),
            supported_reader_versions: vec![EVIDENCE_TIMELINE_CONTRACT_VERSION.to_string()],
            migration_guidance: vec![MigrationGuidance {
                from_version: "doctor-evidence-timeline-v0".to_string(),
                to_version: EVIDENCE_TIMELINE_CONTRACT_VERSION.to_string(),
                breaking: false,
                required_actions: vec![
                    "Honor deterministic chronological sort tie-breakers by node_id.".to_string(),
                    "Treat missing causal references as explicit diagnostics, not silent drops."
                        .to_string(),
                    "Preserve timeline grouping keys exactly for downstream report/export joins."
                        .to_string(),
                ],
            }],
        },
        downstream_consumers: vec![
            "doctor-core-report-v1".to_string(),
            "doctor-report-export-json-v1".to_string(),
            "doctor-report-export-markdown-v1".to_string(),
        ],
    }
}

/// Validates invariants for [`EvidenceTimelineContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, required fields, or compatibility invariants
/// are violated.
pub fn validate_evidence_timeline_contract(
    contract: &EvidenceTimelineContract,
) -> Result<(), String> {
    if contract.contract_version != EVIDENCE_TIMELINE_CONTRACT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    if contract.core_report_contract_version != CORE_DIAGNOSTICS_REPORT_VERSION {
        return Err(format!(
            "unexpected core_report_contract_version {}",
            contract.core_report_contract_version
        ));
    }
    if contract.timeline_source_command.trim().is_empty() {
        return Err("timeline_source_command must be non-empty".to_string());
    }

    validate_lexical_string_set(&contract.required_node_fields, "required_node_fields")?;
    for required in [
        "causal_children",
        "causal_parents",
        "command_refs",
        "evidence_refs",
        "finding_id",
        "has_missing_links",
        "missing_causal_refs",
        "node_id",
        "occurred_at",
        "outcome_class",
        "severity",
        "status",
        "title",
    ] {
        if !contract
            .required_node_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_node_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.required_group_fields, "required_group_fields")?;
    for required in ["group_key", "node_ids"] {
        if !contract
            .required_group_fields
            .iter()
            .any(|field| field == required)
        {
            return Err(format!("required_group_fields missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.sort_modes, "sort_modes")?;
    for required in ["chronological_asc", "chronological_desc"] {
        if !contract.sort_modes.iter().any(|mode| mode == required) {
            return Err(format!("sort_modes missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.filter_modes, "filter_modes")?;
    for required in ["all", "critical_only", "open_only", "with_missing_links"] {
        if !contract.filter_modes.iter().any(|mode| mode == required) {
            return Err(format!("filter_modes missing {required}"));
        }
    }

    validate_lexical_string_set(&contract.group_modes, "group_modes")?;
    for required in ["outcome", "severity", "status"] {
        if !contract.group_modes.iter().any(|mode| mode == required) {
            return Err(format!("group_modes missing {required}"));
        }
    }

    if contract.keyboard_bindings.is_empty() {
        return Err("keyboard_bindings must be non-empty".to_string());
    }
    let mut binding_fingerprints = Vec::new();
    for binding in &contract.keyboard_bindings {
        if binding.key.trim().is_empty()
            || binding.action.trim().is_empty()
            || binding.from_panel.trim().is_empty()
            || binding.to_panel.trim().is_empty()
        {
            return Err("keyboard binding fields must be non-empty".to_string());
        }
        binding_fingerprints.push(format!(
            "{}|{}|{}|{}",
            binding.key, binding.action, binding.from_panel, binding.to_panel
        ));
    }
    let mut sorted_binding_fingerprints = binding_fingerprints.clone();
    sorted_binding_fingerprints.sort();
    sorted_binding_fingerprints.dedup();
    if sorted_binding_fingerprints != binding_fingerprints {
        return Err("keyboard_bindings must be unique and lexically ordered".to_string());
    }

    validate_lexical_string_set(&contract.event_taxonomy, "event_taxonomy")?;
    for required in [
        "causal_expansion_decision",
        "command_invoked",
        "missing_link_diagnostic",
        "parse_failure",
        "snapshot_built",
        "timeline_interaction",
    ] {
        if !contract.event_taxonomy.iter().any(|kind| kind == required) {
            return Err(format!("event_taxonomy missing {required}"));
        }
    }

    if contract.compatibility.minimum_reader_version != contract.contract_version {
        return Err("compatibility.minimum_reader_version must equal contract_version".to_string());
    }
    if !contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &contract.contract_version)
    {
        return Err("supported_reader_versions must include contract_version".to_string());
    }
    if contract.compatibility.migration_guidance.is_empty() {
        return Err("compatibility.migration_guidance must be non-empty".to_string());
    }

    validate_lexical_string_set(&contract.downstream_consumers, "downstream_consumers")?;
    for required in [
        "doctor-core-report-v1",
        "doctor-report-export-json-v1",
        "doctor-report-export-markdown-v1",
    ] {
        if !contract
            .downstream_consumers
            .iter()
            .any(|consumer| consumer == required)
        {
            return Err(format!("downstream_consumers missing {required}"));
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct ParsedTimelineNode {
    node_id: String,
    occurred_at: String,
    finding_id: String,
    title: String,
    severity: String,
    status: String,
    outcome_class: String,
    evidence_refs: Vec<String>,
    command_refs: Vec<String>,
    causal_refs: Vec<String>,
}

fn parse_required_string_array_field(
    entry: &serde_json::Value,
    field: &str,
    source: &str,
    index: usize,
) -> Result<Vec<String>, String> {
    let value = entry
        .get(field)
        .ok_or_else(|| format!("parse_failure: {source}[{index}] missing field {field}"))?;
    let array = value.as_array().ok_or_else(|| {
        format!("parse_failure: {source}[{index}] field {field} must be an array")
    })?;
    let mut items = Vec::new();
    for (item_index, item) in array.iter().enumerate() {
        let text = item.as_str().ok_or_else(|| {
            format!("parse_failure: {source}[{index}].{field}[{item_index}] must be a string")
        })?;
        if text.trim().is_empty() {
            return Err(format!(
                "parse_failure: {source}[{index}].{field}[{item_index}] must be non-empty"
            ));
        }
        items.push(text.to_string());
    }
    items.sort();
    items.dedup();
    Ok(items)
}

fn parse_optional_string_array_field(
    entry: &serde_json::Value,
    field: &str,
    source: &str,
    index: usize,
) -> Result<Vec<String>, String> {
    let Some(value) = entry.get(field) else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let array = value.as_array().ok_or_else(|| {
        format!("parse_failure: {source}[{index}] field {field} must be an array")
    })?;
    let mut items = Vec::new();
    for (item_index, item) in array.iter().enumerate() {
        let text = item.as_str().ok_or_else(|| {
            format!("parse_failure: {source}[{index}].{field}[{item_index}] must be a string")
        })?;
        if text.trim().is_empty() {
            return Err(format!(
                "parse_failure: {source}[{index}].{field}[{item_index}] must be non-empty"
            ));
        }
        items.push(text.to_string());
    }
    items.sort();
    items.dedup();
    Ok(items)
}

/// Parses evidence-timeline nodes from JSON payloads.
///
/// # Errors
///
/// Returns `Err` when required fields are missing, malformed, or when node ids
/// are duplicated.
pub fn parse_evidence_timeline_nodes(
    contract: &EvidenceTimelineContract,
    raw_json: &str,
) -> Result<Vec<EvidenceTimelineNode>, String> {
    validate_evidence_timeline_contract(contract)?;
    let payload: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|err| format!("parse_failure: timeline JSON: {err}"))?;
    let entries = parse_result_array(&payload, "timeline")?;

    let mut parsed = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        parsed.push(ParsedTimelineNode {
            node_id: parse_required_string_field(entry, "id", "timeline", index)?,
            occurred_at: parse_required_string_field(entry, "occurred_at", "timeline", index)?,
            finding_id: parse_required_string_field(entry, "finding_id", "timeline", index)?,
            title: parse_required_string_field(entry, "title", "timeline", index)?,
            severity: parse_required_string_field(entry, "severity", "timeline", index)?,
            status: parse_required_string_field(entry, "status", "timeline", index)?,
            outcome_class: parse_required_string_field(entry, "outcome_class", "timeline", index)?,
            evidence_refs: parse_required_string_array_field(
                entry,
                "evidence_refs",
                "timeline",
                index,
            )?,
            command_refs: parse_required_string_array_field(
                entry,
                "command_refs",
                "timeline",
                index,
            )?,
            causal_refs: parse_optional_string_array_field(
                entry,
                "causal_refs",
                "timeline",
                index,
            )?,
        });
    }

    let mut id_set = BTreeSet::new();
    for node in &parsed {
        if !id_set.insert(node.node_id.clone()) {
            return Err(format!(
                "parse_failure: duplicate timeline node id {}",
                node.node_id
            ));
        }
    }

    let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut nodes = Vec::with_capacity(parsed.len());
    for node in parsed {
        let mut causal_parents = Vec::new();
        let mut missing_causal_refs = Vec::new();
        for ref_id in node.causal_refs {
            if ref_id == node.node_id || !id_set.contains(&ref_id) {
                missing_causal_refs.push(ref_id);
                continue;
            }
            causal_parents.push(ref_id.clone());
            children
                .entry(ref_id)
                .or_default()
                .insert(node.node_id.clone());
        }
        causal_parents.sort();
        causal_parents.dedup();
        missing_causal_refs.sort();
        missing_causal_refs.dedup();
        let has_missing_links = node.evidence_refs.is_empty() || !missing_causal_refs.is_empty();
        nodes.push(EvidenceTimelineNode {
            node_id: node.node_id,
            occurred_at: node.occurred_at,
            finding_id: node.finding_id,
            title: node.title,
            severity: node.severity,
            status: node.status,
            outcome_class: node.outcome_class,
            evidence_refs: node.evidence_refs,
            command_refs: node.command_refs,
            causal_parents,
            causal_children: Vec::new(),
            missing_causal_refs,
            has_missing_links,
        });
    }

    let node_index = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| (node.node_id.clone(), index))
        .collect::<BTreeMap<_, _>>();
    for (parent_id, child_ids) in children {
        if let Some(index) = node_index.get(&parent_id).copied() {
            nodes[index].causal_children = child_ids.into_iter().collect();
        }
    }

    nodes.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    Ok(nodes)
}

/// Builds one deterministic evidence-timeline snapshot.
///
/// # Errors
///
/// Returns `Err` when the contract or selected controls are invalid.
#[allow(clippy::too_many_lines)]
pub fn build_evidence_timeline_snapshot(
    contract: &EvidenceTimelineContract,
    timeline_json: &str,
    sort_mode: &str,
    filter_mode: &str,
    group_mode: &str,
    focused_panel: &str,
    selected_node: Option<&str>,
) -> Result<EvidenceTimelineSnapshot, String> {
    validate_evidence_timeline_contract(contract)?;
    if !contract.sort_modes.iter().any(|mode| mode == sort_mode) {
        return Err(format!("unsupported sort_mode {sort_mode}"));
    }
    if !contract.filter_modes.iter().any(|mode| mode == filter_mode) {
        return Err(format!("unsupported filter_mode {filter_mode}"));
    }
    if !contract.group_modes.iter().any(|mode| mode == group_mode) {
        return Err(format!("unsupported group_mode {group_mode}"));
    }
    if !matches!(
        focused_panel,
        "context_panel" | "primary_panel" | "action_panel" | "evidence_panel"
    ) {
        return Err(format!("unsupported focused_panel {focused_panel}"));
    }

    let mut events = vec![EvidenceTimelineEvent {
        event_kind: "command_invoked".to_string(),
        source: "timeline".to_string(),
        node_id: None,
        message: contract.timeline_source_command.clone(),
    }];
    let mut parse_errors = Vec::new();

    let mut nodes = match parse_evidence_timeline_nodes(contract, timeline_json) {
        Ok(parsed) => parsed,
        Err(err) => {
            events.push(EvidenceTimelineEvent {
                event_kind: "parse_failure".to_string(),
                source: "timeline".to_string(),
                node_id: None,
                message: err.clone(),
            });
            parse_errors.push(err);
            Vec::new()
        }
    };

    match filter_mode {
        "all" => {}
        "critical_only" => nodes.retain(|node| node.severity == "critical"),
        "open_only" => nodes.retain(|node| node.status == "open" || node.status == "in_progress"),
        "with_missing_links" => nodes.retain(|node| node.has_missing_links),
        _ => return Err(format!("unsupported filter_mode {filter_mode}")),
    }

    nodes.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    if sort_mode == "chronological_desc" {
        nodes.reverse();
    }

    let selected_node = selected_node.map(str::to_string);
    let evidence_panel_node = if focused_panel == "evidence_panel" {
        selected_node.clone()
    } else {
        None
    };

    if let Some(node_id) = selected_node.as_ref() {
        if let Some(node) = nodes.iter().find(|node| node.node_id == *node_id) {
            if focused_panel == "evidence_panel" {
                events.push(EvidenceTimelineEvent {
                    event_kind: "causal_expansion_decision".to_string(),
                    source: "interaction".to_string(),
                    node_id: Some(node.node_id.clone()),
                    message: format!(
                        "expanded node {} (parents={} children={})",
                        node.node_id,
                        node.causal_parents.len(),
                        node.causal_children.len()
                    ),
                });
            }
        } else {
            events.push(EvidenceTimelineEvent {
                event_kind: "missing_link_diagnostic".to_string(),
                source: "interaction".to_string(),
                node_id: Some(node_id.clone()),
                message: "selected node does not exist in current filtered timeline".to_string(),
            });
        }
    }

    for node in &nodes {
        if node.has_missing_links {
            let detail = if node.evidence_refs.is_empty() && node.missing_causal_refs.is_empty() {
                "missing evidence refs".to_string()
            } else if node.evidence_refs.is_empty() {
                format!(
                    "missing evidence refs; missing causal refs={}",
                    node.missing_causal_refs.join(",")
                )
            } else if node.missing_causal_refs.is_empty() {
                "missing link detected".to_string()
            } else {
                format!("missing causal refs={}", node.missing_causal_refs.join(","))
            };
            events.push(EvidenceTimelineEvent {
                event_kind: "missing_link_diagnostic".to_string(),
                source: "timeline".to_string(),
                node_id: Some(node.node_id.clone()),
                message: detail,
            });
        }
    }

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for node in &nodes {
        let group_key = match group_mode {
            "severity" => node.severity.clone(),
            "status" => node.status.clone(),
            "outcome" => node.outcome_class.clone(),
            _ => return Err(format!("unsupported group_mode {group_mode}")),
        };
        grouped
            .entry(group_key)
            .or_default()
            .push(node.node_id.clone());
    }
    let groups = grouped
        .into_iter()
        .map(|(group_key, node_ids)| EvidenceTimelineGroup {
            group_key,
            node_ids,
        })
        .collect::<Vec<_>>();

    events.push(EvidenceTimelineEvent {
        event_kind: "timeline_interaction".to_string(),
        source: "interaction".to_string(),
        node_id: selected_node.clone(),
        message: format!(
            "sort={sort_mode} filter={filter_mode} group={group_mode} panel={focused_panel}"
        ),
    });
    events.push(EvidenceTimelineEvent {
        event_kind: "snapshot_built".to_string(),
        source: "snapshot".to_string(),
        node_id: selected_node.clone(),
        message: format!(
            "nodes={} groups={} errors={}",
            nodes.len(),
            groups.len(),
            parse_errors.len()
        ),
    });

    let node_fingerprint = nodes
        .iter()
        .map(|node| format!("{}@{}", node.node_id, node.occurred_at))
        .collect::<Vec<_>>()
        .join(",");
    let group_fingerprint = groups
        .iter()
        .map(|group| format!("{}={}", group.group_key, group.node_ids.join("+")))
        .collect::<Vec<_>>()
        .join(",");
    let refresh_fingerprint = format!(
        "sort={sort_mode};filter={filter_mode};group={group_mode};panel={focused_panel};selected={};nodes={node_fingerprint};groups={group_fingerprint}",
        selected_node.as_deref().unwrap_or("-")
    );

    Ok(EvidenceTimelineSnapshot {
        schema_version: contract.contract_version.clone(),
        sort_mode: sort_mode.to_string(),
        filter_mode: filter_mode.to_string(),
        group_mode: group_mode.to_string(),
        focused_panel: focused_panel.to_string(),
        selected_node,
        evidence_panel_node,
        nodes,
        groups,
        parse_errors,
        refresh_fingerprint,
        events,
    })
}

/// Runs a deterministic keyboard-driven smoke workflow for timeline drill-down.
///
/// # Errors
///
/// Returns `Err` when any workflow snapshot assembly step fails.
pub fn run_evidence_timeline_keyboard_flow_smoke(
    contract: &EvidenceTimelineContract,
) -> Result<EvidenceTimelineWorkflowTranscript, String> {
    let timeline_json = r#"{
  "result": [
    {
      "id": "timeline-001",
      "occurred_at": "2026-03-01T10:00:00Z",
      "finding_id": "finding-queue-overflow",
      "title": "Queue pressure exceeded threshold",
      "severity": "high",
      "status": "open",
      "outcome_class": "failed",
      "evidence_refs": ["evidence-001"],
      "command_refs": ["cmd-001"],
      "causal_refs": []
    },
    {
      "id": "timeline-002",
      "occurred_at": "2026-03-01T10:02:00Z",
      "finding_id": "finding-cancel-tail",
      "title": "Cancellation tail entered stalled phase",
      "severity": "critical",
      "status": "in_progress",
      "outcome_class": "failed",
      "evidence_refs": ["evidence-002"],
      "command_refs": ["cmd-002"],
      "causal_refs": ["timeline-001"]
    },
    {
      "id": "timeline-003",
      "occurred_at": "2026-03-01T10:04:00Z",
      "finding_id": "finding-ghost-link",
      "title": "Unlinked evidence node detected",
      "severity": "medium",
      "status": "open",
      "outcome_class": "cancelled",
      "evidence_refs": [],
      "command_refs": ["cmd-003"],
      "causal_refs": ["timeline-missing"]
    }
  ]
}"#;

    let boot = build_evidence_timeline_snapshot(
        contract,
        timeline_json,
        "chronological_asc",
        "all",
        "severity",
        "context_panel",
        Some("timeline-001"),
    )?;
    let focus_primary = build_evidence_timeline_snapshot(
        contract,
        timeline_json,
        "chronological_asc",
        "all",
        "severity",
        "primary_panel",
        Some("timeline-001"),
    )?;
    let cursor_next = build_evidence_timeline_snapshot(
        contract,
        timeline_json,
        "chronological_asc",
        "all",
        "severity",
        "primary_panel",
        Some("timeline-002"),
    )?;
    let drill_down = build_evidence_timeline_snapshot(
        contract,
        timeline_json,
        "chronological_asc",
        "all",
        "severity",
        "evidence_panel",
        Some("timeline-002"),
    )?;
    let close_drill = build_evidence_timeline_snapshot(
        contract,
        timeline_json,
        "chronological_asc",
        "all",
        "severity",
        "primary_panel",
        Some("timeline-002"),
    )?;

    Ok(EvidenceTimelineWorkflowTranscript {
        scenario_id: "doctor-evidence-timeline-keyboard-smoke".to_string(),
        steps: vec![
            EvidenceTimelineInteractionStep {
                step_id: "boot".to_string(),
                key_chord: "boot".to_string(),
                focused_panel: "context_panel".to_string(),
                selected_node: Some("timeline-001".to_string()),
                evidence_panel_node: None,
                snapshot: boot,
            },
            EvidenceTimelineInteractionStep {
                step_id: "focus_primary".to_string(),
                key_chord: "tab".to_string(),
                focused_panel: "primary_panel".to_string(),
                selected_node: Some("timeline-001".to_string()),
                evidence_panel_node: None,
                snapshot: focus_primary,
            },
            EvidenceTimelineInteractionStep {
                step_id: "cursor_next".to_string(),
                key_chord: "j".to_string(),
                focused_panel: "primary_panel".to_string(),
                selected_node: Some("timeline-002".to_string()),
                evidence_panel_node: None,
                snapshot: cursor_next,
            },
            EvidenceTimelineInteractionStep {
                step_id: "drill_down".to_string(),
                key_chord: "enter".to_string(),
                focused_panel: "evidence_panel".to_string(),
                selected_node: Some("timeline-002".to_string()),
                evidence_panel_node: Some("timeline-002".to_string()),
                snapshot: drill_down,
            },
            EvidenceTimelineInteractionStep {
                step_id: "close_drill".to_string(),
                key_chord: "esc".to_string(),
                focused_panel: "primary_panel".to_string(),
                selected_node: Some("timeline-002".to_string()),
                evidence_panel_node: None,
                snapshot: close_drill,
            },
        ],
    })
}

/// Returns the canonical core diagnostics-report contract.
#[must_use]
pub fn core_diagnostics_report_contract() -> CoreDiagnosticsReportContract {
    CoreDiagnosticsReportContract {
        contract_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
        required_sections: vec![
            "commands".to_string(),
            "evidence".to_string(),
            "findings".to_string(),
            "provenance".to_string(),
            "summary".to_string(),
        ],
        summary_required_fields: vec![
            "critical_findings".to_string(),
            "overall_outcome".to_string(),
            "status".to_string(),
            "total_findings".to_string(),
        ],
        finding_required_fields: vec![
            "command_refs".to_string(),
            "evidence_refs".to_string(),
            "finding_id".to_string(),
            "severity".to_string(),
            "status".to_string(),
            "title".to_string(),
        ],
        evidence_required_fields: vec![
            "artifact_pointer".to_string(),
            "evidence_id".to_string(),
            "franken_trace_id".to_string(),
            "outcome_class".to_string(),
            "replay_pointer".to_string(),
            "source".to_string(),
        ],
        command_required_fields: vec![
            "command".to_string(),
            "command_id".to_string(),
            "exit_code".to_string(),
            "outcome_class".to_string(),
            "tool".to_string(),
        ],
        provenance_required_fields: vec![
            "generated_at".to_string(),
            "generated_by".to_string(),
            "run_id".to_string(),
            "scenario_id".to_string(),
            "seed".to_string(),
            "trace_id".to_string(),
        ],
        outcome_classes: vec![
            "cancelled".to_string(),
            "failed".to_string(),
            "success".to_string(),
        ],
        logging_contract_version: STRUCTURED_LOGGING_CONTRACT_VERSION.to_string(),
        evidence_schema_version: EVIDENCE_SCHEMA_VERSION.to_string(),
        compatibility: ContractCompatibility {
            minimum_reader_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
            supported_reader_versions: vec![CORE_DIAGNOSTICS_REPORT_VERSION.to_string()],
            migration_guidance: vec![MigrationGuidance {
                from_version: "doctor-core-report-v0".to_string(),
                to_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
                breaking: false,
                required_actions: vec![
                    "Fail validation when report lists are not lexically ordered.".to_string(),
                    "Preserve command/evidence pointers exactly for deterministic replay."
                        .to_string(),
                    "Treat summary/findings/evidence/commands/provenance as required sections."
                        .to_string(),
                ],
            }],
        },
        advanced_extension_bead: "asupersync-2b4jj.5.8".to_string(),
        integration_gate_beads: vec![
            "asupersync-2b4jj.5.3".to_string(),
            "asupersync-2b4jj.5.5".to_string(),
        ],
    }
}

/// Validates invariants for [`CoreDiagnosticsReportContract`].
///
/// # Errors
///
/// Returns `Err` when ordering, schema, or compatibility invariants are violated.
pub fn validate_core_diagnostics_report_contract(
    contract: &CoreDiagnosticsReportContract,
) -> Result<(), String> {
    if contract.contract_version != CORE_DIAGNOSTICS_REPORT_VERSION {
        return Err(format!(
            "unexpected contract_version {}",
            contract.contract_version
        ));
    }
    validate_lexical_string_set(&contract.required_sections, "required_sections")?;
    for section in ["commands", "evidence", "findings", "provenance", "summary"] {
        if !contract
            .required_sections
            .iter()
            .any(|candidate| candidate == section)
        {
            return Err(format!("required_sections missing {section}"));
        }
    }
    validate_lexical_string_set(&contract.summary_required_fields, "summary_required_fields")?;
    validate_lexical_string_set(&contract.finding_required_fields, "finding_required_fields")?;
    validate_lexical_string_set(
        &contract.evidence_required_fields,
        "evidence_required_fields",
    )?;
    validate_lexical_string_set(&contract.command_required_fields, "command_required_fields")?;
    validate_lexical_string_set(
        &contract.provenance_required_fields,
        "provenance_required_fields",
    )?;
    validate_lexical_string_set(&contract.outcome_classes, "outcome_classes")?;
    for required in ["cancelled", "failed", "success"] {
        if !contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == required)
        {
            return Err(format!("outcome_classes missing required value {required}"));
        }
    }
    if contract.logging_contract_version != STRUCTURED_LOGGING_CONTRACT_VERSION {
        return Err(format!(
            "unexpected logging_contract_version {}",
            contract.logging_contract_version
        ));
    }
    if contract.evidence_schema_version != EVIDENCE_SCHEMA_VERSION {
        return Err(format!(
            "unexpected evidence_schema_version {}",
            contract.evidence_schema_version
        ));
    }
    if contract.advanced_extension_bead != "asupersync-2b4jj.5.8" {
        return Err("advanced_extension_bead must reference asupersync-2b4jj.5.8".to_string());
    }
    validate_lexical_string_set(&contract.integration_gate_beads, "integration_gate_beads")?;
    for required in ["asupersync-2b4jj.5.3", "asupersync-2b4jj.5.5"] {
        if !contract
            .integration_gate_beads
            .iter()
            .any(|candidate| candidate == required)
        {
            return Err(format!(
                "integration_gate_beads missing required value {required}"
            ));
        }
    }

    if contract
        .compatibility
        .minimum_reader_version
        .trim()
        .is_empty()
    {
        return Err("compatibility.minimum_reader_version must be non-empty".to_string());
    }
    validate_lexical_string_set(
        &contract.compatibility.supported_reader_versions,
        "compatibility.supported_reader_versions",
    )?;
    if !contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &contract.compatibility.minimum_reader_version)
    {
        return Err("minimum_reader_version missing from supported_reader_versions".to_string());
    }
    for (index, guidance) in contract.compatibility.migration_guidance.iter().enumerate() {
        if guidance.from_version.trim().is_empty() || guidance.to_version.trim().is_empty() {
            return Err(format!(
                "migration_guidance[{index}] has empty from/to version"
            ));
        }
        validate_lexical_string_set(
            &guidance.required_actions,
            &format!("migration_guidance[{index}].required_actions"),
        )?;
    }
    Ok(())
}

/// Validates one [`CoreDiagnosticsReport`] against the contract.
///
/// # Errors
///
/// Returns `Err` when required fields, ordering, or reference integrity fail.
#[allow(clippy::too_many_lines)]
pub fn validate_core_diagnostics_report(
    report: &CoreDiagnosticsReport,
    contract: &CoreDiagnosticsReportContract,
) -> Result<(), String> {
    validate_core_diagnostics_report_contract(contract)?;

    if report.schema_version != contract.contract_version {
        return Err(format!(
            "report schema_version {} does not match contract {}",
            report.schema_version, contract.contract_version
        ));
    }
    if !report.report_id.starts_with("doctor-report-") || !is_slug_like(&report.report_id) {
        return Err("report_id must match doctor-report-* slug format".to_string());
    }
    if report.summary.status.trim().is_empty() {
        return Err("summary.status must be non-empty".to_string());
    }
    if !["degraded", "failed", "healthy"]
        .iter()
        .any(|candidate| candidate == &report.summary.status.as_str())
    {
        return Err("summary.status must be one of degraded|failed|healthy".to_string());
    }
    if !contract
        .outcome_classes
        .iter()
        .any(|candidate| candidate == &report.summary.overall_outcome)
    {
        return Err(format!(
            "summary.overall_outcome {} is not supported",
            report.summary.overall_outcome
        ));
    }
    if report.summary.total_findings != report.findings.len() as u32 {
        return Err("summary.total_findings must match findings length".to_string());
    }
    let computed_critical = report
        .findings
        .iter()
        .filter(|finding| finding.severity == "critical")
        .count() as u32;
    if report.summary.critical_findings != computed_critical {
        return Err("summary.critical_findings must match critical findings count".to_string());
    }

    let finding_ids = report
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<Vec<_>>();
    if !finding_ids.is_empty() {
        validate_lexical_string_set(&finding_ids, "findings.finding_id")?;
    }

    let evidence_ids = report
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect::<Vec<_>>();
    if !evidence_ids.is_empty() {
        validate_lexical_string_set(&evidence_ids, "evidence.evidence_id")?;
    }

    let command_ids = report
        .commands
        .iter()
        .map(|command| command.command_id.clone())
        .collect::<Vec<_>>();
    if !command_ids.is_empty() {
        validate_lexical_string_set(&command_ids, "commands.command_id")?;
    }

    let evidence_set = evidence_ids.iter().collect::<BTreeSet<_>>();
    let command_set = command_ids.iter().collect::<BTreeSet<_>>();

    for finding in &report.findings {
        if finding.title.trim().is_empty() {
            return Err(format!(
                "finding {} title must be non-empty",
                finding.finding_id
            ));
        }
        if !["critical", "high", "low", "medium"]
            .iter()
            .any(|candidate| candidate == &finding.severity.as_str())
        {
            return Err(format!(
                "finding {} has unsupported severity {}",
                finding.finding_id, finding.severity
            ));
        }
        if !["in_progress", "open", "resolved"]
            .iter()
            .any(|candidate| candidate == &finding.status.as_str())
        {
            return Err(format!(
                "finding {} has unsupported status {}",
                finding.finding_id, finding.status
            ));
        }
        validate_lexical_string_set(
            &finding.evidence_refs,
            &format!("finding {} evidence_refs", finding.finding_id),
        )?;
        validate_lexical_string_set(
            &finding.command_refs,
            &format!("finding {} command_refs", finding.finding_id),
        )?;
        for evidence_ref in &finding.evidence_refs {
            if !evidence_set.contains(evidence_ref) {
                return Err(format!(
                    "finding {} references unknown evidence {}",
                    finding.finding_id, evidence_ref
                ));
            }
        }
        for command_ref in &finding.command_refs {
            if !command_set.contains(command_ref) {
                return Err(format!(
                    "finding {} references unknown command {}",
                    finding.finding_id, command_ref
                ));
            }
        }
    }

    for evidence in &report.evidence {
        if evidence.source.trim().is_empty()
            || evidence.artifact_pointer.trim().is_empty()
            || evidence.replay_pointer.trim().is_empty()
        {
            return Err(format!(
                "evidence {} must define source/artifact_pointer/replay_pointer",
                evidence.evidence_id
            ));
        }
        if !contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == &evidence.outcome_class)
        {
            return Err(format!(
                "evidence {} has unsupported outcome_class {}",
                evidence.evidence_id, evidence.outcome_class
            ));
        }
        if !evidence.franken_trace_id.starts_with("trace-")
            || !is_slug_like(&evidence.franken_trace_id)
        {
            return Err(format!(
                "evidence {} franken_trace_id must match trace-* slug format",
                evidence.evidence_id
            ));
        }
    }

    for command in &report.commands {
        if command.command.trim().is_empty() || command.tool.trim().is_empty() {
            return Err(format!(
                "command {} must define command/tool",
                command.command_id
            ));
        }
        if command.command.contains('\n') || command.command.contains('\r') {
            return Err(format!(
                "command {} must be single-line",
                command.command_id
            ));
        }
        if !is_slug_like(&command.tool) {
            return Err(format!(
                "command {} tool must be slug-like",
                command.command_id
            ));
        }
        if !contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == &command.outcome_class)
        {
            return Err(format!(
                "command {} has unsupported outcome_class {}",
                command.command_id, command.outcome_class
            ));
        }
    }

    if !report.provenance.run_id.starts_with("run-") || !is_slug_like(&report.provenance.run_id) {
        return Err("provenance.run_id must match run-* slug format".to_string());
    }
    if !is_slug_like(&report.provenance.scenario_id) {
        return Err("provenance.scenario_id must be slug-like".to_string());
    }
    if !report.provenance.trace_id.starts_with("trace-")
        || !is_slug_like(&report.provenance.trace_id)
    {
        return Err("provenance.trace_id must match trace-* slug format".to_string());
    }
    if report.provenance.seed.trim().is_empty()
        || report.provenance.generated_by.trim().is_empty()
        || report.provenance.generated_at.trim().is_empty()
    {
        return Err("provenance seed/generated_by/generated_at must be non-empty".to_string());
    }
    if !report.provenance.generated_at.contains('T') {
        return Err("provenance.generated_at must be RFC3339-like".to_string());
    }

    Ok(())
}

/// Returns deterministic core-report fixtures for happy/partial/failure paths.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn core_diagnostics_report_fixtures() -> Vec<CoreDiagnosticsFixture> {
    vec![
        CoreDiagnosticsFixture {
            fixture_id: "baseline_failure_path".to_string(),
            description:
                "Baseline failure fixture with critical finding and failed gate evidence."
                    .to_string(),
            report: CoreDiagnosticsReport {
                schema_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
                report_id: "doctor-report-failure-v1".to_string(),
                summary: CoreDiagnosticsSummary {
                    status: "failed".to_string(),
                    overall_outcome: "failed".to_string(),
                    total_findings: 2,
                    critical_findings: 1,
                },
                findings: vec![
                    CoreDiagnosticsFinding {
                        finding_id: "finding-001".to_string(),
                        title: "Obligation leak during shutdown path".to_string(),
                        severity: "critical".to_string(),
                        status: "open".to_string(),
                        evidence_refs: vec!["evidence-001".to_string()],
                        command_refs: vec!["command-001".to_string()],
                    },
                    CoreDiagnosticsFinding {
                        finding_id: "finding-002".to_string(),
                        title: "Replay mismatch for cancellation timeline".to_string(),
                        severity: "high".to_string(),
                        status: "in_progress".to_string(),
                        evidence_refs: vec!["evidence-002".to_string()],
                        command_refs: vec!["command-002".to_string()],
                    },
                ],
                evidence: vec![
                    CoreDiagnosticsEvidence {
                        evidence_id: "evidence-001".to_string(),
                        source: "structured_log".to_string(),
                        artifact_pointer: "artifacts/run-doctor-failure/doctor/core-report/finding-001.json".to_string(),
                        replay_pointer:
                            "rch exec -- cargo test -p asupersync -- obligation_leak".to_string(),
                        outcome_class: "failed".to_string(),
                        franken_trace_id: "trace-franken-failure-001".to_string(),
                    },
                    CoreDiagnosticsEvidence {
                        evidence_id: "evidence-002".to_string(),
                        source: "trace".to_string(),
                        artifact_pointer:
                            "artifacts/run-doctor-failure/doctor/core-report/trace-002.json"
                                .to_string(),
                        replay_pointer:
                            "asupersync trace verify artifacts/run-doctor-failure/trace-002.bin"
                                .to_string(),
                        outcome_class: "failed".to_string(),
                        franken_trace_id: "trace-franken-failure-002".to_string(),
                    },
                ],
                commands: vec![
                    CoreDiagnosticsCommand {
                        command_id: "command-001".to_string(),
                        command:
                            "rch exec -- cargo test -p asupersync obligation_leak -- --nocapture"
                                .to_string(),
                        tool: "rch".to_string(),
                        exit_code: 101,
                        outcome_class: "failed".to_string(),
                    },
                    CoreDiagnosticsCommand {
                        command_id: "command-002".to_string(),
                        command:
                            "asupersync trace verify artifacts/run-doctor-failure/trace-002.bin"
                                .to_string(),
                        tool: "asupersync".to_string(),
                        exit_code: 2,
                        outcome_class: "failed".to_string(),
                    },
                ],
                provenance: CoreDiagnosticsProvenance {
                    run_id: "run-doctor-failure".to_string(),
                    scenario_id: "doctor-core-report-failure".to_string(),
                    trace_id: "trace-doctor-failure".to_string(),
                    seed: "1337".to_string(),
                    generated_by: "doctor_asupersync".to_string(),
                    generated_at: "2026-02-26T06:00:00Z".to_string(),
                },
            },
        },
        CoreDiagnosticsFixture {
            fixture_id: "happy_path".to_string(),
            description: "Healthy baseline fixture with deterministic replay-ready artifacts."
                .to_string(),
            report: CoreDiagnosticsReport {
                schema_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
                report_id: "doctor-report-happy-v1".to_string(),
                summary: CoreDiagnosticsSummary {
                    status: "healthy".to_string(),
                    overall_outcome: "success".to_string(),
                    total_findings: 1,
                    critical_findings: 0,
                },
                findings: vec![CoreDiagnosticsFinding {
                    finding_id: "finding-010".to_string(),
                    title: "Baseline diagnostics fixture coverage verified".to_string(),
                    severity: "low".to_string(),
                    status: "resolved".to_string(),
                    evidence_refs: vec!["evidence-010".to_string()],
                    command_refs: vec!["command-010".to_string()],
                }],
                evidence: vec![CoreDiagnosticsEvidence {
                    evidence_id: "evidence-010".to_string(),
                    source: "benchmark".to_string(),
                    artifact_pointer:
                        "artifacts/run-doctor-happy/doctor/core-report/benchmark-010.json"
                            .to_string(),
                    replay_pointer:
                        "rch exec -- cargo test -p asupersync doctor_core_report_smoke"
                            .to_string(),
                    outcome_class: "success".to_string(),
                    franken_trace_id: "trace-franken-happy-010".to_string(),
                }],
                commands: vec![CoreDiagnosticsCommand {
                    command_id: "command-010".to_string(),
                    command:
                        "rch exec -- cargo test -p asupersync doctor_core_report_smoke -- --nocapture"
                            .to_string(),
                    tool: "rch".to_string(),
                    exit_code: 0,
                    outcome_class: "success".to_string(),
                }],
                provenance: CoreDiagnosticsProvenance {
                    run_id: "run-doctor-happy".to_string(),
                    scenario_id: "doctor-core-report-happy".to_string(),
                    trace_id: "trace-doctor-happy".to_string(),
                    seed: "2026".to_string(),
                    generated_by: "doctor_asupersync".to_string(),
                    generated_at: "2026-02-26T06:01:00Z".to_string(),
                },
            },
        },
        CoreDiagnosticsFixture {
            fixture_id: "partial_data_path".to_string(),
            description:
                "Partial-data fixture with cancelled outcome and minimal still-valid envelope."
                    .to_string(),
            report: CoreDiagnosticsReport {
                schema_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
                report_id: "doctor-report-partial-v1".to_string(),
                summary: CoreDiagnosticsSummary {
                    status: "degraded".to_string(),
                    overall_outcome: "cancelled".to_string(),
                    total_findings: 0,
                    critical_findings: 0,
                },
                findings: Vec::new(),
                evidence: vec![CoreDiagnosticsEvidence {
                    evidence_id: "evidence-020".to_string(),
                    source: "structured_log".to_string(),
                    artifact_pointer:
                        "artifacts/run-doctor-partial/doctor/core-report/structured-log-020.json"
                            .to_string(),
                    replay_pointer:
                        "rch exec -- cargo test -p asupersync doctor_partial_report -- --nocapture"
                            .to_string(),
                    outcome_class: "cancelled".to_string(),
                    franken_trace_id: "trace-franken-partial-020".to_string(),
                }],
                commands: vec![CoreDiagnosticsCommand {
                    command_id: "command-020".to_string(),
                    command:
                        "rch exec -- cargo test -p asupersync doctor_partial_report -- --nocapture"
                            .to_string(),
                    tool: "rch".to_string(),
                    exit_code: 130,
                    outcome_class: "cancelled".to_string(),
                }],
                provenance: CoreDiagnosticsProvenance {
                    run_id: "run-doctor-partial".to_string(),
                    scenario_id: "doctor-core-report-partial".to_string(),
                    trace_id: "trace-doctor-partial".to_string(),
                    seed: "777".to_string(),
                    generated_by: "doctor_asupersync".to_string(),
                    generated_at: "2026-02-26T06:02:00Z".to_string(),
                },
            },
        },
    ]
}

/// Returns a serializable bundle containing contract + deterministic fixtures.
#[must_use]
pub fn core_diagnostics_report_bundle() -> CoreDiagnosticsReportBundle {
    CoreDiagnosticsReportBundle {
        contract: core_diagnostics_report_contract(),
        fixtures: core_diagnostics_report_fixtures(),
    }
}

/// Runs deterministic core-report fixture smoke and emits structured-log events.
///
/// # Errors
///
/// Returns `Err` when contract/report validation or log emission fails.
pub fn run_core_diagnostics_report_smoke(
    bundle: &CoreDiagnosticsReportBundle,
    logging_contract: &StructuredLoggingContract,
) -> Result<Vec<StructuredLogEvent>, String> {
    validate_core_diagnostics_report_contract(&bundle.contract)?;
    validate_lexical_string_set(
        &bundle
            .fixtures
            .iter()
            .map(|fixture| fixture.fixture_id.clone())
            .collect::<Vec<_>>(),
        "core diagnostics fixture_id",
    )?;
    let mut events = Vec::new();
    for fixture in &bundle.fixtures {
        if fixture.description.trim().is_empty() {
            return Err(format!(
                "fixture {} must define non-empty description",
                fixture.fixture_id
            ));
        }
        validate_core_diagnostics_report(&fixture.report, &bundle.contract)?;
        for flow_id in ["execution", "integration", "remediation", "replay"] {
            let mut fields = BTreeMap::new();
            fields.insert(
                "artifact_pointer".to_string(),
                format!(
                    "artifacts/{}/doctor/core-report/{}.json",
                    fixture.report.provenance.run_id, fixture.fixture_id
                ),
            );
            fields.insert(
                "command_provenance".to_string(),
                format!(
                    "asupersync doctor report-contract --fixture {}",
                    fixture.fixture_id
                ),
            );
            fields.insert("flow_id".to_string(), flow_id.to_string());
            fields.insert(
                "outcome_class".to_string(),
                fixture.report.summary.overall_outcome.clone(),
            );
            fields.insert(
                "run_id".to_string(),
                fixture.report.provenance.run_id.clone(),
            );
            fields.insert(
                "scenario_id".to_string(),
                fixture.report.provenance.scenario_id.clone(),
            );
            fields.insert(
                "trace_id".to_string(),
                fixture.report.provenance.trace_id.clone(),
            );
            let event = emit_structured_log_event(
                logging_contract,
                flow_id,
                "verification_summary",
                &fields,
            )?;
            events.push(event);
        }
    }
    events.sort_by(|left, right| {
        (
            left.flow_id.as_str(),
            left.event_kind.as_str(),
            left.fields
                .get("trace_id")
                .map(String::as_str)
                .unwrap_or_default(),
        )
            .cmp(&(
                right.flow_id.as_str(),
                right.event_kind.as_str(),
                right
                    .fields
                    .get("trace_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ))
    });
    Ok(events)
}

fn advanced_taxonomy_allowlists() -> (Vec<String>, Vec<String>, Vec<String>) {
    let taxonomy = crate::observability::diagnostics::advanced_observability_contract();
    let mut classes = taxonomy
        .event_classes
        .iter()
        .map(|entry| entry.class_id.clone())
        .collect::<Vec<_>>();
    classes.sort();
    classes.dedup();
    let mut dimensions = taxonomy
        .troubleshooting_dimensions
        .iter()
        .map(|entry| entry.dimension.clone())
        .collect::<Vec<_>>();
    dimensions.sort();
    dimensions.dedup();
    let mut severities = taxonomy
        .severity_semantics
        .iter()
        .map(|entry| entry.severity.clone())
        .collect::<Vec<_>>();
    severities.sort();
    severities.dedup();
    (classes, dimensions, severities)
}

/// Returns the canonical advanced diagnostics-report extension contract.
#[must_use]
pub fn advanced_diagnostics_report_extension_contract() -> AdvancedDiagnosticsReportExtensionContract
{
    let (class_allowlist, dimension_allowlist, severity_allowlist) = advanced_taxonomy_allowlists();
    AdvancedDiagnosticsReportExtensionContract {
        contract_version: ADVANCED_DIAGNOSTICS_REPORT_VERSION.to_string(),
        base_contract_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
        taxonomy_contract_version:
            crate::observability::diagnostics::ADVANCED_OBSERVABILITY_CONTRACT_VERSION.to_string(),
        required_extension_sections: vec![
            "collaboration_trail".to_string(),
            "remediation_deltas".to_string(),
            "troubleshooting_playbooks".to_string(),
            "trust_transitions".to_string(),
        ],
        remediation_delta_required_fields: vec![
            "delta_id".to_string(),
            "delta_outcome".to_string(),
            "finding_id".to_string(),
            "mapped_taxonomy_class".to_string(),
            "mapped_taxonomy_dimension".to_string(),
            "next_status".to_string(),
            "previous_status".to_string(),
            "verification_evidence_refs".to_string(),
        ],
        trust_transition_required_fields: vec![
            "mapped_taxonomy_severity".to_string(),
            "next_score".to_string(),
            "outcome_class".to_string(),
            "previous_score".to_string(),
            "rationale".to_string(),
            "stage".to_string(),
            "transition_id".to_string(),
        ],
        collaboration_required_fields: vec![
            "action".to_string(),
            "actor".to_string(),
            "bead_ref".to_string(),
            "channel".to_string(),
            "entry_id".to_string(),
            "mapped_taxonomy_narrative".to_string(),
            "message_ref".to_string(),
            "thread_id".to_string(),
        ],
        playbook_required_fields: vec![
            "command_refs".to_string(),
            "evidence_refs".to_string(),
            "ordered_steps".to_string(),
            "playbook_id".to_string(),
            "title".to_string(),
            "trigger_taxonomy_class".to_string(),
            "trigger_taxonomy_severity".to_string(),
        ],
        outcome_classes: vec![
            "cancelled".to_string(),
            "failed".to_string(),
            "success".to_string(),
        ],
        taxonomy_mapping: AdvancedDiagnosticsTaxonomyMapping {
            class_allowlist,
            dimension_allowlist,
            severity_allowlist,
        },
        compatibility: ContractCompatibility {
            minimum_reader_version: ADVANCED_DIAGNOSTICS_REPORT_VERSION.to_string(),
            supported_reader_versions: vec![ADVANCED_DIAGNOSTICS_REPORT_VERSION.to_string()],
            migration_guidance: vec![MigrationGuidance {
                from_version: "doctor-advanced-report-v0".to_string(),
                to_version: ADVANCED_DIAGNOSTICS_REPORT_VERSION.to_string(),
                breaking: false,
                required_actions: vec![
                    "Map extension taxonomy fields to doctor-observability-v1 allowlists."
                        .to_string(),
                    "Preserve deterministic lexical ordering for all extension vectors."
                        .to_string(),
                    "Validate extension references against base core report ids.".to_string(),
                ],
            }],
        },
        integration_handoff_bead: "asupersync-2b4jj.5.5".to_string(),
    }
}

/// Validates invariants for [`AdvancedDiagnosticsReportExtensionContract`].
///
/// # Errors
///
/// Returns `Err` when schema, ordering, compatibility, or taxonomy mapping invariants are violated.
#[allow(clippy::too_many_lines)]
pub fn validate_advanced_diagnostics_report_extension_contract(
    contract: &AdvancedDiagnosticsReportExtensionContract,
) -> Result<(), String> {
    if contract.contract_version != ADVANCED_DIAGNOSTICS_REPORT_VERSION {
        return Err(format!(
            "unexpected advanced contract_version {}",
            contract.contract_version
        ));
    }
    if contract.base_contract_version != CORE_DIAGNOSTICS_REPORT_VERSION {
        return Err(format!(
            "unexpected base_contract_version {}",
            contract.base_contract_version
        ));
    }
    if contract.taxonomy_contract_version
        != crate::observability::diagnostics::ADVANCED_OBSERVABILITY_CONTRACT_VERSION
    {
        return Err(format!(
            "unexpected taxonomy_contract_version {}",
            contract.taxonomy_contract_version
        ));
    }
    validate_lexical_string_set(
        &contract.required_extension_sections,
        "required_extension_sections",
    )?;
    for required in [
        "collaboration_trail",
        "remediation_deltas",
        "troubleshooting_playbooks",
        "trust_transitions",
    ] {
        if !contract
            .required_extension_sections
            .iter()
            .any(|candidate| candidate == required)
        {
            return Err(format!("required_extension_sections missing {required}"));
        }
    }
    validate_lexical_string_set(
        &contract.remediation_delta_required_fields,
        "remediation_delta_required_fields",
    )?;
    validate_lexical_string_set(
        &contract.trust_transition_required_fields,
        "trust_transition_required_fields",
    )?;
    validate_lexical_string_set(
        &contract.collaboration_required_fields,
        "collaboration_required_fields",
    )?;
    validate_lexical_string_set(
        &contract.playbook_required_fields,
        "playbook_required_fields",
    )?;
    validate_lexical_string_set(&contract.outcome_classes, "outcome_classes")?;
    for required in ["cancelled", "failed", "success"] {
        if !contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == required)
        {
            return Err(format!("outcome_classes missing required value {required}"));
        }
    }

    validate_lexical_string_set(
        &contract.taxonomy_mapping.class_allowlist,
        "taxonomy_mapping.class_allowlist",
    )?;
    validate_lexical_string_set(
        &contract.taxonomy_mapping.dimension_allowlist,
        "taxonomy_mapping.dimension_allowlist",
    )?;
    validate_lexical_string_set(
        &contract.taxonomy_mapping.severity_allowlist,
        "taxonomy_mapping.severity_allowlist",
    )?;

    let (taxonomy_classes, taxonomy_dimensions, taxonomy_severities) =
        advanced_taxonomy_allowlists();
    for class in &contract.taxonomy_mapping.class_allowlist {
        if !taxonomy_classes.iter().any(|candidate| candidate == class) {
            return Err(format!(
                "taxonomy class {class} is not defined in advanced taxonomy"
            ));
        }
    }
    for dimension in &contract.taxonomy_mapping.dimension_allowlist {
        if !taxonomy_dimensions
            .iter()
            .any(|candidate| candidate == dimension)
        {
            return Err(format!(
                "taxonomy dimension {dimension} is not defined in advanced taxonomy"
            ));
        }
    }
    for severity in &contract.taxonomy_mapping.severity_allowlist {
        if !taxonomy_severities
            .iter()
            .any(|candidate| candidate == severity)
        {
            return Err(format!(
                "taxonomy severity {severity} is not defined in advanced taxonomy"
            ));
        }
    }

    if contract
        .compatibility
        .minimum_reader_version
        .trim()
        .is_empty()
    {
        return Err("compatibility.minimum_reader_version must be non-empty".to_string());
    }
    validate_lexical_string_set(
        &contract.compatibility.supported_reader_versions,
        "compatibility.supported_reader_versions",
    )?;
    if !contract
        .compatibility
        .supported_reader_versions
        .iter()
        .any(|version| version == &contract.compatibility.minimum_reader_version)
    {
        return Err("minimum_reader_version missing from supported_reader_versions".to_string());
    }
    for (index, guidance) in contract.compatibility.migration_guidance.iter().enumerate() {
        if guidance.from_version.trim().is_empty() || guidance.to_version.trim().is_empty() {
            return Err(format!(
                "migration_guidance[{index}] has empty from/to version"
            ));
        }
        validate_lexical_string_set(
            &guidance.required_actions,
            &format!("migration_guidance[{index}].required_actions"),
        )?;
    }
    if contract.integration_handoff_bead != "asupersync-2b4jj.5.5" {
        return Err("integration_handoff_bead must reference asupersync-2b4jj.5.5".to_string());
    }
    Ok(())
}

/// Validates one advanced diagnostics extension against base report + contracts.
///
/// # Errors
///
/// Returns `Err` when schema linkage, ordering, taxonomy mapping, or reference integrity fails.
#[allow(clippy::too_many_lines)]
pub fn validate_advanced_diagnostics_report_extension(
    extension: &AdvancedDiagnosticsReportExtension,
    core_report: &CoreDiagnosticsReport,
    extension_contract: &AdvancedDiagnosticsReportExtensionContract,
    core_contract: &CoreDiagnosticsReportContract,
) -> Result<(), String> {
    validate_core_diagnostics_report(core_report, core_contract)?;
    validate_advanced_diagnostics_report_extension_contract(extension_contract)?;

    if extension.schema_version != extension_contract.contract_version {
        return Err(format!(
            "extension schema_version {} does not match contract {}",
            extension.schema_version, extension_contract.contract_version
        ));
    }
    if extension.base_report_schema_version != core_contract.contract_version {
        return Err(format!(
            "extension base_report_schema_version {} does not match core contract {}",
            extension.base_report_schema_version, core_contract.contract_version
        ));
    }
    if extension.base_report_id != core_report.report_id {
        return Err("extension base_report_id must match core report_id".to_string());
    }

    let remediation_ids = extension
        .remediation_deltas
        .iter()
        .map(|delta| delta.delta_id.clone())
        .collect::<Vec<_>>();
    if !remediation_ids.is_empty() {
        validate_lexical_string_set(&remediation_ids, "remediation_deltas.delta_id")?;
    }
    let trust_ids = extension
        .trust_transitions
        .iter()
        .map(|transition| transition.transition_id.clone())
        .collect::<Vec<_>>();
    if !trust_ids.is_empty() {
        validate_lexical_string_set(&trust_ids, "trust_transitions.transition_id")?;
    }
    let collaboration_ids = extension
        .collaboration_trail
        .iter()
        .map(|entry| entry.entry_id.clone())
        .collect::<Vec<_>>();
    if !collaboration_ids.is_empty() {
        validate_lexical_string_set(&collaboration_ids, "collaboration_trail.entry_id")?;
    }
    let playbook_ids = extension
        .troubleshooting_playbooks
        .iter()
        .map(|entry| entry.playbook_id.clone())
        .collect::<Vec<_>>();
    if !playbook_ids.is_empty() {
        validate_lexical_string_set(&playbook_ids, "troubleshooting_playbooks.playbook_id")?;
    }

    let finding_ids = core_report
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect::<BTreeSet<_>>();
    let evidence_ids = core_report
        .evidence
        .iter()
        .map(|evidence| evidence.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    let command_ids = core_report
        .commands
        .iter()
        .map(|command| command.command_id.clone())
        .collect::<BTreeSet<_>>();

    for delta in &extension.remediation_deltas {
        if !finding_ids.contains(&delta.finding_id) {
            return Err(format!(
                "remediation delta {} references unknown finding {}",
                delta.delta_id, delta.finding_id
            ));
        }
        if !["in_progress", "open", "resolved"]
            .iter()
            .any(|candidate| candidate == &delta.previous_status.as_str())
            || !["in_progress", "open", "resolved"]
                .iter()
                .any(|candidate| candidate == &delta.next_status.as_str())
        {
            return Err(format!(
                "remediation delta {} has unsupported status transition {} -> {}",
                delta.delta_id, delta.previous_status, delta.next_status
            ));
        }
        if !extension_contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == &delta.delta_outcome)
        {
            return Err(format!(
                "remediation delta {} has unsupported outcome {}",
                delta.delta_id, delta.delta_outcome
            ));
        }
        if !extension_contract
            .taxonomy_mapping
            .class_allowlist
            .iter()
            .any(|candidate| candidate == &delta.mapped_taxonomy_class)
        {
            return Err(format!(
                "remediation delta {} has unsupported taxonomy class {}",
                delta.delta_id, delta.mapped_taxonomy_class
            ));
        }
        if !extension_contract
            .taxonomy_mapping
            .dimension_allowlist
            .iter()
            .any(|candidate| candidate == &delta.mapped_taxonomy_dimension)
        {
            return Err(format!(
                "remediation delta {} has unsupported taxonomy dimension {}",
                delta.delta_id, delta.mapped_taxonomy_dimension
            ));
        }
        validate_lexical_string_set(
            &delta.verification_evidence_refs,
            &format!(
                "remediation delta {} verification_evidence_refs",
                delta.delta_id
            ),
        )?;
        for reference in &delta.verification_evidence_refs {
            if !evidence_ids.contains(reference) {
                return Err(format!(
                    "remediation delta {} references unknown evidence {}",
                    delta.delta_id, reference
                ));
            }
        }
    }

    for transition in &extension.trust_transitions {
        if !extension_contract
            .outcome_classes
            .iter()
            .any(|candidate| candidate == &transition.outcome_class)
        {
            return Err(format!(
                "trust transition {} has unsupported outcome {}",
                transition.transition_id, transition.outcome_class
            ));
        }
        if !extension_contract
            .taxonomy_mapping
            .severity_allowlist
            .iter()
            .any(|candidate| candidate == &transition.mapped_taxonomy_severity)
        {
            return Err(format!(
                "trust transition {} has unsupported taxonomy severity {}",
                transition.transition_id, transition.mapped_taxonomy_severity
            ));
        }
        if transition.rationale.trim().is_empty() || transition.stage.trim().is_empty() {
            return Err(format!(
                "trust transition {} must define stage and rationale",
                transition.transition_id
            ));
        }
    }

    for entry in &extension.collaboration_trail {
        if entry.channel.trim().is_empty()
            || entry.actor.trim().is_empty()
            || entry.action.trim().is_empty()
            || entry.thread_id.trim().is_empty()
            || entry.message_ref.trim().is_empty()
            || entry.bead_ref.trim().is_empty()
            || entry.mapped_taxonomy_narrative.trim().is_empty()
        {
            return Err(format!(
                "collaboration entry {} has empty required fields",
                entry.entry_id
            ));
        }
    }

    for playbook in &extension.troubleshooting_playbooks {
        if !extension_contract
            .taxonomy_mapping
            .class_allowlist
            .iter()
            .any(|candidate| candidate == &playbook.trigger_taxonomy_class)
        {
            return Err(format!(
                "playbook {} has unsupported taxonomy class {}",
                playbook.playbook_id, playbook.trigger_taxonomy_class
            ));
        }
        if !extension_contract
            .taxonomy_mapping
            .severity_allowlist
            .iter()
            .any(|candidate| candidate == &playbook.trigger_taxonomy_severity)
        {
            return Err(format!(
                "playbook {} has unsupported taxonomy severity {}",
                playbook.playbook_id, playbook.trigger_taxonomy_severity
            ));
        }
        if playbook.title.trim().is_empty() {
            return Err(format!(
                "playbook {} must define title",
                playbook.playbook_id
            ));
        }
        validate_lexical_string_set(
            &playbook.ordered_steps,
            &format!("playbook {} ordered_steps", playbook.playbook_id),
        )?;
        validate_lexical_string_set(
            &playbook.command_refs,
            &format!("playbook {} command_refs", playbook.playbook_id),
        )?;
        validate_lexical_string_set(
            &playbook.evidence_refs,
            &format!("playbook {} evidence_refs", playbook.playbook_id),
        )?;
        for command_ref in &playbook.command_refs {
            if !command_ids.contains(command_ref) {
                return Err(format!(
                    "playbook {} references unknown command {}",
                    playbook.playbook_id, command_ref
                ));
            }
        }
        for evidence_ref in &playbook.evidence_refs {
            if !evidence_ids.contains(evidence_ref) {
                return Err(format!(
                    "playbook {} references unknown evidence {}",
                    playbook.playbook_id, evidence_ref
                ));
            }
        }
    }
    Ok(())
}

/// Returns deterministic advanced diagnostics fixtures built on core-report fixtures.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn advanced_diagnostics_report_fixtures() -> Vec<AdvancedDiagnosticsFixture> {
    let core_fixtures = core_diagnostics_report_fixtures();
    let failure = core_fixtures
        .iter()
        .find(|fixture| fixture.fixture_id == "baseline_failure_path")
        .expect("baseline failure fixture exists")
        .report
        .clone();
    let happy = core_fixtures
        .iter()
        .find(|fixture| fixture.fixture_id == "happy_path")
        .expect("happy fixture exists")
        .report
        .clone();

    vec![
        AdvancedDiagnosticsFixture {
            fixture_id: "advanced_failure_path".to_string(),
            description:
                "Failure-path extension fixture with remediation delta and collaboration trail."
                    .to_string(),
            core_report: failure,
            extension: AdvancedDiagnosticsReportExtension {
                schema_version: ADVANCED_DIAGNOSTICS_REPORT_VERSION.to_string(),
                base_report_id: "doctor-report-failure-v1".to_string(),
                base_report_schema_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
                remediation_deltas: vec![AdvancedRemediationDelta {
                    delta_id: "delta-001".to_string(),
                    finding_id: "finding-001".to_string(),
                    previous_status: "open".to_string(),
                    next_status: "in_progress".to_string(),
                    delta_outcome: "failed".to_string(),
                    mapped_taxonomy_class: "remediation_safety".to_string(),
                    mapped_taxonomy_dimension: "recovery_planning".to_string(),
                    verification_evidence_refs: vec!["evidence-001".to_string()],
                }],
                trust_transitions: vec![AdvancedTrustTransition {
                    transition_id: "trust-001".to_string(),
                    stage: "post-remediation-attempt".to_string(),
                    previous_score: 82,
                    next_score: 44,
                    outcome_class: "failed".to_string(),
                    mapped_taxonomy_severity: "error".to_string(),
                    rationale: "Critical finding persisted after first remediation pass."
                        .to_string(),
                }],
                collaboration_trail: vec![AdvancedCollaborationEntry {
                    entry_id: "collab-001".to_string(),
                    channel: "agent_mail".to_string(),
                    actor: "ChartreuseBrook".to_string(),
                    action: "requested remediation follow-up".to_string(),
                    thread_id: "br-2b4jj.5.8".to_string(),
                    message_ref: "mail-advanced-001".to_string(),
                    bead_ref: "asupersync-2b4jj.5.8".to_string(),
                    mapped_taxonomy_narrative:
                        "Remediation safety remained degraded after failed verification."
                            .to_string(),
                }],
                troubleshooting_playbooks: vec![AdvancedTroubleshootingPlaybook {
                    playbook_id: "playbook-001".to_string(),
                    title: "Critical remediation retry loop".to_string(),
                    trigger_taxonomy_class: "remediation_safety".to_string(),
                    trigger_taxonomy_severity: "error".to_string(),
                    ordered_steps: vec![
                        "capture_fresh_evidence".to_string(),
                        "reproduce_failure_with_rch".to_string(),
                        "stage_patch_and_verify".to_string(),
                    ],
                    command_refs: vec!["command-001".to_string()],
                    evidence_refs: vec!["evidence-001".to_string()],
                }],
            },
        },
        AdvancedDiagnosticsFixture {
            fixture_id: "advanced_happy_path".to_string(),
            description:
                "Healthy-path extension fixture with trust improvement and closure guidance."
                    .to_string(),
            core_report: happy,
            extension: AdvancedDiagnosticsReportExtension {
                schema_version: ADVANCED_DIAGNOSTICS_REPORT_VERSION.to_string(),
                base_report_id: "doctor-report-happy-v1".to_string(),
                base_report_schema_version: CORE_DIAGNOSTICS_REPORT_VERSION.to_string(),
                remediation_deltas: vec![AdvancedRemediationDelta {
                    delta_id: "delta-010".to_string(),
                    finding_id: "finding-010".to_string(),
                    previous_status: "in_progress".to_string(),
                    next_status: "resolved".to_string(),
                    delta_outcome: "success".to_string(),
                    mapped_taxonomy_class: "verification_governance".to_string(),
                    mapped_taxonomy_dimension: "contract_compliance".to_string(),
                    verification_evidence_refs: vec!["evidence-010".to_string()],
                }],
                trust_transitions: vec![AdvancedTrustTransition {
                    transition_id: "trust-010".to_string(),
                    stage: "post-verification".to_string(),
                    previous_score: 76,
                    next_score: 95,
                    outcome_class: "success".to_string(),
                    mapped_taxonomy_severity: "info".to_string(),
                    rationale:
                        "Verification summary and replay checks indicate stable healthy state."
                            .to_string(),
                }],
                collaboration_trail: vec![AdvancedCollaborationEntry {
                    entry_id: "collab-010".to_string(),
                    channel: "beads".to_string(),
                    actor: "ChartreuseBrook".to_string(),
                    action: "closed remediation bead".to_string(),
                    thread_id: "br-2b4jj.5.8".to_string(),
                    message_ref: "mail-advanced-010".to_string(),
                    bead_ref: "asupersync-2b4jj.5.8".to_string(),
                    mapped_taxonomy_narrative:
                        "Verification governance is healthy and ready for promotion.".to_string(),
                }],
                troubleshooting_playbooks: vec![AdvancedTroubleshootingPlaybook {
                    playbook_id: "playbook-010".to_string(),
                    title: "Healthy promotion checklist".to_string(),
                    trigger_taxonomy_class: "verification_governance".to_string(),
                    trigger_taxonomy_severity: "info".to_string(),
                    ordered_steps: vec![
                        "archive_artifacts".to_string(),
                        "promote_release".to_string(),
                        "publish_summary".to_string(),
                    ],
                    command_refs: vec!["command-010".to_string()],
                    evidence_refs: vec!["evidence-010".to_string()],
                }],
            },
        },
    ]
}

/// Returns a serializable bundle containing core + advanced report contracts and fixtures.
#[must_use]
pub fn advanced_diagnostics_report_bundle() -> AdvancedDiagnosticsReportBundle {
    AdvancedDiagnosticsReportBundle {
        core_contract: core_diagnostics_report_contract(),
        extension_contract: advanced_diagnostics_report_extension_contract(),
        fixtures: advanced_diagnostics_report_fixtures(),
    }
}

/// Runs deterministic advanced-extension fixture smoke and emits structured events.
///
/// # Errors
///
/// Returns `Err` when contract/report validation or structured-log emission fails.
pub fn run_advanced_diagnostics_report_smoke(
    bundle: &AdvancedDiagnosticsReportBundle,
    logging_contract: &StructuredLoggingContract,
) -> Result<Vec<StructuredLogEvent>, String> {
    validate_core_diagnostics_report_contract(&bundle.core_contract)?;
    validate_advanced_diagnostics_report_extension_contract(&bundle.extension_contract)?;
    validate_lexical_string_set(
        &bundle
            .fixtures
            .iter()
            .map(|fixture| fixture.fixture_id.clone())
            .collect::<Vec<_>>(),
        "advanced diagnostics fixture_id",
    )?;

    let mut events = Vec::new();
    for fixture in &bundle.fixtures {
        if fixture.description.trim().is_empty() {
            return Err(format!(
                "fixture {} must define non-empty description",
                fixture.fixture_id
            ));
        }
        validate_advanced_diagnostics_report_extension(
            &fixture.extension,
            &fixture.core_report,
            &bundle.extension_contract,
            &bundle.core_contract,
        )?;

        for (flow_id, kind) in [
            ("integration", "integration_sync"),
            ("remediation", "remediation_verify"),
            ("replay", "replay_complete"),
        ] {
            let mut fields = BTreeMap::new();
            fields.insert(
                "artifact_pointer".to_string(),
                format!(
                    "artifacts/{}/doctor/advanced-report/{}.json",
                    fixture.core_report.provenance.run_id, fixture.fixture_id
                ),
            );
            fields.insert(
                "command_provenance".to_string(),
                format!(
                    "asupersync doctor report-advanced-contract --fixture {}",
                    fixture.fixture_id
                ),
            );
            fields.insert("flow_id".to_string(), flow_id.to_string());
            fields.insert(
                "outcome_class".to_string(),
                fixture.core_report.summary.overall_outcome.clone(),
            );
            fields.insert(
                "run_id".to_string(),
                fixture.core_report.provenance.run_id.clone(),
            );
            fields.insert(
                "scenario_id".to_string(),
                fixture.core_report.provenance.scenario_id.clone(),
            );
            fields.insert(
                "trace_id".to_string(),
                format!("{}-{}", fixture.core_report.provenance.trace_id, flow_id),
            );
            let event = emit_structured_log_event(logging_contract, flow_id, kind, &fields)?;
            events.push(event);
        }
    }
    events.sort_by(|left, right| {
        (
            left.flow_id.as_str(),
            left.event_kind.as_str(),
            left.fields
                .get("trace_id")
                .map(String::as_str)
                .unwrap_or_default(),
        )
            .cmp(&(
                right.flow_id.as_str(),
                right.event_kind.as_str(),
                right
                    .fields
                    .get("trace_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ))
    });
    Ok(events)
}

fn capability_rank(capability: TerminalCapabilityClass) -> u8 {
    match capability {
        TerminalCapabilityClass::Ansi16 => 1,
        TerminalCapabilityClass::Ansi256 => 2,
        TerminalCapabilityClass::TrueColor => 3,
    }
}

/// Returns the canonical visual-language contract for doctor TUI surfaces.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn visual_language_contract() -> VisualLanguageContract {
    VisualLanguageContract {
        contract_version: VISUAL_LANGUAGE_VERSION.to_string(),
        source_showcase: "frankentui-demo-showcase-v1".to_string(),
        default_profile_id: "showcase_ansi256".to_string(),
        profiles: vec![
            VisualStyleProfile {
                id: "showcase_ansi16".to_string(),
                label: "Showcase ANSI-16".to_string(),
                minimum_capability: TerminalCapabilityClass::Ansi16,
                typography_tokens: vec![
                    "body:mono-regular".to_string(),
                    "code:mono-semibold".to_string(),
                    "heading:mono-bold".to_string(),
                ],
                spacing_tokens: vec![
                    "gutter-1".to_string(),
                    "gutter-2".to_string(),
                    "gutter-3".to_string(),
                ],
                palette_tokens: vec![
                    ColorToken {
                        role: "background".to_string(),
                        fg: "ansi-black".to_string(),
                        bg: "ansi-default".to_string(),
                        accent: "ansi-blue".to_string(),
                    },
                    ColorToken {
                        role: "critical".to_string(),
                        fg: "ansi-red-bright".to_string(),
                        bg: "ansi-default".to_string(),
                        accent: "ansi-red".to_string(),
                    },
                    ColorToken {
                        role: "panel".to_string(),
                        fg: "ansi-white".to_string(),
                        bg: "ansi-black".to_string(),
                        accent: "ansi-cyan".to_string(),
                    },
                    ColorToken {
                        role: "primary_text".to_string(),
                        fg: "ansi-white".to_string(),
                        bg: "ansi-default".to_string(),
                        accent: "ansi-white".to_string(),
                    },
                    ColorToken {
                        role: "secondary_text".to_string(),
                        fg: "ansi-bright-black".to_string(),
                        bg: "ansi-default".to_string(),
                        accent: "ansi-cyan".to_string(),
                    },
                    ColorToken {
                        role: "warning".to_string(),
                        fg: "ansi-yellow-bright".to_string(),
                        bg: "ansi-default".to_string(),
                        accent: "ansi-yellow".to_string(),
                    },
                ],
                panel_motifs: vec![
                    "hard_edges".to_string(),
                    "inline_badges".to_string(),
                    "mono_rule_dividers".to_string(),
                ],
                motion_cues: vec![
                    MotionCue {
                        id: "focus_pulse".to_string(),
                        trigger: "focus_change".to_string(),
                        pattern: "single_blink".to_string(),
                        duration_ms: 80,
                    },
                    MotionCue {
                        id: "page_reveal".to_string(),
                        trigger: "screen_enter".to_string(),
                        pattern: "line_wipe".to_string(),
                        duration_ms: 120,
                    },
                    MotionCue {
                        id: "row_stagger".to_string(),
                        trigger: "list_render".to_string(),
                        pattern: "staggered_print".to_string(),
                        duration_ms: 90,
                    },
                ],
                fallback_profile_id: None,
                readability_notes: vec![
                    "prefer_high_contrast_text_for_alert_panels".to_string(),
                    "reserve_bright_red_for_critical_events_only".to_string(),
                ],
            },
            VisualStyleProfile {
                id: "showcase_ansi256".to_string(),
                label: "Showcase ANSI-256".to_string(),
                minimum_capability: TerminalCapabilityClass::Ansi256,
                typography_tokens: vec![
                    "body:mono-regular".to_string(),
                    "code:mono-semibold".to_string(),
                    "heading:mono-bold".to_string(),
                ],
                spacing_tokens: vec![
                    "gutter-1".to_string(),
                    "gutter-2".to_string(),
                    "gutter-3".to_string(),
                ],
                palette_tokens: vec![
                    ColorToken {
                        role: "background".to_string(),
                        fg: "gray-245".to_string(),
                        bg: "gray-16".to_string(),
                        accent: "indigo-99".to_string(),
                    },
                    ColorToken {
                        role: "critical".to_string(),
                        fg: "red-203".to_string(),
                        bg: "gray-16".to_string(),
                        accent: "red-196".to_string(),
                    },
                    ColorToken {
                        role: "panel".to_string(),
                        fg: "gray-252".to_string(),
                        bg: "gray-23".to_string(),
                        accent: "cyan-45".to_string(),
                    },
                    ColorToken {
                        role: "primary_text".to_string(),
                        fg: "gray-255".to_string(),
                        bg: "gray-16".to_string(),
                        accent: "gray-255".to_string(),
                    },
                    ColorToken {
                        role: "secondary_text".to_string(),
                        fg: "gray-250".to_string(),
                        bg: "gray-16".to_string(),
                        accent: "cyan-87".to_string(),
                    },
                    ColorToken {
                        role: "warning".to_string(),
                        fg: "yellow-220".to_string(),
                        bg: "gray-16".to_string(),
                        accent: "yellow-214".to_string(),
                    },
                ],
                panel_motifs: vec![
                    "angled_headers".to_string(),
                    "layered_status_pills".to_string(),
                    "striped_rule_dividers".to_string(),
                ],
                motion_cues: vec![
                    MotionCue {
                        id: "focus_pulse".to_string(),
                        trigger: "focus_change".to_string(),
                        pattern: "double_blink".to_string(),
                        duration_ms: 90,
                    },
                    MotionCue {
                        id: "page_reveal".to_string(),
                        trigger: "screen_enter".to_string(),
                        pattern: "gradient_wipe".to_string(),
                        duration_ms: 140,
                    },
                    MotionCue {
                        id: "row_stagger".to_string(),
                        trigger: "list_render".to_string(),
                        pattern: "staggered_fade".to_string(),
                        duration_ms: 100,
                    },
                ],
                fallback_profile_id: Some("showcase_ansi16".to_string()),
                readability_notes: vec![
                    "keep_warning_and_critical_roles_distinct".to_string(),
                    "prefer_mono_alignment_for_numeric_columns".to_string(),
                ],
            },
            VisualStyleProfile {
                id: "showcase_truecolor".to_string(),
                label: "Showcase TrueColor".to_string(),
                minimum_capability: TerminalCapabilityClass::TrueColor,
                typography_tokens: vec![
                    "body:mono-regular".to_string(),
                    "code:mono-semibold".to_string(),
                    "heading:mono-bold".to_string(),
                ],
                spacing_tokens: vec![
                    "gutter-1".to_string(),
                    "gutter-2".to_string(),
                    "gutter-3".to_string(),
                ],
                palette_tokens: vec![
                    ColorToken {
                        role: "background".to_string(),
                        fg: "#dce6f2".to_string(),
                        bg: "#111827".to_string(),
                        accent: "#4f7cff".to_string(),
                    },
                    ColorToken {
                        role: "critical".to_string(),
                        fg: "#ff6b6b".to_string(),
                        bg: "#111827".to_string(),
                        accent: "#ff4d4f".to_string(),
                    },
                    ColorToken {
                        role: "panel".to_string(),
                        fg: "#f8fafc".to_string(),
                        bg: "#1f2937".to_string(),
                        accent: "#23b5d3".to_string(),
                    },
                    ColorToken {
                        role: "primary_text".to_string(),
                        fg: "#f9fafb".to_string(),
                        bg: "#111827".to_string(),
                        accent: "#f9fafb".to_string(),
                    },
                    ColorToken {
                        role: "secondary_text".to_string(),
                        fg: "#9fb3c8".to_string(),
                        bg: "#111827".to_string(),
                        accent: "#6ee7f7".to_string(),
                    },
                    ColorToken {
                        role: "warning".to_string(),
                        fg: "#ffd166".to_string(),
                        bg: "#111827".to_string(),
                        accent: "#ffb703".to_string(),
                    },
                ],
                panel_motifs: vec![
                    "angled_headers".to_string(),
                    "layered_status_pills".to_string(),
                    "slashed_rule_dividers".to_string(),
                ],
                motion_cues: vec![
                    MotionCue {
                        id: "focus_pulse".to_string(),
                        trigger: "focus_change".to_string(),
                        pattern: "soft_glow".to_string(),
                        duration_ms: 110,
                    },
                    MotionCue {
                        id: "page_reveal".to_string(),
                        trigger: "screen_enter".to_string(),
                        pattern: "top_down_reveal".to_string(),
                        duration_ms: 160,
                    },
                    MotionCue {
                        id: "row_stagger".to_string(),
                        trigger: "list_render".to_string(),
                        pattern: "staggered_fade".to_string(),
                        duration_ms: 120,
                    },
                ],
                fallback_profile_id: Some("showcase_ansi256".to_string()),
                readability_notes: vec![
                    "bound_max_saturation_for_long_running_eyestrain_control".to_string(),
                    "preserve_critical_role_contrast_above_4_5_to_1".to_string(),
                ],
            },
        ],
        screen_styles: vec![
            ScreenVisualStyle {
                screen_id: "bead_command_center".to_string(),
                preferred_profile_id: "showcase_truecolor".to_string(),
                required_color_roles: vec![
                    "background".to_string(),
                    "panel".to_string(),
                    "primary_text".to_string(),
                    "warning".to_string(),
                ],
                canonical_layout_motif: "triple-pane command runway".to_string(),
                degraded_layout_motif: "stacked split with compact status badges".to_string(),
            },
            ScreenVisualStyle {
                screen_id: "gate_status_board".to_string(),
                preferred_profile_id: "showcase_truecolor".to_string(),
                required_color_roles: vec![
                    "background".to_string(),
                    "critical".to_string(),
                    "panel".to_string(),
                    "primary_text".to_string(),
                ],
                canonical_layout_motif: "layered gate lanes with slashed dividers".to_string(),
                degraded_layout_motif: "single-column gate list with explicit severity tags"
                    .to_string(),
            },
            ScreenVisualStyle {
                screen_id: "incident_console".to_string(),
                preferred_profile_id: "showcase_truecolor".to_string(),
                required_color_roles: vec![
                    "background".to_string(),
                    "critical".to_string(),
                    "panel".to_string(),
                    "primary_text".to_string(),
                    "secondary_text".to_string(),
                ],
                canonical_layout_motif: "priority stack with continuous evidence rail".to_string(),
                degraded_layout_motif: "priority queue + inline evidence bullets".to_string(),
            },
            ScreenVisualStyle {
                screen_id: "replay_inspector".to_string(),
                preferred_profile_id: "showcase_ansi256".to_string(),
                required_color_roles: vec![
                    "background".to_string(),
                    "panel".to_string(),
                    "primary_text".to_string(),
                    "secondary_text".to_string(),
                ],
                canonical_layout_motif: "timeline + diff pane with synchronized cursor".to_string(),
                degraded_layout_motif: "single timeline table with deterministic markers"
                    .to_string(),
            },
        ],
        accessibility_constraints: vec![
            "all_alert_roles_must_remain_distinguishable_in_ansi16".to_string(),
            "avoid_motion_only_state_signals".to_string(),
            "preserve_text_readability_under_small_terminal_widths".to_string(),
        ],
        non_goals: vec![
            "do_not_recreate_generic_dashboard_defaults".to_string(),
            "do_not_use_ambient_rainbow_palette_without_semantic_meaning".to_string(),
            "do_not_use_typography_that_breaks_monospace_alignment".to_string(),
        ],
    }
}

/// Validates structural invariants of a [`VisualLanguageContract`].
///
/// # Errors
///
/// Returns `Err` when required fields are missing, duplicated, or inconsistent.
#[allow(clippy::too_many_lines)]
pub fn validate_visual_language_contract(contract: &VisualLanguageContract) -> Result<(), String> {
    if contract.contract_version.trim().is_empty() {
        return Err("visual contract_version must be non-empty".to_string());
    }
    if contract.source_showcase.trim().is_empty() {
        return Err("source_showcase must be non-empty".to_string());
    }
    if contract.default_profile_id.trim().is_empty() {
        return Err("default_profile_id must be non-empty".to_string());
    }
    if contract.profiles.is_empty() {
        return Err("profiles must be non-empty".to_string());
    }
    if contract.screen_styles.is_empty() {
        return Err("screen_styles must be non-empty".to_string());
    }
    if contract.accessibility_constraints.is_empty() {
        return Err("accessibility_constraints must be non-empty".to_string());
    }
    if contract.non_goals.is_empty() {
        return Err("non_goals must be non-empty".to_string());
    }

    let mut accessibility = contract.accessibility_constraints.clone();
    accessibility.sort();
    accessibility.dedup();
    if accessibility != contract.accessibility_constraints {
        return Err("accessibility_constraints must be unique and lexically sorted".to_string());
    }
    let mut non_goals = contract.non_goals.clone();
    non_goals.sort();
    non_goals.dedup();
    if non_goals != contract.non_goals {
        return Err("non_goals must be unique and lexically sorted".to_string());
    }

    let mut profile_ids = BTreeSet::new();
    let mut lexical_profile_ids = Vec::with_capacity(contract.profiles.len());
    for profile in &contract.profiles {
        if profile.id.trim().is_empty() || profile.label.trim().is_empty() {
            return Err("profile id and label must be non-empty".to_string());
        }
        if !profile_ids.insert(profile.id.clone()) {
            return Err(format!("duplicate profile id: {}", profile.id));
        }
        lexical_profile_ids.push(profile.id.clone());

        if profile.typography_tokens.is_empty()
            || profile.spacing_tokens.is_empty()
            || profile.palette_tokens.is_empty()
            || profile.panel_motifs.is_empty()
            || profile.motion_cues.is_empty()
            || profile.readability_notes.is_empty()
        {
            return Err(format!(
                "profile {} must define typography/spacing/palette/motion/motifs/readability",
                profile.id
            ));
        }

        let mut typography = profile.typography_tokens.clone();
        typography.sort();
        typography.dedup();
        if typography != profile.typography_tokens {
            return Err(format!(
                "profile {} typography_tokens must be unique and lexically sorted",
                profile.id
            ));
        }
        let mut spacing = profile.spacing_tokens.clone();
        spacing.sort();
        spacing.dedup();
        if spacing != profile.spacing_tokens {
            return Err(format!(
                "profile {} spacing_tokens must be unique and lexically sorted",
                profile.id
            ));
        }
        let mut motifs = profile.panel_motifs.clone();
        motifs.sort();
        motifs.dedup();
        if motifs != profile.panel_motifs {
            return Err(format!(
                "profile {} panel_motifs must be unique and lexically sorted",
                profile.id
            ));
        }
        let mut notes = profile.readability_notes.clone();
        notes.sort();
        notes.dedup();
        if notes != profile.readability_notes {
            return Err(format!(
                "profile {} readability_notes must be unique and lexically sorted",
                profile.id
            ));
        }

        let mut cue_ids = BTreeSet::new();
        let mut lexical_cue_ids = Vec::new();
        for cue in &profile.motion_cues {
            if cue.id.trim().is_empty()
                || cue.trigger.trim().is_empty()
                || cue.pattern.trim().is_empty()
                || cue.duration_ms == 0
            {
                return Err(format!("profile {} has invalid motion cue", profile.id));
            }
            if !cue_ids.insert(cue.id.clone()) {
                return Err(format!(
                    "profile {} has duplicate motion cue id {}",
                    profile.id, cue.id
                ));
            }
            lexical_cue_ids.push(cue.id.clone());
        }
        let mut sorted_cue_ids = lexical_cue_ids.clone();
        sorted_cue_ids.sort();
        if sorted_cue_ids != lexical_cue_ids {
            return Err(format!(
                "profile {} motion cues must be in lexical id order",
                profile.id
            ));
        }

        let mut palette_roles = BTreeSet::new();
        let mut lexical_palette_roles = Vec::new();
        for token in &profile.palette_tokens {
            if token.role.trim().is_empty()
                || token.fg.trim().is_empty()
                || token.bg.trim().is_empty()
                || token.accent.trim().is_empty()
            {
                return Err(format!("profile {} has invalid palette token", profile.id));
            }
            if !palette_roles.insert(token.role.clone()) {
                return Err(format!(
                    "profile {} has duplicate palette role {}",
                    profile.id, token.role
                ));
            }
            lexical_palette_roles.push(token.role.clone());
        }
        let mut sorted_palette_roles = lexical_palette_roles.clone();
        sorted_palette_roles.sort();
        if sorted_palette_roles != lexical_palette_roles {
            return Err(format!(
                "profile {} palette token roles must be in lexical order",
                profile.id
            ));
        }
    }

    let mut sorted_profile_ids = lexical_profile_ids.clone();
    sorted_profile_ids.sort();
    if sorted_profile_ids != lexical_profile_ids {
        return Err("profiles must be ordered lexically by profile id".to_string());
    }
    if !profile_ids.contains(&contract.default_profile_id) {
        return Err(format!(
            "default_profile_id {} not found in profiles",
            contract.default_profile_id
        ));
    }

    let profile_map: BTreeMap<_, _> = contract
        .profiles
        .iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect();
    for profile in &contract.profiles {
        if let Some(fallback_id) = &profile.fallback_profile_id {
            if fallback_id == &profile.id {
                return Err(format!(
                    "profile {} fallback_profile_id must not self-reference",
                    profile.id
                ));
            }
            let Some(fallback_profile) = profile_map.get(fallback_id) else {
                return Err(format!(
                    "profile {} references unknown fallback profile {}",
                    profile.id, fallback_id
                ));
            };
            if capability_rank(fallback_profile.minimum_capability)
                > capability_rank(profile.minimum_capability)
            {
                return Err(format!(
                    "profile {} fallback {} must not increase capability requirements",
                    profile.id, fallback_id
                ));
            }
        }
    }

    let mut seen_screen_ids = BTreeSet::new();
    let mut lexical_screen_ids = Vec::new();
    for style in &contract.screen_styles {
        if style.screen_id.trim().is_empty()
            || style.preferred_profile_id.trim().is_empty()
            || style.canonical_layout_motif.trim().is_empty()
            || style.degraded_layout_motif.trim().is_empty()
        {
            return Err("screen style fields must be non-empty".to_string());
        }
        if !seen_screen_ids.insert(style.screen_id.clone()) {
            return Err(format!("duplicate screen_id: {}", style.screen_id));
        }
        lexical_screen_ids.push(style.screen_id.clone());
        if !profile_ids.contains(&style.preferred_profile_id) {
            return Err(format!(
                "screen {} references unknown preferred profile {}",
                style.screen_id, style.preferred_profile_id
            ));
        }
        if style.required_color_roles.is_empty() {
            return Err(format!(
                "screen {} must define required_color_roles",
                style.screen_id
            ));
        }
        let mut deduped_roles = style.required_color_roles.clone();
        deduped_roles.sort();
        deduped_roles.dedup();
        if deduped_roles != style.required_color_roles {
            return Err(format!(
                "screen {} required_color_roles must be unique and lexically sorted",
                style.screen_id
            ));
        }

        let preferred_profile = profile_map
            .get(&style.preferred_profile_id)
            .expect("profile existence checked above");
        let preferred_roles: BTreeSet<_> = preferred_profile
            .palette_tokens
            .iter()
            .map(|token| token.role.as_str())
            .collect();
        for required_role in &style.required_color_roles {
            if !preferred_roles.contains(required_role.as_str()) {
                return Err(format!(
                    "screen {} requires role {} missing from profile {}",
                    style.screen_id, required_role, style.preferred_profile_id
                ));
            }
        }
    }
    let mut sorted_screen_ids = lexical_screen_ids.clone();
    sorted_screen_ids.sort();
    if sorted_screen_ids != lexical_screen_ids {
        return Err("screen_styles must be ordered lexically by screen_id".to_string());
    }

    Ok(())
}

fn resolve_profile_for_capability(
    contract: &VisualLanguageContract,
    preferred_profile_id: &str,
    screen_id: &str,
    correlation_id: &str,
    capability: TerminalCapabilityClass,
) -> Result<(String, bool, Vec<VisualThemeEvent>), String> {
    let profile_map: BTreeMap<_, _> = contract
        .profiles
        .iter()
        .map(|profile| (&profile.id, profile))
        .collect();
    let mut current_profile_id = preferred_profile_id.to_string();
    let mut fallback_applied = false;
    let mut visited = BTreeSet::new();
    let mut events = Vec::new();

    loop {
        if !visited.insert(current_profile_id.clone()) {
            return Err(format!(
                "cycle detected while resolving fallback for profile {current_profile_id}"
            ));
        }
        let profile = profile_map.get(&current_profile_id).ok_or_else(|| {
            format!("screen {screen_id} references unknown profile {current_profile_id}")
        })?;
        if capability_rank(capability) >= capability_rank(profile.minimum_capability) {
            events.push(VisualThemeEvent {
                event_kind: "theme_selected".to_string(),
                correlation_id: correlation_id.to_string(),
                screen_id: screen_id.to_string(),
                profile_id: current_profile_id.clone(),
                capability_class: capability,
                message: format!(
                    "selected profile {current_profile_id} for capability {capability:?}"
                ),
                remediation_hint: "none".to_string(),
            });
            return Ok((current_profile_id, fallback_applied, events));
        }
        if let Some(next_profile_id) = &profile.fallback_profile_id {
            fallback_applied = true;
            events.push(VisualThemeEvent {
                event_kind: "theme_fallback".to_string(),
                correlation_id: correlation_id.to_string(),
                screen_id: screen_id.to_string(),
                profile_id: current_profile_id.clone(),
                capability_class: capability,
                message: format!(
                    "fallback from profile {current_profile_id} to {next_profile_id} for capability {capability:?}"
                ),
                remediation_hint:
                    "use a stronger terminal capability to restore preferred profile".to_string(),
            });
            current_profile_id.clone_from(next_profile_id);
            continue;
        }
        events.push(VisualThemeEvent {
            event_kind: "theme_selected".to_string(),
            correlation_id: correlation_id.to_string(),
            screen_id: screen_id.to_string(),
            profile_id: current_profile_id.clone(),
            capability_class: capability,
            message: format!(
                "selected profile {current_profile_id} without fallback despite capability mismatch"
            ),
            remediation_hint: "define fallback profile chain for this capability class".to_string(),
        });
        return Ok((current_profile_id, fallback_applied, events));
    }
}

/// Simulates visual token application for one screen and terminal capability.
///
/// Emits deterministic structured theme events for selection/fallback,
/// token-resolution failures, and layout degradation.
///
/// # Errors
///
/// Returns `Err` when the requested screen or profile cannot be resolved.
pub fn simulate_visual_token_application(
    contract: &VisualLanguageContract,
    screen_id: &str,
    correlation_id: &str,
    capability: TerminalCapabilityClass,
) -> Result<VisualApplicationTranscript, String> {
    simulate_visual_token_application_for_viewport(
        contract,
        screen_id,
        correlation_id,
        capability,
        DEFAULT_VISUAL_VIEWPORT_WIDTH,
        DEFAULT_VISUAL_VIEWPORT_HEIGHT,
    )
}

/// Simulates visual token application with explicit viewport dimensions.
///
/// Compact terminals below the readability threshold degrade to the
/// screen-specific degraded layout motif and emit a deterministic
/// `layout_degradation` event.
///
/// # Errors
///
/// Returns `Err` when the requested screen/profile cannot be resolved or
/// when viewport dimensions are zero.
#[allow(clippy::too_many_lines)]
pub fn simulate_visual_token_application_for_viewport(
    contract: &VisualLanguageContract,
    screen_id: &str,
    correlation_id: &str,
    capability: TerminalCapabilityClass,
    viewport_width: u16,
    viewport_height: u16,
) -> Result<VisualApplicationTranscript, String> {
    if viewport_width == 0 {
        return Err("viewport_width must be greater than zero".to_string());
    }
    if viewport_height == 0 {
        return Err("viewport_height must be greater than zero".to_string());
    }

    let screen_style = contract
        .screen_styles
        .iter()
        .find(|style| style.screen_id == screen_id)
        .ok_or_else(|| format!("unknown screen_id: {screen_id}"))?;
    let (selected_profile_id, fallback_applied, mut events) = resolve_profile_for_capability(
        contract,
        &screen_style.preferred_profile_id,
        screen_id,
        correlation_id,
        capability,
    )?;
    let selected_profile = contract
        .profiles
        .iter()
        .find(|profile| profile.id == selected_profile_id)
        .ok_or_else(|| format!("resolved profile {selected_profile_id} not found"))?;
    let selected_roles: BTreeSet<_> = selected_profile
        .palette_tokens
        .iter()
        .map(|token| token.role.clone())
        .collect();
    let missing_roles: Vec<String> = screen_style
        .required_color_roles
        .iter()
        .filter(|role| !selected_roles.contains(*role))
        .cloned()
        .collect();

    if !missing_roles.is_empty() {
        events.push(VisualThemeEvent {
            event_kind: "token_resolution_failure".to_string(),
            correlation_id: correlation_id.to_string(),
            screen_id: screen_id.to_string(),
            profile_id: selected_profile_id.clone(),
            capability_class: capability,
            message: format!("missing required color roles: {}", missing_roles.join(", ")),
            remediation_hint: "add missing role tokens to the selected visual profile".to_string(),
        });
    }

    let compact_viewport =
        viewport_width < MIN_VISUAL_VIEWPORT_WIDTH || viewport_height < MIN_VISUAL_VIEWPORT_HEIGHT;
    if fallback_applied || compact_viewport {
        let mut remediation_parts = Vec::new();
        if fallback_applied {
            remediation_parts.push("use truecolor/ansi256 terminal to restore canonical motif");
        }
        if compact_viewport {
            remediation_parts
                .push("increase terminal viewport to at least 110x32 to restore canonical motif");
        }
        events.push(VisualThemeEvent {
            event_kind: "layout_degradation".to_string(),
            correlation_id: correlation_id.to_string(),
            screen_id: screen_id.to_string(),
            profile_id: selected_profile_id.clone(),
            capability_class: capability,
            message: format!(
                "applied degraded layout motif: {}; viewport={}x{}",
                screen_style.degraded_layout_motif, viewport_width, viewport_height
            ),
            remediation_hint: remediation_parts.join("; "),
        });
    }

    Ok(VisualApplicationTranscript {
        contract_version: contract.contract_version.clone(),
        correlation_id: correlation_id.to_string(),
        screen_id: screen_id.to_string(),
        selected_profile_id,
        fallback_applied,
        applied_layout_motif: if fallback_applied || compact_viewport {
            screen_style.degraded_layout_motif.clone()
        } else {
            screen_style.canonical_layout_motif.clone()
        },
        missing_roles,
        events,
    })
}

/// Scan a Cargo workspace and summarize capability-flow references.
///
/// The report is deterministic: members, surfaces, and sample paths are all
/// emitted in sorted order.
///
/// # Errors
///
/// Returns `io::Error` if the root manifest cannot be read or if directory
/// traversal fails.
#[allow(clippy::too_many_lines)]
pub fn scan_workspace(root: &Path) -> io::Result<WorkspaceScanReport> {
    let root = root.to_path_buf();
    let manifest_path = root.join("Cargo.toml");
    let manifest_text = fs::read_to_string(&manifest_path)?;
    let mut log = ScanLog::default();
    log.info(
        "scan_start",
        "starting workspace scan",
        Some(relative_to(&root, &manifest_path)),
    );

    let workspace_members = parse_workspace_string_array(&manifest_text, "members", &mut log);
    let workspace_excludes = parse_workspace_string_array(&manifest_text, "exclude", &mut log);
    log.info(
        "workspace_manifest",
        format!(
            "parsed workspace arrays: members={}, excludes={}",
            workspace_members.len(),
            workspace_excludes.len()
        ),
        Some(relative_to(&root, &manifest_path)),
    );

    let (member_dirs, excluded_dirs) =
        resolve_member_dirs(&root, &workspace_members, &workspace_excludes, &mut log)?;
    let member_scans = collect_member_scans(&root, &member_dirs, &excluded_dirs, &mut log)?;
    let (members, edges) = build_members_and_edges(member_scans);
    log.info(
        "scan_complete",
        format!(
            "scan complete: members={}, edges={}, warnings={}",
            members.len(),
            edges.len(),
            log.warnings.len()
        ),
        None,
    );

    Ok(WorkspaceScanReport {
        root: root.display().to_string(),
        workspace_manifest: manifest_path.display().to_string(),
        scanner_version: SCANNER_VERSION.to_string(),
        taxonomy_version: TAXONOMY_VERSION.to_string(),
        members,
        capability_edges: edges,
        warnings: log.warnings,
        events: log.events,
    })
}

/// Analyze high-signal runtime invariants from a workspace scan report.
///
/// This pass is intentionally deterministic and conservative: it only emits
/// findings that can be justified from scanner facts, warnings, and lifecycle
/// events without guessing hidden runtime behavior.
#[must_use]
pub fn analyze_workspace_invariants(report: &WorkspaceScanReport) -> InvariantAnalyzerReport {
    let correlation_id = format!(
        "doctor-invariant:{}:{}:{}",
        INVARIANT_ANALYZER_VERSION, report.scanner_version, report.workspace_manifest
    );
    let detected_surfaces = report
        .capability_edges
        .iter()
        .map(|edge| edge.surface.as_str())
        .collect::<BTreeSet<_>>();
    let detected_surface_text = if detected_surfaces.is_empty() {
        "<none>".to_string()
    } else {
        detected_surfaces
            .iter()
            .copied()
            .collect::<Vec<_>>()
            .join(", ")
    };
    let no_members_discovered = report.members.is_empty();
    let mut findings = Vec::new();
    let mut rule_traces = Vec::new();

    let mut push_finding = |rule_id: &str,
                            finding_id: &str,
                            severity: &str,
                            summary: String,
                            confidence: u8,
                            evidence: Vec<String>,
                            remediation_guidance: &str| {
        findings.push(InvariantFinding {
            finding_id: finding_id.to_string(),
            rule_id: rule_id.to_string(),
            severity: severity.to_string(),
            summary,
            confidence,
            evidence,
            remediation_guidance: remediation_guidance.to_string(),
        });
    };

    let structured_rule_id = "structured_concurrency_surface";
    let missing_structured = ["cx", "scope"]
        .into_iter()
        .filter(|required| !detected_surfaces.contains(required))
        .map(str::to_string)
        .collect::<Vec<_>>();
    if no_members_discovered {
        rule_traces.push(InvariantRuleTrace {
            rule_id: structured_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "suppressed".to_string(),
            confidence: 100,
            evidence: vec!["no members discovered in workspace scan".to_string()],
            suppressed_reason: Some("no members discovered".to_string()),
        });
    } else if missing_structured.is_empty() {
        rule_traces.push(InvariantRuleTrace {
            rule_id: structured_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 95,
            evidence: vec![format!("detected surfaces: {detected_surface_text}")],
            suppressed_reason: None,
        });
    } else {
        let evidence = vec![
            format!(
                "missing required structured-concurrency surfaces: {}",
                missing_structured.join(", ")
            ),
            format!("detected surfaces: {detected_surface_text}"),
        ];
        push_finding(
            structured_rule_id,
            "structured_concurrency_surface_missing",
            "error",
            format!(
                "workspace scan is missing structured-concurrency evidence ({})",
                missing_structured.join(", ")
            ),
            95,
            evidence.clone(),
            "Add explicit `Cx` and `Scope` usage (or their canonical markers) to runtime entry points so structured-concurrency ownership is analyzable.",
        );
        rule_traces.push(InvariantRuleTrace {
            rule_id: structured_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 95,
            evidence,
            suppressed_reason: None,
        });
    }

    let cancel_rule_id = "cancel_phase_surface";
    if no_members_discovered {
        rule_traces.push(InvariantRuleTrace {
            rule_id: cancel_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "suppressed".to_string(),
            confidence: 100,
            evidence: vec!["no members discovered in workspace scan".to_string()],
            suppressed_reason: Some("no members discovered".to_string()),
        });
    } else if detected_surfaces.contains("cancel") {
        rule_traces.push(InvariantRuleTrace {
            rule_id: cancel_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 90,
            evidence: vec!["detected cancellation surface marker: cancel".to_string()],
            suppressed_reason: None,
        });
    } else {
        let evidence = vec![
            "missing cancellation surface marker: cancel".to_string(),
            format!("detected surfaces: {detected_surface_text}"),
        ];
        push_finding(
            cancel_rule_id,
            "cancel_phase_surface_missing",
            "warn",
            "workspace scan did not observe cancellation-phase markers".to_string(),
            90,
            evidence.clone(),
            "Add explicit cancellation protocol markers (`CancelKind`, `CancelReason`, or `asupersync::cancel`) to the scanned member surfaces.",
        );
        rule_traces.push(InvariantRuleTrace {
            rule_id: cancel_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 90,
            evidence,
            suppressed_reason: None,
        });
    }

    let obligation_rule_id = "obligation_surface";
    if no_members_discovered {
        rule_traces.push(InvariantRuleTrace {
            rule_id: obligation_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "suppressed".to_string(),
            confidence: 100,
            evidence: vec!["no members discovered in workspace scan".to_string()],
            suppressed_reason: Some("no members discovered".to_string()),
        });
    } else if detected_surfaces.contains("obligation") {
        rule_traces.push(InvariantRuleTrace {
            rule_id: obligation_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 90,
            evidence: vec!["detected obligation surface marker: obligation".to_string()],
            suppressed_reason: None,
        });
    } else {
        let evidence = vec![
            "missing obligation surface marker: obligation".to_string(),
            format!("detected surfaces: {detected_surface_text}"),
        ];
        push_finding(
            obligation_rule_id,
            "obligation_surface_missing",
            "warn",
            "workspace scan did not observe obligation-accounting markers".to_string(),
            90,
            evidence.clone(),
            "Add explicit obligation protocol markers (`Obligation`, `asupersync::obligation`, `reserve(`, `commit(`) where ownership is enforced.",
        );
        rule_traces.push(InvariantRuleTrace {
            rule_id: obligation_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 90,
            evidence,
            suppressed_reason: None,
        });
    }

    let lifecycle_rule_id = "scan_lifecycle_events";
    let event_phases = report
        .events
        .iter()
        .map(|event| event.phase.as_str())
        .collect::<BTreeSet<_>>();
    let mut missing_phases = Vec::new();
    for required in ["scan_start", "scan_complete"] {
        if !event_phases.contains(required) {
            missing_phases.push(required.to_string());
        }
    }
    if missing_phases.is_empty() {
        rule_traces.push(InvariantRuleTrace {
            rule_id: lifecycle_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 100,
            evidence: vec!["scan_start and scan_complete events are present".to_string()],
            suppressed_reason: None,
        });
    } else {
        let evidence = vec![
            format!("missing phases: {}", missing_phases.join(", ")),
            format!(
                "observed phases: {}",
                event_phases.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ];
        push_finding(
            lifecycle_rule_id,
            "scan_lifecycle_events_missing",
            "error",
            "scanner lifecycle events are incomplete".to_string(),
            100,
            evidence.clone(),
            "Ensure scanner emits both `scan_start` and `scan_complete` events so downstream replay/diagnostics remain deterministic.",
        );
        rule_traces.push(InvariantRuleTrace {
            rule_id: lifecycle_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 100,
            evidence,
            suppressed_reason: None,
        });
    }

    let warnings_rule_id = "scanner_warning_integrity";
    if report.warnings.is_empty() {
        rule_traces.push(InvariantRuleTrace {
            rule_id: warnings_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 85,
            evidence: vec!["workspace scan emitted no warnings".to_string()],
            suppressed_reason: None,
        });
    } else {
        let mut warning_evidence = report.warnings.clone();
        warning_evidence.sort();
        push_finding(
            warnings_rule_id,
            "scanner_warning_signal_present",
            "warn",
            format!(
                "workspace scan emitted {} warning(s) requiring triage",
                warning_evidence.len()
            ),
            85,
            warning_evidence.clone(),
            "Triage scanner warnings before remediation generation so analyzer confidence remains high.",
        );
        rule_traces.push(InvariantRuleTrace {
            rule_id: warnings_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 85,
            evidence: warning_evidence,
            suppressed_reason: None,
        });
    }

    findings.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then_with(|| a.finding_id.cmp(&b.finding_id))
    });
    rule_traces.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    InvariantAnalyzerReport {
        analyzer_version: INVARIANT_ANALYZER_VERSION.to_string(),
        scanner_version: report.scanner_version.clone(),
        taxonomy_version: report.taxonomy_version.clone(),
        correlation_id,
        member_count: report.members.len(),
        finding_count: findings.len(),
        findings,
        rule_traces,
    }
}

/// Analyze lock-order and contention risk over a workspace scan report.
///
/// This analyzer combines static lock-acquisition sequence checks with
/// contention-marker density scoring to produce deterministic hotspot rankings.
#[must_use]
pub fn analyze_workspace_lock_contention(
    report: &WorkspaceScanReport,
) -> LockContentionAnalyzerReport {
    let correlation_id = format!(
        "doctor-lock-contention:{}:{}:{}",
        LOCK_CONTENTION_ANALYZER_VERSION, report.scanner_version, report.workspace_manifest
    );
    let root = Path::new(&report.root);
    let mut hotspots: BTreeMap<String, LockHotspotAccumulator> = BTreeMap::new();
    let mut violations = Vec::new();
    let mut violation_counter: u32 = 0;
    let mut rule_traces = Vec::new();

    for member in &report.members {
        let member_root = root.join(&member.relative_path);
        let source_root = member_root.join("src");
        let rust_files = collect_rust_files(&source_root).unwrap_or_default();
        for file in rust_files {
            let source = match fs::read_to_string(&file) {
                Ok(source) => source,
                Err(_) => continue,
            };
            let relative_path = relative_to(root, &file);
            let accumulator = hotspots.entry(relative_path.clone()).or_default();
            let mut current_function = "<module>".to_string();
            let mut previous_lock: Option<(LockShard, usize)> = None;

            for (line_index, line) in source.lines().enumerate() {
                let line_number = line_index + 1;
                let trimmed = line.trim();
                let sanitized = sanitize_line_for_lock_analysis(trimmed);
                let sanitized_trimmed = sanitized.trim();

                if let Some(function_name) = parse_function_name(sanitized_trimmed) {
                    current_function = function_name;
                    previous_lock = None;
                }

                if sanitized_trimmed.is_empty() {
                    continue;
                }

                if sanitized_trimmed.contains(".lock(") {
                    accumulator.lock_acquisitions = accumulator.lock_acquisitions.saturating_add(1);
                    push_unique_evidence(
                        &mut accumulator.evidence,
                        format!("{relative_path}:{line_number}: lock-acquire `{trimmed}`"),
                        12,
                    );
                }

                if has_contention_marker(sanitized_trimmed) {
                    accumulator.contention_markers =
                        accumulator.contention_markers.saturating_add(1);
                    push_unique_evidence(
                        &mut accumulator.evidence,
                        format!("{relative_path}:{line_number}: contention-marker `{trimmed}`"),
                        12,
                    );
                }

                if let Some(current_shard) = detect_lock_shard(sanitized_trimmed) {
                    if let Some((previous_shard, previous_line)) = previous_lock {
                        if current_shard.rank() < previous_shard.rank() {
                            violation_counter = violation_counter.saturating_add(1);
                            accumulator.violation_count =
                                accumulator.violation_count.saturating_add(1);
                            let evidence = vec![
                                format!(
                                    "{relative_path}:{previous_line}: previous lock {}",
                                    previous_shard.label()
                                ),
                                format!(
                                    "{relative_path}:{line_number}: current lock {}",
                                    current_shard.label()
                                ),
                                format!("observed snippet: `{trimmed}`"),
                            ];
                            violations.push(LockOrderViolation {
                                violation_id: format!("lock-order-{violation_counter:03}"),
                                path: relative_path.clone(),
                                function_name: current_function.clone(),
                                expected_order: LOCK_ORDER_CANONICAL.to_string(),
                                observed_transition: format!(
                                    "{} -> {}",
                                    previous_shard.label(),
                                    current_shard.label()
                                ),
                                severity: "error".to_string(),
                                confidence: 90,
                                evidence,
                                remediation_guidance: "Acquire sharded runtime locks in canonical order E(Config) -> D(Instrumentation) -> B(Regions) -> A(Tasks) -> C(Obligations).".to_string(),
                            });
                        }
                    }
                    previous_lock = Some((current_shard, line_number));
                }
            }
        }
    }

    let mut hotspot_entries = hotspots
        .into_iter()
        .filter_map(|(path, accumulator)| {
            let risk_score = compute_lock_hotspot_risk(&accumulator);
            if risk_score == 0 {
                return None;
            }
            Some((path, accumulator, risk_score))
        })
        .collect::<Vec<_>>();

    hotspot_entries.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| right.1.violation_count.cmp(&left.1.violation_count))
    });

    let mut ranked_hotspots = Vec::with_capacity(hotspot_entries.len());
    for (index, (path, accumulator, risk_score)) in hotspot_entries.into_iter().enumerate() {
        ranked_hotspots.push(LockContentionHotspot {
            hotspot_id: format!("lock-hotspot-{:03}", index + 1),
            path,
            lock_acquisitions: accumulator.lock_acquisitions,
            contention_markers: accumulator.contention_markers,
            violation_count: accumulator.violation_count,
            risk_score,
            risk_level: classify_lock_hotspot_risk(risk_score).to_string(),
            confidence: compute_lock_hotspot_confidence(&accumulator),
            evidence: accumulator.evidence,
            remediation_guidance: "Review lock-heavy paths for deterministic shard-order compliance and trim unnecessary lock scope or hold duration.".to_string(),
        });
    }

    violations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.function_name.cmp(&right.function_name))
            .then_with(|| left.violation_id.cmp(&right.violation_id))
    });
    let mut deadlock_pattern_counts: BTreeMap<String, u32> = BTreeMap::new();
    for violation in &violations {
        *deadlock_pattern_counts
            .entry(violation.observed_transition.clone())
            .or_insert(0) += 1;
    }
    let deadlock_risk_patterns = deadlock_pattern_counts.keys().cloned().collect::<Vec<_>>();

    let rule_id = "lock_order_consistency";
    if report.members.is_empty() {
        rule_traces.push(LockContentionRuleTrace {
            rule_id: rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "suppressed".to_string(),
            confidence: 100,
            evidence: vec!["no members discovered in workspace scan".to_string()],
            suppressed_reason: Some("no members discovered".to_string()),
        });
    } else if violations.is_empty() {
        rule_traces.push(LockContentionRuleTrace {
            rule_id: rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 90,
            evidence: vec![
                "no lock-order inversions observed in scanned member sources".to_string(),
            ],
            suppressed_reason: None,
        });
    } else {
        let evidence = violations
            .iter()
            .take(3)
            .map(|violation| {
                format!(
                    "{}:{} ({})",
                    violation.path, violation.observed_transition, violation.function_name
                )
            })
            .collect::<Vec<_>>();
        rule_traces.push(LockContentionRuleTrace {
            rule_id: rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 90,
            evidence,
            suppressed_reason: None,
        });
    }

    let hotspot_rule_id = "contention_hotspot_ranking";
    if ranked_hotspots.is_empty() {
        rule_traces.push(LockContentionRuleTrace {
            rule_id: hotspot_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "suppressed".to_string(),
            confidence: 80,
            evidence: vec![
                "no lock/contention markers observed in scanned member sources".to_string(),
            ],
            suppressed_reason: Some("no lock/contention markers".to_string()),
        });
    } else {
        let evidence = ranked_hotspots
            .iter()
            .take(5)
            .map(|hotspot| {
                format!(
                    "{} score={} locks={} contention={} violations={}",
                    hotspot.path,
                    hotspot.risk_score,
                    hotspot.lock_acquisitions,
                    hotspot.contention_markers,
                    hotspot.violation_count
                )
            })
            .collect::<Vec<_>>();
        rule_traces.push(LockContentionRuleTrace {
            rule_id: hotspot_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 85,
            evidence,
            suppressed_reason: None,
        });
    }

    let deadlock_rule_id = "deadlock_risk_patterns";
    if report.members.is_empty() {
        rule_traces.push(LockContentionRuleTrace {
            rule_id: deadlock_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "suppressed".to_string(),
            confidence: 100,
            evidence: vec!["no members discovered in workspace scan".to_string()],
            suppressed_reason: Some("no members discovered".to_string()),
        });
    } else if deadlock_pattern_counts.is_empty() {
        rule_traces.push(LockContentionRuleTrace {
            rule_id: deadlock_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "pass".to_string(),
            confidence: 90,
            evidence: vec!["no deadlock-risk inversion patterns observed".to_string()],
            suppressed_reason: None,
        });
    } else {
        let evidence = deadlock_pattern_counts
            .iter()
            .take(5)
            .map(|(pattern, count)| format!("{pattern} count={count}"))
            .collect::<Vec<_>>();
        rule_traces.push(LockContentionRuleTrace {
            rule_id: deadlock_rule_id.to_string(),
            correlation_id: correlation_id.clone(),
            outcome: "fail".to_string(),
            confidence: 90,
            evidence,
            suppressed_reason: None,
        });
    }

    rule_traces.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));

    LockContentionAnalyzerReport {
        analyzer_version: LOCK_CONTENTION_ANALYZER_VERSION.to_string(),
        scanner_version: report.scanner_version.clone(),
        correlation_id,
        member_count: report.members.len(),
        hotspot_count: ranked_hotspots.len(),
        violation_count: violations.len(),
        deadlock_risk_patterns,
        hotspots: ranked_hotspots,
        violations,
        rule_traces,
        reproduction_commands: vec![
            format!(
                "asupersync doctor analyze-lock-contention --root {}",
                report.root
            ),
            "rch exec -- cargo test --lib cli::doctor::tests::analyze_workspace_lock_contention_is_deterministic".to_string(),
        ],
    }
}

/// Emit deterministic structured events for lock-order/contention analyzer results.
///
/// # Errors
///
/// Returns `Err` when event envelopes violate the structured logging contract.
pub fn emit_lock_contention_structured_events(
    analysis: &LockContentionAnalyzerReport,
    run_id: &str,
    scenario_id: &str,
) -> Result<Vec<StructuredLogEvent>, String> {
    let contract = structured_logging_contract();
    let normalized_run_id = if run_id.trim().is_empty() {
        "run-lock-contention".to_string()
    } else {
        run_id.trim().to_string()
    };
    let normalized_scenario_id = if scenario_id.trim().is_empty() {
        "doctor-lock-contention".to_string()
    } else {
        scenario_id.trim().to_string()
    };
    let trace_suffix = normalized_run_id
        .strip_prefix("run-")
        .unwrap_or(&normalized_run_id);
    let command_provenance = analysis
        .reproduction_commands
        .first()
        .cloned()
        .unwrap_or_else(|| "asupersync doctor analyze-lock-contention --root .".to_string());

    let mut events = Vec::new();
    for hotspot in analysis.hotspots.iter().take(5) {
        let mut fields = BTreeMap::new();
        fields.insert(
            "artifact_pointer".to_string(),
            format!(
                "artifacts/{normalized_run_id}/integration/{}.json",
                hotspot.hotspot_id
            ),
        );
        fields.insert("command_provenance".to_string(), command_provenance.clone());
        fields.insert("flow_id".to_string(), "integration".to_string());
        fields.insert(
            "outcome_class".to_string(),
            if hotspot.violation_count > 0 {
                "failed".to_string()
            } else {
                "success".to_string()
            },
        );
        fields.insert("run_id".to_string(), normalized_run_id.clone());
        fields.insert("scenario_id".to_string(), normalized_scenario_id.clone());
        fields.insert(
            "trace_id".to_string(),
            format!("trace-{trace_suffix}-{}", hotspot.hotspot_id),
        );
        fields.insert(
            "integration_target".to_string(),
            "lock_order_contention_analyzer".to_string(),
        );
        fields.insert("risk_score".to_string(), hotspot.risk_score.to_string());
        fields.insert("risk_level".to_string(), hotspot.risk_level.clone());
        fields.insert("confidence".to_string(), hotspot.confidence.to_string());
        fields.insert(
            "lock_acquisition_count".to_string(),
            hotspot.lock_acquisitions.to_string(),
        );
        fields.insert(
            "contention_marker_count".to_string(),
            hotspot.contention_markers.to_string(),
        );
        fields.insert(
            "violation_count".to_string(),
            hotspot.violation_count.to_string(),
        );
        fields.insert(
            "threshold_explanation".to_string(),
            lock_hotspot_threshold_explanation(hotspot.risk_score).to_string(),
        );
        fields.insert(
            "lock_sequence".to_string(),
            hotspot.evidence.first().cloned().unwrap_or_default(),
        );
        let event =
            emit_structured_log_event(&contract, "integration", "integration_sync", &fields)?;
        events.push(event);
    }

    let mut summary_fields = BTreeMap::new();
    summary_fields.insert(
        "artifact_pointer".to_string(),
        format!("artifacts/{normalized_run_id}/integration/verification_summary.json"),
    );
    summary_fields.insert("command_provenance".to_string(), command_provenance);
    summary_fields.insert("flow_id".to_string(), "integration".to_string());
    summary_fields.insert(
        "outcome_class".to_string(),
        if analysis.violation_count > 0 {
            "failed".to_string()
        } else {
            "success".to_string()
        },
    );
    summary_fields.insert("run_id".to_string(), normalized_run_id.clone());
    summary_fields.insert("scenario_id".to_string(), normalized_scenario_id);
    summary_fields.insert(
        "trace_id".to_string(),
        format!("trace-{trace_suffix}-verification"),
    );
    summary_fields.insert(
        "integration_target".to_string(),
        "lock_order_contention_analyzer".to_string(),
    );
    summary_fields.insert(
        "violation_count".to_string(),
        analysis.violation_count.to_string(),
    );
    summary_fields.insert(
        "hotspot_count".to_string(),
        analysis.hotspot_count.to_string(),
    );
    summary_fields.insert(
        "deadlock_risk_pattern_count".to_string(),
        analysis.deadlock_risk_patterns.len().to_string(),
    );
    events.push(emit_structured_log_event(
        &contract,
        "integration",
        "verification_summary",
        &summary_fields,
    )?);

    events.sort_by(|left, right| {
        (
            left.flow_id.as_str(),
            left.event_kind.as_str(),
            left.fields
                .get("trace_id")
                .map(String::as_str)
                .unwrap_or_default(),
        )
            .cmp(&(
                right.flow_id.as_str(),
                right.event_kind.as_str(),
                right
                    .fields
                    .get("trace_id")
                    .map(String::as_str)
                    .unwrap_or_default(),
            ))
    });

    Ok(events)
}

fn compute_lock_hotspot_risk(accumulator: &LockHotspotAccumulator) -> u32 {
    accumulator
        .lock_acquisitions
        .saturating_mul(2)
        .saturating_add(accumulator.contention_markers.saturating_mul(12))
        .saturating_add(accumulator.violation_count.saturating_mul(40))
}

fn compute_lock_hotspot_confidence(accumulator: &LockHotspotAccumulator) -> u8 {
    let mut confidence = 70;
    if accumulator.lock_acquisitions >= 2 {
        confidence += 5;
    }
    if accumulator.contention_markers >= 1 {
        confidence += 10;
    }
    if accumulator.violation_count >= 1 {
        confidence += 15;
    }
    confidence.min(95)
}

fn lock_hotspot_threshold_explanation(score: u32) -> &'static str {
    if score >= 160 {
        "critical: score >= 160 (high contention and/or repeated lock-order inversions)"
    } else if score >= 90 {
        "high: score in [90, 159] (strong contention signal with elevated deadlock risk)"
    } else if score >= 40 {
        "medium: score in [40, 89] (moderate lock pressure; monitor lock scope/hold time)"
    } else {
        "low: score < 40 (baseline lock pressure)"
    }
}

fn classify_lock_hotspot_risk(score: u32) -> &'static str {
    if score >= 160 {
        "critical"
    } else if score >= 90 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "low"
    }
}

fn parse_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let function_start = trimmed.find("fn ")?;
    let remainder = &trimmed[function_start + 3..];
    let identifier = remainder
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    if identifier.is_empty() {
        None
    } else {
        Some(identifier)
    }
}

fn sanitize_line_for_lock_analysis(line: &str) -> String {
    let mut sanitized = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;
    let mut in_char = false;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if in_string {
            if escaped {
                escaped = false;
                sanitized.push(' ');
                continue;
            }
            if ch == '\\' {
                escaped = true;
                sanitized.push(' ');
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            sanitized.push(' ');
            continue;
        }

        if in_char {
            if escaped {
                escaped = false;
                sanitized.push(' ');
                continue;
            }
            if ch == '\\' {
                escaped = true;
                sanitized.push(' ');
                continue;
            }
            if ch == '\'' {
                in_char = false;
            }
            sanitized.push(' ');
            continue;
        }

        if ch == '"' {
            in_string = true;
            sanitized.push(' ');
            continue;
        }
        if ch == '\'' {
            in_char = true;
            sanitized.push(' ');
            continue;
        }
        if ch == '/' && chars.peek().copied() == Some('/') {
            break;
        }
        sanitized.push(ch);
    }

    sanitized
}

fn detect_lock_shard(line: &str) -> Option<LockShard> {
    if !line.contains(".lock(") {
        return None;
    }
    let normalized = line.replace(' ', "");
    if normalized.contains(".config.lock(") {
        Some(LockShard::Config)
    } else if normalized.contains(".instrumentation.lock(") {
        Some(LockShard::Instrumentation)
    } else if normalized.contains(".regions.lock(") {
        Some(LockShard::Regions)
    } else if normalized.contains(".tasks.lock(") {
        Some(LockShard::Tasks)
    } else if normalized.contains(".obligations.lock(") {
        Some(LockShard::Obligations)
    } else {
        None
    }
}

fn has_contention_marker(line: &str) -> bool {
    [
        "ContendedMutex",
        "lock-metrics",
        "lock_wait_ns",
        "lock_hold_ns",
        "contention",
        "try_lock(",
        "parking_lot::",
    ]
    .iter()
    .any(|marker| line.contains(marker))
}

fn push_unique_evidence(evidence: &mut Vec<String>, entry: String, limit: usize) {
    if evidence.len() >= limit || evidence.iter().any(|existing| existing == &entry) {
        return;
    }
    evidence.push(entry);
}

fn resolve_member_dirs(
    root: &Path,
    workspace_members: &[String],
    workspace_excludes: &[String],
    log: &mut ScanLog,
) -> io::Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>)> {
    let mut member_dirs = BTreeSet::new();
    if workspace_members.is_empty() {
        member_dirs.insert(root.to_path_buf());
        log.info(
            "member_discovery",
            "no workspace members declared; treating root package as single member",
            Some(".".to_string()),
        );
    } else {
        for pattern in workspace_members {
            for path in expand_member_pattern(root, pattern, log)? {
                member_dirs.insert(path);
            }
        }
    }

    let mut excluded_dirs = BTreeSet::new();
    for pattern in workspace_excludes {
        for path in expand_member_pattern(root, pattern, log)? {
            excluded_dirs.insert(path);
        }
    }

    Ok((member_dirs, excluded_dirs))
}

fn collect_member_scans(
    root: &Path,
    member_dirs: &BTreeSet<PathBuf>,
    excluded_dirs: &BTreeSet<PathBuf>,
    log: &mut ScanLog,
) -> io::Result<Vec<MemberScan>> {
    let mut member_scans = Vec::new();
    for member_dir in member_dirs {
        if excluded_dirs.contains(member_dir) {
            log.info(
                "member_discovery",
                "excluded workspace member",
                Some(relative_to(root, member_dir)),
            );
            continue;
        }
        match scan_member(root, member_dir, log)? {
            Some(scan) => {
                log.info(
                    "member_scan",
                    format!(
                        "scanned member {} with {} detected surfaces",
                        scan.member.name,
                        scan.member.capability_surfaces.len()
                    ),
                    Some(scan.member.relative_path.clone()),
                );
                member_scans.push(scan);
            }
            None => {
                log.warn(
                    "member_scan",
                    format!(
                        "member missing Cargo.toml: {}",
                        relative_to(root, member_dir)
                    ),
                    Some(relative_to(root, member_dir)),
                );
            }
        }
    }
    member_scans.sort_by(|a, b| a.member.relative_path.cmp(&b.member.relative_path));
    Ok(member_scans)
}

fn build_members_and_edges(
    member_scans: Vec<MemberScan>,
) -> (Vec<WorkspaceMember>, Vec<CapabilityEdge>) {
    let mut members = Vec::with_capacity(member_scans.len());
    let mut edges = Vec::new();
    for scan in member_scans {
        for (surface, files) in &scan.evidence {
            let sample_files = files
                .iter()
                .take(MAX_SAMPLE_FILES)
                .cloned()
                .collect::<Vec<_>>();
            edges.push(CapabilityEdge {
                member: scan.member.name.clone(),
                surface: surface.clone(),
                evidence_count: files.len(),
                sample_files,
            });
        }
        members.push(scan.member);
    }

    edges.sort_by(|a, b| {
        a.member
            .cmp(&b.member)
            .then_with(|| a.surface.cmp(&b.surface))
    });
    (members, edges)
}

fn scan_member(
    root: &Path,
    member_dir: &Path,
    log: &mut ScanLog,
) -> io::Result<Option<MemberScan>> {
    let manifest_path = member_dir.join("Cargo.toml");
    if !manifest_path.is_file() {
        return Ok(None);
    }

    let manifest_text = fs::read_to_string(&manifest_path)?;
    let member_relative_path = relative_to(root, member_dir);
    let package_name = parse_package_name(&manifest_text, &member_relative_path, log)
        .unwrap_or_else(|| {
            member_dir
                .file_name()
                .and_then(|name| name.to_str())
                .map_or_else(|| "unknown".to_string(), ToString::to_string)
        });

    let source_root = member_dir.join("src");
    let rust_files = collect_rust_files(&source_root)?;
    let rust_file_count = rust_files.len();
    let mut evidence: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for file in rust_files {
        let source = fs::read_to_string(&file)?;
        let matched_surfaces = detect_surfaces(&source);
        if matched_surfaces.is_empty() {
            continue;
        }
        let relative_file = relative_to(root, &file);
        for surface in matched_surfaces {
            evidence
                .entry(surface.to_string())
                .or_default()
                .insert(relative_file.clone());
        }
    }

    let member = WorkspaceMember {
        name: package_name,
        relative_path: relative_to(root, member_dir),
        manifest_path: relative_to(root, &manifest_path),
        rust_file_count,
        capability_surfaces: evidence.keys().cloned().collect(),
    };

    Ok(Some(MemberScan { member, evidence }))
}

fn parse_workspace_string_array(manifest: &str, key: &str, log: &mut ScanLog) -> Vec<String> {
    let mut in_workspace = false;
    let mut collecting = false;
    let mut buffer = String::new();
    let mut values = Vec::new();
    let prefix = format!("{key} =");

    for line in manifest.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('[') {
            if collecting {
                let parsed = parse_string_array_literal(&buffer);
                values.extend(parsed.values);
                if parsed.malformed {
                    log.warn(
                        "workspace_manifest",
                        format!("malformed workspace array for key `{key}`"),
                        None,
                    );
                }
                buffer.clear();
                collecting = false;
            }
            in_workspace = trimmed == "[workspace]";
            continue;
        }

        if !in_workspace {
            continue;
        }

        if !collecting && trimmed.starts_with(&prefix) {
            collecting = true;
            if let Some((_, rhs)) = trimmed.split_once('=') {
                buffer.push_str(rhs.trim_start());
                buffer.push('\n');
            }
            if trimmed.contains(']') {
                let parsed = parse_string_array_literal(&buffer);
                values.extend(parsed.values);
                if parsed.malformed {
                    log.warn(
                        "workspace_manifest",
                        format!("malformed workspace array for key `{key}`"),
                        None,
                    );
                }
                buffer.clear();
                collecting = false;
            }
            continue;
        }

        if collecting {
            buffer.push_str(trimmed);
            buffer.push('\n');
            if trimmed.contains(']') {
                let parsed = parse_string_array_literal(&buffer);
                values.extend(parsed.values);
                if parsed.malformed {
                    log.warn(
                        "workspace_manifest",
                        format!("malformed workspace array for key `{key}`"),
                        None,
                    );
                }
                buffer.clear();
                collecting = false;
            }
        }
    }

    if collecting {
        let parsed = parse_string_array_literal(&buffer);
        values.extend(parsed.values);
        log.warn(
            "workspace_manifest",
            format!("unterminated workspace array for key `{key}`"),
            None,
        );
    }

    values
}

fn parse_string_array_literal(text: &str) -> ParsedStringArray {
    let mut malformed = false;
    let limit = text.find(']').unwrap_or_else(|| {
        malformed = true;
        text.len()
    });
    let slice = &text[..limit];
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escaped = false;

    for ch in slice.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => {
                if in_string {
                    values.push(current.clone());
                    current.clear();
                    in_string = false;
                } else {
                    in_string = true;
                }
            }
            _ if in_string => current.push(ch),
            _ => {}
        }
    }

    if in_string || escaped {
        malformed = true;
    }

    ParsedStringArray { values, malformed }
}

fn parse_package_name(manifest: &str, member_relative: &str, log: &mut ScanLog) -> Option<String> {
    let mut in_package = false;
    let mut saw_package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
            if in_package {
                saw_package = true;
            }
            continue;
        }
        if !in_package || !trimmed.starts_with("name =") {
            continue;
        }
        let parsed = parse_string_array_literal(trimmed);
        if parsed.malformed {
            log.warn(
                "member_scan",
                "malformed package name field in Cargo.toml".to_string(),
                Some(member_relative.to_string()),
            );
        }
        if let Some(name) = parsed.values.first() {
            return Some(name.clone());
        }
    }
    if saw_package {
        log.warn(
            "member_scan",
            "missing package name in Cargo.toml".to_string(),
            Some(member_relative.to_string()),
        );
    }
    None
}

fn expand_member_pattern(
    root: &Path,
    pattern: &str,
    log: &mut ScanLog,
) -> io::Result<Vec<PathBuf>> {
    if !pattern.contains('*') {
        return Ok(vec![root.join(pattern)]);
    }

    if let Some(base) = pattern.strip_suffix("/*") {
        let base_dir = root.join(base);
        if !base_dir.is_dir() {
            log.warn(
                "member_discovery",
                format!("wildcard base missing: {}", base_dir.display()),
                Some(relative_to(root, &base_dir)),
            );
            return Ok(Vec::new());
        }
        let mut dirs = Vec::new();
        for entry in fs::read_dir(base_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                dirs.push(entry.path());
            }
        }
        dirs.sort();
        return Ok(dirs);
    }

    log.warn(
        "member_discovery",
        format!("unsupported workspace member glob pattern: {pattern}"),
        None,
    );
    Ok(Vec::new())
}

fn collect_rust_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let mut entries = fs::read_dir(&dir)?.collect::<Result<Vec<_>, io::Error>>()?;
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|ext| ext.to_str()) == Some("rs")
            {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn detect_surfaces(source: &str) -> BTreeSet<&'static str> {
    let mut surfaces = BTreeSet::new();
    for (surface, markers) in SURFACE_MARKERS {
        if markers.iter().any(|marker| source.contains(marker)) {
            surfaces.insert(surface);
        }
    }
    surfaces
}

fn relative_to(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directories");
        }
        fs::write(path, content).expect("write file");
    }

    fn make_single_member_workspace_report(source: &str) -> WorkspaceScanReport {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crate_a/src/lib.rs"), source);
        scan_workspace(root).expect("scan workspace")
    }

    #[test]
    fn scan_workspace_discovers_members_and_surfaces() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a", "crate_b"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crate_a/src/lib.rs"),
            "use asupersync::Cx;\nuse asupersync::Scope;\nuse asupersync::channel::mpsc;\n",
        );
        write_file(
            &root.join("crate_b/Cargo.toml"),
            r#"[package]
name = "crate_b"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crate_b/src/lib.rs"),
            "use asupersync::runtime::RuntimeBuilder;\nuse asupersync::lab::LabRuntime;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].name, "crate_a");
        assert_eq!(report.members[1].name, "crate_b");
        assert_eq!(report.scanner_version, SCANNER_VERSION);
        assert_eq!(report.taxonomy_version, TAXONOMY_VERSION);
        assert!(
            report
                .events
                .iter()
                .any(|event| event.phase == "scan_complete")
        );
        assert!(
            report
                .capability_edges
                .iter()
                .any(|edge| edge.surface == "cx")
        );
        assert!(
            report
                .capability_edges
                .iter()
                .any(|edge| edge.surface == "runtime")
        );
    }

    #[test]
    fn scan_workspace_supports_simple_wildcard_members() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/*"]
"#,
        );
        write_file(
            &root.join("crates/a/Cargo.toml"),
            r#"[package]
name = "a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crates/a/src/lib.rs"), "use asupersync::Cx;\n");
        write_file(
            &root.join("crates/b/Cargo.toml"),
            r#"[package]
name = "b"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("crates/b/src/lib.rs"),
            "use asupersync::trace::ReplayEvent;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 2);
        assert_eq!(report.members[0].name, "a");
        assert_eq!(report.members[1].name, "b");
    }

    #[test]
    fn scan_workspace_reports_missing_member_manifest() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["missing_member"]
"#,
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert!(report.members.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("missing Cargo.toml"))
        );
        assert!(report.events.iter().any(|event| event.level == "warn"));
    }

    #[test]
    fn scan_workspace_falls_back_to_single_package_root() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[package]
name = "root_pkg"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(
            &root.join("src/lib.rs"),
            "use asupersync::Cx;\nuse asupersync::Budget;\nuse asupersync::Outcome;\n",
        );

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members.len(), 1);
        assert_eq!(report.members[0].name, "root_pkg");
        assert!(
            report.members[0]
                .capability_surfaces
                .iter()
                .any(|surface| surface == "cx")
        );
    }

    #[test]
    fn scan_workspace_warns_on_unterminated_workspace_array() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a"
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = "crate_a"
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crate_a/src/lib.rs"), "use asupersync::Cx;\n");

        let report = scan_workspace(root).expect("scan workspace");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("unterminated workspace array"))
        );
    }

    #[test]
    fn scan_workspace_warns_on_malformed_package_name() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();

        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["crate_a"]
"#,
        );
        write_file(
            &root.join("crate_a/Cargo.toml"),
            r#"[package]
name = crate_a
version = "0.1.0"
edition = "2024"
"#,
        );
        write_file(&root.join("crate_a/src/lib.rs"), "use asupersync::Cx;\n");

        let report = scan_workspace(root).expect("scan workspace");
        assert_eq!(report.members[0].name, "crate_a");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("malformed package name"))
        );
    }

    #[test]
    fn analyze_workspace_invariants_flags_missing_cancel_and_obligation_markers() {
        let report =
            make_single_member_workspace_report("use asupersync::Cx;\nuse asupersync::Scope;\n");
        let analysis = analyze_workspace_invariants(&report);

        assert_eq!(analysis.analyzer_version, INVARIANT_ANALYZER_VERSION);
        assert_eq!(analysis.member_count, 1);
        assert_eq!(analysis.finding_count, analysis.findings.len());

        let finding_rule_ids = analysis
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(finding_rule_ids.contains("cancel_phase_surface"));
        assert!(finding_rule_ids.contains("obligation_surface"));
        assert!(!finding_rule_ids.contains("scan_lifecycle_events"));

        let lifecycle_trace = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "scan_lifecycle_events")
            .expect("lifecycle trace");
        assert_eq!(lifecycle_trace.outcome, "pass");
    }

    #[test]
    fn analyze_workspace_invariants_flags_missing_scan_complete_event() {
        let report = make_single_member_workspace_report(
            "use asupersync::Cx;\nuse asupersync::Scope;\nuse asupersync::cancel::CancelReason;\nuse asupersync::obligation::Obligation;\n",
        );
        let mut broken = report.clone();
        broken.events.retain(|event| event.phase != "scan_complete");

        let analysis = analyze_workspace_invariants(&broken);
        let finding = analysis
            .findings
            .iter()
            .find(|candidate| candidate.rule_id == "scan_lifecycle_events")
            .expect("lifecycle finding");
        assert_eq!(finding.severity, "error");
        assert!(
            finding
                .evidence
                .iter()
                .any(|line| line.contains("scan_complete"))
        );
    }

    #[test]
    fn analyze_workspace_invariants_suppresses_surface_rules_without_members() {
        let temp = tempdir().expect("temp dir");
        let root = temp.path();
        write_file(
            &root.join("Cargo.toml"),
            r#"[workspace]
members = ["missing_member"]
"#,
        );
        let report = scan_workspace(root).expect("scan workspace");
        assert!(report.members.is_empty());

        let analysis = analyze_workspace_invariants(&report);
        for suppressed_rule in [
            "cancel_phase_surface",
            "obligation_surface",
            "structured_concurrency_surface",
        ] {
            let trace = analysis
                .rule_traces
                .iter()
                .find(|candidate| candidate.rule_id == suppressed_rule)
                .expect("suppressed trace");
            assert_eq!(trace.outcome, "suppressed");
            assert_eq!(
                trace.suppressed_reason.as_deref(),
                Some("no members discovered")
            );
        }
        assert!(
            analysis
                .findings
                .iter()
                .any(|finding| finding.rule_id == "scanner_warning_integrity")
        );
    }

    #[test]
    fn analyze_workspace_invariants_is_deterministic() {
        let report = make_single_member_workspace_report(
            "use asupersync::Cx;\nuse asupersync::Scope;\nuse asupersync::cancel::CancelReason;\nuse asupersync::obligation::Obligation;\n",
        );
        let first = analyze_workspace_invariants(&report);
        let second = analyze_workspace_invariants(&report);
        assert_eq!(first, second);
        assert_eq!(first.rule_traces.len(), 5);
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "structured_concurrency_surface"
                    && trace.outcome == "pass")
        );
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "scan_lifecycle_events" && trace.outcome == "pass")
        );
    }

    #[test]
    fn analyze_workspace_lock_contention_detects_violation_and_hotspots() {
        let report = make_single_member_workspace_report(
            r#"
struct RuntimeState;
impl RuntimeState {
    fn bad_order(&self) {
        let _tasks = self.tasks.lock();
        let _regions = self.regions.lock();
        let _obligations = self.obligations.lock();
    }

    fn contention_marker(&self) {
        let _instrumentation = self.instrumentation.lock();
        // lock_wait_ns and lock_hold_ns are emitted by lock metrics.
    }
}
"#,
        );
        let analysis = analyze_workspace_lock_contention(&report);
        assert_eq!(analysis.analyzer_version, LOCK_CONTENTION_ANALYZER_VERSION);
        assert!(analysis.hotspot_count >= 1);
        assert!(analysis.violation_count >= 1);
        assert!(
            analysis
                .deadlock_risk_patterns
                .iter()
                .any(|pattern| pattern.contains("A(Tasks) -> B(Regions)"))
        );
        assert!(analysis.violations.iter().any(|violation| {
            violation
                .observed_transition
                .contains("A(Tasks) -> B(Regions)")
        }));
        let lock_rule = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "lock_order_consistency")
            .expect("lock-order trace");
        assert_eq!(lock_rule.outcome, "fail");
        let deadlock_rule = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "deadlock_risk_patterns")
            .expect("deadlock trace");
        assert_eq!(deadlock_rule.outcome, "fail");
    }

    #[test]
    fn analyze_workspace_lock_contention_ignores_comments_and_string_literals() {
        let report = make_single_member_workspace_report(
            r#"
impl RuntimeState {
    fn comments_and_strings_only(&self) {
        // let _tasks = self.tasks.lock();
        let _text = "self.regions.lock(); lock_wait_ns";
        let _char = '.';
    }
}
"#,
        );
        let analysis = analyze_workspace_lock_contention(&report);
        assert_eq!(analysis.hotspot_count, 0);
        assert_eq!(analysis.violation_count, 0);
        assert!(analysis.deadlock_risk_patterns.is_empty());
        let hotspot_rule = analysis
            .rule_traces
            .iter()
            .find(|trace| trace.rule_id == "contention_hotspot_ranking")
            .expect("hotspot trace");
        assert_eq!(hotspot_rule.outcome, "suppressed");
    }

    #[test]
    fn analyze_workspace_lock_contention_is_deterministic() {
        let report = make_single_member_workspace_report(
            r#"
impl RuntimeState {
    fn deterministic_lock_path(&self) {
        let _config = self.config.lock();
        let _instrumentation = self.instrumentation.lock();
        let _regions = self.regions.lock();
        let _tasks = self.tasks.lock();
        let _obligations = self.obligations.lock();
    }
}
"#,
        );
        let first = analyze_workspace_lock_contention(&report);
        let second = analyze_workspace_lock_contention(&report);
        assert_eq!(first, second);
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "contention_hotspot_ranking")
        );
        assert!(
            first
                .rule_traces
                .iter()
                .any(|trace| trace.rule_id == "deadlock_risk_patterns")
        );
    }

    #[test]
    fn emit_lock_contention_structured_events_are_valid_and_deterministic() {
        let report = make_single_member_workspace_report(
            r#"
impl RuntimeState {
    fn lock_path(&self) {
        let _tasks = self.tasks.lock();
        let _regions = self.regions.lock();
        // contention marker for scoring
        let _ = "lock_wait_ns";
    }
}
"#,
        );
        let analysis = analyze_workspace_lock_contention(&report);
        let first = emit_lock_contention_structured_events(
            &analysis,
            "run-lock-contention-smoke",
            "doctor-lock-contention-smoke",
        )
        .expect("first events");
        let second = emit_lock_contention_structured_events(
            &analysis,
            "run-lock-contention-smoke",
            "doctor-lock-contention-smoke",
        )
        .expect("second events");
        assert_eq!(first, second);
        let contract = structured_logging_contract();
        validate_structured_logging_event_stream(&contract, &first).expect("valid event stream");
        assert!(
            first
                .iter()
                .any(|event| event.fields.get("risk_score").is_some())
        );
        assert!(
            first
                .iter()
                .any(|event| event.fields.get("threshold_explanation").is_some())
        );
    }

    #[test]
    fn operator_model_contract_validates() {
        let contract = operator_model_contract();
        validate_operator_model_contract(&contract).expect("valid operator contract");
    }

    #[test]
    fn operator_model_contract_is_deterministic() {
        let first = operator_model_contract();
        let second = operator_model_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn operator_model_contract_round_trip_json() {
        let contract = operator_model_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: OperatorModelContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_operator_model_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn operator_model_contract_rejects_duplicate_persona_ids() {
        let mut contract = operator_model_contract();
        contract.personas.push(contract.personas[0].clone());
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("duplicate persona id"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_unsorted_mission_success_signals() {
        let mut contract = operator_model_contract();
        contract.personas[0].mission_success_signals =
            vec!["z_signal".to_string(), "a_signal".to_string()];
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("mission_success_signals must be lexically sorted"));
    }

    #[test]
    fn operator_model_contract_rejects_unknown_decision_step_binding() {
        let mut contract = operator_model_contract();
        contract.personas[0].high_stakes_decisions[0].decision_step = "unknown_step".to_string();
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown step"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_decision_evidence_outside_contract() {
        let mut contract = operator_model_contract();
        contract.personas[0].high_stakes_decisions[0]
            .required_evidence
            .push("not_in_contract".to_string());
        contract.personas[0].high_stakes_decisions[0]
            .required_evidence
            .sort();
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown evidence key"), "{err}");
    }

    #[test]
    fn operator_model_contract_navigation_topology_matches_screen_contract() {
        let contract = operator_model_contract();
        let topology_screens: BTreeSet<_> = contract
            .navigation_topology
            .screens
            .iter()
            .map(|screen| screen.id.clone())
            .collect();
        let screen_contract_screens: BTreeSet<_> = screen_engine_contract()
            .screens
            .iter()
            .map(|screen| screen.id.clone())
            .collect();
        assert_eq!(topology_screens, screen_contract_screens);
    }

    #[test]
    fn operator_model_contract_rejects_unsorted_navigation_screens() {
        let mut contract = operator_model_contract();
        contract.navigation_topology.screens.swap(0, 1);
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("navigation_topology.screens must be lexically sorted by id"),
            "{err}"
        );
    }

    #[test]
    fn operator_model_contract_rejects_route_with_unknown_screen() {
        let mut contract = operator_model_contract();
        contract.navigation_topology.routes[0].to_screen = "unknown_screen".to_string();
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown screen"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_route_event_missing_core_field() {
        let mut contract = operator_model_contract();
        contract.navigation_topology.route_events[0]
            .required_fields
            .retain(|field| field != "trace_id");
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(err.contains("missing required field trace_id"), "{err}");
    }

    #[test]
    fn operator_model_contract_rejects_duplicate_keyboard_binding_scope_key() {
        let mut contract = operator_model_contract();
        contract
            .navigation_topology
            .keyboard_bindings
            .push(contract.navigation_topology.keyboard_bindings[0].clone());
        let err = validate_operator_model_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("duplicate navigation keyboard binding"),
            "{err}"
        );
    }

    #[test]
    fn ux_signoff_matrix_contract_validates() {
        let contract = ux_signoff_matrix_contract();
        validate_ux_signoff_matrix_contract(&contract).expect("valid ux signoff matrix");
    }

    #[test]
    fn ux_signoff_matrix_contract_is_deterministic() {
        let first = ux_signoff_matrix_contract();
        let second = ux_signoff_matrix_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn ux_signoff_matrix_contract_round_trip_json() {
        let contract = ux_signoff_matrix_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: UxSignoffMatrixContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_ux_signoff_matrix_contract(&parsed).expect("parsed ux signoff matrix valid");
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_unsorted_journeys() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys.swap(0, 1);
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("ux_signoff journeys must be lexically sorted by journey_id"),
            "{err}"
        );
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_transition_route_mismatch() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys[0].transitions[0].route_ref =
            "route_incident_console_to_runtime_health".to_string();
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(err.contains("mismatches"), "{err}");
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_missing_interruption_assertions() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys[1].interruption_assertions.clear();
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("interruption_assertions must be non-empty"),
            "{err}"
        );
    }

    #[test]
    fn ux_signoff_matrix_contract_rejects_unknown_evidence_key() {
        let mut contract = ux_signoff_matrix_contract();
        contract.journeys[2].evidence_assertions[0]
            .required_evidence_keys
            .push("unknown_evidence_key".to_string());
        contract.journeys[2].evidence_assertions[0]
            .required_evidence_keys
            .sort();
        let err = validate_ux_signoff_matrix_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown evidence key"), "{err}");
    }

    #[test]
    fn screen_engine_contract_validates() {
        let contract = screen_engine_contract();
        validate_screen_engine_contract(&contract).expect("valid screen contract");
    }

    #[test]
    fn screen_engine_contract_is_deterministic() {
        let first = screen_engine_contract();
        let second = screen_engine_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn screen_engine_contract_round_trip_json() {
        let contract = screen_engine_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: ScreenEngineContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_screen_engine_contract(&parsed).expect("parsed screen contract valid");
    }

    #[test]
    fn screen_engine_contract_version_support_checks() {
        let contract = screen_engine_contract();
        let current_version = contract.contract_version.clone();
        assert!(is_screen_contract_version_supported(
            &contract,
            &current_version
        ));

        let mut with_legacy = contract.clone();
        with_legacy.compatibility.minimum_reader_version = current_version.clone();
        with_legacy.compatibility.supported_reader_versions = vec![
            "doctor-screen-engine-v0".to_string(),
            current_version.clone(),
        ];
        assert!(!is_screen_contract_version_supported(
            &with_legacy,
            "doctor-screen-engine-v0"
        ));

        let mut invalid = contract;
        invalid.compatibility.supported_reader_versions =
            vec![current_version, "doctor-screen-engine-v0".to_string()];
        let err = validate_screen_engine_contract(&invalid).expect_err("must fail");
        assert!(
            err.contains("supported_reader_versions must be lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn screen_exchange_enforces_required_fields_and_logs_rejection_context() {
        let contract = screen_engine_contract();
        let request = ScreenExchangeRequest {
            screen_id: "runtime_health".to_string(),
            correlation_id: "corr-001".to_string(),
            rerun_context: "br-2b4jj.1.1/run-001".to_string(),
            payload: BTreeMap::new(),
            outcome: ExchangeOutcome::Success,
        };

        let rejection = simulate_screen_exchange(&contract, &request).expect_err("must reject");
        assert_eq!(rejection.contract_version, contract.contract_version);
        assert_eq!(rejection.correlation_id, request.correlation_id);
        assert_eq!(rejection.rerun_context, request.rerun_context);
        assert_eq!(
            rejection.validation_failures,
            vec![
                "missing required request field action".to_string(),
                "missing required request field focus_target".to_string(),
                "missing required request field run_id".to_string(),
            ]
        );
    }

    #[test]
    fn screen_exchange_simulates_success_cancelled_and_failed_paths() {
        let contract = screen_engine_contract();
        let mut payload = BTreeMap::new();
        payload.insert("action".to_string(), "refresh".to_string());
        payload.insert("focus_target".to_string(), "runtime:core".to_string());
        payload.insert("run_id".to_string(), "run-001".to_string());

        for (outcome, expected_state, expected_class) in [
            (ExchangeOutcome::Success, "ready", "success"),
            (ExchangeOutcome::Cancelled, "cancelled", "cancelled"),
            (ExchangeOutcome::Failed, "failed", "failed"),
        ] {
            let request = ScreenExchangeRequest {
                screen_id: "runtime_health".to_string(),
                correlation_id: format!("corr-{expected_class}"),
                rerun_context: "br-2b4jj.1.1/run-002".to_string(),
                payload: payload.clone(),
                outcome,
            };

            let envelope =
                simulate_screen_exchange(&contract, &request).expect("contract exchange");
            assert_eq!(envelope.contract_version, contract.contract_version);
            assert_eq!(envelope.screen_id, request.screen_id);
            assert_eq!(envelope.outcome_class, expected_class);
            assert_eq!(
                envelope.response_payload.get("state"),
                Some(&expected_state.to_string())
            );
            assert_eq!(
                envelope.response_payload.get("outcome_class"),
                Some(&expected_class.to_string())
            );
            assert_eq!(
                envelope.response_payload.get("confidence_score"),
                Some(&"1.0".to_string())
            );
            assert_eq!(
                envelope.response_payload.get("findings"),
                Some(&"[]".to_string())
            );
        }
    }

    #[test]
    fn visual_language_contract_validates() {
        let contract = visual_language_contract();
        validate_visual_language_contract(&contract).expect("valid visual contract");
    }

    #[test]
    fn visual_language_contract_is_deterministic() {
        let first = visual_language_contract();
        let second = visual_language_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn visual_language_contract_round_trip_json() {
        let contract = visual_language_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: VisualLanguageContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_visual_language_contract(&parsed).expect("parsed visual contract valid");
    }

    #[test]
    fn visual_language_contract_rejects_unsorted_non_goals() {
        let mut contract = visual_language_contract();
        contract.non_goals = vec!["z".to_string(), "a".to_string()];
        let err = validate_visual_language_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("non_goals must be unique and lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn visual_language_contract_rejects_capability_raising_fallback() {
        let mut contract = visual_language_contract();
        contract.profiles[0].fallback_profile_id = Some("showcase_truecolor".to_string());
        let err = validate_visual_language_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("must not increase capability requirements"),
            "{err}"
        );
    }

    #[test]
    fn simulate_visual_token_application_falls_back_for_ansi16() {
        let contract = visual_language_contract();
        let transcript = simulate_visual_token_application(
            &contract,
            "incident_console",
            "corr-visual-1",
            TerminalCapabilityClass::Ansi16,
        )
        .expect("simulate");

        assert!(transcript.fallback_applied);
        assert_eq!(transcript.selected_profile_id, "showcase_ansi16");
        assert_eq!(
            transcript.applied_layout_motif,
            "priority queue + inline evidence bullets"
        );
        assert!(
            transcript
                .events
                .iter()
                .any(|event| event.event_kind == "theme_fallback")
        );
        assert!(
            transcript
                .events
                .iter()
                .any(|event| event.event_kind == "layout_degradation")
        );
    }

    #[test]
    fn simulate_visual_token_application_logs_missing_role_event() {
        let mut contract = visual_language_contract();
        contract.profiles[0]
            .palette_tokens
            .retain(|token| token.role != "warning");

        let transcript = simulate_visual_token_application(
            &contract,
            "bead_command_center",
            "corr-visual-2",
            TerminalCapabilityClass::Ansi16,
        )
        .expect("simulate");

        assert_eq!(transcript.missing_roles, vec!["warning".to_string()]);
        assert!(
            transcript
                .events
                .iter()
                .any(|event| event.event_kind == "token_resolution_failure")
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn simulate_visual_token_application_viewport_matrix_snapshots_are_stable() {
        let contract = visual_language_contract();
        let scenarios = vec![
            (
                "bead_command_center",
                132_u16,
                44_u16,
                TerminalCapabilityClass::TrueColor,
            ),
            (
                "bead_command_center",
                96_u16,
                28_u16,
                TerminalCapabilityClass::TrueColor,
            ),
            (
                "incident_console",
                132_u16,
                44_u16,
                TerminalCapabilityClass::Ansi16,
            ),
            (
                "replay_inspector",
                120_u16,
                40_u16,
                TerminalCapabilityClass::Ansi256,
            ),
            (
                "replay_inspector",
                100_u16,
                30_u16,
                TerminalCapabilityClass::Ansi256,
            ),
        ];

        let mut observed = Vec::new();
        for (screen_id, width, height, capability) in scenarios {
            let correlation_id =
                format!("snapshot-{screen_id}-{width}x{height}-{capability:?}").to_lowercase();
            let transcript = simulate_visual_token_application_for_viewport(
                &contract,
                screen_id,
                &correlation_id,
                capability,
                width,
                height,
            )
            .expect("simulate");

            let compact_viewport =
                width < MIN_VISUAL_VIEWPORT_WIDTH || height < MIN_VISUAL_VIEWPORT_HEIGHT;
            if compact_viewport {
                assert!(
                    transcript.events.iter().any(|event| {
                        event.event_kind == "layout_degradation"
                            && event
                                .message
                                .contains(&format!("viewport={width}x{height}"))
                    }),
                    "expected viewport degradation event for {screen_id} {width}x{height}"
                );
            }

            observed.push((
                screen_id.to_string(),
                format!("{width}x{height}"),
                format!("{capability:?}"),
                transcript.selected_profile_id,
                transcript.fallback_applied,
                transcript.applied_layout_motif,
                transcript.missing_roles,
                transcript
                    .events
                    .iter()
                    .map(|event| event.event_kind.clone())
                    .collect::<Vec<_>>(),
            ));
        }

        assert_eq!(
            observed,
            vec![
                (
                    "bead_command_center".to_string(),
                    "132x44".to_string(),
                    "TrueColor".to_string(),
                    "showcase_truecolor".to_string(),
                    false,
                    "triple-pane command runway".to_string(),
                    Vec::<String>::new(),
                    vec!["theme_selected".to_string()],
                ),
                (
                    "bead_command_center".to_string(),
                    "96x28".to_string(),
                    "TrueColor".to_string(),
                    "showcase_truecolor".to_string(),
                    false,
                    "stacked split with compact status badges".to_string(),
                    Vec::<String>::new(),
                    vec![
                        "theme_selected".to_string(),
                        "layout_degradation".to_string(),
                    ],
                ),
                (
                    "incident_console".to_string(),
                    "132x44".to_string(),
                    "Ansi16".to_string(),
                    "showcase_ansi16".to_string(),
                    true,
                    "priority queue + inline evidence bullets".to_string(),
                    Vec::<String>::new(),
                    vec![
                        "theme_fallback".to_string(),
                        "theme_fallback".to_string(),
                        "theme_selected".to_string(),
                        "layout_degradation".to_string(),
                    ],
                ),
                (
                    "replay_inspector".to_string(),
                    "120x40".to_string(),
                    "Ansi256".to_string(),
                    "showcase_ansi256".to_string(),
                    false,
                    "timeline + diff pane with synchronized cursor".to_string(),
                    Vec::<String>::new(),
                    vec!["theme_selected".to_string()],
                ),
                (
                    "replay_inspector".to_string(),
                    "100x30".to_string(),
                    "Ansi256".to_string(),
                    "showcase_ansi256".to_string(),
                    false,
                    "single timeline table with deterministic markers".to_string(),
                    Vec::<String>::new(),
                    vec![
                        "theme_selected".to_string(),
                        "layout_degradation".to_string(),
                    ],
                ),
            ]
        );
    }

    #[test]
    fn simulate_visual_token_application_rejects_zero_viewport_dimensions() {
        let contract = visual_language_contract();
        let width_error = simulate_visual_token_application_for_viewport(
            &contract,
            "bead_command_center",
            "corr-visual-viewport-width-zero",
            TerminalCapabilityClass::TrueColor,
            0,
            44,
        )
        .expect_err("zero width must fail");
        assert_eq!(width_error, "viewport_width must be greater than zero");

        let height_error = simulate_visual_token_application_for_viewport(
            &contract,
            "bead_command_center",
            "corr-visual-viewport-height-zero",
            TerminalCapabilityClass::TrueColor,
            132,
            0,
        )
        .expect_err("zero height must fail");
        assert_eq!(height_error, "viewport_height must be greater than zero");
    }

    fn mixed_artifacts_fixture() -> Vec<RuntimeArtifact> {
        vec![
            RuntimeArtifact {
                artifact_id: "artifact-benchmark".to_string(),
                artifact_type: "benchmark".to_string(),
                source_path: "target/criterion/summary.txt".to_string(),
                replay_pointer: "rch exec -- cargo bench --bench doctor_ingestion".to_string(),
                content: "throughput_gib_s=12.4\nlatency_p95_ms=4.1\n".to_string(),
            },
            RuntimeArtifact {
                artifact_id: "artifact-log".to_string(),
                artifact_type: "structured_log".to_string(),
                source_path: "logs/run-42.json".to_string(),
                replay_pointer: "rch exec -- cargo test -p asupersync -- --nocapture".to_string(),
                content: r#"{
  "correlation_id": "corr-42",
  "scenario_id": "doctor-smoke",
  "seed": "42",
  "outcome_class": "cancelled",
  "summary": "operator cancelled after triage"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "artifact-trace".to_string(),
                artifact_type: "trace".to_string(),
                source_path: "trace/run-42.trace.json".to_string(),
                replay_pointer: "asupersync trace verify trace/run-42.trace.json".to_string(),
                content: r#"{
  "trace_id": "trace-42",
  "scenario_id": "doctor-smoke",
  "seed": 42,
  "outcome_class": "success",
  "message": "trace verification complete"
}"#
                .to_string(),
            },
            RuntimeArtifact {
                artifact_id: "artifact-ubs".to_string(),
                artifact_type: "ubs_findings".to_string(),
                source_path: "ubs-output.txt".to_string(),
                replay_pointer: "ubs src/cli/doctor/mod.rs".to_string(),
                content: "src/cli/doctor/mod.rs:10:5 issue A\nsrc/cli/doctor/mod.rs:20:7 issue B\n"
                    .to_string(),
            },
        ]
    }

    #[test]
    fn evidence_ingestion_normalizes_mixed_bundle_and_validates() {
        let report = ingest_runtime_artifacts("run-42", &mixed_artifacts_fixture());
        validate_evidence_ingestion_report(&report).expect("report should validate");
        assert_eq!(report.schema_version, EVIDENCE_SCHEMA_VERSION);
        assert_eq!(report.rejected.len(), 0);
        assert_eq!(report.records.len(), 6);

        let cancelled = report
            .records
            .iter()
            .find(|record| record.artifact_id == "artifact-log")
            .expect("cancelled record");
        assert_eq!(cancelled.outcome_class, "cancelled");
        assert_eq!(cancelled.correlation_id, "corr-42");
    }

    #[test]
    fn evidence_ingestion_rejects_malformed_json_and_tracks_reason() {
        let artifacts = vec![RuntimeArtifact {
            artifact_id: "bad-log".to_string(),
            artifact_type: "structured_log".to_string(),
            source_path: "logs/bad.json".to_string(),
            replay_pointer: "replay bad".to_string(),
            content: "{not json}".to_string(),
        }];

        let report = ingest_runtime_artifacts("run-bad", &artifacts);
        assert_eq!(report.records.len(), 0);
        assert_eq!(report.rejected.len(), 1);
        assert!(
            report.rejected[0].reason.contains("invalid JSON payload"),
            "{}",
            report.rejected[0].reason
        );
        let has_rejection_event = report.events.iter().any(|event| {
            event.stage == "reject_artifact"
                && event.artifact_id.as_deref() == Some("bad-log")
                && event.replay_pointer.as_deref() == Some("replay bad")
        });
        assert!(has_rejection_event, "expected reject_artifact event");
    }

    #[test]
    fn evidence_ingestion_deduplicates_records_deterministically() {
        let duplicate_trace = RuntimeArtifact {
            artifact_id: "trace-dup-a".to_string(),
            artifact_type: "trace".to_string(),
            source_path: "trace/a.json".to_string(),
            replay_pointer: "trace replay a".to_string(),
            content: r#"{"correlation_id":"corr-dup","scenario_id":"s","seed":"1","outcome_class":"success","summary":"same"}"#.to_string(),
        };
        let duplicate_trace_b = RuntimeArtifact {
            artifact_id: "trace-dup-b".to_string(),
            artifact_type: "trace".to_string(),
            source_path: "trace/b.json".to_string(),
            replay_pointer: "trace replay b".to_string(),
            content: duplicate_trace.content.clone(),
        };

        let report = ingest_runtime_artifacts("run-dedupe", &[duplicate_trace, duplicate_trace_b]);
        validate_evidence_ingestion_report(&report).expect("report should validate");
        assert_eq!(report.records.len(), 1);
        let dedupe_events = report
            .events
            .iter()
            .filter(|event| event.stage == "dedupe_record")
            .count();
        assert_eq!(dedupe_events, 1);
    }

    #[test]
    fn evidence_ingestion_e2e_replay_is_stable_across_repeated_runs() {
        let first = ingest_runtime_artifacts("run-e2e", &mixed_artifacts_fixture());
        let second = ingest_runtime_artifacts("run-e2e", &mixed_artifacts_fixture());
        assert_eq!(first, second);
        validate_evidence_ingestion_report(&first).expect("first report valid");
        validate_evidence_ingestion_report(&second).expect("second report valid");
    }

    #[test]
    fn structured_logging_contract_validates() {
        let contract = structured_logging_contract();
        validate_structured_logging_contract(&contract).expect("valid logging contract");
    }

    #[test]
    fn structured_logging_contract_round_trip_json() {
        let contract = structured_logging_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: StructuredLoggingContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_structured_logging_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn structured_logging_contract_rejects_unsorted_event_taxonomy() {
        let mut contract = structured_logging_contract();
        contract.event_taxonomy = vec![
            "verification_summary".to_string(),
            "command_start".to_string(),
        ];
        let err = validate_structured_logging_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("event_taxonomy must be lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn emit_structured_log_event_enforces_required_fields() {
        let contract = structured_logging_contract();
        let mut fields = BTreeMap::new();
        fields.insert(
            "artifact_pointer".to_string(),
            "artifacts/run-1/execution/start.json".to_string(),
        );
        fields.insert(
            "command_provenance".to_string(),
            "rch exec -- cargo test".to_string(),
        );
        fields.insert("flow_id".to_string(), "execution".to_string());
        fields.insert("outcome_class".to_string(), "success".to_string());
        fields.insert("run_id".to_string(), "run-1".to_string());
        fields.insert(
            "scenario_id".to_string(),
            "doctor-execution-smoke".to_string(),
        );

        let err = emit_structured_log_event(&contract, "execution", "command_start", &fields)
            .expect_err("missing trace_id must fail");
        assert!(err.contains("missing required field trace_id"), "{err}");
    }

    #[test]
    fn emit_structured_log_event_enforces_format_rules() {
        let contract = structured_logging_contract();
        let mut fields = BTreeMap::new();
        fields.insert(
            "artifact_pointer".to_string(),
            "artifacts/run-1/execution/start.json".to_string(),
        );
        fields.insert(
            "command_provenance".to_string(),
            "rch exec -- cargo test".to_string(),
        );
        fields.insert("flow_id".to_string(), "execution".to_string());
        fields.insert("outcome_class".to_string(), "success".to_string());
        fields.insert("run_id".to_string(), "run-1".to_string());
        fields.insert("scenario_id".to_string(), "Doctor Scenario".to_string());
        fields.insert("trace_id".to_string(), "trace-1".to_string());

        let err = emit_structured_log_event(&contract, "execution", "command_start", &fields)
            .expect_err("invalid scenario_id must fail");
        assert!(
            err.contains("invalid field format for scenario_id"),
            "{err}"
        );
    }

    #[test]
    fn structured_logging_smoke_run_is_deterministic_and_validates() {
        let contract = structured_logging_contract();
        let first = run_structured_logging_smoke(&contract, "run-logging-smoke").expect("smoke");
        let second = run_structured_logging_smoke(&contract, "run-logging-smoke").expect("smoke");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&contract, &first).expect("stream valid");

        let mut observed_flows = BTreeSet::new();
        for event in &first {
            observed_flows.insert(event.flow_id.clone());
        }
        assert_eq!(
            observed_flows.into_iter().collect::<Vec<_>>(),
            vec![
                "execution".to_string(),
                "integration".to_string(),
                "remediation".to_string(),
                "replay".to_string(),
            ]
        );
    }

    #[test]
    fn structured_logging_event_stream_rejects_out_of_order_events() {
        let contract = structured_logging_contract();
        let mut events = run_structured_logging_smoke(&contract, "run-ordering").expect("smoke");
        events.reverse();

        let err = validate_structured_logging_event_stream(&contract, &events)
            .expect_err("reversed events must fail ordering");
        assert!(
            err.contains("events must be lexically ordered by flow_id/event_kind/trace_id"),
            "{err}"
        );
    }

    #[test]
    fn remediation_recipe_contract_validates() {
        let contract = remediation_recipe_contract();
        validate_remediation_recipe_contract(&contract).expect("valid remediation recipe contract");
    }

    #[test]
    fn remediation_recipe_contract_round_trip_json() {
        let contract = remediation_recipe_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: RemediationRecipeContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_remediation_recipe_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn parse_remediation_recipe_rejects_unknown_fix_intent() {
        let contract = remediation_recipe_contract();
        let mut bad = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();
        bad.fix_intent = "rewrite_runtime_in_one_shot".to_string();
        let payload = serde_json::to_string(&bad).expect("serialize");

        let err = parse_remediation_recipe(&contract, &payload).expect_err("must fail");
        assert!(err.contains("unsupported fix_intent"), "{err}");
    }

    #[test]
    fn remediation_confidence_score_is_deterministic() {
        let contract = remediation_recipe_contract();
        let fixture = remediation_recipe_fixtures()
            .first()
            .expect("fixture")
            .recipe
            .clone();

        let first = compute_remediation_confidence_score(&contract, &fixture).expect("score");
        let second = compute_remediation_confidence_score(&contract, &fixture).expect("score");
        assert_eq!(first, second);
        assert_eq!(first.confidence_score, 80);
        assert_eq!(first.risk_band, "guarded_auto_apply".to_string());
    }

    #[test]
    fn remediation_recipe_smoke_is_deterministic_and_logs_decision_context() {
        let recipe_contract = remediation_recipe_contract();
        let logging_contract = structured_logging_contract();

        let first =
            run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
        let second =
            run_remediation_recipe_smoke(&recipe_contract, &logging_contract).expect("smoke");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&logging_contract, &first)
            .expect("event stream valid");

        let has_rejection = first.iter().any(|event| {
            event
                .fields
                .get("rejection_rationale")
                .is_some_and(|value| !value.trim().is_empty())
        });
        assert!(
            has_rejection,
            "smoke stream should include rejection rationale"
        );
    }

    #[test]
    fn execution_adapter_contract_validates() {
        let contract = execution_adapter_contract();
        validate_execution_adapter_contract(&contract).expect("valid execution adapter contract");
    }

    #[test]
    fn execution_adapter_contract_is_deterministic() {
        let first = execution_adapter_contract();
        let second = execution_adapter_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn execution_adapter_contract_round_trip_json() {
        let contract = execution_adapter_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: ExecutionAdapterContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_execution_adapter_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn execution_adapter_contract_rejects_unsorted_command_classes() {
        let mut contract = execution_adapter_contract();
        contract.command_classes.swap(0, 1);
        let err = validate_execution_adapter_contract(&contract).expect_err("must fail");
        assert!(
            err.contains("command_classes.class_id must be lexically sorted"),
            "{err}"
        );
    }

    #[test]
    fn plan_execution_command_wraps_rch_invocation() {
        let contract = execution_adapter_contract();
        let request = ExecutionAdapterRequest {
            command_id: "cmd-1".to_string(),
            command_class: "cargo_test".to_string(),
            correlation_id: "corr-1".to_string(),
            raw_command: "  cargo   test   -p   asupersync ".to_string(),
            prefer_remote: true,
        };
        let plan = plan_execution_command(&contract, &request, true).expect("plan should build");
        assert_eq!(plan.route, "remote_rch");
        assert_eq!(plan.normalized_command, "cargo test -p asupersync");
        assert_eq!(plan.routed_command, "rch exec -- cargo test -p asupersync");
        assert_eq!(plan.initial_state, "planned");
    }

    #[test]
    fn plan_execution_command_falls_back_when_rch_unavailable() {
        let contract = execution_adapter_contract();
        let request = ExecutionAdapterRequest {
            command_id: "cmd-2".to_string(),
            command_class: "cargo_check".to_string(),
            correlation_id: "corr-2".to_string(),
            raw_command: "cargo check --all-targets".to_string(),
            prefer_remote: true,
        };
        let plan = plan_execution_command(&contract, &request, false).expect("plan should build");
        assert_eq!(plan.route, "local_direct");
        assert_eq!(plan.routed_command, "cargo check --all-targets");
    }

    #[test]
    fn advance_execution_state_supports_cancel_path() {
        let contract = execution_adapter_contract();
        let queued = advance_execution_state(&contract, "planned", "enqueue").expect("enqueue");
        let running = advance_execution_state(&contract, &queued, "start").expect("start");
        let cancel_requested =
            advance_execution_state(&contract, &running, "cancel").expect("cancel");
        let cancelled = advance_execution_state(&contract, &cancel_requested, "cancel_completed")
            .expect("cancel complete");
        assert_eq!(cancelled, "cancelled");
    }

    #[test]
    fn advance_execution_state_rejects_invalid_transition() {
        let contract = execution_adapter_contract();
        let err = advance_execution_state(&contract, "planned", "cancel").expect_err("must fail");
        assert!(err.contains("invalid execution state transition"), "{err}");
    }

    #[test]
    fn scenario_composer_contract_validates() {
        let contract = scenario_composer_contract();
        validate_scenario_composer_contract(&contract).expect("valid scenario composer contract");
    }

    #[test]
    fn scenario_composer_contract_is_deterministic() {
        let first = scenario_composer_contract();
        let second = scenario_composer_contract();
        assert_eq!(first, second);
    }

    #[test]
    fn scenario_composer_contract_round_trip_json() {
        let contract = scenario_composer_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: ScenarioComposerContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_scenario_composer_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn scenario_composer_contract_rejects_unknown_command_class_reference() {
        let mut contract = scenario_composer_contract();
        contract.scenario_templates[0]
            .required_command_classes
            .push("unknown_command_class".to_string());
        contract.scenario_templates[0]
            .required_command_classes
            .sort();
        let err = validate_scenario_composer_contract(&contract).expect_err("must fail");
        assert!(err.contains("references unknown command class"), "{err}");
    }

    #[test]
    fn compose_scenario_run_uses_defaults() {
        let contract = scenario_composer_contract();
        let request = ScenarioRunRequest {
            run_id: "run-happy".to_string(),
            template_id: "scenario_happy_path_smoke".to_string(),
            correlation_id: "corr-happy".to_string(),
            seed: String::new(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let entry = compose_scenario_run(&contract, &request).expect("compose should succeed");
        assert_eq!(entry.queue_id, "queue-run-happy");
        assert_eq!(entry.priority, 120);
        assert_eq!(entry.state, "queued");
    }

    #[test]
    fn orchestration_state_machine_requires_seed_for_replay_template() {
        let contract = scenario_composer_contract();
        let request = ScenarioRunRequest {
            run_id: "run-no-seed".to_string(),
            template_id: "scenario_cancel_recovery".to_string(),
            correlation_id: "corr-no-seed".to_string(),
            seed: String::new(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let err = compose_scenario_run(&contract, &request).expect_err("must fail");
        assert!(
            err.contains("seed must be non-empty for templates requiring replay seed"),
            "{err}"
        );
    }

    #[test]
    fn orchestration_state_machine_trims_seed_and_run_id_for_lineage() {
        let contract = scenario_composer_contract();
        let request = ScenarioRunRequest {
            run_id: " run-trim ".to_string(),
            template_id: "scenario_cancel_recovery".to_string(),
            correlation_id: "corr-trim".to_string(),
            seed: " seed-77 ".to_string(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let entry = compose_scenario_run(&contract, &request).expect("compose should succeed");
        assert_eq!(entry.queue_id, "queue-run-trim");
        assert_eq!(entry.run_id, "run-trim");
        assert_eq!(entry.seed, "seed-77");
    }

    #[test]
    fn build_scenario_run_queue_orders_by_priority_then_run_id() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-b".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-b".to_string(),
                seed: String::new(),
                priority_override: Some(120),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-a".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-a".to_string(),
                seed: String::new(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-c".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-c".to_string(),
                seed: String::new(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let order = queue
            .iter()
            .map(|entry| entry.run_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                "run-a".to_string(),
                "run-c".to_string(),
                "run-b".to_string()
            ]
        );
    }

    #[test]
    fn build_scenario_run_queue_rejects_queue_overflow() {
        let mut contract = scenario_composer_contract();
        contract.queue_policy.max_queue_depth = 1;
        contract.queue_policy.max_concurrent_runs = 1;

        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-one".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-one".to_string(),
                seed: String::new(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-two".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-two".to_string(),
                seed: String::new(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let err = build_scenario_run_queue(&contract, &requests).expect_err("must fail");
        assert!(err.contains("queue_full"), "{err}");
    }

    #[test]
    fn dispatch_scenario_run_queue_respects_max_concurrency() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-1".to_string(),
                template_id: "scenario_regression_bundle".to_string(),
                correlation_id: "corr-1".to_string(),
                seed: "seed-1".to_string(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-2".to_string(),
                template_id: "scenario_cancel_recovery".to_string(),
                correlation_id: "corr-2".to_string(),
                seed: "seed-2".to_string(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-3".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-3".to_string(),
                seed: String::new(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let dispatched = dispatch_scenario_run_queue(&contract, &queue).expect("dispatch works");
        let running = dispatched
            .iter()
            .filter(|entry| entry.state == "running")
            .count();
        assert_eq!(running, 2);
    }

    #[test]
    fn orchestration_state_machine_dispatch_is_deterministic_and_preserves_entries() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-c".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-c".to_string(),
                seed: String::new(),
                priority_override: Some(180),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-a".to_string(),
                template_id: "scenario_cancel_recovery".to_string(),
                correlation_id: "corr-a".to_string(),
                seed: "seed-a".to_string(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-d".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-d".to_string(),
                seed: String::new(),
                priority_override: Some(120),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-b".to_string(),
                template_id: "scenario_regression_bundle".to_string(),
                correlation_id: "corr-b".to_string(),
                seed: "seed-b".to_string(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let first = dispatch_scenario_run_queue(&contract, &queue).expect("first dispatch");
        let second = dispatch_scenario_run_queue(&contract, &queue).expect("second dispatch");

        assert_eq!(first, second, "dispatch order must be deterministic");
        assert_eq!(
            first.len(),
            requests.len(),
            "dispatch must preserve entries"
        );

        let ordered = first
            .iter()
            .map(|entry| entry.run_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ordered, vec!["run-a", "run-b", "run-c", "run-d"]);
        assert_eq!(
            first
                .iter()
                .filter(|entry| entry.state == "running")
                .count(),
            usize::from(contract.queue_policy.max_concurrent_runs)
        );
        assert!(
            first
                .iter()
                .all(|entry| entry.state == "running" || entry.state == "queued")
        );
    }

    #[test]
    fn orchestration_state_machine_transition_matrix_matches_contract() {
        let contract = execution_adapter_contract();
        let states = [
            "planned",
            "queued",
            "running",
            "cancel_requested",
            "succeeded",
            "failed",
            "cancelled",
        ];
        let triggers = [
            "enqueue",
            "start",
            "cancel",
            "process_exit_zero",
            "process_exit_nonzero",
            "cancel_completed",
            "cancel_timeout",
        ];

        let allowed = contract
            .state_transitions
            .iter()
            .map(|transition| {
                (
                    (transition.from_state.as_str(), transition.trigger.as_str()),
                    transition.to_state.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        for state in states {
            for trigger in triggers {
                let next = advance_execution_state(&contract, state, trigger);
                if let Some(expected) = allowed.get(&(state, trigger)) {
                    assert_eq!(next.expect("valid transition"), *expected);
                } else {
                    let err = next.expect_err("transition should be rejected");
                    assert!(err.contains("invalid execution state transition"), "{err}");
                }
            }
        }
    }

    #[test]
    fn e2e_harness_core_contract_validates() {
        let contract = e2e_harness_core_contract();
        validate_e2e_harness_core_contract(&contract).expect("valid harness contract");
    }

    #[test]
    fn e2e_harness_core_contract_round_trip_json() {
        let contract = e2e_harness_core_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: E2eHarnessCoreContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_e2e_harness_core_contract(&parsed).expect("parsed harness contract valid");
    }

    #[test]
    fn parse_e2e_harness_config_rejects_missing_field() {
        let contract = e2e_harness_core_contract();
        let mut raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        raw.remove("seed");
        let err = parse_e2e_harness_config(&contract, &raw).expect_err("must fail");
        assert!(err.contains("missing required config field seed"), "{err}");
    }

    #[test]
    fn parse_e2e_harness_config_parses_valid_input() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let parsed = parse_e2e_harness_config(&contract, &raw).expect("parse should succeed");
        assert_eq!(parsed.timeout_secs, 120);
        assert_eq!(parsed.expected_outcome, "success");
    }

    #[test]
    fn propagate_harness_seed_is_deterministic() {
        let first = propagate_harness_seed("seed-42", "stage-bootstrap").expect("first seed");
        let second = propagate_harness_seed("seed-42", "stage-bootstrap").expect("second seed");
        assert_eq!(first, second);
        assert_eq!(first, "seed-42-stage-bootstrap");
    }

    #[test]
    fn build_e2e_harness_transcript_is_deterministic() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec![
            "stage-bootstrap".to_string(),
            "stage-run".to_string(),
            "stage-verify".to_string(),
        ];
        let first =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("first transcript");
        let second =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("second transcript");
        assert_eq!(first, second);
        assert_eq!(first.events[0].state, "started");
        assert_eq!(first.events[2].state, "completed");
    }

    #[test]
    fn build_e2e_harness_transcript_rejects_invalid_stage() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec!["stage bootstrap".to_string()];
        let err = build_e2e_harness_transcript(&contract, &config, &stages).expect_err("must fail");
        assert!(err.contains("must be slug-like"), "{err}");
    }

    #[test]
    fn orchestration_state_machine_cancelled_transcript_terminal_state() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "cancelled".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-cancel".to_string()),
            ("scenario_id".to_string(), "scenario-cancel".to_string()),
            ("script_id".to_string(), "script-cancel".to_string()),
            ("seed".to_string(), "seed-77".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec![
            "stage-bootstrap".to_string(),
            "stage-run".to_string(),
            "stage-cleanup".to_string(),
        ];
        let transcript =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("transcript");

        assert_eq!(transcript.events[0].state, "started");
        assert_eq!(transcript.events[1].state, "running");
        assert_eq!(transcript.events[2].state, "cancelled");
        assert_eq!(transcript.events[2].outcome_class, "cancelled");

        let seeds = transcript
            .events
            .iter()
            .map(|event| event.propagated_seed.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(seeds.len(), stages.len(), "stage seeds must remain unique");
    }

    #[test]
    fn build_e2e_harness_artifact_index_is_lexical_and_stable() {
        let contract = e2e_harness_core_contract();
        let raw = BTreeMap::from([
            ("correlation_id".to_string(), "corr-e2e".to_string()),
            ("expected_outcome".to_string(), "success".to_string()),
            ("requested_by".to_string(), "doctor_cli".to_string()),
            ("run_id".to_string(), "run-e2e".to_string()),
            ("scenario_id".to_string(), "scenario-e2e".to_string()),
            ("script_id".to_string(), "script-smoke".to_string()),
            ("seed".to_string(), "seed-42".to_string()),
            ("timeout_secs".to_string(), "120".to_string()),
        ]);
        let config = parse_e2e_harness_config(&contract, &raw).expect("parse");
        let stages = vec!["stage-bootstrap".to_string(), "stage-verify".to_string()];
        let transcript =
            build_e2e_harness_transcript(&contract, &config, &stages).expect("transcript");
        let index = build_e2e_harness_artifact_index(&contract, &transcript).expect("index");
        let ids = index
            .iter()
            .map(|entry| entry.artifact_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "scenario-e2e-structured-log".to_string(),
                "scenario-e2e-summary".to_string(),
                "scenario-e2e-transcript".to_string(),
            ]
        );
    }

    #[test]
    fn doctor_scenario_coverage_packs_contract_validates() {
        let contract = doctor_scenario_coverage_packs_contract();
        validate_doctor_scenario_coverage_packs_contract(&contract).expect("valid contract");
    }

    #[test]
    fn doctor_scenario_coverage_packs_contract_round_trip_json() {
        let contract = doctor_scenario_coverage_packs_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: DoctorScenarioCoveragePacksContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_doctor_scenario_coverage_packs_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn select_doctor_scenario_coverage_packs_filters_variants() {
        let contract = doctor_scenario_coverage_packs_contract();
        let cancellation =
            select_doctor_scenario_coverage_packs(&contract, "cancellation").expect("select");
        assert_eq!(cancellation.len(), 1);
        assert_eq!(cancellation[0].workflow_variant, "cancellation");

        let all = select_doctor_scenario_coverage_packs(&contract, "all").expect("select");
        let variants = all
            .iter()
            .map(|pack| pack.workflow_variant.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            variants,
            BTreeSet::from([
                "cancellation".to_string(),
                "degraded_dependency".to_string(),
                "recovery".to_string(),
                "retry".to_string(),
            ])
        );
    }

    #[test]
    fn doctor_scenario_coverage_pack_smoke_report_is_deterministic() {
        let contract = doctor_scenario_coverage_packs_contract();
        let first = build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-4242")
            .expect("first");
        let second =
            build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-4242")
                .expect("second");
        assert_eq!(first, second);
        assert_eq!(first.runs.len(), 4);
        assert_eq!(
            first
                .runs
                .iter()
                .map(|run| run.workflow_variant.clone())
                .collect::<Vec<_>>(),
            vec![
                "cancellation".to_string(),
                "degraded_dependency".to_string(),
                "recovery".to_string(),
                "retry".to_string(),
            ]
        );
    }

    #[test]
    fn doctor_scenario_coverage_pack_smoke_report_aligns_terminal_outcomes() {
        let contract = doctor_scenario_coverage_packs_contract();
        let report = build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-900")
            .expect("report");
        for run in &report.runs {
            let expected_terminal =
                expected_terminal_state_for_outcome(&run.expected_outcome).expect("mapping");
            assert_eq!(
                run.terminal_state, expected_terminal,
                "pack {}",
                run.pack_id
            );
            assert_eq!(run.status, "passed");
            assert_eq!(
                run.artifact_index
                    .iter()
                    .map(|entry| entry.artifact_class.clone())
                    .collect::<Vec<_>>(),
                vec![
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ]
            );
            assert!(
                run.structured_log_summary
                    .snapshot_path
                    .starts_with("artifacts/"),
                "snapshot path should remain canonical"
            );
            assert!(
                run.structured_log_summary
                    .metrics_path
                    .starts_with("artifacts/"),
                "metrics path should remain canonical"
            );
            assert!(
                run.structured_log_summary
                    .replay_metadata_path
                    .starts_with("artifacts/"),
                "replay metadata path should remain canonical"
            );
        }
    }

    #[test]
    fn doctor_scenario_coverage_pack_visual_harness_manifest_is_complete() {
        let contract = doctor_scenario_coverage_packs_contract();
        let report =
            build_doctor_scenario_coverage_pack_smoke_report(&contract, "all", "seed-visual")
                .expect("report");
        for run in &report.runs {
            assert_eq!(
                run.artifact_manifest.schema_version,
                DOCTOR_VISUAL_HARNESS_MANIFEST_VERSION
            );
            assert_eq!(run.artifact_manifest.run_id, run.transcript.run_id);
            assert_eq!(
                run.artifact_manifest.scenario_id,
                run.transcript.scenario_id
            );
            assert_eq!(
                run.visual_snapshot.viewport_width,
                DEFAULT_VISUAL_VIEWPORT_WIDTH
            );
            assert_eq!(
                run.visual_snapshot.viewport_height,
                DEFAULT_VISUAL_VIEWPORT_HEIGHT
            );
            assert!(
                run.visual_snapshot.stage_digest.starts_with("len:"),
                "stage digest should use canonical content_digest formatting"
            );

            let classes = run
                .artifact_manifest
                .records
                .iter()
                .map(|record| record.artifact_class.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                classes,
                BTreeSet::from([
                    "metrics".to_string(),
                    "replay_metadata".to_string(),
                    "snapshot".to_string(),
                    "structured_log".to_string(),
                    "summary".to_string(),
                    "transcript".to_string(),
                ])
            );

            for record in &run.artifact_manifest.records {
                assert!(
                    record.artifact_path.starts_with("artifacts/"),
                    "artifact paths must stay under artifacts/: {}",
                    record.artifact_id
                );
                assert!(
                    matches!(record.retention_class.as_str(), "hot" | "warm"),
                    "retention class must stay canonical"
                );
                let mut linked = record.linked_artifacts.clone();
                let mut sorted = linked.clone();
                sorted.sort();
                sorted.dedup();
                assert_eq!(linked, sorted, "linked artifacts must be lexical+unique");
                linked.clear();
            }
        }
    }

    #[test]
    fn evidence_timeline_contract_validates() {
        let contract = evidence_timeline_contract();
        validate_evidence_timeline_contract(&contract).expect("valid contract");
    }

    #[test]
    fn evidence_timeline_contract_round_trip_json() {
        let contract = evidence_timeline_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: EvidenceTimelineContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_evidence_timeline_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn build_evidence_timeline_snapshot_orders_groups_and_filters() {
        let contract = evidence_timeline_contract();
        let timeline_json = r#"[
  {
    "id":"timeline-010",
    "occurred_at":"2026-03-01T10:05:00Z",
    "finding_id":"finding-b",
    "title":"B",
    "severity":"critical",
    "status":"open",
    "outcome_class":"failed",
    "evidence_refs":["evidence-010"],
    "command_refs":["cmd-010"],
    "causal_refs":["timeline-005"]
  },
  {
    "id":"timeline-005",
    "occurred_at":"2026-03-01T10:00:00Z",
    "finding_id":"finding-a",
    "title":"A",
    "severity":"high",
    "status":"resolved",
    "outcome_class":"success",
    "evidence_refs":["evidence-005"],
    "command_refs":["cmd-005"],
    "causal_refs":[]
  },
  {
    "id":"timeline-020",
    "occurred_at":"2026-03-01T10:10:00Z",
    "finding_id":"finding-c",
    "title":"C",
    "severity":"critical",
    "status":"in_progress",
    "outcome_class":"failed",
    "evidence_refs":["evidence-020"],
    "command_refs":["cmd-020"],
    "causal_refs":["timeline-010"]
  }
]"#;

        let all_snapshot = build_evidence_timeline_snapshot(
            &contract,
            timeline_json,
            "chronological_asc",
            "all",
            "severity",
            "primary_panel",
            Some("timeline-010"),
        )
        .expect("snapshot");
        let all_ids = all_snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            all_ids,
            vec![
                "timeline-005".to_string(),
                "timeline-010".to_string(),
                "timeline-020".to_string(),
            ]
        );
        assert_eq!(
            all_snapshot
                .groups
                .iter()
                .map(|group| group.group_key.clone())
                .collect::<Vec<_>>(),
            vec!["critical".to_string(), "high".to_string()]
        );

        let critical_desc_snapshot = build_evidence_timeline_snapshot(
            &contract,
            timeline_json,
            "chronological_desc",
            "critical_only",
            "status",
            "primary_panel",
            Some("timeline-020"),
        )
        .expect("snapshot");
        let filtered_ids = critical_desc_snapshot
            .nodes
            .iter()
            .map(|node| node.node_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            filtered_ids,
            vec!["timeline-020".to_string(), "timeline-010".to_string()]
        );
        assert_eq!(
            critical_desc_snapshot
                .groups
                .iter()
                .map(|group| group.group_key.clone())
                .collect::<Vec<_>>(),
            vec!["in_progress".to_string(), "open".to_string()]
        );
    }

    #[test]
    fn build_evidence_timeline_snapshot_emits_missing_link_and_causal_events() {
        let contract = evidence_timeline_contract();
        let timeline_json = r#"{
  "result": [
    {
      "id":"timeline-a",
      "occurred_at":"2026-03-01T12:00:00Z",
      "finding_id":"finding-a",
      "title":"A",
      "severity":"high",
      "status":"open",
      "outcome_class":"failed",
      "evidence_refs":["evidence-a"],
      "command_refs":["cmd-a"],
      "causal_refs":[]
    },
    {
      "id":"timeline-b",
      "occurred_at":"2026-03-01T12:01:00Z",
      "finding_id":"finding-b",
      "title":"B",
      "severity":"critical",
      "status":"in_progress",
      "outcome_class":"failed",
      "evidence_refs":[],
      "command_refs":["cmd-b"],
      "causal_refs":["timeline-a","timeline-missing"]
    }
  ]
}"#;

        let snapshot = build_evidence_timeline_snapshot(
            &contract,
            timeline_json,
            "chronological_asc",
            "all",
            "outcome",
            "evidence_panel",
            Some("timeline-b"),
        )
        .expect("snapshot");

        assert_eq!(snapshot.evidence_panel_node.as_deref(), Some("timeline-b"));
        assert!(
            snapshot.events.iter().any(|event| {
                event.event_kind == "causal_expansion_decision"
                    && event.node_id.as_deref() == Some("timeline-b")
            }),
            "missing causal_expansion_decision event"
        );
        assert!(
            snapshot.events.iter().any(|event| {
                event.event_kind == "missing_link_diagnostic"
                    && event.node_id.as_deref() == Some("timeline-b")
            }),
            "missing missing_link_diagnostic event"
        );
    }

    #[test]
    fn evidence_timeline_keyboard_flow_smoke_is_deterministic() {
        let contract = evidence_timeline_contract();
        let first = run_evidence_timeline_keyboard_flow_smoke(&contract).expect("first smoke");
        let second = run_evidence_timeline_keyboard_flow_smoke(&contract).expect("second smoke");
        assert_eq!(first, second);
        assert_eq!(first.steps.len(), 5);
        assert_eq!(first.steps[1].focused_panel, "primary_panel");
        assert_eq!(
            first.steps[2].selected_node.as_deref(),
            Some("timeline-002")
        );
        assert_eq!(first.steps[3].focused_panel, "evidence_panel");
        assert_eq!(
            first.steps[3].evidence_panel_node.as_deref(),
            Some("timeline-002")
        );
        assert_eq!(first.steps[4].focused_panel, "primary_panel");
        assert!(first.steps[4].evidence_panel_node.is_none());
    }

    #[test]
    fn beads_command_center_contract_validates() {
        let contract = beads_command_center_contract();
        validate_beads_command_center_contract(&contract).expect("valid contract");
    }

    #[test]
    fn beads_command_center_contract_round_trip_json() {
        let contract = beads_command_center_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: BeadsCommandCenterContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_beads_command_center_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn parse_br_ready_items_sorts_by_priority_then_id() {
        let contract = beads_command_center_contract();
        let raw = r#"[
  {"id":"asupersync-2b4jj.5.2","title":"Mail pane","status":"open","priority":2},
  {"id":"asupersync-2b4jj.5.1","title":"Command center","status":"in_progress","priority":2,"assignee":"VioletStone"},
  {"id":"asupersync-2b4jj.2.1","title":"Scanner","status":"open","priority":1}
]"#;
        let parsed = parse_br_ready_items(&contract, raw).expect("parse");
        let ids = parsed
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "asupersync-2b4jj.2.1".to_string(),
                "asupersync-2b4jj.5.1".to_string(),
                "asupersync-2b4jj.5.2".to_string(),
            ]
        );
        assert_eq!(parsed[1].assignee.as_deref(), Some("VioletStone"));
    }

    #[test]
    fn parse_br_blocked_items_handles_string_and_object_blockers() {
        let contract = beads_command_center_contract();
        let raw = r#"[
  {
    "id":"asupersync-2b4jj.5.2",
    "title":"Mail pane",
    "status":"open",
    "priority":2,
    "blocked_by":["asupersync-2b4jj.2.1", {"id":"asupersync-2b4jj.2.1"}, {"id":"asupersync-2b4jj.2.0"}]
  },
  {
    "id":"asupersync-2b4jj.5.3",
    "title":"Franken export",
    "status":"open",
    "priority":1,
    "blocked_by":["asupersync-2b4jj.5.2"]
  }
]"#;
        let parsed = parse_br_blocked_items(&contract, raw).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "asupersync-2b4jj.5.2");
        assert_eq!(
            parsed[0].blocked_by,
            vec![
                "asupersync-2b4jj.2.0".to_string(),
                "asupersync-2b4jj.2.1".to_string(),
            ]
        );
    }

    #[test]
    fn parse_bv_triage_recommendations_sorts_by_score_and_normalizes_reasons() {
        let contract = beads_command_center_contract();
        let raw = r#"{
  "triage": {
    "quick_ref": {
      "top_picks": [
        {
          "id":"asupersync-2b4jj.5.1",
          "title":"Command center",
          "score":0.31,
          "unblocks":3,
          "reasons":["high impact","available","available"]
        },
        {
          "id":"asupersync-2b4jj.5.2",
          "title":"Mail pane",
          "score":0.2,
          "unblocks":2,
          "reasons":["available"]
        }
      ]
    }
  }
}"#;
        let parsed = parse_bv_triage_recommendations(&contract, raw).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].id, "asupersync-2b4jj.5.1");
        assert_eq!(
            parsed[0].reasons,
            vec!["available".to_string(), "high impact".to_string()]
        );
    }

    #[test]
    fn build_beads_command_center_snapshot_filters_and_marks_stale() {
        let contract = beads_command_center_contract();
        let ready_json = r#"[
  {"id":"asupersync-2b4jj.5.1","title":"Command center","status":"open","priority":2},
  {"id":"asupersync-2b4jj.2.1","title":"Scanner","status":"in_progress","priority":1},
  {"id":"asupersync-2b4jj.5.2","title":"Mail pane","status":"open","priority":2}
]"#;
        let blocked_json = r#"[
  {
    "id":"asupersync-2b4jj.5.2",
    "title":"Mail pane",
    "status":"open",
    "priority":2,
    "blocked_by":[{"id":"asupersync-2b4jj.2.1"}]
  }
]"#;
        let triage_json = r#"{
  "triage": {
    "quick_ref": {
      "top_picks": [
        {"id":"asupersync-2b4jj.5.1","title":"Command center","score":0.3,"unblocks":3,"reasons":["available","high impact"]},
        {"id":"asupersync-2b4jj.5.2","title":"Mail pane","score":0.2,"unblocks":2,"reasons":["available"]}
      ]
    }
  }
}"#;

        let snapshot = build_beads_command_center_snapshot(
            &contract,
            ready_json,
            blocked_json,
            triage_json,
            "unblocked_only",
            301,
        )
        .expect("snapshot");
        let ready_ids = snapshot
            .ready_work
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ready_ids,
            vec![
                "asupersync-2b4jj.2.1".to_string(),
                "asupersync-2b4jj.5.1".to_string(),
            ]
        );
        assert!(snapshot.blocked_work.is_empty());
        assert!(snapshot.stale);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "stale_data_detected")
        );
    }

    #[test]
    fn build_beads_command_center_snapshot_tracks_parse_failures() {
        let contract = beads_command_center_contract();
        let ready_json = "{not-json}";
        let blocked_json = "[]";
        let triage_json = r#"{"triage":{"quick_ref":{"top_picks":[]}}}"#;
        let snapshot = build_beads_command_center_snapshot(
            &contract,
            ready_json,
            blocked_json,
            triage_json,
            "all",
            5,
        )
        .expect("snapshot");
        assert_eq!(snapshot.ready_work.len(), 0);
        assert_eq!(snapshot.parse_errors.len(), 1);
        assert!(
            snapshot.parse_errors[0].contains("parse_failure: ready JSON"),
            "{}",
            snapshot.parse_errors[0]
        );
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "parse_failure" && event.source == "ready")
        );
    }

    #[test]
    fn build_beads_command_center_snapshot_handles_empty_state() {
        let contract = beads_command_center_contract();
        let ready_json = "[]";
        let blocked_json = "[]";
        let triage_json = r#"{"triage":{"quick_ref":{"top_picks":[]}}}"#;
        let snapshot = build_beads_command_center_snapshot(
            &contract,
            ready_json,
            blocked_json,
            triage_json,
            "all",
            0,
        )
        .expect("snapshot");
        assert_eq!(snapshot.ready_work.len(), 0);
        assert_eq!(snapshot.blocked_work.len(), 0);
        assert_eq!(snapshot.triage.len(), 0);
        assert_eq!(snapshot.parse_errors.len(), 0);
        assert!(!snapshot.stale);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "snapshot_built")
        );
    }

    #[test]
    fn beads_command_center_smoke_is_deterministic() {
        let contract = beads_command_center_contract();
        let first = run_beads_command_center_smoke(&contract).expect("first smoke");
        let second = run_beads_command_center_smoke(&contract).expect("second smoke");
        assert_eq!(first, second);
        assert_eq!(first.ready_work.len(), 3);
        assert_eq!(first.blocked_work.len(), 1);
        assert_eq!(first.triage.len(), 2);
        assert!(!first.stale);
    }

    #[test]
    fn agent_mail_pane_contract_validates() {
        let contract = agent_mail_pane_contract();
        validate_agent_mail_pane_contract(&contract).expect("valid contract");
    }

    #[test]
    fn agent_mail_pane_contract_round_trip_json() {
        let contract = agent_mail_pane_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: AgentMailPaneContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_agent_mail_pane_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn parse_agent_mail_messages_maps_ack_required_variants() {
        let contract = agent_mail_pane_contract();
        let raw = r#"{
  "result": [
    {
      "id": 2449,
      "subject": "Re: coordination",
      "importance": "normal",
      "ack_required": true,
      "created_ts": "2026-02-27T19:14:05.885632+00:00",
      "thread_id": "coord-2026-02-27-blackelk",
      "from": "BlackElk"
    },
    {
      "id": 2506,
      "subject": "Start mail pane",
      "importance": "normal",
      "ack_required": 0,
      "created_ts": "2026-02-27T23:52:19.925466+00:00",
      "thread_id": "asupersync-2b4jj.5.2",
      "from": "VioletStone",
      "delivery_status": "sent"
    }
  ]
}"#;
        let parsed_inbox =
            parse_agent_mail_messages(&contract, raw, "inbox", "inbox").expect("parse");
        assert!(parsed_inbox[0].ack_required);
        assert_eq!(parsed_inbox[0].direction, "inbox");
        assert_eq!(parsed_inbox[0].delivery_status, "received");

        let parsed_outbox =
            parse_agent_mail_messages(&contract, raw, "outbox", "outbox").expect("parse");
        assert!(!parsed_outbox[1].ack_required);
        assert_eq!(parsed_outbox[1].direction, "outbox");
        assert_eq!(parsed_outbox[1].delivery_status, "sent");
    }

    #[test]
    fn parse_agent_mail_messages_rejects_invalid_direction() {
        let contract = agent_mail_pane_contract();
        let raw = r#"{"result":[]}"#;
        let err =
            parse_agent_mail_messages(&contract, raw, "inbox", "sideways").expect_err("must fail");
        assert!(err.contains("direction must be inbox or outbox"));
    }

    #[test]
    fn parse_agent_mail_contacts_sorts_and_handles_optional_fields() {
        let contract = agent_mail_pane_contract();
        let raw = r#"{
  "result": [
    {
      "to":"ZuluAgent",
      "status":"pending",
      "reason":"Need handshake",
      "updated_ts":"2026-02-27T20:00:00+00:00",
      "expires_ts":"2026-03-06T20:00:00+00:00"
    },
    {
      "to":"AlphaAgent",
      "status":"approved",
      "reason":"Already linked",
      "updated_ts":"2026-02-27T19:00:00+00:00",
      "expires_ts":""
    }
  ]
}"#;
        let contacts = parse_agent_mail_contacts(&contract, raw).expect("parse");
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].peer, "AlphaAgent");
        assert_eq!(contacts[0].expires_ts, None);
        assert_eq!(contacts[1].peer, "ZuluAgent");
        assert_eq!(
            contacts[1].expires_ts.as_deref(),
            Some("2026-03-06T20:00:00+00:00")
        );
    }

    #[test]
    fn build_agent_mail_pane_snapshot_applies_ack_and_thread_filter() {
        let contract = agent_mail_pane_contract();
        let inbox_json = r#"{
  "result": [
    {
      "id": 2449,
      "subject": "Re: coordination",
      "importance": "normal",
      "ack_required": true,
      "created_ts": "2026-02-27T19:14:05.885632+00:00",
      "thread_id": "coord-2026-02-27-blackelk",
      "from": "BlackElk"
    }
  ]
}"#;
        let outbox_json = r#"[
  {
    "id": 2507,
    "subject": "Re: coordination",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T23:52:39.925466+00:00",
    "thread_id": "coord-2026-02-27-blackelk",
    "from": "VioletStone",
    "delivery_status": "sent"
  }
]"#;
        let contacts_json = r#"{"result":[{"to":"BlackElk","status":"approved","reason":"coord","updated_ts":"2026-02-27T18:36:16.334889+00:00"}]}"#;

        let snapshot = build_agent_mail_pane_snapshot(
            &contract,
            inbox_json,
            outbox_json,
            contacts_json,
            Some("coord-2026-02-27-blackelk"),
            "thread_only",
            &[2449],
        )
        .expect("snapshot");
        assert_eq!(snapshot.pending_ack_count, 0);
        assert_eq!(snapshot.thread_messages.len(), 2);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "ack_transition" && event.message_id == Some(2449))
        );
    }

    #[test]
    fn build_agent_mail_pane_snapshot_unacked_only_adds_ack_replay_command() {
        let contract = agent_mail_pane_contract();
        let inbox_json = r#"{
  "result": [
    {
      "id": 3001,
      "subject": "Needs ack",
      "importance": "high",
      "ack_required": true,
      "created_ts": "2026-02-27T20:00:00+00:00",
      "from": "BlackElk"
    }
  ]
}"#;
        let outbox_json = "[]";
        let contacts_json = r#"{"result":[]}"#;

        let snapshot = build_agent_mail_pane_snapshot(
            &contract,
            inbox_json,
            outbox_json,
            contacts_json,
            None,
            "unacked_only",
            &[],
        )
        .expect("snapshot");
        assert_eq!(snapshot.pending_ack_count, 1);
        assert!(
            snapshot
                .replay_commands
                .iter()
                .any(|command| command == &contract.acknowledge_command)
        );
        assert!(
            !snapshot
                .replay_commands
                .iter()
                .any(|command| command == &contract.reply_command)
        );
    }

    #[test]
    fn build_agent_mail_pane_snapshot_tracks_parse_failures_and_delivery_failure() {
        let contract = agent_mail_pane_contract();
        let inbox_json = r#"{
  "result": [
    {
      "id": 3001,
      "subject": "Needs ack",
      "importance": "high",
      "ack_required": true,
      "created_ts": "2026-02-27T20:00:00+00:00",
      "thread_id": "thread-1",
      "from": "BlackElk"
    }
  ]
}"#;
        let outbox_json = r#"[
  {
    "id": 4001,
    "subject": "Reply attempt",
    "importance": "normal",
    "ack_required": 0,
    "created_ts": "2026-02-27T20:01:00+00:00",
    "thread_id": "thread-1",
    "from": "VioletStone",
    "delivery_status": "failed"
  }
]"#;
        let invalid_contacts_json = "{not-json}";

        let snapshot = build_agent_mail_pane_snapshot(
            &contract,
            inbox_json,
            outbox_json,
            invalid_contacts_json,
            Some("thread-1"),
            "all",
            &[],
        )
        .expect("snapshot");
        assert_eq!(snapshot.parse_errors.len(), 1);
        assert_eq!(snapshot.pending_ack_count, 1);
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "parse_failure" && event.source == "contacts")
        );
        assert!(
            snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "delivery_failure"
                    && event.message_id == Some(4001))
        );
    }

    #[test]
    fn agent_mail_pane_smoke_workflow_is_deterministic() {
        let contract = agent_mail_pane_contract();
        let first = run_agent_mail_pane_smoke(&contract).expect("first smoke");
        let second = run_agent_mail_pane_smoke(&contract).expect("second smoke");
        assert_eq!(first, second);
        assert_eq!(first.steps.len(), 3);
        assert_eq!(first.steps[0].step_id, "fetch");
        assert_eq!(first.steps[0].snapshot.pending_ack_count, 1);
        assert_eq!(first.steps[1].step_id, "ack");
        assert_eq!(first.steps[1].snapshot.pending_ack_count, 0);
        assert_eq!(first.steps[2].step_id, "reply");
        assert_eq!(first.steps[2].snapshot.thread_messages.len(), 2);
        assert!(
            first.steps[2]
                .snapshot
                .events
                .iter()
                .any(|event| event.event_kind == "thread_view_updated")
        );
    }

    #[test]
    fn core_diagnostics_report_contract_validates() {
        let contract = core_diagnostics_report_contract();
        validate_core_diagnostics_report_contract(&contract).expect("valid core report contract");
    }

    #[test]
    fn core_diagnostics_report_contract_round_trip_json() {
        let contract = core_diagnostics_report_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: CoreDiagnosticsReportContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_core_diagnostics_report_contract(&parsed).expect("parsed contract valid");
    }

    #[test]
    fn core_diagnostics_report_bundle_is_deterministic_and_valid() {
        let first = core_diagnostics_report_bundle();
        let second = core_diagnostics_report_bundle();
        assert_eq!(first, second);

        validate_core_diagnostics_report_contract(&first.contract).expect("contract valid");
        for fixture in &first.fixtures {
            validate_core_diagnostics_report(&fixture.report, &first.contract)
                .expect("fixture report valid");
        }
    }

    #[test]
    fn core_diagnostics_report_rejects_unsorted_findings() {
        let contract = core_diagnostics_report_contract();
        let mut fixture = core_diagnostics_report_fixtures()
            .into_iter()
            .find(|candidate| candidate.fixture_id == "baseline_failure_path")
            .expect("fixture exists");
        fixture.report.findings.swap(0, 1);
        let err = validate_core_diagnostics_report(&fixture.report, &contract)
            .expect_err("unsorted findings must fail");
        assert!(err.contains("findings.finding_id"), "{err}");
    }

    #[test]
    fn core_diagnostics_report_smoke_emits_valid_structured_events() {
        let bundle = core_diagnostics_report_bundle();
        let logging_contract = structured_logging_contract();
        let first =
            run_core_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke events");
        let second =
            run_core_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke events");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&logging_contract, &first)
            .expect("structured event stream valid");

        let mut scenario_ids = first
            .iter()
            .filter_map(|event| event.fields.get("scenario_id").cloned())
            .collect::<Vec<_>>();
        scenario_ids.sort();
        scenario_ids.dedup();
        assert_eq!(
            scenario_ids,
            vec![
                "doctor-core-report-failure".to_string(),
                "doctor-core-report-happy".to_string(),
                "doctor-core-report-partial".to_string(),
            ]
        );
    }

    #[test]
    fn advanced_diagnostics_report_extension_contract_validates() {
        let contract = advanced_diagnostics_report_extension_contract();
        validate_advanced_diagnostics_report_extension_contract(&contract)
            .expect("valid extension contract");
    }

    #[test]
    fn advanced_diagnostics_report_extension_contract_round_trip_json() {
        let contract = advanced_diagnostics_report_extension_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let parsed: AdvancedDiagnosticsReportExtensionContract =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, parsed);
        validate_advanced_diagnostics_report_extension_contract(&parsed)
            .expect("parsed extension contract valid");
    }

    #[test]
    fn advanced_diagnostics_bundle_is_deterministic_and_valid() {
        let first = advanced_diagnostics_report_bundle();
        let second = advanced_diagnostics_report_bundle();
        assert_eq!(first, second);

        for fixture in &first.fixtures {
            validate_advanced_diagnostics_report_extension(
                &fixture.extension,
                &fixture.core_report,
                &first.extension_contract,
                &first.core_contract,
            )
            .expect("fixture extension should validate");
        }
    }

    #[test]
    fn advanced_extension_contract_rejects_unknown_taxonomy_class() {
        let mut contract = advanced_diagnostics_report_extension_contract();
        contract
            .taxonomy_mapping
            .class_allowlist
            .push("unknown_taxonomy_class".to_string());
        contract.taxonomy_mapping.class_allowlist.sort();
        let err = validate_advanced_diagnostics_report_extension_contract(&contract)
            .expect_err("unknown taxonomy class must fail");
        assert!(err.contains("unknown_taxonomy_class"), "{err}");
    }

    #[test]
    fn advanced_extension_rejects_base_report_id_mismatch() {
        let bundle = advanced_diagnostics_report_bundle();
        let fixture = bundle.fixtures.first().expect("fixture exists");
        let mut extension = fixture.extension.clone();
        extension.base_report_id = "doctor-report-mismatch".to_string();

        let err = validate_advanced_diagnostics_report_extension(
            &extension,
            &fixture.core_report,
            &bundle.extension_contract,
            &bundle.core_contract,
        )
        .expect_err("mismatched base report id should fail");
        assert!(err.contains("base_report_id"), "{err}");
    }

    #[test]
    fn advanced_diagnostics_report_smoke_emits_valid_structured_events() {
        let bundle = advanced_diagnostics_report_bundle();
        let logging_contract = structured_logging_contract();
        let first =
            run_advanced_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke");
        let second =
            run_advanced_diagnostics_report_smoke(&bundle, &logging_contract).expect("smoke");
        assert_eq!(first, second);
        validate_structured_logging_event_stream(&logging_contract, &first)
            .expect("structured events valid");

        let mut scenario_ids = first
            .iter()
            .filter_map(|event| event.fields.get("scenario_id").cloned())
            .collect::<Vec<_>>();
        scenario_ids.sort();
        scenario_ids.dedup();
        assert_eq!(
            scenario_ids,
            vec![
                "doctor-core-report-failure".to_string(),
                "doctor-core-report-happy".to_string(),
            ]
        );
    }
}
