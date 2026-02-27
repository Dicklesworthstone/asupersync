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
        lines.push(format!(
            "Failure taxonomy: {}",
            self.failure_taxonomy.len()
        ));
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

const SCANNER_VERSION: &str = "doctor-workspace-scan-v1";
const TAXONOMY_VERSION: &str = "capability-surfaces-v1";
const OPERATOR_MODEL_VERSION: &str = "doctor-operator-model-v1";
const NAVIGATION_TOPOLOGY_VERSION: &str = "doctor-navigation-topology-v1";
const UX_SIGNOFF_MATRIX_VERSION: &str = "doctor-ux-signoff-matrix-v1";
const UX_BASELINE_MATRIX_VERSION: &str = "doctor-ux-acceptance-matrix-v0";
const SCREEN_ENGINE_CONTRACT_VERSION: &str = "doctor-screen-engine-v1";
const EVIDENCE_SCHEMA_VERSION: &str = "doctor-evidence-v1";
const STRUCTURED_LOGGING_CONTRACT_VERSION: &str = "doctor-logging-v1";
const EXECUTION_ADAPTER_CONTRACT_VERSION: &str = "doctor-exec-adapter-v1";
const SCENARIO_COMPOSER_CONTRACT_VERSION: &str = "doctor-scenario-composer-v1";
const CORE_DIAGNOSTICS_REPORT_VERSION: &str = "doctor-core-report-v1";
const ADVANCED_DIAGNOSTICS_REPORT_VERSION: &str = "doctor-advanced-report-v1";
const VISUAL_LANGUAGE_VERSION: &str = "doctor-visual-language-v1";
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
                description:
                    "Cancellation-path replay with deterministic recovery verification."
                        .to_string(),
                required_command_classes: vec![
                    "cargo_check".to_string(),
                    "cargo_test".to_string(),
                ],
                required_artifacts: vec![
                    "structured_log".to_string(),
                    "trace_bundle".to_string(),
                ],
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
                description:
                    "Full regression execution with replay-ready transcript capture."
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
                operator_action: "Provide deterministic replay seed and retry compose."
                    .to_string(),
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

    validate_lexical_string_set(
        &contract.required_request_fields,
        "required_request_fields",
    )?;
    for required in ["correlation_id", "requested_by", "run_id", "seed", "template_id"] {
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
            return Err(format!("template {} has empty description", template.template_id));
        }
        validate_lexical_string_set(
            &template.required_command_classes,
            &format!(
                "template {} required_command_classes",
                template.template_id
            ),
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
        return Err(
            "queue_policy.cancellation_policy must be cancel_duplicate_run_id".to_string(),
        );
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
        priority: request.priority_override.unwrap_or(template.default_priority),
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
        contract.scenario_templates[0].required_command_classes.sort();
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
            seed: "".to_string(),
            priority_override: None,
            requested_by: "doctor_cli".to_string(),
        };
        let entry = compose_scenario_run(&contract, &request).expect("compose should succeed");
        assert_eq!(entry.queue_id, "queue-run-happy");
        assert_eq!(entry.priority, 120);
        assert_eq!(entry.state, "queued");
    }

    #[test]
    fn build_scenario_run_queue_orders_by_priority_then_run_id() {
        let contract = scenario_composer_contract();
        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-b".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-b".to_string(),
                seed: "".to_string(),
                priority_override: Some(120),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-a".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-a".to_string(),
                seed: "".to_string(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-c".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-c".to_string(),
                seed: "".to_string(),
                priority_override: Some(220),
                requested_by: "doctor_cli".to_string(),
            },
        ];
        let queue = build_scenario_run_queue(&contract, &requests).expect("queue should build");
        let order = queue.iter().map(|entry| entry.run_id.clone()).collect::<Vec<_>>();
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

        let requests = vec![
            ScenarioRunRequest {
                run_id: "run-one".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-one".to_string(),
                seed: "".to_string(),
                priority_override: None,
                requested_by: "doctor_cli".to_string(),
            },
            ScenarioRunRequest {
                run_id: "run-two".to_string(),
                template_id: "scenario_happy_path_smoke".to_string(),
                correlation_id: "corr-two".to_string(),
                seed: "".to_string(),
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
                seed: "".to_string(),
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
