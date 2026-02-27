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
const SCREEN_ENGINE_CONTRACT_VERSION: &str = "doctor-screen-engine-v1";
const EVIDENCE_SCHEMA_VERSION: &str = "doctor-evidence-v1";
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

    OperatorModelContract {
        contract_version: OPERATOR_MODEL_VERSION.to_string(),
        personas,
        decision_loops,
        global_evidence_requirements,
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
}
