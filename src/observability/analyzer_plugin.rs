//! Analyzer plugin API and schema/version contract for diagnostics pipelines.
//!
//! This module defines deterministic extension points for third-party analyzers
//! without introducing ambient authority. Plugins are registered explicitly,
//! schema negotiation is deterministic, and execution is isolated so one plugin
//! cannot prevent the rest of a pack from running.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use thiserror::Error;

/// Contract version for the analyzer plugin API.
pub const ANALYZER_PLUGIN_CONTRACT_VERSION: &str = "doctor-analyzer-plugin-v1";

/// Semantic schema version used by plugin input/output contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnalyzerSchemaVersion {
    /// Breaking-compatibility version line.
    pub major: u16,
    /// Additive/backward-compatible increment within a major line.
    pub minor: u16,
}

impl AnalyzerSchemaVersion {
    /// Creates a semantic analyzer schema version.
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl PartialOrd for AnalyzerSchemaVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnalyzerSchemaVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
    }
}

/// Explicit capability required by plugins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalyzerCapability {
    /// Read workspace source/manifests.
    WorkspaceRead,
    /// Read structured evidence artifacts.
    EvidenceRead,
    /// Read replay/trace data.
    TraceRead,
    /// Emit structured lifecycle and finding events.
    StructuredEventEmit,
}

/// Plugin runtime isolation profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalyzerSandboxPolicy {
    /// Plugin is pure/read-only and must not mutate external state.
    DeterministicReadOnly,
    /// Plugin may call bounded external adapters but must remain deterministic.
    DeterministicBounded,
}

/// Plugin metadata used for registration and compatibility checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerPluginDescriptor {
    /// Stable plugin identifier (`slug-like`) used in reports and logs.
    pub plugin_id: String,
    /// Human-readable plugin display name.
    pub display_name: String,
    /// Plugin implementation version.
    pub plugin_version: String,
    /// Input schemas this plugin can read, sorted lexically and unique.
    pub supported_input_schemas: Vec<AnalyzerSchemaVersion>,
    /// Output schema emitted by this plugin.
    pub output_schema: AnalyzerSchemaVersion,
    /// Capabilities required to run this plugin.
    pub required_capabilities: Vec<AnalyzerCapability>,
    /// Sandbox profile required by this plugin.
    pub sandbox_policy: AnalyzerSandboxPolicy,
}

/// One diagnostics finding emitted by a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerFinding {
    /// Stable finding identifier within a plugin namespace.
    pub finding_id: String,
    /// Severity class for prioritization.
    pub severity: AnalyzerSeverity,
    /// Human-readable summary.
    pub summary: String,
    /// Confidence score in basis points (0..=10000).
    pub confidence_bps: u16,
}

/// Severity class for plugin findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalyzerSeverity {
    /// Informational finding.
    Info,
    /// Non-blocking warning.
    Warn,
    /// Actionable high-severity finding.
    Error,
}

/// Plugin output envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerOutput {
    /// Output schema version used by this payload.
    pub schema_version: AnalyzerSchemaVersion,
    /// Deterministic findings list (normalized by the host before aggregation).
    pub findings: Vec<AnalyzerFinding>,
    /// Optional summary metadata.
    pub summary: String,
}

/// Input passed to plugins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerRequest {
    /// Deterministic run identifier.
    pub run_id: String,
    /// Correlation id linking logs/traces/reports.
    pub correlation_id: String,
    /// Workspace root path for context.
    pub workspace_root: String,
    /// Host schema version offered for negotiation.
    pub host_schema_version: AnalyzerSchemaVersion,
    /// Capabilities granted for this run.
    pub granted_capabilities: Vec<AnalyzerCapability>,
}

impl AnalyzerRequest {
    /// Creates a normalized request where capability grants are sorted and unique.
    #[must_use]
    pub fn new(
        run_id: String,
        correlation_id: String,
        workspace_root: String,
        host_schema_version: AnalyzerSchemaVersion,
        mut granted_capabilities: Vec<AnalyzerCapability>,
    ) -> Self {
        granted_capabilities.sort_unstable();
        granted_capabilities.dedup();
        Self {
            run_id,
            correlation_id,
            workspace_root,
            host_schema_version,
            granted_capabilities,
        }
    }
}

/// Third-party analyzer plugin interface.
pub trait AnalyzerPlugin: Send + Sync {
    /// Returns immutable plugin metadata.
    fn descriptor(&self) -> AnalyzerPluginDescriptor;

    /// Executes plugin analysis under the negotiated input schema.
    fn analyze(
        &self,
        request: &AnalyzerRequest,
        negotiated_input_schema: AnalyzerSchemaVersion,
    ) -> Result<AnalyzerOutput, AnalyzerPluginRunError>;
}

/// Lifecycle phase emitted during plugin execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginLifecyclePhase {
    /// Plugin passed registration checks.
    Registered,
    /// Schema negotiation completed.
    Negotiated,
    /// Plugin started execution.
    Started,
    /// Plugin completed successfully.
    Completed,
    /// Plugin execution skipped by policy/compatibility checks.
    Skipped,
    /// Plugin returned a typed execution error.
    Failed,
    /// Plugin panicked and was isolated.
    Panicked,
    /// Host detected a contract violation.
    ContractViolation,
}

/// Schema negotiation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaDecision {
    /// Plugin supports the host schema exactly.
    Exact,
    /// Plugin accepted by downgrading to a lower compatible minor version.
    BackwardCompatibleFallback,
    /// Plugin incompatible because host major is unsupported.
    IncompatibleMajor,
    /// Plugin incompatible because host minor is older than plugin requirements.
    HostMinorTooOld,
}

/// Detailed schema negotiation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaNegotiation {
    /// Negotiation decision category.
    pub decision: SchemaDecision,
    /// Selected schema for execution, if compatible.
    pub selected_schema: Option<AnalyzerSchemaVersion>,
    /// Deterministic rationale for logging.
    pub rationale: String,
}

/// Lifecycle event emitted during registration and pack execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLifecycleEvent {
    /// Plugin identifier.
    pub plugin_id: String,
    /// Lifecycle phase.
    pub phase: PluginLifecyclePhase,
    /// Optional schema decision for negotiation/skip paths.
    pub schema_decision: Option<SchemaDecision>,
    /// Deterministic run identifier.
    pub run_id: String,
    /// Correlation identifier.
    pub correlation_id: String,
    /// Human-readable event message.
    pub message: String,
}

/// Per-plugin execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginExecutionState {
    /// Plugin completed and emitted output.
    Succeeded,
    /// Plugin returned a typed error.
    Failed,
    /// Plugin panicked and was isolated.
    Panicked,
    /// Plugin was skipped because input schema is incompatible.
    SkippedIncompatibleSchema,
    /// Plugin was skipped due to missing capability grants.
    SkippedMissingCapabilities,
    /// Requested plugin id was unknown to the registry.
    SkippedUnknownPlugin,
}

/// Per-plugin execution record used in aggregated reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginExecutionRecord {
    /// Plugin id.
    pub plugin_id: String,
    /// Plugin implementation version (or `unknown`).
    pub plugin_version: String,
    /// Final execution state.
    pub state: PluginExecutionState,
    /// Negotiated input schema, if compatible.
    pub negotiated_input_schema: Option<AnalyzerSchemaVersion>,
    /// Output schema from plugin output, if any.
    pub output_schema: Option<AnalyzerSchemaVersion>,
    /// Number of findings emitted by this plugin.
    pub finding_count: usize,
    /// Optional error code for failed/violating paths.
    pub error_code: Option<String>,
}

/// Aggregated finding with source plugin provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedAnalyzerFinding {
    /// Source plugin id.
    pub plugin_id: String,
    /// Normalized finding payload.
    pub finding: AnalyzerFinding,
}

/// Deterministic plugin-pack execution report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerPluginPackReport {
    /// API contract version used by this report.
    pub contract_version: String,
    /// Host schema presented for negotiation.
    pub host_schema_version: AnalyzerSchemaVersion,
    /// Execution order after deterministic sorting/selection.
    pub execution_order: Vec<String>,
    /// Per-plugin execution records.
    pub executions: Vec<PluginExecutionRecord>,
    /// Aggregated findings across successful plugins.
    pub aggregated_findings: Vec<AggregatedAnalyzerFinding>,
    /// Structured lifecycle log for registration/negotiation/execution.
    pub lifecycle_events: Vec<PluginLifecycleEvent>,
}

/// Registration-time validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PluginRegistrationError {
    /// A required descriptor field is empty or invalid.
    #[error("invalid descriptor for plugin `{plugin_id}`: {reason}")]
    InvalidDescriptor {
        /// Plugin id, or the fallback diagnostic label when absent.
        plugin_id: String,
        /// Deterministic reason string.
        reason: String,
    },
    /// Registry already contains this plugin id.
    #[error("plugin id `{plugin_id}` is already registered")]
    DuplicatePluginId {
        /// Duplicate plugin id.
        plugin_id: String,
    },
}

/// Typed plugin execution error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct AnalyzerPluginRunError {
    /// Stable error code for deterministic diagnostics.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

impl AnalyzerPluginRunError {
    /// Creates a typed plugin error.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Registry for analyzer plugins.
#[derive(Default)]
pub struct AnalyzerPluginRegistry {
    plugins: BTreeMap<String, Arc<dyn AnalyzerPlugin>>,
}

impl AnalyzerPluginRegistry {
    /// Creates an empty plugin registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns sorted plugin ids currently registered.
    #[must_use]
    pub fn plugin_ids(&self) -> Vec<String> {
        self.plugins.keys().cloned().collect()
    }

    /// Registers one plugin after descriptor validation.
    pub fn register(
        &mut self,
        plugin: Arc<dyn AnalyzerPlugin>,
    ) -> Result<AnalyzerPluginDescriptor, PluginRegistrationError> {
        let descriptor = plugin.descriptor();
        validate_descriptor(&descriptor)?;
        if self.plugins.contains_key(&descriptor.plugin_id) {
            return Err(PluginRegistrationError::DuplicatePluginId {
                plugin_id: descriptor.plugin_id,
            });
        }
        self.plugins.insert(descriptor.plugin_id.clone(), plugin);
        Ok(descriptor)
    }

    /// Executes a plugin pack deterministically with schema negotiation and isolation.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn run_pack(
        &self,
        request: &AnalyzerRequest,
        requested_plugins: &[String],
    ) -> AnalyzerPluginPackReport {
        let run_id = request.run_id.clone();
        let correlation_id = request.correlation_id.clone();
        let mut lifecycle_events = Vec::new();
        let execution_order = normalized_execution_order(self, requested_plugins);
        let mut executions = Vec::new();
        let mut aggregated_findings = Vec::new();

        for plugin_id in &execution_order {
            let Some(plugin) = self.plugins.get(plugin_id) else {
                lifecycle_events.push(PluginLifecycleEvent {
                    plugin_id: plugin_id.clone(),
                    phase: PluginLifecyclePhase::Skipped,
                    schema_decision: None,
                    run_id: run_id.clone(),
                    correlation_id: correlation_id.clone(),
                    message: "plugin is not registered".to_string(),
                });
                executions.push(PluginExecutionRecord {
                    plugin_id: plugin_id.clone(),
                    plugin_version: "unknown".to_string(),
                    state: PluginExecutionState::SkippedUnknownPlugin,
                    negotiated_input_schema: None,
                    output_schema: None,
                    finding_count: 0,
                    error_code: Some("plugin_not_registered".to_string()),
                });
                continue;
            };

            let descriptor = plugin.descriptor();
            lifecycle_events.push(PluginLifecycleEvent {
                plugin_id: descriptor.plugin_id.clone(),
                phase: PluginLifecyclePhase::Registered,
                schema_decision: None,
                run_id: run_id.clone(),
                correlation_id: correlation_id.clone(),
                message: "plugin descriptor loaded".to_string(),
            });

            let missing_caps = missing_capabilities(
                &request.granted_capabilities,
                &descriptor.required_capabilities,
            );
            if !missing_caps.is_empty() {
                lifecycle_events.push(PluginLifecycleEvent {
                    plugin_id: descriptor.plugin_id.clone(),
                    phase: PluginLifecyclePhase::Skipped,
                    schema_decision: None,
                    run_id: run_id.clone(),
                    correlation_id: correlation_id.clone(),
                    message: format!(
                        "missing capabilities: {}",
                        missing_caps
                            .iter()
                            .map(|cap| format!("{cap:?}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                });
                executions.push(PluginExecutionRecord {
                    plugin_id: descriptor.plugin_id,
                    plugin_version: descriptor.plugin_version,
                    state: PluginExecutionState::SkippedMissingCapabilities,
                    negotiated_input_schema: None,
                    output_schema: None,
                    finding_count: 0,
                    error_code: Some("missing_capability".to_string()),
                });
                continue;
            }

            let negotiation = negotiate_schema_version(
                request.host_schema_version,
                &descriptor.supported_input_schemas,
            );
            lifecycle_events.push(PluginLifecycleEvent {
                plugin_id: descriptor.plugin_id.clone(),
                phase: PluginLifecyclePhase::Negotiated,
                schema_decision: Some(negotiation.decision),
                run_id: run_id.clone(),
                correlation_id: correlation_id.clone(),
                message: negotiation.rationale.clone(),
            });
            let Some(selected_schema) = negotiation.selected_schema else {
                lifecycle_events.push(PluginLifecycleEvent {
                    plugin_id: descriptor.plugin_id.clone(),
                    phase: PluginLifecyclePhase::Skipped,
                    schema_decision: Some(negotiation.decision),
                    run_id: run_id.clone(),
                    correlation_id: correlation_id.clone(),
                    message: "plugin skipped due to schema incompatibility".to_string(),
                });
                executions.push(PluginExecutionRecord {
                    plugin_id: descriptor.plugin_id,
                    plugin_version: descriptor.plugin_version,
                    state: PluginExecutionState::SkippedIncompatibleSchema,
                    negotiated_input_schema: None,
                    output_schema: None,
                    finding_count: 0,
                    error_code: Some("incompatible_schema".to_string()),
                });
                continue;
            };

            lifecycle_events.push(PluginLifecycleEvent {
                plugin_id: descriptor.plugin_id.clone(),
                phase: PluginLifecyclePhase::Started,
                schema_decision: Some(negotiation.decision),
                run_id: run_id.clone(),
                correlation_id: correlation_id.clone(),
                message: "plugin execution started".to_string(),
            });

            let run_result = catch_unwind(AssertUnwindSafe(|| {
                plugin.analyze(request, selected_schema)
            }));
            match run_result {
                Ok(Ok(mut output)) => {
                    if output.schema_version != descriptor.output_schema {
                        lifecycle_events.push(PluginLifecycleEvent {
                            plugin_id: descriptor.plugin_id.clone(),
                            phase: PluginLifecyclePhase::ContractViolation,
                            schema_decision: Some(negotiation.decision),
                            run_id: run_id.clone(),
                            correlation_id: correlation_id.clone(),
                            message: format!(
                                "plugin output schema mismatch: expected {:?}, got {:?}",
                                descriptor.output_schema, output.schema_version
                            ),
                        });
                        executions.push(PluginExecutionRecord {
                            plugin_id: descriptor.plugin_id,
                            plugin_version: descriptor.plugin_version,
                            state: PluginExecutionState::Failed,
                            negotiated_input_schema: Some(selected_schema),
                            output_schema: Some(output.schema_version),
                            finding_count: 0,
                            error_code: Some("output_schema_mismatch".to_string()),
                        });
                        continue;
                    }

                    if let Err(err) =
                        normalize_plugin_findings(&descriptor.plugin_id, &mut output.findings)
                    {
                        lifecycle_events.push(PluginLifecycleEvent {
                            plugin_id: descriptor.plugin_id.clone(),
                            phase: PluginLifecyclePhase::ContractViolation,
                            schema_decision: Some(negotiation.decision),
                            run_id: run_id.clone(),
                            correlation_id: correlation_id.clone(),
                            message: err.message.clone(),
                        });
                        executions.push(PluginExecutionRecord {
                            plugin_id: descriptor.plugin_id,
                            plugin_version: descriptor.plugin_version,
                            state: PluginExecutionState::Failed,
                            negotiated_input_schema: Some(selected_schema),
                            output_schema: Some(output.schema_version),
                            finding_count: 0,
                            error_code: Some(err.code),
                        });
                        continue;
                    }

                    lifecycle_events.push(PluginLifecycleEvent {
                        plugin_id: descriptor.plugin_id.clone(),
                        phase: PluginLifecyclePhase::Completed,
                        schema_decision: Some(negotiation.decision),
                        run_id: run_id.clone(),
                        correlation_id: correlation_id.clone(),
                        message: format!(
                            "plugin completed with {} finding(s)",
                            output.findings.len()
                        ),
                    });
                    let finding_count = output.findings.len();
                    aggregated_findings.extend(output.findings.into_iter().map(|finding| {
                        AggregatedAnalyzerFinding {
                            plugin_id: descriptor.plugin_id.clone(),
                            finding,
                        }
                    }));
                    executions.push(PluginExecutionRecord {
                        plugin_id: descriptor.plugin_id,
                        plugin_version: descriptor.plugin_version,
                        state: PluginExecutionState::Succeeded,
                        negotiated_input_schema: Some(selected_schema),
                        output_schema: Some(output.schema_version),
                        finding_count,
                        error_code: None,
                    });
                }
                Ok(Err(err)) => {
                    lifecycle_events.push(PluginLifecycleEvent {
                        plugin_id: descriptor.plugin_id.clone(),
                        phase: PluginLifecyclePhase::Failed,
                        schema_decision: Some(negotiation.decision),
                        run_id: run_id.clone(),
                        correlation_id: correlation_id.clone(),
                        message: format!("plugin returned error: {}", err.code),
                    });
                    executions.push(PluginExecutionRecord {
                        plugin_id: descriptor.plugin_id,
                        plugin_version: descriptor.plugin_version,
                        state: PluginExecutionState::Failed,
                        negotiated_input_schema: Some(selected_schema),
                        output_schema: None,
                        finding_count: 0,
                        error_code: Some(err.code),
                    });
                }
                Err(_) => {
                    lifecycle_events.push(PluginLifecycleEvent {
                        plugin_id: descriptor.plugin_id.clone(),
                        phase: PluginLifecyclePhase::Panicked,
                        schema_decision: Some(negotiation.decision),
                        run_id: run_id.clone(),
                        correlation_id: correlation_id.clone(),
                        message: "plugin panicked; isolation preserved".to_string(),
                    });
                    executions.push(PluginExecutionRecord {
                        plugin_id: descriptor.plugin_id,
                        plugin_version: descriptor.plugin_version,
                        state: PluginExecutionState::Panicked,
                        negotiated_input_schema: Some(selected_schema),
                        output_schema: None,
                        finding_count: 0,
                        error_code: Some("plugin_panicked".to_string()),
                    });
                }
            }
        }

        aggregated_findings.sort_unstable_by(|left, right| {
            left.plugin_id
                .cmp(&right.plugin_id)
                .then(left.finding.finding_id.cmp(&right.finding.finding_id))
                .then(left.finding.severity.cmp(&right.finding.severity))
                .then(left.finding.summary.cmp(&right.finding.summary))
                .then(
                    left.finding
                        .confidence_bps
                        .cmp(&right.finding.confidence_bps),
                )
        });

        AnalyzerPluginPackReport {
            contract_version: ANALYZER_PLUGIN_CONTRACT_VERSION.to_string(),
            host_schema_version: request.host_schema_version,
            execution_order,
            executions,
            aggregated_findings,
            lifecycle_events,
        }
    }
}

/// Runs a deterministic smoke flow for a provided plugin set.
#[must_use]
pub fn run_analyzer_plugin_pack_smoke(
    registry: &AnalyzerPluginRegistry,
    request: &AnalyzerRequest,
) -> AnalyzerPluginPackReport {
    registry.run_pack(request, &registry.plugin_ids())
}

/// Negotiates a plugin input schema against the host schema.
#[must_use]
pub fn negotiate_schema_version(
    host_schema: AnalyzerSchemaVersion,
    supported: &[AnalyzerSchemaVersion],
) -> SchemaNegotiation {
    if supported.is_empty() {
        return SchemaNegotiation {
            decision: SchemaDecision::IncompatibleMajor,
            selected_schema: None,
            rationale: "plugin provides no supported input schema".to_string(),
        };
    }
    if supported.contains(&host_schema) {
        return SchemaNegotiation {
            decision: SchemaDecision::Exact,
            selected_schema: Some(host_schema),
            rationale: "exact schema match".to_string(),
        };
    }
    let mut same_major: Vec<AnalyzerSchemaVersion> = supported
        .iter()
        .copied()
        .filter(|schema| schema.major == host_schema.major)
        .collect();
    if same_major.is_empty() {
        return SchemaNegotiation {
            decision: SchemaDecision::IncompatibleMajor,
            selected_schema: None,
            rationale: "host schema major is unsupported".to_string(),
        };
    }
    same_major.sort_unstable();
    if let Some(candidate) = same_major
        .iter()
        .rev()
        .find(|schema| schema.minor <= host_schema.minor)
    {
        return SchemaNegotiation {
            decision: SchemaDecision::BackwardCompatibleFallback,
            selected_schema: Some(*candidate),
            rationale: "falling back to highest compatible minor version".to_string(),
        };
    }
    SchemaNegotiation {
        decision: SchemaDecision::HostMinorTooOld,
        selected_schema: None,
        rationale: "host schema minor is older than plugin minimum".to_string(),
    }
}

fn validate_descriptor(
    descriptor: &AnalyzerPluginDescriptor,
) -> Result<(), PluginRegistrationError> {
    if descriptor.plugin_id.trim().is_empty() {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: "<empty>".to_string(),
            reason: "plugin_id must be non-empty".to_string(),
        });
    }
    if !is_slug_like(&descriptor.plugin_id) {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "plugin_id must be slug-like".to_string(),
        });
    }
    if descriptor.display_name.trim().is_empty() {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "display_name must be non-empty".to_string(),
        });
    }
    if descriptor.plugin_version.trim().is_empty() {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "plugin_version must be non-empty".to_string(),
        });
    }
    if descriptor.supported_input_schemas.is_empty() {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "supported_input_schemas must be non-empty".to_string(),
        });
    }
    let mut schema_copy = descriptor.supported_input_schemas.clone();
    schema_copy.sort_unstable();
    if schema_copy != descriptor.supported_input_schemas {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "supported_input_schemas must be lexically sorted".to_string(),
        });
    }
    let unique_schema_count = schema_copy.iter().collect::<BTreeSet<_>>().len();
    if unique_schema_count != schema_copy.len() {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "supported_input_schemas must be unique".to_string(),
        });
    }
    let mut capability_copy = descriptor.required_capabilities.clone();
    capability_copy.sort_unstable();
    capability_copy.dedup();
    if capability_copy != descriptor.required_capabilities {
        return Err(PluginRegistrationError::InvalidDescriptor {
            plugin_id: descriptor.plugin_id.clone(),
            reason: "required_capabilities must be sorted and unique".to_string(),
        });
    }
    Ok(())
}

fn normalized_execution_order(
    registry: &AnalyzerPluginRegistry,
    requested_plugins: &[String],
) -> Vec<String> {
    if requested_plugins.is_empty() {
        return registry.plugin_ids();
    }
    let mut normalized = requested_plugins.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn missing_capabilities(
    granted: &[AnalyzerCapability],
    required: &[AnalyzerCapability],
) -> Vec<AnalyzerCapability> {
    let granted: BTreeSet<AnalyzerCapability> = granted.iter().copied().collect();
    required
        .iter()
        .copied()
        .filter(|required_capability| !granted.contains(required_capability))
        .collect()
}

fn normalize_plugin_findings(
    plugin_id: &str,
    findings: &mut [AnalyzerFinding],
) -> Result<(), AnalyzerPluginRunError> {
    findings.sort_unstable_by(|left, right| {
        left.finding_id
            .cmp(&right.finding_id)
            .then(left.severity.cmp(&right.severity))
            .then(left.summary.cmp(&right.summary))
            .then(left.confidence_bps.cmp(&right.confidence_bps))
    });

    for pair in findings.windows(2) {
        if pair[0].finding_id == pair[1].finding_id {
            return Err(AnalyzerPluginRunError::new(
                "duplicate_finding_id",
                format!(
                    "plugin `{plugin_id}` emitted duplicate finding_id `{}`",
                    pair[0].finding_id
                ),
            ));
        }
    }

    Ok(())
}

fn is_slug_like(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

#[cfg(test)]
#[path = "analyzer_plugin_inline_tests.rs"]
mod tests;
