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
    /// Primary UI surfaces used by this persona.
    pub primary_views: Vec<String>,
    /// Default decision loop identifier.
    pub default_decision_loop: String,
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
                "- {} ({}) => {} [loop={}]",
                persona.label, persona.id, persona.mission, persona.default_decision_loop
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
            primary_views: vec![
                "bead_command_center".to_string(),
                "scenario_workbench".to_string(),
                "evidence_timeline".to_string(),
            ],
            default_decision_loop: "triage_investigate_remediate".to_string(),
        },
        OperatorPersona {
            id: "release_guardian".to_string(),
            label: "Release Guardian".to_string(),
            mission: "Enforce release gates and block unsafe promotions.".to_string(),
            primary_views: vec![
                "gate_status_board".to_string(),
                "artifact_audit".to_string(),
                "decision_ledger".to_string(),
            ],
            default_decision_loop: "release_gate_verification".to_string(),
        },
        OperatorPersona {
            id: "runtime_operator".to_string(),
            label: "Runtime Operator".to_string(),
            mission: "Contain live incidents while preserving deterministic evidence.".to_string(),
            primary_views: vec![
                "incident_console".to_string(),
                "runtime_health".to_string(),
                "replay_inspector".to_string(),
            ],
            default_decision_loop: "incident_containment".to_string(),
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
    }

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
        }
    }

    for persona in &contract.personas {
        if !seen_loops.contains(&persona.default_decision_loop) {
            return Err(format!(
                "persona {} references unknown decision loop {}",
                persona.id, persona.default_decision_loop
            ));
        }
    }

    let mut deduped = contract.global_evidence_requirements.clone();
    deduped.sort();
    deduped.dedup();
    if deduped.len() != contract.global_evidence_requirements.len() {
        return Err("global_evidence_requirements must be unique".to_string());
    }
    if deduped != contract.global_evidence_requirements {
        return Err("global_evidence_requirements must be lexically sorted".to_string());
    }

    Ok(())
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
}
