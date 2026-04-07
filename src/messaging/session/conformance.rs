//! Runtime session conformance monitoring for FABRIC protocol contracts.
//!
//! The contract and projection layers describe what a two-party protocol is
//! allowed to do. This module turns that static description into a small
//! runtime monitor:
//!
//! - each role receives a projected local view annotated with global paths;
//! - observations are checked against the next legal local transition;
//! - timeout/evidence/recovery metadata is surfaced on violations;
//! - a small oracle wrapper lets lab-mode tests treat the monitor as a
//!   deterministic invariant checker.

use super::contract::{
    GlobalSessionType, Label, MessageType, ProtocolContract, ProtocolContractValidationError,
    RoleName, SessionPath, SessionType,
};
use super::projection::ProjectionError;
use crate::cx::Cx;
use crate::lab::runtime::LabRuntime;
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
struct StepMetadata {
    evidence_checkpoints: Vec<String>,
    timeout: Option<Duration>,
    compensation_paths: Vec<ConformanceRecoveryBranch>,
    cutoff_paths: Vec<ConformanceRecoveryBranch>,
}

impl StepMetadata {
    fn to_violation_evidence(
        &self,
        contract_name: &str,
        role: &RoleName,
        path: SessionPath,
    ) -> ConformanceViolationEvidence {
        ConformanceViolationEvidence {
            contract_name: contract_name.to_owned(),
            role: role.clone(),
            path: Some(path),
            candidate_paths: Vec::new(),
            evidence_checkpoints: self.evidence_checkpoints.clone(),
            timeout: self.timeout,
            compensation_paths: self.compensation_paths.clone(),
            cutoff_paths: self.cutoff_paths.clone(),
        }
    }

    fn into_check_record(
        self,
        role: RoleName,
        path: SessionPath,
        expectation: ConformanceExpectation,
        observed: ConformanceObserved,
        observed_at: Option<Time>,
    ) -> ConformanceCheckRecord {
        ConformanceCheckRecord {
            role,
            path,
            expectation,
            observed,
            observed_at,
            evidence_checkpoints: self.evidence_checkpoints,
            timeout: self.timeout,
            compensation_paths: self.compensation_paths,
            cutoff_paths: self.cutoff_paths,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnnotatedLocalBranch {
    label: Label,
    path: SessionPath,
    metadata: StepMetadata,
    continuation: AnnotatedLocalType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AnnotatedLocalType {
    Send {
        path: SessionPath,
        metadata: StepMetadata,
        message: MessageType,
        next: Box<Self>,
    },
    Receive {
        path: SessionPath,
        metadata: StepMetadata,
        message: MessageType,
        next: Box<Self>,
    },
    Choice {
        branches: Vec<AnnotatedLocalBranch>,
    },
    Branch {
        branches: Vec<AnnotatedLocalBranch>,
    },
    Recurse {
        label: Label,
    },
    RecursePoint {
        label: Label,
        body: Box<Self>,
    },
    End {
        path: SessionPath,
    },
}

impl AnnotatedLocalType {
    fn expectation(&self) -> ConformanceExpectation {
        match self {
            Self::Send { message, .. } => ConformanceExpectation::Send {
                message: message.clone(),
            },
            Self::Receive { message, .. } => ConformanceExpectation::Receive {
                message: message.clone(),
            },
            Self::Choice { branches } => ConformanceExpectation::ChooseBranch {
                labels: branches.iter().map(|branch| branch.label.clone()).collect(),
            },
            Self::Branch { branches } => ConformanceExpectation::ObserveBranch {
                labels: branches.iter().map(|branch| branch.label.clone()).collect(),
            },
            Self::End { .. } => ConformanceExpectation::Complete,
            Self::Recurse { .. } | Self::RecursePoint { .. } => {
                unreachable!("role state is normalized before querying expectations")
            }
        }
    }

    fn timeout_budget(&self) -> Option<Duration> {
        match self {
            Self::Send { metadata, .. } | Self::Receive { metadata, .. } => metadata.timeout,
            Self::Choice { branches } | Self::Branch { branches } => branches
                .iter()
                .filter_map(|branch| branch.metadata.timeout)
                .min(),
            Self::End { .. } => None,
            Self::Recurse { .. } | Self::RecursePoint { .. } => {
                unreachable!("role state is normalized before querying timeouts")
            }
        }
    }

    fn violation_evidence(
        &self,
        contract_name: &str,
        role: &RoleName,
    ) -> ConformanceViolationEvidence {
        match self {
            Self::Send { path, metadata, .. } | Self::Receive { path, metadata, .. } => {
                metadata.to_violation_evidence(contract_name, role, path.clone())
            }
            Self::Choice { branches } | Self::Branch { branches } => {
                aggregate_branch_evidence(contract_name, role, branches)
            }
            Self::End { path } => ConformanceViolationEvidence {
                contract_name: contract_name.to_owned(),
                role: role.clone(),
                path: Some(path.clone()),
                candidate_paths: Vec::new(),
                evidence_checkpoints: Vec::new(),
                timeout: None,
                compensation_paths: Vec::new(),
                cutoff_paths: Vec::new(),
            },
            Self::Recurse { .. } | Self::RecursePoint { .. } => {
                unreachable!("role state is normalized before querying evidence")
            }
        }
    }
}

fn aggregate_branch_evidence(
    contract_name: &str,
    role: &RoleName,
    branches: &[AnnotatedLocalBranch],
) -> ConformanceViolationEvidence {
    let mut evidence_checkpoints = Vec::new();
    let mut compensation_paths = Vec::new();
    let mut cutoff_paths = Vec::new();

    for branch in branches {
        for checkpoint in &branch.metadata.evidence_checkpoints {
            if !evidence_checkpoints.contains(checkpoint) {
                evidence_checkpoints.push(checkpoint.clone());
            }
        }
        for compensation in &branch.metadata.compensation_paths {
            if !compensation_paths.contains(compensation) {
                compensation_paths.push(compensation.clone());
            }
        }
        for cutoff in &branch.metadata.cutoff_paths {
            if !cutoff_paths.contains(cutoff) {
                cutoff_paths.push(cutoff.clone());
            }
        }
    }

    ConformanceViolationEvidence {
        contract_name: contract_name.to_owned(),
        role: role.clone(),
        path: None,
        candidate_paths: branches.iter().map(|branch| branch.path.clone()).collect(),
        evidence_checkpoints,
        timeout: branches
            .iter()
            .filter_map(|branch| branch.metadata.timeout)
            .min(),
        compensation_paths,
        cutoff_paths,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageStepKind {
    Send,
    Receive,
}

impl MessageStepKind {
    fn expectation(self, message: MessageType) -> ConformanceExpectation {
        match self {
            Self::Send => ConformanceExpectation::Send { message },
            Self::Receive => ConformanceExpectation::Receive { message },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchStepKind {
    Choice,
    Observe,
}

impl BranchStepKind {
    fn expectation(self, labels: Vec<Label>) -> ConformanceExpectation {
        match self {
            Self::Choice => ConformanceExpectation::ChooseBranch { labels },
            Self::Observe => ConformanceExpectation::ObserveBranch { labels },
        }
    }
}

struct ObserveRequest<'a> {
    contract_name: &'a str,
    role: &'a RoleName,
    message: Option<&'a MessageType>,
    label: Option<&'a Label>,
    observed: &'a ConformanceObserved,
    observed_at: Option<Time>,
}

impl ObserveRequest<'_> {
    fn unexpected(
        &self,
        expected: ConformanceExpectation,
        evidence: ConformanceViolationEvidence,
    ) -> Box<ConformanceViolation> {
        Box::new(ConformanceViolation::UnexpectedObservation {
            contract_name: self.contract_name.to_owned(),
            role: self.role.clone(),
            expected,
            observed: self.observed.clone(),
            evidence: Box::new(evidence),
        })
    }
}

fn observation_time(state: &RoleConformanceState, observed_at: Option<Time>) -> Time {
    observed_at.unwrap_or(state.entered_at)
}

fn check_observation_timeout(
    state: &RoleConformanceState,
    contract_name: &str,
    role: &RoleName,
    now: Option<Time>,
) -> Result<(), Box<ConformanceViolation>> {
    let Some(now) = now else {
        return Ok(());
    };
    let Some(timeout) = state.current.timeout_budget() else {
        return Ok(());
    };
    let elapsed_nanos = now.duration_since(state.entered_at);
    let timeout_nanos = duration_to_nanos(timeout);
    if elapsed_nanos > timeout_nanos {
        return Err(Box::new(ConformanceViolation::Timeout {
            contract_name: contract_name.to_owned(),
            role: role.clone(),
            expected: state.current.expectation(),
            elapsed: Duration::from_nanos(elapsed_nanos),
            evidence: Box::new(state.current.violation_evidence(contract_name, role)),
        }));
    }
    Ok(())
}

fn observe_message_step(
    state: &mut RoleConformanceState,
    request: &ObserveRequest<'_>,
    kind: MessageStepKind,
    path: SessionPath,
    metadata: StepMetadata,
    expected_message: &MessageType,
    next: AnnotatedLocalType,
) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
    let expectation = kind.expectation(expected_message.clone());
    if request.label.is_some() || request.message != Some(expected_message) {
        return Err(request.unexpected(
            expectation,
            metadata.to_violation_evidence(request.contract_name, request.role, path),
        ));
    }
    let record = metadata.into_check_record(
        request.role.clone(),
        path,
        expectation,
        request.observed.clone(),
        request.observed_at,
    );
    let entered_at = observation_time(state, request.observed_at);
    state.advance_to(next, entered_at);
    Ok(record)
}

fn observe_branch_step(
    state: &mut RoleConformanceState,
    request: &ObserveRequest<'_>,
    kind: BranchStepKind,
    branches: &[AnnotatedLocalBranch],
) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
    let expectation =
        kind.expectation(branches.iter().map(|branch| branch.label.clone()).collect());
    let aggregate_evidence =
        || aggregate_branch_evidence(request.contract_name, request.role, branches);
    if request.message.is_some() {
        return Err(request.unexpected(expectation, aggregate_evidence()));
    }
    let Some(observed_label) = request.label else {
        return Err(request.unexpected(expectation, aggregate_evidence()));
    };
    let Some(branch) = branches
        .iter()
        .find(|branch| &branch.label == observed_label)
    else {
        return Err(request.unexpected(expectation, aggregate_evidence()));
    };
    let record = branch.metadata.clone().into_check_record(
        request.role.clone(),
        branch.path.clone(),
        expectation,
        request.observed.clone(),
        request.observed_at,
    );
    let entered_at = observation_time(state, request.observed_at);
    state.advance_to(branch.continuation.clone(), entered_at);
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RoleConformanceState {
    current: AnnotatedLocalType,
    recursion_points: BTreeMap<Label, AnnotatedLocalType>,
    entered_at: Time,
}

impl RoleConformanceState {
    fn new(root: AnnotatedLocalType, entered_at: Time) -> Self {
        let mut state = Self {
            current: root,
            recursion_points: BTreeMap::new(),
            entered_at,
        };
        state.normalize();
        state
    }

    fn normalize(&mut self) {
        // Track which Recurse labels have been resolved to detect degenerate
        // cycles like `RecursePoint("L", Recurse("L"))`.  Such contracts pass
        // validation but would loop forever without this guard.
        let mut resolved_recurse_labels: Vec<Label> = Vec::new();
        loop {
            match self.current.clone() {
                AnnotatedLocalType::RecursePoint { label, body } => {
                    let body_val = *body;
                    self.recursion_points.insert(label, body_val.clone());
                    self.current = body_val;
                }
                AnnotatedLocalType::Recurse { label } => {
                    if resolved_recurse_labels.contains(&label) {
                        // Degenerate cycle: the recursion body immediately
                        // recurses back without any protocol step.  Treat as
                        // end-of-protocol so callers get `Complete` instead
                        // of an infinite loop or a panic.
                        self.current = AnnotatedLocalType::End {
                            path: SessionPath::root(),
                        };
                        break;
                    }
                    resolved_recurse_labels.push(label.clone());
                    self.current =
                        self.recursion_points
                            .get(&label)
                            .cloned()
                            .unwrap_or_else(|| {
                                unreachable!("validated contracts always recurse to known labels")
                            });
                }
                _ => break,
            }
        }
    }

    fn is_complete(&self) -> bool {
        matches!(self.current, AnnotatedLocalType::End { .. })
    }

    fn advance_to(&mut self, next: AnnotatedLocalType, entered_at: Time) {
        self.current = next;
        self.entered_at = entered_at;
        self.normalize();
    }
}

struct MonitorMetadata {
    default_timeout: Option<Duration>,
    timeout_overrides: BTreeMap<SessionPath, Duration>,
    evidence_by_path: BTreeMap<SessionPath, Vec<String>>,
    compensation_by_path: BTreeMap<SessionPath, Vec<ConformanceRecoveryBranch>>,
    cutoff_by_path: BTreeMap<SessionPath, Vec<ConformanceRecoveryBranch>>,
}

impl MonitorMetadata {
    fn from_contract(contract: &ProtocolContract) -> Self {
        Self {
            default_timeout: contract.timeout_law.default_timeout,
            timeout_overrides: contract
                .timeout_law
                .per_step
                .iter()
                .map(|rule| (rule.path.clone(), rule.timeout))
                .collect(),
            evidence_by_path: collect_named_paths(
                contract
                    .evidence_checkpoints
                    .iter()
                    .map(|checkpoint| (&checkpoint.path, checkpoint.name.clone())),
            ),
            compensation_by_path: collect_recovery_paths(&contract.compensation_paths),
            cutoff_by_path: collect_recovery_paths(&contract.cutoff_paths),
        }
    }

    fn for_path(&self, path: &SessionPath) -> StepMetadata {
        StepMetadata {
            evidence_checkpoints: self.evidence_by_path.get(path).cloned().unwrap_or_default(),
            timeout: if is_end_path(path) {
                None
            } else {
                self.timeout_overrides
                    .get(path)
                    .copied()
                    .or(self.default_timeout)
            },
            compensation_paths: self
                .compensation_by_path
                .get(path)
                .cloned()
                .unwrap_or_default(),
            cutoff_paths: self.cutoff_by_path.get(path).cloned().unwrap_or_default(),
        }
    }
}

fn collect_named_paths<'a, I>(items: I) -> BTreeMap<SessionPath, Vec<String>>
where
    I: IntoIterator<Item = (&'a SessionPath, String)>,
{
    let mut by_path: BTreeMap<SessionPath, Vec<String>> = BTreeMap::new();
    for (path, name) in items {
        by_path.entry(path.to_owned()).or_default().push(name);
    }
    by_path
}

trait RecoveryPathLike {
    fn name(&self) -> &str;
    fn trigger(&self) -> &SessionPath;
    fn recovery_path(&self) -> &[SessionPath];
}

impl RecoveryPathLike for super::contract::CompensationPath {
    fn name(&self) -> &str {
        &self.name
    }

    fn trigger(&self) -> &SessionPath {
        &self.trigger
    }

    fn recovery_path(&self) -> &[SessionPath] {
        &self.path
    }
}

impl RecoveryPathLike for super::contract::CutoffPath {
    fn name(&self) -> &str {
        &self.name
    }

    fn trigger(&self) -> &SessionPath {
        &self.trigger
    }

    fn recovery_path(&self) -> &[SessionPath] {
        &self.path
    }
}

fn collect_recovery_paths<T>(paths: &[T]) -> BTreeMap<SessionPath, Vec<ConformanceRecoveryBranch>>
where
    T: RecoveryPathLike,
{
    let mut by_path = BTreeMap::new();
    for path in paths {
        push_recovery_branch(
            &mut by_path,
            path.trigger(),
            path.name(),
            path.recovery_path(),
            ConformanceRecoveryStage::Trigger,
        );
        for step in path.recovery_path() {
            push_recovery_branch(
                &mut by_path,
                step,
                path.name(),
                path.recovery_path(),
                ConformanceRecoveryStage::Step,
            );
        }
    }
    by_path
}

fn push_recovery_branch(
    by_path: &mut BTreeMap<SessionPath, Vec<ConformanceRecoveryBranch>>,
    path: &SessionPath,
    name: &str,
    recovery_path: &[SessionPath],
    stage: ConformanceRecoveryStage,
) {
    let branch = ConformanceRecoveryBranch {
        name: name.to_owned(),
        stage,
        recovery_path: recovery_path.to_vec(),
    };
    let target = by_path.entry(path.to_owned()).or_default();
    if !target.contains(&branch) {
        target.push(branch);
    }
}

fn is_end_path(path: &SessionPath) -> bool {
    path.segments()
        .last()
        .is_some_and(|segment| segment == "end")
}

fn build_annotated_local_type(
    global: &GlobalSessionType,
    roles: &[RoleName],
    role: &RoleName,
    metadata: &MonitorMetadata,
) -> Result<AnnotatedLocalType, ProjectionError> {
    if roles.len() != 2 {
        return Err(ProjectionError::UnsupportedRoleCount {
            actual: roles.len(),
        });
    }
    if !roles.contains(role) {
        return Err(ProjectionError::UnknownRole(role.clone()));
    }
    build_annotated_session_type(&global.root, &SessionPath::root(), roles, role, metadata)
}

fn build_annotated_session_type(
    session_type: &SessionType,
    base: &SessionPath,
    roles: &[RoleName],
    role: &RoleName,
    metadata: &MonitorMetadata,
) -> Result<AnnotatedLocalType, ProjectionError> {
    match session_type {
        SessionType::Send { message, next } => {
            build_annotated_message_step(base, "send", message, next, roles, role, metadata)
        }
        SessionType::Receive { message, next } => {
            build_annotated_message_step(base, "receive", message, next, roles, role, metadata)
        }
        SessionType::Choice { decider, branches } => {
            if !roles.contains(decider) {
                return Err(ProjectionError::UnknownRole(decider.clone()));
            }
            let branches =
                build_annotated_branches(base, "choice", decider, branches, roles, role, metadata)?;
            if role == decider {
                Ok(AnnotatedLocalType::Choice { branches })
            } else {
                Ok(AnnotatedLocalType::Branch { branches })
            }
        }
        SessionType::Branch { offerer, branches } => {
            if !roles.contains(offerer) {
                return Err(ProjectionError::UnknownRole(offerer.clone()));
            }
            let branches =
                build_annotated_branches(base, "branch", offerer, branches, roles, role, metadata)?;
            if role == offerer {
                Ok(AnnotatedLocalType::Choice { branches })
            } else {
                Ok(AnnotatedLocalType::Branch { branches })
            }
        }
        SessionType::Recurse { label } => Ok(AnnotatedLocalType::Recurse {
            label: label.clone(),
        }),
        SessionType::RecursePoint { label, body } => Ok(AnnotatedLocalType::RecursePoint {
            label: label.clone(),
            body: Box::new(build_annotated_session_type(
                body,
                &base.child(format!("recurse-point:{label}")),
                roles,
                role,
                metadata,
            )?),
        }),
        SessionType::End => Ok(AnnotatedLocalType::End {
            path: base.child("end"),
        }),
    }
}

fn build_annotated_message_step(
    base: &SessionPath,
    prefix: &str,
    message: &MessageType,
    next: &SessionType,
    roles: &[RoleName],
    role: &RoleName,
    metadata: &MonitorMetadata,
) -> Result<AnnotatedLocalType, ProjectionError> {
    if !roles.contains(&message.sender) {
        return Err(ProjectionError::UnknownRole(message.sender.clone()));
    }
    if !roles.contains(&message.receiver) {
        return Err(ProjectionError::UnknownRole(message.receiver.clone()));
    }

    let path = base.child(format!("{prefix}:{}", message.name));
    let next = build_annotated_session_type(next, &path, roles, role, metadata)?;
    let step_metadata = metadata.for_path(&path);
    if role == &message.sender {
        Ok(AnnotatedLocalType::Send {
            path,
            metadata: step_metadata,
            message: message.clone(),
            next: Box::new(next),
        })
    } else if role == &message.receiver {
        Ok(AnnotatedLocalType::Receive {
            path,
            metadata: step_metadata,
            message: message.clone(),
            next: Box::new(next),
        })
    } else {
        Err(ProjectionError::UnknownRole(role.clone()))
    }
}

fn build_annotated_branches(
    base: &SessionPath,
    prefix: &str,
    controller: &RoleName,
    branches: &[super::contract::SessionBranch],
    roles: &[RoleName],
    role: &RoleName,
    metadata: &MonitorMetadata,
) -> Result<Vec<AnnotatedLocalBranch>, ProjectionError> {
    branches
        .iter()
        .map(|branch| {
            let path = base.child(format!("{prefix}:{controller}:{}", branch.label));
            Ok(AnnotatedLocalBranch {
                label: branch.label.clone(),
                metadata: metadata.for_path(&path),
                continuation: build_annotated_session_type(
                    &branch.continuation,
                    &path,
                    roles,
                    role,
                    metadata,
                )?,
                path,
            })
        })
        .collect()
}

/// Recovery hook stage relative to the declared recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceRecoveryStage {
    /// Path that activates the recovery branch.
    Trigger,
    /// Path that participates inside the recovery branch itself.
    Step,
}

/// One compensation/cutoff branch attached to a conformance failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceRecoveryBranch {
    /// Human-readable recovery branch name.
    pub name: String,
    /// Whether the current step triggered or participated in the recovery path.
    pub stage: ConformanceRecoveryStage,
    /// Ordered recovery path declared by the contract.
    pub recovery_path: Vec<SessionPath>,
}

/// Next legal local transition for one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConformanceExpectation {
    /// The role must emit the named message.
    Send {
        /// Expected message descriptor.
        message: MessageType,
    },
    /// The role must consume the named message.
    Receive {
        /// Expected message descriptor.
        message: MessageType,
    },
    /// The role must choose one of the declared branch labels.
    ChooseBranch {
        /// Legal branch labels.
        labels: Vec<Label>,
    },
    /// The role must observe one of the declared peer branch labels.
    ObserveBranch {
        /// Legal branch labels.
        labels: Vec<Label>,
    },
    /// The local protocol is already complete.
    Complete,
}

impl fmt::Display for ConformanceExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send { message } => write!(f, "send {}", message.name),
            Self::Receive { message } => write!(f, "receive {}", message.name),
            Self::ChooseBranch { labels } => {
                write!(f, "choose one of [{}]", join_labels(labels))
            }
            Self::ObserveBranch { labels } => {
                write!(f, "observe one of [{}]", join_labels(labels))
            }
            Self::Complete => f.write_str("complete"),
        }
    }
}

/// Concrete role-local observation checked by the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConformanceObserved {
    /// Observed message transition, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageType>,
    /// Observed branch label, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<Label>,
}

impl ConformanceObserved {
    fn from_inputs(message: Option<&MessageType>, label: Option<&Label>) -> Self {
        Self {
            message: message.cloned(),
            label: label.cloned(),
        }
    }
}

impl fmt::Display for ConformanceObserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.message, &self.label) {
            (Some(message), None) => write!(f, "message {}", message.name),
            (None, Some(label)) => write!(f, "label {label}"),
            (Some(message), Some(label)) => write!(f, "message {} + label {}", message.name, label),
            (None, None) => f.write_str("empty observation"),
        }
    }
}

/// Extra metadata emitted alongside a conformance violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceViolationEvidence {
    /// Human-readable source contract name.
    pub contract_name: String,
    /// Role that observed the violating transition.
    pub role: RoleName,
    /// Precise path when the next step is unambiguous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<SessionPath>,
    /// Candidate paths when the monitor was waiting on a labeled branch choice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_paths: Vec<SessionPath>,
    /// Evidence checkpoints attached to the failing path or candidate set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_checkpoints: Vec<String>,
    /// Timeout budget active at the point of failure, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,
    /// Compensation branches available from the failing path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compensation_paths: Vec<ConformanceRecoveryBranch>,
    /// Graceful cutoff branches available from the failing path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoff_paths: Vec<ConformanceRecoveryBranch>,
}

impl ConformanceViolationEvidence {
    fn location(&self) -> String {
        self.path.as_ref().map_or_else(
            || {
                if self.candidate_paths.is_empty() {
                    "unknown-path".to_owned()
                } else {
                    self.candidate_paths
                        .iter()
                        .map(SessionPath::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            },
            SessionPath::to_string,
        )
    }
}

/// One successful conformance check emitted by the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceCheckRecord {
    /// Role whose local protocol view advanced.
    pub role: RoleName,
    /// Global protocol path satisfied by the observation.
    pub path: SessionPath,
    /// Next-step expectation that was satisfied.
    pub expectation: ConformanceExpectation,
    /// Concrete observation that satisfied the step.
    pub observed: ConformanceObserved,
    /// Time attached to the observation when the caller supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<Time>,
    /// Evidence checkpoints attached to the satisfied path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_checkpoints: Vec<String>,
    /// Timeout budget attached to the satisfied path, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<Duration>,
    /// Compensation branches that become relevant at this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compensation_paths: Vec<ConformanceRecoveryBranch>,
    /// Graceful cutoff branches that become relevant at this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoff_paths: Vec<ConformanceRecoveryBranch>,
}

/// Construction failure while projecting conformance state from a contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConformanceMonitorInitError {
    /// The source contract failed validation.
    #[error(transparent)]
    InvalidContract(#[from] ProtocolContractValidationError),
    /// A role-local projection failed unexpectedly.
    #[error(transparent)]
    Projection(#[from] ProjectionError),
}

/// Role-local conformance violation emitted by the runtime monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConformanceViolation {
    /// Observation referenced a role outside the contract.
    UnknownRole {
        /// Human-readable source contract name.
        contract_name: String,
        /// Unknown role name.
        role: RoleName,
    },
    /// Observation does not match the next legal local transition.
    UnexpectedObservation {
        /// Human-readable source contract name.
        contract_name: String,
        /// Role whose local state rejected the observation.
        role: RoleName,
        /// Next legal local transition.
        expected: ConformanceExpectation,
        /// Concrete observation supplied by the caller.
        observed: ConformanceObserved,
        /// Evidence/recovery metadata attached to the failing step.
        evidence: Box<ConformanceViolationEvidence>,
    },
    /// Time budget for the next local step elapsed before progress.
    Timeout {
        /// Human-readable source contract name.
        contract_name: String,
        /// Role whose local state timed out.
        role: RoleName,
        /// Next legal local transition that failed to arrive in time.
        expected: ConformanceExpectation,
        /// Elapsed time since the current step became active.
        elapsed: Duration,
        /// Evidence/recovery metadata attached to the timed-out step.
        evidence: Box<ConformanceViolationEvidence>,
    },
    /// The protocol was already complete for the role.
    AlreadyComplete {
        /// Human-readable source contract name.
        contract_name: String,
        /// Role whose local protocol had already ended.
        role: RoleName,
        /// Observation supplied after completion.
        observed: ConformanceObserved,
    },
}

impl fmt::Display for ConformanceViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRole {
                contract_name,
                role,
            } => write!(
                f,
                "protocol `{contract_name}` does not declare role `{role}`"
            ),
            Self::UnexpectedObservation {
                contract_name,
                role,
                expected,
                observed,
                evidence,
            } => write!(
                f,
                "protocol `{contract_name}` role `{role}` expected {expected} at `{}` but observed {observed}",
                evidence.location()
            ),
            Self::Timeout {
                contract_name,
                role,
                expected,
                elapsed,
                evidence,
            } => write!(
                f,
                "protocol `{contract_name}` role `{role}` timed out waiting for {expected} at `{}` after {}ms",
                evidence.location(),
                elapsed.as_millis()
            ),
            Self::AlreadyComplete {
                contract_name,
                role,
                observed,
            } => write!(
                f,
                "protocol `{contract_name}` role `{role}` is already complete; observed {observed}"
            ),
        }
    }
}

impl std::error::Error for ConformanceViolation {}

/// Runtime monitor that checks observations against projected local session types.
#[derive(Debug, Clone)]
pub struct ConformanceMonitor {
    contract_name: String,
    roles: BTreeMap<RoleName, RoleConformanceState>,
    history: Vec<ConformanceCheckRecord>,
}

impl ConformanceMonitor {
    /// Build a fresh monitor from a validated protocol contract.
    pub fn new(contract: &ProtocolContract) -> Result<Self, ConformanceMonitorInitError> {
        Self::new_at(contract, Time::ZERO)
    }

    /// Build a fresh monitor with an explicit activation time.
    pub fn new_at(
        contract: &ProtocolContract,
        start_time: Time,
    ) -> Result<Self, ConformanceMonitorInitError> {
        contract.validate()?;

        let metadata = MonitorMetadata::from_contract(contract);
        let mut roles = BTreeMap::new();
        for role in &contract.roles {
            let local = build_annotated_local_type(
                &contract.global_type,
                &contract.roles,
                role,
                &metadata,
            )?;
            roles.insert(role.clone(), RoleConformanceState::new(local, start_time));
        }

        Ok(Self {
            contract_name: contract.name.clone(),
            roles,
            history: Vec::new(),
        })
    }

    /// Return successful checks recorded so far.
    #[must_use]
    pub fn history(&self) -> &[ConformanceCheckRecord] {
        &self.history
    }

    /// Return the current expectation for one role, when the role exists.
    #[must_use]
    pub fn pending_expectation(&self, role: &RoleName) -> Option<ConformanceExpectation> {
        self.roles
            .get(role)
            .map(|state| state.current.expectation())
    }

    /// Return whether one role has reached protocol completion.
    #[must_use]
    pub fn is_role_complete(&self, role: &RoleName) -> bool {
        self.roles
            .get(role)
            .is_some_and(RoleConformanceState::is_complete)
    }

    /// Return whether all roles have reached protocol completion.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.roles.values().all(RoleConformanceState::is_complete)
    }

    /// Observe one role-local transition without attaching a timestamp.
    pub fn observe(
        &mut self,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        self.observe_at_inner(role, message, label, None)
    }

    /// Observe one role-local transition at a specific logical time.
    pub fn observe_at(
        &mut self,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
        now: Time,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        self.observe_at_inner(role, message, label, Some(now))
    }

    /// Observe one role-local transition using `Cx` time/logging facilities.
    pub fn observe_with_cx(
        &mut self,
        cx: &Cx,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        let now = cx.now();
        match self.observe_at(role, message, label, now) {
            Ok(record) => {
                trace_conformance_check(
                    cx,
                    &self.contract_name,
                    &record.role,
                    &record.path,
                    "ok",
                    &record.observed,
                );
                Ok(record)
            }
            Err(violation) => {
                let path = violation_path(violation.as_ref());
                let root_path = SessionPath::root();
                trace_conformance_check(
                    cx,
                    &self.contract_name,
                    role,
                    path.as_ref().unwrap_or(&root_path),
                    "violation",
                    &ConformanceObserved::from_inputs(message, label),
                );
                Err(violation)
            }
        }
    }

    /// Check whether any role timed out by `now`.
    pub fn check_timeout(&self, now: Time) -> Result<(), Box<ConformanceViolation>> {
        for (role, state) in &self.roles {
            if state.is_complete() {
                continue;
            }
            let Some(timeout) = state.current.timeout_budget() else {
                continue;
            };
            let elapsed_nanos = now.duration_since(state.entered_at);
            let timeout_nanos = duration_to_nanos(timeout);
            if elapsed_nanos > timeout_nanos {
                return Err(Box::new(ConformanceViolation::Timeout {
                    contract_name: self.contract_name.clone(),
                    role: role.clone(),
                    expected: state.current.expectation(),
                    elapsed: Duration::from_nanos(elapsed_nanos),
                    evidence: Box::new(state.current.violation_evidence(&self.contract_name, role)),
                }));
            }
        }
        Ok(())
    }

    fn observe_at_inner(
        &mut self,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
        now: Option<Time>,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        let contract_name = self.contract_name.clone();
        let observed = ConformanceObserved::from_inputs(message, label);
        let role_state = self.roles.get_mut(role).ok_or_else(|| {
            Box::new(ConformanceViolation::UnknownRole {
                contract_name: contract_name.clone(),
                role: role.clone(),
            })
        })?;
        if role_state.is_complete() {
            return Err(Box::new(ConformanceViolation::AlreadyComplete {
                contract_name,
                role: role.clone(),
                observed,
            }));
        }

        check_observation_timeout(role_state, &contract_name, role, now)?;

        let request = ObserveRequest {
            contract_name: &contract_name,
            role,
            message,
            label,
            observed: &observed,
            observed_at: now,
        };

        let record = match role_state.current.clone() {
            AnnotatedLocalType::Send {
                path,
                metadata,
                message: expected_message,
                next,
            } => observe_message_step(
                role_state,
                &request,
                MessageStepKind::Send,
                path,
                metadata,
                &expected_message,
                *next,
            )?,
            AnnotatedLocalType::Receive {
                path,
                metadata,
                message: expected_message,
                next,
            } => observe_message_step(
                role_state,
                &request,
                MessageStepKind::Receive,
                path,
                metadata,
                &expected_message,
                *next,
            )?,
            AnnotatedLocalType::Choice { branches } => {
                observe_branch_step(role_state, &request, BranchStepKind::Choice, &branches)?
            }
            AnnotatedLocalType::Branch { branches } => {
                observe_branch_step(role_state, &request, BranchStepKind::Observe, &branches)?
            }
            AnnotatedLocalType::End { .. }
            | AnnotatedLocalType::Recurse { .. }
            | AnnotatedLocalType::RecursePoint { .. } => {
                unreachable!("role state is normalized before runtime observation")
            }
        };

        self.history.push(record.clone());
        Ok(record)
    }
}

/// Thin wrapper that records conformance violations for lab-mode oracle checks.
#[derive(Debug, Clone)]
pub struct ConformanceOracle {
    monitor: ConformanceMonitor,
    violations: Vec<ConformanceViolation>,
}

impl ConformanceOracle {
    /// Build an oracle from a validated protocol contract.
    pub fn new(contract: &ProtocolContract) -> Result<Self, ConformanceMonitorInitError> {
        Self::new_at(contract, Time::ZERO)
    }

    /// Build an oracle with an explicit activation time.
    pub fn new_at(
        contract: &ProtocolContract,
        start_time: Time,
    ) -> Result<Self, ConformanceMonitorInitError> {
        Ok(Self {
            monitor: ConformanceMonitor::new_at(contract, start_time)?,
            violations: Vec::new(),
        })
    }

    /// Borrow the underlying conformance monitor.
    #[must_use]
    pub fn monitor(&self) -> &ConformanceMonitor {
        &self.monitor
    }

    /// Return all violations observed so far.
    #[must_use]
    pub fn violations(&self) -> &[ConformanceViolation] {
        &self.violations
    }

    /// Observe one transition without an explicit timestamp.
    pub fn observe(
        &mut self,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        match self.monitor.observe(role, message, label) {
            Ok(record) => Ok(record),
            Err(violation) => {
                self.violations.push((*violation).clone());
                Err(violation)
            }
        }
    }

    /// Observe one transition at a specific logical time.
    pub fn observe_at(
        &mut self,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
        now: Time,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        match self.monitor.observe_at(role, message, label, now) {
            Ok(record) => Ok(record),
            Err(violation) => {
                self.violations.push((*violation).clone());
                Err(violation)
            }
        }
    }

    /// Observe one transition using `Cx` time/logging facilities.
    pub fn observe_with_cx(
        &mut self,
        cx: &Cx,
        role: &RoleName,
        message: Option<&MessageType>,
        label: Option<&Label>,
    ) -> Result<ConformanceCheckRecord, Box<ConformanceViolation>> {
        match self.monitor.observe_with_cx(cx, role, message, label) {
            Ok(record) => Ok(record),
            Err(violation) => {
                self.violations.push((*violation).clone());
                Err(violation)
            }
        }
    }

    /// Check for timeout violations at a specific logical time.
    pub fn check_timeout(&mut self, now: Time) -> Result<(), Box<ConformanceViolation>> {
        match self.monitor.check_timeout(now) {
            Ok(()) => Ok(()),
            Err(violation) => {
                self.violations.push((*violation).clone());
                Err(violation)
            }
        }
    }

    /// Check the monitor against the current `LabRuntime` virtual time.
    pub fn check_lab(&mut self, runtime: &LabRuntime) -> Result<(), Box<ConformanceViolation>> {
        self.check_timeout(runtime.now())
    }
}

fn violation_path(violation: &ConformanceViolation) -> Option<SessionPath> {
    match violation {
        ConformanceViolation::UnexpectedObservation { evidence, .. }
        | ConformanceViolation::Timeout { evidence, .. } => evidence
            .path
            .clone()
            .or_else(|| evidence.candidate_paths.first().cloned()),
        ConformanceViolation::UnknownRole { .. } | ConformanceViolation::AlreadyComplete { .. } => {
            None
        }
    }
}

fn trace_conformance_check(
    cx: &Cx,
    contract_name: &str,
    role: &RoleName,
    path: &SessionPath,
    outcome: &str,
    observed: &ConformanceObserved,
) {
    let role_name = role.to_string();
    let path_value = path.to_string();
    let message_name = observed
        .message
        .as_ref()
        .map_or("-", |message| message.name.as_str());
    let label_name = observed.label.as_ref().map_or("-", Label::as_str);
    let fields = [
        ("event", "conformance_check"),
        ("contract", contract_name),
        ("role", role_name.as_str()),
        ("path", path_value.as_str()),
        ("outcome", outcome),
        ("message", message_name),
        ("label", label_name),
    ];
    cx.trace_with_fields("conformance_check", &fields);
}

fn join_labels(labels: &[Label]) -> String {
    labels
        .iter()
        .map(Label::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn duration_to_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::super::contract::TimeoutOverride;
    use super::*;
    use crate::trace::{TraceBufferHandle, TraceData, TraceEventKind};
    use crate::types::{Budget, RegionId, TaskId};
    use crate::util::ArenaIndex;
    use franken_kernel::SchemaVersion;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn path(segments: &[&str]) -> SessionPath {
        let mut path = SessionPath::root();
        for segment in segments {
            path = path.child(*segment);
        }
        path
    }

    fn test_cx_with_trace() -> (Cx, TraceBufferHandle) {
        let cx = Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        );
        let trace = TraceBufferHandle::new(32);
        cx.set_trace_buffer(trace.clone());
        (cx, trace)
    }

    fn request_reply_contract() -> ProtocolContract {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        ProtocolContract::new(
            "user_lookup",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        )
    }

    fn reservation_handoff_contract() -> ProtocolContract {
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");
        let granted = MessageType::new("granted", steward.clone(), caller.clone(), "Lease");
        let denied = MessageType::new("denied", steward.clone(), caller.clone(), "Denied");
        let handoff = MessageType::new("handoff", caller.clone(), steward.clone(), "Delegate");

        ProtocolContract::new(
            "reservation_handoff",
            SchemaVersion::new(1, 0, 1),
            vec![caller.clone(), steward.clone()],
            GlobalSessionType::new(SessionType::send(
                reserve,
                SessionType::branch(
                    steward,
                    vec![
                        super::super::contract::SessionBranch::new(
                            "granted",
                            SessionType::receive(
                                granted,
                                SessionType::send(handoff, SessionType::End),
                            ),
                        ),
                        super::super::contract::SessionBranch::new(
                            "denied",
                            SessionType::receive(denied, SessionType::End),
                        ),
                    ],
                ),
            )),
        )
    }

    fn compensating_request_reply_contract() -> ProtocolContract {
        let mut contract = request_reply_contract();
        contract.timeout_law.default_timeout = Some(Duration::from_secs(1));
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            path(&["send:get_user", "receive:user"]),
            Duration::from_secs(2),
        ));
        contract
            .compensation_paths
            .push(super::super::contract::CompensationPath::new(
                "rollback-request",
                path(&["send:get_user"]),
                vec![path(&["send:get_user", "receive:user", "end"])],
            ));
        contract
    }

    #[test]
    fn valid_trace_is_accepted_and_roles_complete() {
        init_test("valid_trace_is_accepted_and_roles_complete");
        let contract = request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        let mut monitor = ConformanceMonitor::new(&contract).expect("monitor");
        let request_send = monitor
            .observe(&client, Some(&request), None)
            .expect("client send request");
        assert_eq!(request_send.path, path(&["send:get_user"]));
        assert_eq!(
            request_send.expectation,
            ConformanceExpectation::Send {
                message: request.clone()
            }
        );

        monitor
            .observe(&server, Some(&request), None)
            .expect("server receive request");
        monitor
            .observe(&server, Some(&response), None)
            .expect("server send response");
        monitor
            .observe(&client, Some(&response), None)
            .expect("client receive response");

        assert!(monitor.is_role_complete(&client));
        assert!(monitor.is_role_complete(&server));
        assert!(monitor.is_complete());
        assert_eq!(monitor.history().len(), 4);

        crate::test_complete!("valid_trace_is_accepted_and_roles_complete");
    }

    #[test]
    fn invalid_branch_is_rejected_with_candidate_paths() {
        init_test("invalid_branch_is_rejected_with_candidate_paths");
        let contract = reservation_handoff_contract();
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");

        let mut monitor = ConformanceMonitor::new(&contract).expect("monitor");
        monitor
            .observe(&caller, Some(&reserve), None)
            .expect("caller send reserve");
        monitor
            .observe(&steward, Some(&reserve), None)
            .expect("steward receive reserve");

        let err = monitor
            .observe(&caller, None, Some(&Label::from("queued")))
            .expect_err("unexpected label should fail");
        assert!(
            matches!(
                err.as_ref(),
                ConformanceViolation::UnexpectedObservation { .. }
            ),
            "unexpected violation: {err:?}"
        );
        if let ConformanceViolation::UnexpectedObservation {
            expected, evidence, ..
        } = err.as_ref()
        {
            assert_eq!(
                expected,
                &ConformanceExpectation::ObserveBranch {
                    labels: vec![Label::from("granted"), Label::from("denied")],
                }
            );
            assert_eq!(
                evidence.candidate_paths,
                vec![
                    path(&["send:reserve", "branch:steward:granted"]),
                    path(&["send:reserve", "branch:steward:denied"]),
                ]
            );
        }

        crate::test_complete!("invalid_branch_is_rejected_with_candidate_paths");
    }

    #[test]
    fn timeout_is_detected_from_timeout_law() {
        init_test("timeout_is_detected_from_timeout_law");
        let contract = compensating_request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");

        let mut monitor = ConformanceMonitor::new_at(&contract, Time::ZERO).expect("monitor");
        monitor
            .observe_at(&client, Some(&request), None, Time::ZERO)
            .expect("client request");

        let err = monitor
            .check_timeout(Time::from_secs(2))
            .expect_err("server receive should time out after 1s default");
        assert!(
            matches!(err.as_ref(), ConformanceViolation::Timeout { .. }),
            "unexpected violation: {err:?}"
        );
        if let ConformanceViolation::Timeout {
            role,
            expected,
            evidence,
            ..
        } = err.as_ref()
        {
            assert_eq!(role, &server);
            assert_eq!(
                expected,
                &ConformanceExpectation::Receive { message: request }
            );
            assert_eq!(evidence.path, Some(path(&["send:get_user"])));
            assert_eq!(evidence.timeout, Some(Duration::from_secs(1)));
        }

        crate::test_complete!("timeout_is_detected_from_timeout_law");
    }

    #[test]
    fn compensation_paths_are_emitted_in_violation_evidence() {
        init_test("compensation_paths_are_emitted_in_violation_evidence");
        let contract = compensating_request_reply_contract();
        let monitor = ConformanceMonitor::new(&contract).expect("monitor");

        let err = monitor
            .check_timeout(Time::from_secs(2))
            .expect_err("initial send should time out");
        assert!(
            matches!(err.as_ref(), ConformanceViolation::Timeout { .. }),
            "unexpected violation: {err:?}"
        );
        if let ConformanceViolation::Timeout { evidence, .. } = err.as_ref() {
            assert_eq!(evidence.path, Some(path(&["send:get_user"])));
            assert!(
                evidence
                    .compensation_paths
                    .iter()
                    .any(|branch| branch.name == "rollback-request"),
                "expected rollback-request compensation in evidence"
            );
        }

        crate::test_complete!("compensation_paths_are_emitted_in_violation_evidence");
    }

    #[test]
    fn lab_runtime_oracle_reports_timeout() {
        init_test("lab_runtime_oracle_reports_timeout");
        let contract = compensating_request_reply_contract();
        let mut runtime = LabRuntime::with_seed(7);
        let mut oracle = ConformanceOracle::new_at(&contract, runtime.now()).expect("oracle");

        runtime.advance_time(1_500_000_000);
        let err = oracle
            .check_lab(&runtime)
            .expect_err("oracle should report timeout");
        assert!(matches!(err.as_ref(), ConformanceViolation::Timeout { .. }));
        assert_eq!(oracle.violations().len(), 1);

        crate::test_complete!("lab_runtime_oracle_reports_timeout");
    }

    #[test]
    fn observe_with_cx_logs_conformance_check_event() {
        init_test("observe_with_cx_logs_conformance_check_event");
        let contract = request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server, "GetUser");

        let (cx, trace) = test_cx_with_trace();
        let mut monitor = ConformanceMonitor::new(&contract).expect("monitor");
        monitor
            .observe_with_cx(&cx, &client, Some(&request), None)
            .expect("logged check");

        let saw_conformance_event = trace.snapshot().iter().any(|event| {
            event.kind == TraceEventKind::UserTrace
                && matches!(&event.data, TraceData::Message(message) if message == "conformance_check")
        });
        assert!(
            saw_conformance_event,
            "expected conformance_check trace event"
        );

        crate::test_complete!("observe_with_cx_logs_conformance_check_event");
    }

    #[test]
    fn degenerate_recurse_to_self_does_not_loop() {
        init_test("degenerate_recurse_to_self_does_not_loop");
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        // Build a contract whose body is RecursePoint("L", Recurse("L"))
        // — a degenerate empty loop.  This passes validation but previously
        // caused normalize() to spin forever.
        let request = MessageType::new("ping", client.clone(), server.clone(), "Ping");
        let contract = ProtocolContract::new(
            "degenerate",
            SchemaVersion::new(0, 0, 1),
            vec![client.clone(), server.clone()],
            GlobalSessionType::new(SessionType::send(
                request.clone(),
                SessionType::recurse_point("L", SessionType::recurse("L")),
            )),
        );
        // Construction must not hang.
        let monitor = ConformanceMonitor::new(&contract).expect("monitor should not loop");
        // After the first send, both roles should reach a synthetic End
        // because the degenerate recursion is treated as completion.
        let mut monitor = monitor;
        monitor
            .observe(&client, Some(&request), None)
            .expect("client send");
        assert!(
            monitor.is_role_complete(&client),
            "client should be complete after degenerate recursion resolves to End"
        );
        crate::test_complete!("degenerate_recurse_to_self_does_not_loop");
    }
}
