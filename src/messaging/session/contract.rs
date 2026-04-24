//! Session-typed protocol contracts for FABRIC's service/session lane.
//!
//! The contract surface here is intentionally structural: it captures a
//! two-party protocol as a global session grammar plus the evidence, timeout,
//! compensation, and cutoff metadata that later FABRIC layers will project
//! into local types, obligations, and conformance monitors.

use franken_kernel::SchemaVersion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;
use thiserror::Error;

/// Participant role name in a protocol contract.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    /// Construct a role name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow the underlying role name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(&self) -> bool {
        is_symbolic_identifier(self.as_str())
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for RoleName {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for RoleName {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Branch or recursion label in a protocol grammar.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Label(String);

impl Label {
    /// Construct a label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    /// Borrow the underlying label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(&self) -> bool {
        is_symbolic_identifier(self.as_str())
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Label {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Label {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Address of a protocol transition inside the session tree.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionPath(Vec<String>);

impl SessionPath {
    /// Root of a contract's global session tree.
    #[must_use]
    pub fn root() -> Self {
        Self(vec!["root".to_owned()])
    }

    /// Return a new path extended with one segment.
    #[must_use]
    pub fn child(&self, segment: impl Into<String>) -> Self {
        let mut segments = self.0.clone();
        segments.push(segment.into());
        Self(segments)
    }

    /// Borrow the path segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for SessionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.join("/"))
    }
}

/// Message-shape descriptor used by session steps.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MessageType {
    /// Stable message name.
    pub name: String,
    /// Sender role for this transition.
    pub sender: RoleName,
    /// Receiver role for this transition.
    pub receiver: RoleName,
    /// Named payload schema or record type.
    pub payload_schema: String,
}

impl MessageType {
    /// Construct a message descriptor.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        sender: impl Into<RoleName>,
        receiver: impl Into<RoleName>,
        payload_schema: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            sender: sender.into(),
            receiver: receiver.into(),
            payload_schema: payload_schema.into(),
        }
    }
}

/// One labeled branch in a choice or branch node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBranch {
    /// Branch label.
    pub label: Label,
    /// Continuation for the labeled branch.
    pub continuation: SessionType,
}

impl SessionBranch {
    /// Construct a branch.
    #[must_use]
    pub fn new(label: impl Into<Label>, continuation: SessionType) -> Self {
        Self {
            label: label.into(),
            continuation,
        }
    }
}

/// Global session grammar for a two-party protocol contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionType {
    /// The next step is a send transition.
    Send {
        /// Message emitted at this step.
        message: MessageType,
        /// Continuation after the send.
        next: Box<Self>,
    },
    /// The next step is a receive transition.
    Receive {
        /// Message consumed at this step.
        message: MessageType,
        /// Continuation after the receive.
        next: Box<Self>,
    },
    /// The local decider chooses one labeled continuation.
    Choice {
        /// Role that decides which branch to take.
        decider: RoleName,
        /// Available labeled continuations.
        branches: Vec<SessionBranch>,
    },
    /// The peer offers a labeled branch to this endpoint.
    Branch {
        /// Role that offers the branches.
        offerer: RoleName,
        /// Available labeled continuations.
        branches: Vec<SessionBranch>,
    },
    /// Jump to the nearest matching recursion point.
    Recurse {
        /// Recursion label being revisited.
        label: Label,
    },
    /// Define a recursion point and its body.
    RecursePoint {
        /// Recursion label bound by this node.
        label: Label,
        /// Recursive protocol body.
        body: Box<Self>,
    },
    /// End of the protocol.
    #[default]
    End,
}

impl SessionType {
    /// Construct a send step.
    #[must_use]
    pub fn send(message: MessageType, next: Self) -> Self {
        Self::Send {
            message,
            next: Box::new(next),
        }
    }

    /// Construct a receive step.
    #[must_use]
    pub fn receive(message: MessageType, next: Self) -> Self {
        Self::Receive {
            message,
            next: Box::new(next),
        }
    }

    /// Construct a choice step.
    #[must_use]
    pub fn choice(decider: impl Into<RoleName>, branches: Vec<SessionBranch>) -> Self {
        Self::Choice {
            decider: decider.into(),
            branches,
        }
    }

    /// Construct a branch step.
    #[must_use]
    pub fn branch(offerer: impl Into<RoleName>, branches: Vec<SessionBranch>) -> Self {
        Self::Branch {
            offerer: offerer.into(),
            branches,
        }
    }

    /// Construct a recursion jump.
    #[must_use]
    pub fn recurse(label: impl Into<Label>) -> Self {
        Self::Recurse {
            label: label.into(),
        }
    }

    /// Construct a recursion point.
    #[must_use]
    pub fn recurse_point(label: impl Into<Label>, body: Self) -> Self {
        Self::RecursePoint {
            label: label.into(),
            body: Box::new(body),
        }
    }

    /// Return true when this grammar contains no transitions.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::End)
    }

    fn collect_paths(&self, base: &SessionPath, paths: &mut BTreeSet<SessionPath>) {
        paths.insert(base.clone());
        match self {
            Self::Send { message, next } => {
                let here = base.child(format!("send:{}", message.name));
                paths.insert(here.clone());
                next.collect_paths(&here, paths);
            }
            Self::Receive { message, next } => {
                let here = base.child(format!("receive:{}", message.name));
                paths.insert(here.clone());
                next.collect_paths(&here, paths);
            }
            Self::Choice { decider, branches } => {
                for branch in branches {
                    let here = base.child(format!("choice:{decider}:{}", branch.label));
                    paths.insert(here.clone());
                    branch.continuation.collect_paths(&here, paths);
                }
            }
            Self::Branch { offerer, branches } => {
                for branch in branches {
                    let here = base.child(format!("branch:{offerer}:{}", branch.label));
                    paths.insert(here.clone());
                    branch.continuation.collect_paths(&here, paths);
                }
            }
            Self::Recurse { label } => {
                paths.insert(base.child(format!("recurse:{label}")));
            }
            Self::RecursePoint { label, body } => {
                let here = base.child(format!("recurse-point:{label}"));
                paths.insert(here.clone());
                body.collect_paths(&here, paths);
            }
            Self::End => {
                paths.insert(base.child("end"));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate(
        &self,
        roles: &[RoleName],
        base: &SessionPath,
        active_labels: &mut Vec<Label>,
    ) -> Result<(), ProtocolContractValidationError> {
        match self {
            Self::Send { message, next } => {
                validate_message(message, roles)?;
                next.validate(
                    roles,
                    &base.child(format!("send:{}", message.name)),
                    active_labels,
                )
            }
            Self::Receive { message, next } => {
                validate_message(message, roles)?;
                next.validate(
                    roles,
                    &base.child(format!("receive:{}", message.name)),
                    active_labels,
                )
            }
            Self::Choice { decider, branches } => {
                if !decider.is_valid() {
                    return Err(ProtocolContractValidationError::InvalidRoleName(
                        decider.clone(),
                    ));
                }
                if !roles.contains(decider) {
                    return Err(ProtocolContractValidationError::UnknownRole {
                        context: format!("choice at `{base}`"),
                        role: decider.clone(),
                    });
                }
                if branches.is_empty() {
                    return Err(ProtocolContractValidationError::ChoiceWithoutBranches {
                        path: base.clone(),
                    });
                }

                let mut labels = BTreeSet::new();
                for branch in branches {
                    if !branch.label.is_valid() {
                        return Err(ProtocolContractValidationError::InvalidLabel(
                            branch.label.clone(),
                        ));
                    }
                    if !labels.insert(branch.label.clone()) {
                        return Err(ProtocolContractValidationError::DuplicateBranchLabel {
                            path: base.clone(),
                            label: branch.label.clone(),
                        });
                    }
                    branch.continuation.validate(
                        roles,
                        &base.child(format!("choice:{decider}:{}", branch.label)),
                        active_labels,
                    )?;
                }
                Ok(())
            }
            Self::Branch { offerer, branches } => {
                if !offerer.is_valid() {
                    return Err(ProtocolContractValidationError::InvalidRoleName(
                        offerer.clone(),
                    ));
                }
                if !roles.contains(offerer) {
                    return Err(ProtocolContractValidationError::UnknownRole {
                        context: format!("branch at `{base}`"),
                        role: offerer.clone(),
                    });
                }
                if branches.is_empty() {
                    return Err(ProtocolContractValidationError::BranchWithoutBranches {
                        path: base.clone(),
                    });
                }

                let mut labels = BTreeSet::new();
                for branch in branches {
                    if !branch.label.is_valid() {
                        return Err(ProtocolContractValidationError::InvalidLabel(
                            branch.label.clone(),
                        ));
                    }
                    if !labels.insert(branch.label.clone()) {
                        return Err(ProtocolContractValidationError::DuplicateBranchLabel {
                            path: base.clone(),
                            label: branch.label.clone(),
                        });
                    }
                    branch.continuation.validate(
                        roles,
                        &base.child(format!("branch:{offerer}:{}", branch.label)),
                        active_labels,
                    )?;
                }
                Ok(())
            }
            Self::Recurse { label } => {
                if !label.is_valid() {
                    return Err(ProtocolContractValidationError::InvalidLabel(label.clone()));
                }
                if !active_labels.contains(label) {
                    return Err(ProtocolContractValidationError::UndefinedRecursionLabel {
                        path: base.clone(),
                        label: label.clone(),
                    });
                }
                Ok(())
            }
            Self::RecursePoint { label, body } => {
                if !label.is_valid() {
                    return Err(ProtocolContractValidationError::InvalidLabel(label.clone()));
                }
                if active_labels.contains(label) {
                    return Err(ProtocolContractValidationError::DuplicateRecursionLabel {
                        path: base.clone(),
                        label: label.clone(),
                    });
                }
                active_labels.push(label.clone());
                let result = body.validate(
                    roles,
                    &base.child(format!("recurse-point:{label}")),
                    active_labels,
                );
                active_labels.pop();
                result
            }
            Self::End => Ok(()),
        }
    }
}

/// Wrapper for the global session grammar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GlobalSessionType {
    /// Root of the global session tree.
    pub root: SessionType,
}

impl GlobalSessionType {
    /// Construct a global session grammar.
    #[must_use]
    pub fn new(root: SessionType) -> Self {
        Self { root }
    }

    /// Collect deterministic path addresses for all reachable transitions.
    #[must_use]
    pub fn paths(&self) -> BTreeSet<SessionPath> {
        let mut paths = BTreeSet::new();
        self.root.collect_paths(&SessionPath::root(), &mut paths);
        paths
    }
}

/// Transition marked as evidence-material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCheckpoint {
    /// Human-readable checkpoint name.
    pub name: String,
    /// Path of the material transition.
    pub path: SessionPath,
}

impl EvidenceCheckpoint {
    /// Construct an evidence checkpoint.
    #[must_use]
    pub fn new(name: impl Into<String>, path: SessionPath) -> Self {
        Self {
            name: name.into(),
            path,
        }
    }
}

/// Per-step timeout policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TimeoutLaw {
    /// Optional default timeout applied to every step.
    pub default_timeout: Option<Duration>,
    /// Step-specific overrides keyed by session path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_step: Vec<TimeoutOverride>,
}

/// Timeout override for one transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutOverride {
    /// Transition receiving the override.
    pub path: SessionPath,
    /// Timeout budget for the transition.
    pub timeout: Duration,
}

impl TimeoutOverride {
    /// Construct a timeout override.
    #[must_use]
    pub fn new(path: SessionPath, timeout: Duration) -> Self {
        Self { path, timeout }
    }
}

/// Saga-style compensation path anchored to a protocol transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompensationPath {
    /// Human-readable compensation path name.
    pub name: String,
    /// Transition that activates the compensation path.
    pub trigger: SessionPath,
    /// Ordered compensation transitions.
    pub path: Vec<SessionPath>,
}

impl CompensationPath {
    /// Construct a compensation path.
    #[must_use]
    pub fn new(name: impl Into<String>, trigger: SessionPath, path: Vec<SessionPath>) -> Self {
        Self {
            name: name.into(),
            trigger,
            path,
        }
    }
}

/// Graceful termination path anchored to a protocol transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutoffPath {
    /// Human-readable cutoff path name.
    pub name: String,
    /// Transition that starts the graceful cutoff.
    pub trigger: SessionPath,
    /// Ordered cutoff transitions.
    pub path: Vec<SessionPath>,
}

impl CutoffPath {
    /// Construct a cutoff path.
    #[must_use]
    pub fn new(name: impl Into<String>, trigger: SessionPath, path: Vec<SessionPath>) -> Self {
        Self {
            name: name.into(),
            trigger,
            path,
        }
    }
}

/// Session-typed protocol contract for a FABRIC interaction boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolContract {
    /// Human-readable protocol name.
    pub name: String,
    /// Contract schema version.
    pub version: SchemaVersion,
    /// Declared participant roles.
    pub roles: Vec<RoleName>,
    /// Global session grammar.
    pub global_type: GlobalSessionType,
    /// Evidence-material transitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_checkpoints: Vec<EvidenceCheckpoint>,
    /// Timeout policy over the session graph.
    #[serde(default)]
    pub timeout_law: TimeoutLaw,
    /// Compensation paths for saga-style recovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compensation_paths: Vec<CompensationPath>,
    /// Graceful cutoff paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cutoff_paths: Vec<CutoffPath>,
}

impl ProtocolContract {
    /// Construct a contract with empty evidence/recovery metadata.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: SchemaVersion,
        roles: Vec<RoleName>,
        global_type: GlobalSessionType,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            roles,
            global_type,
            evidence_checkpoints: Vec::new(),
            timeout_law: TimeoutLaw::default(),
            compensation_paths: Vec::new(),
            cutoff_paths: Vec::new(),
        }
    }

    /// Validate the contract.
    pub fn validate(&self) -> Result<(), ProtocolContractValidationError> {
        if self.name.trim().is_empty() {
            return Err(ProtocolContractValidationError::EmptyContractName);
        }
        if self.roles.len() != 2 {
            return Err(ProtocolContractValidationError::UnsupportedRoleCount {
                actual: self.roles.len(),
            });
        }

        let mut roles = BTreeSet::new();
        for role in &self.roles {
            if !role.is_valid() {
                return Err(ProtocolContractValidationError::InvalidRoleName(
                    role.clone(),
                ));
            }
            if !roles.insert(role.clone()) {
                return Err(ProtocolContractValidationError::DuplicateRole(role.clone()));
            }
        }

        if self.global_type.root.is_terminal() {
            return Err(ProtocolContractValidationError::EmptyProtocol);
        }

        let mut active_labels = Vec::new();
        self.global_type
            .root
            .validate(&self.roles, &SessionPath::root(), &mut active_labels)?;

        let valid_paths = self.global_type.paths();

        let mut checkpoint_names = BTreeSet::new();
        for checkpoint in &self.evidence_checkpoints {
            if checkpoint.name.trim().is_empty() {
                return Err(ProtocolContractValidationError::EmptyEvidenceCheckpointName);
            }
            if !checkpoint_names.insert(checkpoint.name.clone()) {
                return Err(
                    ProtocolContractValidationError::DuplicateEvidenceCheckpointName(
                        checkpoint.name.clone(),
                    ),
                );
            }
            if !is_addressable_session_path(&checkpoint.path, &valid_paths) {
                return Err(ProtocolContractValidationError::UnknownEvidencePath {
                    name: checkpoint.name.clone(),
                    path: checkpoint.path.clone(),
                });
            }
        }

        if let Some(default_timeout) = self.timeout_law.default_timeout {
            if default_timeout.is_zero() {
                return Err(ProtocolContractValidationError::ZeroDefaultTimeout);
            }
        }

        let mut timeout_paths = BTreeSet::new();
        for override_rule in &self.timeout_law.per_step {
            if override_rule.timeout.is_zero() {
                return Err(ProtocolContractValidationError::ZeroTimeoutOverride {
                    path: override_rule.path.clone(),
                });
            }
            if !is_addressable_session_path(&override_rule.path, &valid_paths) {
                return Err(ProtocolContractValidationError::UnknownTimeoutPath {
                    path: override_rule.path.clone(),
                });
            }
            if !timeout_paths.insert(override_rule.path.clone()) {
                return Err(ProtocolContractValidationError::DuplicateTimeoutOverride {
                    path: override_rule.path.clone(),
                });
            }
        }

        validate_recovery_paths(&self.compensation_paths, &valid_paths)?;
        validate_cutoff_paths(&self.cutoff_paths, &valid_paths)?;

        let (left_local, right_local) = super::projection::project_pair(self)
            .map_err(|err| ProtocolContractValidationError::ProjectionInvariant(err.to_string()))?;
        if !super::projection::is_dual(&left_local, &right_local) {
            return Err(ProtocolContractValidationError::ProjectedRolesNotDual {
                left: self.roles[0].clone(),
                right: self.roles[1].clone(),
            });
        }

        Ok(())
    }

    /// Validate and return the contract for fluent construction.
    pub fn validated(self) -> Result<Self, ProtocolContractValidationError> {
        self.validate()?;
        Ok(self)
    }
}

/// Validation failures for protocol contracts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolContractValidationError {
    /// Contract names must not be empty.
    #[error("protocol contract name must not be empty")]
    EmptyContractName,
    /// The current FABRIC surface is intentionally limited to two parties.
    #[error("protocol contract must declare exactly two roles for now, got {actual}")]
    UnsupportedRoleCount {
        /// The actual role count found.
        actual: usize,
    },
    /// Role names must be symbolic identifiers.
    #[error("invalid role name `{0}`")]
    InvalidRoleName(RoleName),
    /// Duplicate roles are not allowed.
    #[error("duplicate role `{0}`")]
    DuplicateRole(RoleName),
    /// Message or branch references an undeclared role.
    #[error("{context} references undeclared role `{role}`")]
    UnknownRole {
        /// Description of where the unknown role was referenced.
        context: String,
        /// The undeclared role name.
        role: RoleName,
    },
    /// Empty message names are not allowed.
    #[error("message name must not be empty")]
    EmptyMessageName,
    /// Payload schemas must be named explicitly.
    #[error("message `{0}` must declare a payload schema")]
    EmptyPayloadSchema(String),
    /// Self-directed messages are not meaningful at the contract boundary.
    #[error("message `{message}` cannot send from and to the same role `{role}`")]
    SelfDirectedMessage {
        /// The message name with sender equal to receiver.
        message: String,
        /// The role that is both sender and receiver.
        role: RoleName,
    },
    /// The grammar must contain at least one transition.
    #[error("protocol contract must contain at least one non-terminal step")]
    EmptyProtocol,
    /// Choice nodes need at least one labeled continuation.
    #[error("choice at `{path}` must contain at least one branch")]
    ChoiceWithoutBranches {
        /// Session path of the empty choice node.
        path: SessionPath,
    },
    /// Branch nodes need at least one labeled continuation.
    #[error("branch at `{path}` must contain at least one branch")]
    BranchWithoutBranches {
        /// Session path of the empty branch node.
        path: SessionPath,
    },
    /// Labels must be symbolic identifiers.
    #[error("invalid label `{0}`")]
    InvalidLabel(Label),
    /// Duplicate labels inside a single choice/branch are not allowed.
    #[error("duplicate branch label `{label}` at `{path}`")]
    DuplicateBranchLabel {
        /// Session path where the duplicate was found.
        path: SessionPath,
        /// The duplicated label.
        label: Label,
    },
    /// Recursion labels must be unique within the active scope.
    #[error("duplicate recursion label `{label}` at `{path}`")]
    DuplicateRecursionLabel {
        /// Session path where the duplicate was found.
        path: SessionPath,
        /// The duplicated recursion label.
        label: Label,
    },
    /// Recursion references must target an active recursion point.
    #[error("undefined recursion label `{label}` at `{path}`")]
    UndefinedRecursionLabel {
        /// Session path where the undefined reference was found.
        path: SessionPath,
        /// The undefined recursion label.
        label: Label,
    },
    /// Evidence checkpoint names must be present.
    #[error("evidence checkpoint name must not be empty")]
    EmptyEvidenceCheckpointName,
    /// Evidence checkpoint names must be unique.
    #[error("duplicate evidence checkpoint `{0}`")]
    DuplicateEvidenceCheckpointName(String),
    /// Evidence checkpoints must point at a real transition.
    #[error("evidence checkpoint `{name}` references unknown path `{path}`")]
    UnknownEvidencePath {
        /// The evidence checkpoint name.
        name: String,
        /// The unresolvable session path.
        path: SessionPath,
    },
    /// Default timeouts must be positive when present.
    #[error("default timeout must be greater than zero")]
    ZeroDefaultTimeout,
    /// Per-step timeouts must be positive.
    #[error("timeout override at `{path}` must be greater than zero")]
    ZeroTimeoutOverride {
        /// The session path with the zero timeout.
        path: SessionPath,
    },
    /// Timeout overrides must point at a real transition.
    #[error("timeout override references unknown path `{path}`")]
    UnknownTimeoutPath {
        /// The unresolvable session path.
        path: SessionPath,
    },
    /// Timeout overrides must be unique per path.
    #[error("duplicate timeout override for `{path}`")]
    DuplicateTimeoutOverride {
        /// The duplicated session path.
        path: SessionPath,
    },
    /// Compensation path names must be present.
    #[error("compensation path name must not be empty")]
    EmptyCompensationPathName,
    /// Compensation paths must contain at least one step.
    #[error("compensation path `{name}` must contain at least one step")]
    EmptyCompensationSequence {
        /// The compensation path name.
        name: String,
    },
    /// Compensation triggers must exist in the session tree.
    #[error("compensation path `{name}` references unknown trigger `{path}`")]
    UnknownCompensationTrigger {
        /// The compensation path name.
        name: String,
        /// The unresolvable trigger path.
        path: SessionPath,
    },
    /// Compensation steps must exist in the session tree.
    #[error("compensation path `{name}` references unknown step `{path}`")]
    UnknownCompensationStep {
        /// The compensation path name.
        name: String,
        /// The unresolvable step path.
        path: SessionPath,
    },
    /// Compensation path names must be unique.
    #[error("duplicate compensation path `{0}`")]
    DuplicateCompensationPath(String),
    /// Compensation paths must progress forward along one ordered branch.
    #[error("compensation path `{name}` must stay ordered; `{path}` does not extend `{previous}`")]
    InvalidCompensationSequenceOrder {
        /// The compensation path name.
        name: String,
        /// The previous step in the declared recovery sequence.
        previous: SessionPath,
        /// The step that failed to extend the previous step.
        path: SessionPath,
    },
    /// Cutoff path names must be present.
    #[error("cutoff path name must not be empty")]
    EmptyCutoffPathName,
    /// Cutoff paths must contain at least one step.
    #[error("cutoff path `{name}` must contain at least one step")]
    EmptyCutoffSequence {
        /// The cutoff path name.
        name: String,
    },
    /// Cutoff triggers must exist in the session tree.
    #[error("cutoff path `{name}` references unknown trigger `{path}`")]
    UnknownCutoffTrigger {
        /// The cutoff path name.
        name: String,
        /// The unresolvable trigger path.
        path: SessionPath,
    },
    /// Cutoff steps must exist in the session tree.
    #[error("cutoff path `{name}` references unknown step `{path}`")]
    UnknownCutoffStep {
        /// The cutoff path name.
        name: String,
        /// The unresolvable step path.
        path: SessionPath,
    },
    /// Cutoff path names must be unique.
    #[error("duplicate cutoff path `{0}`")]
    DuplicateCutoffPath(String),
    /// Cutoff paths must progress forward along one ordered branch.
    #[error("cutoff path `{name}` must stay ordered; `{path}` does not extend `{previous}`")]
    InvalidCutoffSequenceOrder {
        /// The cutoff path name.
        name: String,
        /// The previous step in the declared recovery sequence.
        previous: SessionPath,
        /// The step that failed to extend the previous step.
        path: SessionPath,
    },
    /// Projection should succeed once the structural contract checks are green.
    #[error("projection invariant failed: {0}")]
    ProjectionInvariant(String),
    /// Both projected local views must be dual for a valid two-party contract.
    #[error("projected local protocols for `{left}` and `{right}` are not dual")]
    ProjectedRolesNotDual {
        /// The first projected role.
        left: RoleName,
        /// The second projected role.
        right: RoleName,
    },
}

fn is_symbolic_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
}

fn validate_message(
    message: &MessageType,
    roles: &[RoleName],
) -> Result<(), ProtocolContractValidationError> {
    if message.name.trim().is_empty() {
        return Err(ProtocolContractValidationError::EmptyMessageName);
    }
    if !message.sender.is_valid() {
        return Err(ProtocolContractValidationError::InvalidRoleName(
            message.sender.clone(),
        ));
    }
    if !message.receiver.is_valid() {
        return Err(ProtocolContractValidationError::InvalidRoleName(
            message.receiver.clone(),
        ));
    }
    if !roles.contains(&message.sender) {
        return Err(ProtocolContractValidationError::UnknownRole {
            context: format!("message `{}` sender", message.name),
            role: message.sender.clone(),
        });
    }
    if !roles.contains(&message.receiver) {
        return Err(ProtocolContractValidationError::UnknownRole {
            context: format!("message `{}` receiver", message.name),
            role: message.receiver.clone(),
        });
    }
    if message.sender == message.receiver {
        return Err(ProtocolContractValidationError::SelfDirectedMessage {
            message: message.name.clone(),
            role: message.sender.clone(),
        });
    }
    if message.payload_schema.trim().is_empty() {
        return Err(ProtocolContractValidationError::EmptyPayloadSchema(
            message.name.clone(),
        ));
    }
    Ok(())
}

fn validate_recovery_paths(
    paths: &[CompensationPath],
    valid_paths: &BTreeSet<SessionPath>,
) -> Result<(), ProtocolContractValidationError> {
    let mut names = BTreeSet::new();
    for compensation in paths {
        if compensation.name.trim().is_empty() {
            return Err(ProtocolContractValidationError::EmptyCompensationPathName);
        }
        if !names.insert(compensation.name.clone()) {
            return Err(ProtocolContractValidationError::DuplicateCompensationPath(
                compensation.name.clone(),
            ));
        }
        if !is_addressable_session_path(&compensation.trigger, valid_paths) {
            return Err(
                ProtocolContractValidationError::UnknownCompensationTrigger {
                    name: compensation.name.clone(),
                    path: compensation.trigger.clone(),
                },
            );
        }
        if compensation.path.is_empty() {
            return Err(ProtocolContractValidationError::EmptyCompensationSequence {
                name: compensation.name.clone(),
            });
        }
        for step in &compensation.path {
            if !is_addressable_session_path(step, valid_paths) {
                return Err(ProtocolContractValidationError::UnknownCompensationStep {
                    name: compensation.name.clone(),
                    path: step.clone(),
                });
            }
        }
        if let Some((previous, path)) = first_unordered_recovery_step(&compensation.path) {
            return Err(
                ProtocolContractValidationError::InvalidCompensationSequenceOrder {
                    name: compensation.name.clone(),
                    previous,
                    path,
                },
            );
        }
    }
    Ok(())
}

fn validate_cutoff_paths(
    paths: &[CutoffPath],
    valid_paths: &BTreeSet<SessionPath>,
) -> Result<(), ProtocolContractValidationError> {
    let mut names = BTreeSet::new();
    for cutoff in paths {
        if cutoff.name.trim().is_empty() {
            return Err(ProtocolContractValidationError::EmptyCutoffPathName);
        }
        if !names.insert(cutoff.name.clone()) {
            return Err(ProtocolContractValidationError::DuplicateCutoffPath(
                cutoff.name.clone(),
            ));
        }
        if !is_addressable_session_path(&cutoff.trigger, valid_paths) {
            return Err(ProtocolContractValidationError::UnknownCutoffTrigger {
                name: cutoff.name.clone(),
                path: cutoff.trigger.clone(),
            });
        }
        if cutoff.path.is_empty() {
            return Err(ProtocolContractValidationError::EmptyCutoffSequence {
                name: cutoff.name.clone(),
            });
        }
        for step in &cutoff.path {
            if !is_addressable_session_path(step, valid_paths) {
                return Err(ProtocolContractValidationError::UnknownCutoffStep {
                    name: cutoff.name.clone(),
                    path: step.clone(),
                });
            }
        }
        if let Some((previous, path)) = first_unordered_recovery_step(&cutoff.path) {
            return Err(
                ProtocolContractValidationError::InvalidCutoffSequenceOrder {
                    name: cutoff.name.clone(),
                    previous,
                    path,
                },
            );
        }
    }
    Ok(())
}

fn is_addressable_session_path(path: &SessionPath, valid_paths: &BTreeSet<SessionPath>) -> bool {
    path != &SessionPath::root() && valid_paths.contains(path)
}

fn first_unordered_recovery_step(path: &[SessionPath]) -> Option<(SessionPath, SessionPath)> {
    path.windows(2).find_map(|window| {
        let [previous, next] = window else {
            return None;
        };
        (!is_strict_session_path_extension(previous, next))
            .then(|| (previous.clone(), next.clone()))
    })
}

fn is_strict_session_path_extension(previous: &SessionPath, next: &SessionPath) -> bool {
    next.segments().len() > previous.segments().len()
        && next.segments().starts_with(previous.segments())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn path(parts: &[&str]) -> SessionPath {
        let mut current = SessionPath::root();
        for part in parts {
            current = current.child(*part);
        }
        current
    }

    #[test]
    fn request_reply_contract_validates_and_roundtrips() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        let mut contract = ProtocolContract::new(
            "user_lookup",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.evidence_checkpoints.push(EvidenceCheckpoint::new(
            "request-enqueued",
            path(&["send:get_user"]),
        ));
        contract.timeout_law.default_timeout = Some(Duration::from_secs(5));
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            path(&["send:get_user", "receive:user"]),
            Duration::from_secs(2),
        ));
        contract.compensation_paths.push(CompensationPath::new(
            "cancel-request",
            path(&["send:get_user"]),
            vec![path(&["send:get_user", "receive:user", "end"])],
        ));
        contract.cutoff_paths.push(CutoffPath::new(
            "reply-cutoff",
            path(&["send:get_user", "receive:user"]),
            vec![path(&["send:get_user", "receive:user", "end"])],
        ));

        contract.validate().unwrap();

        let json = serde_json::to_string(&contract).unwrap();
        let decoded: ProtocolContract = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, contract);
    }

    #[test]
    fn streaming_protocol_with_choice_and_recursion_validates() {
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", producer.clone(), consumer.clone(), "Chunk");
        let close = MessageType::new("close", producer.clone(), consumer.clone(), "Close");

        let contract = ProtocolContract {
            name: "streaming".to_owned(),
            version: SchemaVersion::new(1, 1, 0),
            roles: vec![producer, consumer.clone()],
            global_type: GlobalSessionType::new(SessionType::send(
                open,
                SessionType::recurse_point(
                    "stream_loop",
                    SessionType::choice(
                        consumer,
                        vec![
                            SessionBranch::new(
                                "chunk",
                                SessionType::receive(chunk, SessionType::recurse("stream_loop")),
                            ),
                            SessionBranch::new(
                                "done",
                                SessionType::receive(close, SessionType::End),
                            ),
                        ],
                    ),
                ),
            )),
            evidence_checkpoints: vec![EvidenceCheckpoint::new(
                "chunk-ack",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
            )],
            timeout_law: TimeoutLaw {
                default_timeout: Some(Duration::from_secs(10)),
                per_step: vec![TimeoutOverride::new(
                    path(&[
                        "send:open_stream",
                        "recurse-point:stream_loop",
                        "choice:consumer:done",
                        "receive:close",
                    ]),
                    Duration::from_secs(1),
                )],
            },
            compensation_paths: vec![CompensationPath::new(
                "rollback-stream",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
                vec![path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                    "receive:close",
                    "end",
                ])],
            )],
            cutoff_paths: vec![CutoffPath::new(
                "graceful-stop",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                ]),
                vec![path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                    "receive:close",
                    "end",
                ])],
            )],
        };

        contract.validate().unwrap();
    }

    #[test]
    fn reservation_handoff_protocol_with_branch_validates() {
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");
        let granted = MessageType::new("granted", steward.clone(), caller.clone(), "Lease");
        let denied = MessageType::new("denied", steward.clone(), caller.clone(), "Denied");
        let handoff = MessageType::new("handoff", caller.clone(), steward.clone(), "Delegate");

        let contract = ProtocolContract::new(
            "reservation_handoff",
            SchemaVersion::new(1, 0, 1),
            vec![caller, steward.clone()],
            GlobalSessionType::new(SessionType::send(
                reserve,
                SessionType::branch(
                    steward,
                    vec![
                        SessionBranch::new(
                            "granted",
                            SessionType::receive(
                                granted,
                                SessionType::send(handoff, SessionType::End),
                            ),
                        ),
                        SessionBranch::new(
                            "denied",
                            SessionType::receive(denied, SessionType::End),
                        ),
                    ],
                ),
            )),
        );

        contract.validate().unwrap();
    }

    #[test]
    fn undefined_recursion_label_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");

        let contract = ProtocolContract::new(
            "bad_loop",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::recurse("missing_loop"),
            )),
        );

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UndefinedRecursionLabel {
                path: path(&["send:request"]),
                label: Label::from("missing_loop"),
            })
        );
    }

    #[test]
    fn unknown_evidence_path_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "bad_evidence",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract
            .evidence_checkpoints
            .push(EvidenceCheckpoint::new("missing", path(&["send:nope"])));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownEvidencePath {
                name: "missing".to_owned(),
                path: path(&["send:nope"]),
            })
        );
    }

    #[test]
    fn root_evidence_path_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_evidence",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract
            .evidence_checkpoints
            .push(EvidenceCheckpoint::new("root", SessionPath::root()));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownEvidencePath {
                name: "root".to_owned(),
                path: SessionPath::root(),
            })
        );
    }

    #[test]
    fn root_timeout_override_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_timeout",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            SessionPath::root(),
            Duration::from_secs(1),
        ));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownTimeoutPath {
                path: SessionPath::root(),
            })
        );
    }

    #[test]
    fn root_compensation_trigger_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_compensation",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.compensation_paths.push(CompensationPath::new(
            "rollback",
            SessionPath::root(),
            vec![path(&["send:request", "receive:response", "end"])],
        ));

        assert_eq!(
            contract.validate(),
            Err(
                ProtocolContractValidationError::UnknownCompensationTrigger {
                    name: "rollback".to_owned(),
                    path: SessionPath::root(),
                }
            )
        );
    }

    #[test]
    fn root_cutoff_step_is_rejected() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "root_cutoff",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.cutoff_paths.push(CutoffPath::new(
            "graceful",
            path(&["send:request"]),
            vec![SessionPath::root()],
        ));

        assert_eq!(
            contract.validate(),
            Err(ProtocolContractValidationError::UnknownCutoffStep {
                name: "graceful".to_owned(),
                path: SessionPath::root(),
            })
        );
    }

    #[test]
    fn compensation_path_must_progress_forward() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "unordered_compensation",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.compensation_paths.push(CompensationPath::new(
            "rollback",
            path(&["send:request"]),
            vec![
                path(&["send:request", "receive:response", "end"]),
                path(&["send:request", "receive:response"]),
            ],
        ));

        assert_eq!(
            contract.validate(),
            Err(
                ProtocolContractValidationError::InvalidCompensationSequenceOrder {
                    name: "rollback".to_owned(),
                    previous: path(&["send:request", "receive:response", "end"]),
                    path: path(&["send:request", "receive:response"]),
                }
            )
        );
    }

    #[test]
    fn cutoff_path_must_progress_forward() {
        let client = RoleName::from("client");
        let server = RoleName::from("server");
        let request = MessageType::new("request", client.clone(), server.clone(), "Req");
        let response = MessageType::new("response", server.clone(), client.clone(), "Resp");

        let mut contract = ProtocolContract::new(
            "unordered_cutoff",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.cutoff_paths.push(CutoffPath::new(
            "graceful",
            path(&["send:request"]),
            vec![
                path(&["send:request", "receive:response", "end"]),
                path(&["send:request", "receive:response"]),
            ],
        ));

        assert_eq!(
            contract.validate(),
            Err(
                ProtocolContractValidationError::InvalidCutoffSequenceOrder {
                    name: "graceful".to_owned(),
                    previous: path(&["send:request", "receive:response", "end"]),
                    path: path(&["send:request", "receive:response"]),
                }
            )
        );
    }
}
