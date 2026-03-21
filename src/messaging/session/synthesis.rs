//! Deterministic protocol-scaffolding synthesis for FABRIC sessions.

use super::contract::{
    CompensationPath, CutoffPath, Label, MessageType, ProtocolContract,
    ProtocolContractValidationError, RoleName, SessionPath, SessionType, TimeoutOverride,
};
use franken_kernel::SchemaVersion;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use thiserror::Error;

/// Synthesized, role-local scaffolding for one validated protocol contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedProtocolScaffold {
    /// Human-readable contract name.
    pub contract_name: String,
    /// Contract schema version.
    pub contract_version: SchemaVersion,
    /// Role-local handler scaffolds.
    pub handlers: Vec<SynthesizedRoleHandler>,
    /// Mechanically-derived transition and branch obligations.
    pub obligations: Vec<DerivedSessionObligation>,
}

impl SynthesizedProtocolScaffold {
    /// Return the synthesized handler for one role, when present.
    #[must_use]
    pub fn handler_for(&self, role: &RoleName) -> Option<&SynthesizedRoleHandler> {
        self.handlers.iter().find(|handler| &handler.role == role)
    }
}

/// Role-local scaffold produced from a validated session contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedRoleHandler {
    /// Role served by this scaffold.
    pub role: RoleName,
    /// Deterministic sequence/tree projection of the global contract.
    pub steps: Vec<SynthesizedHandlerStep>,
}

impl SynthesizedRoleHandler {
    /// Return the synthesized step at one path, when present.
    #[must_use]
    pub fn step(&self, path: &SessionPath) -> Option<&SynthesizedHandlerStep> {
        self.steps.iter().find(|step| &step.path == path)
    }
}

/// One role-local step in the synthesized scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedHandlerStep {
    /// Global path of the step inside the validated protocol tree.
    pub path: SessionPath,
    /// Role-local action taken at that path.
    pub action: SynthesizedAction,
    /// Obligations registered when the role reaches this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub register_obligations: Vec<String>,
    /// Obligations completed when the role reaches this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub complete_obligations: Vec<String>,
    /// Evidence checkpoints attached to this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_checkpoints: Vec<String>,
    /// Deterministic timeout/recovery branches attached to this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub error_branches: Vec<SynthesizedErrorBranch>,
}

/// Role-local action at one synthesized step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SynthesizedAction {
    /// Emit a message to the counterparty.
    Emit {
        /// Message emitted at this step.
        message: MessageType,
    },
    /// Consume a message from the counterparty.
    Consume {
        /// Message consumed at this step.
        message: MessageType,
    },
    /// Choose one labeled branch.
    ChooseBranch {
        /// Counterparty observing the branch choice.
        peer: RoleName,
        /// Branch label chosen at this step.
        label: Label,
    },
    /// Observe a counterparty branch choice.
    ObserveBranch {
        /// Counterparty controlling the branch choice.
        peer: RoleName,
        /// Branch label observed at this step.
        label: Label,
    },
    /// Enter a recursion point.
    EnterRecursion {
        /// Label of the recursion point.
        label: Label,
    },
    /// Jump back to a recursion point.
    RepeatRecursion {
        /// Label of the recursion target.
        label: Label,
    },
    /// Complete the protocol.
    Complete,
}

/// One mechanically-derived obligation attached to the synthesized scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedSessionObligation {
    /// Stable obligation identifier.
    pub id: String,
    /// Global protocol path that created the obligation.
    pub path: SessionPath,
    /// Semantic kind of the obligation.
    pub kind: DerivedSessionObligationKind,
    /// Role that registers the obligation.
    pub register_role: RoleName,
    /// Role that completes the obligation.
    pub complete_role: RoleName,
}

/// Semantic class of a synthesized session obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DerivedSessionObligationKind {
    /// Delivery/handling obligation for one message transition.
    Transition {
        /// Message carried by the obligation.
        message: MessageType,
    },
    /// Control obligation for one deterministic branch choice.
    BranchSelection {
        /// Branch label selected at this point.
        label: Label,
    },
}

/// Timeout or recovery branch attached to one synthesized handler step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedErrorBranch {
    /// Human-readable branch name.
    pub name: String,
    /// Deterministic branch semantics.
    pub kind: SynthesizedErrorBranchKind,
}

/// Deterministic timeout or recovery branch semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SynthesizedErrorBranchKind {
    /// Timeout branch attached to one protocol path.
    Timeout {
        /// Timeout budget enforced for the path.
        timeout: Duration,
    },
    /// Compensation branch or hook for saga-style recovery.
    Compensation {
        /// Whether the path triggers or participates in the recovery branch.
        stage: RecoveryHookStage,
        /// Ordered recovery path declared by the contract.
        recovery_path: Vec<SessionPath>,
    },
    /// Graceful cutoff branch or hook.
    Cutoff {
        /// Whether the path triggers or participates in the cutoff branch.
        stage: RecoveryHookStage,
        /// Ordered cutoff path declared by the contract.
        recovery_path: Vec<SessionPath>,
    },
}

/// Position of a synthesized recovery hook relative to a recovery path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHookStage {
    /// Path that activates the recovery branch.
    Trigger,
    /// Path that participates inside the recovery branch itself.
    Step,
}

/// Conservative adapter between two compatible protocol revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibleProtocolAdapter {
    /// Contract name shared by both revisions.
    pub contract_name: String,
    /// Previous contract version.
    pub from_version: SchemaVersion,
    /// Evolved contract version.
    pub to_version: SchemaVersion,
    /// Paths preserved exactly across both revisions.
    pub preserved_paths: Vec<SessionPath>,
    /// Additive branch labels introduced by the evolved revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_branches: Vec<AddedBranchPath>,
    /// Additional evidence checkpoints introduced by the evolved revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_evidence_checkpoints: Vec<String>,
    /// Additional timeout overrides introduced by the evolved revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_timeout_overrides: Vec<TimeoutOverride>,
    /// Additional compensation paths introduced by the evolved revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_compensation_paths: Vec<String>,
    /// Additional cutoff paths introduced by the evolved revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added_cutoff_paths: Vec<String>,
}

/// One additive branch path introduced by a compatible protocol evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddedBranchPath {
    /// Parent path of the choice or branch node.
    pub parent: SessionPath,
    /// Role controlling the new branch.
    pub controller: RoleName,
    /// Newly added branch label.
    pub label: Label,
}

/// Validation or synthesis failure for one protocol scaffold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolSynthesisError {
    /// The input contract failed validation.
    #[error(transparent)]
    InvalidContract(#[from] ProtocolContractValidationError),
}

/// Compatibility failure between two protocol revisions.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolEvolutionCompatibilityError {
    /// The previous contract failed validation.
    #[error("previous contract is invalid: {0}")]
    InvalidPrevious(ProtocolContractValidationError),
    /// The evolved contract failed validation.
    #[error("evolved contract is invalid: {0}")]
    InvalidNext(ProtocolContractValidationError),
    /// Compatible evolution requires the contract name to stay stable.
    #[error("contract name changed from `{previous}` to `{next}`")]
    ContractNameChanged {
        /// Previous contract name.
        previous: String,
        /// Evolved contract name.
        next: String,
    },
    /// Compatible evolution requires the declared role set to stay stable.
    #[error("role set changed between protocol revisions")]
    RoleSetChanged,
    /// Compatible evolution requires the default timeout to stay stable.
    #[error("default timeout changed between protocol revisions")]
    DefaultTimeoutChanged,
    /// Session node kind changed at one path.
    #[error("session kind changed at `{path}` from `{previous}` to `{next}`")]
    SessionKindChanged {
        /// Path where the grammar changed incompatibly.
        path: SessionPath,
        /// Previous node kind.
        previous: String,
        /// Evolved node kind.
        next: String,
    },
    /// Message shape changed incompatibly.
    #[error("message changed incompatibly at `{path}`")]
    MessageChanged {
        /// Path where the message changed.
        path: SessionPath,
    },
    /// Choice/branch controller changed incompatibly.
    #[error("branch controller changed incompatibly at `{path}`")]
    BranchControllerChanged {
        /// Path where the controller changed.
        path: SessionPath,
    },
    /// A branch label required by the previous revision disappeared.
    #[error("branch `{label}` disappeared at `{path}`")]
    MissingBranch {
        /// Path of the enclosing choice or branch node.
        path: SessionPath,
        /// Missing branch label.
        label: Label,
    },
    /// Recursion labels changed incompatibly.
    #[error("recursion label changed incompatibly at `{path}`")]
    RecursionLabelChanged {
        /// Path where the recursion label changed.
        path: SessionPath,
    },
    /// Evidence checkpoint removed from the evolved revision.
    #[error("evidence checkpoint `{name}` was removed")]
    RemovedEvidenceCheckpoint {
        /// Removed evidence checkpoint name.
        name: String,
    },
    /// Timeout override removed from the evolved revision.
    #[error("timeout override for `{path}` was removed")]
    RemovedTimeoutOverride {
        /// Removed timeout override path.
        path: SessionPath,
    },
    /// Compensation path removed from the evolved revision.
    #[error("compensation path `{name}` was removed")]
    RemovedCompensationPath {
        /// Removed compensation path name.
        name: String,
    },
    /// Cutoff path removed from the evolved revision.
    #[error("cutoff path `{name}` was removed")]
    RemovedCutoffPath {
        /// Removed cutoff path name.
        name: String,
    },
}

/// Backward-compatible alias while the session module re-export catches up.
pub type SynthesizedHandlerPlaceholder = SynthesizedProtocolScaffold;

/// Synthesize deterministic role-local scaffolding from one validated contract.
pub fn synthesize_protocol_scaffold(
    contract: &ProtocolContract,
) -> Result<SynthesizedProtocolScaffold, ProtocolSynthesisError> {
    contract.validate()?;

    let metadata = SynthesisMetadata::from_contract(contract);
    let mut scaffold = SynthesizedProtocolScaffold {
        contract_name: contract.name.clone(),
        contract_version: contract.version,
        handlers: contract
            .roles
            .iter()
            .cloned()
            .map(|role| SynthesizedRoleHandler {
                role,
                steps: Vec::new(),
            })
            .collect(),
        obligations: Vec::new(),
    };

    let mut builder = ScaffoldBuilder {
        roles: &contract.roles,
        metadata: &metadata,
        scaffold: &mut scaffold,
    };
    builder.walk(&contract.global_type.root, &SessionPath::root());

    Ok(scaffold)
}

/// Build a conservative adapter between two compatible protocol revisions.
pub fn adapt_protocol_evolution(
    previous: &ProtocolContract,
    next: &ProtocolContract,
) -> Result<CompatibleProtocolAdapter, ProtocolEvolutionCompatibilityError> {
    previous
        .validate()
        .map_err(ProtocolEvolutionCompatibilityError::InvalidPrevious)?;
    next.validate()
        .map_err(ProtocolEvolutionCompatibilityError::InvalidNext)?;

    if previous.name != next.name {
        return Err(ProtocolEvolutionCompatibilityError::ContractNameChanged {
            previous: previous.name.clone(),
            next: next.name.clone(),
        });
    }
    if previous.roles != next.roles {
        return Err(ProtocolEvolutionCompatibilityError::RoleSetChanged);
    }
    if previous.timeout_law.default_timeout != next.timeout_law.default_timeout {
        return Err(ProtocolEvolutionCompatibilityError::DefaultTimeoutChanged);
    }

    let mut adapter = CompatibleProtocolAdapter {
        contract_name: previous.name.clone(),
        from_version: previous.version,
        to_version: next.version,
        preserved_paths: previous.global_type.paths().into_iter().collect(),
        added_branches: Vec::new(),
        added_evidence_checkpoints: collect_added_evidence(previous, next)?,
        added_timeout_overrides: collect_added_timeouts(previous, next)?,
        added_compensation_paths: collect_added_compensation(previous, next)?,
        added_cutoff_paths: collect_added_cutoffs(previous, next)?,
    };

    compare_session_types(
        &previous.global_type.root,
        &next.global_type.root,
        &SessionPath::root(),
        &mut adapter,
    )?;

    Ok(adapter)
}

struct ScaffoldBuilder<'a> {
    roles: &'a [RoleName],
    metadata: &'a SynthesisMetadata,
    scaffold: &'a mut SynthesizedProtocolScaffold,
}

impl ScaffoldBuilder<'_> {
    fn walk(&mut self, session: &SessionType, base: &SessionPath) {
        match session {
            SessionType::Send { message, next } => {
                self.push_transition_step(base, "send", message, next);
            }
            SessionType::Receive { message, next } => {
                self.push_transition_step(base, "receive", message, next);
            }
            SessionType::Choice { decider, branches } => {
                self.push_branch_steps(base, decider, branches);
            }
            SessionType::Branch { offerer, branches } => {
                self.push_branch_steps(base, offerer, branches);
            }
            SessionType::RecursePoint { label, body } => {
                let path = base.child(format!("recurse-point:{label}"));
                for role in self.roles {
                    self.push_step(role, path.clone(), SynthesizedAction::EnterRecursion {
                        label: label.clone(),
                    });
                }
                self.walk(body, &path);
            }
            SessionType::Recurse { label } => {
                let path = base.child(format!("recurse:{label}"));
                for role in self.roles {
                    self.push_step(role, path.clone(), SynthesizedAction::RepeatRecursion {
                        label: label.clone(),
                    });
                }
            }
            SessionType::End => {
                let path = base.child("end");
                for role in self.roles {
                    self.push_step(role, path.clone(), SynthesizedAction::Complete);
                }
            }
        }
    }

    fn push_transition_step(
        &mut self,
        base: &SessionPath,
        prefix: &str,
        message: &MessageType,
        next: &SessionType,
    ) {
        let path = base.child(format!("{prefix}:{}", message.name));
        let obligation_id = format!("transition:{path}");
        self.scaffold.obligations.push(DerivedSessionObligation {
            id: obligation_id.clone(),
            path: path.clone(),
            kind: DerivedSessionObligationKind::Transition {
                message: message.clone(),
            },
            register_role: message.sender.clone(),
            complete_role: message.receiver.clone(),
        });

        self.push_step(
            &message.sender,
            path.clone(),
            SynthesizedAction::Emit {
                message: message.clone(),
            },
        );
        self.last_step_mut(&message.sender)
            .register_obligations
            .push(obligation_id.clone());

        self.push_step(
            &message.receiver,
            path.clone(),
            SynthesizedAction::Consume {
                message: message.clone(),
            },
        );
        self.last_step_mut(&message.receiver)
            .complete_obligations
            .push(obligation_id);

        self.walk(next, &path);
    }

    fn push_branch_steps(
        &mut self,
        base: &SessionPath,
        controller: &RoleName,
        branches: &[super::contract::SessionBranch],
    ) {
        let peer = self.peer(controller);
        for branch in branches {
            let path = branch_path(base, controller, &branch.label);
            let obligation_id = format!("branch:{path}");
            self.scaffold.obligations.push(DerivedSessionObligation {
                id: obligation_id.clone(),
                path: path.clone(),
                kind: DerivedSessionObligationKind::BranchSelection {
                    label: branch.label.clone(),
                },
                register_role: controller.clone(),
                complete_role: peer.clone(),
            });

            self.push_step(
                controller,
                path.clone(),
                SynthesizedAction::ChooseBranch {
                    peer: peer.clone(),
                    label: branch.label.clone(),
                },
            );
            self.last_step_mut(controller)
                .register_obligations
                .push(obligation_id.clone());

            self.push_step(
                &peer,
                path.clone(),
                SynthesizedAction::ObserveBranch {
                    peer: controller.clone(),
                    label: branch.label.clone(),
                },
            );
            self.last_step_mut(&peer)
                .complete_obligations
                .push(obligation_id);

            self.walk(&branch.continuation, &path);
        }
    }

    fn push_step(&mut self, role: &RoleName, path: SessionPath, action: SynthesizedAction) {
        let step = SynthesizedHandlerStep {
            evidence_checkpoints: self.metadata.evidence_for(&path),
            error_branches: self.metadata.error_branches_for(&path),
            path,
            action,
            register_obligations: Vec::new(),
            complete_obligations: Vec::new(),
        };
        self.handler_mut(role).steps.push(step);
    }

    fn peer(&self, role: &RoleName) -> RoleName {
        self.roles
            .iter()
            .find(|candidate| *candidate != role)
            .cloned()
            .unwrap_or_else(|| role.clone())
    }

    fn handler_mut(&mut self, role: &RoleName) -> &mut SynthesizedRoleHandler {
        self.scaffold
            .handlers
            .iter_mut()
            .find(|handler| &handler.role == role)
            .unwrap_or_else(|| unreachable!("validated contracts always synthesize declared roles"))
    }

    fn last_step_mut(&mut self, role: &RoleName) -> &mut SynthesizedHandlerStep {
        self.handler_mut(role)
            .steps
            .last_mut()
            .unwrap_or_else(|| unreachable!("step was just inserted"))
    }
}

struct SynthesisMetadata {
    default_timeout: Option<Duration>,
    timeout_overrides: BTreeMap<SessionPath, Duration>,
    evidence_by_path: BTreeMap<SessionPath, Vec<String>>,
    compensation_by_path: BTreeMap<SessionPath, Vec<SynthesizedErrorBranch>>,
    cutoff_by_path: BTreeMap<SessionPath, Vec<SynthesizedErrorBranch>>,
}

impl SynthesisMetadata {
    fn from_contract(contract: &ProtocolContract) -> Self {
        let timeout_overrides = contract
            .timeout_law
            .per_step
            .iter()
            .map(|override_rule| (override_rule.path.clone(), override_rule.timeout))
            .collect();
        let evidence_by_path = collect_named_paths(
            contract
                .evidence_checkpoints
                .iter()
                .map(|checkpoint| (&checkpoint.path, checkpoint.name.clone())),
        );
        let compensation_by_path = collect_recovery_paths(
            &contract.compensation_paths,
            SynthesizedErrorBranchKindBuilder::Compensation,
        );
        let cutoff_by_path = collect_recovery_paths(
            &contract.cutoff_paths,
            SynthesizedErrorBranchKindBuilder::Cutoff,
        );

        Self {
            default_timeout: contract.timeout_law.default_timeout,
            timeout_overrides,
            evidence_by_path,
            compensation_by_path,
            cutoff_by_path,
        }
    }

    fn evidence_for(&self, path: &SessionPath) -> Vec<String> {
        self.evidence_by_path.get(path).cloned().unwrap_or_default()
    }

    fn error_branches_for(&self, path: &SessionPath) -> Vec<SynthesizedErrorBranch> {
        let mut branches = Vec::new();
        if !path.ends_with("end")
            && let Some(timeout) = self.timeout_overrides.get(path).copied().or(self.default_timeout)
        {
            branches.push(SynthesizedErrorBranch {
                name: format!("timeout:{path}"),
                kind: SynthesizedErrorBranchKind::Timeout { timeout },
            });
        }
        if let Some(compensation) = self.compensation_by_path.get(path) {
            branches.extend(compensation.clone());
        }
        if let Some(cutoff) = self.cutoff_by_path.get(path) {
            branches.extend(cutoff.clone());
        }
        branches
    }
}

enum SynthesizedErrorBranchKindBuilder {
    Compensation,
    Cutoff,
}

fn collect_named_paths<I>(items: I) -> BTreeMap<SessionPath, Vec<String>>
where
    I: IntoIterator<Item = (SessionPathRef<'static>, String)>,
{
    let mut by_path = BTreeMap::new();
    for (path, name) in items {
        by_path
            .entry(path.to_owned())
            .or_insert_with(Vec::new)
            .push(name);
    }
    by_path
}

type SessionPathRef<'a> = &'a SessionPath;

fn collect_recovery_paths<T>(
    paths: &[T],
    kind_builder: SynthesizedErrorBranchKindBuilder,
) -> BTreeMap<SessionPath, Vec<SynthesizedErrorBranch>>
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
            RecoveryHookStage::Trigger,
            &kind_builder,
        );
        for step in path.recovery_path() {
            push_recovery_branch(
                &mut by_path,
                step,
                path.name(),
                path.recovery_path(),
                RecoveryHookStage::Step,
                &kind_builder,
            );
        }
    }
    by_path
}

fn push_recovery_branch(
    by_path: &mut BTreeMap<SessionPath, Vec<SynthesizedErrorBranch>>,
    path: &SessionPath,
    name: &str,
    recovery_path: &[SessionPath],
    stage: RecoveryHookStage,
    builder: &SynthesizedErrorBranchKindBuilder,
) {
    let kind = match builder {
        SynthesizedErrorBranchKindBuilder::Compensation => SynthesizedErrorBranchKind::Compensation {
            stage,
            recovery_path: recovery_path.to_vec(),
        },
        SynthesizedErrorBranchKindBuilder::Cutoff => SynthesizedErrorBranchKind::Cutoff {
            stage,
            recovery_path: recovery_path.to_vec(),
        },
    };
    by_path
        .entry(path.clone())
        .or_insert_with(Vec::new)
        .push(SynthesizedErrorBranch {
            name: name.to_owned(),
            kind,
        });
}

trait RecoveryPathLike {
    fn name(&self) -> &str;
    fn trigger(&self) -> &SessionPath;
    fn recovery_path(&self) -> &[SessionPath];
}

impl RecoveryPathLike for CompensationPath {
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

impl RecoveryPathLike for CutoffPath {
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

fn branch_path(base: &SessionPath, controller: &RoleName, label: &Label) -> SessionPath {
    let prefix = if base
        .segments()
        .last()
        .is_some_and(|segment| segment.starts_with("send:"))
    {
        "branch"
    } else {
        "choice"
    };
    base.child(format!("{prefix}:{controller}:{label}"))
}

fn compare_session_types(
    previous: &SessionType,
    next: &SessionType,
    base: &SessionPath,
    adapter: &mut CompatibleProtocolAdapter,
) -> Result<(), ProtocolEvolutionCompatibilityError> {
    match (previous, next) {
        (
            SessionType::Send {
                message: previous_message,
                next: previous_next,
            },
            SessionType::Send {
                message: next_message,
                next: next_next,
            },
        ) => {
            let path = base.child(format!("send:{}", previous_message.name));
            compare_messages(previous_message, next_message, &path)?;
            compare_session_types(previous_next, next_next, &path, adapter)
        }
        (
            SessionType::Receive {
                message: previous_message,
                next: previous_next,
            },
            SessionType::Receive {
                message: next_message,
                next: next_next,
            },
        ) => {
            let path = base.child(format!("receive:{}", previous_message.name));
            compare_messages(previous_message, next_message, &path)?;
            compare_session_types(previous_next, next_next, &path, adapter)
        }
        (
            SessionType::Choice {
                decider: previous_decider,
                branches: previous_branches,
            },
            SessionType::Choice {
                decider: next_decider,
                branches: next_branches,
            },
        ) => compare_branch_sets(
            previous_decider,
            next_decider,
            previous_branches,
            next_branches,
            base,
            adapter,
        ),
        (
            SessionType::Branch {
                offerer: previous_offerer,
                branches: previous_branches,
            },
            SessionType::Branch {
                offerer: next_offerer,
                branches: next_branches,
            },
        ) => compare_branch_sets(
            previous_offerer,
            next_offerer,
            previous_branches,
            next_branches,
            base,
            adapter,
        ),
        (
            SessionType::Recurse {
                label: previous_label,
            },
            SessionType::Recurse { label: next_label },
        ) => {
            if previous_label != next_label {
                return Err(ProtocolEvolutionCompatibilityError::RecursionLabelChanged {
                    path: base.clone(),
                });
            }
            Ok(())
        }
        (
            SessionType::RecursePoint {
                label: previous_label,
                body: previous_body,
            },
            SessionType::RecursePoint {
                label: next_label,
                body: next_body,
            },
        ) => {
            if previous_label != next_label {
                return Err(ProtocolEvolutionCompatibilityError::RecursionLabelChanged {
                    path: base.clone(),
                });
            }
            compare_session_types(
                previous_body,
                next_body,
                &base.child(format!("recurse-point:{previous_label}")),
                adapter,
            )
        }
        (SessionType::End, SessionType::End) => Ok(()),
        _ => Err(ProtocolEvolutionCompatibilityError::SessionKindChanged {
            path: base.clone(),
            previous: session_kind(previous).to_owned(),
            next: session_kind(next).to_owned(),
        }),
    }
}

fn compare_messages(
    previous: &MessageType,
    next: &MessageType,
    path: &SessionPath,
) -> Result<(), ProtocolEvolutionCompatibilityError> {
    if previous == next {
        Ok(())
    } else {
        Err(ProtocolEvolutionCompatibilityError::MessageChanged { path: path.clone() })
    }
}

fn compare_branch_sets(
    previous_controller: &RoleName,
    next_controller: &RoleName,
    previous_branches: &[super::contract::SessionBranch],
    next_branches: &[super::contract::SessionBranch],
    base: &SessionPath,
    adapter: &mut CompatibleProtocolAdapter,
) -> Result<(), ProtocolEvolutionCompatibilityError> {
    if previous_controller != next_controller {
        return Err(ProtocolEvolutionCompatibilityError::BranchControllerChanged {
            path: base.clone(),
        });
    }

    let next_by_label = next_branches
        .iter()
        .map(|branch| (branch.label.clone(), branch))
        .collect::<BTreeMap<_, _>>();

    for previous_branch in previous_branches {
        let Some(next_branch) = next_by_label.get(&previous_branch.label) else {
            return Err(ProtocolEvolutionCompatibilityError::MissingBranch {
                path: base.clone(),
                label: previous_branch.label.clone(),
            });
        };
        compare_session_types(
            &previous_branch.continuation,
            &next_branch.continuation,
            &branch_path(base, previous_controller, &previous_branch.label),
            adapter,
        )?;
    }

    for next_branch in next_branches {
        if previous_branches
            .iter()
            .all(|previous_branch| previous_branch.label != next_branch.label)
        {
            adapter.added_branches.push(AddedBranchPath {
                parent: base.clone(),
                controller: previous_controller.clone(),
                label: next_branch.label.clone(),
            });
        }
    }

    Ok(())
}

fn collect_added_evidence(
    previous: &ProtocolContract,
    next: &ProtocolContract,
) -> Result<Vec<String>, ProtocolEvolutionCompatibilityError> {
    for checkpoint in &previous.evidence_checkpoints {
        if !next.evidence_checkpoints.contains(checkpoint) {
            return Err(ProtocolEvolutionCompatibilityError::RemovedEvidenceCheckpoint {
                name: checkpoint.name.clone(),
            });
        }
    }
    Ok(next
        .evidence_checkpoints
        .iter()
        .filter(|checkpoint| !previous.evidence_checkpoints.contains(checkpoint))
        .map(|checkpoint| checkpoint.name.clone())
        .collect())
}

fn collect_added_timeouts(
    previous: &ProtocolContract,
    next: &ProtocolContract,
) -> Result<Vec<TimeoutOverride>, ProtocolEvolutionCompatibilityError> {
    for timeout in &previous.timeout_law.per_step {
        if !next.timeout_law.per_step.contains(timeout) {
            return Err(ProtocolEvolutionCompatibilityError::RemovedTimeoutOverride {
                path: timeout.path.clone(),
            });
        }
    }
    Ok(next
        .timeout_law
        .per_step
        .iter()
        .filter(|timeout| !previous.timeout_law.per_step.contains(timeout))
        .cloned()
        .collect())
}

fn collect_added_compensation(
    previous: &ProtocolContract,
    next: &ProtocolContract,
) -> Result<Vec<String>, ProtocolEvolutionCompatibilityError> {
    for path in &previous.compensation_paths {
        if !next.compensation_paths.contains(path) {
            return Err(ProtocolEvolutionCompatibilityError::RemovedCompensationPath {
                name: path.name.clone(),
            });
        }
    }
    Ok(next
        .compensation_paths
        .iter()
        .filter(|path| !previous.compensation_paths.contains(path))
        .map(|path| path.name.clone())
        .collect())
}

fn collect_added_cutoffs(
    previous: &ProtocolContract,
    next: &ProtocolContract,
) -> Result<Vec<String>, ProtocolEvolutionCompatibilityError> {
    for path in &previous.cutoff_paths {
        if !next.cutoff_paths.contains(path) {
            return Err(ProtocolEvolutionCompatibilityError::RemovedCutoffPath {
                name: path.name.clone(),
            });
        }
    }
    Ok(next
        .cutoff_paths
        .iter()
        .filter(|path| !previous.cutoff_paths.contains(path))
        .map(|path| path.name.clone())
        .collect())
}

fn session_kind(session: &SessionType) -> &'static str {
    match session {
        SessionType::Send { .. } => "send",
        SessionType::Receive { .. } => "receive",
        SessionType::Choice { .. } => "choice",
        SessionType::Branch { .. } => "branch",
        SessionType::Recurse { .. } => "recurse",
        SessionType::RecursePoint { .. } => "recurse_point",
        SessionType::End => "end",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::contract::{GlobalSessionType, SessionBranch};

    fn path(parts: &[&str]) -> SessionPath {
        let mut current = SessionPath::root();
        for part in parts {
            current = current.child(*part);
        }
        current
    }

    fn request_reply_contract() -> ProtocolContract {
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
        contract.timeout_law.default_timeout = Some(Duration::from_secs(5));
        contract.timeout_law.per_step.push(TimeoutOverride::new(
            path(&["send:get_user", "receive:user"]),
            Duration::from_secs(2),
        ));
        contract.evidence_checkpoints.push(super::super::contract::EvidenceCheckpoint::new(
            "request-enqueued",
            path(&["send:get_user"]),
        ));
        contract
    }

    fn streaming_contract() -> ProtocolContract {
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", producer.clone(), consumer.clone(), "Chunk");
        let close = MessageType::new("close", producer.clone(), consumer.clone(), "Close");

        ProtocolContract {
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
            evidence_checkpoints: vec![super::super::contract::EvidenceCheckpoint::new(
                "chunk-ack",
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
            )],
            timeout_law: super::super::contract::TimeoutLaw {
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
        }
    }

    fn reservation_handoff_contract(version: SchemaVersion) -> ProtocolContract {
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let reserve = MessageType::new("reserve", caller.clone(), steward.clone(), "Reserve");
        let granted = MessageType::new("granted", steward.clone(), caller.clone(), "Lease");
        let denied = MessageType::new("denied", steward.clone(), caller.clone(), "Denied");

        ProtocolContract::new(
            "reservation_handoff",
            version,
            vec![caller, steward.clone()],
            GlobalSessionType::new(SessionType::send(
                reserve,
                SessionType::branch(
                    steward,
                    vec![
                        SessionBranch::new(
                            "granted",
                            SessionType::receive(granted, SessionType::End),
                        ),
                        SessionBranch::new(
                            "denied",
                            SessionType::receive(denied, SessionType::End),
                        ),
                    ],
                ),
            )),
        )
    }

    #[test]
    fn synthesizes_request_reply_handler_scaffolds() {
        let contract = request_reply_contract();
        let scaffold = synthesize_protocol_scaffold(&contract).expect("synthesized");
        let client = RoleName::from("client");
        let server = RoleName::from("server");

        assert_eq!(scaffold.obligations.len(), 2);

        let client_handler = scaffold.handler_for(&client).expect("client handler");
        let request_path = path(&["send:get_user"]);
        let response_path = path(&["send:get_user", "receive:user"]);
        let request_step = client_handler.step(&request_path).expect("request step");
        let response_step = client_handler.step(&response_path).expect("response step");

        assert!(matches!(
            request_step.action,
            SynthesizedAction::Emit { .. }
        ));
        assert_eq!(
            request_step.register_obligations,
            vec!["transition:root/send:get_user".to_owned()]
        );
        assert_eq!(
            request_step.evidence_checkpoints,
            vec!["request-enqueued".to_owned()]
        );
        assert_eq!(request_step.error_branches.len(), 1);

        assert!(matches!(
            response_step.action,
            SynthesizedAction::Consume { .. }
        ));
        assert_eq!(
            response_step.complete_obligations,
            vec!["transition:root/send:get_user/receive:user".to_owned()]
        );
        assert_eq!(
            response_step.error_branches,
            vec![SynthesizedErrorBranch {
                name: "timeout:root/send:get_user/receive:user".to_owned(),
                kind: SynthesizedErrorBranchKind::Timeout {
                    timeout: Duration::from_secs(2),
                },
            }]
        );

        let server_handler = scaffold.handler_for(&server).expect("server handler");
        assert_eq!(
            server_handler
                .step(&request_path)
                .expect("server receive request")
                .complete_obligations,
            vec!["transition:root/send:get_user".to_owned()]
        );
        assert_eq!(
            server_handler
                .step(&response_path)
                .expect("server emit response")
                .register_obligations,
            vec!["transition:root/send:get_user/receive:user".to_owned()]
        );
    }

    #[test]
    fn synthesizes_streaming_protocol_with_error_branches() {
        let contract = streaming_contract();
        let scaffold = synthesize_protocol_scaffold(&contract).expect("synthesized");
        let consumer = RoleName::from("consumer");
        let handler = scaffold.handler_for(&consumer).expect("consumer handler");
        let chunk_choice_path = path(&[
            "send:open_stream",
            "recurse-point:stream_loop",
            "choice:consumer:chunk",
        ]);
        let chunk_receive_path = path(&[
            "send:open_stream",
            "recurse-point:stream_loop",
            "choice:consumer:chunk",
            "receive:chunk",
        ]);
        let done_choice_path = path(&[
            "send:open_stream",
            "recurse-point:stream_loop",
            "choice:consumer:done",
        ]);

        assert!(matches!(
            handler.step(&chunk_choice_path).expect("chunk choice").action,
            SynthesizedAction::ChooseBranch { .. }
        ));
        assert!(matches!(
            handler.step(&chunk_receive_path).expect("chunk receive").action,
            SynthesizedAction::Consume { .. }
        ));
        assert!(
            handler
                .step(&chunk_receive_path)
                .expect("chunk receive")
                .evidence_checkpoints
                .contains(&"chunk-ack".to_owned())
        );
        assert!(
            handler
                .step(&chunk_receive_path)
                .expect("chunk receive")
                .error_branches
                .iter()
                .any(|branch| matches!(
                    branch.kind,
                    SynthesizedErrorBranchKind::Compensation {
                        stage: RecoveryHookStage::Trigger,
                        ..
                    }
                ))
        );
        assert!(
            handler
                .step(&done_choice_path)
                .expect("done choice")
                .error_branches
                .iter()
                .any(|branch| matches!(
                    branch.kind,
                    SynthesizedErrorBranchKind::Cutoff {
                        stage: RecoveryHookStage::Trigger,
                        ..
                    }
                ))
        );
    }

    #[test]
    fn synthesizes_saga_compensation_hooks_from_recovery_paths() {
        let mut contract = request_reply_contract();
        contract.compensation_paths.push(CompensationPath::new(
            "rollback-request",
            path(&["send:get_user"]),
            vec![path(&["send:get_user", "receive:user", "end"])],
        ));

        let scaffold = synthesize_protocol_scaffold(&contract).expect("synthesized");
        let client_handler = scaffold
            .handler_for(&RoleName::from("client"))
            .expect("client handler");
        let request_step = client_handler
            .step(&path(&["send:get_user"]))
            .expect("request step");

        assert!(
            request_step.error_branches.iter().any(|branch| matches!(
                branch.kind,
                SynthesizedErrorBranchKind::Compensation {
                    stage: RecoveryHookStage::Trigger,
                    ..
                }
            ))
        );
    }

    #[test]
    fn evolved_protocol_adapter_accepts_added_branch_and_metadata() {
        let previous = reservation_handoff_contract(SchemaVersion::new(1, 0, 0));
        let mut next = reservation_handoff_contract(SchemaVersion::new(1, 1, 0));
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");
        let queued = MessageType::new("queued", steward.clone(), caller, "Queued");

        if let SessionType::Send { next, .. } = &mut next.global_type.root
            && let SessionType::Branch { branches, .. } = next.as_mut()
        {
            branches.push(SessionBranch::new(
                "queued",
                SessionType::receive(queued, SessionType::End),
            ));
        }
        next.evidence_checkpoints.push(super::super::contract::EvidenceCheckpoint::new(
            "reserve-sent",
            path(&["send:reserve"]),
        ));

        let adapter = adapt_protocol_evolution(&previous, &next).expect("compatible");

        assert_eq!(adapter.contract_name, "reservation_handoff");
        assert_eq!(
            adapter.added_branches,
            vec![AddedBranchPath {
                parent: path(&["send:reserve"]),
                controller: steward,
                label: Label::from("queued"),
            }]
        );
        assert_eq!(
            adapter.added_evidence_checkpoints,
            vec!["reserve-sent".to_owned()]
        );
    }
}
