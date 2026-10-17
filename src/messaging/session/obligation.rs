//! Mechanical obligation derivation for session-typed protocol contracts.

use super::contract::{
    CompensationPath, CutoffPath, MessageType, ProtocolContract, ProtocolContractValidationError,
    SessionBranch, SessionPath, SessionType,
};
use crate::obligation::ledger::{ObligationLedger, ObligationToken};
use crate::record::{ObligationKind, SourceLocation};
use crate::types::{RegionId, TaskId, Time};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

/// Semantic class of a mechanically derived protocol obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DerivedObligationClass {
    /// A send step expects one or more reciprocal receives later in the flow.
    Reply,
    /// A protocol step is governed by an explicit timeout budget.
    Timeout,
    /// A saga-style compensation path must remain available after a trigger.
    Compensation,
    /// A graceful cutoff path must remain available after a trigger.
    Cutoff,
}

impl DerivedObligationClass {
    /// Map the semantic class onto the runtime's concrete ledger categories.
    #[must_use]
    pub const fn ledger_kind(self) -> ObligationKind {
        match self {
            Self::Reply => ObligationKind::Ack,
            Self::Timeout => ObligationKind::Lease,
            Self::Compensation | Self::Cutoff => ObligationKind::SendPermit,
        }
    }

    /// Stable lowercase name for diagnostics and serialization-adjacent output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::Timeout => "timeout",
            Self::Compensation => "compensation",
            Self::Cutoff => "cutoff",
        }
    }
}

impl fmt::Display for DerivedObligationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One obligation derived mechanically from a protocol contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedObligation {
    /// Stable obligation name.
    pub name: String,
    /// Semantic class of obligation.
    pub class: DerivedObligationClass,
    /// Protocol step that activates the obligation.
    pub trigger: SessionPath,
    /// Protocol steps that satisfy or advance the obligation.
    pub steps: Vec<SessionPath>,
    /// Timeout budget attached to the obligation, when applicable.
    pub timeout: Option<Duration>,
    /// Message that activated the obligation, when applicable.
    pub message: Option<MessageType>,
}

impl DerivedObligation {
    fn reply(trigger: SessionPath, message: MessageType, steps: Vec<SessionPath>) -> Self {
        Self {
            name: format!("reply:{}@{trigger}", message.name),
            class: DerivedObligationClass::Reply,
            trigger,
            steps,
            timeout: None,
            message: Some(message),
        }
    }

    fn timeout(trigger: SessionPath, timeout: Duration) -> Self {
        Self {
            name: format!("timeout@{trigger}"),
            class: DerivedObligationClass::Timeout,
            trigger: trigger.clone(),
            steps: vec![trigger],
            timeout: Some(timeout),
            message: None,
        }
    }

    fn compensation(path: &CompensationPath) -> Self {
        Self {
            name: format!("compensation:{}@{}", path.name, path.trigger),
            class: DerivedObligationClass::Compensation,
            trigger: path.trigger.clone(),
            steps: path.path.clone(),
            timeout: None,
            message: None,
        }
    }

    fn cutoff(path: &CutoffPath) -> Self {
        Self {
            name: format!("cutoff:{}@{}", path.name, path.trigger),
            class: DerivedObligationClass::Cutoff,
            trigger: path.trigger.clone(),
            steps: path.path.clone(),
            timeout: None,
            message: None,
        }
    }

    /// Runtime ledger kind used when materializing this obligation.
    #[must_use]
    pub const fn ledger_kind(&self) -> ObligationKind {
        self.class.ledger_kind()
    }

    /// Deterministic description carried into the runtime obligation ledger.
    #[must_use]
    pub fn description(&self) -> String {
        let mut description = format!("{} obligation triggered at {}", self.class, self.trigger);
        if let Some(message) = &self.message {
            write!(
                description,
                " for {}->{}:{}",
                message.sender, message.receiver, message.name
            )
            .expect("writing to String must succeed");
        }
        if let Some(timeout) = self.timeout {
            write!(description, " with timeout={}ms", timeout.as_millis())
                .expect("writing to String must succeed");
        }
        if !self.steps.is_empty() {
            let steps = self
                .steps
                .iter()
                .map(SessionPath::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            write!(description, " steps=[{steps}]").expect("writing to String must succeed");
        }
        description
    }

    /// Reserve the obligation in the runtime ledger.
    pub fn reserve_in_ledger(
        &self,
        ledger: &mut ObligationLedger,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> ObligationToken {
        let token = ledger.acquire_with_context(
            self.ledger_kind(),
            holder,
            region,
            now,
            SourceLocation::unknown(),
            None,
            Some(self.description()),
        );
        debug_assert_eq!(token.kind(), self.ledger_kind());
        token
    }
}

/// Full mechanical obligation inventory for one protocol contract.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DerivedObligations {
    /// Name of the source contract.
    pub contract_name: String,
    /// Deterministically ordered derived obligations.
    pub obligations: Vec<DerivedObligation>,
}

impl DerivedObligations {
    /// Validate a contract and derive its runtime obligation inventory.
    pub fn from_contract(
        contract: &ProtocolContract,
    ) -> Result<Self, ProtocolContractValidationError> {
        contract.validate()?;

        let mut obligations = Vec::new();
        collect_reply_obligations(
            &contract.global_type.root,
            &SessionPath::root(),
            &mut obligations,
        );
        obligations.extend(derive_timeout_obligations(contract));
        obligations.extend(
            contract
                .compensation_paths
                .iter()
                .map(DerivedObligation::compensation),
        );
        obligations.extend(contract.cutoff_paths.iter().map(DerivedObligation::cutoff));
        obligations.sort_by(|left, right| {
            (
                left.class,
                &left.trigger,
                &left.name,
                &left.steps,
                left.timeout,
                &left.message,
            )
                .cmp(&(
                    right.class,
                    &right.trigger,
                    &right.name,
                    &right.steps,
                    right.timeout,
                    &right.message,
                ))
        });

        Ok(Self {
            contract_name: contract.name.clone(),
            obligations,
        })
    }

    /// Reserve every derived obligation in the runtime ledger with a shared
    /// holder/region binding.
    pub fn reserve_all_in_ledger(
        &self,
        ledger: &mut ObligationLedger,
        holder: TaskId,
        region: RegionId,
        now: Time,
    ) -> Vec<ObligationToken> {
        self.obligations
            .iter()
            .map(|obligation| obligation.reserve_in_ledger(ledger, holder, region, now))
            .collect()
    }
}

fn derive_timeout_obligations(contract: &ProtocolContract) -> Vec<DerivedObligation> {
    let mut timeouts = BTreeMap::new();

    if let Some(default_timeout) = contract.timeout_law.default_timeout {
        for path in contract
            .global_type
            .paths()
            .into_iter()
            .filter(is_default_timeout_path)
        {
            timeouts.insert(path, default_timeout);
        }
    }

    for override_rule in &contract.timeout_law.per_step {
        timeouts.insert(override_rule.path.clone(), override_rule.timeout);
    }

    timeouts
        .into_iter()
        .map(|(path, timeout)| DerivedObligation::timeout(path, timeout))
        .collect()
}

fn is_default_timeout_path(path: &SessionPath) -> bool {
    path.segments().last().is_some_and(|segment| {
        segment.starts_with("send:")
            || segment.starts_with("receive:")
            || segment.starts_with("choice:")
            || segment.starts_with("branch:")
    })
}

fn collect_reply_obligations(
    session: &SessionType,
    base: &SessionPath,
    obligations: &mut Vec<DerivedObligation>,
) {
    match session {
        SessionType::Send { message, next } => {
            let here = base.child(format!("send:{}", message.name));
            let mut reply_steps = BTreeSet::new();
            collect_reciprocal_receives(next, &here, message, &mut reply_steps);
            if !reply_steps.is_empty() {
                obligations.push(DerivedObligation::reply(
                    here.clone(),
                    message.clone(),
                    reply_steps.into_iter().collect(),
                ));
            }
            collect_reply_obligations(next, &here, obligations);
        }
        SessionType::Receive { message, next } => {
            let here = base.child(format!("receive:{}", message.name));
            collect_reply_obligations(next, &here, obligations);
        }
        SessionType::Choice { decider, branches } => {
            collect_branch_reply_obligations(
                branches,
                base,
                |label| format!("choice:{decider}:{label}"),
                obligations,
            );
        }
        SessionType::Branch { offerer, branches } => {
            collect_branch_reply_obligations(
                branches,
                base,
                |label| format!("branch:{offerer}:{label}"),
                obligations,
            );
        }
        SessionType::RecursePoint { label, body } => {
            let here = base.child(format!("recurse-point:{label}"));
            collect_reply_obligations(body, &here, obligations);
        }
        SessionType::Recurse { .. } | SessionType::End => {}
    }
}

fn collect_branch_reply_obligations<F>(
    branches: &[SessionBranch],
    base: &SessionPath,
    segment: F,
    obligations: &mut Vec<DerivedObligation>,
) where
    F: Fn(&str) -> String,
{
    for branch in branches {
        let here = base.child(segment(branch.label.as_str()));
        collect_reply_obligations(&branch.continuation, &here, obligations);
    }
}

fn collect_reciprocal_receives(
    session: &SessionType,
    base: &SessionPath,
    sent: &MessageType,
    steps: &mut BTreeSet<SessionPath>,
) {
    match session {
        SessionType::Send { message, next } => {
            let here = base.child(format!("send:{}", message.name));
            collect_reciprocal_receives(next, &here, sent, steps);
        }
        SessionType::Receive { message, next } => {
            let here = base.child(format!("receive:{}", message.name));
            if message.sender == sent.receiver && message.receiver == sent.sender {
                steps.insert(here.clone());
            }
            collect_reciprocal_receives(next, &here, sent, steps);
        }
        SessionType::Choice { decider, branches } => {
            for branch in branches {
                let here = base.child(format!("choice:{decider}:{}", branch.label));
                collect_reciprocal_receives(&branch.continuation, &here, sent, steps);
            }
        }
        SessionType::Branch { offerer, branches } => {
            for branch in branches {
                let here = base.child(format!("branch:{offerer}:{}", branch.label));
                collect_reciprocal_receives(&branch.continuation, &here, sent, steps);
            }
        }
        SessionType::RecursePoint { label, body } => {
            let here = base.child(format!("recurse-point:{label}"));
            collect_reciprocal_receives(body, &here, sent, steps);
        }
        SessionType::Recurse { .. } | SessionType::End => {}
    }
}

#[cfg(test)]
#[path = "obligation_inline_tests.rs"]
mod tests;
