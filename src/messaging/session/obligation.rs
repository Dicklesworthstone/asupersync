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
mod tests {
    use super::*;
    use crate::record::ObligationAbortReason;
    use crate::util::ArenaIndex;
    use franken_kernel::SchemaVersion;

    fn path(parts: &[&str]) -> SessionPath {
        let mut current = SessionPath::root();
        for part in parts {
            current = current.child(*part);
        }
        current
    }

    fn task_id(slot: u32) -> TaskId {
        TaskId::from_arena(ArenaIndex::new(slot, 0))
    }

    fn region_id(slot: u32) -> RegionId {
        RegionId::from_arena(ArenaIndex::new(slot, 0))
    }

    fn request_reply_contract() -> ProtocolContract {
        let client = super::super::contract::RoleName::from("client");
        let server = super::super::contract::RoleName::from("server");
        let request = MessageType::new("get_user", client.clone(), server.clone(), "GetUser");
        let response = MessageType::new("user", server.clone(), client.clone(), "UserRecord");

        let mut contract = ProtocolContract::new(
            "user_lookup",
            SchemaVersion::new(1, 0, 0),
            vec![client, server],
            super::super::contract::GlobalSessionType::new(SessionType::send(
                request,
                SessionType::receive(response, SessionType::End),
            )),
        );
        contract.timeout_law.default_timeout = Some(Duration::from_secs(5));
        contract
            .timeout_law
            .per_step
            .push(super::super::contract::TimeoutOverride::new(
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
        contract
    }

    fn streaming_contract() -> ProtocolContract {
        let producer = super::super::contract::RoleName::from("producer");
        let consumer = super::super::contract::RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", consumer.clone(), producer.clone(), "Chunk");
        let close = MessageType::new("close", consumer.clone(), producer.clone(), "Close");

        ProtocolContract {
            name: "streaming".to_owned(),
            version: SchemaVersion::new(1, 1, 0),
            roles: vec![producer.clone(), consumer.clone()],
            global_type: super::super::contract::GlobalSessionType::new(SessionType::send(
                open,
                SessionType::recurse_point(
                    "stream_loop",
                    SessionType::choice(
                        consumer.clone(),
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
            evidence_checkpoints: Vec::new(),
            timeout_law: super::super::contract::TimeoutLaw {
                default_timeout: Some(Duration::from_secs(10)),
                per_step: vec![super::super::contract::TimeoutOverride::new(
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

    #[test]
    fn derives_request_reply_timeout_and_recovery_obligations() {
        let derived = DerivedObligations::from_contract(&request_reply_contract())
            .expect("request/reply contract should derive");

        assert_eq!(derived.contract_name, "user_lookup");
        assert_eq!(derived.obligations.len(), 5);

        let reply = derived
            .obligations
            .iter()
            .find(|obligation| obligation.class == DerivedObligationClass::Reply)
            .expect("reply obligation should exist");
        assert_eq!(reply.ledger_kind(), ObligationKind::Ack);
        assert_eq!(reply.trigger, path(&["send:get_user"]));
        assert_eq!(reply.steps, vec![path(&["send:get_user", "receive:user"])]);
        assert_eq!(
            reply
                .message
                .as_ref()
                .expect("reply obligation keeps message")
                .name,
            "get_user"
        );

        let send_timeout = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Timeout
                    && obligation.trigger == path(&["send:get_user"])
            })
            .expect("default send timeout should exist");
        assert_eq!(send_timeout.timeout, Some(Duration::from_secs(5)));
        assert_eq!(send_timeout.ledger_kind(), ObligationKind::Lease);

        let receive_timeout = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Timeout
                    && obligation.trigger == path(&["send:get_user", "receive:user"])
            })
            .expect("receive override should exist");
        assert_eq!(receive_timeout.timeout, Some(Duration::from_secs(2)));

        let compensation = derived
            .obligations
            .iter()
            .find(|obligation| obligation.class == DerivedObligationClass::Compensation)
            .expect("compensation obligation should exist");
        assert_eq!(compensation.ledger_kind(), ObligationKind::SendPermit);
        assert_eq!(compensation.trigger, path(&["send:get_user"]));
        assert_eq!(
            compensation.steps,
            vec![path(&["send:get_user", "receive:user", "end"])]
        );

        let cutoff = derived
            .obligations
            .iter()
            .find(|obligation| obligation.class == DerivedObligationClass::Cutoff)
            .expect("cutoff obligation should exist");
        assert_eq!(cutoff.ledger_kind(), ObligationKind::SendPermit);
        assert_eq!(cutoff.trigger, path(&["send:get_user", "receive:user"]));
    }

    #[test]
    fn derives_streaming_reply_targets_and_saga_paths() {
        let derived = DerivedObligations::from_contract(&streaming_contract())
            .expect("streaming contract should derive");

        let reply = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Reply
                    && obligation.trigger == path(&["send:open_stream"])
            })
            .expect("open_stream should derive a reply obligation");
        assert_eq!(
            reply.steps,
            vec![
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:chunk",
                    "receive:chunk",
                ]),
                path(&[
                    "send:open_stream",
                    "recurse-point:stream_loop",
                    "choice:consumer:done",
                    "receive:close",
                ]),
            ]
        );

        let receive_close_timeout = derived
            .obligations
            .iter()
            .find(|obligation| {
                obligation.class == DerivedObligationClass::Timeout
                    && obligation.trigger
                        == path(&[
                            "send:open_stream",
                            "recurse-point:stream_loop",
                            "choice:consumer:done",
                            "receive:close",
                        ])
            })
            .expect("receive:close timeout should exist");
        assert_eq!(receive_close_timeout.timeout, Some(Duration::from_secs(1)));

        let compensation = derived
            .obligations
            .iter()
            .find(|obligation| obligation.name.starts_with("compensation:rollback-stream@"))
            .expect("stream compensation should exist");
        assert_eq!(
            compensation.trigger,
            path(&[
                "send:open_stream",
                "recurse-point:stream_loop",
                "choice:consumer:chunk",
                "receive:chunk",
            ])
        );

        let cutoff = derived
            .obligations
            .iter()
            .find(|obligation| obligation.name.starts_with("cutoff:graceful-stop@"))
            .expect("stream cutoff should exist");
        assert_eq!(
            cutoff.steps,
            vec![path(&[
                "send:open_stream",
                "recurse-point:stream_loop",
                "choice:consumer:done",
                "receive:close",
                "end",
            ])]
        );
    }

    #[test]
    fn derived_obligations_reserve_cleanly_in_runtime_ledger() {
        let derived = DerivedObligations::from_contract(&request_reply_contract())
            .expect("request/reply contract should derive");

        let mut ledger = ObligationLedger::new();
        let tokens = derived.reserve_all_in_ledger(
            &mut ledger,
            task_id(1),
            region_id(7),
            Time::from_nanos(0),
        );

        assert_eq!(tokens.len(), derived.obligations.len());
        assert_eq!(ledger.stats().pending, derived.obligations.len() as u64);
        assert!(
            tokens
                .iter()
                .zip(&derived.obligations)
                .all(|(token, obligation)| token.kind() == obligation.ledger_kind())
        );

        for (index, token) in tokens.into_iter().enumerate() {
            ledger.abort(
                token,
                Time::from_nanos((index + 1) as u64),
                ObligationAbortReason::Explicit,
            );
        }

        assert_eq!(ledger.stats().pending, 0);
        assert_eq!(
            ledger.stats().total_aborted,
            derived.obligations.len() as u64
        );
    }

    #[test]
    fn description_includes_message_timeout_and_steps() {
        let obligation = DerivedObligation {
            name: "reply:get_user@send:get_user".to_owned(),
            class: DerivedObligationClass::Reply,
            trigger: path(&["send:get_user"]),
            steps: vec![
                path(&["send:get_user", "receive:user"]),
                path(&["send:get_user", "receive:user", "end"]),
            ],
            timeout: Some(Duration::from_millis(1500)),
            message: Some(MessageType::new(
                "get_user",
                super::super::contract::RoleName::from("client"),
                super::super::contract::RoleName::from("server"),
                "GetUser",
            )),
        };

        let description = obligation.description();
        assert!(description.starts_with("reply obligation triggered at "));
        assert!(description.contains("for client->server:get_user"));
        assert!(description.contains("with timeout=1500ms"));
        assert!(description.contains("steps=["));
        assert!(description.contains("receive:user"));
        assert!(description.contains("end"));
    }
}
