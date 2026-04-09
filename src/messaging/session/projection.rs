//! Local session projection and duality checks for FABRIC protocol contracts.
//!
//! The contract layer models a protocol as a global session grammar shared by
//! both participants. This module projects that shared grammar into a local
//! view for one role and checks whether two projected local views are dual.

use super::contract::{
    GlobalSessionType, Label, MessageType, ProtocolContract, RoleName, SessionType,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One labeled branch in a projected local session type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSessionBranch {
    /// Branch label chosen or observed at this node.
    pub label: Label,
    /// Continuation for the labeled branch.
    pub continuation: LocalSessionType,
}

impl LocalSessionBranch {
    /// Construct a projected local branch.
    #[must_use]
    pub fn new(label: impl Into<Label>, continuation: LocalSessionType) -> Self {
        Self {
            label: label.into(),
            continuation,
        }
    }
}

/// Local view of a global session grammar for one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LocalSessionType {
    /// This role sends a message, then continues as `next`.
    Send {
        /// Message emitted by this role.
        message: MessageType,
        /// Continuation after the send.
        next: Box<Self>,
    },
    /// This role receives a message, then continues as `next`.
    Receive {
        /// Message consumed by this role.
        message: MessageType,
        /// Continuation after the receive.
        next: Box<Self>,
    },
    /// This role chooses one labeled continuation.
    Choice {
        /// Available labeled continuations.
        branches: Vec<LocalSessionBranch>,
    },
    /// The peer chooses one labeled continuation and this role must accept it.
    Branch {
        /// Available labeled continuations.
        branches: Vec<LocalSessionBranch>,
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
        /// Recursive local body.
        body: Box<Self>,
    },
    /// End of the projected protocol.
    #[default]
    End,
}

impl LocalSessionType {
    /// Construct a local send step.
    #[must_use]
    pub fn send(message: MessageType, next: Self) -> Self {
        Self::Send {
            message,
            next: Box::new(next),
        }
    }

    /// Construct a local receive step.
    #[must_use]
    pub fn receive(message: MessageType, next: Self) -> Self {
        Self::Receive {
            message,
            next: Box::new(next),
        }
    }

    /// Construct a local choice step.
    #[must_use]
    pub fn choice(branches: Vec<LocalSessionBranch>) -> Self {
        Self::Choice { branches }
    }

    /// Construct a local branch step.
    #[must_use]
    pub fn branch(branches: Vec<LocalSessionBranch>) -> Self {
        Self::Branch { branches }
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
}

/// Failures that can occur while projecting a global session grammar.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProjectionError {
    /// The current FABRIC projection layer is limited to two-party contracts.
    #[error("session projection requires exactly two roles, got {actual}")]
    UnsupportedRoleCount {
        /// The actual role count found.
        actual: usize,
    },
    /// The requested role was not declared by the contract.
    #[error("session projection references undeclared role `{0}`")]
    UnknownRole(RoleName),
}

/// Project a global session grammar into a local view for `role`.
pub fn project(
    global_type: &GlobalSessionType,
    roles: &[RoleName],
    role: &RoleName,
) -> Result<LocalSessionType, ProjectionError> {
    if roles.len() != 2 {
        return Err(ProjectionError::UnsupportedRoleCount {
            actual: roles.len(),
        });
    }
    if !roles.contains(role) {
        return Err(ProjectionError::UnknownRole(role.clone()));
    }
    project_session_type(&global_type.root, roles, role)
}

/// Project a two-party protocol contract into a local view for `role`.
pub fn project_contract(
    contract: &ProtocolContract,
    role: &RoleName,
) -> Result<LocalSessionType, ProjectionError> {
    project(&contract.global_type, &contract.roles, role)
}

/// Project both participant views for a two-party contract.
pub fn project_pair(
    contract: &ProtocolContract,
) -> Result<(LocalSessionType, LocalSessionType), ProjectionError> {
    let [left, right] = contract.roles.as_slice() else {
        return Err(ProjectionError::UnsupportedRoleCount {
            actual: contract.roles.len(),
        });
    };
    Ok((
        project(&contract.global_type, &contract.roles, left)?,
        project(&contract.global_type, &contract.roles, right)?,
    ))
}

/// Return whether two projected local session types are dual.
#[must_use]
pub fn is_dual(left: &LocalSessionType, right: &LocalSessionType) -> bool {
    match (left, right) {
        (
            LocalSessionType::Send {
                message: left_message,
                next: left_next,
            },
            LocalSessionType::Receive {
                message: right_message,
                next: right_next,
            },
        )
        | (
            LocalSessionType::Receive {
                message: left_message,
                next: left_next,
            },
            LocalSessionType::Send {
                message: right_message,
                next: right_next,
            },
        ) => left_message == right_message && is_dual(left_next, right_next),
        (
            LocalSessionType::Choice {
                branches: left_branches,
            },
            LocalSessionType::Branch {
                branches: right_branches,
            },
        )
        | (
            LocalSessionType::Branch {
                branches: left_branches,
            },
            LocalSessionType::Choice {
                branches: right_branches,
            },
        ) => branches_are_dual(left_branches, right_branches),
        (
            LocalSessionType::Recurse { label: left_label },
            LocalSessionType::Recurse { label: right_label },
        ) => left_label == right_label,
        (
            LocalSessionType::RecursePoint {
                label: left_label,
                body: left_body,
            },
            LocalSessionType::RecursePoint {
                label: right_label,
                body: right_body,
            },
        ) => left_label == right_label && is_dual(left_body, right_body),
        (LocalSessionType::End, LocalSessionType::End) => true,
        _ => false,
    }
}

fn project_session_type(
    session_type: &SessionType,
    roles: &[RoleName],
    role: &RoleName,
) -> Result<LocalSessionType, ProjectionError> {
    match session_type {
        SessionType::Send { message, next } | SessionType::Receive { message, next } => {
            project_message_step(message, next, role, roles)
        }
        SessionType::Choice { decider, branches } => {
            if !roles.contains(decider) {
                return Err(ProjectionError::UnknownRole(decider.clone()));
            }
            let branches = project_branches(branches, roles, role)?;
            if role == decider {
                Ok(LocalSessionType::choice(branches))
            } else {
                Ok(LocalSessionType::branch(branches))
            }
        }
        SessionType::Branch { offerer, branches } => {
            if !roles.contains(offerer) {
                return Err(ProjectionError::UnknownRole(offerer.clone()));
            }
            let branches = project_branches(branches, roles, role)?;
            if role == offerer {
                Ok(LocalSessionType::choice(branches))
            } else {
                Ok(LocalSessionType::branch(branches))
            }
        }
        SessionType::Recurse { label } => Ok(LocalSessionType::recurse(label.clone())),
        SessionType::RecursePoint { label, body } => Ok(LocalSessionType::recurse_point(
            label.clone(),
            project_session_type(body, roles, role)?,
        )),
        SessionType::End => Ok(LocalSessionType::End),
    }
}

fn project_message_step(
    message: &MessageType,
    next: &SessionType,
    role: &RoleName,
    roles: &[RoleName],
) -> Result<LocalSessionType, ProjectionError> {
    if !roles.contains(&message.sender) {
        return Err(ProjectionError::UnknownRole(message.sender.clone()));
    }
    if !roles.contains(&message.receiver) {
        return Err(ProjectionError::UnknownRole(message.receiver.clone()));
    }

    let next = project_session_type(next, roles, role)?;
    if role == &message.sender {
        Ok(LocalSessionType::send(message.clone(), next))
    } else if role == &message.receiver {
        Ok(LocalSessionType::receive(message.clone(), next))
    } else {
        Err(ProjectionError::UnknownRole(role.clone()))
    }
}

fn project_branches(
    branches: &[super::contract::SessionBranch],
    roles: &[RoleName],
    role: &RoleName,
) -> Result<Vec<LocalSessionBranch>, ProjectionError> {
    branches
        .iter()
        .map(|branch| {
            Ok(LocalSessionBranch::new(
                branch.label.clone(),
                project_session_type(&branch.continuation, roles, role)?,
            ))
        })
        .collect()
}

fn branches_are_dual(left: &[LocalSessionBranch], right: &[LocalSessionBranch]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter().all(|left_branch| {
        right
            .iter()
            .find(|candidate| candidate.label == left_branch.label)
            .is_some_and(|right_branch| {
                is_dual(&left_branch.continuation, &right_branch.continuation)
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_kernel::SchemaVersion;

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

    fn streaming_contract() -> ProtocolContract {
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");
        let open = MessageType::new("open_stream", producer.clone(), consumer.clone(), "Open");
        let chunk = MessageType::new("chunk", producer.clone(), consumer.clone(), "Chunk");
        let close = MessageType::new("close", producer.clone(), consumer.clone(), "Close");

        ProtocolContract::new(
            "streaming",
            SchemaVersion::new(1, 1, 0),
            vec![producer, consumer.clone()],
            GlobalSessionType::new(SessionType::send(
                open,
                SessionType::recurse_point(
                    "stream_loop",
                    SessionType::choice(
                        consumer,
                        vec![
                            super::super::contract::SessionBranch::new(
                                "chunk",
                                SessionType::receive(chunk, SessionType::recurse("stream_loop")),
                            ),
                            super::super::contract::SessionBranch::new(
                                "done",
                                SessionType::receive(close, SessionType::End),
                            ),
                        ],
                    ),
                ),
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
            vec![caller, steward.clone()],
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

    #[test]
    fn request_reply_projection_is_dual() {
        let contract = request_reply_contract();
        let client = RoleName::from("client");
        let server = RoleName::from("server");

        let client_local = project_contract(&contract, &client).expect("client projection");
        let server_local = project_contract(&contract, &server).expect("server projection");

        assert!(matches!(client_local, LocalSessionType::Send { .. }));
        assert!(matches!(server_local, LocalSessionType::Receive { .. }));
        assert!(is_dual(&client_local, &server_local));
    }

    #[test]
    fn choice_projection_maps_decider_to_choice_and_peer_to_branch() {
        let contract = streaming_contract();
        let producer = RoleName::from("producer");
        let consumer = RoleName::from("consumer");

        let producer_local = project_contract(&contract, &producer).expect("producer projection");
        let consumer_local = project_contract(&contract, &consumer).expect("consumer projection");

        assert!(is_dual(&producer_local, &consumer_local));

        let LocalSessionType::Send { next, .. } = producer_local else {
            panic!("producer should send the opening frame");
        };
        let LocalSessionType::RecursePoint { body, .. } = *next else {
            panic!("producer should enter the projected recursion point");
        };
        assert!(matches!(*body, LocalSessionType::Branch { .. }));

        let LocalSessionType::Receive { next, .. } = consumer_local else {
            panic!("consumer should receive the opening frame");
        };
        let LocalSessionType::RecursePoint { body, .. } = *next else {
            panic!("consumer should enter the projected recursion point");
        };
        assert!(matches!(*body, LocalSessionType::Choice { .. }));
    }

    #[test]
    fn branch_projection_maps_controller_to_choice_and_peer_to_branch() {
        let contract = reservation_handoff_contract();
        let caller = RoleName::from("caller");
        let steward = RoleName::from("steward");

        let caller_local = project_contract(&contract, &caller).expect("caller projection");
        let steward_local = project_contract(&contract, &steward).expect("steward projection");

        assert!(is_dual(&caller_local, &steward_local));

        let LocalSessionType::Send { next, .. } = caller_local else {
            panic!("caller should send the reservation");
        };
        assert!(matches!(*next, LocalSessionType::Branch { .. }));

        let LocalSessionType::Receive { next, .. } = steward_local else {
            panic!("steward should receive the reservation");
        };
        assert!(matches!(*next, LocalSessionType::Choice { .. }));
    }

    #[test]
    fn projection_rejects_unknown_role() {
        let contract = request_reply_contract();
        let err = project_contract(&contract, &RoleName::from("outsider")).unwrap_err();
        assert_eq!(
            err,
            ProjectionError::UnknownRole(RoleName::from("outsider"))
        );
    }

    #[test]
    fn projection_rejects_invalid_role_count() {
        let contract = ProtocolContract::new(
            "bad_roles",
            SchemaVersion::new(1, 0, 0),
            vec![RoleName::from("client")],
            GlobalSessionType::new(SessionType::send(
                MessageType::new("ping", "client", "server", "Ping"),
                SessionType::End,
            )),
        );

        let err = project(
            &contract.global_type,
            &contract.roles,
            &RoleName::from("client"),
        )
        .unwrap_err();
        assert_eq!(err, ProjectionError::UnsupportedRoleCount { actual: 1 });
    }

    #[test]
    fn duality_rejects_mismatched_branch_labels() {
        let left =
            LocalSessionType::choice(vec![LocalSessionBranch::new("ok", LocalSessionType::End)]);
        let right =
            LocalSessionType::branch(vec![LocalSessionBranch::new("nope", LocalSessionType::End)]);

        assert!(!is_dual(&left, &right));
    }

    #[test]
    fn project_pair_returns_dual_locals() {
        let contract = request_reply_contract();
        let (left, right) = project_pair(&contract).expect("project pair");
        assert!(is_dual(&left, &right));
    }
}
