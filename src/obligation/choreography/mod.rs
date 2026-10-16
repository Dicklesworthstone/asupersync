// Module-level clippy allows for initial design module (bd-1f8jn.1).
#![allow(clippy::must_use_candidate)]
#![allow(clippy::use_self)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::unused_self)]

//! Choreographic programming for saga protocol generation (bd-1f8jn.1).
//!
//! Defines a choreography DSL for specifying Asupersync saga protocols as
//! global interaction descriptions. A choreography is a single source of
//! truth describing the interactions between multiple participants. The
//! projection compiler (bd-1f8jn.2) will later generate per-participant
//! session-typed code from these global protocols.
//!
//! # Background
//!
//! Choreographic programming (Montesi 2023, "Introduction to Choreographies")
//! eliminates protocol mismatch bugs by construction. Instead of independently
//! writing each participant's code and hoping they match, you write a single
//! global protocol and *project* it to per-participant local types.
//!
//! # DSL Grammar (Asupersync Choreography Language)
//!
//! ```text
//! protocol     ::= 'protocol' IDENT '{' participant+ interaction '}'
//! participant  ::= 'participant' IDENT ':' ROLE ';'
//! interaction  ::= comm | choice | loop_ | seq | compensation | end
//! comm         ::= IDENT '.' IDENT '(' msg_type ')' '->' IDENT then
//! choice       ::= 'if' IDENT '.decides(' IDENT ')' '{' interaction '}' 'else' '{' interaction '}'
//! loop_        ::= 'loop' IDENT '{' interaction '}'
//! compensation ::= 'compensate' '{' interaction '}' 'with' '{' interaction '}'
//! seq          ::= interaction ';' interaction
//! end          ::= 'end'
//! then         ::= '.' interaction | ';' interaction
//! msg_type     ::= IDENT | IDENT '<' type_args '>'
//! ```
//!
//! # Example
//!
//! ```
//! use asupersync::obligation::choreography::*;
//!
//! let protocol = GlobalProtocol::builder("two_phase_commit")
//!     .participant("coordinator", "saga-coordinator")
//!     .participant("worker", "saga-participant")
//!     .interaction(
//!         Interaction::comm("coordinator", "reserve", "ReserveMsg", "worker")
//!             .then(Interaction::choice(
//!                 "coordinator",
//!                 "commit_ready",
//!                 Interaction::comm("coordinator", "commit", "CommitMsg", "worker")
//!                     .then(Interaction::end())
//!                     .expect("comm interactions accept continuations"),
//!                 Interaction::comm("coordinator", "abort", "AbortMsg", "worker")
//!                     .then(Interaction::end())
//!                     .expect("comm interactions accept continuations"),
//!             ))
//!             .expect("comm interactions accept continuations"),
//!     )
//!     .build();
//!
//! let errors = protocol.validate();
//! assert!(errors.is_empty(), "Validation errors: {errors:?}");
//!
//! // Knowledge-of-choice: coordinator decides, so it must be the sender
//! // in the first communication after the branch. This is validated
//! // automatically.
//! assert!(protocol.is_deadlock_free());
//! ```
//!
//! # Deadlock Freedom
//!
//! The validator enforces the **knowledge-of-choice** condition: after a
//! branching point, the deciding participant must be the sender in the
//! first communication of every branch. This ensures the other participants
//! learn which branch was taken via the message they receive, rather than
//! having to guess. This is the standard condition for deadlock-free
//! multiparty session types (Honda-Yoshida-Carbone 2008).
//!
//! # CALM Integration
//!
//! Each communication action carries an optional CALM monotonicity
//! annotation. When projecting to saga execution plans, monotone
//! communications can be batched for coordination-free execution.

pub mod codegen;
pub mod pipeline;

use crate::obligation::calm::Monotonicity;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ============================================================================
// AST: Global Protocol
// ============================================================================

/// A global choreography protocol describing interactions between participants.
///
/// This is the single source of truth from which per-participant session types
/// and saga execution plans are derived.
#[derive(Debug, Clone)]
pub struct GlobalProtocol {
    /// Protocol name (used as identifier in code generation).
    pub name: String,
    /// Ordered map of participant name → role.
    pub participants: BTreeMap<String, Participant>,
    /// The interaction tree describing the global protocol.
    pub interaction: Interaction,
    /// Duplicate participant names encountered during builder construction.
    ///
    /// Stored for validation so duplicate declarations are surfaced as
    /// deterministic `ValidationError::DuplicateParticipant` entries instead
    /// of being silently overwritten by the map.
    duplicate_participants: BTreeSet<String>,
}

/// A named participant in a choreography with a typed role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// Participant identifier (e.g., "coordinator", "worker-1").
    pub name: String,
    /// Role tag (e.g., "saga-coordinator", "saga-participant").
    pub role: String,
}

/// A message type reference in a communication action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageType {
    /// Type name (e.g., "ReserveMsg", "CommitMsg").
    pub name: String,
    /// Optional type parameters (e.g., `["T"]` for `Payload<T>`).
    pub type_params: Vec<String>,
}

/// An interaction in the global choreography.
///
/// Interactions form a tree structure representing the protocol's control flow.
/// Each variant corresponds to a primitive in the choreographic calculus.
#[derive(Debug, Clone)]
pub enum Interaction {
    /// Communication: `sender.action(msg) -> receiver`.
    ///
    /// The sender transmits a message of the given type to the receiver.
    /// This is the fundamental building block of choreographies.
    Comm {
        /// Participant sending the message.
        sender: String,
        /// Action label (e.g., "reserve", "commit", "send_data").
        action: String,
        /// Message type being transmitted.
        msg_type: MessageType,
        /// Participant receiving the message.
        receiver: String,
        /// CALM monotonicity annotation for saga optimization.
        monotonicity: Option<Monotonicity>,
        /// Continuation after this communication.
        then: Box<Self>,
    },

    /// Choice: `if decider.decides(predicate) { then_branch } else { else_branch }`.
    ///
    /// The deciding participant evaluates a local predicate and selects a branch.
    /// The knowledge-of-choice condition requires the decider to be the sender
    /// in the first communication of every branch.
    Choice {
        /// Participant making the decision.
        decider: String,
        /// Predicate label (for documentation/tracing).
        predicate: String,
        /// Branch taken when predicate holds.
        then_branch: Box<Self>,
        /// Branch taken when predicate does not hold.
        else_branch: Box<Self>,
    },

    /// Recursion point: `loop label { body }`.
    ///
    /// Marks a point to which the protocol can loop back via `Continue`.
    Loop {
        /// Label for this recursion point (must be unique within protocol).
        label: String,
        /// Loop body.
        body: Box<Self>,
    },

    /// Jump back to enclosing loop: `continue label`.
    Continue {
        /// Label of the `Loop` to jump back to.
        label: String,
    },

    /// Compensation block: `compensate { forward } with { compensate }`.
    ///
    /// The forward interaction runs first. If a failure occurs, the
    /// compensating interaction runs to undo the effects. This integrates
    /// with Asupersync's saga rollback mechanism.
    Compensate {
        /// The forward (happy-path) interaction.
        forward: Box<Self>,
        /// The compensation (rollback) interaction.
        compensate: Box<Self>,
    },

    /// Sequential composition: `first; second`.
    Seq {
        /// First interaction.
        first: Box<Self>,
        /// Second interaction (runs after first completes).
        second: Box<Self>,
    },

    /// Parallel composition: `par { left } and { right }`.
    ///
    /// Both branches execute concurrently. Participants in each branch
    /// must be disjoint (no participant appears in both).
    Par {
        /// Left parallel branch.
        left: Box<Self>,
        /// Right parallel branch.
        right: Box<Self>,
    },

    /// Protocol termination.
    End,
}

// ============================================================================
// Builder API
// ============================================================================

/// Builder for constructing `GlobalProtocol` instances.
///
/// Provides a fluent API for defining choreographies without directly
/// constructing the AST.
pub struct ProtocolBuilder {
    name: String,
    participants: BTreeMap<String, Participant>,
    interaction: Option<Interaction>,
    duplicate_participants: BTreeSet<String>,
}

/// Builder error for invalid interaction chaining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoreographyBuildError {
    /// A continuation was attached to an interaction kind that does not accept
    /// direct chaining.
    InvalidContinuationTarget {
        /// The interaction kind that rejected the continuation.
        kind: &'static str,
    },
}

impl fmt::Display for ChoreographyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContinuationTarget { kind } => {
                write!(f, "cannot attach a direct continuation to `{kind}`")
            }
        }
    }
}

impl GlobalProtocol {
    /// Start building a new global protocol.
    pub fn builder(name: &str) -> ProtocolBuilder {
        ProtocolBuilder {
            name: name.to_string(),
            participants: BTreeMap::new(),
            interaction: None,
            duplicate_participants: BTreeSet::new(),
        }
    }
}

impl ProtocolBuilder {
    /// Add a participant with the given name and role.
    #[must_use]
    pub fn participant(mut self, name: &str, role: &str) -> Self {
        if self.participants.contains_key(name) {
            self.duplicate_participants.insert(name.to_string());
            return self;
        }
        self.participants.insert(
            name.to_string(),
            Participant {
                name: name.to_string(),
                role: role.to_string(),
            },
        );
        self
    }

    /// Set the protocol's interaction tree.
    #[must_use]
    pub fn interaction(mut self, interaction: Interaction) -> Self {
        self.interaction = Some(interaction);
        self
    }

    /// Build the `GlobalProtocol`, consuming the builder.
    pub fn build(self) -> GlobalProtocol {
        GlobalProtocol {
            name: self.name,
            participants: self.participants,
            // Missing interaction is treated as an empty protocol so validation
            // can reject it deterministically without panicking.
            interaction: self.interaction.unwrap_or(Interaction::End),
            duplicate_participants: self.duplicate_participants,
        }
    }
}

// ============================================================================
// Interaction constructors
// ============================================================================

impl Interaction {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Comm { .. } => "comm",
            Self::Choice { .. } => "choice",
            Self::Loop { .. } => "loop",
            Self::Continue { .. } => "continue",
            Self::Compensate { .. } => "compensate",
            Self::Seq { .. } => "seq",
            Self::Par { .. } => "par",
            Self::End => "end",
        }
    }

    /// Create a communication action: `sender.action(msg) -> receiver`.
    pub fn comm(sender: &str, action: &str, msg_type: &str, receiver: &str) -> Self {
        Self::Comm {
            sender: sender.to_string(),
            action: action.to_string(),
            msg_type: MessageType {
                name: msg_type.to_string(),
                type_params: Vec::new(),
            },
            receiver: receiver.to_string(),
            monotonicity: None,
            then: Box::new(Self::End),
        }
    }

    /// Create a communication with a generic message type.
    pub fn comm_generic(
        sender: &str,
        action: &str,
        msg_type: &str,
        type_params: &[&str],
        receiver: &str,
    ) -> Self {
        Self::Comm {
            sender: sender.to_string(),
            action: action.to_string(),
            msg_type: MessageType {
                name: msg_type.to_string(),
                type_params: type_params.iter().map(|s| (*s).to_string()).collect(),
            },
            receiver: receiver.to_string(),
            monotonicity: None,
            then: Box::new(Self::End),
        }
    }

    /// Create a communication with CALM monotonicity annotation.
    pub fn comm_calm(
        sender: &str,
        action: &str,
        msg_type: &str,
        receiver: &str,
        monotonicity: Monotonicity,
    ) -> Self {
        Self::Comm {
            sender: sender.to_string(),
            action: action.to_string(),
            msg_type: MessageType {
                name: msg_type.to_string(),
                type_params: Vec::new(),
            },
            receiver: receiver.to_string(),
            monotonicity: Some(monotonicity),
            then: Box::new(Self::End),
        }
    }

    /// Set the continuation after a `Comm` interaction.
    pub fn then(self, next: Interaction) -> Result<Self, ChoreographyBuildError> {
        match self {
            Self::Comm {
                sender,
                action,
                msg_type,
                receiver,
                monotonicity,
                ..
            } => Ok(Self::Comm {
                sender,
                action,
                msg_type,
                receiver,
                monotonicity,
                then: Box::new(next),
            }),
            other => Err(ChoreographyBuildError::InvalidContinuationTarget {
                kind: other.kind_name(),
            }),
        }
    }

    /// Create a choice: `if decider.decides(predicate) { then } else { otherwise }`.
    pub fn choice(
        decider: &str,
        predicate: &str,
        then_branch: Interaction,
        else_branch: Interaction,
    ) -> Self {
        Self::Choice {
            decider: decider.to_string(),
            predicate: predicate.to_string(),
            then_branch: Box::new(then_branch),
            else_branch: Box::new(else_branch),
        }
    }

    /// Create a labeled loop: `loop label { body }`.
    pub fn loop_(label: &str, body: Interaction) -> Self {
        Self::Loop {
            label: label.to_string(),
            body: Box::new(body),
        }
    }

    /// Create a continue (jump to loop): `continue label`.
    pub fn continue_(label: &str) -> Self {
        Self::Continue {
            label: label.to_string(),
        }
    }

    /// Create a compensation block: `compensate { forward } with { compensate }`.
    pub fn compensate(forward: Interaction, compensate: Interaction) -> Self {
        Self::Compensate {
            forward: Box::new(forward),
            compensate: Box::new(compensate),
        }
    }

    /// Create a sequential composition: `first; second`.
    pub fn seq(first: Interaction, second: Interaction) -> Self {
        Self::Seq {
            first: Box::new(first),
            second: Box::new(second),
        }
    }

    /// Create a parallel composition: `par { left } and { right }`.
    pub fn par(left: Interaction, right: Interaction) -> Self {
        Self::Par {
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Protocol termination.
    pub fn end() -> Self {
        Self::End
    }
}

// ============================================================================
// Participant extraction
// ============================================================================

impl Interaction {
    /// Collect all participant names referenced in this interaction tree.
    pub fn referenced_participants(&self) -> BTreeSet<String> {
        let mut participants = BTreeSet::new();
        self.collect_participants(&mut participants);
        participants
    }

    fn collect_participants(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::Comm {
                sender,
                receiver,
                then,
                ..
            } => {
                out.insert(sender.clone());
                out.insert(receiver.clone());
                then.collect_participants(out);
            }
            Self::Choice {
                decider,
                then_branch,
                else_branch,
                ..
            } => {
                out.insert(decider.clone());
                then_branch.collect_participants(out);
                else_branch.collect_participants(out);
            }
            Self::Loop { body, .. } => {
                body.collect_participants(out);
            }
            Self::Continue { .. } | Self::End => {}
            Self::Compensate {
                forward,
                compensate,
            } => {
                forward.collect_participants(out);
                compensate.collect_participants(out);
            }
            Self::Seq { first, second } => {
                first.collect_participants(out);
                second.collect_participants(out);
            }
            Self::Par { left, right } => {
                left.collect_participants(out);
                right.collect_participants(out);
            }
        }
    }

    /// Return the first sender/decider in this interaction, if any.
    ///
    /// Used for knowledge-of-choice validation.
    #[cfg(test)]
    fn first_active_participant(&self) -> Option<&str> {
        match self {
            Self::Comm { sender, .. } => Some(sender),
            Self::Choice { decider, .. } => Some(decider),
            Self::Loop { body, .. } => body.first_active_participant(),
            Self::Continue { .. } | Self::End => None,
            Self::Compensate { forward, .. } => forward.first_active_participant(),
            Self::Seq { first, second } => first
                .first_active_participant()
                .or_else(|| second.first_active_participant()),
            Self::Par { left, right } => left
                .first_active_participant()
                .or_else(|| right.first_active_participant()),
        }
    }

    /// Return all participants that may act first in this interaction.
    ///
    /// This differs from `first_active_participant()` for parallel composition:
    /// in `Par`, either branch may progress first, so both branch starters are
    /// considered "first active".
    fn first_active_participants(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect_first_active_participants(&mut out);
        out
    }

    fn collect_first_active_participants(&self, out: &mut BTreeSet<String>) {
        match self {
            Self::Comm { sender, .. } => {
                out.insert(sender.clone());
            }
            Self::Choice { decider, .. } => {
                out.insert(decider.clone());
            }
            Self::Loop { body, .. } => body.collect_first_active_participants(out),
            Self::Continue { .. } | Self::End => {}
            Self::Compensate { forward, .. } => forward.collect_first_active_participants(out),
            Self::Seq { first, second } => {
                let mut first_set = BTreeSet::new();
                first.collect_first_active_participants(&mut first_set);
                if first_set.is_empty() {
                    second.collect_first_active_participants(out);
                } else {
                    out.extend(first_set);
                }
            }
            Self::Par { left, right } => {
                left.collect_first_active_participants(out);
                right.collect_first_active_participants(out);
            }
        }
    }
}

// ============================================================================
// Validation
// ============================================================================

/// A validation error found in a choreography protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// A communication references an undeclared participant.
    UndeclaredParticipant {
        /// The undeclared participant name.
        name: String,
        /// Where the reference occurs.
        context: String,
    },
    /// A participant sends a message to itself.
    SelfCommunication {
        /// The self-communicating participant.
        participant: String,
        /// The action label.
        action: String,
    },
    /// Knowledge-of-choice violation: the decider is not the sender in
    /// the first communication of a branch.
    KnowledgeOfChoice {
        /// The deciding participant.
        decider: String,
        /// Which branch has the violation ("then" or "else").
        branch: &'static str,
        /// Who actually sends first (if any).
        first_sender: Option<String>,
    },
    /// A `Continue` references an undefined loop label.
    UndefinedLoopLabel {
        /// The undefined label.
        label: String,
    },
    /// Duplicate loop labels in the same protocol.
    DuplicateLoopLabel {
        /// The duplicated label.
        label: String,
    },
    /// Empty protocol (no interactions).
    EmptyProtocol,
    /// Parallel branches share a participant.
    ParallelParticipantOverlap {
        /// The overlapping participant name.
        participant: String,
    },
    /// Duplicate participant name in declaration.
    DuplicateParticipant {
        /// The duplicated participant name.
        name: String,
    },
    /// No participants declared.
    NoParticipants,
    /// Potential livelock detected: loop can recurse infinitely without progress.
    Livelock {
        /// The label of the problematic loop.
        label: String,
        /// Description of why this loop might not make progress.
        reason: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndeclaredParticipant { name, context } => {
                write!(f, "undeclared participant '{name}' in {context}")
            }
            Self::SelfCommunication {
                participant,
                action,
            } => {
                write!(
                    f,
                    "self-communication: '{participant}' sends '{action}' to itself"
                )
            }
            Self::KnowledgeOfChoice {
                decider,
                branch,
                first_sender,
            } => {
                let sender_desc = first_sender
                    .as_deref()
                    .map_or_else(|| "(no communication)".to_string(), |s| format!("'{s}'"));
                write!(
                    f,
                    "knowledge-of-choice violation: '{decider}' decides but {branch} branch \
                     starts with sender {sender_desc}"
                )
            }
            Self::UndefinedLoopLabel { label } => {
                write!(f, "continue references undefined loop label '{label}'")
            }
            Self::DuplicateLoopLabel { label } => {
                write!(f, "duplicate loop label '{label}'")
            }
            Self::EmptyProtocol => write!(f, "protocol has no interactions"),
            Self::ParallelParticipantOverlap { participant } => {
                write!(
                    f,
                    "participant '{participant}' appears in both parallel branches"
                )
            }
            Self::DuplicateParticipant { name } => {
                write!(f, "duplicate participant declaration '{name}'")
            }
            Self::NoParticipants => write!(f, "no participants declared"),
            Self::Livelock { label, reason } => {
                write!(f, "potential livelock in loop '{label}': {reason}")
            }
        }
    }
}

impl GlobalProtocol {
    /// Validate the protocol for well-formedness.
    ///
    /// Checks:
    /// 1. All referenced participants are declared
    /// 2. No self-communication (sender == receiver)
    /// 3. Knowledge-of-choice (deadlock freedom)
    /// 4. Loop label consistency (no undefined, no duplicates)
    /// 5. Parallel branches have disjoint participants
    /// 6. At least one participant declared
    /// 7. Protocol is non-empty
    /// 8. Livelock freedom (bounded recursion analysis)
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        // Duplicate participant declarations are tracked at build time.
        // Validate deterministically in lexical order.
        for name in &self.duplicate_participants {
            errors.push(ValidationError::DuplicateParticipant { name: name.clone() });
        }

        // Check: at least one participant
        if self.participants.is_empty() {
            errors.push(ValidationError::NoParticipants);
        }

        // Check: non-empty protocol
        if matches!(self.interaction, Interaction::End) {
            errors.push(ValidationError::EmptyProtocol);
        }

        // Check: all referenced participants are declared
        let declared: BTreeSet<&str> = self.participants.keys().map(String::as_str).collect();
        let referenced = self.interaction.referenced_participants();
        for name in &referenced {
            if !declared.contains(name.as_str()) {
                errors.push(ValidationError::UndeclaredParticipant {
                    name: name.clone(),
                    context: format!("protocol '{}'", self.name),
                });
            }
        }

        // Check: interaction-level rules
        let mut loop_labels = BTreeSet::new();
        self.validate_interaction(&self.interaction, &declared, &mut loop_labels, &mut errors);

        errors
    }

    fn validate_interaction(
        &self,
        interaction: &Interaction,
        declared: &BTreeSet<&str>,
        loop_labels: &mut BTreeSet<String>,
        errors: &mut Vec<ValidationError>,
    ) {
        match interaction {
            Interaction::Comm {
                sender,
                receiver,
                action,
                then,
                ..
            } => {
                // No self-communication
                if sender == receiver {
                    errors.push(ValidationError::SelfCommunication {
                        participant: sender.clone(),
                        action: action.clone(),
                    });
                }
                // Both declared
                if !declared.contains(sender.as_str()) {
                    errors.push(ValidationError::UndeclaredParticipant {
                        name: sender.clone(),
                        context: format!("send action '{action}'"),
                    });
                }
                if !declared.contains(receiver.as_str()) {
                    errors.push(ValidationError::UndeclaredParticipant {
                        name: receiver.clone(),
                        context: format!("receive action '{action}'"),
                    });
                }
                self.validate_interaction(then, declared, loop_labels, errors);
            }
            Interaction::Choice {
                decider,
                then_branch,
                else_branch,
                ..
            } => {
                // Decider must be declared
                if !declared.contains(decider.as_str()) {
                    errors.push(ValidationError::UndeclaredParticipant {
                        name: decider.clone(),
                        context: "choice decider".to_string(),
                    });
                }

                // Knowledge-of-choice: decider must be the first sender
                // in each branch.
                self.check_knowledge_of_choice(decider, then_branch, "then", errors);
                self.check_knowledge_of_choice(decider, else_branch, "else", errors);

                self.validate_interaction(then_branch, declared, loop_labels, errors);
                self.validate_interaction(else_branch, declared, loop_labels, errors);
            }
            Interaction::Loop { label, body } => {
                let inserted = loop_labels.insert(label.clone());
                if !inserted {
                    errors.push(ValidationError::DuplicateLoopLabel {
                        label: label.clone(),
                    });
                }
                // Livelock analysis: check if the loop can make progress
                self.check_livelock(label, body, errors);
                self.validate_interaction(body, declared, loop_labels, errors);
                // Remove the label after validating the body so it doesn't
                // leak into sibling interactions (e.g. Seq siblings, Choice
                // branches, Par branches).  Only the body of the Loop should
                // be able to `continue` to this label.
                // Only remove if we successfully inserted — a duplicate label
                // must not remove the outer loop's entry.
                if inserted {
                    loop_labels.remove(label);
                }
            }
            Interaction::Continue { label } => {
                if !loop_labels.contains(label) {
                    errors.push(ValidationError::UndefinedLoopLabel {
                        label: label.clone(),
                    });
                }
            }
            Interaction::End => {}
            Interaction::Compensate {
                forward,
                compensate,
            } => {
                self.validate_interaction(forward, declared, loop_labels, errors);
                self.validate_interaction(compensate, declared, loop_labels, errors);
            }
            Interaction::Seq { first, second } => {
                self.validate_interaction(first, declared, loop_labels, errors);
                self.validate_interaction(second, declared, loop_labels, errors);
            }
            Interaction::Par { left, right } => {
                // Parallel branches must have disjoint participants
                let left_parts = left.referenced_participants();
                let right_parts = right.referenced_participants();
                for p in &left_parts {
                    if right_parts.contains(p) {
                        errors.push(ValidationError::ParallelParticipantOverlap {
                            participant: p.clone(),
                        });
                    }
                }
                self.validate_interaction(left, declared, loop_labels, errors);
                self.validate_interaction(right, declared, loop_labels, errors);
            }
        }
    }

    /// Check the knowledge-of-choice condition for a single branch.
    ///
    /// The decider must be the sender in the first communication of the branch,
    /// ensuring that other participants learn which branch was taken.
    fn check_knowledge_of_choice(
        &self,
        decider: &str,
        branch: &Interaction,
        branch_name: &'static str,
        errors: &mut Vec<ValidationError>,
    ) {
        let first_senders = branch.first_active_participants();
        if first_senders.is_empty() {
            // Branch is End or Continue — acceptable (trivial branches).
            return;
        }

        for first_sender in first_senders {
            if first_sender != decider {
                errors.push(ValidationError::KnowledgeOfChoice {
                    decider: decider.to_string(),
                    branch: branch_name,
                    first_sender: Some(first_sender),
                });
            }
        }
    }

    /// Check for potential livelock in a loop body.
    ///
    /// Livelock occurs when a loop can recurse infinitely without making progress.
    /// This method detects several classes of livelock:
    /// 1. Immediate infinite recursion (body is just a Continue to the same label)
    /// 2. Progress-free loops (no communication actions, only control flow leading to Continue)
    /// 3. Unbounded recursion paths (loop has execution paths with no guaranteed termination)
    fn check_livelock(
        &self,
        loop_label: &str,
        body: &Interaction,
        errors: &mut Vec<ValidationError>,
    ) {
        // Check for immediate infinite recursion: loop body is just "continue self"
        if let Interaction::Continue { label } = body {
            if label == loop_label {
                errors.push(ValidationError::Livelock {
                    label: loop_label.to_string(),
                    reason: "loop body is just 'continue' to itself (immediate infinite recursion)"
                        .to_string(),
                });
                return;
            }
        }

        // Check for progress-free loops: analyze if the body can lead to Continue
        // without any communication actions that could change state
        let progress_analysis = self.analyze_loop_progress(body, loop_label);

        if progress_analysis.has_continue_path && !progress_analysis.has_progress_guarantee {
            let reason = if progress_analysis.comm_count == 0 {
                "loop body contains no communication actions but has paths leading to recursion"
                    .to_string()
            } else {
                format!(
                    "loop body has {} communication(s) but no guaranteed progress on recursion paths",
                    progress_analysis.comm_count
                )
            };

            errors.push(ValidationError::Livelock {
                label: loop_label.to_string(),
                reason,
            });
        }
    }

    /// Analyze whether a loop body can make progress or might livelock.
    fn analyze_loop_progress(
        &self,
        interaction: &Interaction,
        target_label: &str,
    ) -> LoopProgressAnalysis {
        let mut analysis = LoopProgressAnalysis::new();
        let _fallthrough_paths =
            Self::analyze_progress_recursive(interaction, target_label, &mut analysis, false);
        analysis
    }

    /// Recursively analyze interaction for progress guarantees.
    ///
    /// Returns the set of progress states for paths that fall through this
    /// interaction without jumping to the target loop label. `true` means that
    /// path has observed at least one communication action. Target `continue`
    /// paths are terminal for this analysis and are recorded directly in
    /// `analysis`.
    fn analyze_progress_recursive(
        interaction: &Interaction,
        target_label: &str,
        analysis: &mut LoopProgressAnalysis,
        progress_seen: bool,
    ) -> BTreeSet<bool> {
        match interaction {
            Interaction::Comm { then, .. } => {
                analysis.comm_count += 1;
                // Communication is progress for every downstream path,
                // including paths inside a choice branch.
                Self::analyze_progress_recursive(then, target_label, analysis, true)
            }
            Interaction::Continue { label } => {
                if label == target_label {
                    analysis.has_continue_path = true;
                    if !progress_seen {
                        analysis.has_progress_guarantee = false;
                    }
                }
                BTreeSet::new()
            }
            Interaction::Choice {
                then_branch,
                else_branch,
                ..
            } => {
                // Both branches need to be analyzed separately. A choice is
                // progress-safe only if every branch that can continue has
                // already observed communication on that path.
                let mut fallthrough = Self::analyze_progress_recursive(
                    then_branch,
                    target_label,
                    analysis,
                    progress_seen,
                );
                fallthrough.extend(Self::analyze_progress_recursive(
                    else_branch,
                    target_label,
                    analysis,
                    progress_seen,
                ));
                fallthrough
            }
            Interaction::Loop { body, .. } => {
                // Nested loops - analyze their body
                Self::analyze_progress_recursive(body, target_label, analysis, progress_seen)
            }
            Interaction::Seq { first, second } => {
                let first_fallthrough =
                    Self::analyze_progress_recursive(first, target_label, analysis, progress_seen);
                let mut fallthrough = BTreeSet::new();
                for path_progress in first_fallthrough {
                    fallthrough.extend(Self::analyze_progress_recursive(
                        second,
                        target_label,
                        analysis,
                        path_progress,
                    ));
                }
                fallthrough
            }
            Interaction::Par { left, right } => {
                let mut fallthrough =
                    Self::analyze_progress_recursive(left, target_label, analysis, progress_seen);
                fallthrough.extend(Self::analyze_progress_recursive(
                    right,
                    target_label,
                    analysis,
                    progress_seen,
                ));
                fallthrough
            }
            Interaction::Compensate {
                forward,
                compensate,
            } => {
                let forward_fallthrough = Self::analyze_progress_recursive(
                    forward,
                    target_label,
                    analysis,
                    progress_seen,
                );
                let mut fallthrough = BTreeSet::new();
                for path_progress in forward_fallthrough {
                    fallthrough.extend(Self::analyze_progress_recursive(
                        compensate,
                        target_label,
                        analysis,
                        path_progress,
                    ));
                }
                fallthrough
            }
            Interaction::End => BTreeSet::from([progress_seen]),
        }
    }

    /// Check whether the protocol is deadlock-free.
    ///
    /// A protocol is deadlock-free if it passes all validation checks,
    /// in particular the knowledge-of-choice condition on every branch.
    pub fn is_deadlock_free(&self) -> bool {
        self.validate().is_empty()
    }
}

// ============================================================================
// Analysis: Communication count and depth
// ============================================================================

/// Summary statistics for a choreography protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolStats {
    /// Total number of communication actions (Comm nodes).
    pub comm_count: usize,
    /// Number of choice points (Choice nodes).
    pub choice_count: usize,
    /// Number of loop points (Loop nodes).
    pub loop_count: usize,
    /// Number of compensation blocks (Compensate nodes).
    pub compensate_count: usize,
    /// Number of parallel blocks (Par nodes).
    pub par_count: usize,
    /// Maximum nesting depth of the interaction tree.
    pub max_depth: usize,
    /// Number of distinct participants referenced.
    pub participant_count: usize,
    /// Number of monotone-annotated communications.
    pub monotone_comm_count: usize,
    /// Number of non-monotone-annotated communications.
    pub non_monotone_comm_count: usize,
}

/// Analysis result for livelock detection in loop bodies.
#[derive(Debug, Clone)]
struct LoopProgressAnalysis {
    /// Whether there's a path from the loop body that leads to Continue.
    has_continue_path: bool,
    /// Whether all paths to Continue are guaranteed to make progress.
    has_progress_guarantee: bool,
    /// Total number of communication actions found in the loop body.
    comm_count: usize,
}

impl LoopProgressAnalysis {
    fn new() -> Self {
        Self {
            has_continue_path: false,
            has_progress_guarantee: true,
            comm_count: 0,
        }
    }
}

impl GlobalProtocol {
    /// Compute summary statistics for this protocol.
    pub fn stats(&self) -> ProtocolStats {
        let mut stats = ProtocolStats {
            comm_count: 0,
            choice_count: 0,
            loop_count: 0,
            compensate_count: 0,
            par_count: 0,
            max_depth: 0,
            participant_count: self.interaction.referenced_participants().len(),
            monotone_comm_count: 0,
            non_monotone_comm_count: 0,
        };
        Self::count_interaction(&self.interaction, 0, &mut stats);
        stats
    }

    fn count_interaction(interaction: &Interaction, depth: usize, stats: &mut ProtocolStats) {
        if depth > stats.max_depth {
            stats.max_depth = depth;
        }
        match interaction {
            Interaction::Comm {
                monotonicity, then, ..
            } => {
                stats.comm_count = stats.comm_count.saturating_add(1);
                match monotonicity {
                    Some(Monotonicity::Monotone) => {
                        stats.monotone_comm_count = stats.monotone_comm_count.saturating_add(1)
                    }
                    Some(Monotonicity::NonMonotone) => {
                        stats.non_monotone_comm_count =
                            stats.non_monotone_comm_count.saturating_add(1)
                    }
                    None => {}
                }
                Self::count_interaction(then, depth.saturating_add(1), stats);
            }
            Interaction::Choice {
                then_branch,
                else_branch,
                ..
            } => {
                stats.choice_count = stats.choice_count.saturating_add(1);
                Self::count_interaction(then_branch, depth.saturating_add(1), stats);
                Self::count_interaction(else_branch, depth.saturating_add(1), stats);
            }
            Interaction::Loop { body, .. } => {
                stats.loop_count = stats.loop_count.saturating_add(1);
                Self::count_interaction(body, depth.saturating_add(1), stats);
            }
            Interaction::Continue { .. } | Interaction::End => {}
            Interaction::Compensate {
                forward,
                compensate,
            } => {
                stats.compensate_count += 1;
                Self::count_interaction(forward, depth + 1, stats);
                Self::count_interaction(compensate, depth + 1, stats);
            }
            Interaction::Seq { first, second } => {
                Self::count_interaction(first, depth, stats);
                Self::count_interaction(second, depth, stats);
            }
            Interaction::Par { left, right } => {
                stats.par_count += 1;
                Self::count_interaction(left, depth + 1, stats);
                Self::count_interaction(right, depth + 1, stats);
            }
        }
    }
}

// ============================================================================
// Projection (types only — implementation in bd-1f8jn.2)
// ============================================================================

/// A projected local protocol for a single participant.
///
/// This is the target of choreographic projection: each participant gets a
/// local view of the global protocol describing only their actions.
#[derive(Debug, Clone)]
pub enum LocalType {
    /// Send a message of the given type, then continue.
    Send {
        /// Action label.
        action: String,
        /// Message type.
        msg_type: MessageType,
        /// Recipient participant name.
        to: String,
        /// Continuation.
        then: Box<Self>,
    },
    /// Receive a message of the given type, then continue.
    Recv {
        /// Action label.
        action: String,
        /// Message type.
        msg_type: MessageType,
        /// Sender participant name.
        from: String,
        /// Continuation.
        then: Box<Self>,
    },
    /// Internal choice: this participant decides which branch.
    InternalChoice {
        /// Local predicate label.
        predicate: String,
        /// Then branch.
        then_branch: Box<Self>,
        /// Else branch.
        else_branch: Box<Self>,
    },
    /// External choice: wait for the peer to decide.
    ExternalChoice {
        /// Participant offering the choice.
        from: String,
        /// Then branch.
        then_branch: Box<Self>,
        /// Else branch.
        else_branch: Box<Self>,
    },
    /// Recursion point.
    Rec {
        /// Loop label.
        label: String,
        /// Loop body.
        body: Box<Self>,
    },
    /// Jump to recursion point.
    RecVar {
        /// Target loop label.
        label: String,
    },
    /// Compensation: forward + rollback.
    Compensate {
        /// Forward (happy-path) interaction.
        forward: Box<Self>,
        /// Compensation (rollback) interaction.
        compensate: Box<Self>,
    },
    /// End of local protocol.
    End,
}

impl GlobalProtocol {
    /// Project the global protocol to a local type for the given participant.
    ///
    /// This is the core of choreographic projection: given a global interaction
    /// tree, produce the local view for a single participant by:
    /// - Keeping Comm nodes where the participant is sender or receiver
    /// - Translating Choice nodes based on whether participant is the decider
    /// - Preserving structural nodes (Loop, Compensate, Seq)
    /// - Merging parallel branches (keeping only branches involving the participant)
    ///
    /// Returns `None` if the participant is not involved in any interaction.
    pub fn project(&self, participant: &str) -> Option<LocalType> {
        project_interaction(&self.interaction, participant)
    }
}

fn project_choice(
    decider: &str,
    predicate: &str,
    then_branch: &Interaction,
    else_branch: &Interaction,
    participant: &str,
) -> Option<LocalType> {
    let then_local = project_interaction(then_branch, participant);
    let else_local = project_interaction(else_branch, participant);

    match (then_local, else_local) {
        (Some(then_l), Some(else_l)) => {
            if decider == participant {
                Some(LocalType::InternalChoice {
                    predicate: predicate.to_string(),
                    then_branch: Box::new(then_l),
                    else_branch: Box::new(else_l),
                })
            } else {
                Some(LocalType::ExternalChoice {
                    from: decider.to_string(),
                    then_branch: Box::new(then_l),
                    else_branch: Box::new(else_l),
                })
            }
        }
        // Keep branch structure when only one side has local actions.
        // Collapsing to the single non-empty branch loses control-flow
        // semantics and can force actions that should be conditional.
        (Some(then_l), None) => {
            if decider == participant {
                Some(LocalType::InternalChoice {
                    predicate: predicate.to_string(),
                    then_branch: Box::new(then_l),
                    else_branch: Box::new(LocalType::End),
                })
            } else {
                Some(LocalType::ExternalChoice {
                    from: decider.to_string(),
                    then_branch: Box::new(then_l),
                    else_branch: Box::new(LocalType::End),
                })
            }
        }
        (None, Some(else_l)) => {
            if decider == participant {
                Some(LocalType::InternalChoice {
                    predicate: predicate.to_string(),
                    then_branch: Box::new(LocalType::End),
                    else_branch: Box::new(else_l),
                })
            } else {
                Some(LocalType::ExternalChoice {
                    from: decider.to_string(),
                    then_branch: Box::new(LocalType::End),
                    else_branch: Box::new(else_l),
                })
            }
        }
        (None, None) => None,
    }
}

#[allow(clippy::too_many_lines)]
fn project_interaction(interaction: &Interaction, participant: &str) -> Option<LocalType> {
    match interaction {
        Interaction::Comm {
            sender,
            receiver,
            action,
            msg_type,
            then,
            ..
        } => {
            let then_local = project_interaction(then, participant).unwrap_or(LocalType::End);

            if sender == participant {
                Some(LocalType::Send {
                    action: action.clone(),
                    msg_type: msg_type.clone(),
                    to: receiver.clone(),
                    then: Box::new(then_local),
                })
            } else if receiver == participant {
                Some(LocalType::Recv {
                    action: action.clone(),
                    msg_type: msg_type.clone(),
                    from: sender.clone(),
                    then: Box::new(then_local),
                })
            } else {
                // Participant not involved in this communication
                project_interaction(then, participant)
            }
        }
        Interaction::Choice {
            decider,
            predicate,
            then_branch,
            else_branch,
        } => project_choice(decider, predicate, then_branch, else_branch, participant),
        Interaction::Loop { label, body } => {
            // Only project the loop if the participant is actually referenced
            // in the loop body.  Without this check, a bare `Continue` inside
            // the body would project to `RecVar` for uninvolved participants,
            // creating a vacuous `Rec { body: RecVar }` that `seq_local`
            // treats as a fixed point — silently dropping any actions that
            // follow the loop in a Seq.
            let refs = body.referenced_participants();
            if !refs.contains(participant) {
                return None;
            }
            let body_local = project_interaction(body, participant)?;
            Some(LocalType::Rec {
                label: label.clone(),
                body: Box::new(body_local),
            })
        }
        Interaction::Continue { label } => Some(LocalType::RecVar {
            label: label.clone(),
        }),
        Interaction::End => None,
        Interaction::Compensate {
            forward,
            compensate,
        } => {
            let fwd = project_interaction(forward, participant);
            let comp = project_interaction(compensate, participant);
            match (fwd, comp) {
                (Some(f), Some(c)) => Some(LocalType::Compensate {
                    forward: Box::new(f),
                    compensate: Box::new(c),
                }),
                (Some(f), None) => Some(LocalType::Compensate {
                    forward: Box::new(f),
                    compensate: Box::new(LocalType::End),
                }),
                (None, Some(c)) => Some(LocalType::Compensate {
                    forward: Box::new(LocalType::End),
                    compensate: Box::new(c),
                }),
                (None, None) => None,
            }
        }
        Interaction::Seq { first, second } => {
            let first_local = project_interaction(first, participant);
            let second_local = project_interaction(second, participant);
            match (first_local, second_local) {
                (Some(f), Some(s)) => Some(seq_local(f, s)),
                (Some(f), None) => Some(f),
                (None, Some(s)) => Some(s),
                (None, None) => None,
            }
        }
        Interaction::Par { left, right } => {
            // For projection, a participant can only be in one branch
            // (disjointness is validated separately).
            let left_local = project_interaction(left, participant);
            let right_local = project_interaction(right, participant);
            match (left_local, right_local) {
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                (None, None) => None,
                (Some(l), Some(_)) => {
                    // If participant is in both branches (should be caught
                    // by validation), take the left branch.
                    Some(l)
                }
            }
        }
    }
}

// ---- end project_interaction ----

/// Concatenate two local types sequentially by appending `second` at every
/// `End` leaf of `first`.
fn seq_local(first: LocalType, second: LocalType) -> LocalType {
    match first {
        LocalType::End => second,
        LocalType::Send {
            action,
            msg_type,
            to,
            then,
        } => LocalType::Send {
            action,
            msg_type,
            to,
            then: Box::new(seq_local(*then, second)),
        },
        LocalType::Recv {
            action,
            msg_type,
            from,
            then,
        } => LocalType::Recv {
            action,
            msg_type,
            from,
            then: Box::new(seq_local(*then, second)),
        },
        LocalType::InternalChoice {
            predicate,
            then_branch,
            else_branch,
        } => LocalType::InternalChoice {
            predicate,
            then_branch: Box::new(seq_local(*then_branch, second.clone())),
            else_branch: Box::new(seq_local(*else_branch, second)),
        },
        LocalType::ExternalChoice {
            from,
            then_branch,
            else_branch,
        } => LocalType::ExternalChoice {
            from,
            then_branch: Box::new(seq_local(*then_branch, second.clone())),
            else_branch: Box::new(seq_local(*else_branch, second)),
        },
        LocalType::Rec { label, body } => LocalType::Rec {
            label,
            body: Box::new(seq_local(*body, second)),
        },
        LocalType::RecVar { label } => LocalType::RecVar { label },
        LocalType::Compensate {
            forward,
            compensate,
        } => LocalType::Compensate {
            forward: Box::new(seq_local(*forward, second)),
            compensate,
        },
    }
}

// ============================================================================
// Display implementations
// ============================================================================

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if !self.type_params.is_empty() {
            write!(f, "<{}>", self.type_params.join(", "))?;
        }
        Ok(())
    }
}

impl fmt::Display for Interaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indented(f, 0)
    }
}

impl Interaction {
    fn fmt_indented(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        let pad = "  ".repeat(indent);
        match self {
            Self::Comm {
                sender,
                action,
                msg_type,
                receiver,
                monotonicity,
                then,
            } => {
                let calm_tag = match monotonicity {
                    Some(Monotonicity::Monotone) => " [monotone]",
                    Some(Monotonicity::NonMonotone) => " [non-monotone]",
                    None => "",
                };
                write!(
                    f,
                    "{pad}{sender}.{action}({msg_type}) -> {receiver}{calm_tag}"
                )?;
                if !matches!(**then, Self::End) {
                    writeln!(f)?;
                    then.fmt_indented(f, indent)?;
                }
                Ok(())
            }
            Self::Choice {
                decider,
                predicate,
                then_branch,
                else_branch,
            } => {
                writeln!(f, "{pad}if {decider}.decides({predicate}) {{")?;
                then_branch.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                writeln!(f, "{pad}}} else {{")?;
                else_branch.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::Loop { label, body } => {
                writeln!(f, "{pad}loop {label} {{")?;
                body.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::Continue { label } => write!(f, "{pad}continue {label}"),
            Self::Compensate {
                forward,
                compensate,
            } => {
                writeln!(f, "{pad}compensate {{")?;
                forward.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                writeln!(f, "{pad}}} with {{")?;
                compensate.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::Seq { first, second } => {
                first.fmt_indented(f, indent)?;
                writeln!(f, ";")?;
                second.fmt_indented(f, indent)
            }
            Self::Par { left, right } => {
                writeln!(f, "{pad}par {{")?;
                left.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                writeln!(f, "{pad}}} and {{")?;
                right.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::End => write!(f, "{pad}end"),
        }
    }
}

impl fmt::Display for LocalType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indented(f, 0)
    }
}

impl LocalType {
    fn fmt_indented(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        let pad = "  ".repeat(indent);
        match self {
            Self::Send {
                action,
                msg_type,
                to,
                then,
            } => {
                write!(f, "{pad}!{action}({msg_type}) -> {to}")?;
                if !matches!(**then, Self::End) {
                    writeln!(f)?;
                    then.fmt_indented(f, indent)?;
                }
                Ok(())
            }
            Self::Recv {
                action,
                msg_type,
                from,
                then,
            } => {
                write!(f, "{pad}?{action}({msg_type}) <- {from}")?;
                if !matches!(**then, Self::End) {
                    writeln!(f)?;
                    then.fmt_indented(f, indent)?;
                }
                Ok(())
            }
            Self::InternalChoice {
                predicate,
                then_branch,
                else_branch,
            } => {
                writeln!(f, "{pad}⊕ decides({predicate}) {{")?;
                then_branch.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                writeln!(f, "{pad}}} else {{")?;
                else_branch.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::ExternalChoice {
                from,
                then_branch,
                else_branch,
            } => {
                writeln!(f, "{pad}& offers({from}) {{")?;
                then_branch.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                writeln!(f, "{pad}}} else {{")?;
                else_branch.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::Rec { label, body } => {
                writeln!(f, "{pad}μ{label} {{")?;
                body.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::RecVar { label } => write!(f, "{pad}{label}"),
            Self::Compensate {
                forward,
                compensate,
            } => {
                writeln!(f, "{pad}compensate {{")?;
                forward.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                writeln!(f, "{pad}}} with {{")?;
                compensate.fmt_indented(f, indent + 1)?;
                writeln!(f)?;
                write!(f, "{pad}}}")
            }
            Self::End => write!(f, "{pad}end"),
        }
    }
}

// ============================================================================
// Example protocols (expressiveness analysis)
// ============================================================================

/// Build the canonical two-phase commit choreography.
///
/// ```text
/// protocol two_phase_commit {
///   participant coordinator: saga-coordinator;
///   participant worker: saga-participant;
///
///   coordinator.reserve(ReserveMsg) -> worker
///   if coordinator.decides(commit_ready) {
///     coordinator.commit(CommitMsg) -> worker
///   } else {
///     coordinator.abort(AbortMsg) -> worker
///   }
/// }
/// ```
pub fn example_two_phase_commit() -> GlobalProtocol {
    GlobalProtocol::builder("two_phase_commit")
        .participant("coordinator", "saga-coordinator")
        .participant("worker", "saga-participant")
        .interaction(
            Interaction::comm_calm(
                "coordinator",
                "reserve",
                "ReserveMsg",
                "worker",
                Monotonicity::Monotone,
            )
            .then(Interaction::choice(
                "coordinator",
                "commit_ready",
                Interaction::comm_calm(
                    "coordinator",
                    "commit",
                    "CommitMsg",
                    "worker",
                    Monotonicity::NonMonotone,
                )
                .then(Interaction::end())
                .expect("comm interactions accept continuations"),
                Interaction::comm_calm(
                    "coordinator",
                    "abort",
                    "AbortMsg",
                    "worker",
                    Monotonicity::NonMonotone,
                )
                .then(Interaction::end())
                .expect("comm interactions accept continuations"),
            ))
            .expect("comm interactions accept continuations"),
        )
        .build()
}

/// Build the lease renewal choreography with recursion.
///
/// ```text
/// protocol lease_renewal {
///   participant holder: lease-holder;
///   participant resource: resource-manager;
///
///   holder.acquire(AcquireMsg) -> resource
///   loop renew_loop {
///     if holder.decides(needs_renewal) {
///       holder.renew(RenewMsg) -> resource
///       continue renew_loop
///     } else {
///       holder.release(ReleaseMsg) -> resource
///     }
///   }
/// }
/// ```
pub fn example_lease_renewal() -> GlobalProtocol {
    GlobalProtocol::builder("lease_renewal")
        .participant("holder", "lease-holder")
        .participant("resource", "resource-manager")
        .interaction(
            Interaction::comm_calm(
                "holder",
                "acquire",
                "AcquireMsg",
                "resource",
                Monotonicity::Monotone,
            )
            .then(Interaction::loop_(
                "renew_loop",
                Interaction::choice(
                    "holder",
                    "needs_renewal",
                    Interaction::comm_calm(
                        "holder",
                        "renew",
                        "RenewMsg",
                        "resource",
                        Monotonicity::Monotone,
                    )
                    .then(Interaction::continue_("renew_loop"))
                    .expect("comm interactions accept continuations"),
                    Interaction::comm_calm(
                        "holder",
                        "release",
                        "ReleaseMsg",
                        "resource",
                        Monotonicity::NonMonotone,
                    )
                    .then(Interaction::end())
                    .expect("comm interactions accept continuations"),
                ),
            ))
            .expect("comm interactions accept continuations"),
        )
        .build()
}

/// Build a three-participant saga with compensation.
///
/// ```text
/// protocol saga_with_compensation {
///   participant coordinator: saga-coordinator;
///   participant service_a: saga-participant;
///   participant service_b: saga-participant;
///
///   compensate {
///     coordinator.reserve_a(ReserveMsg) -> service_a
///     coordinator.reserve_b(ReserveMsg) -> service_b
///     if coordinator.decides(all_ok) {
///       coordinator.commit_a(CommitMsg) -> service_a
///       coordinator.commit_b(CommitMsg) -> service_b
///     } else {
///       coordinator.abort_a(AbortMsg) -> service_a
///       coordinator.abort_b(AbortMsg) -> service_b
///     }
///   } with {
///     coordinator.compensate_a(CompensateMsg) -> service_a
///     coordinator.compensate_b(CompensateMsg) -> service_b
///   }
/// }
/// ```
pub fn example_saga_compensation() -> GlobalProtocol {
    GlobalProtocol::builder("saga_with_compensation")
        .participant("coordinator", "saga-coordinator")
        .participant("service_a", "saga-participant")
        .participant("service_b", "saga-participant")
        .interaction(Interaction::compensate(
            Interaction::seq(
                Interaction::comm("coordinator", "reserve_a", "ReserveMsg", "service_a"),
                Interaction::seq(
                    Interaction::comm("coordinator", "reserve_b", "ReserveMsg", "service_b"),
                    Interaction::choice(
                        "coordinator",
                        "all_ok",
                        Interaction::seq(
                            Interaction::comm("coordinator", "commit_a", "CommitMsg", "service_a"),
                            Interaction::comm("coordinator", "commit_b", "CommitMsg", "service_b"),
                        ),
                        Interaction::seq(
                            Interaction::comm("coordinator", "abort_a", "AbortMsg", "service_a"),
                            Interaction::comm("coordinator", "abort_b", "AbortMsg", "service_b"),
                        ),
                    ),
                ),
            ),
            Interaction::seq(
                Interaction::comm("coordinator", "compensate_a", "CompensateMsg", "service_a"),
                Interaction::comm("coordinator", "compensate_b", "CompensateMsg", "service_b"),
            ),
        ))
        .build()
}

/// Build a scatter-gather pattern with parallel composition.
///
/// ```text
/// protocol scatter_gather {
///   participant coordinator: saga-coordinator;
///   participant worker_a: saga-participant;
///   participant worker_b: saga-participant;
///
///   par {
///     coordinator.request_a(RequestMsg) -> worker_a
///     worker_a.response_a(ResponseMsg) -> coordinator
///   } and {
///     coordinator.request_b(RequestMsg) -> worker_b
///     worker_b.response_b(ResponseMsg) -> coordinator
///   }
/// }
/// ```
///
/// Note: This protocol has a participant overlap (coordinator appears in both
/// branches). In a real implementation, you'd use separate coordinator proxies
/// or a multicast primitive. This is included to demonstrate the validation
/// catching the overlap.
pub fn example_scatter_gather_overlap() -> GlobalProtocol {
    GlobalProtocol::builder("scatter_gather")
        .participant("coordinator", "saga-coordinator")
        .participant("worker_a", "saga-participant")
        .participant("worker_b", "saga-participant")
        .interaction(Interaction::par(
            Interaction::seq(
                Interaction::comm("coordinator", "request_a", "RequestMsg", "worker_a"),
                Interaction::comm("worker_a", "response_a", "ResponseMsg", "coordinator"),
            ),
            Interaction::seq(
                Interaction::comm("coordinator", "request_b", "RequestMsg", "worker_b"),
                Interaction::comm("worker_b", "response_b", "ResponseMsg", "coordinator"),
            ),
        ))
        .build()
}

/// Build a valid scatter-gather with disjoint participant sets.
///
/// Uses dedicated proxy participants so parallel branches don't share
/// participants.
pub fn example_scatter_gather_disjoint() -> GlobalProtocol {
    GlobalProtocol::builder("scatter_gather_disjoint")
        .participant("proxy_a", "scatter-proxy")
        .participant("proxy_b", "scatter-proxy")
        .participant("worker_a", "saga-participant")
        .participant("worker_b", "saga-participant")
        .interaction(Interaction::par(
            Interaction::seq(
                Interaction::comm("proxy_a", "request_a", "RequestMsg", "worker_a"),
                Interaction::comm("worker_a", "response_a", "ResponseMsg", "proxy_a"),
            ),
            Interaction::seq(
                Interaction::comm("proxy_b", "request_b", "RequestMsg", "worker_b"),
                Interaction::comm("worker_b", "response_b", "ResponseMsg", "proxy_b"),
            ),
        ))
        .build()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
