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
//!                     .then(Interaction::end()),
//!                 Interaction::comm("coordinator", "abort", "AbortMsg", "worker")
//!                     .then(Interaction::end()),
//!             )),
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

use crate::obligation::calm::Monotonicity;
use std::collections::{BTreeMap, BTreeSet, HashSet};
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
}

impl GlobalProtocol {
    /// Start building a new global protocol.
    pub fn builder(name: &str) -> ProtocolBuilder {
        ProtocolBuilder {
            name: name.to_string(),
            participants: BTreeMap::new(),
            interaction: None,
        }
    }
}

impl ProtocolBuilder {
    /// Add a participant with the given name and role.
    #[must_use]
    pub fn participant(mut self, name: &str, role: &str) -> Self {
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
    ///
    /// # Panics
    ///
    /// Panics if no interaction was set.
    pub fn build(self) -> GlobalProtocol {
        GlobalProtocol {
            name: self.name,
            participants: self.participants,
            interaction: self.interaction.expect("interaction must be set"),
        }
    }
}

// ============================================================================
// Interaction constructors
// ============================================================================

impl Interaction {
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
    ///
    /// # Panics
    ///
    /// Panics if called on a non-`Comm` variant.
    #[must_use]
    pub fn then(mut self, next: Interaction) -> Self {
        match &mut self {
            Self::Comm { then, .. } => {
                **then = next;
            }
            _ => panic!("then() can only be called on Comm interactions"),
        }
        self
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
    fn first_active_participant(&self) -> Option<&str> {
        match self {
            Self::Comm { sender, .. } => Some(sender),
            Self::Choice { decider, .. } => Some(decider),
            Self::Loop { body, .. } => body.first_active_participant(),
            Self::Continue { .. } | Self::End => None,
            Self::Compensate { forward, .. } => forward.first_active_participant(),
            Self::Seq { first, .. } => first.first_active_participant(),
            Self::Par { left, .. } => left.first_active_participant(),
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
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

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
        let mut loop_labels = HashSet::new();
        self.validate_interaction(&self.interaction, &declared, &mut loop_labels, &mut errors);

        errors
    }

    fn validate_interaction(
        &self,
        interaction: &Interaction,
        declared: &BTreeSet<&str>,
        loop_labels: &mut HashSet<String>,
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
                if !loop_labels.insert(label.clone()) {
                    errors.push(ValidationError::DuplicateLoopLabel {
                        label: label.clone(),
                    });
                }
                self.validate_interaction(body, declared, loop_labels, errors);
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
        match branch.first_active_participant() {
            Some(first_sender) if first_sender == decider => {
                // OK: decider is the first sender
            }
            Some(first_sender) => {
                errors.push(ValidationError::KnowledgeOfChoice {
                    decider: decider.to_string(),
                    branch: branch_name,
                    first_sender: Some(first_sender.to_string()),
                });
            }
            None => {
                // Branch is End or Continue — acceptable (trivial branches).
            }
        }
    }

    /// Check whether the protocol is deadlock-free.
    ///
    /// A protocol is deadlock-free if it passes all validation checks,
    /// in particular the knowledge-of-choice condition on every branch.
    pub fn is_deadlock_free(&self) -> bool {
        self.validate()
            .iter()
            .all(|e| !matches!(e, ValidationError::KnowledgeOfChoice { .. }))
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
                stats.comm_count += 1;
                match monotonicity {
                    Some(Monotonicity::Monotone) => stats.monotone_comm_count += 1,
                    Some(Monotonicity::NonMonotone) => stats.non_monotone_comm_count += 1,
                    None => {}
                }
                Self::count_interaction(then, depth + 1, stats);
            }
            Interaction::Choice {
                then_branch,
                else_branch,
                ..
            } => {
                stats.choice_count += 1;
                Self::count_interaction(then_branch, depth + 1, stats);
                Self::count_interaction(else_branch, depth + 1, stats);
            }
            Interaction::Loop { body, .. } => {
                stats.loop_count += 1;
                Self::count_interaction(body, depth + 1, stats);
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
        (Some(local), None) | (None, Some(local)) => Some(local),
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
                (Some(f), None) => Some(f),
                (None, Some(c)) => Some(c),
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
                .then(Interaction::end()),
                Interaction::comm_calm(
                    "coordinator",
                    "abort",
                    "AbortMsg",
                    "worker",
                    Monotonicity::NonMonotone,
                )
                .then(Interaction::end()),
            )),
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
                    .then(Interaction::continue_("renew_loop")),
                    Interaction::comm_calm(
                        "holder",
                        "release",
                        "ReleaseMsg",
                        "resource",
                        Monotonicity::NonMonotone,
                    )
                    .then(Interaction::end()),
                ),
            )),
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
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Validation: well-formed protocols
    // ------------------------------------------------------------------

    #[test]
    fn two_phase_commit_validates() {
        let protocol = example_two_phase_commit();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    #[test]
    fn two_phase_commit_is_deadlock_free() {
        let protocol = example_two_phase_commit();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn lease_renewal_validates() {
        let protocol = example_lease_renewal();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    #[test]
    fn lease_renewal_is_deadlock_free() {
        let protocol = example_lease_renewal();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn saga_compensation_validates() {
        let protocol = example_saga_compensation();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    #[test]
    fn saga_compensation_is_deadlock_free() {
        let protocol = example_saga_compensation();
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn scatter_gather_disjoint_validates() {
        let protocol = example_scatter_gather_disjoint();
        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
    }

    // ------------------------------------------------------------------
    // Validation: error detection
    // ------------------------------------------------------------------

    #[test]
    fn detects_self_communication() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role")
            .interaction(
                Interaction::comm("alice", "ping", "Ping", "alice").then(Interaction::end()),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::SelfCommunication { .. })));
    }

    #[test]
    fn detects_undeclared_participant() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role")
            .interaction(Interaction::comm("alice", "ping", "Ping", "bob").then(Interaction::end()))
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::UndeclaredParticipant { name, .. } if name == "bob")
        ));
    }

    #[test]
    fn detects_knowledge_of_choice_violation() {
        // bob decides but alice sends first in the then-branch
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role-a")
            .participant("bob", "role-b")
            .interaction(Interaction::choice(
                "bob",
                "some_pred",
                // then-branch: alice sends first — violation!
                Interaction::comm("alice", "msg", "Msg", "bob").then(Interaction::end()),
                // else-branch: bob sends — ok
                Interaction::comm("bob", "msg", "Msg", "alice").then(Interaction::end()),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::KnowledgeOfChoice { branch: "then", .. })));
        assert!(!protocol.is_deadlock_free());
    }

    #[test]
    fn detects_undefined_loop_label() {
        let protocol = GlobalProtocol::builder("bad")
            .participant("alice", "role")
            .participant("bob", "role")
            .interaction(
                Interaction::comm("alice", "msg", "Msg", "bob")
                    .then(Interaction::continue_("nonexistent")),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(
            |e| matches!(e, ValidationError::UndefinedLoopLabel { label } if label == "nonexistent")
        ));
    }

    #[test]
    fn detects_parallel_participant_overlap() {
        let protocol = example_scatter_gather_overlap();
        let errors = protocol.validate();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::ParallelParticipantOverlap { participant } if participant == "coordinator")));
    }

    #[test]
    fn detects_empty_protocol() {
        let protocol = GlobalProtocol::builder("empty")
            .participant("alice", "role")
            .interaction(Interaction::end())
            .build();

        let errors = protocol.validate();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::EmptyProtocol)));
    }

    #[test]
    fn detects_no_participants() {
        let protocol = GlobalProtocol::builder("no_parts")
            .interaction(Interaction::end())
            .build();

        let errors = protocol.validate();
        assert!(errors
            .iter()
            .any(|e| matches!(e, ValidationError::NoParticipants)));
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    #[test]
    fn two_phase_commit_stats() {
        let protocol = example_two_phase_commit();
        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 3); // reserve, commit, abort
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.loop_count, 0);
        assert_eq!(stats.participant_count, 2);
        assert_eq!(stats.monotone_comm_count, 1); // reserve
        assert_eq!(stats.non_monotone_comm_count, 2); // commit, abort
    }

    #[test]
    fn lease_renewal_stats() {
        let protocol = example_lease_renewal();
        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 3); // acquire, renew, release
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.loop_count, 1);
        assert_eq!(stats.participant_count, 2);
    }

    #[test]
    fn saga_compensation_stats() {
        let protocol = example_saga_compensation();
        let stats = protocol.stats();
        assert_eq!(stats.compensate_count, 1);
        assert_eq!(stats.choice_count, 1);
        assert_eq!(stats.participant_count, 3);
    }

    // ------------------------------------------------------------------
    // Projection
    // ------------------------------------------------------------------

    #[test]
    fn project_two_phase_commit_coordinator() {
        let protocol = example_two_phase_commit();
        let local = protocol.project("coordinator").expect("projection failed");

        // Coordinator should: send reserve, then internal choice (commit or abort)
        match &local {
            LocalType::Send {
                action, to, then, ..
            } => {
                assert_eq!(action, "reserve");
                assert_eq!(to, "worker");
                match then.as_ref() {
                    LocalType::InternalChoice { predicate, .. } => {
                        assert_eq!(predicate, "commit_ready");
                    }
                    other => panic!("Expected InternalChoice, got {other}"),
                }
            }
            other => panic!("Expected Send, got {other}"),
        }
    }

    #[test]
    fn project_two_phase_commit_worker() {
        let protocol = example_two_phase_commit();
        let local = protocol.project("worker").expect("projection failed");

        // Worker should: recv reserve, then external choice
        match &local {
            LocalType::Recv {
                action, from, then, ..
            } => {
                assert_eq!(action, "reserve");
                assert_eq!(from, "coordinator");
                match then.as_ref() {
                    LocalType::ExternalChoice { from, .. } => {
                        assert_eq!(from, "coordinator");
                    }
                    other => panic!("Expected ExternalChoice, got {other}"),
                }
            }
            other => panic!("Expected Recv, got {other}"),
        }
    }

    #[test]
    fn project_lease_renewal_holder() {
        let protocol = example_lease_renewal();
        let local = protocol.project("holder").expect("projection failed");

        // Holder: send acquire, then recursive loop with internal choice
        match &local {
            LocalType::Send { action, then, .. } => {
                assert_eq!(action, "acquire");
                match then.as_ref() {
                    LocalType::Rec { label, .. } => {
                        assert_eq!(label, "renew_loop");
                    }
                    other => panic!("Expected Rec, got {other}"),
                }
            }
            other => panic!("Expected Send, got {other}"),
        }
    }

    #[test]
    fn project_returns_none_for_uninvolved_participant() {
        let protocol = example_two_phase_commit();
        assert!(protocol.project("uninvolved").is_none());
    }

    // ------------------------------------------------------------------
    // Display
    // ------------------------------------------------------------------

    #[test]
    fn display_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let output = format!("{}", protocol.interaction);
        assert!(output.contains("coordinator.reserve(ReserveMsg) -> worker"));
        assert!(output.contains("coordinator.decides(commit_ready)"));
        assert!(output.contains("[monotone]"));
    }

    #[test]
    fn display_local_type() {
        let protocol = example_two_phase_commit();
        let local = protocol.project("coordinator").unwrap();
        let output = format!("{local}");
        assert!(output.contains("!reserve(ReserveMsg) -> worker"));
        assert!(output.contains("decides(commit_ready)"));
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn nested_choice_validates() {
        let protocol = GlobalProtocol::builder("nested_choice")
            .participant("a", "role-a")
            .participant("b", "role-b")
            .interaction(Interaction::choice(
                "a",
                "outer",
                Interaction::comm("a", "m1", "M1", "b").then(Interaction::choice(
                    "a",
                    "inner",
                    Interaction::comm("a", "m2", "M2", "b").then(Interaction::end()),
                    Interaction::comm("a", "m3", "M3", "b").then(Interaction::end()),
                )),
                Interaction::comm("a", "m4", "M4", "b").then(Interaction::end()),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.is_empty(), "Unexpected errors: {errors:?}");
        assert!(protocol.is_deadlock_free());
    }

    #[test]
    fn generic_message_type() {
        let protocol = GlobalProtocol::builder("generic")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(
                Interaction::comm_generic("a", "send", "Payload", &["T"], "b")
                    .then(Interaction::end()),
            )
            .build();

        let errors = protocol.validate();
        assert!(errors.is_empty());

        let stats = protocol.stats();
        assert_eq!(stats.comm_count, 1);

        let output = format!("{}", protocol.interaction);
        assert!(output.contains("Payload<T>"));
    }

    #[test]
    fn compensation_projection() {
        let protocol = example_saga_compensation();
        let local_coord = protocol.project("coordinator").expect("projection failed");

        match &local_coord {
            LocalType::Compensate {
                forward,
                compensate,
            } => {
                // Forward should start with a send
                match forward.as_ref() {
                    LocalType::Send { action, .. } => assert_eq!(action, "reserve_a"),
                    other => panic!("Expected Send in forward, got {other}"),
                }
                // Compensate should start with a send
                match compensate.as_ref() {
                    LocalType::Send { action, .. } => assert_eq!(action, "compensate_a"),
                    other => panic!("Expected Send in compensate, got {other}"),
                }
            }
            other => panic!("Expected Compensate, got {other}"),
        }
    }

    #[test]
    fn duplicate_loop_label_detected() {
        let protocol = GlobalProtocol::builder("dup_labels")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::loop_(
                "x",
                Interaction::comm("a", "m", "M", "b").then(Interaction::loop_(
                    "x", // duplicate!
                    Interaction::comm("a", "n", "N", "b").then(Interaction::continue_("x")),
                )),
            ))
            .build();

        let errors = protocol.validate();
        assert!(errors.iter().any(|e| matches!(
            e,
            ValidationError::DuplicateLoopLabel { label } if label == "x"
        )));
    }
}
