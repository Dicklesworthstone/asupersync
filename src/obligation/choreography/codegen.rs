// Module-level clippy allows matching the parent module (bd-1f8jn.2).
#![allow(clippy::must_use_candidate)]
#![allow(clippy::use_self)]

//! Code generation from choreographic projection (bd-1f8jn.2).
//!
//! Takes a [`GlobalProtocol`] and generates per-participant Rust code:
//! - Session type aliases mapping to the existing `session_types` primitives
//! - Message structs for each communication action
//! - Async handler function skeletons with the correct protocol flow
//!
//! # Architecture
//!
//! ```text
//! GlobalProtocol
//!   ↓ validate()
//! Vec<ValidationError>  (must be empty)
//!   ↓ project(participant)
//! LocalType
//!   ↓ ProjectionCompiler::compile()
//! ProjectionOutput
//!   ↓ render()
//! String  (Rust source code)
//! ```

use super::{GlobalProtocol, Interaction, LocalType, ValidationError};
use crate::obligation::calm::Monotonicity;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;

// ============================================================================
// Projection compiler
// ============================================================================

/// Output of the projection compiler for a single participant.
#[derive(Debug, Clone)]
pub struct ProjectionOutput {
    /// Protocol name.
    pub protocol_name: String,
    /// Participant name this projection is for.
    pub participant_name: String,
    /// Participant role.
    pub participant_role: String,
    /// Generated session type alias (Rust type expression).
    pub session_type: String,
    /// Message structs needed by this participant.
    pub message_structs: Vec<GeneratedMessage>,
    /// Async handler function skeleton.
    pub handler_skeleton: String,
    /// Per-communication CALM annotations for saga optimization.
    pub calm_annotations: Vec<CalmAnnotation>,
    /// Number of local states in the projected protocol.
    pub local_state_count: usize,
    /// Number of local transitions.
    pub local_transition_count: usize,
}

/// A generated message struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedMessage {
    /// Struct name (PascalCase).
    pub name: String,
    /// Whether the message carries payload (has type params).
    pub has_payload: bool,
    /// Type parameters, if any.
    pub type_params: Vec<String>,
}

/// CALM annotation on a projected communication.
#[derive(Debug, Clone)]
pub struct CalmAnnotation {
    /// Action label.
    pub action: String,
    /// Direction (send or recv).
    pub direction: &'static str,
    /// Peer participant.
    pub peer: String,
    /// Monotonicity classification.
    pub monotonicity: Monotonicity,
}

/// Error during projection compilation.
#[derive(Debug, Clone)]
pub enum CompilationError {
    /// Protocol validation failed.
    ValidationFailed(Vec<ValidationError>),
    /// Participant not found in protocol.
    ParticipantNotFound {
        /// The missing participant name.
        name: String,
    },
    /// Projection produced no local type (participant uninvolved).
    EmptyProjection {
        /// Participant name.
        participant: String,
    },
}

impl fmt::Display for CompilationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidationFailed(errors) => {
                write!(f, "protocol validation failed: ")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            Self::ParticipantNotFound { name } => {
                write!(f, "participant '{name}' not declared in protocol")
            }
            Self::EmptyProjection { participant } => {
                write!(
                    f,
                    "projection for '{participant}' is empty (not involved in any interaction)"
                )
            }
        }
    }
}

/// Projection compiler: validates, projects, and generates code from choreographies.
#[derive(Debug)]
pub struct ProjectionCompiler {
    /// Whether to include tracing spans in generated code.
    pub include_tracing: bool,
}

impl Default for ProjectionCompiler {
    fn default() -> Self {
        Self {
            include_tracing: true,
        }
    }
}

impl ProjectionCompiler {
    /// Create a new projection compiler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Compile a global protocol for a specific participant.
    ///
    /// Validates the protocol, projects it to a local type, and generates
    /// Rust code including session type aliases, message structs, and
    /// handler function skeletons.
    pub fn compile(
        &self,
        protocol: &GlobalProtocol,
        participant: &str,
    ) -> Result<ProjectionOutput, CompilationError> {
        // Step 1: Validate
        let errors = protocol.validate();
        if !errors.is_empty() {
            return Err(CompilationError::ValidationFailed(errors));
        }

        // Step 2: Check participant exists
        if !protocol.participants.contains_key(participant) {
            return Err(CompilationError::ParticipantNotFound {
                name: participant.to_string(),
            });
        }

        // Step 3: Project
        let local_type =
            protocol
                .project(participant)
                .ok_or_else(|| CompilationError::EmptyProjection {
                    participant: participant.to_string(),
                })?;

        // Step 4: Collect messages
        let messages = collect_messages(&protocol.interaction, participant);

        // Step 5: Collect CALM annotations
        let calm = collect_calm_annotations(&protocol.interaction, participant);

        // Step 6: Count states and transitions
        let (states, transitions) = count_local_complexity(&local_type);

        // Step 7: Generate session type
        let session_type = render_session_type(&local_type);

        // Step 8: Generate handler skeleton
        let role = &protocol.participants[participant].role;
        let handler = render_handler(
            &protocol.name,
            participant,
            role,
            &local_type,
            self.include_tracing,
        );

        Ok(ProjectionOutput {
            protocol_name: protocol.name.clone(),
            participant_name: participant.to_string(),
            participant_role: role.clone(),
            session_type,
            message_structs: messages,
            handler_skeleton: handler,
            calm_annotations: calm,
            local_state_count: states,
            local_transition_count: transitions,
        })
    }

    /// Compile a global protocol for all participants.
    ///
    /// Returns a map from participant name to projection output.
    pub fn compile_all(
        &self,
        protocol: &GlobalProtocol,
    ) -> Result<BTreeMap<String, ProjectionOutput>, CompilationError> {
        let errors = protocol.validate();
        if !errors.is_empty() {
            return Err(CompilationError::ValidationFailed(errors));
        }

        let mut outputs = BTreeMap::new();
        for name in protocol.participants.keys() {
            match self.compile(protocol, name) {
                Ok(output) => {
                    outputs.insert(name.clone(), output);
                }
                Err(CompilationError::EmptyProjection { .. }) => {
                    // Skip participants not involved in any interaction
                }
                Err(e) => return Err(e),
            }
        }
        Ok(outputs)
    }
}

// ============================================================================
// Message collection
// ============================================================================

fn collect_messages(interaction: &Interaction, participant: &str) -> Vec<GeneratedMessage> {
    let mut seen = BTreeSet::new();
    let mut messages = Vec::new();
    collect_messages_recursive(interaction, participant, &mut seen, &mut messages);
    messages
}

fn collect_messages_recursive(
    interaction: &Interaction,
    participant: &str,
    seen: &mut BTreeSet<String>,
    out: &mut Vec<GeneratedMessage>,
) {
    match interaction {
        Interaction::Comm {
            sender,
            receiver,
            msg_type,
            then,
            ..
        } => {
            if (sender == participant || receiver == participant)
                && seen.insert(msg_type.name.clone())
            {
                out.push(GeneratedMessage {
                    name: msg_type.name.clone(),
                    has_payload: !msg_type.type_params.is_empty(),
                    type_params: msg_type.type_params.clone(),
                });
            }
            collect_messages_recursive(then, participant, seen, out);
        }
        Interaction::Choice {
            then_branch,
            else_branch,
            ..
        } => {
            collect_messages_recursive(then_branch, participant, seen, out);
            collect_messages_recursive(else_branch, participant, seen, out);
        }
        Interaction::Loop { body, .. } => {
            collect_messages_recursive(body, participant, seen, out);
        }
        Interaction::Compensate {
            forward,
            compensate,
        } => {
            collect_messages_recursive(forward, participant, seen, out);
            collect_messages_recursive(compensate, participant, seen, out);
        }
        Interaction::Seq { first, second } => {
            collect_messages_recursive(first, participant, seen, out);
            collect_messages_recursive(second, participant, seen, out);
        }
        Interaction::Par { left, right } => {
            collect_messages_recursive(left, participant, seen, out);
            collect_messages_recursive(right, participant, seen, out);
        }
        Interaction::Continue { .. } | Interaction::End => {}
    }
}

// ============================================================================
// CALM annotation collection
// ============================================================================

fn collect_calm_annotations(interaction: &Interaction, participant: &str) -> Vec<CalmAnnotation> {
    let mut annotations = Vec::new();
    collect_calm_recursive(interaction, participant, &mut annotations);
    annotations
}

fn collect_calm_recursive(
    interaction: &Interaction,
    participant: &str,
    out: &mut Vec<CalmAnnotation>,
) {
    match interaction {
        Interaction::Comm {
            sender,
            receiver,
            action,
            monotonicity,
            then,
            ..
        } => {
            if let Some(mono) = monotonicity {
                if sender == participant {
                    out.push(CalmAnnotation {
                        action: action.clone(),
                        direction: "send",
                        peer: receiver.clone(),
                        monotonicity: *mono,
                    });
                } else if receiver == participant {
                    out.push(CalmAnnotation {
                        action: action.clone(),
                        direction: "recv",
                        peer: sender.clone(),
                        monotonicity: *mono,
                    });
                }
            }
            collect_calm_recursive(then, participant, out);
        }
        Interaction::Choice {
            then_branch,
            else_branch,
            ..
        } => {
            collect_calm_recursive(then_branch, participant, out);
            collect_calm_recursive(else_branch, participant, out);
        }
        Interaction::Loop { body, .. } => {
            collect_calm_recursive(body, participant, out);
        }
        Interaction::Compensate {
            forward,
            compensate,
        } => {
            collect_calm_recursive(forward, participant, out);
            collect_calm_recursive(compensate, participant, out);
        }
        Interaction::Seq { first, second } => {
            collect_calm_recursive(first, participant, out);
            collect_calm_recursive(second, participant, out);
        }
        Interaction::Par { left, right } => {
            collect_calm_recursive(left, participant, out);
            collect_calm_recursive(right, participant, out);
        }
        Interaction::Continue { .. } | Interaction::End => {}
    }
}

// ============================================================================
// Local complexity counting
// ============================================================================

fn count_local_complexity(local: &LocalType) -> (usize, usize) {
    let mut states = 0;
    let mut transitions = 0;
    count_local_recursive(local, &mut states, &mut transitions);
    (states, transitions)
}

fn count_local_recursive(local: &LocalType, states: &mut usize, transitions: &mut usize) {
    *states += 1;
    match local {
        LocalType::Send { then, .. } | LocalType::Recv { then, .. } => {
            *transitions += 1;
            count_local_recursive(then, states, transitions);
        }
        LocalType::InternalChoice {
            then_branch,
            else_branch,
            ..
        }
        | LocalType::ExternalChoice {
            then_branch,
            else_branch,
            ..
        } => {
            *transitions += 2;
            count_local_recursive(then_branch, states, transitions);
            count_local_recursive(else_branch, states, transitions);
        }
        LocalType::Rec { body, .. } => {
            count_local_recursive(body, states, transitions);
        }
        LocalType::RecVar { .. } => {
            *transitions += 1; // back-edge
        }
        LocalType::Compensate {
            forward,
            compensate,
        } => {
            count_local_recursive(forward, states, transitions);
            count_local_recursive(compensate, states, transitions);
        }
        LocalType::End => {}
    }
}

// ============================================================================
// Session type rendering
// ============================================================================

fn render_session_type(local: &LocalType) -> String {
    match local {
        LocalType::End => "End".to_string(),
        LocalType::Send { msg_type, then, .. } => {
            let then_ty = render_session_type(then);
            format!("Send<{msg_type}, {then_ty}>")
        }
        LocalType::Recv { msg_type, then, .. } => {
            let then_ty = render_session_type(then);
            format!("Recv<{msg_type}, {then_ty}>")
        }
        LocalType::InternalChoice {
            then_branch,
            else_branch,
            ..
        } => {
            let a = render_session_type(then_branch);
            let b = render_session_type(else_branch);
            format!("Select<{a}, {b}>")
        }
        LocalType::ExternalChoice {
            then_branch,
            else_branch,
            ..
        } => {
            let a = render_session_type(then_branch);
            let b = render_session_type(else_branch);
            format!("Offer<{a}, {b}>")
        }
        LocalType::Rec { label, body } => {
            let body_ty = render_session_type(body);
            format!("Rec_{label}<{body_ty}>")
        }
        LocalType::RecVar { label } => format!("Var_{label}"),
        LocalType::Compensate { forward, .. } => {
            // Compensation is a runtime concern; the session type
            // only reflects the forward path.
            render_session_type(forward)
        }
    }
}

fn entry_channel_role(local: &LocalType) -> &'static str {
    match local {
        LocalType::Send { .. } | LocalType::InternalChoice { .. } => "Initiator",
        LocalType::Recv { .. } | LocalType::ExternalChoice { .. } => "Responder",
        LocalType::Rec { body, .. } => entry_channel_role(body),
        LocalType::Compensate { forward, .. } => entry_channel_role(forward),
        LocalType::RecVar { .. } | LocalType::End => "Initiator",
    }
}

// ============================================================================
// Handler code generation
// ============================================================================

fn render_handler(
    protocol: &str,
    participant: &str,
    role: &str,
    local: &LocalType,
    include_tracing: bool,
) -> String {
    let fn_name = format!("{protocol}_{participant}");
    let mut code = String::new();

    // Module header
    writeln!(code, "//! Generated by choreographic projection compiler.").ok();
    writeln!(code, "//! Protocol: {protocol}").ok();
    writeln!(code, "//! Participant: {participant} (role: {role})").ok();
    writeln!(code, "//!").ok();
    writeln!(
        code,
        "//! DO NOT EDIT — regenerate from the global choreography."
    )
    .ok();
    writeln!(code).ok();

    // Imports
    writeln!(code, "use asupersync::obligation::session_types::{{").ok();
    writeln!(
        code,
        "    Chan, End, Send, Recv, Select, Offer, Initiator, Responder,"
    )
    .ok();
    writeln!(code, "}};").ok();
    writeln!(code, "use asupersync::record::ObligationKind;").ok();
    if include_tracing {
        writeln!(code).ok();
        writeln!(code, "// Tracing spans (bd-1f8jn.2 spec):").ok();
        writeln!(
            code,
            "// Span: compiler::project with protocol_name=\"{protocol}\", participant_name=\"{participant}\""
        ).ok();
    }
    writeln!(code).ok();

    // Message structs
    writeln!(code, "// --- Message types ---").ok();
    writeln!(code).ok();
    render_message_skeletons(local, &mut code, &mut BTreeSet::new());
    writeln!(code).ok();

    // Session type alias
    let session_ty = render_session_type(local);
    let entry_role = entry_channel_role(local);
    writeln!(code, "/// Session type for {participant} in {protocol}.").ok();
    writeln!(code, "pub type {participant}_Session = {session_ty};").ok();
    writeln!(code).ok();

    // Handler function
    writeln!(
        code,
        "/// Handler for {participant} in the {protocol} choreography."
    )
    .ok();
    writeln!(code, "pub async fn {fn_name}(").ok();
    writeln!(code, "    chan: Chan<{entry_role}, {participant}_Session>,").ok();
    writeln!(code, ") {{").ok();

    render_handler_body(local, &mut code, 1);

    writeln!(code, "}}").ok();

    code
}

fn render_message_skeletons(local: &LocalType, code: &mut String, seen: &mut BTreeSet<String>) {
    match local {
        LocalType::Send { msg_type, then, .. } | LocalType::Recv { msg_type, then, .. } => {
            if seen.insert(msg_type.name.clone()) {
                writeln!(code, "#[derive(Debug, Clone)]").ok();
                writeln!(code, "pub struct {};", msg_type.name).ok();
                writeln!(code).ok();
            }
            render_message_skeletons(then, code, seen);
        }
        LocalType::InternalChoice {
            then_branch,
            else_branch,
            ..
        }
        | LocalType::ExternalChoice {
            then_branch,
            else_branch,
            ..
        } => {
            render_message_skeletons(then_branch, code, seen);
            render_message_skeletons(else_branch, code, seen);
        }
        LocalType::Rec { body, .. } => {
            render_message_skeletons(body, code, seen);
        }
        LocalType::Compensate {
            forward,
            compensate,
        } => {
            render_message_skeletons(forward, code, seen);
            render_message_skeletons(compensate, code, seen);
        }
        LocalType::RecVar { .. } | LocalType::End => {}
    }
}

fn render_handler_body(local: &LocalType, code: &mut String, indent: usize) {
    let pad = "    ".repeat(indent);
    match local {
        LocalType::Send {
            action,
            msg_type,
            to,
            then,
            ..
        } => {
            writeln!(code, "{pad}// Send {action}({msg_type}) to {to}").ok();
            writeln!(
                code,
                "{pad}let chan = chan.send({msg_type} {{ /* fields */ }});"
            )
            .ok();
            render_handler_body(then, code, indent);
        }
        LocalType::Recv {
            action,
            msg_type,
            from,
            then,
            ..
        } => {
            writeln!(code, "{pad}// Receive {action}({msg_type}) from {from}").ok();
            writeln!(code, "{pad}let (msg, chan) = chan.recv();").ok();
            render_handler_body(then, code, indent);
        }
        LocalType::InternalChoice {
            predicate,
            then_branch,
            else_branch,
            ..
        } => {
            writeln!(code, "{pad}// Internal choice: decides({predicate})").ok();
            writeln!(code, "{pad}if /* {predicate} */ true {{").ok();
            writeln!(code, "{pad}    let chan = chan.select_left();").ok();
            render_handler_body(then_branch, code, indent + 1);
            writeln!(code, "{pad}}} else {{").ok();
            writeln!(code, "{pad}    let chan = chan.select_right();").ok();
            render_handler_body(else_branch, code, indent + 1);
            writeln!(code, "{pad}}}").ok();
        }
        LocalType::ExternalChoice {
            from,
            then_branch,
            else_branch,
            ..
        } => {
            writeln!(code, "{pad}// External choice: offered by {from}").ok();
            writeln!(code, "{pad}match chan.offer() {{").ok();
            writeln!(code, "{pad}    Left(chan) => {{").ok();
            render_handler_body(then_branch, code, indent + 2);
            writeln!(code, "{pad}    }}").ok();
            writeln!(code, "{pad}    Right(chan) => {{").ok();
            render_handler_body(else_branch, code, indent + 2);
            writeln!(code, "{pad}    }}").ok();
            writeln!(code, "{pad}}}").ok();
        }
        LocalType::Rec { label, body } => {
            writeln!(code, "{pad}// Loop: {label}").ok();
            writeln!(code, "{pad}loop {{").ok();
            render_handler_body(body, code, indent + 1);
            writeln!(code, "{pad}    break;").ok();
            writeln!(code, "{pad}}}").ok();
        }
        LocalType::RecVar { label } => {
            writeln!(code, "{pad}continue; // -> {label}").ok();
        }
        LocalType::Compensate {
            forward,
            compensate,
        } => {
            writeln!(code, "{pad}// Compensation block").ok();
            writeln!(code, "{pad}// Forward:").ok();
            render_handler_body(forward, code, indent);
            writeln!(code, "{pad}// Compensation (on failure):").ok();
            writeln!(code, "{pad}// {{").ok();
            let mut compensation_skeleton = String::new();
            render_handler_body(compensate, &mut compensation_skeleton, 0);
            for line in compensation_skeleton.lines() {
                if line.is_empty() {
                    writeln!(code, "{pad}//").ok();
                } else {
                    writeln!(code, "{pad}// {line}").ok();
                }
            }
            writeln!(code, "{pad}// }}").ok();
        }
        LocalType::End => {
            writeln!(code, "{pad}// Protocol complete").ok();
            writeln!(code, "{pad}chan.close();").ok();
        }
    }
}

// ============================================================================
// Full module rendering
// ============================================================================

impl ProjectionOutput {
    /// Render the complete Rust source code for this projection.
    pub fn render(&self) -> String {
        self.handler_skeleton.clone()
    }

    /// Render a summary of the projection (for logging/diagnostics).
    pub fn summary(&self) -> String {
        format!(
            "Projection: {} -> {} (role: {}, states: {}, transitions: {}, messages: {}, calm_annotations: {})",
            self.protocol_name,
            self.participant_name,
            self.participant_role,
            self.local_state_count,
            self.local_transition_count,
            self.message_structs.len(),
            self.calm_annotations.len(),
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "codegen_inline_tests.rs"]
mod tests;
