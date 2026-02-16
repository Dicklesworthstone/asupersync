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
    render_message_stubs(local, &mut code, &mut BTreeSet::new());
    writeln!(code).ok();

    // Session type alias
    let session_ty = render_session_type(local);
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
    writeln!(code, "    chan: Chan<Initiator, {participant}_Session>,").ok();
    writeln!(code, ") {{").ok();

    render_handler_body(local, &mut code, 1);

    writeln!(code, "}}").ok();

    code
}

fn render_message_stubs(local: &LocalType, code: &mut String, seen: &mut BTreeSet<String>) {
    match local {
        LocalType::Send { msg_type, then, .. } | LocalType::Recv { msg_type, then, .. } => {
            if seen.insert(msg_type.name.clone()) {
                writeln!(code, "#[derive(Debug, Clone)]").ok();
                writeln!(code, "pub struct {};", msg_type.name).ok();
                writeln!(code).ok();
            }
            render_message_stubs(then, code, seen);
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
            render_message_stubs(then_branch, code, seen);
            render_message_stubs(else_branch, code, seen);
        }
        LocalType::Rec { body, .. } => {
            render_message_stubs(body, code, seen);
        }
        LocalType::Compensate {
            forward,
            compensate,
        } => {
            render_message_stubs(forward, code, seen);
            render_message_stubs(compensate, code, seen);
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
            let mut compensation_stub = String::new();
            render_handler_body(compensate, &mut compensation_stub, 0);
            for line in compensation_stub.lines() {
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
mod tests {
    use super::*;
    use crate::obligation::choreography::{
        example_lease_renewal, example_saga_compensation, example_two_phase_commit,
    };

    fn compiler() -> ProjectionCompiler {
        ProjectionCompiler::new()
    }

    // ------------------------------------------------------------------
    // Basic compilation
    // ------------------------------------------------------------------

    #[test]
    fn compile_two_phase_commit_coordinator() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        assert_eq!(output.protocol_name, "two_phase_commit");
        assert_eq!(output.participant_name, "coordinator");
        assert_eq!(output.participant_role, "saga-coordinator");
        assert!(output.local_state_count > 0);
        assert!(output.local_transition_count > 0);
    }

    #[test]
    fn compile_two_phase_commit_worker() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");

        assert_eq!(output.participant_name, "worker");
        assert_eq!(output.participant_role, "saga-participant");
    }

    #[test]
    fn compile_all_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let outputs = compiler()
            .compile_all(&protocol)
            .expect("compilation failed");

        assert_eq!(outputs.len(), 2);
        assert!(outputs.contains_key("coordinator"));
        assert!(outputs.contains_key("worker"));
    }

    #[test]
    fn compile_lease_renewal() {
        let protocol = example_lease_renewal();
        let output = compiler()
            .compile(&protocol, "holder")
            .expect("compilation failed");

        assert_eq!(output.protocol_name, "lease_renewal");
        // Should have 3 messages: Acquire, Renew, Release
        assert_eq!(output.message_structs.len(), 3);
    }

    #[test]
    fn compile_saga_compensation() {
        let protocol = example_saga_compensation();
        let outputs = compiler()
            .compile_all(&protocol)
            .expect("compilation failed");

        assert_eq!(outputs.len(), 3);
        assert!(outputs.contains_key("coordinator"));
        assert!(outputs.contains_key("service_a"));
        assert!(outputs.contains_key("service_b"));
    }

    // ------------------------------------------------------------------
    // Session type generation
    // ------------------------------------------------------------------

    #[test]
    fn session_type_two_phase_commit_coordinator() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        // coordinator: Send<Reserve, Select<Send<Commit, End>, Send<Abort, End>>>
        assert!(output.session_type.contains("Send<ReserveMsg"));
        assert!(output.session_type.contains("Select<"));
        assert!(output.session_type.contains("CommitMsg"));
        assert!(output.session_type.contains("AbortMsg"));
    }

    #[test]
    fn session_type_two_phase_commit_worker() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");

        // worker: Recv<Reserve, Offer<Recv<Commit, End>, Recv<Abort, End>>>
        assert!(output.session_type.contains("Recv<ReserveMsg"));
        assert!(output.session_type.contains("Offer<"));
    }

    // ------------------------------------------------------------------
    // Code generation
    // ------------------------------------------------------------------

    #[test]
    fn generated_code_contains_protocol_header() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("Protocol: two_phase_commit"));
        assert!(code.contains("Participant: coordinator"));
        assert!(code.contains("DO NOT EDIT"));
    }

    #[test]
    fn generated_code_contains_message_structs() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("pub struct ReserveMsg"));
        assert!(code.contains("pub struct CommitMsg"));
        assert!(code.contains("pub struct AbortMsg"));
    }

    #[test]
    fn generated_code_contains_handler_function() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("pub async fn two_phase_commit_coordinator"));
        assert!(code.contains("chan.send("));
        assert!(code.contains("chan.select_left()"));
        assert!(code.contains("chan.close()"));
    }

    #[test]
    fn generated_code_worker_has_offer() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "worker")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("chan.recv()"));
        assert!(code.contains("chan.offer()"));
        assert!(code.contains("Left(chan)"));
        assert!(code.contains("Right(chan)"));
    }

    #[test]
    fn generated_code_lease_has_loop() {
        let protocol = example_lease_renewal();
        let output = compiler()
            .compile(&protocol, "holder")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("loop {"));
        assert!(code.contains("continue;"));
        assert!(code.contains("break;"));
    }

    #[test]
    fn generated_code_compensation_block() {
        let protocol = example_saga_compensation();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        assert!(code.contains("Compensation block"));
        assert!(code.contains("Forward:"));
        assert!(code.contains("Compensation (on failure):"));
    }

    #[test]
    fn generated_code_compensation_actions_are_stubbed() {
        let protocol = example_saga_compensation();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");
        let code = output.render();

        let mut found_compensate_send = false;
        for line in code.lines() {
            if line.contains("let chan = chan.send(CompensateMsg") {
                found_compensate_send = true;
                assert!(
                    line.trim_start().starts_with("//"),
                    "Compensation send must be commented skeleton code, got: {line}"
                );
            }
        }
        assert!(
            found_compensate_send,
            "Expected generated compensation skeleton to include CompensateMsg send stubs"
        );
    }

    // ------------------------------------------------------------------
    // CALM annotations
    // ------------------------------------------------------------------

    #[test]
    fn calm_annotations_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        // coordinator: reserve (monotone send), commit (non-monotone send), abort (non-monotone send)
        assert_eq!(output.calm_annotations.len(), 3);

        let reserve = output
            .calm_annotations
            .iter()
            .find(|a| a.action == "reserve")
            .expect("reserve annotation missing");
        assert_eq!(reserve.monotonicity, Monotonicity::Monotone);
        assert_eq!(reserve.direction, "send");

        let commit = output
            .calm_annotations
            .iter()
            .find(|a| a.action == "commit")
            .expect("commit annotation missing");
        assert_eq!(commit.monotonicity, Monotonicity::NonMonotone);
    }

    // ------------------------------------------------------------------
    // Error cases
    // ------------------------------------------------------------------

    #[test]
    fn compile_unknown_participant() {
        let protocol = example_two_phase_commit();
        let result = compiler().compile(&protocol, "unknown");

        assert!(matches!(
            result,
            Err(CompilationError::ParticipantNotFound { .. })
        ));
    }

    #[test]
    fn compile_invalid_protocol() {
        let protocol = GlobalProtocol::builder("bad")
            .interaction(Interaction::end())
            .build();

        let result = compiler().compile(&protocol, "nobody");
        assert!(matches!(result, Err(CompilationError::ValidationFailed(_))));
    }

    // ------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------

    #[test]
    fn summary_format() {
        let protocol = example_two_phase_commit();
        let output = compiler()
            .compile(&protocol, "coordinator")
            .expect("compilation failed");

        let summary = output.summary();
        assert!(summary.contains("two_phase_commit"));
        assert!(summary.contains("coordinator"));
        assert!(summary.contains("saga-coordinator"));
    }

    // ------------------------------------------------------------------
    // Render completeness
    // ------------------------------------------------------------------

    #[test]
    fn render_all_five_examples() {
        use crate::obligation::choreography::*;

        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let c = compiler();
        for protocol in &protocols {
            let outputs = c.compile_all(protocol).expect("compilation failed");
            assert!(!outputs.is_empty(), "No outputs for {}", protocol.name);
            for (name, output) in &outputs {
                let code = output.render();
                assert!(!code.is_empty(), "Empty code for {name}");
                assert!(
                    code.contains("chan.close()"),
                    "Missing close for {name} in {}",
                    protocol.name
                );
            }
        }
    }

    // ==================================================================
    // bd-1f8jn.4: Comprehensive codegen test suite
    // ==================================================================

    // ------------------------------------------------------------------
    // Codegen determinism
    // ------------------------------------------------------------------

    #[test]
    fn codegen_deterministic_two_phase_commit() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let out1 = c.compile(&protocol, "coordinator").unwrap();
        let out2 = c.compile(&protocol, "coordinator").unwrap();
        assert_eq!(out1.render(), out2.render());
        assert_eq!(out1.session_type, out2.session_type);
    }

    #[test]
    fn codegen_deterministic_all_participants() {
        let c = compiler();
        let protocol = example_saga_compensation();
        let all1 = c.compile_all(&protocol).unwrap();
        let all2 = c.compile_all(&protocol).unwrap();
        assert_eq!(all1.len(), all2.len());
        for (name, o1) in &all1 {
            let o2 = &all2[name];
            assert_eq!(
                o1.render(),
                o2.render(),
                "Non-deterministic codegen for {name}"
            );
            assert_eq!(o1.session_type, o2.session_type);
        }
    }

    // ------------------------------------------------------------------
    // Message struct collection
    // ------------------------------------------------------------------

    #[test]
    fn message_structs_no_duplicates() {
        let c = compiler();
        let protocol = example_saga_compensation();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let names: Vec<&str> = output
            .message_structs
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        let unique: BTreeSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "Duplicate messages: {names:?}");
    }

    #[test]
    fn message_structs_match_protocol_comms() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let coord = c.compile(&protocol, "coordinator").unwrap();
        let msg_names: BTreeSet<&str> = coord
            .message_structs
            .iter()
            .map(|m| m.name.as_str())
            .collect();
        assert!(msg_names.contains("ReserveMsg"));
        assert!(msg_names.contains("CommitMsg"));
        assert!(msg_names.contains("AbortMsg"));
    }

    #[test]
    fn message_structs_only_relevant_to_participant() {
        let c = compiler();
        let protocol = example_saga_compensation();
        let sa = c.compile(&protocol, "service_a").unwrap();
        let msg_names: BTreeSet<&str> =
            sa.message_structs.iter().map(|m| m.name.as_str()).collect();
        assert!(msg_names.contains("ReserveMsg"));
        assert!(msg_names.contains("CommitMsg"));
        assert!(msg_names.contains("AbortMsg"));
        assert!(msg_names.contains("CompensateMsg"));
    }

    // ------------------------------------------------------------------
    // Session type structure
    // ------------------------------------------------------------------

    #[test]
    fn session_type_lease_has_recursion() {
        let c = compiler();
        let protocol = example_lease_renewal();
        let output = c.compile(&protocol, "holder").unwrap();
        assert!(
            output.session_type.contains("Rec_renew_loop"),
            "Expected recursion, got: {}",
            output.session_type
        );
    }

    #[test]
    fn session_type_end_at_leaves() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        assert!(output.session_type.contains("End"));
    }

    // ------------------------------------------------------------------
    // CALM annotation correctness
    // ------------------------------------------------------------------

    #[test]
    fn calm_annotations_worker_perspective() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "worker").unwrap();
        assert_eq!(output.calm_annotations.len(), 3);
        for ann in &output.calm_annotations {
            assert_eq!(ann.direction, "recv");
            assert_eq!(ann.peer, "coordinator");
        }
    }

    #[test]
    fn calm_annotations_missing_when_no_calm_tags() {
        let protocol = GlobalProtocol::builder("no_calm")
            .participant("a", "role")
            .participant("b", "role")
            .interaction(Interaction::comm("a", "msg", "Msg", "b").then(Interaction::end()))
            .build();
        let c = compiler();
        let output = c.compile(&protocol, "a").unwrap();
        assert!(output.calm_annotations.is_empty());
    }

    // ------------------------------------------------------------------
    // Complexity counting
    // ------------------------------------------------------------------

    #[test]
    fn complexity_two_phase_commit_coordinator() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        assert!(output.local_state_count > 0);
        assert!(output.local_transition_count > 0);
        assert!(output.local_transition_count <= output.local_state_count * 2);
    }

    #[test]
    fn complexity_grows_with_protocol_size() {
        let c = compiler();
        let simple = example_two_phase_commit();
        let complex = example_saga_compensation();
        let simple_out = c.compile(&simple, "coordinator").unwrap();
        let complex_out = c.compile(&complex, "coordinator").unwrap();
        assert!(complex_out.local_state_count >= simple_out.local_state_count);
    }

    // ------------------------------------------------------------------
    // Generated code structure
    // ------------------------------------------------------------------

    #[test]
    fn generated_code_has_imports() {
        let c = compiler();
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let code = output.render();
        assert!(code.contains("use asupersync::obligation::session_types::"));
        assert!(code.contains("Chan, End, Send, Recv"));
    }

    #[test]
    fn generated_code_tracing_disabled() {
        let c = ProjectionCompiler {
            include_tracing: false,
        };
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let code = output.render();
        assert!(!code.contains("Span:"));
    }

    #[test]
    fn generated_code_tracing_enabled() {
        let c = ProjectionCompiler {
            include_tracing: true,
        };
        let protocol = example_two_phase_commit();
        let output = c.compile(&protocol, "coordinator").unwrap();
        let code = output.render();
        assert!(code.contains("Span:"));
    }

    #[test]
    fn compilation_error_display() {
        let err1 = CompilationError::ParticipantNotFound { name: "x".into() };
        assert!(format!("{err1}").contains("'x'"));

        let err2 = CompilationError::EmptyProjection {
            participant: "y".into(),
        };
        assert!(format!("{err2}").contains("'y'"));

        let err3 =
            CompilationError::ValidationFailed(vec![super::super::ValidationError::EmptyProtocol]);
        assert!(format!("{err3}").contains("validation failed"));
    }

    // ------------------------------------------------------------------
    // compile_all skips uninvolved participants
    // ------------------------------------------------------------------

    #[test]
    fn compile_all_skips_uninvolved() {
        let protocol = GlobalProtocol::builder("partial")
            .participant("a", "role")
            .participant("b", "role")
            .participant("ghost", "role")
            .interaction(Interaction::comm("a", "msg", "Msg", "b").then(Interaction::end()))
            .build();

        let c = compiler();
        let outputs = c.compile_all(&protocol).unwrap();
        assert!(outputs.contains_key("a"));
        assert!(outputs.contains_key("b"));
        assert!(!outputs.contains_key("ghost"));
    }
}
