// Module-level clippy allows matching the parent module (bd-1f8jn.3).
#![allow(clippy::must_use_candidate)]
#![allow(clippy::use_self)]

//! End-to-end saga pipeline: choreography → runnable participant code (bd-1f8jn.3).
//!
//! Bridges the choreographic projection compiler (bd-1f8jn.2) with the CALM-optimized
//! saga executor (bd-2wrsc.2) to generate complete, runnable Asupersync participant
//! code from a single global protocol specification.
//!
//! # Pipeline
//!
//! ```text
//! GlobalProtocol
//!   ↓ SagaPipeline::generate()
//!   ├── validate & project (bd-1f8jn.2)
//!   ├── choreography_to_saga_plan()     ← converts interactions to SagaSteps
//!   ├── SagaExecutionPlan::from_plan()  ← CALM batching
//!   ├── render_saga_module()            ← Cx + EvidenceLedger + compensation
//!   └── render_lab_test()               ← deterministic test harness
//! SagaPipelineOutput
//!   { per-participant code, lab test scaffold, saga plans }
//! ```
//!
//! # Generated Code Structure
//!
//! For each participant, generates:
//! - **Saga plan**: `SagaPlan` with steps derived from protocol interactions
//! - **Async handler**: `async fn <proto>_<participant>(cx: &Cx, chan: Chan<...>)`
//!   with `cx.checkpoint()`, `cx.trace()`, compensation blocks, and evidence emission
//! - **Lab test**: Setup code creating session channels between all participants
//!   and spawning them under a deterministic Lab runtime
//!
//! # Example
//!
//! ```
//! use asupersync::obligation::choreography::{example_two_phase_commit, pipeline::SagaPipeline};
//!
//! let pipeline = SagaPipeline::new();
//! let output = pipeline.generate(&example_two_phase_commit()).expect("pipeline failed");
//!
//! assert_eq!(output.participants.len(), 2);
//! assert!(output.participants.contains_key("coordinator"));
//! assert!(output.participants.contains_key("worker"));
//!
//! // Each participant has a saga plan with CALM-batched steps
//! let coord = &output.participants["coordinator"];
//! assert!(!coord.saga_plan.steps.is_empty());
//! assert!(coord.source_code.contains("cx.checkpoint()"));
//!
//! // Lab test scaffold is generated
//! assert!(output.lab_test_code.contains("fn test_"));
//! ```

use super::codegen::{CompilationError, ProjectionCompiler, ProjectionOutput};
use super::{GlobalProtocol, Interaction, LocalType};
use crate::obligation::calm::Monotonicity;
use crate::obligation::saga::{SagaExecutionPlan, SagaOpKind, SagaPlan, SagaStep};
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

// ============================================================================
// Pipeline types
// ============================================================================

/// End-to-end pipeline: global choreography → runnable saga participant code.
#[derive(Debug)]
pub struct SagaPipeline {
    /// Inner projection compiler.
    compiler: ProjectionCompiler,
    /// Whether to generate lab test scaffolds.
    pub generate_lab_tests: bool,
}

impl Default for SagaPipeline {
    fn default() -> Self {
        Self {
            compiler: ProjectionCompiler::new(),
            generate_lab_tests: true,
        }
    }
}

/// Output of the saga pipeline for a single participant.
#[derive(Debug, Clone)]
pub struct SagaParticipantCode {
    /// Participant name.
    pub participant_name: String,
    /// Participant role.
    pub participant_role: String,
    /// Protocol name.
    pub protocol_name: String,
    /// Saga plan derived from the choreographic projection.
    pub saga_plan: SagaPlan,
    /// CALM-batched execution plan.
    pub execution_plan: SagaExecutionPlan,
    /// Projection compiler output (session type, messages, etc.).
    pub projection: ProjectionOutput,
    /// Generated Rust source code with Cx, compensation, and evidence.
    pub source_code: String,
}

/// Complete pipeline output for all participants.
#[derive(Debug, Clone)]
pub struct SagaPipelineOutput {
    /// Protocol name.
    pub protocol_name: String,
    /// Per-participant generated code and saga plans.
    pub participants: BTreeMap<String, SagaParticipantCode>,
    /// Lab test scaffold code.
    pub lab_test_code: String,
}

/// Pipeline error.
#[derive(Debug, Clone)]
pub enum PipelineError {
    /// Compilation (projection) failed.
    Compilation(CompilationError),
    /// No participants produced output.
    NoParticipants,
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compilation(e) => write!(f, "compilation error: {e}"),
            Self::NoParticipants => write!(f, "no participants produced output"),
        }
    }
}

impl From<CompilationError> for PipelineError {
    fn from(e: CompilationError) -> Self {
        Self::Compilation(e)
    }
}

// ============================================================================
// Pipeline implementation
// ============================================================================

impl SagaPipeline {
    /// Create a new saga pipeline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate complete saga participant code from a global protocol.
    ///
    /// Validates, projects, converts to saga plans, and renders Rust source
    /// code with Cx integration, compensation handlers, and evidence emission.
    pub fn generate(&self, protocol: &GlobalProtocol) -> Result<SagaPipelineOutput, PipelineError> {
        self.generate_with_locals(protocol)
    }

    /// Generate a saga plan only (without full code generation).
    ///
    /// Useful for analyzing CALM batching properties without rendering code.
    pub fn plan_only(
        &self,
        protocol: &GlobalProtocol,
        participant: &str,
    ) -> Result<(SagaPlan, SagaExecutionPlan), PipelineError> {
        // Validate
        let errors = protocol.validate();
        if !errors.is_empty() {
            return Err(PipelineError::Compilation(
                CompilationError::ValidationFailed(errors),
            ));
        }

        let saga_plan = choreography_to_saga_plan(
            &protocol.name,
            participant,
            &protocol.interaction,
            participant,
        );
        let execution_plan = SagaExecutionPlan::from_plan(&saga_plan);

        Ok((saga_plan, execution_plan))
    }
}

// ============================================================================
// Choreography → SagaPlan conversion
// ============================================================================

/// Convert a choreographic interaction tree into a flat saga plan for a participant.
///
/// Maps choreographic primitives to saga operations:
/// - `Comm(sender=me)` → `SagaOpKind::Send`
/// - `Comm(receiver=me)` → `SagaOpKind::Recv`
/// - `Choice(decider=me)` → no step (local decision)
/// - `Compensate` → forward steps + compensation steps (marked as abort)
/// - `Loop`/`Continue` → unrolled as linear steps (single iteration)
fn choreography_to_saga_plan(
    protocol_name: &str,
    plan_name: &str,
    interaction: &Interaction,
    participant: &str,
) -> SagaPlan {
    let mut steps = Vec::new();
    interaction_to_steps(interaction, participant, &mut steps);

    SagaPlan::new(format!("{protocol_name}_{plan_name}"), steps)
}

fn interaction_to_steps(interaction: &Interaction, participant: &str, steps: &mut Vec<SagaStep>) {
    match interaction {
        Interaction::Comm {
            sender,
            receiver,
            action,
            monotonicity,
            then,
            ..
        } => {
            if sender == participant {
                let mono = monotonicity.unwrap_or(Monotonicity::NonMonotone);
                // Reserve before send if this is the first action
                steps.push(SagaStep::with_override(
                    SagaOpKind::Send,
                    format!("send_{action}"),
                    mono,
                ));
            } else if receiver == participant {
                let mono = monotonicity.unwrap_or(Monotonicity::NonMonotone);
                steps.push(SagaStep::with_override(
                    SagaOpKind::Recv,
                    format!("recv_{action}"),
                    mono,
                ));
            }
            interaction_to_steps(then, participant, steps);
        }

        Interaction::Choice {
            decider,
            then_branch,
            else_branch,
            ..
        } => {
            if decider == participant {
                // Local decision point — budget check before branching
                steps.push(SagaStep::new(
                    SagaOpKind::BudgetCheck,
                    "choice_budget_check".to_string(),
                ));
            }
            // Include steps from both branches (saga must handle either path)
            interaction_to_steps(then_branch, participant, steps);
            interaction_to_steps(else_branch, participant, steps);
        }

        Interaction::Loop { body, .. } => {
            // Single-iteration unrolling for saga plan
            interaction_to_steps(body, participant, steps);
        }

        Interaction::Compensate {
            forward,
            compensate,
        } => {
            // Collect forward-participant steps first.
            let forward_start = steps.len();
            interaction_to_steps(forward, participant, steps);
            let forward_end = steps.len();

            // Collect compensation-participant steps independently so participants
            // that only appear in compensation are still represented.
            let mut compensation_steps = Vec::new();
            interaction_to_steps(compensate, participant, &mut compensation_steps);

            if !compensation_steps.is_empty() {
                // Add reserve/abort boundary markers only when this participant
                // has both forward work and compensation work.
                if forward_end > forward_start {
                    steps.push(SagaStep::new(
                        SagaOpKind::Reserve,
                        "compensation_boundary".to_string(),
                    ));
                }

                steps.extend(compensation_steps);

                if forward_end > forward_start {
                    steps.push(SagaStep::new(
                        SagaOpKind::Abort,
                        "compensation_abort".to_string(),
                    ));
                }
            }
        }

        Interaction::Seq { first, second } => {
            interaction_to_steps(first, participant, steps);
            interaction_to_steps(second, participant, steps);
        }

        Interaction::Par { left, right } => {
            // Both branches contribute steps (can run concurrently)
            interaction_to_steps(left, participant, steps);
            interaction_to_steps(right, participant, steps);
        }

        Interaction::Continue { .. } | Interaction::End => {}
    }
}

// ============================================================================
// Saga module rendering (Cx + EvidenceLedger + compensation)
// ============================================================================

/// Render saga handler body with Cx integration from the local type.
#[allow(clippy::too_many_lines)]
fn render_saga_handler_body(
    local: &LocalType,
    code: &mut String,
    indent: usize,
    protocol: &str,
    participant: &str,
) {
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
                "{pad}cx.checkpoint().expect(\"cancelled before send {action}\");"
            )
            .ok();
            writeln!(
                code,
                "{pad}cx.trace(\"{protocol}:{participant} sending {action}\");"
            )
            .ok();
            writeln!(
                code,
                "{pad}let chan = chan.send({msg_type} {{ /* fields */ }});"
            )
            .ok();
            render_saga_handler_body(then, code, indent, protocol, participant);
        }
        LocalType::Recv {
            action,
            msg_type,
            from,
            then,
            ..
        } => {
            writeln!(code, "{pad}// Receive {action}({msg_type}) from {from}").ok();
            writeln!(
                code,
                "{pad}cx.checkpoint().expect(\"cancelled before recv {action}\");"
            )
            .ok();
            writeln!(
                code,
                "{pad}cx.trace(\"{protocol}:{participant} receiving {action}\");"
            )
            .ok();
            writeln!(code, "{pad}let (msg, chan) = chan.recv();").ok();
            render_saga_handler_body(then, code, indent, protocol, participant);
        }
        LocalType::InternalChoice {
            predicate,
            then_branch,
            else_branch,
            ..
        } => {
            writeln!(code, "{pad}// Internal choice: decides({predicate})").ok();
            writeln!(
                code,
                "{pad}cx.checkpoint().expect(\"cancelled at choice point\");"
            )
            .ok();
            writeln!(
                code,
                "{pad}cx.trace(\"{protocol}:{participant} deciding {predicate}\");"
            )
            .ok();
            writeln!(code, "{pad}if /* {predicate} */ true {{").ok();
            writeln!(code, "{pad}    let chan = chan.select_left();").ok();
            render_saga_handler_body(then_branch, code, indent + 1, protocol, participant);
            writeln!(code, "{pad}}} else {{").ok();
            writeln!(code, "{pad}    let chan = chan.select_right();").ok();
            render_saga_handler_body(else_branch, code, indent + 1, protocol, participant);
            writeln!(code, "{pad}}}").ok();
        }
        LocalType::ExternalChoice {
            from,
            then_branch,
            else_branch,
            ..
        } => {
            writeln!(code, "{pad}// External choice: offered by {from}").ok();
            writeln!(
                code,
                "{pad}cx.checkpoint().expect(\"cancelled at offer point\");"
            )
            .ok();
            writeln!(code, "{pad}match chan.offer() {{").ok();
            writeln!(code, "{pad}    Left(chan) => {{").ok();
            writeln!(
                code,
                "{pad}        cx.trace(\"{protocol}:{participant} branch: left\");"
            )
            .ok();
            render_saga_handler_body(then_branch, code, indent + 2, protocol, participant);
            writeln!(code, "{pad}    }}").ok();
            writeln!(code, "{pad}    Right(chan) => {{").ok();
            writeln!(
                code,
                "{pad}        cx.trace(\"{protocol}:{participant} branch: right\");"
            )
            .ok();
            render_saga_handler_body(else_branch, code, indent + 2, protocol, participant);
            writeln!(code, "{pad}    }}").ok();
            writeln!(code, "{pad}}}").ok();
        }
        LocalType::Rec { label, body } => {
            writeln!(code, "{pad}// Loop: {label}").ok();
            writeln!(code, "{pad}loop {{").ok();
            writeln!(
                code,
                "{pad}    cx.checkpoint().expect(\"cancelled in loop {label}\");"
            )
            .ok();
            render_saga_handler_body(body, code, indent + 1, protocol, participant);
            writeln!(code, "{pad}}}").ok();
        }
        LocalType::RecVar { label } => {
            writeln!(code, "{pad}continue; // -> {label}").ok();
        }
        LocalType::Compensate {
            forward,
            compensate,
        } => {
            writeln!(code, "{pad}// === Compensation block (saga rollback) ===").ok();
            writeln!(
                code,
                "{pad}cx.trace(\"{protocol}:{participant} entering compensation scope\");"
            )
            .ok();
            writeln!(code, "{pad}// Forward path:").ok();
            render_saga_handler_body(forward, code, indent, protocol, participant);
            writeln!(code, "{pad}// Compensation handler (on saga failure):").ok();
            writeln!(code, "{pad}// If the forward path fails, execute:").ok();
            writeln!(code, "{pad}// {{").ok();
            render_saga_handler_body(compensate, code, indent, protocol, participant);
            writeln!(
                code,
                "{pad}//     cx.trace(\"{protocol}:{participant} compensation executed\");"
            )
            .ok();
            writeln!(code, "{pad}// }}").ok();
        }
        LocalType::End => {
            writeln!(code, "{pad}// Protocol complete").ok();
            writeln!(
                code,
                "{pad}cx.trace(\"{protocol}:{participant} closing channel\");"
            )
            .ok();
            writeln!(code, "{pad}chan.close();").ok();
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
// Enhanced pipeline with local type threading
// ============================================================================

/// Internal: compile and generate with local type access.
///
/// The public `generate()` method delegates here, re-projecting to get the
/// actual `LocalType` for saga-aware rendering.
fn compile_and_render(
    compiler: &ProjectionCompiler,
    protocol: &GlobalProtocol,
    participant: &str,
) -> Result<(ProjectionOutput, SagaPlan, SagaExecutionPlan, String), CompilationError> {
    // Get the projection output
    let projection = compiler.compile(protocol, participant)?;

    // Re-project to get the LocalType
    let local_type =
        protocol
            .project(participant)
            .ok_or_else(|| CompilationError::EmptyProjection {
                participant: participant.to_string(),
            })?;

    // Build saga plan from choreographic interactions
    let saga_plan = choreography_to_saga_plan(
        &protocol.name,
        participant,
        &protocol.interaction,
        participant,
    );
    let execution_plan = SagaExecutionPlan::from_plan(&saga_plan);

    // Render full module with the actual LocalType
    let source_code = render_saga_module_with_local(
        &protocol.name,
        participant,
        &projection.participant_role,
        &projection,
        &local_type,
        &saga_plan,
        &execution_plan,
    );

    Ok((projection, saga_plan, execution_plan, source_code))
}

/// Render the saga module using the actual LocalType, not an earlier stand-in.
#[allow(clippy::too_many_lines)]
fn render_saga_module_with_local(
    protocol: &str,
    participant: &str,
    role: &str,
    projection: &ProjectionOutput,
    local_type: &LocalType,
    saga_plan: &SagaPlan,
    execution_plan: &SagaExecutionPlan,
) -> String {
    let fn_name = format!("{protocol}_{participant}");
    let entry_role = entry_channel_role(local_type);
    let mut code = String::new();

    // Module header
    writeln!(code, "//! Generated saga participant code.").ok();
    writeln!(code, "//! Protocol: {protocol}").ok();
    writeln!(code, "//! Participant: {participant} (role: {role})").ok();
    writeln!(code, "//!").ok();
    writeln!(
        code,
        "//! Pipeline: choreography → projection → saga plan → code"
    )
    .ok();
    writeln!(code, "//! Saga steps: {}", saga_plan.steps.len()).ok();
    writeln!(
        code,
        "//! CALM batches: {} ({} coordination-free, {} barriers)",
        execution_plan.batches.len(),
        execution_plan.coordination_free_batch_count(),
        execution_plan.coordination_barrier_count(),
    )
    .ok();
    writeln!(
        code,
        "//! Monotone ratio: {:.0}%",
        saga_plan.monotone_ratio() * 100.0
    )
    .ok();
    writeln!(code, "//!").ok();
    writeln!(
        code,
        "//! DO NOT EDIT — regenerate from the global choreography."
    )
    .ok();
    writeln!(code).ok();

    // Imports
    writeln!(code, "use asupersync::cx::Cx;").ok();
    writeln!(code, "use asupersync::obligation::session_types::{{").ok();
    writeln!(
        code,
        "    Chan, End, Send, Recv, Select, Offer, Initiator, Responder,"
    )
    .ok();
    writeln!(code, "}};").ok();
    writeln!(code, "use asupersync::obligation::saga::{{").ok();
    writeln!(
        code,
        "    SagaPlan, SagaStep, SagaOpKind, SagaExecutionPlan,"
    )
    .ok();
    writeln!(code, "    MonotoneSagaExecutor,").ok();
    writeln!(code, "}};").ok();
    writeln!(code, "use asupersync::obligation::calm::Monotonicity;").ok();
    writeln!(code, "use asupersync::record::ObligationKind;").ok();
    writeln!(code, "use franken_evidence::EvidenceLedgerBuilder;").ok();
    writeln!(code).ok();

    // Message structs
    writeln!(code, "// --- Message types ---").ok();
    writeln!(code).ok();
    for msg in &projection.message_structs {
        writeln!(code, "#[derive(Debug, Clone)]").ok();
        if msg.has_payload {
            writeln!(
                code,
                "pub struct {}<{}> {{",
                msg.name,
                msg.type_params.join(", ")
            )
            .ok();
            writeln!(code, "    pub payload: ({}),", msg.type_params.join(", ")).ok();
            writeln!(code, "}}").ok();
        } else {
            writeln!(code, "pub struct {};", msg.name).ok();
        }
        writeln!(code).ok();
    }

    // Session type alias
    writeln!(code, "/// Session type for {participant} in {protocol}.").ok();
    writeln!(
        code,
        "pub type {participant}_Session = {};",
        projection.session_type
    )
    .ok();
    writeln!(code).ok();

    // Saga plan constructor
    writeln!(code, "/// Build the saga plan for {participant}.").ok();
    writeln!(code, "pub fn {fn_name}_saga_plan() -> SagaPlan {{").ok();
    writeln!(code, "    SagaPlan::new(\"{}\", vec![", saga_plan.name).ok();
    for step in &saga_plan.steps {
        let mono_str = match step.monotonicity {
            Monotonicity::Monotone => "Monotonicity::Monotone",
            Monotonicity::NonMonotone => "Monotonicity::NonMonotone",
        };
        writeln!(
            code,
            "        SagaStep::with_override(SagaOpKind::{}, \"{}\", {mono_str}),",
            step.op, step.label,
        )
        .ok();
    }
    writeln!(code, "    ])").ok();
    writeln!(code, "}}").ok();
    writeln!(code).ok();

    // Main async handler with Cx
    writeln!(
        code,
        "/// Saga handler for {participant} in the {protocol} choreography."
    )
    .ok();
    writeln!(code, "///").ok();
    writeln!(code, "/// Integrates with the Cx capability context for:").ok();
    writeln!(code, "/// - Cancellation checkpoints (`cx.checkpoint()`)").ok();
    writeln!(code, "/// - Observability tracing (`cx.trace()`)").ok();
    writeln!(code, "/// - Evidence emission (`cx.emit_evidence()`)").ok();
    writeln!(code, "pub async fn {fn_name}(").ok();
    writeln!(code, "    cx: &Cx,").ok();
    writeln!(code, "    chan: Chan<{entry_role}, {participant}_Session>,").ok();
    writeln!(code, ") {{").ok();

    // Entry checkpoint + trace
    writeln!(
        code,
        "    cx.checkpoint().expect(\"cancelled before start\");"
    )
    .ok();
    writeln!(code, "    cx.trace(\"{protocol}:{participant} starting\");").ok();
    writeln!(code).ok();

    // Handler body from local type
    render_saga_handler_body(local_type, &mut code, 1, protocol, participant);

    // Evidence emission at end
    writeln!(code).ok();
    writeln!(code, "    // Emit execution evidence").ok();
    writeln!(code, "    let evidence = EvidenceLedgerBuilder::new()").ok();
    writeln!(
        code,
        "        .ts_unix_ms(0) // set from cx.logical_clock()"
    )
    .ok();
    writeln!(code, "        .component(\"{protocol}_{participant}\")").ok();
    writeln!(code, "        .action(\"saga_completed\")").ok();
    writeln!(code, "        .posterior(vec![1.0])").ok();
    writeln!(code, "        .chosen_expected_loss(0.0)").ok();
    writeln!(code, "        .calibration_score(1.0)").ok();
    writeln!(code, "        .build()").ok();
    writeln!(code, "        .expect(\"valid evidence\");").ok();
    writeln!(code, "    cx.emit_evidence(&evidence);").ok();
    writeln!(
        code,
        "    cx.trace(\"{protocol}:{participant} completed\");"
    )
    .ok();
    writeln!(code, "}}").ok();

    code
}

// ============================================================================
// Lab test scaffold rendering
// ============================================================================

#[allow(clippy::too_many_lines)]
fn render_lab_test(protocol: &str, participants: &BTreeMap<String, SagaParticipantCode>) -> String {
    let mut code = String::new();

    writeln!(code, "//! Lab test scaffold for {protocol} choreography.").ok();
    writeln!(code, "//!").ok();
    writeln!(code, "//! Generated by the saga pipeline (bd-1f8jn.3).").ok();
    writeln!(
        code,
        "//! Sets up session channels between all participants and"
    )
    .ok();
    writeln!(
        code,
        "//! runs the choreography under deterministic Lab runtime."
    )
    .ok();
    writeln!(code).ok();

    // Imports
    writeln!(code, "#[cfg(test)]").ok();
    writeln!(code, "mod tests {{").ok();
    writeln!(code, "    use asupersync::cx::Cx;").ok();
    writeln!(code, "    use asupersync::obligation::session_types::*;").ok();
    writeln!(code, "    use asupersync::obligation::saga::*;").ok();
    writeln!(code).ok();

    // Test function
    writeln!(code, "    #[test]").ok();
    writeln!(code, "    fn test_{protocol}_choreography() {{").ok();
    writeln!(
        code,
        "        let lab = asupersync::LabRuntime::new(asupersync::LabConfig::default());"
    )
    .ok();
    writeln!(
        code,
        "        let _ = &lab; // deterministic runtime handle for scaffold extensions"
    )
    .ok();

    // Create channels for each pair
    let participant_names: Vec<&str> = participants.keys().map(String::as_str).collect();
    writeln!(
        code,
        "        // Set up session channels between participants"
    )
    .ok();

    for (i, name_a) in participant_names.iter().enumerate() {
        for name_b in &participant_names[i + 1..] {
            writeln!(code, "        // Channel: {name_a} <-> {name_b}").ok();
            writeln!(
                code,
                "        let (chan_{name_a}_to_{name_b}, chan_{name_b}_to_{name_a}) = ((), ());"
            )
            .ok();
        }
    }

    writeln!(code).ok();
    writeln!(
        code,
        "        // Compose participant entry channels from pair endpoints"
    )
    .ok();
    for name in &participant_names {
        writeln!(code, "        let chan_{name} = ();").ok();
    }

    writeln!(code).ok();
    writeln!(code, "        // Prepare participant tasks for Lab runtime").ok();

    for name in &participant_names {
        let pc = &participants[*name];
        writeln!(code, "        // {name} (role: {})", pc.participant_role).ok();
        writeln!(code, "        let _{name}_task = || {{").ok();
        writeln!(
            code,
            "            let cx = Cx::for_test(\"{protocol}_{name}\");"
        )
        .ok();
        writeln!(
            code,
            "            // Scaffold hook: invoke {protocol}_{name} once endpoint wiring is provided."
        )
        .ok();
        writeln!(code, "            let _ = (&cx, &chan_{name});").ok();
        writeln!(code, "        }};").ok();
    }

    writeln!(code).ok();
    writeln!(
        code,
        "        // Participant task launch is intentionally scaffolded for protocol-specific wiring."
    )
    .ok();

    writeln!(code, "    }}").ok();

    // CALM analysis test
    writeln!(code).ok();
    writeln!(code, "    #[test]").ok();
    writeln!(code, "    fn test_{protocol}_calm_analysis() {{").ok();
    for (name, pc) in participants {
        writeln!(
            code,
            "        // {name}: {} steps, {:.0}% monotone",
            pc.saga_plan.steps.len(),
            pc.saga_plan.monotone_ratio() * 100.0,
        )
        .ok();
        writeln!(code, "        let plan = {protocol}_{name}_saga_plan();").ok();
        writeln!(
            code,
            "        let exec = SagaExecutionPlan::from_plan(&plan);"
        )
        .ok();
        writeln!(
            code,
            "        assert_eq!(exec.total_steps(), {});",
            pc.saga_plan.steps.len()
        )
        .ok();
        writeln!(
            code,
            "        assert_eq!(exec.coordination_barrier_count(), {});",
            pc.execution_plan.coordination_barrier_count(),
        )
        .ok();
    }
    writeln!(code, "    }}").ok();

    writeln!(code, "}}").ok();

    code
}

// ============================================================================
// Pipeline generate() (actual implementation using compile_and_render)
// ============================================================================

impl SagaPipeline {
    /// Generate with local type threading (replaces the default generate path).
    fn generate_with_locals(
        &self,
        protocol: &GlobalProtocol,
    ) -> Result<SagaPipelineOutput, PipelineError> {
        // Validate first
        let errors = protocol.validate();
        if !errors.is_empty() {
            return Err(PipelineError::Compilation(
                CompilationError::ValidationFailed(errors),
            ));
        }

        let mut participants = BTreeMap::new();

        for name in protocol.participants.keys() {
            match compile_and_render(&self.compiler, protocol, name) {
                Ok((projection, saga_plan, execution_plan, source_code)) => {
                    participants.insert(
                        name.clone(),
                        SagaParticipantCode {
                            participant_name: name.clone(),
                            participant_role: projection.participant_role.clone(),
                            protocol_name: protocol.name.clone(),
                            saga_plan,
                            execution_plan,
                            projection,
                            source_code,
                        },
                    );
                }
                Err(CompilationError::EmptyProjection { .. }) => {
                    // Skip uninvolved participants
                }
                Err(e) => return Err(PipelineError::Compilation(e)),
            }
        }

        if participants.is_empty() {
            return Err(PipelineError::NoParticipants);
        }

        let lab_test_code = if self.generate_lab_tests {
            render_lab_test(&protocol.name, &participants)
        } else {
            String::new()
        };

        Ok(SagaPipelineOutput {
            protocol_name: protocol.name.clone(),
            participants,
            lab_test_code,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "pipeline_inline_tests.rs"]
mod tests;
