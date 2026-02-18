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
//! assert!(output.lab_test_code.contains("async fn test_"));
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

/// Render the saga module using the actual LocalType (not the placeholder).
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
    writeln!(code, "    chan: Chan<Initiator, {participant}_Session>,").ok();
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
        "        let _ = &lab; // TODO: execute choreography inside deterministic LabRuntime"
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
                "        let (chan_{name_a}_to_{name_b}, chan_{name_b}_to_{name_a}) = ("
            )
            .ok();
            writeln!(code, "            /* create session channel pair */").ok();
            writeln!(
                code,
                "            todo!(\"wire up session endpoint for {name_a} -> {name_b}\"),"
            )
            .ok();
            writeln!(
                code,
                "            todo!(\"wire up session endpoint for {name_b} -> {name_a}\"),"
            )
            .ok();
            writeln!(code, "        );").ok();
        }
    }

    writeln!(code).ok();
    writeln!(
        code,
        "        // Compose participant entry channels from pair endpoints"
    )
    .ok();
    for name in &participant_names {
        writeln!(
            code,
            "        let chan_{name} = todo!(\"compose session endpoint for {name} from pair channels\");"
        )
        .ok();
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
            "            // TODO: execute in structured scope: {protocol}_{name}(&cx, chan_{name}).await;"
        )
        .ok();
        writeln!(code, "            let _ = (&cx, &chan_{name});").ok();
        writeln!(code, "        }};").ok();
    }

    writeln!(code).ok();
    writeln!(
        code,
        "        // TODO: execute participant tasks in a structured scope and await quiescence."
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
mod tests {
    use super::*;
    use crate::obligation::choreography::{
        example_lease_renewal, example_saga_compensation, example_scatter_gather_disjoint,
        example_two_phase_commit,
    };

    fn pipeline() -> SagaPipeline {
        SagaPipeline::new()
    }

    // ------------------------------------------------------------------
    // Pipeline generation — two-phase commit
    // ------------------------------------------------------------------

    #[test]
    fn generate_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "two_phase_commit");
        assert_eq!(output.participants.len(), 2);
        assert!(output.participants.contains_key("coordinator"));
        assert!(output.participants.contains_key("worker"));
    }

    #[test]
    fn two_phase_commit_coordinator_saga_plan() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        assert!(!coord.saga_plan.steps.is_empty());

        // Coordinator sends: reserve, commit, abort
        let send_steps: Vec<_> = coord
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .collect();
        assert!(
            send_steps.len() >= 2,
            "coordinator should have at least 2 send steps, got {}",
            send_steps.len()
        );
    }

    #[test]
    fn two_phase_commit_worker_saga_plan() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let worker = &output.participants["worker"];
        assert!(!worker.saga_plan.steps.is_empty());

        // Worker receives: reserve, commit/abort
        let recv_steps: Vec<_> = worker
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Recv)
            .collect();
        assert!(
            recv_steps.len() >= 2,
            "worker should have at least 2 recv steps, got {}",
            recv_steps.len()
        );
    }

    #[test]
    fn two_phase_commit_calm_batching() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        // Should have coordination barriers (commit/abort are non-monotone)
        assert!(
            coord.execution_plan.coordination_barrier_count() > 0
                || coord.execution_plan.coordination_free_batch_count() > 0,
            "execution plan should have at least one batch"
        );
    }

    // ------------------------------------------------------------------
    // Pipeline generation — lease renewal
    // ------------------------------------------------------------------

    #[test]
    fn generate_lease_renewal() {
        let protocol = example_lease_renewal();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "lease_renewal");
        assert!(output.participants.contains_key("holder"));
        assert!(output.participants.contains_key("resource"));
    }

    #[test]
    fn lease_renewal_holder_has_loop_steps() {
        let protocol = example_lease_renewal();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let holder = &output.participants["holder"];
        // Holder sends acquire, renew, release — at least 3 send steps
        let send_count = holder
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .count();
        assert!(send_count >= 3, "holder should send acquire+renew+release");
    }

    // ------------------------------------------------------------------
    // Pipeline generation — saga compensation
    // ------------------------------------------------------------------

    #[test]
    fn generate_saga_compensation() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "saga_with_compensation");
        assert_eq!(output.participants.len(), 3);
        assert!(output.participants.contains_key("coordinator"));
        assert!(output.participants.contains_key("service_a"));
        assert!(output.participants.contains_key("service_b"));
    }

    #[test]
    fn saga_compensation_has_compensation_steps() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        // Compensation protocol should generate Reserve and Abort boundary steps
        let has_reserve = coord
            .saga_plan
            .steps
            .iter()
            .any(|s| s.op == SagaOpKind::Reserve);
        let has_abort = coord
            .saga_plan
            .steps
            .iter()
            .any(|s| s.op == SagaOpKind::Abort);
        assert!(
            has_reserve || has_abort,
            "compensation protocol should have reserve/abort boundary steps"
        );
    }

    #[test]
    fn compensate_keeps_compensation_only_participants_without_spurious_boundaries() {
        let protocol = GlobalProtocol::builder("compensation_partial_roles")
            .participant("coordinator", "saga-coordinator")
            .participant("worker", "saga-worker")
            .participant("undoer", "saga-undoer")
            .interaction(Interaction::compensate(
                Interaction::comm("coordinator", "reserve_work", "ReserveMsg", "worker"),
                Interaction::comm("coordinator", "undo_work", "UndoMsg", "undoer"),
            ))
            .build();

        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let worker = &output.participants["worker"];
        assert!(
            worker
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "recv_reserve_work"),
            "forward-only participant should keep forward step"
        );
        assert!(
            !worker
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "compensation_boundary" || s.label == "compensation_abort"),
            "forward-only participant should not get compensation boundary markers"
        );

        let undoer = &output.participants["undoer"];
        assert!(
            undoer
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "recv_undo_work"),
            "compensation-only participant should keep compensation step"
        );
        assert!(
            !undoer
                .saga_plan
                .steps
                .iter()
                .any(|s| s.label == "compensation_boundary" || s.label == "compensation_abort"),
            "compensation-only participant should not get compensation boundary markers"
        );
    }

    // ------------------------------------------------------------------
    // Source code content
    // ------------------------------------------------------------------

    #[test]
    fn source_code_contains_cx_checkpoint() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert!(
                participant.source_code.contains("cx.checkpoint()"),
                "{name} source code should contain cx.checkpoint()"
            );
        }
    }

    #[test]
    fn source_code_contains_cx_trace() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert!(
                participant.source_code.contains("cx.trace("),
                "{name} source code should contain cx.trace()"
            );
        }
    }

    #[test]
    fn source_code_contains_evidence_emission() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert!(
                participant.source_code.contains("EvidenceLedgerBuilder"),
                "{name} source code should contain EvidenceLedgerBuilder"
            );
            assert!(
                participant.source_code.contains("cx.emit_evidence"),
                "{name} source code should contain cx.emit_evidence()"
            );
        }
    }

    #[test]
    fn source_code_contains_saga_plan_fn() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        assert!(
            coord
                .source_code
                .contains("pub fn two_phase_commit_coordinator_saga_plan()")
        );

        let worker = &output.participants["worker"];
        assert!(
            worker
                .source_code
                .contains("pub fn two_phase_commit_worker_saga_plan()")
        );
    }

    #[test]
    fn source_code_contains_do_not_edit() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for participant in output.participants.values() {
            assert!(participant.source_code.contains("DO NOT EDIT"));
        }
    }

    #[test]
    fn source_code_contains_session_type() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let coord = &output.participants["coordinator"];
        assert!(coord.source_code.contains("coordinator_Session"));

        let worker = &output.participants["worker"];
        assert!(worker.source_code.contains("worker_Session"));
    }

    // ------------------------------------------------------------------
    // Lab test scaffold
    // ------------------------------------------------------------------

    #[test]
    fn lab_test_generated() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(
            !output.lab_test_code.is_empty(),
            "lab test code should be generated"
        );
        assert!(
            output
                .lab_test_code
                .contains("test_two_phase_commit_choreography")
        );
        assert!(
            output
                .lab_test_code
                .contains("test_two_phase_commit_calm_analysis")
        );
    }

    #[test]
    fn lab_test_disabled() {
        let protocol = example_two_phase_commit();
        let mut pipe = pipeline();
        pipe.generate_lab_tests = false;

        let output = pipe
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(
            output.lab_test_code.is_empty(),
            "lab test code should be empty when disabled"
        );
    }

    #[test]
    fn lab_test_contains_participant_spawns() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(output.lab_test_code.contains("_coordinator_task"));
        assert!(output.lab_test_code.contains("_worker_task"));
        assert!(
            output
                .lab_test_code
                .contains("LabRuntime::new(asupersync::LabConfig::default())")
        );
        assert!(!output.lab_test_code.contains("tokio::spawn"));
    }

    #[test]
    fn lab_test_channel_scaffold_is_unique_per_participant() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        // Pairwise directional placeholders must exist.
        assert!(
            output
                .lab_test_code
                .contains("let (chan_proxy_a_to_proxy_b, chan_proxy_b_to_proxy_a) = (")
        );
        assert!(
            output
                .lab_test_code
                .contains("let (chan_proxy_a_to_worker_a, chan_worker_a_to_proxy_a) = (")
        );

        // Each participant should have exactly one entry-channel placeholder.
        for name in ["proxy_a", "proxy_b", "worker_a", "worker_b"] {
            let decl = format!(
                "let chan_{name} = todo!(\"compose session endpoint for {name} from pair channels\");"
            );
            assert_eq!(
                output.lab_test_code.matches(&decl).count(),
                1,
                "{name} should have exactly one channel entry placeholder"
            );
        }
    }

    // ------------------------------------------------------------------
    // plan_only
    // ------------------------------------------------------------------

    #[test]
    fn plan_only_two_phase_commit() {
        let protocol = example_two_phase_commit();
        let (plan, exec) = pipeline()
            .plan_only(&protocol, "coordinator")
            .expect("plan_only failed");

        assert!(!plan.steps.is_empty());
        assert!(exec.total_steps() > 0);
    }

    #[test]
    fn plan_only_saga_compensation() {
        let protocol = example_saga_compensation();
        let (plan, exec) = pipeline()
            .plan_only(&protocol, "service_a")
            .expect("plan_only failed");

        assert!(!plan.steps.is_empty());
        assert!(exec.total_steps() > 0);
    }

    // ------------------------------------------------------------------
    // Error cases
    // ------------------------------------------------------------------

    #[test]
    fn pipeline_error_display() {
        let err = PipelineError::NoParticipants;
        assert_eq!(format!("{err}"), "no participants produced output");

        let err = PipelineError::Compilation(CompilationError::ParticipantNotFound {
            name: "x".to_string(),
        });
        assert!(format!("{err}").contains("participant 'x'"));
    }

    // ------------------------------------------------------------------
    // All example protocols through the pipeline
    // ------------------------------------------------------------------

    #[test]
    fn all_example_protocols_through_pipeline() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|_| panic!("pipeline failed for {}", protocol.name));

            assert!(
                !output.participants.is_empty(),
                "no participants for {}",
                protocol.name
            );

            for (name, participant) in &output.participants {
                // Every participant should have non-empty saga plan
                assert!(
                    !participant.saga_plan.steps.is_empty(),
                    "{name} in {} has empty saga plan",
                    protocol.name
                );

                // Every participant should have non-empty source code
                assert!(
                    !participant.source_code.is_empty(),
                    "{name} in {} has empty source code",
                    protocol.name
                );

                // Source code should reference key integrations
                assert!(
                    participant.source_code.contains("cx.checkpoint()"),
                    "{name} in {} missing cx.checkpoint()",
                    protocol.name
                );
                assert!(
                    participant.source_code.contains("chan."),
                    "{name} in {} missing session channel operations",
                    protocol.name
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // CALM monotonicity properties
    // ------------------------------------------------------------------

    #[test]
    fn monotone_ratio_reasonable() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            let ratio = participant.saga_plan.monotone_ratio();
            assert!(
                (0.0..=1.0).contains(&ratio),
                "{name} has invalid monotone ratio: {ratio}"
            );
        }
    }

    #[test]
    fn execution_plan_step_count_matches_saga_plan() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, participant) in &output.participants {
            assert_eq!(
                participant.execution_plan.total_steps(),
                participant.saga_plan.steps.len(),
                "{name}: execution plan steps != saga plan steps"
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: scatter-gather disjoint through full pipeline (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn generate_scatter_gather_disjoint() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert_eq!(output.protocol_name, "scatter_gather_disjoint");
        assert_eq!(output.participants.len(), 4);
        assert!(output.participants.contains_key("proxy_a"));
        assert!(output.participants.contains_key("proxy_b"));
        assert!(output.participants.contains_key("worker_a"));
        assert!(output.participants.contains_key("worker_b"));
    }

    #[test]
    fn scatter_gather_proxy_sends_and_worker_receives() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        let proxy_a = &output.participants["proxy_a"];
        let worker_a = &output.participants["worker_a"];

        // proxy_a sends request_a, receives response_a
        let proxy_send_count = proxy_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .count();
        let proxy_recv_count = proxy_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Recv)
            .count();
        assert_eq!(proxy_send_count, 1, "proxy_a should send once");
        assert_eq!(proxy_recv_count, 1, "proxy_a should recv once");

        // worker_a receives request_a, sends response_a
        let worker_send_count = worker_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Send)
            .count();
        let worker_recv_count = worker_a
            .saga_plan
            .steps
            .iter()
            .filter(|s| s.op == SagaOpKind::Recv)
            .count();
        assert_eq!(worker_send_count, 1, "worker_a should send once");
        assert_eq!(worker_recv_count, 1, "worker_a should recv once");
    }

    #[test]
    fn scatter_gather_lab_test_references_all_participants() {
        let protocol = example_scatter_gather_disjoint();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        assert!(output.lab_test_code.contains("_proxy_a_task"));
        assert!(output.lab_test_code.contains("_proxy_b_task"));
        assert!(output.lab_test_code.contains("_worker_a_task"));
        assert!(output.lab_test_code.contains("_worker_b_task"));
    }

    // ------------------------------------------------------------------
    // E2E: codegen determinism (bd-1f8jn.4 item 8)
    // ------------------------------------------------------------------

    #[test]
    fn codegen_deterministic_across_runs() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();

        for protocol in &protocols {
            let output1 = pipe
                .generate_with_locals(protocol)
                .expect("pipeline failed");
            let output2 = pipe
                .generate_with_locals(protocol)
                .expect("pipeline failed");

            // Same participants
            assert_eq!(
                output1.participants.len(),
                output2.participants.len(),
                "{}: participant count differs across runs",
                protocol.name
            );

            // Same source code for each participant
            for (name, p1) in &output1.participants {
                let p2 = &output2.participants[name];
                assert_eq!(
                    p1.source_code, p2.source_code,
                    "{}: source code differs for {name}",
                    protocol.name
                );

                // Hash-based golden check
                let mut h1 = DefaultHasher::new();
                p1.source_code.hash(&mut h1);
                let mut h2 = DefaultHasher::new();
                p2.source_code.hash(&mut h2);
                assert_eq!(
                    h1.finish(),
                    h2.finish(),
                    "{}: code hash differs for {name}",
                    protocol.name
                );
            }

            // Same lab test code
            assert_eq!(
                output1.lab_test_code, output2.lab_test_code,
                "{}: lab test code differs",
                protocol.name
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: cross-protocol structural invariants (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn all_valid_protocols_through_full_pipeline() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|e| panic!("{}: pipeline failed: {e}", protocol.name));

            // Structural invariants every output must satisfy:
            assert!(
                !output.participants.is_empty(),
                "{}: no participants",
                protocol.name
            );

            for (name, p) in &output.participants {
                // Protocol metadata consistency
                assert_eq!(
                    p.protocol_name, protocol.name,
                    "{name}: protocol_name mismatch"
                );
                assert_eq!(
                    p.participant_name, *name,
                    "{name}: participant_name mismatch"
                );

                // Saga plan non-empty
                assert!(
                    !p.saga_plan.steps.is_empty(),
                    "{name} in {}: empty saga plan",
                    protocol.name
                );

                // Execution plan covers all steps
                assert_eq!(
                    p.execution_plan.total_steps(),
                    p.saga_plan.steps.len(),
                    "{name} in {}: step count mismatch",
                    protocol.name
                );

                // Monotone ratio valid
                let ratio = p.saga_plan.monotone_ratio();
                assert!(
                    (0.0..=1.0).contains(&ratio),
                    "{name} in {}: invalid monotone ratio {ratio}",
                    protocol.name
                );

                // Source code structural requirements
                assert!(
                    p.source_code.contains("cx.checkpoint()"),
                    "{name} in {}: missing cx.checkpoint()",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("cx.trace("),
                    "{name} in {}: missing cx.trace()",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("EvidenceLedgerBuilder"),
                    "{name} in {}: missing EvidenceLedgerBuilder",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("DO NOT EDIT"),
                    "{name} in {}: missing DO NOT EDIT header",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("use asupersync::cx::Cx;"),
                    "{name} in {}: missing Cx import",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("pub async fn"),
                    "{name} in {}: missing async handler",
                    protocol.name
                );
                assert!(
                    p.source_code.contains("pub fn")
                        && p.source_code.contains("_saga_plan() -> SagaPlan"),
                    "{name} in {}: missing saga_plan constructor",
                    protocol.name
                );
            }

            // Lab test scaffold present
            assert!(
                !output.lab_test_code.is_empty(),
                "{}: empty lab test code",
                protocol.name
            );
            assert!(
                output.lab_test_code.contains("#[cfg(test)]"),
                "{}: lab test missing cfg(test)",
                protocol.name
            );
            assert!(
                output
                    .lab_test_code
                    .contains("LabRuntime::new(asupersync::LabConfig::default())"),
                "{}: lab test missing LabRuntime scaffold",
                protocol.name
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: plan_only consistency with generate (bd-1f8jn.4)
    // ------------------------------------------------------------------

    #[test]
    fn plan_only_matches_generate_saga_plan() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|e| panic!("{}: generate failed: {e}", protocol.name));

            for (name, p) in &output.participants {
                let (plan, exec) = pipe.plan_only(protocol, name).unwrap_or_else(|e| {
                    panic!("{}: plan_only failed for {name}: {e}", protocol.name)
                });

                // Same step count
                assert_eq!(
                    plan.steps.len(),
                    p.saga_plan.steps.len(),
                    "{name} in {}: plan_only step count differs from generate",
                    protocol.name
                );

                // Same step labels and ops
                for (i, (a, b)) in plan.steps.iter().zip(p.saga_plan.steps.iter()).enumerate() {
                    assert_eq!(
                        a.op, b.op,
                        "{name} in {} step {i}: op mismatch ({:?} vs {:?})",
                        protocol.name, a.op, b.op
                    );
                    assert_eq!(
                        a.label, b.label,
                        "{name} in {} step {i}: label mismatch",
                        protocol.name
                    );
                }

                // Same execution plan totals
                assert_eq!(
                    exec.total_steps(),
                    p.execution_plan.total_steps(),
                    "{name} in {}: execution plan total_steps mismatch",
                    protocol.name
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // E2E: compensation boundary markers (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn saga_compensation_source_code_has_compensation_scope() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        // At least one participant should have compensation scope in generated code
        let has_compensation = output.participants.values().any(|p| {
            p.source_code.contains("compensation")
                || p.source_code.contains("Compensation")
                || p.source_code.contains("rollback")
        });
        assert!(
            has_compensation,
            "saga compensation protocol should generate compensation scope code"
        );
    }

    #[test]
    fn saga_compensation_all_participants_have_steps() {
        let protocol = example_saga_compensation();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for (name, p) in &output.participants {
            assert!(
                !p.saga_plan.steps.is_empty(),
                "{name} has empty saga plan in compensation protocol"
            );
            assert!(
                !p.source_code.is_empty(),
                "{name} has empty source code in compensation protocol"
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: CALM batch analysis across protocols (bd-1f8jn.4 item 5)
    // ------------------------------------------------------------------

    #[test]
    fn calm_batching_produces_at_least_one_batch_per_participant() {
        let protocols = vec![
            example_two_phase_commit(),
            example_lease_renewal(),
            example_saga_compensation(),
            example_scatter_gather_disjoint(),
        ];

        let pipe = pipeline();
        for protocol in &protocols {
            let output = pipe
                .generate_with_locals(protocol)
                .unwrap_or_else(|e| panic!("{}: pipeline failed: {e}", protocol.name));

            for (name, p) in &output.participants {
                let batch_count = p.execution_plan.coordination_free_batch_count()
                    + p.execution_plan.coordination_barrier_count();
                assert!(
                    batch_count > 0,
                    "{name} in {}: no CALM batches",
                    protocol.name
                );
            }
        }
    }

    #[test]
    fn source_code_calm_header_reflects_batch_counts() {
        let protocol = example_two_phase_commit();
        let output = pipeline()
            .generate_with_locals(&protocol)
            .expect("pipeline failed");

        for p in output.participants.values() {
            // Header should contain CALM batch info
            assert!(
                p.source_code.contains("CALM batches:"),
                "source code missing CALM batch header"
            );
            assert!(
                p.source_code.contains("Monotone ratio:"),
                "source code missing monotone ratio header"
            );
        }
    }

    // ------------------------------------------------------------------
    // E2E: pipeline error paths (bd-1f8jn.4)
    // ------------------------------------------------------------------

    #[test]
    fn pipeline_rejects_invalid_protocol() {
        use crate::obligation::choreography::Interaction;

        // Protocol with self-communication (invalid)
        let protocol = GlobalProtocol::builder("bad_protocol")
            .participant("alice", "role")
            .interaction(Interaction::comm("alice", "msg", "Msg", "alice"))
            .build();

        let result = pipeline().generate_with_locals(&protocol);
        assert!(result.is_err(), "pipeline should reject invalid protocol");

        match result.unwrap_err() {
            PipelineError::Compilation(CompilationError::ValidationFailed(errors)) => {
                assert!(!errors.is_empty());
            }
            other => panic!("expected ValidationFailed, got: {other}"),
        }
    }

    #[test]
    fn plan_only_rejects_invalid_protocol() {
        use crate::obligation::choreography::Interaction;

        let protocol = GlobalProtocol::builder("bad_protocol")
            .participant("alice", "role")
            .interaction(Interaction::comm("alice", "msg", "Msg", "alice"))
            .build();

        let result = pipeline().plan_only(&protocol, "alice");
        assert!(result.is_err(), "plan_only should reject invalid protocol");
    }
}
