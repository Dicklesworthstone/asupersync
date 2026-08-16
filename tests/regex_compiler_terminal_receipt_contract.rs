//! Fail-closed terminal contract for the bounded regex compiler.

#[path = "../src/observability/regex_boundaries.rs"]
mod regex_boundaries;
#[path = "../src/observability/regex_ir.rs"]
mod regex_ir;
#[allow(dead_code)]
#[path = "../src/observability/regex_lowering.rs"]
mod regex_lowering;
#[path = "../src/observability/regex_semantics.rs"]
pub mod regex_semantics;
#[path = "../src/observability/regex_syntax.rs"]
mod regex_syntax;

// The frozen IR module's inline tests use the production crate path.
mod observability {
    pub use crate::regex_semantics;
}

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use regex::Regex as IncumbentRegex;
use regex_boundaries::FoldBoundaryLimits;
use regex_ir::{
    ACCOUNTED_CAPTURE_SLOT_BYTES, ACCOUNTED_CLASS_BYTES, ACCOUNTED_CLASS_RANGE_BYTES,
    ACCOUNTED_PROGRAM_BYTES, ACCOUNTED_STATE_BYTES, CaptureSlot, ClassId, CompileError,
    CompileErrorKind, CompileLimits, CompileResources, Instruction, Program, State, StateId,
};
use regex_lowering::{LOWERING_ID, LOWERING_SCHEMA_VERSION, lower};
use regex_semantics::{CanonicalRanges, ScalarRange, SemanticLimits};
use regex_syntax::{
    Ast, AstNodeKind, ClassSetOperator, LexerLimits, ParserLimits, SourceSpan, parse,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_compiler_terminal_receipt_v1.json";
const DOC_PATH: &str = "docs/regex_compiler_terminal_receipt.md";
const COMPILER_FUZZ_SEED: u64 = 0xC011_A3D5_7EED_0001;
const MALFORMED_IR_FUZZ_SEED: u64 = 0x1BAD_1DEA_7EED_0002;

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn contract() -> Value {
    serde_json::from_str(&read(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn object<'value>(
    value: &'value Value,
    key: &str,
) -> Result<&'value serde_json::Map<String, Value>, String> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{key} must be an object"))
}

fn array<'value>(value: &'value Value, key: &str) -> Result<&'value [Value], String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{key} must be an array"))
}

fn text<'value>(value: &'value Value, key: &str) -> Result<&'value str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> Result<bool, String> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{key} must be boolean"))
}

fn sha256(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    hex::encode(Sha256::digest(bytes))
}

fn lower_default(pattern: &str) -> Result<Program, regex_lowering::LowerError> {
    lower(
        pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits::default(),
    )
}

fn terminal_validate(value: &Value) -> Result<(), String> {
    if number(value, "schema_version")? != 1
        || text(value, "artifact_id")? != "regex-compiler-terminal-receipt-v1"
        || text(value, "bead_id")? != "asupersync-5z2scg.8.3.3.4"
        || text(value, "capability_id")? != "CAP-REGEX-PRIVACY"
        || text(value, "terminal_id")? != "ASUP-REGEX-COMPILER-TERMINAL-V1"
        || text(value, "grammar_id")? != regex_syntax::GRAMMAR_ID
        || text(value, "lowering_id")? != LOWERING_ID
        || number(value, "lowering_schema_version")? != u64::from(LOWERING_SCHEMA_VERSION)
        || text(value, "ir_id")? != regex_ir::IR_ID
        || number(value, "ir_schema_version")? != u64::from(regex_ir::IR_SCHEMA_VERSION)
    {
        return Err("terminal identity drifted".to_owned());
    }

    let decision = Value::Object(object(value, "decision")?.clone());
    if text(&decision, "disposition")? != "KEEP_INCUMBENT_DEFER"
        || text(&decision, "incumbent_state")? != "RETAIN_REGEX_AND_REGEX_SYNTAX"
        || text(&decision, "candidate_state")?
            != "BOUNDED_VALIDATED_COMPILER_WITHOUT_PRODUCTION_MATCHER"
        || !boolean(&decision, "compiler_terminal_complete")?
        || !boolean(&decision, "all_ast_rows_accounted")?
        || !boolean(&decision, "all_validator_error_rows_accounted")?
        || !boolean(&decision, "reference_language_evidence_complete")?
        || !boolean(&decision, "priority_capture_evidence_complete")?
        || !boolean(&decision, "bounded_compiler_fuzz_complete")?
        || !boolean(&decision, "malformed_ir_fuzz_complete")?
        || !boolean(&decision, "vm_experimentation_authorized")?
        || boolean(&decision, "matcher_execution_authorized")?
        || boolean(&decision, "production_cutover_eligible")?
        || boolean(&decision, "dependency_removal_authorized")?
        || text(&decision, "on_missing_unknown_expired_or_drifted_evidence")?
            != "KEEP_INCUMBENT_DEFER"
    {
        return Err("terminal decision must remain fail closed".to_owned());
    }

    let predecessors = array(value, "predecessors")?;
    let expected_predecessors = [
        (
            "artifacts/regex_semantic_terminal_receipt_v1.json",
            "139bfa189252df82fc62376efc23079b2ba0a56cc3f423d696750c0c3cedd77f",
        ),
        (
            "artifacts/regex_ir_schema_contract_v1.json",
            "6ccf18da906444a4e7041c07be955abffe2cc947229623663854966bdd3a1e17",
        ),
        (
            "artifacts/regex_ir_lowering_contract_v1.json",
            "5241cdc8d6f361eef2e7a435d2f104946a53c63ca2e2309201bced12889cfb05",
        ),
        (
            "artifacts/regex_priority_capture_lowering_contract_v1.json",
            "9a5b74d1c3c40cbe7ce5075be04d4eb1412d4871227ff296f9a3ca61b602e076",
        ),
    ];
    if predecessors.len() != expected_predecessors.len() {
        return Err("predecessor count drifted".to_owned());
    }
    for (row, (path, digest)) in predecessors.iter().zip(expected_predecessors) {
        if text(row, "path")? != path || text(row, "sha256")? != digest || sha256(path) != digest {
            return Err(format!("predecessor drifted: {path}"));
        }
    }

    let sources = array(value, "candidate_sources")?;
    if sources.len() != 5 {
        return Err("candidate source count drifted".to_owned());
    }
    for row in sources {
        let path = text(row, "path")?;
        let digest = text(row, "sha256")?;
        if sha256(path) != digest
            || fs::metadata(path)
                .map_err(|error| format!("metadata {path}: {error}"))?
                .len()
                != number(row, "bytes")?
            || text(row, "revision")?.len() != 40
        {
            return Err(format!("candidate source drifted: {path}"));
        }
    }

    let revisions = Value::Object(object(value, "source_revisions")?.clone());
    for (key, path) in [
        ("cargo_toml_sha256", "Cargo.toml"),
        ("cargo_lock_sha256", "Cargo.lock"),
        ("rust_toolchain_sha256", "rust-toolchain.toml"),
    ] {
        if text(&revisions, key)? != sha256(path) {
            return Err(format!("source revision digest drifted: {path}"));
        }
    }

    let oracle = Value::Object(object(value, "oracle")?.clone());
    if text(&oracle, "incumbent_package")? != "regex@1.13.1"
        || text(&oracle, "structural_reference_package")? != "regex-syntax@0.8.11"
        || text(&oracle, "independent_reference")? != "bounded_literal_language_enumerator_v1"
        || !boolean(&oracle, "incumbent_quarantined_to_test_evidence")?
        || !boolean(&oracle, "wording_is_not_compared")?
        || text(&oracle, "oracle_expiry_utc")? != "2026-10-23T00:00:00Z"
        || array(&oracle, "invalidate_earlier_on")?.len() != 4
    {
        return Err("oracle pin, quarantine, or expiry drifted".to_owned());
    }

    let ast_rows = array(value, "ast_rows")?;
    let ast_ids = ast_rows
        .iter()
        .map(|row| text(row, "row_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let ast_kinds = ast_rows
        .iter()
        .map(|row| text(row, "kind").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if ast_rows.len() != 23
        || ast_ids.len() != 23
        || ast_kinds.len() != 23
        || ast_rows
            .iter()
            .any(|row| !matches!(text(row, "result"), Ok("LOWERED_CHECKED")))
    {
        return Err("AST row join drifted".to_owned());
    }

    let quantifier_rows = array(value, "quantifier_rows")?;
    if quantifier_rows.len() != 10
        || quantifier_rows
            .iter()
            .any(|row| !matches!(text(row, "result"), Ok("LOWERED_CHECKED" | "KEEP_DEFER")))
    {
        return Err("quantifier row join drifted".to_owned());
    }

    let validator_rows = array(value, "validator_rows")?;
    let validator_codes = validator_rows
        .iter()
        .map(|row| text(row, "code").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if validator_rows.len() != 28
        || validator_codes
            != (1..=28)
                .map(|index| format!("RGX-IR-E{index:03}"))
                .collect()
    {
        return Err("validator error row join drifted".to_owned());
    }

    let limits = Value::Object(object(value, "limits")?.clone());
    let defaults = CompileLimits::default();
    for (key, expected) in [
        (
            "max_states",
            u64::try_from(defaults.max_states).map_err(|_| "max_states conversion")?,
        ),
        (
            "max_transitions",
            u64::try_from(defaults.max_transitions).map_err(|_| "max_transitions conversion")?,
        ),
        (
            "max_classes",
            u64::try_from(defaults.max_classes).map_err(|_| "max_classes conversion")?,
        ),
        (
            "max_ranges_per_class",
            u64::try_from(defaults.max_ranges_per_class)
                .map_err(|_| "max_ranges_per_class conversion")?,
        ),
        (
            "max_total_class_ranges",
            u64::try_from(defaults.max_total_class_ranges)
                .map_err(|_| "max_total_class_ranges conversion")?,
        ),
        (
            "max_capture_slots",
            u64::try_from(defaults.max_capture_slots)
                .map_err(|_| "max_capture_slots conversion")?,
        ),
        (
            "max_repetition_expansion",
            defaults.max_repetition_expansion,
        ),
        ("max_memory_bytes", defaults.max_memory_bytes),
        ("max_work_units", defaults.max_work_units),
    ] {
        if number(&limits, key)? != expected {
            return Err(format!("compile limit drifted: {key}"));
        }
    }

    let evidence = Value::Object(object(value, "evidence")?.clone());
    for (key, expected) in [
        ("ast_rows", 23),
        ("quantifier_rows", 10),
        ("validator_rows", 28),
        ("independent_language_patterns", 14),
        ("independent_max_haystack_length", 5),
        ("independent_language_comparisons", 882),
        ("priority_capture_goldens", 7),
        ("property_cases", 512),
        ("compiler_fuzz_cases", 1_024),
        ("compiler_fuzz_max_pattern_scalars", 48),
        ("malformed_ir_fuzz_cases", 1_024),
    ] {
        if number(&evidence, key)? != expected {
            return Err(format!("evidence count drifted: {key}"));
        }
    }
    if text(&evidence, "compiler_fuzz_seed")? != "0xC011_A3D5_7EED_0001"
        || text(&evidence, "malformed_ir_fuzz_seed")? != "0x1BAD_1DEA_7EED_0002"
        || boolean(&evidence, "panic_observed")?
        || boolean(&evidence, "hang_observed")?
        || boolean(&evidence, "unbounded_allocation_observed")?
        || boolean(&evidence, "partial_program_on_error")?
    {
        return Err("fuzz evidence must remain bounded and panic free".to_owned());
    }

    let minimized = array(value, "retained_minimized_cases")?;
    if minimized.len() != 3
        || minimized
            .iter()
            .any(|row| !matches!(text(row, "disposition"), Ok("KEEP_DEFER")))
    {
        return Err("retained minimized case disposition drifted".to_owned());
    }
    Ok(())
}

#[test]
fn identity_predecessors_sources_limits_and_decision_are_fail_closed() {
    terminal_validate(&contract()).expect("compiler terminal receipt must validate");
}

fn ast_kind_names(ast: &Ast) -> BTreeSet<&'static str> {
    ast.nodes
        .iter()
        .map(|node| match &node.kind {
            AstNodeKind::Empty => "empty",
            AstNodeKind::Literal(_) => "literal",
            AstNodeKind::Dot => "dot",
            AstNodeKind::Escape(_) => "escape",
            AstNodeKind::Assertion(_) => "assertion",
            AstNodeKind::LineStart => "line-start",
            AstNodeKind::LineEnd => "line-end",
            AstNodeKind::Concat(_) => "concat",
            AstNodeKind::Alternation(_) => "alternation",
            AstNodeKind::Capture { .. } => "capture",
            AstNodeKind::NonCapturing { .. } => "non-capturing",
            AstNodeKind::Flags { scoped: true, .. } => "flags-scoped",
            AstNodeKind::Flags { scoped: false, .. } => "flags-directive",
            AstNodeKind::Repetition { .. } => "repetition",
            AstNodeKind::Class { .. } => "class",
            AstNodeKind::ClassLiteral(_) => "class-literal",
            AstNodeKind::ClassEscape(_) => "class-escape",
            AstNodeKind::PosixClass { .. } => "posix-class",
            AstNodeKind::ClassRange { .. } => "class-range",
            AstNodeKind::ClassUnion(_) => "class-union",
            AstNodeKind::ClassSet {
                operator: ClassSetOperator::Intersection,
                ..
            } => "class-set-intersection",
            AstNodeKind::ClassSet {
                operator: ClassSetOperator::Difference,
                ..
            } => "class-set-difference",
            AstNodeKind::ClassSet {
                operator: ClassSetOperator::SymmetricDifference,
                ..
            } => "class-set-symmetric-difference",
        })
        .collect()
}

#[test]
fn every_ast_and_quantifier_row_has_checked_compiler_evidence() {
    let value = contract();
    for row in array(&value, "ast_rows").expect("AST rows") {
        let pattern = text(row, "pattern").expect("AST pattern");
        let expected_kind = text(row, "kind").expect("AST kind");
        let ast = parse(pattern, LexerLimits::default(), ParserLimits::default())
            .unwrap_or_else(|error| panic!("parse AST row {pattern:?}: {error}"));
        assert!(
            ast_kind_names(&ast).contains(expected_kind),
            "AST row {pattern:?} did not contain {expected_kind}"
        );
        let program = lower_default(pattern)
            .unwrap_or_else(|error| panic!("lower AST row {pattern:?}: {error}"));
        program
            .validate(CompileLimits::default())
            .unwrap_or_else(|error| panic!("validate AST row {pattern:?}: {error}"));
    }

    for row in array(&value, "quantifier_rows").expect("quantifier rows") {
        let pattern = text(row, "pattern").expect("quantifier pattern");
        match text(row, "result").expect("quantifier result") {
            "LOWERED_CHECKED" => lower_default(pattern)
                .unwrap_or_else(|error| panic!("lower quantifier row {pattern:?}: {error}"))
                .validate(CompileLimits::default())
                .unwrap_or_else(|error| panic!("validate quantifier row {pattern:?}: {error}")),
            "KEEP_DEFER" => {
                let error = lower_default(pattern)
                    .expect_err(&format!("quantifier row {pattern:?} must fail closed"));
                let expected = text(row, "error_code").expect("defer error code");
                assert_eq!(error.code(), expected, "{pattern:?}");
            }
            other => panic!("unexpected quantifier result {other}"),
        }
    }
}

fn reaccount(program: &mut Program) {
    let transitions = program
        .states
        .iter()
        .map(|state| state.instruction.transition_count())
        .sum::<usize>();
    let class_ranges = program
        .classes
        .iter()
        .map(|class| class.ranges.range_count())
        .sum::<usize>();
    let states = u64::try_from(program.states.len()).expect("small state count");
    let classes = u64::try_from(program.classes.len()).expect("small class count");
    let ranges = u64::try_from(class_ranges).expect("small range count");
    let slots = u64::try_from(program.capture_slots).expect("small slot count");
    let transition_count = u64::try_from(transitions).expect("small transition count");
    let accounted_memory_bytes = ACCOUNTED_PROGRAM_BYTES
        + states * ACCOUNTED_STATE_BYTES
        + classes * ACCOUNTED_CLASS_BYTES
        + ranges * ACCOUNTED_CLASS_RANGE_BYTES
        + slots * ACCOUNTED_CAPTURE_SLOT_BYTES;
    let work_units =
        1 + states + transition_count + classes + ranges + slots + program.repetition_expansion;
    program.resources = CompileResources {
        states: program.states.len(),
        transitions,
        classes: program.classes.len(),
        class_ranges,
        capture_slots: program.capture_slots,
        repetition_expansion: program.repetition_expansion,
        accounted_memory_bytes,
        work_units,
    };
}

fn observe_error(
    observed: &mut BTreeSet<(String, String)>,
    error: CompileError,
    expected: CompileErrorKind,
) {
    assert_eq!(error.kind, expected);
    observed.insert((error.code().to_owned(), format!("{expected:?}")));
}

fn validate_as(
    observed: &mut BTreeSet<(String, String)>,
    program: &Program,
    limits: CompileLimits,
    expected: CompileErrorKind,
) {
    let error = program
        .validate(limits)
        .expect_err(&format!("{expected:?} mutation must fail"));
    observe_error(observed, error, expected);
}

fn state_with_accept() -> State {
    State {
        instruction: Instruction::Accept,
        source: SourceSpan {
            byte_start: 0,
            byte_end: 0,
            scalar_start: 0,
            scalar_end: 0,
        },
    }
}

#[test]
fn validator_triggers_every_typed_error_and_rejects_collapsed_priority() {
    let mut observed = BTreeSet::new();

    let literal = lower_default("a").expect("literal program");
    validate_as(
        &mut observed,
        &literal,
        CompileLimits {
            max_states: 0,
            ..CompileLimits::default()
        },
        CompileErrorKind::InvalidLimits,
    );

    let mut invalid_schema = literal.clone();
    invalid_schema.schema_version = regex_ir::IR_SCHEMA_VERSION + 1;
    validate_as(
        &mut observed,
        &invalid_schema,
        CompileLimits::default(),
        CompileErrorKind::InvalidSchema,
    );

    let overflow = Program::checked(
        StateId::new(0),
        StateId::new(0),
        vec![state_with_accept()],
        vec![],
        0,
        u64::MAX,
        CompileLimits::default(),
    )
    .expect_err("work accounting must overflow");
    observe_error(
        &mut observed,
        overflow,
        CompileErrorKind::ArithmeticOverflow,
    );

    let mut empty = literal.clone();
    empty.states.clear();
    validate_as(
        &mut observed,
        &empty,
        CompileLimits::default(),
        CompileErrorKind::EmptyProgram,
    );
    validate_as(
        &mut observed,
        &literal,
        CompileLimits {
            max_states: literal.resources.states - 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::StateLimit,
    );

    let alternation = lower_default("a|b").expect("alternation");
    validate_as(
        &mut observed,
        &alternation,
        CompileLimits {
            max_transitions: 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::TransitionLimit,
    );
    let concat = lower_default("ab").expect("two classes");
    validate_as(
        &mut observed,
        &concat,
        CompileLimits {
            max_classes: 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::ClassLimit,
    );

    let ranged = lower_default("[a-cx-z]").expect("two canonical ranges");
    validate_as(
        &mut observed,
        &ranged,
        CompileLimits {
            max_ranges_per_class: 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::ClassRangeLimit,
    );
    validate_as(
        &mut observed,
        &ranged,
        CompileLimits {
            max_total_class_ranges: 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::TotalClassRangeLimit,
    );

    let capture = lower_default("(a)").expect("capture");
    validate_as(
        &mut observed,
        &capture,
        CompileLimits {
            max_capture_slots: 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::CaptureSlotLimit,
    );
    let mut odd_slots = capture.clone();
    odd_slots.capture_slots = 1;
    validate_as(
        &mut observed,
        &odd_slots,
        CompileLimits::default(),
        CompileErrorKind::OddCaptureSlots,
    );

    let repeated = lower_default("a{3}").expect("repetition expansion");
    validate_as(
        &mut observed,
        &repeated,
        CompileLimits {
            max_repetition_expansion: 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::RepetitionLimit,
    );
    validate_as(
        &mut observed,
        &literal,
        CompileLimits {
            max_memory_bytes: literal.resources.accounted_memory_bytes - 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::MemoryLimit,
    );
    validate_as(
        &mut observed,
        &literal,
        CompileLimits {
            max_work_units: literal.resources.work_units - 1,
            ..CompileLimits::default()
        },
        CompileErrorKind::WorkLimit,
    );

    let mut accounting = literal.clone();
    accounting.resources.work_units += 1;
    validate_as(
        &mut observed,
        &accounting,
        CompileLimits::default(),
        CompileErrorKind::ResourceAccountingMismatch,
    );
    let mut invalid_entry = literal.clone();
    invalid_entry.entry = StateId::new(usize::MAX);
    validate_as(
        &mut observed,
        &invalid_entry,
        CompileLimits::default(),
        CompileErrorKind::InvalidEntry,
    );
    let mut invalid_accept = literal.clone();
    invalid_accept.accept = StateId::new(usize::MAX);
    validate_as(
        &mut observed,
        &invalid_accept,
        CompileLimits::default(),
        CompileErrorKind::InvalidAccept,
    );

    let mut accept_not_terminal = literal.clone();
    accept_not_terminal.states[accept_not_terminal.accept.index()].instruction =
        Instruction::Jump {
            target: accept_not_terminal.accept,
        };
    reaccount(&mut accept_not_terminal);
    validate_as(
        &mut observed,
        &accept_not_terminal,
        CompileLimits::default(),
        CompileErrorKind::AcceptNotTerminal,
    );

    let mut extra_accept = literal.clone();
    extra_accept.states[0].instruction = Instruction::Accept;
    reaccount(&mut extra_accept);
    validate_as(
        &mut observed,
        &extra_accept,
        CompileLimits::default(),
        CompileErrorKind::ExtraAcceptState,
    );

    let mut invalid_target = literal.clone();
    invalid_target.states[0].instruction = Instruction::Jump {
        target: StateId::new(usize::MAX),
    };
    validate_as(
        &mut observed,
        &invalid_target,
        CompileLimits::default(),
        CompileErrorKind::InvalidTarget,
    );
    let mut invalid_class = literal.clone();
    invalid_class.states[0].instruction = Instruction::Consume {
        class: ClassId::new(usize::MAX),
        target: literal.accept,
    };
    validate_as(
        &mut observed,
        &invalid_class,
        CompileLimits::default(),
        CompileErrorKind::InvalidClassReference,
    );
    let mut invalid_slot = capture.clone();
    let save = invalid_slot
        .states
        .iter_mut()
        .find(|state| matches!(state.instruction, Instruction::Save { .. }))
        .expect("capture Save");
    let Instruction::Save { target, .. } = save.instruction else {
        unreachable!("Save selected");
    };
    save.instruction = Instruction::Save {
        slot: CaptureSlot::new(usize::MAX),
        target,
    };
    validate_as(
        &mut observed,
        &invalid_slot,
        CompileLimits::default(),
        CompileErrorKind::InvalidCaptureSlot,
    );

    let mut invalid_span = literal.clone();
    invalid_span.states[0].source.byte_end = invalid_span.states[0].source.byte_start;
    validate_as(
        &mut observed,
        &invalid_span,
        CompileLimits::default(),
        CompileErrorKind::InvalidSpan,
    );
    let mut noncanonical = literal.clone();
    noncanonical.classes[0].ranges = CanonicalRanges::Unicode(vec![ScalarRange::new('z', 'a')]);
    validate_as(
        &mut observed,
        &noncanonical,
        CompileLimits::default(),
        CompileErrorKind::NonCanonicalClass,
    );

    let mut unreferenced_class = concat;
    for state in &mut unreferenced_class.states {
        if let Instruction::Consume { class, target } = state.instruction
            && class == ClassId::new(1)
        {
            state.instruction = Instruction::Consume {
                class: ClassId::new(0),
                target,
            };
        }
    }
    validate_as(
        &mut observed,
        &unreferenced_class,
        CompileLimits::default(),
        CompileErrorKind::UnreferencedClass,
    );

    let mut unreferenced_slot = capture;
    for state in &mut unreferenced_slot.states {
        if let Instruction::Save { slot, target } = state.instruction
            && slot == CaptureSlot::new(0)
        {
            state.instruction = Instruction::Save {
                slot: CaptureSlot::new(1),
                target,
            };
        }
    }
    validate_as(
        &mut observed,
        &unreferenced_slot,
        CompileLimits::default(),
        CompileErrorKind::UnreferencedCaptureSlot,
    );

    let mut unreachable_accept = literal;
    let Instruction::Consume { class, .. } = unreachable_accept.states[0].instruction else {
        panic!("literal entry must consume");
    };
    unreachable_accept.states[0].instruction = Instruction::Consume {
        class,
        target: StateId::new(0),
    };
    validate_as(
        &mut observed,
        &unreachable_accept,
        CompileLimits::default(),
        CompileErrorKind::AcceptUnreachable,
    );

    let mut collapsed_priority = lower_default("^|$").expect("assertion alternation");
    let split = collapsed_priority
        .states
        .iter_mut()
        .find(|state| matches!(state.instruction, Instruction::Split { .. }))
        .expect("ordered split");
    let Instruction::Split { preferred, .. } = split.instruction else {
        unreachable!("Split selected");
    };
    split.instruction = Instruction::Split {
        preferred,
        fallback: preferred,
    };
    validate_as(
        &mut observed,
        &collapsed_priority,
        CompileLimits::default(),
        CompileErrorKind::UnreachableState,
    );

    let expected = array(&contract(), "validator_rows")
        .expect("validator rows")
        .iter()
        .map(|row| {
            (
                text(row, "code").expect("validator code").to_owned(),
                text(row, "kind").expect("validator kind").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(observed, expected);
}

#[derive(Clone)]
enum ReferenceExpr {
    Empty,
    Literal(char),
    Concat(Vec<Self>),
    Alternation(Vec<Self>),
    Repeat {
        child: Box<Self>,
        min: usize,
        max: Option<usize>,
    },
}

fn concatenate_sets(
    left: &BTreeSet<String>,
    right: &BTreeSet<String>,
    max_len: usize,
) -> BTreeSet<String> {
    let mut output = BTreeSet::new();
    for prefix in left {
        for suffix in right {
            if prefix.len() + suffix.len() <= max_len {
                output.insert(format!("{prefix}{suffix}"));
            }
        }
    }
    output
}

fn reference_language(expression: &ReferenceExpr, max_len: usize) -> BTreeSet<String> {
    match expression {
        ReferenceExpr::Empty => BTreeSet::from([String::new()]),
        ReferenceExpr::Literal(value) => BTreeSet::from([value.to_string()]),
        ReferenceExpr::Concat(children) => {
            children
                .iter()
                .fold(BTreeSet::from([String::new()]), |language, child| {
                    concatenate_sets(&language, &reference_language(child, max_len), max_len)
                })
        }
        ReferenceExpr::Alternation(children) => children
            .iter()
            .flat_map(|child| reference_language(child, max_len))
            .collect(),
        ReferenceExpr::Repeat { child, min, max } => {
            let child_language = reference_language(child, max_len);
            let maximum = max.unwrap_or(max_len);
            let mut output = BTreeSet::new();
            let mut exact = BTreeSet::from([String::new()]);
            for count in 0..=maximum {
                if count >= *min {
                    output.extend(exact.iter().cloned());
                }
                exact = concatenate_sets(&exact, &child_language, max_len);
            }
            output
        }
    }
}

fn literal(value: char) -> ReferenceExpr {
    ReferenceExpr::Literal(value)
}

fn alternation(children: Vec<ReferenceExpr>) -> ReferenceExpr {
    ReferenceExpr::Alternation(children)
}

fn concat(children: Vec<ReferenceExpr>) -> ReferenceExpr {
    ReferenceExpr::Concat(children)
}

fn repeat(child: ReferenceExpr, min: usize, max: Option<usize>) -> ReferenceExpr {
    ReferenceExpr::Repeat {
        child: Box::new(child),
        min,
        max,
    }
}

fn small_haystacks(alphabet: &[char], max_len: usize) -> Vec<String> {
    let mut values = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..max_len {
        frontier = frontier
            .iter()
            .flat_map(|prefix| {
                alphabet
                    .iter()
                    .map(move |suffix| format!("{prefix}{suffix}"))
            })
            .collect();
        values.extend(frontier.iter().cloned());
    }
    values
}

fn class_matches(ranges: &CanonicalRanges, haystack: &str, offset: usize) -> Option<usize> {
    match ranges {
        CanonicalRanges::Unicode(_) => haystack.get(offset..)?.chars().next().and_then(|scalar| {
            ranges
                .contains_scalar(scalar)
                .then_some(offset + scalar.len_utf8())
        }),
        CanonicalRanges::Bytes(byte_ranges) => {
            let byte = *haystack.as_bytes().get(offset)?;
            byte_ranges
                .iter()
                .any(|range| byte >= range.start && byte <= range.end)
                .then_some(offset + 1)
        }
    }
}

fn prioritized_match(program: &Program, haystack: &str) -> Option<Vec<Option<(usize, usize)>>> {
    let initial_slots = vec![None; program.capture_slots];
    let mut pending = vec![(program.entry, 0_usize, initial_slots)];
    let mut seen = BTreeSet::new();
    while let Some((state_id, offset, slots)) = pending.pop() {
        if !seen.insert((state_id.index(), offset, slots.clone())) {
            continue;
        }
        let state = program.states.get(state_id.index())?;
        match state.instruction {
            Instruction::Accept => {
                if offset == haystack.len() {
                    return Some(
                        slots
                            .chunks_exact(2)
                            .map(|pair| pair[0].zip(pair[1]))
                            .collect(),
                    );
                }
            }
            Instruction::Jump { target } => pending.push((target, offset, slots)),
            Instruction::Split {
                preferred,
                fallback,
            } => {
                pending.push((fallback, offset, slots.clone()));
                pending.push((preferred, offset, slots));
            }
            Instruction::Consume { class, target } => {
                let ranges = &program.classes.get(class.index())?.ranges;
                if let Some(next) = class_matches(ranges, haystack, offset) {
                    pending.push((target, next, slots));
                }
            }
            Instruction::Assert { kind, target } => {
                if kind.is_match(haystack, offset).unwrap_or(false) {
                    pending.push((target, offset, slots));
                }
            }
            Instruction::Save { slot, target } => {
                let mut updated = slots;
                *updated.get_mut(slot.index())? = Some(offset);
                pending.push((target, offset, updated));
            }
        }
    }
    None
}

fn incumbent_match(pattern: &str, haystack: &str) -> Option<Vec<Option<(usize, usize)>>> {
    let anchored =
        IncumbentRegex::new(&format!(r"\A(?:{pattern})\z")).expect("fixture must compile");
    let captures = anchored.captures(haystack)?;
    Some(
        (1..captures.len())
            .map(|index| {
                captures
                    .get(index)
                    .map(|matched| (matched.start(), matched.end()))
            })
            .collect(),
    )
}

#[test]
fn independent_bounded_language_enumerator_agrees_for_all_small_haystacks() {
    let a = || literal('a');
    let b = || literal('b');
    let cases = [
        ("", ReferenceExpr::Empty),
        ("a", a()),
        ("b", b()),
        ("ab", concat(vec![a(), b()])),
        ("a|b", alternation(vec![a(), b()])),
        ("(?:a|b)b", concat(vec![alternation(vec![a(), b()]), b()])),
        ("a?", repeat(a(), 0, Some(1))),
        ("a*", repeat(a(), 0, None)),
        ("a+", repeat(a(), 1, None)),
        ("a{2}", repeat(a(), 2, Some(2))),
        ("a{1,3}", repeat(a(), 1, Some(3))),
        ("(?:ab){0,2}", repeat(concat(vec![a(), b()]), 0, Some(2))),
        (
            "(?:a|b){2}",
            repeat(alternation(vec![a(), b()]), 2, Some(2)),
        ),
        ("a{2,}", repeat(a(), 2, None)),
    ];
    let haystacks = small_haystacks(&['a', 'b'], 5);
    assert_eq!(haystacks.len(), 63);
    for (pattern, expression) in cases {
        let expected = reference_language(&expression, 5);
        let program = lower_default(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        for haystack in &haystacks {
            assert_eq!(
                prioritized_match(&program, haystack).is_some(),
                expected.contains(haystack),
                "pattern={pattern:?} haystack={haystack:?}"
            );
        }
    }
}

#[test]
fn prioritized_capture_goldens_match_the_pinned_incumbent() {
    for (pattern, haystack, expected) in [
        ("(a*)(a*)", "aa", vec![Some((0, 2)), Some((2, 2))]),
        ("(a*?)(a*)", "aa", vec![Some((0, 0)), Some((0, 2))]),
        ("(a+?)(a*)", "aa", vec![Some((0, 1)), Some((1, 2))]),
        ("(a{1,2}?)(a?)", "aa", vec![Some((0, 1)), Some((1, 2))]),
        ("(?i:(a+))", "Aa", vec![Some((0, 2))]),
        ("(a|aa)(a?)", "aa", vec![Some((0, 1)), Some((1, 2))]),
        ("(aa|a)(a?)", "aa", vec![Some((0, 2)), Some((2, 2))]),
    ] {
        let program = lower_default(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        assert_eq!(
            prioritized_match(&program, haystack),
            Some(expected.clone()),
            "{pattern:?}"
        );
        assert_eq!(incumbent_match(pattern, haystack), Some(expected));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn generated_priority_and_capture_cases_match_the_incumbent(
        left in prop::sample::select(&["a", "b", "[ab]", "(?:a|b)", "(?i:a)"]),
        left_quantifier in prop::sample::select(&["", "?", "*", "+", "{0,2}", "{1,3}", "{2,}"]),
        right in prop::sample::select(&["a", "b", "[ab]", "(?:a|b)"]),
        right_quantifier in prop::sample::select(&["", "?", "*?", "+?", "{0,2}?", "{1,3}?"]),
        haystack in prop::collection::vec(prop::sample::select(&['a', 'b', 'A']), 0..=5),
    ) {
        let pattern = format!("({left}{left_quantifier})({right}{right_quantifier})");
        let haystack = haystack.into_iter().collect::<String>();
        let program = lower_default(&pattern)
            .unwrap_or_else(|error| panic!("{pattern}: {error}"));
        prop_assert_eq!(
            prioritized_match(&program, &haystack),
            incumbent_match(&pattern, &haystack),
            "pattern={:?} haystack={:?}",
            pattern,
            haystack
        );
    }
}

fn xorshift64(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn bounded_utf8_compiler_fuzz_is_panic_free_and_never_leaks_partial_ir() {
    const ALPHABET: &[char] = &[
        'a', 'b', 'A', 'Σ', '😀', '(', ')', '[', ']', '{', '}', '?', '*', '+', '|', '^', '$', '\\',
        '.', '-', ':', 'i', 'u', ',', '0', '1', '2',
    ];
    let limits = CompileLimits {
        max_states: 256,
        max_transitions: 512,
        max_classes: 128,
        max_ranges_per_class: 256,
        max_total_class_ranges: 512,
        max_capture_slots: 64,
        max_repetition_expansion: 256,
        max_memory_bytes: 256 * 1024,
        max_work_units: 16 * 1024,
    };
    let mut state = COMPILER_FUZZ_SEED;
    let mut successes = 0_usize;
    let mut failures = 0_usize;
    let alphabet_len = u64::try_from(ALPHABET.len()).expect("alphabet length fits u64");
    for _ in 0..1_024 {
        let length = usize::try_from(xorshift64(&mut state) % 49).expect("bounded fuzz length");
        let pattern = (0..length)
            .map(|_| {
                let index = usize::try_from(xorshift64(&mut state) % alphabet_len)
                    .expect("bounded alphabet index");
                ALPHABET[index]
            })
            .collect::<String>();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            lower(
                &pattern,
                LexerLimits {
                    max_pattern_bytes: 256,
                    max_tokens: 256,
                },
                ParserLimits {
                    max_ast_nodes: 256,
                    max_nesting: 32,
                },
                SemanticLimits {
                    max_semantic_atoms: 128,
                    max_ranges_per_class: 256,
                    max_total_ranges: 512,
                    backend_nesting_limit: 32,
                },
                FoldBoundaryLimits {
                    max_fold_atoms: 128,
                    max_ranges_per_fold: 256,
                    max_total_fold_ranges: 512,
                    max_boundary_assertions: 128,
                    backend_nesting_limit: 32,
                },
                limits,
            )
        }));
        let compiled = outcome.unwrap_or_else(|_| panic!("compiler fuzz panicked for {pattern:?}"));
        match compiled {
            Ok(program) => {
                program
                    .validate(limits)
                    .unwrap_or_else(|error| panic!("fuzz program did not revalidate: {error}"));
                successes += 1;
            }
            Err(_) => failures += 1,
        }
    }
    assert!(
        successes > 0,
        "fuzz corpus must exercise successful lowering"
    );
    assert!(failures > 0, "fuzz corpus must exercise typed failures");
}

fn mutate_ir_for_fuzz(selector: u64, noise: u64) -> Program {
    match selector % 10 {
        0 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.schema_version = regex_ir::IR_SCHEMA_VERSION + 1;
            program
        }
        1 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.entry = StateId::new(usize::MAX);
            program
        }
        2 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.accept = StateId::new(usize::MAX);
            program
        }
        3 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.states[0].instruction = Instruction::Jump {
                target: StateId::new(
                    program
                        .states
                        .len()
                        .saturating_add(usize::try_from(noise % 1_024).expect("bounded noise"))
                        .saturating_add(1),
                ),
            };
            program
        }
        4 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.states[0].instruction = Instruction::Consume {
                class: ClassId::new(usize::MAX),
                target: program.accept,
            };
            program
        }
        5 => {
            let mut program = lower_default("(a)").expect("fuzz capture");
            let save = program
                .states
                .iter_mut()
                .find(|state| matches!(state.instruction, Instruction::Save { .. }))
                .expect("capture Save");
            let Instruction::Save { target, .. } = save.instruction else {
                unreachable!("Save selected");
            };
            save.instruction = Instruction::Save {
                slot: CaptureSlot::new(usize::MAX),
                target,
            };
            program
        }
        6 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.states[0].source.byte_end = program.states[0].source.byte_start;
            program
        }
        7 => {
            let mut program = lower_default("a").expect("fuzz literal");
            program.resources.work_units ^= noise | 1;
            program
        }
        8 => {
            let mut program = lower_default("^|$").expect("fuzz priority");
            let split = program
                .states
                .iter_mut()
                .find(|state| matches!(state.instruction, Instruction::Split { .. }))
                .expect("priority Split");
            let Instruction::Split { preferred, .. } = split.instruction else {
                unreachable!("Split selected");
            };
            split.instruction = Instruction::Split {
                preferred,
                fallback: preferred,
            };
            program
        }
        _ => {
            let mut program = lower_default("a").expect("fuzz literal");
            let Instruction::Consume { class, .. } = program.states[0].instruction else {
                panic!("literal entry must consume");
            };
            program.states[0].instruction = Instruction::Consume {
                class,
                target: StateId::new(0),
            };
            program
        }
    }
}

#[test]
fn deterministic_malformed_ir_fuzz_returns_only_typed_errors() {
    let mut state = MALFORMED_IR_FUZZ_SEED;
    let mut observed_codes = BTreeSet::new();
    for _ in 0..1_024 {
        let selector = xorshift64(&mut state);
        let noise = xorshift64(&mut state);
        let program = mutate_ir_for_fuzz(selector, noise);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            program.validate(CompileLimits::default())
        }));
        let validation = outcome.unwrap_or_else(|_| panic!("malformed IR validator panicked"));
        let error = validation.expect_err("every malformed IR mutation must fail");
        observed_codes.insert(error.code());
    }
    assert!(
        observed_codes.len() >= 8,
        "mutation corpus must exercise distinct validator classes"
    );
}

#[test]
fn docs_replay_oracle_minimized_cases_and_no_claims_are_machine_checked() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in array(&value, "required_doc_markers").expect("doc markers") {
        let marker = marker.as_str().expect("doc marker text");
        assert!(docs.contains(marker), "missing doc marker {marker}");
    }

    let proof = Value::Object(object(&value, "proof").expect("proof").clone());
    for key in ["contract_command", "clippy_command"] {
        let command = text(&proof, key).expect("proof command");
        assert!(command.contains("RCH_REQUIRE_REMOTE=1 rch exec"));
        assert!(command.contains("--base HEAD --clean-overlay"));
        assert!(command.contains("CARGO_INCREMENTAL=0"));
        assert!(command.contains("CARGO_PROFILE_TEST_DEBUG=0"));
        assert!(
            command.contains("--overlay-path tests/regex_compiler_terminal_receipt_contract.rs")
        );
        assert!(!command.contains("ALLOW_LOCAL"));
    }
    assert_eq!(
        text(&proof, "format_command").expect("format command"),
        "rustfmt --edition 2024 --check tests/regex_compiler_terminal_receipt_contract.rs"
    );
    assert!(!boolean(&proof, "local_cargo_fallback").expect("local fallback"));

    let minimized = array(&value, "retained_minimized_cases").expect("minimized cases");
    let minimized_map = minimized
        .iter()
        .map(|row| {
            (
                text(row, "pattern").expect("minimized pattern"),
                text(row, "error_code").expect("minimized error"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(minimized_map.get("(?:a?)*"), Some(&"RGX-LOWER-E009"));
    assert_eq!(minimized_map.get("(a){0}"), Some(&"RGX-LOWER-E010"));
    let mut unsupported_property = String::from(r"\p");
    unsupported_property.push('{');
    unsupported_property.push_str("Age:16.0");
    unsupported_property.push('}');
    assert_eq!(
        minimized_map.get(unsupported_property.as_str()),
        Some(&"RGX-LEX-E004")
    );

    let no_claims = array(&value, "no_claims")
        .expect("no claims")
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .expect("no-claim strings");
    for boundary in [
        "no matcher or VM execution correctness",
        "no production wiring or dependency removal",
        "no persisted or deserializable IR format",
        "no performance improvement or no-regression claim",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(&boundary), "missing no-claim {boundary}");
    }
}
