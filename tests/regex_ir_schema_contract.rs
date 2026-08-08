#[path = "../src/observability/regex_boundaries.rs"]
mod regex_boundaries;
#[path = "../src/observability/regex_ir.rs"]
mod regex_ir;
#[path = "../src/observability/regex_semantics.rs"]
pub mod regex_semantics;
#[path = "../src/observability/regex_syntax.rs"]
mod regex_syntax;

// The source module's inline tests use the production crate path. Re-export
// the sibling semantic module through the same private facade in this
// integration-test crate so those tests exercise the identical source.
mod observability {
    pub use crate::regex_semantics;
}

use std::collections::BTreeSet;
use std::fs;

use regex_ir::{
    ACCOUNTED_CAPTURE_SLOT_BYTES, ACCOUNTED_CLASS_BYTES, ACCOUNTED_CLASS_RANGE_BYTES,
    ACCOUNTED_PROGRAM_BYTES, ACCOUNTED_STATE_BYTES, ClassId, CompileErrorKind, CompileLimits,
    DIAGNOSTIC_SCHEMA_ID, IR_ID, IR_SCHEMA_VERSION, Instruction, IrClass, PERSISTENCE_POLICY,
    Program, State, StateId,
};
use regex_semantics::{CanonicalRanges, ScalarRange};
use regex_syntax::SourceSpan;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_ir_schema_contract_v1.json";
const DOC_PATH: &str = "docs/regex_ir_schema_contract.md";
const SOURCE_PATH: &str = "src/observability/regex_ir.rs";
const TERMINAL_PATH: &str = "artifacts/regex_semantic_terminal_receipt_v1.json";
const FROZEN_SOURCE_SHA256: &str =
    "de4906beb838fda2c57bccfdb16316e8de661e564940a47e7b9b87f065311cb3";
const FROZEN_TERMINAL_SHA256: &str =
    "0f6482523661aff2ded0450f569a871abff52e91f7645a79dc4281c1a4bafe08";

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn contract() -> Value {
    serde_json::from_str(&read(ARTIFACT_PATH))
        .unwrap_or_else(|error| panic!("parse {ARTIFACT_PATH}: {error}"))
}

fn object<'value>(value: &'value Value, key: &str) -> &'value serde_json::Map<String, Value> {
    value
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{key} must be an object"))
}

fn array<'value>(value: &'value Value, key: &str) -> &'value [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn text<'value>(value: &'value Value, key: &str) -> &'value str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be text"))
}

fn number(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{key} must be an unsigned integer"))
}

fn boolean(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} must be boolean"))
}

fn sha256(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn identity_authority_sources_and_decision_are_fail_closed() {
    let value = contract();
    assert_eq!(number(&value, "schema_version"), 1);
    assert_eq!(text(&value, "artifact_id"), "regex-ir-schema-contract-v1");
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.3.1");
    assert_eq!(text(&value, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(text(&value, "ir_id"), IR_ID);
    assert_eq!(number(&value, "ir_schema_version"), 1);
    assert_eq!(text(&value, "diagnostic_schema_id"), DIAGNOSTIC_SCHEMA_ID);
    assert_eq!(IR_SCHEMA_VERSION, 1);

    let decision = Value::Object(object(&value, "decision").clone());
    assert_eq!(
        text(&decision, "disposition"),
        "STAGED_BOUNDED_THOMPSON_IR_SCHEMA"
    );
    assert_eq!(
        text(&decision, "incumbent_state"),
        "RETAIN_REGEX_AND_REGEX_SYNTAX"
    );
    assert!(boolean(&decision, "compiler_experimentation_authorized"));
    assert!(boolean(&decision, "compiler_must_retain_pinned_semantics"));
    assert!(boolean(&decision, "r3_3_1_schema_complete"));
    assert!(boolean(&decision, "lowering_authorized_for_r3_3_2"));
    assert!(!boolean(&decision, "matcher_execution_authorized"));
    assert!(!boolean(&decision, "production_wiring_authorized"));
    assert!(!boolean(&decision, "persistence_authorized"));
    assert!(!boolean(&decision, "cutover_eligible"));
    assert!(!boolean(&decision, "dependency_removal_authorized"));
    assert!(array(&decision, "unknown_representation_needs").is_empty());

    let authority = Value::Object(object(&value, "authority").clone());
    assert_eq!(text(&authority, "semantic_terminal_path"), TERMINAL_PATH);
    assert_eq!(
        text(&authority, "semantic_terminal_sha256"),
        FROZEN_TERMINAL_SHA256
    );
    assert_eq!(
        text(&authority, "semantic_terminal_disposition"),
        "KEEP_INCUMBENT_DEFER"
    );
    assert!(!boolean(
        &authority,
        "capability_registry_persistence_contract"
    ));
    assert_eq!(sha256(TERMINAL_PATH), FROZEN_TERMINAL_SHA256);
    assert_eq!(sha256(SOURCE_PATH), FROZEN_SOURCE_SHA256);

    let sources = array(&value, "sources");
    assert_eq!(sources.len(), 4);
    for source in sources {
        assert_eq!(sha256(text(source, "path")), text(source, "sha256"));
        assert!(number(source, "bytes") > 0);
    }
}

#[test]
fn every_field_instruction_and_accepted_syntax_need_is_mapped() {
    let value = contract();
    let fields = array(&value, "program_fields")
        .iter()
        .map(|row| text(row, "field"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        BTreeSet::from([
            "schema_version",
            "ir_id",
            "entry",
            "accept",
            "states",
            "classes",
            "capture_slots",
            "repetition_expansion",
            "resources",
        ])
    );

    let instructions = array(&value, "instruction_schema")
        .iter()
        .map(|row| text(row, "op"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        instructions,
        BTreeSet::from(["Accept", "Jump", "Split", "Consume", "Assert", "Save"])
    );

    let syntax = array(&value, "accepted_syntax_mapping")
        .iter()
        .filter_map(|row| row.get("ast").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        syntax,
        BTreeSet::from([
            "Empty",
            "Literal",
            "Dot",
            "Escape",
            "Assertion",
            "LineStart",
            "LineEnd",
            "Concat",
            "Alternation",
            "Capture",
            "NonCapturing",
            "Flags",
            "Repetition",
            "Class",
            "ClassLiteral",
            "ClassEscape",
            "PosixClass",
            "ClassRange",
            "ClassUnion",
            "ClassSet",
        ])
    );
    assert!(
        array(&value, "accepted_syntax_mapping")
            .iter()
            .all(|row| !row.to_string().contains("UNKNOWN"))
    );
}

#[test]
fn accounting_limits_failures_and_diagnostics_are_exact() {
    let value = contract();
    let resources = Value::Object(object(&value, "resource_contract").clone());
    assert_eq!(
        text(&resources, "accounting_model"),
        "TARGET_INDEPENDENT_FIXED_SCHEMA_COSTS"
    );
    assert!(!boolean(&resources, "uses_rust_size_of"));
    let bytes = Value::Object(object(&resources, "accounted_bytes").clone());
    assert_eq!(number(&bytes, "program"), ACCOUNTED_PROGRAM_BYTES);
    assert_eq!(number(&bytes, "state"), ACCOUNTED_STATE_BYTES);
    assert_eq!(number(&bytes, "class"), ACCOUNTED_CLASS_BYTES);
    assert_eq!(number(&bytes, "class_range"), ACCOUNTED_CLASS_RANGE_BYTES);
    assert_eq!(number(&bytes, "capture_slot"), ACCOUNTED_CAPTURE_SLOT_BYTES);

    let limits = CompileLimits::default();
    let frozen = Value::Object(object(&resources, "default_limits").clone());
    assert_eq!(number(&frozen, "states"), limits.max_states as u64);
    assert_eq!(
        number(&frozen, "transitions"),
        limits.max_transitions as u64
    );
    assert_eq!(number(&frozen, "classes"), limits.max_classes as u64);
    assert_eq!(
        number(&frozen, "ranges_per_class"),
        limits.max_ranges_per_class as u64
    );
    assert_eq!(
        number(&frozen, "total_class_ranges"),
        limits.max_total_class_ranges as u64
    );
    assert_eq!(
        number(&frozen, "capture_slots"),
        limits.max_capture_slots as u64
    );
    assert_eq!(
        number(&frozen, "repetition_expansion"),
        limits.max_repetition_expansion
    );
    assert_eq!(number(&frozen, "memory_bytes"), limits.max_memory_bytes);
    assert_eq!(number(&frozen, "work_units"), limits.max_work_units);

    let failures = array(&value, "compile_failures");
    assert_eq!(failures.len(), 28);
    let codes = failures
        .iter()
        .map(|row| text(row, "code"))
        .collect::<BTreeSet<_>>();
    assert_eq!(codes.len(), failures.len());
    assert_eq!(CompileErrorKind::InvalidLimits.code(), "RGX-IR-E001");
    assert_eq!(CompileErrorKind::UnreachableState.code(), "RGX-IR-E028");

    let diagnostic = Value::Object(object(&value, "diagnostic_contract").clone());
    assert_eq!(text(&diagnostic, "persistence_policy"), PERSISTENCE_POLICY);
    assert!(!boolean(&diagnostic, "decoder_exists"));
    assert!(!boolean(&diagnostic, "raw_pattern_included"));
    assert!(boolean(&diagnostic, "all_program_fields_included"));
    assert!(!boolean(
        &diagnostic,
        "cross_version_compatibility_promised"
    ));
}

#[test]
fn checked_constructor_emits_only_valid_complete_programs() {
    let span = SourceSpan {
        byte_start: 0,
        byte_end: 1,
        scalar_start: 0,
        scalar_end: 1,
    };
    let program = Program::checked(
        StateId::new(0),
        StateId::new(1),
        vec![
            State {
                instruction: Instruction::Consume {
                    class: ClassId::new(0),
                    target: StateId::new(1),
                },
                source: span,
            },
            State {
                instruction: Instruction::Accept,
                source: SourceSpan {
                    byte_start: 1,
                    byte_end: 1,
                    scalar_start: 1,
                    scalar_end: 1,
                },
            },
        ],
        vec![IrClass {
            ranges: CanonicalRanges::Unicode(vec![ScalarRange::new('x', 'x')]),
            source: span,
        }],
        0,
        0,
        CompileLimits::default(),
    )
    .expect("tiny canonical program");
    program
        .validate(CompileLimits::default())
        .expect("checked program validates");
    assert_eq!(program.resources.states, 2);
    assert_eq!(program.resources.transitions, 1);

    let diagnostic = program.diagnostic_json();
    assert_eq!(text(&diagnostic, "schema_id"), DIAGNOSTIC_SCHEMA_ID);
    assert_eq!(text(&diagnostic, "persistence_policy"), PERSISTENCE_POLICY);
    assert!(!diagnostic.to_string().contains("secret-pattern"));

    let error = program
        .validate(CompileLimits {
            max_states: 1,
            ..CompileLimits::default()
        })
        .expect_err("state ceiling must fail");
    assert_eq!(error.kind, CompileErrorKind::StateLimit);
    assert_eq!(error.code(), "RGX-IR-E005");
}

#[test]
fn docs_replay_and_no_claim_boundaries_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX IR SCHEMA CONTRACT -->",
        "ASUP-REGEX-THOMPSON-IR-V1",
        "There is no\n`UNKNOWN` representation row.",
        "diagnostic-only-no-deserialization-contract",
        "No local Cargo fallback is approved.",
        "<!-- END REGEX IR SCHEMA CONTRACT -->",
    ] {
        assert!(docs.contains(marker), "missing doc marker: {marker}");
    }

    let proof = Value::Object(object(&value, "proof").clone());
    for key in ["unit_command", "contract_command", "clippy_command"] {
        let command = text(&proof, key);
        assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec --"));
        assert!(command.contains("CARGO_INCREMENTAL=0"));
    }
    assert!(boolean(&proof, "no_local_fallback"));

    let no_claims = array(&value, "no_claims")
        .iter()
        .map(|row| row.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join("\n");
    for marker in [
        "no AST lowering implementation",
        "no matcher or VM execution",
        "no persisted or deserializable IR format",
        "no public API or production wiring",
        "no regex or regex-syntax removal authorization",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }
}
