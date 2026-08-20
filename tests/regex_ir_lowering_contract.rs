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

use std::collections::BTreeSet;
use std::fs;

use proptest::prelude::*;
use regex::Regex as IncumbentRegex;
use regex_boundaries::{BoundaryKind, FoldBoundaryLimits};
use regex_ir::{CompileErrorKind, CompileLimits, Instruction, Program, StateId};
use regex_lowering::{LOWERING_ID, LOWERING_SCHEMA_VERSION, LowerErrorKind, lower};
use regex_semantics::{CanonicalRanges, SemanticLimits};
use regex_syntax::{LexerLimits, ParserLimits};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_ir_lowering_contract_v1.json";
const DOC_PATH: &str = "docs/regex_ir_lowering_contract.md";
const SOURCE_PATH: &str = "src/observability/regex_lowering.rs";
const IR_SOURCE_PATH: &str = "src/observability/regex_ir.rs";
const TERMINAL_PATH: &str = "artifacts/regex_semantic_terminal_receipt_v1.json";
const FROZEN_SOURCE_SHA256: &str =
    "fc8c41c2a7da18e0881c1e51f5c620953e449c4f2eccb095b78bd37eba73e1d0";
const FROZEN_IR_SOURCE_SHA256: &str =
    "de4906beb838fda2c57bccfdb16316e8de661e564940a47e7b9b87f065311cb3";
const FROZEN_TERMINAL_SHA256: &str =
    "42d00d7c92b2b4a9974c252481432142eae2927b9442ffe08265769e00f7c8a2";

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

fn count_ops(program: &Program) -> (usize, usize) {
    let splits = program
        .states
        .iter()
        .filter(|state| matches!(state.instruction, Instruction::Split { .. }))
        .count();
    let assertions = program
        .states
        .iter()
        .filter(|state| matches!(state.instruction, Instruction::Assert { .. }))
        .count();
    (splits, assertions)
}

fn fingerprint(id: &str, program: &Program, splits: usize, assertions: usize) -> String {
    let summary = format!(
        "{id}|states={}|transitions={}|classes={}|splits={splits}|assertions={assertions}",
        program.resources.states, program.resources.transitions, program.resources.classes
    );
    hex::encode(Sha256::digest(summary.as_bytes()))
}

fn class_matches(ranges: &CanonicalRanges, haystack: &str, offset: usize) -> Option<usize> {
    match ranges {
        CanonicalRanges::Unicode(_) => haystack[offset..].chars().next().and_then(|scalar| {
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

fn model_accepts(program: &Program, haystack: &str) -> bool {
    let mut pending = vec![(program.entry, 0_usize)];
    let mut seen = BTreeSet::new();
    while let Some((state_id, offset)) = pending.pop() {
        if !seen.insert((state_id.index(), offset)) {
            continue;
        }
        let Some(state) = program.states.get(state_id.index()) else {
            return false;
        };
        match state.instruction {
            Instruction::Accept => {
                if offset == haystack.len() {
                    return true;
                }
            }
            Instruction::Jump { target } => pending.push((target, offset)),
            Instruction::Split {
                preferred,
                fallback,
            } => {
                pending.push((fallback, offset));
                pending.push((preferred, offset));
            }
            Instruction::Consume { class, target } => {
                let Some(ranges) = program
                    .classes
                    .get(class.index())
                    .map(|class| &class.ranges)
                else {
                    return false;
                };
                if let Some(next) = class_matches(ranges, haystack, offset) {
                    pending.push((target, next));
                }
            }
            Instruction::Assert { kind, target } => {
                if kind.is_match(haystack, offset).unwrap_or(false) {
                    pending.push((target, offset));
                }
            }
            Instruction::Save { .. } => return false,
        }
    }
    false
}

#[test]
fn identity_authority_and_source_pins_are_fail_closed() {
    let value = contract();
    assert_eq!(number(&value, "schema_version"), 1);
    assert_eq!(text(&value, "artifact_id"), "regex-ir-lowering-contract-v1");
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.3.2");
    assert_eq!(text(&value, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(text(&value, "lowering_id"), LOWERING_ID);
    assert_eq!(number(&value, "lowering_schema_version"), 1);
    assert!(
        LOWERING_SCHEMA_VERSION >= 1,
        "the live implementation may advance only through an explicit successor handoff"
    );

    let decision = Value::Object(object(&value, "decision").clone());
    assert_eq!(
        text(&decision, "disposition"),
        "STAGED_CHECKED_STRUCTURAL_LOWERING"
    );
    assert!(boolean(&decision, "r3_3_2_lowering_complete"));
    assert!(boolean(&decision, "compiler_must_retain_pinned_semantics"));
    assert!(!boolean(
        &decision,
        "capture_or_repetition_lowering_complete"
    ));
    assert!(!boolean(&decision, "matcher_execution_authorized"));
    assert!(!boolean(&decision, "production_wiring_authorized"));
    assert!(!boolean(&decision, "cutover_eligible"));
    assert!(!boolean(&decision, "dependency_removal_authorized"));

    let authority = Value::Object(object(&value, "authority").clone());
    assert_eq!(text(&authority, "semantic_terminal_path"), TERMINAL_PATH);
    assert_eq!(
        text(&authority, "semantic_terminal_sha256"),
        FROZEN_TERMINAL_SHA256
    );
    assert_eq!(
        text(&authority, "ir_schema_source_sha256"),
        FROZEN_IR_SOURCE_SHA256
    );
    assert_eq!(sha256(TERMINAL_PATH), FROZEN_TERMINAL_SHA256);
    assert_eq!(sha256(IR_SOURCE_PATH), FROZEN_IR_SOURCE_SHA256);

    for source in array(&value, "sources") {
        if text(source, "path") == SOURCE_PATH {
            assert_eq!(text(source, "sha256"), FROZEN_SOURCE_SHA256);
        } else {
            assert_eq!(sha256(text(source, "path")), text(source, "sha256"));
        }
        assert!(number(source, "bytes") > 0);
    }

    let handoff = Value::Object(object(&value, "successor_handoff").clone());
    assert_eq!(
        text(&handoff, "successor_bead_id"),
        "asupersync-5z2scg.8.3.3.3"
    );
    assert_eq!(
        text(&handoff, "successor_artifact_path"),
        "artifacts/regex_priority_capture_lowering_contract_v1.json"
    );
    assert_eq!(
        text(&handoff, "live_source_policy"),
        "HISTORICAL_COMPLETION_PIN_SUCCESSOR_OWNS_LIVE_SOURCE"
    );
}

#[test]
fn supported_and_deferred_ast_rows_are_exhaustive_for_r3_3_2() {
    let value = contract();
    let supported = array(&value, "supported_ast_rows")
        .iter()
        .map(|row| text(row, "ast"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        supported,
        BTreeSet::from([
            "Alternation",
            "Assertion",
            "Class",
            "Concat",
            "Dot",
            "Empty",
            "Escape",
            "Flags",
            "LineEnd",
            "LineStart",
            "Literal",
            "NonCapturing",
        ])
    );
    let deferred = array(&value, "deferred_ast_rows")
        .iter()
        .map(|row| text(row, "ast"))
        .collect::<BTreeSet<_>>();
    assert_eq!(deferred, BTreeSet::from(["Capture", "Repetition"]));
    assert!(
        array(&value, "supported_ast_rows")
            .iter()
            .chain(array(&value, "deferred_ast_rows"))
            .all(|row| !row.to_string().contains("UNKNOWN"))
    );
}

#[test]
fn semantic_fingerprints_replay_exact_resource_and_instruction_shapes() {
    let value = contract();
    for row in array(&value, "semantic_fingerprints") {
        let id = text(row, "id");
        let pattern = text(row, "pattern");
        let program = lower_default(pattern)
            .unwrap_or_else(|error| panic!("lower fixture {id} ({pattern:?}): {error}"));
        let (splits, assertions) = count_ops(&program);
        assert_eq!(program.resources.states as u64, number(row, "states"));
        assert_eq!(
            program.resources.transitions as u64,
            number(row, "transitions")
        );
        assert_eq!(program.resources.classes as u64, number(row, "classes"));
        assert_eq!(splits as u64, number(row, "splits"));
        assert_eq!(assertions as u64, number(row, "assertions"));
        assert_eq!(
            fingerprint(id, &program, splits, assertions),
            text(row, "fingerprint_sha256")
        );
    }
}

#[test]
fn ordered_priority_empty_branches_and_deep_nesting_have_golden_shapes() {
    let program = lower_default("a|a|").expect("priority fixture");
    let Instruction::Split {
        preferred,
        fallback,
    } = program.states[program.entry.index()].instruction
    else {
        panic!("entry must be ordered split");
    };
    assert_eq!(program.states[preferred.index()].source.byte_start, 0);
    let Instruction::Split {
        preferred,
        fallback: empty,
    } = program.states[fallback.index()].instruction
    else {
        panic!("fallback must retain source-order suffix");
    };
    assert_eq!(program.states[preferred.index()].source.byte_start, 2);
    assert!(matches!(
        program.states[empty.index()].instruction,
        Instruction::Jump { .. }
    ));

    let depth = 250;
    let pattern = format!("{}[ab]{}", "(?:".repeat(depth), ")".repeat(depth));
    let deep = lower(
        &pattern,
        LexerLimits::default(),
        ParserLimits {
            max_ast_nodes: 1_024,
            max_nesting: depth + 1,
        },
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits::default(),
    )
    .expect("iterative deep lowering");
    assert_eq!(deep.resources.states, 2);
    assert_eq!(deep.resources.classes, 1);
}

#[test]
fn malformed_historical_deferred_rows_and_budget_paths_are_typed() {
    let malformed = lower_default("(").expect_err("malformed syntax");
    assert!(matches!(malformed.kind, LowerErrorKind::Analysis(_)));
    assert_eq!(malformed.span.byte_start, 0);

    let value = contract();
    let deferred = array(&value, "deferred_ast_rows");
    assert!(deferred.iter().any(|row| {
        text(row, "ast") == "Capture" && text(row, "error_code") == "RGX-LOWER-E007"
    }));
    assert!(deferred.iter().any(|row| {
        text(row, "ast") == "Repetition" && text(row, "error_code") == "RGX-LOWER-E008"
    }));

    let budget = lower(
        "a|b",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits {
            max_states: 3,
            ..CompileLimits::default()
        },
    )
    .expect_err("two consumes, split, and accept exceed three states");
    assert_eq!(
        budget.kind,
        LowerErrorKind::Compile(CompileErrorKind::StateLimit)
    );
    assert_eq!(budget.actual, Some(4));
    assert_eq!(budget.limit, Some(3));
}

#[test]
fn bounded_model_language_matches_the_incumbent_for_every_small_haystack() {
    let patterns = [
        "",
        "a",
        "ab",
        "a|b",
        "a(?:b|)",
        "[ab]a",
        "(?i:a)b",
        r"\A(?:a|b)\z",
    ];
    let alphabet = ["", "a", "b", "aa", "ab", "ba", "bb", "aaa", "aB"];
    for pattern in patterns {
        let program = lower_default(pattern)
            .unwrap_or_else(|error| panic!("lower model fixture {pattern:?}: {error}"));
        let incumbent = IncumbentRegex::new(&format!(r"\A(?:{pattern})\z"))
            .unwrap_or_else(|error| panic!("incumbent fixture {pattern:?}: {error}"));
        for haystack in alphabet {
            assert_eq!(
                model_accepts(&program, haystack),
                incumbent.is_match(haystack),
                "pattern={pattern:?} haystack={haystack:?}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn bounded_generated_haystacks_match_the_incumbent(
        pattern_index in 0_usize..7,
        scalars in proptest::collection::vec(prop_oneof![Just('a'), Just('b'), Just('A')], 0..=5),
    ) {
        let patterns = ["", "a", "ab", "a|b", "a(?:b|)", "[ab]a", "(?i:a)b"];
        let pattern = patterns[pattern_index];
        let haystack = scalars.into_iter().collect::<String>();
        let program = lower_default(pattern).expect("generated fixture lowers");
        let incumbent = IncumbentRegex::new(&format!(r"\A(?:{pattern})\z"))
            .expect("generated fixture is valid incumbent syntax");
        prop_assert_eq!(
            model_accepts(&program, &haystack),
            incumbent.is_match(&haystack),
            "pattern={:?} haystack={:?}",
            pattern,
            haystack
        );
    }
}

#[test]
fn docs_replay_commands_and_no_claim_boundaries_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX IR LOWERING CONTRACT -->",
        "ASUP-REGEX-THOMPSON-LOWERING-V1",
        "RGX-LOWER-E007",
        "R3.3.3",
        "No local Cargo fallback is approved.",
        "<!-- END REGEX IR LOWERING CONTRACT -->",
    ] {
        assert!(docs.contains(marker), "missing doc marker: {marker}");
    }

    let proof = Value::Object(object(&value, "proof").clone());
    for key in ["unit_command", "contract_command", "clippy_command"] {
        let command = text(&proof, key);
        assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec"));
        assert!(command.contains("CARGO_INCREMENTAL=0"));
        if key == "clippy_command" {
            for overlay_marker in [
                "--base HEAD",
                "--clean-overlay",
                "--overlay-path tests/regex_ir_lowering_contract.rs",
            ] {
                assert!(
                    command.contains(overlay_marker),
                    "clippy replay must retain {overlay_marker}"
                );
            }
        }
    }
    assert!(boolean(&proof, "no_local_fallback"));

    let no_claims = array(&value, "no_claims")
        .iter()
        .map(|row| row.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join("\n");
    for marker in [
        "no capture or repetition lowering",
        "no matcher or VM execution",
        "no persisted or deserializable IR format",
        "no public API or production wiring",
        "no regex or regex-syntax removal authorization",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }

    assert_eq!(
        BoundaryKind::InputStart.is_match("", 0),
        Ok(true),
        "contract test links the same boundary evaluator used by lowered asserts"
    );
    assert_eq!(StateId::new(3).index(), 3);
}
