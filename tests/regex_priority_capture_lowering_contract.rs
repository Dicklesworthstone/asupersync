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
use regex_boundaries::FoldBoundaryLimits;
use regex_ir::{CompileErrorKind, CompileLimits, Instruction, Program, StateId};
use regex_lowering::{LOWERING_ID, LOWERING_SCHEMA_VERSION, LowerErrorKind, lower};
use regex_semantics::{CanonicalRanges, SemanticLimits};
use regex_syntax::{LexerLimits, ParserLimits};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_priority_capture_lowering_contract_v1.json";
const DOC_PATH: &str = "docs/regex_priority_capture_lowering_contract.md";
const SOURCE_PATH: &str = "src/observability/regex_lowering.rs";
const IR_SOURCE_PATH: &str = "src/observability/regex_ir.rs";
const SEMANTIC_TERMINAL_PATH: &str = "artifacts/regex_semantic_terminal_receipt_v1.json";
const FROZEN_SOURCE_SHA256: &str =
    "ca5a1bf0113e7c7ce0a77d489501a823d9153229d064ca7a5584e931f3dce8f0";
const FROZEN_IR_SOURCE_SHA256: &str =
    "de4906beb838fda2c57bccfdb16316e8de661e564940a47e7b9b87f065311cb3";
const FROZEN_TERMINAL_SHA256: &str =
    "2bc7b84bc1ffb5d128820b9f0d3f09c66bdfa61ffda0e98add1f8e34438105c9";

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

fn small_haystacks(max_len: usize) -> Vec<String> {
    let mut values = vec![String::new()];
    for _ in 0..max_len {
        let prior = values.clone();
        for prefix in prior {
            for suffix in ['a', 'b', 'A'] {
                values.push(format!("{prefix}{suffix}"));
            }
        }
    }
    values.sort();
    values.dedup();
    values
}

#[test]
fn identity_authority_and_source_pins_are_fail_closed() {
    let value = contract();
    assert_eq!(number(&value, "schema_version"), 1);
    assert_eq!(
        text(&value, "artifact_id"),
        "regex-priority-capture-lowering-contract-v1"
    );
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.3.3");
    assert_eq!(text(&value, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(text(&value, "lowering_id"), LOWERING_ID);
    assert_eq!(LOWERING_SCHEMA_VERSION, 2);
    assert_eq!(sha256(SOURCE_PATH), FROZEN_SOURCE_SHA256);
    assert_eq!(sha256(IR_SOURCE_PATH), FROZEN_IR_SOURCE_SHA256);
    assert_eq!(sha256(SEMANTIC_TERMINAL_PATH), FROZEN_TERMINAL_SHA256);

    let decision = Value::Object(object(&value, "decision").clone());
    assert_eq!(
        text(&decision, "disposition"),
        "STAGED_PRIORITY_CAPTURE_LOWERING"
    );
    assert!(boolean(&decision, "r3_3_3_lowering_complete"));
    assert!(boolean(&decision, "capture_numbering_preserved"));
    assert!(boolean(&decision, "greediness_priority_preserved"));
    assert!(boolean(&decision, "nullable_unbounded_loops_fail_closed"));
    assert!(!boolean(&decision, "matcher_execution_authorized"));
    assert!(!boolean(&decision, "production_wiring_authorized"));
    assert!(!boolean(&decision, "dependency_removal_authorized"));

    for source in array(&value, "sources") {
        assert_eq!(sha256(text(source, "path")), text(source, "sha256"));
        assert!(number(source, "bytes") > 0);
    }
}

#[test]
fn quantifier_rows_cover_zero_one_many_bounded_and_unbounded_shapes() {
    let value = contract();
    let rows = array(&value, "quantifier_rows")
        .iter()
        .map(|row| text(row, "syntax"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        rows,
        BTreeSet::from(["*", "+", "?", "{m,n}", "{m,}", "{n}"])
    );

    for pattern in [
        "a?",
        "a*?",
        "a+",
        "a{0}",
        "a{1}",
        "a{3}",
        "a{0,3}",
        "a{2,4}",
        "a{2,}",
        "(?:a{1,2}){2,3}",
    ] {
        let program = lower_default(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        program
            .validate(CompileLimits::default())
            .unwrap_or_else(|error| panic!("{pattern} validation: {error}"));
    }
    let zero = lower_default("a{0}").expect("zero repetition");
    assert_eq!(zero.resources.classes, 0);
    assert_eq!(zero.resources.states, 2);
    let exact = lower_default("(?:ab){3}").expect("finite cloned body");
    assert_eq!(exact.repetition_expansion, 4);
    assert_eq!(exact.resources.classes, 2);
}

#[test]
fn greediness_and_capture_goldens_agree_with_the_incumbent() {
    for (pattern, haystack, expected) in [
        ("(a*)(a*)", "aa", vec![Some((0, 2)), Some((2, 2))]),
        ("(a*?)(a*)", "aa", vec![Some((0, 0)), Some((0, 2))]),
        ("(a+?)(a*)", "aa", vec![Some((0, 1)), Some((1, 2))]),
        ("(a{1,2}?)(a?)", "aa", vec![Some((0, 1)), Some((1, 2))]),
        ("(?i:(a+))", "Aa", vec![Some((0, 2))]),
    ] {
        let program = lower_default(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        assert_eq!(
            prioritized_match(&program, haystack),
            Some(expected.clone())
        );
        assert_eq!(incumbent_match(pattern, haystack), Some(expected));
    }

    let captures = lower_default("((a))(b)").expect("nested capture numbering");
    assert_eq!(captures.capture_slots, 6);
    let slots = captures
        .states
        .iter()
        .filter_map(|state| match state.instruction {
            Instruction::Save { slot, .. } => Some(slot.index()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(slots, BTreeSet::from([0, 1, 2, 3, 4, 5]));
}

#[test]
fn scoped_flags_and_swap_greed_feed_the_lowering_without_scope_loss() {
    let scoped = lower_default("(?i:a)(?-i:b)(?U:c+?)").expect("flag scopes");
    assert!(scoped.classes[0].ranges.contains_scalar('A'));
    assert!(scoped.classes[0].ranges.contains_scalar('a'));
    assert!(scoped.classes[1].ranges.contains_scalar('b'));
    assert!(!scoped.classes[1].ranges.contains_scalar('B'));

    let c_consume = scoped
        .states
        .iter()
        .enumerate()
        .find_map(|(index, state)| match state.instruction {
            Instruction::Consume { class, .. }
                if scoped.classes[class.index()].ranges.contains_scalar('c') =>
            {
                Some(StateId::new(index))
            }
            _ => None,
        })
        .expect("c consume");
    let split = scoped
        .states
        .iter()
        .find_map(|state| match state.instruction {
            Instruction::Split {
                preferred,
                fallback,
            } if preferred == c_consume || fallback == c_consume => Some((preferred, fallback)),
            _ => None,
        })
        .expect("c repetition split");
    assert_eq!(
        split.0, c_consume,
        "U swaps default greediness and the explicit lazy suffix swaps it back"
    );
}

#[test]
fn nullable_loops_capture_erasure_and_resource_limits_fail_predictably() {
    for pattern in ["(?:)*", "(?:a?)*", "(?:a{0,1})+", "(?:^){1,}"] {
        let error = lower_default(pattern).expect_err("nullable loop must fail closed");
        assert_eq!(
            error.kind,
            LowerErrorKind::NullableUnboundedRepetition,
            "{pattern}"
        );
        assert_eq!(error.code(), "RGX-LOWER-E009");
    }
    let erased = lower_default("(a){0}").expect_err("capture erasure");
    assert_eq!(erased.kind, LowerErrorKind::CaptureErasedByZeroRepetition);
    assert_eq!(erased.code(), "RGX-LOWER-E010");

    let repetition = lower(
        "(?:ab){4}",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits {
            max_repetition_expansion: 4,
            ..CompileLimits::default()
        },
    )
    .expect_err("six cloned states exceed four");
    assert_eq!(
        repetition.kind,
        LowerErrorKind::Compile(CompileErrorKind::RepetitionLimit)
    );
    assert_eq!(repetition.actual, Some(6));
    assert_eq!(repetition.limit, Some(4));

    let capture_slots = lower(
        "((a))",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits {
            max_capture_slots: 2,
            ..CompileLimits::default()
        },
    )
    .expect_err("capture slot limit");
    assert_eq!(
        capture_slots.kind,
        LowerErrorKind::Compile(CompileErrorKind::CaptureSlotLimit)
    );
    assert_eq!(capture_slots.actual, Some(4));
    assert_eq!(capture_slots.limit, Some(2));
}

#[test]
fn bounded_small_languages_and_captures_match_the_incumbent() {
    let patterns = [
        "a?",
        "a*",
        "a+?",
        "a{0}",
        "a{2}",
        "a{1,3}",
        "(?:ab){0,2}",
        "(a*)(b?)",
        "(a*?)(a*)",
        "(?i:a{1,2})b?",
        "(?:a|b)+",
        "(a{1,2}?)(a?)",
    ];
    for pattern in patterns {
        let program = lower_default(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        for haystack in small_haystacks(4) {
            assert_eq!(
                prioritized_match(&program, &haystack),
                incumbent_match(pattern, &haystack),
                "pattern={pattern:?} haystack={haystack:?}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn generated_small_language_agrees_with_incumbent(
        left in prop::sample::select(&["a", "b", "[ab]", "(?:a|b)", "(?i:a)"]),
        left_quantifier in prop::sample::select(&["", "?", "*", "+", "{0,2}", "{1,3}", "{2,}"]),
        right in prop::sample::select(&["a", "b", "[ab]", "(?:a|b)"]),
        right_quantifier in prop::sample::select(&["", "?", "*?", "+?", "{0,2}?", "{1,3}?"]),
        haystack in prop::collection::vec(prop::sample::select(&['a', 'b', 'A']), 0..=5),
    ) {
        let pattern = format!("{left}{left_quantifier}{right}{right_quantifier}");
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

#[test]
fn docs_commands_and_no_claim_boundaries_are_machine_checked() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in array(&value, "required_doc_markers") {
        let marker = marker.as_str().expect("doc marker text");
        assert!(docs.contains(marker), "missing doc marker {marker}");
    }
    let proof = Value::Object(object(&value, "proof").clone());
    for key in ["unit_command", "contract_command", "clippy_command"] {
        let command = text(&proof, key);
        assert!(command.contains("RCH_REQUIRE_REMOTE=1 rch exec"));
        assert!(command.contains("CARGO_INCREMENTAL=0"));
        assert!(command.contains("CARGO_PROFILE_TEST_DEBUG=0"));
        assert!(!command.contains("ALLOW_LOCAL"));
    }
    assert!(
        text(&proof, "clippy_command")
            .contains("--overlay-path tests/regex_priority_capture_lowering_contract.rs")
    );
    assert_eq!(
        text(&proof, "format_command"),
        "rustfmt --edition 2024 --check src/observability/regex_lowering.rs tests/regex_ir_lowering_contract.rs tests/regex_priority_capture_lowering_contract.rs"
    );
    let no_claims = array(&value, "no_claims")
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .expect("no-claim strings");
    for boundary in [
        "matcher or VM execution correctness",
        "production wiring or dependency removal",
        "broad workspace health",
        "performance improvement",
        "release readiness",
        "local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(&boundary), "missing no-claim {boundary}");
    }
}
