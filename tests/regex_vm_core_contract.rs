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
#[allow(dead_code)]
#[path = "../src/observability/regex_vm.rs"]
mod regex_vm;

// The frozen IR module's inline tests use the production crate path.
mod observability {
    pub use crate::regex_semantics;
}

use std::collections::BTreeSet;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use regex::Regex as IncumbentRegex;
use regex_boundaries::FoldBoundaryLimits;
use regex_ir::{ClassId, CompileLimits, Instruction, Program, StateId};
use regex_lowering::{LOWERING_ID, LOWERING_SCHEMA_VERSION, lower};
use regex_semantics::{CanonicalRanges, SemanticLimits};
use regex_syntax::{LexerLimits, ParserLimits};
use regex_vm::{
    ACCOUNTED_SEEN_BYTE, ACCOUNTED_THREAD_BYTES, ACCOUNTED_TRACE_EVENT_BYTES,
    ACCOUNTED_VM_BASE_BYTES, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_THREADS_PER_OFFSET,
    DEFAULT_MAX_TRACE_EVENTS, DEFAULT_MAX_VM_MEMORY_BYTES, DEFAULT_MAX_VM_WORK_UNITS,
    OFFSET_BUCKET_COUNT, VM_ID, VM_SCHEMA_VERSION, VmErrorKind, VmLimits, execute_full,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_vm_core_contract_v1.json";
const DOC_PATH: &str = "docs/regex_vm_core_contract.md";
const TERMINAL_PATH: &str = "artifacts/regex_compiler_terminal_receipt_v1.json";
const VM_SOURCE_PATH: &str = "src/observability/regex_vm.rs";
const MOD_SOURCE_PATH: &str = "src/observability/mod.rs";
const FROZEN_TERMINAL_SHA256: &str =
    "14e895e467f6265988b93b487c320ba1035067784b46ba54457d6df57609711e";
const FROZEN_VM_SOURCE_SHA256: &str =
    "8952e787fe20b6bd0b4896b90e00fe25ed93d44154279c4c4c4deab1565d0e30";
const FROZEN_MOD_SOURCE_SHA256: &str =
    "75927f5785fff839df41d3b46c9acb76cd07cda854b6b978d1ac79d1d5a9921b";
const EXECUTION_FUZZ_SEED: u64 = 0x51A7_E7E5_7EED_0001;
const MALFORMED_IR_SEED: u64 = 0x1BAD_1DEA_7EED_0002;

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

fn lower_default(pattern: &str) -> Program {
    lower(
        pattern,
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits::default(),
    )
    .unwrap_or_else(|error| panic!("lower {pattern:?}: {error}"))
}

fn vm_accepts(program: &Program, haystack: &str) -> bool {
    execute_full(
        program,
        haystack,
        CompileLimits::default(),
        VmLimits::default(),
    )
    .unwrap_or_else(|error| panic!("execute on {haystack:?}: {error}"))
    .is_full_match
}

fn class_next_offset(ranges: &CanonicalRanges, haystack: &str, offset: usize) -> Option<usize> {
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

fn reference_accepts(program: &Program, haystack: &str) -> bool {
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
            Instruction::Jump { target } | Instruction::Save { target, .. } => {
                pending.push((target, offset));
            }
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
                if let Some(next_offset) = class_next_offset(ranges, haystack, offset) {
                    pending.push((target, next_offset));
                }
            }
            Instruction::Assert { kind, target } => {
                if kind.is_match(haystack, offset).unwrap_or(false) {
                    pending.push((target, offset));
                }
            }
        }
    }
    false
}

fn all_haystacks(alphabet: &[char], maximum_scalars: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut frontier = vec![String::new()];
    for _ in 0..maximum_scalars {
        let mut next = Vec::with_capacity(frontier.len().saturating_mul(alphabet.len()));
        for prefix in &frontier {
            for scalar in alphabet {
                let mut candidate = prefix.clone();
                candidate.push(*scalar);
                next.push(candidate);
            }
        }
        all.extend(next.iter().cloned());
        frontier = next;
    }
    all
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn generated_haystack(state: &mut u64, maximum_scalars: usize) -> String {
    const ALPHABET: [char; 6] = ['a', 'b', 'A', 'é', '0', '\n'];
    let length = usize::try_from(next_random(state) % (maximum_scalars as u64 + 1))
        .expect("bounded length fits usize");
    (0..length)
        .map(|_| {
            let index = usize::try_from(next_random(state) % ALPHABET.len() as u64)
                .expect("bounded alphabet index fits usize");
            ALPHABET[index]
        })
        .collect()
}

#[test]
fn identity_authority_source_pins_and_decision_are_fail_closed() {
    let value = contract();
    assert_eq!(number(&value, "schema_version"), 1);
    assert_eq!(text(&value, "artifact_id"), "regex-vm-core-contract-v1");
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.4.1");
    assert_eq!(text(&value, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(text(&value, "vm_id"), VM_ID);
    assert_eq!(
        number(&value, "vm_schema_version"),
        u64::from(VM_SCHEMA_VERSION)
    );
    assert_eq!(LOWERING_ID, "ASUP-REGEX-THOMPSON-LOWERING-V1");
    assert_eq!(LOWERING_SCHEMA_VERSION, 2);

    let terminal = Value::Object(object(&value, "compiler_terminal").clone());
    assert_eq!(text(&terminal, "path"), TERMINAL_PATH);
    assert_eq!(text(&terminal, "sha256"), FROZEN_TERMINAL_SHA256);
    assert_eq!(sha256(TERMINAL_PATH), FROZEN_TERMINAL_SHA256);
    assert_eq!(text(&terminal, "disposition"), "KEEP_INCUMBENT_DEFER");
    assert!(boolean(&terminal, "vm_experimentation_authorized"));
    assert!(!boolean(&terminal, "production_cutover_eligible"));

    for source in array(&value, "sources") {
        let path = text(source, "path");
        if path == VM_SOURCE_PATH {
            assert_eq!(text(source, "sha256"), FROZEN_VM_SOURCE_SHA256);
            assert_eq!(number(source, "bytes"), 36_360);
            assert_eq!(text(source, "pin_scope"), "historical_r3_4_1_source");
            continue;
        }
        assert_eq!(sha256(path), text(source, "sha256"), "source drift: {path}");
        let bytes = fs::metadata(path)
            .unwrap_or_else(|error| panic!("metadata {path}: {error}"))
            .len();
        assert_eq!(bytes, number(source, "bytes"), "source size drift: {path}");
    }
    assert_eq!(sha256(MOD_SOURCE_PATH), FROZEN_MOD_SOURCE_SHA256);

    let handoff = Value::Object(object(&value, "successor_handoff").clone());
    assert_eq!(
        text(&handoff, "live_source_authority"),
        "artifacts/regex_vm_captures_contract_v1.json"
    );
    assert_eq!(
        text(&handoff, "successor_bead_id"),
        "asupersync-5z2scg.8.3.4.2"
    );
    assert!(boolean(&handoff, "historical_vm_source_pin_retained"));
    assert!(!boolean(&handoff, "live_vm_source_pin"));
    assert!(boolean(
        &handoff,
        "core_behavior_replayed_against_successor_source"
    ));

    let decision = Value::Object(object(&value, "decision").clone());
    assert_eq!(text(&decision, "disposition"), "STAGED_BOUNDED_VM_CORE");
    for key in [
        "r3_4_1_vm_core_complete",
        "validated_ir_required",
        "whole_haystack_recognition_only",
        "ordered_first_arrival_deduplication",
        "strictly_safe",
        "deterministic",
        "panic_free_under_contract_limits",
    ] {
        assert!(boolean(&decision, key), "{key} must be true");
    }
    for key in [
        "production_wiring_authorized",
        "leftmost_search_authorized",
        "capture_propagation_authorized",
        "iteration_or_cancellation_authorized",
        "dependency_removal_authorized",
    ] {
        assert!(!boolean(&decision, key), "{key} must remain false");
    }
}

#[test]
fn limits_error_registry_and_accounting_formula_match_the_implementation() {
    let value = contract();
    let limits = Value::Object(object(&value, "limits").clone());
    assert_eq!(
        number(&limits, "max_input_bytes"),
        DEFAULT_MAX_INPUT_BYTES as u64
    );
    assert_eq!(
        number(&limits, "max_threads_per_offset"),
        DEFAULT_MAX_THREADS_PER_OFFSET as u64
    );
    assert_eq!(
        number(&limits, "max_memory_bytes"),
        DEFAULT_MAX_VM_MEMORY_BYTES
    );
    assert_eq!(number(&limits, "max_work_units"), DEFAULT_MAX_VM_WORK_UNITS);
    assert_eq!(
        number(&limits, "max_trace_events"),
        DEFAULT_MAX_TRACE_EVENTS as u64
    );
    assert_eq!(
        number(&limits, "accounted_vm_base_bytes"),
        ACCOUNTED_VM_BASE_BYTES
    );
    assert_eq!(
        number(&limits, "accounted_thread_bytes"),
        ACCOUNTED_THREAD_BYTES
    );
    assert_eq!(number(&limits, "accounted_seen_byte"), ACCOUNTED_SEEN_BYTE);
    assert_eq!(
        number(&limits, "accounted_trace_event_bytes"),
        ACCOUNTED_TRACE_EVENT_BYTES
    );

    let expected_errors = [
        ("RGX-VM-E001", VmErrorKind::InvalidLimits),
        ("RGX-VM-E002", VmErrorKind::InputLimit),
        ("RGX-VM-E003", VmErrorKind::ThreadLimit),
        ("RGX-VM-E004", VmErrorKind::MemoryLimit),
        ("RGX-VM-E005", VmErrorKind::WorkLimit),
        ("RGX-VM-E006", VmErrorKind::ArithmeticOverflow),
        ("RGX-VM-E007", VmErrorKind::InvalidState),
        ("RGX-VM-E008", VmErrorKind::InvalidClass),
        ("RGX-VM-E009", VmErrorKind::BucketCollision),
    ];
    assert_eq!(array(&value, "error_rows").len(), expected_errors.len());
    for (row, (code, kind)) in array(&value, "error_rows").iter().zip(expected_errors) {
        assert_eq!(text(row, "code"), code);
        assert_eq!(kind.code(), code);
    }

    let program = lower_default("(?:a|b)*");
    let outcome = execute_full(
        &program,
        "abba",
        CompileLimits::default(),
        VmLimits::default(),
    )
    .expect("accounted execution");
    let states = program.states.len() as u64;
    let threads = program.states.len().min(DEFAULT_MAX_THREADS_PER_OFFSET) as u64;
    let expected_memory = ACCOUNTED_VM_BASE_BYTES
        + OFFSET_BUCKET_COUNT as u64
            * (threads * ACCOUNTED_THREAD_BYTES + states * ACCOUNTED_SEEN_BYTE)
        + DEFAULT_MAX_TRACE_EVENTS as u64 * ACCOUNTED_TRACE_EVENT_BYTES;
    assert_eq!(outcome.resources.accounted_memory_bytes, expected_memory);
    assert!(outcome.resources.work_units <= DEFAULT_MAX_VM_WORK_UNITS);
}

#[test]
fn exact_fixtures_match_the_reference_and_expected_results() {
    let value = contract();
    assert_eq!(array(&value, "fixtures").len(), 15);
    for row in array(&value, "fixtures") {
        let case_id = text(row, "case_id");
        let pattern = text(row, "pattern");
        let haystack = text(row, "haystack");
        let expected = boolean(row, "expected");
        let program = lower_default(pattern);
        assert_eq!(
            reference_accepts(&program, haystack),
            expected,
            "reference {case_id}"
        );
        assert_eq!(vm_accepts(&program, haystack), expected, "VM {case_id}");
    }
}

#[test]
fn bounded_languages_match_an_independent_model_and_the_incumbent() {
    let patterns = [
        "",
        "a",
        "ab",
        "a|b",
        "a*",
        "a+",
        "a?",
        "a{1,3}",
        "[ab]+",
        "[^b]*",
        ".",
        r"\d*",
        "(?i:a)b",
        r"\A(?:a|é)\z",
        "(a|b)+",
    ];
    let haystacks = all_haystacks(&['a', 'b', 'A', 'é'], 4);
    assert_eq!(haystacks.len(), 341);
    let mut comparisons = 0_usize;
    for pattern in patterns {
        let program = lower_default(pattern);
        let incumbent = IncumbentRegex::new(&format!(r"\A(?:{pattern})\z"))
            .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"));
        for haystack in &haystacks {
            let reference = reference_accepts(&program, haystack);
            assert_eq!(
                vm_accepts(&program, haystack),
                reference,
                "VM/reference pattern={pattern:?} haystack={haystack:?}"
            );
            assert_eq!(
                reference,
                incumbent.is_match(haystack),
                "reference/incumbent pattern={pattern:?} haystack={haystack:?}"
            );
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 5_115);
    let evidence = Value::Object(object(&contract(), "evidence").clone());
    assert_eq!(
        comparisons as u64,
        number(&evidence, "bounded_reference_comparisons")
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn generated_supported_inputs_match_reference_and_incumbent(
        pattern_index in 0_usize..14,
        scalars in proptest::collection::vec(
            prop_oneof![Just('a'), Just('b'), Just('A'), Just('é'), Just('0')],
            0..=7,
        ),
    ) {
        let patterns = [
            "", "a", "ab", "a|b", "a*", "a+", "a?", "a{1,3}", "[ab]+",
            "[^b]*", ".", r"\d*", "(?i:a)b", "(a|b)+",
        ];
        let pattern = patterns[pattern_index];
        let haystack = scalars.into_iter().collect::<String>();
        let program = lower_default(pattern);
        let incumbent = IncumbentRegex::new(&format!(r"\A(?:{pattern})\z"))
            .expect("generated pattern is valid incumbent syntax");
        let reference = reference_accepts(&program, &haystack);
        prop_assert_eq!(vm_accepts(&program, &haystack), reference);
        prop_assert_eq!(reference, incumbent.is_match(&haystack));
    }
}

#[test]
fn ordered_epsilon_cycle_exact_bytes_and_long_input_replay_are_bounded() {
    let exact = lower_default("(?i-u:é)");
    let exact_bytes = exact
        .classes
        .iter()
        .filter_map(|class| match &class.ranges {
            CanonicalRanges::Bytes(ranges) if ranges.len() == 1 => {
                let range = ranges.first()?;
                (range.start == range.end).then_some(range.start)
            }
            CanonicalRanges::Unicode(_) | CanonicalRanges::Bytes(_) => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(exact_bytes, "é".as_bytes());
    assert!(vm_accepts(&exact, "é"));

    let cycle = regex_ir::Program::checked(
        StateId::new(0),
        StateId::new(3),
        vec![
            regex_ir::State {
                instruction: Instruction::Split {
                    preferred: StateId::new(1),
                    fallback: StateId::new(2),
                },
                source: regex_syntax::SourceSpan {
                    byte_start: 0,
                    byte_end: 0,
                    scalar_start: 0,
                    scalar_end: 0,
                },
            },
            regex_ir::State {
                instruction: Instruction::Jump {
                    target: StateId::new(3),
                },
                source: regex_syntax::SourceSpan {
                    byte_start: 0,
                    byte_end: 0,
                    scalar_start: 0,
                    scalar_end: 0,
                },
            },
            regex_ir::State {
                instruction: Instruction::Split {
                    preferred: StateId::new(0),
                    fallback: StateId::new(3),
                },
                source: regex_syntax::SourceSpan {
                    byte_start: 0,
                    byte_end: 0,
                    scalar_start: 0,
                    scalar_end: 0,
                },
            },
            regex_ir::State {
                instruction: Instruction::Accept,
                source: regex_syntax::SourceSpan {
                    byte_start: 0,
                    byte_end: 0,
                    scalar_start: 0,
                    scalar_end: 0,
                },
            },
        ],
        vec![],
        0,
        0,
        CompileLimits::default(),
    )
    .expect("valid epsilon cycle");
    let cycle_outcome = execute_full(&cycle, "", CompileLimits::default(), VmLimits::default())
        .expect("cycle terminates");
    assert!(cycle_outcome.is_full_match);
    assert!(cycle_outcome.resources.deduplicated_threads >= 1);

    let program = lower_default("a*");
    let haystack = "a".repeat(100_000);
    let first = execute_full(
        &program,
        &haystack,
        CompileLimits::default(),
        VmLimits::default(),
    )
    .expect("long input");
    let second = execute_full(
        &program,
        &haystack,
        CompileLimits::default(),
        VmLimits::default(),
    )
    .expect("long input replay");
    assert!(first.is_full_match);
    assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
    assert_eq!(first.resources, second.resources);
    assert!(first.trace_truncated);
    assert_eq!(first.trace.len(), DEFAULT_MAX_TRACE_EVENTS);
    let visit_bound = program.states.len() as u64 * (haystack.len() as u64 + 1);
    assert!(first.resources.state_visits <= visit_bound);
}

#[test]
fn deterministic_execution_and_malformed_ir_fuzz_are_panic_free() {
    let patterns = [
        "",
        "a",
        "ab",
        "a|b",
        "a*",
        "a+",
        "a?",
        "a{1,3}",
        "[ab]+",
        ".",
        r"\d*",
        "(?i:a)b",
        r"\A(?:a|é)\z",
        "(a|b)+",
        "(?:é|(?i-u:é))",
    ];
    let mut state = EXECUTION_FUZZ_SEED;
    for case in 0..1_024 {
        let pattern_index = usize::try_from(next_random(&mut state) % patterns.len() as u64)
            .expect("bounded pattern index fits usize");
        let pattern = patterns[pattern_index];
        let haystack = generated_haystack(&mut state, 12);
        let program = lower_default(pattern);
        let caught = catch_unwind(AssertUnwindSafe(|| {
            execute_full(
                &program,
                &haystack,
                CompileLimits::default(),
                VmLimits {
                    max_input_bytes: 128,
                    max_threads_per_offset: 1_024,
                    max_memory_bytes: 512 * 1_024,
                    max_work_units: 128 * 1_024,
                    max_trace_events: 32,
                },
            )
        }));
        assert!(caught.is_ok(), "execution fuzz panic at case {case}");
        let outcome = caught
            .expect("panic checked")
            .unwrap_or_else(|error| panic!("execution fuzz case {case}: {error}"));
        assert_eq!(
            outcome.is_full_match,
            reference_accepts(&program, &haystack),
            "execution fuzz mismatch case {case}"
        );
    }

    let base = lower_default("a|b");
    let mut state = MALFORMED_IR_SEED;
    for case in 0..1_024 {
        let mut malformed = base.clone();
        match next_random(&mut state) % 10 {
            0 => malformed.schema_version = u16::MAX,
            1 => malformed.entry = StateId::new(usize::MAX),
            2 => malformed.accept = StateId::new(usize::MAX),
            3 => {
                malformed.states[0].instruction = Instruction::Jump {
                    target: StateId::new(usize::MAX),
                };
            }
            4 => malformed.resources.states = malformed.resources.states.saturating_add(1),
            5 => {
                let state = malformed
                    .states
                    .iter_mut()
                    .find(|state| matches!(state.instruction, Instruction::Consume { .. }))
                    .expect("base program has consume");
                state.instruction = Instruction::Consume {
                    class: ClassId::new(usize::MAX),
                    target: malformed.accept,
                };
            }
            6 => malformed.capture_slots = 1,
            7 => {
                malformed.states[0].source.byte_start = 2;
                malformed.states[0].source.byte_end = 1;
            }
            8 => {
                let accept_index = malformed.accept.index();
                malformed.states[accept_index].instruction = Instruction::Jump {
                    target: malformed.entry,
                };
            }
            9 => malformed.states[0].instruction = Instruction::Accept,
            _ => unreachable!("modulo ten"),
        }
        let caught = catch_unwind(AssertUnwindSafe(|| {
            execute_full(
                &malformed,
                "a",
                CompileLimits::default(),
                VmLimits::default(),
            )
        }));
        assert!(caught.is_ok(), "malformed IR panic at case {case}");
        let error = caught
            .expect("panic checked")
            .expect_err("malformed IR cannot produce a partial outcome");
        assert!(
            matches!(error.kind, VmErrorKind::Compile(_)),
            "malformed IR must fail in R3.3 validation at case {case}: {error}"
        );
    }
}

#[test]
fn docs_replay_commands_retained_cases_and_no_claims_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX VM CORE CONTRACT -->",
        "ASUP-REGEX-THREAD-SET-VM-V1",
        "STAGED_BOUNDED_VM_CORE",
        "regex@1.13.1",
        "2026-10-23T00:00:00Z",
        "RGX-VM-MIN-003",
        "No local Cargo fallback is approved.",
        "no leftmost search or capture propagation",
        "no production privacy wiring or dependency removal",
        "<!-- END REGEX VM CORE CONTRACT -->",
    ] {
        assert!(docs.contains(marker), "missing doc marker: {marker}");
    }

    let minimized = array(&value, "retained_minimized_cases");
    assert_eq!(minimized.len(), 4);
    assert!(minimized.iter().any(|row| {
        text(row, "case_id") == "RGX-VM-MIN-003"
            && text(row, "disposition") == "KEEP_INCUMBENT_DEFER"
    }));

    let proof = Value::Object(object(&value, "proof").clone());
    for key in ["unit_command", "contract_command", "clippy_command"] {
        let command = text(&proof, key);
        assert!(command.starts_with("RCH_REQUIRE_REMOTE=1 rch exec"));
        assert!(command.contains("--base HEAD"));
        assert!(command.contains("--clean-overlay"));
        assert!(command.contains("--overlay-path src/observability/regex_vm.rs"));
        assert!(command.contains("CARGO_INCREMENTAL=0"));
    }
    assert!(!boolean(&proof, "local_cargo_fallback"));

    let no_claims = array(&value, "no_claims")
        .iter()
        .map(|row| row.as_str().expect("no-claim text"))
        .collect::<Vec<_>>()
        .join("\n");
    for marker in [
        "no leftmost search or capture propagation",
        "no iteration API or cancellation integration",
        "no production privacy wiring or dependency removal",
        "no non-folded byte-mode escape lowering claim",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }
}
