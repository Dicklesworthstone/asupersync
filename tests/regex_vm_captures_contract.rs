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

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use regex::Regex as IncumbentRegex;
use regex_boundaries::FoldBoundaryLimits;
use regex_ir::{CompileLimits, Program};
use regex_lowering::lower;
use regex_semantics::SemanticLimits;
use regex_syntax::{LexerLimits, ParserLimits};
use regex_vm::{
    ACCOUNTED_CAPTURE_HISTORY_ALLOCATION_FLOOR_BYTES, ACCOUNTED_CAPTURE_HISTORY_NODE_BYTES,
    ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES, ACCOUNTED_CAPTURE_THREAD_BYTES,
    ACCOUNTED_CAPTURE_TOUCHED_KEY_BYTES, CAPTURE_OFFSET_BUCKET_COUNT, CAPTURE_SEEN_KEYS_PER_STATE,
    CAPTURE_VM_ID, CAPTURE_VM_SCHEMA_VERSION, CaptureSpan, CaptureVmLimits,
    DEFAULT_MAX_CAPTURE_HISTORY_NODES, VmErrorKind, VmLimits, VmMatch, execute_anchored,
    execute_captures_full, execute_search,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_vm_captures_contract_v1.json";
const DOC_PATH: &str = "docs/regex_vm_captures_contract.md";
const PREDECESSOR_PATH: &str = "artifacts/regex_vm_core_contract_v1.json";
const TERMINAL_PATH: &str = "artifacts/regex_compiler_terminal_receipt_v1.json";
const LOWERING_PATH: &str = "artifacts/regex_priority_capture_lowering_contract_v1.json";
const VM_SOURCE_PATH: &str = "src/observability/regex_vm.rs";
const TERMINAL_SHA256: &str = "ef2714f4e4d4503bb80e622f17ee8c52476ebfab2ef31982702458e98bd11641";
const LOWERING_SHA256: &str = "a9af4009265150f76e9e1296bb5b5dc4dd27f11d7a48d4576dec3b4328a47b60";
const FROZEN_R3_4_2_VM_SHA256: &str =
    "5b27779e8384d5746b471064820f87410b3ccc5dea06ac637890eefc460ef0ee";

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedMatch {
    span: CaptureSpan,
    captures: Vec<Option<CaptureSpan>>,
}

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

fn normalize_vm(matched: VmMatch) -> NormalizedMatch {
    NormalizedMatch {
        span: matched.span,
        captures: matched.captures,
    }
}

fn vm_search(pattern: &str, haystack: &str) -> Option<NormalizedMatch> {
    execute_search(
        &lower_default(pattern),
        haystack,
        CompileLimits::default(),
        CaptureVmLimits::default(),
    )
    .unwrap_or_else(|error| panic!("VM {pattern:?} on {haystack:?}: {error}"))
    .matched
    .map(normalize_vm)
}

fn incumbent_search(pattern: &str, haystack: &str) -> Option<NormalizedMatch> {
    let regex = IncumbentRegex::new(pattern)
        .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"));
    let captures = regex.captures(haystack)?;
    let whole = captures.get(0).expect("capture zero is present");
    let groups = (1..captures.len())
        .map(|index| {
            captures.get(index).map(|capture| CaptureSpan {
                start: capture.start(),
                end: capture.end(),
            })
        })
        .collect();
    Some(NormalizedMatch {
        span: CaptureSpan {
            start: whole.start(),
            end: whole.end(),
        },
        captures: groups,
    })
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

#[test]
fn identity_sources_authority_and_decision_are_fail_closed() {
    let value = contract();
    assert_eq!(number(&value, "schema_version"), 1);
    assert_eq!(text(&value, "artifact_id"), "regex-vm-captures-contract-v1");
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.4.2");
    assert_eq!(text(&value, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(text(&value, "capture_vm_id"), CAPTURE_VM_ID);
    assert_eq!(
        number(&value, "capture_vm_schema_version"),
        u64::from(CAPTURE_VM_SCHEMA_VERSION)
    );
    assert_eq!(sha256(TERMINAL_PATH), TERMINAL_SHA256);
    assert_eq!(sha256(LOWERING_PATH), LOWERING_SHA256);
    assert!(fs::metadata(PREDECESSOR_PATH).is_ok());

    for source in array(&value, "sources") {
        let path = text(source, "path");
        if path == VM_SOURCE_PATH {
            assert_eq!(text(source, "sha256"), FROZEN_R3_4_2_VM_SHA256);
            assert_eq!(number(source, "bytes"), 77_571);
            assert_eq!(text(source, "pin_scope"), "historical_r3_4_2_source");
            continue;
        }
        assert_eq!(sha256(path), text(source, "sha256"), "source drift: {path}");
        let bytes = fs::metadata(path)
            .unwrap_or_else(|error| panic!("metadata {path}: {error}"))
            .len();
        assert_eq!(bytes, number(source, "bytes"), "source size drift: {path}");
    }

    let handoff = Value::Object(object(&value, "successor_handoff").clone());
    assert_eq!(
        text(&handoff, "live_source_authority"),
        "artifacts/regex_vm_iteration_contract_v1.json"
    );
    assert_eq!(
        text(&handoff, "successor_bead_id"),
        "asupersync-5z2scg.8.3.4.3"
    );
    assert!(boolean(&handoff, "historical_vm_source_pin_retained"));
    assert!(!boolean(&handoff, "live_vm_source_pin"));
    assert!(boolean(
        &handoff,
        "capture_behavior_replayed_against_successor_source"
    ));

    let decision = Value::Object(object(&value, "decision").clone());
    for key in [
        "r3_4_2_priority_capture_complete",
        "validated_ir_required",
        "one_shot_search_authorized",
        "anchored_prefix_authorized",
        "anchored_full_capture_authorized",
        "leftmost_first",
        "preferred_before_fallback",
        "persistent_capture_history",
        "strictly_safe",
        "deterministic",
        "panic_free_under_contract_limits",
    ] {
        assert!(boolean(&decision, key), "{key} must be true");
    }
    for key in [
        "leftmost_longest",
        "iteration_authorized",
        "replacement_authorized",
        "cancellation_authorized",
        "production_wiring_authorized",
        "dependency_removal_authorized",
    ] {
        assert!(!boolean(&decision, key), "{key} must remain false");
    }
}

#[test]
fn priority_capture_limits_and_errors_match_the_implementation() {
    let value = contract();
    let limits = Value::Object(object(&value, "limits").clone());
    assert_eq!(
        number(&limits, "max_capture_history_nodes"),
        DEFAULT_MAX_CAPTURE_HISTORY_NODES as u64
    );
    assert_eq!(
        number(&limits, "seen_keys_per_state"),
        CAPTURE_SEEN_KEYS_PER_STATE as u64
    );
    assert_eq!(
        number(&limits, "offset_bucket_count"),
        CAPTURE_OFFSET_BUCKET_COUNT as u64
    );
    assert_eq!(
        number(&limits, "accounted_capture_thread_bytes"),
        ACCOUNTED_CAPTURE_THREAD_BYTES
    );
    assert_eq!(
        number(&limits, "accounted_capture_touched_key_bytes"),
        ACCOUNTED_CAPTURE_TOUCHED_KEY_BYTES
    );
    assert_eq!(
        number(&limits, "accounted_capture_history_node_bytes"),
        ACCOUNTED_CAPTURE_HISTORY_NODE_BYTES
    );
    assert_eq!(
        number(&limits, "accounted_capture_history_allocation_floor_bytes"),
        ACCOUNTED_CAPTURE_HISTORY_ALLOCATION_FLOOR_BYTES
    );
    assert_eq!(
        number(&limits, "accounted_capture_result_slot_bytes"),
        ACCOUNTED_CAPTURE_RESULT_SLOT_BYTES
    );

    let expected_errors = [
        ("RGX-VM-E010", VmErrorKind::CaptureHistoryLimit),
        ("RGX-VM-E011", VmErrorKind::InvalidCaptureHistory),
        ("RGX-VM-E012", VmErrorKind::InvalidCaptureBoundary),
    ];
    assert_eq!(array(&value, "capture_error_rows").len(), 3);
    for (row, (code, kind)) in array(&value, "capture_error_rows")
        .iter()
        .zip(expected_errors)
    {
        assert_eq!(text(row, "code"), code);
        assert_eq!(kind.code(), code);
    }
}

#[test]
fn exact_goldens_match_independent_spans_and_the_incumbent() {
    let value = contract();
    let fixtures = array(&value, "fixtures");
    assert_eq!(fixtures.len(), 20);
    for row in fixtures {
        let case_id = text(row, "case_id");
        let pattern = text(row, "pattern");
        let haystack = text(row, "haystack");
        let vm = vm_search(pattern, haystack);
        let incumbent = incumbent_search(pattern, haystack);
        assert_eq!(vm, incumbent, "incumbent mismatch for {case_id}");

        if boolean(row, "matched") {
            let matched = vm.unwrap_or_else(|| panic!("{case_id} must match"));
            let expected_start = number(row, "start") as usize;
            let expected_end = number(row, "end") as usize;
            assert_eq!(
                matched.span,
                CaptureSpan {
                    start: expected_start,
                    end: expected_end,
                },
                "whole span for {case_id}"
            );
        } else {
            assert!(vm.is_none(), "{case_id} must not match");
        }
    }
}

#[test]
fn ambiguous_exhaustive_languages_match_regex_1_13_1() {
    let patterns = [
        "(a|ab)",
        "(ab|a)",
        "(a+)",
        "(a+?)",
        "(a*)",
        "(a*?)",
        "(a)?b",
        "(a??)b",
        "(a{1,3})",
        "(a{1,3}?)",
        "((a)|(b))",
        "(a)+",
        "((a+?)(a*))",
        "(?i:(a+))",
        "(é+)",
    ];
    let haystacks = all_haystacks(&['a', 'b', 'A', 'é'], 4);
    assert_eq!(haystacks.len(), 341);
    let mut comparisons = 0_usize;
    for pattern in patterns {
        for haystack in &haystacks {
            assert_eq!(
                vm_search(pattern, haystack),
                incumbent_search(pattern, haystack),
                "pattern={pattern:?} haystack={haystack:?}"
            );
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 5_115);
    assert_eq!(
        number(
            &Value::Object(object(&contract(), "evidence").clone()),
            "bounded_incumbent_comparisons"
        ),
        comparisons as u64
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn generated_priority_and_capture_results_match_incumbent(
        pattern_index in 0_usize..15,
        scalars in proptest::collection::vec(
            prop_oneof![Just('a'), Just('b'), Just('A'), Just('é')],
            0..=8,
        ),
    ) {
        let patterns = [
            "(a|ab)", "(ab|a)", "(a+)", "(a+?)", "(a*)", "(a*?)",
            "(a)?b", "(a??)b", "(a{1,3})", "(a{1,3}?)", "((a)|(b))",
            "(a)+", "((a+?)(a*))", "(?i:(a+))", "(é+)",
        ];
        let pattern = patterns[pattern_index];
        let haystack = scalars.into_iter().collect::<String>();
        prop_assert_eq!(
            vm_search(pattern, &haystack),
            incumbent_search(pattern, &haystack)
        );
    }
}

#[test]
fn anchored_prefix_and_full_modes_preserve_priority_without_conflation() {
    let program = lower_default("(a|ab)");
    let prefix = execute_anchored(
        &program,
        "ab",
        CompileLimits::default(),
        CaptureVmLimits::default(),
    )
    .expect("anchored prefix")
    .matched
    .expect("prefix match");
    assert_eq!(prefix.span, CaptureSpan { start: 0, end: 1 });
    assert_eq!(
        prefix.captures,
        vec![Some(CaptureSpan { start: 0, end: 1 })]
    );

    let full = execute_captures_full(
        &program,
        "ab",
        CompileLimits::default(),
        CaptureVmLimits::default(),
    )
    .expect("anchored full")
    .matched
    .expect("full fallback");
    assert_eq!(full.span, CaptureSpan { start: 0, end: 2 });
    assert_eq!(full.captures, vec![Some(CaptureSpan { start: 0, end: 2 })]);
}

#[test]
fn work_memory_history_trace_and_unicode_boundaries_are_bounded() {
    let program = lower_default("(é+?)");
    let haystack = format!("{}éé", "x".repeat(20_000));
    let first = execute_search(
        &program,
        &haystack,
        CompileLimits::default(),
        CaptureVmLimits::default(),
    )
    .expect("long leftmost search");
    let second = execute_search(
        &program,
        &haystack,
        CompileLimits::default(),
        CaptureVmLimits::default(),
    )
    .expect("deterministic replay");
    assert_eq!(first.matched, second.matched);
    assert_eq!(first.resources, second.resources);
    assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
    assert_eq!(
        first.matched.expect("Unicode match").span,
        CaptureSpan {
            start: 20_000,
            end: 20_002,
        }
    );
    assert!(
        first.resources.core.state_visits
            <= program.states.len() as u64
                * CAPTURE_SEEN_KEYS_PER_STATE as u64
                * (haystack.len() as u64 + 1)
    );
    assert!(first.resources.capture_history_nodes <= DEFAULT_MAX_CAPTURE_HISTORY_NODES);
    assert!(first.resources.core.accounted_memory_bytes <= VmLimits::default().max_memory_bytes);
    assert!(first.resources.core.work_units <= VmLimits::default().max_work_units);
    assert!(first.trace_truncated);
    assert_eq!(first.trace.len(), VmLimits::default().max_trace_events);
}

#[test]
fn every_capture_ceiling_and_error_display_fail_closed() {
    let private = "capture-secret-canary";
    let program = lower_default("(a)+");
    let invalid = execute_search(
        &program,
        "a",
        CompileLimits::default(),
        CaptureVmLimits {
            max_capture_history_nodes: 0,
            ..CaptureVmLimits::default()
        },
    )
    .expect_err("invalid capture limits");
    assert_eq!(invalid.kind, VmErrorKind::InvalidLimits);

    let history = execute_search(
        &program,
        private,
        CompileLimits::default(),
        CaptureVmLimits {
            max_capture_history_nodes: 1,
            ..CaptureVmLimits::default()
        },
    )
    .expect_err("capture history limit");
    assert_eq!(history.kind, VmErrorKind::CaptureHistoryLimit);
    let rendered = history.to_string();
    assert!(rendered.starts_with("[RGX-VM-E010]"));
    assert!(!rendered.contains(private));

    let work = execute_search(
        &program,
        "a",
        CompileLimits::default(),
        CaptureVmLimits {
            vm: VmLimits {
                max_work_units: 1,
                ..VmLimits::default()
            },
            ..CaptureVmLimits::default()
        },
    )
    .expect_err("capture work limit");
    assert_eq!(work.kind, VmErrorKind::WorkLimit);
}

#[test]
fn bounded_adversarial_execution_is_panic_free_and_deterministic() {
    let patterns = [
        "(a|aa)*b",
        "(a|ab)",
        "(ab|a)",
        "((a+?)(a*))",
        "((a)|(b))*",
        "(é+?)",
    ];
    for (case, pattern) in patterns.into_iter().enumerate() {
        let program = lower_default(pattern);
        for haystack in all_haystacks(&['a', 'b', 'é'], 5) {
            let caught = catch_unwind(AssertUnwindSafe(|| {
                execute_search(
                    &program,
                    &haystack,
                    CompileLimits::default(),
                    CaptureVmLimits {
                        vm: VmLimits {
                            max_input_bytes: 128,
                            max_threads_per_offset: 1_024,
                            max_memory_bytes: 2 * 1_024 * 1_024,
                            max_work_units: 256 * 1_024,
                            max_trace_events: 32,
                        },
                        max_capture_history_nodes: 8_192,
                    },
                )
            }));
            assert!(caught.is_ok(), "panic case={case} haystack={haystack:?}");
            let first = caught
                .expect("panic checked")
                .unwrap_or_else(|error| panic!("case={case} haystack={haystack:?}: {error}"));
            assert_eq!(
                first.matched.map(normalize_vm),
                incumbent_search(pattern, &haystack),
                "case={case} haystack={haystack:?}"
            );
        }
    }
}

#[test]
fn docs_replay_commands_and_no_claims_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX VM CAPTURES CONTRACT -->",
        "ASUP-REGEX-PRIORITY-CAPTURE-VM-V1",
        "regex@1.13.1",
        "leftmost-first, not leftmost-longest",
        "Persistent capture history",
        "No local Cargo fallback is approved.",
        "no iteration, replacement, or zero-width progress API",
        "no production privacy wiring or dependency removal",
        "<!-- END REGEX VM CAPTURES CONTRACT -->",
    ] {
        assert!(docs.contains(marker), "missing doc marker: {marker}");
    }

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
        "no iteration, replacement, or zero-width progress API",
        "no cancellation integration",
        "no production privacy wiring or dependency removal",
        "no non-folded byte-mode escape lowering claim",
        "no performance improvement or no-regression claim",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }
}
