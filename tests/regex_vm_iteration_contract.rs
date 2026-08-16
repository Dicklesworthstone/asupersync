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
use regex::{Captures as IncumbentCaptures, Regex as IncumbentRegex};
use regex_boundaries::FoldBoundaryLimits;
use regex_ir::{CompileLimits, Program};
use regex_lowering::lower;
use regex_semantics::SemanticLimits;
use regex_syntax::{LexerLimits, ParserLimits};
use regex_vm::{
    ACCOUNTED_ITERATION_MATCH_BYTES, ACCOUNTED_ITERATION_TRACE_EVENT_BYTES,
    ACCOUNTED_VM_BASE_BYTES, CaptureSpan, CaptureVmLimits, DEFAULT_MAX_ITERATED_MATCHES,
    DEFAULT_MAX_ITERATION_TRACE_EVENTS, ITERATION_VM_ID, ITERATION_VM_SCHEMA_VERSION,
    IterationPolicy, IterationVmLimits, VmErrorKind, VmIterationOutcome, VmLimits, VmMatch,
    execute_find_iter,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_vm_iteration_contract_v1.json";
const DOC_PATH: &str = "docs/regex_vm_iteration_contract.md";
const PREDECESSOR_PATH: &str = "artifacts/regex_vm_captures_contract_v1.json";
const TERMINAL_PATH: &str = "artifacts/regex_compiler_terminal_receipt_v1.json";
const VM_SOURCE_PATH: &str = "src/observability/regex_vm.rs";
const TERMINAL_SHA256: &str = "93eefa5d80dfbd798822ec24688e4b29f3e1fbae3345c41f1341a517ac0eee12";
const FROZEN_R3_4_3_VM_SHA256: &str =
    "d0d2b841cb3533bc0dbfdcbd6c237e594391015e649477b408ff047ea75ffe2c";

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

fn sha256_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
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

fn normalize_incumbent(captures: IncumbentCaptures<'_>) -> NormalizedMatch {
    let whole = captures.get(0).expect("capture zero is present");
    NormalizedMatch {
        span: CaptureSpan {
            start: whole.start(),
            end: whole.end(),
        },
        captures: (1..captures.len())
            .map(|index| {
                captures.get(index).map(|capture| CaptureSpan {
                    start: capture.start(),
                    end: capture.end(),
                })
            })
            .collect(),
    }
}

fn vm_iter(pattern: &str, haystack: &str, policy: IterationPolicy) -> Vec<NormalizedMatch> {
    execute_find_iter(
        &lower_default(pattern),
        haystack,
        CompileLimits::default(),
        policy,
        IterationVmLimits::default(),
    )
    .unwrap_or_else(|error| panic!("VM {pattern:?} on {haystack:?}: {error}"))
    .matches
    .into_iter()
    .map(normalize_vm)
    .collect()
}

fn incumbent_non_overlapping(pattern: &str, haystack: &str) -> Vec<NormalizedMatch> {
    IncumbentRegex::new(pattern)
        .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"))
        .captures_iter(haystack)
        .map(normalize_incumbent)
        .collect()
}

fn modeled_overlapping(pattern: &str, haystack: &str) -> Vec<NormalizedMatch> {
    let regex = IncumbentRegex::new(pattern)
        .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"));
    let mut matched = Vec::new();
    let mut search_start = Some(0_usize);
    while let Some(start) = search_start {
        let Some(captures) = regex.captures_at(haystack, start) else {
            break;
        };
        let normalized = normalize_incumbent(captures);
        let match_start = normalized.span.start;
        matched.push(normalized);
        search_start = haystack
            .get(match_start..)
            .and_then(|remaining| remaining.chars().next())
            .map(|scalar| match_start + scalar.len_utf8());
    }
    matched
}

fn expected_spans(row: &Value) -> Vec<CaptureSpan> {
    array(row, "spans")
        .iter()
        .map(|span| {
            let pair = span
                .as_array()
                .unwrap_or_else(|| panic!("span must be a pair: {span}"));
            assert_eq!(pair.len(), 2);
            CaptureSpan {
                start: pair[0].as_u64().expect("span start") as usize,
                end: pair[1].as_u64().expect("span end") as usize,
            }
        })
        .collect()
}

fn policy(row: &Value) -> IterationPolicy {
    match text(row, "policy") {
        "non_overlapping" => IterationPolicy::NonOverlapping,
        "overlapping" => IterationPolicy::Overlapping,
        other => panic!("unknown iteration policy {other}"),
    }
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

fn normalized_receipt(outcome: &VmIterationOutcome) -> Value {
    let matches = outcome
        .matches
        .iter()
        .map(|matched| {
            let captures = matched
                .captures
                .iter()
                .map(|capture| capture.map_or(Value::Null, |span| json!([span.start, span.end])))
                .collect::<Vec<_>>();
            json!({
                "span": [matched.span.start, matched.span.end],
                "captures": captures,
            })
        })
        .collect::<Vec<_>>();
    let trace = outcome
        .trace
        .iter()
        .map(|event| {
            json!({
                "sequence": event.sequence,
                "search_start": event.search_start,
                "matched": event.matched.map(|span| [span.start, span.end]),
                "next_search_start": event.next_search_start,
                "search_fingerprint": format!("{:016x}", event.search_fingerprint),
                "discarded_adjacent_empty": event.discarded_adjacent_empty,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "matches": matches,
        "resources": {
            "search_attempts": outcome.resources.search_attempts,
            "matches": outcome.resources.matches,
            "zero_width_advances": outcome.resources.zero_width_advances,
            "overlap_advances": outcome.resources.overlap_advances,
            "total_work_units": outcome.resources.total_work_units,
            "peak_accounted_memory_bytes": outcome.resources.peak_accounted_memory_bytes,
        },
        "execution_fingerprint": format!("{:016x}", outcome.execution_fingerprint),
        "trace": trace,
        "trace_truncated": outcome.trace_truncated,
    })
}

#[test]
fn identity_sources_authority_and_decision_are_fail_closed() {
    let value = contract();
    assert_eq!(number(&value, "schema_version"), 1);
    assert_eq!(
        text(&value, "artifact_id"),
        "regex-vm-iteration-contract-v1"
    );
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.4.3");
    assert_eq!(text(&value, "capability_id"), "CAP-REGEX-PRIVACY");
    assert_eq!(text(&value, "iteration_vm_id"), ITERATION_VM_ID);
    assert_eq!(
        number(&value, "iteration_vm_schema_version"),
        u64::from(ITERATION_VM_SCHEMA_VERSION)
    );
    assert_eq!(sha256(TERMINAL_PATH), TERMINAL_SHA256);
    assert!(fs::metadata(PREDECESSOR_PATH).is_ok());

    for source in array(&value, "sources") {
        let path = text(source, "path");
        if path == VM_SOURCE_PATH {
            assert_eq!(text(source, "sha256"), FROZEN_R3_4_3_VM_SHA256);
            assert_eq!(number(source, "bytes"), 101_389);
            assert_eq!(text(source, "pin_scope"), "historical_r3_4_3_source");
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
        "artifacts/regex_vm_terminal_receipt_v1.json"
    );
    assert_eq!(
        text(&handoff, "successor_bead_id"),
        "asupersync-5z2scg.8.3.4.4"
    );
    assert!(boolean(&handoff, "historical_vm_source_pin_retained"));
    assert!(!boolean(&handoff, "live_vm_source_pin"));
    assert!(boolean(
        &handoff,
        "iteration_behavior_replayed_against_successor_source"
    ));

    let decision = Value::Object(object(&value, "decision").clone());
    for key in [
        "r3_4_3_iteration_complete",
        "validated_ir_required",
        "single_match_authorized",
        "is_match_authorized",
        "capture_iteration_authorized",
        "non_overlapping_iteration_authorized",
        "overlapping_iteration_authorized",
        "replacement_span_production_authorized",
        "unicode_zero_width_progress",
        "strictly_safe",
        "deterministic",
        "panic_free_under_contract_limits",
    ] {
        assert!(boolean(&decision, key), "{key} must be true");
    }
    for key in [
        "replacement_template_expansion_authorized",
        "capture_reference_syntax_authorized",
        "cancellation_authorized",
        "production_wiring_authorized",
        "dependency_removal_authorized",
    ] {
        assert!(!boolean(&decision, key), "{key} must remain false");
    }
}

#[test]
fn iteration_limits_errors_and_accounting_match_the_implementation() {
    let value = contract();
    let limits = Value::Object(object(&value, "limits").clone());
    assert_eq!(
        number(&limits, "max_matches"),
        DEFAULT_MAX_ITERATED_MATCHES as u64
    );
    assert_eq!(
        number(&limits, "max_iteration_trace_events"),
        DEFAULT_MAX_ITERATION_TRACE_EVENTS as u64
    );
    assert_eq!(
        number(&limits, "accounted_iteration_match_bytes"),
        ACCOUNTED_ITERATION_MATCH_BYTES
    );
    assert_eq!(
        number(&limits, "accounted_iteration_trace_event_bytes"),
        ACCOUNTED_ITERATION_TRACE_EVENT_BYTES
    );
    assert_eq!(VmErrorKind::MatchLimit.code(), "RGX-VM-E013");
    assert_eq!(VmErrorKind::InvalidIterationBoundary.code(), "RGX-VM-E014");
    assert_eq!(array(&value, "iteration_error_rows").len(), 2);
}

#[test]
fn exact_goldens_match_independent_iteration_models() {
    let fixtures = array(&contract(), "fixtures").to_vec();
    assert_eq!(fixtures.len(), 20);
    for row in fixtures {
        let case_id = text(&row, "case_id");
        let pattern = text(&row, "pattern");
        let haystack = text(&row, "haystack");
        let policy = policy(&row);
        let vm = vm_iter(pattern, haystack, policy);
        let reference = match policy {
            IterationPolicy::NonOverlapping => incumbent_non_overlapping(pattern, haystack),
            IterationPolicy::Overlapping => modeled_overlapping(pattern, haystack),
        };
        assert_eq!(vm, reference, "reference mismatch for {case_id}");
        assert_eq!(
            vm.iter().map(|matched| matched.span).collect::<Vec<_>>(),
            expected_spans(&row),
            "frozen spans for {case_id}"
        );
    }
}

#[test]
fn bounded_non_overlapping_languages_match_regex_1_13_1() {
    let patterns = [
        "", "a", "a*", "a+?", "(a)?b", "(a|ab)", "(ab|a)", "(a)+", "(é*)", r"\b",
    ];
    let haystacks = all_haystacks(&['a', 'b', 'é'], 4);
    assert_eq!(haystacks.len(), 121);
    let mut comparisons = 0_usize;
    for pattern in patterns {
        for haystack in &haystacks {
            assert_eq!(
                vm_iter(pattern, haystack, IterationPolicy::NonOverlapping),
                incumbent_non_overlapping(pattern, haystack),
                "pattern={pattern:?} haystack={haystack:?}"
            );
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 1_210);
    assert_eq!(
        number(
            &Value::Object(object(&contract(), "evidence").clone()),
            "bounded_non_overlapping_incumbent_comparisons"
        ),
        comparisons as u64
    );
}

#[test]
fn bounded_overlap_languages_match_independent_progress_model() {
    let patterns = ["", "a", "aa", "a*", "(a|aa)", "(aa|a)"];
    let haystacks = all_haystacks(&['a', 'b', 'é'], 4);
    assert_eq!(haystacks.len(), 121);
    let mut comparisons = 0_usize;
    for pattern in patterns {
        for haystack in &haystacks {
            assert_eq!(
                vm_iter(pattern, haystack, IterationPolicy::Overlapping),
                modeled_overlapping(pattern, haystack),
                "pattern={pattern:?} haystack={haystack:?}"
            );
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 726);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn generated_non_overlapping_results_match_incumbent(
        pattern_index in 0_usize..10,
        scalars in proptest::collection::vec(
            prop_oneof![Just('a'), Just('b'), Just('A'), Just('é')],
            0..=10,
        ),
    ) {
        let patterns = [
            "", "a", "a*", "a+?", "(a)?b", "(a|ab)", "(ab|a)",
            "(a)+", "(?i:(a+))", r"\b",
        ];
        let pattern = patterns[pattern_index];
        let haystack = scalars.into_iter().collect::<String>();
        prop_assert_eq!(
            vm_iter(pattern, &haystack, IterationPolicy::NonOverlapping),
            incumbent_non_overlapping(pattern, &haystack)
        );
    }
}

#[test]
fn zero_width_unicode_progress_and_replacement_order_are_exact() {
    let outcome = execute_find_iter(
        &lower_default(""),
        "éa",
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
    )
    .expect("empty Unicode iteration");
    assert_eq!(
        outcome.replacement_spans().collect::<Vec<_>>(),
        vec![
            CaptureSpan { start: 0, end: 0 },
            CaptureSpan { start: 2, end: 2 },
            CaptureSpan { start: 3, end: 3 },
        ]
    );
    assert_eq!(outcome.resources.zero_width_advances, 2);
    assert_eq!(
        outcome
            .trace
            .iter()
            .map(|event| (event.search_start, event.next_search_start))
            .collect::<Vec<_>>(),
        vec![(0, Some(2)), (2, Some(3)), (3, None)]
    );

    let captured = vm_iter("(a)?b", "b ab", IterationPolicy::NonOverlapping);
    assert_eq!(captured[0].captures, vec![None]);
    assert_eq!(
        captured[1].captures,
        vec![Some(CaptureSpan { start: 2, end: 3 })]
    );
}

#[test]
fn privacy_patterns_emit_replayable_normalized_receipts_without_input_text() {
    let probes = [
        (
            "RGX-PRIV-CUSTOM-TOKEN",
            r"token-[A-F0-9]{8}",
            "contact token-DEADBEEF now",
        ),
        (
            "RGX-PRIV-CUSTOM-SECRET",
            r"secret-\d{4}",
            "value secret-2048 end",
        ),
        ("RGX-PRIV-SSN", r"\b\d{3}-\d{2}-\d{4}\b", "ssn 123-45-6789"),
        (
            "RGX-PRIV-CARD",
            r"\b(?:\d[ -]?){13,19}\b",
            "card 4111 1111 1111 1111",
        ),
    ];
    let value = contract();
    assert_eq!(array(&value, "privacy_probes").len(), probes.len());
    for ((probe_id, pattern, input), row) in probes.into_iter().zip(array(&value, "privacy_probes"))
    {
        assert_eq!(text(row, "probe_id"), probe_id);
        assert_eq!(text(row, "pattern"), pattern);
        assert_eq!(text(row, "input_sha256"), sha256_text(input));

        let program = lower_default(pattern);
        let first = execute_find_iter(
            &program,
            input,
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("{probe_id}: {error}"));
        let second = execute_find_iter(
            &program,
            input,
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
        )
        .unwrap_or_else(|error| panic!("replay {probe_id}: {error}"));
        assert_eq!(
            first
                .matches
                .iter()
                .cloned()
                .map(normalize_vm)
                .collect::<Vec<_>>(),
            incumbent_non_overlapping(pattern, input),
            "{probe_id} incumbent spans"
        );
        let first_receipt = normalized_receipt(&first);
        assert_eq!(first_receipt, normalized_receipt(&second));
        let serialized = serde_json::to_string(&first_receipt).expect("serialize receipt");
        assert!(!serialized.contains(input), "{probe_id} leaked full input");
        for fragment in input
            .split_whitespace()
            .filter(|fragment| fragment.len() >= 8)
        {
            assert!(
                !serialized.contains(fragment),
                "{probe_id} leaked input fragment"
            );
        }
        assert!(!first.matches.is_empty(), "{probe_id} must produce a span");
    }
}

#[test]
fn match_work_memory_trace_and_long_input_limits_are_bounded() {
    let empty = lower_default("");
    let private = "iteration-private-canary";
    let match_limit = execute_find_iter(
        &empty,
        private,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits {
            max_matches: 1,
            ..IterationVmLimits::default()
        },
    )
    .expect_err("second empty match exceeds limit");
    assert_eq!(match_limit.kind, VmErrorKind::MatchLimit);
    assert!(!match_limit.to_string().contains(private));

    let work = execute_find_iter(
        &lower_default("a"),
        "a",
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits {
            capture: CaptureVmLimits {
                vm: VmLimits {
                    max_work_units: 1,
                    ..VmLimits::default()
                },
                ..CaptureVmLimits::default()
            },
            ..IterationVmLimits::default()
        },
    )
    .expect_err("aggregate work ceiling");
    assert_eq!(work.kind, VmErrorKind::WorkLimit);

    let memory = execute_find_iter(
        &empty,
        "",
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits {
            capture: CaptureVmLimits {
                vm: VmLimits {
                    max_memory_bytes: ACCOUNTED_VM_BASE_BYTES
                        + DEFAULT_MAX_ITERATION_TRACE_EVENTS as u64
                            * ACCOUNTED_ITERATION_TRACE_EVENT_BYTES,
                    ..VmLimits::default()
                },
                ..CaptureVmLimits::default()
            },
            ..IterationVmLimits::default()
        },
    )
    .expect_err("retained base leaves no executor memory");
    assert_eq!(memory.kind, VmErrorKind::MemoryLimit);

    let trace = execute_find_iter(
        &empty,
        "ab",
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits {
            max_trace_events: 1,
            ..IterationVmLimits::default()
        },
    )
    .expect("truncated trace");
    assert_eq!(trace.trace.len(), 1);
    assert!(trace.trace_truncated);

    let haystack = "a".repeat(20_000);
    let program = lower_default("a+");
    let first = execute_find_iter(
        &program,
        &haystack,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
    )
    .expect("long iteration");
    let second = execute_find_iter(
        &program,
        &haystack,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
    )
    .expect("long replay");
    assert_eq!(first.matches, second.matches);
    assert_eq!(first.resources, second.resources);
    assert_eq!(first.execution_fingerprint, second.execution_fingerprint);
    assert_eq!(
        first.replacement_spans().collect::<Vec<_>>(),
        vec![CaptureSpan {
            start: 0,
            end: haystack.len(),
        }]
    );
    assert!(
        first.resources.total_work_units <= IterationVmLimits::default().capture.vm.max_work_units
    );
    assert!(
        first.resources.peak_accounted_memory_bytes
            <= IterationVmLimits::default().capture.vm.max_memory_bytes
    );
}

#[test]
fn bounded_adversarial_iteration_is_panic_free_and_deterministic() {
    let patterns = ["", "a*", "(a|aa)*b", "(a)?b", "(é*?)", r"\b"];
    for (case, pattern) in patterns.into_iter().enumerate() {
        let program = lower_default(pattern);
        for haystack in all_haystacks(&['a', 'b', 'é'], 4) {
            let caught = catch_unwind(AssertUnwindSafe(|| {
                execute_find_iter(
                    &program,
                    &haystack,
                    CompileLimits::default(),
                    IterationPolicy::NonOverlapping,
                    IterationVmLimits {
                        capture: CaptureVmLimits {
                            vm: VmLimits {
                                max_input_bytes: 128,
                                max_threads_per_offset: 1_024,
                                max_memory_bytes: 2 * 1_024 * 1_024,
                                max_work_units: 256 * 1_024,
                                max_trace_events: 32,
                            },
                            max_capture_history_nodes: 8_192,
                        },
                        max_matches: 128,
                        max_trace_events: 32,
                    },
                )
            }));
            assert!(caught.is_ok(), "panic case={case} haystack={haystack:?}");
            let first = caught
                .expect("panic checked")
                .unwrap_or_else(|error| panic!("case={case} haystack={haystack:?}: {error}"));
            assert_eq!(
                first
                    .matches
                    .into_iter()
                    .map(normalize_vm)
                    .collect::<Vec<_>>(),
                incumbent_non_overlapping(pattern, &haystack),
                "case={case} haystack={haystack:?}"
            );
        }
    }
}

#[test]
fn docs_proof_commands_and_no_claims_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX VM ITERATION CONTRACT -->",
        "ASUP-REGEX-ITERATION-VM-V1",
        "regex@1.13.1",
        "Non-overlapping",
        "Overlapping",
        "Normalized replay receipts",
        "No local Cargo fallback is approved.",
        "no replacement-template parser or capture-reference expansion claim",
        "no production privacy wiring or dependency-removal claim",
        "<!-- END REGEX VM ITERATION CONTRACT -->",
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
        "no replacement-template parser or capture-reference expansion",
        "no cancellation or cooperative-yield integration",
        "no production privacy wiring or dependency removal",
        "no accepted regex syntax expansion",
        "no performance improvement or no-regression claim",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }
}
