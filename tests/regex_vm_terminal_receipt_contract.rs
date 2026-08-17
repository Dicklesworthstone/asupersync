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
use std::hint::black_box;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use regex::{Captures as IncumbentCaptures, Regex as IncumbentRegex};
use regex_boundaries::FoldBoundaryLimits;
use regex_ir::{CompileLimits, Program};
use regex_lowering::{LowerErrorKind, lower};
use regex_semantics::SemanticLimits;
use regex_syntax::{LexerLimits, ParserLimits};
use regex_vm::{
    CaptureSpan, DEFAULT_CANCELLATION_CHECK_INTERVAL_WORK_UNITS, IterationPolicy,
    IterationVmLimits, VmCancellationCheckpoint, VmCancellationControl, VmErrorKind, VmLimits,
    VmMatch, execute_find_iter, execute_find_iter_with_control, execute_full_with_control,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_vm_terminal_receipt_v1.json";
const DOC_PATH: &str = "docs/regex_vm_terminal_receipt.md";
const COMPILER_TERMINAL_PATH: &str = "artifacts/regex_compiler_terminal_receipt_v1.json";
const ITERATION_PREDECESSOR_PATH: &str = "artifacts/regex_vm_iteration_contract_v1.json";
const COMPILER_TERMINAL_SHA256: &str =
    "1e45fa0b183120b6541d8fa87ec55ccfcb3c0df2292e078a158790c168c49781";
const ITERATION_PREDECESSOR_SHA256: &str =
    "2da7a146e5ed41b5b9379b2b470805bb6967905c4bdab367fd63ce60797bfd74";
const VM_SOURCE_SHA256: &str = "68f5b24f8ba6cfc454d8287e2285b2a30f572fa8b168e94d316375d7c00bb2e5";

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

fn assert_non_overlapping_same(pattern: &str, haystack: &str) {
    let candidate = execute_find_iter(
        &lower_default(pattern),
        haystack,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
    )
    .unwrap_or_else(|error| panic!("candidate {pattern:?}: {error}"))
    .matches
    .into_iter()
    .map(normalize_vm)
    .collect::<Vec<_>>();
    let incumbent = IncumbentRegex::new(pattern)
        .unwrap_or_else(|error| panic!("incumbent {pattern:?}: {error}"))
        .captures_iter(haystack)
        .map(normalize_incumbent)
        .collect::<Vec<_>>();
    assert_eq!(candidate, incumbent, "{pattern:?}");
}

#[test]
fn identity_authority_pins_and_fail_closed_decision_are_exact() {
    let value = contract();
    assert_eq!(text(&value, "artifact_id"), "regex-vm-terminal-receipt-v1");
    assert_eq!(text(&value, "terminal_id"), "ASUP-REGEX-VM-TERMINAL-V1");
    assert_eq!(text(&value, "bead_id"), "asupersync-5z2scg.8.3.4.4");

    let authority = Value::Object(object(&value, "authority").clone());
    assert_eq!(
        text(&authority, "compiler_terminal_path"),
        COMPILER_TERMINAL_PATH
    );
    assert_eq!(
        text(&authority, "compiler_terminal_sha256"),
        COMPILER_TERMINAL_SHA256
    );
    assert_eq!(
        text(&authority, "iteration_predecessor_path"),
        ITERATION_PREDECESSOR_PATH
    );
    assert_eq!(
        text(&authority, "iteration_predecessor_sha256"),
        ITERATION_PREDECESSOR_SHA256
    );
    assert_eq!(sha256(COMPILER_TERMINAL_PATH), COMPILER_TERMINAL_SHA256);
    assert_eq!(
        sha256(ITERATION_PREDECESSOR_PATH),
        ITERATION_PREDECESSOR_SHA256
    );
    assert!(!boolean(&authority, "production_cutover_eligible"));

    let vm_source = array(&value, "sources")
        .iter()
        .find(|row| text(row, "path") == "src/observability/regex_vm.rs")
        .expect("VM source row");
    assert_eq!(text(vm_source, "sha256"), VM_SOURCE_SHA256);
    assert_eq!(sha256("src/observability/regex_vm.rs"), VM_SOURCE_SHA256);
    assert_eq!(
        number(vm_source, "bytes"),
        fs::metadata("src/observability/regex_vm.rs")
            .expect("VM source metadata")
            .len()
    );

    let decision = Value::Object(object(&value, "decision").clone());
    assert_eq!(text(&decision, "disposition"), "KEEP_INCUMBENT_DEFER");
    assert!(boolean(&decision, "r3_4_vm_terminal_complete"));
    assert!(boolean(&decision, "explicit_cancellation_checkpoints"));
    assert!(boolean(&decision, "performance_measurement_complete"));
    assert!(!boolean(&decision, "ambient_cancellation_state"));
    assert!(!boolean(&decision, "all_mapped_rows_same_or_better"));
    assert!(!boolean(&decision, "matcher_api_integration_authorized"));
    assert!(!boolean(&decision, "dependency_removal_authorized"));
    assert_eq!(
        text(&decision, "on_missing_unknown_expired_or_drifted_evidence"),
        "KEEP_INCUMBENT_DEFER"
    );
}

#[test]
fn cancellation_is_explicit_deterministic_private_and_budget_precedent() {
    assert_eq!(VmErrorKind::Cancelled.code(), "RGX-VM-E015");
    assert_eq!(DEFAULT_CANCELLATION_CHECK_INTERVAL_WORK_UNITS, 1_024);

    let mut invalid_probe = |_: VmCancellationCheckpoint| false;
    assert!(matches!(
        VmCancellationControl::new(0, &mut invalid_probe),
        Err(error) if error.kind == VmErrorKind::InvalidLimits
    ));

    let program = lower_default("(a+)");
    let private_input = "terminal-private-canary-aaaaaaaa";
    let mut first_probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 5;
    let mut first = VmCancellationControl::new(4, &mut first_probe).expect("first control");
    let first_error = execute_find_iter_with_control(
        &program,
        private_input,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
        &mut first,
    )
    .expect_err("fifth checkpoint cancels");
    let first_receipt = (
        first_error,
        first.cancelled_at(),
        first.checkpoints(),
        first.checkpoint_fingerprint(),
    );
    assert_eq!(first_error.kind, VmErrorKind::Cancelled);
    assert_eq!(first.observed_work_units(), 20);
    assert!(!first_error.to_string().contains(private_input));

    let mut second_probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == 5;
    let mut second = VmCancellationControl::new(4, &mut second_probe).expect("second control");
    let second_error = execute_find_iter_with_control(
        &program,
        private_input,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
        &mut second,
    )
    .expect_err("replayed cancellation");
    assert_eq!(
        first_receipt,
        (
            second_error,
            second.cancelled_at(),
            second.checkpoints(),
            second.checkpoint_fingerprint(),
        )
    );
    let reusable_matches = execute_find_iter(
        &program,
        private_input,
        CompileLimits::default(),
        IterationPolicy::NonOverlapping,
        IterationVmLimits::default(),
    )
    .expect("program remains reusable")
    .matches
    .len();
    let incumbent_matches = IncumbentRegex::new("(a+)")
        .expect("incumbent reusable oracle")
        .captures_iter(private_input)
        .count();
    assert_eq!(
        reusable_matches, incumbent_matches,
        "reused candidate remains exact after cancellation"
    );

    let mut probe_called = false;
    let mut work_probe = |_: VmCancellationCheckpoint| {
        probe_called = true;
        true
    };
    let mut work_control = VmCancellationControl::new(2, &mut work_probe).expect("work control");
    let work_error = execute_full_with_control(
        &lower_default("a"),
        "a",
        CompileLimits::default(),
        VmLimits {
            max_work_units: 1,
            ..VmLimits::default()
        },
        &mut work_control,
    )
    .expect_err("built-in work budget fails first");
    assert_eq!(work_error.kind, VmErrorKind::WorkLimit);
    assert!(!probe_called);
}

#[test]
fn cancellation_sequences_cover_160_intervals_and_cutoffs() {
    let program = lower_default("a");
    let input = "a a a a a a a a";
    let mut cases = 0_u64;
    for interval in 1..=16_u64 {
        for cancel_at in 1..=10_u64 {
            let mut probe = |checkpoint: VmCancellationCheckpoint| checkpoint.sequence == cancel_at;
            let mut control =
                VmCancellationControl::new(interval, &mut probe).expect("valid control");
            let result = execute_find_iter_with_control(
                &program,
                input,
                CompileLimits::default(),
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
                &mut control,
            );
            match result {
                Err(error) => {
                    assert_eq!(error.kind, VmErrorKind::Cancelled);
                    let checkpoint = control.cancelled_at().expect("cancel checkpoint");
                    assert_eq!(checkpoint.sequence, cancel_at);
                    assert_eq!(checkpoint.work_units, interval * cancel_at);
                }
                Ok(outcome) => {
                    assert_eq!(outcome.matches.len(), 8);
                    assert!(control.cancelled_at().is_none());
                    assert!(control.checkpoints() < cancel_at);
                    assert_eq!(
                        control.observed_work_units(),
                        outcome.resources.total_work_units
                    );
                }
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 160);
}

#[test]
fn adversarial_rows_are_bounded_exact_and_panic_free() {
    let cases = [
        ("a*", "a".repeat(20_000)),
        ("(?:a|aa)+b", format!("{}b", "a".repeat(2_048))),
        (
            "(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+",
            "abcdefghijklmnopqrstuvwxyz".repeat(128),
        ),
        (r"\p{Greek}+", "αβγ".repeat(1_024)),
    ];
    for (pattern, input) in cases {
        let caught = catch_unwind(AssertUnwindSafe(|| {
            assert_non_overlapping_same(pattern, &input);
        }));
        assert!(caught.is_ok(), "panic for {pattern:?}");
    }

    let nested = format!("{}a{}", "(".repeat(64), ")".repeat(64));
    assert_non_overlapping_same(&nested, "a");

    let nullable = lower(
        "(?:a?)*",
        LexerLimits::default(),
        ParserLimits::default(),
        SemanticLimits::default(),
        FoldBoundaryLimits::default(),
        CompileLimits::default(),
    )
    .expect_err("nullable unbounded loop remains deferred");
    assert_eq!(nullable.kind, LowerErrorKind::NullableUnboundedRepetition);
    assert_eq!(nullable.code(), "RGX-LOWER-E009");
}

#[test]
fn adversarial_work_scales_without_catastrophic_backtracking() {
    let program = lower_default("(?:a|aa)+b");
    let run = |count: usize| {
        execute_find_iter(
            &program,
            &format!("{}b", "a".repeat(count)),
            CompileLimits::default(),
            IterationPolicy::NonOverlapping,
            IterationVmLimits::default(),
        )
        .expect("bounded ambiguous suffix")
        .resources
        .total_work_units
    };
    let one = run(512);
    let two = run(1_024);
    assert!(two > one);
    assert!(
        two <= one.saturating_mul(3),
        "work must remain approximately linear: {one} -> {two}"
    );
}

#[test]
fn measured_target_rows_have_raw_provenance_and_honest_unknown_cells() {
    let value = contract();
    let performance = Value::Object(object(&value, "performance_evidence").clone());
    assert_eq!(text(&performance, "status"), "MEASURED_NO_THRESHOLD_CLAIM");
    assert_eq!(number(&performance, "sample_count_per_operation"), 9);
    for row in array(&performance, "target_rows") {
        assert_eq!(text(row, "status"), "MEASURED");
        assert!(matches!(text(row, "target_id"), "ovh-a" | "hz2"));
        assert!(!text(row, "topology").contains("PENDING"));
        assert!(!text(row, "toolchain").is_empty());
        for key in [
            "compile_candidate_ns",
            "compile_incumbent_ns",
            "match_candidate_ns",
            "match_incumbent_ns",
        ] {
            let samples = array(row, key);
            assert_eq!(samples.len(), 9, "{key}");
            assert!(
                samples
                    .iter()
                    .all(|sample| sample.as_u64().is_some_and(|value| value > 0)),
                "{key} must contain raw nonzero nanoseconds"
            );
        }
        assert_eq!(text(row, "allocation_status"), "UNKNOWN_NOT_INSTRUMENTED");
        assert_eq!(text(row, "rss_status"), "UNKNOWN_NOT_INSTRUMENTED");
        assert_eq!(
            text(row, "compile_observed_ordering"),
            "CANDIDATE_LOWER_ALL_SAMPLES"
        );
        assert_eq!(
            text(row, "match_observed_ordering"),
            "CANDIDATE_HIGHER_ALL_SAMPLES"
        );
    }
    assert_eq!(array(&performance, "measurement_commands").len(), 2);
    assert!(
        text(&performance, "admission").contains("no threshold"),
        "raw measurements do not admit a regression claim"
    );
}

#[test]
fn docs_proof_and_no_claim_boundaries_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    for marker in [
        "<!-- BEGIN REGEX VM TERMINAL RECEIPT -->",
        "ASUP-REGEX-VM-TERMINAL-V1",
        "KEEP_INCUMBENT_DEFER",
        "RGX-VM-E015",
        "caller-supplied",
        "No local Cargo fallback is approved.",
        "no performance improvement or no-regression claim",
        "no production privacy wiring or dependency removal",
        "<!-- END REGEX VM TERMINAL RECEIPT -->",
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
        "no production privacy wiring or dependency removal",
        "no complete public regex API",
        "no allocation or RSS measurement",
        "no performance improvement or no-regression claim",
        "no broad workspace health or release-readiness claim",
        "no local Cargo fallback approval",
    ] {
        assert!(no_claims.contains(marker), "missing no-claim: {marker}");
    }
}

fn elapsed_ns(started: Instant, repetitions: u64) -> u64 {
    let nanos = started.elapsed().as_nanos();
    u64::try_from(nanos / u128::from(repetitions))
        .expect("average elapsed nanoseconds fit in u64")
        .max(1)
}

#[test]
fn benchmark_provenance_emitter() {
    let Ok(target_id) = std::env::var("REGEX_VM_BENCH_TARGET") else {
        return;
    };
    let pattern = "([a-z]+)=([0-9]+)";
    let input = "a=1 bb=22;".repeat(512);
    assert!(input.len() >= 4_096);
    let repetitions = 5_u64;
    let mut compile_candidate_ns = Vec::with_capacity(9);
    let mut compile_incumbent_ns = Vec::with_capacity(9);
    let mut match_candidate_ns = Vec::with_capacity(9);
    let mut match_incumbent_ns = Vec::with_capacity(9);

    let candidate = lower_default(pattern);
    let incumbent = IncumbentRegex::new(pattern).expect("benchmark incumbent");
    let expected_matches = incumbent.captures_iter(&input).count();
    for _ in 0..9 {
        let started = Instant::now();
        for _ in 0..repetitions {
            black_box(lower_default(black_box(pattern)));
        }
        compile_candidate_ns.push(elapsed_ns(started, repetitions));

        let started = Instant::now();
        for _ in 0..repetitions {
            black_box(IncumbentRegex::new(black_box(pattern)).expect("compile incumbent"));
        }
        compile_incumbent_ns.push(elapsed_ns(started, repetitions));

        let started = Instant::now();
        for _ in 0..repetitions {
            let outcome = execute_find_iter(
                black_box(&candidate),
                black_box(&input),
                CompileLimits::default(),
                IterationPolicy::NonOverlapping,
                IterationVmLimits::default(),
            )
            .expect("match candidate");
            assert_eq!(outcome.matches.len(), expected_matches);
            black_box(outcome);
        }
        match_candidate_ns.push(elapsed_ns(started, repetitions));

        let started = Instant::now();
        for _ in 0..repetitions {
            assert_eq!(
                black_box(&incumbent)
                    .captures_iter(black_box(&input))
                    .count(),
                expected_matches
            );
        }
        match_incumbent_ns.push(elapsed_ns(started, repetitions));
    }

    println!(
        "REGEX_VM_BENCH_RECEIPT={}",
        json!({
            "target_id": target_id,
            "compile_candidate_ns": compile_candidate_ns,
            "compile_incumbent_ns": compile_incumbent_ns,
            "match_candidate_ns": match_candidate_ns,
            "match_incumbent_ns": match_incumbent_ns,
        })
    );
}
