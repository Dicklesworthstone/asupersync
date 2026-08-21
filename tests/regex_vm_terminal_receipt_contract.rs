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
    CaptureSpan, DEFAULT_CANCELLATION_CHECK_INTERVAL_WORK_UNITS,
    DEFAULT_PRIVATE_PATTERN_CACHE_MAX_ENTRIES,
    DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES,
    DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILES,
    DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LIVE_ACCOUNTED_BYTES,
    DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LOOKUP_WORK_UNITS,
    DEFAULT_PRIVATE_PATTERN_CACHE_MAX_PATTERN_BYTES, IterationPolicy, IterationVmLimits,
    PrivatePatternCache, PrivatePatternCacheCheckpoint, PrivatePatternCacheErrorKind,
    PrivatePatternCacheLimits, PrivatePatternConfig, VmCancellationCheckpoint,
    VmCancellationControl, VmErrorKind, VmLimits, VmMatch, execute_find_iter,
    execute_find_iter_with_control, execute_full_with_control,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ARTIFACT_PATH: &str = "artifacts/regex_vm_terminal_receipt_v1.json";
const DOC_PATH: &str = "docs/regex_vm_terminal_receipt.md";
const COMPILER_TERMINAL_PATH: &str = "artifacts/regex_compiler_terminal_receipt_v1.json";
const ITERATION_PREDECESSOR_PATH: &str = "artifacts/regex_vm_iteration_contract_v1.json";
const COMPILER_TERMINAL_SHA256: &str =
    "3a67d943175079ab0378080de5b8ee06fd5e979b0c9555dc30a45cbb62da2f5b";
const ITERATION_PREDECESSOR_SHA256: &str =
    "f8ad1b1f0b3d6b148524701c39224c51988ef3be2f63531647a5f303439ade92";
const VM_SOURCE_SHA256: &str = "eb26edc914e1c2c4683d53132524446a2a84052072202d070581ca9917d27947";

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
    assert!(boolean(&decision, "r3_6_bounded_cache_implemented"));
    assert!(boolean(&decision, "r3_6_performance_measurement_complete"));
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
fn r3_6_cache_policy_is_bounded_exact_private_and_deferred() {
    let value = contract();
    let policy = Value::Object(object(&value, "r3_6_cache_policy").clone());
    assert_eq!(text(&policy, "bead_id"), "asupersync-5z2scg.8.3.6");
    assert_eq!(
        text(&policy, "status"),
        "IMPLEMENTED_MEASURED_KEEP_INCUMBENT_DEFER"
    );
    assert_eq!(
        text(&policy, "ownership"),
        "CALLER_OWNED_NO_GLOBAL_INSTANCE"
    );
    assert_eq!(
        text(&policy, "key_identity"),
        "FULL_CONFIG_FINGERPRINT_PREFILTER_EXACT_SOURCE_EQUALITY"
    );
    assert!(boolean(&policy, "compile_runs_outside_cache_state_mutex"));
    assert!(boolean(&policy, "cancellation_callbacks_outside_mutex"));
    assert!(boolean(&policy, "default_single_inflight_compile"));
    assert!(!boolean(&policy, "source_erasure_claim"));
    assert!(!boolean(&policy, "production_cutover_eligible"));

    let limits = Value::Object(object(&policy, "default_limits").clone());
    let defaults = PrivatePatternCacheLimits::default();
    assert_eq!(
        number(&limits, "max_entries"),
        u64::try_from(DEFAULT_PRIVATE_PATTERN_CACHE_MAX_ENTRIES).expect("entry limit fits")
    );
    assert_eq!(
        number(&limits, "max_pattern_bytes"),
        u64::try_from(DEFAULT_PRIVATE_PATTERN_CACHE_MAX_PATTERN_BYTES).expect("pattern limit fits")
    );
    assert_eq!(
        number(&limits, "max_live_accounted_bytes"),
        DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LIVE_ACCOUNTED_BYTES
    );
    assert_eq!(
        number(&limits, "max_inflight_compiles"),
        u64::try_from(DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILES)
            .expect("compile count fits")
    );
    assert_eq!(
        number(&limits, "max_inflight_compile_accounted_bytes"),
        DEFAULT_PRIVATE_PATTERN_CACHE_MAX_INFLIGHT_COMPILE_ACCOUNTED_BYTES
    );
    assert_eq!(
        number(&limits, "max_lookup_work_units"),
        DEFAULT_PRIVATE_PATTERN_CACHE_MAX_LOOKUP_WORK_UNITS
    );
    assert_eq!(defaults.max_inflight_compiles, 1);

    let error_codes = array(&policy, "error_codes")
        .iter()
        .map(|row| row.as_str().expect("cache error code text"))
        .collect::<Vec<_>>();
    let expected_codes = [
        PrivatePatternCacheErrorKind::InvalidLimits,
        PrivatePatternCacheErrorKind::PatternLimit,
        PrivatePatternCacheErrorKind::EntryTooLarge,
        PrivatePatternCacheErrorKind::CapacityPinned,
        PrivatePatternCacheErrorKind::Closed,
        PrivatePatternCacheErrorKind::Cancelled,
        PrivatePatternCacheErrorKind::Config,
        PrivatePatternCacheErrorKind::AllocationFailure,
        PrivatePatternCacheErrorKind::ArithmeticOverflow,
        PrivatePatternCacheErrorKind::CompileCapacity,
        PrivatePatternCacheErrorKind::CompileMemoryCapacity,
        PrivatePatternCacheErrorKind::LookupWorkLimit,
    ]
    .map(PrivatePatternCacheErrorKind::code);
    assert_eq!(error_codes, expected_codes);
    assert_ne!(
        PrivatePatternCacheCheckpoint::Lookup,
        PrivatePatternCacheCheckpoint::Compile
    );
    assert_ne!(
        PrivatePatternCacheCheckpoint::Compile,
        PrivatePatternCacheCheckpoint::Admission
    );

    let private_pattern = "r3_6_terminal_private_cache_canary";
    let cache = PrivatePatternCache::new(defaults).expect("valid cache policy");
    let lease = cache
        .get_or_compile(PrivatePatternConfig::new(private_pattern))
        .expect("admit private cache fixture");
    assert!(lease.is_match(private_pattern).expect("cached match"));
    for rendered in [format!("{cache:?}"), format!("{lease:?}")] {
        assert!(!rendered.contains(private_pattern));
    }
    cache.shutdown();
    drop(lease);
    let snapshot = cache.snapshot();
    assert!(snapshot.closed);
    assert_eq!(snapshot.entries, 0);
    assert_eq!(snapshot.live_accounted_bytes, 0);
    assert_eq!(snapshot.inflight_compiles, 0);
    assert_eq!(snapshot.inflight_compile_accounted_bytes, 0);
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
fn r3_6_release_profile_evidence_is_cross_host_bounded_and_deferred() {
    let value = contract();
    let performance = Value::Object(object(&value, "r3_6_release_performance_evidence").clone());
    assert_eq!(
        text(&performance, "status"),
        "MEASURED_KEEP_INCUMBENT_DEFER"
    );
    assert_eq!(
        text(&performance, "harness_revision"),
        "3244d50a1d6fb29ea2914b99babd205d88c59522"
    );
    assert_eq!(number(&performance, "sample_count_per_operation"), 1_001);
    assert_eq!(number(&performance, "warmup_count_per_operation"), 32);
    assert_eq!(number(&performance, "raw_samples_per_target"), 24_024);
    assert_eq!(text(&performance, "percentile_method"), "nearest-rank");
    assert_eq!(text(&performance, "disposition"), "KEEP_INCUMBENT_DEFER");

    let operation_order = array(&performance, "operation_order")
        .iter()
        .map(|row| row.as_str().expect("operation name"))
        .collect::<Vec<_>>();
    assert_eq!(
        operation_order,
        [
            "owned_compile",
            "incumbent_compile",
            "owned_cache_miss",
            "owned_cache_hit",
            "owned_is_match",
            "incumbent_is_match",
        ]
    );
    assert_eq!(
        array(&performance, "metric_order"),
        ["operations_per_second", "p50_ns", "p95_ns", "p999_ns"]
            .map(Value::from)
            .as_slice()
    );

    let expected_targets = [
        ("ovh-a-x86_64", "29985909466202203"),
        ("mac-mini-max-aarch64-apple-darwin", "29985909466202206"),
    ];
    let target_rows = array(&performance, "target_rows");
    assert_eq!(target_rows.len(), expected_targets.len());
    for (target, (expected_id, expected_job)) in target_rows.iter().zip(expected_targets) {
        assert_eq!(text(target, "target_id"), expected_id);
        assert_eq!(text(target, "rch_job_id"), expected_job);
        let scenarios = array(target, "scenario_rows");
        assert_eq!(scenarios.len(), 4);
        for scenario in scenarios {
            let metrics = array(scenario, "operation_metrics");
            assert_eq!(metrics.len(), operation_order.len());
            for row in metrics {
                let cells = row.as_array().expect("operation metric row");
                assert_eq!(cells.len(), 4);
                let values = cells
                    .iter()
                    .map(|cell| cell.as_u64().expect("positive metric"))
                    .collect::<Vec<_>>();
                assert!(values.iter().all(|value| *value > 0));
                assert!(values[1] <= values[2]);
                assert!(values[2] <= values[3]);
            }
            let owned_match = metrics[4].as_array().expect("owned match metrics");
            let incumbent_match = metrics[5].as_array().expect("incumbent match metrics");
            assert!(
                owned_match[1].as_u64().expect("owned p50")
                    > incumbent_match[1].as_u64().expect("incumbent p50"),
                "owned match p50 must retain the incumbent for {} on {expected_id}",
                text(scenario, "scenario_id")
            );
        }
    }

    let raw_receipts = array(&performance, "raw_latency_receipts");
    assert_eq!(raw_receipts.len(), 2);
    assert_eq!(text(&raw_receipts[0], "rch_job_id"), "29985909466202203");
    assert_eq!(text(&raw_receipts[1], "rch_job_id"), "29985909466202206");
    for receipt in raw_receipts {
        assert_eq!(
            text(receipt, "marker"),
            "R3_6_REGEX_VM_RELEASE_PERF_RECEIPT="
        );
        assert!(text(receipt, "status").contains("TERMINAL_EXIT_0"));
    }

    let resources = array(&performance, "resource_rows");
    assert_eq!(resources.len(), 3);
    let heaptrack = resources
        .iter()
        .find(|row| text(row, "target_id") == "ts2-x86_64-heaptrack")
        .expect("heaptrack resource row");
    assert_eq!(text(heaptrack, "rch_job_id"), "29985909466202208");
    assert_eq!(number(heaptrack, "allocation_calls"), 53_248_319);
    assert_eq!(number(heaptrack, "temporary_allocations"), 19_075_354);
    assert_eq!(number(heaptrack, "process_lifetime_residual_bytes"), 944);

    let xctrace = resources
        .iter()
        .find(|row| text(row, "target_id") == "mac-mini-max-aarch64-xctrace")
        .expect("xctrace resource row");
    assert_eq!(text(xctrace, "rch_job_id"), "29985909466202209");
    assert_eq!(number(xctrace, "allocation_count_total"), 53_249_485);
    assert_eq!(number(xctrace, "persistent_bytes"), 121_536);

    let rss = resources
        .iter()
        .find(|row| text(row, "target_id") == "mac-mini-max-aarch64-rss")
        .expect("Apple RSS row");
    assert_eq!(number(rss, "maximum_resident_set_bytes"), 7_766_016);
    assert_eq!(number(rss, "peak_memory_footprint_bytes"), 5_849_376);
    assert_eq!(number(rss, "swaps"), 0);
    assert!(text(&performance, "cache_shutdown_invariant").contains("zero entries"));
    assert!(text(&performance, "admission").contains("no performance improvement"));
}

#[test]
fn docs_proof_and_no_claim_boundaries_are_discoverable() {
    let value = contract();
    let docs = read(DOC_PATH);
    let normalized_docs = docs.split_whitespace().collect::<Vec<_>>().join(" ");
    for marker in [
        "<!-- BEGIN REGEX VM TERMINAL RECEIPT -->",
        "ASUP-REGEX-VM-TERMINAL-V1",
        "KEEP_INCUMBENT_DEFER",
        "RGX-VM-E015",
        "caller-supplied",
        "PrivatePatternCache",
        "default 2 GiB aggregate budget intentionally admits one",
        "R3.6 release-profile matrix is now measured",
        "24,024 raw samples",
        "53,248,319 allocation calls",
        "No local Cargo fallback is approved.",
        "no production cutover",
        "no production privacy wiring or dependency removal",
        "<!-- END REGEX VM TERMINAL RECEIPT -->",
    ] {
        assert!(
            normalized_docs.contains(marker),
            "missing doc marker: {marker}"
        );
    }

    let proof = Value::Object(object(&value, "proof").clone());
    for key in [
        "r3_6_cache_unit_command",
        "unit_command",
        "contract_command",
        "clippy_command",
    ] {
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
        "no R3.6 performance improvement, no-regression, or production-cutover claim",
        "no complete public regex API",
        "no allocator-usable-size, zero-process-leak, or production-RSS guarantee",
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

const R3_6_RELEASE_PERF_SAMPLE_COUNT: usize = 1_001;
const R3_6_RELEASE_PERF_WARMUP_COUNT: usize = 32;

struct R3_6ReleasePerfScenario {
    id: &'static str,
    pattern: &'static str,
    input: String,
}

fn r3_6_release_perf_scenarios() -> Vec<R3_6ReleasePerfScenario> {
    vec![
        R3_6ReleasePerfScenario {
            id: "ascii_capture_tail_match",
            pattern: "([a-z]+)=([0-9]+)$",
            input: format!("{}key=123456", "x;".repeat(2_048)),
        },
        R3_6ReleasePerfScenario {
            id: "unicode_property_tail_match",
            pattern: r"\p{Greek}+$",
            input: format!("{}{}", "latin;".repeat(512), "αβγ".repeat(512)),
        },
        R3_6ReleasePerfScenario {
            id: "ambiguous_alternation_suffix_match",
            pattern: "(?:a|aa)+b$",
            input: format!("{}b", "a".repeat(2_048)),
        },
        R3_6ReleasePerfScenario {
            id: "wide_alternation_full_scan_miss",
            pattern: "(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)+Z$",
            input: "abcdefghijklmnopqrstuvwxyz".repeat(128),
        },
    ]
}

fn r3_6_measure_once<T>(operation: impl FnOnce() -> T) -> (u64, T) {
    let started = Instant::now();
    let result = black_box(operation());
    let elapsed = u64::try_from(started.elapsed().as_nanos())
        .expect("single operation nanoseconds fit in u64")
        .max(1);
    (elapsed, result)
}

fn r3_6_nearest_rank(samples: &[u64], numerator: usize, denominator: usize) -> u64 {
    assert!(!samples.is_empty());
    assert!(numerator > 0 && numerator <= denominator);
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    let rank = numerator
        .checked_mul(ordered.len())
        .and_then(|value| value.checked_add(denominator - 1))
        .expect("bounded percentile rank")
        / denominator;
    ordered[rank.saturating_sub(1)]
}

fn r3_6_distribution(operation: &str, samples: Vec<u64>, bytes_per_operation: usize) -> Value {
    assert_eq!(samples.len(), R3_6_RELEASE_PERF_SAMPLE_COUNT);
    let total_ns = samples.iter().copied().map(u128::from).sum::<u128>().max(1);
    let sample_count = u128::try_from(samples.len()).expect("sample count fits in u128");
    let operations_per_second = sample_count
        .saturating_mul(1_000_000_000)
        .checked_div(total_ns)
        .expect("nonzero total nanoseconds");
    let bytes_per_second = sample_count
        .saturating_mul(u128::try_from(bytes_per_operation).expect("byte count fits in u128"))
        .saturating_mul(1_000_000_000)
        .checked_div(total_ns)
        .expect("nonzero total nanoseconds");
    json!({
        "operation": operation,
        "sample_count": samples.len(),
        "bytes_per_operation": bytes_per_operation,
        "operations_per_second": u64::try_from(operations_per_second)
            .expect("operation throughput fits in u64"),
        "bytes_per_second": u64::try_from(bytes_per_second)
            .expect("byte throughput fits in u64"),
        "p50_ns": r3_6_nearest_rank(&samples, 50, 100),
        "p95_ns": r3_6_nearest_rank(&samples, 95, 100),
        "p999_ns": r3_6_nearest_rank(&samples, 999, 1_000),
        "raw_ns": samples,
    })
}

#[test]
fn r3_6_release_performance_emitter() {
    let Ok(target_id) = std::env::var("R3_6_REGEX_PERF_TARGET") else {
        return;
    };
    let scenario_filter = std::env::var("R3_6_REGEX_PERF_SCENARIO").ok();
    let mut scenario_rows = Vec::new();

    for scenario in r3_6_release_perf_scenarios() {
        if scenario_filter
            .as_deref()
            .is_some_and(|selected| selected != scenario.id)
        {
            continue;
        }

        let config = PrivatePatternConfig::new(scenario.pattern);
        for _ in 0..R3_6_RELEASE_PERF_WARMUP_COUNT {
            black_box(
                PrivatePatternConfig::load(config.clone()).expect("warm owned pattern compile"),
            );
            black_box(IncumbentRegex::new(scenario.pattern).expect("warm incumbent compile"));
        }

        let mut owned_compile_ns = Vec::with_capacity(R3_6_RELEASE_PERF_SAMPLE_COUNT);
        let mut incumbent_compile_ns = Vec::with_capacity(R3_6_RELEASE_PERF_SAMPLE_COUNT);
        for _ in 0..R3_6_RELEASE_PERF_SAMPLE_COUNT {
            let sample_config = config.clone();
            let (elapsed, loaded) = r3_6_measure_once(|| {
                PrivatePatternConfig::load(sample_config).expect("owned pattern compile")
            });
            owned_compile_ns.push(elapsed);
            black_box(loaded);

            let (elapsed, incumbent) = r3_6_measure_once(|| {
                IncumbentRegex::new(black_box(scenario.pattern)).expect("incumbent compile")
            });
            incumbent_compile_ns.push(elapsed);
            black_box(incumbent);
        }

        let cache = PrivatePatternCache::new(PrivatePatternCacheLimits::default())
            .expect("valid release performance cache policy");
        for _ in 0..R3_6_RELEASE_PERF_WARMUP_COUNT {
            cache.clear();
            black_box(
                cache
                    .get_or_compile(config.clone())
                    .expect("warm cache miss compile"),
            );
        }
        let mut cache_miss_ns = Vec::with_capacity(R3_6_RELEASE_PERF_SAMPLE_COUNT);
        for _ in 0..R3_6_RELEASE_PERF_SAMPLE_COUNT {
            cache.clear();
            let sample_config = config.clone();
            let (elapsed, lease) = r3_6_measure_once(|| {
                cache
                    .get_or_compile(sample_config)
                    .expect("cache miss compile")
            });
            cache_miss_ns.push(elapsed);
            black_box(lease);
        }

        cache.clear();
        black_box(
            cache
                .get_or_compile(config.clone())
                .expect("prime cache-hit scenario"),
        );
        for _ in 0..R3_6_RELEASE_PERF_WARMUP_COUNT {
            black_box(
                cache
                    .get_or_compile(config.clone())
                    .expect("warm cache hit"),
            );
        }
        let mut cache_hit_ns = Vec::with_capacity(R3_6_RELEASE_PERF_SAMPLE_COUNT);
        for _ in 0..R3_6_RELEASE_PERF_SAMPLE_COUNT {
            let sample_config = config.clone();
            let (elapsed, lease) =
                r3_6_measure_once(|| cache.get_or_compile(sample_config).expect("cache hit"));
            cache_hit_ns.push(elapsed);
            black_box(lease);
        }

        let owned = PrivatePatternConfig::load(config.clone()).expect("owned matcher compile");
        let incumbent = IncumbentRegex::new(scenario.pattern).expect("incumbent matcher compile");
        let expected = incumbent.is_match(&scenario.input);
        assert_eq!(
            owned.is_match(&scenario.input).expect("owned preflight"),
            expected
        );
        for _ in 0..R3_6_RELEASE_PERF_WARMUP_COUNT {
            assert_eq!(
                black_box(&owned)
                    .is_match(black_box(&scenario.input))
                    .expect("warm owned match"),
                expected
            );
            assert_eq!(
                black_box(&incumbent).is_match(black_box(&scenario.input)),
                expected
            );
        }
        let mut owned_match_ns = Vec::with_capacity(R3_6_RELEASE_PERF_SAMPLE_COUNT);
        let mut incumbent_match_ns = Vec::with_capacity(R3_6_RELEASE_PERF_SAMPLE_COUNT);
        for _ in 0..R3_6_RELEASE_PERF_SAMPLE_COUNT {
            let (elapsed, matched) = r3_6_measure_once(|| {
                black_box(&owned)
                    .is_match(black_box(&scenario.input))
                    .expect("owned match")
            });
            assert_eq!(matched, expected);
            owned_match_ns.push(elapsed);

            let (elapsed, matched) =
                r3_6_measure_once(|| black_box(&incumbent).is_match(black_box(&scenario.input)));
            assert_eq!(matched, expected);
            incumbent_match_ns.push(elapsed);
        }

        let live_snapshot = cache.snapshot();
        assert_eq!(live_snapshot.entries, 1);
        assert_eq!(live_snapshot.inflight_compiles, 0);
        assert_eq!(live_snapshot.inflight_compile_accounted_bytes, 0);
        assert_eq!(
            live_snapshot.hits,
            u64::try_from(R3_6_RELEASE_PERF_WARMUP_COUNT + R3_6_RELEASE_PERF_SAMPLE_COUNT)
                .expect("cache hit count fits")
        );
        cache.shutdown();
        let shutdown_snapshot = cache.snapshot();
        assert!(shutdown_snapshot.closed);
        assert_eq!(shutdown_snapshot.entries, 0);
        assert_eq!(shutdown_snapshot.live_accounted_bytes, 0);
        assert_eq!(shutdown_snapshot.inflight_compiles, 0);
        assert_eq!(shutdown_snapshot.inflight_compile_accounted_bytes, 0);

        scenario_rows.push(json!({
            "scenario_id": scenario.id,
            "pattern_bytes": scenario.pattern.len(),
            "input_bytes": scenario.input.len(),
            "expected_match": expected,
            "operations": [
                r3_6_distribution("owned_compile", owned_compile_ns, scenario.pattern.len()),
                r3_6_distribution(
                    "incumbent_compile",
                    incumbent_compile_ns,
                    scenario.pattern.len(),
                ),
                r3_6_distribution("owned_cache_miss", cache_miss_ns, scenario.pattern.len()),
                r3_6_distribution("owned_cache_hit", cache_hit_ns, scenario.pattern.len()),
                r3_6_distribution("owned_is_match", owned_match_ns, scenario.input.len()),
                r3_6_distribution(
                    "incumbent_is_match",
                    incumbent_match_ns,
                    scenario.input.len(),
                ),
            ],
            "cache_snapshot_before_shutdown": {
                "entries": live_snapshot.entries,
                "live_accounted_bytes": live_snapshot.live_accounted_bytes,
                "hits": live_snapshot.hits,
                "misses": live_snapshot.misses,
                "compilations": live_snapshot.compilations,
                "admissions": live_snapshot.admissions,
                "evictions": live_snapshot.evictions,
                "clears": live_snapshot.clears,
            },
            "cache_snapshot_after_shutdown": {
                "closed": shutdown_snapshot.closed,
                "entries": shutdown_snapshot.entries,
                "live_accounted_bytes": shutdown_snapshot.live_accounted_bytes,
                "inflight_compiles": shutdown_snapshot.inflight_compiles,
                "inflight_compile_accounted_bytes": shutdown_snapshot
                    .inflight_compile_accounted_bytes,
            },
        }));
    }

    assert!(
        scenario_filter.is_none() || scenario_rows.len() == 1,
        "selected performance scenario must exist"
    );
    assert_eq!(
        scenario_rows.len(),
        scenario_filter.as_ref().map_or(4, |_| 1)
    );
    println!(
        "R3_6_REGEX_VM_RELEASE_PERF_RECEIPT={}",
        json!({
            "target_id": target_id,
            "profile": "cargo test --release with debuginfo disabled",
            "sample_count_per_operation": R3_6_RELEASE_PERF_SAMPLE_COUNT,
            "warmup_count_per_operation": R3_6_RELEASE_PERF_WARMUP_COUNT,
            "percentile_method": "nearest-rank",
            "incumbent_revision": "regex@1.13.1",
            "scenario_rows": scenario_rows,
        })
    );
}
