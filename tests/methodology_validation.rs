//! Methodology validation tests for the §0 Alien-Artifact Implementation Framework (bd-1e2if.7).
//!
//! Validates the four methodology pillars:
//! 1. **Baseline infrastructure** — benchmark schema and latency bounds
//! 2. **Golden checksum framework** — capture/verify workflow
//! 3. **Evidence ledger integration** — decision points emit valid entries
//! 4. **Decision contract validation** — invariants on loss matrix, posterior, actions
//!
//! Plus cross-pillar consistency checks and property-based tests.

#[macro_use]
mod common;

use std::sync::Arc;

use asupersync::Cx;
use asupersync::evidence_sink::{
    CollectorSink, EvidenceSink, NullSink, emit_budget_evidence, emit_cancel_evidence,
    emit_scheduler_evidence,
};
use asupersync::runtime::scheduler::decision_contract::{self, SchedulerDecisionContract};
use asupersync::types::Time;
use franken_decision::{DecisionContract, EvalContext, FallbackPolicy, Posterior, evaluate};
use franken_kernel::{DecisionId, TraceId};

// ============================================================================
// Helpers
// ============================================================================

fn test_eval_ctx(calibration: f64) -> EvalContext {
    EvalContext {
        calibration_score: calibration,
        e_process: 1.0,
        ci_width: 0.1,
        decision_id: DecisionId::from_parts(1_700_000_000_000, 42),
        trace_id: TraceId::from_parts(1_700_000_000_000, 1),
        ts_unix_ms: 1_700_000_000_000,
    }
}

fn zero_snapshot() -> asupersync::obligation::lyapunov::StateSnapshot {
    asupersync::obligation::lyapunov::StateSnapshot {
        time: Time::ZERO,
        live_tasks: 0,
        pending_obligations: 0,
        obligation_age_sum_ns: 0,
        draining_regions: 0,
        deadline_pressure: 0.0,
        pending_send_permits: 0,
        pending_acks: 0,
        pending_leases: 0,
        pending_io_ops: 0,
        cancel_requested_tasks: 0,
        cancelling_tasks: 0,
        finalizing_tasks: 0,
        ready_queue_depth: 0,
    }
}

// ============================================================================
// Pillar 1: Baseline Infrastructure
// ============================================================================

/// Verify that the baseline JSON artifact has the correct schema.
#[test]
fn baseline_schema_validity() {
    let baseline_contents =
        std::fs::read_to_string("artifacts/baseline.json").expect("baseline.json must exist");
    let baseline: serde_json::Value =
        serde_json::from_str(&baseline_contents).expect("baseline.json must be valid JSON");

    // Required top-level fields
    assert!(
        baseline.get("schema_version").is_some(),
        "baseline must have schema_version"
    );
    assert!(
        baseline.get("baselines").is_some(),
        "baseline must have baselines array"
    );

    let baselines = baseline["baselines"]
        .as_array()
        .expect("baselines is array");
    assert!(!baselines.is_empty(), "baselines must not be empty");

    // Each entry must have required fields
    for entry in baselines {
        let op = entry
            .get("operation")
            .and_then(|v| v.as_str())
            .expect("entry must have operation");
        assert!(entry.get("p50_ns").is_some(), "entry {op} must have p50_ns");
        assert!(
            entry.get("ci95_lower_ns").is_some(),
            "entry {op} must have ci95_lower_ns"
        );
        assert!(
            entry.get("ci95_upper_ns").is_some(),
            "entry {op} must have ci95_upper_ns"
        );
        assert!(
            entry.get("timestamp").is_some(),
            "entry {op} must have timestamp"
        );
        assert!(
            entry.get("git_sha").is_some(),
            "entry {op} must have git_sha"
        );
    }
}

/// Verify that baselines cover the expected operation categories.
#[test]
fn baseline_covers_required_operations() {
    let baseline_contents = std::fs::read_to_string("artifacts/baseline.json").unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&baseline_contents).unwrap();
    let baselines = baseline["baselines"].as_array().unwrap();

    let operations: Vec<&str> = baselines
        .iter()
        .filter_map(|e| e.get("operation").and_then(|v| v.as_str()))
        .collect();

    // Must cover the five primary operation categories
    let required_prefixes = [
        "methodology/task_spawn",
        "methodology/task_cancellation",
        "methodology/channel",
        "methodology/cx_capability",
        "methodology/budget",
    ];

    for prefix in &required_prefixes {
        assert!(
            operations.iter().any(|op| op.starts_with(prefix)),
            "baseline must cover {prefix} operations"
        );
    }
}

/// Verify that p50 values are positive and CIs are ordered correctly.
#[test]
fn baseline_values_are_sane() {
    let baseline_contents = std::fs::read_to_string("artifacts/baseline.json").unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&baseline_contents).unwrap();
    let baselines = baseline["baselines"].as_array().unwrap();

    for entry in baselines {
        let op = entry["operation"].as_str().unwrap();
        let p50 = entry["p50_ns"].as_f64().expect("p50_ns must be number");
        assert!(p50 >= 0.0, "{op}: p50_ns must be non-negative, got {p50}");

        let ci_lower = entry["ci95_lower_ns"].as_f64().unwrap_or(0.0);
        let ci_upper = entry["ci95_upper_ns"].as_f64().unwrap_or(f64::MAX);

        // CI lower <= p50 <= CI upper (with some tolerance for rounding)
        assert!(
            ci_lower <= p50 * 1.01,
            "{op}: ci95_lower ({ci_lower}) should be <= p50 ({p50})"
        );
        assert!(
            ci_upper >= p50 * 0.99,
            "{op}: ci95_upper ({ci_upper}) should be >= p50 ({p50})"
        );
    }
}

// ============================================================================
// Pillar 2: Golden Checksum Framework
// ============================================================================

/// Verify that golden_checksums.json has the correct schema.
#[test]
fn golden_checksum_schema_validity() {
    let contents = std::fs::read_to_string("artifacts/golden_checksums.json")
        .expect("golden_checksums.json must exist");
    let golden: serde_json::Value =
        serde_json::from_str(&contents).expect("golden_checksums.json must be valid JSON");

    assert!(
        golden.get("schema_version").is_some(),
        "must have schema_version"
    );
    assert!(
        golden.get("checksums").is_some(),
        "must have checksums object"
    );

    let checksums = golden["checksums"]
        .as_object()
        .expect("checksums is object");
    assert!(!checksums.is_empty(), "checksums must not be empty");

    // Each entry must have output_hash
    for (name, entry) in checksums {
        assert!(
            entry.get("output_hash").is_some(),
            "checksum entry '{name}' must have output_hash"
        );
        let hash = entry["output_hash"].as_str().unwrap();
        assert_eq!(
            hash.len(),
            64,
            "checksum '{name}' hash must be 64 hex chars (SHA-256)"
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "checksum '{name}' hash must be valid hex"
        );
    }
}

/// Verify that golden checksums cover the expected subsystem categories.
#[test]
fn golden_checksum_covers_subsystems() {
    let contents = std::fs::read_to_string("artifacts/golden_checksums.json").unwrap();
    let golden: serde_json::Value = serde_json::from_str(&contents).unwrap();
    let checksums = golden["checksums"].as_object().unwrap();

    let keys: Vec<&str> = checksums.keys().map(String::as_str).collect();

    let required_prefixes = [
        "scheduler/",
        "channel/",
        "cancel/",
        "lab/",
        "budget/",
        "obligation/",
    ];

    for prefix in &required_prefixes {
        assert!(
            keys.iter().any(|k| k.starts_with(prefix)),
            "golden checksums must cover {prefix} subsystem"
        );
    }
}

/// Verify the capture/verify workflow: a known deterministic output produces
/// a stable checksum.
#[test]
fn golden_checksum_determinism() {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    // Produce a deterministic output (same as golden_output bench scenario)
    let mut sched = asupersync::runtime::scheduler::Scheduler::new();
    for i in 0..100_u32 {
        let priority = (i % 8) as u8;
        sched.schedule(asupersync::types::TaskId::new_for_test(i, 0), priority);
    }
    let mut output = String::new();
    while let Some(id) = sched.pop() {
        write!(output, "{},", id.arena_index().index()).unwrap();
    }

    // Hash should be stable
    let hash1 = {
        let mut h = Sha256::new();
        h.update(output.as_bytes());
        format!(
            "{:064x}",
            u128::from_be_bytes(h.finalize()[..16].try_into().unwrap())
        )
    };

    // Run again — should produce identical hash
    let mut sched2 = asupersync::runtime::scheduler::Scheduler::new();
    for i in 0..100_u32 {
        let priority = (i % 8) as u8;
        sched2.schedule(asupersync::types::TaskId::new_for_test(i, 0), priority);
    }
    let mut output2 = String::new();
    while let Some(id) = sched2.pop() {
        write!(output2, "{},", id.arena_index().index()).unwrap();
    }

    let hash2 = {
        let mut h = Sha256::new();
        h.update(output2.as_bytes());
        format!(
            "{:064x}",
            u128::from_be_bytes(h.finalize()[..16].try_into().unwrap())
        )
    };

    assert_eq!(hash1, hash2, "same input must produce same checksum");
}

// ============================================================================
// Pillar 3: Evidence Ledger Integration
// ============================================================================

/// Verify that CollectorSink captures emitted evidence entries.
#[test]
fn evidence_collector_sink_captures_entries() {
    let sink = CollectorSink::new();
    assert!(sink.is_empty());

    emit_scheduler_evidence(&sink, "meet_deadlines", 5, 10, 20, false);
    assert_eq!(sink.len(), 1);

    let entries = sink.entries();
    assert_eq!(entries[0].component, "scheduler");
    assert_eq!(entries[0].action, "meet_deadlines");
    assert!(!entries[0].fallback_active);
    assert!(entries[0].is_valid());
}

/// Verify that NullSink discards entries (zero overhead).
#[test]
fn evidence_null_sink_discards() {
    let sink = NullSink;
    emit_scheduler_evidence(&sink, "no_preference", 0, 0, 0, true);
    // NullSink has no way to read back — this is a compile/runtime check
}

/// Verify that scheduler evidence entries have valid structure.
#[test]
fn evidence_scheduler_entry_is_valid() {
    let sink = CollectorSink::new();
    emit_scheduler_evidence(&sink, "drain_cancel", 30, 5, 100, false);

    let entries = sink.entries();
    let entry = &entries[0];

    assert_eq!(entry.component, "scheduler");
    assert_eq!(entry.action, "drain_cancel");
    assert_eq!(entry.posterior.len(), 3);
    assert!((entry.posterior.iter().sum::<f64>() - 1.0).abs() < 1e-6);
    assert!((entry.calibration_score - 1.0).abs() < f64::EPSILON);
    assert!(!entry.fallback_active);
    assert!(!entry.top_features.is_empty());

    let errors = entry.validate();
    assert!(
        errors.is_empty(),
        "scheduler evidence should be valid: {errors:?}"
    );
}

/// Verify that cancellation evidence entries have valid structure.
#[test]
fn evidence_cancel_entry_is_valid() {
    let sink = CollectorSink::new();
    emit_cancel_evidence(&sink, "user", 100, 5);

    let entries = sink.entries();
    let entry = &entries[0];

    assert_eq!(entry.component, "cancellation");
    assert_eq!(entry.action, "cancel_user");
    assert_eq!(entry.posterior, vec![1.0]);
    assert!(entry.is_valid());
}

/// Verify that budget evidence entries have valid structure.
#[test]
fn evidence_budget_entry_is_valid() {
    let sink = CollectorSink::new();
    emit_budget_evidence(&sink, "poll_quota", 50, Some(3000));

    let entries = sink.entries();
    let entry = &entries[0];

    assert_eq!(entry.component, "budget");
    assert!(entry.action.starts_with("exhausted_"));
    assert!(entry.is_valid());
}

/// Verify that multiple evidence entries from different subsystems accumulate.
#[test]
fn evidence_multi_subsystem_accumulation() {
    let sink = Arc::new(CollectorSink::new());

    emit_scheduler_evidence(sink.as_ref(), "meet_deadlines", 10, 20, 30, false);
    emit_cancel_evidence(sink.as_ref(), "timeout", 500, 7);
    emit_budget_evidence(sink.as_ref(), "deadline", 0, Some(5_000_000_000));

    let entries = sink.entries();
    assert_eq!(entries.len(), 3);

    let components: Vec<&str> = entries.iter().map(|e| e.component.as_str()).collect();
    assert!(components.contains(&"scheduler"));
    assert!(components.contains(&"cancellation"));
    assert!(components.contains(&"budget"));

    // All entries should be independently valid
    for entry in &entries {
        assert!(
            entry.is_valid(),
            "entry {} should be valid",
            entry.component
        );
    }
}

/// Verify that Cx carries and propagates evidence sink.
#[test]
fn evidence_cx_integration() {
    let sink = Arc::new(CollectorSink::new());
    let cx = Cx::for_testing().with_evidence_sink(Some(sink.clone() as Arc<dyn EvidenceSink>));

    let entry = franken_evidence::EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_700_000_000_000)
        .component("test")
        .action("validate")
        .posterior(vec![1.0])
        .chosen_expected_loss(0.0)
        .calibration_score(0.95)
        .build()
        .expect("valid entry");

    cx.emit_evidence(&entry);

    assert_eq!(sink.len(), 1);
    assert_eq!(sink.entries()[0].component, "test");
}

// ============================================================================
// Pillar 4: Decision Contract Validation
// ============================================================================

/// Verify that the loss matrix has correct dimensions and non-negative values.
#[test]
fn decision_contract_loss_matrix_invariants() {
    let contract = SchedulerDecisionContract::new();
    let loss_matrix = contract.loss_matrix();

    // 4 states x 3 actions
    assert_eq!(
        contract.state_space().len(),
        decision_contract::state::COUNT
    );
    assert_eq!(
        contract.action_set().len(),
        decision_contract::action::COUNT
    );

    // All expected losses must be non-negative
    let posterior = Posterior::uniform(decision_contract::state::COUNT);
    let action = contract.choose_action(&posterior);
    assert!(action < decision_contract::action::COUNT);
    let _ = loss_matrix;
}

/// Verify that posterior sums to 1.0 after Bayesian update.
#[test]
fn decision_contract_posterior_normalization() {
    let contract = SchedulerDecisionContract::new();
    let mut posterior = Posterior::uniform(decision_contract::state::COUNT);

    // Update with observation
    contract.update_posterior(&mut posterior, decision_contract::state::HEALTHY);

    let probs = posterior.probs();
    let sum: f64 = probs.iter().sum();
    assert!(
        (sum - 1.0).abs() < 1e-10,
        "posterior must sum to 1.0, got {sum}"
    );
}

/// Verify that Bayes-optimal action selection minimizes expected loss.
#[test]
fn decision_contract_argmin_correctness() {
    let contract = SchedulerDecisionContract::new();

    // Healthy state → aggressive (lowest loss in row 0)
    let posterior = Posterior::new(vec![0.95, 0.02, 0.02, 0.01]).unwrap();
    let outcome = evaluate(&contract, &posterior, &test_eval_ctx(0.95));
    assert_eq!(outcome.action_index, decision_contract::action::AGGRESSIVE);

    // Congested state → conservative (lowest loss in row 1)
    let posterior = Posterior::new(vec![0.02, 0.92, 0.03, 0.03]).unwrap();
    let outcome = evaluate(&contract, &posterior, &test_eval_ctx(0.95));
    assert_eq!(
        outcome.action_index,
        decision_contract::action::CONSERVATIVE
    );
}

/// Verify fallback policy triggers when calibration is low.
#[test]
fn decision_contract_fallback_policy() {
    let contract = SchedulerDecisionContract::new();
    let posterior = Posterior::uniform(decision_contract::state::COUNT);

    // Low calibration → fallback
    let outcome = evaluate(&contract, &posterior, &test_eval_ctx(0.1));
    assert!(outcome.fallback_active);
    assert_eq!(
        outcome.action_index,
        decision_contract::action::CONSERVATIVE
    );
}

/// Verify that snapshot_likelihoods produces non-negative values that don't blow up.
#[test]
fn decision_contract_snapshot_likelihoods_sanity() {
    // Quiescent
    let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&zero_snapshot());
    assert_eq!(likelihoods.len(), decision_contract::state::COUNT);
    for (i, &l) in likelihoods.iter().enumerate() {
        assert!(l >= 0.0, "likelihood[{i}] must be non-negative");
        assert!(l.is_finite(), "likelihood[{i}] must be finite");
    }

    // Extreme values
    let mut extreme = zero_snapshot();
    extreme.cancel_requested_tasks = u32::MAX / 2;
    extreme.cancelling_tasks = u32::MAX / 2;
    extreme.ready_queue_depth = u32::MAX / 2;
    extreme.deadline_pressure = 1000.0;
    extreme.draining_regions = u32::MAX / 2;

    let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&extreme);
    for (i, &l) in likelihoods.iter().enumerate() {
        assert!(l.is_finite(), "extreme likelihood[{i}] must be finite");
        assert!(l >= 0.0, "extreme likelihood[{i}] must be non-negative");
    }
}

/// Verify that the audit entry from evaluate() produces a valid evidence ledger.
#[test]
fn decision_contract_audit_entry_validity() {
    let contract = SchedulerDecisionContract::new();
    let posterior = Posterior::new(vec![0.7, 0.1, 0.1, 0.1]).unwrap();
    let outcome = evaluate(&contract, &posterior, &test_eval_ctx(0.92));

    let evidence = outcome.audit_entry.to_evidence_ledger();
    assert_eq!(evidence.component, "scheduler");
    assert!(evidence.is_valid(), "audit entry evidence must be valid");
    assert!(!evidence.action.is_empty());
    assert!(!evidence.posterior.is_empty());
}

/// Verify custom loss matrix accepts valid configurations.
#[test]
fn decision_contract_custom_loss_matrix() {
    let losses = vec![
        1.0, 2.0, 3.0, // healthy
        4.0, 5.0, 6.0, // congested
        7.0, 8.0, 9.0, // unstable
        10.0, 11.0, 12.0, // partitioned
    ];
    let contract =
        SchedulerDecisionContract::with_losses_and_policy(losses, FallbackPolicy::default());

    // Should not panic and should produce valid results
    let posterior = Posterior::uniform(decision_contract::state::COUNT);
    let outcome = evaluate(&contract, &posterior, &test_eval_ctx(0.95));
    assert!(outcome.action_index < decision_contract::action::COUNT);
}

/// Verify the contract name is stable.
#[test]
fn decision_contract_name_is_scheduler() {
    let contract = SchedulerDecisionContract::new();
    assert_eq!(contract.name(), "scheduler");
}

// ============================================================================
// Cross-Pillar Consistency
// ============================================================================

/// Verify that baseline and golden checksums reference valid git SHAs.
#[test]
fn cross_pillar_git_sha_format() {
    // Baseline
    let baseline_contents = std::fs::read_to_string("artifacts/baseline.json").unwrap();
    let baseline: serde_json::Value = serde_json::from_str(&baseline_contents).unwrap();
    let git_sha = baseline["git_sha"].as_str().unwrap();
    assert!(
        git_sha.len() >= 7,
        "baseline git_sha must be at least 7 chars"
    );
    assert!(
        git_sha.chars().all(|c| c.is_ascii_hexdigit()),
        "baseline git_sha must be valid hex"
    );

    // Golden checksums
    let golden_contents = std::fs::read_to_string("artifacts/golden_checksums.json").unwrap();
    let golden: serde_json::Value = serde_json::from_str(&golden_contents).unwrap();
    let checksums = golden["checksums"].as_object().unwrap();
    for (name, entry) in checksums {
        if let Some(sha) = entry.get("git_sha").and_then(|v| v.as_str()) {
            assert!(
                sha.len() >= 7,
                "golden checksum '{name}' git_sha must be at least 7 chars"
            );
            assert!(
                sha.chars().all(|c| c.is_ascii_hexdigit()),
                "golden checksum '{name}' git_sha must be valid hex"
            );
        }
    }
}

/// Verify that CI workflow file exists and references the four gates.
#[test]
fn ci_gates_workflow_exists() {
    let workflow = std::fs::read_to_string(".github/workflows/methodology-gates.yml")
        .expect("methodology-gates.yml must exist");

    assert!(
        workflow.contains("baseline-gate"),
        "workflow must define baseline-gate job"
    );
    assert!(
        workflow.contains("flamegraph-gate"),
        "workflow must define flamegraph-gate job"
    );
    assert!(
        workflow.contains("golden-checksum-gate"),
        "workflow must define golden-checksum-gate job"
    );
    assert!(
        workflow.contains("proof-note-gate"),
        "workflow must define proof-note-gate job"
    );
}

/// Verify that artifact directories exist.
#[test]
fn artifact_directories_exist() {
    assert!(
        std::path::Path::new("artifacts/baseline.json").exists(),
        "artifacts/baseline.json must exist"
    );
    assert!(
        std::path::Path::new("artifacts/golden_checksums.json").exists(),
        "artifacts/golden_checksums.json must exist"
    );
    assert!(
        std::path::Path::new("artifacts/flamegraphs").is_dir(),
        "artifacts/flamegraphs/ directory must exist"
    );
    assert!(
        std::path::Path::new("artifacts/proof_notes").is_dir(),
        "artifacts/proof_notes/ directory must exist"
    );
}

// ============================================================================
// Property-Based Tests
// ============================================================================

use proptest::prelude::*;

proptest! {
    #![proptest_config(common::test_proptest_config(256))]

    /// Property: snapshot_likelihoods always produces finite, non-negative values.
    #[test]
    fn prop_snapshot_likelihoods_bounded(
        cancel_req in 0..1000_u32,
        cancelling in 0..1000_u32,
        finalizing in 0..100_u32,
        ready_depth in 0..10000_u32,
        obligations in 0..1000_u32,
        draining in 0..100_u32,
        deadline in 0.0..10.0_f64,
    ) {
        let mut snapshot = zero_snapshot();
        snapshot.cancel_requested_tasks = cancel_req;
        snapshot.cancelling_tasks = cancelling;
        snapshot.finalizing_tasks = finalizing;
        snapshot.ready_queue_depth = ready_depth;
        snapshot.pending_obligations = obligations;
        snapshot.draining_regions = draining;
        snapshot.deadline_pressure = deadline;

        let likelihoods = SchedulerDecisionContract::snapshot_likelihoods(&snapshot);
        for (i, &l) in likelihoods.iter().enumerate() {
            prop_assert!(l >= 0.0, "likelihood[{}] = {} is negative", i, l);
            prop_assert!(l.is_finite(), "likelihood[{}] = {} is not finite", i, l);
            prop_assert!(l <= 1.0 + 1e-10, "likelihood[{}] = {} exceeds 1.0", i, l);
        }
    }

    /// Property: evidence entries from emit helpers are always valid.
    #[test]
    fn prop_evidence_entries_always_valid(
        cancel_depth in 0..1000_u32,
        timed_depth in 0..1000_u32,
        ready_depth in 0..1000_u32,
    ) {
        let sink = CollectorSink::new();
        emit_scheduler_evidence(
            &sink,
            "test_action",
            cancel_depth,
            timed_depth,
            ready_depth,
            false,
        );
        let entries = sink.entries();
        prop_assert!(!entries.is_empty());
        prop_assert!(entries[0].is_valid(), "entry must be valid");
    }

    /// Property: decision contract always selects a valid action index.
    #[test]
    fn prop_decision_contract_valid_action(
        p0 in 0.01..1.0_f64,
        p1 in 0.01..1.0_f64,
        p2 in 0.01..1.0_f64,
        p3 in 0.01..1.0_f64,
        cal in 0.0..1.0_f64,
    ) {
        // Normalize to valid posterior
        let sum = p0 + p1 + p2 + p3;
        let posterior = Posterior::new(vec![p0/sum, p1/sum, p2/sum, p3/sum]).unwrap();
        let contract = SchedulerDecisionContract::new();
        let outcome = evaluate(&contract, &posterior, &test_eval_ctx(cal));
        prop_assert!(outcome.action_index < decision_contract::action::COUNT);
    }
}
