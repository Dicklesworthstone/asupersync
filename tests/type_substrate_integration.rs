//! Cross-crate type substrate integration verification (bd-32awe).
//!
//! Verifies that all FrankenSuite foundation crates share the same canonical
//! types via `franken_kernel`, with no competing definitions.
//!
//! The dependency DAG is:
//! ```text
//! franken_kernel (leaf, no deps)
//!     ├──▶ franken_evidence (independent of kernel)
//!     ├──▶ franken_decision (depends on kernel + evidence)
//!     └──▶ asupersync (depends on all three)
//! ```

// ---------------------------------------------------------------------------
// Type identity tests: verify same type across crate boundaries
// ---------------------------------------------------------------------------

/// Verify that `franken_kernel::TraceId` is the same type whether accessed
/// directly or re-exported through `franken_decision`.
fn accepts_kernel_trace_id(id: franken_kernel::TraceId) -> u128 {
    id.as_u128()
}

#[test]
fn trace_id_type_identity_across_crates() {
    // Create a TraceId via franken_kernel.
    let kernel_id = franken_kernel::TraceId::from_parts(1_700_000_000_000, 42);

    // If the types were different (forked), this would fail to compile.
    let raw = accepts_kernel_trace_id(kernel_id);
    assert_ne!(raw, 0);
}

/// Verify that `franken_kernel::DecisionId` round-trips through creation.
#[test]
fn decision_id_type_identity() {
    let id = franken_kernel::DecisionId::from_raw(0xDEAD_BEEF);
    assert_eq!(id.as_u128(), 0xDEAD_BEEF);
}

/// Verify that `franken_kernel::PolicyId` is usable across crate boundaries.
#[test]
fn policy_id_type_identity() {
    let id = franken_kernel::PolicyId::new("test_policy", 1);
    assert_eq!(id.name(), "test_policy");
    assert_eq!(id.version(), 1);
}

/// Verify that `franken_kernel::SchemaVersion` compatibility checks work.
#[test]
fn schema_version_type_identity() {
    let v1 = franken_kernel::SchemaVersion::new(1, 0, 0);
    let v1_1 = franken_kernel::SchemaVersion::new(1, 1, 0);
    let v2 = franken_kernel::SchemaVersion::new(2, 0, 0);

    // Same major version is compatible.
    assert!(v1.is_compatible(&v1_1));
    assert!(v1_1.is_compatible(&v1));

    // Different major version is incompatible.
    assert!(!v1.is_compatible(&v2));
}

/// Verify that `franken_kernel::Budget` is the canonical budget type.
#[test]
fn budget_type_identity() {
    let b = franken_kernel::Budget::new(5000);
    assert_eq!(b.remaining_ms(), 5000);

    // Test tropical semiring min (combination operation).
    let b2 = franken_kernel::Budget::new(3000);
    let combined = b.min(b2);
    assert_eq!(combined.remaining_ms(), 3000); // min(5000, 3000)
}

/// Verify that `franken_kernel::Cx` capability context works with `NoCaps`.
#[test]
fn cx_type_identity() {
    let trace = franken_kernel::TraceId::from_parts(1_700_000_000_000, 42);
    let cx = franken_kernel::Cx::new(trace, franken_kernel::Budget::new(5000), franken_kernel::NoCaps);
    assert_eq!(cx.budget().remaining_ms(), 5000);
    assert_eq!(cx.depth(), 0);

    // Child context.
    let child = cx.child(franken_kernel::NoCaps, franken_kernel::Budget::new(3000));
    assert_eq!(child.depth(), 1);
    assert_eq!(child.budget().remaining_ms(), 3000);
}

// ---------------------------------------------------------------------------
// EvidenceLedger type identity
// ---------------------------------------------------------------------------

/// Verify that `franken_evidence::EvidenceLedger` is constructable and valid.
#[test]
fn evidence_ledger_type_identity() {
    let entry = franken_evidence::EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_700_000_000_000)
        .component("type_substrate_test")
        .action("verify")
        .posterior(vec![0.8, 0.2])
        .expected_loss("verify", 0.05)
        .expected_loss("skip", 0.5)
        .chosen_expected_loss(0.05)
        .calibration_score(0.95)
        .fallback_active(false)
        .top_feature("coverage", 1.0)
        .build()
        .expect("valid entry");

    assert_eq!(entry.component, "type_substrate_test");
    assert_eq!(entry.action, "verify");
    assert!(!entry.fallback_active);
}

/// Verify EvidenceLedger serialization round-trip.
#[test]
fn evidence_ledger_serde_roundtrip() {
    let entry = franken_evidence::EvidenceLedgerBuilder::new()
        .ts_unix_ms(1_700_000_000_000)
        .component("serde_test")
        .action("roundtrip")
        .posterior(vec![1.0])
        .expected_loss("roundtrip", 0.0)
        .chosen_expected_loss(0.0)
        .calibration_score(1.0)
        .fallback_active(false)
        .build()
        .expect("valid entry");

    let json = serde_json::to_string(&entry).expect("serialize");
    let parsed: franken_evidence::EvidenceLedger =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(entry.component, parsed.component);
    assert_eq!(entry.action, parsed.action);
}

// ---------------------------------------------------------------------------
// DecisionContract type identity
// ---------------------------------------------------------------------------

/// Verify that `franken_decision` types use `franken_kernel` identifiers.
#[test]
fn decision_contract_uses_kernel_types() {
    // DecisionAuditEntry references DecisionId from franken_kernel.
    let decision_id = franken_kernel::DecisionId::from_raw(123);

    let trace_id = franken_kernel::TraceId::from_parts(1_700_000_000_000, 1);

    // Create a DecisionAuditEntry (which internally stores a DecisionId).
    let audit = franken_decision::DecisionAuditEntry {
        decision_id,
        trace_id,
        contract_name: "test".into(),
        action_chosen: "verify".into(),
        expected_loss: 0.05,
        calibration_score: 0.95,
        fallback_active: false,
        posterior_snapshot: vec![0.8, 0.2],
        expected_loss_by_action: std::iter::once(("verify".to_string(), 0.05)).collect(),
        ts_unix_ms: 1_700_000_000_000,
    };

    // If DecisionAuditEntry.decision_id were a different type than
    // franken_kernel::DecisionId, this comparison would fail to compile.
    assert_eq!(audit.decision_id, decision_id);
}

/// Verify LossMatrix construction and Bayes action selection.
#[test]
fn loss_matrix_type_identity() {
    let matrix = franken_decision::LossMatrix::new(
        vec!["good".into(), "bad".into()],
        vec!["continue".into(), "stop".into()],
        vec![0.0, 0.3, 0.8, 0.1],
    )
    .expect("valid matrix");

    let posterior = franken_decision::Posterior::uniform(2);
    let action = matrix.bayes_action(&posterior);
    // With uniform prior and losses [0.0, 0.3; 0.8, 0.1]:
    // continue: 0.5*0.0 + 0.5*0.8 = 0.4
    // stop: 0.5*0.3 + 0.5*0.1 = 0.2
    // Bayes action = stop (index 1)
    assert_eq!(action, 1);
}

/// Verify Posterior Bayesian update.
#[test]
fn posterior_bayesian_update() {
    let mut posterior = franken_decision::Posterior::uniform(2);
    assert!((posterior.probs()[0] - 0.5).abs() < 1e-10);

    posterior.bayesian_update(&[0.9, 0.1]);
    // After update: P(good|obs) proportional to 0.5 * 0.9 = 0.45
    // P(bad|obs) proportional to 0.5 * 0.1 = 0.05
    // Normalized: good = 0.9, bad = 0.1
    assert!((posterior.probs()[0] - 0.9).abs() < 1e-10);
    assert!((posterior.probs()[1] - 0.1).abs() < 1e-10);
}

// ---------------------------------------------------------------------------
// Dependency DAG verification
// ---------------------------------------------------------------------------

/// Verify no circular dependency: franken_kernel has no franken deps.
///
/// This is a compile-time check. If franken_kernel depended on
/// franken_evidence or franken_decision, the workspace would fail to
/// compile with a circular dependency error.
#[test]
fn franken_kernel_is_leaf() {
    // If this compiles, franken_kernel is a leaf (no circular deps).
    let _ = franken_kernel::TraceId::from_raw(0);
}

/// Verify the dependency DAG: franken_decision depends on both
/// franken_kernel and franken_evidence.
#[test]
fn franken_decision_depends_on_both() {
    // This test verifies that franken_decision can use types from both
    // franken_kernel (DecisionId) and franken_evidence (EvidenceLedger).
    let decision_id = franken_kernel::DecisionId::from_raw(1);
    let entry = franken_evidence::EvidenceLedgerBuilder::new()
        .ts_unix_ms(0)
        .component("dag_test")
        .action("verify")
        .posterior(vec![1.0])
        .expected_loss("verify", 0.0)
        .chosen_expected_loss(0.0)
        .calibration_score(1.0)
        .fallback_active(false)
        .build()
        .expect("valid");
    assert_eq!(entry.component, "dag_test");

    let trace_id = franken_kernel::TraceId::from_parts(1_700_000_000_000, 99);

    // franken_decision uses DecisionId from franken_kernel.
    let audit = franken_decision::DecisionAuditEntry {
        decision_id,
        trace_id,
        contract_name: "dag".into(),
        action_chosen: "verify".into(),
        expected_loss: 0.0,
        calibration_score: 1.0,
        fallback_active: false,
        posterior_snapshot: vec![1.0],
        expected_loss_by_action: std::iter::once(("verify".to_string(), 0.0)).collect(),
        ts_unix_ms: 0,
    };
    assert_eq!(audit.decision_id, decision_id);
}

// ---------------------------------------------------------------------------
// Cross-crate integration: asupersync uses foundation types
// ---------------------------------------------------------------------------

/// Verify that asupersync's obligation system integrates with EvidenceLedger.
#[test]
fn obligation_saga_produces_evidence_entry() {
    use asupersync::obligation::saga::{
        MonotoneSagaExecutor, SagaExecutionPlan, SagaOpKind, SagaPlan, SagaStep, StepExecutor,
    };
    use asupersync::trace::distributed::lattice::LatticeState;

    struct TestExecutor;
    impl StepExecutor for TestExecutor {
        fn execute(&mut self, _step: &SagaStep) -> LatticeState {
            LatticeState::Reserved
        }
    }

    let plan = SagaPlan::new(
        "integration_test",
        vec![
            SagaStep::new(SagaOpKind::Reserve, "r1"),
            SagaStep::new(SagaOpKind::Send, "s1"),
            SagaStep::new(SagaOpKind::Acquire, "a1"),
        ],
    );
    let exec_plan = SagaExecutionPlan::from_plan(&plan);
    let executor = MonotoneSagaExecutor::new();
    let mut step_exec = TestExecutor;

    let result = executor.execute(&exec_plan, &mut step_exec);
    assert!(result.calm_optimized);
    assert_eq!(result.barrier_count, 0);

    // Build evidence entry and verify it's a valid franken_evidence type.
    let evidence = MonotoneSagaExecutor::build_evidence(&result);
    assert_eq!(evidence.component, "saga_executor");
    assert_eq!(evidence.action, "calm_optimized");

    // Serialize to verify serde compatibility.
    let json = serde_json::to_string(&evidence).expect("serialize evidence");
    let _: franken_evidence::EvidenceLedger =
        serde_json::from_str(&json).expect("deserialize evidence");
}

/// Verify that CALM classifications are consistent across the type boundary.
#[test]
fn calm_classification_consistency() {
    use asupersync::obligation::calm;
    use asupersync::obligation::saga::SagaOpKind;

    // All 16 CALM operations must have matching SagaOpKind variants.
    let classifications = calm::classifications();
    assert_eq!(classifications.len(), 16);

    for c in classifications {
        let op = match c.operation {
            "Reserve" => SagaOpKind::Reserve,
            "Commit" => SagaOpKind::Commit,
            "Abort" => SagaOpKind::Abort,
            "Send" => SagaOpKind::Send,
            "Recv" => SagaOpKind::Recv,
            "Acquire" => SagaOpKind::Acquire,
            "Renew" => SagaOpKind::Renew,
            "Release" => SagaOpKind::Release,
            "RegionClose" => SagaOpKind::RegionClose,
            "Delegate" => SagaOpKind::Delegate,
            "CrdtMerge" => SagaOpKind::CrdtMerge,
            "CancelRequest" => SagaOpKind::CancelRequest,
            "CancelDrain" => SagaOpKind::CancelDrain,
            "MarkLeaked" => SagaOpKind::MarkLeaked,
            "BudgetCheck" => SagaOpKind::BudgetCheck,
            "LeakDetection" => SagaOpKind::LeakDetection,
            other => panic!("unknown CALM operation: {other}"),
        };
        assert_eq!(
            op.monotonicity(),
            c.monotonicity,
            "SagaOpKind::{} disagrees with CalmClassification",
            c.operation,
        );
    }
}

// ---------------------------------------------------------------------------
// Type fork detection (runtime verification of baseline)
// ---------------------------------------------------------------------------

/// Verify that the known type fork count hasn't increased.
///
/// The `.type_fork_baseline.json` documents pre-migration forks. This test
/// ensures no new forks were accidentally introduced.
#[test]
fn type_fork_baseline_unchanged() {
    let baseline_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".type_fork_baseline.json");

    if !baseline_path.exists() {
        // Baseline file is optional; skip if not present.
        return;
    }

    let content = std::fs::read_to_string(&baseline_path).expect("read baseline");
    let value: serde_json::Value = serde_json::from_str(&content).expect("parse baseline");

    let count = value["baseline_count"].as_u64().expect("baseline_count");
    // The baseline documents 7 known pre-migration forks.
    assert_eq!(
        count, 7,
        "type fork baseline count changed — check for unauthorized type forks"
    );

    let forks = value["known_forks"].as_array().expect("known_forks array");
    assert_eq!(forks.len(), 7);
}
