//! br-asupersync-4cxzhk: enforcement test that `ExplorationBudgetConfig`'s
//! `target_coverage` is an ACTIVE control, not an inert footgun.
//!
//! The audited defect (SnowyFortress): the conformal bound was the quantile of
//! BINARY {0.0, 1.0} novelty scores, so `conformal_upper_bound` was always
//! exactly 0.0 or 1.0 and `target_met = bound <= (1 - target_coverage)` reduced
//! to `bound == 0.0` — completely independent of the configured
//! `target_coverage`. `estimate_*(.. 0.5)` and `(.. 0.9999)` produced identical
//! decisions. WildSpire's fix (c6657b068) replaced the binary quantile with a
//! finite-sample Hoeffding upper bound on the novelty proportion.
//!
//! These tests run against the public API (so they compile the library in
//! non-test mode and are immune to unrelated `#[cfg(test)]` breakage elsewhere
//! in the crate) and lock in three properties: the bound is granular (not the
//! degenerate 0/1), `target_coverage` flips the decision on IDENTICAL data, and
//! an under-calibrated sample still fails closed.

use asupersync::lab::{ExplorationBudget, ExplorationBudgetConfig};

/// Same observations + same `alpha`, two different `target_coverage` values must
/// now produce DIFFERENT decisions. Pre-fix they were identical.
#[test]
fn target_coverage_changes_decision_on_identical_data() {
    // 100 runs, 5 discoveries, alpha = 0.1.
    // Hoeffding bound = 5/100 + sqrt(ln(1/0.1) / (2*100)) ≈ 0.05 + 0.107 ≈ 0.157.
    let lenient =
        ExplorationBudget::estimate_from_counts(100, 5, ExplorationBudgetConfig::new(0.1, 0.80));
    let strict =
        ExplorationBudget::estimate_from_counts(100, 5, ExplorationBudgetConfig::new(0.1, 0.95));

    // The bound depends only on the data + alpha, so it is identical for both —
    // and crucially it is GRANULAR, not the old degenerate 0.0/1.0 binary value.
    assert!(
        (lenient.conformal_upper_bound - strict.conformal_upper_bound).abs() < f64::EPSILON,
        "bound must depend on data+alpha only, got {} vs {}",
        lenient.conformal_upper_bound,
        strict.conformal_upper_bound
    );
    assert!(
        lenient.conformal_upper_bound > 0.1 && lenient.conformal_upper_bound < 0.3,
        "bound must be granular (not the degenerate 0/1), got {}",
        lenient.conformal_upper_bound
    );

    // target_residual_rate = 1 - target_coverage: 0.20 (lenient) vs 0.05 (strict).
    // bound ≈ 0.157 ⇒ met under 0.80 coverage, NOT met under 0.95 coverage.
    assert!(
        lenient.target_met,
        "target_coverage=0.80 (residual 0.20) should be met by bound {}",
        lenient.conformal_upper_bound
    );
    assert!(
        !strict.target_met,
        "target_coverage=0.95 (residual 0.05) should NOT be met by bound {}",
        strict.conformal_upper_bound
    );

    // The recommendation follows the (now meaningful) decision.
    assert_eq!(
        lenient.recommended_additional_runs, 0,
        "a met target needs no additional runs"
    );
    assert!(
        strict.recommended_additional_runs > 0,
        "an unmet target must recommend additional runs"
    );
}

/// Sweeping `target_coverage` upward must be monotone: once a coverage level is
/// unmet, every stricter level is also unmet (the threshold only tightens).
#[test]
fn stricter_coverage_is_never_easier_to_meet() {
    let data = (100usize, 5usize);
    let mut prev_met = true;
    for coverage in [0.50, 0.70, 0.80, 0.90, 0.95, 0.99] {
        let est = ExplorationBudget::estimate_from_counts(
            data.0,
            data.1,
            ExplorationBudgetConfig::new(0.1, coverage),
        );
        if !prev_met {
            assert!(
                !est.target_met,
                "coverage {coverage} met despite a looser level already failing"
            );
        }
        prev_met = est.target_met;
    }
}

/// Below `min_samples` the bound is 1.0 and the target is never met — the
/// estimator fails closed instead of certifying convergence on thin evidence.
#[test]
fn under_calibrated_sample_fails_closed() {
    // Default min_samples is 20; 5 observations is under-calibrated.
    let est =
        ExplorationBudget::estimate_from_counts(5, 0, ExplorationBudgetConfig::new(0.1, 0.95));
    assert!(
        (est.conformal_upper_bound - 1.0).abs() < f64::EPSILON,
        "under-calibrated bound must be 1.0, got {}",
        est.conformal_upper_bound
    );
    assert!(
        !est.target_met,
        "an under-calibrated estimate must not certify the coverage target"
    );
}
