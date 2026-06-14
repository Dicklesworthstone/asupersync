//! br-asupersync-7tcipb (item 2): enforcement test that `LabConfig::with_oracles`
//! / `LabConfig::selected_oracles()` is a REAL filtering control, not a
//! parsed-and-ignored phantom.
//!
//! Before the fix, `FilteredOracleReport` only consulted the *scenario's*
//! oracle list and never the config selection, so building a `LabRuntime` from
//! `LabConfig::new(seed).with_oracles(&["task_leak"])` had no observable effect:
//! the builder advertised oracle filtering it never performed. These tests run a
//! real `LabRuntime` and assert that `FilteredOracleReport::for_lab_config`
//! narrows the reported oracle set to exactly the configured selection.

use asupersync::lab::{FilteredOracleReport, LabConfig, LabRuntime};

/// An empty selection (the default — no operator narrowing) must leave the full
/// oracle report intact. This is the regression guard: wiring the config knob
/// in must NOT change behavior when the operator did not select a subset.
#[test]
fn empty_selection_reports_every_oracle() {
    let mut runtime = LabRuntime::new(LabConfig::new(42));
    runtime.run_until_quiescent();
    let report = runtime.report();
    let full_len = report.oracle_report.entries.len();
    assert!(
        full_len > 1,
        "expected the lab to report multiple oracles, got {full_len}"
    );

    let filtered = FilteredOracleReport::for_lab_config(report.oracle_report, runtime.config());
    assert_eq!(
        filtered.checked.len(),
        full_len,
        "an empty with_oracles() selection must not narrow the report"
    );
    assert_eq!(filtered.entries.len(), full_len);
}

/// A non-empty `with_oracles` selection must narrow the report to exactly the
/// selected oracle(s). This is the core enforcement: pre-fix this selection was
/// inert and the report still contained every oracle.
#[test]
fn with_oracles_narrows_report_to_selection() {
    // Discover the oracles a bare run reports, so the test does not hard-code an
    // assumption about the registry contents beyond "more than one is reported".
    let mut probe = LabRuntime::new(LabConfig::new(7));
    probe.run_until_quiescent();
    let probe_report = probe.report();
    let all_names: Vec<String> = probe_report
        .oracle_report
        .entries
        .iter()
        .map(|e| e.invariant.clone())
        .collect();
    assert!(
        all_names.len() >= 2,
        "need >=2 reported oracles to prove narrowing, got {all_names:?}"
    );

    // Every reported entry comes from a reportable oracle, so its name is a
    // valid `with_oracles` selection.
    let chosen = all_names[0].clone();
    let config = LabConfig::new(7)
        .with_oracles(&[chosen.as_str()])
        .expect("a reported oracle name is a valid with_oracles() selection");

    let mut runtime = LabRuntime::new(config);
    runtime.run_until_quiescent();
    let report = runtime.report();
    let filtered = FilteredOracleReport::for_lab_config(report.oracle_report, runtime.config());

    assert_eq!(
        filtered.checked,
        vec![chosen.clone()],
        "with_oracles() must narrow the report to exactly the selected oracle"
    );
    assert_eq!(filtered.entries.len(), 1);
    assert!(
        filtered.checked.len() < all_names.len(),
        "selection must be a strict subset of the {} reported oracles",
        all_names.len()
    );
}

/// Selecting `"all"` is equivalent to no selection: the full report is returned.
#[test]
fn select_all_reports_every_oracle() {
    let mut baseline = LabRuntime::new(LabConfig::new(99));
    baseline.run_until_quiescent();
    let baseline_report = baseline.report();
    let full_len = baseline_report.oracle_report.entries.len();
    assert!(full_len > 1, "expected multiple oracles, got {full_len}");

    let config = LabConfig::new(99)
        .with_oracles(&["all"])
        .expect("\"all\" is a valid selection");
    let mut runtime = LabRuntime::new(config);
    runtime.run_until_quiescent();
    let report = runtime.report();
    let filtered = FilteredOracleReport::for_lab_config(report.oracle_report, runtime.config());

    assert_eq!(
        filtered.checked.len(),
        full_len,
        "selecting \"all\" must not narrow the report"
    );
}
