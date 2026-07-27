//! Shared Phase 6 p50 baseline gate for criterion bench binaries
//! (br-asupersync-sched-hot-path-perf-bt4y5f.1).
//!
//! `artifacts/baseline.json` is the single tracked-row registry for every
//! Phase 6 gated bench target. Each bench binary owns a disjoint operation
//! prefix (`methodology/` for `methodology_baselines`, `sched/<group>/` for
//! the scheduler hot-path benches) and compares ONLY its own rows, so one
//! registry file can hold rows produced by several bench binaries without any
//! binary failing on estimates it did not measure. Rows are compared against
//! the criterion output of the run that just finished in this process, so the
//! gate result and the measurement come from the same remote environment.
//!
//! Semantics are identical to the original embedded `methodology_baselines`
//! gate: `ASUPERSYNC_PHASE6_BASELINE` names the tracked registry (gate is a
//! no-op when unset), `ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT` must be exactly
//! `5`, and any tracked p50 more than 5% slower fails the process. A prefix
//! that matches zero rows is an error, not a pass: a gated binary whose rows
//! vanished from the registry must fail closed, never silently skip.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const PHASE6_BASELINE_ENV: &str = "ASUPERSYNC_PHASE6_BASELINE";
const PHASE6_THRESHOLD_ENV: &str = "ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT";
const PHASE6_MAX_REGRESSION_PCT: f64 = 5.0;

#[derive(Deserialize)]
struct TrackedBaseline {
    schema_version: String,
    baselines: Vec<TrackedBaselineRow>,
}

#[derive(Deserialize)]
struct TrackedBaselineRow {
    operation: String,
    p50_ns: f64,
}

#[derive(Deserialize)]
struct CriterionEstimates {
    median: CriterionPointEstimate,
}

#[derive(Deserialize)]
struct CriterionPointEstimate {
    point_estimate: f64,
}

fn criterion_home() -> PathBuf {
    env::var_os("CRITERION_HOME").map_or_else(
        || {
            env::var_os("CARGO_TARGET_DIR").map_or_else(
                || PathBuf::from("target/criterion"),
                |target| PathBuf::from(target).join("criterion"),
            )
        },
        PathBuf::from,
    )
}

fn criterion_directory(operation: &str) -> Result<PathBuf, String> {
    if operation.matches('/').count() < 2 {
        return Err(format!(
            "tracked Phase 6 operation {operation:?} must contain a group and benchmark name"
        ));
    }
    // Criterion makes the group id filename-safe as one component. Gated
    // operations use a slash-bearing group id (`methodology/<group>` or
    // `sched/<group>`) followed by the function and optional value components,
    // so only the first slash becomes an underscore on disk.
    Ok(PathBuf::from(operation.replacen('/', "_", 1)))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {label} {}: {error}", path.display()))
}

/// Runs the Phase 6 p50 gate over the tracked rows owned by `prefix`.
///
/// Returns `Ok(())` when the gate env var is unset (gate not requested) or
/// when every owned row is within the regression threshold.
pub fn run_phase6_p50_gate(prefix: &str) -> Result<(), String> {
    let Some(baseline_path) = env::var_os(PHASE6_BASELINE_ENV) else {
        return Ok(());
    };

    let threshold = env::var(PHASE6_THRESHOLD_ENV)
        .map_err(|_| format!("{PHASE6_THRESHOLD_ENV} must be set to 5"))?
        .parse::<f64>()
        .map_err(|error| format!("{PHASE6_THRESHOLD_ENV} must be numeric: {error}"))?;
    if threshold.to_bits() != PHASE6_MAX_REGRESSION_PCT.to_bits() {
        return Err(format!(
            "{PHASE6_THRESHOLD_ENV} must be exactly {PHASE6_MAX_REGRESSION_PCT}, got {threshold}"
        ));
    }

    let baseline_path = PathBuf::from(baseline_path);
    let baseline: TrackedBaseline = read_json(&baseline_path, "tracked Phase 6 baseline")?;
    if baseline.schema_version != "1.0.0" {
        return Err(format!(
            "tracked Phase 6 baseline schema must be 1.0.0, got {:?}",
            baseline.schema_version
        ));
    }
    if baseline.baselines.is_empty() {
        return Err("tracked Phase 6 baseline contains no rows".to_string());
    }

    let criterion_home = criterion_home();
    let mut operations = BTreeSet::new();
    let mut owned_rows = 0usize;
    let mut regressions = Vec::new();

    for row in &baseline.baselines {
        if row.operation.is_empty() {
            return Err("tracked Phase 6 baseline contains an empty operation".to_string());
        }
        if !operations.insert(row.operation.as_str()) {
            return Err(format!(
                "tracked Phase 6 baseline contains duplicate operation {:?}",
                row.operation
            ));
        }
        if !row.operation.starts_with(prefix) {
            continue;
        }
        owned_rows += 1;
        if !row.p50_ns.is_finite() || row.p50_ns <= 0.0 {
            return Err(format!(
                "tracked Phase 6 baseline operation {:?} has invalid p50_ns",
                row.operation
            ));
        }

        let estimates_path = criterion_home
            .join(criterion_directory(&row.operation)?)
            .join("new/estimates.json");
        let estimates: CriterionEstimates =
            read_json(&estimates_path, "Phase 6 Criterion estimates")?;
        let candidate_p50_ns = estimates.median.point_estimate;
        if !candidate_p50_ns.is_finite() || candidate_p50_ns <= 0.0 {
            return Err(format!(
                "Phase 6 candidate operation {:?} has invalid median.point_estimate",
                row.operation
            ));
        }

        let delta_pct = (candidate_p50_ns / row.p50_ns - 1.0) * 100.0;
        if delta_pct > PHASE6_MAX_REGRESSION_PCT {
            regressions.push(format!(
                "{}: {:.2} -> {:.2} (+{:.2}%)",
                row.operation, row.p50_ns, candidate_p50_ns, delta_pct
            ));
        }
    }

    if owned_rows == 0 {
        return Err(format!(
            "tracked Phase 6 baseline contains no rows for prefix {prefix:?}; \
             a gated bench binary must own at least one tracked row"
        ));
    }

    if regressions.is_empty() {
        println!(
            "[PHASE6] p50 gate passed: {owned_rows} tracked rows compared at 5.00% under prefix \
             {prefix:?}; rows under other prefixes and untracked Criterion rows are outside this \
             gate."
        );
        Ok(())
    } else {
        Err(format!(
            "p50 regressions (>5.00%):\n  - {}",
            regressions.join("\n  - ")
        ))
    }
}
