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
//! Semantics follow the original embedded `methodology_baselines` gate:
//! `ASUPERSYNC_PHASE6_BASELINE` names the tracked registry (gate is a
//! no-op when unset), `ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT` must be exactly
//! `5`, and a tracked row fails only when its measured p50 exceeds
//! `max(p50 * 1.05, ci95_upper * 1.02, p50 + 0.6ns)`
//! (br-asupersync-87h3es). The extra terms exist because same-host ambient
//! noise (co-tenancy, frequency/power states, alignment) exceeds 5% on
//! few-ns rows — a 0.5ns absolute shift reads as +100% on a 0.5ns row —
//! and four same-host runs produced four disjoint failing sets under the
//! pure relative gate, including a red clean-HEAD control. Recorded CIs
//! encode the recording run's own volatility, so a candidate inside that
//! envelope is measurement noise; the absolute floor covers the sub-ns
//! class whose quick-mode CIs can collapse to `[p50, p50]` and encode no
//! volatility. Rows without a recorded `ci95_upper_ns` keep the other two
//! terms; rows with a malformed one fail closed. A prefix that matches
//! zero rows is an error, not a pass: a gated binary whose rows vanished
//! from the registry must fail closed, never silently skip.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

const PHASE6_BASELINE_ENV: &str = "ASUPERSYNC_PHASE6_BASELINE";
const PHASE6_THRESHOLD_ENV: &str = "ASUPERSYNC_PHASE6_MAX_REGRESSION_PCT";
const PHASE6_MAX_REGRESSION_PCT: f64 = 5.0;
/// Headroom multiplier applied to a row's recorded `ci95_upper_ns`
/// (br-asupersync-87h3es). The recorded CI bounds the *median estimate* of
/// the recording run; a fresh run's median estimate carries its own
/// estimation error on top, so a candidate a hair above the recorded upper
/// bound is still indistinguishable from noise. 2% keeps that allowance far
/// below the 5% relative threshold it complements.
const PHASE6_CI95_HEADROOM: f64 = 1.02;
/// Absolute noise floor in nanoseconds (br-asupersync-87h3es). Ambient
/// same-host effects (co-tenancy, frequency/power states, code alignment)
/// shift few-ns rows by ~0.5ns between runs regardless of the code under
/// test: the four-run dossier recorded +0.51ns on a 0.47ns row and +0.47ns
/// on a 1.42ns row from clean baselines, and a red clean-HEAD control. A
/// sub-floor delta can also be +100% relative, so the relative and ci95
/// checks alone misfire on this class; deltas at or below the floor are
/// never regressions. 0.6ns clears the observed ambient band while a
/// genuine ~1ns+ slowdown still fails.
const PHASE6_ABSOLUTE_NOISE_FLOOR_NS: f64 = 0.6;

#[derive(Deserialize)]
struct TrackedBaseline {
    schema_version: String,
    baselines: Vec<TrackedBaselineRow>,
}

#[derive(Deserialize)]
struct TrackedBaselineRow {
    operation: String,
    p50_ns: f64,
    /// Upper bound of the 95% confidence interval recorded with this row.
    /// When present, the gate fails only above
    /// `max(p50_ns * 1.05, ci95_upper_ns * PHASE6_CI95_HEADROOM)` — the
    /// recorded CI is the row's own measured volatility, so a candidate
    /// inside it is noise by the recording run's own evidence
    /// (br-asupersync-87h3es). Absent on legacy rows, which keep the pure
    /// relative gate.
    #[serde(default)]
    ci95_upper_ns: Option<f64>,
    /// Host-class tag of the run that recorded this row (`host:<hostname>`).
    /// The RCH fleet is heterogeneous (OVH dedicated vs Contabo VPS classes
    /// differ 30-70% on single-thread micro-cycles) and workers cannot be
    /// pinned, so a 5% gate is only meaningful like-to-like: tagged rows are
    /// compared ONLY when this process is executing on the same host class,
    /// and are loudly skipped otherwise. Untagged rows (the legacy
    /// `methodology/` set) compare unconditionally, preserving the original
    /// gate behavior until they are re-recorded with tags
    /// (br-asupersync-pjivey).
    #[serde(default)]
    environment: Option<String>,
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

/// The host-class tag of THIS process: `host:<hostname>`. The gate runs
/// inside the bench process on the executing worker, so the hostname is the
/// ground truth for like-to-like comparison — no operator input, no worker
/// lottery ambiguity.
fn current_environment() -> Result<String, String> {
    let output = std::process::Command::new("hostname")
        .output()
        .map_err(|error| format!("cannot resolve hostname for environment matching: {error}"))?;
    if !output.status.success() {
        return Err("hostname exited non-zero; cannot match tagged baseline rows".to_string());
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        return Err(
            "hostname returned empty output; cannot match tagged baseline rows".to_string(),
        );
    }
    Ok(format!("host:{name}"))
}

/// Computes the fail limit for one tracked row (br-asupersync-87h3es): a
/// measured p50 fails the gate only above
/// `max(p50 * 1.05, ci95_upper * PHASE6_CI95_HEADROOM, p50 + 0.6ns)`.
///
/// The three terms cover distinct noise classes: the relative threshold is
/// the actual regression policy; the recorded ci95 envelope covers rows
/// whose recording run measured wide volatility; the absolute floor covers
/// few-ns rows where ambient host effects move the measurement by ~0.5ns
/// even when the recording run's CI happened to be tight (a quick-mode CI
/// can collapse to `[p50, p50]` and encode no volatility at all).
///
/// A malformed `ci95_upper_ns` (non-finite, or below the recorded p50 —
/// which would silently *narrow* the gate) is an error, never a fallback:
/// a corrupted registry row must fail closed.
fn row_limit_ns(operation: &str, p50_ns: f64, ci95_upper_ns: Option<f64>) -> Result<f64, String> {
    let relative_limit_ns = p50_ns * (1.0 + PHASE6_MAX_REGRESSION_PCT / 100.0);
    let floor_limit_ns = p50_ns + PHASE6_ABSOLUTE_NOISE_FLOOR_NS;
    let base_limit_ns = relative_limit_ns.max(floor_limit_ns);
    match ci95_upper_ns {
        None => Ok(base_limit_ns),
        Some(upper) => {
            if !upper.is_finite() || upper < p50_ns {
                return Err(format!(
                    "tracked Phase 6 baseline operation {operation:?} has invalid ci95_upper_ns \
                     ({upper}; must be finite and >= p50_ns)"
                ));
            }
            Ok(base_limit_ns.max(upper * PHASE6_CI95_HEADROOM))
        }
    }
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
    let mut compared_rows = 0usize;
    let mut skipped_environments = BTreeSet::new();
    let mut current_env: Option<String> = None;
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
        if let Some(tag) = &row.environment {
            let current = match &current_env {
                Some(current) => current,
                None => {
                    current_env = Some(current_environment()?);
                    current_env.as_ref().expect("environment just resolved")
                }
            };
            if tag != current {
                println!(
                    "[PHASE6] row {:?} skipped: recorded on {tag}, this run is {current} \
                     (like-to-like only; see docs/perf_runbook.md)",
                    row.operation
                );
                skipped_environments.insert(tag.clone());
                continue;
            }
        }
        compared_rows += 1;
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

        let limit_ns = row_limit_ns(&row.operation, row.p50_ns, row.ci95_upper_ns)?;
        let delta_pct = (candidate_p50_ns / row.p50_ns - 1.0) * 100.0;
        if candidate_p50_ns > limit_ns {
            regressions.push(format!(
                "{}: {:.2} -> {:.2} (+{:.2}%, limit {:.2}ns = \
                 max(p50*1.05, ci95_upper*{PHASE6_CI95_HEADROOM}, \
                 p50+{PHASE6_ABSOLUTE_NOISE_FLOOR_NS}ns))",
                row.operation, row.p50_ns, candidate_p50_ns, delta_pct, limit_ns
            ));
        }
    }

    if owned_rows == 0 {
        return Err(format!(
            "tracked Phase 6 baseline contains no rows for prefix {prefix:?}; \
             a gated bench binary must own at least one tracked row"
        ));
    }
    if compared_rows == 0 {
        // Every owned row was recorded on a different host class. A skip is
        // not a pass: fail closed so a worker-lottery mismatch can never be
        // cited as gate evidence.
        return Err(format!(
            "environment mismatch: all {owned_rows} rows under prefix {prefix:?} were recorded \
             on {:?}, but this run executed on {:?}; rerun until the dispatch lands on the \
             recording host class, or re-record the rows for this class \
             (docs/perf_runbook.md)",
            skipped_environments.iter().cloned().collect::<Vec<_>>(),
            current_env.as_deref().unwrap_or("<unresolved>")
        ));
    }

    if regressions.is_empty() {
        let skipped = owned_rows - compared_rows;
        println!(
            "[PHASE6] p50 gate passed: {compared_rows} of {owned_rows} tracked rows compared at \
             max(5.00%, ci95 envelope) under prefix {prefix:?} ({skipped} skipped as \
             other-host-class); rows under other prefixes and untracked Criterion rows are \
             outside this gate."
        );
        Ok(())
    } else {
        Err(format!(
            "p50 regressions (beyond max(5.00%, ci95 envelope)):\n  - {}",
            regressions.join("\n  - ")
        ))
    }
}
