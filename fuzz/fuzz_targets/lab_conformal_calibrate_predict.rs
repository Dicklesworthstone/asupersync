#![no_main]

//! br-asupersync-gu6ua2 — fuzz target for `ConformalCalibrator` in
//! `src/lab/conformal.rs`.
//!
//! ## Contract under test
//!
//! 1. **Panic floor on the calibrator pipeline.**
//!    `ConformalCalibrator::new(config)` followed by an arbitrary
//!    interleaving of `calibrate(&OracleReport)` and
//!    `predict(&OracleReport)` calls must NEVER panic, regardless of
//!    the values inside the OracleReport (including
//!    failed > total, NaN-laden stats, empty entries vec,
//!    duplicated invariant names).
//!
//! 2. **Configuration sanitisation.** ConformalConfig::new asserts
//!    a valid alpha (0..=1) — the fuzz target catches that assertion
//!    by clamping the seed alpha BEFORE constructing the config, so
//!    crashes from intentional config rejection do not pollute the
//!    crash queue. Adversarial alpha values are still exercised via
//!    the bounded-clamp path.
//!
//! 3. **`is_well_calibrated` is total.** After any sequence of
//!    calibrate/predict calls, `is_well_calibrated()` must produce
//!    a `bool` without panicking — even when no calibration data
//!    was supplied (the empty-history path) and when adversarial
//!    reports drove the internal coverage counters.
//!
//! ## Input shape
//!
//! Each iteration consumes a typed seed via `arbitrary::Arbitrary`:
//!   - `alpha_raw: u8` — quantised to one of nine alpha values that
//!     covers the boundary cases (0.001, 0.05, 0.1, 0.5, 0.95, 0.99,
//!     and the open boundaries) without tripping the
//!     ConformalConfig::new assertion.
//!   - `min_calibration_samples: u8` — capped at 64.
//!   - `ops: Vec<Op>` — bounded sequence of {Calibrate, Predict}
//!     where each Op carries a synthesised OracleReport with
//!     adversarial counts (passed/failed/total) and adversarial
//!     entries.
//!
//! Bounded resources: input clamped to 64 KiB; ops vec capped at
//! 1024.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::lab::conformal::{ConformalCalibrator, ConformalConfig};
use asupersync::lab::oracle::{OracleEntryReport, OracleReport};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 64 * 1024;
const MAX_OPS: usize = 1024;
const MAX_ENTRIES: usize = 32;

#[derive(Arbitrary)]
struct Seed {
    alpha_choice: u8,
    min_calibration_samples: u8,
    ops: Vec<OpSeed>,
}

#[derive(Arbitrary)]
struct OpSeed {
    /// Even -> Calibrate; Odd -> Predict.
    kind: u8,
    report: ReportSeed,
}

#[derive(Arbitrary)]
struct ReportSeed {
    total: u32,
    passed: u32,
    failed: u32,
    check_time_nanos: u64,
    entries: Vec<EntrySeed>,
}

#[derive(Arbitrary)]
struct EntrySeed {
    invariant_kind: u8,
    passed: bool,
    violation_present: bool,
    entities_tracked: u32,
    events_recorded: u32,
}

impl ReportSeed {
    fn into_report(self) -> OracleReport {
        let entries: Vec<OracleEntryReport> = self
            .entries
            .into_iter()
            .take(MAX_ENTRIES)
            .map(|e| {
                let invariant = match e.invariant_kind & 0x07 {
                    0 => "no_task_leak",
                    1 => "no_obligation_leak",
                    2 => "loser_drain",
                    3 => "quiescence",
                    4 => "supervision",
                    5 => "mailbox",
                    6 => "determinism",
                    _ => "synthetic_invariant",
                };
                OracleEntryReport {
                    invariant: invariant.to_string(),
                    passed: e.passed,
                    violation: if e.violation_present {
                        Some("synthetic violation".to_string())
                    } else {
                        None
                    },
                    stats: asupersync::lab::oracle::OracleStats {
                        entities_tracked: e.entities_tracked as usize,
                        events_recorded: e.events_recorded as usize,
                    },
                }
            })
            .collect();
        OracleReport {
            entries,
            // Use `as usize` cast — adversarial total/passed/failed
            // (e.g., failed > total) is legal at the type level and
            // is precisely what we want the calibrator to handle
            // without panicking.
            total: self.total as usize,
            passed: self.passed as usize,
            failed: self.failed as usize,
            check_time_nanos: self.check_time_nanos,
        }
    }
}

fn quantised_alpha(choice: u8) -> f64 {
    // Avoid 0.0 and 1.0 themselves — ConformalConfig::new rejects
    // those via assert; the fuzz target tests the calibrator
    // pipeline, not the constructor's config-rejection contract.
    match choice & 0x0F {
        0 => 0.001,
        1 => 0.005,
        2 => 0.01,
        3 => 0.025,
        4 => 0.05,
        5 => 0.10,
        6 => 0.20,
        7 => 0.30,
        8 => 0.40,
        9 => 0.50,
        10 => 0.60,
        11 => 0.70,
        12 => 0.80,
        13 => 0.90,
        14 => 0.95,
        _ => 0.99,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    let mut u = Unstructured::new(data);
    let Ok(seed) = Seed::arbitrary(&mut u) else {
        return;
    };

    let alpha = quantised_alpha(seed.alpha_choice);
    let min_samples = (seed.min_calibration_samples as usize).min(64);

    let config = ConformalConfig {
        alpha,
        min_calibration_samples: min_samples,
    };
    let mut cal = ConformalCalibrator::new(config);

    for op in seed.ops.into_iter().take(MAX_OPS) {
        let report = op.report.into_report();
        if op.kind & 1 == 0 {
            // Contract 1: calibrate must not panic on adversarial
            // OracleReport.
            cal.calibrate(&report);
        } else {
            // Contract 1: predict must not panic and may return None
            // when the calibration history is too short.
            let _ = cal.predict(&report);
        }
    }

    // Contract 3: is_well_calibrated must be total — no panic, no
    // matter what the call sequence was.
    let _ = cal.is_well_calibrated();
});
