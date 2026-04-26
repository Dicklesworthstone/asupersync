//! Meta-fuzz target for `FuzzHarness::run` (br-asupersync-ifb4n3).
//!
//! `FuzzHarness` is the public driver for asupersync's own fuzz campaigns:
//! it iterates a budgeted seed plan, runs a user-supplied test closure
//! against a `LabRuntime` per seed, and aggregates the per-seed outcome
//! into a `FuzzReport`. Two properties are intended invariants but lacked
//! a fuzz oracle prior to this target:
//!
//!   * **P1 panic-floor**: `run()` MUST NEVER propagate a panic from the
//!     test closure regardless of what the closure does (string panic,
//!     owned-String panic, non-string `panic_any` payload, panic after
//!     allocation, panic recovered by an inner `catch_unwind`).
//!   * **P2 progress-floor**: `run()` MUST return with
//!     `report.iterations == config.iterations` — the campaign must not
//!     short-circuit when individual seeds panic, and must not double-
//!     count seeds either.
//!
//! Output invariants the target also checks:
//!
//!   * `findings.len() ≤ iterations`
//!   * Every `FuzzFinding.seed` lies in `[base_seed, base_seed + iterations)`
//!     (with wraparound when the campaign straddles `u64::MAX`)
//!   * `FuzzFinding.entropy_seed` matches the configured value
//!   * `unique_certificates ≥ 1`
//!   * `to_regression_corpus` round-trip preserves `findings.len()`,
//!     `base_seed`, `entropy_seed`, and `iterations`
//!   * The campaign is **deterministic**: a second `harness.run` with
//!     the same config + same closure produces the same `iterations`
//!     and the same `finding_seeds()` Vec
//!
//! Out of scope (explicitly): closures that hang indefinitely. The bead
//! identifies this as a separate progress-floor gap; a fuzz target that
//! actually runs hang-prone closures would itself hang, so the
//! hang-protection property is left for a dedicated regression test
//! once a per-seed wall-clock timeout is added to `FuzzHarness`.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::lab::fuzz::{FuzzConfig, FuzzHarness};
use asupersync::lab::runtime::LabRuntime;
use libfuzzer_sys::fuzz_target;
use std::sync::Mutex;

/// Per-seed closure behaviour. Designed to exercise the catch_unwind
/// path inside `run_single` with the panic shapes the bead enumerates,
/// without actually hanging or aborting the fuzzer process.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Behaviour {
    /// Closure returns immediately. Baseline.
    Noop,
    /// `panic!("...static literal...")` — payload is `&'static str`.
    PanicStatic,
    /// `panic!("{}", String::from(...))` — payload is `String`.
    PanicString,
    /// `panic_any(u32)` — non-string `Box<dyn Any>` payload that the
    /// downcast inside `run_single` cannot extract.
    PanicAny,
    /// Allocate a small Vec, then return cleanly.
    AllocSmall,
    /// Allocate a small Vec, then panic — exercises stack-unwinding
    /// past a heap allocation.
    AllocAndPanic,
    /// Inner `catch_unwind` absorbs an inner panic; closure then
    /// returns cleanly. Verifies that nested catch_unwind doesn't
    /// pollute the outer harness's catch_unwind state.
    NestedCatchUnwind,
}

#[derive(Arbitrary, Debug)]
struct CampaignInput {
    base_seed: u64,
    entropy_seed: u64,
    /// Bounded to a small range to keep each fuzzer iteration fast.
    iterations_byte: u8,
    max_steps_word: u16,
    worker_count_byte: u8,
    minimize: bool,
    minimize_attempts_byte: u8,
    behaviours: Vec<Behaviour>,
}

fuzz_target!(|input: CampaignInput| {
    // Empty behaviour list would cause modulo-by-zero in dispatch.
    if input.behaviours.is_empty() {
        return;
    }
    // Bound the input size so a single fuzzer iteration stays well
    // under the libfuzzer per-input timeout. Each seed runs the
    // closure once, plus up to `minimize_attempts` extra times when
    // the seed produces a finding and minimization is enabled.
    if input.behaviours.len() > 32 {
        return;
    }

    // Bounded campaign budget. iterations ∈ [1, 16],
    // max_steps ∈ [100, 10_099], worker_count ∈ [1, 4],
    // minimize_attempts ∈ [1, 8]. Bounds keep per-input runtime small
    // while still exercising the multi-iteration aggregation logic.
    let iterations = ((input.iterations_byte as usize) % 16) + 1;
    let max_steps = ((input.max_steps_word as u64) % 10_000) + 100;
    let worker_count = ((input.worker_count_byte as usize) % 4) + 1;
    let minimize_attempts = ((input.minimize_attempts_byte as usize) % 8) + 1;

    let mut config = FuzzConfig::new(input.base_seed, iterations)
        .entropy_seed(input.entropy_seed)
        .max_steps(max_steps)
        .worker_count(worker_count)
        .minimize(input.minimize);
    config.minimize_attempts = minimize_attempts;

    // First run.
    let report = run_with_behaviours(&config, &input.behaviours);

    // ── P2 progress-floor ────────────────────────────────────────
    assert_eq!(
        report.iterations, iterations,
        "P2 progress-floor BROKEN: report.iterations ({}) != configured iterations ({})",
        report.iterations, iterations
    );

    // ── Output invariants ────────────────────────────────────────
    assert!(
        report.findings.len() <= iterations,
        "findings.len() ({}) > iterations ({})",
        report.findings.len(),
        iterations
    );

    let valid_range_end = input.base_seed.wrapping_add(iterations as u64);
    let wraps = valid_range_end < input.base_seed;
    for f in &report.findings {
        let in_range = if wraps {
            // Campaign straddles u64::MAX: valid seeds are
            // [base_seed, u64::MAX] ∪ [0, valid_range_end).
            f.seed >= input.base_seed || f.seed < valid_range_end
        } else {
            f.seed >= input.base_seed && f.seed < valid_range_end
        };
        assert!(
            in_range,
            "finding seed {} outside campaign range [{}, {}) wraps={}",
            f.seed, input.base_seed, valid_range_end, wraps
        );
        assert_eq!(
            f.entropy_seed, input.entropy_seed,
            "finding.entropy_seed drift: got {}, expected {}",
            f.entropy_seed, input.entropy_seed
        );
    }

    assert!(
        report.unique_certificates >= 1,
        "unique_certificates was 0 — at least one iteration ran so at least one cert was produced"
    );

    // Regression-corpus round-trip preserves headline counts.
    let corpus = report.to_regression_corpus(input.base_seed);
    assert_eq!(
        corpus.cases.len(),
        report.findings.len(),
        "regression corpus drift: cases ({}) != findings ({})",
        corpus.cases.len(),
        report.findings.len()
    );
    assert_eq!(corpus.base_seed, input.base_seed);
    assert_eq!(corpus.entropy_seed, input.entropy_seed);
    assert_eq!(corpus.iterations, iterations);
    assert_eq!(corpus.schema_version, 1);

    // Each regression case's replay_seed must equal either the
    // original seed (no minimization) or finding.minimized_seed.
    for case in &corpus.cases {
        let matching_finding = report
            .findings
            .iter()
            .find(|f| f.seed == case.seed)
            .expect("every regression case must correspond to a finding");
        let expected = matching_finding.minimized_seed.unwrap_or(matching_finding.seed);
        assert_eq!(
            case.replay_seed, expected,
            "regression case replay_seed {} doesn't match finding {} minimized_seed {:?}",
            case.replay_seed, matching_finding.seed, matching_finding.minimized_seed
        );
    }

    // ── Determinism re-run ───────────────────────────────────────
    // Same config, same behaviour sequence, same dispatch logic →
    // must produce the same iterations and the same set of finding
    // seeds. If this assertion fires, the harness has a hidden source
    // of nondeterminism (clock-derived state, ambient RNG, hash-seed
    // dependency).
    let report2 = run_with_behaviours(&config, &input.behaviours);
    assert_eq!(
        report.iterations, report2.iterations,
        "non-deterministic iterations: {} vs {}",
        report.iterations, report2.iterations
    );
    assert_eq!(
        report.finding_seeds(),
        report2.finding_seeds(),
        "non-deterministic finding seeds across two runs of the same config"
    );
    assert_eq!(
        report.unique_certificates, report2.unique_certificates,
        "non-deterministic unique_certificates: {} vs {}",
        report.unique_certificates, report2.unique_certificates
    );
});

/// Runs a `FuzzHarness::run` campaign with a closure that dispatches
/// behaviours cyclically by call index. The dispatch is deterministic
/// given (config, behaviours), even across multiple `run()` invocations,
/// because the call counter starts fresh per harness instance.
///
/// Wraps the call in `catch_unwind` to enforce P1 panic-floor: any
/// panic that escapes `harness.run` is itself an assertion failure
/// caught by libfuzzer, which is exactly the bug class this target
/// is meant to find.
fn run_with_behaviours(
    config: &FuzzConfig,
    behaviours: &[Behaviour],
) -> asupersync::lab::fuzz::FuzzReport {
    let harness = FuzzHarness::new(config.clone());
    let call_count = Mutex::new(0usize);
    let behaviours = behaviours.to_vec();

    let test = |_rt: &mut LabRuntime| {
        let idx = {
            let mut g = call_count.lock().unwrap_or_else(|e| e.into_inner());
            let v = *g;
            *g += 1;
            v
        };
        dispatch_behaviour(behaviours[idx % behaviours.len()]);
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.run(test)));
    match result {
        Ok(report) => report,
        Err(_) => panic!(
            "P1 panic-floor BROKEN: FuzzHarness::run propagated a panic from the test closure"
        ),
    }
}

fn dispatch_behaviour(b: Behaviour) {
    match b {
        Behaviour::Noop => {}
        Behaviour::PanicStatic => panic!("br-ifb4n3: static-str panic"),
        Behaviour::PanicString => {
            let owned = String::from("br-ifb4n3: owned-String panic");
            panic!("{owned}");
        }
        Behaviour::PanicAny => {
            // u32 payload — the run_single downcast tries &'static str
            // and String and falls back to the "<unknown panic payload>"
            // branch. Verifies that fallback is taken without panicking
            // the harness.
            std::panic::panic_any(0xDEAD_BEEFu32);
        }
        Behaviour::AllocSmall => {
            let v: Vec<u8> = vec![0; 1024];
            std::hint::black_box(v);
        }
        Behaviour::AllocAndPanic => {
            let v: Vec<u8> = vec![0; 1024];
            std::hint::black_box(&v);
            panic!("br-ifb4n3: post-alloc panic");
        }
        Behaviour::NestedCatchUnwind => {
            // Inner catch_unwind absorbs the inner panic; closure
            // returns Ok. The outer harness MUST observe a clean
            // completion (no recorded TestPanic finding for this
            // iteration).
            let _ = std::panic::catch_unwind(|| panic!("inner-absorbed"));
        }
    }
}
