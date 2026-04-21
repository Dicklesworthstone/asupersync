#![allow(clippy::all)]
//! Phase/oracle assertion macros for E2E tests.

/// Execute a named phase within an E2E test, logging entry and exit.
#[macro_export]
macro_rules! e2e_phase {
    ($harness:expr, $phase:expr, $body:expr) => {{
        $harness.phase($phase);
        let __result = $body;
        tracing::debug!(
            test = %$harness.name,
            phase = %$phase,
            "phase complete: {}",
            $phase
        );
        __result
    }};
}

/// Assert all oracles are clean (no violations).
#[macro_export]
macro_rules! e2e_assert_oracle_clean {
    ($harness:expr) => {
        $harness.verify_all_oracles();
    };
}

/// Log the repro command for the current test.
#[macro_export]
macro_rules! e2e_repro {
    ($harness:expr) => {
        $harness.log_repro_command();
    };
}

/// Run a test body across multiple seeds for determinism verification.
#[macro_export]
macro_rules! e2e_multi_seed {
    ($test_fn:expr, $seeds:expr) => {
        for &seed in $seeds {
            $test_fn(seed);
        }
    };
}
