//! Contract tests for the fuzz target compile gate workflow.

#![allow(missing_docs)]

const FUZZ_WORKFLOW: &str = include_str!("../.github/workflows/fuzz.yml");

#[test]
fn fuzz_workflow_has_push_and_pull_request_compile_gate_triggers() {
    for required in [
        "push:",
        "pull_request:",
        "branches: [main]",
        "      - 'src/**'",
        "      - 'fuzz/Cargo.toml'",
        "      - 'fuzz/fuzz_targets/**'",
        "      - '.github/workflows/fuzz.yml'",
    ] {
        assert!(
            FUZZ_WORKFLOW.contains(required),
            "fuzz workflow must contain trigger token: {required}"
        );
    }
}

#[test]
fn fuzz_build_gate_compiles_round_six_targets_through_rch_executor() {
    for required in [
        "fuzz-build-gate:",
        "name: Fuzz target compile gate",
        "FUZZ_BUILD_GATE_TARGETS: >-",
        "BASE_TARGET_DIR=\"${TMPDIR:-/tmp}/rch_target_fuzz_build_gate_${GITHUB_RUN_ID:-local}\"",
        "for fuzz_target in ${FUZZ_BUILD_GATE_TARGETS}; do",
        "if [[ \"${RCH_EXECUTOR_MODE:-remote}\" == \"remote\" ]]; then",
        "RCH_REQUIRE_REMOTE=1 \"$RCH_BIN\" exec -- env \\",
        "\"$RCH_BIN\" exec -- env \\",
        "CARGO_INCREMENTAL=0 \\",
        "CARGO_PROFILE_DEV_DEBUG=0 \\",
        "CARGO_TARGET_DIR=\"${target_dir}\" \\",
        "cargo check --manifest-path fuzz/Cargo.toml --bin \"${fuzz_target}\"",
    ] {
        assert!(
            FUZZ_WORKFLOW.contains(required),
            "fuzz build gate must contain: {required}"
        );
    }
    assert!(
        !FUZZ_WORKFLOW.contains("cargo check --manifest-path fuzz/Cargo.toml --bins"),
        "full all-bin fuzz gate is known-red and must not be wired as CI-blocking yet"
    );
}

#[test]
fn fuzz_build_gate_declares_executor_mode_and_logs_context() {
    for required in [
        "a cargo executor is required for fuzz-target builds",
        "mode=\"remote\"",
        "mode=\"ci-fallback\"",
        "./scripts/rch_ci_fallback.sh",
        "RCH_EXECUTOR_MODE=$mode",
        "::group::Fuzz build gate context",
        "UTC start:",
        "event:",
        "sha:",
        "base target dir:",
        "targets:",
        "executor:",
        "executor mode:",
        "target dir:",
        "rustc -Vv",
        "cargo -V",
        "::group::RCH fuzz build gate: ${fuzz_target}",
    ] {
        assert!(
            FUZZ_WORKFLOW.contains(required),
            "fuzz build gate must preserve diagnostic token: {required}"
        );
    }
}

#[test]
fn expensive_fuzz_matrix_remains_schedule_or_manual_only() {
    for required in [
        "needs: fuzz-build-gate",
        "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
        "summary:",
        "if: always() && (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
    ] {
        assert!(
            FUZZ_WORKFLOW.contains(required),
            "fuzz matrix boundary must contain: {required}"
        );
    }
}

#[test]
fn repaired_round_six_targets_are_in_scheduled_fuzz_matrix() {
    for target in [
        "raptorq_decoder_gauss_matrix",
        "fuzz_distributed_recovery_decode",
        "mutex_poison_persistence",
    ] {
        let occurrences = FUZZ_WORKFLOW.matches(target).count();
        assert!(
            occurrences >= 2,
            "round-six target {target} must be available for manual dispatch and scheduled matrix"
        );
    }
}
