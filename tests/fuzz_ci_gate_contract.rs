//! Contract tests for the fuzz target compile gate workflow.

#![allow(missing_docs)]

const FUZZ_CARGO_TOML: &str = include_str!("../fuzz/Cargo.toml");
const FUZZ_WORKFLOW: &str = include_str!("../.github/workflows/fuzz.yml");
const DNS_LOOKUP_DECODER: &str = include_str!("../fuzz/fuzz_targets/dns_lookup_decoder.rs");

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
fn fuzz_build_gate_compiles_all_bins_through_rch_executor() {
    for required in [
        "fuzz-build-gate:",
        "name: Fuzz target compile gate",
        "target_dir=\"${TMPDIR:-/tmp}/rch_target_fuzz_build_gate_${GITHUB_RUN_ID:-local}_all_bins\"",
        "if [[ \"${RCH_EXECUTOR_MODE:-remote}\" == \"remote\" ]]; then",
        "RCH_REQUIRE_REMOTE=1 \"$RCH_BIN\" exec -- env \\",
        "\"$RCH_BIN\" exec -- env \\",
        "CARGO_INCREMENTAL=0 \\",
        "CARGO_PROFILE_DEV_DEBUG=0 \\",
        "CARGO_TARGET_DIR=\"${target_dir}\" \\",
        "cargo check --manifest-path fuzz/Cargo.toml --bins --keep-going",
    ] {
        assert!(
            FUZZ_WORKFLOW.contains(required),
            "fuzz build gate must contain: {required}"
        );
    }
    assert!(
        !FUZZ_WORKFLOW
            .contains("cargo check --manifest-path fuzz/Cargo.toml --bin \"${fuzz_target}\""),
        "fuzz compile gate must cover every registered bin, not a selected target loop"
    );
    assert!(
        !FUZZ_WORKFLOW.contains("FUZZ_BUILD_GATE_TARGETS"),
        "fuzz compile gate must not carry a curated target allowlist"
    );
}

#[test]
fn all_bins_gate_keeps_dns_lookup_decoder_registered() {
    for required in [
        "name = \"dns_lookup_decoder\"",
        "path = \"fuzz_targets/dns_lookup_decoder.rs\"",
    ] {
        assert!(
            FUZZ_CARGO_TOML.contains(required),
            "dns_lookup_decoder must stay registered as a fuzz binary: {required}"
        );
    }
    assert!(
        DNS_LOOKUP_DECODER.contains("#![no_main]"),
        "dns_lookup_decoder must keep the libFuzzer no_main entrypoint"
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
        "target dir:",
        "executor:",
        "executor mode:",
        "rustc -Vv",
        "cargo -V",
        "::group::RCH fuzz build gate: all bins",
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

#[test]
fn dns_message_decoder_is_not_a_nested_no_main_include() {
    let dns_message_decoder = include_str!("../fuzz/fuzz_targets/dns_message_decoder.rs");

    assert!(
        dns_message_decoder.contains("#![no_main]"),
        "dns_message_decoder must remain a standalone libFuzzer target"
    );
    assert!(
        !dns_message_decoder.contains("include!(\"dns_lookup_decoder.rs\")"),
        "dns_message_decoder must not include the lookup target with its own crate attributes"
    );
    assert!(
        dns_message_decoder.contains("parse_dns_response_for_fuzz")
            && dns_message_decoder.contains("decode_dns_name_for_fuzz"),
        "dns_message_decoder must drive the direct DNS parser fuzz seams"
    );
}
