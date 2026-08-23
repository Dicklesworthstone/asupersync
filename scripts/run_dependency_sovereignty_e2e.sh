#!/usr/bin/env bash
# Deterministic dependency-sovereignty E2E and forensic-evidence runner.
#
# The default smoke profile is local and contract-only: it validates the live
# VER A1 matrix and the runner's fail-closed outcome classifier. Cargo-backed
# scenarios are opt-in and always require remote RCH execution.

# The scenario dispatcher runs in a timeout-owned child Bash process. ShellCheck
# cannot see those indirect exported-function calls or that `jq -n` does not
# read the summary path it writes.
# shellcheck disable=SC2094,SC2317

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MATRIX="$PROJECT_ROOT/artifacts/dependency_verification_matrix_v1.json"
FAILURE_MATRIX="$PROJECT_ROOT/artifacts/dependency_failure_injection_matrix_v1.json"
REAL_SERVICE_FIXTURE_MATRIX="$PROJECT_ROOT/artifacts/dependency_real_service_fixture_matrix_v1.json"
FEATURE_PLATFORM_CONSUMER_MATRIX="$PROJECT_ROOT/artifacts/dependency_feature_platform_consumer_matrix_v1.json"
FINAL_SIGNOFF_MATRIX="$PROJECT_ROOT/artifacts/dependency_verification_final_signoff_v1.json"
REGISTRY="$PROJECT_ROOT/artifacts/dependency_capability_registry_v1.json"
DORMANT_INVENTORY="$PROJECT_ROOT/artifacts/dormant_e2e_inventory_v1.json"
DORMANT_FS_RUNNER="$PROJECT_ROOT/scripts/fs_parity_proof_runner.sh"
DORMANT_INT_RUNNER="$PROJECT_ROOT/scripts/cross_subsystem_recovery_proof_runner.sh"
DORMANT_DIST_RUNNER="$PROJECT_ROOT/scripts/distributed_hash_snapshot_recovery_proof_runner.sh"
SUITE_ID="dependency-sovereignty"
SUITE_SCENARIO_ID="E2E-SUITE-DEPENDENCY-SOVEREIGNTY"
BEAD_ID="asupersync-dep-p1-foundations-upksjk.6.2"
TRACK_ID="phase-1-verification"
EVIDENCE_OWNER="$BEAD_ID"
OUTPUT_ROOT="${DEPENDENCY_SOVEREIGNTY_OUTPUT_ROOT:-$PROJECT_ROOT/target/e2e-results/dependency-sovereignty}"
RUN_ID="${DEPENDENCY_SOVEREIGNTY_RUN_ID:-}"
SEED="${TEST_SEED:-0xDEADBEEF}"
STEP_TIMEOUT="${DEPENDENCY_SOVEREIGNTY_TIMEOUT:-${E2E_TIMEOUT:-900}}"
FAIL_FAST=0
DRY_RUN=0
LIST_ONLY=0
SELF_TEST_ONLY=0
SELECTED_SCENARIOS=()
CANARY="VER_A2_CANARY_SECRET_DO_NOT_RETAIN"
NKEY_SECRET_CANARY="NKEY-SECRET-CANARY-0123456789ABC"
NKEY_DOWNSTREAM_CANARY="NKEY-DOWNSTREAM-CANARY-012345678"
LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'USAGE'
usage: run_dependency_sovereignty_e2e.sh [options]

options:
  --list                       List stable scenario IDs.
  --scenario ID                Select one scenario; may be repeated.
  --run-id ID                  Use an explicit deterministic run label.
  --dry-run                    Emit inventory and replay artifacts without execution.
  --timeout SECONDS            Bound each selected scenario (default: 900).
  --fail-fast                  Stop execution after the first non-passing scenario.
  --continue-for-diagnostics   Keep running after failures (the default).
  --self-test                  Run only the 12-fixture shell classifier contract.
  --help                       Show this help.

Cargo-backed scenarios require:
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario failure-injection-contract
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario real-service-fixture-contract
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario feature-platform-consumer-contract
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario aggregate-signoff-contract
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario sqlite-parity-aggregate
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario api-adr-registry-contract
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario api-adr-phase3-signoff
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario atp_version_artifacts
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario lz4_trace_replay
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario lz4_cross_version_artifact
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario lz4_malformed_limits
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario offline-tuner-logging-parity
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario temp_artifacts
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh \
    --scenario dormant-e2e-aggregate-signoff

The dormant aggregate runs the maintained filesystem, cross-subsystem, and
distributed lanes once each. Every original DORMANT-* inventory ID is also a
stable alias that runs its owning lane and emits a checked disposition report.
USAGE
}

scenario_ids() {
    printf '%s\n' \
        catalog \
        runner-contract \
        registry-contract \
        baseline-contract \
        cutover-policy-contract \
        verification-matrix-contract \
        failure-injection-contract \
        real-service-fixture-contract \
        feature-platform-consumer-contract \
        aggregate-signoff-contract \
        sqlite-parity-aggregate \
        api-adr-registry-contract \
        api-adr-phase3-signoff \
        atp_version_artifacts \
        dep-sovereignty-asupersync_d24mms_11_d22341de8339 \
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8 \
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e \
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988 \
        lz4_trace_replay \
        lz4_cross_version_artifact \
        lz4_malformed_limits \
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd \
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d \
        offline-tuner-logging-parity \
        temp_artifacts \
        dormant-e2e-filesystem-recovery \
        dormant-e2e-cross-subsystem-recovery \
        dormant-e2e-distributed-recovery \
        dormant-e2e-aggregate-signoff
    jq -r '.test_inventory[].scenario_id' "$DORMANT_INVENTORY"
}

scenario_is_known() {
    case "$1" in
        catalog | runner-contract | registry-contract | baseline-contract | cutover-policy-contract | verification-matrix-contract | failure-injection-contract | real-service-fixture-contract | feature-platform-consumer-contract | aggregate-signoff-contract | sqlite-parity-aggregate | api-adr-registry-contract | api-adr-phase3-signoff | atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339 | dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8 | dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e | dep-sovereignty-asupersync_5z2scg_3_7_94b694387988 | lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits | dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd | dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d | offline-tuner-logging-parity | temp_artifacts | dormant-e2e-filesystem-recovery | dormant-e2e-cross-subsystem-recovery | dormant-e2e-distributed-recovery | dormant-e2e-aggregate-signoff)
            return 0
            ;;
        DORMANT-*)
            jq -e --arg id "$1" '.test_inventory | any(.scenario_id == $id)' \
                "$DORMANT_INVENTORY" >/dev/null
            ;;
        *)
            return 1
            ;;
    esac
}

scenario_is_cargo() {
    case "$1" in
        registry-contract | baseline-contract | cutover-policy-contract | verification-matrix-contract | failure-injection-contract | real-service-fixture-contract | feature-platform-consumer-contract | aggregate-signoff-contract | sqlite-parity-aggregate | api-adr-registry-contract | api-adr-phase3-signoff | atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339 | dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8 | dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e | dep-sovereignty-asupersync_5z2scg_3_7_94b694387988 | lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits | dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd | dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d | offline-tuner-logging-parity | temp_artifacts | dormant-e2e-filesystem-recovery | dormant-e2e-cross-subsystem-recovery | dormant-e2e-distributed-recovery | dormant-e2e-aggregate-signoff | DORMANT-*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

scenario_surface() {
    case "$1" in
        catalog) printf 'audit' ;;
        sqlite-parity-aggregate | atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339 | dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8 | dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e | dep-sovereignty-asupersync_5z2scg_3_7_94b694387988 | lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits | dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd | dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d | offline-tuner-logging-parity | temp_artifacts | dormant-e2e-* | DORMANT-*) printf 'e2e' ;;
        runner-contract | failure-injection-contract | real-service-fixture-contract | feature-platform-consumer-contract | aggregate-signoff-contract | api-adr-registry-contract | api-adr-phase3-signoff) printf 'contract' ;;
        *) printf 'integration' ;;
    esac
}

scenario_fixture() {
    case "$1" in
        catalog) printf 'artifacts/dependency_verification_matrix_v1.json' ;;
        runner-contract) printf 'fixture:ver-a2-outcome-taxonomy-v1' ;;
        registry-contract) printf 'tests/dependency_capability_registry_contract.rs' ;;
        baseline-contract) printf 'tests/dependency_capability_baseline_contract.rs' ;;
        cutover-policy-contract) printf 'tests/dependency_cutover_policy_contract.rs' ;;
        verification-matrix-contract) printf 'tests/dependency_verification_matrix_contract.rs' ;;
        failure-injection-contract) printf 'artifacts/dependency_failure_injection_matrix_v1.json' ;;
        real-service-fixture-contract) printf 'artifacts/dependency_real_service_fixture_matrix_v1.json' ;;
        feature-platform-consumer-contract) printf 'artifacts/dependency_feature_platform_consumer_matrix_v1.json' ;;
        aggregate-signoff-contract) printf 'artifacts/dependency_verification_final_signoff_v1.json' ;;
        sqlite-parity-aggregate) printf 'tests/fixtures/sqlite-parity-consumer/Cargo.toml' ;;
        api-adr-registry-contract) printf 'artifacts/dependency_api_adr_registry_v1.json' ;;
        api-adr-phase3-signoff) printf 'artifacts/dependency_api_adr_phase3_signoff_v1.json' ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339) printf 'tests/atp_cdc_deduplication.rs' ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8) printf 'artifacts/time_utc_rfc3339_foundation_v1.json' ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e) printf 'artifacts/typed_format_final_signoff_v1.json' ;;
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988) printf 'tests/fixtures/typed-format-historical-corpus/v0.3.9.json' ;;
        lz4_trace_replay | lz4_cross_version_artifact) printf 'tests/fixtures/lz4-trace-historical-corpus/v0.3.9.json' ;;
        lz4_malformed_limits) printf 'tests/lz4_trace_integration_e2e.rs' ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd) printf 'artifacts/lz4_final_signoff_v1.json' ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d) printf 'tests/fixtures/dependency-capability-baseline-consumer' ;;
        offline-tuner-logging-parity) printf 'tests/offline_tuner_env_logger_parity.rs' ;;
        temp_artifacts) printf 'tests/temp_artifact_lifecycle.rs' ;;
        dormant-e2e-* | DORMANT-*) printf 'artifacts/dormant_e2e_inventory_v1.json' ;;
    esac
}

scenario_profile() {
    case "$1" in
        catalog | runner-contract) printf 'contract-only' ;;
        feature-platform-consumer-contract) printf 'sparse-feature-platform-consumer' ;;
        aggregate-signoff-contract) printf 'aggregate-signoff' ;;
        sqlite-parity-aggregate) printf 'sqlite-dual-engine-current' ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339) printf 'atp-artifact-default' ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8) printf 'current-cli-owned-formatter-keep' ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e) printf 'typed-format-terminal-keep' ;;
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988) printf 'published-v0.3.9-current-cli' ;;
        lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits) printf 'lz4-owned-shadow' ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd) printf 'lz4-terminal-keep' ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d) printf 'nkey-owned-types-default' ;;
        offline-tuner-logging-parity) printf 'offline-tuner-cli-simd' ;;
        temp_artifacts) printf 'tempfile-default-sparse-combined-lifecycle' ;;
        dormant-e2e-filesystem-recovery | DORMANT-FS-*) printf 'dormant-filesystem-maintained' ;;
        dormant-e2e-cross-subsystem-recovery | DORMANT-INT-*) printf 'dormant-cross-subsystem-maintained' ;;
        dormant-e2e-distributed-recovery | DORMANT-DIST-*) printf 'dormant-distributed-maintained' ;;
        dormant-e2e-aggregate-signoff) printf 'dormant-e2e-aggregate' ;;
        *) printf 'nightly-default' ;;
    esac
}

scenario_capabilities() {
    case "$1" in
        catalog | runner-contract | verification-matrix-contract | failure-injection-contract | real-service-fixture-contract | aggregate-signoff-contract)
            printf '["CAP-REAL-SERVICE-E2E","CAP-VERIFICATION-PROFILES"]'
            ;;
        dormant-e2e-* | DORMANT-*)
            printf '["CAP-REAL-SERVICE-E2E","CAP-VERIFICATION-PROFILES"]'
            ;;
        sqlite-parity-aggregate)
            printf '["CAP-SQLITE","CAP-DOWNSTREAM-CONSUMERS","CAP-REAL-SERVICE-E2E"]'
            ;;
        feature-platform-consumer-contract)
            printf '["CAP-DOWNSTREAM-CONSUMERS","CAP-PUBLIC-API-TOPOLOGY","CAP-REAL-SERVICE-E2E","CAP-VERIFICATION-PROFILES"]'
            ;;
        registry-contract)
            printf '["CAP-DOWNSTREAM-CONSUMERS","CAP-PUBLIC-API-TOPOLOGY","CAP-VERIFICATION-PROFILES"]'
            ;;
        baseline-contract)
            printf '["CAP-DOWNSTREAM-CONSUMERS","CAP-REAL-SERVICE-E2E","CAP-VERIFICATION-PROFILES"]'
            ;;
        cutover-policy-contract)
            printf '["CAP-DEPENDENCY-LEDGER","CAP-REAL-SERVICE-E2E","CAP-VERIFICATION-PROFILES"]'
            ;;
        api-adr-registry-contract)
            printf '["CAP-OTLP-ECOSYSTEM","CAP-PUBLIC-API-TOPOLOGY"]'
            ;;
        api-adr-phase3-signoff)
            printf '["CAP-PUBLIC-API-TOPOLOGY","CAP-DEPENDENCY-LEDGER"]'
            ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339)
            printf '["CAP-ATP-VERSION-SCANNER"]'
            ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8)
            printf '["CAP-TIME-UTC-RFC3339"]'
            ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e | dep-sovereignty-asupersync_5z2scg_3_7_94b694387988)
            printf '["CAP-PERSISTED-TRACE-SNAPSHOT","CAP-SERDE-GENERIC"]'
            ;;
        lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits)
            printf '["CAP-TRACE-LZ4"]'
            ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd)
            printf '["CAP-TRACE-LZ4"]'
            ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d)
            printf '["CAP-NKEY-AUTH","CAP-DOWNSTREAM-CONSUMERS","CAP-PUBLIC-API-TOPOLOGY"]'
            ;;
        offline-tuner-logging-parity)
            printf '["CAP-CLI-OFFLINE-TUNER","CAP-DIAGNOSTICS","CAP-REAL-SERVICE-E2E"]'
            ;;
        temp_artifacts)
            printf '["CAP-TEMP-ARTIFACTS","CAP-VERIFICATION-PROFILES"]'
            ;;
    esac
}

scenario_features() {
    case "$1" in
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339)
            printf '["default"]'
            ;;
        sqlite-parity-aggregate)
            printf '["sqlite"]'
            ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8)
            printf '["cli"]'
            ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e | dep-sovereignty-asupersync_5z2scg_3_7_94b694387988)
            printf '["cli","default","test-internals","trace-compression"]'
            ;;
        lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits)
            printf '["cli","test-internals","trace-compression"]'
            ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd)
            printf '["cli","no-default-features","test-internals","trace-compression"]'
            ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d)
            printf '["default"]'
            ;;
        offline-tuner-logging-parity)
            printf '["cli","simd-intrinsics"]'
            ;;
        temp_artifacts)
            printf '["benchmark-adapters","cli","default","no-default-features","test-internals"]'
            ;;
        dormant-e2e-filesystem-recovery | DORMANT-FS-*)
            printf '["test-internals"]'
            ;;
        dormant-e2e-cross-subsystem-recovery | DORMANT-INT-*)
            printf '["cross-subsystem-recovery-e2e","no-default-features"]'
            ;;
        dormant-e2e-distributed-recovery | DORMANT-DIST-*)
            printf '["distributed-hash-snapshot-recovery-e2e","no-default-features"]'
            ;;
        dormant-e2e-aggregate-signoff)
            printf '["cross-subsystem-recovery-e2e","distributed-hash-snapshot-recovery-e2e","test-internals"]'
            ;;
        *)
            printf '[]'
            ;;
    esac
}

scenario_evidence_owner() {
    case "$1" in
        failure-injection-contract) printf 'asupersync-dep-p1-foundations-upksjk.6.4' ;;
        real-service-fixture-contract) printf 'asupersync-dep-p1-foundations-upksjk.6.3' ;;
        feature-platform-consumer-contract) printf 'asupersync-dep-p1-foundations-upksjk.6.5' ;;
        aggregate-signoff-contract) printf 'asupersync-dep-p1-foundations-upksjk.6.6' ;;
        sqlite-parity-aggregate) printf 'asupersync-ym2wtv.2.9' ;;
        api-adr-registry-contract) printf 'asupersync-dep-p3-api-adrs-h3jspm.3' ;;
        api-adr-phase3-signoff) printf 'asupersync-dep-p3-api-adrs-h3jspm.13' ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339) printf 'asupersync-d24mms.11' ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8) printf 'asupersync-d24mms.4' ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e) printf 'asupersync-5z2scg.3.5' ;;
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988) printf 'asupersync-5z2scg.3.7' ;;
        lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits) printf 'asupersync-0h6myr.4.4' ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd) printf 'asupersync-0h6myr.4.5' ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d) printf 'asupersync-dep-p4-nkeys-poc60v.1.3' ;;
        offline-tuner-logging-parity) printf 'asupersync-d24mms.3' ;;
        temp_artifacts) printf 'asupersync-d24mms.5' ;;
        dormant-e2e-filesystem-recovery | DORMANT-FS-*) printf 'asupersync-d24mms.12.2' ;;
        dormant-e2e-cross-subsystem-recovery | DORMANT-INT-*) printf 'asupersync-d24mms.12.3' ;;
        dormant-e2e-distributed-recovery | DORMANT-DIST-*) printf 'asupersync-d24mms.12.4' ;;
        dormant-e2e-aggregate-signoff) printf 'asupersync-d24mms.12.5' ;;
        *) printf '%s' "$EVIDENCE_OWNER" ;;
    esac
}

scenario_step_id() {
    case "$1" in
        failure-injection-contract) printf 'ver-a4-failure-injection-contract' ;;
        real-service-fixture-contract) printf 'ver-a3-real-service-fixture-contract' ;;
        feature-platform-consumer-contract) printf 'ver-a5-feature-platform-consumer-contract' ;;
        aggregate-signoff-contract) printf 'ver-a6-aggregate-signoff-contract' ;;
        sqlite-parity-aggregate) printf 'sqlite-p9-aggregate-dual-engine' ;;
        api-adr-registry-contract) printf 'adr-003-api-adr-registry-contract' ;;
        api-adr-phase3-signoff) printf 'adr-013-api-adr-phase3-signoff' ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339) printf 'd24mms-11-artifact-version-reassembly' ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8) printf 'd24mms-4-utc-cli-rfc3339' ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e) printf 'typed-formats-a5-terminal-keep-signoff' ;;
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988) printf 'typed-formats-a7-cross-version-e2e' ;;
        lz4_trace_replay) printf 'lz4-a4-trace-replay' ;;
        lz4_cross_version_artifact) printf 'lz4-a4-cross-version-artifact' ;;
        lz4_malformed_limits) printf 'lz4-a4-malformed-limits' ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd) printf 'lz4-a5-terminal-keep-signoff' ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d) printf 'nkey-n3-owned-type-redaction' ;;
        offline-tuner-logging-parity) printf 'd24mms-3-offline-tuner-logging-parity' ;;
        temp_artifacts) printf 'd24mms-5-temp-artifact-lifecycle' ;;
        dormant-e2e-* | DORMANT-*) printf 'd24mms-12-5-%s' "${1//./-}" ;;
        *) printf 'ver-a2-%s' "$1" ;;
    esac
}

scenario_command_display() {
    local scenario_id="$1"
    case "$scenario_id" in
        catalog)
            printf '%s' "jq -e <dependency-sovereignty catalog predicate> artifacts/dependency_verification_matrix_v1.json"
            ;;
        runner-contract)
            printf '%s' "bash scripts/run_dependency_sovereignty_e2e.sh --self-test"
            ;;
        registry-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_capability_registry_contract -- --nocapture"
            ;;
        baseline-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_capability_baseline_contract -- --nocapture"
            ;;
        cutover-policy-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_cutover_policy_contract -- --nocapture"
            ;;
        verification-matrix-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_verification_matrix_contract -- --nocapture"
            ;;
        failure-injection-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_failure_injection_matrix_contract -- --nocapture"
            ;;
        real-service-fixture-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_real_service_fixture_contract -- --nocapture"
            ;;
        feature-platform-consumer-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_feature_platform_consumer_matrix_contract -- --nocapture"
            ;;
        aggregate-signoff-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_verification_final_signoff_contract -- --nocapture"
            ;;
        sqlite-parity-aggregate)
            printf '%s' "env -u CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 RCH_BUILD_TIMEOUT_SEC=<scenario-timeout> RCH_TEST_TIMEOUT_SEC=<scenario-timeout> rch exec --base HEAD --clean-overlay --overlay-path tests/fixtures/sqlite-parity-consumer/src/main.rs -- env ASUPERSYNC_SOURCE_REVISION=<source-commit> SQLITE_PARITY_TARGET=x86_64-unknown-linux-gnu SQLITE_PARITY_HOST=linux-x86_64-rch-worker CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 3 --locked --manifest-path tests/fixtures/sqlite-parity-consumer/Cargo.toml --bin asupersync-sqlite-parity-consumer -- --nocapture --test-threads=1"
            ;;
        api-adr-registry-contract)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture"
            ;;
        api-adr-phase3-signoff)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --test dependency_api_adr_phase3_signoff_contract -- --nocapture"
            ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --lib --test atp_cdc_deduplication toolchain_version_detection -- --nocapture --test-threads=1"
            ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --features cli --test time_utc_rfc3339_foundation_contract dep_sovereignty_asupersync_d24mms_4_b6e90e93b1e8 -- --nocapture --test-threads=1"
            ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated>_generic cargo test --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml --locked -- --nocapture && RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated>_historical cargo test --manifest-path tests/fixtures/typed-format-cross-version-consumer/Cargo.toml --locked -- --nocapture && RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --features cli,test-internals,trace-compression --test typed_format_registry_contract --test runtime_snapshot_codec_e2e --test replay_e2e_suite --test typed_format_cross_version_e2e --test typed_format_final_signoff_contract -- --nocapture --test-threads=1"
            ;;
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated>_consumer cargo test --manifest-path tests/fixtures/typed-format-cross-version-consumer/Cargo.toml --locked -- --nocapture && RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --features cli,test-internals,trace-compression --test typed_format_cross_version_e2e -- --nocapture --test-threads=1"
            ;;
        lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --features cli,test-internals,trace-compression --test lz4_trace_integration_e2e $scenario_id -- --nocapture --test-threads=1"
            ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated>_sparse cargo check --quiet -p asupersync --no-default-features --features trace-compression && RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test --quiet -p asupersync --features cli,test-internals,trace-compression --test lz4_surface_artifact_inventory_contract --test lz4_owned_codec_corpus_contract --test lz4_trace_integration_e2e --test lz4_final_signoff_contract -- --nocapture --test-threads=1"
            ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --locked --lib ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d -- --nocapture --test-threads=1 && RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated>_consumer cargo test --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml --locked ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d__downstream_consumer -- --nocapture --test-threads=1"
            ;;
        offline-tuner-logging-parity)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path Cargo.toml --overlay-path Cargo.lock --overlay-path src/bin/offline_tuner.rs --overlay-path tests/offline_tuner_env_logger_parity.rs -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> cargo test -p asupersync --locked --features cli,simd-intrinsics --bin offline_tuner --test offline_tuner_env_logger_parity -- --nocapture --test-threads=1"
            ;;
        temp_artifacts)
            printf '%s' "RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path scripts/run_dependency_sovereignty_e2e.sh --overlay-path docs/dependency_capability_baseline.md --overlay-path src/atp/benchmark/suite.rs --overlay-path src/net/atp/transport_quic/mod.rs --overlay-path src/net/atp/transport_rq/mod.rs --overlay-path src/net/atp/transport_rq/transport_rq_tests.rs --overlay-path src/test_logging.rs --overlay-path tests/dependency_capability_baseline_contract.rs --overlay-path tests/e2e_log_quality_schema.rs --overlay-path tests/temp_artifact_lifecycle.rs -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR=<isolated> bash -lc '<default, sparse, combined tempfile graph checks plus focused lifecycle and production-consumer tests>'"
            ;;
        dormant-e2e-* | DORMANT-*)
            printf '%s' "RCH_REQUIRE_REMOTE=1 bash scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario $scenario_id"
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            if [[ -z "${2:-}" ]]; then
                printf 'missing scenario ID after --scenario\n' >&2
                exit 64
            fi
            SELECTED_SCENARIOS+=("$2")
            shift 2
            ;;
        --run-id)
            if [[ -z "${2:-}" ]]; then
                printf 'missing run ID after --run-id\n' >&2
                exit 64
            fi
            RUN_ID="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --timeout)
            if [[ -z "${2:-}" ]]; then
                printf 'missing timeout after --timeout\n' >&2
                exit 64
            fi
            STEP_TIMEOUT="$2"
            shift 2
            ;;
        --fail-fast)
            FAIL_FAST=1
            shift
            ;;
        --continue-for-diagnostics)
            FAIL_FAST=0
            shift
            ;;
        --self-test)
            SELF_TEST_ONLY=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            printf 'unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 64
            ;;
    esac
done

if [[ "$LIST_ONLY" -eq 1 ]]; then
    scenario_ids
    exit 0
fi

if [[ "$SELF_TEST_ONLY" -eq 1 ]]; then
    if [[ "${#SELECTED_SCENARIOS[@]}" -ne 0 ]]; then
        printf '%s\n' '--self-test cannot be combined with --scenario' >&2
        exit 64
    fi
    SELECTED_SCENARIOS=(runner-contract)
fi

if [[ "${#SELECTED_SCENARIOS[@]}" -eq 0 ]]; then
    SELECTED_SCENARIOS=(catalog runner-contract)
fi

for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
    if ! scenario_is_known "$scenario_id"; then
        printf 'unknown scenario: %s\n' "$scenario_id" >&2
        printf 'use --list for stable scenario IDs\n' >&2
        exit 64
    fi
done

REPRO_COMMAND="bash scripts/run_all_e2e.sh --suite dependency-sovereignty"
if [[ "${#SELECTED_SCENARIOS[@]}" -eq 1 ]]; then
    REPRO_COMMAND+=" --scenario ${SELECTED_SCENARIOS[0]}"
elif [[ "${#SELECTED_SCENARIOS[@]}" -ne 2 || "${SELECTED_SCENARIOS[0]}" != "catalog" || "${SELECTED_SCENARIOS[1]}" != "runner-contract" ]]; then
    REPRO_COMMAND="bash scripts/run_dependency_sovereignty_e2e.sh"
    for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
        REPRO_COMMAND+=" --scenario $scenario_id"
    done
fi
for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
    if scenario_is_cargo "$scenario_id"; then
        REPRO_COMMAND="RCH_REQUIRE_REMOTE=1 $REPRO_COMMAND"
        break
    fi
done

if [[ ! "$STEP_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    printf 'timeout must be a positive integer\n' >&2
    exit 64
fi

if [[ -z "$RUN_ID" ]]; then
    RUN_ID="run-$(date -u +%Y%m%dT%H%M%SZ)-$$"
fi
if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    printf 'invalid run ID: use only ASCII letters, digits, dot, underscore, and hyphen\n' >&2
    exit 64
fi

RUN_DIR="$OUTPUT_ROOT/$RUN_ID"
SUMMARY="$RUN_DIR/summary.json"
EVENTS="$RUN_DIR/events.ndjson"
SCENARIOS="$RUN_DIR/scenarios.ndjson"
VALIDATION_STAGES="$RUN_DIR/validation_stages.ndjson"
ARTIFACT_MANIFEST="$RUN_DIR/artifact_manifest.ndjson"
ENVIRONMENT="$RUN_DIR/environment.json"
REPRO_MANIFEST="$RUN_DIR/repro_manifest.json"
LATEST="$OUTPUT_ROOT/latest.json"
LATEST_SUCCESS="$OUTPUT_ROOT/latest_success.json"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SOURCE_REVISION="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
CONFIG_DIGEST=""
FAILURE_CONFIG_DIGEST=""
REAL_SERVICE_FIXTURE_CONFIG_DIGEST=""
FEATURE_PLATFORM_CONSUMER_CONFIG_DIGEST=""
FINAL_SIGNOFF_CONFIG_DIGEST=""
DORMANT_INVENTORY_DIGEST=""

if [[ -e "$RUN_DIR" ]]; then
    printf 'refusing to overwrite retained evidence directory: %s\n' "$RUN_DIR" >&2
    exit 73
fi
if [[ ! -f "$MATRIX" || ! -f "$FAILURE_MATRIX" || ! -f "$REAL_SERVICE_FIXTURE_MATRIX" || ! -f "$FEATURE_PLATFORM_CONSUMER_MATRIX" || ! -f "$FINAL_SIGNOFF_MATRIX" || ! -f "$REGISTRY" || ! -f "$DORMANT_INVENTORY" || ! -x "$DORMANT_FS_RUNNER" || ! -x "$DORMANT_INT_RUNNER" || ! -x "$DORMANT_DIST_RUNNER" ]]; then
    printf 'required dependency-sovereignty inputs are missing\n' >&2
    exit 66
fi

mkdir -p "$RUN_DIR"
: >"$EVENTS"
: >"$SCENARIOS"
: >"$VALIDATION_STAGES"
: >"$ARTIFACT_MANIFEST"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        printf 'SHA-256 unavailable\n' >&2
        return 69
    fi
}

monotonic_ms() {
    if [[ -r /proc/uptime ]]; then
        awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime
    else
        date +%s000
    fi
}

redact_stream() {
    sed -E \
        -e "s/${CANARY}/[REDACTED_CANARY]/g" \
        -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1[REDACTED]/g' \
        -e 's#([A-Za-z][A-Za-z0-9+.-]*://)[^/@:[:space:]]+:[^/@[:space:]]+@#\1[REDACTED_CREDENTIALS]@#g' \
        -e 's/(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*/\1 [REDACTED]/g' \
        -e 's/(NKEY_SEED=)S[A-Z0-9]+/\1[REDACTED]/g'
}

safe_version() {
    local command_name="$1"
    shift
    if command -v "$command_name" >/dev/null 2>&1; then
        "$command_name" "$@" 2>&1 | head -n 1
    else
        printf 'unavailable'
    fi
}

CONFIG_DIGEST="$(sha256_file "$MATRIX")"
FAILURE_CONFIG_DIGEST="$(sha256_file "$FAILURE_MATRIX")"
REAL_SERVICE_FIXTURE_CONFIG_DIGEST="$(sha256_file "$REAL_SERVICE_FIXTURE_MATRIX")"
FEATURE_PLATFORM_CONSUMER_CONFIG_DIGEST="$(sha256_file "$FEATURE_PLATFORM_CONSUMER_MATRIX")"
FINAL_SIGNOFF_CONFIG_DIGEST="$(sha256_file "$FINAL_SIGNOFF_MATRIX")"
DORMANT_INVENTORY_DIGEST="$(sha256_file "$DORMANT_INVENTORY")"
jq -n \
    --arg schema_version "dependency-sovereignty-environment-v1" \
    --arg run_id "$RUN_ID" \
    --arg suite_id "$SUITE_ID" \
    --arg bead_id "$BEAD_ID" \
    --arg track_id "$TRACK_ID" \
    --arg source_revision "$SOURCE_REVISION" \
    --arg target "$(rustc -vV 2>/dev/null | awk -F': ' '$1 == "host" {print $2}')" \
    --arg host "$(uname -srm)" \
    --arg rustc "$(safe_version rustc --version)" \
    --arg cargo "$(safe_version cargo --version)" \
    --arg jq "$(safe_version jq --version)" \
    --arg rch "$(safe_version rch --version)" \
    --arg test_seed "$SEED" \
    --arg step_timeout "$STEP_TIMEOUT" \
    --arg config_digest "$CONFIG_DIGEST" \
    --arg failure_config_digest "$FAILURE_CONFIG_DIGEST" \
    --arg real_service_fixture_config_digest "$REAL_SERVICE_FIXTURE_CONFIG_DIGEST" \
    --arg feature_platform_consumer_config_digest "$FEATURE_PLATFORM_CONSUMER_CONFIG_DIGEST" \
    --arg final_signoff_config_digest "$FINAL_SIGNOFF_CONFIG_DIGEST" \
    --arg dormant_inventory_digest "$DORMANT_INVENTORY_DIGEST" \
    --arg redaction_policy "metadata-and-secret-patterns-v1" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      suite_id: $suite_id,
      bead_id: $bead_id,
      track_id: $track_id,
      source_revision: $source_revision,
      target: $target,
      host: $host,
      tool_versions: {rustc: $rustc, cargo: $cargo, jq: $jq, rch: $rch},
      environment_allowlist: {
        TEST_SEED: $test_seed,
        DEPENDENCY_SOVEREIGNTY_TIMEOUT: $step_timeout,
        RCH_REQUIRE_REMOTE: (env.RCH_REQUIRE_REMOTE // "unset")
      },
      config_snapshot: {
        source: "artifacts/dependency_verification_matrix_v1.json",
        sha256: $config_digest,
        additional_sources: [
          {
            source: "artifacts/dependency_failure_injection_matrix_v1.json",
            sha256: $failure_config_digest
          },
          {
            source: "artifacts/dependency_real_service_fixture_matrix_v1.json",
            sha256: $real_service_fixture_config_digest
          },
          {
            source: "artifacts/dependency_feature_platform_consumer_matrix_v1.json",
            sha256: $feature_platform_consumer_config_digest
          },
          {
            source: "artifacts/dependency_verification_final_signoff_v1.json",
            sha256: $final_signoff_config_digest
          },
          {
            source: "artifacts/dormant_e2e_inventory_v1.json",
            sha256: $dormant_inventory_digest
          }
        ]
      },
      redaction_policy: $redaction_policy
    }' >"$ENVIRONMENT"

emit_validation_stage() {
    local scenario_id="$1"
    local step_id="$2"
    local stage="$3"
    local observed_outcome="$4"
    local exit_code="$5"
    local signal="$6"
    local elapsed_ms="$7"
    local command="$8"
    local target_dir="$9"
    local execution_backend="${10}"
    local rch_worker="${11}"
    local cleanup_result="${12}"
    local first_failing_invariant="${13}"
    local replay_pointer="${14}"
    local capability_ids
    local feature_flags
    capability_ids="$(scenario_capabilities "$scenario_id")"
    feature_flags="$(scenario_features "$scenario_id")"
    jq -cn \
        --arg schema_version "dependency-sovereignty-validation-stage-v1" \
        --arg run_id "$RUN_ID" \
        --arg bead_id "$BEAD_ID" \
        --arg track_id "$TRACK_ID" \
        --arg scenario_id "$scenario_id" \
        --arg step_id "$step_id" \
        --arg stage "$stage" \
        --arg validation_surface "$(scenario_surface "$scenario_id")" \
        --arg profile_family "$(scenario_profile "$scenario_id")" \
        --arg seed_or_fixture_id "$(scenario_fixture "$scenario_id")" \
        --arg config_snapshot_ref "environment.json#/config_snapshot" \
        --arg command "$command" \
        --arg expected_outcome "PASSED" \
        --arg observed_outcome "$observed_outcome" \
        --argjson exit_code "$exit_code" \
        --argjson signal "$signal" \
        --argjson monotonic_elapsed_ms "$elapsed_ms" \
        --arg stdout_log "$scenario_id/$step_id.stdout.log" \
        --arg stderr_log "$scenario_id/$step_id.stderr.log" \
        --arg execution_backend "$execution_backend" \
        --arg rch_worker "$rch_worker" \
        --arg cargo_target_dir "$target_dir" \
        --arg evidence_owner "$(scenario_evidence_owner "$scenario_id")" \
        --arg redaction_policy "metadata-and-secret-patterns-v1" \
        --arg cleanup_result "$cleanup_result" \
        --arg first_failing_invariant "$first_failing_invariant" \
        --arg replay_pointer "$replay_pointer" \
        --argjson capability_ids "$capability_ids" \
        --argjson feature_flags "$feature_flags" \
        '{
          schema_version: $schema_version,
          run_id: $run_id,
          bead_id: $bead_id,
          track_id: $track_id,
          capability_ids: $capability_ids,
          scenario_id: $scenario_id,
          step_id: $step_id,
          stage: $stage,
          validation_surface: $validation_surface,
          profile_family: $profile_family,
          feature_flags: $feature_flags,
          seed_or_fixture_id: $seed_or_fixture_id,
          config_snapshot_ref: $config_snapshot_ref,
          command: $command,
          expected_outcome: $expected_outcome,
          observed_outcome: $observed_outcome,
          exit_code: $exit_code,
          signal: $signal,
          monotonic_elapsed_ms: $monotonic_elapsed_ms,
          artifacts: {stdout_log: $stdout_log, stderr_log: $stderr_log},
          rch: {
            routed: ($execution_backend == "rch"),
            worker: $rch_worker,
            execution_backend: $execution_backend,
            cargo_target_dir: $cargo_target_dir
          },
          evidence_owner: $evidence_owner,
          service_tool_versions: {},
          redaction_policy: $redaction_policy,
          first_failing_invariant: (if $first_failing_invariant == "" then null else $first_failing_invariant end),
          cleanup_result: $cleanup_result,
          replay_pointer: $replay_pointer
        }' | tee -a "$VALIDATION_STAGES" >>"$EVENTS"
}

classify_result() {
    local exit_code="$1"
    local timed_out="$2"
    local signal="$3"
    local unsupported="$4"
    local blocked_rch="$5"
    local local_fallback="$6"
    local summary_ok="$7"
    local artifact_ok="$8"
    local replay_ok="$9"
    local cleanup_ok="${10}"
    if [[ "$unsupported" -eq 1 ]]; then
        printf 'UNSUPPORTED_PLATFORM'
    elif [[ "$blocked_rch" -eq 1 ]]; then
        printf 'BLOCKED_RCH'
    elif [[ "$local_fallback" -eq 1 ]]; then
        printf 'LOCAL_FALLBACK'
    elif [[ "$timed_out" -eq 1 ]]; then
        printf 'TIMEOUT'
    elif [[ "$signal" -gt 0 ]]; then
        printf 'SIGNAL'
    elif [[ "$summary_ok" -eq 0 ]]; then
        printf 'CORRUPT_SUMMARY'
    elif [[ "$artifact_ok" -eq 0 ]]; then
        printf 'MISSING_ARTIFACT'
    elif [[ "$replay_ok" -eq 0 ]]; then
        printf 'REPLAY_FAILURE'
    elif [[ "$cleanup_ok" -eq 0 ]]; then
        printf 'CLEANUP_FAILURE'
    elif [[ "$exit_code" -eq 0 ]]; then
        printf 'PASSED'
    elif [[ "$exit_code" -eq 1 ]]; then
        printf 'ASSERTION_FAILURE'
    else
        printf 'COMMAND_FAILURE'
    fi
}

dormant_lane_for_selection() {
    case "$1" in
        dormant-e2e-filesystem-recovery | DORMANT-FS-*) printf 'filesystem' ;;
        dormant-e2e-cross-subsystem-recovery | DORMANT-INT-*) printf 'cross-subsystem' ;;
        dormant-e2e-distributed-recovery | DORMANT-DIST-*) printf 'distributed' ;;
        *) return 64 ;;
    esac
}

dormant_owner_for_lane() {
    case "$1" in
        filesystem) printf 'asupersync-d24mms.12.2' ;;
        cross-subsystem) printf 'asupersync-d24mms.12.3' ;;
        distributed) printf 'asupersync-d24mms.12.4' ;;
        *) return 64 ;;
    esac
}

dormant_runner_for_lane() {
    case "$1" in
        filesystem) printf '%s' "$DORMANT_FS_RUNNER" ;;
        cross-subsystem) printf '%s' "$DORMANT_INT_RUNNER" ;;
        distributed) printf '%s' "$DORMANT_DIST_RUNNER" ;;
        *) return 64 ;;
    esac
}

validate_dormant_lane_report() {
    local lane="$1"
    local report="$2"
    jq -e --arg lane "$lane" '
      (.validation_passed == true) and
      (.test_status == 0) and
      ((.git_sha | type) == "string" and (.git_sha | length) > 0) and
      ((.command | type) == "string" and (.command | contains("rch"))) and
      ((.rch_target_dir | type) == "string" and (.rch_target_dir | length) > 0) and
      (((.missing_scenarios // []) | length) == 0) and
      (((.duplicate_scenarios // []) | length) == 0) and
      (((.missing_fields // []) | length) == 0) and
      (((.drifts // []) | length) == 0) and
      (if $lane == "filesystem" then
         (.row_count == 28 and .pass_count == 26 and .skip_count == 2 and .fail_count == 0) and
         ([.rows[] | select(.verdict == "skip") | .scenario_id] | sort) ==
           ["io-uring-cancellation-support-boundary", "io-uring-unknown-completion-attribution"] and
         all(.rows[]; .cleanup_status == "removed") and
         all(.rows[] | select(.verdict == "skip"); ((.unsupported_reason // "") | length) > 0)
       elif $lane == "cross-subsystem" then
         (.row_count == 17 and .pass_count == 16 and .skip_count == 1 and .fail_count == 0) and
         ([.rows[] | select(.verdict == "skip") | .scenario_id] == ["DORMANT-INT-005"]) and
         (.rows[] | select(.scenario_id == "DORMANT-INT-005") | .unsupported_reason) == "PLACEHOLDER_NOT_EVIDENCE" and
         all(.rows[]; ((.cleanup_status | type) == "string" and (.cleanup_status | length) > 0))
       elif $lane == "distributed" then
         (.row_count == 5 and .pass_count == 5 and .skip_count == 0 and .fail_count == 0) and
         all(.rows[]; (.verdict == "pass" and (.cleanup_status | type) == "object" and (.cleanup_status | length) > 0))
       else false end)
    ' "$report" >/dev/null
}

run_dormant_lane() {
    local lane="$1"
    local selection_root="$2"
    local child_dir="$selection_root/children/$lane"
    local runner
    runner="$(dormant_runner_for_lane "$lane")" || return $?
    mkdir -p "$child_dir"

    case "$lane" in
        filesystem)
            ASUPERSYNC_FS_PARITY_BEAD_ID=asupersync-d24mms.12.2 \
                bash "$runner" "$child_dir" || return $?
            ;;
        cross-subsystem)
            ASUPERSYNC_CROSS_SUBSYSTEM_BEAD_ID=asupersync-d24mms.12.3 \
                bash "$runner" "$child_dir" || return $?
            ;;
        distributed)
            ASUPERSYNC_DISTRIBUTED_RECOVERY_BEAD_ID=asupersync-d24mms.12.4 \
                bash "$runner" "$child_dir" || return $?
            ;;
    esac

    validate_dormant_lane_report "$lane" "$child_dir/run_report.json" || return $?
    jq -c --arg lane "$lane" --arg path "${child_dir#"$RUN_DIR/"}/run_report.json" '
      {
        lane: $lane,
        report: $path,
        bead_id,
        git_sha,
        command,
        features,
        rch_target_dir,
        test_status,
        row_count,
        pass_count,
        skip_count,
        fail_count,
        validation_passed
      }
    ' "$child_dir/run_report.json" >>"$selection_root/child_reports.ndjson"
}

emit_dormant_disposition_rows() {
    local selection="$1"
    local lane="$2"
    local selection_root="$3"
    local child_report="$selection_root/children/$lane/run_report.json"
    local owner
    local runner
    owner="$(dormant_owner_for_lane "$lane")" || return $?
    runner="$(dormant_runner_for_lane "$lane")" || return $?
    runner="${runner#"$PROJECT_ROOT/"}"

    jq -c \
      --arg selection "$selection" \
      --arg owner "$owner" \
      --arg lane "$lane" \
      --arg runner "$runner" \
      --arg child_report "${child_report#"$RUN_DIR/"}" \
      --slurpfile child "$child_report" '
      def maintained_ids($id):
        if $id == "DORMANT-FS-001" then [
          "dormant-fs-normal-recursive-traversal",
          "dormant-fs-simple-symlink-traversal",
          "dormant-fs-circular-symlink-detection",
          "dormant-fs-broken-symlink-handling",
          "dormant-fs-mixed-symlink-tree",
          "dormant-fs-cross-root-vfs-traversal",
          "dormant-fs-bounded-partial-traversal"
        ]
        elif $id == "DORMANT-FS-002" then ["dormant-fs-normal-recursive-traversal"]
        elif $id == "DORMANT-FS-003" then ["dormant-fs-circular-symlink-detection"]
        elif $id == "DORMANT-FS-004" then ["dormant-fs-broken-symlink-handling"]
        elif $id == "DORMANT-FS-005" then ["dormant-fs-mixed-symlink-tree"]
        else [$id] end;
      .test_inventory[]
      | select(
          if ($selection | startswith("DORMANT-")) then .scenario_id == $selection
          else .repair_owner == $owner end
        )
      | . as $inventory
      | maintained_ids($inventory.scenario_id) as $ids
      | ([$ids[] as $id | $child[0].rows[] | select(.scenario_id == $id)]) as $receipts
      | {
          schema_version: "dormant-e2e-disposition-row-v1",
          dormant_scenario_id: $inventory.scenario_id,
          source_file: $inventory.source_file,
          original_test_function: $inventory.test_function,
          original_status: $inventory.status,
          repair_owner: $inventory.repair_owner,
          disposition: (if $inventory.scenario_id == "DORMANT-INT-005" then "PLACEHOLDER_NOT_EVIDENCE" else "EQUAL_OR_BETTER" end),
          canonical_lane: $lane,
          runner_script: $runner,
          child_report: $child_report,
          maintained_scenario_ids: $ids,
          maintained_receipts: [
            $receipts[] | {
              scenario_id,
              verdict,
              cleanup_status,
              unsupported_reason: (.unsupported_reason // null),
              infrastructure_blocker: (.infrastructure_blocker // null),
              first_failure: (.first_failure // null)
            }
          ],
          receipt_complete: (($receipts | length) == ($ids | length)),
          accepted: (
            (($receipts | length) == ($ids | length)) and
            (if $inventory.scenario_id == "DORMANT-INT-005" then
               all($receipts[]; .verdict == "skip" and .unsupported_reason == "PLACEHOLDER_NOT_EVIDENCE")
             else all($receipts[]; .verdict == "pass") end)
          ),
          cleanup_complete: all($receipts[];
            (.cleanup_status != null) and
            (if (.cleanup_status | type) == "string" then (.cleanup_status | length) > 0
             elif (.cleanup_status | type) == "object" then (.cleanup_status | length) > 0
             else false end)),
          proof_source_revision: $child[0].git_sha,
          proof_command: $child[0].command,
          feature_profile: $child[0].features,
          deleted_or_migrated: false,
          unknown: false,
          replay_command: ("RCH_REQUIRE_REMOTE=1 bash scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario " + $inventory.scenario_id),
          no_claim_boundary: "Disposition proves maintained equal-or-better receipt coverage only; child lane no-claim boundaries remain controlling."
        }
    ' "$DORMANT_INVENTORY" >>"$selection_root/dispositions.ndjson"
}

validate_dormant_sources() {
    local selection_root="$1"
    local rows_file="$selection_root/source_files.ndjson"
    : >"$rows_file"
    while IFS=$'\t' read -r relative expected_sha expected_lines; do
        local absolute="$PROJECT_ROOT/$relative"
        local actual_sha=""
        local actual_lines=0
        local exists=false
        if [[ -f "$absolute" ]]; then
            exists=true
            actual_sha="$(sha256_file "$absolute")" || return $?
            actual_lines="$(awk 'END { print NR }' "$absolute")"
        fi
        jq -cn \
          --arg path "$relative" \
          --arg expected_sha256 "$expected_sha" \
          --arg actual_sha256 "$actual_sha" \
          --argjson expected_line_count "$expected_lines" \
          --argjson actual_line_count "$actual_lines" \
          --argjson exists "$exists" '
          {
            path: $path,
            expected_sha256: $expected_sha256,
            actual_sha256: $actual_sha256,
            expected_line_count: $expected_line_count,
            actual_line_count: $actual_line_count,
            exists: $exists,
            deleted_or_migrated: false,
            preserved: ($exists and $expected_sha256 == $actual_sha256 and $expected_line_count == $actual_line_count)
          }
        ' >>"$rows_file"
    done < <(jq -r '.modules[] | [.path, .sha256, .line_count] | @tsv' "$DORMANT_INVENTORY")
    jq -se 'length == 3 and all(.[]; .preserved == true)' "$rows_file" >/dev/null
}

dormant_expected_ids_json() {
    local selection="$1"
    case "$selection" in
        dormant-e2e-aggregate-signoff)
            jq '[.test_inventory[].scenario_id]' "$DORMANT_INVENTORY"
            ;;
        dormant-e2e-filesystem-recovery)
            jq '[.test_inventory[] | select(.repair_owner == "asupersync-d24mms.12.2") | .scenario_id]' "$DORMANT_INVENTORY"
            ;;
        dormant-e2e-cross-subsystem-recovery)
            jq '[.test_inventory[] | select(.repair_owner == "asupersync-d24mms.12.3") | .scenario_id]' "$DORMANT_INVENTORY"
            ;;
        dormant-e2e-distributed-recovery)
            jq '[.test_inventory[] | select(.repair_owner == "asupersync-d24mms.12.4") | .scenario_id]' "$DORMANT_INVENTORY"
            ;;
        DORMANT-*)
            jq -n --arg id "$selection" '[$id]'
            ;;
        *) return 64 ;;
    esac
}

finalize_dormant_selection() {
    local selection="$1"
    local selection_root="$2"
    local report="$selection_root/disposition_report.json"
    local expected_json
    local rows_json
    local sources_json
    local child_reports_json
    local validation_passed

    validate_dormant_sources "$selection_root" || return $?
    expected_json="$(dormant_expected_ids_json "$selection")" || return $?
    rows_json="$(jq -s . "$selection_root/dispositions.ndjson")" || return $?
    sources_json="$(jq -s . "$selection_root/source_files.ndjson")" || return $?
    child_reports_json="$(jq -s . "$selection_root/child_reports.ndjson")" || return $?
    validation_passed="$(jq -nr \
      --argjson expected "$expected_json" \
      --argjson rows "$rows_json" \
      --argjson sources "$sources_json" \
      --argjson children "$child_reports_json" '
      (($expected - [$rows[].dormant_scenario_id]) | length) == 0 and
      (([$rows[].dormant_scenario_id] - $expected) | length) == 0 and
      ($rows | group_by(.dormant_scenario_id) | all(.[]; length == 1)) and
      all($rows[]; .receipt_complete and .accepted and .cleanup_complete and (.unknown | not) and (.deleted_or_migrated | not)) and
      ($sources | length) == 3 and all($sources[]; .preserved) and
      ($children | length) > 0 and all($children[]; .validation_passed and .test_status == 0)
    ')"

    jq -n \
      --arg schema_version "dormant-e2e-disposition-report-v1" \
      --arg bead_id "asupersync-d24mms.12.5" \
      --arg selection_id "$selection" \
      --arg source_inventory "artifacts/dormant_e2e_inventory_v1.json" \
      --arg source_revision "$SOURCE_REVISION" \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --argjson expected_ids "$expected_json" \
      --argjson dispositions "$rows_json" \
      --argjson source_files "$sources_json" \
      --argjson child_reports "$child_reports_json" \
      --argjson validation_passed "$validation_passed" '
      {
        schema_version: $schema_version,
        bead_id: $bead_id,
        selection_id: $selection_id,
        source_inventory: $source_inventory,
        source_revision: $source_revision,
        generated_at: $generated_at,
        expected_dormant_scenario_ids: $expected_ids,
        counts: {
          expected: ($expected_ids | length),
          disposition_rows: ($dispositions | length),
          equal_or_better: ([$dispositions[] | select(.disposition == "EQUAL_OR_BETTER")] | length),
          placeholder_not_evidence: ([$dispositions[] | select(.disposition == "PLACEHOLDER_NOT_EVIDENCE")] | length),
          unknown: ([$dispositions[] | select(.unknown)] | length),
          deleted_or_migrated: ([$dispositions[] | select(.deleted_or_migrated)] | length)
        },
        source_files: $source_files,
        child_reports: $child_reports,
        dispositions: $dispositions,
        validation_passed: $validation_passed,
        redaction_result: "passed",
        cleanup_result: "passed",
        replay_command: ("RCH_REQUIRE_REMOTE=1 bash scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario " + $selection_id),
        no_claim_boundaries: [
          "The report proves canonical discovery, child-runner admission, disposition completeness, redaction, replay metadata, and source preservation only.",
          "It does not prove broad workspace health, release readiness, performance, live external-service interoperability, dependency exit, or surfaces excluded by A2, A3, and A4."
        ]
      }
    ' >"$report"

    if [[ "$validation_passed" != "true" ]]; then
        printf 'dormant disposition validation failed: %s\n' "$report" >&2
        return 1
    fi
    printf 'Dormant disposition: %s\n' "$report"
}

run_dormant_selection() {
    local selection="$1"
    local selection_root="$RUN_DIR/$selection/dormant-signoff"
    local lane
    mkdir -p "$selection_root"
    : >"$selection_root/dispositions.ndjson"
    : >"$selection_root/child_reports.ndjson"

    if [[ "$selection" == "dormant-e2e-aggregate-signoff" ]]; then
        for lane in filesystem cross-subsystem distributed; do
            run_dormant_lane "$lane" "$selection_root" || return $?
            emit_dormant_disposition_rows "$selection" "$lane" "$selection_root" || return $?
        done
    else
        lane="$(dormant_lane_for_selection "$selection")" || return $?
        run_dormant_lane "$lane" "$selection_root" || return $?
        emit_dormant_disposition_rows "$selection" "$lane" "$selection_root" || return $?
    fi

    finalize_dormant_selection "$selection" "$selection_root"
}

run_classifier_contract() {
    local failed=0
    local observed
    local fixture
    local redacted_probe
    while IFS='|' read -r fixture expected exit_code timed_out signal unsupported blocked fallback summary_ok artifact_ok replay_ok cleanup_ok; do
        observed="$(
            classify_result \
                "$exit_code" "$timed_out" "$signal" "$unsupported" "$blocked" \
                "$fallback" "$summary_ok" "$artifact_ok" "$replay_ok" "$cleanup_ok"
        )"
        printf 'fixture=%s expected=%s observed=%s\n' "$fixture" "$expected" "$observed"
        if [[ "$observed" != "$expected" ]]; then
            failed=1
        fi
    done <<'FIXTURES'
happy-path|PASSED|0|0|0|0|0|0|1|1|1|1
assertion-failure|ASSERTION_FAILURE|1|0|0|0|0|0|1|1|1|1
command-failure|COMMAND_FAILURE|2|0|0|0|0|0|1|1|1|1
timeout|TIMEOUT|124|1|0|0|0|0|1|1|1|1
signal|SIGNAL|143|0|15|0|0|0|1|1|1|1
unsupported-platform|UNSUPPORTED_PLATFORM|0|0|0|1|0|0|1|1|1|1
blocked-rch|BLOCKED_RCH|75|0|0|0|1|0|1|1|1|1
local-fallback|LOCAL_FALLBACK|0|0|0|0|0|1|1|1|1|1
corrupt-summary|CORRUPT_SUMMARY|0|0|0|0|0|0|0|1|1|1
missing-artifact|MISSING_ARTIFACT|0|0|0|0|0|0|1|0|1|1
replay-failure|REPLAY_FAILURE|0|0|0|0|0|0|1|1|0|1
cleanup-failure|CLEANUP_FAILURE|0|0|0|0|0|0|1|1|1|0
FIXTURES
    redacted_probe="$(printf 'canary=%s' "$CANARY" | redact_stream)"
    printf 'fixture=redaction-canary expected=canary=[REDACTED_CANARY] observed=%s\n' "$redacted_probe"
    if [[ "$redacted_probe" != "canary=[REDACTED_CANARY]" ]]; then
        failed=1
    fi
    return "$failed"
}

execute_scenario() {
    local scenario_id="$1"
    local target_dir="$2"
    case "$scenario_id" in
        catalog)
            jq -e '
              (.schema_version == 1) and
              (.counts.matrix_beads >= 300) and
              (.counts.capabilities == 50) and
              (.counts.evidence_plans >= 1500) and
              ([.matrix[].evidence_plans[] | select(.class == "e2e")] | length > 0) and
              ([.matrix[].evidence_plans[] | select(.class == "e2e") | .command] |
                all(. == "scripts/run_all_e2e.sh --suite dependency-sovereignty"))
            ' "$MATRIX"
            ;;
        runner-contract)
            run_classifier_contract
            ;;
        registry-contract)
            env -u CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_capability_registry_contract -- --nocapture
            ;;
        baseline-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_capability_baseline_contract -- --nocapture
            ;;
        cutover-policy-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_cutover_policy_contract -- --nocapture
            ;;
        verification-matrix-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_verification_matrix_contract -- --nocapture
            ;;
        failure-injection-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_failure_injection_matrix_contract -- --nocapture
            ;;
        real-service-fixture-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_real_service_fixture_contract -- --nocapture
            ;;
        feature-platform-consumer-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_feature_platform_consumer_matrix_contract -- --nocapture
            ;;
        aggregate-signoff-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_verification_final_signoff_contract -- --nocapture
            ;;
        sqlite-parity-aggregate)
            env -u CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 \
                RCH_BUILD_TIMEOUT_SEC="$STEP_TIMEOUT" RCH_TEST_TIMEOUT_SEC="$STEP_TIMEOUT" \
                rch exec --base HEAD --clean-overlay \
                --overlay-path tests/fixtures/sqlite-parity-consumer/src/main.rs -- \
                env ASUPERSYNC_SOURCE_REVISION="$SOURCE_REVISION" \
                SQLITE_PARITY_TARGET=x86_64-unknown-linux-gnu \
                SQLITE_PARITY_HOST=linux-x86_64-rch-worker \
                CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' \
                cargo test -j 3 --locked --manifest-path tests/fixtures/sqlite-parity-consumer/Cargo.toml \
                    --bin asupersync-sqlite-parity-consumer -- --nocapture --test-threads=1
            ;;
        api-adr-registry-contract)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
            ;;
        api-adr-phase3-signoff)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --test dependency_api_adr_phase3_signoff_contract -- --nocapture
            ;;
        atp_version_artifacts | dep-sovereignty-asupersync_d24mms_11_d22341de8339)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --lib --test atp_cdc_deduplication \
                toolchain_version_detection -- --nocapture --test-threads=1
            ;;
        dep-sovereignty-asupersync_d24mms_4_b6e90e93b1e8)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --features cli \
                --test time_utc_rfc3339_foundation_contract \
                dep_sovereignty_asupersync_d24mms_4_b6e90e93b1e8 \
                -- --nocapture --test-threads=1
            ;;
        dep-sovereignty-asupersync_5z2scg_3_5_66765b43947e)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${target_dir}_generic" \
                cargo test --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml \
                --locked -- --nocapture &&
                env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                    RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${target_dir}_historical" \
                    cargo test --manifest-path tests/fixtures/typed-format-cross-version-consumer/Cargo.toml \
                    --locked -- --nocapture &&
                env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                    RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                    cargo test -p asupersync --features cli,test-internals,trace-compression \
                    --test typed_format_registry_contract \
                    --test runtime_snapshot_codec_e2e \
                    --test replay_e2e_suite \
                    --test typed_format_cross_version_e2e \
                    --test typed_format_final_signoff_contract \
                    -- --nocapture --test-threads=1
            ;;
        dep-sovereignty-asupersync_5z2scg_3_7_94b694387988)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${target_dir}_consumer" \
                cargo test --manifest-path tests/fixtures/typed-format-cross-version-consumer/Cargo.toml --locked -- --nocapture &&
                env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                    RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                    cargo test -p asupersync --features cli,test-internals,trace-compression \
                    --test typed_format_cross_version_e2e -- --nocapture --test-threads=1
            ;;
        lz4_trace_replay | lz4_cross_version_artifact | lz4_malformed_limits)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --features cli,test-internals,trace-compression \
                --test lz4_trace_integration_e2e "$scenario_id" -- --nocapture --test-threads=1
            ;;
        dep-sovereignty-asupersync_0h6myr_4_5_04aaef97c5dd)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${target_dir}_sparse" \
                cargo check --quiet -p asupersync --no-default-features --features trace-compression &&
                env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                    RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                    cargo test --quiet -p asupersync \
                    --features cli,test-internals,trace-compression \
                    --test lz4_surface_artifact_inventory_contract \
                    --test lz4_owned_codec_corpus_contract \
                    --test lz4_trace_integration_e2e \
                    --test lz4_final_signoff_contract \
                    -- --nocapture --test-threads=1
            ;;
        dep-sovereignty-asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --locked --lib \
                ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d \
                -- --nocapture --test-threads=1 &&
                env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
                    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                    RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${target_dir}_consumer" \
                    cargo test --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml \
                    --locked ver_a1_asupersync_dep_p4_nkeys_poc60v_1_3_5e81559b363d__downstream_consumer \
                    -- --nocapture --test-threads=1
            ;;
        offline-tuner-logging-parity)
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
                --overlay-path Cargo.toml \
                --overlay-path Cargo.lock \
                --overlay-path src/bin/offline_tuner.rs \
                --overlay-path tests/offline_tuner_env_logger_parity.rs -- \
                env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="$target_dir" \
                cargo test -p asupersync --locked --features cli,simd-intrinsics \
                    --bin offline_tuner --test offline_tuner_env_logger_parity \
                    -- --nocapture --test-threads=1
            ;;
        temp_artifacts)
            run_temp_artifact_cargo() {
                local target_suffix="$1"
                shift
                env -u CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
                    --overlay-path scripts/run_dependency_sovereignty_e2e.sh \
                    --overlay-path docs/dependency_capability_baseline.md \
                    --overlay-path src/atp/benchmark/suite.rs \
                    --overlay-path src/net/atp/transport_quic/mod.rs \
                    --overlay-path src/net/atp/transport_rq/mod.rs \
                    --overlay-path src/net/atp/transport_rq/transport_rq_tests.rs \
                    --overlay-path src/test_logging.rs \
                    --overlay-path tests/dependency_capability_baseline_contract.rs \
                    --overlay-path tests/e2e_log_quality_schema.rs \
                    --overlay-path tests/temp_artifact_lifecycle.rs -- \
                    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
                    RUSTFLAGS='-D warnings -C debuginfo=0' \
                    CARGO_TARGET_DIR="${target_dir}_${target_suffix}" "$@"
            }

            run_temp_artifact_cargo sparse_default \
                cargo check --locked -p asupersync --no-default-features --lib -j 2 || return $?
            run_temp_artifact_cargo sparse_test_internals \
                cargo check --locked -p asupersync --no-default-features \
                    --features test-internals --lib -j 2 || return $?
            run_temp_artifact_cargo sparse_benchmark_adapters \
                cargo check --locked -p asupersync --no-default-features \
                    --features benchmark-adapters --lib -j 2 || return $?
            run_temp_artifact_cargo sparse_cli \
                cargo check --locked -p asupersync --no-default-features \
                    --features cli --bin asupersync -j 2 || return $?
            run_temp_artifact_cargo combined \
                cargo check --locked -p asupersync \
                    --features cli,test-internals,benchmark-adapters \
                    --lib --bin asupersync -j 2 || return $?
            run_temp_artifact_cargo evidence \
                cargo test --locked -p asupersync \
                    --features cli,test-internals,benchmark-adapters \
                    --test temp_artifact_lifecycle -j 2 \
                    -- --nocapture --test-threads=1 || return $?
            run_temp_artifact_cargo evidence \
                cargo test --locked -p asupersync --features cli --bin asupersync \
                    write_replay_artifact_ -j 2 -- --nocapture --test-threads=1 || return $?
            run_temp_artifact_cargo evidence \
                cargo test --locked -p asupersync --lib pack_small_files_ \
                    -j 2 -- --nocapture --test-threads=1 || return $?
            run_temp_artifact_cargo evidence \
                cargo test --locked -p asupersync --lib \
                    quic_prepare_source_manifest_hashes_files_with_streaming_digests \
                    -j 2 -- --nocapture --test-threads=1 || return $?
            run_temp_artifact_cargo evidence \
                cargo test --locked -p asupersync --test dependency_capability_baseline_contract \
                    tempfile_claim_time_profile_checkpoint_is_source_pinned_and_fail_closed \
                    -j 2 -- --nocapture --test-threads=1 || return $?
            run_temp_artifact_cargo evidence \
                cargo test --locked -p asupersync --test e2e_log_quality_schema \
                    dependency_sovereignty_ -j 2 -- --nocapture --test-threads=1
            ;;
        dormant-e2e-* | DORMANT-*)
            run_dormant_selection "$scenario_id"
            ;;
    esac
}

export MATRIX FAILURE_MATRIX REAL_SERVICE_FIXTURE_MATRIX FEATURE_PLATFORM_CONSUMER_MATRIX FINAL_SIGNOFF_MATRIX PROJECT_ROOT CANARY SOURCE_REVISION STEP_TIMEOUT
export DORMANT_INVENTORY DORMANT_FS_RUNNER DORMANT_INT_RUNNER DORMANT_DIST_RUNNER RUN_DIR
export -f classify_result execute_scenario redact_stream run_classifier_contract sha256_file
export -f dormant_lane_for_selection dormant_owner_for_lane dormant_runner_for_lane
export -f validate_dormant_lane_report run_dormant_lane emit_dormant_disposition_rows
export -f validate_dormant_sources dormant_expected_ids_json finalize_dormant_selection run_dormant_selection

TOTAL=0
PASSED=0
FAILED=0
BLOCKED=0
UNSUPPORTED=0
DRY_RUN_COUNT=0
FIRST_FAILURE=""
STOPPED=0

for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
    TOTAL=$((TOTAL + 1))
    step_id="$(scenario_step_id "$scenario_id")"
    step_dir="$RUN_DIR/$scenario_id"
    stdout_log="$step_dir/$step_id.stdout.log"
    stderr_log="$step_dir/$step_id.stderr.log"
    target_dir="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_sovereignty_${scenario_id//-/_}"
    command_display="$(scenario_command_display "$scenario_id")"
    command_display="${command_display/<isolated>/$target_dir}"
    replay_command="RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh --scenario $scenario_id"
    mkdir -p "$step_dir"
    : >"$stdout_log"
    : >"$stderr_log"

    if [[ "$STOPPED" -eq 1 ]]; then
        observed_outcome="NOT_RUN_FAIL_FAST"
        exit_code=0
        signal=0
        duration_ms=0
        execution_backend="not_run"
        rch_worker="not-applicable"
        cleanup_result="not_run"
        first_failing_invariant="prior scenario triggered fail-fast"
    elif [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'dry-run scenario=%s command=%s\n' "$scenario_id" "$command_display" >"$stdout_log"
        observed_outcome="DRY_RUN"
        exit_code=0
        signal=0
        duration_ms=0
        execution_backend="dry_run"
        rch_worker="not-applicable"
        cleanup_result="passed"
        first_failing_invariant=""
        DRY_RUN_COUNT=$((DRY_RUN_COUNT + 1))
    else
        blocked_rch=0
        local_fallback=0
        timed_out=0
        signal=0
        unsupported=0
        summary_ok=1
        artifact_ok=1
        replay_ok=1
        cleanup_ok=1
        rch_worker="not-applicable"
        if scenario_is_cargo "$scenario_id"; then
            execution_backend="rch"
            if [[ "${RCH_REQUIRE_REMOTE:-}" != "1" ]] || ! command -v rch >/dev/null 2>&1; then
                blocked_rch=1
                execution_backend="blocked"
                printf 'RCH_REQUIRE_REMOTE=1 and an installed rch are required; local Cargo fallback refused\n' >"$stderr_log"
            fi
        else
            execution_backend="local_static"
        fi

        start_ms="$(monotonic_ms)"
        exit_code=0
        if [[ "$blocked_rch" -eq 0 ]]; then
            (
                cd "$PROJECT_ROOT" || exit 70
                # shellcheck disable=SC2016
                VER_A2_REDACTION_CANARY="$CANARY" timeout "$STEP_TIMEOUT" \
                    bash -c 'execute_scenario "$1" "$2"' _ "$scenario_id" "$target_dir"
            ) > >(redact_stream | tee -a "$stdout_log") \
                2> >(redact_stream | tee -a "$stderr_log" >&2)
            exit_code=$?
            wait
        else
            exit_code=75
        fi
        end_ms="$(monotonic_ms)"
        duration_ms=$((end_ms - start_ms))
        if [[ "$exit_code" -eq 124 ]]; then
            timed_out=1
        elif [[ "$exit_code" -ge 128 ]]; then
            signal=$((exit_code - 128))
        fi
        if [[ "$exit_code" -eq 103 ]] && grep -Eq '\[RCH-I003\]|remote required; refusing local fallback' "$stdout_log" "$stderr_log" 2>/dev/null; then
            blocked_rch=1
            execution_backend="blocked"
        elif grep -Eq "$LOCAL_FALLBACK_PATTERN" "$stdout_log" "$stderr_log" 2>/dev/null; then
            local_fallback=1
        fi
        if [[ "$blocked_rch" -eq 1 ]]; then
            rch_worker="unassigned"
        else
            rch_worker="$(
                {
                    grep -hEo 'Selected worker: [A-Za-z0-9._-]+' "$stdout_log" "$stderr_log" || true
                    grep -hEo '\[RCH\] remote [A-Za-z0-9._-]+' "$stdout_log" "$stderr_log" || true
                } | awk '{print $NF}' | tail -n 1
            )"
        fi
        if [[ -z "$rch_worker" ]]; then
            if scenario_is_cargo "$scenario_id"; then
                rch_worker="unknown"
            else
                rch_worker="not-applicable"
            fi
        fi
        residual_children="$(jobs -pr | wc -l | tr -d ' ')"
        if [[ "$residual_children" != "0" ]]; then
            cleanup_ok=0
        fi
        cleanup_result="passed"
        if [[ "$cleanup_ok" -eq 0 ]]; then
            cleanup_result="failed:$residual_children-residual-children"
        fi
        observed_outcome="$(
            classify_result \
                "$exit_code" "$timed_out" "$signal" "$unsupported" "$blocked_rch" \
                "$local_fallback" "$summary_ok" "$artifact_ok" "$replay_ok" "$cleanup_ok"
        )"
        first_failing_invariant=""
        if [[ "$observed_outcome" != "PASSED" ]]; then
            first_failing_invariant="outcome_taxonomy::$observed_outcome"
        fi
    fi

    case "$observed_outcome" in
        PASSED) PASSED=$((PASSED + 1)) ;;
        DRY_RUN | NOT_RUN_FAIL_FAST) ;;
        BLOCKED_RCH)
            BLOCKED=$((BLOCKED + 1))
            FAILED=$((FAILED + 1))
            ;;
        UNSUPPORTED_PLATFORM)
            UNSUPPORTED=$((UNSUPPORTED + 1))
            FAILED=$((FAILED + 1))
            ;;
        *) FAILED=$((FAILED + 1)) ;;
    esac
    if [[ -z "$FIRST_FAILURE" && "$observed_outcome" != "PASSED" && "$observed_outcome" != "DRY_RUN" && "$observed_outcome" != "NOT_RUN_FAIL_FAST" ]]; then
        FIRST_FAILURE="$first_failing_invariant"
    fi

    emit_validation_stage \
        "$scenario_id" "$step_id" "scenario_finished" "$observed_outcome" \
        "$exit_code" "$signal" "$duration_ms" "$command_display" "$target_dir" \
        "$execution_backend" "$rch_worker" "$cleanup_result" \
        "$first_failing_invariant" "$replay_command"

    capability_ids="$(scenario_capabilities "$scenario_id")"
    jq -cn \
        --arg schema_version "dependency-sovereignty-scenario-v1" \
        --arg run_id "$RUN_ID" \
        --arg bead_id "$BEAD_ID" \
        --arg track_id "$TRACK_ID" \
        --arg scenario_id "$scenario_id" \
        --arg step_id "$step_id" \
        --arg validation_surface "$(scenario_surface "$scenario_id")" \
        --arg profile_family "$(scenario_profile "$scenario_id")" \
        --argjson feature_flags "$(scenario_features "$scenario_id")" \
        --arg seed_or_fixture_id "$(scenario_fixture "$scenario_id")" \
        --arg config_snapshot_ref "environment.json#/config_snapshot" \
        --arg command "$command_display" \
        --arg observed_outcome "$observed_outcome" \
        --argjson exit_code "$exit_code" \
        --argjson signal "$signal" \
        --argjson monotonic_elapsed_ms "$duration_ms" \
        --arg execution_backend "$execution_backend" \
        --arg rch_worker "$rch_worker" \
        --arg cargo_target_dir "$target_dir" \
        --arg evidence_owner "$(scenario_evidence_owner "$scenario_id")" \
        --arg cleanup_result "$cleanup_result" \
        --arg first_failing_invariant "$first_failing_invariant" \
        --arg replay_pointer "$replay_command" \
        --argjson capability_ids "$capability_ids" \
        '{
          schema_version: $schema_version,
          run_id: $run_id,
          bead_id: $bead_id,
          track_id: $track_id,
          capability_ids: $capability_ids,
          scenario_id: $scenario_id,
          step_id: $step_id,
          validation_surface: $validation_surface,
          profile_family: $profile_family,
          feature_flags: $feature_flags,
          seed_or_fixture_id: $seed_or_fixture_id,
          config_snapshot_ref: $config_snapshot_ref,
          command: $command,
          expected_outcome: "PASSED",
          observed_outcome: $observed_outcome,
          exit_code: $exit_code,
          signal: $signal,
          monotonic_elapsed_ms: $monotonic_elapsed_ms,
          artifacts: {
            stdout_log: ($scenario_id + "/" + $step_id + ".stdout.log"),
            stderr_log: ($scenario_id + "/" + $step_id + ".stderr.log")
          },
          rch: {
            routed: ($execution_backend == "rch"),
            worker: $rch_worker,
            execution_backend: $execution_backend,
            cargo_target_dir: $cargo_target_dir
          },
          evidence_owner: $evidence_owner,
          service_tool_versions: {},
          redaction_policy: "metadata-and-secret-patterns-v1",
          first_failing_invariant: (if $first_failing_invariant == "" then null else $first_failing_invariant end),
          cleanup_result: $cleanup_result,
          replay_pointer: $replay_pointer
        }' >>"$SCENARIOS"

    if [[ "$FAIL_FAST" -eq 1 && "$observed_outcome" != "PASSED" && "$observed_outcome" != "DRY_RUN" ]]; then
        STOPPED=1
    fi
done

if grep -R -Fq "$CANARY" "$RUN_DIR"; then
    FAILED=$((FAILED + 1))
    if [[ -z "$FIRST_FAILURE" ]]; then
        FIRST_FAILURE="redaction::canary_leak"
    fi
fi
if grep -R -Fq -e "$NKEY_SECRET_CANARY" -e "$NKEY_DOWNSTREAM_CANARY" "$RUN_DIR"; then
    FAILED=$((FAILED + 1))
    if [[ -z "$FIRST_FAILURE" ]]; then
        FIRST_FAILURE="redaction::nkey_secret_canary_leak"
    fi
fi

DORMANT_DISPOSITION_REPORTS_JSON="$(
    find "$RUN_DIR" -type f -path '*/dormant-signoff/disposition_report.json' \
        -printf '%P\n' | LC_ALL=C sort | jq -R . | jq -s .
)"

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STATUS="passed"
FAILURE_CLASS="none"
if [[ "$FAILED" -gt 0 ]]; then
    STATUS="failed"
    FAILURE_CLASS="${FIRST_FAILURE:-scenario_failure}"
fi

jq -s \
    --arg schema_version "dependency-sovereignty-repro-manifest-v1" \
    --arg run_id "$RUN_ID" \
    --arg source_revision "$SOURCE_REVISION" \
    --arg seed "$SEED" \
    --argjson dormant_disposition_reports "$DORMANT_DISPOSITION_REPORTS_JSON" \
    --arg no_claim_boundary "Replay metadata proves runner reproducibility only; it does not prove replacement parity, real-service interoperability, release readiness, or dependency exit." \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      source_revision: $source_revision,
      seed: $seed,
      scenario_ids: (map(.scenario_id)),
      replay_commands: (map({scenario_id, command: .replay_pointer})),
      failing_scenarios: (map(select(.observed_outcome != "PASSED" and .observed_outcome != "DRY_RUN" and .observed_outcome != "NOT_RUN_FAIL_FAST") | {scenario_id, observed_outcome, first_failing_invariant})),
      artifact_paths: ([
        "summary.json",
        "events.ndjson",
        "scenarios.ndjson",
        "validation_stages.ndjson",
        "artifact_manifest.ndjson",
        "environment.json",
        "repro_manifest.json"
      ] + $dormant_disposition_reports),
      dormant_disposition_reports: $dormant_disposition_reports,
      no_claim_boundary: $no_claim_boundary
    }' "$SCENARIOS" >"$REPRO_MANIFEST"

jq -n \
    --arg schema_version "e2e-suite-summary-v3" \
    --arg suite_id "$SUITE_ID" \
    --arg scenario_id "$SUITE_SCENARIO_ID" \
    --arg seed "$SEED" \
    --arg started_ts "$STARTED_TS" \
    --arg ended_ts "$ENDED_TS" \
    --arg status "$STATUS" \
    --arg failure_class "$FAILURE_CLASS" \
    --arg repro_command "$REPRO_COMMAND" \
    --arg artifact_path "$SUMMARY" \
    --arg events_ndjson "$EVENTS" \
    --arg scenarios_ndjson "$SCENARIOS" \
    --arg validation_stages_ndjson "$VALIDATION_STAGES" \
    --arg artifact_manifest_ndjson "$ARTIFACT_MANIFEST" \
    --arg environment_json "$ENVIRONMENT" \
    --arg repro_manifest_json "$REPRO_MANIFEST" \
    --arg first_failing_invariant "$FIRST_FAILURE" \
    --argjson dormant_disposition_reports "$DORMANT_DISPOSITION_REPORTS_JSON" \
    --argjson total "$TOTAL" \
    --argjson passed "$PASSED" \
    --argjson failed "$FAILED" \
    --argjson blocked "$BLOCKED" \
    --argjson unsupported "$UNSUPPORTED" \
    --argjson dry_run "$DRY_RUN_COUNT" \
    '{
      schema_version: $schema_version,
      suite_id: $suite_id,
      scenario_id: $scenario_id,
      seed: $seed,
      started_ts: $started_ts,
      ended_ts: $ended_ts,
      status: $status,
      failure_class: $failure_class,
      repro_command: $repro_command,
      artifact_path: $artifact_path,
      counts: {
        total: $total,
        passed: $passed,
        failed: $failed,
        blocked: $blocked,
        unsupported: $unsupported,
        dry_run: $dry_run
      },
      artifacts: {
        events_ndjson: $events_ndjson,
        scenarios_ndjson: $scenarios_ndjson,
        validation_stages_ndjson: $validation_stages_ndjson,
        artifact_manifest_ndjson: $artifact_manifest_ndjson,
        environment_json: $environment_json,
        repro_manifest_json: $repro_manifest_json,
        dormant_disposition_reports: $dormant_disposition_reports
      },
      first_failing_invariant: (if $first_failing_invariant == "" then null else $first_failing_invariant end),
      cleanup_result: "passed",
      redaction_policy: "metadata-and-secret-patterns-v1",
      no_claim_boundary: "This suite proves runner, schema, replay, redaction, cleanup, and selected dormant-disposition contracts only. It does not prove campaign implementations outside selected child receipts, performance, release readiness, broad workspace health, live external-service interoperability, or dependency exit."
    }' >"$SUMMARY"

{
    printf '%s\n' "$SUMMARY" "$EVENTS" "$SCENARIOS" "$VALIDATION_STAGES" "$ENVIRONMENT" "$REPRO_MANIFEST"
    find "$RUN_DIR" -mindepth 2 -type f \
        \( -name '*.log' -o -path '*/dormant-signoff/*' \) -print
} | LC_ALL=C sort -u | while IFS= read -r artifact_path; do
    [[ -f "$artifact_path" ]] || continue
    jq -cn \
        --arg schema_version "dependency-sovereignty-artifact-entry-v1" \
        --arg path "${artifact_path#"$RUN_DIR/"}" \
        --arg sha256 "$(sha256_file "$artifact_path")" \
        --argjson size_bytes "$(wc -c <"$artifact_path" | tr -d ' ')" \
        '{schema_version: $schema_version, path: $path, sha256: $sha256, size_bytes: $size_bytes}' \
        >>"$ARTIFACT_MANIFEST"
done

write_pointer() {
    local pointer_path="$1"
    local pointer_status="$2"
    local temporary_path="${pointer_path}.tmp.$$"
    jq -n \
        --arg schema_version "dependency-sovereignty-run-pointer-v1" \
        --arg run_id "$RUN_ID" \
        --arg status "$pointer_status" \
        --arg summary "$SUMMARY" \
        --arg events "$EVENTS" \
        --arg scenarios "$SCENARIOS" \
        --arg validation_stages "$VALIDATION_STAGES" \
        --arg artifact_manifest "$ARTIFACT_MANIFEST" \
        --arg environment "$ENVIRONMENT" \
        --arg repro_manifest "$REPRO_MANIFEST" \
        --argjson dormant_disposition_reports "$DORMANT_DISPOSITION_REPORTS_JSON" \
        '{
          schema_version: $schema_version,
          run_id: $run_id,
          status: $status,
          summary: $summary,
          events: $events,
          scenarios: $scenarios,
          validation_stages: $validation_stages,
          artifact_manifest: $artifact_manifest,
          environment: $environment,
          repro_manifest: $repro_manifest,
          dormant_disposition_reports: $dormant_disposition_reports
        }' >"$temporary_path"
    mv "$temporary_path" "$pointer_path"
}

mkdir -p "$OUTPUT_ROOT"
write_pointer "$LATEST" "$STATUS"
if [[ "$STATUS" == "passed" ]]; then
    write_pointer "$LATEST_SUCCESS" "$STATUS"
fi

printf 'Dependency sovereignty suite: %s\n' "$STATUS"
printf 'Summary: %s\n' "$SUMMARY"
printf 'Artifacts: %s\n' "$RUN_DIR"
printf 'Replay: %s\n' "$REPRO_COMMAND"

if [[ "$STATUS" != "passed" ]]; then
    exit 1
fi
exit 0
