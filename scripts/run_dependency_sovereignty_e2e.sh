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
REGISTRY="$PROJECT_ROOT/artifacts/dependency_capability_registry_v1.json"
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
    --scenario registry-contract
USAGE
}

scenario_ids() {
    printf '%s\n' \
        catalog \
        runner-contract \
        registry-contract \
        baseline-contract \
        cutover-policy-contract \
        verification-matrix-contract
}

scenario_is_known() {
    case "$1" in
        catalog | runner-contract | registry-contract | baseline-contract | cutover-policy-contract | verification-matrix-contract)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

scenario_is_cargo() {
    case "$1" in
        registry-contract | baseline-contract | cutover-policy-contract | verification-matrix-contract)
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
        runner-contract) printf 'contract' ;;
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
    esac
}

scenario_profile() {
    case "$1" in
        catalog | runner-contract) printf 'contract-only' ;;
        *) printf 'nightly-default' ;;
    esac
}

scenario_capabilities() {
    case "$1" in
        catalog | runner-contract | verification-matrix-contract)
            printf '["CAP-REAL-SERVICE-E2E","CAP-VERIFICATION-PROFILES"]'
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

if [[ -e "$RUN_DIR" ]]; then
    printf 'refusing to overwrite retained evidence directory: %s\n' "$RUN_DIR" >&2
    exit 73
fi
if [[ ! -f "$MATRIX" || ! -f "$REGISTRY" ]]; then
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
        sha256: $config_digest
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
    capability_ids="$(scenario_capabilities "$scenario_id")"
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
        --arg evidence_owner "$EVIDENCE_OWNER" \
        --arg redaction_policy "metadata-and-secret-patterns-v1" \
        --arg cleanup_result "$cleanup_result" \
        --arg first_failing_invariant "$first_failing_invariant" \
        --arg replay_pointer "$replay_pointer" \
        --argjson capability_ids "$capability_ids" \
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
          feature_flags: [],
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
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay -- \
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
    esac
}

export MATRIX PROJECT_ROOT CANARY
export -f classify_result execute_scenario redact_stream run_classifier_contract

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
    step_id="ver-a2-${scenario_id}"
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
        if grep -Eq "$LOCAL_FALLBACK_PATTERN" "$stdout_log" "$stderr_log" 2>/dev/null; then
            local_fallback=1
        fi
        rch_worker="$(
            {
                grep -hEo 'Selected worker: [A-Za-z0-9._-]+' "$stdout_log" "$stderr_log" || true
                grep -hEo '\[RCH\] remote [A-Za-z0-9._-]+' "$stdout_log" "$stderr_log" || true
            } | awk '{print $NF}' | tail -n 1
        )"
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
        --arg evidence_owner "$EVIDENCE_OWNER" \
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
          feature_flags: [],
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
    --arg no_claim_boundary "Replay metadata proves runner reproducibility only; it does not prove replacement parity, real-service interoperability, release readiness, or dependency exit." \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      source_revision: $source_revision,
      seed: $seed,
      scenario_ids: (map(.scenario_id)),
      replay_commands: (map({scenario_id, command: .replay_pointer})),
      failing_scenarios: (map(select(.observed_outcome != "PASSED" and .observed_outcome != "DRY_RUN" and .observed_outcome != "NOT_RUN_FAIL_FAST") | {scenario_id, observed_outcome, first_failing_invariant})),
      artifact_paths: [
        "summary.json",
        "events.ndjson",
        "scenarios.ndjson",
        "validation_stages.ndjson",
        "artifact_manifest.ndjson",
        "environment.json",
        "repro_manifest.json"
      ],
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
    --arg repro_command "bash scripts/run_all_e2e.sh --suite dependency-sovereignty" \
    --arg artifact_path "$SUMMARY" \
    --arg events_ndjson "$EVENTS" \
    --arg scenarios_ndjson "$SCENARIOS" \
    --arg validation_stages_ndjson "$VALIDATION_STAGES" \
    --arg artifact_manifest_ndjson "$ARTIFACT_MANIFEST" \
    --arg environment_json "$ENVIRONMENT" \
    --arg repro_manifest_json "$REPRO_MANIFEST" \
    --arg first_failing_invariant "$FIRST_FAILURE" \
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
        repro_manifest_json: $repro_manifest_json
      },
      first_failing_invariant: (if $first_failing_invariant == "" then null else $first_failing_invariant end),
      cleanup_result: "passed",
      redaction_policy: "metadata-and-secret-patterns-v1",
      no_claim_boundary: "This suite proves runner, schema, replay, redaction, and cleanup contracts only. It does not prove campaign implementations, replacement parity, real-service interoperability, performance, release readiness, broad workspace health, or dependency exit."
    }' >"$SUMMARY"

{
    printf '%s\n' "$SUMMARY" "$EVENTS" "$SCENARIOS" "$VALIDATION_STAGES" "$ENVIRONMENT" "$REPRO_MANIFEST"
    find "$RUN_DIR" -mindepth 2 -type f -name '*.log' -print
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
          repro_manifest: $repro_manifest
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
printf 'Replay: bash scripts/run_all_e2e.sh --suite dependency-sovereignty\n'

if [[ "$STATUS" != "passed" ]]; then
    exit 1
fi
exit 0
