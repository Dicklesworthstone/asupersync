#!/usr/bin/env bash
# Replayable CAP A2 dependency-capability baseline runner.
#
# Run from the repository controller; every Cargo command is delegated to RCH
# and this script intentionally refuses local Cargo fallback:
#   RCH_REQUIRE_REMOTE=1 \
#     bash scripts/run_dependency_capability_baseline.sh <scenario>
#
# The aggregate successor may emit BLOCKED_PLATFORM, BLOCKED_OWNER, or
# UNSUPPORTED in addition to this runner's PASS, FAIL, and BLOCKED_EXTERNAL.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT="$PROJECT_ROOT/artifacts/dependency_capability_baseline_v1.json"
OUTPUT_ROOT="${DEPENDENCY_CAPABILITY_BASELINE_OUTPUT_ROOT:-$PROJECT_ROOT/target/e2e-results/dependency-capability-baseline}"
SCENARIO_ID="${1:-}"
BASELINE_REVISION="$(jq -r '.baseline_source_revision' "$ARTIFACT")"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_ID="${DEPENDENCY_CAPABILITY_BASELINE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$-${SCENARIO_ID:-missing}}"
CANARY="CAP_A2_CANARY_SECRET_DO_NOT_LOG"

redact_stream() {
    sed "s/$CANARY/[REDACTED]/g"
}

sha256_stream() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{ print $1 }'
    else
        printf 'SHA-256 unavailable: install sha256sum or shasum\n' >&2
        return 69
    fi
}

sha256_file() {
    sha256_stream <"$1"
}

usage() {
    cat >&2 <<'USAGE'
usage: run_dependency_capability_baseline.sh <scenario>

scenarios:
  contract          Validate the canonical artifact, negative mutations, docs, and runner.
  consumer-default  Run the standalone public consumer without optional profiles.
  consumer-full     Run the standalone public consumer with the full feature profile.
  catalog           Validate static counts, stable IDs, and typed blocker coverage.

Required invocation:
  RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_capability_baseline.sh <scenario>
USAGE
}

case "$SCENARIO_ID" in
    contract | consumer-default | consumer-full | catalog) ;;
    *)
        usage
        exit 64
        ;;
esac

if [[ ! "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid run ID: only ASCII letters, digits, dot, underscore, and hyphen are accepted" >&2
    exit 64
fi

RUN_DIR="$OUTPUT_ROOT/$RUN_ID"
STEP_ID="cap-a2-$SCENARIO_ID"
STEP_DIR="$RUN_DIR/steps/$STEP_ID"
SUMMARY="$RUN_DIR/summary.json"
EVENTS="$RUN_DIR/events.ndjson"
STDOUT_LOG="$RUN_DIR/stdout.log"
STDERR_LOG="$RUN_DIR/stderr.log"
STEP_STDOUT="$STEP_DIR/stdout.log"
STEP_STDERR="$STEP_DIR/stderr.log"
PROVENANCE="$RUN_DIR/provenance.json"
REPLAY="$RUN_DIR/replay.sh"

if [[ -e "$RUN_DIR" ]]; then
    echo "refusing to overwrite retained evidence directory: $RUN_DIR" >&2
    exit 73
fi

mkdir -p "$STEP_DIR"
: >"$EVENTS"
: >"$STDOUT_LOG"
: >"$STDERR_LOG"
: >"$STEP_STDOUT"
: >"$STEP_STDERR"

emit_event() {
    local event="$1"
    local outcome="$2"
    local detail="$3"
    jq -cn \
        --arg schema "dependency-capability-baseline-event-v1" \
        --arg run_id "$RUN_ID" \
        --arg scenario_id "$SCENARIO_ID" \
        --arg step_id "$STEP_ID" \
        --arg event "$event" \
        --arg outcome "$outcome" \
        --arg detail "$detail" \
        --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
          schema: $schema,
          run_id: $run_id,
          scenario_id: $scenario_id,
          step_id: $step_id,
          event: $event,
          outcome: $outcome,
          detail: $detail,
          at_utc: $at
        }' >>"$EVENTS"
}

write_provenance() {
    local source_revision
    local rustc_version
    local cargo_version
    local host
    local target
    local controller_dirty_paths
    source_revision="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
    controller_dirty_paths="$(git -C "$PROJECT_ROOT" status --short)"
    rustc_version="$(rustc --version --verbose 2>&1)"
    cargo_version="$(cargo --version --verbose 2>&1)"
    host="$(uname -a)"
    target="$(rustc -vV | awk -F': ' '$1 == "host" { print $2 }')"
    jq -n \
        --arg schema "dependency-capability-baseline-provenance-v1" \
        --arg run_id "$RUN_ID" \
        --arg scenario_id "$SCENARIO_ID" \
        --arg step_id "$STEP_ID" \
        --arg source_revision "$source_revision" \
        --arg baseline_revision "$BASELINE_REVISION" \
        --arg rustc "$rustc_version" \
        --arg cargo "$cargo_version" \
        --arg toolchain_provenance_scope "controller; remote Cargo output retained in step logs" \
        --arg command "$COMMAND_DISPLAY" \
        --arg features "$FEATURE_PROFILE" \
        --arg fixture_id "$FIXTURE_ID" \
        --arg target "$target" \
        --arg host "$host" \
        --arg controller_dirty_paths "$controller_dirty_paths" \
        --arg execution_tree "$EXECUTION_TREE" \
        --arg execution_transport "$EXECUTION_TRANSPORT" \
        --arg fixture_digest "$FIXTURE_DIGEST" \
        --argjson fixture_manifest "$FIXTURE_MANIFEST" \
        --arg rch_worker "$RCH_WORKER_OBSERVED" \
        --arg rch_required "${RCH_REQUIRE_REMOTE:-0}" \
        --arg generated_at "$GENERATED_AT" \
        '{
          schema: $schema,
          run_id: $run_id,
          scenario_id: $scenario_id,
          step_id: $step_id,
          source_revision: $source_revision,
          baseline_revision: $baseline_revision,
          source_drift: ($source_revision != $baseline_revision),
          rustc: $rustc,
          cargo: $cargo,
          toolchain_provenance_scope: $toolchain_provenance_scope,
          command: $command,
          features: $features,
          fixture_id: $fixture_id,
          target: $target,
          host: $host,
          execution_tree: $execution_tree,
          controller_dirty_paths: ($controller_dirty_paths | split("\n") | map(select(length > 0))),
          execution_transport: $execution_transport,
          fixture_digest: $fixture_digest,
          fixture_manifest: $fixture_manifest,
          rch_worker: $rch_worker,
          rch_require_remote: $rch_required,
          generated_at_utc: $generated_at
        }' >"$PROVENANCE"
}

case "$SCENARIO_ID" in
    contract)
        FEATURE_PROFILE="default"
        FIXTURE_ID="dependency-capability-baseline-v1"
        FIXTURE_PATHS=(
            artifacts/dependency_capability_baseline_v1.json
            artifacts/dependency_capability_registry_v1.json
            tests/dependency_capability_baseline_contract.rs
            docs/dependency_capability_baseline.md
            scripts/run_dependency_capability_baseline.sh
        )
        EXECUTION_TREE="clean committed HEAD; controller dirt excluded from remote Cargo"
        EXECUTION_TRANSPORT="RCH_REMOTE"
        MINIMUM_TESTS=26
        COMMAND=(
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay --
            env
            "CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_capability_baseline_contract"
            CARGO_INCREMENTAL=0
            CARGO_PROFILE_TEST_DEBUG=0
            "RUSTFLAGS=-D warnings -C debuginfo=0"
            cargo test -p asupersync
            --test dependency_capability_baseline_contract
            --
            --nocapture
        )
        ;;
    consumer-default)
        FEATURE_PROFILE="consumer-default"
        FIXTURE_ID="dependency-capability-baseline-consumer-v1"
        FIXTURE_PATHS=(
            tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml
            tests/fixtures/dependency-capability-baseline-consumer/Cargo.lock
            tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs
        )
        EXECUTION_TREE="clean committed HEAD; controller dirt excluded from remote Cargo"
        EXECUTION_TRANSPORT="RCH_REMOTE"
        MINIMUM_TESTS=7
        COMMAND=(
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay --
            env
            "CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_capability_consumer_default"
            CARGO_INCREMENTAL=0
            CARGO_PROFILE_TEST_DEBUG=0
            "RUSTFLAGS=-D warnings -C debuginfo=0"
            cargo test
            --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml
            --locked
            --
            --nocapture
        )
        ;;
    consumer-full)
        FEATURE_PROFILE="consumer-full"
        FIXTURE_ID="dependency-capability-baseline-consumer-v1"
        FIXTURE_PATHS=(
            tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml
            tests/fixtures/dependency-capability-baseline-consumer/Cargo.lock
            tests/fixtures/dependency-capability-baseline-consumer/src/lib.rs
        )
        EXECUTION_TREE="clean committed HEAD; controller dirt excluded from remote Cargo"
        EXECUTION_TRANSPORT="RCH_REMOTE"
        MINIMUM_TESTS=9
        COMMAND=(
            env RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --no-overlay --
            env
            "CARGO_TARGET_DIR=${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_capability_consumer_full"
            CARGO_INCREMENTAL=0
            CARGO_PROFILE_TEST_DEBUG=0
            "RUSTFLAGS=-D warnings -C debuginfo=0"
            cargo test
            --manifest-path tests/fixtures/dependency-capability-baseline-consumer/Cargo.toml
            --features full-profile
            --locked
            --
            --nocapture
        )
        ;;
    catalog)
        FEATURE_PROFILE="static-catalog"
        FIXTURE_ID="dependency-capability-baseline-v1"
        FIXTURE_PATHS=(artifacts/dependency_capability_baseline_v1.json)
        EXECUTION_TREE="controller working tree; static catalog input is content-hashed; no Cargo executed"
        EXECUTION_TRANSPORT="LOCAL_STATIC"
        MINIMUM_TESTS=1
        COMMAND=(
            jq -e
            '
              (.schema_version == 1) and
              (.capability_baselines | length == 50) and
              (.evidence_catalog | length >= 40) and
              ([.capability_baselines[].capability_id] | unique | length == 50) and
              ([.capability_baselines[].cutover_eligible] | all(. == false)) and
              ([.capability_baselines[].cases | keys | length] | all(. == 6)) and
              ([.capability_baselines[].cases[].disposition] |
                all(. == "EVIDENCE" or . == "NOT_APPLICABLE" or startswith("BLOCKED_")))
            '
            artifacts/dependency_capability_baseline_v1.json
        )
        ;;
esac

FIXTURE_MANIFEST_LINES="$(
    for fixture_path in "${FIXTURE_PATHS[@]}"; do
        fixture_sha256="$(sha256_file "$PROJECT_ROOT/$fixture_path")"
        printf '%s  %s\n' "$fixture_sha256" "$fixture_path"
    done
)"
FIXTURE_MANIFEST="$(
    jq -Rsc '
      split("\n")
      | map(select(length > 0))
      | map(capture("^(?<sha256>[0-9a-f]{64})  (?<path>.+)$"))
    ' <<<"$FIXTURE_MANIFEST_LINES"
)"
FIXTURE_DIGEST="$(
    printf '%s\n' "$FIXTURE_MANIFEST_LINES" | sha256_stream
)"
printf -v COMMAND_DISPLAY '%q ' "${COMMAND[@]}"
COMMAND_DISPLAY="${COMMAND_DISPLAY% }"

{
    printf '#!/usr/bin/env bash\nset -euo pipefail\n'
    printf 'cd %q\n' "$PROJECT_ROOT"
    printf 'RCH_REQUIRE_REMOTE=1 '
    printf '%q ' bash scripts/run_dependency_capability_baseline.sh "$SCENARIO_ID"
    printf '\n'
} >"$REPLAY"
chmod 0755 "$REPLAY"

emit_event "run_started" "RUNNING" "remote-only Cargo policy admitted; static catalog runs no Cargo"

START_NS="$(date +%s%N)"
COMMAND_STATUS=0
LOGGING_STATUS=0
BLOCKER_REASON=""
REDACTION_SELF_TEST="$(
    printf 'canary=%s' "$CANARY" | redact_stream
)"
if [[ "$REDACTION_SELF_TEST" == "canary=[REDACTED]" ]]; then
    REDACTION_SELF_TEST_STATUS="PASS"
    emit_event "redaction_filter_self_test" "PASS" "synthetic canary was removed before retention"
else
    REDACTION_SELF_TEST_STATUS="FAIL"
    emit_event "redaction_filter_self_test" "FAIL" "synthetic canary filter did not produce the expected sentinel"
fi
if [[ "${RCH_REQUIRE_REMOTE:-}" != "1" ]]; then
    COMMAND_STATUS=75
    BLOCKER_REASON="RCH_REQUIRE_REMOTE=1 was not present in the controller environment; local Cargo fallback was refused"
    printf '%s\n' "$BLOCKER_REASON" | tee -a "$STDERR_LOG" "$STEP_STDERR" >&2
    emit_event "admission_blocked" "BLOCKED_EXTERNAL" "$BLOCKER_REASON"
else
    emit_event "step_started" "RUNNING" "executing declared scenario command"
    set +e
    (
        cd "$PROJECT_ROOT"
        CAP_A2_LOG_REDACTION_CANARY="$CANARY" "${COMMAND[@]}"
    ) > >(redact_stream | tee -a "$STEP_STDOUT" "$STDOUT_LOG") \
        2> >(redact_stream | tee -a "$STEP_STDERR" "$STDERR_LOG" >&2)
    COMMAND_STATUS=$?
    wait
    LOGGING_STATUS=$?
    set -e
fi
END_NS="$(date +%s%N)"
DURATION_MS="$(((END_NS - START_NS) / 1000000))"
RCH_WORKER_OBSERVED="$(
    {
        grep -hEo 'Selected worker: [A-Za-z0-9._-]+' "$STEP_STDOUT" "$STEP_STDERR" || true
        grep -hEo '\[RCH\] remote [A-Za-z0-9._-]+' "$STEP_STDOUT" "$STEP_STDERR" || true
    } | awk '{ print $NF }' | tail -n 1
)"
if [[ "$EXECUTION_TRANSPORT" == "LOCAL_STATIC" ]]; then
    RCH_WORKER_OBSERVED="not-applicable"
elif [[ -z "$RCH_WORKER_OBSERVED" ]]; then
    RCH_WORKER_OBSERVED="unknown"
fi
PROVENANCE_STATUS="PASS"
if [[ "$EXECUTION_TRANSPORT" == "RCH_REMOTE" &&
    "$COMMAND_STATUS" -eq 0 &&
    "$RCH_WORKER_OBSERVED" == "unknown" ]]; then
    PROVENANCE_STATUS="FAIL"
    printf 'provenance failure: successful remote-required command did not identify its RCH worker\n' |
        tee -a "$STDERR_LOG" "$STEP_STDERR" >&2
fi
write_provenance

if [[ "$SCENARIO_ID" == "catalog" && "$COMMAND_STATUS" -eq 0 ]]; then
    OBSERVED_TESTS=1
else
    OBSERVED_TESTS="$(
        {
            grep -hEo '[0-9]+ passed' "$STEP_STDOUT" "$STEP_STDERR" || true
        } | awk '{ total += $1 } END { print total + 0 }'
    )"
fi

OUTCOME="PASS"
if [[ -n "$BLOCKER_REASON" ]]; then
    OUTCOME="BLOCKED_EXTERNAL"
elif [[ "$COMMAND_STATUS" -ne 0 ]]; then
    OUTCOME="FAIL"
elif [[ "$LOGGING_STATUS" -ne 0 ]]; then
    OUTCOME="FAIL"
    printf 'logging pipeline failure: status %s\n' "$LOGGING_STATUS" |
        tee -a "$STDERR_LOG" "$STEP_STDERR" >&2
elif [[ "$PROVENANCE_STATUS" != "PASS" ]]; then
    OUTCOME="FAIL"
elif ((OBSERVED_TESTS < MINIMUM_TESTS)); then
    OUTCOME="FAIL"
    printf 'minimum_tests failure: expected at least %s, observed %s\n' \
        "$MINIMUM_TESTS" "$OBSERVED_TESTS" |
        tee -a "$STDERR_LOG" "$STEP_STDERR" >&2
fi

REDACTION_STATUS="$REDACTION_SELF_TEST_STATUS"
if grep -Fq "$CANARY" "$STDOUT_LOG" "$STDERR_LOG"; then
    REDACTION_STATUS="FAIL"
    OUTCOME="FAIL"
    printf 'redaction canary leaked into retained logs\n' |
        tee -a "$STDERR_LOG" "$STEP_STDERR" >&2
fi

RESIDUAL_CHILDREN="$(jobs -pr | wc -l | tr -d ' ')"
CLEANUP_STATUS="PASS"
if [[ "$RESIDUAL_CHILDREN" != "0" ]]; then
    CLEANUP_STATUS="FAIL"
    OUTCOME="FAIL"
fi
GENERATED_PATHS="$(
    {
        find "$RUN_DIR" -mindepth 1 -print
        printf '%s\n' "$SUMMARY"
    } |
        sed "s#^$RUN_DIR/##" |
        LC_ALL=C sort -u |
        jq -Rsc 'split("\n") | map(select(length > 0))'
)"
GENERATED_PATH_COUNT="$(jq 'length' <<<"$GENERATED_PATHS")"
SOURCE_REVISION="$(jq -r '.source_revision' "$PROVENANCE")"
SOURCE_DRIFT="$(jq -r '.source_drift' "$PROVENANCE")"

jq -n \
    --arg schema "dependency-capability-baseline-summary-v1" \
    --arg run_id "$RUN_ID" \
    --arg scenario_id "$SCENARIO_ID" \
    --arg step_id "$STEP_ID" \
    --arg outcome "$OUTCOME" \
    --arg source_revision "$SOURCE_REVISION" \
    --arg baseline_revision "$BASELINE_REVISION" \
    --argjson source_drift "$SOURCE_DRIFT" \
    --arg command "$COMMAND_DISPLAY" \
    --arg features "$FEATURE_PROFILE" \
    --arg fixture_id "$FIXTURE_ID" \
    --arg fixture_digest "$FIXTURE_DIGEST" \
    --argjson fixture_manifest "$FIXTURE_MANIFEST" \
    --argjson command_exit "$COMMAND_STATUS" \
    --argjson minimum_tests "$MINIMUM_TESTS" \
    --argjson observed_tests "$OBSERVED_TESTS" \
    --argjson duration_ms "$DURATION_MS" \
    --arg redaction_status "$REDACTION_STATUS" \
    --arg cleanup_status "$CLEANUP_STATUS" \
    --argjson residual_children "$RESIDUAL_CHILDREN" \
    --argjson generated_path_count "$GENERATED_PATH_COUNT" \
    --argjson generated_paths "$GENERATED_PATHS" \
    --arg blocker_reason "$BLOCKER_REASON" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema: $schema,
      run_id: $run_id,
      scenario_id: $scenario_id,
      step_id: $step_id,
      outcome: $outcome,
      source_revision: $source_revision,
      baseline_revision: $baseline_revision,
      source_drift: $source_drift,
      command: $command,
      features: $features,
      fixture_id: $fixture_id,
      fixture_digest: $fixture_digest,
      fixture_manifest: $fixture_manifest,
      command_exit: $command_exit,
      minimum_tests: $minimum_tests,
      observed_tests: $observed_tests,
      duration_ms: $duration_ms,
      redaction_status: $redaction_status,
      cleanup_status: $cleanup_status,
      residual_children: $residual_children,
      generated_path_count: $generated_path_count,
      generated_paths: $generated_paths,
      blocker_reason: (if $blocker_reason == "" then null else $blocker_reason end),
      artifacts: {
        events_ndjson: "events.ndjson",
        stdout_log: "stdout.log",
        stderr_log: "stderr.log",
        provenance_json: "provenance.json",
        replay_sh: "replay.sh"
      },
      generated_at_utc: $generated_at,
      no_claim_boundary: "This focused CAP A2 run is incumbent baseline evidence only; it does not prove replacement parity, broad workspace health, release readiness, performance improvement, or cutover eligibility."
    }' >"$SUMMARY"

emit_event "step_finished" "$OUTCOME" "scenario command and evidence checks completed"
emit_event "run_finished" "$OUTCOME" "summary and replay artifacts retained"

printf 'CAP A2 baseline scenario: %s\n' "$SCENARIO_ID"
printf '  outcome:          %s\n' "$OUTCOME"
printf '  tests:            %s observed / %s minimum\n' "$OBSERVED_TESTS" "$MINIMUM_TESTS"
printf '  duration_ms:      %s\n' "$DURATION_MS"
printf '  redaction:        %s\n' "$REDACTION_STATUS"
printf '  cleanup:          %s (%s residual children)\n' "$CLEANUP_STATUS" "$RESIDUAL_CHILDREN"
printf '  source_revision:  %s (drift=%s)\n' "$SOURCE_REVISION" "$SOURCE_DRIFT"
printf '  artifacts:        %s\n' "$RUN_DIR"
printf '  replay:           %s\n' "$REPLAY"

if [[ "$OUTCOME" != "PASS" ]]; then
    exit 1
fi
