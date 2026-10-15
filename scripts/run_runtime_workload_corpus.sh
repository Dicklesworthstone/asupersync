#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CORPUS_ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_workload_corpus_v1.json"
COORDINATION_CONTRACT="${PROJECT_ROOT}/artifacts/agent_swarm_coordination_workload_contract_v1.json"
OUTPUT_ROOT="${WORKLOAD_CORPUS_OUTPUT_DIR:-${PROJECT_ROOT}/target/workload-corpus}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
SYNTHESIZE_COORDINATION_PACK=0
COORDINATION_BUNDLE=""
COORDINATION_FIXTURE_ID=""
COORDINATION_GENERATED_AT="${WORKLOAD_CORPUS_GENERATED_AT:-2026-05-05T05:00:00Z}"
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"

declare -a SELECTED_WORKLOADS=()

usage() {
    cat <<'EOF'
Usage: ./scripts/run_runtime_workload_corpus.sh [options]

Options:
  --list                  List canonical workload IDs and exit
  --workload <id>         Run one workload (repeatable)
  --output-root <dir>     Override local bundle root (default: target/workload-corpus)
  --synthesize-coordination-pack
                          Convert a coordination bundle into an expansion pack
  --coordination-bundle <path>
                          Explicit coordination workload bundle JSON input
  --coordination-fixture  Use the accepted checked coordination fixture
  --coordination-fixture-id <id>
                          Use a named checked coordination fixture
  --generated-at <ts>     Stable generated_at for synthesis artifacts
  -h, --help              Show help
EOF
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for workload corpus execution" >&2
        exit 1
    fi
    if [ ! -f "$CORPUS_ARTIFACT" ]; then
        echo "FATAL: workload corpus artifact missing at ${CORPUS_ARTIFACT}" >&2
        exit 1
    fi
}

require_coordination_contract() {
    require_tools
    if [ ! -f "$COORDINATION_CONTRACT" ]; then
        echo "FATAL: coordination workload contract missing at ${COORDINATION_CONTRACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

render_command() {
    local rendered
    printf -v rendered '%q ' "$@"
    printf '%s' "${rendered% }"
}

is_rch_local_fallback_log() {
    local log_file="$1"
    grep -Eiq '^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally' "$log_file" 2>/dev/null
}

build_workload_command_argv() {
    local workload_id="$1"
    local output_name="$2"
    local -n output_ref="$output_name"
    local synth_root="target/workload-corpus"

    case "$workload_id" in
        AA01-WL-CPU-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=bench-release"
                "WORKLOAD_CONFIG_REF=scripts/run_perf_e2e.sh::phase0_baseline,scheduler_benchmark"
                "ASUPERSYNC_SEED=0xAA010201"
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/run_perf_e2e.sh
                --bench
                phase0_baseline
                --bench
                scheduler_benchmark
                --no-compare
            )
            ;;
        AA01-WL-CANCEL-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=lab-deterministic"
                "WORKLOAD_CONFIG_REF=tests/cancellation_stress_e2e.rs::cancel_storm_single_region"
                "TEST_SEED=0xAA010202"
                "ASUPERSYNC_SEED=0xAA010202"
                "${RCH_BIN}"
                exec
                --
                env
                "CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_runtime_workload_corpus_cancel}"
                "${CARGO_BIN}"
                test
                --test
                cancellation_stress_e2e
                cancel_storm_single_region
                --
                --nocapture
            )
            ;;
        AA01-WL-IO-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=native-e2e"
                "WORKLOAD_CONFIG_REF=scripts/test_transport_e2e.sh::e2e_transport/all_features"
                "TEST_SEED=0xAA010203"
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/test_transport_e2e.sh
            )
            ;;
        AA01-WL-BURST-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=native-e2e"
                "WORKLOAD_CONFIG_REF=scripts/test_scheduler_wakeup_e2e.sh::scheduler_backoff+scheduler_lane_fairness+stress_tests"
                "TEST_SEED=0xAA010204"
                "SKIP_LOOM=1"
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/test_scheduler_wakeup_e2e.sh
            )
            ;;
        AA01-WL-TIMER-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=lab-deterministic"
                "WORKLOAD_CONFIG_REF=tests/time_e2e.rs::test_timer_wheel_basic_operations"
                "TEST_SEED=0xAA010205"
                "ASUPERSYNC_SEED=0xAA010205"
                "${RCH_BIN}"
                exec
                --
                env
                "CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_runtime_workload_corpus_timer}"
                "${CARGO_BIN}"
                test
                --test
                time_e2e
                test_timer_wheel_basic_operations
                --
                --nocapture
            )
            ;;
        AA01-WL-FANIO-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=native-e2e"
                "WORKLOAD_CONFIG_REF=scripts/test_messaging_e2e.sh::e2e_messaging/all_features"
                "TEST_SEED=0xAA010206"
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/test_messaging_e2e.sh
            )
            ;;
        AA01-WL-DIST-001)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=distributed-shadow"
                "WORKLOAD_CONFIG_REF=scripts/test_distributed_e2e.sh::e2e_distributed+distributed_trace_remote_invariants"
                "TEST_SEED=0xAA010207"
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/test_distributed_e2e.sh
            )
            ;;
        AA01-WL-IO-HTTP-EX1)
            output_ref=(
                env
                "WORKLOAD_ID=${workload_id}"
                "RUNTIME_PROFILE=native-e2e"
                "WORKLOAD_CONFIG_REF=scripts/test_http_e2e.sh::http_e2e/all_features"
                "TEST_SEED=0xAA010208"
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/test_http_e2e.sh
            )
            ;;
        ASWARM-WL-LOCK-001|ASWARM-WL-RCH-001|ASWARM-WL-DIRTY-001|ASWARM-WL-ARTIFACT-001|ASWARM-WL-FANOUT-001|ASWARM-WL-STALE-001|ASWARM-WL-LATENCY-001)
            output_ref=(
                env
                "RCH_BIN=${RCH_BIN}"
                bash
                ./scripts/run_runtime_workload_corpus.sh
                --synthesize-coordination-pack
                --coordination-fixture-id
                accepted-all-families
                --output-root
                "${synth_root}"
                --generated-at
                2026-05-05T05:00:00Z
            )
            ;;
        *)
            echo "FATAL: unsupported workload command mapping for ${workload_id}" >&2
            return 1
            ;;
    esac
}

load_workload_json() {
    local workload_id="$1"
    jq -c --arg workload_id "$workload_id" '
        .workloads[]
        | select(.workload_id == $workload_id)
    ' "$CORPUS_ARTIFACT"
}

list_workloads() {
    jq -r '
        .workloads[]
        | [.workload_id, .family, .regime, .runtime_profile, .entrypoint_kind]
        | @tsv
    ' "$CORPUS_ARTIFACT" \
        | while IFS=$'\t' read -r workload_id family regime runtime_profile entrypoint_kind; do
            printf '%-20s family=%-18s regime=%-28s profile=%-20s kind=%s\n' \
                "$workload_id" \
                "$family" \
                "$regime" \
                "$runtime_profile" \
                "$entrypoint_kind"
        done
}

coordination_fixture_bundle_json() {
    local fixture_id="$1"
    jq -c --arg fixture_id "$fixture_id" '
        .coordination_workload_synthesis.fixture_bundles[]
        | select(.fixture_id == $fixture_id)
        | .bundle
    ' "$CORPUS_ARTIFACT"
}

coordination_bundle_json() {
    if [[ -n "$COORDINATION_BUNDLE" ]]; then
        if [[ ! -f "$COORDINATION_BUNDLE" ]]; then
            echo "FATAL: coordination bundle missing at ${COORDINATION_BUNDLE}" >&2
            return 2
        fi
        jq -c '.' "$COORDINATION_BUNDLE"
        return
    fi

    local fixture_id="${COORDINATION_FIXTURE_ID:-accepted-all-families}"
    local fixture_json
    fixture_json="$(coordination_fixture_bundle_json "$fixture_id")"
    if [[ -z "$fixture_json" ]]; then
        echo "FATAL: unknown coordination fixture id: ${fixture_id}" >&2
        return 2
    fi
    printf '%s\n' "$fixture_json"
}

synthesize_coordination_pack() {
    require_coordination_contract

    if [[ -n "$COORDINATION_BUNDLE" && -n "$COORDINATION_FIXTURE_ID" ]]; then
        echo "FATAL: use either --coordination-bundle or --coordination-fixture-id, not both" >&2
        return 2
    fi

    local bundle_json
    bundle_json="$(coordination_bundle_json)"
    local run_id
    run_id="$(jq -r '.run_id // "coordination-bundle"' <<<"$bundle_json")"
    local out_dir="${OUTPUT_ROOT}/coordination-expansion/${run_id}"
    local pack_path="${out_dir}/coordination-workload-expansion-pack.json"
    local evidence_path="${out_dir}/coordination-scheduler-evidence-inputs.json"
    local report_path="${out_dir}/coordination-workload-synthesis-report.json"
    local jsonl_path="${out_dir}/coordination-workload-expansion.jsonl"
    local summary_path="${out_dir}/coordination-workload-synthesis.summary.txt"

    mkdir -p "$out_dir"

    jq -n \
        --slurpfile corpus "$CORPUS_ARTIFACT" \
        --slurpfile contract "$COORDINATION_CONTRACT" \
        --argjson bundle "$bundle_json" \
        --arg generated_at "$COORDINATION_GENERATED_AT" '
        def synth: $corpus[0].coordination_workload_synthesis;
        def mappings: synth.scenario_family_mapping;
        def required: synth.required_scenario_families;
        def accepted_events:
            [($bundle.events // [])
             | .[]
             | select((.refusal_reason // "") == "" and (.redaction_verdict // "") != "refused")];
        def accepted_families:
            [accepted_events[].workload_family] | unique;
        def missing_families:
            required - accepted_families;
        def events_for($family):
            [accepted_events[] | select(.workload_family == $family)];
        def as_number($value):
            (($value // 0) | tonumber? // 0);
        def max_queue_depth($events):
            ([$events[] | as_number(.queue_depth_or_lock_state.queue_depth)] | max // 0);
        def queue_depth_bucket($depth):
            if $depth >= 16 then "q16_plus"
            elif $depth >= 8 then "q08_15"
            elif $depth >= 4 then "q04_07"
            elif $depth >= 1 then "q01_03"
            else "q00"
            end;
        def stable_command_hash($text):
            "cmdclass:" + (
              ($text | tostring | explode)
              | reduce .[] as $codepoint (0; ((. * 131 + $codepoint) % 1000000007))
              | tostring
            );
        def rch_pressure_summary($events):
            max_queue_depth($events) as $max_depth
            | {
                queue_depth_bucket: queue_depth_bucket($max_depth),
                max_queue_depth: $max_depth,
                proof_fanout_count: ($events | length),
                artifact_retrieval_tail_bucket:
                  (if (([$events[] | (.artifact_refs // []) | length] | add // 0) > 0)
                   then "artifact_refs_observed"
                   else "artifact_tail_unknown"
                   end),
                timeout_or_refusal_reasons:
                  ([$events[]
                    | (.queue_depth_or_lock_state.timeout_or_refusal_reason // .refusal_reason // "")
                    | select(. != "")]
                   | unique),
                command_class_hashes:
                  ([$events[]
                    | stable_command_hash((.command_class // "unknown") + "|" + (.event_kind // "unknown"))]
                   | unique)
              };
        def pressure_summary($mapping; $events):
            if $mapping.family == "concurrent_rch_proofs" then
              {rch: rch_pressure_summary($events)}
            else
              {}
            end;

        {
          schema_version: "runtime-workload-coordination-expansion-pack-v1",
          contract_version: $corpus[0].contract_version,
          source_contract_version: $contract[0].contract_version,
          pack_id: synth.pack_id,
          baseline_denominator: false,
          generated_at: $generated_at,
          source_run_id: ($bundle.run_id // "coordination-bundle"),
          source_bundle_hash: ($bundle.source_bundle_hash // "sha256:missing-source-bundle-hash"),
          required_scenario_families: required,
          covered_scenario_families: accepted_families,
          missing_scenario_families: missing_families,
          workloads: [
            mappings[] as $mapping
            | events_for($mapping.family) as $family_events
            | select(($family_events | length) > 0)
            | {
                workload_id: $mapping.workload_id,
                family: "agent-swarm-coordination",
                scenario_family: $mapping.family,
                scenario_id: $mapping.scenario_id,
                runtime_profile: $mapping.runtime_profile,
                semantic_pressure: $mapping.semantic_pressure,
                provenance_only_context: $mapping.provenance_only_context,
                source_event_kinds: ($family_events | map(.event_kind) | unique),
                source_event_count: ($family_events | length),
                source_hashes: ($family_events | map(.source_hash) | unique),
                source_bundle_hash: ($bundle.source_bundle_hash // "sha256:missing-source-bundle-hash"),
                replay_command: $mapping.replay_command,
                entry_command: $mapping.entry_command,
                expected_artifact_globs: $mapping.expected_artifact_globs,
                scheduler_evidence_input_id: $mapping.scheduler_evidence_input_id,
                pressure_summary: pressure_summary($mapping; $family_events)
              }
          ],
          refused_bundles:
            if (missing_families | length) == 0 then []
            else [{
              source_run_id: ($bundle.run_id // "coordination-bundle"),
              refusal_reason: "missing_scenario_dimensions",
              missing_scenario_families: missing_families
            }]
            end
        }
    ' >"$pack_path"

    jq -c '.workloads[]' "$pack_path" >"$jsonl_path"

    jq -n \
        --slurpfile pack "$pack_path" '
        {
          schema_version: "asupersync.scheduler-coordination-evidence-inputs.v1",
          source_pack_id: $pack[0].pack_id,
          source_bundle_hash: $pack[0].source_bundle_hash,
          source_run_id: $pack[0].source_run_id,
          evidence_inputs: [
            $pack[0].workloads[]
            | {
                evidence_input_id: .scheduler_evidence_input_id,
                workload_id: .workload_id,
                workload_class: "interactive_swarm",
                scenario_family: .scenario_family,
                semantic_pressure: .semantic_pressure,
                provenance_only_context: .provenance_only_context,
                source_event_count: .source_event_count,
                source_hashes: .source_hashes,
                source_bundle_hash: .source_bundle_hash,
                pressure_summary: .pressure_summary
              }
          ]
        }
    ' >"$evidence_path"

    jq -n \
        --slurpfile pack "$pack_path" \
        --arg pack_path "$pack_path" \
        --arg evidence_path "$evidence_path" \
        --arg report_path "$report_path" \
        --arg jsonl_path "$jsonl_path" \
        --arg summary_path "$summary_path" '
        ($pack[0].missing_scenario_families | length) as $missing_count
        | {
            schema_version: "runtime-workload-coordination-synthesis-report-v1",
            pack_id: $pack[0].pack_id,
            source_run_id: $pack[0].source_run_id,
            source_bundle_hash: $pack[0].source_bundle_hash,
            status: (if $missing_count == 0 then "passed" else "refused" end),
            accepted_workload_count: ($pack[0].workloads | length),
            refused_bundle_count: ($pack[0].refused_bundles | length),
            missing_scenario_families: $pack[0].missing_scenario_families,
            rch_pressure_summary:
              ([$pack[0].workloads[]
                | select(.scenario_family == "concurrent_rch_proofs")
                | .pressure_summary.rch][0] // {}),
            first_failure_line:
              (if $missing_count == 0 then ""
               else "missing_scenario_dimensions: " + ($pack[0].missing_scenario_families | join(","))
               end),
            artifact_paths: {
              expansion_pack: $pack_path,
              scheduler_evidence_inputs: $evidence_path,
              report: $report_path,
              workloads_jsonl: $jsonl_path,
              summary: $summary_path
            }
          }
    ' >"$report_path"

    {
        echo "coordination_workload_synthesis run_id=${run_id} pack=agent-swarm-coordination-pressure"
        echo "family	source_events	semantic_pressure	provenance_only_context	rch_queue_depth_bucket"
        jq -r '
            .workloads[]
            | [
                .scenario_family,
                (.source_event_kinds | join(",")),
                (.semantic_pressure | join(",")),
                (.provenance_only_context | join(",")),
                (if .scenario_family == "concurrent_rch_proofs"
                 then (.pressure_summary.rch.queue_depth_bucket // "q00")
                 else ""
                 end)
              ]
            | @tsv
        ' "$pack_path"
        jq -r '
            .refused_bundles[]
            | "refused\t" + (.missing_scenario_families | join(",")) + "\tmissing_scenario_dimensions\trefusal_provenance"
        ' "$pack_path"
    } >"$summary_path"

    local status
    status="$(jq -r '.status' "$report_path")"
    echo "coordination_synthesis_result run_id=${run_id} status=${status} pack=${pack_path}"
    echo "artifact ${pack_path}"
    echo "artifact ${evidence_path}"
    echo "artifact ${report_path}"
    echo "artifact ${jsonl_path}"
    echo "artifact ${summary_path}"

    [[ "$status" == "passed" ]]
}

append_result() {
    local entry="$1"
    if [[ -z "${RESULTS_JSON:-}" ]]; then
        RESULTS_JSON="$entry"
    else
        RESULTS_JSON="${RESULTS_JSON},${entry}"
    fi
}

run_workload() {
    local workload_id="$1"
    local workload_json
    workload_json="$(load_workload_json "$workload_id")"
    if [[ -z "$workload_json" ]]; then
        echo "FATAL: unknown workload id: ${workload_id}" >&2
        return 1
    fi

    local family scenario_id regime runtime_profile seed config_ref entrypoint_kind
    local entry_command replay_command expected_artifacts expected_evidence rendered_command
    local -a command_args=()
    family="$(jq -r '.family' <<<"$workload_json")"
    scenario_id="$(jq -r '.scenario_id' <<<"$workload_json")"
    regime="$(jq -r '.regime' <<<"$workload_json")"
    runtime_profile="$(jq -r '.runtime_profile' <<<"$workload_json")"
    seed="$(jq -r '.seed' <<<"$workload_json")"
    config_ref="$(jq -r '.config_ref' <<<"$workload_json")"
    entrypoint_kind="$(jq -r '.entrypoint_kind' <<<"$workload_json")"
    entry_command="$(jq -r '.entry_command' <<<"$workload_json")"
    replay_command="$(jq -r '.replay_command' <<<"$workload_json")"
    expected_artifacts="$(jq -c '.expected_artifacts' <<<"$workload_json")"
    expected_evidence="$(jq -c '.expected_evidence' <<<"$workload_json")"
    build_workload_command_argv "$workload_id" command_args
    rendered_command="$(render_command "${command_args[@]}")"

    local workload_dir="${RUN_DIR}/${workload_id}"
    local log_file="${workload_dir}/run.log"
    local summary_file="${workload_dir}/bundle_manifest.json"
    local started_ts ended_ts status rc rch_local_fallback rch_local_fallback_marker failure_class

    mkdir -p "$workload_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    export WORKLOAD_ID="$workload_id"
    export RUNTIME_PROFILE="$runtime_profile"
    export WORKLOAD_CONFIG_REF="$config_ref"
    export ASUPERSYNC_WORKLOAD_ID="$workload_id"
    export ASUPERSYNC_RUNTIME_PROFILE="$runtime_profile"
    export ASUPERSYNC_WORKLOAD_CONFIG_REF="$config_ref"
    export TEST_SEED="$seed"
    export ASUPERSYNC_SEED="$seed"

    echo ">>> Running ${workload_id}"
    echo "    family: ${family}"
    echo "    regime: ${regime}"
    echo "    profile: ${runtime_profile}"
    echo "    seed: ${seed}"
    echo "    command: ${rendered_command}"

    set +e
    pushd "$PROJECT_ROOT" >/dev/null
    "${command_args[@]}" 2>&1 | tee "$log_file"
    rc=${PIPESTATUS[0]}
    popd >/dev/null
    set -e

    rch_local_fallback=false
    rch_local_fallback_marker=""
    failure_class=""
    if is_rch_local_fallback_log "$log_file"; then
        rc=86
        rch_local_fallback=true
        failure_class="rch_local_fallback"
        rch_local_fallback_marker="${workload_dir}/rch_local_fallback.txt"
        printf 'rch local fallback detected; refusing local cargo execution\n' >"$rch_local_fallback_marker"
        printf '\nFATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_file"
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    status="failed"
    if [[ "$rc" -eq 0 ]]; then
        status="passed"
    fi

    cat >"$summary_file" <<EOF
{
  "schema_version": "runtime-workload-bundle-v1",
  "contract_version": "runtime-workload-corpus-v1",
  "workload_id": "$(json_escape "$workload_id")",
  "family": "$(json_escape "$family")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "regime": "$(json_escape "$regime")",
  "runtime_profile": "$(json_escape "$runtime_profile")",
  "seed": "$(json_escape "$seed")",
  "workload_config_ref": "$(json_escape "$config_ref")",
  "entrypoint_kind": "$(json_escape "$entrypoint_kind")",
  "artifact_path": "$(json_escape "$summary_file")",
  "run_log_path": "$(json_escape "$log_file")",
  "entry_command": "$(json_escape "$rendered_command")",
  "replay_command": "$(json_escape "$replay_command")",
  "status": "$(json_escape "$status")",
  "failure_class": "$(json_escape "$failure_class")",
  "rch_local_fallback": ${rch_local_fallback},
  "rch_local_fallback_marker": "$(json_escape "$rch_local_fallback_marker")",
  "exit_code": ${rc},
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")",
  "expected_artifacts": ${expected_artifacts},
  "expected_evidence": ${expected_evidence}
}
EOF

    append_result "$(jq -c '.' "$summary_file")"

    [[ "$rc" -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --workload)
            SELECTED_WORKLOADS+=("${2:-}")
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
            shift 2
            ;;
        --synthesize-coordination-pack)
            SYNTHESIZE_COORDINATION_PACK=1
            shift
            ;;
        --coordination-bundle)
            COORDINATION_BUNDLE="${2:-}"
            shift 2
            ;;
        --coordination-fixture)
            COORDINATION_FIXTURE_ID="accepted-all-families"
            shift
            ;;
        --coordination-fixture-id)
            COORDINATION_FIXTURE_ID="${2:-}"
            shift 2
            ;;
        --generated-at)
            COORDINATION_GENERATED_AT="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_tools

if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_workloads
    exit 0
fi

if [[ "$SYNTHESIZE_COORDINATION_PACK" -eq 1 ]]; then
    synthesize_coordination_pack
    exit $?
fi

if [[ "${#SELECTED_WORKLOADS[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_WORKLOADS < <(jq -r '.default_core_set[]' "$CORPUS_ARTIFACT")
fi

mkdir -p "$RUN_DIR"
RESULTS_JSON=""
OVERALL_RC=0

for workload_id in "${SELECTED_WORKLOADS[@]}"; do
    if ! run_workload "$workload_id"; then
        OVERALL_RC=1
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<EOF
{
  "schema_version": "runtime-workload-run-report-v1",
  "contract_version": "runtime-workload-corpus-v1",
  "artifact_path": "$(json_escape "$RUN_REPORT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "selected_workloads": $(jq -nc --argjson ids "$(printf '%s\n' "${SELECTED_WORKLOADS[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" '$ids'),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
EOF

echo ""
echo "==================================================================="
echo "                  RUNTIME WORKLOAD CORPUS SUMMARY                  "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
