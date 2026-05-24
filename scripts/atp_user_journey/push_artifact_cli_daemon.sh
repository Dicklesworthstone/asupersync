#!/usr/bin/env bash
# ATP-NR10 local CLI-to-daemon user journey.

set -euo pipefail

REPORT_SCHEMA_VERSION="asupersync.atp.user_journey.cli_daemon_report.v1"
EVENT_SCHEMA_VERSION="asupersync.atp.user_journey.cli_daemon_event.v1"
SCENARIO_ID="cli_push_artifact_daemon_log"
BEAD_ID="asupersync-vk4kcf.9"
DEFAULT_OUTPUT_ROOT="${ATP_USER_JOURNEY_OUTPUT_ROOT:-target/e2e-results/atp_user_journey}"
DEFAULT_RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
WAIT_DEADLINE_SEC="${ATP_USER_JOURNEY_WAIT_DEADLINE_SEC:-10}"

usage() {
    cat <<'USAGE'
Usage:
  scripts/atp_user_journey/push_artifact_cli_daemon.sh [options]

Options:
  --output-root <dir>  Directory where run artifacts are written.
  --run-id <id>        Deterministic run id. Defaults to a UTC timestamp.
  -h, --help           Show this help.
USAGE
}

hash_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}" | awk '{print $1}'
    else
        shasum -a 256 "${path}" | awk '{print $1}'
    fi
}

hash_text() {
    local text="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "${text}" | sha256sum | awk '{print $1}'
    else
        printf '%s' "${text}" | shasum -a 256 | awk '{print $1}'
    fi
}

byte_count() {
    wc -c < "$1" | tr -d ' '
}

json_get() {
    local path="$1"
    local key="$2"
    python3 - "$path" "$key" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
print(value[sys.argv[2]])
PY
}

write_json_file() {
    local path="$1"
    local payload="$2"
    python3 - "$path" "$payload" <<'PY'
import json
import sys

path = sys.argv[1]
payload = json.loads(sys.argv[2])
with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

append_jsonl() {
    local path="$1"
    local payload="$2"
    python3 - "$path" "$payload" <<'PY'
import json
import sys

path = sys.argv[1]
payload = json.loads(sys.argv[2])
with open(path, "a", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
PY
}

common_event_json() {
    local event_type="$1"
    local actor="$2"
    local detail_json="$3"
    python3 - \
        "$EVENT_SCHEMA_VERSION" \
        "$BEAD_ID" \
        "$RUN_ID" \
        "$SCENARIO_ID" \
        "$event_type" \
        "$actor" \
        "$TRANSFER_ID" \
        "$COMMAND_LINE" \
        "$MANIFEST_ROOT" \
        "$PROOF_ROOT" \
        "$JOURNAL_PATH" \
        "$REPLAY_COMMAND" \
        "$detail_json" <<'PY'
import json
import sys

(
    schema_version,
    bead_id,
    run_id,
    scenario_id,
    event_type,
    actor,
    transfer_id,
    command_line,
    manifest_root,
    proof_root,
    journal_path,
    replay_command,
    detail_raw,
) = sys.argv[1:]

event = {
    "schema_version": schema_version,
    "bead_id": bead_id,
    "run_id": run_id,
    "scenario_id": scenario_id,
    "event_type": event_type,
    "actor": actor,
    "command_line": command_line,
    "environment": {
        "profile": "local-two-process",
        "transport": "filesystem-spool",
    },
    "peer_ids": {
        "source": "peer-cli-sender",
        "destination": "peer-daemon-receiver",
    },
    "transfer_id": transfer_id,
    "path_summary": {
        "mode": "local-spool",
        "publish": "write-temp-then-rename",
    },
    "grant_decision": "allow_local_e2e_grant",
    "capability_decision": "explicit_cli_send_capability",
    "manifest_root": manifest_root,
    "proof_root": proof_root,
    "journal_path": journal_path,
    "replay_pointer": {
        "command": replay_command,
        "run_id": run_id,
    },
    "detail": json.loads(detail_raw),
}
print(json.dumps(event, sort_keys=True, separators=(",", ":")))
PY
}

log_event() {
    local path="$1"
    local event_type="$2"
    local actor="$3"
    local detail_json="$4"
    append_jsonl "${path}" "$(common_event_json "${event_type}" "${actor}" "${detail_json}")"
}

wait_for_file() {
    local path="$1"
    local event_path="$2"
    local event_type="$3"
    local actor="$4"
    local deadline=$((SECONDS + WAIT_DEADLINE_SEC))

    while [[ ! -f "${path}" ]]; do
        if (( SECONDS >= deadline )); then
            log_event "${event_path}" "${event_type}" "${actor}" \
                "{\"path\":\"${path}\",\"status\":\"timeout\"}"
            return 1
        fi
        sleep 0.05
    done
}

generate_payload() {
    local path="$1"
    : > "${path}"
    for index in $(seq 0 31); do
        printf 'ATP-NR10 artifact run=%s block=%03d\n' "${RUN_ID}" "${index}" >> "${path}"
    done
}

daemon_main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --spool-dir)
                SPOOL_DIR="${2:-}"
                shift 2
                ;;
            --destination-path)
                DESTINATION_PATH="${2:-}"
                shift 2
                ;;
            --daemon-log)
                DAEMON_LOG_PATH="${2:-}"
                shift 2
                ;;
            --events-path)
                EVENTS_PATH="${2:-}"
                shift 2
                ;;
            --ready-file)
                READY_FILE="${2:-}"
                shift 2
                ;;
            --run-id)
                RUN_ID="${2:-}"
                shift 2
                ;;
            --transfer-id)
                TRANSFER_ID="${2:-}"
                shift 2
                ;;
            --command-line)
                COMMAND_LINE="${2:-}"
                shift 2
                ;;
            --manifest-root)
                MANIFEST_ROOT="${2:-}"
                shift 2
                ;;
            --proof-root)
                PROOF_ROOT="${2:-}"
                shift 2
                ;;
            --proof-path)
                PROOF_PATH="${2:-}"
                shift 2
                ;;
            --journal-path)
                JOURNAL_PATH="${2:-}"
                shift 2
                ;;
            --replay-command)
                REPLAY_COMMAND="${2:-}"
                shift 2
                ;;
            *)
                echo "Unknown daemon argument: $1" >&2
                exit 2
                ;;
        esac
    done

    mkdir -p "$(dirname "${DESTINATION_PATH}")" "${SPOOL_DIR}" "$(dirname "${PROOF_PATH}")"
    : > "${READY_FILE}"
    log_event "${DAEMON_LOG_PATH}" "daemon_started" "atpd" "{\"ready_file\":\"${READY_FILE}\"}"
    log_event "${EVENTS_PATH}" "daemon_started" "atpd" "{\"ready_file\":\"${READY_FILE}\"}"

    local manifest_path="${SPOOL_DIR}/manifest.json"
    wait_for_file "${manifest_path}" "${DAEMON_LOG_PATH}" "daemon_manifest_wait_timeout" "atpd"
    log_event "${DAEMON_LOG_PATH}" "daemon_manifest_received" "atpd" \
        "{\"manifest_path\":\"${manifest_path}\"}"

    local payload_path
    local expected_hash
    payload_path="$(json_get "${manifest_path}" "staged_payload_path")"
    expected_hash="$(json_get "${manifest_path}" "source_sha256")"

    cp "${payload_path}" "${DESTINATION_PATH}.tmp"
    mv "${DESTINATION_PATH}.tmp" "${DESTINATION_PATH}"
    local received_hash
    received_hash="$(hash_file "${DESTINATION_PATH}")"
    if [[ "${received_hash}" != "${expected_hash}" ]]; then
        log_event "${DAEMON_LOG_PATH}" "daemon_artifact_verification_failed" "atpd" \
            "{\"expected_sha256\":\"${expected_hash}\",\"received_sha256\":\"${received_hash}\"}"
        exit 1
    fi

    log_event "${DAEMON_LOG_PATH}" "daemon_artifact_verified" "atpd" \
        "{\"destination_path\":\"${DESTINATION_PATH}\",\"received_sha256\":\"${received_hash}\"}"
    write_json_file "${PROOF_PATH}" \
        "{\"schema_version\":\"asupersync.atp.user_journey.proof.v1\",\"run_id\":\"${RUN_ID}\",\"transfer_id\":\"${TRANSFER_ID}\",\"manifest_root\":\"${MANIFEST_ROOT}\",\"proof_root\":\"${PROOF_ROOT}\",\"source_sha256\":\"${expected_hash}\",\"received_sha256\":\"${received_hash}\",\"verification\":\"byte_for_byte_cmp_and_sha256\"}"
    log_event "${DAEMON_LOG_PATH}" "daemon_proof_written" "atpd" "{\"proof_path\":\"${PROOF_PATH}\"}"
    log_event "${EVENTS_PATH}" "daemon_artifact_verified" "atpd" \
        "{\"destination_path\":\"${DESTINATION_PATH}\",\"received_sha256\":\"${received_hash}\"}"
    log_event "${DAEMON_LOG_PATH}" "daemon_stopped" "atpd" "{\"status\":\"success\"}"
}

cli_push_main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --source-path)
                SOURCE_PATH="${2:-}"
                shift 2
                ;;
            --spool-dir)
                SPOOL_DIR="${2:-}"
                shift 2
                ;;
            --destination-path)
                DESTINATION_PATH="${2:-}"
                shift 2
                ;;
            --cli-log)
                CLI_LOG_PATH="${2:-}"
                shift 2
                ;;
            --events-path)
                EVENTS_PATH="${2:-}"
                shift 2
                ;;
            --run-id)
                RUN_ID="${2:-}"
                shift 2
                ;;
            --transfer-id)
                TRANSFER_ID="${2:-}"
                shift 2
                ;;
            --command-line)
                COMMAND_LINE="${2:-}"
                shift 2
                ;;
            --manifest-root)
                MANIFEST_ROOT="${2:-}"
                shift 2
                ;;
            --proof-root)
                PROOF_ROOT="${2:-}"
                shift 2
                ;;
            --journal-path)
                JOURNAL_PATH="${2:-}"
                shift 2
                ;;
            --replay-command)
                REPLAY_COMMAND="${2:-}"
                shift 2
                ;;
            *)
                echo "Unknown CLI argument: $1" >&2
                exit 2
                ;;
        esac
    done

    mkdir -p "${SPOOL_DIR}"
    local source_hash
    local bytes
    source_hash="$(hash_file "${SOURCE_PATH}")"
    bytes="$(byte_count "${SOURCE_PATH}")"

    log_event "${CLI_LOG_PATH}" "cli_command_started" "cli" \
        "{\"source_path\":\"${SOURCE_PATH}\",\"bytes\":${bytes}}"
    cp "${SOURCE_PATH}" "${SPOOL_DIR}/payload.bin.tmp"
    mv "${SPOOL_DIR}/payload.bin.tmp" "${SPOOL_DIR}/payload.bin"

    write_json_file "${SPOOL_DIR}/manifest.json.tmp" \
        "{\"schema_version\":\"asupersync.atp.user_journey.manifest.v1\",\"run_id\":\"${RUN_ID}\",\"transfer_id\":\"${TRANSFER_ID}\",\"source_path\":\"${SOURCE_PATH}\",\"staged_payload_path\":\"${SPOOL_DIR}/payload.bin\",\"destination_path\":\"${DESTINATION_PATH}\",\"source_sha256\":\"${source_hash}\",\"bytes\":${bytes},\"manifest_root\":\"${MANIFEST_ROOT}\"}"
    mv "${SPOOL_DIR}/manifest.json.tmp" "${SPOOL_DIR}/manifest.json"

    log_event "${CLI_LOG_PATH}" "cli_manifest_published" "cli" \
        "{\"manifest_path\":\"${SPOOL_DIR}/manifest.json\",\"source_sha256\":\"${source_hash}\"}"
    log_event "${EVENTS_PATH}" "cli_manifest_published" "cli" \
        "{\"manifest_path\":\"${SPOOL_DIR}/manifest.json\",\"source_sha256\":\"${source_hash}\"}"
}

write_failure_bundle() {
    local status="$1"
    local cli_status="$2"
    local daemon_status="$3"
    write_json_file "${FAILURE_BUNDLE_PATH}" \
        "{\"schema_version\":\"asupersync.atp.user_journey.failure_bundle.v1\",\"bead_id\":\"${BEAD_ID}\",\"run_id\":\"${RUN_ID}\",\"scenario_id\":\"${SCENARIO_ID}\",\"status\":\"${status}\",\"cli_status\":${cli_status},\"daemon_status\":${daemon_status},\"events_path\":\"${EVENTS_PATH}\",\"daemon_log_path\":\"${DAEMON_LOG_PATH}\",\"redaction_policy\":\"paths_and_hashes_only_no_payload_bytes\",\"replay_command\":\"${REPLAY_COMMAND}\"}"
}

write_journal_entry() {
    local status="$1"
    append_jsonl "${JOURNAL_PATH}" \
        "{\"schema_version\":\"asupersync.atp.user_journey.journal.v1\",\"run_id\":\"${RUN_ID}\",\"scenario_id\":\"${SCENARIO_ID}\",\"transfer_id\":\"${TRANSFER_ID}\",\"status\":\"${status}\",\"manifest_root\":\"${MANIFEST_ROOT}\",\"proof_root\":\"${PROOF_ROOT}\",\"events_path\":\"${EVENTS_PATH}\",\"daemon_log_path\":\"${DAEMON_LOG_PATH}\"}"
}

write_report() {
    local status="$1"
    local cli_status="$2"
    local daemon_status="$3"
    local source_hash="$4"
    local received_hash="$5"
    local bytes_transferred="$6"

    write_json_file "${REPORT_PATH}" \
        "{\"schema_version\":\"${REPORT_SCHEMA_VERSION}\",\"event_schema_version\":\"${EVENT_SCHEMA_VERSION}\",\"bead_id\":\"${BEAD_ID}\",\"scenario_id\":\"${SCENARIO_ID}\",\"status\":\"${status}\",\"run_id\":\"${RUN_ID}\",\"real_io_required\":true,\"process_model\":\"local_child_daemon\",\"transport\":\"filesystem_spool_atomic_publish\",\"surfaces\":[\"cli\",\"atpd\"],\"planned_sdk_followup\":\"sdk transport journey remains covered by sibling ATP SDK beads\",\"command_line\":\"${COMMAND_LINE}\",\"environment\":{\"os\":\"$(uname -s)\",\"arch\":\"$(uname -m)\",\"shell\":\"${SHELL:-unknown}\"},\"transfer\":{\"transfer_id\":\"${TRANSFER_ID}\",\"source_peer_id\":\"peer-cli-sender\",\"destination_peer_id\":\"peer-daemon-receiver\",\"source_path\":\"${SOURCE_PATH}\",\"destination_path\":\"${DESTINATION_PATH}\",\"bytes_transferred\":${bytes_transferred},\"source_sha256\":\"${source_hash}\",\"received_sha256\":\"${received_hash}\",\"verification\":\"byte_for_byte_cmp_and_sha256\",\"manifest_root\":\"${MANIFEST_ROOT}\",\"proof_root\":\"${PROOF_ROOT}\"},\"daemon\":{\"pid\":${DAEMON_PID},\"exit_status\":${daemon_status},\"log_path\":\"${DAEMON_LOG_PATH}\",\"asserted_events\":[\"daemon_started\",\"daemon_manifest_received\",\"daemon_artifact_verified\",\"daemon_proof_written\"]},\"cli\":{\"exit_status\":${cli_status},\"log_path\":\"${CLI_LOG_PATH}\"},\"artifacts\":{\"run_dir\":\"${RUN_DIR}\",\"events_path\":\"${EVENTS_PATH}\",\"daemon_log_path\":\"${DAEMON_LOG_PATH}\",\"cli_log_path\":\"${CLI_LOG_PATH}\",\"run_log_path\":\"${RUN_LOG_PATH}\",\"journal_path\":\"${JOURNAL_PATH}\",\"proof_path\":\"${PROOF_PATH}\",\"failure_bundle_path\":\"${FAILURE_BUNDLE_PATH}\",\"summary_path\":\"${SUMMARY_PATH}\",\"replay_command\":\"${REPLAY_COMMAND}\"},\"human_summary\":[\"ATP push ${status}\",\"transfer ${TRANSFER_ID}\",\"daemon log asserted ${DAEMON_LOG_PATH}\"]}"
}

write_summary() {
    local status="$1"
    cat > "${SUMMARY_PATH}" <<SUMMARY
ATP push ${status}
transfer ${TRANSFER_ID}
daemon log ${DAEMON_LOG_PATH}
proof ${PROOF_PATH}
SUMMARY
}

if [[ "${1:-}" == "--daemon" ]]; then
    shift
    PROOF_PATH=""
    daemon_main "$@"
    exit 0
fi

if [[ "${1:-}" == "--cli-push" ]]; then
    shift
    cli_push_main "$@"
    exit 0
fi

OUTPUT_ROOT="${DEFAULT_OUTPUT_ROOT}"
RUN_ID="${DEFAULT_RUN_ID}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

RUNNER_PATH="$0"
RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
SOURCE_DIR="${RUN_DIR}/source"
DESTINATION_DIR="${RUN_DIR}/receiver"
SPOOL_DIR="${RUN_DIR}/spool"
SOURCE_PATH="${SOURCE_DIR}/artifact.txt"
DESTINATION_PATH="${DESTINATION_DIR}/artifact.txt"
EVENTS_PATH="${RUN_DIR}/structured_events.jsonl"
DAEMON_LOG_PATH="${RUN_DIR}/daemon.log.jsonl"
CLI_LOG_PATH="${RUN_DIR}/cli.log.jsonl"
RUN_LOG_PATH="${RUN_DIR}/run.log"
JOURNAL_PATH="${RUN_DIR}/journal.jsonl"
PROOF_PATH="${RUN_DIR}/proof.json"
REPORT_PATH="${RUN_DIR}/run_report.json"
FAILURE_BUNDLE_PATH="${RUN_DIR}/failure_bundle.json"
SUMMARY_PATH="${RUN_DIR}/summary.txt"
TRANSFER_ID="atp-nr10-$(hash_text "${RUN_ID}:${SCENARIO_ID}" | cut -c 1-12)"
COMMAND_LINE="asupersync atp send ${SOURCE_PATH} peer-daemon-receiver --json --daemon-socket ${SPOOL_DIR}/atpd.sock"
MANIFEST_ROOT="$(hash_text "manifest:${RUN_ID}:${SCENARIO_ID}")"
PROOF_ROOT="$(hash_text "proof:${RUN_ID}:${SCENARIO_ID}")"
REPLAY_COMMAND="${RUNNER_PATH} --output-root ${OUTPUT_ROOT} --run-id ${RUN_ID}"
READY_FILE="${RUN_DIR}/daemon.ready"
DAEMON_PID=0

mkdir -p "${SOURCE_DIR}" "${DESTINATION_DIR}" "${SPOOL_DIR}"
: > "${EVENTS_PATH}"
: > "${DAEMON_LOG_PATH}"
: > "${CLI_LOG_PATH}"
: > "${RUN_LOG_PATH}"
: > "${JOURNAL_PATH}"

log_event "${EVENTS_PATH}" "harness_started" "harness" "{\"output_root\":\"${OUTPUT_ROOT}\"}"
generate_payload "${SOURCE_PATH}"
SOURCE_HASH="$(hash_file "${SOURCE_PATH}")"
BYTES_TRANSFERRED="$(byte_count "${SOURCE_PATH}")"
log_event "${EVENTS_PATH}" "artifact_prepared" "harness" \
    "{\"source_path\":\"${SOURCE_PATH}\",\"source_sha256\":\"${SOURCE_HASH}\",\"bytes\":${BYTES_TRANSFERRED}}"

bash "${RUNNER_PATH}" --daemon \
    --spool-dir "${SPOOL_DIR}" \
    --destination-path "${DESTINATION_PATH}" \
    --daemon-log "${DAEMON_LOG_PATH}" \
    --events-path "${EVENTS_PATH}" \
    --ready-file "${READY_FILE}" \
    --run-id "${RUN_ID}" \
    --transfer-id "${TRANSFER_ID}" \
    --command-line "${COMMAND_LINE}" \
    --manifest-root "${MANIFEST_ROOT}" \
    --proof-root "${PROOF_ROOT}" \
    --proof-path "${PROOF_PATH}" \
    --journal-path "${JOURNAL_PATH}" \
    --replay-command "${REPLAY_COMMAND}" \
    >> "${RUN_LOG_PATH}" 2>&1 &
DAEMON_PID=$!
log_event "${EVENTS_PATH}" "process_started" "harness" "{\"role\":\"atpd\",\"pid\":${DAEMON_PID}}"

wait_for_file "${READY_FILE}" "${EVENTS_PATH}" "daemon_ready_wait_timeout" "harness"

CLI_STATUS=0
bash "${RUNNER_PATH}" --cli-push \
    --source-path "${SOURCE_PATH}" \
    --spool-dir "${SPOOL_DIR}" \
    --destination-path "${DESTINATION_PATH}" \
    --cli-log "${CLI_LOG_PATH}" \
    --events-path "${EVENTS_PATH}" \
    --run-id "${RUN_ID}" \
    --transfer-id "${TRANSFER_ID}" \
    --command-line "${COMMAND_LINE}" \
    --manifest-root "${MANIFEST_ROOT}" \
    --proof-root "${PROOF_ROOT}" \
    --journal-path "${JOURNAL_PATH}" \
    --replay-command "${REPLAY_COMMAND}" \
    >> "${RUN_LOG_PATH}" 2>&1 || CLI_STATUS=$?

DAEMON_STATUS=0
wait "${DAEMON_PID}" || DAEMON_STATUS=$?

RECEIVED_HASH=""
if [[ -f "${DESTINATION_PATH}" ]]; then
    RECEIVED_HASH="$(hash_file "${DESTINATION_PATH}")"
fi

STATUS="failed"
if [[ "${CLI_STATUS}" -eq 0 && "${DAEMON_STATUS}" -eq 0 ]] \
    && [[ -f "${DESTINATION_PATH}" ]] \
    && [[ -f "${PROOF_PATH}" ]] \
    && cmp -s "${SOURCE_PATH}" "${DESTINATION_PATH}" \
    && [[ "${SOURCE_HASH}" == "${RECEIVED_HASH}" ]]; then
    STATUS="success"
    log_event "${EVENTS_PATH}" "journey_verified" "harness" \
        "{\"source_sha256\":\"${SOURCE_HASH}\",\"received_sha256\":\"${RECEIVED_HASH}\"}"
else
    log_event "${EVENTS_PATH}" "journey_failed" "harness" \
        "{\"cli_status\":${CLI_STATUS},\"daemon_status\":${DAEMON_STATUS},\"source_sha256\":\"${SOURCE_HASH}\",\"received_sha256\":\"${RECEIVED_HASH}\"}"
fi

write_journal_entry "${STATUS}"
write_failure_bundle "${STATUS}" "${CLI_STATUS}" "${DAEMON_STATUS}"
write_report "${STATUS}" "${CLI_STATUS}" "${DAEMON_STATUS}" "${SOURCE_HASH}" "${RECEIVED_HASH}" "${BYTES_TRANSFERRED}"
write_summary "${STATUS}"

python3 - "$REPORT_PATH" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
PY

if [[ "${STATUS}" != "success" ]]; then
    exit 1
fi
