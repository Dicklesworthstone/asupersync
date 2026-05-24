#!/usr/bin/env bash
# Local ATP multi-process e2e smoke runner.

set -euo pipefail

SCHEMA_VERSION="asupersync.atp.multiproc.runner.v1"
EVENT_SCHEMA_VERSION="asupersync.atp.multiproc.event.v1"
DEFAULT_OUTPUT_ROOT="${ATP_MULTIPROC_E2E_OUTPUT_ROOT:-target/e2e-results/atp_multiproc}"
DEFAULT_RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
PEER_WAIT_DEADLINE_SEC="${ATP_MULTIPROC_E2E_PEER_WAIT_DEADLINE_SEC:-10}"

usage() {
    cat <<'USAGE'
Usage:
  scripts/atp_multiproc_e2e/run_two_peer_transfer.sh [options]

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

unix_millis() {
    date -u +%s%3N 2>/dev/null || printf '%s000' "$(date -u +%s)"
}

log_event() {
    local event_type="$1"
    local peer_id="$2"
    local detail="$3"
    printf '{"schema_version":"%s","run_id":"%s","event_type":"%s","peer_id":"%s","detail":"%s","unix_millis":%s}\n' \
        "${EVENT_SCHEMA_VERSION}" "${RUN_ID}" "${event_type}" "${peer_id}" "${detail}" "$(unix_millis)" \
        >> "${EVENTS_PATH}"
}

wait_for_file() {
    local path="$1"
    local event_type="$2"
    local peer_id="$3"
    local deadline=$((SECONDS + PEER_WAIT_DEADLINE_SEC))
    while [[ ! -f "${path}" ]]; do
        if (( SECONDS >= deadline )); then
            log_event "${event_type}" "${peer_id}" "timeout_waiting_for_${path}"
            return 1
        fi
        sleep 0.05
    done
}

peer_main() {
    local role=""
    local peer_id=""
    local home=""
    local inbox=""
    local source=""
    local destination=""
    local ready_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --role)
                role="${2:-}"
                shift 2
                ;;
            --peer-id)
                peer_id="${2:-}"
                shift 2
                ;;
            --home)
                home="${2:-}"
                shift 2
                ;;
            --inbox)
                inbox="${2:-}"
                shift 2
                ;;
            --source)
                source="${2:-}"
                shift 2
                ;;
            --destination)
                destination="${2:-}"
                shift 2
                ;;
            --ready-file)
                ready_file="${2:-}"
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
            *)
                echo "Unknown peer argument: $1" >&2
                exit 2
                ;;
        esac
    done

    mkdir -p "${home}" "${inbox}"
    case "${role}" in
        receiver)
            : > "${ready_file}"
            log_event "peer_ready" "${peer_id}" "home=${home}"
            wait_for_file "${inbox}/payload.bin" "transfer_receive_timeout" "${peer_id}"
            cp "${inbox}/payload.bin" "${destination}"
            log_event "transfer_received" "${peer_id}" "sha256=$(hash_file "${destination}")"
            ;;
        sender)
            wait_for_file "${ready_file}" "receiver_ready_timeout" "${peer_id}"
            cp "${source}" "${inbox}/payload.bin.tmp"
            mv "${inbox}/payload.bin.tmp" "${inbox}/payload.bin"
            log_event "transfer_sent" "${peer_id}" "sha256=$(hash_file "${source}")"
            ;;
        *)
            echo "Unknown peer role: ${role}" >&2
            exit 2
            ;;
    esac
}

generate_payload() {
    local path="$1"
    : > "${path}"
    for index in $(seq 0 127); do
        printf 'ATP-MULTIPROC-E2E-PAYLOAD run=%s block=%03d\n' "${RUN_ID}" "${index}" >> "${path}"
    done
}

write_failure_bundle() {
    local status="$1"
    local sender_status="$2"
    local receiver_status="$3"
    cat > "${FAILURE_BUNDLE_PATH}" <<JSON
{
  "schema_version": "${SCHEMA_VERSION}",
  "run_id": "${RUN_ID}",
  "status": "${status}",
  "sender_status": ${sender_status},
  "receiver_status": ${receiver_status},
  "events_path": "${EVENTS_PATH}",
  "redaction_policy": "temp_paths_only_no_payload_bytes",
  "replay_command": "scripts/atp_multiproc_e2e/run_two_peer_transfer.sh --output-root ${OUTPUT_ROOT} --run-id ${RUN_ID}"
}
JSON
}

write_report() {
    local status="$1"
    local sender_status="$2"
    local receiver_status="$3"
    local source_hash="$4"
    local received_hash="$5"
    local bytes_transferred="$6"
    cat > "${REPORT_PATH}" <<JSON
{
  "schema_version": "${SCHEMA_VERSION}",
  "run_id": "${RUN_ID}",
  "status": "${status}",
  "peer_count": 2,
  "process_model": "local_child_processes",
  "transport": "filesystem_spool_with_atomic_publish",
  "real_io_required": true,
  "environment": {
    "os": "$(uname -s)",
    "arch": "$(uname -m)",
    "shell": "${SHELL:-unknown}"
  },
  "transfer": {
    "transfer_id": "atp-multiproc-${RUN_ID}",
    "source_peer_id": "peer-sender",
    "destination_peer_id": "peer-receiver",
    "source_path": "${SOURCE_PATH}",
    "destination_path": "${DESTINATION_PATH}",
    "bytes_transferred": ${bytes_transferred},
    "source_sha256": "${source_hash}",
    "received_sha256": "${received_hash}",
    "verification": "byte_for_byte_cmp_and_sha256"
  },
  "child_processes": [
    {
      "role": "receiver",
      "peer_id": "peer-receiver",
      "pid": ${RECEIVER_PID},
      "exit_status": ${receiver_status},
      "home": "${RECEIVER_HOME}",
      "command": "bash ${RUNNER_PATH} --peer --role receiver"
    },
    {
      "role": "sender",
      "peer_id": "peer-sender",
      "pid": ${SENDER_PID},
      "exit_status": ${sender_status},
      "home": "${SENDER_HOME}",
      "command": "bash ${RUNNER_PATH} --peer --role sender"
    }
  ],
  "artifacts": {
    "run_dir": "${RUN_DIR}",
    "events_path": "${EVENTS_PATH}",
    "run_log_path": "${RUN_LOG_PATH}",
    "failure_bundle_path": "${FAILURE_BUNDLE_PATH}",
    "replay_command": "scripts/atp_multiproc_e2e/run_two_peer_transfer.sh --output-root ${OUTPUT_ROOT} --run-id ${RUN_ID}"
  }
}
JSON
}

if [[ "${1:-}" == "--peer" ]]; then
    shift
    RUN_ID=""
    EVENTS_PATH=""
    peer_main "$@"
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
SENDER_HOME="${RUN_DIR}/homes/sender"
RECEIVER_HOME="${RUN_DIR}/homes/receiver"
SPOOL_DIR="${RUN_DIR}/spool/receiver-inbox"
SOURCE_PATH="${SENDER_HOME}/payload.bin"
DESTINATION_PATH="${RECEIVER_HOME}/received.bin"
READY_FILE="${RUN_DIR}/receiver.ready"
EVENTS_PATH="${RUN_DIR}/structured_events.jsonl"
RUN_LOG_PATH="${RUN_DIR}/run.log"
REPORT_PATH="${RUN_DIR}/run_report.json"
FAILURE_BUNDLE_PATH="${RUN_DIR}/failure_bundle.json"
SENDER_PID=0
RECEIVER_PID=0

mkdir -p "${SENDER_HOME}" "${RECEIVER_HOME}" "${SPOOL_DIR}"
: > "${EVENTS_PATH}"
: > "${RUN_LOG_PATH}"

log_event "harness_started" "harness" "output_root=${OUTPUT_ROOT}"
generate_payload "${SOURCE_PATH}"
SOURCE_HASH="$(hash_file "${SOURCE_PATH}")"
log_event "fixture_generated" "peer-sender" "sha256=${SOURCE_HASH}"

bash "${RUNNER_PATH}" --peer \
    --role receiver \
    --peer-id peer-receiver \
    --home "${RECEIVER_HOME}" \
    --inbox "${SPOOL_DIR}" \
    --destination "${DESTINATION_PATH}" \
    --ready-file "${READY_FILE}" \
    --events-path "${EVENTS_PATH}" \
    --run-id "${RUN_ID}" \
    >> "${RUN_LOG_PATH}" 2>&1 &
RECEIVER_PID=$!
log_event "process_started" "peer-receiver" "pid=${RECEIVER_PID}"

bash "${RUNNER_PATH}" --peer \
    --role sender \
    --peer-id peer-sender \
    --home "${SENDER_HOME}" \
    --inbox "${SPOOL_DIR}" \
    --source "${SOURCE_PATH}" \
    --ready-file "${READY_FILE}" \
    --events-path "${EVENTS_PATH}" \
    --run-id "${RUN_ID}" \
    >> "${RUN_LOG_PATH}" 2>&1 &
SENDER_PID=$!
log_event "process_started" "peer-sender" "pid=${SENDER_PID}"

SENDER_STATUS=0
wait "${SENDER_PID}" || SENDER_STATUS=$?

RECEIVER_STATUS=0
wait "${RECEIVER_PID}" || RECEIVER_STATUS=$?

RECEIVED_HASH=""
BYTES_TRANSFERRED=0
if [[ -f "${DESTINATION_PATH}" ]]; then
    RECEIVED_HASH="$(hash_file "${DESTINATION_PATH}")"
    BYTES_TRANSFERRED="$(wc -c < "${DESTINATION_PATH}" | tr -d ' ')"
fi

STATUS="failed"
if [[ "${SENDER_STATUS}" -eq 0 && "${RECEIVER_STATUS}" -eq 0 ]] \
    && [[ -f "${DESTINATION_PATH}" ]] \
    && cmp -s "${SOURCE_PATH}" "${DESTINATION_PATH}" \
    && [[ "${SOURCE_HASH}" == "${RECEIVED_HASH}" ]]; then
    STATUS="success"
    log_event "transfer_verified" "harness" "sha256=${SOURCE_HASH}"
else
    log_event "transfer_failed" "harness" "sender_status=${SENDER_STATUS},receiver_status=${RECEIVER_STATUS}"
fi

write_failure_bundle "${STATUS}" "${SENDER_STATUS}" "${RECEIVER_STATUS}"
write_report "${STATUS}" "${SENDER_STATUS}" "${RECEIVER_STATUS}" "${SOURCE_HASH}" "${RECEIVED_HASH}" "${BYTES_TRANSFERRED}"

if [[ "${STATUS}" != "success" ]]; then
    exit 1
fi
