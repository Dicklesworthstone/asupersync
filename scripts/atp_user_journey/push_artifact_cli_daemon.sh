#!/usr/bin/env bash
# ATP-NR10 local CLI-to-daemon user journey, run against the real binary.
#
# `asupersync atp serve --listen 127.0.0.1:0` runs as a child daemon. The
# harness reads the loopback address it bound from its first stdout line, runs
# `asupersync atp send <artifact> <address>` as a separate process, stops the
# daemon, and checks the copy the daemon committed under its inbox byte for
# byte and by SHA-256. The harness never moves the artifact itself: without a
# runnable binary it exits 2 instead of running the journey some other way.
#
# Observations the binary does not offer are listed in the report's `not_run`
# array, with the reason, rather than reconstructed by the harness
# (br-asupersync-bi2462.144).

set -euo pipefail

REPORT_SCHEMA_VERSION="asupersync.atp.user_journey.cli_daemon_report.v1"
EVENT_SCHEMA_VERSION="asupersync.atp.user_journey.cli_daemon_event.v1"
SCENARIO_ID="cli_push_artifact_daemon_log"
BEAD_ID="asupersync-vk4kcf.9"
DEFAULT_OUTPUT_ROOT="${ATP_USER_JOURNEY_OUTPUT_ROOT:-target/e2e-results/atp_user_journey}"
DEFAULT_RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
READY_DEADLINE_SEC="${ATP_USER_JOURNEY_WAIT_DEADLINE_SEC:-30}"
SEND_DEADLINE_SEC="${ATP_USER_JOURNEY_SEND_DEADLINE_SEC:-120}"
STOP_DEADLINE_SEC="${ATP_USER_JOURNEY_STOP_DEADLINE_SEC:-10}"
PREFLIGHT_DEADLINE_SEC=30
# 14000 text lines of about 50 bytes: several hundred KB, so the transfer
# spans more than one of the transport's 256 KiB ObjectData chunks.
PAYLOAD_LINES=14000
LISTEN_REQUEST="127.0.0.1:0"
# The peer id the binary sends in the ATP-over-TCP handshake, for both
# `atp send` and `atp serve` (src/bin/asupersync.rs).
BINARY_PEER_ID="asupersync-cli"
NOT_YET_REPORTED="not_yet_reported_by_atp_send"
# The ATP-over-TCP v1 receipt carries no proof root.
PROOF_ROOT="not_produced_by_atp_tcp_v1"

usage() {
    cat <<'USAGE'
Usage:
  scripts/atp_user_journey/push_artifact_cli_daemon.sh --asupersync-bin <path> [options]

Runs `asupersync atp serve` (daemon) and `asupersync atp send` (CLI) over
loopback and verifies the artifact the daemon received. Build the binary
first, for example with `cargo build --features cli --bin asupersync`.

Options:
  --asupersync-bin <path>  The asupersync binary to run (default: $ASUPERSYNC_BIN).
  --output-root <dir>      Directory where run artifacts are written.
  --run-id <id>            Deterministic run id. Defaults to a UTC timestamp.
  -h, --help               Show this help.

Exit status: 0 when the journey is verified, 1 when it ran and failed, and 2
for a usage error or a missing or unrunnable binary.
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

byte_count() {
    wc -c < "$1" | tr -d ' '
}

now_ms() {
    python3 -c 'import time; print(int(time.time() * 1000))'
}

# Shell-quoted command line for the argv, so it can be replayed verbatim.
quote_argv() {
    local quoted
    quoted="$(printf '%q ' "$@")"
    printf '%s' "${quoted% }"
}

# Compact JSON object from key/value pairs. A value is a string unless it is
# prefixed with `json:`, in which case the rest is parsed as JSON.
json_object() {
    python3 - "$@" <<'PY'
import json
import sys

args = sys.argv[1:]
if len(args) % 2:
    raise SystemExit("json_object needs key/value pairs")
out = {}
for key, raw in zip(args[0::2], args[1::2]):
    out[key] = json.loads(raw[5:]) if raw.startswith("json:") else raw
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
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

# Every event names the command line of the process it describes.
actor_command_line() {
    case "$1" in
        atp_serve) printf '%s' "${SERVE_COMMAND_LINE}" ;;
        atp_send) printf '%s' "${SEND_COMMAND_LINE}" ;;
        *) printf '%s' "${REPLAY_COMMAND}" ;;
    esac
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
        "$(actor_command_line "${actor}")" \
        "$ASUPERSYNC_BIN" \
        "$BINARY_PEER_ID" \
        "$TRANSFER_ID" \
        "${LISTEN_ADDRESS:-not_yet_bound}" \
        "$MANIFEST_ROOT" \
        "$PROOF_ROOT" \
        "$JOURNAL_PATH" \
        "$REPLAY_COMMAND" \
        "$detail_json" <<'PY'
import json
import sys
import time

(
    schema_version,
    bead_id,
    run_id,
    scenario_id,
    event_type,
    actor,
    command_line,
    asupersync_bin,
    peer_id,
    transfer_id,
    listen_address,
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
    "ts_unix_ms": int(time.time() * 1000),
    "command_line": command_line,
    "environment": {
        "profile": "local-two-process",
        "transport": "atp-over-tcp-loopback",
        "asupersync_bin": asupersync_bin,
    },
    "peer_ids": {
        "source": peer_id,
        "destination": peer_id,
    },
    "transfer_id": transfer_id,
    "path_summary": {
        "mode": "tcp-loopback",
        "listen_address": listen_address,
    },
    # Both commands refuse a plaintext transfer off loopback unless
    # --allow-plaintext is given; a loopback address needs no opt-in.
    "grant_decision": "loopback_plaintext_allowed_without_opt_in",
    "capability_decision": "no_capability_check_in_atp_tcp_v1",
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
    printf '[%s] %s -> %s %s\n' "${actor}" "${event_type}" "${path##*/}" "${detail_json}" \
        >> "${RUN_LOG_PATH}"
}

add_failure() {
    FAILURE_REASONS+="$1"$'\n'
    printf '[harness] failure: %s\n' "$1" >> "${RUN_LOG_PATH}"
}

# A live, non-zombie process.
pid_alive() {
    local pid="$1"
    local state
    kill -0 "${pid}" 2>/dev/null || return 1
    if command -v ps >/dev/null 2>&1; then
        state="$(ps -o stat= -p "${pid}" 2>/dev/null || true)"
        state="${state//[[:space:]]/}"
        [[ -n "${state}" && "${state}" != Z* ]] || return 1
    fi
    return 0
}

# Runs "$@" with stdout and stderr in files and kills it after deadline_sec.
# Returns its exit status; on the deadline it returns 124 and sets
# CHILD_TIMED_OUT=true.
run_bounded() {
    local deadline_sec="$1"
    local stdout_path="$2"
    local stderr_path="$3"
    shift 3
    CHILD_TIMED_OUT=false
    "$@" > "${stdout_path}" 2> "${stderr_path}" < /dev/null &
    CHILD_PID=$!
    local deadline=$((SECONDS + deadline_sec))
    while pid_alive "${CHILD_PID}"; do
        if (( SECONDS >= deadline )); then
            kill -KILL "${CHILD_PID}" 2>/dev/null || true
            wait "${CHILD_PID}" 2>/dev/null || true
            CHILD_PID=0
            CHILD_TIMED_OUT=true
            return 124
        fi
        sleep 0.05
    done
    local status=0
    wait "${CHILD_PID}" || status=$?
    CHILD_PID=0
    return "${status}"
}

generate_payload() {
    python3 - "$1" "${RUN_ID}" "${PAYLOAD_LINES}" <<'PY'
import sys

path, run_id, lines = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(path, "w", encoding="utf-8", newline="\n") as handle:
    for index in range(lines):
        handle.write(f"ATP-NR10 artifact run={run_id} block={index:06d}\n")
PY
}

# Prints the address from the daemon's first stdout line. Exit 1: no complete
# line yet. Exit 3: a complete line that is not a loopback listening report.
parse_listen_address() {
    python3 - "$1" <<'PY'
import ipaddress
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
        text = handle.read()
except FileNotFoundError:
    sys.exit(1)
if "\n" not in text:
    sys.exit(1)
line = text.split("\n", 1)[0].strip()
try:
    status = json.loads(line)
    address = status["listen_address"]
    host, port = address.rsplit(":", 1)
    port = int(port)
    loopback = ipaddress.ip_address(host.strip("[]")).is_loopback
except (ValueError, KeyError, TypeError, AttributeError) as error:
    print(f"unparseable atp serve status line {line!r}: {error}", file=sys.stderr)
    sys.exit(3)
if status.get("message") != "listening" or not loopback or not 0 < port < 65536:
    print(f"atp serve status is not a loopback listening report: {line}", file=sys.stderr)
    sys.exit(3)
print(address)
PY
}

wait_for_daemon_ready() {
    local deadline=$((SECONDS + READY_DEADLINE_SEC))
    local parsed
    local status
    while true; do
        if grep -q 'listen_address' "${DAEMON_STDOUT_PATH}" 2>/dev/null; then
            status=0
            parsed="$(parse_listen_address "${DAEMON_STDOUT_PATH}" 2>> "${RUN_LOG_PATH}")" || status=$?
            if [[ "${status}" -eq 0 ]]; then
                LISTEN_ADDRESS="${parsed}"
                return 0
            fi
            if [[ "${status}" -ne 1 ]]; then
                add_failure "atp serve printed a status line that is not a loopback listening report"
                return 1
            fi
        fi
        if ! pid_alive "${DAEMON_PID}"; then
            add_failure "atp serve exited before it reported a listening address"
            log_event "${EVENTS_PATH}" "daemon_exited_before_ready" "harness" \
                "$(json_object pid "json:${DAEMON_PID}")"
            return 1
        fi
        if (( SECONDS >= deadline )); then
            add_failure "atp serve reported no listening address within ${READY_DEADLINE_SEC} s"
            log_event "${EVENTS_PATH}" "daemon_ready_wait_timeout" "harness" \
                "$(json_object deadline_sec "json:${READY_DEADLINE_SEC}")"
            return 1
        fi
        sleep 0.05
    done
}

# Validates the single JSON object `atp send` printed and prints its fields,
# tab-separated, followed by the object itself.
read_send_result() {
    python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    lines = [line for line in handle.read().splitlines() if line.strip()]
if len(lines) != 1:
    print(f"expected one JSON line from atp send, got {len(lines)}", file=sys.stderr)
    sys.exit(1)
result = json.loads(lines[0])
types = {
    "status": str,
    "committed": bool,
    "sha_ok": bool,
    "merkle_ok": bool,
    "files": int,
    "bytes_sent": int,
    "transfer_id": str,
    "merkle_root": str,
    "target": str,
}
for key, kind in types.items():
    value = result.get(key)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        print(f"atp send result field {key!r} is {value!r}", file=sys.stderr)
        sys.exit(1)
    if kind is str and not value.strip():
        print(f"atp send result field {key!r} is empty", file=sys.stderr)
        sys.exit(1)
fields = []
for key in types:
    value = result[key]
    fields.append(("true" if value else "false") if isinstance(value, bool) else str(value))
fields.append(json.dumps(result, sort_keys=True, separators=(",", ":")))
print("\t".join(fields))
PY
}

# Per-transfer lines `atp serve` wrote to stderr: commits, failures, panics.
scan_daemon_stderr() {
    python3 - "${DAEMON_STDERR_PATH}" <<'PY'
import json
import re
import sys

commit = re.compile(r"^atp: committed transfer (\S+) \((\d+) bytes, (\d+) files\)$")
commits, failed, panics = [], 0, 0
with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.rstrip("\n")
        match = commit.match(line)
        if match:
            commits.append(
                {
                    "transfer_id": match.group(1),
                    "bytes": int(match.group(2)),
                    "files": int(match.group(3)),
                }
            )
        elif line.startswith("atp: transfer failed"):
            failed += 1
        elif "panicked" in line:
            panics += 1
first = commits[0] if commits else None
print(
    "\t".join(
        [
            str(len(commits)),
            first["transfer_id"] if first else "-",
            str(first["bytes"]) if first else "-1",
            str(first["files"]) if first else "-1",
            str(failed),
            str(panics),
            json.dumps(first, sort_keys=True, separators=(",", ":")),
        ]
    )
)
PY
}

inbox_entries() {
    python3 - "$1" <<'PY'
import os
import sys

try:
    names = sorted(os.listdir(sys.argv[1]))
except FileNotFoundError:
    names = []
print(",".join(names))
PY
}

dump_child_logs() {
    local label
    local log_file
    [[ "${CHILD_LOGS_DUMPED:-false}" == false ]] || return 0
    CHILD_LOGS_DUMPED=true
    for label in "atp serve stderr" "atp serve stdout" "atp send stderr" "atp send stdout"; do
        case "${label}" in
            "atp serve stderr") log_file="${DAEMON_STDERR_PATH}" ;;
            "atp serve stdout") log_file="${DAEMON_STDOUT_PATH}" ;;
            "atp send stderr") log_file="${CLI_STDERR_PATH}" ;;
            *) log_file="${CLI_STDOUT_PATH}" ;;
        esac
        {
            printf -- '----- %s (%s) -----\n' "${label}" "${log_file}"
            if [[ -s "${log_file}" ]]; then
                tail -n 200 "${log_file}"
            else
                printf '(empty)\n'
            fi
        } | tee -a "${RUN_LOG_PATH}" >&2
    done
}

stop_daemon() {
    [[ "${DAEMON_PID}" -gt 0 && "${DAEMON_STOPPED}" == false ]] || return 0
    DAEMON_STOPPED=true
    if pid_alive "${DAEMON_PID}"; then
        DAEMON_ALIVE_AT_STOP=true
        DAEMON_STOP_SIGNAL="TERM"
        kill -TERM "${DAEMON_PID}" 2>/dev/null || true
        local deadline=$((SECONDS + STOP_DEADLINE_SEC))
        while pid_alive "${DAEMON_PID}"; do
            if (( SECONDS >= deadline )); then
                DAEMON_STOP_SIGNAL="KILL"
                kill -KILL "${DAEMON_PID}" 2>/dev/null || true
                break
            fi
            sleep 0.05
        done
    else
        DAEMON_ALIVE_AT_STOP=false
        DAEMON_STOP_SIGNAL="none"
    fi
    DAEMON_STATUS=0
    wait "${DAEMON_PID}" 2>/dev/null || DAEMON_STATUS=$?
}

# Every exit path, including a harness error under `set -e` or a signal,
# stops the daemon and any running `atp send`.
on_exit() {
    local status=$?
    trap - EXIT
    if [[ "${CHILD_PID:-0}" -gt 0 ]]; then
        kill -KILL "${CHILD_PID}" 2>/dev/null || true
        wait "${CHILD_PID}" 2>/dev/null || true
    fi
    if [[ "${DAEMON_PID:-0}" -gt 0 && "${DAEMON_STOPPED:-true}" == false ]]; then
        stop_daemon || true
        if [[ "${status}" -ne 0 ]]; then
            printf 'push_artifact_cli_daemon.sh: aborted with status %s; child logs follow\n' \
                "${status}" >&2
            dump_child_logs || true
        fi
    fi
    exit "${status}"
}

require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "Missing value for $1" >&2
        usage >&2
        exit 2
    fi
}

OUTPUT_ROOT="${DEFAULT_OUTPUT_ROOT}"
RUN_ID="${DEFAULT_RUN_ID}"
ASUPERSYNC_BIN="${ASUPERSYNC_BIN:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)
            require_value "$@"
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        --run-id)
            require_value "$@"
            RUN_ID="$2"
            shift 2
            ;;
        --asupersync-bin)
            require_value "$@"
            ASUPERSYNC_BIN="$2"
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

if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "--run-id must match [A-Za-z0-9._-]+, got '${RUN_ID}'" >&2
    exit 2
fi

if [[ -z "${ASUPERSYNC_BIN}" ]]; then
    echo "push_artifact_cli_daemon.sh: no asupersync binary given; pass --asupersync-bin <path> or set ASUPERSYNC_BIN (build it with: cargo build --features cli --bin asupersync). The journey runs only against the real binary." >&2
    exit 2
fi
case "${ASUPERSYNC_BIN}" in
    /*) ;;
    *) ASUPERSYNC_BIN="${PWD}/${ASUPERSYNC_BIN}" ;;
esac
if [[ ! -f "${ASUPERSYNC_BIN}" || ! -x "${ASUPERSYNC_BIN}" ]]; then
    echo "push_artifact_cli_daemon.sh: asupersync binary ${ASUPERSYNC_BIN} is not an executable file. The journey runs only against the real binary." >&2
    exit 2
fi

case "${OUTPUT_ROOT}" in
    /*) ;;
    *) OUTPUT_ROOT="${PWD}/${OUTPUT_ROOT}" ;;
esac
RUNNER_PATH="$0"
case "${RUNNER_PATH}" in
    /*) ;;
    *) RUNNER_PATH="${PWD}/${RUNNER_PATH}" ;;
esac

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
SOURCE_DIR="${RUN_DIR}/source"
RECEIVER_ROOT="${RUN_DIR}/receiver"
SOURCE_PATH="${SOURCE_DIR}/artifact.txt"
EVENTS_PATH="${RUN_DIR}/structured_events.jsonl"
DAEMON_LOG_PATH="${RUN_DIR}/daemon.log.jsonl"
CLI_LOG_PATH="${RUN_DIR}/cli.log.jsonl"
RUN_LOG_PATH="${RUN_DIR}/run.log"
JOURNAL_PATH="${RUN_DIR}/journal.jsonl"
PROOF_PATH="${RUN_DIR}/proof.json"
REPORT_PATH="${RUN_DIR}/run_report.json"
FAILURE_BUNDLE_PATH="${RUN_DIR}/failure_bundle.json"
SUMMARY_PATH="${RUN_DIR}/summary.txt"
DAEMON_STDOUT_PATH="${RUN_DIR}/daemon.stdout.log"
DAEMON_STDERR_PATH="${RUN_DIR}/daemon.stderr.log"
CLI_STDOUT_PATH="${RUN_DIR}/cli.stdout.log"
CLI_STDERR_PATH="${RUN_DIR}/cli.stderr.log"
VERSION_STDOUT_PATH="${RUN_DIR}/binary_version.stdout.log"
VERSION_STDERR_PATH="${RUN_DIR}/binary_version.stderr.log"
REPLAY_COMMAND="$(quote_argv "${RUNNER_PATH}" --output-root "${OUTPUT_ROOT}" --run-id "${RUN_ID}" --asupersync-bin "${ASUPERSYNC_BIN}")"

mkdir -p "${SOURCE_DIR}" "${RECEIVER_ROOT}"
# A fresh receiver data directory per invocation: a rerun with the same run id
# must not find the artifact already in the inbox, where the receiver would
# answer "already in sync" and move no bytes.
RECEIVER_DATA_DIR="$(mktemp -d "${RECEIVER_ROOT}/data.XXXXXX")"
INBOX_DIR="${RECEIVER_DATA_DIR}/inbox"
# `atp serve` commits a single-file transfer as <data-dir>/inbox/<file name>.
DESTINATION_PATH="${INBOX_DIR}/artifact.txt"

for log_file in "${EVENTS_PATH}" "${DAEMON_LOG_PATH}" "${CLI_LOG_PATH}" "${RUN_LOG_PATH}" \
    "${JOURNAL_PATH}" "${DAEMON_STDOUT_PATH}" "${DAEMON_STDERR_PATH}" \
    "${CLI_STDOUT_PATH}" "${CLI_STDERR_PATH}"; do
    : > "${log_file}"
done

TRANSFER_ID="${NOT_YET_REPORTED}"
MANIFEST_ROOT="${NOT_YET_REPORTED}"
LISTEN_ADDRESS=""
FAILURE_REASONS=""
CHILD_PID=0
CHILD_TIMED_OUT=false
CHILD_LOGS_DUMPED=false
DAEMON_PID=0
DAEMON_STOPPED=false
DAEMON_READY=false
DAEMON_STATUS=null
DAEMON_ALIVE_AT_STOP=null
DAEMON_STOP_SIGNAL="none"
DAEMON_COMMIT_JSON=null
CLI_STATUS=null
CLI_TIMED_OUT=false
CLI_ELAPSED_MS=null
CLI_RESULT_JSON=null
SEND_PARSED=false
SEND_BYTES_SENT=0
RECEIVED_HASH=""
INBOX_LISTING=""

SERVE_ARGV=("${ASUPERSYNC_BIN}" --format stream-json atp serve --listen "${LISTEN_REQUEST}" --data-dir "${RECEIVER_DATA_DIR}")
SERVE_COMMAND_LINE="$(quote_argv "${SERVE_ARGV[@]}")"
# Completed with the daemon's address once it reports one.
SEND_COMMAND_LINE="$(quote_argv "${ASUPERSYNC_BIN}" --format json atp send "${SOURCE_PATH}") <daemon-listen-address>"

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

VERSION_STATUS=0
run_bounded "${PREFLIGHT_DEADLINE_SEC}" "${VERSION_STDOUT_PATH}" "${VERSION_STDERR_PATH}" \
    "${ASUPERSYNC_BIN}" --version || VERSION_STATUS=$?
if [[ "${VERSION_STATUS}" -ne 0 ]]; then
    echo "push_artifact_cli_daemon.sh: ${ASUPERSYNC_BIN} --version exited ${VERSION_STATUS}; the journey runs only against a working binary." >&2
    cat "${VERSION_STDERR_PATH}" >&2 || true
    exit 2
fi
ASUPERSYNC_VERSION="$(head -n 1 "${VERSION_STDOUT_PATH}")"

log_event "${EVENTS_PATH}" "harness_started" "harness" \
    "$(json_object output_root "${OUTPUT_ROOT}" asupersync_bin "${ASUPERSYNC_BIN}" asupersync_version "${ASUPERSYNC_VERSION}")"
generate_payload "${SOURCE_PATH}"
SOURCE_HASH="$(hash_file "${SOURCE_PATH}")"
SOURCE_BYTES="$(byte_count "${SOURCE_PATH}")"
log_event "${EVENTS_PATH}" "artifact_prepared" "harness" \
    "$(json_object source_path "${SOURCE_PATH}" source_sha256 "${SOURCE_HASH}" bytes "json:${SOURCE_BYTES}")"

# Daemon: the real `atp serve`, on an OS-chosen loopback port.
"${SERVE_ARGV[@]}" > "${DAEMON_STDOUT_PATH}" 2> "${DAEMON_STDERR_PATH}" < /dev/null &
DAEMON_PID=$!
log_event "${EVENTS_PATH}" "process_started" "harness" \
    "$(json_object role atp_serve pid "json:${DAEMON_PID}" command_line "${SERVE_COMMAND_LINE}" data_dir "${RECEIVER_DATA_DIR}")"

if wait_for_daemon_ready; then
    DAEMON_READY=true
    SEND_ARGV=("${ASUPERSYNC_BIN}" --format json atp send "${SOURCE_PATH}" "${LISTEN_ADDRESS}")
    SEND_COMMAND_LINE="$(quote_argv "${SEND_ARGV[@]}")"
    DETAIL="$(json_object listen_address "${LISTEN_ADDRESS}" requested_listen "${LISTEN_REQUEST}" pid "json:${DAEMON_PID}" observed_from daemon_stdout)"
    log_event "${DAEMON_LOG_PATH}" "daemon_started" "atp_serve" "${DETAIL}"
    log_event "${EVENTS_PATH}" "daemon_started" "atp_serve" "${DETAIL}"

    # CLI: the real `atp send`, as a separate process, to the reported address.
    DETAIL="$(json_object source_path "${SOURCE_PATH}" target "${LISTEN_ADDRESS}" bytes "json:${SOURCE_BYTES}" deadline_sec "json:${SEND_DEADLINE_SEC}")"
    log_event "${CLI_LOG_PATH}" "cli_command_started" "atp_send" "${DETAIL}"
    log_event "${EVENTS_PATH}" "cli_command_started" "atp_send" "${DETAIL}"
    SEND_STARTED_MS="$(now_ms)"
    CLI_STATUS=0
    run_bounded "${SEND_DEADLINE_SEC}" "${CLI_STDOUT_PATH}" "${CLI_STDERR_PATH}" \
        "${SEND_ARGV[@]}" || CLI_STATUS=$?
    CLI_TIMED_OUT="${CHILD_TIMED_OUT}"
    CLI_ELAPSED_MS=$(( $(now_ms) - SEND_STARTED_MS ))

    SEND_LINE=""
    if [[ "${CLI_STATUS}" -eq 0 ]]; then
        SEND_LINE="$(read_send_result "${CLI_STDOUT_PATH}" 2>> "${RUN_LOG_PATH}")" || SEND_LINE=""
    fi
    if [[ -n "${SEND_LINE}" ]]; then
        IFS=$'\t' read -r SEND_STATUS SEND_COMMITTED SEND_SHA_OK SEND_MERKLE_OK SEND_FILES \
            SEND_BYTES_SENT SEND_TRANSFER_ID SEND_MERKLE_ROOT SEND_TARGET CLI_RESULT_JSON \
            <<< "${SEND_LINE}"
        SEND_PARSED=true
        TRANSFER_ID="${SEND_TRANSFER_ID}"
        MANIFEST_ROOT="${SEND_MERKLE_ROOT}"
        DETAIL="$(json_object exit_status "json:${CLI_STATUS}" elapsed_ms "json:${CLI_ELAPSED_MS}" result "json:${CLI_RESULT_JSON}")"
        log_event "${CLI_LOG_PATH}" "cli_send_completed" "atp_send" "${DETAIL}"
        log_event "${EVENTS_PATH}" "cli_send_completed" "atp_send" "${DETAIL}"

        # The receiver's verdict: `atp serve` computed sha_ok and merkle_ok,
        # committed, and returned them in its Proof-frame receipt, which
        # `atp send` prints. The committed file is read from the daemon's
        # inbox, which no other process writes.
        if [[ -f "${DESTINATION_PATH}" ]]; then
            RECEIVED_HASH="$(hash_file "${DESTINATION_PATH}")"
        fi
        if [[ "${SEND_COMMITTED}" == true && "${SEND_SHA_OK}" == true \
            && "${SEND_MERKLE_OK}" == true && "${RECEIVED_HASH}" == "${SOURCE_HASH}" ]]; then
            DETAIL="$(json_object destination_path "${DESTINATION_PATH}" received_sha256 "${RECEIVED_HASH}" receipt "json:{\"committed\":${SEND_COMMITTED},\"sha_ok\":${SEND_SHA_OK},\"merkle_ok\":${SEND_MERKLE_OK},\"files\":${SEND_FILES}}" observed_from "receiver Proof-frame receipt printed by atp send, and the committed file under the daemon inbox")"
            log_event "${DAEMON_LOG_PATH}" "daemon_artifact_verified" "atp_serve" "${DETAIL}"
            log_event "${EVENTS_PATH}" "daemon_artifact_verified" "atp_serve" "${DETAIL}"
        fi
    else
        DETAIL="$(json_object exit_status "json:${CLI_STATUS}" timed_out "json:${CLI_TIMED_OUT}" elapsed_ms "json:${CLI_ELAPSED_MS}" stdout_path "${CLI_STDOUT_PATH}" stderr_path "${CLI_STDERR_PATH}")"
        log_event "${CLI_LOG_PATH}" "cli_send_failed" "atp_send" "${DETAIL}"
        log_event "${EVENTS_PATH}" "cli_send_failed" "atp_send" "${DETAIL}"
    fi
fi

stop_daemon
DETAIL="$(json_object pid "json:${DAEMON_PID}" signal "${DAEMON_STOP_SIGNAL}" exit_status "json:${DAEMON_STATUS}" alive_until_stop "json:${DAEMON_ALIVE_AT_STOP}")"
log_event "${DAEMON_LOG_PATH}" "daemon_stopped" "atp_serve" "${DETAIL}"
log_event "${EVENTS_PATH}" "daemon_stopped" "atp_serve" "${DETAIL}"

SCAN_LINE="$(scan_daemon_stderr)"
IFS=$'\t' read -r DAEMON_COMMIT_COUNT DAEMON_COMMIT_ID DAEMON_COMMIT_BYTES DAEMON_COMMIT_FILES \
    DAEMON_FAILED_LINES DAEMON_PANIC_LINES DAEMON_COMMIT_JSON <<< "${SCAN_LINE}"
if [[ "${DAEMON_COMMIT_COUNT}" -gt 0 ]]; then
    log_event "${DAEMON_LOG_PATH}" "daemon_commit_logged" "atp_serve" \
        "$(json_object commit "json:${DAEMON_COMMIT_JSON}" count "json:${DAEMON_COMMIT_COUNT}" observed_from daemon_stderr)"
fi

# Verification: every check runs, and each failure is named.
if [[ -f "${DESTINATION_PATH}" ]]; then
    RECEIVED_HASH="$(hash_file "${DESTINATION_PATH}")"
fi
INBOX_LISTING="$(inbox_entries "${INBOX_DIR}")"
if [[ "${DAEMON_READY}" == true ]]; then
    if [[ "${CLI_TIMED_OUT}" == true ]]; then
        add_failure "atp send did not finish within ${SEND_DEADLINE_SEC} s"
    elif [[ "${CLI_STATUS}" -ne 0 ]]; then
        add_failure "atp send exited ${CLI_STATUS}"
    elif [[ "${SEND_PARSED}" != true ]]; then
        add_failure "atp send exited 0 without one parseable JSON result on stdout"
    fi
fi
if [[ "${SEND_PARSED}" == true ]]; then
    [[ "${SEND_STATUS}" == committed ]] || add_failure "atp send reported status ${SEND_STATUS}"
    [[ "${SEND_COMMITTED}" == true ]] || add_failure "receiver receipt committed=${SEND_COMMITTED}"
    [[ "${SEND_SHA_OK}" == true ]] || add_failure "receiver receipt sha_ok=${SEND_SHA_OK}"
    [[ "${SEND_MERKLE_OK}" == true ]] || add_failure "receiver receipt merkle_ok=${SEND_MERKLE_OK}"
    [[ "${SEND_FILES}" -eq 1 ]] || add_failure "atp send reported ${SEND_FILES} files, expected 1"
    [[ "${SEND_BYTES_SENT}" -eq "${SOURCE_BYTES}" ]] \
        || add_failure "atp send reported ${SEND_BYTES_SENT} bytes sent for a ${SOURCE_BYTES}-byte artifact"
    [[ "${SEND_TARGET}" == "${LISTEN_ADDRESS}" ]] \
        || add_failure "atp send targeted ${SEND_TARGET}, the daemon listened on ${LISTEN_ADDRESS}"
fi
if [[ ! -f "${DESTINATION_PATH}" ]]; then
    add_failure "no committed artifact at ${DESTINATION_PATH}"
else
    cmp -s "${SOURCE_PATH}" "${DESTINATION_PATH}" \
        || add_failure "committed artifact differs from the source byte for byte"
    [[ "${RECEIVED_HASH}" == "${SOURCE_HASH}" ]] \
        || add_failure "committed artifact sha256 ${RECEIVED_HASH} differs from source ${SOURCE_HASH}"
fi
[[ "${INBOX_LISTING}" == "artifact.txt" ]] \
    || add_failure "daemon inbox holds [${INBOX_LISTING}], expected exactly [artifact.txt]"
[[ "${DAEMON_ALIVE_AT_STOP}" == true ]] \
    || add_failure "atp serve was not running when the harness stopped it (exit status ${DAEMON_STATUS})"
[[ "${DAEMON_FAILED_LINES}" -eq 0 ]] \
    || add_failure "atp serve logged ${DAEMON_FAILED_LINES} failed transfer(s) on stderr"
[[ "${DAEMON_PANIC_LINES}" -eq 0 ]] || add_failure "atp serve stderr reports a panic"
if [[ "${DAEMON_COMMIT_COUNT}" -gt 1 ]]; then
    add_failure "atp serve logged ${DAEMON_COMMIT_COUNT} committed transfers, expected at most 1"
elif [[ "${DAEMON_COMMIT_COUNT}" -eq 1 ]]; then
    [[ "${DAEMON_COMMIT_ID}" == "${TRANSFER_ID}" ]] \
        || add_failure "atp serve committed transfer ${DAEMON_COMMIT_ID}, atp send reported ${TRANSFER_ID}"
    [[ "${DAEMON_COMMIT_BYTES}" -eq "${SOURCE_BYTES}" && "${DAEMON_COMMIT_FILES}" -eq 1 ]] \
        || add_failure "atp serve logged ${DAEMON_COMMIT_BYTES} bytes in ${DAEMON_COMMIT_FILES} files"
fi

STATUS="failed"
if [[ -z "${FAILURE_REASONS}" ]]; then
    STATUS="success"
fi

export REPORT_SCHEMA_VERSION EVENT_SCHEMA_VERSION SCENARIO_ID BEAD_ID RUN_ID STATUS \
    ASUPERSYNC_BIN ASUPERSYNC_VERSION BINARY_PEER_ID TRANSFER_ID MANIFEST_ROOT PROOF_ROOT \
    SOURCE_PATH DESTINATION_PATH SOURCE_HASH RECEIVED_HASH SOURCE_BYTES SEND_BYTES_SENT \
    LISTEN_REQUEST LISTEN_ADDRESS SERVE_COMMAND_LINE SEND_COMMAND_LINE REPLAY_COMMAND \
    DAEMON_PID DAEMON_STATUS DAEMON_STOP_SIGNAL DAEMON_ALIVE_AT_STOP DAEMON_COMMIT_JSON \
    CLI_STATUS CLI_TIMED_OUT CLI_ELAPSED_MS CLI_RESULT_JSON FAILURE_REASONS INBOX_LISTING \
    RUN_DIR RECEIVER_DATA_DIR EVENTS_PATH DAEMON_LOG_PATH CLI_LOG_PATH RUN_LOG_PATH \
    JOURNAL_PATH PROOF_PATH REPORT_PATH FAILURE_BUNDLE_PATH SUMMARY_PATH \
    DAEMON_STDOUT_PATH DAEMON_STDERR_PATH CLI_STDOUT_PATH CLI_STDERR_PATH

if [[ "${STATUS}" == success ]]; then
    log_event "${EVENTS_PATH}" "journey_verified" "harness" \
        "$(json_object source_sha256 "${SOURCE_HASH}" received_sha256 "${RECEIVED_HASH}" bytes "json:${SOURCE_BYTES}")"
else
    log_event "${EVENTS_PATH}" "journey_failed" "harness" \
        "$(json_object failure_reasons "json:$(printf '%s' "${FAILURE_REASONS}" | python3 -c 'import json, sys; print(json.dumps([l for l in sys.stdin.read().splitlines() if l]))')" source_sha256 "${SOURCE_HASH}" received_sha256 "${RECEIVED_HASH}")"
    dump_child_logs
fi

# Proof, journal entry, failure bundle, report and summary, from the facts above.
python3 - <<'PY'
import json
import os
import platform

env = os.environ


def raw_json(name):
    value = env.get(name, "null")
    return json.loads(value) if value else None


def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


status = env["STATUS"]
failure_reasons = [line for line in env.get("FAILURE_REASONS", "").splitlines() if line]
cli_result = raw_json("CLI_RESULT_JSON")
daemon_commit = raw_json("DAEMON_COMMIT_JSON")
receipt = None
if cli_result is not None:
    receipt = {key: cli_result[key] for key in ("status", "committed", "sha_ok", "merkle_ok", "files")}

not_run = [
    {
        "assertion": "daemon_manifest_received",
        "reason": "atp serve logs no per-manifest line, so manifest receipt is not observable apart from the commit",
    },
    {
        "assertion": "daemon_proof_written",
        "reason": "atp serve writes no proof file; its verdict reaches the harness only as the Proof-frame receipt fields atp send prints (committed, sha_ok, merkle_ok)",
    },
    {
        "assertion": "proof_root",
        "reason": "the ATP-over-TCP v1 receipt carries no proof root",
    },
]
if daemon_commit is None:
    not_run.append(
        {
            "assertion": "daemon_commit_log_line",
            "reason": "atp serve prints a finished transfer only on its next accept-loop pass (another connection or the 60 s accept timeout); the harness stopped it first",
        }
    )

proof = {
    "schema_version": "asupersync.atp.user_journey.proof.v1",
    "status": "verified" if status == "success" else "not_verified",
    "producer": "harness, from the atp send result and its own cmp and sha256 of the committed file",
    "run_id": env["RUN_ID"],
    "transfer_id": env["TRANSFER_ID"],
    "manifest_root": env["MANIFEST_ROOT"],
    "proof_root": env["PROOF_ROOT"],
    "source_sha256": env["SOURCE_HASH"],
    "received_sha256": env["RECEIVED_HASH"],
    "verification": "byte_for_byte_cmp_and_sha256",
    "receiver_receipt": receipt,
    "daemon_listen_address": env["LISTEN_ADDRESS"] or None,
}
write_json(env["PROOF_PATH"], proof)

journal = {
    "schema_version": "asupersync.atp.user_journey.journal.v1",
    "run_id": env["RUN_ID"],
    "scenario_id": env["SCENARIO_ID"],
    "transfer_id": env["TRANSFER_ID"],
    "status": status,
    "manifest_root": env["MANIFEST_ROOT"],
    "proof_root": env["PROOF_ROOT"],
    "listen_address": env["LISTEN_ADDRESS"] or None,
    "events_path": env["EVENTS_PATH"],
    "daemon_log_path": env["DAEMON_LOG_PATH"],
}
with open(env["JOURNAL_PATH"], "a", encoding="utf-8") as handle:
    json.dump(journal, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")

bundle = {
    "schema_version": "asupersync.atp.user_journey.failure_bundle.v1",
    "bead_id": env["BEAD_ID"],
    "run_id": env["RUN_ID"],
    "scenario_id": env["SCENARIO_ID"],
    "status": status,
    "cli_status": raw_json("CLI_STATUS"),
    "daemon_status": raw_json("DAEMON_STATUS"),
    "failure_reasons": failure_reasons,
    "events_path": env["EVENTS_PATH"],
    "daemon_log_path": env["DAEMON_LOG_PATH"],
    "cli_log_path": env["CLI_LOG_PATH"],
    "run_log_path": env["RUN_LOG_PATH"],
    "daemon_stderr_path": env["DAEMON_STDERR_PATH"],
    "cli_stderr_path": env["CLI_STDERR_PATH"],
    "redaction_policy": "paths_and_hashes_only_no_payload_bytes",
    "replay_command": env["REPLAY_COMMAND"],
}
write_json(env["FAILURE_BUNDLE_PATH"], bundle)

report = {
    "schema_version": env["REPORT_SCHEMA_VERSION"],
    "event_schema_version": env["EVENT_SCHEMA_VERSION"],
    "bead_id": env["BEAD_ID"],
    "scenario_id": env["SCENARIO_ID"],
    "status": status,
    "run_id": env["RUN_ID"],
    "real_io_required": True,
    "process_model": "local_child_daemon",
    "transport": "atp_tcp_loopback",
    "surfaces": ["asupersync atp send", "asupersync atp serve"],
    "planned_sdk_followup": "sdk transport journey remains covered by sibling ATP SDK beads",
    "command_line": env["SEND_COMMAND_LINE"],
    "environment": {
        "os": platform.system(),
        "arch": platform.machine(),
        "shell": env.get("SHELL", "unknown"),
        "asupersync_bin": env["ASUPERSYNC_BIN"],
        "asupersync_version": env["ASUPERSYNC_VERSION"],
    },
    "transfer": {
        "transfer_id": env["TRANSFER_ID"],
        "source_peer_id": env["BINARY_PEER_ID"],
        "destination_peer_id": env["BINARY_PEER_ID"],
        "source_path": env["SOURCE_PATH"],
        "destination_path": env["DESTINATION_PATH"],
        "source_bytes": int(env["SOURCE_BYTES"]),
        "bytes_transferred": int(env["SEND_BYTES_SENT"]),
        "source_sha256": env["SOURCE_HASH"],
        "received_sha256": env["RECEIVED_HASH"],
        "verification": "byte_for_byte_cmp_and_sha256",
        "manifest_root": env["MANIFEST_ROOT"],
        "proof_root": env["PROOF_ROOT"],
        "receiver_receipt": receipt,
    },
    "daemon": {
        "pid": int(env["DAEMON_PID"]),
        "command_line": env["SERVE_COMMAND_LINE"],
        "requested_listen": env["LISTEN_REQUEST"],
        "listen_address": env["LISTEN_ADDRESS"] or None,
        "data_dir": env["RECEIVER_DATA_DIR"],
        "inbox_entries": [name for name in env["INBOX_LISTING"].split(",") if name],
        "alive_until_stop": raw_json("DAEMON_ALIVE_AT_STOP"),
        "stop_signal": env["DAEMON_STOP_SIGNAL"],
        "exit_status": raw_json("DAEMON_STATUS"),
        "commit_log_line": daemon_commit,
        "log_path": env["DAEMON_LOG_PATH"],
        "stdout_path": env["DAEMON_STDOUT_PATH"],
        "stderr_path": env["DAEMON_STDERR_PATH"],
        "asserted_events": ["daemon_started", "daemon_artifact_verified", "daemon_stopped"],
    },
    "cli": {
        "command_line": env["SEND_COMMAND_LINE"],
        "exit_status": raw_json("CLI_STATUS"),
        "timed_out": raw_json("CLI_TIMED_OUT"),
        "elapsed_ms": raw_json("CLI_ELAPSED_MS"),
        "result": cli_result,
        "log_path": env["CLI_LOG_PATH"],
        "stdout_path": env["CLI_STDOUT_PATH"],
        "stderr_path": env["CLI_STDERR_PATH"],
    },
    "not_run": not_run,
    "failure_reasons": failure_reasons,
    "artifacts": {
        "run_dir": env["RUN_DIR"],
        "receiver_data_dir": env["RECEIVER_DATA_DIR"],
        "events_path": env["EVENTS_PATH"],
        "daemon_log_path": env["DAEMON_LOG_PATH"],
        "cli_log_path": env["CLI_LOG_PATH"],
        "run_log_path": env["RUN_LOG_PATH"],
        "journal_path": env["JOURNAL_PATH"],
        "proof_path": env["PROOF_PATH"],
        "failure_bundle_path": env["FAILURE_BUNDLE_PATH"],
        "summary_path": env["SUMMARY_PATH"],
        "daemon_stdout_path": env["DAEMON_STDOUT_PATH"],
        "daemon_stderr_path": env["DAEMON_STDERR_PATH"],
        "cli_stdout_path": env["CLI_STDOUT_PATH"],
        "cli_stderr_path": env["CLI_STDERR_PATH"],
        "replay_command": env["REPLAY_COMMAND"],
    },
    "human_summary": [
        f"ATP push {status}",
        f"transfer {env['TRANSFER_ID']}",
        f"daemon log asserted {env['DAEMON_LOG_PATH']}",
    ],
}
write_json(env["REPORT_PATH"], report)

with open(env["SUMMARY_PATH"], "w", encoding="utf-8") as handle:
    handle.write(f"ATP push {status}\n")
    handle.write(f"transfer {env['TRANSFER_ID']}\n")
    handle.write(f"daemon log {env['DAEMON_LOG_PATH']}\n")
    handle.write(f"proof {env['PROOF_PATH']}\n")

print(json.dumps(report, sort_keys=True, separators=(",", ":")))
PY

if [[ "${STATUS}" != "success" ]]; then
    exit 1
fi
