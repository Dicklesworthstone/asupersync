#!/usr/bin/env bash
# ATP CLI, atpd, and SDK user-journey e2e contract runner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="${ATP_CLI_USER_JOURNEY_OUTPUT_ROOT:-${REPO_ROOT}/target/e2e-results/atp_cli_user_journey}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
TIMEOUT_SEC="${ATP_CLI_USER_JOURNEY_TIMEOUT_SEC:-180}"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_atp_cli_user_journey_e2e}"
RCH_BIN="${RCH_BIN:-rch}"
CONTRACT_ONLY=0
DRY_RUN=0

usage() {
    cat <<'USAGE'
Usage: scripts/run_atp_cli_user_journey_e2e.sh [options]

Options:
  --output-root <dir>     Directory for run_report.json and structured_events.jsonl.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for the rch cargo proof.
  --target-dir <dir>      Cargo target directory used by rch.
  --contract-only         Validate the structured bundle contract without cargo.
  --dry-run               Record planned commands and emit a passing dry-run bundle.
  -h, --help              Show this help.
USAGE
}

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
        --timeout-sec)
            TIMEOUT_SEC="${2:-}"
            shift 2
            ;;
        --target-dir)
            TARGET_DIR="${2:-}"
            shift 2
            ;;
        --contract-only)
            CONTRACT_ONLY=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
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

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
RUN_LOG_PATH="${RUN_DIR}/run.log"
mkdir -p "${RUN_DIR}"
: > "${RUN_LOG_PATH}"

CARGO_COMMAND=(
    cargo test -p asupersync --features cli --lib cli::atp_user_journey -- --nocapture
)
RCH_COMMAND=(
    "${RCH_BIN}" exec -- env "CARGO_TARGET_DIR=${TARGET_DIR}" "${CARGO_COMMAND[@]}"
)

CARGO_STATUS=0
if [[ "${CONTRACT_ONLY}" -eq 1 || "${DRY_RUN}" -eq 1 ]]; then
    {
        printf 'ATP_CLI_USER_JOURNEY_COMMAND dry_run=%s contract_only=%s command=' \
            "${DRY_RUN}" "${CONTRACT_ONLY}"
        printf '%q ' "${RCH_COMMAND[@]}"
        printf '\nATP_CLI_USER_JOURNEY_COMMAND_STATUS status=0 skipped=true\n'
    } >> "${RUN_LOG_PATH}"
else
    if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        exit 1
    fi
    {
        printf 'ATP_CLI_USER_JOURNEY_COMMAND timeout_sec=%s command=' "${TIMEOUT_SEC}"
        printf '%q ' "${RCH_COMMAND[@]}"
        printf '\n'
    } >> "${RUN_LOG_PATH}"
    set +e
    timeout "${TIMEOUT_SEC}" "${RCH_COMMAND[@]}" >> "${RUN_LOG_PATH}" 2>&1
    CARGO_STATUS=$?
    set -e
    echo "ATP_CLI_USER_JOURNEY_COMMAND_STATUS status=${CARGO_STATUS}" >> "${RUN_LOG_PATH}"
fi

VALIDATOR_ARGS=(
    --output-root "${OUTPUT_ROOT}"
    --run-id "${RUN_ID}"
    --cargo-status "${CARGO_STATUS}"
)
if [[ "${DRY_RUN}" -eq 1 ]]; then
    VALIDATOR_ARGS+=(--dry-run)
fi

python3 "${REPO_ROOT}/tests/cli/atp_user_journey_contract.py" "${VALIDATOR_ARGS[@]}"
