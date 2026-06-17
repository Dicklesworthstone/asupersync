#!/usr/bin/env bash
# Structured wrapper for the ARQ/QUIC fleet E2E lane.
#
# H5 owns the script surface and structure. The real two-machine execution is
# owned by G1/G2; normal mode delegates to the existing fleet benchmark driver
# with METHODS=atpquic, while --validate-structure emits a deterministic contract
# JSON without touching remote hosts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BENCH_SCRIPT="$SCRIPT_DIR/atp_quic_vs_rsync_benchmark.sh"
MODE="${1:-run}"

usage() {
    cat >&2 <<USAGE
Usage:
  $0 --validate-structure
  $0 run

Normal run requires the fleet benchmark environment:
  SENDER RECEIVER RECEIVER_IP ATP_BIN_LOCAL

The run delegates to scripts/atp_quic_vs_rsync_benchmark.sh with METHODS=atpquic.
G1/G2 own the actual two-machine execution and performance claims.
USAGE
}

case "$MODE" in
    -h|--help)
        usage
        exit 0
        ;;
    --validate-structure)
        if [[ ! -x "$BENCH_SCRIPT" && ! -f "$BENCH_SCRIPT" ]]; then
            echo "missing benchmark script: $BENCH_SCRIPT" >&2
            exit 1
        fi
        python3 - "$PROJECT_ROOT" "$BENCH_SCRIPT" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
bench = pathlib.Path(sys.argv[2])
payload = {
    "schema_version": "arq-quic-fleet-e2e-structure-v1",
    "status": "structure-valid",
    "script": str(root / "scripts/run_arq_quic_fleet_e2e.sh"),
    "delegates_to": str(bench),
    "required_env": ["SENDER", "RECEIVER", "RECEIVER_IP", "ATP_BIN_LOCAL"],
    "forced_methods": "atpquic",
    "no_claim_boundaries": [
        "structure validation does not execute the fleet transfer",
        "G1/G2 own two-machine evidence and benchmark claims",
        "no rsync comparison or performance claim is emitted by --validate-structure"
    ],
}
print(json.dumps(payload, sort_keys=True))
PY
        ;;
    run)
        for var in SENDER RECEIVER RECEIVER_IP ATP_BIN_LOCAL; do
            if [[ -z "${!var:-}" ]]; then
                echo "missing required environment variable: $var" >&2
                exit 2
            fi
        done
        export METHODS="atpquic"
        exec "$BENCH_SCRIPT" all
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        usage
        exit 2
        ;;
esac
