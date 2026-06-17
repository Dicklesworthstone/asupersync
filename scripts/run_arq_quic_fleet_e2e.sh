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
Artifacts are retained under artifacts/arq_quic_e2e/<RUN_ID>/ unless OUTDIR is set.
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
    "optional_env": ["RUN_ID", "OUTDIR", "WR_BASE", "WR", "LOCAL_BASE", "LOCAL", "PORT", "SIZES"],
    "forced_methods": "atpquic",
    "retained_artifacts": {
        "local_default_root": str(root / "artifacts/arq_quic_e2e"),
        "remote_default_root": "/tmp/atp_bench/runs/<RUN_ID>",
        "packet_evidence": "receiver-side tcpdump_<method>_<label>.pcap when tcpdump is available",
        "receiver_logs": "recv_<method>_<label>.log copied into OUTDIR when available",
        "result_fields": ["retained_remote_dst", "retained_receiver_log", "tcpdump_status", "tcpdump_pcap"]
    },
    "no_delete_contract": [
        "normal runs use a unique RUN_ID-scoped remote work directory",
        "destination directories are retained for inspection",
        "payload and receiver artifacts are retained instead of being cleaned during the run"
    ],
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
        RUN_ID="${RUN_ID:-arq_quic_fleet_$(date -u +%Y%m%dT%H%M%SZ)_$$}"
        export RUN_ID
        OUTDIR="${OUTDIR:-$PROJECT_ROOT/artifacts/arq_quic_e2e/$RUN_ID}"
        export OUTDIR
        exec "$BENCH_SCRIPT" all
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        usage
        exit 2
        ;;
esac
