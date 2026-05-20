#!/usr/bin/env bash
# Validate the incident replay import contract fixtures.
#
# Default mode is a deterministic fixture/catalog smoke that writes structured
# logs without invoking cargo. Pass --execute-rch to run the Rust importer test
# suite through rch as the heavy end-to-end lane.

set -euo pipefail

ARTIFACT="artifacts/incident_replay_import_contract_v1.json"
OUTPUT_ROOT="target/incident-replay-import"
RUN_ID="manual"
EXECUTE_RCH=0
RCH_BIN="${RCH_BIN:-rch}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/validate_incident_replay_import.sh [--output-root DIR] [--run-id ID] [--execute-rch]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --execute-rch)
      EXECUTE_RCH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

OUTDIR="${OUTPUT_ROOT}/${RUN_ID}"
REPORT="${OUTDIR}/incident-replay-import-report.json"
LOG="${OUTDIR}/incident-replay-import-events.ndjson"
RCH_LOG="${OUTDIR}/incident-replay-import-rch.log"
RCH_LOCAL_FALLBACK_MARKER="${OUTDIR}/incident-replay-import-rch-local-fallback.txt"
mkdir -p "$OUTDIR"

python3 - "$ARTIFACT" "$REPORT" "$LOG" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])

artifact = json.loads(artifact_path.read_text())
required = {
    "schema_version",
    "bead_id",
    "package_schema_version",
    "import_verdicts",
    "block_reason_kinds",
    "supported_replay_source_roles",
    "fixtures",
    "required_log_fields",
}
missing = sorted(required - artifact.keys())
if missing:
    raise SystemExit(f"artifact missing required fields: {missing}")

expected_verdicts = {"imported", "blocked", "malformed"}
if set(artifact["import_verdicts"]) != expected_verdicts:
    raise SystemExit("import_verdicts must be imported/blocked/malformed")

fixtures = artifact["fixtures"]
events = []

for fixture in fixtures["accepted"]:
    bundle = fixture["bundle"]
    roles = [
        source["kind"]
        for source in sorted(
            bundle["sources"],
            key=lambda source: (
                source["kind"],
                source["content_hash"],
                source["source_id"],
            ),
        )
    ]
    event = {
        "scenario_id": fixture["scenario_id"],
        "bead_id": artifact["bead_id"],
        "bundle_id": bundle["bundle_id"],
        "verdict": "imported",
        "package_id": "validated-by-rust-importer-test",
        "block_reason_kinds": [],
        "artifact_path": str(artifact_path),
        "source_roles": roles,
    }
    events.append(event)

for fixture in fixtures["rejected"]:
    bundle = fixture["bundle"]
    event = {
        "scenario_id": fixture["scenario_id"],
        "bead_id": artifact["bead_id"],
        "bundle_id": bundle["bundle_id"],
        "verdict": "blocked",
        "package_id": None,
        "block_reason_kinds": fixture["expected_block_reason_kinds"],
        "artifact_path": str(artifact_path),
        "source_roles": [source["kind"] for source in bundle["sources"]],
    }
    events.append(event)

events.append(
    {
        "scenario_id": "malformed-json",
        "bead_id": artifact["bead_id"],
        "bundle_id": None,
        "verdict": "malformed",
        "package_id": None,
        "block_reason_kinds": ["malformed_json"],
        "artifact_path": str(artifact_path),
        "source_roles": [],
    }
)

required_log_fields = set(artifact["required_log_fields"])
for event in events:
    missing_fields = sorted(required_log_fields - event.keys())
    if missing_fields:
        raise SystemExit(
            f"event {event['scenario_id']} missing fields: {missing_fields}"
        )

log_path.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n")
report = {
    "schema_version": "incident-replay-import-run-report-v1",
    "artifact": str(artifact_path),
    "scenario_count": len(events),
    "verdicts": sorted({event["verdict"] for event in events}),
    "events_path": str(log_path),
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

for event in events:
    print(json.dumps(event, sort_keys=True))
PY

if [[ "$EXECUTE_RCH" -eq 1 ]]; then
  set +e
  "${RCH_BIN}" exec -- \
    env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_incident_replay_import_script" \
      CARGO_INCREMENTAL=0 \
      CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS="-D warnings -C debuginfo=0" \
      cargo test -p asupersync --test incident_replay_import --features test-internals -- --nocapture \
    >"$RCH_LOG" 2>&1
  rch_status=$?
  set -e

  if grep -Eq '^\[RCH\] local \(|falling back to local' "$RCH_LOG" 2>/dev/null; then
    echo "rch local fallback detected; refusing local cargo execution" > "$RCH_LOCAL_FALLBACK_MARKER"
    exit 86
  fi
  if [[ "$rch_status" -ne 0 ]]; then
    exit "$rch_status"
  fi
fi

echo "report=${REPORT}"
