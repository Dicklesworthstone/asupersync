#!/bin/bash
# ATP-N7: validate proof-lane artifacts emitted by run_lane.sh.

set -euo pipefail

LANE_ID=""
ARTIFACTS_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lane)
            LANE_ID="$2"
            shift 2
            ;;
        --artifacts-dir)
            ARTIFACTS_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$LANE_ID" || -z "$ARTIFACTS_DIR" ]]; then
    echo "Usage: validate_artifacts.sh --lane <lane> --artifacts-dir <dir>" >&2
    exit 2
fi

LANE_DIR="${ARTIFACTS_DIR}/${LANE_ID}"
METADATA="${LANE_DIR}/metadata.json"
STATUS="${LANE_DIR}/status.txt"

if [[ ! -s "$METADATA" ]]; then
    echo "Missing lane metadata: $METADATA" >&2
    exit 1
fi

if [[ ! -s "$STATUS" ]]; then
    echo "Missing lane status: $STATUS" >&2
    exit 1
fi

python3 - "$METADATA" "$STATUS" "$LANE_ID" <<'PY'
import json
import pathlib
import sys

metadata_path = pathlib.Path(sys.argv[1])
status_path = pathlib.Path(sys.argv[2])
expected_lane = sys.argv[3]

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
status = status_path.read_text(encoding="utf-8").strip()

if metadata.get("lane_id") != expected_lane:
    raise SystemExit(
        f"metadata lane_id {metadata.get('lane_id')!r} does not match {expected_lane!r}"
    )
if status != "SUCCESS":
    raise SystemExit(f"lane {expected_lane} status is {status!r}, expected SUCCESS")
if int(metadata.get("required_failures", -1)) != 0:
    raise SystemExit(f"lane {expected_lane} recorded required failures")
if int(metadata.get("exit_code", -1)) != 0:
    raise SystemExit(f"lane {expected_lane} recorded non-zero exit code")

print(f"validated lane artifacts for {expected_lane}")
PY
