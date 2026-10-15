#!/bin/bash
# ATP-N7: build a deterministic lane proof receipt from lane artifacts.

set -euo pipefail

LANE_ID=""
ARTIFACTS_DIR=""
OUTPUT=""

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
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$LANE_ID" || -z "$ARTIFACTS_DIR" || -z "$OUTPUT" ]]; then
    echo "Usage: generate_proof.sh --lane <lane> --artifacts-dir <dir> --output <path>" >&2
    exit 2
fi

mkdir -p "$(dirname "$OUTPUT")"

python3 - "$LANE_ID" "$ARTIFACTS_DIR" "$OUTPUT" <<'PY'
import hashlib
import json
import pathlib
import sys

lane_id = sys.argv[1]
artifacts_dir = pathlib.Path(sys.argv[2])
output = pathlib.Path(sys.argv[3])
metadata_path = artifacts_dir / lane_id / "metadata.json"
status_path = artifacts_dir / lane_id / "status.txt"

if not metadata_path.exists():
    raise SystemExit(f"missing metadata: {metadata_path}")
if not status_path.exists():
    raise SystemExit(f"missing status: {status_path}")

metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
status = status_path.read_text(encoding="utf-8").strip()
digest = hashlib.sha256(metadata_path.read_bytes() + b"\n" + status.encode()).hexdigest()

proof = {
    "schema_version": "atp-lane-proof-v1",
    "lane_id": lane_id,
    "status": status,
    "metadata": metadata,
    "metadata_status_sha256": digest,
    "passed": status == "SUCCESS"
    and int(metadata.get("required_failures", 1)) == 0
    and int(metadata.get("exit_code", 1)) == 0,
}

output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"wrote {output}")
PY
