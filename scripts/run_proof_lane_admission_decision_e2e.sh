#!/usr/bin/env bash
set -euo pipefail

RUN_ID="local-check"
OUTPUT_ROOT="target/proof-lane-admission-decision"
GENERATED_AT="2026-06-06T05:35:00Z"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="${2:?missing --run-id value}"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="${2:?missing --output-root value}"
      shift 2
      ;;
    --generated-at)
      GENERATED_AT="${2:?missing --generated-at value}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

mkdir -p "$OUTPUT_ROOT"
LOG_PATH="$OUTPUT_ROOT/${RUN_ID}.log"
SUMMARY_PATH="$OUTPUT_ROOT/${RUN_ID}.summary.json"
: > "$LOG_PATH"

fixtures=(
  high_core_admit
  same_socket_contention_queue
  low_memory_numa_node
  stale_topology_input
  unrelated_dirty_tree_blocker
)

for fixture in "${fixtures[@]}"; do
  input="tests/fixtures/proof_lane_admission_decision/${fixture}.json"
  json_out="$OUTPUT_ROOT/${RUN_ID}.${fixture}.json"
  md_out="$OUTPUT_ROOT/${RUN_ID}.${fixture}.md"

  python3 scripts/proof_lane_admission_decision.py \
    --input "$input" \
    --generated-at "$GENERATED_AT" \
    --output json > "$json_out"
  python3 scripts/proof_lane_admission_decision.py \
    --input "$input" \
    --generated-at "$GENERATED_AT" \
    --output markdown > "$md_out"

  python3 - "$fixture" "$json_out" >> "$LOG_PATH" <<'PY'
import json
import sys

fixture = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    receipt = json.load(handle)
decision = receipt["decision"]
topology = receipt["topology_guidance"]
print(
    " ".join(
        [
            f"fixture={fixture}",
            f"decision={decision['admission_decision']}",
            f"precondition={decision['admission_precondition']}",
            f"topology={topology['classification']}",
            f"profile={topology['profile_id'] or 'none'}",
            f"proof_may_run_now={str(decision['proof_may_run_now']).lower()}",
        ]
    )
)
PY
done

python3 - "$OUTPUT_ROOT" "$RUN_ID" "${fixtures[@]}" > "$SUMMARY_PATH" <<'PY'
import json
import sys
from pathlib import Path

output_root = Path(sys.argv[1])
run_id = sys.argv[2]
fixtures = sys.argv[3:]
rows = []
for fixture in fixtures:
    path = output_root / f"{run_id}.{fixture}.json"
    with path.open("r", encoding="utf-8") as handle:
        receipt = json.load(handle)
    rows.append(
        {
            "fixture": fixture,
            "json_receipt": str(path),
            "markdown_receipt": str(output_root / f"{run_id}.{fixture}.md"),
            "admission_decision": receipt["decision"]["admission_decision"],
            "admission_precondition": receipt["decision"]["admission_precondition"],
            "proof_may_run_now": receipt["decision"]["proof_may_run_now"],
            "reason_codes": receipt["decision"]["reason_codes"],
            "topology_classification": receipt["topology_guidance"]["classification"],
            "topology_profile_id": receipt["topology_guidance"]["profile_id"],
            "topology_guidance_is_correctness_evidence": receipt["topology_guidance"][
                "topology_guidance_is_correctness_evidence"
            ],
        }
    )

print(
    json.dumps(
        {
            "schema_version": "proof-lane-admission-decision-e2e-summary-v1",
            "run_id": run_id,
            "dry_run_only": True,
            "non_mutating": True,
            "runs_cargo": False,
            "runs_rch": False,
            "writes_only_under": str(output_root),
            "log_path": str(output_root / f"{run_id}.log"),
            "fixtures": rows,
        },
        indent=2,
        sort_keys=True,
    )
)
PY

echo "$SUMMARY_PATH"
