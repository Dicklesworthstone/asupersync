#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FIXTURE="${FIXTURE:-${PROJECT_ROOT}/tests/fixtures/dirty_tree_ownership_receipt/release_prep_shared_main.json}"
REPO_PATH="${REPO_PATH:-${PROJECT_ROOT}}"
AGENT="${AGENT:-TopazGoose}"
GENERATED_AT="${GENERATED_AT:-2026-06-05T06:05:00Z}"
OUTPUT_DIR="${OUTPUT_DIR:-${TMPDIR:-/tmp}/asupersync-dirty-tree-ownership-e2e-$$}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_dirty_tree_ownership_receipt_e2e.sh [--fixture PATH] [--repo-path PATH] [--agent NAME] [--generated-at TS] [--output-dir PATH]

Runs the dirty-tree ownership receipt against a synthetic shared-main fixture and
prints detailed, deterministic operator logs. The script is non-mutating: it
does not stage, commit, reset, clean, branch, create worktrees, send Agent Mail,
mutate Beads, or run Cargo.
USAGE
}

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --fixture)
            FIXTURE="$2"
            shift 2
            ;;
        --repo-path)
            REPO_PATH="$2"
            shift 2
            ;;
        --agent)
            AGENT="$2"
            shift 2
            ;;
        --generated-at)
            GENERATED_AT="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
RECEIPT_PATH="${OUTPUT_DIR}/dirty_tree_ownership_receipt.json"

python3 "${PROJECT_ROOT}/scripts/dirty_tree_ownership_receipt.py" \
    --fixture "$FIXTURE" \
    --repo-path "$REPO_PATH" \
    --agent "$AGENT" \
    --generated-at "$GENERATED_AT" \
    --release-prep-report \
    --output json \
    >"$RECEIPT_PATH"

python3 - "$RECEIPT_PATH" "$FIXTURE" <<'PY'
import json
import pathlib
import sys

receipt_path = pathlib.Path(sys.argv[1])
fixture_path = pathlib.Path(sys.argv[2])
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
report = receipt["release_prep_report"]

print("DIRTY_TREE_OWNERSHIP_E2E start")
print(f"fixture={fixture_path.name}")
print(f"repo_path={receipt['repo_path']}")
print(f"receipt_path={receipt_path}")
print(f"input_files count={len(report['input_files'])}")
for path in report["input_files"]:
    print(f"input_file path={path}")

print(f"reservation_holders count={len(report['reservation_holders'])}")
for row in report["reservation_holders"]:
    print(
        "reservation_holder "
        f"holder={row['holder']} pattern={row['path_pattern']} "
        f"state={row['state']} expires={row['expires_ts']}"
    )

subject_rows = []
for row in report["rows"]:
    for subject in row["matched_lane_subjects"]:
        subject_rows.append((row["path"], subject))
print(f"matched_lane_subjects count={len(subject_rows)}")
for path, subject in subject_rows:
    print(
        "matched_lane_subject "
        f"path={path} from={subject['from']} thread={subject['thread_id']} "
        f"subject={subject['subject']}"
    )

print(f"classifications count={len(report['rows'])}")
for row in report["rows"]:
    print(
        "classification "
        f"path={row['path']} class={row['classification']} "
        f"base={row['base_classification']} owner={row['owner']} "
        f"release_blocker={str(row['release_blocker']).lower()} "
        f"next={row['recommended_next_step']}"
    )

summary = report["release_blocker_summary"]
print(
    "release_blocker_summary "
    f"decision={summary['decision']} total={summary['total_dirty_paths']} "
    f"blockers={summary['release_blocker_count']} reason={summary['reason']}"
)
for path in summary["blocker_paths"]:
    print(f"release_blocker path={path}")

safety = report["safety"]
print(
    "safety "
    f"mutating_commands_executed={str(safety['mutating_commands_executed']).lower()} "
    f"destructive_cleanup_recommended={str(safety['destructive_cleanup_recommended']).lower()} "
    f"peer_owned_edit_or_stage_recommended={str(safety['peer_owned_edit_or_stage_recommended']).lower()}"
)
print("DIRTY_TREE_OWNERSHIP_E2E done")
PY
