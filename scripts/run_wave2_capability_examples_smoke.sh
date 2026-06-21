#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${WAVE2_CAPABILITY_EXAMPLES_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/capability_examples_smoke_recipes_evidence.json}"
OUTPUT_ROOT="${WAVE2_CAPABILITY_EXAMPLES_OUTPUT_ROOT:-${REPO_ROOT}/target/wave2-capability-examples}"
RUN_ID="${WAVE2_CAPABILITY_EXAMPLES_RUN_ID:-default}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_wave2_capability_examples_smoke.sh [options]

Options:
  --artifact <path>       Capability examples evidence artifact to validate.
  --output-root <dir>     Directory for the smoke report.
  --run-id <id>           Stable run identifier used in the output path.
  --list                  List smoke targets and exit.
  -h, --help              Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact)
            ARTIFACT_PATH="${2:-}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        --list)
            printf '%s\n' 'capability_examples_smoke_recipes'
            exit 0
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

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$OUTPUT_ROOT" "$RUN_ID" <<'PY'
import json
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
artifact_path = Path(sys.argv[2])
output_root = Path(sys.argv[3])
run_id = sys.argv[4]
report_dir = output_root / "asupersync-osh9jv" / run_id
report_path = report_dir / "capability-examples-smoke-report.json"

artifact = json.loads(artifact_path.read_text())
drifts = []
log_rows = []


def repo_path(relative):
    return repo_root / relative


def as_list(value, key):
    items = value.get(key, [])
    if not isinstance(items, list):
        drifts.append(f"{key}:not_array")
        return []
    return items


def require(condition, failure):
    if not condition:
        drifts.append(failure)


def text_value(row, key):
    value = row.get(key, "")
    if isinstance(value, list):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


def contains_sensitive_marker(value):
    lowered = value.lower()
    return any(marker in lowered for marker in ("password=", "token=", "secret=", "bearer "))


require(
    artifact.get("schema_version") == "capability-examples-smoke-recipes-evidence-v1",
    "schema_version:mismatch",
)
require(artifact.get("bead_id") == "asupersync-osh9jv", "bead_id:mismatch")
require(
    artifact.get("capability_id") == "capability_examples_smoke_recipes",
    "capability_id:mismatch",
)

for path_key in ("runner_script", "contract_test"):
    path = artifact.get(path_key, "")
    require(bool(path), f"{path_key}:missing")
    require(repo_path(path).is_file(), f"{path_key}:not_found:{path}")

for source_path in as_list(artifact, "source_evidence_paths"):
    require(repo_path(source_path).exists(), f"source_evidence_path:not_found:{source_path}")

required_log_fields = as_list(artifact, "required_log_fields")
required_cases = set(as_list(artifact, "required_support_cases"))
forbidden_markers = tuple(as_list(artifact, "forbidden_runtime_markers"))
seen_cases = set()

for row in as_list(artifact, "example_rows"):
    scenario_id = row.get("scenario_id", "<missing>")
    first_failure = ""

    for field in required_log_fields:
        if field not in row:
            failure = f"{scenario_id}:missing_field:{field}"
            drifts.append(failure)
            first_failure = first_failure or failure

    case_tags = set(as_list(row, "case_tags"))
    seen_cases.update(case_tags)

    command = row.get("command", "")
    if "cargo " in command and "rch exec --" not in command:
        failure = f"{scenario_id}:cargo_command_without_rch"
        drifts.append(failure)
        first_failure = first_failure or failure

    row_text = json.dumps(row, sort_keys=True)
    if contains_sensitive_marker(row_text):
        failure = f"{scenario_id}:sensitive_marker"
        drifts.append(failure)
        first_failure = first_failure or failure

    example_path = row.get("example_path", "")
    unsupported_reason = row.get("unsupported_reason", "")
    if unsupported_reason.strip():
        fallback_target = row.get("fallback_target", "")
        live_owner = row.get("live_owner_bead_id", "")
        if not fallback_target or not repo_path(fallback_target).exists():
            failure = f"{scenario_id}:unsupported_missing_fallback"
            drifts.append(failure)
            first_failure = first_failure or failure
        if not live_owner:
            failure = f"{scenario_id}:unsupported_missing_live_owner"
            drifts.append(failure)
            first_failure = first_failure or failure
    else:
        if not example_path or not repo_path(example_path).exists():
            failure = f"{scenario_id}:example_path_not_found"
            drifts.append(failure)
            first_failure = first_failure or failure
        if not command.strip():
            failure = f"{scenario_id}:command_missing"
            drifts.append(failure)
            first_failure = first_failure or failure

    if example_path.startswith("examples/") and repo_path(example_path).exists():
        body = repo_path(example_path).read_text()
        for marker in forbidden_markers:
            if marker and marker in body:
                failure = f"{scenario_id}:forbidden_runtime_marker:{marker}"
                drifts.append(failure)
                first_failure = first_failure or failure

    if row.get("expected_output_digest") != row.get("actual_output_digest"):
        failure = f"{scenario_id}:digest_mismatch"
        drifts.append(failure)
        first_failure = first_failure or failure

    emitted = {
        field: text_value(row, field)
        for field in required_log_fields
    }
    if first_failure:
        emitted["verdict"] = "fail"
        emitted["first_failure"] = first_failure
    log_rows.append(emitted)
    print(" ".join(f"{field}={emitted[field]}" for field in required_log_fields))

missing_cases = sorted(required_cases - seen_cases)
if missing_cases:
    drifts.append("required_support_cases:missing:" + ",".join(missing_cases))

report_dir.mkdir(parents=True, exist_ok=True)
report = {
    "bead_id": "asupersync-osh9jv",
    "capability_id": "capability_examples_smoke_recipes",
    "run_id": run_id,
    "artifact_path": str(artifact_path),
    "report_path": str(report_path),
    "row_count": len(log_rows),
    "required_support_cases": sorted(required_cases),
    "seen_support_cases": sorted(seen_cases),
    "drifts": drifts,
    "validation_passed": not drifts,
    "log_rows": log_rows,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if drifts:
    print("validation_failed=" + ",".join(drifts), file=sys.stderr)
    sys.exit(1)
PY
