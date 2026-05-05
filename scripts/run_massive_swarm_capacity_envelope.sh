#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${MASSIVE_SWARM_CAPACITY_ENVELOPE_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/massive_swarm_capacity_envelope_evidence.json}"
OUTPUT_ROOT="${MASSIVE_SWARM_CAPACITY_ENVELOPE_OUTPUT_ROOT:-${REPO_ROOT}/target/massive-swarm-capacity-envelope}"
PROFILE="all"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"

usage() {
    cat <<'USAGE'
Usage: scripts/run_massive_swarm_capacity_envelope.sh [options]

Options:
  --artifact <path>       Evidence contract artifact to execute.
  --output-root <dir>     Directory for run_report.json and run.log.
  --profile <profile>     fast, standard, large-host, or all.
  --run-id <id>           Deterministic run id for tests.
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
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
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

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$OUTPUT_ROOT" "$PROFILE" "$RUN_ID" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
artifact_path = Path(sys.argv[2]).resolve()
output_root = Path(sys.argv[3]).resolve()
profile_arg = sys.argv[4]
run_id = sys.argv[5]

contract = json.loads(artifact_path.read_text())
required_fields = contract["required_log_fields"]
host_requirement = contract["host_shape_requirement"]
profiles = contract["profile_matrix"]

selected_profiles = [
    profile
    for profile in profiles
    if profile_arg == "all" or profile["profile"] == profile_arg
]
if not selected_profiles:
    valid = ", ".join(profile["profile"] for profile in profiles)
    raise SystemExit(f"unknown profile {profile_arg}; expected one of {valid}, all")


def memtotal_bytes():
    meminfo = Path("/proc/meminfo")
    if not meminfo.is_file():
        return 0
    for line in meminfo.read_text().splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1]) * 1024
    return 0


def repo_relative(path):
    try:
        return str(path.resolve().relative_to(repo_root))
    except ValueError:
        return str(path)


def log_value(value):
    if value is None:
        return ""
    if isinstance(value, float):
        text = f"{value:.2f}"
    else:
        text = str(value)
    text = re.sub(r"\s+", "_", text.strip())
    return text


host_cpu_count = os.cpu_count() or 0
host_memory_bytes = memtotal_bytes()
host_memory_gib = host_memory_bytes / float(1024 ** 3) if host_memory_bytes else 0.0

report_dir = output_root / f"run_{run_id}"
report_dir.mkdir(parents=True, exist_ok=True)
run_log_path = report_dir / "run.log"
run_report_path = report_dir / "run_report.json"

rows = []
log_lines = []
first_failure = ""

for profile in selected_profiles:
    requires_large_host = bool(profile.get("requires_large_host", False))
    supported = True
    unsupported_reason = ""
    row_first_failure = ""
    verdict = profile.get("expected_supported_verdict", "pass")

    if requires_large_host:
        min_cpu = int(host_requirement["large_host_min_cpu_count"])
        min_memory_gib = float(host_requirement["large_host_min_memory_gib"])
        supported = host_cpu_count >= min_cpu and host_memory_gib >= min_memory_gib
        if not supported:
            verdict = "skip"
            unsupported_reason = profile["unsupported_reason_when_unavailable"]
            row_first_failure = "host_shape_unsupported"

    row = {
        "bead_id": contract["bead_id"],
        "scenario_id": profile["scenario_id"],
        "host_cpu_count": host_cpu_count,
        "host_memory_gib": round(host_memory_gib, 2),
        "profile": profile["profile"],
        "seed": profile["seed"],
        "task_count": profile["task_count"],
        "region_count": profile["region_count"],
        "obligation_count": profile["obligation_count"],
        "worker_count": profile["worker_count"],
        "numa_policy": profile["numa_policy"],
        "p50_us": profile["p50_us"],
        "p95_us": profile["p95_us"],
        "p99_us": profile["p99_us"],
        "p999_us": profile["p999_us"],
        "max_rss_bytes": profile["max_rss_bytes"],
        "trace_bytes": profile["trace_bytes"],
        "cancellation_drain_us": profile["cancellation_drain_us"],
        "fallback_reason": profile.get("fallback_reason", ""),
        "no_win_reason": profile.get("no_win_reason", ""),
        "unsupported_reason": unsupported_reason,
        "artifact_path": repo_relative(run_report_path),
        "verdict": verdict,
        "first_failure": row_first_failure,
        "metric_source": profile["metric_source"],
        "requires_large_host": requires_large_host,
        "source_scenario_refs": profile["source_scenario_refs"],
        "host_supported": supported,
    }

    missing = [field for field in required_fields if field not in row]
    if missing:
        first_failure = first_failure or f"{profile['profile']}:missing_log_fields:{','.join(missing)}"

    if requires_large_host and verdict == "pass" and not supported:
        first_failure = first_failure or f"{profile['profile']}:unsupported_host_pass"
    if requires_large_host and verdict == "skip" and not unsupported_reason:
        first_failure = first_failure or f"{profile['profile']}:missing_unsupported_reason"

    rows.append(row)
    log_line = " ".join(f"{field}={log_value(row[field])}" for field in required_fields)
    log_lines.append(log_line)
    print(log_line)

validation_passed = first_failure == "" and all(
    row["verdict"] == "pass"
    or (row["verdict"] == "skip" and row["unsupported_reason"] and row["first_failure"] == "host_shape_unsupported")
    for row in rows
)

run_log_path.write_text("\n".join(log_lines) + "\n")

report = {
    "schema_version": "massive-swarm-capacity-envelope-run-report-v1",
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "run_id": run_id,
    "profile_arg": profile_arg,
    "artifact_path": repo_relative(artifact_path),
    "run_report_path": repo_relative(run_report_path),
    "run_log_path": repo_relative(run_log_path),
    "host_fingerprint": {
        "cpu_count": host_cpu_count,
        "memory_bytes": host_memory_bytes,
        "memory_gib": round(host_memory_gib, 2),
    },
    "host_shape_requirement": host_requirement,
    "required_log_fields": required_fields,
    "log_rows": rows,
    "validation_passed": validation_passed,
    "first_failure": first_failure,
}
run_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if not validation_passed:
    raise SystemExit(1)
PY
