#!/usr/bin/env bash
# Flake burndown report generator (asupersync-umelq.18.10)
#
# Analyzes quarantine manifest + nightly run history to produce trend-aware
# burndown reports with ownership routing and SLA breach detection.
#
# Usage:
#   scripts/generate_flake_burndown_report.sh [OPTIONS]
#
# Options:
#   --output PATH            Output report path (default: stdout)
#   --window N               Days of history to analyze (default: 14)
#   --quarantine PATH        Quarantine manifest path
#   --history-dir PATH       Nightly run history directory
#   --json                   JSON output (default: true)
#   -h, --help               Show this help
#
# Exit codes:
#   0 = report generated, no SLA breaches
#   1 = SLA breaches or critical regressions detected
#   2 = configuration error
#
# Bead: asupersync-umelq.18.10

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Defaults
OUTPUT=""
WINDOW_DAYS=14
QUARANTINE_PATH="$PROJECT_ROOT/artifacts/wasm_flake_quarantine_manifest.json"
HISTORY_DIR="$PROJECT_ROOT/target/nightly-stress"
JSON_OUTPUT=true

while [ $# -gt 0 ]; do
  case "$1" in
    --output)
      OUTPUT="$2"
      shift 2
      ;;
    --window)
      WINDOW_DAYS="$2"
      shift 2
      ;;
    --quarantine)
      QUARANTINE_PATH="$2"
      shift 2
      ;;
    --history-dir)
      HISTORY_DIR="$2"
      shift 2
      ;;
    --json)
      JSON_OUTPUT=true
      shift
      ;;
    -h|--help)
      head -25 "$0" | tail -22
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

# ── Analysis ────────────────────────────────────────────────────────────

python3 - "$QUARANTINE_PATH" "$HISTORY_DIR" "$WINDOW_DAYS" "$TIMESTAMP" "$OUTPUT" <<'PYEOF'
import json
import os
import sys
from datetime import datetime, timedelta, timezone

quarantine_path = sys.argv[1]
history_dir = sys.argv[2]
window_days = int(sys.argv[3])
generated_at = sys.argv[4]
output_path = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None

now = datetime.now(timezone.utc)
cutoff = now - timedelta(days=window_days)

# ── Parse quarantine manifest ──────────────────────────────────────────

open_flakes = []
resolved_recent = []
new_recent = []
sla_breaches = []
owner_routing = {}

sla_hours = {"critical": 24, "high": 72, "medium": 168}

if os.path.exists(quarantine_path):
    with open(quarantine_path) as f:
        data = json.load(f)

    entries = data.get("entries", data) if isinstance(data, dict) else data
    if isinstance(entries, list):
        for entry in entries:
            status = entry.get("status", "")
            severity = entry.get("severity", "low")
            owner = entry.get("owner", "unassigned")
            opened_at = entry.get("opened_at_utc", "")

            if status == "open":
                open_flakes.append(entry)

                # SLA check
                if opened_at:
                    try:
                        opened_dt = datetime.fromisoformat(opened_at.replace("Z", "+00:00"))
                        elapsed_hours = (now - opened_dt).total_seconds() / 3600
                        limit = sla_hours.get(severity, 168)
                        if elapsed_hours > limit:
                            sla_breaches.append({
                                "id": entry.get("id", "unknown"),
                                "severity": severity,
                                "owner": owner,
                                "elapsed_hours": round(elapsed_hours, 1),
                                "sla_limit_hours": limit,
                            })
                    except (ValueError, TypeError):
                        pass

                # Owner routing
                owner_routing.setdefault(owner, []).append({
                    "id": entry.get("id", "unknown"),
                    "suite": entry.get("suite", "unknown"),
                    "severity": severity,
                })

            elif status == "resolved":
                resolved_at = entry.get("resolved_at_utc", "")
                if resolved_at:
                    try:
                        resolved_dt = datetime.fromisoformat(resolved_at.replace("Z", "+00:00"))
                        if resolved_dt >= cutoff:
                            resolved_recent.append(entry)
                    except (ValueError, TypeError):
                        pass

            if opened_at:
                try:
                    opened_dt = datetime.fromisoformat(opened_at.replace("Z", "+00:00"))
                    if opened_dt >= cutoff and status != "resolved":
                        new_recent.append(entry)
                except (ValueError, TypeError):
                    pass

# ── Parse nightly run history ──────────────────────────────────────────

history = []
if os.path.isdir(history_dir):
    for run_dir in sorted(os.listdir(history_dir)):
        manifest_path = os.path.join(history_dir, run_dir, "run_manifest.json")
        if not os.path.isfile(manifest_path):
            continue
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            date_str = manifest.get("started_at_utc", "")[:10]
            history.append({
                "date": date_str,
                "run_id": manifest.get("run_id", run_dir),
                "result": manifest.get("overall_result", "unknown"),
                "total_tests_run": manifest.get("total_tests_run", 0),
                "total_tests_passed": manifest.get("total_tests_passed", 0),
                "total_tests_failed": manifest.get("total_tests_failed", 0),
                "duration_secs": manifest.get("total_duration_secs", 0),
            })
        except (json.JSONDecodeError, KeyError):
            continue

# ── Burndown trend ──────────────────────────────────────────────────────

critical_count = sum(1 for f in open_flakes if f.get("severity") == "critical")
high_count = sum(1 for f in open_flakes if f.get("severity") == "high")
medium_count = sum(1 for f in open_flakes if f.get("severity") == "medium")

if len(open_flakes) == 0:
    burndown_trend = "clear"
elif len(resolved_recent) > len(new_recent):
    burndown_trend = "improving"
elif len(resolved_recent) < len(new_recent):
    burndown_trend = "degrading"
else:
    burndown_trend = "stable"

release_blocked = critical_count > 0 or len(sla_breaches) > 0
block_reasons = []
if critical_count > 0:
    block_reasons.append(f"{critical_count} critical flake(s) in quarantine")
if len(sla_breaches) > 0:
    block_reasons.append(f"{len(sla_breaches)} SLA breach(es) detected")

# ── Owner routing list ──────────────────────────────────────────────────

owner_list = []
for owner, items in sorted(owner_routing.items()):
    owner_list.append({
        "owner": owner,
        "open_count": len(items),
        "items": items,
    })

# ── Build report ────────────────────────────────────────────────────────

report = {
    "schema_version": "nightly-burndown-report-v1",
    "generated_at_utc": generated_at,
    "window_days": window_days,
    "summary": {
        "total_open_flakes": len(open_flakes),
        "critical_flakes": critical_count,
        "high_flakes": high_count,
        "medium_flakes": medium_count,
        "overdue_sla_count": len(sla_breaches),
        "resolved_in_window": len(resolved_recent),
        "new_in_window": len(new_recent),
        "burndown_trend": burndown_trend,
    },
    "release_gate": {
        "blocked": release_blocked,
        "reasons": block_reasons,
    },
    "sla_breaches": sla_breaches,
    "owner_routing": owner_list,
    "history": history[-window_days:],
}

output_json = json.dumps(report, indent=2)

if output_path:
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(output_json + "\n")
    print(f"Burndown report written to: {output_path}", file=sys.stderr)
else:
    print(output_json)

# Exit code
if release_blocked:
    sys.exit(1)
sys.exit(0)
PYEOF
