#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

artifact_root="${STUB_SCAN_ARTIFACT_ROOT:-target/mock-code-finder/asupersync-a45}"
jsonl="$artifact_root/no-mock-policy.jsonl"
summary="$artifact_root/no-mock-policy.summary.json"
policy_report="$artifact_root/no-mock-policy-report.json"
policy_log="$artifact_root/no-mock-policy.log"
negative_log="$artifact_root/no-mock-negative-fixture.log"
fixture_log="$artifact_root/no-mock-policy-fixtures.log"
stub_log="$artifact_root/no-mock-stub-scan.log"
stub_artifact_root="$artifact_root/stub-scan"
mkdir -p "$artifact_root" "$stub_artifact_root"

dump_failure_logs() {
  local status=$?
  if [[ "$status" -eq 0 ]]; then
    return
  fi
  echo "NO_MOCK_POLICY_EVIDENCE failed status=$status" >&2
  local log
  for log in "$policy_log" "$negative_log" "$fixture_log" "$stub_log"; do
    if [[ -f "$log" ]]; then
      echo "----- $log -----" >&2
      tail -200 "$log" >&2 || true
    else
      echo "----- $log missing -----" >&2
    fi
  done
}
trap dump_failure_logs EXIT

git_state="$(git rev-parse --short HEAD)"
if ! git diff --quiet -- . ':!target' 2>/dev/null; then
  git_state="${git_state}+dirty"
fi

echo "NO_MOCK_POLICY_EVIDENCE start bead=asupersync-a45 output=$jsonl" >&2

python3 scripts/check_no_mock_policy.py \
  --report-json "$policy_report" \
  --max-errors 20 >"$policy_log" 2>&1

python3 scripts/check_no_mock_policy.py \
  --self-test-negative-fixture >"$negative_log" 2>&1

python3 scripts/check_no_mock_policy.py \
  --self-test-policy-fixtures >"$fixture_log" 2>&1

STUB_SCAN_ARTIFACT_ROOT="$stub_artifact_root" \
STUB_SCAN_ARTIFACT_PATH_ROOT="$stub_artifact_root" \
  bash scripts/scan_stubs.sh >"$stub_log" 2>&1

python3 - "$jsonl" "$git_state" "$policy_report" "$policy_log" "$negative_log" "$fixture_log" "$stub_log" <<'PY'
import json
import sys

jsonl_path, git_state, policy_report_path, policy_log, negative_log, fixture_log, stub_log = sys.argv[1:]

with open(policy_report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)

schema = "mock-code-finder-evidence-jsonl-schema-v1"
bead = "asupersync-a45"
command = "bash scripts/run_no_mock_policy_evidence.sh"
category_counts = report["category_counts"]
scan_counts = report["scan_counts"]
coverage_counts = report["coverage_counts"]
remaining = report["remaining_allowlist_entries"]
category_summary = ", ".join(
    f"{name}:paths={counts['paths']},covered={counts['covered']},violations={counts['violations']}"
    for name, counts in sorted(category_counts.items())
)

records = [
    {
        "scenario_id": "NO-MOCK-POLICY-GATE-LIVE",
        "source_files_inspected": [
            "scripts/check_no_mock_policy.py",
            ".github/no_mock_policy.json",
            "artifacts/no_mock_policy_contract_v1.json",
        ],
        "test_filter": "no-mock-policy-report",
        "input_artifact": ".github/no_mock_policy.json",
        "output_artifact": policy_report_path,
        "expected_behavior": "The current tree produces a categorized no-mock policy report with zero undocumented or expired paths.",
        "actual_behavior": (
            f"status={report['status']} matching_paths={scan_counts['matching_paths']} "
            f"violating_paths={scan_counts['violating_paths']} coverage={coverage_counts}; "
            f"categories={category_summary}; remaining_allowlist_entries={len(remaining)}; log={policy_log}"
        ),
    },
    {
        "scenario_id": "NO-MOCK-NEGATIVE-CONFORMANCE-LIVE",
        "source_files_inspected": [
            "scripts/check_no_mock_policy.py",
            ".github/no_mock_policy.json",
        ],
        "test_filter": "self-test-negative-fixture",
        "input_artifact": "scripts/check_no_mock_policy.py",
        "output_artifact": negative_log,
        "expected_behavior": "A newly introduced fake conformance helper is rejected as conformance_placeholder.",
        "actual_behavior": f"negative conformance fixture rejected; log={negative_log}",
    },
    {
        "scenario_id": "NO-MOCK-POLICY-FIXTURES-LIVE",
        "source_files_inspected": [
            "scripts/check_no_mock_policy.py",
            ".github/no_mock_policy.json",
        ],
        "test_filter": "self-test-policy-fixtures",
        "input_artifact": ".github/no_mock_policy.json",
        "output_artifact": fixture_log,
        "expected_behavior": "Parser/classifier fixtures cover legitimate test doubles, new production placeholders, duplicate allowlist rows, expired rows, and missing replacement_issue metadata.",
        "actual_behavior": f"policy parser/classifier fixtures passed; log={fixture_log}",
    },
    {
        "scenario_id": "NO-MOCK-STUB-SCAN-RATCHET-LIVE",
        "source_files_inspected": [
            "scripts/scan_stubs.sh",
            "scripts/check_no_mock_policy.py",
            ".github/no_mock_policy.json",
        ],
        "test_filter": "scan_stubs",
        "input_artifact": "scripts/scan_stubs.sh",
        "output_artifact": stub_log,
        "expected_behavior": "The existing scan_stubs.sh production ratchet remains green after the no-mock policy coverage repair.",
        "actual_behavior": f"scan_stubs.sh passed with artifact root derived from STUB_SCAN_ARTIFACT_ROOT; log={stub_log}",
    },
]

with open(jsonl_path, "w", encoding="utf-8") as handle:
    for scenario in records:
        record = {
            "schema_version": schema,
            "bead_id": bead,
            "subsystem": "mock-code-finder",
            "support_class": "production_live",
            "command": command,
            "rch_command_if_used": "",
            "cargo_features": [],
            "env_keys_required": ["STUB_SCAN_ARTIFACT_ROOT"],
            "deterministic_seed_or_fixture_id": "no-mock-policy-contract-v1",
            "verdict": "pass",
            "first_failure_line": "",
            "duration_ms": 0,
            "git_sha_or_tree_state": git_state,
            "blocker_bead_id": "",
            "evidence_quality": "live",
        }
        record.update(scenario)
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
PY

python3 scripts/validate_mock_code_finder_evidence.py \
  --contract artifacts/mock_code_finder_verification_contract_v1.json \
  --jsonl "$jsonl" \
  --summary-output "$summary"

echo "NO_MOCK_POLICY_EVIDENCE jsonl=$jsonl" >&2
echo "NO_MOCK_POLICY_EVIDENCE summary=$summary" >&2
echo "NO_MOCK_POLICY_EVIDENCE report=$policy_report" >&2
wc -l "$jsonl" >&2
