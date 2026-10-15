#!/usr/bin/env python3
"""WASM flake-governance gate (asupersync-umelq.18.5).

Validates:
  1) Flake detection dashboard health and required suite coverage
  2) Quarantine manifest automation + SLA compliance
  3) Incident forensics playbook command linkage
  4) Release-blocking thresholds for unresolved high-severity flakes

Outputs:
  - artifacts/wasm_flake_governance_report.json
  - artifacts/wasm_flake_governance_events.ndjson
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CheckResult:
    check_id: str
    status: str  # pass | fail | skip
    detail: str


class GovernanceError(ValueError):
    """Raised when governance policy content is invalid."""


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise GovernanceError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise GovernanceError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise GovernanceError(f"root object required in {path}")
    return raw


def parse_iso8601_utc(raw: str) -> dt.datetime:
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    parsed = dt.datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise GovernanceError(f"timestamp missing timezone: {raw}")
    return parsed.astimezone(dt.timezone.utc)


def resolve_path(base: pathlib.Path, value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if path.is_absolute():
        return path
    return (base / path).resolve()


def validate_policy_shape(policy: dict[str, Any]) -> CheckResult:
    required_keys = {
        "schema_version",
        "detection",
        "quarantine",
        "quality_thresholds",
        "sla_targets_hours",
        "forensics_playbook",
        "output",
    }
    missing = sorted(required_keys - set(policy.keys()))
    if missing:
        return CheckResult(
            check_id="WG-POLICY-001",
            status="fail",
            detail=f"missing required policy keys: {', '.join(missing)}",
        )

    if policy.get("schema_version") != "wasm-flake-governance-policy-v1":
        return CheckResult(
            check_id="WG-POLICY-002",
            status="fail",
            detail="schema_version must be wasm-flake-governance-policy-v1",
        )

    detection = policy.get("detection", {})
    if not isinstance(detection.get("required_suites"), list) or not detection.get(
        "required_suites"
    ):
        return CheckResult(
            check_id="WG-POLICY-003",
            status="fail",
            detail="detection.required_suites must be a non-empty list",
        )

    thresholds = policy.get("quality_thresholds", {})
    threshold_keys = {
        "max_flake_rate_pct",
        "max_false_positive_rate_pct",
        "max_unresolved_high_severity_flakes",
        "max_unresolved_critical_severity_flakes",
        "max_critical_test_failures",
    }
    if not threshold_keys.issubset(set(thresholds.keys())):
        return CheckResult(
            check_id="WG-POLICY-004",
            status="fail",
            detail="quality_thresholds missing required fields",
        )

    return CheckResult(
        check_id="WG-POLICY-000",
        status="pass",
        detail="policy schema and required sections validated",
    )


def check_forensics_playbook(doc_path: pathlib.Path, required_commands: list[str]) -> CheckResult:
    if not doc_path.exists():
        return CheckResult(
            check_id="WG-FORENSICS-001",
            status="fail",
            detail=f"forensics playbook missing: {doc_path}",
        )

    text = doc_path.read_text(encoding="utf-8")
    missing = [cmd for cmd in required_commands if cmd not in text]
    if missing:
        return CheckResult(
            check_id="WG-FORENSICS-002",
            status="fail",
            detail=f"forensics playbook missing commands: {', '.join(missing)}",
        )

    required_tokens = ["replay", "trace_pointer", "reactivation"]
    token_missing = [token for token in required_tokens if token not in text]
    if token_missing:
        return CheckResult(
            check_id="WG-FORENSICS-003",
            status="fail",
            detail=f"forensics playbook missing tokens: {', '.join(token_missing)}",
        )

    return CheckResult(
        check_id="WG-FORENSICS-000",
        status="pass",
        detail="forensics playbook links deterministic replay + quarantine workflow",
    )


def check_dashboard(
    dashboard_path: pathlib.Path,
    dashboard_schema_version: str,
    required_suites: list[str],
    thresholds: dict[str, Any],
) -> CheckResult:
    if not dashboard_path.exists():
        return CheckResult(
            check_id="WG-DASH-001",
            status="fail",
            detail=f"dashboard file missing: {dashboard_path}",
        )

    try:
        dashboard = load_json(dashboard_path)
    except GovernanceError as exc:
        return CheckResult(
            check_id="WG-DASH-002",
            status="fail",
            detail=f"dashboard JSON invalid: {exc}",
        )

    if dashboard.get("schema_version") != dashboard_schema_version:
        return CheckResult(
            check_id="WG-DASH-003",
            status="fail",
            detail=(
                "dashboard schema mismatch: "
                f"expected {dashboard_schema_version}, got {dashboard.get('schema_version')}"
            ),
        )

    suites = dashboard.get("suites", [])
    if not isinstance(suites, list):
        return CheckResult(
            check_id="WG-DASH-004",
            status="fail",
            detail="dashboard suites must be a list",
        )

    suite_names = {
        s.get("suite") for s in suites if isinstance(s, dict) and isinstance(s.get("suite"), str)
    }
    missing_suites = [name for name in required_suites if name not in suite_names]
    if missing_suites:
        return CheckResult(
            check_id="WG-DASH-005",
            status="fail",
            detail=f"dashboard missing required suites: {', '.join(missing_suites)}",
        )

    suite_count = dashboard.get("suite_count")
    if not isinstance(suite_count, int) or suite_count < 0:
        suite_count = len(suites)

    unstable_count = dashboard.get("unstable_suite_count")
    if not isinstance(unstable_count, int) or unstable_count < 0:
        unstable_count = sum(
            1 for s in suites if isinstance(s, dict) and bool(s.get("unstable", False))
        )

    flake_rate = 0.0
    if suite_count > 0:
        flake_rate = (unstable_count * 100.0) / suite_count

    false_positive_proxy_count = 0
    critical_test_failures = 0
    for suite in suites:
        if not isinstance(suite, dict):
            continue
        unstable = bool(suite.get("unstable", False))
        outcomes = suite.get("outcomes", {})
        failures = outcomes.get("fail", 0) if isinstance(outcomes, dict) else 0
        if isinstance(failures, int) and failures > 0:
            critical_test_failures += failures
        if unstable and isinstance(failures, int) and failures == 0:
            false_positive_proxy_count += 1

    false_positive_rate = 0.0
    if suite_count > 0:
        false_positive_rate = (false_positive_proxy_count * 100.0) / suite_count

    breaches: list[str] = []
    if flake_rate > float(thresholds["max_flake_rate_pct"]):
        breaches.append(
            f"flake_rate_pct breach ({flake_rate:.2f} > {thresholds['max_flake_rate_pct']})"
        )
    if false_positive_rate > float(thresholds["max_false_positive_rate_pct"]):
        breaches.append(
            "false_positive_rate_pct breach "
            f"({false_positive_rate:.2f} > {thresholds['max_false_positive_rate_pct']})"
        )
    if critical_test_failures > int(thresholds["max_critical_test_failures"]):
        breaches.append(
            "critical_test_failures breach "
            f"({critical_test_failures} > {thresholds['max_critical_test_failures']})"
        )

    if breaches:
        return CheckResult(
            check_id="WG-DASH-006",
            status="fail",
            detail="; ".join(breaches),
        )

    return CheckResult(
        check_id="WG-DASH-000",
        status="pass",
        detail=(
            f"dashboard healthy (suite_count={suite_count}, unstable={unstable_count}, "
            f"flake_rate_pct={flake_rate:.2f}, false_positive_rate_pct={false_positive_rate:.2f}, "
            f"critical_test_failures={critical_test_failures})"
        ),
    )


def compute_dashboard_health(dashboard_path: pathlib.Path) -> dict[str, Any]:
    if not dashboard_path.exists():
        return {
            "status": "missing",
            "detail": f"dashboard missing: {dashboard_path}",
            "trend_lines": [],
        }

    try:
        dashboard = load_json(dashboard_path)
    except GovernanceError as exc:
        return {
            "status": "invalid",
            "detail": str(exc),
            "trend_lines": [],
        }

    suites = dashboard.get("suites", [])
    if not isinstance(suites, list):
        suites = []

    suite_count = dashboard.get("suite_count")
    if not isinstance(suite_count, int) or suite_count < 0:
        suite_count = len(suites)

    unstable_suite_count = dashboard.get("unstable_suite_count")
    if not isinstance(unstable_suite_count, int) or unstable_suite_count < 0:
        unstable_suite_count = sum(
            1 for suite in suites if isinstance(suite, dict) and bool(suite.get("unstable", False))
        )

    false_positive_proxy_count = 0
    critical_test_failures = 0
    trend_lines: list[dict[str, Any]] = []
    for suite in suites:
        if not isinstance(suite, dict):
            continue
        name = suite.get("suite", "<unknown>")
        unstable = bool(suite.get("unstable", False))
        outcomes = suite.get("outcomes", {})
        failures = outcomes.get("fail", 0) if isinstance(outcomes, dict) else 0
        if isinstance(failures, int) and failures > 0:
            critical_test_failures += failures
        if unstable and isinstance(failures, int) and failures == 0:
            false_positive_proxy_count += 1
        trend_lines.append(
            {
                "suite": name,
                "unstable": unstable,
                "failures": failures,
                "duration_spread_pct": suite.get("duration_spread_pct"),
                "instability_signals": suite.get("instability_signals", []),
            }
        )

    flake_rate_pct = 0.0
    false_positive_proxy_rate_pct = 0.0
    if suite_count > 0:
        flake_rate_pct = (unstable_suite_count * 100.0) / suite_count
        false_positive_proxy_rate_pct = (false_positive_proxy_count * 100.0) / suite_count

    gate_health = "healthy"
    if unstable_suite_count > 0 or critical_test_failures > 0:
        gate_health = "degraded"

    return {
        "status": "ok",
        "schema_version": dashboard.get("schema_version"),
        "gate_health": gate_health,
        "suite_count": suite_count,
        "unstable_suite_count": unstable_suite_count,
        "flake_rate_pct": round(flake_rate_pct, 2),
        "false_positive_proxy_rate_pct": round(false_positive_proxy_rate_pct, 2),
        "critical_test_failures": critical_test_failures,
        "trend_lines": trend_lines,
    }


def check_quarantine_manifest(
    manifest_path: pathlib.Path,
    schema_version: str,
    statuses: set[str],
    required_fields: list[str],
    thresholds: dict[str, Any],
    sla_targets_hours: dict[str, Any],
) -> CheckResult:
    if not manifest_path.exists():
        return CheckResult(
            check_id="WG-QUAR-001",
            status="fail",
            detail=f"quarantine manifest missing: {manifest_path}",
        )

    try:
        manifest = load_json(manifest_path)
    except GovernanceError as exc:
        return CheckResult(
            check_id="WG-QUAR-002",
            status="fail",
            detail=f"quarantine manifest JSON invalid: {exc}",
        )

    if manifest.get("schema_version") != schema_version:
        return CheckResult(
            check_id="WG-QUAR-003",
            status="fail",
            detail=(
                "quarantine schema mismatch: "
                f"expected {schema_version}, got {manifest.get('schema_version')}"
            ),
        )

    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        return CheckResult(
            check_id="WG-QUAR-004",
            status="fail",
            detail="quarantine entries must be a list",
        )

    unresolved_high = 0
    unresolved_critical = 0
    sla_breaches: list[str] = []
    now = dt.datetime.now(dt.timezone.utc)

    for entry in entries:
        if not isinstance(entry, dict):
            return CheckResult(
                check_id="WG-QUAR-005",
                status="fail",
                detail="quarantine entries must be objects",
            )

        missing = [field for field in required_fields if field not in entry]
        if missing:
            return CheckResult(
                check_id="WG-QUAR-006",
                status="fail",
                detail=f"quarantine entry missing fields: {', '.join(missing)}",
            )

        status = entry.get("status")
        severity = entry.get("severity")
        if status not in statuses:
            return CheckResult(
                check_id="WG-QUAR-007",
                status="fail",
                detail=f"invalid quarantine status: {status}",
            )
        if severity not in {"critical", "high", "medium", "low"}:
            return CheckResult(
                check_id="WG-QUAR-008",
                status="fail",
                detail=f"invalid quarantine severity: {severity}",
            )

        if status == "open":
            if severity == "high":
                unresolved_high += 1
            if severity == "critical":
                unresolved_critical += 1

            opened_raw = entry.get("opened_at_utc")
            sla_hours = entry.get("sla_hours")
            if not isinstance(opened_raw, str):
                return CheckResult(
                    check_id="WG-QUAR-009",
                    status="fail",
                    detail="open quarantine entry requires string opened_at_utc",
                )
            if not isinstance(sla_hours, int) or sla_hours <= 0:
                return CheckResult(
                    check_id="WG-QUAR-010",
                    status="fail",
                    detail="open quarantine entry requires positive integer sla_hours",
                )

            opened_at = parse_iso8601_utc(opened_raw)
            age_hours = (now - opened_at).total_seconds() / 3600.0
            if age_hours > sla_hours:
                sla_breaches.append(
                    f"{entry.get('id', '<unknown>')} breached entry SLA ({age_hours:.1f}h > {sla_hours}h)"
                )

            target = sla_targets_hours.get(severity)
            if isinstance(target, int) and target > 0 and sla_hours > target:
                sla_breaches.append(
                    f"{entry.get('id', '<unknown>')} sla_hours exceeds policy target ({sla_hours}h > {target}h)"
                )

    breaches: list[str] = []
    if unresolved_high > int(thresholds["max_unresolved_high_severity_flakes"]):
        breaches.append(
            "unresolved high flakes breach "
            f"({unresolved_high} > {thresholds['max_unresolved_high_severity_flakes']})"
        )
    if unresolved_critical > int(thresholds["max_unresolved_critical_severity_flakes"]):
        breaches.append(
            "unresolved critical flakes breach "
            f"({unresolved_critical} > {thresholds['max_unresolved_critical_severity_flakes']})"
        )
    breaches.extend(sla_breaches)

    if breaches:
        return CheckResult(
            check_id="WG-QUAR-011",
            status="fail",
            detail="; ".join(breaches),
        )

    return CheckResult(
        check_id="WG-QUAR-000",
        status="pass",
        detail=(
            f"quarantine healthy (entries={len(entries)}, unresolved_high={unresolved_high}, "
            f"unresolved_critical={unresolved_critical})"
        ),
    )


def git_sha(project_root: pathlib.Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    sha = result.stdout.strip()
    return sha or None


def write_report(
    report_path: pathlib.Path,
    events_path: pathlib.Path,
    policy_path: pathlib.Path,
    results: list[CheckResult],
    gate_status: str,
    dashboard_health: dict[str, Any] | None = None,
) -> None:
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    pass_count = sum(1 for r in results if r.status == "pass")
    fail_count = sum(1 for r in results if r.status == "fail")
    skip_count = sum(1 for r in results if r.status == "skip")

    report = {
        "schema_version": "wasm-flake-governance-report-v1",
        "generated_at_utc": generated_at,
        "git_sha": git_sha(pathlib.Path.cwd()),
        "policy_path": str(policy_path),
        "gate_status": gate_status,
        "summary": {
            "total": len(results),
            "pass": pass_count,
            "fail": fail_count,
            "skip": skip_count,
        },
        "results": [asdict(r) for r in results],
    }
    if dashboard_health is not None:
        report["dashboard_health"] = dashboard_health

    report_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.parent.mkdir(parents=True, exist_ok=True)

    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with events_path.open("w", encoding="utf-8") as handle:
        for result in results:
            event = {
                "schema_version": "wasm-flake-governance-event-v1",
                "generated_at_utc": generated_at,
                "check_id": result.check_id,
                "status": result.status,
                "detail": result.detail,
            }
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        default=".github/wasm_flake_governance_policy.json",
        help="WASM flake governance policy JSON path",
    )
    parser.add_argument(
        "--dashboard",
        default=None,
        help="Override dashboard path",
    )
    parser.add_argument(
        "--quarantine-manifest",
        default=None,
        help="Override quarantine manifest path",
    )
    parser.add_argument(
        "--forensics-doc",
        default=None,
        help="Override forensics doc path",
    )
    parser.add_argument(
        "--report-path",
        default=None,
        help="Override output report path",
    )
    parser.add_argument(
        "--events-path",
        default=None,
        help="Override output events path",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run internal self-tests and exit",
    )
    return parser.parse_args()


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        policy_path = root / "policy.json"
        doc_path = root / "playbook.md"
        dashboard_path = root / "dashboard.json"
        quarantine_path = root / "quarantine.json"

        doc_path.write_text(
            "\n".join(
                [
                    "# playbook",
                    "bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics",
                    "TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh",
                    "python3 ./scripts/check_incident_forensics_playbook.py",
                    "python3 ./scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json",
                    "replay",
                    "trace_pointer",
                    "reactivation",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        dashboard = {
            "schema_version": "sem-variance-dashboard-v1",
            "suite_count": 2,
            "unstable_suite_count": 0,
            "suites": [
                {
                    "suite": "witness_seed_equivalence",
                    "unstable": False,
                    "outcomes": {"pass": 5, "fail": 0},
                },
                {
                    "suite": "cross_seed_replay",
                    "unstable": False,
                    "outcomes": {"pass": 5, "fail": 0},
                },
            ],
        }
        dashboard_path.write_text(
            json.dumps(dashboard, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        quarantine = {
            "schema_version": "wasm-flake-quarantine-v1",
            "entries": [],
        }
        quarantine_path.write_text(
            json.dumps(quarantine, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        policy = {
            "schema_version": "wasm-flake-governance-policy-v1",
            "detection": {
                "dashboard_schema_version": "sem-variance-dashboard-v1",
                "required_suites": ["witness_seed_equivalence", "cross_seed_replay"],
            },
            "quarantine": {
                "manifest_schema_version": "wasm-flake-quarantine-v1",
                "statuses": ["open", "resolved", "reactivated"],
                "required_fields": [
                    "id",
                    "suite",
                    "severity",
                    "status",
                    "owner",
                    "opened_at_utc",
                    "sla_hours",
                    "replay_command",
                    "trace_pointer",
                    "reactivation_criteria",
                ],
            },
            "quality_thresholds": {
                "max_flake_rate_pct": 0.0,
                "max_false_positive_rate_pct": 5.0,
                "max_unresolved_high_severity_flakes": 0,
                "max_unresolved_critical_severity_flakes": 0,
                "max_critical_test_failures": 0,
            },
            "sla_targets_hours": {"critical": 24, "high": 72, "medium": 168},
            "forensics_playbook": {
                "required_commands": [
                    "bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics",
                    "TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh",
                    "python3 ./scripts/check_incident_forensics_playbook.py",
                    "python3 ./scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json",
                ]
            },
            "output": {
                "report_path": "artifacts/wasm_flake_governance_report.json",
                "events_path": "artifacts/wasm_flake_governance_events.ndjson",
            },
        }
        policy_path.write_text(json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8")

        # Test 1: policy shape pass
        result = validate_policy_shape(policy)
        assert result.status == "pass"

        # Test 2: forensics playbook pass
        result = check_forensics_playbook(doc_path, policy["forensics_playbook"]["required_commands"])
        assert result.status == "pass"

        # Test 3: dashboard pass
        result = check_dashboard(
            dashboard_path,
            policy["detection"]["dashboard_schema_version"],
            policy["detection"]["required_suites"],
            policy["quality_thresholds"],
        )
        assert result.status == "pass"

        # Test 4: quarantine pass
        result = check_quarantine_manifest(
            quarantine_path,
            policy["quarantine"]["manifest_schema_version"],
            set(policy["quarantine"]["statuses"]),
            policy["quarantine"]["required_fields"],
            policy["quality_thresholds"],
            policy["sla_targets_hours"],
        )
        assert result.status == "pass"

        # Test 5: dashboard flake-rate fail
        dashboard_bad = dict(dashboard)
        dashboard_bad["unstable_suite_count"] = 1
        dashboard_path.write_text(json.dumps(dashboard_bad, sort_keys=True) + "\n", encoding="utf-8")
        result = check_dashboard(
            dashboard_path,
            policy["detection"]["dashboard_schema_version"],
            policy["detection"]["required_suites"],
            policy["quality_thresholds"],
        )
        assert result.status == "fail"

        # Restore dashboard
        dashboard_path.write_text(json.dumps(dashboard, sort_keys=True) + "\n", encoding="utf-8")

        # Test 6: forensics playbook missing command fail
        doc_path.write_text("replay trace_pointer reactivation\n", encoding="utf-8")
        result = check_forensics_playbook(doc_path, policy["forensics_playbook"]["required_commands"])
        assert result.status == "fail"

        # Restore playbook
        doc_path.write_text(
            "\n".join(
                [
                    "bash ./scripts/run_all_e2e.sh --suite wasm-incident-forensics",
                    "TEST_SEED=4242 bash ./scripts/test_wasm_incident_forensics_e2e.sh",
                    "python3 ./scripts/check_incident_forensics_playbook.py",
                    "python3 ./scripts/check_wasm_flake_governance.py --policy .github/wasm_flake_governance_policy.json",
                    "replay trace_pointer reactivation",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # Test 7: quarantine unresolved high fail
        old_opened = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).isoformat()
        quarantine_high = {
            "schema_version": "wasm-flake-quarantine-v1",
            "entries": [
                {
                    "id": "Q1",
                    "suite": "cross_seed_replay",
                    "severity": "high",
                    "status": "open",
                    "owner": "runtime-core",
                    "opened_at_utc": old_opened,
                    "sla_hours": 72,
                    "replay_command": "cargo test --test replay_e2e_suite cross_seed_replay_suite -- --nocapture",
                    "trace_pointer": "target/e2e-results/example/replay.json",
                    "reactivation_criteria": "three consecutive stable runs",
                }
            ],
        }
        quarantine_path.write_text(
            json.dumps(quarantine_high, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result = check_quarantine_manifest(
            quarantine_path,
            policy["quarantine"]["manifest_schema_version"],
            set(policy["quarantine"]["statuses"]),
            policy["quarantine"]["required_fields"],
            policy["quality_thresholds"],
            policy["sla_targets_hours"],
        )
        assert result.status == "fail"

        # Test 8: quarantine resolved pass
        quarantine_resolved = quarantine_high
        quarantine_resolved["entries"][0]["status"] = "resolved"
        quarantine_path.write_text(
            json.dumps(quarantine_resolved, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        result = check_quarantine_manifest(
            quarantine_path,
            policy["quarantine"]["manifest_schema_version"],
            set(policy["quarantine"]["statuses"]),
            policy["quarantine"]["required_fields"],
            policy["quality_thresholds"],
            policy["sla_targets_hours"],
        )
        assert result.status == "pass"

        # Test 9: policy schema mismatch fail
        bad_policy = dict(policy)
        bad_policy["schema_version"] = "wrong"
        result = validate_policy_shape(bad_policy)
        assert result.status == "fail"

    print("all 9 self-tests passed")


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0

    policy_path = pathlib.Path(args.policy).resolve()

    try:
        policy = load_json(policy_path)
    except GovernanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    project_root = pathlib.Path.cwd()
    base_dir = policy_path.parent.parent if policy_path.parent.name == ".github" else project_root

    policy_check = validate_policy_shape(policy)
    results: list[CheckResult] = [policy_check]
    if policy_check.status == "fail":
        gate_status = "fail"
        report_path = resolve_path(
            base_dir,
            args.report_path
            or policy.get("output", {}).get("report_path", "artifacts/wasm_flake_governance_report.json"),
        )
        events_path = resolve_path(
            base_dir,
            args.events_path
            or policy.get("output", {}).get("events_path", "artifacts/wasm_flake_governance_events.ndjson"),
        )
        write_report(report_path, events_path, policy_path, results, gate_status, None)
        print("WASM flake governance gate: FAIL")
        print(f"  Report: {report_path}")
        print(f"  Events: {events_path}")
        print(f"  FAIL: {policy_check.detail}")
        return 1

    detection = policy["detection"]
    quarantine = policy["quarantine"]
    thresholds = policy["quality_thresholds"]
    sla_targets = policy["sla_targets_hours"]
    forensics = policy["forensics_playbook"]

    dashboard_path = resolve_path(
        base_dir,
        args.dashboard or detection.get("dashboard_path", "target/semantic-verification/flake/latest/variance_dashboard.json"),
    )
    quarantine_path = resolve_path(
        base_dir,
        args.quarantine_manifest or quarantine.get("manifest_path", "artifacts/wasm_flake_quarantine_manifest.json"),
    )
    forensics_doc_path = resolve_path(
        base_dir,
        args.forensics_doc or forensics.get("doc_path", "docs/wasm_flake_governance_and_forensics.md"),
    )

    results.append(
        check_dashboard(
            dashboard_path,
            detection.get("dashboard_schema_version", "sem-variance-dashboard-v1"),
            detection.get("required_suites", []),
            thresholds,
        )
    )
    dashboard_health = compute_dashboard_health(dashboard_path)
    results.append(
        check_quarantine_manifest(
            quarantine_path,
            quarantine.get("manifest_schema_version", "wasm-flake-quarantine-v1"),
            set(quarantine.get("statuses", [])),
            quarantine.get("required_fields", []),
            thresholds,
            sla_targets,
        )
    )
    results.append(
        check_forensics_playbook(
            forensics_doc_path,
            forensics.get("required_commands", []),
        )
    )

    fail_count = sum(1 for r in results if r.status == "fail")
    pass_count = sum(1 for r in results if r.status == "pass")
    gate_status = "pass" if fail_count == 0 else "fail"

    report_path = resolve_path(
        base_dir,
        args.report_path
        or policy.get("output", {}).get("report_path", "artifacts/wasm_flake_governance_report.json"),
    )
    events_path = resolve_path(
        base_dir,
        args.events_path
        or policy.get("output", {}).get("events_path", "artifacts/wasm_flake_governance_events.ndjson"),
    )
    write_report(
        report_path,
        events_path,
        policy_path,
        results,
        gate_status,
        dashboard_health,
    )

    print(f"WASM flake governance gate: {gate_status.upper()}")
    print(f"  Checks: {pass_count} pass, {fail_count} fail")
    print(f"  Report: {report_path}")
    print(f"  Events: {events_path}")
    for result in results:
        if result.status == "fail":
            print(f"  FAIL: [{result.check_id}] {result.detail}")

    return 0 if gate_status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
