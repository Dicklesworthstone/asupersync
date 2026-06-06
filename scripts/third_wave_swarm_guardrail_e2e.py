#!/usr/bin/env python3
"""Run deterministic third-wave swarm guardrail e2e checks.

The helper consumes an aggregate fixture, invokes the checked child guardrail
helpers against their checked fixtures, and emits one stable JSON or Markdown
report. It does not inspect live tracker state, contact coordination services,
run proof commands, or mutate repository state.
"""

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "third-wave-swarm-guardrail-e2e-report-v1"
FIXTURE_SCHEMA_VERSION = "third-wave-swarm-guardrail-e2e-fixture-v1"
CONTRACT_SCHEMA_VERSION = "third-wave-swarm-guardrail-e2e-contract-v1"

GLOBAL_FORBIDDEN_ACTIONS = [
    "do-not-create-branches",
    "do-not-create-worktrees",
    "do-not-edit-peer-dirty-files",
    "do-not-contact-live-coordination-services",
    "do-not-run-proof-commands",
    "do-not-rewrite-tracker-state",
    "do-not-treat-child-helper-failure-as-green",
    "do-not-ignore-missing-child-classifications",
]

GLOBAL_NON_CLAIMS = [
    "This e2e report verifies guardrail fixture behavior; it is not a broad workspace health proof.",
    "Child helper fixtures do not override live br, bv, Git, Agent Mail, reservation, or RCH state.",
    "A passing report does not close a bead, push refs, mirror refs, or release reservations.",
    "This e2e report is not a release publish proof and not a substitute for broad check/clippy/test gates.",
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def bool_value(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def load_bundle(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    value = load_json(path)
    if not isinstance(value, dict):
        raise SystemExit(f"{path}: fixture must be a JSON object")
    if value.get("schema_version") == CONTRACT_SCHEMA_VERSION:
        fixture = value.get("fixture")
        if not isinstance(fixture, dict):
            raise SystemExit(f"{path}: contract artifact must contain fixture object")
        contract = value
    else:
        fixture = value
        contract = {"expected_summary": fixture.get("expected_summary", {})}
    if fixture.get("schema_version") != FIXTURE_SCHEMA_VERSION:
        raise SystemExit(
            f"{path}: fixture schema_version must be {FIXTURE_SCHEMA_VERSION}"
        )
    return contract, fixture


def sorted_strings(values: list[str]) -> list[str]:
    return sorted(set(value for value in values if value))


def repo_path(repo_root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute():
        return path
    return repo_root / path


def row_key(component: dict[str, Any]) -> str:
    key = string(component.get("row_key"))
    return key if key else "scenario_id"


def marker_key(marker: dict[str, Any], default_key: str) -> str:
    key = string(marker.get("row_key"))
    return key if key else default_key


def rows_by_key(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {string(row.get(key)): row for row in rows if string(row.get(key))}


def child_command(repo_root: Path, component: dict[str, Any]) -> list[str]:
    command = [
        "python3",
        str(repo_path(repo_root, string(component.get("helper")))),
        "--fixture",
        str(repo_path(repo_root, string(component.get("fixture")))),
        "--generated-at",
        string(component.get("generated_at")),
    ]
    command.extend(string_list(component.get("extra_args")))
    command.extend(["--output", "json"])
    return command


def run_child(repo_root: Path, component: dict[str, Any]) -> tuple[Any | None, str, str, int]:
    command = child_command(repo_root, component)
    completed = subprocess.run(
        command,
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return None, completed.stdout, completed.stderr, completed.returncode
    try:
        return json.loads(completed.stdout), completed.stdout, completed.stderr, 0
    except json.JSONDecodeError as err:
        return None, completed.stdout, f"invalid child JSON: {err}", 1


def validate_summary(
    component: dict[str, Any], child_report: dict[str, Any]
) -> list[dict[str, Any]]:
    summary = child_report.get("summary")
    if not isinstance(summary, dict):
        return [
            {
                "field": "summary",
                "expected": "object",
                "actual": type(summary).__name__,
                "matched": False,
            }
        ]
    results: list[dict[str, Any]] = []
    expected = component.get("expected_summary")
    if not isinstance(expected, dict):
        expected = {}
    for key in sorted(expected):
        actual = summary.get(key)
        expected_value = expected[key]
        results.append(
            {
                "field": key,
                "expected": expected_value,
                "actual": actual,
                "matched": actual == expected_value,
            }
        )
    return results


def validate_classifications(
    component: dict[str, Any], child_report: dict[str, Any]
) -> list[dict[str, Any]]:
    summary = child_report.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    counts = summary.get("classification_counts")
    if not isinstance(counts, dict):
        counts = {}
    catalog = child_report.get("classification_catalog")
    if not isinstance(catalog, dict):
        catalog = {}
    results: list[dict[str, Any]] = []
    for classification in string_list(component.get("required_classifications")):
        observed_count = counts.get(classification, 0)
        results.append(
            {
                "classification": classification,
                "expected_count": 1,
                "observed_count": observed_count,
                "catalog_present": classification in catalog,
                "matched": observed_count == 1 and classification in catalog,
            }
        )
    return results


def validate_markers(
    component: dict[str, Any], child_report: dict[str, Any]
) -> list[dict[str, Any]]:
    rows = dict_list(child_report.get("rows"))
    default_key = row_key(component)
    results: list[dict[str, Any]] = []
    for marker in dict_list(component.get("required_markers")):
        key = marker_key(marker, default_key)
        row_id = string(marker.get("row_id"))
        row = rows_by_key(rows, key).get(row_id)
        errors: list[str] = []
        if row is None:
            errors.append("missing-row")
        else:
            expected_classification = string(marker.get("classification"))
            if string(row.get("classification")) != expected_classification:
                errors.append("classification-mismatch")
            expected_bools = marker.get("bool_fields")
            if not isinstance(expected_bools, dict):
                expected_bools = {}
            for field, expected_value in expected_bools.items():
                actual = bool_value(row.get(field))
                if actual != bool_value(expected_value):
                    errors.append(f"{field}-mismatch")
        results.append(
            {
                "row_key": key,
                "row_id": row_id,
                "classification": string(marker.get("classification")),
                "matched": not errors,
                "errors": errors,
            }
        )
    return results


def classify_component(repo_root: Path, component: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    helper = repo_path(repo_root, string(component.get("helper")))
    fixture = repo_path(repo_root, string(component.get("fixture")))
    if not helper.exists():
        errors.append("missing-helper")
    if not fixture.exists():
        errors.append("missing-fixture")

    child_report: dict[str, Any] = {}
    stdout = ""
    stderr = ""
    returncode = 1
    if not errors:
        loaded, stdout, stderr, returncode = run_child(repo_root, component)
        if returncode != 0:
            errors.append("child-helper-failed")
        elif not isinstance(loaded, dict):
            errors.append("child-report-not-object")
        else:
            child_report = loaded

    expected_schema = string(component.get("report_schema_version"))
    child_schema = string(child_report.get("schema_version"))
    if child_report and child_schema != expected_schema:
        errors.append("schema-version-mismatch")

    summary_results = validate_summary(component, child_report)
    classification_results = validate_classifications(component, child_report)
    marker_results = validate_markers(component, child_report)
    if any(not result["matched"] for result in summary_results):
        errors.append("summary-mismatch")
    if any(not result["matched"] for result in classification_results):
        errors.append("classification-mismatch")
    if any(not result["matched"] for result in marker_results):
        errors.append("marker-mismatch")

    rows = dict_list(child_report.get("rows"))
    status = "passed" if not errors else "failed"
    return {
        "id": string(component.get("id")),
        "title": string(component.get("title")),
        "bead_id": string(component.get("bead_id")),
        "status": status,
        "errors": sorted_strings(errors),
        "helper": string(component.get("helper")),
        "fixture": string(component.get("fixture")),
        "generated_at": string(component.get("generated_at")),
        "command": child_command(repo_root, component),
        "returncode": returncode,
        "stderr": stderr,
        "stdout_bytes": len(stdout.encode()),
        "child_schema_version": child_schema,
        "expected_schema_version": expected_schema,
        "child_row_count": len(rows),
        "required_classification_count": len(
            string_list(component.get("required_classifications"))
        ),
        "required_marker_count": len(dict_list(component.get("required_markers"))),
        "summary": child_report.get("summary", {}),
        "summary_results": summary_results,
        "classification_results": classification_results,
        "marker_results": marker_results,
    }


def combine_classification_counts(components: list[dict[str, Any]]) -> dict[str, int]:
    combined: dict[str, int] = {}
    for component in components:
        summary = component.get("summary")
        if not isinstance(summary, dict):
            continue
        counts = summary.get("classification_counts")
        if not isinstance(counts, dict):
            continue
        for classification, count in counts.items():
            if isinstance(classification, str) and isinstance(count, int):
                combined[classification] = combined.get(classification, 0) + count
    return dict(sorted(combined.items()))


def build_report(
    contract: dict[str, Any],
    fixture: dict[str, Any],
    generated_at: str,
    repo_root: Path,
) -> dict[str, Any]:
    component_reports = [
        classify_component(repo_root, component)
        for component in dict_list(fixture.get("components"))
    ]
    failed = [component for component in component_reports if component["status"] != "passed"]
    summary = {
        "component_count": len(component_reports),
        "passed_components": len(component_reports) - len(failed),
        "failed_components": len(failed),
        "child_scenario_count": sum(
            int(component["child_row_count"]) for component in component_reports
        ),
        "required_classification_count": sum(
            int(component["required_classification_count"])
            for component in component_reports
        ),
        "required_marker_count": sum(
            int(component["required_marker_count"]) for component in component_reports
        ),
        "dry_run_only": True,
        "non_mutating": True,
        "invokes_child_helpers": True,
        "uses_live_external_services": False,
        "runs_proof_commands": False,
        "mutation_command_count": 0,
        "proof_command_count": 0,
        "guardrail_verdict": "pass" if not failed else "fail",
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "fixture_id": string(fixture.get("fixture_id")),
        "bundle_id": string(fixture.get("bundle_id")),
        "parent_bead_id": string(fixture.get("parent_bead_id")),
        "generated_at": generated_at,
        "summary": summary,
        "expected_summary": contract.get("expected_summary", {}),
        "combined_classification_counts": combine_classification_counts(
            component_reports
        ),
        "components": component_reports,
        "global_forbidden_actions": string_list(
            fixture.get("global_forbidden_actions")
        )
        or GLOBAL_FORBIDDEN_ACTIONS,
        "non_claims": string_list(fixture.get("non_claims")) or GLOBAL_NON_CLAIMS,
    }


def format_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Third-Wave Swarm Guardrail E2E",
        "",
        f"bundle_id: `{report['bundle_id']}`",
        f"parent_bead_id: `{report['parent_bead_id']}`",
        f"generated_at: `{report['generated_at']}`",
        f"guardrail_verdict: `{summary['guardrail_verdict']}`",
        f"component_count: `{summary['component_count']}`",
        f"passed_components: `{summary['passed_components']}`",
        f"failed_components: `{summary['failed_components']}`",
        "",
        "## Components",
        "",
    ]
    for component in report["components"]:
        lines.extend(
            [
                f"- `{component['id']}` {component['status']}: {component['title']}",
                f"  - helper: `{component['helper']}`",
                f"  - fixture: `{component['fixture']}`",
                f"  - child_rows: `{component['child_row_count']}`",
                f"  - required_classifications: `{component['required_classification_count']}`",
                f"  - required_markers: `{component['required_marker_count']}`",
            ]
        )
        if component["errors"]:
            lines.append(f"  - errors: `{', '.join(component['errors'])}`")
    lines.extend(["", "## Guardrails", ""])
    for action in report["global_forbidden_actions"]:
        lines.append(f"- `{action}`")
    lines.extend(["", "## Non-Claims", ""])
    for non_claim in report["non_claims"]:
        lines.append(f"- {non_claim}")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run deterministic third-wave swarm guardrail e2e checks."
    )
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--generated-at", default=utc_now())
    parser.add_argument(
        "--output",
        choices=["json", "markdown"],
        default="json",
        help="Report format to write to stdout.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path("."),
        help="Repository root used to resolve child helper and fixture paths.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    contract, fixture = load_bundle(args.fixture)
    report = build_report(contract, fixture, args.generated_at, repo_root)
    if args.output == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_markdown(report), end="")
    return 0 if report["summary"]["failed_components"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
