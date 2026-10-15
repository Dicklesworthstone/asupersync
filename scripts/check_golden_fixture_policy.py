#!/usr/bin/env python3
"""Golden fixture policy checker (SEM-12.8).

Validates that golden fixture modifications follow the update policy:
1. Every fixture file referenced in manifest.json exists.
2. Every fixture has a matching change_log entry for the latest update.
3. Drift justification is present when fixtures are modified.
4. Schema versions are consistent across all fixtures.

Usage:
    python scripts/check_golden_fixture_policy.py [--strict]

Exit codes:
    0 - all checks pass
    1 - policy violations found
    2 - configuration/IO error
"""

import json
import sys
from pathlib import Path

FIXTURE_DIR = Path("tests/fixtures/semantic_golden")
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"


def load_manifest():
    """Load and validate the manifest file."""
    if not MANIFEST_PATH.exists():
        print(f"ERROR: manifest not found: {MANIFEST_PATH}")
        sys.exit(2)
    with open(MANIFEST_PATH) as f:
        return json.load(f)


def check_schema_version(manifest):
    """Verify manifest schema version."""
    version = manifest.get("schema_version")
    if version != "semantic-golden-manifest-v1":
        return [f"Manifest schema_version is '{version}', expected 'semantic-golden-manifest-v1'"]
    return []


def check_fixture_files_exist(manifest):
    """Verify all fixture files referenced in manifest exist."""
    errors = []
    for fixture in manifest.get("fixtures", []):
        fid = fixture.get("id", "<no-id>")
        filename = fixture.get("file")
        if not filename:
            errors.append(f"Fixture '{fid}' has no 'file' field")
            continue
        path = FIXTURE_DIR / filename
        if not path.exists():
            errors.append(f"Fixture '{fid}' references missing file: {path}")
    return errors


def check_fixture_schema_consistency(manifest):
    """Verify all fixture files have consistent schema versions."""
    errors = []
    for fixture in manifest.get("fixtures", []):
        fid = fixture.get("id", "<no-id>")
        filename = fixture.get("file")
        if not filename:
            continue
        path = FIXTURE_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        sv = data.get("schema_version")
        if sv != "semantic-golden-fixture-v1":
            errors.append(f"Fixture '{fid}' ({filename}) has schema_version '{sv}', "
                         f"expected 'semantic-golden-fixture-v1'")
        data_id = data.get("fixture_id")
        if data_id != fid:
            errors.append(f"Fixture '{fid}' ({filename}) has fixture_id '{data_id}', "
                         f"expected '{fid}'")
        manifest_rules = sorted(fixture.get("rule_ids", []))
        data_rules = sorted(data.get("rule_ids", []))
        if manifest_rules != data_rules:
            errors.append(f"Fixture '{fid}' rule_ids mismatch: "
                         f"manifest={manifest_rules}, file={data_rules}")
    return errors


def check_update_policy(manifest):
    """Verify update policy is properly configured."""
    errors = []
    policy = manifest.get("update_policy", {})
    if not policy.get("review_required"):
        errors.append("update_policy.review_required must be true")
    if not policy.get("drift_justification_required"):
        errors.append("update_policy.drift_justification_required must be true")
    reviewers = policy.get("reviewers", [])
    if not reviewers:
        errors.append("update_policy.reviewers must not be empty")
    checklist = policy.get("checklist", [])
    if len(checklist) < 3:
        errors.append(f"update_policy.checklist has {len(checklist)} items, need >= 3")
    return errors


def check_change_log(manifest):
    """Verify change_log entries have required fields."""
    errors = []
    change_log = manifest.get("change_log", [])
    if not change_log:
        errors.append("change_log must not be empty")
        return errors
    for i, entry in enumerate(change_log):
        prefix = f"change_log[{i}]"
        for field in ["date", "author", "action", "justification", "fixtures_affected"]:
            if field not in entry:
                errors.append(f"{prefix} missing required field: {field}")
        affected = entry.get("fixtures_affected", [])
        if not affected:
            errors.append(f"{prefix} fixtures_affected must not be empty")
    return errors


def check_strict_drift(manifest):
    """In strict mode, verify every fixture's last_updated matches a change_log entry."""
    errors = []
    log_dates = {entry.get("date") for entry in manifest.get("change_log", [])}
    for fixture in manifest.get("fixtures", []):
        fid = fixture.get("id", "<no-id>")
        last_updated = fixture.get("last_updated")
        if last_updated and last_updated not in log_dates:
            errors.append(f"Fixture '{fid}' last_updated '{last_updated}' "
                         f"has no matching change_log entry")
    return errors


def main():
    strict = "--strict" in sys.argv
    manifest = load_manifest()

    all_errors = []
    all_errors.extend(check_schema_version(manifest))
    all_errors.extend(check_fixture_files_exist(manifest))
    all_errors.extend(check_fixture_schema_consistency(manifest))
    all_errors.extend(check_update_policy(manifest))
    all_errors.extend(check_change_log(manifest))
    if strict:
        all_errors.extend(check_strict_drift(manifest))

    if all_errors:
        print(f"FAIL: {len(all_errors)} golden fixture policy violation(s):")
        for err in all_errors:
            print(f"  - {err}")
        sys.exit(1)
    else:
        fixture_count = len(manifest.get("fixtures", []))
        print(f"OK: {fixture_count} golden fixtures pass all policy checks"
              f"{' (strict)' if strict else ''}")
        sys.exit(0)


if __name__ == "__main__":
    main()
