#!/usr/bin/env python3
"""Validate mock-code-finder proof evidence JSONL files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_CONTRACT = Path("artifacts/mock_code_finder_verification_contract_v1.json")
SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|apikey|authorization|database_url|postgres_url)\b"
    r"\s*[:=]\s*(?!<redacted>|redacted|none|null|$)[^,\s]+"
)
SECRET_URI = re.compile(r"(?i)\b(postgres|mysql|redis)://[^:@\s]+:[^@\s]+@")


class ValidationError(Exception):
    """Raised when contract or evidence validation fails."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"{path}: invalid JSON: {exc}") from exc


def required_fields(contract: dict[str, Any]) -> list[str]:
    layout = contract.get("record_layout")
    if not isinstance(layout, dict):
        raise ValidationError("contract missing object record_layout")
    fields = layout.get("required_fields")
    if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
        raise ValidationError("contract record_layout.required_fields must be a string list")
    if len(fields) != len(set(fields)):
        raise ValidationError("contract record_layout.required_fields contains duplicates")
    return fields


def allowed_values(contract: dict[str, Any], key: str) -> set[str]:
    allowed = contract.get("allowed_values")
    if not isinstance(allowed, dict):
        raise ValidationError("contract missing object allowed_values")
    values = allowed.get(key)
    if not isinstance(values, list) or not values or not all(isinstance(value, str) for value in values):
        raise ValidationError(f"contract allowed_values.{key} must be a nonempty string list")
    if len(values) != len(set(values)):
        raise ValidationError(f"contract allowed_values.{key} contains duplicates")
    return set(values)


def assert_string(record: dict[str, Any], field: str, label: str) -> str:
    value = record.get(field)
    if not isinstance(value, str):
        raise ValidationError(f"{label}: field {field} must be a string")
    return value


def assert_string_list(record: dict[str, Any], field: str, label: str) -> list[str]:
    value = record.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"{label}: field {field} must be a list of strings")
    return value


def scan_for_unredacted_secret(value: Any, label: str, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "env_keys_required":
                continue
            scan_for_unredacted_secret(child, label, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_for_unredacted_secret(child, label, f"{path}[{index}]")
    elif isinstance(value, str):
        if SECRET_ASSIGNMENT.search(value) or SECRET_URI.search(value):
            raise ValidationError(f"{label}: unredacted secret-looking value at {path}")


def validate_contract(contract: dict[str, Any]) -> None:
    if contract.get("contract_version") != "mock-code-finder-verification-contract-v1":
        raise ValidationError("contract_version must be mock-code-finder-verification-contract-v1")
    if contract.get("schema_version") != "mock-code-finder-evidence-jsonl-schema-v1":
        raise ValidationError("schema_version must be mock-code-finder-evidence-jsonl-schema-v1")
    if contract.get("bead_id") != "asupersync-qlvtin":
        raise ValidationError("bead_id must be asupersync-qlvtin")
    if contract.get("artifact_root") != "artifacts/mock-code-finder":
        raise ValidationError("artifact_root must be artifacts/mock-code-finder")

    fields = required_fields(contract)
    for field in [
        "schema_version",
        "bead_id",
        "scenario_id",
        "subsystem",
        "support_class",
        "source_files_inspected",
        "command",
        "rch_command_if_used",
        "cargo_features",
        "test_filter",
        "env_keys_required",
        "deterministic_seed_or_fixture_id",
        "input_artifact",
        "output_artifact",
        "expected_behavior",
        "actual_behavior",
        "verdict",
        "first_failure_line",
        "duration_ms",
        "git_sha_or_tree_state",
        "blocker_bead_id",
        "evidence_quality",
    ]:
        if field not in fields:
            raise ValidationError(f"contract required_fields missing {field}")

    for key in ["support_class", "verdict", "evidence_quality"]:
        allowed_values(contract, key)

    expected_quality = contract.get("verdict_evidence_quality")
    if not isinstance(expected_quality, dict):
        raise ValidationError("contract missing object verdict_evidence_quality")
    for verdict in allowed_values(contract, "verdict"):
        values = expected_quality.get(verdict)
        if not isinstance(values, list) or not values:
            raise ValidationError(f"contract verdict_evidence_quality missing {verdict}")
        unknown = set(values) - allowed_values(contract, "evidence_quality")
        if unknown:
            raise ValidationError(f"contract verdict_evidence_quality.{verdict} has unknown values: {sorted(unknown)}")

    samples = contract.get("sample_records")
    if not isinstance(samples, list) or not samples:
        raise ValidationError("contract sample_records must be a nonempty list")
    sample_verdicts = set()
    for index, sample in enumerate(samples, 1):
        validate_record(sample, contract, f"sample_records[{index}]")
        sample_verdicts.add(sample["verdict"])
    missing_verdicts = allowed_values(contract, "verdict") - sample_verdicts
    if missing_verdicts:
        raise ValidationError(f"contract sample_records missing verdicts: {sorted(missing_verdicts)}")


def validate_record(record: Any, contract: dict[str, Any], label: str) -> dict[str, str]:
    if not isinstance(record, dict):
        raise ValidationError(f"{label}: record must be a JSON object")

    fields = required_fields(contract)
    missing = [field for field in fields if field not in record]
    if missing:
        raise ValidationError(f"{label}: missing required fields: {', '.join(missing)}")

    schema_version = assert_string(record, "schema_version", label)
    if schema_version != contract["schema_version"]:
        raise ValidationError(f"{label}: schema_version must be {contract['schema_version']}")

    bead_id = assert_string(record, "bead_id", label)
    if not bead_id.startswith("asupersync-"):
        raise ValidationError(f"{label}: bead_id must be an asupersync bead id")

    scenario_id = assert_string(record, "scenario_id", label)
    if not scenario_id:
        raise ValidationError(f"{label}: scenario_id must be nonempty")

    assert_string(record, "subsystem", label)
    source_files = assert_string_list(record, "source_files_inspected", label)
    if not source_files:
        raise ValidationError(f"{label}: source_files_inspected must not be empty")

    command = assert_string(record, "command", label)
    if not command.strip():
        raise ValidationError(f"{label}: command must be nonempty")

    rch_command = assert_string(record, "rch_command_if_used", label)
    if rch_command and not rch_command.startswith("rch exec -- "):
        raise ValidationError(f"{label}: rch_command_if_used must start with 'rch exec -- '")

    for field in [
        "test_filter",
        "deterministic_seed_or_fixture_id",
        "input_artifact",
        "output_artifact",
        "expected_behavior",
        "actual_behavior",
        "first_failure_line",
        "git_sha_or_tree_state",
        "blocker_bead_id",
    ]:
        assert_string(record, field, label)

    for field in ["cargo_features", "env_keys_required"]:
        assert_string_list(record, field, label)

    for env_key in record["env_keys_required"]:
        if "=" in env_key or ":" in env_key:
            raise ValidationError(f"{label}: env_keys_required must contain key names only")
        if not env_key or env_key.strip() != env_key:
            raise ValidationError(f"{label}: env_keys_required entries must be trimmed and nonempty")

    duration = record.get("duration_ms")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 0:
        raise ValidationError(f"{label}: duration_ms must be a nonnegative number")

    support_class = assert_string(record, "support_class", label)
    verdict = assert_string(record, "verdict", label)
    evidence_quality = assert_string(record, "evidence_quality", label)

    if support_class not in allowed_values(contract, "support_class"):
        raise ValidationError(f"{label}: unknown support_class {support_class}")
    if verdict not in allowed_values(contract, "verdict"):
        raise ValidationError(f"{label}: unknown verdict {verdict}")
    if evidence_quality not in allowed_values(contract, "evidence_quality"):
        raise ValidationError(f"{label}: unknown evidence_quality {evidence_quality}")

    expected_quality = contract["verdict_evidence_quality"][verdict]
    if evidence_quality not in expected_quality:
        raise ValidationError(
            f"{label}: verdict {verdict} cannot use evidence_quality {evidence_quality}; expected one of {expected_quality}"
        )
    if verdict == "blocked" and not record["blocker_bead_id"]:
        raise ValidationError(f"{label}: blocked verdict requires blocker_bead_id")
    if verdict in {"pass", "fail"} and support_class in {"audit_only", "fixture_reference"}:
        raise ValidationError(f"{label}: {verdict} verdict cannot rely on {support_class} support")
    if verdict == "pass" and not record["output_artifact"] and not record["test_filter"]:
        raise ValidationError(f"{label}: pass verdict needs output_artifact or test_filter")

    scan_for_unredacted_secret(record, label)
    return {
        "verdict": verdict,
        "evidence_quality": evidence_quality,
        "support_class": support_class,
    }


def validate_jsonl_text(text: str, contract: dict[str, Any], label: str) -> dict[str, Any]:
    verdicts: Counter[str] = Counter()
    qualities: Counter[str] = Counter()
    support_classes: Counter[str] = Counter()
    records = 0

    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"{label}:{line_number}: invalid JSON: {exc}") from exc
        summary = validate_record(record, contract, f"{label}:{line_number}")
        records += 1
        verdicts[summary["verdict"]] += 1
        qualities[summary["evidence_quality"]] += 1
        support_classes[summary["support_class"]] += 1

    if records == 0:
        raise ValidationError(f"{label}: zero scenario records")

    return {
        "records": records,
        "verdicts": dict(sorted(verdicts.items())),
        "evidence_quality": dict(sorted(qualities.items())),
        "support_class": dict(sorted(support_classes.items())),
    }


def validate_jsonl_file(path: Path, contract: dict[str, Any]) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValidationError(f"{path}: file does not exist") from exc
    return validate_jsonl_text(text, contract, str(path))


def expect_failure(name: str, func: Any) -> None:
    try:
        func()
    except ValidationError:
        return
    raise ValidationError(f"self-test negative case unexpectedly passed: {name}")


def run_self_test(contract: dict[str, Any]) -> None:
    validate_contract(contract)
    samples = contract["sample_records"]
    valid_jsonl = "\n".join(json.dumps(record, sort_keys=True) for record in samples) + "\n"
    validate_jsonl_text(valid_jsonl, contract, "<self-test-valid-jsonl>")

    expect_failure(
        "malformed-json",
        lambda: validate_jsonl_text('{"schema_version": "mock-code-finder-evidence-jsonl-schema-v1"\n', contract, "<bad-json>"),
    )

    missing_field = dict(samples[0])
    del missing_field["actual_behavior"]
    expect_failure(
        "missing-required-field",
        lambda: validate_jsonl_text(json.dumps(missing_field), contract, "<missing-field>"),
    )

    expect_failure(
        "zero-scenario-output",
        lambda: validate_jsonl_text("\n\n", contract, "<empty-jsonl>"),
    )

    secret_leak = dict(samples[0])
    secret_leak["actual_behavior"] = "database_url=postgres://user:plaintext@example.invalid/db"
    expect_failure(
        "unredacted-secret",
        lambda: validate_jsonl_text(json.dumps(secret_leak), contract, "<secret-leak>"),
    )

    dishonest = dict(samples[-1])
    dishonest["verdict"] = "pass"
    dishonest["evidence_quality"] = "live"
    dishonest["support_class"] = "audit_only"
    expect_failure(
        "audit-only-live-pass",
        lambda: validate_jsonl_text(json.dumps(dishonest), contract, "<dishonest-pass>"),
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--jsonl", type=Path, action="append", default=[])
    parser.add_argument("--summary-output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--validate-contract-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        contract = load_json(args.contract)
        validate_contract(contract)

        summaries: dict[str, Any] = {}
        if args.self_test:
            run_self_test(contract)
            summaries["self_test"] = {"verdict": "pass"}

        for path in args.jsonl:
            summaries[str(path)] = validate_jsonl_file(path, contract)

        if not args.self_test and not args.jsonl and not args.validate_contract_only:
            raise ValidationError("provide --self-test, --validate-contract-only, or at least one --jsonl")

        if args.summary_output:
            args.summary_output.write_text(json.dumps(summaries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        elif summaries:
            print(json.dumps(summaries, indent=2, sort_keys=True))
        return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
