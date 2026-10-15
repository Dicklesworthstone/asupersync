#!/usr/bin/env python3
"""Validate wasm ABI contract policy and emit deterministic gate artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any


class PolicyError(ValueError):
    """Raised when policy validation fails."""


@dataclass(frozen=True)
class ContractPaths:
    contract_id: str
    source: str
    documentation: str
    required_doc_markers: tuple[str, ...]


@dataclass(frozen=True)
class ExpectedContract:
    major_version: int
    minor_version: int
    signature_fingerprint: int
    symbols: tuple[str, ...]


@dataclass(frozen=True)
class ObservedContract:
    major_version: int
    minor_version: int
    signature_fingerprint: int
    symbols: tuple[str, ...]


MAJOR_RE = re.compile(r"pub const WASM_ABI_MAJOR_VERSION: u16 = ([0-9_]+);")
MINOR_RE = re.compile(r"pub const WASM_ABI_MINOR_VERSION: u16 = ([0-9_]+);")
FINGERPRINT_RE = re.compile(
    r"pub const WASM_ABI_SIGNATURE_FINGERPRINT_V1: u64 = ([0-9_]+);"
)
SIGNATURE_BLOCK_RE = re.compile(
    r"pub const WASM_ABI_SIGNATURES_V1:\s*\[WasmAbiSignature;\s*\d+\]\s*=\s*\[(.*?)\];",
    re.DOTALL,
)
SYMBOL_RE = re.compile(r"symbol:\s*WasmAbiSymbol::([A-Za-z0-9_]+)")
MIGRATION_ENTRY_RE = re.compile(
    r"Current ABI entry:\s*`v(?P<major>\d+)\.(?P<minor>\d+)\s+fingerprint=(?P<fingerprint>[0-9_]+)`"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_abi_policy.json",
        help="Path to policy JSON",
    )
    parser.add_argument(
        "--summary-output",
        default="",
        help="Override summary output path",
    )
    parser.add_argument(
        "--log-output",
        default="",
        help="Override event log output path",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run parser/validation self-tests and exit",
    )
    return parser.parse_args()


def _require_str(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{key} must be a non-empty string")
    return value


def _require_int(mapping: dict[str, Any], key: str) -> int:
    value = mapping.get(key)
    if not isinstance(value, int):
        raise PolicyError(f"{key} must be an integer")
    return value


def _require_str_list(mapping: dict[str, Any], key: str) -> tuple[str, ...]:
    value = mapping.get(key)
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise PolicyError(f"{key} must be list[str]")
    if not value:
        raise PolicyError(f"{key} must not be empty")
    return tuple(value)


def load_policy(path: pathlib.Path) -> tuple[ContractPaths, ExpectedContract, str, str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in policy file {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise PolicyError("policy root must be an object")
    if raw.get("schema_version") != "wasm-abi-policy-v1":
        raise PolicyError("unsupported or missing schema_version")

    contract_raw = raw.get("contract")
    if not isinstance(contract_raw, dict):
        raise PolicyError("contract must be an object")
    contract = ContractPaths(
        contract_id=_require_str(contract_raw, "contract_id"),
        source=_require_str(contract_raw, "source"),
        documentation=_require_str(contract_raw, "documentation"),
        required_doc_markers=_require_str_list(contract_raw, "required_doc_markers"),
    )

    expected_raw = raw.get("expected")
    if not isinstance(expected_raw, dict):
        raise PolicyError("expected must be an object")
    expected = ExpectedContract(
        major_version=_require_int(expected_raw, "major_version"),
        minor_version=_require_int(expected_raw, "minor_version"),
        signature_fingerprint=_require_int(expected_raw, "signature_fingerprint"),
        symbols=_require_str_list(expected_raw, "symbols"),
    )
    if len(set(expected.symbols)) != len(expected.symbols):
        raise PolicyError("expected.symbols contains duplicates")

    output_raw = raw.get("output")
    if not isinstance(output_raw, dict):
        raise PolicyError("output must be an object")
    summary_path = _require_str(output_raw, "summary_path")
    log_path = _require_str(output_raw, "log_path")

    return contract, expected, summary_path, log_path


def _parse_int_from_regex(pattern: re.Pattern[str], source: str, label: str) -> int:
    match = pattern.search(source)
    if not match:
        raise PolicyError(f"failed to parse {label} from wasm ABI source")
    return int(match.group(1).replace("_", ""))


def _camel_to_snake(value: str) -> str:
    chars: list[str] = []
    for idx, ch in enumerate(value):
        if ch.isupper() and idx > 0:
            chars.append("_")
        chars.append(ch.lower())
    return "".join(chars)


def parse_contract_from_source(source: str) -> ObservedContract:
    major = _parse_int_from_regex(MAJOR_RE, source, "major version")
    minor = _parse_int_from_regex(MINOR_RE, source, "minor version")
    fingerprint = _parse_int_from_regex(FINGERPRINT_RE, source, "signature fingerprint")

    block_match = SIGNATURE_BLOCK_RE.search(source)
    if not block_match:
        raise PolicyError("failed to parse WASM_ABI_SIGNATURES_V1 from source")
    block = block_match.group(1)
    symbols = tuple(_camel_to_snake(match) for match in SYMBOL_RE.findall(block))
    if not symbols:
        raise PolicyError("WASM_ABI_SIGNATURES_V1 has no parsed symbols")

    return ObservedContract(
        major_version=major,
        minor_version=minor,
        signature_fingerprint=fingerprint,
        symbols=symbols,
    )


def compare_contract(expected: ExpectedContract, observed: ObservedContract) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if expected.major_version != observed.major_version:
        findings.append(
            {
                "field": "major_version",
                "expected": expected.major_version,
                "actual": observed.major_version,
                "message": "major ABI version drift detected",
            }
        )
    if expected.minor_version != observed.minor_version:
        findings.append(
            {
                "field": "minor_version",
                "expected": expected.minor_version,
                "actual": observed.minor_version,
                "message": "minor ABI version drift detected",
            }
        )
    if expected.signature_fingerprint != observed.signature_fingerprint:
        findings.append(
            {
                "field": "signature_fingerprint",
                "expected": expected.signature_fingerprint,
                "actual": observed.signature_fingerprint,
                "message": "signature fingerprint drift detected",
            }
        )

    if expected.symbols != observed.symbols:
        findings.append(
            {
                "field": "symbols",
                "expected": list(expected.symbols),
                "actual": list(observed.symbols),
                "message": "symbol ordering/content drift detected",
            }
        )

    if len(set(observed.symbols)) != len(observed.symbols):
        findings.append(
            {
                "field": "symbols_uniqueness",
                "expected": "all symbols unique",
                "actual": "duplicates detected",
                "message": "WASM_ABI_SIGNATURES_V1 contains duplicate symbols",
            }
        )

    return findings


def verify_documentation(contract: ContractPaths, doc_text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if contract.contract_id not in doc_text:
        findings.append(
            {
                "field": "contract_id",
                "expected": contract.contract_id,
                "actual": "missing",
                "message": "documentation missing contract identifier",
            }
        )

    for marker in contract.required_doc_markers:
        if marker not in doc_text:
            findings.append(
                {
                    "field": "documentation_marker",
                    "expected": marker,
                    "actual": "missing",
                    "message": "documentation marker missing",
                }
            )

    return findings


def verify_migration_notes(doc_text: str, observed: ObservedContract) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    heading = "## Migration Notes Ledger"
    if heading not in doc_text:
        findings.append(
            {
                "field": "migration_notes_heading",
                "expected": heading,
                "actual": "missing",
                "message": "documentation missing migration notes ledger heading",
            }
        )
        return findings

    match = MIGRATION_ENTRY_RE.search(doc_text)
    if not match:
        findings.append(
            {
                "field": "migration_notes_current_entry",
                "expected": (
                    "Current ABI entry: `v<major>.<minor> fingerprint=<fingerprint>`"
                ),
                "actual": "missing_or_malformed",
                "message": "migration notes missing parseable current ABI entry",
            }
        )
        return findings

    doc_major = int(match.group("major"))
    doc_minor = int(match.group("minor"))
    doc_fingerprint = int(match.group("fingerprint").replace("_", ""))

    if (
        doc_major != observed.major_version
        or doc_minor != observed.minor_version
        or doc_fingerprint != observed.signature_fingerprint
    ):
        findings.append(
            {
                "field": "migration_notes_current_entry",
                "expected": {
                    "major_version": observed.major_version,
                    "minor_version": observed.minor_version,
                    "signature_fingerprint": observed.signature_fingerprint,
                },
                "actual": {
                    "major_version": doc_major,
                    "minor_version": doc_minor,
                    "signature_fingerprint": doc_fingerprint,
                },
                "message": "migration notes current ABI entry does not match source contract",
            }
        )

    return findings


def write_outputs(
    summary_path: pathlib.Path,
    log_path: pathlib.Path,
    contract: ContractPaths,
    expected: ExpectedContract,
    observed: ObservedContract,
    findings: list[dict[str, Any]],
) -> None:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    passed = not findings

    summary = {
        "schema_version": "wasm-abi-contract-summary-v1",
        "generated_at": now,
        "status": "pass" if passed else "fail",
        "contract_id": contract.contract_id,
        "source": contract.source,
        "documentation": contract.documentation,
        "expected": {
            "major_version": expected.major_version,
            "minor_version": expected.minor_version,
            "signature_fingerprint": expected.signature_fingerprint,
            "symbols": list(expected.symbols),
        },
        "observed": {
            "major_version": observed.major_version,
            "minor_version": observed.minor_version,
            "signature_fingerprint": observed.signature_fingerprint,
            "symbols": list(observed.symbols),
        },
        "finding_count": len(findings),
        "findings": findings,
    }

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    events: list[dict[str, Any]] = []
    if findings:
        for finding in findings:
            events.append(
                {
                    "schema": "wasm-abi-contract-event-v1",
                    "event": "wasm_abi_policy_finding",
                    "severity": "error",
                    "generated_at": now,
                    **finding,
                }
            )
    else:
        events.append(
            {
                "schema": "wasm-abi-contract-event-v1",
                "event": "wasm_abi_policy_pass",
                "severity": "info",
                "generated_at": now,
                "message": "WASM ABI contract policy checks passed",
            }
        )

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


def run_self_tests() -> None:
    source = """
pub const WASM_ABI_MAJOR_VERSION: u16 = 1;
pub const WASM_ABI_MINOR_VERSION: u16 = 0;
pub const WASM_ABI_SIGNATURE_FINGERPRINT_V1: u64 = 1_234;
pub const WASM_ABI_SIGNATURES_V1: [WasmAbiSignature; 2] = [
    WasmAbiSignature {
        symbol: WasmAbiSymbol::RuntimeCreate,
        request: WasmAbiPayloadShape::Empty,
        response: WasmAbiPayloadShape::HandleRefV1,
    },
    WasmAbiSignature {
        symbol: WasmAbiSymbol::FetchRequest,
        request: WasmAbiPayloadShape::FetchRequestV1,
        response: WasmAbiPayloadShape::OutcomeEnvelopeV1,
    },
];
"""
    observed = parse_contract_from_source(source)
    assert observed.major_version == 1
    assert observed.minor_version == 0
    assert observed.signature_fingerprint == 1234
    assert observed.symbols == ("runtime_create", "fetch_request")
    assert _camel_to_snake("TaskJoin") == "task_join"

    expected = ExpectedContract(
        major_version=1,
        minor_version=0,
        signature_fingerprint=1234,
        symbols=("runtime_create", "fetch_request"),
    )
    assert not compare_contract(expected, observed)

    expected_bad = ExpectedContract(
        major_version=1,
        minor_version=1,
        signature_fingerprint=1234,
        symbols=("runtime_create", "fetch_request"),
    )
    assert compare_contract(expected_bad, observed)

    docs = (
        "Contract ID: `asupersync-wasm-abi-v1`\n"
        "Drift Detection and CI Gate\n"
        "## Migration Notes Ledger\n"
        "Current ABI entry: `v1.0 fingerprint=1234`\n"
    )
    contract = ContractPaths(
        contract_id="asupersync-wasm-abi-v1",
        source="src/types/wasm_abi.rs",
        documentation="docs/wasm_abi_contract.md",
        required_doc_markers=("Drift Detection and CI Gate",),
    )
    assert not verify_documentation(contract, docs)
    assert verify_documentation(contract, "missing everything")
    assert not verify_migration_notes(docs, observed)
    assert verify_migration_notes("## Migration Notes Ledger\n", observed)
    assert verify_migration_notes(
        "## Migration Notes Ledger\nCurrent ABI entry: `v2.0 fingerprint=1`\n", observed
    )

    print("wasm ABI policy self-test passed")


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_tests()
        return 0

    repo_root = pathlib.Path.cwd()
    policy_path = pathlib.Path(args.policy)
    contract, expected, summary_default, log_default = load_policy(policy_path)

    source_path = repo_root / contract.source
    doc_path = repo_root / contract.documentation
    source_text = source_path.read_text(encoding="utf-8")
    doc_text = doc_path.read_text(encoding="utf-8")

    observed = parse_contract_from_source(source_text)
    findings = compare_contract(expected, observed)
    findings.extend(verify_documentation(contract, doc_text))
    findings.extend(verify_migration_notes(doc_text, observed))

    summary_path = pathlib.Path(args.summary_output or summary_default)
    log_path = pathlib.Path(args.log_output or log_default)
    write_outputs(summary_path, log_path, contract, expected, observed, findings)

    if findings:
        print(f"WASM ABI policy gate failed with {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("WASM ABI policy gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
