#!/usr/bin/env python3
"""WASM dependency policy gate for forbidden/conditional runtime crates.

This script performs a deterministic dependency audit using `cargo tree` and
applies policy classifications:
- forbidden crates: always fail the gate
- conditional crates: allowed only with explicit transition tracking

It emits:
- JSON summary report
- NDJSON structured finding log
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

TREE_LINE_RE = re.compile(r"^(\d+)(.+)$")


@dataclass(frozen=True)
class PolicyEntry:
    name: str
    reason: str
    remediation: str
    risk_score: int


@dataclass(frozen=True)
class Transition:
    crate: str
    status: str
    owner: str
    replacement_issue: str
    expires_at_utc: str
    notes: str


@dataclass(frozen=True)
class Profile:
    profile_id: str
    target: str
    all_features: bool
    no_default_features: bool
    features: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    profile_id: str
    target: str
    crate: str
    version: str
    transitive_chain: tuple[str, ...]
    decision: str
    decision_reason: str
    remediation: str
    risk_score: int
    transition_status: str
    transition_issue: str | None


class PolicyError(ValueError):
    """Raised when policy validation fails."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/wasm_dependency_policy.json",
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
        help="Override NDJSON output path",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run unit checks for parser/classification logic",
    )
    parser.add_argument(
        "--only-profile",
        action="append",
        default=[],
        help="Restrict scan to one or more profile IDs",
    )
    return parser.parse_args()


def parse_iso8601_utc(raw: str) -> dt.datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise PolicyError(f"timestamp missing timezone: {raw}")
    return parsed.astimezone(dt.timezone.utc)


def load_policy(policy_path: pathlib.Path) -> dict[str, Any]:
    try:
        data = json.loads(policy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON in policy file {policy_path}: {exc}") from exc

    if data.get("schema_version") != "wasm-dependency-policy-v1":
        raise PolicyError("unsupported or missing schema_version")

    for key in ("profiles", "forbidden_crates", "conditional_crates", "transitions"):
        if not isinstance(data.get(key), list):
            raise PolicyError(f"{key} must be a list")

    thresholds = data.get("risk_thresholds")
    if not isinstance(thresholds, dict) or not isinstance(thresholds.get("high"), int):
        raise PolicyError("risk_thresholds.high must be an integer")

    output_cfg = data.get("output")
    if not isinstance(output_cfg, dict):
        raise PolicyError("output must be an object")
    if not isinstance(output_cfg.get("summary_path"), str) or not isinstance(
        output_cfg.get("log_path"), str
    ):
        raise PolicyError("output.summary_path and output.log_path must be strings")

    return data


def load_profiles(policy: dict[str, Any], only_profile: set[str]) -> list[Profile]:
    profiles: list[Profile] = []
    seen: set[str] = set()
    for raw in policy["profiles"]:
        if not isinstance(raw, dict):
            raise PolicyError("profiles entries must be objects")
        profile_id = raw.get("id")
        target = raw.get("target")
        if not isinstance(profile_id, str) or not isinstance(target, str):
            raise PolicyError("profile id/target must be strings")
        if profile_id in seen:
            raise PolicyError(f"duplicate profile id: {profile_id}")
        seen.add(profile_id)

        features = raw.get("features", [])
        if not isinstance(features, list) or not all(isinstance(x, str) for x in features):
            raise PolicyError(f"profile {profile_id}: features must be a list[str]")

        if only_profile and profile_id not in only_profile:
            continue

        profiles.append(
            Profile(
                profile_id=profile_id,
                target=target,
                all_features=bool(raw.get("all_features", False)),
                no_default_features=bool(raw.get("no_default_features", False)),
                features=tuple(sorted(features)),
            )
        )

    if only_profile and not profiles:
        missing = ", ".join(sorted(only_profile))
        raise PolicyError(f"--only-profile selected unknown profile(s): {missing}")

    return profiles


def load_entry_map(raw_entries: list[dict[str, Any]], section_name: str) -> dict[str, PolicyEntry]:
    entries: dict[str, PolicyEntry] = {}
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise PolicyError(f"{section_name} entries must be objects")

        name = raw.get("name")
        reason = raw.get("reason")
        remediation = raw.get("remediation")
        risk_score = raw.get("risk_score")

        if not isinstance(name, str):
            raise PolicyError(f"{section_name}.name must be string")
        if not isinstance(reason, str) or not reason.strip():
            raise PolicyError(f"{section_name}.{name}: reason must be non-empty string")
        if not isinstance(remediation, str) or not remediation.strip():
            raise PolicyError(f"{section_name}.{name}: remediation must be non-empty string")
        if not isinstance(risk_score, int) or not (0 <= risk_score <= 100):
            raise PolicyError(f"{section_name}.{name}: risk_score must be int in [0, 100]")
        if name in entries:
            raise PolicyError(f"duplicate entry {name} in {section_name}")

        entries[name] = PolicyEntry(
            name=name,
            reason=reason,
            remediation=remediation,
            risk_score=risk_score,
        )

    return entries


def load_transitions(raw_transitions: list[dict[str, Any]]) -> dict[str, Transition]:
    transitions: dict[str, Transition] = {}
    for raw in raw_transitions:
        if not isinstance(raw, dict):
            raise PolicyError("transitions entries must be objects")

        crate = raw.get("crate")
        status = raw.get("status")
        owner = raw.get("owner")
        replacement_issue = raw.get("replacement_issue")
        expires_at_utc = raw.get("expires_at_utc")
        notes = raw.get("notes", "")

        if not isinstance(crate, str):
            raise PolicyError("transition crate must be string")
        if not isinstance(status, str) or status not in {"active", "resolved"}:
            raise PolicyError(f"transition {crate}: status must be active|resolved")
        if not isinstance(owner, str) or not owner.strip():
            raise PolicyError(f"transition {crate}: owner must be non-empty string")
        if not isinstance(replacement_issue, str) or not replacement_issue.strip():
            raise PolicyError(f"transition {crate}: replacement_issue must be non-empty string")
        if not isinstance(expires_at_utc, str):
            raise PolicyError(f"transition {crate}: expires_at_utc must be string")
        parse_iso8601_utc(expires_at_utc)
        if not isinstance(notes, str):
            raise PolicyError(f"transition {crate}: notes must be string")
        if crate in transitions:
            raise PolicyError(f"duplicate transition for crate {crate}")

        transitions[crate] = Transition(
            crate=crate,
            status=status,
            owner=owner,
            replacement_issue=replacement_issue,
            expires_at_utc=expires_at_utc,
            notes=notes,
        )

    return transitions


def validate_policy_cross_refs(
    forbidden_map: dict[str, PolicyEntry],
    conditional_map: dict[str, PolicyEntry],
    transitions: dict[str, Transition],
) -> None:
    overlap = set(forbidden_map).intersection(conditional_map)
    if overlap:
        names = ", ".join(sorted(overlap))
        raise PolicyError(f"ambiguous policy mapping; crate(s) in forbidden+conditional: {names}")

    for crate in transitions:
        if crate not in forbidden_map and crate not in conditional_map:
            raise PolicyError(
                f"transition references crate not present in forbidden/conditional maps: {crate}"
            )


def parse_tree_line(raw_line: str) -> tuple[int, str, str]:
    match = TREE_LINE_RE.match(raw_line.strip())
    if match is None:
        raise PolicyError(f"invalid cargo tree line format: {raw_line!r}")

    depth = int(match.group(1))
    payload = match.group(2).strip()
    if not payload:
        raise PolicyError(f"missing package payload in line: {raw_line!r}")

    payload = payload.replace(" (*)", "")
    parts = payload.split()
    if len(parts) < 2:
        raise PolicyError(f"invalid package payload in line: {raw_line!r}")

    crate = parts[0]
    version = parts[1] if parts[1].startswith("v") else "v?"
    return depth, crate, version


def run_cargo_tree(profile: Profile) -> tuple[list[str], list[str]]:
    cmd = [
        "cargo",
        "tree",
        "--workspace",
        "--target",
        profile.target,
        "-e",
        "normal",
        "--prefix",
        "depth",
        "--charset",
        "ascii",
    ]

    if profile.no_default_features:
        cmd.append("--no-default-features")
    if profile.all_features:
        cmd.append("--all-features")
    if profile.features:
        cmd += ["--features", ",".join(profile.features)]

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        raise RuntimeError(
            f"cargo tree failed for profile={profile.profile_id} target={profile.target}: {stderr}"
        )

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return cmd, lines


def classify_dependency(
    crate: str,
    forbidden_map: dict[str, PolicyEntry],
    conditional_map: dict[str, PolicyEntry],
    transitions: dict[str, Transition],
    now_utc: dt.datetime,
) -> tuple[str, str, str, int, str, str | None]:
    transition = transitions.get(crate)

    if crate in forbidden_map:
        entry = forbidden_map[crate]
        decision = "forbidden"
    elif crate in conditional_map:
        entry = conditional_map[crate]
        decision = "conditional"
    else:
        return "allowed", "not policy-managed", "none", 0, "none", None

    transition_status = "none"
    transition_issue: str | None = None
    if transition is not None:
        transition_issue = transition.replacement_issue
        expiry = parse_iso8601_utc(transition.expires_at_utc)
        if transition.status == "resolved":
            transition_status = "resolved"
        elif expiry <= now_utc:
            transition_status = "expired"
        else:
            transition_status = "active"

    return (
        decision,
        entry.reason,
        entry.remediation,
        entry.risk_score,
        transition_status,
        transition_issue,
    )


def scan_profile(
    profile: Profile,
    forbidden_map: dict[str, PolicyEntry],
    conditional_map: dict[str, PolicyEntry],
    transitions: dict[str, Transition],
    now_utc: dt.datetime,
) -> tuple[list[Finding], dict[str, Any]]:
    cmd, lines = run_cargo_tree(profile)

    findings: list[Finding] = []
    stack: list[str] = []

    for raw_line in lines:
        depth, crate, version = parse_tree_line(raw_line)

        if depth == 0:
            stack = [crate]
        else:
            while len(stack) > depth:
                stack.pop()
            while len(stack) < depth:
                stack.append("<missing-parent>")
            stack.append(crate)

        (
            decision,
            reason,
            remediation,
            risk_score,
            transition_status,
            transition_issue,
        ) = classify_dependency(crate, forbidden_map, conditional_map, transitions, now_utc)

        if decision == "allowed":
            continue

        findings.append(
            Finding(
                profile_id=profile.profile_id,
                target=profile.target,
                crate=crate,
                version=version,
                transitive_chain=tuple(stack),
                decision=decision,
                decision_reason=reason,
                remediation=remediation,
                risk_score=risk_score,
                transition_status=transition_status,
                transition_issue=transition_issue,
            )
        )

    findings = sorted(
        set(findings),
        key=lambda item: (
            item.profile_id,
            item.decision,
            item.crate,
            item.version,
            ">".join(item.transitive_chain),
        ),
    )

    stats = {
        "profile_id": profile.profile_id,
        "target": profile.target,
        "command": " ".join(cmd),
        "line_count": len(lines),
        "finding_count": len(findings),
        "forbidden_count": sum(1 for item in findings if item.decision == "forbidden"),
        "conditional_count": sum(1 for item in findings if item.decision == "conditional"),
    }

    return findings, stats


def finding_to_json(finding: Finding) -> dict[str, Any]:
    return {
        "profile_id": finding.profile_id,
        "target": finding.target,
        "crate": finding.crate,
        "version": finding.version,
        "transitive_chain": list(finding.transitive_chain),
        "decision": finding.decision,
        "decision_reason": finding.decision_reason,
        "remediation": finding.remediation,
        "risk_score": finding.risk_score,
        "transition_status": finding.transition_status,
        "transition_issue": finding.transition_issue,
    }


def write_ndjson(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evaluate_gate(
    findings: list[Finding],
    risk_high_threshold: int,
) -> tuple[bool, dict[str, Any]]:
    forbidden_hits = [item for item in findings if item.decision == "forbidden"]
    unresolved_high_risk = [
        item
        for item in findings
        if item.risk_score >= risk_high_threshold
        and item.transition_status not in {"active", "resolved"}
    ]
    expired_transitions = [item for item in findings if item.transition_status == "expired"]

    passed = not forbidden_hits and not unresolved_high_risk and not expired_transitions

    summary = {
        "passed": passed,
        "forbidden_count": len(forbidden_hits),
        "unresolved_high_risk_count": len(unresolved_high_risk),
        "expired_transition_count": len(expired_transitions),
        "high_risk_threshold": risk_high_threshold,
    }

    return passed, summary


def run_self_tests() -> int:
    def expect(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    now = parse_iso8601_utc("2026-01-01T00:00:00Z")

    depth, crate, version = parse_tree_line("2serde_json v1.0.149")
    expect(depth == 2, "depth parsing failed")
    expect(crate == "serde_json", "crate parsing failed")
    expect(version == "v1.0.149", "version parsing failed")

    forbidden = {"tokio": PolicyEntry("tokio", "forbidden", "remove", 100)}
    conditional = {"tower": PolicyEntry("tower", "conditional", "feature-gate", 70)}
    transitions = {
        "tower": Transition(
            crate="tower",
            status="active",
            owner="runtime-core",
            replacement_issue="asupersync-umelq.3.2",
            expires_at_utc="2026-06-01T00:00:00Z",
            notes="tracked",
        )
    }

    (
        decision_tokio,
        _reason_tokio,
        _rem_tokio,
        risk_tokio,
        transition_tokio,
        _,
    ) = classify_dependency("tokio", forbidden, conditional, transitions, now)
    expect(decision_tokio == "forbidden", "tokio decision should be forbidden")
    expect(risk_tokio == 100, "tokio risk score should be 100")
    expect(transition_tokio == "none", "tokio transition should be none")

    (
        decision_tower,
        _reason_tower,
        _rem_tower,
        risk_tower,
        transition_tower,
        transition_issue,
    ) = classify_dependency("tower", forbidden, conditional, transitions, now)
    expect(decision_tower == "conditional", "tower decision should be conditional")
    expect(risk_tower == 70, "tower risk score should be 70")
    expect(transition_tower == "active", "tower transition should be active")
    expect(
        transition_issue == "asupersync-umelq.3.2",
        "tower transition issue should match expected bead",
    )

    try:
        validate_policy_cross_refs(
            {"tokio": PolicyEntry("tokio", "x", "y", 90)},
            {"tokio": PolicyEntry("tokio", "x", "y", 90)},
            {},
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("overlap between forbidden/conditional should raise PolicyError")

    print("WASM dependency policy self-test passed")
    return 0


def main() -> int:
    args = parse_args()

    if args.self_test:
        return run_self_tests()

    policy_path = pathlib.Path(args.policy)
    policy = load_policy(policy_path)

    forbidden_map = load_entry_map(policy["forbidden_crates"], "forbidden_crates")
    conditional_map = load_entry_map(policy["conditional_crates"], "conditional_crates")
    transitions = load_transitions(policy["transitions"])
    validate_policy_cross_refs(forbidden_map, conditional_map, transitions)

    selected_profiles = load_profiles(policy, set(args.only_profile))

    if not selected_profiles:
        raise PolicyError("no profiles selected for scanning")

    now_utc = dt.datetime.now(dt.timezone.utc)
    risk_high_threshold = int(policy["risk_thresholds"]["high"])

    all_findings: list[Finding] = []
    profile_stats: list[dict[str, Any]] = []
    for profile in selected_profiles:
        findings, stats = scan_profile(
            profile,
            forbidden_map,
            conditional_map,
            transitions,
            now_utc,
        )
        all_findings.extend(findings)
        profile_stats.append(stats)

    all_findings = sorted(
        all_findings,
        key=lambda item: (
            item.profile_id,
            item.decision,
            item.crate,
            item.version,
            ">".join(item.transitive_chain),
        ),
    )

    passed, gate_summary = evaluate_gate(all_findings, risk_high_threshold)

    output_cfg = policy["output"]
    summary_path = pathlib.Path(args.summary_output or output_cfg["summary_path"])
    log_path = pathlib.Path(args.log_output or output_cfg["log_path"])

    findings_json = [finding_to_json(item) for item in all_findings]

    summary = {
        "schema_version": "wasm-dependency-audit-report-v1",
        "generated_at_utc": now_utc.isoformat().replace("+00:00", "Z"),
        "policy_path": str(policy_path),
        "policy_schema_version": policy["schema_version"],
        "profiles": sorted(profile_stats, key=lambda item: item["profile_id"]),
        "gate": gate_summary,
        "finding_count": len(findings_json),
        "findings": findings_json,
    }

    logs = []
    for finding in all_findings:
        log_row = {
            "event": "wasm_dependency_policy_finding",
            "ts_utc": now_utc.isoformat().replace("+00:00", "Z"),
            **finding_to_json(finding),
        }
        logs.append(log_row)

    write_json(summary_path, summary)
    write_ndjson(log_path, logs)

    if passed:
        print(
            "WASM dependency policy gate passed: "
            f"findings={len(findings_json)} forbidden={gate_summary['forbidden_count']} "
            f"unresolved_high_risk={gate_summary['unresolved_high_risk_count']} "
            f"expired_transitions={gate_summary['expired_transition_count']}"
        )
        return 0

    print(
        "WASM dependency policy gate failed: "
        f"forbidden={gate_summary['forbidden_count']} "
        f"unresolved_high_risk={gate_summary['unresolved_high_risk_count']} "
        f"expired_transitions={gate_summary['expired_transition_count']}"
    )
    print(f"Summary: {summary_path}")
    print(f"Log: {log_path}")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PolicyError as exc:
        print(f"WASM dependency policy configuration error: {exc}")
        raise SystemExit(2)
