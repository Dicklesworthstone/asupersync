#!/usr/bin/env python3
"""Emit a non-mutating inventory of proof-lane receipt helpers.

The helper consumes fixture rows that describe receipt scripts, contract tests,
fixtures, and capability coverage. It produces a deterministic operator report
that points out duplicate, superseded, draft, or weakly covered helper surfaces
before agents spend time building overlapping proof artifacts.
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-receipt-inventory-v1"
DRAFT_STATUSES = {"draft", "in_progress", "uncommitted", "wip"}
SUPERSEDED_STATUSES = {"superseded", "retired", "replaced"}
CURRENT_STATUSES = {"current", "shipped", "active", "landed"}
TOKEN_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b(token|secret|password|api[_-]?key|authorization)(\s*[:=]\s*)([^\s,;]+)"
)
SECRET_FLAG_RE = re.compile(
    r"(?i)(--(?:token|secret|password|api[_-]?key|authorization)\b\s+)(?!-)([^\s,;]+)"
)
URL_QUERY_RE = re.compile(r"(https?://[^\s?#)>\]]+)\?[^ \n)>\]]+")
LONG_WORD_RE = re.compile(r"\b[A-Za-z0-9._~/+=-]{96,}\b")
SPACE_RE = re.compile(r"\s+")
SAFE_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CARGO_COMMAND_RE = re.compile(r"(?<![A-Za-z0-9_.-])cargo(?![A-Za-z0-9_.-])", re.IGNORECASE)
RCH_LOCAL_FALLBACK_RE = re.compile(
    r"(?m)^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally",
    re.IGNORECASE,
)
FORBIDDEN_VALIDATION_PATTERNS = (
    (
        "rm -rf",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])rm\s+-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]*\b"),
    ),
    (
        "git reset --hard",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])git\s+reset\s+--hard\b"),
    ),
    (
        "git clean -fd",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])git\s+clean\s+-(?=[A-Za-z]*f)(?=[A-Za-z]*d)[A-Za-z]*\b"),
    ),
    (
        "git worktree add",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])git\s+worktree\s+add\b"),
    ),
    (
        "git checkout -b",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])git\s+checkout\s+-b\b"),
    ),
    (
        "git switch -c",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])git\s+switch\s+-c\b"),
    ),
    (
        "git branch non-main",
        re.compile(r"(?i)(?<![A-Za-z0-9_.-])git\s+branch\s+(?!-)(?!main(?:\s|$))\S+"),
    ),
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def current_date(generated_at: str) -> str:
    parsed = parse_timestamp(generated_at)
    if parsed is None:
        return dt.datetime.now(dt.timezone.utc).date().isoformat()
    return parsed.date().isoformat()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rows_from(value: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    rows: list[dict[str, Any]] = []
    for key in keys:
        maybe_rows = value.get(key)
        if isinstance(maybe_rows, list):
            rows.extend(item for item in maybe_rows if isinstance(item, dict))
    return rows


def as_string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def redacted_string_list(value: Any, counts: dict[str, int]) -> list[str]:
    return [redact_text(item, counts) for item in as_string_list(value)]


def slug_from_path(path: str) -> str:
    name = Path(path).name
    if name.endswith(".py"):
        name = name[:-3]
    return name.replace("_", "-")


def helper_id(row: dict[str, Any]) -> str:
    for key in ("helper_id", "name", "id"):
        value = as_string(row.get(key))
        if value:
            return value
    script_path = as_string(row.get("script_path"))
    if script_path:
        return slug_from_path(script_path)
    return hashlib.sha1(json.dumps(row, sort_keys=True).encode()).hexdigest()[:12]


def redact_text(text: str, counts: dict[str, int]) -> str:
    def replace(pattern: re.Pattern[str], replacement: str, label: str, value: str) -> str:
        redacted, changed = pattern.subn(replacement, value)
        counts[label] = counts.get(label, 0) + changed
        counts["total"] = counts.get("total", 0) + changed
        return redacted

    text = replace(URL_QUERY_RE, r"\1?[REDACTED_QUERY]", "url_query", text)
    text = replace(TOKEN_RE, r"\1[REDACTED_TOKEN]", "token", text)
    text = replace(KEY_VALUE_SECRET_RE, r"\1\2[REDACTED_SECRET]", "secret", text)
    text = replace(SECRET_FLAG_RE, r"\1[REDACTED_SECRET]", "secret", text)
    text = replace(LONG_WORD_RE, "[REDACTED_LONG_TOKEN]", "long_token", text)
    return text


def compact_text(text: str, counts: dict[str, int], limit: int = 260) -> str:
    compact = SPACE_RE.sub(" ", redact_text(text, counts)).strip()
    if len(compact) <= limit:
        return compact
    counts["truncated"] = counts.get("truncated", 0) + 1
    counts["total"] = counts.get("total", 0) + 1
    return compact[: limit - 19].rstrip() + " [TRUNCATED]"


def normalize_helper(row: dict[str, Any], counts: dict[str, int]) -> dict[str, Any]:
    status = as_string(row.get("status")).lower() or "unknown"
    script_path = as_string(row.get("script_path"))
    test_path = as_string(row.get("test_path") or row.get("contract_test_path"))
    fixture_root = as_string(row.get("fixture_root") or row.get("fixtures_path"))
    capability_id = as_string(row.get("capability_id") or row.get("capability"))
    if not capability_id:
        capability_id = slug_from_path(script_path) if script_path else helper_id(row)
    return {
        "helper_id": helper_id(row),
        "capability_id": capability_id,
        "status": status,
        "script_path": script_path,
        "test_path": test_path,
        "fixture_root": fixture_root,
        "owner": as_string(row.get("owner") or row.get("agent")),
        "bead_id": as_string(row.get("bead_id")),
        "commit": as_string(row.get("commit") or row.get("commit_hash"))[:12],
        "superseded_by": as_string(row.get("superseded_by")),
        "validation": redacted_string_list(row.get("validation") or row.get("validation_commands"), counts),
        "summary": compact_text(as_string(row.get("summary") or row.get("description")), counts),
    }


def is_superseded(row: dict[str, Any]) -> bool:
    return bool(row["superseded_by"]) or row["status"] in SUPERSEDED_STATUSES


def is_draft(row: dict[str, Any]) -> bool:
    return row["status"] in DRAFT_STATUSES


def is_covered(row: dict[str, Any]) -> bool:
    return bool(row["script_path"] and row["test_path"] and row["fixture_root"])


def first_non_assignment(argv: list[str], start: int = 0) -> int:
    index = start
    while index < len(argv) and "=" in argv[index]:
        name, _value = argv[index].split("=", 1)
        if not SAFE_ENV_NAME.fullmatch(name):
            break
        index += 1
    return index


def command_mentions_cargo(command: str) -> bool:
    return CARGO_COMMAND_RE.search(command) is not None


def command_routes_cargo_through_rch(command: str) -> bool:
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return not command_mentions_cargo(command)

    lowered = [arg.lower() for arg in argv]
    if "cargo" not in lowered:
        return not command_mentions_cargo(command)

    program_index = first_non_assignment(argv)
    if program_index >= len(argv):
        return False
    if lowered[program_index:program_index + 3] != ["rch", "exec", "--"]:
        return False

    remote_index = program_index + 3
    if remote_index < len(argv) and lowered[remote_index] == "env":
        remote_index = first_non_assignment(argv, remote_index + 1)
    return remote_index < len(argv) and lowered[remote_index] == "cargo"


def command_routes_cargo_with_target_dir(command: str) -> bool:
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return not command_mentions_cargo(command)

    lowered = [arg.lower() for arg in argv]
    if "cargo" not in lowered:
        return not command_mentions_cargo(command)

    program_index = first_non_assignment(argv)
    if program_index >= len(argv):
        return False
    if lowered[program_index:program_index + 3] != ["rch", "exec", "--"]:
        return False

    remote_index = program_index + 3
    if remote_index >= len(argv) or lowered[remote_index] != "env":
        return False

    has_target_dir = False
    remote_index += 1
    while remote_index < len(argv) and "=" in argv[remote_index]:
        name, value = argv[remote_index].split("=", 1)
        if not SAFE_ENV_NAME.fullmatch(name):
            break
        if name == "CARGO_TARGET_DIR" and value:
            has_target_dir = True
        remote_index += 1
    return has_target_dir and remote_index < len(argv) and lowered[remote_index] == "cargo"


def command_routes_cargo_with_remote_required(command: str) -> bool:
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return not command_mentions_cargo(command)

    lowered = [arg.lower() for arg in argv]
    if "cargo" not in lowered:
        return not command_mentions_cargo(command)

    program_index = first_non_assignment(argv)
    if program_index >= len(argv):
        return False
    if lowered[program_index:program_index + 3] != ["rch", "exec", "--"]:
        return False

    for assignment in argv[:program_index]:
        name, value = assignment.split("=", 1)
        if name == "RCH_REQUIRE_REMOTE" and value.lower() in {"1", "true", "yes", "on"}:
            return True
    return False


def unsafe_validation_commands(row: dict[str, Any]) -> list[str]:
    return [
        command
        for command in row["validation"]
        if command_mentions_cargo(command) and not command_routes_cargo_through_rch(command)
    ]


def missing_target_dir_validation_commands(row: dict[str, Any]) -> list[str]:
    return [
        command
        for command in row["validation"]
        if command_mentions_cargo(command)
        and command_routes_cargo_through_rch(command)
        and not command_routes_cargo_with_target_dir(command)
    ]


def missing_remote_required_validation_commands(row: dict[str, Any]) -> list[str]:
    return [
        command
        for command in row["validation"]
        if command_mentions_cargo(command)
        and command_routes_cargo_through_rch(command)
        and not command_routes_cargo_with_remote_required(command)
    ]


def local_fallback_validation_commands(row: dict[str, Any]) -> list[str]:
    return [
        command
        for command in row["validation"]
        if RCH_LOCAL_FALLBACK_RE.search(command)
    ]


def forbidden_validation_commands(row: dict[str, Any]) -> list[tuple[str, str]]:
    violations = []
    for command in row["validation"]:
        for label, pattern in FORBIDDEN_VALIDATION_PATTERNS:
            if pattern.search(command):
                violations.append((command, label))
                break
    return violations


def canonical_key(row: dict[str, Any]) -> tuple[int, int, int, str]:
    if is_superseded(row):
        tier = 3
    elif is_draft(row):
        tier = 2
    elif not is_covered(row):
        tier = 1
    else:
        tier = 0
    validation_bonus = 0 if row["validation"] else 1
    commit_bonus = 0 if row["commit"] else 1
    return (tier, validation_bonus, commit_bonus, row["helper_id"])


def group_by_capability(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["capability_id"], []).append(row)
    return grouped


def classify_row(row: dict[str, Any], canonical: dict[str, Any], active_count: int) -> str:
    if is_draft(row) and row["superseded_by"]:
        return "superseded-draft"
    if is_superseded(row):
        return "superseded"
    if not row["test_path"]:
        return "missing-contract-test"
    if not row["fixture_root"]:
        return "missing-fixture-root"
    if is_draft(row):
        return "draft"
    if row["helper_id"] == canonical["helper_id"]:
        return "canonical"
    if active_count > 1:
        return "duplicate-capability"
    return "covered"


def capability_summaries(
    grouped: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    summaries = []
    canonical_by_capability = {}
    for capability_id in sorted(grouped):
        rows = sorted(grouped[capability_id], key=lambda row: row["helper_id"])
        active = [row for row in rows if not is_superseded(row)]
        superseded = [row for row in rows if is_superseded(row)]
        drafts = [row for row in active if is_draft(row)]
        canonical = sorted(rows, key=canonical_key)[0]
        canonical_by_capability[capability_id] = canonical
        duplicate_active_count = max(0, len(active) - 1)
        summaries.append(
            {
                "capability_id": capability_id,
                "helper_count": len(rows),
                "active_helper_count": len(active),
                "superseded_helper_count": len(superseded),
                "draft_helper_count": len(drafts),
                "duplicate_active_count": duplicate_active_count,
                "canonical_helper": canonical["helper_id"],
                "needs_review": duplicate_active_count > 0
                or bool(drafts)
                or any(not is_covered(row) for row in rows)
                or any(unsafe_validation_commands(row) for row in rows)
                or any(missing_target_dir_validation_commands(row) for row in rows)
                or any(missing_remote_required_validation_commands(row) for row in rows)
                or any(local_fallback_validation_commands(row) for row in rows)
                or any(forbidden_validation_commands(row) for row in rows),
            }
        )
    return summaries, canonical_by_capability


def inventory_rows(
    helpers: list[dict[str, Any]],
    grouped: dict[str, list[dict[str, Any]]],
    canonical_by_capability: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for row in sorted(helpers, key=lambda item: (item["capability_id"], item["helper_id"])):
        active_count = len([item for item in grouped[row["capability_id"]] if not is_superseded(item)])
        classification = classify_row(row, canonical_by_capability[row["capability_id"]], active_count)
        rows.append({**row, "classification": classification})
    return rows


def review_cues(rows: list[dict[str, Any]], capabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cues = []
    for capability in capabilities:
        if capability["duplicate_active_count"] > 0:
            cues.append(
                {
                    "kind": "capability-overlap",
                    "severity": "high",
                    "capability_id": capability["capability_id"],
                    "canonical_helper": capability["canonical_helper"],
                    "recommendation": "coordinate before adding another helper for this capability",
                }
            )
    for row in rows:
        if row["classification"] == "superseded-draft":
            cues.append(
                {
                    "kind": "stand-down-draft",
                    "severity": "high",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "superseded_by": row["superseded_by"],
                    "recommendation": "do not continue this draft; port missing cases to the superseding helper",
                }
            )
        elif row["classification"] == "superseded":
            cues.append(
                {
                    "kind": "superseded-helper",
                    "severity": "medium",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "superseded_by": row["superseded_by"],
                    "recommendation": "route future fixes to the superseding helper and avoid citing this one as canonical",
                }
            )
        elif row["classification"] == "draft":
            cues.append(
                {
                    "kind": "draft-helper",
                    "severity": "medium",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "recommendation": "finish or retire this draft before citing it as canonical",
                }
            )
        elif row["classification"] in {"missing-contract-test", "missing-fixture-root"}:
            cues.append(
                {
                    "kind": row["classification"],
                    "severity": "medium",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "recommendation": "add fixture-backed contract coverage before citing this helper",
                }
            )
        for command in unsafe_validation_commands(row):
            cues.append(
                {
                    "kind": "unsafe-validation-command",
                    "severity": "high",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "command": command,
                    "recommendation": "route Cargo validation through rch exec before citing this helper",
                }
            )
        for command in missing_target_dir_validation_commands(row):
            cues.append(
                {
                    "kind": "missing-cargo-target-dir-validation",
                    "severity": "high",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "command": command,
                    "recommendation": "include explicit CARGO_TARGET_DIR in the rch exec env before citing this helper",
                }
            )
        for command in missing_remote_required_validation_commands(row):
            cues.append(
                {
                    "kind": "missing-remote-required-validation",
                    "severity": "high",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "command": command,
                    "recommendation": "prefix rch Cargo validation with RCH_REQUIRE_REMOTE=1 before citing this helper",
                }
            )
        for command in local_fallback_validation_commands(row):
            cues.append(
                {
                    "kind": "rch-local-fallback-validation",
                    "severity": "high",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "command": command,
                    "recommendation": "rerun validation remotely; local rch fallback is not acceptable proof",
                }
            )
        for command, violation in forbidden_validation_commands(row):
            cues.append(
                {
                    "kind": "forbidden-validation-command",
                    "severity": "high",
                    "capability_id": row["capability_id"],
                    "helper_id": row["helper_id"],
                    "command": command,
                    "violation": violation,
                    "recommendation": "remove forbidden destructive operations from validation commands and record a proof blocker instead",
                }
            )
    return sorted(cues, key=lambda cue: (cue["severity"], cue["kind"], cue["capability_id"], cue.get("helper_id", "")))


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    source = load_json(Path(args.fixture))
    counts: dict[str, int] = {}
    helpers = [normalize_helper(row, counts) for row in rows_from(source, ("helpers", "receipts"))]
    grouped = group_by_capability(helpers)
    capabilities, canonical_by_capability = capability_summaries(grouped)
    rows = inventory_rows(helpers, grouped, canonical_by_capability)
    cues = review_cues(rows, capabilities)
    generated_at = args.generated_at or utc_now()

    classifications: dict[str, int] = {}
    for row in rows:
        classification = row["classification"]
        classifications[classification] = classifications.get(classification, 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "agent": args.agent,
        "repo_path": str(args.repo_path),
        "source_counts": {
            "helpers": len(helpers),
            "capabilities": len(capabilities),
            "review_cues": len(cues),
            "duplicate_capabilities": sum(1 for row in capabilities if row["duplicate_active_count"] > 0),
            "superseded_helpers": sum(1 for row in rows if row["classification"] in {"superseded", "superseded-draft"}),
        },
        "classification_counts": classifications,
        "capabilities": capabilities,
        "helpers": rows,
        "review_cues": cues,
        "redaction_counts": counts,
        "safety": {
            "non_mutating": True,
            "reads_fixture_only": True,
            "agent_mail_mutated": False,
            "beads_mutated": False,
            "git_mutated": False,
            "cargo_executed": False,
            "branch_or_worktree_operations": False,
            "files_deleted": False,
            "live_probe_performed": False,
        },
        "safety_notes": [
            "fixture mode reads only the supplied inventory JSON",
            "receipt does not inspect live Agent Mail, Beads, git, rch, or cargo state",
            "review cues are advisory and require human or agent coordination before action",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a proof receipt helper inventory")
    parser.add_argument("--fixture", required=True, help="Fixture JSON containing helpers or receipts rows")
    parser.add_argument("--repo-path", default=".", help="Repository path recorded in the receipt")
    parser.add_argument("--agent", default="", help="Agent producing the inventory receipt")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic receipts")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
