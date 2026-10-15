#!/usr/bin/env python3
"""Emit a non-mutating inventory of proof-lane receipt helpers.

The helper consumes fixture rows that describe receipt scripts, contract tests,
fixtures, and capability coverage. It produces a deterministic operator report
that points out duplicate, superseded, draft, or weakly covered helper surfaces
before agents spend time building overlapping proof artifacts.
"""

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "proof-receipt-inventory-v1"
ASW_RELEASE_SCHEMA_VERSION = "asw-release-proof-v1"
DRAFT_STATUSES = {"draft", "in_progress", "uncommitted", "wip"}
SUPERSEDED_STATUSES = {"superseded", "retired", "replaced"}
CURRENT_STATUSES = {"current", "shipped", "active", "landed"}
ASW_READY_BEAD_STATUSES = {"closed", "done"}
ASW_READY_LEASE_STATUSES = {"active", "committed", "released", "completed"}
ASW_READY_ADMISSION_STATUSES = {"accepted", "admitted", "ready"}
ASW_READY_HANDOFF_DECISIONS = {"continue", "ready"}
ASW_PASS_STATUSES = {"green", "ok", "pass", "passed", "success", "succeeded"}
ASW_BLOCKER_ORDER = {
    "dirty-peer-file": 10,
    "reservation-mismatch": 20,
    "missing-reservation-evidence": 30,
    "stale-bead-status": 40,
    "missing-mail-closeout": 50,
    "mail-reservations-not-released": 60,
    "missing-lease-receipt": 70,
    "lease-not-committed": 80,
    "missing-admission-receipt": 90,
    "admission-not-admitted": 100,
    "missing-handoff-capsule": 110,
    "handoff-blocked": 120,
    "missing-commit-proof": 130,
    "unpushed-commit": 140,
    "missing-main-mirror-sync": 150,
    "rch-local-fallback-proof": 160,
    "missing-cargo-target-dir-proof": 170,
    "missing-remote-required-proof": 180,
    "missing-remote-rch-proof": 190,
}
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


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, int):
        return value != 0
    return default


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def redacted_string_list(value: Any, counts: dict[str, int]) -> list[str]:
    return [redact_text(item, counts) for item in as_string_list(value)]


def redacted_path_patterns(value: Any, counts: dict[str, int]) -> list[str]:
    rows = value if isinstance(value, list) else []
    paths: list[str] = []
    for item in rows:
        if isinstance(item, str) and item:
            paths.append(redact_text(item, counts))
        elif isinstance(item, dict):
            path = as_string(item.get("path_pattern") or item.get("path") or item.get("glob"))
            if path:
                paths.append(redact_text(path, counts))
    return sorted(dict.fromkeys(paths))


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


def normalize_proof_class(value: Any) -> str:
    proof_class = as_string(value).lower().replace("_", "-") or "production"
    if proof_class in {"prod", "release", "required"}:
        return "production"
    if proof_class in {"narrow", "narrow-supplemental", "supplemental"}:
        return "narrow-supplemental"
    if proof_class in {"blocker", "external", "external-blocker"}:
        return "external-blocker"
    return proof_class


def normalize_rch_proof(row: Any, counts: dict[str, int]) -> dict[str, Any]:
    data = row if isinstance(row, dict) else {"command": as_string(row)}
    raw_command = as_string(data.get("command"))
    raw_excerpt = as_string(data.get("output_excerpt") or data.get("log_excerpt"))
    status = as_string(data.get("status")).lower() or "unknown"
    local_fallback = (
        as_bool(data.get("local_fallback"))
        or bool(RCH_LOCAL_FALLBACK_RE.search(raw_command))
        or bool(RCH_LOCAL_FALLBACK_RE.search(raw_excerpt))
    )
    return {
        "command": compact_text(raw_command, counts, limit=520),
        "status": status,
        "proof_class": normalize_proof_class(data.get("proof_class") or data.get("class") or data.get("kind")),
        "remote": as_bool(data.get("remote")),
        "local_fallback": local_fallback,
        "cargo_command": command_mentions_cargo(raw_command),
        "routes_through_rch": command_routes_cargo_through_rch(raw_command),
        "has_cargo_target_dir": command_routes_cargo_with_target_dir(raw_command),
        "remote_required": command_routes_cargo_with_remote_required(raw_command),
        "output_excerpt": compact_text(raw_excerpt, counts, limit=260),
    }


def normalize_commit(row: Any, counts: dict[str, int]) -> dict[str, Any]:
    data = row if isinstance(row, dict) else {"hash": as_string(row)}
    pushed_refs = redacted_string_list(data.get("pushed_refs") or data.get("refs"), counts)
    main_ref_pushed = as_bool(data.get("main_ref_pushed"))
    pushed = as_bool(data.get("pushed"), default=main_ref_pushed)
    return {
        "hash": as_string(data.get("hash") or data.get("commit") or data.get("commit_hash"))[:12],
        "pushed": pushed,
        "main_ref_pushed": main_ref_pushed,
        "main_mirror_pushed": as_bool(data.get("main_mirror_pushed")),
        "pushed_refs": pushed_refs,
    }


def normalize_lease(row: Any, counts: dict[str, int]) -> dict[str, Any]:
    data = row if isinstance(row, dict) else {"lease_id": as_string(row)}
    return {
        "lease_id": as_string(data.get("lease_id") or data.get("id")),
        "resource": compact_text(as_string(data.get("resource") or data.get("path") or data.get("name")), counts, limit=160),
        "status": as_string(data.get("status")).lower() or "unknown",
    }


def proof_is_remote_production_pass(proof: dict[str, Any]) -> bool:
    return (
        proof["proof_class"] == "production"
        and proof["status"] in ASW_PASS_STATUSES
        and proof["remote"]
        and proof["cargo_command"]
        and proof["routes_through_rch"]
        and proof["has_cargo_target_dir"]
        and proof["remote_required"]
        and not proof["local_fallback"]
    )


def path_is_reserved(path: str, reservations: list[str]) -> bool:
    return any(
        path == pattern
        or fnmatch.fnmatchcase(path, pattern)
        or fnmatch.fnmatchcase(pattern, path)
        for pattern in reservations
    )


def asw_blocker(kind: str, detail: str = "", **extra: str) -> dict[str, Any]:
    row: dict[str, Any] = {"kind": kind, "severity": "high"}
    if detail:
        row["detail"] = detail
    for key, value in extra.items():
        if value:
            row[key] = value
    return row


def sort_asw_blockers(blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        blockers,
        key=lambda blocker: (
            ASW_BLOCKER_ORDER.get(blocker["kind"], 1000),
            blocker["kind"],
            blocker.get("path", ""),
            blocker.get("command", ""),
            blocker.get("detail", ""),
        ),
    )


def normalize_asw_release_packet(row: dict[str, Any], counts: dict[str, int]) -> dict[str, Any]:
    bead = as_dict(row.get("bead") or row.get("beads"))
    mail = as_dict(row.get("mail") or row.get("agent_mail"))
    admission = as_dict(row.get("admission") or row.get("admission_receipt"))
    handoff = as_dict(row.get("handoff") or row.get("handoff_capsule"))
    rch_proofs = [
        normalize_rch_proof(proof, counts)
        for proof in rows_from({"rows": row.get("rch_proofs") or row.get("rch") or []}, ("rows",))
    ]
    if not rch_proofs:
        rch_proofs = [normalize_rch_proof(proof, counts) for proof in as_string_list(row.get("validation"))]
    commits = [
        normalize_commit(commit, counts)
        for commit in rows_from({"rows": row.get("commits") or []}, ("rows",))
    ]
    leases = [
        normalize_lease(lease, counts)
        for lease in rows_from({"rows": row.get("leases") or row.get("lease_receipts") or []}, ("rows",))
    ]
    reservations = redacted_path_patterns(row.get("reservation_paths") or row.get("reservations"), counts)
    touched_paths = redacted_path_patterns(row.get("touched_paths") or row.get("paths"), counts)
    dirty_peer_paths = redacted_path_patterns(row.get("dirty_peer_paths"), counts)

    bead_status = as_string(bead.get("status") or row.get("bead_status")).lower() or "unknown"
    mail_closeout_sent = as_bool(mail.get("closeout_sent") or mail.get("closeout_message_sent"))
    mail_reservations_released = as_bool(mail.get("reservations_released"))
    admission_status = as_string(admission.get("status")).lower() or "unknown"
    handoff_decision = as_string(handoff.get("decision") or handoff.get("status")).lower() or "unknown"

    blockers: list[dict[str, Any]] = []
    if dirty_peer_paths:
        blockers.append(
            asw_blocker(
                "dirty-peer-file",
                f"{len(dirty_peer_paths)} dirty peer-owned path(s) overlap proof scope",
                path=dirty_peer_paths[0],
            )
        )
    if touched_paths and not reservations:
        blockers.append(asw_blocker("missing-reservation-evidence", "touched paths have no reservation evidence"))
    for path in touched_paths:
        if reservations and not path_is_reserved(path, reservations):
            blockers.append(asw_blocker("reservation-mismatch", "touched path is not covered by reservations", path=path))
    if bead_status not in ASW_READY_BEAD_STATUSES:
        blockers.append(asw_blocker("stale-bead-status", f"bead status is {bead_status}"))
    if not mail_closeout_sent:
        blockers.append(asw_blocker("missing-mail-closeout", "Agent Mail closeout evidence is missing"))
    if not mail_reservations_released:
        blockers.append(asw_blocker("mail-reservations-not-released", "file reservations are not released"))
    if not leases:
        blockers.append(asw_blocker("missing-lease-receipt", "lease or admission obligation evidence is missing"))
    for lease in leases:
        if lease["status"] not in ASW_READY_LEASE_STATUSES:
            blockers.append(
                asw_blocker("lease-not-committed", f"lease {lease['lease_id'] or lease['resource']} is {lease['status']}")
            )
    if not admission:
        blockers.append(asw_blocker("missing-admission-receipt", "admission receipt is missing"))
    elif admission_status not in ASW_READY_ADMISSION_STATUSES:
        blockers.append(asw_blocker("admission-not-admitted", f"admission status is {admission_status}"))
    if not handoff:
        blockers.append(asw_blocker("missing-handoff-capsule", "handoff capsule verifier evidence is missing"))
    elif handoff_decision not in ASW_READY_HANDOFF_DECISIONS:
        blockers.append(asw_blocker("handoff-blocked", f"handoff decision is {handoff_decision}"))
    if not commits:
        blockers.append(asw_blocker("missing-commit-proof", "commit evidence is missing"))
    for commit in commits:
        commit_id = commit["hash"] or "(unknown)"
        if not commit["pushed"] or not commit["main_ref_pushed"]:
            blockers.append(asw_blocker("unpushed-commit", f"commit {commit_id} is not pushed to main"))
        if commit["main_ref_pushed"] and not commit["main_mirror_pushed"]:
            blockers.append(asw_blocker("missing-main-mirror-sync", f"commit {commit_id} lacks main mirror evidence"))
    for proof in rch_proofs:
        if proof["local_fallback"]:
            blockers.append(
                asw_blocker(
                    "rch-local-fallback-proof",
                    "local fallback cannot satisfy release proof",
                    command=proof["command"],
                )
            )
        if proof["cargo_command"] and proof["routes_through_rch"] and not proof["has_cargo_target_dir"]:
            blockers.append(
                asw_blocker(
                    "missing-cargo-target-dir-proof",
                    "Cargo proof lacks explicit CARGO_TARGET_DIR",
                    command=proof["command"],
                )
            )
        if proof["cargo_command"] and proof["routes_through_rch"] and not proof["remote_required"]:
            blockers.append(
                asw_blocker(
                    "missing-remote-required-proof",
                    "Cargo proof lacks RCH_REQUIRE_REMOTE=1",
                    command=proof["command"],
                )
            )

    remote_production_passes = [proof for proof in rch_proofs if proof_is_remote_production_pass(proof)]
    if not remote_production_passes:
        blockers.append(asw_blocker("missing-remote-rch-proof", "no remote production Cargo proof passed"))

    blockers = sort_asw_blockers(blockers)
    proof_class_counts: dict[str, int] = {}
    for proof in rch_proofs:
        proof_class = proof["proof_class"]
        proof_class_counts[proof_class] = proof_class_counts.get(proof_class, 0) + 1

    packet = {
        "bead_id": as_string(row.get("bead_id") or bead.get("id")),
        "agent": as_string(row.get("agent") or row.get("owner")),
        "status": "ready" if not blockers else "blocked",
        "first_blocker": blockers[0] if blockers else None,
        "blockers": blockers,
        "reservations": reservations,
        "touched_paths": touched_paths,
        "dirty_peer_paths": dirty_peer_paths,
        "bead": {
            "status": bead_status,
            "updated_at": as_string(bead.get("updated_at")),
        },
        "mail": {
            "closeout_sent": mail_closeout_sent,
            "reservations_released": mail_reservations_released,
            "thread_id": as_string(mail.get("thread_id")),
        },
        "leases": leases,
        "admission": {
            "status": admission_status,
            "receipt_id": as_string(admission.get("receipt_id") or admission.get("id")),
        },
        "handoff": {
            "decision": handoff_decision,
            "capsule_id": as_string(handoff.get("capsule_id") or handoff.get("id")),
        },
        "commits": commits,
        "rch_proofs": rch_proofs,
        "evidence_counts": {
            "commits": len(commits),
            "leases": len(leases),
            "reservations": len(reservations),
            "touched_paths": len(touched_paths),
            "dirty_peer_paths": len(dirty_peer_paths),
            "remote_production_proofs": len(remote_production_passes),
            "proof_classes": proof_class_counts,
        },
    }
    return packet


def build_asw_release_proof(source: Any, counts: dict[str, int]) -> dict[str, Any] | None:
    packets = [
        normalize_asw_release_packet(row, counts)
        for row in rows_from(source, ("asw_release_proofs", "release_proofs"))
    ]
    if not packets:
        return None

    packets = sorted(packets, key=lambda packet: (packet["bead_id"], packet["agent"]))
    blocked_packets = [packet for packet in packets if packet["status"] == "blocked"]
    ready_packets = [packet for packet in packets if packet["status"] == "ready"]
    first_blocker = None
    if blocked_packets:
        first_packet = sorted(
            blocked_packets,
            key=lambda packet: (
                ASW_BLOCKER_ORDER.get(packet["first_blocker"]["kind"], 1000),
                packet["bead_id"],
                packet["agent"],
            ),
        )[0]
        first_blocker = {
            "bead_id": first_packet["bead_id"],
            "agent": first_packet["agent"],
            **first_packet["first_blocker"],
        }

    proof_class_counts: dict[str, int] = {}
    remote_production_proofs = 0
    for packet in packets:
        remote_production_proofs += packet["evidence_counts"]["remote_production_proofs"]
        for proof_class, count in packet["evidence_counts"]["proof_classes"].items():
            proof_class_counts[proof_class] = proof_class_counts.get(proof_class, 0) + count

    release_status = "ready" if not blocked_packets else "blocked"
    if first_blocker is None:
        human_summary = (
            f"ASW release proof ready: {len(ready_packets)}/{len(packets)} packet(s) ready; "
            f"{remote_production_proofs} remote production proof(s); main mirror evidence present."
        )
    else:
        human_summary = (
            f"ASW release proof blocked: {len(blocked_packets)}/{len(packets)} packet(s) blocked; "
            f"first blocker {first_blocker['kind']} for {first_blocker['bead_id']}; "
            f"{remote_production_proofs} remote production proof(s)."
        )

    return {
        "schema_version": ASW_RELEASE_SCHEMA_VERSION,
        "release_status": release_status,
        "packet_count": len(packets),
        "ready_count": len(ready_packets),
        "blocked_count": len(blocked_packets),
        "first_blocker": first_blocker,
        "proof_class_counts": proof_class_counts,
        "remote_production_proofs": remote_production_proofs,
        "human_summary": human_summary,
        "packets": packets,
    }


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

    receipt = {
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
    asw_release_proof = build_asw_release_proof(source, counts)
    if asw_release_proof is not None:
        receipt["asw_release_proof"] = asw_release_proof
        receipt["source_counts"]["asw_release_packets"] = asw_release_proof["packet_count"]
    return receipt


def render_summary(receipt: dict[str, Any]) -> str:
    asw_release_proof = receipt.get("asw_release_proof")
    if isinstance(asw_release_proof, dict):
        return as_string(asw_release_proof.get("human_summary"))
    return (
        f"proof receipt inventory: {receipt['source_counts']['helpers']} helper(s), "
        f"{receipt['source_counts']['review_cues']} review cue(s)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a proof receipt helper inventory")
    parser.add_argument("--fixture", required=True, help="Fixture JSON containing helpers or receipts rows")
    parser.add_argument("--repo-path", default=".", help="Repository path recorded in the receipt")
    parser.add_argument("--agent", default="", help="Agent producing the inventory receipt")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic receipts")
    parser.add_argument("--output", choices=["json", "summary"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    if args.output == "summary":
        print(render_summary(receipt))
    else:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
