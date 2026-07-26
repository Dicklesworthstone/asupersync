#!/usr/bin/env python3
"""CI matrix policy gate for lane coverage, thresholds, and artifacts.

This validator enforces that required CI lanes are represented in the workflow
with explicit job/step/artifact contracts and replay commands.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Any


JOB_ID_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
STEP_NAME_RE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$", re.MULTILINE)
RCH_EXEC_RE = re.compile(r'(?m)(?:\brch\b|"\$RCH_BIN"|\$\{RCH_BIN\}|\$RCH_BIN)\s+exec\s+--')
RCH_EXEC_COMMAND_RE = re.compile(
    r'(?m)(?:\brch\b|"\$RCH_BIN"|\$\{RCH_BIN\}|\$RCH_BIN)\s+exec\s+--\s+([^&;\n|]+)'
)
CARGO_WORD_RE = re.compile(r"\bcargo\b")
# The cargo binary is not always the literal token `cargo`: several proof/smoke
# runners invoke `"${CARGO_BIN:-cargo}"` so the binary can be overridden. Such a
# token still contains the word "cargo", so CARGO_WORD_RE admits the body for
# checking, but `tokens.index("cargo")` then fails and the invocation is
# misreported as rch_cargo_unparseable. Match the indirection forms explicitly.
CARGO_BINARY_TOKEN_RE = re.compile(
    r"^(?:cargo|\$(?:CARGO_BIN\b|\{CARGO_BIN(?::-[^}]*)?\}))$"
)


def is_cargo_binary_token(token: str) -> bool:
    return CARGO_BINARY_TOKEN_RE.match(token) is not None


def find_cargo_token_index(tokens: list[str]) -> int | None:
    for index, token in enumerate(tokens):
        if is_cargo_binary_token(token):
            return index
    return None
SHELL_COMMAND_SPLIT_RE = re.compile(r"(?:&&|\|\||;|\n)")
ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class PolicyError(ValueError):
    """Raised when the policy or inputs are malformed."""


@dataclass(frozen=True)
class LanePolicy:
    lane_id: str
    title: str
    owner: str
    required_job_ids: tuple[str, ...]
    required_step_names: tuple[str, ...]
    required_artifact_names: tuple[str, ...]
    replay_command: str
    require_rch: bool
    rch_required_step_names: tuple[str, ...]
    rch_forbidden_fallback_phrase: str
    failure_taxonomy: tuple[str, ...]
    max_failures: int
    required_artifacts_min: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=".github/ci_matrix_policy.json", type=Path)
    parser.add_argument("--workflow", type=Path, default=None)
    # Default must be None, not "": Path("") normalizes to Path("."), whose str()
    # is "." and therefore truthy, so an empty-string default silently wins over
    # the policy's output paths and the run dies writing a file onto the cwd.
    parser.add_argument("--summary-output", default=None, type=Path)
    parser.add_argument("--events-output", default=None, type=Path)
    parser.add_argument("--script-scan-root", default=None, type=Path)
    parser.add_argument("--script-scan-glob", default="*.sh")
    parser.add_argument("--skip-script-scan", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


ARRAY_ASSIGN_OPEN_RE = re.compile(
    r"^[ \t]*(?:(?:local|declare|typeset|readonly|export)[ \t]+(?:-[A-Za-z]+[ \t]+)*)?"
    r"[A-Za-z_][A-Za-z0-9_]*\+?=\([ \t]*$"
)
ARRAY_ASSIGN_LINE_RE = re.compile(
    r"^[ \t]*(?:(?:local|declare|typeset|readonly|export)[ \t]+(?:-[A-Za-z]+[ \t]+)*)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\+?=\((.*)\)[ \t]*$"
)
ARRAY_REF_RE = re.compile(r'"?\$\{([A-Za-z_][A-Za-z0-9_]*)\[[@*]\]\}"?')
MAX_EXPANSION_CHARS = 200_000


def fold_multiline_array_assignments(text: str) -> str:
    """Join `NAME=(\\n  elem\\n  elem\\n)` into a single logical line.

    Command arrays are the house style for routed cargo invocations here:

        cmd=(
            "$RCH_BIN" exec -- env
            "CARGO_TARGET_DIR=${bench_target_dir}"
            cargo bench --bench "$bench"
        )
        "${cmd[@]}"

    SHELL_COMMAND_SPLIT_RE splits on newlines, so the `cargo bench ...` element
    looks like a standalone command starting with `cargo` and is reported
    local_cargo, even though the composed command is correctly routed. Folding
    the array back into one line lets the existing checks see the real command.

    An array that is never closed is left exactly as-is, so a malformed script
    can never hide a bare cargo line behind an unterminated `(`.
    """
    lines = text.splitlines()
    folded: list[str] = []
    index = 0
    while index < len(lines):
        if not ARRAY_ASSIGN_OPEN_RE.match(lines[index]):
            folded.append(lines[index])
            index += 1
            continue
        block = [lines[index]]
        cursor = index + 1
        while cursor < len(lines):
            block.append(lines[cursor])
            if lines[cursor].strip().startswith(")"):
                break
            cursor += 1
        if cursor < len(lines):
            folded.append(" ".join(part.strip() for part in block if part.strip()))
            index = cursor + 1
        else:
            folded.extend(block)
            index = len(lines)
    return "\n".join(folded)


def collect_array_definitions(text: str) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for line in text.splitlines():
        match = ARRAY_ASSIGN_LINE_RE.match(line)
        if match:
            definitions.setdefault(match.group(1), match.group(2).strip())
    return definitions


def expand_array_references(text: str) -> str:
    """Substitute `"${NAME[@]}"` with NAME's definition, up to three levels.

    Detection then happens where the array is EXECUTED rather than where it is
    defined, which is what keeps the definition-vs-execution split honest:
    `CMD=(cargo build)` followed by `"${CMD[@]}"` still expands to a bare
    `cargo build` at the execution site and is still reported local_cargo.
    """
    definitions = collect_array_definitions(text)
    if not definitions:
        return text
    expanded = text
    for _ in range(3):
        replaced = ARRAY_REF_RE.sub(
            lambda match: definitions.get(match.group(1), match.group(0)), expanded
        )
        if replaced == expanded or len(replaced) > MAX_EXPANSION_CHARS:
            break
        expanded = replaced
    return expanded


def is_array_assignment(segment: str) -> bool:
    return ARRAY_ASSIGN_LINE_RE.match(segment.strip()) is not None


def normalize_shell_text(text: str) -> str:
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    return expand_array_references(fold_multiline_array_assignments(joined))


def truncate_at_unterminated_quote(text: str) -> str:
    """Cut `text` at the first quote that is opened and never closed.

    RCH_EXEC_COMMAND_RE captures everything up to a shell metacharacter or end of
    line, so an `rch exec --` command that is itself a quoted ARGUMENT overruns
    its own string literal:

        run_proof_lane "P1" "CRITICAL" "Native QUIC Conformance" \\
            'rch exec -- env CARGO_TARGET_DIR="..." cargo test --lib foo' \\
            600

    normalize_shell_text folds the continuation, so the captured body becomes
    `env CARGO_TARGET_DIR="..." cargo test --lib foo'  600` -- the stray quote is
    mid-body, not trailing, so rstrip cannot help and shlex raises "No closing
    quotation". The command is fully compliant; only the capture is ragged.

    An unterminated quote is exactly the point where the enclosing literal ended,
    so truncating there recovers the real command. Balanced quotes are left
    alone, and text with no unterminated quote is returned unchanged.
    """
    quote: str | None = None
    opened_at: int | None = None
    for index, char in enumerate(text):
        if quote is None:
            if char in "\"'":
                quote = char
                opened_at = index
        elif char == quote:
            quote = None
            opened_at = None
    if quote is not None and opened_at is not None:
        return text[:opened_at]
    return text


def shell_tokens(text: str) -> list[str]:
    # Fail-closed by construction: every candidate below only REMOVES trailing
    # continuation/quote characters or truncates at an unterminated quote. None
    # can introduce a leading `env` or a CARGO_TARGET_DIR= assignment, so a
    # genuinely non-compliant body such as `cargo fmt --check"` still tokenizes
    # to tokens[0] == "cargo" and is still flagged. Anything that fails to parse
    # after every candidate still yields [] -> rch_cargo_unparseable.
    stripped = text.strip()
    candidates = [
        text,
        text.rstrip('",\''),
        stripped.rstrip('",\''),
        stripped.rstrip("\\").strip().rstrip('",\''),
        truncate_at_unterminated_quote(stripped).strip(),
    ]
    for candidate in candidates:
        try:
            return shlex.split(candidate, posix=True)
        except ValueError:
            continue
    return []


def token_is_env_assignment(token: str) -> bool:
    return ENV_ASSIGNMENT_RE.match(token) is not None


def command_starts_with_local_cargo(command: str) -> bool:
    tokens = shell_tokens(command.strip())
    if not tokens:
        return False

    index = 0
    while index < len(tokens) and token_is_env_assignment(tokens[index]):
        index += 1

    if index < len(tokens) and tokens[index] == "env":
        index += 1
        while index < len(tokens) and token_is_env_assignment(tokens[index]):
            index += 1

    return index < len(tokens) and is_cargo_binary_token(tokens[index])


def has_local_cargo_command(text: str) -> bool:
    normalized = normalize_shell_text(text)
    return any(
        # An array assignment DEFINES a command, it does not run one. Skipping it
        # here is not a hole: expand_array_references has already inlined the
        # definition at every `"${NAME[@]}"` execution site, so an unrouted array
        # is still caught there. Checking it in both places would report
        # `CARGO_COMMAND=(cargo test ...)` as a local invocation even when the
        # only execution site wraps it in `rch exec -- env CARGO_TARGET_DIR=...`.
        not is_array_assignment(segment) and command_starts_with_local_cargo(segment)
        for segment in SHELL_COMMAND_SPLIT_RE.split(normalized)
    )


def rch_exec_cargo_violations(text: str) -> list[str]:
    normalized = normalize_shell_text(text)
    violations: list[str] = []
    for match in RCH_EXEC_COMMAND_RE.finditer(normalized):
        body = match.group(1).strip()
        if not CARGO_WORD_RE.search(body):
            continue

        tokens = shell_tokens(body)
        if not tokens:
            violations.append("rch_cargo_unparseable")
            continue

        if tokens[0] in {"bash", "sh"} and "-c" in tokens and any(CARGO_WORD_RE.search(token) for token in tokens):
            violations.append("rch_nested_shell_cargo")
            continue

        if is_cargo_binary_token(tokens[0]):
            violations.append("rch_cargo_missing_env")
            continue

        if tokens[0] != "env":
            violations.append("rch_cargo_unstructured")
            continue

        cargo_index = find_cargo_token_index(tokens)
        if cargo_index is None:
            violations.append("rch_cargo_unparseable")
            continue

        if not any(token.startswith("CARGO_TARGET_DIR=") for token in tokens[1:cargo_index]):
            violations.append("rch_cargo_missing_target_dir")

    return violations


def cargo_routing_violations(text: str) -> list[str]:
    violations = rch_exec_cargo_violations(text)
    if has_local_cargo_command(text):
        violations.append("local_cargo")
    return sorted(set(violations))


SCRIPT_ROUTING_EXCEPTION_CATEGORIES = {
    # A `printf`/heredoc that CONSTRUCTS a command string for display or repro
    # while the real execution is routed. Telling a command that is built from
    # one that is run needs shell dataflow this scan does not do.
    "command_builder_string",
    # A bare invocation reachable only behind an explicit, default-off opt-in
    # (ALLOW_LOCAL_CARGO=1, --local, ...). AGENTS.md permits a local run when the
    # operator explicitly authorizes one; the flag IS that authorization.
    "gated_local_opt_in",
    # Code that only executes ON the worker, inside an already-routed context --
    # e.g. a script that dispatches itself via `rch exec -- bash <self> __remote`.
    # Routing it again would be rch-inside-rch.
    "remote_reentrant_block",
}


def validate_script_routing_exceptions(policy: dict[str, Any]) -> list[dict[str, Any]]:
    raw = policy.get("script_routing_exceptions", [])
    if not isinstance(raw, list):
        raise PolicyError("script_routing_exceptions must be a list")
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        label = f"script_routing_exceptions[{index}]"
        if not isinstance(entry, dict):
            raise PolicyError(f"{label} must be an object")
        pattern = require_str(entry.get("pattern"), f"{label}.pattern")
        if pattern in seen:
            raise PolicyError(f"duplicate script_routing_exceptions pattern {pattern}")
        seen.add(pattern)
        category = require_str(entry.get("category"), f"{label}.category")
        if category not in SCRIPT_ROUTING_EXCEPTION_CATEGORIES:
            raise PolicyError(
                f"{label}.category {category!r} is not one of "
                f"{sorted(SCRIPT_ROUTING_EXCEPTION_CATEGORIES)}"
            )
        require_str(entry.get("owner"), f"{label}.owner")
        require_str(entry.get("reason"), f"{label}.reason")
        # Every entry must carry the exact violation kinds it excuses, so an
        # exception written for a display string cannot silently also excuse a
        # genuinely unrouted command that appears in the same file later.
        violations = entry.get("violations")
        if not isinstance(violations, list) or not violations:
            raise PolicyError(f"{label}.violations must be a non-empty list")
        for violation in violations:
            require_str(violation, f"{label}.violations[]")
        if not (
            isinstance(entry.get("expires_at_utc"), str)
            or isinstance(entry.get("revisit_condition"), str)
        ):
            raise PolicyError(
                f"{label} must include expires_at_utc or revisit_condition"
            )
    return raw


def script_routing_exception_expired(entry: dict[str, Any], now_utc: dt.datetime) -> bool:
    expiry = entry.get("expires_at_utc")
    if not isinstance(expiry, str):
        return False
    raw = expiry[:-1] + "+00:00" if expiry.endswith("Z") else expiry
    parsed = dt.datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise PolicyError(f"expires_at_utc must include a timezone: {expiry}")
    return parsed.astimezone(dt.timezone.utc) <= now_utc


def apply_script_routing_exceptions(
    reports: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
    now_utc: dt.datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split reports into still-violating and excused.

    An exception removes only the violation kinds it names, and only while it is
    unexpired. Anything it does not name stays a violation, so a file with a
    documented builder string still fails on a newly added unrouted command.
    """
    remaining: list[dict[str, Any]] = []
    excused: list[dict[str, Any]] = []
    for report in reports:
        path = report["path"]
        kinds = list(report["violations"])
        applied: list[dict[str, Any]] = []
        for entry in exceptions:
            if not fnmatch.fnmatch(path, entry["pattern"]):
                continue
            if script_routing_exception_expired(entry, now_utc):
                continue
            excused_kinds = [kind for kind in kinds if kind in entry["violations"]]
            if not excused_kinds:
                continue
            kinds = [kind for kind in kinds if kind not in entry["violations"]]
            applied.append(
                {
                    "pattern": entry["pattern"],
                    "category": entry["category"],
                    "owner": entry["owner"],
                    "reason": entry["reason"],
                    "expires_at_utc": entry.get("expires_at_utc", ""),
                    "revisit_condition": entry.get("revisit_condition", ""),
                    "violations": excused_kinds,
                }
            )
        if applied:
            excused.append({"path": path, "exceptions": applied})
        if kinds:
            remaining.append({"path": path, "violations": kinds})
    return remaining, excused


def collect_script_routing_violations(script_root: Path, script_glob: str) -> list[dict[str, Any]]:
    if not script_root.exists():
        return []

    reports: list[dict[str, Any]] = []
    for path in sorted(script_root.glob(script_glob)):
        if not path.is_file():
            continue
        violations = cargo_routing_violations(path.read_text(encoding="utf-8", errors="replace"))
        if violations:
            reports.append({"path": str(path), "violations": violations})
    return reports


def rch_replay_compliant(command: str) -> bool:
    return bool(RCH_EXEC_RE.search(command)) and not cargo_routing_violations(command)


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PolicyError(f"policy must be a JSON object: {path}")
    return payload


def require_str(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError(f"{label} must be a non-empty string")
    return raw


def require_int(raw: Any, label: str, minimum: int = 0) -> int:
    if not isinstance(raw, int) or raw < minimum:
        raise PolicyError(f"{label} must be an integer >= {minimum}")
    return raw


def require_str_list(raw: Any, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise PolicyError(f"{label} must be list[str] with non-empty entries")
    return tuple(raw)


def require_bool(raw: Any, label: str) -> bool:
    if not isinstance(raw, bool):
        raise PolicyError(f"{label} must be a boolean")
    return raw


def load_policy(policy_path: Path) -> tuple[dict[str, Any], list[LanePolicy], Path, Path]:
    policy = load_json(policy_path)
    if policy.get("schema_version") != "ci-matrix-policy-v1":
        raise PolicyError("unsupported or missing schema_version")

    output = policy.get("output")
    if not isinstance(output, dict):
        raise PolicyError("output must be an object")
    summary_path = Path(require_str(output.get("summary_path"), "output.summary_path"))
    events_path = Path(require_str(output.get("events_path"), "output.events_path"))

    defaults = policy.get("threshold_defaults", {})
    if not isinstance(defaults, dict):
        raise PolicyError("threshold_defaults must be an object")
    default_max_failures = require_int(defaults.get("max_failures", 0), "threshold_defaults.max_failures")
    default_artifacts_min = require_int(
        defaults.get("required_artifacts_min", 0), "threshold_defaults.required_artifacts_min"
    )
    rch_defaults = policy.get("rch_defaults", {})
    if not isinstance(rch_defaults, dict):
        raise PolicyError("rch_defaults must be an object")
    default_rch_forbidden_fallback_phrase = require_str(
        rch_defaults.get(
            "forbidden_fallback_phrase",
            rch_defaults.get("fallback_phrase", "falling back to local"),
        ),
        "rch_defaults.forbidden_fallback_phrase",
    )

    lanes_raw = policy.get("lanes")
    if not isinstance(lanes_raw, list) or not lanes_raw:
        raise PolicyError("lanes must be a non-empty list")

    lanes: list[LanePolicy] = []
    seen_ids: set[str] = set()
    for idx, lane_raw in enumerate(lanes_raw):
        if not isinstance(lane_raw, dict):
            raise PolicyError(f"lanes[{idx}] must be an object")
        lane_id = require_str(lane_raw.get("lane_id"), f"lanes[{idx}].lane_id")
        if lane_id in seen_ids:
            raise PolicyError(f"duplicate lane_id: {lane_id}")
        seen_ids.add(lane_id)

        thresholds = lane_raw.get("thresholds", {})
        if not isinstance(thresholds, dict):
            raise PolicyError(f"lanes[{idx}].thresholds must be an object")

        lanes.append(
            LanePolicy(
                lane_id=lane_id,
                title=require_str(lane_raw.get("title"), f"lanes[{idx}].title"),
                owner=require_str(lane_raw.get("owner"), f"lanes[{idx}].owner"),
                required_job_ids=require_str_list(
                    lane_raw.get("required_job_ids", []), f"lanes[{idx}].required_job_ids"
                ),
                required_step_names=require_str_list(
                    lane_raw.get("required_step_names", []), f"lanes[{idx}].required_step_names"
                ),
                required_artifact_names=require_str_list(
                    lane_raw.get("required_artifact_names", []), f"lanes[{idx}].required_artifact_names"
                ),
                replay_command=require_str(lane_raw.get("replay_command"), f"lanes[{idx}].replay_command"),
                require_rch=require_bool(lane_raw.get("require_rch", False), f"lanes[{idx}].require_rch"),
                rch_required_step_names=require_str_list(
                    lane_raw.get("rch_required_step_names", []), f"lanes[{idx}].rch_required_step_names"
                ),
                rch_forbidden_fallback_phrase=require_str(
                    lane_raw.get(
                        "rch_forbidden_fallback_phrase",
                        lane_raw.get("rch_fallback_phrase", default_rch_forbidden_fallback_phrase),
                    ),
                    f"lanes[{idx}].rch_forbidden_fallback_phrase",
                ),
                failure_taxonomy=require_str_list(
                    lane_raw.get("failure_taxonomy", []), f"lanes[{idx}].failure_taxonomy"
                ),
                max_failures=require_int(
                    thresholds.get("max_failures", default_max_failures),
                    f"lanes[{idx}].thresholds.max_failures",
                ),
                required_artifacts_min=require_int(
                    thresholds.get("required_artifacts_min", default_artifacts_min),
                    f"lanes[{idx}].thresholds.required_artifacts_min",
                ),
            )
        )

    return policy, lanes, summary_path, events_path


def collect_step_run_blocks(workflow_text: str) -> dict[str, list[str]]:
    step_runs: dict[str, list[str]] = {}
    lines = workflow_text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        step_match = re.match(r"^(\s*)-\s+name:\s*(.+?)\s*$", line)
        if not step_match:
            index += 1
            continue

        step_indent = len(step_match.group(1))
        step_name = step_match.group(2).strip()
        index += 1
        collected_runs: list[str] = []

        while index < len(lines):
            next_line = lines[index]
            next_indent = len(next_line) - len(next_line.lstrip(" "))
            if next_indent <= step_indent and re.match(r"^\s*-\s+name:\s*", next_line):
                break

            run_match = re.match(r"^\s*run:\s*(.*)$", next_line)
            if run_match:
                suffix = run_match.group(1)
                run_indent = next_indent
                if suffix and suffix != "|":
                    collected_runs.append(suffix.strip())
                    index += 1
                    continue

                index += 1
                run_lines: list[str] = []
                while index < len(lines):
                    body_line = lines[index]
                    body_indent = len(body_line) - len(body_line.lstrip(" "))
                    if body_line.strip() and body_indent <= run_indent:
                        break
                    if body_line.strip():
                        offset = min(len(body_line), run_indent + 2)
                        run_lines.append(body_line[offset:])
                    else:
                        run_lines.append("")
                    index += 1
                collected_runs.append("\n".join(run_lines))
                continue

            index += 1

        if collected_runs:
            step_runs.setdefault(step_name, []).extend(collected_runs)

    return step_runs


def collect_workflow_contracts(workflow_text: str) -> tuple[set[str], set[str], dict[str, list[str]]]:
    job_ids = {match.group(1).strip() for match in JOB_ID_RE.finditer(workflow_text)}
    step_names = {match.group(1).strip() for match in STEP_NAME_RE.finditer(workflow_text)}
    step_run_blocks = collect_step_run_blocks(workflow_text)
    return job_ids, step_names, step_run_blocks


def artifact_name_exists(workflow_text: str, artifact_name: str) -> bool:
    return f"name: {artifact_name}" in workflow_text


def evaluate_lane(
    lane: LanePolicy,
    workflow_text: str,
    job_ids: set[str],
    step_names: set[str],
    step_run_blocks: dict[str, list[str]],
) -> dict[str, Any]:
    missing_job_ids = sorted(job for job in lane.required_job_ids if job not in job_ids)
    missing_steps = sorted(step for step in lane.required_step_names if step not in step_names)
    missing_artifacts = sorted(
        artifact for artifact in lane.required_artifact_names if not artifact_name_exists(workflow_text, artifact)
    )
    missing_contracts = [
        *[f"job:{item}" for item in missing_job_ids],
        *[f"step:{item}" for item in missing_steps],
        *[f"artifact:{item}" for item in missing_artifacts],
    ]
    replay_routing_violations = cargo_routing_violations(lane.replay_command)
    rch_compliant = rch_replay_compliant(lane.replay_command)
    if lane.require_rch and not RCH_EXEC_RE.search(lane.replay_command):
        missing_contracts.append("replay:rch_prefix")
    if lane.require_rch:
        missing_contracts.extend(f"replay:{violation}" for violation in replay_routing_violations)

    artifact_contract_count = len(lane.required_artifact_names) - len(missing_artifacts)
    if artifact_contract_count < lane.required_artifacts_min:
        missing_contracts.append(
            f"threshold:required_artifacts_min({artifact_contract_count}<{lane.required_artifacts_min})"
        )

    rch_noncompliant_steps: list[str] = []
    rch_local_fallback_steps: list[str] = []
    for step_name in lane.rch_required_step_names:
        if step_name not in step_names:
            continue
        step_runs = step_run_blocks.get(step_name, [])
        if not any(RCH_EXEC_RE.search(script) for script in step_runs):
            rch_noncompliant_steps.append(step_name)
            missing_contracts.append(f"step_rch:{step_name}")
        step_routing_violations = sorted(
            {
                violation
                for script in step_runs
                for violation in cargo_routing_violations(script)
            }
        )
        if step_routing_violations:
            if step_name not in rch_noncompliant_steps:
                rch_noncompliant_steps.append(step_name)
            missing_contracts.extend(
                f"step_{violation}:{step_name}" for violation in step_routing_violations
            )
        if any(lane.rch_forbidden_fallback_phrase in script for script in step_runs):
            rch_local_fallback_steps.append(step_name)
            missing_contracts.append(f"step_local_fallback:{step_name}")

    status = "pass" if not missing_contracts else "fail"
    return {
        "lane_id": lane.lane_id,
        "title": lane.title,
        "owner": lane.owner,
        "status": status,
        "required_job_ids": list(lane.required_job_ids),
        "required_step_names": list(lane.required_step_names),
        "required_artifact_names": list(lane.required_artifact_names),
        "require_rch": lane.require_rch,
        "rch_required_step_names": list(lane.rch_required_step_names),
        "rch_noncompliant_step_names": rch_noncompliant_steps,
        "rch_local_fallback_step_names": rch_local_fallback_steps,
        "replay_routing_violations": replay_routing_violations,
        "rch_compliant": rch_compliant,
        "missing_job_ids": missing_job_ids,
        "missing_steps": missing_steps,
        "missing_artifacts": missing_artifacts,
        "artifact_contract_count": artifact_contract_count,
        "missing_contracts": missing_contracts,
        "replay_command": lane.replay_command,
        "failure_taxonomy": list(lane.failure_taxonomy),
        "thresholds": {
            "max_failures": lane.max_failures,
            "required_artifacts_min": lane.required_artifacts_min,
        },
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_ndjson(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def run_self_tests() -> int:
    sample_policy = {
        "schema_version": "ci-matrix-policy-v1",
        "output": {"summary_path": "artifacts/a.json", "events_path": "artifacts/b.ndjson"},
        "threshold_defaults": {"max_failures": 0, "required_artifacts_min": 0},
        "lanes": [
            {
                "lane_id": "unit",
                "title": "Unit lane",
                "owner": "runtime-core",
                "required_job_ids": ["test"],
                "required_step_names": ["Run unit tests"],
                "required_artifact_names": ["ci-summary-report"],
                "replay_command": (
                    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest "
                    "cargo test --lib --all-features"
                ),
                "require_rch": True,
                "rch_required_step_names": ["Run unit tests"],
                "failure_taxonomy": ["unit_assertion_failure"],
                "thresholds": {"max_failures": 0, "required_artifacts_min": 1},
            }
        ],
    }
    policy_path = Path("/tmp/ci_matrix_policy_selftest.json")
    policy_path.write_text(json.dumps(sample_policy), encoding="utf-8")
    _, lanes, _, _ = load_policy(policy_path)

    workflow_pass = """
jobs:
  test:
    steps:
      - name: Run unit tests
        run: |
          if [[ ! -x "$RCH_BIN" ]]; then
            echo "rch is required for unit tests" >&2
            exit 1
          fi
          "$RCH_BIN" exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest cargo test --lib --all-features
  ci-summary-d5:
    steps:
      - name: Upload
        with:
          name: ci-summary-report
"""
    jobs_pass, steps_pass, step_runs_pass = collect_workflow_contracts(workflow_pass)
    lane_pass = evaluate_lane(lanes[0], workflow_pass, jobs_pass, steps_pass, step_runs_pass)
    if lane_pass["status"] != "pass":
        raise AssertionError("expected pass lane status")

    cargo_bin_lane = LanePolicy(
        lane_id="unit-cargo-bin",
        title="Unit lane with configurable cargo binary",
        owner="runtime-core",
        required_job_ids=("test",),
        required_step_names=("Run unit tests",),
        required_artifact_names=("ci-summary-report",),
        replay_command=(
            'rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest "$CARGO_BIN" '
            "test --lib --all-features"
        ),
        require_rch=True,
        rch_required_step_names=("Run unit tests",),
        rch_forbidden_fallback_phrase="falling back to local",
        failure_taxonomy=("unit_assertion_failure",),
        max_failures=0,
        required_artifacts_min=1,
    )
    workflow_cargo_bin_pass = """
jobs:
  test:
    steps:
      - name: Run unit tests
        run: |
          "$RCH_BIN" exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest "$CARGO_BIN" test --lib --all-features
  ci-summary-d5:
    steps:
      - name: Upload
        with:
          name: ci-summary-report
"""
    jobs_cargo_bin, steps_cargo_bin, step_runs_cargo_bin = collect_workflow_contracts(workflow_cargo_bin_pass)
    lane_cargo_bin = evaluate_lane(
        cargo_bin_lane,
        workflow_cargo_bin_pass,
        jobs_cargo_bin,
        steps_cargo_bin,
        step_runs_cargo_bin,
    )
    if lane_cargo_bin["status"] != "pass":
        raise AssertionError("expected pass lane status for rch-routed CARGO_BIN replay")

    script_selftest_dir = policy_path.parent / "ci_matrix_policy_script_selftest"
    script_selftest_dir.mkdir(parents=True, exist_ok=True)
    (script_selftest_dir / "route_good.sh").write_text(
        "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest cargo test --lib\n",
        encoding="utf-8",
    )
    (script_selftest_dir / "route_bad.sh").write_text("cargo test --lib\n", encoding="utf-8")
    script_reports = collect_script_routing_violations(script_selftest_dir, "route_*.sh")
    script_report_by_name = {Path(report["path"]).name: report for report in script_reports}
    if "route_good.sh" in script_report_by_name:
        raise AssertionError("expected rch-routed script scan fixture to pass")
    if script_report_by_name.get("route_bad.sh", {}).get("violations") != ["local_cargo"]:
        raise AssertionError("expected script scan fixture to report local_cargo")

    workflow_fail = """
jobs:
  docs:
    steps:
      - name: Build documentation
"""
    jobs_fail, steps_fail, step_runs_fail = collect_workflow_contracts(workflow_fail)
    lane_fail = evaluate_lane(lanes[0], workflow_fail, jobs_fail, steps_fail, step_runs_fail)
    if lane_fail["status"] != "fail":
        raise AssertionError("expected fail lane status")
    if "job:test" not in lane_fail["missing_contracts"]:
        raise AssertionError("expected missing required job")
    if "step:Run unit tests" not in lane_fail["missing_contracts"]:
        raise AssertionError("expected missing required step")
    if "artifact:ci-summary-report" not in lane_fail["missing_contracts"]:
        raise AssertionError("expected missing artifact contract")

    non_rch_lane = LanePolicy(
        lane_id="unit-no-rch",
        title="Unit lane without rch",
        owner="runtime-core",
        required_job_ids=("test",),
        required_step_names=("Run unit tests",),
        required_artifact_names=("ci-summary-report",),
        replay_command="cargo test --lib --all-features",
        require_rch=True,
        rch_required_step_names=("Run unit tests",),
        rch_forbidden_fallback_phrase="falling back to local",
        failure_taxonomy=("unit_assertion_failure",),
        max_failures=0,
        required_artifacts_min=1,
    )
    lane_non_rch = evaluate_lane(non_rch_lane, workflow_pass, jobs_pass, steps_pass, step_runs_pass)
    if lane_non_rch["status"] != "fail":
        raise AssertionError("expected fail lane status when require_rch is true but replay command is non-rch")
    if "replay:rch_prefix" not in lane_non_rch["missing_contracts"]:
        raise AssertionError("expected replay:rch_prefix contract failure")

    bare_rch_lane = LanePolicy(
        lane_id="unit-bare-rch",
        title="Unit lane with bare rch cargo",
        owner="runtime-core",
        required_job_ids=("test",),
        required_step_names=("Run unit tests",),
        required_artifact_names=("ci-summary-report",),
        replay_command="rch exec -- cargo test --lib --all-features",
        require_rch=True,
        rch_required_step_names=("Run unit tests",),
        rch_forbidden_fallback_phrase="falling back to local",
        failure_taxonomy=("unit_assertion_failure",),
        max_failures=0,
        required_artifacts_min=1,
    )
    lane_bare_rch = evaluate_lane(bare_rch_lane, workflow_pass, jobs_pass, steps_pass, step_runs_pass)
    if lane_bare_rch["status"] != "fail":
        raise AssertionError("expected fail lane status when replay command uses bare rch cargo")
    if "replay:rch_cargo_missing_env" not in lane_bare_rch["missing_contracts"]:
        raise AssertionError("expected replay:rch_cargo_missing_env contract failure")

    workflow_step_fail = """
jobs:
  test:
    steps:
      - name: Run unit tests
        run: cargo test --lib --all-features
"""
    jobs_step, steps_step, step_runs_step = collect_workflow_contracts(workflow_step_fail)
    lane_step_fail = evaluate_lane(lanes[0], workflow_step_fail, jobs_step, steps_step, step_runs_step)
    if lane_step_fail["status"] != "fail":
        raise AssertionError("expected fail lane status when required step lacks rch and runs local cargo")
    if "step_rch:Run unit tests" not in lane_step_fail["missing_contracts"]:
        raise AssertionError("expected step_rch failure for required step")
    if "step_local_cargo:Run unit tests" not in lane_step_fail["missing_contracts"]:
        raise AssertionError("expected step_local_cargo failure for required step")

    workflow_local_fallback_fail = """
jobs:
  test:
    steps:
      - name: Run unit tests
        run: |
          if [[ -x "$RCH_BIN" ]]; then
            "$RCH_BIN" exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest cargo test --lib --all-features
          else
            echo "rch unavailable; falling back to local cargo test --lib --all-features"
            cargo test --lib --all-features
          fi
"""
    jobs_fallback, steps_fallback, step_runs_fallback = collect_workflow_contracts(workflow_local_fallback_fail)
    lane_fallback_fail = evaluate_lane(lanes[0], workflow_local_fallback_fail, jobs_fallback, steps_fallback, step_runs_fallback)
    if lane_fallback_fail["status"] != "fail":
        raise AssertionError("expected fail lane status when required step falls back to local cargo")
    if "step_local_fallback:Run unit tests" not in lane_fallback_fail["missing_contracts"]:
        raise AssertionError("expected step_local_fallback failure for required step")

    artifact_threshold_lane = LanePolicy(
        lane_id="artifact-threshold",
        title="Artifact threshold lane",
        owner="runtime-core",
        required_job_ids=("test",),
        required_step_names=("Run unit tests",),
        required_artifact_names=(),
        replay_command="rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_ci_policy_selftest cargo test --lib --all-features",
        require_rch=True,
        rch_required_step_names=("Run unit tests",),
        rch_forbidden_fallback_phrase="falling back to local",
        failure_taxonomy=("artifact_contract_failure",),
        max_failures=0,
        required_artifacts_min=1,
    )
    artifact_threshold_report = evaluate_lane(
        artifact_threshold_lane,
        workflow_pass,
        jobs_pass,
        steps_pass,
        step_runs_pass,
    )
    if artifact_threshold_report["status"] != "fail":
        raise AssertionError("expected fail lane status when artifact threshold is unmet")
    if not any(
        item.startswith("threshold:required_artifacts_min")
        for item in artifact_threshold_report["missing_contracts"]
    ):
        raise AssertionError("expected required_artifacts_min threshold failure")

    # Shell-shape fixtures for the routing scan (br-asupersync-t440nm). Each
    # "must flag" case pins a way the scan could silently fail OPEN; each "must
    # be clean" case pins a false positive that previously made the gate cry
    # wolf. Keep both halves: a routing gate that reports compliant commands is
    # as useless as one that misses violations, just in the other direction.
    routing_must_flag = [
        # A command array that is never routed, executed via "${CMD[@]}".
        ('CMD=(\n    cargo build --release\n)\n"${CMD[@]}"\n', "local_cargo"),
        # Routed, but `cargo` sits directly after `rch exec --` with no env.
        ('CMD=(\n    "$RCH_BIN" exec --\n    cargo test\n)\n"${CMD[@]}"\n', "rch_cargo_missing_env"),
        # Routed through env, but without the mandatory CARGO_TARGET_DIR.
        ('CMD=(\n    "$RCH_BIN" exec -- env FOO=1\n    cargo test\n)\n"${CMD[@]}"\n', "rch_cargo_missing_target_dir"),
        # Same three shapes with the overridable binary spelling.
        ('rch exec -- "${CARGO_BIN:-cargo}" test\n', "rch_cargo_missing_env"),
        ('env CARGO_TARGET_DIR=/t/x "${CARGO_BIN:-cargo}" bench\n', "local_cargo"),
        # An unterminated array must not swallow the bare cargo line after it.
        ("CMD=(\n    cargo build --release\n", "local_cargo"),
        # A plain local invocation, the base case.
        ("cargo bench --bench x\n", "local_cargo"),
    ]
    for source, expected in routing_must_flag:
        found = cargo_routing_violations(source)
        if expected not in found:
            raise AssertionError(
                f"routing scan failed open: expected {expected} in {found} for {source!r}"
            )

    routing_must_be_clean = [
        # Multi-line command array, correctly routed. SHELL_COMMAND_SPLIT_RE
        # splits on newlines, so without array folding the `cargo` element looks
        # like a standalone local command.
        'CMD=(\n    "$RCH_BIN" exec -- env\n    "CARGO_TARGET_DIR=/t/x"\n    cargo bench --bench y\n)\n"${CMD[@]}"\n',
        # Composed arrays: the cargo array is inlined into a routed wrapper.
        'CARGO_COMMAND=(\n    cargo test -p asupersync\n)\n'
        'RCH_COMMAND=(\n    "${RCH_BIN}" exec -- env "CARGO_TARGET_DIR=/t/x" "${CARGO_COMMAND[@]}"\n)\n'
        'timeout 60 "${RCH_COMMAND[@]}"\n',
        # The overridable binary spelling, correctly routed.
        'CMD=(\n    "$RCH_BIN" exec -- env\n    "CARGO_TARGET_DIR=/t/x"\n    "${CARGO_BIN:-cargo}" test -p asupersync\n)\n"${CMD[@]}"\n',
        # An `rch exec --` command passed as a quoted ARGUMENT: the capture runs
        # past the closing quote, so the body must be truncated at the
        # unterminated quote instead of being called unparseable.
        "run_proof_lane \"P1\" \"CRITICAL\" \"Native QUIC\" \\\n"
        "    'rch exec -- env CARGO_TARGET_DIR=\"/t/x\" cargo test --lib foo' \\\n"
        "    600\n",
    ]
    for source in routing_must_be_clean:
        found = cargo_routing_violations(source)
        if found:
            raise AssertionError(
                f"routing scan false positive: expected clean, got {found} for {source!r}"
            )

    # Script-routing exception fixtures (br-asupersync-gjn12m). An exception
    # mechanism is only worth having if it cannot quietly grow into a blanket
    # waiver, so pin the ways it must REFUSE to excuse.
    now = dt.datetime.now(dt.timezone.utc)
    base_exception = {
        "pattern": "*scripts/route_bad.sh",
        "category": "command_builder_string",
        "owner": "runtime-core",
        "reason": "fixture",
        "revisit_condition": "fixture",
        "violations": ["local_cargo"],
    }
    reports = [{"path": "scripts/route_bad.sh", "violations": ["local_cargo"]}]

    remaining, excused = apply_script_routing_exceptions(reports, [base_exception], now)
    if remaining or len(excused) != 1:
        raise AssertionError("expected the matching exception to excuse the violation")

    # Only the NAMED violation kinds are excused; anything else still fails.
    mixed = [{"path": "scripts/route_bad.sh", "violations": ["local_cargo", "rch_cargo_missing_env"]}]
    remaining, _ = apply_script_routing_exceptions(mixed, [base_exception], now)
    if remaining != [{"path": "scripts/route_bad.sh", "violations": ["rch_cargo_missing_env"]}]:
        raise AssertionError("exception must not excuse violation kinds it does not name")

    # An expired exception excuses nothing.
    expired = dict(base_exception, expires_at_utc="2000-01-01T00:00:00Z")
    remaining, excused = apply_script_routing_exceptions(reports, [expired], now)
    if not remaining or excused:
        raise AssertionError("expired exception must not excuse")

    # A non-matching pattern excuses nothing.
    other = dict(base_exception, pattern="*scripts/route_other.sh")
    remaining, _ = apply_script_routing_exceptions(reports, [other], now)
    if not remaining:
        raise AssertionError("non-matching exception must not excuse")

    # Malformed entries fail closed at load time rather than silently excusing.
    for broken, label in [
        ({**base_exception, "violations": []}, "empty violations"),
        ({k: v for k, v in base_exception.items() if k != "reason"}, "missing reason"),
        ({k: v for k, v in base_exception.items() if k != "owner"}, "missing owner"),
        ({**base_exception, "category": "not_a_category"}, "unknown category"),
        (
            {k: v for k, v in base_exception.items() if k != "revisit_condition"},
            "no expiry and no revisit condition",
        ),
    ]:
        try:
            validate_script_routing_exceptions({"script_routing_exceptions": [broken]})
        except PolicyError:
            pass
        else:
            raise AssertionError(f"malformed exception accepted: {label}")

    # Duplicate patterns are rejected so two entries cannot disagree silently.
    try:
        validate_script_routing_exceptions(
            {"script_routing_exceptions": [base_exception, dict(base_exception)]}
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("duplicate exception patterns accepted")

    print("CI matrix policy self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_tests()

    policy_path = args.policy
    policy, lanes, default_summary_path, default_events_path = load_policy(policy_path)
    script_scan_root = args.script_scan_root if args.script_scan_root is not None else policy_path.parent.parent / "scripts"
    script_routing_exceptions = validate_script_routing_exceptions(policy)
    script_routing_excused: list[dict[str, Any]] = []
    script_routing_violations = (
        []
        if args.skip_script_scan
        else collect_script_routing_violations(script_scan_root, args.script_scan_glob)
    )
    if script_routing_violations:
        script_routing_violations, script_routing_excused = apply_script_routing_exceptions(
            script_routing_violations,
            script_routing_exceptions,
            dt.datetime.now(dt.timezone.utc),
        )

    workflow_path = args.workflow or Path(require_str(policy.get("workflow_path"), "workflow_path"))
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow_sha256 = sha256_text(workflow_text)
    job_ids, step_names, step_run_blocks = collect_workflow_contracts(workflow_text)

    lane_reports = [
        evaluate_lane(lane, workflow_text, job_ids, step_names, step_run_blocks) for lane in lanes
    ]
    failing_lane_ids = [lane["lane_id"] for lane in lane_reports if lane["status"] != "pass"]
    overall_status = "pass" if not failing_lane_ids and not script_routing_violations else "fail"
    rch_required_lane_count = sum(1 for lane in lane_reports if lane.get("require_rch") is True)
    rch_noncompliant_lane_ids = [
        lane["lane_id"]
        for lane in lane_reports
        if lane.get("require_rch") is True and lane.get("rch_compliant") is not True
    ]
    rch_noncompliant_step_refs = sorted(
        f"{lane['lane_id']}::{step_name}"
        for lane in lane_reports
        for step_name in lane.get("rch_noncompliant_step_names", [])
    )
    rch_local_fallback_step_refs = sorted(
        f"{lane['lane_id']}::{step_name}"
        for lane in lane_reports
        for step_name in lane.get("rch_local_fallback_step_names", [])
    )

    summary_path = args.summary_output if args.summary_output is not None else default_summary_path
    events_path = args.events_output if args.events_output is not None else default_events_path

    summary = {
        "schema_version": "ci-matrix-policy-report-v1",
        "generated_at": utc_now(),
        "policy_id": policy.get("policy_id"),
        "policy_path": str(policy_path),
        "workflow_path": str(workflow_path),
        "workflow_sha256": workflow_sha256,
        "status": overall_status,
        "lane_count": len(lane_reports),
        "failing_lane_count": len(failing_lane_ids),
        "failing_lane_ids": failing_lane_ids,
        "rch_required_lane_count": rch_required_lane_count,
        "rch_noncompliant_lane_count": len(rch_noncompliant_lane_ids),
        "rch_noncompliant_lane_ids": rch_noncompliant_lane_ids,
        "rch_noncompliant_step_count": len(rch_noncompliant_step_refs),
        "rch_noncompliant_step_refs": rch_noncompliant_step_refs,
        "rch_local_fallback_step_count": len(rch_local_fallback_step_refs),
        "rch_local_fallback_step_refs": rch_local_fallback_step_refs,
        "rch_missing_fallback_step_count": 0,
        "rch_missing_fallback_step_refs": [],
        "script_scan": {
            "enabled": not args.skip_script_scan,
            "root": str(script_scan_root),
            "glob": args.script_scan_glob,
            "violating_path_count": len(script_routing_violations),
            "violations": script_routing_violations,
            # Excused paths are reported, never hidden: an exception that stops
            # being visible is an exception nobody revisits.
            "excused_path_count": len(script_routing_excused),
            "excused": script_routing_excused,
        },
        "lanes": lane_reports,
    }

    events: list[dict[str, Any]] = []
    for lane in lane_reports:
        events.append(
            {
                "schema_version": "ci-matrix-policy-event-v1",
                "generated_at": summary["generated_at"],
                "lane_id": lane["lane_id"],
                "owner": lane["owner"],
                "status": lane["status"],
                "missing_contracts": lane["missing_contracts"],
                "replay_command": lane["replay_command"],
                "replay_routing_violations": lane["replay_routing_violations"],
                "require_rch": lane["require_rch"],
                "rch_compliant": lane["rch_compliant"],
                "failure_taxonomy": lane["failure_taxonomy"],
            }
        )
    for report in script_routing_violations:
        events.append(
            {
                "schema_version": "ci-matrix-policy-script-event-v1",
                "generated_at": summary["generated_at"],
                "path": report["path"],
                "status": "fail",
                "routing_violations": report["violations"],
            }
        )

    write_json(summary_path, summary)
    write_ndjson(events_path, events)
    print(f"CI matrix summary: {summary_path}")
    print(f"CI matrix events: {events_path}")

    if overall_status != "pass":
        for lane in lane_reports:
            if lane["status"] != "pass":
                missing = ", ".join(lane["missing_contracts"])
                print(f"CI matrix lane failed: {lane['lane_id']} [{missing}]")
        for report in script_routing_violations:
            violations = ", ".join(report["violations"])
            print(f"CI matrix script failed: {report['path']} [{violations}]")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
