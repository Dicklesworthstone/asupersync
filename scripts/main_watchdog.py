#!/usr/bin/env python3
"""Main watchdog: verify every new `origin/main` commit through RCH (asupersync-bi2462.147).

GitHub Actions is disabled for this repository and web/API commits bypass the
local pre-push hook, so nothing checks what lands on main. This helper is the
detection half of that gap: it is an agent-run loop, not enforcement. It never
reverts, edits, or pushes anyone's code.

Modes:
  plan      List commits since the last covered SHA (or --since), with per-commit
            flags and the lanes and targeted tests a batch needs. Read-only git.
  run       Execute the plan's lanes through `rch exec --base <sha> --clean-overlay
            --no-overlay`, classify each log fail-closed, bisect a new red to its
            first commit, append receipts, and (with --file-beads) file one P0 bead
            per new red signature. State lives outside the repository.
  evaluate  Run the same engine against a JSON scenario of commits and raw lane
            logs. Nothing is executed and no bead is filed; bead payloads are
            printed. This is the dry-run the planted-red acceptance check uses.
  summary   Daily summary and exit metrics from receipts, git, and the tracker.

A lane is green only when the remote exit is 0, cargo reached `Finished`, nothing
failed to compile, and (for test lanes) every expected target ran at least one
test and none failed. Admission refusals, RCH false greens (E412/E504), missing
remote exits, and zero-test runs are never green.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = "main-watchdog-v1"
WATCHDOG_BEAD = "asupersync-bi2462.147"
DEFAULT_STATE_DIR = Path(os.environ.get("RCH_TARGET_BASE", "/data/tmp")) / "asupersync_main_watchdog"
WEB_API_IDENTITY_SUFFIX = "@users.noreply.github.com"

VERDICT_GREEN = "green"
VERDICT_RED = "red"
VERDICT_DEFERRED = "deferred"  # admission refused; retry later
VERDICT_NO_EVIDENCE = "no-evidence"  # ran, but proves nothing (false green, zero tests, no exit)

FLAMEGRAPH_DIRS = ("src/runtime/scheduler/", "src/channel/", "src/obligation/", "src/cancel/", "src/sync/")
PROOF_NOTE_DIRS = ("src/obligation/", "src/safety/")
MAX_LIB_FILTERS = 40

# Self-declared absence of compilation or execution, as web/API commits phrase it
# ("Tests have NOT been compiled or executed", "compilation and Rust tests have NOT
# run", "Rust/Cargo/RCH are unavailable", "rch not found, exit 127"). A commit that
# merely describes someone else's code as "never compiled" must not match.
NOT_COMPILED_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\b(?:not|none)\s+(?:been\s+|yet\s+)?(?:compiled|executed|run)\s+(?:or|nor|and)\s+(?:compiled|executed|run|tested)\b",
        r"\b(?:compilation|tests?)\b[^.\n]{0,80}\b(?:have|has)\s+not\s+(?:been\s+)?run\b",
        r"\b(?:compilation|tests?|rustfmt)\b[^.\n]{0,80}\b(?:are|is|were|was)\s+not\s+run\b",
        r"\bremains?\s+not\s+run\b",
        r"\b(?:was|were|is|are|been)\s+not\s+(?:yet\s+)?(?:compiled|executed)\b",
        r"\b(?:rust|cargo|rustc|rch)\b[^.\n]{0,40}\b(?:are|is)\s+(?:absent|unavailable)\b",
        r"\brch\s+not\s+found\b",
        r"\bnot\s+(?:rust\s+)?execution(?:\s+evidence)?\b",
        r"\b(?:compilation|execution|compiler|tests?)\b[^.\n]{0,60}\bremains?\s+unverified\b",
        r"\bnot\s+executed\s+proof\b",
        r"\bno\s+compilation\b",
    )
]
BEAD_ID_RE = re.compile(r"\b(?:br-)?asupersync-[a-z0-9]+(?:[.-][a-z0-9]+)*\b|\bbr-[a-z0-9]+(?:[.-][a-z0-9]+)*\b")
WORKSPACE_CRATES = {
    "asupersync-macros",
    "asupersync-conformance",
    "asupersync-browser-core",
    "asupersync-tokio-compat",
    "asupersync-wasm",
}
UNSAFE_BLOCK_RE = re.compile(r"\bunsafe\s*\{")
FILE_CFG_RE = re.compile(r"^\s*#!\[cfg\((.*)\)\]\s*$")
FEATURE_RE = re.compile(r'feature\s*=\s*"([^"]+)"')
REMOTE_EXIT_RE = re.compile(r"Remote command finished: exit=(\d+)")
WORKER_RE = re.compile(r"Selected worker: (\S+)")
NATIVE_ONLY_GUARD_RE = re.compile(r'not\(\s*target_arch\s*=\s*"wasm32"\s*\)|\bunix\b')
TEST_RESULT_RE = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
)
RUNNING_TARGET_RE = re.compile(r"^\s*Running (?:tests|benches|examples)/([A-Za-z0-9_\-/]+)\.rs\b")
RUNNING_UNITTESTS_RE = re.compile(r"^\s*Running unittests (\S+)")
COULD_NOT_COMPILE_RE = re.compile(r"error: could not compile `([^`]+)`(?: \(([^)]*)\))?")
FIRST_ERROR_RE = re.compile(r"^(?:\S+\.rs:\d+:\d+: error(?:\[E\d+\])?:.*|error(?:\[E\d+\])?: (?!could not compile|aborting).*)$")
FAILED_TEST_RE = re.compile(r"^test (\S+) \.\.\. FAILED$")
NO_TARGET_RE = re.compile(r"error: no (?:test|bin|example|bench) target named `([^`]+)`")
COMPILE_TARGET_RE = re.compile(r'\((?:test|bin|example|bench) "([^"]+)"\)')
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ---------------------------------------------------------------------------
# Pure helpers (exercised by tests/main_watchdog_contract.rs through `evaluate`)
# ---------------------------------------------------------------------------


QUOTED_RE = re.compile(r'"[^"\n]*"|`[^`\n]*`')


def declares_not_compiled(message: str) -> bool:
    """True when a commit message declares its own change was not compiled or executed.

    Quoted text is ignored: a message that quotes another commit's declaration
    (for example to describe the predicate itself) is not declaring anything.
    """
    unquoted = QUOTED_RE.sub(" ", message)
    return any(p.search(unquoted) for p in NOT_COMPILED_PATTERNS)


def bead_ids(message: str, known: set[str] | None = None) -> list[str]:
    """Bead ids a commit message cites, normalized to `asupersync-...`.

    Workspace crate names are not bead ids. When the tracker's ids are known, only
    real ids count, so a hyphenated word cannot pass for a citation.
    """
    ids = set()
    for raw in BEAD_ID_RE.findall(message):
        bead = raw.removeprefix("br-")
        if not bead.startswith("asupersync-"):
            bead = "asupersync-" + bead
        bead = bead.rstrip(".")
        if bead in WORKSPACE_CRATES:
            continue
        if known is not None and bead not in known:
            continue
        ids.add(bead)
    return sorted(ids)


def tracker_ids(issues_path: Path = Path(".beads/issues.jsonl")) -> set[str] | None:
    try:
        text = issues_path.read_text()
    except FileNotFoundError:
        return None
    ids = set()
    for line in text.splitlines():
        try:
            ids.add(json.loads(line)["id"])
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return ids


def is_code_path(path: str) -> bool:
    """Rust sources, manifests, lockfiles and build scripts anywhere in the workspace."""
    return path.endswith(".rs") or Path(path).name in ("Cargo.toml", "Cargo.lock")


def is_web_api_identity(email: str) -> bool:
    return email.lower().endswith(WEB_API_IDENTITY_SUFFIX)


def file_cfg_features(source: str) -> tuple[list[str], bool]:
    """Features a test file's crate-level `#![cfg(...)]` requires.

    Returns (features, understood). Only `feature = "x"` and `all(...)` of those
    are understood; anything else (not/any/target) is reported as not understood
    so the caller can mark the mapping instead of guessing.
    """
    features: list[str] = []
    understood = True
    for line in source.splitlines()[:40]:
        match = FILE_CFG_RE.match(line)
        if not match:
            continue
        # Native-only guards hold on the Linux fleet; what remains must be a
        # conjunction of `feature = "..."` terms to be understood.
        expr = NATIVE_ONLY_GUARD_RE.sub("", match.group(1))
        residue = FEATURE_RE.sub("", expr)
        residue = re.sub(r"\ball\(|[(),\s]", "", residue)
        if residue:
            understood = False
            continue
        features.extend(FEATURE_RE.findall(expr))
    return sorted(set(features)), understood


def lib_filter_for(path: str) -> str | None:
    """`src/a/b/c.rs` -> `a::b::c`; `src/a/b/mod.rs` -> `a::b`; roots and bins -> None."""
    if not path.startswith("src/") or not path.endswith(".rs"):
        return None
    rel = path[len("src/") : -len(".rs")]
    if rel in ("lib", "main") or rel.startswith("bin/"):
        return None
    parts = rel.split("/")
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts) if parts else None


def compress_lib_filters(filters: list[str], limit: int = MAX_LIB_FILTERS) -> list[str]:
    """Drop filters covered by a shorter prefix; widen to top-level modules past `limit`."""
    unique = sorted(set(filters))
    kept: list[str] = []
    for item in unique:
        if not any(item == k or item.startswith(k + "::") for k in kept):
            kept.append(item)
    if len(kept) > limit:
        kept = sorted({item.split("::")[0] for item in kept})
    return kept


def classify_lane_output(text: str, client_exit: int, lane: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed verdict for one lane log.

    `lane["kind"]` is "build" (check/clippy) or "test". Test lanes carry
    `expected_targets` (integration target names) and may set `lib_filters`.
    """
    clean = ANSI_RE.sub("", text)
    lines = clean.splitlines()
    remote_exits = [int(m.group(1)) for m in REMOTE_EXIT_RE.finditer(clean)]
    remote_exit = remote_exits[-1] if remote_exits else None
    result: dict[str, Any] = {
        "verdict": VERDICT_NO_EVIDENCE,
        "reason": "",
        "remote_exit": remote_exit,
        "client_exit": client_exit,
        "worker": (workers[-1] if (workers := WORKER_RE.findall(clean)) else None),
        "failing_targets": [],
        "first_error": "",
        "counts": {"passed": 0, "failed": 0, "ignored": 0, "filtered": 0, "results": 0},
        "targets_seen": [],
    }
    if remote_exit is None and client_exit == 103:
        result.update(verdict=VERDICT_DEFERRED, reason="admission refused (exit 103)")
        return result
    if re.search(r"RCH-E(412|504)\b", clean):
        result["reason"] = "RCH false green marker (E412/E504): nothing ran"
        return result
    if remote_exit is None:
        result["reason"] = f"no remote exit in log (client exit {client_exit})"
        return result
    missing_target = NO_TARGET_RE.search(clean)
    if missing_target:
        # Cargo refused the target list itself (for example a bisect probe asked for a
        # target that does not exist yet at that commit): nothing was tested.
        result["reason"] = f"cargo has no target `{missing_target.group(1)}` at this commit"
        return result

    failing: list[str] = []
    for match in COULD_NOT_COMPILE_RE.finditer(clean):
        failing.append(f"{match.group(1)} ({match.group(2)})" if match.group(2) else match.group(1))
    first_error = next((line.strip() for line in lines if FIRST_ERROR_RE.match(line.strip())), "")
    finished = any(line.strip().startswith("Finished `") for line in lines)

    if lane["kind"] == "build":
        if failing or remote_exit != 0:
            result.update(
                verdict=VERDICT_RED,
                failing_targets=sorted(set(failing)) or [f"remote exit {remote_exit}"],
                first_error=first_error or f"remote exit {remote_exit}",
                reason="compile or lint failure",
            )
        elif finished:
            result.update(verdict=VERDICT_GREEN, reason="Finished with remote exit 0")
        else:
            result["reason"] = "remote exit 0 without `Finished`"
        return result

    # Test lane. Failing tests are named `<target>::<test>` so a known red can later be
    # healed only by a run that actually executed its target.
    seen: list[str] = []
    failed_tests: list[str] = []
    current = "?"
    for line in lines:
        running = RUNNING_TARGET_RE.match(line)
        if running:
            current = running.group(1).split("/")[-1]
            seen.append(current)
        elif RUNNING_UNITTESTS_RE.match(line):
            current = "lib"
            seen.append("lib")
        elif failed := FAILED_TEST_RE.match(line.strip()):
            failed_tests.append(f"{current}::{failed.group(1)}")
    counts = result["counts"]
    for line in lines:
        tr = TEST_RESULT_RE.match(line.strip())
        if tr:
            counts["results"] += 1
            counts["passed"] += int(tr.group(2))
            counts["failed"] += int(tr.group(3))
            counts["ignored"] += int(tr.group(4))
            counts["filtered"] += int(tr.group(6))
    result["targets_seen"] = sorted(set(seen))
    if failing or counts["failed"] or failed_tests or remote_exit != 0:
        result.update(
            verdict=VERDICT_RED,
            failing_targets=sorted(set(failing + failed_tests)) or [f"remote exit {remote_exit}"],
            first_error=(f"test {failed_tests[0]} FAILED" if failed_tests else first_error) or f"remote exit {remote_exit}",
            reason="test or compile failure",
        )
        return result
    missing = [t for t in lane.get("expected_targets", []) if t not in seen]
    if missing:
        result["reason"] = "expected targets did not run: " + ", ".join(missing)
        return result
    if lane.get("lib_filters") and "lib" not in seen:
        result["reason"] = "lib unit tests did not run"
        return result
    if counts["results"] == 0 or counts["passed"] == 0:
        result["reason"] = "zero tests passed (filtered, gated, or empty target)"
        return result
    result.update(verdict=VERDICT_GREEN, reason="all expected targets ran, 0 failed")
    return result


def red_targets(outcome: dict[str, Any]) -> set[str]:
    """What is red, per target; a red with no named target is keyed by its first error."""
    return set(outcome.get("failing_targets") or [outcome.get("first_error") or "unattributed red"])


def red_signature(lane_id: str, targets: set[str]) -> str:
    material = lane_id + "\n" + "\n".join(sorted(targets))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def bead_payload(
    lane: dict[str, Any], commit: dict[str, Any], outcome: dict[str, Any], batch: list[str], new_targets: set[str]
) -> dict[str, Any]:
    sha7 = commit["sha"][:9]
    target = sorted(new_targets)[0]
    first_error = " ".join(outcome.get("first_error", "").split())[:110]
    identity = commit.get("author_email", "")
    title = f"[main-watchdog] RED {lane['id']} at {sha7}: {target} - {first_error} ({identity})"
    web_api = is_web_api_identity(identity)
    description = "\n".join(
        [
            "## What the main watchdog saw",
            f"- Commit: `{commit['sha']}` \"{commit.get('subject', '')}\"",
            f"- Author identity: `{commit.get('author_name', '')} <{identity}>`"
            + (" (GitHub web/API identity: bypasses the local pre-push hook)" if web_api else ""),
            f"- Batch checked: {batch[0][:9]}..{batch[-1][:9]} ({len(batch)} commit(s)); first red commit found by bisect: `{sha7}`",
            f"- Lane: `{lane['id']}`: `{lane['display_command']}`",
            f"- Remote exit: {outcome.get('remote_exit')}; client exit: {outcome.get('client_exit')}",
            f"- Newly red targets: {', '.join(sorted(new_targets))}",
            f"- All failing targets at the batch head: {', '.join(outcome.get('failing_targets') or [])}",
            f"- Worker: {outcome.get('worker') or 'unknown'}",
            f"- First error: `{outcome.get('first_error', '')}`",
            f"- Commit message declares not compiled/executed: {declares_not_compiled(commit.get('message', ''))}",
            f"- Beads cited by the commit: {', '.join(commit.get('beads') or []) or 'none'}",
            "",
            "## Rules",
            "Filed automatically by `scripts/main_watchdog.py` (" + WATCHDOG_BEAD + "). The watchdog does not revert or",
            "edit anyone's code. Reproduce with the lane command via `rch exec --base <sha> --clean-overlay --no-overlay`,",
            "fix forward on main, and close this bead with the green receipt.",
        ]
    )
    return {
        "title": title,
        "type": "bug",
        "priority": 0,
        "labels": ["watchdog", "main-red", "validation"],
        "parent": WATCHDOG_BEAD,
        "description": description,
        "lane": lane["id"],
        "culprit": commit["sha"],
        "new_targets": sorted(new_targets),
        "signature": red_signature(lane["id"], new_targets),
    }


# ---------------------------------------------------------------------------
# Engine: batch -> lanes -> classify -> bisect -> receipts/beads
# ---------------------------------------------------------------------------

Runner = Callable[[dict[str, Any], str], tuple[str, int]]
TargetExists = Callable[[str, str], bool]  # (sha, test target name) -> exists at sha


def target_of(key: str) -> str | None:
    """The test target a red key belongs to: `target::test` or `pkg (test "target")`."""
    compile_target = COMPILE_TARGET_RE.search(key)
    if compile_target:
        return compile_target.group(1)
    return key.split("::", 1)[0] if "::" in key else None


def lane_at_commit(lane: dict[str, Any], sha: str, target_exists: TargetExists | None) -> dict[str, Any]:
    """The lane as it can run at `sha`: `--test X` targets absent there are dropped.

    A bisect probe must not ask cargo for a target that a later commit added; cargo
    would refuse the whole invocation and the refusal would look like a red.
    """
    if lane["kind"] != "test" or target_exists is None:
        return lane
    argv: list[str] = []
    kept: list[str] = []
    source = lane["argv"]
    index = 0
    while index < len(source):
        if source[index] == "--test" and index + 1 < len(source):
            name = source[index + 1]
            if target_exists(sha, name):
                argv += ["--test", name]
                kept.append(name)
            index += 2
            continue
        argv.append(source[index])
        index += 1
    expected = [t for t in lane.get("expected_targets", []) if t in kept]
    return {**lane, "argv": argv, "expected_targets": expected, "display_command": " ".join(argv)}


def red_can_exist_at(lane: dict[str, Any], sha: str, new_targets: set[str], target_exists: TargetExists | None) -> bool:
    """False when every newly red target's test target is absent at `sha`, so it cannot be red there."""
    if lane["kind"] != "test" or target_exists is None:
        return True
    owners = {target_of(t) for t in new_targets}
    if None in owners:
        return True
    return any(target_exists(sha, owner) for owner in owners if owner is not None)


def probe(
    lane: dict[str, Any], sha: str, runner: Runner, new_targets: set[str], target_exists: TargetExists | None
) -> tuple[str, dict[str, Any] | None]:
    """Run one bisect probe. Returns (kind, outcome): kind is `red`, `clear` or `undecided`."""
    if not red_can_exist_at(lane, sha, new_targets, target_exists):
        return "clear", None  # the failing target does not exist yet at this commit
    probe_lane = lane_at_commit(lane, sha, target_exists)
    text, exit_code = runner(probe_lane, sha)
    outcome = classify_lane_output(text, exit_code, probe_lane)
    if outcome["verdict"] == VERDICT_RED and red_targets(outcome) & new_targets:
        return "red", outcome
    if outcome["verdict"] in (VERDICT_GREEN, VERDICT_RED):
        return "clear", outcome  # green, or red only for other targets
    return "undecided", outcome


def bisect_first_red(
    lane: dict[str, Any], batch: list[str], runner: Runner, new_targets: set[str], target_exists: TargetExists | None = None
) -> tuple[int, bool, list[dict[str, Any]]]:
    """Index in `batch` of the first commit at which any of `new_targets` is red.

    Assumes they are red at the batch head. Returns (index, exact, probes). A probe
    that is not decisive (deferred or no evidence) stops the search; the answer is
    then the earliest index still known to be red and `exact` is False, so the bead
    names a range instead of claiming a single culprit.
    """
    probes: list[dict[str, Any]] = []
    lo, hi = 0, len(batch) - 1  # invariant: batch[hi] is red for new_targets
    exact = True
    while lo < hi:
        mid = (lo + hi) // 2
        kind, outcome = probe(lane, batch[mid], runner, new_targets, target_exists)
        probes.append({"sha": batch[mid], "verdict": outcome["verdict"] if outcome else "target-absent"})
        if kind == "red":
            hi = mid
        elif kind == "clear":
            lo = mid + 1
        else:
            exact = False
            break
    return hi, exact and lo == hi, probes


def heal_candidates(lane: dict[str, Any], lane_known: dict[str, Any], failing: set[str], outcome: dict[str, Any]) -> list[str]:
    """Known reds this outcome proves healed.

    A build lane covers every target, so absence from its failures heals. A targeted
    test lane only covers the targets it ran, so a known red heals only when its own
    target ran and passed.
    """
    if lane["kind"] == "build":
        return sorted(set(lane_known) - failing)
    seen = set(outcome.get("targets_seen") or [])
    return sorted(t for t in lane_known if t not in failing and target_of(t) in seen)


def run_engine(
    plan: dict[str, Any], runner: Runner, state: dict[str, Any], now: str, target_exists: TargetExists | None = None
) -> dict[str, Any]:
    commits = {c["sha"]: c for c in plan["commits"]}
    batch = [c["sha"] for c in plan["commits"]]
    head = batch[-1]
    known = state.setdefault("known_reds", {})
    receipts: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []
    notes: list[str] = []
    all_green = True
    for lane in plan["lanes"]:
        text, exit_code = runner(lane, head)
        outcome = classify_lane_output(text, exit_code, lane)
        receipt = {
            "schema": SCHEMA_VERSION,
            "recorded_at": now,
            "lane": lane["id"],
            "command": lane["display_command"],
            "sha": head,
            "batch": [batch[0], head],
            "batch_size": len(batch),
            **{
                k: outcome[k]
                for k in ("verdict", "reason", "remote_exit", "client_exit", "worker", "failing_targets", "first_error", "counts", "targets_seen")
            },
        }
        if outcome["verdict"] != VERDICT_GREEN:
            all_green = False
        lane_known: dict[str, Any] = known.setdefault(lane["id"], {})
        if outcome["verdict"] == VERDICT_RED:
            failing = red_targets(outcome)
            healed = heal_candidates(lane, lane_known, failing, outcome)
            for target in healed:
                lane_known.pop(target)
            if healed:
                receipt["healed"] = healed
                notes.append(f"{lane['id']}: healed at {head[:9]}: {', '.join(healed)}")
            still = sorted(failing & set(lane_known))
            if still:
                receipt["still_red"] = {t: lane_known[t].get("bead") for t in still}
                notes.append(f"{lane['id']}: still red: " + ", ".join(f"{t} (bead {lane_known[t].get('bead')})" for t in still))
            new_targets = failing - set(lane_known)
            if new_targets:
                index, exact, probes = bisect_first_red(lane, batch, runner, new_targets, target_exists)
                pre_existing = False
                base = plan.get("since")
                if index == 0 and base:
                    # Red at the first commit of the batch: it may predate the batch.
                    kind, base_outcome = probe(lane, base, runner, new_targets, target_exists)
                    probes.append(
                        {"sha": base, "verdict": base_outcome["verdict"] if base_outcome else "target-absent", "batch_base": True}
                    )
                    if kind == "red":
                        pre_existing = True
                    elif kind == "undecided":
                        exact = False
                culprit = commits[batch[index]]
                payload = bead_payload(lane, culprit, outcome, batch, new_targets)
                if pre_existing:
                    payload["title"] = payload["title"].replace(
                        f"at {culprit['sha'][:9]}", f"already red at batch base {base[:9]}"
                    )
                    payload["description"] = (
                        f"**Pre-existing:** already red at `{base}` (the last covered commit before this batch), so no commit in "
                        "this batch caused it. The commit named below is only the first one checked.\n\n" + payload["description"]
                    )
                    payload["culprit"] = None
                elif not exact:
                    payload["title"] = payload["title"].replace(f"at {culprit['sha'][:9]}", f"in {batch[0][:9]}..{culprit['sha'][:9]}")
                payloads.append(payload)
                receipt.update(
                    new_red=sorted(new_targets),
                    culprit=None if pre_existing else culprit["sha"],
                    culprit_exact=exact and not pre_existing,
                    pre_existing=pre_existing,
                    bisect_probes=probes,
                )
                for target in new_targets:
                    lane_known[target] = {
                        "culprit": None if pre_existing else culprit["sha"],
                        "first_seen": now,
                        "bead": None,
                        "signature": payload["signature"],
                    }
        elif outcome["verdict"] == VERDICT_GREEN and lane_known:
            healed = heal_candidates(lane, lane_known, set(), outcome)
            for target in healed:
                lane_known.pop(target)
            if healed:
                receipt["healed"] = healed
                notes.append(f"{lane['id']}: healed at {head[:9]}: {', '.join(healed)}")
        if not lane_known:
            known.pop(lane["id"], None)
        receipts.append(receipt)
    if all_green:
        state["last_green"] = head
    if all(r["verdict"] in (VERDICT_GREEN, VERDICT_RED) for r in receipts):
        state["last_covered"] = head  # decisive for every lane (green or attributed red)
    return {"receipts": receipts, "bead_payloads": payloads, "notes": notes, "state": state}


# ---------------------------------------------------------------------------
# Planning (read-only git)
# ---------------------------------------------------------------------------


def git(*args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if check and proc.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


_TRACKER_IDS: set[str] | None = None


def commit_record(sha: str, scan_unsafe: bool = True) -> dict[str, Any]:
    global _TRACKER_IDS
    if _TRACKER_IDS is None:
        _TRACKER_IDS = tracker_ids() or set()
    fields = git("show", "-s", "--format=%H%x00%an%x00%ae%x00%cI%x00%s%x00%B", sha).split("\x00")
    parents = git("rev-list", "--parents", "-n", "1", sha).split()[1:]
    base = parents[0] if parents else "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # empty tree
    paths = [p for p in git("diff", "--name-only", base, sha).splitlines() if p]
    message = fields[5]
    unsafe_paths = []
    for path in paths if scan_unsafe else []:
        if path.endswith(".rs"):
            body = git("show", f"{sha}:{path}", check=False)
            if UNSAFE_BLOCK_RE.search(body):
                unsafe_paths.append(path)
    return {
        "sha": fields[0],
        "author_name": fields[1],
        "author_email": fields[2],
        "committed_at": fields[3],
        "subject": fields[4],
        "message": message,
        "paths": paths,
        "is_merge": len(parents) > 1,
        "beads": bead_ids(message, _TRACKER_IDS or None),
        "unsafe_paths": unsafe_paths,
    }


def phase6_report(commit: dict[str, Any]) -> list[dict[str, Any]]:
    """README "Phase 6 Policy Gates" artifacts a direct-main commit should have committed (report only)."""
    keys = [commit["sha"][:7], commit["sha"][:9]] + [b.removeprefix("br-") for b in commit["beads"]]
    tree = set(git("ls-tree", "-r", "--name-only", commit["sha"], "--", "artifacts/flamegraphs", "artifacts/proof_notes").split())
    findings = []
    gates = [
        ("flamegraph", any(p.startswith(FLAMEGRAPH_DIRS) for p in commit["paths"]), "artifacts/flamegraphs/main-{}.svg"),
        (
            "proof-note",
            any(p.startswith(PROOF_NOTE_DIRS) for p in commit["paths"]) or bool(commit["unsafe_paths"]),
            "artifacts/proof_notes/main-{}.md",
        ),
    ]
    for gate, triggered, pattern in gates:
        if not triggered:
            continue
        candidates = [pattern.format(k) for k in keys]
        present = [c for c in candidates if c in tree]
        findings.append({"gate": gate, "present": present, "missing": not present, "expected_one_of": candidates})
    return findings


_TARGET_EXISTS_CACHE: dict[tuple[str, str], bool] = {}


def git_target_exists(sha: str, name: str) -> bool:
    """Whether integration test target `name` exists at `sha` (registered path or tests/<name>.rs)."""
    key = (sha, name)
    if key not in _TARGET_EXISTS_CACHE:
        paths = [path for path, entry in cargo_test_registry(sha).items() if entry["name"] == name] or [f"tests/{name}.rs"]
        _TARGET_EXISTS_CACHE[key] = any(
            subprocess.run(["git", "cat-file", "-e", f"{sha}:{path}"], capture_output=True, check=False).returncode == 0
            for path in paths
        )
    return _TARGET_EXISTS_CACHE[key]


def cargo_test_registry(sha: str) -> dict[str, dict[str, Any]]:
    manifest = tomllib.loads(git("show", f"{sha}:Cargo.toml"))
    registry = {}
    for entry in manifest.get("test", []):
        path = entry.get("path", f"tests/{entry['name']}.rs")
        registry[path] = {"name": entry["name"], "features": sorted(entry.get("required-features", []))}
    return registry


def targeted_tests(head: str, paths: list[str]) -> tuple[dict[str, list[str]], list[str], list[str]]:
    """Map changed paths to integration targets grouped by feature set, lib filters, and unmapped paths."""
    registry = cargo_test_registry(head)
    groups: dict[str, set[str]] = {}
    lib_filters: list[str] = []
    unmapped: list[str] = []
    existing = set(git("ls-tree", "-r", "--name-only", head, "--", "tests").split())
    for path in sorted(set(paths)):
        if path.startswith("src/"):
            f = lib_filter_for(path)
            if f:
                lib_filters.append(f)
            continue
        if not path.startswith("tests/") or not path.endswith(".rs") or path not in existing:
            continue
        targets: list[tuple[str, list[str]]] = []
        if path in registry:
            targets.append((registry[path]["name"], registry[path]["features"]))
        elif path.count("/") == 1:
            source = git("show", f"{head}:{path}", check=False)
            features, understood = file_cfg_features(source)
            if not understood:
                unmapped.append(f"{path} (crate cfg not understood)")
                continue
            targets.append((Path(path).stem, features))
        else:
            top = path.split("/")[1]
            owners = [p for p in registry if p.startswith(f"tests/{top}/")]
            for owner in owners:
                targets.append((registry[owner]["name"], registry[owner]["features"]))
            if not owners:
                hits = git("grep", "-lE", rf"^\s*(pub\s+)?mod\s+{re.escape(top)}\s*;", head, "--", "tests/*.rs", check=False)
                for hit in hits.split():
                    file = hit.split(":", 1)[1]
                    if file.count("/") == 1:
                        features, understood = file_cfg_features(git("show", f"{head}:{file}", check=False))
                        if understood:
                            targets.append((Path(file).stem, features))
            if not targets:
                unmapped.append(f"{path} (no owning test target found)")
        for name, features in targets:
            groups.setdefault(",".join(features), set()).add(name)
    return {k: sorted(v) for k, v in groups.items()}, compress_lib_filters(lib_filters), unmapped


def build_lanes(head: str, paths: list[str], jobs: int, with_all_features: bool) -> tuple[list[dict[str, Any]], list[str]]:
    lanes: list[dict[str, Any]] = [
        {"id": "check-default", "kind": "build", "argv": ["cargo", "check", "-j", str(jobs), "--all-targets", "--keep-going", "--message-format=short"]},
        {
            "id": "clippy-default",
            "kind": "build",
            "argv": ["cargo", "clippy", "-j", str(jobs), "--all-targets", "--keep-going", "--message-format=short", "--", "-D", "warnings"],
            "needs_clippy_component": True,
        },
        {
            "id": "native-cancel-contract",
            "kind": "test",
            "argv": [
                "env", "CARGO_INCREMENTAL=0", "CARGO_PROFILE_TEST_DEBUG=0", "RUSTFLAGS=-D warnings -C debuginfo=0",
                "cargo", "test", "-j", str(jobs), "-p", "asupersync", "--locked", "--test", "runtime_abort_vs_cancel_semantics_audit",
            ],
            "expected_targets": ["runtime_abort_vs_cancel_semantics_audit"],
        },
    ]
    if with_all_features:
        lanes.insert(1, {"id": "check-all-features", "kind": "build", "argv": ["cargo", "check", "-j", str(jobs), "--all-targets", "--all-features", "--keep-going", "--message-format=short"]})
    groups, lib_filters, unmapped = targeted_tests(head, paths)
    for features, names in sorted(groups.items()):
        argv = ["cargo", "test", "-j", str(jobs), "-p", "asupersync", "--no-fail-fast"]
        if features:
            argv += ["--features", features]
        for name in names:
            argv += ["--test", name]
        suffix = features.replace(",", "+") or "default"
        lanes.append({"id": f"targeted-tests[{suffix}]", "kind": "test", "argv": argv, "expected_targets": names})
    if lib_filters:
        lanes.append(
            {
                "id": "targeted-lib",
                "kind": "test",
                "argv": ["cargo", "test", "-j", str(jobs), "-p", "asupersync", "--lib", "--", *lib_filters],
                "expected_targets": [],
                "lib_filters": lib_filters,
            }
        )
    for lane in lanes:
        lane["display_command"] = " ".join(lane["argv"])
    return lanes, unmapped


def make_plan(since: str | None, until: str, max_batch: int, jobs: int, with_all_features: bool, state: dict[str, Any]) -> dict[str, Any]:
    start = since or state.get("last_covered")
    if not start:
        raise SystemExit("no --since and no last_covered in state: pass --since <sha> for the first run")
    shas = git("rev-list", "--reverse", "--first-parent", f"{start}..{until}").split()
    if not shas:
        return {"schema": SCHEMA_VERSION, "commits": [], "lanes": [], "since": start, "until": until}
    batch = shas[:max_batch]
    commits = [commit_record(s) for s in batch]
    paths = sorted({p for c in commits for p in c["paths"]})
    lanes, unmapped = build_lanes(batch[-1], paths, jobs, with_all_features)
    flags = []
    for c in commits:
        code_paths = [p for p in c["paths"] if is_code_path(p)]
        flags.append(
            {
                "sha": c["sha"],
                "web_api_identity": is_web_api_identity(c["author_email"]),
                "declares_not_compiled": declares_not_compiled(c["message"]),
                "beadless_code_commit": bool(code_paths) and not c["beads"] and not c["is_merge"],
                "phase6": phase6_report(c),
            }
        )
    return {
        "schema": SCHEMA_VERSION,
        "since": start,
        "until": until,
        "remaining_after_batch": len(shas) - len(batch),
        "commits": commits,
        "flags": flags,
        "lanes": lanes,
        "unmapped_paths": unmapped,
    }


# ---------------------------------------------------------------------------
# RCH runner, state, receipts, beads
# ---------------------------------------------------------------------------


def rch_runner(target_dir: str, admission_attempts: int, admission_sleep: int, log_dir: Path) -> Runner:
    def run(lane: dict[str, Any], sha: str) -> tuple[str, int]:
        env = dict(os.environ)
        env.update(
            RCH_REQUIRE_REMOTE="1",
            RCH_BUILD_TIMEOUT_SEC=env.get("RCH_BUILD_TIMEOUT_SEC", "5400"),
            RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=env.get("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS", "3000"),
            CARGO_TARGET_DIR=f"{target_dir}_{lane['id'].split('[')[0]}",
        )
        if lane.get("needs_clippy_component") and os.environ.get("WATCHDOG_CLIPPY_WORKERS"):
            env["RCH_WORKER"] = os.environ["WATCHDOG_CLIPPY_WORKERS"]
        argv = ["rch", "exec", "--base", sha, "--clean-overlay", "--no-overlay", "--", *lane["argv"]]
        text, code = "", 103
        for _ in range(admission_attempts):
            proc = subprocess.run(argv, capture_output=True, text=True, env=env, check=False)
            text, code = proc.stdout + proc.stderr, proc.returncode
            if not (code == 103 and not REMOTE_EXIT_RE.search(text)):
                break
            subprocess.run(["sleep", str(admission_sleep)], check=False)
        log_dir.mkdir(parents=True, exist_ok=True)
        with open(log_dir / f"{sha[:12]}_{re.sub(r'[^A-Za-z0-9_.+-]', '_', lane['id'])}.log", "a", encoding="utf-8") as log:
            log.write(text)
        return text, code

    return run


def load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"schema": SCHEMA_VERSION, "known_reds": {}}


def post_receipts(plan: dict[str, Any], receipts: list[dict[str, Any]]) -> None:
    """Comment the batch receipt on every bead a commit in the batch cites.

    Commits that cite no bead are counted in `summary` instead.
    """
    lines = [f"main-watchdog receipt ({WATCHDOG_BEAD}), batch {receipts[0]['batch'][0][:9]}..{receipts[0]['sha'][:9]}:"]
    for r in receipts:
        c = r["counts"]
        lines.append(
            f"- {r['lane']}: {r['verdict']} ({r['reason']}); remote exit {r['remote_exit']}; worker {r.get('worker')}; "
            f"passed {c['passed']} failed {c['failed']} ignored {c['ignored']} filtered {c['filtered']}"
            + (f"; failing: {', '.join(r['failing_targets'])}" if r["failing_targets"] else "")
        )
    text = "\n".join(lines) + "\n"
    cited = sorted({b for c in plan["commits"] for b in c["beads"]})
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
        handle.write(text)
        path = handle.name
    for bead in cited:
        target = bead if bead.startswith("asupersync-") else bead.removeprefix("br-")
        subprocess.run(["br", "comments", "add", target, "-f", path, "--author", "main-watchdog"], capture_output=True, check=False)


def existing_bead_for(new_targets: list[str], open_issues: list[dict[str, Any]]) -> str | None:
    """An open bead whose title or description already names every newly red test.

    Test names are matched without their `target::` prefix, as bead text names them.
    A red keyed only by an error message never matches, so it is always filed.
    """
    names = [t.split("::", 1)[1] for t in new_targets if "::" in t]
    if not names or len(names) != len(new_targets):
        return None
    for issue in open_issues:
        text = f"{issue.get('title', '')}\n{issue.get('description', '')}"
        if all(re.search(rf"\b{re.escape(name)}\b", text) for name in names):
            return issue.get("id")
    return None


def open_tracker_issues(issues_path: Path = Path(".beads/issues.jsonl")) -> list[dict[str, Any]]:
    try:
        lines = issues_path.read_text().splitlines()
    except FileNotFoundError:
        return []
    issues = []
    for line in lines:
        try:
            issue = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(issue, dict) and issue.get("status") not in ("closed", "tombstone"):
            issues.append(issue)
    return issues


def file_bead(payload: dict[str, Any]) -> str | None:
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as handle:
        handle.write(payload["description"])
        desc_path = handle.name
    proc = subprocess.run(
        [
            "br", "create", "--title", payload["title"], "-t", payload["type"], "-p", str(payload["priority"]),
            "-l", ",".join(payload["labels"]), "--parent", payload["parent"], "--description-file", desc_path,
            "--actor", "main-watchdog", "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        data = json.loads(proc.stdout)
        return data.get("id") if isinstance(data, dict) else None
    except json.JSONDecodeError:
        sys.stderr.write(f"br create failed: {proc.stderr.strip()}\n")
        return None


# ---------------------------------------------------------------------------
# Summary / exit metrics
# ---------------------------------------------------------------------------


def orphan_count(sha: str) -> int:
    """Top-level src/*.rs files no `mod`, #[path] or include! reaches (mirrors tests/dormant_e2e_inventory_contract.rs)."""
    lib = git("show", f"{sha}:src/lib.rs")
    declared = set()
    for line in lib.splitlines():
        rest = line.strip()
        if rest.startswith("//"):
            continue
        while rest.startswith("#["):
            end = rest.find("]")
            if end < 0:
                break
            rest = rest[end + 1 :].strip()
        rest = re.sub(r"^pub(\([^)]*\))?\s+", "", rest)
        match = re.match(r"mod\s+([A-Za-z0-9_]+)\s*;", rest)
        if match:
            declared.add(match.group(1))
    tops = [p for p in git("ls-tree", "--name-only", sha, "src/").split() if p.endswith(".rs")]
    referenced = set()
    grep = git("grep", "-hoE", r'(#\[path = "|include!\(")[^"]+\.rs"', sha, "--", "src", "tests", "benches", "examples", check=False)
    for hit in grep.splitlines():
        referenced.add(Path(hit.split('"')[1]).name)
    return sum(1 for p in tops if Path(p).stem not in declared | {"lib", "main"} and Path(p).name not in referenced)


def tracker_counts(issues_path: Path, now: dt.datetime) -> dict[str, int]:
    counts = {"open_p0": 0, "open_p1": 0, "stale_in_progress_7d": 0}
    if not issues_path.exists():
        return counts
    for line in issues_path.read_text().splitlines():
        try:
            issue = json.loads(line)
        except json.JSONDecodeError:
            continue
        status, priority = issue.get("status"), issue.get("priority")
        if status == "open" and priority == 0:
            counts["open_p0"] += 1
        if status == "open" and priority == 1:
            counts["open_p1"] += 1
        if status == "in_progress":
            try:
                updated = dt.datetime.fromisoformat(str(issue.get("updated_at")).replace("Z", "+00:00"))
            except ValueError:
                continue
            if (now - updated).days >= 7:
                counts["stale_in_progress_7d"] += 1
    return counts


def summary(receipts_path: Path, since: str, until: str, issues_path: Path, now: dt.datetime) -> dict[str, Any]:
    shas = git("rev-list", "--reverse", "--first-parent", f"{since}..{until}").split()
    receipts = []
    if receipts_path.exists():
        receipts = [json.loads(line) for line in receipts_path.read_text().splitlines() if line.strip()]
    order = {s: i for i, s in enumerate(shas)}
    covered_green_by: dict[str, str] = {}
    by_head: dict[str, list[dict[str, Any]]] = {}
    for r in receipts:
        by_head.setdefault(r["sha"], []).append(r)
    for head, rs in by_head.items():
        if head in order and rs and all(r["verdict"] == VERDICT_GREEN for r in rs):
            recorded = min(r["recorded_at"] for r in rs)
            for sha in shas[: order[head] + 1]:
                covered_green_by.setdefault(sha, recorded)
    green_2h = beadless = not_compiled = web_api = 0
    beadless_list, not_compiled_list = [], []
    for sha in shas:
        c = commit_record(sha, scan_unsafe=False)
        committed = dt.datetime.fromisoformat(c["committed_at"])
        if sha in covered_green_by and dt.datetime.fromisoformat(covered_green_by[sha]) - committed <= dt.timedelta(hours=2):
            green_2h += 1
        if any(is_code_path(p) for p in c["paths"]) and not c["beads"] and not c["is_merge"]:
            beadless += 1
            beadless_list.append(f"{sha[:9]} {c['subject'][:70]}")
        if declares_not_compiled(c["message"]):
            not_compiled += 1
            not_compiled_list.append(f"{sha[:9]} {c['author_email']} {c['subject'][:60]}")
        web_api += is_web_api_identity(c["author_email"])
    total = len(shas)
    return {
        "schema": SCHEMA_VERSION,
        "window": [since, until],
        "generated_at": now.isoformat(),
        "commits": total,
        "web_api_identity_commits": web_api,
        "percent_green_within_2h": round(100.0 * green_2h / total, 1) if total else None,
        "beadless_code_commits": beadless,
        "beadless_code_commit_list": beadless_list,
        "declares_not_compiled": not_compiled,
        "declares_not_compiled_list": not_compiled_list,
        "orphan_top_level_sources": orphan_count(until),
        **tracker_counts(issues_path, now),
        "reds_in_window": sorted({f"{r['lane']}@{r.get('culprit', r['sha'])[:9]}" for r in receipts if r["verdict"] == VERDICT_RED and r["sha"] in order}),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("--since", help="exclusive start SHA; defaults to state.last_covered")
        p.add_argument("--until", default="origin/main")
        p.add_argument("--max-batch", type=int, default=25)
        p.add_argument("--jobs", type=int, default=4)
        p.add_argument("--with-all-features", action="store_true")
        p.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
        p.add_argument("--no-fetch", action="store_true", help="skip `git fetch origin` before planning")
        if name == "run":
            p.add_argument("--file-beads", action="store_true", help="file a P0 bead per newly red target set")
            p.add_argument("--post-receipts", action="store_true", help="comment the batch receipt on cited beads")
            p.add_argument("--admission-attempts", type=int, default=40)
            p.add_argument("--admission-sleep", type=int, default=90)
    e = sub.add_parser("evaluate")
    e.add_argument("--scenario", type=Path, required=True)
    s = sub.add_parser("summary")
    s.add_argument("--since", required=True)
    s.add_argument("--until", default="origin/main")
    s.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    s.add_argument("--issues", type=Path, default=Path(".beads/issues.jsonl"))
    args = parser.parse_args(argv)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

    if args.mode == "evaluate":
        scenario = json.loads(args.scenario.read_text())
        logs = scenario["lane_logs"]

        absent = {sha: set(names) for sha, names in scenario.get("absent_targets", {}).items()}

        def fake_runner(lane: dict[str, Any], sha: str) -> tuple[str, int]:
            # Like cargo: asking for a target that does not exist at `sha` fails the invocation.
            argv = lane.get("argv", [])
            for index, arg in enumerate(argv[:-1]):
                if arg == "--test" and argv[index + 1] in absent.get(sha, set()):
                    name = argv[index + 1]
                    return f"error: no test target named `{name}` in `asupersync` package\n  Remote command finished: exit=101 in 1ms\n", 101
            entry = logs.get(lane["id"], {}).get(sha)
            if entry is None:
                return "", 103
            return entry["log"], entry.get("client_exit", 0)

        def fake_target_exists(sha: str, name: str) -> bool:
            return name not in absent.get(sha, set())

        for lane in scenario["plan"]["lanes"]:
            lane.setdefault("display_command", " ".join(lane.get("argv", [lane["id"]])))
        result = run_engine(
            scenario["plan"],
            fake_runner,
            scenario.get("state", {"known_reds": {}}),
            scenario.get("now", "2026-01-01T00:00:00+00:00"),
            None if scenario.get("disable_target_filter") else fake_target_exists,
        )
        probes = scenario.get("probes", {})
        result["probe_results"] = {
            "declares_not_compiled": [declares_not_compiled(m) for m in probes.get("declares_not_compiled", [])],
            "bead_ids": [bead_ids(m, set(probes["known_ids"]) if "known_ids" in probes else None) for m in probes.get("bead_ids", [])],
            "file_cfg_features": [list(file_cfg_features(s)) for s in probes.get("file_cfg_features", [])],
            "lib_filter_for": [lib_filter_for(p) for p in probes.get("lib_filter_for", [])],
            "existing_bead_for": [
                existing_bead_for(case["new_targets"], case["open_issues"]) for case in probes.get("existing_bead_for", [])
            ],
        }
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    if args.mode == "summary":
        report = summary(args.state_dir / "receipts.jsonl", args.since, args.until, args.issues, now)
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    state_path = args.state_dir / "state.json"
    state = load_state(state_path)
    if not args.no_fetch:
        git("fetch", "-q", "origin", check=False)
    plan = make_plan(args.since, args.until, args.max_batch, args.jobs, args.with_all_features, state)
    if args.mode == "plan":
        json.dump(plan, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if not plan["commits"]:
        print(json.dumps({"schema": SCHEMA_VERSION, "status": "no new commits", "since": plan["since"]}))
        return 0
    args.state_dir.mkdir(parents=True, exist_ok=True)
    runner = rch_runner(str(args.state_dir / "target"), args.admission_attempts, args.admission_sleep, args.state_dir / "logs")
    result = run_engine(plan, runner, state, now.isoformat(), git_target_exists)
    open_issues = open_tracker_issues()
    for payload in result["bead_payloads"]:
        if args.file_beads:
            existing = existing_bead_for(payload["new_targets"], open_issues)
            if existing:
                payload["existing_bead"] = existing  # already tracked: record it, file nothing
                bead = existing
            else:
                bead = file_bead(payload)
                payload["filed_bead"] = bead
            for target in payload["new_targets"]:
                entry = state["known_reds"].get(payload["lane"], {}).get(target)
                if entry is not None:
                    entry["bead"] = bead
    if args.post_receipts:
        post_receipts(plan, result["receipts"])
    with open(args.state_dir / "receipts.jsonl", "a", encoding="utf-8") as handle:
        for receipt in result["receipts"]:
            handle.write(json.dumps(receipt, sort_keys=True) + "\n")
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True))
    json.dump({"plan_flags": plan["flags"], "unmapped_paths": plan["unmapped_paths"], **result}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 1 if any(r["verdict"] == VERDICT_RED for r in result["receipts"]) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
