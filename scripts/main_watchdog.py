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
  summary   Daily summary and exit metrics from receipts, git, and the tracker, with
            the ledgers of asupersync-bi2462.147.1: rule-3 receipt latency per
            no-compile-path commit (overdue after 2 h, escalated after 6 h), test
            targets added in the window that no lane has executed, stranded or
            stale work in the shared checkout, and duplicate-fix leads (same bead,
            or overlapping lines from different bases: a lead, not proof). `run`
            files the 6 h escalations (one P0 per commit, once) for commits after
            `--ledger-since`. It also lists owner decisions recorded in bead
            comments (explicit markers only) that no later commit cites after 48 h.

A lane is green only when the remote exit is 0, cargo reached `Finished`, nothing
failed to compile, and (for test lanes) every expected target ran at least one
test and none failed. Admission refusals, RCH false greens (E412/E504), missing
remote exits, and zero-test runs are never green.

Changed `src/` files are mapped through the module tree (`mod` declarations,
`#[path]`, `include!`) to their lib module path and the `cfg` features on their
chain. Touched feature-gated modules add a `check-features` all-targets check and
run the lib lane with those features, as one union: a break that shows only under
a subset of them is not detected (`--with-all-features` checks the full set). A
changed file no crate root reaches is reported as unmapped: nothing compiles it.
A touched workspace member crate (for example asupersync-macros) gets its own
`cargo test -p <crate>` lane; its clippy is not run. Head lanes run `--parallel`
at a time; bisection is serial.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import posixpath
import re
import subprocess
import sys
import tempfile
import tomllib
from concurrent.futures import ThreadPoolExecutor
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
INNER_CFG_RE = re.compile(r"#!\[cfg\(")
CFG_TOKEN_RE = re.compile(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*)|("[^"]*")|([(),=]))')
# A `mod x;` at column 0 (the tree has no indented or macro-wrapped file modules).
MOD_DECL_RE = re.compile(r"^(?:pub(?:\([^)\n]*\))?[ \t]+)?mod[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*;", re.MULTILINE)
INCLUDE_RE = re.compile(r'\binclude!\(\s*"([^"]+)"\s*\)')
ENV_GATE_RE = re.compile(r'"REAL_[A-Z0-9_]+"')
PATH_ATTR_RE = re.compile(r'^path\s*=\s*"([^"]+)"$')
# A cfg requirement lists the alternative feature sets that make a predicate hold in a
# watchdog build (Linux RCH worker, default features on). TRUE holds as is; NEVER has no
# alternative (nothing the watchdog runs compiles it); None is not understood.
TRUE: frozenset[frozenset[str]] = frozenset({frozenset()})
NEVER: frozenset[frozenset[str]] = frozenset()
REMOTE_EXIT_RE = re.compile(r"Remote command finished: exit=(\d+)")
WORKER_RE = re.compile(r"Selected worker: (\S+)")
EXECUTED_TEST_RE = re.compile(r"^test (\S+) \.\.\. (?:ok|FAILED)$")
TEST_RESULT_RE = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
)
RUNNING_TARGET_RE = re.compile(r"^\s*Running (?:tests|benches|examples)/([A-Za-z0-9_\-/]+)\.rs\b")
RUNNING_UNITTESTS_RE = re.compile(r"^\s*Running unittests (\S+)")
COULD_NOT_COMPILE_RE = re.compile(r"error: could not compile `([^`]+)`(?: \(([^)]*)\))?")
FIRST_ERROR_RE = re.compile(r"^(?:\S+\.rs:\d+:\d+: error(?:\[E\d+\])?:.*|error(?:\[E\d+\])?: (?!could not compile|aborting).*)$")
FAILED_TEST_RE = re.compile(r"^test (\S+) \.\.\. FAILED$")
NO_TARGET_RE = re.compile(r"error: no (?:test|bin|example|bench) target named `([^`]+)`")
# rustc itself was killed (the worker ran out of memory): it never reached a verdict.
COMPILER_KILLED_RE = re.compile(r"process didn't exit successfully: `(?:[^`\s]*/)?rustc [^`]*` \(signal: 9, SIGKILL: kill\)")
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


Requirement = Any  # frozenset[frozenset[str]] (TRUE, NEVER, alternatives) or None


def _cfg_tokens(expr: str) -> list[str] | None:
    tokens: list[str] = []
    pos = 0
    while expr[pos:].strip():
        match = CFG_TOKEN_RE.match(expr, pos)
        if not match:
            return None
        tokens.append(next(group for group in match.groups() if group is not None))
        pos = match.end()
    return tokens


def _cfg_parse(tokens: list[str], i: int) -> tuple[tuple[Any, ...], int]:
    head = tokens[i]
    if head in ("all", "any", "not") and tokens[i + 1] == "(":
        args = []
        i += 2
        while tokens[i] != ")":
            node, i = _cfg_parse(tokens, i)
            args.append(node)
            if tokens[i] == ",":
                i += 1
        return (head, args), i + 1
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", head):
        raise ValueError(head)
    if i + 1 < len(tokens) and tokens[i + 1] == "=":
        if not tokens[i + 2].startswith('"'):
            raise ValueError(tokens[i + 2])
        return ("kv", head, tokens[i + 2].strip('"')), i + 3
    return ("flag", head), i + 1


def _alternatives(sets: Any) -> frozenset[frozenset[str]]:
    """Minimal alternatives only (a superset of another alternative adds nothing)."""
    pool = set(sets)
    minimal = sorted((s for s in pool if not any(o < s for o in pool)), key=lambda s: (len(s), sorted(s)))
    return frozenset(minimal[:64])


def _cfg_eval(node: tuple[Any, ...], defaults: frozenset[str]) -> Requirement:
    kind = node[0]
    if kind == "kv":
        key, value = node[1], node[2]
        if key == "feature":
            return TRUE if value in defaults else frozenset({frozenset({value})})
        if key == "target_os":
            return TRUE if value == "linux" else NEVER
        if key == "target_family":
            return TRUE if value == "unix" else NEVER
        if key == "target_arch" and value.startswith("wasm"):
            return NEVER
        return None
    if kind == "flag":
        if node[1] in ("unix", "test", "debug_assertions"):
            return TRUE
        if node[1] in ("windows", "miri"):
            return NEVER
        return None
    args = [_cfg_eval(arg, defaults) for arg in node[1]]
    if kind == "all":
        return combine_requirements(args)
    if kind == "any":
        alternatives = [s for arg in args if arg is not None for s in arg]
        if alternatives:
            return _alternatives(alternatives)
        return None if None in args else NEVER
    # not(...) holds without extra features exactly when its operand needs some (or never
    # holds), and never holds when its operand already holds in every watchdog build.
    if len(args) != 1 or args[0] is None:
        return None
    return NEVER if frozenset() in args[0] else TRUE


def cfg_requirement(expr: str, defaults: frozenset[str] = frozenset()) -> Requirement:
    """What the predicate of `cfg(<expr>)` needs to hold on a Linux RCH worker."""
    tokens = _cfg_tokens(expr)
    if not tokens:
        return None
    try:
        node, end = _cfg_parse(tokens, 0)
    except (IndexError, ValueError):
        return None
    return _cfg_eval(node, defaults) if end == len(tokens) else None


def combine_requirements(reqs: list[Requirement]) -> Requirement:
    """Conjunction: NEVER dominates, then not-understood, else pairwise unions of alternatives."""
    if any(req is not None and not req for req in reqs):
        return NEVER
    if None in reqs:
        return None
    result = TRUE
    for req in reqs:
        result = _alternatives(a | b for a in result for b in req)
    return result


def chosen_features(req: Requirement) -> frozenset[str] | None:
    """The smallest feature set that satisfies `req`; None when none is known to."""
    if not req:
        return None
    return min(req, key=lambda s: (len(s), sorted(s)))


def requirement_json(req: Requirement) -> Any:
    if req is None:
        return None
    return sorted(chosen_features(req)) if req else "never"


def _balanced_end(text: str, start: int) -> int:
    """Index just past the bracket closing the one at `start` (strings skipped), or -1."""
    depth, i, in_string = 0, start, False
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\":
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def inner_cfg_requirement(source: str, defaults: frozenset[str] = frozenset()) -> Requirement:
    """Conjunction of a file's leading inner `#![cfg(...)]` attributes (single- or multi-line)."""
    reqs: list[Requirement] = []
    for match in INNER_CFG_RE.finditer(source):
        if source.count("\n", 0, match.start()) > 80:
            break
        line_start = source.rfind("\n", 0, match.start()) + 1
        if source[line_start : match.start()].strip():
            continue
        end = _balanced_end(source, match.end() - 1)
        if end < 0:
            return None
        reqs.append(cfg_requirement(source[match.end() : end - 1], defaults))
    return combine_requirements(reqs)


def file_cfg_features(source: str, defaults: frozenset[str] = frozenset()) -> tuple[list[str], bool]:
    """Features a test file's crate-level `#![cfg(...)]` requires, as (features, understood).

    A cfg that never holds on the Linux fleet (wasm-only, windows-only) or that is not
    understood is reported as not understood, so the caller marks the mapping instead of
    running a target that compiles to nothing.
    """
    chosen = chosen_features(inner_cfg_requirement(source, defaults))
    return (sorted(chosen), True) if chosen is not None else ([], False)


def _attrs_before(text: str, pos: int) -> list[str]:
    """Bodies of the outer attributes stacked directly above `pos` (comments skipped)."""
    attrs: list[str] = []
    end = pos
    while True:
        j = end
        while j > 0 and text[j - 1].isspace():
            j -= 1
        line_start = text.rfind("\n", 0, j) + 1
        if j > line_start and text[line_start:j].lstrip().startswith("//"):
            end = line_start
            continue
        if j == 0 or text[j - 1] != "]":
            return attrs
        depth, k = 0, j - 1
        while k >= 0:
            if text[k] == "]":
                depth += 1
            elif text[k] == "[":
                depth -= 1
                if depth == 0:
                    break
            k -= 1
        if k < 1 or text[k - 1] != "#":
            return attrs
        attrs.append(text[k + 1 : j - 1].strip())
        end = k - 1


def module_tree(
    sources: dict[str, str], roots: dict[str, Requirement], defaults: frozenset[str] = frozenset()
) -> dict[str, tuple[str | None, Requirement]]:
    """Map every source file a crate root reaches to (lib module path, cfg requirement).

    Follows column-0 `mod x;` declarations (with `#[path]`) and `include!`, conjoining
    every `cfg` on the way. `src/lib.rs` yields lib module paths; other roots (binaries)
    yield None. A file missing from the result is compiled by nothing.
    """
    tree: dict[str, tuple[str | None, Requirement]] = {}

    def rank(modpath: str | None, req: Requirement) -> tuple[bool, bool, int]:
        chosen = chosen_features(req)
        return (modpath is None, chosen is None, len(chosen) if chosen is not None else 0)

    def walk(path: str, modpath: str | None, req: Requirement, mod_rs: bool) -> None:
        text = sources.get(path)
        if text is None:
            return
        req = combine_requirements([req, inner_cfg_requirement(text, defaults)])
        if path in tree and rank(*tree[path]) <= rank(modpath, req):
            return
        tree[path] = (modpath, req)
        directory = posixpath.dirname(path)
        child_dir = directory if mod_rs else posixpath.join(directory, posixpath.basename(path)[: -len(".rs")])
        for match in MOD_DECL_RE.finditer(text):
            name = match.group(1)
            attrs = _attrs_before(text, match.start())
            cfgs = [cfg_requirement(a[len("cfg(") : -1], defaults) for a in attrs if a.startswith("cfg(") and a.endswith(")")]
            child_req = combine_requirements([req, *cfgs])
            child_mod = None if modpath is None else (f"{modpath}::{name}" if modpath else name)
            explicit = next((m.group(1) for a in attrs if (m := PATH_ATTR_RE.match(a))), None)
            if explicit:
                walk(posixpath.normpath(posixpath.join(directory, explicit)), child_mod, child_req, True)
                continue
            for candidate, child_mod_rs in ((f"{child_dir}/{name}.rs", False), (f"{child_dir}/{name}/mod.rs", True)):
                if candidate in sources:
                    walk(candidate, child_mod, child_req, child_mod_rs)
                    break
        for match in INCLUDE_RE.finditer(text):
            walk(posixpath.normpath(posixpath.join(directory, match.group(1))), modpath, req, mod_rs)

    for root, req in sorted(roots.items()):
        walk(root, "" if root == "src/lib.rs" else None, req, True)
    return tree


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
        "unexercised_filters": [],
        "targets_executed": [],
        "env_gated_targets": list(lane.get("env_gated_targets", [])),
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
    # A compiler killed on the worker proves nothing about the code. With no real
    # diagnostic beside it the lane is undecided, not red: such a red was once bisected
    # to an innocent commit (lib test, vmi workers, 2026-09-25).
    compiler_killed = bool(COMPILER_KILLED_RE.search(clean)) and not first_error
    killed_reason = "rustc was killed on the worker (signal 9, out of memory): nothing was compiled or tested"

    if lane["kind"] == "build":
        if compiler_killed:
            result["reason"] = killed_reason
            return result
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
    lib_tests: list[str] = []
    executed_targets: set[str] = set()
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
        if current == "lib" and (executed := EXECUTED_TEST_RE.match(line.strip())):
            lib_tests.append(executed.group(1))
        if (tr := TEST_RESULT_RE.match(line.strip())) and int(tr.group(2)) + int(tr.group(3)) > 0:
            executed_targets.add(current)
    result["targets_executed"] = sorted(executed_targets - {"?"})
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
    # Informational: a changed module whose filter selected no executed test has no unit
    # test here; the lane still vouches only for what it ran.
    result["unexercised_filters"] = [f for f in lane.get("lib_filters", []) if not any(f in name for name in lib_tests)]
    if compiler_killed and not failed_tests and not counts["failed"]:
        result["reason"] = killed_reason
        return result
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
    plan: dict[str, Any],
    runner: Runner,
    state: dict[str, Any],
    now: str,
    target_exists: TargetExists | None = None,
    parallel: int = 1,
) -> dict[str, Any]:
    commits = {c["sha"]: c for c in plan["commits"]}
    batch = [c["sha"] for c in plan["commits"]]
    head = batch[-1]
    known = state.setdefault("known_reds", {})
    receipts: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []
    notes: list[str] = []
    all_green = True
    head_runs: list[tuple[str, int]] | None = None
    if parallel > 1 and len(plan["lanes"]) > 1:
        # Head lanes are independent; only wall clock changes. Bisection stays serial below.
        with ThreadPoolExecutor(max_workers=parallel) as pool:
            head_runs = list(pool.map(lambda lane: runner(lane, head), plan["lanes"]))
    for index, lane in enumerate(plan["lanes"]):
        text, exit_code = head_runs[index] if head_runs is not None else runner(lane, head)
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
                for k in (
                    "verdict", "reason", "remote_exit", "client_exit", "worker", "failing_targets", "first_error", "counts",
                    "targets_seen", "unexercised_filters", "targets_executed", "env_gated_targets",
                )
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


def target_root_paths(name: str, registry: dict[str, dict[str, Any]]) -> list[str]:
    """Files whose presence means test target `name` exists.

    Failing tests are keyed `<target>::<test>`, where the lib unit-test target is `lib`:
    it exists wherever src/lib.rs does. Treating it like an integration target
    (tests/lib.rs) made every bisect probe read `target-absent` and blamed the head.
    """
    if name == "lib":
        return ["src/lib.rs"]
    return [path for path, entry in registry.items() if entry["name"] == name] or [f"tests/{name}.rs"]


def git_target_exists(sha: str, name: str) -> bool:
    """Whether test target `name` exists at `sha` (see `target_root_paths`)."""
    key = (sha, name)
    if key not in _TARGET_EXISTS_CACHE:
        paths = target_root_paths(name, cargo_test_registry(sha))
        _TARGET_EXISTS_CACHE[key] = any(
            subprocess.run(["git", "cat-file", "-e", f"{sha}:{path}"], capture_output=True, check=False).returncode == 0
            for path in paths
        )
    return _TARGET_EXISTS_CACHE[key]


def manifest_at(sha: str) -> dict[str, Any]:
    return tomllib.loads(git("show", f"{sha}:Cargo.toml"))


def cargo_test_registry(sha: str) -> dict[str, dict[str, Any]]:
    registry = {}
    for entry in manifest_at(sha).get("test", []):
        path = entry.get("path", f"tests/{entry['name']}.rs")
        registry[path] = {"name": entry["name"], "features": sorted(entry.get("required-features", []))}
    return registry


def tree_sources(sha: str, prefix: str = "src/") -> dict[str, str]:
    """Every `.rs` blob under `prefix` at `sha`, read through one `git cat-file --batch`."""
    entries = []
    for line in git("ls-tree", "-r", sha, "--", prefix).splitlines():
        meta, path = line.split("\t", 1)
        _mode, kind, blob = meta.split()
        if kind == "blob" and path.endswith(".rs"):
            entries.append((path, blob))
    stdin = "".join(f"{blob}\n" for _, blob in entries).encode()
    out = subprocess.run(["git", "cat-file", "--batch"], input=stdin, capture_output=True, check=True).stdout
    sources, pos = {}, 0
    for path, _blob in entries:
        header_end = out.index(b"\n", pos)
        size = int(out[pos:header_end].split()[2])
        sources[path] = out[header_end + 1 : header_end + 1 + size].decode("utf-8", "replace")
        pos = header_end + 1 + size + 1
    return sources


def crate_roots(sources: dict[str, str], manifest: dict[str, Any], defaults: frozenset[str]) -> dict[str, Requirement]:
    """The library root plus every binary root, each with the features its target requires."""
    roots: dict[str, Requirement] = {"src/lib.rs": TRUE}
    for entry in manifest.get("bin", []):
        required = frozenset(entry.get("required-features", [])) - defaults
        roots[entry.get("path", f"src/bin/{entry['name']}.rs")] = frozenset({required})
    for path in sources:
        if path == "src/main.rs" or re.fullmatch(r"src/bin/[^/]+\.rs|src/bin/[^/]+/main\.rs", path):
            roots.setdefault(path, TRUE)
    return roots


def workspace_members(head: str, manifest: dict[str, Any]) -> dict[str, str]:
    """Member directory -> package name, for every workspace member except the root package."""
    members = {}
    for directory in manifest.get("workspace", {}).get("members", []):
        if directory in (".", ""):
            continue
        member = tomllib.loads(git("show", f"{head}:{directory}/Cargo.toml", check=False) or "")
        if name := member.get("package", {}).get("name"):
            members[directory.rstrip("/")] = name
    return members


def targeted_tests(head: str, paths: list[str]) -> dict[str, Any]:
    """Map changed paths to integration targets grouped by feature set, lib filters, unmapped
    paths, the features gating the touched `src/` modules, and touched workspace member crates."""
    manifest = manifest_at(head)
    defaults = frozenset(manifest.get("features", {}).get("default", []))
    registry = cargo_test_registry(head)
    members = workspace_members(head, manifest)
    groups: dict[str, set[str]] = {}
    lib_filters: list[str] = []
    unmapped: list[str] = []
    src_features: set[str] = set()
    crates: set[str] = set()
    env_gated: set[str] = set()
    existing = set(git("ls-tree", "-r", "--name-only", head, "--", "tests").split())
    sources: dict[str, str] = {}
    tree: dict[str, tuple[str | None, Requirement]] = {}
    if any(p.startswith("src/") and p.endswith(".rs") for p in paths):
        sources = tree_sources(head)
        tree = module_tree(sources, crate_roots(sources, manifest, defaults), defaults)
    for path in sorted(set(paths)):
        member = next((d for d in members if path.startswith(d + "/")), None)
        if member:
            # A root `cargo check --all-targets` builds a member only as a dependency,
            # never its own tests (for the macros crate: its trybuild compile-fail suite).
            crates.add(members[member])
            continue
        if path.startswith("src/"):
            if path not in sources:
                continue  # not Rust, or removed at head: check-default covers the crate
            entry = tree.get(path)
            if entry is None:
                unmapped.append(f"{path} (no crate root reaches it: nothing compiles it)")
            elif entry[1] is None:
                unmapped.append(f"{path} (cfg not understood)")
            elif not entry[1]:
                unmapped.append(f"{path} (its cfg never holds on a Linux worker)")
            else:
                src_features |= chosen_features(entry[1]) or frozenset()
                if entry[0]:
                    lib_filters.append(entry[0])
            continue
        if not path.startswith("tests/") or not path.endswith(".rs") or path not in existing:
            continue
        targets: list[tuple[str, list[str]]] = []
        if path in registry:
            features, understood = file_cfg_features(git("show", f"{head}:{path}", check=False), defaults)
            required = set(registry[path]["features"]) | (set(features) if understood else set())
            targets.append((registry[path]["name"], sorted(required)))
        elif path.count("/") == 1:
            source = git("show", f"{head}:{path}", check=False)
            features, understood = file_cfg_features(source, defaults)
            if not understood:
                unmapped.append(f"{path} (crate cfg not understood)")
                continue
            targets.append((Path(path).stem, features))
        else:
            top = path.split("/")[1]
            owners = [p for p in registry if p.startswith(f"tests/{top}/")]
            for owner in owners:
                features, understood = file_cfg_features(git("show", f"{head}:{owner}", check=False), defaults)
                required = set(registry[owner]["features"]) | (set(features) if understood else set())
                targets.append((registry[owner]["name"], sorted(required)))
            if not owners:
                hits = git("grep", "-lE", rf"^\s*(pub\s+)?mod\s+{re.escape(top)}\s*;", head, "--", "tests/*.rs", check=False)
                for hit in hits.split():
                    file = hit.split(":", 1)[1]
                    if file.count("/") == 1:
                        features, understood = file_cfg_features(git("show", f"{head}:{file}", check=False), defaults)
                        if understood:
                            targets.append((Path(file).stem, features))
            if not targets:
                unmapped.append(f"{path} (no owning test target found)")
        for name, features in targets:
            groups.setdefault(",".join(features), set()).add(name)
            root = next((p for p, e in registry.items() if e["name"] == name), f"tests/{name}.rs")
            if ENV_GATE_RE.search(git("show", f"{head}:{root}", check=False)):
                env_gated.add(name)
    return {
        "groups": {k: sorted(v) for k, v in groups.items()},
        "lib_filters": compress_lib_filters(lib_filters),
        "unmapped": unmapped,
        "src_features": sorted(src_features),
        "crates": sorted(crates),
        "env_gated": sorted(env_gated),
    }


# Test lanes build without debuginfo or incremental state. With full debuginfo the lib
# test's rustc was OOM-killed on the smaller workers (2026-09-25), and linking every
# test binary with it costs time on each bisect probe. What is tested does not change.
LEAN_TEST_ENV = ["env", "CARGO_INCREMENTAL=0", "CARGO_PROFILE_TEST_DEBUG=0"]


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
    mapped = targeted_tests(head, paths)
    groups, lib_filters, unmapped, src_features = mapped["groups"], mapped["lib_filters"], mapped["unmapped"], mapped["src_features"]
    feature_args = ["--features", ",".join(src_features)] if src_features else []
    if src_features:
        # Touched feature-gated modules are invisible to check-default: check every target
        # with the union of their features (a subset-only break needs --with-all-features).
        lanes.insert(
            1,
            {
                "id": "check-features",
                "kind": "build",
                "argv": ["cargo", "check", "-j", str(jobs), "--all-targets", *feature_args, "--keep-going", "--message-format=short"],
            },
        )
    for features, names in sorted(groups.items()):
        argv = [*LEAN_TEST_ENV, "cargo", "test", "-j", str(jobs), "-p", "asupersync", "--no-fail-fast"]
        if features:
            argv += ["--features", features]
        for name in names:
            argv += ["--test", name]
        suffix = features.replace(",", "+") or "default"
        lane = {"id": f"targeted-tests[{suffix}]", "kind": "test", "argv": argv, "expected_targets": names}
        if gated := sorted(set(names) & set(mapped["env_gated"])):
            # These skip their live bodies unless a REAL_* switch is set: green here is not
            # a live-service receipt.
            lane["env_gated_targets"] = gated
        lanes.append(lane)
    if lib_filters:
        lanes.append(
            {
                "id": "targeted-lib",
                "kind": "test",
                "argv": [*LEAN_TEST_ENV, "cargo", "test", "-j", str(jobs), "-p", "asupersync", *feature_args, "--lib", "--", *lib_filters],
                "expected_targets": [],
                "lib_filters": lib_filters,
            }
        )
    for crate in mapped["crates"]:
        lanes.append(
            {
                "id": f"targeted-crate[{crate}]",
                "kind": "test",
                "argv": [*LEAN_TEST_ENV, "cargo", "test", "-j", str(jobs), "-p", crate, "--no-fail-fast"],
                "expected_targets": [],
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
            # A loaded all-targets check at -j 2..4 exceeded 5400 s (RCH-E104) on 2026-09-24.
            RCH_BUILD_TIMEOUT_SEC=env.get("RCH_BUILD_TIMEOUT_SEC", "10800"),
            RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=env.get("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS", "3000"),
            # One target directory per lane: parallel lanes must not share a cargo build lock.
            CARGO_TARGET_DIR=f"{target_dir}_{re.sub(r'[^A-Za-z0-9_.+-]', '_', lane['id'])}",
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


def file_or_queue(
    payloads: list[dict[str, Any]],
    state: dict[str, Any],
    open_issues: list[dict[str, Any]],
    filer: Callable[[dict[str, Any]], str | None],
) -> None:
    """File each red payload once. A failed filing is queued, never lost.

    A red target enters `known_reds` in the run that sees it, so no later run
    produces its payload again. A `br create` that fails (for example while the
    tracker refuses writes) therefore used to drop the P0 for good. Failed
    payloads now wait in `state["pending_beads"]`, and every run retries them
    first. A payload that meanwhile gained an open bead is recorded, not filed.
    """
    pending = state.get("pending_beads", [])
    titles = {p["title"] for p in pending}
    still_pending = []
    for payload in pending + [p for p in payloads if p["title"] not in titles]:
        existing = existing_bead_for(payload["new_targets"], open_issues)
        bead = existing or filer(payload)
        if not bead:
            still_pending.append(payload)
            continue
        payload["existing_bead" if existing else "filed_bead"] = bead
        for target in payload["new_targets"]:
            entry = state["known_reds"].get(payload["lane"], {}).get(target)
            if entry is not None:
                entry["bead"] = bead
    state["pending_beads"] = still_pending


def file_or_queue_rounds(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate helper: successive `file_or_queue` runs sharing one state.

    Each round lists the payload titles whose `br create` fails. Any other
    title is filed as `filed:<title>`.
    """
    state = case["state"]
    rounds = []
    for round_ in case["rounds"]:
        fail = set(round_.get("fail_titles", []))
        file_or_queue(
            round_.get("payloads", []),
            state,
            round_.get("open_issues", []),
            lambda payload, fail=fail: None if payload["title"] in fail else f"filed:{payload['title']}",
        )
        rounds.append(
            {
                "pending": [p["title"] for p in state["pending_beads"]],
                "beads": {
                    lane: {target: entry.get("bead") for target, entry in targets.items()}
                    for lane, targets in state["known_reds"].items()
                },
            }
        )
    return rounds


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


# ---------------------------------------------------------------------------
# Ledgers (asupersync-bi2462.147.1): receipt latency, first runs, stranded work,
# duplicate fixes. Pure functions; `evaluate` drives them from scenarios.
# ---------------------------------------------------------------------------

RECEIPT_DUE = dt.timedelta(hours=2)
RECEIPT_ESCALATE = dt.timedelta(hours=6)
STRANDED_AFTER = dt.timedelta(hours=2)
MAX_BEHIND = 5
# Beads that commits cite for process rather than for the change itself.
PROCESS_BEADS = {WATCHDOG_BEAD, "asupersync-bi2462.162"}
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")


def _hours(delta: dt.timedelta) -> float:
    return round(delta.total_seconds() / 3600, 1)


def owes_receipt(commit: dict[str, Any]) -> bool:
    """Validation Path rule 3: a commit landed without a compile path that touches code."""
    no_compile_path = is_web_api_identity(commit["author_email"]) or declares_not_compiled(commit["message"])
    return no_compile_path and not commit.get("is_merge") and any(is_code_path(p) for p in commit["paths"])


def watchdog_runs(receipts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Lane receipts grouped into runs (one head checked at one time), oldest first."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for receipt in receipts:
        grouped.setdefault((receipt["recorded_at"], receipt["sha"]), []).append(receipt)
    return [
        {
            "head": head,
            "recorded_at": recorded,
            "green": all(r["verdict"] == VERDICT_GREEN for r in rs),
            "red": any(r["verdict"] == VERDICT_RED for r in rs),
            "culprits": sorted({r["culprit"] for r in rs if r.get("culprit")}),
        }
        for (recorded, head), rs in sorted(grouped.items())
    ]


def receipt_ledger(commits: list[dict[str, Any]], receipts: list[dict[str, Any]], now: dt.datetime) -> dict[str, Any]:
    """Heal latency for every commit that owes a rule-3 receipt; `commits` oldest first.

    A run covers a commit when its head is that commit or a later one. A commit is green
    at the first all-green covering run, and red when a run names it as the culprit. It
    is blocked while its latest covering run is red for another commit, because that red
    has its own P0. Otherwise it is pending until 2 h, overdue until 6 h, and escalated
    after that.
    """
    order = {c["sha"]: i for i, c in enumerate(commits)}
    runs = [run for run in watchdog_runs(receipts) if run["head"] in order]
    rows = []
    for index, commit in enumerate(commits):
        if not owes_receipt(commit):
            continue
        landed = dt.datetime.fromisoformat(commit["committed_at"])
        covering = [run for run in runs if order[run["head"]] >= index]
        green = next((run for run in covering if run["green"]), None)
        row: dict[str, Any] = {
            "sha": commit["sha"],
            "subject": commit["subject"],
            "author_email": commit["author_email"],
            "beads": commit["beads"],
            "landed_at": commit["committed_at"],
            "age_h": _hours(now - landed),
        }
        if green:
            row.update(status="green", receipt_at=green["recorded_at"], latency_h=_hours(dt.datetime.fromisoformat(green["recorded_at"]) - landed))
        elif any(commit["sha"] in run["culprits"] for run in covering):
            row["status"] = "red"
        elif covering and covering[-1]["red"]:
            row.update(status="blocked", blocked_by=covering[-1]["culprits"])
        else:
            age = now - landed
            row["status"] = "pending" if age < RECEIPT_DUE else "overdue" if age < RECEIPT_ESCALATE else "escalate"
        rows.append(row)
    return {
        "owed": len(rows),
        "green_within_2h": sum(1 for r in rows if r["status"] == "green" and r["latency_h"] <= _hours(RECEIPT_DUE)),
        "overdue": [r["sha"] for r in rows if r["status"] == "overdue"],
        "escalate": [r["sha"] for r in rows if r["status"] == "escalate"],
        "rows": rows,
    }


def receipt_escalation_payload(row: dict[str, Any]) -> dict[str, Any]:
    sha9 = row["sha"][:9]
    cited = ", ".join(row["beads"]) or "none"
    description = (
        f"**Validation Path rule 3 (AGENTS.md):** `{row['sha']}` landed at {row['landed_at']} without a compile path "
        f"and has no green main-watchdog receipt after {row['age_h']} h.\n\n"
        f"- Subject: {row['subject']}\n"
        f"- Author identity: {row['author_email']}\n"
        f"- Cited beads: {cited}\n\n"
        "Heal owner: the cited bead's assignee, else the watchdog operator. Repair forward and cite the new receipt. "
        "The watchdog does not revert or edit anyone's code; reverting someone else's commit needs the owner.\n"
    )
    return {
        "title": f"[main-watchdog] NO GREEN RECEIPT after 6 h: {sha9} ({row['author_email']}) {row['subject'][:80]}"[:240],
        "type": "bug",
        "priority": 0,
        "labels": ["main-watchdog", "rule-3"],
        "parent": WATCHDOG_BEAD,
        "description": description,
        "sha": row["sha"],
    }


def first_run_ledger(added_targets: list[str], receipts: list[dict[str, Any]]) -> dict[str, Any]:
    """Test targets added since a baseline that no watchdog lane has executed (>0 tests)."""
    executed = {t for r in receipts for t in r.get("targets_executed", [])}
    never = sorted(t for t in set(added_targets) if t not in executed)
    return {"added": len(set(added_targets)), "never_run": never}


def stranded_alerts(tree: dict[str, Any], now: dt.datetime) -> list[str]:
    """Alerts for work stuck in the shared tree: unpushed past 2 h, or far behind origin."""
    alerts = []
    oldest = tree.get("oldest_unpushed_at")
    if tree.get("ahead") and oldest and now - dt.datetime.fromisoformat(oldest) > STRANDED_AFTER:
        beads = ", ".join(tree.get("oldest_unpushed_beads") or []) or "none cited"
        alerts.append(
            f"stranded: main is {tree['ahead']} commit(s) ahead of origin/main; the oldest unpushed commit is "
            f"{_hours(now - dt.datetime.fromisoformat(oldest))} h old (beads: {beads})"
        )
    if tree.get("landed_elsewhere"):
        alerts.append(
            f"stale: {tree['landed_elsewhere']} commit(s) on the shared main are already on origin under other SHAs; "
            "the shared checkout is not tracking origin"
        )
    if tree.get("behind", 0) > MAX_BEHIND:
        alerts.append(f"behind: main is {tree['behind']} commits behind origin/main")
    return alerts


def diff_hunks(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Old-side line ranges per file from a `git diff -U0` / `git show -U0` text."""
    hunks: dict[str, list[tuple[int, int]]] = {}
    path = None
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            path = line.rsplit(" b/", 1)[-1]
        elif path and (match := HUNK_RE.match(line)):
            start, count = int(match.group(1)), int(match.group(2) or 1)
            hunks.setdefault(path, []).append((start, start + max(count, 1) - 1))
    return hunks


def duplicate_fixes(origin_items: list[dict[str, Any]], local_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pairs of (origin commit, local commit or uncommitted diff) citing the same change bead or
    changing overlapping old-side lines of one file. Line numbers come from different bases,
    so an overlap is a lead to check, not proof."""
    flags = []
    for origin in origin_items:
        for local in local_items:
            beads = sorted((set(origin["beads"]) & set(local["beads"])) - PROCESS_BEADS)
            overlapping = sorted(
                path
                for path, ranges in local["hunks"].items()
                if any(a0 <= b1 and b0 <= a1 for a0, a1 in ranges for b0, b1 in origin["hunks"].get(path, []))
            )
            if beads or overlapping:
                flags.append({"origin": origin["id"], "local": local["id"], "beads": beads, "overlapping_files": overlapping})
    return flags


def shared_tree_state() -> dict[str, Any]:
    """The shared checkout's `main` against origin, and its dirty paths by last-modified time.

    A local commit whose patch (`git cherry`) or subject is already on origin under another
    SHA is counted as landed elsewhere, not as stranded work.
    """
    ahead = git("log", "--reverse", "--format=%H%x09%cI%x09%s", "origin/main..main", check=False).splitlines()
    upstream_subjects = set(git("log", "--format=%s", "main..origin/main", check=False).splitlines())
    equivalent = {line[2:] for line in git("cherry", "origin/main", "main", check=False).splitlines() if line.startswith("- ")}
    unpushed = []
    landed_elsewhere = 0
    for line in ahead:
        sha, committed, subject = (line.split("\t", 2) + ["", ""])[:3]
        if sha in equivalent or subject in upstream_subjects:
            landed_elsewhere += 1
        else:
            unpushed.append((sha, committed))
    oldest = unpushed[0] if unpushed else None
    dirty = []
    for line in git("status", "--porcelain", check=False).splitlines():
        path = line[3:].split(" -> ")[-1]
        try:
            modified = dt.datetime.fromtimestamp(os.path.getmtime(path), dt.timezone.utc).isoformat(timespec="seconds")
        except OSError:
            modified = None
        dirty.append({"path": path, "modified_at": modified})
    return {
        "ahead": len(unpushed),
        "landed_elsewhere": landed_elsewhere,
        "behind": int(git("rev-list", "--count", "main..origin/main", check=False).strip() or 0),
        "oldest_unpushed_at": oldest[1] if oldest else None,
        "oldest_unpushed_beads": bead_ids(git("log", "-1", "--format=%B", oldest[0], check=False)) if oldest else [],
        "dirty": sorted(dirty, key=lambda d: d["modified_at"] or ""),
    }


def _rust_hunks(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    return {path: ranges for path, ranges in diff_hunks(diff_text).items() if path.endswith(".rs")}


def duplicate_fix_items(window: str = "72.hours") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Origin commits of the last `window` that the shared tree lacks, and the shared tree's
    unpushed commits plus its diff. An origin commit the tree already contains cannot be
    duplicated by work built on top of it."""
    def item(label: str, sha: str) -> dict[str, Any]:
        return {
            "id": label,
            "beads": bead_ids(git("log", "-1", "--format=%B", sha, check=False)),
            "hunks": _rust_hunks(git("show", "-U0", "--format=", sha, check=False)),
        }

    origin = [item(sha[:9], sha) for sha in git("rev-list", "--first-parent", f"--since={window}", "main..origin/main", check=False).split()]
    local = [item(f"local {sha[:9]}", sha) for sha in git("rev-list", "origin/main..main", check=False).split()]
    working = _rust_hunks(git("diff", "-U0", "HEAD", check=False))
    for path in list(working):
        # A dirty file already byte-identical to origin is landed work in a stale checkout,
        # not a second fix.
        blob = git("rev-parse", "-q", "--verify", f"origin/main:{path}", check=False).strip()
        if blob and git("hash-object", "--", path, check=False).strip() == blob:
            del working[path]
    if working:
        local.append({"id": "working tree", "beads": [], "hunks": working})
    return origin, local


DECISION_RE = re.compile(r"\bOWNER DECISION\b|\brecorded verbatim\b|^Release owner decision:", re.MULTILINE)
DECISION_DUE = dt.timedelta(hours=48)


def decision_ledger(issues: list[dict[str, Any]], commits: list[dict[str, Any]], now: dt.datetime) -> list[dict[str, Any]]:
    """Owner decisions recorded in bead comments, and the first commit citing that bead after them.

    A decision is a comment carrying an explicit marker ("OWNER DECISION", "recorded
    verbatim", "Release owner decision:"); a passing mention of the phrase is not one.
    Status: implemented (a later commit cites the bead), closed (settled in the tracker
    without one), pending (under 48 h), or stale.
    """
    rows = []
    for issue in issues:
        for comment in issue.get("comments") or []:
            text = comment.get("text") or comment.get("body") or ""
            if not DECISION_RE.search(text):
                continue
            decided = dt.datetime.fromisoformat(str(comment.get("created_at")).replace("Z", "+00:00"))
            later = sorted(
                (dt.datetime.fromisoformat(c["committed_at"]), c["sha"])
                for c in commits
                if issue["id"] in c["beads"] and dt.datetime.fromisoformat(c["committed_at"]) > decided
            )
            row = {"bead": issue["id"], "decided_at": decided.isoformat(), "age_h": _hours(now - decided)}
            if later:
                row.update(status="implemented", implemented_by=later[0][1])
            elif issue.get("status") in ("closed", "tombstone"):
                row["status"] = "closed"  # settled in the tracker; no citing commit required
            else:
                row["status"] = "pending" if now - decided < DECISION_DUE else "stale"
            rows.append(row)
    return sorted(rows, key=lambda r: r["decided_at"])


def recent_commits(days: int = 30) -> list[dict[str, Any]]:
    """Origin commits of the last `days`, with committer time and cited beads."""
    out = git("log", "--first-parent", f"--since={days}.days", "--format=%H%x1f%cI%x1f%B%x1e", "origin/main", check=False)
    commits = []
    for record in out.split("\x1e"):
        parts = record.strip("\n").split("\x1f")
        if len(parts) == 3:
            commits.append({"sha": parts[0], "committed_at": parts[1], "beads": bead_ids(parts[2])})
    return commits


def recent_issues(issues_path: Path, days: int = 30, now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Tracker rows (open or closed) updated within `days`."""
    now = now or dt.datetime.now(dt.timezone.utc)
    rows = []
    try:
        lines = issues_path.read_text().splitlines()
    except FileNotFoundError:
        return rows
    for line in lines:
        try:
            issue = json.loads(line)
            updated = dt.datetime.fromisoformat(str(issue.get("updated_at")).replace("Z", "+00:00"))
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(issue, dict) and now - updated <= dt.timedelta(days=days):
            rows.append(issue)
    return rows


def added_test_targets(since: str, until: str) -> list[str]:
    """Integration test targets whose root file was added in since..until."""
    registry = cargo_test_registry(until)
    added = git("diff", "--diff-filter=A", "--name-only", f"{since}..{until}", "--", "tests", check=False).split()
    names = []
    for path in added:
        if path in registry:
            names.append(registry[path]["name"])
        elif path.count("/") == 1 and path.endswith(".rs"):
            names.append(Path(path).stem)
    return sorted(set(names))


def ledger_commits(since: str, until: str) -> list[dict[str, Any]]:
    return [commit_record(s, scan_unsafe=False) for s in git("rev-list", "--reverse", "--first-parent", f"{since}..{until}").split()]


def escalate_overdue_receipts(state: dict[str, Any], receipts_path: Path, now: dt.datetime, file_beads: bool) -> list[dict[str, Any]]:
    """File one P0 per commit with no green receipt 6 h after landing (rule 3).

    Only commits after `state["ledger_since"]` count, so work that landed before the
    watchdog covered main is not flooded with beads; with no `ledger_since`, nothing
    escalates. A commit is escalated once (`state["receipt_escalations"]`) and never when
    an open bead already names it.
    """
    since = state.get("ledger_since")
    if not since:
        return []
    receipts = [json.loads(line) for line in receipts_path.read_text().splitlines() if line.strip()] if receipts_path.exists() else []
    ledger = receipt_ledger(ledger_commits(since, "origin/main"), receipts, now)
    filed = state.setdefault("receipt_escalations", {})
    open_issues = open_tracker_issues()
    payloads = []
    for row in ledger["rows"]:
        if row["status"] != "escalate" or row["sha"] in filed:
            continue
        payload = receipt_escalation_payload(row)
        existing = next(
            (i.get("id") for i in open_issues if "NO GREEN RECEIPT" in i.get("title", "") and row["sha"][:9] in i.get("title", "")),
            None,
        )
        if existing:
            payload["existing_bead"] = filed[row["sha"]] = existing
        elif file_beads and (bead := file_bead(payload)):
            payload["filed_bead"] = filed[row["sha"]] = bead
        payloads.append(payload)
    return payloads


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
        "receipt_ledger": receipt_ledger(ledger_commits(since, until), receipts, now),
        "first_run_ledger": first_run_ledger(added_test_targets(since, until), receipts),
        "stranded_alerts": stranded_alerts(shared_tree_state(), now),
        "duplicate_fixes": duplicate_fixes(*duplicate_fix_items()),
        "owner_decisions": [
            row
            for row in decision_ledger(recent_issues(issues_path, now=now), recent_commits(), now)
            if row["status"] in ("pending", "stale")
        ],
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
            p.add_argument("--parallel", type=int, default=2, help="head lanes run concurrently (RCH admits ~2-3 per project)")
            p.add_argument(
                "--ledger-since",
                help="record in state: rule-3 receipt escalation counts commits after this SHA (unset: no escalation)",
            )
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
            scenario.get("parallel", 1),
        )
        probes = scenario.get("probes", {})
        result["probe_results"] = {
            "declares_not_compiled": [declares_not_compiled(m) for m in probes.get("declares_not_compiled", [])],
            "bead_ids": [bead_ids(m, set(probes["known_ids"]) if "known_ids" in probes else None) for m in probes.get("bead_ids", [])],
            "file_cfg_features": [list(file_cfg_features(s)) for s in probes.get("file_cfg_features", [])],
            "cfg_requirement": [requirement_json(cfg_requirement(e, frozenset(probes.get("defaults", [])))) for e in probes.get("cfg_requirement", [])],
            "module_tree": {
                path: [modpath, requirement_json(req)]
                for path, (modpath, req) in module_tree(
                    probes.get("module_tree", {}).get("sources", {}),
                    {root: TRUE for root in probes.get("module_tree", {}).get("roots", [])},
                    frozenset(probes.get("defaults", [])),
                ).items()
            },
            "lib_filter_for": [lib_filter_for(p) for p in probes.get("lib_filter_for", [])],
            "receipt_ledger": [
                {
                    "ledger": (ledger := receipt_ledger(case["commits"], case["receipts"], dt.datetime.fromisoformat(case["now"]))),
                    "payloads": [receipt_escalation_payload(row) for row in ledger["rows"] if row["status"] == "escalate"],
                }
                for case in probes.get("receipt_ledger", [])
            ],
            "first_run_ledger": [first_run_ledger(case["added"], case["receipts"]) for case in probes.get("first_run_ledger", [])],
            "stranded_alerts": [stranded_alerts(case["tree"], dt.datetime.fromisoformat(case["now"])) for case in probes.get("stranded", [])],
            "duplicate_fixes": [duplicate_fixes(case["origin"], case["local"]) for case in probes.get("duplicate_fixes", [])],
            "diff_hunks": [diff_hunks(text) for text in probes.get("diff_hunks", [])],
            "target_root_paths": [
                target_root_paths(case["name"], case.get("registry", {})) for case in probes.get("target_root_paths", [])
            ],
            "decision_ledger": [
                decision_ledger(case["issues"], case["commits"], dt.datetime.fromisoformat(case["now"]))
                for case in probes.get("decision_ledger", [])
            ],
            "existing_bead_for": [
                existing_bead_for(case["new_targets"], case["open_issues"]) for case in probes.get("existing_bead_for", [])
            ],
            "file_or_queue": [file_or_queue_rounds(case) for case in probes.get("file_or_queue", [])],
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
    args.state_dir.mkdir(parents=True, exist_ok=True)
    if args.ledger_since:
        state["ledger_since"] = args.ledger_since
    if not plan["commits"]:
        if args.file_beads and state.get("pending_beads"):
            file_or_queue([], state, open_tracker_issues(), file_bead)
        escalations = escalate_overdue_receipts(state, args.state_dir / "receipts.jsonl", now, args.file_beads)
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True))
        print(json.dumps({"schema": SCHEMA_VERSION, "status": "no new commits", "since": plan["since"], "receipt_escalations": escalations}))
        return 0
    runner = rch_runner(str(args.state_dir / "target"), args.admission_attempts, args.admission_sleep, args.state_dir / "logs")
    result = run_engine(plan, runner, state, now.isoformat(), git_target_exists, args.parallel)
    if args.file_beads:
        file_or_queue(result["bead_payloads"], state, open_tracker_issues(), file_bead)
    if args.post_receipts:
        post_receipts(plan, result["receipts"])
    with open(args.state_dir / "receipts.jsonl", "a", encoding="utf-8") as handle:
        for receipt in result["receipts"]:
            handle.write(json.dumps(receipt, sort_keys=True) + "\n")
    result["receipt_escalations"] = escalate_overdue_receipts(state, args.state_dir / "receipts.jsonl", now, args.file_beads)
    state_path.write_text(json.dumps(state, indent=2, sort_keys=True))
    json.dump({"plan_flags": plan["flags"], "unmapped_paths": plan["unmapped_paths"], **result}, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 1 if any(r["verdict"] == VERDICT_RED for r in result["receipts"]) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
