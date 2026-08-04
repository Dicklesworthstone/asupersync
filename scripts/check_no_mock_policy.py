#!/usr/bin/env python3
"""Enforce implementation-completeness policy with allowlist + waiver expiry checks."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    text: str
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class ClassifiedPath:
    path: str
    category: str
    owner: str
    hits: tuple[Hit, ...]


REQUIRES_REPLACEMENT_ISSUE = {
    "conformance_placeholder",
    "production_stub",
    "stale_audit_prose",
}
TERM_MOCK = "mo" + "ck"
TERM_FAKE = "fa" + "ke"
TERM_STUB = "st" + "ub"
TERM_PLACEHOLDER = "place" + "holder"
TERM_DEFERRED = "to" + "do"
TERM_UNIMPLEMENTED = "un" + "implemented"


def no_mock_label() -> str:
    return f"no-{TERM_MOCK}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/no_mock_policy.json",
        help="Path to implementation-completeness policy JSON",
    )
    parser.add_argument(
        "--report-json",
        type=pathlib.Path,
        help="Optional path for a machine-readable categorized report",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=50,
        help="Maximum per-path console errors before truncating; report JSON still contains all",
    )
    parser.add_argument(
        "--self-test-negative-fixture",
        action="store_true",
        help="Run an isolated negative fixture proving invalid conformance fails the policy",
    )
    parser.add_argument(
        "--self-test-policy-fixtures",
        action="store_true",
        help="Run policy parser/classifier fixtures against isolated repos",
    )
    return parser.parse_args()


def parse_iso8601_utc(raw: str) -> dt.datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {raw}")
    return parsed.astimezone(dt.timezone.utc)


def load_policy(policy_path: pathlib.Path) -> dict:
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != f"{no_mock_label()}-policy-v1":
        raise ValueError("unsupported or missing schema_version")
    if not isinstance(data.get("allowlist_paths"), list):
        raise ValueError("allowlist_paths must be a list")
    if not isinstance(data.get("allowlist_entries", []), list):
        raise ValueError("allowlist_entries must be a list")
    if not isinstance(data.get("allowlist_groups", []), list):
        raise ValueError("allowlist_groups must be a list")
    if not isinstance(data.get("waivers"), list):
        raise ValueError("waivers must be a list")
    if not isinstance(data.get("owner_routes"), list):
        raise ValueError("owner_routes must be a list")
    if not isinstance(data.get("classification_rules", []), list):
        raise ValueError("classification_rules must be a list")
    validate_structured_allowlist(data)
    return data


def require_justified_text(entry: dict[str, Any], label: str, subject: str) -> None:
    """Validate the optional `justified_text` narrowing field.

    Absent means "cover the whole path", which is the historical behavior. When
    present it must be a non-empty list of compilable regexes; anything else is
    a load-time error rather than a silently ignored field, because a typo that
    disabled narrowing would restore whole-file coverage without saying so.
    """
    raw = entry.get("justified_text")
    if raw is None:
        return
    if not isinstance(raw, list) or not raw:
        raise ValueError(
            f"{label} entry for {subject} justified_text must be a non-empty list of regexes"
        )
    for pattern in raw:
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(
                f"{label} entry for {subject} justified_text entries must be non-empty strings"
            )
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(
                f"{label} entry for {subject} justified_text regex {pattern!r} is invalid: {error}"
            ) from error


def require_metadata(entry: dict[str, Any], label: str) -> None:
    pattern = entry.get("pattern", entry.get("path"))
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"{label} entry must include non-empty path or pattern")
    for field in ("category", "owner", "reason"):
        if not isinstance(entry.get(field), str) or not entry[field]:
            raise ValueError(f"{label} entry for {pattern} must include {field}")
    require_justified_text(entry, label, pattern)
    if not (
        isinstance(entry.get("expires_at_utc"), str)
        or isinstance(entry.get("revisit_condition"), str)
    ):
        raise ValueError(
            f"{label} entry for {pattern} must include expires_at_utc or revisit_condition"
        )
    category = entry.get("category")
    if (
        category in REQUIRES_REPLACEMENT_ISSUE
        and not isinstance(entry.get("replacement_issue"), str)
    ):
        raise ValueError(
            f"{label} entry for {pattern} category={category} must include replacement_issue"
        )


def require_group_metadata(group: dict[str, Any], label: str) -> None:
    group_id = group.get("group_id")
    if not isinstance(group_id, str) or not group_id:
        raise ValueError(f"{label} entry must include non-empty group_id")
    patterns = group.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        raise ValueError(f"{label} entry {group_id} must include non-empty patterns")
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"{label} entry {group_id} patterns must be non-empty strings")
    for field in ("category", "owner", "reason"):
        if not isinstance(group.get(field), str) or not group[field]:
            raise ValueError(f"{label} entry {group_id} must include {field}")
    require_justified_text(group, label, group_id)
    if not (
        isinstance(group.get("expires_at_utc"), str)
        or isinstance(group.get("revisit_condition"), str)
    ):
        raise ValueError(
            f"{label} entry {group_id} must include expires_at_utc or revisit_condition"
        )
    category = group.get("category")
    if (
        category in REQUIRES_REPLACEMENT_ISSUE
        and not isinstance(group.get("replacement_issue"), str)
    ):
        raise ValueError(
            f"{label} entry {group_id} category={category} must include replacement_issue"
        )


def validate_structured_allowlist(policy: dict) -> None:
    seen: set[tuple[str, str, str]] = set()
    for entry in policy.get("allowlist_entries", []):
        require_metadata(entry, "allowlist_entries")
        key = ("allowlist_entries", str(entry.get("category")), entry_pattern(entry))
        if key in seen:
            raise ValueError(f"duplicate allowlist entry for {key[1]} {key[2]}")
        seen.add(key)
    for group in policy.get("allowlist_groups", []):
        require_group_metadata(group, "allowlist_groups")
        for entry in expand_allowlist_group(group):
            key = ("allowlist_entries", str(entry.get("category")), entry_pattern(entry))
            if key in seen:
                raise ValueError(f"duplicate allowlist entry for {key[1]} {key[2]}")
            seen.add(key)
    for waiver in policy.get("waivers", []):
        require_metadata(waiver, "waivers")
        if not isinstance(waiver.get("status"), str):
            raise ValueError("waiver entries must include status")
        key = ("waivers", str(waiver.get("category")), entry_pattern(waiver))
        if key in seen:
            raise ValueError(f"duplicate waiver entry for {key[1]} {key[2]}")
        seen.add(key)


def run_scan(
    roots: Iterable[str],
    terms: list[str],
    cwd: pathlib.Path | None = None,
) -> list[Hit]:
    escaped = [re.escape(term) for term in terms]
    token_re = re.compile(rf"(?i)\b({'|'.join(escaped)})\b")

    if shutil.which("rg") is None:
        return run_scan_without_ripgrep(roots, token_re, cwd=cwd)

    cmd = ["rg", "--line-number", "--no-heading", "--color", "never"]
    for term in terms:
        cmd += ["-e", rf"(?i)\b{re.escape(term)}\b"]
    cmd += list(roots)

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=cwd)
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr)
        raise RuntimeError("ripgrep scan failed")
    if proc.returncode == 1:
        return []

    return parse_scan_rows(proc.stdout.splitlines(), token_re)


def parse_scan_rows(rows: Iterable[str], token_re: re.Pattern[str]) -> list[Hit]:
    hits: list[Hit] = []
    for row in rows:
        parts = row.split(":", 2)
        if len(parts) != 3:
            continue
        path, line_raw, text = parts
        try:
            line = int(line_raw)
        except ValueError:
            continue
        tokens = tuple(sorted({m.group(1).lower() for m in token_re.finditer(text)}))
        if not tokens:
            continue
        hits.append(Hit(path=path, line=line, text=text, tokens=tokens))
    return hits


def run_scan_without_ripgrep(
    roots: Iterable[str],
    token_re: re.Pattern[str],
    cwd: pathlib.Path | None = None,
) -> list[Hit]:
    base = cwd if cwd is not None else pathlib.Path.cwd()
    hits: list[Hit] = []

    for root in roots:
        root_path = base / root
        if root_path.is_file():
            candidates = [root_path]
        elif root_path.is_dir():
            candidates = sorted(path for path in root_path.rglob("*") if path.is_file())
        else:
            continue

        for path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel_path = path.relative_to(base).as_posix()
            for line_number, line in enumerate(text.splitlines(), start=1):
                tokens = tuple(sorted({m.group(1).lower() for m in token_re.finditer(line)}))
                if tokens:
                    hits.append(
                        Hit(path=rel_path, line=line_number, text=line, tokens=tokens)
                    )

    return hits


_IDENT_CHAR_RE = re.compile(r"[A-Za-z0-9_]")
_RAW_STRING_PREFIX_RE = re.compile(r"b?r(?P<hashes>#*)\"")
_ATTRIBUTE_OPEN_RE = re.compile(r"#!?\[")


def _char_literal_end(source: str, after_quote: int) -> int | None:
    """Return the offset just past a char literal opened before `after_quote`.

    Returns ``None`` when the quote opens a lifetime or loop label instead of a
    literal, which is the only other legal meaning of ``'`` in Rust.
    """
    n = len(source)
    if after_quote >= n:
        return None
    if source[after_quote] == "\\":
        cursor = after_quote + 1
        if cursor >= n:
            return None
        escape = source[cursor]
        if escape == "u":
            if cursor + 1 >= n or source[cursor + 1] != "{":
                return None
            brace = source.find("}", cursor + 1)
            if brace < 0:
                return None
            cursor = brace + 1
        elif escape == "x":
            cursor += 3
        else:
            cursor += 1
        if cursor < n and source[cursor] == "'":
            return cursor + 1
        return None
    if after_quote + 1 < n and source[after_quote + 1] == "'":
        return after_quote + 2
    return None


def rust_code_mask(source: str) -> bytearray | None:
    """Mark every character of `source` as code (1) or not-code (0).

    Not-code means the character sits inside a line comment, a (nestable) block
    comment, a string/byte-string/raw-string literal, or a char literal. The
    mask exists so brace matching and attribute detection never trip over a
    brace that lives inside a doc comment or a formatted string.

    Returns ``None`` when the source cannot be lexed unambiguously (unterminated
    comment or literal). Callers must treat ``None`` as "no test regions here",
    never as "no test regions needed".
    """
    n = len(source)
    mask = bytearray(b"\x01" * n)
    i = 0

    while i < n:
        char = source[i]

        if char == "/" and i + 1 < n and source[i + 1] == "/":
            end = source.find("\n", i)
            end = n if end < 0 else end
            for offset in range(i, end):
                mask[offset] = 0
            i = end
            continue

        if char == "/" and i + 1 < n and source[i + 1] == "*":
            start = i
            depth = 0
            while i < n:
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                elif source.startswith("*/", i):
                    depth -= 1
                    i += 2
                    if depth == 0:
                        break
                else:
                    i += 1
            if depth != 0:
                return None
            for offset in range(start, i):
                mask[offset] = 0
            continue

        prev_is_ident = i > 0 and _IDENT_CHAR_RE.match(source[i - 1]) is not None

        if char in "rb" and not prev_is_ident:
            raw = _RAW_STRING_PREFIX_RE.match(source, i)
            if raw is not None:
                terminator = '"' + raw.group("hashes")
                end = source.find(terminator, raw.end())
                if end < 0:
                    return None
                end += len(terminator)
                for offset in range(i, end):
                    mask[offset] = 0
                i = end
                continue

        opens_string = char == '"' or (
            char == "b" and not prev_is_ident and i + 1 < n and source[i + 1] == '"'
        )
        if opens_string:
            start = i
            i += 1 if char == '"' else 2
            closed = False
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == '"':
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                return None
            for offset in range(start, i):
                mask[offset] = 0
            continue

        opens_quote = char == "'" or (
            char == "b" and not prev_is_ident and i + 1 < n and source[i + 1] == "'"
        )
        if opens_quote:
            start = i
            after_quote = i + (1 if char == "'" else 2)
            end = _char_literal_end(source, after_quote)
            if end is None:
                # Lifetime (`'a`) or loop label (`'outer:`): stay in code.
                i = after_quote
                continue
            for offset in range(start, end):
                mask[offset] = 0
            i = end
            continue

        i += 1

    return mask


def _skip_code_whitespace(source: str, mask: bytearray, i: int) -> int:
    n = len(source)
    while i < n and (mask[i] == 0 or source[i].isspace()):
        i += 1
    return i


def _parse_cfg_predicate(
    source: str, mask: bytearray, after_open: int
) -> tuple[str, int] | None:
    """Parse `cfg(<predicate>)]` starting just past an attribute's `#[` / `#![`.

    Returns ``(predicate, offset_past_closing_bracket)`` or ``None`` when the
    attribute is not a `cfg` attribute (including `cfg_attr`) or is malformed.
    """
    n = len(source)
    cursor = _skip_code_whitespace(source, mask, after_open)
    if not source.startswith("cfg", cursor):
        return None
    cursor += 3
    # `cfg_attr(...)` and any other `cfg`-prefixed identifier are not `cfg`.
    if cursor < n and _IDENT_CHAR_RE.match(source[cursor]) is not None:
        return None
    cursor = _skip_code_whitespace(source, mask, cursor)
    if cursor >= n or source[cursor] != "(" or mask[cursor] == 0:
        return None

    depth = 0
    predicate_start = cursor + 1
    while cursor < n:
        if mask[cursor] != 0:
            if source[cursor] == "(":
                depth += 1
            elif source[cursor] == ")":
                depth -= 1
                if depth == 0:
                    break
        cursor += 1
    if depth != 0 or cursor >= n:
        return None

    predicate = source[predicate_start:cursor]
    cursor = _skip_code_whitespace(source, mask, cursor + 1)
    if cursor >= n or source[cursor] != "]" or mask[cursor] == 0:
        return None
    return (predicate, cursor + 1)


def _split_top_level_commas(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return parts


def cfg_predicate_is_test_only(predicate: str) -> bool:
    """True only when the predicate can never hold in a non-test build.

    `test` and `all(test, ...)` qualify. `any(test, ...)` deliberately does not:
    it also holds when the other disjunct holds, so the guarded item does reach
    production builds. Anything unrecognised is treated as reaching production.
    """
    stripped = predicate.strip()
    if stripped == "test":
        return True
    if not stripped.startswith("all"):
        return False
    rest = stripped[3:].lstrip()
    if not rest.startswith("(") or not rest.endswith(")"):
        return False
    return any(arg.strip() == "test" for arg in _split_top_level_commas(rest[1:-1]))


def _item_extent(source: str, mask: bytearray, i: int) -> tuple[int, bool] | None:
    """Find the end of the item an outer attribute ending at `i` applies to.

    Returns ``(end_offset, is_braced)``, or ``None`` when the extent is ambiguous
    and the caller must fail closed.

    A `;` at brace-depth 0 ends a statement item. This is why depth matters
    rather than "first brace wins": `use crate::foo::{A, B};` opens braces that
    are part of a path, not a body, so the item still ends at its semicolon.
    Otherwise the first balanced top-level `{...}` is the body, confirmed once
    any further code follows it (or the file ends).
    """
    n = len(source)
    cursor = i
    depth = 0
    first_close: int | None = None

    while cursor < n:
        if mask[cursor] != 0:
            char = source[cursor]
            if char == "{":
                if depth == 0 and first_close is not None:
                    return (first_close, True)
                depth += 1
            elif char == "}":
                if depth == 0:
                    # The enclosing block is closing. If the item's own body
                    # already closed, that body is the extent; otherwise the
                    # attribute had no resolvable item.
                    return (first_close, True) if first_close is not None else None
                depth -= 1
                if depth == 0 and first_close is None:
                    first_close = cursor
            elif depth == 0:
                if char == ";":
                    return (cursor, False)
                if first_close is not None and not char.isspace():
                    return (first_close, True)
        cursor += 1

    if first_close is not None:
        return (first_close, True)
    return None


def _line_start(source: str, offset: int) -> int:
    newline = source.rfind("\n", 0, offset)
    return 0 if newline < 0 else newline + 1


def _indent_width(source: str, offset: int) -> int | None:
    """Indent column of `offset`, or None when other text precedes it on the line."""
    start = _line_start(source, offset)
    if any(char not in " \t" for char in source[start:offset]):
        return None
    return offset - start


def cfg_test_regions(source: str) -> list[tuple[int, int]] | None:
    """Inclusive 1-based line ranges gated by a test-only `#[cfg(...)]`.

    Returns ``None`` when any part of the file cannot be resolved unambiguously,
    which callers must read as "classify every hit in this file as production".

    Braced regions are cross-checked against rustfmt's layout: the closing brace
    must open its own line at exactly the attribute's indent column. That is a
    second, independent witness for the extent the lexer computed, so a lexer
    that silently drifted past the real close cannot quietly widen a test region
    over production code.
    """
    mask = rust_code_mask(source)
    if mask is None:
        return None

    total_lines = source.count("\n") + 1
    regions: list[tuple[int, int]] = []
    depth = 0
    depth_cursor = 0

    for match in _ATTRIBUTE_OPEN_RE.finditer(source):
        start = match.start()
        while depth_cursor < start:
            if mask[depth_cursor] != 0:
                char = source[depth_cursor]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            depth_cursor += 1

        if mask[start] == 0:
            continue
        parsed = _parse_cfg_predicate(source, mask, match.end())
        if parsed is None:
            continue
        predicate, attribute_end = parsed
        if not cfg_predicate_is_test_only(predicate):
            continue

        if source.startswith("#![", start):
            # Inner attribute: it gates the block that encloses it, not a
            # following item. Only file scope is unambiguous enough to trust.
            if depth != 0:
                return None
            regions.append((1, total_lines))
            continue

        extent = _item_extent(source, mask, attribute_end)
        if extent is None:
            return None
        end_offset, is_braced = extent

        if is_braced:
            attribute_indent = _indent_width(source, start)
            close_indent = _indent_width(source, end_offset)
            if attribute_indent is None or close_indent != attribute_indent:
                return None

        regions.append(
            (
                source.count("\n", 0, start) + 1,
                source.count("\n", 0, end_offset) + 1,
            )
        )

    return regions


def is_rust_source_under_src(path: str) -> bool:
    parts = pathlib.PurePosixPath(path).parts
    return path.endswith(".rs") and "src" in parts


def partition_test_gated_hits(
    hits: list[Hit],
    base: pathlib.Path,
) -> tuple[list[Hit], list[Hit], list[str]]:
    """Split hits into (production, test-gated, paths whose extent was ambiguous).

    A hit inside a `#[cfg(test)]` region under `src/` is a test double written in
    the layout AGENTS.md mandates ("Every module includes inline `#[cfg(test)]`
    unit tests alongside the implementation"), not an unfinished production path.
    Classifying it as `production_stub` forces a whole-file allowlist entry,
    which is what blinded the gate to the rest of those files.

    Every ambiguous case resolves to production: unreadable file, unlexable
    source, or an extent the rustfmt cross-check does not confirm.
    """
    production: list[Hit] = []
    test_gated: list[Hit] = []
    undetermined: list[str] = []

    hits_by_path: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        hits_by_path[hit.path].append(hit)

    for path in sorted(hits_by_path):
        path_hits = hits_by_path[path]
        if not is_rust_source_under_src(path):
            production.extend(path_hits)
            continue
        try:
            source = (base / path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            production.extend(path_hits)
            undetermined.append(path)
            continue
        regions = cfg_test_regions(source)
        if regions is None:
            production.extend(path_hits)
            undetermined.append(path)
            continue
        for hit in path_hits:
            if any(start <= hit.line <= end for start, end in regions):
                test_gated.append(hit)
            else:
                production.append(hit)

    return production, test_gated, undetermined


def route_owner(path: str, routes: list[dict], default_owner: str) -> str:
    for route in routes:
        pattern = route.get("pattern")
        owner = route.get("owner")
        if isinstance(pattern, str) and isinstance(owner, str) and fnmatch.fnmatch(path, pattern):
            return owner
    return default_owner


def classify_path(path: str, policy: dict) -> str:
    for rule in policy.get("classification_rules", []):
        pattern = rule.get("pattern")
        category = rule.get("category")
        if isinstance(pattern, str) and isinstance(category, str):
            if fnmatch.fnmatch(path, pattern):
                return category
    if path.startswith("conformance/") or path.startswith("tests/conformance/"):
        return "conformance_placeholder"
    if "_audit" in pathlib.PurePosixPath(path).name:
        return "stale_audit_prose"
    if path.startswith("tests/"):
        return "intentional_test_double"
    if path.startswith("src/"):
        return "production_stub"
    if path.startswith("scripts/"):
        return "fixture_reference_implementation"
    return "unclassified"


def entry_pattern(entry: dict[str, Any]) -> str:
    return str(entry.get("pattern", entry.get("path", "")))


def expand_allowlist_group(group: dict[str, Any]) -> list[dict[str, Any]]:
    expanded = []
    for pattern in group.get("patterns", []):
        entry = {
            key: value
            for key, value in group.items()
            if key not in {"patterns"}
        }
        entry["pattern"] = pattern
        entry["source_group_id"] = group["group_id"]
        expanded.append(entry)
    return expanded


def allowlist_entries(policy: dict) -> list[dict[str, Any]]:
    entries = list(policy.get("allowlist_entries", []))
    for group in policy.get("allowlist_groups", []):
        entries.extend(expand_allowlist_group(group))
    return entries


def policy_categories(policy: dict) -> set[str]:
    categories: set[str] = set()
    for rule in policy.get("classification_rules", []):
        category = rule.get("category")
        if isinstance(category, str) and category:
            categories.add(category)
    for entry in allowlist_entries(policy):
        category = entry.get("category")
        if isinstance(category, str) and category != "any":
            categories.add(category)
    for waiver in policy.get("waivers", []):
        category = waiver.get("category")
        if isinstance(category, str) and category != "any":
            categories.add(category)
    return categories


def entry_justifies_hits(entry: dict[str, Any], hits: Iterable[Hit]) -> bool:
    """Whether a `justified_text` entry accounts for every flagged line.

    An entry without `justified_text` covers its whole path, as before. With it,
    the entry covers the path only if EVERY flagged line matches one of its
    regexes; a single unmatched line makes the entry not apply, so the hit falls
    through to the next entry, then to waivers, then to a violation. That is
    what stops one justified sentence from blessing a file forever: the
    justification is pinned to the text, which travels with the code in a way
    line numbers do not.
    """
    raw = entry.get("justified_text")
    if raw is None:
        return True
    if not isinstance(raw, list) or not raw:
        return False
    try:
        patterns = [re.compile(pattern) for pattern in raw]
    except (re.error, TypeError):
        return False
    return all(
        any(pattern.search(hit.text) for pattern in patterns) for hit in hits
    )


def entry_matches(
    entry: dict[str, Any],
    path: str,
    category: str,
    hits: Iterable[Hit] = (),
) -> bool:
    pattern = entry_pattern(entry)
    entry_category = entry.get("category", "any")
    if entry_category not in ("any", category):
        return False
    if not fnmatch.fnmatch(path, pattern):
        return False
    return entry_justifies_hits(entry, hits)


def entry_expired(entry: dict[str, Any], now_utc: dt.datetime) -> bool:
    expiry_raw = entry.get("expires_at_utc")
    if not isinstance(expiry_raw, str):
        return False
    return parse_iso8601_utc(expiry_raw) <= now_utc


def coverage_for_path(
    path: str,
    category: str,
    policy: dict,
    now_utc: dt.datetime,
    hits: Iterable[Hit] = (),
) -> tuple[str, dict[str, Any] | None]:
    hits = tuple(hits)
    for entry in allowlist_entries(policy):
        if entry_matches(entry, path, category, hits):
            if entry_expired(entry, now_utc):
                return ("expired_allowlist", entry)
            return ("allowlist", entry)

    if path in set(policy.get("allowlist_paths", [])):
        return (
            "legacy_allowlist",
            {
                "path": path,
                "category": "documented_allowlist",
                "owner": "legacy",
                "reason": "legacy exact-path allowlist entry",
            },
        )

    for waiver in policy.get("waivers", []):
        if waiver.get("status") == "active" and entry_matches(waiver, path, category, hits):
            if entry_expired(waiver, now_utc):
                return ("expired_waiver", waiver)
            return ("waiver", waiver)

    return ("violation", None)


def evaluate_policy(
    policy: dict,
    policy_path: pathlib.Path,
    now_utc: dt.datetime,
    cwd: pathlib.Path | None = None,
) -> dict[str, Any]:
    roots = policy.get("scan", {}).get("roots", ["src", "tests"])
    terms = policy.get("scan", {}).get("terms", [TERM_MOCK, TERM_FAKE, TERM_STUB])
    routes: list[dict] = policy.get("owner_routes", [])
    default_owner = policy.get("default_owner", "runtime-core")

    base = cwd if cwd is not None else pathlib.Path.cwd()
    scanned_hits = run_scan(roots, terms, cwd=cwd)
    hits, test_gated_hits, undetermined_paths = partition_test_gated_hits(
        scanned_hits, base
    )

    hits_by_path: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        hits_by_path[hit.path].append(hit)

    test_gated_by_path: dict[str, list[Hit]] = defaultdict(list)
    for hit in test_gated_hits:
        test_gated_by_path[hit.path].append(hit)
    test_gated_rows = [
        {
            "path": path,
            "category": classify_path(path, policy),
            "owner": route_owner(path, routes, default_owner),
            "first_line": min(hit.line for hit in path_hits),
            "tokens": sorted({token for hit in path_hits for token in hit.tokens}),
            "hit_count": len(path_hits),
            "coverage": "test_gated",
        }
        for path, path_hits in sorted(test_gated_by_path.items())
    ]

    classified_paths: list[ClassifiedPath] = []
    for path, path_hits in sorted(hits_by_path.items()):
        owner = route_owner(path, routes, default_owner)
        category = classify_path(path, policy)
        classified_paths.append(
            ClassifiedPath(
                path=path,
                category=category,
                owner=owner,
                hits=tuple(path_hits),
            )
        )

    category_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"paths": 0, "hits": 0, "violations": 0, "covered": 0}
    )
    for category in policy_categories(policy):
        _ = category_counts[category]
    coverage_counts: dict[str, int] = defaultdict(int)
    violations: list[dict[str, Any]] = []
    covered: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    remaining_allowlist_entries: list[dict[str, Any]] = []

    for classified in classified_paths:
        path_hits = list(classified.hits)
        tokens = sorted({token for hit in path_hits for token in hit.tokens})
        first_line = min(hit.line for hit in path_hits)
        category_counts[classified.category]["paths"] += 1
        category_counts[classified.category]["hits"] += len(path_hits)

        coverage, entry = coverage_for_path(
            classified.path, classified.category, policy, now_utc, path_hits
        )
        coverage_counts[coverage] += 1

        row = {
            "path": classified.path,
            "category": classified.category,
            "owner": classified.owner,
            "first_line": first_line,
            "tokens": tokens,
            "hit_count": len(path_hits),
            "coverage": coverage,
            "policy_entry": entry,
        }

        if coverage in ("allowlist", "legacy_allowlist", "waiver"):
            category_counts[classified.category]["covered"] += 1
            covered.append(row)
            if coverage in ("allowlist", "waiver") and entry is not None:
                remaining_allowlist_entries.append(
                    {
                        "path": classified.path,
                        "category": classified.category,
                        "coverage": coverage,
                        "owner": entry.get("owner", classified.owner),
                        "reason": entry.get("reason", ""),
                        "replacement_issue": entry.get("replacement_issue", ""),
                        "expires_at_utc": entry.get("expires_at_utc", ""),
                        "revisit_condition": entry.get("revisit_condition", ""),
                        "source_group_id": entry.get("source_group_id", ""),
                        "justified_text": list(entry.get("justified_text", [])),
                    }
                )
        else:
            category_counts[classified.category]["violations"] += 1
            violations.append(row)
            if coverage.startswith("expired"):
                expired.append(row)

    return {
        "schema_version": f"{no_mock_label()}-policy-report-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "policy_path": str(policy_path),
        "scan": {"roots": list(roots), "terms": list(terms)},
        "category_counts": dict(sorted(category_counts.items())),
        "coverage_counts": dict(sorted(coverage_counts.items())),
        "policy_counts": {
            "allowlist_paths": len(policy.get("allowlist_paths", [])),
            "allowlist_paths_legacy": len(policy.get("allowlist_paths", [])),
            "allowlist_entries": len(allowlist_entries(policy)),
            "allowlist_entry_groups": len(policy.get("allowlist_groups", [])),
            "waivers_total": len(policy.get("waivers", [])),
            "waivers_active": sum(
                1 for waiver in policy.get("waivers", []) if waiver.get("status") == "active"
            ),
        },
        "scan_counts": {
            "matching_paths": len(hits_by_path),
            "matching_hits": sum(len(path_hits) for path_hits in hits_by_path.values()),
            "violating_paths": len(violations),
            "expired_entries": len(expired),
            "expired_waivers": sum(1 for row in expired if row["coverage"] == "expired_waiver"),
            "scanned_hits": len(scanned_hits),
            "test_gated_hits": len(test_gated_hits),
            "test_gated_paths": len(test_gated_by_path),
            "test_gated_undetermined_paths": len(undetermined_paths),
        },
        "violations": violations,
        "covered": covered,
        "test_gated": test_gated_rows,
        "test_gated_undetermined_paths": sorted(undetermined_paths),
        "first_failure_line": (
            f"{violations[0]['path']}:{violations[0]['first_line']}" if violations else ""
        ),
        "remaining_allowlist_entries": sorted(
            remaining_allowlist_entries,
            key=lambda row: (
                row["category"],
                row["coverage"],
                row["source_group_id"],
                row["path"],
            ),
        ),
        "status": "pass" if not violations else "fail",
    }


def print_report(report: dict[str, Any], policy_path: pathlib.Path, max_errors: int) -> None:
    print("Implementation-completeness policy category summary:")
    for category, counts in report["category_counts"].items():
        print(
            f"  {category}: paths={counts['paths']} hits={counts['hits']} "
            f"covered={counts['covered']} violations={counts['violations']}"
        )

    counts = report["scan_counts"]
    if counts["test_gated_hits"] or counts["test_gated_undetermined_paths"]:
        print(
            f"  (excluded as #[cfg(test)]-gated: {counts['test_gated_hits']} hit(s) "
            f"across {counts['test_gated_paths']} path(s); "
            f"{counts['test_gated_undetermined_paths']} path(s) could not be resolved "
            "and were scanned as production)"
        )

    violations = report["violations"]
    for row in violations[:max_errors]:
        token_csv = ",".join(row["tokens"])
        print(
            f"::error file={row['path']},line={row['first_line']}::"
            f"Implementation-completeness policy violation category={row['category']} owner={row['owner']}; "
            f"terms={token_csv}; add structured allowlist entry or active waiver in {policy_path}"
        )

    if len(violations) > max_errors:
        print(
            f"Console output truncated after {max_errors} violation(s); "
            f"{len(violations) - max_errors} additional path(s) are in the JSON report."
        )

    if violations:
        print(
            "Implementation-completeness policy gate failed: "
            f"{len(violations)} undocumented or expired path(s) across "
            f"{len(report['category_counts'])} categor(ies)."
        )
    else:
        print(
            "Implementation-completeness policy gate passed: "
            f"{report['scan_counts']['matching_paths']} matching path(s), "
            "all covered by structured allowlist/active waivers."
        )


def run_negative_fixture_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix=f"asupersync-{no_mock_label()}-policy-") as tmp_raw:
        tmp = pathlib.Path(tmp_raw)
        fixture = tmp / "conformance" / "src" / f"{TERM_FAKE}_helper.rs"
        fixture.parent.mkdir(parents=True)
        fixture.write_text(
            (
                f"pub fn {TERM_FAKE}_conformance_helper() "
                f"{{ {TERM_UNIMPLEMENTED}!(\"{TERM_MOCK} {TERM_PLACEHOLDER}\"); }}\n"
            ),
            encoding="utf-8",
        )
        policy = {
            "schema_version": f"{no_mock_label()}-policy-v1",
            "scan": {
                "roots": ["conformance"],
                "terms": [
                    TERM_MOCK,
                    TERM_FAKE,
                    TERM_STUB,
                    TERM_PLACEHOLDER,
                    TERM_DEFERRED,
                    TERM_UNIMPLEMENTED,
                ],
            },
            "allowlist_paths": [],
            "allowlist_entries": [],
            "waivers": [],
            "owner_routes": [{"pattern": "conformance/**", "owner": "conformance"}],
            "classification_rules": [
                {"pattern": "conformance/**", "category": "conformance_placeholder"}
            ],
            "default_owner": "runtime-core",
        }
        report = evaluate_policy(
            policy,
            pathlib.Path("<negative-fixture>"),
            dt.datetime.now(dt.timezone.utc),
            cwd=tmp,
        )
    expected = [
        row
        for row in report["violations"]
        if row["path"] == f"conformance/src/{TERM_FAKE}_helper.rs"
        and row["category"] == "conformance_placeholder"
    ]
    if report["status"] != "fail" or not expected:
        print("negative fixture failed: invalid conformance helper was not rejected")
        return 1
    print("negative fixture passed: invalid conformance helper rejected as conformance_placeholder")
    return 0


def run_policy_fixture_self_tests(policy_path: pathlib.Path) -> int:
    policy = load_policy(policy_path)
    now = dt.datetime.now(dt.timezone.utc)

    def create_scan_roots(tmp: pathlib.Path, fixture_policy: dict[str, Any]) -> None:
        for root in fixture_policy.get("scan", {}).get("roots", []):
            if isinstance(root, str):
                (tmp / root).mkdir(parents=True, exist_ok=True)

    def evaluate_fixture(path: str, source: str) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix=f"asupersync-{no_mock_label()}-policy-") as tmp_raw:
            tmp = pathlib.Path(tmp_raw)
            create_scan_roots(tmp, policy)
            fixture = tmp / path
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_text(source, encoding="utf-8")
            return evaluate_policy(policy, policy_path, now, cwd=tmp)

    legitimate_test = evaluate_fixture(
        "tests/policy_legitimate_test_double.rs",
        f"struct {TERM_MOCK.title()}Peer; fn {TERM_FAKE}_payload() -> &'static str {{ \"{TERM_STUB} fixture\" }}\n",
    )
    if legitimate_test["status"] != "pass":
        print("policy fixture failed: legitimate tests/** double was rejected")
        return 1

    fake_conformance = evaluate_fixture(
        f"tests/conformance/policy_negative_{TERM_FAKE}_helper.rs",
        (
            f"pub fn {TERM_FAKE}_conformance_helper() "
            f"{{ {TERM_UNIMPLEMENTED}!(\"{TERM_MOCK} {TERM_PLACEHOLDER}\"); }}\n"
        ),
    )
    if fake_conformance["status"] != "fail":
        print("policy fixture failed: new invalid conformance helper was not rejected")
        return 1
    if not any(
        row["category"] == "conformance_placeholder"
        and row["path"] == f"tests/conformance/policy_negative_{TERM_FAKE}_helper.rs"
        for row in fake_conformance["violations"]
    ):
        print("policy fixture failed: invalid conformance helper had wrong category")
        return 1

    fake_production = evaluate_fixture(
        f"src/policy_negative_production_{TERM_STUB}.rs",
        f"pub fn not_real() {{ {TERM_DEFERRED}!(\"{TERM_PLACEHOLDER} {TERM_MOCK} behavior\"); }}\n",
    )
    if fake_production["status"] != "fail":
        print("policy fixture failed: new production incomplete behavior was not rejected")
        return 1
    if not any(
        row["category"] == "production_stub"
        and row["path"] == f"src/policy_negative_production_{TERM_STUB}.rs"
        for row in fake_production["violations"]
    ):
        print("policy fixture failed: production incomplete behavior had wrong category")
        return 1

    def evaluate_with_policy(
        fixture_policy: dict[str, Any], path: str, source: str
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix=f"asupersync-{no_mock_label()}-policy-") as tmp_raw:
            tmp = pathlib.Path(tmp_raw)
            create_scan_roots(tmp, fixture_policy)
            fixture = tmp / path
            fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_text(source, encoding="utf-8")
            return evaluate_policy(fixture_policy, policy_path, now, cwd=tmp)

    # --- cfg(test) awareness (asupersync-pzfwf5) -------------------------------
    #
    # AGENTS.md mandates inline `#[cfg(test)]` unit tests in every module, and
    # the policy already treats tests/** as intentional_test_double. A double
    # written in that mandated layout must not read as production_stub. The
    # pairing matters more than either half: the same file, same terms, must
    # still fail the moment one hit sits outside the test module.
    cfg_test_path = f"src/policy_cfg_test_{TERM_STUB}.rs"
    # Terms are matched on word boundaries, so every hit line below is a
    # standalone term: `{TERM_FAKE}_peer` would not match at all.
    cfg_test_module = (
        "#[cfg(test)]\n"
        "mod tests {\n"
        f"    fn double() -> &'static str {{ \"{TERM_MOCK} {TERM_PLACEHOLDER}\" }}\n"
        "\n"
        "    #[test]\n"
        f"    fn uses_double() {{ assert_eq!(double(), \"{TERM_MOCK} {TERM_PLACEHOLDER}\"); }}\n"
        "}\n"
    )
    cfg_test_only = evaluate_fixture(
        cfg_test_path, "pub fn shipped() -> u8 { 7 }\n\n" + cfg_test_module
    )
    if cfg_test_only["status"] != "pass":
        print(f"policy fixture failed: {TERM_MOCK} terms inside a #[cfg(test)] module were rejected")
        return 1
    if cfg_test_only["scan_counts"]["test_gated_hits"] != 2:
        print("policy fixture failed: #[cfg(test)] hits were not accounted for as test-gated")
        return 1

    cfg_test_mixed = evaluate_fixture(
        cfg_test_path,
        f"pub fn shipped() {{ {TERM_DEFERRED}!(\"{TERM_PLACEHOLDER} behavior\"); }}\n\n"
        + cfg_test_module,
    )
    if cfg_test_mixed["status"] != "fail":
        print("policy fixture failed: production hit alongside a #[cfg(test)] module was not rejected")
        return 1
    if not any(
        row["category"] == "production_stub" and row["path"] == cfg_test_path
        for row in cfg_test_mixed["violations"]
    ):
        print("policy fixture failed: mixed cfg(test)/production file had wrong category")
        return 1

    # An unlexable file must fail closed: no regions, so every hit is production.
    if cfg_test_regions(f"/* unterminated\n#[cfg(test)]\nmod tests {{ {TERM_STUB} }}\n") is not None:
        print("policy fixture failed: unterminated block comment did not fail closed")
        return 1
    # `any(test, ...)` still holds in non-test builds, so it is not a test gate.
    if cfg_predicate_is_test_only('any(test, feature = "x")'):
        print("policy fixture failed: any(test, ...) was treated as test-only")
        return 1
    if not cfg_predicate_is_test_only('all(test, feature = "x")'):
        print("policy fixture failed: all(test, ...) was not treated as test-only")
        return 1

    # --- justified_text narrowing (asupersync-pzfwf5) -------------------------
    #
    # A path-only allowlist entry blesses a whole file forever. A narrowed entry
    # covers only the sentence it justifies, so an unrelated hit added later to
    # the same file still fails.
    narrowed_path = f"src/policy_narrowed_{TERM_STUB}.rs"
    narrowed_policy = dict(policy)
    narrowed_policy["allowlist_entries"] = [
        {
            "pattern": narrowed_path,
            "category": "production_stub",
            "owner": "runtime-core",
            "reason": "fixture: prose describing a deliberate platform shim",
            "revisit_condition": "fixture",
            "replacement_issue": "asupersync-pzfwf5",
            "justified_text": [rf"deliberate platform {TERM_STUB}"],
        }
    ]
    narrowed_policy["allowlist_groups"] = []
    narrowed_policy["waivers"] = []

    narrowed_covered = evaluate_with_policy(
        narrowed_policy,
        narrowed_path,
        f"// This no-op is a deliberate platform {TERM_STUB}, not unfinished work.\n"
        "pub fn shipped() -> u8 { 7 }\n",
    )
    if narrowed_covered["status"] != "pass":
        print("policy fixture failed: justified_text entry did not cover its own sentence")
        return 1

    narrowed_violating = evaluate_with_policy(
        narrowed_policy,
        narrowed_path,
        f"// This no-op is a deliberate platform {TERM_STUB}, not unfinished work.\n"
        f"// {TERM_DEFERRED.upper()}: implement the retry path.\n"
        "pub fn shipped() -> u8 { 7 }\n",
    )
    if narrowed_violating["status"] != "fail":
        print("policy fixture failed: unjustified hit in a narrowed file was not rejected")
        return 1
    if not any(
        row["coverage"] == "violation" and row["path"] == narrowed_path
        for row in narrowed_violating["violations"]
    ):
        print("policy fixture failed: unjustified hit did not fall through to a violation")
        return 1

    invalid_justified_text = dict(policy)
    invalid_justified_text["allowlist_entries"] = [
        {
            "pattern": "src/invalid_regex.rs",
            "category": "production_stub",
            "owner": "runtime-core",
            "reason": "fixture",
            "revisit_condition": "fixture",
            "replacement_issue": "asupersync-pzfwf5",
            "justified_text": ["unterminated ("],
        }
    ]
    invalid_justified_text["allowlist_groups"] = []
    invalid_justified_text["waivers"] = []
    try:
        validate_structured_allowlist(invalid_justified_text)
    except ValueError:
        pass
    else:
        print("policy fixture failed: invalid justified_text regex passed validation")
        return 1

    invalid_missing_bead = dict(policy)
    invalid_missing_bead["allowlist_entries"] = [
        {
            "pattern": "src/missing_bead.rs",
            "category": "production_stub",
            "owner": "runtime-core",
            "reason": "fixture",
            "revisit_condition": "fixture",
        }
    ]
    invalid_missing_bead["allowlist_groups"] = []
    invalid_missing_bead["waivers"] = []
    try:
        validate_structured_allowlist(invalid_missing_bead)
    except ValueError:
        pass
    else:
        print("policy fixture failed: production allowlist without replacement_issue passed")
        return 1

    invalid_duplicate = dict(policy)
    invalid_duplicate["allowlist_entries"] = [
        {
            "pattern": "tests/duplicate.rs",
            "category": "intentional_test_double",
            "owner": "test-infra",
            "reason": "fixture",
            "revisit_condition": "fixture",
        },
        {
            "pattern": "tests/duplicate.rs",
            "category": "intentional_test_double",
            "owner": "test-infra",
            "reason": "fixture",
            "revisit_condition": "fixture",
        },
    ]
    invalid_duplicate["allowlist_groups"] = []
    invalid_duplicate["waivers"] = []
    try:
        validate_structured_allowlist(invalid_duplicate)
    except ValueError:
        pass
    else:
        print("policy fixture failed: duplicate allowlist entries passed")
        return 1

    expired_policy = dict(policy)
    expired_policy["allowlist_entries"] = [
        {
            "pattern": f"src/expired_{TERM_PLACEHOLDER}.rs",
            "category": "production_stub",
            "owner": "runtime-core",
            "reason": "fixture",
            "expires_at_utc": "2000-01-01T00:00:00Z",
            "replacement_issue": "asupersync-a45",
        }
    ]
    expired_policy["allowlist_groups"] = []
    expired_policy["waivers"] = []
    with tempfile.TemporaryDirectory(prefix=f"asupersync-{no_mock_label()}-policy-") as tmp_raw:
        tmp = pathlib.Path(tmp_raw)
        create_scan_roots(tmp, expired_policy)
        fixture = tmp / "src" / f"expired_{TERM_PLACEHOLDER}.rs"
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(
            f"pub fn expired() {{ {TERM_DEFERRED}!(\"{TERM_MOCK} {TERM_PLACEHOLDER}\"); }}\n",
            encoding="utf-8",
        )
        expired_report = evaluate_policy(expired_policy, policy_path, now, cwd=tmp)
    if expired_report["status"] != "fail" or not any(
        row["coverage"] == "expired_allowlist" for row in expired_report["violations"]
    ):
        print("policy fixture failed: expired allowlist did not fail as expired")
        return 1

    print(
        "policy fixtures passed: classifier, cfg(test) awareness, justified_text narrowing, "
        "allowlist metadata, duplicates, expiry, and negative gates"
    )
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test_negative_fixture:
        return run_negative_fixture_self_test()
    if args.self_test_policy_fixtures:
        return run_policy_fixture_self_tests(pathlib.Path(args.policy))

    policy_path = pathlib.Path(args.policy)
    policy = load_policy(policy_path)
    report = evaluate_policy(
        policy,
        policy_path,
        dt.datetime.now(dt.timezone.utc),
    )
    if args.report_json is not None:
        args.report_json.parent.mkdir(parents=True, exist_ok=True)
        args.report_json.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print_report(report, policy_path, max(0, args.max_errors))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
