#!/usr/bin/env python3
"""Enforce no-mock policy with allowlist + waiver expiry checks."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import pathlib
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    text: str
    tokens: tuple[str, ...]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--policy",
        default=".github/no_mock_policy.json",
        help="Path to no-mock policy JSON",
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
    if data.get("schema_version") != "no-mock-policy-v1":
        raise ValueError("unsupported or missing schema_version")
    if not isinstance(data.get("allowlist_paths"), list):
        raise ValueError("allowlist_paths must be a list")
    if not isinstance(data.get("waivers"), list):
        raise ValueError("waivers must be a list")
    if not isinstance(data.get("owner_routes"), list):
        raise ValueError("owner_routes must be a list")
    return data


def run_scan(roots: Iterable[str], terms: list[str]) -> list[Hit]:
    escaped = [re.escape(term) for term in terms]
    token_re = re.compile(rf"(?i)\b({'|'.join(escaped)})\b")

    cmd = ["rg", "--line-number", "--no-heading", "--color", "never"]
    for term in terms:
        cmd += ["-e", rf"(?i)\b{re.escape(term)}\b"]
    cmd += list(roots)

    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr)
        raise RuntimeError("ripgrep scan failed")
    if proc.returncode == 1:
        return []

    hits: list[Hit] = []
    for row in proc.stdout.splitlines():
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


def route_owner(path: str, routes: list[dict], default_owner: str) -> str:
    for route in routes:
        pattern = route.get("pattern")
        owner = route.get("owner")
        if isinstance(pattern, str) and isinstance(owner, str) and fnmatch.fnmatch(path, pattern):
            return owner
    return default_owner


def main() -> int:
    args = parse_args()
    policy_path = pathlib.Path(args.policy)
    policy = load_policy(policy_path)

    roots = policy.get("scan", {}).get("roots", ["src", "tests"])
    terms = policy.get("scan", {}).get("terms", ["mock", "fake", "stub"])
    allowlist = set(policy.get("allowlist_paths", []))
    waivers: list[dict] = policy.get("waivers", [])
    routes: list[dict] = policy.get("owner_routes", [])
    default_owner = policy.get("default_owner", "runtime-core")

    now_utc = dt.datetime.now(dt.timezone.utc)

    waiver_by_path: dict[str, dict] = {}
    expired_waivers: list[dict] = []
    for waiver in waivers:
        path = waiver.get("path")
        status = waiver.get("status")
        expiry_raw = waiver.get("expires_at_utc")
        if not isinstance(path, str) or not isinstance(status, str) or not isinstance(expiry_raw, str):
            raise ValueError("waiver must include path/status/expires_at_utc")
        expiry = parse_iso8601_utc(expiry_raw)
        if status == "active":
            waiver_by_path[path] = waiver
            if expiry <= now_utc:
                expired_waivers.append(waiver)

    hits = run_scan(roots, terms)
    hits_by_path: dict[str, list[Hit]] = defaultdict(list)
    for hit in hits:
        hits_by_path[hit.path].append(hit)

    violations: list[tuple[str, list[Hit], str]] = []
    for path, path_hits in sorted(hits_by_path.items()):
        if path in allowlist:
            continue
        waiver = waiver_by_path.get(path)
        if waiver is not None and waiver not in expired_waivers:
            continue
        owner = route_owner(path, routes, default_owner)
        violations.append((path, path_hits, owner))

    for waiver in expired_waivers:
        path = str(waiver["path"])
        owner = str(waiver.get("owner", route_owner(path, routes, default_owner)))
        waiver_id = str(waiver.get("waiver_id", "<unknown>"))
        expiry = str(waiver.get("expires_at_utc"))
        replacement = str(waiver.get("replacement_issue", "<unspecified>"))
        print(
            f"::error file={path}::Expired no-mock waiver {waiver_id} owner={owner} "
            f"expired_at={expiry} replacement_issue={replacement}"
        )

    for path, path_hits, owner in violations:
        first_line = min(hit.line for hit in path_hits)
        tokens = sorted({token for hit in path_hits for token in hit.tokens})
        token_csv = ",".join(tokens)
        print(
            f"::error file={path},line={first_line}::No-mock policy violation owner={owner}; "
            f"terms={token_csv}; add allowlist entry or active waiver in {policy_path}"
        )

    if expired_waivers or violations:
        print(
            "No-mock policy gate failed: "
            f"{len(violations)} non-allowlisted path(s), {len(expired_waivers)} expired waiver(s)."
        )
        return 1

    print(
        "No-mock policy gate passed: "
        f"{len(hits_by_path)} matching path(s) scanned, all covered by allowlist/active waivers."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
