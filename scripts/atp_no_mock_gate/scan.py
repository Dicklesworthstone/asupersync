#!/usr/bin/env python3
"""ATP-specific no-mock/no-placeholder gate.

The broader repo policy is intentionally noisy while ATP is being hardened. This
gate is narrower and fail-closed: current ATP debt must be named in the policy
with owner, rationale, expiry, and proof/replacement routing; any new unlisted
mock/fake/stub/placeholder/TODO marker exits nonzero.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "atp-no-mock-gate-report-v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY = Path(__file__).with_name("policy.json")
RG_TIMEOUT_SECONDS = 30
REQUIRED_ALLOWLIST_FIELDS = {
    "id",
    "pattern",
    "category",
    "owner",
    "reason",
    "expires_at_utc",
}
TOKEN_PATTERNS = {
    "ignored_test": r"#\s*\[\s*ignore\b",
    "todo_macro": r"\btodo\s*!\s*\(",
    "unimplemented_macro": r"\bunimplemented\s*!\s*\(",
    "mock": r"\bmock\b",
    "fake": r"\bfake\b",
    "stub": r"\bstub\b",
    "placeholder": r"\bplaceholder\b",
    "todo": r"\btodo\b",
    "unimplemented": r"\bunimplemented\b",
}
TOKEN_RE = re.compile("|".join(f"(?P<{name}>{pattern})" for name, pattern in TOKEN_PATTERNS.items()), re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--report-json", type=Path)
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(raw: str) -> dt.datetime:
    value = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp must include timezone: {raw}")
    return parsed.astimezone(dt.timezone.utc)


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise ValueError(f"invalid policy JSON in {path}: {err}") from err
    if policy.get("schema_version") != "atp-no-mock-policy-v1":
        raise ValueError("unsupported policy schema_version")
    scan = policy.get("scan")
    if not isinstance(scan, dict) or not isinstance(scan.get("roots"), list):
        raise ValueError("policy.scan.roots must be a list")
    entries = policy.get("allowlist_entries", [])
    if not isinstance(entries, list):
        raise ValueError("policy.allowlist_entries must be a list")
    seen_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("allowlist entries must be objects")
        missing = REQUIRED_ALLOWLIST_FIELDS - set(entry)
        if missing:
            raise ValueError(f"allowlist entry missing fields {sorted(missing)}")
        entry_id = str(entry["id"])
        if entry_id in seen_ids:
            raise ValueError(f"duplicate allowlist id {entry_id}")
        seen_ids.add(entry_id)
        if "replacement_issue" not in entry and "proof_lane" not in entry:
            raise ValueError(f"allowlist entry {entry_id} needs replacement_issue or proof_lane")
        if "contains" not in entry and "regex" not in entry and any(ch in str(entry["pattern"]) for ch in "*?["):
            continue
        if "contains" not in entry and "regex" not in entry:
            raise ValueError(f"allowlist entry {entry_id} must include contains or regex for exact file patterns")
        if "regex" in entry:
            re.compile(str(entry["regex"]))
        parse_utc(str(entry["expires_at_utc"]))
    return policy


def existing_roots(repo_root: Path, roots: list[str]) -> list[str]:
    return [root for root in roots if (repo_root / root).exists()]


def scan_hits(repo_root: Path, roots: list[str]) -> list[dict[str, Any]]:
    roots = existing_roots(repo_root, roots)
    if not roots:
        return []

    cmd = ["rg", "--line-number", "--no-heading", "--color", "never", "-i"]
    for pattern in TOKEN_PATTERNS.values():
        cmd.extend(["-e", pattern])
    cmd.extend(roots)

    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
        timeout=RG_TIMEOUT_SECONDS,
    )
    if proc.returncode == 1:
        return []
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise RuntimeError("ripgrep ATP no-mock scan failed")

    hits: list[dict[str, Any]] = []
    for raw in proc.stdout.splitlines():
        parts = raw.split(":", 2)
        if len(parts) != 3:
            continue
        path, line_raw, text = parts
        try:
            line = int(line_raw)
        except ValueError:
            continue
        tokens = sorted({match.lastgroup or "unknown" for match in TOKEN_RE.finditer(text)})
        if not tokens:
            continue
        hits.append(
            {
                "path": path,
                "line": line,
                "tokens": tokens,
                "text": text.strip(),
                "surface": classify_surface(path),
            }
        )
    return hits


def classify_surface(path: str) -> str:
    if path.startswith("src/atp/"):
        return "production_atp"
    if path.startswith("tests/atp/"):
        return "atp_test"
    return "unknown"


def entry_matches(entry: dict[str, Any], hit: dict[str, Any]) -> bool:
    if not fnmatch.fnmatch(hit["path"], str(entry["pattern"])):
        return False
    if "contains" in entry and str(entry["contains"]) not in hit["text"]:
        return False
    if "regex" in entry and re.search(str(entry["regex"]), hit["text"]) is None:
        return False
    return True


def coverage_for_hit(
    hit: dict[str, Any],
    entries: list[dict[str, Any]],
    now_utc: dt.datetime,
) -> tuple[str, dict[str, Any] | None]:
    for entry in entries:
        if not entry_matches(entry, hit):
            continue
        if parse_utc(str(entry["expires_at_utc"])) <= now_utc:
            return "expired_allowlist", entry
        return "allowlist", entry
    return "violation", None


def build_report(
    repo_root: Path,
    policy_path: Path,
    generated_at: str | None,
) -> dict[str, Any]:
    policy = load_policy(policy_path)
    now_utc = parse_utc(generated_at) if generated_at else dt.datetime.now(dt.timezone.utc)
    hits = scan_hits(repo_root, [str(root) for root in policy["scan"]["roots"]])
    entries = policy["allowlist_entries"]

    covered: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    coverage_counts: Counter[str] = Counter()
    token_counts: Counter[str] = Counter()
    surface_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    for hit in hits:
        coverage, entry = coverage_for_hit(hit, entries, now_utc)
        coverage_counts[coverage] += 1
        surface_counts[hit["surface"]] += 1
        for token in hit["tokens"]:
            token_counts[token] += 1
        row = {
            **hit,
            "coverage": coverage,
            "allowlist_id": entry.get("id", "") if entry else "",
            "category": entry.get("category", "unwaived") if entry else "unwaived",
            "owner": entry.get("owner", policy.get("default_owner", "atp-dml")) if entry else policy.get("default_owner", "atp-dml"),
            "reason": entry.get("reason", "") if entry else "",
            "replacement_issue": entry.get("replacement_issue", "") if entry else "",
            "proof_lane": entry.get("proof_lane", "") if entry else "",
            "expires_at_utc": entry.get("expires_at_utc", "") if entry else "",
        }
        category_counts[row["category"]] += 1
        if coverage == "allowlist":
            covered.append(row)
        else:
            violations.append(row)

    status = "pass" if not violations else "fail"
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or utc_now(),
        "policy_path": str(policy_path),
        "scan": {
            "roots": policy["scan"]["roots"],
            "terms": policy["scan"]["terms"],
            "implementation": "ripgrep",
        },
        "summary": {
            "status": status,
            "release_blocking": bool(violations),
            "matching_hits": len(hits),
            "covered_hits": len(covered),
            "violation_hits": len(violations),
            "allowlist_entries": len(entries),
            "coverage_counts": dict(sorted(coverage_counts.items())),
            "surface_counts": dict(sorted(surface_counts.items())),
            "token_counts": dict(sorted(token_counts.items())),
            "category_counts": dict(sorted(category_counts.items())),
            "first_failure": f"{violations[0]['path']}:{violations[0]['line']}" if violations else "",
        },
        "violations": violations,
        "covered": covered,
    }


def render_text(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        f"ATP no-mock gate: {summary['status']}",
        f"matching_hits={summary['matching_hits']}",
        f"covered_hits={summary['covered_hits']}",
        f"violation_hits={summary['violation_hits']}",
        f"first_failure={summary['first_failure']}",
    ]
    for violation in report["violations"][:20]:
        tokens = ",".join(violation["tokens"])
        lines.append(
            f"::error file={violation['path']},line={violation['line']}::"
            f"ATP no-mock violation tokens={tokens}; add scoped policy entry or remove placeholder"
        )
    return "\n".join(lines) + "\n"


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="asupersync-atp-no-mock-gate-") as tmp_raw:
        root = Path(tmp_raw)
        (root / "src/atp").mkdir(parents=True)
        (root / "tests/atp/no_mock").mkdir(parents=True)
        (root / "src/atp/transport.rs").write_text(
            "pub fn ship() { todo!(\"placeholder mock transport\"); }\n",
            encoding="utf-8",
        )
        (root / "tests/atp/no_mock/fixture.rs").write_text(
            "struct MockPeer; fn fixture() -> &'static str { \"fake fixture\" }\n",
            encoding="utf-8",
        )
        policy = {
            "schema_version": "atp-no-mock-policy-v1",
            "scan": {
                "roots": ["src/atp", "tests/atp"],
                "terms": ["mock", "fake", "stub", "placeholder", "todo", "unimplemented"],
            },
            "default_owner": "atp-dml",
            "allowlist_entries": [
                {
                    "id": "test-fixture",
                    "pattern": "tests/atp/no_mock/**",
                    "category": "scanner_fixture",
                    "owner": "atp-dml",
                    "reason": "self-test fixture",
                    "proof_lane": "self-test",
                    "expires_at_utc": "2026-07-01T00:00:00Z",
                }
            ],
        }
        policy_path = root / "policy.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        report = build_report(root, policy_path, "2026-05-24T22:30:00Z")

    if report["summary"]["status"] != "fail":
        print("self-test failed: production placeholder was not rejected", file=sys.stderr)
        return 1
    if not any(row["path"] == "src/atp/transport.rs" for row in report["violations"]):
        print("self-test failed: expected production violation missing", file=sys.stderr)
        return 1
    if not any(row["path"] == "tests/atp/no_mock/fixture.rs" for row in report["covered"]):
        print("self-test failed: expected fixture allowlist coverage missing", file=sys.stderr)
        return 1
    print("self-test passed: allowed fixture covered and production placeholder rejected")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_test()

    report = build_report(args.repo_root.resolve(), args.policy, args.generated_at)
    if args.report_json:
        write_report(args.report_json, report)
    if args.output == "json":
        sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_text(report))
    return 0 if report["summary"]["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
