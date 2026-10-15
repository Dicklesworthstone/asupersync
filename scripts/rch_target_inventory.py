#!/usr/bin/env python3
"""Inventory local rch target directories without cleanup side effects.

The report gives agents an exact, non-mutating candidate list they can paste
into an authorization request. It never removes files and exposes no cleanup
flag. Live mode scans `/tmp/rch_target*` plus repo-local `.rch-target-*` paths;
fixture mode keeps the classifier deterministic for contract tests.
"""

import argparse
import datetime as dt
import glob
import json
import os
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "rch-target-inventory-v1"
DEFAULT_STALE_SECONDS = 60 * 60


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


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_patterns() -> list[str]:
    return ["/tmp/rch_target*", str(repo_root() / ".rch-target-*")]


def has_glob_magic(value: str) -> bool:
    return any(char in value for char in "*?[")


def format_bytes(value: int | None) -> str:
    if value is None:
        return "unknown"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(value)
    for unit in units:
        if amount < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024.0
    return f"{value} B"


def target_kind(path: str) -> str:
    name = Path(path).name
    if name.startswith("rch_target"):
        return "tmp-rch-target"
    if name.startswith(".rch-target-"):
        return "repo-rch-target"
    return "other"


def owner_hint(path: str) -> str | None:
    name = Path(path).name
    if name.startswith("rch_target_"):
        suffix = name.removeprefix("rch_target_")
        for part in suffix.replace("-", "_").split("_"):
            if part:
                return part
    if name.startswith(".rch-target-"):
        suffix = name.removeprefix(".rch-target-")
        parts = [part for part in suffix.split("-") if part]
        if parts:
            return f"worker:{parts[0]}"
    return None


def path_contains(parent: Path, child: str) -> bool:
    try:
        child_path = Path(child).resolve(strict=False)
        parent_path = parent.resolve(strict=False)
    except OSError:
        return False
    return child_path == parent_path or parent_path in child_path.parents


def open_file_count(path: Path) -> tuple[int | None, str]:
    proc = Path("/proc")
    if not proc.exists():
        return None, "unavailable"

    count = 0
    probe_status = "ok"
    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        try:
            fd_entries = list(fd_dir.iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for fd in fd_entries:
            try:
                target = os.readlink(fd)
            except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                continue
            if path_contains(path, target):
                count += 1
    return count, probe_status


def directory_size(path: Path) -> tuple[int | None, str, str | None]:
    total = 0
    try:
        root_stat = path.stat()
    except PermissionError as error:
        return None, "permission-denied", str(error)
    except FileNotFoundError:
        return None, "missing", None
    except OSError as error:
        return None, "error", str(error)

    if path.is_file():
        return root_stat.st_size, "ok", None

    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        stat_result = entry.stat(follow_symlinks=False)
                    except PermissionError as error:
                        return None, "permission-denied", str(error)
                    except FileNotFoundError:
                        continue
                    except OSError as error:
                        return None, "error", str(error)
                    total += stat_result.st_size
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
        except PermissionError as error:
            return None, "permission-denied", str(error)
        except FileNotFoundError:
            continue
        except OSError as error:
            return None, "error", str(error)

    return total, "ok", None


def iso_from_timestamp(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    return (
        dt.datetime.fromtimestamp(seconds, dt.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def expand_patterns(patterns: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for pattern in patterns:
        matches = sorted(glob.glob(pattern)) if has_glob_magic(pattern) else []
        if not matches and not has_glob_magic(pattern):
            matches = [pattern]
        if not matches:
            rows.append({"path": pattern, "exists": False, "source_pattern": pattern})
            continue
        for match in matches:
            normalized = str(Path(match))
            if normalized in seen:
                continue
            seen.add(normalized)
            rows.append({"path": normalized, "exists": Path(normalized).exists(), "source_pattern": pattern})
    return rows


def live_records(patterns: list[str], skip_open_probe: bool) -> list[dict[str, Any]]:
    records = []
    for row in expand_patterns(patterns):
        path = Path(row["path"])
        record: dict[str, Any] = dict(row)
        if not record["exists"]:
            records.append(record)
            continue

        size, probe_status, error = directory_size(path)
        record["size_bytes"] = size
        record["probe_status"] = probe_status
        if error:
            record["probe_error"] = error
        try:
            record["mtime"] = iso_from_timestamp(path.stat().st_mtime)
        except (FileNotFoundError, PermissionError, OSError):
            record["mtime"] = None
        if skip_open_probe:
            record["open_file_count"] = None
            record["open_file_probe"] = "skipped"
        else:
            count, status = open_file_count(path)
            record["open_file_count"] = count
            record["open_file_probe"] = status
        records.append(record)
    return records


def load_source(path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    with path.open("r", encoding="utf-8") as handle:
        source = json.load(handle)
    roots = source.get("roots", [])
    candidates = source.get("candidates", [])
    if not isinstance(roots, list) or not all(isinstance(root, str) for root in roots):
        raise ValueError("source roots must be a list of strings")
    if not isinstance(candidates, list) or not all(isinstance(row, dict) for row in candidates):
        raise ValueError("source candidates must be a list of objects")
    return roots, candidates


def normalize_record(
    record: dict[str, Any], generated_at: str, stale_seconds: int
) -> dict[str, Any]:
    path = str(record.get("path", ""))
    exists = bool(record.get("exists", True))
    size_bytes = record.get("size_bytes")
    if isinstance(size_bytes, bool) or not isinstance(size_bytes, int):
        size_bytes = None
    probe_status = str(record.get("probe_status", "ok" if exists else "missing"))
    open_count = record.get("open_file_count")
    if isinstance(open_count, bool) or not isinstance(open_count, int):
        open_count = None
    open_probe = str(record.get("open_file_probe", "provided" if open_count is not None else "unknown"))
    mtime = record.get("mtime")
    age_seconds = None
    generated = parse_timestamp(generated_at)
    modified = parse_timestamp(mtime)
    if generated is not None and modified is not None:
        age_seconds = max(0, int((generated - modified).total_seconds()))

    if not exists:
        classification = "missing"
        authorization_candidate = False
        reason = "path does not exist"
    elif probe_status == "permission-denied":
        classification = "permission-denied"
        authorization_candidate = False
        reason = "inventory could not read this path"
    elif open_count is not None and open_count > 0:
        classification = "active-looking"
        authorization_candidate = False
        reason = "one or more open file descriptors appear under this path"
    elif age_seconds is not None and age_seconds < stale_seconds:
        classification = "recent-looking"
        authorization_candidate = False
        reason = "path is newer than the stale threshold"
    else:
        classification = "stale-looking"
        authorization_candidate = True
        reason = "path is old enough and has no observed open files"

    return {
        "path": path,
        "source_pattern": record.get("source_pattern"),
        "exists": exists,
        "kind": target_kind(path),
        "target_name": Path(path).name,
        "owner_hint": owner_hint(path),
        "size_bytes": size_bytes,
        "size_human": format_bytes(size_bytes),
        "mtime": mtime,
        "age_seconds": age_seconds,
        "age_hours": round(age_seconds / 3600, 3) if age_seconds is not None else None,
        "probe_status": probe_status,
        "probe_error": record.get("probe_error"),
        "open_file_count": open_count,
        "open_file_probe": open_probe,
        "classification": classification,
        "authorization_candidate": authorization_candidate,
        "reason": reason,
    }


def build_inventory(
    roots: list[str],
    records: list[dict[str, Any]],
    generated_at: str,
    stale_seconds: int,
) -> dict[str, Any]:
    candidates = [normalize_record(row, generated_at, stale_seconds) for row in records]
    authorization_candidates = [row for row in candidates if row["authorization_candidate"]]
    expected_recovered = sum(row["size_bytes"] or 0 for row in authorization_candidates)
    existing = [row for row in candidates if row["exists"]]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "non_mutating": True,
        "deletion_command_available": False,
        "roots": roots,
        "stale_threshold_seconds": stale_seconds,
        "summary": {
            "total_candidates": len(candidates),
            "existing_candidates": len(existing),
            "missing_candidates": sum(1 for row in candidates if not row["exists"]),
            "authorization_candidate_count": len(authorization_candidates),
            "active_looking_count": sum(1 for row in candidates if row["classification"] == "active-looking"),
            "permission_denied_count": sum(1 for row in candidates if row["classification"] == "permission-denied"),
            "expected_recovered_bytes": expected_recovered,
            "expected_recovered_human": format_bytes(expected_recovered),
        },
        "candidates": candidates,
    }


def emit_text(inventory: dict[str, Any]) -> str:
    lines = [
        "RCH target inventory",
        f"Generated: {inventory['generated_at']}",
        f"Non-mutating: {inventory['non_mutating']}",
        f"Expected recovered with authorization: {inventory['summary']['expected_recovered_human']}",
        "",
    ]
    for row in inventory["candidates"]:
        marker = "AUTH" if row["authorization_candidate"] else "SKIP"
        lines.append(
            f"{marker} {row['classification']} {row['size_human']} {row['path']} ({row['reason']})"
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Report local rch target directories and likely cleanup candidates "
            "without mutating the filesystem."
        )
    )
    parser.add_argument("--source", type=Path, help="Fixture JSON with roots and candidate records")
    parser.add_argument(
        "--root-pattern",
        action="append",
        dest="root_patterns",
        help="Glob or explicit path to scan; defaults to /tmp/rch_target* and repo .rch-target-*",
    )
    parser.add_argument("--generated-at", default=utc_now(), help="RFC3339 timestamp for deterministic reports")
    parser.add_argument(
        "--stale-seconds",
        type=int,
        default=DEFAULT_STALE_SECONDS,
        help="Minimum age before an unopened existing target is authorization-ready",
    )
    parser.add_argument("--skip-open-probe", action="store_true", help="Skip /proc fd scan")
    parser.add_argument("--output", choices=["json", "text"], default="json")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.source:
            roots, records = load_source(args.source)
        else:
            roots = args.root_patterns or default_patterns()
            records = live_records(roots, args.skip_open_probe)
        inventory = build_inventory(roots, records, args.generated_at, args.stale_seconds)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"rch target inventory failed: {error}", file=sys.stderr)
        return 2

    if args.output == "json":
        print(json.dumps(inventory, indent=2, sort_keys=True))
    else:
        print(emit_text(inventory), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
