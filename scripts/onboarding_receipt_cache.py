#!/usr/bin/env python3
"""Evaluate whether a cached onboarding receipt is safe to reuse.

The helper is intentionally non-mutating: it reads a current receipt and an
optional cache snapshot, then emits a deterministic decision plus a proposed
cache record for a caller to persist explicitly.
"""

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "onboarding-receipt-cache-v1"


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


def load_json(path: str | None, default: Any) -> Any:
    if not path:
        return default
    return json.loads(Path(path).read_text(encoding="utf-8"))


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def receipt_key(receipt: dict[str, Any]) -> str:
    parts = [
        string_value(receipt.get("schema_version")),
        string_value(receipt.get("repo_path")),
        string_value(receipt.get("branch")),
        string_value(receipt.get("agent")),
    ]
    if all(not part for part in parts):
        parts = [canonical_digest(receipt)]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def cache_entries(cache: Any) -> list[dict[str, Any]]:
    if isinstance(cache, list):
        return [entry for entry in cache if isinstance(entry, dict)]
    if isinstance(cache, dict):
        entries = cache.get("entries")
        if isinstance(entries, list):
            return [entry for entry in entries if isinstance(entry, dict)]
        return [cache]
    return []


def age_seconds(now: dt.datetime, entry: dict[str, Any]) -> int | None:
    timestamp = parse_timestamp(entry.get("cached_at") or entry.get("generated_at"))
    if timestamp is None:
        return None
    return max(0, int((now - timestamp).total_seconds()))


def summarize_receipt(receipt: dict[str, Any], digest: str, key: str) -> dict[str, Any]:
    dirty = receipt.get("dirty_clusters")
    reservations = receipt.get("reservation_conflicts")
    ready = receipt.get("ready_beads")
    in_progress = receipt.get("in_progress_beads")
    next_action = receipt.get("next_action")
    return {
        "receipt_key": key,
        "receipt_digest_sha256": digest,
        "schema_version": string_value(receipt.get("schema_version")),
        "repo_path": string_value(receipt.get("repo_path")),
        "branch": string_value(receipt.get("branch")),
        "agent": string_value(receipt.get("agent")),
        "generated_at": string_value(receipt.get("generated_at")),
        "dirty_cluster_count": len(dirty) if isinstance(dirty, list) else 0,
        "reservation_conflict_count": len(reservations) if isinstance(reservations, list) else 0,
        "ready_bead_count": len(ready) if isinstance(ready, list) else 0,
        "in_progress_bead_count": len(in_progress) if isinstance(in_progress, list) else 0,
        "next_action_category": string_value(next_action.get("category")) if isinstance(next_action, dict) else "",
    }


def matching_entry(entries: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    for entry in entries:
        if entry.get("receipt_key") == key:
            return entry
    return None


def decision_for(
    current: dict[str, Any],
    entry: dict[str, Any] | None,
    now: dt.datetime,
    ttl_seconds: int,
) -> tuple[str, str, int | None]:
    if entry is None:
        return "refresh-cache", "no matching cache entry", None

    age = age_seconds(now, entry)
    if age is None:
        return "refresh-cache", "matching entry has no parseable cache timestamp", None
    if age > ttl_seconds:
        return "refresh-cache", "matching entry exceeded TTL", age

    if entry.get("receipt_digest_sha256") != current["receipt_digest_sha256"]:
        return "refresh-cache", "matching entry digest differs from current receipt", age

    return "reuse-cache", "matching entry is fresh and digest-stable", age


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    source = load_json(args.receipt, {})
    if not isinstance(source, dict):
        raise ValueError("receipt must be a JSON object")
    cache = load_json(args.cache, {"entries": []})
    generated_at = args.generated_at or utc_now()
    now = parse_timestamp(generated_at) or dt.datetime.now(dt.timezone.utc)
    key = receipt_key(source)
    digest = canonical_digest(source)
    summary = summarize_receipt(source, digest, key)
    entries = cache_entries(cache)
    entry = matching_entry(entries, key)
    decision, reason, cache_age = decision_for(summary, entry, now, args.ttl_seconds)

    proposed_record = dict(summary)
    proposed_record.update({
        "cached_at": generated_at,
        "ttl_seconds": args.ttl_seconds,
    })

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "ttl_seconds": args.ttl_seconds,
        "receipt_key": key,
        "decision": decision,
        "reason": reason,
        "cache_age_seconds": cache_age,
        "cache_entry_found": entry is not None,
        "current_receipt_summary": summary,
        "proposed_cache_record": proposed_record,
        "redaction_policy": {
            "raw_receipt_embedded": False,
            "secret_values_embedded": False,
            "output_contains_hashes_and_counts_only": True,
        },
        "non_mutating": True,
        "forbidden_actions": {
            "writes_cache": False,
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate onboarding receipt cache freshness")
    parser.add_argument("--receipt", required=True, help="Current onboarding/session receipt JSON")
    parser.add_argument("--cache", help="Existing cache snapshot JSON")
    parser.add_argument("--ttl-seconds", type=int, default=1800, help="Freshness TTL for cache reuse")
    parser.add_argument("--generated-at", default="", help="Stable UTC timestamp for deterministic receipts")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    if args.ttl_seconds <= 0:
        print(json.dumps({"error": "ttl-seconds must be positive"}, indent=2), file=sys.stderr)
        return 2

    try:
        receipt = build_receipt(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"error": str(error)}, indent=2), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
