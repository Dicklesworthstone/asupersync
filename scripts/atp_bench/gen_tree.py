#!/usr/bin/env python3
"""Seeded power-law tree generator for the ATP benchmark matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class TreeProfile:
    name: str
    files: int
    alpha: float
    min_size: int
    max_size: int
    depth: int
    fanout: int


PROFILES = {
    "tree_small": TreeProfile(
        name="tree_small",
        files=2_000,
        alpha=1.4,
        min_size=1 * 1024,
        max_size=1 * 1024 * 1024,
        depth=6,
        fanout=5,
    ),
    "tree_big": TreeProfile(
        name="tree_big",
        files=400,
        alpha=1.2,
        min_size=10 * 1024,
        max_size=50 * 1024 * 1024,
        depth=5,
        fanout=7,
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate deterministic benchmark file trees and JSONL manifests."
    )
    parser.add_argument("--root", required=True, type=Path, help="tree output root")
    parser.add_argument(
        "--kind",
        choices=sorted(PROFILES),
        default="tree_small",
        help="built-in tree profile",
    )
    parser.add_argument("--seed", type=int, default=0xA7BEEF, help="deterministic seed")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="manifest JSONL path; defaults to <root>.manifest.jsonl",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="emit manifest path/size rows without creating payload files",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="also print a one-line JSON summary to stdout",
    )
    return parser.parse_args()


def bounded_pareto_size(rng: random.Random, profile: TreeProfile) -> int:
    while True:
        u = max(rng.random(), 1e-12)
        size = int(profile.min_size / ((1.0 - u) ** (1.0 / profile.alpha)))
        if profile.min_size <= size <= profile.max_size:
            return size


def randbytes(rng: random.Random, size: int) -> bytes:
    if hasattr(rng, "randbytes"):
        return rng.randbytes(size)
    return bytes(rng.getrandbits(8) for _ in range(size))


def rel_path_for(index: int, seed: int, profile: TreeProfile) -> Path:
    rng = random.Random((seed << 32) ^ index ^ 0x5EED5EED)
    depth = max(1, profile.depth - rng.randrange(0, 3))
    parts = []
    n = index
    for level in range(depth):
        bucket = (n + rng.randrange(profile.fanout)) % profile.fanout
        parts.append(f"d{level:02d}_{bucket:02d}")
        n //= max(profile.fanout, 1)
    return Path(*parts) / f"file_{index:06d}.bin"


def planned_rows(profile: TreeProfile, seed: int) -> Iterable[dict[str, object]]:
    size_rng = random.Random(seed ^ 0x51A5E5)
    for index in range(profile.files):
        rel = rel_path_for(index, seed, profile)
        yield {
            "schema": "atp-bench-tree-manifest-v1",
            "kind": profile.name,
            "seed": seed,
            "index": index,
            "path": rel.as_posix(),
            "size": bounded_pareto_size(size_rng, profile),
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_payload(path: Path, size: int, seed: int, index: int) -> str:
    if path.exists():
        if not path.is_file():
            raise RuntimeError(f"refusing to overwrite non-file path: {path}")
        actual = path.stat().st_size
        if actual != size:
            raise RuntimeError(
                f"existing file size mismatch for {path}: have {actual}, want {size}"
            )
        return sha256_file(path)

    path.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random((seed << 32) ^ index ^ 0xC001D00D)
    remaining = size
    digest = hashlib.sha256()
    with path.open("xb") as fh:
        while remaining:
            chunk_size = min(CHUNK_SIZE, remaining)
            chunk = randbytes(rng, chunk_size)
            fh.write(chunk)
            digest.update(chunk)
            remaining -= chunk_size
    return digest.hexdigest()


def ensure_inside(root: Path, child: Path) -> None:
    root_abs = root.resolve()
    child_abs = child.resolve(strict=False)
    try:
        child_abs.relative_to(root_abs)
    except ValueError as exc:
        raise RuntimeError(f"generated path escapes root: {child}") from exc


def main() -> int:
    args = parse_args()
    profile = PROFILES[args.kind]
    root = args.root
    manifest = args.manifest or root.with_suffix(root.suffix + ".manifest.jsonl")

    if root.exists() and not root.is_dir():
        raise RuntimeError(f"root exists and is not a directory: {root}")
    if manifest.exists() and not manifest.is_file():
        raise RuntimeError(f"manifest exists and is not a file: {manifest}")
    if not args.dry_run:
        root.mkdir(parents=True, exist_ok=True)
        manifest.parent.mkdir(parents=True, exist_ok=True)

    rows = list(planned_rows(profile, args.seed))
    total_bytes = 0
    if args.dry_run:
        out = sys.stdout
        close_out = False
    else:
        out = manifest.open("x", encoding="utf-8")
        close_out = True

    try:
        for row in rows:
            rel = Path(str(row["path"]))
            target = root / rel
            ensure_inside(root, target)
            total_bytes += int(row["size"])
            if args.dry_run:
                row["sha256"] = None
            else:
                row["sha256"] = write_payload(target, int(row["size"]), args.seed, int(row["index"]))
            out.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    finally:
        if close_out:
            out.close()

    if args.summary:
        summary = {
            "schema": "atp-bench-tree-summary-v1",
            "kind": profile.name,
            "seed": args.seed,
            "files": len(rows),
            "total_bytes": total_bytes,
            "root": os.fspath(root),
            "manifest": os.fspath(manifest),
            "dry_run": bool(args.dry_run),
        }
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(1)
    except Exception as exc:
        print(f"gen_tree.py: {exc}", file=sys.stderr)
        raise SystemExit(2)
