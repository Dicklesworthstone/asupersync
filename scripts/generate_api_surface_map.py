#!/usr/bin/env python3
"""Generate the checked Asupersync API surface map artifact.

The current artifact is a deterministic root-surface map built from `src/lib.rs`
plus the curated entry-point config. `--rustdoc-json` is accepted so the deeper
rustdoc JSON item extractor can be added without changing the artifact path or
contract test.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "api-surface-map-v1"
DEFAULT_CONFIG = Path("scripts/api_surface_map_config_v1.json")
DEFAULT_LIB = Path("src/lib.rs")
DEFAULT_OUTPUT = Path("artifacts/api_surface_map_v1.json")

PUB_MOD = re.compile(r"^\s*pub\s+mod\s+([A-Za-z0-9_]+)\s*;")
PUB_MOD_INLINE = re.compile(r"^\s*pub\s+mod\s+([A-Za-z0-9_]+)\s*\{")
PUB_USE_START = re.compile(r"^\s*pub\s+use\s+(.+)")
FEATURE = re.compile(r'feature\s*=\s*"([^"]+)"')


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def stable_dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def collect_cfg(lines: list[str], start: int) -> tuple[str | None, int]:
    line = lines[start].strip()
    if not line.startswith("#[cfg"):
        return None, start

    cfg_lines = [line]
    idx = start
    while not cfg_lines[-1].endswith("]") and idx + 1 < len(lines):
        idx += 1
        cfg_lines.append(lines[idx].strip())
    return " ".join(cfg_lines), idx


def feature_flags(cfg: str | None) -> list[str]:
    if not cfg:
        return []
    return sorted(set(FEATURE.findall(cfg)))


def classify(name: str, cfg: str | None, core_modules: set[str]) -> str:
    cfg_text = cfg or ""
    if "test" in cfg_text or "test-internals" in cfg_text:
        return "test-internals"
    if feature_flags(cfg_text):
        return "feature-gated"
    if "not(target_arch = \"wasm32\")" in cfg_text:
        return "native-only"
    if name in core_modules:
        return "core"
    return "preview"


def parse_root_exports(lib_rs: Path, config: dict[str, Any]) -> list[dict[str, Any]]:
    lines = lib_rs.read_text(encoding="utf-8").splitlines()
    core_modules = set(config.get("core_modules", []))
    module_docs = config.get("module_docs", {})
    exports: list[dict[str, Any]] = []
    pending_cfg: str | None = None
    idx = 0
    brace_depth = 0

    while idx < len(lines):
        if brace_depth > 0:
            brace_depth += lines[idx].count("{") - lines[idx].count("}")
            idx += 1
            continue

        cfg, cfg_end = collect_cfg(lines, idx)
        if cfg is not None:
            pending_cfg = cfg
            idx = cfg_end + 1
            continue

        line = lines[idx]
        mod_match = PUB_MOD.match(line)
        mod_inline_match = PUB_MOD_INLINE.match(line)
        use_match = PUB_USE_START.match(line)

        if mod_match or mod_inline_match:
            name = (mod_match or mod_inline_match).group(1)
            exports.append(
                {
                    "name": name,
                    "kind": "module",
                    "signature": f"pub mod {name}",
                    "doc": module_docs.get(name, ""),
                    "stability": classify(name, pending_cfg, core_modules),
                    "feature_flags": feature_flags(pending_cfg),
                    "cfg": pending_cfg,
                    "line": idx + 1,
                }
            )
            pending_cfg = None
            brace_depth += line.count("{") - line.count("}")
        elif use_match:
            start_line = idx + 1
            use_lines = [use_match.group(1).strip()]
            while ";" not in use_lines[-1] and idx + 1 < len(lines):
                idx += 1
                use_lines.append(lines[idx].strip())
            for target in expand_pub_use(" ".join(use_lines)):
                name = target.split("::", 1)[0].strip("{} ")
                exports.append(
                    {
                        "name": target,
                        "kind": "reexport",
                        "signature": f"pub use {target}",
                        "doc": "",
                        "stability": classify(name, pending_cfg, core_modules),
                        "feature_flags": feature_flags(pending_cfg),
                        "cfg": pending_cfg,
                        "line": start_line,
                    }
                )
            pending_cfg = None
        elif line.strip() and not line.strip().startswith("#["):
            pending_cfg = None
            brace_depth += line.count("{") - line.count("}")

        idx += 1

    return sorted(exports, key=lambda item: (item["kind"], item["name"], item["line"]))


def expand_pub_use(raw: str) -> list[str]:
    cleaned = raw.strip().rstrip(";").strip()
    if "::{" not in cleaned:
        return [cleaned]

    prefix, rest = cleaned.split("::{", 1)
    names = rest.rsplit("}", 1)[0]
    return [
        f"{prefix}::{name.strip()}"
        for name in names.split(",")
        if name.strip()
    ]


def build_entry_points(config: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    entries = []
    for entry in config.get("entry_points", []):
        example_path = entry["example_path"]
        entries.append(
            {
                "use_case": entry["use_case"],
                "symbol": entry["symbol"],
                "summary": entry["summary"],
                "example": {
                    "path": example_path,
                    "exists": (root / example_path).exists(),
                },
            }
        )
    return sorted(entries, key=lambda item: item["use_case"])


def build_map(config_path: Path, lib_rs: Path, rustdoc_json: Path | None) -> dict[str, Any]:
    root = repo_root()
    config = load_json(config_path)
    root_exports = parse_root_exports(lib_rs, config)
    modules = [item for item in root_exports if item["kind"] == "module"]

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "scripts/generate_api_surface_map.py",
        "generation": {
            "source_kind": "src-lib-rs-root-export-scan",
            "rustdoc_json_supported": True,
            "rustdoc_json_input": str(rustdoc_json) if rustdoc_json else None,
            "config_path": str(config_path),
            "source_path": str(lib_rs),
            "command": "rch exec -- python3 scripts/generate_api_surface_map.py --check",
            "notes": [
                "Default contract compares root public exports from src/lib.rs for fast drift detection.",
                "Pass --rustdoc-json to extend item-level extraction without changing the artifact contract.",
            ],
        },
        "entry_points": build_entry_points(config, root),
        "root_exports": root_exports,
        "modules": modules,
        "counts": {
            "entry_points": len(config.get("entry_points", [])),
            "root_exports": len(root_exports),
            "modules": len(modules),
        },
    }


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=root / DEFAULT_CONFIG)
    parser.add_argument("--lib-rs", type=Path, default=root / DEFAULT_LIB)
    parser.add_argument("--output", type=Path, default=root / DEFAULT_OUTPUT)
    parser.add_argument("--rustdoc-json", type=Path)
    parser.add_argument("--check", action="store_true", help="Fail if output is stale")
    args = parser.parse_args()

    artifact = build_map(args.config, args.lib_rs, args.rustdoc_json)
    rendered = stable_dump(artifact)

    if args.check:
        try:
            current = args.output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"{args.output} is missing; regenerate without --check", file=sys.stderr)
            return 1
        if current != rendered:
            print(f"{args.output} is stale; rerun scripts/generate_api_surface_map.py", file=sys.stderr)
            return 1
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
