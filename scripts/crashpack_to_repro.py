#!/usr/bin/env python3
"""Turn crashpack-style failure artifacts into deterministic repro commands.

The helper is intentionally non-mutating. It consumes a small JSON failure
artifact, normalizes it into direct-main-safe command rows, and separates command
safety from any later operator decision to run the command.
"""

import argparse
import datetime as dt
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "crashpack-repro-command-v1"
INPUT_SCHEMA_VERSION = "crashpack-to-repro-input-v1"
SUPPORTED_SOURCE_KINDS = {
    "cargo_test",
    "fuzz",
    "rch_wrapper_hang_after_remote_exit",
    "proof_runner_blocker",
}
FORBIDDEN_PATTERNS = [
    "git branch ",
    "git checkout -b",
    "git switch -c",
    "git worktree",
    "worktree add",
    "git push origin head:",
    "git push --set-upstream",
    "rm -rf",
    "git reset --hard",
    "git clean -fd",
    "/tmp/asupersync-",
    "/data/projects/asupersync-",
]
SPACE_RE = re.compile(r"[^A-Za-z0-9_]+")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> dt.datetime | None:
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


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_string(value: Any) -> str:
    return value if isinstance(value, str) else ""


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def slug(value: str) -> str:
    normalized = SPACE_RE.sub("_", value.strip()).strip("_").lower()
    return normalized[:80] or "unnamed"


def target_dir(artifact_id: str) -> str:
    return f"${{TMPDIR:-/tmp}}/rch_target_crashpack_{slug(artifact_id)}"


def cargo_env(artifact_id: str) -> list[str]:
    return [
        "CARGO_INCREMENTAL=0",
        f"CARGO_TARGET_DIR={target_dir(artifact_id)}",
        "CARGO_PROFILE_TEST_DEBUG=0",
        "RUSTFLAGS=-C debuginfo=0",
    ]


def rch_cargo_command(artifact_id: str, cargo_args: list[str]) -> list[str]:
    return ["rch", "exec", "--", "env", *cargo_env(artifact_id), *cargo_args]


def cargo_test_args(data: dict[str, Any]) -> list[str]:
    cargo = as_dict(data.get("cargo"))
    args = ["cargo", "test"]
    package = as_string(cargo.get("package"))
    if package:
        args.extend(["-p", package])
    test_target = as_string(cargo.get("test"))
    if test_target:
        args.extend(["--test", test_target])
    features = as_string_list(cargo.get("features"))
    if features:
        args.extend(["--features", ",".join(sorted(features))])
    test_filter = as_string(cargo.get("filter"))
    if test_filter:
        args.append(test_filter)
    extra_args = as_string_list(cargo.get("extra_args"))
    if extra_args:
        args.append("--")
        args.extend(extra_args)
    return args


def fuzz_args(data: dict[str, Any]) -> list[str]:
    fuzz = as_dict(data.get("fuzz"))
    target = as_string(fuzz.get("target"))
    if not target:
        raise ValueError("fuzz artifact requires fuzz.target")
    args = ["cargo", "fuzz", "run", target]
    artifact_path = as_string(fuzz.get("artifact_path"))
    if artifact_path:
        args.append(artifact_path)
    libfuzzer_args = as_string_list(fuzz.get("libfuzzer_args"))
    if libfuzzer_args:
        args.append("--")
        args.extend(libfuzzer_args)
    return args


def proof_runner_args(data: dict[str, Any]) -> list[str]:
    proof_runner = as_dict(data.get("proof_runner"))
    cargo_args = as_string_list(proof_runner.get("cargo_args"))
    if not cargo_args:
        raise ValueError("proof_runner_blocker artifact requires proof_runner.cargo_args")
    if cargo_args[0] != "cargo":
        raise ValueError("proof_runner.cargo_args must start with cargo")
    return cargo_args


def uses_rch(argv: list[str]) -> bool:
    return len(argv) >= 3 and argv[0:3] == ["rch", "exec", "--"]


def command_violations(argv: list[str]) -> list[dict[str, str]]:
    joined = " ".join(argv).lower()
    violations = []
    for pattern in FORBIDDEN_PATTERNS:
        if pattern in joined:
            violations.append(
                {
                    "code": "forbidden-command-pattern",
                    "pattern": pattern,
                    "message": "generated command is not direct-main safe",
                }
            )
    runs_cargo = "cargo" in argv
    if runs_cargo and not uses_rch(argv):
        violations.append(
            {
                "code": "cargo-without-rch",
                "pattern": "cargo",
                "message": "cargo proof commands must be routed through rch",
            }
        )
    if "/tmp/rch_target_" in joined:
        violations.append(
            {
                "code": "hardcoded-tmpdir",
                "pattern": "/tmp/rch_target_",
                "message": "target dirs must use ${TMPDIR:-/tmp}",
            }
        )
    return violations


def command_row(
    command_id: str,
    kind: str,
    argv: list[str],
    cwd: str,
    reason: str,
) -> dict[str, Any]:
    violations = command_violations(argv)
    return {
        "id": command_id,
        "kind": kind,
        "argv": argv,
        "shell_command": shlex.join(argv),
        "cwd": cwd,
        "reason": reason,
        "uses_rch": uses_rch(argv),
        "runs_cargo": "cargo" in argv,
        "direct_main_safe": not violations,
        "safety_violations": violations,
    }


def build_commands(data: dict[str, Any]) -> list[dict[str, Any]]:
    artifact_id = as_string(data.get("artifact_id")) or "unnamed"
    cwd = as_string(as_dict(data.get("repo")).get("cwd")) or "."
    source_kind = as_string(data.get("source_kind"))

    if source_kind == "cargo_test":
        return [
            command_row(
                "rerun-cargo-test",
                "cargo-test-rerun",
                rch_cargo_command(artifact_id, cargo_test_args(data)),
                cwd,
                "rerun the focused failing integration or unit test through rch",
            )
        ]
    if source_kind == "fuzz":
        return [
            command_row(
                "rerun-fuzz-artifact",
                "fuzz-artifact-rerun",
                rch_cargo_command(artifact_id, fuzz_args(data)),
                cwd,
                "replay the captured fuzz artifact through rch without creating branches or worktrees",
            )
        ]
    if source_kind == "proof_runner_blocker":
        return [
            command_row(
                "rerun-proof-runner-blocker",
                "proof-runner-blocker-rerun",
                rch_cargo_command(artifact_id, proof_runner_args(data)),
                cwd,
                "rerun the blocked proof-runner contract lane through rch",
            )
        ]
    if source_kind == "rch_wrapper_hang_after_remote_exit":
        rch = as_dict(data.get("rch"))
        original = as_string_list(rch.get("original_command_argv"))
        if not original:
            raise ValueError("rch wrapper artifact requires rch.original_command_argv")
        commands = [
            command_row(
                "rerun-remote-proof",
                "rch-remote-proof-rerun",
                original,
                cwd,
                "rerun the exact remote proof command; keep remote exit separate from artifact retrieval",
            )
        ]
        log_path = as_string(rch.get("log_path"))
        wrapper_exit_code = rch.get("wrapper_exit_code")
        if log_path:
            diagnostic = [
                "python3",
                "scripts/rch_retrieval_receipt.py",
                "--log",
                log_path,
                "--output",
                "json",
            ]
            if isinstance(wrapper_exit_code, int):
                diagnostic.extend(["--wrapper-exit-code", str(wrapper_exit_code)])
            commands.append(
                command_row(
                    "classify-rch-retrieval",
                    "rch-retrieval-diagnostic",
                    diagnostic,
                    cwd,
                    "classify wrapper retrieval separately from the remote proof verdict",
                )
            )
        return commands
    raise ValueError(f"unsupported source_kind: {source_kind}")


def existing_helper_analysis() -> dict[str, Any]:
    return {
        "new_tool_file_required": True,
        "rationale": (
            "existing helpers classify a single proof log, inventory proof helpers, "
            "or replay coordination transcripts; none accepts heterogeneous crashpack "
            "and failure-artifact schemas and emits normalized repro command JSON"
        ),
        "existing_helpers_considered": [
            {
                "path": "scripts/rch_retrieval_receipt.py",
                "fit": "partial",
                "reason": "classifies rch retrieval logs but does not generate rerun commands from cargo, fuzz, or proof-runner artifacts",
            },
            {
                "path": "scripts/swarm_coordination_replay_pack.py",
                "fit": "not-an-extension-point",
                "reason": "validates coordination timelines and closeout evidence, not failure-artifact command synthesis",
            },
            {
                "path": "scripts/proof_receipt_inventory.py",
                "fit": "not-an-extension-point",
                "reason": "inventories helper capabilities and duplicate proof surfaces, not crashpack repro commands",
            },
        ],
    }


def build_receipt(args: argparse.Namespace) -> dict[str, Any]:
    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    generated_at = args.generated_at or utc_now()
    source_kind = as_string(data.get("source_kind"))
    if data.get("schema_version") != INPUT_SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {INPUT_SCHEMA_VERSION}")
    if source_kind not in SUPPORTED_SOURCE_KINDS:
        raise ValueError(f"source_kind must be one of {sorted(SUPPORTED_SOURCE_KINDS)}")

    commands = build_commands(data)
    violations = [
        {**violation, "command_id": command["id"]}
        for command in commands
        for violation in command["safety_violations"]
    ]
    failure = as_dict(data.get("failure"))
    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": data.get("schema_version"),
        "generated_at": generated_at,
        "current_date": current_date(generated_at),
        "source": {
            "artifact_id": as_string(data.get("artifact_id")),
            "source_kind": source_kind,
            "bead_id": as_string(data.get("bead_id")),
            "summary": as_string(failure.get("summary")),
            "first_blocker": as_string(failure.get("first_blocker")),
            "touched_files": sorted(set(as_string_list(data.get("touched_files")))),
        },
        "accepted_input_contract": {
            "schema_version": INPUT_SCHEMA_VERSION,
            "supported_source_kinds": sorted(SUPPORTED_SOURCE_KINDS),
            "required_top_level_fields": [
                "schema_version",
                "artifact_id",
                "source_kind",
                "failure",
            ],
        },
        "tool_selection": existing_helper_analysis(),
        "commands": commands,
        "summary": {
            "command_count": len(commands),
            "safe_for_direct_main": not violations,
            "safety_violation_count": len(violations),
        },
        "safety": {
            "direct_main_safe": not violations,
            "violations": violations,
            "forbidden_patterns_checked": FORBIDDEN_PATTERNS,
            "cargo_commands_require_rch": True,
            "target_dirs_require_tmpdir_expansion": True,
        },
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "runs_agent_mail_mutation": False,
            "runs_destructive_command": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate repro commands from crashpack failure artifacts")
    parser.add_argument("--input", required=True, help="Path to crashpack-to-repro JSON input")
    parser.add_argument("--generated-at", default="", help="UTC timestamp for deterministic output")
    parser.add_argument("--output", choices=["json"], default="json")
    args = parser.parse_args()

    try:
        receipt = build_receipt(args)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(json.dumps({"error": str(error)}, indent=2, sort_keys=True), file=sys.stderr)
        return 2

    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
