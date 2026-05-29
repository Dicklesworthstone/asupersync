#!/usr/bin/env python3
"""Run or classify module-scoped proof microharnesses.

The receipt intentionally distinguishes a narrow microharness guarantee from the
broader release gates. A microharness is useful when a blocked proof is trapped
behind a broad lib-test/dev-dep graph, but it must declare the proof target and
the exclusions in the output.
"""

import argparse
import datetime as dt
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "module-microharness-proof-receipt-v1"
DEFAULT_GENERATED_AT = "live"
TEST_TARGET = "raptorq_proof_table_invariant_microharness"
LANES: dict[str, dict[str, Any]] = {
    "raptorq-table-invariant": {
        "lane_id": "raptorq-table-invariant",
        "implementation_bead_id": "asupersync-l5m170.1",
        "blocked_bead_id": "asupersync-to7e65.12",
        "proof_target": "raptorq-proof-table-invariant",
        "cargo_test_target": TEST_TARGET,
        "target_dir_slug": "rch_target_l5m170_1_raptorq_table_invariant",
        "guarantee": (
            "RaptorQ proof-artifact RFC table corruption is reported and serialized "
            "as explicit invariant evidence, not as an unsupported source-block "
            "placeholder or sentinel."
        ),
        "exclusions": [
            "does not run the broad lib-test graph",
            "does not prove full RaptorQ encode/decode recovery",
            "does not replace the final mock-code-finder stub ratchet or release proof gates",
        ],
        "touched_files": [
            "src/raptorq/proof.rs",
            f"tests/{TEST_TARGET}.rs",
        ],
    }
}

SELECTED_WORKER_RE = re.compile(r"Selected worker:\s*(?P<worker>\S+)")
RCH_REMOTE_SUMMARY_RE = re.compile(r"^\[RCH\]\s+remote\s+(?P<worker>\S+)\b", re.MULTILINE)
REMOTE_FINISHED_RE = re.compile(
    r"Remote command finished:\s*exit=(?P<exit>-?\d+)(?:\s+in\s+(?P<elapsed_ms>\d+)ms)?"
)
REMOTE_FAILED_RE = re.compile(
    r"^\[RCH\]\s+remote\s+(?P<worker>\S+)\s+failed\s+\(exit\s+(?P<exit>-?\d+)\)",
    re.MULTILINE,
)
REMOTE_COMMAND_RE = re.compile(r"Executing command remotely:\s*(?P<command>.+)")
RUNNING_TESTS_RE = re.compile(r"\brunning\s+(?P<count>\d+)\s+tests?\b")
TEST_RESULT_RE = re.compile(
    r"test result:\s*(?P<status>ok|FAILED)\.\s+"
    r"(?P<passed>\d+)\s+passed;\s+"
    r"(?P<failed>\d+)\s+failed;\s+"
    r"(?P<ignored>\d+)\s+ignored;\s+"
    r"(?P<measured>\d+)\s+measured;\s+"
    r"(?P<filtered>\d+)\s+filtered out"
)
COMPILE_FRONTIER_RE = re.compile(
    r"^\s*(Compiling|Checking|Finished|Running)\s+.+$|^\s*error(?:\[|\:)|^\s*warning(?:\[|\:)",
    re.MULTILINE,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
TIMEOUT_RE = re.compile(
    r"(?im)(module microharness wrapper timed out|local wrapper timed out|"
    r"timed out while|timeout expired|terminated by timeout|signal TERM)"
)
MICROHARNESS_EVENT_RE = re.compile(r"ASUPERSYNC_MICROHARNESS_EVENT\s+(?P<event>\{.+\})")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def generated_at(value: str | None) -> str:
    if not value or value == DEFAULT_GENERATED_AT:
        return utc_now()
    return value


def default_target_dir(lane: dict[str, Any], run_id: str) -> str:
    slug = lane["target_dir_slug"]
    suffix = f"_{run_id}" if run_id else ""
    return f"${{TMPDIR:-/tmp}}/{slug}{suffix}"


def default_artifact_dir(run_id: str) -> Path:
    slug = run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path(os.environ.get("TMPDIR", "/tmp")) / "asupersync_module_microharness" / slug


def cargo_args(lane: dict[str, Any]) -> list[str]:
    return [
        "cargo",
        "test",
        "-p",
        "asupersync",
        "--test",
        str(lane["cargo_test_target"]),
        "--no-default-features",
        "--features",
        "test-internals",
        "--",
        "--nocapture",
    ]


def command_argv(lane: dict[str, Any], target_dir: str) -> list[str]:
    return [
        "rch",
        "exec",
        "--",
        "env",
        "CARGO_BUILD_JOBS=2",
        "CARGO_INCREMENTAL=0",
        f"CARGO_TARGET_DIR={target_dir}",
        f"ASUPERSYNC_PROOF_BEAD={lane['blocked_bead_id']}",
        f"ASUPERSYNC_PROOF_LANE={lane['lane_id']}",
        *cargo_args(lane),
    ]


def command_display(lane: dict[str, Any], target_dir: str) -> str:
    return "RCH_REQUIRE_REMOTE=1 " + shlex.join(command_argv(lane, target_dir))


def selected_worker(text: str) -> str | None:
    match = SELECTED_WORKER_RE.search(text)
    if match:
        return match.group("worker")
    remote_match = RCH_REMOTE_SUMMARY_RE.search(text)
    if remote_match:
        return remote_match.group("worker")
    failure = REMOTE_FAILED_RE.search(text)
    if failure:
        return failure.group("worker")
    return None


def strip_ansi(value: str) -> str:
    return ANSI_RE.sub("", value).strip()


def remote_exit(text: str) -> int | None:
    matches = list(REMOTE_FINISHED_RE.finditer(text))
    if matches:
        return int(matches[-1].group("exit"))
    failure = REMOTE_FAILED_RE.search(text)
    if failure:
        return int(failure.group("exit"))
    return None


def remote_elapsed_ms(text: str) -> int | None:
    matches = list(REMOTE_FINISHED_RE.finditer(text))
    if not matches:
        return None
    elapsed = matches[-1].group("elapsed_ms")
    return int(elapsed) if elapsed is not None else None


def remote_command(text: str) -> str | None:
    match = REMOTE_COMMAND_RE.search(text)
    if match:
        return strip_ansi(match.group("command"))
    return None


def last_compile_frontier(text: str) -> dict[str, Any] | None:
    last: dict[str, Any] | None = None
    for line_no, line in enumerate(text.splitlines(), start=1):
        if COMPILE_FRONTIER_RE.search(line):
            last = {"line": line_no, "text": strip_ansi(line)}
    return last


def parse_test_count(text: str) -> int | None:
    matches = list(RUNNING_TESTS_RE.finditer(text))
    if not matches:
        return None
    return int(matches[-1].group("count"))


def parse_test_result(text: str) -> dict[str, Any] | None:
    matches = list(TEST_RESULT_RE.finditer(text))
    if not matches:
        return None
    match = matches[-1]
    return {
        "status": match.group("status"),
        "passed": int(match.group("passed")),
        "failed": int(match.group("failed")),
        "ignored": int(match.group("ignored")),
        "measured": int(match.group("measured")),
        "filtered_out": int(match.group("filtered")),
    }


def parse_microharness_events(text: str) -> list[dict[str, Any]]:
    events = []
    for match in MICROHARNESS_EVENT_RE.finditer(text):
        try:
            loaded = json.loads(match.group("event"))
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            events.append(loaded)
    return events


def classify_status(text: str, timed_out: bool) -> tuple[str, str, bool]:
    exit_code = remote_exit(text)
    test_result = parse_test_result(text)
    timeout_seen = timed_out or TIMEOUT_RE.search(text) is not None

    if exit_code == 0 and test_result and test_result["failed"] == 0:
        return "passed", "close-or-unblock-with-current-head-proof", True
    if exit_code is not None and exit_code != 0:
        return "failed", "fix-failing-microharness-before-closeout", False
    if timeout_seen:
        return "unknown-stalled", "retry-on-fresh-worker-or-use-stall-receipt", False
    if exit_code == 0:
        return "unknown-no-test-result", "inspect-log-before-closeout", False
    return "unknown-no-remote-exit", "retry-with-structured-stall-receipt", False


def lane_projection(lane: dict[str, Any], command: str) -> dict[str, Any]:
    return {
        "lane_id": lane["lane_id"],
        "implementation_bead_id": lane["implementation_bead_id"],
        "blocked_bead_id": lane["blocked_bead_id"],
        "proof_target": lane["proof_target"],
        "cargo_test_target": lane["cargo_test_target"],
        "guarantee": lane["guarantee"],
        "exclusions": lane["exclusions"],
        "touched_files": lane["touched_files"],
        "command": command,
    }


def classify_log(
    *,
    lane: dict[str, Any],
    text: str,
    mode: str,
    command: str,
    target_dir: str,
    generated_at_value: str,
    artifact_paths: dict[str, str],
    timed_out: bool = False,
    duration_ms: int | None = None,
) -> dict[str, Any]:
    status, retry_recommendation, passes = classify_status(text, timed_out)
    test_result = parse_test_result(text)
    test_count = parse_test_count(text)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at_value,
        "mode": mode,
        "lane": lane_projection(lane, command),
        "execution": {
            "command": command,
            "target_dir": target_dir,
            "selected_worker": selected_worker(text),
            "remote_exit_code": remote_exit(text),
            "remote_elapsed_ms": remote_elapsed_ms(text),
            "duration_ms": duration_ms,
            "wrapper_timed_out": timed_out or TIMEOUT_RE.search(text) is not None,
            "last_compile_frontier": last_compile_frontier(text),
            "remote_command": remote_command(text),
            "test_count": test_count,
            "test_result": test_result,
            "microharness_events": parse_microharness_events(text),
        },
        "artifacts": artifact_paths,
        "summary": {
            "status": status,
            "passes": passes,
            "retry_recommendation": retry_recommendation,
            "ready_to_close_blocked_bead": passes,
        },
    }


def dry_run_receipt(
    lane: dict[str, Any],
    command: str,
    target_dir: str,
    generated_at_value: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at_value,
        "mode": "dry-run",
        "lane": lane_projection(lane, command),
        "execution": {
            "command": command,
            "target_dir": target_dir,
            "selected_worker": None,
            "remote_exit_code": None,
            "remote_elapsed_ms": None,
            "duration_ms": None,
            "wrapper_timed_out": False,
            "last_compile_frontier": None,
            "remote_command": None,
            "test_count": None,
            "test_result": None,
            "microharness_events": [],
        },
        "artifacts": {},
        "summary": {
            "status": "planned",
            "passes": False,
            "retry_recommendation": "run-with-rch-before-closeout",
            "ready_to_close_blocked_bead": False,
        },
    }


def run_execute(
    lane: dict[str, Any],
    command: str,
    target_dir: str,
    generated_at_value: str,
    artifact_dir: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    log_path = artifact_dir / "module_microharness_rch.log"
    receipt_path = artifact_dir / "module_microharness_receipt.json"

    env = os.environ.copy()
    env["RCH_REQUIRE_REMOTE"] = "1"
    argv = command_argv(lane, target_dir)
    start = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            argv,
            cwd=Path.cwd(),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        text = completed.stdout + completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = error.stdout or ""
        stderr = error.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        text = stdout + stderr + f"\nmodule microharness wrapper timed out after {timeout_seconds}s\n"
    duration_ms = int((time.monotonic() - start) * 1000)

    log_path.write_text(text, encoding="utf-8")
    receipt = classify_log(
        lane=lane,
        text=text,
        mode="execute",
        command=command,
        target_dir=target_dir,
        generated_at_value=generated_at_value,
        artifact_paths={
            "artifact_dir": str(artifact_dir),
            "log": str(log_path),
            "receipt": str(receipt_path),
        },
        timed_out=timed_out,
        duration_ms=duration_ms,
    )
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run or classify module-scoped proof microharnesses")
    parser.add_argument("--lane", choices=sorted(LANES), default="raptorq-table-invariant")
    parser.add_argument("--list", action="store_true", help="list configured microharness lanes")
    parser.add_argument("--dry-run", action="store_true", help="emit the planned receipt without executing rch")
    parser.add_argument("--execute", action="store_true", help="run the lane through rch and write artifacts")
    parser.add_argument("--from-log", type=Path, help="classify an existing combined rch/cargo log")
    parser.add_argument("--command", help="command string to record when classifying --from-log")
    parser.add_argument("--target-dir", help="CARGO_TARGET_DIR to record/use")
    parser.add_argument("--artifact-dir", type=Path, help="artifact directory for --execute")
    parser.add_argument("--run-id", default="", help="stable suffix for target and artifact directories")
    parser.add_argument("--generated-at", default=DEFAULT_GENERATED_AT)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--output", choices=["json", "pretty"], default="json")
    return parser.parse_args(argv)


def emit(receipt: Any, output: str) -> None:
    if output == "pretty":
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print(json.dumps(receipt, sort_keys=True))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    lane = LANES[args.lane]
    target_dir = args.target_dir or default_target_dir(lane, args.run_id)
    command = args.command or command_display(lane, target_dir)
    generated_at_value = generated_at(args.generated_at)

    if args.list:
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": generated_at_value,
                "lanes": [lane_projection(row, command_display(row, default_target_dir(row, args.run_id))) for row in LANES.values()],
            },
            args.output,
        )
        return 0

    modes = [args.dry_run, args.execute, args.from_log is not None]
    if sum(1 for mode in modes if mode) != 1:
        print("choose exactly one of --dry-run, --execute, or --from-log", file=sys.stderr)
        return 2

    if args.dry_run:
        emit(dry_run_receipt(lane, command, target_dir, generated_at_value), args.output)
        return 0

    if args.from_log is not None:
        text = args.from_log.read_text(encoding="utf-8")
        receipt = classify_log(
            lane=lane,
            text=text,
            mode="from-log",
            command=command,
            target_dir=target_dir,
            generated_at_value=generated_at_value,
            artifact_paths={"log": str(args.from_log)},
        )
        emit(receipt, args.output)
        return 0 if receipt["summary"]["status"] != "failed" else 1

    artifact_dir = args.artifact_dir or default_artifact_dir(args.run_id)
    receipt = run_execute(
        lane,
        command,
        target_dir,
        generated_at_value,
        artifact_dir,
        args.timeout,
    )
    emit(receipt, args.output)
    return 0 if receipt["summary"]["passes"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
