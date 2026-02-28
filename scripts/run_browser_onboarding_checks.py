#!/usr/bin/env python3
"""Deterministic Browser Edition onboarding runner.

Runs documented onboarding command bundles for:
- vanilla browser smoke
- react readiness
- next readiness

Emits structured per-step NDJSON logs and scenario summary JSON artifacts under
artifacts/onboarding/.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Step:
    step_id: str
    command: str
    remediation_hint: str


SCENARIOS: dict[str, list[Step]] = {
    "vanilla": [
        Step(
            "vanilla.browser_ready_handoff",
            "rch exec -- cargo test -p asupersync browser_ready_handoff -- --nocapture",
            "Inspect scheduler fairness/handoff regressions in src/runtime/scheduler/three_lane.rs.",
        ),
        Step(
            "vanilla.quiescence",
            "rch exec -- cargo test --test close_quiescence_regression "
            "browser_nested_cancel_cascade_reaches_quiescence -- --nocapture",
            "Verify region close drains cancellation/finalizers before close acknowledgement.",
        ),
        Step(
            "vanilla.security_policy",
            "rch exec -- cargo test --test security_invariants browser_fetch_security -- --nocapture",
            "Review browser fetch capability defaults and allowlist policy in src/io/cap.rs.",
        ),
    ],
    "react": [
        Step(
            "react.clock_start_zero",
            "rch exec -- cargo test --test native_seam_parity "
            "browser_clock_through_trait_starts_at_zero -- --nocapture",
            "Check BrowserMonotonicClock bootstrap semantics and time source trait wiring.",
        ),
        Step(
            "react.clock_advances",
            "rch exec -- cargo test --test native_seam_parity "
            "browser_clock_through_trait_advances_with_host_samples -- --nocapture",
            "Check monotonic clamp policy and host-sample advancement path for browser clock.",
        ),
        Step(
            "react.obligation_lifecycle",
            "rch exec -- cargo test --test obligation_wasm_parity "
            "wasm_full_browser_lifecycle_simulation -- --nocapture",
            "Inspect obligation drain/commit lifecycle invariants in tests/obligation_wasm_parity.rs.",
        ),
    ],
    "next": [
        Step(
            "next.dependency_policy",
            "python3 scripts/check_wasm_dependency_policy.py "
            "--policy .github/wasm_dependency_policy.json",
            "Resolve forbidden or unresolved wasm dependency policy findings before Next integration.",
        ),
        Step(
            "next.wasm_profile_check",
            "rch exec -- cargo check --target wasm32-unknown-unknown "
            "--no-default-features --features wasm-browser-dev",
            "Resolve wasm32 compile blockers (for example getrandom wasm_js gating) before Next onboarding.",
        ),
        Step(
            "next.optimization_policy",
            "python3 scripts/check_wasm_optimization_policy.py "
            "--policy .github/wasm_optimization_policy.json",
            "Fix optimization policy schema/profile mapping and regenerate summary artifact.",
        ),
    ],
}


def write_ndjson(path: Path, rows: Iterable[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def tail_excerpt(path: Path, max_lines: int = 30) -> str:
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-max_lines:])


def run_step(
    scenario_id: str,
    step: Step,
    out_dir: Path,
    dry_run: bool,
) -> dict:
    log_path = out_dir / f"{step.step_id}.log"
    started_at = now_iso()
    t0 = time.perf_counter()

    env_metadata = {
        "cwd": str(Path.cwd()),
        "target": "wasm32-unknown-unknown",
        "runner": "rch",
    }

    if dry_run:
        return {
            "scenario_id": scenario_id,
            "step_id": step.step_id,
            "command": step.command,
            "repro_command": step.command,
            "started_at": started_at,
            "ended_at": started_at,
            "duration_ms": 0,
            "exit_code": 0,
            "outcome": "dry_run",
            "env": env_metadata,
            "artifact_log_path": str(log_path),
            "remediation_hint": step.remediation_hint,
        }

    with log_path.open("w", encoding="utf-8") as log_f:
        proc = subprocess.run(
            step.command,
            shell=True,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )

    duration_ms = int((time.perf_counter() - t0) * 1000)
    ended_at = now_iso()
    outcome = "pass" if proc.returncode == 0 else "fail"

    return {
        "scenario_id": scenario_id,
        "step_id": step.step_id,
        "command": step.command,
        "repro_command": step.command,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "exit_code": proc.returncode,
        "outcome": outcome,
        "env": env_metadata,
        "artifact_log_path": str(log_path),
        "failure_excerpt": tail_excerpt(log_path, max_lines=40) if outcome == "fail" else "",
        "remediation_hint": step.remediation_hint,
    }


def run_scenario(scenario_id: str, out_dir: Path, dry_run: bool) -> int:
    steps = SCENARIOS[scenario_id]
    rows: list[dict] = []
    scenario_status = "pass"

    for step in steps:
        row = run_step(scenario_id=scenario_id, step=step, out_dir=out_dir, dry_run=dry_run)
        rows.append(row)
        if row["outcome"] == "fail":
            scenario_status = "fail"
            # Preserve deterministic partial artifact set and stop early.
            break

    suffix = ".dry_run" if dry_run else ""
    ndjson_path = out_dir / f"{scenario_id}{suffix}.ndjson"
    summary_path = out_dir / f"{scenario_id}{suffix}.summary.json"
    write_ndjson(ndjson_path, rows)

    summary = {
        "schema": "asupersync-onboarding-summary-v1",
        "scenario_id": scenario_id,
        "status": scenario_status if not dry_run else "dry_run",
        "step_count": len(rows),
        "failed_steps": [r["step_id"] for r in rows if r["outcome"] == "fail"],
        "ndjson_path": str(ndjson_path),
        "generated_at": now_iso(),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    print(
        f"[onboarding] scenario={scenario_id} status={summary['status']} "
        f"steps={summary['step_count']} ndjson={ndjson_path}"
    )
    return 0 if summary["status"] in {"pass", "dry_run"} else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run browser onboarding check bundles.")
    parser.add_argument(
        "--scenario",
        choices=["vanilla", "react", "next", "all"],
        default="all",
        help="Scenario to run (default: all).",
    )
    parser.add_argument(
        "--out-dir",
        default="artifacts/onboarding",
        help="Output directory for logs and summaries.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Emit artifacts without executing commands.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    scenarios = ["vanilla", "react", "next"] if args.scenario == "all" else [args.scenario]

    exit_code = 0
    for scenario_id in scenarios:
        scenario_exit = run_scenario(
            scenario_id=scenario_id,
            out_dir=out_dir,
            dry_run=args.dry_run,
        )
        exit_code = max(exit_code, scenario_exit)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
