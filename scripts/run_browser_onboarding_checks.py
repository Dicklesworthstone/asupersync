#!/usr/bin/env python3
"""Deterministic Browser Edition onboarding runner.

Runs documented onboarding command bundles for:
- vanilla browser smoke
- dedicated worker readiness
- shared-worker coordinator readiness
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
    package_entrypoint: str = ""
    adapter_path: str = ""
    runtime_profile: str = "FP-BR-DEV"
    diagnostic_category: str = "onboarding"
    coverage_kind: str = "policy"
    trace_artifact_hint: str = ""


def rch_cargo_command(target_slug: str, cargo_args: str) -> str:
    if not all(char.isalnum() or char == "_" for char in target_slug):
        raise ValueError("target_slug must contain only letters, numbers, or underscores")
    return (
        'rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/'
        f'rch_target_browser_onboarding_{target_slug}" cargo {cargo_args}'
    )


SCENARIOS: dict[str, list[Step]] = {
    "vanilla": [
        Step(
            "vanilla.typescript_type_model",
            "python3 scripts/check_wasm_typescript_type_model_policy.py "
            "--policy .github/wasm_typescript_type_model_policy.json "
            "--only-scenario TS-TYPE-VANILLA",
            "Resolve type-model policy findings for vanilla TypeScript semantics.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="type_model",
        ),
        Step(
            "vanilla.typescript_package_topology",
            "python3 scripts/check_wasm_typescript_package_policy.py "
            "--policy .github/wasm_typescript_package_policy.json "
            "--only-scenario TS-PKG-VANILLA-ESM "
            "--only-scenario TS-PKG-VANILLA-CJS",
            "Resolve package topology/export-map policy findings for vanilla TypeScript onboarding.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="package_topology",
        ),
        Step(
            "vanilla.storage_artifact_bundle",
            "PATH=/usr/bin:$PATH bash scripts/validate_vite_vanilla_consumer.sh",
            "Restage package outputs or inspect the maintained vanilla consumer fixture when BrowserStorage or BrowserArtifactStore bundle markers drift.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="durable_storage",
            coverage_kind="behavioral",
            trace_artifact_hint="target/e2e-results/vite_vanilla_consumer/<timestamp>/summary.json",
        ),
        Step(
            "vanilla.browser_ready_handoff",
            rch_cargo_command(
                "vanilla_browser_ready_handoff",
                "test -p asupersync browser_ready_handoff -- --nocapture",
            ),
            "Inspect scheduler fairness/handoff regressions in src/runtime/scheduler/three_lane.rs.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="runtime_handoff",
        ),
        Step(
            "vanilla.quiescence",
            rch_cargo_command(
                "vanilla_quiescence",
                "test --test close_quiescence_regression "
                "browser_nested_cancel_cascade_reaches_quiescence -- --nocapture",
            ),
            "Verify region close drains cancellation/finalizers before close acknowledgement.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="quiescence",
        ),
        Step(
            "vanilla.security_policy",
            rch_cargo_command(
                "vanilla_security_policy",
                "test --test security_invariants browser_fetch_security -- --nocapture",
            ),
            "Review browser fetch capability defaults and allowlist policy in src/io/cap.rs.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="security_policy",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/vanilla.security_policy.log",
        ),
        Step(
            "vanilla.behavior_loser_drain_replay",
            rch_cargo_command(
                "vanilla_behavior_loser_drain_replay",
                "test --test e2e_combinator "
                "browser_spork_harness_deterministic_replay -- --nocapture",
            ),
            "Investigate browser loser-drain replay determinism regressions in tests/e2e/combinator/cancel_correctness/browser_loser_drain.rs.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="loser_drain",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/vanilla.behavior_loser_drain_replay.log",
        ),
        Step(
            "vanilla.negative_skipped_loser_detection",
            rch_cargo_command(
                "vanilla_negative_skipped_loser_detection",
                "test --test e2e_combinator "
                "browser_oracle_detects_skipped_loser -- --nocapture",
            ),
            "Ensure loser-drain oracle violations are surfaced with deterministic diagnostics.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="loser_drain_negative",
            coverage_kind="negative",
            trace_artifact_hint="artifacts/onboarding/vanilla.negative_skipped_loser_detection.log",
        ),
        Step(
            "vanilla.timing_mid_computation_drain",
            rch_cargo_command(
                "vanilla_timing_mid_computation_drain",
                "test --test e2e_combinator "
                "browser_mid_computation_task_drained_on_region_close -- --nocapture",
            ),
            "Verify mid-computation cancellation drains under browser-style cooperative scheduling.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="timing_stress",
            coverage_kind="timing_stress",
            trace_artifact_hint="artifacts/onboarding/vanilla.timing_mid_computation_drain.log",
        ),
        Step(
            "vanilla.lifecycle_tab_suspension_multi_obligation",
            rch_cargo_command(
                "vanilla_lifecycle_tab_suspension_multi_obligation",
                "test --test obligation_wasm_parity "
                "wasm_host_interruption_tab_suspension_multi_obligation -- --nocapture",
            ),
            "Investigate lifecycle chaos drift for multi-obligation tab suspension handling.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="lifecycle_chaos",
            coverage_kind="lifecycle_chaos",
            trace_artifact_hint="artifacts/onboarding/vanilla.lifecycle_tab_suspension_multi_obligation.log",
        ),
        Step(
            "vanilla.lifecycle_suspend_resume_cancel_drain",
            rch_cargo_command(
                "vanilla_lifecycle_suspend_resume_cancel_drain",
                "test --test obligation_wasm_parity "
                "wasm_host_interruption_during_cancel_drain -- --nocapture",
            ),
            "Verify suspend/resume cancel-drain path stays leak-free under lifecycle interruption.",
            package_entrypoint="@asupersync/browser",
            adapter_path="none",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="lifecycle_chaos",
            coverage_kind="lifecycle_chaos",
            trace_artifact_hint="artifacts/onboarding/vanilla.lifecycle_suspend_resume_cancel_drain.log",
        ),
    ],
    "react": [
        Step(
            "react.typescript_type_model",
            "python3 scripts/check_wasm_typescript_type_model_policy.py "
            "--policy .github/wasm_typescript_type_model_policy.json "
            "--only-scenario TS-TYPE-REACT",
            "Resolve type-model policy findings for React adapter semantics.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="type_model",
        ),
        Step(
            "react.typescript_package_topology",
            "python3 scripts/check_wasm_typescript_package_policy.py "
            "--policy .github/wasm_typescript_package_policy.json "
            "--only-scenario TS-PKG-REACT-ESM "
            "--only-scenario TS-PKG-REACT-CJS",
            "Resolve package topology/export-map policy findings for React adapter onboarding.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="package_topology",
        ),
        Step(
            "react.clock_start_zero",
            rch_cargo_command(
                "react_clock_start_zero",
                "test --test native_seam_parity "
                "browser_clock_through_trait_starts_at_zero -- --nocapture",
            ),
            "Check BrowserMonotonicClock bootstrap semantics and time source trait wiring.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="adapter_lifecycle",
        ),
        Step(
            "react.clock_advances",
            rch_cargo_command(
                "react_clock_advances",
                "test --test native_seam_parity "
                "browser_clock_through_trait_advances_with_host_samples -- --nocapture",
            ),
            "Check monotonic clamp policy and host-sample advancement path for browser clock.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="adapter_lifecycle",
        ),
        Step(
            "react.obligation_lifecycle",
            rch_cargo_command(
                "react_obligation_lifecycle",
                "test --test obligation_wasm_parity "
                "wasm_full_browser_lifecycle_simulation -- --nocapture",
            ),
            "Inspect obligation drain/commit lifecycle invariants in tests/obligation_wasm_parity.rs.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="obligation_lifecycle",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/react.obligation_lifecycle.log",
        ),
        Step(
            "react.behavior_strict_mode_double_invocation",
            rch_cargo_command(
                "react_behavior_strict_mode_double_invocation",
                "test --test react_wasm_strictmode_harness "
                "strict_mode_double_invocation_is_leak_free_and_cancel_correct -- --nocapture",
            ),
            "Fix React strict-mode lifecycle leaks or cancel/join sequencing drift.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="strict_mode_behavior",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/react.behavior_strict_mode_double_invocation.log",
        ),
        Step(
            "react.timing_restart_churn",
            rch_cargo_command(
                "react_timing_restart_churn",
                "test --test react_wasm_strictmode_harness "
                "rapid_restart_churn_keeps_event_sequence_balanced -- --nocapture",
            ),
            "Investigate restart-churn race regressions in React adapter task cancellation/join sequencing.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="restart_churn",
            coverage_kind="timing_stress",
            trace_artifact_hint="artifacts/onboarding/react.timing_restart_churn.log",
        ),
        Step(
            "react.lifecycle_background_throttle_suspend_resume",
            rch_cargo_command(
                "react_lifecycle_background_throttle_suspend_resume",
                "test --test react_wasm_strictmode_harness "
                "lifecycle_background_throttle_suspend_resume_navigation_churn_is_deterministic -- --nocapture",
            ),
            "Investigate React lifecycle chaos regressions across background throttle, suspend/resume, and navigation churn.",
            package_entrypoint="@asupersync/react",
            adapter_path="react/provider",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="lifecycle_chaos",
            coverage_kind="lifecycle_chaos",
            trace_artifact_hint="artifacts/onboarding/react.lifecycle_background_throttle_suspend_resume.log",
        ),
    ],
    "worker": [
        Step(
            "worker.runtime_support_matrix",
            rch_cargo_command(
                "worker_runtime_support_matrix",
                "test --test wasm_browser_feasibility_matrix "
                "dedicated_worker_ -- --nocapture",
            ),
            "Inspect dedicated-worker support classification drift across packages/browser/src/index.ts, docs/WASM.md, and docs/integration.md.",
            package_entrypoint="@asupersync/browser",
            adapter_path="worker/bootstrap",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="support_matrix",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/worker.runtime_support_matrix.log",
        ),
        Step(
            "worker.sdk_runtime_diagnostics",
            rch_cargo_command(
                "worker_sdk_runtime_diagnostics",
                "test --test wasm_js_exports_coverage_contract "
                "browser_src_index_ -- --nocapture",
            ),
            "Verify dedicated-worker runtime diagnostics and actionable guidance in packages/browser/src/index.ts.",
            package_entrypoint="@asupersync/browser",
            adapter_path="worker/bootstrap",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="sdk_diagnostics",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/worker.sdk_runtime_diagnostics.log",
        ),
        Step(
            "worker.storage_artifact_diagnostics",
            rch_cargo_command(
                "worker_storage_artifact_diagnostics",
                "test --test wasm_js_exports_coverage_contract "
                "browser_src_index_exposes_storage_and_artifact_diagnostics -- --nocapture",
            ),
            "Verify BrowserStorage and BrowserArtifactStore failure diagnostics, cleanup flows, and worker download guidance in packages/browser/src/index.ts.",
            package_entrypoint="@asupersync/browser",
            adapter_path="worker/bootstrap",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="durable_storage",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/worker.storage_artifact_diagnostics.log",
        ),
        Step(
            "worker.fetch_host_bridge",
            rch_cargo_command(
                "worker_fetch_host_bridge",
                "test --test wasm_js_exports_coverage_contract "
                "browser_core_fetch_bridge_supports_window_or_worker_hosts -- --nocapture",
            ),
            "Confirm browser-core fetch host wiring still accepts dedicated-worker globals when window is unavailable.",
            package_entrypoint="@asupersync/browser",
            adapter_path="worker/bootstrap",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="fetch_host",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/worker.fetch_host_bridge.log",
        ),
        Step(
            "worker.coordinator_protocol",
            rch_cargo_command(
                "worker_coordinator_protocol",
                "test --lib worker_channel::tests::coordinator_ -- --nocapture",
            ),
            "Investigate worker coordination protocol regressions in src/net/worker_channel.rs before touching browser-side bootstrap code.",
            package_entrypoint="@asupersync/browser",
            adapter_path="worker/bootstrap",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="worker_coordination",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/worker.coordinator_protocol.log",
        ),
        Step(
            "worker.storage_artifact_export_handoff",
            "PATH=/usr/bin:$PATH bash scripts/validate_dedicated_worker_consumer.sh",
            "Rebuild or restage package artifacts if the maintained dedicated-worker consumer fixture cannot bundle the storage/export handoff path cleanly.",
            package_entrypoint="@asupersync/browser",
            adapter_path="worker/bootstrap",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="durable_storage",
            coverage_kind="behavioral",
            trace_artifact_hint="target/e2e-results/dedicated_worker_consumer/<timestamp>/summary.json",
        ),
    ],
    "shared_worker": [
        Step(
            "shared_worker.support_matrix",
            rch_cargo_command(
                "shared_worker_support_matrix",
                "test --test wasm_browser_feasibility_matrix "
                "shared_worker_ -- --nocapture",
            ),
            "Inspect shared-worker fail-closed and bounded coordinator contract drift across docs, onboarding, and package helpers.",
            package_entrypoint="@asupersync/browser",
            adapter_path="shared_worker/coordinator",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="support_matrix",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/shared_worker.support_matrix.log",
        ),
        Step(
            "shared_worker.coordinator_fixture",
            "PATH=/usr/bin:$PATH bash scripts/validate_shared_worker_consumer.sh",
            "Rebuild or restage package artifacts if the maintained shared-worker consumer fixture cannot bundle or replay the bounded coordinator attach/reuse/fallback path cleanly.",
            package_entrypoint="@asupersync/browser",
            adapter_path="shared_worker/coordinator",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="shared_worker_coordination",
            coverage_kind="behavioral",
            trace_artifact_hint="target/e2e-results/shared_worker_consumer/<timestamp>/summary.json",
        ),
    ],
    "next": [
        Step(
            "next.typescript_type_model",
            "python3 scripts/check_wasm_typescript_type_model_policy.py "
            "--policy .github/wasm_typescript_type_model_policy.json "
            "--only-scenario TS-TYPE-NEXT",
            "Resolve type-model policy findings for Next.js adapter semantics.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="type_model",
        ),
        Step(
            "next.typescript_package_topology",
            "python3 scripts/check_wasm_typescript_package_policy.py "
            "--policy .github/wasm_typescript_package_policy.json "
            "--only-scenario TS-PKG-NEXT-ESM "
            "--only-scenario TS-PKG-NEXT-CJS",
            "Resolve package topology/export-map policy findings for Next.js adapter onboarding.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="package_topology",
        ),
        Step(
            "next.dependency_policy",
            "python3 scripts/check_wasm_dependency_policy.py "
            "--policy .github/wasm_dependency_policy.json",
            "Resolve forbidden or unresolved wasm dependency policy findings before Next integration.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="dependency_policy",
        ),
        Step(
            "next.wasm_profile_check",
            rch_cargo_command(
                "next_wasm_profile_check",
                "check --target wasm32-unknown-unknown "
                "--no-default-features --features wasm-browser-dev",
            ),
            "Resolve wasm32 compile blockers (for example getrandom wasm_js gating) before Next onboarding.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="profile_closure",
        ),
        Step(
            "next.bootstrap_state_machine_contract",
            rch_cargo_command(
                "next_bootstrap_state_machine_contract",
                "test --test wasm_abi_contract nextjs_bootstrap_ -- --nocapture",
            ),
            "Fix Next.js bootstrap transition/recovery contract regressions and ensure deterministic log fields.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="bootstrap_contract",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/next.bootstrap_state_machine_contract.log",
        ),
        Step(
            "next.behavior_bootstrap_harness",
            rch_cargo_command(
                "next_behavior_bootstrap_harness",
                "test --test nextjs_bootstrap_harness -- --nocapture",
            ),
            "Investigate Next.js hydration/bootstrap behavior regressions in harness tests.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="bootstrap_harness",
            coverage_kind="behavioral",
            trace_artifact_hint="artifacts/onboarding/next.behavior_bootstrap_harness.log",
        ),
        Step(
            "next.timing_navigation_churn",
            rch_cargo_command(
                "next_timing_navigation_churn",
                "test --test nextjs_bootstrap_harness "
                "rapid_navigation_churn_with_interleaved_recovery_remains_deterministic -- --nocapture",
            ),
            "Investigate navigation-churn timing/recovery regressions in Next.js bootstrap state machine.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="lifecycle_chaos",
            coverage_kind="lifecycle_chaos",
            trace_artifact_hint="artifacts/onboarding/next.timing_navigation_churn.log",
        ),
        Step(
            "next.optimization_policy",
            "python3 scripts/check_wasm_optimization_policy.py "
            "--policy .github/wasm_optimization_policy.json",
            "Fix optimization policy schema/profile mapping and regenerate summary artifact.",
            package_entrypoint="@asupersync/next",
            adapter_path="next/app-router",
            runtime_profile="FP-BR-DEV",
            diagnostic_category="optimization_policy",
            coverage_kind="policy",
            trace_artifact_hint="artifacts/onboarding/next.optimization_policy.log",
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


def log_has_rch_local_fallback(path: Path) -> bool:
    if not path.exists():
        return False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("[RCH] local (") or "falling back to local" in line.lower():
            return True
    return False


def run_step(
    scenario_id: str,
    step_index: int,
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
        "runtime_profile": step.runtime_profile,
        "framework_lane": scenario_id,
    }

    if dry_run:
        return {
            "scenario_id": scenario_id,
            "step_index": step_index,
            "step_id": step.step_id,
            "correlation_id": f"{scenario_id}:{step_index:02d}:{step.step_id}",
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
            "package_entrypoint": step.package_entrypoint,
            "adapter_path": step.adapter_path,
            "runtime_profile": step.runtime_profile,
            "diagnostic_category": step.diagnostic_category,
            "coverage_kind": step.coverage_kind,
            "trace_artifact_hint": step.trace_artifact_hint,
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
    exit_code = proc.returncode
    rch_local_fallback = log_has_rch_local_fallback(log_path)
    rch_local_fallback_marker = ""
    if rch_local_fallback:
        exit_code = 86
        rch_local_fallback_marker = str(
            log_path.with_name(f"{log_path.stem}.rch_local_fallback.txt")
        )
        Path(rch_local_fallback_marker).write_text(
            "rch local fallback detected; refusing local cargo execution\n",
            encoding="utf-8",
        )
    outcome = "pass" if exit_code == 0 else "fail"

    return {
        "scenario_id": scenario_id,
        "step_index": step_index,
        "step_id": step.step_id,
        "correlation_id": f"{scenario_id}:{step_index:02d}:{step.step_id}",
        "command": step.command,
        "repro_command": step.command,
        "started_at": started_at,
        "ended_at": ended_at,
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "outcome": outcome,
        "env": env_metadata,
        "artifact_log_path": str(log_path),
        "rch_local_fallback": rch_local_fallback,
        "rch_local_fallback_marker": rch_local_fallback_marker,
        "failure_excerpt": tail_excerpt(log_path, max_lines=40) if outcome == "fail" else "",
        "remediation_hint": step.remediation_hint,
        "package_entrypoint": step.package_entrypoint,
        "adapter_path": step.adapter_path,
        "runtime_profile": step.runtime_profile,
        "diagnostic_category": step.diagnostic_category,
        "coverage_kind": step.coverage_kind,
        "trace_artifact_hint": step.trace_artifact_hint,
    }


def run_scenario(scenario_id: str, out_dir: Path, dry_run: bool) -> int:
    steps = SCENARIOS[scenario_id]
    rows: list[dict] = []
    scenario_status = "pass"

    for index, step in enumerate(steps):
        row = run_step(
            scenario_id=scenario_id,
            step_index=index,
            step=step,
            out_dir=out_dir,
            dry_run=dry_run,
        )
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
        "ordered_correlation_ids": [r["correlation_id"] for r in rows],
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
        choices=["vanilla", "worker", "shared_worker", "react", "next", "all"],
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

    scenarios = (
        ["vanilla", "worker", "shared_worker", "react", "next"]
        if args.scenario == "all"
        else [args.scenario]
    )

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
