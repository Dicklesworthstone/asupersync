#!/usr/bin/env python3
"""Evaluate Browser Edition pilot cohort candidates deterministically."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
import unittest


ALLOWED_PROFILES = {
    "FP-BR-MIN",
    "FP-BR-DEV",
    "FP-BR-PROD",
    "FP-BR-DET",
}

SUPPORTED_FRAMEWORKS = {"vanilla", "react", "next"}
SUPPORTED_PROFILE_FAMILIES = {"native", "wasm"}
DEFERRED_SURFACE_PREFIXES = (
    "native_socket",
    "io_uring",
    "native_tls",
    "fs",
    "process",
    "signal",
    "server",
    "native_db",
    "kafka",
    "quic_native",
    "http3_native",
)

TELEMETRY_SCHEMA_VERSION = "asupersync-pilot-observability-v1"
TELEMETRY_ALERT_EVENT = "pilot_slo_alert"
TELEMETRY_GATE_EVENT = "pilot_slo_gate_summary"
DEFAULT_PARITY_TOLERANCE_PCT = 5.0

REQUIRED_TELEMETRY_FIELDS = {
    "scenario_id",
    "framework",
    "profile_family",
    "signal_name",
    "signal_source",
    "signal_value",
    "threshold_kind",
    "threshold_value",
    "capability_surface",
    "owner_route",
    "replay_command",
    "trace_pointer",
    "remediation_pointer",
}


def now_iso() -> str:
    forced_ts = os.environ.get("ASUPERSYNC_EVAL_TS")
    if forced_ts:
        return forced_ts
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class Evaluation:
    candidate_id: str
    eligible: bool
    score: int
    risk_tier: str
    exclusion_reasons: list[str]
    warning_flags: list[str]
    selected_frameworks: list[str]
    profile: str

    def as_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "eligible": self.eligible,
            "score": self.score,
            "risk_tier": self.risk_tier,
            "exclusion_reasons": self.exclusion_reasons,
            "warning_flags": self.warning_flags,
            "selected_frameworks": self.selected_frameworks,
            "profile": self.profile,
        }


def validate_telemetry_events(events: list[dict]) -> list[str]:
    errors: list[str] = []
    for idx, event in enumerate(events):
        if not isinstance(event, dict):
            errors.append(f"event[{idx}] must be an object")
            continue

        missing = sorted(key for key in REQUIRED_TELEMETRY_FIELDS if key not in event)
        if missing:
            errors.append(f"event[{idx}] missing fields: {','.join(missing)}")
            continue

        framework = str(event["framework"]).strip().lower()
        if framework not in SUPPORTED_FRAMEWORKS:
            errors.append(f"event[{idx}] has unsupported framework: {framework}")

        profile_family = str(event["profile_family"]).strip().lower()
        if profile_family not in SUPPORTED_PROFILE_FAMILIES:
            errors.append(f"event[{idx}] has unsupported profile_family: {profile_family}")

        threshold_kind = str(event["threshold_kind"]).strip().lower()
        if threshold_kind not in {"max", "min"}:
            errors.append(f"event[{idx}] threshold_kind must be max|min (got {threshold_kind})")

        for numeric_field in ("signal_value", "threshold_value"):
            value = event.get(numeric_field)
            if not isinstance(value, (int, float)):
                errors.append(f"event[{idx}] {numeric_field} must be numeric")
    return errors


def threshold_breach(signal_value: float, threshold_kind: str, threshold_value: float) -> bool:
    if threshold_kind == "max":
        return signal_value > threshold_value
    return signal_value < threshold_value


def evaluate_telemetry(payload: dict | list[dict]) -> dict:
    if isinstance(payload, dict):
        events = payload.get("events")
        parity_tolerance_default = float(
            payload.get("parity_tolerance_pct_default", DEFAULT_PARITY_TOLERANCE_PCT)
        )
        seed = payload.get("seed")
    else:
        events = payload
        parity_tolerance_default = DEFAULT_PARITY_TOLERANCE_PCT
        seed = None

    if not isinstance(events, list):
        raise ValueError("telemetry input must contain an events array")

    validation_errors = validate_telemetry_events(events)
    if validation_errors:
        raise ValueError("; ".join(validation_errors))

    grouped: dict[tuple[str, str, str], dict] = {}
    latest_per_framework_signal: dict[tuple[str, str, str], dict] = {}
    alerts: list[dict] = []
    threshold_evaluations: list[dict] = []

    for raw in events:
        event = dict(raw)
        event["framework"] = str(event["framework"]).strip().lower()
        event["profile_family"] = str(event["profile_family"]).strip().lower()
        event["threshold_kind"] = str(event["threshold_kind"]).strip().lower()
        event["signal_name"] = str(event["signal_name"]).strip()
        event["signal_source"] = str(event["signal_source"]).strip()
        event["capability_surface"] = str(event["capability_surface"]).strip()
        event["owner_route"] = str(event["owner_route"]).strip()
        event["replay_command"] = str(event["replay_command"]).strip()
        event["trace_pointer"] = str(event["trace_pointer"]).strip()
        event["remediation_pointer"] = str(event["remediation_pointer"]).strip()

        key = (event["profile_family"], event["framework"], event["signal_name"])
        stats = grouped.setdefault(
            key,
            {
                "profile_family": event["profile_family"],
                "framework": event["framework"],
                "signal_name": event["signal_name"],
                "signal_source": event["signal_source"],
                "samples": 0,
                "sum": 0.0,
                "min": float("inf"),
                "max": float("-inf"),
                "latest_value": None,
                "latest_threshold_kind": event["threshold_kind"],
                "latest_threshold_value": float(event["threshold_value"]),
                "latest_owner_route": event["owner_route"],
                "latest_capability_surface": event["capability_surface"],
            },
        )

        value = float(event["signal_value"])
        stats["samples"] += 1
        stats["sum"] += value
        stats["min"] = min(stats["min"], value)
        stats["max"] = max(stats["max"], value)
        stats["latest_value"] = value
        stats["latest_threshold_kind"] = event["threshold_kind"]
        stats["latest_threshold_value"] = float(event["threshold_value"])
        stats["latest_owner_route"] = event["owner_route"]
        stats["latest_capability_surface"] = event["capability_surface"]

        latest_key = (event["framework"], event["signal_name"], event["profile_family"])
        latest_per_framework_signal[latest_key] = {
            "value": value,
            "threshold_kind": event["threshold_kind"],
            "threshold_value": float(event["threshold_value"]),
            "owner_route": event["owner_route"],
            "capability_surface": event["capability_surface"],
            "replay_command": event["replay_command"],
            "trace_pointer": event["trace_pointer"],
            "remediation_pointer": event["remediation_pointer"],
            "scenario_id": str(event["scenario_id"]),
            "signal_source": event["signal_source"],
            "parity_tolerance_pct": float(
                event.get("parity_tolerance_pct", parity_tolerance_default)
            ),
        }

        breached = threshold_breach(
            value, event["threshold_kind"], float(event["threshold_value"])
        )
        threshold_eval = {
            "profile_family": event["profile_family"],
            "framework": event["framework"],
            "signal_name": event["signal_name"],
            "signal_source": event["signal_source"],
            "signal_value": value,
            "threshold_kind": event["threshold_kind"],
            "threshold_value": float(event["threshold_value"]),
            "breach": breached,
            "capability_surface": event["capability_surface"],
            "owner_route": event["owner_route"],
            "replay_command": event["replay_command"],
            "trace_pointer": event["trace_pointer"],
            "remediation_pointer": event["remediation_pointer"],
            "scenario_id": str(event["scenario_id"]),
        }
        threshold_evaluations.append(threshold_eval)

        if breached:
            severity = "high"
            if event["threshold_kind"] == "max":
                over = value - float(event["threshold_value"])
                if float(event["threshold_value"]) > 0 and (over / float(event["threshold_value"])) >= 0.5:
                    severity = "critical"
            else:
                under = float(event["threshold_value"]) - value
                if float(event["threshold_value"]) > 0 and (under / float(event["threshold_value"])) >= 0.5:
                    severity = "critical"

            alerts.append(
                {
                    "alert_id": (
                        f"{event['scenario_id']}:{event['profile_family']}:"
                        f"{event['framework']}:{event['signal_name']}"
                    ),
                    "severity": severity,
                    "profile_family": event["profile_family"],
                    "framework": event["framework"],
                    "signal_name": event["signal_name"],
                    "signal_source": event["signal_source"],
                    "signal_value": value,
                    "threshold_kind": event["threshold_kind"],
                    "threshold_value": float(event["threshold_value"]),
                    "capability_surface": event["capability_surface"],
                    "owner_route": event["owner_route"],
                    "replay_command": event["replay_command"],
                    "trace_pointer": event["trace_pointer"],
                    "remediation_pointer": event["remediation_pointer"],
                    "scenario_id": str(event["scenario_id"]),
                }
            )

    aggregation_rows = []
    for key in sorted(grouped):
        stats = grouped[key]
        samples = int(stats["samples"])
        aggregation_rows.append(
            {
                "profile_family": stats["profile_family"],
                "framework": stats["framework"],
                "signal_name": stats["signal_name"],
                "signal_source": stats["signal_source"],
                "samples": samples,
                "avg": (stats["sum"] / samples) if samples > 0 else 0.0,
                "min": stats["min"] if samples > 0 else 0.0,
                "max": stats["max"] if samples > 0 else 0.0,
                "latest_value": stats["latest_value"],
                "latest_threshold_kind": stats["latest_threshold_kind"],
                "latest_threshold_value": stats["latest_threshold_value"],
                "owner_route": stats["latest_owner_route"],
                "capability_surface": stats["latest_capability_surface"],
            }
        )

    parity_checks: list[dict] = []
    for framework in sorted(SUPPORTED_FRAMEWORKS):
        signal_names = sorted(
            {
                k[1]
                for k in latest_per_framework_signal
                if k[0] == framework
            }
        )
        for signal_name in signal_names:
            wasm = latest_per_framework_signal.get((framework, signal_name, "wasm"))
            native = latest_per_framework_signal.get((framework, signal_name, "native"))
            if not wasm or not native:
                continue

            denom = max(abs(float(native["value"])), 1e-9)
            delta_pct = abs(float(wasm["value"]) - float(native["value"])) / denom * 100.0
            tolerance = max(
                float(wasm.get("parity_tolerance_pct", parity_tolerance_default)),
                float(native.get("parity_tolerance_pct", parity_tolerance_default)),
            )
            breach = delta_pct > tolerance
            parity_checks.append(
                {
                    "framework": framework,
                    "signal_name": signal_name,
                    "wasm_value": float(wasm["value"]),
                    "native_value": float(native["value"]),
                    "delta_pct": delta_pct,
                    "tolerance_pct": tolerance,
                    "breach": breach,
                    "owner_route": wasm["owner_route"],
                    "capability_surface": wasm["capability_surface"],
                    "replay_command": wasm["replay_command"],
                    "trace_pointer": wasm["trace_pointer"],
                }
            )

    parity_breaches = [row for row in parity_checks if row["breach"]]
    ci_parity_ok = len(parity_breaches) == 0
    status = "pass" if len(alerts) == 0 and ci_parity_ok else "fail"

    replay_links = sorted(
        {
            (row["replay_command"], row["trace_pointer"])
            for row in alerts
        }
    )
    owner_routes = sorted({row["owner_route"] for row in alerts})

    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "generated_at": now_iso(),
        "seed": seed,
        "status": status,
        "event_count": len(events),
        "alerts_count": len(alerts),
        "ci_parity_ok": ci_parity_ok,
        "threshold_evaluations": sorted(
            threshold_evaluations,
            key=lambda row: (
                row["profile_family"],
                row["framework"],
                row["signal_name"],
                row["scenario_id"],
            ),
        ),
        "aggregations": aggregation_rows,
        "parity_checks": sorted(
            parity_checks,
            key=lambda row: (row["framework"], row["signal_name"]),
        ),
        "alerts": sorted(
            alerts,
            key=lambda row: (
                row["severity"],
                row["framework"],
                row["signal_name"],
                row["scenario_id"],
            ),
        ),
        "incident_drill_links": [
            {"replay_command": command, "trace_pointer": trace}
            for command, trace in replay_links
        ],
        "owner_routes": owner_routes,
    }


def normalize_frameworks(values: list[str]) -> list[str]:
    return sorted({v.strip().lower() for v in values if v.strip()})


def has_deferred_surface(values: list[str]) -> bool:
    lowered = [v.strip().lower() for v in values]
    for item in lowered:
        for prefix in DEFERRED_SURFACE_PREFIXES:
            if item.startswith(prefix):
                return True
    return False


def compute_score(candidate: dict) -> int:
    score = 0
    frameworks = normalize_frameworks(candidate.get("frameworks", []))
    profile = candidate.get("profile", "")
    has_replay_pipeline = bool(candidate.get("has_replay_pipeline", False))
    has_ci = bool(candidate.get("has_ci", False))
    security_owner = bool(candidate.get("security_owner", False))
    support_contact = bool(candidate.get("support_contact", False))
    pilot_window_days = int(candidate.get("pilot_window_days", 0))

    if profile in {"FP-BR-DEV", "FP-BR-DET"}:
        score += 30
    elif profile in {"FP-BR-PROD", "FP-BR-MIN"}:
        score += 20

    if "vanilla" in frameworks:
        score += 10
    if "react" in frameworks:
        score += 10
    if "next" in frameworks:
        score += 10

    if has_replay_pipeline:
        score += 15
    if has_ci:
        score += 10
    if security_owner:
        score += 10
    if support_contact:
        score += 5

    if 7 <= pilot_window_days <= 30:
        score += 10
    elif pilot_window_days > 30:
        score += 5

    return score


def risk_tier_for(candidate: dict, score: int) -> str:
    deferred = has_deferred_surface(candidate.get("requested_capabilities", []))
    replay = bool(candidate.get("has_replay_pipeline", False))
    profile = candidate.get("profile", "")

    if deferred:
        return "high"
    if not replay or profile == "FP-BR-PROD":
        return "medium"
    if score >= 70:
        return "low"
    return "medium"


def evaluate_candidate(candidate: dict) -> Evaluation:
    candidate_id = str(candidate.get("candidate_id", "unknown"))
    profile = str(candidate.get("profile", ""))
    frameworks = normalize_frameworks(candidate.get("frameworks", []))
    requested_caps = candidate.get("requested_capabilities", [])

    exclusion_reasons: list[str] = []
    warning_flags: list[str] = []

    if profile not in ALLOWED_PROFILES:
        exclusion_reasons.append("profile_not_allowed")

    unsupported_frameworks = [f for f in frameworks if f not in SUPPORTED_FRAMEWORKS]
    if unsupported_frameworks:
        exclusion_reasons.append(f"unsupported_frameworks:{','.join(sorted(unsupported_frameworks))}")

    if not frameworks:
        exclusion_reasons.append("no_framework_selected")

    if has_deferred_surface(requested_caps):
        exclusion_reasons.append("requested_deferred_surface")

    if not candidate.get("support_contact"):
        warning_flags.append("missing_support_contact")
    if not candidate.get("has_ci"):
        warning_flags.append("missing_ci")
    if not candidate.get("has_replay_pipeline"):
        warning_flags.append("missing_replay_pipeline")

    score = compute_score(candidate)
    risk_tier = risk_tier_for(candidate, score)
    eligible = len(exclusion_reasons) == 0

    return Evaluation(
        candidate_id=candidate_id,
        eligible=eligible,
        score=score,
        risk_tier=risk_tier,
        exclusion_reasons=sorted(exclusion_reasons),
        warning_flags=sorted(warning_flags),
        selected_frameworks=frameworks,
        profile=profile,
    )


def evaluate(candidates: list[dict]) -> dict:
    rows = [evaluate_candidate(c) for c in candidates]
    accepted = [r for r in rows if r.eligible]

    return {
        "schema": "asupersync-pilot-cohort-eval-v1",
        "generated_at": now_iso(),
        "candidate_count": len(rows),
        "eligible_count": len(accepted),
        "results": [r.as_dict() for r in rows],
    }


def write_intake_log(path: Path, evaluations: dict, source_file: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in evaluations["results"]:
            event = {
                "ts": evaluations["generated_at"],
                "event": "pilot_intake_evaluation",
                "source_file": source_file,
                "candidate_id": row["candidate_id"],
                "eligible": row["eligible"],
                "score": row["score"],
                "risk_tier": row["risk_tier"],
                "profile": row["profile"],
                "frameworks": row["selected_frameworks"],
                "warning_flags": row["warning_flags"],
                "exclusion_reasons": row["exclusion_reasons"],
            }
            f.write(json.dumps(event, sort_keys=True))
            f.write("\n")


def write_telemetry_log(path: Path, summary: dict, source_file: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for alert in summary.get("alerts", []):
            event = {
                "ts": summary["generated_at"],
                "event": TELEMETRY_ALERT_EVENT,
                "source_file": source_file,
                "schema_version": summary["schema_version"],
                "status": summary["status"],
                **alert,
            }
            f.write(json.dumps(event, sort_keys=True))
            f.write("\n")

        gate = {
            "ts": summary["generated_at"],
            "event": TELEMETRY_GATE_EVENT,
            "source_file": source_file,
            "schema_version": summary["schema_version"],
            "status": summary["status"],
            "event_count": summary["event_count"],
            "alerts_count": summary["alerts_count"],
            "ci_parity_ok": summary["ci_parity_ok"],
            "owner_routes": summary.get("owner_routes", []),
        }
        f.write(json.dumps(gate, sort_keys=True))
        f.write("\n")


class EvaluatorTests(unittest.TestCase):
    def sample_telemetry_event(self, **overrides: object) -> dict:
        base = {
            "scenario_id": "pilot-drill-1",
            "framework": "react",
            "profile_family": "wasm",
            "signal_name": "incident_mtta_minutes",
            "signal_source": "pilot_drill",
            "signal_value": 8.0,
            "threshold_kind": "max",
            "threshold_value": 15.0,
            "capability_surface": "wasm.replay",
            "owner_route": "oncall:wasm-runtime",
            "replay_command": "asupersync lab replay examples/scenarios/smoke_happy_path.yaml --seed 4242",
            "trace_pointer": "artifacts/replay/pilot-drill-1.json",
            "remediation_pointer": "docs/wasm_pilot_observability_contract.md#incident-response",
            "parity_tolerance_pct": 5.0,
        }
        base.update(overrides)
        return base

    def test_accepts_low_risk_candidate(self) -> None:
        candidate = {
            "candidate_id": "acme-frontend",
            "profile": "FP-BR-DET",
            "frameworks": ["react"],
            "requested_capabilities": ["fetch"],
            "has_replay_pipeline": True,
            "has_ci": True,
            "security_owner": True,
            "support_contact": True,
            "pilot_window_days": 14,
        }
        result = evaluate_candidate(candidate)
        self.assertTrue(result.eligible)
        self.assertEqual(result.risk_tier, "low")
        self.assertGreaterEqual(result.score, 70)

    def test_rejects_deferred_surface_request(self) -> None:
        candidate = {
            "candidate_id": "legacy-io",
            "profile": "FP-BR-DEV",
            "frameworks": ["next"],
            "requested_capabilities": ["native_socket_listener"],
            "has_replay_pipeline": True,
            "has_ci": True,
            "security_owner": False,
            "support_contact": True,
            "pilot_window_days": 10,
        }
        result = evaluate_candidate(candidate)
        self.assertFalse(result.eligible)
        self.assertIn("requested_deferred_surface", result.exclusion_reasons)

    def test_rejects_unknown_profile(self) -> None:
        candidate = {
            "candidate_id": "invalid-profile",
            "profile": "FP-UNKNOWN",
            "frameworks": ["vanilla"],
            "requested_capabilities": ["fetch"],
            "has_replay_pipeline": True,
            "has_ci": True,
            "security_owner": True,
            "support_contact": True,
            "pilot_window_days": 10,
        }
        result = evaluate_candidate(candidate)
        self.assertFalse(result.eligible)
        self.assertIn("profile_not_allowed", result.exclusion_reasons)

    def test_normalization_of_frameworks(self) -> None:
        normalized = normalize_frameworks(["React", "react", "NEXT", ""])
        self.assertEqual(normalized, ["next", "react"])

    def test_telemetry_summary_passes_when_thresholds_and_parity_hold(self) -> None:
        payload = {
            "seed": 4242,
            "events": [
                self.sample_telemetry_event(
                    framework="react",
                    profile_family="wasm",
                    signal_name="incident_mtta_minutes",
                    signal_value=8.0,
                    threshold_kind="max",
                    threshold_value=15.0,
                ),
                self.sample_telemetry_event(
                    framework="react",
                    profile_family="native",
                    signal_name="incident_mtta_minutes",
                    signal_value=8.2,
                    threshold_kind="max",
                    threshold_value=15.0,
                ),
            ],
        }

        summary = evaluate_telemetry(payload)
        self.assertEqual(summary["schema_version"], TELEMETRY_SCHEMA_VERSION)
        self.assertEqual(summary["status"], "pass")
        self.assertEqual(summary["alerts_count"], 0)
        self.assertTrue(summary["ci_parity_ok"])

    def test_telemetry_alerts_include_owner_route_and_trace_pointer(self) -> None:
        payload = {
            "events": [
                self.sample_telemetry_event(
                    signal_name="error_budget_burn_pct",
                    signal_value=12.0,
                    threshold_kind="max",
                    threshold_value=5.0,
                    owner_route="oncall:pilot-sre",
                ),
                self.sample_telemetry_event(
                    profile_family="native",
                    signal_name="error_budget_burn_pct",
                    signal_value=4.0,
                    threshold_kind="max",
                    threshold_value=5.0,
                    owner_route="oncall:pilot-sre",
                ),
            ]
        }
        summary = evaluate_telemetry(payload)
        self.assertEqual(summary["status"], "fail")
        self.assertGreaterEqual(summary["alerts_count"], 1)
        alert = summary["alerts"][0]
        for required in [
            "owner_route",
            "replay_command",
            "trace_pointer",
            "remediation_pointer",
            "signal_source",
            "capability_surface",
        ]:
            self.assertIn(required, alert)
            self.assertTrue(alert[required])

    def test_telemetry_parity_check_flags_drift(self) -> None:
        payload = {
            "events": [
                self.sample_telemetry_event(
                    framework="next",
                    profile_family="wasm",
                    signal_name="replay_success_rate_pct",
                    signal_value=90.0,
                    threshold_kind="min",
                    threshold_value=89.0,
                    parity_tolerance_pct=3.0,
                ),
                self.sample_telemetry_event(
                    framework="next",
                    profile_family="native",
                    signal_name="replay_success_rate_pct",
                    signal_value=100.0,
                    threshold_kind="min",
                    threshold_value=89.0,
                    parity_tolerance_pct=3.0,
                ),
            ]
        }
        summary = evaluate_telemetry(payload)
        self.assertEqual(summary["status"], "fail")
        self.assertFalse(summary["ci_parity_ok"])
        self.assertTrue(any(row["breach"] for row in summary["parity_checks"]))

    def test_telemetry_validation_requires_replay_and_owner_fields(self) -> None:
        invalid_event = self.sample_telemetry_event()
        invalid_event.pop("owner_route")
        with self.assertRaisesRegex(ValueError, "missing fields"):
            evaluate_telemetry({"events": [invalid_event]})


def run_self_test() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvaluatorTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate Browser Edition pilot cohort candidates.")
    parser.add_argument("--input", help="JSON file containing an array of candidate objects.")
    parser.add_argument(
        "--output",
        default="artifacts/pilot/pilot_cohort_eval.json",
        help="Output JSON path for evaluation results.",
    )
    parser.add_argument(
        "--log-output",
        default="artifacts/pilot/pilot_intake.ndjson",
        help="Structured NDJSON intake log output path.",
    )
    parser.add_argument(
        "--telemetry-input",
        help="JSON file containing pilot telemetry events (object with events[] or events array).",
    )
    parser.add_argument(
        "--telemetry-output",
        default="artifacts/pilot/pilot_observability_summary.json",
        help="Output JSON path for telemetry/SLO summary.",
    )
    parser.add_argument(
        "--telemetry-log-output",
        default="artifacts/pilot/pilot_observability_alerts.ndjson",
        help="Structured NDJSON alert + gate output path for telemetry mode.",
    )
    parser.add_argument("--self-test", action="store_true", help="Run internal unit checks and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_test:
        return run_self_test()

    if args.telemetry_input:
        input_path = Path(args.telemetry_input)
        data = json.loads(input_path.read_text(encoding="utf-8"))
        summary = evaluate_telemetry(data)

        output_path = Path(args.telemetry_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        write_telemetry_log(Path(args.telemetry_log_output), summary, source_file=str(input_path))
        print(
            f"status={summary['status']} events={summary['event_count']} "
            f"alerts={summary['alerts_count']} output={output_path}"
        )
        return 0 if summary["status"] == "pass" else 1

    if not args.input:
        print(
            "either --input (cohort mode) or --telemetry-input (telemetry mode) is required "
            "unless --self-test is used",
            file=sys.stderr,
        )
        return 2

    input_path = Path(args.input)
    data = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        print("input JSON must be an array of candidate objects", file=sys.stderr)
        return 2

    evaluations = evaluate(data)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(evaluations, indent=2, sort_keys=True), encoding="utf-8")

    write_intake_log(Path(args.log_output), evaluations, source_file=str(input_path))
    print(
        f"evaluated={evaluations['candidate_count']} eligible={evaluations['eligible_count']} "
        f"output={output_path}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
