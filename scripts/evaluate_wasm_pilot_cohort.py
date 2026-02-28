#!/usr/bin/env python3
"""Evaluate Browser Edition pilot cohort candidates deterministically."""

from __future__ import annotations

import argparse
import json
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


def now_iso() -> str:
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


class EvaluatorTests(unittest.TestCase):
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
    parser.add_argument("--self-test", action="store_true", help="Run internal unit checks and exit.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_test:
        return run_self_test()

    if not args.input:
        print("--input is required unless --self-test is used", file=sys.stderr)
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
