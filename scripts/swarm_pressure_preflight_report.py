#!/usr/bin/env python3
"""Build a deterministic, non-mutating swarm pressure preflight report.

The report composes existing proof-lane, pressure, proof-freshness, admission,
and dirty-tree ownership artifacts. It does not run proof lanes, mutate Beads,
send Agent Mail, edit git state, or treat cached/status artifacts as fresh
behavioral proof.
"""

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "swarm-pressure-preflight-report-v1"
INPUT_SCHEMA_VERSION = "swarm-pressure-preflight-input-v1"

DEFAULT_SOURCES = {
    "proof_lane_manifest": "artifacts/proof_lane_manifest_v1.json",
    "proof_status_snapshot": "artifacts/proof_status_snapshot_v1.json",
    "runtime_pressure_contract": "artifacts/runtime_pressure_control_evidence_contract_v1.json",
}

BLOCKING_PROOF_EVIDENCE_STATUSES = {
    "blocked",
    "no-win",
    "stale-evidence",
    "unsupported",
}
WARNING_PROOF_EVIDENCE_STATUSES = {
    "rerun-required",
}
EXACT_FILTER_ZERO_CLASSIFICATIONS = {
    "exact-filter-zero-tests",
    "exact-filter-no-executed-tests",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def string_value(value: Any) -> str:
    return value if isinstance(value, str) else ""


def bool_value(value: Any) -> bool:
    return value if isinstance(value, bool) else False


def first_bool_value(*values: Any) -> bool:
    for value in values:
        if isinstance(value, bool):
            return value
    return False


def int_value(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    return 0


def stable_strings(value: Any) -> list[str]:
    return sorted({item for item in as_list(value) if isinstance(item, str) and item})


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def canonical_digest(data: Any) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def artifact_version(data: Any) -> str:
    payload = as_dict(data)
    for key in ("contract_version", "schema_version", "input_schema_version"):
        value = string_value(payload.get(key))
        if value:
            return value
    return ""


def source_spec(config: dict[str, Any], kind: str) -> Any:
    sources = as_dict(config.get("sources"))
    if kind in sources:
        return sources[kind]
    default = DEFAULT_SOURCES.get(kind)
    if default:
        return {"path": default}
    return None


def load_source(repo_path: Path, kind: str, spec: Any) -> dict[str, Any]:
    errors: list[str] = []
    artifact_path = ""
    data: Any = {}
    data_provided = False

    if spec is None:
        errors.append("source-not-configured")
    elif isinstance(spec, str):
        artifact_path = spec
    elif isinstance(spec, dict):
        artifact_path = string_value(spec.get("artifact_path") or spec.get("path"))
        if "data" in spec:
            data = spec["data"]
            data_provided = True
    else:
        errors.append("source-spec-must-be-string-or-object")

    if not data_provided and artifact_path and not errors:
        path = Path(artifact_path)
        if not path.is_absolute():
            path = repo_path / path
        try:
            data = load_json(path)
        except (OSError, json.JSONDecodeError) as error:
            errors.append(str(error))

    payload = as_dict(data)
    return {
        "kind": kind,
        "artifact_path": artifact_path,
        "load_status": "ok" if not errors else "error",
        "errors": errors,
        "version": artifact_version(payload),
        "digest": canonical_digest(payload) if payload else "",
        "data": payload,
    }


def load_source_list(repo_path: Path, kind: str, specs: Any) -> list[dict[str, Any]]:
    return [
        load_source(repo_path, kind, spec)
        for spec in as_list(specs)
    ]


def source_summary(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": source["kind"],
        "artifact_path": source["artifact_path"],
        "load_status": source["load_status"],
        "version": source["version"],
        "digest": source["digest"],
        "errors": source["errors"],
    }


def issue(
    *,
    kind: str,
    severity: str,
    source: dict[str, Any],
    reason: str,
    lane_id: str = "",
    claim_id: str = "",
    path: str = "",
    action: str = "",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "source_kind": source["kind"],
        "artifact_path": source["artifact_path"],
        "lane_id": lane_id,
        "claim_id": claim_id,
        "path": path,
        "reason": reason,
        "recommended_action": action,
        "current_source_diagnosis": True,
        "behavioral_correctness_proof": False,
    }


def summarize_manifest(source: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    data = source["data"]
    warnings: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    policy = as_dict(data.get("resource_envelope_policy"))
    classes = {
        string_value(row.get("class_id")): as_dict(row)
        for row in as_list(policy.get("classes"))
        if isinstance(row, dict) and string_value(row.get("class_id"))
    }
    command_prefix = string_value(as_dict(data.get("command_policy")).get("all_commands_must_start_with"))
    lanes = [as_dict(row) for row in as_list(data.get("lanes")) if isinstance(row, dict)]
    lane_rows = []
    pressure_counts: dict[str, int] = {}

    for lane in lanes:
        lane_id = string_value(lane.get("lane_id"))
        lane_kind = string_value(lane.get("kind"))
        class_id = string_value(lane.get("resource_envelope_class"))
        command = string_value(lane.get("command"))
        envelope = classes.get(class_id)
        state = "ok"
        reasons: list[str] = []
        if envelope is None:
            state = "missing-envelope"
            reasons.append("resource envelope class is missing")
            blockers.append(
                issue(
                    kind="missing-resource-envelope",
                    severity="blocker",
                    source=source,
                    lane_id=lane_id,
                    reason=f"lane references unknown resource_envelope_class {class_id!r}",
                    action="add or correct the proof-lane resource envelope before dispatch",
                )
            )
        else:
            allowed_kinds = set(stable_strings(envelope.get("lane_kinds")))
            pressure = string_value(envelope.get("resource_pressure")) or "unknown"
            pressure_counts[pressure] = pressure_counts.get(pressure, 0) + 1
            if lane_kind not in allowed_kinds:
                state = "kind-envelope-mismatch"
                reasons.append("lane kind is not admitted by resource envelope")
                blockers.append(
                    issue(
                        kind="resource-envelope-kind-mismatch",
                        severity="blocker",
                        source=source,
                        lane_id=lane_id,
                        reason=f"{class_id} does not admit lane kind {lane_kind}",
                        action="align lane kind with envelope lane_kinds",
                    )
                )
            if not bool_value(envelope.get("remote_required")) or bool_value(envelope.get("local_fallback_allowed")):
                state = "unsafe-remote-policy"
                reasons.append("remote-required/no-local-fallback policy is not fail-closed")
                blockers.append(
                    issue(
                        kind="unsafe-resource-envelope-policy",
                        severity="blocker",
                        source=source,
                        lane_id=lane_id,
                        reason="resource envelope must require remote execution and forbid local fallback",
                        action="fix remote_required/local_fallback_allowed on the envelope",
                    )
                )
            if int_value(envelope.get("timeout_seconds")) <= 0 or int_value(envelope.get("memory_mb")) <= 0:
                state = "missing-bounds"
                reasons.append("timeout or memory bound is missing")
                blockers.append(
                    issue(
                        kind="missing-resource-bounds",
                        severity="blocker",
                        source=source,
                        lane_id=lane_id,
                        reason="resource envelope must carry nonzero timeout_seconds and memory_mb",
                        action="add finite time and memory bounds",
                    )
                )

        if command_prefix and command and not command.startswith(command_prefix):
            state = "bad-command-prefix"
            reasons.append("command does not use remote-required RCH prefix")
            blockers.append(
                issue(
                    kind="unsafe-proof-command-prefix",
                    severity="blocker",
                    source=source,
                    lane_id=lane_id,
                    reason="proof command does not start with the manifest remote-required prefix",
                    action="rewrite command with RCH_REQUIRE_REMOTE=1 rch exec --",
                )
            )

        lane_rows.append(
            {
                "lane_id": lane_id,
                "kind": lane_kind,
                "resource_envelope_class": class_id,
                "state": state,
                "reasons": reasons,
                "guarantee_ids": stable_strings(lane.get("guarantee_ids")),
                "source_paths": stable_strings(lane.get("source_paths")),
            }
        )

    if source["load_status"] != "ok":
        blockers.append(
            issue(
                kind="source-load-error",
                severity="blocker",
                source=source,
                reason="proof lane manifest could not be loaded",
                action="restore the manifest before running preflight",
            )
        )

    summary = {
        "contract_version": string_value(data.get("contract_version")),
        "lane_count": len(lanes),
        "resource_envelope_class_count": len(classes),
        "lane_states": count_by(lane_rows, "state"),
        "resource_pressure_counts": dict(sorted(pressure_counts.items())),
        "required_guarantee_ids": stable_strings(data.get("required_guarantee_ids")),
        "command_prefix": command_prefix,
        "lanes": lane_rows,
    }
    return summary, blockers, warnings


def summarize_status(source: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    data = source["data"]
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    rows = [as_dict(row) for row in as_list(data.get("claim_categories")) if isinstance(row, dict)]
    row_summaries = []
    for row in rows:
        claim_id = string_value(row.get("claim_id"))
        status = string_value(row.get("status"))
        proof_status = string_value(row.get("proof_evidence_status"))
        lane_ids = stable_strings(row.get("manifest_lane_ids"))
        row_summaries.append(
            {
                "claim_id": claim_id,
                "status": status,
                "proof_evidence_status": proof_status,
                "manifest_lane_ids": lane_ids,
            }
        )
        if status == "red_blocked_external" or proof_status in BLOCKING_PROOF_EVIDENCE_STATUSES:
            blockers.append(
                issue(
                    kind="blocked-proof-status",
                    severity="blocker",
                    source=source,
                    claim_id=claim_id,
                    reason=f"claim status={status}, proof_evidence_status={proof_status}",
                    action="resolve the validation-frontier blocker or rerun the canonical lane",
                )
            )
        elif proof_status in WARNING_PROOF_EVIDENCE_STATUSES:
            warnings.append(
                issue(
                    kind="proof-rerun-required",
                    severity="warning",
                    source=source,
                    claim_id=claim_id,
                    reason="claim has a canonical lane but no fresh proof in this snapshot",
                    action="run the listed RCH command before citing fresh proof",
                )
            )

    if source["load_status"] != "ok":
        blockers.append(
            issue(
                kind="source-load-error",
                severity="blocker",
                source=source,
                reason="proof status snapshot could not be loaded",
                action="restore the snapshot before running preflight",
            )
        )

    return {
        "contract_version": string_value(data.get("contract_version")),
        "claim_count": len(rows),
        "by_status": count_by(row_summaries, "status"),
        "by_proof_evidence_status": count_by(row_summaries, "proof_evidence_status"),
        "claims": row_summaries,
    }, blockers, warnings


def summarize_runtime_pressure_contract(
    source: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    data = source["data"]
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    schemas = as_dict(data.get("schema_versions"))
    proof_lanes = [as_dict(row) for row in as_list(data.get("proof_lanes")) if isinstance(row, dict)]
    evidence_claims = [as_dict(row) for row in as_list(data.get("evidence_claims")) if isinstance(row, dict)]
    operator_policy = as_dict(data.get("operator_policy"))

    for key in [
        "runtime_pressure_snapshot",
        "runtime_pressure_admission_policy",
        "runtime_pressure_admission_decision",
        "runtime_pressure_rch_proof_lane",
    ]:
        if not string_value(schemas.get(key)):
            warnings.append(
                issue(
                    kind="missing-pressure-schema-version",
                    severity="warning",
                    source=source,
                    reason=f"runtime pressure contract does not expose schema_versions.{key}",
                    action="refresh the pressure evidence contract schema map",
                )
            )

    if source["load_status"] != "ok":
        blockers.append(
            issue(
                kind="source-load-error",
                severity="blocker",
                source=source,
                reason="runtime pressure contract could not be loaded",
                action="restore the pressure contract before running preflight",
            )
        )

    return {
        "contract_version": string_value(data.get("contract_version")),
        "schema_versions": dict(sorted((key, value) for key, value in schemas.items() if isinstance(value, str))),
        "proof_lane_ids": [
            string_value(row.get("lane_id") or row.get("proof_lane_id"))
            for row in proof_lanes
            if string_value(row.get("lane_id") or row.get("proof_lane_id"))
        ],
        "evidence_claim_count": len(evidence_claims),
        "operator_policy": {
            "production_signals_are_advisory_without_lab_or_replay_evidence": bool_value(
                operator_policy.get("production_signals_are_advisory_without_lab_or_replay_evidence")
            ),
            "adaptive_controls_remain_opt_in_until_stronger_evidence": bool_value(
                operator_policy.get("adaptive_controls_remain_opt_in_until_stronger_evidence")
            ),
            "deadlock_claims_require_explicit_trapped_cycle_proof": bool_value(
                operator_policy.get("deadlock_claims_require_explicit_trapped_cycle_proof")
            ),
        },
    }, blockers, warnings


def summarize_freshness_receipts(
    sources: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    rows = []
    for source in sources:
        data = source["data"]
        for row in [as_dict(item) for item in as_list(data.get("rows")) if isinstance(item, dict)]:
            classification = string_value(row.get("classification"))
            decision = string_value(row.get("decision"))
            evidence = as_dict(row.get("evidence"))
            lane_id = string_value(row.get("lane_id") or row.get("manifest_lane_id"))
            artifact_path = string_value(row.get("artifact_path"))
            executed = int_value(evidence.get("exact_filter_executed_tests"))
            is_zero_exact = (
                classification in EXACT_FILTER_ZERO_CLASSIFICATIONS
                or "zero-tests" in stable_strings(evidence.get("exact_filter_proof_reasons"))
                or ("exact_filter" in evidence and executed == 0)
            )
            rows.append(
                {
                    "artifact_path": artifact_path,
                    "classification": classification,
                    "decision": decision,
                    "safe_to_cite": bool_value(row.get("safe_to_cite")),
                    "lane_id": lane_id,
                    "exact_filter": string_value(evidence.get("exact_filter")),
                    "exact_filter_executed_tests": executed,
                }
            )
            if is_zero_exact:
                blockers.append(
                    issue(
                        kind="stale-exact-filter-zero-tests",
                        severity="blocker",
                        source=source,
                        lane_id=lane_id,
                        reason="exact-filter Cargo proof ran zero tests and cannot be cited",
                        action="verify the exact test name on current main and rerun through RCH",
                    )
                )
            elif not bool_value(row.get("safe_to_cite")) and decision in {"rerun-required", "blocked"}:
                warnings.append(
                    issue(
                        kind="proof-artifact-not-citeable",
                        severity="warning",
                        source=source,
                        lane_id=lane_id,
                        reason=f"artifact classification={classification}, decision={decision}",
                        action="rerun or replace the proof artifact before citing it",
                    )
                )
        if source["load_status"] != "ok":
            blockers.append(
                issue(
                    kind="source-load-error",
                    severity="blocker",
                    source=source,
                    reason="proof freshness receipt could not be loaded",
                    action="restore the receipt or remove it from the preflight input",
                )
            )
    return {
        "receipt_count": len(sources),
        "row_count": len(rows),
        "by_classification": count_by(rows, "classification"),
        "by_decision": count_by(rows, "decision"),
        "rows": rows,
    }, blockers, warnings


def summarize_admission_receipts(
    sources: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    rows = []
    pressure_classes: list[str] = []
    for source in sources:
        data = source["data"]
        decision = as_dict(data.get("decision"))
        integrated = as_dict(data.get("integrated_operator_receipt"))
        resource = as_dict(data.get("resource_pressure_summary") or integrated.get("resource_pressure_summary"))
        disk = as_dict(data.get("disk_summary") or integrated.get("disk_summary"))
        lane_id = string_value(data.get("lane_id") or decision.get("lane_id"))
        decision_name = string_value(decision.get("admission_decision") or integrated.get("admission_decision"))
        proof_may_run = first_bool_value(
            decision.get("proof_may_run_now"),
            integrated.get("proof_may_run_now"),
        )
        pressure_class = string_value(resource.get("class") or resource.get("pressure_class") or "unknown")
        if pressure_class:
            pressure_classes.append(pressure_class)
        disk_ok = disk.get("sufficient_for_lane")
        row = {
            "lane_id": lane_id,
            "admission_decision": decision_name,
            "proof_may_run_now": proof_may_run,
            "reason_codes": stable_strings(decision.get("reason_codes") or integrated.get("reason_codes")),
            "resource_pressure_class": pressure_class,
            "disk_sufficient_for_lane": disk_ok if isinstance(disk_ok, bool) else None,
        }
        rows.append(row)
        if not proof_may_run:
            blockers.append(
                issue(
                    kind="proof-admission-blocked",
                    severity="blocker",
                    source=source,
                    lane_id=lane_id,
                    reason=f"admission_decision={decision_name}",
                    action="satisfy admission preconditions before dispatching this proof lane",
                )
            )
        if pressure_class in {"high", "critical"}:
            warnings.append(
                issue(
                    kind="runtime-pressure-high",
                    severity="warning",
                    source=source,
                    lane_id=lane_id,
                    reason=f"resource pressure class is {pressure_class}",
                    action="queue, split, or wait for pressure to fall before broad proof lanes",
                )
            )
        if disk_ok is False:
            blockers.append(
                issue(
                    kind="disk-headroom-insufficient",
                    severity="blocker",
                    source=source,
                    lane_id=lane_id,
                    reason="admission receipt reports insufficient target-dir disk headroom",
                    action="wait for disk headroom or choose a different target directory",
                )
            )
        if source["load_status"] != "ok":
            blockers.append(
                issue(
                    kind="source-load-error",
                    severity="blocker",
                    source=source,
                    reason="proof admission receipt could not be loaded",
                    action="restore the receipt or remove it from the preflight input",
                )
            )

    pressure_summary = {
        "classes": sorted(set(pressure_classes)),
        "mixed_pressure": len(set(pressure_classes)) > 1,
        "by_class": dict(sorted((name, pressure_classes.count(name)) for name in set(pressure_classes))),
    }
    return {
        "receipt_count": len(sources),
        "by_decision": count_by(rows, "admission_decision"),
        "admissible_count": sum(1 for row in rows if row["proof_may_run_now"]),
        "blocked_count": sum(1 for row in rows if not row["proof_may_run_now"]),
        "rows": rows,
    }, blockers, warnings, pressure_summary


def summarize_dirty_tree(
    source: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    if source is None:
        return {
            "present": False,
            "decision": "not-provided",
            "blocker_count": 0,
            "rows": [],
        }, [], []

    data = source["data"]
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    release = as_dict(data.get("release_prep_report"))
    summary = as_dict(release.get("release_blocker_summary"))
    rows = [as_dict(row) for row in as_list(release.get("rows")) if isinstance(row, dict)]

    for row in rows:
        if bool_value(row.get("release_blocker")):
            blockers.append(
                issue(
                    kind="dirty-tree-release-blocker",
                    severity="blocker",
                    source=source,
                    path=string_value(row.get("path")),
                    reason=string_value(row.get("reason")) or "dirty path blocks release/preflight",
                    action=string_value(row.get("recommended_next_step")) or "coordinate dirty-tree owner",
                )
            )
    if source["load_status"] != "ok":
        blockers.append(
            issue(
                kind="source-load-error",
                severity="blocker",
                source=source,
                reason="dirty-tree ownership receipt could not be loaded",
                action="restore the receipt or omit dirty-tree gating from this preflight",
            )
        )

    return {
        "present": True,
        "decision": string_value(summary.get("decision")),
        "total_dirty_paths": int_value(summary.get("total_dirty_paths")),
        "blocker_count": int_value(summary.get("blocker_count")),
        "release_ready": bool_value(summary.get("release_ready")),
        "by_classification": as_dict(summary.get("by_classification")),
        "rows": [
            {
                "path": string_value(row.get("path")),
                "classification": string_value(row.get("classification")),
                "release_blocker": bool_value(row.get("release_blocker")),
                "owner": string_value(row.get("owner")),
                "reason": string_value(row.get("reason")),
                "recommended_next_step": string_value(row.get("recommended_next_step")),
            }
            for row in rows
        ],
    }, blockers, warnings


def count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = string_value(row.get(key)) or "<missing>"
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def sorted_issues(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        rows,
        key=lambda row: (
            row["severity"],
            row["kind"],
            row["source_kind"],
            row["artifact_path"],
            row["lane_id"],
            row["claim_id"],
            row["path"],
        ),
    )


def operator_decision(blockers: list[dict[str, Any]], warnings: list[dict[str, Any]]) -> str:
    if blockers:
        return "preflight-blocked"
    if warnings:
        return "preflight-attention"
    return "preflight-pass"


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    repo_path = args.repo_path.resolve()
    config: dict[str, Any] = {}
    if args.fixture:
        loaded = load_json(args.fixture)
        if not isinstance(loaded, dict):
            raise ValueError("fixture must be a JSON object")
        config = loaded

    generated_at = args.generated_at or string_value(config.get("generated_at")) or utc_now()
    manifest = load_source(repo_path, "proof_lane_manifest", source_spec(config, "proof_lane_manifest"))
    status = load_source(repo_path, "proof_status_snapshot", source_spec(config, "proof_status_snapshot"))
    pressure_contract = load_source(
        repo_path,
        "runtime_pressure_contract",
        source_spec(config, "runtime_pressure_contract"),
    )
    freshness_sources = load_source_list(
        repo_path,
        "proof_freshness_receipt",
        as_dict(config.get("sources")).get("proof_freshness_receipts", []),
    )
    admission_sources = load_source_list(
        repo_path,
        "proof_admission_receipt",
        as_dict(config.get("sources")).get("proof_admission_receipts", []),
    )
    dirty_source_spec = as_dict(config.get("sources")).get("dirty_tree_ownership_receipt")
    dirty_source = (
        load_source(repo_path, "dirty_tree_ownership_receipt", dirty_source_spec)
        if dirty_source_spec is not None
        else None
    )

    sections: dict[str, Any] = {}
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    sections["proof_lane_envelope_health"], section_blockers, section_warnings = summarize_manifest(manifest)
    blockers.extend(section_blockers)
    warnings.extend(section_warnings)

    sections["proof_status_snapshot"], section_blockers, section_warnings = summarize_status(status)
    blockers.extend(section_blockers)
    warnings.extend(section_warnings)

    sections["runtime_pressure_contract"], section_blockers, section_warnings = summarize_runtime_pressure_contract(
        pressure_contract
    )
    blockers.extend(section_blockers)
    warnings.extend(section_warnings)

    sections["proof_freshness"], section_blockers, section_warnings = summarize_freshness_receipts(
        freshness_sources
    )
    blockers.extend(section_blockers)
    warnings.extend(section_warnings)

    admission, section_blockers, section_warnings, pressure_summary = summarize_admission_receipts(
        admission_sources
    )
    sections["proof_admission"] = admission
    sections["pressure_summary"] = pressure_summary
    blockers.extend(section_blockers)
    warnings.extend(section_warnings)

    sections["dirty_tree"], section_blockers, section_warnings = summarize_dirty_tree(dirty_source)
    blockers.extend(section_blockers)
    warnings.extend(section_warnings)

    source_rows = [manifest, status, pressure_contract, *freshness_sources, *admission_sources]
    if dirty_source is not None:
        source_rows.append(dirty_source)

    blocker_rows = sorted_issues(blockers)
    warning_rows = sorted_issues(warnings)
    decision = operator_decision(blocker_rows, warning_rows)

    return {
        "schema_version": SCHEMA_VERSION,
        "input_schema_version": string_value(config.get("schema_version")) or INPUT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "profile_id": string_value(config.get("profile_id")) or "live-default",
        "dry_run_only": True,
        "non_mutating": True,
        "forbidden_actions": {
            "runs_cargo": False,
            "runs_rch": False,
            "runs_git_mutation": False,
            "runs_beads_mutation": False,
            "sends_agent_mail": False,
            "writes_cache": False,
            "deletes_files": False,
        },
        "source_artifacts": [source_summary(source) for source in source_rows],
        "sections": sections,
        "blockers": blocker_rows,
        "warnings": warning_rows,
        "operator_summary": {
            "decision": decision,
            "ready_for_release_gate": decision == "preflight-pass",
            "ready_to_dispatch_proof_lanes": decision in {"preflight-pass", "preflight-attention"},
            "blocker_count": len(blocker_rows),
            "warning_count": len(warning_rows),
            "source_count": len(source_rows),
            "top_blocker_kinds": count_by(blocker_rows, "kind"),
            "top_warning_kinds": count_by(warning_rows, "kind"),
        },
        "proof_boundary": {
            "current_source_diagnosis": True,
            "behavioral_correctness_proof": False,
            "fresh_rch_pass_proof": False,
            "source_diagnosis_note": (
                "This report proves only that current artifacts and receipts were parsed "
                "and aggregated consistently for preflight triage."
            ),
            "behavioral_correctness_note": (
                "Cargo, clippy, tests, formal proofs, and release gates still require their "
                "own canonical RCH lanes before any behavioral correctness claim."
            ),
        },
        "non_coverage": [
            "does not start proof lanes",
            "does not run Cargo, clippy, tests, rustdoc, fuzzing, or Lean",
            "does not prove behavioral correctness",
            "does not mutate git, Beads, Agent Mail, or proof caches",
            "does not replace OS-level RCH worker cgroup or memory limits",
            "does not clean, stage, stash, revert, or delete dirty files",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["operator_summary"]
    lines = [
        "# Swarm Pressure Preflight Report",
        "",
        f"- profile_id: {report['profile_id']}",
        f"- generated_at: {report['generated_at']}",
        f"- decision: {summary['decision']}",
        f"- blockers: {summary['blocker_count']}",
        f"- warnings: {summary['warning_count']}",
        f"- source_count: {summary['source_count']}",
        "",
        "## Source Artifacts",
    ]
    for source in report["source_artifacts"]:
        lines.append(
            "- "
            f"{source['kind']} | path={source['artifact_path'] or '<inline>'} | "
            f"version={source['version'] or '<missing>'} | digest={source['digest'] or '<missing>'}"
        )
    lines.append("")
    lines.append("## Blockers")
    if report["blockers"]:
        for row in report["blockers"]:
            lines.append(
                "- "
                f"{row['kind']} | source={row['source_kind']} | "
                f"lane={row['lane_id'] or '<none>'} | path={row['path'] or '<none>'} | "
                f"reason={row['reason']}"
            )
    else:
        lines.append("- <none>")
    lines.append("")
    lines.append("## Warnings")
    if report["warnings"]:
        for row in report["warnings"]:
            lines.append(
                "- "
                f"{row['kind']} | source={row['source_kind']} | "
                f"lane={row['lane_id'] or '<none>'} | claim={row['claim_id'] or '<none>'} | "
                f"reason={row['reason']}"
            )
    else:
        lines.append("- <none>")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a deterministic swarm pressure preflight report")
    parser.add_argument("--fixture", type=Path, help="Read deterministic input from a JSON fixture")
    parser.add_argument("--repo-path", type=Path, default=Path.cwd(), help="Repository root")
    parser.add_argument("--generated-at", default="", help="Override generated_at timestamp")
    parser.add_argument("--output", choices=["json", "markdown"], default="json")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        report = build_report(args)
    except Exception as error:
        print(f"swarm_pressure_preflight_report: {error}", file=sys.stderr)
        return 2

    if args.output == "markdown":
        print(render_markdown(report))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
