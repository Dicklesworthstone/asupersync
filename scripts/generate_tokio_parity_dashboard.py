#!/usr/bin/env python3
"""Generate TOKIO-REPLACE parity dashboard artifacts for T1.4.a.

This script composes a deterministic dashboard from repository truth:
- Beads issue graph (`.beads/issues.jsonl`)
- Capability inventory (`docs/tokio_ecosystem_capability_inventory.md`)
- Expected evidence artifacts for each TOKIO-REPLACE track

Outputs:
- machine-readable JSON (`docs/tokio_parity_dashboard.json` by default)
- human-readable markdown (`docs/tokio_parity_dashboard.md` by default)
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path
from typing import Any


PROGRAM_ID = "asupersync-2oh2u"
PROGRAM_BEAD = "asupersync-2oh2u.1.4.1"
SCHEMA_VERSION = "tokio-parity-dashboard-v1"

TRACKS: list[dict[str, str]] = [
    {
        "track": "T1",
        "name": "Definition-of-Done baseline",
        "root_id": "asupersync-2oh2u.1",
    },
    {"track": "T2", "name": "I/O and tokio-util", "root_id": "asupersync-2oh2u.2"},
    {
        "track": "T3",
        "name": "Filesystem/process/signal",
        "root_id": "asupersync-2oh2u.3",
    },
    {"track": "T4", "name": "QUIC and HTTP/3", "root_id": "asupersync-2oh2u.4"},
    {
        "track": "T5",
        "name": "Web, middleware, gRPC",
        "root_id": "asupersync-2oh2u.5",
    },
    {"track": "T6", "name": "Database and messaging", "root_id": "asupersync-2oh2u.6"},
    {"track": "T7", "name": "Interop adapters", "root_id": "asupersync-2oh2u.7"},
    {
        "track": "T8",
        "name": "Conformance and CI gates",
        "root_id": "asupersync-2oh2u.10",
    },
    {"track": "T9", "name": "Migration and GA", "root_id": "asupersync-2oh2u.11"},
]

TRACK_EVIDENCE: dict[str, list[str]] = {
    "T1": [
        "docs/tokio_ecosystem_capability_inventory.md",
        "docs/tokio_capability_evidence_map.md",
        "docs/tokio_capability_risk_register.md",
        "docs/tokio_gap_scoring_rubric.md",
        "docs/tokio_gap_wave_classification.md",
        "docs/tokio_functional_parity_contract.md",
        "docs/tokio_nonfunctional_closure_criteria.md",
        "docs/tokio_evidence_checklist.md",
        "docs/tokio_replacement_roadmap.md",
    ],
    "T2": ["docs/tokio_io_parity_audit.md", "tests/tokio_io_parity_audit.rs"],
    "T3": [
        "docs/tokio_fs_process_signal_parity_matrix.md",
        "docs/tokio_fs_process_signal_parity_matrix.json",
        "tests/tokio_fs_process_signal_parity_matrix.rs",
    ],
    "T4": [],
    "T5": ["docs/tokio_web_grpc_parity_map.md", "tests/tokio_web_grpc_parity_map.rs"],
    "T6": [
        "docs/tokio_db_messaging_gap_baseline.md",
        "tests/tokio_db_messaging_gap_baseline.rs",
    ],
    "T7": [
        "docs/tokio_interop_target_ranking.md",
        "tests/tokio_interop_target_ranking.rs",
    ],
    "T8": [
        "docs/tokio_deterministic_lab_model_expansion.md",
        "docs/tokio_executable_conformance_contracts.md",
        "docs/tokio_ci_quality_gate_enforcement.md",
        "tests/tokio_deterministic_lab_model_expansion.rs",
        "tests/tokio_executable_conformance_contracts.rs",
        "tests/tokio_ci_quality_gate_enforcement.rs",
    ],
    "T9": [
        "docs/tokio_migration_strategy_decision_framework.md",
        "tests/tokio_migration_strategy_decision_framework.rs",
    ],
}


def utc_now_rfc3339() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate TOKIO-REPLACE parity dashboard artifacts."
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root path (default: current directory).",
    )
    parser.add_argument(
        "--issues",
        default=".beads/issues.jsonl",
        help="Path to beads issues jsonl (relative to repo root).",
    )
    parser.add_argument(
        "--inventory-doc",
        default="docs/tokio_ecosystem_capability_inventory.md",
        help="Path to capability inventory markdown (relative to repo root).",
    )
    parser.add_argument(
        "--json-out",
        default="docs/tokio_parity_dashboard.json",
        help="Output JSON path (relative to repo root).",
    )
    parser.add_argument(
        "--md-out",
        default="docs/tokio_parity_dashboard.md",
        help="Output markdown path (relative to repo root).",
    )
    parser.add_argument(
        "--generated-at",
        default=None,
        help="Override generated_at timestamp (RFC3339 UTC string).",
    )
    return parser.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load_ndjson(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            parsed = json.loads(line)
            if not isinstance(parsed, dict):
                continue
            parsed["_line"] = line_no
            records.append(parsed)
    return records


def file_sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_status(issue: dict[str, Any] | None) -> str:
    if not issue:
        return "missing"
    raw = issue.get("status", "unknown")
    if isinstance(raw, str):
        return raw.lower()
    return "unknown"


def is_closed(issue: dict[str, Any] | None) -> bool:
    return get_status(issue) == "closed"


def dependency_ids(issue: dict[str, Any]) -> list[str]:
    deps = issue.get("dependencies")
    if not isinstance(deps, list):
        return []
    out: list[str] = []
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        dep_id = dep.get("depends_on_id")
        dep_type = dep.get("type")
        if not isinstance(dep_id, str):
            continue
        # Parent-child expresses hierarchy; blocker chains are for actual blocking deps.
        if dep_type == "parent-child":
            continue
        out.append(dep_id)
    return sorted(set(out))


def unresolved_dependencies(issue: dict[str, Any], issues_by_id: dict[str, dict[str, Any]]) -> list[str]:
    unresolved: list[str] = []
    for dep_id in dependency_ids(issue):
        dep_issue = issues_by_id.get(dep_id)
        if dep_issue is None or not is_closed(dep_issue):
            unresolved.append(dep_id)
    return sorted(unresolved)


def build_blocker_chain(
    issue_id: str, issues_by_id: dict[str, dict[str, Any]]
) -> tuple[list[str], bool]:
    chain = [issue_id]
    seen = {issue_id}
    current = issue_id
    cycle_detected = False
    while True:
        issue = issues_by_id.get(current)
        if issue is None:
            break
        unresolved = unresolved_dependencies(issue, issues_by_id)
        if not unresolved:
            break
        next_id = unresolved[0]
        chain.append(next_id)
        if next_id in seen:
            cycle_detected = True
            break
        seen.add(next_id)
        current = next_id
    return chain, cycle_detected


def normalize_axis_value(raw: str) -> str:
    value = raw.strip().strip("`").strip()
    value = value.replace("**", "")
    if "—" in value:
        value = value.split("—", 1)[0].strip()
    if " - " in value:
        value = value.split(" - ", 1)[0].strip()
    return value.lower().replace(" ", "_")


def parse_inventory_families(doc: str) -> list[dict[str, str]]:
    lines = doc.splitlines()
    family_indices: list[tuple[int, str, str]] = []
    header_re = re.compile(r"^###\s+(F\d+)\s+—\s+(.+)$")
    for idx, line in enumerate(lines):
        match = header_re.match(line.strip())
        if match:
            family_indices.append((idx, match.group(1), match.group(2).strip()))

    families: list[dict[str, str]] = []
    for i, (start_idx, family_id, title) in enumerate(family_indices):
        end_idx = family_indices[i + 1][0] if i + 1 < len(family_indices) else len(lines)
        block = lines[start_idx:end_idx]

        parity = "unknown"
        maturity = "unknown"
        determinism = "unknown"
        for line in block:
            stripped = line.strip()
            if stripped.startswith("| Parity |"):
                parts = [p.strip() for p in stripped.split("|")]
                if len(parts) >= 3:
                    parity = normalize_axis_value(parts[2])
            elif stripped.startswith("| Maturity |"):
                parts = [p.strip() for p in stripped.split("|")]
                if len(parts) >= 3:
                    maturity = normalize_axis_value(parts[2])
            elif stripped.startswith("| Determinism |"):
                parts = [p.strip() for p in stripped.split("|")]
                if len(parts) >= 3:
                    determinism = normalize_axis_value(parts[2])

        families.append(
            {
                "family_id": family_id,
                "title": title,
                "parity": parity,
                "maturity": maturity,
                "determinism": determinism,
            }
        )
    return families


def track_issues(root_id: str, issues_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    prefix = f"{root_id}."
    items = [issue for issue_id, issue in issues_by_id.items() if issue_id.startswith(prefix)]
    return sorted(items, key=lambda issue: str(issue.get("id", "")))


def count_statuses(issues: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"open": 0, "in_progress": 0, "closed": 0, "other": 0}
    for issue in issues:
        status = get_status(issue)
        if status in counts:
            counts[status] += 1
        else:
            counts["other"] += 1
    return counts


def build_track_rows(repo_root: Path, issues_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in TRACKS:
        track = spec["track"]
        root_id = spec["root_id"]
        root_issue = issues_by_id.get(root_id)
        children = track_issues(root_id, issues_by_id)
        status_counts = count_statuses(children)
        child_total = len(children)
        closed_count = status_counts["closed"]
        completion_ratio = (closed_count / child_total) if child_total else 0.0

        expected_artifacts = TRACK_EVIDENCE.get(track, [])
        evidence_rows: list[dict[str, Any]] = []
        for rel_path in expected_artifacts:
            abs_path = repo_root / rel_path
            evidence_rows.append(
                {
                    "path": rel_path,
                    "exists": abs_path.exists(),
                    "sha256": file_sha256(abs_path),
                }
            )
        evidence_present = sum(1 for row in evidence_rows if row["exists"])
        evidence_ratio = (evidence_present / len(evidence_rows)) if evidence_rows else 1.0

        unresolved_children = [
            issue for issue in children if unresolved_dependencies(issue, issues_by_id)
        ]
        unresolved_count = len(unresolved_children)
        top_blocker = None
        if unresolved_children:
            issue = unresolved_children[0]
            chain, cycle = build_blocker_chain(str(issue.get("id", "")), issues_by_id)
            top_blocker = {
                "issue_id": issue.get("id"),
                "status": get_status(issue),
                "chain": chain,
                "cycle_detected": cycle,
            }

        rows.append(
            {
                "track": track,
                "name": spec["name"],
                "root_bead_id": root_id,
                "root_status": get_status(root_issue),
                "root_title": root_issue.get("title") if root_issue else None,
                "children_total": child_total,
                "children_closed": closed_count,
                "children_in_progress": status_counts["in_progress"],
                "children_open": status_counts["open"],
                "completion_ratio": round(completion_ratio, 4),
                "evidence": {
                    "required_count": len(evidence_rows),
                    "present_count": evidence_present,
                    "completeness_ratio": round(evidence_ratio, 4),
                    "artifacts": evidence_rows,
                },
                "unresolved_blocker_count": unresolved_count,
                "top_blocker_chain": top_blocker,
            }
        )
    return rows


def build_blocker_chains(issues_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    for issue_id, issue in issues_by_id.items():
        status = get_status(issue)
        if status == "closed":
            continue
        unresolved = unresolved_dependencies(issue, issues_by_id)
        if not unresolved:
            continue
        chain, cycle = build_blocker_chain(issue_id, issues_by_id)
        chains.append(
            {
                "issue_id": issue_id,
                "title": issue.get("title"),
                "status": status,
                "direct_unresolved_dependencies": unresolved,
                "chain": chain,
                "chain_length": len(chain),
                "cycle_detected": cycle,
            }
        )
    chains.sort(
        key=lambda row: (
            -int(row["chain_length"]),
            str(row["status"]),
            str(row["issue_id"]),
        )
    )
    return chains


def program_issues(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    issues: dict[str, dict[str, Any]] = {}
    for record in records:
        issue_id = record.get("id")
        if not isinstance(issue_id, str):
            continue
        if issue_id == PROGRAM_ID or issue_id.startswith(f"{PROGRAM_ID}."):
            issues[issue_id] = record
    return issues


def build_summary(
    issues_by_id: dict[str, dict[str, Any]],
    tracks: list[dict[str, Any]],
    families: list[dict[str, str]],
    blocker_chains: list[dict[str, Any]],
) -> dict[str, Any]:
    all_issues = list(issues_by_id.values())
    status_counts = count_statuses(all_issues)

    parity_counts: dict[str, int] = {}
    for family in families:
        parity = family["parity"]
        parity_counts[parity] = parity_counts.get(parity, 0) + 1

    return {
        "program_id": PROGRAM_ID,
        "program_issue_count": len(all_issues),
        "status_counts": status_counts,
        "track_count": len(tracks),
        "capability_family_count": len(families),
        "capability_parity_counts": parity_counts,
        "unresolved_blocker_count": len(blocker_chains),
    }


def sanitize_token(raw: str) -> str:
    token = re.sub(r"[^a-zA-Z0-9._-]+", "-", raw.strip().lower())
    return token.strip("-")


def build_drift_routing(
    generated_at: str, tracks: list[dict[str, Any]], blocker_chains: list[dict[str, Any]], ci_policy: dict[str, Any]
) -> dict[str, Any]:
    alerts: list[dict[str, Any]] = []

    for row in tracks:
        track = row["track"]
        root_id = str(row["root_bead_id"])
        root_status = str(row["root_status"])
        evidence_ratio = float(row["evidence"]["completeness_ratio"])
        unresolved = int(row["unresolved_blocker_count"])
        children_total = int(row["children_total"])
        children_closed = int(row["children_closed"])

        if root_status == "closed" and evidence_ratio < 1.0:
            condition = "closed_with_missing_evidence"
            alerts.append(
                {
                    "alert_id": f"{track}:{condition}",
                    "condition": condition,
                    "severity": "high",
                    "affected_issue_ids": [root_id],
                    "bead_actions": {
                        "status_flag_command": f"br update {root_id} --status in_progress --assignee <agent>",
                        "follow_up_template_command": (
                            "br create --title "
                            f"\"[TOKIO-PARITY-DRIFT] {condition} :: {root_id}\" "
                            "--type task --priority 0 --add-label tokio-replacement "
                            "--add-label dashboard --add-label drift"
                        ),
                    },
                }
            )

        if root_status == "closed" and unresolved > 0:
            condition = "closed_with_unresolved_blockers"
            alerts.append(
                {
                    "alert_id": f"{track}:{condition}",
                    "condition": condition,
                    "severity": "high",
                    "affected_issue_ids": [root_id],
                    "bead_actions": {
                        "status_flag_command": f"br update {root_id} --status in_progress --assignee <agent>",
                        "follow_up_template_command": (
                            "br create --title "
                            f"\"[TOKIO-PARITY-DRIFT] {condition} :: {root_id}\" "
                            "--type task --priority 0 --add-label tokio-replacement "
                            "--add-label dashboard --add-label drift"
                        ),
                    },
                }
            )

        if root_status == "closed" and children_closed < children_total:
            condition = "closed_with_incomplete_children"
            alerts.append(
                {
                    "alert_id": f"{track}:{condition}",
                    "condition": condition,
                    "severity": "high",
                    "affected_issue_ids": [root_id],
                    "bead_actions": {
                        "status_flag_command": f"br update {root_id} --status in_progress --assignee <agent>",
                        "follow_up_template_command": (
                            "br create --title "
                            f"\"[TOKIO-PARITY-DRIFT] {condition} :: {root_id}\" "
                            "--type task --priority 0 --add-label tokio-replacement "
                            "--add-label dashboard --add-label drift"
                        ),
                    },
                }
            )

    for row in blocker_chains:
        if not row["cycle_detected"]:
            continue
        issue_id = str(row["issue_id"])
        condition = "dependency_cycle_detected"
        alerts.append(
            {
                "alert_id": f"{issue_id}:{condition}",
                "condition": condition,
                "severity": "urgent",
                "affected_issue_ids": [issue_id],
                "bead_actions": {
                    "status_flag_command": f"br update {issue_id} --status in_progress --assignee <agent>",
                    "follow_up_template_command": (
                        "br create --title "
                        f"\"[TOKIO-PARITY-DRIFT] {condition} :: {issue_id}\" "
                        "--type task --priority 0 --add-label tokio-replacement "
                        "--add-label dashboard --add-label drift"
                    ),
                },
            }
        )

    owner_roles = [
        ci_policy["ownership"]["primary_owner"],
        ci_policy["ownership"]["escalation_owner"],
    ]
    for alert in alerts:
        thread_seed = f"{alert['condition']}-{alert['affected_issue_ids'][0]}"
        thread_id = f"tokio-parity-drift-{sanitize_token(thread_seed)}"
        message_template = (
            "Detected drift condition `{condition}` at `{generated_at}`. "
            "Affected issue ids: {affected_issue_ids}. "
            "Execute `{status_flag_command}` and triage follow-up using "
            "`{follow_up_template_command}`."
        ).format(
            condition=alert["condition"],
            generated_at=generated_at,
            affected_issue_ids=", ".join(alert["affected_issue_ids"]),
            status_flag_command=alert["bead_actions"]["status_flag_command"],
            follow_up_template_command=alert["bead_actions"]["follow_up_template_command"],
        )
        alert["agent_mail"] = {
            "thread_id": thread_id,
            "subject": (
                f"[tokio-parity-drift] {alert['condition']} :: "
                f"{', '.join(alert['affected_issue_ids'])}"
            ),
            "recipient_roles": owner_roles,
            "message_template": message_template,
            "send_message_template": (
                "mcp__mcp_agent_mail__send_message("
                "project_key=\"/data/projects/asupersync\", "
                "sender_name=\"<agent>\", to=[\"<agent>\"], "
                f"subject=\"[tokio-parity-drift] {alert['condition']}\", "
                f"thread_id=\"{thread_id}\", ack_required=true, "
                "body_md=\"<rendered-from-message_template>\""
                ")"
            ),
        }

    return {
        "policy_id": "tokio-parity-drift-routing-v1",
        "generated_at": generated_at,
        "owner_roles": owner_roles,
        "alert_count": len(alerts),
        "alerts": alerts,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    generated_at = payload["generated_at"]
    summary = payload["summary"]
    tracks = payload["tracks"]
    families = payload["capability_families"]
    blocker_chains = payload["blocker_chains"]
    ci_policy = payload["ci_policy"]
    drift_routing = payload["drift_routing"]

    lines: list[str] = []
    lines.append("# Tokio Replacement Parity Dashboard")
    lines.append("")
    lines.append(f"**Bead**: `{PROGRAM_BEAD}` ([T1.4.a])")
    lines.append("**Generator**: `scripts/generate_tokio_parity_dashboard.py`")
    lines.append(f"**Generated at (UTC)**: `{generated_at}`")
    lines.append(f"**Schema**: `{payload['schema_version']}`")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- Program issues: **{summary['program_issue_count']}**")
    lines.append(
        "- Status counts: "
        f"open={summary['status_counts']['open']}, "
        f"in_progress={summary['status_counts']['in_progress']}, "
        f"closed={summary['status_counts']['closed']}, "
        f"other={summary['status_counts']['other']}"
    )
    lines.append(f"- Tracks: **{summary['track_count']}**")
    lines.append(
        "- Capability families: "
        f"**{summary['capability_family_count']}** "
        f"(parity states: {summary['capability_parity_counts']})"
    )
    lines.append(
        f"- Unresolved blocker chains: **{summary['unresolved_blocker_count']}**"
    )
    lines.append("")
    lines.append("## 2. Track Parity Dashboard")
    lines.append("")
    lines.append(
        "| Track | Root Bead | Root Status | Child Progress | Evidence | Unresolved Blockers |"
    )
    lines.append("|---|---|---|---|---|---|")
    for row in tracks:
        lines.append(
            "| {track} | `{root}` | `{status}` | {closed}/{total} ({ratio:.1%}) | {ep}/{er} ({e_ratio:.1%}) | {blockers} |".format(
                track=row["track"],
                root=row["root_bead_id"],
                status=row["root_status"],
                closed=row["children_closed"],
                total=row["children_total"],
                ratio=row["completion_ratio"],
                ep=row["evidence"]["present_count"],
                er=row["evidence"]["required_count"],
                e_ratio=row["evidence"]["completeness_ratio"],
                blockers=row["unresolved_blocker_count"],
            )
        )
    lines.append("")
    lines.append("## 3. Evidence Completeness by Track")
    lines.append("")
    for row in tracks:
        lines.append(f"### {row['track']} — {row['name']}")
        lines.append("")
        artifacts: list[dict[str, Any]] = row["evidence"]["artifacts"]
        if not artifacts:
            lines.append("- No explicit artifact contract declared for this track yet.")
            lines.append("")
            continue
        missing = [entry["path"] for entry in artifacts if not entry["exists"]]
        if missing:
            lines.append("- Missing artifacts:")
            for artifact in missing:
                lines.append(f"  - `{artifact}`")
        else:
            lines.append("- All required evidence artifacts are present.")
        lines.append("")
    lines.append("## 4. Unresolved Blocker Chains")
    lines.append("")
    lines.append(
        "Top unresolved chains by depth. Chain starts with blocked issue and follows unresolved dependencies."
    )
    lines.append("")
    if blocker_chains:
        lines.append("| Issue | Status | Chain |")
        lines.append("|---|---|---|")
        for row in blocker_chains[:20]:
            chain = " -> ".join(f"`{issue_id}`" for issue_id in row["chain"])
            lines.append(f"| `{row['issue_id']}` | `{row['status']}` | {chain} |")
    else:
        lines.append("No unresolved blocker chains detected.")
    lines.append("")
    lines.append("## 5. Capability Family Parity Snapshot")
    lines.append("")
    lines.append(
        "| Family | Title | Parity | Maturity | Determinism |"
    )
    lines.append("|---|---|---|---|---|")
    for family in families:
        lines.append(
            "| {id} | {title} | `{parity}` | `{maturity}` | `{det}` |".format(
                id=family["family_id"],
                title=family["title"],
                parity=family["parity"],
                maturity=family["maturity"],
                det=family["determinism"],
            )
        )
    lines.append("")
    lines.append("## 6. Drift-Detection Rules")
    lines.append("")
    for rule in payload["drift_detection_rules"]:
        lines.append(f"- `{rule['id']}` {rule['rule']}")
    lines.append("")
    lines.append("## 7. CI/Nightly Drift Enforcement Policy")
    lines.append("")
    lines.append(f"- Policy ID: `{ci_policy['policy_id']}`")
    lines.append("- Hard-fail conditions:")
    for condition in ci_policy["hard_fail_conditions"]:
        lines.append(f"  - `{condition}`")
    lines.append("- Promotion criteria:")
    for criterion in ci_policy["promotion_criteria"]:
        lines.append(f"  - {criterion}")
    lines.append("- Rollback and exception handling:")
    for criterion in ci_policy["rollback_or_exception_criteria"]:
        lines.append(f"  - {criterion}")
    lines.append(
        f"- Ownership and escalation: `{ci_policy['ownership']['primary_owner']}` "
        f"(escalate to `{ci_policy['ownership']['escalation_owner']}`)"
    )
    lines.append(
        "- Enforcement workflow: `.github/workflows/tokio_parity_dashboard_drift.yml`"
    )
    lines.append("")
    lines.append("## 8. Drift Alert Routing")
    lines.append("")
    lines.append(
        "Drift alerts are converted into beads status-routing commands and agent-mail templates."
    )
    lines.append("")
    if drift_routing["alerts"]:
        lines.append("| Condition | Severity | Affected IDs | Agent-Mail Thread |")
        lines.append("|---|---|---|---|")
        for alert in drift_routing["alerts"]:
            lines.append(
                "| `{condition}` | `{severity}` | {affected} | `{thread_id}` |".format(
                    condition=alert["condition"],
                    severity=alert["severity"],
                    affected=", ".join(f"`{issue}`" for issue in alert["affected_issue_ids"]),
                    thread_id=alert["agent_mail"]["thread_id"],
                )
            )
            lines.append(
                f"- Status flag command: `{alert['bead_actions']['status_flag_command']}`"
            )
            lines.append(
                "- Follow-up bead template: "
                f"`{alert['bead_actions']['follow_up_template_command']}`"
            )
            lines.append(
                "- Agent-mail template: "
                f"`{alert['agent_mail']['send_message_template']}`"
            )
    else:
        lines.append("No actionable drift alerts detected.")
    lines.append("")
    lines.append("## 9. Deterministic Regeneration")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 scripts/generate_tokio_parity_dashboard.py")
    lines.append("rch exec -- cargo test --test tokio_parity_dashboard -- --nocapture")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def display_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    issues_path = (repo_root / args.issues).resolve()
    inventory_doc_path = (repo_root / args.inventory_doc).resolve()
    json_out_path = (repo_root / args.json_out).resolve()
    md_out_path = (repo_root / args.md_out).resolve()

    generated_at = args.generated_at or utc_now_rfc3339()

    records = load_ndjson(issues_path)
    issues_by_id = program_issues(records)
    inventory_doc = read_text(inventory_doc_path)
    families = parse_inventory_families(inventory_doc)
    tracks = build_track_rows(repo_root, issues_by_id)
    blocker_chains = build_blocker_chains(issues_by_id)

    ci_policy = {
        "policy_id": "tokio-parity-dashboard-drift-v1",
        "hard_fail_conditions": [
            "dependency_cycle_detected",
            "closed_with_missing_evidence",
            "closed_with_unresolved_blockers",
            "closed_with_incomplete_children",
            "dashboard_artifact_drift",
        ],
        "promotion_criteria": [
            "all hard-fail conditions clear",
            "dashboard artifacts are regenerated and committed",
            "tokio_parity_dashboard contract tests pass in CI",
        ],
        "rollback_or_exception_criteria": [
            "if hard-fail triggers, block promotion and open/append remediation bead comments",
            "exceptions require explicit owner approval and follow-up bead with due date",
            "nightly failures must be triaged before next release promotion window",
        ],
        "ownership": {
            "primary_owner": "tokio-replacement track owner",
            "escalation_owner": "runtime maintainers",
        },
    }

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bead_id": PROGRAM_BEAD,
        "program_id": PROGRAM_ID,
        "generated_at": generated_at,
        "generated_by": "scripts/generate_tokio_parity_dashboard.py",
        "inputs": {
            "issues_path": str(Path(args.issues)),
            "inventory_doc_path": str(Path(args.inventory_doc)),
            "issues_sha256": file_sha256(issues_path),
            "inventory_sha256": file_sha256(inventory_doc_path),
        },
        "summary": build_summary(issues_by_id, tracks, families, blocker_chains),
        "tracks": tracks,
        "capability_families": families,
        "blocker_chains": blocker_chains,
        "drift_detection_rules": [
            {
                "id": "PD-DRIFT-01",
                "rule": "dashboard must be generated from .beads/issues.jsonl and capability inventory markdown",
            },
            {
                "id": "PD-DRIFT-02",
                "rule": "all TOKIO-REPLACE tracks T1..T9 must be present with stable root bead mapping",
            },
            {
                "id": "PD-DRIFT-03",
                "rule": "evidence completeness must be recomputed from in-repo artifact existence",
            },
            {
                "id": "PD-DRIFT-04",
                "rule": "unresolved blocker chains must be derived from live dependency edges (excluding parent-child)",
            },
            {
                "id": "PD-DRIFT-05",
                "rule": "JSON and markdown artifacts must be emitted from the same in-memory payload",
            },
        ],
        "ci_policy": ci_policy,
        "drift_routing": build_drift_routing(
            generated_at=generated_at,
            tracks=tracks,
            blocker_chains=blocker_chains,
            ci_policy=ci_policy,
        ),
        "ci_commands": [
            "python3 scripts/generate_tokio_parity_dashboard.py",
            "rch exec -- cargo test --test tokio_parity_dashboard -- --nocapture",
        ],
    }

    markdown = render_markdown(payload)
    write_json(json_out_path, payload)
    write_text(md_out_path, markdown)

    print(f"Wrote {display_path(json_out_path, repo_root)}")
    print(f"Wrote {display_path(md_out_path, repo_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
