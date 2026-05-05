#!/usr/bin/env bash
set -euo pipefail

MODE="dry-run"
OUTPUT_ROOT="target/agent-swarm-coordination-collector"
RUN_ID=""
GENERATED_AT=""
FIXTURE=0
SOURCES=()

usage() {
  cat <<'USAGE'
Usage: scripts/run_agent_swarm_coordination_collector.sh [options]

Modes:
  --list                         List collector adapters and artifact outputs.
  --dry-run                      Print planned inputs without reading source files.
  --execute                      Read explicit sources and emit a bundle.
  --fixture                      Use checked synthetic fixture inputs.

Options:
  --source KIND:PATH              Add an explicit source input. Repeatable.
                                  KIND is agent_mail, beads, bv, rch,
                                  git_dirty_frontier, or artifact_store.
  --output-root PATH              Artifact root for execute/fixture output.
  --run-id ID                    Stable run id. Defaults deterministically.
  --generated-at TIMESTAMP        Stable generated_at override.
  -h, --help                      Show this help.

This collector never reads live Agent Mail, Beads, bv, rch, git, or home
directory state on its own. It only consumes explicit files or checked fixtures.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --list)
      MODE="list"
      shift
      ;;
    --dry-run)
      MODE="dry-run"
      shift
      ;;
    --execute)
      MODE="execute"
      shift
      ;;
    --fixture)
      FIXTURE=1
      shift
      ;;
    --source)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --source" >&2
        exit 2
      fi
      SOURCES+=("$2")
      shift 2
      ;;
    --output-root)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --output-root" >&2
        exit 2
      fi
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --run-id)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --run-id" >&2
        exit 2
      fi
      RUN_ID="$2"
      shift 2
      ;;
    --generated-at)
      if [[ $# -lt 2 ]]; then
        echo "missing value for --generated-at" >&2
        exit 2
      fi
      GENERATED_AT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$FIXTURE" == "1" && "$MODE" == "dry-run" ]]; then
  MODE="execute"
fi

SOURCE_SPECS=""
if [[ ${#SOURCES[@]} -gt 0 ]]; then
  SOURCE_SPECS="$(printf '%s\n' "${SOURCES[@]}")"
fi

COLLECTOR_MODE="$MODE" \
COLLECTOR_FIXTURE="$FIXTURE" \
COLLECTOR_OUTPUT_ROOT="$OUTPUT_ROOT" \
COLLECTOR_RUN_ID="$RUN_ID" \
COLLECTOR_GENERATED_AT="$GENERATED_AT" \
COLLECTOR_SOURCE_SPECS="$SOURCE_SPECS" \
python3 - <<'PY'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

CONTRACT_VERSION = "agent-swarm-coordination-collector-contract-v1"
BUNDLE_VERSION = "agent-swarm-coordination-workload-bundle-v1"
EVENT_VERSION = "agent-swarm-coordination-event-v1"
DEFAULT_GENERATED_AT = "2026-05-05T05:00:00Z"
STALE_SOURCE_MAX_SECONDS = 24 * 60 * 60
ADAPTERS = [
    "agent_mail",
    "beads",
    "bv",
    "rch",
    "git_dirty_frontier",
    "artifact_store",
]
SORT_KEY = [
    "event_ts",
    "stable_sequence",
    "source_kind",
    "source_thread_or_bead",
    "event_kind",
    "correlation_id",
]


def h(text, size=12):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:size]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def parse_instant(value):
    text = str(value or "")
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def pseudonym(prefix, value):
    if not value:
        return f"{prefix}:unknown"
    return f"{prefix}:coord-{h(str(value), 8)}"


def safe_thread(value):
    if not value:
        return "thread:unknown"
    text = str(value)
    if re.fullmatch(r"asupersync-[A-Za-z0-9.]+", text):
        return text
    return f"thread:{h(text, 10)}"


def contains_secret(text):
    patterns = [
        r"Authorization:\s*Bearer\s+\S+",
        r"\bBearer\s+[A-Za-z0-9._-]{10,}",
        r"\bgh[pousr]_[A-Za-z0-9_]+",
        r"\bapi[_-]?key\s*=",
        r"\bpassword\s*=",
        r"BEGIN OPENSSH PRIVATE KEY",
    ]
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def event(
    *,
    source_kind,
    source_agent,
    source_thread_or_bead,
    event_ts,
    event_kind,
    correlation_id,
    command_class,
    workload_family,
    queue_depth_or_lock_state=None,
    file_frontier=None,
    artifact_refs=None,
    redaction_verdict="metadata_only",
    refusal_reason="",
):
    ev = {
        "schema_version": EVENT_VERSION,
        "run_id": "",
        "source_kind": source_kind,
        "source_agent": pseudonym("agent", source_agent),
        "source_thread_or_bead": safe_thread(source_thread_or_bead),
        "event_ts": event_ts or DEFAULT_GENERATED_AT,
        "stable_sequence": "",
        "event_kind": event_kind,
        "correlation_id": correlation_id or f"{source_kind}:{event_kind}:unknown",
        "command_class": command_class,
        "workload_family": workload_family,
        "queue_depth_or_lock_state": queue_depth_or_lock_state or {},
        "file_frontier": file_frontier or {
            "changed_paths_count": 0,
            "unsupported_dirty_paths_count": 0,
            "path_hashes": [],
        },
        "artifact_refs": artifact_refs or [],
        "redaction_verdict": redaction_verdict,
        "source_hash": "",
        "refusal_reason": refusal_reason,
    }
    source_basis = {
        key: ev[key]
        for key in [
            "source_kind",
            "source_agent",
            "source_thread_or_bead",
            "event_ts",
            "event_kind",
            "correlation_id",
            "command_class",
            "workload_family",
            "queue_depth_or_lock_state",
            "file_frontier",
            "artifact_refs",
            "redaction_verdict",
            "refusal_reason",
        ]
    }
    ev["source_hash"] = f"sha256:{hashlib.sha256(canonical(source_basis).encode()).hexdigest()}"
    return ev


def refresh_source_hash(ev):
    source_basis = {
        key: ev[key]
        for key in [
            "source_kind",
            "source_agent",
            "source_thread_or_bead",
            "event_ts",
            "event_kind",
            "correlation_id",
            "command_class",
            "workload_family",
            "queue_depth_or_lock_state",
            "file_frontier",
            "artifact_refs",
            "redaction_verdict",
            "refusal_reason",
        ]
    }
    ev["source_hash"] = f"sha256:{hashlib.sha256(canonical(source_basis).encode()).hexdigest()}"


def mark_refused(ev, reason):
    ev["redaction_verdict"] = "refused"
    ev["refusal_reason"] = reason
    refresh_source_hash(ev)


def refused(kind, path, reason, detail):
    return event(
        source_kind=kind if kind in ADAPTERS else "unknown",
        source_agent="collector",
        source_thread_or_bead=path,
        event_ts=DEFAULT_GENERATED_AT,
        event_kind="input_refused",
        correlation_id=f"collector-refusal:{kind}:{h(path + reason + detail, 10)}",
        command_class="coordination",
        workload_family="coordination_latency_burst",
        redaction_verdict="refused",
        refusal_reason=reason,
    )


def stale_source_event(ev, generated_at):
    event_time = parse_instant(ev.get("event_ts"))
    generated_time = parse_instant(generated_at)
    if event_time is None or generated_time is None:
        return False
    return (generated_time - event_time).total_seconds() > STALE_SOURCE_MAX_SECONDS


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()
    return raw, json.loads(raw)


def as_items(data, key):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get(key), list):
            return data[key]
        if isinstance(data.get("result"), list):
            return data["result"]
        if isinstance(data.get("issues"), list):
            return data["issues"]
    return [data]


def agent_mail_events(data):
    out = []
    for msg in as_items(data, "messages"):
        if not isinstance(msg, dict):
            out.append(refused("agent_mail", "message", "missing_required_field", "not-object"))
            continue
        body = str(msg.get("body_md") or msg.get("body") or "")
        if contains_secret(body):
            out.append(
                refused(
                    "agent_mail",
                    str(msg.get("id", "message")),
                    "unredacted_secret",
                    "message-body-secret",
                )
            )
            continue
        subject = str(msg.get("subject") or "")
        family = "coordination_latency_burst" if msg.get("ack_required") else "proof_runner_fanout"
        if "reservation" in subject.lower() or "lease" in subject.lower():
            family = "tracker_lock_contention"
        out.append(
            event(
                source_kind="agent_mail",
                source_agent=msg.get("from") or msg.get("sender") or "unknown",
                source_thread_or_bead=msg.get("thread_id") or msg.get("subject") or "mail",
                event_ts=msg.get("created_ts") or msg.get("created_at") or DEFAULT_GENERATED_AT,
                event_kind="message_sent",
                correlation_id=f"mail:{msg.get('id', h(canonical(msg), 10))}",
                command_class="coordination",
                workload_family=family,
                queue_depth_or_lock_state={
                    "ack_required": bool(msg.get("ack_required")),
                    "body_retained": False,
                },
                redaction_verdict="metadata_only",
            )
        )
    return out


def beads_events(data):
    out = []
    for issue in as_items(data, "issues"):
        if not isinstance(issue, dict):
            out.append(refused("beads", "issue", "missing_required_field", "not-object"))
            continue
        issue_id = issue.get("id") or issue.get("issue_id")
        status = issue.get("status", "unknown")
        if not issue_id:
            out.append(refused("beads", "issue", "missing_required_field", "missing-id"))
            continue
        family = "stale_in_progress_reclaim" if status == "in_progress" else "tracker_lock_contention"
        out.append(
            event(
                source_kind="beads",
                source_agent=issue.get("assignee") or "beads",
                source_thread_or_bead=issue_id,
                event_ts=issue.get("updated_at") or issue.get("created_at") or DEFAULT_GENERATED_AT,
                event_kind="bead_status_changed",
                correlation_id=f"bead:{issue_id}:{status}",
                command_class="tracker",
                workload_family=family,
                queue_depth_or_lock_state={
                    "status": status,
                    "priority": issue.get("priority"),
                    "dependency_count": issue.get("dependency_count", 0),
                },
                redaction_verdict="pseudonymized",
            )
        )
        for dep in issue.get("dependencies", []) or []:
            dep_id = dep.get("id") or dep.get("depends_on_id")
            if dep_id:
                out.append(
                    event(
                        source_kind="beads",
                        source_agent=issue.get("assignee") or "beads",
                        source_thread_or_bead=issue_id,
                        event_ts=issue.get("updated_at") or DEFAULT_GENERATED_AT,
                        event_kind="dependency_added",
                        correlation_id=f"dep:{issue_id}:{dep_id}",
                        command_class="tracker",
                        workload_family="tracker_lock_contention",
                        queue_depth_or_lock_state={"dependency": dep_id},
                        redaction_verdict="pseudonymized",
                    )
                )
    return out


def bv_events(data):
    summary = data.get("plan", {}).get("summary", {}) if isinstance(data, dict) else {}
    total_actionable = data.get("plan", {}).get("total_actionable", 0) if isinstance(data, dict) else 0
    return [
        event(
            source_kind="bv",
            source_agent="bv",
            source_thread_or_bead=data.get("label_scope", "bv") if isinstance(data, dict) else "bv",
            event_ts=data.get("generated_at", DEFAULT_GENERATED_AT) if isinstance(data, dict) else DEFAULT_GENERATED_AT,
            event_kind="robot_plan_snapshot",
            correlation_id=f"bv:plan:{h(canonical(summary), 10)}",
            command_class="tracker",
            workload_family="proof_runner_fanout",
            queue_depth_or_lock_state={
                "total_actionable": total_actionable,
                "highest_impact": summary.get("highest_impact"),
            },
            redaction_verdict="metadata_only",
        )
    ]


def rch_events(raw, data):
    out = []
    if isinstance(data, dict):
        jobs = data.get("jobs") or data.get("builds") or []
        if not jobs:
            jobs = [data]
        for job in jobs:
            if not isinstance(job, dict):
                continue
            status = str(job.get("status") or job.get("state") or "queued")
            if "complete" in status or "finished" in status:
                kind = "rch_job_completed"
            elif "start" in status or "running" in status:
                kind = "rch_job_started"
            else:
                kind = "rch_job_queued"
            out.append(
                event(
                    source_kind="rch",
                    source_agent=job.get("agent") or "rch",
                    source_thread_or_bead=job.get("bead_id") or job.get("id") or "rch",
                    event_ts=job.get("created_ts") or job.get("started_ts") or job.get("finished_ts") or DEFAULT_GENERATED_AT,
                    event_kind=kind,
                    correlation_id=f"rch:{job.get('id', h(canonical(job), 10))}",
                    command_class="validation",
                    workload_family="concurrent_rch_proofs",
                    queue_depth_or_lock_state={
                        "queue_depth": job.get("queue_depth", 0),
                        "worker_pool": "redacted",
                    },
                    redaction_verdict="redacted",
                )
            )
    elif "No active builds" in raw:
        out.append(
            event(
                source_kind="rch",
                source_agent="rch",
                source_thread_or_bead="rch",
                event_ts=DEFAULT_GENERATED_AT,
                event_kind="rch_job_completed",
                correlation_id="rch:no-active-builds",
                command_class="validation",
                workload_family="concurrent_rch_proofs",
                queue_depth_or_lock_state={"queue_depth": 0},
                redaction_verdict="metadata_only",
            )
        )
    return out


def git_dirty_events(data):
    paths = []
    if isinstance(data, list):
        paths = [str(item) for item in data]
    elif isinstance(data, dict):
        paths = [str(item) for item in data.get("paths", [])]
    if not paths:
        paths = []
    path_hashes = [f"path:{h(path, 10)}" for path in sorted(set(paths))]
    unsupported = sum(1 for path in paths if path.startswith("/") or path.startswith("~"))
    return [
        event(
            source_kind="git_dirty_frontier",
            source_agent="git",
            source_thread_or_bead="dirty-frontier",
            event_ts=(data.get("observed_at") if isinstance(data, dict) else None) or DEFAULT_GENERATED_AT,
            event_kind="dirty_frontier_observed",
            correlation_id=f"git:dirty:{h('|'.join(sorted(paths)), 10)}",
            command_class="git_state",
            workload_family="fail_closed_dirty_frontier",
            file_frontier={
                "changed_paths_count": len(set(paths)),
                "unsupported_dirty_paths_count": unsupported,
                "path_hashes": path_hashes,
            },
            redaction_verdict="pseudonymized",
        )
    ]


def artifact_events(data):
    refs = as_items(data, "artifacts")
    out = []
    for ref in refs:
        if isinstance(ref, dict):
            path = str(ref.get("path") or ref.get("artifact") or "artifact")
            bead = ref.get("bead_id") or ref.get("thread_id") or "artifact"
            ts = ref.get("created_ts") or ref.get("created_at") or DEFAULT_GENERATED_AT
        else:
            path = str(ref)
            bead = "artifact"
            ts = DEFAULT_GENERATED_AT
        out.append(
            event(
                source_kind="artifact_store",
                source_agent="artifact",
                source_thread_or_bead=bead,
                event_ts=ts,
                event_kind="artifact_published",
                correlation_id=f"artifact:{h(path, 10)}",
                command_class="artifact",
                workload_family="artifact_retrieval_tail",
                artifact_refs=[{"path_hash": f"artifact:{h(path, 10)}"}],
                redaction_verdict="metadata_only",
            )
        )
    return out


def fixture_sources():
    return [
        (
            "agent_mail",
            [
                {
                    "id": 771,
                    "from": "BlueMountain",
                    "thread_id": "asupersync-qn8i0p.2",
                    "created_ts": "2026-05-05T05:12:37Z",
                    "subject": "reservation conflict on tracker lease",
                    "ack_required": True,
                    "body_md": "metadata-only fixture body is intentionally not retained",
                },
                {
                    "id": 771,
                    "from": "BlueMountain",
                    "thread_id": "asupersync-qn8i0p.2",
                    "created_ts": "2026-05-05T05:12:37Z",
                    "subject": "reservation conflict on tracker lease",
                    "ack_required": True,
                    "body_md": "duplicate fixture body is intentionally not retained",
                },
            ],
        ),
        (
            "beads",
            {
                "issues": [
                    {
                        "id": "asupersync-qn8i0p.2",
                        "status": "in_progress",
                        "priority": 1,
                        "assignee": "CreamCarp",
                        "updated_at": "2026-05-05T05:13:43Z",
                        "dependency_count": 3,
                    }
                ]
            },
        ),
        (
            "bv",
            {
                "generated_at": "2026-05-05T05:14:00Z",
                "label_scope": "swarm-ops",
                "plan": {
                    "total_actionable": 1,
                    "summary": {"highest_impact": "asupersync-qn8i0p.2"},
                },
            },
        ),
        (
            "rch",
            {
                "jobs": [
                    {
                        "id": "proof-001",
                        "status": "queued",
                        "bead_id": "asupersync-qn8i0p.2",
                        "queue_depth": 3,
                        "created_ts": "2026-05-05T05:14:30Z",
                    },
                    {
                        "id": "proof-002",
                        "status": "completed",
                        "bead_id": "asupersync-hxi1ga",
                        "queue_depth": 0,
                        "finished_ts": "2026-05-05T05:15:00Z",
                    },
                ]
            },
        ),
        (
            "git_dirty_frontier",
            {
                "observed_at": "2026-05-05T05:15:30Z",
                "paths": [
                    ".beads/issues.jsonl",
                    "/data/projects/asupersync/tests/conformance/quic_connection_migration_rfc9000.rs",
                ],
            },
        ),
        (
            "artifact_store",
            {
                "artifacts": [
                    {
                        "bead_id": "asupersync-hxi1ga",
                        "path": "target/mock-code-finder/asupersync-hxi1ga-final/summary.json",
                        "created_at": "2026-05-05T05:16:00Z",
                    }
                ]
            },
        ),
    ]


def collect_from_kind(kind, raw, data, path):
    if kind == "agent_mail":
        return agent_mail_events(data)
    if kind == "beads":
        return beads_events(data)
    if kind == "bv":
        return bv_events(data)
    if kind == "rch":
        return rch_events(raw, data)
    if kind == "git_dirty_frontier":
        return git_dirty_events(data)
    if kind == "artifact_store":
        return artifact_events(data)
    return [refused("unknown", path, "unsupported_source_kind", kind)]


def materialize(events, output_root, run_id, generated_at, hard_fail):
    stale_count = 0
    for ev in events:
        if ev["redaction_verdict"] != "refused" and stale_source_event(ev, generated_at):
            mark_refused(ev, "stale_source")
            stale_count += 1
    if stale_count:
        hard_fail = True

    pre_sorted = sorted(
        events,
        key=lambda ev: (
            ev["event_ts"],
            ev["source_kind"],
            ev["source_thread_or_bead"],
            ev["event_kind"],
            ev["correlation_id"],
            ev["source_hash"],
        ),
    )
    deduped = []
    seen = set()
    duplicates = 0
    for ev in pre_sorted:
        key = (ev["source_hash"], ev["correlation_id"], ev["event_kind"])
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        deduped.append(ev)

    for index, ev in enumerate(deduped, start=1):
        ev["run_id"] = run_id
        ev["stable_sequence"] = f"{index:06d}"

    deduped = sorted(deduped, key=lambda ev: tuple(ev[key] for key in SORT_KEY))
    refused_count = sum(1 for ev in deduped if ev["redaction_verdict"] == "refused")
    if refused_count:
        hard_fail = True
    redacted_count = sum(1 for ev in deduped if ev["redaction_verdict"] == "redacted")
    pseudonymized_count = sum(1 for ev in deduped if ev["redaction_verdict"] == "pseudonymized")
    metadata_count = sum(1 for ev in deduped if ev["redaction_verdict"] == "metadata_only")
    source_hash = f"sha256:{hashlib.sha256(canonical(deduped).encode()).hexdigest()}"
    redaction_report = {
        "redacted_field_count": redacted_count,
        "pseudonymized_field_count": pseudonymized_count,
        "metadata_only_field_count": metadata_count,
        "refused_event_count": refused_count,
        "retained_field_summary": {
            "message_body_retained": False,
            "raw_paths_retained": False,
            "raw_worker_names_retained": False,
            "artifact_paths_hashed": True,
        },
    }
    bundle = {
        "schema_version": BUNDLE_VERSION,
        "run_id": run_id,
        "event_schema_version": EVENT_VERSION,
        "generated_at": generated_at,
        "source_bundle_hash": source_hash,
        "events": deduped,
        "duplicate_policy": {
            "dedupe_key": ["source_hash", "correlation_id", "event_kind"],
            "action": "dedupe_then_sort",
            "duplicate_event_count": duplicates,
        },
        "redaction_report": redaction_report,
        "runtime_workload_expansion_pack": {
            "pack_id": "agent-swarm-coordination-pressure",
            "baseline_denominator": False,
            "compatible_runner": "scripts/run_runtime_workload_corpus.sh",
            "source_collector": CONTRACT_VERSION,
        },
    }
    first_failure = ""
    for ev in deduped:
        if ev["refusal_reason"]:
            first_failure = f"{ev['correlation_id']} {ev['refusal_reason']}"
            break
    verdict = "fail_closed" if hard_fail else "pass"
    report = {
        "contract_version": CONTRACT_VERSION,
        "run_id": run_id,
        "generated_at": generated_at,
        "source_count": int(os.environ.get("COLLECTOR_SOURCE_COUNT", "0")),
        "accepted_event_count": len(deduped) - refused_count,
        "refused_event_count": refused_count,
        "duplicate_event_count": duplicates,
        "stale_source_event_count": stale_count,
        "adapter_count": len(ADAPTERS),
        "privacy_verdict": verdict,
        "first_failure_line": first_failure,
        "source_bundle_hash": source_hash,
        "artifact_paths": {},
    }

    out_dir = Path(output_root) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = out_dir / "coordination-workload-bundle.json"
    jsonl_path = out_dir / "coordination-workload-events.jsonl"
    report_path = out_dir / "coordination-collector-report.json"
    summary_path = out_dir / "coordination-collector.summary.txt"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    jsonl_path.write_text("".join(json.dumps(ev, sort_keys=True) + "\n" for ev in deduped), encoding="utf-8")
    report["artifact_paths"] = {
        "bundle": str(bundle_path),
        "events_jsonl": str(jsonl_path),
        "report": str(report_path),
        "summary": str(summary_path),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = (
        f"collector_result run_id={run_id} verdict={verdict} "
        f"accepted={report['accepted_event_count']} refused={refused_count} "
        f"duplicates={duplicates} bundle={bundle_path}\n"
    )
    summary_path.write_text(summary, encoding="utf-8")
    print(summary, end="")
    for path in [bundle_path, jsonl_path, report_path, summary_path]:
        print(f"artifact {path}")
    return 3 if hard_fail else 0


def main():
    mode = os.environ["COLLECTOR_MODE"]
    fixture = os.environ["COLLECTOR_FIXTURE"] == "1"
    output_root = os.environ["COLLECTOR_OUTPUT_ROOT"]
    run_id = os.environ["COLLECTOR_RUN_ID"] or (
        "coordination-collector-fixture" if fixture else "coordination-collector-run"
    )
    generated_at = os.environ["COLLECTOR_GENERATED_AT"] or DEFAULT_GENERATED_AT
    specs = [line for line in os.environ.get("COLLECTOR_SOURCE_SPECS", "").splitlines() if line]

    if mode == "list":
        print("collector agent-swarm-coordination-collector")
        print("modes list dry-run fixture execute")
        print("outputs bundle events_jsonl report summary")
        for adapter in ADAPTERS:
            print(f"adapter {adapter}")
        return 0

    if mode == "dry-run":
        print(f"collector_dry_run output_root={output_root} run_id={run_id} read_sources=false")
        for spec in specs:
            print(f"planned_source {spec}")
        if fixture:
            print("planned_fixture checked_synthetic_coordination_inputs")
        return 0

    if mode != "execute":
        print(f"unsupported mode: {mode}", file=sys.stderr)
        return 2

    if not fixture and not specs:
        print("execute requires --source or --fixture", file=sys.stderr)
        return 2

    inputs = []
    if fixture:
        for kind, data in fixture_sources():
            inputs.append((kind, (canonical(data), data, f"fixture:{kind}")))

    for spec in specs:
        if ":" not in spec:
            inputs.append(("unknown", {"path": spec, "error": "missing kind separator"}))
            continue
        kind, path = spec.split(":", 1)
        if kind not in ADAPTERS:
            inputs.append(("unknown", {"path": path, "error": f"unsupported kind {kind}"}))
            continue
        try:
            raw, data = load_json(path)
        except json.JSONDecodeError as exc:
            inputs.append((kind, {"path": path, "malformed_json": str(exc)}))
            continue
        except OSError as exc:
            inputs.append((kind, {"path": path, "read_error": str(exc)}))
            continue
        inputs.append((kind, (raw, data, path)))

    os.environ["COLLECTOR_SOURCE_COUNT"] = str(len(inputs))
    events = []
    hard_fail = False
    for kind, payload in inputs:
        if kind == "unknown":
            events.append(refused("unknown", str(payload.get("path", "unknown")), "unsupported_source_kind", payload.get("error", "")))
            hard_fail = True
            continue
        if isinstance(payload, dict) and "malformed_json" in payload:
            events.append(refused(kind, str(payload["path"]), "unknown_schema_version", payload["malformed_json"]))
            hard_fail = True
            continue
        if isinstance(payload, dict) and "read_error" in payload:
            events.append(refused(kind, str(payload["path"]), "missing_required_field", payload["read_error"]))
            hard_fail = True
            continue
        raw, data, path = payload
        if contains_secret(raw):
            events.append(refused(kind, path, "unredacted_secret", "source-secret-detected"))
            hard_fail = True
            continue
        events.extend(collect_from_kind(kind, raw, data, path))

    return materialize(events, output_root, run_id, generated_at, hard_fail)


if __name__ == "__main__":
    sys.exit(main())
PY
