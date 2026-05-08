#!/usr/bin/env python3
"""
Operator proof-lane dashboard - machine-readable proof-lane status model

Ingests artifacts/proof_lane_manifest_v1.json, proof status snapshots, and command results
to build a comprehensive view of asupersync runtime proof status.

Usage:
  python3 scripts/operator_proof_lane_dashboard.py [--format=json|table|summary] [--category=all|production|fuzz|rustdoc|formal|blockers]
  python3 scripts/operator_proof_lane_dashboard.py --execute-lane <lane_id>
  python3 scripts/operator_proof_lane_dashboard.py --validate-all
"""

import json
import sys
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse

@dataclass
class LaneStatus:
    lane_id: str
    kind: str
    command: str
    status: str  # 'green', 'yellow_frontier', 'yellow_scoped', 'red_blocked_external', 'unknown'
    last_executed: Optional[str] = None
    execution_result: Optional[str] = None
    execution_duration_ms: Optional[int] = None
    guarantee_ids: List[str] = None
    covers: str = ""
    explicit_not_covered: str = ""
    expected_signal: str = ""
    common_blockers: List[str] = None
    escalation_notes: str = ""
    blocker_evidence: Optional[Dict[str, Any]] = None

@dataclass
class GuaranteeStatus:
    guarantee_id: str
    description: str
    status: str
    lane_statuses: List[str]
    proof_commands: List[str]

@dataclass
class ProofDashboard:
    timestamp: str
    manifest_version: str
    snapshot_version: str
    summary: Dict[str, int]
    production_graph_proofs: List[LaneStatus]
    fuzz_smoke_evidence: List[LaneStatus]
    rustdoc_frontier: List[LaneStatus]
    formal_proof_evidence: List[LaneStatus]
    quality_gates: List[LaneStatus]
    known_blockers: List[Dict[str, Any]]
    guarantees: List[GuaranteeStatus]
    lane_coverage: Dict[str, LaneStatus]

def load_manifest() -> Dict[str, Any]:
    """Load proof lane manifest"""
    manifest_path = Path("artifacts/proof_lane_manifest_v1.json")
    if not manifest_path.exists():
        raise FileNotFoundError(f"Proof lane manifest not found: {manifest_path}")

    with open(manifest_path) as f:
        return json.load(f)

def load_proof_status_snapshot() -> Dict[str, Any]:
    """Load most recent proof status snapshot"""
    snapshot_path = Path("artifacts/proof_status_snapshot_v1.json")
    if not snapshot_path.exists():
        raise FileNotFoundError(f"Proof status snapshot not found: {snapshot_path}")

    with open(snapshot_path) as f:
        return json.load(f)

def execute_lane_command(command: str, timeout: int = 300) -> Tuple[int, str, int]:
    """Execute a proof lane command and return (exit_code, output, duration_ms)"""
    print(f"Executing: {command}", file=sys.stderr)
    start_time = datetime.now()

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=Path.cwd()
        )
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        return result.returncode, result.stdout + result.stderr, duration_ms
    except subprocess.TimeoutExpired:
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        return 124, f"Command timed out after {timeout}s", duration_ms
    except Exception as e:
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        return 1, f"Execution failed: {e}", duration_ms

def categorize_lane(lane: Dict[str, Any]) -> str:
    """Categorize a lane by its kind and purpose"""
    kind = lane.get("kind", "unknown")
    lane_id = lane.get("lane_id", "")

    if kind == "dependency_graph" and "tokio" in lane_id:
        return "production"
    elif kind in ["compile_frontier", "test_frontier"] and "fuzz" in lane_id:
        return "fuzz"
    elif kind == "documentation_frontier":
        return "rustdoc"
    elif kind == "formal_frontier":
        return "formal"
    elif kind in ["lint_frontier", "format_frontier", "compile_frontier", "test_frontier"]:
        return "quality"
    else:
        return "other"

def map_execution_to_status(exit_code: int, output: str, expected_signal: str) -> str:
    """Map command execution result to proof status"""
    if exit_code == 0:
        if "warning: nothing to print" in output and "nothing to print" in expected_signal:
            return "green"
        elif "Build completed successfully" in output and "Build completed successfully" in expected_signal:
            return "green"
        elif exit_code == 0 and "exits 0" in expected_signal:
            return "green"
        else:
            return "yellow_frontier"  # Passed but may need verification
    else:
        return "red_blocked_external"

def build_dashboard(execute_commands: bool = False, validate_all: bool = False) -> ProofDashboard:
    """Build the complete proof dashboard"""
    manifest = load_manifest()
    snapshot = load_proof_status_snapshot()

    timestamp = datetime.now().isoformat()

    # Map claim statuses from snapshot
    claim_statuses = {}
    for claim in snapshot.get("claim_categories", []):
        claim_id = claim.get("claim_id")
        status = claim.get("status", "unknown")
        proof_commands = claim.get("proof_commands", [])
        blocked_frontier = claim.get("blocked_frontier")
        claim_statuses[claim_id] = {
            "status": status,
            "proof_commands": proof_commands,
            "blocked_frontier": blocked_frontier
        }

    # Build lane statuses
    lane_coverage = {}
    production_proofs = []
    fuzz_evidence = []
    rustdoc_frontier = []
    formal_evidence = []
    quality_gates = []
    known_blockers = []

    for lane in manifest.get("lanes", []):
        lane_id = lane.get("lane_id")
        command = lane.get("command", "")
        kind = lane.get("kind", "unknown")
        category = categorize_lane(lane)

        # Determine status from snapshot mapping or execution
        status = "unknown"
        execution_result = None
        execution_duration_ms = None
        last_executed = None

        if execute_commands or validate_all:
            exit_code, output, duration = execute_lane_command(command)
            status = map_execution_to_status(exit_code, output, lane.get("expected_signal", ""))
            execution_result = f"exit_code={exit_code}, output_length={len(output)}"
            execution_duration_ms = duration
            last_executed = datetime.now().isoformat()

            if exit_code != 0:
                known_blockers.append({
                    "lane_id": lane_id,
                    "command": command,
                    "exit_code": exit_code,
                    "output_preview": output[:200] + "..." if len(output) > 200 else output,
                    "timestamp": last_executed
                })
        else:
            # Try to infer status from snapshot claims
            for claim_id, claim_info in claim_statuses.items():
                if command in claim_info.get("proof_commands", []):
                    status = claim_info["status"]
                    if claim_info.get("blocked_frontier"):
                        known_blockers.append(claim_info["blocked_frontier"])
                    break

        lane_status = LaneStatus(
            lane_id=lane_id,
            kind=kind,
            command=command,
            status=status,
            last_executed=last_executed,
            execution_result=execution_result,
            execution_duration_ms=execution_duration_ms,
            guarantee_ids=lane.get("guarantee_ids", []),
            covers=lane.get("covers", ""),
            explicit_not_covered=lane.get("explicit_not_covered", ""),
            expected_signal=lane.get("expected_signal", ""),
            common_blockers=lane.get("common_unrelated_blockers", []),
            escalation_notes=lane.get("escalation_notes", "")
        )

        lane_coverage[lane_id] = lane_status

        # Categorize for dashboard sections
        if category == "production":
            production_proofs.append(lane_status)
        elif category == "fuzz":
            fuzz_evidence.append(lane_status)
        elif category == "rustdoc":
            rustdoc_frontier.append(lane_status)
        elif category == "formal":
            formal_evidence.append(lane_status)
        elif category == "quality":
            quality_gates.append(lane_status)

    # Build guarantee statuses
    guarantees = []
    for guarantee in manifest.get("guarantees", []):
        guarantee_id = guarantee.get("guarantee_id")
        lane_ids = guarantee.get("lane_ids", [])
        lane_statuses = [lane_coverage.get(lid, LaneStatus("unknown", "unknown", "", "unknown")).status for lid in lane_ids]

        # Determine overall guarantee status
        if all(s == "green" for s in lane_statuses):
            guarantee_status = "green"
        elif any(s == "red_blocked_external" for s in lane_statuses):
            guarantee_status = "red_blocked_external"
        elif any(s == "yellow_frontier" for s in lane_statuses):
            guarantee_status = "yellow_frontier"
        else:
            guarantee_status = "unknown"

        # Find proof commands for this guarantee
        proof_commands = []
        for lane_id in lane_ids:
            if lane_id in lane_coverage:
                proof_commands.append(lane_coverage[lane_id].command)

        guarantees.append(GuaranteeStatus(
            guarantee_id=guarantee_id,
            description=guarantee.get("description", ""),
            status=guarantee_status,
            lane_statuses=lane_statuses,
            proof_commands=proof_commands
        ))

    # Build summary
    summary = {
        "total_lanes": len(lane_coverage),
        "green": sum(1 for ls in lane_coverage.values() if ls.status == "green"),
        "yellow_frontier": sum(1 for ls in lane_coverage.values() if ls.status == "yellow_frontier"),
        "yellow_scoped": sum(1 for ls in lane_coverage.values() if ls.status == "yellow_scoped"),
        "red_blocked": sum(1 for ls in lane_coverage.values() if ls.status == "red_blocked_external"),
        "unknown": sum(1 for ls in lane_coverage.values() if ls.status == "unknown"),
        "total_guarantees": len(guarantees),
        "guarantees_green": sum(1 for g in guarantees if g.status == "green"),
        "guarantees_red": sum(1 for g in guarantees if g.status == "red_blocked_external")
    }

    return ProofDashboard(
        timestamp=timestamp,
        manifest_version=manifest.get("contract_version", "unknown"),
        snapshot_version=snapshot.get("contract_version", "unknown"),
        summary=summary,
        production_graph_proofs=production_proofs,
        fuzz_smoke_evidence=fuzz_evidence,
        rustdoc_frontier=rustdoc_frontier,
        formal_proof_evidence=formal_evidence,
        quality_gates=quality_gates,
        known_blockers=known_blockers,
        guarantees=guarantees,
        lane_coverage=lane_coverage
    )

def format_table_output(dashboard: ProofDashboard, category: str = "all") -> str:
    """Format dashboard as human-readable table"""
    lines = []
    lines.append(f"# Asupersync Proof Lane Dashboard - {dashboard.timestamp}")
    lines.append("")

    # Summary
    s = dashboard.summary
    lines.append("## Summary")
    lines.append(f"Total lanes: {s['total_lanes']} | Green: {s['green']} | Yellow: {s['yellow_frontier'] + s['yellow_scoped']} | Red: {s['red_blocked']} | Unknown: {s['unknown']}")
    lines.append(f"Total guarantees: {s['total_guarantees']} | Green: {s['guarantees_green']} | Red: {s['guarantees_red']}")
    lines.append("")

    # Category sections
    sections = []
    if category in ["all", "production"]:
        sections.append(("Production Graph Proofs", dashboard.production_graph_proofs))
    if category in ["all", "fuzz"]:
        sections.append(("Fuzz Smoke Evidence", dashboard.fuzz_smoke_evidence))
    if category in ["all", "rustdoc"]:
        sections.append(("Rustdoc Frontier", dashboard.rustdoc_frontier))
    if category in ["all", "formal"]:
        sections.append(("Formal Proof Evidence", dashboard.formal_proof_evidence))
    if category in ["all", "quality"]:
        sections.append(("Quality Gates", dashboard.quality_gates))
    if category in ["all", "blockers"] and dashboard.known_blockers:
        sections.append(("Known Blockers", dashboard.known_blockers))

    for section_name, items in sections:
        if not items:
            continue

        lines.append(f"## {section_name}")

        if section_name == "Known Blockers":
            for blocker in items:
                if isinstance(blocker, dict):
                    lines.append(f"- {blocker.get('lane_id', 'unknown')}: {blocker.get('command', '')[:60]}...")
                    lines.append(f"  Exit: {blocker.get('exit_code', 'unknown')} | {blocker.get('timestamp', 'unknown')}")
        else:
            for item in items:
                status_indicator = "✅" if item.status == "green" else "🟡" if item.status.startswith("yellow") else "❌" if item.status.startswith("red") else "❓"
                lines.append(f"{status_indicator} {item.lane_id} ({item.kind})")
                lines.append(f"   {item.covers[:80]}...")
                if item.last_executed:
                    lines.append(f"   Last run: {item.last_executed} ({item.execution_duration_ms}ms)")
        lines.append("")

    return "\n".join(lines)

def format_summary_output(dashboard: ProofDashboard) -> str:
    """Format dashboard as brief summary"""
    s = dashboard.summary
    status = "🟢 HEALTHY" if s["red_blocked"] == 0 and s["unknown"] < 3 else "🟡 DEGRADED" if s["red_blocked"] < 3 else "🔴 BLOCKED"

    return f"""Asupersync Proof Status: {status}
Lanes: {s['green']} green, {s['yellow_frontier'] + s['yellow_scoped']} yellow, {s['red_blocked']} red, {s['unknown']} unknown
Guarantees: {s['guarantees_green']}/{s['total_guarantees']} green
Blockers: {len(dashboard.known_blockers)}
Updated: {dashboard.timestamp}"""

def main():
    parser = argparse.ArgumentParser(description="Asupersync proof lane dashboard")
    parser.add_argument("--format", choices=["json", "table", "summary"], default="table",
                       help="Output format")
    parser.add_argument("--category", choices=["all", "production", "fuzz", "rustdoc", "formal", "quality", "blockers"],
                       default="all", help="Filter by category")
    parser.add_argument("--execute-lane", help="Execute a specific lane command")
    parser.add_argument("--validate-all", action="store_true",
                       help="Execute all lane commands to get live status")

    args = parser.parse_args()

    try:
        if args.execute_lane:
            # Execute specific lane
            manifest = load_manifest()
            lane = None
            for l in manifest.get("lanes", []):
                if l.get("lane_id") == args.execute_lane:
                    lane = l
                    break

            if not lane:
                print(f"Lane not found: {args.execute_lane}", file=sys.stderr)
                sys.exit(1)

            command = lane.get("command", "")
            exit_code, output, duration = execute_lane_command(command)

            print(f"Lane: {args.execute_lane}")
            print(f"Command: {command}")
            print(f"Exit code: {exit_code}")
            print(f"Duration: {duration}ms")
            print(f"Output:\n{output}")

            sys.exit(exit_code)

        # Build dashboard
        dashboard = build_dashboard(validate_all=args.validate_all)

        if args.format == "json":
            # Convert to dict for JSON serialization
            dashboard_dict = asdict(dashboard)
            print(json.dumps(dashboard_dict, indent=2, ensure_ascii=False))
        elif args.format == "summary":
            print(format_summary_output(dashboard))
        else:  # table
            print(format_table_output(dashboard, args.category))

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()