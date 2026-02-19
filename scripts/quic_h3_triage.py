#!/usr/bin/env python3
"""QH3-L3 triage helper: parse QuicH3ScenarioManifest JSON and print
human-readable reports, or list all scenarios from the replay catalog.

Usage:
    python3 scripts/quic_h3_triage.py manifest.json       # triage a single manifest
    python3 scripts/quic_h3_triage.py --catalog            # list all catalog entries
    python3 scripts/quic_h3_triage.py --catalog --verbose  # catalog with repro commands

No external dependencies -- stdlib only (json, sys, argparse, os).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


# ============================================================================
# Constants
# ============================================================================

_CATALOG_PATH = Path(__file__).resolve().parent.parent / "artifacts" / "quic_h3_replay_catalog_v1.json"

_SEPARATOR = "=" * 72
_THIN_SEP = "-" * 72


# ============================================================================
# Manifest triage
# ============================================================================

def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON file and return the parsed dict."""
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def fmt_us(us: int | None) -> str:
    """Format a microsecond value as a human-readable string."""
    if us is None:
        return "n/a"
    if us < 1_000:
        return f"{us}us"
    if us < 1_000_000:
        return f"{us / 1_000:.1f}ms"
    return f"{us / 1_000_000:.3f}s"


def fmt_bytes(b: int) -> str:
    """Format a byte count as a human-readable string."""
    if b < 1024:
        return f"{b}B"
    if b < 1024 * 1024:
        return f"{b / 1024:.1f}KB"
    return f"{b / (1024 * 1024):.2f}MB"


def print_manifest_report(manifest: dict[str, Any]) -> str:
    """Build a human-readable triage report from a scenario manifest dict."""
    lines: list[str] = []

    # -- Header --
    lines.append(_SEPARATOR)
    lines.append("QUIC/H3 SCENARIO TRIAGE REPORT")
    lines.append(_SEPARATOR)
    lines.append("")

    scenario_id = manifest.get("scenario_id", "UNKNOWN")
    seed = manifest.get("seed", "?")
    passed = manifest.get("passed", False)
    duration_us = manifest.get("duration_us", 0)
    failure_class = manifest.get("failure_class", "unknown")
    status_str = "PASS" if passed else "FAIL"

    lines.append(f"  Scenario:       {scenario_id}")
    lines.append(f"  Seed:           {seed}")
    lines.append(f"  Status:         {status_str}")
    lines.append(f"  Failure class:  {failure_class}")
    lines.append(f"  Duration:       {fmt_us(duration_us)}")
    lines.append(f"  Schema:         {manifest.get('schema_id', 'n/a')} v{manifest.get('schema_version', '?')}")
    lines.append(f"  Trace FP:       {manifest.get('trace_fingerprint', 'n/a')}")
    lines.append("")

    # -- Replay command --
    replay_cmd = manifest.get("replay_command", "")
    if replay_cmd:
        lines.append(_THIN_SEP)
        lines.append("REPLAY COMMAND")
        lines.append(_THIN_SEP)
        lines.append(f"  {replay_cmd}")
        lines.append("")

    # -- Transport summary --
    transport = manifest.get("transport_summary")
    if transport:
        lines.append(_THIN_SEP)
        lines.append("TRANSPORT SUMMARY")
        lines.append(_THIN_SEP)
        lines.append(f"  Packets sent:    {transport.get('packets_sent', 0)}")
        lines.append(f"  Packets acked:   {transport.get('packets_acked', 0)}")
        lines.append(f"  Packets lost:    {transport.get('packets_lost', 0)}")
        lines.append(f"  Bytes sent:      {fmt_bytes(transport.get('bytes_sent', 0))}")
        lines.append(f"  Bytes acked:     {fmt_bytes(transport.get('bytes_acked', 0))}")
        lines.append(f"  Bytes lost:      {fmt_bytes(transport.get('bytes_lost', 0))}")
        lines.append(f"  Smoothed RTT:    {fmt_us(transport.get('smoothed_rtt_us'))}")
        lines.append(f"  Min RTT:         {fmt_us(transport.get('min_rtt_us'))}")
        lines.append(f"  CWND:            {fmt_bytes(transport.get('cwnd', 0))}")
        ssthresh = transport.get("ssthresh", 0)
        ssthresh_str = "inf (slow start)" if ssthresh == 18446744073709551615 else fmt_bytes(ssthresh)
        lines.append(f"  SSThresh:        {ssthresh_str}")
        lines.append(f"  PTO count:       {transport.get('pto_count', 0)}")
        lines.append(f"  Final state:     {transport.get('final_state', 'unknown')}")
        lines.append("")

    # -- H3 summary --
    h3 = manifest.get("h3_summary")
    if h3:
        lines.append(_THIN_SEP)
        lines.append("H3 SUMMARY")
        lines.append(_THIN_SEP)
        lines.append(f"  Requests sent:       {h3.get('requests_sent', 0)}")
        lines.append(f"  Responses received:  {h3.get('responses_received', 0)}")
        lines.append(f"  Streams opened:      {h3.get('streams_opened', 0)}")
        lines.append(f"  Streams reset:       {h3.get('streams_reset', 0)}")
        goaway_id = h3.get("goaway_id")
        lines.append(f"  GOAWAY ID:           {goaway_id if goaway_id is not None else 'none'}")
        lines.append(f"  Settings exchanged:  {h3.get('settings_exchanged', False)}")
        lines.append(f"  Protocol errors:     {h3.get('protocol_errors', 0)}")
        lines.append("")

    # -- Invariant verdicts --
    verdicts = manifest.get("invariant_verdicts", [])
    if verdicts:
        lines.append(_THIN_SEP)
        lines.append("INVARIANT VERDICTS")
        lines.append(_THIN_SEP)
        for v in verdicts:
            inv_id = v.get("invariant_id", "?")
            verdict = v.get("verdict", "?")
            details = v.get("details", "")
            icon = {"pass": "[PASS]", "fail": "[FAIL]", "skip": "[SKIP]"}.get(
                verdict, f"[{verdict.upper()}]"
            )
            lines.append(f"  {icon} {inv_id}")
            if details:
                lines.append(f"         {details}")
        lines.append("")

    # -- Failure fingerprint --
    fp = manifest.get("failure_fingerprint")
    if fp:
        lines.append(_THIN_SEP)
        lines.append("FAILURE FINGERPRINT")
        lines.append(_THIN_SEP)
        lines.append(f"  Bucket:          {fp.get('bucket', 'unknown')}")
        assertion = fp.get("assertion")
        if assertion:
            lines.append(f"  Assertion:       {assertion}")
        bt_hash = fp.get("backtrace_hash")
        if bt_hash:
            lines.append(f"  Backtrace hash:  {bt_hash}")
        last_event = fp.get("last_event_before_failure")
        if last_event:
            lines.append(f"  Last event:      {json.dumps(last_event, separators=(',', ':'))}")
        lines.append("")

    # -- Connection lifecycle timeline --
    lifecycle = manifest.get("connection_lifecycle", [])
    if lifecycle:
        lines.append(_THIN_SEP)
        lines.append("CONNECTION LIFECYCLE TIMELINE")
        lines.append(_THIN_SEP)
        for transition in lifecycle:
            from_s = transition.get("from_state", "?")
            to_s = transition.get("to_state", "?")
            ts = transition.get("ts_us", 0)
            trigger = transition.get("trigger", "?")
            lines.append(f"  [{fmt_us(ts):>10s}] {from_s} -> {to_s}  (trigger: {trigger})")
        lines.append("")

    # -- Event timeline --
    timeline = manifest.get("event_timeline")
    if timeline:
        lines.append(_THIN_SEP)
        lines.append("EVENT TIMELINE")
        lines.append(_THIN_SEP)
        lines.append(f"  Total events:  {timeline.get('total_events', 0)}")
        by_cat = timeline.get("by_category", {})
        if by_cat:
            lines.append("  By category:")
            for cat, count in sorted(by_cat.items()):
                lines.append(f"    {cat}: {count}")
        by_lvl = timeline.get("by_level", {})
        if by_lvl:
            lines.append("  By level:")
            for lvl, count in sorted(by_lvl.items()):
                lines.append(f"    {lvl}: {count}")
        lines.append("")

    # -- Profile tags --
    tags = manifest.get("profile_tags", [])
    if tags:
        lines.append(f"  Profile tags: {', '.join(tags)}")
        lines.append("")

    # -- Artifact paths --
    artifacts = manifest.get("artifact_paths", [])
    if artifacts:
        lines.append(_THIN_SEP)
        lines.append("ARTIFACT PATHS")
        lines.append(_THIN_SEP)
        for p in artifacts:
            lines.append(f"  {p}")
        lines.append("")

    lines.append(_SEPARATOR)

    return "\n".join(lines)


# ============================================================================
# Catalog listing
# ============================================================================

def print_catalog(verbose: bool = False) -> str:
    """Load the replay catalog and build a human-readable listing."""
    if not _CATALOG_PATH.exists():
        return f"ERROR: catalog not found at {_CATALOG_PATH}"

    catalog = load_json(_CATALOG_PATH)
    entries = catalog.get("entries", [])

    lines: list[str] = []
    lines.append(_SEPARATOR)
    lines.append(f"QUIC/H3 REPLAY CATALOG ({len(entries)} scenarios)")
    lines.append(f"  Schema:  {catalog.get('schema_version', '?')}")
    lines.append(f"  Generated: {catalog.get('generated_at_utc', '?')}")
    lines.append(_SEPARATOR)
    lines.append("")

    # Group entries by test file.
    by_file: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        test_files = entry.get("test_files", ["unknown"])
        for tf in test_files:
            by_file.setdefault(tf, []).append(entry)

    for tf in sorted(by_file.keys()):
        file_entries = by_file[tf]
        lines.append(_THIN_SEP)
        lines.append(f"  {tf} ({len(file_entries)} tests)")
        lines.append(_THIN_SEP)

        for entry in file_entries:
            funcs = entry.get("test_functions", [])
            func_str = ", ".join(funcs) if funcs else "?"
            tags = entry.get("profile_tags", [])
            tag_str = ", ".join(tags) if tags else "-"
            seed = entry.get("seed", "?")
            outcome = entry.get("expected_outcome", "?")

            lines.append(f"  {entry.get('scenario_id', '?')}")
            lines.append(f"    Function:  {func_str}")
            lines.append(f"    Seed:      {seed}")
            lines.append(f"    Outcome:   {outcome}")
            lines.append(f"    Tags:      {tag_str}")

            if verbose:
                repro_cmd = entry.get("repro_cmd", "")
                if repro_cmd:
                    lines.append(f"    Repro:     {repro_cmd}")

            lines.append("")

    lines.append(_SEPARATOR)
    lines.append(f"Total: {len(entries)} entries across {len(by_file)} test files")
    lines.append(_SEPARATOR)

    return "\n".join(lines)


# ============================================================================
# CLI
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="QH3-L3 triage helper: parse manifest JSON or list catalog scenarios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 scripts/quic_h3_triage.py manifest.json\n"
            "  python3 scripts/quic_h3_triage.py --catalog\n"
            "  python3 scripts/quic_h3_triage.py --catalog --verbose\n"
        ),
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        default=None,
        help="Path to a QuicH3ScenarioManifest JSON file to triage.",
    )
    parser.add_argument(
        "--catalog",
        action="store_true",
        help="List all scenarios from the replay catalog.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include repro commands in catalog listing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.catalog:
        report = print_catalog(verbose=args.verbose)
        print(report)
        return 0

    if args.manifest is None:
        parser.print_help()
        return 1

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"ERROR: manifest file not found: {manifest_path}", file=sys.stderr)
        return 1

    manifest = load_json(manifest_path)
    report = print_manifest_report(manifest)
    print(report)
    return 0


# ============================================================================
# Smoke test
# ============================================================================

def test_triage_output() -> None:
    """Smoke test: build a sample manifest dict and verify the triage report
    contains the expected sections."""
    sample_manifest = {
        "schema_id": "quic-h3-forensic-manifest.v1",
        "schema_version": 1,
        "scenario_id": "QH3-TEST-SMOKE",
        "seed": "0x00000000DEADBEEF",
        "config_hash": "",
        "trace_fingerprint": "abcdef0123456789",
        "replay_command": "ASUPERSYNC_SEED=0xDEADBEEF cargo test test_smoke -- --nocapture",
        "failure_class": "passed",
        "invariant_ids": ["inv.quic.handshake_completes", "inv.quic.rtt_positive"],
        "invariant_verdicts": [
            {
                "invariant_id": "inv.quic.handshake_completes",
                "verdict": "pass",
                "details": "Both endpoints reached Established",
            },
            {
                "invariant_id": "inv.quic.rtt_positive",
                "verdict": "pass",
                "details": "smoothed_rtt=20000us",
            },
        ],
        "artifact_paths": [],
        "event_timeline": {
            "total_events": 12,
            "by_category": {"quic_transport": 4, "quic_connection": 2, "h3_request": 2, "test_harness": 4},
            "by_level": {"INFO": 8, "DEBUG": 4},
        },
        "transport_summary": {
            "packets_sent": 5,
            "packets_acked": 4,
            "packets_lost": 1,
            "bytes_sent": 6000,
            "bytes_acked": 4800,
            "bytes_lost": 1200,
            "smoothed_rtt_us": 20000,
            "min_rtt_us": 18000,
            "cwnd": 15920,
            "ssthresh": 18446744073709551615,
            "pto_count": 0,
            "final_state": "established",
        },
        "h3_summary": {
            "requests_sent": 1,
            "responses_received": 1,
            "streams_opened": 2,
            "streams_reset": 0,
            "goaway_id": None,
            "settings_exchanged": True,
            "protocol_errors": 0,
        },
        "connection_lifecycle": [
            {"from_state": "idle", "to_state": "handshaking", "ts_us": 100, "trigger": "begin_handshake"},
            {"from_state": "handshaking", "to_state": "established", "ts_us": 5000, "trigger": "handshake_confirmed"},
        ],
        "failure_fingerprint": None,
        "passed": True,
        "duration_us": 1100000,
        "profile_tags": ["fast", "happy-path"],
    }

    report = print_manifest_report(sample_manifest)

    # Verify key sections are present.
    assert "QUIC/H3 SCENARIO TRIAGE REPORT" in report, "missing report header"
    assert "QH3-TEST-SMOKE" in report, "missing scenario_id"
    assert "0x00000000DEADBEEF" in report, "missing seed"
    assert "PASS" in report, "missing status"
    assert "TRANSPORT SUMMARY" in report, "missing transport summary"
    assert "H3 SUMMARY" in report, "missing h3 summary"
    assert "INVARIANT VERDICTS" in report, "missing invariant verdicts"
    assert "[PASS] inv.quic.handshake_completes" in report, "missing invariant verdict detail"
    assert "REPLAY COMMAND" in report, "missing replay command section"
    assert "CONNECTION LIFECYCLE TIMELINE" in report, "missing lifecycle timeline"
    assert "idle -> handshaking" in report, "missing lifecycle transition"
    assert "EVENT TIMELINE" in report, "missing event timeline"
    assert "Packets sent:    5" in report, "missing packet count"
    assert "20.0ms" in report, "missing RTT formatting"
    assert "FAILURE FINGERPRINT" not in report, "should not have fingerprint on pass"

    # Verify a failing manifest includes failure fingerprint.
    fail_manifest = dict(sample_manifest)
    fail_manifest["passed"] = False
    fail_manifest["failure_class"] = "assertion_failure"
    fail_manifest["failure_fingerprint"] = {
        "bucket": "assertion_failure",
        "assertion": "expected 42 got 43",
        "backtrace_hash": None,
        "last_event_before_failure": {"type": "PacketSent", "pn_space": "initial"},
    }

    fail_report = print_manifest_report(fail_manifest)
    assert "FAIL" in fail_report, "missing FAIL status"
    assert "FAILURE FINGERPRINT" in fail_report, "missing failure fingerprint"
    assert "assertion_failure" in fail_report, "missing failure bucket"
    assert "expected 42 got 43" in fail_report, "missing assertion text"

    # Verify catalog listing (if catalog file exists).
    if _CATALOG_PATH.exists():
        catalog_report = print_catalog(verbose=False)
        assert "QUIC/H3 REPLAY CATALOG" in catalog_report, "missing catalog header"
        assert "72 scenarios" in catalog_report, "missing correct entry count"

        verbose_report = print_catalog(verbose=True)
        assert "Repro:" in verbose_report, "verbose catalog should include repro commands"

    print("All smoke tests passed.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        test_triage_output()
    else:
        sys.exit(main())
