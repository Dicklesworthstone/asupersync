#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# generate_verification_summary.sh — SEM-12.10
#
# Produces a human-readable verification summary and triage report from
# the unified runner report, evidence bundle, and gate evaluation data.
#
# Inputs (auto-discovered or via flags):
#   --runner-report   path to verification_report.json
#   --evidence-bundle path to evidence_bundle.json
#   --gate-manifest   path to bundle_manifest.json
#   --output-dir      directory for generated summary (default: target/verification-summary)
#   --json            also emit machine-readable JSON summary
#   --ci              strict mode (non-zero exit on failures)
#   --verbose         show per-rule detail
#
# Outputs:
#   <output-dir>/verification_summary.md   human-readable report
#   <output-dir>/verification_summary.json  machine-readable summary (with --json)
#   <output-dir>/triage_report.md           failure triage with root-cause hints
#
# Exit codes:
#   0 — summary generated, no critical failures
#   1 — summary generated, critical failures present (CI mode)
#   2 — configuration/input error
#
# Bead: asupersync-3cddg.12.10
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNNER_REPORT=""
EVIDENCE_BUNDLE=""
GATE_MANIFEST=""
OUTPUT_DIR="${PROJECT_ROOT}/target/verification-summary"
JSON_OUTPUT=false
CI_MODE=false
VERBOSE=false

# ─── Argument parsing ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --runner-report)  RUNNER_REPORT="$2";   shift 2 ;;
        --evidence-bundle) EVIDENCE_BUNDLE="$2"; shift 2 ;;
        --gate-manifest)  GATE_MANIFEST="$2";   shift 2 ;;
        --output-dir)     OUTPUT_DIR="$2";       shift 2 ;;
        --json)           JSON_OUTPUT=true;      shift ;;
        --ci)             CI_MODE=true;          shift ;;
        --verbose)        VERBOSE=true;          shift ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

# ─── Auto-discover inputs ───────────────────────────────────────────
if [[ -z "$RUNNER_REPORT" ]]; then
    RUNNER_REPORT="${PROJECT_ROOT}/target/semantic-verification/verification_report.json"
fi
if [[ -z "$EVIDENCE_BUNDLE" ]]; then
    EVIDENCE_BUNDLE="${PROJECT_ROOT}/target/semantic-readiness/evidence_bundle.json"
fi
if [[ -z "$GATE_MANIFEST" ]]; then
    GATE_MANIFEST="${PROJECT_ROOT}/target/evidence-bundle/metadata/bundle_manifest.json"
fi

# Validate required inputs
MISSING_INPUTS=()
if [[ ! -f "$RUNNER_REPORT" ]]; then
    MISSING_INPUTS+=("runner report: $RUNNER_REPORT")
fi
if [[ ! -f "$EVIDENCE_BUNDLE" ]]; then
    MISSING_INPUTS+=("evidence bundle: $EVIDENCE_BUNDLE")
fi

if [[ ${#MISSING_INPUTS[@]} -gt 0 ]]; then
    echo "[verification-summary] ERROR: Missing required inputs:" >&2
    for m in "${MISSING_INPUTS[@]}"; do
        echo "  - $m" >&2
    done
    echo "" >&2
    echo "Run these first:" >&2
    echo "  scripts/run_semantic_verification.sh --profile full --json" >&2
    echo "  scripts/build_semantic_evidence_bundle.sh --report <path> --output <path>" >&2
    exit 2
fi

mkdir -p "$OUTPUT_DIR"

TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT_HASH=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")

log() { echo "[verification-summary] $(date -u '+%H:%M:%S') $*"; }
log "Generating verification summary (commit: $COMMIT_HASH)"

# ─── Generate summary via embedded Python ────────────────────────────
python3 - "$RUNNER_REPORT" "$EVIDENCE_BUNDLE" "$GATE_MANIFEST" \
          "$OUTPUT_DIR" "$TIMESTAMP" "$COMMIT_HASH" \
          "$JSON_OUTPUT" "$VERBOSE" <<'PYTHON_SCRIPT'
import json
import sys
import os
from collections import defaultdict

runner_path = sys.argv[1]
bundle_path = sys.argv[2]
gate_path   = sys.argv[3]
output_dir  = sys.argv[4]
timestamp   = sys.argv[5]
commit_hash = sys.argv[6]
json_output = sys.argv[7] == "true"
verbose     = sys.argv[8] == "true"

# ── Load data ────────────────────────────────────────────────────────
with open(runner_path) as f:
    runner = json.load(f)

with open(bundle_path) as f:
    bundle = json.load(f)

gate_manifest = None
if os.path.isfile(gate_path):
    with open(gate_path) as f:
        gate_manifest = json.load(f)

# ── Domain metadata ─────────────────────────────────────────────────
DOMAIN_ORDER = [
    "cancellation", "obligation", "region", "outcome",
    "ownership", "combinator", "capability", "determinism"
]

DOMAIN_LABELS = {
    "cancellation": "Cancellation",
    "obligation":   "Obligation Lifecycle",
    "region":       "Region Lifecycle",
    "outcome":      "Outcome Algebra",
    "ownership":    "Ownership Model",
    "combinator":   "Combinators",
    "capability":   "Capability Security",
    "determinism":  "Determinism & Replay",
}

# ── Aggregate per-domain stats ──────────────────────────────────────
domain_stats = defaultdict(lambda: {
    "total": 0, "with_gaps": 0, "rules": [],
    "evidence_present": defaultdict(int),
    "evidence_missing": defaultdict(int),
    "tiers": defaultdict(int),
})

rules = bundle.get("traceability", {}).get("rules", [])
for rule in rules:
    d = rule["domain"]
    ds = domain_stats[d]
    ds["total"] += 1
    ds["tiers"][rule.get("tier", "?")] += 1
    missing = rule.get("missing_classes", [])
    if missing:
        ds["with_gaps"] += 1
    for cls in rule.get("required_classes", []):
        if cls in missing:
            ds["evidence_missing"][cls] += 1
        else:
            ds["evidence_present"][cls] += 1
    ds["rules"].append(rule)

# ── Suite results ───────────────────────────────────────────────────
suite_results = runner.get("results", [])
suites_passed = runner.get("suites_passed", 0)
suites_failed = runner.get("suites_failed", 0)
suites_total  = runner.get("suites_total", 0)
overall_status = runner.get("overall_status", "unknown")

# ── Gate results ────────────────────────────────────────────────────
gates = {}
if gate_manifest:
    gates = gate_manifest.get("gates", {})

# ── Missing evidence by owner ───────────────────────────────────────
missing_by_owner = bundle.get("missing_evidence_by_owner", [])
missing_evidence = bundle.get("missing_evidence", [])

# ── First-failure analysis ──────────────────────────────────────────
first_failures = []

# Check suite failures
for s in suite_results:
    if s.get("status") == "failed":
        suite_name = s.get("suite", "unknown")
        first_failures.append({
            "source": "suite",
            "id": suite_name,
            "description": f"Suite '{suite_name}' failed",
            "root_cause_hint": f"Check {suite_name}_output.txt in report dir for test failures",
            "rerun": f"scripts/run_semantic_verification.sh --profile full --suite {suite_name}",
        })

# Check gate failures
for gid, gdata in sorted(gates.items()):
    if gdata.get("verdict") in ("FAIL", "DEFER"):
        details = gdata.get("details", "")
        first_failures.append({
            "source": "gate",
            "id": gid,
            "description": f"Gate {gid}: {gdata['verdict']} ({gdata.get('checks_passed',0)}/{gdata.get('checks_total',0)})",
            "root_cause_hint": details if details else "No specific details available",
            "rerun": f"scripts/assemble_evidence_bundle.sh --json --phase 1",
        })

# Check coverage gaps by domain
for d in DOMAIN_ORDER:
    ds = domain_stats.get(d, {})
    if ds.get("with_gaps", 0) > 0:
        gap_classes = []
        for cls, count in sorted(ds.get("evidence_missing", {}).items()):
            if count > 0:
                gap_classes.append(f"{cls}:{count}")
        if gap_classes:
            first_failures.append({
                "source": "coverage",
                "id": f"domain.{d}",
                "description": f"{DOMAIN_LABELS.get(d, d)}: {ds['with_gaps']}/{ds['total']} rules have evidence gaps",
                "root_cause_hint": f"Missing evidence classes: {', '.join(gap_classes)}",
                "rerun": f"cargo test --test semantic_golden_fixture_validation  # for UT/OC gaps",
            })

# ── Generate Markdown summary ───────────────────────────────────────
lines = []
def emit(s=""): lines.append(s)

emit("# Semantic Verification Summary")
emit()
emit(f"**Generated**: {timestamp}")
emit(f"**Commit**: `{commit_hash}`")
emit(f"**Profile**: {runner.get('profile', 'unknown')}")
emit(f"**Duration**: {runner.get('total_duration_s', 0)}s")
emit(f"**Overall Status**: **{overall_status.upper()}**")
emit()
emit("---")
emit()

# ── 1. Suite Results ────────────────────────────────────────────────
emit("## 1. Verification Suite Results")
emit()
emit("| Suite | Status | Duration | Required |")
emit("|-------|--------|----------|----------|")
for s in suite_results:
    status = s.get("status", "unknown")
    status_icon = "PASS" if status == "passed" else ("FAIL" if status == "failed" else "SKIP")
    req = "yes" if s.get("required") else "no"
    emit(f"| {s.get('suite', '?')} | **{status_icon}** | {s.get('duration_s', 0)}s | {req} |")
emit()
emit(f"**Passed**: {suites_passed}/{suites_total}")
if suites_failed > 0:
    emit(f"**Failed**: {suites_failed}")
emit()

# ── 2. Readiness Gates ──────────────────────────────────────────────
if gates:
    emit("## 2. Readiness Gate Status")
    emit()
    phase_verdict = gate_manifest.get("phase_verdict", "?") if gate_manifest else "?"
    emit(f"**Phase Verdict**: **{phase_verdict}**")
    emit()
    emit("| Gate | Domain | Verdict | Checks |")
    emit("|------|--------|---------|--------|")
    gate_domain_map = {
        "G1": "Documentation Alignment",
        "G2": "LEAN Proof Coverage",
        "G3": "TLA+ Model Checking",
        "G4": "Runtime Conformance",
        "G5": "Property and Law Tests",
        "G6": "Cross-Artifact E2E",
        "G7": "Logging and Diagnostics",
    }
    for gid in ["G1", "G2", "G3", "G4", "G5", "G6", "G7"]:
        gdata = gates.get(gid, {})
        verdict = gdata.get("verdict", "?")
        checks = f"{gdata.get('checks_passed', 0)}/{gdata.get('checks_total', 0)}"
        domain = gate_domain_map.get(gid, "?")
        emit(f"| {gid} | {domain} | **{verdict}** | {checks} |")
    emit()

# ── 3. Coverage by Semantic Domain ──────────────────────────────────
emit("## 3. Coverage by Semantic Domain")
emit()
emit("| Domain | Rules | Covered | Gaps | HIGH | MED | LOW |")
emit("|--------|:-----:|:-------:|:----:|:----:|:---:|:---:|")
total_rules = 0
total_covered = 0
total_gaps = 0
for d in DOMAIN_ORDER:
    ds = domain_stats.get(d, {"total": 0, "with_gaps": 0, "tiers": {}})
    covered = ds["total"] - ds["with_gaps"]
    total_rules += ds["total"]
    total_covered += covered
    total_gaps += ds["with_gaps"]
    high = ds["tiers"].get("HIGH", 0)
    med = ds["tiers"].get("MED", 0)
    low = ds["tiers"].get("LOW", 0) + ds["tiers"].get("SCOPE-OUT", 0)
    label = DOMAIN_LABELS.get(d, d)
    pct = int(100 * covered / ds["total"]) if ds["total"] > 0 else 0
    emit(f"| {label} | {ds['total']} | {covered} ({pct}%) | {ds['with_gaps']} | {high} | {med} | {low} |")
total_pct = int(100 * total_covered / total_rules) if total_rules > 0 else 0
emit(f"| **Total** | **{total_rules}** | **{total_covered} ({total_pct}%)** | **{total_gaps}** | | | |")
emit()

# ── 4. Evidence Class Distribution ──────────────────────────────────
emit("## 4. Evidence Class Distribution")
emit()
all_classes = ["UT", "PT", "OC", "E2E", "LOG", "DOC", "CI"]
emit("| Domain | " + " | ".join(all_classes) + " |")
emit("|--------" + "|:---:" * len(all_classes) + "|")
for d in DOMAIN_ORDER:
    ds = domain_stats.get(d, {"total": 0, "evidence_present": {}, "evidence_missing": {}})
    label = DOMAIN_LABELS.get(d, d)
    cells = []
    for cls in all_classes:
        present = ds["evidence_present"].get(cls, 0)
        missing = ds["evidence_missing"].get(cls, 0)
        if present > 0 and missing == 0:
            cells.append(f"{present}")
        elif present > 0 and missing > 0:
            cells.append(f"{present}/{present+missing}")
        elif missing > 0:
            cells.append(f"0/{missing}")
        else:
            cells.append("-")
    emit(f"| {label} | " + " | ".join(cells) + " |")
emit()

# ── 5. First-Failure Triage ─────────────────────────────────────────
emit("## 5. First-Failure Triage")
emit()
if not first_failures:
    emit("No failures detected.")
else:
    for i, ff in enumerate(first_failures, 1):
        emit(f"### {i}. [{ff['source'].upper()}] {ff['id']}")
        emit()
        emit(f"**Issue**: {ff['description']}")
        emit(f"**Root Cause Hint**: {ff['root_cause_hint']}")
        emit(f"**Rerun**: `{ff['rerun']}`")
        emit()
emit()

# ── 6. Remediation Owners ──────────────────────────────────────────
if missing_by_owner:
    emit("## 6. Remediation Owners")
    emit()
    emit("| Owner Bead | Missing Evidence Items |")
    emit("|------------|:---------------------:|")
    for entry in sorted(missing_by_owner, key=lambda e: -e["count"]):
        emit(f"| `{entry['owner_bead']}` | {entry['count']} |")
    emit()
    emit(f"**Total missing evidence items**: {len(missing_evidence)}")
    emit()

# ── 7. Reproducibility ─────────────────────────────────────────────
emit("## 7. Reproducibility")
emit()
emit("```bash")
emit("# Full verification run")
emit("scripts/run_semantic_verification.sh --profile full --json")
emit()
emit("# Evidence bundle")
emit("scripts/build_semantic_evidence_bundle.sh \\")
emit("  --report target/semantic-verification/verification_report.json \\")
emit("  --output target/semantic-readiness/evidence_bundle.json")
emit()
emit("# Gate evaluation")
emit("scripts/assemble_evidence_bundle.sh --json --phase 1")
emit()
emit("# Regenerate this summary")
emit("scripts/generate_verification_summary.sh --json")
emit("```")
emit()

# ── 8. Artifact Links ──────────────────────────────────────────────
emit("## 8. Artifact Links")
emit()
artifacts = bundle.get("inputs", {})
emit("| Artifact | Path |")
emit("|----------|------|")
for name, path in sorted(artifacts.items()):
    # Make path relative to project root
    rel = path.replace("/data/projects/asupersync/", "")
    emit(f"| {name} | `{rel}` |")
if gate_manifest:
    bundle_artifacts = gate_manifest.get("artifacts", {})
    for name, path in sorted(bundle_artifacts.items()):
        emit(f"| {name} | `target/evidence-bundle/{path}` |")
emit()

# ── Write markdown ──────────────────────────────────────────────────
md_path = os.path.join(output_dir, "verification_summary.md")
with open(md_path, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"[verification-summary] Summary: {md_path}")

# ── Generate triage report ──────────────────────────────────────────
triage_lines = []
def t(s=""): triage_lines.append(s)

t("# Verification Triage Report")
t()
t(f"**Generated**: {timestamp}")
t(f"**Commit**: `{commit_hash}`")
t()
t("---")
t()

if not first_failures:
    t("## All Clear")
    t()
    t("No failures or gaps require immediate attention.")
else:
    t(f"## {len(first_failures)} Items Requiring Attention")
    t()

    # Group by source type
    by_source = defaultdict(list)
    for ff in first_failures:
        by_source[ff["source"]].append(ff)

    source_labels = {"suite": "Suite Failures", "gate": "Gate Failures", "coverage": "Coverage Gaps"}
    for src in ["suite", "gate", "coverage"]:
        items = by_source.get(src, [])
        if not items:
            continue
        t(f"### {source_labels.get(src, src)} ({len(items)})")
        t()
        for ff in items:
            t(f"#### {ff['id']}")
            t()
            t(f"- **Issue**: {ff['description']}")
            t(f"- **Root Cause**: {ff['root_cause_hint']}")
            t(f"- **Rerun**: `{ff['rerun']}`")
            t()

    # Remediation action items
    t("### Remediation Action Items")
    t()
    if missing_by_owner:
        for entry in sorted(missing_by_owner, key=lambda e: -e["count"]):
            t(f"- [ ] **{entry['owner_bead']}**: Resolve {entry['count']} missing evidence items")
    t()

    # Per-rule detail (verbose)
    if verbose:
        t("### Per-Rule Detail")
        t()
        for d in DOMAIN_ORDER:
            ds = domain_stats.get(d, {"rules": []})
            gap_rules = [r for r in ds["rules"] if r.get("missing_classes")]
            if not gap_rules:
                continue
            t(f"#### {DOMAIN_LABELS.get(d, d)}")
            t()
            t("| # | Rule ID | Tier | Present | Missing |")
            t("|---|---------|------|---------|---------|")
            for r in gap_rules:
                present = r.get("status_text", "?")
                missing = ", ".join(r.get("missing_classes", []))
                t(f"| {r['rule_index']} | `{r['rule_id']}` | {r.get('tier', '?')} | {present} | {missing} |")
            t()

t("---")
t()
t("*Generated by `scripts/generate_verification_summary.sh` (SEM-12.10)*")

triage_path = os.path.join(output_dir, "triage_report.md")
with open(triage_path, "w") as f:
    f.write("\n".join(triage_lines) + "\n")
print(f"[verification-summary] Triage: {triage_path}")

# ── JSON summary ────────────────────────────────────────────────────
if json_output:
    summary_json = {
        "schema": "verification-summary-v1",
        "timestamp": timestamp,
        "commit_hash": commit_hash,
        "profile": runner.get("profile", "unknown"),
        "duration_s": runner.get("total_duration_s", 0),
        "overall_status": overall_status,
        "suites": {
            "total": suites_total,
            "passed": suites_passed,
            "failed": suites_failed,
            "results": suite_results,
        },
        "gates": {
            "phase_verdict": gate_manifest.get("phase_verdict", "unknown") if gate_manifest else "no_manifest",
            "overall_verdict": gate_manifest.get("overall_verdict", "unknown") if gate_manifest else "no_manifest",
            "details": {gid: gdata for gid, gdata in sorted(gates.items())} if gates else {},
        },
        "coverage": {
            "total_rules": total_rules,
            "covered": total_covered,
            "gaps": total_gaps,
            "coverage_pct": total_pct,
            "domains": {},
        },
        "missing_evidence": {
            "total": len(missing_evidence),
            "by_owner": missing_by_owner,
        },
        "first_failures": first_failures,
        "reproducibility": {
            "summary": "scripts/generate_verification_summary.sh --json",
            "runner": "scripts/run_semantic_verification.sh --profile full --json",
            "bundle": "scripts/assemble_evidence_bundle.sh --json --phase 1",
        },
    }
    # Add per-domain coverage
    for d in DOMAIN_ORDER:
        ds = domain_stats.get(d, {"total": 0, "with_gaps": 0, "evidence_present": {}, "evidence_missing": {}})
        covered = ds["total"] - ds["with_gaps"]
        summary_json["coverage"]["domains"][d] = {
            "total": ds["total"],
            "covered": covered,
            "gaps": ds["with_gaps"],
            "coverage_pct": int(100 * covered / ds["total"]) if ds["total"] > 0 else 0,
            "evidence_present": dict(ds["evidence_present"]),
            "evidence_missing": dict(ds["evidence_missing"]),
        }

    json_path = os.path.join(output_dir, "verification_summary.json")
    with open(json_path, "w") as f:
        json.dump(summary_json, f, indent=2)
        f.write("\n")
    print(f"[verification-summary] JSON: {json_path}")

# ── Exit status ─────────────────────────────────────────────────────
has_critical = suites_failed > 0 or any(
    g.get("verdict") == "FAIL"
    for gid, g in gates.items()
    if gid in ("G1", "G4")  # Phase 1 required gates
)
sys.exit(1 if has_critical else 0)
PYTHON_SCRIPT

PYTHON_EXIT=$?

if [[ $PYTHON_EXIT -eq 0 ]]; then
    log "Summary generated successfully"
elif [[ $PYTHON_EXIT -eq 1 ]]; then
    log "WARNING: Summary generated with critical failures present"
else
    log "ERROR: Summary generation failed"
    exit 2
fi

# ─── Print summary to stdout ────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo " Verification Summary ($(date -u '+%Y-%m-%d'))"
echo "══════════════════════════════════════════════════"
echo ""

# Quick stats from the generated JSON if available
if [[ -f "${OUTPUT_DIR}/verification_summary.json" ]]; then
    python3 -c "
import json, sys
with open('${OUTPUT_DIR}/verification_summary.json') as f:
    d = json.load(f)
print(f\"  Overall:    {d['overall_status'].upper()}\")
print(f\"  Suites:     {d['suites']['passed']}/{d['suites']['total']} passed\")
g = d.get('gates', {})
print(f\"  Phase:      {g.get('phase_verdict', 'N/A')}\")
c = d['coverage']
print(f\"  Coverage:   {c['covered']}/{c['total_rules']} rules ({c['coverage_pct']}%)\")
me = d['missing_evidence']
print(f\"  Gaps:       {me['total']} missing evidence items\")
ff = d['first_failures']
print(f\"  Triage:     {len(ff)} items requiring attention\")
" 2>/dev/null || true
else
    echo "  (run with --json for quick stats)"
fi

echo ""
echo "  Reports:"
echo "    Summary: ${OUTPUT_DIR}/verification_summary.md"
echo "    Triage:  ${OUTPUT_DIR}/triage_report.md"
if [[ "$JSON_OUTPUT" == "true" ]]; then
    echo "    JSON:    ${OUTPUT_DIR}/verification_summary.json"
fi
echo ""

if [[ "$CI_MODE" == "true" && $PYTHON_EXIT -ne 0 ]]; then
    log "CI mode: exiting with failure status"
    exit 1
fi

exit 0
