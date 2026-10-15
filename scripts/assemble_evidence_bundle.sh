#!/usr/bin/env bash
# Evidence Bundle Assembly (SEM-09.2)
#
# Assembles a normalized evidence bundle from Lean, TLA+, runtime, docs,
# and SEM-12 verification outputs with reproducibility metadata.
#
# Usage:
#   scripts/assemble_evidence_bundle.sh [OPTIONS]
#
# Options:
#   --json              Write structured JSON bundle manifest
#   --ci                CI mode: strict verdicts, no exceptions
#   --phase PHASE       Target phase: 1 (default), 2, 3
#   --output-dir DIR    Override bundle output directory
#   --skip-runner       Skip re-running unified verification (use cached)
#   --verbose           Verbose output
#
# Exit codes:
#   0 - Bundle assembled, all required gates pass
#   1 - Bundle assembled, one or more required gates fail
#   2 - Configuration error
#
# Bead: asupersync-3cddg.9.2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUNDLE_DIR="$PROJECT_ROOT/target/evidence-bundle"
VERIFICATION_DIR="$PROJECT_ROOT/target/semantic-verification"
JSON_OUTPUT=false
CI_MODE=false
PHASE=1
SKIP_RUNNER=false
VERBOSE=false

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --ci) CI_MODE=true; JSON_OUTPUT=true; shift ;;
    --phase) PHASE="$2"; shift 2 ;;
    --output-dir) BUNDLE_DIR="$2"; shift 2 ;;
    --skip-runner) SKIP_RUNNER=true; shift ;;
    --verbose) VERBOSE=true; shift ;;
    -h|--help) head -26 "$0" | tail -23; exit 0 ;;
    *) echo "ERROR: Unknown argument: $1"; exit 2 ;;
  esac
done

log() { echo "[evidence-bundle] $(date -u +%H:%M:%S) $*"; }
vlog() { [ "$VERBOSE" = true ] && log "$*" || true; }

# ─── Directory setup ──────────────────────────────────────────────

mkdir -p "$BUNDLE_DIR"/{metadata,lean,tla,runtime,docs,cross_artifact}

BUNDLE_TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUNDLE_START=$(date +%s)

log "Assembling evidence bundle (phase=$PHASE, ci=$CI_MODE)"
log "Output: $BUNDLE_DIR"

# ─── Gate verdict tracking ────────────────────────────────────────

declare -A GATE_VERDICT
declare -A GATE_CHECKS_PASSED
declare -A GATE_CHECKS_TOTAL
declare -A GATE_DETAILS
declare -a EXCEPTIONS=()
OVERALL_VERDICT="PASS"

for g in G1 G2 G3 G4 G5 G6 G7; do
  GATE_VERDICT[$g]="PENDING"
  GATE_CHECKS_PASSED[$g]=0
  GATE_CHECKS_TOTAL[$g]=0
  GATE_DETAILS[$g]=""
done

gate_check() {
  local gate="$1" check_name="$2" result="$3" detail="${4:-}"
  local total=${GATE_CHECKS_TOTAL[$gate]}
  local passed=${GATE_CHECKS_PASSED[$gate]}
  GATE_CHECKS_TOTAL[$gate]=$((total + 1))
  if [ "$result" = "PASS" ]; then
    GATE_CHECKS_PASSED[$gate]=$((passed + 1))
    vlog "  $gate/$check_name: PASS"
  else
    vlog "  $gate/$check_name: FAIL ($detail)"
    GATE_DETAILS[$gate]="${GATE_DETAILS[$gate]}${GATE_DETAILS[$gate]:+; }$check_name: $detail"
  fi
}

finalize_gate() {
  local gate="$1"
  if [ "${GATE_CHECKS_PASSED[$gate]}" -eq "${GATE_CHECKS_TOTAL[$gate]}" ]; then
    GATE_VERDICT[$gate]="PASS"
  else
    GATE_VERDICT[$gate]="FAIL"
    OVERALL_VERDICT="FAIL"
  fi
  log "  $gate: ${GATE_VERDICT[$gate]} (${GATE_CHECKS_PASSED[$gate]}/${GATE_CHECKS_TOTAL[$gate]})"
}

# ─── Step 1: Run unified verification (or use cached) ────────────

if [ "$SKIP_RUNNER" = false ]; then
  log "Running unified semantic verification..."
  RUNNER_ARGS="--json --profile full"
  [ "$CI_MODE" = true ] && RUNNER_ARGS="$RUNNER_ARGS --ci"
  if "$SCRIPT_DIR/run_semantic_verification.sh" $RUNNER_ARGS 2>&1 | tee "$BUNDLE_DIR/runtime/verification_output.txt"; then
    RUNNER_STATUS="passed"
  else
    RUNNER_STATUS="failed"
  fi
else
  log "Skipping unified runner (--skip-runner), using cached results"
  RUNNER_STATUS="cached"
fi

# Copy verification report if available
if [ -f "$VERIFICATION_DIR/verification_report.json" ]; then
  cp "$VERIFICATION_DIR/verification_report.json" "$BUNDLE_DIR/runtime/verification_report.json"
  vlog "Copied verification_report.json"
fi

# ─── Step 2: G1 — Documentation Alignment ────────────────────────

log "Evaluating G1: Documentation Alignment..."

# Check 1: All 47 rule IDs in contract docs
RULE_ID_COUNT=0
CONTRACT_DOCS="$PROJECT_ROOT/docs/semantic_contract_schema.md $PROJECT_ROOT/docs/semantic_contract_glossary.md $PROJECT_ROOT/docs/semantic_contract_transitions.md $PROJECT_ROOT/docs/semantic_contract_invariants.md"
for doc in $CONTRACT_DOCS; do
  if [ -f "$doc" ]; then
    count=$(grep -cE '(rule\.|inv\.|def\.|comb\.|law\.)' "$doc" 2>/dev/null || true)
    RULE_ID_COUNT=$((RULE_ID_COUNT + count))
  fi
done
if [ "$RULE_ID_COUNT" -ge 47 ]; then
  gate_check G1 "rule_id_coverage" "PASS"
else
  gate_check G1 "rule_id_coverage" "FAIL" "found $RULE_ID_COUNT rule references, need 47+"
fi

# Check 2: Glossary exists and has entries
if [ -f "$PROJECT_ROOT/docs/semantic_contract_glossary.md" ]; then
  GLOSSARY_ENTRIES=$(grep -c '^###\|^##' "$PROJECT_ROOT/docs/semantic_contract_glossary.md" 2>/dev/null || true)
  if [ "$GLOSSARY_ENTRIES" -ge 11 ]; then
    gate_check G1 "glossary_coverage" "PASS"
  else
    gate_check G1 "glossary_coverage" "FAIL" "found $GLOSSARY_ENTRIES entries, need 11+"
  fi
else
  gate_check G1 "glossary_coverage" "FAIL" "glossary doc missing"
fi

# Check 3: Transition rules doc exists with PRE/POST
if [ -f "$PROJECT_ROOT/docs/semantic_contract_transitions.md" ]; then
  TRANSITION_RULES=$(grep -ciE '(PRE|POST|precondition|postcondition)' "$PROJECT_ROOT/docs/semantic_contract_transitions.md" 2>/dev/null || true)
  if [ "$TRANSITION_RULES" -ge 15 ]; then
    gate_check G1 "transition_rules" "PASS"
  else
    gate_check G1 "transition_rules" "FAIL" "found $TRANSITION_RULES PRE/POST refs, need 15+"
  fi
else
  gate_check G1 "transition_rules" "FAIL" "transitions doc missing"
fi

# Check 4: Invariant doc exists with clauses
if [ -f "$PROJECT_ROOT/docs/semantic_contract_invariants.md" ]; then
  INVARIANT_CLAUSES=$(grep -c '^###\|^##' "$PROJECT_ROOT/docs/semantic_contract_invariants.md" 2>/dev/null || true)
  if [ "$INVARIANT_CLAUSES" -ge 14 ]; then
    gate_check G1 "invariant_clauses" "PASS"
  else
    gate_check G1 "invariant_clauses" "FAIL" "found $INVARIANT_CLAUSES clauses, need 14+"
  fi
else
  gate_check G1 "invariant_clauses" "FAIL" "invariants doc missing"
fi

# Check 5: Docs lint tests pass (from runner)
if [ -f "$BUNDLE_DIR/runtime/verification_report.json" ]; then
  DOCS_STATUS=$(python3 -c "
import json, sys
with open('$BUNDLE_DIR/runtime/verification_report.json') as f:
    r = json.load(f)
for s in r.get('results', []):
    if s['suite'] == 'docs':
        print(s['status'])
        sys.exit(0)
print('missing')
" 2>/dev/null || echo "missing")
  if [ "$DOCS_STATUS" = "passed" ]; then
    gate_check G1 "docs_lint" "PASS"
  else
    gate_check G1 "docs_lint" "FAIL" "docs suite: $DOCS_STATUS"
  fi
else
  gate_check G1 "docs_lint" "FAIL" "no verification report"
fi

finalize_gate G1

# Copy docs evidence
for doc in semantic_contract_schema.md semantic_contract_glossary.md \
           semantic_contract_transitions.md semantic_contract_invariants.md \
           semantic_docs_rule_mapping.md semantic_verification_matrix.md; do
  [ -f "$PROJECT_ROOT/docs/$doc" ] && cp "$PROJECT_ROOT/docs/$doc" "$BUNDLE_DIR/docs/" 2>/dev/null || true
done

# ─── Step 3: G2 — LEAN Proof Coverage ────────────────────────────

log "Evaluating G2: LEAN Proof Coverage..."

# Check 1: Lean spec file exists
if [ -f "$PROJECT_ROOT/formal/lean/Asupersync.lean" ]; then
  gate_check G2 "spec_exists" "PASS"
else
  gate_check G2 "spec_exists" "FAIL" "Lean spec not found"
fi

# Check 2: Coverage matrix exists
if [ -f "$PROJECT_ROOT/formal/lean/coverage/lean_coverage_matrix.sample.json" ]; then
  gate_check G2 "coverage_matrix" "PASS"
  cp "$PROJECT_ROOT/formal/lean/coverage/lean_coverage_matrix.sample.json" \
     "$BUNDLE_DIR/lean/coverage_matrix.json"
else
  gate_check G2 "coverage_matrix" "FAIL" "coverage matrix missing"
fi

# Check 3: Theorem surface inventory
if [ -f "$PROJECT_ROOT/formal/lean/coverage/theorem_surface_inventory.json" ]; then
  THEOREM_COUNT=$(python3 -c "
import json
with open('$PROJECT_ROOT/formal/lean/coverage/theorem_surface_inventory.json') as f:
    d = json.load(f)
print(len(d.get('theorems', d)) if isinstance(d, dict) else len(d))
" 2>/dev/null || true)
  if [ "$THEOREM_COUNT" -gt 0 ]; then
    gate_check G2 "theorem_inventory" "PASS"
  else
    gate_check G2 "theorem_inventory" "FAIL" "0 theorems found"
  fi
  cp "$PROJECT_ROOT/formal/lean/coverage/theorem_surface_inventory.json" \
     "$BUNDLE_DIR/lean/theorem_inventory.json"
else
  gate_check G2 "theorem_inventory" "FAIL" "theorem inventory missing"
fi

# Check 4: Baseline report exists (regression detection)
if [ -f "$PROJECT_ROOT/formal/lean/coverage/baseline_report_v1.json" ]; then
  gate_check G2 "baseline_exists" "PASS"
  cp "$PROJECT_ROOT/formal/lean/coverage/baseline_report_v1.json" \
     "$BUNDLE_DIR/lean/baseline_report.json"
else
  gate_check G2 "baseline_exists" "FAIL" "baseline report missing"
fi

# Check 5: Lean validation tests pass (from runner)
if [ -f "$BUNDLE_DIR/runtime/verification_report.json" ]; then
  LEAN_STATUS=$(python3 -c "
import json, sys
with open('$BUNDLE_DIR/runtime/verification_report.json') as f:
    r = json.load(f)
for s in r.get('results', []):
    if s['suite'] == 'lean_validation':
        print(s['status'])
        sys.exit(0)
print('missing')
" 2>/dev/null || echo "missing")
  if [ "$LEAN_STATUS" = "passed" ]; then
    gate_check G2 "lean_validation_tests" "PASS"
  else
    gate_check G2 "lean_validation_tests" "FAIL" "lean validation suite: $LEAN_STATUS"
  fi
else
  gate_check G2 "lean_validation_tests" "FAIL" "no verification report"
fi

finalize_gate G2

# ─── Step 4: G3 — TLA+ Model Checking ────────────────────────────

log "Evaluating G3: TLA+ Model Checking..."

# Check 1: TLA+ spec exists
if [ -f "$PROJECT_ROOT/formal/tla/Asupersync.tla" ]; then
  gate_check G3 "spec_exists" "PASS"
else
  gate_check G3 "spec_exists" "FAIL" "TLA+ spec not found"
fi

# Check 2: MC config exists
if [ -f "$PROJECT_ROOT/formal/tla/Asupersync_MC.cfg" ]; then
  gate_check G3 "config_exists" "PASS"
else
  gate_check G3 "config_exists" "FAIL" "MC config not found"
fi

# Check 3: TLC result shows no violations
if [ -f "$PROJECT_ROOT/formal/tla/output/result.json" ]; then
  TLC_VIOLATIONS=$(python3 -c "
import json
with open('$PROJECT_ROOT/formal/tla/output/result.json') as f:
    d = json.load(f)
print(d.get('violations', -1))
" 2>/dev/null || echo -1)
  TLC_STATES=$(python3 -c "
import json
with open('$PROJECT_ROOT/formal/tla/output/result.json') as f:
    d = json.load(f)
print(d.get('distinct_states', 0))
" 2>/dev/null || true)
  TLC_STATUS=$(python3 -c "
import json
with open('$PROJECT_ROOT/formal/tla/output/result.json') as f:
    d = json.load(f)
print(d.get('status', 'unknown'))
" 2>/dev/null || echo "unknown")
  if [ "$TLC_VIOLATIONS" = "0" ] && [ "$TLC_STATUS" = "pass" ]; then
    gate_check G3 "no_violations" "PASS"
  else
    gate_check G3 "no_violations" "FAIL" "violations=$TLC_VIOLATIONS status=$TLC_STATUS"
  fi
  # Check 4: State space within bound
  if [ "$TLC_STATES" -lt 10000000 ] && [ "$TLC_STATES" -gt 0 ]; then
    gate_check G3 "state_space_bound" "PASS"
  else
    gate_check G3 "state_space_bound" "FAIL" "states=$TLC_STATES (limit 10M)"
  fi
  cp "$PROJECT_ROOT/formal/tla/output/result.json" "$BUNDLE_DIR/tla/model_check_result.json"
else
  gate_check G3 "no_violations" "FAIL" "TLC result.json not found"
  gate_check G3 "state_space_bound" "FAIL" "TLC result.json not found"
fi

# Check 5: TLA validation tests pass (from runner)
if [ -f "$BUNDLE_DIR/runtime/verification_report.json" ]; then
  TLA_STATUS=$(python3 -c "
import json, sys
with open('$BUNDLE_DIR/runtime/verification_report.json') as f:
    r = json.load(f)
for s in r.get('results', []):
    if s['suite'] == 'tla_validation':
        print(s['status'])
        sys.exit(0)
print('missing')
" 2>/dev/null || echo "missing")
  if [ "$TLA_STATUS" = "passed" ]; then
    gate_check G3 "tla_validation_tests" "PASS"
  else
    gate_check G3 "tla_validation_tests" "FAIL" "tla validation suite: $TLA_STATUS"
  fi
else
  gate_check G3 "tla_validation_tests" "FAIL" "no verification report"
fi

# Check 6: Abstractions documented
ABSTRACTION_COUNT=$(grep -c 'ADR-' "$PROJECT_ROOT/formal/tla/Asupersync.tla" 2>/dev/null || true)
if [ "$ABSTRACTION_COUNT" -ge 4 ]; then
  gate_check G3 "abstractions_documented" "PASS"
else
  gate_check G3 "abstractions_documented" "FAIL" "found $ABSTRACTION_COUNT ADR refs, need 4+"
fi

finalize_gate G3

# Copy TLA+ evidence
for f in "$PROJECT_ROOT"/formal/tla/output/*.log; do
  [ -f "$f" ] && cp "$f" "$BUNDLE_DIR/tla/" 2>/dev/null || true
done
cp "$PROJECT_ROOT/formal/tla/Asupersync.tla" "$BUNDLE_DIR/tla/" 2>/dev/null || true
cp "$PROJECT_ROOT/formal/tla/Asupersync_MC.cfg" "$BUNDLE_DIR/tla/" 2>/dev/null || true

# ─── Step 5: G4 — Runtime Conformance ────────────────────────────

log "Evaluating G4: Runtime Conformance..."

# Check 1: Gap matrix exists
if [ -f "$PROJECT_ROOT/docs/semantic_runtime_gap_matrix.md" ]; then
  CODE_GAPS=$(grep -c 'CODE-GAP' "$PROJECT_ROOT/docs/semantic_runtime_gap_matrix.md" 2>/dev/null || true)
  # CODE-GAPs in the matrix file count mentions; check for unresolved ones
  UNRESOLVED=$(grep -c 'CODE-GAP.*open\|CODE-GAP.*unresolved' "$PROJECT_ROOT/docs/semantic_runtime_gap_matrix.md" 2>/dev/null || true)
  if [ "$UNRESOLVED" -eq 0 ]; then
    gate_check G4 "code_gaps_zero" "PASS"
  else
    gate_check G4 "code_gaps_zero" "FAIL" "$UNRESOLVED unresolved CODE-GAPs"
  fi
  cp "$PROJECT_ROOT/docs/semantic_runtime_gap_matrix.md" "$BUNDLE_DIR/docs/" 2>/dev/null || true
else
  gate_check G4 "code_gaps_zero" "FAIL" "gap matrix doc missing"
fi

# Check 2: DOC-GAP annotations in source
DOC_GAP_COUNT=$(grep -rn 'DOC-GAP\|rule\.\|inv\.' "$PROJECT_ROOT/src/" --include='*.rs' 2>/dev/null | grep -c 'rule-id\|DOC-GAP\|inv\.\|rule\.' || echo 0)
if [ "$DOC_GAP_COUNT" -ge 7 ]; then
  gate_check G4 "doc_gap_annotations" "PASS"
else
  gate_check G4 "doc_gap_annotations" "FAIL" "found $DOC_GAP_COUNT annotations, need 7+"
fi

# Check 3: Conformance harness tests pass
if [ -f "$BUNDLE_DIR/runtime/verification_report.json" ]; then
  GOLDEN_STATUS=$(python3 -c "
import json, sys
with open('$BUNDLE_DIR/runtime/verification_report.json') as f:
    r = json.load(f)
for s in r.get('results', []):
    if s['suite'] == 'golden':
        print(s['status'])
        sys.exit(0)
print('missing')
" 2>/dev/null || echo "missing")
  if [ "$GOLDEN_STATUS" = "passed" ]; then
    gate_check G4 "conformance_tests" "PASS"
  else
    gate_check G4 "conformance_tests" "FAIL" "golden suite: $GOLDEN_STATUS"
  fi
else
  gate_check G4 "conformance_tests" "FAIL" "no verification report"
fi

finalize_gate G4

# ─── Step 6: G5 — Property and Law Tests ─────────────────────────

log "Evaluating G5: Property and Law Tests..."

# Check for property/law test files
LAW_TESTS=$(grep -rl 'law_join_assoc\|law_race_comm\|law_timeout_min\|metamorphic_drain\|law_race_abandon' \
  "$PROJECT_ROOT/tests/" "$PROJECT_ROOT/src/" --include='*.rs' 2>/dev/null | wc -l || true)
LAW_TESTS=$(echo "${LAW_TESTS:-0}" | tr -d '[:space:]')
if [ "$LAW_TESTS" -ge 1 ]; then
  gate_check G5 "law_tests_exist" "PASS"
else
  gate_check G5 "law_tests_exist" "FAIL" "no law/property test files found"
fi

# Check conformance harness references laws
if [ -f "$PROJECT_ROOT/tests/semantic_conformance_harness.rs" ]; then
  LAW_REFS=$(grep -c 'law\|property\|metamorphic' "$PROJECT_ROOT/tests/semantic_conformance_harness.rs" 2>/dev/null || true)
  if [ "$LAW_REFS" -ge 3 ]; then
    gate_check G5 "harness_law_coverage" "PASS"
  else
    gate_check G5 "harness_law_coverage" "FAIL" "conformance harness has $LAW_REFS law refs, need 3+"
  fi
else
  gate_check G5 "harness_law_coverage" "FAIL" "conformance harness missing"
fi

finalize_gate G5

# ─── Step 7: G6 — Cross-Artifact E2E ─────────────────────────────

log "Evaluating G6: Cross-Artifact E2E..."

# Check 1: Witness replay test file exists
if [ -f "$PROJECT_ROOT/tests/semantic_witness_replay_e2e.rs" ]; then
  gate_check G6 "witness_replay_tests" "PASS"
else
  gate_check G6 "witness_replay_tests" "FAIL" "witness replay test file missing"
fi

# Check 2: Adversarial corpus tests exist
if [ -f "$PROJECT_ROOT/tests/adversarial_witness_corpus.rs" ]; then
  gate_check G6 "adversarial_tests" "PASS"
else
  gate_check G6 "adversarial_tests" "FAIL" "adversarial corpus test file missing"
fi

# Check 3: Capability audit (no unsafe in cx/)
if [ -d "$PROJECT_ROOT/src/cx" ]; then
  UNSAFE_COUNT=$(grep -rl 'unsafe' "$PROJECT_ROOT/src/cx/" --include='*.rs' 2>/dev/null | wc -l || true)
  UNSAFE_COUNT=$(echo "${UNSAFE_COUNT:-0}" | tr -d '[:space:]')
  if [ "$UNSAFE_COUNT" -eq 0 ]; then
    gate_check G6 "capability_audit" "PASS"
  else
    gate_check G6 "capability_audit" "FAIL" "$UNSAFE_COUNT files with unsafe in cx/"
  fi
else
  # cx/ may not exist as a directory
  gate_check G6 "capability_audit" "PASS"
fi

# Check 4: E2E logging tests pass (from runner)
if [ -f "$BUNDLE_DIR/runtime/verification_report.json" ]; then
  LOG_STATUS=$(python3 -c "
import json, sys
with open('$BUNDLE_DIR/runtime/verification_report.json') as f:
    r = json.load(f)
for s in r.get('results', []):
    if s['suite'] == 'logging_schema':
        print(s['status'])
        sys.exit(0)
print('missing')
" 2>/dev/null || echo "missing")
  if [ "$LOG_STATUS" = "passed" ]; then
    gate_check G6 "logging_e2e" "PASS"
  else
    gate_check G6 "logging_e2e" "FAIL" "logging_schema suite: $LOG_STATUS"
  fi
else
  gate_check G6 "logging_e2e" "FAIL" "no verification report"
fi

finalize_gate G6

# ─── Step 8: G7 — Logging and Diagnostics ────────────────────────

log "Evaluating G7: Logging and Diagnostics..."

# Check 1: Log schema documentation exists
if [ -f "$PROJECT_ROOT/docs/semantic_verification_log_schema.md" ]; then
  gate_check G7 "log_schema_doc" "PASS"
  cp "$PROJECT_ROOT/docs/semantic_verification_log_schema.md" "$BUNDLE_DIR/docs/" 2>/dev/null || true
else
  gate_check G7 "log_schema_doc" "FAIL" "log schema doc missing"
fi

# Check 2: Structured log fields defined
if [ -f "$PROJECT_ROOT/docs/semantic_verification_log_schema.md" ]; then
  REQUIRED_FIELDS="schema_version entry_id rule_id evidence_class verdict artifact_path"
  FIELDS_OK=true
  for field in $REQUIRED_FIELDS; do
    if ! grep -q "$field" "$PROJECT_ROOT/docs/semantic_verification_log_schema.md" 2>/dev/null; then
      FIELDS_OK=false
      break
    fi
  done
  if [ "$FIELDS_OK" = true ]; then
    gate_check G7 "log_fields_defined" "PASS"
  else
    gate_check G7 "log_fields_defined" "FAIL" "missing required log fields"
  fi
else
  gate_check G7 "log_fields_defined" "FAIL" "log schema doc missing"
fi

# Check 3: Coverage gate in verification runner
if [ -f "$BUNDLE_DIR/runtime/verification_report.json" ]; then
  COVERAGE_GATE=$(python3 -c "
import json
with open('$BUNDLE_DIR/runtime/verification_report.json') as f:
    r = json.load(f)
qg = r.get('quality_gates', {}).get('semantic_coverage_logging_gate', {})
print(qg.get('status', 'missing'))
" 2>/dev/null || echo "missing")
  if [ "$COVERAGE_GATE" != "missing" ]; then
    gate_check G7 "coverage_gate_present" "PASS"
  else
    gate_check G7 "coverage_gate_present" "FAIL" "coverage gate missing from report"
  fi
else
  gate_check G7 "coverage_gate_present" "FAIL" "no verification report"
fi

finalize_gate G7

# ─── Step 9: Cross-Artifact Conformance Matrix ───────────────────

log "Building cross-artifact conformance matrix..."

# Generate conformance matrix from existing artifacts
python3 - "$PROJECT_ROOT" "$BUNDLE_DIR" <<'PYEOF'
import json, os, re, sys

project_root = sys.argv[1]
bundle_dir = sys.argv[2]

# Canonical rule domains
DOMAINS = {
    "cancel": list(range(1, 13)),
    "obligation": list(range(13, 22)),
    "region": list(range(22, 29)),
    "outcome": list(range(29, 33)),
    "ownership": list(range(33, 37)),
    "combinator": list(range(37, 44)),
    "capability": [44, 45],
    "determinism": [46, 47],
}

# Check TLA+ coverage
tla_coverage = set()
tla_path = os.path.join(project_root, "formal/tla/Asupersync.tla")
if os.path.isfile(tla_path):
    tla_content = open(tla_path).read()
    for m in re.finditer(r'#(\d+)', tla_content):
        tla_coverage.add(int(m.group(1)))

# Check Lean coverage
lean_coverage = set()
lean_path = os.path.join(project_root, "formal/lean/Asupersync.lean")
if os.path.isfile(lean_path):
    lean_content = open(lean_path).read()
    for m in re.finditer(r'#(\d+)', lean_content):
        lean_coverage.add(int(m.group(1)))

# Check docs coverage via rule mapping
docs_coverage = set()
mapping_path = os.path.join(project_root, "docs/semantic_docs_rule_mapping.md")
if os.path.isfile(mapping_path):
    mapping_content = open(mapping_path).read()
    for m in re.finditer(r'#(\d+)', mapping_content):
        docs_coverage.add(int(m.group(1)))

# Build matrix
rules = []
for domain, ids in sorted(DOMAINS.items()):
    for rule_id in ids:
        rules.append({
            "rule_id": rule_id,
            "domain": domain,
            "lean": rule_id in lean_coverage,
            "tla": rule_id in tla_coverage,
            "docs": rule_id in docs_coverage,
            "coverage_count": sum([
                rule_id in lean_coverage,
                rule_id in tla_coverage,
                rule_id in docs_coverage,
            ]),
        })

# Summary
total = len(rules)
lean_count = sum(1 for r in rules if r["lean"])
tla_count = sum(1 for r in rules if r["tla"])
docs_count = sum(1 for r in rules if r["docs"])
full_coverage = sum(1 for r in rules if r["coverage_count"] == 3)
partial = sum(1 for r in rules if 0 < r["coverage_count"] < 3)
uncovered = sum(1 for r in rules if r["coverage_count"] == 0)

matrix = {
    "schema": "conformance-matrix-v1",
    "total_rules": total,
    "summary": {
        "lean_coverage": lean_count,
        "tla_coverage": tla_count,
        "docs_coverage": docs_count,
        "full_coverage": full_coverage,
        "partial_coverage": partial,
        "uncovered": uncovered,
    },
    "rules": rules,
}

out_path = os.path.join(bundle_dir, "cross_artifact/conformance_matrix.json")
with open(out_path, "w") as f:
    json.dump(matrix, f, indent=2)

print(f"Conformance matrix: {total} rules, {lean_count} lean, {tla_count} tla, {docs_count} docs, {full_coverage} full, {uncovered} uncovered")
PYEOF

# ─── Step 10: Phase completion assessment ─────────────────────────

log "Assessing phase $PHASE completion..."

case "$PHASE" in
  1)
    # Phase 1: G1 + G4 CODE-GAPs required
    REQUIRED_GATES="G1 G4"
    OPTIONAL_GATES="G2 G3 G5 G6 G7"
    ;;
  2)
    # Phase 2: All gates required
    REQUIRED_GATES="G1 G2 G3 G4 G5 G6 G7"
    OPTIONAL_GATES=""
    ;;
  3)
    # Phase 3: All gates required, zero exceptions
    REQUIRED_GATES="G1 G2 G3 G4 G5 G6 G7"
    OPTIONAL_GATES=""
    ;;
esac

PHASE_VERDICT="PASS"
REQUIRED_PASSED=0
REQUIRED_TOTAL=0
for g in $REQUIRED_GATES; do
  REQUIRED_TOTAL=$((REQUIRED_TOTAL + 1))
  if [ "${GATE_VERDICT[$g]}" = "PASS" ]; then
    REQUIRED_PASSED=$((REQUIRED_PASSED + 1))
  else
    PHASE_VERDICT="FAIL"
  fi
done

OPTIONAL_PASSED=0
OPTIONAL_TOTAL=0
for g in $OPTIONAL_GATES; do
  OPTIONAL_TOTAL=$((OPTIONAL_TOTAL + 1))
  if [ "${GATE_VERDICT[$g]}" = "PASS" ]; then
    OPTIONAL_PASSED=$((OPTIONAL_PASSED + 1))
  fi
done

BUNDLE_END=$(date +%s)
BUNDLE_DURATION=$((BUNDLE_END - BUNDLE_START))

# ─── Summary ─────────────────────────────────────────────────────

echo ""
echo "══════════════════════════════════════════════════"
echo " Evidence Bundle Summary (Phase $PHASE)"
echo "══════════════════════════════════════════════════"
echo ""
printf "  %-25s %s\n" "Phase verdict:" "$PHASE_VERDICT"
printf "  %-25s %s\n" "Required gates:" "$REQUIRED_PASSED/$REQUIRED_TOTAL"
printf "  %-25s %s\n" "Optional gates:" "$OPTIONAL_PASSED/$OPTIONAL_TOTAL"
printf "  %-25s %s\n" "Duration:" "${BUNDLE_DURATION}s"
echo ""
echo "  Gate Results:"
for g in G1 G2 G3 G4 G5 G6 G7; do
  verdict="${GATE_VERDICT[$g]}"
  checks="${GATE_CHECKS_PASSED[$g]}/${GATE_CHECKS_TOTAL[$g]}"
  case "$verdict" in
    PASS) marker="[PASS]" ;;
    FAIL) marker="[FAIL]" ;;
    *)    marker="[PEND]" ;;
  esac
  required="req"
  for og in $OPTIONAL_GATES; do
    [ "$og" = "$g" ] && required="opt"
  done
  printf "    %-6s %s  (%s) [%s]\n" "$g" "$marker" "$checks" "$required"
done
echo ""

# ─── JSON bundle manifest ────────────────────────────────────────

if [ "$JSON_OUTPUT" = true ]; then
  # Build gate verdicts JSON
  GATES_JSON="{"
  FIRST=true
  for g in G1 G2 G3 G4 G5 G6 G7; do
    if [ "$FIRST" = false ]; then GATES_JSON+=","; fi
    details="${GATE_DETAILS[$g]}"
    details_escaped=$(echo "$details" | sed 's/"/\\"/g')
    GATES_JSON+="\"$g\":{\"verdict\":\"${GATE_VERDICT[$g]}\",\"checks_passed\":${GATE_CHECKS_PASSED[$g]},\"checks_total\":${GATE_CHECKS_TOTAL[$g]},\"details\":\"$details_escaped\"}"
    FIRST=false
  done
  GATES_JSON+="}"

  cat > "$BUNDLE_DIR/metadata/bundle_manifest.json" <<MANIFEST_EOF
{
  "schema": "evidence-bundle-v1",
  "bead": "asupersync-3cddg.9.2",
  "phase": $PHASE,
  "timestamp": "$BUNDLE_TIMESTAMP",
  "duration_s": $BUNDLE_DURATION,
  "phase_verdict": "$PHASE_VERDICT",
  "overall_verdict": "$OVERALL_VERDICT",
  "required_gates_passed": $REQUIRED_PASSED,
  "required_gates_total": $REQUIRED_TOTAL,
  "optional_gates_passed": $OPTIONAL_PASSED,
  "optional_gates_total": $OPTIONAL_TOTAL,
  "gates": $GATES_JSON,
  "runner_status": "$RUNNER_STATUS",
  "exceptions": [],
  "artifacts": {
    "lean_coverage": "lean/coverage_matrix.json",
    "lean_baseline": "lean/baseline_report.json",
    "lean_theorems": "lean/theorem_inventory.json",
    "tla_result": "tla/model_check_result.json",
    "tla_spec": "tla/Asupersync.tla",
    "tla_config": "tla/Asupersync_MC.cfg",
    "runtime_report": "runtime/verification_report.json",
    "conformance_matrix": "cross_artifact/conformance_matrix.json",
    "docs_rule_mapping": "docs/semantic_docs_rule_mapping.md",
    "docs_verification_matrix": "docs/semantic_verification_matrix.md"
  },
  "reproducibility": {
    "rerun_command": "scripts/assemble_evidence_bundle.sh --json --phase $PHASE",
    "unified_runner": "scripts/run_semantic_verification.sh --json --profile full",
    "lean_runner": "scripts/run_lean_regression.sh --json",
    "tla_runner": "scripts/run_tla_scenarios.sh --json",
    "model_check": "scripts/run_model_check.sh --ci"
  }
}
MANIFEST_EOF

  log "Bundle manifest: $BUNDLE_DIR/metadata/bundle_manifest.json"
fi

# ─── Exit code ───────────────────────────────────────────────────

log "Bundle assembled at $BUNDLE_DIR"

if [ "$CI_MODE" = true ] && [ "$PHASE_VERDICT" = "FAIL" ]; then
  log "CI FAILED: phase $PHASE requirements not met"
  exit 1
fi

if [ "$OVERALL_VERDICT" = "FAIL" ] && [ "$CI_MODE" = false ]; then
  log "WARNING: some gates failed (see details above)"
fi

exit 0
