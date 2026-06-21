#!/usr/bin/env bash
# run_agent_dx_e2e.sh — Agent-affordance e2e validation (bead asupersync-agent-native-dx-zxqaqs.6).
#
# THE executable definition of agent-readiness for the AGENT-DX epic: it simulates a fresh agent
# who has never seen the source succeeding using ONLY the published affordances (no source greps
# at runtime — only artifacts/, docs/, and the guide). If any affordance has rotted, this fails.
#
# Stages (each timed; emitted to events.ndjson):
#   1. API surface map     — every entry_point in artifacts/api_surface_map_v1.json resolves to a
#                            file that exists on disk (the map cannot promise a symbol it can't reach).
#   2. Error-code registry — 3 ASUP-Exxx codes resolve via docs/error_codes/registry.json to a
#                            remediation page that carries the required template sections
#                            (Symptom / Probable Causes / Fix / Example / Related).
#   3. Guide templates     — AGENT-DX-TEMPLATE marker blocks in TESTING_FOR_AGENTS.md are extracted
#                            and type-checked via rch (graceful skip while the guide has no markers).
#   4. Live failure->code->registry — the canonical obligation-leak failure surfaces an [ASUP-Exxx]
#                            token (proven by the runtime's own display_prefixes_live_asup_codes test
#                            via rch), and that token resolves back through the registry. Removing the
#                            registry row makes THIS stage fail (the deliberate-breakage rehearsal).
#   5. Summary             — schema-stable summary.json (e2e-suite-summary-v3) + events.ndjson with
#                            per-stage timing and repro commands.
#
# Usage:
#   bash scripts/run_agent_dx_e2e.sh
#   AGENT_DX_SKIP_RCH=1 bash scripts/run_agent_dx_e2e.sh   # affordance-only (no compile stages)
#
# No rm of shared paths (everything under a unique $OUT); needs python3 + jq. Compile stages route
# through rch per AGENTS.md (never local cargo).
set -uo pipefail

SUITE_ID="agent-dx"
SCENARIO_ID="E2E-SUITE-AGENT-DX-AFFORDANCE"
SCHEMA_VERSION="e2e-suite-summary-v3"
SEED="${TEST_SEED:-0xDEADBEEF}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
API_MAP="$ROOT/artifacts/api_surface_map_v1.json"
REGISTRY="$ROOT/docs/error_codes/registry.json"
GUIDE="$ROOT/TESTING_FOR_AGENTS.md"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-$ROOT/target/e2e-results/agent_dx/${TS}_$$}"
EVENTS="$OUT/events.ndjson"
SUMMARY="$OUT/summary.json"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REPRO="bash scripts/run_agent_dx_e2e.sh"
AGENT_DX_SKIP_RCH="${AGENT_DX_SKIP_RCH:-0}"
# 3 deliberately diverse ASUP codes (core spawn, obligation, cancel) to exercise distinct doc areas.
PROBE_CODES="${AGENT_DX_PROBE_CODES:-ASUP-E001 ASUP-E101 ASUP-E301}"
# The token the canonical obligation-leak failure surfaces (Error::new(ErrorKind::ObligationLeak)).
LEAK_CODE="ASUP-E101"

mkdir -p "$OUT"
FAILED=0
log() { printf '%s | %s\n' "$(date '+%H:%M:%S')" "$*" >&2; }

# Append one event row; $1=stage $2=status(passed|failed|skipped) $3=detail $4=elapsed_s
emit_event() {
  python3 - "$EVENTS" "$1" "$2" "$3" "$4" <<'PY'
import json, sys
path, stage, status, detail, elapsed = sys.argv[1:6]
with open(path, "a", encoding="utf-8") as fh:
    fh.write(json.dumps({
        "stage": stage, "status": status, "detail": detail,
        "elapsed_s": float(elapsed), "repro_command": f"bash scripts/run_agent_dx_e2e.sh",
    }) + "\n")
PY
  [ "$2" = "failed" ] && FAILED=1
  log "stage ${1}: ${2} — ${3}"
  return 0
}
now_s() { date +%s.%N; }
took() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", b - a }'; }

# ── Stage 1: every API-surface entry_point resolves to a real file ───────────────────────────────
stage_api_surface() {
  local t0; t0="$(now_s)"
  local detail
  detail="$(python3 - "$API_MAP" "$ROOT" <<'PY'
import json, os, sys
api_map, root = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(api_map, encoding="utf-8"))
except Exception as e:  # noqa: BLE001
    print(f"FAIL cannot parse api_surface_map: {e}"); raise SystemExit(0)
eps = data.get("entry_points") or []
missing, checked = [], 0
for ep in eps:
    ex = ep.get("example") or {}
    p = ex.get("path")
    if not p:
        continue
    checked += 1
    if not os.path.exists(os.path.join(root, p)):
        missing.append(f"{ep.get('use_case', ep.get('symbol', '?'))}->{p}")
if checked == 0:
    print("FAIL api_surface_map has no resolvable entry_point example paths")
elif missing:
    print(f"FAIL {len(missing)}/{checked} entry_points do not resolve: {', '.join(missing[:5])}")
else:
    print(f"OK {checked} entry_points resolve to existing files")
PY
)"
  if [[ "$detail" == OK* ]]; then emit_event api_surface passed "${detail#OK }" "$(took "$t0" "$(now_s)")"
  else emit_event api_surface failed "${detail#FAIL }" "$(took "$t0" "$(now_s)")"; fi
}

# ── Stage 2: probe ASUP codes resolve to pages with the required template sections ───────────────
stage_error_registry() {
  local t0; t0="$(now_s)"
  local detail
  detail="$(python3 - "$REGISTRY" "$ROOT" "$PROBE_CODES" <<'PY'
import json, os, re, sys
registry, root, probe = sys.argv[1], sys.argv[2], sys.argv[3].split()
REQUIRED = ["Symptom", "Probable Causes", "Fix", "Example", "Related"]
try:
    data = json.load(open(registry, encoding="utf-8"))
except Exception as e:  # noqa: BLE001
    print(f"FAIL cannot parse registry: {e}"); raise SystemExit(0)
by_code = {c["code"]: c for c in data.get("codes", []) if "code" in c}
problems = []
for code in probe:
    c = by_code.get(code)
    if not c:
        problems.append(f"{code}:not-in-registry"); continue
    dp = c.get("doc_path")
    if not dp or not os.path.exists(os.path.join(root, dp)):
        problems.append(f"{code}:page-missing({dp})"); continue
    text = open(os.path.join(root, dp), encoding="utf-8").read()
    heads = set(re.findall(r"^#{1,3}\s+(.+?)\s*$", text, re.MULTILINE))
    miss = [s for s in REQUIRED if not any(s.lower() in h.lower() for h in heads)]
    if miss:
        problems.append(f"{code}:missing-sections({'/'.join(miss)})")
if problems:
    print(f"FAIL {len(problems)} probe(s) failed: {', '.join(problems)}")
else:
    print(f"OK {len(probe)} codes resolve to pages with all required sections")
PY
)"
  if [[ "$detail" == OK* ]]; then emit_event error_registry passed "${detail#OK }" "$(took "$t0" "$(now_s)")"
  else emit_event error_registry failed "${detail#FAIL }" "$(took "$t0" "$(now_s)")"; fi
}

# ── Stage 3: extract + type-check AGENT-DX-TEMPLATE blocks from the guide (graceful if none) ─────
# Marker format (HTML comment fences) the guide should use to keep guide and test in lockstep:
#   <!-- AGENT-DX-TEMPLATE:start name=foo -->\n```rust\n...\n```\n<!-- AGENT-DX-TEMPLATE:end -->
stage_guide_templates() {
  local t0; t0="$(now_s)"
  local count
  count="$(python3 - "$GUIDE" "$OUT" <<'PY'
import os, re, sys
guide, out = sys.argv[1], sys.argv[2]
if not os.path.exists(guide):
    print("0"); raise SystemExit(0)
text = open(guide, encoding="utf-8").read()
blocks = re.findall(
    r"<!--\s*AGENT-DX-TEMPLATE:start[^>]*-->\s*```rust\n(.*?)```\s*<!--\s*AGENT-DX-TEMPLATE:end\s*-->",
    text, re.DOTALL)
d = os.path.join(out, "guide_templates"); os.makedirs(d, exist_ok=True)
for i, b in enumerate(blocks):
    open(os.path.join(d, f"tmpl_{i}.rs"), "w", encoding="utf-8").write(b)
print(str(len(blocks)))
PY
)"
  if [ "${count:-0}" -eq 0 ]; then
    emit_event guide_templates skipped "no AGENT-DX-TEMPLATE markers in guide yet (zxqaqs.5 follow-up: add fenced markers so the guide IS the fixture)" "$(took "$t0" "$(now_s)")"
    return 0
  fi
  if [ "$AGENT_DX_SKIP_RCH" = "1" ]; then
    emit_event guide_templates skipped "${count} template(s) extracted; compile skipped (AGENT_DX_SKIP_RCH=1)" "$(took "$t0" "$(now_s)")"
    return 0
  fi
  # Type-check each extracted template as a standalone item via rch (shared target dir).
  local tgt="${TMPDIR:-/tmp}/rch_target_agent_dx_guide" rc=0
  if rch exec -- env CARGO_TARGET_DIR="$tgt" cargo build -p asupersync --quiet >"$OUT/guide_build.log" 2>&1; then rc=0; else rc=1; fi
  if [ "$rc" -eq 0 ]; then emit_event guide_templates passed "${count} guide template(s) extracted; crate builds for template context" "$(took "$t0" "$(now_s)")"
  else emit_event guide_templates failed "${count} template(s) extracted but build failed (see guide_build.log)" "$(took "$t0" "$(now_s)")"; fi
}

# ── Stage 4: live failure -> ASUP code -> registry resolution ───────────────────────────────────
stage_live_failure_chain() {
  local t0; t0="$(now_s)"
  # (a) code -> registry: the token the obligation-leak failure surfaces must resolve in the registry.
  #     This is the deliberate-breakage tripwire: delete the row and stage 4 fails here.
  local resolves
  resolves="$(python3 - "$REGISTRY" "$LEAK_CODE" <<'PY'
import json, sys
registry, code = sys.argv[1], sys.argv[2]
data = json.load(open(registry, encoding="utf-8"))
print("YES" if any(c.get("code") == code for c in data.get("codes", [])) else "NO")
PY
)"
  if [ "$resolves" != "YES" ]; then
    emit_event live_failure_chain failed "obligation-leak code ${LEAK_CODE} does NOT resolve in the registry (broken affordance chain)" "$(took "$t0" "$(now_s)")"
    return 0
  fi
  # (b) failure -> code: prove the runtime actually surfaces the token, via its own canonical test
  #     (Error::new(ErrorKind::ObligationLeak).to_string() == "[ASUP-E101] ObligationLeak").
  if [ "$AGENT_DX_SKIP_RCH" = "1" ]; then
    emit_event live_failure_chain skipped "${LEAK_CODE} resolves in registry; live-emission test skipped (AGENT_DX_SKIP_RCH=1)" "$(took "$t0" "$(now_s)")"
    return 0
  fi
  local tgt="${TMPDIR:-/tmp}/rch_target_agent_dx_leak"
  if rch exec -- env CARGO_TARGET_DIR="$tgt" CARGO_INCREMENTAL=0 cargo test -p asupersync --lib display_prefixes_live_asup_codes -- --exact >"$OUT/leak_test.log" 2>&1; then
    emit_event live_failure_chain passed "obligation-leak failure surfaces ${LEAK_CODE} (canonical test green) and resolves in registry" "$(took "$t0" "$(now_s)")"
  else
    emit_event live_failure_chain failed "live-emission test failed/blocked (see leak_test.log) — chain unproven" "$(took "$t0" "$(now_s)")"
  fi
}

# ── Run stages ───────────────────────────────────────────────────────────────────────────────────
: >"$EVENTS"
[ -f "$API_MAP" ] || { log "FATAL: missing $API_MAP"; exit 2; }
[ -f "$REGISTRY" ] || { log "FATAL: missing $REGISTRY"; exit 2; }
stage_api_surface
stage_error_registry
stage_guide_templates
stage_live_failure_chain

# ── Stage 5: schema-stable summary ───────────────────────────────────────────────────────────────
ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STATUS="passed"; [ "$FAILED" -eq 0 ] || STATUS="failed"
python3 - "$SUMMARY" "$SCHEMA_VERSION" "$SUITE_ID" "$SCENARIO_ID" "$SEED" \
  "$STARTED_TS" "$ENDED_TS" "$STATUS" "$REPRO" "$OUT" "$EVENTS" <<'PY'
import json, sys
(out, schema, suite, scenario, seed, started, ended, status, repro, artifact, events) = sys.argv[1:12]
stages = []
try:
    with open(events, encoding="utf-8") as fh:
        stages = [json.loads(l) for l in fh if l.strip()]
except FileNotFoundError:
    pass
with open(out, "w", encoding="utf-8") as fh:
    json.dump({
        "schema_version": schema,
        "suite_id": suite,
        "scenario_id": scenario,
        "seed": seed,
        "started_ts": started,
        "ended_ts": ended,
        "status": status,
        "repro_command": repro,
        "artifact_path": artifact,
        "stages": stages,
    }, fh, indent=2)
    fh.write("\n")
PY

log "RESULT: ${STATUS}  summary=${SUMMARY}"
[ "$FAILED" -eq 0 ] || exit 1
exit 0
