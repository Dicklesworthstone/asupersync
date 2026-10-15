#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# selftest_matrix.sh — no-root, no-cargo, no-network self-test for the matrix
# harness (cc_1 lane). Validates the planner -> runner -> scorer wiring and the
# BENCHMARK INTEGRITY guarantees BEFORE the orchestrator pays for the expensive
# Phase-2 root run. Exercises only the dry-run / pure-tooling paths:
#
#   1. matrix_bench.sh dry-run plan: correct cell count, valid JSON, all keys.
#   2. gen_tree.py --dry-run: rows parse, sizes within the profile bounds, and
#      the generator is DETERMINISTIC (same seed -> identical plan).
#   3. score_matrix.py --self-test (the scorer's own invariants).
#   4. integrity end-to-end: a synthetic results JSONL with a sha-MISS row is
#      scored; the failing cell MUST be excluded from headline ratios and listed
#      under "Failed or excluded rows" (a non-converging transfer is never a win).
#
# Run: bash scripts/atp_bench/selftest_matrix.sh
# ─────────────────────────────────────────────────────────────────────────────

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL + 1)); }
banner() { printf '\n== %s ==\n' "$*"; }

# ── 1. planner dry-run ───────────────────────────────────────────────────────
banner "1. matrix_bench.sh dry-run plan"
PLAN_OUT="$TMP/plan_run"
bash "$HERE/matrix_bench.sh" --out "$PLAN_OUT" \
    --workloads 50M,tree_small --regimes good,bad --tiers nocrypto >"$TMP/plan.jsonl" 2>"$TMP/plan.err" || {
        bad "planner exited non-zero"; cat "$TMP/plan.err" >&2; }
# 50M: 2 regimes x 1 tier x 2 methods x 3 reps = 12; tree_small: x5 reps = 20; total 32.
EXPECT_ROWS=32
GOT_ROWS="$(grep -c '"schema":"atp-bench-matrix-plan-v1"' "$TMP/plan.jsonl" || true)"
if [ "$GOT_ROWS" = "$EXPECT_ROWS" ]; then ok "plan has $GOT_ROWS cells (expected $EXPECT_ROWS)"; else bad "plan has $GOT_ROWS cells (expected $EXPECT_ROWS)"; fi
if python3 - "$TMP/plan.jsonl" <<'PY'
import json, sys
need = {"run_id", "git_head", "workload", "workload_path", "regime", "crypto_tier", "method", "rep", "netem"}
methods = set()
with open(sys.argv[1]) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)  # raises on malformed JSON
        missing = need - row.keys()
        assert not missing, f"row missing keys: {missing}"
        methods.add(row["method"])
# nocrypto tier must pair the lab atp method against the rsync daemon (apples-to-apples).
assert methods == {"atp-rq-lab", "rsyncd"}, f"unexpected methods: {methods}"
PY
then ok "every plan row is valid JSON with all keys; nocrypto methods = {atp-rq-lab, rsyncd}"; else bad "plan JSON/keys/methods check"; fi

# ── 2. gen_tree dry-run: bounds + determinism ────────────────────────────────
banner "2. gen_tree.py --dry-run (bounds + determinism)"
python3 "$HERE/gen_tree.py" --kind tree_small --root "$TMP/t" --dry-run >"$TMP/gt1.jsonl" 2>/dev/null || bad "gen_tree dry-run exited non-zero"
python3 "$HERE/gen_tree.py" --kind tree_small --root "$TMP/t" --dry-run >"$TMP/gt2.jsonl" 2>/dev/null || true
if diff -q "$TMP/gt1.jsonl" "$TMP/gt2.jsonl" >/dev/null 2>&1; then ok "gen_tree is deterministic (same seed -> identical plan)"; else bad "gen_tree NOT deterministic"; fi
if python3 - "$TMP/gt1.jsonl" <<'PY'
import json, sys
lo, hi = 1024, 1024 * 1024  # tree_small bounds
n = 0
with open(sys.argv[1]) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        assert lo <= r["size"] <= hi, f"size {r['size']} out of [{lo},{hi}]"
        assert "/" in r["path"], f"path not nested: {r['path']}"
        n += 1
assert n == 2000, f"expected 2000 files, got {n}"
PY
then ok "all 2000 tree_small files within [1KiB,1MiB], nested paths"; else bad "gen_tree bounds/count check"; fi

# ── 3. scorer self-test ──────────────────────────────────────────────────────
banner "3. score_matrix.py --self-test"
if python3 "$HERE/score_matrix.py" --self-test >/dev/null 2>&1; then ok "scorer self-test"; else bad "scorer self-test"; fi

# ── 4. integrity: sha-MISS excluded from headline ────────────────────────────
banner "4. integrity — failing cell excluded from headline ratios"
cat >"$TMP/results.jsonl" <<'JSONL'
{"workload":"50M","workload_kind":"file","size_bytes":52428800,"regime":"bad","crypto_tier":"nocrypto","method":"atp-rq-lab","rep":1,"wall_s":4.2,"peak_rss_kb":9000,"avg_rss_kb":8000,"sha_ok":true,"status":"ok"}
{"workload":"50M","workload_kind":"file","size_bytes":52428800,"regime":"bad","crypto_tier":"nocrypto","method":"atp-rq-lab","rep":2,"wall_s":4.6,"peak_rss_kb":9100,"avg_rss_kb":8100,"sha_ok":true,"status":"ok"}
{"workload":"50M","workload_kind":"file","size_bytes":52428800,"regime":"bad","crypto_tier":"nocrypto","method":"rsyncd","rep":1,"wall_s":9.0,"peak_rss_kb":4000,"avg_rss_kb":3500,"sha_ok":true,"status":"ok"}
{"workload":"50M","workload_kind":"file","size_bytes":52428800,"regime":"bad","crypto_tier":"nocrypto","method":"rsyncd","rep":2,"wall_s":9.4,"peak_rss_kb":4100,"avg_rss_kb":3600,"sha_ok":true,"status":"ok"}
{"workload":"50M","workload_kind":"file","size_bytes":52428800,"regime":"broken","crypto_tier":"nocrypto","method":"atp-rq-lab","rep":1,"wall_s":123.0,"peak_rss_kb":247000,"avg_rss_kb":200000,"sha_ok":false,"status":"sha_mismatch"}
{"workload":"50M","workload_kind":"file","size_bytes":52428800,"regime":"broken","crypto_tier":"nocrypto","method":"rsyncd","rep":1,"wall_s":7.5,"peak_rss_kb":4200,"avg_rss_kb":3700,"sha_ok":true,"status":"ok"}
JSONL
python3 "$HERE/score_matrix.py" "$TMP/results.jsonl" >"$TMP/scorecard.md" 2>/dev/null || bad "scorer crashed on synthetic results"
# atp wins the 'bad' cell (4.4/9.2 ~ 0.48) -> ratio table must contain a 'bad' row.
# (scorer's ratio table carries an "ATP streams" column between ATP method and
# rsync method, so allow one column between atp-rq-lab and rsyncd.)
if grep -qE '\| 50M \| bad \| nocrypto \| atp-rq-lab \|[^|]*\| rsyncd \|' "$TMP/scorecard.md"; then ok "atp-vs-rsync ratio present for verified 'bad' cell"; else bad "missing headline ratio for 'bad' cell"; fi
# The 123s sha-MISS cell MUST appear in failures, NOT in a headline ratio row.
# (scorer surfaces these under "## Failed or incomplete rows".)
if awk '/## Failed or incomplete rows/{f=1} f && /50M.*broken.*atp-rq-lab.*sha_mismatch/{print; found=1} END{exit !found}' "$TMP/scorecard.md" >/dev/null; then
    ok "sha-MISS (50M/broken) surfaced under 'Failed or incomplete rows'"
else bad "sha-MISS not surfaced as a failure"; fi
# Crucial: there must be NO ATP-vs-rsync ratio row for the broken regime (atp
# failed there). Scope the check to the "## ATP vs rsync ratios" SECTION only —
# the "Per-cell method medians" table legitimately lists the failed cell as n/a.
RATIOS_SECTION="$(awk '/^## ATP vs rsync ratios/{f=1;next} /^## /{f=0} f' "$TMP/scorecard.md")"
if printf '%s\n' "$RATIOS_SECTION" | grep -qE '\| 50M \| broken \|'; then
    bad "FAILED cell leaked into headline ratios (integrity violation)"
else ok "failing 'broken' cell correctly EXCLUDED from headline ratios"; fi

# ── summary ──────────────────────────────────────────────────────────────────
banner "summary"
printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
[ "$FAIL" = "0" ] || exit 1
echo "matrix harness self-test GREEN"
