#!/usr/bin/env bash
# API-v2 user-journey e2e runner (bead asupersync-dx-core-api-v2-u1z5hn.12).
#
# The epic's promise is a JOURNEY — "5-line hello world", "15-line fan-out",
# "deterministic test in one attribute". Unit tests prove the pieces; this
# script is the executable proof of the whole on-ramp:
#
#   1. dx_line_budget    the DX gate. Ceremony creeping back into the on-ramp
#                        programs is itself a regression, so their length is a
#                        TESTED INVARIANT, not a style preference.
#   2. run_example x3    compiles and RUNS examples/{hello,spawn_fanout,
#                        deterministic_test}.rs and asserts exit code + stdout.
#                        `cargo check --all-targets` compiles examples but never
#                        runs them, so before this lane the headline programs
#                        could exit non-zero and no gate would notice.
#   3. integration_lane  the tests/api_v2_integration.rs surface lane.
#   4. artifact_contract self-check over the emitted artifacts.
#
# Every stage appends one events.ndjson row carrying its own repro command, so
# a failure names the stage AND the exact command to re-run. `--rehearse-failure`
# exercises that attribution path on purpose (see AC4 in the bead).
#
# Cargo work is remote-required through `rch exec`; there is no local fallback.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="${API_V2_E2E_OUTPUT_ROOT:-${REPO_ROOT}/target/e2e-results/api_v2}"
RUN_ID="${API_V2_E2E_RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
TIMEOUT_SEC="${API_V2_E2E_TIMEOUT_SEC:-900}"
# Empty by default, and that is deliberate. Pinning a custom CARGO_TARGET_DIR
# forces a cold full-library rebuild AND a large artifact retrieval back to this
# host; measured here, that retrieval is what timed out (RCH-E309: the remote
# compile succeeded but the artifacts never arrived). Leaving it unset lets rch
# use its warm shared worker target, which is the same reason
# scripts/run_appspec_reference_journey_e2e.sh leaves it empty. Override with
# --target-dir when you deliberately want an isolated build.
TARGET_DIR="${API_V2_E2E_TARGET_DIR:-}"
RCH_BIN="${RCH_BIN:-rch}"
REHEARSE_FAILURE=0
SKIP_CARGO=0

# The DX budgets, counted in code lines (see dx_line_count).
#
# `hello`=7 and `spawn_fanout`=20 are the bead's mandated ceilings, deliberately
# above the 5/15 headline targets so attribute lines fit without letting real
# ceremony back in. Actual: 5 and 15, so both carry real headroom.
#
# `deterministic_test`=22 is set here rather than by the bead. It gets two more
# than the fan-out budget because it does two programs' work — it builds a
# fan-out AND asserts that two runs replay identically — and it currently sits
# at 20. A budget equal to the current count is a knife-edge that the next
# rustfmt reflow trips for no DX reason, which would teach agents to distrust
# the gate. Two lines of headroom keeps a real regression detectable (a stray
# builder, an unwrap ladder, a manual runtime setup is more than two lines)
# while an innocent reflow stays green.
declare -A LINE_BUDGET=(
    [hello]=7
    [spawn_fanout]=20
    [deterministic_test]=22
)
# Substring each example must print, so "it exited 0" cannot pass for "it ran".
# `hello` prints nothing by design — its contract is exit code only.
declare -A STDOUT_GOLDEN=(
    [hello]=""
    [spawn_fanout]=""
    [deterministic_test]="deterministic: replayed 28 under seed 7, quiescent, 0 violations"
)
EXAMPLES=(hello spawn_fanout deterministic_test)

usage() {
    cat <<'USAGE'
Usage: scripts/run_api_v2_e2e.sh [options]

Runs the API-v2 on-ramp journey end to end: the DX line budget, the three
on-ramp example programs, the api_v2_integration test lane, and an artifact
contract check. Emits summary.json + events.ndjson under the run directory.

Options:
  --output-root <dir>   Root for run_<id>/ artifacts (default: target/e2e-results/api_v2).
  --run-id <id>         Deterministic run id (default: UTC timestamp).
  --timeout-sec <sec>   Wall-clock timeout per cargo stage.
  --target-dir <dir>    CARGO_TARGET_DIR used by rch (isolated by default).
  --rch-bin <path>      rch binary (default: rch).
  --rehearse-failure    Also prove the harness pinpoints a broken stage and
                        emits a usable repro command (AC4). Adds two
                        deliberately-failing stages against scratch copies and
                        bogus targets; never mutates tracked files.
  --skip-cargo          Run only the stages that need no compiler (DX budget +
                        artifact contract). For fast local iteration; NOT a
                        substitute for a full run.
  -h, --help            Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)      OUTPUT_ROOT="${2:-}"; shift 2 ;;
        --run-id)           RUN_ID="${2:-}"; shift 2 ;;
        --timeout-sec)      TIMEOUT_SEC="${2:-}"; shift 2 ;;
        --target-dir)       TARGET_DIR="${2:-}"; shift 2 ;;
        --rch-bin)          RCH_BIN="${2:-}"; shift 2 ;;
        --rehearse-failure) REHEARSE_FAILURE=1; shift ;;
        --skip-cargo)       SKIP_CARGO=1; shift ;;
        -h|--help)          usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
EVENTS="${RUN_DIR}/events.ndjson"
SUMMARY="${RUN_DIR}/summary.json"
RUN_LOG="${RUN_DIR}/run.log"
mkdir -p "${RUN_DIR}"
: > "${EVENTS}"
: > "${RUN_LOG}"

RUN_START_MS=$(( $(date -u +%s%N) / 1000000 ))
STAGES_TOTAL=0
STAGES_FAILED=0
STAGES_BLOCKED=0

json_escape() {
    # Escape for embedding in a JSON string literal: backslash, quote, newline, tab.
    printf '%s' "$1" | python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])'
}

# emit_event <stage> <status> <duration_ms> <repro_command> <detail>
emit_event() {
    local stage="$1" status="$2" duration_ms="$3" repro="$4" detail="$5"
    STAGES_TOTAL=$((STAGES_TOTAL + 1))
    # Only "fail" is a failure. "skipped" is a recorded absence of evidence —
    # it must be visible in the artifacts (so nobody reads a skipped run as a
    # green one) without turning the run red.
    if [[ "${status}" == "fail" ]]; then
        STAGES_FAILED=$((STAGES_FAILED + 1))
    fi
    if [[ "${status}" == "blocked" ]]; then
        STAGES_BLOCKED=$((STAGES_BLOCKED + 1))
    fi
    printf '{"run_id":"%s","stage":"%s","status":"%s","duration_ms":%s,"repro_command":"%s","detail":"%s"}\n' \
        "$(json_escape "${RUN_ID}")" \
        "$(json_escape "${stage}")" \
        "$(json_escape "${status}")" \
        "${duration_ms}" \
        "$(json_escape "${repro}")" \
        "$(json_escape "${detail}")" \
        >> "${EVENTS}"
    printf '[%s] %-28s %-4s %6sms  %s\n' \
        "$(date -u +%H:%M:%SZ)" "${stage}" "${status}" "${duration_ms}" "${detail}" | tee -a "${RUN_LOG}"
}

now_ms() { printf '%s' $(( $(date -u +%s%N) / 1000000 )); }

# ---------------------------------------------------------------------------
# Stage 1: the DX line budget.
#
# Counts non-empty, non-comment lines: a doc comment explaining the example is
# documentation, not ceremony, and gating on raw `wc -l` would punish exactly
# the thing we want authors to add.
# ---------------------------------------------------------------------------
dx_line_count() {
    local file="$1"
    grep -cvE '^[[:space:]]*(//.*)?$' "${file}"
}

check_line_budget() {
    local dir="$1" stage_suffix="${2:-}"
    local start end name file budget actual violations=()
    start="$(now_ms)"
    for name in "${EXAMPLES[@]}"; do
        file="${dir}/${name}.rs"
        budget="${LINE_BUDGET[${name}]}"
        if [[ ! -f "${file}" ]]; then
            violations+=("${name}.rs is missing")
            continue
        fi
        actual="$(dx_line_count "${file}")"
        if (( actual > budget )); then
            violations+=("${name}.rs has ${actual} code lines, budget ${budget}")
        fi
    done
    end="$(now_ms)"
    local repro="bash scripts/run_api_v2_e2e.sh --skip-cargo"
    if [[ -n "${stage_suffix}" ]]; then
        # A rehearsal row must reproduce the rehearsal, not the real gate.
        repro="bash scripts/run_api_v2_e2e.sh --skip-cargo --rehearse-failure"
    fi
    if (( ${#violations[@]} > 0 )); then
        emit_event "dx_line_budget${stage_suffix}" "fail" "$((end - start))" "${repro}" \
            "DX budget exceeded: ${violations[*]}"
        return 1
    fi
    emit_event "dx_line_budget${stage_suffix}" "pass" "$((end - start))" "${repro}" \
        "on-ramp programs within budget (hello<=${LINE_BUDGET[hello]}, spawn_fanout<=${LINE_BUDGET[spawn_fanout]}, deterministic_test<=${LINE_BUDGET[deterministic_test]})"
    return 0
}

# ---------------------------------------------------------------------------
# Cargo stages, all remote-required.
# ---------------------------------------------------------------------------
require_rch() {
    if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
        echo "FATAL: rch is required (remote-only validation) and was not found at: ${RCH_BIN}" >&2
        echo "       This lane has no local cargo fallback by policy." >&2
        exit 1
    fi
}

# Cargo stages: ONE `rch exec` per cargo command.
#
# A single `rch exec -- bash -c '<all four stages>'` would pay source sync and
# dispatch once instead of four times, which is tempting because a cold first
# example measured 248s. It does not work: rch's admission classifier only
# offloads commands it recognises as compilation, so a bash wrapper is rejected
# as a "non-compilation command" and, under RCH_REQUIRE_REMOTE=1, refused
# outright with RCH-E301. Every repo script that offloads cargo puts the cargo
# command directly after `rch exec --`; that is a constraint, not a style.
#
# The cost is bounded because all stages share ${TARGET_DIR}: the first stage
# pays the library compile and the rest reuse it.
#
# rch_cargo <stage> <repro-label> <cargo args...>
#   Runs one cargo command remotely, refuses local fallback, and requires
#   POSITIVE evidence that a worker took it. Sets RCH_STATUS / RCH_OUT /
#   RCH_LOG / RCH_MS.
rch_cargo() {
    local stage="$1"; shift
    local out_file="${RUN_DIR}/${1}"; shift
    local rch_log="${RUN_DIR}/rch_${stage//[:\/]/_}.log"
    local start end
    # An explicit array, not an unquoted ${VAR:+...} expansion: word-splitting
    # rules differ between shells, and an empty TARGET_DIR must contribute zero
    # arguments rather than an empty one.
    local -a env_prefix=()
    if [[ -n "${TARGET_DIR}" ]]; then
        env_prefix=(env "CARGO_TARGET_DIR=${TARGET_DIR}")
    fi

    start="$(now_ms)"
    set +e
    # `--base HEAD --clean-overlay -o <lane paths>` rather than a plain
    # `rch exec --`. Two reasons, both learned the hard way:
    #
    #  1. COST. A plain invocation syncs the whole working tree. On shared `main`
    #     that includes every other agent's dirt plus untracked scratch dirs, and
    #     measured here it blew the 30s sync timeout and burned 8m16s before rch
    #     refused (RCH-E309). A clean baseline plus four files transfers almost
    #     nothing because the worker already has HEAD.
    #  2. GROUNDING. Evidence from a shared dirty tree cannot be attributed to
    #     this lane — a peer's half-finished edit could make it pass or fail.
    #     Overlaying only the paths this lane owns is what makes the result mean
    #     something about the on-ramp rather than about the tree.
    RCH_REQUIRE_REMOTE=1 timeout "${TIMEOUT_SEC}" "${RCH_BIN}" exec \
        --base HEAD --clean-overlay \
        -o examples/hello.rs -o examples/spawn_fanout.rs \
        -o examples/deterministic_test.rs -o tests/api_v2_integration.rs -- \
        "${env_prefix[@]}" "$@" > "${out_file}" 2> "${rch_log}"
    RCH_STATUS=$?
    set -e
    end="$(now_ms)"
    RCH_MS=$((end - start))
    RCH_OUT="${out_file}"
    # Remote command output does NOT arrive on `rch exec`'s stdout: rch relays
    # the worker's combined output (compile lines, test results, the program's
    # own stdout) on ITS stderr, so it lands in ${rch_log} and ${out_file}
    # stays empty. First proven by run_full10: integration tests printed
    # "test result: ok. 6 passed" into the rch log while the stdout capture
    # was 0 bytes, and the golden/pass checks read only the empty file — a
    # never-executed check reading a never-written stream. Evidence checks
    # must therefore accept either stream; they still require the POSITIVE
    # marker, so this stays fail-closed.
    RCH_LOG="${rch_log}"
    cat "${rch_log}" >> "${RUN_LOG}"

    # Positive-only offload evidence. An earlier version of this check accepted
    # any /RCH-E[0-9]+/ marker and therefore treated the REFUSAL code RCH-E301
    # as proof of offload — a fail-open gate inside the gate that exists to stop
    # fail-open. Only a named worker counts.
    RCH_REMOTE_EVIDENCE="$(grep -oE 'Selected worker: [^ ]+|\[RCH\] remote [a-z0-9]+' "${rch_log}" | head -1 || true)"
    RCH_REFUSAL="$(grep -oE 'RCH-E[0-9]+' "${rch_log}" | head -1 || true)"
    # Infrastructure failure is NOT a code failure, and the two must never be
    # reported the same way: a worker sync timeout that reads as "the example is
    # broken" sends the next agent debugging the wrong thing. Captured as a
    # distinct classification, still non-green (see the `blocked` handling).
    RCH_INFRA_BLOCK=""
    if grep -qE 'refusing local fallback|remote retries exhausted|sync_to_remote: timed out|Remote build failed on all' "${rch_log}"; then
        RCH_INFRA_BLOCK="$(grep -oE 'sync_to_remote: timed out after [0-9]+ms|Remote build failed on all [0-9]+ tried worker\(s\)|remote retries exhausted|non-compilation command' "${rch_log}" | head -1 || true)"
        RCH_INFRA_BLOCK="${RCH_INFRA_BLOCK:-rch refused or could not complete remote execution}"
    fi
    return 0
}

# offload_ok <stage> <repro>  — emits a fail event and returns 1 when the stage
# has no positive remote evidence, so a local or refused run can never be
# reported as fleet evidence.
offload_ok() {
    local stage="$1" repro="$2"
    if [[ -n "${RCH_REFUSAL}" || -n "${RCH_INFRA_BLOCK}" ]]; then
        emit_event "${stage}" "blocked" "${RCH_MS}" "${repro}" \
            "INFRASTRUCTURE, not code: ${RCH_REFUSAL:+${RCH_REFUSAL} }${RCH_INFRA_BLOCK:-rch refused the command}. No remote execution completed, so this stage produced no evidence either way."
        return 1
    fi
    if [[ -z "${RCH_REMOTE_EVIDENCE}" ]]; then
        emit_event "${stage}" "blocked" "${RCH_MS}" "${repro}" \
            "no named-worker evidence in rch output; refusing to report this as fleet evidence"
        return 1
    fi
    return 0
}

run_example() {
    local name="$1"
    local repro="RCH_REQUIRE_REMOTE=1 ${RCH_BIN} exec --base HEAD --clean-overlay -o examples/${name}.rs -o tests/api_v2_integration.rs -- cargo run --quiet --example ${name}"
    rch_cargo "run_example:${name}" "${name}.stdout" cargo run --quiet --example "${name}"
    offload_ok "run_example:${name}" "${repro}" || return 1

    if (( RCH_STATUS != 0 )); then
        emit_event "run_example:${name}" "fail" "${RCH_MS}" "${repro}" \
            "exit status ${RCH_STATUS}; stderr in rch_run_example_${name}.log"
        return 1
    fi
    local golden="${STDOUT_GOLDEN[${name}]:-}"
    if [[ -n "${golden}" ]] && ! grep -qF "${golden}" "${RCH_OUT}" "${RCH_LOG}"; then
        emit_event "run_example:${name}" "fail" "${RCH_MS}" "${repro}" \
            "stdout golden not found; expected substring '${golden}'"
        return 1
    fi
    emit_event "run_example:${name}" "pass" "${RCH_MS}" "${repro}" \
        "exit 0${golden:+, stdout golden matched} (${RCH_REMOTE_EVIDENCE})"
    return 0
}

run_integration_lane() {
    local repro="RCH_REQUIRE_REMOTE=1 ${RCH_BIN} exec --base HEAD --clean-overlay -o tests/api_v2_integration.rs -- cargo test -p asupersync --test api_v2_integration --features test-internals"
    rch_cargo "integration_lane" "integration_lane.log" \
        cargo test -p asupersync --test api_v2_integration --features test-internals
    offload_ok "integration_lane" "${repro}" || return 1

    if (( RCH_STATUS != 0 )); then
        emit_event "integration_lane" "fail" "${RCH_MS}" "${repro}" \
            "exit status ${RCH_STATUS}; see integration_lane.log"
        return 1
    fi
    # An empty lane is a silently-passing lane. Require observed test results.
    local passed
    passed="$(grep -ohE 'test result: ok\. [0-9]+ passed' "${RCH_OUT}" "${RCH_LOG}" | grep -oE '[0-9]+' | head -1 || true)"
    if [[ -z "${passed}" || "${passed}" -eq 0 ]]; then
        emit_event "integration_lane" "fail" "${RCH_MS}" "${repro}" \
            "lane reported no passing tests; a lane that runs nothing proves nothing"
        return 1
    fi
    emit_event "integration_lane" "pass" "${RCH_MS}" "${repro}" \
        "${passed} tests passed (${RCH_REMOTE_EVIDENCE})"
    return 0
}

run_cargo_stages() {
    local rc=0 example
    for example in "${EXAMPLES[@]}"; do
        run_example "${example}" || rc=1
    done
    run_integration_lane || rc=1

    # Every expected stage must have reported. A missing stage is a silent gap,
    # not a pass.
    local expected missing=()
    for expected in "${EXAMPLES[@]}"; do
        grep -q "\"stage\":\"run_example:${expected}\"" "${EVENTS}" || missing+=("run_example:${expected}")
    done
    grep -q '"stage":"integration_lane"' "${EVENTS}" || missing+=("integration_lane")
    if (( ${#missing[@]} > 0 )); then
        emit_event "cargo_stage_coverage" "fail" 0 "bash scripts/run_api_v2_e2e.sh" \
            "stages never reported: ${missing[*]}"
        rc=1
    fi
    return "${rc}"
}

# ---------------------------------------------------------------------------
# AC4: rehearse the failure modes so stage attribution + repro emission are
# themselves tested. Uses scratch copies and a bogus target; tracked files are
# never modified.
# ---------------------------------------------------------------------------
rehearse_failure() {
    local scratch="${RUN_DIR}/rehearsal"
    mkdir -p "${scratch}"
    local name
    for name in "${EXAMPLES[@]}"; do
        cp "${REPO_ROOT}/examples/${name}.rs" "${scratch}/${name}.rs"
    done
    # Bust the budget on the copy only.
    local i
    for i in $(seq 1 40); do
        printf 'let _ceremony_%s = %s;\n' "${i}" "${i}" >> "${scratch}/hello.rs"
    done

    local before_failed="${STAGES_FAILED}"
    if check_line_budget "${scratch}" ":rehearsal"; then
        echo "FATAL: rehearsal did not fail the DX budget; the gate cannot detect ceremony" >&2
        return 1
    fi
    if (( STAGES_FAILED != before_failed + 1 )); then
        echo "FATAL: rehearsal failure was not recorded as a failed stage" >&2
        return 1
    fi
    # Confirm the emitted row actually names the stage and carries a repro.
    local row
    row="$(grep '"stage":"dx_line_budget:rehearsal"' "${EVENTS}" | tail -1)"
    if [[ -z "${row}" ]] || ! grep -q '"repro_command":"[^"]\+"' <<<"${row}"; then
        echo "FATAL: rehearsed failure row missing stage attribution or repro command" >&2
        return 1
    fi
    echo "REHEARSAL OK: a broken on-ramp program fails dx_line_budget with a repro command" | tee -a "${RUN_LOG}"
    return 0
}

# ---------------------------------------------------------------------------
# Execute.
# ---------------------------------------------------------------------------
OVERALL=0

check_line_budget "${REPO_ROOT}/examples" || OVERALL=1

if (( SKIP_CARGO == 0 )); then
    require_rch
    run_cargo_stages || OVERALL=1
else
    emit_event "cargo_stages" "skipped" 0 "bash scripts/run_api_v2_e2e.sh" \
        "--skip-cargo requested; example runs and integration lane did NOT execute"
fi

if (( REHEARSE_FAILURE == 1 )); then
    # The rehearsal is expected to add one failed stage; it must not turn the
    # run red, so its bookkeeping is reconciled in the summary below.
    rehearse_failure || OVERALL=1
    REHEARSED=1
else
    REHEARSED=0
fi

RUN_END_MS=$(( $(date -u +%s%N) / 1000000 ))
DURATION_MS=$((RUN_END_MS - RUN_START_MS))

# Rehearsed failures are deliberate; exclude them from the pass/fail verdict but
# keep them in events.ndjson so the evidence is auditable.
REHEARSED_FAILURES="$(grep -c '"stage":"[^"]*:rehearsal"' "${EVENTS}" || true)"
REAL_FAILURES=$((STAGES_FAILED - REHEARSED_FAILURES))
if (( REAL_FAILURES < 0 )); then REAL_FAILURES=0; fi
if (( REAL_FAILURES > 0 )); then OVERALL=1; else OVERALL=${OVERALL}; fi

python3 - "${RUN_DIR}" "${RUN_ID}" "${DURATION_MS}" "${STAGES_TOTAL}" "${REAL_FAILURES}" \
    "${REHEARSED_FAILURES}" "${REHEARSED}" "${SKIP_CARGO}" "${STAGES_BLOCKED}" <<'PY'
import json, sys, pathlib

run_dir = pathlib.Path(sys.argv[1])
run_id, duration_ms, total, real_failed, rehearsed_failed, rehearsed, skip_cargo, blocked = sys.argv[2:10]

events = []
for i, line in enumerate((run_dir / "events.ndjson").read_text().splitlines(), start=1):
    line = line.strip()
    if not line:
        continue
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError as exc:
        print(f"API_V2_E2E FAIL: events.ndjson line {i} is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)

# Artifact contract (AC3): every row carries the schema fields, and a failing
# row must carry a repro command or the harness is not actionable.
required = {"run_id", "stage", "status", "duration_ms", "repro_command", "detail"}
errors = []
for e in events:
    missing = required - set(e)
    if missing:
        errors.append(f"event {e.get('stage')!r} missing fields: {sorted(missing)}")
    if e.get("status") == "fail" and not e.get("repro_command"):
        errors.append(f"failed stage {e.get('stage')!r} carries no repro_command")
    if not isinstance(e.get("duration_ms"), int):
        errors.append(f"event {e.get('stage')!r} duration_ms is not an integer")

summary = {
    "schema": "api-v2-user-journey-e2e-v1",
    "run_id": run_id,
    "duration_ms": int(duration_ms),
    "stages_total": int(total),
    "stages_failed": int(real_failed),
    "stages_blocked": int(blocked),
    "rehearsed_failures": int(rehearsed_failed),
    "failure_rehearsed": rehearsed == "1",
    "cargo_stages_skipped": skip_cargo == "1",
    "status": (
        "fail"
        if int(real_failed) > 0 or errors
        else "blocked" if int(blocked) > 0 else "pass"
    ),
    "stages": [{k: e[k] for k in ("stage", "status", "duration_ms")} for e in events],
    "artifact_contract_errors": errors,
    "no_claim": (
        (
            "DX line budget checked ONLY. The example programs were not compiled or run and "
            "the api_v2_integration lane did not execute, so this run is not journey evidence."
            if skip_cargo == "1"
            else "Proves the on-ramp programs run, stay within their DX line budget, and that "
            "the api_v2_integration surface lane passes."
        )
        + " Does not prove broad workspace health, release readiness, or performance."
    ),
}
(run_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

if errors:
    print("API_V2_E2E FAIL: artifact contract violations", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)
print(
    f"API_V2_E2E {summary['status'].upper()}: {total} stages, {real_failed} failed"
    + (f", {rehearsed_failed} rehearsed failure(s)" if int(rehearsed_failed) else "")
    + f", {int(duration_ms)/1000:.1f}s"
)
print(f"  artifacts: {run_dir}/{{events.ndjson,summary.json,run.log}}")
PY
CONTRACT_STATUS=$?
if (( CONTRACT_STATUS != 0 )); then
    OVERALL=1
fi

if (( OVERALL != 0 )); then
    echo "API_V2_E2E FAILED — see ${RUN_DIR}/events.ndjson for the failing stage and its repro command" >&2
fi
exit "${OVERALL}"
