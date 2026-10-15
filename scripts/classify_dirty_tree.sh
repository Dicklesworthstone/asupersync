#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
FORMAT="text"
RUN_CARGO_PROBE=0

usage() {
    cat <<'USAGE'
Usage: scripts/classify_dirty_tree.sh [--json] [--cargo-probe] [--self-test]

Non-destructively classify dirty shared-main state. The script never deletes,
resets, cleans, branches, worktrees, stashes, or modifies repository files.

Options:
  --json         Emit JSON report instead of text.
  --cargo-probe Probe rch queue state and report whether cargo validation is blocked.
  --self-test   Run parser/classifier self-tests and exit.
USAGE
}

for arg in "$@"; do
    case "$arg" in
        --json) FORMAT="json" ;;
        --cargo-probe) RUN_CARGO_PROBE=1 ;;
        --self-test) SELF_TEST=1 ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            usage >&2
            exit 2
            ;;
    esac
done

SELF_TEST="${SELF_TEST:-0}"

classify_path() {
    local path="$1"
    case "$path" in
        .beads/issues.jsonl)
            printf 'beads-tracker-state'
            ;;
        src/runtime/state.rs|src/obligation/lyapunov.rs)
            printf 'asupersync-l0q0rs/read-biased-snapshot-or-governor'
            ;;
        src/runtime/config.rs|src/runtime/builder.rs|src/runtime/scheduler/three_lane.rs)
            printf 'asupersync-99if94/runtime-scheduler-config'
            ;;
        benches/scheduler_benchmark.rs|benches/cancel_drain_bench.rs)
            printf 'asupersync-op8n0f/benchmark-evidence'
            ;;
        scripts/classify_dirty_tree.sh)
            printf 'asupersync-8cjqbt/dirty-tree-classifier'
            ;;
        scripts/run_scheduler_global_ready_contention_smoke.sh)
            printf 'asupersync-yo65m7/ready-contention-smoke'
            ;;
        scripts/run_governor_state_snapshot_smoke.sh)
            printf 'asupersync-9dv8em/governor-state-snapshot-smoke'
            ;;
        fuzz/fuzz_targets/h2_*|fuzz/fuzz_targets/distributed_snapshot.rs)
            printf 'asupersync-q94ai8/testing-fuzzing'
            ;;
        src/observability/otlp_*_audit_test.rs)
            printf 'asupersync-7h2gyz/observability-otlp-audit'
            ;;
        .*-artifacts/*|topology-smoke-out/*)
            printf 'asupersync-beih6k/generated-artifact-output'
            ;;
        *)
            printf 'unknown'
            ;;
    esac
}

recommend_action() {
    local status="$1"
    local path="$2"
    local cluster="$3"
    case "$status:$cluster" in
        \?\?:asupersync-beih6k/generated-artifact-output)
            printf 'preserve; generated output requires owner confirmation before deletion'
            ;;
        *:beads-tracker-state)
            printf 'stage only with the matching bead work; do not mix unrelated tracker updates'
            ;;
        *:asupersync-8cjqbt/dirty-tree-classifier)
            printf 'stage with asupersync-8cjqbt after validation; keep unrelated dirty work out of the commit'
            ;;
        \?\?:*)
            printf 'preserve untracked work; identify owner before staging or removal'
            ;;
        *:unknown)
            printf 'inspect diff and assign owner before validation'
            ;;
        *)
            printf 'coordinate with suspected owner/bead before staging or validation'
            ;;
    esac
}

json_escape() {
    printf '%s' "$1" | jq -Rsa . | tr -d '\n'
}

self_test() {
    local failed=0

    local actual
    actual="$(classify_path "src/runtime/state.rs")"
    [[ "$actual" == "asupersync-l0q0rs/read-biased-snapshot-or-governor" ]] || {
        echo "self-test failed: state.rs cluster=$actual" >&2
        failed=1
    }

    actual="$(classify_path "src/runtime/scheduler/three_lane.rs")"
    [[ "$actual" == "asupersync-99if94/runtime-scheduler-config" ]] || {
        echo "self-test failed: three_lane cluster=$actual" >&2
        failed=1
    }

    actual="$(classify_path "benches/scheduler_benchmark.rs")"
    [[ "$actual" == "asupersync-op8n0f/benchmark-evidence" ]] || {
        echo "self-test failed: scheduler benchmark cluster=$actual" >&2
        failed=1
    }

    actual="$(classify_path "fuzz/fuzz_targets/h2_request_with_huge_authority.rs")"
    [[ "$actual" == "asupersync-q94ai8/testing-fuzzing" ]] || {
        echo "self-test failed: h2 fuzz cluster=$actual" >&2
        failed=1
    }

    actual="$(classify_path "src/observability/otlp_dns_resolution_failure_audit_test.rs")"
    [[ "$actual" == "asupersync-7h2gyz/observability-otlp-audit" ]] || {
        echo "self-test failed: otlp cluster=$actual" >&2
        failed=1
    }

    actual="$(classify_path "scripts/classify_dirty_tree.sh")"
    [[ "$actual" == "asupersync-8cjqbt/dirty-tree-classifier" ]] || {
        echo "self-test failed: classifier script cluster=$actual" >&2
        failed=1
    }

    actual="$(classify_path "scripts/run_governor_state_snapshot_smoke.sh")"
    [[ "$actual" == "asupersync-9dv8em/governor-state-snapshot-smoke" ]] || {
        echo "self-test failed: governor smoke script cluster=$actual" >&2
        failed=1
    }

    actual="$(recommend_action "??" "scripts/classify_dirty_tree.sh" "asupersync-8cjqbt/dirty-tree-classifier")"
    [[ "$actual" == "stage with asupersync-8cjqbt after validation; keep unrelated dirty work out of the commit" ]] || {
        echo "self-test failed: classifier script action=$actual" >&2
        failed=1
    }

    actual="$(recommend_action "??" "topology-smoke-out/run.log" "asupersync-beih6k/generated-artifact-output")"
    [[ "$actual" == "preserve; generated output requires owner confirmation before deletion" ]] || {
        echo "self-test failed: generated action=$actual" >&2
        failed=1
    }

    if [[ "$failed" == "0" ]]; then
        echo "DIRTY_TREE_CLASSIFIER_SELF_TEST passed"
    fi
    exit "$failed"
}

if [[ "$SELF_TEST" == "1" ]]; then
    self_test
fi

cd "$PROJECT_ROOT"

BRANCH="$(git branch --show-current)"
UPSTREAM="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
UPSTREAM_STATE="none"
if [[ -n "$UPSTREAM" ]]; then
    LEFT_RIGHT="$(git rev-list --left-right --count "${UPSTREAM}...HEAD" 2>/dev/null || printf '0\t0')"
    BEHIND="$(awk '{print $1}' <<<"$LEFT_RIGHT")"
    AHEAD="$(awk '{print $2}' <<<"$LEFT_RIGHT")"
    UPSTREAM_STATE="upstream=${UPSTREAM},ahead=${AHEAD},behind=${BEHIND}"
fi

STATUS_RAW="$(git status --porcelain=v1)"
STAGED_COUNT=0
UNSTAGED_COUNT=0
UNTRACKED_COUNT=0
CARGO_BLOCKED=false
RCH_QUEUE_SUMMARY="not_probed"
REPORT_ROWS=()

while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    status="${line:0:2}"
    path="${line:3}"
    index_status="${status:0:1}"
    worktree_status="${status:1:1}"
    if [[ "$status" == "??" ]]; then
        UNTRACKED_COUNT=$((UNTRACKED_COUNT + 1))
    else
        [[ "$index_status" != " " ]] && STAGED_COUNT=$((STAGED_COUNT + 1))
        [[ "$worktree_status" != " " ]] && UNSTAGED_COUNT=$((UNSTAGED_COUNT + 1))
    fi
    cluster="$(classify_path "$path")"
    action="$(recommend_action "$status" "$path" "$cluster")"
    REPORT_ROWS+=("${status}|${path}|${cluster}|${action}")
done <<<"$STATUS_RAW"

if [[ "$RUN_CARGO_PROBE" == "1" ]]; then
    if command -v rch >/dev/null 2>&1; then
        RCH_QUEUE_SUMMARY="$(rch queue | tr '\n' ' ' | sed 's/[[:space:]][[:space:]]*/ /g')"
    else
        RCH_QUEUE_SUMMARY="rch_not_found"
    fi
    if (( UNSTAGED_COUNT > 0 || UNTRACKED_COUNT > 0 )); then
        CARGO_BLOCKED=true
    fi
fi

if [[ "$FORMAT" == "json" ]]; then
    {
        printf '{'
        printf '"schema_version":"dirty-tree-classifier-v1",'
        printf '"branch":%s,' "$(json_escape "$BRANCH")"
        printf '"upstream_state":%s,' "$(json_escape "$UPSTREAM_STATE")"
        printf '"staged_count":%d,' "$STAGED_COUNT"
        printf '"unstaged_tracked_count":%d,' "$UNSTAGED_COUNT"
        printf '"untracked_count":%d,' "$UNTRACKED_COUNT"
        printf '"cargo_validation_blocked":%s,' "$CARGO_BLOCKED"
        printf '"rch_queue_summary":%s,' "$(json_escape "$RCH_QUEUE_SUMMARY")"
        printf '"entries":['
        first=1
        for row in "${REPORT_ROWS[@]}"; do
            IFS='|' read -r status path cluster action <<<"$row"
            [[ "$first" == "0" ]] && printf ','
            first=0
            printf '{"status":%s,"path":%s,"suspected_owner_or_bead":%s,"recommended_action":%s}' \
                "$(json_escape "$status")" \
                "$(json_escape "$path")" \
                "$(json_escape "$cluster")" \
                "$(json_escape "$action")"
        done
        printf ']}'
        printf '\n'
    }
else
    echo "DIRTY_TREE_CLASSIFIER schema=dirty-tree-classifier-v1"
    echo "branch=$BRANCH"
    echo "upstream_state=$UPSTREAM_STATE"
    echo "staged_count=$STAGED_COUNT"
    echo "unstaged_tracked_count=$UNSTAGED_COUNT"
    echo "untracked_count=$UNTRACKED_COUNT"
    echo "cargo_validation_blocked=$CARGO_BLOCKED"
    echo "rch_queue_summary=$RCH_QUEUE_SUMMARY"
    for row in "${REPORT_ROWS[@]}"; do
        IFS='|' read -r status path cluster action <<<"$row"
        echo "entry status=$status path=$path suspected_owner_or_bead=$cluster recommended_action=$action"
    done
fi
