#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ARTIFACT_ROOT="${STUB_SCAN_ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts}"
ARTIFACT_PATH_ROOT="${STUB_SCAN_ARTIFACT_PATH_ROOT:-${ARTIFACT_ROOT}}"
EVENTS_FILE="${ARTIFACT_ROOT}/stub_resolution_scan_events.ndjson"
SUMMARY_FILE="${ARTIFACT_ROOT}/stub_resolution_scan_summary.json"
EVENTS_PATH_FIELD="${ARTIFACT_PATH_ROOT}/stub_resolution_scan_events.ndjson"
SUMMARY_PATH_FIELD="${ARTIFACT_PATH_ROOT}/stub_resolution_scan_summary.json"
ALLOWLIST_FILE="${PROJECT_ROOT}/.stub-allowlist.txt"
TMP_EVENTS="$(mktemp)"
TMP_SUMMARY="$(mktemp)"
# Z1 owns the scan ratchet / allowlist policy surface. Z0b owns the heavier
# rch-backed verification runner that consumes this scan as one stage.
BEAD_ID="asupersync-v2ofj7.10.1"
TRACK_ID="Z"
PROFILE_FAMILY="stub-resolution-scan"
COMMAND_STRING="bash ${SCRIPT_DIR}/$(basename "$0")"
CONFIG_SNAPSHOT_REF="docs/stub_closure_policy.md::Scan Rules; TESTING.md::Shared Validation Contract (asupersync-ay6qvw)"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RCKSTB_INVENTORY_FILE="${PROJECT_ROOT}/artifacts/stub_placeholder_inventory_v1.json"
RCKSTB_INVENTORY_SUMMARY_JSON='{"schema_version":"stub-placeholder-inventory-summary-v1","artifact_path":"artifacts/stub_placeholder_inventory_v1.json","scanned_paths":[],"marker_count":0,"disposition_counts":{},"unclassified_count":0,"verdict":"blocked","first_failure":"inventory summary not run"}'

mkdir -p "$ARTIFACT_ROOT"
: >"$TMP_EVENTS"

CHECKS_TOTAL=0
FAILURES=0

json_bool() {
    if [[ "$1" -eq 1 ]]; then
        printf 'true'
    else
        printf 'false'
    fi
}

path_is_git_ignored() {
    local path="$1"
    local repo_path="$path"
    if [[ "$repo_path" == "${PROJECT_ROOT}/"* ]]; then
        repo_path="${repo_path#${PROJECT_ROOT}/}"
    fi

    if git -C "$PROJECT_ROOT" check-ignore -q -- "$repo_path" 2>/dev/null; then
        return 0
    fi

    return 1
}

record_event() {
    local check_id="$1"
    local status="$2"
    local subject="$3"
    local detail="$4"
    local observed_outcome="passed"
    local exit_code=0

    if [[ "$status" != "pass" ]]; then
        observed_outcome="failed"
        exit_code=1
    fi

    jq -nc \
        --arg schema_version "stub-resolution-scan-event-v1" \
        --arg bead_id "$BEAD_ID" \
        --arg track_id "$TRACK_ID" \
        --arg scenario_id "$check_id" \
        --arg validation_surface "scan" \
        --arg profile_family "$PROFILE_FAMILY" \
        --argjson feature_flags '["scan"]' \
        --arg seed_or_fixture_id "none" \
        --arg config_snapshot_ref "$CONFIG_SNAPSHOT_REF" \
        --arg command "$COMMAND_STRING" \
        --arg expected_outcome "zero violations" \
        --arg observed_outcome "$observed_outcome" \
        --arg artifact_path "$SUMMARY_PATH_FIELD" \
        --arg replay_pointer "$COMMAND_STRING" \
        --arg execution_backend "local" \
        --arg evidence_owner "$BEAD_ID" \
        --arg subject "$subject" \
        --arg detail "$detail" \
        --arg exit_code "$exit_code" \
        '{
          schema_version: $schema_version,
          bead_id: $bead_id,
          track_id: $track_id,
          scenario_id: $scenario_id,
          validation_surface: $validation_surface,
          profile_family: $profile_family,
          feature_flags: $feature_flags,
          seed_or_fixture_id: $seed_or_fixture_id,
          config_snapshot_ref: $config_snapshot_ref,
          command: $command,
          expected_outcome: $expected_outcome,
          observed_outcome: $observed_outcome,
          exit_code: ($exit_code | tonumber),
          artifact_path: $artifact_path,
          replay_pointer: $replay_pointer,
          rch_routed: false,
          execution_backend: $execution_backend,
          evidence_owner: $evidence_owner,
          check_id: $scenario_id,
          subject: $subject,
          detail: $detail
        }' >>"$TMP_EVENTS"
}

report_pass() {
    local check_id="$1"
    local subject="$2"
    local detail="$3"
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    printf '[PASS] %s\n' "$subject"
    record_event "$check_id" "pass" "$subject" "$detail"
}

report_fail() {
    local check_id="$1"
    local subject="$2"
    local detail="$3"
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    FAILURES=$((FAILURES + 1))
    printf '[FAIL] %s\n' "$subject"
    printf '       %s\n' "$detail"
    record_event "$check_id" "fail" "$subject" "$detail"
}

allowlist_symbol_regex() {
    local symbol="$1"
    local escaped
    escaped="$(printf '%s' "$symbol" | sed -e 's/[][(){}.^$+?|\\]/\\&/g' -e 's/\*/[[:alnum:]_]*/g')"
    printf '%s' "$escaped"
}

allowlist_symbol_matches_file() {
    local path="$1"
    local symbol="$2"

    if [[ "$symbol" == *"*"* ]]; then
        local symbol_regex
        symbol_regex="$(allowlist_symbol_regex "$symbol")"
        rg -q --pcre2 "$symbol_regex" "$path"
        return
    fi

    if rg -Fq "$symbol" "$path"; then
        return 0
    fi

    if [[ "$symbol" == *"::"* ]]; then
        local owner="${symbol%::*}"
        local member="${symbol##*::}"
        if rg -Fq "$owner" "$path" && rg -Fq "$member" "$path"; then
            return 0
        fi
    fi

    return 1
}

check_stub_allowlist_file_is_valid() {
    if [[ ! -f "$ALLOWLIST_FILE" ]]; then
        report_fail "ZR-SCAN-ALLOWLIST-FILE" "Stub allowlist is missing" "$ALLOWLIST_FILE"
        return 0
    fi

    local line_no=0
    local invalid_entries=""
    local missing_paths=""
    local missing_symbols=""
    local duplicate_entries=""
    declare -A seen_entries=()

    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        line_no=$((line_no + 1))
        local line="${raw_line#"${raw_line%%[![:space:]]*}"}"
        if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
            continue
        fi

        if [[ ! "$line" =~ ^([^:[:space:]]+):([^[:space:]]+)[[:space:]]+\((.+)\)[[:space:]]+\[(IMPLEMENT|CONVERGE|QUARANTINE|DOCUMENT|RETIRE|RESOLVED)\]$ ]]; then
            invalid_entries+="${line_no}: ${raw_line}"$'\n'
            continue
        fi

        local path="${BASH_REMATCH[1]}"
        local symbol="${BASH_REMATCH[2]}"
        local entry_key="${path}:${symbol}"

        if [[ -n "${seen_entries[$entry_key]:-}" ]]; then
            duplicate_entries+="${entry_key}"$'\n'
        else
            seen_entries["$entry_key"]=1
        fi

        if [[ ! -e "${PROJECT_ROOT}/${path}" ]]; then
            missing_paths+="${path}"$'\n'
            continue
        fi

        if ! allowlist_symbol_matches_file "${PROJECT_ROOT}/${path}" "$symbol"; then
            missing_symbols+="${path}:${symbol}"$'\n'
        fi
    done <"$ALLOWLIST_FILE"

    if [[ -n "$invalid_entries" ]]; then
        report_fail "ZR-SCAN-ALLOWLIST-SYNTAX" "Stub allowlist has malformed entries" "$(printf '%s' "$invalid_entries" | sed '/^$/d')"
    else
        report_pass "ZR-SCAN-ALLOWLIST-SYNTAX" "Stub allowlist entries parse cleanly" "$ALLOWLIST_FILE"
    fi

    if [[ -n "$duplicate_entries" ]]; then
        report_fail "ZR-SCAN-ALLOWLIST-DUPLICATES" "Stub allowlist has duplicate path:symbol entries" "$(printf '%s' "$duplicate_entries" | sed '/^$/d')"
    else
        report_pass "ZR-SCAN-ALLOWLIST-DUPLICATES" "Stub allowlist entries are unique" "no duplicate path:symbol pairs"
    fi

    if [[ -n "$missing_paths" ]]; then
        report_fail "ZR-SCAN-ALLOWLIST-PATHS" "Stub allowlist references missing paths" "$(printf '%s' "$missing_paths" | sed '/^$/d')"
    else
        report_pass "ZR-SCAN-ALLOWLIST-PATHS" "Stub allowlist paths exist" "all documented waiver paths resolve in-repo"
    fi

    if [[ -n "$missing_symbols" ]]; then
        report_fail "ZR-SCAN-ALLOWLIST-SYMBOLS" "Stub allowlist references symbols that are no longer present" "$(printf '%s' "$missing_symbols" | sed '/^$/d')"
    else
        report_pass "ZR-SCAN-ALLOWLIST-SYMBOLS" "Stub allowlist symbols still match the referenced files" "allowlist remains anchored to live surfaces"
    fi
}

build_rckstb_inventory_summary() {
    if [[ ! -f "$RCKSTB_INVENTORY_FILE" ]]; then
        jq -nc \
            --arg artifact_path "artifacts/stub_placeholder_inventory_v1.json" \
            --arg first_failure "inventory file is missing" \
            '{
              schema_version: "stub-placeholder-inventory-summary-v1",
              artifact_path: $artifact_path,
              scanned_paths: [],
              marker_count: 0,
              selector_count: 0,
              disposition_counts: {},
              unclassified_count: 1,
              verdict: "fail",
              first_failure: $first_failure
            }'
        return 0
    fi

    python3 - "$PROJECT_ROOT" "$RCKSTB_INVENTORY_FILE" <<'PY'
import json
import pathlib
import sys
from collections import Counter

project_root = pathlib.Path(sys.argv[1])
inventory_path = pathlib.Path(sys.argv[2])
artifact_path = "artifacts/stub_placeholder_inventory_v1.json"

try:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
except Exception as exc:  # noqa: BLE001 - shell summary must stay diagnostic.
    print(json.dumps({
        "schema_version": "stub-placeholder-inventory-summary-v1",
        "artifact_path": artifact_path,
        "scanned_paths": [],
        "marker_count": 0,
        "selector_count": 0,
        "disposition_counts": {},
        "unclassified_count": 1,
        "verdict": "fail",
        "first_failure": f"failed to read inventory: {exc}",
    }, sort_keys=True))
    raise SystemExit(0)

terms = [str(term) for term in inventory.get("marker_terms", [])]
extensions = {str(ext) for ext in inventory.get("file_extensions", [])}
selectors = list(inventory.get("selectors", []))


def selector_matches(selector: dict, rel_path: str, text: str, term: str) -> bool:
    exact_paths = selector.get("paths", []) or []
    prefixes = selector.get("path_prefixes", []) or []
    path_matches = rel_path in exact_paths or any(rel_path.startswith(prefix) for prefix in prefixes)
    if not path_matches:
        return False

    text_lower = text.lower()
    term_lower = term.lower()
    for selector_term in selector.get("terms", []) or []:
        selector_term_lower = str(selector_term).lower()
        if selector_term_lower in text_lower or selector_term_lower in term_lower:
            return True
    return False


markers = []
for root_name in inventory.get("scanned_paths", []):
    root = project_root / str(root_name)
    if not root.exists():
        continue
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.removeprefix(".") not in extensions:
            continue
        rel_path = path.relative_to(project_root).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            line_lower = line.lower()
            for term in terms:
                if term.lower() in line_lower:
                    markers.append({
                        "path": rel_path,
                        "line": line_no,
                        "term": term,
                        "text": line.strip(),
                    })

unclassified = []
disposition_counts: Counter[str] = Counter()
for marker in markers:
    matched = next(
        (
            selector
            for selector in selectors
            if selector_matches(selector, marker["path"], marker["text"], marker["term"])
        ),
        None,
    )
    if matched is None:
        unclassified.append(marker)
    else:
        disposition_counts[str(matched.get("disposition", "unknown"))] += 1

first_failure = ""
if unclassified:
    marker = unclassified[0]
    first_failure = f"{marker['path']}:{marker['line']}:{marker['term']}: {marker['text']}"

print(json.dumps({
    "schema_version": "stub-placeholder-inventory-summary-v1",
    "artifact_path": artifact_path,
    "scanned_paths": inventory.get("scanned_paths", []),
    "marker_count": len(markers),
    "selector_count": len(selectors),
    "disposition_counts": dict(sorted(disposition_counts.items())),
    "unclassified_count": len(unclassified),
    "verdict": "pass" if not unclassified else "fail",
    "first_failure": first_failure,
}, sort_keys=True))
PY
}

check_rckstb_placeholder_inventory_is_classified() {
    RCKSTB_INVENTORY_SUMMARY_JSON="$(build_rckstb_inventory_summary)"
    local marker_count
    local unclassified_count
    local first_failure
    marker_count="$(jq -r '.marker_count // 0' <<<"$RCKSTB_INVENTORY_SUMMARY_JSON")"
    unclassified_count="$(jq -r '.unclassified_count // 0' <<<"$RCKSTB_INVENTORY_SUMMARY_JSON")"
    first_failure="$(jq -r '.first_failure // ""' <<<"$RCKSTB_INVENTORY_SUMMARY_JSON")"

    if [[ "$unclassified_count" == "0" ]]; then
        report_pass "ZR-SCAN-RCKSTB-INVENTORY" "rckstb placeholder inventory classifies live markers" "marker_count=${marker_count}; unclassified_count=0; artifact=artifacts/stub_placeholder_inventory_v1.json"
    else
        report_fail "ZR-SCAN-RCKSTB-INVENTORY" "rckstb placeholder inventory has unclassified markers" "unclassified_count=${unclassified_count}; first_failure=${first_failure}"
    fi
}

check_no_stray_binaries_in_src() {
    local matches=""
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        # Stub-resolution closure should be deterministic across worktrees.
        # Ignore local gitignored scratch outputs, but still fail on real
        # non-ignored binary artifacts in source-owned trees.
        if path_is_git_ignored "$path"; then
            continue
        fi
        matches+="${path}"$'\n'
    done < <(find "${PROJECT_ROOT}/src" -type f \( -name '*.out' -o -name '*.exe' -o -name '*.o' -o -name '*.so' -o -name '*.dylib' \) -print 2>/dev/null | sort || true)
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-NO-STRAY-BINARIES" "No stray binary artifacts under src/" "src/ tree is source-only"
    else
        report_fail "ZR-SCAN-NO-STRAY-BINARIES" "Stray binary artifacts under src/" "$(printf '%s' "$matches" | sed '/^$/d')"
    fi
}

check_no_crate_level_dead_code_allow() {
    local matches
    matches="$(rg -n '^#!\[allow\(dead_code\)\]' "${PROJECT_ROOT}/src/lib.rs" || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-NO-CRATE-DEAD-CODE" "src/lib.rs has no crate-level dead_code allow" "crate root preserves the global lint"
    else
        report_fail "ZR-SCAN-NO-CRATE-DEAD-CODE" "src/lib.rs has a crate-level dead_code allow" "$matches"
    fi
}

check_no_todo_in_production() {
    local matches
    matches="$(scan_production_rust_marker 'todo!\(' || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-NO-TODO-IN-SRC" "No todo!() remains in production src/" "runtime source tree is free of todo!() sentinels"
    else
        report_fail "ZR-SCAN-NO-TODO-IN-SRC" "Found todo!() in production src/" "$matches"
    fi
}

check_no_unimplemented_in_production() {
    local matches
    matches="$(scan_production_rust_marker 'unimplemented!\(' || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-NO-UNIMPLEMENTED-IN-SRC" "No unimplemented!() remains in production src/" "runtime source tree is free of production unimplemented!() sentinels"
    else
        report_fail "ZR-SCAN-NO-UNIMPLEMENTED-IN-SRC" "Found unimplemented!() in production src/" "$matches"
    fi
}

scan_production_rust_marker() {
    local pattern="$1"
    python3 - "$PROJECT_ROOT" "$pattern" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
pattern = re.compile(sys.argv[2])


def brace_delta(line: str) -> int:
    # Good enough for marker filtering: test modules/functions use ordinary
    # braces, and marker comments/strings should not control test scope.
    return line.count("{") - line.count("}")


def production_lines(path: pathlib.Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if any("#![cfg(test)]" in line for line in lines[:16]):
        return []

    out: list[tuple[int, str]] = []
    depth = 0
    cfg_test_pending = False
    test_attr_pending = False
    cfg_test_depth: int | None = None
    test_fn_depth: int | None = None

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#[cfg(test)]"):
            cfg_test_pending = True
        if stripped.startswith("#[test]"):
            test_attr_pending = True

        delta = brace_delta(line)
        next_depth = depth + delta
        starts_cfg_test_scope = cfg_test_pending and (
            stripped.startswith("mod ")
            or stripped.startswith("fn ")
            or " mod " in stripped
            or " fn " in stripped
        )
        starts_test_fn = test_attr_pending and (
            stripped.startswith("fn ") or " fn " in stripped
        )

        if starts_cfg_test_scope:
            cfg_test_depth = max(next_depth, depth + 1)
            cfg_test_pending = False
        if starts_test_fn:
            test_fn_depth = max(next_depth, depth + 1)
            test_attr_pending = False

        if cfg_test_depth is None and test_fn_depth is None and pattern.search(line):
            out.append((index, line.rstrip()))

        depth = next_depth
        if cfg_test_depth is not None and depth < cfg_test_depth:
            cfg_test_depth = None
        if test_fn_depth is not None and depth < test_fn_depth:
            test_fn_depth = None

    return out


for path in sorted((root / "src").rglob("*.rs")):
    rel = path.relative_to(root).as_posix()
    for line_no, line in production_lines(path):
        print(f"{rel}:{line_no}:{line}")
PY
}

check_production_todo_comments_are_tracked() {
    local matches
    matches="$(scan_production_rust_marker 'TODO|FIXME' || true)"
    local unexpected=""
    local tracked=""

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$line" == src/messaging/nats.rs:*"TODO: Re-establish subscriptions that existed before disconnect"* ]]; then
            tracked+="${line} -> asupersync-jh9g1j"$'\n'
        else
            unexpected+="${line}"$'\n'
        fi
    done <<<"$matches"

    if [[ -n "$unexpected" ]]; then
        report_fail "ZR-SCAN-PROD-TODO-TRACKED" "Found untracked production TODO/FIXME markers" "$(printf '%s' "$unexpected" | sed '/^$/d'; printf '\nCreate a concrete br bead or add a specific tracked-marker entry.')"
    else
        report_pass "ZR-SCAN-PROD-TODO-TRACKED" "Production TODO/FIXME markers are tracked" "${tracked:-no live production TODO/FIXME markers}"
    fi
}

check_no_not_implemented_panics_in_production() {
    local matches
    matches="$(scan_production_rust_marker 'panic!\([^)]*(TODO|todo|not implemented|Not implemented|NOT IMPLEMENTED)' || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-NO-NOT-IMPLEMENTED-PANICS" "No not-implemented panic sentinels remain in production src/" "test-only audit panics are ignored by cfg(test) filtering"
    else
        report_fail "ZR-SCAN-NO-NOT-IMPLEMENTED-PANICS" "Found not-implemented panic sentinels in production src/" "$matches"
    fi
}

check_grpc_health_auth_todo_resolved() {
    local matches
    matches="$(rg -n 'TODO: Implement configurable authentication mode|Health check accessed without authentication validation' "${PROJECT_ROOT}/src/grpc/health.rs" || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-GRPC-HEALTH-XFX177-RESOLVED" "gRPC health auth TODO is resolved" "canonical blocker asupersync-xfx177 is closed; no stale TODO remains in src/grpc/health.rs"
    else
        report_fail "ZR-SCAN-GRPC-HEALTH-XFX177-RESOLVED" "gRPC health auth TODO is still present" "$matches"
    fi
}

check_combinator_compile_errors_are_gated() {
    local failures_buffer=""
    while IFS= read -r path; do
        [[ -z "$path" ]] && continue
        if ! rg -q '#\[cfg\(not\(feature = "proc-macros"\)\)\]' "$path"; then
            failures_buffer+="${path}"$'\n'
        fi
    done < <(rg -l '^[[:space:]]*compile_error!' "${PROJECT_ROOT}/src/combinator" || true)

    if [[ -z "$failures_buffer" ]]; then
        report_pass "ZR-SCAN-GUARDED-COMPILE-ERRORS" "combinator compile_error! sites are cfg-guarded" "checked src/combinator macro surfaces"
    else
        report_fail "ZR-SCAN-GUARDED-COMPILE-ERRORS" "Found combinator compile_error! files without proc-macro cfg guard" "$(printf '%s' "$failures_buffer" | sed '/^$/d')"
    fi
}

check_transport_mock_is_gated() {
    local mock_line
    mock_line="$(rg -n 'pub mod mock;' "${PROJECT_ROOT}/src/transport/mod.rs" | head -n1 || true)"
    if [[ -z "$mock_line" ]]; then
        report_pass "ZR-SCAN-TRANSPORT-MOCK-GATED" "transport/mock is not publicly exported" "src/transport/mod.rs has no public mock export"
        return 0
    fi

    local line_no
    line_no="${mock_line%%:*}"
    local start_line=1
    if (( line_no > 2 )); then
        start_line=$((line_no - 2))
    fi
    local context
    context="$(sed -n "${start_line},${line_no}p" "${PROJECT_ROOT}/src/transport/mod.rs")"
    if grep -q 'cfg' <<<"$context"; then
        report_pass "ZR-SCAN-TRANSPORT-MOCK-GATED" "transport/mock export is cfg-gated" "$(printf '%s' "$mock_line")"
    else
        report_fail "ZR-SCAN-TRANSPORT-MOCK-GATED" "transport/mock export is not cfg-gated" "$(printf '%s\n%s' "$mock_line" "$context")"
    fi
}

check_no_conformance_dummy_panics() {
    local matches
    matches="$(rg -n 'panic!\("dummy' "${PROJECT_ROOT}/conformance/src/runner.rs" || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-CONFORMANCE-DUMMY-PANIC" "Conformance runner has no panic!(\"dummy\") placeholders" "conformance/src/runner.rs is free of dummy panics"
    else
        report_fail "ZR-SCAN-CONFORMANCE-DUMMY-PANIC" "Conformance runner still has panic-based dummy placeholders" "$matches"
    fi
}

check_api_skeleton_moved_out_of_root() {
    if [[ -e "${PROJECT_ROOT}/asupersync_v4_api_skeleton.rs" ]]; then
        report_fail "ZR-SCAN-API-SKELETON-ROOT" "API skeleton still lives in project root" "expected docs/design/api_skeleton_v4.rs to be the historical location"
    else
        report_pass "ZR-SCAN-API-SKELETON-ROOT" "API skeleton is no longer in the project root" "historical reference is outside the compiled source tree"
    fi
}

check_no_skeleton_placeholders_in_src() {
    local matches
    matches="$(rg -n 'skeleton_placeholder!' "${PROJECT_ROOT}/src" || true)"
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-SKELETON-PLACEHOLDERS" "No skeleton_placeholder! macros remain under src/" "runtime source tree is free of API skeleton sentinels"
    else
        report_fail "ZR-SCAN-SKELETON-PLACEHOLDERS" "Found skeleton_placeholder! macros under src/" "$matches"
    fi
}

check_stub_resolution_probe_module_exists() {
    if [[ -f "${PROJECT_ROOT}/tests/stub_resolution_audit.rs" ]]; then
        report_pass "ZR-SCAN-PROBE-MODULE" "tests/stub_resolution_audit.rs exists" "probe module is available for cargo test --test stub_resolution_audit"
    else
        report_fail "ZR-SCAN-PROBE-MODULE" "tests/stub_resolution_audit.rs is missing" "Z0a probe module is not present"
    fi
}

check_stub_ratchet_assets_are_audited() {
    local audit_file="${PROJECT_ROOT}/audit_index.jsonl"
    if [[ ! -f "$audit_file" ]]; then
        report_fail "ZR-SCAN-AUDIT-RATCHET-ASSETS" "audit_index.jsonl is missing" "$audit_file"
        return 0
    fi

    local missing=""
    local required_paths=(
        "scripts/scan_stubs.sh"
        "scripts/verify_stub_resolution.sh"
        "tests/stub_resolution_audit.rs"
        "docs/stub_closure_policy.md"
        "docs/stub_disposition_matrix.md"
        "TESTING.md"
        ".stub-allowlist.txt"
    )

    for path in "${required_paths[@]}"; do
        if ! rg -Fq "\"file\":\"${path}\"" "$audit_file"; then
            missing+="${path}"$'\n'
        fi
    done

    if [[ -z "$missing" ]]; then
        report_pass "ZR-SCAN-AUDIT-RATCHET-ASSETS" "Stub-ratchet assets are recorded in audit_index.jsonl" "scan, verification, policy, probe, and allowlist assets have audit entries"
    else
        report_fail "ZR-SCAN-AUDIT-RATCHET-ASSETS" "Stub-ratchet assets are missing audit_index.jsonl entries" "$(printf '%s' "$missing" | sed '/^$/d')"
    fi
}

check_no_unimplemented_in_examples_and_tests() {
    local matches
    if command -v ast-grep >/dev/null 2>&1; then
        matches="$(ast-grep run -l Rust -p 'unimplemented!()' "${PROJECT_ROOT}/examples" "${PROJECT_ROOT}/tests" 2>/dev/null || true)"
    else
        matches="$(rg -n '^[^"]*unimplemented!\(\)' "${PROJECT_ROOT}/examples" "${PROJECT_ROOT}/tests" || true)"
    fi
    if [[ -z "$matches" ]]; then
        report_pass "ZR-SCAN-NO-HARNESS-UNIMPLEMENTED" "No unimplemented!() remains in examples/ or tests/" "harness surfaces are non-panicking"
    else
        report_fail "ZR-SCAN-NO-HARNESS-UNIMPLEMENTED" "Found unimplemented!() in examples/ or tests/" "$matches"
    fi
}

check_stub_allowlist_file_is_valid
check_rckstb_placeholder_inventory_is_classified
check_no_stray_binaries_in_src
check_no_crate_level_dead_code_allow
check_no_todo_in_production
check_no_unimplemented_in_production
check_production_todo_comments_are_tracked
check_no_not_implemented_panics_in_production
check_grpc_health_auth_todo_resolved
check_combinator_compile_errors_are_gated
check_transport_mock_is_gated
check_no_conformance_dummy_panics
check_api_skeleton_moved_out_of_root
check_no_skeleton_placeholders_in_src
check_stub_resolution_probe_module_exists
check_stub_ratchet_assets_are_audited
check_no_unimplemented_in_examples_and_tests

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EXIT_CODE=0
OBSERVED_OUTCOME="passed"
if (( FAILURES > 0 )); then
    EXIT_CODE=1
    OBSERVED_OUTCOME="failed"
fi

jq -nc \
    --arg schema_version "stub-resolution-scan-summary-v1" \
    --arg bead_id "$BEAD_ID" \
    --arg track_id "$TRACK_ID" \
    --arg scenario_id "ZR-SCAN-SUMMARY" \
    --arg validation_surface "scan" \
    --arg profile_family "$PROFILE_FAMILY" \
    --argjson feature_flags '["scan"]' \
    --arg seed_or_fixture_id "none" \
    --arg config_snapshot_ref "$CONFIG_SNAPSHOT_REF" \
    --arg command "$COMMAND_STRING" \
    --arg expected_outcome "zero violations" \
    --arg observed_outcome "$OBSERVED_OUTCOME" \
    --arg artifact_path "$SUMMARY_PATH_FIELD" \
    --arg replay_pointer "$COMMAND_STRING" \
    --arg execution_backend "local" \
    --arg evidence_owner "$BEAD_ID" \
    --arg events_path "$EVENTS_PATH_FIELD" \
    --arg started_ts "$STARTED_TS" \
    --arg ended_ts "$ENDED_TS" \
    --arg checks_total "$CHECKS_TOTAL" \
    --arg failures "$FAILURES" \
    --arg exit_code "$EXIT_CODE" \
    --argjson rckstb_inventory "$RCKSTB_INVENTORY_SUMMARY_JSON" \
    '{
      schema_version: $schema_version,
      bead_id: $bead_id,
      track_id: $track_id,
      scenario_id: $scenario_id,
      validation_surface: $validation_surface,
      profile_family: $profile_family,
      feature_flags: $feature_flags,
      seed_or_fixture_id: $seed_or_fixture_id,
      config_snapshot_ref: $config_snapshot_ref,
      command: $command,
      expected_outcome: $expected_outcome,
      observed_outcome: $observed_outcome,
      exit_code: ($exit_code | tonumber),
      artifact_path: $artifact_path,
      replay_pointer: $replay_pointer,
      rch_routed: false,
      execution_backend: $execution_backend,
      evidence_owner: $evidence_owner,
      checks_total: ($checks_total | tonumber),
      failures: ($failures | tonumber),
      started_ts: $started_ts,
      ended_ts: $ended_ts,
      events_path: $events_path,
      rckstb_scanned_paths: $rckstb_inventory.scanned_paths,
      rckstb_marker_count: $rckstb_inventory.marker_count,
      rckstb_disposition_counts: $rckstb_inventory.disposition_counts,
      rckstb_unclassified_count: $rckstb_inventory.unclassified_count,
      rckstb_inventory_artifact_path: $rckstb_inventory.artifact_path,
      rckstb_inventory_verdict: $rckstb_inventory.verdict,
      rckstb_inventory_first_failure: $rckstb_inventory.first_failure,
      rckstb_placeholder_inventory: $rckstb_inventory
    }' >"$TMP_SUMMARY"

mv "$TMP_EVENTS" "$EVENTS_FILE"
mv "$TMP_SUMMARY" "$SUMMARY_FILE"

printf '\nSummary: %s\n' "$SUMMARY_FILE"
printf 'Events:  %s\n' "$EVENTS_FILE"
exit "$EXIT_CODE"
