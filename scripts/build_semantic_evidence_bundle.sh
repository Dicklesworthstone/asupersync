#!/usr/bin/env bash
# SEM-09.2: Assemble normalized semantic readiness evidence bundle.
#
# Produces a deterministic JSON bundle that joins:
# - SEM-12 unified runner output
# - SEM-09 readiness gate declarations
# - SEM-12 verification matrix (rule-ID traceability)
#
# The bundle includes explicit "missing evidence" entries with owning bead IDs
# so gate closure work can be routed without ambiguity.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REPORT_PATH="$PROJECT_ROOT/target/semantic-verification/verification_report.json"
MATRIX_PATH="$PROJECT_ROOT/docs/semantic_verification_matrix.md"
GATES_PATH="$PROJECT_ROOT/docs/semantic_readiness_gates.md"
OUTPUT_PATH="$PROJECT_ROOT/target/semantic-readiness/evidence_bundle.json"
STRICT=false

usage() {
    cat <<'USAGE'
Usage: scripts/build_semantic_evidence_bundle.sh [options]

Options:
  --report <path>   Runner report JSON path
                    (default: target/semantic-verification/verification_report.json)
  --matrix <path>   Verification matrix markdown path
                    (default: docs/semantic_verification_matrix.md)
  --gates <path>    Readiness gates markdown path
                    (default: docs/semantic_readiness_gates.md)
  --output <path>   Bundle output JSON path
                    (default: target/semantic-readiness/evidence_bundle.json)
  --strict          Exit non-zero if missing evidence entries are present
  -h, --help        Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --report)
            REPORT_PATH="${2:-}"
            shift 2
            ;;
        --matrix)
            MATRIX_PATH="${2:-}"
            shift 2
            ;;
        --gates)
            GATES_PATH="${2:-}"
            shift 2
            ;;
        --output)
            OUTPUT_PATH="${2:-}"
            shift 2
            ;;
        --strict)
            STRICT=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    echo "FATAL: jq is required" >&2
    exit 2
fi
if [[ ! -f "$REPORT_PATH" ]]; then
    echo "FATAL: runner report not found: $REPORT_PATH" >&2
    exit 2
fi
if [[ ! -f "$MATRIX_PATH" ]]; then
    echo "FATAL: matrix file not found: $MATRIX_PATH" >&2
    exit 2
fi
if [[ ! -f "$GATES_PATH" ]]; then
    echo "FATAL: gates file not found: $GATES_PATH" >&2
    exit 2
fi

OUTPUT_DIR="$(dirname "$OUTPUT_PATH")"
mkdir -p "$OUTPUT_DIR"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/semantic-evidence-bundle.XXXXXX")"
RULES_NDJSON="$TMP_DIR/rules.ndjson"
MISSING_NDJSON="$TMP_DIR/missing.ndjson"
GATES_NDJSON="$TMP_DIR/gates.ndjson"
touch "$RULES_NDJSON" "$MISSING_NDJSON" "$GATES_NDJSON"
cleanup() { :; }
trap cleanup EXIT

runner_schema="$(jq -r '.schema // ""' "$REPORT_PATH")"
runner_profile="$(jq -r '.profile // "full"' "$REPORT_PATH")"
runner_overall_status="$(jq -r '.overall_status // "unknown"' "$REPORT_PATH")"
runner_report_dir_raw="$(jq -r '.report_dir // ""' "$REPORT_PATH")"
report_base_dir="$(cd "$(dirname "$REPORT_PATH")" && pwd)"

if [[ -z "$runner_report_dir_raw" ]]; then
    runner_report_dir="$report_base_dir"
elif [[ "$runner_report_dir_raw" = /* ]]; then
    runner_report_dir="$runner_report_dir_raw"
else
    runner_report_dir="$report_base_dir/$runner_report_dir_raw"
fi

suite_owner_bead() {
    case "$1" in
        docs) echo "asupersync-3cddg.12.2" ;;
        golden) echo "asupersync-3cddg.12.8" ;;
        lean_validation|lean_build) echo "asupersync-3cddg.12.3" ;;
        tla_validation|tla_check) echo "asupersync-3cddg.12.4" ;;
        logging_schema) echo "asupersync-3cddg.12.7" ;;
        coverage_gate) echo "asupersync-3cddg.12.14" ;;
        *) echo "asupersync-3cddg.9.3" ;;
    esac
}

evidence_class_owner_bead() {
    case "$1" in
        UT|PT|OC) echo "asupersync-3cddg.12.5" ;;
        E2E) echo "asupersync-3cddg.12.6" ;;
        LOG) echo "asupersync-3cddg.12.7" ;;
        DOC) echo "asupersync-3cddg.12.2" ;;
        CI) echo "asupersync-3cddg.12.9" ;;
        *) echo "asupersync-3cddg.9.3" ;;
    esac
}

evidence_class_suite_source() {
    case "$1" in
        UT|PT|OC) echo "golden" ;;
        E2E|LOG) echo "logging_schema" ;;
        DOC) echo "docs" ;;
        CI) echo "coverage_gate" ;;
        *) echo "unknown" ;;
    esac
}

required_classes_for_tier() {
    case "$1" in
        HIGH) echo "UT PT OC E2E LOG DOC" ;;
        MED) echo "UT OC LOG DOC" ;;
        LOW) echo "UT DOC" ;;
        SCOPE-OUT) echo "CI" ;;
        *) echo "" ;;
    esac
}

append_missing() {
    local kind="$1"
    local owner_bead="$2"
    local details_json="$3"
    jq -cn \
        --arg kind "$kind" \
        --arg owner_bead "$owner_bead" \
        --argjson details "$details_json" \
        '{kind:$kind,owner_bead:$owner_bead,details:$details}' \
        >> "$MISSING_NDJSON"
}

# Runner suite failures/skips (required suites are actionable gaps).
jq -c '.results // [] | .[]' "$REPORT_PATH" | while IFS= read -r suite_row; do
    suite_name="$(jq -r '.suite // ""' <<< "$suite_row")"
    suite_status="$(jq -r '.status // "unknown"' <<< "$suite_row")"
    suite_required="$(jq -r '.required // false' <<< "$suite_row")"
    if [[ "$suite_required" == "true" && "$suite_status" != "passed" ]]; then
        owner_bead="$(suite_owner_bead "$suite_name")"
        details_json="$(jq -cn \
            --arg suite "$suite_name" \
            --arg status "$suite_status" \
            --arg source_file "$REPORT_PATH" \
            '{suite:$suite,status:$status,source_file:$source_file}')"
        append_missing "runner_suite" "$owner_bead" "$details_json"
    fi
done

# Profile artifact gaps.
mapfile -t required_artifacts < <(jq -r '.profile_contract.required_artifacts // [] | .[]' "$REPORT_PATH")
for artifact in "${required_artifacts[@]}"; do
    artifact_path="$runner_report_dir/$artifact"
    if [[ ! -e "$artifact_path" ]]; then
        details_json="$(jq -cn \
            --arg artifact "$artifact" \
            --arg expected_path "$artifact_path" \
            --arg source_file "$REPORT_PATH" \
            '{artifact:$artifact,expected_path:$expected_path,source_file:$source_file}')"
        append_missing "runner_artifact" "asupersync-3cddg.12.11" "$details_json"
    fi
done

# Parse readiness gates.
while IFS= read -r line; do
    gate_id="$(sed -E 's/^###[[:space:]]+(G[0-9]+):.*/\1/' <<< "$line")"
    gate_title="$(sed -E 's/^###[[:space:]]+G[0-9]+:[[:space:]]*//' <<< "$line")"
    jq -cn \
        --arg gate_id "$gate_id" \
        --arg title "$gate_title" \
        --arg source_file "$GATES_PATH" \
        '{gate_id:$gate_id,title:$title,source_file:$source_file}' \
        >> "$GATES_NDJSON"
done < <(grep -E '^### G[0-9]+:' "$GATES_PATH" || true)

# Parse matrix rule rows and compute per-rule missing requirements.
while IFS=$'\t' read -r domain rule_index rule_id tier ut pt oc e2e log_field doc ci status_text; do
    required_classes="$(required_classes_for_tier "$tier")"
    if [[ -z "$required_classes" ]]; then
        continue
    fi

    missing_classes=()
    for klass in $required_classes; do
        value="N"
        case "$klass" in
            UT) value="$ut" ;;
            PT) value="$pt" ;;
            OC) value="$oc" ;;
            E2E) value="$e2e" ;;
            LOG) value="$log_field" ;;
            DOC) value="$doc" ;;
            CI) value="$ci" ;;
        esac
        if [[ "$value" != "Y" ]]; then
            missing_classes+=("$klass")
            owner_bead="$(evidence_class_owner_bead "$klass")"
            details_json="$(jq -cn \
                --arg domain "$domain" \
                --arg rule_id "$rule_id" \
                --arg tier "$tier" \
                --arg required_class "$klass" \
                --arg source_file "$MATRIX_PATH" \
                '{domain:$domain,rule_id:$rule_id,tier:$tier,required_class:$required_class,source_file:$source_file}')"
            append_missing "matrix_rule_requirement" "$owner_bead" "$details_json"
        fi
    done

    required_json="$(jq -cn --arg classes "$required_classes" '$classes | split(" ") | map(select(length > 0))')"
    missing_joined="$(printf '%s\n' "${missing_classes[@]:-}" | xargs || true)"
    missing_json="$(jq -cn --arg classes "$missing_joined" '$classes | split(" ") | map(select(length > 0))')"
    class_source_json="$(jq -cn \
        --argjson required "$required_json" \
        '
        reduce $required[] as $klass ({}; .[$klass] =
            (if $klass == "UT" or $klass == "PT" or $klass == "OC" then "golden"
             elif $klass == "E2E" or $klass == "LOG" then "logging_schema"
             elif $klass == "DOC" then "docs"
             elif $klass == "CI" then "coverage_gate"
             else "unknown" end))
        ')"

    jq -cn \
        --arg domain "$domain" \
        --argjson rule_index "$rule_index" \
        --arg rule_id "$rule_id" \
        --arg tier "$tier" \
        --arg status_text "$status_text" \
        --argjson required_classes "$required_json" \
        --argjson missing_classes "$missing_json" \
        --argjson class_source "$class_source_json" \
        --arg source_file "$MATRIX_PATH" \
        '{
            domain:$domain,
            rule_index:$rule_index,
            rule_id:$rule_id,
            tier:$tier,
            status_text:$status_text,
            required_classes:$required_classes,
            missing_classes:$missing_classes,
            evidence_class_sources:$class_source,
            source_file:$source_file
        }' >> "$RULES_NDJSON"
done < <(
    awk '
        function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
        function norm(v) { v = trim(v); return (v == "Y") ? "Y" : "N" }
        BEGIN { domain = "" }
        $0 ~ /^### 4\.[0-9]+ [A-Za-z]+ Domain/ {
            domain = tolower($3)
            next
        }
        $0 ~ /^\|[[:space:]]*[0-9]+[[:space:]]*\|/ {
            split($0, p, "|")
            rule_index = trim(p[2])
            rule_id = trim(p[3]); gsub(/`/, "", rule_id)
            tier = trim(p[4])
            ut = norm(p[5]); pt = norm(p[6]); oc = norm(p[7]); e2e = norm(p[8])
            log_field = norm(p[9]); doc = norm(p[10]); ci = norm(p[11])
            status_text = trim(p[12])
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", \
                domain, rule_index, rule_id, tier, ut, pt, oc, e2e, log_field, doc, ci, status_text
        }
    ' "$MATRIX_PATH"
)

RUNNER_SUITE_STATUS_JSON="$(jq -c '
    (.results // [])
    | map({key:.suite, value:{status:(.status // "unknown"), required:(.required // false), duration_s:(.duration_s // 0)}})
    | from_entries
' "$REPORT_PATH")"
GATES_JSON="$(jq -cs '.' "$GATES_NDJSON")"
RULES_JSON="$(jq -cs 'sort_by(.rule_index)' "$RULES_NDJSON")"
MISSING_JSON="$(jq -cs '.' "$MISSING_NDJSON")"

owner_rollup_json="$(jq -cn --argjson missing "$MISSING_JSON" '
    ($missing | group_by(.owner_bead) | map({owner_bead: .[0].owner_bead, count: length}))
')"
bundle_status="$(jq -nr \
    --arg runner "$runner_overall_status" \
    --argjson missing "$MISSING_JSON" \
    'if $runner == "passed" and ($missing | length) == 0 then "pass" else "needs_attention" end')"

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -n \
    --arg schema_version "semantic-evidence-bundle-v1" \
    --arg generated_at "$generated_at" \
    --arg bundle_status "$bundle_status" \
    --arg project_root "$PROJECT_ROOT" \
    --arg report_path "$REPORT_PATH" \
    --arg matrix_path "$MATRIX_PATH" \
    --arg gates_path "$GATES_PATH" \
    --arg output_path "$OUTPUT_PATH" \
    --arg runner_schema "$runner_schema" \
    --arg runner_profile "$runner_profile" \
    --arg runner_overall_status "$runner_overall_status" \
    --arg runner_report_dir "$runner_report_dir" \
    --argjson suite_status "$RUNNER_SUITE_STATUS_JSON" \
    --argjson gates "$GATES_JSON" \
    --argjson rules "$RULES_JSON" \
    --argjson missing "$MISSING_JSON" \
    --argjson owner_rollup "$owner_rollup_json" \
    '{
        schema_version:$schema_version,
        generated_at:$generated_at,
        status:$bundle_status,
        inputs:{
            project_root:$project_root,
            runner_report:$report_path,
            matrix:$matrix_path,
            readiness_gates:$gates_path
        },
        runner:{
            schema:$runner_schema,
            profile:$runner_profile,
            overall_status:$runner_overall_status,
            report_dir:$runner_report_dir,
            suite_status:$suite_status
        },
        readiness_gates:$gates,
        traceability:{
            matrix_rule_count:($rules | length),
            rules:$rules
        },
        missing_evidence:$missing,
        missing_evidence_by_owner:$owner_rollup,
        deterministic_rerun:{
            supported:true,
            commands:[
                ("scripts/run_semantic_verification.sh --profile " + $runner_profile + " --json"),
                ("scripts/build_semantic_evidence_bundle.sh --report " + $report_path + " --output " + $output_path)
            ]
        }
    }' > "$OUTPUT_PATH"

echo "[semantic-evidence-bundle] Wrote: $OUTPUT_PATH"

if [[ "$STRICT" == "true" ]]; then
    missing_count="$(jq -r '.missing_evidence | length' "$OUTPUT_PATH")"
    if [[ "$missing_count" -gt 0 ]]; then
        echo "[semantic-evidence-bundle] STRICT failure: missing_evidence=$missing_count" >&2
        exit 1
    fi
fi

exit 0
