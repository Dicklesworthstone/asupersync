#!/usr/bin/env bash
# Canonical dependency supply-chain gate for asupersync.
#
# This runner never updates a lockfile or build tree. It emits raw scanner
# output plus a machine-readable summary and fails closed when a required tool
# or advisory database receipt cannot be verified.

set -euo pipefail

readonly BLOCKED_EXIT=75
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly POLICY_PATH="${REPO_ROOT}/artifacts/dependency_supply_chain_policy_v1.json"

OUTPUT_DIR="${DEPENDENCY_AUDIT_OUTPUT_DIR:-${TMPDIR:-/tmp}/asupersync-dependency-audit}"
DB_ROOT="${ASUPERSYNC_ADVISORY_DB_ROOT:-${OUTPUT_DIR}/advisory-dbs}"
SUMMARY_PATH="${OUTPUT_DIR}/summary.json"
EVENTS_PATH="${OUTPUT_DIR}/events.ndjson"

mkdir -p -- "${OUTPUT_DIR}" "${DB_ROOT}"
cd -- "${REPO_ROOT}"

require_host_tool() {
    local tool="$1"
    if ! command -v "${tool}" >/dev/null 2>&1; then
        write_blocked_summary "missing required host tool: ${tool}"
        exit "${BLOCKED_EXIT}"
    fi
}

emit_event() {
    local event="$1"
    local outcome="$2"
    local detail="$3"
    jq -cn \
        --arg event "${event}" \
        --arg outcome "${outcome}" \
        --arg detail "${detail}" \
        '{schema_version: 1, event: $event, outcome: $outcome, detail: $detail}' \
        >>"${EVENTS_PATH}"
}

write_blocked_summary() {
    local reason="$1"
    jq -n \
        --arg artifact_id "dependency-supply-chain-audit-summary-v1" \
        --arg bead_id "asupersync-mnotoo.2" \
        --arg outcome "BLOCKED_EXTERNAL" \
        --arg reason "${reason}" \
        '{
            schema_version: 1,
            artifact_id: $artifact_id,
            bead_id: $bead_id,
            outcome: $outcome,
            blocker: $reason,
            root_workspace: {status: "blocked"},
            excluded_fuzz_workspace: {status: "not_evaluated"}
        }' >"${SUMMARY_PATH}"
    emit_event "preflight" "blocked" "${reason}"
    printf 'dependency audit blocked: %s\n' "${reason}" >&2
}

policy_string() {
    local expression="$1"
    jq -er "${expression}" "${POLICY_PATH}"
}

install_tools() {
    require_host_tool cargo
    require_host_tool jq

    local deny_crate
    local deny_version
    local audit_crate
    local audit_version
    deny_crate="$(policy_string '.tools.cargo_deny.crate')"
    deny_version="$(policy_string '.tools.cargo_deny.version')"
    audit_crate="$(policy_string '.tools.cargo_audit.crate')"
    audit_version="$(policy_string '.tools.cargo_audit.version')"

    cargo install --locked --version "${deny_version}" "${deny_crate}"
    cargo install --locked --version "${audit_version}" "${audit_crate}"
}

verify_tools() {
    require_host_tool jq
    require_host_tool git
    require_host_tool cargo
    require_host_tool cargo-deny
    require_host_tool cargo-audit

    local expected_deny
    local expected_audit
    local observed_deny
    local observed_audit
    expected_deny="$(policy_string '.tools.cargo_deny.version_output')"
    expected_audit="$(policy_string '.tools.cargo_audit.version_output')"
    observed_deny="$(cargo-deny --version)"
    observed_audit="$(cargo-audit --version)"

    if [[ "${observed_deny}" != "${expected_deny}" ]]; then
        write_blocked_summary \
            "cargo-deny version mismatch: expected ${expected_deny}, observed ${observed_deny}"
        exit "${BLOCKED_EXIT}"
    fi
    if [[ "${observed_audit}" != "${expected_audit}" ]]; then
        write_blocked_summary \
            "cargo-audit version mismatch: expected ${expected_audit}, observed ${observed_audit}"
        exit "${BLOCKED_EXIT}"
    fi

    emit_event "tool-preflight" "pass" \
        "${observed_deny}; ${observed_audit}"
}

database_receipt() {
    local -a git_dirs=()
    local maximum_age
    local repo
    local revision
    local commit_epoch
    local commit_timestamp
    local observed_epoch
    local age_seconds
    local url

    maximum_age="$(policy_string '.advisory_database_policy.maximum_age_seconds')"
    mapfile -t git_dirs < <(find "${DB_ROOT}" -mindepth 2 -maxdepth 2 -type d -name .git -print)
    if [[ "${#git_dirs[@]}" -ne 1 ]]; then
        write_blocked_summary \
            "expected exactly one RustSec database below ${DB_ROOT}, found ${#git_dirs[@]}"
        exit "${BLOCKED_EXIT}"
    fi

    repo="$(dirname -- "${git_dirs[0]}")"
    revision="$(git -C "${repo}" rev-parse HEAD)"
    commit_epoch="$(git -C "${repo}" show -s --format=%ct HEAD)"
    commit_timestamp="$(git -C "${repo}" show -s --format=%cI HEAD)"
    observed_epoch="$(date -u +%s)"
    age_seconds=$((observed_epoch - commit_epoch))
    if ((age_seconds < 0)); then
        age_seconds=0
    fi
    url="$(git -C "${repo}" remote get-url origin)"

    if ((age_seconds > maximum_age)); then
        write_blocked_summary \
            "RustSec database ${revision} is ${age_seconds}s old; maximum is ${maximum_age}s"
        exit "${BLOCKED_EXIT}"
    fi

    jq -n \
        --arg path "${repo}" \
        --arg url "${url}" \
        --arg revision "${revision}" \
        --arg commit_timestamp_utc "${commit_timestamp}" \
        --argjson age_seconds "${age_seconds}" \
        --argjson maximum_age_seconds "${maximum_age}" \
        '{
            path: $path,
            url: $url,
            revision: $revision,
            commit_timestamp_utc: $commit_timestamp_utc,
            age_seconds: $age_seconds,
            maximum_age_seconds: $maximum_age_seconds,
            fetched: true,
            fresh: true
        }' >"${OUTPUT_DIR}/advisory-database-receipt.json"
    printf '%s\n' "${repo}"
}

lockfile_duplicates() {
    local lockfile="$1"
    local output="$2"
    local package_rows="${OUTPUT_DIR}/package-rows.$$.tsv"

    awk '
        function emit() {
            if (name != "" && version != "") {
                print name "\t" version
            }
        }
        /^\[\[package\]\]$/ {
            emit()
            name = ""
            version = ""
            next
        }
        /^name = "/ {
            value = $0
            sub(/^name = "/, "", value)
            sub(/"$/, "", value)
            name = value
            next
        }
        /^version = "/ {
            value = $0
            sub(/^version = "/, "", value)
            sub(/"$/, "", value)
            version = value
            next
        }
        END {
            emit()
        }
    ' "${lockfile}" | LC_ALL=C sort -u >"${package_rows}"

    jq -Rn '
        [
            inputs
            | select(length > 0)
            | split("\t")
            | {name: .[0], version: .[1]}
        ]
        | group_by(.name)
        | map({
            name: .[0].name,
            versions: (map(.version) | unique | sort)
        })
        | map(select(.versions | length > 1))
    ' <"${package_rows}" >"${output}"
}

duplicate_expansions() {
    local current="$1"
    local scope="$2"
    local output="$3"

    jq -n \
        --arg scope "${scope}" \
        --slurpfile policy "${POLICY_PATH}" \
        --slurpfile current "${current}" '
        ($policy[0].duplicate_version_ratchets[$scope].allowed) as $allowed
        | [
            $current[0][]
            | . as $observed
            | ($allowed | map(select(.name == $observed.name)) | first) as $baseline
            | if $baseline == null then
                  {
                      name: $observed.name,
                      reason: "new_duplicate_family",
                      observed_versions: $observed.versions
                  }
              else
                  ($observed.versions - $baseline.versions) as $added
                  | select($added | length > 0)
                  | {
                      name: $observed.name,
                      reason: "new_duplicate_version",
                      added_versions: $added,
                      observed_versions: $observed.versions,
                      allowed_versions: $baseline.versions
                  }
              end
        ]
    ' >"${output}"
}

run_gate() {
    verify_tools
    export ASUPERSYNC_ADVISORY_DB_ROOT="${DB_ROOT}"

    local deny_output="${OUTPUT_DIR}/cargo-deny-root.jsonl"
    local audit_output="${OUTPUT_DIR}/cargo-audit-root.json"
    local fuzz_deny_output="${OUTPUT_DIR}/cargo-deny-fuzz.jsonl"
    local fuzz_audit_output="${OUTPUT_DIR}/cargo-audit-fuzz.json"
    local root_duplicates="${OUTPUT_DIR}/root-duplicates.json"
    local root_duplicate_expansions="${OUTPUT_DIR}/root-duplicate-expansions.json"
    local fuzz_duplicates="${OUTPUT_DIR}/fuzz-duplicates.json"
    local fuzz_duplicate_expansions="${OUTPUT_DIR}/fuzz-duplicate-expansions.json"
    local deny_rc=0
    local audit_rc=0
    local fuzz_deny_rc=0
    local fuzz_audit_rc=0
    local db_repo
    local duplicate_expansion_count
    local fuzz_duplicate_expansion_count
    local root_status
    local fuzz_status
    local fuzz_deny_status
    local fuzz_audit_status
    local overall_outcome

    cargo-deny --locked --workspace --log-level error --format json \
        check --config deny.toml advisories licenses bans sources \
        >"${deny_output}" 2>&1 || deny_rc=$?

    db_repo="$(database_receipt)"

    cargo-audit audit --db "${db_repo}" --no-fetch --deny warnings --json \
        >"${audit_output}" 2>&1 || audit_rc=$?

    lockfile_duplicates Cargo.lock "${root_duplicates}"
    duplicate_expansions "${root_duplicates}" root "${root_duplicate_expansions}"
    duplicate_expansion_count="$(jq 'length' "${root_duplicate_expansions}")"

    cargo-deny --manifest-path fuzz/Cargo.toml --locked --log-level error --format json \
        check --config deny.toml advisories licenses bans sources \
        >"${fuzz_deny_output}" 2>&1 || fuzz_deny_rc=$?
    cargo-audit audit --file fuzz/Cargo.lock --db "${db_repo}" --no-fetch --deny warnings --json \
        >"${fuzz_audit_output}" 2>&1 || fuzz_audit_rc=$?
    lockfile_duplicates fuzz/Cargo.lock "${fuzz_duplicates}"
    duplicate_expansions "${fuzz_duplicates}" fuzz "${fuzz_duplicate_expansions}"
    fuzz_duplicate_expansion_count="$(jq 'length' "${fuzz_duplicate_expansions}")"

    root_status="pass"
    if ((deny_rc != 0 || audit_rc != 0 || duplicate_expansion_count != 0)); then
        root_status="fail"
    fi

    fuzz_deny_status="pass"
    if ((fuzz_deny_rc != 0)); then
        fuzz_deny_status="fail_policy"
    fi
    fuzz_audit_status="pass"
    if ((fuzz_audit_rc != 0)); then
        fuzz_audit_status="fail_advisories"
    fi
    fuzz_status="pass"
    if [[ "${fuzz_deny_status}" != "pass" || "${fuzz_audit_status}" != "pass" ]] ||
        ((fuzz_duplicate_expansion_count != 0)); then
        fuzz_status="fail"
    fi

    overall_outcome="PASS"
    if [[ "${root_status}" != "pass" || "${fuzz_status}" != "pass" ]]; then
        overall_outcome="FAIL"
    fi

    jq -n \
        --arg artifact_id "dependency-supply-chain-audit-summary-v1" \
        --arg bead_id "asupersync-mnotoo.2" \
        --arg outcome "${overall_outcome}" \
        --arg root_status "${root_status}" \
        --arg fuzz_status "${fuzz_status}" \
        --arg fuzz_deny_status "${fuzz_deny_status}" \
        --arg fuzz_audit_status "${fuzz_audit_status}" \
        --argjson cargo_deny_exit "${deny_rc}" \
        --argjson cargo_audit_exit "${audit_rc}" \
        --argjson duplicate_expansion_count "${duplicate_expansion_count}" \
        --argjson fuzz_duplicate_expansion_count "${fuzz_duplicate_expansion_count}" \
        --argjson fuzz_cargo_deny_exit "${fuzz_deny_rc}" \
        --argjson fuzz_cargo_audit_exit "${fuzz_audit_rc}" \
        --slurpfile database "${OUTPUT_DIR}/advisory-database-receipt.json" \
        '{
            schema_version: 1,
            artifact_id: $artifact_id,
            bead_id: $bead_id,
            outcome: $outcome,
            advisory_database: $database[0],
            root_workspace: {
                status: $root_status,
                cargo_deny_exit: $cargo_deny_exit,
                cargo_audit_exit: $cargo_audit_exit,
                duplicate_expansion_count: $duplicate_expansion_count
            },
            excluded_fuzz_workspace: {
                status: $fuzz_status,
                cargo_deny_status: $fuzz_deny_status,
                cargo_deny_exit: $fuzz_cargo_deny_exit,
                cargo_audit_status: $fuzz_audit_status,
                cargo_audit_exit: $fuzz_cargo_audit_exit,
                duplicate_expansion_count: $fuzz_duplicate_expansion_count
            },
            no_claim: "A PASS covers the checked root and excluded-fuzz dependency policies only; it does not prove fuzz-target behavior, release readiness, or undisclosed-vulnerability absence."
        }' >"${SUMMARY_PATH}"

    emit_event "root-workspace" "${root_status}" \
        "cargo-deny=${deny_rc}; cargo-audit=${audit_rc}; duplicate-expansions=${duplicate_expansion_count}"
    emit_event "excluded-fuzz-workspace" "${fuzz_status}" \
        "cargo-deny=${fuzz_deny_status}; cargo-audit=${fuzz_audit_status}; duplicate-expansions=${fuzz_duplicate_expansion_count}"

    jq . "${SUMMARY_PATH}"
    if [[ "${overall_outcome}" != "PASS" ]]; then
        return 1
    fi
}

self_test() {
    verify_tools
    export ASUPERSYNC_ADVISORY_DB_ROOT="${DB_ROOT}"

    local fixture_dir
    local db_repo
    local metadata_path
    local fixture_failures=0
    local advisory_rc=0
    local license_rc=0
    local fuzz_license_rc=0
    local source_rc=0
    local duplicate_count

    fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/asupersync-dependency-fixtures.XXXXXX")"
    sed '/RUSTSEC-2025-0134/d' deny.toml >"${fixture_dir}/deny-advisory.toml"
    sed '/^[[:space:]]*"ISC",$/d' deny.toml >"${fixture_dir}/deny-license.toml"
    sed '/^[[:space:]]*"NCSA",$/d' deny.toml >"${fixture_dir}/deny-fuzz-license.toml"

    cargo-deny --locked --workspace --log-level error --format json \
        check --config deny.toml advisories \
        >"${fixture_dir}/bootstrap-advisories.jsonl" 2>&1
    db_repo="$(database_receipt)"

    cargo-deny --locked --workspace --log-level error --format json \
        check --config "${fixture_dir}/deny-advisory.toml" --disable-fetch advisories \
        >"${fixture_dir}/advisory-ignore-removed.jsonl" 2>&1 || advisory_rc=$?
    if ((advisory_rc == 0)) ||
        ! grep -q 'RUSTSEC-2025-0134' "${fixture_dir}/advisory-ignore-removed.jsonl"; then
        emit_event "fixture-advisory-ignore-removed" "fail" \
            "expected a named RUSTSEC-2025-0134 rejection"
        fixture_failures=$((fixture_failures + 1))
    else
        emit_event "fixture-advisory-ignore-removed" "pass" \
            "temporary config rejected RUSTSEC-2025-0134"
    fi

    cargo-deny --locked --workspace --log-level error --format json \
        check --config "${fixture_dir}/deny-license.toml" licenses \
        >"${fixture_dir}/license-isc-removed.jsonl" 2>&1 || license_rc=$?
    if ((license_rc == 0)) ||
        ! grep -Eq 'ISC|untrusted' "${fixture_dir}/license-isc-removed.jsonl"; then
        emit_event "fixture-license-isc-removed" "fail" \
            "expected an ISC or untrusted license rejection"
        fixture_failures=$((fixture_failures + 1))
    else
        emit_event "fixture-license-isc-removed" "pass" \
            "temporary config rejected the removed ISC allowance"
    fi

    cargo-deny --manifest-path fuzz/Cargo.toml --locked --log-level error --format json \
        check --config "${fixture_dir}/deny-fuzz-license.toml" licenses \
        >"${fixture_dir}/license-ncsa-removed.jsonl" 2>&1 || fuzz_license_rc=$?
    if ((fuzz_license_rc == 0)) ||
        ! grep -q 'NCSA' "${fixture_dir}/license-ncsa-removed.jsonl"; then
        emit_event "fixture-fuzz-license-ncsa-removed" "fail" \
            "expected libfuzzer-sys to reject the removed NCSA allowance"
        fixture_failures=$((fixture_failures + 1))
    else
        emit_event "fixture-fuzz-license-ncsa-removed" "pass" \
            "temporary config rejected libfuzzer-sys without NCSA"
    fi

    lockfile_duplicates Cargo.lock "${fixture_dir}/duplicates.json"
    jq '
        map(
            if .name == "base64"
            then .versions += ["99.0.0"] | .versions |= unique
            else .
            end
        )
    ' "${fixture_dir}/duplicates.json" >"${fixture_dir}/duplicates-mutated.json"
    duplicate_expansions \
        "${fixture_dir}/duplicates-mutated.json" root "${fixture_dir}/duplicate-expansions.json"
    duplicate_count="$(jq 'length' "${fixture_dir}/duplicate-expansions.json")"
    if ((duplicate_count != 1)) ||
        ! jq -e '.[0].name == "base64" and .[0].added_versions == ["99.0.0"]' \
            "${fixture_dir}/duplicate-expansions.json" >/dev/null; then
        emit_event "fixture-duplicate-version-added" "fail" \
            "expected exactly one base64 expansion"
        fixture_failures=$((fixture_failures + 1))
    else
        emit_event "fixture-duplicate-version-added" "pass" \
            "ratchet rejected base64 99.0.0"
    fi

    metadata_path="${fixture_dir}/metadata.json"
    cargo metadata --locked --format-version 1 >"${fixture_dir}/metadata-original.json"
    jq '
        .packages |= (
            reduce range(0; length) as $index (
                {packages: ., changed: false};
                if (.changed | not) and .packages[$index].source != null then
                    .packages[$index].source =
                        "git+https://example.invalid/unapproved.git?rev=deadbeef#deadbeef"
                    | .changed = true
                else
                    .
                end
            )
            | .packages
        )
    ' "${fixture_dir}/metadata-original.json" >"${metadata_path}"
    cargo-deny --locked --workspace --log-level error --format json \
        check --config deny.toml --metadata-path "${metadata_path}" sources \
        >"${fixture_dir}/unknown-git-source.jsonl" 2>&1 || source_rc=$?
    if ((source_rc == 0)) ||
        ! grep -Eq 'unknown-git|git source|not explicitly allowed' \
            "${fixture_dir}/unknown-git-source.jsonl"; then
        emit_event "fixture-unknown-git-source" "fail" \
            "expected the mutated metadata source to be rejected"
        fixture_failures=$((fixture_failures + 1))
    else
        emit_event "fixture-unknown-git-source" "pass" \
            "temporary metadata rejected an unapproved git source"
    fi

    jq -n \
        --arg artifact_id "dependency-supply-chain-negative-fixtures-v1" \
        --arg fixture_dir "${fixture_dir}" \
        --arg db_repo "${db_repo}" \
        --argjson failures "${fixture_failures}" \
        '{
            schema_version: 1,
            artifact_id: $artifact_id,
            outcome: (if $failures == 0 then "PASS" else "FAIL" end),
            fixture_failures: $failures,
            fixture_evidence_directory: $fixture_dir,
            advisory_database_path: $db_repo
        }' >"${OUTPUT_DIR}/self-test-summary.json"
    jq . "${OUTPUT_DIR}/self-test-summary.json"

    if ((fixture_failures != 0)); then
        return 1
    fi
}

usage() {
    printf 'usage: %s {install-tools|run|self-test}\n' "${0##*/}" >&2
}

case "${1:-run}" in
    install-tools)
        install_tools
        ;;
    run)
        run_gate
        ;;
    self-test)
        self_test
        ;;
    *)
        usage
        exit 64
        ;;
esac
