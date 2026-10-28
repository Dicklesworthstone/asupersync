#!/usr/bin/env bash
# GH #86: compile an isolated downstream consumer on stable Rust 1.99.x.
# Invoke from the checkout through RCH, or explicitly on a qualification host:
#   RCH_REQUIRE_REMOTE=1 rch exec -- bash scripts/validate_tls_send.sh
# There is no automatic local fallback and no publishing side effect.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$ROOT/tests/fixtures/tls-send-consumer/Cargo.toml"
PROFILES=(native native-tls reported reported-tls defaults defaults-tls tls-core native-roots webpki-roots)
FEATURES=('' tls nightly-outcome-try nightly-outcome-try,tls runtime-defaults runtime-defaults,tls tls-core tls-native-roots tls-webpki-roots)

if [[ "${1:-}" == --help ]]; then
    cat <<'HELP'
Usage: bash scripts/validate_tls_send.sh [1.99.0 1.99.1 ...]
       bash scripts/validate_tls_send.sh --list

Default compilers: 1.99.0 and 1.99.1. Run on each available Linux/macOS host.
Use RCH_REQUIRE_REMOTE=1 rch exec -- for the direct-main qualification lane.
Each compiler must be an installed, exact stable Rust 1.99.x release.
No RUSTC_BOOTSTRAP, compiler wrappers, or inherited rustflags are used.
Logs, resolved dependency features, and the consumer lockfile are retained in
TLS_SEND_OUTPUT_DIR (default: a new directory below target/tls-send-results).
A missing compiler, resolution error, or failed cell makes the runner fail.
A pass covers this downstream compilation matrix only, not release readiness.
HELP
    exit 0
fi
if [[ "${1:-}" == --list ]]; then
    for i in "${!PROFILES[@]}"; do
        printf '%s\t%s\n' "${PROFILES[$i]}" "${FEATURES[$i]:-(proc-macros,native-runtime only)}"
    done
    exit 0
fi
TOOLCHAINS=("$@")
if [[ ${#TOOLCHAINS[@]} -eq 0 ]]; then
    TOOLCHAINS=(1.99.0 1.99.1)
fi
for toolchain in "${TOOLCHAINS[@]}"; do
    if [[ ! "$toolchain" =~ ^1\.99\.[0-9]+$ ]]; then
        echo "Expected an exact stable 1.99.x toolchain, got: $toolchain" >&2
        exit 2
    fi
done

cd "$ROOT"
mkdir -p "$ROOT/target/tls-send-results"
OUTPUT="${TLS_SEND_OUTPUT_DIR:-$(mktemp -d "$ROOT/target/tls-send-results/run.XXXXXX")}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
# Never overwrite an earlier qualification receipt.
if [[ -e "$OUTPUT/summary.tsv" ]]; then
    echo "Refusing to overwrite existing receipt: $OUTPUT/summary.tsv" >&2
    exit 2
fi
printf 'stage\texit_code\tlog\n' > "$OUTPUT/summary.tsv"
uname -a > "$OUTPUT/host.txt"
git rev-parse HEAD > "$OUTPUT/git-head.txt"
git status --porcelain=v1 > "$OUTPUT/git-status.txt"

# Qualification must not accidentally exercise a bootstrap/new-solver wrapper.
unset RUSTC_BOOTSTRAP RUSTC RUSTDOC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/tls-send-build}"
export CARGO_TERM_COLOR=never
failed=0
lock_ready=0
run_stage() {
    local name="$1" rc=0
    shift
    printf 'Running %s\n' "$name"
    if "$@" > "$OUTPUT/$name.log" 2>&1; then
        rc=0
    else
        rc=$?
        failed=1
        cat "$OUTPUT/$name.log" >&2
    fi
    printf '%s\t%s\t%s\n' "$name" "$rc" "$name.log" >> "$OUTPUT/summary.tsv"
    return "$rc"
}

for toolchain in "${TOOLCHAINS[@]}"; do
    if ! run_stage "$toolchain-rustc" rustc "+$toolchain" -vV; then
        continue
    fi
    if ! grep -Fxq "release: $toolchain" "$OUTPUT/$toolchain-rustc.log"; then
        printf '%s\t1\t%s\n' "$toolchain-stable-identity" "$toolchain-rustc.log" >> "$OUTPUT/summary.tsv"
        failed=1
        continue
    fi
    if ! run_stage "$toolchain-cargo" cargo "+$toolchain" --version; then
        continue
    fi
    # This fixture intentionally has its own lock, independent of the large
    # workspace's dev graph. Reuse it on subsequent invocations. Preserve the
    # exact resolution alongside the logs rather than claiming it is root's.
    if [[ "$lock_ready" == 0 ]]; then
        if [[ ! -f "${MANIFEST%/*}/Cargo.lock" ]]; then
            if ! run_stage consumer-lock cargo "+$toolchain" generate-lockfile --manifest-path "$MANIFEST"; then
                continue
            fi
        fi
        cp "${MANIFEST%/*}/Cargo.lock" "$OUTPUT/Cargo.lock"
        lock_ready=1
    fi
    for i in "${!PROFILES[@]}"; do
        name="$toolchain-${PROFILES[$i]}"
        args=(--manifest-path "$MANIFEST" --locked --no-default-features)
        if [[ -n "${FEATURES[$i]}" ]]; then
            args+=(--features "${FEATURES[$i]}")
        fi
        if ! run_stage "$name-graph" cargo "+$toolchain" tree "${args[@]}" --edges normal --prefix none --format '{p} features=[{f}]'; then
            continue
        fi
        # A falsely unified test graph is not downstream qualification. Also
        # check rustls really is present/absent in the intended TLS/no-TLS row.
        graph="$OUTPUT/$name-graph.log"
        if ! grep -q '^asupersync v' "$graph" || grep '^asupersync v' "$graph" | grep -q 'test-internals'; then
            printf '%s\t1\t%s\n' "$name-graph-isolation" "$name-graph.log" >> "$OUTPUT/summary.tsv"
            failed=1
            continue
        fi
        has_tls=0
        if grep -q '^rustls v' "$graph"; then has_tls=1; fi
        expected_tls=0
        if [[ "${FEATURES[$i]}" == *tls* ]]; then expected_tls=1; fi
        if [[ "$has_tls" != "$expected_tls" ]]; then
            printf '%s\t1\t%s\n' "$name-tls-selection" "$name-graph.log" >> "$OUTPUT/summary.tsv"
            failed=1
            continue
        fi
        run_stage "$name-check" cargo "+$toolchain" check --lib "${args[@]}" || :
    done
done
printf 'Qualification logs: %s\n' "$OUTPUT"
if [[ "$failed" != 0 ]]; then
    echo 'FAIL: at least one required compiler or matrix cell did not pass.' >&2
    exit 1
fi
echo 'PASS: downstream compilation matrix only; release gates remain separate.'
