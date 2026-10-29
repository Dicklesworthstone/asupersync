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
The native TLS/off rows also compile an opt-in depth sentinel at a LOWER
recursion limit (60), scoped to these exact compilers. The ordinary consumer
uses Rust's default limit. A failed sentinel is a failure, not a skipped row.
A missing compiler, resolution error, or failed cell makes the runner fail.
The runtime tests additionally check lazy/concurrent access, inherited sharing,
and cancellation. Production-only tests submit a Cx-capturing future to the
attached blocking pool with TLS off/on. Focused root HTTP/TLS integration
targets run separately.
A pass is scoped to these checks, not release readiness.
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
# .cargo/config.toml sets nightly-only -Z threads=4. A nonempty RUSTFLAGS
# overrides Cargo config/target rustflags without enabling unstable features.
export RUSTFLAGS='-C debuginfo=0'
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
        if [[ "${PROFILES[$i]}" == native || "${PROFILES[$i]}" == native-tls ]]; then
            probe_features=depth-probe
            if [[ -n "${FEATURES[$i]}" ]]; then probe_features+=,${FEATURES[$i]}; fi
            run_stage "$name-depth-probe" cargo "+$toolchain" check --bin depth_probe --manifest-path "$MANIFEST" --locked --no-default-features --features "$probe_features" || :
            if run_stage "$name-blocking-pool" cargo "+$toolchain" test --lib "${args[@]}" -- --nocapture; then
                log="$OUTPUT/$name-blocking-pool.log"
                # Name both sentinels: a filtered or ignored test must never
                # turn this production-only runtime row into an empty pass.
                if ! grep -Fxq 'test public_runtime_types_are_send ... ok' "$log" ||
                   ! grep -Fxq 'test cx_capturing_future_runs_on_attached_blocking_pool ... ok' "$log" ||
                   ! grep -Eq 'test result: ok\. [1-9][0-9]* passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' "$log"; then
                    printf '%s\t1\t%s\n' "$name-blocking-pool-required-tests" "$name-blocking-pool.log" >> "$OUTPUT/summary.tsv"
                    failed=1
                fi
            fi
        fi
    done
    # Only these separate runtime rows enable test-internals. Never use their
    # unified graph as evidence for the production-only compile rows above.
    for tls in off on; do
        features=behavior
        root_features=proc-macros,native-runtime,test-internals
        tests=(--test http_client_default_for_runtime_conformance --test http_client_pool_wait)
        if [[ "$tls" == on ]]; then
            features+=,tls
            root_features+=,tls
            tests+=(--test http_client_https_e2e)
        fi
        name="$toolchain-slot-tls-$tls"
        if run_stage "$name" cargo "+$toolchain" test --manifest-path "$MANIFEST" --locked --no-default-features --features "$features" --test http_slot -- --nocapture; then
            if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed; 0 failed;' "$OUTPUT/$name.log"; then
                printf '%s\t1\t%s\n' "$name-nonzero-tests" "$name.log" >> "$OUTPUT/summary.tsv"
                failed=1
            fi
        fi
        run_stage "$toolchain-http-tls-$tls" cargo "+$toolchain" test --locked -p asupersync --no-default-features --features "$root_features" "${tests[@]}" -- --nocapture || :
    done
done
printf 'Qualification logs: %s\n' "$OUTPUT"
if [[ "$failed" != 0 ]]; then
    echo 'FAIL: at least one required compiler or matrix cell did not pass.' >&2
    exit 1
fi
echo 'PASS: downstream Send matrix and focused runtime HTTP/TLS checks; release gates remain separate.'
