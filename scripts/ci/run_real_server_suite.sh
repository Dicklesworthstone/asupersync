#!/usr/bin/env bash
# Fail-closed runner for ONE real-server integration suite.
#
#   scripts/ci/run_real_server_suite.sh <test-target> [extra cargo args...]
#
# Example:
#   REAL_POSTGRES_TESTS=true POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
#     scripts/ci/run_real_server_suite.sh postgres_real_server --features postgres,mysql
#
# Why this exists: every real-server suite in this repository skips cleanly
# when its REAL_* toggle or URL is missing, and a skipped test still counts as
# "passed" in cargo's summary. A lane that only checks cargo's exit code is
# therefore fail-open: it turns green without ever talking to a server. This
# wrapper rejects the outcomes that would hide that:
#
#   * cargo exit code != 0                       -> fail
#   * no terminal `test result:` line             -> fail (the binary never ran)
#   * `0 passed`                                  -> fail (filtered / empty)
#   * any suite skip marker in the output         -> fail (silent pass)
#
# The suites print their skip decisions as JSON log lines or plain messages
# only when output is NOT captured, so `--nocapture` is mandatory here.
#
# Environment:
#   RCH_BIN            command runner (default: ~/.local/bin/rch; CI passes
#                      scripts/rch_ci_fallback.sh so cargo runs on the runner
#                      next to the docker services).
#   CARGO_TARGET_DIR   forwarded; defaults to ${TMPDIR:-/tmp}/rch_target_ci_real_servers.
#   REAL_* / *_URL     forwarded to the test binary untouched.
set -euo pipefail

target="${1:?usage: $0 <test-target> [extra cargo args...]}"
shift

RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
if [[ ! -x "$RCH_BIN" ]]; then
    echo "run_real_server_suite: rch is required (RCH_BIN=$RCH_BIN is not executable)" >&2
    exit 1
fi

target_dir="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_ci_real_servers}"
log="$(mktemp "${TMPDIR:-/tmp}/real_server_${target}.XXXXXX.log")"

set +e
"$RCH_BIN" exec -- env CARGO_TARGET_DIR="$target_dir" \
    cargo test -p asupersync "$@" --test "$target" -- --nocapture 2>&1 | tee "$log"
rc="${PIPESTATUS[0]}"
set -e

# Markers every suite in tests/ uses when it decides NOT to talk to a server.
# Anchored to the exact strings the suites print (postgres/mysql/nats/jetstream:
# JSON `"event":"test_skipped"`; redis: "skipping Redis E2E test"; kafka:
# "deterministic skip" / "skipped-real-broker"). Fail closed on any of them.
skip_pattern='"event":"test_skipped"|skipping Redis E2E test|deterministic skip because|skipped-real-broker|not set to '"'"'true'"'"''
if grep -qE "$skip_pattern" "$log"; then
    echo "run_real_server_suite: $target skipped instead of running against the real server:" >&2
    grep -nE "$skip_pattern" "$log" | head -n 10 >&2
    exit 1
fi

summary="$(grep -E '^test result: ' "$log" | tail -n 1 || true)"
if [[ -z "$summary" ]]; then
    echo "run_real_server_suite: $target produced no terminal 'test result:' line (cargo exit $rc)" >&2
    exit 1
fi

if [[ "$rc" -ne 0 ]]; then
    echo "run_real_server_suite: $target failed (cargo exit $rc): $summary" >&2
    exit "$rc"
fi

passed="$(sed -E 's/^test result: [a-zA-Z]+\. ([0-9]+) passed.*/\1/' <<<"$summary")"
if ! [[ "$passed" =~ ^[0-9]+$ ]] || [[ "$passed" -eq 0 ]]; then
    echo "run_real_server_suite: $target passed zero tests: $summary" >&2
    exit 1
fi

echo "run_real_server_suite: $target OK ($passed passed): $summary"
