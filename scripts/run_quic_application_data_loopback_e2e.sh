#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RUN_ID="${RUN_ID:-managed-quic-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_${RUN_ID}}"
OUTPUT_ROOT="${OUTPUT_ROOT:-${TMPDIR:-/tmp}/asupersync-quic-${RUN_ID}}"
BASE_REV="$(git rev-parse "${ASUPERSYNC_QUIC_BASE:-HEAD}^{commit}")"
OVERLAY_MODE="${ASUPERSYNC_QUIC_CLEAN_OVERLAY:-0}"
QUIC_WORKER="${ASUPERSYNC_QUIC_RCH_WORKER:-${RCH_WORKER:-}}"
BUILD_JOBS="${ASUPERSYNC_QUIC_BUILD_JOBS:-8}"
QUIC_CARGO_HOME="${ASUPERSYNC_QUIC_CARGO_HOME:-${CARGO_HOME:-}}"
QUIC_ARTIFACT_BASE="${ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE:-}"
OVERLAY_FINGERPRINT=""
if [[ ! "${BUILD_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
  echo "refused: ASUPERSYNC_QUIC_BUILD_JOBS must be a positive integer" >&2
  exit 2
fi
REMOTE_CARGO_ENV=()
if [[ -n "${QUIC_CARGO_HOME}" ]]; then
  REMOTE_CARGO_ENV+=("CARGO_HOME=${QUIC_CARGO_HOME}")
fi
if [[ -n "${QUIC_ARTIFACT_BASE}" ]]; then
  if [[ "${QUIC_ARTIFACT_BASE}" != /* ]]; then
    echo "refused: ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE must be an absolute remote directory" >&2
    exit 2
  fi
  # Select an existing worker directory outside the clean-overlay snapshot to
  # retain process artifacts after RCH reaps that snapshot. Forward explicitly;
  # the harness creates its own unique child directory beneath this base.
  REMOTE_CARGO_ENV+=("ASUPERSYNC_MANAGED_QUIC_ARTIFACT_BASE=${QUIC_ARTIFACT_BASE}")
fi
if [[ -e "${OUTPUT_ROOT}" ]]; then
  echo "refused: OUTPUT_ROOT already exists; preserve its earlier evidence: ${OUTPUT_ROOT}" >&2
  exit 2
fi
mkdir -p "${OUTPUT_ROOT}"

# Installed executable evidence, not a version-number assumption. Refuse before
# issuing proof commands if the complete source-selection surface is missing.
rch exec --help > "${OUTPUT_ROOT}/rch-exec-help.log"
for option in --base --clean-overlay --overlay-path --no-overlay; do
  if ! grep -q -- "${option}" "${OUTPUT_ROOT}/rch-exec-help.log"; then
    echo "declared_unavailable: installed RCH lacks ${option}" >&2
    exit 2
  fi
done
SOURCE_ARGS=(--base "${BASE_REV}")
if [[ "${OVERLAY_MODE}" == 1 ]]; then
  # This is the complete, reviewable managed-handoff source slice. The caller
  # coordinates these exact reservations; unselected peer dirt stays excluded.
  SOURCE_ARGS+=(--clean-overlay)
  for path in src/net/quic_native/connection_manager.rs src/net/quic_native/managed_endpoint.rs \
    src/net/quic_native/udp_connection.rs src/net/quic_native/endpoint.rs \
    src/net/quic_native/endpoint_api.rs src/net/quic_native/mod.rs \
    tests/quic_h3_live_udp.rs scripts/run_quic_application_data_loopback_e2e.sh; do
    SOURCE_ARGS+=(--overlay-path "${path}")
  done
elif [[ "${OVERLAY_MODE}" == 0 ]]; then
  SOURCE_ARGS+=(--no-overlay)
else
  echo "refused: ASUPERSYNC_QUIC_CLEAN_OVERLAY must be 0 or 1" >&2
  exit 2
fi

echo "ATP_QUIC_TRACE=${ATP_QUIC_TRACE:-1}"
echo "CARGO_TARGET_DIR=${TARGET_DIR}"
echo "build_jobs=${BUILD_JOBS} cargo_home=${QUIC_CARGO_HOME:-remote-default}"
echo "managed_artifact_base=${QUIC_ARTIFACT_BASE:-remote-test-default}"
echo "base=${BASE_REV} overlay_mode=${OVERLAY_MODE} logs=${OUTPUT_ROOT}"

run_stage() {
  local stage="$1" features="$2" target="$3" status=0 receipt
  env RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=verbose RCH_WORKER="${QUIC_WORKER}" RCH_WORKERS= NO_COLOR=1 \
    rch exec "${SOURCE_ARGS[@]}" -- env "${REMOTE_CARGO_ENV[@]}" \
    ATP_QUIC_TRACE="${ATP_QUIC_TRACE:-1}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
    RUSTFLAGS='-D warnings -C debuginfo=0' \
    cargo test --jobs "${BUILD_JOBS}" -p asupersync --locked \
    --features "${features}" --test "${target}" -- --nocapture \
    2>&1 | tee "${OUTPUT_ROOT}/${stage}.log" || status=$?
  if [[ "${status}" != 0 ]]; then
    echo "failed: ${stage} terminal_exit=${status}; original output retained" >&2
    return "${status}"
  fi
  receipt="$(python3 - "${OUTPUT_ROOT}/${stage}.log" "${BASE_REV}" "${QUIC_WORKER}" "${OVERLAY_FINGERPRINT}" <<'PY'
import pathlib, re, sys
path, base, worker, fingerprint = sys.argv[1:]
log = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
selected = re.findall(r"Selected worker: ([A-Za-z0-9_.-]+) at ", log)
terminal = re.findall(r"^\[RCH\] remote ([A-Za-z0-9_.-]+) \([^\n]+\)$", log, re.M)
sources = re.findall(r"^\[RCH\] clean-overlay receipt: base=([0-9a-f]{40}) overlay-fingerprint=([0-9a-f]{64})$", log, re.M)
assert len(selected) == 1 and terminal == selected, "actual unique remote terminal worker required"
assert not worker or selected == [worker], "worker changed between required stages"
assert len(sources) == 1 and sources[0][0] == base, "selected source receipt required"
assert not fingerprint or sources[0][1] == fingerprint, "source changed between required stages"
assert re.search(r"test result: ok\. [1-9][0-9]* passed; 0 failed;", log), "nonzero terminal tests required"
print(selected[0], sources[0][1])
PY
)"
  read -r QUIC_WORKER OVERLAY_FINGERPRINT <<< "${receipt}"
}

# Preserve the original protocol fixture stage and its assertions. Its keys and
# manually established state are not credited as authenticated managed proof.
run_stage protocol-fixture test-internals,tls quic_application_data_udp_loopback
# The managed tests use public APIs for real TLS handshakes and consuming
# handoffs. The conformance dev-dependency unifies test-internals into this
# target, so all four original tests and both managed parents must execute.
# The ignored peer is explicitly executed twice by its parent.
run_stage authenticated-managed http3,tls quic_h3_live_udp
python3 - "${OUTPUT_ROOT}/authenticated-managed.log" "${BASE_REV}" "${OVERLAY_MODE}" <<'PY'
import hashlib, json, pathlib, re, subprocess, sys
path, base, overlay = sys.argv[1:]
log = re.sub(r"\x1b\[[0-9;]*m", "", pathlib.Path(path).read_text())
counts = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", log)
assert counts[-1:] == [("6", "0", "1", "0", "0")], ("all public parents and one intentional helper required", counts)
parents = {
    "authenticated_h3_router_request_response_crosses_real_udp",
    "authenticated_h3_produced_response_obeys_live_udp_credit_and_quiesces",
    "cancellation_refuses_live_request_before_router_dispatch",
    "negotiated_non_h3_alpn_refuses_live_application_handles",
    "authenticated_managed_public_handoff_self_wake_and_restart_cross_real_udp",
    "authenticated_managed_two_process_public_exchange_cancel_and_restart",
}
passed = re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ok$", log, re.M)
assert len(passed) == len(parents) and set(passed) == parents, ("all six named parents must pass exactly once", passed)
ignored = re.findall(r"^test ([A-Za-z0-9_]+) \.\.\. ignored(?:, [^\n]*)?$", log, re.M)
assert ignored == ["authenticated_managed_process_peer"], ("only the named process helper may be ignored", ignored)
rows = [json.loads(line.split("MANAGED_QUIC_TWO_PROCESS ", 1)[1]) for line in log.splitlines() if "MANAGED_QUIC_TWO_PROCESS " in line]
assert len(rows) == 1, "one actual two-process summary required"
summary = rows[0]
paths = dict(test="tests/quic_h3_live_udp.rs", runner="scripts/run_quic_application_data_loopback_e2e.sh", manager="src/net/quic_native/connection_manager.rs", managed="src/net/quic_native/managed_endpoint.rs", owner="src/net/quic_native/udp_connection.rs", endpoint="src/net/quic_native/endpoint.rs", application="src/net/quic_native/endpoint_api.rs", exports="src/net/quic_native/mod.rs")
expected = {key: hashlib.sha256(pathlib.Path(value).read_bytes() if overlay == "1" else subprocess.check_output(["git", "show", f"{base}:{value}"])).hexdigest() for key, value in paths.items()}
assert summary["source"] == expected, "compiled source identity differs from the selected revision/overlay"
children = summary["children"]
assert len(children) == summary["actual_child_count"] == 2
assert summary["actual_authenticated_sessions"] == 1
assert {child["role"] for child in children} == {"client", "server"}
assert len({child["pid"] for child in children}) == 2
assert re.fullmatch(r"[0-9a-f]{64}", summary["executable_sha256"])
for child in children:
    assert child["source"] == expected and child["executable_sha256"] == summary["executable_sha256"]
    assert child["runtime_quiescent"] and child["parked_cancelled_and_restarted"]
    assert child["active_connections_after_shutdown"] == 0 and len(child["rounds"]) == 2
    assert all(round["received_bytes"] > 0 and round["packets_sent"] > 0 and round["packets_received"] > 0 for round in child["rounds"])
print("verified managed public proof: 6 parent tests; 2 executed child helpers; 1 authenticated session; 2 exchange rounds; managed tests use public APIs; no same-router, WouldBlock, or performance claim")
PY
